"""Stage 6 against the real stack: multi-turn conversations through the gateway.

    docker compose up -d --wait && uv run pytest -m integration -s tests/integration/test_stage6.py

The held-out conversations (``datasets/multiturn/heldout.jsonl``) are replayed with and without a
session id; ``scripts/eval_multiturn.py`` is the full report. Requests carry no customer id; ML
blocks never ban a session (the conversation lock escalates instead).
"""

from __future__ import annotations

import statistics
import time
import uuid

import httpx
import pytest
from fastapi.testclient import TestClient

from app.main import create_app
from scripts.eval_multiturn import CachingTransport, evaluate, score_cfg
from tests.integration.test_stack import GATEWAY_URL, admin, msg, new_key, settings

pytestmark = pytest.mark.integration


def test_heldout_conversations_stage6_never_loses_a_catch_and_stays_quiet_on_benign_chats() -> None:
    summary, _ = evaluate("heldout.jsonl", {}, CachingTransport())
    for kind, v in summary.items():
        print(kind, v)
        if "caught_stage6" in v:
            assert int(v["caught_stage6"].split("/")[0]) >= int(v["caught_single_turn"].split("/")[0])
    _caught, added = score_cfg(summary)
    assert added <= 0.10  # loose floor; the printed numbers are the point


def test_lock_and_admin_view_through_the_container() -> None:
    conv = f"it-{uuid.uuid4().hex[:8]}"
    with httpx.Client(base_url=GATEWAY_URL, timeout=5) as c:
        _k, key = new_key(c)
        auth = {"authorization": f"Bearer {key}"}

        def say(text: str) -> dict:
            return c.post("/v1/inspect", json=msg(text, session_id=conv), headers=auth).json()

        first = say("Hi, I need to change my seat")
        assert first["action"] == "allow", first["reasons"]
        # Three AI replies blocked for leaking a credential (probabilistic strikes: the session is not
        # banned) — the conversation lock escalates instead.
        for _ in range(3):
            leak = c.post(
                "/v1/inspect/outbound",
                json={"session_id": conv, "reply": "The key is AKIAABCDEFGHIJKLMNOP"},
                headers=auth,
            ).json()
            assert leak["action"] == "block" and leak["cmp_action"] == "send_fallback"
        deadline, view = time.monotonic() + 3, {}
        while time.monotonic() < deadline and not (view.get("conversation") or {}).get("locked"):
            view = c.get(f"/admin/sessions/{conv}", headers=admin()).json()
            time.sleep(0.05)
        memory = view["conversation"]
        assert memory["locked"] and memory["blocks"] == 3 and memory["replies_seen"] == 3
        locked = say("Is my flight on time?")
        assert "conversation_locked" in locked["reasons"] and locked["cmp_action"] == "handoff_to_agent"
        assert c.delete(f"/admin/sessions/{conv}", headers=admin()).status_code == 200
        assert say("Is my flight on time?")["action"] == "allow"


def test_tracked_conversation_latency() -> None:
    """A turn with history pays one Redis GET more than the first turn of a session."""
    cfg = settings(rl_api_key_capacity=100_000, rl_global_capacity=100_000, rl_endpoint_capacity=100_000)
    with TestClient(create_app(settings=cfg)) as c:
        _k, key = new_key(c)
        auth = {"authorization": f"Bearer {key}"}
        tracked, untracked = [], []
        run = f"lat-{uuid.uuid4().hex[:8]}"
        for i in range(60):
            text = f"Question {i}: my bag never arrived in Calgary, what can I do?"
            t0 = time.perf_counter()
            c.post("/v1/inspect", json=msg(text, session_id=f"{run}-{i // 6}"), headers=auth)
            tracked.append((time.perf_counter() - t0) * 1000)
            t0 = time.perf_counter()
            c.post("/v1/inspect", json=msg(text), headers=auth)  # a new session: empty memory
            untracked.append((time.perf_counter() - t0) * 1000)

    def p(xs: list[float], q: float) -> float:
        return sorted(xs)[int(len(xs) * q) - 1]

    print(
        f"\nfirst turn p50 {statistics.median(untracked):.1f} ms p99 {p(untracked, 0.99):.1f} ms; "
        f"later turns p50 {statistics.median(tracked):.1f} ms p99 {p(tracked, 0.99):.1f} ms"
    )
    assert statistics.median(tracked) < 50
