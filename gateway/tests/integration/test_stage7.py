"""Stage 7 against the real stack: canaries in PostgreSQL, outbound checks, proxied replies.

docker compose up -d --wait && uv run pytest -m integration -s tests/integration/test_stage7.py
"""

from __future__ import annotations

import statistics
import time
import uuid

import httpx
import pytest
from fastapi.testclient import TestClient

from app.main import create_app
from tests.integration.test_stack import GATEWAY_URL, admin, end_user, msg, new_key, settings, sid

pytestmark = pytest.mark.integration
CARD = "4111 1111 1111 1111"


def test_canary_leak_through_the_container_blocks_and_bans() -> None:
    user, session = f"it-{uuid.uuid4().hex[:8]}", sid()
    with httpx.Client(base_url=GATEWAY_URL, timeout=5) as c:
        _k, key = new_key(c)
        auth = {"authorization": f"Bearer {key}"}
        created = c.post("/admin/canaries", json={"label": "prompt"}, headers=admin())
        assert created.status_code == 201
        token = created.json()["token"]
        ok = c.post(
            "/v1/inspect/outbound",
            json={"session_id": session, "reply": "Your flight is on time.", "customer_id": user},
            headers=auth,
        )
        assert ok.json()["action"] == "allow" and ok.json()["deliver"] == "Your flight is on time."
        leak = c.post(
            "/v1/inspect/outbound",
            json={"session_id": session, "reply": f"My hidden marker is {token}", "customer_id": user},
            headers=auth,
        ).json()
        assert leak["action"] == "block" and leak["deliver"] is None and leak["reasons"] == ["canary_leak"]
        deadline, status = time.monotonic() + 3, ""
        while time.monotonic() < deadline and status != "banned":
            # A new chat of the same customer: the customer is banned, not only that session.
            d = c.post("/v1/inspect", json=msg("hello there", user_id=user), headers=auth).json()
            status = (d["reasons"] or [""])[0]
            time.sleep(0.05)
        assert status == "banned"  # the deterministic strike banned the customer who extracted the prompt
        # The canary is shared by every test run: revoke it so later leak tests start clean.
        c.delete(f"/admin/canaries/{created.json()['id']}", headers=admin())


def test_proxied_replies_are_checked_through_the_container() -> None:
    with httpx.Client(base_url=GATEWAY_URL, timeout=5) as c:
        _k, key = new_key(c)
        auth = {"authorization": f"Bearer {key}", **end_user()}
        card = c.post("/v1/ai/leak-test", json={"reply": f"Card on file: {CARD}"}, headers=auth)
        assert card.status_code == 200 and card.json()["reply"] == "Card on file: [REDACTED:card]"
        scope = {"booking_ref": ["ABC123"]}
        mine = c.post(
            "/v1/ai/leak-test",
            json={"reply": "Booking reference ABC123", "allowed_identifiers": scope},
            headers=auth,
        )
        assert mine.status_code == 200 and mine.json()["reply"] == "Booking reference ABC123"
        assert "x-security-allowed-identifiers" not in mine.headers
        theirs = c.post(
            "/v1/ai/leak-test",
            json={"reply": "Booking reference XYZ789", "allowed_identifiers": scope},
            headers=auth,
        )
        assert theirs.status_code == 502 and theirs.json()["error"] == "response_blocked"


def test_inbound_redaction_and_outbound_latency() -> None:
    cfg = settings(rl_api_key_capacity=100_000, rl_global_capacity=100_000, rl_endpoint_capacity=100_000)
    with TestClient(create_app(settings=cfg)) as c:
        _k, key = new_key(c)
        auth = {"authorization": f"Bearer {key}"}
        d = c.post("/v1/inspect", json=msg(f"Please refund {CARD}"), headers=auth).json()
        assert d["redacted_message"] == "Please refund [REDACTED:card]"
        reply = (
            "Your booking reference ABC123 is confirmed for AC854 on 2 November; a receipt was sent to "
            "jane@example.com. See https://www.aircanada.com/baggage for the allowance."
        )
        times, session = [], sid()
        for _ in range(200):
            t0 = time.perf_counter()
            r = c.post(
                "/v1/inspect/outbound",
                json={
                    "session_id": session,
                    "reply": reply,
                    "allowed_identifiers": {"booking_ref": ["ABC123"], "email": ["jane@example.com"]},
                },
                headers=auth,
            ).json()
            times.append((time.perf_counter() - t0) * 1000)
        assert r["action"] == "allow" and r["deliver"] == reply
    times.sort()
    print(
        f"\noutbound inspect round trip p50 {statistics.median(times):.2f} ms p99 {times[197]:.2f} ms; "
        f"pipeline {r['latency_ms']} ms"
    )
    assert statistics.median(times) < 20
