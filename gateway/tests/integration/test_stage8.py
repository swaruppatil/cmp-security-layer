"""Stage 8 against the real stack: bot simulation on real Redis, and a real-time bot via the container.

docker compose up -d --wait && uv run pytest -m integration -s tests/integration/test_stage8.py
"""

from __future__ import annotations

import time
import uuid

import httpx
import pytest
from fastapi.testclient import TestClient

from app.main import create_app
from scripts.simulate_bots import FakeClock, run
from tests.integration.test_stack import GATEWAY_URL, msg, new_key, settings

pytestmark = pytest.mark.integration


def test_simulated_sessions_on_real_redis() -> None:
    clock = FakeClock()
    cfg = settings(
        rl_user_capacity=1_000_000,
        rl_ip_capacity=1_000_000,
        rl_session_capacity=1_000_000,
        rl_api_key_capacity=1_000_000,
        rl_global_capacity=1_000_000,
        rl_endpoint_capacity=1_000_000,
    )
    with TestClient(create_app(settings=cfg)) as c:
        c.app.state.bots.clock = clock
        _k, key = new_key(c)
        summary = run(c, {"authorization": f"Bearer {key}"}, clock)
    for profile, v in summary.items():
        print(
            profile,
            {
                k: v[k]
                for k in ("sessions", "sessions_throttled", "sessions_slowed", "first_throttle_at_message")
            },
            v["signals"],
        )
    assert summary["human"]["sessions_throttled"] == 0 and summary["human"]["sessions_slowed"] == 0
    assert summary["timer_template"]["sessions_throttled"] == summary["timer_template"]["sessions"]
    assert summary["fast_paster"]["sessions_slowed"] == summary["fast_paster"]["sessions"]


def test_real_time_bot_through_the_container_is_throttled() -> None:
    user = f"it-bot-{uuid.uuid4().hex[:8]}"
    with httpx.Client(base_url=GATEWAY_URL, timeout=5) as c:
        _k, key = new_key(c)
        auth = {"authorization": f"Bearer {key}"}
        results = []
        for _ in range(12):
            results.append(
                c.post(
                    "/v1/inspect",
                    json=msg(
                        "Status of my booking please",
                        user_id=user,
                        session_id=f"s-{user}",
                        user_agent="python-requests/2.31",
                        channel="web",
                    ),
                    headers=auth,
                ).json()
            )
            time.sleep(0.3)
        actions = [r["action"] for r in results]
        assert "throttle" in actions, actions
        first = results[actions.index("throttle")]
        bot = next(x for x in first["checks"] if x["name"] == "bot")
        print(
            "\nfirst throttle at request",
            actions.index("throttle") + 1,
            first["reasons"],
            bot["detail"]["signals"],
        )
        assert bot["detail"]["tier"] in ("likely", "bot")
        # A person chatting at the same time is unaffected.
        person = c.post(
            "/v1/inspect",
            json=msg("Can I change my seat on AC854?", user_id=f"it-person-{uuid.uuid4().hex[:6]}"),
            headers=auth,
        ).json()
        assert person["action"] == "allow"
