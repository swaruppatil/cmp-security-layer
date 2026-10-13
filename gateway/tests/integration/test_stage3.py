"""Stage 3 against the real stack: Redis token buckets, Postgres bans, cross-instance propagation.

    docker compose up -d --wait && uv run pytest -m integration

IPs are random addresses in 198.18.0.0/15 (reserved for benchmarking) and user IDs are random, so
repeated runs never collide with state left by earlier runs.
"""

from __future__ import annotations

import random
import time
import uuid

import httpx
import pytest
from fastapi.testclient import TestClient

from app.main import create_app
from tests.integration.test_stack import ADMIN_KEY, GATEWAY_URL, msg, new_key, settings

pytestmark = pytest.mark.integration
ADMIN = {"x-admin-key": ADMIN_KEY}


def rand_ip() -> str:
    return f"198.{random.randint(18, 19)}.{random.randint(0, 255)}.{random.randint(1, 254)}"  # noqa: S311


def rand_user() -> str:
    return f"user-{uuid.uuid4().hex[:12]}"


def wait_for(fn, timeout: float = 3.0, interval: float = 0.05):
    deadline = time.monotonic() + timeout
    value = fn()
    while time.monotonic() < deadline and not value:
        time.sleep(interval)
        value = fn()
    return value


def test_real_redis_token_bucket_throttles_and_isolates_users() -> None:
    with TestClient(create_app(settings=settings(rl_user_capacity=3, rl_user_refill_per_sec=0.01))) as c:
        _k, key = new_key(c)
        auth = {"authorization": f"Bearer {key}"}
        user, other = rand_user(), rand_user()
        actions = [
            c.post("/v1/inspect", json=msg(user_id=user), headers=auth).json()["action"] for _ in range(4)
        ]
        assert actions == ["allow", "allow", "allow", "throttle"]
        other_action = c.post("/v1/inspect", json=msg(user_id=other), headers=auth).json()["action"]
        assert other_action == "allow"


def test_ban_created_on_one_instance_blocks_on_another_within_a_second() -> None:
    with TestClient(create_app(settings=settings())) as a, TestClient(create_app(settings=settings())) as b:
        _k, key = new_key(a)
        auth = {"authorization": f"Bearer {key}"}
        user = rand_user()
        assert b.post("/v1/inspect", json=msg(user_id=user), headers=auth).json()["action"] == "allow"

        started = time.monotonic()
        ban = a.post(
            "/admin/bans",
            json={
                "entity_type": "user",
                "value": user,
                "reason": "integration",
                "duration_seconds": 300,
            },
            headers=ADMIN,
        )
        assert ban.status_code == 201, ban.text

        def blocked_on_b() -> bool:
            body = b.post("/v1/inspect", json=msg(user_id=user), headers=auth).json()
            return body["action"] == "block"

        assert wait_for(blocked_on_b, timeout=1.0), "instance B did not pick up the ban via Redis pub/sub"
        propagation = time.monotonic() - started

        assert a.delete(f"/admin/bans/{ban.json()['id']}", headers=ADMIN).status_code == 200
        assert wait_for(lambda: not blocked_on_b(), timeout=1.0), "unban did not propagate"
        assert propagation < 1.0


def test_throttle_abuse_escalates_to_an_auto_ban_recorded_in_postgres() -> None:
    """A chat that keeps hammering after being throttled: its session is struck and banned."""
    cfg = settings(rl_session_capacity=1, rl_session_refill_per_sec=0.01, throttle_strike_count=3)
    with TestClient(create_app(settings=cfg)) as c:
        _k, key = new_key(c)
        auth = {"authorization": f"Bearer {key}"}
        session, ip = f"it-{uuid.uuid4().hex[:12]}", rand_ip()
        for _ in range(4):  # 1 allowed, then 3 throttled → 3rd throttle is a strike
            c.post("/v1/inspect", json=msg(ip=ip, session_id=session), headers=auth)

        bans = c.get("/admin/bans", params={"entity_type": "session", "value": session}, headers=ADMIN).json()
        assert len(bans) == 1
        assert bans[0]["source"] == "auto" and bans[0]["permanent"] is False
        assert bans[0]["evidence"]["last_reason"] == "rate_limit_abuse"
        d = c.post("/v1/inspect", json=msg(ip=ip, session_id=session), headers=auth).json()
        assert d["reasons"] == ["banned"] and d["cmp_action"] == "retry_later"  # a 60 s ban
        # The IP was not charged: other chats from it are unaffected.
        assert c.post("/v1/inspect", json=msg(ip=ip), headers=auth).json()["action"] == "allow"

        rep = c.get(
            "/admin/reputation", params={"entity_type": "session", "value": session}, headers=ADMIN
        ).json()
        assert rep["strikes"]["total"] == 1
        assert rep["recent_strikes"][0]["reason"] == "rate_limit_abuse"
        assert rep["active_ban"] is not None


def test_short_ban_expires_without_any_reload() -> None:
    with TestClient(create_app(settings=settings())) as c:
        _k, key = new_key(c)
        auth = {"authorization": f"Bearer {key}"}
        user = rand_user()
        c.post(
            "/admin/bans",
            json={
                "entity_type": "user",
                "value": user,
                "reason": "short",
                "duration_seconds": 1,
            },
            headers=ADMIN,
        )
        assert c.post("/v1/inspect", json=msg(user_id=user), headers=auth).json()["action"] == "block"
        time.sleep(1.2)
        assert c.post("/v1/inspect", json=msg(user_id=user), headers=auth).json()["action"] == "allow"


def test_bruteforce_from_one_ip_is_banned_before_auth() -> None:
    with TestClient(create_app(settings=settings(auth_fail_strike_count=5, trusted_proxy_count=1))) as c:
        _k, key = new_key(c)
        attacker = {"x-forwarded-for": rand_ip()}
        for _ in range(5):
            c.post(
                "/v1/inspect",
                json=msg(),
                headers={**attacker, "authorization": "Bearer cmpsk_0123456789_guess"},
            )
        res = c.post("/v1/inspect", json=msg(), headers={**attacker, "authorization": f"Bearer {key}"})
        assert res.status_code == 403
        bans = c.get(
            "/admin/bans", params={"entity_type": "ip", "value": attacker["x-forwarded-for"]}, headers=ADMIN
        ).json()
        assert bans[0]["evidence"]["last_reason"] == "auth_bruteforce"


def test_blacklist_import_and_cidr_ban_against_real_db() -> None:
    with TestClient(create_app(settings=settings())) as c:
        _k, key = new_key(c)
        auth = {"authorization": f"Bearer {key}"}
        ips = [rand_ip() for _ in range(3)]
        res = c.post(
            "/admin/blacklists",
            json={"entity_type": "ip", "values": [*ips, "nope"], "reason": "feed"},
            headers=ADMIN,
        )
        assert res.json()["inserted"] == 3 and len(res.json()["invalid"]) == 1
        for ip in ips:
            assert c.post("/v1/inspect", json=msg(ip=ip), headers=auth).json()["action"] == "block"

        net = f"198.19.{random.randint(0, 255)}.0/24"  # noqa: S311
        c.post(
            "/admin/bans",
            json={"entity_type": "cidr", "value": net, "reason": "range", "duration_seconds": 60},
            headers=ADMIN,
        )
        inside = net.replace(".0/24", ".77")
        assert c.post("/v1/inspect", json=msg(ip=inside), headers=auth).json()["action"] == "block"


def test_end_to_end_ban_through_the_gateway_container() -> None:
    with httpx.Client(base_url=GATEWAY_URL, timeout=5) as c:
        _k, key = new_key(c)
        auth = {"authorization": f"Bearer {key}"}
        user = rand_user()
        assert c.post("/v1/inspect", json=msg(user_id=user), headers=auth).json()["action"] == "allow"
        c.post(
            "/admin/bans",
            json={
                "entity_type": "user",
                "value": user,
                "reason": "e2e",
                "duration_seconds": 60,
            },
            headers=ADMIN,
        )
        assert c.post("/v1/inspect", json=msg(user_id=user), headers=auth).json()["action"] == "block"
        proxied = c.post("/v1/ai/chat", json={"message": "hi"}, headers={**auth, "x-end-user-id": user})
        assert proxied.status_code == 403
