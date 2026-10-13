"""Stage 3 through the HTTP API: throttling, bans, blacklists, brute force, reputation."""

import pytest
from fastapi.testclient import TestClient

from app.main import create_app
from tests.fakes import ADMIN_KEY, FakeRepo, make_deps, make_settings

ADMIN = {"x-admin-key": ADMIN_KEY}


def client_for(repo: FakeRepo, deps=None, **settings) -> TestClient:
    app = create_app(
        settings=make_settings(**settings), deps=deps or make_deps(), repo=repo, background_tasks=False
    )
    return TestClient(app)


@pytest.fixture
def repo() -> FakeRepo:
    return FakeRepo()


@pytest.fixture
def key(repo):
    return repo.add_key()


def bearer(k):
    return {"authorization": f"Bearer {k}"}


def inspect(c, k, user_id=None, session_id=None, **body):
    payload = {"session_id": session_id or f"s-{user_id or 'anon'}", "message": "hello", **body}
    if user_id:
        payload["customer_id"] = user_id
    return c.post("/v1/inspect", json=payload, headers=bearer(k))


def customer(c, raw):
    """The stored (hashed) form of a CMP customer id."""
    return c.app.state.sessions.customer(raw)


# ------------------------------------------------------------------ rate limiting
def test_inspect_returns_throttle_decision_when_bucket_is_empty(repo, key):
    with client_for(repo, rl_ip_capacity=2, rl_ip_refill_per_sec=0.01) as c:
        actions = [inspect(c, key, ip="203.0.113.9").json()["action"] for _ in range(3)]
        assert actions == ["allow", "allow", "throttle"]
        throttled = inspect(c, key, ip="203.0.113.9").json()
        assert throttled["reasons"] == ["rate_limited"]
        assert throttled["retry_after_seconds"] >= 1
        # A different end user is unaffected.
        assert inspect(c, key, ip="203.0.113.10").json()["action"] == "allow"


def test_proxy_throttle_returns_429_with_retry_after_and_no_details(repo, key):
    with client_for(repo, rl_api_key_capacity=1, rl_api_key_refill_per_sec=0.01) as c:
        assert c.post("/v1/ai/chat", json={"message": "hi"}, headers=bearer(key)).status_code == 200
        res = c.post("/v1/ai/chat", json={"message": "hi"}, headers=bearer(key))
        assert res.status_code == 429
        assert int(res.headers["retry-after"]) >= 1
        assert "api_key" not in res.text  # which bucket fired is not revealed


def test_redis_outage_fails_open_by_default(repo, key):
    deps = make_deps()

    async def broken(*_a, **_k):
        raise ConnectionError("redis down")

    with client_for(repo, deps=deps) as c:
        c.app.state.admission._script = broken
        body = inspect(c, key).json()
        assert body["action"] == "allow"
        admission = next(x for x in body["checks"] if x["name"] == "admission")
        assert admission["detail"]["degraded"] is True


def test_redis_outage_can_fail_closed(repo, key):
    with client_for(repo, rate_limit_failure_mode="closed") as c:

        async def broken(*_a, **_k):
            raise ConnectionError("redis down")

        c.app.state.admission._script = broken
        assert inspect(c, key).json()["action"] == "throttle"


# ------------------------------------------------------------------ bans
def test_admin_ban_blocks_the_end_user_immediately_and_unban_restores(repo, key):
    with client_for(repo) as c:
        assert inspect(c, key, user_id="u1").json()["action"] == "allow"
        ban = c.post(
            "/admin/bans",
            json={
                "entity_type": "user",
                "value": "u1",
                "reason": "abuse",
                "duration_seconds": 600,
            },
            headers=ADMIN,
        )
        assert ban.status_code == 201, ban.text
        assert ban.json()["value"] == customer(c, "u1")  # the raw customer id is never stored
        blocked = inspect(c, key, user_id="u1").json()
        assert blocked["action"] == "block" and blocked["reasons"] == ["banned"]
        assert inspect(c, key, user_id="u2").json()["action"] == "allow"

        proxied = c.post(
            "/v1/ai/chat", json={"message": "hi"}, headers={**bearer(key), "x-end-user-id": "u1"}
        )
        assert proxied.status_code == 403
        assert "banned" not in proxied.text  # the end client is not told it is banned

        assert c.delete(f"/admin/bans/{ban.json()['id']}", headers=ADMIN).status_code == 200
        assert inspect(c, key, user_id="u1").json()["action"] == "allow"


def test_session_ban_ends_the_contact(repo, key):
    with client_for(repo) as c:
        ban = c.post(
            "/admin/bans",
            json={"entity_type": "session", "value": "contact-1", "reason": "abuse", "permanent": True},
            headers=ADMIN,
        )
        assert ban.status_code == 201
        d = inspect(c, key, session_id="contact-1").json()
        assert d["reasons"] == ["banned"] and d["cmp_action"] == "end_contact"
        assert inspect(c, key, session_id="contact-2").json()["action"] == "allow"


def test_cidr_ban_applies_to_every_caller(repo, key):
    other_key = repo.add_key()
    with client_for(repo) as c:
        res = c.post(
            "/admin/bans",
            json={"entity_type": "cidr", "value": "198.51.100.7/24", "reason": "range", "permanent": True},
            headers=ADMIN,
        )
        assert res.status_code == 201
        assert res.json()["value"] == "198.51.100.0/24"  # normalised
        assert inspect(c, key, ip="198.51.100.250").json()["action"] == "block"
        assert inspect(c, other_key, ip="198.51.100.250").json()["action"] == "block"  # global
        assert inspect(c, key, ip="198.51.101.1").json()["action"] == "allow"


@pytest.mark.parametrize(
    "body",
    [
        {"entity_type": "tenant", "value": "t1", "reason": "r", "duration_seconds": 60},  # no such type
        {"entity_type": "cidr", "value": "0.0.0.0/0", "reason": "r", "permanent": True},  # too broad
        {"entity_type": "ip", "value": "not-an-ip", "reason": "r", "permanent": True},
        {"entity_type": "ip", "value": "1.2.3.4", "reason": "r"},  # neither duration nor permanent
        {"entity_type": "ip", "value": "1.2.3.4", "reason": "r", "permanent": True, "duration_seconds": 5},
    ],
)
def test_ban_validation(repo, body):
    with client_for(repo) as c:
        assert c.post("/admin/bans", json=body, headers=ADMIN).status_code == 422


def test_blacklist_import_reports_invalid_values(repo, key):
    with client_for(repo) as c:
        res = c.post(
            "/admin/blacklists",
            json={
                "entity_type": "ip",
                "reason": "feed",
                "values": ["203.0.113.1", "203.0.113.1", "bogus", "203.0.113.2"],
            },
            headers=ADMIN,
        )
        assert res.status_code == 201
        assert res.json()["inserted"] == 2
        assert [i["value"] for i in res.json()["invalid"]] == ["bogus"]
        assert inspect(c, key, ip="203.0.113.2").json()["action"] == "block"
        listed = c.get("/admin/bans", params={"entity_type": "ip"}, headers=ADMIN).json()
        assert {b["source"] for b in listed} == {"blacklist"}


def test_ban_endpoints_require_admin(repo):
    with client_for(repo) as c:
        assert c.get("/admin/bans").status_code == 401
        assert c.post("/admin/bans", json={}).status_code == 401


# ------------------------------------------------------------------ brute force (pre-auth)
def test_bad_key_flood_bans_the_ip_before_auth(repo, key):
    with client_for(repo, auth_fail_strike_count=3, trusted_proxy_count=1) as c:
        attacker = {"x-forwarded-for": "198.51.100.66"}
        for _ in range(3):
            assert (
                c.post(
                    "/v1/inspect",
                    json={"session_id": "s-anon-9", "message": "hi"},
                    headers={**attacker, "authorization": "Bearer cmpsk_0123456789_wrong"},
                ).status_code
                == 401
            )
        # Now even a *valid* key from that IP is refused before it is checked.
        res = c.post(
            "/v1/inspect",
            json={"session_id": "s-anon-10", "message": "hi"},
            headers={**attacker, **bearer(key)},
        )
        assert res.status_code == 403
        # Other IPs are unaffected.
        ok = c.post(
            "/v1/inspect",
            json={"session_id": "s-anon-11", "message": "hi"},
            headers={"x-forwarded-for": "203.0.113.5", **bearer(key)},
        )
        assert ok.status_code == 200
        banned = c.get(
            "/admin/bans", params={"entity_type": "ip", "value": "198.51.100.66"}, headers=ADMIN
        ).json()
        assert banned[0]["source"] == "auto" and "tenant_id" not in banned[0]


# ------------------------------------------------------------------ reputation
def test_poor_reputation_restricts_and_proxy_tells_the_app(repo, key):
    with client_for(repo, reputation_restrict_at=20) as c:
        import asyncio

        from app.entities import Entity

        rep = c.app.state.reputation
        c.portal.call(rep.record, Entity("user", customer(c, "u9")), "attack")  # score 25
        body = inspect(c, key, user_id="u9").json()
        assert body["action"] == "restrict"
        assert body["reasons"] == ["poor_reputation"]

        res = c.post("/v1/ai/chat", json={"message": "hi"}, headers={**bearer(key), "x-end-user-id": "u9"})
        assert res.status_code == 200
        assert res.json()["headers"]["x-security-restricted"] == "true"
        del asyncio


def test_reputation_endpoint(repo, key):
    with client_for(repo, rl_user_capacity=1, rl_user_refill_per_sec=0.01) as c:
        inspect(c, key, user_id="u5")
        inspect(c, key, user_id="u5")  # throttled → reputation +5 (background task)
        snap = c.get(
            "/admin/reputation",
            params={"entity_type": "user", "value": "u5"},
            headers=ADMIN,
        ).json()
        assert snap["score"] == pytest.approx(5, abs=0.1)
        assert snap["events"] == {"throttled": 1}
        assert snap["active_ban"] is None


def test_unban_with_clear_history_forgets_reputation(repo, key):
    with client_for(repo) as c:
        from app.entities import Entity

        c.portal.call(c.app.state.reputation.record, Entity("user", customer(c, "u7")), "attack")
        ban = c.post(
            "/admin/bans",
            json={
                "entity_type": "user",
                "value": "u7",
                "reason": "r",
                "duration_seconds": 60,
            },
            headers=ADMIN,
        ).json()
        c.delete(f"/admin/bans/{ban['id']}", params={"clear_history": "true"}, headers=ADMIN)
        snap = c.get(
            "/admin/reputation",
            params={"entity_type": "user", "value": "u7"},
            headers=ADMIN,
        ).json()
        assert snap["score"] == 0


def test_clear_reputation_endpoint(repo, key):
    with client_for(repo) as c:
        from app.entities import Entity

        c.portal.call(c.app.state.reputation.record, Entity("ip", "203.0.113.77"), "attack")
        res = c.delete(
            "/admin/reputation", params={"entity_type": "ip", "value": "203.0.113.77"}, headers=ADMIN
        )
        assert res.status_code == 200
        snap = c.get(
            "/admin/reputation", params={"entity_type": "ip", "value": "203.0.113.77"}, headers=ADMIN
        )
        assert snap.json()["score"] == 0
        assert (
            c.delete(
                "/admin/reputation", params={"entity_type": "ip", "value": "x"}, headers=ADMIN
            ).status_code
            == 422
        )
