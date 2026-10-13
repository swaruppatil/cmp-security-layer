"""Integration tests against the docker compose stack.

    docker compose up -d --wait
    uv run pytest -m integration

Two layers:
* in-process apps wired to the real Redis / Postgres / mock-ai (published host ports), which covers
  the SQL, migrations and cross-instance cache invalidation;
* end-to-end HTTP calls to the gateway container itself.
"""

from __future__ import annotations

import os
import socket
import time
import uuid

import httpx
import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app

pytestmark = pytest.mark.integration

ADMIN_KEY = os.environ.get("ADMIN_API_KEY", "change-me-admin-key")
HOST = {
    "redis_url": os.environ.get("IT_REDIS_URL", "redis://localhost:16379"),
    "database_url": os.environ.get("IT_DATABASE_URL", "postgresql://sec:sec@localhost:15432/security"),
    "ml_url": os.environ.get("IT_ML_URL", "http://localhost:18000"),
    "upstream_ai_url": os.environ.get("IT_UPSTREAM_URL", "http://localhost:19000"),
}
GATEWAY_URL = os.environ.get("IT_GATEWAY_URL", "http://localhost:18080")


def _port_open(url: str) -> bool:
    hostport = url.split("//", 1)[1].split("/", 1)[0].rsplit("@", 1)[-1]
    host, port = hostport.rsplit(":", 1)
    try:
        with socket.create_connection((host, int(port)), timeout=0.5):
            return True
    except OSError:
        return False


@pytest.fixture(scope="module", autouse=True)
def stack_running() -> None:
    missing = [name for name, url in {**HOST, "gateway": GATEWAY_URL}.items() if not _port_open(url)]
    if missing:
        pytest.skip(f"docker compose stack not reachable: {missing}")


def settings(**overrides: object) -> Settings:
    values: dict[str, object] = {"admin_api_key": ADMIN_KEY, "max_prompt_chars": 200, **HOST}
    values.update(overrides)
    return Settings(**values)  # type: ignore[arg-type]


def admin() -> dict[str, str]:
    return {"x-admin-key": ADMIN_KEY}


def new_key(client: TestClient | httpx.Client, scopes: list[str] | None = None) -> tuple[str, str]:
    """A fresh caller key (id, plaintext). Each test uses its own, so its events can be found by key."""
    created = client.post(
        "/admin/api-keys",
        json={"name": f"it-{uuid.uuid4().hex[:10]}", "scopes": scopes or ["inspect", "outbound", "proxy"]},
        headers=admin(),
    )
    assert created.status_code == 201, created.text
    return created.json()["id"], created.json()["api_key"]


def sid(prefix: str = "it") -> str:
    """A session id no earlier run used (sessions carry memory, buckets, strikes and bans)."""
    return f"{prefix}-{uuid.uuid4().hex[:12]}"


def end_user() -> dict[str, str]:
    """Proxy-mode identity headers. Local proxy calls all come from Docker's host address; naming the
    user (and the chat) means each test is judged on its own record, not on that shared address."""
    return {"x-end-user-id": f"it-user-{uuid.uuid4().hex[:8]}", "x-session-id": sid()}


def msg(text: str = "hi", user_id: str | None = None, session_id: str | None = None, **extra: object) -> dict:
    """An inspect body: a new session unless one is given; ``user_id`` becomes CMP's customer id."""
    body: dict[str, object] = {"session_id": session_id or sid(), "message": text, **extra}
    if user_id:
        body["customer_id"] = user_id
    return body


# ------------------------------------------------------------------ in-process, real stores
def test_full_flow_against_real_postgres_redis_and_mock_ai() -> None:
    with TestClient(create_app(settings=settings())) as c:
        assert c.get("/ready").status_code == 200
        key_id, key = new_key(c)
        auth = {"authorization": f"Bearer {key}"}

        session = sid()
        started = c.post("/v1/sessions/" + session + "/start", json={"channel": "web"}, headers=auth)
        assert started.status_code == 200
        decision = c.post("/v1/inspect", json=msg("Can I change my seat?", session_id=session), headers=auth)
        assert decision.status_code == 200
        assert decision.json()["action"] == "allow" and decision.json()["cmp_action"] == "deliver"
        assert c.post("/v1/sessions/" + session + "/end", headers=auth).json()["existed"] is True

        proxied = c.post("/v1/ai/chat", json={"message": "hello"}, headers={**auth, **end_user()})
        assert proxied.status_code == 200, proxied.text
        body = proxied.json()
        assert body["reply"] == "Mock assistant received 5 characters."
        assert body["security"]["decision"] == "allow"
        assert body["received_gateway_credentials"] is False

        blocked = c.post("/v1/ai/chat", json={"message": "x" * 300}, headers={**auth, **end_user()})
        assert blocked.status_code == 403

        keys = c.get("/admin/api-keys", headers=admin()).json()
        mine = next(k for k in keys if k["id"] == key_id)
        assert mine["last_used_at"] is not None
        assert "key_hash" not in mine

        assert c.delete(f"/admin/api-keys/{key_id}", headers=admin()).status_code == 200
        assert c.post("/v1/inspect", json=msg(), headers=auth).status_code == 401


def test_revocation_reaches_other_gateway_instances_via_redis() -> None:
    """Instance B has the key cached; revoking it through instance A must evict it from B."""
    with (
        TestClient(create_app(settings=settings(auth_cache_ttl_seconds=300))) as a,
        TestClient(create_app(settings=settings(auth_cache_ttl_seconds=300))) as b,
    ):
        key_id, key = new_key(a)
        auth = {"authorization": f"Bearer {key}"}
        assert b.post("/v1/inspect", json=msg(), headers=auth).status_code == 200  # cached in B
        lookups_before = b.app.state.auth.lookups

        assert a.delete(f"/admin/api-keys/{key_id}", headers=admin()).status_code == 200

        deadline = time.monotonic() + 3
        status = 200
        while time.monotonic() < deadline:
            status = b.post("/v1/inspect", json=msg(), headers=auth).status_code
            if status == 401:
                break
            time.sleep(0.05)
        assert status == 401, "instance B kept serving a revoked key from its cache"
        assert b.app.state.auth.lookups > lookups_before


def test_scopes_against_real_db() -> None:
    with TestClient(create_app(settings=settings())) as c:
        _kid, key = new_key(c, scopes=["inspect"])
        auth = {"x-api-key": key}
        assert c.post("/v1/ai/chat", json={"message": "hi"}, headers=auth).status_code == 403  # no proxy
        assert c.post("/v1/inspect", json=msg(), headers=auth).status_code == 200
        reply = {"session_id": sid(), "reply": "ok"}
        assert c.post("/v1/inspect/outbound", json=reply, headers=auth).status_code == 403  # no outbound


def test_tenants_are_gone_from_the_schema() -> None:
    import asyncio

    import asyncpg

    async def check() -> None:
        conn = await asyncpg.connect(HOST["database_url"])
        try:
            assert await conn.fetchval("SELECT to_regclass('public.tenants')") is None
            cols = {
                r["column_name"]
                for r in await conn.fetch(
                    "SELECT column_name FROM information_schema.columns "
                    "WHERE table_schema = 'public' AND column_name = 'tenant_id'"
                )
            }
            assert cols == set()
        finally:
            await conn.close()

    asyncio.run(check())


def test_migrations_are_idempotent() -> None:
    import asyncio

    from app.db.migrate import migrate

    assert asyncio.run(migrate(HOST["database_url"])) == []


# ------------------------------------------------------------------ end to end, gateway container
def test_end_to_end_through_the_gateway_container() -> None:
    with httpx.Client(base_url=GATEWAY_URL, timeout=5) as c:
        assert c.get("/health").json()["status"] == "ok"
        assert c.get("/ready").status_code == 200
        _kid, key = new_key(c)
        res = c.post(
            "/v1/ai/chat",
            json={"message": "hello there"},
            headers={"authorization": f"Bearer {key}", **end_user()},
        )
        assert res.status_code == 200, res.text
        assert res.json()["security"]["decision"] == "allow"
        assert res.headers["x-security-request-id"]
        assert c.post("/v1/inspect", json=msg()).status_code == 401
