"""Route tests through the real FastAPI app, with fake Redis/Postgres/upstream."""

import asyncio
from collections.abc import Iterator

import httpx
import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.deps import Probe
from app.main import create_app
from tests.fakes import ADMIN_KEY, FakeRepo, make_deps, make_settings, upstream_echo

ADMIN = {"x-admin-key": ADMIN_KEY}
HI = {"session_id": "s1", "message": "hi"}


@pytest.fixture
def repo() -> FakeRepo:
    return FakeRepo()


def client_for(repo: FakeRepo, deps=None, **settings) -> TestClient:
    app = create_app(
        settings=make_settings(**settings), deps=deps or make_deps(), repo=repo, background_tasks=False
    )
    return TestClient(app)


@pytest.fixture
def client(repo: FakeRepo) -> Iterator[TestClient]:
    with client_for(repo) as c:
        yield c


def bearer(key: str) -> dict[str, str]:
    return {"authorization": f"Bearer {key}"}


# ---------------------------------------------------------------- health / ready
def test_health(client):
    res = client.get("/health")
    assert res.status_code == 200
    assert res.json()["service"] == "gateway"
    assert "x-request-id" in res.headers


def test_ready_ok(client):
    res = client.get("/ready")
    assert res.status_code == 200
    assert set(res.json()["checks"]) == {"redis", "postgres", "ml-service"}


def test_ready_reports_failing_and_hanging_dependencies(repo):
    async def boom():
        raise ConnectionError("refused")

    async def hang():
        await asyncio.sleep(10)

    deps = make_deps(probes=[Probe("postgres", boom), Probe("ml-service", hang)])
    with client_for(repo, deps=deps) as c:
        res = c.get("/ready")
    assert res.status_code == 503
    checks = res.json()["checks"]
    assert checks["postgres"] == {"ok": False, "error": "refused", "ms": checks["postgres"]["ms"]}
    assert "timeout" in checks["ml-service"]["error"]


# ---------------------------------------------------------------- inspect
def test_inspect_requires_a_valid_key(client, repo):
    assert client.post("/v1/inspect", json=HI).status_code == 401
    assert client.post("/v1/inspect", json=HI, headers=bearer("cmpsk_0123456789_nope")).status_code == 401
    res = client.post("/v1/inspect", json=HI, headers={"x-api-key": "garbage"})
    assert res.status_code == 401
    assert res.json() == {"detail": {"error": "unauthorized"}}  # no reason leaked


def test_inspect_requires_inspect_scope(client, repo):
    key = repo.add_key(scopes=("proxy",))
    assert client.post("/v1/inspect", json=HI, headers=bearer(key)).status_code == 403


def test_inspect_allows_normal_message(client, repo):
    key = repo.add_key()
    res = client.post(
        "/v1/inspect",
        json={"message": "Where is my bag?", "session_id": "c1", "ip": "203.0.113.9"},
        headers={**bearer(key), "x-request-id": "req-123"},
    )
    assert res.status_code == 200
    body = res.json()
    assert body["action"] == "allow"
    assert body["request_id"] == "req-123"
    assert [c["name"] for c in body["checks"]] == [
        "ban",
        "bot",
        "admission",
        "size",
        "conversation_memory",
        "rules",
        "ml",
        "conversation",
    ]
    assert res.headers["x-request-id"] == "req-123"
    assert body["cmp_action"] == "deliver" and body["session_state"] == "anonymous"


def test_inspect_requires_a_session_id(client, repo):
    key = repo.add_key()
    res = client.post("/v1/inspect", json={"message": "hi"}, headers=bearer(key))
    assert res.status_code == 422
    bad = client.post("/v1/inspect", json={"message": "hi", "session_id": "a b/c"}, headers=bearer(key))
    assert bad.status_code == 422


def test_inspect_blocks_oversized_message(client, repo):
    key = repo.add_key()
    res = client.post("/v1/inspect", json={"session_id": "s1", "message": "x" * 51}, headers=bearer(key))
    assert res.status_code == 200
    assert res.json()["action"] == "block"
    assert res.json()["reasons"] == ["message_too_long"]
    assert res.json()["cmp_action"] == "refuse"


def test_size_limit_depends_on_the_channel(repo):
    key = repo.add_key()
    with client_for(repo, max_prompt_chars=4000, channel_max_chars="sms:100") as c:
        long = {"session_id": "s1", "message": "where is my bag " * 10}
        assert c.post("/v1/inspect", json=long, headers=bearer(key)).json()["action"] == "allow"
        sms = c.post("/v1/inspect", json={**long, "channel": "sms"}, headers=bearer(key)).json()
    assert sms["reasons"] == ["message_too_long"]
    assert sms["checks"][-1]["detail"]["limit"] == 100


def test_validation_errors_do_not_echo_input(client, repo):
    key = repo.add_key()
    res = client.post(
        "/v1/inspect", json={"session_id": "s", "messag": "secret-value-123"}, headers=bearer(key)
    )
    assert res.status_code == 422
    assert "secret-value-123" not in res.text


def test_body_over_limit_rejected_before_parsing(repo):
    key = repo.add_key()
    with client_for(repo, max_body_bytes=100) as c:
        res = c.post(
            "/v1/inspect",
            content=b'{"session_id":"s","message":"' + b"x" * 200 + b'"}',
            headers={**bearer(key), "content-type": "application/json"},
        )
    assert res.status_code == 413


# ---------------------------------------------------------------- proxy
def test_proxy_forwards_allowed_request_without_gateway_credentials(client, repo):
    key = repo.add_key()
    res = client.post("/v1/ai/chat", json={"message": "hello"}, headers={**bearer(key), "x-custom": "kept"})
    assert res.status_code == 200
    seen = res.json()
    assert seen["path"] == "/v1/ai/chat"
    assert seen["body"] == '{"message":"hello"}'
    assert "authorization" not in seen["headers"]
    assert "x-api-key" not in seen["headers"]
    assert seen["headers"]["x-custom"] == "kept"
    assert seen["headers"]["x-security-decision"] == "allow"
    assert seen["headers"]["x-security-restricted"] == "false"
    assert res.headers["x-security-request-id"] == seen["headers"]["x-security-request-id"]


def test_proxy_blocked_request_never_reaches_upstream(repo):
    calls = []

    def handler(request):
        calls.append(request)
        return upstream_echo(request)

    key = repo.add_key()
    with client_for(repo, deps=make_deps(upstream=handler)) as c:
        res = c.post(
            "/v1/ai/chat", json={"messages": [{"role": "user", "content": "x" * 60}]}, headers=bearer(key)
        )
    assert res.status_code == 403
    assert res.json()["error"] == "request_blocked"
    assert "message_too_long" not in res.text  # reason not revealed to the end client
    assert calls == []


def test_proxy_requires_proxy_scope(client, repo):
    key = repo.add_key(scopes=("inspect",))
    assert client.post("/v1/ai/chat", json={"message": "hi"}, headers=bearer(key)).status_code == 403


def test_proxy_get_without_body_is_forwarded(client, repo):
    key = repo.add_key()
    res = client.get("/v1/ai/models?x=1", headers=bearer(key))
    assert res.status_code == 200
    assert res.json()["method"] == "GET"


def test_proxy_invalid_json_rejected(client, repo):
    key = repo.add_key()
    res = client.post(
        "/v1/ai/chat", content=b"{not json", headers={**bearer(key), "content-type": "application/json"}
    )
    assert res.status_code == 400


@pytest.mark.parametrize(
    ("error", "status"),
    [(httpx.ConnectError("down"), 502), (httpx.ReadTimeout("slow"), 504)],
)
def test_proxy_upstream_failures(repo, error, status):
    def handler(_request):
        raise error

    key = repo.add_key()
    with client_for(repo, deps=make_deps(upstream=handler)) as c:
        res = c.post("/v1/ai/chat", json={"message": "hi"}, headers=bearer(key))
    assert res.status_code == status


def test_proxy_passes_upstream_status_through(repo):
    key = repo.add_key()
    deps = make_deps(upstream=lambda r: httpx.Response(418, json={"teapot": True}))
    with client_for(repo, deps=deps) as c:
        res = c.post("/v1/ai/chat", json={"message": "hi"}, headers=bearer(key))
    assert res.status_code == 418
    assert res.json() == {"teapot": True}


# ---------------------------------------------------------------- admin
def test_admin_requires_admin_key(client):
    assert client.get("/admin/api-keys").status_code == 401
    assert client.get("/admin/api-keys", headers={"x-admin-key": "wrong-key-000"}).status_code == 401
    assert client.get("/admin/api-keys", headers=ADMIN).status_code == 200


def test_admin_key_lifecycle(client):
    created = client.post("/admin/api-keys", json={"name": "enricher", "scopes": ["inspect"]}, headers=ADMIN)
    assert created.status_code == 201
    key = created.json()["api_key"]
    assert key.startswith("cmpsk_")
    assert "key_hash" not in created.json()
    assert "tenant_id" not in created.json()

    listed = client.get("/admin/api-keys", headers=ADMIN).json()
    assert "api_key" not in listed[0] and "key_hash" not in listed[0]  # plaintext shown only once

    assert client.post("/v1/inspect", json=HI, headers=bearer(key)).status_code == 200
    # "inspect" alone does not allow checking AI replies
    reply = {"session_id": "s1", "reply": "ok"}
    assert client.post("/v1/inspect/outbound", json=reply, headers=bearer(key)).status_code == 403

    revoked = client.delete(f"/admin/api-keys/{created.json()['id']}", headers=ADMIN)
    assert revoked.status_code == 200
    # Rejected immediately, even though it was cached a moment ago.
    assert client.post("/v1/inspect", json=HI, headers=bearer(key)).status_code == 401
    assert client.app.state.deps.redis.published, "revocation must be broadcast to other instances"


def test_default_scopes_cover_both_cmp_calls(client):
    key = client.post("/admin/api-keys", json={"name": "cmp"}, headers=ADMIN).json()
    assert key["scopes"] == ["inspect", "outbound"]
    reply = {"session_id": "s1", "reply": "ok"}
    assert client.post("/v1/inspect/outbound", json=reply, headers=bearer(key["api_key"])).status_code == 200


def test_no_tenant_endpoints(client):
    assert client.get("/admin/tenants", headers=ADMIN).status_code == 404


def test_admin_validation(client):
    bad_scope = client.post("/admin/api-keys", json={"name": "k", "scopes": ["root"]}, headers=ADMIN)
    assert bad_scope.status_code == 422
    assert client.post("/admin/api-keys", json={"name": ""}, headers=ADMIN).status_code == 422


def test_bootstrap_key_is_created_once(repo):
    from app.auth.keys import generate_key

    new = generate_key()
    with client_for(repo, bootstrap_api_key=new.plaintext) as c:
        assert c.post("/v1/inspect", json=HI, headers=bearer(new.plaintext)).status_code == 200
    with client_for(repo, bootstrap_api_key=new.plaintext):
        pass
    assert [k["name"] for k in repo.keys.values()] == ["cmp"]


# ---------------------------------------------------------------- config
def test_config_requires_admin_key():
    from app.config import Settings

    with pytest.raises(ValidationError):
        Settings(_env_file=None)  # type: ignore[call-arg]


def test_config_rejects_invalid_failure_mode():
    with pytest.raises(ValidationError):
        make_settings(ml_failure_mode="yolo")
