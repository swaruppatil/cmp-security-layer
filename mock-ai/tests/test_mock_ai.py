import json

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_health():
    assert client.get("/health").json()["status"] == "ok"


def test_chat_echoes_security_headers():
    res = client.post(
        "/v1/ai/chat",
        json={"message": "hello"},
        headers={"x-security-decision": "restrict", "x-security-restricted": "true"},
    )
    body = res.json()
    assert body["reply"] == "Mock assistant received 5 characters."
    assert body["security"]["restricted"] is True
    assert body["received_gateway_credentials"] is False


def test_leak_test_returns_reply_and_scope_header():
    plain = client.post("/v1/ai/leak-test", json={"reply": "hello"})
    assert plain.json() == {"reply": "hello"} and "x-security-allowed-identifiers" not in plain.headers
    scoped = client.post(
        "/v1/ai/leak-test", json={"reply": "x", "allowed_identifiers": {"booking_ref": ["ABC123"]}}
    )
    assert json.loads(scoped.headers["x-security-allowed-identifiers"]) == {"booking_ref": ["ABC123"]}
