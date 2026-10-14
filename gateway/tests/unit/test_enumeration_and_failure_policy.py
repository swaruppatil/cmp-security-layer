"""Identifier enumeration (many different booking references from one chat or IP) and the failure
policy for sensitive endpoints (state unavailable → restrict)."""

from __future__ import annotations

from fastapi.testclient import TestClient

from app.main import create_app
from tests.fakes import ADMIN_KEY, FakeRepo, make_deps, make_settings, ml_scores

ADMIN = {"x-admin-key": ADMIN_KEY}
REFS = [f"AB{chr(67 + i)}{100 + i}" for i in range(14)]  # ABC100, ABD101, … distinct booking refs


def client(**overrides):
    repo = FakeRepo()
    key = repo.add_key()
    app = create_app(
        settings=make_settings(**{"max_prompt_chars": 4000, "bot_enabled": False, **overrides}),
        deps=make_deps(ml=ml_scores()),
        repo=repo,
        background_tasks=False,
    )
    return TestClient(app), {"authorization": f"Bearer {key}"}, repo


def say(c, auth, session, text, **extra):
    body = {"session_id": session, "message": text, **extra}
    return c.post("/v1/inspect", json=body, headers=auth).json()


def detail(d, name):
    return next((x["detail"] for x in d["checks"] if x["name"] == name), None)


# ------------------------------------------------------------------ enumeration
def test_guessing_booking_references_in_one_chat_is_restricted():
    c, auth, _repo = client()
    with c:
        for ref in REFS[:3]:
            d = say(c, auth, "guess-1", f"What is the status of booking {ref}?")
            assert d["action"] == "allow", d["reasons"]
        d = say(c, auth, "guess-1", f"What is the status of booking {REFS[3]}?")
    assert d["action"] == "restrict" and d["reasons"] == ["identifier_enumeration"]
    assert d["cmp_action"] == "forward_without_tools"  # the AI cannot look anything up
    assert detail(d, "enumeration")["counts"]["session"]["booking_ref"] == 4


def test_the_same_reference_again_and_again_is_not_enumeration():
    c, auth, _repo = client()
    with c:
        for _ in range(6):
            d = say(c, auth, "same-1", f"Any news on booking {REFS[0]}?")
            assert d["action"] == "allow"
    assert detail(d, "enumeration")["counts"]["session"]["booking_ref"] == 1


def test_messages_without_identifiers_skip_the_check():
    c, auth, _repo = client()
    with c:
        d = say(c, auth, "none-1", "Is my flight on time?")
    assert "enumeration" not in {x["name"] for x in d["checks"]}


def test_a_verified_customers_own_bookings_never_count():
    c, auth, _repo = client()
    with c:
        c.post(
            "/v1/sessions/own-1/identity",
            json={"verified": True, "identifiers": {"booking_ref": REFS[:5]}},
            headers=auth,
        )
        for ref in REFS[:5]:
            d = say(c, auth, "own-1", f"Can you check booking {ref}?")
            assert d["action"] == "allow", d["reasons"]


def test_eight_references_in_one_chat_are_blocked_and_the_chat_is_banned_briefly():
    c, auth, repo = client()
    with c:
        results = [say(c, auth, "guess-2", f"Status of booking {ref}?") for ref in REFS[:8]]
        assert [r["action"] for r in results[3:7]] == ["restrict"] * 4
        last = results[7]
        assert last["action"] == "block" and last["reasons"] == ["identifier_enumeration"]
        # a strike on the session: the chat takes the ladder's first step (1 minute), nobody else
        assert say(c, auth, "guess-2", "Is my flight on time?")["reasons"] == ["banned"]
    assert {s["entity_type"] for s in repo.strikes} == {"session"}
    assert {b["entity_type"] for b in repo.bans.values()} == {"session"}


def test_one_ip_trying_references_across_many_chats_is_restricted():
    c, auth, _repo = client()
    with c:
        results = [
            say(c, auth, f"ipguess-{i}", f"Status of booking {ref}?", ip="198.51.100.40")
            for i, ref in enumerate(REFS[:12])
        ]
    assert all(r["action"] == "allow" for r in results[:11])
    assert results[11]["action"] == "restrict" and results[11]["reasons"] == ["identifier_enumeration"]
    assert detail(results[11], "enumeration")["counts"]["ip"]["booking_ref"] == 12


def test_shared_and_never_ban_ips_are_not_counted_per_ip():
    c, auth, _repo = client(never_ban_cidrs="127.0.0.0/8,10.0.0.0/8")
    with c:
        # a known shared address: three customers chatted normally from it
        for user in ("a", "b", "c"):
            say(c, auth, f"wifi-{user}", "Is my flight on time?", ip="203.0.113.60", customer_id=user)
        shared = [
            say(c, auth, f"wifi-chat-{i}", f"Status of booking {ref}?", ip="203.0.113.60")
            for i, ref in enumerate(REFS[:13])
        ]
        trusted = [
            say(c, auth, f"nat-{i}", f"Status of booking {ref}?", ip="10.1.2.3")
            for i, ref in enumerate(REFS[:13])
        ]
    assert all(r["action"] == "allow" for r in shared + trusted)
    assert detail(shared[-1], "enumeration")["ip_counted"] is False
    assert detail(trusted[-1], "enumeration")["ip_counted"] is False


def test_enumeration_can_be_switched_off():
    c, auth, _repo = client(enum_enabled=False)
    with c:
        for ref in REFS[:6]:
            d = say(c, auth, "off-1", f"Status of booking {ref}?")
    assert d["action"] == "allow" and detail(d, "enumeration") is None


# ------------------------------------------------------------------ failure policy
async def _broken(*_a, **_k):
    raise ConnectionError("redis down")


def _break_redis(c):
    """Every Redis-backed part of the request path fails, as when Redis is down."""
    c.app.state.admission._script = _broken
    c.app.state.sessions.get = _broken
    c.app.state.conversations.load = _broken


def test_sensitive_endpoint_is_restricted_when_state_is_unavailable():
    c, auth, _repo = client()
    with c:
        _break_redis(c)
        d = say(c, auth, "down-1", "Please change my booking to tomorrow", endpoint="booking-changes")
    assert d["action"] == "restrict" and d["reasons"] == ["state_unavailable"]
    assert d["cmp_action"] == "forward_without_tools"
    assert set(detail(d, "failure_policy")["degraded"]) >= {
        "admission",
        "conversation_memory",
        "session_store",
    }


def test_ordinary_chat_carries_on_when_state_is_unavailable():
    c, auth, _repo = client()
    with c:
        _break_redis(c)
        d = say(c, auth, "down-2", "Is my flight on time?")
    assert d["action"] == "allow" and "failure_policy" not in {x["name"] for x in d["checks"]}


def test_sensitive_endpoint_carries_on_when_everything_is_up():
    c, auth, _repo = client()
    with c:
        d = say(c, auth, "up-1", "Please change my booking to tomorrow", endpoint="booking-changes")
    assert d["action"] == "allow" and "failure_policy" not in {x["name"] for x in d["checks"]}


def test_one_unavailable_dependency_is_enough():
    c, auth, _repo = client()
    with c:
        c.app.state.sessions.get = _broken  # only the session record cannot be read
        d = say(c, auth, "down-3", "I want a refund", endpoint="refunds")
    assert d["reasons"] == ["state_unavailable"] and detail(d, "failure_policy")["degraded"] == [
        "session_store"
    ]


def test_failure_mode_can_block_or_allow():
    c, auth, _repo = client(degraded_sensitive_action="block")
    with c:
        _break_redis(c)
        d = say(c, auth, "down-4", "Change my booking please", endpoint="booking-changes")
    assert d["action"] == "block" and d["reasons"] == ["state_unavailable"]
    c, auth, _repo = client(degraded_sensitive_action="allow")
    with c:
        _break_redis(c)
        d = say(c, auth, "down-5", "Change my booking please", endpoint="booking-changes")
    assert d["action"] == "allow" and detail(d, "failure_policy")["mode"] == "allow"


def test_a_policy_can_mark_an_endpoint_sensitive_and_cannot_override_the_safety_rule():
    c, auth, _repo = client()
    with c:
        c.post(
            "/admin/policies",
            json={"name": "loyalty", "endpoint_pattern": "loyalty", "sensitive": True, "mode": "monitor"},
            headers=ADMIN,
        )
        _break_redis(c)
        d = say(c, auth, "down-6", "Move my points to my spouse", endpoint="loyalty")
    # sensitive by policy; monitor mode does not turn this safety restriction into "allow"
    assert d["action"] == "restrict" and d["reasons"] == ["state_unavailable"] and d["would_have"] is None


def test_enumeration_counter_down_counts_as_degraded(monkeypatch):
    from app.state.enumeration import EnumerationTracker

    monkeypatch.setattr(EnumerationTracker, "note", _broken)
    c, auth, _repo = client()
    with c:
        d = say(c, auth, "down-7", "Change booking ABC123 please", endpoint="booking-changes")
    assert detail(d, "enumeration") == {"unavailable": True}
    assert d["reasons"] == ["state_unavailable"] and "enumeration" in detail(d, "failure_policy")["degraded"]
