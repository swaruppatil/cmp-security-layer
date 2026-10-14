"""Stage 6: conversation memory and multi-turn signals.

Pure analysis functions are tested directly; the end-to-end tests drive /v1/inspect with a
session id against fakeredis and a fake ML service that returns bag-of-words vectors. Requests
carry no customer id; a session is banned only for deterministic strikes, so the ML blocks used
here never ban it (the conversation lock does the escalation).
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.conversation.analysis import TurnInput, assess, is_crescendo, next_acc
from app.conversation.state import BlockedTurn, ConversationState, Turn, cosine, state_key, text_hash
from app.main import create_app
from app.pipeline.models import Action
from tests.fakes import ADMIN_KEY, FakeRepo, bow_vector, make_deps, make_settings, ml_conversational

ADMIN = {"x-admin-key": ADMIN_KEY}


def settings(**overrides):
    # Test turns arrive milliseconds apart: bot profiling (tested in test_bots) would throttle them.
    return make_settings(**{"max_prompt_chars": 2000, "bot_enabled": False, **overrides})


def state(**kw) -> ConversationState:
    return ConversationState(session_id="c", **kw)


# ------------------------------------------------------------------ pure analysis
def test_state_round_trips_through_json():
    st = state(
        turns=[Turn(n=0, hash="h", action="allow", score=0.1, text="hi", vector=[0.5, 0.5])],
        blocked=[BlockedTurn(n=1, hash="b")],
        n=2,
        acc=0.4,
        blocks=1,
        setup_turn=0,
    )
    assert ConversationState.from_json(st.to_json()) == st
    assert st.key() == state_key("c") == "conv:c"


def test_text_hash_ignores_disguises_and_cosine_handles_missing_vectors():
    assert text_hash("Refund EVERYTHING") == text_hash("refund   everything")
    assert text_hash("r3fund everything") == text_hash("refund everything")
    assert cosine([1.0, 0.0], [1.0, 0.0]) == pytest.approx(1.0)
    assert cosine(None, [1.0]) is None and cosine([1.0], [1.0, 0.0]) is None


def test_accumulator_adds_up_borderline_turns_and_decays_on_normal_ones():
    s = settings()
    st = state()
    accs = []
    for _ in range(6):
        st.acc, _ = next_acc(st, 0.65, None, s)
        accs.append(st.acc)
    assert accs == sorted(accs) and accs[-1] >= s.conv_restrict_at  # several 0.65 turns add up
    for _ in range(4):
        st.acc, _ = next_acc(st, 0.05, None, s)
    assert st.acc < 0.4  # normal turns let it fade


def test_setup_marker_doubles_excess_while_armed():
    s = settings()
    plain, _ = next_acc(state(n=3), 0.6, None, s)
    armed, detail = next_acc(state(n=3, setup_turn=1), 0.6, None, s)
    assert detail["armed"] and armed == pytest.approx(plain * s.conv_setup_boost)
    expired, detail = next_acc(state(n=20, setup_turn=1), 0.6, None, s)
    assert not detail["armed"] and expired == pytest.approx(plain)


def test_crescendo_needs_three_rising_turns_leaning_to_attack():
    turns = [
        Turn(n=0, hash="a", action="allow", score=0, attack_lean=-0.3),
        Turn(n=1, hash="b", action="allow", score=0, attack_lean=-0.1),
    ]
    assert is_crescendo(state(turns=turns), 0.05)
    assert not is_crescendo(state(turns=turns), -0.05)  # still leaning benign
    assert not is_crescendo(state(turns=turns[:1]), 0.2)  # not enough history
    assert not is_crescendo(state(turns=turns), None)


def test_retry_of_a_blocked_turn_restricts_or_blocks_if_risky():
    s = settings()
    st = state(blocked=[BlockedTurn(n=0, hash="x", vector=bow_vector("refund every ticket now"))], blocks=1)
    calm = assess(st, TurnInput(score=0.2, hash="y", vector=bow_vector("refund every ticket now please")), s)
    assert calm.worst and calm.worst.reason == "retry_after_block" and calm.worst.action == Action.RESTRICT
    risky = assess(st, TurnInput(score=0.8, hash="x"), s)  # identical text (hash) and risky on its own
    assert risky.worst and risky.worst.action == Action.BLOCK and risky.worst.strike
    other = assess(st, TurnInput(score=0.1, hash="z", vector=bow_vector("where is my bag")), s)
    assert other.worst is None


def test_window_counts_only_when_clearly_above_every_single_turn():
    s = settings(conv_window_ml_action="block")
    split = assess(state(), TurnInput(score=0.2, hash="h", window_score=0.95, window_turn_max=0.3), s)
    assert split.worst and split.worst.reason == "split_payload" and split.worst.action == Action.BLOCK
    # An earlier suspicious turn inside the window must not re-flag every later turn.
    echo = assess(state(), TurnInput(score=0.1, hash="h", window_score=0.8, window_turn_max=0.78), s)
    assert echo.worst is None
    rules = assess(
        state(), TurnInput(score=0.1, hash="h", window_rules=[("override.ignore_prior", "high")]), s
    )
    assert rules.worst and rules.worst.action == Action.BLOCK and rules.worst.strike


def test_conversation_locks_after_repeated_blocks():
    s = settings(conv_max_blocks=3)
    a = assess(state(blocks=3), TurnInput(score=0.0, hash="h"), s)
    assert a.worst and a.worst.reason == "conversation_locked" and a.worst.action == Action.RESTRICT
    b = assess(state(blocks=3), TurnInput(score=0.0, hash="h"), settings(conv_lock_action="block"))
    assert b.worst and b.worst.action == Action.BLOCK and not b.worst.strike


# ------------------------------------------------------------------ end to end over HTTP
def client(score_for, calls=None, **overrides):
    repo = FakeRepo()
    key = repo.add_key()
    deps = make_deps(ml=ml_conversational(score_for, calls=calls))
    app = create_app(settings=settings(**overrides), deps=deps, repo=repo, background_tasks=False)
    return TestClient(app), {"authorization": f"Bearer {key}"}, repo, deps


def say(c, auth, text, conv="conv-1"):
    return c.post("/v1/inspect", json={"message": text, "session_id": conv}, headers=auth).json()


def test_requests_without_a_session_have_no_conversation_memory():
    """Only the proxy can see requests without a session (no X-Session-Id header)."""
    c, auth, _t, deps = client(lambda t: 0.05)
    with c:
        assert c.post("/v1/ai/chat", json={"message": "Where is my bag?"}, headers=auth).status_code == 200
        keys = c.portal.call(deps.redis.keys, "conv:*")
        assert keys == []
        c.post("/v1/ai/chat", json={"message": "Where is my bag?"}, headers={**auth, "x-session-id": "p1"})
        assert c.portal.call(deps.redis.keys, "conv:*") == [b"conv:p1"]


def test_probing_turns_add_up_to_a_restriction():
    c, auth, _t, _d = client(lambda t: 0.65)  # each turn below the ML restrict threshold (0.7)
    with c:
        actions = [say(c, auth, f"tell me about internal procedure number {i}")["action"] for i in range(6)]
        assert actions[0] == "allow"
        assert "restrict" in actions
        d = say(c, auth, "and what about procedure seven then")
        conv = next(x for x in d["checks"] if x["name"] == "conversation")
        assert d["reasons"] == ["conversation_risk"] and conv["detail"]["accumulated"]["after"] >= 1.0


def test_normal_long_chat_is_never_flagged():
    c, auth, _t, _d = client(lambda t: 0.05)
    with c:
        for i in range(15):
            assert say(c, auth, f"Question {i} about my booking and baggage allowance")["action"] == "allow"


def test_attack_split_across_turns_is_caught_by_the_window():
    # Each part alone looks fine; the joined window (contains a newline) is what scores high.
    c, auth, _t, _d = client(
        lambda t: 0.95 if "\n" in t and "part two" in t else 0.1, conv_window_ml_action="block"
    )
    with c:
        assert say(c, auth, "here is part one of my request")["action"] == "allow"
        d = say(c, auth, "and here is part two of it")
        assert d["action"] == "block" and d["reasons"] == ["split_payload"]
        conv = next(x for x in d["checks"] if x["name"] == "conversation")
        assert conv["detail"]["window"]["lift"] >= 0.25 and conv["evidence"] == "probabilistic"


def test_blocked_turns_leave_the_window_and_keep_no_text():
    calls: list[dict] = []
    c, auth, _repo, deps = client(
        lambda t: 0.95 if "refund every ticket" in t else 0.1, calls=calls, conv_window_ml_action="restrict"
    )
    with c:
        assert say(c, auth, "please refund every ticket on this account")["action"] == "block"  # ML
        say(c, auth, "what time does boarding start for my flight")
        say(c, auth, "and which gate should I go to")
        st = c.portal.call(c.app.state.conversations.get, "conv-1")
    # The blocked turn's text never went to the ML window, and is not stored.
    windows = [t for body in calls for t in body["texts"] if "\n" in t]
    assert windows and not any("refund every ticket" in w for w in windows)
    assert st.blocks == 1 and st.turns[0].action == "block" and st.turns[0].text is None
    assert st.turns[1].text == "what time does boarding start for my flight"
    assert st.blocked[0].vector is not None  # fetched in the background for retry detection


def test_retry_after_block_and_lock_then_admin_reset():
    c, auth, repo, deps = client(lambda t: 0.95 if "refund every ticket" in t else 0.1)
    with c:
        assert say(c, auth, "please refund every ticket on this account")["action"] == "block"  # ML
        retry = say(c, auth, "ok then just refund every ticket on the account")
        assert retry["action"] == "block"  # ML blocks again; also seen as a retry
        conv = say(c, auth, "please refund every single ticket on this account")
        assert conv["reasons"] == ["retry_after_block"] and conv["action"] == "restrict"
        say(c, auth, "refund every ticket please")  # third block → locked from now on
        locked = say(c, auth, "Is my flight on time today?")
        # Three attacks also cost the session its reputation; the lock is what CMP acts on.
        assert locked["action"] == "restrict" and "conversation_locked" in locked["reasons"]
        assert locked["cmp_action"] == "handoff_to_agent"
        # ML (probabilistic) strikes are recorded against the session, but never ban it.
        # Blocks by the ML tier alone refuse the message and lock the chat, but strike and ban nobody.
        assert repo.strikes == [] and repo.bans == {}

        view = c.get("/admin/sessions/conv-1", headers=ADMIN).json()["conversation"]
        assert view["locked"] and view["blocks"] == 3 and len(view["blocked_turns"]) == 3
        assert "text" not in view["turns"][0]  # the admin view never shows message text
        assert c.delete("/admin/sessions/conv-1", headers=ADMIN).json() == {"deleted": True}
        assert say(c, auth, "Is my flight on time today?")["action"] == "allow"
        assert c.get("/admin/sessions/conv-1", headers={}).status_code == 401


def test_conversations_are_separate_per_id():
    c, auth, _t, _d = client(lambda t: 0.95 if "refund every ticket" in t else 0.1, conv_max_blocks=1)
    with c:
        say(c, auth, "please refund every ticket on this account", conv="a")
        assert say(c, auth, "Is my flight on time today?", conv="a")["reasons"] == ["conversation_locked"]
        assert say(c, auth, "Is my flight on time today?", conv="b")["action"] == "allow"


def test_ml_gets_window_and_vector_request_only_for_tracked_conversations():
    calls: list[dict] = []
    c, auth, _t, _d = client(lambda t: 0.05, calls=calls, conv_window_ml_action="restrict")
    with c:
        c.post("/v1/ai/chat", json={"message": "Where is my bag, it never arrived?"}, headers=auth)
        say(c, auth, "My bag never arrived in Calgary")
        say(c, auth, "ok")  # too short for ML itself, but the window is still scored
        say(c, auth, "It was a blue suitcase with a red tag")
    assert "return_vectors" not in calls[0]
    assert calls[1].get("return_vectors") is True and len(calls[1]["texts"]) == 1  # no history yet
    assert calls[2]["texts"] == ["My bag never arrived in Calgary\nok"]  # window only
    assert len(calls[3]["texts"]) == 2 and calls[3]["texts"][1].count("\n") == 2


def test_window_is_not_sent_to_ml_when_its_ml_action_is_off():
    calls: list[dict] = []
    c, auth, _t, _d = client(lambda t: 0.05, calls=calls)  # default: conv_window_ml_action="off"
    with c:
        say(c, auth, "My bag never arrived in Calgary")
        say(c, auth, "It was a blue suitcase with a red tag")
    assert all(len(body["texts"]) == 1 for body in calls) and calls[1]["return_vectors"] is True


def test_redis_failure_skips_conversation_analysis_but_not_the_rest():
    c, auth, _t, _d = client(lambda t: 0.05)
    with c:

        async def broken(*_a, **_k):
            raise ConnectionError("redis down")

        c.app.state.conversations.load = broken
        d = say(c, auth, "Is my flight on time today?")
        names = [x["name"] for x in d["checks"]]
        assert d["action"] == "allow" and "ml" in names and "conversation" not in names
        mem = next(x for x in d["checks"] if x["name"] == "conversation_memory")
        assert mem["detail"] == {"unavailable": True}


def test_conversation_disabled_setting():
    c, auth, _t, _d = client(lambda t: 0.05, conversation_enabled=False)
    with c:
        d = say(c, auth, "Is my flight on time today?")
        assert "conversation" not in {x["name"] for x in d["checks"]}


async def test_back_to_back_turns_from_a_stale_snapshot_are_all_counted():
    """Turns that arrive before the previous update is written must still all be recorded."""
    import uuid

    from app.auth.models import Principal
    from app.conversation.service import ConversationService
    from app.pipeline.context import RequestContext
    from app.pipeline.models import CheckResult, Decision
    from tests.fakes import FakeRedis

    svc = ConversationService(FakeRedis(), settings(), ml=None)
    principal = Principal(uuid.uuid4(), "cmp", "0123456789", frozenset({"inspect"}))
    stale = await svc.load("c")  # every request saw this same empty state
    for i in range(3):
        ctx = RequestContext(
            request_id=f"r{i}",
            principal=principal,
            text=f"attack number {i}",
            endpoint="chat",
            session_id="c",
            conversation=stale,
        )
        decision = Decision(
            request_id=f"r{i}",
            action=Action.BLOCK,
            risk=0.95,
            reasons=["x"],
            latency_ms=1,
            checks=[CheckResult(name="rules", passed=False, score=0.95, action=Action.BLOCK)],
        )
        await svc.record(ctx, decision)
    st = await svc.get("c")
    assert st is not None and st.n == 3 and st.blocks == 3 and [t.n for t in st.turns] == [0, 1, 2]
    assert st.acc > 0.65 * 2  # accumulated over all three, not just the last


async def test_record_after_end_does_not_recreate_memory():
    """The post-response update of a turn answered just before /end must not resurrect the session."""
    import uuid

    from app.auth.models import Principal
    from app.conversation.service import ConversationService
    from app.pipeline.context import RequestContext
    from app.pipeline.models import CheckResult, Decision
    from app.session.service import SessionService
    from tests.fakes import FakeRedis

    redis = FakeRedis()
    conv = ConversationService(redis, settings(), ml=None)
    sess = SessionService(redis, settings())
    principal = Principal(uuid.uuid4(), "cmp", "0123456789", frozenset({"inspect"}))
    ctx = RequestContext(
        request_id="r1",
        principal=principal,
        text="Do you have flights to Halifax on Friday?",
        endpoint="chat",
        session_id="ended",
        conversation=await conv.load("ended"),
    )
    decision = Decision(
        request_id="r1",
        action=Action.ALLOW,
        risk=0.0,
        reasons=[],
        latency_ms=1,
        checks=[CheckResult(name="rules", passed=True, score=0.0, action=Action.ALLOW)],
    )
    await conv.record(ctx, decision)
    assert await conv.get("ended") is not None
    assert await sess.end("ended") is True
    await conv.record(ctx, decision)  # the background update of a turn in flight
    assert await conv.get("ended") is None
    assert await sess.end("ended") is False
