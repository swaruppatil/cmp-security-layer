"""Post-decision bookkeeping: reputation, strikes, automatic bans; and the Redis event listener."""

import uuid

from app.auth.keys import hash_key
from app.auth.models import Principal
from app.auth.service import INVALIDATION_CHANNEL, AuthService
from app.bans.index import Subject
from app.bans.service import BANS_CHANNEL, BanService
from app.entities import Entity
from app.pipeline.after import AfterDecision
from app.pipeline.context import RequestContext
from app.pipeline.models import Action, CheckResult, Decision
from app.reputation.service import ReputationService
from app.state.events import listen_events
from app.state.shared_ip import SharedIpTracker
from tests.fakes import FakeRedis, FakeRepo, make_settings

PRINCIPAL = Principal(uuid.uuid4(), "cmp", "0123456789", frozenset({"inspect"}))


def setup(**settings):
    s = make_settings(**settings)
    redis, repo = FakeRedis(), FakeRepo()
    rep = ReputationService(redis, s)
    bans = BanService(repo, redis, s)
    return AfterDecision(rep, bans, s, shared_ip=SharedIpTracker(redis, s)), rep, bans, repo


def ctx(**kw):
    base = {
        "request_id": "r1",
        "principal": PRINCIPAL,
        "text": "x",
        "endpoint": "chat",
        "ip": "203.0.113.9",
        "user_id": "u1",
    }
    base.update(kw)
    return RequestContext(**base)


def decision(action, *checks, reasons=()):
    return Decision(
        request_id="r1", action=action, risk=1.0, reasons=list(reasons), checks=list(checks), latency_ms=0.1
    )


USER = Entity("user", "u1")
IP = Entity("ip", "203.0.113.9")
SESSION = Entity("session", "contact-1")


ATTACK = CheckResult(
    name="rules",
    passed=False,
    action=Action.BLOCK,
    reason="instruction_override",
    strike=True,
    evidence="deterministic",
)


def attack_decision():
    return decision(Action.BLOCK, ATTACK, reasons=["instruction_override"])


async def test_identified_attack_is_charged_to_the_user_not_the_shared_ip():
    after, rep, bans, repo = setup()
    await after(ctx(), attack_decision())
    assert (await rep.snapshot(USER))["score"] == 25
    assert (await rep.snapshot(USER))["strikes"] == {"total": 1, "deterministic": 1}
    assert bans.match(Subject(user_id="u1")) is not None
    # The IP may be an airport's Wi-Fi: other people behind it are not affected.
    assert bans.match(Subject(ip="203.0.113.9")) is None
    assert (await rep.snapshot(IP))["score"] == 0
    assert {s["entity_type"] for s in repo.strikes} == {"user"}


async def test_attack_in_a_session_strikes_the_session_and_the_customer():
    after, rep, bans, repo = setup()
    await after(ctx(session_id="contact-1"), attack_decision())
    assert {s["entity_type"] for s in repo.strikes} == {"user", "session"}
    assert bans.match(Subject(session_id="contact-1")) is not None
    assert (await rep.snapshot(SESSION))["strikes"]["total"] == 1
    assert bans.match(Subject(ip="203.0.113.9")) is None


async def test_anonymous_customer_in_a_session_is_not_charged_to_the_ip():
    """A session is a personal identity: an anonymous chat's attack costs the session, not the IP."""
    after, _rep, bans, repo = setup()
    await after(ctx(user_id=None, session_id="contact-2"), attack_decision())
    assert {s["entity_type"] for s in repo.strikes} == {"session"}
    assert bans.match(Subject(ip="203.0.113.9")) is None


async def test_anonymous_attack_is_charged_to_the_ip():
    after, rep, bans, repo = setup()
    await after(ctx(user_id=None), attack_decision())
    assert bans.match(Subject(ip="203.0.113.9")) is not None
    assert {s["entity_type"] for s in repo.strikes} == {"ip"}


async def test_many_attackers_from_one_unshared_ip_get_the_ip_struck():
    """One attacker rotating user ids: the third different identity striking from the IP bans the IP."""
    after, _rep, bans, _repo = setup()
    for i in range(2):
        await after(ctx(user_id=f"fake-{i}"), attack_decision())
        assert bans.match(Subject(ip="203.0.113.9")) is None
    await after(ctx(user_id="fake-2"), attack_decision())
    assert bans.match(Subject(ip="203.0.113.9")) is not None


async def test_a_shared_ip_is_never_banned_for_its_users_attacks():
    after, _rep, bans, _repo = setup()
    for user in ("alice", "bob", "carol"):  # normal customers behind the same Wi-Fi
        await after(ctx(user_id=user), decision(Action.ALLOW))
    for i in range(5):
        await after(ctx(user_id=f"attacker-{i}"), attack_decision())
    assert bans.match(Subject(ip="203.0.113.9")) is None
    assert bans.match(Subject(user_id="attacker-4")) is not None


async def test_attacker_ids_do_not_count_as_good_users():
    """Inventing user ids cannot make an IP look shared: only allowed traffic counts."""
    after, _rep, _bans, _repo = setup()
    tracker = after._shared
    for i in range(5):
        await after(ctx(user_id=f"fake-{i}"), attack_decision())
    assert await tracker.users("203.0.113.9") == 0


async def test_automatic_ip_bans_are_never_permanent():
    after, _rep, bans, _repo = setup()
    for i in range(5):
        await after(ctx(user_id=None, request_id=f"r{i}"), attack_decision())
    ban = bans.match(Subject(ip="203.0.113.9"))
    assert ban is not None and not ban.permanent


async def test_non_attack_block_only_nudges_reputation():
    after, rep, bans, repo = setup()
    size = CheckResult(name="size", passed=False, action=Action.BLOCK, reason="message_too_long")
    await after(ctx(), decision(Action.BLOCK, size, reasons=["message_too_long"]))
    assert (await rep.snapshot(USER))["score"] == 2
    assert repo.strikes == [] and repo.bans == {}


async def test_already_banned_requests_are_not_double_counted():
    after, rep, *_ = setup()
    banned = CheckResult(name="ban", passed=False, action=Action.BLOCK, reason="banned")
    await after(ctx(), decision(Action.BLOCK, banned, reasons=["banned"]))
    assert (await rep.snapshot(USER))["score"] == 0


async def test_repeated_throttling_becomes_a_strike():
    after, rep, bans, repo = setup(throttle_strike_count=3)
    throttled = decision(
        Action.THROTTLE,
        CheckResult(name="admission", passed=False, action=Action.THROTTLE, reason="rate_limited"),
        reasons=["rate_limited"],
    )
    for _ in range(2):
        await after(ctx(), throttled)
    assert repo.strikes == []
    await after(ctx(), throttled)
    assert {s["reason"] for s in repo.strikes} == {"rate_limit_abuse"}
    assert bans.match(Subject(user_id="u1")) is not None
    assert (await rep.snapshot(USER))["events"]["throttled"] == 3


async def test_allowed_requests_change_nothing():
    after, rep, *_ = setup()
    await after(ctx(), decision(Action.ALLOW))
    assert (await rep.snapshot(USER))["score"] == 0


async def test_auth_bruteforce_bans_the_ip_globally():
    after, rep, bans, repo = setup(auth_fail_strike_count=3)
    for _ in range(3):
        await after.record_auth_failure("198.51.100.4", "r")
    hit = bans.match(Subject(ip="198.51.100.4"))
    assert hit is not None and hit.entity_type == "ip"
    assert repo.strikes[-1]["reason"] == "auth_bruteforce"


async def test_auth_failures_from_non_ip_clients_are_ignored():
    after, _rep, _bans, repo = setup(auth_fail_strike_count=1)
    await after.record_auth_failure("testclient", "r")
    assert repo.strikes == []


async def test_bookkeeping_failures_never_raise():
    after, rep, *_ = setup()

    async def broken(*_a, **_k):
        raise ConnectionError("redis down")

    rep.record = broken  # type: ignore[method-assign]
    attack = CheckResult(name="rules", passed=False, action=Action.BLOCK, reason="x", strike=True)
    await after(ctx(), decision(Action.BLOCK, attack, reasons=["x"]))  # must not raise
    await after.record_auth_failure("198.51.100.4", "r")


# ------------------------------------------------------------------ event listener
class ScriptedPubSub:
    def __init__(self, messages):
        self.messages = messages
        self.closed = False

    async def subscribe(self, *channels):
        self.channels = channels

    async def listen(self):
        for m in self.messages:
            yield m
        raise ConnectionError("connection dropped")  # ends the test via CancelledError below

    async def aclose(self):
        self.closed = True


class ScriptedRedis:
    def __init__(self, pubsub):
        self._pubsub = pubsub

    def pubsub(self):
        return self._pubsub


async def test_listener_dispatches_auth_and_ban_events():
    import asyncio

    repo = FakeRepo()
    key = repo.add_key()
    auth = AuthService(repo, ttl_seconds=60, negative_ttl_seconds=5, max_entries=10)
    await auth.authenticate(key)
    for k in repo.keys.values():
        k["status"] = "revoked"
    bans = BanService(repo, FakeRedis(), make_settings())
    await repo.create_ban(
        entity_type="ip",
        value="203.0.113.9",
        reason="r",
        source="manual",
        evidence={},
        permanent=True,
        expires_at=None,
        created_by="admin",
    )

    pubsub = ScriptedPubSub(
        [
            {"type": "subscribe", "channel": INVALIDATION_CHANNEL, "data": 1},
            {"type": "message", "channel": INVALIDATION_CHANNEL.encode(), "data": hash_key(key).encode()},
            {"type": "message", "channel": BANS_CHANNEL.encode(), "data": b"1"},
        ]
    )
    task = asyncio.create_task(listen_events(ScriptedRedis(pubsub), auth, bans))
    await asyncio.sleep(0.05)
    task.cancel()

    assert bans.match(Subject(ip="203.0.113.9")) is not None  # ban reload happened
    assert pubsub.closed
    import pytest

    from app.auth.service import AuthError

    with pytest.raises(AuthError):
        await auth.authenticate(key)  # cache entry dropped


async def test_blocked_ai_reply_strikes_the_session_not_the_customer():
    after, _rep, bans, repo = setup()
    leak = CheckResult(
        name="reply_data",
        passed=False,
        action=Action.BLOCK,
        reason="secret_in_reply",
        strike=True,
        evidence="probabilistic",
    )
    out = ctx(session_id="contact-7", direction="outbound", mode="outbound")
    for _ in range(3):
        await after(out, decision(Action.BLOCK, leak, reasons=["secret_in_reply"]))
    assert {s["entity_type"] for s in repo.strikes} == {"session"}
    assert bans.match(Subject(user_id="u1")) is None and repo.bans == {}


async def test_canary_leak_still_strikes_the_customer():
    after, _rep, bans, repo = setup()
    canary = CheckResult(
        name="canary",
        passed=False,
        action=Action.BLOCK,
        reason="canary_leak",
        strike=True,
        evidence="deterministic",
    )
    out = ctx(session_id="contact-8", direction="outbound", mode="outbound")
    await after(out, decision(Action.BLOCK, canary, reasons=["canary_leak"]))
    assert {s["entity_type"] for s in repo.strikes} == {"user", "session"}
    assert bans.match(Subject(user_id="u1")) is not None


async def test_an_anonymous_chats_attacks_are_banned_progressively():
    """Rules + ML agree on an attack (probabilistic, two signals): the session climbs the ladder."""
    after, rep, bans, repo = setup(ban_ladder_seconds=[60, 300, 3600])
    rules = CheckResult(
        name="rules",
        passed=False,
        action=Action.BLOCK,
        reason="instruction_override",
        strike=True,
        evidence="probabilistic",
    )
    ml = CheckResult(
        name="ml",
        passed=False,
        action=Action.BLOCK,
        reason="ml_injection",
        strike=True,
        evidence="probabilistic",
    )
    anon = ctx(session_id="contact-9", user_id=None)
    await after(anon, decision(Action.BLOCK, rules, ml, reasons=["instruction_override", "ml_injection"]))
    first = bans.match(Subject(session_id="contact-9"))
    assert first is not None and not first.permanent
    assert (await rep.snapshot(Entity("session", "contact-9")))["strikes"]["total"] == 1
    await after(anon, decision(Action.BLOCK, rules, ml, reasons=["instruction_override", "ml_injection"]))
    second = bans.match(Subject(session_id="contact-9"))
    assert second is not None and second.expires_at > first.expires_at  # 5 minutes now, not 1
    assert (
        len(
            [
                b
                for b in repo.bans.values()
                if b.get("session_id") == "contact-9" or b.get("value") == "contact-9"
            ]
        )
        >= 1
    )
    assert bans.match(Subject(ip="203.0.113.9")) is None  # the address is not charged for one chat
