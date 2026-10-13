"""Token buckets + reputation read, running the real Lua script on fakeredis."""

import asyncio

import pytest

from app.entities import Entity
from app.reputation.service import ReputationService
from app.state.admission import AdmissionService, Bucket
from tests.fakes import FakeRedis, make_settings


@pytest.fixture
def redis():
    return FakeRedis()


def svc(redis, **settings):
    s = make_settings(**settings)
    return AdmissionService(redis, s), ReputationService(redis, s)


async def test_bucket_allows_burst_then_throttles(redis):
    admission, _ = svc(redis)
    bucket = [Bucket("ip", "rl:t:ip:1.2.3.4", capacity=3, refill_per_sec=0.1)]
    results = [await admission.admit(bucket, []) for _ in range(4)]
    assert [r.allowed for r in results] == [True, True, True, False]
    denied = results[-1]
    assert denied.limited_by == "ip"
    assert 9 < denied.retry_after_seconds <= 10  # one token at 0.1/s


async def test_refused_request_spends_no_tokens_in_other_buckets(redis):
    admission, _ = svc(redis)
    small = Bucket("user", "rl:t:user:u1", capacity=1, refill_per_sec=0.01)
    big = Bucket("global", "rl:global", capacity=100, refill_per_sec=0.01)
    assert (await admission.admit([big, small], [])).allowed
    refused = await admission.admit([big, small], [])
    assert not refused.allowed and refused.limited_by == "user"
    # The global bucket was not charged for the refused request.
    assert refused.remaining["global"] == pytest.approx(99, abs=0.01)


async def test_bucket_refills_over_time(redis):
    admission, _ = svc(redis)
    bucket = [Bucket("ip", "rl:t:ip:9.9.9.9", capacity=1, refill_per_sec=20)]
    assert (await admission.admit(bucket, [])).allowed
    assert not (await admission.admit(bucket, [])).allowed
    await asyncio.sleep(0.1)  # 20/s → 2 tokens' worth, capped at capacity 1
    assert (await admission.admit(bucket, [])).allowed


async def test_buckets_are_independent_per_key(redis):
    admission, _ = svc(redis)
    a = [Bucket("ip", "rl:t:ip:1.1.1.1", capacity=1, refill_per_sec=0.01)]
    b = [Bucket("ip", "rl:t:ip:2.2.2.2", capacity=1, refill_per_sec=0.01)]
    assert (await admission.admit(a, [])).allowed
    assert (await admission.admit(b, [])).allowed
    assert not (await admission.admit(a, [])).allowed


async def test_reputation_is_read_in_the_same_call(redis):
    admission, reputation = svc(redis)
    user = Entity("user", "u1")
    other = Entity("user", "u2")
    await reputation.record(user, "attack")
    await reputation.record(user, "attack")
    result = await admission.admit([Bucket("global", "rl:global", 10, 1)], [user, other])
    assert result.reputation[user.key()] == pytest.approx(50, abs=0.1)
    assert result.reputation[other.key()] == 0.0


async def test_bucket_selection_skips_missing_identities(redis):
    admission, _ = svc(redis)
    scopes = [b.scope for b in admission.buckets(api_key_id="k", endpoint="chat", ip=None, user_id=None)]
    assert scopes == ["api_key", "global", "endpoint"]
    buckets = admission.buckets(api_key_id="k", endpoint="chat", ip="1.2.3.4", user_id="u", session_id="s1")
    assert [b.scope for b in buckets] == ["api_key", "global", "endpoint", "session", "ip", "user"]
    assert {b.key for b in buckets} >= {"rl:session:s1", "rl:ip:1.2.3.4", "rl:user:u"}


async def test_reputation_clamps_decays_and_counts_events(redis):
    _, reputation = svc(redis, reputation_half_life_seconds=0.2)
    e = Entity("ip", "1.2.3.4")
    for _ in range(6):
        score = await reputation.record(e, "attack")
    assert score == 100.0  # clamped
    await asyncio.sleep(0.2)  # one half-life
    snap = await reputation.snapshot(e)
    assert 40 < snap["score"] < 60
    assert snap["events"] == {"attack": 6}


async def test_strikes_count_evidence_kinds_and_window(redis):
    _, reputation = svc(redis, strike_window_seconds=1)
    e = Entity("user", "u1")
    assert (await reputation.add_strike(e, "probabilistic", "r1")).total == 1
    two = await reputation.add_strike(e, "deterministic", "r2")
    assert (two.total, two.deterministic) == (2, 1)
    await asyncio.sleep(1.1)
    fresh = await reputation.add_strike(e, "probabilistic", "r3")
    assert (fresh.total, fresh.deterministic) == (1, 0)  # old strikes left the window


async def test_window_counter_and_reset(redis):
    _, reputation = svc(redis)
    e = Entity("ip", "1.2.3.4")
    assert [await reputation.count_event(e, "auth_failed", 60) for _ in range(3)] == [1, 2, 3]
    await reputation.reset_event(e, "auth_failed")
    assert await reputation.count_event(e, "auth_failed", 60) == 1
