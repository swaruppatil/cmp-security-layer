"""Stage 8: bot features, score, tiers and adaptive throttling (fakeredis + a fake clock)."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.bots.features import Event, bands, compute, hamming, simhash
from app.bots.service import WEIGHTS, tier_for
from app.main import create_app
from scripts.simulate_bots import FakeClock, run
from tests.fakes import FakeRepo, make_deps, make_settings, ml_scores


def settings(**overrides):
    return make_settings(max_prompt_chars=4000, **overrides)


# ------------------------------------------------------------------ features
def test_simhash_near_and_far():
    a = simhash("Please send me the ticket details for booking ABC123 right now")
    b = simhash("Please send me the ticket details for booking XYZ789 right now")
    c = simhash("My bag never arrived in Calgary, what should I do about it")
    assert a is not None and b is not None and c is not None
    assert hamming(a, a) == 0 and hamming(a, b) <= 12 < hamming(a, c)
    assert simhash("ok thanks") is None  # too short to fingerprint
    assert simhash("PLEASE   send me the TICKET details for booking ABC123 right now") == a  # folded


def test_bands_share_one_for_close_fingerprints():
    h = simhash("I want a full refund for my cancelled flight and compensation")
    assert h is not None
    flipped = h ^ 0b111  # three bits apart, all in band 0
    assert set(bands(h)) & set(bands(flipped))


def test_event_round_trip():
    e = Event(123, 45, 0xDEADBEEF)
    assert Event.decode(e.encode()) == e and Event.decode(Event(1, 2, None).encode()) == Event(1, 2, None)
    assert Event.decode("garbage") is None


def features(gaps: list[float], length: int = 60, text_hash: int | None = None):
    events, t = [], 0
    for g in gaps:
        t += int(g * 1000)
        events.append(Event(t, length, text_hash))
    return compute(events[:-1], events[-1], min_gaps=5, fast_cps=20, fast_min_chars=30, dup_distance=12)


def test_timer_regular_gaps_have_low_cv_irregular_high():
    assert features([2.0] * 8).gap_cv == 0.0
    assert features([3, 25, 7, 40, 12, 5, 30, 9]).gap_cv > 0.5
    assert features([2.0] * 3).gap_cv is None  # too few gaps to judge


def test_typing_speed_and_duplicates():
    fast = features([1.0] * 6, length=80)  # 80 chars a second
    assert fast.fast_share == 1.0 and fast.judged == 5
    slow = features([20.0] * 6, length=80)  # 4 chars/s
    assert slow.fast_share == 0.0
    h = simhash("Please send me the ticket details for booking ABC123 right now")
    assert features([5.0] * 6, text_hash=h).duplicates == 5


def test_no_single_signal_reaches_the_likely_tier():
    s = settings()
    assert all(tier_for(w, s)[0] in ("normal", "suspect") for w in WEIGHTS.values())
    assert tier_for(WEIGHTS["timer"] + WEIGHTS["repetition"], s)[0] == "likely"
    assert tier_for(WEIGHTS["timer"] + WEIGHTS["fast_typing"], s) == ("bot", s.bot_likely_cost)


# ------------------------------------------------------------------ over HTTP
def client(**overrides):
    repo = FakeRepo()
    key = repo.add_key()
    deps = make_deps(ml=ml_scores())
    app = create_app(settings=settings(**overrides), deps=deps, repo=repo, background_tasks=False)
    return TestClient(app), {"authorization": f"Bearer {key}"}


def send(c, auth, text, user="u1", **extra):
    return c.post(
        "/v1/inspect",
        json={"session_id": f"s-{user}", "message": text, "customer_id": user, **extra},
        headers=auth,
    ).json()


def bot_detail(d):
    return next(x for x in d["checks"] if x["name"] == "bot")["detail"]


def test_simulation_bots_throttled_or_slowed_humans_untouched():
    clock = FakeClock()
    c, auth = client(rl_user_capacity=1_000_000, rl_ip_capacity=1_000_000, rl_session_capacity=1_000_000)
    with c:
        c.app.state.bots.clock = clock
        summary = run(c, auth, clock)
    human = summary["human"]
    assert human["sessions_throttled"] == 0 and human["sessions_slowed"] == 0
    for profile in ("timer_template", "jittered_timer"):
        assert summary[profile]["sessions_throttled"] == summary[profile]["sessions"], profile
    for profile in ("fast_paster", "burst"):
        assert summary[profile]["sessions_slowed"] == summary[profile]["sessions"], profile
    assert summary["slow_poller"]["sessions_throttled"] == 0  # slow and harmless: left alone
    assert summary["campaign"]["signals"].get("campaign", 0) >= 3


def test_bot_tier_throttles_with_a_cooldown():
    clock = FakeClock()
    c, auth = client()
    with c:
        c.app.state.bots.clock = clock
        d = {}
        for i in range(12):
            clock.advance(2.0)
            d = send(c, auth, f"Please send me the ticket details for booking reference {1000 + i}")
            if d["action"] == "throttle":
                break
        assert d["action"] == "throttle" and d["reasons"] == ["bot_detected"]
        assert d["retry_after_seconds"] == 30
        assert {"timer", "repetition"} <= set(bot_detail(d)["signals"])


def test_likely_tier_drains_the_users_bucket_faster():
    """Same bucket: a 'likely bot' (timer + repetition) runs dry in a few requests; a person doesn't."""
    clock = FakeClock()
    c, auth = client(rl_user_capacity=30, rl_user_refill_per_sec=0.01)
    with c:
        c.app.state.bots.clock = clock
        bot = []
        for _ in range(15):
            clock.advance(2.0)
            # Short (typing speed not judged) and identical: timer + repetition = "likely", not "bot".
            bot.append(send(c, auth, "Status of my booking please", user="bot"))
        first = next(i for i, d in enumerate(bot) if d["action"] == "throttle")
        assert first < 10 and bot[first]["reasons"] == ["rate_limited"]
        assert bot_detail(bot[first])["tier"] == "likely"
        assert next(x for x in bot[first]["checks"] if x["name"] == "admission")["detail"]["cost"] == 10.0
        person = []
        for i in range(15):
            clock.advance(15 + 7 * (i % 3) + i)
            person.append(
                send(c, auth, f"Question number {i} about my seat and bags", user="person")["action"]
            )
        assert "throttle" not in person


def test_campaign_across_identities():
    clock = FakeClock()
    c, auth = client()
    msg = "I want a full refund for my cancelled flight and compensation for the hotel I had to book"
    with c:
        c.app.state.bots.clock = clock
        details = []
        for i in range(6):
            clock.advance(10)
            details.append(bot_detail(send(c, auth, msg, user=f"camp-{i}")))
        assert "campaign" not in details[3]["signals"] and "campaign" in details[5]["signals"]
        assert details[5]["campaign_identities"] == 6 and details[5]["tier"] == "suspect"
        clock.advance(10)
        short = bot_detail(send(c, auth, "Is my flight on time?", user="camp-x"))
        assert "campaign" not in short["signals"]  # short common questions never count


def test_user_agent_and_hosting_ip_signals():
    c, auth = client(bot_hosting_cidrs="203.0.113.0/24")
    with c:
        d = send(c, auth, "Is my flight on time?", user_agent="python-requests/2.31", ip="203.0.113.7")
        assert {"automation_ua", "hosting_ip"} <= set(bot_detail(d)["signals"])
        # On SMS / WhatsApp the user agent belongs to the messaging provider, not the customer.
        d = send(
            c, auth, "Is my flight on time?", user="u3", user_agent="python-requests/2.31", channel="sms"
        )
        assert "automation_ua" not in bot_detail(d)["signals"]
        d = send(c, auth, "Is my flight on time?", user="u2", user_agent="Mozilla/5.0 (iPhone)")
        assert bot_detail(d)["signals"] == []
        # Proxy mode expects a user agent; a request without one is a (weak) signal.
        res = c.post("/v1/ai/chat", json={"message": "hello there"}, headers={**auth, "user-agent": ""})
        assert res.status_code == 200


def test_trusted_shared_ip_is_not_profiled():
    c, auth = client(never_ban_cidrs="127.0.0.0/8,10.0.0.0/8")
    with c:
        d = c.post(
            "/v1/inspect",
            json={"session_id": "s-anon-1", "message": "Is my flight on time?", "ip": "10.1.2.3"},
            headers=auth,
        ).json()
        assert set(bot_detail(d)["features"]) == {"session"}  # the session is profiled, the trusted IP is not
        d = send(c, auth, "Is my flight on time?", ip="10.1.2.3")
        assert set(bot_detail(d)["features"]) == {"user", "session"}


def test_every_session_is_profiled_and_disable_switch():
    c, auth = client()
    with c:
        d = c.post(
            "/v1/inspect", json={"session_id": "s-anon-2", "message": "Is my flight on time?"}, headers=auth
        ).json()
        assert set(bot_detail(d)["features"]) == {"session"}
    c, auth = client(bot_enabled=False)
    with c:
        assert "bot" not in {x["name"] for x in send(c, auth, "Is my flight on time?")["checks"]}


def test_redis_failure_skips_bot_check():
    c, auth = client()
    with c:

        async def broken(*_a, **_k):
            raise ConnectionError("redis down")

        c.app.state.bots.assess = broken
        d = send(c, auth, "Is my flight on time?")
        assert d["action"] == "allow" and bot_detail(d) == {"unavailable": True}


@pytest.mark.parametrize("ua", ["curl/8.4", "Go-http-client/1.1", "Mozilla/5.0 HeadlessChrome/120"])
def test_automation_user_agents(ua):
    c, auth = client()
    with c:
        assert "automation_ua" in bot_detail(send(c, auth, "hello there friend", user_agent=ua))["signals"]
