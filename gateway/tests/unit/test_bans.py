"""Ban index matching and ban-service escalation rules."""

import uuid
from datetime import UTC, datetime, timedelta

import pytest

from app.bans.index import BanEntry, BanIndex, Subject
from app.bans.service import BANS_CHANNEL, BanService, validate_cidr_not_too_broad
from app.entities import Entity, normalize
from app.reputation.service import StrikeCount
from tests.fakes import FakeRedis, FakeRepo, make_settings

FUTURE = datetime.now(UTC) + timedelta(hours=1)


def entry(entity_type, value, permanent=False, expires_at=FUTURE):
    return BanEntry(uuid.uuid4(), entity_type, value, permanent, None if permanent else expires_at, "manual")


# ------------------------------------------------------------------ index
def test_exact_matches():
    idx = BanIndex([entry("user", "u1"), entry("ip", "203.0.113.9"), entry("session", "contact-1")])
    assert idx.match(Subject(user_id="u1")) is not None
    assert idx.match(Subject(user_id="u2")) is None
    assert idx.match(Subject(ip="203.0.113.9")) is not None
    assert idx.match(Subject(ip="203.0.113.10")) is None
    assert idx.match(Subject(session_id="contact-1")).entity_type == "session"
    assert idx.match(Subject(session_id="contact-2", user_id="u3")) is None


def test_cidr_matching_ipv4_and_ipv6():
    idx = BanIndex([entry("cidr", "198.51.100.0/24"), entry("cidr", "2001:db8::/32")])
    assert idx.match(Subject(ip="198.51.100.200")) is not None
    assert idx.match(Subject(ip="198.51.101.1")) is None
    assert idx.match(Subject(ip="2001:db8:1::5")) is not None
    assert idx.match(Subject(ip="2001:db9::5")) is None


def test_ipv4_mapped_ipv6_matches_ipv4_ban():
    idx = BanIndex([entry("ip", "203.0.113.9")])
    assert idx.match(Subject(ip="::ffff:203.0.113.9")) is not None


def test_expired_bans_stop_matching_without_reload():
    idx = BanIndex([entry("user", "u1", expires_at=datetime.now(UTC) + timedelta(seconds=1))])
    assert idx.match(Subject(user_id="u1")) is not None
    assert idx.match(Subject(user_id="u1"), now=datetime.now(UTC) + timedelta(seconds=2)) is None


def test_strongest_ban_wins_for_the_same_entity():
    short = entry("user", "u1", expires_at=datetime.now(UTC) + timedelta(minutes=1))
    perm = entry("user", "u1", permanent=True)
    idx = BanIndex([perm, short])
    assert idx.match(Subject(user_id="u1")).permanent


def test_garbage_ip_is_ignored():
    idx = BanIndex([entry("cidr", "10.0.0.0/8")])
    assert idx.match(Subject(ip="testclient")) is None


def test_value_normalisation():
    assert normalize("ip", " 2001:DB8::1 ") == "2001:db8::1"
    assert normalize("cidr", "198.51.100.7/24") == "198.51.100.0/24"
    with pytest.raises(ValueError):
        normalize("ip", "999.1.1.1")
    with pytest.raises(ValueError):
        validate_cidr_not_too_broad("0.0.0.0/0", "cidr")


# ------------------------------------------------------------------ service
def service(**settings):
    repo, redis = FakeRepo(), FakeRedis()
    return BanService(repo, redis, make_settings(**settings)), repo, redis


async def test_new_ban_is_applied_on_other_instances_without_a_database_read():
    bans_a, _repo_a, redis = service()
    await bans_a.ban(
        entity_type="ip",
        value="203.0.113.9",
        reason="r",
        source="manual",
        created_by="admin",
        duration_seconds=60,
    )
    assert bans_a.match(Subject(ip="203.0.113.9")) is not None

    channel, message = redis.published[-1]
    assert channel == BANS_CHANNEL and '"op":"add"' in message

    # Instance B whose database is down still applies the ban from the message alone.
    bans_b, repo_b, _ = service()
    repo_b.fail_ban_loads = True
    await bans_b.apply_message(message)
    assert bans_b.match(Subject(ip="203.0.113.9")) is not None
    assert bans_b.reload_failures == 0


async def test_unban_and_unknown_messages_trigger_a_full_reload():
    bans, repo, redis = service()
    row = await bans.ban(
        entity_type="ip", value="203.0.113.9", reason="r", source="manual", created_by="admin", permanent=True
    )
    await bans.unban(row["id"], "admin")
    assert redis.published[-1] == (BANS_CHANNEL, "reload")
    repo.fail_ban_loads = True
    await bans.apply_message("{not json")
    assert bans.reload_failures == 1  # tried to reload


async def test_ban_requires_exactly_one_of_duration_or_permanent():
    bans, *_ = service()
    with pytest.raises(ValueError):
        await bans.ban(entity_type="ip", value="1.2.3.4", reason="r", source="manual", created_by="a")
    with pytest.raises(ValueError):
        await bans.ban(
            entity_type="ip",
            value="1.2.3.4",
            reason="r",
            source="manual",
            created_by="a",
            duration_seconds=5,
            permanent=True,
        )


@pytest.mark.parametrize(
    ("total", "deterministic", "duration", "permanent"),
    [
        (1, 0, 60, False),
        (2, 1, 900, False),
        (3, 0, 86400, False),
        (4, 0, 86400, False),  # probabilistic evidence only: capped, never permanent
        (9, 0, 86400, False),
        (4, 1, None, True),  # 4 strikes incl. deterministic evidence → permanent
    ],
)
async def test_escalation_ladder(total, deterministic, duration, permanent):
    bans, repo, _ = service()
    ban = await bans.escalate(
        Entity("user", f"u-{total}-{deterministic}"),
        StrikeCount(total, deterministic),
        reason="attack",
        evidence="probabilistic",
        request_id="r",
    )
    assert ban is not None
    assert ban["permanent"] is permanent
    if duration is not None:
        remaining = (ban["expires_at"] - datetime.now(UTC)).total_seconds()
        assert duration - 5 < remaining <= duration
    assert repo.strikes[-1]["ban_id"] == ban["id"]


async def test_never_ban_ips_are_recorded_but_not_banned():
    bans, repo, _ = service(never_ban_cidrs="10.0.0.0/8")
    ban = await bans.escalate(
        Entity("ip", "10.1.2.3"),
        StrikeCount(5, 5),
        reason="x",
        evidence="deterministic",
        request_id="r",
    )
    assert ban is None
    assert repo.bans == {}
    assert repo.strikes[-1]["ban_id"] is None


async def test_existing_stronger_ban_is_not_replaced():
    bans, repo, _ = service()
    await bans.ban(
        entity_type="user",
        value="u1",
        reason="r",
        source="manual",
        created_by="admin",
        permanent=True,
    )
    ban = await bans.escalate(
        Entity("user", "u1"), StrikeCount(1, 0), reason="x", evidence="probabilistic", request_id="r"
    )
    assert ban is None
    assert len(repo.bans) == 1


async def test_failed_reload_keeps_the_previous_index():
    bans, repo, _ = service()
    await bans.ban(
        entity_type="ip", value="203.0.113.9", reason="r", source="manual", created_by="admin", permanent=True
    )
    repo.fail_ban_loads = True
    assert await bans.reload() is False
    assert bans.match(Subject(ip="203.0.113.9")) is not None
    assert bans.reload_failures == 1


async def test_unban_lifts_the_ban():
    bans, *_ = service()
    row = await bans.ban(
        entity_type="ip", value="203.0.113.9", reason="r", source="manual", created_by="admin", permanent=True
    )
    assert await bans.unban(row["id"], "admin") is not None
    assert bans.match(Subject(ip="203.0.113.9")) is None
    assert await bans.unban(uuid.uuid4(), "admin") is None


async def test_session_bans_are_never_permanent():
    bans, *_ = service()
    ban = await bans.escalate(
        Entity("session", "contact-9"),
        StrikeCount(9, 9),
        reason="x",
        evidence="deterministic",
        request_id="r",
    )
    assert ban is not None and ban["permanent"] is False
    assert bans.match(Subject(session_id="contact-9")) is not None
