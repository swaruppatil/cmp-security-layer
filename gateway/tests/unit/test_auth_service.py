from datetime import UTC, datetime, timedelta

import pytest

from app.auth.keys import generate_key, hash_key
from app.auth.service import INVALIDATION_CHANNEL, AuthError, AuthService, listen_for_invalidations
from tests.fakes import FakeRepo


def service(repo, **kw):
    return AuthService(
        repo, ttl_seconds=kw.get("ttl", 30), negative_ttl_seconds=kw.get("neg", 5), max_entries=100
    )


async def test_valid_key_returns_principal_and_is_cached():
    repo = FakeRepo()
    key = repo.add_key(scopes=("inspect",))
    auth = service(repo)

    p1 = await auth.authenticate(key)
    p2 = await auth.authenticate(key)
    assert p1 == p2
    assert p1.name == "test"
    assert p1.has_scope("inspect") and not p1.has_scope("proxy")
    assert auth.lookups == 1  # second call served from cache


async def test_unknown_key_is_negatively_cached():
    auth = service(FakeRepo())
    key = generate_key().plaintext
    for _ in range(3):
        with pytest.raises(AuthError):
            await auth.authenticate(key)
    assert auth.lookups == 1  # repeated bad keys don't hit the database


@pytest.mark.parametrize(
    ("setup", "reason"),
    [
        (lambda r: r.add_key(status="revoked"), "key_revoked"),
        (lambda r: r.add_key(expires_at=datetime.now(UTC) - timedelta(seconds=1)), "key_expired"),
    ],
)
async def test_rejected_keys(setup, reason):
    repo = FakeRepo()
    key = setup(repo)
    with pytest.raises(AuthError) as exc:
        await service(repo).authenticate(key)
    assert exc.value.reason == reason


async def test_right_prefix_wrong_secret_rejected():
    repo = FakeRepo()
    key = repo.add_key()
    forged = key.rsplit("_", 1)[0] + "_" + generate_key().plaintext.rsplit("_", 1)[1]
    with pytest.raises(AuthError) as exc:
        await service(repo).authenticate(forged)
    assert exc.value.reason == "hash_mismatch"


async def test_malformed_key_never_reaches_repository():
    auth = service(FakeRepo())
    with pytest.raises(AuthError) as exc:
        await auth.authenticate("garbage")
    assert exc.value.reason == "malformed_or_missing_key"
    assert auth.lookups == 0


async def test_invalidate_forces_fresh_lookup():
    repo = FakeRepo()
    key = repo.add_key()
    auth = service(repo)
    await auth.authenticate(key)
    # Revoke in the "database" and invalidate the cache, as the admin API does.
    for k in repo.keys.values():
        k["status"] = "revoked"
    auth.invalidate(hash_key(key))
    with pytest.raises(AuthError):
        await auth.authenticate(key)


class FakePubSub:
    def __init__(self, messages):
        self._messages = messages

    async def listen(self):
        for m in self._messages:
            yield m


async def test_invalidation_listener_drops_cached_keys():
    repo = FakeRepo()
    key = repo.add_key()
    auth = service(repo)
    await auth.authenticate(key)
    for k in repo.keys.values():
        k["status"] = "revoked"

    subscribed = []

    async def subscribe(channel):
        subscribed.append(channel)
        return FakePubSub(
            [{"type": "subscribe", "data": 1}, {"type": "message", "data": hash_key(key).encode()}]
        )

    await listen_for_invalidations(subscribe, auth)
    assert subscribed == [INVALIDATION_CHANNEL]
    with pytest.raises(AuthError):
        await auth.authenticate(key)
