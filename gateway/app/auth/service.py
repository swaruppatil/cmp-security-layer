"""API key authentication with an in-process cache.

Hot path: presented key → SHA-256 → local cache hit → Principal, in microseconds and with no
network call. A miss reads Postgres once (by indexed prefix) and caches the result.

* Valid keys are cached for ``auth_cache_ttl_seconds``.
* Invalid keys are cached for ``auth_negative_cache_ttl_seconds``, so someone hammering the gateway
  with bad keys cannot turn every request into a database query.
* Revoking a key publishes its hash on a Redis channel; every gateway instance drops it from its
  cache immediately. The TTL is the safety net if a message is missed.
"""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from typing import Protocol

from cachetools import TTLCache

from app.auth.keys import hash_key, hashes_match, parse_key
from app.auth.models import ApiKeyRecord, Principal

log = logging.getLogger(__name__)

INVALIDATION_CHANNEL = "auth:invalidate"


class KeyRepository(Protocol):
    async def find_key_by_prefix(self, prefix: str) -> ApiKeyRecord | None: ...


class AuthError(Exception):
    """Raised for any authentication failure. The reason is for logs only, never for the caller."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


_INVALID = object()  # negative-cache marker


class AuthService:
    def __init__(
        self,
        repo: KeyRepository,
        *,
        ttl_seconds: float,
        negative_ttl_seconds: float,
        max_entries: int,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._repo = repo
        self._valid: TTLCache[str, Principal] = TTLCache(maxsize=max_entries, ttl=ttl_seconds)
        self._invalid: TTLCache[str, object] = TTLCache(maxsize=max_entries, ttl=negative_ttl_seconds)
        self._clock = clock or (lambda: datetime.now(UTC))
        self.lookups = 0  # database lookups performed (observability / tests)

    async def authenticate(self, presented: str | None) -> Principal:
        parsed = parse_key(presented)
        if parsed is None:
            raise AuthError("malformed_or_missing_key")

        key_hash = hash_key(parsed.full)
        cached = self._valid.get(key_hash)
        if cached is not None:
            return cached
        if key_hash in self._invalid:
            raise AuthError("invalid_key_cached")

        self.lookups += 1
        record = await self._repo.find_key_by_prefix(parsed.prefix)
        reason = self._reject_reason(record, parsed.full)
        if reason is not None:
            self._invalid[key_hash] = _INVALID
            raise AuthError(reason)

        assert record is not None
        principal = Principal(
            api_key_id=record.id,
            name=record.name,
            api_key_prefix=record.prefix,
            scopes=frozenset(record.scopes),
        )
        self._valid[key_hash] = principal
        return principal

    def _reject_reason(self, record: ApiKeyRecord | None, full_key: str) -> str | None:
        if record is None:
            return "unknown_key"
        if not hashes_match(record.key_hash, full_key):
            return "hash_mismatch"
        if record.status != "active":
            return "key_revoked"
        if record.expires_at is not None and record.expires_at <= self._clock():
            return "key_expired"
        return None

    def invalidate(self, key_hash: str) -> None:
        self._valid.pop(key_hash, None)
        self._invalid.pop(key_hash, None)

    def clear(self) -> None:
        self._valid.clear()
        self._invalid.clear()


async def listen_for_invalidations(
    subscribe: Callable[[str], Awaitable[object]],
    service: AuthService,
) -> None:
    """Background task: drop revoked keys from this instance's cache.

    ``subscribe`` is the Redis pub/sub subscription (injected so tests can fake it).
    """
    pubsub = await subscribe(INVALIDATION_CHANNEL)
    async for message in pubsub.listen():  # type: ignore[attr-defined]
        if message.get("type") != "message":
            continue
        data = message.get("data")
        key_hash = data.decode() if isinstance(data, bytes) else str(data)
        service.invalidate(key_hash)
        log.info("auth cache invalidated", extra={"key_hash_prefix": key_hash[:8]})
