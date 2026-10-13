"""CMP sessions: one Amazon Connect contact, from ``start_chat`` to the end of the contact.

The session id (CMP's contact id) is the backbone of everything the gateway knows about a chat:

* **attributes** — channel, IP, device, user agent and the (hashed) customer, given once by
  ``POST /v1/sessions/{id}/start`` and inherited by every later inspect call of the session;
* **verification** — ``POST /v1/sessions/{id}/identity`` after CMP's IDV: the session becomes
  ``verified`` (policies may differ) and the customer's own booking references, emails … become the
  data AI replies may contain;
* **typed identifiers** — identifiers the customer typed themselves; the AI may repeat them back;
* **conversation memory, the session rate bucket, session strikes and bans** — keyed by the same id;
* **idempotency** — ``message_id`` → the decision, so a CMP retry neither re-runs the checks nor
  charges the customer twice.

Storage: one JSON value per session at ``sess:{id}`` (TTL ``SESSION_TTL_SECONDS``, refreshed on use)
and ``idem:{session}:{message_id}`` per decision (TTL ``IDEMPOTENCY_TTL_SECONDS``). Identifiers are
kept only as keyed hashes. Every failure is logged and swallowed by the callers: without Redis the
gateway still decides, from what the request itself carries.
"""

from __future__ import annotations

import logging
import time
from dataclasses import asdict, dataclass, field
from typing import Any

import orjson

from app.config import Settings
from app.conversation.state import state_key
from app.session.identity import customer_key, hash_identifiers

log = logging.getLogger("gateway.sessions")

ANONYMOUS = "anonymous"
VERIFIED = "verified"
MAX_HASHES_PER_TYPE = 50


def session_key(session_id: str) -> str:
    return f"sess:{session_id}"


def idem_key(session_id: str, message_id: str) -> str:
    return f"idem:{session_id}:{message_id}"


@dataclass
class SessionRecord:
    session_id: str
    channel: str | None = None
    ip: str | None = None
    device_id: str | None = None
    user_agent: str | None = None
    user: str | None = None  # hashed customer id
    state: str = ANONYMOUS
    started_at: float | None = None
    verified_at: float | None = None
    # type -> hashes of identifiers the session may see (verified ∪ typed by the customer)
    verified_ids: dict[str, list[str]] = field(default_factory=dict)
    typed_ids: dict[str, list[str]] = field(default_factory=dict)

    def allowed_hashes(self) -> dict[str, set[str]]:
        out: dict[str, set[str]] = {}
        for source in (self.verified_ids, self.typed_ids):
            for t, hashes in source.items():
                out.setdefault(t, set()).update(hashes)
        return out

    def public(self) -> dict[str, Any]:
        """What the admin API shows: attributes and counts, never identifier hashes."""
        return {
            "session_id": self.session_id,
            "channel": self.channel,
            "ip": self.ip,
            "device_id": self.device_id,
            "user_agent": self.user_agent,
            "user": self.user,
            "state": self.state,
            "started_at": self.started_at,
            "verified_at": self.verified_at,
            "verified_identifiers": {t: len(v) for t, v in self.verified_ids.items()},
            "typed_identifiers": {t: len(v) for t, v in self.typed_ids.items()},
        }

    def to_json(self) -> bytes:
        return orjson.dumps(asdict(self))

    @classmethod
    def from_json(cls, raw: bytes | str) -> SessionRecord:
        d: dict[str, Any] = orjson.loads(raw)
        known = {f for f in cls.__dataclass_fields__}
        return cls(**{k: v for k, v in d.items() if k in known})


def _merge_hashes(current: dict[str, list[str]], new: dict[str, set[str]]) -> dict[str, list[str]]:
    out = {t: list(v) for t, v in current.items()}
    for t, hashes in new.items():
        merged = list(dict.fromkeys([*out.get(t, []), *sorted(hashes)]))
        out[t] = merged[-MAX_HASHES_PER_TYPE:]
    return out


class SessionService:
    def __init__(self, redis: Any, settings: Settings) -> None:
        self._redis = redis
        self._s = settings
        self._key = settings.identity_hash_key.get_secret_value()

    @property
    def settings(self) -> Settings:
        return self._s

    def customer(self, customer_id: str | None) -> str | None:
        return customer_key(self._key, customer_id)

    def hash_identifiers(self, identifiers: dict[str, list[str]]) -> dict[str, set[str]]:
        return hash_identifiers(self._key, identifiers)

    async def get(self, session_id: str) -> SessionRecord | None:
        raw = await self._redis.get(session_key(session_id))
        return SessionRecord.from_json(raw) if raw is not None else None

    async def _save(self, rec: SessionRecord) -> None:
        await self._redis.set(session_key(rec.session_id), rec.to_json(), ex=self._s.session_ttl_seconds)

    async def start(
        self,
        session_id: str,
        *,
        channel: str | None,
        ip: str | None,
        device_id: str | None,
        user_agent: str | None,
        customer_id: str | None,
    ) -> SessionRecord:
        """Create the session, or update the attributes of an existing one (``start`` is idempotent:
        CMP may call it again, e.g. after a reconnect). Verification is kept."""
        rec = await self.get(session_id) or SessionRecord(session_id=session_id, started_at=time.time())
        rec.channel = (channel or rec.channel or "").lower() or None
        rec.ip = ip or rec.ip
        rec.device_id = device_id or rec.device_id
        rec.user_agent = user_agent or rec.user_agent
        rec.user = self.customer(customer_id) or rec.user
        await self._save(rec)
        return rec

    async def verify(
        self,
        session_id: str,
        *,
        verified: bool,
        customer_id: str | None,
        identifiers: dict[str, list[str]],
    ) -> SessionRecord:
        """Record CMP's identity verification. ``verified=false`` (a failed or reset IDV) drops the
        session back to anonymous and forgets the verified identifiers."""
        rec = await self.get(session_id) or SessionRecord(session_id=session_id, started_at=time.time())
        if verified:
            rec.state, rec.verified_at = VERIFIED, time.time()
            rec.user = self.customer(customer_id) or rec.user
            rec.verified_ids = _merge_hashes({}, self.hash_identifiers(identifiers))
        else:
            rec.state, rec.verified_at, rec.verified_ids = ANONYMOUS, None, {}
        await self._save(rec)
        return rec

    async def remember(
        self,
        session_id: str,
        request: dict[str, Any],
        typed: dict[str, set[str]],
        *,
        current: SessionRecord | None | object = ...,
    ) -> None:
        """After an inspect call: create the session if CMP never called ``start``, fill in attributes
        it did not have, add typed identifiers, refresh the TTL. ``current``: the record the request
        already loaded (``None`` = there was none), so no second read is needed; omit it to read."""
        rec = await self.get(session_id) if current is ... else current
        assert rec is None or isinstance(rec, SessionRecord)
        changed = rec is None
        rec = rec or SessionRecord(session_id=session_id, started_at=time.time())
        for name in ("channel", "ip", "device_id", "user_agent", "user"):
            if getattr(rec, name) is None and request.get(name):
                setattr(rec, name, request[name])
                changed = True
        if typed:
            merged = _merge_hashes(rec.typed_ids, typed)
            changed = changed or merged != rec.typed_ids
            rec.typed_ids = merged
        if changed:
            await self._save(rec)
        else:
            await self._redis.expire(session_key(session_id), self._s.session_ttl_seconds)

    async def end(self, session_id: str) -> bool:
        """Forget the session and its conversation memory (the contact is over). Strikes and bans on
        the session stay until they expire: the record of what happened is the audit trail's job."""
        n = await self._redis.delete(session_key(session_id), state_key(session_id))
        return bool(n)

    # ---------------------------------------------------------------- idempotency
    async def cached_decision(self, session_id: str, message_id: str) -> dict[str, Any] | None:
        raw = await self._redis.get(idem_key(session_id, message_id))
        return orjson.loads(raw) if raw is not None else None

    async def cache_decision(self, session_id: str, message_id: str, decision: dict[str, Any]) -> None:
        await self._redis.set(
            idem_key(session_id, message_id),
            orjson.dumps(decision),
            ex=self._s.idempotency_ttl_seconds,
            nx=True,
        )
