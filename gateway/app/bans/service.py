"""Ban management: the active-ban cache, manual bans, blacklists, strike escalation, unbanning.

Source of truth is PostgreSQL. Each gateway instance keeps a ``BanIndex`` in memory:
* loaded at startup;
* rebuilt immediately when any instance publishes on ``bans:changed`` (Redis pub/sub);
* rebuilt every ``ban_cache_refresh_seconds`` as a safety net.
If a reload fails (Postgres down), the previous index keeps serving.

Escalation (``escalate``) follows the safety rules in PLAN.md §5.3–5.4:
* durations come from ``ban_ladder_seconds`` by strike count (default 1 min, 15 min, 24 h);
* a **permanent** ban needs ``permanent_after_strikes`` strikes **including deterministic evidence** —
  probabilistic (model) evidence alone is capped at the longest ladder step;
* IPs inside ``never_ban_cidrs`` are never banned automatically;
* IP / CIDR bans (``IP_BAN_NEVER_PERMANENT``) and session bans are never permanent: addresses are
  reassigned, and a session ends with its contact;
* an existing stronger ban is never replaced by a weaker one.
"""

from __future__ import annotations

import ipaddress
import logging
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol
from uuid import UUID

import orjson

from app.bans.index import BanEntry, BanIndex, Subject
from app.config import Settings
from app.entities import Entity, IPNetwork, parse_cidr_list, parse_ip
from app.reputation.service import StrikeCount

log = logging.getLogger("gateway.bans")

BANS_CHANNEL = "bans:changed"


class BanRepository(Protocol):
    async def load_active_bans(self) -> list[dict[str, Any]]: ...

    async def create_ban(self, **fields: Any) -> dict[str, Any]: ...

    async def revoke_ban(self, ban_id: UUID, revoked_by: str) -> dict[str, Any] | None: ...

    async def record_strike(self, **fields: Any) -> None: ...


def _entry_to_wire(e: BanEntry) -> dict[str, Any]:
    return {
        "id": str(e.id),
        "entity_type": e.entity_type,
        "value": e.value,
        "permanent": e.permanent,
        "expires_at": e.expires_at.isoformat() if e.expires_at else None,
        "source": e.source,
    }


def _entry_from_wire(d: dict[str, Any]) -> BanEntry:
    return BanEntry(
        id=UUID(d["id"]),
        entity_type=d["entity_type"],
        value=d["value"],
        permanent=bool(d["permanent"]),
        expires_at=datetime.fromisoformat(d["expires_at"]) if d.get("expires_at") else None,
        source=d["source"],
    )


def _entry(row: dict[str, Any]) -> BanEntry:
    return BanEntry(
        id=row["id"],
        entity_type=row["entity_type"],
        value=row["value"],
        permanent=row["permanent"],
        expires_at=row["expires_at"],
        source=row["source"],
    )


class BanService:
    def __init__(self, repo: BanRepository, redis: Any, settings: Settings) -> None:
        self._repo = repo
        self._redis = redis
        self._settings = settings
        self._never_ban: list[IPNetwork] = parse_cidr_list(settings.never_ban_cidrs)
        self.index = BanIndex()
        self.loaded_at: datetime | None = None
        self.reload_failures = 0

    # ------------------------------------------------------------------ cache
    async def reload(self) -> bool:
        try:
            rows = await self._repo.load_active_bans()
        except Exception:  # noqa: BLE001 - keep serving the previous index
            self.reload_failures += 1
            log.warning("ban cache reload failed; keeping previous index", exc_info=True)
            return False
        self.index = BanIndex([_entry(r) for r in rows])
        self.loaded_at = datetime.now(UTC)
        return True

    async def notify_changed(self) -> None:
        """Full rebuild here and on every instance. Used for unbans and bulk imports (rare)."""
        await self.reload()
        await self._publish("reload")

    async def notify_added(self, row: dict[str, Any]) -> None:
        """Incremental: add one ban here and on every instance, without touching PostgreSQL.

        Automatic bans arrive in bursts during an attack wave; a full reload per ban would make every
        instance re-read the whole table thousands of times exactly when the hot path is busiest.
        """
        entry = _entry(row)
        self.index.add(entry)
        await self._publish(orjson.dumps({"op": "add", "ban": _entry_to_wire(entry)}).decode())

    async def apply_message(self, data: str) -> None:
        """Handle a ``bans:changed`` message from another instance."""
        if data.startswith("{"):
            try:
                msg = orjson.loads(data)
                if msg.get("op") == "add":
                    self.index.add(_entry_from_wire(msg["ban"]))
                    return
            except (orjson.JSONDecodeError, KeyError, ValueError, TypeError):
                log.warning("bad ban message; doing a full reload")
        await self.reload()

    async def _publish(self, message: str) -> None:
        try:
            await self._redis.publish(BANS_CHANNEL, message)
        except Exception:  # noqa: BLE001 - periodic refresh is the fallback
            log.warning("could not publish ban change; other instances rely on periodic refresh")

    def match(self, subject: Subject) -> BanEntry | None:
        return self.index.match(subject)

    def is_never_ban(self, ip: str | None) -> bool:
        addr = parse_ip(ip)
        return addr is not None and any(addr in net for net in self._never_ban if addr.version == net.version)

    # ------------------------------------------------------------------ manual
    async def ban(
        self,
        *,
        entity_type: str,
        value: str,
        reason: str,
        source: str,
        created_by: str,
        duration_seconds: int | None = None,
        permanent: bool = False,
        evidence: dict[str, Any] | None = None,
        notify: bool = True,
    ) -> dict[str, Any]:
        if permanent == (duration_seconds is not None):
            raise ValueError("give exactly one of duration_seconds or permanent=true")
        expires_at = None if permanent else datetime.now(UTC) + timedelta(seconds=duration_seconds or 0)
        row = await self._repo.create_ban(
            entity_type=entity_type,
            value=value,
            reason=reason,
            source=source,
            evidence=evidence or {},
            permanent=permanent,
            expires_at=expires_at,
            created_by=created_by,
        )
        if notify:
            await self.notify_added(row)
        log.info(
            "ban created",
            extra={"ban_id": str(row["id"]), "type": entity_type, "source": source, "permanent": permanent},
        )
        return row

    async def unban(self, ban_id: UUID, revoked_by: str) -> dict[str, Any] | None:
        row = await self._repo.revoke_ban(ban_id, revoked_by)
        if row is not None:
            await self.notify_changed()
        return row

    # ------------------------------------------------------------------ escalation
    def _duration_for(self, strikes: StrikeCount, entity_type: str = "user") -> tuple[int | None, bool]:
        """(duration_seconds, permanent) for this many strikes. Automatic IP bans stop at the last
        ladder step when ``IP_BAN_NEVER_PERMANENT`` (addresses are reassigned to other people); session
        bans always do (a session is one contact — a permanent ban on it means nothing)."""
        s = self._settings
        never_permanent = entity_type == "session" or (
            entity_type in ("ip", "cidr") and s.ip_ban_never_permanent
        )
        if strikes.total >= s.permanent_after_strikes and strikes.deterministic > 0 and not never_permanent:
            return None, True
        ladder = s.ban_ladder_seconds
        step = min(strikes.total, len(ladder)) - 1
        return ladder[max(step, 0)], False

    async def record_strike(self, entity: Entity, *, reason: str, evidence: str, request_id: str) -> None:
        """Keep the durable record of a strike that does not lead to a ban."""
        await self._repo.record_strike(
            entity_type=entity.type,
            value=entity.value,
            reason=reason,
            evidence_kind=evidence,
            request_id=request_id,
            ban_id=None,
        )

    async def escalate(
        self, entity: Entity, strikes: StrikeCount, *, reason: str, evidence: str, request_id: str
    ) -> dict[str, Any] | None:
        """Ban ``entity`` according to its strike count. Returns the ban row, or None if none was created."""
        if entity.type == "ip" and self.is_never_ban(entity.value):
            log.info("strike on never-ban IP; not banning", extra={"request_id": request_id})
            await self._repo.record_strike(
                entity_type=entity.type,
                value=entity.value,
                reason=reason,
                evidence_kind=evidence,
                request_id=request_id,
                ban_id=None,
            )
            return None

        duration, permanent = self._duration_for(strikes, entity.type)
        new_expiry = None if permanent else datetime.now(UTC) + timedelta(seconds=duration or 0)
        subject = Subject(
            ip=entity.value if entity.type == "ip" else None,
            user_id=entity.value if entity.type == "user" else None,
            device_id=entity.value if entity.type == "device" else None,
            session_id=entity.value if entity.type == "session" else None,
        )
        existing = self.match(subject)
        if existing is not None and (
            existing.permanent
            or (not permanent and existing.expires_at and new_expiry and existing.expires_at >= new_expiry)
        ):
            ban_row: dict[str, Any] | None = None
        else:
            ban_row = await self.ban(
                entity_type=entity.type,
                value=entity.value,
                reason=f"auto: {reason}",
                source="auto",
                created_by="gateway",
                duration_seconds=duration,
                permanent=permanent,
                evidence={
                    "strikes_in_window": strikes.total,
                    "deterministic_strikes": strikes.deterministic,
                    "last_reason": reason,
                    "last_request_id": request_id,
                },
            )
        await self._repo.record_strike(
            entity_type=entity.type,
            value=entity.value,
            reason=reason,
            evidence_kind=evidence,
            request_id=request_id,
            ban_id=ban_row["id"] if ban_row else None,
        )
        return ban_row


def validate_cidr_not_too_broad(value: str, entity_type: str) -> None:
    """Refuse absurdly broad ranges (e.g. 0.0.0.0/0) that would ban everyone."""
    if entity_type != "cidr":
        return
    net = ipaddress.ip_network(value, strict=False)
    minimum = 8 if net.version == 4 else 16
    if net.prefixlen < minimum:
        raise ValueError(f"CIDR too broad: /{net.prefixlen} (minimum /{minimum})")
