"""In-memory index of active bans. Every lookup is local: no network call on the request path.

* Exact entities (ip, user, device, session, api_key): one dict lookup per (type, value).
* CIDR ranges: grouped by (IP version, prefix length). Checking an IP masks it once per
  prefix length present and does a dict lookup, so the cost depends on how many *different* prefix
  lengths are banned (a handful), not on how many ranges (could be thousands).

Expiry is checked at lookup time, so a ban stops applying the moment it expires even before the next
reload.
"""

from __future__ import annotations

import ipaddress
from collections import defaultdict
from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import UUID

from app.entities import IPAddress, parse_ip


@dataclass(frozen=True)
class BanEntry:
    id: UUID
    entity_type: str
    value: str
    permanent: bool
    expires_at: datetime | None
    source: str

    def active(self, now: datetime) -> bool:
        return self.permanent or (self.expires_at is not None and self.expires_at > now)

    def stronger_than(self, other: BanEntry) -> bool:
        if self.permanent != other.permanent:
            return self.permanent
        return (self.expires_at or datetime.min.replace(tzinfo=UTC)) > (
            other.expires_at or datetime.min.replace(tzinfo=UTC)
        )


@dataclass(frozen=True)
class Subject:
    """The identities on one request that bans can match."""

    ip: str | None = None
    user_id: str | None = None
    device_id: str | None = None
    session_id: str | None = None
    api_key_id: str | None = None


class BanIndex:
    def __init__(self, entries: list[BanEntry] | None = None) -> None:
        self._exact: dict[tuple[str, str], BanEntry] = {}
        # version -> prefixlen -> network_address_int -> entry
        self._nets: dict[int, dict[int, dict[int, BanEntry]]] = defaultdict(dict)
        self.size = 0
        for e in entries or []:
            self.add(e)

    def add(self, entry: BanEntry) -> None:
        if entry.entity_type == "cidr":
            net = ipaddress.ip_network(entry.value, strict=False)
            by_len = self._nets[net.version].setdefault(net.prefixlen, {})
            current = by_len.get(int(net.network_address))
            if current is None or entry.stronger_than(current):
                by_len[int(net.network_address)] = entry
        else:
            key = (entry.entity_type, entry.value)
            current = self._exact.get(key)
            if current is None or entry.stronger_than(current):
                self._exact[key] = entry
        self.size += 1

    def _exact_hit(self, entity_type: str, value: str | None, now: datetime) -> BanEntry | None:
        if value is None:
            return None
        e = self._exact.get((entity_type, value))
        return e if e is not None and e.active(now) else None

    def _cidr_hit(self, addr: IPAddress, now: datetime) -> BanEntry | None:
        by_len = self._nets.get(addr.version)
        if not by_len:
            return None
        bits = 32 if addr.version == 4 else 128
        as_int = int(addr)
        for prefixlen, nets in by_len.items():
            mask = ((1 << prefixlen) - 1) << (bits - prefixlen) if prefixlen else 0
            e = nets.get(as_int & mask)
            if e is not None and e.active(now):
                return e
        return None

    def match(self, subject: Subject, now: datetime | None = None) -> BanEntry | None:
        """The ban that applies to this request, if any (the most personal identity first)."""
        now = now or datetime.now(UTC)
        addr = parse_ip(subject.ip)
        ip_value = str(addr) if addr is not None else None
        for entity_type, value in (
            ("user", subject.user_id),
            ("device", subject.device_id),
            ("session", subject.session_id),
            ("api_key", subject.api_key_id),
            ("ip", ip_value),
        ):
            hit = self._exact_hit(entity_type, value, now)
            if hit is not None:
                return hit
        if addr is not None:
            return self._cidr_hit(addr, now)
        return None
