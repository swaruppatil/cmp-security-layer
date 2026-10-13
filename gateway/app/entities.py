"""Entities the gateway can rate-limit, score, strike and ban.

An entity is (type, value). The gateway serves one product (CMP), so there is no tenant scope:
a user id, a session id or an IP means the same thing on every request.

* type  — ip, cidr, user, device, session, api_key
  * ``session`` — the CMP / Amazon Connect contact id: one chat, start to end
  * ``user``    — the customer, as a keyed hash of the customer id (never the raw id)
* value — normalised: IPs in canonical form, CIDRs as networks, everything else as given.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Literal

EntityType = Literal["ip", "cidr", "user", "device", "session", "api_key"]
ENTITY_TYPES: tuple[EntityType, ...] = ("ip", "cidr", "user", "device", "session", "api_key")
# Identities of the *end user*: these collect reputation and strikes and can be auto-banned.
END_USER_TYPES: tuple[EntityType, ...] = ("user", "device", "session", "ip")

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network


@dataclass(frozen=True)
class Entity:
    type: EntityType
    value: str

    def key(self) -> str:
        return f"{self.type}:{self.value}"


def parse_ip(value: str | None) -> IPAddress | None:
    if not value:
        return None
    try:
        addr = ipaddress.ip_address(value.strip())
    except ValueError:
        return None
    # Treat IPv4-mapped IPv6 (::ffff:1.2.3.4) as the IPv4 address so bans match either form.
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        return addr.ipv4_mapped
    return addr


def normalize(entity_type: EntityType, value: str) -> str:
    """Canonical form of a value, or ValueError if it is not valid for the type."""
    value = value.strip()
    if not value:
        raise ValueError("value must not be empty")
    if entity_type == "ip":
        addr = parse_ip(value)
        if addr is None:
            raise ValueError(f"not an IP address: {value!r}")
        return str(addr)
    if entity_type == "cidr":
        try:
            return str(ipaddress.ip_network(value, strict=False))
        except ValueError as exc:
            raise ValueError(f"not a CIDR range: {value!r}") from exc
    if len(value) > 200:
        raise ValueError("value too long")
    return value


def parse_cidr_list(raw: str) -> list[IPNetwork]:
    return [ipaddress.ip_network(part.strip(), strict=False) for part in raw.split(",") if part.strip()]


def end_user_entities(
    ip: str | None, user_id: str | None, device_id: str | None, session_id: str | None = None
) -> list[Entity]:
    """The end-user identities present on a request, most personal first (IP last)."""
    out: list[Entity] = []
    if user_id:
        out.append(Entity("user", user_id))
    if device_id:
        out.append(Entity("device", device_id))
    if session_id:
        out.append(Entity("session", session_id))
    addr = parse_ip(ip)
    if addr is not None:
        out.append(Entity("ip", str(addr)))
    return out
