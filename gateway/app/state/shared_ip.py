"""Shared-IP awareness: who else is behind this address?

Many customers can share one IP (airport and hotel Wi-Fi, mobile-carrier NAT, offices). Two small
Redis structures per IP let the gateway tell a shared address from a single attacker:

* ``ipgood:{ip}`` — HyperLogLog of distinct users whose requests from this IP were
  **allowed** in the last 24 h. Written after every allowed, identified request; read by admission
  (to scale the IP rate limit) and after a striking block.
* ``ipbad:{ip}`` — set of distinct identities that got a **strike** from this IP in the last
  hour. Written and read after every striking block of an identified request.

A HyperLogLog counts distinct members in 12 KB at most, with ~1 % error — plenty to tell "one person"
from "a hundred people". Only allowed traffic counts as good, so an attacker who invents user ids
cannot make an IP look shared.
"""

from __future__ import annotations

from typing import Any

from app.config import Settings


def good_key(ip: str) -> str:
    return f"ipgood:{ip}"


def bad_key(ip: str) -> str:
    return f"ipbad:{ip}"


class SharedIpTracker:
    def __init__(self, redis: Any, settings: Settings) -> None:
        self._redis = redis
        self._s = settings

    async def note_good(self, ip: str, identity: str) -> None:
        async with self._redis.pipeline(transaction=False) as pipe:
            pipe.pfadd(good_key(ip), identity)
            pipe.expire(good_key(ip), self._s.shared_ip_window_seconds)
            await pipe.execute()

    async def users(self, ip: str) -> int:
        return int(await self._redis.pfcount(good_key(ip)))

    async def note_attacker(self, ip: str, identity: str) -> int:
        """Record a striking identity on this IP; return how many distinct ones there were recently."""
        async with self._redis.pipeline(transaction=True) as pipe:
            pipe.sadd(bad_key(ip), identity)
            pipe.expire(bad_key(ip), self._s.ip_attackers_window_seconds)
            pipe.scard(bad_key(ip))
            res = await pipe.execute()
        return int(res[-1])

    def is_shared(self, users: int) -> bool:
        return users >= self._s.shared_ip_min_users
