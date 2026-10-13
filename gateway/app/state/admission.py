"""Rate limiting + reputation read, in one Redis round trip (see ``scripts.ADMISSION``).

Buckets:

| scope    | key                     | default             |
|----------|-------------------------|---------------------|
| session  | rl:session:{session_id} | burst 20, 0.2/s     |
| user     | rl:user:{user}          | burst 30, 0.5/s     |
| ip       | rl:ip:{ip}              | burst 60, 1/s (×10 on a shared IP) |
| api_key  | rl:key:{api_key_id}     | burst 2000, 200/s   |
| endpoint | rl:ep:{endpoint}        | burst 5000, 500/s   |
| global   | rl:global               | burst 10000, 1000/s |

Buckets for identities the request doesn't carry (no session, no user id, no IP) are not checked.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.config import Settings
from app.entities import Entity
from app.state.scripts import ADMISSION


@dataclass(frozen=True)
class Bucket:
    scope: str
    key: str
    capacity: float
    refill_per_sec: float
    cost: float = 1.0
    scalable: bool = False  # the IP bucket: larger for shared IPs


@dataclass
class AdmissionResult:
    allowed: bool
    limited_by: str | None = None
    retry_after_seconds: float = 0.0
    remaining: dict[str, float] = field(default_factory=dict)
    reputation: dict[str, float] = field(default_factory=dict)  # entity key -> score 0..100
    ip_users: int = 0  # distinct good users recently seen on the request's IP


def rep_key(entity: Entity) -> str:
    return f"rep:{entity.key()}"


class AdmissionService:
    def __init__(self, redis: Any, settings: Settings) -> None:
        self._settings = settings
        self._script = redis.register_script(ADMISSION)

    def buckets(
        self,
        *,
        api_key_id: str,
        endpoint: str,
        ip: str | None,
        user_id: str | None,
        session_id: str | None = None,
        end_user_cost: float = 1.0,
    ) -> list[Bucket]:
        """``end_user_cost`` > 1 makes a suspected bot drain its own session / user / ip buckets faster
        (Stage 8); the key, endpoint and global buckets always cost 1, so one bot can't exhaust CMP's
        quota."""
        s = self._settings
        out = [
            Bucket("api_key", f"rl:key:{api_key_id}", s.rl_api_key_capacity, s.rl_api_key_refill_per_sec),
            Bucket("global", "rl:global", s.rl_global_capacity, s.rl_global_refill_per_sec),
            Bucket("endpoint", f"rl:ep:{endpoint}", s.rl_endpoint_capacity, s.rl_endpoint_refill_per_sec),
        ]
        if session_id:
            out.append(
                Bucket(
                    "session",
                    f"rl:session:{session_id}",
                    s.rl_session_capacity,
                    s.rl_session_refill_per_sec,
                    end_user_cost,
                )
            )
        if ip:
            out.append(
                Bucket(
                    "ip",
                    f"rl:ip:{ip}",
                    s.rl_ip_capacity,
                    s.rl_ip_refill_per_sec,
                    end_user_cost,
                    scalable=True,
                )
            )
        if user_id:
            out.append(
                Bucket(
                    "user",
                    f"rl:user:{user_id}",
                    s.rl_user_capacity,
                    s.rl_user_refill_per_sec,
                    end_user_cost,
                )
            )
        return out

    async def admit(
        self, buckets: list[Bucket], reputation_of: list[Entity], shared_key: str | None = None
    ) -> AdmissionResult:
        """``shared_key``: the IP's good-user counter (``ipgood:{ip}``) — a shared IP gets a
        larger IP bucket (``SHARED_IP_RATE_MULTIPLIER``)."""
        s = self._settings
        keys = [b.key for b in buckets] + [rep_key(e) for e in reputation_of]
        if shared_key:
            keys.append(shared_key)
        args: list[Any] = [len(buckets)]
        for b in buckets:
            args += [b.capacity, b.refill_per_sec, b.cost, int(b.scalable)]
        args += [
            s.reputation_half_life_seconds,
            int(bool(shared_key)),
            s.shared_ip_min_users,
            s.shared_ip_rate_multiplier,
        ]

        raw = await self._script(keys=keys, args=args)
        denied = int(raw[0])
        retry = float(raw[1])
        n = len(buckets)
        remaining = {b.scope: float(raw[2 + i]) for i, b in enumerate(buckets)}
        reputation = {e.key(): float(raw[2 + n + j]) for j, e in enumerate(reputation_of)}
        return AdmissionResult(
            allowed=denied == 0,
            limited_by=buckets[denied - 1].scope if denied else None,
            retry_after_seconds=retry,
            remaining=remaining,
            reputation=reputation,
            ip_users=int(float(raw[-1])),
        )
