"""Reputation scores, strike counters and event windows (Redis).

* Reputation: 0–100 per entity, rises with bad behaviour, halves every half-life (default 6 h).
* Strikes: a sorted set per entity holding the strikes of the last 30 days, each tagged with the kind
  of evidence behind it, so escalation can tell certain evidence from model guesses.
* Event windows: fixed-window counters for throttles and failed logins.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Literal

from app.config import Settings
from app.entities import Entity
from app.state.admission import rep_key
from app.state.scripts import REPUTATION_ADD, STRIKE_ADD, WINDOW_COUNT

Evidence = Literal["deterministic", "probabilistic"]

# How much each event raises the score (0–100 scale).
REPUTATION_DELTAS: dict[str, float] = {
    "throttled": 5.0,
    "blocked": 2.0,  # refused for a non-attack reason (e.g. too long)
    "attack": 25.0,  # refused by a check that counts as a strike
    "auth_failed": 5.0,
}


@dataclass(frozen=True)
class StrikeCount:
    total: int
    deterministic: int


class ReputationService:
    def __init__(self, redis: Any, settings: Settings) -> None:
        self._redis = redis
        self._settings = settings
        self._add = redis.register_script(REPUTATION_ADD)
        self._strike = redis.register_script(STRIKE_ADD)
        self._window = redis.register_script(WINDOW_COUNT)

    async def record(self, entity: Entity, event: str) -> float:
        delta = REPUTATION_DELTAS[event]
        s = self._settings
        raw = await self._add(
            keys=[rep_key(entity)],
            args=[delta, s.reputation_half_life_seconds, s.reputation_ttl_seconds, event],
        )
        return float(raw)

    async def add_strike(self, entity: Entity, evidence: Evidence, request_id: str) -> StrikeCount:
        raw = await self._strike(
            keys=[f"strikes:{entity.key()}"],
            args=[self._settings.strike_window_seconds, evidence, request_id],
        )
        return StrikeCount(total=int(raw[0]), deterministic=int(raw[1]))

    async def count_event(self, entity: Entity, event: str, window_seconds: int) -> int:
        return int(await self._window(keys=[f"win:{event}:{entity.key()}"], args=[window_seconds]))

    async def reset_event(self, entity: Entity, event: str) -> None:
        await self._redis.delete(f"win:{event}:{entity.key()}")

    async def snapshot(self, entity: Entity) -> dict[str, Any]:
        """Current score (decayed), event counters and strikes — for the admin API."""
        data = await self._redis.hgetall(rep_key(entity))
        decoded = {
            k.decode() if isinstance(k, bytes) else k: v.decode() if isinstance(v, bytes) else v
            for k, v in data.items()
        }
        score = 0.0
        if "score" in decoded:
            # Same decay rule as the Lua scripts, applied locally (read-only).
            age = max(0.0, time.time() - float(decoded.get("ts", time.time())))
            score = float(decoded["score"]) * 0.5 ** (age / self._settings.reputation_half_life_seconds)
        events = {k.removeprefix("event:"): int(v) for k, v in decoded.items() if k.startswith("event:")}
        strikes = await self._redis.zrange(f"strikes:{entity.key()}", 0, -1)
        members = [m.decode() if isinstance(m, bytes) else m for m in strikes]
        return {
            "entity": {"type": entity.type, "value": entity.value},
            "score": round(score, 2),
            "events": events,
            "strikes": {
                "total": len(members),
                "deterministic": sum(1 for m in members if ":deterministic:" in m),
            },
        }

    async def clear(self, entity: Entity) -> None:
        """Forget an entity's reputation and strikes (used when an admin unbans with clear_history)."""
        await self._redis.delete(rep_key(entity), f"strikes:{entity.key()}")
