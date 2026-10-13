"""Policies: per channel, session state and endpoint, how decisions are enforced. Versioned; every
decision records the policy id and version that applied.

A policy (``policies`` table, every version kept in ``policy_versions``):

| field            | meaning                                                                       |
|------------------|-------------------------------------------------------------------------------|
| channel          | ``web``, ``sms``, ``whatsapp`` … or NULL for every channel                    |
| session_state    | ``anonymous`` / ``verified`` (after CMP's identity verification), or NULL for both |
| endpoint_pattern | glob on the logical endpoint (``*``, ``chat``, ``booking/*`` …)              |
| mode             | ``enforce`` — or ``monitor``: decide and record, but tell the caller "allow" (safe rollout) |
| actions          | overrides of the final action, e.g. ``{"restrict": "block"}`` on a sensitive endpoint, ``{"block": "restrict"}`` while tuning |
| thresholds       | ``ml_block_at`` / ``ml_restrict_at``: replace the model's calibrated thresholds |
| sensitive        | marks endpoints that act on data (bookings, refunds); informational for now   |

Resolution (most specific wins): a policy naming the channel beats one that doesn't, then one naming
the session state, then an exact endpoint over a pattern, then the longer pattern; the global default
(``*``, any channel, any state) catches the rest. Example: ``{channel: sms, session_state: anonymous,
actions: {"restrict": "block"}}`` is stricter for unverified SMS chats only. Policies are cached in memory and
reloaded every ``POLICY_CACHE_TTL_SECONDS`` and whenever any instance changes one (Redis pub/sub
``policies:changed``).

Safety rules hold whatever a policy says: a ban, a throttle and a canary leak are never overridden,
and monitor mode never strikes or bans anyone (the action the after-decision step sees is "allow").
"""

from __future__ import annotations

import fnmatch
import logging
import time
from dataclasses import dataclass, field
from typing import Any

from app.pipeline.models import Action, Decision

log = logging.getLogger("gateway.policy")
CHANNEL = "policies:changed"
OVERRIDABLE = frozenset({Action.ALLOW, Action.RESTRICT, Action.BLOCK, Action.INSPECT})
NEVER_OVERRIDE_REASONS = frozenset(
    {"banned", "canary_leak", "bot_detected", "rate_limited", "rate_limit_unavailable"}
)


@dataclass(frozen=True)
class Policy:
    id: str
    name: str
    endpoint_pattern: str
    version: int
    mode: str = "enforce"
    sensitive: bool = False
    thresholds: dict[str, float] = field(default_factory=dict)
    actions: dict[str, str] = field(default_factory=dict)
    channel: str | None = None
    session_state: str | None = None

    @classmethod
    def from_row(cls, row: dict[str, Any]) -> Policy:
        return cls(
            id=str(row["id"]),
            name=row["name"],
            endpoint_pattern=row["endpoint_pattern"],
            version=int(row["version"]),
            mode=row.get("mode", "enforce"),
            sensitive=bool(row.get("sensitive", False)),
            thresholds=dict(row.get("thresholds") or {}),
            actions=dict(row.get("actions") or {}),
            channel=row.get("channel"),
            session_state=row.get("session_state"),
        )

    def specificity(self) -> tuple[int, int, int, int]:
        wildcard = any(ch in self.endpoint_pattern for ch in "*?[")
        return (
            1 if self.channel else 0,
            1 if self.session_state else 0,
            0 if wildcard else 1,
            len(self.endpoint_pattern),
        )

    def matches(self, endpoint: str, channel: str | None, session_state: str | None) -> bool:
        if self.channel is not None and self.channel != (channel or "").lower():
            return False
        if self.session_state is not None and self.session_state != session_state:
            return False
        return fnmatch.fnmatchcase(endpoint, self.endpoint_pattern)


def apply(policy: Policy | None, decision: Decision) -> Decision:
    """Apply action overrides and monitor mode to a decision (in place) and stamp the policy on it."""
    if policy is None:
        return decision
    decision.policy_id, decision.policy_version, decision.policy_mode = policy.id, policy.version, policy.mode  # type: ignore[assignment]
    protected = bool(NEVER_OVERRIDE_REASONS & set(decision.reasons))
    override = policy.actions.get(decision.action.value)
    if override and not protected and decision.action in OVERRIDABLE:
        decision.action = Action(override)
    if policy.mode == "monitor" and decision.action != Action.ALLOW and not protected:
        decision.would_have, decision.action = decision.action, Action.ALLOW
    return decision


class PolicyService:
    def __init__(self, repo: Any, ttl_seconds: float = 30.0) -> None:
        self._repo = repo
        self._ttl = ttl_seconds
        self._policies: list[Policy] = []
        self._loaded_at = 0.0

    async def reload(self) -> None:
        try:
            rows = await self._repo.active_policies()
        except Exception:  # noqa: BLE001 - keep serving the last good set
            log.warning("policy reload failed; keeping %d cached policies", len(self._policies))
            self._loaded_at = time.monotonic()
            return
        self._policies = sorted(
            (Policy.from_row(r) for r in rows), key=lambda p: p.specificity(), reverse=True
        )
        self._loaded_at = time.monotonic()

    async def resolve(
        self, endpoint: str, *, channel: str | None = None, session_state: str | None = None
    ) -> Policy | None:
        if time.monotonic() - self._loaded_at > self._ttl:
            await self.reload()
        for p in self._policies:  # most specific first
            if p.matches(endpoint, channel, session_state):
                return p
        return None

    def invalidate(self) -> None:
        self._loaded_at = 0.0
