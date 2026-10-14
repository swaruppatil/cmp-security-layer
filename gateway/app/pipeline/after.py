"""What happens after a decision: reputation, strikes, automatic bans.

Runs as a background task after the response is sent, so it adds no latency. Every failure is
logged and swallowed: bookkeeping must never break request handling.

| Decision                                   | Effect on the identities it is charged to               |
|--------------------------------------------|---------------------------------------------------------|
| throttled                                  | reputation +5; after N throttles in a window → strike   |
| blocked by a check marked ``strike``       | reputation +25; strike (evidence kind from the check)   |
|                                            | — a session is banned only for deterministic strikes    |
|                                            | — a lone probabilistic verdict from a check named in    |
|                                            |   SINGLE_SIGNAL_NO_STRIKE (ml, rules) is a block, not a  |
|                                            |   strike: one model opinion never starts the ban ladder |
| AI reply blocked, probabilistic evidence   | the session only: its lock escalates, no ban (the AI's   |
|                                            |   fault, not the person's)                              |
| customer message blocked with strike       | session, customer, device: strikes and the ban ladder   |
|                                            |   (1 min, 5 min, …; BAN_LADDER_SECONDS)                 |
| blocked for another reason (e.g. too long) | reputation +2                                           |
| blocked because already banned             | nothing (no double counting)                            |
| allowed                                    | the customer / device counts as a "good user" of the IP |

**Who is charged — identity first.** Many people can share one IP (Wi-Fi, mobile-carrier NAT). So:

* a request with a session, user or device id is charged to those identities only — never to its IP
  (so an attack costs the attacker's own session and customer id, not the airport Wi-Fi);
* an anonymous request (IP only) is charged to the IP;
* the IP itself is charged as well only when ``IP_ATTACKERS_FOR_STRIKE`` *different* identities were
  struck from it within the window **and** it is not a shared IP (``SHARED_IP_MIN_USERS`` good users)
  — this catches one attacker rotating user ids or opening chat after chat, without punishing an
  airport's Wi-Fi. Only customer and device ids count as good users (opening a session is free).

Failed authentication is tracked separately (``record_auth_failure``), per connecting IP.
Conversation memory (Stage 6) is updated first, for every analysed turn of a tracked conversation.
Every decision is counted in the Prometheus metrics and published to the audit stream (Stage 9).
"""

from __future__ import annotations

import logging

from app import metrics
from app.audit.events import build_event
from app.audit.stream import AuditPublisher
from app.bans.service import BanService
from app.config import Settings
from app.conversation.service import ConversationService
from app.entities import Entity, end_user_entities, parse_ip
from app.pipeline.context import RequestContext
from app.pipeline.models import Action, Decision
from app.reputation.service import Evidence, ReputationService
from app.state.shared_ip import SharedIpTracker

log = logging.getLogger("gateway.after")
TRUSTED_FOR_SHARING = ("user", "device")


class AfterDecision:
    def __init__(
        self,
        reputation: ReputationService,
        bans: BanService,
        settings: Settings,
        conversations: ConversationService | None = None,
        audit: AuditPublisher | None = None,
        shared_ip: SharedIpTracker | None = None,
    ) -> None:
        self._rep = reputation
        self._bans = bans
        self._s = settings
        self._conversations = conversations
        self._audit = audit
        self._shared = shared_ip
        self._lone = frozenset(x.strip() for x in settings.single_signal_no_strike.split(",") if x.strip())

    async def __call__(self, ctx: RequestContext, decision: Decision) -> None:
        try:
            metrics.record(ctx.mode, decision)
            if self._audit is not None and self._s.audit_enabled:
                await self._audit.publish(build_event(ctx, decision, self._s))  # never raises
        except Exception:  # noqa: BLE001
            log.exception("audit / metrics failed", extra={"request_id": decision.request_id})
        if self._conversations is not None:
            await self._conversations.record(ctx, decision)  # never raises
        try:
            await self._handle(ctx, decision)
        except Exception:  # noqa: BLE001
            log.exception("post-decision bookkeeping failed", extra={"request_id": decision.request_id})

    async def _handle(self, ctx: RequestContext, decision: Decision) -> None:
        entities = end_user_entities(ctx.ip, ctx.user_id, ctx.device_id, ctx.session_id)
        if not entities:
            return
        personal = [e for e in entities if e.type != "ip"]
        ip_entity = next((e for e in entities if e.type == "ip"), None)

        if decision.action == Action.ALLOW:
            # Only a customer or device id makes an IP look shared: sessions cost nothing to open, so
            # counting them would let one client make its own IP "shared" (and its limit 10× larger).
            known = next((e for e in personal if e.type in TRUSTED_FOR_SHARING), None)
            if known is not None and ip_entity is not None and self._shared is not None:
                await self._shared.note_good(ip_entity.value, known.key())
            return
        if decision.action not in (Action.THROTTLE, Action.BLOCK) or "banned" in decision.reasons:
            return

        striking = [c for c in decision.checks if c.strike] if decision.action == Action.BLOCK else []
        evidence: Evidence = (
            "deterministic" if any(c.evidence == "deterministic" for c in striking) else "probabilistic"
        )
        if striking and evidence == "probabilistic" and len(striking) == 1 and striking[0].name in self._lone:
            # One probabilistic signal (the model, or a phrase rule the model did not confirm): refuse
            # the message, count the block, but do not start the ban ladder on a single opinion.
            log.info(
                "single probabilistic signal: block without strike",
                extra={"request_id": decision.request_id, "check": striking[0].name},
            )
            striking = []
        session = next((e for e in personal if e.type == "session"), None)
        reply_only = (
            bool(striking)
            and ctx.direction == "outbound"
            and evidence == "probabilistic"
            and session is not None
        )
        targets: list[Entity]
        if reply_only and session is not None:
            # A blocked AI reply (a secret, someone else's data) is evidence about the conversation, not
            # proof about the person: the session takes the strike and its lock escalates, nobody is
            # banned. A canary leak (deterministic: only an extracted system prompt contains it) still
            # strikes the customer.
            targets = [session]
        else:
            targets = await self._charged(
                personal, ip_entity, attack=bool(striking), request_id=decision.request_id
            )

        if decision.action == Action.THROTTLE:
            for e in targets:
                await self._rep.record(e, "throttled")
                count = await self._rep.count_event(e, "throttle", self._s.throttle_strike_window_seconds)
                if count >= self._s.throttle_strike_count:
                    await self._rep.reset_event(e, "throttle")
                    await self._strike(e, "rate_limit_abuse", "deterministic", decision.request_id)
            return

        if not striking:
            for e in targets:
                await self._rep.record(e, "blocked")
            return
        reason = striking[0].reason or striking[0].name
        for e in targets:
            await self._rep.record(e, "attack")
            await self._strike(e, reason, evidence, decision.request_id, ladder=not reply_only)

    async def _charged(
        self, personal: list[Entity], ip_entity: Entity | None, *, attack: bool, request_id: str
    ) -> list[Entity]:
        """The identities a refusal is charged to (see the module docstring)."""
        if not personal:
            return [ip_entity] if ip_entity is not None else []
        if ip_entity is None or not attack or self._shared is None:
            return personal
        attackers = await self._shared.note_attacker(ip_entity.value, personal[0].key())
        if attackers < self._s.ip_attackers_for_strike:
            return personal
        users = await self._shared.users(ip_entity.value)
        if self._shared.is_shared(users):
            log.info(
                "shared IP spared",
                extra={"request_id": request_id, "attackers": attackers, "good_users": users},
            )
            return personal
        return [*personal, ip_entity]

    async def _strike(
        self, entity: Entity, reason: str, evidence: Evidence, request_id: str, *, ladder: bool = True
    ) -> None:
        """Record a strike and, unless ``ladder`` is off, ban the entity for the ladder step its strike
        count reached: the customer's own attacks block them progressively (BAN_LADDER_SECONDS), while
        a chat whose AI replies leaked is only locked."""
        strikes = await self._rep.add_strike(entity, evidence, request_id)
        if not ladder:
            await self._bans.record_strike(entity, reason=reason, evidence=evidence, request_id=request_id)
            return
        ban = await self._bans.escalate(
            entity, strikes, reason=reason, evidence=evidence, request_id=request_id
        )
        log.info(
            "strike recorded",
            extra={
                "request_id": request_id,
                "entity_type": entity.type,
                "strikes": strikes.total,
                "banned": ban is not None,
            },
        )

    async def record_auth_failure(self, ip: str | None, request_id: str) -> None:
        """Brute-force protection: too many bad keys from one IP → strike → IP ban."""
        try:
            addr = parse_ip(ip)
            if addr is None:
                return
            entity = Entity("ip", str(addr))
            await self._rep.record(entity, "auth_failed")
            count = await self._rep.count_event(entity, "auth_failed", self._s.auth_fail_window_seconds)
            if count >= self._s.auth_fail_strike_count:
                await self._rep.reset_event(entity, "auth_failed")
                await self._strike(entity, "auth_bruteforce", "deterministic", request_id)
        except Exception:  # noqa: BLE001
            log.exception("auth-failure bookkeeping failed", extra={"request_id": request_id})
