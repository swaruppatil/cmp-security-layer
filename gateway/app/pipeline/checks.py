"""Pipeline checks.

Each check is an async callable ``(ctx) -> CheckResult``, run in this order by ``build_pipeline``:

1. ``ban``       — local, no network. Banned → BLOCK.
   ``bot``       — (Stage 8) one Redis call: bot features → score → tier. Bot tier → THROTTLE; lower
                   tiers make the next step drain the end user's buckets faster.
2. ``admission`` — one Redis call: token buckets (THROTTLE when empty) + reputation (RESTRICT when poor).
3. ``size``      — empty / oversized text → BLOCK.
   ``sensitive`` — (Stage 7) PII / payment / secrets; high-risk types redacted before the AI. No action.
4. ``conversation_memory`` — (requests with a session id) one Redis GET; prepares the window.
5. ``rules``     — local detectors (phrases, tokens, encodings, markup). high → BLOCK + strike.
6. ``ml``        — injection classifier, strict timeout; also scores the conversation window.
7. ``conversation`` — multi-turn signals (``app/conversation/analysis.py``).

A check that blocks stops the pipeline, so later (more expensive) checks never run for it.
"""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable
from typing import Any

from app.bans.index import Subject
from app.bans.service import BanService
from app.bots.service import BotService
from app.config import Settings, parse_channel_limits
from app.conversation.analysis import TurnInput, assess
from app.conversation.service import ConversationService
from app.conversation.state import text_hash
from app.detectors import sensitive
from app.detectors.engine import analyze
from app.entities import end_user_entities
from app.ml.client import MLClient, MLUnavailable
from app.pipeline.context import ConversationWindow, RequestContext
from app.pipeline.models import Action, CheckResult
from app.session.identity import identifier_hash
from app.state.admission import AdmissionService
from app.state.shared_ip import good_key

log = logging.getLogger("gateway.checks")

Check = Callable[[RequestContext], Awaitable[CheckResult | None]]


def make_ban_check(bans: BanService) -> Check:
    async def ban_check(ctx: RequestContext) -> CheckResult:
        hit = bans.match(
            Subject(
                ip=ctx.ip,
                user_id=ctx.user_id,
                device_id=ctx.device_id,
                session_id=ctx.session_id,
                api_key_id=str(ctx.principal.api_key_id),
            )
        )
        if hit is None:
            return CheckResult(name="ban", passed=True)
        return CheckResult(
            name="ban",
            passed=False,
            score=1.0,
            action=Action.BLOCK,
            reason="banned",
            detail={
                "ban_id": str(hit.id),
                "entity_type": hit.entity_type,
                "permanent": hit.permanent,
                "expires_at": hit.expires_at.isoformat() if hit.expires_at else None,
                "source": hit.source,
            },
        )

    return ban_check


def make_bot_check(bots: BotService, settings: Settings) -> Check:
    """Bot score for the request's end-user identities (see ``app/bots/service.py``).

    ``None`` when the request has no profiled identity (no session / user / device / IP, or only a
    trusted shared IP). Redis unavailable → skipped (fail open; rate limits still apply). The user
    agent only counts on channels where it is the customer's browser (``BOT_UA_CHANNELS``)."""
    ua_channels = {c.strip().lower() for c in settings.bot_ua_channels.split(",") if c.strip()}

    async def bot_check(ctx: RequestContext) -> CheckResult | None:
        entities = end_user_entities(ctx.ip, ctx.user_id, ctx.device_id, ctx.session_id)
        ua_counts = ctx.channel is None or ctx.channel.lower() in ua_channels
        try:
            result = await bots.assess(
                entities,
                ctx.text,
                user_agent=ctx.user_agent if ua_counts else None,
                user_agent_expected=ctx.user_agent_expected and ua_counts,
                ip=ctx.ip,
            )
        except Exception:  # noqa: BLE001
            log.warning("bot features unavailable", extra={"request_id": ctx.request_id})
            return CheckResult(name="bot", passed=True, detail={"unavailable": True})
        if result is None:
            return None
        ctx.bot_cost = result.cost
        detail: dict[str, Any] = {
            "score": result.score,
            "tier": result.tier,
            "signals": result.signals,
            "cost": result.cost,
            "features": result.features,
        }
        if result.campaign_identities:
            detail["campaign_identities"] = result.campaign_identities
        if result.tier == "bot":
            detail["retry_after_seconds"] = settings.bot_cooldown_seconds
            return CheckResult(
                name="bot",
                passed=False,
                score=result.score,
                action=Action.THROTTLE,
                reason="bot_detected",
                detail=detail,
            )
        return CheckResult(name="bot", passed=result.tier == "normal", score=result.score, detail=detail)

    return bot_check


def make_admission_check(admission: AdmissionService, settings: Settings) -> Check:
    """Rate limits + reputation in one Redis round trip."""

    async def admission_check(ctx: RequestContext) -> CheckResult:
        entities = end_user_entities(ctx.ip, ctx.user_id, ctx.device_id, ctx.session_id)
        ip = next((e.value for e in entities if e.type == "ip"), None)
        buckets = admission.buckets(
            api_key_id=str(ctx.principal.api_key_id),
            endpoint=ctx.endpoint,
            ip=ip,
            user_id=ctx.user_id,
            session_id=ctx.session_id,
            end_user_cost=ctx.bot_cost,
        )
        try:
            result = await admission.admit(buckets, entities, shared_key=good_key(ip) if ip else None)
        except Exception as exc:  # noqa: BLE001 - Redis unavailable
            log.warning("admission check unavailable: %s", type(exc).__name__)
            if settings.rate_limit_failure_mode == "closed":
                return CheckResult(
                    name="admission",
                    passed=False,
                    score=0.0,
                    action=Action.THROTTLE,
                    reason="rate_limit_unavailable",
                    detail={"retry_after_seconds": 1},
                )
            return CheckResult(
                name="admission",
                passed=True,
                reason=None,
                detail={"degraded": True, "error": type(exc).__name__},
            )

        shared = ip is not None and result.ip_users >= settings.shared_ip_min_users
        identified = any(e.type in ("user", "device") for e in entities)
        # A known customer (or device) on a shared IP is judged by their own reputation, not by the
        # address's (which other people behind it may have earned). An anonymous session is not.
        judged = {
            k: v for k, v in result.reputation.items() if not (identified and shared and k.startswith("ip:"))
        }
        worst = max(judged.values(), default=0.0)
        detail = {
            "remaining": {k: round(v, 2) for k, v in result.remaining.items()},
            "reputation": {k: round(v, 2) for k, v in result.reputation.items()},
            "ip_users": result.ip_users,
            "ip_shared": shared,
        }
        if not result.allowed:
            retry = max(1, int(result.retry_after_seconds + 0.999))
            return CheckResult(
                name="admission",
                passed=False,
                score=0.0,
                action=Action.THROTTLE,
                reason="rate_limited",
                detail={
                    **detail,
                    "limited_by": result.limited_by,
                    "retry_after_seconds": retry,
                    "cost": ctx.bot_cost,
                },
            )
        if worst >= settings.reputation_restrict_at:
            return CheckResult(
                name="admission",
                passed=False,
                score=round(worst / 100, 3),
                action=Action.RESTRICT,
                reason="poor_reputation",
                detail=detail,
            )
        return CheckResult(name="admission", passed=True, score=round(worst / 100, 3), detail=detail)

    return admission_check


def make_size_check(settings: Settings) -> Check:
    """Block empty and oversized text (characters, after stripping whitespace for the empty test).

    The limit can be stricter per channel (``CHANNEL_MAX_CHARS``: an SMS is at most 1600 characters, so
    a 4000-character "SMS" did not come from a phone); ``MAX_PROMPT_CHARS`` is the ceiling for all."""
    per_channel = parse_channel_limits(settings.channel_max_chars)

    async def size_check(ctx: RequestContext) -> CheckResult:
        limit = min(
            per_channel.get((ctx.channel or "").lower(), settings.max_prompt_chars), settings.max_prompt_chars
        )
        length = len(ctx.text)
        if not ctx.text.strip():
            return CheckResult(
                name="size",
                passed=False,
                score=1.0,
                action=Action.BLOCK,
                reason="empty_message",
                detail={"chars": length},
            )
        if length > limit:
            return CheckResult(
                name="size",
                passed=False,
                score=1.0,
                action=Action.BLOCK,
                reason="message_too_long",
                detail={"chars": length, "limit": limit},
            )
        return CheckResult(name="size", passed=True, detail={"chars": length, "limit": limit})

    return size_check


def make_sensitive_check(settings: Settings) -> Check:
    """Find personal data, payment data and secrets in user text; redact the high-risk types.

    It never blocks: customers legitimately send their own details. Redaction means the AI (and the
    conversation memory, and any log) never sees a card number, SIN, passport number or credential.
    Identifiers the customer typed (booking ref, email, phone, ticket, Aeroplan) are remembered for the
    session as keyed hashes, so the AI may repeat them back (see the outbound ``reply_data`` check).
    ``None`` (left out of the decision) when nothing was found."""
    redact_types = sensitive.parse_types(settings.inbound_redact_types)
    scoped = sensitive.parse_types(settings.outbound_scope_types)
    hash_key = settings.identity_hash_key.get_secret_value()

    async def sensitive_check(ctx: RequestContext) -> CheckResult | None:
        fields = ctx.text_fields or [ctx.text]
        findings = [f for i, text in enumerate(fields) for f in sensitive.find(text, field=i)]
        if not findings:
            return None
        ctx.redactions = [f.public() | {"redacted": f.type in redact_types} for f in findings]
        if ctx.session_id:
            for i, text in enumerate(fields):
                own = [f for f in findings if f.field == i and f.type in scoped]
                for f, value in sensitive.values(text, own):
                    ctx.typed_identifiers.setdefault(f.type, set()).add(
                        identifier_hash(hash_key, f.type, value, normalized=True)
                    )
        if any(f.type in redact_types for f in findings):
            ctx.redacted_fields = [
                sensitive.redact(
                    text, [f for f in findings if f.field == i], lambda f: f.type in redact_types
                )
                for i, text in enumerate(fields)
            ]
        types = sorted({f.type for f in findings})
        return CheckResult(
            name="sensitive",
            passed=True,
            detail={
                "types": types,
                "redacted": sorted({f.type for f in findings if f.type in redact_types}),
                "count": len(findings),
            },
        )

    return sensitive_check


SEVERITY_SCORE = {"high": 0.95, "medium": 0.6, "low": 0.3}


def make_rules_check(settings: Settings) -> Check:
    """Fast local detection: attack phrases, role tokens, encoded / hidden payloads, markup, links.

    high   → BLOCK + deterministic strike
    medium → RESTRICT
    low    → no action; raises risk
    """
    allowed = tuple(d.strip().lower() for d in settings.allowed_link_domains.split(",") if d.strip())

    async def rules_check(ctx: RequestContext) -> CheckResult:
        fields = ctx.text_fields or [ctx.text]
        analysis = analyze(fields, allowed_link_domains=allowed, max_links=settings.max_links)
        severity = analysis.severity
        detail = {
            "ruleset": analysis.ruleset_version,
            "findings": [
                {"id": f.id, "family": f.family, "severity": f.severity, "via": f.via, "field": f.field}
                for f in analysis.findings
            ],
        }
        if severity is None:
            return CheckResult(name="rules", passed=True, detail=detail)
        worst = analysis.of(severity)[0]
        score = SEVERITY_SCORE[severity]
        if severity == "high":
            return CheckResult(
                name="rules",
                passed=False,
                score=score,
                action=Action.BLOCK,
                reason=worst.family,
                detail=detail,
                strike=True,
                evidence="deterministic",
            )
        if severity == "medium":
            return CheckResult(
                name="rules",
                passed=False,
                score=score,
                action=Action.RESTRICT,
                reason=worst.family,
                detail=detail,
            )
        return CheckResult(name="rules", passed=True, score=score, detail=detail)

    return rules_check


def make_ml_check(client: MLClient, settings: Settings) -> Check:
    """Injection classifier in the ML service. Never the *only* thing standing in front of a
    sensitive action: when it can't answer, ML_FAILURE_MODE decides (default restrict).

    For a tracked conversation the same call also scores the conversation window and returns
    embeddings; only this request's own fields decide this check."""

    async def ml_check(ctx: RequestContext) -> CheckResult:
        fields = [f for f in (ctx.text_fields or [ctx.text]) if len(f.strip()) >= settings.ml_min_chars]
        # The joined window rides along only when its ML score may act (CONV_WINDOW_ML_ACTION).
        use_window = ctx.window is not None and settings.conv_window_ml_action != "off"
        window = ctx.window.text if use_window and ctx.window is not None else None
        texts = fields + ([window] if window else [])
        if not texts:
            return CheckResult(name="ml", passed=True, detail={"skipped": "too_short"})
        try:
            result = await client.score(
                texts, settings.max_prompt_chars, vectors=ctx.conversation is not None
            )
        except MLUnavailable as exc:
            detail: dict[str, Any] = {"unavailable": exc.reason, "failure_mode": settings.ml_failure_mode}
            if not fields:  # only the window would have been scored; this turn itself is too short
                return CheckResult(name="ml", passed=True, detail={**detail, "skipped": "too_short"})
            mode = settings.ml_failure_mode
            if mode == "allow":
                return CheckResult(name="ml", passed=True, detail={**detail, "degraded": True})
            action = Action.RESTRICT if mode == "restrict" else Action.BLOCK
            return CheckResult(name="ml", passed=False, action=action, reason="ml_unavailable", detail=detail)

        ctx.ml, ctx.ml_fields = result, len(fields)
        if not fields:
            return CheckResult(name="ml", passed=True, detail={"skipped": "too_short", "window_scored": True})
        own = result.per_text[: len(fields)] if result.per_text else []
        top = max(own, key=lambda t: t.score) if own else None
        score = round(top.score if top else result.score, 4)
        block_at, restrict_at, source = resolve_ml_thresholds(ctx, settings, result.thresholds)
        scored: dict[str, Any] = {
            "score": score,
            "model_version": result.model_version,
            "service_latency_ms": result.service_latency_ms,
            "thresholds": {"block": block_at, "restrict": restrict_at, "source": source},
        }
        components = top.components if top else result.components
        if components:
            scored["components"] = components
        if top is not None:
            ctx.turn_vector = top.vector
            if components and "attack_similarity" in components and "benign_similarity" in components:
                ctx.turn_attack_lean = round(
                    float(components["attack_similarity"]) - float(components["benign_similarity"]), 4
                )
        if score >= block_at:
            return CheckResult(
                name="ml",
                passed=False,
                score=score,
                action=Action.BLOCK,
                reason="ml_injection",
                detail=scored,
                strike=True,
                evidence="probabilistic",
            )
        if score >= restrict_at:
            return CheckResult(
                name="ml",
                passed=False,
                score=score,
                action=Action.RESTRICT,
                reason="ml_suspicious",
                detail=scored,
            )
        return CheckResult(name="ml", passed=True, score=score, detail=scored)

    return ml_check


def resolve_ml_thresholds(
    ctx: RequestContext, settings: Settings, model: dict[str, float] | None
) -> tuple[float, float, str]:
    """(block, restrict, source). Precedence: the request's policy, then the model's calibrated
    thresholds (unless ML_USE_MODEL_THRESHOLDS=false), then the gateway settings."""
    if settings.ml_use_model_thresholds and model:
        block, restrict, source = model["block"], model["restrict"], "model"
    else:
        block, restrict, source = settings.ml_block_at, settings.ml_restrict_at, "gateway"
    t = ctx.policy.thresholds if ctx.policy is not None else {}
    if "ml_block_at" in t or "ml_restrict_at" in t:
        block, restrict, source = (
            float(t.get("ml_block_at", block)),
            float(t.get("ml_restrict_at", restrict)),
            "policy",
        )
    return block, restrict, source


def ml_thresholds(ctx: RequestContext, settings: Settings) -> tuple[float, float]:
    """(block, restrict) the ML check used for this request."""
    block, restrict, _ = resolve_ml_thresholds(
        ctx, settings, ctx.ml.thresholds if ctx.ml is not None else None
    )
    return block, restrict


def make_conversation_memory_check(service: ConversationService, settings: Settings) -> Check:
    """Load this session's conversation memory (one Redis GET) and build the window for the ML call.

    No session id → nothing to do (``None``: left out of the decision). Redis unavailable →
    conversation analysis is skipped for this request (fail open; single-turn checks still run)."""

    async def conversation_memory_check(ctx: RequestContext) -> CheckResult | None:
        if not ctx.session_id:
            return None
        try:
            state = await service.load(ctx.session_id)
        except Exception:  # noqa: BLE001
            log.warning("conversation memory unavailable", extra={"request_id": ctx.request_id})
            return CheckResult(name="conversation_memory", passed=True, detail={"unavailable": True})
        ctx.conversation = state
        previous = [t for t in state.seen_by_ai() if t.text][-(settings.conv_window_turns - 1) :]
        if previous:
            ctx.window = ConversationWindow(
                text="\n".join([*(t.text or "" for t in previous), ctx.text]),
                turn_max=max(t.score for t in previous),
                rule_ids={rid for t in previous for rid in t.rule_ids},
            )
        return CheckResult(
            name="conversation_memory",
            passed=True,
            detail={
                "turns": state.n,
                "remembered": len(state.turns),
                "blocks": state.blocks,
                "accumulated": state.acc,
                "window_turns": len(previous) + 1 if previous else 0,
            },
        )

    return conversation_memory_check


def make_conversation_check(settings: Settings) -> Check:
    """Multi-turn signals (see ``app/conversation/analysis.py``). Runs last, after rules and ML."""
    allowed = tuple(d.strip().lower() for d in settings.allowed_link_domains.split(",") if d.strip())

    async def conversation_check(ctx: RequestContext) -> CheckResult | None:
        state = ctx.conversation
        if state is None:
            return None
        by_name = {r.name: r for r in ctx.results}
        turn_score = max((by_name[n].score for n in ("rules", "ml") if n in by_name), default=0.0)
        rules = by_name.get("rules")
        rule_ids = [f["id"] for f in rules.detail.get("findings", [])] if rules else []
        block_at, restrict_at = ml_thresholds(ctx, settings)

        turn = TurnInput(
            score=turn_score,
            hash=text_hash(ctx.text),
            vector=ctx.turn_vector,
            attack_lean=ctx.turn_attack_lean,
            rule_ids=rule_ids,
            block_at=block_at,
            restrict_at=restrict_at,
        )
        if ctx.window is not None:
            turn.window_turn_max = max(ctx.window.turn_max, turn_score)
            if ctx.ml is not None and len(ctx.ml.per_text) > ctx.ml_fields:
                turn.window_score = ctx.ml.per_text[ctx.ml_fields].score
            # Rules on the joined window: only findings no single turn produced on its own.
            seen = ctx.window.rule_ids | set(rule_ids)
            found = analyze([ctx.window.text], allowed_link_domains=allowed, max_links=settings.max_links)
            turn.window_rules = [
                (f.id, f.severity)
                for f in found.findings
                if f.id not in seen and f.severity in ("high", "medium")
            ]

        result = assess(state, turn, settings)
        worst = result.worst
        if worst is None:
            return CheckResult(name="conversation", passed=True, detail=result.detail)
        return CheckResult(
            name="conversation",
            passed=False,
            score=round(min(1.0, worst.score), 4),
            action=worst.action,
            reason=worst.reason,
            detail=result.detail,
            strike=worst.strike,
            evidence="probabilistic" if worst.strike else None,
        )

    return conversation_check
