"""Pipeline checks.

Each check is an async callable ``(ctx) -> CheckResult``, run in this order by ``build_pipeline``:

1. ``ban``       — local, no network. Banned → BLOCK.
   ``bot``       — (Stage 8) one Redis call: bot features → score → tier. Bot tier → THROTTLE; lower
                   tiers make the next step drain the end user's buckets faster.
2. ``admission`` — one Redis call: token buckets (THROTTLE when empty) + reputation (RESTRICT when poor).
3. ``size``      — empty / oversized text → BLOCK.
   ``sensitive`` — (Stage 7) PII / payment / secrets; high-risk types redacted before the AI. No action.
   ``enumeration`` — many different booking refs / tickets / Aeroplan numbers from one chat or IP
                   → restrict (4 in a chat) or block (8); one Redis call, only when identifiers appear.
4. ``conversation_memory`` — (requests with a session id) one Redis GET; prepares the window.
5. ``rules``     — local detectors (phrases, tokens, encodings, markup). high → BLOCK + strike.
6. ``ml``        — injection classifier, strict timeout; also scores the conversation window.
7. ``conversation`` — multi-turn signals (``app/conversation/analysis.py``).
8. ``failure_policy`` — a sensitive endpoint (bookings, refunds, payments …) whose Redis-backed checks
                   or session record were unavailable → restrict (``state_unavailable``).

A check that blocks stops the pipeline, so later (more expensive) checks never run for it.
"""

from __future__ import annotations

import fnmatch
import logging
import re
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
from app.entities import end_user_entities, parse_cidr_list, parse_ip
from app.ml.client import MLClient, MLUnavailable
from app.pipeline.context import ConversationWindow, RequestContext
from app.pipeline.models import Action, CheckResult
from app.session.identity import identifier_hash
from app.state.admission import AdmissionService
from app.state.enumeration import EnumerationTracker
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
        # Keyed hashes of the identifiers typed here: remembered for the session (repeat-back scope) and
        # counted by the enumeration check.
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


def make_enumeration_check(tracker: EnumerationTracker, settings: Settings) -> Check:
    """Many *different* booking references (tickets, Aeroplan numbers) from one chat — or from one IP
    across chats — within ``ENUM_WINDOW_SECONDS``: someone guessing references to find a valid one.

    Counts the identifiers the ``sensitive`` check found in this message (keyed hashes, never values).
    The verified customer's own identifiers never count. The IP is not counted when it is shared (3+
    known customers use it) or on the never-ban list — many honest people type references there.

    chat ≥ ENUM_SESSION_RESTRICT_AT (4) or IP ≥ ENUM_IP_RESTRICT_AT (12) → restrict (no tools, so no
    lookups); chat ≥ ENUM_SESSION_BLOCK_AT (8) → block + a probabilistic strike (never bans a session).
    ``None`` when the message carries none of the counted identifiers."""
    types = {t.strip() for t in settings.enum_types.split(",") if t.strip()}
    never = parse_cidr_list(settings.never_ban_cidrs)

    async def enumeration_check(ctx: RequestContext) -> CheckResult | None:
        typed = {
            t: hashes - ctx.own_identifiers.get(t, set())
            for t, hashes in ctx.typed_identifiers.items()
            if t in types
        }
        typed = {t: h for t, h in typed.items() if h}
        if not typed:
            return None
        admission = next((r for r in ctx.results if r.name == "admission"), None)
        shared = bool(admission and admission.detail.get("ip_shared"))
        addr = parse_ip(ctx.ip)
        trusted = addr is not None and any(addr in n for n in never if addr.version == n.version)
        ip = str(addr) if addr is not None and not shared and not trusted else None
        try:
            counts = await tracker.note(ctx.session_id, ip, typed)
        except Exception:  # noqa: BLE001 - Redis down: skipped (the failure policy covers sensitive endpoints)
            log.warning("enumeration counters unavailable", extra={"request_id": ctx.request_id})
            return CheckResult(name="enumeration", passed=True, detail={"unavailable": True})
        in_chat = max(counts.get("session", {}).values(), default=0)
        from_ip = max(counts.get("ip", {}).values(), default=0)
        detail: dict[str, Any] = {
            "counts": counts,
            "ip_counted": ip is not None,
            "thresholds": {
                "session_restrict": settings.enum_session_restrict_at,
                "session_block": settings.enum_session_block_at,
                "ip_restrict": settings.enum_ip_restrict_at,
            },
        }
        if in_chat >= settings.enum_session_block_at:
            return CheckResult(
                name="enumeration",
                passed=False,
                score=0.9,
                action=Action.BLOCK,
                reason="identifier_enumeration",
                detail=detail,
                strike=True,
                evidence="probabilistic",
            )
        if in_chat >= settings.enum_session_restrict_at or from_ip >= settings.enum_ip_restrict_at:
            return CheckResult(
                name="enumeration",
                passed=False,
                score=0.6,
                action=Action.RESTRICT,
                reason="identifier_enumeration",
                detail=detail,
            )
        return CheckResult(name="enumeration", passed=True, detail=detail)

    return enumeration_check


# Checks whose state lives in Redis: when one of them could not run, a sensitive endpoint fails safe.
STATEFUL_CHECKS = ("bot", "admission", "conversation_memory", "enumeration")


def make_failure_policy_check(settings: Settings) -> Check:
    """Failure policy for sensitive endpoints — the last check.

    A request is sensitive when its policy says so (``sensitive: true``) or its endpoint matches
    ``SENSITIVE_ENDPOINTS`` (default ``booking*, refund*, payment*, account*``). If, for such a request,
    a check that needs Redis could not run (rate limits, bot profiling, conversation memory,
    enumeration) or the session record could not be read, the request is restricted (or blocked:
    ``DEGRADED_SENSITIVE_ACTION``), reason ``state_unavailable`` — the gateway does not let an action
    on someone's data through while it cannot see the chat's history, limits or verification.
    Ordinary chat carries on as before. (The ML service has its own failure mode, ``ML_FAILURE_MODE``.)
    ``None`` when the request is not sensitive or nothing was degraded."""
    patterns = [p.strip() for p in settings.sensitive_endpoints.split(",") if p.strip()]
    mode = settings.degraded_sensitive_action

    async def failure_policy_check(ctx: RequestContext) -> CheckResult | None:
        sensitive_ep = bool(ctx.policy and ctx.policy.sensitive) or any(
            fnmatch.fnmatchcase(ctx.endpoint, p) for p in patterns
        )
        if not sensitive_ep:
            return None
        degraded = [
            r.name
            for r in ctx.results
            if r.name in STATEFUL_CHECKS and (r.detail.get("unavailable") or r.detail.get("degraded"))
        ]
        if not ctx.session_store_ok:
            degraded.append("session_store")
        if not degraded:
            return None
        detail = {"degraded": degraded, "endpoint": ctx.endpoint, "mode": mode}
        if mode == "allow":
            return CheckResult(name="failure_policy", passed=True, detail=detail)
        return CheckResult(
            name="failure_policy",
            passed=False,
            score=0.5,
            action=Action.BLOCK if mode == "block" else Action.RESTRICT,
            reason="state_unavailable",
            detail=detail,
        )

    return failure_policy_check


SEVERITY_SCORE = {"high": 0.95, "medium": 0.6, "low": 0.3}


def make_rules_check(settings: Settings) -> Check:
    """Fast local detection: attack phrases, role tokens, encoded / hidden payloads, markup, links.

    high   → BLOCK. Deterministic findings (template tokens, hidden text, an attack inside an encoded
             layer) strike on their own. Phrase findings are *probabilistic*: the block is provisional
             and the ML check confirms the strike or softens the block (RULES_CORROBORATE_WITH_ML).
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
                {
                    "id": f.id,
                    "family": f.family,
                    "severity": f.severity,
                    "via": f.via,
                    "field": f.field,
                    "evidence": f.evidence,
                }
                for f in analysis.findings
            ],
        }
        if severity is None:
            return CheckResult(name="rules", passed=True, detail=detail)
        worst = analysis.of(severity)[0]
        score = SEVERITY_SCORE[severity]
        if severity == "high":
            evidence = analysis.evidence("high")
            provisional = (
                evidence == "probabilistic" and settings.rules_corroborate_with_ml and settings.ml_enabled
            )
            if provisional:
                detail["corroboration"] = "pending"
            return CheckResult(
                name="rules",
                passed=False,
                score=score,
                action=Action.BLOCK,
                reason=worst.family,
                detail=detail,
                strike=True,
                evidence=evidence,
                provisional=provisional,
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


def corroborate_rules(
    ctx: RequestContext, ml_score: float | None, restrict_at: float, settings: Settings
) -> None:
    """Settle a provisional rules block with the ML tier's opinion (in place, on the rules result).

    ML agrees (score ≥ restrict threshold) → the block stands and strikes. ML finds the text clearly
    benign (< RULES_ML_CLEAR_BELOW) → softened to a restrict, no strike: the phrase was a false alarm
    like "what are your rules for pets". In between, or ML unavailable → the block stands, no strike."""
    rules = next((r for r in ctx.results if r.name == "rules" and r.provisional), None)
    if rules is None:
        return
    rules.provisional = False
    if ml_score is None:
        rules.strike = False
        rules.detail["corroboration"] = "ml_unavailable"
    elif ml_score >= restrict_at:
        rules.detail["corroboration"] = "confirmed"
    elif ml_score < settings.rules_ml_clear_below:
        rules.action, rules.strike, rules.score = Action.RESTRICT, False, SEVERITY_SCORE["medium"]
        rules.detail["corroboration"] = "softened"
    else:
        rules.strike = False
        rules.detail["corroboration"] = "unconfirmed"


REDACTION_TOKEN = re.compile(r"\[REDACTED:([a-z_]+)\]")


def for_model(text: str) -> str:
    """Redacted text as the model should see it: "[REDACTED:card]" becomes the plain word "card". The
    model never saw bracketed tokens; a bare noun reads like the customer wrote "my card"."""
    return REDACTION_TOKEN.sub(lambda m: m.group(1).replace("_", " "), text)


SEGMENT_MIN_CHARS = 400  # texts at least this long are also scored paragraph by paragraph
SEGMENT_MAX = 4  # at most this many segments per field (each costs ML time)
_PARAGRAPH = re.compile(r"\n\s*\n|\n(?=\S)|(?<=[.!?])\s+(?=[A-Z\"'\[(])")


def segments(text: str) -> list[str]:
    """Paragraphs (then sentences) of a long text, longest first, so an instruction buried in a pasted
    email is scored on its own instead of being diluted by the surrounding prose. Empty for short text."""
    if len(text) < SEGMENT_MIN_CHARS:
        return []
    parts = [p.strip() for p in _PARAGRAPH.split(text) if p and len(p.strip()) >= 20]
    if len(parts) <= 1:
        return []
    parts.sort(key=len, reverse=True)
    return parts[:SEGMENT_MAX]


def make_ml_check(client: MLClient, settings: Settings) -> Check:
    """Injection classifier in the ML service. Never the *only* thing standing in front of a
    sensitive action: when it can't answer, ML_FAILURE_MODE decides (default restrict).

    For a tracked conversation the same call also scores the conversation window and returns
    embeddings; only this request's own fields decide this check."""

    async def ml_check(ctx: RequestContext) -> CheckResult:
        # The redacted text when the sensitive check redacted anything: card numbers and credentials
        # never leave the gateway, and "[REDACTED:card]" tells the model nothing it needs.
        texts_in = (
            [for_model(f) for f in ctx.redacted_fields]
            if ctx.redacted_fields is not None
            else (ctx.text_fields or [ctx.text])
        )
        fields = [f for f in texts_in if len(f.strip()) >= settings.ml_min_chars]
        # Long fields are also scored piece by piece: an injection pasted inside an email body must
        # not hide behind three paragraphs of ordinary text. Pieces follow the fields and the window.
        pieces: list[tuple[int, str]] = [(i, seg) for i, f in enumerate(fields) for seg in segments(f)]
        # The joined window rides along only when its ML score may act (CONV_WINDOW_ML_ACTION).
        use_window = ctx.window is not None and settings.conv_window_ml_action != "off"
        window = ctx.window.text if use_window and ctx.window is not None else None
        texts = fields + ([window] if window else []) + [seg for _, seg in pieces]
        if not texts:
            return CheckResult(name="ml", passed=True, detail={"skipped": "too_short"})
        try:
            result = await client.score(
                texts, settings.max_prompt_chars, vectors=ctx.conversation is not None
            )
        except MLUnavailable as exc:
            detail: dict[str, Any] = {"unavailable": exc.reason, "failure_mode": settings.ml_failure_mode}
            corroborate_rules(ctx, None, settings.ml_restrict_at, settings)
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
        piece_scores = result.per_text[len(fields) + (1 if window else 0) :] if result.per_text else []
        buried = max((t.score for t in piece_scores), default=0.0)
        if buried > score:  # a piece scored higher than its whole field: use it for the decision
            score = round(buried, 4)
            top = max(piece_scores, key=lambda t: t.score)
        block_at, restrict_at, source = resolve_ml_thresholds(ctx, settings, result.thresholds)
        scored: dict[str, Any] = {
            "score": score,
            "segments": len(pieces),
            "buried_score": round(buried, 4) if pieces else None,
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
        corroborate_rules(ctx, score, restrict_at, settings)
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


def make_off_topic_check(settings: Settings) -> Check:
    """The assistant used for something that is not customer support (homework, code, essays).

    Reads the ML tier's ``topic_similarity`` (cosine to airline-support examples) against the model's
    calibrated ``off_topic`` threshold. Not an attack: no strike. OFF_TOPIC_ACTION decides whether it
    is only recorded (``flag``) or the request is restricted so CMP can send a scripted redirect.
    ``None`` when the model sent no topic signal or the request was already refused."""

    async def off_topic_check(ctx: RequestContext) -> CheckResult | None:
        if settings.off_topic_action == "off" or ctx.ml is None or not ctx.ml.per_text:
            return None
        if any(r.action == Action.BLOCK for r in ctx.results):
            return None
        cut = (ctx.ml.thresholds or {}).get("off_topic")
        own = ctx.ml.per_text[: ctx.ml_fields] if ctx.ml_fields else ctx.ml.per_text
        sims = [
            float(t.components["topic_similarity"])
            for t in own
            if t.components and t.components.get("topic_similarity") is not None
        ]
        if cut is None or not sims:
            return None
        sim = min(sims)
        detail = {"topic_similarity": round(sim, 4), "threshold": cut}
        if sim >= cut:
            return CheckResult(name="off_topic", passed=True, detail=detail)
        if settings.off_topic_action == "restrict":
            return CheckResult(
                name="off_topic",
                passed=False,
                score=0.4,
                action=Action.RESTRICT,
                reason="off_topic",
                detail=detail,
            )
        return CheckResult(name="off_topic", passed=False, score=0.2, reason="off_topic", detail=detail)

    return off_topic_check


def make_fusion_check(settings: Settings) -> Check:
    """Weak signals that agree. No single check acted, but two or more low/medium rule findings from
    different families together with an ML score just under the restrict threshold → restrict."""

    async def fusion_check(ctx: RequestContext) -> CheckResult | None:
        if not settings.fusion_enabled:
            return None
        by_name = {r.name: r for r in ctx.results}
        rules, ml = by_name.get("rules"), by_name.get("ml")
        if rules is None or ml is None or ml.action is not None or rules.action is not None:
            return None
        families = {f["family"] for f in rules.detail.get("findings", [])}
        if len(families) < 2:
            return None
        _block_at, restrict_at = ml_thresholds(ctx, settings)
        if ml.score < restrict_at - settings.fusion_ml_margin:
            return None
        return CheckResult(
            name="fusion",
            passed=False,
            score=round(max(ml.score, rules.score), 4),
            action=Action.RESTRICT,
            reason="weak_signals_agree",
            detail={"families": sorted(families), "ml_score": ml.score, "restrict_at": restrict_at},
        )

    return fusion_check


def make_untrusted_content_check(settings: Settings) -> Check:
    """Indirect injection in text the AI fetched (tool results, retrieved documents) rather than the
    customer wrote. The attack is real, the customer is not its author: the request is restricted
    (UNTRUSTED_CONTENT_ACTION) and nobody is struck. ``None`` when there is no such text."""
    allowed = tuple(d.strip().lower() for d in settings.allowed_link_domains.split(",") if d.strip())

    async def untrusted_content_check(ctx: RequestContext) -> CheckResult | None:
        if settings.untrusted_content_action == "off" or not ctx.untrusted_fields:
            return None
        analysis = analyze(
            ctx.untrusted_fields, allowed_link_domains=allowed, max_links=settings.max_links, untrusted=True
        )
        detail: dict[str, Any] = {
            "fields": len(ctx.untrusted_fields),
            "findings": [
                {"id": f.id, "family": f.family, "severity": f.severity, "field": f.field}
                for f in analysis.findings
            ],
        }
        if analysis.severity not in ("high", "medium"):
            return CheckResult(name="untrusted_content", passed=True, detail=detail)
        worst = analysis.of(analysis.severity)[0]
        mode = settings.untrusted_content_action
        if mode == "flag":
            return CheckResult(
                name="untrusted_content", passed=False, score=0.5, reason="indirect_injection", detail=detail
            )
        action = Action.BLOCK if mode == "block" and analysis.severity == "high" else Action.RESTRICT
        return CheckResult(
            name="untrusted_content",
            passed=False,
            score=SEVERITY_SCORE[analysis.severity],
            action=action,
            reason="indirect_injection",
            detail={**detail, "worst": worst.id},
        )

    return untrusted_content_check
