"""Inspect mode: CMP sends a message, the gateway returns a decision, CMP enforces it.

This is how CMP uses the gateway: its chat messages flow through Amazon Connect and Kafka, not HTTP,
so the enricher asks for a decision before publishing a customer message to the AI agent, and the
processor asks before delivering the AI's reply. Both calls carry CMP's session id (the contact id);
attributes given once to ``POST /v1/sessions/{id}/start`` are inherited.

Every decision carries a ``cmp_action`` (``app/cmp.py``) so CMP needs no knowledge of check names.
The response also includes reason codes and per-check results for CMP's logs; CMP must never show
those to the customer.

Idempotency: with a ``message_id``, a repeat of the same (session, message) within
``IDEMPOTENCY_TTL_SECONDS`` returns the first decision (``replayed: true``) without running the
checks again or charging the customer a second time.
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, BackgroundTasks, Depends, Request

from app.auth.models import Principal
from app.cmp import inbound_action, outbound_action
from app.pipeline.context import RequestContext
from app.pipeline.decide import decide
from app.pipeline.models import Action, Decision, InspectRequest, OutboundDecision, OutboundRequest
from app.security import request_id, require_scope
from app.session.service import ANONYMOUS, SessionRecord, SessionService

log = logging.getLogger("gateway.decision")
router = APIRouter(prefix="/v1", tags=["inspect"])


async def _session(sessions: SessionService, session_id: str) -> tuple[SessionRecord | None, bool]:
    """(the session record or None, whether the read worked)."""
    try:
        return await sessions.get(session_id), True
    except Exception:  # noqa: BLE001 - Redis down: decide from what the request carries
        log.warning("session store unavailable")
        return None, False


async def _replay(sessions: SessionService, session_id: str, key: str | None) -> dict[str, Any] | None:
    if not key:
        return None
    try:
        return await sessions.cached_decision(session_id, key)
    except Exception:  # noqa: BLE001
        log.warning("idempotency cache unavailable")
        return None


async def _remember_session(
    sessions: SessionService,
    ctx: RequestContext,
    decision: Decision,
    rec: SessionRecord | None,
    loaded: bool,
) -> None:
    """Before the response: the session learns this message's attributes and typed identifiers, so the
    AI's reply — checked moments later — already sees them. One Redis write (the record was read at the
    start of the request); only a TTL refresh when nothing changed."""
    if not ctx.session_id:
        return
    # Identifiers typed in a refused message are not the customer's to see repeated back.
    typed = ctx.typed_identifiers if decision.action in (Action.ALLOW, Action.RESTRICT) else {}
    attrs = {
        "channel": ctx.channel,
        "ip": ctx.ip,
        "device_id": ctx.device_id,
        "user_agent": ctx.user_agent,
        "user": ctx.user_id,
    }
    try:
        if loaded:
            await sessions.remember(ctx.session_id, attrs, typed, current=rec)
        else:  # the first read failed: read again rather than overwrite what may be there
            await sessions.remember(ctx.session_id, attrs, typed)
    except Exception:  # noqa: BLE001
        log.warning("session update failed", extra={"request_id": decision.request_id})


async def _remember_decision(sessions: SessionService, ctx: RequestContext, decision: Decision) -> None:
    """Idempotency record, written before the response (one Redis SET): a CMP retry that arrives a
    moment later gets this decision back. Two copies arriving at the very same instant can both run."""
    if not (ctx.session_id and ctx.message_id):
        return
    try:
        await sessions.cache_decision(
            ctx.session_id, f"{ctx.direction}:{ctx.message_id}", decision.model_dump(mode="json")
        )
    except Exception:  # noqa: BLE001
        log.warning("idempotency cache unavailable", extra={"request_id": decision.request_id})


def _log(decision: Decision, mode: str, principal: Principal, ctx: RequestContext) -> None:
    log.info(
        "decision",
        extra={
            "request_id": decision.request_id,
            "mode": mode,
            "caller": principal.name,
            "session_id": ctx.session_id,
            "action": decision.action.value,
            "cmp_action": decision.cmp_action,
            "risk": decision.risk,
            "reasons": decision.reasons,
            "latency_ms": decision.latency_ms,
        },
    )


@router.post("/inspect", response_model=Decision)
async def inspect(
    body: InspectRequest,
    request: Request,
    background: BackgroundTasks,
    principal: Principal = Depends(require_scope("inspect")),
) -> Decision:
    sessions: SessionService = request.app.state.sessions
    settings = request.app.state.settings
    cached = await _replay(
        sessions, body.session_id, f"inbound:{body.message_id}" if body.message_id else None
    )
    if cached is not None:
        return Decision(**{**cached, "replayed": True})

    rec, loaded = await _session(sessions, body.session_id)
    ctx = RequestContext(
        request_id=request_id(request),
        principal=principal,
        text=body.message,
        text_fields=[body.message],
        endpoint=body.endpoint,
        ip=body.ip or (rec.ip if rec else None),
        user_id=sessions.customer(body.customer_id) or (rec.user if rec else None),
        session_id=body.session_id,
        device_id=body.device_id or (rec.device_id if rec else None),
        channel=body.channel or (rec.channel if rec else None),
        metadata=body.metadata,
        user_agent=body.user_agent or (rec.user_agent if rec else None),
        message_id=body.message_id,
        session_state=rec.state if rec else ANONYMOUS,
        mode="inspect",
    )
    decision = await decide(request.app.state, request.app.state.pipeline, ctx)
    decision.redactions = ctx.redactions
    if ctx.redacted_fields is not None:
        decision.redacted_message = ctx.redacted_fields[0]
    prior_blocks = ctx.conversation.blocks if ctx.conversation is not None else 0
    decision.cmp_action = inbound_action(
        decision, prior_blocks, settings.cmp_handoff_after_blocks, settings.cmp_short_ban_seconds
    )
    decision.session_state = ctx.session_state
    await _remember_session(sessions, ctx, decision, rec, loaded)
    await _remember_decision(sessions, ctx, decision)
    # Reputation, strikes, auto-bans, audit, conversation memory: after the response is sent.
    background.add_task(request.app.state.after_decision, ctx, decision)
    _log(decision, "inspect", principal, ctx)
    return decision


@router.post("/inspect/outbound", response_model=OutboundDecision)
async def inspect_outbound(
    body: OutboundRequest,
    request: Request,
    background: BackgroundTasks,
    principal: Principal = Depends(require_scope("outbound")),
) -> OutboundDecision:
    """Check an AI reply before delivering it. Deliver ``deliver`` (never the original ``reply``);
    when ``cmp_action`` is ``send_fallback`` (``deliver`` is ``None``), send a safe fallback instead."""
    sessions: SessionService = request.app.state.sessions
    cached = await _replay(
        sessions, body.session_id, f"outbound:{body.message_id}" if body.message_id else None
    )
    if cached is not None:
        return OutboundDecision(**{**cached, "replayed": True})

    rec, _loaded = await _session(sessions, body.session_id)
    ctx = RequestContext(
        request_id=request_id(request),
        principal=principal,
        text=body.reply,
        text_fields=[body.reply],
        endpoint=body.endpoint,
        ip=body.ip or (rec.ip if rec else None),
        user_id=sessions.customer(body.customer_id) or (rec.user if rec else None),
        session_id=body.session_id,
        device_id=body.device_id or (rec.device_id if rec else None),
        channel=body.channel or (rec.channel if rec else None),
        metadata=body.metadata,
        message_id=body.message_id,
        session_state=rec.state if rec else ANONYMOUS,
        direction="outbound",
        mode="outbound",
        allowed_identifiers=(
            {k: list(v) for k, v in body.allowed_identifiers.items()}
            if body.allowed_identifiers is not None
            else None
        ),
        allowed_identifier_hashes=rec.allowed_hashes() if rec is not None else None,
    )
    ctx.deliver = body.reply
    base = await decide(request.app.state, request.app.state.outbound_pipeline, ctx)
    deliver = None if base.action == Action.BLOCK else ctx.deliver
    decision = OutboundDecision(**base.model_dump(), deliver=deliver)
    decision.redactions = ctx.redactions
    decision.cmp_action = outbound_action(deliver)
    decision.session_state = ctx.session_state
    await _remember_decision(sessions, ctx, decision)
    background.add_task(request.app.state.after_decision, ctx, decision)
    _log(decision, "outbound", principal, ctx)
    return decision
