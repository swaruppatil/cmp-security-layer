"""CMP session lifecycle (see ``app/session/service.py``).

    POST /v1/sessions/{session_id}/start      start_chat: channel, customer, IP, device, user agent
    POST /v1/sessions/{session_id}/identity   IDV result: verified + the customer's own identifiers
    POST /v1/sessions/{session_id}/end        the contact is over: forget the session and its memory

All three are optional — ``/v1/inspect`` works with only a session id — but each makes the checks
better: ``start`` gives every message of the session its identities, ``identity`` lets AI replies
contain the verified customer's own data (and nobody else's), ``end`` frees memory at once.
Need the ``inspect`` scope (the enricher makes these calls).
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Path, Request

from app.auth.models import Principal
from app.pipeline.models import SessionIdentity, SessionStart
from app.security import require_scope
from app.session.service import SessionService

log = logging.getLogger("gateway.sessions")
router = APIRouter(prefix="/v1/sessions", tags=["sessions"])

SessionIdPath = Path(..., min_length=1, max_length=200, pattern=r"^[A-Za-z0-9._:@-]+$")
_UNAVAILABLE = HTTPException(status_code=503, detail={"error": "session_store_unavailable"})


def sessions(request: Request) -> SessionService:
    s: SessionService = request.app.state.sessions
    return s


@router.post("/{session_id}/start")
async def start_session(
    body: SessionStart,
    session_id: str = SessionIdPath,
    svc: SessionService = Depends(sessions),
    _: Principal = Depends(require_scope("inspect")),
) -> dict[str, Any]:
    try:
        rec = await svc.start(
            session_id,
            channel=body.channel,
            ip=body.ip,
            device_id=body.device_id,
            user_agent=body.user_agent,
            customer_id=body.customer_id,
        )
    except Exception:  # noqa: BLE001 - CMP carries on: inspect still works from request fields
        log.warning("session start failed")
        raise _UNAVAILABLE from None
    return rec.public()


@router.post("/{session_id}/identity")
async def session_identity(
    body: SessionIdentity,
    session_id: str = SessionIdPath,
    svc: SessionService = Depends(sessions),
    _: Principal = Depends(require_scope("inspect")),
) -> dict[str, Any]:
    try:
        rec = await svc.verify(
            session_id,
            verified=body.verified,
            customer_id=body.customer_id,
            identifiers={k: list(v) for k, v in body.identifiers.items()},
        )
    except Exception:  # noqa: BLE001
        log.warning("session identity update failed")
        raise _UNAVAILABLE from None
    log.info("session identity", extra={"verified": body.verified})
    return rec.public()


@router.post("/{session_id}/end")
async def end_session(
    session_id: str = SessionIdPath,
    svc: SessionService = Depends(sessions),
    _: Principal = Depends(require_scope("inspect")),
) -> dict[str, Any]:
    try:
        existed = await svc.end(session_id)
    except Exception:  # noqa: BLE001
        log.warning("session end failed")
        raise _UNAVAILABLE from None
    return {"session_id": session_id, "ended": True, "existed": existed}
