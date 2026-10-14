"""Admin API: what the gateway knows about one CMP session (contact).

    GET    /admin/sessions/{session_id}   attributes, verification, conversation memory, bans, strikes
    DELETE /admin/sessions/{session_id}   reset: forget the conversation memory (unlocks a locked
                                          session) and the session's reputation and strike counters

Never message text, identifier values or embeddings: per-turn scores, actions, rule ids and counts.
For the full timeline of a session, see ``GET /admin/events?session_id=…`` or the dashboard.
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Path, Request

from app.bans.index import Subject
from app.conversation.service import ConversationService
from app.entities import Entity
from app.reputation.service import ReputationService
from app.security import require_admin
from app.session.service import SessionService

log = logging.getLogger("gateway.admin")
router = APIRouter(prefix="/admin", tags=["admin: sessions"], dependencies=[Depends(require_admin)])

SessionIdPath = Path(..., min_length=1, max_length=200)


def conversations(request: Request) -> ConversationService:
    c: ConversationService = request.app.state.conversations
    return c


def sessions(request: Request) -> SessionService:
    s: SessionService = request.app.state.sessions
    return s


@router.get("/sessions/{session_id}")
async def get_session(
    request: Request,
    session_id: str = SessionIdPath,
    conv: ConversationService = Depends(conversations),
    sess: SessionService = Depends(sessions),
) -> dict[str, Any]:
    record = await sess.get(session_id)
    state = await conv.get(session_id)
    hit = request.app.state.bans.match(Subject(session_id=session_id))
    strikes = await request.app.state.repo.list_strikes("session", session_id)
    if record is None and state is None and hit is None and not strikes:
        raise HTTPException(status_code=404, detail={"error": "not_found"})
    settings = conv.settings
    out: dict[str, Any] = {
        "session_id": session_id,
        "session": record.public() if record else None,
        "ban": ({"id": str(hit.id), "expires_at": hit.expires_at, "source": hit.source} if hit else None),
        "strikes": strikes,
        "conversation": None,
    }
    if state is not None:
        out["conversation"] = {
            "turns_seen": state.n,
            "replies_seen": state.replies,
            "blocks": state.blocks,
            "locked": state.blocks >= settings.conv_max_blocks,
            "accumulated_risk": state.acc,
            "thresholds": {"restrict": settings.conv_restrict_at, "block": settings.conv_block_at},
            "setup_turn": state.setup_turn,
            "turns": [
                {
                    "n": t.n,
                    "action": t.action,
                    "score": t.score,
                    "attack_lean": t.attack_lean,
                    "rule_ids": t.rule_ids,
                    "hash": t.hash,
                }
                for t in state.turns
            ],
            "assistant_turns": [
                {"n": a.n, "action": a.action, "chars": a.chars, "reasons": a.reasons, "hash": a.hash}
                for a in state.assistant
            ],
            "blocked_turns": [b.n for b in state.blocked],
            # The gateway's own redacted copy of the exchange (customer turns and checked AI replies).
            "transcript": [
                {
                    "n": e.n,
                    "role": e.role,
                    "ts": e.ts,
                    "action": e.action,
                    "reasons": e.reasons,
                    "text": e.text,
                }
                for e in state.transcript
            ],
        }
    return out


@router.delete("/sessions/{session_id}")
async def reset_session(
    request: Request,
    session_id: str = SessionIdPath,
    conv: ConversationService = Depends(conversations),
) -> dict[str, Any]:
    """A ban on the session is not lifted here: use ``DELETE /admin/bans/{id}``."""
    deleted = await conv.delete(session_id)
    reputation: ReputationService = request.app.state.reputation
    await reputation.clear(Entity("session", session_id))
    if not deleted:
        raise HTTPException(status_code=404, detail={"error": "not_found"})
    log.info("session reset")
    return {"deleted": True}
