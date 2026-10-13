"""Admin API: canary tokens (Stage 7).

    POST   /admin/canaries               create; the token is returned once
    GET    /admin/canaries               list (never the token)
    DELETE /admin/canaries/{canary_id}   revoke

Put the token in the AI agent's system prompt. If it ever appears in a reply, the outbound check
blocks the reply and records a deterministic strike against the session and customer that caused it.
"""

from __future__ import annotations

import logging
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field

from app.outbound.canary import CanaryService
from app.security import require_admin

log = logging.getLogger("gateway.admin")
router = APIRouter(prefix="/admin", tags=["admin: canaries"], dependencies=[Depends(require_admin)])


class CanaryIn(BaseModel):
    label: str = Field("system-prompt", min_length=1, max_length=100)


def canaries(request: Request) -> CanaryService:
    c: CanaryService = request.app.state.canaries
    return c


@router.post("/canaries", status_code=status.HTTP_201_CREATED)
async def create_canary(body: CanaryIn, svc: CanaryService = Depends(canaries)) -> dict[str, Any]:
    row = await svc.create(body.label)
    log.info("canary created", extra={"canary_id": str(row["id"])})
    return row


@router.get("/canaries")
async def list_canaries(request: Request) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = await request.app.state.repo.list_canaries()
    return rows


@router.delete("/canaries/{canary_id}")
async def revoke_canary(
    canary_id: UUID, request: Request, svc: CanaryService = Depends(canaries)
) -> dict[str, Any]:
    row: dict[str, Any] | None = await request.app.state.repo.revoke_canary(canary_id)
    if row is None:
        raise HTTPException(status_code=404, detail={"error": "not_found_or_revoked"})
    svc.invalidate()
    log.info("canary revoked", extra={"canary_id": str(canary_id)})
    return row
