"""Admin API: protected prompts (prompt-leak detection by content).

    POST   /admin/protected-prompts               register a system prompt (only shingle hashes are kept)
    GET    /admin/protected-prompts               list (label, word count, dates — never the prompt)
    DELETE /admin/protected-prompts/{prompt_id}   revoke

Register the AI agent's system prompt (and each translation of it). If a reply shares
``PROMPT_LEAK_MIN_SHINGLES`` or more 8-word runs with a registered prompt, the outbound check blocks
the reply and records a deterministic strike. Complements canary tokens (``/admin/canaries``), which a
coaxed model may leave out of a paraphrased leak.
"""

from __future__ import annotations

import logging
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field

from app.outbound.prompt_leak import PromptLeakService
from app.security import require_admin

log = logging.getLogger("gateway.admin")
router = APIRouter(prefix="/admin", tags=["admin: canaries"], dependencies=[Depends(require_admin)])


class ProtectedPromptIn(BaseModel):
    label: str = Field("system-prompt", min_length=1, max_length=100)
    text: str = Field(..., min_length=20, max_length=50_000, description="The prompt; never stored")


def prompts(request: Request) -> PromptLeakService:
    p: PromptLeakService = request.app.state.prompt_leak
    return p


@router.post("/protected-prompts", status_code=status.HTTP_201_CREATED)
async def register_prompt(
    body: ProtectedPromptIn, svc: PromptLeakService = Depends(prompts)
) -> dict[str, Any]:
    row = await svc.register(body.label, body.text)
    log.info("protected prompt registered", extra={"prompt_id": str(row["id"])})
    return row


@router.get("/protected-prompts")
async def list_prompts(request: Request) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = await request.app.state.repo.list_protected_prompts()
    return rows


@router.delete("/protected-prompts/{prompt_id}")
async def revoke_prompt(
    prompt_id: UUID, request: Request, svc: PromptLeakService = Depends(prompts)
) -> dict[str, Any]:
    row: dict[str, Any] | None = await request.app.state.repo.revoke_protected_prompt(prompt_id)
    if row is None:
        raise HTTPException(status_code=404, detail={"error": "not_found_or_revoked"})
    svc.invalidate()
    log.info("protected prompt revoked", extra={"prompt_id": str(prompt_id)})
    return row
