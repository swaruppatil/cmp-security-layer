"""Admin API: caller API keys.

    POST   /admin/api-keys          create a key for a caller (CMP's enricher, its processor, a test tool)
    GET    /admin/api-keys          list keys (never the key itself)
    DELETE /admin/api-keys/{id}     revoke: every gateway instance stops accepting it within a second

There are no tenants: the gateway protects one product (CMP). Keys differ by name and scopes —
``inspect`` (``/v1/inspect`` and the session calls), ``outbound`` (``/v1/inspect/outbound``) and
``proxy`` (``/v1/ai/*``). Protected by ``ADMIN_API_KEY`` (header ``X-Admin-Key`` or
``Authorization: Bearer``).
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any
from uuid import UUID

import asyncpg
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field, field_validator

from app.auth.keys import generate_key
from app.auth.service import INVALIDATION_CHANNEL
from app.db.repository import VALID_SCOPES, Repository
from app.security import require_admin

log = logging.getLogger("gateway.admin")
router = APIRouter(prefix="/admin", tags=["admin"], dependencies=[Depends(require_admin)])


def repo(request: Request) -> Repository:
    r: Repository = request.app.state.repo
    return r


class ApiKeyIn(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    scopes: list[str] = Field(default_factory=lambda: ["inspect", "outbound"])
    expires_at: datetime | None = None

    @field_validator("scopes")
    @classmethod
    def known_scopes(cls, v: list[str]) -> list[str]:
        unknown = set(v) - VALID_SCOPES
        if unknown:
            raise ValueError(f"unknown scopes: {sorted(unknown)}; allowed: {sorted(VALID_SCOPES)}")
        if not v:
            raise ValueError("at least one scope is required")
        return sorted(set(v))


async def _invalidate(request: Request, key_hashes: list[str]) -> None:
    """Drop keys from this instance's cache now, and tell every other instance via Redis."""
    auth = request.app.state.auth
    for h in key_hashes:
        auth.invalidate(h)
    redis = request.app.state.deps.redis
    for h in key_hashes:
        try:
            await redis.publish(INVALIDATION_CHANNEL, h)
        except Exception:  # noqa: BLE001 - cache TTL is the fallback
            log.warning("could not publish auth invalidation; other instances rely on cache TTL")


@router.post("/api-keys", status_code=status.HTTP_201_CREATED)
async def create_api_key(body: ApiKeyIn, r: Repository = Depends(repo)) -> dict[str, Any]:
    new = generate_key()
    try:
        record = await r.create_api_key(body.name, new.prefix, new.key_hash, body.scopes, body.expires_at)
    except asyncpg.UniqueViolationError:  # a prefix collision: 1 in 10^12, just ask again
        raise HTTPException(status_code=409, detail={"error": "retry"}) from None
    log.info("api key created", extra={"key_name": body.name, "prefix": new.prefix})
    # The plaintext key is returned exactly once and never stored.
    return {**record, "api_key": new.plaintext}


@router.get("/api-keys")
async def list_api_keys(r: Repository = Depends(repo)) -> list[dict[str, Any]]:
    return await r.list_api_keys()


@router.delete("/api-keys/{key_id}")
async def revoke_api_key(key_id: UUID, request: Request, r: Repository = Depends(repo)) -> dict[str, Any]:
    key_hash = await r.revoke_api_key(key_id)
    if key_hash is None:
        raise HTTPException(status_code=404, detail={"error": "api_key_not_found"})
    await _invalidate(request, [key_hash])
    log.info("api key revoked", extra={"key_id": str(key_id)})
    return {"id": key_id, "status": "revoked"}
