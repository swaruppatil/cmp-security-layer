"""Admin API: bans, blacklists, reputation.

Entity types: ``session`` (a CMP contact id), ``user`` (a customer), ``device``, ``ip``, ``cidr``,
``api_key``. A ``user`` value may be CMP's raw customer id or the ``cu_…`` hash the dashboard shows:
raw ids are hashed with ``IDENTITY_HASH_KEY`` on the way in, so the gateway never stores them.
"""

from __future__ import annotations

import logging
from typing import Any, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, Field, model_validator

from app.bans.index import Subject
from app.bans.service import BanService, validate_cidr_not_too_broad
from app.entities import END_USER_TYPES, Entity, EntityType, normalize
from app.reputation.service import ReputationService
from app.security import require_admin
from app.session.identity import customer_key

log = logging.getLogger("gateway.admin")
router = APIRouter(prefix="/admin", tags=["admin: bans"], dependencies=[Depends(require_admin)])


def bans(request: Request) -> BanService:
    b: BanService = request.app.state.bans
    return b


def reputation(request: Request) -> ReputationService:
    r: ReputationService = request.app.state.reputation
    return r


def _clean(entity_type: str, value: str) -> str:
    cleaned = normalize(entity_type, value)  # type: ignore[arg-type]
    validate_cidr_not_too_broad(cleaned, entity_type)
    return cleaned


def _identity(request: Request, entity_type: str, value: str) -> str:
    """User values are stored hashed: hash a raw customer id (a ``cu_…`` value is kept as is)."""
    if entity_type != "user":
        return value
    key = request.app.state.settings.identity_hash_key.get_secret_value()
    return customer_key(key, value) or value


class BanIn(BaseModel):
    entity_type: EntityType
    value: str = Field(..., min_length=1, max_length=200)
    reason: str = Field(..., min_length=1, max_length=500)
    duration_seconds: int | None = Field(None, gt=0, le=10 * 365 * 24 * 3600)
    permanent: bool = False

    @model_validator(mode="after")
    def check(self) -> BanIn:
        if self.permanent == (self.duration_seconds is not None):
            raise ValueError("give exactly one of duration_seconds or permanent=true")
        self.value = _clean(self.entity_type, self.value)
        return self


class BlacklistIn(BaseModel):
    entity_type: Literal["ip", "cidr", "user", "device", "session", "api_key"]
    values: list[str] = Field(..., min_length=1, max_length=10_000)
    reason: str = Field(..., min_length=1, max_length=500)


@router.post("/bans", status_code=status.HTTP_201_CREATED)
async def create_ban(body: BanIn, request: Request, b: BanService = Depends(bans)) -> dict[str, Any]:
    return await b.ban(
        entity_type=body.entity_type,
        value=_identity(request, body.entity_type, body.value),
        reason=body.reason,
        source="manual",
        created_by="admin",
        duration_seconds=body.duration_seconds,
        permanent=body.permanent,
    )


@router.post("/blacklists", status_code=status.HTTP_201_CREATED)
async def import_blacklist(
    body: BlacklistIn, request: Request, b: BanService = Depends(bans)
) -> dict[str, Any]:
    """Bulk-add permanent bans (e.g. known-bad IP ranges). Invalid values are reported, not inserted."""
    rows: list[dict[str, Any]] = []
    invalid: list[dict[str, str]] = []
    seen: set[str] = set()
    for raw in body.values:
        try:
            value = _identity(request, body.entity_type, _clean(body.entity_type, raw))
        except ValueError as exc:
            invalid.append({"value": raw[:200], "error": str(exc)})
            continue
        if value in seen:
            continue
        seen.add(value)
        rows.append(
            {
                "entity_type": body.entity_type,
                "value": value,
                "reason": body.reason,
                "source": "blacklist",
                "created_by": "admin",
            }
        )
    inserted = await request.app.state.repo.create_bans_bulk(rows)
    if inserted:
        await b.notify_changed()
    return {"inserted": inserted, "invalid": invalid}


@router.get("/bans")
async def list_bans(
    request: Request,
    active_only: bool = True,
    entity_type: EntityType | None = None,
    value: str | None = None,
    limit: int = Query(100, gt=0, le=1000),
) -> list[dict[str, Any]]:
    if value is not None and entity_type is not None:
        try:
            value = _identity(request, entity_type, normalize(entity_type, value))
        except ValueError as exc:
            raise HTTPException(status_code=422, detail={"error": str(exc)}) from None
    rows: list[dict[str, Any]] = await request.app.state.repo.list_bans(
        active_only=active_only, entity_type=entity_type, value=value, limit=limit
    )
    return rows


@router.delete("/bans/{ban_id}")
async def unban(
    ban_id: UUID,
    clear_history: bool = False,
    b: BanService = Depends(bans),
    r: ReputationService = Depends(reputation),
) -> dict[str, Any]:
    """Lift a ban. ``clear_history=true`` also forgets the entity's reputation and strikes."""
    row = await b.unban(ban_id, revoked_by="admin")
    if row is None:
        raise HTTPException(status_code=404, detail={"error": "ban_not_found"})
    if clear_history and row["entity_type"] in END_USER_TYPES:
        await r.clear(Entity(row["entity_type"], row["value"]))
    log.info("ban revoked", extra={"ban_id": str(ban_id), "clear_history": clear_history})
    return row


@router.get("/reputation")
async def get_reputation(
    request: Request,
    entity_type: Literal["ip", "user", "device", "session"],
    value: str,
    r: ReputationService = Depends(reputation),
    b: BanService = Depends(bans),
) -> dict[str, Any]:
    """Score, event counts, strikes and the active ban (if any) for one end-user identity."""
    try:
        value = _identity(request, entity_type, normalize(entity_type, value))
    except ValueError as exc:
        raise HTTPException(status_code=422, detail={"error": str(exc)}) from None
    snapshot = await r.snapshot(Entity(entity_type, value))
    hit = b.match(
        Subject(
            ip=value if entity_type == "ip" else None,
            user_id=value if entity_type == "user" else None,
            device_id=value if entity_type == "device" else None,
            session_id=value if entity_type == "session" else None,
        )
    )
    snapshot["active_ban"] = (
        {"id": hit.id, "permanent": hit.permanent, "expires_at": hit.expires_at, "source": hit.source}
        if hit
        else None
    )
    snapshot["recent_strikes"] = await request.app.state.repo.list_strikes(entity_type, value)
    return snapshot


@router.delete("/reputation")
async def clear_reputation(
    request: Request,
    entity_type: Literal["ip", "user", "device", "session"],
    value: str,
    r: ReputationService = Depends(reputation),
) -> dict[str, Any]:
    """Forget an identity's reputation score and strike counters (e.g. a shared office IP after an
    incident is resolved). Active bans are not lifted here — see ``DELETE /admin/bans/{id}``; the
    durable strike records in PostgreSQL stay for the audit."""
    try:
        value = _identity(request, entity_type, normalize(entity_type, value))
    except ValueError as exc:
        raise HTTPException(status_code=422, detail={"error": str(exc)}) from None
    await r.clear(Entity(entity_type, value))
    log.info("reputation cleared", extra={"entity_type": entity_type})
    return {"cleared": True, "entity_type": entity_type, "value": value}
