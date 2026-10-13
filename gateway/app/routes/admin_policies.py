"""Admin API: policies with versioning (Stage 9). See ``app/policy/service.py`` for what they do.

    POST   /admin/policies                  create (version 1)
    GET    /admin/policies?channel=         list (``include_inactive`` for retired ones)
    GET    /admin/policies/{id}             one policy + its version history
    PUT    /admin/policies/{id}             replace → version + 1 (the old version is kept)
    DELETE /admin/policies/{id}             retire (the global default cannot be retired)

Every change is broadcast (``policies:changed``) so all gateway instances reload it.
"""

from __future__ import annotations

import logging
from typing import Any, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field, field_validator, model_validator

from app.pipeline.models import Channel
from app.policy.service import CHANNEL
from app.security import require_admin

log = logging.getLogger("gateway.admin")
router = APIRouter(prefix="/admin/policies", tags=["admin: policies"], dependencies=[Depends(require_admin)])

ActionName = Literal["allow", "restrict", "block", "inspect"]


class PolicyIn(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    channel: Channel | None = Field(None, description="omit for every channel")
    session_state: Literal["anonymous", "verified"] | None = Field(
        None, description="omit for both; 'verified' = after CMP's identity verification"
    )
    endpoint_pattern: str = Field(
        "*", min_length=1, max_length=200, description="glob on the logical endpoint"
    )
    sensitive: bool = False
    mode: Literal["enforce", "monitor"] = "enforce"
    thresholds: dict[Literal["ml_block_at", "ml_restrict_at"], float] = Field(default_factory=dict)
    actions: dict[ActionName, ActionName] = Field(
        default_factory=dict, description='overrides of the final action, e.g. {"restrict": "block"}'
    )
    description: str = Field("", max_length=1000)
    by: str = Field("admin", min_length=1, max_length=100)

    @field_validator("thresholds")
    @classmethod
    def _range(cls, v: dict[str, float]) -> dict[str, float]:
        if any(not 0 < x <= 1 for x in v.values()):
            raise ValueError("thresholds must be in (0, 1]")
        return v

    @model_validator(mode="after")
    def _order(self) -> PolicyIn:
        t = self.thresholds
        if "ml_block_at" in t and "ml_restrict_at" in t and t["ml_restrict_at"] >= t["ml_block_at"]:
            raise ValueError("ml_restrict_at must be below ml_block_at")
        return self


async def _changed(request: Request) -> None:
    request.app.state.policies.invalidate()
    try:
        await request.app.state.deps.redis.publish(CHANNEL, "changed")
    except Exception:  # noqa: BLE001 - other instances catch up on their cache TTL
        log.warning("policy change broadcast failed")


@router.post("", status_code=status.HTTP_201_CREATED)
async def create_policy(body: PolicyIn, request: Request) -> dict[str, Any]:
    try:
        row = await request.app.state.repo.save_policy(None, body.model_dump(), body.by)
    except Exception as exc:  # unique (channel, session state, pattern) among active policies
        if "unique" in str(exc).lower() or "duplicate" in str(exc).lower():
            raise HTTPException(status_code=409, detail={"error": "policy_exists_for_scope"}) from None
        raise
    await _changed(request)
    log.info("policy created", extra={"policy_id": str(row["id"])})
    return row  # type: ignore[no-any-return]


@router.get("")
async def list_policies(
    request: Request, channel: Channel | None = None, include_inactive: bool = False
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = await request.app.state.repo.list_policies(channel, include_inactive)
    return rows


@router.get("/{policy_id}")
async def get_policy(policy_id: UUID, request: Request) -> dict[str, Any]:
    row = await request.app.state.repo.get_policy(policy_id)
    if row is None:
        raise HTTPException(status_code=404, detail={"error": "not_found"})
    return {**row, "versions": await request.app.state.repo.policy_versions(policy_id)}


@router.put("/{policy_id}")
async def replace_policy(policy_id: UUID, body: PolicyIn, request: Request) -> dict[str, Any]:
    current = await request.app.state.repo.get_policy(policy_id)
    if current is None or not current["active"]:
        raise HTTPException(status_code=404, detail={"error": "not_found_or_retired"})
    if current["name"] == "global-default" and (body.channel or body.session_state):
        raise HTTPException(status_code=422, detail={"error": "global_default_applies_everywhere"})
    row = await request.app.state.repo.save_policy(policy_id, body.model_dump(), body.by)
    await _changed(request)
    log.info("policy updated", extra={"policy_id": str(policy_id), "version": row["version"]})
    return row  # type: ignore[no-any-return]


@router.delete("/{policy_id}")
async def retire_policy(policy_id: UUID, request: Request) -> dict[str, Any]:
    row = await request.app.state.repo.deactivate_policy(policy_id)
    if row is None:
        raise HTTPException(status_code=404, detail={"error": "not_found_retired_or_global_default"})
    await _changed(request)
    log.info("policy retired", extra={"policy_id": str(policy_id)})
    return row  # type: ignore[no-any-return]
