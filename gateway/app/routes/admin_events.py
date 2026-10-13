"""Admin API: security events, accuracy labels, metrics summary, Prometheus metrics (Stage 9).

    GET  /admin/events                     search (newest first; ``before`` = cursor for the next page)
    GET  /admin/events/{id}                one event with every check
    POST /admin/events/{id}/label          mark false_positive / true_positive (or clear with null)
    GET  /admin/metrics/summary?hours=24   counts, top reasons, latency percentiles, labels, hourly series
    GET  /metrics                          Prometheus text format (admin key, e.g. as a bearer token)

Events never contain message text: only a hash and a redacted excerpt.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta
from typing import Any, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from pydantic import BaseModel, Field

from app import metrics
from app.security import require_admin
from app.session.identity import customer_key

log = logging.getLogger("gateway.admin")
router = APIRouter(tags=["admin: events & metrics"], dependencies=[Depends(require_admin)])


class LabelIn(BaseModel):
    label: Literal["false_positive", "true_positive"] | None
    note: str | None = Field(None, max_length=500)
    by: str = Field("admin", min_length=1, max_length=100)


@router.get("/admin/events")
async def search_events(
    request: Request,
    session_id: str | None = Query(None, max_length=200, description="every decision of one CMP session"),
    api_key_id: UUID | None = Query(None, description="decisions requested with one caller key"),
    action: Literal["allow", "restrict", "block", "throttle", "inspect"] | None = None,
    cmp_action: str | None = Query(None, max_length=50),
    channel: str | None = Query(None, max_length=50),
    reason: str | None = Query(None, max_length=100),
    mode: Literal["inspect", "proxy", "outbound", "proxy-outbound"] | None = None,
    user_id: str | None = Query(None, max_length=200, description="CMP customer id or its cu_… hash"),
    ip: str | None = Query(None, max_length=64),
    label: Literal["false_positive", "true_positive"] | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
    before: datetime | None = Query(
        None, description="cursor: the ts of the last event of the previous page"
    ),
    limit: int = Query(50, ge=1, le=500),
) -> dict[str, Any]:
    key = request.app.state.settings.identity_hash_key.get_secret_value()
    filters = {
        "session_id": session_id,
        "api_key_id": api_key_id,
        "action": action,
        "cmp_action": cmp_action,
        "channel": channel,
        "reason": reason,
        "mode": mode,
        "user_id": customer_key(key, user_id),
        "ip": ip,
        "label": label,
        "since": since,
        "until": until,
        "before": before,
    }
    rows = await request.app.state.repo.search_events(filters, limit)
    return {"events": rows, "next_before": rows[-1]["ts"] if len(rows) == limit else None}


@router.get("/admin/events/{event_id}")
async def get_event(event_id: UUID, request: Request) -> dict[str, Any]:
    row: dict[str, Any] | None = await request.app.state.repo.get_event(event_id)
    if row is None:
        raise HTTPException(status_code=404, detail={"error": "not_found"})
    return row


@router.post("/admin/events/{event_id}/label")
async def label_event(event_id: UUID, body: LabelIn, request: Request) -> dict[str, Any]:
    row: dict[str, Any] | None = await request.app.state.repo.label_event(
        event_id, body.label, body.note, body.by
    )
    if row is None:
        raise HTTPException(status_code=404, detail={"error": "not_found"})
    if body.label:
        metrics.LABELS.labels(label=body.label).inc()
    log.info("event labelled", extra={"event_id": str(event_id), "label": body.label})
    return row


@router.get("/admin/metrics/summary")
async def summary(
    request: Request,
    hours: int = Query(24, ge=1, le=24 * 90),
    channel: str | None = Query(None, max_length=50),
    api_key_id: UUID | None = None,
) -> dict[str, Any]:
    since = datetime.now(UTC) - timedelta(hours=hours)
    data: dict[str, Any] = await request.app.state.repo.events_summary(since, channel, api_key_id)
    labelled = (data.get("false_positives") or 0) + (data.get("true_positives") or 0)
    data["labelled_precision"] = round(data["true_positives"] / labelled, 4) if labelled else None
    data["since"] = since
    data["active_bans"] = request.app.state.bans.index.size
    return data


@router.get("/metrics", include_in_schema=False)
async def prometheus() -> Response:
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)
