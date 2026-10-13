"""Proxy mode: inspect the request, and forward it to the protected AI app only if allowed.

* allow    → forwarded unchanged (apart from the headers below)
* restrict → forwarded with ``X-Security-Restricted: true`` so the app switches off sensitive tools
* block    → 403 with a generic body; nothing reaches the app
* throttle → 429 with ``Retry-After``; nothing reaches the app

Sensitive data (Stage 7): high-risk values in the request (card, SIN, passport, credentials …) are
redacted in the forwarded body. The app's JSON response goes through the outbound checks before it
is returned: blocked → 502 with a generic body; otherwise its reply fields are returned as the
checks left them (redacted, links stripped). The app may declare the identifiers this user may see in
an ``X-Security-Allowed-Identifiers`` response header (JSON, e.g. ``{"booking_ref": ["ABC123"]}``);
the gateway uses it for the authorized-data check and never passes it on.

End-user identity comes from headers: ``X-Session-Id`` (conversation memory, session limits and
bans), ``X-End-User-Id`` (stored hashed), ``X-Device-Id``, ``X-Channel`` (default ``web``).

Headers added to the forwarded request: ``X-Security-Request-Id``, ``X-Security-Decision``,
``X-Security-Restricted``. The gateway's own credentials (``Authorization`` / ``X-API-Key``) are never
forwarded upstream.
"""

from __future__ import annotations

import logging
from typing import Any

import httpx
import orjson
from fastapi import APIRouter, BackgroundTasks, Depends, Request, Response
from fastapi.responses import JSONResponse

from app.auth.models import Principal
from app.pipeline.context import RequestContext
from app.pipeline.decide import decide
from app.pipeline.extract import (
    RESPONSE_TEXT_KEYS,
    combined_text,
    extract_text_fields,
    replace_text_fields,
)
from app.pipeline.models import ACTION_SEVERITY, Action, Decision
from app.security import client_ip, request_id, require_scope

log = logging.getLogger("gateway.decision")
router = APIRouter(prefix="/v1/ai", tags=["proxy"])

# Hop-by-hop headers (RFC 9110 §7.6.1) and headers the gateway sets itself.
_DROP_REQUEST_HEADERS = frozenset(
    {
        "host",
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
        "content-length",
        "authorization",
        "x-api-key",
        "x-security-request-id",
        "x-security-decision",
        "x-security-restricted",
        "x-security-redacted",
    }
)
_DROP_RESPONSE_HEADERS = frozenset(
    {
        "connection",
        "keep-alive",
        "transfer-encoding",
        "content-length",
        "content-encoding",
        "server",
        "x-security-allowed-identifiers",
    }
)
SCOPE_HEADER = "x-security-allowed-identifiers"
MAX_REPLY_FIELDS = 20


def _blocked_response(decision: Decision) -> JSONResponse:
    if decision.action == Action.THROTTLE:
        headers = {"Retry-After": str(decision.retry_after_seconds or 1)}
        return JSONResponse(
            {"error": "too_many_requests", "request_id": decision.request_id},
            status_code=429,
            headers=headers,
        )
    # Generic on purpose: never reveal which check fired or the score.
    return JSONResponse(
        {
            "error": "request_blocked",
            "message": "This request can't be processed.",
            "request_id": decision.request_id,
        },
        status_code=403,
    )


async def proxy(
    path: str,
    request: Request,
    background: BackgroundTasks,
    principal: Principal = Depends(require_scope("proxy")),
) -> Response:
    settings = request.app.state.settings
    rid = request_id(request)

    raw = await request.body()
    if len(raw) > settings.max_body_bytes:
        return JSONResponse({"error": "payload_too_large", "request_id": rid}, status_code=413)

    fields: list[str] = []
    parsed: Any = None
    content_type = request.headers.get("content-type", "")
    if raw:
        if "json" in content_type:
            try:
                parsed = orjson.loads(raw)
            except orjson.JSONDecodeError:
                return JSONResponse({"error": "invalid_json", "request_id": rid}, status_code=400)
            fields = extract_text_fields(parsed)
        elif content_type.startswith("text/"):
            fields = [raw.decode("utf-8", errors="replace")]

    ctx = RequestContext(
        request_id=rid,
        principal=principal,
        text=combined_text(fields),
        text_fields=fields,
        endpoint=path,
        ip=client_ip(request, settings),
        user_id=request.app.state.sessions.customer(request.headers.get("x-end-user-id")),
        session_id=(request.headers.get("x-session-id") or "")[:200] or None,
        device_id=request.headers.get("x-device-id"),
        channel=(request.headers.get("x-channel") or "web").lower()[:50],
        user_agent=request.headers.get("user-agent"),
        user_agent_expected=True,
        mode="proxy",
    )
    # Requests with no user text (e.g. GET /v1/ai/models) skip content checks, not identity checks.
    decision = await decide(request.app.state, request.app.state.pipeline, ctx, has_text=bool(fields))
    # Reputation, strikes and auto-bans run after the response is sent (FastAPI attaches these
    # tasks to whichever Response we return, including the refusals below).
    background.add_task(request.app.state.after_decision, ctx, decision)

    log.info(
        "decision",
        extra={
            "request_id": rid,
            "mode": "proxy",
            "caller": principal.name,
            "path": path,
            "action": decision.action.value,
            "risk": decision.risk,
            "reasons": decision.reasons,
            "latency_ms": decision.latency_ms,
        },
    )
    if decision.action in (Action.BLOCK, Action.THROTTLE):
        return _blocked_response(decision)

    headers = {k: v for k, v in request.headers.items() if k.lower() not in _DROP_REQUEST_HEADERS}
    headers["x-security-request-id"] = rid
    headers["x-security-decision"] = decision.action.value
    headers["x-security-restricted"] = "true" if decision.action == Action.RESTRICT else "false"
    headers["x-security-redacted"] = "true" if ctx.redacted_fields is not None else "false"
    if ctx.redacted_fields is not None:  # forward the redacted text, never the original
        if parsed is not None:
            raw = orjson.dumps(replace_text_fields(parsed, ctx.redacted_fields))
        else:
            raw = ctx.redacted_fields[0].encode()

    upstream: httpx.AsyncClient = request.app.state.deps.upstream
    try:
        upstream_res = await upstream.request(
            request.method,
            f"/v1/ai/{path}",
            params=request.query_params,
            content=raw,
            headers=headers,
        )
    except httpx.TimeoutException:
        return JSONResponse({"error": "upstream_timeout", "request_id": rid}, status_code=504)
    except httpx.HTTPError:
        return JSONResponse({"error": "upstream_unavailable", "request_id": rid}, status_code=502)

    response_headers = {
        k: v for k, v in upstream_res.headers.items() if k.lower() not in _DROP_RESPONSE_HEADERS
    }
    response_headers["x-security-request-id"] = rid
    content = upstream_res.content
    if settings.outbound_enabled and "json" in upstream_res.headers.get("content-type", ""):
        checked = await _check_reply(request, ctx, upstream_res, background)
        if checked is None:
            return JSONResponse(
                {
                    "error": "response_blocked",
                    "message": "The response can't be delivered.",
                    "request_id": rid,
                },
                status_code=502,
            )
        content = checked
    return Response(content=content, status_code=upstream_res.status_code, headers=response_headers)


async def _check_reply(
    request: Request, inbound: RequestContext, res: httpx.Response, background: BackgroundTasks
) -> bytes | None:
    """Run the outbound checks on each reply field of a JSON response.

    Returns the (possibly rewritten) body, or ``None`` when the response must be withheld."""
    try:
        body = orjson.loads(res.content)
    except orjson.JSONDecodeError:
        return res.content
    fields = extract_text_fields(body, RESPONSE_TEXT_KEYS)[:MAX_REPLY_FIELDS]
    if not fields:
        return res.content
    scope: dict[str, list[str]] | None = None
    if SCOPE_HEADER in res.headers:
        try:
            raw_scope = orjson.loads(res.headers[SCOPE_HEADER])
            scope = {str(k): [str(v) for v in vals] for k, vals in raw_scope.items()}
        except (orjson.JSONDecodeError, AttributeError, TypeError):
            scope = {}  # unreadable scope: treat as "this user may see no identifiers"
    delivered: list[str] = []
    worst: tuple[RequestContext, Decision] | None = None
    for text in fields:
        ctx = RequestContext(
            request_id=inbound.request_id,
            principal=inbound.principal,
            text=text,
            text_fields=[text],
            endpoint=inbound.endpoint,
            ip=inbound.ip,
            user_id=inbound.user_id,
            session_id=inbound.session_id,
            device_id=inbound.device_id,
            channel=inbound.channel,
            direction="outbound",
            mode="proxy-outbound",
            allowed_identifiers=scope,
        )
        ctx.deliver = text
        decision = await decide(request.app.state, request.app.state.outbound_pipeline, ctx)
        if worst is None or ACTION_SEVERITY[decision.action] > ACTION_SEVERITY[worst[1].action]:
            worst = (ctx, decision)
        delivered.append(ctx.deliver if ctx.deliver is not None else text)
    assert worst is not None
    background.add_task(request.app.state.after_decision, worst[0], worst[1])
    log.info(
        "decision",
        extra={
            "request_id": inbound.request_id,
            "mode": "proxy-outbound",
            "action": worst[1].action.value,
            "reasons": worst[1].reasons,
        },
    )
    if worst[1].action == Action.BLOCK:
        return None
    if delivered == fields:
        return res.content
    return orjson.dumps(replace_text_fields(body, delivered, RESPONSE_TEXT_KEYS))


# One route per method, so every operation has its own id in the OpenAPI document.
for _method in ("GET", "POST", "PUT", "PATCH", "DELETE"):
    router.add_api_route(
        "/{path:path}",
        proxy,
        methods=[_method],
        name=f"proxy_{_method.lower()}",
        summary=f"{_method} through the gateway to the protected AI app",
    )
