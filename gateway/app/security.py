"""FastAPI dependencies: API-key auth, scopes, admin auth, client IP, request IDs."""

from __future__ import annotations

import hmac
import logging
import uuid
from collections.abc import Awaitable, Callable

from fastapi import Depends, Header, HTTPException, Request, status

from app.auth.keys import extract_presented_key
from app.auth.models import Principal
from app.auth.service import AuthError, AuthService
from app.bans.index import Subject
from app.config import Settings

log = logging.getLogger(__name__)

# One generic message for every auth failure: never tell the caller *why* a key was rejected.
_UNAUTHORIZED = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail={"error": "unauthorized"},
    headers={"WWW-Authenticate": "Bearer"},
)


def get_settings(request: Request) -> Settings:
    settings: Settings = request.app.state.settings
    return settings


def get_auth(request: Request) -> AuthService:
    auth: AuthService = request.app.state.auth
    return auth


def request_id(request: Request) -> str:
    rid: str | None = getattr(request.state, "request_id", None)
    if rid is None:
        rid = request.headers.get("x-request-id") or str(uuid.uuid4())
        request.state.request_id = rid
    return rid


_FORBIDDEN = HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail={"error": "forbidden"})


async def authenticate(
    request: Request,
    authorization: str | None = Header(default=None),
    x_api_key: str | None = Header(default=None),
    auth: AuthService = Depends(get_auth),
) -> Principal:
    settings: Settings = request.app.state.settings
    connecting_ip = client_ip(request, settings)

    # Banned IPs are refused before their key is even looked at (brute-force protection).
    if request.app.state.bans.match(Subject(ip=connecting_ip)) is not None:
        raise _FORBIDDEN

    presented = extract_presented_key(authorization, x_api_key)
    try:
        principal = await auth.authenticate(presented)
    except AuthError as exc:
        rid = request_id(request)
        log.info("auth rejected", extra={"reason": exc.reason, "request_id": rid})
        # Inline (not a background task): only failing requests pay for it, and it must not be skipped.
        await request.app.state.after_decision.record_auth_failure(connecting_ip, rid)
        raise _UNAUTHORIZED from None
    request.state.principal = principal
    return principal


def require_scope(scope: str) -> Callable[..., Awaitable[Principal]]:
    async def dependency(principal: Principal = Depends(authenticate)) -> Principal:
        if not principal.has_scope(scope):
            raise _FORBIDDEN
        return principal

    return dependency


async def require_admin(
    authorization: str | None = Header(default=None),
    x_admin_key: str | None = Header(default=None),
    settings: Settings = Depends(get_settings),
) -> None:
    presented = x_admin_key or extract_presented_key(authorization, None) or ""
    expected = settings.admin_api_key.get_secret_value()
    if not hmac.compare_digest(presented.encode(), expected.encode()):
        raise _UNAUTHORIZED


def client_ip(request: Request, settings: Settings) -> str | None:
    """The end client's IP.

    X-Forwarded-For is only trusted for the configured number of proxies in front of the gateway;
    otherwise anyone could claim any IP by sending the header.
    """
    direct = request.client.host if request.client else None
    if settings.trusted_proxy_count <= 0:
        return direct
    forwarded = request.headers.get("x-forwarded-for")
    if not forwarded:
        return direct
    hops = [h.strip() for h in forwarded.split(",") if h.strip()]
    # The rightmost N entries were added by our trusted proxies; the one before them is the client.
    index = len(hops) - settings.trusted_proxy_count
    if index < 0:
        return hops[0] if hops else direct
    return hops[index] if index < len(hops) else direct
