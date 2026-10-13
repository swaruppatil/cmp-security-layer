from __future__ import annotations

import asyncio

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from app import VERSION
from app.deps import run_probe

router = APIRouter(tags=["health"])


@router.get("/health")
async def health() -> dict[str, str]:
    """Liveness: the process is up. Never touches dependencies."""
    return {"status": "ok", "service": "gateway", "version": VERSION}


@router.get("/ready")
async def ready(request: Request) -> JSONResponse:
    """Readiness: every dependency answers within the probe timeout; 503 names the one that didn't."""
    deps = request.app.state.deps
    timeout_ms = request.app.state.settings.ready_probe_timeout_ms
    results = await asyncio.gather(*(run_probe(p, timeout_ms) for p in deps.probes))
    checks = {p.name: r for p, r in zip(deps.probes, results, strict=True)}
    is_ready = all(r["ok"] for r in results)
    return JSONResponse(
        {"status": "ready" if is_ready else "not_ready", "checks": checks},
        status_code=200 if is_ready else 503,
    )
