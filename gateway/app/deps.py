"""External clients (Redis, PostgreSQL, ML service, upstream AI app) and readiness probes.

Created once at startup by the app lifespan and shared by all requests. Tests replace this object
with fakes, so routes never construct clients themselves.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

import asyncpg
import httpx
import redis.asyncio as aioredis

from app.config import Settings


@dataclass
class Probe:
    name: str
    check: Callable[[], Awaitable[None]]


async def run_probe(probe: Probe, timeout_ms: int) -> dict[str, Any]:
    started = time.perf_counter()
    try:
        await asyncio.wait_for(probe.check(), timeout=timeout_ms / 1000)
        return {"ok": True, "ms": round((time.perf_counter() - started) * 1000, 1)}
    except TimeoutError:
        return {"ok": False, "error": f"timeout after {timeout_ms} ms", "ms": timeout_ms}
    except Exception as exc:  # noqa: BLE001 - any failure means "not ready"
        return {
            "ok": False,
            "error": str(exc) or type(exc).__name__,
            "ms": round((time.perf_counter() - started) * 1000, 1),
        }


@dataclass
class Deps:
    redis: Any
    db: Any
    upstream: httpx.AsyncClient
    ml: httpx.AsyncClient
    probes: list[Probe] = field(default_factory=list)

    async def close(self) -> None:
        await self.upstream.aclose()
        await self.ml.aclose()
        if self.redis is not None:
            await self.redis.aclose()
        if self.db is not None:
            await self.db.close()


async def create_deps(settings: Settings) -> Deps:
    redis = aioredis.from_url(
        settings.redis_url,
        socket_connect_timeout=2,
        socket_timeout=2,
        health_check_interval=30,
    )
    db = await asyncpg.create_pool(
        settings.database_url,
        min_size=settings.db_pool_min,
        max_size=settings.db_pool_max,
        timeout=2,
        command_timeout=5,
    )
    limits = httpx.Limits(max_connections=200, max_keepalive_connections=50)
    upstream = httpx.AsyncClient(
        base_url=settings.upstream_ai_url,
        timeout=httpx.Timeout(settings.upstream_timeout_seconds, connect=2.0),
        limits=limits,
    )
    ml = httpx.AsyncClient(
        base_url=settings.ml_url,
        timeout=httpx.Timeout(settings.ml_timeout_ms / 1000, connect=1.0),
        # Long keep-alive: a reconnect costs part of the 50 ms ML budget after a quiet spell.
        limits=httpx.Limits(max_connections=settings.ml_max_concurrency, keepalive_expiry=120),
    )

    async def redis_probe() -> None:
        if not await redis.ping():
            raise RuntimeError("ping returned false")

    async def db_probe() -> None:
        await db.fetchval("SELECT 1")

    async def ml_probe() -> None:
        # Readiness gets its own timeout; the request-path ML timeout is far tighter.
        res = await ml.get("/health", timeout=settings.ready_probe_timeout_ms / 1000)
        res.raise_for_status()

    return Deps(
        redis=redis,
        db=db,
        upstream=upstream,
        ml=ml,
        probes=[Probe("redis", redis_probe), Probe("postgres", db_probe), Probe("ml-service", ml_probe)],
    )
