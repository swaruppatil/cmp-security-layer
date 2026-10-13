"""Audit pipeline: decisions → Redis Stream → audit worker → PostgreSQL ``security_events``.

* **Publish** (after the response, in the background): one ``XADD`` per decision onto
  ``AUDIT_STREAM`` (trimmed to about ``AUDIT_STREAM_MAXLEN`` entries). If Redis is down the event
  is written straight to PostgreSQL instead, so no decision goes unrecorded while either store is up.
* **Worker** (a background task in every gateway, or ``python -m app.audit.stream``): reads the
  stream through a consumer group, so several gateways share the work and each event is written
  once; inserts a batch (``ON CONFLICT DO NOTHING`` — delivery is at least once) and acknowledges it
  only after the insert succeeds. Entries a crashed worker left unacknowledged are claimed after
  ``AUDIT_CLAIM_IDLE_SECONDS`` and retried.
"""

from __future__ import annotations

import asyncio
import logging
import os
import socket
from typing import Any

import orjson

from app import metrics
from app.config import Settings

log = logging.getLogger("gateway.audit")
GROUP = "audit-writers"


class AuditPublisher:
    def __init__(self, redis: Any, repo: Any, settings: Settings) -> None:
        self._redis = redis
        self._repo = repo
        self._s = settings

    async def publish(self, event: dict[str, Any]) -> None:
        try:
            await self._redis.xadd(
                self._s.audit_stream,
                {"e": orjson.dumps(event)},
                maxlen=self._s.audit_stream_maxlen,
                approximate=True,
            )
            metrics.AUDIT_EVENTS.labels(outcome="queued").inc()
            return
        except Exception:  # noqa: BLE001
            log.warning("audit stream unavailable; writing the event directly")
        try:
            await self._repo.insert_events([event])
            metrics.AUDIT_EVENTS.labels(outcome="direct").inc()
        except Exception:  # noqa: BLE001
            metrics.AUDIT_EVENTS.labels(outcome="dropped").inc()
            log.exception("audit event dropped", extra={"request_id": event.get("request_id")})


class AuditWorker:
    def __init__(self, redis: Any, repo: Any, settings: Settings, consumer: str | None = None) -> None:
        self._redis = redis
        self._repo = repo
        self._s = settings
        self._consumer = consumer or f"{socket.gethostname()}-{os.getpid()}"
        self._group_ready = False

    async def _ensure_group(self) -> None:
        if self._group_ready:
            return
        try:
            await self._redis.xgroup_create(self._s.audit_stream, GROUP, id="0", mkstream=True)
        except Exception as exc:  # noqa: BLE001
            if "BUSYGROUP" not in str(exc):
                raise
        self._group_ready = True

    async def _write(self, entries: list[tuple[Any, dict[Any, Any]]]) -> int:
        events, ids = [], []
        for entry_id, fields in entries:
            ids.append(entry_id)
            raw = fields.get(b"e") or fields.get("e")
            try:
                if raw is None:
                    raise TypeError("no event field")
                events.append(orjson.loads(raw))
            except (orjson.JSONDecodeError, TypeError):
                metrics.AUDIT_WRITES.labels(outcome="malformed").inc()
                log.error("malformed audit entry %s skipped", entry_id)
        if events:
            await self._repo.insert_events(events)  # raises → nothing acked → retried later
            metrics.AUDIT_WRITES.labels(outcome="written").inc(len(events))
        if ids:
            await self._redis.xack(self._s.audit_stream, GROUP, *ids)
        return len(events)

    async def run_once(self, block_ms: int | None = None) -> int:
        """Claim stale entries, then read and write one batch. Returns events written."""
        await self._ensure_group()
        written = 0
        claimed = await self._redis.xautoclaim(
            self._s.audit_stream,
            GROUP,
            self._consumer,
            min_idle_time=self._s.audit_claim_idle_seconds * 1000,
            start_id="0-0",
            count=self._s.audit_batch_size,
        )
        if claimed and claimed[1]:
            written += await self._write(claimed[1])
        resp = await self._redis.xreadgroup(
            GROUP,
            self._consumer,
            {self._s.audit_stream: ">"},
            count=self._s.audit_batch_size,
            block=block_ms,
        )
        for _stream, entries in resp or []:
            written += await self._write(entries)
        try:
            info = await self._redis.xpending(self._s.audit_stream, GROUP)
            metrics.AUDIT_PENDING.set(int(info["pending"]) if isinstance(info, dict) else int(info[0]))
        except Exception:  # noqa: BLE001
            log.debug("xpending failed", exc_info=True)
        return written

    async def drain(self) -> int:
        """Write everything currently in the stream (tests, shutdown)."""
        total = 0
        while True:
            n = await self.run_once(block_ms=None)
            total += n
            if n == 0:
                return total

    async def run_forever(self, idle_sleep: float = 0.5) -> None:
        """Poll the stream: read without blocking, and sleep briefly when it is empty.

        Not a blocking XREADGROUP: cancelling a task in the middle of a blocking Redis read did not
        always return, which hung gateway shutdown. A plain sleep is always cancellable; the cost is up
        to ``idle_sleep`` seconds before an event is written."""
        backoff = 0.5
        while True:
            try:
                written = await self.run_once(block_ms=None)
                backoff = 0.5
                if written == 0:
                    await asyncio.sleep(idle_sleep)
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001
                metrics.AUDIT_WRITES.labels(outcome="error").inc()
                log.warning("audit worker error; retrying in %.1fs", backoff, exc_info=True)
                await asyncio.sleep(backoff)
                backoff = min(backoff * 2, 10)


async def _main() -> None:  # pragma: no cover - standalone worker process
    from app.db.repository import Repository
    from app.deps import create_deps

    settings = Settings()
    logging.basicConfig(level=settings.log_level.upper())
    deps = await create_deps(settings)
    try:
        await AuditWorker(deps.redis, Repository(deps.db), settings).run_forever()
    finally:
        await deps.close()


if __name__ == "__main__":  # pragma: no cover
    asyncio.run(_main())
