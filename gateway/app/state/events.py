"""Cross-instance events over Redis pub/sub, plus the periodic ban-cache refresh.

| Channel           | Message      | Effect on every instance                    |
|-------------------|--------------|---------------------------------------------|
| ``auth:invalidate`` | key hash     | drop that key from the auth cache           |
| ``bans:changed``    | ban JSON     | add that ban to the local index (no DB read) |
| ``bans:changed``    | ``reload``   | reload the ban index from PostgreSQL        |
| ``policies:changed``| policy id    | reload policies on the next request          |

If the subscription breaks (Redis restart), it reconnects with a short back-off. Cache TTLs and the
periodic ban refresh cover anything missed while disconnected.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from app.auth.service import INVALIDATION_CHANNEL, AuthService
from app.bans.service import BANS_CHANNEL, BanService
from app.policy.service import CHANNEL as POLICIES_CHANNEL
from app.policy.service import PolicyService

log = logging.getLogger("gateway.events")


async def listen_events(
    redis: Any, auth: AuthService, bans: BanService, policies: PolicyService | None = None
) -> None:
    backoff = 0.5
    while True:
        pubsub = redis.pubsub()
        try:
            await pubsub.subscribe(INVALIDATION_CHANNEL, BANS_CHANNEL, POLICIES_CHANNEL)
            backoff = 0.5
            async for message in pubsub.listen():
                if message.get("type") != "message":
                    continue
                channel = message.get("channel")
                channel = channel.decode() if isinstance(channel, bytes) else channel
                data = message.get("data")
                data = data.decode() if isinstance(data, bytes) else str(data)
                if channel == INVALIDATION_CHANNEL:
                    auth.invalidate(data)
                elif channel == BANS_CHANNEL:
                    await bans.apply_message(data)
                elif channel == POLICIES_CHANNEL and policies is not None:
                    policies.invalidate()
        except asyncio.CancelledError:
            await _close(pubsub)
            raise
        except Exception:  # noqa: BLE001
            log.warning("event subscription lost; reconnecting in %.1fs", backoff)
        # Close the broken subscription *before* backing off, so no dead socket is held while waiting.
        await _close(pubsub)
        await asyncio.sleep(backoff)
        backoff = min(backoff * 2, 10)


async def _close(pubsub: Any) -> None:
    try:
        await pubsub.aclose()
    except Exception:  # noqa: BLE001
        log.debug("pubsub close failed", exc_info=True)


async def refresh_bans_periodically(bans: BanService, interval_seconds: float) -> None:
    while True:
        await asyncio.sleep(interval_seconds)
        await bans.reload()
