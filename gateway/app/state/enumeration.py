"""Identifier enumeration: how many *different* booking references (tickets, Aeroplan numbers …) one
chat — or one IP, across chats — has typed within ``ENUM_WINDOW_SECONDS``.

A customer mentions one or two references; someone guessing references to find a valid one mentions
many. Each identifier is a keyed hash (never the value), kept in a sorted set scored by time:

    enum:session:{session_id}:{type}    distinct identifiers this chat typed
    enum:ip:{ip}:{type}                 distinct identifiers typed from this IP, across chats

One pipelined Redis round trip per message that carries an identifier: add, drop entries older than
the window, count, refresh the expiry.
"""

from __future__ import annotations

import time
from typing import Any

from app.config import Settings


def session_key(session_id: str, type_: str) -> str:
    return f"enum:session:{session_id}:{type_}"


def ip_key(ip: str, type_: str) -> str:
    return f"enum:ip:{ip}:{type_}"


class EnumerationTracker:
    def __init__(self, redis: Any, settings: Settings) -> None:
        self._redis = redis
        self._s = settings

    async def note(
        self, session_id: str | None, ip: str | None, typed: dict[str, set[str]]
    ) -> dict[str, dict[str, int]]:
        """Record ``typed`` (type → hashes) and return the distinct counts in the window:
        ``{"session": {type: n}, "ip": {type: n}}`` (only the scopes given)."""
        now = time.time()
        window = self._s.enum_window_seconds
        keys: list[tuple[str, str, str]] = []  # (scope, type, key)
        for type_ in typed:
            if session_id:
                keys.append(("session", type_, session_key(session_id, type_)))
            if ip:
                keys.append(("ip", type_, ip_key(ip, type_)))
        async with self._redis.pipeline(transaction=False) as pipe:
            for _scope, type_, key in keys:
                pipe.zadd(key, {h: now for h in typed[type_]})
                pipe.zremrangebyscore(key, 0, now - window)
                pipe.zcard(key)
                pipe.expire(key, window)
            res = await pipe.execute()
        out: dict[str, dict[str, int]] = {}
        for i, (scope, type_, _key) in enumerate(keys):
            out.setdefault(scope, {})[type_] = int(res[i * 4 + 2])
        return out
