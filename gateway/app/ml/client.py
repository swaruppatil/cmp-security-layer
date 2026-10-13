"""Client for the ML service's ``POST /v1/score``.

Built to never slow the gateway down more than ``ml_timeout_ms``:
* one hard deadline per call (connect + send + read), enforced with ``asyncio.wait_for`` on top of
  the HTTP client's own timeouts;
* a concurrency cap: when ``ml_max_concurrency`` calls are already in flight, new requests are
  *shed* immediately instead of queueing — under overload the ML tier degrades first, never bans
  and rate limits (PLAN.md §13);
* any failure raises ``MLUnavailable``; the check turns that into ``ML_FAILURE_MODE``.
"""

from __future__ import annotations

import asyncio
import base64
import struct
import time
from dataclasses import dataclass, field
from typing import Any

import httpx

MAX_TEXTS = 20


class MLUnavailable(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def decode_vector(encoded: str | None) -> list[float] | None:
    """base64 little-endian float16 (from the ML service) → list of floats. No numpy needed."""
    if not encoded:
        return None
    raw = base64.b64decode(encoded)
    return list(struct.unpack(f"<{len(raw) // 2}e", raw))


@dataclass(frozen=True)
class TextScore:
    score: float
    components: dict[str, Any] | None = None
    vector: list[float] | None = None


@dataclass(frozen=True)
class MLScore:
    score: float  # max injection probability over the texts
    scores: list[float]
    model_version: str
    service_latency_ms: float
    # The model's own calibrated operating point ({"block": x, "restrict": y}), if it sent one.
    thresholds: dict[str, float] | None = None
    # Why the highest-scoring text scored what it did (n-gram, embedding, similarity, nearest family).
    components: dict[str, Any] | None = None
    # One entry per text sent, in order (score, components, and the embedding when requested).
    per_text: list[TextScore] = field(default_factory=list)


class MLClient:
    def __init__(self, http: httpx.AsyncClient, *, timeout_ms: int, max_concurrency: int) -> None:
        self._http = http
        self._timeout = timeout_ms / 1000
        self._sem = asyncio.Semaphore(max_concurrency)
        self.shed = 0  # calls refused because the tier was saturated (observability)
        self.last_used = time.monotonic()

    async def score(self, texts: list[str], max_chars: int, *, vectors: bool = False) -> MLScore:
        self.last_used = time.monotonic()
        if self._sem.locked():
            self.shed += 1
            raise MLUnavailable("saturated")
        payload: dict[str, Any] = {"texts": [t[:max_chars] for t in texts[:MAX_TEXTS]]}
        if vectors:
            payload["return_vectors"] = True
        async with self._sem:
            try:
                res = await asyncio.wait_for(
                    self._http.post("/v1/score", json=payload), timeout=self._timeout
                )
            except TimeoutError:
                raise MLUnavailable("timeout") from None
            except httpx.HTTPError as exc:
                raise MLUnavailable(type(exc).__name__) from None
        if res.status_code != 200:
            raise MLUnavailable(f"http_{res.status_code}")
        try:
            body: dict[str, Any] = res.json()
            results = body["results"]
            scores = [float(r["score"]) for r in results]
            top = max(range(len(scores)), key=scores.__getitem__) if scores else None
            raw = body.get("thresholds")
            thresholds = {"block": float(raw["block"]), "restrict": float(raw["restrict"])} if raw else None
            return MLScore(
                score=max(scores, default=0.0),
                scores=scores,
                model_version=str(body["model_version"]),
                service_latency_ms=float(body.get("latency_ms", 0.0)),
                thresholds=thresholds,
                components=results[top].get("components") if top is not None else None,
                per_text=[
                    TextScore(float(r["score"]), r.get("components"), decode_vector(r.get("vector")))
                    for r in results
                ],
            )
        except (ValueError, KeyError, TypeError, struct.error):
            raise MLUnavailable("bad_response") from None


async def keep_warm(client: MLClient, interval: float) -> None:
    """Score a dummy text whenever this gateway has made no ML call for ``interval`` seconds.

    After a quiet spell the first real call paid a new connection and a cold code path on both sides
    and overran ML_TIMEOUT_MS, so the first customer message was restricted as ``ml_unavailable``
    (seen after the stack sat idle overnight). Keeping the connection and the path warm costs one
    tiny request per interval while idle and nothing under traffic."""
    while True:
        await asyncio.sleep(interval)
        if time.monotonic() - client.last_used >= interval:
            try:
                await client.score(["warm-up"], 100)
            except MLUnavailable:
                pass
