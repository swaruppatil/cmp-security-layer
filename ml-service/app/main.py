"""ML/NLP detection service.

    GET  /health      liveness + whether a model is loaded
    GET  /v1/model    version, embedder, calibrated thresholds, training data, evaluation metrics
    POST /v1/score    {"texts": [...]} → per text: score (0..1) + the components behind it;
                      plus the model's calibrated block/restrict thresholds

The model is loaded once at startup from ``ML_MODEL_DIR`` (``current.json`` names the bundle) and
warmed up with one call, so the first real request doesn't pay ONNX initialisation. Scoring is a few
milliseconds of CPU per text; it runs in FastAPI's threadpool (sync endpoint).
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel, Field

from app.config import settings
from app.model import InjectionModel, load_current

VERSION = "0.6.0"
MAX_TEXTS = 50
MAX_CHARS = 20_000

log = logging.getLogger("ml-service")


class ScoreRequest(BaseModel):
    texts: list[str] = Field(..., min_length=1, max_length=MAX_TEXTS)
    # Also return each text's embedding (base64 float16, unit length) — used by the gateway's
    # conversation analysis to compare turns. Off by default: it adds ~1 KB per text.
    return_vectors: bool = False


class Components(BaseModel):
    ngram: float
    embedding: float
    attack_similarity: float
    benign_similarity: float
    nearest_attack_family: str | None


class ScoreResult(BaseModel):
    score: float
    components: Components
    vector: str | None = None


class Thresholds(BaseModel):
    block: float
    restrict: float


class ScoreResponse(BaseModel):
    model_version: str
    thresholds: Thresholds
    results: list[ScoreResult]
    latency_ms: float


async def keep_warm(app: FastAPI, interval: float) -> None:
    """Score a dummy text whenever the service has been idle for ``interval`` seconds.

    After 15–30 s without traffic the first real score took 36–72 ms instead of ~6 ms (ONNX Runtime
    and the CPU go cold), overrunning the gateway's 50 ms ML budget — so the first customer message
    after a quiet spell was restricted as ``ml_unavailable``. This costs ~6 ms of CPU per interval."""
    while True:
        await asyncio.sleep(interval)
        if time.monotonic() - app.state.last_used >= interval and app.state.model is not None:
            await asyncio.to_thread(app.state.model.score, ["warm-up"])
            app.state.last_used = time.monotonic()


def create_app(model: InjectionModel | None = None, model_dir: str | None = None) -> FastAPI:
    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        if model is not None:
            app.state.model = model
        else:
            try:
                app.state.model = load_current(
                    model_dir or settings.model_dir,
                    cache_dir=settings.embed_cache_dir,
                    threads=settings.embed_threads,
                )
                app.state.model.score(["warm-up"])
                log.info("model loaded: %s", app.state.model.version)
            except (OSError, KeyError, ValueError, TypeError) as exc:
                # Start anyway so /health can report it; /v1/score answers 503.
                app.state.model = None
                log.error("no model loaded: %s", exc)
        app.state.last_used = time.monotonic()
        warm = None
        if app.state.model is not None and settings.keep_warm_seconds > 0:
            warm = asyncio.create_task(keep_warm(app, settings.keep_warm_seconds))
        yield
        if warm is not None:
            warm.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await warm

    app = FastAPI(title="CMP Security ML Service", version=VERSION, lifespan=lifespan)

    def current(request: Request) -> InjectionModel:
        m: InjectionModel | None = request.app.state.model
        if m is None:
            raise HTTPException(status_code=503, detail={"error": "model_not_loaded"})
        return m

    @app.get("/health")
    def health(request: Request) -> dict[str, Any]:
        m = request.app.state.model
        return {
            "status": "ok",
            "service": "ml-service",
            "version": VERSION,
            "model_loaded": m is not None,
            "model_version": m.version if m else None,
            "embedder": m.embedder_name if m else None,
        }

    @app.get("/v1/model")
    def model_info(request: Request) -> dict[str, Any]:
        m = current(request)
        return {"version": m.version, **m.metadata}

    @app.post("/v1/score", response_model=ScoreResponse)
    def score(body: ScoreRequest, request: Request) -> ScoreResponse:
        m = current(request)
        started = time.perf_counter()
        request.app.state.last_used = time.monotonic()
        scored = m.score_detailed([t[:MAX_CHARS] for t in body.texts], return_vectors=body.return_vectors)
        return ScoreResponse(
            model_version=m.version,
            thresholds=Thresholds(**m.thresholds),
            results=[
                ScoreResult(
                    score=round(r["score"], 4), components=Components(**r["components"]), vector=r["vector"]
                )
                for r in scored
            ],
            latency_ms=round((time.perf_counter() - started) * 1000, 3),
        )

    return app


app = create_app()
