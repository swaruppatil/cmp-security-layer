"""ML/NLP detection service.

    GET  /health      liveness + which models are loaded
    GET  /v1/model    version, embedder, calibrated thresholds, training data, evaluation metrics
    POST /v1/score    {"texts": [...], "model": "chat"|"tool"} → per text: score (0..1) + the
                      components behind it; plus the answering model's calibrated thresholds

Two models, same format (``app/ensemble.py``):

* **chat** — customer messages (``models/current.json``). Always present.
* **tool** — tool output the AI agent is about to read: booking records, emails, documents
  (``models/tool/current.json``). Trained on the chat data *plus* ``datasets/tool`` and calibrated
  on tool content, so a normal booking remark is not an injection and a planted instruction is.
  Optional: a request for ``"tool"`` when none is loaded is answered by the chat model, and the
  response says which one answered (``model``).

Models are loaded once at startup from ``ML_MODEL_DIR`` and warmed up, so the first real request
doesn't pay ONNX initialisation. Scoring is a few milliseconds of CPU per text; it runs in FastAPI's
threadpool (sync endpoint).
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any, Literal

from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel, Field

from app.config import settings
from app.model import InjectionModel, load_current, load_tool

VERSION = "0.8.0"
MAX_TEXTS = 50
MAX_CHARS = 20_000

log = logging.getLogger("ml-service")

ModelName = Literal["chat", "tool"]


class ScoreRequest(BaseModel):
    texts: list[str] = Field(..., min_length=1, max_length=MAX_TEXTS)
    # Also return each text's embedding (base64 float16, unit length) — used by the gateway's
    # conversation analysis to compare turns. Off by default: it adds ~1 KB per text.
    return_vectors: bool = False
    # Which model: "chat" for customer messages, "tool" for tool output (falls back to chat).
    model: ModelName = "chat"


class Components(BaseModel):
    ngram: float
    embedding: float
    attack_similarity: float
    benign_similarity: float
    nearest_attack_family: str | None
    # Similarity to airline-support examples; below thresholds.off_topic the message is not customer
    # support at all (homework, code, essays). Not part of the score. None for older models.
    topic_similarity: float | None = None
    # P(injection) from the pretrained transformer view (None when the model was trained without it).
    transformer: float | None = None


class ScoreResult(BaseModel):
    score: float
    components: Components
    vector: str | None = None


class Thresholds(BaseModel):
    block: float
    restrict: float
    off_topic: float | None = None


class ScoreResponse(BaseModel):
    model_version: str
    # The model that answered: "chat" or "tool" (chat when "tool" was asked for but none is loaded).
    model: ModelName
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
        if time.monotonic() - app.state.last_used >= interval:
            for m in (app.state.model, getattr(app.state, "tool_model", None)):
                if m is not None:
                    await asyncio.to_thread(m.score, ["warm-up"])
            app.state.last_used = time.monotonic()


def create_app(
    model: InjectionModel | None = None,
    model_dir: str | None = None,
    tool_model: InjectionModel | None = None,
) -> FastAPI:
    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        app.state.tool_model = tool_model
        if model is not None:
            app.state.model = model
        else:
            where = model_dir or settings.model_dir
            try:
                app.state.model = load_current(
                    where, cache_dir=settings.embed_cache_dir, threads=settings.embed_threads
                )
                app.state.model.score(["warm-up"])
                log.info("chat model loaded: %s", app.state.model.version)
            except (OSError, KeyError, ValueError, TypeError) as exc:
                # Start anyway so /health can report it; /v1/score answers 503.
                app.state.model = None
                log.error("no model loaded: %s", exc)
            if tool_model is None:
                try:
                    app.state.tool_model = load_tool(
                        where, cache_dir=settings.embed_cache_dir, threads=settings.embed_threads
                    )
                    if app.state.tool_model is not None:
                        app.state.tool_model.score(["warm-up"])
                        log.info("tool model loaded: %s", app.state.tool_model.version)
                except (OSError, KeyError, ValueError, TypeError) as exc:
                    app.state.tool_model = None
                    log.error("tool model not loaded (chat model answers for it): %s", exc)
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

    def current(request: Request, which: ModelName = "chat") -> tuple[InjectionModel, ModelName]:
        if which == "tool" and request.app.state.tool_model is not None:
            return request.app.state.tool_model, "tool"
        m: InjectionModel | None = request.app.state.model
        if m is None:
            raise HTTPException(status_code=503, detail={"error": "model_not_loaded"})
        return m, "chat"

    @app.get("/health")
    def health(request: Request) -> dict[str, Any]:
        m = request.app.state.model
        t = request.app.state.tool_model
        return {
            "status": "ok",
            "service": "ml-service",
            "version": VERSION,
            "model_loaded": m is not None,
            "model_version": m.version if m else None,
            "tool_model_version": t.version if t else None,
            "embedder": m.embedder_name if m else None,
        }

    @app.get("/v1/model")
    def model_info(request: Request, model: ModelName = "chat") -> dict[str, Any]:
        m, which = current(request, model)
        return {"version": m.version, "model": which, **m.metadata}

    @app.post("/v1/score", response_model=ScoreResponse)
    def score(body: ScoreRequest, request: Request) -> ScoreResponse:
        m, which = current(request, body.model)
        started = time.perf_counter()
        request.app.state.last_used = time.monotonic()
        scored = m.score_detailed([t[:MAX_CHARS] for t in body.texts], return_vectors=body.return_vectors)
        return ScoreResponse(
            model_version=m.version,
            model=which,
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
