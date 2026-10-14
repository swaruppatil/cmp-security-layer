"""Gateway application factory.

    uv run uvicorn app.main:create_app --factory --port 8080    # local
    create_app(settings=..., deps=..., repo=...)               # tests (inject fakes)

On startup the lifespan:
1. creates the clients (unless injected) and runs pending database migrations;
2. creates the bootstrap caller key (``BOOTSTRAP_API_KEY``) if set and missing;
   builds the services: auth, admission (rate limits + reputation read), reputation/strikes, bans,
   CMP sessions, conversation memory;
3. loads the ban index, builds the pipeline and warms up the ML connection;
4. starts background tasks: the Redis event listener (auth invalidation, ban and policy changes),
   the periodic ban refresh and the audit worker (stream → security_events).
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from app import VERSION, metrics
from app.audit.stream import AuditPublisher, AuditWorker
from app.auth.keys import hash_key, parse_key
from app.auth.service import AuthService
from app.bans.service import BanService
from app.bots.service import BotService
from app.config import Settings
from app.conversation.service import ConversationService
from app.db.migrate import enable_dashboard_role, migrate
from app.db.repository import Repository
from app.deps import Deps, create_deps
from app.ml.client import MLClient
from app.ml.client import keep_warm as keep_ml_warm
from app.outbound.canary import CanaryService
from app.outbound.checks import (
    make_canary_check,
    make_prompt_leak_check,
    make_reply_commitment_check,
    make_reply_credential_request_check,
    make_reply_data_check,
    make_reply_injection_check,
    make_reply_links_check,
    make_reply_shape_check,
    make_reply_size_check,
)
from app.outbound.prompt_leak import PromptLeakService
from app.pipeline.after import AfterDecision
from app.pipeline.checks import (
    make_admission_check,
    make_ban_check,
    make_bot_check,
    make_conversation_check,
    make_conversation_memory_check,
    make_enumeration_check,
    make_failure_policy_check,
    make_fusion_check,
    make_ml_check,
    make_off_topic_check,
    make_rules_check,
    make_sensitive_check,
    make_size_check,
    make_untrusted_content_check,
)
from app.pipeline.engine import Pipeline, Stage
from app.policy.service import PolicyService
from app.reputation.service import ReputationService
from app.routes import (
    admin,
    admin_bans,
    admin_canaries,
    admin_events,
    admin_policies,
    admin_prompts,
    admin_sessions,
    health,
    inspect,
    inspect_tool_results,
    proxy,
    sessions,
)
from app.security import request_id
from app.session.service import SessionService
from app.state.admission import AdmissionService
from app.state.enumeration import EnumerationTracker
from app.state.events import listen_events, refresh_bans_periodically
from app.state.shared_ip import SharedIpTracker

log = logging.getLogger("gateway")

OPENAPI_TAGS = [
    {
        "name": "inspect",
        "description": "CMP asks for a decision on a customer message or an AI reply; CMP enforces it.",
    },
    {
        "name": "sessions",
        "description": "CMP session lifecycle: start (attributes), identity (IDV result), end.",
    },
    {
        "name": "proxy",
        "description": "Forward requests to the protected AI app when allowed; replies are checked too.",
    },
    {"name": "health", "description": "Liveness and readiness."},
    {"name": "admin", "description": "Caller API keys (CMP's enricher, its processor, test tools)."},
    {
        "name": "admin: bans",
        "description": "Bans, blacklists, reputation (sessions, customers, devices, IPs).",
    },
    {"name": "admin: policies", "description": "Policies per channel × session state × endpoint, versioned."},
    {
        "name": "admin: events & metrics",
        "description": "Audit trail search, accuracy labels, metrics summary.",
    },
    {
        "name": "admin: sessions",
        "description": "One session: attributes, verification, memory, bans, strikes.",
    },
    {
        "name": "admin: canaries",
        "description": "System-prompt leak detection: canary tokens and protected prompts (shingles).",
    },
]


def build_pipeline(
    settings: Settings,
    bans: BanService,
    admission: AdmissionService,
    ml: MLClient,
    conversations: ConversationService | None = None,
    bots: BotService | None = None,
    enumeration: EnumerationTracker | None = None,
) -> Pipeline:
    """The ordered checks: cheapest first, identity before content, the network-bound ML tier last,
    then the multi-turn analysis that needs everyone else's results.

    A check that blocks or throttles stops the pipeline, so most attacks never reach the ML tier.
    """
    stages = [
        Stage(make_ban_check(bans), needs_text=False),  # local memory, ~µs
    ]
    if settings.bot_enabled and bots is not None:
        stages.append(Stage(make_bot_check(bots, settings), needs_text=False))  # one Redis call
    stages += [
        Stage(make_admission_check(admission, settings), needs_text=False),  # one Redis call
        Stage(make_size_check(settings), needs_text=True),
    ]
    if settings.sensitive_enabled:
        stages.append(Stage(make_sensitive_check(settings)))  # local regex, redacts before anything else
        if settings.enum_enabled and enumeration is not None:
            stages.append(Stage(make_enumeration_check(enumeration, settings)))  # one Redis call, if any ids
    tracked = settings.conversation_enabled and conversations is not None
    if tracked:
        assert conversations is not None
        stages.append(Stage(make_conversation_memory_check(conversations, settings)))  # one Redis GET
    if settings.rules_enabled:
        stages.append(Stage(make_rules_check(settings), needs_text=True))  # local, ~50 µs
        stages.append(
            Stage(make_untrusted_content_check(settings), needs_text=True)
        )  # tool results, documents
    if settings.ml_enabled:
        stages.append(Stage(make_ml_check(ml, settings), needs_text=True))  # ML service, ≤ ML_TIMEOUT_MS
        stages.append(Stage(make_off_topic_check(settings), needs_text=True))  # local, from the ML answer
        if settings.rules_enabled:
            stages.append(
                Stage(make_fusion_check(settings), needs_text=True)
            )  # local, weak signals that agree
    if tracked:
        stages.append(Stage(make_conversation_check(settings)))  # local, uses the results above
    stages.append(Stage(make_failure_policy_check(settings), needs_text=False))  # local, last
    return Pipeline(stages)


SHUTDOWN_GRACE_SECONDS = 5.0


async def stop_tasks(tasks: list[asyncio.Task[None]]) -> None:
    """Cancel the background tasks and wait for them — but never longer than the grace period: a task
    stuck in a network call must not stop the gateway from shutting down (or a redeploy from finishing)."""
    for task in tasks:
        task.cancel()
    if not tasks:
        return
    _done, pending = await asyncio.wait(tasks, timeout=SHUTDOWN_GRACE_SECONDS)
    for task in pending:
        log.warning("background task did not stop within %.0f s: %s", SHUTDOWN_GRACE_SECONDS, task.get_name())


async def warm_up_ml(http: Any) -> None:
    """Open the connection to the ML service before the first real request.

    Without this the first request after a gateway start pays TCP setup and a cold scoring path,
    overruns ML_TIMEOUT_MS and is restricted as ``ml_unavailable``. Failures are ignored: /ready
    reports the ML service's health, and the failure mode covers it at request time."""
    for _ in range(2):
        with contextlib.suppress(Exception):
            await http.post("/v1/score", json={"texts": ["warm-up"], "return_vectors": True}, timeout=5)


async def bootstrap_caller_key(store: Any, cfg: Settings) -> None:
    """Create the ``BOOTSTRAP_API_KEY`` caller key if it does not exist (only its hash is stored).

    Lets a deployment hand CMP its key through a secret store instead of an admin call."""
    assert cfg.bootstrap_api_key is not None
    parsed = parse_key(cfg.bootstrap_api_key.get_secret_value())
    if parsed is None:
        raise RuntimeError("BOOTSTRAP_API_KEY must look like cmpsk_<10 hex chars>_<secret>")
    scopes = sorted({x.strip() for x in cfg.bootstrap_api_key_scopes.split(",") if x.strip()})
    if await store.ensure_api_key(cfg.bootstrap_api_key_name, parsed.prefix, hash_key(parsed.full), scopes):
        log.info("bootstrap caller key created", extra={"prefix": parsed.prefix})


def build_outbound_pipeline(
    settings: Settings,
    canaries: CanaryService,
    prompts: PromptLeakService | None = None,
    enumeration: EnumerationTracker | None = None,
) -> Pipeline:
    """Checks on an AI reply: size, prompt leaks (canary and content), echoed injections, requests for
    credentials, sensitive / out-of-scope data, unverified commitments, shape, exfiltration links."""
    stages = [Stage(make_reply_size_check(settings)), Stage(make_canary_check(canaries))]
    if prompts is not None:
        stages.append(Stage(make_prompt_leak_check(prompts, settings)))
    stages += [
        Stage(make_reply_injection_check(settings)),
        Stage(make_reply_credential_request_check(settings)),
        Stage(make_reply_data_check(settings, enumeration)),
        Stage(make_reply_commitment_check(settings)),
        Stage(make_reply_shape_check(settings)),
        Stage(make_reply_links_check(settings)),
    ]
    return Pipeline(stages)


def create_app(
    settings: Settings | None = None,
    deps: Deps | None = None,
    repo: Any | None = None,
    run_migrations: bool = True,
    background_tasks: bool = True,
) -> FastAPI:
    """Build the app. Passing ``deps``/``repo`` skips creating real clients (used by tests).

    ``background_tasks=False`` skips the Redis event listener and periodic ban refresh (unit tests
    drive those directly; fakeredis pub/sub does not cooperate with TestClient's event loop).
    """

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        cfg: Settings = app.state.settings
        logging.basicConfig(
            level=cfg.log_level.upper(), format="%(asctime)s %(levelname)s %(name)s %(message)s"
        )
        owned_deps = deps is None
        app.state.deps = deps or await create_deps(cfg)
        if owned_deps and run_migrations:
            applied = await migrate(cfg.database_url)
            if applied:
                log.info("migrations applied: %s", ", ".join(applied))
            if cfg.dashboard_db_password is not None:
                await enable_dashboard_role(cfg.database_url, cfg.dashboard_db_password.get_secret_value())

        redis = app.state.deps.redis
        store: Any = repo or Repository(app.state.deps.db)
        app.state.repo = store
        if cfg.bootstrap_api_key is not None:
            await bootstrap_caller_key(store, cfg)
        app.state.auth = AuthService(
            store,
            ttl_seconds=cfg.auth_cache_ttl_seconds,
            negative_ttl_seconds=cfg.auth_negative_cache_ttl_seconds,
            max_entries=cfg.auth_cache_max_entries,
        )
        app.state.reputation = ReputationService(redis, cfg)
        app.state.bans = BanService(store, redis, cfg)
        await app.state.bans.reload()
        app.state.admission = AdmissionService(redis, cfg)
        app.state.ml = MLClient(
            app.state.deps.ml, timeout_ms=cfg.ml_timeout_ms, max_concurrency=cfg.ml_max_concurrency
        )
        # The background fetch of embeddings for blocked turns gets a looser timeout than the hot path.
        background_ml = MLClient(
            app.state.deps.ml, timeout_ms=max(cfg.ml_timeout_ms, 1000), max_concurrency=8
        )
        app.state.conversations = ConversationService(redis, cfg, background_ml)
        app.state.sessions = SessionService(redis, cfg)
        app.state.audit = AuditPublisher(redis, store, cfg)
        app.state.audit_worker = AuditWorker(redis, store, cfg)
        app.state.policies = PolicyService(store, ttl_seconds=cfg.policy_cache_ttl_seconds)
        await app.state.policies.reload()
        app.state.shared_ip = SharedIpTracker(redis, cfg)
        app.state.after_decision = AfterDecision(
            app.state.reputation,
            app.state.bans,
            cfg,
            app.state.conversations,
            app.state.audit,
            app.state.shared_ip,
        )
        metrics.ACTIVE_BANS.set_function(lambda: app.state.bans.index.size)
        app.state.bots = BotService(redis, cfg)
        enumeration = EnumerationTracker(redis, cfg)
        app.state.pipeline = build_pipeline(
            cfg,
            app.state.bans,
            app.state.admission,
            app.state.ml,
            app.state.conversations,
            app.state.bots,
            enumeration,
        )
        app.state.canaries = CanaryService(store, ttl_seconds=cfg.canary_cache_ttl_seconds)
        app.state.prompt_leak = PromptLeakService(store, ttl_seconds=cfg.canary_cache_ttl_seconds)
        app.state.outbound_pipeline = build_outbound_pipeline(
            cfg, app.state.canaries, app.state.prompt_leak, enumeration
        )

        if owned_deps and cfg.ml_enabled:
            await warm_up_ml(app.state.deps.ml)

        tasks: list[asyncio.Task[None]] = []
        if background_tasks:
            tasks = [
                asyncio.create_task(
                    listen_events(redis, app.state.auth, app.state.bans, app.state.policies), name="events"
                ),
                asyncio.create_task(
                    refresh_bans_periodically(app.state.bans, cfg.ban_cache_refresh_seconds),
                    name="ban-refresh",
                ),
            ]
            if cfg.ml_enabled and cfg.ml_keep_warm_seconds > 0:
                tasks.append(
                    asyncio.create_task(
                        keep_ml_warm(app.state.ml, cfg.ml_keep_warm_seconds), name="ml-keep-warm"
                    )
                )
            if cfg.audit_enabled and cfg.audit_worker_enabled:
                tasks.append(asyncio.create_task(app.state.audit_worker.run_forever(), name="audit-worker"))
        try:
            yield
        finally:
            await stop_tasks(tasks)
            if owned_deps:
                await app.state.deps.close()

    app = FastAPI(
        title="CMP Security Gateway",
        version=VERSION,
        lifespan=lifespan,
        description=(
            "AI security gateway for CMP: every customer message and AI reply of a CMP session "
            "(Amazon Connect contact) gets a decision and a cmp_action. Authentication, bans, rate "
            "limiting, prompt-attack detection (rules + ML), multi-turn analysis, sensitive-data "
            "redaction, outbound checks, bot detection, policies and an audit trail.\n\n"
            "Callers authenticate with `Authorization: Bearer <api key>` (or `X-API-Key`); admin "
            "endpoints take `X-Admin-Key` (or the admin key as a bearer token)."
        ),
        openapi_tags=OPENAPI_TAGS,
    )
    app.state.settings = settings or Settings()

    @app.middleware("http")
    async def request_id_and_size(request: Request, call_next: Any) -> Any:
        rid = request_id(request)
        declared = request.headers.get("content-length")
        if declared and declared.isdigit() and int(declared) > app.state.settings.max_body_bytes:
            return JSONResponse({"error": "payload_too_large", "request_id": rid}, status_code=413)
        response = await call_next(request)
        response.headers["x-request-id"] = rid
        return response

    @app.exception_handler(Exception)
    async def unexpected_error(request: Request, exc: Exception) -> JSONResponse:
        # Never drop the connection or leak internals: a generic 500 with the request id to look up.
        rid = request_id(request)
        log.exception("unhandled error", extra={"request_id": rid, "path": request.url.path})
        return JSONResponse({"error": "internal_error", "request_id": rid}, status_code=500)

    @app.exception_handler(RequestValidationError)
    async def validation_error(request: Request, exc: RequestValidationError) -> JSONResponse:
        # Field names and messages only; never echo the submitted values back.
        errors = [{"loc": list(e.get("loc", [])), "msg": e.get("msg")} for e in exc.errors()]
        return JSONResponse(
            {"error": "invalid_request", "details": errors, "request_id": request_id(request)},
            status_code=422,
        )

    app.include_router(health.router)
    app.include_router(inspect.router)
    app.include_router(inspect_tool_results.router)
    app.include_router(sessions.router)
    app.include_router(admin.router)
    app.include_router(admin_bans.router)
    app.include_router(admin_sessions.router)
    app.include_router(admin_canaries.router)
    app.include_router(admin_prompts.router)
    app.include_router(admin_events.router)
    app.include_router(admin_policies.router)
    app.include_router(proxy.router)
    return app
