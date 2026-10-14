"""Tool-result inspection: check what a tool returned *before* the AI agent reads it.

In CMP an indirect prompt injection does not come from the customer's message: it sits in data the AI
fetches — a booking remark, an email body, a review, a web page. The AI agent calls
``POST /v1/inspect/tool-result`` with the tool's output; the gateway answers with what the agent may
put in the model's context.

How the result is read. JSON is walked and every string value is a *segment* (its path is kept, so
``bookings[0].remarks``); plain text is split into paragraphs. Long strings are cut into pieces of at
most ``SEGMENT_CHARS`` on sentence boundaries. Each segment is checked on its own — the rule engine
through ``untrusted_content`` (never a strike: the customer did not write it) and the ML classifier
per segment — so one poisoned remark is found among fifty clean fields and only it is removed. The ML
call asks for the service's tool-content model (trained on chat *and* tool data, with thresholds
calibrated on tool content); a service without one answers with the chat model.

* nothing found → allow, ``cmp_action`` ``deliver``: ``deliver`` is the result, unchanged;
* suspicious pieces (ML ≥ restrict, a medium rule finding — or the ML tier unavailable) → restrict,
  ``deliver_without_tools``: ``deliver`` is the result with those pieces replaced by ``REMOVED``;
* an injection (ML ≥ block; a high rule finding when UNTRUSTED_CONTENT_ACTION=block; a finding that
  cannot be placed) or a result too large to inspect → block, ``withhold``: ``deliver`` is None and the
  agent gives the model a neutral "the lookup returned nothing usable" instead.

``deliver_without_tools`` and ``withhold`` also mean: no further tool calls in this turn (an
injection may have been only partly removed, and its usual aim is a tool call). Nobody is struck or
banned and conversation memory is not touched; the decision is audited (mode ``tool``) and counted.

Callers need a key with the ``tool`` scope (CMP's AI agent). Policies match the endpoint
``tool:<tool_name>`` (a policy pattern ``tool*`` covers every tool).
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from typing import Any

from fastapi import APIRouter, BackgroundTasks, Depends, Request
from pydantic import BaseModel, Field

from app import metrics
from app.audit.events import build_event
from app.auth.models import Principal
from app.config import Settings
from app.ml.client import MLClient, MLUnavailable
from app.pipeline.checks import Check, make_untrusted_content_check, resolve_ml_thresholds
from app.pipeline.context import RequestContext
from app.pipeline.decide import decide
from app.pipeline.engine import Pipeline, Stage
from app.pipeline.models import Action, Channel, CheckResult, Decision, SessionId
from app.routes.inspect import _remember_decision, _replay, _session
from app.security import request_id, require_scope
from app.session.service import ANONYMOUS, SessionService

log = logging.getLogger("gateway.decision")
router = APIRouter(prefix="/v1", tags=["inspect"])

SEGMENT_CHARS = 600  # longer strings are cut into pieces of at most this many characters
MAX_SEGMENTS = 200  # beyond this the result is too large to inspect: withheld
MAX_RESULT_CHARS = 100_000
MAX_DEPTH = 12
ML_BATCH = 20  # texts per ML call (the ML client's limit)
REMOVED = "[removed by the security gateway: this text contained instructions]"

_SENTENCE_END = re.compile(r"(?<=[.!?])\s+")


@dataclass
class Segment:
    path: str
    text: str
    start: int  # offset of this piece inside the original string (pieces of one string share a path)


def _pieces(text: str) -> list[tuple[int, str]]:
    """(offset, piece) for one string: paragraphs, then sentences packed up to SEGMENT_CHARS."""
    out: list[tuple[int, str]] = []
    for para in re.finditer(r"[^\n]+(?:\n(?!\s*\n)[^\n]*)*", text):  # blocks between blank lines
        start, block = para.start(), para.group()
        if not block.strip():
            continue
        if len(block) <= SEGMENT_CHARS:
            out.append((start, block))
            continue
        pos, cur, cur_start = start, "", start
        for sentence in _SENTENCE_END.split(block):
            offset = text.find(sentence, pos)
            pos = offset + len(sentence)
            if cur and len(cur) + 1 + len(sentence) > SEGMENT_CHARS:
                out.append((cur_start, cur))
                cur, cur_start = "", offset
            if not cur:
                cur_start = offset
            # A single sentence longer than the limit is hard-cut.
            while len(sentence) > SEGMENT_CHARS:
                out.append((offset, sentence[:SEGMENT_CHARS]))
                sentence, offset = sentence[SEGMENT_CHARS:], offset + SEGMENT_CHARS
                cur_start = offset
            cur = f"{cur} {sentence}" if cur else sentence
        if cur:
            out.append((cur_start, cur))
    return out


def segments_of(result: Any) -> list[Segment]:
    """Every string in ``result`` (JSON values, or one text), cut into checkable pieces."""
    found: list[Segment] = []

    def walk(node: Any, path: str, depth: int) -> None:
        if depth > MAX_DEPTH or len(found) > MAX_SEGMENTS:
            return
        if isinstance(node, str):
            found.extend(Segment(path, piece, start) for start, piece in _pieces(node))
        elif isinstance(node, dict):
            for k, v in node.items():
                walk(v, f"{path}.{k}" if path else str(k), depth + 1)
        elif isinstance(node, list):
            for i, v in enumerate(node):
                walk(v, f"{path}[{i}]", depth + 1)

    walk(result, "", 0)
    return found


def sanitized(result: Any, segments: list[Segment], flagged: set[int]) -> Any:
    """A copy of ``result`` with the flagged pieces replaced by ``REMOVED`` (same shape and types)."""
    by_path: dict[str, list[Segment]] = {}
    for i in sorted(flagged):
        by_path.setdefault(segments[i].path, []).append(segments[i])

    def fix(s: str, path: str) -> str:
        for seg in sorted(by_path.get(path, []), key=lambda x: -x.start):  # right to left: offsets hold
            s = s[: seg.start] + REMOVED + s[seg.start + len(seg.text) :]
        return s

    def walk(node: Any, path: str, depth: int) -> Any:
        if depth > MAX_DEPTH:
            return node
        if isinstance(node, str):
            return fix(node, path) if path in by_path else node
        if isinstance(node, dict):
            return {k: walk(v, f"{path}.{k}" if path else str(k), depth + 1) for k, v in node.items()}
        if isinstance(node, list):
            return [walk(v, f"{path}[{i}]", depth + 1) for i, v in enumerate(node)]
        return node

    return walk(result, "", 0)


def make_tool_ml_check(client: MLClient, settings: Settings) -> Check:
    """The ML classifier on every segment (not only the highest-scoring text, as for a chat message):
    which segments are suspicious is what lets the gateway remove only those. Never a strike."""

    async def tool_ml_check(ctx: RequestContext) -> CheckResult:
        texts = ctx.untrusted_fields
        idx = [i for i, t in enumerate(texts) if len(t.strip()) >= settings.ml_min_chars]
        if not idx:
            return CheckResult(name="ml", passed=True, detail={"skipped": "too_short"})
        scores: dict[int, float] = {}
        result = None
        try:
            for b in range(0, len(idx), ML_BATCH):
                batch = idx[b : b + ML_BATCH]
                result = await client.score(
                    [texts[i] for i in batch], settings.max_prompt_chars, model="tool"
                )
                scores.update(zip(batch, result.scores, strict=False))
        except MLUnavailable as exc:
            detail: dict[str, Any] = {"unavailable": exc.reason, "failure_mode": settings.ml_failure_mode}
            if settings.ml_failure_mode == "allow":
                return CheckResult(name="ml", passed=True, detail={**detail, "degraded": True})
            # Unchecked tool data is passed on, but the agent may not act on it (no tools this turn).
            return CheckResult(
                name="ml", passed=False, action=Action.RESTRICT, reason="ml_unavailable", detail=detail
            )
        assert result is not None
        block_at, restrict_at, source = resolve_ml_thresholds(ctx, settings, result.thresholds)
        top = max(scores.values())
        detail = {
            "score": round(top, 4),
            "model_version": result.model_version,
            # "tool" when the ML service has a tool-content model; it falls back to the chat model.
            "model": result.model,
            "segments_scored": len(scores),
            "thresholds": {"block": block_at, "restrict": restrict_at, "source": source},
            "flagged": [
                {"segment": i, "score": round(s, 4)} for i, s in sorted(scores.items()) if s >= restrict_at
            ],
        }
        if top >= block_at:
            return CheckResult(
                name="ml",
                passed=False,
                score=top,
                action=Action.BLOCK,
                reason="indirect_injection",
                detail=detail,
            )
        if top >= restrict_at:
            return CheckResult(
                name="ml",
                passed=False,
                score=top,
                action=Action.RESTRICT,
                reason="tool_result_suspicious",
                detail=detail,
            )
        return CheckResult(name="ml", passed=True, score=top, detail=detail)

    return tool_ml_check


def build_tool_pipeline(settings: Settings, ml: MLClient) -> Pipeline:
    """Rules first (local, µs; an injection the rules are sure of skips the ML call), then ML."""
    stages = [Stage(make_untrusted_content_check(settings))]
    if settings.ml_enabled:
        stages.append(Stage(make_tool_ml_check(ml, settings)))
    return Pipeline(stages)


def flagged_segments(decision: Decision, n: int) -> set[int] | None:
    """Indexes of the segments a check flagged; None when a finding cannot be placed (then nothing
    of the result can be trusted)."""
    flagged: set[int] = set()
    for c in decision.checks:
        if c.name == "untrusted_content" and c.action is not None:
            for f in c.detail.get("findings", []):
                if f.get("severity") not in ("high", "medium"):
                    continue
                if not isinstance(f.get("field"), int):
                    return None
                flagged.add(f["field"])
        elif c.name == "ml":
            flagged.update(x["segment"] for x in c.detail.get("flagged", []))
    return {i for i in flagged if 0 <= i < n}


class ToolResultRequest(BaseModel):
    """Body of POST /v1/inspect/tool-result: one tool output, sent by CMP's AI agent before the model
    reads it."""

    session_id: str = SessionId
    tool_name: str = Field(..., min_length=1, max_length=100, pattern=r"^[A-Za-z0-9._:-]+$")
    result: Any = Field(..., description="The tool's output: a JSON value or text")
    message_id: str | None = Field(None, max_length=200, description="A repeat returns the cached decision")
    channel: Channel | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class ToolResultDecision(Decision):
    """``deliver`` is exactly what the agent may give the model (same shape as ``result``), or None."""

    deliver: Any = None
    segments: int = 0
    removed: list[str] = Field(default_factory=list, description="Paths of the removed pieces")


def _parse(result: Any) -> Any:
    """A JSON document sent as a string is inspected (and returned) as JSON."""
    if isinstance(result, str) and result.lstrip()[:1] in ("{", "["):
        try:
            return json.loads(result)
        except ValueError:
            return result
    return result


@router.post("/inspect/tool-result", response_model=ToolResultDecision)
async def inspect_tool_result(
    body: ToolResultRequest,
    request: Request,
    background: BackgroundTasks,
    principal: Principal = Depends(require_scope("tool")),
) -> ToolResultDecision:
    state = request.app.state
    settings: Settings = state.settings
    sessions: SessionService = state.sessions
    cached = await _replay(sessions, body.session_id, f"tool:{body.message_id}" if body.message_id else None)
    if cached is not None:
        return ToolResultDecision(**{**cached, "replayed": True})
    pipeline = getattr(state, "tool_pipeline", None)
    if pipeline is None:
        pipeline = state.tool_pipeline = build_tool_pipeline(settings, state.ml)

    original = body.result
    parsed = _parse(original)
    segs = segments_of(parsed)
    rec, loaded = await _session(sessions, body.session_id)
    ctx = RequestContext(
        request_id=request_id(request),
        principal=principal,
        text="\n".join(s.text for s in segs),
        endpoint=f"tool:{body.tool_name}",
        session_id=body.session_id,
        channel=body.channel or (rec.channel if rec else None),
        metadata={**body.metadata, "tool_name": body.tool_name},
        message_id=body.message_id,
        session_state=rec.state if rec else ANONYMOUS,
        mode="tool",
        direction="tool",
        session_store_ok=loaded,
    )
    ctx.untrusted_fields = [s.text for s in segs]

    too_large = len(segs) > MAX_SEGMENTS or len(ctx.text) > MAX_RESULT_CHARS
    if too_large:
        base = Decision(
            request_id=ctx.request_id,
            action=Action.BLOCK,
            risk=1.0,
            reasons=["tool_result_too_large"],
            checks=[
                CheckResult(
                    name="size",
                    passed=False,
                    score=1.0,
                    action=Action.BLOCK,
                    reason="tool_result_too_large",
                    detail={"segments": len(segs), "chars": len(ctx.text), "limit_segments": MAX_SEGMENTS},
                )
            ],
            latency_ms=0.0,
        )
    else:
        base = await decide(state, pipeline, ctx, has_text=bool(segs))

    removed: list[str] = []
    if base.action == Action.BLOCK:
        deliver, cmp_action = None, "withhold"
    elif base.action == Action.RESTRICT:
        flagged = flagged_segments(base, len(segs))
        if flagged is None:
            deliver, cmp_action = None, "withhold"
        else:
            deliver = sanitized(parsed, segs, flagged) if flagged else parsed
            removed = sorted({segs[i].path or "(text)" for i in flagged})
            cmp_action = "deliver_without_tools"
        if isinstance(original, str) and deliver is not None and not isinstance(deliver, str):
            deliver = json.dumps(deliver, ensure_ascii=False)
    else:
        deliver, cmp_action = original, "deliver"
    decision = ToolResultDecision(**base.model_dump(), deliver=deliver, segments=len(segs), removed=removed)
    decision.cmp_action = cmp_action
    decision.session_state = ctx.session_state
    await _remember_decision(sessions, ctx, decision)
    background.add_task(_record, state, ctx, decision)
    log.info(
        "decision",
        extra={
            "request_id": decision.request_id,
            "mode": "tool",
            "caller": principal.name,
            "session_id": ctx.session_id,
            "tool": body.tool_name,
            "action": decision.action.value,
            "cmp_action": decision.cmp_action,
            "segments": len(segs),
            "removed": len(removed),
            "latency_ms": decision.latency_ms,
        },
    )
    return decision


async def _record(state: Any, ctx: RequestContext, decision: Decision) -> None:
    """Metrics and the audit event only: tool data is not the customer's, so no reputation, strike,
    ban or conversation memory follows from it."""
    try:
        metrics.record(ctx.mode, decision)
        if state.settings.audit_enabled:
            await state.audit.publish(build_event(ctx, decision, state.settings))
    except Exception:  # noqa: BLE001
        log.exception("tool-result audit failed", extra={"request_id": decision.request_id})
