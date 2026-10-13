"""Runs the checks for one request and turns their results into a Decision.

Checks run in order. A check that returns BLOCK or THROTTLE stops the pipeline: once a request is
going to be refused there is no point paying for the later (more expensive) checks.

Each check declares whether it reads the request text. Requests with no user text (for example
``GET /v1/ai/models`` through the proxy) skip those, but still go through identity checks such as
bans and rate limits (Stage 3).

A check may return ``None`` when it has nothing to report (e.g. conversation memory for a request
without a conversation id); it is left out of the decision. Later checks can read earlier results
through ``ctx.results``.

Fusion rule: the strictest action any check asked for wins; risk is the highest score.
"""

from __future__ import annotations

import time
from collections.abc import Sequence
from dataclasses import dataclass

from app.pipeline.checks import Check
from app.pipeline.context import RequestContext
from app.pipeline.models import ACTION_SEVERITY, Action, CheckResult, Decision

STOP_ACTIONS = frozenset({Action.BLOCK, Action.THROTTLE})


@dataclass(frozen=True)
class Stage:
    check: Check
    needs_text: bool = True


class Pipeline:
    def __init__(self, stages: Sequence[Stage]) -> None:
        self._stages = list(stages)

    async def run(self, ctx: RequestContext, *, has_text: bool = True) -> Decision:
        started = time.perf_counter()
        results: list[CheckResult] = ctx.results
        for stage in self._stages:
            if stage.needs_text and not has_text:
                continue
            t0 = time.perf_counter_ns()
            result = await stage.check(ctx)
            if result is None:
                continue
            result.duration_us = (time.perf_counter_ns() - t0) // 1000
            results.append(result)
            if result.action in STOP_ACTIONS:
                break

        action = Action.ALLOW
        for r in results:
            if r.action is not None and ACTION_SEVERITY[r.action] > ACTION_SEVERITY[action]:
                action = r.action
        risk = max((r.score for r in results), default=0.0)
        reasons = [r.reason for r in results if r.reason]
        throttles = [
            int(r.detail.get("retry_after_seconds", 1)) for r in results if r.action == Action.THROTTLE
        ]
        return Decision(
            request_id=ctx.request_id,
            action=action,
            risk=risk,
            reasons=reasons,
            checks=results,
            latency_ms=round((time.perf_counter() - started) * 1000, 3),
            retry_after_seconds=max(throttles) if throttles else None,
        )
