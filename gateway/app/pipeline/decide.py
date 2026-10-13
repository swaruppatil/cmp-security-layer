"""One entry point for every route: resolve the policy, run the checks, apply the policy."""

from __future__ import annotations

from typing import Any

from app.pipeline.context import RequestContext
from app.pipeline.engine import Pipeline
from app.pipeline.models import Decision
from app.policy.service import apply


async def decide(state: Any, pipeline: Pipeline, ctx: RequestContext, *, has_text: bool = True) -> Decision:
    """``state`` is ``app.state`` (policies, pipelines)."""
    ctx.policy = await state.policies.resolve(
        ctx.endpoint, channel=ctx.channel, session_state=ctx.session_state
    )
    decision = await pipeline.run(ctx, has_text=has_text)
    return apply(ctx.policy, decision)
