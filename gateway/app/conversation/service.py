"""Load and update conversation memory.

* ``load`` runs inside the pipeline (one Redis GET, before the rules) so the ML call can include the
  window re-score in the same request.
* ``record`` runs after the response, in the background: it appends the turn, updates the
  accumulator, counts blocks and remembers blocked turns for retry detection. A blocked turn that
  never reached the ML tier gets its embedding fetched here, off the hot path.

Updates are atomic: ``record`` re-reads the latest state inside a Redis optimistic transaction
(WATCH / MULTI, retried on conflict) and applies this turn to *that*, never to the snapshot the
request was analysed with. Turns fired back to back — before the previous turn's update has been
written — are therefore all counted (blocks, the lock, retry memory, the accumulator). A turn that
arrives before the previous update lands is still *analysed* against slightly older history.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Any

from redis.exceptions import WatchError

from app.config import Settings
from app.conversation.analysis import SETUP_RULES, next_acc
from app.conversation.state import (
    MAX_BLOCKED_REMEMBERED,
    AssistantTurn,
    BlockedTurn,
    ConversationState,
    Turn,
    state_key,
    text_hash,
)
from app.ml.client import MLClient, MLUnavailable
from app.pipeline.context import RequestContext
from app.pipeline.models import Action, Decision

log = logging.getLogger("gateway.conversation")
MAX_UPDATE_ATTEMPTS = 8

# Decisions that mean the content was never looked at: nothing to remember.
NOT_ANALYSED = frozenset({"banned", "message_too_long", "empty_message"})


class ConversationService:
    def __init__(self, redis: Any, settings: Settings, ml: MLClient | None = None) -> None:
        self._redis = redis
        self._s = settings
        self._ml = ml

    @property
    def settings(self) -> Settings:
        return self._s

    async def load(self, session_id: str) -> ConversationState:
        raw = await self._redis.get(state_key(session_id))
        if raw is None:
            return ConversationState(session_id=session_id)
        return ConversationState.from_json(raw)

    async def save(self, state: ConversationState) -> None:
        await self._redis.set(state.key(), state.to_json(), ex=self._s.conversation_ttl_seconds)

    async def delete(self, session_id: str) -> bool:
        return bool(await self._redis.delete(state_key(session_id)))

    async def get(self, session_id: str) -> ConversationState | None:
        raw = await self._redis.get(state_key(session_id))
        return ConversationState.from_json(raw) if raw is not None else None

    async def record(self, ctx: RequestContext, decision: Decision) -> None:
        try:
            await self._record(ctx, decision)
        except Exception:  # noqa: BLE001
            log.exception("conversation update failed", extra={"request_id": decision.request_id})

    async def _record(self, ctx: RequestContext, decision: Decision) -> None:
        if ctx.direction == "outbound":
            # The AI's reply is remembered as an assistant turn (no text). A blocked reply (canary
            # leak, someone else's data …) also counts as a block, so repeated leaks lock the session
            # like repeated attacks do.
            if ctx.session_id:
                reply = AssistantTurn(
                    n=0,
                    hash=text_hash(ctx.text) if ctx.text else "",
                    action=decision.action.value,
                    chars=len(ctx.text or ""),
                    reasons=decision.reasons[:5],
                )
                await self._mutate(ctx.session_id, lambda st: self._add_reply(st, reply))
            return
        state = ctx.conversation
        if state is None or decision.action == Action.THROTTLE or NOT_ANALYSED & set(decision.reasons):
            return
        by_name = {c.name: c for c in decision.checks}
        score = max((by_name[n].score for n in ("rules", "ml") if n in by_name), default=0.0)
        rules = by_name.get("rules")
        rule_ids = [f["id"] for f in rules.detail.get("findings", [])] if rules else []
        vector, lean = ctx.turn_vector, ctx.turn_attack_lean
        h = text_hash(ctx.text)
        blocked = decision.action == Action.BLOCK

        if blocked and vector is None and self._ml is not None:
            try:  # embedding for retry detection, fetched off the hot path
                res = await self._ml.score([ctx.text], self._s.max_prompt_chars, vectors=True)
                vector = res.per_text[0].vector if res.per_text else None
            except MLUnavailable:
                pass

        turn = Turn(
            n=0,  # set from the latest state below
            hash=h,
            action=decision.action.value,
            score=round(score, 4),
            # Stored redacted: no card number, SIN or credential ever lands in conversation memory.
            text=None if blocked else ctx.safe_text[: self._s.conv_turn_chars],
            vector=vector,
            attack_lean=lean,
            rule_ids=rule_ids,
        )
        await self._mutate(state.session_id, lambda st: self._add_turn(st, turn, blocked))

    def _add_reply(self, state: ConversationState, reply: AssistantTurn) -> None:
        reply.n = max(state.n - 1, 0)
        state.assistant = [*state.assistant, reply][-self._s.conversation_window :]
        state.replies += 1
        if reply.action == Action.BLOCK.value:
            state.blocks += 1

    def _add_turn(self, state: ConversationState, turn: Turn, blocked: bool) -> None:
        # Recomputed on the latest state, so turns recorded out of order still accumulate.
        state.acc, _ = next_acc(state, turn.score, turn.attack_lean, self._s)
        turn.n = state.n
        state.turns = [*state.turns, turn][-self._s.conversation_window :]
        if blocked:
            state.blocks += 1
            state.blocked = [*state.blocked, BlockedTurn(n=turn.n, hash=turn.hash, vector=turn.vector)][
                -MAX_BLOCKED_REMEMBERED:
            ]
        if SETUP_RULES & set(turn.rule_ids):
            state.setup_turn = turn.n
        if state.first_vector is None and turn.vector is not None and not blocked:
            state.first_vector = turn.vector
        state.n += 1

    async def _mutate(self, session_id: str, change: Callable[[ConversationState], None]) -> None:
        """Apply ``change`` to the latest stored state, atomically (WATCH / MULTI, retried on conflict)."""
        key = state_key(session_id)
        for _ in range(MAX_UPDATE_ATTEMPTS):
            async with self._redis.pipeline(transaction=True) as pipe:
                try:
                    await pipe.watch(key)
                    raw = await pipe.get(key)
                    state = (
                        ConversationState.from_json(raw)
                        if raw is not None
                        else ConversationState(session_id=session_id)
                    )
                    change(state)
                    pipe.multi()
                    pipe.set(key, state.to_json(), ex=self._s.conversation_ttl_seconds)
                    await pipe.execute()
                    return
                except WatchError:
                    continue  # another turn of this conversation was written first; re-read and retry
        log.warning("conversation update gave up after retries", extra={"session": session_id})
