"""Multi-turn signals: decisions that need the conversation's history, not just this message.

* **accumulated risk** — many individually-borderline turns (probing) add up:
  ``acc = decay·acc + max(0, score − floor)``; ≥ CONV_RESTRICT_AT restricts, ≥ CONV_BLOCK_AT blocks.
* **setup marker** — "from now on …" arms the conversation: for N turns, excess counts double.
* **crescendo** — attack-likeness (ML attack − benign similarity) rising three turns in a row adds a
  small bonus to the accumulator.
* **window re-score** — the recent turns the AI saw, joined, scored by ML and rules. Counts only
  when the window scores clearly higher than any single turn (an attack split across turns), never
  just because one earlier turn was already suspicious.
* **retry after block** — a turn very similar to an earlier blocked one: restrict; block if it also
  looks risky on its own.
* **conversation lock** — after CONV_MAX_BLOCKS blocked turns, every later turn gets CONV_LOCK_ACTION.
* **drift** — distance of this turn from the first one; reported, not acted on.

Every function here is pure (no I/O), so the same code updates state after a turn that an earlier
check already blocked (``next_acc``) and is easy to test.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.config import Settings
from app.conversation.state import ConversationState, cosine
from app.pipeline.models import ACTION_SEVERITY, Action

# Rule ids that set up a later attack rather than being one (see detectors/rules.py).
SETUP_RULES = frozenset({"override.from_now_on", "jailbreak.evil_twin", "tokens.fake_turn"})


@dataclass
class TurnInput:
    score: float  # max(rules, ML) for this turn
    hash: str
    vector: list[float] | None = None
    attack_lean: float | None = None
    rule_ids: list[str] = field(default_factory=list)
    # Window re-score (None when there is no history or the ML tier didn't answer).
    window_score: float | None = None
    window_turn_max: float = 0.0  # best single-turn score among the window's turns
    window_rules: list[tuple[str, str]] = field(default_factory=list)  # (rule id, severity), cross-turn only
    # The ML model's operating point, reused for the window score.
    block_at: float = 0.9
    restrict_at: float = 0.7


@dataclass
class Signal:
    name: str
    action: Action
    reason: str
    score: float
    strike: bool = False


@dataclass
class Assessment:
    signals: list[Signal]
    acc: float
    detail: dict[str, Any]

    @property
    def worst(self) -> Signal | None:
        if not self.signals:
            return None
        return max(self.signals, key=lambda s: (ACTION_SEVERITY[s.action], s.score))


def is_armed(state: ConversationState, s: Settings) -> bool:
    return state.setup_turn is not None and state.n - state.setup_turn <= s.conv_setup_turns


def is_crescendo(state: ConversationState, attack_lean: float | None) -> bool:
    """Attack-likeness strictly rising over the last three turns, and now leaning to attack."""
    leans = [t.attack_lean for t in state.turns[-2:]] + [attack_lean]
    values = [x for x in leans if x is not None]
    if len(values) < 3:
        return False
    a, b, c = values
    return a < b < c and c > 0


def next_acc(
    state: ConversationState, score: float, attack_lean: float | None, s: Settings
) -> tuple[float, dict[str, Any]]:
    excess = max(0.0, score - s.conv_floor)
    armed = is_armed(state, s)
    if armed:
        excess *= s.conv_setup_boost
    crescendo = is_crescendo(state, attack_lean)
    if crescendo:
        excess += s.conv_crescendo_bonus
    acc = s.conv_decay * state.acc + excess
    return round(acc, 4), {"armed": armed, "crescendo": crescendo, "excess": round(excess, 4)}


def assess(state: ConversationState, turn: TurnInput, s: Settings) -> Assessment:
    signals: list[Signal] = []
    detail: dict[str, Any] = {"turn": state.n, "history_turns": len(state.turns), "blocks": state.blocks}

    # 1. Locked conversation.
    if state.blocks >= s.conv_max_blocks:
        lock = Action.BLOCK if s.conv_lock_action == "block" else Action.RESTRICT
        signals.append(Signal("lock", lock, "conversation_locked", 1.0))

    # 2. Retry after block.
    if state.blocked:
        sims = [1.0 if b.hash == turn.hash else cosine(turn.vector, b.vector) for b in state.blocked]
        best = max((x for x in sims if x is not None), default=None)
        if best is not None:
            detail["retry_similarity"] = round(best, 4)
            if best >= s.conv_retry_similarity:
                risky = turn.score >= turn.restrict_at
                signals.append(
                    Signal(
                        "retry", Action.BLOCK if risky else Action.RESTRICT, "retry_after_block", best, risky
                    )
                )

    # 3. Window re-score (split payloads).
    if turn.window_score is not None:
        lift = turn.window_score - turn.window_turn_max
        detail["window"] = {"score": round(turn.window_score, 4), "lift": round(lift, 4)}
        if lift >= s.conv_window_lift and s.conv_window_ml_action != "off":
            if turn.window_score >= turn.block_at and s.conv_window_ml_action == "block":
                signals.append(Signal("window", Action.BLOCK, "split_payload", turn.window_score, True))
            elif turn.window_score >= turn.restrict_at:
                signals.append(Signal("window", Action.RESTRICT, "split_payload", turn.window_score))
    if turn.window_rules:
        detail["window_rules"] = [rid for rid, _ in turn.window_rules]
        high = any(sev == "high" for _, sev in turn.window_rules)
        signals.append(
            Signal(
                "window_rules",
                Action.BLOCK if high else Action.RESTRICT,
                "split_payload",
                0.95 if high else 0.6,
                high,
            )
        )

    # 4. Accumulated risk (with setup markers and crescendo folded in).
    acc, acc_detail = next_acc(state, turn.score, turn.attack_lean, s)
    detail["accumulated"] = {"before": round(state.acc, 4), "after": acc, **acc_detail}
    if acc >= s.conv_block_at:
        signals.append(
            Signal("accumulated", Action.BLOCK, "persistent_probing", min(1.0, acc / s.conv_block_at), True)
        )
    elif acc >= s.conv_restrict_at:
        signals.append(
            Signal("accumulated", Action.RESTRICT, "conversation_risk", min(1.0, acc / s.conv_block_at))
        )

    # 5. Drift from the first turn (reported, not acted on).
    drift = cosine(turn.vector, state.first_vector)
    if drift is not None:
        detail["drift"] = round(1 - drift, 4)

    detail["signals"] = [sig.name for sig in signals]
    return Assessment(signals=signals, acc=acc, detail=detail)
