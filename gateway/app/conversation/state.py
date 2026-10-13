"""Conversation memory: what the gateway remembers about one conversation, stored in Redis.

One JSON value per CMP session (contact) at ``conv:{session_id}``, rewritten after each turn with
the TTL refreshed (``CONVERSATION_TTL_SECONDS``). Roughly 1.5 KB per turn (text excerpt +
half-precision embedding), at most ``CONVERSATION_WINDOW`` turns.

The AI's replies (``POST /v1/inspect/outbound``) are kept as *assistant turns* — action, length and a
hash, never their text. They are a separate list, so they never enter the window re-score or the
accumulated risk (which measure what the *customer* sends); a blocked reply counts as a block.

Privacy: turn excerpts (``CONV_TURN_CHARS``) are kept only for the window re-score and expire with
the TTL. Blocked turns keep no text at all — only a hash and an embedding, for retry detection.
"""

from __future__ import annotations

import hashlib
import math
from dataclasses import asdict, dataclass, field
from typing import Any

import orjson

from app.detectors.normalize import normalize

MAX_BLOCKED_REMEMBERED = 5


def text_hash(text: str) -> str:
    """Hash of the folded text: disguised copies of the same message hash the same."""
    return hashlib.sha256(normalize(text).match.encode()).hexdigest()[:16]


def cosine(a: list[float] | None, b: list[float] | None) -> float | None:
    if not a or not b or len(a) != len(b):
        return None
    dot = sum(x * y for x, y in zip(a, b, strict=True))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(y * y for y in b))
    return dot / (na * nb) if na and nb else None


@dataclass
class Turn:
    n: int  # turn number within the conversation (0-based)
    hash: str
    action: str  # final decision for this turn
    score: float  # max of the rules and ML scores for this turn
    text: str | None = None  # excerpt; None for blocked turns
    vector: list[float] | None = None
    attack_lean: float | None = None  # ML attack_similarity - benign_similarity
    rule_ids: list[str] = field(default_factory=list)


@dataclass
class BlockedTurn:
    n: int
    hash: str
    vector: list[float] | None = None


@dataclass
class AssistantTurn:
    n: int  # the customer turn it answers (state.n - 1 when it was recorded)
    hash: str
    action: str  # outbound decision: allow / restrict / block
    chars: int
    reasons: list[str] = field(default_factory=list)


@dataclass
class ConversationState:
    session_id: str
    turns: list[Turn] = field(default_factory=list)
    assistant: list[AssistantTurn] = field(default_factory=list)
    replies: int = 0  # AI replies checked so far
    blocked: list[BlockedTurn] = field(default_factory=list)
    n: int = 0  # turns seen so far (including ones no longer in the window)
    acc: float = 0.0  # accumulated risk
    blocks: int = 0  # blocked turns so far
    setup_turn: int | None = None  # last turn that contained a setup marker
    first_vector: list[float] | None = None  # embedding of the first scored turn (drift reference)

    def key(self) -> str:
        return state_key(self.session_id)

    def seen_by_ai(self) -> list[Turn]:
        """Turns that reached the AI (allowed or restricted). Blocked turns never did."""
        return [t for t in self.turns if t.action not in ("block", "throttle")]

    def to_json(self) -> bytes:
        return orjson.dumps(asdict(self))

    @classmethod
    def from_json(cls, raw: bytes | str) -> ConversationState:
        d: dict[str, Any] = orjson.loads(raw)
        d.pop("tenant", None)  # written before tenants were removed
        if "session_id" not in d:
            d["session_id"] = d.pop("conversation_id", "")
        d["assistant"] = [AssistantTurn(**a) for a in d.get("assistant", [])]
        d["turns"] = [Turn(**t) for t in d.get("turns", [])]
        d["blocked"] = [BlockedTurn(**b) for b in d.get("blocked", [])]
        return cls(**d)


def state_key(session_id: str) -> str:
    return f"conv:{session_id}"
