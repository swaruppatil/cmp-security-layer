"""What CMP should do with a decision: one ``cmp_action`` per decision, so the enricher and the
processor need no knowledge of check names or reasons.

Inbound (``POST /v1/inspect``):

* ``deliver`` — allow: publish the message to the AI agent (``redacted_message`` instead, if present)
* ``forward_without_tools`` — restrict: publish with tools / account actions switched off
* ``retry_later`` — throttle (rate limit, bot cooldown): wait ``retry_after_seconds``, "one moment"
* ``refuse`` — block: a canned "I can't help with that" reply
* ``handoff_to_agent`` — the session is locked, or this is its ``CMP_HANDOFF_AFTER_BLOCKS``-th
  block: transfer the contact to a live agent
* ``end_contact`` — the session, customer, device or IP is banned for longer than
  ``CMP_SHORT_BAN_SECONDS`` (or permanently): close the contact politely. A shorter ban is
  ``retry_later``, with ``retry_after_seconds`` set to when it ends.

Outbound (``POST /v1/inspect/outbound``): ``deliver`` (send ``deliver``, never the original reply) or
``send_fallback`` (nothing may be sent: use a safe fallback message).
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Literal

from app.pipeline.models import Action, Decision

CmpAction = Literal[
    "deliver",
    "forward_without_tools",
    "retry_later",
    "refuse",
    "handoff_to_agent",
    "end_contact",
    "send_fallback",
]


def ban_seconds_left(decision: Decision) -> float | None:
    """Seconds until the ban on this request ends; ``inf`` when permanent, None when not banned."""
    ban = next((c for c in decision.checks if c.name == "ban" and c.reason == "banned"), None)
    if ban is None:
        return None
    if ban.detail.get("permanent") or not ban.detail.get("expires_at"):
        return float("inf")
    ends = datetime.fromisoformat(str(ban.detail["expires_at"]))
    return max(0.0, (ends - datetime.now(UTC)).total_seconds())


def inbound_action(
    decision: Decision, prior_blocks: int, handoff_after_blocks: int, short_ban_seconds: int = 900
) -> CmpAction:
    """``prior_blocks``: blocks this session already had before this message. May set
    ``decision.retry_after_seconds`` (a short ban)."""
    reasons = set(decision.reasons)
    if decision.action == Action.THROTTLE:
        return "retry_later"
    if decision.action == Action.BLOCK:
        left = ban_seconds_left(decision)
        if left is not None:
            if left <= short_ban_seconds:
                decision.retry_after_seconds = max(1, int(left + 0.999))
                return "retry_later"
            return "end_contact"
        if "conversation_locked" in reasons or prior_blocks + 1 >= handoff_after_blocks:
            return "handoff_to_agent"
        return "refuse"
    if decision.action == Action.RESTRICT:
        return "handoff_to_agent" if "conversation_locked" in reasons else "forward_without_tools"
    return "deliver"


def outbound_action(deliver: str | None) -> CmpAction:
    return "deliver" if deliver is not None else "send_fallback"
