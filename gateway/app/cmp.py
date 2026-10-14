"""What CMP should do with a decision: one ``cmp_action`` per decision, so the enricher and the
processor need no knowledge of check names or reasons.

Inbound (``POST /v1/inspect``):

* ``deliver`` — allow: publish the message to the AI agent (``redacted_message`` instead, if present)
* ``forward_without_tools`` — restrict: publish with tools / account actions switched off
* ``retry_later`` — throttle (rate limit, bot cooldown): wait ``retry_after_seconds``, "one moment"
* ``refuse`` — block: a canned "I can't help with that" reply. Repeated attacks are not escalated
  through CMP: the session's strikes ban it for a growing period (``BAN_LADDER_SECONDS``), which
  the next message sees as ``retry_later`` and then ``end_contact``
* ``end_contact`` — the session, customer, device or IP is banned for longer than
  ``CMP_SHORT_BAN_SECONDS`` (or permanently): close the contact politely. A shorter ban is
  ``retry_later``, with ``retry_after_seconds`` set to when it ends.

Outbound (``POST /v1/inspect/outbound``): ``deliver`` (send ``deliver``, never the original reply),
``send_fallback`` (nothing may be sent, including a reply that promises money or approvals the AI
cannot make: use a safe fallback message).

Tool results (``POST /v1/inspect/tool-result``, ``app/routes/inspect_tool_results.py``): ``deliver``
(give the model ``deliver``), ``deliver_without_tools`` (give the model ``deliver`` — suspicious pieces
removed — and make no further tool calls this turn) or ``withhold`` (give the model a neutral "the lookup
returned nothing usable"; no further tool calls this turn).
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
    "end_contact",
    "send_fallback",
    "deliver_without_tools",
    "withhold",
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


def inbound_action(decision: Decision, short_ban_seconds: int = 900) -> CmpAction:
    """May set ``decision.retry_after_seconds`` (a short ban)."""
    if decision.action == Action.THROTTLE:
        return "retry_later"
    if decision.action == Action.BLOCK:
        left = ban_seconds_left(decision)
        if left is not None:
            if left <= short_ban_seconds:
                decision.retry_after_seconds = max(1, int(left + 0.999))
                return "retry_later"
            return "end_contact"
        return "refuse"
    if decision.action == Action.RESTRICT:
        return "forward_without_tools"
    return "deliver"


# Restricted replies whose content must not reach the customer as written: CMP sends its fallback
# instead of the AI's text.
REVIEW_REASONS = frozenset({"unverified_commitment"})


def outbound_action(deliver: str | None, decision: Decision | None = None) -> CmpAction:
    if deliver is None:
        return "send_fallback"
    if decision is not None and decision.action == Action.RESTRICT and REVIEW_REASONS & set(decision.reasons):
        return "send_fallback"
    return "deliver"
