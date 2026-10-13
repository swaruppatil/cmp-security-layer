from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from app.auth.models import Principal

if TYPE_CHECKING:
    from app.conversation.state import ConversationState
    from app.ml.client import MLScore
    from app.pipeline.models import CheckResult
    from app.policy.service import Policy


@dataclass
class ConversationWindow:
    """The recent turns the AI saw, plus this one, joined for the split-payload re-score."""

    text: str
    turn_max: float  # best single-turn score among the previous turns in the window
    rule_ids: set[str]  # rule ids that already fired on a single turn in the window


@dataclass
class RequestContext:
    """Everything a check may look at for one request."""

    request_id: str
    principal: Principal
    text: str
    endpoint: str
    ip: str | None = None
    # The customer, as a keyed hash of CMP's customer id (``app/session/identity.py``).
    user_id: str | None = None
    # The CMP / Amazon Connect contact id: the backbone for conversation memory, the session rate
    # bucket, session bans and idempotency.
    session_id: str | None = None
    device_id: str | None = None
    channel: str | None = None
    # CMP's id for this message; a repeat within IDEMPOTENCY_TTL_SECONDS returns the cached decision.
    message_id: str | None = None
    # "anonymous" until CMP reports a successful identity verification for the session, then "verified".
    session_state: str = "anonymous"
    # All text fields found in a proxied body (indirect-injection checks read every one).
    text_fields: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    # The end user's user agent: proxy mode reads the header (and expects one); inspect mode only has
    # it when the caller passes it.
    user_agent: str | None = None
    user_agent_expected: bool = False
    # Which route produced this request: inspect | proxy | outbound | proxy-outbound.
    mode: str = "inspect"
    # The policy for (channel, session state, endpoint), resolved before the checks run (Stage 9).
    policy: Policy | None = None
    # "outbound" when the text is an AI reply (POST /v1/inspect/outbound, proxied responses).
    direction: str = "inbound"
    # Outbound: identifiers this user may see, by type (None = the caller gave no scope).
    allowed_identifiers: dict[str, list[str]] | None = None
    # Outbound, when the caller sent no list: hashes of the identifiers the session may see — from the
    # identity verification and the ones the customer typed in this session (``app/session``).
    allowed_identifier_hashes: dict[str, set[str]] | None = None

    # --- filled in while the pipeline runs ---
    # Bot tier (Stage 8): the end user's rate-limit buckets cost this much per request.
    bot_cost: float = 1.0
    # Sensitive data: findings (public form) and, when anything was redacted, the redacted fields
    # (same order as text_fields). Outbound: ``deliver`` is the reply as it may be sent.
    redactions: list[dict[str, Any]] = field(default_factory=list)
    redacted_fields: list[str] | None = None
    # Inbound: hashes of the identifiers (booking ref, email …) the customer typed, remembered for the
    # session so the AI may repeat them back.
    typed_identifiers: dict[str, set[str]] = field(default_factory=dict)
    deliver: str | None = None
    results: list[CheckResult] = field(default_factory=list)  # results of the checks so far
    ml: MLScore | None = None  # the ML answer for this request (fields first, then the window)
    ml_fields: int = 0  # how many of ml.per_text are this request's own fields
    # Conversation analysis (Stage 6); None when the request has no conversation id.
    conversation: ConversationState | None = None
    window: ConversationWindow | None = None
    turn_vector: list[float] | None = None
    turn_attack_lean: float | None = None

    @property
    def safe_text(self) -> str:
        """The text with sensitive data redacted (what may be stored or forwarded)."""
        return "\n".join(self.redacted_fields) if self.redacted_fields is not None else self.text
