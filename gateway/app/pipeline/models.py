"""Decision types shared by the pipeline, the inspect API and the proxy."""

from __future__ import annotations

from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, Field


class Action(StrEnum):
    ALLOW = "allow"
    BLOCK = "block"
    THROTTLE = "throttle"
    RESTRICT = "restrict"
    INSPECT = "inspect"


# Severity order used when several checks disagree: the strictest action wins.
ACTION_SEVERITY: dict[Action, int] = {
    Action.ALLOW: 0,
    Action.INSPECT: 1,
    Action.RESTRICT: 2,
    Action.THROTTLE: 3,
    Action.BLOCK: 4,
}


class CheckResult(BaseModel):
    """What one check concluded. ``action`` is None when the check has no opinion."""

    name: str
    passed: bool
    score: float = Field(0.0, ge=0.0, le=1.0)
    action: Action | None = None
    reason: str | None = None
    detail: dict[str, Any] = Field(default_factory=dict)
    duration_us: int = 0
    # True when this result counts as a strike against the end user (attack signals, abuse).
    strike: bool = False
    # How certain the evidence is. Permanent bans require deterministic evidence.
    evidence: Literal["deterministic", "probabilistic"] | None = None
    # True when a later check may confirm or soften this result (a phrase rule waiting for the ML
    # tier's opinion): the pipeline carries on past it instead of stopping.
    provisional: bool = False


class Decision(BaseModel):
    request_id: str
    action: Action
    risk: float = Field(ge=0.0, le=1.0)
    reasons: list[str]
    checks: list[CheckResult]
    latency_ms: float
    # Seconds the caller should wait before retrying (throttle only).
    retry_after_seconds: int | None = None
    # Sensitive data found (types and fingerprints only, never values). When anything was redacted,
    # ``redacted_message`` is the text the caller should pass on instead of the original (inspect mode).
    redactions: list[dict[str, Any]] = Field(default_factory=list)
    redacted_message: str | None = None
    # The policy that applied (Stage 9). In monitor mode ``action`` is what the caller must do (allow)
    # and ``would_have`` is what enforcement would have done.
    policy_id: str | None = None
    policy_version: int | None = None
    policy_mode: Literal["enforce", "monitor"] = "enforce"
    would_have: Action | None = None
    # What CMP should do (``app/cmp.py``), the session state the decision was made in, and whether
    # this is the cached decision for a repeated message_id.
    cmp_action: str | None = None
    session_state: str | None = None
    replayed: bool = False


class OutboundDecision(Decision):
    """Decision on an AI reply. ``deliver`` is exactly what the caller may send to the user: the
    reply, possibly redacted or with links stripped — or ``None`` when the reply must not be sent."""

    deliver: str | None = None


SessionId = Field(
    ...,
    min_length=1,
    max_length=200,
    pattern=r"^[A-Za-z0-9._:@-]+$",
    description="CMP's session id (the Amazon Connect contact id)",
)
Channel = Literal["web", "sms", "whatsapp", "apple", "facebook", "voice", "other"]


class InspectRequest(BaseModel):
    """Body of POST /v1/inspect: one customer message, sent by CMP's enricher before it is published
    to the AI agent. Attributes given to ``POST /v1/sessions/{id}/start`` need not be repeated: the
    gateway takes them from the session; a value sent here wins for this request."""

    session_id: str = SessionId
    message: str = Field(..., description="The customer's text to inspect")
    message_id: str | None = Field(
        None, max_length=200, description="CMP's message id; a repeat returns the cached decision"
    )
    customer_id: str | None = Field(
        None, max_length=200, description="CMP's customer id; stored only as a keyed hash"
    )
    ip: str | None = Field(None, max_length=64, description="Customer's IP as seen by CMP")
    device_id: str | None = Field(None, max_length=200)
    channel: Channel | None = None
    user_agent: str | None = Field(
        None, max_length=500, description="Customer's browser user agent (web channel only)"
    )
    endpoint: str = Field("chat", max_length=100, description="Logical endpoint, used to select policies")
    metadata: dict[str, Any] = Field(default_factory=dict)


IdentifierType = Literal["email", "phone", "booking_ref", "ticket", "aeroplan"]


class OutboundRequest(BaseModel):
    """Body of POST /v1/inspect/outbound: an AI reply, checked by CMP's processor before delivery."""

    session_id: str = SessionId
    reply: str = Field(..., description="The AI's reply, before delivery")
    message_id: str | None = Field(None, max_length=200)
    customer_id: str | None = Field(None, max_length=200)
    ip: str | None = Field(None, max_length=64)
    device_id: str | None = Field(None, max_length=200)
    channel: Channel | None = None
    endpoint: str = Field("chat", max_length=100)
    # The data this customer may see. Usually omitted: the gateway then uses the session's scope —
    # identifiers from the identity verification plus the ones the customer typed. Send a list to
    # override it for this reply; send {} to allow no identifiers at all.
    allowed_identifiers: dict[IdentifierType, list[str]] | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class SessionStart(BaseModel):
    """Body of POST /v1/sessions/{id}/start (CMP's start_chat)."""

    channel: Channel | None = None
    customer_id: str | None = Field(None, max_length=200)
    ip: str | None = Field(None, max_length=64)
    device_id: str | None = Field(None, max_length=200)
    user_agent: str | None = Field(None, max_length=500)


class SessionIdentity(BaseModel):
    """Body of POST /v1/sessions/{id}/identity (CMP's IDV result)."""

    verified: bool
    customer_id: str | None = Field(None, max_length=200)
    identifiers: dict[IdentifierType, list[str]] = Field(
        default_factory=dict,
        description="The verified customer's own booking refs, emails, phones, tickets, Aeroplan numbers",
    )
