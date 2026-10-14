"""Turn a decision into an audit event (one row of ``security_events``).

What is recorded: who (caller key, session, hashed customer, device, IP), where (mode, endpoint),
what was decided (action, what the caller was told, risk, reasons, every check with its score,
timing and detail),
which versions decided it (policy, model, ruleset) and how long it took.

What is never recorded: the raw text. Instead a hash of it (to find repeats) and, if
``STORE_REDACTED_EXCERPT`` is on, the first ``AUDIT_EXCERPT_CHARS`` characters with *every*
sensitive value redacted (emails, phones and booking references too — not only the inbound
redaction types).
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from app.config import Settings
from app.conversation.state import text_hash
from app.detectors import sensitive
from app.pipeline.context import RequestContext
from app.pipeline.models import Decision


def excerpt(text: str, limit: int) -> str:
    clipped = text[: limit * 2]  # redact before cutting, so a value is never cut in half and leaked
    return sensitive.redact(clipped, sensitive.find(clipped))[:limit]


def build_event(ctx: RequestContext, decision: Decision, settings: Settings) -> dict[str, Any]:
    by_name = {c.name: c for c in decision.checks}
    ml = by_name.get("ml")
    rules = by_name.get("rules")
    text = ctx.text or ""
    return {
        "id": str(uuid.uuid4()),
        "ts": datetime.now(UTC).isoformat(),
        "request_id": decision.request_id,
        "api_key_id": str(ctx.principal.api_key_id),
        "mode": ctx.mode,
        "endpoint": ctx.endpoint[:200],
        "action": (decision.would_have or decision.action).value,
        "enforced_action": decision.action.value,
        "risk": decision.risk,
        "reasons": decision.reasons,
        "checks": [
            {
                "name": c.name,
                "passed": c.passed,
                "action": c.action.value if c.action else None,
                "reason": c.reason,
                "score": c.score,
                "duration_us": c.duration_us,
                "strike": c.strike,
                "evidence": c.evidence,
                "detail": c.detail,
            }
            for c in decision.checks
        ],
        "user_id": ctx.user_id,
        "ip": ctx.ip,
        "device_id": ctx.device_id,
        "session_id": ctx.session_id,
        "message_id": ctx.message_id,
        "session_state": ctx.session_state,
        "cmp_action": decision.cmp_action,
        "channel": ctx.channel,
        "policy_id": decision.policy_id,
        "policy_version": decision.policy_version,
        "model_version": ml.detail.get("model_version") if ml else None,
        "ruleset_version": rules.detail.get("ruleset") if rules else None,
        "latency_ms": decision.latency_ms,
        "text_hash": text_hash(text) if text else None,
        "text_chars": len(text),
        "redacted_excerpt": excerpt(text, settings.audit_excerpt_chars),
        # Kafka publish outcome (None when the request carried no publish spec).
        "published": decision.published,
        "publish_topic": (decision.publish_detail or {}).get("topic") if decision.published else None,
        "publish_error": decision.publish_error if settings.store_redacted_excerpt and text else None,
    }
