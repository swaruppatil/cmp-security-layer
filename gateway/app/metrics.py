"""Prometheus metrics (``GET /metrics``, admin key required — Prometheus sends it as a bearer token).

| metric                                   | labels           | meaning                                        |
|------------------------------------------|------------------|------------------------------------------------|
| gateway_decisions_total                  | mode, action     | decisions, by what the caller was told         |
| gateway_decision_reasons_total           | mode, reason     | why requests were blocked / restricted / throttled |
| gateway_monitor_only_total               | action           | monitor-mode policies: what *would* have happened |
| gateway_pipeline_seconds                 | mode             | time spent in the checks (histogram)           |
| gateway_check_seconds                    | check            | time per check (histogram)                     |
| gateway_degraded_total                   | component        | a dependency was unavailable and its check was skipped / fell back |
| gateway_active_bans                      |                  | bans in the local index                        |
| gateway_audit_events_total               | outcome          | queued to the stream / written directly / dropped |
| gateway_audit_writes_total               | outcome          | worker: written / malformed / error            |
| gateway_audit_pending                    |                  | stream entries delivered but not yet written   |
| gateway_event_labels_total               | label            | events an admin marked false / true positive   |
"""

from __future__ import annotations

from prometheus_client import Counter, Gauge, Histogram

LATENCY_BUCKETS = (0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0)

DECISIONS = Counter("gateway_decisions_total", "Decisions by mode and enforced action", ["mode", "action"])
REASONS = Counter("gateway_decision_reasons_total", "Decision reasons", ["mode", "reason"])
MONITOR_ONLY = Counter(
    "gateway_monitor_only_total", "Actions a monitor-mode policy did not enforce", ["action"]
)
PIPELINE_SECONDS = Histogram(
    "gateway_pipeline_seconds", "Time in the checks", ["mode"], buckets=LATENCY_BUCKETS
)
CHECK_SECONDS = Histogram("gateway_check_seconds", "Time per check", ["check"], buckets=LATENCY_BUCKETS)
DEGRADED = Counter(
    "gateway_degraded_total", "Dependency unavailable; check skipped or fell back", ["component"]
)
ACTIVE_BANS = Gauge("gateway_active_bans", "Bans in the local index")
AUDIT_EVENTS = Counter("gateway_audit_events_total", "Audit events by publish outcome", ["outcome"])
AUDIT_WRITES = Counter("gateway_audit_writes_total", "Audit worker outcomes", ["outcome"])
AUDIT_PENDING = Gauge("gateway_audit_pending", "Audit entries delivered but not yet written")
LABELS = Counter("gateway_event_labels_total", "Events labelled by an admin", ["label"])


def record(mode: str, decision: object) -> None:
    """Count one decision. ``decision`` is a Decision (typed loosely to avoid an import cycle)."""
    action = decision.action.value  # type: ignore[attr-defined]
    DECISIONS.labels(mode=mode, action=action).inc()
    for reason in decision.reasons:  # type: ignore[attr-defined]
        REASONS.labels(mode=mode, reason=reason).inc()
    would = decision.would_have  # type: ignore[attr-defined]
    if would is not None:
        MONITOR_ONLY.labels(action=would.value).inc()
    PIPELINE_SECONDS.labels(mode=mode).observe(decision.latency_ms / 1000)  # type: ignore[attr-defined]
    for c in decision.checks:  # type: ignore[attr-defined]
        CHECK_SECONDS.labels(check=c.name).observe(c.duration_us / 1_000_000)
        d = c.detail
        if d.get("unavailable") or d.get("degraded"):
            DEGRADED.labels(component=c.name).inc()
