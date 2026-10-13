"""Generate the Grafana dashboard (dashboards/gateway.json).

    python3 observability/grafana/build_dashboard.py            # write the JSON
    python3 observability/grafana/build_dashboard.py --queries  # print every SQL query (for checking)

Two data sources:
* **Prometheus** (uid ``prometheus``) — live counters and latency histograms (top rows).
* **PostgreSQL** (uid ``security-db``, read-only role ``dashboard_reader``) — the audit trail, one
  row per decision, through the views ``security_events_view``, ``security_event_checks_view`` and
  ``security_sessions_view`` (migrations 005 / 006). This is where per-message details come from: the
  redacted message, scores, reasons, which check decided, rule ids, bot tier, conversation state,
  outbound findings, the session and the action CMP was told to take.

Dashboard filters (channel, session state, mode, action, CMP action, reason, session id, customer / IP,
text search, event id) apply to every SQL panel. All values go into SQL through Grafana's
``sqlstring`` format (quoted and escaped), and the role can only read the audit trail, bans and
policies.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

OUT = Path(__file__).parent / "dashboards" / "gateway.json"
PROM = {"type": "prometheus", "uid": "prometheus"}
SQL = {"type": "grafana-postgresql-datasource", "uid": "security-db"}
ACTION_COLOURS = {"allow": "green", "restrict": "orange", "throttle": "purple", "block": "red"}


def F(a: str = "") -> str:
    """The dashboard filters as a SQL condition, for the view aliased ``a``."""
    p = f"{a}." if a else ""
    return (
        f"$__timeFilter({p}ts)"
        f" AND (${{channel:sqlstring}} = 'all' OR {p}channel = ${{channel:sqlstring}})"
        f" AND (${{state:sqlstring}} = 'all' OR {p}session_state = ${{state:sqlstring}})"
        f" AND (${{mode:sqlstring}} = 'all' OR {p}mode = ${{mode:sqlstring}})"
        f" AND (${{action:sqlstring}} = 'all' OR {p}action = ${{action:sqlstring}})"
        f" AND (${{cmp_action:sqlstring}} = 'all' OR {p}cmp_action = ${{cmp_action:sqlstring}})"
        f" AND (${{session:sqlstring}} = '' OR {p}session_id = ${{session:sqlstring}})"
        f" AND (${{reason:sqlstring}} = 'all' OR ${{reason:sqlstring}} = ANY({p}reason_list))"
        f" AND (${{user:sqlstring}} = '' OR {p}user_id = ${{user:sqlstring}} OR {p}ip = ${{user:sqlstring}})"
        f" AND (${{search:sqlstring}} = '' OR {p}message ILIKE '%' || ${{search:sqlstring}} || '%')"
    )


_id = 0
_y = 0
panels: list[dict[str, Any]] = []


def nid() -> int:
    global _id
    _id += 1
    return _id


def row(title: str) -> None:
    global _y
    panels.append({"id": nid(), "type": "row", "title": title, "collapsed": False,
                   "gridPos": {"x": 0, "y": _y, "w": 24, "h": 1}, "panels": []})
    _y += 1


def place(p: dict[str, Any], x: int, w: int, h: int, newline: bool) -> dict[str, Any]:
    global _y
    p["gridPos"] = {"x": x, "y": _y, "w": w, "h": h}
    if newline:
        _y += h
    panels.append(p)
    return p


def prom_ts(title: str, exprs: list[tuple[str, str]], unit: str = "short", stack: bool = False,
            desc: str = "") -> dict[str, Any]:
    return {"id": nid(), "type": "timeseries", "title": title, "description": desc, "datasource": PROM,
            "fieldConfig": {"defaults": {"unit": unit, "custom": {"stacking": {"mode": "normal" if stack else "none"}}},
                            "overrides": []},
            "targets": [{"refId": chr(65 + i), "datasource": PROM, "expr": e, "legendFormat": l}
                        for i, (e, l) in enumerate(exprs)]}


def prom_stat(title: str, expr: str, unit: str = "short", desc: str = "") -> dict[str, Any]:
    return {"id": nid(), "type": "stat", "title": title, "description": desc, "datasource": PROM,
            "fieldConfig": {"defaults": {"unit": unit}, "overrides": []},
            "targets": [{"refId": "A", "datasource": PROM, "expr": f"({expr}) or vector(0)"}]}


def sql_target(sql: str, fmt: str = "table") -> dict[str, Any]:
    return {"refId": "A", "datasource": SQL, "rawSql": " ".join(sql.split()), "format": fmt, "rawQuery": True,
            "editorMode": "code"}


def action_override(field: str = "action") -> dict[str, Any]:
    return {"matcher": {"id": "byName", "options": field}, "properties": [
        {"id": "custom.cellOptions", "value": {"type": "color-background"}},
        {"id": "mappings", "value": [{"type": "value", "options": {
            k: {"color": v, "index": i} for i, (k, v) in enumerate(ACTION_COLOURS.items())}}]},
    ]}


def score_override(field: str, restrict: float = 0.66, block: float = 0.969) -> dict[str, Any]:
    return {"matcher": {"id": "byName", "options": field}, "properties": [
        {"id": "custom.cellOptions", "value": {"type": "color-background", "mode": "basic"}},
        {"id": "thresholds", "value": {"mode": "absolute", "steps": [
            {"color": "transparent", "value": None}, {"color": "orange", "value": restrict},
            {"color": "red", "value": block}]}},
    ]}


def width(field: str, px: int) -> dict[str, Any]:
    return {"matcher": {"id": "byName", "options": field}, "properties": [{"id": "custom.width", "value": px}]}


EVENT_PANEL_ID, CHECKS_PANEL_ID = 900, 901  # fixed ids, so links can open them full screen


def drill_link(field: str = "id") -> dict[str, Any]:
    base = "/d/cmp-security-gateway/cmp-security-gateway?${__url_time_range}&var-event_id=${__value.raw}"
    return {"matcher": {"id": "byName", "options": field}, "properties": [
        {"id": "links", "value": [
            {"title": "Every check of this event", "url": f"{base}&viewPanel={CHECKS_PANEL_ID}"},
            {"title": "Event summary", "url": f"{base}&viewPanel={EVENT_PANEL_ID}"},
        ]}]}


def table(title: str, sql: str, desc: str = "", overrides: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    return {"id": nid(), "type": "table", "title": title, "description": desc, "datasource": SQL,
            "fieldConfig": {"defaults": {"custom": {"filterable": True, "cellOptions": {"type": "auto"}}},
                            "overrides": overrides or []},
            "options": {"showHeader": True, "cellHeight": "sm", "footer": {"show": False}},
            "targets": [sql_target(sql)]}


def bars(title: str, sql: str, desc: str = "", horizontal: bool = True, stack: bool = False) -> dict[str, Any]:
    return {"id": nid(), "type": "barchart", "title": title, "description": desc, "datasource": SQL,
            "fieldConfig": {"defaults": {"custom": {"fillOpacity": 80}}, "overrides": []},
            "options": {"orientation": "horizontal" if horizontal else "vertical", "showValue": "auto",
                        "stacking": "normal" if stack else "none", "legend": {"showLegend": stack},
                        "xTickLabelRotation": 0},
            "targets": [sql_target(sql)]}


def sql_stat(title: str, sql: str, desc: str = "", unit: str = "short") -> dict[str, Any]:
    return {"id": nid(), "type": "stat", "title": title, "description": desc, "datasource": SQL,
            "fieldConfig": {"defaults": {"unit": unit}, "overrides": []},
            "options": {"reduceOptions": {"calcs": ["lastNotNull"], "fields": "", "values": False}},
            "targets": [sql_target(sql)]}


def sql_ts(title: str, sql: str, desc: str = "", stack: bool = True) -> dict[str, Any]:
    return {"id": nid(), "type": "timeseries", "title": title, "description": desc, "datasource": SQL,
            "fieldConfig": {"defaults": {"custom": {"stacking": {"mode": "normal" if stack else "none"},
                                                    "drawStyle": "bars", "fillOpacity": 70}}, "overrides": []},
            "targets": [sql_target(sql, "time_series")]}


V = "security_events_view"
# What a filter set to "All" stands for. Grafana inserts a custom "all" value as is — the :sqlstring
# format is NOT applied to it — so it must already be a quoted SQL string: the conditions then read
# ('all' = 'all' OR channel = 'all'), true for every row. (A bare all is a SQL syntax error.)
ALL = "'all'"
q = lambda p, mode: f'histogram_quantile({p}, sum by (le) (rate(gateway_pipeline_seconds_bucket{{mode="{mode}"}}[5m])))'  # noqa: E731

# ---------------------------------------------------------------- live metrics (Prometheus)
row("Live traffic (Prometheus, all channels)")
place(prom_stat("Decisions / s", "sum(rate(gateway_decisions_total[1m]))", "reqps"), 0, 6, 4, False)
place(prom_stat("Blocked / s", 'sum(rate(gateway_decisions_total{action="block"}[1m]))', "reqps"), 6, 6, 4, False)
place(prom_stat("Active bans", "sum(gateway_active_bans)"), 12, 6, 4, False)
place(prom_stat("False-positive reports (24 h)",
                'sum(increase(gateway_event_labels_total{label="false_positive"}[24h]))'), 18, 6, 4, True)
place(prom_ts("Decisions by action", [("sum by (action) (rate(gateway_decisions_total[1m]))", "{{action}}")],
              "reqps", True), 0, 12, 8, False)
place(prom_ts("Top reasons (blocked / restricted / throttled)",
              [("topk(10, sum by (reason) (rate(gateway_decision_reasons_total[5m])))", "{{reason}}")], "reqps"),
      12, 12, 8, True)
place(prom_ts("Pipeline latency (inspect)", [(q(0.5, "inspect"), "p50"), (q(0.95, "inspect"), "p95"),
                                             (q(0.99, "inspect"), "p99")], "s"), 0, 12, 8, False)
place(prom_ts("Check latency p95", [("histogram_quantile(0.95, sum by (le, check) "
                                     "(rate(gateway_check_seconds_bucket[5m])))", "{{check}}")], "s"),
      12, 12, 8, True)
place(prom_ts("Degraded dependencies (check skipped / fell back)",
              [("sum by (component) (rate(gateway_degraded_total[5m]))", "{{component}}")], "reqps"), 0, 8, 7, False)
place(prom_ts("Monitor-mode policies: would have enforced",
              [("sum by (action) (rate(gateway_monitor_only_total[5m]))", "{{action}}")], "reqps"), 8, 8, 7, False)
place(prom_ts("Audit trail", [("sum by (outcome) (rate(gateway_audit_events_total[5m]))", "published: {{outcome}}"),
                              ("sum by (outcome) (rate(gateway_audit_writes_total[5m]))", "worker: {{outcome}}"),
                              ("gateway_audit_pending", "pending")]), 16, 8, 7, True)

# ---------------------------------------------------------------- headline numbers for the filters (SQL)
row("Selection summary (audit trail — follows the filters above)")
place(sql_stat("Decisions", f"SELECT count(*) FROM {V} WHERE {F()}"), 0, 4, 4, False)
place(sql_stat("Flagged %", f"SELECT round(100.0 * count(*) FILTER (WHERE action <> 'allow') / NULLIF(count(*), 0), 1) "
                            f"FROM {V} WHERE {F()}", unit="percent"), 4, 4, 4, False)
place(sql_stat("Blocked", f"SELECT count(*) FROM {V} WHERE {F()} AND action = 'block'"), 8, 4, 4, False)
place(sql_stat("Distinct customers", f"SELECT count(DISTINCT user_id) FROM {V} WHERE {F()}"), 12, 4, 4, False)
place(sql_stat("Sessions (chats)", f"SELECT count(DISTINCT session_id) FROM {V} WHERE {F()}"), 16, 4, 4, False)
place(sql_stat("Median latency", f"SELECT percentile_cont(0.5) WITHIN GROUP (ORDER BY latency_ms) FROM {V} "
                                 f"WHERE {F()}", unit="ms"), 20, 4, 4, True)

# ---------------------------------------------------------------- message explorer
row("Message explorer")
place(table(
    "Recent decisions — message, decision and why",
    f"""SELECT ts AS "time", channel, mode, endpoint, message, action, cmp_action,
        CASE WHEN monitor_only THEN 'monitor (would block/restrict)' ELSE '' END AS policy,
        reasons, decided_by, round(risk::numeric, 3) AS risk, round(ml_score::numeric, 3) AS ml_score,
        rules_fired, bot_tier, sensitive_found, redacted, round(conv_accumulated::numeric, 2) AS conv_risk,
        round(latency_ms::numeric, 1) AS ms, session_id, session_state, user_id, ip, label, id
      FROM {V} WHERE {F()} ORDER BY ts DESC LIMIT 300""",
    "Every decision in the time range that matches the filters. The message is the stored redacted "
    "excerpt (sensitive values replaced). Click an id to see every check of that event below.",
    [action_override(), score_override("risk"), score_override("ml_score"), width("message", 380),
     width("time", 150), drill_link()]), 0, 24, 13, True)
place(table(
    "Why it was flagged — evidence per decision",
    f"""SELECT ts AS "time", message, action, reasons, decided_by,
        concat_ws(' | ',
          CASE WHEN rules_fired IS NOT NULL THEN 'rules: ' || rules_fired END,
          CASE WHEN ml_score IS NOT NULL THEN 'ml ' || round(ml_score::numeric, 3) || ' (restrict ≥ '
               || round(ml_restrict_at::numeric, 3) || ', block ≥ ' || round(ml_block_at::numeric, 3)
               || '; wording ' || round(ml_ngram::numeric, 2) || ', meaning ' || round(ml_embedding::numeric, 2)
               || ', looks like ' || coalesce(ml_nearest_family, '-') || ')' END,
          CASE WHEN ml_note IS NOT NULL THEN 'ml: ' || ml_note END,
          CASE WHEN bot_signals IS NOT NULL THEN 'bot ' || bot_tier || ': ' || bot_signals END,
          CASE WHEN rate_limited_by IS NOT NULL THEN 'rate limit hit: ' || rate_limited_by END,
          CASE WHEN reputation >= 60 THEN 'reputation ' || round(reputation::numeric) END,
          CASE WHEN conv_signals IS NOT NULL THEN 'conversation: ' || conv_signals || ' (risk '
               || round(conv_accumulated::numeric, 2) || ')' END,
          CASE WHEN out_of_scope IS NOT NULL THEN 'not this user''s data: ' || out_of_scope END,
          CASE WHEN decided_by = 'canary' THEN 'canary token in reply' END
        ) AS evidence, cmp_action, session_id, user_id, id
      FROM {V} WHERE {F()} AND action <> 'allow' ORDER BY ts DESC LIMIT 200""",
    "Only blocked / restricted / throttled decisions, with the evidence each check reported.",
    [action_override(), width("message", 320), width("evidence", 520), drill_link()]), 0, 24, 11, True)

# ---------------------------------------------------------------- CMP sessions
row("CMP sessions — what CMP was told to do")
place(bars("CMP actions",
           f"""SELECT coalesce(cmp_action, '-') AS cmp_action, count(*) AS decisions
               FROM {V} WHERE {F()} GROUP BY 1 ORDER BY 2 DESC""",
           "deliver · forward_without_tools · retry_later · refuse · handoff_to_agent · end_contact "
           "(customer messages); deliver · send_fallback (AI replies)."), 0, 8, 9, False)
place(bars("By channel and session state",
           f"""SELECT coalesce(channel, '-') || ' / ' || coalesce(session_state, '-') AS "channel / state",
                 count(*) FILTER (WHERE action = 'allow') AS allowed,
                 count(*) FILTER (WHERE action <> 'allow') AS flagged
               FROM {V} WHERE {F()} GROUP BY 1 ORDER BY 1""",
           "Verified = CMP reported a successful identity verification for the session.", stack=True),
      8, 8, 9, False)
place(table("Sessions",
            """SELECT session_id, channel, session_state, messages, replies, blocked, restricted, throttled,
                  round(max_risk::numeric, 3) AS max_risk, last_cmp_action, reasons, started, last_seen
                FROM security_sessions_view
                WHERE last_seen >= $__timeFrom() AND started <= $__timeTo()
                  AND (${channel:sqlstring} = 'all' OR channel = ${channel:sqlstring})
                  AND (${session:sqlstring} = '' OR session_id = ${session:sqlstring})
                ORDER BY last_seen DESC LIMIT 200""",
            "One row per CMP session (contact). Copy a session id into the 'Session id' filter to follow it."),
      16, 8, 9, True)
place(table(
    "Session timeline (set the 'Session id' filter)",
    f"""SELECT ts AS "time", CASE WHEN mode = 'outbound' THEN 'AI reply' ELSE 'customer' END AS who,
        message, action, cmp_action, reasons, decided_by, round(risk::numeric, 3) AS risk,
        round(conv_accumulated::numeric, 2) AS conv_risk, conv_signals, session_state, message_id, id
      FROM {V} WHERE {F()} AND ${{session:sqlstring}} <> '' ORDER BY ts""",
    "Every customer message and AI reply of one session, in order, with what CMP was told each time.",
    [action_override(), width("message", 380), drill_link()]), 0, 24, 10, True)

# ---------------------------------------------------------------- tuning
row("Tuning — near misses and possible false positives")
place(table(
    "Allowed, but close to the line (possible missed attacks)",
    f"""SELECT ts AS "time", message, round(ml_score::numeric, 3) AS ml_score,
        round(ml_restrict_at::numeric, 3) AS restrict_at, round(ml_ngram::numeric, 2) AS wording,
        round(ml_embedding::numeric, 2) AS meaning, ml_nearest_family AS looks_like, user_id, id
      FROM {V} WHERE {F()} AND action = 'allow' AND ml_score >= 0.3 ORDER BY ml_score DESC LIMIT 100""",
    "Messages the model scored 0.3 or more that were still allowed. Read them: real attacks here mean "
    "the restrict threshold could be lower.",
    [score_override("ml_score"), width("message", 360), drill_link()]), 0, 12, 10, False)
place(table(
    "Flagged by the model only (check for false positives)",
    f"""SELECT ts AS "time", message, action, round(ml_score::numeric, 3) AS ml_score,
        ml_nearest_family AS looks_like, label, user_id, id
      FROM {V} WHERE {F()} AND decided_by = 'ml' ORDER BY ts DESC LIMIT 100""",
    "No rule matched; the model alone decided. Normal customer messages here are false positives — "
    "label them with POST /admin/events/{id}/label.",
    [action_override(), score_override("ml_score"), width("message", 360), drill_link()]), 12, 12, 10, True)
place(bars(
    "ML score distribution",
    f"""SELECT to_char(floor(LEAST(ml_score, 0.999) * 10) / 10, 'FM0.0') || '–'
            || to_char(floor(LEAST(ml_score, 0.999) * 10) / 10 + 0.1, 'FM0.0') AS score,
        count(*) FILTER (WHERE action = 'allow') AS allowed,
        count(*) FILTER (WHERE action <> 'allow') AS flagged
      FROM {V} WHERE {F()} AND ml_score IS NOT NULL GROUP BY 1 ORDER BY 1""",
    "How the model's scores spread. A healthy model puts normal traffic at the left and attacks at the "
    "right; a bump in the middle is where tuning matters.", horizontal=False, stack=True), 0, 12, 8, False)
place(table(
    "ML threshold check",
    f"""SELECT model_version, ml_threshold_source AS source, round(min(ml_restrict_at)::numeric, 4) AS restrict_at,
        round(min(ml_block_at)::numeric, 4) AS block_at, count(*) AS scored,
        count(*) FILTER (WHERE ml_score >= ml_restrict_at AND ml_score < ml_block_at) AS restricted_band,
        count(*) FILTER (WHERE ml_score >= ml_block_at) AS block_band,
        round(avg(ml_ms)::numeric, 1) AS avg_ms, count(*) FILTER (WHERE ml_note = 'too_short') AS skipped_short
      FROM {V} WHERE {F()} AND (ml_score IS NOT NULL OR ml_note IS NOT NULL)
      GROUP BY 1, 2 ORDER BY 1 DESC""",
    "Which model and thresholds decided, how many messages fell in each band, average model time."),
      12, 12, 8, True)

# ---------------------------------------------------------------- drill-down
row("Event drill-down")
place(table(
    "Event ${event_id}",
    f"""SELECT ts AS "time", channel, mode, endpoint, message, action, enforced_action, cmp_action, reasons,
        decided_by, round(risk::numeric, 3) AS risk, policy_version, model_version, ruleset_version,
        round(latency_ms::numeric, 2) AS ms, session_id, message_id, session_state, user_id, ip, label, label_note
      FROM {V} WHERE id::text = ${{event_id:sqlstring}}""",
    "Paste an event id into the 'Event id' filter at the top, or click an id in any table.",
    [action_override(), width("message", 360)]), 0, 24, 4, True)["id"] = EVENT_PANEL_ID
place(table(
    "Every check of the event, in order",
    """SELECT position AS "#", check_name AS "check", action, reason, round(score::numeric, 4) AS score,
        round(duration_ms::numeric, 3) AS ms, strike, evidence, detail::text AS detail
      FROM security_event_checks_view WHERE event_id::text = ${event_id:sqlstring} ORDER BY position""",
    "What each check saw: its action, reason, score, time, whether it counted as a strike, and its full "
    "detail (rule ids, ML components and thresholds, bot features, conversation state, redactions).",
    [action_override(), width("detail", 900)]), 0, 24, 10, True)["id"] = CHECKS_PANEL_ID

# ---------------------------------------------------------------- detection breakdown
row("Detection breakdown")
place(bars("Which check decided (flagged requests)",
           f"SELECT decided_by, count(*) AS requests FROM {V} WHERE {F()} AND action <> 'allow' "
           f"GROUP BY 1 ORDER BY 2 DESC"), 0, 8, 8, False)
place(bars("Rules fired",
           f"""SELECT f->>'id' AS rule, count(*) AS times FROM {V} v
               JOIN security_event_checks_view k ON k.event_id = v.id AND k.check_name = 'rules',
               jsonb_array_elements(k.detail->'findings') f
               WHERE {F('v')} GROUP BY 1 ORDER BY 2 DESC LIMIT 15"""), 8, 8, 8, False)
place(bars("Model-flagged messages: nearest attack family",
           f"SELECT coalesce(ml_nearest_family, '-') AS family, count(*) AS messages FROM {V} "
           f"WHERE {F()} AND ml_score >= ml_restrict_at GROUP BY 1 ORDER BY 2 DESC"), 16, 8, 8, True)
place(bars("Sensitive data found / redacted",
           f"""SELECT t AS type, count(*) AS found,
                 count(*) FILTER (WHERE t = ANY(string_to_array(coalesce(redacted, ''), ', '))) AS redacted
               FROM {V}, unnest(string_to_array(sensitive_found, ', ')) t
               WHERE {F()} AND sensitive_found IS NOT NULL GROUP BY 1 ORDER BY 2 DESC""", stack=True),
      0, 8, 8, False)
place(table("Decisions by endpoint",
            f"""SELECT endpoint, count(*) AS total, count(*) FILTER (WHERE action = 'allow') AS allow,
                  count(*) FILTER (WHERE action = 'restrict') AS restrict,
                  count(*) FILTER (WHERE action = 'throttle') AS throttle,
                  count(*) FILTER (WHERE action = 'block') AS block,
                  round(percentile_cont(0.95) WITHIN GROUP (ORDER BY latency_ms)::numeric, 1) AS p95_ms
                FROM {V} WHERE {F()} GROUP BY 1 ORDER BY 2 DESC""",
            "Useful with policies: sensitive endpoints should show more restrictions/blocks."), 8, 8, 8, False)
place(table("Latency by check (from the audit trail)",
            f"""SELECT k.check_name AS "check", count(*) AS runs, round(avg(k.duration_ms)::numeric, 3) AS avg_ms,
                  round(percentile_cont(0.95) WITHIN GROUP (ORDER BY k.duration_ms)::numeric, 3) AS p95_ms,
                  round(max(k.duration_ms)::numeric, 1) AS max_ms
                FROM {V} v JOIN security_event_checks_view k ON k.event_id = v.id
                WHERE {F('v')} GROUP BY 1 ORDER BY 3 DESC"""), 16, 8, 8, True)

# ---------------------------------------------------------------- outbound
row("AI replies (outbound)")
place(bars("Reply decisions by reason",
           f"""SELECT coalesce(nullif(reasons, ''), 'delivered unchanged') AS reason, count(*) AS replies
               FROM {V} WHERE {F()} AND mode IN ('outbound', 'proxy-outbound') GROUP BY 1 ORDER BY 2 DESC"""),
      0, 8, 9, False)
place(table("Replies blocked or changed",
            f"""SELECT ts AS "time", mode, message AS reply, action, cmp_action, reasons, reply_scope,
                  out_of_scope, redacted, images_removed, links_removed, canary_known, session_id, id
                FROM {V} WHERE {F()} AND mode IN ('outbound', 'proxy-outbound')
                  AND (action <> 'allow' OR redacted IS NOT NULL OR coalesce(images_removed, 0) + coalesce(links_removed, 0) > 0)
                ORDER BY ts DESC LIMIT 100""",
            "Canary leaks, someone else's data, secrets, record dumps — and replies delivered with "
            "redactions or links removed.",
            [action_override(), width("reply", 360), drill_link()]), 8, 16, 9, True)

# ---------------------------------------------------------------- bots and conversations
row("Bots and conversations")
place(sql_ts("Bot tiers over time",
             f"""SELECT $__timeGroupAlias(ts, '1m'),
                   count(*) FILTER (WHERE bot_tier = 'suspect') AS suspect,
                   count(*) FILTER (WHERE bot_tier = 'likely') AS likely,
                   count(*) FILTER (WHERE bot_tier = 'bot') AS bot
                 FROM {V} WHERE {F()} AND bot_tier IS NOT NULL GROUP BY 1 ORDER BY 1"""), 0, 8, 9, False)
place(table("Most bot-like identities",
            f"""SELECT coalesce(user_id, session_id, ip) AS identity, count(*) AS requests,
                  round(max(bot_score)::numeric, 2) AS max_score,
                  (array_agg(bot_tier ORDER BY bot_score DESC NULLS LAST))[1] AS worst_tier,
                  string_agg(DISTINCT bot_signals, ' / ') AS signals,
                  count(*) FILTER (WHERE action = 'throttle') AS throttled, max(ts) AS last_seen
                FROM {V} WHERE {F()} AND bot_score > 0 GROUP BY 1 ORDER BY max_score DESC, requests DESC LIMIT 50""",
            "Signals: timer, fast_typing, repetition, campaign, rate, automation_ua, missing_ua, hosting_ip."),
      8, 16, 9, True)
place(table("Sessions at risk",
            f"""SELECT session_id, (array_agg(channel ORDER BY ts DESC))[1] AS channel,
                  count(*) FILTER (WHERE mode = 'inspect') AS turns,
                  count(*) FILTER (WHERE mode = 'outbound') AS replies,
                  count(*) FILTER (WHERE action = 'block') AS blocked,
                  round(max(conv_accumulated)::numeric, 2) AS max_risk,
                  string_agg(DISTINCT conv_signals, ' / ') AS signals,
                  bool_or('conversation_locked' = ANY(reason_list)) AS locked,
                  (array_agg(cmp_action ORDER BY ts DESC))[1] AS last_cmp_action,
                  (array_agg(message ORDER BY ts DESC))[1] AS last_message, max(ts) AS last_seen
                FROM {V} WHERE {F()} AND session_id IS NOT NULL GROUP BY 1
                HAVING count(*) FILTER (WHERE action <> 'allow') > 0 OR max(conv_accumulated) >= 0.5
                ORDER BY blocked DESC, max_risk DESC LIMIT 50""",
            "Sessions with blocked messages or replies, rising accumulated risk, or a lock. Paste a session id "
            "into the 'Session id' filter to see its timeline; reset one with DELETE /admin/sessions/{id}.",
            [width("last_message", 320)]), 0, 24, 9, True)

# ---------------------------------------------------------------- identities, bans, policies, accuracy
row("Identities, bans, policies, accuracy")
place(table("Most-refused identities",
            f"""SELECT coalesce(user_id, ip) AS "customer / IP",
                  count(DISTINCT session_id) AS sessions,
                  count(*) FILTER (WHERE action = 'block') AS blocked,
                  count(*) FILTER (WHERE action = 'throttle') AS throttled,
                  count(*) FILTER (WHERE action = 'restrict') AS restricted,
                  (array_agg(reasons ORDER BY ts DESC))[1] AS last_reasons, max(ts) AS last_seen
                FROM {V} WHERE {F()} AND action <> 'allow' AND coalesce(user_id, ip) IS NOT NULL
                GROUP BY 1 ORDER BY blocked DESC, throttled DESC LIMIT 50""",
            "Customers appear as cu_… (a keyed hash of CMP's customer id; ban or look one up with the raw id "
            "or the hash)."), 0, 12, 9, False)
place(table("Active bans",
            """SELECT b.created_at AS "time", b.entity_type AS type, b.value, b.reason, b.source,
                  CASE WHEN b.permanent THEN 'permanent' ELSE to_char(b.expires_at, 'YYYY-MM-DD HH24:MI:SS') END AS until,
                  b.evidence::text AS evidence
                FROM bans b
                WHERE b.revoked_at IS NULL AND (b.permanent OR b.expires_at > now())
                  AND (${session:sqlstring} = '' OR (b.entity_type = 'session' AND b.value = ${session:sqlstring}))
                ORDER BY b.created_at DESC LIMIT 100""",
            "Lift one with DELETE /admin/bans/{id}?clear_history=true."), 12, 12, 9, True)
place(table("Policies in force",
            """SELECT p.name, coalesce(p.channel, 'any') AS channel, coalesce(p.session_state, 'any') AS session_state,
                  p.endpoint_pattern AS endpoint, p.mode, p.actions::text AS action_overrides,
                  p.thresholds::text AS thresholds, p.version, p.updated_at
                FROM policies p
                WHERE p.active AND (${channel:sqlstring} = 'all' OR p.channel IS NULL OR p.channel = ${channel:sqlstring})
                ORDER BY p.channel NULLS FIRST, p.session_state NULLS FIRST, p.endpoint_pattern"""), 0, 12, 8, False)
place(table("Monitor mode — what would have been enforced",
            f"""SELECT ts AS "time", channel, endpoint, message, action AS would_have, reasons, policy_version,
                  session_id, id
                FROM {V} WHERE {F()} AND monitor_only ORDER BY ts DESC LIMIT 100""",
            "Decisions a monitor-mode policy recorded but did not enforce. Review before switching to enforce.",
            [action_override("would_have"), width("message", 320), drill_link()]), 12, 12, 8, True)
place(table("Accuracy labels",
            f"""SELECT labeled_at AS "time", label, label_note AS note, message, action, reasons, decided_by,
                  round(ml_score::numeric, 3) AS ml_score, id
                FROM {V} WHERE {F()} AND label IS NOT NULL ORDER BY labeled_at DESC LIMIT 100""",
            "Events an admin marked false_positive / true_positive (POST /admin/events/{id}/label).",
            [action_override(), width("message", 320), drill_link()]), 0, 16, 8, False)
place(sql_stat("Labelled precision",
               f"""SELECT round(100.0 * count(*) FILTER (WHERE label = 'true_positive')
                        / NULLIF(count(*) FILTER (WHERE label IS NOT NULL), 0), 1) FROM {V} WHERE {F()}""",
               "Of the flagged events someone labelled, the share that were real attacks.", "percent"),
      16, 8, 4, True)
place(table("Versions that decided",
            f"""SELECT coalesce(model_version, '-') AS model, coalesce(ruleset_version, '-') AS ruleset,
                  coalesce(policy_version::text, '-') AS policy_version, count(*) AS decisions,
                  min(ts) AS first_seen, max(ts) AS last_seen
                FROM {V} WHERE {F()} GROUP BY 1, 2, 3 ORDER BY last_seen DESC LIMIT 20"""), 16, 8, 4, True)

# ---------------------------------------------------------------- variables
def custom_var(name: str, label: str, options: list[str]) -> dict[str, Any]:
    return {"name": name, "label": label, "type": "custom", "query": ",".join(options), "includeAll": True,
            "allValue": ALL, "multi": False, "current": {"text": "All", "value": "$__all"},
            "options": [{"text": "All", "value": "$__all", "selected": True}]
            + [{"text": o, "value": o, "selected": False} for o in options]}


def query_var(name: str, label: str, sql: str) -> dict[str, Any]:
    return {"name": name, "label": label, "type": "query", "datasource": SQL, "query": sql, "definition": sql,
            "refresh": 2, "includeAll": True, "allValue": ALL, "multi": False, "sort": 1,
            "current": {"text": "All", "value": "$__all"}}


def text_var(name: str, label: str) -> dict[str, Any]:
    return {"name": name, "label": label, "type": "textbox", "query": "", "current": {"text": "", "value": ""}}


dashboard = {
    "uid": "cmp-security-gateway",
    "title": "CMP Security Gateway",
    "description": "Live metrics (Prometheus) and per-decision details from the audit trail (PostgreSQL).",
    "schemaVersion": 39,
    "version": 4,
    "refresh": "10s",
    "time": {"from": "now-1h", "to": "now"},
    "tags": ["cmp", "security"],
    "templating": {"list": [
        custom_var("channel", "Channel", ["web", "sms", "whatsapp", "apple", "facebook", "voice", "other"]),
        custom_var("state", "Session state", ["anonymous", "verified"]),
        custom_var("mode", "Mode", ["inspect", "proxy", "outbound", "proxy-outbound"]),
        custom_var("action", "Action", ["allow", "restrict", "throttle", "block"]),
        custom_var("cmp_action", "CMP action", ["deliver", "forward_without_tools", "retry_later", "refuse",
                                                "handoff_to_agent", "end_contact", "send_fallback"]),
        query_var("reason", "Reason", "SELECT DISTINCT unnest(reasons) FROM security_events "
                                      "WHERE ts > now() - interval '7 days' ORDER BY 1"),
        text_var("session", "Session id"),
        text_var("user", "Customer (cu_…) / IP"),
        text_var("search", "Message contains"),
        text_var("event_id", "Event id"),
    ]},
    "panels": panels,
}


def queries() -> list[tuple[str, str]]:
    out = []
    for p in panels:
        for t in p.get("targets", []):
            if "rawSql" in t:
                out.append((p["title"], t["rawSql"]))
    for v in dashboard["templating"]["list"]:
        if v["type"] == "query":
            out.append((f"variable {v['name']}", v["query"]))
    return out


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--queries", action="store_true")
    args = ap.parse_args()
    if args.queries:
        print(json.dumps(queries()))
    else:
        OUT.write_text(json.dumps(dashboard, indent=2) + "\n")
        sql_panels = sum(1 for p in panels if p.get("datasource") == SQL)
        print(f"wrote {OUT.name}: {len(panels)} panels ({sql_panels} SQL, "
              f"{sum(1 for p in panels if p.get('datasource') == PROM)} Prometheus)")
