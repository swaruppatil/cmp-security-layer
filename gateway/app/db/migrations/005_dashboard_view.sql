-- Stage 9b: a readable view of the audit trail for dashboards, and a read-only role for Grafana.
--
-- security_events keeps every check's detail as JSON. This view pulls the fields people look at when
-- testing or investigating into plain columns: the (redacted) message, action, reasons, which check
-- decided, the ML score and its parts, the rules that fired, the bot tier, sensitive data found,
-- conversation state, outbound findings, timings and versions. No raw text exists to expose: the
-- message column is the redacted excerpt.

CREATE OR REPLACE VIEW security_events_view AS
SELECT
    e.id,
    e.ts,
    e.request_id,
    e.tenant_id,
    t.name                                               AS tenant,
    e.mode,
    e.endpoint,
    e.action,
    e.enforced_action,
    (e.action <> e.enforced_action)                      AS monitor_only,
    e.risk,
    array_to_string(e.reasons, ', ')                     AS reasons,
    e.reasons                                            AS reason_list,
    e.redacted_excerpt                                   AS message,
    e.text_chars,
    e.text_hash,
    e.user_id,
    e.ip,
    e.device_id,
    e.conversation_id,
    e.channel,
    COALESCE(decider.name, CASE WHEN e.action = 'allow' THEN '-' ELSE 'policy' END) AS decided_by,
    jsonb_array_length(e.checks)                         AS checks_run,
    -- ML
    (ml.c->'detail'->>'score')::real                                   AS ml_score,
    (ml.c->'detail'->'components'->>'ngram')::real                     AS ml_ngram,
    (ml.c->'detail'->'components'->>'embedding')::real                 AS ml_embedding,
    (ml.c->'detail'->'components'->>'attack_similarity')::real         AS ml_attack_similarity,
    (ml.c->'detail'->'components'->>'benign_similarity')::real         AS ml_benign_similarity,
    ml.c->'detail'->'components'->>'nearest_attack_family'             AS ml_nearest_family,
    (ml.c->'detail'->'thresholds'->>'restrict')::real                  AS ml_restrict_at,
    (ml.c->'detail'->'thresholds'->>'block')::real                     AS ml_block_at,
    ml.c->'detail'->'thresholds'->>'source'                            AS ml_threshold_source,
    COALESCE(ml.c->'detail'->>'skipped', ml.c->'detail'->>'unavailable') AS ml_note,
    (ml.c->>'duration_us')::real / 1000                                AS ml_ms,
    -- rules
    (SELECT string_agg(DISTINCT f->>'id', ', ') FROM jsonb_array_elements(rules.c->'detail'->'findings') f) AS rules_fired,
    (SELECT max(f->>'severity') FROM jsonb_array_elements(rules.c->'detail'->'findings') f)                 AS rules_max_severity,
    (rules.c->>'duration_us')::real / 1000                             AS rules_ms,
    -- bot
    (bot.c->'detail'->>'score')::real                                  AS bot_score,
    bot.c->'detail'->>'tier'                                           AS bot_tier,
    (SELECT string_agg(s, ', ') FROM jsonb_array_elements_text(bot.c->'detail'->'signals') s) AS bot_signals,
    (bot.c->'detail'->>'cost')::real                                   AS bot_cost,
    -- admission
    adm.c->'detail'->>'limited_by'                                     AS rate_limited_by,
    (SELECT max(v::real) FROM jsonb_each_text(adm.c->'detail'->'reputation') r(k, v)) AS reputation,
    -- sensitive data (inbound check, or the reply check for outbound)
    COALESCE(
        (SELECT string_agg(s, ', ') FROM jsonb_array_elements_text(sens.c->'detail'->'types') s),
        (SELECT string_agg(s, ', ') FROM jsonb_array_elements_text(rdata.c->'detail'->'types') s)
    )                                                                  AS sensitive_found,
    COALESCE(
        (SELECT string_agg(s, ', ') FROM jsonb_array_elements_text(sens.c->'detail'->'redacted') s),
        (SELECT string_agg(s, ', ') FROM jsonb_array_elements_text(rdata.c->'detail'->'redacted') s)
    )                                                                  AS redacted,
    -- outbound
    (SELECT string_agg(k || ' ×' || v, ', ') FROM jsonb_each_text(rdata.c->'detail'->'out_of_scope') o(k, v)) AS out_of_scope,
    (can.c->'detail'->>'known_token')::boolean                        AS canary_known,
    (links.c->'detail'->>'images_removed')::int                        AS images_removed,
    (links.c->'detail'->>'links_removed')::int                         AS links_removed,
    -- conversation
    (conv.c->'detail'->>'turn')::int                                   AS conv_turn,
    (conv.c->'detail'->>'blocks')::int                                 AS conv_blocks,
    (conv.c->'detail'->'accumulated'->>'after')::real                  AS conv_accumulated,
    (SELECT string_agg(s, ', ') FROM jsonb_array_elements_text(conv.c->'detail'->'signals') s) AS conv_signals,
    (conv.c->'detail'->>'retry_similarity')::real                      AS conv_retry_similarity,
    (conv.c->'detail'->>'drift')::real                                 AS conv_drift,
    -- versions, timing, labels
    e.latency_ms,
    e.policy_id,
    e.policy_version,
    e.model_version,
    e.ruleset_version,
    e.label,
    e.label_note,
    e.labeled_at
FROM security_events e
LEFT JOIN tenants t ON t.id = e.tenant_id
LEFT JOIN LATERAL (SELECT x.value AS c FROM jsonb_array_elements(e.checks) x WHERE x.value->>'name' = 'ml' LIMIT 1) ml ON true
LEFT JOIN LATERAL (SELECT x.value AS c FROM jsonb_array_elements(e.checks) x WHERE x.value->>'name' = 'rules' LIMIT 1) rules ON true
LEFT JOIN LATERAL (SELECT x.value AS c FROM jsonb_array_elements(e.checks) x WHERE x.value->>'name' = 'bot' LIMIT 1) bot ON true
LEFT JOIN LATERAL (SELECT x.value AS c FROM jsonb_array_elements(e.checks) x WHERE x.value->>'name' = 'admission' LIMIT 1) adm ON true
LEFT JOIN LATERAL (SELECT x.value AS c FROM jsonb_array_elements(e.checks) x WHERE x.value->>'name' = 'sensitive' LIMIT 1) sens ON true
LEFT JOIN LATERAL (SELECT x.value AS c FROM jsonb_array_elements(e.checks) x WHERE x.value->>'name' = 'reply_data' LIMIT 1) rdata ON true
LEFT JOIN LATERAL (SELECT x.value AS c FROM jsonb_array_elements(e.checks) x WHERE x.value->>'name' = 'canary' LIMIT 1) can ON true
LEFT JOIN LATERAL (SELECT x.value AS c FROM jsonb_array_elements(e.checks) x WHERE x.value->>'name' = 'reply_links' LIMIT 1) links ON true
LEFT JOIN LATERAL (SELECT x.value AS c FROM jsonb_array_elements(e.checks) x WHERE x.value->>'name' = 'conversation' LIMIT 1) conv ON true
-- "decided by": the first check that asked for the action the decision ended with.
LEFT JOIN LATERAL (
    SELECT d.chk->>'name' AS name FROM jsonb_array_elements(e.checks) WITH ORDINALITY d(chk, n)
     WHERE d.chk->>'action' = e.action ORDER BY d.n LIMIT 1
) decider ON true;

-- One row per check of every event (the drill-down panel).
CREATE OR REPLACE VIEW security_event_checks_view AS
SELECT e.id AS event_id, e.ts, x.n AS position, x.c->>'name' AS check_name, x.c->>'action' AS action,
       x.c->>'reason' AS reason, (x.c->>'score')::real AS score, (x.c->>'duration_us')::real / 1000 AS duration_ms,
       (x.c->>'strike')::boolean AS strike, x.c->>'evidence' AS evidence, x.c->'detail' AS detail
  FROM security_events e, jsonb_array_elements(e.checks) WITH ORDINALITY x(c, n);

-- Read-only role for dashboards. It can read the audit trail, bans, policies — never
-- API keys or canary hashes. Created without login; the gateway enables login with
-- DASHBOARD_DB_PASSWORD at startup (so no password lives in this file).
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'dashboard_reader') THEN
        CREATE ROLE dashboard_reader NOLOGIN;
    END IF;
END $$;
GRANT USAGE ON SCHEMA public TO dashboard_reader;
GRANT SELECT ON security_events, security_events_view, security_event_checks_view, bans, strikes,
                policies, policy_versions TO dashboard_reader;
GRANT SELECT (id, name, status, created_at) ON tenants TO dashboard_reader;
