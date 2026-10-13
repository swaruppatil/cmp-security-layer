-- CMP refactor: no tenants, the CMP session (Amazon Connect contact id) as the backbone.
--
-- * The gateway protects one product, so the tenants table and every tenant_id column go. API keys
--   are caller identities (CMP's enricher, its processor, test tools), told apart by name and scopes.
-- * Policies are chosen by channel × session state × endpoint instead of tenant × endpoint.
--   Tenant-specific policies are retired (kept, inactive, with their history).
-- * "session" becomes an entity type: sessions get strikes and (never permanent) bans.
-- * The audit trail records the session id, CMP's message id, the session state and the action CMP
--   was told to take.

-- the dashboard view reads tenant columns: rebuilt at the end
DROP VIEW IF EXISTS security_events_view;

-- ---------------------------------------------------------------- API keys = callers
ALTER TABLE api_keys DROP COLUMN tenant_id;
ALTER TABLE api_keys ALTER COLUMN scopes SET DEFAULT ARRAY['inspect', 'outbound'];
-- keys made before the "outbound" scope existed could call /v1/inspect/outbound with "inspect"
UPDATE api_keys SET scopes = array_append(scopes, 'outbound')
 WHERE 'inspect' = ANY(scopes) AND NOT 'outbound' = ANY(scopes);

-- ---------------------------------------------------------------- policies
UPDATE policies SET active = false, updated_at = now() WHERE tenant_id IS NOT NULL AND active;
DROP INDEX IF EXISTS policies_scope_idx;
DROP INDEX IF EXISTS policies_tenant_idx;
ALTER TABLE policies DROP COLUMN tenant_id;
ALTER TABLE policies ADD COLUMN channel text CHECK (channel IS NULL OR length(channel) BETWEEN 1 AND 50);
ALTER TABLE policies ADD COLUMN session_state text CHECK (session_state IN ('anonymous', 'verified'));
CREATE UNIQUE INDEX policies_scope_idx
    ON policies (COALESCE(channel, '*'), COALESCE(session_state, '*'), endpoint_pattern) WHERE active;
CREATE INDEX policies_active_idx ON policies (active);

-- ---------------------------------------------------------------- bans and strikes
ALTER TABLE bans DROP COLUMN tenant_id;
ALTER TABLE bans DROP CONSTRAINT IF EXISTS bans_entity_type_check;
ALTER TABLE bans ADD CONSTRAINT bans_entity_type_check
    CHECK (entity_type IN ('ip', 'cidr', 'user', 'device', 'session', 'api_key'));

ALTER TABLE strikes DROP COLUMN tenant_id;
ALTER TABLE strikes DROP CONSTRAINT IF EXISTS strikes_entity_type_check;
ALTER TABLE strikes ADD CONSTRAINT strikes_entity_type_check
    CHECK (entity_type IN ('ip', 'user', 'device', 'session'));

-- ---------------------------------------------------------------- canaries
ALTER TABLE canaries DROP COLUMN tenant_id;

-- ---------------------------------------------------------------- audit trail
ALTER TABLE security_events DROP COLUMN tenant_id;
ALTER TABLE security_events RENAME COLUMN conversation_id TO session_id;
ALTER TABLE security_events ADD COLUMN message_id text;
ALTER TABLE security_events ADD COLUMN session_state text;
ALTER TABLE security_events ADD COLUMN cmp_action text;
DROP INDEX IF EXISTS security_events_user_idx;
DROP INDEX IF EXISTS security_events_conv_idx;
CREATE INDEX security_events_user_idx ON security_events (user_id, ts DESC) WHERE user_id IS NOT NULL;
CREATE INDEX security_events_session_idx ON security_events (session_id, ts) WHERE session_id IS NOT NULL;
CREATE INDEX security_events_channel_idx ON security_events (channel, ts DESC);

DROP TABLE tenants;

-- ---------------------------------------------------------------- dashboard view (005, without tenants)
CREATE VIEW security_events_view AS
SELECT
    e.id,
    e.ts,
    e.request_id,
    e.api_key_id,
    e.mode,
    e.endpoint,
    e.action,
    e.enforced_action,
    (e.action <> e.enforced_action)                      AS monitor_only,
    e.cmp_action,
    e.risk,
    array_to_string(e.reasons, ', ')                     AS reasons,
    e.reasons                                            AS reason_list,
    e.redacted_excerpt                                   AS message,
    e.text_chars,
    e.text_hash,
    e.session_id,
    e.message_id,
    e.session_state,
    e.channel,
    e.user_id,
    e.ip,
    e.device_id,
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
    rdata.c->'detail'->>'scope'                                        AS reply_scope,
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
LEFT JOIN LATERAL (SELECT x.value AS c FROM jsonb_array_elements(e.checks) x WHERE x.value->>'name' = 'ml' LIMIT 1) ml ON true
LEFT JOIN LATERAL (SELECT x.value AS c FROM jsonb_array_elements(e.checks) x WHERE x.value->>'name' = 'rules' LIMIT 1) rules ON true
LEFT JOIN LATERAL (SELECT x.value AS c FROM jsonb_array_elements(e.checks) x WHERE x.value->>'name' = 'bot' LIMIT 1) bot ON true
LEFT JOIN LATERAL (SELECT x.value AS c FROM jsonb_array_elements(e.checks) x WHERE x.value->>'name' = 'admission' LIMIT 1) adm ON true
LEFT JOIN LATERAL (SELECT x.value AS c FROM jsonb_array_elements(e.checks) x WHERE x.value->>'name' = 'sensitive' LIMIT 1) sens ON true
LEFT JOIN LATERAL (SELECT x.value AS c FROM jsonb_array_elements(e.checks) x WHERE x.value->>'name' = 'reply_data' LIMIT 1) rdata ON true
LEFT JOIN LATERAL (SELECT x.value AS c FROM jsonb_array_elements(e.checks) x WHERE x.value->>'name' = 'canary' LIMIT 1) can ON true
LEFT JOIN LATERAL (SELECT x.value AS c FROM jsonb_array_elements(e.checks) x WHERE x.value->>'name' = 'reply_links' LIMIT 1) links ON true
LEFT JOIN LATERAL (SELECT x.value AS c FROM jsonb_array_elements(e.checks) x WHERE x.value->>'name' = 'conversation' LIMIT 1) conv ON true
LEFT JOIN LATERAL (
    SELECT d.chk->>'name' AS name FROM jsonb_array_elements(e.checks) WITH ORDINALITY d(chk, n)
     WHERE d.chk->>'action' = e.action ORDER BY d.n LIMIT 1
) decider ON true;

-- One row per session: what happened in each CMP contact (the "sessions" dashboard panel).
CREATE VIEW security_sessions_view AS
SELECT session_id,
       min(ts)                                                     AS started,
       max(ts)                                                     AS last_seen,
       count(*) FILTER (WHERE mode = 'inspect')                    AS messages,
       count(*) FILTER (WHERE mode = 'outbound')                   AS replies,
       count(*) FILTER (WHERE action = 'block')                    AS blocked,
       count(*) FILTER (WHERE action = 'restrict')                 AS restricted,
       count(*) FILTER (WHERE action = 'throttle')                 AS throttled,
       max(risk)                                                   AS max_risk,
       (array_agg(channel ORDER BY ts DESC) FILTER (WHERE channel IS NOT NULL))[1]             AS channel,
       (array_agg(session_state ORDER BY ts DESC) FILTER (WHERE session_state IS NOT NULL))[1] AS session_state,
       (array_agg(user_id ORDER BY ts DESC) FILTER (WHERE user_id IS NOT NULL))[1]             AS user_id,
       (array_agg(cmp_action ORDER BY ts DESC) FILTER (WHERE cmp_action IS NOT NULL))[1]       AS last_cmp_action,
       (SELECT string_agg(DISTINCT r, ', ') FROM security_events x, unnest(x.reasons) r
         WHERE x.session_id = e.session_id)                                                    AS reasons
  FROM security_events e
 WHERE session_id IS NOT NULL
 GROUP BY session_id;

GRANT SELECT ON security_events_view, security_sessions_view TO dashboard_reader;
