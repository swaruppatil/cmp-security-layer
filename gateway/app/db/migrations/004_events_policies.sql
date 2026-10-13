-- Stage 9: the audit trail (security_events) and versioned policies.

-- One row per decision (inspect, proxy, outbound, proxied replies), written by the audit worker from
-- the Redis stream. Never the raw text: a hash of it and an excerpt with every sensitive value redacted.
CREATE TABLE security_events (
    id               uuid PRIMARY KEY,
    ts               timestamptz NOT NULL,
    request_id       text NOT NULL,
    tenant_id        uuid REFERENCES tenants(id) ON DELETE CASCADE,
    api_key_id       uuid,
    mode             text NOT NULL CHECK (mode IN ('inspect', 'proxy', 'outbound', 'proxy-outbound')),
    endpoint         text NOT NULL,
    action           text NOT NULL,
    enforced_action  text NOT NULL,           -- what the caller was told (differs in monitor mode)
    risk             real NOT NULL,
    reasons          text[] NOT NULL DEFAULT '{}',
    checks           jsonb NOT NULL DEFAULT '[]'::jsonb,
    user_id          text,
    ip               text,
    device_id        text,
    conversation_id  text,
    channel          text,
    policy_id        uuid,
    policy_version   integer,
    model_version    text,
    ruleset_version  text,
    latency_ms       real NOT NULL,
    text_hash        text,
    text_chars       integer,
    redacted_excerpt text,
    -- Accuracy tracking: an admin marks an event as a false / true positive.
    label            text CHECK (label IN ('false_positive', 'true_positive')),
    label_note       text,
    labeled_by       text,
    labeled_at       timestamptz
);
CREATE INDEX security_events_ts_idx ON security_events (ts DESC);
CREATE INDEX security_events_tenant_ts_idx ON security_events (tenant_id, ts DESC);
CREATE INDEX security_events_action_idx ON security_events (action, ts DESC);
CREATE INDEX security_events_user_idx ON security_events (tenant_id, user_id, ts DESC) WHERE user_id IS NOT NULL;
CREATE INDEX security_events_conv_idx ON security_events (tenant_id, conversation_id) WHERE conversation_id IS NOT NULL;
CREATE INDEX security_events_label_idx ON security_events (label, ts DESC) WHERE label IS NOT NULL;

-- Policies (table from 001) get the shape the policy engine uses:
--   mode        enforce | monitor (monitor: decide and record, but always tell the caller "allow")
--   actions     action overrides, e.g. {"restrict": "block"} on a sensitive endpoint
--   thresholds  {"ml_block_at": 0.95, "ml_restrict_at": 0.8} — override the model's thresholds
ALTER TABLE policies ADD COLUMN mode text NOT NULL DEFAULT 'enforce' CHECK (mode IN ('enforce', 'monitor'));
ALTER TABLE policies ADD COLUMN description text NOT NULL DEFAULT '';
UPDATE policies SET thresholds = '{}'::jsonb, actions = '{}'::jsonb
 WHERE tenant_id IS NULL AND name = 'global-default';
CREATE UNIQUE INDEX policies_scope_idx ON policies (COALESCE(tenant_id, '00000000-0000-0000-0000-000000000000'::uuid),
                                                    endpoint_pattern) WHERE active;

-- Every version of every policy, kept forever (decisions reference policy_id + version).
CREATE TABLE policy_versions (
    policy_id   uuid NOT NULL REFERENCES policies(id) ON DELETE CASCADE,
    version     integer NOT NULL,
    body        jsonb NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    created_by  text NOT NULL,
    PRIMARY KEY (policy_id, version)
);
INSERT INTO policy_versions (policy_id, version, body, created_by)
SELECT id, version, jsonb_build_object('name', name, 'endpoint_pattern', endpoint_pattern, 'sensitive', sensitive,
                                       'mode', mode, 'thresholds', thresholds, 'actions', actions,
                                       'description', description), 'migration'
  FROM policies;
