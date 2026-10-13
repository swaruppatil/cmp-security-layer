-- Stage 3: bans, blacklists and strikes.
--
-- One table for every kind of ban; `source` says where it came from:
--   manual    — an admin decision
--   auto      — escalation after strikes (never permanent without deterministic evidence)
--   blacklist — imported lists (e.g. known-bad IP ranges)
-- tenant_id NULL means the ban applies to every tenant (used for IP / CIDR bans).

CREATE TABLE bans (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id    uuid REFERENCES tenants(id) ON DELETE CASCADE,
    entity_type  text NOT NULL CHECK (entity_type IN ('ip', 'cidr', 'user', 'device', 'api_key')),
    value        text NOT NULL CHECK (length(value) BETWEEN 1 AND 200),
    reason       text NOT NULL CHECK (length(reason) BETWEEN 1 AND 500),
    source       text NOT NULL CHECK (source IN ('manual', 'auto', 'blacklist')),
    evidence     jsonb NOT NULL DEFAULT '{}'::jsonb,
    permanent    boolean NOT NULL DEFAULT false,
    expires_at   timestamptz,
    created_at   timestamptz NOT NULL DEFAULT now(),
    created_by   text NOT NULL,
    revoked_at   timestamptz,
    revoked_by   text,
    CHECK (permanent OR expires_at IS NOT NULL),
    CHECK (NOT (permanent AND expires_at IS NOT NULL))
);
-- Active-ban lookups and the cache reload read only unrevoked rows.
CREATE INDEX bans_active_idx ON bans (entity_type, value) WHERE revoked_at IS NULL;
CREATE INDEX bans_tenant_idx ON bans (tenant_id) WHERE revoked_at IS NULL;

-- Durable record of every strike (Redis holds the hot counters used for escalation).
CREATE TABLE strikes (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     uuid REFERENCES tenants(id) ON DELETE CASCADE,
    entity_type   text NOT NULL CHECK (entity_type IN ('ip', 'user', 'device')),
    value         text NOT NULL,
    reason        text NOT NULL,
    evidence_kind text NOT NULL CHECK (evidence_kind IN ('deterministic', 'probabilistic')),
    request_id    text,
    ban_id        uuid REFERENCES bans(id) ON DELETE SET NULL,
    created_at    timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX strikes_entity_idx ON strikes (entity_type, value, created_at DESC);
