-- Stage 2: tenants, API keys, policies.
-- gen_random_uuid() is built into PostgreSQL 13+.

CREATE TABLE tenants (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name        text NOT NULL UNIQUE CHECK (length(name) BETWEEN 1 AND 100),
    status      text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
    created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE api_keys (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name          text NOT NULL CHECK (length(name) BETWEEN 1 AND 100),
    prefix        text NOT NULL UNIQUE,          -- clear, indexed, used for lookup
    key_hash      text NOT NULL,                  -- sha256 of the full key; plaintext is never stored
    scopes        text[] NOT NULL DEFAULT ARRAY['inspect', 'proxy'],
    status        text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked')),
    created_at    timestamptz NOT NULL DEFAULT now(),
    expires_at    timestamptz,
    revoked_at    timestamptz,
    last_used_at  timestamptz
);
CREATE INDEX api_keys_tenant_idx ON api_keys (tenant_id);

-- Policies: which action to take per risk band. tenant_id NULL = global default.
-- Used from Stage 4 onward; created now so tenants can reference a policy from the start.
CREATE TABLE policies (
    id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id         uuid REFERENCES tenants(id) ON DELETE CASCADE,
    name              text NOT NULL,
    endpoint_pattern  text NOT NULL DEFAULT '*',
    sensitive         boolean NOT NULL DEFAULT false,
    thresholds        jsonb NOT NULL DEFAULT '{}'::jsonb,
    actions           jsonb NOT NULL DEFAULT '{}'::jsonb,
    version           integer NOT NULL DEFAULT 1,
    active            boolean NOT NULL DEFAULT true,
    created_at        timestamptz NOT NULL DEFAULT now(),
    updated_at        timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX policies_tenant_idx ON policies (tenant_id) WHERE active;

INSERT INTO policies (tenant_id, name, endpoint_pattern, sensitive, thresholds, actions)
VALUES (
    NULL,
    'global-default',
    '*',
    false,
    '{"flag_at": 0.3, "block_at": 0.7, "strike_at": 0.9}'::jsonb,
    '{"below_flag": "allow", "flag": "allow", "block": "block", "strike": "block"}'::jsonb
);
