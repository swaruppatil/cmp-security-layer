-- Stage 7: canary tokens.
--
-- A canary is a unique marker the protected app places in its system prompt. It must never appear
-- in a reply: if it does, the instructions leaked. Only a SHA-256 hash is stored; the token is shown
-- once, at creation (like API keys).

CREATE TABLE canaries (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    label       text NOT NULL CHECK (length(label) BETWEEN 1 AND 100),
    token_hash  text NOT NULL UNIQUE,
    created_at  timestamptz NOT NULL DEFAULT now(),
    revoked_at  timestamptz
);
CREATE INDEX canaries_tenant_idx ON canaries (tenant_id) WHERE revoked_at IS NULL;
