-- Protected prompts (prompt-leak detection by content): only shingle hashes are stored, never the prompt.
CREATE TABLE IF NOT EXISTS protected_prompts (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    label       text NOT NULL,
    shingles    jsonb NOT NULL,          -- array of sha256 hex strings (8-word shingles of the folded prompt)
    word_count  integer NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    revoked_at  timestamptz
);
CREATE INDEX IF NOT EXISTS protected_prompts_active ON protected_prompts (revoked_at) WHERE revoked_at IS NULL;
