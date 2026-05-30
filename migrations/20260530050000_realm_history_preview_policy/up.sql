-- Realm history / preview policy durable projection columns.
--
-- The reducer remains the source of truth; these columns mirror the effective
-- Realm policy components so restart hydration and directory preview gates do
-- not have to infer security state from opaque payload JSON.

ALTER TABLE spaces
    ADD COLUMN IF NOT EXISTS history_visibility TEXT NOT NULL DEFAULT 'joined'
        CHECK (history_visibility IN (
            'world_readable', 'shared', 'invited', 'joined', 'restricted'
        )),
    ADD COLUMN IF NOT EXISTS history_sharing_policy JSONB,
    ADD COLUMN IF NOT EXISTS history_sharing_policy_digest TEXT,
    ADD COLUMN IF NOT EXISTS preview_policy JSONB,
    ADD COLUMN IF NOT EXISTS preview_policy_digest TEXT,
    ADD COLUMN IF NOT EXISTS encryption_profile TEXT NOT NULL DEFAULT 'mls_rfc9420'
        CHECK (encryption_profile IN ('none', 'plaintext', 'mls_rfc9420')),
    ADD COLUMN IF NOT EXISTS plaintext_visible_services JSONB NOT NULL DEFAULT '[]'::JSONB;

CREATE INDEX IF NOT EXISTS spaces_history_visibility_updated_idx
    ON spaces (history_visibility, updated_at, id);

CREATE INDEX IF NOT EXISTS spaces_history_sharing_policy_digest_idx
    ON spaces (history_sharing_policy_digest)
    WHERE history_sharing_policy_digest IS NOT NULL;

CREATE INDEX IF NOT EXISTS spaces_preview_policy_digest_idx
    ON spaces (preview_policy_digest)
    WHERE preview_policy_digest IS NOT NULL;
