DROP INDEX IF EXISTS spaces_preview_policy_digest_idx;
DROP INDEX IF EXISTS spaces_history_sharing_policy_digest_idx;
DROP INDEX IF EXISTS spaces_history_visibility_updated_idx;

ALTER TABLE spaces
    DROP COLUMN IF EXISTS plaintext_visible_services,
    DROP COLUMN IF EXISTS encryption_profile,
    DROP COLUMN IF EXISTS preview_policy_digest,
    DROP COLUMN IF EXISTS preview_policy,
    DROP COLUMN IF EXISTS history_sharing_policy_digest,
    DROP COLUMN IF EXISTS history_sharing_policy,
    DROP COLUMN IF EXISTS history_visibility;
