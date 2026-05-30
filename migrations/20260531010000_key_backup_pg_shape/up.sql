ALTER TABLE key_backups
    ADD COLUMN IF NOT EXISTS account_id TEXT,
    ADD COLUMN IF NOT EXISTS scheme TEXT,
    ADD COLUMN IF NOT EXISTS version INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS key_material_encrypted BYTEA;

UPDATE key_backups
SET account_id = COALESCE(account_id, actor_id)
WHERE account_id IS NULL;

CREATE INDEX IF NOT EXISTS key_backups_account_idx
    ON key_backups (account_id);
