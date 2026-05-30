DROP INDEX IF EXISTS key_backups_account_idx;

ALTER TABLE key_backups
    DROP COLUMN IF EXISTS key_material_encrypted,
    DROP COLUMN IF EXISTS version,
    DROP COLUMN IF EXISTS scheme,
    DROP COLUMN IF EXISTS account_id;
