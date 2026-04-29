DROP INDEX IF EXISTS devices_actor_updated_idx;

ALTER TABLE devices
    DROP COLUMN IF EXISTS created_at;
