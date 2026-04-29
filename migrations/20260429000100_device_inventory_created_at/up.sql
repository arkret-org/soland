ALTER TABLE devices
    ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT NOW();

CREATE INDEX IF NOT EXISTS devices_actor_updated_idx
    ON devices (actor, updated_at, device_id)
    WHERE revoked_at IS NULL;
