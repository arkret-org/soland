-- Reverse the rename.

DROP INDEX IF EXISTS idx_space_state_events_lookup;
ALTER TABLE space_state_events
    RENAME COLUMN subject TO state_key;
CREATE INDEX IF NOT EXISTS idx_space_state_events_lookup
    ON space_state_events (space_id, event_type, state_key, created_at);
