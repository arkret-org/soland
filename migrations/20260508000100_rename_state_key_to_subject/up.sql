-- Rename space_state_events.state_key to subject.
--
-- The Move/Anchor/Lattice rebase (spec 2026-05-08) standardised on
-- "cell subject" as the per-kind reducer-projection key. This column
-- was the physical storage of that subject; the rename brings the DB
-- schema in line with the rest of the codebase.

ALTER TABLE space_state_events
    RENAME COLUMN state_key TO subject;

-- Drop and recreate the projection lookup index on the new column name.
DROP INDEX IF EXISTS idx_space_state_events_lookup;
CREATE INDEX IF NOT EXISTS idx_space_state_events_lookup
    ON space_state_events (space_id, event_type, subject, created_at);
