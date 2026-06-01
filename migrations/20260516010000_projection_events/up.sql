-- Append-only projection event log. Mirror of the in-memory
-- ProjectionEventRecord stream maintained by the routing layer
-- (`project_accepted_operations` → `append_projection_event` →
-- `state.persistence.projection_events().append(...)`).
--
-- One row per accepted projection event; admins / replay / debug
-- tooling read the full history via `snapshot_all()`. The set is
-- write-heavy and snapshot reads are coarse (no per-space / per-actor
-- indexing needed at this layer — those queries hit the canonical
-- `events` table instead).

CREATE TABLE projection_events (
    -- Surrogate primary key so duplicate event_id (e.g. retry of the
    -- same operation) doesn't fail; the canonical_events table is the
    -- one with the `(actor_id, actor_seq)` uniqueness invariant.
    ordinal       BIGSERIAL PRIMARY KEY,
    event_id      TEXT NOT NULL,
    realm_id      TEXT NOT NULL,
    event_kind    TEXT NOT NULL,
    operation_type TEXT NOT NULL,
    operation_id  TEXT,
    sender        TEXT,
    payload       JSONB NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL
);

CREATE INDEX projection_events_space_idx ON projection_events(realm_id);
CREATE INDEX projection_events_created_at_idx ON projection_events(created_at);
