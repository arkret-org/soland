-- Place projection state — server-side state-machine for cx.place.*
-- lifecycle events. Spec: contrix-spec/spec/v1/zh/models/space-and-place.md
-- §4.4 + common-fields.md §5.1. soland's reducer maintains this in-memory
-- (ProjectionState::places) and persists here for restart durability.
--
-- State semantics:
--   active     — default after cx.place.create.
--   archived   — set by cx.place.archive; reversible via cx.place.restore.
--   tombstoned — set by cx.place.tombstone; terminal, MUST NOT be restored.

CREATE TABLE projection_places (
    place_id          TEXT PRIMARY KEY,
    space_id          TEXT NOT NULL,
    kind              TEXT NOT NULL,
    title             TEXT NOT NULL,
    parent_ref        TEXT,
    rank              TEXT,
    state             TEXT NOT NULL DEFAULT 'active'
        CHECK (state IN ('active', 'archived', 'tombstoned')),
    state_changed_at  TIMESTAMPTZ,
    created_by        TEXT NOT NULL,
    created_at        TIMESTAMPTZ NOT NULL,
    updated_by        TEXT,
    updated_at        TIMESTAMPTZ
);

CREATE INDEX projection_places_space_idx ON projection_places(space_id);
CREATE INDEX projection_places_state_idx ON projection_places(state);
CREATE INDEX projection_places_parent_idx ON projection_places(parent_ref)
    WHERE parent_ref IS NOT NULL;
