-- Space-container projection state - server-side state-machine for ck.space.*
-- lifecycle events. Spec: cokret-spec/spec/v1/zh/models/realm-and-space.md
-- §4.4 + common-fields.md §5.1. soland's reducer maintains this in-memory
-- (ProjectionState::space_containers) and persists here for restart durability.
--
-- State semantics:
--   active     - default after ck.space.create.
--   archived   - set by ck.space.archive; reversible via ck.space.restore.
--   tombstoned - set by ck.space.tombstone; terminal, MUST NOT be restored.

CREATE TABLE projection_space_containers (
    container_space_id TEXT PRIMARY KEY,
    realm_id           TEXT NOT NULL,
    -- Column order mirrors the spec space field order (kind, rank before
    -- title; spec/v1/artifacts/schemas/space.schema.json).
    kind              TEXT NOT NULL,
    rank              TEXT,
    title             TEXT NOT NULL,
    parent_ref        TEXT,
    state             TEXT NOT NULL DEFAULT 'active'
        CHECK (state IN ('active', 'archived', 'tombstoned')),
    state_changed_at  TIMESTAMPTZ,
    created_by        TEXT NOT NULL,
    created_at        TIMESTAMPTZ NOT NULL,
    updated_by        TEXT,
    updated_at        TIMESTAMPTZ
);

CREATE INDEX projection_space_containers_realm_idx ON projection_space_containers(realm_id);
CREATE INDEX projection_space_containers_state_idx ON projection_space_containers(state);
CREATE INDEX projection_space_containers_parent_idx ON projection_space_containers(parent_ref)
    WHERE parent_ref IS NOT NULL;
