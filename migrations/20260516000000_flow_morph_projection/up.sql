-- Flow / Morph projection state — server-side state-machine for
-- ck.flow.* and ck.morph.* lifecycle events. Spec:
-- cokret-spec/spec/v1/zh/models/common-fields.md §5.1 (canonical
-- state-transition table). soland's reducer maintains this in-memory
-- (ProjectionState::flows / ProjectionState::morphs) and persists here
-- for restart durability. Mirror of the projection_space_containers table from the
-- 20260515000000_space_container_projection migration; key difference is the state
-- enum:
--   - Flow / Morph: active / archived / deleted / redacted (per spec §5
--     ObjectState row — Flow / Morph carry the redacted state but have
--     no dedicated tombstone event; terminal state is reached via
--     ck.redaction).
--   - Space-container uses {active, archived, tombstoned} (covered by the prior
--     migration; SpaceContainerLifecycleState).

CREATE TABLE projection_flows (
    flow_id           TEXT PRIMARY KEY,
    realm_id          TEXT NOT NULL,
    -- CXP-0007: the Circle this Flow is scoped to (`ck:circle:…`), if any.
    -- A message's effective circle-scope is derived from its Flow's
    -- scope_circle_id (spec: scope_circle_id is a Flow field, not a message
    -- field), so it MUST survive restart to keep circle-scoped messages
    -- hidden from realm members outside the Circle. Column position mirrors
    -- the spec flow field order (scope_circle_id immediately follows realm_id;
    -- spec/v1/artifacts/schemas/flow.schema.json).
    scope_circle_id   TEXT,
    title             TEXT NOT NULL,
    summary           TEXT,
    state             TEXT NOT NULL DEFAULT 'active'
        CHECK (state IN ('active', 'archived', 'deleted', 'redacted')),
    state_changed_at  TIMESTAMPTZ,
    created_by        TEXT NOT NULL,
    created_at        TIMESTAMPTZ NOT NULL,
    updated_by        TEXT,
    updated_at        TIMESTAMPTZ
);

CREATE INDEX projection_flows_realm_idx ON projection_flows(realm_id);
CREATE INDEX projection_flows_state_idx ON projection_flows(state);

CREATE TABLE projection_morphs (
    morph_id          TEXT PRIMARY KEY,
    realm_id          TEXT NOT NULL,
    morph_type        TEXT NOT NULL,
    title             TEXT,
    state             TEXT NOT NULL DEFAULT 'active'
        CHECK (state IN ('active', 'archived', 'deleted', 'redacted')),
    state_changed_at  TIMESTAMPTZ,
    created_by        TEXT NOT NULL,
    created_at        TIMESTAMPTZ NOT NULL,
    updated_by        TEXT,
    updated_at        TIMESTAMPTZ
);

CREATE INDEX projection_morphs_realm_idx ON projection_morphs(realm_id);
CREATE INDEX projection_morphs_state_idx ON projection_morphs(state);
CREATE INDEX projection_morphs_type_idx ON projection_morphs(morph_type);
