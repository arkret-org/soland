-- CXP-0007 (spec b7d35be / floor 2b0d70d) — add `scope_circle_id` to the
-- Flow / Space / Morph projection mirrors. When non-null, the row's
-- visibility / encryption boundary is bound to the named Circle's MLS
-- group instead of the parent Realm's. The wire layer enforces
-- `scope_circle_id.realm_id == row.realm_id`
-- (reducer reason `circle_realm_mismatch`).
--
-- `projection_flows.scope_circle_id` is present in the current
-- `20260516000000_flow_morph_projection` baseline, but older local databases
-- may still need this migration to add it. Keep the column changes
-- idempotent so both paths converge.
--
-- Space additionally carries `default_scope_circle_id` (default for new
-- children) and `child_scope_policy` (free/required/locked) per
-- `spec/v1/artifacts/schemas/space.schema.json`.
--
-- The Event Envelope mirror picks up the projected `effective_scope`
-- field; for soland this is recorded directly on `projection_events`
-- without requiring a separate side-band table.

ALTER TABLE projection_flows ADD COLUMN IF NOT EXISTS scope_circle_id TEXT;
ALTER TABLE projection_morphs ADD COLUMN IF NOT EXISTS scope_circle_id TEXT;
ALTER TABLE projection_space_containers ADD COLUMN IF NOT EXISTS scope_circle_id TEXT;
ALTER TABLE projection_space_containers ADD COLUMN IF NOT EXISTS default_scope_circle_id TEXT;
ALTER TABLE projection_space_containers ADD COLUMN IF NOT EXISTS child_scope_policy TEXT
    CHECK (child_scope_policy IN ('free', 'require_scope_circle_id', 'locked'));

ALTER TABLE projection_events ADD COLUMN IF NOT EXISTS effective_scope TEXT;

CREATE INDEX IF NOT EXISTS projection_flows_scope_circle_id_idx
    ON projection_flows(scope_circle_id);
CREATE INDEX IF NOT EXISTS projection_morphs_scope_circle_id_idx
    ON projection_morphs(scope_circle_id);
CREATE INDEX IF NOT EXISTS projection_space_containers_scope_circle_id_idx
    ON projection_space_containers(scope_circle_id);
CREATE INDEX IF NOT EXISTS projection_events_effective_scope_idx
    ON projection_events(effective_scope);
