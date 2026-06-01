DROP INDEX IF EXISTS projection_events_effective_scope_idx;
DROP INDEX IF EXISTS projection_space_containers_scope_circle_id_idx;
DROP INDEX IF EXISTS projection_morphs_scope_circle_id_idx;
DROP INDEX IF EXISTS projection_flows_scope_circle_id_idx;

ALTER TABLE projection_events DROP COLUMN IF EXISTS effective_scope;
ALTER TABLE projection_space_containers DROP COLUMN IF EXISTS child_scope_policy;
ALTER TABLE projection_space_containers DROP COLUMN IF EXISTS default_scope_circle_id;
ALTER TABLE projection_space_containers DROP COLUMN IF EXISTS scope_circle_id;
ALTER TABLE projection_morphs DROP COLUMN IF EXISTS scope_circle_id;
