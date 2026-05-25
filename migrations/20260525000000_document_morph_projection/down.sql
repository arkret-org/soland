ALTER TABLE projection_morphs
    DROP COLUMN IF EXISTS versions,
    DROP COLUMN IF EXISTS facets,
    DROP COLUMN IF EXISTS schema_refs,
    DROP COLUMN IF EXISTS fields;
