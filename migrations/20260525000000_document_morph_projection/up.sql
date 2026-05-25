ALTER TABLE projection_morphs
    ADD COLUMN fields JSONB NOT NULL DEFAULT '{}'::jsonb,
    ADD COLUMN schema_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
    ADD COLUMN facets JSONB NOT NULL DEFAULT '[]'::jsonb,
    ADD COLUMN versions JSONB NOT NULL DEFAULT '[]'::jsonb;
