ALTER TABLE mls_commits
    ADD COLUMN covered_seals jsonb DEFAULT '[]'::jsonb NOT NULL;
