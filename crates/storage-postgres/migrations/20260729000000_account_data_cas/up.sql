ALTER TABLE public.account_datas
    ADD COLUMN revision bigint NOT NULL DEFAULT 1,
    ADD COLUMN tombstone boolean NOT NULL DEFAULT false,
    ADD CONSTRAINT account_datas_revision_positive CHECK (revision >= 1);

