ALTER TABLE public.account_datas
    DROP CONSTRAINT account_datas_revision_positive,
    DROP COLUMN tombstone,
    DROP COLUMN revision;

