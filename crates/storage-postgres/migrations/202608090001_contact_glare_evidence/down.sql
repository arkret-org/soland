ALTER TABLE public.contacts
    DROP COLUMN IF EXISTS control_outcomes,
    DROP COLUMN IF EXISTS basis_evidence,
    DROP COLUMN IF EXISTS request_mirror_receipts,
    DROP COLUMN IF EXISTS request_receipts;
