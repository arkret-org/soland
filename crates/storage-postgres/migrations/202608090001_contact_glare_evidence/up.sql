ALTER TABLE public.contacts
    ADD COLUMN IF NOT EXISTS request_receipts jsonb DEFAULT '[]'::jsonb NOT NULL,
    ADD COLUMN IF NOT EXISTS request_mirror_receipts jsonb DEFAULT '[]'::jsonb NOT NULL,
    ADD COLUMN IF NOT EXISTS basis_evidence jsonb,
    ADD COLUMN IF NOT EXISTS control_outcomes jsonb DEFAULT '[]'::jsonb NOT NULL;
