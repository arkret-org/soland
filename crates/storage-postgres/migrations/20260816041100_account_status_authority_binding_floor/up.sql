CREATE TABLE public.account_status_replica_records (
    account_authority_id text NOT NULL CHECK (account_authority_id LIKE 'ak:did_core:%'),
    account_id text NOT NULL,
    status_seq bigint NOT NULL CHECK (status_seq >= 1),
    record_id text NOT NULL UNIQUE CHECK (record_id LIKE 'ak:account_status_record:%'),
    record jsonb NOT NULL,
    receipt jsonb NOT NULL,
    accepted_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (account_authority_id, account_id, status_seq)
);

CREATE INDEX account_status_replica_records_range_idx
    ON public.account_status_replica_records (account_authority_id, account_id, status_seq);
