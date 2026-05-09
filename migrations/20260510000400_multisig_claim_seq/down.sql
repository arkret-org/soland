DROP INDEX IF EXISTS multisig_pending_claim_seq_idx;

ALTER TABLE multisig_pending
    DROP COLUMN IF EXISTS claim_seq;
