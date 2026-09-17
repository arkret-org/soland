-- Exactly inverts up.sql: restore the pre-NC-TYPE-001 column name so the
-- up -> down -> up schema cycle round-trips against the squashed initial
-- migration.
ALTER TABLE public.security_transactions
    RENAME COLUMN terminal_outcome TO terminal_result;
