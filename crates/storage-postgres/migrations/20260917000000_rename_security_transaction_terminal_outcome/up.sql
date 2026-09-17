-- Rename `security_transactions.terminal_result` to `terminal_outcome`.
--
-- NC-TYPE-001 reserves the `_result` suffix for the 23 typed current-result
-- envelopes that are in bijection with `result_kind`. The answer a synchronous
-- operation or query returns is an `_outcome`. `SecurityTransactionResource`
-- carries the signed terminal decision of a security transaction, and the
-- upstream SDK type is already `SecurityTransactionTerminalOutcome`
-- (`arkret-rust-sdk/crates/models-crypto/src/security_transaction.rs`), so the
-- field -- and therefore the column that materializes it -- is
-- `terminal_outcome`. A column MUST carry the same name as the spec field it
-- materializes, so this is a column rename, not a compatibility alias.
ALTER TABLE public.security_transactions
    RENAME COLUMN terminal_result TO terminal_outcome;
