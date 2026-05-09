-- Round 28 (2026-05-10): partition-tolerant fencing token for the
-- MAL-11 multisig watchdog leader-election columns. After a network
-- partition heals, two nodes may both believe they hold the lease (the
-- write to `claimed_by_node_id`/`claimed_until` from the loser was
-- accepted before the partition was detected). To make a *stale*
-- leader's eventual publish reject deterministically at the row level,
-- we add a monotonic claim counter — every successful `try_claim`
-- bumps `claim_seq`; the watchdog snapshots the seq it owns and the
-- post-aggregate `delete` / `release_claim` only succeeds when the
-- row's seq still matches.
ALTER TABLE multisig_pending
    ADD COLUMN IF NOT EXISTS claim_seq BIGINT NOT NULL DEFAULT 0;

CREATE INDEX IF NOT EXISTS multisig_pending_claim_seq_idx
    ON multisig_pending(claim_seq);
