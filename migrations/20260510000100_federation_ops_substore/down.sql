DROP TABLE IF EXISTS federation_operations;

ALTER TABLE multisig_pending
    DROP COLUMN IF EXISTS claimed_by_node_id,
    DROP COLUMN IF EXISTS claimed_until;
