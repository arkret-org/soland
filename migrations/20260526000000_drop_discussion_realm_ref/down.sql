-- CXP-0007 — the legacy `discussion_realm_ref` field is now in the
-- forbidden-wire-fields hard-reject set; restoring the column would
-- contradict the protocol invariant. Provide a no-op down to satisfy
-- diesel's bidirectional migration contract without resurrecting the
-- forbidden field.
SELECT 1;
