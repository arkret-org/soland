-- Durable REC-1 recovery policy / receipt acceptance records.
-- These tables are the restart fence for policy monotonicity and receipt
-- replay protection; routing code still performs the signature and
-- supersedes binding checks before insert.

CREATE TABLE recovery_policies (
    policy_id            TEXT PRIMARY KEY
        CHECK (policy_id LIKE 'cx:policy:%'),
    principal_id         TEXT NOT NULL,
    version              INTEGER NOT NULL CHECK (version >= 1),
    trust_domain         TEXT NOT NULL,
    allowed_proof_kinds  TEXT[] NOT NULL,
    supersedes           TEXT REFERENCES recovery_policies(policy_id),
    expires_at           TIMESTAMPTZ,
    issued_at            TIMESTAMPTZ NOT NULL,
    verification_method  TEXT NOT NULL,
    raw_payload          JSONB NOT NULL,
    accepted_at          TIMESTAMPTZ NOT NULL,
    UNIQUE (principal_id, version)
);

CREATE INDEX recovery_policies_principal_active_idx
    ON recovery_policies(principal_id, version DESC);

CREATE TABLE recovery_receipts (
    receipt_id           TEXT PRIMARY KEY
        CHECK (receipt_id LIKE 'cx:receipt:%'),
    principal_id         TEXT NOT NULL,
    recovery_session_id  TEXT NOT NULL UNIQUE
        CHECK (recovery_session_id LIKE 'cx:recovery_session:%'),
    policy_id            TEXT NOT NULL REFERENCES recovery_policies(policy_id),
    policy_version       INTEGER NOT NULL CHECK (policy_version >= 1),
    trust_domain         TEXT NOT NULL,
    new_device_id        TEXT NOT NULL,
    proof_digest         TEXT NOT NULL,
    outcome              TEXT NOT NULL,
    started_at           TIMESTAMPTZ NOT NULL,
    completed_at         TIMESTAMPTZ NOT NULL,
    verification_method  TEXT NOT NULL,
    raw_payload          JSONB NOT NULL,
    accepted_at          TIMESTAMPTZ NOT NULL
);

CREATE INDEX recovery_receipts_principal_idx ON recovery_receipts(principal_id);
CREATE INDEX recovery_receipts_policy_idx ON recovery_receipts(policy_id, policy_version);
