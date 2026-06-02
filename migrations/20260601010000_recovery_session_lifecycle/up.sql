-- C-P2 — Recovery session lifecycle (REC-1).
--
-- The original `recovery_session` table (migration
-- 20260526030000_agent_personal_provisioning) was a scaffold tied to
-- `backup_series`, which does not fit the recovery-policy proof model. It was
-- never wired into the persistence trait or HTTP API, so we reshape it (no data
-- to migrate) to the policy-proof session: a session binds a requesting device
-- to a principal's active recovery policy snapshot + a server challenge, and
-- transitions pending -> verified -> completed (or rejected/expired).

DROP TABLE IF EXISTS recovery_session;

CREATE TABLE recovery_session (
    recovery_session_id   TEXT PRIMARY KEY
        CHECK (recovery_session_id LIKE 'cx:recovery_session:%'),
    principal_id          TEXT NOT NULL,
    requesting_device_id  TEXT NOT NULL,
    trust_domain          TEXT NOT NULL,
    policy_id             TEXT NOT NULL,
    policy_version        INTEGER NOT NULL CHECK (policy_version >= 1),
    policy_payload        JSONB NOT NULL,
    challenge             TEXT NOT NULL,
    state                 TEXT NOT NULL DEFAULT 'pending'
        CHECK (state IN ('pending', 'verified', 'completed', 'rejected', 'expired')),
    proof_payload         JSONB,
    created_at            TIMESTAMPTZ NOT NULL,
    updated_at            TIMESTAMPTZ NOT NULL,
    expires_at            TIMESTAMPTZ NOT NULL
);

CREATE INDEX recovery_session_principal_idx ON recovery_session(principal_id);
