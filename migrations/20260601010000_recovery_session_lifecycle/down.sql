-- Revert to the original scaffold shape from
-- 20260526030000_agent_personal_provisioning.
DROP TABLE IF EXISTS recovery_session;

CREATE TABLE recovery_session (
    recovery_session_id    TEXT PRIMARY KEY
        CHECK (recovery_session_id LIKE 'cx:recovery_session:%'),
    actor_id               TEXT NOT NULL,
    series_id              TEXT NOT NULL REFERENCES backup_series(series_id)
                            ON DELETE CASCADE,
    state                  TEXT NOT NULL DEFAULT 'pending'
        CHECK (state IN ('pending', 'verified', 'rejected', 'expired')),
    policy_payload         JSONB,
    receipt_payload        JSONB,
    created_at             TIMESTAMPTZ NOT NULL,
    updated_at             TIMESTAMPTZ NOT NULL,
    expires_at             TIMESTAMPTZ
);
CREATE INDEX recovery_session_actor_idx ON recovery_session(actor_id);
