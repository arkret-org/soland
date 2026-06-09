-- CKP-0008 / CKP-0009 (spec head 37ce729) — Personal Agent + Sidecar
-- provisioning durable bookkeeping. Mirrors the canonical id-kind-registry
-- shapes for `agent_session`, `agent_key`,
-- `accountability_grant`, `backup_series`, `recovery_session`. The reducer
-- continues to authoritatively project from the Event log; these tables
-- are the restart-durability mirror plus the queue used by the
-- pending-draft / sidecar-projection account-data flows.
--
-- Schema scaffolds only (P2-impl) — relations like the
-- `agent_principal <-> agent_key <-> session_grant` join row are
-- intentionally left as TODOs so the migration round-trips cleanly. The
-- reducer + projection pipeline lands in the follow-up P2 sub-task.

CREATE TABLE agent_principal (
    agent_principal_id     TEXT PRIMARY KEY
        CHECK (
            agent_principal_id LIKE 'did:%'
            AND agent_principal_id !~ '[[:space:]#?]'
        ),
    controller_did         TEXT NOT NULL,
    agent_id               TEXT NOT NULL,
    display_name           TEXT NOT NULL,
    state                  TEXT NOT NULL DEFAULT 'active'
        CHECK (state IN ('active', 'paused', 'deactivated')),
    state_changed_at       TIMESTAMPTZ,
    created_at             TIMESTAMPTZ NOT NULL,
    updated_at             TIMESTAMPTZ NOT NULL
);

CREATE INDEX agent_principal_controller_idx ON agent_principal(controller_did);
CREATE INDEX agent_principal_state_idx ON agent_principal(state);

CREATE TABLE agent_session (
    agent_session_id       TEXT PRIMARY KEY
        CHECK (agent_session_id LIKE 'ck:agent_session:%'),
    agent_principal_id     TEXT NOT NULL REFERENCES agent_principal(agent_principal_id)
                            ON DELETE CASCADE,
    verification_method    TEXT NOT NULL,
    runtime_attestation    JSONB,
    state                  TEXT NOT NULL DEFAULT 'active'
        CHECK (state IN ('active', 'revoked', 'expired')),
    created_at             TIMESTAMPTZ NOT NULL,
    expires_at             TIMESTAMPTZ,
    revoked_at             TIMESTAMPTZ
);

CREATE INDEX agent_session_principal_idx ON agent_session(agent_principal_id);
CREATE INDEX agent_session_state_idx ON agent_session(state);

CREATE TABLE agent_key (
    agent_key_id           TEXT PRIMARY KEY
        CHECK (agent_key_id LIKE 'ck:agent_key:%'),
    agent_principal_id     TEXT NOT NULL REFERENCES agent_principal(agent_principal_id)
                            ON DELETE CASCADE,
    verification_method    TEXT NOT NULL,
    state                  TEXT NOT NULL DEFAULT 'authorized'
        CHECK (state IN ('authorized', 'revoked')),
    authorized_at          TIMESTAMPTZ NOT NULL,
    revoked_at             TIMESTAMPTZ,
    revocation_reason      TEXT
);

CREATE INDEX agent_key_principal_idx ON agent_key(agent_principal_id);
CREATE INDEX agent_key_state_idx ON agent_key(state);

CREATE TABLE agent_grant (
    grant_id               TEXT PRIMARY KEY
        CHECK (grant_id LIKE 'ck:accountability_grant:%' OR grant_id LIKE 'ck:grant:%'),
    agent_principal_id     TEXT NOT NULL REFERENCES agent_principal(agent_principal_id)
                            ON DELETE CASCADE,
    grant_kind             TEXT NOT NULL,
    scope                  JSONB NOT NULL,
    state                  TEXT NOT NULL DEFAULT 'active'
        CHECK (state IN ('active', 'detached', 'revoked', 'expired')),
    created_at             TIMESTAMPTZ NOT NULL,
    detached_at            TIMESTAMPTZ,
    expires_at             TIMESTAMPTZ
);

CREATE INDEX agent_grant_principal_idx ON agent_grant(agent_principal_id);
CREATE INDEX agent_grant_state_idx ON agent_grant(state);

CREATE TABLE backup_series (
    series_id              TEXT PRIMARY KEY
        CHECK (series_id LIKE 'ck:backup_series:%'),
    actor_id               TEXT NOT NULL,
    backup_class           TEXT NOT NULL
        CHECK (backup_class IN ('did_recovery', 'secret_storage', 'mls_history', 'external')),
    head_backup_id         TEXT,
    head_seq               BIGINT NOT NULL DEFAULT 0
        CHECK (head_seq >= 0),
    frontier_ref           TEXT,
    created_at             TIMESTAMPTZ NOT NULL,
    updated_at             TIMESTAMPTZ NOT NULL,
    retired_at             TIMESTAMPTZ
);

CREATE INDEX backup_series_actor_idx ON backup_series(actor_id);
CREATE INDEX backup_series_class_idx ON backup_series(backup_class);
CREATE UNIQUE INDEX backup_series_actor_class_uniq
    ON backup_series(actor_id, backup_class)
    WHERE retired_at IS NULL;

CREATE TABLE recovery_session (
    recovery_session_id    TEXT PRIMARY KEY
        CHECK (recovery_session_id LIKE 'ck:recovery_session:%'),
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
CREATE INDEX recovery_session_series_idx ON recovery_session(series_id);
CREATE INDEX recovery_session_state_idx ON recovery_session(state);

-- `ck.agent.draft.v1` controller-private actor-private queue. The reducer
-- keeps drafts hidden from the agent runtime until the controller
-- explicitly approves them (ck.agent.action_approve event).
CREATE TABLE pending_agent_drafts (
    draft_id               TEXT PRIMARY KEY
        CHECK (draft_id LIKE 'ck:agent_draft:%'),
    agent_principal_id     TEXT NOT NULL REFERENCES agent_principal(agent_principal_id)
                            ON DELETE CASCADE,
    controller_did         TEXT NOT NULL,
    draft_payload          JSONB NOT NULL,
    state                  TEXT NOT NULL DEFAULT 'pending'
        CHECK (state IN ('pending', 'approved', 'rejected', 'expired')),
    proposed_at            TIMESTAMPTZ NOT NULL,
    decided_at             TIMESTAMPTZ,
    decided_by             TEXT
);

CREATE INDEX pending_agent_drafts_principal_idx ON pending_agent_drafts(agent_principal_id);
CREATE INDEX pending_agent_drafts_controller_idx ON pending_agent_drafts(controller_did);
CREATE INDEX pending_agent_drafts_state_idx ON pending_agent_drafts(state);

-- CKP-0010 — agent participation policy.
-- Controller-set per-scope selection (`ck.agent.participation.v1`).
-- Booleans mirror cokret_core::AgentParticipation field order
-- (reply, accept_third_party_mention, act_on_behalf).
CREATE TABLE agent_participation (
    agent_principal_id          TEXT NOT NULL REFERENCES agent_principal(agent_principal_id)
                                ON DELETE CASCADE,
    scope_kind                  TEXT NOT NULL
        CHECK (scope_kind IN ('realm', 'circle', 'flow')),
    scope_key                   TEXT NOT NULL,
    realm_id                    TEXT NOT NULL,
    scope                       JSONB NOT NULL,
    reply                       BOOLEAN NOT NULL DEFAULT FALSE,
    accept_third_party_mention  BOOLEAN NOT NULL DEFAULT FALSE,
    act_on_behalf               BOOLEAN NOT NULL DEFAULT FALSE,
    updated_at                  TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (agent_principal_id, scope_key)
);

CREATE INDEX agent_participation_realm_idx ON agent_participation(realm_id);

-- Governance ceiling per scope (deployment ⊇ Realm ⊇ Circle ⊇ Flow,
-- tighten-only). One row per scope_key; reducer enforces the monotone
-- invariant against the parent scope on write.
CREATE TABLE agent_participation_ceiling (
    scope_kind                  TEXT NOT NULL
        CHECK (scope_kind IN ('realm', 'circle', 'flow')),
    scope_key                   TEXT NOT NULL,
    realm_id                    TEXT NOT NULL,
    reply                       BOOLEAN NOT NULL DEFAULT FALSE,
    accept_third_party_mention  BOOLEAN NOT NULL DEFAULT FALSE,
    act_on_behalf               BOOLEAN NOT NULL DEFAULT FALSE,
    updated_at                  TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (scope_key)
);

CREATE INDEX agent_participation_ceiling_realm_idx ON agent_participation_ceiling(realm_id);

-- CKP-0016 §9.4.5 — per-recipient notification projection. Derived from
-- ck.message.create mention fanout; native agents are gated by their
-- effective accept_third_party_mention bit before a row is written.
CREATE TABLE notification (
    notification_id    TEXT PRIMARY KEY,
    recipient_id       TEXT NOT NULL,
    realm_id           TEXT NOT NULL,
    source_event_id    TEXT NOT NULL,
    notification_type  TEXT NOT NULL,
    created_at         TIMESTAMPTZ NOT NULL,
    read_at            TIMESTAMPTZ
);

CREATE INDEX notification_recipient_idx ON notification(recipient_id, created_at DESC);
CREATE INDEX notification_source_idx ON notification(source_event_id);
