CREATE TABLE organization_registration_challenges (
    challenge_id TEXT PRIMARY KEY,
    organization_id TEXT NOT NULL,
    record JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_request_digest TEXT,
    consumed_outcome_id TEXT,
    consumed_at TIMESTAMPTZ,
    CONSTRAINT organization_registration_challenge_consumption_complete CHECK (
        (consumed_request_digest IS NULL
            AND consumed_outcome_id IS NULL
            AND consumed_at IS NULL)
        OR
        (consumed_request_digest IS NOT NULL
            AND consumed_outcome_id IS NOT NULL
            AND consumed_at IS NOT NULL)
    )
);

CREATE INDEX organization_registration_challenges_organization_idx
    ON organization_registration_challenges (organization_id, created_at DESC);

CREATE TABLE organization_registration_outcomes (
    outcome_id TEXT PRIMARY KEY,
    organization_id TEXT NOT NULL,
    registration_generation BIGINT NOT NULL CHECK (registration_generation > 0),
    outcome JSONB NOT NULL,
    committed_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX organization_registration_outcomes_generation_idx
    ON organization_registration_outcomes (
        organization_id,
        registration_generation,
        committed_at
    );

ALTER TABLE organization_registration_challenges
    ADD CONSTRAINT organization_registration_challenge_consumed_outcome_fk
    FOREIGN KEY (consumed_outcome_id)
    REFERENCES organization_registration_outcomes(outcome_id);

CREATE FUNCTION reject_organization_registration_outcome_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'organization registration outcomes are immutable'
        USING ERRCODE = '55000';
END;
$$;

CREATE TRIGGER organization_registration_outcomes_immutable_update
BEFORE UPDATE OR DELETE ON organization_registration_outcomes
FOR EACH ROW
EXECUTE FUNCTION reject_organization_registration_outcome_mutation();

CREATE TABLE organization_registration_states (
    organization_id TEXT PRIMARY KEY,
    current_generation BIGINT NOT NULL CHECK (current_generation > 0),
    current_outcome_id TEXT NOT NULL
        REFERENCES organization_registration_outcomes(outcome_id),
    state JSONB NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX organization_registration_states_generation_idx
    ON organization_registration_states (organization_id, current_generation);
