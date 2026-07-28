DROP TABLE IF EXISTS organization_registration_states;
DROP TRIGGER IF EXISTS organization_registration_outcomes_immutable_update
    ON organization_registration_outcomes;
DROP FUNCTION IF EXISTS reject_organization_registration_outcome_mutation();
DROP TABLE IF EXISTS organization_registration_challenges;
DROP TABLE IF EXISTS organization_registration_outcomes;
