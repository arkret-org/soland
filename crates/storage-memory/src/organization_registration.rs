use arkret_models_identity::{OrganizationRegistrationChallenge, OrganizationRegistrationOutcome};
use arkret_wire::DidCoreId;
use soland_storage::{
    OrganizationRegistrationChallengeRecord, OrganizationRegistrationCurrent,
    OrganizationRegistrationEnsureCommit, OrganizationRegistrationGenerationRecord,
    OrganizationRegistrationLifecycleCommit, OrganizationRegistrationRefreshCommit,
    OrganizationRegistrationStateRecord, OrganizationRegistrationStore,
    OrganizationRegistrationTerminalReason, PersistenceError, PersistenceResult,
    apply_organization_registration_ensure, apply_organization_registration_lifecycle,
    apply_organization_registration_refresh, apply_organization_registration_stale,
    validate_prepared_challenge,
};

use super::{BTreeMap, Mutex, async_trait};

#[derive(Clone, Default)]
struct MemoryOrganizationRegistrationState {
    challenges: BTreeMap<String, OrganizationRegistrationChallengeRecord>,
    registrations: BTreeMap<DidCoreId, OrganizationRegistrationStateRecord>,
    outcomes: BTreeMap<String, OrganizationRegistrationOutcome>,
}

#[derive(Default)]
pub(crate) struct MemoryOrganizationRegistrationStore {
    state: Mutex<MemoryOrganizationRegistrationState>,
}

impl MemoryOrganizationRegistrationStore {
    pub(crate) fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl OrganizationRegistrationStore for MemoryOrganizationRegistrationStore {
    async fn prepare_challenge(
        &self,
        challenge: OrganizationRegistrationChallenge,
    ) -> PersistenceResult<OrganizationRegistrationChallengeRecord> {
        validate_prepared_challenge(&challenge)?;
        let id = challenge.challenge_id.clone();
        let record = OrganizationRegistrationChallengeRecord::prepared(challenge);
        let mut state = self.state.lock();
        if state.challenges.contains_key(&id) {
            return Err(PersistenceError::Conflict(
                "organization registration prepare challenge id already exists".to_owned(),
            ));
        }
        state.challenges.insert(id, record.clone());
        Ok(record)
    }

    async fn get_challenge(
        &self,
        challenge_id: &str,
    ) -> PersistenceResult<Option<OrganizationRegistrationChallengeRecord>> {
        Ok(self.state.lock().challenges.get(challenge_id).cloned())
    }

    async fn get_current(
        &self,
        organization_id: &DidCoreId,
    ) -> PersistenceResult<Option<OrganizationRegistrationCurrent>> {
        current_from_state(&self.state.lock(), organization_id)
    }

    async fn get_generation(
        &self,
        organization_id: &DidCoreId,
        generation: u64,
    ) -> PersistenceResult<Option<OrganizationRegistrationGenerationRecord>> {
        Ok(self
            .state
            .lock()
            .registrations
            .get(organization_id)
            .and_then(|state| state.generations.get(&generation))
            .cloned())
    }

    async fn get_outcome(
        &self,
        outcome_id: &str,
    ) -> PersistenceResult<Option<OrganizationRegistrationOutcome>> {
        Ok(self.state.lock().outcomes.get(outcome_id).cloned())
    }

    async fn ensure(
        &self,
        commit: OrganizationRegistrationEnsureCommit,
    ) -> PersistenceResult<OrganizationRegistrationOutcome> {
        let mut state = self.state.lock();
        let snapshot = state.clone();
        let result = (|| {
            let organization_id = challenge_organization_id(&state, &commit.challenge_id)?;
            let MemoryOrganizationRegistrationState {
                challenges,
                registrations,
                outcomes,
            } = &mut *state;
            let challenge = challenges
                .get_mut(&commit.challenge_id)
                .expect("challenge was resolved above");
            let mut registration = registrations.remove(&organization_id);
            let result = apply_organization_registration_ensure(
                challenge,
                &mut registration,
                outcomes,
                commit,
            );
            if let Some(registration) = registration {
                registrations.insert(organization_id, registration);
            }
            result
        })();
        if result.is_err() {
            *state = snapshot;
        }
        result
    }

    async fn refresh(
        &self,
        commit: OrganizationRegistrationRefreshCommit,
    ) -> PersistenceResult<OrganizationRegistrationOutcome> {
        let mut state = self.state.lock();
        let snapshot = state.clone();
        let result = (|| {
            let organization_id = challenge_organization_id(&state, &commit.challenge_id)?;
            let MemoryOrganizationRegistrationState {
                challenges,
                registrations,
                outcomes,
            } = &mut *state;
            let challenge = challenges
                .get_mut(&commit.challenge_id)
                .expect("challenge was resolved above");
            let registration = registrations.get_mut(&organization_id).ok_or_else(|| {
                PersistenceError::NotFound("organization registration".to_owned())
            })?;
            apply_organization_registration_refresh(challenge, registration, outcomes, commit)
        })();
        if result.is_err() {
            *state = snapshot;
        }
        result
    }

    async fn mark_stale(
        &self,
        organization_id: &DidCoreId,
        expected_current_generation: u64,
        expected_current_outcome_id: &str,
        changed_at: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<OrganizationRegistrationCurrent> {
        let mut state = self.state.lock();
        let snapshot = state.clone();
        let result = (|| {
            let MemoryOrganizationRegistrationState {
                registrations,
                outcomes,
                ..
            } = &mut *state;
            let registration = registrations.get_mut(organization_id).ok_or_else(|| {
                PersistenceError::NotFound("organization registration".to_owned())
            })?;
            apply_organization_registration_stale(
                registration,
                outcomes,
                organization_id,
                expected_current_generation,
                expected_current_outcome_id,
                changed_at,
            )
        })();
        if result.is_err() {
            *state = snapshot;
        }
        result
    }

    async fn revoke(
        &self,
        commit: OrganizationRegistrationLifecycleCommit,
    ) -> PersistenceResult<OrganizationRegistrationOutcome> {
        self.apply_lifecycle(commit, None)
    }

    async fn deactivate(
        &self,
        commit: OrganizationRegistrationLifecycleCommit,
    ) -> PersistenceResult<OrganizationRegistrationOutcome> {
        self.apply_lifecycle(
            commit,
            Some(OrganizationRegistrationTerminalReason::ExternalDidDeactivated),
        )
    }
}

impl MemoryOrganizationRegistrationStore {
    fn apply_lifecycle(
        &self,
        commit: OrganizationRegistrationLifecycleCommit,
        required_reason: Option<OrganizationRegistrationTerminalReason>,
    ) -> PersistenceResult<OrganizationRegistrationOutcome> {
        let mut state = self.state.lock();
        let snapshot = state.clone();
        let result = (|| {
            let MemoryOrganizationRegistrationState {
                registrations,
                outcomes,
                ..
            } = &mut *state;
            let registration = registrations
                .get_mut(&commit.organization_id)
                .ok_or_else(|| {
                    PersistenceError::NotFound("organization registration".to_owned())
                })?;
            apply_organization_registration_lifecycle(
                registration,
                outcomes,
                commit,
                required_reason,
            )
        })();
        if result.is_err() {
            *state = snapshot;
        }
        result
    }
}

fn challenge_organization_id(
    state: &MemoryOrganizationRegistrationState,
    challenge_id: &str,
) -> PersistenceResult<DidCoreId> {
    state
        .challenges
        .get(challenge_id)
        .map(|record| record.challenge.organization_id.clone())
        .ok_or_else(|| {
            PersistenceError::Conflict(
                "organization_registration_challenge_invalid: challenge not found".to_owned(),
            )
        })
}

fn current_from_state(
    state: &MemoryOrganizationRegistrationState,
    organization_id: &DidCoreId,
) -> PersistenceResult<Option<OrganizationRegistrationCurrent>> {
    let Some(registration) = state.registrations.get(organization_id) else {
        return Ok(None);
    };
    registration.validate()?;
    let generation = registration.current()?.clone();
    let outcome = state
        .outcomes
        .get(&generation.current_outcome_id)
        .cloned()
        .ok_or_else(|| {
            PersistenceError::Internal(
                "organization registration current outcome is missing".to_owned(),
            )
        })?;
    Ok(Some(OrganizationRegistrationCurrent {
        generation,
        outcome,
    }))
}

#[cfg(test)]
mod tests {
    use soland_storage::contract_tests::assert_organization_registration_store_contract;

    use super::MemoryOrganizationRegistrationStore;

    #[tokio::test]
    async fn memory_adapter_satisfies_organization_registration_contract() {
        let store = MemoryOrganizationRegistrationStore::new();
        let namespace = format!("memory-organization-registration-{}", uuid::Uuid::now_v7());
        assert_organization_registration_store_contract(&store, &namespace).await;
    }
}
