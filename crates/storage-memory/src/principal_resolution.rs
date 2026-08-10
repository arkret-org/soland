use std::collections::BTreeMap;

use arkret_wire::{CoreId, Event};
use soland_storage::{
    PersistenceError, PersistenceResult, PrincipalResolutionCasResult, PrincipalResolutionRecord,
    PrincipalResolutionStore, validate_principal_resolution_record,
};

use super::{Mutex, async_trait};

#[derive(Default)]
pub(crate) struct MemoryPrincipalResolutionStore {
    rows: Mutex<BTreeMap<String, MemoryPrincipalResolutionState>>,
}

#[derive(Clone)]
struct MemoryPrincipalResolutionState {
    current: PrincipalResolutionRecord,
    /// Canonical order, genesis first and current last.
    history: Vec<Event>,
}

impl MemoryPrincipalResolutionStore {
    pub(crate) fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl PrincipalResolutionStore for MemoryPrincipalResolutionStore {
    async fn current(
        &self,
        principal_id: &CoreId,
    ) -> PersistenceResult<Option<PrincipalResolutionRecord>> {
        Ok(self
            .rows
            .lock()
            .get(principal_id.as_str())
            .map(|state| state.current.clone()))
    }

    async fn compare_and_set(
        &self,
        expected_current_event_ref: Option<&str>,
        next: PrincipalResolutionRecord,
    ) -> PersistenceResult<PrincipalResolutionCasResult> {
        validate_principal_resolution_record(&next)?;
        let principal_key = next.principal_id.as_str().to_owned();
        let mut rows = self.rows.lock();
        let current = rows.get(&principal_key);
        let observed_ref = current.map(|state| state.current.current_event.event_id.as_str());
        if observed_ref != expected_current_event_ref {
            return Ok(PrincipalResolutionCasResult::Conflict(
                current.map(|state| state.current.clone()),
            ));
        }
        if expected_current_event_ref == Some(next.current_event.event_id.as_str()) {
            return Err(PersistenceError::SchemaViolation(
                "principal resolution CAS cannot rewrite the current Event in place".to_owned(),
            ));
        }

        if let Some(current) = current {
            if current.current.principal_control_realm_id != next.principal_control_realm_id
                || current.current.genesis_event.event_id != next.genesis_event.event_id
            {
                return Err(PersistenceError::SchemaViolation(
                    "principal resolution CAS cannot change the principal's PCR or genesis Event"
                        .to_owned(),
                ));
            }
        }

        let mut history = current
            .map(|state| state.history.clone())
            .unwrap_or_else(|| vec![next.genesis_event.clone()]);
        if history
            .last()
            .is_none_or(|event| event.event_id != next.current_event.event_id)
        {
            history.push(next.current_event.clone());
        }
        rows.insert(
            principal_key,
            MemoryPrincipalResolutionState {
                current: next.clone(),
                history,
            },
        );
        Ok(PrincipalResolutionCasResult::Applied(next))
    }

    async fn history_newest_first(
        &self,
        principal_id: &CoreId,
        after_event_ref: Option<&str>,
        limit: usize,
    ) -> PersistenceResult<Vec<Event>> {
        let rows = self.rows.lock();
        let Some(state) = rows.get(principal_id.as_str()) else {
            return Ok(Vec::new());
        };
        let mut newest_first = state.history.iter().rev();
        if let Some(after) = after_event_ref {
            let Some(position) = newest_first
                .clone()
                .position(|event| event.event_id.as_str() == after)
            else {
                return Err(PersistenceError::NotFound(format!(
                    "principal resolution history cursor {after}"
                )));
            };
            for _ in 0..=position {
                let _ = newest_first.next();
            }
        }
        Ok(newest_first.take(limit).cloned().collect())
    }
}

#[cfg(test)]
mod tests {
    use arkret_models_identity::PrincipalResolutionProjection;
    use arkret_wire::{ActorId, FullId, Hlc, RealmId, ScopeRef};
    use chrono::{TimeZone, Utc};
    use soland_storage::{PrincipalResolutionCasResult, PrincipalResolutionRecord};

    use super::*;

    fn principal() -> CoreId {
        CoreId::new("ak:did_core:web:alice.example").unwrap()
    }

    fn genesis_event() -> Event {
        arkret_wire::test_support::raw_event_at(
            arkret_wire::EventKind::RealmCreate.as_str(),
            ScopeRef::RealmGenesis,
            ActorId::from(principal()),
            0,
            Hlc::new("019f00000000-0000-00000001").unwrap(),
            serde_json::json!({"sequence": 0}),
            Utc.timestamp_opt(1_786_291_200, 0).unwrap(),
        )
        .unwrap()
    }

    fn update_event(genesis: &Event) -> Event {
        arkret_wire::test_support::raw_event_at(
            arkret_wire::EventKind::IdentityResolutionUpdate.as_str(),
            ScopeRef::Realm {
                realm_id: genesis.realm_id.clone(),
            },
            ActorId::from(principal()),
            1,
            Hlc::new("019f00000000-0001-00000001").unwrap(),
            serde_json::json!({"sequence": 1}),
            Utc.timestamp_opt(1_786_291_201, 0).unwrap(),
        )
        .unwrap()
    }

    fn record(genesis: &Event, current: Event) -> PrincipalResolutionRecord {
        PrincipalResolutionRecord {
            principal_id: principal(),
            principal_control_realm_id: genesis.realm_id.clone(),
            genesis_event: genesis.clone(),
            projection: PrincipalResolutionProjection {
                full_id: FullId::new("did:web:alice.example").unwrap(),
                method_history_head: format!("head-{}", current.actor_seq),
                version_id: format!("version-{}", current.actor_seq),
                resolution_event_ref: current.event_id.to_string(),
                updated_at: current.created_at,
            },
            current_event: current,
        }
    }

    #[tokio::test]
    async fn principal_resolution_cas_and_history_are_durable_independent_of_cursor_reads() {
        let store = MemoryPrincipalResolutionStore::new();
        let genesis = genesis_event();
        let first = record(&genesis, genesis.clone());
        assert!(matches!(
            store.compare_and_set(None, first.clone()).await.unwrap(),
            PrincipalResolutionCasResult::Applied(_)
        ));
        assert!(matches!(
            store.compare_and_set(None, first).await.unwrap(),
            PrincipalResolutionCasResult::Conflict(Some(_))
        ));
        assert!(matches!(
            store
                .compare_and_set(
                    Some(genesis.event_id.as_str()),
                    record(&genesis, genesis.clone())
                )
                .await,
            Err(PersistenceError::SchemaViolation(_))
        ));

        let update = update_event(&genesis);
        let next = record(&genesis, update.clone());
        assert!(matches!(
            store
                .compare_and_set(Some(genesis.event_id.as_str()), next.clone())
                .await
                .unwrap(),
            PrincipalResolutionCasResult::Applied(_)
        ));
        assert_eq!(store.current(&principal()).await.unwrap(), Some(next));
        assert_eq!(
            store
                .history_newest_first(&principal(), Some(update.event_id.as_str()), 8)
                .await
                .unwrap(),
            vec![genesis]
        );
        assert!(matches!(
            store
                .history_newest_first(&principal(), Some("ak:event:missing"), 8)
                .await,
            Err(PersistenceError::NotFound(_))
        ));
    }
}
