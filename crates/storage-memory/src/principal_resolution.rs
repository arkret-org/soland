use std::collections::BTreeMap;

use arkret_wire::{Event, PrincipalAuthorityKey, RealmId};
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

fn authority_map_key(authority: &PrincipalAuthorityKey) -> String {
    format!(
        "{}\0{}",
        authority.principal_id, authority.principal_server_id
    )
}

#[async_trait]
impl PrincipalResolutionStore for MemoryPrincipalResolutionStore {
    async fn by_authority_key(
        &self,
        authority_key: &PrincipalAuthorityKey,
    ) -> PersistenceResult<Option<PrincipalResolutionRecord>> {
        Ok(self
            .rows
            .lock()
            .get(&authority_map_key(authority_key))
            .map(|state| state.current.clone()))
    }

    async fn for_realm(
        &self,
        pcr_realm_id: &RealmId,
    ) -> PersistenceResult<Option<PrincipalResolutionRecord>> {
        Ok(self
            .rows
            .lock()
            .values()
            .find(|state| state.current.pcr_realm_id == *pcr_realm_id)
            .map(|state| state.current.clone()))
    }

    async fn compare_and_set(
        &self,
        expected_current_event_ref: Option<&str>,
        next: PrincipalResolutionRecord,
    ) -> PersistenceResult<PrincipalResolutionCasResult> {
        validate_principal_resolution_record(&next)?;
        let authority_map_key = authority_map_key(&next.authority_key);
        let mut rows = self.rows.lock();
        if rows.values().any(|state| {
            state.current.pcr_realm_id == next.pcr_realm_id
                && state.current.authority_key != next.authority_key
        }) {
            return Err(PersistenceError::SchemaViolation(
                "a PCR Realm cannot be rebound to another account authority key".to_owned(),
            ));
        }
        let current = rows.get(&authority_map_key);
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

        if let Some(current) = current
            && (current.current.authority_key != next.authority_key
                || current.current.pcr_realm_id != next.pcr_realm_id
                || current.current.genesis_event.event_id != next.genesis_event.event_id)
        {
            return Err(PersistenceError::SchemaViolation(
                    "principal resolution CAS cannot change the account authority key, PCR Realm or genesis Event"
                        .to_owned(),
                ));
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
            authority_map_key,
            MemoryPrincipalResolutionState {
                current: next.clone(),
                history,
            },
        );
        Ok(PrincipalResolutionCasResult::Applied(next))
    }

    async fn history_newest_first(
        &self,
        authority_key: &PrincipalAuthorityKey,
        after_event_ref: Option<&str>,
        limit: usize,
    ) -> PersistenceResult<Vec<Event>> {
        let rows = self.rows.lock();
        let Some(state) = rows.get(&authority_map_key(authority_key)) else {
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
    use arkret_wire::{Did, DidCoreId, Hlc, PrincipalAuthorityKey, ScopeRef};
    use chrono::{TimeZone, Utc};
    use soland_storage::{PrincipalResolutionCasResult, PrincipalResolutionRecord};

    use super::*;

    fn principal() -> DidCoreId {
        DidCoreId::new("ak:did_core:web:alice.example").unwrap()
    }

    fn principal_server() -> DidCoreId {
        DidCoreId::new("ak:did_core:web:principal.example").unwrap()
    }

    fn genesis_event() -> Event {
        arkret_wire::test_support::raw_event_at(
            arkret_wire::EventKind::RealmCreate.as_str(),
            ScopeRef::RealmGenesis,
            principal(),
            principal_server(),
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
            principal(),
            principal_server(),
            1,
            Hlc::new("019f00000000-0001-00000001").unwrap(),
            serde_json::json!({"sequence": 1}),
            Utc.timestamp_opt(1_786_291_201, 0).unwrap(),
        )
        .unwrap()
    }

    fn record(genesis: &Event, current: Event) -> PrincipalResolutionRecord {
        PrincipalResolutionRecord {
            authority_key: PrincipalAuthorityKey::new(principal(), principal_server()),
            pcr_realm_id: genesis.realm_id.clone(),
            genesis_event: genesis.clone(),
            projection: PrincipalResolutionProjection {
                did: Did::new("did:web:alice.example").unwrap(),
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
        let authority_key = next.authority_key.clone();
        assert_eq!(
            store.by_authority_key(&authority_key).await.unwrap(),
            Some(next)
        );
        assert_eq!(
            store
                .history_newest_first(&authority_key, Some(update.event_id.as_str()), 8)
                .await
                .unwrap(),
            vec![genesis]
        );
        assert!(matches!(
            store
                .history_newest_first(&authority_key, Some("ak:event:missing"), 8)
                .await,
            Err(PersistenceError::NotFound(_))
        ));
    }

    #[tokio::test]
    async fn principal_resolution_rejects_same_realm_authority_substitution() {
        let store = MemoryPrincipalResolutionStore::new();
        let genesis = genesis_event();
        let accepted = record(&genesis, genesis.clone());
        store.compare_and_set(None, accepted.clone()).await.unwrap();

        let mut substituted = accepted;
        substituted.authority_key = PrincipalAuthorityKey::new(
            principal(),
            DidCoreId::new("ak:did_core:web:other-principal-server.example").unwrap(),
        );

        assert!(matches!(
            store.compare_and_set(None, substituted).await,
            Err(PersistenceError::SchemaViolation(_))
        ));
    }
}
