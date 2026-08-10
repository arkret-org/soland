use arkret_models_identity::PrincipalResolutionProjection;
use arkret_wire::{CoreId, Event, RealmId};

use super::{PersistenceResult, async_trait};

#[derive(Clone, Debug, PartialEq)]
pub struct PrincipalResolutionRecord {
    pub principal_id: CoreId,
    pub principal_control_realm_id: RealmId,
    pub genesis_event: Event,
    pub current_event: Event,
    pub projection: PrincipalResolutionProjection,
}

pub fn validate_principal_resolution_record(
    record: &PrincipalResolutionRecord,
) -> PersistenceResult<()> {
    let projected = arkret_wire::project_full_id_to_core_id(&record.projection.full_id)
        .map_err(|error| super::PersistenceError::SchemaViolation(error.to_string()))?;
    let current_is_genesis = record.current_event.event_id == record.genesis_event.event_id;
    if projected != record.principal_id
        || record.projection.resolution_event_ref != record.current_event.event_id.as_str()
        || record.projection.method_history_head.is_empty()
        || record.projection.version_id.is_empty()
        || record.genesis_event.kind != arkret_wire::EventKind::RealmCreate
        || record.genesis_event.realm_id != record.principal_control_realm_id
        || record.current_event.realm_id != record.principal_control_realm_id
        || record.genesis_event.actor_id.as_str() != record.principal_id.as_str()
        || record.current_event.actor_id.as_str() != record.principal_id.as_str()
        || (current_is_genesis && record.current_event.kind != arkret_wire::EventKind::RealmCreate)
        || (!current_is_genesis
            && record.current_event.kind != arkret_wire::EventKind::IdentityResolutionUpdate)
    {
        return Err(super::PersistenceError::SchemaViolation(
            "principal resolution record does not bind its stable principal, PCR, Event head and full-id projection"
                .to_owned(),
        ));
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq)]
pub enum PrincipalResolutionCasResult {
    Applied(PrincipalResolutionRecord),
    Conflict(Option<PrincipalResolutionRecord>),
}

/// Durable, rebuildable read index over one PCR's canonical resolution Events.
/// Canonical Event/Seal storage remains the authority; this trait only gives
/// current/history reads an atomic head and bounded ordered history.
#[async_trait]
pub trait PrincipalResolutionStore: Send + Sync {
    async fn current(
        &self,
        principal_id: &CoreId,
    ) -> PersistenceResult<Option<PrincipalResolutionRecord>>;

    async fn compare_and_set(
        &self,
        expected_current_event_ref: Option<&str>,
        next: PrincipalResolutionRecord,
    ) -> PersistenceResult<PrincipalResolutionCasResult>;

    async fn history_newest_first(
        &self,
        principal_id: &CoreId,
        after_event_ref: Option<&str>,
        limit: usize,
    ) -> PersistenceResult<Vec<Event>>;
}
