use async_trait::async_trait;
use soland_storage::{
    EventCommitOutcome, EventCommitRequest, EventCommitUnitOfWork, PersistenceError,
    PersistenceResult, ids,
};

use crate::SolandMemoryPersistenceStore;

#[async_trait]
impl EventCommitUnitOfWork for SolandMemoryPersistenceStore {
    async fn commit_event(
        &self,
        request: EventCommitRequest,
    ) -> PersistenceResult<EventCommitOutcome> {
        let mut events = self.events.data.lock();
        let mut projections = self.projection_events.data.lock();
        let mut idempotency = self.idempotency_keys.data.lock();
        let mut outbox = self.federation_outbox.data.lock();

        let mut staged_events = events.clone();
        let mut staged_projections = projections.clone();
        let mut staged_idempotency = idempotency.clone();
        let mut staged_outbox = outbox.clone();

        if staged_events.contains_key(&request.event.event_id) {
            return Err(PersistenceError::Conflict("duplicate_conflict".to_owned()));
        }
        if request.event.kind == arkret_sdk::events::EventKind::REALM_CREATE
            && request.event.realm_id.is_some()
            && staged_events.values().any(|existing| {
                existing.kind == arkret_sdk::events::EventKind::REALM_CREATE
                    && existing.realm_id == request.event.realm_id
            })
        {
            return Err(PersistenceError::Conflict(
                "realm_already_exists".to_owned(),
            ));
        }
        staged_events.insert(request.event.event_id.clone(), request.event);

        let mut projections_inserted = 0;
        for projection in request.projections {
            ids::typed_uuid_part_or_schema_violation(&projection.event_id)?;
            ids::typed_uuid_part_or_schema_violation(&projection.realm_id)?;
            if let Some(operation_id) = projection.operation_id.as_deref() {
                ids::typed_uuid_part_or_schema_violation(operation_id)?;
            }
            if !staged_projections
                .iter()
                .any(|existing| existing.event_id == projection.event_id)
            {
                staged_projections.push(projection);
                projections_inserted += 1;
            }
        }

        if let Some(record) = request.idempotency {
            staged_idempotency
                .entry((record.principal_id.clone(), record.idempotency_key.clone()))
                .or_insert(record);
        }

        let mut outbox_inserted = 0;
        for record in request.outbox {
            let already_present = staged_outbox.values().any(|existing| {
                existing.peer_did == record.peer_did
                    && existing.idempotency_key == record.idempotency_key
            });
            if !already_present {
                staged_outbox.insert(record.id.clone(), record);
                outbox_inserted += 1;
            }
        }

        *events = staged_events;
        *projections = staged_projections;
        *idempotency = staged_idempotency;
        *outbox = staged_outbox;

        Ok(EventCommitOutcome {
            event_inserted: true,
            projections_inserted,
            outbox_inserted,
        })
    }
}
