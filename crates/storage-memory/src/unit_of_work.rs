use async_trait::async_trait;
use soland_storage::{
    EventBatchCommitRequest, EventCommitOutcome, EventCommitRequest, EventCommitUnitOfWork,
    PersistenceError, PersistenceResult, ids,
};

use crate::SolandMemoryPersistenceStore;
#[cfg(feature = "fault-injection")]
use crate::{FaultPoint, FaultTiming};

fn stage_control_proposal_receipt(
    staged: &mut std::collections::BTreeMap<String, arkret_wire::ControlProposalReceipt>,
    request: &EventCommitRequest,
) -> PersistenceResult<()> {
    let event: arkret_wire::Event = serde_json::from_value(request.event.envelope.clone())
        .map_err(|error| {
            PersistenceError::Conflict(format!(
                "schema_violation: accepted Event envelope is not canonical wire: {error}"
            ))
        })?;
    // Control/Data routing is defined by the typed Event plane. In particular,
    // a closed genesis anchor is a basis-free Control Move, while a DataEvent
    // carries the data-plane seal/auth context. Do not infer the plane from
    // `seal_basis` or from the presence of a receipt.
    let is_control_move =
        event.kind.is_reducer_input() && event.seal_ref.is_none() && event.auth_context.is_none();
    if !is_control_move {
        if request.control_proposal_receipt.is_some() {
            return Err(PersistenceError::Conflict(
                "schema_violation: non-Control Event cannot carry a proposal receipt".to_owned(),
            ));
        }
        return Ok(());
    }
    let event_digest = event.event_digest().map_err(|error| {
        PersistenceError::Conflict(format!(
            "schema_violation: accepted Control Move digest failed: {error}"
        ))
    })?;
    if event_digest != request.event.canonical_digest {
        return Err(PersistenceError::Conflict(
            "schema_violation: canonical digest differs from Control Move digest".to_owned(),
        ));
    }
    let receipt = request.control_proposal_receipt.as_ref().ok_or_else(|| {
        PersistenceError::Conflict(
            "schema_violation: accepted Control Move is missing proposal receipt".to_owned(),
        )
    })?;
    receipt.validate_protocol_bounds().map_err(|error| {
        PersistenceError::Conflict(format!(
            "schema_violation: invalid proposal receipt: {error}"
        ))
    })?;
    if receipt.proposal_digest.as_str() != event_digest || receipt.realm_id != event.realm_id {
        return Err(PersistenceError::Conflict(
            "schema_violation: proposal receipt does not bind Control Move".to_owned(),
        ));
    }
    if let Some(existing) = staged.get(&request.event.event_id)
        && existing != receipt
    {
        return Err(PersistenceError::Conflict(
            "duplicate_conflict: Control Move has a different proposal receipt".to_owned(),
        ));
    }
    staged.insert(request.event.event_id.clone(), receipt.clone());
    Ok(())
}

#[async_trait]
impl EventCommitUnitOfWork for SolandMemoryPersistenceStore {
    async fn commit_event(
        &self,
        request: EventCommitRequest,
    ) -> PersistenceResult<EventCommitOutcome> {
        #[cfg(feature = "fault-injection")]
        self.fault_injector
            .check(FaultPoint::EventCommit, FaultTiming::Before)?;
        let mut events = self.events.data.lock();
        let mut control_proposal_receipts = self.events.control_proposal_receipts.lock();
        let mut projections = self.projection_events.data.lock();
        let mut idempotency = self.idempotency_keys.data.lock();
        let mut outbox = self.federation_outbox.data.lock();

        let mut staged_events = events.clone();
        let mut staged_control_proposal_receipts = control_proposal_receipts.clone();
        let mut staged_projections = projections.clone();
        let mut staged_idempotency = idempotency.clone();
        let mut staged_outbox = outbox.clone();

        if staged_events.contains_key(&request.event.event_id) {
            return Err(PersistenceError::Conflict("duplicate_conflict".to_owned()));
        }
        if request.event.kind == arkret_wire::EventKind::REALM_CREATE
            && request.event.realm_id.is_some()
            && staged_events.values().any(|existing| {
                existing.kind == arkret_wire::EventKind::REALM_CREATE
                    && existing.realm_id == request.event.realm_id
            })
        {
            return Err(PersistenceError::Conflict(
                "realm_already_exists".to_owned(),
            ));
        }
        soland_storage::validate_actor_scope_commit(staged_events.values(), &request.event)?;
        stage_control_proposal_receipt(&mut staged_control_proposal_receipts, &request)?;
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
            let key = (record.principal_id.clone(), record.idempotency_key.clone());
            if staged_idempotency.contains_key(&key) {
                return Err(PersistenceError::Conflict("duplicate_conflict".to_owned()));
            }
            staged_idempotency.insert(key, record);
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
        *control_proposal_receipts = staged_control_proposal_receipts;
        *projections = staged_projections;
        *idempotency = staged_idempotency;
        *outbox = staged_outbox;

        let outcome = EventCommitOutcome {
            event_inserted: true,
            projections_inserted,
            outbox_inserted,
        };
        #[cfg(feature = "fault-injection")]
        self.fault_injector
            .check(FaultPoint::EventCommit, FaultTiming::After)?;
        Ok(outcome)
    }

    async fn commit_event_batch(
        &self,
        request: EventBatchCommitRequest,
    ) -> PersistenceResult<EventCommitOutcome> {
        #[cfg(feature = "fault-injection")]
        self.fault_injector
            .check(FaultPoint::EventCommit, FaultTiming::Before)?;
        if request.events.is_empty() {
            return Err(PersistenceError::Conflict(
                "schema_violation: empty event batch".to_owned(),
            ));
        }
        let mut events = self.events.data.lock();
        let mut control_proposal_receipts = self.events.control_proposal_receipts.lock();
        let mut projections = self.projection_events.data.lock();
        let mut idempotency = self.idempotency_keys.data.lock();
        let mut outbox = self.federation_outbox.data.lock();
        let mut applets = self.applets.records.lock();

        let mut staged_events = events.clone();
        let mut staged_control_proposal_receipts = control_proposal_receipts.clone();
        let mut staged_projections = projections.clone();
        let mut staged_idempotency = idempotency.clone();
        let mut staged_outbox = outbox.clone();
        let mut staged_applets = applets.clone();
        let mut projections_inserted = 0;
        let mut outbox_inserted = 0;

        for event_request in request.events {
            if staged_events.contains_key(&event_request.event.event_id) {
                return Err(PersistenceError::Conflict("duplicate_conflict".to_owned()));
            }
            if event_request.event.kind == arkret_wire::EventKind::REALM_CREATE
                && event_request.event.realm_id.is_some()
                && staged_events.values().any(|existing| {
                    existing.kind == arkret_wire::EventKind::REALM_CREATE
                        && existing.realm_id == event_request.event.realm_id
                })
            {
                return Err(PersistenceError::Conflict(
                    "realm_already_exists".to_owned(),
                ));
            }
            soland_storage::validate_actor_scope_commit(
                staged_events.values(),
                &event_request.event,
            )?;
            stage_control_proposal_receipt(&mut staged_control_proposal_receipts, &event_request)?;
            staged_events.insert(event_request.event.event_id.clone(), event_request.event);

            for projection in event_request.projections {
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
            if let Some(record) = event_request.idempotency {
                let key = (record.principal_id.clone(), record.idempotency_key.clone());
                if staged_idempotency.contains_key(&key) {
                    return Err(PersistenceError::Conflict("duplicate_conflict".to_owned()));
                }
                staged_idempotency.insert(key, record);
            }
            for record in event_request.outbox {
                let already_present = staged_outbox.values().any(|existing| {
                    existing.peer_did == record.peer_did
                        && existing.idempotency_key == record.idempotency_key
                });
                if !already_present {
                    staged_outbox.insert(record.id.clone(), record);
                    outbox_inserted += 1;
                }
            }
        }

        if let Some(mutation) = request.applet_ghosts {
            let record = staged_applets
                .get_mut(&mutation.applet_id)
                .ok_or_else(|| PersistenceError::NotFound("applet registration".to_owned()))?;
            let active = record
                .get("revoked_at")
                .is_none_or(serde_json::Value::is_null)
                && matches!(
                    record.get("status").and_then(serde_json::Value::as_str),
                    Some("installed" | "partially_installed")
                );
            if !active {
                return Err(PersistenceError::Conflict("applet_revoked".to_owned()));
            }
            let record = record.as_object_mut().ok_or_else(|| {
                PersistenceError::Internal("applet record is not an object".to_owned())
            })?;
            let ghosts = record
                .entry("ghosts")
                .or_insert_with(|| serde_json::Value::Array(Vec::new()))
                .as_array_mut()
                .ok_or_else(|| {
                    PersistenceError::Internal("applet ghosts is not an array".to_owned())
                })?;
            let duplicate = ghosts.iter().any(|existing| {
                existing.get("external_id") == mutation.ghost.get("external_id")
                    || existing.get("ghost_actor_id") == mutation.ghost.get("ghost_actor_id")
            });
            if duplicate {
                return Err(PersistenceError::Conflict("duplicate_conflict".to_owned()));
            }
            ghosts.push(mutation.ghost);
        }

        *events = staged_events;
        *control_proposal_receipts = staged_control_proposal_receipts;
        *projections = staged_projections;
        *idempotency = staged_idempotency;
        *outbox = staged_outbox;
        *applets = staged_applets;

        #[cfg(feature = "fault-injection")]
        self.fault_injector
            .check(FaultPoint::EventCommit, FaultTiming::After)?;
        Ok(EventCommitOutcome {
            event_inserted: true,
            projections_inserted,
            outbox_inserted,
        })
    }
}

#[cfg(test)]
mod tests {
    use chrono::{Duration, Utc};
    use soland_storage::{
        AppletGhostCommit, CanonicalEventRecord, EventBatchCommitRequest, EventCommitRequest,
        EventCommitUnitOfWork, IdempotencyRecord,
    };

    use crate::SolandMemoryPersistenceStore;

    fn typed_id(prefix: &str) -> String {
        format!("{prefix}{}", uuid::Uuid::now_v7())
    }

    fn event_request(
        event_id: String,
        realm_id: String,
        actor_id: &str,
        idempotency: Option<IdempotencyRecord>,
    ) -> EventCommitRequest {
        EventCommitRequest {
            event: CanonicalEventRecord {
                event_id: event_id.clone(),
                actor_id: actor_id.to_owned(),
                actor_seq: 0,
                realm_id: Some(realm_id),
                kind: arkret_wire::EventKind::PROFILE_CREATE.to_owned(),
                schema_id: "arkret://events/profile/create/v1".to_owned(),
                canonical_digest: format!("sha256:{event_id}"),
                canonical_bytes: event_id.as_bytes().to_vec(),
                envelope: serde_json::json!({"event_id": event_id}),
                received_at: Utc::now(),
            },
            control_proposal_receipt: None,
            projections: Vec::new(),
            idempotency,
            outbox: Vec::new(),
        }
    }

    #[tokio::test]
    async fn ghost_batch_rolls_back_events_and_projection_on_idempotency_conflict() {
        let store = SolandMemoryPersistenceStore::new();
        let applet_id = typed_id("ak:applet:");
        store.applets.records.lock().insert(
            applet_id.clone(),
            serde_json::json!({
                "status": "installed",
                "revoked_at": null,
                "ghosts": [],
            }),
        );
        let principal_id = "did:web:bridge.example";
        let idempotency_key = "ghost-batch-conflict";
        let now = Utc::now();
        store.idempotency_keys.data.lock().insert(
            (principal_id.to_owned(), idempotency_key.to_owned()),
            IdempotencyRecord {
                principal_id: principal_id.to_owned(),
                idempotency_key: idempotency_key.to_owned(),
                service_id: "did:web:soland.example".to_owned(),
                request_hash: "sha256:first".to_owned(),
                response_status: 201,
                response_body: serde_json::json!({"first": true}),
                created_at: now,
                expires_at: now + Duration::hours(1),
            },
        );
        let event_id = typed_id("ak:event:");
        let request = EventBatchCommitRequest {
            events: vec![event_request(
                event_id.clone(),
                typed_id("ak:realm:"),
                principal_id,
                Some(IdempotencyRecord {
                    principal_id: principal_id.to_owned(),
                    idempotency_key: idempotency_key.to_owned(),
                    service_id: "did:web:soland.example".to_owned(),
                    request_hash: "sha256:competing".to_owned(),
                    response_status: 201,
                    response_body: serde_json::json!({"first": false}),
                    created_at: now,
                    expires_at: now + Duration::hours(1),
                }),
            )],
            applet_ghosts: Some(AppletGhostCommit {
                applet_id: applet_id.clone(),
                ghost: serde_json::json!({
                    "ghost_actor_id": "did:web:bridge.example:ghost:one",
                    "external_id": "one",
                }),
            }),
        };

        assert!(store.commit_event_batch(request).await.is_err());
        assert!(!store.events.data.lock().contains_key(&event_id));
        assert_eq!(
            store.applets.records.lock()[&applet_id]["ghosts"],
            serde_json::json!([])
        );
    }

    #[tokio::test]
    async fn ghost_batch_appends_without_replacing_existing_ghosts() {
        let store = SolandMemoryPersistenceStore::new();
        let applet_id = typed_id("ak:applet:");
        store.applets.records.lock().insert(
            applet_id.clone(),
            serde_json::json!({
                "status": "installed",
                "revoked_at": null,
                "ghosts": [{
                    "ghost_actor_id": "did:web:bridge.example:ghost:first",
                    "external_id": "first",
                }],
            }),
        );
        let request = EventBatchCommitRequest {
            events: vec![event_request(
                typed_id("ak:event:"),
                typed_id("ak:realm:"),
                "did:web:bridge.example:ghost:second",
                None,
            )],
            applet_ghosts: Some(AppletGhostCommit {
                applet_id: applet_id.clone(),
                ghost: serde_json::json!({
                    "ghost_actor_id": "did:web:bridge.example:ghost:second",
                    "external_id": "second",
                }),
            }),
        };

        store.commit_event_batch(request).await.unwrap();
        assert_eq!(
            store.applets.records.lock()[&applet_id]["ghosts"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
    }
}
