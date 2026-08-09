use async_trait::async_trait;
use soland_storage::{
    EventBatchCommitRequest, EventCommitOutcome, EventCommitRequest, EventCommitUnitOfWork,
    PersistenceError, PersistenceResult, ids,
};

use crate::SolandMemoryPersistenceStore;
use crate::events::quarantine_memory_event;
#[cfg(feature = "fault-injection")]
use crate::{FaultPoint, FaultTiming};

fn stage_control_proposal_ack(
    staged: &mut std::collections::BTreeMap<String, arkret_wire::ControlProposalAck>,
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
    // `seal_basis` or from the presence of a Control Proposal Ack.
    let is_control_move =
        event.kind.is_reducer_input() && event.seal_ref.is_none() && event.auth_context.is_none();
    if !is_control_move {
        if request.control_proposal_ack.is_some() || request.self_principal_pcr_device_authorized {
            return Err(PersistenceError::Conflict(
                "schema_violation: non-Control Event cannot carry Control Proposal authority"
                    .to_owned(),
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
    if request.self_principal_pcr_device_authorized {
        if request.control_proposal_ack.is_some()
            || !soland_storage::has_self_principal_pcr_device_authorized_shape(&event)
        {
            return Err(PersistenceError::Conflict(
                "schema_violation: invalid self-principal PCR device-authorized Control Move"
                    .to_owned(),
            ));
        }
        return Ok(());
    }
    let ack = request.control_proposal_ack.as_ref().ok_or_else(|| {
        PersistenceError::Conflict(
            "schema_violation: accepted Control Move is missing Control Proposal Ack".to_owned(),
        )
    })?;
    ack.validate_protocol_bounds().map_err(|error| {
        PersistenceError::Conflict(format!(
            "schema_violation: invalid Control Proposal Ack: {error}"
        ))
    })?;
    if ack.proposal_digest.as_str() != event_digest || ack.realm_id != event.realm_id {
        return Err(PersistenceError::Conflict(
            "schema_violation: Control Proposal Ack does not bind Control Move".to_owned(),
        ));
    }
    if let Some(existing) = staged.get(&request.event.event_id)
        && existing != ack
    {
        return Err(PersistenceError::Conflict(
            "duplicate_conflict: Control Move has a different Control Proposal Ack".to_owned(),
        ));
    }
    staged.insert(request.event.event_id.clone(), ack.clone());
    Ok(())
}

fn stage_canonical_event(
    staged: &mut std::collections::BTreeMap<String, soland_storage::CanonicalEventRecord>,
    event: soland_storage::CanonicalEventRecord,
) -> PersistenceResult<()> {
    ids::validated_event_identity_parts(
        &event.event_id,
        &event.canonical_digest,
        &event.canonical_bytes,
    )?;
    if let Some(existing) = staged.get(&event.event_id) {
        let reason = if existing.canonical_bytes == event.canonical_bytes {
            "duplicate_conflict"
        } else {
            "event_hash_collision"
        };
        return Err(PersistenceError::Conflict(reason.to_owned()));
    }
    staged.insert(event.event_id.clone(), event);
    Ok(())
}

fn stage_projection_event(
    staged: &mut Vec<soland_storage::ProjectionEventRecord>,
    projection: soland_storage::ProjectionEventRecord,
) -> PersistenceResult<bool> {
    if let Some(existing) = staged
        .iter()
        .find(|existing| existing.event_id == projection.event_id)
    {
        if existing.realm_id == projection.realm_id
            && existing.event_kind == projection.event_kind
            && existing.operation_kind == projection.operation_kind
            && existing.operation_id == projection.operation_id
            && existing.sender == projection.sender
            && existing.payload == projection.payload
            && existing.created_at == projection.created_at
            && existing.received_at == projection.received_at
        {
            return Ok(false);
        }
        return Err(PersistenceError::Conflict(
            "duplicate_conflict: projection differs for Event identity".to_owned(),
        ));
    }
    staged.push(projection);
    Ok(true)
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
        let mut quarantined = self.events.quarantined.lock();
        let mut collision_variants = self.events.collision_variants.lock();
        let mut control_proposal_acks = self.events.control_proposal_acks.lock();
        let mut projections = self.projection_events.data.lock();
        let mut idempotency = self.idempotency_keys.data.lock();
        let mut event_outbox_ids = self.events.event_outbox_ids.lock();
        let mut outbox = self.federation_outbox.data.lock();

        let mut staged_events = events.clone();
        let mut staged_control_proposal_acks = control_proposal_acks.clone();
        let mut staged_projections = projections.clone();
        let mut staged_idempotency = idempotency.clone();
        let mut staged_outbox = outbox.clone();

        ids::validated_event_identity_parts(
            &request.event.event_id,
            &request.event.canonical_digest,
            &request.event.canonical_bytes,
        )?;
        if quarantined.contains_key(&request.event.event_id) {
            if collision_variants
                .get(&request.event.event_id)
                .is_some_and(|variants| {
                    variants
                        .iter()
                        .any(|variant| variant.canonical_bytes == request.event.canonical_bytes)
                })
            {
                return Err(PersistenceError::Conflict(
                    "event_hash_collision".to_owned(),
                ));
            }
            quarantine_memory_event(
                &mut events,
                &mut quarantined,
                &mut collision_variants,
                &mut projections,
                &event_outbox_ids,
                &mut outbox,
                request.event,
            );
            return Err(PersistenceError::Conflict(
                "event_hash_collision".to_owned(),
            ));
        }
        if let Some(existing) = staged_events.get(&request.event.event_id) {
            if existing.canonical_bytes != request.event.canonical_bytes {
                quarantine_memory_event(
                    &mut events,
                    &mut quarantined,
                    &mut collision_variants,
                    &mut projections,
                    &event_outbox_ids,
                    &mut outbox,
                    request.event,
                );
                return Err(PersistenceError::Conflict(
                    "event_hash_collision".to_owned(),
                ));
            }
            return Ok(EventCommitOutcome {
                event_inserted: false,
                projections_inserted: 0,
                outbox_inserted: 0,
            });
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
        stage_control_proposal_ack(&mut staged_control_proposal_acks, &request)?;
        let event_id = request.event.event_id.clone();
        stage_canonical_event(&mut staged_events, request.event)?;

        let mut projections_inserted = 0;
        for projection in request.projections {
            ids::parse_event_id(&projection.event_id).ok_or_else(|| {
                PersistenceError::SchemaViolation(format!(
                    "malformed canonical Event id: {:?}",
                    projection.event_id
                ))
            })?;
            arkret_wire::RealmId::new(projection.realm_id.clone()).map_err(|_| {
                PersistenceError::SchemaViolation(format!(
                    "malformed Realm id: {:?}",
                    projection.realm_id
                ))
            })?;
            if let Some(operation_id) = projection.operation_id.as_deref() {
                ids::typed_uuid_part_or_schema_violation(operation_id)?;
            }
            if stage_projection_event(&mut staged_projections, projection)? {
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
                event_outbox_ids
                    .entry(event_id.clone())
                    .or_default()
                    .insert(record.id.clone());
                staged_outbox.insert(record.id.clone(), record);
                outbox_inserted += 1;
            }
        }

        *events = staged_events;
        *control_proposal_acks = staged_control_proposal_acks;
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
        let mut quarantined = self.events.quarantined.lock();
        let mut collision_variants = self.events.collision_variants.lock();
        let mut control_proposal_acks = self.events.control_proposal_acks.lock();
        let mut projections = self.projection_events.data.lock();
        let mut idempotency = self.idempotency_keys.data.lock();
        let mut event_outbox_ids = self.events.event_outbox_ids.lock();
        let mut outbox = self.federation_outbox.data.lock();
        let mut applets = self.applets.records.lock();

        let mut staged_events = events.clone();
        let mut staged_control_proposal_acks = control_proposal_acks.clone();
        let mut staged_projections = projections.clone();
        let mut staged_idempotency = idempotency.clone();
        let mut staged_outbox = outbox.clone();
        let mut staged_event_outbox_ids = event_outbox_ids.clone();
        let mut staged_applets = applets.clone();
        let mut event_inserted = false;
        let mut projections_inserted = 0;
        let mut outbox_inserted = 0;

        for event_request in request.events {
            ids::validated_event_identity_parts(
                &event_request.event.event_id,
                &event_request.event.canonical_digest,
                &event_request.event.canonical_bytes,
            )?;
            if quarantined.contains_key(&event_request.event.event_id) {
                if collision_variants
                    .get(&event_request.event.event_id)
                    .is_some_and(|variants| {
                        variants.iter().any(|variant| {
                            variant.canonical_bytes == event_request.event.canonical_bytes
                        })
                    })
                {
                    return Err(PersistenceError::Conflict(
                        "event_hash_collision".to_owned(),
                    ));
                }
                quarantine_memory_event(
                    &mut events,
                    &mut quarantined,
                    &mut collision_variants,
                    &mut projections,
                    &event_outbox_ids,
                    &mut outbox,
                    event_request.event,
                );
                return Err(PersistenceError::Conflict(
                    "event_hash_collision".to_owned(),
                ));
            }
            if let Some(existing) = staged_events.get(&event_request.event.event_id) {
                if existing.canonical_bytes != event_request.event.canonical_bytes {
                    if !events.contains_key(&event_request.event.event_id) {
                        events.insert(event_request.event.event_id.clone(), existing.clone());
                    }
                    quarantine_memory_event(
                        &mut events,
                        &mut quarantined,
                        &mut collision_variants,
                        &mut projections,
                        &event_outbox_ids,
                        &mut outbox,
                        event_request.event,
                    );
                    return Err(PersistenceError::Conflict(
                        "event_hash_collision".to_owned(),
                    ));
                }
                continue;
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
            stage_control_proposal_ack(&mut staged_control_proposal_acks, &event_request)?;
            let event_id = event_request.event.event_id.clone();
            stage_canonical_event(&mut staged_events, event_request.event)?;
            event_inserted = true;

            for projection in event_request.projections {
                ids::parse_event_id(&projection.event_id).ok_or_else(|| {
                    PersistenceError::SchemaViolation(format!(
                        "malformed canonical Event id: {:?}",
                        projection.event_id
                    ))
                })?;
                arkret_wire::RealmId::new(projection.realm_id.clone()).map_err(|_| {
                    PersistenceError::SchemaViolation(format!(
                        "malformed Realm id: {:?}",
                        projection.realm_id
                    ))
                })?;
                if let Some(operation_id) = projection.operation_id.as_deref() {
                    ids::typed_uuid_part_or_schema_violation(operation_id)?;
                }
                if stage_projection_event(&mut staged_projections, projection)? {
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
                    staged_event_outbox_ids
                        .entry(event_id.clone())
                        .or_default()
                        .insert(record.id.clone());
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
        *control_proposal_acks = staged_control_proposal_acks;
        *projections = staged_projections;
        *idempotency = staged_idempotency;
        *outbox = staged_outbox;
        *event_outbox_ids = staged_event_outbox_ids;
        *applets = staged_applets;

        #[cfg(feature = "fault-injection")]
        self.fault_injector
            .check(FaultPoint::EventCommit, FaultTiming::After)?;
        Ok(EventCommitOutcome {
            event_inserted,
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
        EventCommitUnitOfWork, IdempotencyRecord, PersistenceError,
    };

    use super::stage_control_proposal_ack;
    use crate::SolandMemoryPersistenceStore;

    fn typed_id(prefix: &str) -> String {
        format!("{prefix}{}", uuid::Uuid::now_v7())
    }

    fn realm_id() -> String {
        let digest = arkret_wire::Hash::new(arkret_canonical::sha256_digest(
            uuid::Uuid::now_v7().as_bytes(),
        ))
        .unwrap();
        arkret_wire::RealmId::from_event_id(
            &arkret_wire::EventId::from_event_digest(&digest).unwrap(),
        )
        .to_string()
    }

    fn event_request(
        event_seed: String,
        realm_id: String,
        actor_id: &str,
        idempotency: Option<IdempotencyRecord>,
    ) -> EventCommitRequest {
        let event = arkret_wire::Event::new_with_derived_id_at(
            "ak.test.data",
            arkret_wire::ScopeRef::Realm {
                realm_id: arkret_wire::RealmId::new(realm_id.clone()).unwrap(),
            },
            arkret_wire::Did::new(actor_id.to_owned()).unwrap(),
            0,
            arkret_wire::Hlc::new("019f00000000-0000-00000001").unwrap(),
            serde_json::json!({"seed": event_seed}),
            Utc::now(),
        )
        .unwrap();
        let event_id = event.event_id.as_str().to_owned();
        let canonical_digest = event.event_digest().unwrap();
        let envelope = serde_json::to_value(&event).unwrap();
        let canonical_bytes =
            arkret_canonical::canonical_json_bytes(&event.digest_payload().unwrap()).unwrap();
        EventCommitRequest {
            event: CanonicalEventRecord {
                event_id: event_id.clone(),
                actor_id: actor_id.to_owned(),
                actor_seq: 0,
                realm_id: Some(realm_id),
                kind: "ak.test.data".to_owned(),
                schema_id: "arkret://events/profile/create/v1".to_owned(),
                canonical_digest,
                canonical_bytes,
                envelope,
                received_at: Utc::now(),
            },
            control_proposal_ack: None,
            self_principal_pcr_device_authorized: false,
            projections: Vec::new(),
            idempotency,
            outbox: Vec::new(),
        }
    }

    fn self_principal_pcr_control_request() -> EventCommitRequest {
        let actor_id = "did:web:alice.example";
        let realm_id = arkret_wire::principal_control_realm_id(actor_id).to_string();
        let created_at = Utc::now();
        let mut event = arkret_wire::Event::new_with_derived_id_at(
            arkret_wire::EventKind::CONTACT_REQUESTED,
            arkret_wire::ScopeRef::Realm {
                realm_id: arkret_wire::RealmId::new(realm_id.clone()).unwrap(),
            },
            arkret_wire::Did::new(actor_id.to_owned()).unwrap(),
            0,
            arkret_wire::Hlc::new("019f00000000-0000-00000001").unwrap(),
            serde_json::json!({"contact_id": "ak:contact:test"}),
            created_at,
        )
        .unwrap();
        event.seal_basis = Some(arkret_wire::SealBasis {
            leaves: vec![
                arkret_wire::SealId::new(format!("ak:seal:sha256:{}", "a".repeat(64))).unwrap(),
            ],
        });
        event.event_id = event.derive_event_id().unwrap();
        let event_digest = arkret_wire::Hash::new(event.event_digest().unwrap()).unwrap();
        event.proofs = vec![arkret_wire::Proof {
            kind: arkret_wire::proof_kind::DETACHED_JWS.to_owned(),
            proof_purpose: None,
            verification_method: arkret_wire::DidUrl::new(format!(
                "{actor_id}#ak:device:01904100-0000-7000-8000-000000000001"
            ))
            .unwrap(),
            event_digest: event_digest.clone(),
            created_at,
            domain: None,
            audience: None,
            jws: "fixture.signature".to_owned(),
        }];
        let event_id = event.event_id.to_string();
        let canonical_bytes =
            arkret_canonical::canonical_json_bytes(&event.digest_payload().unwrap()).unwrap();
        EventCommitRequest {
            event: CanonicalEventRecord {
                event_id,
                actor_id: actor_id.to_owned(),
                actor_seq: event.actor_seq,
                realm_id: Some(realm_id),
                kind: event.kind.to_string(),
                schema_id: "arkret://events/contact/requested/v1".to_owned(),
                canonical_digest: event_digest.to_string(),
                canonical_bytes,
                envelope: serde_json::to_value(event).unwrap(),
                received_at: created_at,
            },
            control_proposal_ack: None,
            self_principal_pcr_device_authorized: true,
            projections: Vec::new(),
            idempotency: None,
            outbox: Vec::new(),
        }
    }

    #[test]
    fn self_principal_pcr_device_authority_is_the_only_ackless_control_shape() {
        let request = self_principal_pcr_control_request();
        let mut staged = std::collections::BTreeMap::new();
        stage_control_proposal_ack(&mut staged, &request)
            .expect("current Human PCR device proof is sufficient proposal authority");
        assert!(
            staged.is_empty(),
            "Ack-less PCR move must not synthesize an Ack"
        );

        let mut missing_flag = request.clone();
        missing_flag.self_principal_pcr_device_authorized = false;
        assert!(matches!(
            stage_control_proposal_ack(&mut staged, &missing_flag),
            Err(PersistenceError::Conflict(reason))
                if reason.contains("missing Control Proposal Ack")
        ));

        let mut delegated = request;
        let mut event: arkret_wire::Event =
            serde_json::from_value(delegated.event.envelope.clone()).unwrap();
        event.executed_by = Some(arkret_wire::Did::new("did:web:controller.example").unwrap());
        delegated.event.canonical_digest = event.event_digest().unwrap();
        delegated.event.envelope = serde_json::to_value(event).unwrap();
        assert!(matches!(
            stage_control_proposal_ack(&mut staged, &delegated),
            Err(PersistenceError::Conflict(reason))
                if reason.contains("invalid self-principal PCR device-authorized")
        ));
    }

    #[tokio::test]
    async fn exact_replay_is_noop_but_forged_preimage_is_rejected_before_lookup() {
        let store = SolandMemoryPersistenceStore::new();
        let request = event_request(
            "exact-replay".to_owned(),
            realm_id(),
            "did:web:replay.example",
            None,
        );
        store
            .events
            .data
            .lock()
            .insert(request.event.event_id.clone(), request.event.clone());

        let replay = store.commit_event(request.clone()).await.unwrap();
        assert_eq!(replay, soland_storage::EventCommitOutcome::default());

        let event_id = request.event.event_id.clone();
        let mut collision = request;
        collision.event.canonical_bytes.push(0);
        let error = store.commit_event(collision).await.unwrap_err();
        assert!(matches!(
            error,
            PersistenceError::Conflict(reason) if reason == "event_id_digest_mismatch"
        ));
        assert!(store.events.data.lock().contains_key(&event_id));
        assert!(store.events.quarantined.lock().is_empty());
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
                realm_id(),
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
                realm_id(),
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
