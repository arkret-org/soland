//! Closed, caller-signed Applet Ghost provisioning Event aggregate.

use arkret_state::state::store::ControlProposalIngress;

use super::*;

struct PreparedGhostEvent {
    canonical_event: Event,
    command: soland_services::events::CommitAcceptedEventCommand,
    operation: Option<arkret_event_draft::ProjectedEventOperation>,
    projected_cell_writes: Vec<arkret_wire::cbs::ProjectedCellWrite>,
    projected_event: Option<soland_services::events::ProjectedEvent>,
    actor_id: String,
    realm_id: String,
    actor_seq: u64,
    event_id: String,
    device_id: String,
}

async fn prepare_ghost_event(
    state: &AppState,
    session: &SessionRecord,
    envelope: Value,
    admission: &InternalEventAdmission,
    preceding_events: &BTreeMap<String, (String, String, u64)>,
    preceding_prepared: &[PreparedGhostEvent],
) -> Result<PreparedGhostEvent, SubmitOneError> {
    let raw_bytes = serde_json::to_vec(&envelope).map_err(|_| {
        SubmitOneError::new(
            StatusCode::BAD_REQUEST,
            "json_invalid",
            "event envelope cannot be encoded",
        )
    })?;
    if arkret_wire::event_envelope::validate_event_envelope_byte_len(raw_bytes.len()).is_err() {
        return Err(SubmitOneError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "payload_too_large",
            "event envelope exceeds max_event_bytes",
        ));
    }
    let parsed =
        validate_event_envelope_with_context(state, session, &envelope, &[], Some(admission))
            .await?;
    let typed =
        serde_json::from_value::<arkret_wire::Event>(envelope.clone()).map_err(|error| {
            SubmitOneError::new(
                StatusCode::BAD_REQUEST,
                "schema_violation",
                format!("ghost provisioning Event envelope is invalid: {error}"),
            )
        })?;
    let service = state.event_queries();
    if let Some(existing) = service
        .canonical_event(parsed.event_id.as_str())
        .await
        .map_err(|error| {
            SubmitOneError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                format!("events store unavailable: {error}"),
            )
        })?
    {
        if existing.canonical_bytes == parsed.canonical_bytes {
            return Err(SubmitOneError::new(
                StatusCode::CONFLICT,
                "duplicate",
                "ghost provisioning Event already exists",
            ));
        }
        let record = super::identity_anchor::canonical_record(&parsed, envelope.clone(), now());
        return Err(quarantine_verified_event_collision(state, record).await);
    }
    let scoped_actor_records = service
        .canonical_events_for_realm_actor(parsed.realm_id.as_str(), &parsed.actor.to_string())
        .await
        .map_err(|error| {
            SubmitOneError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                format!("events store unavailable: {error}"),
            )
        })?;
    if let Some(max_seq) = scoped_actor_records
        .iter()
        .map(|record| record.actor_seq)
        .max()
        && parsed.actor_seq < max_seq
    {
        return Err(SubmitOneError::new(
            StatusCode::CONFLICT,
            "cas_conflict",
            "actor_seq is older than the accepted actor frontier",
        ));
    }
    let mut max_actor_predecessor_seq = None;
    for prev_ref in &parsed.prev_refs {
        let predecessor = service
            .canonical_event(prev_ref.as_str())
            .await
            .map_err(|error| {
                SubmitOneError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    format!("events store unavailable: {error}"),
                )
            })?;
        let Some(predecessor) = predecessor else {
            if let Some((realm_id, actor_id, actor_seq)) = preceding_events.get(prev_ref.as_str()) {
                if realm_id != parsed.realm_id.as_str() {
                    return Err(SubmitOneError::new(
                        StatusCode::BAD_REQUEST,
                        "schema_violation",
                        "prev_refs must not reference a staged Event in another Realm",
                    ));
                }
                if actor_id == &parsed.actor.to_string() {
                    max_actor_predecessor_seq = Some(
                        max_actor_predecessor_seq
                            .map_or(*actor_seq, |current: u64| current.max(*actor_seq)),
                    );
                }
                continue;
            }
            return Err(SubmitOneError::new(
                StatusCode::CONFLICT,
                "dependency_missing",
                "prev_refs must reference accepted events",
            ));
        };
        if predecessor.realm_id.as_deref() != Some(parsed.realm_id.as_str()) {
            return Err(SubmitOneError::new(
                StatusCode::BAD_REQUEST,
                "schema_violation",
                "prev_refs must not reference an Event in another Realm",
            ));
        }
        if predecessor.actor_id == parsed.actor.to_string() {
            max_actor_predecessor_seq = Some(
                max_actor_predecessor_seq.map_or(predecessor.actor_seq, |current: u64| {
                    current.max(predecessor.actor_seq)
                }),
            );
        }
    }
    if max_actor_predecessor_seq
        .is_some_and(|predecessor_seq| predecessor_seq.checked_add(1) != Some(parsed.actor_seq))
        || (max_actor_predecessor_seq.is_none() && parsed.actor_seq != 0)
    {
        return Err(SubmitOneError::new(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            "prev_refs must include the preceding actor sequence in the same Realm",
        ));
    }
    enforce_sibling_fork_limit(state, session, &parsed, &scoped_actor_records).await?;

    let received_at = now();
    let mut operation = projection_operation_from_event(&parsed, &envelope);
    // The reducer preflight below reads the receiver's own registry-derived
    // writes; v1 has no producer `effects[]` to take them from.
    let (projected_cell_writes, _) = derive_submit_cell_writes(state, &parsed, &typed).await?;
    if let Some(operation) = operation.as_ref() {
        let mut aggregate_operations = preceding_prepared
            .iter()
            .filter_map(|event| event.operation.clone())
            .collect::<Vec<_>>();
        aggregate_operations.push(operation.clone());
        validate_operation_semantics(state, &aggregate_operations)
            .map_err(SubmitOneError::semantic_schema_violation)?;
        validate_operation_policy_with_plaintext_service_binding(
            state,
            &aggregate_operations,
            true,
        )
        .await
        .map_err(|message| {
            let (status, code) =
                crate::routing::events::operations::operation_policy_reason_code(message);
            SubmitOneError::new(status, code, message)
        })?;
        let projection = state.projections().snapshot();
        projection
            .check_move_preconditions(operation)
            .map_err(|reason| {
                let (code, message) = cbs_bottom_reject(reason);
                let error = SubmitOneError::new(StatusCode::PRECONDITION_FAILED, code, message);
                if reason == "cell_bottom_state" {
                    error.with_details(serde_json::json!({ "reason_code": "cell_in_bottom_state" }))
                } else {
                    error
                }
            })?;
        let preceding_operations = preceding_prepared.iter().filter_map(|event| {
            event
                .operation
                .as_ref()
                .map(|operation| (operation, event.projected_cell_writes.as_slice()))
        });
        let current_operation = std::iter::once((operation, projected_cell_writes.as_slice()));
        if let Some(reason) = state
            .projections()
            .preflight_projected_batch_rejection(preceding_operations.chain(current_operation))
        {
            return Err(SubmitOneError::new(
                StatusCode::PRECONDITION_FAILED,
                reason.clone(),
                reason,
            ));
        }
    }
    if let Some(operation) = operation.as_mut() {
        stamp_projection_operation_received_at(operation, received_at);
    }
    let is_applet_managed_pcr_genesis = parsed.kind == arkret_wire::EventKind::RealmCreate.as_str()
        && typed
            .payload
            .get("object")
            .and_then(Value::as_object)
            .and_then(|genesis| genesis.get("purpose"))
            .and_then(Value::as_str)
            == Some("applet_managed_control")
        && admission.is_applet_formal()
        && envelope
            .as_object()
            .is_some_and(|object| admission.matches(session, object));
    let control_event_for_proposal = Some(typed.clone())
        .filter(|event| event.kind.is_control_plane() && !is_applet_managed_pcr_genesis);
    let control_proposal_ack = if is_applet_managed_pcr_genesis {
        let mut acks = crate::control_proposal::mint_control_proposal_acks(
            state,
            &typed.realm_id,
            std::slice::from_ref(&typed),
            std::slice::from_ref(&parsed.digest_suite),
            received_at,
            None,
        )
        .await
        .map_err(|error| {
            SubmitOneError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "quorum_unreachable",
                format!("Applet-managed PCR genesis Control Proposal Ack unavailable: {error}"),
            )
        })?;
        if acks.len() != 1 {
            return Err(SubmitOneError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "Applet-managed PCR genesis must mint exactly one Control Proposal Ack",
            ));
        }
        acks.pop()
    } else if let Some(event) = control_event_for_proposal.as_ref() {
        let realm_id = parsed.realm_id.clone();
        let worker = crate::notary::NotaryWorker::for_service(state.service_id().clone());
        let (_, authority_set_ref) = worker
            .current_notary_value_for_events(state, &realm_id, std::slice::from_ref(event))
            .await
            .map_err(|error| {
                SubmitOneError::new(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "quorum_unreachable",
                    format!("Control Proposal authority is unavailable: {error}"),
                )
            })?
            .ok_or_else(|| {
                SubmitOneError::new(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "quorum_unreachable",
                    "current proposal authority profile is unavailable",
                )
            })?;
        let proposal_digest = Hash::new(parsed.canonical_digest.clone()).map_err(|error| {
            SubmitOneError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                format!("validated Control Move digest is invalid: {error}"),
            )
        })?;
        let policy = crate::control_proposal::control_proposal_policy(
            state,
            &realm_id,
            std::slice::from_ref(event),
        )
        .await
        .map_err(|error| {
            SubmitOneError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "quorum_unreachable",
                format!("Control Proposal policy is unavailable: {error}"),
            )
        })?;
        worker
            .authority_set_ref_for_events(state, &realm_id, std::slice::from_ref(event))
            .await
            .map_err(|error| {
                SubmitOneError::new(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "quorum_unreachable",
                    format!("Control Proposal authority is unavailable: {error}"),
                )
            })?
            .ok_or_else(|| {
                SubmitOneError::new(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "quorum_unreachable",
                    "this service cannot issue the current authority set's Control Proposal Ack",
                )
            })?;
        Some(
            crate::control_proposal::mint_control_proposal_ack(
                state,
                realm_id,
                proposal_digest,
                authority_set_ref,
                received_at,
                policy,
            )
            .map_err(|error| {
                SubmitOneError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    format!("Control Proposal Ack signing failed: {error}"),
                )
            })?,
        )
    } else {
        None
    };
    let projected_event = operation.as_ref().map(|operation| {
        crate::routing::events::projection::projection_event_from_operation(
            operation,
            Some(&parsed.actor.to_string()),
        )
    });
    // Applet-managed authority creation is Station-local. The unit
    // spans the portal registration lineage and the actor's new PCR, so
    // splitting it into ordinary per-Event federation deliveries would lose
    // its closed aggregate admission and would let a remote peer observe a
    // partial authority. Peers learn later collaboration facts through their
    // normal Realm events; the immutable provision/PCR authority remains on
    // the exact actor_station_id named by the unit.
    let outbox = Vec::new();
    let device_id = parsed.device_id_str().to_owned();
    let command = soland_services::events::CommitAcceptedEventCommand {
        replicated: false,
        membership_compensation_evidence: None,
        governance_dependencies: Vec::new(),
        device_pairing_authorization: None,
        contact_projection: None,
        consent_projection: None,
        event: soland_services::events::AcceptedEvent {
            event_id: parsed.event_id.to_string(),
            actor_id: parsed.actor.to_string(),
            actor_seq: parsed.actor_seq,
            realm_id: Some(parsed.realm_id.to_string()),
            kind: parsed.kind,
            schema_id: parsed.schema_id,
            digest_suite: parsed.digest_suite,
            canonical_digest: parsed.canonical_digest,
            canonical_bytes: parsed.canonical_bytes,
            envelope,
            received_at,
        },
        control_proposal_ingress: control_proposal_ack.map(ControlProposalIngress::AckRequired),
        device_revocation_transition: None,
        device_revocation_gate: None,
        projections: projected_event
            .iter()
            .map(|event| soland_services::events::ProjectedEvent {
                event_id: event.event_id.clone(),
                realm_id: event.realm_id.clone(),
                event_kind: event.event_kind.clone(),
                operation_kind: event.operation_kind.clone(),
                operation_id: event.operation_id.clone(),
                sender: event.sender.clone(),
                payload: event.payload.clone(),
                created_at: event.created_at,
                received_at: event.received_at,
            })
            .collect(),
        idempotency: None,
        deliveries: outbox,
    };
    Ok(PreparedGhostEvent {
        canonical_event: typed,
        command,
        operation,
        projected_cell_writes,
        projected_event,
        actor_id: parsed.actor.to_string(),
        realm_id: parsed.realm_id.to_string(),
        actor_seq: parsed.actor_seq,
        event_id: parsed.event_id.to_string(),
        device_id: device_id.to_owned(),
    })
}

async fn submit_applet_record_event_batch(
    state: &AppState,
    events: Vec<Event>,
    applet_id: arkret_wire::AppletId,
    target_station_id: arkret_wire::DidCoreId,
    expected_applet_identity: Option<Value>,
    applet_identity: Value,
    staged_producer_authority: Option<(arkret_wire::DidUrl, arkret_wire::DidKey)>,
    expected_applet_record: Option<Value>,
    applet_record: Value,
    authoring_preview_subject_key: String,
    authoring_request_digest: String,
    idempotency: EventCommitIdempotency,
    response_body: Value,
    response_status: StatusCode,
) -> Result<(), SubmitOneError> {
    if events.is_empty() {
        return Err(SubmitOneError::new(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            "Applet formal Event unit must not be empty",
        ));
    }
    let mut lock_keys = events
        .iter()
        .map(|event| (event.realm_id.to_string(), event.actor_id.to_string()))
        .collect::<Vec<_>>();
    lock_keys.sort();
    lock_keys.dedup();
    let locks = lock_keys
        .iter()
        .map(|(realm, actor)| actor_submit_lock(realm, actor))
        .collect::<Vec<_>>();
    let mut guards = Vec::with_capacity(locks.len());
    for lock in &locks {
        guards.push(lock.lock().await);
    }

    let mut preceding_events = BTreeMap::new();
    let provision_time = now();
    let session = |actor: &str| SessionRecord {
        token_hash: "applet-ghost-provision".to_owned(),
        account_pk: None,
        actor: actor.to_owned(),
        // Service session: an applet owns no device (see `applet_event_session`).
        device_id: String::new(),
        audience: state.service_id().clone(),
        session_public_key: None,
        agent_session: None,
        session_grant: None,
        expires_at: provision_time + Duration::minutes(5),
        created_at: provision_time,
        revoked_at: None,
    };
    let mut prepared = Vec::with_capacity(events.len());
    for event in events {
        let actor_id = event.actor_id.clone();
        let realm_id = event.realm_id.to_string();
        let kind = event.kind.as_str().to_owned();
        let envelope = typed_event_to_canonical_value(event)?;
        let admission = InternalEventAdmission::applet_formal(
            realm_id.as_str(),
            actor_id.clone(),
            kind.as_str(),
            event_string_field_from_value(&envelope, "event_id").unwrap_or_default(),
            applet_id.clone(),
            staged_producer_authority.clone(),
        );
        let next = prepare_ghost_event(
            state,
            &session(actor_id.signing_principal_id().as_str()),
            envelope,
            &admission,
            &preceding_events,
            &prepared,
        )
        .await?;
        preceding_events.insert(
            next.event_id.clone(),
            (next.realm_id.clone(), next.actor_id.clone(), next.actor_seq),
        );
        prepared.push(next);
    }
    let created_at = now();
    prepared[0].command.idempotency = Some(soland_services::events::IdempotentResponse {
        authenticated_actor: idempotency.authenticated_actor,
        operation_id: idempotency.operation_id,
        key: idempotency.key,
        request_hash: idempotency.request_hash,
        status: response_status.as_u16() as i32,
        body: response_body,
        created_at,
        expires_at: created_at + Duration::seconds(IDEMPOTENCY_KEY_TTL_SECONDS),
    });
    state
        .events()
        .commit_accepted_event_batch(soland_services::events::CommitAcceptedEventBatchCommand {
            events: prepared.iter().map(|event| event.command.clone()).collect(),
            agent_approval_nonce: None,
            franking_replay_nonce: None,
            applet_record: Some(soland_services::events::CommitAppletRecord {
                applet_id,
                identity: soland_services::events::CommitAppletIdentity {
                    target_station_id,
                    expected_record: expected_applet_identity,
                    record: applet_identity,
                },
                expected_record: expected_applet_record,
                record: applet_record,
            }),
            applet_authoring_preview: Some(soland_services::events::CommitAppletAuthoringPreview {
                subject_key: authoring_preview_subject_key,
                request_digest: authoring_request_digest,
            }),
            agent_membership_cascade: None,
        })
        .await
        .map_err(|error| {
            if let Some(collision) = map_event_hash_collision(
                prepared
                    .first()
                    .map(|event| event.command.event.event_id.clone())
                    .unwrap_or_default(),
                &error,
            ) {
                return collision;
            }
            let detail = error.detail();
            let code = if error.is_conflict_kind() {
                // Route on the registered code, never on the diagnostic text.
                match error.conflict_code() {
                    Some(ConflictCode::DuplicateConflict) => "duplicate_conflict",
                    Some(ConflictCode::AppletRevoked) => "applet_revoked",
                    Some(ConflictCode::CasConflict) => "cas_conflict",
                    _ => "failed_precondition",
                }
            } else {
                "internal_error"
            };
            SubmitOneError::new(
                if error.is_conflict_kind() {
                    StatusCode::CONFLICT
                } else {
                    StatusCode::INTERNAL_SERVER_ERROR
                },
                code,
                detail,
            )
        })?;
    for event in prepared.drain(..) {
        if let Some(operation) = event.operation.as_ref() {
            crate::routing::events::projection::project_accepted_canonical_event_from_device(
                state,
                &event.actor_id,
                &event.device_id,
                operation,
                &event.projected_cell_writes,
            )
            .await;
        }
        if (event.canonical_event.kind == arkret_wire::EventKind::RealmCreate
            || event.canonical_event.kind == arkret_wire::EventKind::IdentityResolutionUpdate)
            && let Err(error) =
                persist_principal_resolution_projection(state, &event.canonical_event).await
        {
            // `principal_resolutions` is a rebuildable read index. The canonical
            // Event and its reducer cells are already durable, so a mirror
            // failure is repairable by canonical replay and must never turn an
            // accepted aggregate into an apparent rejection.
            tracing::error!(
                %error,
                event_id = %event.event_id,
                "applet managed actor resolution read-index update failed"
            );
        }
        if let Some(projected) = event.projected_event {
            let _ = state.publish_event_notification(crate::state::EventNotification::event(
                projected.realm_id.clone(),
                projected.event_id.clone(),
                crate::routing::events::projection::projection_event_json(&projected),
            ));
        }
    }
    drop(guards);
    Ok(())
}

pub(in crate::routing) async fn submit_ghost_provision_batch(
    state: &AppState,
    service_id: &str,
    ghost_actor_id: &str,
    realm_id: &str,
    managed_provision: Event,
    pcr_genesis: Event,
    accountability: Event,
    profile: Event,
    applet_id: arkret_wire::AppletId,
    target_station_id: arkret_wire::DidCoreId,
    applet_identity: Value,
    producer_verification_method: arkret_wire::DidUrl,
    producer_signing_key: arkret_wire::DidKey,
    expected_applet_record: Value,
    applet_record: Value,
    authoring_preview_subject_key: String,
    authoring_request_digest: String,
    idempotency: EventCommitIdempotency,
    response_body: Value,
) -> Result<(), SubmitOneError> {
    if managed_provision.actor_id.signing_principal_id().as_str() != service_id
        || pcr_genesis.actor_id.signing_principal_id().as_str() != ghost_actor_id
        || accountability.realm_id.as_str() != realm_id
        || profile.realm_id.as_str() != realm_id
    {
        return Err(SubmitOneError::new(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            "Ghost formal Event unit actor or Realm binding differs from the validated request",
        ));
    }
    submit_applet_record_event_batch(
        state,
        vec![managed_provision, pcr_genesis, accountability, profile],
        applet_id,
        target_station_id,
        Some(applet_identity.clone()),
        applet_identity,
        Some((producer_verification_method, producer_signing_key)),
        Some(expected_applet_record),
        applet_record,
        authoring_preview_subject_key,
        authoring_request_digest,
        idempotency,
        response_body,
        StatusCode::CREATED,
    )
    .await
}

pub(in crate::routing) async fn submit_applet_install_batch(
    state: &AppState,
    events: Vec<Event>,
    applet_id: arkret_wire::AppletId,
    target_station_id: arkret_wire::DidCoreId,
    expected_applet_identity: Option<Value>,
    applet_identity: Value,
    producer_verification_method: arkret_wire::DidUrl,
    producer_signing_key: arkret_wire::DidKey,
    applet_record: Value,
    authoring_preview_subject_key: String,
    authoring_request_digest: String,
    idempotency: EventCommitIdempotency,
    response_body: Value,
) -> Result<(), SubmitOneError> {
    submit_applet_record_event_batch(
        state,
        events,
        applet_id,
        target_station_id,
        expected_applet_identity,
        applet_identity,
        Some((producer_verification_method, producer_signing_key)),
        None,
        applet_record,
        authoring_preview_subject_key,
        authoring_request_digest,
        idempotency,
        response_body,
        StatusCode::CREATED,
    )
    .await
}
