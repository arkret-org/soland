use super::identity_anchor::{
    canonical_record, identical_historical_retry, identical_historical_retry_without_wake,
};
use super::*;

pub(super) struct DirectConversationFoundingCommitContext {
    pub slot: soland_storage::DirectConversationFoundingSlotRecord,
    pub receipt: DirectConversationFoundingAcceptanceReceipt,
    pub founding_authority_evidence:
        arkret_models_collaboration::direct_conversation_ops::DirectConversationFoundingAuthorityEvidence,
}

pub(super) fn batch_begins_realm_create(envelopes: &[Value]) -> bool {
    event_string_field_from_value(envelopes.first().unwrap_or(&Value::Null), "kind").as_deref()
        == Some(arkret_wire::EventKind::RealmCreate.as_str())
}

fn bootstrap_error(
    error: arkret_policy::realm_bootstrap::RealmBootstrapValidationError,
) -> SubmitOneError {
    let reason = error.reason_code();
    if matches!(reason, "effects_payload_mismatch" | "plane_cross_write") {
        SubmitOneError::semantic_schema_violation(reason)
    } else {
        SubmitOneError::new(
            StatusCode::PRECONDITION_FAILED,
            "failed_precondition",
            reason,
        )
    }
}

pub(in crate::routing::events::event_log) fn bootstrap_projection_error(
    error: soland_services::projection::RealmBootstrapProjectionError,
) -> SubmitOneError {
    // `encryption-and-audit.md` §2.10 — the history_access × content_scheme
    // linkage reason is the wire reason verbatim, matching the single-Event
    // admission path (`operation_policy_reason_code`).
    if error.reason == arkret_wire::ReasonCode::HISTORY_ACCESS_REQUIRES_HISTORY_CAPABLE_SCHEME {
        return SubmitOneError::new(
            StatusCode::PRECONDITION_FAILED,
            "failed_precondition",
            error.reason,
        );
    }
    let code = match error.reason.as_str() {
        reason @ ("realm_authority_root_missing" | "realm_authority_root_conflict") => reason,
        _ => "out_of_order_bootstrap",
    };
    SubmitOneError::new(
        StatusCode::PRECONDITION_FAILED,
        "failed_precondition",
        format!("{code}: {}", error.reason),
    )
}

/// Admit an ordinary Realm genesis as the single protocol transaction defined
/// by realm-and-space.md §2.5. No Event or derived projection is written until
/// the complete ordered unit has passed shared shape, envelope, proof, chain,
/// and staged reducer validation.
pub(super) async fn submit_realm_bootstrap_batch(
    state: &AppState,
    session: &SessionRecord,
    envelopes: Vec<Value>,
    internal_admissions: Option<&[InternalEventAdmission]>,
    authorization_leases: Option<&[Option<arkret_wire::AuthorizationLease>]>,
    inbound_publication_evidence: Option<&BTreeMap<String, InboundPublicationEvidence>>,
    direct_conversation_founding: Option<DirectConversationFoundingCommitContext>,
) -> Result<EventsSubmitOutcome, SubmitOneError> {
    if internal_admissions.is_some_and(|admissions| admissions.len() != envelopes.len()) {
        return Err(SubmitOneError::new(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            "Realm bootstrap federation admission cardinality mismatch",
        ));
    }
    if authorization_leases.is_some_and(|leases| leases.len() != envelopes.len()) {
        return Err(SubmitOneError::new(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            "Realm bootstrap publication lease cardinality mismatch",
        ));
    }
    let typed_events = envelopes
        .iter()
        .cloned()
        .map(|envelope| {
            serde_json::from_value::<arkret_wire::Event>(envelope).map_err(|error| {
                SubmitOneError::new(
                    StatusCode::BAD_REQUEST,
                    "schema_violation",
                    format!("invalid Realm bootstrap Event envelope: {error}"),
                )
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let unit = arkret_policy::realm_bootstrap::validate_realm_bootstrap_unit(&typed_events)
        .map_err(bootstrap_error)?;

    for envelope in &envelopes {
        let encoded_len = serde_json::to_vec(envelope)
            .map_err(|_| {
                SubmitOneError::new(
                    StatusCode::BAD_REQUEST,
                    "json_invalid",
                    "Realm bootstrap Event cannot be encoded",
                )
            })?
            .len();
        if arkret_wire::event_envelope::validate_event_envelope_byte_len(encoded_len).is_err() {
            return Err(SubmitOneError::new(
                StatusCode::PAYLOAD_TOO_LARGE,
                "payload_too_large",
                "Realm bootstrap Event exceeds max_event_bytes",
            ));
        }
    }

    let actor_lock = actor_submit_lock(unit.realm_id.as_str(), &unit.actor_id.to_string());
    let _guard = actor_lock.lock().await;
    let context = RealmBootstrapBatchContext {
        realm_id: unit.realm_id.to_string(),
        actor_id: unit.actor_id.to_string(),
        digest_algorithm: Some(staged_realm_digest_algorithm(&envelopes[0])),
        identity_anchor_event_id: None,
        identity_anchor_candidate_device: None,
        identity_anchor_resolution: None,
        direct_conversation_founding: direct_conversation_founding.is_some(),
        authority_root: Some(unit.authority_root.clone()),
    };
    let contexts = std::slice::from_ref(&context);
    let mut validated = Vec::with_capacity(envelopes.len());
    for (index, (envelope, typed)) in envelopes.iter().zip(&typed_events).enumerate() {
        super::value::validate_producer_submission_shape(state, session, typed)?;
        validated.push(
            validate_event_envelope_with_context(
                state,
                session,
                envelope,
                contexts,
                internal_admissions.and_then(|admissions| admissions.get(index)),
            )
            .await?,
        );
    }
    validate_actor_chain(&validated)?;
    let received_at = now();
    let mut ingress_receipts = Vec::new();
    if let Some(evidence) = inbound_publication_evidence {
        // Preserve the origin's first-publication evidence. A receiving
        // Station cannot reissue a receipt under another authority's lease.
        for event in &typed_events {
            if let Some(item) = evidence.get(event.event_id.as_str()) {
                store_inbound_publication_evidence(state, item).await?;
                ingress_receipts.extend(item.ingress_receipts.iter().cloned());
            }
        }
    } else if let Some(leases) = authorization_leases {
        if leases.iter().any(Option::is_some) && leases.iter().any(Option::is_none) {
            return Err(SubmitOneError::new(
                StatusCode::BAD_REQUEST,
                "schema_violation",
                "Realm bootstrap cannot mix online and delayed submissions",
            ));
        }
        for (parsed, lease) in validated
            .iter()
            .zip(leases)
            .filter_map(|(parsed, lease)| lease.as_ref().map(|lease| (parsed, lease)))
        {
            ingress_receipts
                .push(mint_and_store_ingress_receipt(state, parsed, lease, received_at).await?);
        }
    }
    let retry_candidates = validated
        .iter()
        .zip(envelopes.iter().cloned())
        .map(|(event, envelope)| canonical_record(event, envelope, received_at))
        .collect::<Vec<_>>();
    if let Some(mut outcome) = identical_historical_retry(state, &retry_candidates).await? {
        publish_confirmed_realm_bootstrap(state, &unit.realm_id)
            .await
            .map_err(|error| {
                SubmitOneError::new(StatusCode::INTERNAL_SERVER_ERROR, "internal_error", error)
            })?;
        outcome.ingress_receipts = ingress_receipts;
        return Ok(outcome);
    }

    let existing = state
        .event_queries()
        .canonical_events()
        .await
        .map_err(|error| {
            SubmitOneError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                format!("events store unavailable: {error}"),
            )
        })?;
    let first = validated.first().expect("shared validator requires create");
    for dependency in &first.prev_refs {
        if !existing
            .iter()
            .any(|record| record.event_id == dependency.as_str())
        {
            return Err(SubmitOneError::new(
                StatusCode::CONFLICT,
                "dependency_missing",
                "Realm bootstrap predecessor is not in accepted history",
            ));
        }
    }
    let operations = validated
        .iter()
        .zip(envelopes.iter())
        .map(|(parsed, envelope)| {
            projection_operation_from_event(parsed, envelope).ok_or_else(|| {
                SubmitOneError::new(
                    StatusCode::BAD_REQUEST,
                    "schema_violation",
                    format!(
                        "Realm bootstrap event kind {} has no projection operation",
                        parsed.kind
                    ),
                )
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    validate_operation_semantics(state, &operations)
        .map_err(SubmitOneError::semantic_schema_violation)?;
    // The genesis unit carries no producer `effects[]` either: each staged
    // Operation is paired with the writes its own signed Event derives from
    // the registered contract (`event-and-patch.md` §2.4.2), in wire order so
    // the two cannot drift apart by index.
    let projected_operations = operations
        .iter()
        .cloned()
        .zip(&typed_events)
        .map(|(operation, event)| {
            // The Realm does not exist yet, so there is no
            // `ak.component.realm.digest_suite.v1` cell to read: genesis
            // projects under the protocol baseline suite.
            let cell_writes = genesis_cell_write_projector(event).map_err(|error| {
                SubmitOneError::new(
                    StatusCode::BAD_REQUEST,
                    "reducer_projection_failed",
                    format!(
                        "Realm bootstrap Event {} does not project its registered cell writes: \
                         {error}",
                        event.event_id
                    ),
                )
            })?;
            Ok(soland_services::projection::ProjectedOperation {
                operation,
                cell_writes,
            })
        })
        .collect::<Result<Vec<_>, SubmitOneError>>()?;
    // Run the reducer against an application-owned clone in wire order. This
    // is the genesis authority boundary: create establishes the staged Realm
    // together with its registered authority-root cell, then only the closed
    // facet kinds can be applied. The create reducer's own authority-root
    // reason codes are surfaced verbatim so a genesis that cannot establish an
    // owner is distinguishable from an out-of-order unit.
    let _staged_projection = match state
        .projections()
        .stage_realm_bootstrap(&projected_operations, context.direct_conversation_founding)
    {
        Ok(staged) => staged,
        Err(error) if error.reason == "realm_already_exists" => {
            // The Seal coordinator may have installed the exact durable unit
            // between the historical lookup and this staging attempt. The
            // projection conflict alone is not enough to call it a retry;
            // confirm every canonical Event first, then leave the live state
            // untouched so any successor projections survive.
            if let Some(mut outcome) =
                identical_historical_retry_without_wake(state, &retry_candidates).await?
            {
                state.wake_control_seal_coordinator();
                outcome.ingress_receipts = ingress_receipts;
                return Ok(outcome);
            }
            return Err(realm_already_exists_error());
        }
        Err(error) => return Err(bootstrap_projection_error(error)),
    };

    if existing.iter().any(|record| {
        record.kind == arkret_wire::EventKind::RealmCreate.as_str()
            && record.realm_id.as_deref() == Some(unit.realm_id.as_str())
    }) {
        // Another Station worker may have committed this exact unit after the
        // point-in-time retry lookup above. Re-read the durable identities
        // before classifying the Realm-create uniqueness hit: byte-identical
        // bootstrap replay is `duplicate`, not `realm_already_exists`.
        // Recovery publishes only a complete, confirmed command unit.
        if let Some(mut outcome) =
            identical_historical_retry_without_wake(state, &retry_candidates).await?
        {
            publish_confirmed_realm_bootstrap(state, &unit.realm_id)
                .await
                .map_err(|error| {
                    SubmitOneError::new(StatusCode::INTERNAL_SERVER_ERROR, "internal_error", error)
                })?;
            state.wake_control_seal_coordinator();
            outcome.ingress_receipts = ingress_receipts;
            return Ok(outcome);
        }
        return Err(realm_already_exists_error());
    }

    let bootstrap_realm_id = unit.realm_id.clone();
    let control_proposal_acks = crate::control_proposal::mint_control_proposal_acks(
        state,
        &bootstrap_realm_id,
        &typed_events,
        &validated
            .iter()
            .map(|parsed| parsed.digest_suite)
            .collect::<Vec<_>>(),
        received_at,
        authorization_leases
            .and_then(|leases| leases.first())
            .and_then(Option::as_ref)
            .map(|lease| &lease.authority_set_ref),
    )
    .await
    .map_err(|error| {
        SubmitOneError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            arkret_wire::error_codes::ErrorCode::SERVICE_UNAVAILABLE,
            format!("Realm bootstrap Control Proposal Acks unavailable: {error}"),
        )
    })?;
    let mut accepted_envelopes = Vec::with_capacity(envelopes.len());
    let mut accepted_typed_events = Vec::with_capacity(envelopes.len());
    let mut governance_dependencies = Vec::with_capacity(envelopes.len());
    for ((envelope, typed), parsed) in envelopes.iter().cloned().zip(&typed_events).zip(&validated)
    {
        let (accepted_typed, accepted_envelope, _, governance_dependency) =
            super::value::accepted_event_envelope(
                state,
                session,
                envelope,
                typed.clone(),
                parsed,
                None,
                received_at,
            )
            .await?;
        accepted_envelopes.push(accepted_envelope);
        accepted_typed_events.push(accepted_typed);
        governance_dependencies.extend(governance_dependency);
    }
    let records = validated
        .iter()
        .zip(accepted_envelopes.iter().cloned())
        .map(|(parsed, envelope)| canonical_record(parsed, envelope, received_at))
        .collect::<Vec<_>>();
    // Build the federation delivery intents *before* the commit so they land in
    // the same transaction as the Events. A construction failure rejects the
    // admission: a Realm genesis unit accepted locally without its outbox rows
    // would be a silently unroutable Realm after any crash.
    let deliveries = if let Some(context) = &direct_conversation_founding {
        direct_conversation_founding_fanout_records(
            state,
            &validated,
            &accepted_envelopes,
            &context.receipt,
            &context.founding_authority_evidence,
            &control_proposal_acks,
        )
        .await
        .map_err(|error| {
            SubmitOneError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "federation_fanout_unavailable",
                format!("Direct Conversation founding delivery intent unavailable: {error}"),
            )
        })?
    } else if session.token_hash.starts_with("federation:") {
        Vec::new()
    } else {
        peer_event_batch_fanout_records(state, &validated, &accepted_envelopes)
            .await
            .map_err(|error| {
                SubmitOneError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "federation_fanout_unavailable",
                    format!("Realm bootstrap federation delivery intent unavailable: {error}"),
                )
            })?
    };
    let pending_delivery_count = deliveries
        .iter()
        .filter(|delivery| delivery.realm_fanout.is_some())
        .map(|delivery| delivery.peer_id.as_str())
        .collect::<std::collections::BTreeSet<_>>()
        .len() as u32;
    let direct_commit_outcome = if let Some(context) = direct_conversation_founding {
        state
            .event_queries()
            .store_direct_conversation_founding_batch(
                records,
                control_proposal_acks.clone(),
                governance_dependencies,
                context.slot,
                deliveries,
            )
            .await
    } else {
        match state
            .event_queries()
            .store_realm_bootstrap_batch(
                records,
                control_proposal_acks.clone(),
                governance_dependencies,
                deliveries,
            )
            .await
        {
            Ok(soland_storage::RealmBootstrapCommitOutcome::Committed) => {
                Ok(soland_storage::DirectConversationFoundingCommitOutcome::Committed)
            }
            Ok(soland_storage::RealmBootstrapCommitOutcome::ExactRetry { event_ids }) => {
                // The durable boundary, rather than the earlier point-in-time
                // lookup, decides whether this worker inserted or replayed the
                // unit. Install before pending-index recovery wakes the Seal
                // coordinator, then return the original duplicate receipt.
                publish_confirmed_realm_bootstrap(state, &unit.realm_id)
                    .await
                    .map_err(|error| {
                        SubmitOneError::new(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "internal_error",
                            error,
                        )
                    })?;
                let pending_delivery_count =
                    durable_pending_delivery_count(state, &event_ids).await?;
                let mut outcome = identical_historical_retry(state, &retry_candidates)
                    .await?
                    .ok_or_else(|| {
                        SubmitOneError::new(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "internal_error",
                            "Realm bootstrap retry lost its durable Event unit",
                        )
                    })?;
                outcome.pending_delivery_count = pending_delivery_count;
                outcome.ingress_receipts = ingress_receipts;
                return Ok(outcome);
            }
            Err(error) => Err(error),
        }
    };
    let commit_outcome = match direct_commit_outcome {
        Ok(outcome) => outcome,
        Err(error) if error.is_realm_already_exists() => {
            // The storage uniqueness boundary is authoritative, but a
            // concurrent exact commit is still a protocol replay. Resolve the
            // stored unit after losing the commit race instead of leaking the
            // defensive `realm_already_exists` branch to an exact retry.
            if let Some(mut outcome) =
                identical_historical_retry_without_wake(state, &retry_candidates).await?
            {
                publish_confirmed_realm_bootstrap(state, &unit.realm_id)
                    .await
                    .map_err(|error| {
                        SubmitOneError::new(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "internal_error",
                            error,
                        )
                    })?;
                state.wake_control_seal_coordinator();
                outcome.ingress_receipts = ingress_receipts;
                return Ok(outcome);
            }
            return Err(realm_already_exists_error());
        }
        Err(error) => {
            if let Some(collision) = map_event_hash_collision(
                validated
                    .first()
                    .map(|event| event.event_id.to_string())
                    .unwrap_or_default(),
                &error,
            ) {
                return Err(collision);
            }
            if error.is_conflict("duplicate_conflict") {
                return Err(SubmitOneError::new(
                    StatusCode::CONFLICT,
                    "duplicate_conflict",
                    "Realm bootstrap raced a different stored unit",
                ));
            }
            return Err(SubmitOneError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                format!("atomic Realm bootstrap commit failed: {error}"),
            ));
        }
    };
    match commit_outcome {
        soland_storage::DirectConversationFoundingCommitOutcome::Committed => {}
        soland_storage::DirectConversationFoundingCommitOutcome::ExactRetry(existing) => {
            // A different worker may have won the durable Direct Conversation
            // founding slot while this AppState had not projected it yet.
            // Recover confirmed effects before returning the exact retry.
            publish_confirmed_realm_bootstrap(state, &unit.realm_id)
                .await
                .map_err(|error| {
                    SubmitOneError::new(StatusCode::INTERNAL_SERVER_ERROR, "internal_error", error)
                })?;
            let pending_delivery_count =
                durable_pending_delivery_count(state, &existing.event_ids).await?;
            let mut outcome = identical_historical_retry(state, &retry_candidates)
                .await?
                .ok_or_else(|| {
                    SubmitOneError::new(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "internal_error",
                        "Direct Conversation founding retry lost its durable Event unit",
                    )
                })?;
            outcome.pending_delivery_count = pending_delivery_count;
            outcome.ingress_receipts = ingress_receipts;
            return Ok(outcome);
        }
        soland_storage::DirectConversationFoundingCommitOutcome::IdempotencyConflict => {
            return Err(SubmitOneError::new(
                StatusCode::CONFLICT,
                "duplicate_conflict",
                "Direct Conversation founding idempotency key names another unit",
            ));
        }
        soland_storage::DirectConversationFoundingCommitOutcome::SlotConflict(_) => {
            return Err(SubmitOneError::new(
                StatusCode::CONFLICT,
                "conflict",
                "direct_conversation_slot_already_committed",
            ));
        }
    }
    // Admission leaves bootstrap effects pending until its complete unit commits.
    publish_confirmed_realm_bootstrap(state, &unit.realm_id)
        .await
        .map_err(|error| {
            SubmitOneError::new(StatusCode::INTERNAL_SERVER_ERROR, "internal_error", error)
        })?;
    let pending_unit = accepted_typed_events
        .iter()
        .zip(&control_proposal_acks)
        .zip(&validated)
        .map(
            |((event, ack), parsed)| arkret_state::state::ControlUnitIngressMember {
                event: event.clone(),
                digest_suite: parsed.digest_suite,
                ingress: arkret_state::state::store::ControlProposalIngress::AckRequired(
                    ack.clone(),
                ),
            },
        )
        .collect::<Vec<_>>();
    state
        .projections()
        .put_pending_control_unit(&pending_unit)
        .await
        .map_err(|error| {
            SubmitOneError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                format!("accepted Realm bootstrap pending index unavailable: {error}"),
            )
        })?;
    state.wake_control_seal_coordinator();
    for parsed in &validated {
        append_audit_log(
            state,
            Some(&session.actor),
            "events.submit",
            json!({
                "event_id": parsed.event_id,
                "realm_id": parsed.realm_id,
                "kind": parsed.kind,
                "canonical_digest": parsed.canonical_digest,
                "atomic_realm_bootstrap_unit": true,
            }),
            "accepted",
        )
        .await;
    }
    let ids = validated
        .iter()
        .map(|event| event.event_id.to_string())
        .collect::<Vec<_>>();
    let cursor = match ids.last() {
        Some(event_id) => Some(
            super::super::super::sync::sync_barrier_token_for_event(state, session, event_id).await,
        ),
        None => None,
    };
    let mut outcome = events_submit_outcome(
        EventsSubmitStatus::Accepted,
        ids,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        cursor,
    );
    outcome.ingress_receipts = ingress_receipts;
    outcome.control_proposal_acks = control_proposal_acks;
    outcome.pending_delivery_count = pending_delivery_count;
    Ok(outcome)
}

fn validate_actor_chain(events: &[ValidatedEventEnvelope]) -> Result<(), SubmitOneError> {
    if events
        .first()
        .is_none_or(|first| first.actor_seq != 0 || !first.prev_refs.is_empty())
    {
        return Err(SubmitOneError::new(
            StatusCode::PRECONDITION_FAILED,
            "failed_precondition",
            "ordinary Realm bootstrap must begin the Realm-scoped actor chain at actor_seq=0",
        ));
    }
    for pair in events.windows(2) {
        let previous = &pair[0];
        let current = &pair[1];
        if current.actor_seq != previous.actor_seq.saturating_add(1)
            || current.prev_refs != vec![previous.event_id.clone()]
        {
            return Err(SubmitOneError::new(
                StatusCode::PRECONDITION_FAILED,
                "failed_precondition",
                "out_of_order_bootstrap",
            ));
        }
    }
    Ok(())
}

/// Rebuild genesis projections only from the locally confirmed command unit.
/// Admission, including exact retries, cannot make bootstrap effects visible.
pub(crate) async fn publish_confirmed_realm_bootstrap(
    state: &AppState,
    realm_id: &arkret_wire::RealmId,
) -> Result<bool, String> {
    crate::routing::identity::device_generation::recover_confirmed_device_projection(
        state, realm_id,
    )
    .await?;
    let Some(events) = state
        .projections()
        .confirmed_genesis_unit(realm_id)
        .await
        .map_err(|error| error.to_string())?
    else {
        return Ok(false);
    };
    let Some(create) = events.first() else {
        return Err("confirmed genesis is empty".to_owned());
    };
    let payload: arkret_models_collaboration::events_payloads::RealmCreatePayload =
        serde_json::from_value(
            serde_json::to_value(&create.payload).map_err(|error| error.to_string())?,
        )
        .map_err(|error| error.to_string())?;
    let direct = match payload.object.purpose {
        arkret_models_collaboration::events_payloads::RealmPurpose::Collaboration => false,
        arkret_models_collaboration::events_payloads::RealmPurpose::DirectConversation => true,
        _ => return Ok(false),
    };
    arkret_policy::realm_bootstrap::validate_realm_bootstrap_unit(&events)
        .map_err(|error| error.to_string())?;
    let projected = events
        .iter()
        .map(|event| {
            let envelope = serde_json::to_value(event).map_err(|error| error.to_string())?;
            let operation = super::super::projection_operation_from_envelope(&envelope)
                .ok_or_else(|| "confirmed bootstrap has no projection operation".to_owned())?;
            let cell_writes =
                genesis_cell_write_projector(event).map_err(|error| error.to_string())?;
            Ok(soland_services::projection::ProjectedOperation {
                operation,
                cell_writes,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    let staged = match state
        .projections()
        .stage_realm_bootstrap(&projected, direct)
    {
        Ok(staged) => Some(staged),
        Err(error) if error.reason == "realm_already_exists" => None,
        Err(error) => return Err(error.reason),
    };
    if let Some(staged) = staged {
        state
            .projections()
            .install_staged_realm_bootstrap(staged)
            .map_err(|error| error.reason)?;
    }
    for projected in &projected {
        let operation = &projected.operation;
        crate::routing::events::projection::ensure_projected_realm(
            state,
            create.actor_id.signing_principal_id().as_str(),
            operation,
        )
        .await;
        let record = crate::routing::events::projection::projection_event_from_operation(
            operation,
            Some(create.actor_id.signing_principal_id().as_str()),
        );
        crate::routing::events::projection::persist_and_publish_projection_event(state, record)
            .await
            .map_err(|error| error.to_string())?;
    }
    organizations::record_realm_organizations_from_event(
        state,
        realm_id.as_str(),
        &serde_json::to_value(create).map_err(|error| error.to_string())?,
    )
    .await
    .map_err(|error| error.to_string())?;
    Ok(true)
}
