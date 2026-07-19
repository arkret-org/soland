use super::identity_anchor::{canonical_record, identical_historical_retry};
use super::*;

pub(super) fn batch_begins_realm_create(envelopes: &[Value]) -> bool {
    event_string_field_from_value(envelopes.first().unwrap_or(&Value::Null), "kind").as_deref()
        == Some(arkret_sdk::events::EventKind::REALM_CREATE)
}

fn bootstrap_error(
    error: arkret_sdk::realm::bootstrap::RealmBootstrapValidationError,
) -> SubmitOneError {
    let reason = error.reason_code();
    SubmitOneError::new(
        StatusCode::PRECONDITION_FAILED,
        "failed_precondition",
        reason,
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
) -> Result<EventsSubmitOutcome, SubmitOneError> {
    let typed_events = envelopes
        .iter()
        .cloned()
        .map(|envelope| {
            serde_json::from_value::<arkret_sdk::Event>(envelope).map_err(|error| {
                SubmitOneError::new(
                    StatusCode::BAD_REQUEST,
                    "schema_violation",
                    format!("invalid Realm bootstrap Event envelope: {error}"),
                )
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let unit = arkret_sdk::realm::bootstrap::validate_realm_bootstrap_unit(&typed_events)
        .map_err(bootstrap_error)?;

    for envelope in &envelopes {
        let encoded_len = serde_json::to_vec(envelope)
            .map_err(|_| {
                SubmitOneError::new(
                    StatusCode::BAD_REQUEST,
                    "bad_json",
                    "Realm bootstrap Event cannot be encoded",
                )
            })?
            .len();
        if arkret_sdk::validate_event_envelope_byte_len(encoded_len).is_err() {
            return Err(SubmitOneError::new(
                StatusCode::PAYLOAD_TOO_LARGE,
                "payload_too_large",
                "Realm bootstrap Event exceeds max_event_bytes",
            ));
        }
    }

    let actor_lock = actor_submit_lock(&unit.actor_id);
    let _guard = actor_lock.lock().await;
    if let Some(outcome) = identical_historical_retry(state, &envelopes).await? {
        return Ok(outcome);
    }
    let context = RealmBootstrapBatchContext {
        realm_id: unit.realm_id.clone(),
        actor_id: unit.actor_id.clone(),
        identity_anchor_event_id: None,
        self_principal_pcr_bootstrap: false,
        ordinary_realm_bootstrap: true,
    };
    let contexts = std::slice::from_ref(&context);
    let mut validated = Vec::with_capacity(envelopes.len());
    for envelope in &envelopes {
        validated.push(
            validate_event_envelope_with_context(state, session, envelope, contexts, None).await?,
        );
    }
    validate_actor_chain(&validated)?;

    let existing = state.events_store().snapshot_all().await.map_err(|error| {
        SubmitOneError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            format!("events store unavailable: {error}"),
        )
    })?;
    if existing.iter().any(|record| {
        record.kind == arkret_sdk::events::EventKind::REALM_CREATE
            && record.realm_id.as_deref() == Some(unit.realm_id.as_str())
    }) {
        return Err(realm_already_exists_error());
    }
    let first = validated.first().expect("shared validator requires create");
    for dependency in &first.prev_refs {
        if !existing.iter().any(|record| record.event_id == *dependency) {
            return Err(SubmitOneError::new(
                StatusCode::CONFLICT,
                "dependency_missing",
                "Realm bootstrap predecessor is not in accepted history",
            ));
        }
    }
    for parsed in &validated {
        for dependency in &parsed.authorized_refs {
            if !existing.iter().any(|record| record.event_id == *dependency)
                && !validated
                    .iter()
                    .any(|candidate| candidate.event_id == *dependency)
            {
                return Err(SubmitOneError::new(
                    StatusCode::CONFLICT,
                    "dependency_missing",
                    "Realm bootstrap authorization reference is not in accepted history",
                ));
            }
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
    for operation in &operations {
        validate_operation_semantics(state, std::slice::from_ref(operation)).map_err(
            |message| SubmitOneError::new(StatusCode::BAD_REQUEST, "schema_violation", message),
        )?;
    }
    // Run the reducer against a clone in wire order. This is the genesis
    // authority boundary: create establishes the staged Realm, then only the
    // exact founding grant and closed facets can be applied.
    {
        let mut staged = state.projection.lock().clone();
        for (index, operation) in operations.iter().enumerate() {
            let effect = if index == 1
                && operation.object_type.as_str() == arkret_sdk::events::EventKind::CAPABILITY_GRANT
            {
                staged.apply_validated_realm_founding_grant(operation, operation.created_at)
            } else {
                staged.apply(operation, &state.hlc)
            };
            if let soland_domain::reducer::ProjectionEffect::Rejected { reason } = effect {
                let code = if operation.object_type.as_str()
                    == arkret_sdk::events::EventKind::CAPABILITY_GRANT
                {
                    "invalid_realm_founding_grant"
                } else {
                    "out_of_order_bootstrap"
                };
                return Err(SubmitOneError::new(
                    StatusCode::PRECONDITION_FAILED,
                    "failed_precondition",
                    format!("{code}: {reason}"),
                ));
            }
        }
    }

    let received_at = now();
    let records = validated
        .iter()
        .zip(envelopes.iter().cloned())
        .map(|(parsed, envelope)| canonical_record(parsed, envelope, received_at))
        .collect::<Vec<_>>();
    state
        .events_store()
        .put_identity_anchor_batch_atomic(records, None, None, None, None)
        .await
        .map_err(|error| {
            if persistence_error_is_realm_already_exists(&error) {
                realm_already_exists_error()
            } else if matches!(
                &error,
                soland_storage::PersistenceError::Conflict(reason)
                    if reason == "duplicate_conflict"
            ) {
                SubmitOneError::new(
                    StatusCode::CONFLICT,
                    "duplicate_conflict",
                    "Realm bootstrap raced a different stored unit",
                )
            } else {
                SubmitOneError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    format!("atomic Realm bootstrap commit failed: {error}"),
                )
            }
        })?;

    for ((parsed, envelope), operation) in validated
        .iter()
        .zip(envelopes.iter())
        .zip(operations.iter())
    {
        if operation.object_type.as_str() == arkret_sdk::events::EventKind::CAPABILITY_GRANT {
            let effect = crate::routing::events::projection::project_validated_realm_founding_grant(
                state, operation,
            );
            debug_assert!(!matches!(
                effect,
                soland_domain::reducer::ProjectionEffect::Rejected { .. }
            ));
        } else {
            crate::routing::events::projection::project_accepted_operations_from_device(
                state,
                &parsed.actor_id,
                &parsed.device_id,
                std::slice::from_ref(operation),
            )
            .await;
        }
        if !session.token_hash.starts_with("federation:") {
            enqueue_peer_event_fanout(state, parsed, envelope).await;
        }
    }
    bootstrap_realm_member_index(
        state,
        &unit.realm_id,
        &unit.actor_id,
        envelopes[0].as_object().expect("validated Realm create"),
    )
    .await;
    organizations::record_realm_organizations_from_event(state, &unit.realm_id, &envelopes[0])
        .await;
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
        .map(|event| event.event_id.clone())
        .collect::<Vec<_>>();
    Ok(events_submit_outcome(
        EventsSubmitStatus::Accepted,
        ids,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Some(super::super::super::sync::sync_token_for_state(state).await),
    ))
}

fn validate_actor_chain(events: &[ValidatedEventEnvelope]) -> Result<(), SubmitOneError> {
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
