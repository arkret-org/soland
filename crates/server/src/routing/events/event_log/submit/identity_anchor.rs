use super::*;

pub(super) fn batch_contains_identity_anchor(envelopes: &[Value]) -> bool {
    envelopes.iter().any(|envelope| {
        envelope
            .get("refs")
            .and_then(Value::as_array)
            .is_some_and(|refs| {
                refs.iter().any(|reference| {
                    matches!(
                        reference.get("role").and_then(Value::as_str),
                        Some("did_inception" | "did_recovery_anchor")
                    )
                })
            })
            || event_string_field_from_value(envelope, "kind").as_deref()
                == Some("ak.device.reanchor")
    })
}

pub(super) async fn submit_identity_anchor_batch(
    state: &AppState,
    session: &SessionRecord,
    envelopes: Vec<Value>,
) -> Result<EventsSubmitOutcome, SubmitOneError> {
    if envelopes.len() != 2 {
        return Err(unit_error(
            "identity anchor unit must contain exactly two ordered Events",
        ));
    }
    for envelope in &envelopes {
        let encoded_len = serde_json::to_vec(envelope)
            .map_err(|_| unit_error("identity anchor Event cannot be encoded"))?
            .len();
        if arkret_sdk::validate_event_envelope_byte_len(encoded_len).is_err() {
            return Err(SubmitOneError::new(
                StatusCode::PAYLOAD_TOO_LARGE,
                "payload_too_large",
                "identity anchor Event exceeds max_event_bytes",
            ));
        }
    }
    let first_kind = event_string_field_from_value(&envelopes[0], "kind");
    let second_kind = event_string_field_from_value(&envelopes[1], "kind");
    let is_bootstrap = first_kind.as_deref() == Some(arkret_sdk::events::EventKind::REALM_CREATE)
        && second_kind.as_deref() == Some(arkret_sdk::events::EventKind::DEVICE_AUTHORIZE);
    let is_reanchor = first_kind.as_deref() == Some("ak.device.reanchor")
        && second_kind.as_deref() == Some(arkret_sdk::events::EventKind::DEVICE_AUTHORIZE);
    if !is_bootstrap && !is_reanchor {
        return Err(unit_error(
            "identity anchor unit must be [ak.realm.create, ak.device.authorize] or [ak.device.reanchor, ak.device.authorize]",
        ));
    }
    let lock_actor = event_string_field_from_value(&envelopes[0], "actor_id")
        .ok_or_else(|| unit_error("identity anchor Event requires actor_id"))?;
    let actor_lock = actor_submit_lock(&lock_actor);
    let _guard = actor_lock.lock().await;
    let generation_lock =
        crate::routing::identity::device_generation::device_generation_admission_lock(&lock_actor);
    let _generation_guard = generation_lock.lock().await;
    if let Some(outcome) = identical_historical_retry(state, &envelopes).await? {
        return Ok(outcome);
    }
    let self_principal_pcr_context = if is_bootstrap {
        Some(validate_self_principal_pcr_bootstrap_context(&envelopes)?)
    } else {
        None
    };

    let first_contexts = self_principal_pcr_context
        .as_ref()
        .map(std::slice::from_ref)
        .unwrap_or_default();
    let first =
        validate_event_envelope_with_context(state, session, &envelopes[0], first_contexts).await?;
    let identity_anchor_context =
        self_principal_pcr_context.unwrap_or(RealmBootstrapBatchContext {
            realm_id: first.realm_id.clone(),
            actor_id: first.actor_id.clone(),
            identity_anchor_event_id: Some(first.event_id.clone()),
            self_principal_pcr_bootstrap: false,
        });
    if identity_anchor_context.realm_id != first.realm_id
        || identity_anchor_context.actor_id != first.actor_id
        || identity_anchor_context.identity_anchor_event_id.as_deref()
            != Some(first.event_id.as_str())
    {
        return Err(unit_error(
            "validated self-principal PCR context does not match the admitted create Event",
        ));
    }
    let second_contexts = std::slice::from_ref(&identity_anchor_context);
    let second =
        validate_event_envelope_with_context(state, session, &envelopes[1], second_contexts)
            .await?;
    validate_unit_relationships(state, &first, &second, &envelopes, is_bootstrap).await?;

    let existing = state.events_store().snapshot_all().await.map_err(|error| {
        SubmitOneError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            format!("events store unavailable: {error}"),
        )
    })?;
    let first_existing = existing
        .iter()
        .find(|record| record.event_id == first.event_id);
    let second_existing = existing
        .iter()
        .find(|record| record.event_id == second.event_id);
    match (first_existing, second_existing) {
        (Some(a), Some(b))
            if a.canonical_bytes == first.canonical_bytes
                && b.canonical_bytes == second.canonical_bytes =>
        {
            return Ok(events_submit_outcome(
                EventsSubmitStatus::Duplicate,
                vec![first.event_id.clone(), second.event_id.clone()],
                vec![first.event_id, second.event_id],
                Vec::new(),
                Vec::new(),
                Some(super::super::super::sync::sync_token_for_state(state).await),
            ));
        }
        (None, None) => {}
        _ => {
            return Err(SubmitOneError::new(
                StatusCode::CONFLICT,
                "duplicate_conflict",
                "identity anchor unit conflicts with a partially or differently stored unit",
            ));
        }
    }
    for dependency in &first.prev_refs {
        if !existing.iter().any(|record| record.event_id == *dependency) {
            return Err(SubmitOneError::new(
                StatusCode::CONFLICT,
                "dependency_missing",
                "identity anchor predecessor is not in accepted history",
            ));
        }
    }
    for dependency in first
        .authorized_refs
        .iter()
        .chain(second.authorized_refs.iter())
    {
        if dependency != &first.event_id
            && dependency != &second.event_id
            && !existing.iter().any(|record| record.event_id == *dependency)
        {
            return Err(SubmitOneError::new(
                StatusCode::CONFLICT,
                "dependency_missing",
                "identity anchor authorization reference is not in accepted history",
            ));
        }
    }
    if is_bootstrap
        && existing.iter().any(|record| {
            record.kind == arkret_sdk::events::EventKind::REALM_CREATE
                && (record.realm_id.as_deref() == Some(first.realm_id.as_str())
                    || (record.actor_id == first.actor_id
                        && record
                            .envelope
                            .pointer("/payload/object/fields/purpose")
                            .and_then(Value::as_str)
                            == Some("principal_control")))
        })
    {
        return Err(realm_already_exists_error());
    }
    let mut conflict_evidence = if is_reanchor {
        conflicting_reanchor_slot(&first, &second, &envelopes[0], &existing)
    } else {
        Vec::new()
    };
    let mut reanchor_conflict = !conflict_evidence.is_empty();
    let received_at = now();
    let records = vec![
        canonical_record(&first, envelopes[0].clone(), received_at),
        canonical_record(&second, envelopes[1].clone(), received_at),
    ];
    let authorized_generation_ref = if reanchor_conflict {
        None
    } else if is_reanchor {
        Some(
            typed_device_reanchor_payload(&envelopes[0])?
                .new_device_generation
                .to_string(),
        )
    } else {
        bootstrap_b_model_generation_ref(&envelopes[0], &envelopes[1])?
    };
    let device_projection = if reanchor_conflict {
        None
    } else {
        Some(
            identity_anchor_device_projection(
                state,
                &second,
                &envelopes[1],
                authorized_generation_ref,
                received_at,
            )
            .await?,
        )
    };
    let receipt = if is_reanchor && !reanchor_conflict {
        Some(
            build_reanchor_batch_receipt(state, &first, &second, &envelopes[0], received_at)
                .await?,
        )
    } else {
        None
    };
    let frontier_cas = if is_reanchor {
        let payload = typed_device_reanchor_payload(&envelopes[0])?;
        let realm_id = RealmId::new(first.realm_id.clone()).map_err(|error| {
            SubmitOneError::new(StatusCode::BAD_REQUEST, "invalid_param", error.to_string())
        })?;
        let raw_leaves = state.seal_store.list_leaves(&realm_id).map_err(|error| {
            SubmitOneError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                format!("Seal frontier unavailable: {error}"),
            )
        })?;
        validate_pre_fence_basis(state, &first, payload.pre_fence_basis.as_ref()).await?;
        Some(soland_storage::IdentityAnchorFrontierCas {
            realm_id: first.realm_id.clone(),
            raw_leaves: raw_leaves
                .into_iter()
                .map(|leaf| leaf.to_string())
                .collect(),
        })
    } else {
        None
    };
    let reanchor_slot = if is_reanchor {
        let payload = typed_device_reanchor_payload(&envelopes[0])?;
        Some(soland_storage::IdentityAnchorReanchorSlot {
            actor_id: first.actor_id.clone(),
            version_number: payload.did_version_number(),
            did_version_id: payload.did_version_id.to_string(),
            reanchor_digest: first.canonical_digest.clone(),
            authorize_digest: second.canonical_digest.clone(),
        })
    } else {
        None
    };
    let commit_outcome = state
        .events_store()
        .put_identity_anchor_batch_atomic(
            records.clone(),
            receipt,
            device_projection,
            frontier_cas,
            reanchor_slot,
        )
        .await
        .map_err(|error| {
            let soland_application::ApplicationError::Storage(error) = error;
            if persistence_error_is_realm_already_exists(&error) {
                realm_already_exists_error()
            } else if matches!(
                &error,
                soland_storage::PersistenceError::Conflict(reason)
                    if reason == "device_reanchor_frontier_mismatch"
            ) {
                frontier_error()
            } else if matches!(
                &error,
                soland_storage::PersistenceError::Conflict(reason)
                    if reason == "duplicate_conflict"
            ) {
                SubmitOneError::new(
                    StatusCode::CONFLICT,
                    "duplicate_conflict",
                    "identity anchor unit raced a different stored unit",
                )
            } else {
                SubmitOneError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    format!("atomic identity anchor commit failed: {error}"),
                )
            }
        })?;
    if commit_outcome.reanchor_conflict {
        reanchor_conflict = true;
        let committed = state.events_store().snapshot_all().await.map_err(|error| {
            SubmitOneError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                format!("events store unavailable after conflict commit: {error}"),
            )
        })?;
        conflict_evidence = conflicting_reanchor_slot(&first, &second, &envelopes[0], &committed);
    }

    if !reanchor_conflict {
        for (parsed, envelope) in [(&first, &envelopes[0]), (&second, &envelopes[1])] {
            if let Some(operation) = projection_operation_from_event(parsed, envelope) {
                crate::routing::events::projection::project_accepted_operations_from_device(
                    state,
                    &parsed.actor_id,
                    &parsed.device_id,
                    &[operation],
                )
                .await;
            }
        }
    }
    if is_bootstrap {
        bootstrap_realm_member_index(
            state,
            &first.realm_id,
            &first.actor_id,
            envelopes[0].as_object().expect("validated Event object"),
        )
        .await;
    }
    for (parsed, envelope) in [(&first, &envelopes[0]), (&second, &envelopes[1])] {
        if !session.token_hash.starts_with("federation:") {
            enqueue_peer_event_fanout(state, parsed, envelope).await;
        }
        append_audit_log(
            state,
            Some(&session.actor),
            "events.submit",
            json!({
                "event_id": parsed.event_id,
                "realm_id": parsed.realm_id,
                "kind": parsed.kind,
                "canonical_digest": parsed.canonical_digest,
                "atomic_identity_anchor_unit": true,
                "quarantine_reason": reanchor_conflict.then_some("device_reanchor_conflict"),
            }),
            if reanchor_conflict {
                "fork_quarantine"
            } else {
                "accepted"
            },
        )
        .await;
    }
    if reanchor_conflict {
        conflict_evidence.extend([first.event_id.clone(), second.event_id.clone()]);
        conflict_evidence.sort_unstable();
        conflict_evidence.dedup();
        Ok(events_submit_outcome(
            EventsSubmitStatus::Partial,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            conflict_evidence,
            Some(super::super::super::sync::sync_token_for_state(state).await),
        ))
    } else {
        Ok(events_submit_outcome(
            EventsSubmitStatus::Accepted,
            vec![first.event_id, second.event_id],
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Some(super::super::super::sync::sync_token_for_state(state).await),
        ))
    }
}

fn validate_self_principal_pcr_bootstrap_context(
    envelopes: &[Value],
) -> Result<RealmBootstrapBatchContext, SubmitOneError> {
    let create: arkret_sdk::Event =
        serde_json::from_value(envelopes[0].clone()).map_err(|error| {
            SubmitOneError::new(
                StatusCode::BAD_REQUEST,
                "schema_violation",
                format!("self-principal PCR create is not a canonical Event: {error}"),
            )
        })?;
    let authorize: arkret_sdk::Event =
        serde_json::from_value(envelopes[1].clone()).map_err(|error| {
            SubmitOneError::new(
                StatusCode::BAD_REQUEST,
                "schema_violation",
                format!("self-principal PCR authorize is not a canonical Event: {error}"),
            )
        })?;
    arkret_sdk::identity::validate_self_principal_bootstrap_unit(&create, &authorize).map_err(
        |error| {
            SubmitOneError::new(
                StatusCode::BAD_REQUEST,
                "schema_violation",
                format!("self-principal PCR bootstrap unit violates the closed profile: {error}"),
            )
        },
    )?;
    Ok(RealmBootstrapBatchContext {
        realm_id: create.realm_id.to_string(),
        actor_id: create.actor_id.to_string(),
        identity_anchor_event_id: Some(create.event_id.to_string()),
        self_principal_pcr_bootstrap: true,
    })
}

async fn identical_historical_retry(
    state: &AppState,
    envelopes: &[Value],
) -> Result<Option<EventsSubmitOutcome>, SubmitOneError> {
    let mut ids = Vec::with_capacity(envelopes.len());
    let mut canonical_bytes = Vec::with_capacity(envelopes.len());
    for envelope in envelopes {
        let id = event_string_field_from_value(envelope, "event_id")
            .ok_or_else(|| unit_error("identity anchor Event requires event_id"))?;
        ids.push(id);
        canonical_bytes.push(event_canonical_bytes(envelope)?);
    }
    let mut existing = Vec::with_capacity(ids.len());
    for id in &ids {
        existing.push(state.events_store().get(id).await.map_err(|error| {
            SubmitOneError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                format!("events store unavailable: {error}"),
            )
        })?);
    }
    if existing.iter().all(Option::is_none) {
        return Ok(None);
    }
    if existing
        .iter()
        .zip(canonical_bytes.iter())
        .all(|(record, bytes)| {
            record
                .as_ref()
                .is_some_and(|record| &record.canonical_bytes == bytes)
        })
    {
        if ids.iter().any(|id| EventId::new(id.clone()).is_err()) {
            return Err(unit_error("stored identity anchor Event id is invalid"));
        }
        return Ok(Some(events_submit_outcome(
            EventsSubmitStatus::Duplicate,
            ids.clone(),
            ids,
            Vec::new(),
            Vec::new(),
            Some(super::super::super::sync::sync_token_for_state(state).await),
        )));
    }
    Err(SubmitOneError::new(
        StatusCode::CONFLICT,
        "duplicate_conflict",
        "identity anchor unit conflicts with a partially or differently stored unit",
    ))
}

fn conflicting_reanchor_slot(
    reanchor: &ValidatedEventEnvelope,
    authorize: &ValidatedEventEnvelope,
    reanchor_envelope: &Value,
    existing: &[CanonicalEventRecord],
) -> Vec<String> {
    let Some(version_id) = reanchor_envelope
        .pointer("/payload/did_version_id")
        .and_then(Value::as_str)
    else {
        return Vec::new();
    };
    let Some((version_number, _)) = version_id.split_once('-') else {
        return Vec::new();
    };
    let mut evidence = existing
        .iter()
        .filter(|record| {
            record.actor_id == reanchor.actor_id && record.kind == "ak.device.reanchor"
        })
        .filter(|record| {
            let candidate_version = record
                .envelope
                .pointer("/payload/did_version_id")
                .and_then(Value::as_str);
            let same_slot = candidate_version
                .and_then(|candidate| candidate.split_once('-'))
                .is_some_and(|(candidate_number, _)| candidate_number == version_number);
            if !same_slot {
                return false;
            }
            let candidate_authorize_digest = record
                .envelope
                .pointer("/payload/replacement_authorize_digest")
                .and_then(Value::as_str);
            candidate_version != Some(version_id)
                || record.canonical_digest != reanchor.canonical_digest
                || candidate_authorize_digest != Some(authorize.canonical_digest.as_str())
        })
        .flat_map(|record| {
            std::iter::once(record.event_id.clone()).chain(
                record
                    .envelope
                    .pointer("/payload/replacement_authorize_event_id")
                    .and_then(Value::as_str)
                    .map(ToOwned::to_owned),
            )
        })
        .collect::<Vec<_>>();
    evidence.sort_unstable();
    evidence.dedup();
    evidence
}

async fn validate_unit_relationships(
    state: &AppState,
    first: &ValidatedEventEnvelope,
    second: &ValidatedEventEnvelope,
    envelopes: &[Value],
    is_bootstrap: bool,
) -> Result<(), SubmitOneError> {
    if first.actor_id != second.actor_id || first.realm_id != second.realm_id {
        return Err(unit_error(
            "identity anchor unit Events must share actor_id and principal-control realm_id",
        ));
    }
    let expected_realm = soland_domain::identity::principal_control_realm_for_did(&first.actor_id);
    if first.realm_id != expected_realm {
        return Err(SubmitOneError::new(
            StatusCode::CONFLICT,
            "failed_precondition",
            "identity anchor unit must target the principal's deterministic control Realm",
        ));
    }
    if second.actor_seq != first.actor_seq.saturating_add(1)
        || second.prev_refs != vec![first.event_id.clone()]
    {
        return Err(SubmitOneError::new(
            StatusCode::CONFLICT,
            if is_bootstrap {
                "schema_violation"
            } else {
                "device_reanchor_authorize_mismatch"
            },
            "replacement device authorization must immediately follow and reference the anchor Event",
        ));
    }
    let first_operation = projection_operation_from_event(first, &envelopes[0]);
    let second_operation = projection_operation_from_event(second, &envelopes[1]);
    for operation in first_operation.iter().chain(second_operation.iter()) {
        validate_operation_semantics(state, std::slice::from_ref(operation)).map_err(
            |message| SubmitOneError::new(StatusCode::BAD_REQUEST, "schema_violation", message),
        )?;
    }
    if let Some(operation) = second_operation.as_ref() {
        validate_operation_policy(state, std::slice::from_ref(operation))
            .await
            .map_err(|message| {
                let (status, code) =
                    crate::routing::events::operations::operation_policy_reason_code(message);
                SubmitOneError::new(status, code, message)
            })?;
    }
    if is_bootstrap {
        if first.actor_seq != 0 || !first.prev_refs.is_empty() {
            return Err(unit_error(
                "self-principal PCR genesis must use actor_seq=0 and an empty predecessor set",
            ));
        }
        let authorize = typed_device_authorize_payload(&envelopes[1])?;
        if authorize.principal_id.as_str() != first.actor_id
            || authorize.enrollment_authority_binding.is_none()
            || authorize.cross_signing_binding.is_some()
        {
            return Err(unit_error(
                "PCR bootstrap authorize must bind the same principal and use only enrollment_authority_binding",
            ));
        }
        return Ok(());
    }

    let payload = typed_device_reanchor_payload(&envelopes[0])?;
    let authorize = typed_device_authorize_payload(&envelopes[1])?;
    if payload.principal_id.as_str() != first.actor_id
        || payload.replacement_authorize_event_id.as_str() != second.event_id
        || payload.replacement_authorize_digest.as_str() != second.canonical_digest
        || authorize.principal_id.as_str() != first.actor_id
        || authorize.enrollment_authority_binding.is_none()
        || authorize.cross_signing_binding.is_some()
    {
        return Err(SubmitOneError::new(
            StatusCode::CONFLICT,
            "device_reanchor_authorize_mismatch",
            "device re-anchor replacement authorization id/digest or generation binding mismatch",
        ));
    }
    validate_reanchor_recovery_session(state, &payload, &authorize).await?;
    validate_reanchor_entry_delegation(state, &payload, &authorize).await?;
    let current = crate::routing::identity::device_generation::current_device_generation(
        state,
        &first.actor_id,
    )
    .await
    .map_err(|error| {
        SubmitOneError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            format!("device generation state unavailable: {error}"),
        )
    })?
    .ok_or_else(|| {
        SubmitOneError::new(
            StatusCode::PRECONDITION_FAILED,
            "failed_precondition",
            "device re-anchor requires an existing B-model generation",
        )
    })?;
    if payload.previous_device_generation.as_str() != current.current_ref {
        return Err(SubmitOneError::new(
            StatusCode::CONFLICT,
            "device_generation_fenced",
            "device re-anchor previous generation does not match the last unconflicted generation",
        ));
    }
    validate_pre_fence_basis(state, first, payload.pre_fence_basis.as_ref()).await?;
    validate_reanchor_actor_frontier(state, first, payload.pre_fence_basis.as_ref()).await?;
    Ok(())
}

async fn validate_reanchor_actor_frontier(
    state: &AppState,
    reanchor: &ValidatedEventEnvelope,
    basis: Option<&arkret_sdk::SealBasis>,
) -> Result<(), SubmitOneError> {
    let covered_digests = if let Some(basis) = basis {
        arkret_sdk::leaf_union_proof(&basis.leaves, state.seal_store.as_ref())
            .map_err(|error| {
                SubmitOneError::new(
                    StatusCode::CONFLICT,
                    "device_reanchor_frontier_mismatch",
                    format!("device re-anchor Seal closure is invalid: {error}"),
                )
            })?
            .into_iter()
            .flat_map(|proof| proof.covered_event_digests)
            .map(|digest| digest.to_string())
            .collect::<std::collections::BTreeSet<_>>()
    } else {
        std::collections::BTreeSet::new()
    };
    let records = state.events_store().snapshot_all().await.map_err(|error| {
        SubmitOneError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            format!("actor frontier lookup failed: {error}"),
        )
    })?;
    let (max_actor_seq, expected_heads) = preserved_actor_frontier(
        &records,
        &reanchor.actor_id,
        &reanchor.realm_id,
        &covered_digests,
    )
    .map_err(|message| {
        SubmitOneError::new(
            StatusCode::CONFLICT,
            "device_reanchor_frontier_mismatch",
            message,
        )
    })?;
    let expected_actor_seq = max_actor_seq.checked_add(1).ok_or_else(|| {
        SubmitOneError::new(
            StatusCode::CONFLICT,
            "device_reanchor_frontier_mismatch",
            "preserved actor sequence cannot be advanced",
        )
    })?;
    let mut declared_heads = reanchor.prev_refs.clone();
    declared_heads.sort_unstable();
    declared_heads.dedup();
    if reanchor.actor_seq != expected_actor_seq || declared_heads != expected_heads {
        return Err(SubmitOneError::new(
            StatusCode::CONFLICT,
            "device_reanchor_frontier_mismatch",
            "device re-anchor actor_seq or prev_refs does not exactly continue the preserved actor frontier",
        ));
    }
    Ok(())
}

fn preserved_actor_frontier(
    records: &[CanonicalEventRecord],
    actor_id: &str,
    realm_id: &str,
    covered_digests: &std::collections::BTreeSet<String>,
) -> Result<(u64, Vec<String>), &'static str> {
    let actor_records = records
        .iter()
        .filter(|record| {
            record.actor_id == actor_id && record.realm_id.as_deref() == Some(realm_id)
        })
        .collect::<Vec<_>>();
    let genesis = actor_records
        .iter()
        .copied()
        .filter(|record| {
            record.actor_seq == 0
                && record.kind == arkret_sdk::events::EventKind::REALM_CREATE
                && record
                    .envelope
                    .pointer("/payload/object/fields/purpose")
                    .and_then(Value::as_str)
                    == Some("principal_control")
        })
        .collect::<Vec<_>>();
    if genesis.len() != 1 {
        return Err("preserved history must contain exactly one principal-control genesis Event");
    }
    let genesis = genesis[0];
    let bootstrap_authorize = actor_records
        .iter()
        .copied()
        .filter(|record| {
            record.actor_seq == 1
                && record.kind == arkret_sdk::events::EventKind::DEVICE_AUTHORIZE
                && event_prev_refs(&record.envelope) == vec![genesis.event_id.as_str()]
        })
        .collect::<Vec<_>>();
    if bootstrap_authorize.len() != 1 {
        return Err("preserved history must contain exactly one bootstrap device authorization");
    }

    let mut preserved_ids = actor_records
        .iter()
        .copied()
        .filter(|record| covered_digests.contains(&record.canonical_digest))
        .map(|record| record.event_id.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    preserved_ids.insert(genesis.event_id.as_str());
    preserved_ids.insert(bootstrap_authorize[0].event_id.as_str());
    let preserved = actor_records
        .into_iter()
        .filter(|record| preserved_ids.contains(record.event_id.as_str()))
        .collect::<Vec<_>>();
    if preserved.iter().any(|record| {
        event_prev_refs(&record.envelope)
            .into_iter()
            .any(|predecessor| !preserved_ids.contains(predecessor))
    }) {
        return Err("accepted Seal closure does not preserve the complete actor predecessor chain");
    }
    let referenced = preserved
        .iter()
        .flat_map(|record| event_prev_refs(&record.envelope))
        .collect::<std::collections::BTreeSet<_>>();
    let mut heads = preserved_ids
        .iter()
        .copied()
        .filter(|event_id| !referenced.contains(event_id))
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>();
    heads.sort_unstable();
    if heads.is_empty() {
        return Err("preserved actor history has no canonical head");
    }
    let max_actor_seq = preserved
        .iter()
        .map(|record| record.actor_seq)
        .max()
        .ok_or("preserved actor history is empty")?;
    Ok((max_actor_seq, heads))
}

fn event_prev_refs(envelope: &Value) -> Vec<&str> {
    envelope
        .get("prev_refs")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect()
}

async fn validate_reanchor_entry_delegation(
    state: &AppState,
    reanchor: &arkret_sdk::DeviceReanchorPayload,
    authorize: &arkret_sdk::DeviceAuthorizePayload,
) -> Result<(), SubmitOneError> {
    let binding = authorize
        .enrollment_authority_binding
        .as_ref()
        .ok_or_else(|| {
            SubmitOneError::new(
                StatusCode::CONFLICT,
                "device_reanchor_authorize_mismatch",
                "replacement authorization is missing its enrollment authority binding",
            )
        })?;
    let entries = state
        .did_application()
        .log_events(reanchor.principal_id.as_str())
        .await
        .map_err(|error| {
            SubmitOneError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                format!("DID history lookup failed: {error}"),
            )
        })?;
    let document = entries
        .iter()
        .find(|entry| {
            entry.operation.get("versionId").and_then(Value::as_str)
                == Some(reanchor.did_version_id.as_str())
        })
        .and_then(|entry| {
            entry
                .operation
                .get("state")
                .or_else(|| entry.operation.get("did_document"))
        })
        .ok_or_else(|| {
            SubmitOneError::new(
                StatusCode::CONFLICT,
                "device_reanchor_authorize_mismatch",
                "replacement authorization DID entry does not expose an enrollment delegation",
            )
        })?;
    let designated = document
        .get("service")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .any(|service| {
            service.get("type").and_then(Value::as_str)
                == Some(arkret_sdk::service::DID_SERVICE_DEVICE_ENROLLMENT_AUTHORITY)
                && service.get("id").and_then(Value::as_str)
                    == Some(binding.authorization_ref.as_str())
                && service.get("serviceEndpoint").and_then(Value::as_str)
                    == Some(binding.authority_did.as_str())
                && binding.authority_did != reanchor.principal_id
        });
    if !designated {
        return Err(SubmitOneError::new(
            StatusCode::CONFLICT,
            "device_reanchor_authorize_mismatch",
            "replacement authorization authority is not the external delegation in the referenced DID entry",
        ));
    }
    Ok(())
}

async fn validate_reanchor_recovery_session(
    state: &AppState,
    reanchor: &arkret_sdk::DeviceReanchorPayload,
    authorize: &arkret_sdk::DeviceAuthorizePayload,
) -> Result<(), SubmitOneError> {
    let session_id = authorize.recovery_session_id.as_ref().ok_or_else(|| {
        SubmitOneError::new(
            StatusCode::CONFLICT,
            "device_reanchor_authorize_mismatch",
            "replacement device authorization must bind a verified recovery session",
        )
    })?;
    let session = state
        .recovery_sessions_store()
        .get(session_id.as_str())
        .await
        .map_err(|error| {
            SubmitOneError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                format!("recovery session lookup failed: {error}"),
            )
        })?
        .ok_or_else(|| {
            SubmitOneError::new(
                StatusCode::CONFLICT,
                "device_reanchor_authorize_mismatch",
                "replacement device authorization recovery session is unknown",
            )
        })?;
    if session.state != "verified"
        || session.expires_at <= now()
        || session.identity_model != arkret_sdk::RecoveryIdentityModel::EnrollmentAuthority
        || session.principal_id != authorize.principal_id.as_str()
        || session.requesting_device_id != authorize.device_id.as_str()
        || session
            .current_device_generation_ref
            .as_ref()
            .map(|generation| generation.as_str())
            != Some(reanchor.previous_device_generation.as_str())
        || session.accepted_seal_frontier.as_ref() != reanchor.pre_fence_basis.as_ref()
    {
        return Err(SubmitOneError::new(
            StatusCode::CONFLICT,
            "device_reanchor_authorize_mismatch",
            "replacement device authorization does not match an active verified recovery session",
        ));
    }
    let mut entries = state
        .did_application()
        .log_events(reanchor.principal_id.as_str())
        .await
        .map_err(|error| {
            SubmitOneError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                format!("DID history lookup failed: {error}"),
            )
        })?;
    entries.sort_by_key(|entry| entry.seq);
    let previous_registry_head = entries
        .iter()
        .position(|entry| {
            entry.operation.get("versionId").and_then(Value::as_str)
                == Some(reanchor.did_version_id.as_str())
        })
        .and_then(|position| position.checked_sub(1))
        .and_then(|position| entries.get(position))
        .map(|entry| entry.event_digest.as_str());
    if session.registry_head.as_ref().map(|head| head.as_str()) != previous_registry_head {
        return Err(SubmitOneError::new(
            StatusCode::CONFLICT,
            "device_reanchor_entry_not_head",
            "device re-anchor does not immediately follow the recovery session registry snapshot",
        ));
    }
    Ok(())
}

async fn validate_pre_fence_basis(
    state: &AppState,
    parsed: &ValidatedEventEnvelope,
    basis: Option<&arkret_sdk::SealBasis>,
) -> Result<(), SubmitOneError> {
    let realm_id = RealmId::new(parsed.realm_id.clone()).map_err(|error| {
        SubmitOneError::new(StatusCode::BAD_REQUEST, "invalid_param", error.to_string())
    })?;
    let leaves =
        crate::routing::identity::device_generation::accepted_device_generation_seal_leaves(
            state,
            &parsed.actor_id,
            &realm_id,
        )
        .await
        .map_err(|error| {
            SubmitOneError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                format!("accepted Seal frontier unavailable: {error}"),
            )
        })?;
    if leaves.is_empty() {
        if basis.is_some() {
            return Err(frontier_error());
        }
        return Ok(());
    }
    let Some(basis) = basis else {
        return Err(frontier_error());
    };
    let declared_leaves = basis
        .leaves
        .iter()
        .map(|leaf| leaf.as_str())
        .collect::<Vec<_>>();
    let mut expected_leaves = leaves.iter().map(|leaf| leaf.as_str()).collect::<Vec<_>>();
    expected_leaves.sort_unstable();
    let mut declared_sorted = declared_leaves;
    declared_sorted.sort_unstable();
    if declared_sorted != expected_leaves {
        return Err(frontier_error());
    }
    let view = arkret_sdk::effective_seal_view(
        &leaves,
        &realm_id,
        state.seal_store.as_ref(),
        state.cell_store.as_ref(),
        state.cell_registry.as_ref(),
    )
    .map_err(|_| frontier_error())?;
    if basis.control_event_set_root != view.control_event_set_root
        || basis.state_root != view.state_root
    {
        return Err(frontier_error());
    }
    Ok(())
}

fn typed_device_reanchor_payload(
    envelope: &Value,
) -> Result<arkret_sdk::DeviceReanchorPayload, SubmitOneError> {
    serde_json::from_value(envelope.get("payload").cloned().unwrap_or(Value::Null)).map_err(
        |error| {
            SubmitOneError::new(
                StatusCode::BAD_REQUEST,
                "schema_violation",
                format!("invalid typed ak.device.reanchor payload: {error}"),
            )
        },
    )
}

fn typed_device_authorize_payload(
    envelope: &Value,
) -> Result<arkret_sdk::DeviceAuthorizePayload, SubmitOneError> {
    serde_json::from_value(envelope.get("payload").cloned().unwrap_or(Value::Null)).map_err(
        |error| {
            SubmitOneError::new(
                StatusCode::BAD_REQUEST,
                "schema_violation",
                format!("invalid typed ak.device.authorize payload: {error}"),
            )
        },
    )
}

fn canonical_record(
    parsed: &ValidatedEventEnvelope,
    envelope: Value,
    received_at: DateTime<Utc>,
) -> CanonicalEventRecord {
    CanonicalEventRecord {
        event_id: parsed.event_id.clone(),
        actor_id: parsed.actor_id.clone(),
        actor_seq: parsed.actor_seq,
        realm_id: Some(parsed.realm_id.clone()),
        kind: parsed.kind.clone(),
        schema_id: parsed.schema_id.clone(),
        canonical_digest: parsed.canonical_digest.clone(),
        canonical_bytes: parsed.canonical_bytes.clone(),
        envelope,
        received_at,
    }
}

fn bootstrap_b_model_generation_ref(
    create_envelope: &Value,
    authorize_envelope: &Value,
) -> Result<Option<String>, SubmitOneError> {
    let authorize = typed_device_authorize_payload(authorize_envelope)?;
    let Some(binding) = authorize.enrollment_authority_binding.as_ref() else {
        return Ok(None);
    };
    if binding.authority_did.as_str() == authorize.principal_id.as_str() {
        return Ok(None);
    }
    create_envelope
        .get("refs")
        .and_then(Value::as_array)
        .and_then(|references| {
            references.iter().find(|reference| {
                reference.get("role").and_then(Value::as_str)
                    == Some(arkret_sdk::identity::DID_INCEPTION_REF_ROLE)
            })
        })
        .and_then(|reference| reference.get("id"))
        .and_then(Value::as_str)
        .map(str::to_owned)
        .map(Some)
        .ok_or_else(|| unit_error("PCR bootstrap is missing its validated DID inception ref"))
}

async fn identity_anchor_device_projection(
    state: &AppState,
    authorize: &ValidatedEventEnvelope,
    envelope: &Value,
    authorized_generation_ref: Option<String>,
    accepted_at: DateTime<Utc>,
) -> Result<soland_storage::DeviceInventoryRecord, SubmitOneError> {
    let typed = typed_device_authorize_payload(envelope)?;
    let principal_id = typed.principal_id.as_str();
    let device_id = typed.device_id.as_str();
    let existing = state
        .devices_store()
        .get(principal_id, device_id)
        .await
        .map_err(|error| {
            SubmitOneError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                format!("device projection lookup failed: {error}"),
            )
        })?;
    let mut payload = existing
        .as_ref()
        .map(|record| record.payload.clone())
        .filter(Value::is_object)
        .unwrap_or_else(|| json!({}));
    let payload_object = payload
        .as_object_mut()
        .expect("device payload is an object");
    payload_object.insert("device_id".to_owned(), Value::String(device_id.to_owned()));
    payload_object.insert(
        "device_public_key".to_owned(),
        Value::String(typed.device_public_key.to_string()),
    );
    payload_object.insert(
        "hpke_key".to_owned(),
        Value::String(typed.hpke_key.to_string()),
    );
    payload_object.insert(
        "algorithms".to_owned(),
        Value::Array(
            typed
                .algorithms
                .iter()
                .map(|algorithm| Value::String(algorithm.to_string()))
                .collect(),
        ),
    );
    payload_object.insert("device_authorize_projected".to_owned(), Value::Bool(true));
    payload_object.insert(
        "device_authorize_event_id".to_owned(),
        Value::String(authorize.event_id.clone()),
    );
    if let Some(generation_ref) = authorized_generation_ref {
        payload_object.insert(
            "authorized_generation_ref".to_owned(),
            Value::String(generation_ref),
        );
    } else {
        payload_object.remove("authorized_generation_ref");
    }
    if let Some(binding) = envelope
        .pointer("/payload/cross_signing_binding")
        .filter(|binding| binding.is_object())
    {
        payload_object.insert("cross_signing_binding".to_owned(), binding.clone());
    } else {
        payload_object.remove("cross_signing_binding");
    }
    Ok(soland_storage::DeviceInventoryRecord {
        actor: principal_id.to_owned(),
        device_id: device_id.to_owned(),
        display_name: existing
            .as_ref()
            .and_then(|record| record.display_name.clone()),
        verification_state: "verified".to_owned(),
        payload,
        created_at: existing
            .as_ref()
            .map_or(accepted_at, |record| record.created_at),
        updated_at: accepted_at,
        revoked_at: existing.as_ref().and_then(|record| record.revoked_at),
    })
}

async fn build_reanchor_batch_receipt(
    state: &AppState,
    reanchor: &ValidatedEventEnvelope,
    authorize: &ValidatedEventEnvelope,
    reanchor_envelope: &Value,
    created_at: DateTime<Utc>,
) -> Result<arkret_sdk::EventBatchReceipt, SubmitOneError> {
    let payload = typed_device_reanchor_payload(reanchor_envelope)?;
    let registry_head = state
        .did_application()
        .log_events(&reanchor.actor_id)
        .await
        .map_err(|error| {
            SubmitOneError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                format!("DID history lookup failed: {error}"),
            )
        })?
        .into_iter()
        .find(|entry| {
            entry.operation.get("versionId").and_then(Value::as_str)
                == Some(payload.did_version_id.as_str())
        })
        .map(|entry| entry.event_digest)
        .ok_or_else(|| {
            SubmitOneError::new(
                StatusCode::CONFLICT,
                "device_reanchor_entry_not_head",
                "accepted registry head digest is unavailable",
            )
        })?;
    let mut receipt = arkret_sdk::EventBatchReceipt {
        schema: "ak.schema.event_batch_receipt.v1".to_owned(),
        receipt_id: arkret_sdk::ReceiptId::new(crate::ids::generate("receipt")).map_err(
            |error| {
                SubmitOneError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    format!("generated Event Batch Receipt id is invalid: {error}"),
                )
            },
        )?,
        issuer: Did::new(state.service_id.clone()).map_err(|error| {
            SubmitOneError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                format!("service DID is invalid: {error}"),
            )
        })?,
        scope: arkret_sdk::EventBatchReceiptScope::DeviceReanchor(
            arkret_sdk::DeviceReanchorReceiptScope {
                kind: arkret_sdk::DeviceReanchorReceiptScopeKind::DeviceReanchorUnit,
                principal_id: payload.principal_id,
                realm_id: RealmId::new(reanchor.realm_id.clone()).map_err(|error| {
                    SubmitOneError::new(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "internal_error",
                        format!("stored principal-control Realm id is invalid: {error}"),
                    )
                })?,
                did_version_id: payload.did_version_id,
                registry_head: Hash::new(registry_head).map_err(|error| {
                    SubmitOneError::new(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "internal_error",
                        format!("registry head digest is invalid: {error}"),
                    )
                })?,
                reanchor_digest: Hash::new(reanchor.canonical_digest.clone()).map_err(|error| {
                    SubmitOneError::new(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "internal_error",
                        format!("re-anchor digest is invalid: {error}"),
                    )
                })?,
                replacement_authorize_digest: Hash::new(authorize.canonical_digest.clone())
                    .map_err(|error| {
                        SubmitOneError::new(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "internal_error",
                            format!("replacement authorization digest is invalid: {error}"),
                        )
                    })?,
            },
        ),
        frontier: arkret_sdk::EventBatchReceiptFrontier {
            actor_seq: Some(authorize.actor_seq),
            event_id: Some(EventId::new(authorize.event_id.clone()).map_err(|error| {
                SubmitOneError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    format!("replacement authorization Event id is invalid: {error}"),
                )
            })?),
            event_digest: Some(
                Hash::new(authorize.canonical_digest.clone()).map_err(|error| {
                    SubmitOneError::new(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "internal_error",
                        format!("replacement authorization digest is invalid: {error}"),
                    )
                })?,
            ),
            hlc: None,
        },
        events: vec![
            arkret_sdk::EventBatchReceiptEvent::Item(arkret_sdk::EventBatchReceiptItem {
                event_id: EventId::new(reanchor.event_id.clone()).map_err(|error| {
                    SubmitOneError::new(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "internal_error",
                        format!("re-anchor Event id is invalid: {error}"),
                    )
                })?,
                event_digest: Hash::new(reanchor.canonical_digest.clone()).map_err(|error| {
                    SubmitOneError::new(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "internal_error",
                        format!("re-anchor digest is invalid: {error}"),
                    )
                })?,
                kind: arkret_sdk::NonEmptyString::new(reanchor.kind.clone())
                    .expect("validated Event kind is non-empty"),
            }),
            arkret_sdk::EventBatchReceiptEvent::Item(arkret_sdk::EventBatchReceiptItem {
                event_id: EventId::new(authorize.event_id.clone()).map_err(|error| {
                    SubmitOneError::new(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "internal_error",
                        format!("replacement authorization Event id is invalid: {error}"),
                    )
                })?,
                event_digest: Hash::new(authorize.canonical_digest.clone()).map_err(|error| {
                    SubmitOneError::new(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "internal_error",
                        format!("replacement authorization digest is invalid: {error}"),
                    )
                })?,
                kind: arkret_sdk::NonEmptyString::new(authorize.kind.clone())
                    .expect("validated Event kind is non-empty"),
            }),
        ],
        created_at,
        proofs: Vec::new(),
    };
    receipt.canonicalize_events().map_err(|error| {
        SubmitOneError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            format!("generated Event Batch Receipt events are invalid: {error}"),
        )
    })?;
    receipt
        .proofs
        .push(sign_event_batch_receipt(state, &receipt)?);
    receipt.validate().map_err(|error| {
        SubmitOneError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            format!("generated Event Batch Receipt is invalid: {error}"),
        )
    })?;
    Ok(receipt)
}

fn sign_event_batch_receipt(
    state: &AppState,
    receipt: &arkret_sdk::EventBatchReceipt,
) -> Result<Proof, SubmitOneError> {
    let mut receipt_value = serde_json::to_value(receipt).map_err(|error| {
        SubmitOneError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            format!("Event Batch Receipt encode failed: {error}"),
        )
    })?;
    receipt_value
        .as_object_mut()
        .expect("typed Event Batch Receipt is an object")
        .remove("proofs");
    let receipt_digest = canonical::canonical_sha256(&receipt_value).map_err(|error| {
        SubmitOneError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            format!("Event Batch Receipt digest failed: {error}"),
        )
    })?;
    let verification_method = format!("{}#notary-key", state.service_id);
    let binding = json!({
        "context": "ak.receipt-proof-v1",
        "payload_digest": receipt_digest.as_str(),
        "issuer": receipt.issuer.as_str(),
        "verification_method": verification_method.as_str(),
        "created_at": receipt.created_at,
    });
    let binding_bytes = canonical::canonical_json_bytes(&binding).map_err(|error| {
        SubmitOneError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            format!("Event Batch Receipt proof binding failed: {error}"),
        )
    })?;
    let jws =
        arkret_sdk::jws::sign_jws_ed25519(&binding_bytes, state.notary_signing_key().as_ref())
            .map_err(|error| {
                SubmitOneError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    format!("Event Batch Receipt signing failed: {error}"),
                )
            })?;
    Ok(Proof {
        kind: proof_kind::DETACHED_JWS.to_owned(),
        alg: "EdDSA".to_owned(),
        verification_method,
        event_digest: Hash::new(receipt_digest).map_err(|error| {
            SubmitOneError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                format!("Event Batch Receipt digest is invalid: {error}"),
            )
        })?,
        created_at: receipt.created_at,
        domain: None,
        audience: None,
        jws,
    })
}

fn unit_error(message: &'static str) -> SubmitOneError {
    SubmitOneError::new(StatusCode::BAD_REQUEST, "schema_violation", message)
}

fn frontier_error() -> SubmitOneError {
    SubmitOneError::new(
        StatusCode::CONFLICT,
        "device_reanchor_frontier_mismatch",
        "device re-anchor pre_fence_basis does not match the complete accepted Seal frontier",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event_id(suffix: &str) -> String {
        format!("ak:event:01904100-0000-7000-8000-{suffix}")
    }

    fn attach_bootstrap_fixture_proof(event: &mut arkret_sdk::Event, verification_method: &str) {
        let digest = arkret_sdk::Hash::new(event.event_digest().unwrap()).unwrap();
        event.proofs = vec![arkret_sdk::Proof {
            kind: arkret_sdk::proof_kind::DETACHED_JWS.to_owned(),
            alg: "EdDSA".to_owned(),
            verification_method: verification_method.to_owned(),
            event_digest: digest,
            created_at: event.created_at,
            domain: None,
            audience: None,
            jws: "fixture.signature".to_owned(),
        }];
    }

    fn sdk_canonical_self_principal_bootstrap_unit() -> Vec<Value> {
        let principal =
            arkret_sdk::Did::new("did:webvh:z6mkfixture:users.example:alice".to_owned()).unwrap();
        let realm_id = arkret_sdk::RealmId::new(
            soland_domain::identity::principal_control_realm_for_did(principal.as_str()),
        )
        .unwrap();
        let created_at = "2026-07-15T00:00:00Z".parse().unwrap();
        let mut create = arkret_sdk::identity::build_self_principal_pcr_create(
            arkret_sdk::identity::SelfPrincipalPcrCreateInput {
                principal_id: principal.clone(),
                realm_id: realm_id.clone(),
                trust_domain: arkret_sdk::TypedTrustDomainId::new(
                    "ak:trust_domain:example.net".to_owned(),
                )
                .unwrap(),
                did_inception_ref: arkret_sdk::EventRef::new(
                    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    arkret_sdk::identity::DID_INCEPTION_REF_ROLE,
                ),
                event_id: arkret_sdk::EventId::new(event_id("000000000001")).unwrap(),
                created_at,
                hlc: arkret_sdk::Hlc::new("01970e589d21-0004-a13f9c2e").unwrap(),
            },
        )
        .unwrap();
        attach_bootstrap_fixture_proof(
            &mut create,
            "did:key:z6MkvMW3tjuvW6PqYiX8dLRNwZWyGhxe3biRDjA4ZPiBaFaJ#z6MkvMW3tjuvW6PqYiX8dLRNwZWyGhxe3biRDjA4ZPiBaFaJ",
        );

        let authority = arkret_sdk::Did::new(
            "did:key:z6MkgZb469vbyZCg3L7kx1PbQuUD4NToPpcy1utdLxUUfpsh".to_owned(),
        )
        .unwrap();
        let authorization_ref =
            arkret_sdk::NonEmptyString::new(format!("{}#enrollment-authority", create.actor_id))
                .unwrap();
        let payload = arkret_sdk::DeviceAuthorizePayload {
            principal_id: create.actor_id.clone(),
            device_id: arkret_sdk::DeviceId::new(
                "ak:device:01904100-0000-7000-8000-000000000001".to_owned(),
            )
            .unwrap(),
            device_public_key: arkret_sdk::NonEmptyString::new("z6MkDeviceKey".to_owned()).unwrap(),
            hpke_key: arkret_sdk::NonEmptyString::new("z6LSDeviceHpkeKey".to_owned()).unwrap(),
            algorithms: vec![
                arkret_sdk::NonEmptyString::new(
                    "ak.hpke_x25519_aead_chacha20poly1305.v1".to_owned(),
                )
                .unwrap(),
            ],
            device_key_algorithm: Some(
                arkret_sdk::NonEmptyString::new("EdDSA".to_owned()).unwrap(),
            ),
            authorized_by: arkret_sdk::DeviceOrPrincipalRef::Did(authority.clone()),
            scopes: None,
            not_before: create.created_at,
            expires_at: None,
            device_signature: None,
            proof: None,
            cross_signing_binding: None,
            enrollment_authority_binding: Some(arkret_sdk::DeviceEnrollmentAuthorityBinding {
                kind: arkret_sdk::DeviceEnrollmentAuthorityBindingKind::ServiceAttested,
                authority_did: authority.clone(),
                authorization_ref: authorization_ref.clone(),
            }),
            recovery_session_id: None,
        };
        let mut authorize = arkret_sdk::Event::new(
            arkret_sdk::events::EventKind::DEVICE_AUTHORIZE,
            realm_id,
            principal,
            1,
            arkret_sdk::Hlc::new("01970e589d21-0005-a13f9c2e").unwrap(),
            serde_json::to_value(payload).unwrap(),
        )
        .unwrap();
        authorize.event_id = arkret_sdk::EventId::new(event_id("000000000002")).unwrap();
        authorize.created_at = create.created_at;
        authorize.prev_refs = vec![create.event_id.clone()];
        authorize.executed_by = Some(authority.clone());
        authorize.authorization_ref = Some(authorization_ref.to_string());
        attach_bootstrap_fixture_proof(
            &mut authorize,
            &format!("{authority}#z6MkgZb469vbyZCg3L7kx1PbQuUD4NToPpcy1utdLxUUfpsh"),
        );

        vec![
            serde_json::to_value(create).unwrap(),
            serde_json::to_value(authorize).unwrap(),
        ]
    }

    #[test]
    fn sdk_canonical_two_slot_pcr_bootstrap_gets_closed_context() {
        let envelopes = sdk_canonical_self_principal_bootstrap_unit();
        let context = validate_self_principal_pcr_bootstrap_context(&envelopes)
            .expect("SDK canonical two-slot bootstrap must be recognized");
        assert!(context.self_principal_pcr_bootstrap);
        assert_eq!(
            context.identity_anchor_event_id.as_deref(),
            envelopes[0].get("event_id").and_then(Value::as_str)
        );
    }

    #[test]
    fn external_bootstrap_generation_comes_from_closed_unit_inception_ref() {
        let envelopes = sdk_canonical_self_principal_bootstrap_unit();
        let expected = envelopes[0]["refs"][0]["id"].as_str().unwrap();

        assert_eq!(
            bootstrap_b_model_generation_ref(&envelopes[0], &envelopes[1])
                .unwrap()
                .as_deref(),
            Some(expected)
        );
    }

    #[test]
    fn managed_agent_create_cannot_get_self_principal_pcr_context() {
        let mut envelopes = sdk_canonical_self_principal_bootstrap_unit();
        let mut create: arkret_sdk::Event = serde_json::from_value(envelopes[0].clone()).unwrap();
        create.executed_by = Some(arkret_sdk::Did::new("did:web:controller.example").unwrap());
        create.authorization_ref = Some("ak:capability:managed-agent".to_owned());
        create.proofs.clear();
        attach_bootstrap_fixture_proof(
            &mut create,
            "did:key:z6MkvMW3tjuvW6PqYiX8dLRNwZWyGhxe3biRDjA4ZPiBaFaJ#z6MkvMW3tjuvW6PqYiX8dLRNwZWyGhxe3biRDjA4ZPiBaFaJ",
        );
        envelopes[0] = serde_json::to_value(create).unwrap();

        assert!(validate_self_principal_pcr_bootstrap_context(&envelopes).is_err());
    }

    fn stored_record(envelope: &Value, actor_seq: u64) -> CanonicalEventRecord {
        CanonicalEventRecord {
            event_id: envelope["event_id"].as_str().unwrap().to_owned(),
            actor_id: "did:webvh:z6mkfixture:alice.example".to_owned(),
            actor_seq,
            realm_id: Some("ak:realm:01904100-0000-7000-8000-000000000010".to_owned()),
            kind: envelope["kind"].as_str().unwrap().to_owned(),
            schema_id: "ak.schema.event_envelope.v1".to_owned(),
            canonical_digest: format!(
                "sha256:{}",
                format!("{actor_seq:x}")
                    .repeat(64)
                    .chars()
                    .take(64)
                    .collect::<String>()
            ),
            canonical_bytes: event_canonical_bytes(envelope).unwrap(),
            envelope: envelope.clone(),
            received_at: chrono::Utc::now(),
        }
    }

    #[test]
    fn identity_anchor_classifier_forces_single_and_split_units_onto_closed_path() {
        let reanchor = json!({
            "event_id": event_id("000000000001"),
            "kind": "ak.device.reanchor"
        });
        let unrelated = json!({
            "event_id": event_id("000000000002"),
            "kind": "ak.profile.update"
        });
        assert!(batch_contains_identity_anchor(std::slice::from_ref(
            &reanchor
        )));
        assert!(batch_contains_identity_anchor(&[unrelated, reanchor]));
        assert!(batch_contains_identity_anchor(&[json!({
            "event_id": event_id("000000000003"),
            "kind": "ak.realm.create",
            "refs": [{"role": "did_inception"}]
        })]));
    }

    #[test]
    fn preserved_actor_frontier_ignores_unsealed_siblings_and_keeps_all_sealed_heads() {
        let genesis_id = event_id("000000000010");
        let authorize_id = event_id("000000000011");
        let left_id = event_id("000000000012");
        let right_id = event_id("000000000013");
        let pending_id = event_id("000000000014");
        let genesis = json!({
            "event_id": genesis_id,
            "kind": "ak.realm.create",
            "prev_refs": [],
            "payload": {"object": {"fields": {"purpose": "principal_control"}}}
        });
        let authorize = json!({
            "event_id": authorize_id,
            "kind": "ak.device.authorize",
            "prev_refs": [genesis_id]
        });
        let left = json!({
            "event_id": left_id,
            "kind": "ak.profile.update",
            "prev_refs": [authorize_id]
        });
        let right = json!({
            "event_id": right_id,
            "kind": "ak.contact.update",
            "prev_refs": [authorize_id]
        });
        let pending = json!({
            "event_id": pending_id,
            "kind": "ak.profile.update",
            "prev_refs": [left_id]
        });
        let records = vec![
            stored_record(&genesis, 0),
            stored_record(&authorize, 1),
            stored_record(&left, 2),
            stored_record(&right, 2),
            stored_record(&pending, 3),
        ];
        let covered = [
            records[2].canonical_digest.clone(),
            records[3].canonical_digest.clone(),
        ]
        .into_iter()
        .collect();
        let (max_seq, heads) = preserved_actor_frontier(
            &records,
            "did:webvh:z6mkfixture:alice.example",
            "ak:realm:01904100-0000-7000-8000-000000000010",
            &covered,
        )
        .unwrap();
        assert_eq!(max_seq, 2);
        assert_eq!(heads, vec![left_id, right_id]);
    }

    #[tokio::test]
    async fn identical_retry_survives_response_loss_and_later_head_advancement() {
        let state = AppState::new(
            crate::config::AppConfig::test_default(),
            soland_storage_postgres::Db { pool: None },
        );
        let reanchor = json!({
            "event_id": event_id("000000000001"),
            "kind": "ak.device.reanchor",
            "proofs": [{"jws": "first-transport-proof"}]
        });
        let authorize = json!({
            "event_id": event_id("000000000002"),
            "kind": "ak.device.authorize",
            "proofs": [{"jws": "first-authority-proof"}]
        });
        state
            .events_store()
            .put(stored_record(&reanchor, 10))
            .await
            .unwrap();
        state
            .events_store()
            .put(stored_record(&authorize, 11))
            .await
            .unwrap();
        let later = json!({
            "event_id": event_id("000000000003"),
            "kind": "ak.profile.update"
        });
        state
            .events_store()
            .put(stored_record(&later, 12))
            .await
            .unwrap();

        let mut retried_reanchor = reanchor;
        retried_reanchor["proofs"] = json!([{"jws": "retried-transport-proof"}]);
        let mut retried_authorize = authorize;
        retried_authorize["proofs"] = json!([{"jws": "retried-authority-proof"}]);
        let outcome = identical_historical_retry(&state, &[retried_reanchor, retried_authorize])
            .await
            .unwrap()
            .expect("stored canonical unit must be returned as duplicate");
        assert_eq!(outcome.status, EventsSubmitStatus::Duplicate);
        assert_eq!(outcome.duplicate.len(), 2);
    }
}
