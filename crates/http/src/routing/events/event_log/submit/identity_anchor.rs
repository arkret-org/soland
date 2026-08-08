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

fn event_digests(envelopes: &[Value]) -> Result<Vec<String>, anyhow::Error> {
    envelopes
        .iter()
        .map(|envelope| {
            let event = serde_json::from_value::<arkret_wire::Event>(envelope.clone())?;
            Ok(event.event_digest()?)
        })
        .collect()
}

fn identity_anchor_candidate_device_key(envelope: &Value) -> Option<String> {
    let payload = envelope.get("payload")?;
    (payload
        .get("authorization_binding_kind")
        .and_then(Value::as_str)
        == Some("root_anchored"))
    .then(|| {
        payload
            .get("device_public_key")
            .and_then(Value::as_str)
            .filter(|key| key.starts_with("did:key:"))
            .map(ToOwned::to_owned)
    })
    .flatten()
}

pub(super) async fn submit_identity_anchor_batch(
    state: &AppState,
    session: &SessionRecord,
    envelopes: Vec<Value>,
    authorization_leases: Option<&[Option<arkret_wire::AuthorizationLease>]>,
    submitted_control_proposal_acks: Option<&[Option<arkret_wire::ControlProposalAck>]>,
    receipt_audience: Option<&Did>,
) -> Result<EventsSubmitOutcome, SubmitOneError> {
    if authorization_leases.is_some_and(|leases| leases.len() != envelopes.len()) {
        return Err(unit_error(
            "identity anchor publication lease cardinality mismatch",
        ));
    }
    if submitted_control_proposal_acks.is_some_and(|acks| acks.len() != envelopes.len()) {
        return Err(unit_error(
            "identity anchor control-proposal-ack cardinality mismatch",
        ));
    }
    if envelopes.len() != 2 {
        return Err(unit_error(
            "identity anchor unit must contain exactly two ordered Events",
        ));
    }
    for envelope in &envelopes {
        let encoded_len = serde_json::to_vec(envelope)
            .map_err(|_| unit_error("identity anchor Event cannot be encoded"))?
            .len();
        if arkret_wire::event_envelope::validate_event_envelope_byte_len(encoded_len).is_err() {
            return Err(SubmitOneError::new(
                StatusCode::PAYLOAD_TOO_LARGE,
                "payload_too_large",
                "identity anchor Event exceeds max_event_bytes",
            ));
        }
    }
    let first_kind = event_string_field_from_value(&envelopes[0], "kind");
    let second_kind = event_string_field_from_value(&envelopes[1], "kind");
    let is_bootstrap = first_kind.as_deref() == Some(arkret_wire::EventKind::REALM_CREATE)
        && second_kind.as_deref() == Some(arkret_wire::EventKind::DEVICE_AUTHORIZE);
    let is_reanchor = first_kind.as_deref() == Some("ak.device.reanchor")
        && second_kind.as_deref() == Some(arkret_wire::EventKind::DEVICE_AUTHORIZE);
    if !is_bootstrap && !is_reanchor {
        return Err(unit_error(
            "identity anchor unit must be [ak.realm.create, ak.device.authorize] or [ak.device.reanchor, ak.device.authorize]",
        ));
    }
    if is_bootstrap && authorization_leases.is_some_and(|leases| leases.iter().any(Option::is_some))
    {
        return Err(unit_error(
            "PCR genesis does not accept pre-genesis authorization leases",
        ));
    }
    if is_bootstrap && receipt_audience.is_none() {
        return Err(unit_error(
            "PCR genesis is accepted only through the registered peer relay",
        ));
    }
    let lock_actor = event_string_field_from_value(&envelopes[0], "actor_id")
        .ok_or_else(|| unit_error("identity anchor Event requires actor_id"))?;
    // The bootstrap head is an `ak.realm.create`, which carries no wire
    // `realm_id`: resolve it the SDK way rather than reading a flat field that
    // is absent by construction.
    let lock_realm = event_realm_id_from_value(&envelopes[0])
        .ok_or_else(|| unit_error("identity anchor Event requires realm_id"))?;
    let actor_lock = actor_submit_lock(&lock_realm, &lock_actor);
    let _guard = actor_lock.lock().await;
    let generation_lock =
        crate::routing::identity::device_generation::device_generation_admission_lock(&lock_actor);
    let _generation_guard = generation_lock.lock().await;
    let identity_anchor_head_context = if is_bootstrap {
        Some(validate_self_principal_pcr_bootstrap_context(&envelopes)?)
    } else {
        Some(RealmBootstrapBatchContext {
            realm_id: lock_realm.clone(),
            actor_id: lock_actor.clone(),
            digest_algorithm: None,
            identity_anchor_event_id: event_string_field_from_value(&envelopes[0], "event_id"),
            self_principal_pcr_bootstrap: false,
            identity_anchor_candidate_device_key: identity_anchor_candidate_device_key(
                &envelopes[1],
            ),
            authority_root: None,
        })
    };

    let first_contexts = identity_anchor_head_context.as_slice();
    let first =
        validate_event_envelope_with_context(state, session, &envelopes[0], first_contexts, None)
            .await?;
    let identity_anchor_context =
        identity_anchor_head_context.unwrap_or(RealmBootstrapBatchContext {
            realm_id: first.realm_id.clone(),
            actor_id: first.actor_id.clone(),
            digest_algorithm: None,
            identity_anchor_event_id: Some(first.event_id.clone()),
            self_principal_pcr_bootstrap: false,
            identity_anchor_candidate_device_key: identity_anchor_candidate_device_key(
                &envelopes[1],
            ),
            authority_root: None,
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
    validate_identity_anchor_candidate_preconditions(state, &first, &envelopes, is_bootstrap)?;
    let second_contexts = std::slice::from_ref(&identity_anchor_context);
    let second =
        validate_event_envelope_with_context(state, session, &envelopes[1], second_contexts, None)
            .await?;
    let received_at = now();
    let retry_candidates = [&first, &second]
        .into_iter()
        .zip(envelopes.iter().cloned())
        .map(|(event, envelope)| canonical_record(event, envelope, received_at))
        .collect::<Vec<_>>();
    if let Some(mut outcome) = identical_historical_retry(state, &retry_candidates).await? {
        if authorization_leases.is_some_and(|leases| leases.iter().any(Option::is_some)) {
            let digests = event_digests(&envelopes).map_err(|error| {
                SubmitOneError::new(
                    StatusCode::BAD_REQUEST,
                    "schema_violation",
                    format!("identity anchor digest failed: {error}"),
                )
            })?;
            let evidence = state
                .event_queries()
                .publication_evidence_for_digests(&digests)
                .await
                .map_err(|error| {
                    SubmitOneError::new(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "internal_error",
                        format!("publication evidence store unavailable: {error}"),
                    )
                })?;
            if evidence.len() != envelopes.len() {
                return Err(SubmitOneError::new(
                    StatusCode::CONFLICT,
                    "duplicate_conflict",
                    "accepted identity anchor unit is missing its atomic publication evidence",
                ));
            }
            outcome.ingress_receipts = evidence
                .into_iter()
                .map(|record| record.ingress_receipt)
                .collect();
        }
        return Ok(outcome);
    }
    validate_unit_relationships(state, &first, &second, &envelopes, is_bootstrap).await?;

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
    for dependency in &first.prev_refs {
        if !existing.iter().any(|record| record.event_id == *dependency) {
            return Err(SubmitOneError::new(
                StatusCode::CONFLICT,
                "dependency_missing",
                "identity anchor predecessor is not in accepted history",
            ));
        }
    }
    if is_bootstrap
        && existing.iter().any(|record| {
            record.kind == arkret_wire::EventKind::REALM_CREATE
                && (record.realm_id.as_deref() == Some(first.realm_id.as_str())
                    || (record.actor_id == first.actor_id
                        && record
                            .envelope
                            .pointer("/payload/object/purpose")
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
    let typed_control_events = envelopes
        .iter()
        .cloned()
        .map(serde_json::from_value::<arkret_wire::Event>)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| {
            SubmitOneError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                format!("accepted identity anchor is not canonical Event wire: {error}"),
            )
        })?;
    let control_proposal_acks = if reanchor_conflict {
        Vec::new()
    } else if is_bootstrap {
        if submitted_control_proposal_acks.is_some_and(|acks| acks.iter().any(Option::is_some)) {
            return Err(unit_error(
                "PCR genesis forbids pre-issued Control Proposal Acks",
            ));
        }
        Vec::new()
    } else {
        let submitted = submitted_control_proposal_acks
            .and_then(|acks| acks.iter().cloned().collect::<Option<Vec<_>>>())
            .ok_or_else(|| {
                unit_error("reanchor requires a Control Proposal Ack for each Control Move")
            })?;
        let realm_id = RealmId::new(first.realm_id.clone()).map_err(|error| {
            SubmitOneError::new(StatusCode::BAD_REQUEST, "invalid_param", error.to_string())
        })?;
        let policy = crate::control_proposal::control_proposal_policy(
            state,
            &realm_id,
            &typed_control_events,
        )
        .await
        .map_err(|error| {
            SubmitOneError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "quorum_unreachable",
                format!("identity anchor proposal policy unavailable: {error}"),
            )
        })?;
        for (event, ack) in typed_control_events.iter().zip(&submitted) {
            crate::control_proposal::verify_control_proposal_ack(state, event, ack, policy)
                .await
                .map_err(|error| {
                    SubmitOneError::new(
                        StatusCode::PRECONDITION_FAILED,
                        "failed_precondition",
                        format!("reanchor Control Proposal Ack is invalid: {error}"),
                    )
                })?;
        }
        submitted
    };
    let complete_leases = authorization_leases
        .filter(|leases| leases.iter().any(Option::is_some))
        .map(|leases| {
            leases
                .iter()
                .cloned()
                .collect::<Option<Vec<_>>>()
                .ok_or_else(|| {
                    unit_error("identity anchor cannot mix online and delayed submissions")
                })
        })
        .transpose()?;
    let publication_evidence = if let Some(leases) = complete_leases.as_deref() {
        vec![
            build_ingress_receipt_record(state, &first, &leases[0], received_at)?,
            build_ingress_receipt_record(state, &second, &leases[1], received_at)?,
        ]
    } else {
        Vec::new()
    };
    let ingress_receipts = publication_evidence
        .iter()
        .map(|record| record.ingress_receipt.clone())
        .collect::<Vec<_>>();
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
        bootstrap_generation_ref(&envelopes[0])?
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
    let receipt = if is_bootstrap {
        Some(build_pcr_genesis_batch_receipt(
            state,
            &first,
            &second,
            &envelopes[0],
            receipt_audience.expect("PCR genesis audience checked above"),
            received_at,
        )?)
    } else if is_reanchor && !reanchor_conflict {
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
        let raw_leaves = state
            .projections()
            .realm_seal_leaves(&realm_id)
            .map_err(|error| {
                SubmitOneError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    format!("Seal frontier unavailable: {error}"),
                )
            })?;
        validate_pre_fence_basis(state, &first, payload.pre_fence_basis.as_ref()).await?;
        Some(soland_services::events::IdentityAnchorFrontierState {
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
        Some(soland_services::events::IdentityAnchorReanchorState {
            actor_id: first.actor_id.clone(),
            version_number: payload.did_version_number(),
            did_version_id: payload.did_version_id.to_string(),
            reanchor_digest: first.canonical_digest.clone(),
            authorize_digest: second.canonical_digest.clone(),
        })
    } else {
        None
    };
    // Same rule as the ordinary Event path: the delivery intents are built
    // before the commit and land inside it, so an accepted identity anchor can
    // never outlive its federation fanout.
    let deliveries = identity_anchor_fanout_records(
        state,
        session,
        &[(&first, &envelopes[0]), (&second, &envelopes[1])],
        &control_proposal_acks,
        &publication_evidence,
    )
    .await?;
    crate::routing::events::test_chaos::pause_at(
        state,
        crate::routing::events::test_chaos::PRE_IDENTITY_ANCHOR_COMMIT,
        first.event_id.as_str(),
    )
    .await;
    let commit_outcome = state
        .event_queries()
        .store_identity_anchor_batch(
            records.clone(),
            control_proposal_acks.clone(),
            receipt,
            device_projection,
            frontier_cas,
            reanchor_slot,
            publication_evidence,
            deliveries,
        )
        .await
        .map_err(|error| {
            if error.is_realm_already_exists() {
                realm_already_exists_error()
            } else if let Some(collision) = map_event_hash_collision(first.event_id.clone(), &error)
            {
                collision
            } else if error.is_conflict("device_reanchor_frontier_mismatch") {
                frontier_error()
            } else if error.is_conflict("duplicate_conflict") {
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
        let committed = state
            .event_queries()
            .canonical_events()
            .await
            .map_err(|error| {
                SubmitOneError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    format!("events store unavailable after conflict commit: {error}"),
                )
            })?;
        conflict_evidence = conflicting_reanchor_slot(&first, &second, &envelopes[0], &committed);
    }

    if !reanchor_conflict {
        for event in &typed_control_events {
            let digest = event.event_digest().map_err(|error| {
                SubmitOneError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    format!("accepted identity anchor digest failed: {error}"),
                )
            })?;
            let ack = control_proposal_acks
                .iter()
                .find(|ack| ack.proposal_digest.as_str() == digest);
            state
                .projections()
                .put_pending_control_event(event, ack)
                .map_err(|error| {
                    SubmitOneError::new(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "internal_error",
                        format!("accepted identity anchor pending index unavailable: {error}"),
                    )
                })?;
        }
        state.wake_control_seal_coordinator();
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
    for parsed in [&first, &second] {
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
        let mut outcome = events_submit_outcome(
            EventsSubmitStatus::Partial,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            conflict_evidence,
            None,
        );
        outcome.ingress_receipts = ingress_receipts;
        Ok(outcome)
    } else {
        let cursor = super::super::super::sync::sync_barrier_token_for_event(
            state,
            session,
            &second.event_id,
        )
        .await;
        let mut outcome = events_submit_outcome(
            EventsSubmitStatus::Accepted,
            vec![first.event_id, second.event_id],
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Some(cursor),
        );
        outcome.ingress_receipts = ingress_receipts;
        outcome.control_proposal_acks = control_proposal_acks;
        Ok(outcome)
    }
}

/// Validate every relationship that supplies trust to the candidate device
/// before its Event proof is evaluated. At this point the root Event is fully
/// verified, while the candidate is intentionally absent from the durable
/// device directory.
fn validate_identity_anchor_candidate_preconditions(
    state: &AppState,
    first: &ValidatedEventEnvelope,
    envelopes: &[Value],
    is_bootstrap: bool,
) -> Result<(), SubmitOneError> {
    let second = envelopes
        .get(1)
        .and_then(Value::as_object)
        .ok_or_else(|| unit_error("identity anchor authorize Event must be an object"))?;
    let second_actor = second
        .get("actor_id")
        .and_then(Value::as_str)
        .ok_or_else(|| unit_error("identity anchor authorize Event requires actor_id"))?;
    let second_realm = event_realm_id_from_value(&envelopes[1])
        .ok_or_else(|| unit_error("identity anchor authorize Event requires realm_id"))?;
    let second_actor_seq = second
        .get("actor_seq")
        .and_then(Value::as_u64)
        .ok_or_else(|| unit_error("identity anchor authorize Event requires actor_seq"))?;
    let second_prev_refs = second
        .get("prev_refs")
        .and_then(Value::as_array)
        .map(|values| values.iter().filter_map(Value::as_str).collect::<Vec<_>>())
        .unwrap_or_default();
    if second_actor != first.actor_id
        || second_realm != first.realm_id
        || second_actor_seq != first.actor_seq.saturating_add(1)
        || second_prev_refs != vec![first.event_id.as_str()]
    {
        return Err(unit_error(
            "candidate device authorization does not immediately continue the verified anchor Event",
        ));
    }

    let authorize = typed_device_authorize_payload(&envelopes[1])?;
    let authorized_by_root = matches!(
        &authorize.authorized_by,
        arkret_models_collaboration::events_payloads::device_identity::DeviceOrPrincipalRef::Did(did)
            if did.as_str() == first.actor_id
    );
    if authorize.principal_id.as_str() != first.actor_id
        || authorize.authorization_binding_kind
            != arkret_models_collaboration::events_payloads::device_identity::DeviceAuthorizationBindingKind::RootAnchored
        || !authorized_by_root
    {
        return Err(unit_error(
            "candidate device authorization is not bound to the verified principal root",
        ));
    }
    crate::routing::identity::device_signing::validate_device_authorize_binding(
        state,
        envelopes[1].get("payload").unwrap_or(&Value::Null),
    )
    .map_err(|message| {
        unit_error(format!(
            "candidate device possession proof failed: {message}"
        ))
    })?;

    let authorize_payload_digest =
        arkret_models_collaboration::events_payloads::device_authorize_payload_digest(
            envelopes[1].get("payload").unwrap_or(&Value::Null),
            arkret_canonical::DigestSuite::Sha256,
        )
        .map_err(|error| {
            unit_error(format!(
                "candidate device authorization payload digest failed: {error}"
            ))
        })?;
    if is_bootstrap {
        let create: arkret_models_collaboration::events_payloads::RealmCreatePayload =
            serde_json::from_value(envelopes[0].get("payload").cloned().unwrap_or(Value::Null))
                .map_err(|error| {
                    unit_error(format!("invalid typed PCR genesis payload: {error}"))
                })?;
        let descriptor = create
            .object
            .founding_device_descriptor
            .ok_or_else(|| unit_error("PCR genesis omits its founding device descriptor"))?;
        descriptor
            .validate()
            .map_err(|error| unit_error(format!("invalid founding device descriptor: {error}")))?;
        let device_key_digest = format!(
            "sha256:{}",
            sha256_hex(descriptor.device_public_key.as_bytes())
        );
        let hpke_key_digest = format!("sha256:{}", sha256_hex(descriptor.hpke_key.as_bytes()));
        if descriptor.device_id != authorize.device_id
            || descriptor.device_public_key != authorize.device_public_key
            || descriptor.hpke_key != authorize.hpke_key
            || descriptor.algorithms != authorize.algorithms
            || descriptor.founding_authorize_payload_digest != authorize_payload_digest
            || descriptor.device_key_digest.as_str() != device_key_digest
            || descriptor.hpke_key_digest.as_str() != hpke_key_digest
        {
            return Err(unit_error(
                "PCR genesis descriptor does not match its candidate device authorization",
            ));
        }
    } else {
        let reanchor = typed_device_reanchor_payload(&envelopes[0])?;
        if reanchor.replacement_authorize_payload_digest != authorize_payload_digest {
            return Err(unit_error(
                "device re-anchor does not commit to its candidate authorization payload",
            ));
        }
    }
    Ok(())
}

async fn identity_anchor_fanout_records(
    state: &AppState,
    session: &SessionRecord,
    unit: &[(&ValidatedEventEnvelope, &Value)],
    control_proposal_acks: &[arkret_wire::ControlProposalAck],
    publication_evidence: &[soland_services::events::PublicationEvidenceRecord],
) -> Result<Vec<soland_services::events::FederationDelivery>, SubmitOneError> {
    if session.token_hash.starts_with("federation:") {
        return Ok(Vec::new());
    }
    let mut deliveries = Vec::new();
    for (parsed, envelope) in unit {
        let control_proposal_ack = control_proposal_acks
            .iter()
            .find(|ack| ack.proposal_digest.as_str() == parsed.canonical_digest);
        deliveries.extend(
            // This unit's ingress receipts are minted but not yet durable —
            // they commit alongside these very outbox rows.
            peer_event_fanout_records(
                state,
                parsed,
                envelope,
                control_proposal_ack,
                publication_evidence,
                None,
            )
            .await
            .map_err(|error| {
                SubmitOneError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "federation_fanout_unavailable",
                    format!("identity anchor federation delivery intent unavailable: {error}"),
                )
            })?,
        );
    }
    Ok(deliveries)
}

fn validate_self_principal_pcr_bootstrap_context(
    envelopes: &[Value],
) -> Result<RealmBootstrapBatchContext, SubmitOneError> {
    let create: arkret_wire::Event =
        serde_json::from_value(envelopes[0].clone()).map_err(|error| {
            SubmitOneError::new(
                StatusCode::BAD_REQUEST,
                "schema_violation",
                format!("self-principal PCR create is not a canonical Event: {error}"),
            )
        })?;
    let authorize: arkret_wire::Event =
        serde_json::from_value(envelopes[1].clone()).map_err(|error| {
            SubmitOneError::new(
                StatusCode::BAD_REQUEST,
                "schema_violation",
                format!("self-principal PCR authorize is not a canonical Event: {error}"),
            )
        })?;
    arkret_bootstrap::validate_self_principal_pcr_genesis_unit(
        &create,
        &authorize,
        &genesis_cell_write_projector,
    )
    .map_err(|error| {
        SubmitOneError::new(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            format!("self-principal PCR bootstrap unit violates the closed profile: {error}"),
        )
    })?;
    Ok(RealmBootstrapBatchContext {
        realm_id: create.realm_id.to_string(),
        actor_id: create.actor_id.to_string(),
        digest_algorithm: Some(staged_realm_digest_algorithm(&envelopes[0])),
        identity_anchor_event_id: Some(create.event_id.to_string()),
        self_principal_pcr_bootstrap: true,
        identity_anchor_candidate_device_key: identity_anchor_candidate_device_key(&envelopes[1]),
        authority_root: None,
    })
}

pub(super) async fn identical_historical_retry(
    state: &AppState,
    candidates: &[CanonicalEventRecord],
) -> Result<Option<EventsSubmitOutcome>, SubmitOneError> {
    let ids = candidates
        .iter()
        .map(|record| record.event_id.clone())
        .collect::<Vec<_>>();
    let mut existing = Vec::with_capacity(ids.len());
    for id in &ids {
        existing.push(
            state
                .event_queries()
                .canonical_event(id)
                .await
                .map_err(|error| {
                    SubmitOneError::new(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "internal_error",
                        format!("events store unavailable: {error}"),
                    )
                })?,
        );
    }
    if existing.iter().all(Option::is_none) {
        return Ok(None);
    }
    if existing.iter().zip(candidates).all(|(record, candidate)| {
        record
            .as_ref()
            .is_some_and(|record| record.canonical_bytes == candidate.canonical_bytes)
    }) {
        if ids.iter().any(|id| EventId::new(id.clone()).is_err()) {
            return Err(unit_error("stored identity anchor Event id is invalid"));
        }
        let mut outcome = events_submit_outcome(
            EventsSubmitStatus::Duplicate,
            Vec::new(),
            ids,
            Vec::new(),
            Vec::new(),
            None,
        );
        for record in existing.iter().flatten() {
            let digest = Hash::new(record.canonical_digest.clone()).map_err(|error| {
                SubmitOneError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    format!("stored anchor Event digest is invalid: {error}"),
                )
            })?;
            let indexed_ack =
                state
                    .projections()
                    .control_proposal_ack(&digest)
                    .map_err(|error| {
                        SubmitOneError::new(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "internal_error",
                            format!("stored Control Proposal Ack unavailable: {error}"),
                        )
                    })?;
            let durable_ack = if indexed_ack.is_none() {
                state
                    .event_queries()
                    .control_proposal_ack_for_event(&record.event_id)
                    .await
                    .map_err(|error| {
                        SubmitOneError::new(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "internal_error",
                            format!("durable Control Proposal Ack unavailable: {error}"),
                        )
                    })?
            } else {
                None
            };
            let ack = indexed_ack.or(durable_ack);
            let event = serde_json::from_value::<arkret_wire::Event>(record.envelope.clone())
                .map_err(|error| {
                    SubmitOneError::new(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "internal_error",
                        format!("stored identity anchor is not canonical Event wire: {error}"),
                    )
                })?;
            state
                .projections()
                .put_pending_control_event(&event, ack.as_ref())
                .map_err(|error| {
                    SubmitOneError::new(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "internal_error",
                        format!("accepted identity anchor pending index recovery failed: {error}"),
                    )
                })?;
            if let Some(ack) = ack {
                outcome.control_proposal_acks.push(ack);
            }
        }
        state.wake_control_seal_coordinator();
        return Ok(Some(outcome));
    }
    if let Some(candidate) = existing
        .iter()
        .zip(candidates)
        .find_map(|(record, candidate)| {
            record
                .as_ref()
                .filter(|record| record.canonical_bytes != candidate.canonical_bytes)
                .map(|_| candidate)
        })
    {
        return Err(quarantine_verified_event_collision(state, candidate.clone()).await);
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
            let candidate_authorize_digest =
                soland_services::events::paired_replacement_authorize(record, existing)
                    .map(|paired| paired.canonical_digest.as_str());
            candidate_version != Some(version_id)
                || record.canonical_digest != reanchor.canonical_digest
                || candidate_authorize_digest != Some(authorize.canonical_digest.as_str())
        })
        .flat_map(|record| {
            std::iter::once(record.event_id.clone()).chain(
                soland_services::events::paired_replacement_authorize(record, existing)
                    .map(|paired| paired.event_id.clone()),
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
    let expected_realm =
        soland_services::identity::principal_control_realm_for_did(&first.actor_id);
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
        let create: arkret_models_collaboration::events_payloads::RealmCreatePayload =
            serde_json::from_value(envelopes[0].get("payload").cloned().unwrap_or(Value::Null))
                .map_err(|error| {
                    SubmitOneError::new(
                        StatusCode::BAD_REQUEST,
                        "schema_violation",
                        format!("invalid typed PCR genesis payload: {error}"),
                    )
                })?;
        let descriptor = create
            .object
            .founding_device_descriptor
            .ok_or_else(|| unit_error("PCR genesis omits its founding device descriptor"))?;
        descriptor.validate().map_err(|error| {
            SubmitOneError::new(
                StatusCode::BAD_REQUEST,
                "schema_violation",
                format!("invalid founding device descriptor: {error}"),
            )
        })?;
        let authorize = typed_device_authorize_payload(&envelopes[1])?;
        let authorize_payload_digest =
            arkret_models_collaboration::events_payloads::device_authorize_payload_digest(
                envelopes[1].get("payload").unwrap_or(&Value::Null),
                arkret_canonical::DigestSuite::Sha256,
            )
            .map_err(|error| {
                SubmitOneError::new(
                    StatusCode::BAD_REQUEST,
                    "schema_violation",
                    format!("PCR genesis authorize payload digest failed: {error}"),
                )
            })?;
        let device_key_digest = format!(
            "sha256:{}",
            sha256_hex(descriptor.device_public_key.as_bytes())
        );
        let hpke_key_digest = format!("sha256:{}", sha256_hex(descriptor.hpke_key.as_bytes()));
        let authorized_by_root = matches!(
            &authorize.authorized_by,
            arkret_models_collaboration::events_payloads::device_identity::DeviceOrPrincipalRef::Did(did)
                if did.as_str() == first.actor_id
        );
        if authorize.principal_id.as_str() != first.actor_id
            || authorize.authorization_binding_kind
                != arkret_models_collaboration::events_payloads::device_identity::DeviceAuthorizationBindingKind::RootAnchored
            || !authorized_by_root
            || authorize.recovery_session_id.is_some()
            || descriptor.device_id != authorize.device_id
            || descriptor.device_public_key != authorize.device_public_key
            || descriptor.hpke_key != authorize.hpke_key
            || descriptor.algorithms != authorize.algorithms
            || descriptor.founding_authorize_payload_digest != authorize_payload_digest
            || descriptor.device_key_digest.as_str() != device_key_digest
            || descriptor.hpke_key_digest.as_str() != hpke_key_digest
        {
            return Err(unit_error(
                "PCR genesis descriptor does not match its root-anchored founding authorization",
            ));
        }
        return Ok(());
    }

    let payload = typed_device_reanchor_payload(&envelopes[0])?;
    let authorize = typed_device_authorize_payload(&envelopes[1])?;
    // The re-anchor commits to the replacement by payload digest: the authorize
    // envelope carries the re-anchor id in prev_refs (checked above) and every
    // event_id derives from its own signed content, so an id or envelope-digest
    // binding would make the two Events preimages of each other.
    let replacement_payload_digest = soland_services::events::replacement_authorize_payload_digest(
        &envelopes[1],
        &second.canonical_digest,
    )
    .map_err(|message| {
        SubmitOneError::new(StatusCode::INTERNAL_SERVER_ERROR, "internal_error", message)
    })?;
    if payload.principal_id.as_str() != first.actor_id
        || payload.replacement_authorize_payload_digest != replacement_payload_digest
        || authorize.principal_id.as_str() != first.actor_id
        || authorize.authorization_binding_kind
            != arkret_models_collaboration::events_payloads::device_identity::DeviceAuthorizationBindingKind::RootAnchored
    {
        return Err(SubmitOneError::new(
            StatusCode::CONFLICT,
            "device_reanchor_authorize_mismatch",
            "device re-anchor replacement authorization payload digest or generation binding mismatch",
        ));
    }
    validate_reanchor_recovery_session(state, &payload, &authorize).await?;
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
    basis: Option<&arkret_wire::DeviceReanchorPreFenceBasis>,
) -> Result<(), SubmitOneError> {
    let covered_digests = if let Some(basis) = basis {
        state
            .projections()
            .seal_leaf_union_proof(&basis.leaves)
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
    let records = state
        .event_queries()
        .canonical_events()
        .await
        .map_err(|error| {
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
                && record.kind == arkret_wire::EventKind::REALM_CREATE
                && record
                    .envelope
                    .pointer("/payload/object/purpose")
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
                && record.kind == arkret_wire::EventKind::DEVICE_AUTHORIZE
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

async fn validate_reanchor_recovery_session(
    state: &AppState,
    reanchor: &arkret_models_collaboration::events_payloads::device_identity::DeviceReanchorPayload,
    authorize: &arkret_models_collaboration::events_payloads::device_identity::DeviceAuthorizePayload,
) -> Result<(), SubmitOneError> {
    let session_id = authorize.recovery_session_id.as_ref().ok_or_else(|| {
        SubmitOneError::new(
            StatusCode::CONFLICT,
            "device_reanchor_authorize_mismatch",
            "replacement device authorization must bind a verified recovery session",
        )
    })?;
    let session = state
        .recovery_sessions()
        .session(session_id.as_str())
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
        .dids()
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
    basis: Option<&arkret_wire::DeviceReanchorPreFenceBasis>,
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
    // The declared roots are compare-and-swap operands, not decoration: the
    // producer snapshotted them, and admission rejects the unit if the live
    // view has moved since (event-auth-state-resolution.md 5.1). Comparing them
    // is the reason they are on the wire at all, and the reason this frontier
    // does not reuse the leaves-only Control Move seal_basis.
    let view = state
        .projections()
        .effective_seal_view(&leaves, &realm_id)
        .map_err(|_| frontier_error())?;
    if view.control_event_set_root != basis.control_event_set_root
        || view.state_root != basis.state_root
    {
        return Err(frontier_error());
    }
    Ok(())
}

fn typed_device_reanchor_payload(
    envelope: &Value,
) -> Result<
    arkret_models_collaboration::events_payloads::device_identity::DeviceReanchorPayload,
    SubmitOneError,
> {
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
) -> Result<
    arkret_models_collaboration::events_payloads::device_identity::DeviceAuthorizePayload,
    SubmitOneError,
> {
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

pub(super) fn canonical_record(
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

fn bootstrap_generation_ref(create_envelope: &Value) -> Result<Option<String>, SubmitOneError> {
    create_envelope
        .get("refs")
        .and_then(Value::as_array)
        .and_then(|references| {
            references.iter().find(|reference| {
                reference.get("role").and_then(Value::as_str)
                    == Some(arkret_bootstrap::DID_INCEPTION_REF_ROLE)
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
) -> Result<soland_services::events::IdentityAnchorDeviceState, SubmitOneError> {
    let typed = typed_device_authorize_payload(envelope)?;
    let principal_id = typed.principal_id.as_str();
    let device_id = typed.device_id.as_str();
    let existing = state
        .identities()
        .find_device(soland_services::identity::FindDeviceQuery {
            actor_id: principal_id.to_owned(),
            device_id: device_id.to_owned(),
        })
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
    payload_object.insert(
        "authorization_binding_kind".to_owned(),
        serde_json::to_value(typed.authorization_binding_kind)
            .expect("device authorization binding kind is serializable"),
    );
    Ok(soland_services::events::IdentityAnchorDeviceState {
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

fn build_pcr_genesis_batch_receipt(
    state: &AppState,
    create: &ValidatedEventEnvelope,
    authorize: &ValidatedEventEnvelope,
    create_envelope: &Value,
    audience: &Did,
    created_at: DateTime<Utc>,
) -> Result<arkret_wire::EventBatchReceipt, SubmitOneError> {
    let create_payload: arkret_models_collaboration::events_payloads::realm::RealmCreatePayload =
        serde_json::from_value(
            create_envelope
                .get("payload")
                .cloned()
                .unwrap_or(Value::Null),
        )
        .map_err(|error| {
            SubmitOneError::new(
                StatusCode::BAD_REQUEST,
                "schema_violation",
                format!("invalid typed PCR genesis payload: {error}"),
            )
        })?;
    let descriptor = create_payload
        .object
        .founding_device_descriptor
        .ok_or_else(|| unit_error("PCR genesis omits its founding device descriptor"))?;
    let create_digest = Hash::new(create.canonical_digest.clone()).map_err(|error| {
        SubmitOneError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            format!("PCR genesis create digest is invalid: {error}"),
        )
    })?;
    let authorize_digest = Hash::new(authorize.canonical_digest.clone()).map_err(|error| {
        SubmitOneError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            format!("PCR genesis authorize digest is invalid: {error}"),
        )
    })?;
    let mut receipt = arkret_wire::EventBatchReceipt {
        schema: arkret_wire::EventBatchReceipt::SCHEMA.to_owned(),
        receipt_id: arkret_identifiers::ReceiptId::new(crate::ids::generate("receipt")).map_err(
            |error| {
                SubmitOneError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    format!("generated Event Batch Receipt id is invalid: {error}"),
                )
            },
        )?,
        issuer: Did::new(state.service_id().clone()).map_err(|error| {
            SubmitOneError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                format!("service DID is invalid: {error}"),
            )
        })?,
        scope: arkret_wire::EventBatchReceiptScope::PcrGenesis(
            arkret_wire::event_receipt::PcrGenesisReceiptScope {
                kind: arkret_wire::event_receipt::PcrGenesisReceiptScopeKind::PcrGenesisUnit,
                principal_id: Did::new(create.actor_id.clone()).map_err(|error| {
                    SubmitOneError::new(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "internal_error",
                        format!("PCR genesis principal is invalid: {error}"),
                    )
                })?,
                realm_id: RealmId::new(create.realm_id.clone()).map_err(|error| {
                    SubmitOneError::new(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "internal_error",
                        format!("PCR genesis Realm id is invalid: {error}"),
                    )
                })?,
                create_digest: create_digest.clone(),
                founding_authorize_digest: authorize_digest.clone(),
                accepted_device_id: descriptor.device_id,
                device_key_digest: descriptor.device_key_digest,
                hpke_key_digest: descriptor.hpke_key_digest,
                accepted_at: created_at,
                audience: audience.clone(),
            },
        ),
        frontier: arkret_wire::EventBatchReceiptFrontier {
            actor_seq: Some(authorize.actor_seq),
            event_id: Some(EventId::new(authorize.event_id.clone()).map_err(|error| {
                SubmitOneError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    format!("PCR genesis authorize Event id is invalid: {error}"),
                )
            })?),
            event_digest: Some(authorize_digest.clone()),
            hlc: None,
        },
        events: vec![
            arkret_wire::EventBatchReceiptEvent::Item(arkret_wire::EventBatchReceiptItem {
                event_id: EventId::new(create.event_id.clone()).map_err(|error| {
                    SubmitOneError::new(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "internal_error",
                        format!("PCR genesis create Event id is invalid: {error}"),
                    )
                })?,
                event_digest: create_digest,
                kind: arkret_wire::NonEmptyString::new(create.kind.clone())
                    .expect("validated Event kind is non-empty"),
            }),
            arkret_wire::EventBatchReceiptEvent::Item(arkret_wire::EventBatchReceiptItem {
                event_id: EventId::new(authorize.event_id.clone()).map_err(|error| {
                    SubmitOneError::new(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "internal_error",
                        format!("PCR genesis authorize Event id is invalid: {error}"),
                    )
                })?,
                event_digest: authorize_digest,
                kind: arkret_wire::NonEmptyString::new(authorize.kind.clone())
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
            format!("generated PCR genesis receipt events are invalid: {error}"),
        )
    })?;
    receipt
        .proofs
        .push(sign_event_batch_receipt(state, &receipt)?);
    receipt.validate().map_err(|error| {
        SubmitOneError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            format!("generated PCR genesis receipt is invalid: {error}"),
        )
    })?;
    Ok(receipt)
}

async fn build_reanchor_batch_receipt(
    state: &AppState,
    reanchor: &ValidatedEventEnvelope,
    authorize: &ValidatedEventEnvelope,
    reanchor_envelope: &Value,
    created_at: DateTime<Utc>,
) -> Result<arkret_wire::EventBatchReceipt, SubmitOneError> {
    let payload = typed_device_reanchor_payload(reanchor_envelope)?;
    let registry_head = state
        .dids()
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
    let mut receipt = arkret_wire::EventBatchReceipt {
        schema: "ak.schema.event_batch_receipt.v1".to_owned(),
        receipt_id: arkret_identifiers::ReceiptId::new(crate::ids::generate("receipt")).map_err(
            |error| {
                SubmitOneError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    format!("generated Event Batch Receipt id is invalid: {error}"),
                )
            },
        )?,
        issuer: Did::new(state.service_id().clone()).map_err(|error| {
            SubmitOneError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                format!("service DID is invalid: {error}"),
            )
        })?,
        scope: arkret_wire::EventBatchReceiptScope::DeviceReanchor(
            arkret_wire::event_receipt::DeviceReanchorReceiptScope {
                kind:
                    arkret_wire::event_receipt::DeviceReanchorReceiptScopeKind::DeviceReanchorUnit,
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
        frontier: arkret_wire::EventBatchReceiptFrontier {
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
            arkret_wire::EventBatchReceiptEvent::Item(arkret_wire::EventBatchReceiptItem {
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
                kind: arkret_wire::NonEmptyString::new(reanchor.kind.clone())
                    .expect("validated Event kind is non-empty"),
            }),
            arkret_wire::EventBatchReceiptEvent::Item(arkret_wire::EventBatchReceiptItem {
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
                kind: arkret_wire::NonEmptyString::new(authorize.kind.clone())
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
    receipt: &arkret_wire::EventBatchReceipt,
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
    let verification_method =
        arkret_wire::DidUrl::new(format!("{}#notary-key", state.service_id())).map_err(
            |error| {
                SubmitOneError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    format!("service notary verification method is invalid: {error}"),
                )
            },
        )?;
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
    let jws = arkret_signatures::jws::sign_jws_ed25519(
        &binding_bytes,
        state.notary_signing_key().as_ref(),
    )
    .map_err(|error| {
        SubmitOneError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            format!("Event Batch Receipt signing failed: {error}"),
        )
    })?;
    Ok(Proof {
        kind: proof_kind::DETACHED_JWS.to_owned(),
        proof_purpose: None,
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

fn unit_error(message: impl Into<String>) -> SubmitOneError {
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
        arkret_identifiers::EventId::from_digest(
            arkret_canonical::DigestSuite::Sha256,
            [suffix.parse::<u8>().unwrap(); 32],
        )
        .to_string()
    }

    fn attach_bootstrap_fixture_proof(event: &mut arkret_wire::Event, verification_method: &str) {
        let digest = arkret_identifiers::Hash::new(event.event_digest().unwrap()).unwrap();
        event.proofs = vec![arkret_wire::Proof {
            kind: arkret_wire::proof_kind::DETACHED_JWS.to_owned(),
            proof_purpose: None,
            verification_method: arkret_wire::DidUrl::new(verification_method.to_owned())
                .expect("fixture verification method is a DID URL"),
            event_digest: digest,
            created_at: event.created_at,
            domain: None,
            audience: None,
            jws: "fixture.signature".to_owned(),
        }];
    }

    fn fixture_founding_authorize_payload(
        principal: &arkret_identifiers::Did,
        created_at: chrono::DateTime<chrono::Utc>,
    ) -> arkret_models_collaboration::events_payloads::device_identity::DeviceAuthorizePayload {
        arkret_models_collaboration::events_payloads::device_identity::DeviceAuthorizePayload {
            principal_id: principal.clone(),
            device_id: arkret_identifiers::DeviceId::new(
                "ak:device:01904100-0000-7000-8000-000000000001".to_owned(),
            )
            .unwrap(),
            device_public_key: arkret_wire::NonEmptyString::new(
                "did:key:z6MkvMW3tjuvW6PqYiX8dLRNwZWyGhxe3biRDjA4ZPiBaFaJ".to_owned(),
            )
            .unwrap(),
            hpke_key: arkret_wire::NonEmptyString::new("z6LSDeviceHpkeKey".to_owned()).unwrap(),
            algorithms: vec![arkret_wire::NonEmptyString::new(
                "ak.hpke_x25519_aead_chacha20poly1305.v1".to_owned(),
            )
            .unwrap()],
            device_key_algorithm: Some(
                arkret_wire::NonEmptyString::new("Ed25519".to_owned()).unwrap(),
            ),
            authorized_by: arkret_models_collaboration::events_payloads::device_identity::DeviceOrPrincipalRef::Did(principal.clone()),
            scopes: None,
            not_before: created_at,
            expires_at: None,
            authorization_binding_kind: arkret_models_collaboration::events_payloads::device_identity::DeviceAuthorizationBindingKind::RootAnchored,
            device_signature: arkret_models_collaboration::events_payloads::SignatureMaterial::NonEmptyString(
                arkret_wire::NonEmptyString::new("AA".to_owned()).unwrap(),
            ),
            recovery_session_id: None,
        }
    }

    fn fixture_founding_device_descriptor(
        principal: &arkret_identifiers::Did,
        created_at: chrono::DateTime<chrono::Utc>,
    ) -> arkret_models_collaboration::events_payloads::FoundingDeviceDescriptor {
        let payload = fixture_founding_authorize_payload(principal, created_at);
        let payload_value = serde_json::to_value(&payload).unwrap();
        arkret_models_collaboration::events_payloads::FoundingDeviceDescriptor {
            descriptor_version: 1,
            device_id: payload.device_id.clone(),
            device_key_digest: arkret_wire::Hash::new(arkret_canonical::sha256_digest(
                payload.device_public_key.as_bytes(),
            ))
            .unwrap(),
            device_public_key: payload.device_public_key.clone(),
            device_key_algorithm: arkret_models_collaboration::events_payloads::FoundingDeviceKeyAlgorithm::Ed25519,
            device_key_purpose: arkret_models_collaboration::events_payloads::FoundingDeviceKeyPurpose::EventSigningAndMlsIdentity,
            hpke_key_digest: arkret_wire::Hash::new(arkret_canonical::sha256_digest(
                payload.hpke_key.as_bytes(),
            ))
            .unwrap(),
            hpke_key: payload.hpke_key.clone(),
            hpke_key_algorithm: arkret_models_collaboration::events_payloads::FoundingDeviceHpkeKeyAlgorithm::X25519,
            algorithms: payload.algorithms.clone(),
            founding_authorize_payload_digest: arkret_models_collaboration::events_payloads::device_identity::device_authorize_payload_digest(
                &payload_value,
                arkret_canonical::DigestSuite::Sha256,
            )
            .unwrap(),
        }
    }

    fn sdk_canonical_self_principal_bootstrap_unit() -> Vec<Value> {
        let principal =
            arkret_identifiers::Did::new("did:webvh:z6mkfixture:users.example:alice".to_owned())
                .unwrap();
        let realm_id = arkret_identifiers::RealmId::new(
            soland_services::identity::principal_control_realm_for_did(principal.as_str()),
        )
        .unwrap();
        let created_at = "2026-07-15T00:00:00.000Z".parse().unwrap();
        let mut create = arkret_bootstrap::build_self_principal_pcr_create(
            arkret_bootstrap::SelfPrincipalPcrCreateInput {
                principal_id: principal.clone(),
                realm_id: realm_id.clone(),
                trust_domain: arkret_identifiers::TypedTrustDomainId::new(
                    "ak:trust_domain:example.net".to_owned(),
                )
                .unwrap(),
                did_inception_ref: arkret_wire::EventRef::new(
                    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    arkret_bootstrap::DID_INCEPTION_REF_ROLE,
                ),
                founding_device_descriptor: fixture_founding_device_descriptor(
                    &principal, created_at,
                ),
                capability_action_registry_digest:
                    arkret_policy::current_capability_action_registry_digest().unwrap(),
                created_at,
                hlc: arkret_identifiers::Hlc::new("01970e589d21-0004-a13f9c2e").unwrap(),
            },
            &genesis_cell_write_projector,
        )
        .unwrap();
        attach_bootstrap_fixture_proof(
            &mut create,
            "did:key:z6MkvMW3tjuvW6PqYiX8dLRNwZWyGhxe3biRDjA4ZPiBaFaJ#z6MkvMW3tjuvW6PqYiX8dLRNwZWyGhxe3biRDjA4ZPiBaFaJ",
        );

        let payload = fixture_founding_authorize_payload(&create.actor_id, create.created_at);
        let authorize_verification_method = format!("{}#{}", create.actor_id, payload.device_id);
        let mut authorize = arkret_wire::Event::new(
            arkret_wire::EventKind::DEVICE_AUTHORIZE,
            arkret_wire::ScopeRef::Realm { realm_id },
            principal,
            1,
            arkret_identifiers::Hlc::new("01970e589d21-0005-a13f9c2e").unwrap(),
            serde_json::to_value(payload).unwrap(),
        )
        .unwrap();
        authorize.event_id = arkret_identifiers::EventId::new(event_id("000000000002")).unwrap();
        authorize.created_at = create.created_at;
        authorize.prev_refs = vec![create.event_id.clone()];
        attach_bootstrap_fixture_proof(&mut authorize, &authorize_verification_method);

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
    fn genesis_generation_comes_from_closed_unit_inception_ref() {
        let envelopes = sdk_canonical_self_principal_bootstrap_unit();
        let expected = envelopes[0]["refs"][0]["id"].as_str().unwrap();

        assert_eq!(
            bootstrap_generation_ref(&envelopes[0]).unwrap().as_deref(),
            Some(expected)
        );
    }

    #[test]
    fn managed_agent_create_cannot_get_self_principal_pcr_context() {
        let mut envelopes = sdk_canonical_self_principal_bootstrap_unit();
        let mut create: arkret_wire::Event = serde_json::from_value(envelopes[0].clone()).unwrap();
        create.executed_by =
            Some(arkret_identifiers::Did::new("did:web:controller.example").unwrap());
        create.authorization_ref = Some(
            arkret_wire::AuthorizationRef::new("did:web:agent.example#managed-controller").unwrap(),
        );
        create.proofs.clear();
        attach_bootstrap_fixture_proof(
            &mut create,
            "did:key:z6MkvMW3tjuvW6PqYiX8dLRNwZWyGhxe3biRDjA4ZPiBaFaJ#z6MkvMW3tjuvW6PqYiX8dLRNwZWyGhxe3biRDjA4ZPiBaFaJ",
        );
        envelopes[0] = serde_json::to_value(create).unwrap();

        assert!(validate_self_principal_pcr_bootstrap_context(&envelopes).is_err());
    }

    fn sdk_test_envelope(envelope: &Value, actor_seq: u64) -> Value {
        let actor = arkret_identifiers::Did::new("did:webvh:z6mkfixture:alice.example").unwrap();
        let mut event = arkret_wire::Event::new(
            envelope["kind"].as_str().unwrap(),
            arkret_wire::ScopeRef::Realm {
                realm_id: arkret_identifiers::RealmId::new(
                    "ak:realm:AdZf1JIkIqUGbzF-sa3XnY2sN0Lumj76eBVunzVt_-yX",
                )
                .unwrap(),
            },
            actor.clone(),
            actor_seq,
            arkret_identifiers::Hlc::new("01970e589d21-0005-a13f9c2e").unwrap(),
            envelope
                .get("payload")
                .cloned()
                .unwrap_or_else(|| json!({})),
        )
        .unwrap();
        event.created_at = "2026-06-03T12:34:56.000Z".parse().unwrap();
        event.prev_refs = envelope
            .get("prev_refs")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .map(|value| arkret_identifiers::EventId::new(value.as_str().unwrap()).unwrap())
            .collect();
        if let Some(jws) = envelope
            .get("proofs")
            .and_then(Value::as_array)
            .and_then(|proofs| proofs.first())
            .and_then(|proof| proof.get("jws"))
            .and_then(Value::as_str)
        {
            event.proofs.push(arkret_wire::Proof {
                kind: "detached_jws".to_owned(),
                proof_purpose: None,
                verification_method: arkret_wire::DidUrl::new(format!("{actor}#key-1")).unwrap(),
                event_digest: arkret_identifiers::Hash::new(format!("sha256:{}", "a".repeat(64)))
                    .unwrap(),
                created_at: event.created_at,
                domain: None,
                audience: None,
                jws: jws.to_owned(),
            });
        }
        event.event_id = event.derive_event_id().unwrap();
        serde_json::to_value(event).unwrap()
    }

    fn stored_record(envelope: &Value, actor_seq: u64) -> CanonicalEventRecord {
        let mut envelope = envelope.clone();
        let is_wire_event = envelope.get("scope_ref").is_some();
        let canonical_bytes = if is_wire_event {
            event_canonical_bytes(&envelope).unwrap()
        } else {
            serde_json::to_vec(&envelope).unwrap()
        };
        let canonical_digest = if is_wire_event {
            arkret_canonical::digest(arkret_canonical::DigestSuite::Sha256, &canonical_bytes)
        } else {
            format!(
                "sha256:{}",
                format!("{actor_seq:x}")
                    .repeat(64)
                    .chars()
                    .take(64)
                    .collect::<String>()
            )
        };
        if is_wire_event {
            let event_id = arkret_identifiers::EventId::from_event_digest(
                &arkret_identifiers::Hash::new(canonical_digest.clone()).unwrap(),
            )
            .unwrap();
            envelope["event_id"] = Value::String(event_id.to_string());
            assert!(
                soland_storage::ids::event_identity_parts(event_id.as_str(), &canonical_digest)
                    .is_ok(),
                "test Event id must encode its canonical digest"
            );
            assert_eq!(
                arkret_canonical::digest(
                    arkret_canonical::DigestSuite::Sha256,
                    event_canonical_bytes(&envelope).unwrap()
                ),
                canonical_digest,
                "test Event canonical bytes must remain stable after stamping its id"
            );
        }
        CanonicalEventRecord {
            event_id: envelope["event_id"].as_str().unwrap().to_owned(),
            actor_id: "did:webvh:z6mkfixture:alice.example".to_owned(),
            actor_seq,
            realm_id: Some("ak:realm:AdZf1JIkIqUGbzF-sa3XnY2sN0Lumj76eBVunzVt_-yX".to_owned()),
            kind: envelope["kind"].as_str().unwrap().to_owned(),
            schema_id: "ak.schema.event_envelope.v1".to_owned(),
            canonical_digest,
            canonical_bytes,
            envelope,
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
            "payload": {"object": {"purpose": "principal_control"}}
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
            "ak:realm:AdZf1JIkIqUGbzF-sa3XnY2sN0Lumj76eBVunzVt_-yX",
            &covered,
        )
        .unwrap();
        assert_eq!(max_seq, 2);
        let mut expected_heads = vec![left_id, right_id];
        expected_heads.sort_unstable();
        assert_eq!(heads, expected_heads);
    }

    #[tokio::test]
    async fn identical_retry_restores_ack_free_pending_anchor_index() {
        let state = AppState::new(
            crate::config::AppConfig::test_default(),
            soland_storage_postgres::Db { pool: None },
        );
        let reanchor = stored_record(
            &sdk_test_envelope(
                &json!({
                    "event_id": event_id("000000000001"),
                    "kind": "ak.device.reanchor",
                    "proofs": [{"jws": "first-transport-proof"}]
                }),
                10,
            ),
            10,
        );
        let authorize = stored_record(
            &sdk_test_envelope(
                &json!({
                    "event_id": event_id("000000000002"),
                    "kind": "ak.device.authorize",
                    "proofs": [{"jws": "first-authority-proof"}]
                }),
                11,
            ),
            11,
        );
        let reanchor_id = reanchor.event_id.clone();
        let authorize_id = authorize.event_id.clone();
        state
            .event_queries()
            .store_canonical_event(reanchor.clone())
            .await
            .unwrap();
        state
            .event_queries()
            .store_canonical_event(authorize.clone())
            .await
            .unwrap();
        let later = sdk_test_envelope(
            &json!({
                "event_id": event_id("000000000003"),
                "kind": "ak.profile.update"
            }),
            12,
        );
        state
            .event_queries()
            .store_canonical_event(stored_record(&later, 12))
            .await
            .unwrap();

        let mut retried_reanchor = reanchor.envelope;
        retried_reanchor["proofs"][0]["jws"] = json!("retried-transport-proof");
        let mut retried_authorize = authorize.envelope;
        retried_authorize["proofs"][0]["jws"] = json!("retried-authority-proof");
        let mut candidates = Vec::new();
        for envelope in [retried_reanchor, retried_authorize] {
            let id = event_string_field_from_value(&envelope, "event_id").unwrap();
            let mut candidate = state
                .event_queries()
                .canonical_event(&id)
                .await
                .unwrap()
                .unwrap();
            candidate.canonical_bytes = event_canonical_bytes(&envelope).unwrap();
            candidate.envelope = envelope;
            candidates.push(candidate);
        }
        let outcome = identical_historical_retry(&state, &candidates)
            .await
            .unwrap()
            .expect("stored canonical unit must be returned as duplicate");
        assert_eq!(outcome.status, EventsSubmitStatus::Duplicate);
        assert!(outcome.accepted.is_empty());
        assert_eq!(outcome.duplicate.len(), 2);
        for event_id in [reanchor_id, authorize_id] {
            let stored = state
                .event_queries()
                .canonical_event(&event_id)
                .await
                .unwrap()
                .expect("canonical anchor Event must remain stored");
            let event: arkret_wire::Event = serde_json::from_value(stored.envelope).unwrap();
            let digest = Hash::new(event.event_digest().unwrap()).unwrap();
            assert_eq!(
                state
                    .projections()
                    .control_event_by_digest(&digest)
                    .unwrap(),
                Some(event),
                "an exact retry must restore the required pending control index",
            );
        }
    }
}
