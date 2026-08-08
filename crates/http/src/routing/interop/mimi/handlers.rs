use salvo::oapi::endpoint;

use super::*;

#[endpoint(operation_id = "mimi_protocol_directory")]
#[tracing::instrument(skip_all, fields(op = "mimi_protocol_directory"))]
pub(super) async fn mimi_protocol_directory(
    depot: &mut Depot,
) -> JsonResult<arkret_models_collaboration::objects::interop::ProviderDirectory> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    json_ok(mimi_provider_directory_value(state)?)
}

#[endpoint(operation_id = "mimi_provider_directory")]
#[tracing::instrument(skip_all, fields(op = "mimi_provider_directory"))]
pub(super) async fn mimi_provider_directory(
    depot: &mut Depot,
) -> JsonResult<arkret_models_collaboration::objects::interop::ProviderDirectory> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    json_ok(mimi_provider_directory_value(state)?)
}

#[endpoint(
    operation_id = "ak.open.mimi.exchange.request_key_material",
    summary = "Request MIMI key material",
    tags("mimi")
)]
#[tracing::instrument(skip_all, fields(op = "ak.open.mimi.exchange.request_key_material"))]
pub(super) async fn mimi_key_material(
    body: JsonBody<MimiKeyMaterialRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<MimiKeyMaterialOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let body = typed_body_value(body.into_inner(), "mimi key material")?;
    verify_mimi_write_service_proof(state, req, None).await?;
    if let Some(message) = unsupported_mimi_draft(&body) {
        return Err(AppError::invalid_param(message).with_wire_code("mimi_draft_unsupported"));
    }
    let target = body
        .get("target_identifier")
        .or_else(|| body.get("target_did"))
        .or_else(|| body.get("mimi_room_uri"))
        .or_else(|| body.get("strand_id"))
        .and_then(|value| value.as_str())
        .unwrap_or("unknown");
    let _receipt = mimi_receipt(
        state,
        "ak.open.mimi.exchange.request_key_material",
        &body,
        json!({
            "target": target,
            "keypackage_claim_lifecycle": "single_use_required",
            "production_gap": "full_mls_keypackage_claim_not_implemented"
        }),
    );
    json_ok(MimiKeyMaterialOutcome {
        key_packages: Vec::new(),
        group_info: None,
        failures: Vec::new(),
        signature: None,
    })
}

#[endpoint(
    operation_id = "ak.open.mimi.command.update_room",
    summary = "Update a MIMI room",
    tags("mimi")
)]
#[tracing::instrument(skip_all, fields(op = "ak.open.mimi.command.update_room"))]
pub(super) async fn mimi_room_update(
    strand_id: PathParam<String>,
    body: JsonBody<MimiRoomUpdateRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<MimiRoomUpdateOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let room_id = strand_id.into_inner();
    let body = typed_body_value(body.into_inner(), "mimi room update")?;
    let room_uri = mimi_room_uri(state, &room_id);
    verify_mimi_write_service_proof(state, req, Some(&room_uri)).await?;
    if let Some(message) = unsupported_mimi_draft(&body) {
        return Err(AppError::invalid_param(message).with_wire_code("mimi_draft_unsupported"));
    }
    if !valid_mimi_room_id(&room_id) {
        return Err(AppError::invalid_param("invalid MIMI room id"));
    }
    // If the update carries a `room_binding` block, persist it as a
    // `ak.mimi.room_binding` projection event so the Arkret
    // timeline observes the binding. Updates without a binding block
    // fall through to the receipt-only response. A binding block that
    // omits both `binding_scope.realm_id` and a top-level `realm_id`
    // is rejected; we never implicitly route to a default Realm.
    let update_payload = decode_mimi_update_payload(&body)?;
    let binding_event_id = match update_payload
        .as_ref()
        .and_then(mimi_room_binding_payload)
        .filter(|binding| binding.is_object())
    {
        Some(binding) => {
            let event_id = emit_mimi_room_binding_event(state, &room_id, binding)
                .await?
                .ok_or_else(|| {
                    AppError::invalid_param(
                        "room_binding requires `binding_scope.realm_id` or a top-level `realm_id`",
                    )
                    .with_wire_code(arkret_wire::ReasonCode::MIMI_GOVERNANCE_BINDING_MISSING)
                })?;
            Some(event_id)
        }
        _ => None,
    };

    let room_state_ref = binding_event_id
        .as_deref()
        .map(EventId::new)
        .transpose()
        .map_err(|error| AppError::internal(format!("MIMI room state ref: {error}")))?;
    let _receipt = mimi_receipt(
        state,
        "ak.open.mimi.command.update_room",
        &body,
        json!({
            "mimi_room_uri": mimi_room_uri(state, &room_id),
            "truth_source": "arkret_signed_event_reducer",
            "status": "projected",
            "binding_emitted": binding_event_id.is_some(),
        }),
    );
    json_ok(MimiRoomUpdateOutcome {
        accepted: true,
        room_state_ref,
        rejected: Vec::new(),
    })
}

#[endpoint(
    operation_id = "ak.open.mimi.command.notify",
    summary = "MIMI notify",
    tags("mimi")
)]
#[tracing::instrument(skip_all, fields(op = "ak.open.mimi.command.notify"))]
pub(super) async fn mimi_notify(
    strand_id: PathParam<String>,
    body: JsonBody<MimiNotifyRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<MimiNotifyOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let room_id = strand_id.into_inner();
    let body = typed_body_value(body.into_inner(), "mimi notify")?;
    let room_uri = mimi_room_uri(state, &room_id);
    verify_mimi_write_service_proof(state, req, Some(&room_uri)).await?;
    if let Some(message) = unsupported_mimi_draft(&body) {
        return Err(AppError::invalid_param(message).with_wire_code("mimi_draft_unsupported"));
    }
    if !valid_mimi_room_id(&room_id) {
        return Err(AppError::invalid_param("invalid MIMI room id"));
    }
    // Fan out a synthetic `ak.open.mimi.command.notify` projection event so live
    // subscribers observe the MIMI provider-to-provider
    // notification. The notify event is an ephemeral signal in the
    // spec's wire_scope taxonomy - we broadcast but don't persist
    // into projection_events so it doesn't pollute durable history.
    let realm_id = mimi_bound_realm_id(state, &room_id).await?.ok_or_else(|| {
        AppError::not_found("MIMI room is not bound to any Arkret Realm")
            .with_wire_code(arkret_wire::ReasonCode::MIMI_GOVERNANCE_BINDING_MISSING)
    })?;
    let event_id = ids::generate_event_id();
    let notify_record = ProjectionEventRecord {
        event_id: event_id.clone(),
        realm_id: realm_id.clone(),
        event_kind: "ak.open.mimi.command.notify".to_owned(),
        operation_kind: "mimi_facade_notify".to_owned(),
        operation_id: None,
        sender: None,
        payload: json!({
            "mimi_room_uri": mimi_room_uri(state, &room_id),
            "mimi_room_id": room_id,
            "mimi_provider_id": mimi_provider_id(state),
            "notify_body": body.clone(),
            "facade": "soland.mimi.v1",
        }),
        created_at: chrono::Utc::now(),
        received_at: chrono::Utc::now(),
    };
    let _ = crate::routing::events::projection::persist_and_publish_projection_event(
        state,
        notify_record,
    )
    .await;

    let _receipt = mimi_receipt(
        state,
        "ak.open.mimi.command.notify",
        &body,
        json!({
            "delivery": "queued",
            "mimi_room_uri": mimi_room_uri(state, &room_id),
            "broadcast_emitted": true,
            "broadcast_event_id": event_id,
        }),
    );
    json_ok(MimiNotifyOutcome {
        accepted: true,
        retry_after_ms: None,
    })
}

#[endpoint(
    operation_id = "ak.open.mimi.command.submit_message",
    summary = "Submit a MIMI message",
    tags("mimi")
)]
#[tracing::instrument(skip_all, fields(op = "ak.open.mimi.command.submit_message"))]
pub(super) async fn mimi_room_message(
    strand_id: PathParam<String>,
    body: JsonBody<MimiSubmitMessageRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<MimiSubmitMessageOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let room_id = strand_id.into_inner();
    let body = typed_body_value(body.into_inner(), "mimi submit message")?;
    let room_uri = mimi_room_uri(state, &room_id);
    verify_mimi_write_service_proof(state, req, Some(&room_uri)).await?;
    if let Some(message) = unsupported_mimi_draft(&body) {
        return Err(AppError::invalid_param(message).with_wire_code("mimi_draft_unsupported"));
    }
    if !valid_mimi_room_id(&room_id) {
        return Err(AppError::invalid_param("invalid MIMI room id"));
    }
    let message = decode_mimi_message_payload(&body)?;
    let source_format = message
        .get("source_format")
        .or_else(|| {
            body.get("ciphertext")
                .and_then(|ciphertext| ciphertext.get("content_type"))
        })
        .and_then(|value| value.as_str())
        .unwrap_or("application/mimi-content");
    if !valid_mimi_content_type(source_format) {
        return Err(AppError::invalid_param("unsupported MIMI content type"));
    }
    let operation_id = ids::generate_operation_id();
    let mimi_message_id = message
        .get("mimi_message_id")
        .and_then(|value| value.as_str())
        .map(str::to_owned)
        .unwrap_or_else(|| {
            format!(
                "mimi-msg-{}",
                operation_id.trim_start_matches("ak:operation:")
            )
        });
    let original_hash = body
        .get("original_envelope_hash")
        .and_then(|value| value.as_str())
        .map(str::to_owned)
        .unwrap_or_else(|| arkret_canonical::sha256_digest(body.to_string().as_bytes()));

    // Map the MIMI message into the canonical Arkret timeline.
    // Append a MessageRecord + a `ak.message.create` projection event so
    // the message shows up in `QUERY /_arkret/self/events`. The
    // MIMI provenance metadata is preserved verbatim under
    // `payload.mimi_provenance` so audit consumers can verify the
    // message arrived through the facade.
    let room_binding = latest_mimi_room_binding(state, &room_id)
        .await?
        .ok_or_else(|| {
            AppError::not_found("MIMI room is not bound to any Arkret Realm")
                .with_wire_code(arkret_wire::ReasonCode::MIMI_GOVERNANCE_BINDING_MISSING)
        })?;
    enforce_mimi_submit_binding(&room_binding, &body, &message)?;
    let realm_id = room_binding.realm_id.clone();
    let sender = body
        .get("sender_actor_id")
        .and_then(|v| v.as_str())
        .map(str::to_owned)
        .unwrap_or_else(|| {
            // Synthesize a stable sender DID from the MIMI provider
            // id + message id when the envelope omits one. Real
            // deployments will normalise this via the identifier
            // mapping layer per spec §10.
            format!("{}#mimi-anonymous", state.service_id(),)
        });
    let mapped_content = map_mimi_message_content(&message, source_format)?;
    let thread_id = message
        .get("thread_id")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .or_else(|| crate::routing::events::strand::strand_id_from_realm_id(&realm_id))
        .ok_or_else(|| AppError::invalid_param("MIMI binding carries a non-canonical realm_id"))?;
    let created_at = chrono::Utc::now();
    let mimi_provenance = json!({
        "facade": "soland.mimi.v1",
        "mimi_provider_id": mimi_provider_id(state),
        "mimi_room_uri": mimi_room_uri(state, &room_id),
        "mimi_room_id": room_id,
        "mimi_room_binding_ref": room_binding.event_id.clone(),
        "mimi_message_id": mimi_message_id,
        "original_sender": sender,
        "original_envelope_hash": original_hash,
        "source_format": source_format,
        "accepted_at": arkret_canonical::format_timestamp_canonical(created_at),
    });
    let event_payload = json!({
        "strand_id": thread_id.clone(),
        "track_name": "discussion",
        "content": mapped_content.content.clone(),
        "metadata": {
            "mimi_provenance": mimi_provenance.clone(),
            "mimi_policy": mapped_content.policy.clone(),
            "quarantine": mapped_content.quarantine.clone(),
        },
    });
    let event_id =
        persist_mimi_canonical_message_event(state, &realm_id, created_at, event_payload).await?;

    let _receipt = mimi_receipt(
        state,
        "ak.open.mimi.command.submit_message",
        &body,
        json!({
            "kind": "ak.mimi.mapping_receipt",
            "profile": "ak.profile.mimi_interop.v1",
            "mimi_room_uri": mimi_room_uri(state, &room_id),
            "source_format": source_format,
            "target_format": "ak.message.create",
            "original_envelope_hash": original_hash,
            "mapped_operation_id": operation_id,
            "arkret_event_id": event_id,
            "mimi_message_id": mimi_message_id,
            "truth_source": "arkret_signed_event_reducer",
            "reducer_chain": "wired",
            "status": mapped_content.status,
            "mimi_policy": mapped_content.policy.clone(),
            "quarantine": mapped_content.quarantine.clone(),
        }),
    );
    append_audit_log(
        state,
        Some(&sender),
        "mimi.submit_message",
        json!({
            "room_id": room_id,
            "realm_id": realm_id,
            "operation_id": operation_id,
            "event_id": event_id,
            "source_format": source_format,
            "mimi_message_id": mimi_message_id,
            "mimi_policy": mapped_content.policy,
            "quarantine": mapped_content.quarantine,
        }),
        mapped_content.status,
    )
    .await;
    let event_ref = EventId::new(event_id)
        .map_err(|error| AppError::internal(format!("MIMI mapped event ref: {error}")))?;
    json_ok(MimiSubmitMessageOutcome {
        event_ref: Some(event_ref),
        delivery: MimiDelivery {
            status: MimiDeliveryStatus::Accepted,
            delivered_to: Vec::new(),
        },
        rejected: Vec::new(),
    })
}

#[endpoint(
    operation_id = "ak.open.mimi.read.group_info",
    summary = "Get MIMI group info",
    tags("mimi")
)]
#[tracing::instrument(skip_all, fields(op = "ak.open.mimi.read.group_info"))]
pub(super) async fn mimi_group_info(
    strand_id: PathParam<String>,
    depot: &mut Depot,
) -> JsonResult<MimiGroupInfoOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let room_id = strand_id.into_inner();
    if !valid_mimi_room_id(&room_id) {
        return Err(AppError::invalid_param("invalid MIMI room id"));
    }
    let realm_id = mimi_bound_realm_id(state, &room_id).await?.ok_or_else(|| {
        AppError::not_found("MIMI room is not bound to any Arkret Realm")
            .with_wire_code(arkret_wire::ReasonCode::MIMI_GOVERNANCE_BINDING_MISSING)
    })?;
    let projection = mimi_room_projection(state, &room_id, &realm_id);
    let projection_bytes = serde_json::to_vec(&projection)
        .map_err(|error| AppError::internal(format!("MIMI group info serialize: {error}")))?;
    let projection = MimiGroupInfo {
        mls_group_id: MlsGroupId::new(format!("mls:{room_id}"))
            .map_err(|error| AppError::internal(format!("MIMI group id invalid: {error}")))?,
        epoch: 0,
        group_info: Base64UrlString::new(arkret_canonical::base64url_encode(&projection_bytes))
            .map_err(|error| AppError::internal(format!("MIMI group info invalid: {error}")))?,
    };
    let _receipt = mimi_receipt(
        state,
        "ak.open.mimi.read.group_info",
        &json!({"room_id": room_id}),
        json!({
            "truth_source": "arkret_signed_event_reducer",
            "projection_only": true
        }),
    );
    json_ok(MimiGroupInfoOutcome {
        group_info: projection,
        room_binding_ref: None,
        proofs: Vec::new(),
    })
}

#[endpoint(
    operation_id = "ak.open.mimi.command.request_consent",
    summary = "Request MIMI consent",
    tags("mimi")
)]
#[tracing::instrument(skip_all, fields(op = "ak.open.mimi.command.request_consent"))]
pub(super) async fn mimi_consent_request(
    aa: AuthArgs,
    body: JsonBody<MimiRequestConsentRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<MimiRequestConsentOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let body = typed_body_value(body.into_inner(), "mimi consent request")?;
    if let Some(message) = unsupported_mimi_draft(&body) {
        return Err(AppError::invalid_param(message).with_wire_code("mimi_draft_unsupported"));
    }
    let requester = body
        .get("requester_id")
        .and_then(Value::as_str)
        .ok_or_else(|| AppError::invalid_param("mimi consent request requires requester_id"))?;
    verify_mimi_consent_write_authority(state, req, aa, requester).await?;
    let consent_id = ids::generate("consent");
    let consent_id = arkret_identifiers::ConsentId::new(consent_id)
        .map_err(|error| AppError::internal(format!("generated consent id is invalid: {error}")))?;
    let _receipt = mimi_receipt(
        state,
        "ak.open.mimi.command.request_consent",
        &body,
        json!({
            "consent_grants_space_capability": false,
            "privacy_state": "holder_private",
            "holder_private_materialized": false,
            "identifier_mapping": "pending_invite_or_pairwise"
        }),
    );
    json_ok(MimiRequestConsentOutcome {
        consent_id,
        status: arkret_wire::NonEmptyString::new("requested")
            .expect("requested is a non-empty protocol literal"),
        challenge: None,
    })
}

#[endpoint(
    operation_id = "ak.open.mimi.command.update_consent",
    summary = "Update MIMI consent",
    tags("mimi")
)]
#[tracing::instrument(skip_all, fields(op = "ak.open.mimi.command.update_consent"))]
pub(super) async fn mimi_consent_update(
    aa: AuthArgs,
    body: JsonBody<MimiUpdateConsentRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<MimiUpdateConsentOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let body = body.into_inner();
    let body_value = typed_body_value(body.clone(), "mimi consent update")?;
    if let Some(message) = unsupported_mimi_draft(&body_value) {
        return Err(AppError::invalid_param(message).with_wire_code("mimi_draft_unsupported"));
    }
    body.validate_consent_event().map_err(|error| {
        AppError::invalid_param(format!("MIMI consent Event binding is invalid: {error}"))
            .with_wire_code("schema_violation")
    })?;
    let session = verify_mimi_consent_update_authority(state, req, aa, &body).await?;
    let event_ref = body.consent_event.event.event_id.clone();
    let updated_at = body.consent_event.event.created_at;
    crate::routing::events::event_log::submit_initial_event_submission(
        state,
        &session,
        body.consent_event.clone(),
    )
    .await
    .map_err(|error| {
        crate::routing::events::event_log::submit_one_error_to_app_error(
            "MIMI consent Event submit failed",
            error.status,
            error.code,
            &error.message,
        )
    })?;
    json_ok(MimiUpdateConsentOutcome {
        status: arkret_models_collaboration::http_bodies::MimiUpdateConsentStatus::Accepted,
        consent_id: body.consent_id,
        decision: body.decision,
        updated_at,
        event_ref,
    })
}

pub(super) async fn verify_mimi_consent_write_authority(
    state: &AppState,
    req: &mut Request,
    aa: AuthArgs,
    expected_actor: &str,
) -> Result<(), AppError> {
    if request_has_bearer_session(req) {
        let session = aa.authenticated_session(state, req).await?;
        if session.actor != expected_actor {
            return Err(AppError::capability_denied(
                "MIMI consent user session must match the consent actor",
            ));
        }
        return Ok(());
    }
    verify_mimi_write_service_proof(state, req, None)
        .await
        .map(|_| ())
}

const MIMI_OPERATION_PROOF_WINDOW_SECONDS: i64 = 300;

async fn verify_mimi_consent_update_authority(
    state: &AppState,
    req: &mut Request,
    aa: AuthArgs,
    body: &MimiUpdateConsentRequestBody,
) -> Result<soland_services::identity::SessionIdentityState, AppError> {
    let session = if request_has_bearer_session(req) {
        let session = aa.authenticated_session(state, req).await?;
        if session.actor != body.actor_id.as_str() {
            return Err(AppError::capability_denied(
                "MIMI consent user session must match the consent actor",
            ));
        }
        session
    } else {
        verify_mimi_write_service_proof(state, req, None).await?;
        let device_id = body
            .consent_event
            .event
            .proofs
            .first()
            .and_then(|proof| proof.verification_method.as_str().rsplit_once('#'))
            .map(|(_, fragment)| fragment.to_owned())
            .ok_or_else(|| {
                AppError::invalid_param("MIMI consent Event requires a DID URL proof key")
                    .with_wire_code("invalid_proof")
            })?;
        soland_services::identity::SessionIdentityState {
            token_hash: format!("mimi-event:{}", body.consent_event.event.event_id),
            actor: body.actor_id.to_string(),
            device_id,
            audience: state.service_id().to_string(),
            session_public_key: None,
            agent_session: None,
            expires_at: now() + chrono::Duration::minutes(5),
            created_at: now(),
            revoked_at: None,
        }
    };

    verify_mimi_consent_actor_proof(state, body).await?;
    Ok(session)
}

async fn verify_mimi_consent_actor_proof(
    state: &AppState,
    body: &MimiUpdateConsentRequestBody,
) -> Result<(), AppError> {
    body.validate_consent_event().map_err(|error| {
        AppError::invalid_param(format!("MIMI consent Event carrier is invalid: {error}"))
            .with_wire_code("invalid_consent_event")
    })?;
    let proof = &body.signature;
    if proof.domain.as_deref() != Some(state.config().trust_domain.as_str()) {
        return Err(AppError::invalid_param(
            "MIMI consent proof domain does not match the destination trust domain",
        )
        .with_wire_code("invalid_proof"));
    }
    let audience_matches = match proof.audience.as_ref() {
        Some(Audience::Single(value)) => value == state.service_id(),
        Some(Audience::Multiple(values)) => values.iter().any(|value| value == state.service_id()),
        None => false,
    };
    if !audience_matches {
        return Err(AppError::invalid_param(
            "MIMI consent proof audience does not cover the destination service",
        )
        .with_wire_code("invalid_proof"));
    }
    let age_seconds = now()
        .signed_duration_since(proof.created_at)
        .num_seconds()
        .unsigned_abs();
    if age_seconds > MIMI_OPERATION_PROOF_WINDOW_SECONDS as u64 {
        return Err(AppError::invalid_param(
            "MIMI consent proof created_at is outside the accepted replay window",
        )
        .with_wire_code("invalid_proof"));
    }
    let binding = body.signature_binding_bytes().map_err(|error| {
        AppError::invalid_param(format!("MIMI consent proof binding is invalid: {error}"))
            .with_wire_code("invalid_proof")
    })?;
    crate::jws_verify::verify_principal_authorized_jws_ed25519_async(
        &binding,
        &proof.jws,
        &proof.verification_method,
        body.actor_id.as_str(),
        state,
    )
    .await
    .map_err(|reason| {
        tracing::warn!(
            %reason,
            actor_id = %body.actor_id,
            verification_method = %proof.verification_method,
            "MIMI consent actor proof verification failed"
        );
        AppError::invalid_param("MIMI consent actor proof JWS verification failed")
            .with_wire_code("invalid_proof")
    })?;
    Ok(())
}

pub(super) fn request_has_bearer_session(req: &Request) -> bool {
    req.headers()
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.trim().to_ascii_lowercase().starts_with("bearer "))
}

#[endpoint(
    operation_id = "ak.open.mimi.read.identifiers",
    summary = "Query MIMI identifiers",
    tags("mimi")
)]
#[tracing::instrument(skip_all, fields(op = "ak.open.mimi.read.identifiers"))]
pub(super) async fn mimi_identifiers_query(
    body: JsonBody<MimiIdentifierQueryRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<MimiIdentifierQueryOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let body = typed_body_value(body.into_inner(), "mimi identifiers query")?;
    verify_mimi_write_service_proof(state, req, None).await?;
    if let Some(message) = unsupported_mimi_draft(&body) {
        return Err(AppError::invalid_param(message).with_wire_code("mimi_draft_unsupported"));
    }
    let identifiers = body
        .get("identifiers")
        .and_then(Value::as_array)
        .filter(|values| !values.is_empty())
        .ok_or_else(|| AppError::missing_param("identifiers is required"))?;
    let mut matches = Vec::with_capacity(identifiers.len());
    for identifier in identifiers {
        let kind = identifier
            .get("kind")
            .and_then(Value::as_str)
            .ok_or_else(|| AppError::invalid_param("identifier entries require kind"))?;
        if !matches!(
            kind,
            "mimi_uri" | "did" | "handle" | "phone" | "email" | "opaque"
        ) {
            return Err(AppError::invalid_param("identifier kind is unsupported"));
        }
        let commitment = identifier
            .get("identifier_commitment")
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| {
                AppError::invalid_param("identifier entries require identifier_commitment")
            })?;
        Hash::new(commitment.to_owned())
            .map_err(|_| AppError::invalid_param("identifier_commitment must be a hash"))?;
        matches.push(MimiIdentifierMatch {
            identifier_commitment: Hash::new(commitment.to_owned())
                .map_err(|_| AppError::invalid_param("identifier_commitment must be a hash"))?,
            matched: false,
            mimi_uri: None,
            subject: None,
        });
    }
    let _receipt = mimi_receipt(
        state,
        "ak.open.mimi.read.identifiers",
        &body,
        json!({
            "contact_graph_exposed": false,
            "connection_identifier_separated": true,
            "reachability_proof_returned": false,
            "mapping_policy": "opaque_fail_closed"
        }),
    );
    json_ok(MimiIdentifierQueryOutcome {
        matches,
        proofs: Vec::new(),
        has_more: false,
    })
}

#[endpoint(
    operation_id = "ak.open.mimi.command.report_abuse",
    summary = "Report MIMI abuse",
    tags("mimi")
)]
#[tracing::instrument(skip_all, fields(op = "ak.open.mimi.command.report_abuse"))]
pub(super) async fn mimi_report_abuse(
    body: JsonBody<MimiReportAbuseRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<MimiReportAbuseOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let body = typed_body_value(body.into_inner(), "mimi report abuse")?;
    let source_provider = verify_mimi_write_service_proof(state, req, None).await?;
    if let Some(message) = unsupported_mimi_draft(&body) {
        return Err(AppError::invalid_param(message).with_wire_code("mimi_draft_unsupported"));
    }
    // Extract room_id segment from MIMI URI
    // `mimi://provider/rooms/<id>` so we can look up a bound Realm if any.
    let mimi_room_id = body
        .get("mimi_room_uri")
        .and_then(Value::as_str)
        .and_then(|uri| uri.rsplit('/').next())
        .or_else(|| body.get("strand_id").and_then(Value::as_str))
        .map(str::to_owned);
    let bound_realm = match mimi_room_id.as_deref() {
        Some(id) => mimi_bound_realm_id(state, id).await?,
        None => None,
    };
    let realm_id = if let Some(realm_id) = body.get("realm_id").and_then(Value::as_str) {
        realm_id.to_owned()
    } else if let Some(bound) = bound_realm {
        bound
    } else {
        return Err(AppError::invalid_param(
            "mimi report requires `realm_id` or a `mimi_room_uri` that resolves to a bound Arkret Realm",
        )
        .with_wire_code(arkret_wire::ReasonCode::MIMI_GOVERNANCE_BINDING_MISSING));
    };
    let reporter = body
        .get("reporter_did")
        .or_else(|| body.get("reporter"))
        .and_then(Value::as_str)
        .ok_or_else(|| AppError::invalid_param("mimi report requires reporter"))?;
    enforce_mimi_reporter_resolution(state, reporter, &body).await?;
    let target_ref = body
        .get("target_event_digest")
        .or_else(|| body.get("target_ref"))
        .and_then(Value::as_str)
        .ok_or_else(|| AppError::invalid_param("mimi report requires target_ref"))?;
    let evidence_package = body.get("evidence_package").unwrap_or(&Value::Null);
    let franking_proof = body
        .get("frank")
        .or_else(|| body.get("franking_proof"))
        .unwrap_or(&Value::Null);
    let source_service = moderation_request_source_service(req);
    let source_ip_hash = moderation_request_source_ip_hash(req);
    let safety = validate_moderation_report_safety(
        state,
        &realm_id,
        reporter,
        target_ref,
        None,
        evidence_package,
        franking_proof,
        source_service.as_deref(),
        &source_ip_hash,
    )
    .await?;
    let canonical_reason = body
        .get("abuse_reason_code")
        .and_then(Value::as_str)
        .filter(|reason| {
            matches!(
                *reason,
                "spam"
                    | "harassment"
                    | "hate_speech"
                    | "nsfw"
                    | "illegal"
                    | "misinformation"
                    | "other"
            )
        })
        .unwrap_or("other");
    let mut event_fields = serde_json::Map::new();
    event_fields.insert("realm_id".to_owned(), json!(realm_id));
    event_fields.insert("effective_scope".to_owned(), safety.effective_scope);
    event_fields.insert("target_ref".to_owned(), json!(target_ref));
    event_fields.insert("report_reason_code".to_owned(), json!(canonical_reason));
    event_fields.insert("reporter".to_owned(), json!(reporter));
    event_fields.insert("provenance".to_owned(), json!("mimi_facade"));
    event_fields.insert("source_provider".to_owned(), json!(source_provider));
    if let Some(description) = body.get("description").cloned() {
        event_fields.insert("description".to_owned(), description);
    }
    if let Some(evidence_package) = safety.evidence_package {
        event_fields.insert("evidence_package".to_owned(), evidence_package);
    }
    if let Some(franking_proof) = safety.franking_proof {
        event_fields.insert("franking_proof".to_owned(), franking_proof);
    }
    let report_event_id = persist_canonical_moderation_report_event(
        state,
        &realm_id,
        reporter,
        target_ref,
        Value::Object(event_fields.clone()),
    )
    .await?;

    // `report` is Event-derived: the id is the accepted
    // `ak.self.moderation.report` Event token retyped, so it exists only after
    // admission and never enters the Event payload.
    let report_id = ReportId::from_event_id(
        &arkret_identifiers::EventId::new(report_event_id.clone())
            .map_err(|error| AppError::internal(format!("MIMI report Event id: {error}")))?,
    );
    let mut report_fields = event_fields;
    report_fields.insert("report_id".to_owned(), json!(report_id.as_str()));
    report_fields.insert("event_id".to_owned(), json!(report_event_id));
    report_fields.insert("kind".to_owned(), json!("mimi_abuse_report"));
    report_fields.insert(
        "mimi_room_uri".to_owned(),
        body.get("mimi_room_uri").cloned().unwrap_or(Value::Null),
    );
    report_fields.insert(
        "provider_id".to_owned(),
        body.get("provider_id").cloned().unwrap_or(Value::Null),
    );
    report_fields.insert("created_at".to_owned(), json!(now()));
    if let Err(error) = state
        .governance()
        .append_moderation_report(Value::Object(report_fields))
        .await
    {
        tracing::error!(%error, "failed to persist mimi abuse report");
    }

    let routed_to = Did::new(state.service_id().clone()).map_or_else(
        |error| {
            tracing::warn!(%error, "mimi: service DID could not be represented in report outcome");
            Vec::new()
        },
        |did| vec![did],
    );
    let _receipt = mimi_receipt(
        state,
        "ak.open.mimi.command.report_abuse",
        &body,
        json!({
            "e2ee_evidence_plaintext_required": false,
            "routed_to": [format!("{}#moderation", state.service_id())],
            "moderation_event_emitted": true,
            "report_event_id": report_event_id,
            "reporter_resolution": "holder_claim_or_consent",
        }),
    );
    json_ok(MimiReportAbuseOutcome {
        report_id,
        status: arkret_wire::NonEmptyString::new("queued")
            .expect("queued is a non-empty protocol literal"),
        routed_to,
    })
}

pub(super) async fn enforce_mimi_reporter_resolution(
    state: &AppState,
    reporter: &str,
    body: &Value,
) -> Result<(), AppError> {
    Did::new(reporter.to_owned())
        .map_err(|error| AppError::invalid_param(format!("invalid reporter DID: {error}")))?;
    if state
        .identities()
        .account(reporter)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
        .is_some()
    {
        return Ok(());
    }
    let evidence = body.get("evidence_package").unwrap_or(&Value::Null);
    let has_holder_claim = evidence
        .get("reporter_holder_claim")
        .or_else(|| body.get("reporter_holder_claim"))
        .is_some_and(non_empty_json_value);
    let has_consent_proof = evidence
        .get("consent_proof")
        .or_else(|| evidence.get("consent_ref"))
        .or_else(|| body.get("consent_proof"))
        .or_else(|| body.get("consent_ref"))
        .is_some_and(non_empty_json_value);
    if has_holder_claim || has_consent_proof {
        return Ok(());
    }
    Err(AppError::capability_denied(
        "MIMI abuse reporter requires local account, holder claim, or consent proof",
    )
    .with_wire_code("mimi_reporter_resolution_required"))
}

#[endpoint(
    operation_id = "ak.open.mimi.command.proxy_download",
    summary = "Proxy a MIMI download",
    tags("mimi")
)]
#[tracing::instrument(skip_all, fields(op = "ak.open.mimi.command.proxy_download"))]
pub(super) async fn mimi_proxy_download(
    body: JsonBody<MimiProxyDownloadRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<MimiProxyDownloadOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let body = typed_body_value(body.into_inner(), "mimi proxy download")?;
    verify_mimi_write_service_proof(state, req, None).await?;
    if let Some(message) = unsupported_mimi_draft(&body) {
        return Err(AppError::invalid_param(message).with_wire_code("mimi_draft_unsupported"));
    }
    let asset_ref = body
        .get("asset_ref")
        .and_then(|value| value.as_str())
        .ok_or_else(|| AppError::missing_param("asset_ref is required"))?;
    enforce_mimi_proxy_download_egress_policy(state, asset_ref)?;
    let asset_policy = body
        .get("asset_privacy_policy")
        .and_then(|value| value.as_str())
        .unwrap_or("provider_proxy");
    let blob = state.deliveries().blob(asset_ref).await.ok().flatten();
    let proxy_required = matches!(asset_policy, "provider_proxy" | "ohttp_relay");
    let download_ref = if proxy_required {
        mimi_proxy_download_ref(state, asset_ref)?
    } else {
        asset_ref.to_owned()
    };
    let mut headers = BTreeMap::new();
    if let Some(blob) = blob.as_ref() {
        headers.insert("content-type".to_owned(), blob.media_type.clone());
        headers.insert("content-length".to_owned(), blob.size_bytes.to_string());
    }
    let _receipt = mimi_receipt(
        state,
        "ak.open.mimi.command.proxy_download",
        &body,
        json!({
            "asset_privacy_policy": asset_policy,
            "direct_object_store_url_returned": false,
            "client_must_verify_content_hash": true
        }),
    );
    json_ok(MimiProxyDownloadOutcome {
        download_ref,
        headers,
        expires_at: Some(now() + Duration::minutes(5)),
    })
}

pub(super) fn mimi_proxy_download_ref(
    state: &AppState,
    asset_ref: &str,
) -> Result<String, AppError> {
    let mut url = reqwest::Url::parse(&format!("{}/proxy-download", mimi_base_url(state)))
        .map_err(|error| AppError::internal(format!("MIMI proxy download URL invalid: {error}")))?;
    url.query_pairs_mut().append_pair("asset_ref", asset_ref);
    Ok(url.to_string())
}

pub(super) fn enforce_mimi_proxy_download_egress_policy(
    state: &AppState,
    asset_ref: &str,
) -> Result<(), AppError> {
    if asset_ref.trim() != asset_ref || asset_ref.is_empty() {
        return Err(mimi_proxy_download_egress_denied(
            "mimi proxy download: asset_ref must be a non-empty canonical reference",
        ));
    }
    let asset_ref = asset_ref.trim();
    if asset_ref.starts_with("ak:blob:") {
        return Ok(());
    }
    if asset_ref.starts_with("//") || asset_ref.contains('\\') {
        return Err(mimi_proxy_download_egress_denied(
            "mimi proxy download: URL-like asset_ref is not allowed without an explicit http(s) scheme",
        ));
    }
    if asset_ref.contains("://") {
        return crate::security::validate_http_url_for_egress(
            asset_ref,
            "mimi proxy download",
            state.config().development_mode,
        )
        .map(|_| ())
        .map_err(mimi_proxy_download_egress_denied);
    }
    if asset_ref.contains(':') {
        return Err(mimi_proxy_download_egress_denied(
            "mimi proxy download: non-blob URI scheme is not allowed",
        ));
    }
    Ok(())
}

pub(super) fn mimi_proxy_download_egress_denied(error: impl Into<String>) -> AppError {
    AppError::capability_denied("MIMI proxy download asset_ref is denied by egress policy")
        .with_wire_code("egress_policy_denied")
        .with_reason_detail(error)
}
#[cfg(test)]
mod consent_proof_tests {
    use arkret_identifiers::{ConsentId, Did, Hash, Hlc, RealmId};
    use arkret_models_collaboration::http_bodies::MimiConsentDecision;
    use arkret_wire::{
        Audience, Event, EventInitialSubmission, EventKind, PayloadProof, ScopeRef, proof_kind,
    };
    use soland_http::error::ErrorCode;
    use soland_storage_postgres::Db;

    use super::*;

    fn state() -> AppState {
        let mut config = crate::config::AppConfig::test_default();
        config.development_mode = true;
        AppState::new(config, Db { pool: None })
    }

    fn request(state: &AppState) -> MimiUpdateConsentRequestBody {
        let actor_id = Did::new("did:web:mimi-proof-test.invalid".to_owned()).unwrap();
        let verification_method = format!("{actor_id}#cotest");
        let consent_id =
            ConsentId::new("ak:consent:01964137-0000-7000-8000-000000000777".to_owned()).unwrap();
        let realm_id =
            RealmId::new("ak:realm:Aaqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq".to_owned())
                .unwrap();
        let consent_event = Event::new_at(
            EventKind::ConsentGrant.as_str(),
            ScopeRef::Realm { realm_id },
            actor_id.clone(),
            1,
            Hlc::new(state.hlc().now()).unwrap(),
            json!({
                "consent_id": consent_id,
                "peer": "did:web:mimi-peer-test.invalid",
                "consent_scope": "direct_message"
            }),
            now(),
        )
        .unwrap();
        let mut request = MimiUpdateConsentRequestBody {
            consent_id,
            decision: MimiConsentDecision::Accept,
            actor_id,
            consent_event: EventInitialSubmission::online(consent_event),
            signature: PayloadProof {
                kind: proof_kind::DETACHED_JWS.to_owned(),
                verification_method: arkret_wire::DidUrl::new(verification_method.clone()).unwrap(),
                payload_digest: Hash::new(format!("sha256:{}", "0".repeat(64))).unwrap(),
                created_at: now(),
                domain: Some(state.config().trust_domain.clone()),
                audience: Some(Audience::Single(state.service_id().to_owned())),
                proof_purpose: None,
                jws: "pending".to_owned(),
            },
            reason: None,
            expires_at: None,
        };
        request.signature.payload_digest = request.payload_digest().unwrap();
        let binding = request.signature_binding_bytes().unwrap();
        let signing_key = arkret_signatures::development_signing_key(&verification_method);
        request.signature.jws =
            arkret_signatures::jws::sign_jws_ed25519(&binding, &signing_key).unwrap();
        request
    }

    #[tokio::test]
    async fn consent_actor_proof_is_verified_and_consumed_once() {
        let state = state();
        let request = request(&state);
        let binding = request.signature_binding_bytes().unwrap();
        let direct_verification = crate::jws_verify::verify_principal_authorized_jws_ed25519_async(
            &binding,
            &request.signature.jws,
            &request.signature.verification_method,
            request.actor_id.as_str(),
            &state,
        )
        .await;
        assert!(
            direct_verification.is_ok(),
            "direct proof verification failed: {direct_verification:?}"
        );

        verify_mimi_consent_actor_proof(&state, &request)
            .await
            .expect("first proof presentation");
        let replay = verify_mimi_consent_actor_proof(&state, &request)
            .await
            .expect_err("proof replay must fail");

        assert_eq!(replay.code, ErrorCode::Conflict);
        assert_eq!(
            replay.wire_code_override.as_deref(),
            Some("duplicate_conflict")
        );
    }

    #[tokio::test]
    async fn consent_actor_proof_rejects_decision_carrier_mismatch() {
        let state = state();
        let mut request = request(&state);
        request.decision = MimiConsentDecision::Revoke;

        let error = verify_mimi_consent_actor_proof(&state, &request)
            .await
            .expect_err("tampered body must fail");

        assert_eq!(error.code, ErrorCode::InvalidParam);
        assert_eq!(
            error.wire_code_override.as_deref(),
            Some("invalid_consent_event")
        );
    }

    #[tokio::test]
    async fn consent_actor_proof_rejects_wrong_destination_binding() {
        let state = state();
        let mut request = request(&state);
        request.signature.domain = Some("ak:trust_domain:other.example".to_owned());

        let error = verify_mimi_consent_actor_proof(&state, &request)
            .await
            .expect_err("cross-domain proof must fail");

        assert_eq!(error.code, ErrorCode::InvalidParam);
        assert_eq!(error.wire_code_override.as_deref(), Some("invalid_proof"));
    }
}
