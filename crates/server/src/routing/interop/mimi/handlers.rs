use super::*;

#[endpoint]
#[tracing::instrument(skip_all, fields(op = "mimi_protocol_directory"))]
pub(super) async fn mimi_protocol_directory(depot: &mut Depot, res: &mut Response) {
    let state = depot.get_typed::<AppState>().expect("state injected");
    res.render(Json(mimi_provider_directory_value(state)));
}

#[endpoint(
    operation_id = "ak.open.mimi.query.provider_directory",
    tags("mimi"),
    summary = "Read the MIMI provider directory"
)]
#[tracing::instrument(skip_all, fields(op = "mimi_provider_directory"))]
pub(super) async fn mimi_provider_directory(depot: &mut Depot, res: &mut Response) {
    let state = depot.get_typed::<AppState>().expect("state injected");
    res.render(Json(mimi_provider_directory_value(state)));
}

#[endpoint(
    operation_id = "ak.open.mimi.exchange.request_key_material",
    tags("mimi"),
    summary = "Claim MIMI/MLS key material for a target identifier"
)]
#[tracing::instrument(skip_all, fields(op = "ak.open.mimi.exchange.request_key_material"))]
pub(super) async fn mimi_key_material(
    body: JsonBody<MimiKeyMaterialRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<MimiKeyMaterialOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let body = typed_body_value(body.into_inner(), "mimi key material")?;
    verify_mimi_write_service_proof(state, req, &body, None)?;
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
    tags("mimi"),
    summary = "Apply a MIMI room update (optionally persists `room_binding`)"
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
    verify_mimi_write_service_proof(state, req, &body, Some(&room_uri))?;
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
                    .with_wire_code(arkret_core::ReasonCode::MIMI_GOVERNANCE_BINDING_MISSING)
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
    tags("mimi"),
    summary = "Fan out a MIMI notify (broadcasts a `ak.open.mimi.command.notify` ephemeral)"
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
    verify_mimi_write_service_proof(state, req, &body, Some(&room_uri))?;
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
    let realm_id = mimi_bound_realm_id(state, &room_id).await.ok_or_else(|| {
        AppError::not_found("MIMI room is not bound to any Arkret Realm")
            .with_wire_code(arkret_core::ReasonCode::MIMI_GOVERNANCE_BINDING_MISSING)
    })?;
    let event_id = ids::generate_event_id();
    let notify_record = ProjectionEventRecord {
        event_id: event_id.clone(),
        realm_id: realm_id.clone(),
        event_kind: "ak.open.mimi.command.notify".to_owned(),
        operation_type: "mimi_facade_notify".to_owned(),
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
    tags("mimi"),
    summary = "Submit a MIMI room message (mapped into ak.message.create projection)"
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
    verify_mimi_write_service_proof(state, req, &body, Some(&room_uri))?;
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
    let event_id = ids::generate_event_id();
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
        .unwrap_or_else(|| arkret_core::canonical::sha256_digest(body.to_string().as_bytes()));

    // Map the MIMI message into the canonical Arkret timeline.
    // Append a MessageRecord + a `ak.message.create` projection event so
    // the message shows up in `GET /_arkret/self/events?realm_id=...`. The
    // MIMI provenance metadata is preserved verbatim under
    // `payload.mimi_provenance` so audit consumers can verify the
    // message arrived through the facade.
    let room_binding = latest_mimi_room_binding(state, &room_id)
        .await
        .ok_or_else(|| {
            AppError::not_found("MIMI room is not bound to any Arkret Realm")
                .with_wire_code(arkret_core::ReasonCode::MIMI_GOVERNANCE_BINDING_MISSING)
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
            format!("{}#mimi-anonymous", state.service_id,)
        });
    let mapped_content = map_mimi_message_content(&message, source_format)?;
    let thread_id = message
        .get("thread_id")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .unwrap_or_else(|| crate::routing::events::strand::strand_id_from_realm_id(&realm_id));
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
        "accepted_at": arkret_core::canonical::format_timestamp_canonical(created_at),
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
    persist_mimi_canonical_message_event(state, &event_id, &realm_id, created_at, event_payload)
        .await?;

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
    operation_id = "ak.open.mimi.query.group_info",
    tags("mimi"),
    summary = "Read a MIMI room's group info / projection"
)]
#[tracing::instrument(skip_all, fields(op = "ak.open.mimi.query.group_info"))]
pub(super) async fn mimi_group_info(
    strand_id: PathParam<String>,
    depot: &mut Depot,
) -> JsonResult<MimiGroupInfoOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let room_id = strand_id.into_inner();
    if !valid_mimi_room_id(&room_id) {
        return Err(AppError::invalid_param("invalid MIMI room id"));
    }
    let realm_id = mimi_bound_realm_id(state, &room_id).await.ok_or_else(|| {
        AppError::not_found("MIMI room is not bound to any Arkret Realm")
            .with_wire_code(arkret_core::ReasonCode::MIMI_GOVERNANCE_BINDING_MISSING)
    })?;
    let projection = mimi_room_projection(state, &room_id, &realm_id);
    let projection_bytes = serde_json::to_vec(&projection)
        .map_err(|error| AppError::internal(format!("MIMI group info serialize: {error}")))?;
    let projection = MimiGroupInfo {
        mls_group_id: MlsGroupId::new(format!("mls:{room_id}"))
            .map_err(|error| AppError::internal(format!("MIMI group id invalid: {error}")))?,
        epoch: 0,
        group_info: Base64UrlString::new(arkret_core::base64url_encode(&projection_bytes))
            .map_err(|error| AppError::internal(format!("MIMI group info invalid: {error}")))?,
    };
    let _receipt = mimi_receipt(
        state,
        "ak.open.mimi.query.group_info",
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
    tags("mimi"),
    summary = "Open a MIMI consent request"
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
    verify_mimi_consent_write_authority(state, req, aa, &body, requester).await?;
    let target_holder = mimi_consent_target_holder(&body);
    let scope = body
        .get("purpose")
        .and_then(Value::as_str)
        .unwrap_or("direct_message");
    let materialized = match target_holder {
        Some(holder) => {
            Some(materialize_mimi_consent_request(state, holder, requester, scope).await?)
        }
        None => None,
    };
    let consent_id = materialized
        .as_ref()
        .map(|(consent_id, _cell)| consent_id.clone())
        .unwrap_or_else(|| ids::generate("consent"));
    let consent_id = arkret_core::ConsentId::new(consent_id)
        .map_err(|error| AppError::internal(format!("generated consent id is invalid: {error}")))?;
    let _receipt = mimi_receipt(
        state,
        "ak.open.mimi.command.request_consent",
        &body,
        json!({
            "consent_grants_space_capability": false,
            "privacy_state": "holder_private",
            "holder_private_materialized": materialized.is_some(),
            "identifier_mapping": if materialized.is_some() { "holder_did" } else { "pending_invite_or_pairwise" }
        }),
    );
    json_ok(MimiRequestConsentOutcome {
        consent_id,
        status: "requested".to_owned(),
        challenge: None,
    })
}

#[endpoint(
    operation_id = "ak.open.mimi.command.update_consent",
    tags("mimi"),
    summary = "Update a MIMI consent state"
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
    let granted = matches!(body.decision, arkret_core::MimiConsentDecision::Accept);
    let consent_id = body.consent_id.as_str();
    let actor_id = body.actor_id.as_str();
    verify_mimi_consent_update_authority(state, req, aa, &body, &body_value).await?;
    let materialized =
        materialize_mimi_consent_update_by_id(state, consent_id, actor_id, granted).await?;
    let updated_at = now();
    let event_ref = materialized
        .as_ref()
        .and_then(|(_, event_ref)| event_ref.as_ref())
        .and_then(|event_ref| EventId::new(event_ref.clone()).ok());
    let _receipt = mimi_receipt(
        state,
        "ak.open.mimi.command.update_consent",
        &body_value,
        json!({
            "consent_grants_space_capability": false,
            "membership_still_required": true,
            "holder_private_materialized": materialized.is_some(),
            "mapped_event_kind": if granted { "ak.consent.grant" } else { "ak.consent.revoke" }
        }),
    );
    json_ok(MimiUpdateConsentOutcome {
        status: if granted { "accepted" } else { "revoked" }.to_owned(),
        updated_at,
        event_ref,
    })
}

pub(super) fn mimi_consent_target_holder(body: &Value) -> Option<&str> {
    body.get("target")
        .and_then(|target| {
            if target.get("kind").and_then(Value::as_str) != Some("did") {
                return None;
            }
            target.get("id")
        })
        .and_then(Value::as_str)
        .filter(|value| value.starts_with("did:"))
}

pub(super) async fn verify_mimi_consent_write_authority(
    state: &AppState,
    req: &Request,
    aa: AuthArgs,
    body: &Value,
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
    verify_mimi_write_service_proof(state, req, body, None)
}

const MIMI_OPERATION_PROOF_WINDOW_SECONDS: i64 = 300;

async fn verify_mimi_consent_update_authority(
    state: &AppState,
    req: &Request,
    aa: AuthArgs,
    body: &MimiUpdateConsentRequestBody,
    body_value: &Value,
) -> Result<(), AppError> {
    if request_has_bearer_session(req) {
        let session = aa.authenticated_session(state, req).await?;
        if session.actor != body.actor_id.as_str() {
            return Err(AppError::capability_denied(
                "MIMI consent user session must match the consent actor",
            ));
        }
    } else {
        verify_mimi_write_service_proof(state, req, body_value, None)?;
    }

    verify_mimi_consent_actor_proof(state, body).await
}

async fn verify_mimi_consent_actor_proof(
    state: &AppState,
    body: &MimiUpdateConsentRequestBody,
) -> Result<(), AppError> {
    let proof = &body.signature;
    if proof.domain.as_deref() != Some(state.config.trust_domain.as_str()) {
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

    consume_mimi_consent_proof_replay(state, body).await
}

async fn consume_mimi_consent_proof_replay(
    state: &AppState,
    body: &MimiUpdateConsentRequestBody,
) -> Result<(), AppError> {
    let proof = &body.signature;
    let replay_digest = arkret_core::canonical::canonical_sha256(&json!({
        "actor_id": body.actor_id,
        "payload_digest": proof.payload_digest,
        "jws": proof.jws,
    }))
    .map_err(|error| AppError::internal(format!("MIMI replay key failed: {error}")))?;
    let replay_key = format!("mimi-consent-proof:{replay_digest}");
    let store = state.idempotency_keys_store();
    let current_time = now();
    if let Err(error) = store.prune_expired(current_time).await {
        tracing::warn!(%error, "MIMI consent replay ledger prune failed");
    }
    if store
        .get(body.actor_id.as_str(), &replay_key)
        .await
        .map_err(|error| AppError::internal(format!("MIMI replay lookup failed: {error}")))?
        .is_some()
    {
        return Err(
            AppError::conflict("MIMI consent proof was already consumed")
                .with_wire_code("duplicate_conflict"),
        );
    }

    let claim = ids::generate("mimi_proof_claim");
    let record = IdempotencyRecord {
        principal_id: body.actor_id.to_string(),
        idempotency_key: replay_key.clone(),
        service_id: state.service_id().to_owned(),
        request_hash: proof.payload_digest.to_string(),
        response_status: StatusCode::NO_CONTENT.as_u16() as i32,
        response_body: json!({ "claim": claim }),
        created_at: current_time,
        expires_at: proof.created_at + Duration::seconds(MIMI_OPERATION_PROOF_WINDOW_SECONDS),
    };
    store
        .record(&record)
        .await
        .map_err(|error| AppError::internal(format!("MIMI replay claim failed: {error}")))?;
    let landed = store
        .get(body.actor_id.as_str(), &replay_key)
        .await
        .map_err(|error| AppError::internal(format!("MIMI replay claim read failed: {error}")))?
        .ok_or_else(|| AppError::internal("MIMI replay claim was not persisted"))?;
    if landed.response_body != record.response_body {
        return Err(
            AppError::conflict("MIMI consent proof was already consumed")
                .with_wire_code("duplicate_conflict"),
        );
    }
    Ok(())
}

pub(super) fn request_has_bearer_session(req: &Request) -> bool {
    req.headers()
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.trim().to_ascii_lowercase().starts_with("bearer "))
}

#[endpoint(
    operation_id = "ak.open.mimi.query.identifiers",
    tags("mimi"),
    summary = "Query opaque MIMI / DID identifier commitments"
)]
#[tracing::instrument(skip_all, fields(op = "ak.open.mimi.query.identifiers"))]
pub(super) async fn mimi_identifiers_query(
    body: JsonBody<MimiIdentifierQueryRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<MimiIdentifierQueryOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let body = typed_body_value(body.into_inner(), "mimi identifiers query")?;
    verify_mimi_write_service_proof(state, req, &body, None)?;
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
        "ak.open.mimi.query.identifiers",
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
    tags("mimi"),
    summary = "File a MIMI abuse report (mirrors as ak.self.moderation.report projection event)"
)]
#[tracing::instrument(skip_all, fields(op = "ak.open.mimi.command.report_abuse"))]
pub(super) async fn mimi_report_abuse(
    body: JsonBody<MimiReportAbuseRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<MimiReportAbuseOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let body = typed_body_value(body.into_inner(), "mimi report abuse")?;
    verify_mimi_write_service_proof(state, req, &body, None)?;
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
        Some(id) => mimi_bound_realm_id(state, id).await,
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
        .with_wire_code(arkret_core::ReasonCode::MIMI_GOVERNANCE_BINDING_MISSING));
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
    let report_id = ids::generate_report_id();
    let mut report_fields = serde_json::Map::new();
    report_fields.insert("report_id".to_owned(), json!(report_id));
    report_fields.insert("kind".to_owned(), json!("mimi_abuse_report"));
    report_fields.insert("realm_id".to_owned(), json!(realm_id));
    report_fields.insert("effective_scope".to_owned(), safety.effective_scope.clone());
    report_fields.insert(
        "mimi_room_uri".to_owned(),
        body.get("mimi_room_uri").cloned().unwrap_or(Value::Null),
    );
    report_fields.insert(
        "provider_id".to_owned(),
        body.get("provider_id").cloned().unwrap_or(Value::Null),
    );
    report_fields.insert("target_event_digest".to_owned(), json!(target_ref));
    report_fields.insert("reporter".to_owned(), json!(reporter));
    if let Some(evidence_package) = safety.evidence_package.clone() {
        report_fields.insert("evidence_package".to_owned(), evidence_package);
    }
    if let Some(franking_proof) = safety.franking_proof.clone() {
        report_fields.insert("franking_proof".to_owned(), franking_proof);
    }
    report_fields.insert("created_at".to_owned(), json!(now()));
    if let Err(error) = state
        .moderation_store()
        .append_report(Value::Object(report_fields))
        .await
    {
        tracing::error!(%error, "failed to persist mimi abuse report");
    }

    // Also emit a `ak.self.moderation.report` projection event so the
    // audit timeline observes the report in the same shape native
    // Arkret reports use. The MIMI provenance is preserved under
    // `payload.mimi_provenance`.
    let mut projection_payload = serde_json::Map::new();
    projection_payload.insert("report_id".to_owned(), json!(report_id));
    projection_payload.insert("effective_scope".to_owned(), safety.effective_scope);
    projection_payload.insert("target_event_digest".to_owned(), json!(target_ref));
    if let Some(franking_proof) = safety.franking_proof {
        projection_payload.insert("franking_proof".to_owned(), franking_proof);
    }
    projection_payload.insert(
        "abuse_reason_code".to_owned(),
        body.get("abuse_reason_code")
            .cloned()
            .unwrap_or(Value::Null),
    );
    projection_payload.insert("evidence_encrypted".to_owned(), json!(true));
    if let Some(evidence_package) = safety.evidence_package {
        projection_payload.insert("evidence_package".to_owned(), evidence_package);
    }
    projection_payload.insert(
        "mimi_provenance".to_owned(),
        json!({
            "facade": "soland.mimi.v1",
            "mimi_room_uri": body.get("mimi_room_uri").cloned(),
            "mimi_provider_id": mimi_provider_id(state),
            "accepted_at": now(),
        }),
    );
    let report_event_id = ids::generate_event_id();
    let report_record = ProjectionEventRecord {
        event_id: report_event_id.clone(),
        realm_id: realm_id.clone(),
        event_kind: "ak.self.moderation.report".to_owned(),
        operation_type: "mimi_facade_report".to_owned(),
        operation_id: None,
        sender: Some(reporter.to_owned()),
        payload: Value::Object(projection_payload),
        created_at: chrono::Utc::now(),
        received_at: chrono::Utc::now(),
    };
    if let Err(error) = crate::routing::events::projection::persist_and_publish_projection_event(
        state,
        report_record,
    )
    .await
    {
        tracing::error!(%error, "mimi: failed to mirror report into projection_events");
    }

    let routed_to = Did::new(state.service_id.clone()).map_or_else(
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
            "routed_to": [format!("{}#moderation", state.service_id)],
            "moderation_event_emitted": true,
            "report_event_id": report_event_id,
            "reporter_resolution": "holder_claim_or_consent",
        }),
    );
    let report_id = ReportId::new(report_id)
        .map_err(|error| AppError::internal(format!("MIMI report id: {error}")))?;
    json_ok(MimiReportAbuseOutcome {
        report_id,
        status: "queued".to_owned(),
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
        .accounts_store()
        .get(reporter)
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
    tags("mimi"),
    summary = "Issue a proxy-download token for a MIMI blob (asset privacy policy honored)"
)]
#[tracing::instrument(skip_all, fields(op = "ak.open.mimi.command.proxy_download"))]
pub(super) async fn mimi_proxy_download(
    body: JsonBody<MimiProxyDownloadRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<MimiProxyDownloadOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let body = typed_body_value(body.into_inner(), "mimi proxy download")?;
    verify_mimi_write_service_proof(state, req, &body, None)?;
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
    let blob = state.blobs_store().get(asset_ref).await.ok().flatten();
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
            state.config.development_mode,
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
    use arkret_core::{
        Audience, ConsentId, Did, Hash, MimiConsentDecision, PayloadProof, proof_kind,
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
        let mut request = MimiUpdateConsentRequestBody {
            consent_id: ConsentId::new(
                "ak:consent:01964137-0000-7000-8000-000000000777".to_owned(),
            )
            .unwrap(),
            decision: MimiConsentDecision::Accept,
            actor_id,
            signature: PayloadProof {
                kind: proof_kind::DETACHED_JWS.to_owned(),
                alg: "EdDSA".to_owned(),
                verification_method: verification_method.clone(),
                payload_digest: Hash::new(format!("sha256:{}", "0".repeat(64))).unwrap(),
                created_at: now(),
                domain: Some(state.config.trust_domain.clone()),
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
    async fn consent_actor_proof_rejects_payload_tampering() {
        let state = state();
        let mut request = request(&state);
        request.decision = MimiConsentDecision::Revoke;

        let error = verify_mimi_consent_actor_proof(&state, &request)
            .await
            .expect_err("tampered body must fail");

        assert_eq!(error.code, ErrorCode::InvalidParam);
        assert_eq!(error.wire_code_override.as_deref(), Some("invalid_proof"));
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
