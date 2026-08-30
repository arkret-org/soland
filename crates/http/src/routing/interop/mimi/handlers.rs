use arkret_models_collaboration::events_payloads::moderation::{
    ModerationReportPayload, ModerationReportProvenance,
};
use salvo::oapi::endpoint;

use super::*;

#[endpoint(operation_id = "org.arkret.soland.interop.mimi.protocol_directory")]
#[tracing::instrument(
    skip_all,
    fields(op = "org.arkret.soland.interop.mimi.protocol_directory")
)]
pub(super) async fn mimi_protocol_directory(
    depot: &mut Depot,
) -> JsonResult<arkret_models_collaboration::objects::interop::ProviderDirectory> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    json_ok(mimi_provider_directory_value(state)?)
}

#[endpoint(operation_id = "ak.open.mimi.read.provider_directory")]
#[tracing::instrument(skip_all, fields(op = "ak.open.mimi.read.provider_directory.v1"))]
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
#[tracing::instrument(skip_all, fields(op = "ak.open.mimi.exchange.request_key_material.v1"))]
pub(super) async fn mimi_key_material(
    body: JsonBody<MimiKeyMaterialRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<MimiKeyMaterialOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let typed = body.into_inner();
    let body = typed_body_value(&typed, "mimi key material")?;
    verify_mimi_source_service_signature(state, req, None).await?;
    if let Some(message) = unsupported_mimi_draft(&body) {
        return Err(AppError::param_invalid(message).with_wire_code("mimi_draft_unsupported"));
    }
    verify_mimi_key_material_request_proofs(state, &typed).await?;
    let target = typed.strand_id.as_str();
    let _receipt = mimi_receipt(
        state,
        arkret_wire::ServiceOperationId::OPEN_MIMI_EXCHANGE_REQUEST_KEY_MATERIAL_V1,
        &body,
        json!({
            "target": target,
            "keypackage_claim_lifecycle": "single_use_required",
            "production_gap": "full_mls_keypackage_claim_not_implemented"
        }),
    );
    json_ok(MimiKeyMaterialOutcome {
        keypackages: Vec::new(),
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
#[tracing::instrument(skip_all, fields(op = "ak.open.mimi.command.update_room.v1"))]
pub(super) async fn mimi_room_update(
    strand_id: PathParam<String>,
    body: JsonBody<MimiRoomUpdateRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<MimiRoomUpdateOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let room_id = strand_id.into_inner();
    let body = typed_body_value(body.into_inner(), "mimi room update")?;
    let room_uri = mimi_room_uri(state, &room_id)?;
    verify_mimi_source_service_signature(state, req, Some(room_uri.as_str())).await?;
    if let Some(message) = unsupported_mimi_draft(&body) {
        return Err(AppError::param_invalid(message).with_wire_code("mimi_draft_unsupported"));
    }
    if !valid_mimi_room_id(&room_id) {
        return Err(AppError::param_invalid("invalid MIMI room id"));
    }
    // If the update carries a `room_binding` block, persist it as a
    // `ak.mimi.room_binding` projection event so the Arkret
    // timeline observes the binding. Updates without a binding block
    // fall through to the receipt-only response. A binding block that
    // omits both `binding_scope.realm_id` and a top-level `realm_id`
    // is rejected; we never implicitly route to a default Realm.
    let update_payload = decode_mimi_update_payload(&body)?;
    let declared_update_kind = body
        .pointer("/update/kind")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            AppError::param_invalid("MIMI room update requires update.kind")
                .with_wire_code("mimi_room_binding_event_invalid")
        })?;
    let decoded_update_kind = update_payload
        .as_ref()
        .and_then(|payload| payload.get("kind"))
        .and_then(Value::as_str);
    if decoded_update_kind.is_some_and(|kind| kind != declared_update_kind) {
        return Err(AppError::param_invalid(
            "declared MIMI update kind does not match the decoded payload",
        )
        .with_wire_code("mimi_room_binding_event_invalid"));
    }
    let binding_event_id = match declared_update_kind {
        arkret_wire::event_kind_str::MIMI_ROOM_BINDING => {
            let binding = update_payload
                .as_ref()
                .and_then(mimi_room_binding_payload)
                .filter(|binding| binding.is_object())
                .ok_or_else(|| {
                    AppError::param_invalid(
                        "room binding branch requires a decoded room binding payload",
                    )
                    .with_wire_code("mimi_room_binding_event_invalid")
                })?;
            let submission = body.get("room_binding_event").cloned().ok_or_else(|| {
                AppError::param_invalid(
                    "room_binding update requires a caller-authored room_binding_event",
                )
                .with_wire_code("mimi_room_binding_event_invalid")
            })?;
            Some(admit_mimi_room_binding_event(state, &room_id, &body, binding, submission).await?)
        }
        _ => {
            if body.get("room_binding_event").is_some() {
                return Err(AppError::param_invalid(
                    "room_binding_event is only valid for a room binding update",
                )
                .with_wire_code("mimi_room_binding_event_invalid"));
            }
            None
        }
    };

    let room_state_ref = binding_event_id
        .as_deref()
        .map(EventId::new)
        .transpose()
        .map_err(|error| AppError::internal(format!("MIMI room state ref: {error}")))?;
    let _receipt = mimi_receipt(
        state,
        arkret_wire::ServiceOperationId::OPEN_MIMI_COMMAND_UPDATE_ROOM_V1,
        &body,
        json!({
            "mimi_room_uri": mimi_room_uri(state, &room_id)?,
            "truth_source": "arkret_signed_event_reducer",
            "status": "projected",
            "binding_emitted": binding_event_id.is_some(),
        }),
    );
    json_ok(MimiRoomUpdateOutcome {
        accepted: true,
        room_state_ref,
        rejections: Vec::new(),
    })
}

#[endpoint(
    operation_id = "ak.open.mimi.command.notify",
    summary = "MIMI notify",
    tags("mimi")
)]
#[tracing::instrument(skip_all, fields(op = "ak.open.mimi.command.notify.v1"))]
pub(super) async fn mimi_notify(
    strand_id: PathParam<String>,
    body: JsonBody<MimiNotifyRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<MimiNotifyOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let room_id = strand_id.into_inner();
    let body = typed_body_value(body.into_inner(), "mimi notify")?;
    let room_uri = mimi_room_uri(state, &room_id)?;
    verify_mimi_source_service_signature(state, req, Some(room_uri.as_str())).await?;
    if let Some(message) = unsupported_mimi_draft(&body) {
        return Err(AppError::param_invalid(message).with_wire_code("mimi_draft_unsupported"));
    }
    if !valid_mimi_room_id(&room_id) {
        return Err(AppError::param_invalid("invalid MIMI room id"));
    }
    // Notify is an ephemeral MIMI control signal, not an Arkret Event. It must
    // not mint an Event id or enter the canonical projection timeline.
    let _realm_id = mimi_bound_realm_id(state, &room_id).await?.ok_or_else(|| {
        AppError::not_found("MIMI room is not bound to any Arkret Realm")
            .with_wire_code(arkret_wire::ReasonCode::MIMI_GOVERNANCE_BINDING_MISSING)
    })?;
    let _receipt = mimi_receipt(
        state,
        arkret_wire::ServiceOperationId::OPEN_MIMI_COMMAND_NOTIFY_V1,
        &body,
        json!({
            "delivery": "queued",
            "mimi_room_uri": mimi_room_uri(state, &room_id)?,
            "broadcast_emitted": false,
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
#[tracing::instrument(skip_all, fields(op = "ak.open.mimi.command.submit_message.v1"))]
pub(super) async fn mimi_room_message(
    strand_id: PathParam<String>,
    body: JsonBody<MimiSubmitMessageRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<MimiSubmitMessageOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let room_id = strand_id.into_inner();
    let body = body.into_inner();
    let room_uri = mimi_room_uri(state, &room_id)?;
    let source_provider =
        verify_mimi_source_service_signature(state, req, Some(room_uri.as_str())).await?;
    if !valid_mimi_room_id(&room_id) {
        return Err(AppError::param_invalid("invalid MIMI room id"));
    }
    let message = decode_mimi_ciphertext_payload(&body.ciphertext)?;
    let associated_data = decode_mimi_associated_data(body.associated_data.as_ref())?;
    let source_format = body.ciphertext.content_type.as_str().to_owned();
    if !valid_mimi_content_type(&source_format) {
        return Err(AppError::param_invalid("unsupported MIMI content type"));
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
    let body_bytes = arkret_canonical::canonical_json_bytes(&body)
        .map_err(|error| AppError::internal(format!("MIMI request canonicalization: {error}")))?;
    let original_hash = arkret_canonical::sha256_digest(&body_bytes);

    // Map the MIMI message into the canonical Arkret timeline.
    // Append a MessageRecord + a `ak.message.create` projection event so
    // the message shows up in `QUERY /_arkret/self/events`. The
    // MIMI provenance is bound in the closed top-level payload branch so
    // admission and audit consumers can verify service authorship separately
    // from external sender attribution.
    let room_binding = latest_mimi_room_binding(state, &room_id)
        .await?
        .ok_or_else(|| {
            AppError::not_found("MIMI room is not bound to any Arkret Realm")
                .with_wire_code(arkret_wire::ReasonCode::MIMI_GOVERNANCE_BINDING_MISSING)
        })?;
    enforce_mimi_submit_binding(&room_binding, &body, &message, associated_data.as_ref())?;
    let realm_id = room_binding.realm_id.clone();
    let sender = body.sender_actor_id.to_string();
    let mapped_content = map_mimi_message_content(&message, &source_format)?;
    let thread_id = message
        .get("thread_id")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .or_else(|| crate::routing::events::strand::strand_id_from_realm_id(&realm_id))
        .ok_or_else(|| AppError::param_invalid("MIMI binding carries a non-canonical realm_id"))?;
    let created_at = chrono::Utc::now();
    let event_payload = json!({
        "strand_id": thread_id.clone(),
        "track_name": "discussion",
        "content": mapped_content.content.clone(),
        "metadata": {
            "mimi_policy": mapped_content.policy.clone(),
            "quarantine": mapped_content.quarantine.clone(),
        },
        "mimi_provenance": {
            "provenance": "mimi_facade",
            "source_provider": source_provider,
            "attributed_sender_actor_id": body.sender_actor_id,
            "attributed_sender_device_id": body.device_id,
            "source_envelope_digest": original_hash,
            "room_binding_ref": room_binding.event_id.clone(),
        },
    });
    let event_id =
        persist_mimi_canonical_message_event(state, &realm_id, created_at, event_payload).await?;

    let body_value = typed_body_value(&body, "mimi submit message")?;
    let _receipt = mimi_receipt(
        state,
        arkret_wire::ServiceOperationId::OPEN_MIMI_COMMAND_SUBMIT_MESSAGE_V1,
        &body_value,
        json!({
            "schema": arkret_wire::SchemaId::MIMI_INTEROP_V1,
            "receipt_kind": "content_mapping_receipt",
            "profile": arkret_wire::ProfileId::MIMI_INTEROP_V1,
            "mimi_room_uri": mimi_room_uri(state, &room_id)?,
            "source_format": source_format,
            "target_format": arkret_wire::event_kind_str::MESSAGE_CREATE,
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
            delivered_to_ids: Vec::new(),
        },
        rejections: Vec::new(),
    })
}

#[endpoint(
    operation_id = "ak.open.mimi.command.request_consent",
    summary = "Request MIMI consent",
    tags("mimi")
)]
#[tracing::instrument(skip_all, fields(op = "ak.open.mimi.command.request_consent.v1"))]
pub(super) async fn mimi_consent_request(
    aa: AuthArgs,
    body: JsonBody<MimiRequestConsentRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<MimiRequestConsentOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let body = body.into_inner();
    let body_value = typed_body_value(body.clone(), "mimi consent request")?;
    if let Some(message) = unsupported_mimi_draft(&body_value) {
        return Err(AppError::param_invalid(message).with_wire_code("mimi_draft_unsupported"));
    }
    let source_id =
        verify_mimi_consent_write_authority(state, req, aa, body.requester_id.as_str()).await?;
    verify_mimi_request_consent_proofs(state, &body).await?;
    let consent_id = ids::generate("consent");
    let consent_id = arkret_identifiers::ConsentId::new(consent_id)
        .map_err(|error| AppError::internal(format!("generated consent id is invalid: {error}")))?;
    state
        .consents()
        .save_mimi_correlation(MimiConsentCorrelation {
            consent_id: consent_id.to_string(),
            requester_id: body.requester_id.to_string(),
            target_kind: mimi_consent_target_kind(body.target.kind).to_owned(),
            target_id: body.target.id.to_string(),
            purpose: mimi_consent_purpose(body.purpose).to_owned(),
            strand_id: body.strand_id.as_ref().map(ToString::to_string),
            source_id,
            created_at: now(),
            expires_at: body.expires_at,
        })
        .await
        .map_err(|error| {
            AppError::internal(format!("persist MIMI consent correlation: {error}"))
        })?;
    let _receipt = mimi_receipt(
        state,
        arkret_wire::ServiceOperationId::OPEN_MIMI_COMMAND_REQUEST_CONSENT_V1,
        &body_value,
        json!({
            "consent_grants_space_capability": false,
            "privacy_state": "holder_private",
            "holder_private_materialized": false,
            "identifier_mapping": "pending_invite_or_pairwise"
        }),
    );
    json_ok(MimiRequestConsentOutcome {
        consent_id,
        status: MimiRequestConsentStatus::Requested,
        challenge: None,
    })
}

#[endpoint(
    operation_id = "ak.open.mimi.command.update_consent",
    summary = "Update MIMI consent",
    tags("mimi")
)]
#[tracing::instrument(skip_all, fields(op = "ak.open.mimi.command.update_consent.v1"))]
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
        return Err(AppError::param_invalid(message).with_wire_code("mimi_draft_unsupported"));
    }
    body.validate_consent_event().map_err(|error| {
        AppError::param_invalid(format!("MIMI consent Event binding is invalid: {error}"))
            .with_wire_code("schema_violation")
    })?;
    let (session, source_id) = verify_mimi_consent_update_authority(state, req, aa, &body).await?;
    verify_mimi_consent_correlation(state, &body, source_id.as_deref()).await?;
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
) -> Result<Option<String>, AppError> {
    if request_has_bearer_session(req) {
        let session = aa.authenticated_session(state, req).await?;
        if session.actor != expected_actor {
            return Err(AppError::capability_denied(
                "MIMI consent user session must match the consent actor",
            ));
        }
        return Ok(None);
    }
    verify_mimi_source_service_signature(state, req, None)
        .await
        .map(Some)
}

const MIMI_OPERATION_PROOF_WINDOW_SECONDS: i64 = 300;

/// Signer identity an inbound MIMI operation proof has to resolve to.
///
/// The two arms are not interchangeable: `PrincipalDevice` requires an
/// accepted device authorization inside this deployment's Principal Control
/// Realm, while `DidController` only requires the proof method to be
/// controlled by the DID the request names as its originator.
enum MimiProofSigner<'a> {
    /// A device of a principal whose account authority lives on this service.
    /// The `update_consent` family uses this: the proof is authored by the
    /// consent actor's own device.
    PrincipalDevice {
        authority: arkret_wire::AccountId,
        device_id: arkret_identifiers::DeviceId,
    },
    /// A verification method controlled by the originator DID carried on the
    /// wire. The federated request families use this: the originator is a
    /// remote principal or provider that this service never holds devices for.
    DidController(&'a str),
}

/// Destination, replay-window and signature checks shared by every inbound
/// MIMI operation proof.
///
/// There is deliberately no context argument. The proof context is baked into
/// `binding` by the request body family's own SDK `proof_binding_bytes`
/// helper, so which context applies falls out of which body type the caller
/// held; a signature produced under one family's context can never verify
/// here under another's. The SDK helper has already enforced
/// `PayloadProof::validate_production`, the absent `proof_purpose`, the
/// `payload_digest` match and the presence of `domain`/`audience`. This
/// function adds only the checks that need deployment state.
async fn verify_mimi_operation_proof(
    state: &AppState,
    binding: &[u8],
    proof: &arkret_wire::PayloadProof,
    signer: MimiProofSigner<'_>,
    label: &str,
) -> Result<(), AppError> {
    if proof.domain.as_deref() != Some(state.config().trust_domain.as_str()) {
        return Err(AppError::param_invalid(format!(
            "{label} proof domain does not match the destination trust domain"
        ))
        .with_wire_code("invalid_proof"));
    }
    let audience_matches = match proof.audience.as_ref() {
        Some(Audience::Single(value)) => value == state.service_id(),
        Some(Audience::Multiple(values)) => values.iter().any(|value| value == state.service_id()),
        None => false,
    };
    if !audience_matches {
        return Err(AppError::param_invalid(format!(
            "{label} proof audience does not cover the destination service"
        ))
        .with_wire_code("invalid_proof"));
    }
    let age_seconds = now()
        .signed_duration_since(proof.created_at)
        .num_seconds()
        .unsigned_abs();
    if age_seconds > MIMI_OPERATION_PROOF_WINDOW_SECONDS as u64 {
        return Err(AppError::param_invalid(format!(
            "{label} proof created_at is outside the accepted replay window"
        ))
        .with_wire_code("invalid_proof"));
    }
    let verified = match signer {
        MimiProofSigner::PrincipalDevice {
            authority,
            device_id,
        } => crate::jws_verify::verify_principal_authorized_jws_with_account_authority_async(
            binding,
            &proof.jws,
            &proof.verification_method,
            &authority,
            &device_id,
            state,
        )
        .await
        .map_err(|error| error.to_string()),
        MimiProofSigner::DidController(issuer) => {
            crate::jws_verify::verify_did_controlled_jws_async(
                binding,
                &proof.jws,
                proof.verification_method.as_str(),
                issuer,
                state,
            )
            .await
        }
    };
    verified.map_err(|reason| {
        tracing::warn!(
            %reason,
            %label,
            verification_method = %proof.verification_method,
            "MIMI operation proof verification failed"
        );
        AppError::param_invalid(format!("{label} proof JWS verification failed"))
            .with_wire_code("invalid_proof")
    })
}

/// Verify every proof carried by a MIMI key-material request.
///
/// `proofs` is `#[serde(default)]` on the wire, so an empty vector is a valid
/// request and this is a no-op for it. The originator is the mandatory
/// `requester_id` field.
async fn verify_mimi_key_material_request_proofs(
    state: &AppState,
    body: &MimiKeyMaterialRequestBody,
) -> Result<(), AppError> {
    let issuer = body.requester_id.to_string();
    for proof in &body.proofs {
        let binding = body.proof_binding_bytes(proof).map_err(|error| {
            AppError::param_invalid(format!(
                "MIMI key material request proof binding is invalid: {error}"
            ))
            .with_wire_code("invalid_proof")
        })?;
        verify_mimi_operation_proof(
            state,
            &binding,
            proof,
            MimiProofSigner::DidController(issuer.as_str()),
            "MIMI key material request",
        )
        .await?;
    }
    Ok(())
}

/// Verify every proof carried by a MIMI consent request.
///
/// `proofs` is `#[serde(default)]` on the wire; an empty vector stays valid.
/// The originator is the mandatory `requester_id` field.
async fn verify_mimi_request_consent_proofs(
    state: &AppState,
    body: &MimiRequestConsentRequestBody,
) -> Result<(), AppError> {
    let issuer = body.requester_id.to_string();
    for proof in &body.proofs {
        let binding = body.proof_binding_bytes(proof).map_err(|error| {
            AppError::param_invalid(format!(
                "MIMI consent request proof binding is invalid: {error}"
            ))
            .with_wire_code("invalid_proof")
        })?;
        verify_mimi_operation_proof(
            state,
            &binding,
            proof,
            MimiProofSigner::DidController(issuer.as_str()),
            "MIMI consent request",
        )
        .await?;
    }
    Ok(())
}

/// Verify every proof carried by a MIMI identifier query.
///
/// `proofs` is `#[serde(default)]` on the wire; an empty vector stays valid.
/// This family's `requester_id` is optional and the SDK transcript then omits
/// `issuer` entirely, so when it is absent the only originator the request
/// carries is the transport-authenticated source service and the proof must
/// be signed by that service.
async fn verify_mimi_identifier_query_proofs(
    state: &AppState,
    body: &MimiIdentifierQueryRequestBody,
    source_id: &str,
) -> Result<(), AppError> {
    let issuer = body
        .requester_id
        .as_ref()
        .map_or_else(|| source_id.to_owned(), ToString::to_string);
    for proof in &body.proofs {
        let binding = body.proof_binding_bytes(proof).map_err(|error| {
            AppError::param_invalid(format!(
                "MIMI identifier query proof binding is invalid: {error}"
            ))
            .with_wire_code("invalid_proof")
        })?;
        verify_mimi_operation_proof(
            state,
            &binding,
            proof,
            MimiProofSigner::DidController(issuer.as_str()),
            "MIMI identifier query",
        )
        .await?;
    }
    Ok(())
}

async fn verify_mimi_consent_update_authority(
    state: &AppState,
    req: &mut Request,
    aa: AuthArgs,
    body: &MimiUpdateConsentRequestBody,
) -> Result<
    (
        soland_services::identity::SessionIdentityState,
        Option<String>,
    ),
    AppError,
> {
    let (session, source_id) = if request_has_bearer_session(req) {
        let session = aa.authenticated_session(state, req).await?;
        if session.actor != body.actor_id.signing_principal_id().as_str() {
            return Err(AppError::capability_denied(
                "MIMI consent user session must match the consent actor",
            ));
        }
        (session, None)
    } else {
        let source_id = verify_mimi_source_service_signature(state, req, None).await?;
        let device_id = body
            .consent_event
            .event
            .proofs
            .first()
            .and_then(arkret_wire::EventProof::as_producer)
            .and_then(|proof| proof.verification_method.as_str().rsplit_once('#'))
            .map(|(_, fragment)| fragment.to_owned())
            .ok_or_else(|| {
                AppError::param_invalid("MIMI consent Event requires a DID URL proof key")
                    .with_wire_code("invalid_proof")
            })?;
        (
            soland_services::identity::SessionIdentityState {
                account_pk: None,
                token_hash: format!("mimi-event:{}", body.consent_event.event.event_id),
                actor: body.actor_id.to_string(),
                device_id,
                audience: state.service_id().to_string(),
                session_public_key: None,
                agent_session: None,
                session_grant: None,
                expires_at: now() + chrono::Duration::minutes(5),
                created_at: now(),
                revoked_at: None,
            },
            Some(source_id),
        )
    };

    verify_mimi_consent_actor_proof(state, body).await?;
    Ok((session, source_id))
}

fn mimi_consent_target_kind(kind: MimiConsentTargetKind) -> &'static str {
    match kind {
        MimiConsentTargetKind::Did => "did",
        MimiConsentTargetKind::MimiUri => "mimi_uri",
        MimiConsentTargetKind::Handle => "handle",
        MimiConsentTargetKind::ProviderUser => "provider_user",
    }
}

fn mimi_consent_purpose(purpose: MimiConsentPurpose) -> &'static str {
    match purpose {
        MimiConsentPurpose::Invite => "invite",
        MimiConsentPurpose::DirectMessage => "direct_message",
        MimiConsentPurpose::VoiceCall => "voice_call",
        MimiConsentPurpose::VideoCall => "video_call",
        MimiConsentPurpose::Presence => "presence",
        MimiConsentPurpose::Any => "any",
    }
}

fn mimi_consent_correlation_unavailable() -> AppError {
    AppError::not_found("MIMI consent correlation is unavailable")
}

async fn verify_mimi_consent_correlation(
    state: &AppState,
    body: &MimiUpdateConsentRequestBody,
    source_id: Option<&str>,
) -> Result<(), AppError> {
    let correlation = state
        .consents()
        .mimi_correlation(body.consent_id.as_str())
        .await
        .map_err(|error| AppError::internal(format!("read MIMI consent correlation: {error}")))?
        .ok_or_else(mimi_consent_correlation_unavailable)?;

    if correlation
        .expires_at
        .is_some_and(|expires_at| expires_at <= now())
        || correlation.source_id.as_deref() != source_id
        || correlation.target_kind != "did"
        || correlation.target_id != body.actor_id.signing_principal_id().as_str()
    {
        return Err(mimi_consent_correlation_unavailable());
    }

    match body.decision {
        arkret_models_collaboration::http_bodies::MimiConsentDecision::Accept => {
            let payload = &body.consent_event.event.payload;
            if payload.get("peer").and_then(Value::as_str)
                != Some(correlation.requester_id.as_str())
                || payload.get("consent_scope").and_then(Value::as_str)
                    != Some(correlation.purpose.as_str())
            {
                return Err(mimi_consent_correlation_unavailable());
            }
        }
        arkret_models_collaboration::http_bodies::MimiConsentDecision::Deny
        | arkret_models_collaboration::http_bodies::MimiConsentDecision::Revoke => {
            let observed_dot_ids = body
                .consent_event
                .event
                .payload
                .get("observed_dot_ids")
                .and_then(Value::as_array)
                .filter(|dots| !dots.is_empty())
                .ok_or_else(mimi_consent_correlation_unavailable)?;
            let cell_id = arkret_state::consent::consent_cell_id(&body.consent_id)
                .map_err(|error| AppError::internal(format!("MIMI consent cell id: {error}")))?;
            let cell = state
                .consents()
                .holder_cell(body.actor_id.signing_principal_id(), &cell_id)
                .filter(|cell| {
                    cell.peer_principal_id.as_str() == correlation.requester_id
                        && cell.consent_scope == correlation.purpose
                        && observed_dot_ids.iter().all(|observed_dot| {
                            observed_dot.as_str().is_some_and(|observed_dot| {
                                cell.grant_dots.get(observed_dot).is_some_and(|dot| {
                                    !cell.revoked_dots.contains(&dot.dot)
                                        && dot
                                            .expires_at
                                            .is_none_or(|expires_at| expires_at > now())
                                })
                            })
                        })
                });
            if cell.is_none() {
                return Err(mimi_consent_correlation_unavailable());
            }
        }
    }
    Ok(())
}

async fn verify_mimi_consent_actor_proof(
    state: &AppState,
    body: &MimiUpdateConsentRequestBody,
) -> Result<(), AppError> {
    body.validate_consent_event().map_err(|error| {
        AppError::param_invalid(format!("MIMI consent Event carrier is invalid: {error}"))
            .with_wire_code("invalid_consent_event")
    })?;
    let proof = &body.signature;
    let binding = body.signature_binding_bytes().map_err(|error| {
        AppError::param_invalid(format!("MIMI consent proof binding is invalid: {error}"))
            .with_wire_code("invalid_proof")
    })?;
    let device_id = proof
        .verification_method
        .as_str()
        .rsplit_once('#')
        .map(|(_, fragment)| fragment)
        .ok_or_else(|| {
            AppError::param_invalid("MIMI consent proof method has no device fragment")
                .with_wire_code("invalid_proof")
        })?;
    let device_id = arkret_identifiers::DeviceId::new(device_id.to_owned()).map_err(|error| {
        AppError::param_invalid(format!(
            "MIMI consent proof method device fragment is invalid: {error}"
        ))
        .with_wire_code("invalid_proof")
    })?;
    let authority = body
        .consent_event
        .event
        .actor_id
        .as_account_id()
        .cloned()
        .ok_or_else(|| {
            AppError::param_invalid("MIMI consent actor must be an account")
                .with_wire_code("invalid_proof")
        })?;
    verify_mimi_operation_proof(
        state,
        &binding,
        proof,
        MimiProofSigner::PrincipalDevice {
            authority,
            device_id,
        },
        "MIMI consent",
    )
    .await
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
#[tracing::instrument(skip_all, fields(op = "ak.open.mimi.read.identifiers.v1"))]
pub(super) async fn mimi_identifiers_query(
    body: JsonBody<MimiIdentifierQueryRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<MimiIdentifierQueryOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let typed = body.into_inner();
    let body = typed_body_value(&typed, "mimi identifiers query")?;
    let source_id = verify_mimi_source_service_signature(state, req, None).await?;
    if let Some(message) = unsupported_mimi_draft(&body) {
        return Err(AppError::param_invalid(message).with_wire_code("mimi_draft_unsupported"));
    }
    verify_mimi_identifier_query_proofs(state, &typed, &source_id).await?;
    let identifiers = body
        .get("identifiers")
        .and_then(Value::as_array)
        .filter(|values| !values.is_empty())
        .ok_or_else(|| AppError::param_missing("identifiers is required"))?;
    let mut matches = Vec::with_capacity(identifiers.len());
    for identifier in identifiers {
        let kind = identifier
            .get("kind")
            .and_then(Value::as_str)
            .ok_or_else(|| AppError::param_invalid("identifier entries require kind"))?;
        if !matches!(
            kind,
            "mimi_uri" | "did" | "handle" | "phone" | "email" | "opaque"
        ) {
            return Err(AppError::param_invalid("identifier kind is unsupported"));
        }
        let commitment = identifier
            .get("identifier_commitment")
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| {
                AppError::param_invalid("identifier entries require identifier_commitment")
            })?;
        Hash::new(commitment.to_owned())
            .map_err(|_| AppError::param_invalid("identifier_commitment must be a hash"))?;
        matches.push(MimiIdentifierMatch {
            identifier_commitment: Hash::new(commitment.to_owned())
                .map_err(|_| AppError::param_invalid("identifier_commitment must be a hash"))?,
            matched: false,
            mimi_uri: None,
            subject_id: None,
        });
    }
    let _receipt = mimi_receipt(
        state,
        arkret_wire::ServiceOperationId::OPEN_MIMI_READ_IDENTIFIERS_V1,
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
#[tracing::instrument(skip_all, fields(op = "ak.open.mimi.command.report_abuse.v1"))]
pub(super) async fn mimi_report_abuse(
    body: JsonBody<MimiReportAbuseRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<MimiReportAbuseOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let body = typed_body_value(body.into_inner(), "mimi report abuse")?;
    let source_provider = verify_mimi_source_service_signature(state, req, None).await?;
    if let Some(message) = unsupported_mimi_draft(&body) {
        return Err(AppError::param_invalid(message).with_wire_code("mimi_draft_unsupported"));
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
        return Err(AppError::param_invalid(
            "mimi report requires `realm_id` or a `mimi_room_uri` that resolves to a bound Arkret Realm",
        )
        .with_wire_code(arkret_wire::ReasonCode::MIMI_GOVERNANCE_BINDING_MISSING));
    };
    let reporter_id = body
        .get("reporter_did")
        .or_else(|| body.get("reporter_id"))
        .and_then(Value::as_str)
        .ok_or_else(|| AppError::param_invalid("mimi report requires reporter_id"))?;
    enforce_mimi_reporter_resolution(state, reporter_id, &body).await?;
    let target_ref = body
        .get("target_event_digest")
        .or_else(|| body.get("target_ref"))
        .and_then(Value::as_str)
        .ok_or_else(|| AppError::param_invalid("mimi report requires target_ref"))?;
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
        reporter_id,
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
    let description =
        body.get("description")
            .map(|value| {
                value.as_str().map(str::to_owned).ok_or_else(|| {
                    AppError::param_invalid("mimi report description must be a string")
                })
            })
            .transpose()?;
    let effective_scope = serde_json::from_value(safety.effective_scope).map_err(|error| {
        AppError::param_invalid(format!("mimi report effective_scope invalid: {error}"))
    })?;
    let evidence_package = safety
        .evidence_package
        .map(serde_json::from_value)
        .transpose()
        .map_err(|error| {
            AppError::param_invalid(format!("mimi report evidence_package invalid: {error}"))
        })?;
    let franking_proof = safety
        .franking_proof
        .map(serde_json::from_value)
        .transpose()
        .map_err(|error| {
            AppError::param_invalid(format!("mimi report franking_proof invalid: {error}"))
        })?;
    let payload = ModerationReportPayload {
        realm_id: arkret_wire::RealmId::new(realm_id.clone()).map_err(|error| {
            AppError::param_invalid(format!("mimi report realm_id invalid: {error}"))
        })?,
        effective_scope,
        target_ref: target_ref.to_owned(),
        report_reason_code: canonical_reason.to_owned(),
        description,
        reporter_id: arkret_wire::DidCoreId::new(reporter_id.to_owned()).map_err(|error| {
            AppError::param_invalid(format!("mimi report reporter_id invalid: {error}"))
        })?,
        provenance: Some(ModerationReportProvenance::MimiFacade),
        source_provider_id: Some(arkret_wire::DidCoreId::new(source_provider).map_err(
            |error| AppError::internal(format!("MIMI source provider id invalid: {error}")),
        )?),
        evidence_refs: None,
        evidence_package,
        franking_proof,
    };
    let report_event_id = persist_mimi_facade_moderation_report_event(state, payload).await?;

    // `report` is Event-derived: the id is the accepted
    // `ak.self.moderation.report` Event token retyped, so it exists only after
    // admission and never enters the Event payload.
    let report_id = ReportId::from_event_id(
        &arkret_identifiers::EventId::new(report_event_id.clone())
            .map_err(|error| AppError::internal(format!("MIMI report Event id: {error}")))?,
    );
    let routed_to = vec![
        arkret_wire::DidCoreId::new(state.service_id().clone())
            .map_err(|error| AppError::internal(format!("service core id is invalid: {error}")))?,
    ];
    let _receipt = mimi_receipt(
        state,
        arkret_wire::ServiceOperationId::OPEN_MIMI_COMMAND_REPORT_ABUSE_V1,
        &body,
        json!({
            "e2ee_evidence_plaintext_required": false,
            "routed_to_ids": [format!("{}#moderation", state.service_id())],
            "moderation_event_emitted": true,
            "report_event_id": report_event_id,
            "reporter_resolution": "holder_claim_or_consent",
        }),
    );
    json_ok(MimiReportAbuseOutcome {
        report_id,
        status: MimiReportAbuseStatus::Queued,
        routed_to_ids: routed_to,
    })
}

pub(super) async fn enforce_mimi_reporter_resolution(
    state: &AppState,
    reporter_id: &str,
    body: &Value,
) -> Result<(), AppError> {
    Did::new(reporter_id.to_owned())
        .map_err(|error| AppError::param_invalid(format!("invalid reporter_id DID: {error}")))?;
    if state
        .identities()
        .account(&arkret_wire::AccountId::new(
            arkret_wire::DidCoreId::new(reporter_id.to_owned()).map_err(|error| {
                AppError::param_invalid(format!("invalid reporter_id: {error}"))
            })?,
            state.service_core_id().clone(),
        ))
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
        "MIMI abuse reporter_id requires local account, holder claim, or consent proof",
    )
    .with_wire_code("mimi_reporter_resolution_required"))
}

#[endpoint(
    operation_id = "ak.open.mimi.command.proxy_download",
    summary = "Proxy a MIMI download",
    tags("mimi")
)]
#[tracing::instrument(skip_all, fields(op = "ak.open.mimi.command.proxy_download.v1"))]
pub(super) async fn mimi_proxy_download(
    body: JsonBody<MimiProxyDownloadRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<MimiProxyDownloadOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let body = typed_body_value(body.into_inner(), "mimi proxy download")?;
    verify_mimi_source_service_signature(state, req, None).await?;
    if let Some(message) = unsupported_mimi_draft(&body) {
        return Err(AppError::param_invalid(message).with_wire_code("mimi_draft_unsupported"));
    }
    let asset_ref = body
        .get("asset_ref")
        .and_then(|value| value.as_str())
        .ok_or_else(|| AppError::param_missing("asset_ref is required"))?;
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
        arkret_wire::ServiceOperationId::OPEN_MIMI_COMMAND_PROXY_DOWNLOAD_V1,
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
    // The in-protocol branch is the typed blob reference. A string that merely
    // opens with `ak:blob:` is not one, and must fall through to the URL /
    // scheme rules below rather than being waved past egress policy.
    if soland_domain::capability::is_typed_blob_ref(asset_ref) {
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
    use arkret_identifiers::{ConsentId, DeviceId, Did, DidCoreId, Hash, Hlc, RealmId, StrandId};
    use arkret_models_collaboration::http_bodies::MimiConsentDecision;
    use arkret_models_collaboration::objects::mimi::{
        MimiConsentTarget, MimiIdentifier, MimiIdentifierKind,
    };
    use arkret_wire::{
        Audience, EventInitialSubmission, EventKind, PayloadProof, ScopeRef, proof_kind,
    };
    use soland_http::error::ErrorCode;
    use soland_services::identity::{DeviceIdentity, SaveDeviceCommand};
    use soland_storage_postgres::Db;

    use super::*;

    fn state() -> AppState {
        let mut config = crate::config::AppConfig::test_default();
        config.development_mode = true;
        AppState::new(config, Db { pool: None })
    }

    fn request(state: &AppState) -> MimiUpdateConsentRequestBody {
        let actor_did = Did::new("did:web:mimi-proof-test.invalid".to_owned()).unwrap();
        let actor_id = arkret_wire::project_did_to_core_id(&actor_did).unwrap();
        let verification_method =
            format!("{actor_did}#ak:device:01964137-0000-7000-8000-000000000777");
        let consent_id =
            ConsentId::new("ak:consent:01964137-0000-7000-8000-000000000777".to_owned()).unwrap();
        let realm_id =
            RealmId::new("ak:realm:Aaqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq".to_owned())
                .unwrap();
        let consent_event = crate::test_event::raw_event_at(
            EventKind::ConsentGrant.as_str(),
            ScopeRef::Realm { realm_id },
            crate::test_actor_id(&actor_did),
            1,
            Hlc::new(state.hlc().now()).unwrap(),
            json!({
                "consent_id": consent_id,
                "peer": "ak:did_core:web:mimi-peer-test.invalid",
                "consent_scope": "direct_message"
            }),
            now(),
        )
        .unwrap();
        let mut request = MimiUpdateConsentRequestBody {
            consent_id,
            decision: MimiConsentDecision::Accept,
            actor_id: arkret_wire::ActorId::account(arkret_wire::AccountId::new(
                actor_id,
                state.service_core_id().clone(),
            )),
            consent_event: EventInitialSubmission::online(consent_event),
            signature: PayloadProof {
                kind: proof_kind::DETACHED_JWS.to_owned(),
                verification_method: arkret_wire::DidUrl::new(verification_method.clone()).unwrap(),
                payload_digest: Hash::new(format!("sha256:{}", "0".repeat(64))).unwrap(),
                created_at: now(),
                domain: Some(state.config().trust_domain.to_string()),
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

    fn canonical_event_record(
        event: &arkret_wire::Event,
        received_at: chrono::DateTime<chrono::Utc>,
    ) -> soland_storage::CanonicalEventRecord {
        soland_storage::CanonicalEventRecord {
            event_id: event.event_id.to_string(),
            actor_id: event.actor_id.to_string(),
            actor_seq: event.actor_seq,
            realm_id: Some(event.realm_id.to_string()),
            kind: event.kind.to_string(),
            schema_id: "ak.schema.event.v1".to_owned(),
            digest_suite: arkret_canonical::DigestSuite::Sha256,
            canonical_digest: event
                .event_digest_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
                .unwrap(),
            canonical_bytes: arkret_canonical::canonical_json_bytes(
                &event.digest_payload().unwrap(),
            )
            .unwrap(),
            envelope: serde_json::to_value(event).unwrap(),
            received_at,
        }
    }

    async fn install_authorized_actor_device(
        state: &AppState,
        request: &MimiUpdateConsentRequestBody,
    ) {
        let (actor_did, device_id) = request
            .signature
            .verification_method
            .as_str()
            .rsplit_once('#')
            .expect("device verification method");
        let actor_did = Did::new(actor_did.to_owned()).unwrap();
        let device_id = DeviceId::new(device_id.to_owned()).unwrap();
        let station_id = request.actor_id.route_service_id().clone();
        let created_at = now();
        let mut genesis = arkret_wire::test_support::raw_event_at(
            EventKind::RealmCreate.as_str(),
            ScopeRef::RealmGenesis,
            request.actor_id.signing_principal_id().clone(),
            station_id.clone(),
            0,
            Hlc::new("019641370000-0000-00000001".to_owned()).unwrap(),
            json!({"object": {"purpose": "principal_control"}}),
            created_at,
        )
        .unwrap();
        genesis.refs = vec![arkret_wire::EventRef::new(
            format!("sha256:{}", "1".repeat(64)),
            "did_inception",
        )];
        genesis
            .refresh_content_bound_identity_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
            .unwrap();
        let pcr_realm_id = genesis.realm_id.clone();
        let signing_key = arkret_signatures::development_signing_key(
            request.signature.verification_method.as_str(),
        );
        let device_public_key = arkret_canonical::ed25519_pubkey_to_did_key_multibase(
            signing_key.verifying_key().as_bytes(),
        );
        let mut authorize = arkret_wire::test_support::raw_event_at(
            EventKind::DeviceAuthorize.as_str(),
            ScopeRef::Realm {
                realm_id: pcr_realm_id.clone(),
            },
            request.actor_id.signing_principal_id().clone(),
            station_id.clone(),
            1,
            Hlc::new("019641370000-0001-00000001".to_owned()).unwrap(),
            json!({
                "principal_id": request.actor_id.signing_principal_id(),
                "device_id": device_id,
                "device_public_key_did": device_public_key,
                "hpke_key": "z6LSTestMimiConsentDeviceHpkeKey",
                "algorithms": ["ak.hpke_x25519_aead_chacha20poly1305.v1", "ak.mls.v1"],
                "authorized_by": request.actor_id.signing_principal_id(),
                "not_before": "2026-05-25T00:00:00.000Z",
                "authorization_binding_kind": "registration_anchor",
                "device_signature": "c2ln"
            }),
            created_at,
        )
        .unwrap();
        authorize.prev_refs = vec![genesis.event_id.clone()];
        authorize
            .refresh_content_bound_identity_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
            .unwrap();
        state
            .test_persistence()
            .events()
            .put(canonical_event_record(&genesis, created_at))
            .await
            .unwrap();
        state
            .test_persistence()
            .events()
            .put(canonical_event_record(&authorize, created_at))
            .await
            .unwrap();
        let resolution = state
            .test_persistence()
            .principal_resolutions()
            .compare_and_set(
                None,
                soland_storage::PrincipalResolutionRecord {
                    account_id: arkret_wire::AccountId::new(
                        request.actor_id.signing_principal_id().clone(),
                        station_id,
                    ),
                    pcr_realm_id,
                    genesis_event: genesis.clone(),
                    current_event: genesis.clone(),
                    projection: arkret_models_identity::PrincipalResolutionProjection {
                        did: actor_did,
                        method_history_head: format!("sha256:{}", "1".repeat(64)),
                        version_id: "1-QmMimiConsentAuthority".to_owned(),
                        resolution_event_ref: genesis.event_id.to_string(),
                        updated_at: genesis.created_at,
                    },
                },
            )
            .await
            .unwrap();
        assert!(matches!(
            resolution,
            soland_storage::PrincipalResolutionCasResult::Applied(_)
        ));
        state
            .identities()
            .save_device(SaveDeviceCommand {
                actor_id: request.actor_id.signing_principal_id().to_string(),
                device_id: device_id.to_string(),
                display_name: None,
                device: DeviceIdentity {
                    actor_id: request.actor_id.signing_principal_id().to_string(),
                    device_id: device_id.to_string(),
                    display_name: None,
                    verification_state: "verified".to_owned(),
                    payload: json!({
                        "device_id": device_id,
                        "device_public_key": device_public_key,
                        "device_authorize_event_id": authorize.event_id,
                        "authorized_generation_ref": 1
                    }),
                    created_at,
                    updated_at: created_at,
                    revoked_at: None,
                },
            })
            .await
            .unwrap();
    }

    async fn install_correlation(
        state: &AppState,
        request: &MimiUpdateConsentRequestBody,
        target_id: &str,
    ) {
        state
            .consents()
            .save_mimi_correlation(MimiConsentCorrelation {
                consent_id: request.consent_id.to_string(),
                requester_id: "ak:did_core:web:mimi-peer-test.invalid".to_owned(),
                target_kind: "did".to_owned(),
                target_id: target_id.to_owned(),
                purpose: "direct_message".to_owned(),
                strand_id: None,
                source_id: None,
                created_at: now(),
                expires_at: None,
            })
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn consent_actor_proof_preflight_is_verified_without_consuming_admission() {
        let state = state();
        let request = request(&state);
        install_authorized_actor_device(&state, &request).await;

        verify_mimi_consent_actor_proof(&state, &request)
            .await
            .expect("first proof presentation");
        verify_mimi_consent_actor_proof(&state, &request)
            .await
            .expect("proof preflight must not consume Event admission");
    }

    #[tokio::test]
    async fn consent_actor_proof_rejects_wrong_station() {
        let state = state();
        let mut request = request(&state);
        install_authorized_actor_device(&state, &request).await;
        request.consent_event.event.actor_id =
            arkret_wire::ActorId::account(arkret_wire::AccountId::new(
                request.actor_id.signing_principal_id().clone(),
                DidCoreId::new("ak:did_core:web:other-station.invalid".to_owned()).unwrap(),
            ));
        request.actor_id = request.consent_event.event.actor_id.clone();
        request
            .consent_event
            .event
            .refresh_content_bound_identity_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
            .unwrap();

        request.signature.payload_digest = request.payload_digest().unwrap();
        let signing_key = arkret_signatures::development_signing_key(
            request.signature.verification_method.as_str(),
        );
        request.signature.jws = arkret_signatures::jws::sign_jws_ed25519(
            &request.signature_binding_bytes().unwrap(),
            &signing_key,
        )
        .unwrap();

        let error = verify_mimi_consent_actor_proof(&state, &request)
            .await
            .expect_err("a different Station authority must fail closed");

        assert_eq!(error.code, ErrorCode::ParamInvalid);
        assert_eq!(error.wire_code_override.as_deref(), Some("invalid_proof"));
    }

    #[tokio::test]
    async fn consent_actor_proof_rejects_wrong_device() {
        let state = state();
        let mut request = request(&state);
        install_authorized_actor_device(&state, &request).await;
        request.signature.verification_method = arkret_wire::DidUrl::new(
            "did:web:mimi-proof-test.invalid#ak:device:01964137-0000-7000-8000-000000000778"
                .to_owned(),
        )
        .unwrap();

        let error = verify_mimi_consent_actor_proof(&state, &request)
            .await
            .expect_err("an unaccepted device must fail closed");

        assert_eq!(error.code, ErrorCode::ParamInvalid);
        assert_eq!(error.wire_code_override.as_deref(), Some("invalid_proof"));
    }

    #[tokio::test]
    async fn consent_actor_proof_rejects_decision_carrier_mismatch() {
        let state = state();
        let mut request = request(&state);
        request.decision = MimiConsentDecision::Revoke;

        let error = verify_mimi_consent_actor_proof(&state, &request)
            .await
            .expect_err("tampered body must fail");

        assert_eq!(error.code, ErrorCode::ParamInvalid);
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

        assert_eq!(error.code, ErrorCode::ParamInvalid);
        assert_eq!(error.wire_code_override.as_deref(), Some("invalid_proof"));
    }

    #[tokio::test]
    async fn consent_correlation_binds_target_peer_and_scope() {
        let state = state();
        let request = request(&state);
        install_correlation(
            &state,
            &request,
            request.actor_id.signing_principal_id().as_str(),
        )
        .await;

        verify_mimi_consent_correlation(&state, &request, None)
            .await
            .expect("matching private correlation");

        let mut mismatched = request.clone();
        mismatched
            .consent_event
            .event
            .payload
            .insert("peer".to_owned(), json!("did:web:other-peer-test.invalid"));
        let error = verify_mimi_consent_correlation(&state, &mismatched, None)
            .await
            .expect_err("mismatched private correlation must fail closed");
        assert_eq!(error.code, ErrorCode::NotFound);
    }

    #[tokio::test]
    async fn unknown_and_invisible_consent_correlations_are_indistinguishable() {
        let state = state();
        let request = request(&state);
        install_correlation(&state, &request, "did:web:another-holder.invalid").await;

        let invisible = verify_mimi_consent_correlation(&state, &request, None)
            .await
            .expect_err("another holder's correlation must be unavailable");

        let mut unknown = request.clone();
        unknown.consent_id =
            ConsentId::new("ak:consent:01964137-0000-7000-8000-000000000778".to_owned()).unwrap();
        let unknown = verify_mimi_consent_correlation(&state, &unknown, None)
            .await
            .expect_err("unknown correlation must be unavailable");

        assert_eq!(invisible.code, ErrorCode::NotFound);
        assert_eq!(unknown.code, invisible.code);
        assert_eq!(unknown.message, invisible.message);
    }

    /// A `did:key` originator. `did:key` documents are self-describing, so the
    /// production DID-controlled verification path resolves them without any
    /// deployment-local device or account state.
    fn did_key_originator(
        seed: &str,
    ) -> (ed25519_dalek::SigningKey, DidCoreId, arkret_wire::DidUrl) {
        let signing_key = arkret_signatures::development_signing_key(seed);
        let multibase = arkret_canonical::ed25519_pubkey_to_did_key_multibase(
            signing_key.verifying_key().as_bytes(),
        );
        let core_id = DidCoreId::new(format!("ak:did_core:key:{multibase}")).unwrap();
        let method = arkret_wire::DidUrl::new(format!("did:key:{multibase}#{multibase}")).unwrap();
        (signing_key, core_id, method)
    }

    fn unsigned_request_proof(state: &AppState, method: &arkret_wire::DidUrl) -> PayloadProof {
        PayloadProof {
            kind: proof_kind::DETACHED_JWS.to_owned(),
            verification_method: method.clone(),
            payload_digest: Hash::new(format!("sha256:{}", "0".repeat(64))).unwrap(),
            created_at: now(),
            domain: Some(state.config().trust_domain.to_string()),
            audience: Some(Audience::Single(state.service_id().to_owned())),
            proof_purpose: None,
            jws: "pending".to_owned(),
        }
    }

    fn fixture_strand_id() -> StrandId {
        let event_id =
            EventId::new("ak:event:AY_KsmK6yLixEOrtHaJQKVPxqvToAwftLv3kDhf3WwDk".to_owned())
                .unwrap();
        StrandId::from_event_id(&event_id)
    }

    fn key_material_request(
        state: &AppState,
        requester_id: &DidCoreId,
        method: &arkret_wire::DidUrl,
    ) -> MimiKeyMaterialRequestBody {
        MimiKeyMaterialRequestBody {
            requester_id: requester_id.clone(),
            strand_id: fixture_strand_id(),
            device_id: DeviceId::new("ak:device:01964137-0000-7000-8000-000000000901".to_owned())
                .unwrap(),
            mimi_room_uri: None,
            realm_id: None,
            mls_group_id: None,
            epoch: None,
            proofs: vec![unsigned_request_proof(state, method)],
        }
    }

    fn signed_key_material_request(
        state: &AppState,
        requester_id: &DidCoreId,
        method: &arkret_wire::DidUrl,
        signing_key: &ed25519_dalek::SigningKey,
    ) -> MimiKeyMaterialRequestBody {
        let mut body = key_material_request(state, requester_id, method);
        body.proofs[0].payload_digest = body.payload_digest().unwrap();
        let proof = body.proofs[0].clone();
        let binding = body.proof_binding_bytes(&proof).unwrap();
        body.proofs[0].jws =
            arkret_signatures::jws::sign_jws_ed25519(&binding, signing_key).unwrap();
        body
    }

    fn request_consent_request(
        state: &AppState,
        requester_id: &DidCoreId,
        method: &arkret_wire::DidUrl,
    ) -> MimiRequestConsentRequestBody {
        MimiRequestConsentRequestBody {
            requester_id: requester_id.clone(),
            target: MimiConsentTarget {
                kind: MimiConsentTargetKind::Did,
                id: arkret_wire::NonEmptyString::new("did:web:mimi-peer-test.invalid").unwrap(),
            },
            purpose: MimiConsentPurpose::DirectMessage,
            strand_id: None,
            expires_at: None,
            proofs: vec![unsigned_request_proof(state, method)],
        }
    }

    fn signed_request_consent_request(
        state: &AppState,
        requester_id: &DidCoreId,
        method: &arkret_wire::DidUrl,
        signing_key: &ed25519_dalek::SigningKey,
    ) -> MimiRequestConsentRequestBody {
        let mut body = request_consent_request(state, requester_id, method);
        body.proofs[0].payload_digest = body.payload_digest().unwrap();
        let proof = body.proofs[0].clone();
        let binding = body.proof_binding_bytes(&proof).unwrap();
        body.proofs[0].jws =
            arkret_signatures::jws::sign_jws_ed25519(&binding, signing_key).unwrap();
        body
    }

    fn identifier_query_request(
        state: &AppState,
        requester_id: &DidCoreId,
        method: &arkret_wire::DidUrl,
    ) -> MimiIdentifierQueryRequestBody {
        MimiIdentifierQueryRequestBody {
            identifiers: vec![MimiIdentifier {
                kind: MimiIdentifierKind::Handle,
                identifier_commitment: Hash::new(format!("sha256:{}", "1".repeat(64))).unwrap(),
            }],
            requester_id: Some(requester_id.clone()),
            privacy_profile: None,
            proofs: vec![unsigned_request_proof(state, method)],
        }
    }

    fn signed_identifier_query_request(
        state: &AppState,
        requester_id: &DidCoreId,
        method: &arkret_wire::DidUrl,
        signing_key: &ed25519_dalek::SigningKey,
    ) -> MimiIdentifierQueryRequestBody {
        let mut body = identifier_query_request(state, requester_id, method);
        body.proofs[0].payload_digest = body.payload_digest().unwrap();
        let proof = body.proofs[0].clone();
        let binding = body.proof_binding_bytes(&proof).unwrap();
        body.proofs[0].jws =
            arkret_signatures::jws::sign_jws_ed25519(&binding, signing_key).unwrap();
        body
    }

    fn binding_context(binding: &[u8]) -> String {
        serde_json::from_slice::<Value>(binding)
            .unwrap()
            .get("context")
            .and_then(Value::as_str)
            .expect("MIMI binding transcript carries a context")
            .to_owned()
    }

    fn assert_rejected_proof(error: &AppError) {
        assert_eq!(error.code, ErrorCode::ParamInvalid);
        assert_eq!(error.wire_code_override.as_deref(), Some("invalid_proof"));
    }

    #[tokio::test]
    async fn request_family_proofs_verify_under_their_own_context() {
        let state = state();
        let (signing_key, requester_id, method) =
            did_key_originator("mimi-request-family-positive");

        verify_mimi_key_material_request_proofs(
            &state,
            &signed_key_material_request(&state, &requester_id, &method, &signing_key),
        )
        .await
        .expect("key material request proof");
        verify_mimi_request_consent_proofs(
            &state,
            &signed_request_consent_request(&state, &requester_id, &method, &signing_key),
        )
        .await
        .expect("consent request proof");
        verify_mimi_identifier_query_proofs(
            &state,
            &signed_identifier_query_request(&state, &requester_id, &method, &signing_key),
            requester_id.as_str(),
        )
        .await
        .expect("identifier query proof");
    }

    #[tokio::test]
    async fn request_families_bind_distinct_proof_contexts() {
        let state = state();
        let (signing_key, requester_id, method) = did_key_originator("mimi-context-separation");
        let key_material =
            signed_key_material_request(&state, &requester_id, &method, &signing_key);
        let consent = signed_request_consent_request(&state, &requester_id, &method, &signing_key);
        let query = signed_identifier_query_request(&state, &requester_id, &method, &signing_key);

        let contexts = [
            binding_context(
                &key_material
                    .proof_binding_bytes(&key_material.proofs[0])
                    .unwrap(),
            ),
            binding_context(&consent.proof_binding_bytes(&consent.proofs[0]).unwrap()),
            binding_context(&query.proof_binding_bytes(&query.proofs[0]).unwrap()),
        ];
        let distinct: std::collections::BTreeSet<&String> = contexts.iter().collect();
        assert_eq!(
            distinct.len(),
            contexts.len(),
            "each MIMI request family must sign under its own registered context"
        );
    }

    // Cross-family replay: the transplanted proof keeps the same signer, the
    // same destination binding and the same freshness, and its
    // `payload_digest` is re-pointed at the destination body so the SDK digest
    // check cannot be what rejects it. The only remaining difference is the
    // per-family context baked into the signed transcript.
    #[tokio::test]
    async fn key_material_rejects_a_consent_request_context_proof() {
        let state = state();
        let (signing_key, requester_id, method) = did_key_originator("mimi-cross-family-consent");
        let consent = signed_request_consent_request(&state, &requester_id, &method, &signing_key);

        let mut key_material = key_material_request(&state, &requester_id, &method);
        let mut replayed = consent.proofs[0].clone();
        replayed.payload_digest = key_material.payload_digest().unwrap();
        key_material.proofs = vec![replayed];

        let error = verify_mimi_key_material_request_proofs(&state, &key_material)
            .await
            .expect_err("a consent-request context proof must not verify as key material");
        assert_rejected_proof(&error);
    }

    #[tokio::test]
    async fn request_consent_rejects_an_identifier_query_context_proof() {
        let state = state();
        let (signing_key, requester_id, method) = did_key_originator("mimi-cross-family-query");
        let query = signed_identifier_query_request(&state, &requester_id, &method, &signing_key);

        let mut consent = request_consent_request(&state, &requester_id, &method);
        let mut replayed = query.proofs[0].clone();
        replayed.payload_digest = consent.payload_digest().unwrap();
        consent.proofs = vec![replayed];

        let error = verify_mimi_request_consent_proofs(&state, &consent)
            .await
            .expect_err("an identifier-query context proof must not verify as a consent request");
        assert_rejected_proof(&error);
    }

    #[tokio::test]
    async fn identifier_query_rejects_a_key_material_context_proof() {
        let state = state();
        let (signing_key, requester_id, method) =
            did_key_originator("mimi-cross-family-key-material");
        let key_material =
            signed_key_material_request(&state, &requester_id, &method, &signing_key);

        let mut query = identifier_query_request(&state, &requester_id, &method);
        let mut replayed = key_material.proofs[0].clone();
        replayed.payload_digest = query.payload_digest().unwrap();
        query.proofs = vec![replayed];

        let error = verify_mimi_identifier_query_proofs(&state, &query, requester_id.as_str())
            .await
            .expect_err("a key-material context proof must not verify as an identifier query");
        assert_rejected_proof(&error);
    }

    #[tokio::test]
    async fn key_material_rejects_a_proof_outside_the_replay_window() {
        let state = state();
        let (signing_key, requester_id, method) = did_key_originator("mimi-replay-window");
        let mut body = key_material_request(&state, &requester_id, &method);
        body.proofs[0].created_at =
            now() - Duration::seconds(MIMI_OPERATION_PROOF_WINDOW_SECONDS + 1);
        body.proofs[0].payload_digest = body.payload_digest().unwrap();
        let proof = body.proofs[0].clone();
        let binding = body.proof_binding_bytes(&proof).unwrap();
        body.proofs[0].jws =
            arkret_signatures::jws::sign_jws_ed25519(&binding, &signing_key).unwrap();

        let error = verify_mimi_key_material_request_proofs(&state, &body)
            .await
            .expect_err("a proof older than the replay window must fail closed");
        assert_rejected_proof(&error);
    }

    #[tokio::test]
    async fn request_family_proofs_stay_optional_on_the_wire() {
        let state = state();
        let (_signing_key, requester_id, method) = did_key_originator("mimi-optional-proofs");
        let mut key_material = key_material_request(&state, &requester_id, &method);
        key_material.proofs.clear();
        let mut query = identifier_query_request(&state, &requester_id, &method);
        query.proofs.clear();

        verify_mimi_key_material_request_proofs(&state, &key_material)
            .await
            .expect("key material proofs are serde-default and may be absent");
        verify_mimi_identifier_query_proofs(&state, &query, requester_id.as_str())
            .await
            .expect("identifier query proofs are serde-default and may be absent");
    }

    // Only a typed blob reference takes the in-protocol branch. A string that
    // merely opens with `ak:blob:` is not one and must be judged by the URL /
    // scheme rules, which fail closed on a bare `ak:` scheme.
    #[test]
    fn proxy_download_admits_only_typed_blob_references() {
        let state = state();
        enforce_mimi_proxy_download_egress_policy(
            &state,
            &format!("ak:blob:sha256:{}", "a".repeat(64)),
        )
        .expect("a content-addressed blob reference stays in-protocol");
        enforce_mimi_proxy_download_egress_policy(
            &state,
            "ak:blob:01964137-0000-7000-8000-000000000777",
        )
        .expect("a typed blob metadata id stays in-protocol");
        enforce_mimi_proxy_download_egress_policy(&state, "ak:blob:abc")
            .expect_err("a non-canonical blob payload is not a blob reference");
        enforce_mimi_proxy_download_egress_policy(&state, &format!("sha256:{}", "a".repeat(64)))
            .expect_err("a bare digest carries no kind segment");
    }
}
