use serde_json::Value;

use super::*;

#[salvo::oapi::endpoint(
    operation_id = "ak.gate.account.command.pair_device",
    summary = "Pair an account device",
    tags("account")
)]
#[tracing::instrument(skip_all, fields(op = "ak.gate.account.command.pair_device"))]
pub(super) async fn account_device_pair(
    aa: super::super::AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    body: JsonBody<AccountDevicePairRequestBody>,
) -> JsonResult<AccountDevicePairOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    json_ok(authorize_account_device_pair(state, &session, body.into_inner()).await?)
}

async fn authorize_account_device_pair(
    state: &AppState,
    session: &SessionRecord,
    body: AccountDevicePairRequestBody,
) -> Result<AccountDevicePairOutcome, AppError> {
    let authorizing_device = ensure_authorizing_device_verified(state, session).await?;
    let active_generation = crate::routing::identity::device_generation::current_device_generation(
        state,
        &session.actor,
    )
    .await
    .map_err(|error| AppError::internal(error.to_string()))?
    .filter(|generation| {
        generation.status
            == crate::routing::identity::device_generation::DeviceGenerationStatus::Active
    });
    let generation_projection = active_generation
        .as_ref()
        .map(|generation| {
            let authorizer_generation = authorizing_device
                .payload
                .get("authorized_generation_ref")
                .and_then(Value::as_str);
            if authorizer_generation != Some(generation.current_ref.as_str()) {
                return Err(AppError::capability_denied(
                    "authorizing device is outside the active device generation",
                )
                .with_wire_code("device_not_authorized"));
            }
            let binding = authorizing_device
                .payload
                .get("enrollment_authority_binding")
                .filter(|binding| binding.is_object())
                .cloned()
                .ok_or_else(|| {
                    AppError::capability_denied(
                        "authorizing device has no enrollment authority binding",
                    )
                    .with_wire_code("device_not_authorized")
                })?;
            Ok((generation.current_ref.clone(), binding))
        })
        .transpose()?;
    let pairing_code = body.pairing_code.as_str().trim();
    if pairing_code.is_empty() {
        return Err(AppError::missing_param("pairing_code is required"));
    }
    let pair_pubkey = pair_pubkey_material(&body.new_device_pubkey)?;
    let device_id = pair_pubkey.device_id.clone();
    if device_id == session.device_id {
        return Err(AppError::conflict(
            "new device id must differ from the authorizing session device",
        )
        .with_wire_code("cannot_pair_current_device"));
    }
    if let Some(existing) = state
        .identities()
        .devices_for_actor(&session.actor)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
        .into_iter()
        .find(|device| device.device_id == device_id)
    {
        if existing.revoked_at.is_some() {
            return Err(AppError::conflict("device is revoked").with_wire_code("device_revoked"));
        }
        if existing.verification_state == "verified" {
            return Err(AppError::conflict("device is already authorized")
                .with_wire_code("device_already_authorized"));
        }
    }

    let authorized_at = now();
    let staged_new_device_pubkey = serde_json::to_value(&body.new_device_pubkey)
        .map_err(|error| AppError::invalid_param(format!("new_device_pubkey invalid: {error}")))?;
    match (
        body.device_pairing_request_id.as_ref(),
        body.challenge_transcript.as_ref(),
    ) {
        (Some(request_id), None) => {
            let record = state
                .device_pairings()
                .get(request_id.as_str())
                .await
                .map_err(|error| AppError::internal(error.to_string()))?
                .ok_or_else(device_pairing_not_found)?;
            if record.state != "pending_authorization"
                || record.expires_at <= authorized_at
                || record.pairing_code != pairing_code
                || record.new_device_pubkey != staged_new_device_pubkey
            {
                return Err(device_pairing_not_found());
            }
            let challenge = arkret_signatures::device_pairing::ServerDevicePairingChallenge {
                client_nonce: arkret_models_collaboration::http_bodies::DevicePairingNonce::new(
                    record.client_nonce,
                )
                .map_err(|error| {
                    AppError::internal(format!("stored client_nonce invalid: {error}"))
                })?,
                device_pairing_request_id: request_id.clone(),
                expires_at: record.expires_at,
                gate_audience: record.gate_audience,
                pairing_code: body.pairing_code.clone(),
                server_nonce: arkret_models_collaboration::http_bodies::DevicePairingNonce::new(
                    record.server_nonce,
                )
                .map_err(|error| {
                    AppError::internal(format!("stored server_nonce invalid: {error}"))
                })?,
            };
            arkret_signatures::device_pairing::verify_server_device_pairing_challenge(
                &body.new_device_pubkey,
                &challenge,
                &body.challenge_proof,
                authorized_at,
            )
            .map_err(device_pairing_proof_failed)?;
        }
        (None, Some(challenge)) => {
            let gate_audience = device_pairing_gate_audience(&state.config().public_base_url)?;
            arkret_signatures::device_pairing::verify_to_device_pairing_challenge(
                &body.new_device_pubkey,
                &body.pairing_code,
                &gate_audience,
                challenge,
                &body.challenge_proof,
                authorized_at,
            )
            .map_err(device_pairing_proof_failed)?;
        }
        _ => {
            return Err(AppError::invalid_param(
                "exactly one of device_pairing_request_id or challenge_transcript is required",
            )
            .with_wire_code("schema_violation"));
        }
    }
    let authorized_event_ref = ids::generate_event_id();
    let display_name = body
        .display_name
        .as_deref()
        .or_else(|| {
            body.device_metadata
                .as_ref()
                .and_then(|metadata| metadata.display_name.as_ref())
                .map(arkret_wire::NonEmptyString::as_str)
        })
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned);
    let mut device_payload = json!({
        "device_id": device_id.clone(),
        "device_public_key": pair_pubkey.device_public_key.clone(),
        "device_authorize_projected": true,
        "device_authorize_event_id": authorized_event_ref.clone(),
        "authorization": {
            "event_kind": "ak.device.authorize",
            "authorized_event_ref": authorized_event_ref.clone(),
            "authorized_by_device_id": session.device_id.clone(),
            "authorized_at": authorized_at,
            "pairing_code": pairing_code,
            "challenge_proof": body.challenge_proof,
            "new_device_pubkey": body.new_device_pubkey,
            "device_public_key": pair_pubkey.device_public_key,
            "device_metadata": body.device_metadata,
        }
    });
    if let Some((generation_ref, enrollment_binding)) = generation_projection
        && let Some(payload) = device_payload.as_object_mut()
    {
        payload.insert(
            "authorized_generation_ref".to_owned(),
            Value::String(generation_ref),
        );
        payload.insert(
            "enrollment_authority_binding".to_owned(),
            enrollment_binding,
        );
    }
    let device = soland_services::identity::SaveDeviceCommand {
        actor_id: session.actor.clone(),
        device_id: device_id.clone(),
        display_name: display_name.clone(),
        device: soland_services::identity::DeviceIdentity {
            actor_id: session.actor.clone(),
            device_id: device_id.clone(),
            display_name: display_name.clone(),
            verification_state: "verified".to_owned(),
            payload: device_payload,
            created_at: authorized_at,
            updated_at: authorized_at,
            revoked_at: None,
        },
    };
    if let Some(device_pairing_request_id) = body
        .device_pairing_request_id
        .as_ref()
        .map(|request_id| request_id.as_str())
    {
        let committed = state
            .device_pairings()
            .commit_authorization(
                device_pairing_request_id,
                pairing_code,
                staged_new_device_pubkey,
                device,
                &authorized_event_ref,
                authorized_at,
            )
            .await
            .map_err(|error| AppError::internal(error.to_string()))?;
        if !committed {
            return Err(AppError::not_found("device pairing request not found"));
        }
    } else {
        state
            .identities()
            .save_device(device)
            .await
            .map_err(|error| AppError::internal(error.to_string()))?;
    }
    append_audit_log(
        state,
        Some(&session.actor),
        "account.device_pair",
        json!({
            "device_id": session.device_id.clone(),
            "new_device_id": device_id,
            "authorized_event_ref": authorized_event_ref.clone(),
        }),
        "accepted",
    )
    .await;

    let device_id =
        DeviceId::new(device_id).map_err(|error| AppError::internal(error.to_string()))?;
    let authorized_event_ref = EventId::new(authorized_event_ref)
        .map_err(|error| AppError::internal(error.to_string()))?;
    Ok(AccountDevicePairOutcome {
        device_id,
        authorized_event_ref,
        device_grant: None,
        key_backup_hint: None,
    })
}

pub(crate) fn initial_session_device_verification_state<'a>(
    existing_devices: &'a [soland_services::identity::DeviceIdentity],
    device_id: &str,
) -> &'a str {
    if existing_devices.is_empty()
        || existing_devices
            .iter()
            .any(|device| device.device_id == device_id && device.verification_state == "verified")
    {
        "verified"
    } else {
        "unverified"
    }
}

async fn ensure_authorizing_device_verified(
    state: &AppState,
    session: &SessionRecord,
) -> Result<soland_services::identity::DeviceIdentity, AppError> {
    let device = state
        .identities()
        .find_device(soland_services::identity::FindDeviceQuery {
            actor_id: session.actor.clone(),
            device_id: session.device_id.clone(),
        })
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
        .ok_or_else(|| {
            AppError::capability_denied("authorizing device is not registered")
                .with_wire_code("device_not_authorized")
        })?;
    if device.revoked_at.is_some() || device.verification_state != "verified" {
        return Err(
            AppError::capability_denied("authorizing device is not verified")
                .with_wire_code("device_not_authorized"),
        );
    }
    Ok(device)
}

struct PairPubkeyMaterial {
    device_id: String,
    device_public_key: String,
}

fn pair_pubkey_material(
    new_device_pubkey: &arkret_models_collaboration::governance::agent_artifacts::PublicKey,
) -> Result<PairPubkeyMaterial, AppError> {
    let public_key = new_device_pubkey.key.as_str();
    let device_public_key = normalize_pair_device_public_key(public_key)?;
    let kid = new_device_pubkey.kid.as_str();
    DeviceId::new(kid.to_owned())
        .map(|device_id| PairPubkeyMaterial {
            device_id: device_id.to_string(),
            device_public_key,
        })
        .map_err(|_| AppError::invalid_param("new_device_pubkey.kid must be a ak:device id"))
}

fn normalize_pair_device_public_key(public_key: &str) -> Result<String, AppError> {
    let public_key = public_key.trim();
    let multibase = public_key
        .strip_prefix("did:key:")
        .and_then(|body| body.split('#').next())
        .unwrap_or(public_key);
    if multibase.starts_with('z') {
        arkret_canonical::decode_ed25519_multibase(multibase).map_err(|error| {
            AppError::invalid_param(format!(
                "new_device_pubkey.public_key is not an Ed25519 multibase key: {error}"
            ))
        })?;
        return Ok(multibase.to_owned());
    }

    let bytes = arkret_canonical::base64url_decode(public_key).map_err(|error| {
        AppError::invalid_param(format!(
            "new_device_pubkey.public_key must be Ed25519 multibase or base64url: {error}"
        ))
    })?;
    let public_key_bytes: [u8; 32] = bytes.try_into().map_err(|bytes: Vec<u8>| {
        AppError::invalid_param(format!(
            "new_device_pubkey.public_key decoded to {} bytes, expected 32",
            bytes.len()
        ))
    })?;
    Ok(arkret_canonical::ed25519_pubkey_to_did_key_multibase(
        &public_key_bytes,
    ))
}

fn device_pairing_gate_audience(public_base_url: &str) -> Result<String, AppError> {
    let url = reqwest::Url::parse(public_base_url)
        .map_err(|error| AppError::internal(format!("public_base_url is invalid: {error}")))?;
    let origin = url.origin().ascii_serialization();
    if origin == "null" {
        return Err(AppError::internal(
            "public_base_url has no origin for device pairing",
        ));
    }
    Ok(origin)
}

fn device_pairing_not_found() -> AppError {
    AppError::not_found("device pairing request not found")
}

fn device_pairing_proof_failed(
    error: arkret_signatures::device_pairing::DevicePairingProofError,
) -> AppError {
    AppError::new(
        arkret_wire::ErrorCode::FailedPrecondition,
        "device pairing challenge proof is invalid",
    )
    .with_reason_code("proof_invalid")
    .with_private_detail(error.to_string())
}
