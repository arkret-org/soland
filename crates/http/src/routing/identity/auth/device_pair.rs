use arkret_event_draft::EventPayloadExt as _;
use serde_json::Value;

use super::*;

#[salvo::oapi::endpoint(
    operation_id = "ak.gate.account.command.pair_device",
    summary = "Pair an account device",
    tags("account")
)]
#[tracing::instrument(skip_all, fields(op = "ak.gate.account.command.pair_device.v1"))]
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
    let digest_suite = state
        .projections()
        .realm_digest_suite(body.authorize_event.event.realm_id.as_str());
    body.validate_authorize_event_binding(digest_suite)
        .map_err(|error| {
            AppError::param_invalid(error.to_string()).with_wire_code("schema_violation")
        })?;
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
    let authorized_generation_ref = active_generation
        .as_ref()
        .map(|generation| {
            let authorizer_generation = authorizing_device
                .payload
                .get("authorized_generation_ref")
                .and_then(Value::as_u64);
            if authorizer_generation != Some(generation.current_ref) {
                return Err(AppError::capability_denied(
                    "authorizing device is outside the active device generation",
                )
                .with_wire_code("device_unauthorized"));
            }
            Ok(generation.current_ref)
        })
        .transpose()?;
    let pairing_code = body.pairing_code.as_str().trim();
    if pairing_code.is_empty() {
        return Err(AppError::param_missing("pairing_code is required"));
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
        let exact_authorize_replay = existing.verification_state == "verified"
            && existing
                .payload
                .get("device_authorize_event_id")
                .and_then(Value::as_str)
                == Some(body.authorize_event.event.event_id.as_str());
        if existing.verification_state == "verified" && !exact_authorize_replay {
            return Err(AppError::conflict("device is already authorized")
                .with_wire_code("device_already_authorized"));
        }
    }

    let authorized_at = now();
    let staged_new_device_pubkey = serde_json::to_value(&body.new_device_pubkey)
        .map_err(|error| AppError::param_invalid(format!("new_device_pubkey invalid: {error}")))?;
    let request_id = &body.device_pairing_request_id;
    let record = state
        .device_pairings()
        .get(request_id.as_str())
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
        .ok_or_else(device_pairing_not_found)?;
    if record.state
        != arkret_models_collaboration::http_bodies::DevicePairingState::PendingAuthorization
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
        .map_err(|error| AppError::internal(format!("stored client_nonce invalid: {error}")))?,
        device_pairing_request_id: request_id.clone(),
        expires_at: record.expires_at,
        gate_audience_uri: record.gate_audience,
        pairing_code: body.pairing_code.clone(),
        server_nonce: arkret_models_collaboration::http_bodies::DevicePairingNonce::new(
            record.server_nonce,
        )
        .map_err(|error| AppError::internal(format!("stored server_nonce invalid: {error}")))?,
    };
    arkret_signatures::device_pairing::verify_server_device_pairing_challenge(
        &body.new_device_pubkey,
        &challenge,
        &body.challenge_proof,
        authorized_at,
    )
    .map_err(device_pairing_proof_failed)?;
    let authorize_payload = body
        .authorize_event
        .event
        .typed_payload::<arkret_wire::event_spec::DeviceAuthorize>()
        .map_err(|error| {
            AppError::param_invalid(format!("authorize_event payload invalid: {error}"))
        })?;
    if body
        .authorize_event
        .event
        .actor_id
        .signing_principal_id()
        .as_str()
        != session.actor
        || authorize_payload.device_id.as_str() != device_id
        || authorize_payload.device_public_key_did.as_str() != pair_pubkey.device_public_key
        || !matches!(
            authorize_payload.authorized_by,
            arkret_models_collaboration::events_payloads::DeviceOrPrincipalRef::DeviceId(ref id)
                if id.as_str() == session.device_id
        )
    {
        return Err(AppError::param_invalid(
            "authorize_event does not bind the authenticated authorizer and candidate device",
        )
        .with_wire_code("schema_violation"));
    }
    let target_attestation =
        arkret_models_collaboration::http_bodies::DevicePairingTargetAttestation {
            device_id: authorize_payload.device_id.clone(),
            device_public_key_did: arkret_wire::DidKey::new(
                authorize_payload.device_public_key_did.as_str().to_owned(),
            )
            .map_err(|error| {
                AppError::param_invalid(format!(
                    "authorize_event device_public_key is not a did:key: {error}"
                ))
            })?,
            hpke_key: authorize_payload.hpke_key.clone(),
            algorithms: authorize_payload.algorithms.clone(),
            device_key_algorithm:
                arkret_models_collaboration::http_bodies::DevicePairingTargetKeyAlgorithm::Ed25519,
            authorization_binding_kind:
                arkret_models_collaboration::events_payloads::DeviceAuthorizationBindingKind::AcceptedDevice,
            pairing_challenge_transcript_digest: body.challenge_proof.transcript_digest.clone(),
            device_signature: authorize_payload.device_signature.clone(),
        };
    target_attestation
        .validate_against_pair_request(&body, digest_suite)
        .map_err(|error| {
            AppError::param_invalid(format!(
                "pairing target attestation does not bind the exact authorize Event: {error}"
            ))
            .with_wire_code("schema_violation")
        })?;
    arkret_signatures::device_pairing::verify_device_pairing_target_attestation(
        &target_attestation,
    )
    .map_err(device_pairing_proof_failed)?;
    let authorized_by_actor_id =
        arkret_wire::DidCoreId::new(session.actor.clone()).map_err(|error| {
            AppError::internal(format!("authenticated actor id is invalid: {error}"))
        })?;
    let pairing_commit = Some(soland_services::events::CommitDevicePairingAuthorization {
        device_pairing_request_id: body.device_pairing_request_id.to_string(),
        pairing_code: pairing_code.to_owned(),
        new_device_pubkey: body.new_device_pubkey.clone(),
        device_id: device_id.clone(),
        authorized_by_actor_id,
        authorized_event_ref: body.authorize_event.event.event_id.to_string(),
        changed_at: authorized_at,
    });
    let submitted =
        crate::routing::events::event_log::submit_initial_event_submission_with_device_pairing(
            state,
            session,
            body.authorize_event.clone(),
            crate::routing::events::event_log::DevicePairingAdmission {
                commit_authorization: pairing_commit,
            },
        )
        .await
        .map_err(|error| {
            crate::routing::events::event_log::submit_one_error_to_app_error(
                "ak.gate.account.command.pair_device.v1 authorize Event submit failed",
                error.status(),
                error.code(),
                &error.message(),
            )
        })?;
    let authorized_event_ref = submitted.event_id;
    let projected = state
        .identities()
        .find_device(soland_services::identity::FindDeviceQuery {
            actor_id: session.actor.clone(),
            device_id: device_id.clone(),
        })
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
        .ok_or_else(|| AppError::internal("accepted authorize Event has no device projection"))?;
    if projected.verification_state != "verified"
        || authorized_generation_ref
            != projected
                .payload
                .get("authorized_generation_ref")
                .and_then(Value::as_u64)
    {
        return Err(AppError::internal(
            "accepted authorize Event produced an inconsistent device projection",
        ));
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

    paired_device_outcome(device_id, &authorized_event_ref)
}

fn paired_device_outcome(
    device_id: String,
    authorized_event_ref: &str,
) -> Result<AccountDevicePairOutcome, AppError> {
    Ok(AccountDevicePairOutcome {
        device_id: DeviceId::new(device_id)
            .map_err(|error| AppError::internal(error.to_string()))?,
        authorized_event_ref: EventId::new(authorized_event_ref.to_owned())
            .map_err(|error| AppError::internal(error.to_string()))?,
        device_grant: None,
        key_backup_hint: None,
    })
}

/// `device-lifecycle.md` §5 — only an accepted `ak.device.authorize` can put a
/// device into the authorized set, and §5.1 makes even the founding device go
/// through the PCR genesis unit. A session login therefore never promotes a
/// device: it may only preserve a verification state some accepted
/// authorization already established. Treating "this account has no device
/// yet" as authorization would mint exactly the row §5 calls a projection
/// integrity failure — `verified` with no `device_authorize_event_id` — which
/// every revocation-gate read then has to reject as an internal fault.
pub(crate) fn initial_session_device_verification_state<'a>(
    existing_devices: &'a [soland_services::identity::DeviceIdentity],
    device_id: &str,
) -> &'a str {
    if existing_devices
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
                .with_wire_code("device_unauthorized")
        })?;
    if device.revoked_at.is_some() || device.verification_state != "verified" {
        return Err(
            AppError::capability_denied("authorizing device is not verified")
                .with_wire_code("device_unauthorized"),
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
        .map_err(|_| AppError::param_invalid("new_device_pubkey.kid must be a ak:device id"))
}

fn normalize_pair_device_public_key(public_key: &str) -> Result<String, AppError> {
    let public_key = public_key.trim();
    let bytes = arkret_canonical::base64url_decode(public_key).map_err(|error| {
        AppError::param_invalid(format!(
            "new_device_pubkey.key must be a base64url Ed25519 key: {error}"
        ))
    })?;
    let public_key_bytes: [u8; 32] = bytes.try_into().map_err(|bytes: Vec<u8>| {
        AppError::param_invalid(format!(
            "new_device_pubkey.key decoded to {} bytes, expected 32",
            bytes.len()
        ))
    })?;
    Ok(format!(
        "did:key:{}",
        arkret_canonical::ed25519_pubkey_to_did_key_multibase(&public_key_bytes)
    ))
}

fn device_pairing_not_found() -> AppError {
    AppError::not_found("device pairing request not found")
}

fn device_pairing_proof_failed(
    error: arkret_signatures::device_pairing::DevicePairingProofError,
) -> AppError {
    AppError::from_rejection(
        arkret_wire::ErrorCode::FailedPrecondition,
        "device pairing challenge proof is invalid",
    )
    .with_reason_code(arkret_wire::ReasonCode::PROOF_INVALID)
    .with_private_detail(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pairing_public_key_requires_raw_base64url_and_normalizes_for_directory_storage() {
        let raw = arkret_canonical::base64url_encode([7_u8; 32]);
        let normalized = normalize_pair_device_public_key(&raw).expect("raw Ed25519 key");
        assert_eq!(
            arkret_canonical::decode_ed25519_multibase(
                normalized.strip_prefix("did:key:").unwrap()
            )
            .unwrap(),
            [7_u8; 32]
        );

        let multibase = arkret_canonical::ed25519_pubkey_to_did_key_multibase(&[7_u8; 32]);
        assert!(normalize_pair_device_public_key(&multibase).is_err());
    }

    #[test]
    fn target_attestation_rejects_any_post_signature_preassembly_change() {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[19_u8; 32]);
        let multibase = arkret_canonical::ed25519_pubkey_to_did_key_multibase(
            signing_key.verifying_key().as_bytes(),
        );
        let unsigned =
            arkret_models_collaboration::http_bodies::UnsignedDevicePairingTargetAttestation::new(
                arkret_wire::DeviceId::new("ak:device:01964137-0000-7000-8000-0000000000b2")
                    .unwrap(),
                arkret_wire::DidKey::new(format!("did:key:{multibase}")).unwrap(),
                arkret_wire::NonEmptyString::new("hpke-public-key").unwrap(),
                vec![
                    arkret_wire::NonEmptyString::new(
                        "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
                    )
                    .unwrap(),
                ],
                arkret_wire::Hash::new(format!("sha256:{}", "a".repeat(64))).unwrap(),
            )
            .unwrap();
        let attestation =
            arkret_signatures::device_pairing::sign_device_pairing_target_attestation(
                unsigned,
                &signing_key,
            )
            .unwrap();
        arkret_signatures::device_pairing::verify_device_pairing_target_attestation(&attestation)
            .unwrap();

        let mut changed_hpke = attestation.clone();
        changed_hpke.hpke_key = arkret_wire::NonEmptyString::new("different-hpke-key").unwrap();
        assert!(
            arkret_signatures::device_pairing::verify_device_pairing_target_attestation(
                &changed_hpke
            )
            .is_err()
        );

        let mut changed_challenge = attestation;
        changed_challenge.pairing_challenge_transcript_digest =
            arkret_wire::Hash::new(format!("sha256:{}", "b".repeat(64))).unwrap();
        assert!(
            arkret_signatures::device_pairing::verify_device_pairing_target_attestation(
                &changed_challenge
            )
            .is_err()
        );
    }
}
