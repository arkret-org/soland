use super::*;

/// §15 step 7 — verify a recovery receipt is signed by the new device's
/// ACCEPTED device key (recorded at `ak.device.authorize`), not the principal
/// signing key or a server key.
pub(super) async fn verify_recovery_receipt_device_signature(
    state: &AppState,
    payload: &Value,
    record: &RecoveryReceiptRecord,
) -> Result<(), AppError> {
    let device_key =
        resolve_authorized_device_key(state, &record.principal_id, &record.new_device_id).await?;

    let auth_data = payload
        .get("auth_data")
        .and_then(Value::as_object)
        .ok_or_else(|| AppError::invalid_param("auth_data is required"))?;
    let signed_fields = parse_signed_fields(
        auth_data,
        RECEIPT_ALLOWED_SIGNED_FIELDS,
        RECEIPT_REQUIRED_SIGNED_FIELDS,
        payload,
    )?;
    let transcript = recovery_signature_transcript(RECEIPT_SIGNATURE_TYPE, payload, &signed_fields);
    let transcript_bytes =
        arkret_core::canonical::canonical_json_bytes(&transcript).map_err(|error| {
            AppError::internal(format!("recovery receipt transcript failed: {error}"))
        })?;
    let signature_b64 = auth_data
        .get("signature")
        .and_then(Value::as_str)
        .ok_or_else(|| AppError::invalid_param("auth_data.signature is required"))?;
    let raw = URL_SAFE_NO_PAD
        .decode(signature_b64.as_bytes())
        .or_else(|_| STANDARD.decode(signature_b64.as_bytes()))
        .map_err(|_| recovery_signature_error("auth_data.signature is not base64/base64url"))?;
    let signature = Signature::from_slice(&raw)
        .map_err(|_| recovery_signature_error("auth_data.signature must be 64 Ed25519 bytes"))?;
    device_key
        .verify(&transcript_bytes, &signature)
        .map_err(|_| {
            crate::metrics::record_digest_mismatch("recovery_receipt_digest");
            recovery_signature_error(
                "recovery receipt signature does not verify against the authorized device key",
            )
        })
}

/// Resolve the Ed25519 public key recorded when `device_id` was authorized for
/// `principal_id` (the device inventory `payload.device_public_key`). Rejects
/// when the device is absent / revoked / unverified / keyless — i.e. no accepted
/// `ak.device.authorize` is on record.
pub(super) async fn resolve_authorized_device_key(
    state: &AppState,
    principal_id: &str,
    device_id: &str,
) -> Result<VerifyingKey, AppError> {
    resolve_authorized_device_key_with_wire_code(
        state,
        principal_id,
        device_id,
        "recovery_receipt_device_not_authorized",
    )
    .await
}

pub(super) async fn resolve_authorized_device_key_with_wire_code(
    state: &AppState,
    principal_id: &str,
    device_id: &str,
    wire_code: &'static str,
) -> Result<VerifyingKey, AppError> {
    let not_authorized = || {
        AppError::conflict(format!(
            "device `{device_id}` has no accepted authorization for principal `{principal_id}`"
        ))
        .with_wire_code(wire_code)
    };
    let device = state
        .identity_application()
        .find_device(soland_application::identity::FindDeviceQuery {
            actor_id: principal_id.to_owned(),
            device_id: device_id.to_owned(),
        })
        .await
        .map_err(|error| AppError::internal(format!("device lookup failed: {error}")))?
        .ok_or_else(not_authorized)?;
    if device.verification_state != "verified" || device.revoked_at.is_some() {
        return Err(not_authorized());
    }
    let material = device
        .payload
        .get("device_public_key")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(not_authorized)?;
    crate::routing::identity::cross_signing::decode_ed25519_key(material, "multibase")
        .map_err(|error| AppError::internal(format!("authorized device key invalid: {error}")))
}

pub(super) async fn verify_recovery_policy_auth_signature(
    state: &AppState,
    payload: &Value,
    record: &RecoveryPolicyRecord,
    session: &SessionRecord,
    existing: Option<&RecoveryPolicyRecord>,
) -> Result<(), AppError> {
    let primary = verify_recovery_auth_signature(
        state,
        payload,
        &record.principal_id,
        POLICY_SIGNATURE_TYPE,
        POLICY_ALLOWED_SIGNED_FIELDS,
        POLICY_REQUIRED_SIGNED_FIELDS,
    )
    .await;
    if primary.is_ok() {
        return primary;
    }

    if existing.is_some() || !recovery_policy_uses_session_device(payload, record, session) {
        return primary;
    }

    verify_recovery_policy_session_device_signature(state, payload, record, session).await
}

pub(super) fn recovery_policy_uses_session_device(
    payload: &Value,
    record: &RecoveryPolicyRecord,
    session: &SessionRecord,
) -> bool {
    let expected = format!("{}#{}", record.principal_id, session.device_id);
    payload
        .get("auth_data")
        .and_then(Value::as_object)
        .and_then(|auth_data| auth_data.get("verification_method"))
        .and_then(Value::as_str)
        .map(str::trim)
        == Some(expected.as_str())
}

pub(super) async fn verify_recovery_policy_session_device_signature(
    state: &AppState,
    payload: &Value,
    record: &RecoveryPolicyRecord,
    session: &SessionRecord,
) -> Result<(), AppError> {
    if session.actor != record.principal_id {
        return Err(AppError::new(
            ErrorCode::CapabilityDenied,
            "session actor does not match recovery policy principal",
        )
        .with_status(StatusCode::FORBIDDEN)
        .with_wire_code("recovery_principal_isolation"));
    }
    let expected_verification_method = format!("{}#{}", record.principal_id, session.device_id);
    let auth_data = payload
        .get("auth_data")
        .and_then(Value::as_object)
        .ok_or_else(|| AppError::invalid_param("auth_data is required"))?;
    let verification_method = auth_data
        .get("verification_method")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| AppError::invalid_param("auth_data.verification_method is required"))?;
    if verification_method != expected_verification_method {
        return Err(recovery_signature_error(format!(
            "genesis recovery policy device signature must use `{expected_verification_method}`"
        )));
    }

    let device_key =
        resolve_session_device_key_for_genesis_policy(state, &record.principal_id, session).await?;
    let signed_fields = parse_signed_fields(
        auth_data,
        POLICY_ALLOWED_SIGNED_FIELDS,
        POLICY_REQUIRED_SIGNED_FIELDS,
        payload,
    )?;
    let transcript = recovery_signature_transcript(POLICY_SIGNATURE_TYPE, payload, &signed_fields);
    let transcript_bytes = arkret_core::canonical::canonical_json_bytes(&transcript)
        .map_err(|error| AppError::internal(format!("recovery transcript failed: {error}")))?;

    let signature_b64 = auth_data
        .get("signature")
        .and_then(Value::as_str)
        .ok_or_else(|| AppError::invalid_param("auth_data.signature is required"))?;
    let raw = URL_SAFE_NO_PAD
        .decode(signature_b64.as_bytes())
        .or_else(|_| STANDARD.decode(signature_b64.as_bytes()))
        .map_err(|_| recovery_signature_error("auth_data.signature is not base64/base64url"))?;
    let signature = Signature::from_slice(&raw)
        .map_err(|_| recovery_signature_error("auth_data.signature must be 64 Ed25519 bytes"))?;
    device_key
        .verify(&transcript_bytes, &signature)
        .map_err(|_| {
            crate::metrics::record_digest_mismatch("recovery_policy_device_digest");
            recovery_signature_error("genesis recovery policy device signature verification failed")
        })
}

pub(super) async fn resolve_session_device_key_for_genesis_policy(
    state: &AppState,
    principal_id: &str,
    session: &SessionRecord,
) -> Result<VerifyingKey, AppError> {
    let not_bound = || {
        AppError::conflict(format!(
            "session device `{}` is not bound to principal `{principal_id}` with a public key",
            session.device_id
        ))
        .with_wire_code("recovery_policy_device_not_authorized")
    };
    let device = state
        .identity_application()
        .find_device(soland_application::identity::FindDeviceQuery {
            actor_id: principal_id.to_owned(),
            device_id: session.device_id.clone(),
        })
        .await
        .map_err(|error| AppError::internal(format!("device lookup failed: {error}")))?
        .ok_or_else(not_bound)?;
    if device.revoked_at.is_some() {
        return Err(not_bound());
    }
    let material = device
        .payload
        .get("device_public_key")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(not_bound)?;
    crate::routing::identity::cross_signing::decode_ed25519_key(material, "multibase")
        .map_err(|error| AppError::internal(format!("session device key invalid: {error}")))
}

pub(super) async fn verify_recovery_auth_signature(
    state: &AppState,
    payload: &Value,
    principal_id: &str,
    transcript_type: &str,
    allowed_fields: &[&str],
    required_fields: &[&str],
) -> Result<(), AppError> {
    let auth_data = payload
        .get("auth_data")
        .and_then(Value::as_object)
        .ok_or_else(|| AppError::invalid_param("auth_data is required"))?;
    let verification_method = auth_data
        .get("verification_method")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| AppError::invalid_param("auth_data.verification_method is required"))?;
    let principal_did = Did::new(principal_id.to_owned())
        .map_err(|error| recovery_signature_error(format!("principal_id DID invalid: {error}")))?;
    // High-risk path: enforce DID document freshness before recovery
    // signature verification (fail-closed-on-stale).
    let resolved_key = crate::jws_verify::resolve_ed25519_verification_key_for_did_fresh(
        state,
        &principal_did,
        verification_method,
    )
    .await
    .map_err(|error| {
        recovery_signature_error(format!("recovery verification key invalid: {error}"))
    })?;

    let signed_fields = parse_signed_fields(auth_data, allowed_fields, required_fields, payload)?;
    let transcript = recovery_signature_transcript(transcript_type, payload, &signed_fields);
    let transcript_bytes = arkret_core::canonical::canonical_json_bytes(&transcript)
        .map_err(|error| AppError::internal(format!("recovery transcript failed: {error}")))?;

    let signature_b64 = auth_data
        .get("signature")
        .and_then(Value::as_str)
        .ok_or_else(|| AppError::invalid_param("auth_data.signature is required"))?;
    let raw = URL_SAFE_NO_PAD
        .decode(signature_b64.as_bytes())
        .or_else(|_| STANDARD.decode(signature_b64.as_bytes()))
        .map_err(|_| recovery_signature_error("auth_data.signature is not base64/base64url"))?;
    let signature = Signature::from_slice(&raw)
        .map_err(|_| recovery_signature_error("auth_data.signature must be 64 Ed25519 bytes"))?;
    resolved_key
        .public_key
        .verify(&transcript_bytes, &signature)
        .map_err(|_| {
            crate::metrics::record_digest_mismatch("recovery_canonical_digest");
            recovery_signature_error("recovery signature verification failed")
        })
}
