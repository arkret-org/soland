use super::*;

pub(super) async fn verify_recovery_policy_auth_signature(
    state: &AppState,
    payload: &Value,
    record: &ValidatedRecoveryPolicy,
    session: &SessionRecord,
    existing: Option<&RecoveryPolicyState>,
) -> Result<(), AppError> {
    let primary = verify_recovery_auth_signature(state, payload, &record.principal_id).await;
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
    record: &ValidatedRecoveryPolicy,
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
    record: &ValidatedRecoveryPolicy,
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
    parse_signed_fields(
        auth_data,
        POLICY_ALLOWED_SIGNED_FIELDS,
        POLICY_REQUIRED_SIGNED_FIELDS,
        payload,
    )?;
    let typed: RecoveryPolicy = serde_json::from_value(payload.clone()).map_err(|error| {
        AppError::invalid_param(format!("recovery policy violates SDK shape: {error}"))
            .with_wire_code("schema_violation")
    })?;
    let transcript_bytes = typed
        .signature_transcript_bytes()
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
        .identities()
        .find_device(soland_services::identity::FindDeviceQuery {
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
    crate::routing::identity::device_signing::decode_ed25519_key(material, "multibase")
        .map_err(|error| AppError::internal(format!("session device key invalid: {error}")))
}

pub(super) async fn verify_recovery_auth_signature(
    state: &AppState,
    payload: &Value,
    principal_id: &str,
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

    parse_signed_fields(
        auth_data,
        POLICY_ALLOWED_SIGNED_FIELDS,
        POLICY_REQUIRED_SIGNED_FIELDS,
        payload,
    )?;
    let typed: RecoveryPolicy = serde_json::from_value(payload.clone()).map_err(|error| {
        AppError::invalid_param(format!("recovery policy violates SDK shape: {error}"))
            .with_wire_code("schema_violation")
    })?;
    let transcript_bytes = typed
        .signature_transcript_bytes()
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
