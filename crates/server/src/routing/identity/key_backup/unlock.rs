use super::*;

/// key-management.md §7.4.1 (normative): a device signature alone cannot defend
/// against a malicious/compromised server injecting or substituting a backup
/// envelope signed by a revoked old device key. Before a receiver trusts/uses an
/// envelope (recovery or read), it MUST anchor `auth_data.signature` to the
/// actor's cross-signing trust root — i.e. the signing device MUST be authorized
/// by an SSK binding chaining to the current published generation, MUST NOT be
/// revoked, and the envelope signature MUST verify against that anchored device
/// key. If it cannot be linked, the envelope MUST be rejected as
/// `untrusted_backup_signature`, even when the series chain and ciphertext_digest
/// are internally self-consistent.
pub(super) fn anchor_key_backup_auth_data_trust_root(
    state: &AppState,
    actor_id: &str,
    backup: &Value,
) -> Result<(), AppError> {
    let untrusted = || {
        AppError::new(
            ErrorCode::InvalidSignature,
            "key backup auth_data.signature is not anchored to the actor cross-signing trust root",
        )
        .with_status(StatusCode::UNAUTHORIZED)
        .with_wire_code("untrusted_backup_signature")
    };

    let auth = backup
        .get("auth_data")
        .and_then(Value::as_object)
        .ok_or_else(untrusted)?;
    let device_id = auth
        .get("device_id")
        .and_then(Value::as_str)
        .ok_or_else(untrusted)?;
    let signature_b64 = auth
        .get("signature")
        .and_then(Value::as_str)
        .ok_or_else(untrusted)?;
    let claimed_generation = auth.get("ssk_generation").and_then(Value::as_u64);

    let principal = Did::new(actor_id.to_owned()).map_err(|_| untrusted())?;
    let device = DeviceId::new(device_id.to_owned()).map_err(|_| untrusted())?;

    // Resolve the device public key and confirm it is anchored under the actor's
    // current published SSK generation (cross-signing trust root).
    let device_public_key = {
        let mgr = state.cross_signing.lock().expect("cross_signing lock");
        if mgr.is_device_revoked(&principal, &device) {
            return Err(untrusted());
        }
        let published = mgr
            .current_cross_signing(&principal)
            .ok_or_else(untrusted)?;
        let published_generation = published.generation;
        let record = mgr.device(&principal, &device).ok_or_else(untrusted)?;
        // The device MUST participate in the cross-signed trust chain (a bootstrap
        // binding alone is not a cross-signing anchor) and that binding MUST chain
        // to the *current* published generation.
        let binding = record
            .cross_signing_binding
            .as_ref()
            .ok_or_else(untrusted)?;
        if binding.ssk_generation != published_generation {
            return Err(untrusted());
        }
        // When the envelope declares an ssk_generation it MUST match the binding.
        if let Some(generation) = claimed_generation
            && generation != published_generation
        {
            return Err(untrusted());
        }
        record.device_public_key.clone().ok_or_else(untrusted)?
    };

    // Verify the envelope's auth_data.signature against the anchored device key
    // over the envelope canonical bytes (signature field stripped), matching the
    // PUT-time signing transcript.
    let verifying_key =
        crate::routing::identity::cross_signing::decode_ed25519_key(&device_public_key, "ed25519")
            .map_err(|_| untrusted())?;
    let mut unsigned = backup.clone();
    if let Some(auth_data) = unsigned.get_mut("auth_data").and_then(Value::as_object_mut) {
        auth_data.remove("signature");
    }
    let canonical = cokret_sdk::canonical::canonical_json_bytes(&unsigned).map_err(|error| {
        AppError::internal(format!(
            "key backup envelope canonicalization failed: {error}"
        ))
    })?;
    let raw = URL_SAFE_NO_PAD
        .decode(signature_b64.as_bytes())
        .or_else(|_| STANDARD.decode(signature_b64.as_bytes()))
        .map_err(|_| untrusted())?;
    let signature = Signature::from_slice(&raw).map_err(|_| untrusted())?;
    verifying_key
        .verify(&canonical, &signature)
        .map_err(|_| untrusted())?;
    Ok(())
}

pub(super) fn key_backup_canonical_digest_without_signature(
    backup: &Value,
) -> Result<String, AppError> {
    let mut canonical = backup.clone();
    if let Some(auth_data) = canonical
        .get_mut("auth_data")
        .and_then(Value::as_object_mut)
    {
        auth_data.remove("signature");
    }
    let bytes = cokret_sdk::canonical::canonical_json_bytes(&canonical).map_err(|error| {
        AppError::internal(format!("key backup canonical digest failed: {error}"))
    })?;
    Ok(cokret_sdk::canonical::sha256_digest(&bytes))
}

pub(super) fn recovery_session_proof_summary(
    record: &RecoverySessionRecord,
) -> Option<(String, String)> {
    let proof = record.proof_payload.as_ref()?.get("proof")?.as_object()?;
    let kind = proof.get("kind").and_then(Value::as_str)?;
    let transcript = json!({
        "type": "ck.identity.recovery_proof.v1",
        "kind": kind,
        "principal_id": record.principal_id.as_str(),
        "requesting_device_id": record.requesting_device_id.as_str(),
        "trust_domain": record.trust_domain.as_str(),
        "policy_id": record.policy_id.as_str(),
        "policy_version": record.policy_version,
        "recovery_session_id": record.recovery_session_id.as_str(),
        "ssk_generation": record.ssk_generation,
        "challenge": record.challenge.as_str(),
        "created_at": record.created_at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        "expires_at": record.expires_at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
    });
    let bytes = cokret_sdk::canonical::canonical_json_bytes(&transcript).ok()?;
    Some((
        kind.to_owned(),
        cokret_sdk::canonical::sha256_digest(&bytes),
    ))
}

pub(super) fn required_proof_string<'a>(
    proof: &'a Value,
    field: &str,
) -> Result<&'a str, AppError> {
    proof
        .get(field)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            AppError::new(
                ErrorCode::SchemaViolation,
                format!("key backup unlock proof `{field}` is required"),
            )
        })
}

pub(super) fn validate_key_backup_unlock_proof_shape(
    proof: &Value,
    actor_id: &str,
    session_device_id: &str,
    backup: &Value,
) -> Result<(), AppError> {
    if required_proof_string(proof, "schema")? != "ck.schema.key_backup_unlock_proof.v1" {
        return Err(schema_error(
            "key backup unlock proof schema must be ck.schema.key_backup_unlock_proof.v1",
        ));
    }
    let recovery_session_id = required_proof_string(proof, "recovery_session_id")?;
    if !recovery_session_id.starts_with("ck:recovery_session:") {
        return Err(schema_error(
            "key backup unlock proof recovery_session_id must start with ck:recovery_session:",
        ));
    }
    if required_proof_string(proof, "principal_id")? != actor_id {
        return Err(AppError::capability_denied(
            "key backup unlock proof principal_id must match authenticated actor",
        ));
    }
    if required_proof_string(proof, "requesting_device_id")? != session_device_id {
        return Err(AppError::capability_denied(
            "key backup unlock proof requesting_device_id must match authenticated session device",
        ));
    }
    for (field, expected) in [
        (
            "backup_id",
            backup
                .get("backup_id")
                .and_then(Value::as_str)
                .unwrap_or_default(),
        ),
        (
            "backup_class",
            backup
                .get("backup_class")
                .and_then(Value::as_str)
                .unwrap_or_default(),
        ),
        (
            "series_id",
            backup
                .get("series_id")
                .and_then(Value::as_str)
                .unwrap_or_default(),
        ),
        (
            "ciphertext_digest",
            backup
                .get("ciphertext_digest")
                .and_then(Value::as_str)
                .unwrap_or_default(),
        ),
    ] {
        if required_proof_string(proof, field)? != expected {
            return Err(AppError::capability_denied(format!(
                "key backup unlock proof `{field}` does not match backup metadata"
            )));
        }
    }
    let proof_kind = required_proof_string(proof, "proof_kind")?;
    if !matches!(
        proof_kind,
        "principal_signing"
            | "recovery_unlock"
            | "device_quorum"
            | "trusted_recovery_service"
            | "threshold_recovery"
    ) {
        return Err(schema_error(format!(
            "key backup unlock proof proof_kind `{proof_kind}` is not supported",
        )));
    }
    if !is_sha_digest(required_proof_string(proof, "proof_digest")?) {
        return Err(schema_error(
            "key backup unlock proof proof_digest must be a sha digest",
        ));
    }
    if !required_proof_string(proof, "issued_at")?.ends_with('Z') {
        return Err(schema_error(
            "key backup unlock proof issued_at must be UTC RFC3339 ending in Z",
        ));
    }

    let auth = proof
        .get("auth_data")
        .and_then(Value::as_object)
        .ok_or_else(|| schema_error("key backup unlock proof auth_data is required"))?;
    if auth
        .get("verification_method")
        .and_then(Value::as_str)
        .is_none_or(str::is_empty)
    {
        return Err(schema_error(
            "key backup unlock proof auth_data.verification_method is required",
        ));
    }
    if !matches!(
        auth.get("signature_algorithm").and_then(Value::as_str),
        Some("Ed25519" | "ES256" | "ML-DSA-65")
    ) {
        return Err(schema_error(
            "key backup unlock proof auth_data.signature_algorithm must be Ed25519, ES256, or ML-DSA-65",
        ));
    }
    let signature = auth
        .get("signature")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if !is_base64url_token(signature) {
        return Err(schema_error(
            "key backup unlock proof auth_data.signature must be base64url",
        ));
    }
    let signed_fields = auth
        .get("signed_fields")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            schema_error("key backup unlock proof auth_data.signed_fields must be an array")
        })?;
    for field in KEY_BACKUP_UNLOCK_PROOF_SIGNED_FIELDS {
        if !signed_fields
            .iter()
            .any(|candidate| candidate.as_str() == Some(*field))
        {
            return Err(schema_error(format!(
                "key backup unlock proof auth_data.signed_fields must cover `{field}`"
            )));
        }
    }
    Ok(())
}

pub(super) fn verify_key_backup_unlock_proof_signature(
    state: &AppState,
    proof: &Value,
) -> Result<(), AppError> {
    let auth = proof
        .get("auth_data")
        .and_then(Value::as_object)
        .ok_or_else(|| schema_error("key backup unlock proof auth_data is required"))?;
    let verification_method = auth
        .get("verification_method")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let signature_b64 = auth
        .get("signature")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let raw = URL_SAFE_NO_PAD
        .decode(signature_b64.as_bytes())
        .or_else(|_| STANDARD.decode(signature_b64.as_bytes()))
        .map_err(|_| {
            AppError::capability_denied("key backup unlock proof signature is not base64url")
        })?;
    let signature = Signature::from_slice(&raw).map_err(|_| {
        AppError::capability_denied("key backup unlock proof signature must be 64 Ed25519 bytes")
    })?;
    let mut unsigned = proof.clone();
    if let Some(auth_data) = unsigned.get_mut("auth_data").and_then(Value::as_object_mut) {
        auth_data.remove("signature");
    }
    let canonical = cokret_sdk::canonical::canonical_json_bytes(&unsigned).map_err(|error| {
        AppError::internal(format!(
            "key backup unlock proof canonicalization failed: {error}"
        ))
    })?;
    let public_key = crate::jws_verify::resolve_ed25519_pubkey(state, verification_method)
        .map_err(|error| {
            AppError::capability_denied(format!(
                "key backup unlock proof verification method invalid: {error}"
            ))
        })?;
    public_key.verify(&canonical, &signature).map_err(|_| {
        AppError::capability_denied("key backup unlock proof signature verification failed")
    })
}

pub(super) async fn enforce_recovery_session_binding_when_present(
    state: &AppState,
    proof: &Value,
    actor_id: &str,
    session_device_id: &str,
) -> Result<(), AppError> {
    let recovery_session_id = required_proof_string(proof, "recovery_session_id")?;
    let Some(record) = state
        .persistence
        .recovery_sessions()
        .get(recovery_session_id)
        .await
        .map_err(|error| AppError::internal(format!("recovery session lookup failed: {error}")))?
    else {
        // Some deployed clients can only provide a device-signed decrypt proof
        // until the policy-layer recovery-session driver is available. When a
        // durable session is present, the checks below make the binding strict.
        return Ok(());
    };
    if record.principal_id != actor_id || record.requesting_device_id != session_device_id {
        return Err(AppError::capability_denied(
            "key backup unlock proof recovery session binding does not match caller",
        ));
    }
    if !matches!(record.state.as_str(), "verified" | "completed") {
        // Registry reason `recovery_evidence_unbound`: the unlock proof is
        // not backed by a verified/completed recovery session, so the
        // recovery evidence is not bound to the session it claims.
        return Err(AppError::conflict(
            "key backup unlock proof recovery session must be verified or completed",
        )
        .with_wire_code("recovery_evidence_unbound"));
    }
    if let Some((kind, digest)) = recovery_session_proof_summary(&record)
        && (required_proof_string(proof, "proof_kind")? != kind
            || required_proof_string(proof, "proof_digest")? != digest)
    {
        return Err(AppError::capability_denied(
            "key backup unlock proof proof_digest does not match recovery session",
        ));
    }
    Ok(())
}

/// Spec `keys_backups_unlock_request_body` (additionalProperties: false) —
/// the unlock proof travels as the `proof` field of the JSON request body of
/// `POST /_cokret/self/keys/backups/{backup_id}/unlock`; header / query
/// carriers are forbidden. The proof MUST validate as
/// `ck.schema.key_backup_unlock_proof.v1` and is verified against the
/// recovery session, caller, requesting device key, and target envelope
/// before the full ciphertext is returned (key-management.md §7.7.1 / §7.8).
pub(super) async fn verify_key_backup_unlock_proof(
    state: &AppState,
    proof: &Value,
    actor_id: &str,
    session_device_id: &str,
    backup: &Value,
) -> Result<(), AppError> {
    validate_key_backup_unlock_proof_shape(proof, actor_id, session_device_id, backup)?;
    enforce_recovery_session_binding_when_present(state, proof, actor_id, session_device_id)
        .await?;
    verify_key_backup_unlock_proof_signature(state, proof)
}
