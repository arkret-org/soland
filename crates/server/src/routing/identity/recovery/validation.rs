use super::*;

pub(super) fn validate_recovery_policy(payload: &Value) -> Result<RecoveryPolicyRecord, AppError> {
    require_const_string(payload, "schema", "ak.schema.recovery_policy.v1")?;
    let policy_id = require_string(payload, "policy_id")?;
    require_policy_id_pattern(&policy_id)?;
    let principal_id = require_did(payload, "principal_id")?;
    let version = require_u32_min(payload, "version", 1)?;
    let trust_domain = require_string(payload, "trust_domain")?;
    if !trust_domain.starts_with("ak:trust_domain:") {
        return Err(AppError::invalid_param(format!(
            "trust_domain `{trust_domain}` must start with ak:trust_domain:",
        )));
    }
    let allowed_proof_kinds = require_string_array(payload, "allowed_proof_kinds")?;
    for kind in &allowed_proof_kinds {
        if !ALLOWED_PROOF_KINDS.contains(&kind.as_str()) {
            return Err(AppError::invalid_param(format!(
                "allowed_proof_kinds entry `{kind}` not in spec enum",
            ))
            .with_wire_code("recovery_proof_kind_unknown"));
        }
    }
    let supersedes = match payload.get("supersedes") {
        Some(Value::Null) | None => None,
        Some(Value::String(s)) => {
            require_policy_id_pattern(s)?;
            Some(s.clone())
        }
        _ => {
            return Err(AppError::invalid_param(
                "supersedes must be null or a ak:policy:<uuidv7> string",
            ));
        }
    };
    if version == 1 && supersedes.is_some() {
        return Err(AppError::invalid_param(
            "genesis policy (version=1) MUST have supersedes=null",
        ));
    }
    if version > 1 && supersedes.is_none() {
        return Err(AppError::invalid_param(
            "non-genesis policy MUST name a predecessor in supersedes",
        ));
    }
    let issued_at = require_rfc3339(payload, "issued_at")?;
    let expires_at = match payload.get("expires_at") {
        Some(Value::Null) | None => None,
        Some(Value::String(s)) => {
            let parsed = chrono::DateTime::parse_from_rfc3339(s)
                .map_err(|_| AppError::invalid_param("expires_at must be rfc3339"))?;
            Some(parsed.with_timezone(&chrono::Utc))
        }
        _ => {
            return Err(AppError::invalid_param(
                "expires_at must be null or rfc3339",
            ));
        }
    };
    if allowed_proof_kinds.is_empty() && expires_at.is_none() {
        return Err(AppError::invalid_param(
            "explicit revocation policy (allowed_proof_kinds=[]) MUST set expires_at",
        ));
    }
    if let Some(exp) = expires_at
        && exp <= issued_at
    {
        return Err(AppError::invalid_param(
            "expires_at MUST be strictly after issued_at",
        ));
    }
    let auth_data = payload
        .get("auth_data")
        .and_then(Value::as_object)
        .ok_or_else(|| AppError::invalid_param("auth_data is required"))?;
    let verification_method = auth_data
        .get("verification_method")
        .and_then(Value::as_str)
        .ok_or_else(|| AppError::invalid_param("auth_data.verification_method is required"))?;
    let signature_algorithm = auth_data
        .get("signature_algorithm")
        .and_then(Value::as_str)
        .ok_or_else(|| AppError::invalid_param("auth_data.signature_algorithm is required"))?;
    if !matches!(signature_algorithm, "EdDSA" | "Ed25519") {
        return Err(AppError::invalid_param(format!(
            "auth_data.signature_algorithm `{signature_algorithm}` not in {{EdDSA, Ed25519}}",
        )));
    }
    auth_data
        .get("signature")
        .and_then(Value::as_str)
        .ok_or_else(|| AppError::invalid_param("auth_data.signature is required"))?;
    auth_data
        .get("signed_fields")
        .and_then(Value::as_array)
        .ok_or_else(|| AppError::invalid_param("auth_data.signed_fields is required"))?;

    Ok(RecoveryPolicyRecord {
        policy_id,
        principal_id,
        version,
        trust_domain,
        allowed_proof_kinds,
        supersedes,
        expires_at,
        issued_at,
        verification_method: verification_method.to_owned(),
        raw_payload: payload.clone(),
        accepted_at: chrono::Utc::now(),
    })
}

pub(super) fn validate_recovery_receipt(
    payload: &Value,
) -> Result<RecoveryReceiptRecord, AppError> {
    require_const_string(payload, "schema", "ak.schema.recovery_receipt.v1")?;
    let receipt_id = require_string(payload, "receipt_id")?;
    if !receipt_id.starts_with("ak:receipt:") {
        return Err(AppError::invalid_param(format!(
            "receipt_id `{receipt_id}` must start with ak:receipt:",
        )));
    }
    let principal_id = require_did(payload, "principal_id")?;
    let recovery_session_id = require_string(payload, "recovery_session_id")?;
    if !recovery_session_id.starts_with("ak:recovery_session:") {
        return Err(AppError::invalid_param(format!(
            "recovery_session_id `{recovery_session_id}` must start with ak:recovery_session:",
        )));
    }
    // UUIDv7 pattern (final 36 chars after the prefix).
    let session_uuid = recovery_session_id
        .strip_prefix("ak:recovery_session:")
        .unwrap_or("");
    let parsed = uuid::Uuid::parse_str(session_uuid).map_err(|_| {
        AppError::invalid_param("recovery_session_id MUST be ak:recovery_session:<uuidv7> per spec")
            .with_wire_code(crate::error::reasons::CURSOR_INTEGRITY_INVALID)
    })?;
    if parsed.get_version_num() != 7 {
        return Err(AppError::invalid_param(
            "recovery_session_id MUST be uuidv7 (version 7)",
        ));
    }
    let policy_id = require_string(payload, "policy_id")?;
    require_policy_id_pattern(&policy_id)?;
    let policy_version = require_u32_min(payload, "policy_version", 1)?;
    let trust_domain = require_string(payload, "trust_domain")?;
    let new_device_id = require_string(payload, "new_device_id")?;
    if !new_device_id.starts_with("ak:device:") {
        return Err(AppError::invalid_param(format!(
            "new_device_id `{new_device_id}` must start with ak:device:",
        )));
    }
    let proof_summary = payload
        .get("proof_summary")
        .and_then(Value::as_object)
        .ok_or_else(|| AppError::invalid_param("proof_summary is required"))?;
    let proof_kind = proof_summary
        .get("kind")
        .and_then(Value::as_str)
        .ok_or_else(|| AppError::invalid_param("proof_summary.kind is required"))?;
    if !ALLOWED_PROOF_KINDS.contains(&proof_kind) {
        return Err(AppError::invalid_param(format!(
            "proof_summary.kind `{proof_kind}` not in spec enum",
        ))
        .with_wire_code("recovery_proof_kind_unknown"));
    }
    let proof_digest = proof_summary
        .get("proof_digest")
        .and_then(Value::as_str)
        .ok_or_else(|| AppError::invalid_param("proof_summary.proof_digest is required"))?
        .to_owned();
    // recovery-receipt.schema.json conditional reqs: threshold_recovery binds
    // quorum_size + share_ids; device_quorum binds quorum_size.
    if matches!(proof_kind, "threshold_recovery" | "device_quorum")
        && proof_summary
            .get("quorum_size")
            .and_then(Value::as_u64)
            .is_none()
    {
        return Err(AppError::invalid_param(format!(
            "proof_summary.quorum_size is required for kind `{proof_kind}`",
        )));
    }
    if proof_kind == "threshold_recovery"
        && proof_summary
            .get("share_ids")
            .and_then(Value::as_array)
            .is_none_or(|a| a.is_empty())
    {
        return Err(AppError::invalid_param(
            "proof_summary.share_ids is required (non-empty) for threshold_recovery",
        ));
    }
    let outcome = require_string(payload, "outcome")?;
    if !matches!(
        outcome.as_str(),
        "completed"
            | "partial"
            | "aborted_by_user"
            | "policy_denied"
            | "evidence_insufficient"
            | "service_defined"
    ) {
        return Err(AppError::invalid_param(format!(
            "outcome `{outcome}` not in spec enum",
        )));
    }
    if outcome != "completed" && payload.get("outcome_reason_code").is_none() {
        return Err(AppError::invalid_param(format!(
            "outcome `{outcome}` requires outcome_reason_code",
        )));
    }
    let started_at = require_rfc3339(payload, "started_at")?;
    let completed_at = require_rfc3339(payload, "completed_at")?;
    if completed_at < started_at {
        return Err(AppError::invalid_param(
            "completed_at MUST be greater than or equal to started_at",
        ));
    }
    // device-lifecycle.md §15 step 7 — backup_classes_unlocked records every
    // backup class the recovering device decrypted; required (MAY be empty).
    let backup_classes = payload
        .get("backup_classes_unlocked")
        .and_then(Value::as_array)
        .ok_or_else(|| AppError::invalid_param("backup_classes_unlocked is required (array)"))?;
    for entry in backup_classes {
        let obj = entry.as_object().ok_or_else(|| {
            AppError::invalid_param("backup_classes_unlocked entries must be objects")
        })?;
        let class = obj
            .get("backup_class")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                AppError::invalid_param("backup_classes_unlocked[].backup_class is required")
            })?;
        if !matches!(class, "did_recovery" | "secret_storage" | "mls_history") {
            return Err(AppError::invalid_param(format!(
                "backup_classes_unlocked[].backup_class `{class}` not in spec enum",
            )));
        }
        for req in ["backup_id", "series_id", "ciphertext_digest"] {
            if obj.get(req).and_then(Value::as_str).is_none() {
                return Err(AppError::invalid_param(format!(
                    "backup_classes_unlocked[].{req} is required",
                )));
            }
        }
    }
    // welcome_count — number of MLS Welcomes replayed for the recovering device.
    if payload
        .get("welcome_count")
        .and_then(Value::as_u64)
        .is_none()
    {
        return Err(AppError::invalid_param(
            "welcome_count is required (integer >= 0)",
        ));
    }
    let auth_data = payload
        .get("auth_data")
        .and_then(Value::as_object)
        .ok_or_else(|| AppError::invalid_param("auth_data is required"))?;
    let verification_method = auth_data
        .get("verification_method")
        .and_then(Value::as_str)
        .ok_or_else(|| AppError::invalid_param("auth_data.verification_method is required"))?;
    let signature_algorithm = auth_data
        .get("signature_algorithm")
        .and_then(Value::as_str)
        .ok_or_else(|| AppError::invalid_param("auth_data.signature_algorithm is required"))?;
    // recovery-receipt.schema.json auth_data.signature_algorithm enum.
    if !matches!(signature_algorithm, "EdDSA" | "ES256") {
        return Err(AppError::invalid_param(format!(
            "auth_data.signature_algorithm `{signature_algorithm}` not in {{EdDSA, ES256}}",
        )));
    }
    auth_data
        .get("signature")
        .and_then(Value::as_str)
        .ok_or_else(|| AppError::invalid_param("auth_data.signature is required"))?;
    auth_data
        .get("signed_fields")
        .and_then(Value::as_array)
        .ok_or_else(|| AppError::invalid_param("auth_data.signed_fields is required"))?;

    Ok(RecoveryReceiptRecord {
        receipt_id,
        principal_id,
        recovery_session_id,
        policy_id,
        policy_version,
        trust_domain,
        new_device_id,
        proof_digest,
        outcome,
        started_at,
        completed_at,
        raw_payload: payload.clone(),
        verification_method: verification_method.to_owned(),
        accepted_at: chrono::Utc::now(),
    })
}

pub(super) fn parse_signed_fields(
    auth_data: &Map<String, Value>,
    allowed_fields: &[&str],
    required_fields: &[&str],
    payload: &Value,
) -> Result<Vec<String>, AppError> {
    let allowed: BTreeSet<&str> = allowed_fields.iter().copied().collect();
    let required: BTreeSet<&str> = required_fields.iter().copied().collect();
    let mut seen = BTreeSet::new();
    let fields = auth_data
        .get("signed_fields")
        .and_then(Value::as_array)
        .ok_or_else(|| AppError::invalid_param("auth_data.signed_fields is required"))?;
    let mut parsed = Vec::with_capacity(fields.len());
    for field in fields {
        let name = field
            .as_str()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                AppError::invalid_param("auth_data.signed_fields entries must be strings")
            })?;
        if !allowed.contains(name) {
            return Err(recovery_signature_error(format!(
                "auth_data.signed_fields contains unsupported field `{name}`"
            )));
        }
        if !seen.insert(name.to_owned()) {
            return Err(recovery_signature_error(format!(
                "auth_data.signed_fields repeats field `{name}`"
            )));
        }
        parsed.push(name.to_owned());
    }
    for required_field in required {
        if !seen.contains(required_field) {
            return Err(recovery_signature_error(format!(
                "auth_data.signed_fields missing required field `{required_field}`"
            )));
        }
    }
    for optional_signed in ["expires_at", "supersedes", "outcome_reason_code"] {
        if payload.get(optional_signed).is_some()
            && allowed.contains(optional_signed)
            && !seen.contains(optional_signed)
        {
            return Err(recovery_signature_error(format!(
                "auth_data.signed_fields missing present optional field `{optional_signed}`"
            )));
        }
    }
    Ok(parsed)
}

pub(super) fn recovery_signature_transcript(
    transcript_type: &str,
    payload: &Value,
    signed_fields: &[String],
) -> Value {
    let mut signed_payload = Map::new();
    for field in signed_fields {
        signed_payload.insert(
            field.clone(),
            payload.get(field).cloned().unwrap_or(Value::Null),
        );
    }
    json!({
        "type": transcript_type,
        "signed_fields": signed_fields,
        "payload": Value::Object(signed_payload),
    })
}

pub(super) fn recovery_signature_error(message: impl Into<String>) -> AppError {
    AppError::new(ErrorCode::InvalidSignature, message.into())
        .with_status(StatusCode::UNAUTHORIZED)
        .with_wire_code(crate::error::reasons::PROOF_INVALID)
}

/// A recovery proof is not bound to the expected (recovery policy, session,
/// recovery key entry) tuple. Registry-canonical `recovery_evidence_unbound`.
pub(super) fn recovery_evidence_unbound_error(message: impl Into<String>) -> AppError {
    AppError::new(ErrorCode::InvalidSignature, message.into())
        .with_status(StatusCode::UNAUTHORIZED)
        .with_wire_code("recovery_evidence_unbound")
}

// ── Small helpers ─────────────────────────────────────────────────────

pub(super) fn require_const_string(
    payload: &Value,
    key: &str,
    expected: &str,
) -> Result<(), AppError> {
    let value = payload
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| AppError::invalid_param(format!("{key} is required")))?;
    if value != expected {
        return Err(AppError::invalid_param(format!(
            "{key} must be `{expected}` (got `{value}`)"
        )));
    }
    Ok(())
}

pub(super) fn require_string(payload: &Value, key: &str) -> Result<String, AppError> {
    payload
        .get(key)
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .ok_or_else(|| AppError::invalid_param(format!("{key} is required")))
}

pub(super) fn require_string_array(payload: &Value, key: &str) -> Result<Vec<String>, AppError> {
    payload
        .get(key)
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(ToOwned::to_owned))
                .collect()
        })
        .ok_or_else(|| AppError::invalid_param(format!("{key} is required (array)")))
}

pub(super) fn require_u32_min(payload: &Value, key: &str, min: u64) -> Result<u32, AppError> {
    let value = payload
        .get(key)
        .and_then(Value::as_u64)
        .ok_or_else(|| AppError::invalid_param(format!("{key} is required (integer)")))?;
    if value < min {
        return Err(AppError::invalid_param(format!(
            "{key} must be >= {min} (got {value})",
        )));
    }
    if value > u32::MAX as u64 {
        return Err(AppError::invalid_param(format!(
            "{key} must fit in u32 (got {value})",
        )));
    }
    Ok(value as u32)
}

pub(super) fn require_did(payload: &Value, key: &str) -> Result<String, AppError> {
    let value = require_string(payload, key)?;
    if !value.starts_with("did:") {
        return Err(AppError::invalid_param(format!(
            "{key} must be a DID (got `{value}`)",
        )));
    }
    Ok(value)
}

pub(super) fn require_rfc3339(
    payload: &Value,
    key: &str,
) -> Result<chrono::DateTime<chrono::Utc>, AppError> {
    let value = require_string(payload, key)?;
    let parsed = chrono::DateTime::parse_from_rfc3339(&value)
        .map_err(|_| AppError::invalid_param(format!("{key} must be rfc3339")))?;
    Ok(parsed.with_timezone(&chrono::Utc))
}

pub(super) fn require_policy_id_pattern(value: &str) -> Result<(), AppError> {
    if !value.starts_with("ak:policy:") {
        return Err(AppError::invalid_param(format!(
            "policy_id `{value}` must start with ak:policy:",
        )));
    }
    let uuid_part = value.trim_start_matches("ak:policy:");
    let parsed = uuid::Uuid::parse_str(uuid_part)
        .map_err(|_| AppError::invalid_param("policy_id MUST be ak:policy:<uuidv7>"))?;
    if parsed.get_version_num() != 7 {
        return Err(AppError::invalid_param(
            "policy_id MUST be uuidv7 (version 7)",
        ));
    }
    Ok(())
}
