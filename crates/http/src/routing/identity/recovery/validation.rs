use super::*;

pub(super) struct ValidatedRecoveryPolicy {
    pub policy_id: String,
    pub principal_id: String,
    pub version: u32,
    pub trust_domain: TrustDomainId,
    pub allowed_proof_kinds: Vec<String>,
    pub supersedes: Option<String>,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    pub issued_at: chrono::DateTime<chrono::Utc>,
    pub raw_payload: Value,
    pub verification_method: String,
}

pub(super) fn validate_recovery_policy(
    payload: &Value,
) -> Result<ValidatedRecoveryPolicy, AppError> {
    let typed: RecoveryPolicy = serde_json::from_value(payload.clone()).map_err(|error| {
        AppError::invalid_param(format!("recovery policy violates SDK shape: {error}"))
            .with_wire_code("schema_violation")
    })?;
    typed.validate().map_err(|error| {
        AppError::invalid_param(format!(
            "recovery policy violates protocol invariants: {error}"
        ))
        .with_wire_code("schema_violation")
    })?;
    require_const_string(payload, "schema", "ak.schema.recovery_policy.v1")?;
    let policy_id = require_string(payload, "policy_id")?;
    require_policy_id_pattern(&policy_id)?;
    let principal_id = typed.principal_id.to_string();
    let version = require_u32_min(payload, "version", 1)?;
    let trust_domain = typed.trust_domain.clone();
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
    if signature_algorithm != "Ed25519" {
        return Err(AppError::invalid_param(format!(
            "auth_data.signature_algorithm `{signature_algorithm}` not in {{Ed25519, Ed25519}}",
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

    Ok(ValidatedRecoveryPolicy {
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
    for optional_signed in [
        "threshold",
        "device_quorum",
        "trusted_recovery_services",
        "recovery_keys",
        "recovery_key_agreements",
        "approval_requirement",
        "audit",
        "not_before",
        "expires_at",
        "outcome_reason_code",
        "device_list_update_event_id",
        "reanchor_event_id",
        "reanchor_batch_receipt_id",
    ] {
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

pub(super) fn recovery_signature_error(message: impl Into<String>) -> AppError {
    AppError::new(ErrorCode::InvalidSignature, message.into())
        .with_status(StatusCode::UNAUTHORIZED)
        .with_wire_code(arkret_wire::ReasonCode::PROOF_INVALID)
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
