//! CXP-0010 / R3 (REC-1) — recovery policy + recovery receipt endpoints.
//!
//! Mounts the two spec endpoints introduced in contrix-spec b47ff6ec:
//!
//! - `POST /api/v1/identity/recovery-policy`  — persist + advance a recovery policy.
//! - `POST /api/v1/identity/recovery-receipt` — record a recovery receipt for a witnessed session.
//!
//! Wire-level validation lands here (proof_kind enum, recovery_session
//! uuid pattern, expires/policy_version monotonicity,
//! `recovery_witness_revoke_lagging` freshness window) plus the REC-1
//! Ed25519 principal signature checks over canonical signed_fields
//! transcripts.

use std::collections::BTreeSet;

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use chrono::SecondsFormat;
use contrix_sdk::Did;
use ed25519_dalek::{Signature, Verifier as _};
use salvo::http::StatusCode;
use salvo::oapi::extract::JsonBody;
use salvo::prelude::*;
use serde_json::{Map, Value, json};

use super::{AuthArgs, append_audit_log};
use crate::error::{AppError, ErrorCode};
use crate::persistence::PersistenceError;
use crate::result::{JsonResult, json_ok};
use crate::state::{AppState, RecoveryPolicyRecord, RecoveryReceiptRecord};

/// Allowed `proof_kind` enum per the spec
/// `recovery-policy.schema.json` / `recovery-receipt.schema.json`.
const ALLOWED_PROOF_KINDS: &[&str] = &[
    "principal_signing",
    "recovery_unlock",
    "device_quorum",
    "trusted_recovery_service",
    "threshold_recovery",
];

/// REC-1 — witness freshness window. A recovery proof carrying a
/// `witness_ref` older than this is rejected with
/// `recovery_witness_revoke_lagging`. The window matches spec
/// `device-lifecycle.md §14.5` (default 24h).
const RECOVERY_WITNESS_FRESHNESS_SECS: i64 = 86_400;

const POLICY_SIGNATURE_TYPE: &str = "cx.identity.recovery_policy.signature.v1";
const RECEIPT_SIGNATURE_TYPE: &str = "cx.identity.recovery_receipt.signature.v1";

const POLICY_ALLOWED_SIGNED_FIELDS: &[&str] = &[
    "schema",
    "policy_id",
    "principal_id",
    "version",
    "trust_domain",
    "allowed_proof_kinds",
    "supersedes",
    "issued_at",
    "expires_at",
];

const POLICY_REQUIRED_SIGNED_FIELDS: &[&str] = POLICY_ALLOWED_SIGNED_FIELDS;

const RECEIPT_ALLOWED_SIGNED_FIELDS: &[&str] = &[
    "schema",
    "receipt_id",
    "principal_id",
    "recovery_session_id",
    "policy_id",
    "policy_version",
    "trust_domain",
    "new_device_id",
    "proof_summary",
    "outcome",
    "outcome_reason_code",
    "started_at",
    "completed_at",
];

const RECEIPT_REQUIRED_SIGNED_FIELDS: &[&str] = &[
    "schema",
    "receipt_id",
    "principal_id",
    "recovery_session_id",
    "policy_id",
    "policy_version",
    "trust_domain",
    "new_device_id",
    "proof_summary",
    "outcome",
    "started_at",
    "completed_at",
];

pub(super) fn router() -> Router {
    Router::with_path("identity")
        .push(Router::with_path("recovery-policy").post(recovery_policy_put))
        .push(Router::with_path("recovery-receipt").post(recovery_receipt_put))
}

#[endpoint(
    operation_id = "cx.identity.recovery_policy.put",
    tags("identity", "recovery"),
    summary = "Submit a cx.schema.recovery_policy.v1 policy (REC-1)",
    status_codes(200, 201, 400, 401, 403, 409, 500)
)]
#[tracing::instrument(skip_all, fields(op = "cx.identity.recovery_policy.put"))]
async fn recovery_policy_put(
    aa: AuthArgs,
    body: JsonBody<Value>,
    depot: &mut Depot,
    res: &mut Response,
    req: &mut Request,
) -> JsonResult<Value> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let payload = body.into_inner();

    let mut record = validate_recovery_policy(&payload)?;
    verify_recovery_auth_signature(
        state,
        &payload,
        &record.principal_id,
        POLICY_SIGNATURE_TYPE,
        POLICY_ALLOWED_SIGNED_FIELDS,
        POLICY_REQUIRED_SIGNED_FIELDS,
    )
    .await?;

    // Per-principal monotonicity check (spec
    // recovery-policy.schema.json §version: receivers MUST reject a
    // publish whose version is not strictly greater than the currently
    // accepted policy).
    if let Some(existing) = state
        .persistence
        .recovery_policies()
        .get_active_for_principal(&record.principal_id)
        .await
        .map_err(recovery_store_error)?
    {
        if record.version <= existing.version {
            return Err(AppError::conflict(format!(
                "policy_version {} is not strictly greater than current {}",
                record.version, existing.version
            ))
            .with_wire_code("recovery_policy_version_not_monotonic"));
        }
        // Schema constraint: when version > 1, supersedes MUST name
        // the predecessor.
        if record.supersedes.as_deref() != Some(existing.policy_id.as_str()) {
            return Err(AppError::conflict(format!(
                "supersedes {:?} does not match current policy_id `{}`",
                record.supersedes, existing.policy_id
            ))
            .with_wire_code("recovery_policy_supersedes_invalid"));
        }
    } else if record.version != 1 {
        return Err(AppError::invalid_param(format!(
            "genesis policy MUST have version=1; got {}",
            record.version
        ))
        .with_wire_code("recovery_policy_genesis_not_v1"));
    }

    let accepted_at = chrono::Utc::now();
    record.accepted_at = accepted_at;
    state
        .persistence
        .recovery_policies()
        .insert(record.clone())
        .await
        .map_err(recovery_policy_store_error)?;

    append_audit_log(
        state,
        Some(&session.actor),
        "cx.identity.recovery_policy.put",
        json!({
            "policy_id": record.policy_id.clone(),
            "principal_id": record.principal_id.clone(),
            "version": record.version,
            "trust_domain": record.trust_domain.clone(),
        }),
        "accepted",
    )
    .await;

    res.status_code(StatusCode::CREATED);
    json_ok(json!({
        "ok": true,
        "policy_id": record.policy_id,
        "principal_id": record.principal_id,
        "version": record.version,
        "accepted_at": accepted_at.to_rfc3339_opts(SecondsFormat::Millis, true),
    }))
}

#[endpoint(
    operation_id = "cx.identity.recovery_receipt.put",
    tags("identity", "recovery"),
    summary = "Record a cx.schema.recovery_receipt.v1 receipt (REC-1)",
    status_codes(200, 201, 400, 401, 403, 409, 500)
)]
#[tracing::instrument(skip_all, fields(op = "cx.identity.recovery_receipt.put"))]
async fn recovery_receipt_put(
    aa: AuthArgs,
    body: JsonBody<Value>,
    depot: &mut Depot,
    res: &mut Response,
    req: &mut Request,
) -> JsonResult<Value> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let payload = body.into_inner();

    let mut record = validate_recovery_receipt(&payload)?;
    verify_recovery_auth_signature(
        state,
        &payload,
        &record.principal_id,
        RECEIPT_SIGNATURE_TYPE,
        RECEIPT_ALLOWED_SIGNED_FIELDS,
        RECEIPT_REQUIRED_SIGNED_FIELDS,
    )
    .await?;

    // REC-1 — recovery_witness_revoke_lagging freshness check on the
    // optional witness ref (when the receipt's proof_summary carries
    // `witness_ref.observed_at`). When the witness observation predates
    // the freshness window, reject with the canonical reason code.
    if let Some(witness_ref) = payload
        .get("proof_summary")
        .and_then(|s| s.get("witness_ref"))
    {
        if let Some(observed_at) = witness_ref
            .get("observed_at")
            .and_then(|v| v.as_str())
            .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        {
            let now = chrono::Utc::now();
            let age_secs = (now - observed_at.with_timezone(&chrono::Utc)).num_seconds();
            if age_secs > RECOVERY_WITNESS_FRESHNESS_SECS {
                return Err(AppError::invalid_param(format!(
                    "witness_ref observed_at is {age_secs}s old (> freshness window \
                     {RECOVERY_WITNESS_FRESHNESS_SECS}s)"
                ))
                .with_wire_code(crate::error::reasons::RECOVERY_WITNESS_REVOKE_LAGGING));
            }
        }
    }

    // Cross-check against the active policy when one is recorded —
    // policy_id + policy_version MUST match the accepted snapshot.
    let active = state
        .persistence
        .recovery_policies()
        .get_active_for_principal(&record.principal_id)
        .await
        .map_err(recovery_store_error)?
        .ok_or_else(|| {
            AppError::conflict(format!(
                "no accepted recovery policy for principal `{}`",
                record.principal_id
            ))
            .with_wire_code("recovery_policy_missing")
        })?;
    if active.policy_id != record.policy_id {
        crate::metrics::record_digest_mismatch("recovery_receipt_policy_binding");
        return Err(AppError::conflict(format!(
            "receipt policy_id `{}` does not match active policy `{}`",
            record.policy_id, active.policy_id
        ))
        .with_wire_code("recovery_policy_id_mismatch"));
    }
    if active.version != record.policy_version {
        crate::metrics::record_digest_mismatch("recovery_receipt_policy_binding");
        return Err(AppError::conflict(format!(
            "receipt policy_version {} does not match active version {}",
            record.policy_version, active.version
        ))
        .with_wire_code("recovery_policy_version_mismatch"));
    }
    if active.trust_domain != record.trust_domain {
        crate::metrics::record_digest_mismatch("recovery_receipt_policy_binding");
        return Err(AppError::conflict(format!(
            "receipt trust_domain `{}` does not match active policy `{}`",
            record.trust_domain, active.trust_domain
        ))
        .with_wire_code("recovery_policy_trust_domain_mismatch"));
    }

    let accepted_at = chrono::Utc::now();
    record.accepted_at = accepted_at;
    state
        .persistence
        .recovery_receipts()
        .insert(record.clone())
        .await
        .map_err(recovery_receipt_store_error)?;

    append_audit_log(
        state,
        Some(&session.actor),
        "cx.identity.recovery_receipt.put",
        json!({
            "receipt_id": record.receipt_id.clone(),
            "principal_id": record.principal_id.clone(),
            "recovery_session_id": record.recovery_session_id.clone(),
            "policy_id": record.policy_id.clone(),
            "outcome": record.outcome.clone(),
        }),
        "accepted",
    )
    .await;

    res.status_code(StatusCode::CREATED);
    json_ok(json!({
        "ok": true,
        "receipt_id": record.receipt_id,
        "principal_id": record.principal_id,
        "recovery_session_id": record.recovery_session_id,
        "outcome": record.outcome,
        "accepted_at": accepted_at.to_rfc3339_opts(SecondsFormat::Millis, true),
    }))
}

fn validate_recovery_policy(payload: &Value) -> Result<RecoveryPolicyRecord, AppError> {
    require_const_string(payload, "schema", "cx.schema.recovery_policy.v1")?;
    let policy_id = require_string(payload, "policy_id")?;
    require_policy_id_pattern(&policy_id)?;
    let principal_id = require_did(payload, "principal_id")?;
    let version = require_u32_min(payload, "version", 1)?;
    let trust_domain = require_string(payload, "trust_domain")?;
    if !trust_domain.starts_with("cx:trust_domain:") {
        return Err(AppError::invalid_param(format!(
            "trust_domain `{trust_domain}` must start with cx:trust_domain:",
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
                "supersedes must be null or a cx:policy:<uuidv7> string",
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
    if let Some(exp) = expires_at {
        if exp <= issued_at {
            return Err(AppError::invalid_param(
                "expires_at MUST be strictly after issued_at",
            ));
        }
    }
    let auth_data = payload
        .get("auth_data")
        .and_then(Value::as_object)
        .ok_or_else(|| AppError::invalid_param("auth_data is required"))?;
    let verification_method = auth_data
        .get("verification_method")
        .and_then(Value::as_str)
        .ok_or_else(|| AppError::invalid_param("auth_data.verification_method is required"))?;
    let signature_alg = auth_data
        .get("signature_alg")
        .and_then(Value::as_str)
        .ok_or_else(|| AppError::invalid_param("auth_data.signature_alg is required"))?;
    if !matches!(signature_alg, "EdDSA" | "Ed25519") {
        return Err(AppError::invalid_param(format!(
            "auth_data.signature_alg `{signature_alg}` not in {{EdDSA, Ed25519}}",
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

fn validate_recovery_receipt(payload: &Value) -> Result<RecoveryReceiptRecord, AppError> {
    require_const_string(payload, "schema", "cx.schema.recovery_receipt.v1")?;
    let receipt_id = require_string(payload, "receipt_id")?;
    if !receipt_id.starts_with("cx:receipt:") {
        return Err(AppError::invalid_param(format!(
            "receipt_id `{receipt_id}` must start with cx:receipt:",
        )));
    }
    let principal_id = require_did(payload, "principal_id")?;
    let recovery_session_id = require_string(payload, "recovery_session_id")?;
    if !recovery_session_id.starts_with("cx:recovery_session:") {
        return Err(AppError::invalid_param(format!(
            "recovery_session_id `{recovery_session_id}` must start with cx:recovery_session:",
        )));
    }
    // UUIDv7 pattern (final 36 chars after the prefix).
    let session_uuid = recovery_session_id
        .strip_prefix("cx:recovery_session:")
        .unwrap_or("");
    let parsed = uuid::Uuid::parse_str(session_uuid).map_err(|_| {
        AppError::invalid_param("recovery_session_id MUST be cx:recovery_session:<uuidv7> per spec")
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
    if !new_device_id.starts_with("cx:device:") {
        return Err(AppError::invalid_param(format!(
            "new_device_id `{new_device_id}` must start with cx:device:",
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
    let auth_data = payload
        .get("auth_data")
        .and_then(Value::as_object)
        .ok_or_else(|| AppError::invalid_param("auth_data is required"))?;
    let verification_method = auth_data
        .get("verification_method")
        .and_then(Value::as_str)
        .ok_or_else(|| AppError::invalid_param("auth_data.verification_method is required"))?;
    let signature_alg = auth_data
        .get("signature_alg")
        .and_then(Value::as_str)
        .ok_or_else(|| AppError::invalid_param("auth_data.signature_alg is required"))?;
    if !matches!(signature_alg, "EdDSA" | "Ed25519") {
        return Err(AppError::invalid_param(format!(
            "auth_data.signature_alg `{signature_alg}` not in {{EdDSA, Ed25519}}",
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

async fn verify_recovery_auth_signature(
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
    let resolved_key = crate::jws_verify::resolve_ed25519_verification_key_for_did(
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
    let transcript_bytes = contrix_sdk::canonical::canonical_json_bytes(&transcript)
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

fn parse_signed_fields(
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

fn recovery_signature_transcript(
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

fn recovery_signature_error(message: impl Into<String>) -> AppError {
    AppError::new(ErrorCode::InvalidSignature, message.into())
        .with_status(StatusCode::UNAUTHORIZED)
        .with_wire_code(crate::error::reasons::PROOF_INVALID)
}

fn recovery_store_error(error: PersistenceError) -> AppError {
    match error {
        PersistenceError::Conflict(message) => AppError::conflict(message),
        PersistenceError::NotFound(message) => AppError::not_found(message),
        PersistenceError::Database(error) => {
            AppError::internal(format!("recovery persistence database error: {error}"))
        }
        PersistenceError::Internal(message) => AppError::internal(message),
    }
}

fn recovery_policy_store_error(error: PersistenceError) -> AppError {
    match error {
        PersistenceError::Conflict(message) if message.contains("principal/version") => {
            AppError::conflict(message).with_wire_code("recovery_policy_version_not_monotonic")
        }
        PersistenceError::Conflict(message) if message.contains("version") => {
            AppError::conflict(message).with_wire_code("recovery_policy_version_not_monotonic")
        }
        PersistenceError::Conflict(message) if message.contains("supersedes") => {
            AppError::conflict(message).with_wire_code("recovery_policy_supersedes_invalid")
        }
        PersistenceError::Conflict(message) => {
            AppError::conflict(message).with_wire_code("recovery_policy_conflict")
        }
        other => recovery_store_error(other),
    }
}

fn recovery_receipt_store_error(error: PersistenceError) -> AppError {
    match error {
        PersistenceError::Conflict(message) if message.contains("recovery_session_id") => {
            AppError::conflict(message).with_wire_code("recovery_session_id_reused")
        }
        PersistenceError::Conflict(message) => {
            AppError::conflict(message).with_wire_code("recovery_receipt_conflict")
        }
        other => recovery_store_error(other),
    }
}

// ── Small helpers ─────────────────────────────────────────────────────

fn require_const_string(payload: &Value, key: &str, expected: &str) -> Result<(), AppError> {
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

fn require_string(payload: &Value, key: &str) -> Result<String, AppError> {
    payload
        .get(key)
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .ok_or_else(|| AppError::invalid_param(format!("{key} is required")))
}

fn require_string_array(payload: &Value, key: &str) -> Result<Vec<String>, AppError> {
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

fn require_u32_min(payload: &Value, key: &str, min: u64) -> Result<u32, AppError> {
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

fn require_did(payload: &Value, key: &str) -> Result<String, AppError> {
    let value = require_string(payload, key)?;
    if !value.starts_with("did:") {
        return Err(AppError::invalid_param(format!(
            "{key} must be a DID (got `{value}`)",
        )));
    }
    Ok(value)
}

fn require_rfc3339(payload: &Value, key: &str) -> Result<chrono::DateTime<chrono::Utc>, AppError> {
    let value = require_string(payload, key)?;
    let parsed = chrono::DateTime::parse_from_rfc3339(&value)
        .map_err(|_| AppError::invalid_param(format!("{key} must be rfc3339")))?;
    Ok(parsed.with_timezone(&chrono::Utc))
}

fn require_policy_id_pattern(value: &str) -> Result<(), AppError> {
    if !value.starts_with("cx:policy:") {
        return Err(AppError::invalid_param(format!(
            "policy_id `{value}` must start with cx:policy:",
        )));
    }
    let uuid_part = value.trim_start_matches("cx:policy:");
    let parsed = uuid::Uuid::parse_str(uuid_part)
        .map_err(|_| AppError::invalid_param("policy_id MUST be cx:policy:<uuidv7>"))?;
    if parsed.get_version_num() != 7 {
        return Err(AppError::invalid_param(
            "policy_id MUST be uuidv7 (version 7)",
        ));
    }
    Ok(())
}
