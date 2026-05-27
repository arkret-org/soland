//! CXP-0010 / R3 (REC-1) — recovery policy + recovery receipt endpoints.
//!
//! Mounts the two spec endpoints introduced in contrix-spec b47ff6ec:
//!
//! - `POST /api/v1/identity/recovery-policy`  — persist + advance a recovery policy.
//! - `POST /api/v1/identity/recovery-receipt` — record a recovery receipt for a witnessed session.
//!
//! Wire-level validation lands here (proof_kind enum, recovery_session
//! uuid pattern, expires/policy_version monotonicity,
//! `recovery_witness_revoke_lagging` freshness window). Internal proof
//! cryptographic verification is flagged `TODO(R4)` so the surrounding
//! receipt accounting is wire-discoverable today.

use chrono::SecondsFormat;
use salvo::http::StatusCode;
use salvo::oapi::extract::JsonBody;
use salvo::prelude::*;
use serde_json::{Value, json};

use super::{AuthArgs, append_audit_log};
use crate::error::AppError;
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
    let session = aa.authenticated_session(state, req)?;
    let payload = body.into_inner();

    let record = validate_recovery_policy(&payload)?;
    // Per-principal monotonicity check (spec
    // recovery-policy.schema.json §version: receivers MUST reject a
    // publish whose version is not strictly greater than the currently
    // accepted policy).
    {
        let mut policies = state
            .recovery_policies
            .lock()
            .expect("recovery_policies lock");
        if let Some(existing) = policies.get(&record.principal_id) {
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
        policies.insert(record.principal_id.clone(), record.clone());
    }

    // TODO(R4): persist to the `recovery_session` table (already exists in
    // migrations/20260526030000_agent_personal_provisioning) and emit
    // the canonical `cx.identity.recovery_policy.publish` audit event.

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
    );

    res.status_code(StatusCode::CREATED);
    json_ok(json!({
        "ok": true,
        "policy_id": record.policy_id,
        "principal_id": record.principal_id,
        "version": record.version,
        "accepted_at": chrono::Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
        "todos": [
            "TODO(R4): verify auth_data.signature against principal_id verification key",
            "TODO(R4): persist into recovery_session/recovery_policy durable table",
        ],
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
    let session = aa.authenticated_session(state, req)?;
    let payload = body.into_inner();

    let record = validate_recovery_receipt(&payload)?;

    // Reject duplicate recovery_session_id (spec
    // recovery-receipt.schema.json: receivers MUST reject receipts that
    // reuse a session id already accepted for the same principal).
    {
        let mut receipts = state
            .recovery_receipts
            .lock()
            .expect("recovery_receipts lock");
        if let Some(existing) = receipts.get(&record.recovery_session_id) {
            if existing.principal_id != record.principal_id {
                return Err(AppError::conflict(format!(
                    "recovery_session_id `{}` already bound to principal `{}`",
                    record.recovery_session_id, existing.principal_id
                ))
                .with_wire_code("recovery_session_id_reused"));
            }
            return Err(AppError::conflict(format!(
                "recovery_session_id `{}` already accepted (receipt_id `{}`)",
                record.recovery_session_id, existing.receipt_id
            ))
            .with_wire_code("recovery_session_id_reused"));
        }
        receipts.insert(record.recovery_session_id.clone(), record.clone());
    }

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
    {
        let policies = state
            .recovery_policies
            .lock()
            .expect("recovery_policies lock");
        if let Some(active) = policies.get(&record.principal_id) {
            if active.policy_id != record.policy_id {
                return Err(AppError::conflict(format!(
                    "receipt policy_id `{}` does not match active policy `{}`",
                    record.policy_id, active.policy_id
                ))
                .with_wire_code("recovery_policy_id_mismatch"));
            }
            if active.version != record.policy_version {
                return Err(AppError::conflict(format!(
                    "receipt policy_version {} does not match active version {}",
                    record.policy_version, active.version
                ))
                .with_wire_code("recovery_policy_version_mismatch"));
            }
        }
    }

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
    );

    res.status_code(StatusCode::CREATED);
    json_ok(json!({
        "ok": true,
        "receipt_id": record.receipt_id,
        "principal_id": record.principal_id,
        "recovery_session_id": record.recovery_session_id,
        "outcome": record.outcome,
        "accepted_at": chrono::Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
        "todos": [
            "TODO(R4): verify auth_data.signature + proof_digest binding",
            "TODO(R4): persist into recovery_session durable table + emit audit chain",
        ],
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
            return Err(AppError::invalid_param("expires_at must be null or rfc3339"));
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
    if !matches!(signature_alg, "EdDSA" | "ES256") {
        return Err(AppError::invalid_param(format!(
            "auth_data.signature_alg `{signature_alg}` not in {{EdDSA, ES256}}",
        )));
    }
    auth_data
        .get("signature")
        .and_then(Value::as_str)
        .ok_or_else(|| AppError::invalid_param("auth_data.signature is required"))?;
    // TODO(R4): verify signature with `verification_method`-resolved
    // public key + RFC 8785 JCS canonical bytes over the policy's
    // signed_fields[]. Today we accept the presence of the field.

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
        AppError::invalid_param(
            "recovery_session_id MUST be cx:recovery_session:<uuidv7> per spec",
        )
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
    require_string(payload, "trust_domain")?;
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
    proof_summary
        .get("proof_digest")
        .and_then(Value::as_str)
        .ok_or_else(|| AppError::invalid_param("proof_summary.proof_digest is required"))?;
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
    let _started_at = require_rfc3339(payload, "started_at")?;
    let completed_at = require_rfc3339(payload, "completed_at")?;
    payload
        .get("auth_data")
        .and_then(Value::as_object)
        .ok_or_else(|| AppError::invalid_param("auth_data is required"))?;
    // TODO(R4): verify auth_data signature; see policy validator above.

    Ok(RecoveryReceiptRecord {
        receipt_id,
        principal_id,
        recovery_session_id,
        policy_id,
        policy_version,
        outcome,
        completed_at,
        raw_payload: payload.clone(),
    })
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
