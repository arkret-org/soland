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
use salvo::oapi::extract::{JsonBody, PathParam, QueryParam};
use salvo::prelude::*;
use serde_json::{Map, Value, json};

use super::{AuthArgs, append_audit_log};
use crate::error::{AppError, ErrorCode};
use crate::persistence::PersistenceError;
use crate::result::{JsonResult, json_ok};
use crate::state::{
    AppState, DeviceInventoryRecord, RecoveryPolicyRecord, RecoveryReceiptRecord,
    RecoverySessionRecord,
};

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

/// C-P2 (REC-1) — recovery session lifetime. A freshly created session must be
/// proven + completed within this window; afterwards it is treated as
/// `expired`. Matches the device-lifecycle interactive recovery window.
const RECOVERY_SESSION_TTL_SECS: i64 = 900;

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
        .push(
            Router::with_path("recovery-policy")
                .post(recovery_policy_put)
                .get(recovery_policy_get),
        )
        .push(Router::with_path("recovery-policies").get(recovery_policies_get))
        .push(Router::with_path("recovery-receipt").post(recovery_receipt_put))
        .push(Router::with_path("recovery-receipts").get(recovery_receipts_get))
        .push(
            Router::with_path("recovery-sessions").post(recovery_session_create), // C-P2 (REC-1)
        )
        .push(
            Router::with_path("recovery-sessions/{recovery_session_id}")
                .get(recovery_session_get),
        )
        .push(
            Router::with_path("recovery-sessions/{recovery_session_id}/proofs")
                .post(recovery_session_proof_submit),
        )
        .push(
            Router::with_path("recovery-sessions/{recovery_session_id}/complete")
                .post(recovery_session_complete),
        )
}

/// REC-1 read APIs — resolve the principal to read recovery state for, enforcing
/// principal isolation: a caller may only read its OWN recovery state. The
/// principal is the authenticated actor; an optional `?principal_id=` query MUST
/// match it (else 403).
async fn resolve_recovery_read_principal(
    aa: &AuthArgs,
    state: &AppState,
    req: &mut Request,
    principal_id_param: Option<String>,
) -> Result<String, AppError> {
    let session = aa.authenticated_session(state, req).await?;
    let principal = session.actor;
    if let Some(requested) = principal_id_param.filter(|p| !p.trim().is_empty())
        && requested != principal
    {
        return Err(AppError::new(
            ErrorCode::CapabilityDenied,
            "principal_id does not match the authenticated principal",
        )
        .with_status(StatusCode::FORBIDDEN)
        .with_wire_code("recovery_principal_isolation"));
    }
    Ok(principal)
}

fn recovery_policy_summary(record: &RecoveryPolicyRecord) -> Value {
    json!({
        "policy_id": record.policy_id,
        "principal_id": record.principal_id,
        "version": record.version,
        "trust_domain": record.trust_domain,
        "allowed_proof_kinds": record.allowed_proof_kinds,
        "supersedes": record.supersedes,
        "expires_at": record.expires_at,
        "issued_at": record.issued_at,
        "accepted_at": record.accepted_at,
        "policy": record.raw_payload,
    })
}

#[endpoint(
    operation_id = "cx.extension.soland.identity.recovery_policy.get",
    tags("identity", "recovery"),
    summary = "Read the currently accepted recovery policy (REC-1)",
    status_codes(200, 401, 403, 500)
)]
#[tracing::instrument(skip_all, fields(op = "cx.extension.soland.identity.recovery_policy.get"))]
async fn recovery_policy_get(
    aa: AuthArgs,
    principal_id: QueryParam<String, false>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<Value> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let principal =
        resolve_recovery_read_principal(&aa, state, req, principal_id.into_inner()).await?;
    let active = state
        .persistence
        .recovery_policies()
        .get_active_for_principal(&principal)
        .await
        .map_err(recovery_store_error)?;
    json_ok(json!({ "active_policy": active.as_ref().map(recovery_policy_summary) }))
}

#[endpoint(
    operation_id = "cx.extension.soland.identity.recovery_policies.get",
    tags("identity", "recovery"),
    summary = "List recovery policy history newest-first (REC-1)",
    status_codes(200, 401, 403, 500)
)]
#[tracing::instrument(skip_all, fields(op = "cx.extension.soland.identity.recovery_policies.get"))]
async fn recovery_policies_get(
    aa: AuthArgs,
    principal_id: QueryParam<String, false>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<Value> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let principal =
        resolve_recovery_read_principal(&aa, state, req, principal_id.into_inner()).await?;
    let policies = state
        .persistence
        .recovery_policies()
        .list_for_principal(&principal)
        .await
        .map_err(recovery_store_error)?;
    let items: Vec<Value> = policies.iter().map(recovery_policy_summary).collect();
    json_ok(json!({ "policies": items }))
}

#[endpoint(
    operation_id = "cx.extension.soland.identity.recovery_receipts.get",
    tags("identity", "recovery"),
    summary = "List recovery receipt history newest-first (REC-1)",
    status_codes(200, 401, 403, 500)
)]
#[tracing::instrument(skip_all, fields(op = "cx.extension.soland.identity.recovery_receipts.get"))]
async fn recovery_receipts_get(
    aa: AuthArgs,
    principal_id: QueryParam<String, false>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<Value> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let principal =
        resolve_recovery_read_principal(&aa, state, req, principal_id.into_inner()).await?;
    let receipts = state
        .persistence
        .recovery_receipts()
        .list_for_principal(&principal)
        .await
        .map_err(recovery_store_error)?;
    let items: Vec<Value> = receipts
        .iter()
        .map(|r| {
            json!({
                "receipt_id": r.receipt_id,
                "recovery_session_id": r.recovery_session_id,
                "policy_id": r.policy_id,
                "policy_version": r.policy_version,
                "trust_domain": r.trust_domain,
                "new_device_id": r.new_device_id,
                "outcome": r.outcome,
                "completed_at": r.completed_at,
                "accepted_at": r.accepted_at,
                "receipt": r.raw_payload,
            })
        })
        .collect();
    json_ok(json!({ "receipts": items }))
}

// ── C-P2 (REC-1) recovery session lifecycle ──────────────────────────────
//
// A recovery session binds a *requesting device* to the principal's currently
// accepted recovery policy snapshot + a server-issued anti-replay challenge,
// and advances `pending -> verified -> completed` (or `rejected` / `expired`).
//
//   POST recovery-sessions                  — create (snapshot policy + challenge)
//   GET  recovery-sessions/{id}             — read status (principal-isolated)
//   POST recovery-sessions/{id}/proofs      — verify a proof (pending -> verified)
//   POST recovery-sessions/{id}/complete    — finalize (only when state == verified)
//
// C-P3 — `/proofs` verifies the `principal_signing` kind cryptographically
// (Ed25519 over the canonical recovery-proof transcript binding every
// session-defining field) and advances `pending -> verified` ONLY on success.
// Other policy-permitted proof kinds return 501 `recovery_proof_kind_unimplemented`
// rather than silently leaving the session pending.
//
// C-P4 — completion emission of a `cx.device.authorize` + receipt is NOT yet
// implemented: `/complete` rejects a non-`verified` session with 409
// `recovery_session_not_verified`, and a `verified` session with 501
// `recovery_completion_unimplemented`. The server never fakes a completed state.

fn recovery_session_summary(record: &RecoverySessionRecord) -> Value {
    json!({
        "recovery_session_id": record.recovery_session_id,
        "principal_id": record.principal_id,
        "requesting_device_id": record.requesting_device_id,
        "trust_domain": record.trust_domain,
        "policy_id": record.policy_id,
        "policy_version": record.policy_version,
        "state": record.state,
        "challenge": record.challenge,
        "created_at": record.created_at.to_rfc3339_opts(SecondsFormat::Millis, true),
        "updated_at": record.updated_at.to_rfc3339_opts(SecondsFormat::Millis, true),
        "expires_at": record.expires_at.to_rfc3339_opts(SecondsFormat::Millis, true),
    })
}

/// Load a session and enforce principal isolation: only the authenticated
/// principal (== `session.actor`) may read or act on its own recovery sessions.
async fn load_owned_recovery_session(
    aa: &AuthArgs,
    state: &AppState,
    req: &mut Request,
    recovery_session_id: &str,
) -> Result<RecoverySessionRecord, AppError> {
    let session = aa.authenticated_session(state, req).await?;
    let principal = session.actor;
    let record = state
        .persistence
        .recovery_sessions()
        .get(recovery_session_id)
        .await
        .map_err(recovery_store_error)?
        .ok_or_else(|| {
            AppError::not_found(format!(
                "recovery session `{recovery_session_id}` not found"
            ))
        })?;
    if record.principal_id != principal {
        return Err(AppError::new(
            ErrorCode::CapabilityDenied,
            "recovery session belongs to a different principal",
        )
        .with_status(StatusCode::FORBIDDEN)
        .with_wire_code("recovery_principal_isolation"));
    }
    Ok(record)
}

#[endpoint(
    operation_id = "cx.extension.soland.identity.recovery_session.create",
    tags("identity", "recovery"),
    summary = "Open a recovery session bound to the active policy (REC-1)",
    status_codes(200, 201, 400, 401, 403, 409, 500)
)]
#[tracing::instrument(skip_all, fields(op = "cx.extension.soland.identity.recovery_session.create"))]
async fn recovery_session_create(
    aa: AuthArgs,
    body: JsonBody<Value>,
    depot: &mut Depot,
    res: &mut Response,
    req: &mut Request,
) -> JsonResult<Value> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let principal = session.actor.clone();
    let payload = body.into_inner();

    let requesting_device_id = require_string(&payload, "requesting_device_id")?;
    if !requesting_device_id.starts_with("cx:device:") {
        return Err(AppError::invalid_param(format!(
            "requesting_device_id `{requesting_device_id}` must start with cx:device:",
        )));
    }
    let trust_domain = require_string(&payload, "trust_domain")?;
    if !trust_domain.starts_with("cx:trust_domain:") {
        return Err(AppError::invalid_param(format!(
            "trust_domain `{trust_domain}` must start with cx:trust_domain:",
        )));
    }

    // A session can only be opened against an accepted recovery policy — and the
    // requested trust_domain MUST match it (no domain confusion).
    let active = state
        .persistence
        .recovery_policies()
        .get_active_for_principal(&principal)
        .await
        .map_err(recovery_store_error)?
        .ok_or_else(|| {
            AppError::conflict(format!(
                "no accepted recovery policy for principal `{principal}`"
            ))
            .with_wire_code("recovery_policy_missing")
        })?;
    if active.trust_domain != trust_domain {
        return Err(AppError::conflict(format!(
            "trust_domain `{trust_domain}` does not match active policy `{}`",
            active.trust_domain
        ))
        .with_wire_code("recovery_policy_trust_domain_mismatch"));
    }
    if active.allowed_proof_kinds.is_empty() {
        // An explicit-revocation policy (allowed_proof_kinds == []) cannot back a
        // recovery session — there is no proof the requester could ever satisfy.
        return Err(AppError::conflict(format!(
            "active recovery policy `{}` permits no proof kinds (recovery disabled)",
            active.policy_id
        ))
        .with_wire_code("recovery_policy_revoked"));
    }

    let now = chrono::Utc::now();
    let record = RecoverySessionRecord {
        recovery_session_id: crate::ids::generate("recovery_session"),
        principal_id: principal.clone(),
        requesting_device_id,
        trust_domain,
        policy_id: active.policy_id.clone(),
        policy_version: active.version,
        policy_payload: active.raw_payload.clone(),
        challenge: generate_recovery_challenge(),
        state: "pending".to_owned(),
        proof_payload: None,
        created_at: now,
        updated_at: now,
        expires_at: now + chrono::Duration::seconds(RECOVERY_SESSION_TTL_SECS),
    };
    state
        .persistence
        .recovery_sessions()
        .insert(record.clone())
        .await
        .map_err(recovery_session_store_error)?;

    append_audit_log(
        state,
        Some(&session.actor),
        "cx.extension.soland.identity.recovery_session.create",
        json!({
            "recovery_session_id": record.recovery_session_id.clone(),
            "principal_id": record.principal_id.clone(),
            "policy_id": record.policy_id.clone(),
            "trust_domain": record.trust_domain.clone(),
        }),
        "created",
    )
    .await;

    res.status_code(StatusCode::CREATED);
    json_ok(recovery_session_summary(&record))
}

#[endpoint(
    operation_id = "cx.extension.soland.identity.recovery_session.get",
    tags("identity", "recovery"),
    summary = "Read a recovery session status (REC-1)",
    status_codes(200, 401, 403, 404, 500)
)]
#[tracing::instrument(skip_all, fields(op = "cx.extension.soland.identity.recovery_session.get"))]
async fn recovery_session_get(
    aa: AuthArgs,
    recovery_session_id: PathParam<String>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<Value> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let mut record =
        load_owned_recovery_session(&aa, state, req, &recovery_session_id.into_inner()).await?;
    record = expire_if_elapsed(state, record).await?;
    json_ok(recovery_session_summary(&record))
}

#[endpoint(
    operation_id = "cx.extension.soland.identity.recovery_session.proof_submit",
    tags("identity", "recovery"),
    summary = "Submit a recovery proof for a pending session (REC-1)",
    status_codes(200, 400, 401, 403, 404, 409, 500)
)]
#[tracing::instrument(skip_all, fields(op = "cx.extension.soland.identity.recovery_session.proof_submit"))]
async fn recovery_session_proof_submit(
    aa: AuthArgs,
    recovery_session_id: PathParam<String>,
    body: JsonBody<Value>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<Value> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session_id = recovery_session_id.into_inner();
    let record = load_owned_recovery_session(&aa, state, req, &session_id).await?;
    let record = expire_if_elapsed(state, record).await?;
    if record.state != "pending" {
        return Err(AppError::conflict(format!(
            "recovery session is `{}`, proofs accepted only while `pending`",
            record.state
        ))
        .with_wire_code("recovery_session_not_pending"));
    }

    let payload = body.into_inner();
    let proof = payload
        .get("proof")
        .and_then(Value::as_object)
        .ok_or_else(|| AppError::invalid_param("proof object is required"))?;
    let proof_kind = proof
        .get("kind")
        .and_then(Value::as_str)
        .ok_or_else(|| AppError::invalid_param("proof.kind is required"))?;
    if !ALLOWED_PROOF_KINDS.contains(&proof_kind) {
        return Err(AppError::invalid_param(format!(
            "proof.kind `{proof_kind}` not in spec enum",
        ))
        .with_wire_code("recovery_proof_kind_unknown"));
    }
    // The proof kind MUST be one the bound policy snapshot permits.
    let policy_allows = record
        .policy_payload
        .get("allowed_proof_kinds")
        .and_then(Value::as_array)
        .map(|kinds| kinds.iter().any(|k| k.as_str() == Some(proof_kind)))
        .unwrap_or(false);
    if !policy_allows {
        return Err(AppError::conflict(format!(
            "proof.kind `{proof_kind}` is not permitted by the bound recovery policy",
        ))
        .with_wire_code("recovery_proof_kind_not_allowed"));
    }
    // Anti-replay: the proof MUST echo the server-issued session challenge.
    let echoed = proof
        .get("challenge")
        .and_then(Value::as_str)
        .ok_or_else(|| AppError::invalid_param("proof.challenge is required"))?;
    if echoed != record.challenge {
        return Err(AppError::new(
            ErrorCode::InvalidSignature,
            "proof.challenge does not match the session challenge",
        )
        .with_status(StatusCode::CONFLICT)
        .with_wire_code("recovery_session_challenge_mismatch"));
    }

    // C-P3 — verify the proof by kind. Only `principal_signing` is implemented;
    // other (policy-permitted) kinds return 501 rather than silently leaving the
    // session pending, so a caller is never misled into thinking the server
    // accepted a proof it cannot actually check.
    match proof_kind {
        "principal_signing" => {
            verify_principal_signing_proof(state, &record, proof).await?;
        }
        other => {
            return Err(AppError::unsupported_feature(format!(
                "proof.kind `{other}` verification not yet implemented (C-P3)"
            ))
            .with_status(StatusCode::NOT_IMPLEMENTED)
            .with_wire_code("recovery_proof_kind_unimplemented"));
        }
    }

    // Proof verified — advance `pending -> verified` and record the proof. The
    // server only reaches this point after a real cryptographic check.
    let now = chrono::Utc::now();
    let updated = RecoverySessionRecord {
        state: "verified".to_owned(),
        proof_payload: Some(payload.clone()),
        updated_at: now,
        ..record
    };
    state
        .persistence
        .recovery_sessions()
        .update(updated.clone())
        .await
        .map_err(recovery_session_store_error)?;

    json_ok(json!({
        "ok": true,
        "recovery_session_id": updated.recovery_session_id,
        "state": updated.state,
        "verification": "verified",
    }))
}

/// C-P3 — verify a `principal_signing` recovery proof.
///
/// The proof MUST carry an Ed25519 signature by the principal's signing key
/// over the canonical recovery-proof transcript, which binds every
/// session-defining field: `(principal_id, requesting_device_id, trust_domain,
/// policy_id, policy_version, recovery_session_id, challenge, expires_at)`.
/// Because the transcript is reconstructed server-side from the stored session,
/// any proof signed over a different binding (stale policy, replayed across
/// principal/domain, different session) fails verification — this gives the
/// `recovery_evidence_unbound` guarantee for free.
async fn verify_principal_signing_proof(
    state: &AppState,
    record: &RecoverySessionRecord,
    proof: &Map<String, Value>,
) -> Result<(), AppError> {
    let verification_method = proof
        .get("verification_method")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| AppError::invalid_param("proof.verification_method is required"))?;
    let principal_did = Did::new(record.principal_id.clone())
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

    let transcript = recovery_proof_transcript(record, "principal_signing");
    let transcript_bytes = contrix_sdk::canonical::canonical_json_bytes(&transcript)
        .map_err(|error| AppError::internal(format!("recovery proof transcript failed: {error}")))?;

    let signature_b64 = proof
        .get("signature")
        .and_then(Value::as_str)
        .ok_or_else(|| AppError::invalid_param("proof.signature is required"))?;
    let raw = URL_SAFE_NO_PAD
        .decode(signature_b64.as_bytes())
        .or_else(|_| STANDARD.decode(signature_b64.as_bytes()))
        .map_err(|_| recovery_signature_error("proof.signature is not base64/base64url"))?;
    let signature = Signature::from_slice(&raw)
        .map_err(|_| recovery_signature_error("proof.signature must be 64 Ed25519 bytes"))?;
    resolved_key
        .public_key
        .verify(&transcript_bytes, &signature)
        .map_err(|_| {
            crate::metrics::record_digest_mismatch("recovery_proof_digest");
            recovery_signature_error("recovery proof signature verification failed")
        })
}

/// Canonical recovery-proof transcript binding every session-defining field.
/// Both the requesting device (when signing) and the server (when verifying)
/// MUST construct this identically.
fn recovery_proof_transcript(record: &RecoverySessionRecord, kind: &str) -> Value {
    json!({
        "type": "cx.identity.recovery_proof.v1",
        "kind": kind,
        "principal_id": record.principal_id,
        "requesting_device_id": record.requesting_device_id,
        "trust_domain": record.trust_domain,
        "policy_id": record.policy_id,
        "policy_version": record.policy_version,
        "recovery_session_id": record.recovery_session_id,
        "challenge": record.challenge,
        "expires_at": record.expires_at.to_rfc3339_opts(SecondsFormat::Millis, true),
    })
}

#[endpoint(
    operation_id = "cx.extension.soland.identity.recovery_session.complete",
    tags("identity", "recovery"),
    summary = "Finalize a verified recovery session (REC-1)",
    status_codes(200, 401, 403, 404, 409, 500)
)]
#[tracing::instrument(skip_all, fields(op = "cx.extension.soland.identity.recovery_session.complete"))]
async fn recovery_session_complete(
    aa: AuthArgs,
    recovery_session_id: PathParam<String>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<Value> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session_id = recovery_session_id.into_inner();
    let record = load_owned_recovery_session(&aa, state, req, &session_id).await?;
    let record = expire_if_elapsed(state, record).await?;

    // The only path to completion is a `verified` session. Proof verification
    // (C-P3) is what flips `pending -> verified`; until it lands no session can
    // reach `verified`, so this endpoint always rejects rather than fabricating
    // a successful recovery.
    if record.state != "verified" {
        return Err(AppError::conflict(format!(
            "recovery session is `{}`, completion requires `verified`",
            record.state
        ))
        .with_wire_code("recovery_session_not_verified"));
    }

    // C-P4 — the proof was cryptographically verified (C-P3), so authorize the
    // requesting device for the principal. This writes a real, auth-consulted
    // `DeviceInventoryRecord` (verification_state=verified) carrying recovery
    // provenance (session id + policy snapshot + proof summary). We mirror the
    // existing `device_authorize_pairing` convention, including its honest
    // `production_gap` marker: the canonical `cx.device.authorize` operation is
    // not yet appended to the principal control/operation stream. The recovery
    // *receipt* remains the principal-signed `POST recovery-receipt` path.
    let now = chrono::Utc::now();
    let proof_summary = record
        .proof_payload
        .as_ref()
        .and_then(|p| p.get("proof"))
        .and_then(Value::as_object)
        .map(|proof| {
            json!({
                "kind": proof.get("kind").cloned().unwrap_or(Value::Null),
                "verification_method": proof
                    .get("verification_method")
                    .cloned()
                    .unwrap_or(Value::Null),
            })
        })
        .unwrap_or(Value::Null);
    let device = DeviceInventoryRecord {
        actor: record.principal_id.clone(),
        device_id: record.requesting_device_id.clone(),
        display_name: None,
        verification_state: "verified".to_owned(),
        payload: json!({
            "recovery": {
                "recovery_session_id": record.recovery_session_id,
                "policy_id": record.policy_id,
                "policy_version": record.policy_version,
                "trust_domain": record.trust_domain,
                "proof_summary": proof_summary,
                "authorized_at": now.to_rfc3339_opts(SecondsFormat::Millis, true),
            }
        }),
        created_at: now,
        updated_at: now,
        revoked_at: None,
    };
    state
        .persistence
        .devices()
        .put(&device)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;

    let completed = RecoverySessionRecord {
        state: "completed".to_owned(),
        updated_at: now,
        ..record
    };
    state
        .persistence
        .recovery_sessions()
        .update(completed.clone())
        .await
        .map_err(recovery_session_store_error)?;

    let authorization_event = json!({
        "event_id": crate::ids::generate_event_id(),
        "event_kind": "cx.device.authorize",
        "actor": completed.principal_id,
        "device_id": completed.requesting_device_id,
        "recovery_session_id": completed.recovery_session_id,
        "policy_id": completed.policy_id,
        "policy_version": completed.policy_version,
        "created_at": now.to_rfc3339_opts(SecondsFormat::Millis, true),
    });
    append_audit_log(
        state,
        Some(&completed.principal_id),
        "cx.extension.soland.identity.recovery_session.complete",
        json!({
            "recovery_session_id": completed.recovery_session_id,
            "device_id": completed.requesting_device_id,
            "policy_id": completed.policy_id,
            "authorization_event": authorization_event,
        }),
        "completed",
    )
    .await;

    json_ok(json!({
        "ok": true,
        "recovery_session_id": completed.recovery_session_id,
        "state": completed.state,
        "device_id": completed.requesting_device_id,
        "authorization_event": authorization_event,
        "production_gap": "authorization_event_not_yet_in_operation_stream",
    }))
}

/// Lazily expire a session whose TTL has elapsed: if a `pending`/`verified`
/// session is past `expires_at`, persist the `expired` transition and return
/// the updated record. Terminal states are returned unchanged.
async fn expire_if_elapsed(
    state: &AppState,
    record: RecoverySessionRecord,
) -> Result<RecoverySessionRecord, AppError> {
    let now = chrono::Utc::now();
    let is_open = matches!(record.state.as_str(), "pending" | "verified");
    if is_open && now > record.expires_at {
        let expired = RecoverySessionRecord {
            state: "expired".to_owned(),
            updated_at: now,
            ..record
        };
        state
            .persistence
            .recovery_sessions()
            .update(expired.clone())
            .await
            .map_err(recovery_session_store_error)?;
        return Ok(expired);
    }
    Ok(record)
}

/// Generate a 256-bit anti-replay challenge (base64url, no padding). Pulled
/// from the OS CSPRNG.
fn generate_recovery_challenge() -> String {
    use rand::RngCore;
    let mut buf = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    URL_SAFE_NO_PAD.encode(buf)
}

fn recovery_session_store_error(error: PersistenceError) -> AppError {
    match error {
        PersistenceError::Conflict(message) if message.contains("already exists") => {
            AppError::conflict(message).with_wire_code("recovery_session_conflict")
        }
        other => recovery_store_error(other),
    }
}

#[endpoint(
    operation_id = "cx.extension.soland.identity.recovery_policy.put",
    tags("identity", "recovery"),
    summary = "Submit a cx.schema.recovery_policy.v1 policy (REC-1)",
    status_codes(200, 201, 400, 401, 403, 409, 500)
)]
#[tracing::instrument(
    skip_all,
    fields(op = "cx.extension.soland.identity.recovery_policy.put")
)]
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
        "cx.extension.soland.identity.recovery_policy.put",
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
    operation_id = "cx.extension.soland.identity.recovery_receipt.put",
    tags("identity", "recovery"),
    summary = "Record a cx.schema.recovery_receipt.v1 receipt (REC-1)",
    status_codes(200, 201, 400, 401, 403, 409, 500)
)]
#[tracing::instrument(
    skip_all,
    fields(op = "cx.extension.soland.identity.recovery_receipt.put")
)]
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
        "cx.extension.soland.identity.recovery_receipt.put",
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

// ────────────────────────────────────────────────────────────────────────
// Late key recovery state machine (spec T16).
// ────────────────────────────────────────────────────────────────────────

/// Spec T16 — per-(actor, ciphertext) late-recovery state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LateRecoveryState {
    DecryptionPending,
    DecryptionFailed,
    LateRecovered,
}

impl LateRecoveryState {
    pub fn can_transition_to(self, new: Self) -> bool {
        use LateRecoveryState::*;
        matches!(
            (self, new),
            (DecryptionPending, DecryptionFailed)
                | (DecryptionPending, LateRecovered)
                | (DecryptionFailed, LateRecovered)
        )
    }
}

/// Spec T16 — accept-late-recovery preconditions. All four MUST evaluate
/// true for the reducer to apply a late key share to a `decryption_failed`
/// cell.
#[derive(Clone, Copy, Debug)]
pub struct LateRecoveryAcceptInputs {
    /// (a) Actor was a Realm member at T₀ (recovery-target ciphertext's
    /// epoch).
    pub member_at_t0: bool,
    /// (b) Realm policy at T₀ permitted the actor to read the ciphertext.
    pub policy_permitted_at_t0: bool,
    /// (c) The presented key share was authorised by an origin permitted
    /// to issue late shares (e.g. cross-signed device or trusted recovery
    /// service).
    pub key_share_authorised: bool,
    /// (d) Audit profile MUST emit a paired `cx.audit.accessed{late_recovery=true}`
    /// event for the read. Callers set this true once they have queued the
    /// audit emit.
    pub audit_emit_queued: bool,
}

/// Spec T16 — apply the 4 accept conditions; reject revoked / removed
/// members with `late_recovery_rejected_membership`.
pub fn late_recovery_accept_check(
    inputs: LateRecoveryAcceptInputs,
) -> Result<(), (ErrorCode, &'static str)> {
    if !inputs.member_at_t0 {
        return Err((
            ErrorCode::LateRecoveryRejectedMembership,
            "actor was not a Realm member at the recovery T₀; late key \
             recovery refused",
        ));
    }
    if !inputs.policy_permitted_at_t0 {
        return Err((
            ErrorCode::LateRecoveryRejectedMembership,
            "Realm policy at T₀ did not permit the actor to read this \
             ciphertext",
        ));
    }
    if !inputs.key_share_authorised {
        return Err((
            ErrorCode::InvalidSignature,
            "late key share origin is not authorised",
        ));
    }
    if !inputs.audit_emit_queued {
        return Err((
            ErrorCode::FailedPrecondition,
            "late key recovery requires a paired cx.audit.accessed{late_recovery=true} \
             audit emit",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod late_recovery_tests {
    use super::*;

    #[test]
    fn late_recovery_rejects_revoked_actor() {
        let err = late_recovery_accept_check(LateRecoveryAcceptInputs {
            member_at_t0: false,
            policy_permitted_at_t0: true,
            key_share_authorised: true,
            audit_emit_queued: true,
        })
        .unwrap_err();
        assert_eq!(err.0, ErrorCode::LateRecoveryRejectedMembership);
    }

    #[test]
    fn late_recovery_accepts_when_all_four_conditions() {
        late_recovery_accept_check(LateRecoveryAcceptInputs {
            member_at_t0: true,
            policy_permitted_at_t0: true,
            key_share_authorised: true,
            audit_emit_queued: true,
        })
        .unwrap();
    }

    #[test]
    fn late_recovery_state_machine_transitions() {
        use LateRecoveryState::*;
        assert!(DecryptionPending.can_transition_to(DecryptionFailed));
        assert!(DecryptionFailed.can_transition_to(LateRecovered));
        assert!(!LateRecovered.can_transition_to(DecryptionPending));
    }
}
