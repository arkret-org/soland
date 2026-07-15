//! AKP-0010 / R3 (REC-1) — recovery policy + recovery receipt endpoints.
//!
//! Mounts recovery policy / receipt endpoints introduced in arkret-spec b47ff6ec:
//!
//! - `GET /_arkret/root/identity/recovery-policy` — read the active recovery policy.
//! - `POST /_arkret/root/identity/recovery-policy` — persist + advance a recovery policy.
//! - `POST /_soland/root/identity/recovery-receipt` — record a recovery receipt for a witnessed
//!   session.
//!
//! Wire-level validation lands here (proof_kind enum, recovery_session
//! uuid pattern, expires/policy_version monotonicity,
//! `recovery_witness_revoke_lagging` freshness window) plus the REC-1
//! Ed25519 principal signature checks over canonical signed_fields
//! transcripts.
//!
//! The implementation is split across sibling submodules under `recovery/`;
//! this module root keeps the routers, the shared `use` surface (re-exported to
//! submodules via `use super::*;`), and the externally-referenced
//! `principal_control_realm_for_did`.

use std::collections::BTreeSet;

use arkret_sdk::{
    DeviceGenerationStatus, DeviceId, Did, EventBatchReceiptScope, Hash, NonEmptyString, PolicyId,
    ProofSummary, RealmId, ReceiptId, RecoveryIdentityModel, RecoveryPolicy,
    RecoveryPolicyActiveOutcome, RecoveryPolicyPublishOutcome, RecoveryPolicyRef,
    RecoveryPolicySummary, RecoveryReceiptOutcome, RecoverySessionCompleteOutcome,
    RecoverySessionCompleteRequestBody, RecoverySessionCreateRequestBody, RecoverySessionId,
    RecoverySessionProofSubmitOutcome, RecoverySessionProofSubmitRequestBody, RecoverySessionState,
    SessionState, TypedTrustDomainId,
};
use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use chrono::SecondsFormat;
use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};
use salvo::http::StatusCode;
use salvo::oapi::extract::{JsonBody, PathParam, QueryParam};
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use super::{AuthArgs, append_audit_log};
use crate::error::{AppError, ErrorCode};
use crate::persistence::PersistenceError;
use crate::result::{JsonResult, json_ok};
use crate::state::{
    AppState, DeviceInventoryRecord, RecoveryPolicyRecord, RecoveryReceiptRecord,
    RecoverySessionRecord, SessionRecord,
};

mod errors;
use errors::*;
mod policy_endpoints;
use policy_endpoints::*;
mod receipt_endpoints;
use receipt_endpoints::*;
mod session_endpoints;
use session_endpoints::*;
mod signatures;
use signatures::*;
mod validation;
use validation::*;
mod wire;
use wire::*;

/// Spec-canonical recovery surface mounted under `/_arkret/root/identity`.
///
/// The standard surface exposes recovery policy read/publish plus recovery
/// session lifecycle operations. Policy history and recovery receipt
/// write/history remain product-private on the `/_soland` track.
pub(super) fn protocol_router() -> Router {
    Router::with_path("identity")
        .push(
            Router::with_path("recovery-policy")
                .post(recovery_policy_put)
                .get(recovery_policy_get),
        )
        .push(
            Router::with_path("recovery-sessions").post(recovery_session_create), // C-P2 (REC-1)
        )
        .push(
            Router::with_path("recovery-sessions/{recovery_session_id}").get(recovery_session_get),
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

pub(super) fn router() -> Router {
    Router::with_path("identity")
        .push(Router::with_path("recovery-policies").get(recovery_policies_get))
        .push(Router::with_path("recovery-receipt").post(recovery_receipt_put))
        .push(Router::with_path("recovery-receipts").get(recovery_receipts_get))
        .push(
            Router::with_path("recovery-sessions").post(recovery_session_create), // C-P2 (REC-1)
        )
        .push(
            Router::with_path("recovery-sessions/{recovery_session_id}").get(recovery_session_get),
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

/// Deterministic principal control realm id for a principal DID
/// (`ak:realm:<uuidv7>`). Device-control events (`ak.device.authorize`,
/// `ak.device.list_update`, future `ak.cross_signing.publish`) land here. The
/// realm is auto-materialized by the projector on the first accepted op.
pub fn principal_control_realm_for_did(principal_did: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"ak:realm:principal-control:v1:");
    hasher.update(principal_did.as_bytes());
    let digest = hasher.finalize();
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    // Force UUIDv7 version (0x7) + RFC-9562 variant (0b10).
    bytes[6] = (bytes[6] & 0x0F) | 0x70;
    bytes[8] = (bytes[8] & 0x3F) | 0x80;
    let group =
        |slice: &[u8]| -> String { slice.iter().map(|b| format!("{b:02x}")).collect::<String>() };
    format!(
        "ak:realm:{}-{}-{}-{}-{}",
        group(&bytes[0..4]),
        group(&bytes[4..6]),
        group(&bytes[6..8]),
        group(&bytes[8..10]),
        group(&bytes[10..16]),
    )
}
