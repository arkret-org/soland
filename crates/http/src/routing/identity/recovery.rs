//! Recovery policy and recovery-session endpoints.
//!
//! Mounts recovery policy / receipt endpoints introduced in arkret-spec b47ff6ec:
//!
//! - `GET /_arkret/root/identity/recovery-policy` — read the active recovery policy.
//! - `POST /_arkret/root/identity/recovery-policy` — persist + advance a recovery policy.
//! Wire-level validation lands here (proof_kind enum, recovery_session
//! uuid pattern, expires/policy_version monotonicity,
//! `recovery_witness_revoke_lagging` freshness window).
//!
//! The implementation is split across sibling submodules under `recovery/`;
//! this module root keeps the routers, the shared `use` surface (re-exported to
//! submodules via `use super::*;`).

use std::collections::BTreeSet;

use arkret_identifiers::{Did, Hash, PolicyId, RealmId, RecoverySessionId};
use arkret_models_crypto::{
    DeviceGenerationStatus, ProofSummary, RecoveryIdentityModel, RecoveryPolicy,
    RecoveryPolicyActiveOutcome, RecoveryPolicyPublishOutcome, RecoveryPolicyRef,
    RecoveryPolicySummary, RecoverySessionCreateRequestBody, RecoverySessionProofSubmitOutcome,
    RecoverySessionProofSubmitRequestBody, RecoverySessionState, SessionState,
    TypedSecurityTransactionContinueRequest,
};
use arkret_wire::{
    NonEmptyString, SecurityTransaction, SecurityTransactionCreateRequest, TransactionId,
};
use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};
use salvo::http::StatusCode;
use salvo::oapi::extract::{JsonBody, PathParam, QueryParam};
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use soland_http::error::{AppError, ErrorCode};
use soland_http::result::{JsonResult, json_ok};
use soland_services::ServiceError as PersistenceError;
use soland_services::identity::{
    RecoveryPolicyState as RecoveryPolicyRecord,
    SecurityTransactionState as SecurityTransactionRecord, SessionIdentityState as SessionRecord,
    principal_control_realm_for_did,
};

use super::{AuthArgs, append_audit_log};
use crate::state::AppState;

mod errors;
use errors::*;
mod policy_endpoints;
use policy_endpoints::*;
mod session_endpoints;
use session_endpoints::*;
mod security_transaction_endpoints;
use security_transaction_endpoints::*;
mod signatures;
use signatures::*;
mod validation;
use validation::*;
mod wire;
use wire::*;

/// Return the proof kind and canonical transcript digest recorded by a
/// verified recovery session. Key-backup release uses this exact helper so it
/// cannot drift from recovery-session proof verification.
pub(super) fn recovery_session_proof_kind_and_digest(
    record: &soland_services::identity::RecoverySessionState,
) -> Option<(String, String)> {
    let summary = recovery_proof_summary(record)?;
    Some((
        summary.get("kind")?.as_str()?.to_owned(),
        summary.get("proof_digest")?.as_str()?.to_owned(),
    ))
}

/// Spec-canonical recovery surface mounted under `/_arkret/root/identity`.
///
/// The standard surface exposes recovery policy read/publish plus recovery
/// session lifecycle operations. Policy history and recovery receipt
/// write is part of the standard recovery lifecycle. Policy and receipt
/// history remain product-private on the `/_soland` track.
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
}

/// Spec-canonical authenticated transaction coordinator surface mounted under
/// `/_arkret/self`.
pub(super) fn self_protocol_router() -> Router {
    Router::new()
        .push(Router::with_path("recovery-authority-tickets").post(recovery_authority_ticket_issue))
        .push(Router::with_path("security-transactions").post(security_transaction_create))
        .push(
            Router::with_path("security-transactions/{transaction_id}")
                .get(security_transaction_get),
        )
        .push(
            Router::with_path("security-transactions/{transaction_id}/continue")
                .post(security_transaction_continue),
        )
}

pub(super) fn router() -> Router {
    Router::with_path("identity")
        .push(Router::with_path("recovery-policies").get(recovery_policies_get))
}
