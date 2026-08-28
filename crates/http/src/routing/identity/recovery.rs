//! Recovery policy and recovery-session endpoints.
//!
//! Mounts recovery policy and durable recovery-transaction endpoints:
//!
//! - `GET /_arkret/root/identity/recovery-policy` — read the active recovery policy.
//! - `POST /_arkret/root/identity/recovery-policy` — persist + advance a recovery policy.
//!
//! Wire-level validation lands here (proof_kind enum, recovery_session
//! uuid pattern, expires/policy_version monotonicity,
//! `recovery_witness_revoke_lagging` freshness window).
//!
//! The implementation is split across sibling submodules under `recovery/`;
//! this module root keeps the routers, the shared `use` surface (re-exported to
//! submodules via `use super::*;`).

use std::collections::BTreeSet;

use arkret_identifiers::{Hash, PolicyId, RealmId, RecoverySessionId, TrustDomainId};
use arkret_models_crypto::{
    Challenge, DeviceGenerationStatus, DidRootTranscript, GenericRecoveryProofBody,
    GenericRecoveryTranscript, ProofSummary, RecoveryIdentityModel, RecoveryPolicy,
    RecoveryPolicyActiveOutcome, RecoveryPolicyPublishOutcome, RecoveryPolicyPublishRequest,
    RecoveryPolicyRef, RecoveryPolicySummary, RecoveryProofKind, RecoveryPublicationAction,
    RecoveryPublicationAuthorityContext, RecoverySessionCreateRequestBody,
    RecoverySessionProofSubmitOutcome, RecoverySessionProofSubmitRequestBody, RecoverySessionState,
    SecurityTransactionContinueRequest, SessionState, TrustedRecoveryServiceProofBody,
    TrustedRecoveryServiceSessionProof,
};
use arkret_wire::{
    AuthoritySetAuthorizationRule, AuthoritySetPolicy, AuthoritySetPolicyKind,
    AuthoritySetPolicySource, AuthoritySetRef, AuthoritySetSourceKind, DeviceId, DidUrl,
    LeaseBasisRef, PrincipalAuthorityKey, RECOVERY_IDENTITY_REANCHOR_AUTHORITY_SET_ID, RequestId,
    SchemaId, SecurityTransaction, SecurityTransactionCreateRequest, SessionGrantId, TransactionId,
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
    RecoveryPolicyState, SecurityTransactionRecord, SessionIdentityState as SessionRecord,
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
pub(super) use security_transaction_endpoints::backup_series_erase_command;
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
        summary.kind.as_wire_str().to_owned(),
        summary.proof_digest.to_string(),
    ))
}

/// Resolve the recovery-policy key that authenticated this recovery session.
/// Recovery-key possession is rooted in the signed policy, not in a DID
/// document that may contain no device methods after every device is lost.
pub(super) fn recovery_session_unlock_verifying_key(
    record: &soland_services::identity::RecoverySessionState,
    verification_method: &str,
) -> Result<VerifyingKey, AppError> {
    let summary = recovery_proof_summary(record).ok_or_else(|| {
        AppError::capability_denied("recovery session has no verified proof summary")
    })?;
    if summary.kind != RecoveryProofKind::RecoveryUnlock
        || summary.verification_method.as_ref().map(DidUrl::as_str) != Some(verification_method)
    {
        return Err(AppError::capability_denied(
            "key backup unlock signature is not identified by the recovery key accepted for the session",
        ));
    }
    let entry = resolve_recovery_key_entry(
        &record.policy_payload,
        verification_method,
        record.created_at,
    )?;
    decode_recovery_key_public_key(&entry)
}

/// Spec-canonical recovery surface mounted under `/_arkret/root/identity`.
///
/// The standard surface exposes recovery policy read/publish plus recovery
/// session lifecycle operations. A recovery receipt has no independent write
/// endpoint: it is the signed terminal artifact of a durable
/// `RecoveryTransaction`.
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
