//! Soland thin wrapper over the canonical detached-JWS verifier in
//! [`contrix_sdk::jws`].
//!
//! All JWS verification semantics (RFC 7515 detached shape, Ed25519
//! signature check, DID resolution, replay-window timing) live in the
//! SDK so yougen, floria, cotest, teabay and soland share one
//! wire-compatible implementation. This module exists only to bridge
//! soland's [`AppState`]-rooted resolver lock into the SDK's
//! `&dyn DidResolver` API and to re-export the pure helpers (replay
//! windows, HLC parsing) for soland callers that reference
//! `crate::jws_verify::*`.
//!
//! # Two-tier verifier model (unchanged)
//!
//! - Dev mode (`config.development_mode == true`): handlers use
//!   `routing::federation::move_anchor::verify_jws_shape` — RFC 7515 §3.2 detached shape,
//!   alg=EdDSA, no zero-sentinel signature, no actual crypto. Lets test fixtures and local dev
//!   iterate without managing real keys.
//! - Production mode (default): handlers use [`verify_jws_ed25519`] via
//!   [`AppState::jws_verifier`]'s closure factory — same shape checks PLUS DID resolution + Ed25519
//!   public-key extraction + RFC 7515 §5.2 signing-input reconstruction + ed25519-dalek verify.

use contrix_sdk::identity::{DidDocument, DidResolver};
use contrix_sdk::{Did, Hash};
use ed25519_dalek::VerifyingKey;

use crate::state::AppState;

/// Resolved Ed25519 verification key with the document metadata that
/// endpoints need to report or bind into audit records.
#[derive(Clone, Debug)]
pub struct ResolvedVerificationKey {
    pub verification_method: String,
    pub algorithm: &'static str,
    pub public_key: VerifyingKey,
    pub did_document_ref: String,
    pub key_log_head: Hash,
}

// Re-exports of pure helpers from the SDK. Identical signatures so call
// sites in `anchorer.rs`, `compactor.rs`, `routing::admin::anchor.rs`,
// `routing::federation::move_anchor.rs` and `routing::events::event_log.rs`
// keep working unchanged.
pub use contrix_sdk::jws::{
    effective_window_for_move, physical_millis_from_hlc, verify_replay_window,
    verify_replay_window_at, verify_replay_window_for_move, verify_replay_window_for_move_at,
};

/// Production Ed25519 detached-JWS verifier.
///
/// Soland-side adapter: locks `state.did_resolver` and dispatches to
/// [`contrix_sdk::jws::verify_jws_ed25519`]. See the SDK module docs for
/// the full spec (RFC 7515 detached shape, alg=EdDSA, did:key /
/// did:web / did:webvh resolution).
pub fn verify_jws_ed25519(
    canonical_bytes: &[u8],
    jws: &str,
    verification_method: &str,
    issuer: &str,
    state: &AppState,
) -> Result<(), String> {
    let resolver = state
        .did_resolver
        .lock()
        .map_err(|e| format!("DID resolver lock poisoned: {e}"))?;
    contrix_sdk::jws::verify_jws_ed25519(
        canonical_bytes,
        jws,
        verification_method,
        issuer,
        &*resolver as &dyn DidResolver,
    )
}

/// Resolve a DID URL to its Ed25519 [`VerifyingKey`] via the AppState
/// resolver chain. Adapter over
/// [`contrix_sdk::jws::resolve_ed25519_pubkey`].
pub fn resolve_ed25519_pubkey(
    state: &AppState,
    verification_method: &str,
) -> Result<VerifyingKey, String> {
    let resolver = state
        .did_resolver
        .lock()
        .map_err(|e| format!("DID resolver lock poisoned: {e}"))?;
    contrix_sdk::jws::resolve_ed25519_pubkey(&*resolver as &dyn DidResolver, verification_method)
}

/// Resolve and validate a DID-scoped Ed25519 verification method.
///
/// This is the shared verifier boundary used by federation, recovery and
/// other control-plane endpoints that sign canonical JSON transcripts outside
/// the detached-JWS wrapper. It enforces the same controller and DID-document
/// membership checks before returning the public key.
pub async fn resolve_ed25519_verification_key_for_did(
    state: &AppState,
    did: &Did,
    verification_method: &str,
) -> Result<ResolvedVerificationKey, String> {
    validate_verification_method_controller(did.as_str(), verification_method)?;
    let document = resolve_did_document(state, did)?;
    require_verification_method_in_document(&document, verification_method)?;
    let public_key = resolve_ed25519_pubkey(state, verification_method)?;
    let key_log_head = did_document_key_log_head(state, did, &document).await?;
    Ok(ResolvedVerificationKey {
        verification_method: verification_method.to_owned(),
        algorithm: "Ed25519",
        public_key,
        did_document_ref: format!("{}#document", did),
        key_log_head,
    })
}

pub fn validate_verification_method_controller(
    controller_did: &str,
    verification_method: &str,
) -> Result<(), String> {
    let Some(fragment) = verification_method
        .strip_prefix(controller_did)
        .and_then(|rest| rest.strip_prefix('#'))
    else {
        return Err("verification method controller does not match DID".to_owned());
    };
    if fragment.trim().is_empty() {
        return Err("verification method fragment is empty".to_owned());
    }
    Ok(())
}

pub fn resolve_did_document(state: &AppState, did: &Did) -> Result<DidDocument, String> {
    let resolver = state
        .did_resolver
        .lock()
        .map_err(|e| format!("DID resolver lock poisoned: {e}"))?;
    let document = resolver
        .resolve_did(did)
        .map_err(|error| format!("DID resolution failed: {error}"))?;
    if document.id != *did {
        return Err("resolved DID document id does not match requested DID".to_owned());
    }
    Ok(document)
}

pub fn require_verification_method_in_document(
    document: &DidDocument,
    verification_method: &str,
) -> Result<(), String> {
    if document
        .verification_methods
        .contains_key(verification_method)
    {
        return Ok(());
    }
    let fragment = verification_method
        .split_once('#')
        .map(|(_, fragment)| fragment)
        .unwrap_or(verification_method);
    if document.verification_methods.contains_key(fragment) {
        return Ok(());
    }
    Err("verification method is not present in DID document".to_owned())
}

async fn did_document_key_log_head(
    state: &AppState,
    did: &Did,
    document: &DidDocument,
) -> Result<Hash, String> {
    if let Ok(Some(record)) = state.persistence.webvh().get_document(did.as_str()).await
        && let Some(head) = record.key_log_head
        && let Ok(hash) = Hash::new(head)
    {
        return Ok(hash);
    }
    let value = serde_json::to_value(document)
        .map_err(|error| format!("DID document serialization failed: {error}"))?;
    let digest = contrix_sdk::canonical::canonical_sha256(&value)
        .map_err(|error| format!("DID document canonical digest failed: {error}"))?;
    Hash::new(digest).map_err(|error| format!("DID document digest invalid: {error}"))
}
