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
//!   `routing::federation::move_anchor::verify_jws_shape` — RFC 7515
//!   §3.2 detached shape, alg=EdDSA, no zero-sentinel signature, no
//!   actual crypto. Lets test fixtures and local dev iterate without
//!   managing real keys.
//! - Production mode (default): handlers use [`verify_jws_ed25519`] via
//!   [`AppState::jws_verifier`]'s closure factory — same shape checks
//!   PLUS DID resolution + Ed25519 public-key extraction + RFC 7515
//!   §5.2 signing-input reconstruction + ed25519-dalek verify.

use contrix_sdk::identity::DidResolver;
use ed25519_dalek::VerifyingKey;

use crate::state::AppState;

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
