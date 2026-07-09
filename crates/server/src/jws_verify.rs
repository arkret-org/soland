//! Soland thin wrapper over the canonical detached-JWS verifier in
//! [`arkret_sdk::jws`].
//!
//! All JWS verification semantics (RFC 7515 detached shape, Ed25519
//! signature check, DID resolution, replay-window timing) live in the
//! SDK so inkson, floria, cotest, teabay and soland share one
//! wire-compatible implementation. This module exists only to bridge
//! soland's [`AppState`]-rooted resolver into the SDK's
//! `&dyn DidResolver` API and to re-export the pure helpers (replay
//! windows, HLC parsing) for soland callers that reference
//! `crate::jws_verify::*`.
//!
//! # Two-tier verifier model (unchanged)
//!
//! - Dev mode (`config.development_mode == true`): handlers use [`verify_jws_shape`] — RFC 7515
//!   §3.2 detached shape, alg=EdDSA, no zero-sentinel signature, no actual crypto. Lets test
//!   fixtures and local dev iterate without managing real keys.
//! - Production mode (default): handlers use [`verify_jws_ed25519`] via
//!   [`AppState::jws_verifier`]'s closure factory — same shape checks PLUS DID resolution + Ed25519
//!   public-key extraction + RFC 7515 §5.2 signing-input reconstruction + ed25519-dalek verify.

use arkret_sdk::identity::{DidDocument, DidResolver};
use arkret_sdk::signatures::{
    Ed25519DetachedJwsVerifier, PublicKeyMaterial, VerifierError, build_proof_envelope,
};
use arkret_sdk::{Did, Hash};
use ed25519_dalek::{SigningKey, VerifyingKey};

use crate::persistence::{
    WEBVH_DOCUMENT_HIGH_RISK_TTL_SECS, WebvhFreshness, verify_did_document_freshness,
};
use crate::routing::identity::webvh_validation::{
    WebvhLogEntry, validate_log_chain, validate_witness_policy_for_log, verify_scid_against_did,
};
use crate::state::AppState;

/// DID document freshness threshold for high-risk verification paths. Equal
/// to the persistence-layer baseline TTL (15min). Records older than this,
/// or records without freshness evidence, fail closed because soland does not
/// perform on-demand network refreshes.
pub const HIGH_RISK_DID_FRESHNESS_MAX_SECS: i64 = WEBVH_DOCUMENT_HIGH_RISK_TTL_SECS;

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
// sites in `notary.rs`, `compactor.rs`, `routing::admin::seal.rs`,
// `routing::federation::move_seal.rs` and `routing::events::event_log.rs`
// keep working unchanged.
pub use arkret_sdk::jws::{
    effective_window_for_move, physical_millis_from_hlc, verify_replay_window,
    verify_replay_window_at, verify_replay_window_for_move, verify_replay_window_for_move_at,
};

/// Shape-only detached-JWS verifier for development mode.
///
/// This is intentionally colocated with soland's production SDK verifier
/// adapter so handlers do not define their own detached-JWS shape semantics.
/// Production mode still delegates to [`verify_jws_ed25519`].
pub fn verify_jws_shape(
    canonical_bytes: &[u8],
    jws: &str,
    verification_method: &str,
    issuer: &str,
) -> Result<(), String> {
    if jws.is_empty() {
        return Err("empty JWS string".to_owned());
    }
    if verification_method.is_empty() {
        return Err("empty verification_method".to_owned());
    }
    if issuer.is_empty() {
        return Err("empty issuer".to_owned());
    }
    if canonical_bytes.is_empty() {
        return Err("empty canonical bytes".to_owned());
    }

    let payload_digest = Hash::new(arkret_sdk::canonical::sha256_digest(canonical_bytes))
        .map_err(|error| error.to_string())?;
    let proof = build_proof_envelope(
        "detached_jws",
        "EdDSA",
        verification_method,
        payload_digest,
        None,
        None,
        jws,
    );
    let verifier = Ed25519DetachedJwsVerifier::new();
    let material = dev_shape_only_public_key();
    match verifier.verify_proof(&proof, canonical_bytes, &material) {
        Ok(()) => reject_zero_signature_sentinel(jws),
        Err(VerifierError::Backend(error)) if error.contains("Ed25519 verification failed") => {
            reject_zero_signature_sentinel(jws)
        }
        Err(error) => Err(error.to_string()),
    }
}

fn reject_zero_signature_sentinel(jws: &str) -> Result<(), String> {
    let signature_b64u = jws.rsplit('.').next().unwrap_or_default();
    if !signature_b64u.is_empty() && signature_b64u.bytes().all(|byte| byte == b'A') {
        return Err("JWS signature is the all-zero sentinel".to_owned());
    }
    Ok(())
}

fn dev_shape_only_public_key() -> PublicKeyMaterial {
    let public_key = SigningKey::from_bytes(&[7u8; 32]).verifying_key();
    PublicKeyMaterial::Ed25519Raw {
        bytes: public_key.to_bytes().to_vec(),
    }
}

/// Production Ed25519 detached-JWS verifier.
///
/// Soland-side adapter: dispatches `state.did_resolver` to
/// [`arkret_sdk::jws::verify_jws_ed25519`]. See the SDK module docs for
/// the full spec (RFC 7515 detached shape, alg=EdDSA, did:key /
/// did:web / did:webvh resolution).
pub fn verify_jws_ed25519(
    canonical_bytes: &[u8],
    jws: &str,
    verification_method: &str,
    issuer: &str,
    state: &AppState,
) -> Result<(), String> {
    arkret_sdk::jws::verify_jws_ed25519(
        canonical_bytes,
        jws,
        verification_method,
        issuer,
        &*state.did_resolver as &dyn DidResolver,
    )
    .map_err(|error| error.to_string())
}

/// Async-native production Ed25519 detached-JWS verifier.
///
/// This resolves the DID document through soland's async resolver service
/// before delegating shape and signature verification to the SDK verifier.
pub async fn verify_jws_ed25519_async(
    canonical_bytes: &[u8],
    jws: &str,
    verification_method: &str,
    issuer: &str,
    state: &AppState,
) -> Result<(), String> {
    let did = arkret_sdk::identity::verification_method_did(verification_method)
        .map_err(|error| error.to_string())?;
    let document = resolve_did_document_async(state, &did).await?;
    let resolver = ResolvedDidDocumentResolver {
        document: &document,
    };
    arkret_sdk::jws::verify_jws_ed25519(
        canonical_bytes,
        jws,
        verification_method,
        issuer,
        &resolver,
    )
    .map_err(|error| error.to_string())
}

/// Resolve a DID URL to its Ed25519 [`VerifyingKey`] via the AppState
/// resolver chain. Adapter over
/// [`arkret_sdk::jws::resolve_ed25519_pubkey`].
pub fn resolve_ed25519_pubkey(
    state: &AppState,
    verification_method: &str,
) -> Result<VerifyingKey, String> {
    arkret_sdk::jws::resolve_ed25519_pubkey(
        &*state.did_resolver as &dyn DidResolver,
        verification_method,
    )
    .map_err(|error| error.to_string())
}

pub async fn resolve_ed25519_pubkey_async(
    state: &AppState,
    verification_method: &str,
) -> Result<VerifyingKey, String> {
    let did = arkret_sdk::identity::verification_method_did(verification_method)
        .map_err(|error| error.to_string())?;
    let document = resolve_did_document_async(state, &did).await?;
    let resolver = ResolvedDidDocumentResolver {
        document: &document,
    };
    arkret_sdk::jws::resolve_ed25519_pubkey(&resolver, verification_method)
        .map_err(|error| error.to_string())
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
    let document = resolve_did_document_async(state, did).await?;
    require_verification_method_in_document(&document, verification_method)?;
    let public_key = {
        let resolver = ResolvedDidDocumentResolver {
            document: &document,
        };
        arkret_sdk::jws::resolve_ed25519_pubkey(&resolver, verification_method)
            .map_err(|error| error.to_string())?
    };
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
    let document = state
        .did_resolver
        .resolve_did(did)
        .map_err(|error| format!("DID resolution failed: {error}"))?;
    if document.id != *did {
        return Err("resolved DID document id does not match requested DID".to_owned());
    }
    Ok(document)
}

pub async fn resolve_did_document_async(
    state: &AppState,
    did: &Did,
) -> Result<DidDocument, String> {
    let document = state
        .did_resolver
        .resolve_did_async(did)
        .await
        .map_err(|error| format!("DID resolution failed: {error}"))?;
    if document.id != *did {
        return Err("resolved DID document id does not match requested DID".to_owned());
    }
    Ok(document)
}

struct ResolvedDidDocumentResolver<'a> {
    document: &'a DidDocument,
}

impl DidResolver for ResolvedDidDocumentResolver<'_> {
    fn supports(&self, did: &Did) -> bool {
        &self.document.id == did
    }

    fn resolve_did(&self, did: &Did) -> arkret_sdk::Result<DidDocument> {
        if self.supports(did) {
            return Ok(self.document.clone());
        }
        Err(arkret_sdk::Error::Protocol(
            "resolved DID document does not match requested DID".to_owned(),
        ))
    }
}

/// DID document freshness gate for high-risk paths (fail-closed-on-stale).
///
/// Fetches the DID's persisted [`WebvhDocumentRecord`] (the ingested
/// document) and evaluates it with [`verify_did_document_freshness`]:
///
/// * [`WebvhFreshness::Fresh`] returns `Ok(())`.
/// * [`WebvhFreshness::Stale`] returns `Err`; the cached public key exceeded the high-risk TTL and
///   must fail closed.
///
/// If persistence has no record for the DID (`get_document` returns `None`),
/// there is no trusted ingestion evidence for high-risk verification and the
/// path also fails closed. Local immediate documents such as dev / extension
/// actors are not persisted here and are handled directly by the SDK resolver
/// inside `verify_jws_ed25519`; this gate only covers cached remote/submitted
/// documents.
///
/// Because soland does not perform on-demand network fetches, "stale" means
/// "unavailable" for high-risk writes; degraded read-only relaxation does not
/// apply here.
pub async fn enforce_high_risk_did_freshness(state: &AppState, did: &Did) -> Result<(), String> {
    let max_age = chrono::Duration::seconds(HIGH_RISK_DID_FRESHNESS_MAX_SECS);
    let record = state
        .persistence
        .webvh()
        .get_document(did.as_str())
        .await
        .map_err(|error| format!("DID freshness lookup failed: {error}"))?;
    let Some(record) = record else {
        // No ingested record means no trusted freshness evidence for a
        // high-risk path, so fail closed.
        return Err(format!(
            "DID document freshness unavailable for high-risk verification: no ingested record for {did}"
        ));
    };
    match verify_did_document_freshness(&record, chrono::Utc::now(), max_age) {
        WebvhFreshness::Fresh => {
            state
                .did_resolver
                .cache_webvh_record(record)
                .map_err(|error| format!("DID freshness cache failed: {error}"))?;
            Ok(())
        }
        WebvhFreshness::Stale => {
            let stale_error = format!(
                "DID document is stale for high-risk verification (exceeded {HIGH_RISK_DID_FRESHNESS_MAX_SECS}s freshness window): {did}"
            );
            if !is_embedded_webvh_document(did, &record) {
                return Err(stale_error);
            }
            if let Err(error) =
                refresh_embedded_webvh_document_for_high_risk(state, did, &record).await
            {
                return Err(format!(
                    "{stale_error}; embedded refresh unavailable: {error}"
                ));
            }
            Ok(())
        }
    }
}

fn is_embedded_webvh_document(did: &Did, record: &crate::state::WebvhDocumentRecord) -> bool {
    did.as_str().starts_with("did:webvh:")
        && record
            .method_evidence
            .get("mode")
            .and_then(serde_json::Value::as_str)
            == Some("embedded_webvh_provider")
}

async fn refresh_embedded_webvh_document_for_high_risk(
    state: &AppState,
    did: &Did,
    record: &crate::state::WebvhDocumentRecord,
) -> Result<(), String> {
    if !is_embedded_webvh_document(did, record) {
        return Err("document is not a local embedded did:webvh record".to_owned());
    }

    let events = state
        .persistence
        .webvh()
        .list_log_events(did.as_str())
        .await
        .map_err(|error| format!("DID log lookup failed: {error}"))?;
    let Some(last_event) = events.last() else {
        return Err("embedded did:webvh log is empty".to_owned());
    };
    if record.seq != last_event.seq {
        return Err(format!(
            "embedded did:webvh document seq {} does not match log tail seq {}",
            record.seq, last_event.seq
        ));
    }
    if record.key_log_head.as_deref() != Some(last_event.event_digest.as_str()) {
        return Err("embedded did:webvh document head does not match log tail".to_owned());
    }

    let log: Vec<WebvhLogEntry> = events
        .iter()
        .map(|event| WebvhLogEntry::new(event.operation.clone()))
        .collect();
    validate_log_chain(&log).map_err(|error| error.to_string())?;
    verify_scid_against_did(did.as_str(), &log[0]).map_err(|error| error.to_string())?;
    validate_witness_policy_for_log(&log, chrono::Utc::now().timestamp())
        .map_err(|error| error.to_string())?;

    state
        .persistence
        .webvh()
        .put_document(record.clone())
        .await
        .map_err(|error| format!("DID document refresh write failed: {error}"))?;
    state
        .did_resolver
        .cache_webvh_record(record.clone())
        .map_err(|error| format!("DID document refresh cache failed: {error}"))?;
    Ok(())
}

/// High-risk variant of [`resolve_ed25519_verification_key_for_did`]: enforce
/// freshness before resolving the public key. High-risk callers such as
/// federation receive and recovery use this variant. Read-side callers that
/// do not need fail-closed semantics can still call the non-`_fresh` version.
pub async fn resolve_ed25519_verification_key_for_did_fresh(
    state: &AppState,
    did: &Did,
    verification_method: &str,
) -> Result<ResolvedVerificationKey, String> {
    // Enforce freshness first: stale or missing evidence rejects before key
    // resolution.
    enforce_high_risk_did_freshness(state, did).await?;
    resolve_ed25519_verification_key_for_did(state, did, verification_method).await
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
    let digest = arkret_sdk::canonical::canonical_sha256(&value)
        .map_err(|error| format!("DID document canonical digest failed: {error}"))?;
    Hash::new(digest).map_err(|error| format!("DID document digest invalid: {error}"))
}
