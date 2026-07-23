//! Soland thin wrapper over the canonical detached-JWS verifier in
//! [`arkret_identity::jws`].
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

use std::collections::BTreeMap;

use arkret_identifiers::{Did, Hash};
use arkret_identity::{DidDocument, DidResolver};
use arkret_signatures::{
    Ed25519DetachedJwsVerifier, PublicKeyMaterial, VerifierError, build_proof_envelope,
};
use ed25519_dalek::{SigningKey, VerifyingKey};
use soland_application::identity::{
    DID_DOCUMENT_HIGH_RISK_TTL_SECS, DidDocumentFreshness, evaluate_did_document_freshness,
};

use crate::routing::identity::webvh_validation::{
    WebvhLogEntry, validate_log_chain, validate_witness_policy_for_log, verify_scid_against_did,
};
use crate::state::AppState;

/// DID document freshness threshold for high-risk verification paths. Equal
/// to the persistence-layer baseline TTL (15min). Records older than this,
/// or records without freshness evidence, fail closed because soland does not
/// perform on-demand network refreshes.
pub const HIGH_RISK_DID_FRESHNESS_MAX_SECS: i64 = DID_DOCUMENT_HIGH_RISK_TTL_SECS;

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
pub use arkret_identity::jws::{
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

    let payload_digest = Hash::new(arkret_canonical::sha256_digest(canonical_bytes))
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
    match verifier.verify_detached_jws(&proof.jws, canonical_bytes, &material) {
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
/// Soland-side adapter: dispatches the injected DID resolver to
/// [`arkret_identity::jws::verify_jws_ed25519`]. See the SDK module docs for
/// the full spec (RFC 7515 detached shape, alg=EdDSA, did:key /
/// did:web / did:webvh resolution).
pub fn verify_jws_ed25519(
    canonical_bytes: &[u8],
    jws: &str,
    verification_method: &str,
    issuer: &str,
    state: &AppState,
) -> Result<(), String> {
    arkret_identity::jws::verify_jws_ed25519(
        canonical_bytes,
        jws,
        verification_method,
        issuer,
        state.did_application().resolver(),
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
    let did = arkret_identity::verification_method_did(verification_method)
        .map_err(|error| error.to_string())?;
    let document = if is_local_service_notary_method(state, &did, verification_method) {
        DidDocument {
            id: did.clone(),
            verification_methods: BTreeMap::from([(
                verification_method.to_owned(),
                arkret_canonical::ed25519_pubkey_to_did_key_multibase(
                    state.notary_verifying_key().as_bytes(),
                ),
            )]),
            also_known_as: Vec::new(),
            updated_at: Some(chrono::Utc::now()),
            raw_properties: BTreeMap::new(),
        }
    } else {
        resolve_did_document_async(state, &did).await?
    };
    let resolver = ResolvedDidDocumentResolver {
        document: &document,
    };
    arkret_identity::jws::verify_jws_ed25519(
        canonical_bytes,
        jws,
        verification_method,
        issuer,
        &resolver,
    )
    .map_err(|error| error.to_string())
}

pub fn verify_jws_ed25519_with_document(
    canonical_bytes: &[u8],
    jws: &str,
    verification_method: &str,
    issuer: &str,
    document_value: &serde_json::Value,
) -> Result<(), String> {
    let document = serde_json::from_value::<DidDocument>(document_value.clone())
        .map_err(|error| format!("historical DID document decode failed: {error}"))?;
    let issuer_did = Did::new(issuer.to_owned()).map_err(|error| error.to_string())?;
    if document.id != issuer_did {
        return Err("historical DID document id does not match issuer".to_owned());
    }
    require_verification_method_in_document(&document, verification_method)?;
    let resolver = ResolvedDidDocumentResolver {
        document: &document,
    };
    arkret_identity::jws::verify_jws_ed25519(
        canonical_bytes,
        jws,
        verification_method,
        issuer,
        &resolver,
    )
    .map_err(|error| error.to_string())
}

/// Verify a proof made by either a principal DID control method or one of the
/// principal's currently-authorized device keys.
///
/// `device-lifecycle.md` §5.4/§8.2 deliberately keeps ordinary device keys in
/// the principal-control device-set projection instead of the DID document.
/// A verification method shaped as `{principal}#{device_id}` therefore MUST
/// resolve through that projection. Non-device methods (identity control,
/// delegated enrollment authority, service notary, and similar methods) keep
/// using the DID-document verifier and its high-risk freshness gate.
#[derive(Debug)]
pub enum PrincipalAuthorizedJwsError {
    HighRiskDidFreshness(String),
    Verification(String),
}

impl std::fmt::Display for PrincipalAuthorizedJwsError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::HighRiskDidFreshness(reason) | Self::Verification(reason) => {
                formatter.write_str(reason)
            }
        }
    }
}

pub async fn verify_principal_authorized_jws_ed25519_async(
    canonical_bytes: &[u8],
    jws: &str,
    verification_method: &str,
    principal_id: &str,
    state: &AppState,
) -> Result<(), PrincipalAuthorizedJwsError> {
    let method_did = arkret_identity::verification_method_did(verification_method)
        .map_err(|error| PrincipalAuthorizedJwsError::Verification(error.to_string()))?;
    if method_did.as_str() != principal_id {
        return Err(PrincipalAuthorizedJwsError::Verification(
            "verification method controller does not match principal".to_owned(),
        ));
    }

    let device_prefix = format!("{principal_id}#");
    if let Some(device_id) = verification_method.strip_prefix(&device_prefix)
        && arkret_identifiers::DeviceId::new(device_id.to_owned()).is_ok()
    {
        let facet =
            crate::routing::identity::cross_signing::try_resolve_device_signing_directory_facet(
                state,
                principal_id,
                device_id,
            )
            .await
            .map_err(|error| {
                PrincipalAuthorizedJwsError::Verification(format!(
                    "device signing directory unavailable: {error}"
                ))
            })?;
        if !matches!(
            facet.status,
            arkret_models_crypto::keys::DeviceStatus::Active
        ) {
            return Err(PrincipalAuthorizedJwsError::Verification(
                "device signing key is not active and authorized".to_owned(),
            ));
        }
        let multibase = facet
            .signing_key_did
            .as_deref()
            .and_then(|value| value.strip_prefix("did:key:"))
            .ok_or_else(|| {
                PrincipalAuthorizedJwsError::Verification(
                    "authorized device signing key is unavailable".to_owned(),
                )
            })?;
        let material = PublicKeyMaterial::Ed25519Multibase {
            value: multibase.to_owned(),
        };
        return Ed25519DetachedJwsVerifier::new()
            .verify_detached_jws(jws, canonical_bytes, &material)
            .map_err(|error| PrincipalAuthorizedJwsError::Verification(error.to_string()));
    }

    if method_did.method() != "key"
        && !is_local_service_notary_method(state, &method_did, verification_method)
    {
        if state.config().development_mode {
            let ingested = state
                .did_application()
                .document(method_did.as_str())
                .await
                .map_err(|error| {
                    PrincipalAuthorizedJwsError::HighRiskDidFreshness(format!(
                        "DID freshness lookup failed: {error}"
                    ))
                })?
                .is_some();
            if !ingested {
                // Local development still verifies a real detached Ed25519
                // JWS. Only key discovery is deterministic, and the derivation
                // lives in the SDK so cotest and every server reconstruct the
                // same fixture identity without accepting a dev-proof type.
                let key = arkret_signatures::development_verifying_key(verification_method);
                let material = PublicKeyMaterial::Ed25519Raw {
                    bytes: key.to_bytes().to_vec(),
                };
                return Ed25519DetachedJwsVerifier::new()
                    .verify_detached_jws(jws, canonical_bytes, &material)
                    .map_err(|error| PrincipalAuthorizedJwsError::Verification(error.to_string()));
            }
        }
        enforce_high_risk_did_freshness(state, &method_did)
            .await
            .map_err(PrincipalAuthorizedJwsError::HighRiskDidFreshness)?;
    }
    verify_jws_ed25519_async(
        canonical_bytes,
        jws,
        verification_method,
        principal_id,
        state,
    )
    .await
    .map_err(PrincipalAuthorizedJwsError::Verification)
}

/// Resolve the active local device-directory evidence needed to verify an
/// original participant-signed Event on a remote Principal Server. The
/// returned evidence is carried only in the service-authenticated federation
/// wrapper; it never mutates the Event or its canonical digest.
pub async fn federated_event_signer_evidence(
    state: &AppState,
    event: &arkret_wire::Event,
) -> Result<Vec<arkret_wire::event_envelope::FederatedDeviceSigningKeyEvidence>, String> {
    let actor_id = event.actor_id.as_str();
    let prefix = format!("{actor_id}#");
    let mut evidence = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for proof in &event.proofs {
        let Some(device_id) = proof.verification_method.strip_prefix(&prefix) else {
            continue;
        };
        let Ok(device_id) = arkret_identifiers::DeviceId::new(device_id.to_owned()) else {
            // DID-control methods remain independently resolvable and do not
            // use principal device-directory evidence.
            continue;
        };
        if !seen.insert(proof.verification_method.clone()) {
            continue;
        }
        evidence.push(
            federated_device_signing_key_evidence(
                state,
                &event.actor_id,
                &device_id,
                &proof.verification_method,
            )
            .await?,
        );
    }
    Ok(evidence)
}

pub async fn federated_device_signing_key_evidence(
    state: &AppState,
    actor_id: &arkret_identifiers::Did,
    device_id: &arkret_identifiers::DeviceId,
    verification_method: &str,
) -> Result<arkret_wire::event_envelope::FederatedDeviceSigningKeyEvidence, String> {
    let expected_method = format!("{actor_id}#{device_id}");
    if verification_method != expected_method {
        return Err("device signing verification method is not actor_id#device_id".to_owned());
    }
    let facet =
        crate::routing::identity::cross_signing::try_resolve_device_signing_directory_facet(
            state,
            actor_id.as_str(),
            device_id.as_str(),
        )
        .await
        .map_err(|error| format!("device signing directory unavailable: {error}"))?;
    if !matches!(
        facet.status,
        arkret_models_crypto::keys::DeviceStatus::Active
    ) {
        return Err("device signer is not active".to_owned());
    }
    let device_signing_key = facet
        .signing_key_did
        .ok_or_else(|| "device signer key is unavailable".to_owned())?;
    let device_authorize_event_id = facet
        .device_authorize_event_id
        .ok_or_else(|| "device signer has no accepted authorization Event".to_owned())?;
    let device_authorize_record = state
        .event_query_application()
        .canonical_event(device_authorize_event_id.as_str())
        .await
        .map_err(|error| format!("device authorization Event lookup failed: {error}"))?
        .ok_or_else(|| "device authorization Event is unavailable".to_owned())?;
    let device_authorize_event =
        serde_json::from_value::<arkret_wire::Event>(device_authorize_record.envelope)
            .map_err(|error| format!("device authorization Event is invalid: {error}"))?;
    Ok(
        arkret_wire::event_envelope::FederatedDeviceSigningKeyEvidence {
            actor_id: actor_id.clone(),
            device_id: device_id.clone(),
            verification_method: verification_method.to_owned(),
            device_signing_key: arkret_wire::DidKey::new(device_signing_key)
                .map_err(|error| format!("device signer key is invalid: {error}"))?,
            authorization_accepted_at: device_authorize_record.received_at,
            device_authorize_event: Box::new(device_authorize_event),
        },
    )
}

/// The local service notary is anchored by the configured service identity
/// and the exact runtime notary key. It therefore does not depend on a cached
/// remote DID document in order to verify service-authored Events.
pub fn is_local_service_notary_method(
    state: &AppState,
    did: &Did,
    verification_method: &str,
) -> bool {
    did.as_str() == state.service_id()
        && verification_method == format!("{}#notary-key", state.service_id())
}

/// Resolve a DID URL to its Ed25519 [`VerifyingKey`] via the AppState
/// resolver chain. Adapter over
/// [`arkret_identity::jws::resolve_ed25519_pubkey`].
pub fn resolve_ed25519_pubkey(
    state: &AppState,
    verification_method: &str,
) -> Result<VerifyingKey, String> {
    arkret_identity::jws::resolve_ed25519_pubkey(
        state.did_application().resolver(),
        verification_method,
    )
    .map_err(|error| error.to_string())
}

pub async fn resolve_ed25519_pubkey_async(
    state: &AppState,
    verification_method: &str,
) -> Result<VerifyingKey, String> {
    let did = arkret_identity::verification_method_did(verification_method)
        .map_err(|error| error.to_string())?;
    let document = resolve_did_document_async(state, &did).await?;
    let resolver = ResolvedDidDocumentResolver {
        document: &document,
    };
    arkret_identity::jws::resolve_ed25519_pubkey(&resolver, verification_method)
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
        arkret_identity::jws::resolve_ed25519_pubkey(&resolver, verification_method)
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
    controller_id: &str,
    verification_method: &str,
) -> Result<(), String> {
    let Some(fragment) = verification_method
        .strip_prefix(controller_id)
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
        .did_application()
        .resolver()
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
        .did_application()
        .resolve_did(did)
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

    fn resolve_did(&self, did: &Did) -> arkret_identity::Result<DidDocument> {
        if self.supports(did) {
            return Ok(self.document.clone());
        }
        Err(arkret_identity::IdentityError::Protocol(
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
        .did_application()
        .document(did.as_str())
        .await
        .map_err(|error| format!("DID freshness lookup failed: {error}"))?;
    let Some(record) = record else {
        // No ingested record means no trusted freshness evidence for a
        // high-risk path, so fail closed.
        return Err(format!(
            "DID document freshness unavailable for high-risk verification: no ingested record for {did}"
        ));
    };
    match evaluate_did_document_freshness(&record, chrono::Utc::now(), max_age) {
        DidDocumentFreshness::Fresh => {
            state
                .did_application()
                .cache_resolved_document_state(record)
                .map_err(|error| format!("DID freshness cache failed: {error}"))?;
            Ok(())
        }
        DidDocumentFreshness::Stale => {
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

fn is_embedded_webvh_document(
    did: &Did,
    record: &soland_application::identity::DidDocumentState,
) -> bool {
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
    record: &soland_application::identity::DidDocumentState,
) -> Result<(), String> {
    if !is_embedded_webvh_document(did, record) {
        return Err("document is not a local embedded did:webvh record".to_owned());
    }

    let events = state
        .did_application()
        .log_events(did.as_str())
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
        .did_application()
        .store_document(record.clone())
        .await
        .map_err(|error| format!("DID document refresh write failed: {error}"))?;
    state
        .did_application()
        .cache_resolved_document_state(record.clone())
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
    if let Ok(Some(record)) = state.did_application().document(did.as_str()).await
        && let Some(head) = record.key_log_head
        && let Ok(hash) = Hash::new(head)
    {
        return Ok(hash);
    }
    let value = serde_json::to_value(document)
        .map_err(|error| format!("DID document serialization failed: {error}"))?;
    let digest = arkret_canonical::canonical_sha256(&value)
        .map_err(|error| format!("DID document canonical digest failed: {error}"))?;
    Hash::new(digest).map_err(|error| format!("DID document digest invalid: {error}"))
}
