//! Soland thin adapter over the canonical detached-JWS verifier in the SDK.
//!
//! All JWS verification semantics (RFC 7515 detached shape, Ed25519
//! signature check, authority binding, replay-window timing) live in the
//! SDK so inkson, floria, cotest, teabay and soland share one
//! wire-compatible implementation. This module selects a document or accepted
//! key from [`AppState`], then hands pinned material to the resolver-free SDK
//! verifier. It also re-exports pure replay-window helpers.
//!
//! # Two-tier verifier model (unchanged)
//!
//! - Dev mode (`config.development_mode == true`): handlers use [`verify_jws_shape`] — RFC 7515
//!   §3.2 detached shape, alg=Ed25519, no zero-sentinel signature, no actual crypto. Lets test
//!   fixtures and local dev iterate without managing real keys.
//! - Production mode (default): handlers use [`verify_did_controlled_jws`] or its async
//!   counterpart. The selected document, issuer and verification-method DID root must agree before
//!   the SDK performs Ed25519 verification.

use std::collections::BTreeMap;

use arkret_identifiers::{DidFullId, Hash};
use arkret_identity::DidDocument;
use arkret_signatures::{
    Ed25519DetachedJwsVerifier, PublicKeyMaterial, VerifierError, build_proof_envelope,
};
use ed25519_dalek::{Signature, SigningKey, Verifier as _, VerifyingKey};
use serde_json::Value;
use soland_services::identity::{
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
    effective_window_for_projection, physical_millis_from_hlc, verify_replay_window,
    verify_replay_window_at, verify_replay_window_for_projection,
    verify_replay_window_for_projection_at,
};

/// Shape-only detached-JWS verifier for development mode.
///
/// This is intentionally colocated with soland's production SDK verifier
/// adapter so handlers do not define their own detached-JWS shape semantics.
/// Production mode still delegates to the SDK's resolver-free verifier.
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
    // §2.2 — even the development-mode shape verifier refuses a bare DID: a
    // proof key is always a `#fragment` DID URL.
    let verification_method = arkret_wire::DidUrl::new(verification_method.to_owned())
        .map_err(|error| format!("verification_method is not a DID URL: {error}"))?;
    let proof = build_proof_envelope(
        "detached_jws",
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

/// Production detached-JWS verifier for a DID-controlled method.
///
/// This synchronous form uses only deployment-local snapshots and configured
/// keys. Signature verification is delegated to the SDK after the document is
/// pinned; `issuer` is compared with both document id and the method's DID root.
pub fn verify_did_controlled_jws(
    canonical_bytes: &[u8],
    jws: &str,
    verification_method: &str,
    issuer: &str,
    state: &AppState,
) -> Result<(), String> {
    let did = arkret_identity::verification_method_did(verification_method)
        .map_err(|error| error.to_string())?;
    let issuer_did = DidFullId::new(issuer.to_owned()).map_err(|error| error.to_string())?;
    if did != issuer_did {
        return Err("verification method controller does not match issuer".to_owned());
    }
    let document = document_for_verification_sync(state, &did, verification_method)?;
    verify_jws_with_pinned_document(canonical_bytes, jws, verification_method, issuer, &document)
}

/// Async-native production Ed25519 detached-JWS verifier.
///
/// This resolves the DID document through soland's async resolver service
/// before delegating shape and signature verification to the SDK verifier.
pub async fn verify_did_controlled_jws_async(
    canonical_bytes: &[u8],
    jws: &str,
    verification_method: &str,
    issuer: &str,
    state: &AppState,
) -> Result<(), String> {
    let did = arkret_identity::verification_method_did(verification_method)
        .map_err(|error| error.to_string())?;
    let issuer_did = DidFullId::new(issuer.to_owned()).map_err(|error| error.to_string())?;
    if did != issuer_did {
        return Err("verification method controller does not match issuer".to_owned());
    }
    let document = document_for_verification(state, &did, verification_method).await?;
    verify_jws_with_pinned_document(canonical_bytes, jws, verification_method, issuer, &document)
}

/// Verify the protocol's compact Ed25519 signature carrier (a single
/// unpadded-base64url signature, not an RFC 7515 detached JWS) against a
/// DID-controlled method. `ProtocolSignature` uses this representation for
/// receipts and principal-service binding proofs.
pub async fn verify_did_controlled_ed25519_signature_async(
    payload: &[u8],
    signature_b64url: &str,
    verification_method: &str,
    issuer: &str,
    state: &AppState,
) -> Result<(), String> {
    let did = arkret_identity::verification_method_did(verification_method)
        .map_err(|error| error.to_string())?;
    let issuer_did = DidFullId::new(issuer.to_owned()).map_err(|error| error.to_string())?;
    if did != issuer_did {
        return Err("verification method controller does not match issuer".to_owned());
    }
    let document = document_for_verification(state, &did, verification_method).await?;
    let public_key_multibase = document
        .verification_methods
        .get(verification_method)
        .ok_or_else(|| "verification method is absent from DID document".to_owned())?;
    let public_key = arkret_canonical::decode_ed25519_multibase(public_key_multibase)
        .map_err(|error| format!("verification method key is invalid: {error}"))?;
    verify_ed25519_signature_with_public_key(payload, signature_b64url, &public_key)
}

/// Verify a compact Ed25519 signature and require the resolved DID method to
/// publish the exact multibase key carried by the signed protocol object.
/// This prevents an object from naming the right method id while embedding a
/// different attacker-controlled key.
pub async fn verify_did_controlled_ed25519_signature_with_public_key_async(
    payload: &[u8],
    signature_b64url: &str,
    verification_method: &str,
    issuer: &str,
    expected_public_key_multibase: &str,
    state: &AppState,
) -> Result<(), String> {
    let did = arkret_identity::verification_method_did(verification_method)
        .map_err(|error| error.to_string())?;
    let issuer_did = DidFullId::new(issuer.to_owned()).map_err(|error| error.to_string())?;
    if did != issuer_did {
        return Err("verification method controller does not match issuer".to_owned());
    }
    let document = document_for_verification(state, &did, verification_method).await?;
    let public_key_multibase = document
        .verification_methods
        .get(verification_method)
        .ok_or_else(|| "verification method is absent from DID document".to_owned())?;
    if public_key_multibase != expected_public_key_multibase {
        return Err("embedded verification key does not match the resolved DID method".to_owned());
    }
    let public_key = arkret_canonical::decode_ed25519_multibase(public_key_multibase)
        .map_err(|error| format!("verification method key is invalid: {error}"))?;
    verify_ed25519_signature_with_public_key(payload, signature_b64url, &public_key)
}

pub fn verify_ed25519_signature_with_public_key(
    payload: &[u8],
    signature_b64url: &str,
    public_key: &[u8; 32],
) -> Result<(), String> {
    if payload.is_empty() {
        return Err("empty signed payload".to_owned());
    }
    let signature_bytes = arkret_canonical::base64url_decode(signature_b64url)
        .map_err(|error| format!("signature is not unpadded base64url: {error}"))?;
    let signature = Signature::from_slice(&signature_bytes)
        .map_err(|_| "Ed25519 signature must be 64 bytes".to_owned())?;
    let verifying_key = VerifyingKey::from_bytes(public_key)
        .map_err(|_| "Ed25519 public key is invalid".to_owned())?;
    verifying_key
        .verify(payload, &signature)
        .map_err(|_| "Ed25519 signature verification failed".to_owned())
}

fn document_for_verification_sync(
    state: &AppState,
    did: &DidFullId,
    verification_method: &str,
) -> Result<DidDocument, String> {
    if is_local_service_notary_method(state, did, verification_method) {
        return Ok(DidDocument {
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
        });
    }
    if let Some(key) = state.federation_peer_verification_method_key(verification_method) {
        return Ok(DidDocument {
            id: did.clone(),
            verification_methods: BTreeMap::from([(
                verification_method.to_owned(),
                arkret_canonical::ed25519_pubkey_to_did_key_multibase(key.as_bytes()),
            )]),
            also_known_as: Vec::new(),
            updated_at: Some(chrono::Utc::now()),
            raw_properties: BTreeMap::new(),
        });
    }
    resolve_did_document(state, did)
}

/// Produce the DID document a JWS should be verified against.
///
/// Two deployment-local sources short-circuit any resolution: this service's
/// own notary key and an already-accepted federation peer key. Everything else
/// goes through [`resolve_did_document_async`], which prefers the durable local
/// DID store and only then the resolver chain.
async fn document_for_verification(
    state: &AppState,
    did: &DidFullId,
    verification_method: &str,
) -> Result<DidDocument, String> {
    if is_local_service_notary_method(state, did, verification_method) {
        return Ok(DidDocument {
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
        });
    }
    if let Some(key) = state.federation_peer_verification_method_key(verification_method) {
        return Ok(DidDocument {
            id: did.clone(),
            verification_methods: BTreeMap::from([(
                verification_method.to_owned(),
                arkret_canonical::ed25519_pubkey_to_did_key_multibase(key.as_bytes()),
            )]),
            also_known_as: Vec::new(),
            updated_at: Some(chrono::Utc::now()),
            raw_properties: BTreeMap::new(),
        });
    }
    resolve_did_document_async(state, did).await
}

/// Decode a pinned/historical DID document that a caller already selected by
/// version, log head or `accepted_at`, so it can be handed to the SDK's
/// zero-resolver verifier [`arkret_identity::verify_jws_with_document`].
///
/// This is a serde adapter, not a verifier: soland deliberately keeps **no**
/// private JWS-with-document implementation
/// (`did-usage-and-verification.md` §6 — one shared verifier layer).
pub fn decode_pinned_did_document(
    document_value: &serde_json::Value,
) -> Result<DidDocument, String> {
    serde_json::from_value::<DidDocument>(document_value.clone())
        .map_err(|error| format!("historical DID document decode failed: {error}"))
}

/// Verify a detached JWS against an already-pinned historical DID document.
///
/// Thin typed adapter over [`arkret_identity::verify_jws_with_document`]:
/// it parses the wire strings into `DidUrl` / `DidFullId`, records the signature
/// verification in metrics, and delegates every semantic check to the SDK.
/// **Zero resolver calls by construction** — the SDK entry point has no
/// resolver parameter.
pub fn verify_jws_with_pinned_document(
    canonical_bytes: &[u8],
    jws: &str,
    verification_method: &str,
    issuer: &str,
    document: &DidDocument,
) -> Result<(), String> {
    let verification_method = arkret_wire::DidUrl::new(verification_method.to_owned())
        .map_err(|error| format!("verification_method is not a DID URL: {error}"))?;
    let issuer_did = DidFullId::new(issuer.to_owned()).map_err(|error| error.to_string())?;
    let outcome = arkret_identity::verify_jws_with_document(
        canonical_bytes,
        jws,
        &verification_method,
        &issuer_did,
        document,
    )
    .map_err(|error| error.to_string());
    crate::metrics::record_signature_verify(
        crate::metrics::SIGNATURE_SCHEME_PINNED_DOCUMENT,
        outcome.is_ok(),
    );
    outcome
}

/// Principal-authorization verification error.
///
/// Generic principal authorization is fail-closed until the caller supplies
/// an exact authority instance and PCR-scoped device evidence. The sole
/// current-DID path below is restricted to registered identity-resolution
/// updates.
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

/// Key source used only by registered identity-resolution updates.
///
/// This path requires the current DID authority document. It deliberately does
/// not consult the PCR device directory, accepted-binding cache, service
/// routes, or development fixture keys.
enum PrincipalVerificationSource {
    AuthorityDocument(Box<DidDocument>),
}

async fn principal_verification_source(
    verification_method: &str,
    principal_id: &str,
    state: &AppState,
) -> Result<(DidFullId, PrincipalVerificationSource), PrincipalAuthorizedJwsError> {
    let method_did = arkret_identity::verification_method_did(verification_method)
        .map_err(|error| PrincipalAuthorizedJwsError::Verification(error.to_string()))?;
    let method_principal_id = arkret_wire::project_full_id_to_core_id(&method_did)
        .map_err(|error| PrincipalAuthorizedJwsError::Verification(error.to_string()))?;
    if method_principal_id.as_str() != principal_id {
        return Err(PrincipalAuthorizedJwsError::Verification(
            "verification method controller does not match principal".to_owned(),
        ));
    }
    if verification_method
        .strip_prefix(method_did.as_str())
        .and_then(|fragment| fragment.strip_prefix('#'))
        .is_some_and(|fragment| arkret_identifiers::DeviceId::new(fragment.to_owned()).is_ok())
    {
        return Err(PrincipalAuthorizedJwsError::Verification(
            "identity resolution updates require a current DID authority method, not a PCR device key"
                .to_owned(),
        ));
    }
    if method_did.method() != "key"
        && !is_local_service_notary_method(state, &method_did, verification_method)
    {
        enforce_high_risk_did_freshness(state, &method_did)
            .await
            .map_err(PrincipalAuthorizedJwsError::HighRiskDidFreshness)?;
    }
    let document = document_for_verification(state, &method_did, verification_method)
        .await
        .map_err(PrincipalAuthorizedJwsError::Verification)?;
    Ok((
        method_did,
        PrincipalVerificationSource::AuthorityDocument(Box::new(document)),
    ))
}

pub async fn verify_principal_authorized_jws_ed25519_async(
    _canonical_bytes: &[u8],
    _jws: &str,
    _verification_method: &str,
    _principal_id: &str,
    _state: &AppState,
) -> Result<(), PrincipalAuthorizedJwsError> {
    Err(PrincipalAuthorizedJwsError::Verification(
        "principal authorization requires an exact authority_instance and PCR-scoped device evidence"
            .to_owned(),
    ))
}

/// Generic compact Ed25519 principal authorization remains fail-closed without
/// an exact authority instance and PCR-scoped device evidence.
pub async fn verify_principal_authorized_ed25519_signature_async(
    _payload: &[u8],
    _signature_b64url: &str,
    _verification_method: &str,
    _principal_id: &str,
    _state: &AppState,
) -> Result<(), PrincipalAuthorizedJwsError> {
    Err(PrincipalAuthorizedJwsError::Verification(
        "principal authorization requires an exact authority_instance and PCR-scoped device evidence"
            .to_owned(),
    ))
}

/// Event-proof counterpart of [`verify_principal_authorized_jws_ed25519_async`].
///
/// # Why Event proofs may not use the generic entry point
///
/// An Event proof's JWS does not sign the bytes handed to a generic detached-JWS
/// verifier: per `encoding.md` §6 it signs the canonical **proof binding
/// object**, and the Event profile's protected header
/// (`arkret_signatures`' `DetachedJwsProtectedHeader`, `deny_unknown_fields`)
/// is strictly narrower than the generic one:
///
/// | check | Event profile (here) | generic profile |
/// | --- | --- | --- |
/// | `kid` header member | rejected | accepted and ignored |
/// | `header.alg` | must be `Ed25519` | must be `Ed25519` |
///
/// Reconstructing the binding bytes by hand and feeding them to the generic
/// verifier — which is what this call site used to do — therefore relaxed the
/// header checks on every DID-rooted Event proof. Every branch below routes
/// through an SDK Event-profile verifier instead, so the transcript, the digest
/// comparison and the header hygiene all come from one implementation.
///
/// `envelope_bytes` are the Event's canonical bytes with `proofs` / `unsigned`
/// stripped (`arkret_signatures::EventProofBuilder::envelope_bytes`); the SDK
/// re-derives `event_digest` from them and constant-time compares it to
/// `proof.event_digest`. `actor_id` is the Event envelope's `actor_id` — the
/// record subject folded into the signed transcript — which for delegated
/// execution differs from `principal_id`, the DID that owns the signing key.
pub async fn verify_principal_authorized_event_proof_async(
    _proof: &arkret_wire::Proof,
    _envelope_bytes: &[u8],
    _actor_id: &arkret_wire::DidCoreId,
    _verification_method: &str,
    _principal_id: &str,
    _state: &AppState,
) -> Result<(), PrincipalAuthorizedJwsError> {
    Err(PrincipalAuthorizedJwsError::Verification(
        "Event principal authorization requires an exact authority_instance and PCR-scoped device evidence"
            .to_owned(),
    ))
}

pub async fn verify_registered_identity_resolution_event_proof_async(
    proof: &arkret_wire::Proof,
    envelope_bytes: &[u8],
    actor_id: &arkret_wire::DidCoreId,
    verification_method: &str,
    principal_id: &str,
    state: &AppState,
) -> Result<(), PrincipalAuthorizedJwsError> {
    let (method_did, source) =
        principal_verification_source(verification_method, principal_id, state).await?;
    let PrincipalVerificationSource::AuthorityDocument(document) = source;
    // Build a one-shot binding only to use the SDK's strict Event-proof
    // verifier. It is not stored: every registered resolution update must
    // re-establish current DID authority and freshness.
    let accepted = principal_binding_acceptance(state, &method_did, verification_method, &document)
        .ok_or_else(|| {
            PrincipalAuthorizedJwsError::Verification(
                "resolved DID document does not form an acceptable current authority binding"
                    .to_owned(),
            )
        })?;
    let outcome = arkret_identity::verify_event_proof_with_binding(
        proof,
        envelope_bytes,
        actor_id,
        &accepted,
    )
    .map_err(|error| PrincipalAuthorizedJwsError::Verification(error.to_string()));
    crate::metrics::record_signature_verify(
        crate::metrics::SIGNATURE_SCHEME_PINNED_DOCUMENT,
        outcome.is_ok(),
    );
    outcome
}

/// Build the §5 binding key this deployment uses for principal-control
/// verification methods.
fn principal_binding_key(
    state: &AppState,
    did: &DidFullId,
    verification_method: &str,
) -> Option<arkret_identity::VerifiedDidBindingKey> {
    Some(arkret_identity::VerifiedDidBindingKey {
        did: did.clone(),
        trust_domain: state.did_binding_trust_domain().ok()?,
        purpose: arkret_identity::DidBindingPurpose::Principal,
        policy_digest: state.did_binding_policy_digest().ok()?,
        verification_method: Some(arkret_wire::DidUrl::new(verification_method.to_owned()).ok()?),
    })
}

/// Build the acceptance a successful authority verification represents, without
/// deciding whether it may be cached.
///
/// The pairing is itself a check: `AcceptedDidBinding::new` refuses a document
/// whose `id` is not the bound DID or whose canonical digest is not the one the
/// binding pins, so a caller can verify an Event proof against the result and
/// get the document-issuer check for free.
fn principal_binding_acceptance(
    state: &AppState,
    did: &DidFullId,
    verification_method: &str,
    document: &DidDocument,
) -> Option<arkret_identity::AcceptedDidBinding> {
    let key = principal_binding_key(state, did, verification_method)?;
    let document_digest = arkret_identity::document_canonical_digest(document).ok()?;
    let verified_at = chrono::Utc::now();
    // The acceptance inherits the high-risk freshness window that gated it, so
    // a binding can never outlive the evidence it rests on.
    let expires_at = verified_at + chrono::Duration::seconds(HIGH_RISK_DID_FRESHNESS_MAX_SECS);
    // §5.2 — the evidence digest is the digest of the canonical evidence
    // receipt, and the receipt is retained so an auditor can recompute it.
    // soland's resolver boundary surfaces no method proof set on this path, so
    // `method_proofs` is empty: that is the normative degenerate form for a
    // proofless resolution, not a placeholder standing in for evidence. It is
    // still strictly stronger than the `evidence_digest = document_digest` this
    // replaced, because the receipt also commits to the resolved method.
    let receipt = arkret_identity::EvidenceReceipt::new(
        did.method(),
        document_digest.clone(),
        &arkret_identity::MethodEvidence::none(),
    );
    let input = arkret_identity::VerifiedDidBindingInput {
        did: did.clone(),
        trust_domain: key.trust_domain.clone(),
        purpose: key.purpose,
        method: did.method().to_owned(),
        verification_method: key.verification_method.clone(),
        document_digest,
        history_head: None,
        version_id: None,
        // §5.5 — neither pin is available here, and this path cannot tell a
        // method that has no history from one whose history the resolver did not
        // surface, so both states are recorded rather than omitted.
        limited_trust: arkret_identity::LimitedTrust::for_proofless_method(None, None).record_for(),
        evidence_digest: receipt.digest().ok()?,
        evidence_dependencies: receipt.evidence_dependencies().ok()?,
        policy_digest: key.policy_digest.clone(),
        verified_at,
        refresh_after: None,
        expires_at: Some(expires_at),
        status: arkret_identity::DidBindingStatus::Active,
    };
    let binding = arkret_identity::VerifiedDidBinding::new(input).ok()?;
    arkret_identity::AcceptedDidBinding::new(binding, document.clone(), receipt).ok()
}

/// Resolve the active local device-directory evidence needed to verify an
/// original participant-signed Event on a remote Principal Server. The
/// returned evidence is carried only in the service-authenticated federation
/// wrapper; it never mutates the Event or its canonical digest.
pub async fn federated_event_signer_evidence(
    state: &AppState,
    event: &arkret_wire::Event,
) -> Result<Vec<arkret_wire::event_envelope::FederatedDeviceSigningKeyEvidence>, String> {
    let mut evidence = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for proof in &event.proofs {
        let Some((method_full_id, device_id)) = proof.verification_method.rsplit_once('#') else {
            continue;
        };
        let Ok(method_full_id) = arkret_wire::DidFullId::new(method_full_id.to_owned()) else {
            continue;
        };
        let Ok(method_actor_id) = arkret_wire::project_full_id_to_core_id(&method_full_id)
            .map(arkret_wire::DidCoreId::from)
        else {
            continue;
        };
        if method_actor_id != event.actor_id {
            continue;
        }
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
    actor_id: &arkret_wire::DidCoreId,
    device_id: &arkret_identifiers::DeviceId,
    verification_method: &str,
) -> Result<arkret_wire::event_envelope::FederatedDeviceSigningKeyEvidence, String> {
    use std::collections::BTreeMap;

    use arkret_wire::event_envelope::{
        FederatedCurrentDeviceProjection, FederatedDeviceGenerationState,
        FederatedDeviceGenerationStatus, FederatedDeviceRecord, FederatedDeviceStatus,
    };

    let (method_full_id, method_fragment) = verification_method
        .rsplit_once('#')
        .ok_or_else(|| "device signing verification method has no fragment".to_owned())?;
    let method_full_id =
        arkret_wire::DidFullId::new(method_full_id.to_owned()).map_err(|error| {
            format!("device signing verification method controller is invalid: {error}")
        })?;
    let method_actor_id = arkret_wire::DidCoreId::from(
        arkret_wire::project_full_id_to_core_id(&method_full_id).map_err(|error| {
            format!("device signing verification method controller cannot be projected: {error}")
        })?,
    );
    if &method_actor_id != actor_id || method_fragment != device_id.as_str() {
        return Err(
            "device signing verification method controller/fragment does not bind actor and device"
                .to_owned(),
        );
    }
    let facet =
        crate::routing::identity::device_signing::try_resolve_device_signing_directory_facet(
            state,
            actor_id.as_str(),
            device_id.as_str(),
        )
        .await
        .map_err(|error| format!("device signing directory unavailable: {error}"))?;
    if facet.status != arkret_models_crypto::keys::DeviceStatus::Active {
        return Err("device signer is not active".to_owned());
    }
    let device_signing_key = arkret_wire::DidKey::new(
        facet
            .signing_key_did
            .ok_or_else(|| "device signer key is unavailable".to_owned())?,
    )
    .map_err(|error| format!("device signer key is invalid: {error}"))?;
    let authorize_event_id = facet
        .device_authorize_event_id
        .ok_or_else(|| "device signer has no accepted authorization Event".to_owned())?;
    let generation_ref = facet
        .authorized_generation_ref
        .ok_or_else(|| "device signer has no active generation binding".to_owned())?;
    let generation = crate::routing::identity::device_generation::current_device_generation(
        state,
        actor_id.as_str(),
    )
    .await
    .map_err(|error| format!("device generation unavailable: {error}"))?
    .ok_or_else(|| "device generation is unavailable".to_owned())?;
    if generation.status
        != crate::routing::identity::device_generation::DeviceGenerationStatus::Active
        || generation.current_ref != generation_ref.as_str()
    {
        return Err("device signer is outside the active device generation".to_owned());
    }

    let authorize_record = state
        .event_queries()
        .canonical_event(authorize_event_id.as_str())
        .await
        .map_err(|error| format!("device authorization Event lookup failed: {error}"))?
        .ok_or_else(|| "device authorization Event is unavailable".to_owned())?;
    if authorize_record.actor_id != actor_id.as_str()
        || authorize_record.kind != arkret_wire::event_kind_str::DEVICE_AUTHORIZE
    {
        return Err("device authorization Event does not bind the requested actor".to_owned());
    }
    let control_realm = authorize_record
        .realm_id
        .as_deref()
        .ok_or_else(|| "device authorization Event has no PCR Realm".to_owned())?;
    let control_realm = arkret_wire::RealmId::new(control_realm.to_owned())
        .map_err(|error| format!("device authorization PCR Realm is invalid: {error}"))?;
    let mut realm_records = state
        .event_queries()
        .canonical_events()
        .await
        .map_err(|error| format!("PCR Realm history lookup failed: {error}"))?;
    realm_records.retain(|record| record.realm_id.as_deref() == Some(control_realm.as_str()));
    let mut records = state
        .event_queries()
        .canonical_events_for_realm_actor(control_realm.as_str(), actor_id.as_str())
        .await
        .map_err(|error| format!("PCR history lookup failed: {error}"))?;
    records.sort_by(|a, b| {
        a.actor_seq
            .cmp(&b.actor_seq)
            .then_with(|| a.event_id.cmp(&b.event_id))
    });
    let create = records
        .iter()
        .find(|record| {
            record.kind == arkret_wire::event_kind_str::REALM_CREATE
                && record
                    .envelope
                    .pointer("/payload/object/purpose")
                    .and_then(Value::as_str)
                    .is_some_and(|purpose| {
                        matches!(purpose, "principal_control" | "managed_agent_control")
                    })
        })
        .ok_or_else(|| "PCR genesis Event is unavailable".to_owned())?;
    let create_event_id = create.event_id.clone();
    let create_actor_seq = create.actor_seq;
    let mut authorization_chain = records
        .iter()
        .filter(|record| {
            record.actor_seq >= create_actor_seq
                && matches!(
                    record.kind.as_str(),
                    arkret_wire::event_kind_str::REALM_CREATE
                        | arkret_wire::event_kind_str::DEVICE_AUTHORIZE
                        | arkret_wire::event_kind_str::DEVICE_REVOKE
                        | arkret_wire::event_kind_str::DEVICE_REANCHOR
                        | arkret_wire::event_kind_str::DEVICE_LIST_UPDATE
                )
        })
        .map(|record| {
            crate::routing::events::event_log::sdk_event_for_state(state, record)
                .map_err(|error| format!("PCR authorization Event is invalid: {error}"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    authorization_chain.sort_by(|a, b| {
        a.actor_seq
            .cmp(&b.actor_seq)
            .then_with(|| a.event_id.as_str().cmp(b.event_id.as_str()))
    });
    if authorization_chain.len() < 2
        || authorization_chain[0].event_id.as_str() != create_event_id
        || !authorization_chain
            .iter()
            .any(|event| event.event_id == authorize_event_id)
    {
        return Err("PCR authorization chain is incomplete".to_owned());
    }
    let genesis_receipt = state
        .event_queries()
        .canonical_batch_receipts_for_event(&create_event_id)
        .await
        .map_err(|error| format!("PCR genesis receipt lookup failed: {error}"))?
        .into_iter()
        .find(|receipt| {
            receipt.pcr_genesis_scope().is_ok_and(|scope| {
                scope.principal_id == *actor_id && scope.realm_id == control_realm
            })
        })
        .ok_or_else(|| "PCR genesis receipt is unavailable".to_owned())?;
    let realm_id = control_realm;
    let chain_digests = authorization_chain
        .iter()
        .map(|event| event.event_digest().map_err(|error| error.to_string()))
        .collect::<Result<Vec<_>, _>>()?;
    let device_key_fragment = device_signing_key
        .as_str()
        .strip_prefix("did:key:")
        .ok_or_else(|| "device signer key is not did:key".to_owned())?;
    let did_key_method = format!("{}#{device_key_fragment}", device_signing_key);
    let accepted_seal = state
        .projections()
        .realm_seal_leaves(&realm_id)
        .map_err(|error| format!("PCR Seal lookup failed: {error}"))?
        .into_iter()
        .filter_map(|id| state.projections().seal_by_id(&id).ok().flatten())
        .find(|seal| {
            let signer_matches = matches!(
                &seal.notary_signature,
                arkret_wire::NotarySig::Single(signature)
                    if signature.verification_method.as_str() == verification_method
                        || signature.verification_method.as_str() == did_key_method.as_str()
            );
            signer_matches
                && chain_digests.iter().all(|digest| {
                    seal.covered_event_digests
                        .iter()
                        .any(|covered| covered.as_str() == digest)
                })
        })
        .ok_or_else(|| {
            "no target-device Seal covers the complete PCR authorization chain".to_owned()
        })?;

    let projection = FederatedCurrentDeviceProjection {
        principal_id: actor_id.clone(),
        device_id: device_id.clone(),
        device_record: FederatedDeviceRecord {
            algorithms: BTreeMap::new(),
            device_signing_key: Some(device_signing_key.clone()),
            hpke_key: facet
                .hpke_key
                .map(arkret_wire::NonEmptyString::new)
                .transpose()
                .map_err(|error| format!("device HPKE key is invalid: {error}"))?,
            trust_algorithms: facet
                .trust_algorithms
                .map(|items| {
                    items
                        .into_iter()
                        .map(arkret_wire::NonEmptyString::new)
                        .collect::<Result<Vec<_>, _>>()
                })
                .transpose()
                .map_err(|error| format!("trust algorithm is invalid: {error}"))?,
            device_status: Some(FederatedDeviceStatus::Active),
            device_authorize_event_id: Some(authorize_event_id.clone()),
            authorized_generation_ref: Some(generation_ref.clone()),
        },
        generation_state: FederatedDeviceGenerationState {
            current_device_generation_ref: generation_ref,
            device_generation_status: FederatedDeviceGenerationStatus::Active,
        },
    };
    let accepted_at = records
        .iter()
        .find(|record| record.event_id == authorize_event_id.as_str())
        .map(|record| record.received_at)
        .ok_or_else(|| "device authorization acceptance timestamp is unavailable".to_owned())?;
    let _ = (
        device_signing_key,
        accepted_at,
        genesis_receipt,
        authorization_chain,
        accepted_seal,
        projection,
        federated_range_completeness_evidence(state, &realm_id, &realm_records)?,
    );
    Err(
        "PCR registration accepted-at DID evidence is unavailable; refusing to emit incomplete federated device evidence"
            .to_owned(),
    )
}

fn federated_range_completeness_evidence(
    state: &AppState,
    realm_id: &arkret_identifiers::RealmId,
    records: &[soland_services::events::CanonicalEventRecord],
) -> Result<Vec<arkret_wire::Event>, String> {
    use std::collections::BTreeMap;

    use arkret_models_collaboration::sync_frames::snapshot::{
        RangeCompletenessAttestation, RangeCompletenessAttestationEventRange,
        RangeCompletenessAttestationEventRangeFromFrontier,
        RangeCompletenessAttestationEventRangeToFrontier,
        RangeCompletenessAttestationWitnessAttestation,
        RangeCompletenessAttestationWitnessAttestationWitnessesItem,
    };
    use arkret_signatures::{Ed25519PayloadSigner, SignEventOptions, sign_event_with_digest_suite};
    use arkret_wire::{
        Event, EventId, EventKind, EventRequirements, PayloadProof, PayloadProofPurpose,
        PayloadSigner, ScopeRef, proof_kind,
    };

    let mut accepted_events = records
        .iter()
        .map(|record| {
            crate::routing::events::event_log::canonical_event_from_record(record)
                .map_err(|error| format!("PCR range Event is invalid: {error}"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    accepted_events.sort_by(|a, b| {
        a.created_at
            .cmp(&b.created_at)
            .then_with(|| a.event_id.as_str().cmp(b.event_id.as_str()))
    });
    let (from_frontier, to_frontier) =
        arkret_state::full_realm_range_frontiers(&accepted_events)
            .map_err(|error| format!("PCR range frontier failed: {error}"))?;
    let range_events = arkret_state::full_realm_range_events(&accepted_events)
        .map_err(|error| format!("PCR range selection failed: {error}"))?;
    let actor_seq_ranges = arkret_state::range_completeness_actor_seq_ranges(&range_events)
        .map_err(|error| format!("PCR actor range failed: {error}"))?;
    if actor_seq_ranges.is_empty() {
        return Err("PCR range completeness has no actor sequence range".to_owned());
    }
    let digest_suite = state.projections().realm_digest_suite(realm_id.as_str());
    let (root, covered_event_ids) =
        arkret_state::range_completeness_root_with_suite(&range_events, digest_suite)
            .map_err(|error| format!("PCR range root failed: {error}"))?;
    let issuer = state.service_resolution_commitment().full_id.clone();
    let issuer_actor = arkret_wire::DidCoreId::from(
        arkret_wire::project_full_id_to_core_id(&issuer)
            .map_err(|error| format!("service issuer projection is invalid: {error}"))?,
    );
    let verification_method = arkret_wire::DidUrl::new(format!("{issuer}#notary-key"))
        .map_err(|error| format!("service notary method is invalid: {error}"))?;
    let observed_at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
    let signer = Ed25519PayloadSigner::new(
        state.notary_signing_key().as_ref().clone(),
        issuer.clone(),
        verification_method.clone(),
    );
    let mut payload = RangeCompletenessAttestation {
        attestation_id: crate::ids::generate("attestation"),
        schema: "ak.schema.range_completeness_attestation.v1".to_owned(),
        issuer: issuer_actor.clone(),
        issuer_role: "federation_device_evidence".to_owned(),
        realm_id: realm_id.clone(),
        event_range: RangeCompletenessAttestationEventRange {
            from_frontier: RangeCompletenessAttestationEventRangeFromFrontier {
                realm_frontier: from_frontier,
                extra: BTreeMap::new(),
            },
            to_frontier: RangeCompletenessAttestationEventRangeToFrontier {
                realm_frontier: to_frontier.clone(),
                extra: BTreeMap::new(),
            },
            actor_seq_ranges,
        },
        root,
        count: covered_event_ids.len() as u64,
        observed_at,
        witness_attestation: RangeCompletenessAttestationWitnessAttestation {
            kind: "single_source".to_owned(),
            witnesses: vec![
                RangeCompletenessAttestationWitnessAttestationWitnessesItem {
                    issuer: issuer_actor.clone(),
                    verification_method: verification_method.clone(),
                    controlling_organization: issuer_actor.clone(),
                    attested_at: Some(observed_at),
                    extra: BTreeMap::new(),
                },
            ],
        },
        proofs: Vec::new(),
    };
    let mut unsigned = serde_json::to_value(&payload).map_err(|error| error.to_string())?;
    unsigned
        .as_object_mut()
        .ok_or_else(|| "range payload is not an object".to_owned())?
        .remove("proofs");
    let canonical =
        arkret_canonical::canonical_json_bytes(&unsigned).map_err(|error| error.to_string())?;
    let mut proof = PayloadProof {
        kind: proof_kind::DETACHED_JWS.to_owned(),
        verification_method: verification_method.clone(),
        payload_digest: arkret_wire::Hash::new(arkret_canonical::sha256_digest(&canonical))
            .map_err(|error| error.to_string())?,
        created_at: observed_at,
        domain: None,
        audience: None,
        proof_purpose: Some(PayloadProofPurpose::IssuerAttestation),
        jws: String::new(),
    };
    let binding = payload
        .proof_binding_bytes(&proof)
        .map_err(|error| error.to_string())?;
    proof.jws = signer
        .sign_payload(&binding)
        .map_err(|error| error.to_string())?
        .jws;
    payload.proofs.push(proof);
    let Value::Object(payload) =
        serde_json::to_value(payload).map_err(|error| error.to_string())?
    else {
        return Err("range payload is not an object".to_owned());
    };
    let actor_seq = accepted_events
        .iter()
        .filter(|event| event.actor_id == issuer_actor)
        .map(|event| event.actor_seq)
        .max()
        .map_or(0, |seq| seq.saturating_add(1));
    let mut event = Event {
        event_id: EventId::new("ak:event:ASyOHakrqmsRPkLKvhTD20V-YWCl-X7zYrlca5tdQLaR")
            .map_err(|error| error.to_string())?,
        kind: EventKind::AttestationRangeCompleteness,
        realm_id: realm_id.clone(),
        scope_ref: ScopeRef::Realm {
            realm_id: realm_id.clone(),
        },
        actor_id: issuer_actor,
        executed_by: None,
        authorization_ref: None,
        applet_id: None,
        external_ref: None,
        actor_kind: None,
        actor_seq,
        created_at: observed_at,
        hlc: None,
        prev_refs: to_frontier,
        refs: Vec::new(),
        causal_refs: Vec::new(),
        preconditions: Vec::new(),
        seal_ref: None,
        auth_context: None,
        seal_basis: None,
        payload: payload.into_iter().collect(),
        redacts: None,
        unsigned: BTreeMap::new(),
        proofs: Vec::new(),
        requirements: EventRequirements::default(),
    };
    event.event_id = event
        .derive_event_id_with_digest_suite(digest_suite)
        .map_err(|error| error.to_string())?;
    sign_event_with_digest_suite(
        &mut event,
        &signer,
        &verification_method,
        digest_suite,
        SignEventOptions::new().with_created_at(observed_at),
    )
    .map_err(|error| error.to_string())?;
    Ok(vec![event])
}

/// The local service notary is anchored by the configured service identity
/// and the exact runtime notary key. It therefore does not depend on a cached
/// remote DID document in order to verify service-authored Events.
pub fn is_local_service_notary_method(
    state: &AppState,
    did: &DidFullId,
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
    arkret_identity::jws::resolve_ed25519_pubkey(state.dids().resolver(), verification_method)
        .map_err(|error| error.to_string())
}

pub async fn resolve_ed25519_pubkey_async(
    state: &AppState,
    verification_method: &str,
) -> Result<VerifyingKey, String> {
    let did = arkret_identity::verification_method_did(verification_method)
        .map_err(|error| error.to_string())?;
    let document = resolve_did_document_async(state, &did).await?;
    arkret_identity::jws::resolve_ed25519_pubkey_from_document(&document, verification_method)
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
    did: &DidFullId,
    verification_method: &str,
) -> Result<ResolvedVerificationKey, String> {
    validate_verification_method_controller(did.as_str(), verification_method)?;
    let document = resolve_did_document_async(state, did).await?;
    require_verification_method_in_document(&document, verification_method)?;
    let public_key =
        arkret_identity::jws::resolve_ed25519_pubkey_from_document(&document, verification_method)
            .map_err(|error| error.to_string())?;
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

pub fn resolve_did_document(state: &AppState, did: &DidFullId) -> Result<DidDocument, String> {
    let document = state
        .dids()
        .resolver()
        .resolve_did_document(did)
        .map_err(|error| format!("DID resolution failed: {error}"))?;
    if document.id != *did {
        return Err("resolved DID document id does not match requested DID".to_owned());
    }
    Ok(document)
}

pub async fn resolve_did_document_async(
    state: &AppState,
    did: &DidFullId,
) -> Result<DidDocument, String> {
    let document = state
        .dids()
        .resolve_did(did)
        .await
        .map_err(|error| format!("DID resolution failed: {error}"))?;
    if document.id != *did {
        return Err("resolved DID document id does not match requested DID".to_owned());
    }
    Ok(document)
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
/// inside the SDK resolver chain; this gate only covers cached remote/submitted
/// documents.
///
/// Because soland does not perform on-demand network fetches, "stale" means
/// "unavailable" for high-risk writes; degraded read-only relaxation does not
/// apply here.
pub async fn enforce_high_risk_did_freshness(
    state: &AppState,
    did: &DidFullId,
) -> Result<(), String> {
    // `did:key` is locally resolvable but has neither a version id nor a
    // history head. `did-usage-and-verification.md` section 5.5 requires high
    // risk authority paths to reject every non-pinned binding, including the
    // otherwise legitimate `method_unsupported` terminal state. Persisting a
    // synthetic document must not turn a bootstrap/test DID into a rotatable,
    // history-pinned authority.
    if did.method() == "key" {
        return Err(format!(
            "DID method did:key cannot satisfy high-risk history and version pinning: {did}"
        ));
    }
    let max_age = chrono::Duration::seconds(HIGH_RISK_DID_FRESHNESS_MAX_SECS);
    let record = state
        .dids()
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
                .cache_resolved_did_document(record)
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
    did: &DidFullId,
    record: &soland_services::identity::DidDocumentState,
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
    did: &DidFullId,
    record: &soland_services::identity::DidDocumentState,
) -> Result<(), String> {
    if !is_embedded_webvh_document(did, record) {
        return Err("document is not a local embedded did:webvh record".to_owned());
    }

    let events = state
        .dids()
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
        .dids()
        .store_document(record.clone())
        .await
        .map_err(|error| format!("DID document refresh write failed: {error}"))?;
    state
        .cache_resolved_did_document(record.clone())
        .map_err(|error| format!("DID document refresh cache failed: {error}"))?;
    Ok(())
}

/// High-risk variant of [`resolve_ed25519_verification_key_for_did`]: enforce
/// freshness before resolving the public key. High-risk callers such as
/// federation receive and recovery use this variant. Read-side callers that
/// do not need fail-closed semantics can still call the non-`_fresh` version.
pub async fn resolve_ed25519_verification_key_for_did_fresh(
    state: &AppState,
    did: &DidFullId,
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
    did: &DidFullId,
    document: &DidDocument,
) -> Result<Hash, String> {
    if let Ok(Some(record)) = state.dids().document(did.as_str()).await
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

#[cfg(test)]
mod did_binding_tests {
    use ed25519_dalek::SigningKey;
    use soland_storage_postgres::Db;

    use super::*;

    const PRINCIPAL: &str = "did:web:principal.example";

    /// A state whose resolver chain has no document for [`PRINCIPAL`]. The
    /// `web` method remains registered so the resolver-policy digest is valid
    /// and an accepted binding can be keyed by that policy. Any verification
    /// that succeeds after seeding the binding therefore used the binding; an
    /// authority-path lookup still fails because no document was ingested.
    fn state_without_any_resolver() -> AppState {
        AppState::new(
            crate::config::AppConfig {
                object_storage: crate::config::ObjectStorageConfig::local(
                    std::env::temp_dir().join("soland-did-binding-test"),
                ),
                did_resolver_allow_methods: vec!["web".to_owned()],
                jws_replay_window_seconds: 0,
                ..crate::config::AppConfig::test_default()
            },
            Db { pool: None },
        )
    }

    fn document_for(did: &DidFullId, verification_method: &str, key: &SigningKey) -> DidDocument {
        DidDocument {
            id: did.clone(),
            verification_methods: BTreeMap::from([(
                verification_method.to_owned(),
                arkret_canonical::ed25519_pubkey_to_did_key_multibase(
                    key.verifying_key().as_bytes(),
                ),
            )]),
            also_known_as: Vec::new(),
            updated_at: Some(chrono::Utc::now()),
            raw_properties: BTreeMap::new(),
        }
    }

    fn did_key_authority(key: &SigningKey) -> (DidFullId, String) {
        let multibase =
            arkret_canonical::ed25519_pubkey_to_did_key_multibase(key.verifying_key().as_bytes());
        let did = DidFullId::new(format!("did:key:{multibase}")).unwrap();
        let verification_method = format!("{did}#{multibase}");
        (did, verification_method)
    }

    fn signed(key: &SigningKey, payload: &[u8]) -> String {
        arkret_signatures::sign_ed25519_detached_jws(key, payload).expect("detached JWS")
    }

    // §3 / §4 row 4 — historical replay: an Event accepted under the old
    // version still verifies against the document pinned at that time, while the
    // current document refuses the same signature.
    #[test]
    fn historical_replay_uses_the_pinned_document_not_the_current_one() {
        let did = DidFullId::new(PRINCIPAL.to_owned()).unwrap();
        let verification_method = format!("{did}#control-1");
        let old_key = SigningKey::from_bytes(&[9u8; 32]);
        let new_key = SigningKey::from_bytes(&[10u8; 32]);
        let pinned = document_for(&did, &verification_method, &old_key);
        let current = document_for(&did, &verification_method, &new_key);

        let payload = b"historical-event";
        let jws = signed(&old_key, payload);
        verify_jws_with_pinned_document(payload, &jws, &verification_method, did.as_str(), &pinned)
            .expect("the pinned historical document still authenticates the old Event");
        verify_jws_with_pinned_document(
            payload,
            &jws,
            &verification_method,
            did.as_str(),
            &current,
        )
        .expect_err("the rotated current document must not accept the old key");
    }

    #[test]
    fn pinned_document_rejects_issuer_and_method_controller_mismatch() {
        let issuer = DidFullId::new(PRINCIPAL.to_owned()).unwrap();
        let other = DidFullId::new("did:web:other.example".to_owned()).unwrap();
        let verification_method = format!("{issuer}#control-1");
        let key = SigningKey::from_bytes(&[11u8; 32]);
        let document = document_for(&issuer, &verification_method, &key);
        let payload = b"issuer-bound-object";
        let jws = signed(&key, payload);

        verify_jws_with_pinned_document(
            payload,
            &jws,
            &verification_method,
            other.as_str(),
            &document,
        )
        .expect_err("a valid signature cannot substitute a different issuer");

        let other_method = format!("{other}#control-1");
        let other_document = document_for(&issuer, &other_method, &key);
        verify_jws_with_pinned_document(
            payload,
            &signed(&key, payload),
            &other_method,
            issuer.as_str(),
            &other_document,
        )
        .expect_err("a method rooted in another DID cannot control the issuer");
    }

    // ========================================================================
    // Event proof protected-header hygiene (`encoding.md` §6)
    //
    // These are the regression tests for routing Event proofs through the
    // generic detached-JWS verifier. Each one pairs the Event-profile rejection
    // with a control showing the **generic** profile accepts the very same JWS,
    // so a failure can only mean the Event path degraded back to the generic
    // one — not that the fixture signature happens to be broken.
    // ========================================================================

    /// Sign `payload` as a detached JWS whose protected header is exactly
    /// `header`, including members the Event profile forbids.
    fn detached_jws_with_header(
        key: &SigningKey,
        header: &serde_json::Value,
        payload: &[u8],
    ) -> String {
        use base64::Engine as _;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use ed25519_dalek::Signer as _;

        let header_b64 = URL_SAFE_NO_PAD
            .encode(arkret_canonical::canonical_json_bytes(header).expect("canonical header"));
        let signing_input = format!("{header_b64}.{}", URL_SAFE_NO_PAD.encode(payload));
        let signature = key.sign(signing_input.as_bytes());
        format!(
            "{header_b64}..{}",
            URL_SAFE_NO_PAD.encode(signature.to_bytes())
        )
    }

    /// A minimal but genuine Event proof: real envelope bytes, an
    /// `event_digest` actually derived from them, and the canonical
    /// proof-binding transcript the JWS has to sign.
    fn event_proof_fixture(verification_method: &str) -> (Vec<u8>, arkret_wire::Proof) {
        let envelope_bytes =
            br#"{"actor_id":"did:web:principal.example","kind":"ak.test.event"}"#.to_vec();
        let event_digest =
            Hash::new(arkret_canonical::sha256_digest(&envelope_bytes)).expect("event digest");
        let proof = build_proof_envelope(
            "detached_jws",
            arkret_wire::DidUrl::new(verification_method.to_owned()).expect("DID URL"),
            event_digest,
            None,
            None,
            "",
        );
        (envelope_bytes, proof)
    }

    #[tokio::test]
    async fn identity_resolution_update_rejects_pcr_device_method() {
        let state = state_without_any_resolver();
        let did = DidFullId::new(PRINCIPAL.to_owned()).unwrap();
        let device_id = "ak:device:01904100-0000-7000-8000-000000000002";
        let verification_method = format!("{did}#{device_id}");
        let (envelope_bytes, proof) = event_proof_fixture(&verification_method);
        let actor_id = crate::test_actor_id(&did);

        let error = verify_registered_identity_resolution_event_proof_async(
            &proof,
            &envelope_bytes,
            &actor_id,
            &verification_method,
            actor_id.as_str(),
            &state,
        )
        .await
        .expect_err("PCR device keys must not replace current DID authority");
        assert!(error.to_string().contains("current DID authority method"));
    }

    /// The Event protected header is `deny_unknown_fields` and knows no `kid`.
    /// The generic header type accepts `kid` and merely reports it, so a proof
    /// carrying one used to sail through this call site.
    #[tokio::test]
    async fn an_event_proof_with_a_kid_protected_header_is_rejected() {
        let state = state_without_any_resolver();
        let key = SigningKey::from_bytes(&[9u8; 32]);
        let (did, verification_method) = did_key_authority(&key);

        let (envelope_bytes, mut proof) = event_proof_fixture(&verification_method);
        let actor_id = crate::test_actor_id(&did);
        let binding_bytes = proof
            .canonical_binding_bytes(&actor_id)
            .expect("binding bytes");
        let jws = detached_jws_with_header(
            &key,
            &serde_json::json!({"alg": "Ed25519", "kid": verification_method}),
            &binding_bytes,
        );
        proof.jws = jws.clone();

        // The Event profile must not.
        verify_registered_identity_resolution_event_proof_async(
            &proof,
            &envelope_bytes,
            &actor_id,
            &verification_method,
            actor_id.as_str(),
            &state,
        )
        .await
        .expect_err("an Event proof protected header may not carry `kid`");
    }

    /// Both Event and generic Ed25519 profiles reject a protected header that
    /// selects a different algorithm.
    #[tokio::test]
    async fn an_event_proof_with_an_unsupported_protected_algorithm_is_rejected() {
        let state = state_without_any_resolver();
        let key = SigningKey::from_bytes(&[9u8; 32]);
        let (did, verification_method) = did_key_authority(&key);

        let (envelope_bytes, mut proof) = event_proof_fixture(&verification_method);
        let actor_id = crate::test_actor_id(&did);
        let binding_bytes = proof
            .canonical_binding_bytes(&actor_id)
            .expect("binding bytes");
        let jws =
            detached_jws_with_header(&key, &serde_json::json!({"alg": "ES256"}), &binding_bytes);
        proof.jws = jws.clone();

        verify_principal_authorized_jws_ed25519_async(
            &binding_bytes,
            &jws,
            &verification_method,
            did.as_str(),
            &state,
        )
        .await
        .expect_err("the generic Ed25519 profile must reject ES256");

        verify_registered_identity_resolution_event_proof_async(
            &proof,
            &envelope_bytes,
            &actor_id,
            &verification_method,
            actor_id.as_str(),
            &state,
        )
        .await
        .expect_err("the Event Ed25519 profile must reject ES256");
    }

    /// Positive control for the two rejections above: a clean current
    /// self-certifying DID authority verifies without any cached binding.
    #[tokio::test]
    async fn a_well_formed_resolution_event_proof_verifies_current_did_authority() {
        let state = state_without_any_resolver();
        let key = SigningKey::from_bytes(&[9u8; 32]);
        let (did, verification_method) = did_key_authority(&key);

        let (envelope_bytes, mut proof) = event_proof_fixture(&verification_method);
        let actor_id = crate::test_actor_id(&did);
        let binding_bytes = proof
            .canonical_binding_bytes(&actor_id)
            .expect("binding bytes");
        proof.jws =
            detached_jws_with_header(&key, &serde_json::json!({"alg": "Ed25519"}), &binding_bytes);

        verify_registered_identity_resolution_event_proof_async(
            &proof,
            &envelope_bytes,
            &actor_id,
            &verification_method,
            actor_id.as_str(),
            &state,
        )
        .await
        .expect("a well-formed Event proof verifies through current DID authority");
    }

    /// The Event verifier re-derives `event_digest` from the envelope bytes it
    /// is handed, so a proof whose transcript names a different Event cannot be
    /// replayed onto this one even with a valid signature.
    #[tokio::test]
    async fn an_event_proof_bound_to_other_envelope_bytes_is_rejected() {
        let state = state_without_any_resolver();
        let key = SigningKey::from_bytes(&[9u8; 32]);
        let (did, verification_method) = did_key_authority(&key);

        let (_, mut proof) = event_proof_fixture(&verification_method);
        let actor_id = crate::test_actor_id(&did);
        let binding_bytes = proof
            .canonical_binding_bytes(&actor_id)
            .expect("binding bytes");
        proof.jws =
            detached_jws_with_header(&key, &serde_json::json!({"alg": "Ed25519"}), &binding_bytes);

        verify_registered_identity_resolution_event_proof_async(
            &proof,
            br#"{"actor_id":"did:web:principal.example","kind":"ak.other.event"}"#,
            &actor_id,
            &verification_method,
            actor_id.as_str(),
            &state,
        )
        .await
        .expect_err("the proof transcript is bound to the Event it was signed over");
    }
}
