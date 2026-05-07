//! Proof verification primitives shared by `repo`, `message`, and `events`.
//!
//! Two verifier shapes:
//! - `DevProofVerifier` — legacy fallback that only checks
//!   `Commit::validate_for_submit`. Used by internal handlers that inject
//!   `dev_proof` (revise/redact/reaction). Production commits go through
//!   `ProofVerifier::for_state` instead.
//! - `ProofVerifier` — service-DID + author + audience + `created_at`-window
//!   binding (rejects `alg: none` and `dev-proof` placeholders in production
//!   mode; see `SERVERX_DEVELOPMENT_MODE=false` semantics in the README).
//!
//! Helper fns (`validate_proof_author_binding`, `validate_proof_service_binding`,
//! `validate_proof_created_at_binding`, `verification_method_did`,
//! `proof_audience_contains`) are re-used across both verifiers and exposed
//! `pub` so the operation/event validators can reuse the same per-proof
//! invariants if/when they need to.

use contrix_sdk::{Audience, Commit, CommitProofVerifier, Did, Hash, Proof};

use crate::state::AppState;

use super::now;

/// Legacy dev-only verifier kept for internal handlers that inject dev_proof.
/// Accepts any non-empty proof list. For client-facing commits, use `ProofVerifier`.
pub struct DevProofVerifier;
impl CommitProofVerifier for DevProofVerifier {
    fn verify_commit(&self, commit: &Commit) -> contrix_sdk::Result<()> {
        commit.validate_for_submit()
    }
}

/// and verifies that each proof's `payload_hash` matches the commit's canonical digest.
pub struct ProofVerifier {
    pub development_mode: bool,
    pub service_did: String,
}

impl ProofVerifier {
    pub fn for_state(state: &AppState) -> Self {
        Self {
            development_mode: state.config.development_mode,
            service_did: state.config.service_did.clone(),
        }
    }
}

impl CommitProofVerifier for ProofVerifier {
    fn verify_commit(&self, commit: &Commit) -> contrix_sdk::Result<()> {
        commit.validate_for_submit()?;
        if self.development_mode {
            return Ok(());
        }
        let commit_digest = commit.commit_digest()?;
        for proof in &commit.proofs {
            proof.validate_production()?;
            if proof.jws == "dev-proof" {
                return Err(contrix_sdk::Error::Protocol(
                    "production commits must not use dev-proof placeholder".to_owned(),
                ));
            }
            if proof.payload_hash.as_str() != commit_digest {
                return Err(contrix_sdk::Error::Protocol(format!(
                    "proof payload_hash {} does not match commit digest {}",
                    proof.payload_hash, commit_digest
                )));
            }
            validate_proof_author_binding(proof, &commit.author)?;
            validate_proof_service_binding(proof, &self.service_did)?;
            validate_proof_created_at_binding(proof, commit.created_at)?;
        }
        Ok(())
    }
}

pub fn validate_proof_author_binding(proof: &Proof, author: &Did) -> contrix_sdk::Result<()> {
    let Some(method_did) = verification_method_did(&proof.verification_method) else {
        return Err(contrix_sdk::Error::Protocol(
            "proof verification_method must be a DID URL with a key fragment".to_owned(),
        ));
    };
    if method_did != author.as_str() {
        return Err(contrix_sdk::Error::Protocol(format!(
            "proof verification_method DID '{}' does not match commit author '{}'",
            method_did, author
        )));
    }
    Ok(())
}

pub fn verification_method_did(verification_method: &str) -> Option<&str> {
    let (did, key_fragment) = verification_method.split_once('#')?;
    (!did.is_empty() && did.starts_with("did:") && !key_fragment.is_empty()).then_some(did)
}

pub fn validate_proof_service_binding(proof: &Proof, service_did: &str) -> contrix_sdk::Result<()> {
    if proof.domain.as_deref() != Some(service_did) {
        return Err(contrix_sdk::Error::Protocol(format!(
            "proof domain must bind to service DID '{}'",
            service_did
        )));
    }
    if !proof_audience_contains(&proof.audience, service_did) {
        return Err(contrix_sdk::Error::Protocol(format!(
            "proof audience must include service DID '{}'",
            service_did
        )));
    }
    Ok(())
}

pub fn proof_audience_contains(audience: &Option<Audience>, expected: &str) -> bool {
    match audience {
        Some(Audience::Single(value)) => value == expected,
        Some(Audience::Multiple(values)) => values.iter().any(|value| value == expected),
        None => false,
    }
}

pub fn validate_proof_created_at_binding(
    proof: &Proof,
    commit_created_at: chrono::DateTime<chrono::Utc>,
) -> contrix_sdk::Result<()> {
    let diff = if proof.created_at > commit_created_at {
        proof.created_at - commit_created_at
    } else {
        commit_created_at - proof.created_at
    };
    if diff > chrono::Duration::minutes(5) {
        return Err(contrix_sdk::Error::Protocol(
            "proof created_at must be within 5 minutes of commit created_at".to_owned(),
        ));
    }
    Ok(())
}

pub fn dev_proof(actor: &str) -> Proof {
    Proof {
        kind: "detached_jws".to_owned(),
        alg: "none".to_owned(),
        verification_method: format!("{actor}#dev"),
        payload_hash: Hash::new(
            "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        )
        .expect("valid hash"),
        created_at: now(),
        domain: Some("soland-dev".to_owned()),
        audience: None,
        jws: "dev-proof".to_owned(),
    }
}
