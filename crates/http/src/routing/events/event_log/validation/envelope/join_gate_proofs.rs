//! Signature verification for `ak.member.state` join gate proofs.
//!
//! `join-policy.md` §4 rule 4 splits this check in two, and the split follows
//! what each layer can do. The reducer compares the binding tuple — Realm,
//! applicant, policy revision, freshness — because that is a pure function of
//! accepted state and replays identically everywhere. Resolving
//! `proofs[].verification_method` to a key the gate's provider or issuer
//! controls needs DID resolution, which a replaying reducer must not perform,
//! so it happens here on the admission path.
//!
//! Both halves are required. Without the tuple the same signature would admit
//! its holder to any Realm; without the signature the tuple is unattested
//! self-assertion.

use arkret_models_collaboration::governance::membership_invite::{
    JoinGateProof, JoinGateProofKind,
};

use super::*;

/// Reject a join whose gate proofs do not verify.
///
/// Failures are reported to a non-member as the single non-enumerable
/// `gate_check_failed` (`join-policy.md` §5): which gate failed, and whether
/// the Realm even carries one, are exactly what the caller must not learn.
pub(crate) async fn validate_join_gate_proof_signatures(
    object: &serde_json::Map<String, Value>,
    state: &AppState,
) -> Result<(), EventValidationError> {
    let Some(payload) = object.get("payload") else {
        return Ok(());
    };
    if payload.get("membership").and_then(Value::as_str) != Some("join") {
        return Ok(());
    }
    let Some(raw_proofs) = payload.get("gate_proofs").and_then(Value::as_array) else {
        return Ok(());
    };
    for raw in raw_proofs {
        // A proof that does not parse as the registered carrier is a schema
        // failure the reducer reports; this pass only judges signatures.
        let Ok(proof) = serde_json::from_value::<JoinGateProof>(raw.clone()) else {
            continue;
        };
        verify_gate_proof(&proof, state).await?;
    }
    Ok(())
}

async fn verify_gate_proof(
    proof: &JoinGateProof,
    state: &AppState,
) -> Result<(), EventValidationError> {
    // The controller the signature has to lead back to. `challenge_response`
    // binds to the gate provider named in the policy, `claim_required` to the
    // issuer the proof itself names, which the reducer separately confirms is
    // inside the gate's trusted issuer list.
    let issuer = match proof.kind {
        JoinGateProofKind::ChallengeResponse => provider_did_controller(proof)?,
        JoinGateProofKind::ClaimRequired => proof
            .issuer_id
            .as_ref()
            .ok_or_else(gate_check_failed)?
            .to_string(),
    };
    // Recomputed from the typed body, so a carried digest over some other
    // object cannot be presented alongside this one.
    let payload_digest = proof.payload_digest().map_err(|_| gate_check_failed())?;
    if proof.proofs.is_empty() {
        return Err(gate_check_failed());
    }
    for detached in &proof.proofs {
        if detached.payload_digest != payload_digest {
            return Err(gate_check_failed());
        }
        let binding = proof
            .proof_binding_object(detached)
            .map_err(|_| gate_check_failed())?;
        let canonical_bytes =
            arkret_canonical::canonical_json_bytes(&binding).map_err(|_| gate_check_failed())?;
        crate::jws_verify::verify_did_controlled_jws_async(
            &canonical_bytes,
            &detached.jws,
            detached.verification_method.as_str(),
            &issuer,
            state,
        )
        .await
        .map_err(|_| gate_check_failed())?;
    }
    Ok(())
}

/// The DID whose document must contain the challenge signer's key.
///
/// A `challenge_response` proof carries no issuer of its own: the authority is
/// the `provider_did` the accepted policy names, which the reducer matches the
/// proof's `gate_id` against. Reading it from the proof would let an applicant
/// nominate their own provider.
fn provider_did_controller(proof: &JoinGateProof) -> Result<String, EventValidationError> {
    let method = proof
        .proofs
        .first()
        .ok_or_else(gate_check_failed)?
        .verification_method
        .as_str();
    arkret_identity::verification_method_did(method)
        .map(|did| did.to_string())
        .map_err(|_| gate_check_failed())
}

fn gate_check_failed() -> EventValidationError {
    event_validation_error(
        StatusCode::FORBIDDEN,
        "failed_precondition",
        "gate_check_failed",
    )
}
