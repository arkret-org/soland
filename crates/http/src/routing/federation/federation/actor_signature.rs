use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, Verifier as _};
use salvo::http::StatusCode;
use soland_http::error::AppError;

use crate::state::AppState;

pub(super) struct VerifiedFederationActor {
    pub(super) verified_key_id: String,
    pub(super) did_document_ref: String,
    pub(super) key_log_head: arkret_identifiers::Hash,
}

struct FederationActorSignature {
    verification_method: String,
    sig_b64: Option<String>,
    jws: Option<String>,
}

pub(super) async fn verify_federation_actor_signature(
    state: &AppState,
    body: &arkret_models_collaboration::federation::wire_dtos::FederationVerifyActorRequestBody,
) -> Result<VerifiedFederationActor, AppError> {
    let actor_signature = FederationActorSignature {
        verification_method: body.signature.key_id.clone(),
        sig_b64: Some(body.signature.signature.clone()),
        jws: None,
    };
    // High-risk path: enforce DID document freshness before federation receive
    // signature verification (fail-closed-on-stale).
    let resolved_key = crate::jws_verify::resolve_ed25519_verification_key_for_did_fresh(
        state,
        &body.actor_id,
        &actor_signature.verification_method,
    )
    .await
    .map_err(|error| {
        if error == "verification method controller does not match DID" {
            actor_signature_error("actor verification method controller does not match actor_id")
        } else {
            actor_signature_error(format!("actor verification key invalid: {error}"))
        }
    })?;

    let transcript_bytes = body
        .actor_signature_transcript_bytes()
        .map_err(|error| AppError::internal(format!("verify-actor transcript failed: {error}")))?;

    if let Some(jws) = actor_signature.jws.as_deref() {
        crate::jws_verify::verify_did_controlled_jws_async(
            &transcript_bytes,
            jws,
            &actor_signature.verification_method,
            body.actor_id.as_str(),
            state,
        )
        .await
        .map_err(|error| {
            actor_signature_error(format!("actor JWS verification failed: {error}"))
        })?;
    } else {
        let sig_b64 = actor_signature.sig_b64.as_deref().ok_or_else(|| {
            actor_signature_error("actor signature requires `sig` or detached `jws`")
        })?;
        let raw = URL_SAFE_NO_PAD
            .decode(sig_b64.as_bytes())
            .or_else(|_| STANDARD.decode(sig_b64.as_bytes()))
            .map_err(|_| actor_signature_error("actor signature is not base64/base64url"))?;
        let signature = Signature::from_slice(&raw)
            .map_err(|_| actor_signature_error("actor signature must be 64 Ed25519 bytes"))?;
        resolved_key
            .public_key
            .verify(&transcript_bytes, &signature)
            .map_err(|_| actor_signature_error("actor signature verification failed"))?;
    }

    Ok(VerifiedFederationActor {
        verified_key_id: resolved_key.verification_method,
        did_document_ref: resolved_key.did_document_ref,
        key_log_head: resolved_key.key_log_head,
    })
}

fn actor_signature_error(message: impl Into<String>) -> AppError {
    AppError::new(
        soland_http::error::ErrorCode::InvalidSignature,
        message.into(),
    )
    .with_status(StatusCode::UNAUTHORIZED)
}
