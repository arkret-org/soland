use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, Verifier as _};
use salvo::http::StatusCode;
use serde_json::{Value, json};

use crate::error::AppError;
use crate::state::AppState;

pub(super) fn federation_verify_actor_digest(
    body: &arkret_sdk::FederationVerifyActorRequestBody,
) -> Result<String, &'static str> {
    let value = serde_json::to_value(body)
        .map_err(|_| "federation verify-actor request must serialize to JSON")?;
    arkret_sdk::canonical::canonical_sha256(&value)
        .map_err(|_| "federation verify-actor request must be canonical JSON")
}

pub(super) fn federation_verify_actor_unsigned_digest(
    body: &arkret_sdk::FederationVerifyActorRequestBody,
) -> Result<String, &'static str> {
    let mut value = serde_json::to_value(body)
        .map_err(|_| "federation verify-actor request must serialize to JSON")?;
    let Some(object) = value.as_object_mut() else {
        return Err("federation verify-actor request must serialize to a JSON object");
    };
    object.remove("signature");
    arkret_sdk::canonical::canonical_sha256(&value)
        .map_err(|_| "federation verify-actor unsigned request must be canonical JSON")
}

/// Federation actor signature transcript v1.
///
/// The actor signs the canonical JSON bytes of this object. It deliberately
/// covers the digest of the verify-actor request with `signature` removed:
/// signing the full body would be self-referential because the signature field
/// is populated after signing. The HTTP federation trust headers still bind
/// the complete request body, including `signature`.
fn federation_verify_actor_signature_transcript(
    body: &arkret_sdk::FederationVerifyActorRequestBody,
    unsigned_request_digest: &str,
) -> Value {
    let scope_id = body.realm_id.as_ref().map(|value| value.as_str());
    json!({
        "type": "ck.federation.verify_actor.signature.v1",
        "actor_id": body.actor_id.as_str(),
        "purpose": body.purpose,
        "challenge": body.challenge,
        "signed_payload_digest": body.signed_payload_digest.as_ref().map(|digest| digest.as_str()),
        "realm_id": scope_id,
        "request_binding_digest": unsigned_request_digest,
    })
}

pub(super) struct VerifiedFederationActor {
    pub(super) verified_key_id: String,
    pub(super) did_document_ref: String,
    pub(super) key_log_head: arkret_sdk::Hash,
}

struct FederationActorSignature {
    verification_method: String,
    sig_b64: Option<String>,
    jws: Option<String>,
}

pub(super) async fn verify_federation_actor_signature(
    state: &AppState,
    body: &arkret_sdk::FederationVerifyActorRequestBody,
    unsigned_request_digest: &str,
) -> Result<VerifiedFederationActor, AppError> {
    let actor_signature = parse_federation_actor_signature(&body.signature)?;
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

    let transcript = federation_verify_actor_signature_transcript(body, unsigned_request_digest);
    let transcript_bytes = arkret_sdk::canonical::canonical_json_bytes(&transcript)
        .map_err(|error| AppError::internal(format!("verify-actor transcript failed: {error}")))?;

    if let Some(jws) = actor_signature.jws.as_deref() {
        crate::jws_verify::verify_jws_ed25519_async(
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

fn parse_federation_actor_signature(value: &Value) -> Result<FederationActorSignature, AppError> {
    let object = value
        .as_object()
        .ok_or_else(|| actor_signature_error("actor signature must be an object"))?;
    let verification_method = object
        .get("kid")
        .or_else(|| object.get("key_id"))
        .or_else(|| object.get("verification_method"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| actor_signature_error("actor signature missing kid"))?
        .to_owned();
    let alg = object
        .get("alg")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| actor_signature_error("actor signature missing alg"))?
        .to_owned();
    if !matches!(alg.as_str(), "Ed25519" | "EdDSA") {
        return Err(actor_signature_error(
            "actor signature alg must be Ed25519 or EdDSA",
        ));
    }
    let sig_b64 = object
        .get("sig")
        .or_else(|| object.get("signature"))
        .or_else(|| object.get("signature_b64"))
        .and_then(Value::as_str)
        .map(ToOwned::to_owned);
    let jws = object
        .get("jws")
        .or_else(|| object.get("detached_jws"))
        .and_then(Value::as_str)
        .map(ToOwned::to_owned);
    if sig_b64.is_none() && jws.is_none() {
        return Err(actor_signature_error(
            "actor signature missing sig or detached jws",
        ));
    }
    Ok(FederationActorSignature {
        verification_method,
        sig_b64,
        jws,
    })
}

fn actor_signature_error(message: impl Into<String>) -> AppError {
    AppError::new(crate::error::ErrorCode::InvalidSignature, message.into())
        .with_status(StatusCode::UNAUTHORIZED)
}
