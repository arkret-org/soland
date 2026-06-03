//! Phase 4 — cross-signing subsystem (crypto-media/device-lifecycle.md §5).
//!
//! Maintains, per principal, the accepted `cx.cross_signing.publish` (PSK →
//! {SSK, USK}) and verifies device `cross_signing_binding` signatures so a
//! `cx.device.authorize` is only trusted when its SSK binding checks out at the
//! currently accepted generation.
//!
//! The state machine itself is the SDK `DeviceManager` (held on `AppState`); we
//! supply the DID-resolved Ed25519 verification and the control-set check that
//! the SDK explicitly leaves to the caller.

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use contrix_sdk::{CrossSigningPublishContent, DeviceId, DeviceTrustBinding, Did};
use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};
use serde_json::{Map, Value};

use crate::error::{AppError, ErrorCode};
use crate::state::AppState;

/// Parse the `cx.cross_signing.publish` operation payload into the SDK content
/// type. Returns a wire reason code on malformed input.
fn parse_publish(payload: &Value) -> Result<CrossSigningPublishContent, &'static str> {
    serde_json::from_value::<CrossSigningPublishContent>(payload.clone())
        .map_err(|_| "cross_signing_publish_malformed")
}

/// Validate a `cx.cross_signing.publish` BEFORE acceptance (read-only). Runs:
/// structural checks, PSK authenticity + control-set membership (the published
/// PSK MUST resolve to a verification method in the principal's DID document and
/// match it), PSK→SSK and PSK→USK binding signatures, and the CAS precondition
/// against the currently accepted generation.
///
/// Used from `validate_operation_policy`; returns a `&'static str` wire reason.
pub async fn validate_cross_signing_publish(
    state: &AppState,
    payload: &Value,
) -> Result<(), &'static str> {
    let content = parse_publish(payload)?;
    content
        .validate_structure()
        .map_err(|_| "cross_signing_publish_invalid_structure")?;

    // PSK authenticity + control-set: the published principal_signing_key MUST
    // resolve to a verification method in the principal's DID document, and the
    // published bytes MUST equal the DID-resolved key. (device-lifecycle §5.2.1
    // step 2.)
    let psk = resolve_psk_in_control_set(state, &content)?;

    // PSK→SSK and PSK→USK binding signatures.
    let ssk_input = content
        .self_signing_binding_input()
        .map_err(|_| "cross_signing_bind_input_failed")?;
    if !ed25519_verify(&psk, &ssk_input, &content.self_signing_key.binding.signature) {
        return Err("cross_signing_self_binding_invalid");
    }
    let usk_input = content
        .user_signing_binding_input()
        .map_err(|_| "cross_signing_bind_input_failed")?;
    if !ed25519_verify(&psk, &usk_input, &content.user_signing_key.binding.signature) {
        return Err("cross_signing_user_binding_invalid");
    }

    // CAS precondition against the currently accepted generation.
    let principal =
        Did::new(content.principal_id.as_str().to_owned()).map_err(|_| "cross_signing_bad_did")?;
    let current = {
        let mgr = state.cross_signing.lock().expect("cross_signing lock");
        mgr.current_cross_signing(&principal)
            .map(|p| p.generation)
            .unwrap_or(0)
    };
    if content.expected_previous_generation != current {
        return Err("cross_signing_cas_conflict");
    }
    if content.generation != current + 1 {
        return Err("cross_signing_generation_not_monotonic");
    }
    Ok(())
}

/// Record an accepted `cx.cross_signing.publish` into the `DeviceManager`
/// (authoritative CAS bookkeeping). Called from the projector AFTER acceptance.
/// Validation already ran in `validate_cross_signing_publish`; failures here are
/// logged (the op was already accepted) but should not occur in practice.
pub fn project_cross_signing_publish(state: &AppState, payload: &Value) {
    let content = match parse_publish(payload) {
        Ok(content) => content,
        Err(reason) => {
            tracing::warn!(reason, "cross_signing.publish projector: malformed payload");
            return;
        }
    };
    let mut mgr = state.cross_signing.lock().expect("cross_signing lock");
    if let Err(error) = mgr.record_cross_signing_publish(content) {
        tracing::warn!(%error, "cross_signing.publish projector: record rejected");
    }
}

/// Verify a `cx.device.authorize` `cross_signing_binding` at recovery
/// completion. The binding MUST be an SSK signature over the device-trust
/// canonical input, at the currently accepted generation (device-lifecycle
/// §5.2.1). Returns a typed `AppError` for the HTTP path.
pub fn verify_device_cross_signing_binding(
    state: &AppState,
    principal_id: &str,
    device_id: &str,
    device_public_key: &str,
    binding: &Map<String, Value>,
) -> Result<(), AppError> {
    let principal = Did::new(principal_id.to_owned())
        .map_err(|e| AppError::invalid_param(format!("principal_id DID invalid: {e}")))?;
    let device = DeviceId::new(device_id.to_owned())
        .map_err(|e| AppError::invalid_param(format!("device_id invalid: {e}")))?;

    let binding_generation = binding
        .get("ssk_generation")
        .and_then(Value::as_u64)
        .ok_or_else(|| AppError::invalid_param("cross_signing_binding.ssk_generation is required"))?;
    let signature_b64 = binding
        .get("signature")
        .and_then(Value::as_str)
        .ok_or_else(|| AppError::invalid_param("cross_signing_binding.signature is required"))?;

    let mgr = state.cross_signing.lock().expect("cross_signing lock");
    let publish = mgr.current_cross_signing(&principal).ok_or_else(|| {
        AppError::conflict(format!(
            "no accepted cross-signing publish for principal `{principal_id}`"
        ))
        .with_wire_code("cross_signing_state_missing")
    })?;

    // Live generation gate (device-lifecycle.md §15 step 3 / §5.2.1): the
    // binding MUST bind the CURRENT accepted generation, not a stale snapshot.
    if binding_generation != publish.generation {
        return Err(AppError::conflict(format!(
            "cross_signing_binding.ssk_generation {binding_generation} != accepted generation {}",
            publish.generation
        ))
        .with_wire_code("device_recovery_ssk_generation_mismatch"));
    }

    let ssk = decode_ed25519_key(&publish.self_signing_key.key.public_key, &publish.self_signing_key.key.key_format)
        .map_err(|e| AppError::internal(format!("accepted SSK public key invalid: {e}")))?;
    let device_input =
        DeviceTrustBinding::canonical_input(&principal, &device, device_public_key, binding_generation)
            .map_err(|e| AppError::internal(format!("device trust binding input failed: {e}")))?;
    if !ed25519_verify(&ssk, &device_input, signature_b64) {
        return Err(AppError::new(
            ErrorCode::InvalidSignature,
            "cross_signing_binding signature does not verify against accepted SSK",
        )
        .with_status(salvo::http::StatusCode::UNAUTHORIZED)
        .with_wire_code(crate::error::reasons::PROOF_INVALID));
    }
    Ok(())
}

/// Resolve the published PSK against the principal DID document (control-set
/// membership) and confirm the published bytes match.
fn resolve_psk_in_control_set(
    state: &AppState,
    content: &CrossSigningPublishContent,
) -> Result<VerifyingKey, &'static str> {
    let kid = content.principal_signing_key.kid.as_str();
    // resolve_ed25519_pubkey enforces that the verification method is present in
    // the principal's DID document — i.e. in its control set.
    let resolved = crate::jws_verify::resolve_ed25519_pubkey(state, kid)
        .map_err(|_| "cross_signing_psk_not_in_control_set")?;
    let published = decode_ed25519_key(
        &content.principal_signing_key.public_key,
        &content.principal_signing_key.key_format,
    )
    .map_err(|_| "cross_signing_psk_undecodable")?;
    if resolved.to_bytes() != published.to_bytes() {
        return Err("cross_signing_psk_mismatch");
    }
    Ok(resolved)
}

/// Decode an Ed25519 public key in the declared `key_format`
/// (`multibase` z-base58btc with the 0xed01 multicodec, or `raw_base64url`).
pub(crate) fn decode_ed25519_key(material: &str, key_format: &str) -> Result<VerifyingKey, String> {
    let raw: Vec<u8> = match key_format {
        "multibase" => {
            let stripped = material
                .strip_prefix('z')
                .ok_or_else(|| "multibase key must start with 'z'".to_owned())?;
            let decoded = bs58::decode(stripped)
                .into_vec()
                .map_err(|e| format!("multibase base58 decode: {e}"))?;
            // Ed25519 multicodec prefix 0xed 0x01.
            match decoded.as_slice() {
                [0xed, 0x01, rest @ ..] => rest.to_vec(),
                _ => return Err("unexpected multicodec prefix (want ed25519-pub)".to_owned()),
            }
        }
        "raw_base64url" => URL_SAFE_NO_PAD
            .decode(material.as_bytes())
            .or_else(|_| STANDARD.decode(material.as_bytes()))
            .map_err(|e| format!("base64 decode: {e}"))?,
        other => return Err(format!("unsupported key_format `{other}`")),
    };
    let bytes: [u8; 32] = raw
        .as_slice()
        .try_into()
        .map_err(|_| "Ed25519 public key must be 32 bytes".to_owned())?;
    VerifyingKey::from_bytes(&bytes).map_err(|e| format!("invalid Ed25519 public key: {e}"))
}

fn ed25519_verify(key: &VerifyingKey, message: &[u8], signature_b64: &str) -> bool {
    let Ok(raw) = URL_SAFE_NO_PAD
        .decode(signature_b64.as_bytes())
        .or_else(|_| STANDARD.decode(signature_b64.as_bytes()))
    else {
        return false;
    };
    let Ok(signature) = Signature::from_slice(&raw) else {
        return false;
    };
    key.verify(message, &signature).is_ok()
}
