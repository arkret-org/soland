//! Phase 4 — cross-signing subsystem (crypto-media/device-lifecycle.md §5).
//!
//! Maintains, per principal, the accepted `ck.cross_signing.publish` (PSK →
//! {SSK, USK}) and verifies device `cross_signing_binding` signatures so a
//! `ck.device.authorize` is only trusted when its SSK binding checks out at the
//! currently accepted generation.
//!
//! The state machine itself is the SDK `DeviceManager` (held on `AppState`); we
//! supply the DID-resolved Ed25519 verification and the control-set check that
//! the SDK explicitly leaves to the caller.

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use cokret_sdk::{CrossSigningPublishContent, DeviceId, DeviceStatus, DeviceTrustBinding, Did};
use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};
use serde_json::{Map, Value};

use crate::error::{AppError, ErrorCode};
use crate::state::AppState;

/// Parse the `ck.cross_signing.publish` operation payload into the SDK content
/// type. Returns a wire reason code on malformed input.
fn parse_publish(payload: &Value) -> Result<CrossSigningPublishContent, &'static str> {
    serde_json::from_value::<CrossSigningPublishContent>(payload.clone())
        .map_err(|_| "cross_signing_publish_malformed")
}

/// Validate a `ck.cross_signing.publish` BEFORE acceptance (read-only). Runs:
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
    if !ed25519_verify(
        &psk,
        &ssk_input,
        &content.self_signing_key.binding.signature,
    ) {
        return Err("cross_signing_self_binding_invalid");
    }
    let usk_input = content
        .user_signing_binding_input()
        .map_err(|_| "cross_signing_bind_input_failed")?;
    if !ed25519_verify(
        &psk,
        &usk_input,
        &content.user_signing_key.binding.signature,
    ) {
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

/// Record an accepted `ck.cross_signing.publish` into the `DeviceManager`
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

/// Validate a `ck.cross_signing.reset` BEFORE acceptance (read-only). Only the
/// `principal_signing` proof variant is implemented (signed by the principal's
/// current DID control key over `reset_signing_input`); the other high-risk
/// variants (recovery_unlock / device_quorum / trusted_recovery_service) are
/// rejected as unimplemented rather than silently accepted. CAS: the reset's
/// `previous_generation` MUST equal the currently accepted generation.
pub async fn validate_cross_signing_reset(
    state: &AppState,
    payload: &Value,
) -> Result<(), &'static str> {
    let content: cokret_sdk::CrossSigningResetContent =
        serde_json::from_value(payload.clone()).map_err(|_| "cross_signing_reset_malformed")?;
    content
        .validate_structure()
        .map_err(|_| "cross_signing_reset_invalid_structure")?;

    let principal =
        Did::new(content.principal_id.as_str().to_owned()).map_err(|_| "cross_signing_bad_did")?;

    // CAS precondition against the currently accepted generation.
    let current = {
        let mgr = state.cross_signing.lock().expect("cross_signing lock");
        mgr.current_cross_signing(&principal)
            .map(|p| p.generation)
            .unwrap_or(0)
    };
    if content.previous_generation != current {
        return Err("cross_signing_reset_cas_conflict");
    }

    match &content.proof {
        cokret_sdk::CrossSigningResetProof::PrincipalSigning {
            verification_method,
            signature,
            ..
        } => {
            // PSK control-set: the signing key MUST resolve in the principal's
            // DID document.
            let psk = crate::jws_verify::resolve_ed25519_pubkey(state, verification_method)
                .map_err(|_| "cross_signing_reset_key_not_in_control_set")?;
            let input = content
                .reset_signing_input()
                .map_err(|_| "cross_signing_reset_input_failed")?;
            if !ed25519_verify(&psk, &input, signature) {
                return Err("cross_signing_reset_signature_invalid");
            }
            Ok(())
        }
        _ => Err("cross_signing_reset_proof_kind_unimplemented"),
    }
}

/// Record an accepted `ck.cross_signing.reset` into the `DeviceManager` (drops
/// the current publish + bumps the generation high-water; marks devices
/// `needs_reverification`). Validation already ran pre-acceptance.
pub fn project_cross_signing_reset(state: &AppState, payload: &Value) {
    let content: cokret_sdk::CrossSigningResetContent =
        match serde_json::from_value(payload.clone()) {
            Ok(content) => content,
            Err(error) => {
                tracing::warn!(%error, "cross_signing.reset projector: malformed payload");
                return;
            }
        };
    let mut mgr = state.cross_signing.lock().expect("cross_signing lock");
    if let Err(error) = mgr.record_cross_signing_reset(&content) {
        tracing::warn!(%error, "cross_signing.reset projector: record rejected");
    }
}

/// Verify a `ck.device.authorize` `cross_signing_binding` at recovery
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
    check_device_cross_signing_binding(state, principal_id, device_id, device_public_key, binding)
        .map_err(device_binding_reason_to_app_error)
}

/// Map a `check_device_cross_signing_binding` wire reason to a typed HTTP error,
/// preserving the recovery `/complete` status semantics.
fn device_binding_reason_to_app_error(reason: &'static str) -> AppError {
    match reason {
        "cross_signing_state_missing" => {
            AppError::conflict("no accepted cross-signing publish for principal")
                .with_wire_code("cross_signing_state_missing")
        }
        "device_recovery_ssk_generation_mismatch" => {
            AppError::conflict("cross_signing_binding.ssk_generation != accepted generation")
                .with_wire_code("device_recovery_ssk_generation_mismatch")
        }
        "cross_signing_binding_invalid" => AppError::new(
            ErrorCode::InvalidSignature,
            "cross_signing_binding signature does not verify against accepted SSK",
        )
        .with_status(salvo::http::StatusCode::UNAUTHORIZED)
        .with_wire_code(crate::error::reasons::PROOF_INVALID),
        other
            if other.starts_with("cross_signing_binding_missing")
                || other.starts_with("device_authorize_") =>
        {
            AppError::invalid_param(other)
        }
        other => AppError::internal(format!("device cross_signing_binding check: {other}")),
    }
}

/// 3a — reason-returning core for `ck.device.authorize` binding verification,
/// shared by the recovery `/complete` path and the event-ingest validator.
pub(crate) fn check_device_cross_signing_binding(
    state: &AppState,
    principal_id: &str,
    device_id: &str,
    device_public_key: &str,
    binding: &Map<String, Value>,
) -> Result<(), &'static str> {
    let principal =
        Did::new(principal_id.to_owned()).map_err(|_| "device_authorize_bad_principal")?;
    let device =
        DeviceId::new(device_id.to_owned()).map_err(|_| "device_authorize_bad_device_id")?;
    let binding_generation = binding
        .get("ssk_generation")
        .and_then(Value::as_u64)
        .ok_or("cross_signing_binding_missing_ssk_generation")?;
    let signature_b64 = binding
        .get("signature")
        .and_then(Value::as_str)
        .ok_or("cross_signing_binding_missing_signature")?;

    let mgr = state.cross_signing.lock().expect("cross_signing lock");
    let publish = mgr
        .current_cross_signing(&principal)
        .ok_or("cross_signing_state_missing")?;
    // Live generation gate (device-lifecycle.md §15 step 3 / §5.2.1).
    if binding_generation != publish.generation {
        return Err("device_recovery_ssk_generation_mismatch");
    }
    let ssk = decode_ed25519_key(
        &publish.self_signing_key.key.public_key,
        &publish.self_signing_key.key.key_format,
    )
    .map_err(|_| "cross_signing_ssk_undecodable")?;
    let device_input = DeviceTrustBinding::canonical_input(
        &principal,
        &device,
        device_public_key,
        binding_generation,
    )
    .map_err(|_| "cross_signing_binding_input_failed")?;
    if !ed25519_verify(&ssk, &device_input, signature_b64) {
        return Err("cross_signing_binding_invalid");
    }
    Ok(())
}

/// 3a — validate a `ck.device.authorize` operation payload's cross_signing_binding
/// at event ingest, so ANY submission path (recovery, or a future client-submitted
/// control event) is verified, not just recovery `/complete`. Bootstrap-first-device
/// authorizations carry a `bootstrap_binding` instead and are validated elsewhere;
/// here we only verify when a `cross_signing_binding` is present.
pub fn validate_device_authorize_binding(
    state: &AppState,
    payload: &Value,
) -> Result<(), &'static str> {
    let Some(binding) = payload
        .get("cross_signing_binding")
        .and_then(Value::as_object)
    else {
        return Ok(());
    };
    let principal_id = payload
        .get("principal_id")
        .and_then(Value::as_str)
        .ok_or("device_authorize_missing_principal_id")?;
    let device_id = payload
        .get("device_id")
        .and_then(Value::as_str)
        .ok_or("device_authorize_missing_device_id")?;
    let device_public_key = payload
        .get("device_public_key")
        .and_then(Value::as_str)
        .ok_or("device_authorize_missing_device_public_key")?;
    check_device_cross_signing_binding(state, principal_id, device_id, device_public_key, binding)
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

/// The signing-key directory facet for a `(principal_id, device_id)` pair, as
/// projected into the `keys/query` response (`device-lifecycle.md` §8.2).
///
/// `signing_key_did` is the authoritative device verify key rendered as an
/// Ed25519 `did:key` (`did:key:` + the stored multibase string), present ONLY
/// when the device is verified and not revoked. `status` mirrors the wire
/// `device_status` enum: `Active` for a verified, non-revoked device on record,
/// `Revoked` otherwise.
pub(crate) struct DeviceSigningDirectoryFacet {
    pub signing_key_did: Option<String>,
    pub status: DeviceStatus,
}

/// Resolve the `keys/query` signing-key directory facet for `(principal_id,
/// device_id)`. Single source of truth for the "verified + not revoked → return
/// `device_signing_key`" rule that `device-lifecycle.md` §8.2 mandates; the
/// recovery receipt path's [`resolve_authorized_device_key`] applies the same
/// device-record predicate (verified + not revoked + non-empty
/// `payload.device_public_key`).
///
/// The stored `payload.device_public_key` is a bare multibase Ed25519 key
/// (`z…`); the directory exposes it as a `did:key`. The key is decoded once to
/// confirm it is a well-formed Ed25519 key before it is surfaced; a present but
/// undecodable key is treated as no key (status `Active` is still reported when
/// the device is otherwise verified and not revoked, but the key is omitted —
/// fail-closed on the verify-key, not on the status).
pub(crate) async fn resolve_device_signing_directory_facet(
    state: &AppState,
    principal_id: &str,
    device_id: &str,
) -> DeviceSigningDirectoryFacet {
    let record = match state.persistence.devices().get(principal_id, device_id).await {
        Ok(Some(record)) => record,
        _ => {
            return DeviceSigningDirectoryFacet {
                signing_key_did: None,
                status: DeviceStatus::Revoked,
            };
        }
    };
    if record.revoked_at.is_some() || record.verification_state != "verified" {
        return DeviceSigningDirectoryFacet {
            signing_key_did: None,
            status: DeviceStatus::Revoked,
        };
    }
    let signing_key_did = record
        .payload
        .get("device_public_key")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .filter(|value| decode_ed25519_key(value, "multibase").is_ok())
        .map(|value| format!("did:key:{value}"));
    DeviceSigningDirectoryFacet {
        signing_key_did,
        status: DeviceStatus::Active,
    }
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
