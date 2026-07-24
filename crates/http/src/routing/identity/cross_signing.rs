//! Phase 4 — cross-signing subsystem (crypto-media/device-lifecycle.md §5).
//!
//! Maintains, per principal, the accepted `ak.cross_signing.publish` (PSK →
//! {SSK, USK}) and verifies device `cross_signing_binding` signatures so a
//! `ak.device.authorize` is only trusted when its SSK binding checks out at the
//! currently accepted generation.
//!
//! The accepted-state index is the server `CrossSigningRegistry` (held on `AppState`); we
//! supply the DID-resolved Ed25519 verification and the control-set check that
//! the SDK explicitly leaves to the caller.

use std::collections::BTreeSet;

use arkret_crypto::DeviceTrustBinding;
use arkret_identifiers::{DeviceId, Did, EventId};
use arkret_models_collaboration::events_payloads::list_message_mimi_mls::{
    MlsRequesterTrustBinding, MlsWelcomeClaimEnvelope,
};
use arkret_models_collaboration::events_payloads::preview_realm_reaction::SignatureMaterial;
use arkret_models_crypto::DeviceStatus;
use arkret_models_identity::artifacts_device_identity::{
    CrossSigningPublish, CrossSigningResetProof, DeviceEnrollmentAuthorityBinding,
    DeviceQuorumSignature,
};
use arkret_models_identity::cross_signing::CrossSigningResetPayload;
use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};
use serde_json::{Map, Value};
use soland_services::identity::{FindDeviceQuery, RecoveryPolicyState};
use soland_http::error::{AppError, ErrorCode};

use crate::state::AppState;

const CROSS_SIGNING_RESET_REPLAY_RETENTION_SECONDS: i64 = 90_000;

/// Parse the `ak.cross_signing.publish` operation payload into the SDK content
/// type. Returns a wire reason code on malformed input.
fn parse_publish(payload: &Value) -> Result<CrossSigningPublish, &'static str> {
    serde_json::from_value::<CrossSigningPublish>(
        crate::routing::events::projection_context_stripped_payload(payload),
    )
    .map_err(|_| "cross_signing_publish_malformed")
}

fn parse_reset(payload: &Value) -> Result<CrossSigningResetPayload, &'static str> {
    serde_json::from_value::<CrossSigningResetPayload>(
        crate::routing::events::projection_context_stripped_payload(payload),
    )
    .map_err(|_| "cross_signing_reset_malformed")
}

/// Validate a `ak.cross_signing.publish` BEFORE acceptance (read-only). Runs:
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
    if crate::routing::identity::device_generation::current_device_generation(
        state,
        content.principal_id.as_str(),
    )
    .await
    .map_err(|_| "cross_signing_state_unavailable")?
    .is_some()
    {
        return Err("cross_signing_model_mismatch");
    }

    // PSK authenticity + control-set: the published principal_signing_key MUST
    // resolve to a verification method in the principal's DID document, and the
    // published bytes MUST equal the DID-resolved key. (device-lifecycle §5.2.1
    // step 2.)
    let psk = resolve_psk_in_control_set(state, &content).await?;

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
    let current = state
        .identities()
        .current_cross_signing(&principal)
        .map(|publish| publish.generation.get())
        .unwrap_or(0);
    if content.expected_previous_generation != current {
        return Err("cross_signing_cas_conflict");
    }
    if content.generation.get() != current + 1 {
        return Err("cross_signing_generation_not_monotonic");
    }
    Ok(())
}

/// Record an accepted `ak.cross_signing.publish` into the `CrossSigningRegistry`
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
    if let Err(error) = state
        .identities()
        .record_cross_signing_publish(content)
    {
        tracing::warn!(%error, "cross_signing.publish projector: record rejected");
    }
}

/// Validate a `ak.cross_signing.reset` BEFORE acceptance (read-only). Verifies
/// the active-generation CAS precondition, replay fence, and one of the four
/// reset proof families over the SDK canonical reset transcript.
pub async fn validate_cross_signing_reset(
    state: &AppState,
    payload: &Value,
) -> Result<(), &'static str> {
    let content = parse_reset(payload)?;
    content
        .validate_structure()
        .map_err(|_| "cross_signing_reset_invalid_structure")?;
    if crate::routing::identity::device_generation::current_device_generation(
        state,
        content.principal_id().as_str(),
    )
    .await
    .map_err(|_| "cross_signing_state_unavailable")?
    .is_some()
    {
        return Err("cross_signing_model_mismatch");
    }

    let principal = Did::new(content.principal_id().as_str().to_owned())
        .map_err(|_| "cross_signing_bad_did")?;
    if cross_signing_reset_replay_seen(state, &content) {
        return Err("cross_signing_reset_replayed");
    }

    // CAS precondition against the currently accepted generation.
    let current = state
        .identities()
        .current_cross_signing(&principal)
        .map(|publish| publish.generation.get())
        .unwrap_or(0);
    if content.previous_generation() != current {
        return Err("cross_signing_reset_generation_mismatch");
    }

    let input = content
        .reset_signing_input()
        .map_err(|_| "cross_signing_reset_input_failed")?;
    match content.proof() {
        CrossSigningResetProof::PrincipalSigning {
            verification_method,
            alg,
            signature,
        } => {
            ensure_reset_alg(alg)?;
            crate::jws_verify::validate_verification_method_controller(
                content.principal_id().as_str(),
                verification_method,
            )
            .map_err(|_| "cross_signing_reset_proof_authority_invalid")?;
            let psk = crate::jws_verify::resolve_ed25519_pubkey_async(state, verification_method)
                .await
                .map_err(|_| "cross_signing_reset_proof_authority_invalid")?;
            if !ed25519_verify(&psk, &input, signature) {
                return Err("cross_signing_reset_signature_invalid");
            }
            Ok(())
        }
        CrossSigningResetProof::RecoveryUnlock {
            recovery_session_id,
            recovery_secret_ref,
            unlock_commitment,
            alg,
            signature,
        } => {
            ensure_reset_alg(alg)?;
            require_verified_reset_recovery_session(state, &content, recovery_session_id.as_str())
                .await?;
            let policy = active_reset_recovery_policy(state, &content, "recovery_unlock").await?;
            if !policy_mentions_identifier(
                &policy,
                &[
                    "recovery_unlock",
                    "recovery_secret_refs",
                    "recovery_secrets",
                    "recovery_keys",
                    "secret_refs",
                ],
                recovery_secret_ref,
            ) {
                return Err("cross_signing_reset_recovery_ref_unknown");
            }
            let expected = content
                .recovery_unlock_commitment()
                .map_err(|_| "cross_signing_reset_input_failed")?;
            if unlock_commitment != &expected {
                return Err("cross_signing_reset_unlock_commitment_mismatch");
            }
            let recovery_key =
                crate::jws_verify::resolve_ed25519_pubkey_async(state, recovery_secret_ref)
                    .await
                    .map_err(|_| "cross_signing_reset_recovery_ref_unknown")?;
            if !ed25519_verify(&recovery_key, &input, signature) {
                return Err("cross_signing_reset_signature_invalid");
            }
            Ok(())
        }
        CrossSigningResetProof::DeviceQuorum {
            threshold,
            signatures,
        } => {
            let policy = active_reset_recovery_policy(state, &content, "device_quorum").await?;
            if let Some(required) = policy_device_quorum_threshold(&policy)
                && threshold.get() < u64::from(required)
            {
                return Err("cross_signing_reset_quorum_below_policy");
            }
            verify_device_quorum_reset(
                state,
                content.principal_id().as_str(),
                threshold.get(),
                signatures,
                &input,
            )
            .await
        }
        CrossSigningResetProof::TrustedRecoveryService {
            recovery_session_id,
            service_id,
            verification_method,
            alg,
            signature,
            attestation_ref,
        } => {
            ensure_reset_alg(alg)?;
            require_verified_reset_recovery_session(state, &content, recovery_session_id.as_str())
                .await?;
            let policy =
                active_reset_recovery_policy(state, &content, "trusted_recovery_service").await?;
            if !policy_mentions_identifier(
                &policy,
                &[
                    "trusted_recovery_service",
                    "trusted_recovery_services",
                    "trusted_services",
                    "recovery_services",
                ],
                service_id.as_str(),
            ) {
                return Err("cross_signing_reset_recovery_service_unknown");
            }
            if policy_requires_trusted_service_attestation(&policy) && attestation_ref.is_none() {
                return Err("cross_signing_reset_attestation_missing");
            }
            crate::jws_verify::validate_verification_method_controller(
                service_id.as_str(),
                verification_method,
            )
            .map_err(|_| "cross_signing_reset_proof_authority_invalid")?;
            let service_key =
                crate::jws_verify::resolve_ed25519_pubkey_async(state, verification_method)
                    .await
                    .map_err(|_| "cross_signing_reset_proof_authority_invalid")?;
            if !ed25519_verify(&service_key, &input, signature) {
                return Err("cross_signing_reset_signature_invalid");
            }
            Ok(())
        }
    }
}

async fn require_verified_reset_recovery_session(
    state: &AppState,
    content: &CrossSigningResetPayload,
    recovery_session_id: &str,
) -> Result<(), &'static str> {
    let record = state
        .recovery_sessions()
        .session(recovery_session_id)
        .await
        .map_err(|_| "cross_signing_reset_recovery_session_unavailable")?
        .ok_or("cross_signing_reset_recovery_session_missing")?;
    if record.principal_id != content.principal_id().as_str() {
        return Err("cross_signing_reset_recovery_session_principal_mismatch");
    }
    if record.state != "verified" {
        return Err("cross_signing_reset_recovery_session_not_verified");
    }
    if *content.issued_at() < record.created_at || *content.issued_at() > record.expires_at {
        return Err("cross_signing_reset_recovery_session_expired");
    }
    Ok(())
}

/// Record an accepted `ak.cross_signing.reset` into the `CrossSigningRegistry` (drops
/// the current publish + bumps the generation high-water; marks devices
/// `needs_reverification`). Validation already ran pre-acceptance.
pub async fn project_cross_signing_reset(state: &AppState, payload: &Value) {
    let content = match parse_reset(payload) {
        Ok(content) => content,
        Err(error) => {
            tracing::warn!(%error, "cross_signing.reset projector: malformed payload");
            return;
        }
    };
    let recorded = state
        .identities()
        .record_cross_signing_reset(&content);
    if let Err(error) = recorded {
        tracing::warn!(%error, "cross_signing.reset projector: record rejected");
        return;
    }
    remember_cross_signing_reset_replay(state, &content);
    if let Err(error) = state
        .deliveries()
        .purge_stale_cross_signing_messages(
            content.principal_id().as_str(),
            content.new_generation(),
        )
        .await
    {
        tracing::warn!(%error, "cross_signing.reset projector: queued verification purge failed");
    }
}

fn ensure_reset_alg(alg: &str) -> Result<(), &'static str> {
    match alg {
        "EdDSA" | "Ed25519" => Ok(()),
        _ => Err("cross_signing_reset_proof_authority_invalid"),
    }
}

async fn active_reset_recovery_policy(
    state: &AppState,
    content: &CrossSigningResetPayload,
    proof_kind: &str,
) -> Result<RecoveryPolicyState, &'static str> {
    let policy = state
        .recovery_policies()
        .active_policy(content.principal_id().as_str())
        .await
        .map_err(|_| "cross_signing_reset_proof_authority_invalid")?
        .ok_or("cross_signing_reset_recovery_ref_unknown")?;
    if policy.trust_domain != content.trust_domain().as_str() {
        return Err("cross_signing_reset_proof_authority_invalid");
    }
    if let Some(expires_at) = policy.expires_at
        && expires_at <= *content.issued_at()
    {
        return Err("cross_signing_reset_proof_authority_invalid");
    }
    if !policy
        .allowed_proof_kinds
        .iter()
        .any(|kind| kind == proof_kind)
    {
        return Err("cross_signing_reset_proof_authority_invalid");
    }
    Ok(policy)
}

fn cross_signing_reset_replay_seen(state: &AppState, content: &CrossSigningResetPayload) -> bool {
    let now = chrono::Utc::now();
    state
        .identities()
        .cross_signing_reset_replay_seen(
            content.principal_id().as_str(),
            content.previous_generation(),
            now,
            CROSS_SIGNING_RESET_REPLAY_RETENTION_SECONDS,
        )
}

fn remember_cross_signing_reset_replay(state: &AppState, content: &CrossSigningResetPayload) {
    let now = chrono::Utc::now();
    state
        .identities()
        .remember_cross_signing_reset_replay(
            content.principal_id().as_str().to_owned(),
            content.previous_generation(),
            now,
            CROSS_SIGNING_RESET_REPLAY_RETENTION_SECONDS,
        );
}

async fn verify_device_quorum_reset(
    state: &AppState,
    principal_id: &str,
    threshold: u64,
    signatures: &[DeviceQuorumSignature],
    input: &[u8],
) -> Result<(), &'static str> {
    let devices = state
        .identities()
        .devices_for_actor(principal_id)
        .await
        .map_err(|_| "cross_signing_reset_quorum_insufficient")?;
    let mut seen_devices = BTreeSet::new();
    let mut valid = 0u64;
    for contribution in signatures {
        ensure_reset_alg(&contribution.alg)?;
        if !seen_devices.insert(contribution.device_id.as_str().to_owned()) {
            return Err("cross_signing_reset_quorum_insufficient");
        }
        let Some(record) = devices
            .iter()
            .find(|record| record.device_id == contribution.device_id.as_str())
        else {
            return Err("cross_signing_reset_quorum_insufficient");
        };
        if record.revoked_at.is_some() || record.verification_state != "verified" {
            return Err("cross_signing_reset_quorum_insufficient");
        }
        let device_public_key = record
            .payload
            .get("device_public_key")
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .ok_or("cross_signing_reset_proof_authority_invalid")?;
        if !device_quorum_method_matches(
            principal_id,
            contribution.device_id.as_str(),
            device_public_key,
            &contribution.verification_method,
        ) {
            return Err("cross_signing_reset_proof_authority_invalid");
        }
        let device_key = decode_ed25519_key(device_public_key, "multibase")
            .map_err(|_| "cross_signing_reset_proof_authority_invalid")?;
        if !ed25519_verify(&device_key, input, &contribution.signature) {
            return Err("cross_signing_reset_signature_invalid");
        }
        valid += 1;
    }
    if valid < threshold {
        return Err("cross_signing_reset_quorum_insufficient");
    }
    Ok(())
}

fn device_quorum_method_matches(
    principal_id: &str,
    device_id: &str,
    device_public_key: &str,
    verification_method: &str,
) -> bool {
    verification_method == format!("{principal_id}#{device_id}")
        || verification_method == format!("did:key:{device_public_key}#{device_public_key}")
        || verification_method == format!("did:key:{device_public_key}")
}

fn policy_mentions_identifier(
    policy: &RecoveryPolicyState,
    top_level_keys: &[&str],
    identifier: &str,
) -> bool {
    top_level_keys.iter().any(|key| {
        policy
            .raw_payload
            .get(*key)
            .is_some_and(|value| value_mentions_identifier(value, identifier))
    })
}

fn value_mentions_identifier(value: &Value, identifier: &str) -> bool {
    match value {
        Value::String(value) => value == identifier,
        Value::Array(values) => values
            .iter()
            .any(|value| value_mentions_identifier(value, identifier)),
        Value::Object(object) => object
            .values()
            .any(|value| value_mentions_identifier(value, identifier)),
        _ => false,
    }
}

fn policy_device_quorum_threshold(policy: &RecoveryPolicyState) -> Option<u32> {
    [
        "/device_quorum/k",
        "/device_quorum/threshold",
        "/device_quorum/quorum_size",
        "/proof_requirements/device_quorum/k",
        "/proof_requirements/device_quorum/threshold",
        "/proof_requirements/device_quorum/quorum_size",
    ]
    .iter()
    .find_map(|pointer| {
        policy
            .raw_payload
            .pointer(pointer)
            .and_then(Value::as_u64)
            .and_then(|value| u32::try_from(value).ok())
    })
}

fn policy_requires_trusted_service_attestation(policy: &RecoveryPolicyState) -> bool {
    [
        "/trusted_recovery_service/attestation_required",
        "/trusted_recovery_services/attestation_required",
        "/proof_requirements/trusted_recovery_service/attestation_required",
        "/attestation_required",
    ]
    .iter()
    .any(|pointer| {
        policy
            .raw_payload
            .pointer(pointer)
            .and_then(Value::as_bool)
            .unwrap_or(false)
    }) || ["trusted_recovery_service", "trusted_recovery_services"]
        .iter()
        .any(|key| {
            policy
                .raw_payload
                .get(*key)
                .is_some_and(value_requires_attestation)
        })
}

fn value_requires_attestation(value: &Value) -> bool {
    match value {
        Value::Object(object) => {
            object
                .get("attestation_required")
                .and_then(Value::as_bool)
                .unwrap_or(false)
                || object.values().any(value_requires_attestation)
        }
        Value::Array(values) => values.iter().any(value_requires_attestation),
        _ => false,
    }
}

/// Verify a `ak.device.authorize` `cross_signing_binding` at recovery
/// completion. The binding MUST be an SSK signature over the device-trust
/// canonical input, at the currently accepted generation (device-lifecycle
/// §5.2.1). Returns a typed `AppError` for the HTTP path.
pub fn verify_device_cross_signing_binding(
    state: &AppState,
    principal_id: &str,
    device_id: &str,
    device_public_key: &str,
    hpke_key: &str,
    algorithms: &[String],
    binding: &Map<String, Value>,
) -> Result<(), AppError> {
    check_device_cross_signing_binding(
        state,
        principal_id,
        device_id,
        device_public_key,
        hpke_key,
        algorithms,
        binding,
    )
    .map_err(device_binding_reason_to_app_error)
}

pub(crate) fn current_accepted_ssk_generation(state: &AppState, principal_id: &str) -> Option<u64> {
    let principal = Did::new(principal_id.to_owned()).ok()?;
    state
        .identities()
        .current_cross_signing(&principal)
        .map(|publish| publish.generation.get())
}

pub(crate) fn persisted_device_is_anchored_to_ssk_generation(
    state: &AppState,
    principal_id: &str,
    device_id: &str,
    device_public_key: &str,
    payload: &Value,
    expected_generation: u64,
) -> bool {
    let Some(binding) = payload
        .get("cross_signing_binding")
        .and_then(Value::as_object)
    else {
        return false;
    };
    if binding.get("ssk_generation").and_then(Value::as_u64) != Some(expected_generation) {
        return false;
    }
    let Some(hpke_key) = payload.get("hpke_key").and_then(Value::as_str) else {
        return false;
    };
    let Some(algorithms) = payload.get("algorithms").and_then(Value::as_array) else {
        return false;
    };
    let algorithms = algorithms
        .iter()
        .map(|value| value.as_str().map(ToOwned::to_owned))
        .collect::<Option<Vec<_>>>()
        .unwrap_or_default();
    check_device_cross_signing_binding(
        state,
        principal_id,
        device_id,
        device_public_key,
        hpke_key,
        &algorithms,
        binding,
    )
    .is_ok()
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
        .with_wire_code(arkret_wire::ReasonCode::PROOF_INVALID),
        other
            if other.starts_with("cross_signing_binding_missing")
                || other.starts_with("device_authorize_") =>
        {
            AppError::invalid_param(other)
        }
        other => AppError::internal(format!("device cross_signing_binding check: {other}")),
    }
}

/// 3a — reason-returning core for `ak.device.authorize` binding verification,
/// shared by the recovery `/complete` path and the event-ingest validator.
pub(crate) fn check_device_cross_signing_binding(
    state: &AppState,
    principal_id: &str,
    device_id: &str,
    device_public_key: &str,
    hpke_key: &str,
    algorithms: &[String],
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

    let publish = state
        .identities()
        .current_cross_signing(&principal)
        .ok_or("cross_signing_state_missing")?;
    // Live generation gate (device-lifecycle.md §15 step 3 / §5.2.1).
    if binding_generation != publish.generation.get() {
        return Err("device_recovery_ssk_generation_mismatch");
    }
    let ssk = decode_ed25519_key(
        publish.self_signing_key.public_key.as_str(),
        publish.self_signing_key.key_format.as_str(),
    )
    .map_err(|_| "cross_signing_ssk_undecodable")?;
    let device_input = DeviceTrustBinding::canonical_input(
        &principal,
        &device,
        device_public_key,
        hpke_key,
        algorithms,
        binding_generation,
    )
    .map_err(|_| "cross_signing_binding_input_failed")?;
    if !ed25519_verify(&ssk, &device_input, signature_b64) {
        return Err("cross_signing_binding_invalid");
    }
    Ok(())
}

/// 3a — validate a `ak.device.authorize` operation payload's cross_signing_binding
/// at event ingest, so ANY submission path (recovery, or a future client-submitted
/// control event) is verified, not just recovery `/complete`. B-model inception
/// authorizations carry an `enrollment_authority_binding` and are validated by
/// the closed identity-anchor path; here we only verify `cross_signing_binding`.
pub fn validate_device_authorize_binding(
    state: &AppState,
    payload: &Value,
) -> Result<(), &'static str> {
    let payload_shape: arkret_models_collaboration::events_payloads::device_identity::DeviceAuthorizePayload =
        serde_json::from_value(device_authorize_wire_payload(payload))
            .map_err(|_| "ak.device.authorize payload violates SDK artifact schema")?;
    payload_shape.validate_authorization_binding_one_of()?;
    // device-lifecycle.md §5.2: the payload MUST carry the canonical
    // (bytewise-sorted, deduplicated) algorithms array that entered the
    // trust binding transcript.
    payload_shape.validate_canonical_algorithms()?;
    verify_device_authorize_device_signature(&payload_shape)?;
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
    let algorithms = payload_shape
        .algorithms
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    check_device_cross_signing_binding(
        state,
        principal_id,
        device_id,
        device_public_key,
        payload_shape.hpke_key.as_str(),
        &algorithms,
        binding,
    )
}

fn verify_device_authorize_device_signature(
    payload: &arkret_models_collaboration::events_payloads::device_identity::DeviceAuthorizePayload,
) -> Result<(), &'static str> {
    let Some(signature_material) = &payload.device_signature else {
        if payload.recovery_session_id.is_some() {
            return Err("device_authorize_device_signature_required");
        }
        return Ok(());
    };
    let signature_b64 = device_authorize_signature_value(signature_material)?;
    let device_key = decode_ed25519_key(payload.device_public_key.as_str(), "multibase")
        .map_err(|_| "device_authorize_device_public_key_invalid")?;
    let input = payload
        .device_possession_signature_input()
        .map_err(|_| "device_authorize_device_signature_input_failed")?;
    if !ed25519_verify(&device_key, &input, signature_b64) {
        return Err("device_authorize_device_signature_invalid");
    }
    Ok(())
}

fn device_authorize_signature_value(
    signature_material: &SignatureMaterial,
) -> Result<&str, &'static str> {
    match signature_material {
        SignatureMaterial::NonEmptyString(value) => Ok(value.as_str()),
        SignatureMaterial::Variant1(object) => {
            if let Some(alg) = object.get("alg").and_then(Value::as_str)
                && !matches!(alg, "EdDSA" | "Ed25519")
            {
                return Err("device_authorize_device_signature_alg_unsupported");
            }
            object
                .get("signature")
                .or_else(|| object.get("sig"))
                .and_then(Value::as_str)
                .ok_or("device_authorize_device_signature_missing_signature")
        }
    }
}

/// Strip the reducer/projection-injected envelope fields so the remaining
/// object is exactly the wire `device_authorize_payload` shape the typed SDK
/// counterpart (`deny_unknown_fields`) accepts.
pub(crate) fn device_authorize_wire_payload(payload: &Value) -> Value {
    crate::routing::events::operations::projection_context_stripped_payload(payload)
}

pub(crate) async fn verify_mls_welcome_claim_envelope_signature(
    state: &AppState,
    envelope: &MlsWelcomeClaimEnvelope,
    sender_device_id: Option<&str>,
    signer_key_evidence: Option<&arkret_wire::event_envelope::FederatedDeviceSigningKeyEvidence>,
) -> Result<(), &'static str> {
    envelope.validate_signature_shape()?;
    if let Some(alg) = envelope.signature.alg.as_deref()
        && !matches!(alg, "EdDSA" | "Ed25519")
    {
        return Err(arkret_wire::ReasonCode::KEYPACKAGE_WELCOME_ENVELOPE_MISMATCH);
    }
    match &envelope.trust_binding {
        MlsRequesterTrustBinding::SskGeneration(generation) => {
            verify_mls_welcome_claim_envelope_ssk_signature(state, envelope, generation.get())
        }
        MlsRequesterTrustBinding::RequesterDeviceId(requester_device_id) => {
            verify_mls_welcome_claim_envelope_device_signature(
                state,
                envelope,
                requester_device_id.as_str(),
                sender_device_id,
                signer_key_evidence,
            )
            .await
        }
    }
}

fn verify_mls_welcome_claim_envelope_ssk_signature(
    state: &AppState,
    envelope: &MlsWelcomeClaimEnvelope,
    envelope_generation: u64,
) -> Result<(), &'static str> {
    let publish = state
        .identities()
        .current_cross_signing(&envelope.requester_did)
        .ok_or(arkret_wire::ReasonCode::KEYPACKAGE_WELCOME_ENVELOPE_MISMATCH)?;
    let (accepted_generation, ssk_kid, ssk_public_key, ssk_key_format) = (
        publish.generation.get(),
        publish.self_signing_key.kid,
        publish.self_signing_key.public_key,
        publish.self_signing_key.key_format,
    );
    if envelope_generation != accepted_generation
        || envelope.signature.kid.as_str() != ssk_kid.as_str()
    {
        return Err(arkret_wire::ReasonCode::KEYPACKAGE_WELCOME_ENVELOPE_MISMATCH);
    }
    let ssk = decode_ed25519_key(ssk_public_key.as_str(), ssk_key_format.as_str())
        .map_err(|_| arkret_wire::ReasonCode::KEYPACKAGE_WELCOME_ENVELOPE_MISMATCH)?;
    let signing_bytes = envelope
        .canonical_signing_bytes()
        .map_err(|_| arkret_wire::ReasonCode::KEYPACKAGE_WELCOME_ENVELOPE_MISMATCH)?;
    if !ed25519_verify(&ssk, &signing_bytes, &envelope.signature.sig) {
        return Err(arkret_wire::ReasonCode::KEYPACKAGE_WELCOME_ENVELOPE_MISMATCH);
    }
    Ok(())
}

async fn verify_mls_welcome_claim_envelope_device_signature(
    state: &AppState,
    envelope: &MlsWelcomeClaimEnvelope,
    requester_device_id: &str,
    sender_device_id: Option<&str>,
    signer_key_evidence: Option<&arkret_wire::event_envelope::FederatedDeviceSigningKeyEvidence>,
) -> Result<(), &'static str> {
    if let Some(sender_device_id) = sender_device_id
        && sender_device_id != requester_device_id
    {
        return Err(arkret_wire::ReasonCode::KEYPACKAGE_WELCOME_ENVELOPE_MISMATCH);
    }
    if let Some(evidence) = signer_key_evidence {
        if evidence.validate_shape().is_err()
            || evidence.actor_id != envelope.requester_did
            || evidence.device_id.as_str() != requester_device_id
            || evidence.verification_method != envelope.signature.kid.as_str()
        {
            return Err(arkret_wire::ReasonCode::KEYPACKAGE_WELCOME_ENVELOPE_MISMATCH);
        }
        let device_public_key = evidence
            .device_signing_key
            .as_str()
            .strip_prefix("did:key:")
            .ok_or(arkret_wire::ReasonCode::KEYPACKAGE_WELCOME_ENVELOPE_MISMATCH)?;
        let device_key = decode_ed25519_key(device_public_key, "multibase")
            .map_err(|_| arkret_wire::ReasonCode::KEYPACKAGE_WELCOME_ENVELOPE_MISMATCH)?;
        let signing_bytes = envelope
            .canonical_signing_bytes()
            .map_err(|_| arkret_wire::ReasonCode::KEYPACKAGE_WELCOME_ENVELOPE_MISMATCH)?;
        if !ed25519_verify(&device_key, &signing_bytes, &envelope.signature.sig) {
            return Err(arkret_wire::ReasonCode::KEYPACKAGE_WELCOME_ENVELOPE_MISMATCH);
        }
        return Ok(());
    }
    let record = state
        .identities()
        .find_device(FindDeviceQuery {
            actor_id: envelope.requester_did.as_str().to_owned(),
            device_id: requester_device_id.to_owned(),
        })
        .await
        .map_err(|_| arkret_wire::ReasonCode::KEYPACKAGE_WELCOME_ENVELOPE_MISMATCH)?
        .ok_or(arkret_wire::ReasonCode::KEYPACKAGE_WELCOME_ENVELOPE_MISMATCH)?;
    if record.revoked_at.is_some() || record.verification_state != "verified" {
        return Err(arkret_wire::ReasonCode::KEYPACKAGE_WELCOME_ENVELOPE_MISMATCH);
    }
    let device_public_key = record
        .payload
        .get("device_public_key")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or(arkret_wire::ReasonCode::KEYPACKAGE_WELCOME_ENVELOPE_MISMATCH)?;
    if !device_signature_kid_points_to_device_key(
        &envelope.signature.kid,
        envelope.requester_did.as_str(),
        device_public_key,
    ) {
        return Err(arkret_wire::ReasonCode::KEYPACKAGE_WELCOME_ENVELOPE_MISMATCH);
    }
    let device_key = decode_ed25519_key(device_public_key, "multibase")
        .map_err(|_| arkret_wire::ReasonCode::KEYPACKAGE_WELCOME_ENVELOPE_MISMATCH)?;
    let signing_bytes = envelope
        .canonical_signing_bytes()
        .map_err(|_| arkret_wire::ReasonCode::KEYPACKAGE_WELCOME_ENVELOPE_MISMATCH)?;
    if !ed25519_verify(&device_key, &signing_bytes, &envelope.signature.sig) {
        return Err(arkret_wire::ReasonCode::KEYPACKAGE_WELCOME_ENVELOPE_MISMATCH);
    }
    Ok(())
}

fn verification_method_controller(verification_method: &str) -> &str {
    let no_query = verification_method
        .split_once('?')
        .map(|(head, _)| head)
        .unwrap_or(verification_method);
    no_query
        .split_once('#')
        .map(|(head, _)| head)
        .unwrap_or(no_query)
}

fn device_signature_kid_points_to_device_key(
    kid: &str,
    actor: &str,
    device_public_key: &str,
) -> bool {
    let expected_did_key = format!("did:key:{device_public_key}");
    kid == expected_did_key
        || kid
            .strip_prefix(&expected_did_key)
            .is_some_and(|rest| rest.starts_with('#') || rest.starts_with('?'))
        || verification_method_controller(kid) == actor
}

/// Resolve the published PSK against the principal DID document (control-set
/// membership) and confirm the published bytes match.
async fn resolve_psk_in_control_set(
    state: &AppState,
    content: &CrossSigningPublish,
) -> Result<VerifyingKey, &'static str> {
    let kid = content.principal_signing_key.kid.as_str();
    // resolve_ed25519_pubkey enforces that the verification method is present in
    // the principal's DID document — i.e. in its control set.
    let resolved = crate::jws_verify::resolve_ed25519_pubkey_async(state, kid)
        .await
        .map_err(|_| "cross_signing_psk_not_in_control_set")?;
    let published = decode_ed25519_key(
        content.principal_signing_key.public_key.as_str(),
        content.principal_signing_key.key_format.as_str(),
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
    /// §8.2: the device HPKE sealing public key echoed verbatim from the
    /// authorize payload projection. Present only for verified, non-revoked
    /// devices; never substituted in projection.
    pub hpke_key: Option<String>,
    /// §8.2: the canonical trust-binding algorithms array echoed verbatim
    /// from the authorize payload projection.
    pub trust_algorithms: Option<Vec<String>>,
    pub status: DeviceStatus,
    /// Tier-2 (device-lifecycle.md §8.2): the device's authoritative
    /// `cross_signing_binding` echoed verbatim for client-side chain
    /// verification. Present only for a verified, non-revoked device that
    /// carries one (inception bootstrap devices have none).
    pub cross_signing_binding: Option<arkret_models_crypto::keys::QueryDeviceCrossSigningBinding>,
    /// Service-attested trust material echoed from `ak.device.authorize`.
    /// Present only for a verified, non-revoked device that was authorized by a
    /// designated enrollment authority.
    pub enrollment_authority_binding: Option<DeviceEnrollmentAuthorityBinding>,
    /// Accepted `ak.device.authorize` event id anchoring the device-set
    /// projection. Service-attested clients use this with
    /// `enrollment_authority_binding` as the hot-path trust anchor.
    pub device_authorize_event_id: Option<EventId>,
    pub authorized_generation_ref: Option<arkret_wire::NonEmptyString>,
}

/// Typed view of the fields the device projection
/// (`project_device_authorize` / recovery completion) persists into the
/// devices-table `payload` column and the directory facet reads back.
/// Tolerant of extra stored fields (it is a storage row, not a wire shape);
/// every field is optional because legacy rows predate the newer columns.
#[derive(Debug, Default, serde::Deserialize)]
pub(crate) struct ProjectedDevicePayload {
    #[serde(default)]
    pub device_public_key: Option<String>,
    /// §8.2: hpke_key echoed verbatim from the authorize payload.
    #[serde(default)]
    pub hpke_key: Option<String>,
    /// §8.2: canonical trust-binding algorithms echoed verbatim.
    #[serde(default)]
    pub algorithms: Option<Vec<String>>,
    #[serde(default)]
    pub cross_signing_binding: Option<arkret_models_crypto::keys::QueryDeviceCrossSigningBinding>,
    #[serde(default)]
    pub enrollment_authority_binding: Option<DeviceEnrollmentAuthorityBinding>,
    #[serde(default)]
    pub device_authorize_event_id: Option<String>,
    #[serde(default)]
    pub authorized_generation_ref: Option<arkret_wire::NonEmptyString>,
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
    try_resolve_device_signing_directory_facet(state, principal_id, device_id)
        .await
        .unwrap_or_else(|error| {
            tracing::error!(%error, %principal_id, %device_id, "failed to resolve device signing directory facet");
            revoked_device_signing_directory_facet()
        })
}

/// Strict variant of [`resolve_device_signing_directory_facet`] for admission
/// paths that must distinguish an unavailable authoritative directory from an
/// unknown, unverified, or revoked device. A persistence failure is propagated
/// so callers can return a retriable service error instead of misclassifying it
/// as an invalid device proof.
pub(crate) async fn try_resolve_device_signing_directory_facet(
    state: &AppState,
    principal_id: &str,
    device_id: &str,
) -> Result<DeviceSigningDirectoryFacet, soland_services::ServiceError> {
    let record = match state
        .identities()
        .find_device(FindDeviceQuery {
            actor_id: principal_id.to_owned(),
            device_id: device_id.to_owned(),
        })
        .await?
    {
        Some(record) => record,
        None => return Ok(revoked_device_signing_directory_facet()),
    };
    if record.revoked_at.is_some() || record.verification_state != "verified" {
        return Ok(revoked_device_signing_directory_facet());
    }
    // Parse the stored projection row once through the typed view; a
    // malformed stored value drops the affected optional field rather than
    // failing the whole query.
    let payload: ProjectedDevicePayload =
        serde_json::from_value(record.payload.clone()).unwrap_or_default();
    let generation =
        crate::routing::identity::device_generation::current_device_generation(state, principal_id)
            .await?;
    let generation_usable = match generation {
        Some(generation) => {
            generation.status
                == crate::routing::identity::device_generation::DeviceGenerationStatus::Active
                && payload.authorized_generation_ref.as_deref()
                    == Some(generation.current_ref.as_str())
        }
        None => payload.authorized_generation_ref.is_none(),
    };
    if !generation_usable {
        return Ok(DeviceSigningDirectoryFacet {
            signing_key_did: None,
            hpke_key: None,
            trust_algorithms: None,
            status: DeviceStatus::Revoked,
            cross_signing_binding: None,
            enrollment_authority_binding: None,
            device_authorize_event_id: None,
            authorized_generation_ref: payload.authorized_generation_ref,
        });
    }
    let signing_key_did = payload
        .device_public_key
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .filter(|value| decode_ed25519_key(value, "multibase").is_ok())
        .map(|value| format!("did:key:{value}"));
    // §8.2: echo the projected hpke_key / canonical algorithms verbatim.
    let hpke_key = payload
        .hpke_key
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned);
    let trust_algorithms = payload.algorithms.filter(|values| !values.is_empty());
    let device_authorize_event_id = payload
        .device_authorize_event_id
        .and_then(|value| EventId::new(value).ok());
    Ok(DeviceSigningDirectoryFacet {
        signing_key_did,
        hpke_key,
        trust_algorithms,
        status: DeviceStatus::Active,
        cross_signing_binding: payload.cross_signing_binding,
        enrollment_authority_binding: payload.enrollment_authority_binding,
        device_authorize_event_id,
        authorized_generation_ref: payload.authorized_generation_ref,
    })
}

fn revoked_device_signing_directory_facet() -> DeviceSigningDirectoryFacet {
    DeviceSigningDirectoryFacet {
        signing_key_did: None,
        hpke_key: None,
        trust_algorithms: None,
        status: DeviceStatus::Revoked,
        cross_signing_binding: None,
        enrollment_authority_binding: None,
        device_authorize_event_id: None,
        authorized_generation_ref: None,
    }
}

/// Resolve the per-principal Tier-2 `cross_signing` outcome material
/// (device-lifecycle.md §8.2 / §8.3): the principal's current accepted
/// `ak.cross_signing.publish` payload, rendered as the
/// `cross-signing-publish.schema.json` counterpart. Returns `None` when no
/// publish is accepted (e.g. inception-only principals). Reuses the
/// authoritative `CrossSigningRegistry::current_cross_signing` accepted state — the
/// same source the publish CAS bookkeeping writes.
pub(crate) fn resolve_current_cross_signing_publish(
    state: &AppState,
    principal_id: &str,
) -> Option<arkret_models_identity::CrossSigningPublish> {
    let principal = Did::new(principal_id.to_owned()).ok()?;
    let publish = state
        .identities()
        .current_cross_signing(&principal)?;
    // Re-serialize the SDK content type into the schema-counterpart publish
    // payload so both crates agree on the wire shape (fields are 1:1).
    serde_json::to_value(&publish).ok().and_then(|value| {
        serde_json::from_value::<arkret_models_identity::CrossSigningPublish>(value).ok()
    })
}

/// Decode an Ed25519 public key in the declared `key_format`
/// (`multibase` z-base58btc with the 0xed01 multicodec, or `raw_base64url`).
pub(crate) fn decode_ed25519_key(material: &str, key_format: &str) -> Result<VerifyingKey, String> {
    let raw: Vec<u8> = match key_format {
        "multibase" => arkret_canonical::decode_ed25519_multibase(material)
            .map(|bytes| bytes.to_vec())
            .map_err(|e| e.to_string())?,
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

pub(crate) fn ed25519_verify(key: &VerifyingKey, message: &[u8], signature_b64: &str) -> bool {
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

