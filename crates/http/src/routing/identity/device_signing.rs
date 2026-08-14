//! Device possession, directory, and recovery-policy verification helpers.

use arkret_identifiers::EventId;
use arkret_models_collaboration::events_payloads::MlsWelcomeClaimEnvelope;
use arkret_models_collaboration::events_payloads::device_identity::DeviceAuthorizePayload;
use arkret_models_crypto::DeviceStatus;
use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};
use serde_json::Value;
use soland_services::identity::{FindDeviceQuery, RecoveryPolicyState};

use crate::state::AppState;

pub(crate) fn device_quorum_method_matches(
    principal_id: &str,
    device_id: &str,
    device_public_key: &str,
    verification_method: &str,
) -> bool {
    let did_key = device_public_key
        .strip_prefix("did:key:")
        .map_or_else(|| format!("did:key:{device_public_key}"), str::to_owned);
    let fragment = did_key
        .strip_prefix("did:key:")
        .unwrap_or(device_public_key);
    verification_method == format!("{principal_id}#{device_id}")
        || verification_method == format!("{did_key}#{fragment}")
}

pub(crate) fn policy_mentions_identifier(
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

pub(crate) fn policy_device_quorum_threshold(policy: &RecoveryPolicyState) -> Option<u32> {
    [
        "/device_quorum/k",
        "/device_quorum/threshold",
        "/device_quorum/quorum_participant_count",
        "/proof_requirements/device_quorum/k",
        "/proof_requirements/device_quorum/threshold",
        "/proof_requirements/device_quorum/quorum_participant_count",
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

pub(crate) fn policy_requires_trusted_service_attestation(policy: &RecoveryPolicyState) -> bool {
    [
        "/trusted_recovery_service/attestation_required",
        "/trusted_recovery_service/require_attestation",
        "/proof_requirements/trusted_recovery_service/attestation_required",
        "/proof_requirements/trusted_recovery_service/require_attestation",
    ]
    .iter()
    .any(|pointer| {
        policy
            .raw_payload
            .pointer(pointer)
            .is_some_and(value_requires_attestation)
    })
}

fn value_requires_attestation(value: &Value) -> bool {
    match value {
        Value::Bool(value) => *value,
        Value::String(value) => matches!(value.as_str(), "required" | "true"),
        _ => false,
    }
}

pub fn validate_device_authorize_binding(
    _state: &AppState,
    payload: &DeviceAuthorizePayload,
) -> Result<(), &'static str> {
    match &payload.authorization_binding_kind {
        arkret_models_collaboration::events_payloads::DeviceAuthorizationBindingKind::RegistrationAnchor
        | arkret_models_collaboration::events_payloads::DeviceAuthorizationBindingKind::PcrRecovery => {
            arkret_signatures::verify_device_authorize_possession(payload)
                .map_err(|_| "device_authorize_device_signature_invalid")
        }
        arkret_models_collaboration::events_payloads::DeviceAuthorizationBindingKind::AcceptedDevice => {
            // The accepted-device target proof is challenge-bound and is
            // verified by the pair_device gate before this Event reaches
            // ordinary admission.  Reinterpreting its signature as the
            // root-anchored full-payload transcript would reject the formal
            // pre-assembly protocol and, more importantly, would omit the
            // pairing challenge from the possession proof.
            payload
                .validate_wire_constraints()
                .map_err(|_| "device_authorize_device_signature_invalid")
        }
    }
}

pub(crate) async fn verify_mls_welcome_claim_envelope_signature(
    state: &AppState,
    envelope: &MlsWelcomeClaimEnvelope,
    sender_device_id: Option<&str>,
    producer_signing_key: Option<&arkret_wire::DidKey>,
) -> Result<(), &'static str> {
    envelope.validate_signature_shape()?;
    if let Some(signature_algorithm) = envelope.signature.signature_algorithm.as_deref()
        && signature_algorithm != "Ed25519"
    {
        return Err(arkret_wire::ReasonCode::KEYPACKAGE_WELCOME_ENVELOPE_MISMATCH);
    }
    let requester_device_id = envelope
        .trust_binding
        .requester_device_id()
        .ok_or(arkret_wire::ReasonCode::KEYPACKAGE_WELCOME_ENVELOPE_MISMATCH)?
        .as_str();
    if let Some(sender_device_id) = sender_device_id
        && sender_device_id != requester_device_id
    {
        return Err(arkret_wire::ReasonCode::KEYPACKAGE_WELCOME_ENVELOPE_MISMATCH);
    }
    if let Some(producer_signing_key) = producer_signing_key {
        let device_public_key = producer_signing_key
            .as_str()
            .strip_prefix("did:key:")
            .ok_or(arkret_wire::ReasonCode::KEYPACKAGE_WELCOME_ENVELOPE_MISMATCH)?;
        return verify_welcome_signature(envelope, device_public_key);
    }
    let record = state
        .identities()
        .find_device(FindDeviceQuery {
            actor_id: envelope.requester_actor_id.as_str().to_owned(),
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
        envelope.signature.kid.as_str(),
        envelope.requester_actor_id.as_str(),
        device_public_key,
    ) {
        return Err(arkret_wire::ReasonCode::KEYPACKAGE_WELCOME_ENVELOPE_MISMATCH);
    }
    verify_welcome_signature(envelope, device_public_key)
}

fn verify_welcome_signature(
    envelope: &MlsWelcomeClaimEnvelope,
    device_public_key: &str,
) -> Result<(), &'static str> {
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
    let expected_principal_id_key = device_public_key
        .strip_prefix("did:key:")
        .map_or_else(|| format!("did:key:{device_public_key}"), str::to_owned);
    kid == expected_principal_id_key
        || kid
            .strip_prefix(&expected_principal_id_key)
            .is_some_and(|rest| rest.starts_with('#') || rest.starts_with('?'))
        || verification_method_controller(kid) == actor
        || arkret_wire::DidFullId::new(verification_method_controller(kid).to_owned())
            .and_then(|controller| arkret_wire::project_full_id_to_core_id(&controller))
            .is_ok_and(|controller| controller.as_str() == actor)
}

pub(crate) struct DeviceSigningDirectoryFacet {
    pub signing_key_did: Option<String>,
    pub hpke_key: Option<String>,
    pub trust_algorithms: Option<Vec<String>>,
    pub status: DeviceStatus,
    pub device_authorize_event_id: Option<EventId>,
    pub authorized_generation_ref: Option<u64>,
}

#[derive(Debug, Default, serde::Deserialize)]
pub(crate) struct ProjectedDevicePayload {
    #[serde(default)]
    pub device_public_key: Option<String>,
    #[serde(default)]
    pub hpke_key: Option<String>,
    #[serde(default)]
    pub algorithms: Option<Vec<String>>,
    #[serde(default)]
    pub device_authorize_event_id: Option<String>,
    #[serde(default)]
    pub authorized_generation_ref: Option<u64>,
}

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
    let payload: ProjectedDevicePayload =
        serde_json::from_value(record.payload.clone()).unwrap_or_default();
    let generation =
        crate::routing::identity::device_generation::current_device_generation(state, principal_id)
            .await?;
    let generation_usable = match generation {
        Some(generation) => {
            generation.status
                == crate::routing::identity::device_generation::DeviceGenerationStatus::Active
                && payload.authorized_generation_ref == Some(generation.current_ref)
        }
        None => payload.authorized_generation_ref.is_none(),
    };
    if !generation_usable {
        return Ok(DeviceSigningDirectoryFacet {
            authorized_generation_ref: payload.authorized_generation_ref,
            ..revoked_device_signing_directory_facet()
        });
    }
    let signing_key_did = payload
        .device_public_key
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .filter(|value| decode_ed25519_key(value, "multibase").is_ok())
        .map(|value| {
            if value.starts_with("did:key:") {
                value.to_owned()
            } else {
                format!("did:key:{value}")
            }
        });
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
        device_authorize_event_id: None,
        authorized_generation_ref: None,
    }
}

pub(crate) fn decode_ed25519_key(material: &str, key_format: &str) -> Result<VerifyingKey, String> {
    let material = material.strip_prefix("did:key:").unwrap_or(material);
    let raw: Vec<u8> = match key_format {
        "multibase" => arkret_canonical::decode_ed25519_multibase(material)
            .map(|bytes| bytes.to_vec())
            .map_err(|error| error.to_string())?,
        "raw_base64url" => URL_SAFE_NO_PAD
            .decode(material.as_bytes())
            .or_else(|_| STANDARD.decode(material.as_bytes()))
            .map_err(|error| format!("base64 decode: {error}"))?,
        other => return Err(format!("unsupported key_format `{other}`")),
    };
    let bytes: [u8; 32] = raw
        .as_slice()
        .try_into()
        .map_err(|_| "Ed25519 public key must be 32 bytes".to_owned())?;
    VerifyingKey::from_bytes(&bytes).map_err(|error| format!("invalid Ed25519 public key: {error}"))
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

#[cfg(test)]
mod tests {
    use super::{device_quorum_method_matches, device_signature_kid_points_to_device_key};

    #[test]
    fn device_signature_kid_projects_full_controller_to_core_actor() {
        assert!(device_signature_kid_points_to_device_key(
            "did:web:alice.example#ak:device:primary",
            "ak:did_core:web:alice.example",
            "z6MkAuthorizedDeviceKey",
        ));
        assert!(!device_signature_kid_points_to_device_key(
            "did:web:mallory.example#ak:device:primary",
            "ak:did_core:web:alice.example",
            "z6MkAuthorizedDeviceKey",
        ));
    }

    #[test]
    fn device_quorum_method_requires_a_concrete_verification_method() {
        let principal = "did:webvh:z6mkfixture:alice.example";
        let device = "ak:device:primary";
        let key = "z6MkQuorum";

        assert!(device_quorum_method_matches(
            principal,
            device,
            key,
            &format!("{principal}#{device}"),
        ));
        assert!(device_quorum_method_matches(
            principal,
            device,
            key,
            &format!("did:key:{key}#{key}"),
        ));
        assert!(!device_quorum_method_matches(
            principal,
            device,
            key,
            &format!("did:key:{key}"),
        ));
    }
}
