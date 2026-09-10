//! Device possession, directory, and recovery-policy verification helpers.

use arkret_identifiers::EventId;
use arkret_models_collaboration::events_payloads::MlsWelcomeClaimEnvelope;
use arkret_models_collaboration::events_payloads::device_identity::DeviceAuthorizePayload;
use arkret_models_crypto::{DeviceStatus, PeerKeyPackageClaimReceipt};
use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};
use serde_json::Value;
use soland_services::identity::{FindDeviceQuery, RecoveryPolicyState};

use super::device_signature_kid_points_to_device_key;
use crate::state::AppState;

pub(crate) fn policy_device_quorum_threshold(policy: &RecoveryPolicyState) -> Option<u32> {
    let policy: arkret_models_crypto::RecoveryPolicy =
        serde_json::from_value(policy.raw_payload.clone()).ok()?;
    policy.validate().ok()?;
    match policy.method(arkret_models_crypto::RecoveryProofKind::DeviceQuorum) {
        Some(arkret_models_crypto::RecoveryMethod::DeviceQuorum { k, .. }) => Some(*k),
        _ => None,
    }
}

pub fn validate_device_authorize_binding(
    _state: &AppState,
    payload: &DeviceAuthorizePayload,
    subject_account_id: &arkret_wire::AccountId,
) -> Result<(), &'static str> {
    arkret_signatures::verify_device_authorize_possession(payload, subject_account_id)
        .map_err(|_| "device_authorize_device_signature_invalid")
}

pub(crate) async fn verify_mls_welcome_claim_envelope_signature(
    state: &AppState,
    envelope: &MlsWelcomeClaimEnvelope,
    claim_receipt: &PeerKeyPackageClaimReceipt,
    sender_device_id: Option<&str>,
    producer_signing_key: Option<&arkret_wire::DidKey>,
) -> Result<(), &'static str> {
    envelope.validate_signature_shape()?;
    if let Some(signature_algorithm) = envelope.signature.signature_algorithm.as_deref()
        && signature_algorithm != "Ed25519"
    {
        return Err(arkret_wire::ReasonCode::KEYPACKAGE_WELCOME_ENVELOPE_MISMATCH);
    }
    match &envelope.trust_binding {
        arkret_models_collaboration::events_payloads::MlsRequesterTrustBinding::RequesterDevice {
            requester_device_id,
            requester_device_authorize_event_id,
        } => {
            if sender_device_id.is_some_and(|sender| sender != requester_device_id.as_str()) {
                return Err(arkret_wire::ReasonCode::KEYPACKAGE_WELCOME_ENVELOPE_MISMATCH);
            }
            let account = envelope.requester_actor_id.as_account_id()
                .ok_or(arkret_wire::ReasonCode::KEYPACKAGE_WELCOME_ENVELOPE_MISMATCH)?;
            if account.station_id.as_str() != state.service_id() {
                // This key is supplied only by exact Event/Actor-bound,
                // independently verified origin-Station admission evidence.
                // A foreign account must never borrow our local device row.
                let key = producer_signing_key
                    .ok_or(arkret_wire::ReasonCode::KEYPACKAGE_WELCOME_ENVELOPE_MISMATCH)?;
                if !device_signature_kid_points_to_device_key(
                    envelope.signature.kid.as_str(),
                    account.principal_id.as_str(),
                    key.as_str(),
                ) {
                    return Err(arkret_wire::ReasonCode::KEYPACKAGE_WELCOME_ENVELOPE_MISMATCH);
                }
                return verify_welcome_signature(envelope, claim_receipt, key.as_str());
            }
            let record = state
                .identities()
                .find_device(FindDeviceQuery {
                    actor_id: account.principal_id.to_string(),
                    device_id: requester_device_id.as_str().to_owned(),
                })
                .await
                .map_err(|_| arkret_wire::ReasonCode::KEYPACKAGE_WELCOME_ENVELOPE_MISMATCH)?
                .ok_or(arkret_wire::ReasonCode::KEYPACKAGE_WELCOME_ENVELOPE_MISMATCH)?;
            if record.revoked_at.is_some() || record.verification_state != "verified" {
                return Err(arkret_wire::ReasonCode::KEYPACKAGE_WELCOME_ENVELOPE_MISMATCH);
            }
            if record
                .payload
                .get("device_authorize_event_id")
                .and_then(Value::as_str)
                != Some(requester_device_authorize_event_id.as_str())
            {
                return Err(arkret_wire::ReasonCode::KEYPACKAGE_WELCOME_ENVELOPE_MISMATCH);
            }
            let device_public_key = record
                .payload
                .get("device_public_key_did")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .ok_or(arkret_wire::ReasonCode::KEYPACKAGE_WELCOME_ENVELOPE_MISMATCH)?;
            if let Some(producer_signing_key) = producer_signing_key {
                let producer_public_key = producer_signing_key
                    .as_str()
                    .strip_prefix("did:key:")
                    .ok_or(arkret_wire::ReasonCode::KEYPACKAGE_WELCOME_ENVELOPE_MISMATCH)?;
                let expected_public_key = device_public_key
                    .strip_prefix("did:key:")
                    .unwrap_or(device_public_key);
                if producer_public_key != expected_public_key {
                    return Err(arkret_wire::ReasonCode::KEYPACKAGE_WELCOME_ENVELOPE_MISMATCH);
                }
            }
            if !device_signature_kid_points_to_device_key(
                envelope.signature.kid.as_str(),
                envelope.requester_actor_id.signing_principal_id().as_str(),
                device_public_key,
            ) {
                return Err(arkret_wire::ReasonCode::KEYPACKAGE_WELCOME_ENVELOPE_MISMATCH);
            }
            verify_welcome_signature(envelope, claim_receipt, device_public_key)
        }
        arkret_models_collaboration::events_payloads::MlsRequesterTrustBinding::RequesterAgent {
            requester_agent_id,
            requester_agent_verification_method,
            requester_agent_key_authorize_event_id,
        } => {
            if sender_device_id.is_some()
                || !matches!(envelope.requester_actor_id, arkret_wire::ActorId::Account { .. })
                || requester_agent_id != envelope.requester_actor_id.signing_principal_id()
                || envelope.signature.kid.as_str()
                    != requester_agent_verification_method.as_str()
            {
                return Err(arkret_wire::ReasonCode::KEYPACKAGE_WELCOME_ENVELOPE_MISMATCH);
            }
            if envelope.requester_actor_id.route_service_id().as_str() != state.service_id() {
                let key = producer_signing_key
                    .ok_or(arkret_wire::ReasonCode::KEYPACKAGE_WELCOME_ENVELOPE_MISMATCH)?;
                return verify_welcome_signature(envelope, claim_receipt, key.as_str());
            }
            if crate::routing::identity::agent_pcr::agent_record_for_actor(
                state, &envelope.requester_actor_id,
            ).await.map_err(|_| arkret_wire::ReasonCode::KEYPACKAGE_WELCOME_ENVELOPE_MISMATCH)?.is_none()
                || !crate::routing::mls::current_agent_key_authorization_matches_method(
                    state,
                    requester_agent_id,
                    requester_agent_key_authorize_event_id.as_str(),
                    requester_agent_verification_method.as_str(),
                )
                .await
            {
                return Err(arkret_wire::ReasonCode::KEYPACKAGE_WELCOME_ENVELOPE_MISMATCH);
            }
            let public_key = if let Some(producer_signing_key) = producer_signing_key {
                let multibase = producer_signing_key
                    .as_str()
                    .strip_prefix("did:key:")
                    .ok_or(arkret_wire::ReasonCode::KEYPACKAGE_WELCOME_ENVELOPE_MISMATCH)?;
                arkret_canonical::decode_ed25519_multibase(multibase)
                    .map_err(|_| arkret_wire::ReasonCode::KEYPACKAGE_WELCOME_ENVELOPE_MISMATCH)?
            } else {
                crate::jws_verify::resolve_ed25519_pubkey_async(
                    state,
                    requester_agent_verification_method.as_str(),
                )
                .await
                .map_err(|_| arkret_wire::ReasonCode::KEYPACKAGE_WELCOME_ENVELOPE_MISMATCH)?
                .to_bytes()
            };
            verify_welcome_signature_with_key(envelope, claim_receipt, &public_key)
        }
        arkret_models_collaboration::events_payloads::MlsRequesterTrustBinding::RequesterMinimalMetadataPairwise {
            requester_pairwise_verification_method,
        } => {
            if sender_device_id.is_some()
                || envelope.signature.kid.as_str()
                    != requester_pairwise_verification_method.as_str()
                || arkret_models_crypto::MlsEndpointIdentity::minimal_metadata_pairwise(
                    envelope.requester_actor_id.signing_principal_id().clone(),
                    requester_pairwise_verification_method.clone(),
                )
                .is_err()
            {
                return Err(arkret_wire::ReasonCode::KEYPACKAGE_WELCOME_ENVELOPE_MISMATCH);
            }
            let multibase = requester_pairwise_verification_method
                .as_str()
                .split_once('#')
                .and_then(|(controller, _)| controller.strip_prefix("did:key:"))
                .ok_or(arkret_wire::ReasonCode::KEYPACKAGE_WELCOME_ENVELOPE_MISMATCH)?;
            let public_key = arkret_canonical::decode_ed25519_multibase(multibase)
                .map_err(|_| arkret_wire::ReasonCode::KEYPACKAGE_WELCOME_ENVELOPE_MISMATCH)?;
            verify_welcome_signature_with_key(envelope, claim_receipt, &public_key)
        }
    }
}

fn verify_welcome_signature(
    envelope: &MlsWelcomeClaimEnvelope,
    claim_receipt: &PeerKeyPackageClaimReceipt,
    device_public_key: &str,
) -> Result<(), &'static str> {
    let device_key = decode_ed25519_key(device_public_key, "multibase")
        .map_err(|_| arkret_wire::ReasonCode::KEYPACKAGE_WELCOME_ENVELOPE_MISMATCH)?;
    verify_welcome_signature_with_key(envelope, claim_receipt, &device_key.to_bytes())
}

fn verify_welcome_signature_with_key(
    envelope: &MlsWelcomeClaimEnvelope,
    claim_receipt: &PeerKeyPackageClaimReceipt,
    key: &[u8; 32],
) -> Result<(), &'static str> {
    let signing_bytes = envelope
        .canonical_signing_bytes(claim_receipt)
        .map_err(|_| arkret_wire::ReasonCode::KEYPACKAGE_WELCOME_ENVELOPE_MISMATCH)?;
    let key = VerifyingKey::from_bytes(key)
        .map_err(|_| arkret_wire::ReasonCode::KEYPACKAGE_WELCOME_ENVELOPE_MISMATCH)?;
    if !ed25519_verify(&key, &signing_bytes, &envelope.signature.sig) {
        return Err(arkret_wire::ReasonCode::KEYPACKAGE_WELCOME_ENVELOPE_MISMATCH);
    }
    Ok(())
}

pub(crate) struct DeviceSigningDirectoryFacet {
    pub signing_key_did: Option<String>,
    pub hpke_key: Option<String>,
    pub trust_algorithms: Option<Vec<String>>,
    pub status: DeviceStatus,
    pub device_authorize_event_id: Option<EventId>,
    pub authorized_generation_ref: Option<u64>,
}

/// Resolve the exact current accepted authorization, not merely an Active
/// directory label. Consumers must not extend this authority with a session
/// lifetime, a cached directory result, or a newly issued attestation TTL.
pub(crate) async fn current_device_authorization(
    state: &AppState,
    actor: &arkret_wire::ActorId,
    device_id: &arkret_wire::DeviceId,
    facet: &DeviceSigningDirectoryFacet,
) -> Result<Option<DeviceAuthorizePayload>, soland_services::ServiceError> {
    if !actor
        .as_account_id()
        .is_some_and(|account| account.station_id.as_str() == state.service_id())
        || facet.status != DeviceStatus::Active
    {
        return Ok(None);
    }
    let (Some(event_id), Some(generation)) = (
        facet.device_authorize_event_id.as_ref(),
        facet
            .authorized_generation_ref
            .filter(|generation| *generation >= 1),
    ) else {
        return Ok(None);
    };
    let Some(event) = state
        .event_queries()
        .canonical_event(event_id.as_str())
        .await
        .map_err(|error| soland_services::ServiceError::internal(error.to_string()))?
    else {
        return Ok(None);
    };
    let Some(payload) = event.envelope.get("payload") else {
        return Ok(None);
    };
    let Ok(authorization) = serde_json::from_value::<DeviceAuthorizePayload>(payload.clone())
    else {
        return Ok(None);
    };
    if event.actor_id != actor.to_string() || authorization.device_id != *device_id {
        return Ok(None);
    }
    // Resolve all authority material before the final current-state gate;
    // no unrelated asynchronous lookup may extend its freshness window.
    let Ok(selector) = super::device_generation::active_device_revocation_gate_selector(
        state,
        actor.signing_principal_id().as_str(),
        device_id.as_str(),
    )
    .await
    else {
        return Ok(None);
    };
    if event_id.as_str() != selector.target_device_authorize_event_id
        || generation != selector.target_device_generation_ref
        || state
            .persistence()
            .device_revocation_gate_status(&selector)
            .await?
            != soland_storage::DeviceRevocationGateStatus::Active
        || !device_authorization_is_effective_at(&authorization, chrono::Utc::now())
    {
        return Ok(None);
    }
    Ok(Some(authorization))
}

pub(crate) fn device_authorization_is_effective_at(
    authorization: &DeviceAuthorizePayload,
    at: chrono::DateTime<chrono::Utc>,
) -> bool {
    authorization.not_before <= at
        && authorization
            .expires_at
            .flatten()
            .is_none_or(|expiry| at < expiry)
}

#[derive(Debug, Default, serde::Deserialize)]
pub(crate) struct ProjectedDevicePayload {
    #[serde(default)]
    pub device_public_key_did: Option<String>,
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
        .device_public_key_did
        .as_deref()
        .map(str::trim)
        .filter(|value| value.starts_with("did:key:"))
        .filter(|value| decode_ed25519_key(value, "multibase").is_ok())
        .map(ToOwned::to_owned);
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
    use arkret_models_collaboration::events_payloads::MlsRequesterTrustBinding;
    use arkret_wire::{AccountId, ActorId, DidCoreId};
    use ed25519_dalek::Signer as _;
    use serde_json::json;

    use super::*;

    #[test]
    fn device_authorization_time_window_has_exact_inclusive_start_and_exclusive_expiry() {
        let start = chrono::DateTime::parse_from_rfc3339("2026-09-01T00:00:00.000Z")
            .unwrap()
            .to_utc();
        let mut authorization: DeviceAuthorizePayload = serde_json::from_value(json!({
            "device_id": "ak:device:01904100-0000-7000-8000-a11ce0000001",
            "device_public_key_did": "did:key:z6MkFixture",
            "hpke_key": "z6LSFixture",
            "algorithms": ["ak.mls.v1"],
            "authorized_by": "ak:did_core:web:alice.example",
            "not_before": "2026-09-01T00:00:00.000Z",
            "authorization_binding_kind": "registration_anchor",
            "device_signature": "c2ln"
        }))
        .unwrap();
        assert!(!device_authorization_is_effective_at(
            &authorization,
            start - chrono::Duration::milliseconds(1)
        ));
        assert!(device_authorization_is_effective_at(&authorization, start));
        assert!(device_authorization_is_effective_at(
            &authorization,
            start + chrono::Duration::days(1)
        ));
        authorization.expires_at = Some(None);
        assert!(device_authorization_is_effective_at(&authorization, start));
        let expiry = start + chrono::Duration::seconds(1);
        authorization.expires_at = Some(Some(expiry));
        assert!(device_authorization_is_effective_at(
            &authorization,
            expiry - chrono::Duration::milliseconds(1)
        ));
        assert!(!device_authorization_is_effective_at(
            &authorization,
            expiry
        ));
        assert!(!device_authorization_is_effective_at(
            &authorization,
            expiry + chrono::Duration::milliseconds(1)
        ));
    }

    fn signed_welcome_fixture(
        actor: ActorId,
        trust_binding: MlsRequesterTrustBinding,
        method: &str,
        key: &ed25519_dalek::SigningKey,
    ) -> (MlsWelcomeClaimEnvelope, PeerKeyPackageClaimReceipt) {
        let realm = "ak:realm:Ac1aCK8aQdnkYImvdH3DFjq4jDCP198pXYWCGzGuVyj5";
        let receipt: PeerKeyPackageClaimReceipt = serde_json::from_value(json!({
            "claim_request_id": "Y2xhaW0",
            "request_digest": format!("sha256:{}", "11".repeat(32)),
            "claims_digest": format!("sha256:{}", "22".repeat(32)),
            "source_id": actor.route_service_id(),
            "destination_id": "ak:did_core:web:destination.example",
            "request": {
                "claim_request_id": "Y2xhaW0",
                "target_account_id": {
                    "principal_id": "ak:did_core:web:bob.example",
                    "station_id": "ak:did_core:web:destination.example"
                },
                "requester_account_id": {
                    "principal_id": actor.signing_principal_id(),
                    "station_id": actor.route_service_id()
                },
                "intended_realm_id": realm,
                "mls_group_id": "fixture-group",
                "claim_purpose": "realm_membership",
                "required_capabilities": ["ak.content.v1"],
                "expires_at": "2099-01-01T00:00:00.000Z"
            },
            "claimed_at": "2026-08-31T00:00:00.000Z",
            "expires_at": "2099-01-01T00:00:00.000Z",
            "signature": {"kid": "did:web:destination.example#notary", "signature_algorithm": "Ed25519", "sig": "AA"}
        })).unwrap();
        let mut envelope = MlsWelcomeClaimEnvelope {
            keypackage_ref: "ak:mls:keypackage:fixture".to_owned(),
            keypackage_digest: arkret_wire::Hash::new(format!("sha256:{}", "33".repeat(32)))
                .unwrap(),
            intended_realm_id: arkret_wire::RealmId::new(realm).unwrap(),
            claim_id: arkret_wire::NonEmptyString::new("fixture-claim").unwrap(),
            requester_actor_id: actor,
            trust_binding,
            welcome_digest: arkret_wire::Hash::new(format!("sha256:{}", "44".repeat(32))).unwrap(),
            created_at: receipt.claimed_at,
            signature: arkret_models_crypto::KeyOperationSignature {
                kid: arkret_wire::NonEmptyString::new(method).unwrap(),
                signature_algorithm: Some(arkret_wire::NonEmptyString::new("Ed25519").unwrap()),
                sig: arkret_wire::Base64UrlString::new("AA").unwrap(),
            },
        };
        envelope.signature.sig = arkret_wire::Base64UrlString::new(
            URL_SAFE_NO_PAD.encode(
                key.sign(&envelope.canonical_signing_bytes(&receipt).unwrap())
                    .to_bytes(),
            ),
        )
        .unwrap();
        (envelope, receipt)
    }

    #[tokio::test]
    async fn foreign_welcome_device_requires_verified_origin_key_not_a_local_same_principal_row() {
        let state = AppState::new(
            crate::config::AppConfig::test_default(),
            soland_storage_postgres::Db { pool: None },
        );
        let key = ed25519_dalek::SigningKey::from_bytes(&[71; 32]);
        let public = arkret_wire::DidKey::new(format!(
            "did:key:{}",
            arkret_canonical::ed25519_pubkey_to_did_key_multibase(&key.verifying_key().to_bytes())
        ))
        .unwrap();
        let principal = DidCoreId::new("ak:did_core:web:alice.example").unwrap();
        let actor = ActorId::account(AccountId::new(
            principal.clone(),
            DidCoreId::new("ak:did_core:web:foreign.example").unwrap(),
        ));
        let device =
            arkret_wire::DeviceId::new("ak:device:01904100-0000-7000-8000-000000000001").unwrap();
        let authorize =
            arkret_wire::EventId::new("ak:event:ARELvWOpF6BRrks3DlbQy-9XIE6aAQQumDQp7fA4ApeM")
                .unwrap();
        let (envelope, receipt) = signed_welcome_fixture(
            actor,
            MlsRequesterTrustBinding::RequesterDevice {
                requester_device_id: device.clone(),
                requester_device_authorize_event_id: authorize.clone(),
            },
            "did:web:alice.example#device",
            &key,
        );
        let now = chrono::Utc::now();
        state.identities().save_device_if_absent(soland_services::identity::DeviceIdentity {
            actor_id: principal.to_string(), device_id: device.to_string(), display_name: None,
            verification_state: "verified".into(),
            payload: json!({"device_public_key_did": public, "device_authorize_event_id": authorize}),
            created_at: now, updated_at: now, revoked_at: None,
        }).await.unwrap();
        assert!(
            verify_mls_welcome_claim_envelope_signature(
                &state,
                &envelope,
                &receipt,
                Some(device.as_str()),
                None
            )
            .await
            .is_err()
        );
        verify_mls_welcome_claim_envelope_signature(
            &state,
            &envelope,
            &receipt,
            Some(device.as_str()),
            Some(&public),
        )
        .await
        .unwrap();
        let mut rewritten = envelope.clone();
        rewritten.requester_actor_id = ActorId::account(AccountId::new(
            principal,
            DidCoreId::new("ak:did_core:web:other-foreign.example").unwrap(),
        ));
        assert!(
            verify_mls_welcome_claim_envelope_signature(
                &state,
                &rewritten,
                &receipt,
                Some(device.as_str()),
                Some(&public)
            )
            .await
            .is_err()
        );
    }

    #[tokio::test]
    async fn agent_and_pairwise_welcome_signatures_preserve_their_exact_account() {
        let state = AppState::new(
            crate::config::AppConfig::test_default(),
            soland_storage_postgres::Db { pool: None },
        );
        let key = ed25519_dalek::SigningKey::from_bytes(&[72; 32]);
        let multibase =
            arkret_canonical::ed25519_pubkey_to_did_key_multibase(&key.verifying_key().to_bytes());
        let public = arkret_wire::DidKey::new(format!("did:key:{multibase}")).unwrap();
        let principal = DidCoreId::new("ak:did_core:web:agent.example").unwrap();
        let station = DidCoreId::new("ak:did_core:web:foreign.example").unwrap();
        let actor = ActorId::account(arkret_wire::AccountId::new(
            principal.clone(),
            station.clone(),
        ));
        let method = "did:web:agent.example#runtime";
        let (envelope, receipt) = signed_welcome_fixture(
            actor,
            MlsRequesterTrustBinding::RequesterAgent {
                requester_agent_id: principal.clone(),
                requester_agent_verification_method: arkret_wire::DidUrl::new(method.to_owned())
                    .unwrap(),
                requester_agent_key_authorize_event_id: arkret_wire::EventId::new(
                    "ak:event:ARELvWOpF6BRrks3DlbQy-9XIE6aAQQumDQp7fA4ApeM",
                )
                .unwrap(),
            },
            method,
            &key,
        );
        assert!(
            verify_mls_welcome_claim_envelope_signature(&state, &envelope, &receipt, None, None)
                .await
                .is_err()
        );
        verify_mls_welcome_claim_envelope_signature(
            &state,
            &envelope,
            &receipt,
            None,
            Some(&public),
        )
        .await
        .unwrap();
        let mut wrong_branch = envelope.clone();
        wrong_branch.requester_actor_id = ActorId::service(principal);
        assert!(
            verify_mls_welcome_claim_envelope_signature(
                &state,
                &wrong_branch,
                &receipt,
                None,
                Some(&public)
            )
            .await
            .is_err()
        );
        let pairwise = DidCoreId::new(format!("ak:did_core:key:{multibase}")).unwrap();
        let method = format!("did:key:{multibase}#{multibase}");
        let (envelope, receipt) = signed_welcome_fixture(
            ActorId::account(AccountId::new(pairwise, station)),
            MlsRequesterTrustBinding::RequesterMinimalMetadataPairwise {
                requester_pairwise_verification_method: arkret_wire::DidUrl::new(method.clone())
                    .unwrap(),
            },
            &method,
            &key,
        );
        verify_mls_welcome_claim_envelope_signature(&state, &envelope, &receipt, None, None)
            .await
            .unwrap();
    }
}
