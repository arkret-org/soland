use super::*;

pub(super) async fn preflight_mls_welcome_claim_signature_reject(
    state: &AppState,
    session: &SessionRecord,
    object: &serde_json::Map<String, Value>,
    actor_id: &arkret_wire::ActorId,
    operation: &Operation,
    internal_admission: Option<&InternalEventAdmission>,
) -> Option<String> {
    if kinds::canonical_kind(operation) != arkret_wire::EventKind::MlsWelcome {
        return None;
    }
    let welcome = match operation.typed_payload::<arkret_wire::event_spec::MlsWelcome>() {
        Ok(welcome) => welcome,
        Err(_) => {
            return Some(arkret_wire::ReasonCode::KEYPACKAGE_WELCOME_ENVELOPE_MISMATCH.to_owned());
        }
    };
    let envelope = &welcome.claim_envelope;
    if &envelope.requester_actor_id != actor_id {
        return Some(arkret_wire::ReasonCode::KEYPACKAGE_WELCOME_ENVELOPE_MISMATCH.to_owned());
    }
    let sender_device_id = welcome.sender_device_id.as_ref().map(|id| id.as_str());
    let producer_signing_key = internal_admission.and_then(|admission| {
        admission.federated_producer_signing_key(session, object, envelope.signature.kid.as_str())
    });
    crate::routing::identity::device_signing::verify_mls_welcome_claim_envelope_signature(
        state,
        envelope,
        &welcome.claim_receipt,
        sender_device_id,
        producer_signing_key,
    )
    .await
    .err()
    .map(str::to_owned)
}

pub(super) async fn preflight_mls_welcome_claim_ledger_reject(
    state: &AppState,
    actor_id: &arkret_wire::ActorId,
    operation: &Operation,
) -> Option<String> {
    if kinds::canonical_kind(operation) != arkret_wire::EventKind::MlsWelcome {
        return None;
    }
    crate::routing::mls::validate_local_welcome_peer_claim(
        state,
        operation.realm_id.as_str(),
        actor_id,
        &operation.payload,
    )
    .await
    .err()
    .map(|reason| {
        if reason == "peer_claim_welcome_pending" {
            "dependency_missing".to_owned()
        } else {
            arkret_wire::ReasonCode::KEYPACKAGE_WELCOME_ENVELOPE_MISMATCH.to_owned()
        }
    })
}

#[cfg(test)]
mod tests {
    use arkret_models_collaboration::events_payloads::{
        MlsRequesterTrustBinding, MlsWelcomePayload,
    };
    use arkret_wire::{AccountId, ActorId, DidCoreId};
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use ed25519_dalek::Signer as _;
    use serde_json::json;

    use super::{AppState, SessionRecord, preflight_mls_welcome_claim_signature_reject};

    #[tokio::test]
    async fn welcome_signature_preflight_binds_the_actual_actor_and_device_signature() {
        let state = AppState::new(
            crate::config::AppConfig::test_default(),
            soland_storage_postgres::Db { pool: None },
        );
        let principal = DidCoreId::new("ak:did_core:web:alice.example").unwrap();
        let station = state.service_core_id();
        let account = ActorId::account(AccountId::new(principal.clone(), station.clone()));
        let service = ActorId::service(principal.clone());
        let foreign = ActorId::account(AccountId::new(
            principal.clone(),
            DidCoreId::new("ak:did_core:web:station-b.example").unwrap(),
        ));
        let device =
            arkret_wire::DeviceId::new("ak:device:01904100-0000-7000-8000-000000000001").unwrap();
        let authorize =
            arkret_wire::EventId::new("ak:event:ARELvWOpF6BRrks3DlbQy-9XIE6aAQQumDQp7fA4ApeM")
                .unwrap();
        let key = ed25519_dalek::SigningKey::from_bytes(&[83; 32]);
        let public = format!(
            "did:key:{}",
            arkret_canonical::ed25519_pubkey_to_did_key_multibase(key.verifying_key().as_bytes(),),
        );
        let at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
        state.identities().save_device_if_absent(soland_services::identity::DeviceIdentity {
            actor_id: principal.to_string(),
            device_id: device.to_string(),
            display_name: None,
            verification_state: "verified".to_owned(),
            payload: json!({"device_public_key": public, "device_authorize_event_id": authorize}),
            created_at: at,
            updated_at: at,
            revoked_at: None,
        }).await.unwrap();
        let fixture = arkret_schema_conformance::spec_json_artifact(
            "fixtures/keypackage-pairwise-welcome-fixture.json",
        )
        .unwrap();
        let mut welcome: MlsWelcomePayload =
            serde_json::from_value(fixture["schema_validation_cases"][0]["instance"].clone())
                .unwrap();
        welcome.sender_device_id = Some(device.clone());
        welcome.claim_envelope.requester_actor_id = account.clone();
        welcome.claim_envelope.trust_binding = MlsRequesterTrustBinding::RequesterDevice {
            requester_device_id: device.clone(),
            requester_device_authorize_event_id: authorize,
        };
        welcome.claim_receipt.source_id = state.service_core_id();
        welcome.claim_receipt.request.requester_id = principal.clone();
        welcome.claim_envelope.signature.kid =
            arkret_wire::NonEmptyString::new("did:web:alice.example#device").unwrap();
        welcome.claim_envelope.signature.sig = arkret_wire::Base64UrlString::new(
            URL_SAFE_NO_PAD.encode(
                key.sign(
                    &welcome
                        .claim_envelope
                        .canonical_signing_bytes(&welcome.claim_receipt)
                        .unwrap(),
                )
                .to_bytes(),
            ),
        )
        .unwrap();
        let operation = arkret_event_draft::test_support::raw_projected_operation(
            arkret_wire::OperationId::new("ak:operation:01904100-0000-7000-8000-000000000001")
                .unwrap(),
            welcome.claim_envelope.intended_realm_id.clone(),
            arkret_wire::EventKind::MlsWelcome,
            serde_json::to_value(&welcome).unwrap(),
        );
        let session = SessionRecord {
            token_hash: "welcome-preflight-test".to_owned(),
            account_pk: None,
            actor: principal.to_string(),
            device_id: device.to_string(),
            audience: state.service_id().clone(),
            session_public_key: None,
            agent_session: None,
            session_grant: None,
            expires_at: at + chrono::Duration::minutes(5),
            created_at: at,
            revoked_at: None,
        };
        let object = json!({"actor_id": account}).as_object().unwrap().clone();
        assert_eq!(
            preflight_mls_welcome_claim_signature_reject(
                &state, &session, &object, &account, &operation, None,
            )
            .await,
            None
        );
        for wrong_actor in [&foreign, &service] {
            assert_eq!(
                preflight_mls_welcome_claim_signature_reject(
                    &state,
                    &session,
                    &object,
                    wrong_actor,
                    &operation,
                    None,
                )
                .await
                .as_deref(),
                Some(arkret_wire::ReasonCode::KEYPACKAGE_WELCOME_ENVELOPE_MISMATCH)
            );
        }
        let mut tampered = operation;
        tampered.payload["claim_envelope"]["signature"]["sig"] =
            json!(URL_SAFE_NO_PAD.encode([0_u8; 64]));
        assert_eq!(
            preflight_mls_welcome_claim_signature_reject(
                &state, &session, &object, &account, &tampered, None,
            )
            .await
            .as_deref(),
            Some(arkret_wire::ReasonCode::KEYPACKAGE_WELCOME_ENVELOPE_MISMATCH)
        );
    }
}
