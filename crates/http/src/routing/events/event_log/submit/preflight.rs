use super::*;

pub(super) async fn preflight_mls_welcome_claim_signature_reject(
    state: &AppState,
    session: &SessionRecord,
    object: &serde_json::Map<String, Value>,
    actor_id: &str,
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
    if envelope.requester_actor_id.as_str() != actor_id {
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
    actor_id: &str,
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

pub(super) async fn preflight_mls_welcome_recipient_reject(
    state: &AppState,
    operation: &Operation,
) -> Option<String> {
    if kinds::canonical_kind(operation) != arkret_wire::EventKind::MlsWelcome {
        return None;
    }
    let welcome = operation
        .typed_payload::<arkret_wire::event_spec::MlsWelcome>()
        .ok()?;
    let (recipient_actor_id, recipient_device_id) = match &welcome.recipient {
        arkret_models_collaboration::events_payloads::MlsWelcomeRecipient::Device {
            recipient_device_id,
        } => (
            welcome.recipient_principal_id.as_ref()?.as_str(),
            recipient_device_id.as_str(),
        ),
        arkret_models_collaboration::events_payloads::MlsWelcomeRecipient::NativeAgent {
            recipient_agent_id,
            agent_key_authorize_event_id,
            ..
        } => {
        let authorization_matches = crate::routing::mls::current_agent_key_authorization_matches(
            state,
                recipient_agent_id,
                agent_key_authorize_event_id.as_str(),
        )
        .await;
        return welcome_recipient_trust_reject_reason(
                Some(agent_key_authorize_event_id.as_str()),
            authorization_matches,
            false,
        )
        .map(str::to_owned);
        }
        arkret_models_collaboration::events_payloads::MlsWelcomeRecipient::MinimalMetadataPairwise {
            ..
        } => return None,
    };
    let recipient_id = state
        .projections()
        .snapshot()
        .member(operation.realm_id.as_str(), recipient_actor_id)
        .and_then(|member| member.recipient_id.clone());
    if recipient_device_is_remote(state.service_id(), recipient_id.as_deref()) {
        // The canonical member delivery binding assigns this recipient to a
        // different Principal Server. That server validates its local device
        // record when the Welcome crosses federation ingress; treating the
        // absent device row on the source server as revocation would make
        // every cross-PS Welcome impossible.
        return None;
    }
    let device_revoked = crate::routing::identity::auth::is_device_revoked(
        state,
        recipient_actor_id,
        recipient_device_id,
    )
    .await;
    welcome_recipient_trust_reject_reason(None, false, device_revoked).map(str::to_owned)
}

fn recipient_device_is_remote(local_service_id: &str, recipient_id: Option<&str>) -> bool {
    recipient_id.is_some_and(|service_id| service_id != local_service_id)
}

fn welcome_recipient_trust_reject_reason(
    agent_key_authorize_event_id: Option<&str>,
    agent_authorization_matches: bool,
    device_revoked: bool,
) -> Option<&'static str> {
    if agent_key_authorize_event_id.is_some() {
        return (!agent_authorization_matches)
            .then_some(arkret_wire::ReasonCode::CLAIM_GENERATION_MISMATCH);
    }
    device_revoked.then_some("device_revoked")
}

#[cfg(test)]
mod tests {
    use super::{recipient_device_is_remote, welcome_recipient_trust_reject_reason};

    #[test]
    fn native_agent_welcome_uses_agent_authorization_instead_of_device_record() {
        assert_eq!(
            welcome_recipient_trust_reject_reason(Some("ak:event:authorize"), true, true),
            None
        );
        assert_eq!(
            welcome_recipient_trust_reject_reason(Some("ak:event:authorize"), false, false),
            Some(arkret_wire::ReasonCode::CLAIM_GENERATION_MISMATCH)
        );
    }

    #[test]
    fn device_welcome_still_rejects_revoked_recipient() {
        assert_eq!(
            welcome_recipient_trust_reject_reason(None, false, true),
            Some("device_revoked")
        );
    }

    #[test]
    fn remote_recipient_device_is_validated_by_its_home_service() {
        assert!(recipient_device_is_remote(
            "did:web:soland-alpha.example",
            Some("did:web:soland-beta.example"),
        ));
        assert!(!recipient_device_is_remote(
            "did:web:soland-alpha.example",
            Some("did:web:soland-alpha.example"),
        ));
        assert!(!recipient_device_is_remote(
            "did:web:soland-alpha.example",
            None,
        ));
    }
}
