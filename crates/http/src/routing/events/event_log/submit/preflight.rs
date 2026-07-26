use super::*;

pub(super) async fn preflight_mls_welcome_claim_signature_reject(
    state: &AppState,
    session: &SessionRecord,
    object: &serde_json::Map<String, Value>,
    actor_id: &str,
    operation: &Operation,
    internal_admission: Option<&InternalEventAdmission>,
) -> Option<String> {
    if kinds::canonical_kind_string(operation) != arkret_wire::events::EventKind::MLS_WELCOME {
        return None;
    }
    let envelope_value = match operation.payload.get("claim_envelope") {
        Some(value) => value.clone(),
        None => {
            return Some(arkret_wire::ReasonCode::KEYPACKAGE_WELCOME_ENVELOPE_MISMATCH.to_owned());
        }
    };
    let envelope = match serde_json::from_value::<
        arkret_models_collaboration::events_payloads::MlsWelcomeClaimEnvelope,
    >(envelope_value)
    {
        Ok(envelope) => envelope,
        Err(_) => {
            return Some(arkret_wire::ReasonCode::KEYPACKAGE_WELCOME_ENVELOPE_MISMATCH.to_owned());
        }
    };
    if envelope.requester_did.as_str() != actor_id {
        return Some(arkret_wire::ReasonCode::KEYPACKAGE_WELCOME_ENVELOPE_MISMATCH.to_owned());
    }
    let sender_device_id = operation
        .payload
        .get("sender_device_id")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let signer_key_evidence = internal_admission.and_then(|admission| {
        admission.signer_key_evidence(session, object, envelope.signature.kid.as_str())
    });
    crate::routing::identity::cross_signing::verify_mls_welcome_claim_envelope_signature(
        state,
        &envelope,
        sender_device_id,
        signer_key_evidence,
    )
    .await
    .err()
    .map(str::to_owned)
}

pub(super) async fn preflight_mls_welcome_recipient_reject(
    state: &AppState,
    operation: &Operation,
) -> Option<String> {
    if kinds::canonical_kind_string(operation) != arkret_wire::events::EventKind::MLS_WELCOME {
        return None;
    }
    let recipient_actor_id = operation
        .payload
        .get("recipient_actor_id")
        .or_else(|| operation.payload.get("recipient_principal_id"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())?;
    let recipient_device_id = operation
        .payload
        .get("recipient_device_id")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())?;
    if let Some(authorize_event_id) = operation
        .payload
        .get("claim_ref")
        .and_then(Value::as_object)
        .and_then(|claim_ref| claim_ref.get("agent_key_authorize_event_id"))
        .and_then(Value::as_str)
    {
        let Ok(recipient) = arkret_identifiers::Did::new(recipient_actor_id.to_owned()) else {
            return Some(arkret_wire::ReasonCode::CLAIM_GENERATION_MISMATCH.to_owned());
        };
        let authorization_matches = crate::routing::mls::current_agent_key_authorization_matches(
            state,
            &recipient,
            authorize_event_id,
        )
        .await;
        return welcome_recipient_trust_reject_reason(
            Some(authorize_event_id),
            authorization_matches,
            false,
        )
        .map(str::to_owned);
    }
    let recipient_service_id = state
        .projections()
        .snapshot()
        .member(operation.realm_id.as_str(), recipient_actor_id)
        .and_then(|member| member.recipient_service_id.clone());
    if recipient_device_is_remote(state.service_id(), recipient_service_id.as_deref()) {
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

fn recipient_device_is_remote(local_service_id: &str, recipient_service_id: Option<&str>) -> bool {
    recipient_service_id.is_some_and(|service_id| service_id != local_service_id)
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
