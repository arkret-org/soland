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
    let envelope =
        match serde_json::from_value::<arkret_models_collaboration::events_payloads::list_message_mimi_mls::MlsWelcomeClaimEnvelope>(envelope_value) {
            Ok(envelope) => envelope,
            Err(_) => {
                return Some(
                    arkret_wire::ReasonCode::KEYPACKAGE_WELCOME_ENVELOPE_MISMATCH.to_owned(),
                );
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
        if !crate::routing::mls::current_agent_key_authorization_matches(
            state,
            &recipient,
            authorize_event_id,
        )
        .await
        {
            return Some(arkret_wire::ReasonCode::CLAIM_GENERATION_MISMATCH.to_owned());
        }
    }
    if crate::routing::identity::auth::is_device_revoked(
        state,
        recipient_actor_id,
        recipient_device_id,
    )
    .await
    {
        return Some("device_revoked".to_owned());
    }
    None
}
