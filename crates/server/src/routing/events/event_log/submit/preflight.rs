use super::*;

pub(super) async fn preflight_mls_welcome_claim_signature_reject(
    state: &AppState,
    actor_id: &str,
    operation: &Operation,
) -> Option<String> {
    if kinds::canonical_kind_string(operation) != arkret_core::events::EventKind::MLS_WELCOME {
        return None;
    }
    let envelope_value = match operation.payload.get("claim_envelope") {
        Some(value) => value.clone(),
        None => {
            return Some(arkret_core::ReasonCode::KEYPACKAGE_WELCOME_ENVELOPE_MISMATCH.to_owned());
        }
    };
    let envelope =
        match serde_json::from_value::<arkret_core::MlsWelcomeClaimEnvelope>(envelope_value) {
            Ok(envelope) => envelope,
            Err(_) => {
                return Some(
                    arkret_core::ReasonCode::KEYPACKAGE_WELCOME_ENVELOPE_MISMATCH.to_owned(),
                );
            }
        };
    if envelope.requester_did.as_str() != actor_id {
        return Some(arkret_core::ReasonCode::KEYPACKAGE_WELCOME_ENVELOPE_MISMATCH.to_owned());
    }
    let sender_device_id = operation
        .payload
        .get("sender_device_id")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty());
    crate::routing::identity::cross_signing::verify_mls_welcome_claim_envelope_signature(
        state,
        &envelope,
        sender_device_id,
    )
    .await
    .err()
    .map(str::to_owned)
}

pub(super) async fn preflight_mls_welcome_recipient_reject(
    state: &AppState,
    operation: &Operation,
) -> Option<String> {
    if kinds::canonical_kind_string(operation) != arkret_core::events::EventKind::MLS_WELCOME {
        return None;
    }
    let Some(recipient_actor_id) = operation
        .payload
        .get("recipient_actor_id")
        .or_else(|| operation.payload.get("recipient_principal_id"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return None;
    };
    let Some(recipient_device_id) = operation
        .payload
        .get("recipient_device_id")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return None;
    };
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
