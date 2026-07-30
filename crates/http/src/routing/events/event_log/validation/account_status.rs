use arkret_models_collaboration::events_payloads::account::{
    AccountStatusPayload, AccountStatusServiceBinding,
};

use super::super::*;

pub(super) async fn validate_account_status_service_binding(
    state: &AppState,
    object: &serde_json::Map<String, Value>,
) -> Result<(), EventValidationError> {
    let payload: AccountStatusPayload = serde_json::from_value(
        object
            .get("payload")
            .cloned()
            .ok_or_else(account_status_unauthorized)?,
    )
    .map_err(|_| account_status_unauthorized())?;
    let actor_id = event_string_field(object, &["actor_id"])
        .and_then(|value| arkret_identifiers::Did::new(value).ok())
        .ok_or_else(account_status_unauthorized)?;
    let executed_by = event_string_field(object, &["executed_by"])
        .and_then(|value| arkret_identifiers::Did::new(value).ok())
        .ok_or_else(account_status_unauthorized)?;
    let verification_method = object
        .get("proofs")
        .and_then(Value::as_array)
        .and_then(|proofs| proofs.first())
        .and_then(|proof| proof.get("verification_method"))
        .and_then(Value::as_str)
        .ok_or_else(account_status_unauthorized)?;
    let proof_controller = verification_method
        .split_once('#')
        .map_or(verification_method, |(controller, _)| controller);
    let proof_controller = arkret_identifiers::Did::new(proof_controller.to_owned())
        .map_err(|_| account_status_unauthorized())?;

    let authoritative_service = state
        .config()
        .account_authority_enrollment_did
        .as_deref()
        .unwrap_or_else(|| state.service_id().as_str());
    let authoritative_service_id = arkret_identifiers::Did::new(authoritative_service.to_owned())
        .map_err(|_| account_status_unauthorized())?;
    let account = state
        .identities()
        .account(payload.principal_id.as_str())
        .await
        .map_err(|_| account_status_unauthorized())?
        .ok_or_else(account_status_unauthorized)?;

    let historical_document = super::enrollment::did_document_at(
        state,
        authoritative_service_id.as_str(),
        payload.effective_at,
    )
    .await
    .map_err(|_| account_status_unauthorized())?;
    let signing_key_valid = historical_document
        .get("verificationMethod")
        .or_else(|| historical_document.get("verification_method"))
        .and_then(Value::as_array)
        .is_some_and(|methods| {
            methods
                .iter()
                .any(|method| method.get("id").and_then(Value::as_str) == Some(verification_method))
        });
    let delegated = authoritative_service_id.as_str() == state.service_id().as_str()
        || state.config().account_authority_enrollment_did.as_deref()
            == Some(authoritative_service_id.as_str());
    payload
        .validate_service_binding(&AccountStatusServiceBinding {
            actor_id: &actor_id,
            proof_controller: &proof_controller,
            signature_kid_controller: &proof_controller,
            authoritative_service_id: &authoritative_service_id,
            bound_account_id: &account.id,
            bound_principal_id: &payload.principal_id,
            signing_key_valid_at_effective_at: signing_key_valid,
            delegation_covers_account_status: delegated && executed_by == authoritative_service_id,
        })
        .map_err(|_| account_status_unauthorized())
}

fn account_status_unauthorized() -> EventValidationError {
    event_validation_error(
        StatusCode::FORBIDDEN,
        "unauthorized",
        "ak.account.status requires an authoritative service-attested account binding",
    )
}
