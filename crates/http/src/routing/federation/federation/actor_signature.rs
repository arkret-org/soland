use salvo::http::StatusCode;
use soland_http::error::AppError;

use crate::state::AppState;

pub(super) struct VerifiedFederationActor {
    pub(super) verified_key_id: String,
    pub(super) did_document_ref: String,
    pub(super) key_log_head: arkret_identifiers::Hash,
}

pub(super) async fn verify_federation_actor_signature(
    _state: &AppState,
    _body: &arkret_models_collaboration::federation::wire_dtos::FederationVerifyActorRequestBody,
) -> Result<VerifiedFederationActor, AppError> {
    Err(actor_signature_error(
        "federation actor verification requires an exact principal authority instance",
    ))
}

fn actor_signature_error(message: impl Into<String>) -> AppError {
    AppError::new(
        soland_http::error::ErrorCode::InvalidSignature,
        message.into(),
    )
    .with_status(StatusCode::UNAUTHORIZED)
}
