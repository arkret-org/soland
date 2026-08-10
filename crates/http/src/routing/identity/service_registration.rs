//! Standard Service Identity Provider operations.

use arkret_models_identity::service_identity::{
    CanonicalServiceUrl, ServiceRegistrationEnsureRequestBody, ServiceRegistrationKey,
    ServiceRegistrationOutcome, ServiceRegistrationReceipt,
};
use arkret_wire::{DidCoreId, PayloadProof, ServiceKind, project_full_id_to_core_id, proof_kind};
use salvo::http::StatusCode;
use salvo::oapi::endpoint;
use salvo::oapi::extract::{JsonBody, QueryParam};
use salvo::prelude::*;
use serde_json::{Value, json};
use soland_http::error::{AppError, ErrorCode};
use soland_http::result::{JsonResult, json_ok};
use soland_services::identity::{DidDocumentState, DidLogEvent, ServiceRegistrationCommitResult};

use super::did::require_embedded_webvh_registration_bearer;
use super::webvh_validation::{
    WebvhLogEntry, validate_log_chain, validate_rotation_authorization_for_log,
    validate_witness_policy_for_log, verify_log_subject, verify_scid_against_did,
    verify_webvh_log_proof,
};
use crate::state::AppState;

#[endpoint(
    summary = "Ensure a service registration",
    tags("service_registration")
)]
pub(crate) async fn ensure(
    depot: &mut Depot,
    req: &mut Request,
    body: JsonBody<ServiceRegistrationEnsureRequestBody>,
) -> JsonResult<ServiceRegistrationOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    require_embedded_webvh_registration_bearer(state, req)?;
    let request = body.into_inner();
    request.validate().map_err(registration_rejected)?;
    let key = request.registration_key().map_err(registration_rejected)?;
    let operation = serde_json::to_value(&request.inception_operation)
        .map_err(|error| AppError::internal(error.to_string()))?;
    validate_signed_inception(&request, &operation)?;

    let issued_at = chrono::Utc::now();
    let receipt = sign_registration_receipt(state, &key, &request, issued_at).await?;
    let outcome = ServiceRegistrationOutcome {
        service_id: receipt.service_id.clone(),
        full_id: request.inception_operation.state.id.clone(),
        did_document: request.inception_operation.state.clone(),
        version_id: request.inception_operation.version_id.clone(),
        registration_receipt: receipt,
        created: true,
    };
    outcome
        .validate_ensure_response(&request)
        .map_err(registration_rejected)?;

    let event_digest = outcome.registration_receipt.log_head_digest.clone();
    let service_full_id = outcome.did_document.id.to_string();
    let document_value = serde_json::to_value(&outcome.did_document)
        .map_err(|error| AppError::internal(error.to_string()))?;
    let document = DidDocumentState {
        did: service_full_id.clone(),
        did_document: document_value,
        key_log_head: Some(event_digest.clone()),
        seq: 1,
        method_evidence: json!({
            "mode": "service_registration_provider",
            "operation": arkret_wire::ServiceOperationId::ROOT_IDENTITY_SERVICE_REGISTRATION_COMMAND_ENSURE,
            "service_kind": key.service_kind().as_str(),
            "public_base": key.public_base().as_str(),
            "version_id": outcome.version_id,
        }),
        fetched_at: issued_at,
        expires_at: issued_at,
        updated_at: issued_at,
    };
    let event = DidLogEvent {
        event_digest,
        did: service_full_id,
        seq: 1,
        operation,
        created_at: issued_at,
    };

    match state
        .dids()
        .commit_service_registration(key, outcome, document.clone(), event)
        .await
        .map_err(provider_unavailable)?
    {
        ServiceRegistrationCommitResult::Created(outcome) => {
            if let Err(error) = state.cache_resolved_did_document(document) {
                tracing::warn!(%error, "failed to cache newly registered service DID document");
            }
            json_ok(outcome)
        }
        ServiceRegistrationCommitResult::Existing(outcome) => json_ok(outcome),
        ServiceRegistrationCommitResult::Conflict => Err(AppError::new(
            ErrorCode::ServiceIdentityConflict,
            "service registration key, DID, or control root is already bound differently",
        )),
    }
}

#[endpoint(summary = "Get a service registration", tags("service_registration"))]
pub(crate) async fn get(
    depot: &mut Depot,
    req: &mut Request,
    service_kind: QueryParam<String, true>,
    public_base: QueryParam<String, true>,
) -> JsonResult<ServiceRegistrationOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    require_embedded_webvh_registration_bearer(state, req)?;
    let service_kind =
        serde_json::from_value::<ServiceKind>(Value::String(service_kind.into_inner()))
            .map_err(|error| AppError::invalid_param(format!("invalid service_kind: {error}")))?;
    let public_base = CanonicalServiceUrl::new(public_base.into_inner())
        .map_err(|error| AppError::invalid_param(error.to_string()))?;
    let key = ServiceRegistrationKey::new(service_kind, public_base)
        .map_err(|error| AppError::invalid_param(error.to_string()))?;
    let outcome = state
        .dids()
        .service_registration(&key)
        .await
        .map_err(provider_unavailable)?
        .ok_or_else(|| {
            AppError::new(
                ErrorCode::DidNotFound,
                "service registration does not exist for the requested key",
            )
            .with_status(StatusCode::NOT_FOUND)
        })?;
    outcome.validate_for(&key).map_err(|error| {
        AppError::internal(format!("stored service registration invalid: {error}"))
    })?;
    json_ok(outcome)
}

fn validate_signed_inception(
    request: &ServiceRegistrationEnsureRequestBody,
    operation: &Value,
) -> Result<(), AppError> {
    verify_webvh_log_proof(operation).map_err(registration_rejected)?;
    let log = [WebvhLogEntry::new(operation.clone())];
    validate_log_chain(&log).map_err(registration_rejected)?;
    let did = request.inception_operation.state.id.as_str();
    verify_scid_against_did(did, &log[0]).map_err(registration_rejected)?;
    verify_log_subject(did, &log).map_err(registration_rejected)?;
    validate_witness_policy_for_log(&log, chrono::Utc::now().timestamp())
        .map_err(registration_rejected)?;
    validate_rotation_authorization_for_log(&log).map_err(registration_rejected)
}

async fn sign_registration_receipt(
    state: &AppState,
    key: &ServiceRegistrationKey,
    request: &ServiceRegistrationEnsureRequestBody,
    issued_at: chrono::DateTime<chrono::Utc>,
) -> Result<ServiceRegistrationReceipt, AppError> {
    let issued_at = arkret_canonical::normalize_timestamp_canonical(issued_at);
    let provider_service_id = DidCoreId::new(state.service_id().clone())
        .map_err(|error| AppError::internal(format!("provider service id invalid: {error}")))?;
    let log_head_digest = request
        .inception_operation
        .log_head_digest()
        .map_err(|error| AppError::internal(error.to_string()))?;
    let control_key_digest = request
        .inception_operation
        .control_key_digest()
        .map_err(|error| AppError::internal(error.to_string()))?;
    let full_id = request.inception_operation.state.id.clone();
    let service_id = DidCoreId::from(
        project_full_id_to_core_id(&full_id)
            .map_err(|error| AppError::internal(error.to_string()))?,
    );
    let (_, verification_method) = state
        .current_service_receipt_binding()
        .await
        .map_err(AppError::internal)?;
    let mut receipt = ServiceRegistrationReceipt {
        registration_receipt_id: arkret_wire::ServiceRegistrationReceiptId::new(format!(
            "ak:service_registration_receipt:{}",
            "0".repeat(64)
        ))
        .map_err(|error| AppError::internal(error.to_string()))?,
        registration_key: key.clone(),
        service_id,
        full_id,
        version_id: request.inception_operation.version_id.clone(),
        log_head_digest,
        control_key_digest,
        issued_at,
        provider_service_id,
        proof: PayloadProof {
            kind: proof_kind::DETACHED_JWS.to_owned(),
            verification_method,
            payload_digest: arkret_wire::Hash::new(format!("sha256:{}", "0".repeat(64)))
                .map_err(|error| AppError::internal(error.to_string()))?,
            created_at: issued_at,
            domain: None,
            audience: None,
            proof_purpose: None,
            jws: "placeholder".to_owned(),
        },
    };
    receipt.registration_receipt_id = receipt
        .expected_registration_receipt_id()
        .map_err(|error| AppError::internal(error.to_string()))?;
    receipt.proof.payload_digest = receipt
        .expected_payload_digest()
        .map_err(|error| AppError::internal(error.to_string()))?;
    receipt.proof = arkret_signatures::service_identity::sign_registration_receipt_proof(
        &receipt,
        state.notary_signing_key().as_ref(),
    )
    .map_err(|error| AppError::internal(error.to_string()))?;
    receipt
        .validate_for(key, &receipt.service_id, &receipt.full_id)
        .map_err(|error| AppError::internal(error.to_string()))?;
    Ok(receipt)
}

fn registration_rejected(error: impl std::fmt::Display) -> AppError {
    AppError::new(
        ErrorCode::ServiceRegistrationRejected,
        format!("service registration rejected: {error}"),
    )
}

fn provider_unavailable(error: impl std::fmt::Display) -> AppError {
    AppError::new(
        ErrorCode::ServiceIdentityProviderUnavailable,
        format!("service identity provider unavailable: {error}"),
    )
}
