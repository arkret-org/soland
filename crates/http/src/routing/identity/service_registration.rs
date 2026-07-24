//! Standard Service Identity Provider operations.

use arkret_identifiers::Did;
use arkret_models_identity::service_identity::{
    CanonicalServiceUrl, ServiceRegistrationEnsureRequestBody, ServiceRegistrationKey,
    ServiceRegistrationOutcome, ServiceRegistrationReceipt, ServiceWebvhDataIntegrityProof,
};
use arkret_wire::ServiceType;
use ed25519_dalek::Signer;
use salvo::http::StatusCode;
use salvo::prelude::*;
use serde_json::{Value, json};
use soland_services::identity::{
    DidDocumentState, DidLogEvent, ServiceRegistrationCommitResult,
};
use soland_http::error::{AppError, ErrorCode};
use soland_http::result::{JsonResult, json_ok};

use super::did::require_embedded_webvh_registration_bearer;
use super::webvh_validation::{
    WebvhLogEntry, validate_log_chain, validate_rotation_authorization_for_log,
    validate_witness_policy_for_log, verify_log_subject, verify_scid_against_did,
    verify_webvh_log_proof,
};
use salvo::oapi::extract::{JsonBody, QueryParam};
use crate::state::AppState;

#[handler]
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
    let receipt = sign_registration_receipt(state, &key, &request, issued_at)?;
    let outcome = ServiceRegistrationOutcome {
        service_id: request.inception_operation.state.id.clone(),
        did_document: request.inception_operation.state.clone(),
        version_id: request.inception_operation.version_id.clone(),
        registration_receipt: receipt,
        created: true,
    };
    outcome
        .validate_ensure_response(&request)
        .map_err(registration_rejected)?;

    let event_digest = outcome.registration_receipt.log_head_digest.clone();
    let service_id = outcome.service_id.to_string();
    let document_value = serde_json::to_value(&outcome.did_document)
        .map_err(|error| AppError::internal(error.to_string()))?;
    let document = DidDocumentState {
        did: service_id.clone(),
        did_document: document_value,
        key_log_head: Some(event_digest.clone()),
        seq: 1,
        method_evidence: json!({
            "mode": "service_registration_provider",
            "operation": arkret_wire::ServiceOperationId::ROOT_IDENTITY_SERVICE_REGISTRATION_COMMAND_ENSURE,
            "service_type": key.service_type().as_str(),
            "public_base": key.public_base().as_str(),
            "version_id": outcome.version_id,
        }),
        fetched_at: issued_at,
        expires_at: issued_at,
        updated_at: issued_at,
    };
    let event = DidLogEvent {
        event_digest,
        did: service_id,
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
            if let Err(error) = state
                .dids()
                .cache_resolved_document_state(document)
            {
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

#[handler]
pub(crate) async fn get(
    depot: &mut Depot,
    req: &mut Request,
    service_type: QueryParam<String, true>,
    public_base: QueryParam<String, true>,
) -> JsonResult<ServiceRegistrationOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    require_embedded_webvh_registration_bearer(state, req)?;
    let service_type =
        serde_json::from_value::<ServiceType>(Value::String(service_type.into_inner()))
            .map_err(|error| AppError::invalid_param(format!("invalid service_type: {error}")))?;
    let public_base = CanonicalServiceUrl::new(public_base.into_inner())
        .map_err(|error| AppError::invalid_param(error.to_string()))?;
    let key = ServiceRegistrationKey::new(service_type, public_base)
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

fn sign_registration_receipt(
    state: &AppState,
    key: &ServiceRegistrationKey,
    request: &ServiceRegistrationEnsureRequestBody,
    issued_at: chrono::DateTime<chrono::Utc>,
) -> Result<ServiceRegistrationReceipt, AppError> {
    let issued_at = arkret_canonical::normalize_timestamp_canonical(issued_at);
    let issued_at_wire = arkret_canonical::format_timestamp_canonical(issued_at);
    let provider_service_id = Did::new(state.service_id().clone())
        .map_err(|error| AppError::internal(format!("provider service DID invalid: {error}")))?;
    let log_head_digest = request
        .inception_operation
        .log_head_digest()
        .map_err(|error| AppError::internal(error.to_string()))?;
    let control_key_digest = request
        .inception_operation
        .control_key_digest()
        .map_err(|error| AppError::internal(error.to_string()))?;
    let receipt_claims = json!({
        "registration_key": key,
        "service_id": request.inception_operation.state.id,
        "version_id": request.inception_operation.version_id,
        "log_head_digest": log_head_digest,
        "control_key_digest": control_key_digest,
        "issued_at": issued_at_wire,
        "provider_service_id": provider_service_id,
    });
    let receipt_digest = arkret_canonical::canonical_sha256(&receipt_claims)
        .map_err(|error| AppError::internal(error.to_string()))?;
    let receipt_id = format!(
        "ak:service_registration_receipt:{}",
        receipt_digest
            .strip_prefix("sha256:")
            .unwrap_or(&receipt_digest)
    );
    let verification_method = provider_verification_method(&provider_service_id);
    let proof_config = json!({
        "type": "DataIntegrityProof",
        "cryptosuite": "eddsa-jcs-2022",
        "verificationMethod": verification_method,
        "proofPurpose": "assertionMethod",
    });
    let signed_receipt = json!({
        "receipt_id": receipt_id,
        "registration_key": key,
        "service_id": request.inception_operation.state.id,
        "version_id": request.inception_operation.version_id,
        "log_head_digest": log_head_digest,
        "control_key_digest": control_key_digest,
        "issued_at": issued_at_wire,
        "provider_service_id": provider_service_id,
    });
    let mut signing_input = Vec::with_capacity(64);
    let proof_config_bytes = arkret_canonical::canonical_json_bytes(&proof_config)
        .map_err(|error| AppError::internal(error.to_string()))?;
    let receipt_bytes = arkret_canonical::canonical_json_bytes(&signed_receipt)
        .map_err(|error| AppError::internal(error.to_string()))?;
    signing_input.extend_from_slice(&arkret_canonical::sha256_bytes(&proof_config_bytes));
    signing_input.extend_from_slice(&arkret_canonical::sha256_bytes(&receipt_bytes));
    let signature = state.notary_signing_key().sign(&signing_input);
    let proof = ServiceWebvhDataIntegrityProof {
        proof_type: "DataIntegrityProof".to_owned(),
        cryptosuite: "eddsa-jcs-2022".to_owned(),
        verification_method,
        proof_purpose: "assertionMethod".to_owned(),
        proof_value: format!("z{}", bs58::encode(signature.to_bytes()).into_string()),
    };
    let receipt = ServiceRegistrationReceipt {
        receipt_id,
        registration_key: key.clone(),
        service_id: request.inception_operation.state.id.clone(),
        version_id: request.inception_operation.version_id.clone(),
        log_head_digest,
        control_key_digest,
        issued_at,
        provider_service_id,
        proof,
    };
    receipt
        .validate_for(key, &request.inception_operation.state.id)
        .map_err(|error| AppError::internal(error.to_string()))?;
    Ok(receipt)
}

fn provider_verification_method(provider_service_id: &Did) -> String {
    if let Some(multibase) = provider_service_id.as_str().strip_prefix("did:key:") {
        format!("{provider_service_id}#{multibase}")
    } else {
        format!("{provider_service_id}#notary-key")
    }
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

