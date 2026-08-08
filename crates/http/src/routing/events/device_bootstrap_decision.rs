use arkret_identifiers::{DeviceId, Did, EventId, Hash, SessionGrantId};
use arkret_models_collaboration::contact_operations::{
    DeviceBootstrapDecision, DeviceBootstrapDecisionOutcome,
    DeviceBootstrapDecisionReceiptPreimage, DeviceBootstrapDecisionReceiptSchema,
    DeviceBootstrapDecisionRecord, DeviceBootstrapDecisionRequestBody,
};
use arkret_wire::{
    Audience, Base64UrlString, PayloadProof, PayloadProofPurpose, ProtocolOpaqueId, proof_kind,
};
use chrono::{DateTime, Utc};
use salvo::http::StatusCode;
use salvo::prelude::*;
use soland_http::error::{AppError, ErrorCode};

use crate::state::AppState;

#[derive(Clone)]
pub(crate) struct DeviceBootstrapDecisionBinding {
    pub account_authority_id: Did,
    pub transaction_id: ProtocolOpaqueId,
    pub decision: DeviceBootstrapDecision,
    pub principal_id: Did,
    pub device_id: DeviceId,
    pub grant_id: SessionGrantId,
    pub canonical_request_digest: Hash,
    pub founding_event_ids: [EventId; 2],
    pub founding_batch_digest: Hash,
    pub bootstrap_transaction_expires_at: DateTime<Utc>,
    pub binding_digest: Hash,
}

fn replay_binding_matches_request(
    decision: DeviceBootstrapDecision,
    stored_binding_digest: &Hash,
    request_digest: &Hash,
) -> bool {
    decision == DeviceBootstrapDecision::Accepted || stored_binding_digest == request_digest
}

pub(crate) async fn build_device_bootstrap_decision_record(
    state: &AppState,
    binding: DeviceBootstrapDecisionBinding,
    decided_at: DateTime<Utc>,
) -> Result<DeviceBootstrapDecisionRecord, AppError> {
    // Wire timestamps are canonicalized to millisecond precision. Normalize
    // before hashing so decoding the retained canonical outcome cannot change
    // the typed receipt and invalidate exact replay.
    let decided_at = DateTime::from_timestamp_millis(decided_at.timestamp_millis())
        .ok_or_else(|| AppError::internal("decision timestamp is out of range"))?;
    let principal_server_id = Did::new(state.service_id().clone())
        .map_err(|error| AppError::internal(format!("invalid service DID: {error}")))?;
    let (_, verification_method) =
        state
            .current_service_receipt_binding()
            .await
            .map_err(|error| {
                AppError::internal(format!(
                    "current service assertion method is unavailable: {error}"
                ))
            })?;
    if !verification_method
        .as_str()
        .starts_with(&format!("{}#", principal_server_id.as_str()))
    {
        return Err(AppError::internal(
            "current receipt signer is not controlled by the serving service DID",
        ));
    }
    let preimage = DeviceBootstrapDecisionReceiptPreimage {
        schema: DeviceBootstrapDecisionReceiptSchema::V1,
        receipt_id: ProtocolOpaqueId::new(format!(
            "bootstrap_decision_receipt:{}",
            uuid::Uuid::now_v7()
        ))
        .map_err(AppError::internal)?,
        principal_server_id,
        account_authority_id: binding.account_authority_id.clone(),
        transaction_id: binding.transaction_id.clone(),
        decision: binding.decision,
        principal_id: binding.principal_id,
        device_id: binding.device_id,
        grant_id: binding.grant_id,
        canonical_request_digest: binding.canonical_request_digest,
        founding_event_ids: binding.founding_event_ids,
        founding_batch_digest: binding.founding_batch_digest,
        bootstrap_transaction_expires_at: binding.bootstrap_transaction_expires_at,
        decided_at,
    };
    let receipt_digest = preimage
        .receipt_digest()
        .map_err(|error| AppError::internal(format!("decision receipt digest failed: {error}")))?;
    let proof_binding = preimage
        .proof_binding_bytes(&verification_method)
        .map_err(|error| AppError::internal(format!("decision proof binding failed: {error}")))?;
    let jws = arkret_signatures::jws::sign_jws_ed25519(
        &proof_binding,
        state.notary_signing_key().as_ref(),
    )
    .map_err(|error| AppError::internal(format!("decision receipt signing failed: {error}")))?;
    let receipt = preimage
        .finalize(PayloadProof {
            kind: proof_kind::DETACHED_JWS.to_owned(),
            verification_method,
            payload_digest: receipt_digest,
            created_at: decided_at,
            domain: None,
            audience: Some(Audience::Single(
                binding.account_authority_id.as_str().to_owned(),
            )),
            proof_purpose: Some(PayloadProofPurpose::IssuerAttestation),
            jws,
        })
        .map_err(|error| AppError::internal(format!("decision receipt invalid: {error}")))?;
    let outcome = DeviceBootstrapDecisionOutcome {
        transaction_id: binding.transaction_id.clone(),
        decision: binding.decision,
        receipt: receipt.clone(),
    };
    let canonical_outcome = arkret_canonical::canonical_json_bytes(&outcome).map_err(|error| {
        AppError::internal(format!("decision outcome encoding failed: {error}"))
    })?;
    let record = DeviceBootstrapDecisionRecord {
        account_authority_id: binding.account_authority_id,
        transaction_id: binding.transaction_id,
        decision: binding.decision,
        binding_digest: binding.binding_digest,
        canonical_outcome_bytes: Base64UrlString::new(arkret_canonical::base64url_encode(
            canonical_outcome,
        ))
        .map_err(AppError::internal)?,
        receipt,
    };
    record
        .decode_and_validate_outcome()
        .map_err(|error| AppError::internal(format!("decision record invalid: {error}")))?;
    Ok(record)
}

#[salvo::oapi::endpoint(
    operation_id = "ak.peer.device_bootstrap.command.decide",
    tags("events"),
    responses((status_code = 200, body = DeviceBootstrapDecisionOutcome, content_type = "application/json"))
)]
#[tracing::instrument(skip_all, fields(op = "ak.peer.device_bootstrap.command.decide"))]
pub(super) async fn decide_device_bootstrap(
    depot: &mut Depot,
    req: &mut Request,
    res: &mut Response,
) -> Result<(), AppError> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    super::peer::validate_peer_request(state, req, true).await?;
    let source_service_id = req
        .headers()
        .get("source-service-id")
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| decision_conflict("source-service-id is required"))?
        .to_owned();
    let request = req
        .parse_json::<DeviceBootstrapDecisionRequestBody>()
        .await
        .map_err(|_| decision_conflict("invalid device bootstrap decision request"))?;
    request
        .validate()
        .map_err(|error| decision_conflict(error.to_string()))?;
    if source_service_id != request.account_authority_id.as_str() {
        return Err(decision_conflict(
            "source-service-id does not match account_authority_id",
        ));
    }
    let record = build_device_bootstrap_decision_record(
        state,
        DeviceBootstrapDecisionBinding {
            account_authority_id: request.account_authority_id.clone(),
            transaction_id: request.transaction_id.clone(),
            decision: request.requested_decision.into(),
            principal_id: request.principal_id.clone(),
            device_id: request.device_id.clone(),
            grant_id: request.grant_id.clone(),
            canonical_request_digest: request.canonical_request_digest.clone(),
            founding_event_ids: request.founding_event_ids.clone(),
            founding_batch_digest: request.founding_batch_digest.clone(),
            bootstrap_transaction_expires_at: request.bootstrap_transaction_expires_at,
            binding_digest: request.decision_request_digest.clone(),
        },
        crate::wire::now(),
    )
    .await?;
    let authoritative = match state
        .event_queries()
        .put_device_bootstrap_decision(&request, record.clone())
        .await
    {
        Ok(soland_storage::DeviceBootstrapDecisionWriteOutcome::Inserted) => record,
        Ok(soland_storage::DeviceBootstrapDecisionWriteOutcome::Existing(existing)) => existing,
        Err(error) if error.is_conflict_kind() => {
            return Err(decision_conflict(error.detail().to_owned()));
        }
        Err(error) => {
            return Err(AppError::new(
                ErrorCode::BootstrapDecisionIndeterminate,
                format!("bootstrap decision storage result is indeterminate: {error}"),
            )
            .with_status(StatusCode::SERVICE_UNAVAILABLE));
        }
    };
    let outcome = authoritative
        .decode_and_validate_outcome()
        .map_err(|error| AppError::internal(format!("stored decision is invalid: {error}")))?;
    if !replay_binding_matches_request(
        authoritative.decision,
        &authoritative.binding_digest,
        &request.decision_request_digest,
    ) {
        return Err(decision_conflict(
            "terminal decision belongs to a different exact request",
        ));
    }
    outcome
        .validate_against(&request)
        .map_err(|error| decision_conflict(error.to_string()))?;
    let canonical_outcome =
        arkret_canonical::base64url_decode(authoritative.canonical_outcome_bytes.as_str())
            .map_err(|error| {
                AppError::internal(format!("stored decision bytes are invalid: {error}"))
            })?;
    res.headers_mut().insert(
        salvo::http::header::CONTENT_TYPE,
        salvo::http::HeaderValue::from_static("application/json"),
    );
    res.write_body(canonical_outcome)
        .map_err(|error| AppError::internal(format!("decision response write failed: {error}")))?;
    Ok(())
}

fn decision_conflict(message: impl Into<String>) -> AppError {
    AppError::new(ErrorCode::BootstrapDecisionConflict, message).with_status(StatusCode::CONFLICT)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(byte: char) -> Hash {
        Hash::new(format!("sha256:{}", byte.to_string().repeat(64))).unwrap()
    }

    #[test]
    fn negative_replay_requires_the_exact_request_digest() {
        let stored = digest('a');
        let exact = digest('a');
        let different = digest('b');
        assert!(replay_binding_matches_request(
            DeviceBootstrapDecision::Cancelled,
            &stored,
            &exact,
        ));
        assert!(!replay_binding_matches_request(
            DeviceBootstrapDecision::Cancelled,
            &stored,
            &different,
        ));
        assert!(replay_binding_matches_request(
            DeviceBootstrapDecision::Accepted,
            &stored,
            &different,
        ));
    }
}
