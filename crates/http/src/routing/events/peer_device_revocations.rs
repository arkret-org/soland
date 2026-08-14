use arkret_wire::{
    DeviceRevocationGateActionClass, DeviceRevocationGateCheckOutcome,
    DeviceRevocationGateCheckRequestBody, DeviceRevocationGateDecision,
    DeviceRevocationGateDecisionReceipt, Hash, PayloadProof, SealId,
    UnsignedDeviceRevocationGateDecisionReceipt,
};
use salvo::prelude::*;
use soland_http::error::AppError;
use soland_http::result::{JsonResult, json_ok};
use soland_services::ServiceErrorKind;

use super::peer::{
    cross_domain_replay, schema_violation, source_service_id_from_request,
    trusted_account_authority_service_id, validate_peer_request,
};
use crate::state::AppState;

#[salvo::oapi::endpoint(
    operation_id = "ak.peer.device_revocations.command.check",
    tags("events")
)]
#[tracing::instrument(skip_all, fields(op = "ak.peer.device_revocations.command.check"))]
pub(super) async fn check_device_revocation_gate(
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<DeviceRevocationGateCheckOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");

    // Authentication and transport binding precede every principal/device
    // lookup. A caller must not use this operation as an account oracle.
    validate_peer_request(state, req, true).await?;
    let source_service_id = source_service_id_from_request(req)?;
    let configured_authority = trusted_account_authority_service_id(state).await?;
    if source_service_id != configured_authority.as_str() {
        return Err(AppError::capability_denied(
            "device revocation gate caller is not the configured Account Authority",
        ));
    }

    let request = req
        .parse_json::<DeviceRevocationGateCheckRequestBody>()
        .await
        .map_err(|_| {
            AppError::json_invalid("invalid ak.peer.device_revocations.command.check request body")
        })?;
    request
        .validate()
        .map_err(|error| schema_violation(error.to_string()))?;
    if !matches!(
        request.action_class,
        DeviceRevocationGateActionClass::SessionGrantIssue
            | DeviceRevocationGateActionClass::SessionGrantRefresh
    ) {
        return Err(schema_violation(
            "peer device revocation check only admits session grant issue or refresh",
        ));
    }

    let local_principal_server = arkret_wire::DidCoreId::new(state.service_id().clone())
        .map_err(|error| AppError::internal(format!("local service id is invalid: {error}")))?;
    if request.principal_authority.principal_server_id != local_principal_server {
        return Err(cross_domain_replay(
            "device revocation gate request is routed to the wrong Principal Server",
        ));
    }

    let origin_current_selector =
        match crate::routing::identity::device_generation::active_device_revocation_gate_selector(
            state,
            request.principal_authority.principal_id.as_str(),
            request.device_id.as_str(),
        )
        .await
        {
            Ok(selector) => Some(selector),
            Err(error)
                if matches!(
                    error.kind(),
                    ServiceErrorKind::NotFound | ServiceErrorKind::Conflict
                ) =>
            {
                None
            }
            Err(error) => {
                return Err(AppError::internal(format!(
                    "origin device authorization projection is unavailable: {error}"
                )));
            }
        };
    let action_class = match request.action_class {
        DeviceRevocationGateActionClass::SessionGrantIssue => {
            soland_storage::DeviceRevocationGateAction::SessionGrantIssue
        }
        DeviceRevocationGateActionClass::SessionGrantRefresh => {
            soland_storage::DeviceRevocationGateAction::SessionGrantRefresh
        }
        _ => unreachable!("non-session action rejected above"),
    };
    let linearization = state
        .persistence()
        .linearize_device_revocation_gate(
            soland_storage::DeviceRevocationGateLinearizationRequest {
                principal_id: request.principal_authority.principal_id.to_string(),
                principal_server_id: request.principal_authority.principal_server_id.to_string(),
                device_id: request.device_id.to_string(),
                expected_device_authorize_event_id: request
                    .expected_device_authorize_event_id
                    .as_ref()
                    .map(ToString::to_string),
                expected_device_generation_ref: request.expected_device_generation_ref,
                origin_current_selector: origin_current_selector.clone(),
                action_class,
                intent_digest: request.intent_digest.to_string(),
                requested_at: request.requested_at,
            },
        )
        .await
        .map_err(|error| {
            AppError::internal(format!(
                "device revocation gate linearization failed: {error}"
            ))
        })?;

    let (decision, derived_binding, blocking_proposal_digest, covering_seal_id) =
        match linearization.status {
            soland_storage::DeviceRevocationGateStatus::Active => (
                DeviceRevocationGateDecision::Allow,
                origin_current_selector.as_ref().map(|selector| {
                    (
                        selector.target_device_authorize_event_id.clone(),
                        selector.target_device_generation_ref,
                    )
                }),
                None,
                None,
            ),
            soland_storage::DeviceRevocationGateStatus::Pending {
                blocking_proposal_digest,
            } => (
                DeviceRevocationGateDecision::RevocationPending,
                None,
                Some(Hash::new(blocking_proposal_digest).map_err(|error| {
                    AppError::internal(format!(
                        "stored blocking proposal digest is invalid: {error}"
                    ))
                })?),
                None,
            ),
            soland_storage::DeviceRevocationGateStatus::Revoked { covering_seal_id } => (
                DeviceRevocationGateDecision::Revoked,
                None,
                None,
                Some(SealId::new(covering_seal_id).map_err(|error| {
                    AppError::internal(format!("stored covering Seal id is invalid: {error}"))
                })?),
            ),
            soland_storage::DeviceRevocationGateStatus::AuthorityMismatch => (
                DeviceRevocationGateDecision::AuthorityMismatch,
                None,
                None,
                None,
            ),
            soland_storage::DeviceRevocationGateStatus::GenerationMismatch => (
                DeviceRevocationGateDecision::GenerationMismatch,
                None,
                None,
                None,
            ),
        };
    let (target_device_authorize_event_id, target_device_generation_ref) = match derived_binding {
        Some((event_id, generation)) => (
            Some(arkret_wire::EventId::new(event_id).map_err(|error| {
                AppError::internal(format!(
                    "derived device authorization Event id is invalid: {error}"
                ))
            })?),
            Some(generation),
        ),
        None => (None, None),
    };
    let (_, verification_method) = state
        .current_service_receipt_binding()
        .await
        .map_err(AppError::internal)?;
    let unsigned_receipt = UnsignedDeviceRevocationGateDecisionReceipt {
        principal_authority: request.principal_authority.clone(),
        device_id: request.device_id.clone(),
        target_device_authorize_event_id,
        target_device_generation_ref,
        action_class: request.action_class,
        intent_digest: request.intent_digest.clone(),
        decision,
        linearization_seq: linearization.linearization_seq,
        linearized_at: linearization.linearized_at,
        expires_at: linearization.expires_at,
        blocking_proposal_digest,
        covering_seal_id,
        verification_method,
    };
    let proof_metadata = unsigned_receipt
        .proof_metadata()
        .map_err(|error| AppError::internal(error.to_string()))?;
    let signing_bytes = unsigned_receipt
        .proof_signing_bytes(&proof_metadata)
        .map_err(|error| AppError::internal(error.to_string()))?;
    let jws = arkret_signatures::jws::sign_jws_ed25519(
        &signing_bytes,
        state.notary_signing_key().as_ref(),
    )
    .map_err(|error| AppError::internal(error.to_string()))?;
    let proof: PayloadProof = proof_metadata
        .finalize(jws)
        .map_err(|error| AppError::internal(error.to_string()))?;
    let receipt: DeviceRevocationGateDecisionReceipt = unsigned_receipt
        .attach_proof(proof)
        .map_err(|error| AppError::internal(error.to_string()))?;
    let outcome = DeviceRevocationGateCheckOutcome {
        decision_receipt: receipt,
    };
    outcome
        .validate_for_request(&request)
        .map_err(|error| AppError::internal(error.to_string()))?;
    json_ok(outcome)
}
