//! Native Agent signer evidence is a closed current/historical protocol.
//!
//! Soland must not reconstruct either branch from old projection rows. Until
//! all signed snapshot, controller-account gate, lifecycle witness and
//! historical admission-receipt inputs are available, evidence production and
//! federation admission fail closed.

use arkret_models_identity::agent_signer_evidence::{
    AgentSignerEvidence, AgentSignerEvidenceBundle, AgentSignerEvidenceQueryFailure,
    AgentSignerEvidenceQueryFailureReason, AgentSignerEvidenceQueryOutcome,
    AgentSignerEvidenceQueryRequestBodyBody, AgentSignerEvidenceQuerySelector,
    ControllerAccountGateAttestation, ControllerAccountGateAttestationIssueOutcome,
    ControllerAccountGateAttestationIssueRequestBody,
};
use arkret_signatures::proof::PublicKeyMaterial;
use salvo::oapi::extract::JsonBody;
use salvo::prelude::*;

use super::*;

#[salvo::oapi::endpoint(operation_id = "ak.self.agent_signer_evidence.query", tags("identity"))]
pub(super) async fn query_agent_signer_evidence(
    aa: AuthArgs,
    body: JsonBody<AgentSignerEvidenceQueryRequestBodyBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AgentSignerEvidenceQueryOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let body = body.into_inner();
    if !crate::routing::realm_has_member(state, body.realm_id.as_str(), &session.actor).await {
        return Err(AppError::not_found("Agent signer evidence is unavailable"));
    }
    let mut failures = Vec::with_capacity(body.queries.len());
    for selector in body.queries {
        let reason = preflight_controller_gate(state, &selector)
            .await
            .err()
            .unwrap_or(AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing);
        failures.push(AgentSignerEvidenceQueryFailure { selector, reason });
    }
    json_ok(AgentSignerEvidenceQueryOutcome {
        evidence: Vec::new(),
        failures: (!failures.is_empty()).then_some(failures),
    })
}

/// Resolve and independently verify the Account Authority-owned controller
/// gate before any Agent-PCR snapshot assembly. The remaining signed
/// Seal/state witness assembly still fails closed below until all exact
/// projection inputs are present.
async fn preflight_controller_gate(
    state: &AppState,
    selector: &AgentSignerEvidenceQuerySelector,
) -> Result<ControllerAccountGateAttestation, AgentSignerEvidenceQueryFailureReason> {
    let AgentSignerEvidenceQuerySelector::CurrentAdmission { agent_id, .. } = selector else {
        return Err(AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing);
    };
    let agent = state
        .agent_pairings()
        .agent(agent_id.as_str())
        .await
        .map_err(|_| AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)?
        .ok_or(AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)?;
    if agent.state != arkret_models_collaboration::agent_operations::AgentLifecycleState::Active
        || agent.authorized_signing_key_binding.is_none()
    {
        return Err(AgentSignerEvidenceQueryFailureReason::AgentAuthorizationInactive);
    }
    let service_id =
        arkret_wire::project_full_id_to_core_id(&state.service_resolution_commitment().full_id)
            .map(arkret_identifiers::ServiceId::from)
            .map_err(|_| AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)?;
    let current_binding = crate::routing::identity::account::current_principal_service_binding(
        state,
        &agent.controller_id,
    )
    .await
    .map_err(|_| AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)?
    .ok_or(AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)?;
    if current_binding.service_id != service_id {
        return Err(AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing);
    }
    let principal_id = arkret_identifiers::PrincipalId::new(agent.controller_id.clone())
        .map_err(|_| AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)?;
    let expected_authority = state
        .config()
        .account_authority_service_id
        .as_deref()
        .and_then(|value| {
            arkret_identifiers::ServiceId::new(value.to_owned())
                .ok()
                .or_else(|| {
                    arkret_wire::FullId::new(value.to_owned())
                        .ok()
                        .and_then(|full| arkret_wire::project_full_id_to_core_id(&full).ok())
                        .map(arkret_identifiers::ServiceId::from)
                })
        })
        .ok_or(AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)?;
    let request = ControllerAccountGateAttestationIssueRequestBody {
        request_id: arkret_identifiers::RequestId::from_uuid(uuid::Uuid::now_v7()),
        principal_id: principal_id.clone(),
        agent_authority_service_id: service_id.clone(),
        agent_authority_service_resolution:
            crate::routing::system::service_resolution::authenticated_current_resolution(
                state,
                &crate::routing::system::describe::build_server_description(state),
            )
            .await
            .map_err(|_| AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)?,
    };
    let authority_url = state
        .config()
        .account_authority_url
        .as_deref()
        .ok_or(AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)?;
    let bearer = state
        .config()
        .session_grant_introspection_bearer
        .as_deref()
        .ok_or(AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)?;
    let endpoint = format!(
        "{}/_arkret/gate/account/controller-gate-attestations",
        authority_url.trim_end_matches('/')
    );
    let (endpoint, client) = crate::security::validate_http_url_for_egress_with_pinned_client(
        &endpoint,
        "controller account gate attestation",
        state.config().development_mode,
        std::time::Duration::from_secs(10),
    )
    .map_err(|_| AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)?;
    let body = arkret_canonical::canonical_json_bytes(&request)
        .map_err(|_| AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)?;
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(
        reqwest::header::CONTENT_TYPE,
        reqwest::header::HeaderValue::from_static("application/json"),
    );
    crate::routing::federation::outbox::insert_header_if_valid(
        &mut headers,
        "content-digest",
        &crate::routing::federation::outbox::content_digest_header_value(&body),
    );
    crate::routing::federation::outbox::insert_header_if_valid(
        &mut headers,
        "source-service-id",
        service_id.as_str(),
    );
    crate::routing::federation::outbox::insert_header_if_valid(
        &mut headers,
        "destination-service-id",
        expected_authority.as_str(),
    );
    crate::routing::federation::outbox::insert_header_if_valid(
        &mut headers,
        "source-trust-domain",
        &state.config().trust_domain,
    );
    crate::routing::federation::outbox::insert_header_if_valid(
        &mut headers,
        "destination-trust-domain",
        &state.config().trust_domain,
    );
    let headers =
        crate::routing::federation::outbox::rfc9421_sign(state, headers, "POST", endpoint.as_str());
    let response = client
        .post(endpoint)
        .bearer_auth(bearer)
        .headers(headers)
        .body(body)
        .send()
        .await
        .map_err(|_| AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)?;
    if !response.status().is_success() {
        return Err(AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing);
    }
    let outcome = response
        .json::<ControllerAccountGateAttestationIssueOutcome>()
        .await
        .map_err(|_| AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)?;
    if outcome.request_id != request.request_id {
        return Err(AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing);
    }
    let gate = outcome.controller_account_gate_attestation;
    let key = state
        .federation_peer_verification_method_key(gate.verification_method.as_str())
        .ok_or(AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)?;
    let material = PublicKeyMaterial::Ed25519Raw {
        bytes: key.to_bytes().to_vec(),
    };
    arkret_signatures::agent_evidence::verify_controller_account_gate_attestation(
        &gate,
        &principal_id,
        &expected_authority,
        &material,
        chrono::Utc::now(),
    )
    .map_err(|_| AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)?;
    if gate.eligibility
        != arkret_models_identity::agent_signer_evidence::ControllerAccountEligibility::Active
    {
        return Err(AgentSignerEvidenceQueryFailureReason::AgentAuthorizationInactive);
    }
    Ok(gate)
}

pub(crate) async fn signer_evidence_bundle_for_events(
    _state: &AppState,
    _events: &[arkret_wire::Event],
) -> Option<AgentSignerEvidenceBundle> {
    None
}

pub(crate) async fn verify_federated_signer_evidence(
    _state: &AppState,
    _evidence: &AgentSignerEvidence,
    _event: &arkret_wire::Event,
    _observed_at: chrono::DateTime<chrono::Utc>,
) -> Result<[u8; 32], AppError> {
    Err(AppError::new(
        ErrorCode::FailedPrecondition,
        "portable Agent signer evidence authority inputs are unavailable",
    )
    .with_wire_code("agent_signer_evidence_missing"))
}
