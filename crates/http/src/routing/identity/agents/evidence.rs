//! Native Agent signer evidence is a closed current/historical protocol.
//!
//! Soland must not reconstruct either branch from old projection rows. Until
//! all signed snapshot, controller-account gate, lifecycle witness and
//! historical admission-receipt inputs are available, evidence production and
//! federation admission fail closed.

use arkret_models_collaboration::agent_signer_evidence::{
    AgentSignerEvidence, AgentSignerEvidenceBundle, AgentSignerEvidenceQueryFailure,
    AgentSignerEvidenceQueryFailureReason, AgentSignerEvidenceQueryOutcome,
    AgentSignerEvidenceQueryRequestBodyBody,
};
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
    let failures = body
        .queries
        .into_iter()
        .map(|selector| AgentSignerEvidenceQueryFailure {
            selector,
            reason: AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing,
        })
        .collect::<Vec<_>>();
    json_ok(AgentSignerEvidenceQueryOutcome {
        evidence: Vec::new(),
        failures: (!failures.is_empty()).then_some(failures),
    })
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
