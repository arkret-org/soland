//! Authenticated durable Control Proposal decision submission and observation.

use arkret_state::state::{ControlProposalSnapshot, StoreError};
use arkret_wire::{
    ControlProposalAuthorityKind, ControlProposalDecision, ControlProposalDecisionFaultReason,
    ControlProposalDecisionKind, ControlProposalDecisionReadOutcome,
    ControlProposalDecisionReadRequestBody, ControlProposalDecisionSubmitOutcome,
    ControlProposalDecisionSubmitRequestBody, ControlProposalDecisionSubmitStatus,
    ControlProposalState,
};

use super::*;

const SUBMIT_OPERATION: &str =
    arkret_wire::ServiceOperationId::SELF_CONTROL_PROPOSAL_DECISIONS_COMMAND_SUBMIT;
const READ_OPERATION: &str =
    arkret_wire::ServiceOperationId::SELF_CONTROL_PROPOSAL_DECISIONS_READ_GET;

fn proposal_not_found() -> AppError {
    AppError::not_found("control proposal not found")
}

fn failed_precondition(message: impl Into<String>) -> AppError {
    AppError::new(ErrorCode::FailedPrecondition, message)
        .with_status(StatusCode::PRECONDITION_FAILED)
        .with_wire_code("failed_precondition")
}

fn decision_commit_error(error: StoreError) -> AppError {
    match error {
        StoreError::NotFound(_) => proposal_not_found(),
        StoreError::Conflict(message) => AppError::conflict(message)
            .with_status(StatusCode::CONFLICT)
            .with_wire_code("duplicate_conflict"),
        StoreError::Backend(message) => AppError::internal(format!(
            "control proposal decision commit failed: {message}"
        )),
    }
}

/// Resolve only the ordinary accepted Event record needed for authorization.
/// This deliberately runs before the private Control Proposal snapshot lookup,
/// making unknown and invisible selectors indistinguishable.
async fn require_visible_proposal(
    state: &AppState,
    session: &SessionRecord,
    realm_id: &RealmId,
    proposal_digest: &Hash,
) -> Result<(), AppError> {
    let records = state
        .event_queries()
        .canonical_events()
        .await
        .map_err(|error| {
            AppError::internal(format!("proposal visibility lookup failed: {error}"))
        })?;
    let Some(record) = records.into_iter().find(|record| {
        record.canonical_digest == proposal_digest.as_str()
            && record.realm_id.as_deref() == Some(realm_id.as_str())
    }) else {
        return Err(proposal_not_found());
    };
    if !event_visible_to_session(state, &record, session).await {
        return Err(proposal_not_found());
    }
    Ok(())
}

fn load_snapshot(
    state: &AppState,
    realm_id: &RealmId,
    proposal_digest: &Hash,
) -> Result<ControlProposalSnapshot, AppError> {
    let snapshot = state
        .projections()
        .control_proposal_snapshot(proposal_digest)
        .map_err(|error| {
            AppError::internal(format!("control proposal snapshot unavailable: {error}"))
        })?
        .ok_or_else(proposal_not_found)?;
    let stored_digest =
        arkret_state::state::control_event_digest(&snapshot.event, snapshot.digest_suite).map_err(
            |error| {
                AppError::internal(format!(
                    "stored control proposal digest is invalid: {error}"
                ))
            },
        )?;
    if snapshot.event.realm_id != *realm_id || stored_digest != *proposal_digest {
        return Err(AppError::internal(
            "control proposal snapshot does not bind its durable selector",
        ));
    }
    Ok(snapshot)
}

fn decision_parts(
    decisions: &[ControlProposalDecision],
) -> Result<
    (
        Vec<ControlProposalDecision>,
        Option<ControlProposalDecision>,
    ),
    AppError,
> {
    let mut defers = Vec::new();
    let mut terminal_reject = None;
    for decision in decisions {
        if decision.is_reject() {
            if terminal_reject.replace(decision.clone()).is_some() {
                return Err(AppError::internal(
                    "control proposal snapshot contains multiple terminal rejects",
                ));
            }
        } else {
            if terminal_reject.is_some() {
                return Err(AppError::internal(
                    "control proposal snapshot continues after terminal reject",
                ));
            }
            defers.push(decision.clone());
        }
    }
    Ok((defers, terminal_reject))
}

fn read_outcome(
    request: &ControlProposalDecisionReadRequestBody,
    snapshot: ControlProposalSnapshot,
    observed_at: chrono::DateTime<chrono::Utc>,
) -> Result<ControlProposalDecisionReadOutcome, AppError> {
    let (defers, terminal_reject) = decision_parts(&snapshot.decisions)?;
    let authority_kind = if snapshot.control_proposal_ack.is_some() {
        ControlProposalAuthorityKind::ControlProposalAck
    } else {
        ControlProposalAuthorityKind::AcklessEventProof
    };
    if authority_kind == ControlProposalAuthorityKind::AcklessEventProof
        && (!snapshot.decisions.is_empty() || snapshot.decision_overdue)
    {
        return Err(AppError::internal(
            "Ack-less control proposal carries Ack-derived decision state",
        ));
    }
    if snapshot.event.kind == arkret_wire::EventKind::DeviceRevoke
        && authority_kind != ControlProposalAuthorityKind::ControlProposalAck
    {
        return Err(AppError::internal(
            "ak.device.revoke durable snapshot omits its canonical Ack",
        ));
    }
    let accepted_seal_id = match snapshot.covering_seals.as_slice() {
        [] => None,
        [seal_id] => Some(seal_id.clone()),
        _ => {
            return Err(AppError::internal(
                "control proposal decision read cannot represent multiple direct covering Seals",
            ));
        }
    };
    if accepted_seal_id.is_some() && terminal_reject.is_some() {
        return Err(AppError::internal(
            "control proposal snapshot has conflicting terminal states",
        ));
    }
    let is_overdue = snapshot.decision_overdue
        || snapshot.control_proposal_ack.as_ref().is_some_and(|ack| {
            let current_due_at = defers
                .last()
                .map(ControlProposalDecision::decision_due_at)
                .unwrap_or(ack.decision_due_at);
            observed_at >= current_due_at
        });
    let proposal_state = if accepted_seal_id.is_some() {
        ControlProposalState::Sealed
    } else if terminal_reject.is_some() {
        ControlProposalState::Rejected
    } else if is_overdue {
        ControlProposalState::Overdue
    } else if !defers.is_empty() {
        ControlProposalState::Deferred
    } else {
        ControlProposalState::Pending
    };
    let outcome = ControlProposalDecisionReadOutcome {
        realm_id: request.realm_id.clone(),
        proposal_digest: request.proposal_digest.clone(),
        proposal_event_kind: snapshot.event.kind.as_str().to_owned(),
        proposal_authority_kind: authority_kind,
        proposal_state,
        control_proposal_ack: snapshot.control_proposal_ack,
        defer_decisions: (!defers.is_empty()).then_some(defers),
        terminal_reject,
        fault_reason: (proposal_state == ControlProposalState::Overdue)
            .then_some(ControlProposalDecisionFaultReason::DecisionOverdue),
        accepted_seal_id,
    };
    outcome.validate_for_request(request).map_err(|error| {
        AppError::internal(format!("stored control proposal state is invalid: {error}"))
    })?;
    Ok(outcome)
}

fn submit_outcome(
    decision: &ControlProposalDecision,
    status: ControlProposalDecisionSubmitStatus,
) -> Result<ControlProposalDecisionSubmitOutcome, AppError> {
    let decision_kind = if decision.is_reject() {
        ControlProposalDecisionKind::SignedReject
    } else {
        ControlProposalDecisionKind::SignedDefer
    };
    let outcome = ControlProposalDecisionSubmitOutcome {
        status,
        proposal_digest: decision.proposal_digest().clone(),
        decision_digest: decision.decision_digest().map_err(|error| {
            AppError::internal(format!("accepted proposal decision digest failed: {error}"))
        })?,
        decision_kind,
        proposal_state: if decision.is_reject() {
            ControlProposalState::Rejected
        } else {
            ControlProposalState::Deferred
        },
    };
    outcome
        .validate_for_request(&ControlProposalDecisionSubmitRequestBody {
            decision: decision.clone(),
        })
        .map_err(|error| {
            AppError::internal(format!("proposal decision outcome is invalid: {error}"))
        })?;
    Ok(outcome)
}

#[salvo::oapi::endpoint(
    operation_id = "ak.self.control_proposal_decisions.command.submit",
    tags("events")
)]
#[tracing::instrument(
    skip_all,
    fields(op = "ak.self.control_proposal_decisions.command.submit")
)]
pub(super) async fn submit_control_proposal_decision(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    body: JsonBody<ControlProposalDecisionSubmitRequestBody>,
) -> JsonResult<ControlProposalDecisionSubmitOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    super::super::super::require_agent_session_scope(&session, SUBMIT_OPERATION)?;
    let request = body.into_inner();
    request.validate_structural().map_err(|error| {
        AppError::new(
            ErrorCode::SchemaViolation,
            format!("invalid Control Proposal decision request: {error}"),
        )
        .with_status(StatusCode::BAD_REQUEST)
    })?;
    let decision = &request.decision;
    require_visible_proposal(
        state,
        &session,
        decision.realm_id(),
        decision.proposal_digest(),
    )
    .await?;
    let snapshot = load_snapshot(state, decision.realm_id(), decision.proposal_digest())?;
    let Some(ack) = snapshot.control_proposal_ack.as_ref() else {
        return Err(failed_precondition(
            "Ack-less Control Proposals do not accept signed decisions",
        ));
    };
    if snapshot.decisions.iter().any(|stored| stored == decision) {
        return json_ok(submit_outcome(
            decision,
            ControlProposalDecisionSubmitStatus::Duplicate,
        )?);
    }
    if !snapshot.covering_seals.is_empty() {
        return Err(AppError::conflict("control proposal is already sealed")
            .with_wire_code("duplicate_conflict"));
    }
    if snapshot
        .decisions
        .iter()
        .any(ControlProposalDecision::is_reject)
    {
        return Err(AppError::conflict(
            "control proposal already has a different terminal decision",
        )
        .with_wire_code("duplicate_conflict"));
    }
    let policy = crate::control_proposal::control_proposal_policy(state, decision.realm_id(), &[])
        .await
        .map_err(|error| {
            AppError::new(
                ErrorCode::FailedPrecondition,
                format!("proposal decision policy is unavailable: {error}"),
            )
            .with_status(StatusCode::SERVICE_UNAVAILABLE)
            .with_wire_code("failed_precondition")
        })?;
    crate::control_proposal::verify_control_proposal_decision(
        state,
        &snapshot.event,
        snapshot.digest_suite,
        ack,
        &snapshot.decisions,
        decision,
        policy,
    )
    .await
    .map_err(|error| {
        failed_precondition(format!("proposal decision verification failed: {error}"))
    })?;

    let status = match state
        .projections()
        .commit_control_proposal_decision(decision.proposal_digest(), decision, policy)
        .await
        .map_err(decision_commit_error)?
    {
        soland_storage::ControlProposalDecisionCommitOutcome::Accepted => {
            ControlProposalDecisionSubmitStatus::Accepted
        }
        soland_storage::ControlProposalDecisionCommitOutcome::Duplicate => {
            ControlProposalDecisionSubmitStatus::Duplicate
        }
    };
    json_ok(submit_outcome(decision, status)?)
}

#[salvo::oapi::endpoint(
    operation_id = "ak.self.control_proposal_decisions.read.get",
    tags("events")
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.control_proposal_decisions.read.get"))]
pub(super) async fn read_control_proposal_decision(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    body: JsonBody<ControlProposalDecisionReadRequestBody>,
) -> JsonResult<ControlProposalDecisionReadOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    super::super::super::require_agent_session_scope(&session, READ_OPERATION)?;
    let request = body.into_inner();
    require_visible_proposal(state, &session, &request.realm_id, &request.proposal_digest).await?;
    let snapshot = load_snapshot(state, &request.realm_id, &request.proposal_digest)?;
    json_ok(read_outcome(&request, snapshot, now())?)
}
