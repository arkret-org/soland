use arkret_models_collaboration::history_key::{
    HistoryAuthorityOutcome, HistoryAuthorityRequest, MembershipAuthorityRequest,
};
use arkret_state::lattice::CellState;

use super::*;

#[salvo::oapi::endpoint(operation_id = "ak.self.seals.read.history_authority", tags("seals"))]
pub(super) async fn read(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    body: JsonBody<HistoryAuthorityRequest>,
) -> JsonResult<HistoryAuthorityOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    super::super::require_agent_session_scope(
        &session,
        arkret_wire::ServiceOperationId::SELF_SEALS_READ_HISTORY_AUTHORITY_V1,
    )?;
    let query = body.into_inner();
    query
        .validate()
        .map_err(|e| AppError::param_invalid(e.to_string()))?;
    let membership = super::membership_authority::current_membership(
        state,
        &session,
        &MembershipAuthorityRequest {
            effective_scope: query.effective_scope.clone(),
            actor_id: query.actor_id.clone(),
            seal_basis: query.seal_basis.clone(),
        },
    )
    .await?;
    let accepted = state
        .projections()
        .effective_state_at(&query.seal_basis.leaves, query.effective_scope.realm_id())
        .await
        .map_err(unavailable)?;
    let policy_cell = match &query.effective_scope {
        arkret_wire::HistoryEffectiveScope::Realm { .. } => {
            arkret_wire::cell::null_subject_cell(arkret_wire::CellFamilyId::REALM_HISTORY_ACCESS_V1)
        }
        arkret_wire::HistoryEffectiveScope::Circle { circle_id, .. } => {
            arkret_wire::cell::subject_cell(
                arkret_wire::CellFamilyId::CIRCLE_HISTORY_ACCESS_V1,
                circle_id.as_str(),
            )
        }
    };
    let policy_cell = arkret_wire::CellRef::new(policy_cell).map_err(unavailable)?;
    let policy: arkret_wire::HistoryAccess = match accepted.get(&policy_cell) {
        Some(CellState::Value(value)) => {
            serde_json::from_value(value.clone()).map_err(unavailable)?
        }
        _ => return Err(unavailable("scope history policy is unavailable")),
    };
    // The accepted stores own this traversal. No closure is sent to a client.
    let closure = state
        .projections()
        .seal_closure(&query.seal_basis.leaves)
        .await
        .map_err(unavailable)?;
    let mut event_digests = BTreeSet::new();
    for id in closure {
        let seal = state
            .projections()
            .seal_by_id(&id)
            .await
            .map_err(unavailable)?
            .ok_or_else(|| unavailable("accepted history Seal is missing"))?;
        if seal.realm_id != *query.effective_scope.realm_id() {
            return Err(unavailable("accepted history crosses Realm"));
        }
        event_digests.extend(seal.delta);
    }
    let mut events = Vec::with_capacity(event_digests.len());
    for digest in event_digests {
        events.push(
            state
                .projections()
                .control_event_by_digest(&digest)
                .await
                .map_err(unavailable)?
                .ok_or_else(|| unavailable("accepted history Event is missing"))?,
        );
    }
    let (historical_membership, join_epoch) = state
        .projections()
        .member_history_at_verified_basis(
            &query.effective_scope,
            &query.actor_id,
            &query.seal_basis,
            &events,
        )
        .await
        .map_err(unavailable)?;
    if historical_membership.incarnation() != &membership.authorization_incarnation {
        return Err(unavailable(
            "history membership differs from the current join identity",
        ));
    }
    let join_epoch = join_epoch
        .ok_or_else(|| unavailable("history membership is ready; MLS lineage is pending"))?;
    let history_floor_epoch = match policy {
        arkret_wire::HistoryAccess::SinceJoin => join_epoch,
        arkret_wire::HistoryAccess::AllHistoryForCurrentMembers => 0,
    };
    if super::endpoints::load_realm_seal_frontier(state, query.effective_scope.realm_id())
        .await?
        .seal_basis
        != query.seal_basis
    {
        return Err(crate::app_error!(
            StateMismatch,
            "history query frontier advanced"
        ));
    }
    let outcome = HistoryAuthorityOutcome {
        account_id: membership.account_id,
        query_digest: query.query_digest().map_err(unavailable)?,
        seal_basis: query.seal_basis.clone(),
        authorization_incarnation: membership.authorization_incarnation,
        join_epoch,
        history_floor_epoch,
    };
    outcome.validate_for_request(&query).map_err(unavailable)?;
    json_ok(outcome)
}

fn unavailable(error: impl std::fmt::Display) -> AppError {
    crate::app_error!(FrontierUnavailable, error.to_string())
}
