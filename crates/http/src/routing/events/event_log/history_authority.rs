use arkret_models_collaboration::history_key::{
    HistoryAuthorityOutcome, HistoryAuthorityRequestBody,
};
use arkret_state::state_model::ResolvedCellState;

use super::*;

#[salvo::oapi::endpoint(operation_id = "ak.self.seals.read.history_authority", tags("seals"))]
pub(super) async fn read(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    body: JsonBody<HistoryAuthorityRequestBody>,
) -> JsonResult<HistoryAuthorityOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    super::super::require_agent_session_scope(
        &session,
        arkret_wire::ServiceOperationId::SELF_SEALS_READ_HISTORY_AUTHORITY_V1,
    )?;
    let query = body.into_inner();
    query.validate().map_err(super::current_query_error)?;
    let (account_id, authorization_incarnation) =
        current_membership(state, &session, &query).await?;
    // The accepted stores own this traversal. No closure is sent to a client.
    let closure = state
        .projections()
        .seal_basis_closure(&query.seal_basis.leaves)
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
    if historical_membership.incarnation() != &authorization_incarnation {
        return Err(unavailable(
            "history membership differs from the current join identity",
        ));
    }
    let history_floor_epoch = if let Some(join_epoch) = join_epoch {
        let accepted = state
            .projections()
            .effective_state_at(&query.seal_basis.leaves, query.effective_scope.realm_id())
            .await
            .map_err(unavailable)?;
        let policy_cell = match &query.effective_scope {
            arkret_wire::HistoryEffectiveScope::Realm { .. } => {
                arkret_wire::cell::null_subject_cell(
                    arkret_wire::CellFamilyId::REALM_HISTORY_ACCESS_V1,
                )
            }
            arkret_wire::HistoryEffectiveScope::Circle { circle_id, .. } => {
                arkret_wire::cell::subject_cell(
                    arkret_wire::CellFamilyId::CIRCLE_HISTORY_ACCESS_V1,
                    circle_id.as_str(),
                )
            }
        };
        let policy_cell = arkret_wire::CellRef::new(policy_cell).map_err(unavailable)?;
        let policy: arkret_wire::HistoryAccess = accepted
            .get(&policy_cell)
            .and_then(ResolvedCellState::settled_value)
            .ok_or_else(|| unavailable("scope history policy is unavailable"))
            .and_then(|value| serde_json::from_value(value.clone()).map_err(unavailable))?;
        Some(match policy {
            arkret_wire::HistoryAccess::SinceJoin => join_epoch,
            arkret_wire::HistoryAccess::AllHistoryForCurrentMembers => 0,
        })
    } else {
        None
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
        account_id,
        query_digest: query.query_digest().map_err(unavailable)?,
        authorization_incarnation,
        join_epoch,
        history_floor_epoch,
    };
    outcome
        .validate_for_request(&query)
        .map_err(|error| super::current_result_error(error, ErrorCode::FrontierUnavailable))?;
    json_ok(outcome)
}

fn unavailable(error: impl std::fmt::Display) -> AppError {
    crate::app_error!(FrontierUnavailable, error.to_string())
}

async fn current_membership(
    state: &AppState,
    session: &SessionRecord,
    query: &HistoryAuthorityRequestBody,
) -> Result<
    (
        arkret_wire::AccountId,
        arkret_models_collaboration::history_key::AuthorizationIncarnation,
    ),
    AppError,
> {
    query.validate().map_err(super::current_query_error)?;
    let actor =
        crate::routing::identity::session_actor::session_actor_from_credential(state, session)?;
    let account_id = actor
        .as_account_id()
        .cloned()
        .ok_or_else(|| AppError::unauthenticated("membership query requires an Account session"))?;
    let scope = arkret_wire::ScopeRef::from(query.effective_scope.clone());
    if !crate::routing::spaces::space::realm_id_accessible(
        state,
        query.effective_scope.realm_id().as_str(),
        Some(session),
    )
    .await
        || !super::governance_proof::scope_visible_to_session(state, &scope, session)
        || !crate::routing::governance_history::history_scope_has_current_member(
            state,
            &query.effective_scope,
            &actor,
        )
        .await
    {
        return Err(AppError::not_found("membership not found"));
    }
    let frontier =
        super::endpoints::load_realm_seal_frontier(state, query.effective_scope.realm_id()).await?;
    if frontier.seal_basis != query.seal_basis {
        return Err(crate::app_error!(
            StateMismatch,
            "membership query frontier is no longer current"
        ));
    }
    let accepted = state
        .projections()
        .effective_state_at(&query.seal_basis.leaves, query.effective_scope.realm_id())
        .await
        .map_err(unavailable)?;
    // Distinguish a missing/non-joined member from an unresolved reducer cell.
    for circle in std::iter::once(None).chain(query.effective_scope.circle_id().map(Some)) {
        let mut coordinates = Vec::new();
        if let Some(circle) = circle {
            coordinates.push(serde_json::Value::String(circle.to_string()));
        }
        coordinates.push(serde_json::Value::String(
            query.actor_id.canonical_key().map_err(unavailable)?,
        ));
        let subject = arkret_wire::cell::composite_subject(&coordinates).map_err(unavailable)?;
        let family = if circle.is_some() {
            arkret_wire::CellFamilyId::CIRCLE_MEMBER_V1
        } else {
            arkret_wire::CellFamilyId::MEMBER_STATE_V1
        };
        let cell = arkret_wire::CellRef::new(arkret_wire::cell::subject_cell(family, &subject))
            .map_err(unavailable)?;
        match accepted
            .get(&cell)
            .and_then(ResolvedCellState::settled_value)
        {
            Some(value) if value.as_str() == Some("join") => {}
            Some(_) => return Err(AppError::not_found("membership not found")),
            None if matches!(accepted.get(&cell), Some(ResolvedCellState::Bottom(_))) => {
                return Err(unavailable("membership cell is unresolved"));
            }
            None => return Err(AppError::not_found("membership not found")),
        }
    }
    if !crate::routing::governance_history::history_scope_has_current_member(
        state,
        &query.effective_scope,
        &query.actor_id,
    )
    .await
    {
        return Err(AppError::not_found("membership not found"));
    }
    let membership = state
        .projections()
        .membership_at_verified_basis(&query.effective_scope, &query.actor_id, &query.seal_basis)
        .await
        .map_err(unavailable)?;
    // Do not return an old join identity after a concurrent accepted frontier advance.
    if super::endpoints::load_realm_seal_frontier(state, query.effective_scope.realm_id())
        .await?
        .seal_basis
        != query.seal_basis
    {
        return Err(crate::app_error!(
            StateMismatch,
            "membership query frontier advanced"
        ));
    }
    Ok((account_id, membership.incarnation().clone()))
}
