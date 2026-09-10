use arkret_models_collaboration::history_key::{
    MembershipAuthorityOutcome, MembershipAuthorityRequestBody,
};
use arkret_state::lattice::CellState;

use super::*;

#[salvo::oapi::endpoint(
    operation_id = "ak.self.seals.read.membership_authority",
    tags("seals")
)]
pub(super) async fn read(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    body: JsonBody<MembershipAuthorityRequestBody>,
) -> JsonResult<MembershipAuthorityOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    super::super::require_agent_session_scope(
        &session,
        arkret_wire::ServiceOperationId::SELF_SEALS_READ_MEMBERSHIP_AUTHORITY_V1,
    )?;
    let query = body.into_inner();
    json_ok(current_membership(state, &session, &query).await?)
}

pub(super) async fn current_membership(
    state: &AppState,
    session: &SessionRecord,
    query: &MembershipAuthorityRequestBody,
) -> Result<MembershipAuthorityOutcome, AppError> {
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
        match accepted.get(&cell) {
            Some(CellState::Bottom(_)) => return Err(unavailable("membership cell is unresolved")),
            None => return Err(AppError::not_found("membership not found")),
            Some(CellState::Value(value)) if value.as_str() == Some("join") => {}
            Some(CellState::Value(_)) => return Err(AppError::not_found("membership not found")),
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
    let outcome = MembershipAuthorityOutcome {
        account_id,
        query_digest: query.query_digest().map_err(unavailable)?,
        seal_basis: query.seal_basis.clone(),
        authorization_incarnation: membership.incarnation().clone(),
    };
    outcome
        .validate_for_request(&query)
        .map_err(|error| super::current_result_error(error, ErrorCode::FrontierUnavailable))?;
    Ok(outcome)
}

fn unavailable(error: impl std::fmt::Display) -> AppError {
    crate::app_error!(FrontierUnavailable, error.to_string())
}
