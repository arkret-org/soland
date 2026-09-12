use arkret_models_crypto::{MlsWelcomeRefsOutcome, MlsWelcomeRefsRequestBody};
use arkret_models_identity::SessionGrantHolderBinding;

use super::*;

#[salvo::oapi::endpoint(operation_id = "ak.self.seals.read.mls_welcome_refs", tags("seals"))]
pub(super) async fn read(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    body: JsonBody<MlsWelcomeRefsRequestBody>,
) -> JsonResult<MlsWelcomeRefsOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    super::super::require_agent_session_scope(
        &session,
        arkret_wire::ServiceOperationId::SELF_SEALS_READ_MLS_WELCOME_REFS_V1,
    )?;
    let query = body.into_inner();
    query.validate().map_err(super::current_query_error)?;
    let actor =
        crate::routing::identity::session_actor::session_actor_from_credential(state, &session)?;
    let account = actor
        .as_account_id()
        .ok_or_else(|| AppError::not_found("Welcome not found"))?;
    let realm = query
        .effective_scope
        .realm_id_opt()
        .expect("validated scope");
    let own_pcr = durable_account_owns_pcr(state, &actor, realm).await?;
    if !super::governance_proof::scope_visible_to_session(state, &query.effective_scope, &session) {
        return Err(AppError::not_found("Welcome not found"));
    }
    let grant = session.session_grant.as_ref().ok_or_else(|| {
        AppError::unauthenticated("Welcome discovery requires an exact session endpoint")
    })?;
    let (recipient_actor, endpoint, authorization_ref, require_realm_membership) = match &grant
        .holder_binding
    {
        SessionGrantHolderBinding::HumanDevice { .. } => {
            let binding = grant.device_binding.as_ref().ok_or_else(|| {
                AppError::unauthenticated("session device authorization is missing")
            })?;
            if binding.device_id.as_str() != session.device_id || session.agent_session.is_some() {
                return Err(AppError::unauthenticated("session device differs"));
            }
            (
                actor.clone(),
                serde_json::json!({"principal_id":account.principal_id,"station_id":account.station_id,"device_id":binding.device_id,"agent_id":null,"verification_method":null}),
                binding.authorization_event_id.to_string(),
                !own_pcr,
            )
        }
        SessionGrantHolderBinding::AgentRuntime {
            agent_id,
            device_id,
            agent_key_authorization_ref,
            verification_method,
        } => {
            if agent_id != &account.principal_id
                || device_id.as_str() != session.device_id
                || !session.agent_session.as_ref().is_some_and(|agent| {
                    agent.freshness_state == arkret_wire::FreshnessState::Fresh
                })
            {
                return Err(AppError::not_found("Welcome not found"));
            }
            (
                actor.clone(),
                serde_json::json!({"principal_id":agent_id,"station_id":account.station_id,"device_id":null,"agent_id":agent_id,"verification_method":verification_method}),
                agent_key_authorization_ref.to_string(),
                !own_pcr,
            )
        }
        SessionGrantHolderBinding::MinimalMetadataPairwise {
            realm_id,
            actor_id,
            verification_method,
        } => {
            if realm_id != realm {
                return Err(AppError::not_found("Welcome not found"));
            }
            super::validation::validate_pairwise_session_holder(
                state,
                &query.effective_scope,
                query.mls_group_id.as_str(),
                actor_id,
                verification_method,
            )
            .await
            .map_err(|_| {
                AppError::unauthenticated("pairwise endpoint authorization is no longer current")
            })?;
            let endpoint_account = actor_id
                .as_account_id()
                .ok_or_else(|| AppError::unauthenticated("pairwise endpoint actor is invalid"))?;
            (
                actor_id.clone(),
                serde_json::json!({"principal_id":endpoint_account.principal_id,"station_id":endpoint_account.station_id,"device_id":null,"agent_id":null,"verification_method":verification_method}),
                verification_method.to_string(),
                true,
            )
        }
        _ => return Err(AppError::not_found("Welcome not found")),
    };
    let mut membership_cells = Vec::new();
    for circle in std::iter::once(None)
        .filter(|_| require_realm_membership)
        .chain(query.effective_scope.circle_id().map(Some))
    {
        let mut coordinates = Vec::new();
        if let Some(circle) = circle {
            coordinates.push(serde_json::json!(circle));
        }
        coordinates.push(serde_json::json!(
            recipient_actor.canonical_key().map_err(unavailable)?
        ));
        let subject = arkret_wire::cell::composite_subject(&coordinates).map_err(unavailable)?;
        let family = if circle.is_some() {
            arkret_wire::CellFamilyId::CIRCLE_MEMBER_V1
        } else {
            arkret_wire::CellFamilyId::MEMBER_STATE_V1
        };
        membership_cells.push(arkret_wire::cell::subject_cell(family, &subject));
    }
    let page=state.persistence().discover_mls_welcome_refs(&soland_storage::MlsWelcomeDiscoveryQuery {
        scope:serde_json::to_value(&query.effective_scope).map_err(unavailable)?,group_id:query.mls_group_id.to_string(),endpoint,
        authority_context:serde_json::json!({"account_id":account,"device_id":session.device_id,"holder_binding":grant.holder_binding,"authorization_ref":authorization_ref,"own_pcr":own_pcr}),
        authorization_ref,membership_cells,limit:query.effective_limit(),cursor:query.cursor.clone(),now:chrono::Utc::now(),
    }).await.map_err(|error|match error {
        soland_storage::PersistenceError::Conflict(ref code) if code=="cursor_invalid"=>crate::app_error!(CursorInvalid,"Welcome discovery window is no longer valid"),
        soland_storage::PersistenceError::Conflict(ref code) if code=="not_found"=>AppError::not_found("Welcome not found"),
        _=>unavailable(error),
    })?;
    let outcome = MlsWelcomeRefsOutcome {
        welcome_refs: page
            .welcome_refs
            .into_iter()
            .map(EventId::new)
            .collect::<Result<_, _>>()
            .map_err(unavailable)?,
        next_cursor: page.next_cursor,
    };
    outcome
        .validate_for_request(&query)
        .map_err(|error| super::current_result_error(error, ErrorCode::FrontierUnavailable))?;
    json_ok(outcome)
}

fn unavailable(error: impl std::fmt::Display) -> AppError {
    crate::app_error!(
        FrontierUnavailable,
        format!("Welcome discovery is unavailable: {error}")
    )
}
