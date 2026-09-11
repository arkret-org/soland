use arkret_identifiers::DidCoreId;
use arkret_models_collaboration::agent_operations::AgentLifecycleState;

use super::*;

pub(super) fn selector_not_found() -> AppError {
    AppError::not_found("not found")
}

pub(super) fn selector_intent_allowed(intent: DirectoryIntent) -> bool {
    matches!(
        intent,
        DirectoryIntent::Lookup
            | DirectoryIntent::Mention
            | DirectoryIntent::Invite
            | DirectoryIntent::MemberAdd
            | DirectoryIntent::ContactRequest
    )
}

pub(super) async fn selector_resolution_allowed(
    state: &AppState,
    session: Option<&SessionRecord>,
    controller_subject: &str,
    request: &DirectoryResolveAgentSelectorRequestBody,
) -> bool {
    if !selector_intent_allowed(request.intent) {
        return false;
    }
    let Some(session) = session else {
        return false;
    };
    if request.requester_id.as_str() != session.actor {
        return false;
    }
    let Ok(requester_actor) =
        crate::routing::identity::session_actor::session_actor_from_credential(state, session)
    else {
        return false;
    };
    let Ok(controller_principal) = directory_actor_core_id(controller_subject) else {
        return false;
    };
    let controller_actor = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
        controller_principal,
        state.service_core_id(),
    ));
    if requester_actor == controller_actor {
        return true;
    }
    let Some(realm_id) = request.realm_id.as_ref().map(RealmId::as_str) else {
        return false;
    };
    super::realm_has_member(state, realm_id, &requester_actor.to_string()).await
        && super::realm_has_member(state, realm_id, &controller_actor.to_string()).await
}

pub(super) fn selector_claim_audience(
    request: &DirectoryResolveAgentSelectorRequestBody,
) -> String {
    request
        .realm_id
        .as_ref()
        .map(RealmId::as_str)
        .unwrap_or_else(|| request.requester_id.as_str())
        .to_owned()
}

fn selector_disclosure_allowed(
    claim: &AgentSelectorClaim,
    controller: &arkret_wire::AccountId,
    request: &DirectoryResolveAgentSelectorRequestBody,
) -> bool {
    let requester_is_controller =
        request.requester_id == controller.principal_id;
    if claim.visibility == HandleVisibility::Private && !requester_is_controller {
        return false;
    }
    if claim.visibility == HandleVisibility::Restricted && claim.audience.is_none() {
        return false;
    }
    if claim
        .audience
        .as_ref()
        .is_some_and(|a| a != &selector_claim_audience(request))
    {
        return false;
    }
    claim
        .claim_scope
        .iter()
        .all(|(key, value)| match key.as_str() {
            "realm_id" => request
                .realm_id
                .as_ref()
                .is_some_and(|realm| value.as_str() == Some(realm.as_str())),
            "purpose" => value.as_str() == Some(request.intent.as_str()),
            "allowed_operations" => value.as_array().is_some_and(|operations| {
                operations.iter().all(|op| op.is_string())
                    && operations.iter().any(|op| {
                        op.as_str() == Some("ak.find.directory.read.resolve_agent_selector.v1")
                    })
            }),
            _ => false,
        })
}

/// Return only the original portable claim surviving at the accepted PCR
/// frontier. A provision projection without an inner claim proof is not a
/// portable claim and must never be signed into one by this directory.
async fn accepted_agent_selector_claim(
    state: &AppState,
    controller: &arkret_wire::AccountId,
    request: &DirectoryResolveAgentSelectorRequestBody,
) -> Result<AgentSelectorClaim, AppError> {
    let current = state
        .persistence()
        .current_principal(controller, state.projections().cell_registry())
        .await
        .map_err(|_| selector_not_found())?;
    let soland_storage::CurrentPrincipalRead::Ready { pcr_realm_id, .. } = current else {
        return Err(selector_not_found());
    };
    let leaves = state
        .projections()
        .realm_seal_leaves(&pcr_realm_id)
        .await
        .map_err(|_| selector_not_found())?;
    if leaves.is_empty() {
        return Err(selector_not_found());
    }
    let effective = state
        .projections()
        .effective_state_at(&leaves, &pcr_realm_id)
        .await
        .map_err(|_| selector_not_found())?;
    let subject =
        arkret_wire::composite_subject(&[controller.principal_id.as_str(), &request.agent_slug])
            .map_err(|_| selector_not_found())?;
    let cell = arkret_wire::CellRef::new(format!(
        "ak:cell:{}:{subject}",
        CellFamilyId::AGENT_SELECTOR_CLAIM_V1
    ))
    .map_err(|_| selector_not_found())?;
    let Some(arkret_state::lattice::CellState::Value(value)) = effective.get(&cell) else {
        return Err(selector_not_found());
    };
    let claim: AgentSelectorClaim =
        serde_json::from_value(value.clone()).map_err(|_| selector_not_found())?;
    if claim.validate().is_err()
        || claim.controller_subject_id != controller.principal_id
        || claim.agent_slug != request.agent_slug
        || claim.subject_account_id.is_none()
        || claim.expires_at.is_some_and(|expiry| expiry <= now())
        || !selector_disclosure_allowed(&claim, controller, request)
        || claim.issuer_id != controller.principal_id
    {
        return Err(selector_not_found());
    }
    for proof in &claim.proofs {
        let binding = claim
            .canonical_proof_binding_bytes(proof)
            .map_err(|_| selector_not_found())?;
        crate::jws_verify::verify_did_controlled_jws_async(
            &binding,
            &proof.jws,
            &proof.verification_method,
            claim.controller_subject_id.as_str(),
            state,
        )
        .await
        .map_err(|_| selector_not_found())?;
    }
    Ok(claim)
}

#[salvo::oapi::endpoint(
    operation_id = "ak.find.directory.read.resolve_agent_selector",
    tags("spaces")
)]
#[tracing::instrument(
    skip_all,
    fields(op = "ak.find.directory.read.resolve_agent_selector.v1")
)]
pub(super) async fn resolve_agent_selector(
    body: JsonBody<DirectoryResolveAgentSelectorRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<DirectoryAgentSelectorResolutionOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    require_demo_directory_provider(state)?;
    let body = body.into_inner();
    validate_agent_slug(&body.agent_slug).map_err(|_| selector_not_found())?;
    if !super::requester_proof::directory_requester_proofs_verified(
        state,
        &body.proofs,
        Some(body.requester_id.as_str()),
        |proof| body.proof_binding_bytes(proof).ok(),
    )
    .await
    {
        return Err(selector_not_found());
    }
    let session = authenticated_session(state, req).await.ok();
    let service_domain = service_handle_domain(state);
    let Some(lookup) = handle_lookup(&body.controller_handle.to_string(), &service_domain) else {
        return Err(selector_not_found());
    };
    let controller_actor = demo_actors(state)
        .await
        .into_iter()
        .find(|candidate| {
            candidate["handle"]
                .as_str()
                .is_some_and(|handle| local_actor_handle_matches(handle, &lookup, &service_domain))
        })
        .ok_or_else(selector_not_found)?;
    let controller_subject = controller_actor
        .get("actor_id")
        .and_then(Value::as_str)
        .ok_or_else(selector_not_found)?;
    if !selector_resolution_allowed(state, session.as_ref(), controller_subject, &body).await {
        return Err(selector_not_found());
    }

    let records = state
        .agent_pairings()
        .agents_for_controller(controller_subject)
        .await
        .map_err(|err| AppError::internal(format!("agent selector lookup failed: {err}")))?;
    let matches: Vec<_> = records
        .iter()
        .filter(|record| {
            record.agent_slug.as_deref() == Some(body.agent_slug.as_str())
                && record.state == AgentLifecycleState::Active
        })
        .collect();
    if matches.len() != 1 {
        return Err(selector_not_found());
    }
    crate::routing::identity::agent_pcr::validate_agent_controller_binding(
        state,
        matches[0],
        now(),
    )
    .await
    .map_err(|_| selector_not_found())?;
    let subject = matches[0].id.as_str();
    let controller_account =
        crate::routing::identity::agent_pcr::agent_controller_account(state, matches[0])
            .await
            .map_err(|_| selector_not_found())?;
    let subject_actor = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
        directory_actor_core_id(subject)?,
        controller_account.station_id.clone(),
    ));
    if body
        .expected_actor_id
        .as_ref()
        .is_some_and(|expected| expected != &subject_actor)
    {
        return Err(selector_not_found());
    }
    let subject_account_id = subject_actor
        .as_account_id()
        .ok_or_else(selector_not_found)?
        .clone();
    let selector_claim = accepted_agent_selector_claim(state, &controller_account, &body).await?;
    if selector_claim.subject_account_id.as_ref() != Some(&subject_account_id) {
        return Err(selector_not_found());
    }
    let response = DirectoryAgentSelectorResolutionOutcome {
        controller_subject_id: selector_claim.controller_subject_id.clone(),
        subject_account_id,
        agent_slug: body.agent_slug,
        expires_at: selector_claim.expires_at,
        source_refs: selector_claim
            .source_refs
            .iter()
            .cloned()
            .map(EventId::new)
            .collect::<Result<_, _>>()
            .map_err(|_| selector_not_found())?,
        selector_claim,
    };
    response.validate().map_err(|err| {
        AppError::internal(format!("agent selector response validation failed: {err}"))
    })?;
    json_ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn selector_shared_realm_checks_full_local_accounts() {
        let state = AppState::new(
            crate::config::AppConfig::test_default(),
            soland_storage_postgres::Db { pool: None },
        );
        let principal = DidCoreId::new("ak:did_core:web:alice.example").unwrap();
        let controller = DidCoreId::new("ak:did_core:web:controller.example").unwrap();
        let realm = RealmId::new("ak:realm:AXqIXbu56hFXteZXtkBsqJxy_puV4mhSv1U0ZkUldxAL").unwrap();
        let mut session = SessionRecord {
            account_pk: None,
            token_hash: "selector-test".to_owned(),
            actor: principal.to_string(),
            device_id: "test-device".to_owned(),
            audience: state.service_id().clone(),
            session_public_key: None,
            agent_session: None,
            session_grant: None,
            expires_at: now() + chrono::Duration::hours(1),
            created_at: now(),
            revoked_at: None,
        };
        let request: DirectoryResolveAgentSelectorRequestBody = serde_json::from_value(json!({
            "controller_handle": "controller:example.com", "agent_slug": "assistant",
            "intent": "lookup", "realm_id": realm, "requester_id": principal,
        }))
        .unwrap();
        for actor in [principal, controller.clone()] {
            let member = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
                actor,
                state.service_core_id(),
            ));
            let payload =
                arkret_models_collaboration::governance::membership_invite::MembershipPayload::join(
                    realm.clone(),
                    member,
                    "test",
                );
            let operation = arkret_event_draft::test_support::raw_projected_operation(
                arkret_wire::OperationId::new("ak:operation:01904100-0000-7000-8000-000000000001")
                    .unwrap(),
                realm.clone(),
                arkret_wire::EventKind::MemberState.as_str(),
                payload.to_value().unwrap(),
            );
            state
                .test_projection()
                .lock()
                .restore_accepted_membership(&operation, now());
        }
        assert!(
            selector_resolution_allowed(&state, Some(&session), controller.as_str(), &request)
                .await
        );
        session.audience = "ak:did_core:web:foreign.example".to_owned();
        assert!(
            !selector_resolution_allowed(&state, Some(&session), controller.as_str(), &request)
                .await
        );
        assert!(
            !selector_resolution_allowed(&state, Some(&session), &session.actor, &request).await
        );
    }
}
