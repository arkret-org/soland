use arkret_identifiers::DidCoreId;
use arkret_models_collaboration::agent_operations::AgentLifecycleState;
use arkret_models_identity::HandleBindingState;
use arkret_wire::SchemaId;

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

/// The signed target is the complete Agent `AccountId`, derived by the caller
/// from the accepted provision's controller account rather than from this
/// service's own Station. The selector namespace stays principal-scoped.
/// Ruling `review/spec-done/2026-09-05-1310`.
pub(super) fn signed_agent_selector_claim(
    state: &AppState,
    controller_subject: &str,
    agent_slug: &str,
    subject_account_id: &arkret_wire::AccountId,
    request: &DirectoryResolveAgentSelectorRequestBody,
) -> Result<AgentSelectorClaim, AppError> {
    let service_id = DidCoreId::new(state.service_id().clone())
        .map_err(|error| AppError::internal(format!("invalid service core id: {error}")))?;
    let issuer = service_id.clone();
    let issuer_did = state.service_resolution_commitment().did.clone();
    let controller_subject = DidCoreId::new(controller_subject.to_owned())
        .map_err(|err| AppError::internal(format!("invalid controller DID: {err}")))?;
    let subject_account_id = subject_account_id.clone();
    let audience = selector_claim_audience(request);
    let created_at = now();
    let expires_at = created_at + chrono::Duration::hours(24);
    let mut claim_scope = BTreeMap::new();
    claim_scope.insert("intent".to_owned(), json!(request.intent.as_str()));
    if let Some(realm_id) = request.realm_id.as_ref() {
        claim_scope.insert("realm_id".to_owned(), json!(realm_id.as_str()));
    }
    let unsigned = json!({
        "schema": SchemaId::AGENT_SELECTOR_CLAIM_V1,
        "controller_subject_id": controller_subject.as_str(),
        "agent_slug": agent_slug,
        "subject_account_id": serde_json::to_value(&subject_account_id)
            .map_err(|error| AppError::internal(format!("serialize agent AccountId: {error}")))?,
        "issuer_id": issuer.as_str(),
        "vouching_id": service_id.as_str(),
        "binding_state": "verified",
        "visibility": "restricted",
        "audience": audience,
        "claim_scope": claim_scope.clone(),
        "expires_at": arkret_canonical::format_timestamp_canonical(expires_at),
        "created_at": arkret_canonical::format_timestamp_canonical(created_at),
        "source_refs": [],
    });
    let canonical_bytes = canonical::canonical_json_bytes(&unsigned).map_err(|err| {
        AppError::internal(format!(
            "agent selector claim canonicalization failed: {err}"
        ))
    })?;
    let signer = Ed25519PayloadSigner::new(
        (*state.notary_signing_key()).clone(),
        issuer_did.clone(),
        arkret_wire::DidUrl::new(format!("{issuer_did}#directory-agent-selector-claim")).map_err(
            |error| {
                AppError::internal(format!(
                    "directory claim verification method is invalid: {error}"
                ))
            },
        )?,
    );
    let signature = PayloadSigner::sign_payload(&signer, &canonical_bytes)
        .map_err(|err| AppError::internal(format!("agent selector claim signing failed: {err}")))?;
    let proof = PayloadProof {
        kind: "detached_jws".to_owned(),
        verification_method: signature.verification_method,
        payload_digest: signature.payload_digest,
        created_at: signature.created_at,
        domain: None,
        audience: None,
        proof_purpose: None,
        jws: signature.jws,
    };
    Ok(AgentSelectorClaim {
        schema: SchemaId::AGENT_SELECTOR_CLAIM_V1.to_owned(),
        controller_subject_id: controller_subject,
        agent_slug: agent_slug.to_owned(),
        subject_account_id,
        issuer_id: issuer,
        vouching_id: Some(service_id),
        binding_state: HandleBindingState::Verified,
        visibility: HandleVisibility::Restricted,
        audience: Some(selector_claim_audience(request)),
        claim_scope,
        expires_at: Some(expires_at),
        created_at,
        verified_at: Some(created_at),
        source_refs: Vec::new(),
        proofs: vec![proof],
    })
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
    let subject = matches[0].id.as_str();
    let controller_account =
        crate::routing::identity::agent_pcr::agent_controller_account(state, matches[0])
            .await
            .map_err(|_| selector_not_found())?;
    let subject_actor = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
        directory_actor_core_id(subject)?,
        controller_account.station_id,
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
    let selector_claim = signed_agent_selector_claim(
        state,
        controller_subject,
        &body.agent_slug,
        &subject_account_id,
        &body,
    )?;
    let response = DirectoryAgentSelectorResolutionOutcome {
        controller_subject_id: selector_claim.controller_subject_id.clone(),
        subject_account_id: selector_claim.subject_account_id.clone(),
        agent_slug: body.agent_slug,
        expires_at: selector_claim.expires_at,
        source_refs: Vec::new(),
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
