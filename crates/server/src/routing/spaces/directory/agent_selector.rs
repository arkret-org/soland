use super::*;

pub(super) fn selector_not_found() -> AppError {
    AppError::not_found("not found")
}

pub(super) fn selector_intent_allowed(intent: &str) -> bool {
    matches!(
        intent.trim(),
        "lookup" | "mention" | "invite" | "member_add"
    )
}

pub(super) async fn selector_resolution_allowed(
    state: &AppState,
    session: Option<&SessionRecord>,
    controller_subject: &str,
    request: &DirectoryResolveAgentSelectorRequestBody,
) -> bool {
    if !selector_intent_allowed(&request.intent) {
        return false;
    }
    let Some(session) = session else {
        return false;
    };
    if request.requester.as_str() != session.actor {
        return false;
    }
    if request.requester.as_str() == controller_subject {
        return true;
    }
    let Some(realm_id) = request.realm_id.as_ref().map(RealmId::as_str) else {
        return false;
    };
    super::realm_has_member(state, realm_id, &session.actor).await
        && super::realm_has_member(state, realm_id, controller_subject).await
}

pub(super) fn selector_claim_audience(
    request: &DirectoryResolveAgentSelectorRequestBody,
) -> String {
    request
        .realm_id
        .as_ref()
        .map(RealmId::as_str)
        .unwrap_or_else(|| request.requester.as_str())
        .to_owned()
}

pub(super) fn signed_agent_selector_claim(
    state: &AppState,
    controller_subject: &str,
    agent_slug: &str,
    subject: &str,
    request: &DirectoryResolveAgentSelectorRequestBody,
) -> Result<AgentSelectorClaim, AppError> {
    let service_did = state.config.service_did.clone();
    let issuer = Did::new(service_did.clone())
        .map_err(|err| AppError::internal(format!("invalid service DID: {err}")))?;
    let controller_subject = Did::new(controller_subject.to_owned())
        .map_err(|err| AppError::internal(format!("invalid controller DID: {err}")))?;
    let subject = Did::new(subject.to_owned())
        .map_err(|err| AppError::internal(format!("invalid agent DID: {err}")))?;
    let audience = selector_claim_audience(request);
    let created_at = now();
    let expires_at = created_at + chrono::Duration::hours(24);
    let mut claim_scope = BTreeMap::new();
    claim_scope.insert("intent".to_owned(), json!(request.intent.as_str()));
    if let Some(realm_id) = request.realm_id.as_ref() {
        claim_scope.insert("realm_id".to_owned(), json!(realm_id.as_str()));
    }
    let unsigned = json!({
        "schema": AGENT_SELECTOR_CLAIM_SCHEMA,
        "controller_subject": controller_subject.as_str(),
        "agent_slug": agent_slug,
        "subject": subject.as_str(),
        "issuer": issuer.as_str(),
        "issuer_service_did": service_did.as_str(),
        "binding_state": "verified",
        "visibility": "restricted",
        "audience": audience,
        "claim_scope": claim_scope.clone(),
        "expires_at": expires_at.to_rfc3339(),
        "created_at": created_at.to_rfc3339(),
        "source_refs": [],
    });
    let canonical_bytes = canonical::canonical_json_bytes(&unsigned).map_err(|err| {
        AppError::internal(format!(
            "agent selector claim canonicalization failed: {err}"
        ))
    })?;
    let signer = Ed25519MoveSigner::new(
        (*state.notary_signing_key()).clone(),
        issuer.clone(),
        format!("{service_did}#directory-agent-selector-claim"),
    );
    let signature = MoveSigner::sign_payload(&signer, &canonical_bytes)
        .map_err(|err| AppError::internal(format!("agent selector claim signing failed: {err}")))?;
    let proof = json!({
        "kind": "detached_jws",
        "alg": signature.alg,
        "verification_method": signature.verification_method,
        "payload_digest": signature.payload_digest.as_str(),
        "created_at": signature.created_at.to_rfc3339(),
        "jws": signature.jws,
    });
    Ok(AgentSelectorClaim {
        schema: AGENT_SELECTOR_CLAIM_SCHEMA.to_owned(),
        controller_subject,
        agent_slug: agent_slug.to_owned(),
        subject,
        issuer,
        issuer_service_did: Some(
            Did::new(state.config.service_did.clone())
                .map_err(|err| AppError::internal(format!("invalid issuer service DID: {err}")))?,
        ),
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

#[endpoint(
    operation_id = "ck.find.directory.query.resolve_agent_selector",
    tags("directory"),
    summary = "Resolve a controller-scoped native personal agent selector exactly"
)]
#[tracing::instrument(
    skip_all,
    fields(op = "ck.find.directory.query.resolve_agent_selector")
)]
pub(super) async fn resolve_agent_selector(
    body: JsonBody<DirectoryResolveAgentSelectorRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<DirectoryAgentSelectorResolutionOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
    require_demo_directory_provider(state)?;
    let body = body.into_inner();
    validate_agent_slug(&body.agent_slug).map_err(|_| selector_not_found())?;
    let session = authenticated_session(state, req).await.ok();
    let service_domain = service_handle_domain(&state.config.service_did);
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
        .get("did")
        .and_then(Value::as_str)
        .ok_or_else(selector_not_found)?;
    if !selector_resolution_allowed(state, session.as_ref(), controller_subject, &body).await {
        return Err(selector_not_found());
    }

    let records = state
        .persistence
        .agents()
        .list_for_controller(controller_subject)
        .await
        .map_err(|err| AppError::internal(format!("agent selector lookup failed: {err}")))?;
    let matches: Vec<&Value> = records
        .iter()
        .filter(|record| {
            record.get("agent_slug").and_then(Value::as_str) == Some(body.agent_slug.as_str())
                && record.get("state").and_then(Value::as_str) == Some("active")
        })
        .collect();
    if matches.len() != 1 {
        return Err(selector_not_found());
    }
    let subject = matches[0]
        .get("agent_principal_id")
        .and_then(Value::as_str)
        .ok_or_else(selector_not_found)?;
    if body
        .expected_agent_did
        .as_ref()
        .is_some_and(|expected| expected.as_str() != subject)
    {
        return Err(selector_not_found());
    }
    let selector_claim =
        signed_agent_selector_claim(state, controller_subject, &body.agent_slug, subject, &body)?;
    let response = DirectoryAgentSelectorResolutionOutcome {
        controller_subject: selector_claim.controller_subject.clone(),
        subject: selector_claim.subject.clone(),
        agent_slug: body.agent_slug,
        verified: true,
        expires_at: selector_claim.expires_at.clone(),
        source_refs: Vec::new(),
        selector_claim,
    };
    response.validate().map_err(|err| {
        AppError::internal(format!("agent selector response validation failed: {err}"))
    })?;
    json_ok(response)
}
