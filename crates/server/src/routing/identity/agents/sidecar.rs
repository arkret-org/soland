use super::*;

pub(super) const SIDECAR_CREATE_DENIED: &str = "sidecar_create_denied";
pub(super) const ADDRESSED_AGENT_NOT_ELIGIBLE: &str = "addressed_agent_not_eligible";
pub(super) const CONTROLLER_IN_ADDRESSED_AGENTS: &str = "controller_in_addressed_agents";

pub(super) fn sidecar_create_denied(message: impl Into<String>) -> AppError {
    AppError::capability_denied(message).with_wire_code(SIDECAR_CREATE_DENIED)
}

pub(super) fn sidecar_failed_precondition(
    reason: &'static str,
    message: impl Into<String>,
) -> AppError {
    AppError::new(ErrorCode::FailedPrecondition, message.into())
        .with_status(StatusCode::PRECONDITION_FAILED)
        .with_wire_code(reason)
}

pub(super) fn sidecar_reducer_reject_to_app_error(reason: &'static str) -> AppError {
    AppError::new(
        ErrorCode::FailedPrecondition,
        format!("agent sidecar reducer rejected: {reason}"),
    )
    .with_status(StatusCode::PRECONDITION_FAILED)
    .with_wire_code(reason)
}

pub(super) async fn authorize_sidecar_ensure(
    state: &AppState,
    controller: &str,
    realm_id: &str,
) -> Result<(), AppError> {
    let owner = state
        .persistence
        .realm_meta()
        .get(realm_id)
        .await
        .ok()
        .flatten()
        .map(|meta| meta.owner);
    let members = realm_members_for_authz(state, realm_id);
    let verdict = state.authz.check(
        controller,
        arkret_sdk::CAP_ACTION_AGENT_SIDECAR_THREAD_ENSURE,
        realm_id,
        realm_id,
        owner.as_deref(),
        &members,
        &[],
    );
    if verdict.allowed {
        return Ok(());
    }
    if matches!(
        verdict.reason.as_str(),
        "explicit_deny" | "quarantine" | "require_review" | "constraints_not_satisfied"
    ) {
        return Err(sidecar_create_denied(
            "ak.self.agent.sidecar_thread.command.ensure denied by policy",
        ));
    }
    if realm_member_joined(state, realm_id, controller) {
        return Ok(());
    }
    Err(sidecar_create_denied(
        "ak.self.agent.sidecar_thread.command.ensure requires a Realm member controller",
    ))
}

pub(super) fn realm_members_for_authz(state: &AppState, realm_id: &str) -> Vec<String> {
    {
        let realms = state.realms.lock();
        {
            RealmId::new(realm_id.to_owned())
                .ok()
                .and_then(|id| realms.get(&id).cloned())
        }
    }
    .map(|realm| {
        realm
            .members
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
    })
    .unwrap_or_default()
}

pub(super) fn realm_member_joined(state: &AppState, realm_id: &str, actor: &str) -> bool {
    let in_realm_directory = {
        let realms = state.realms.lock();
        {
            RealmId::new(realm_id.to_owned())
                .ok()
                .and_then(|id| realms.get(&id).cloned())
        }
    }
    .and_then(|realm| {
        Did::new(actor.to_owned())
            .ok()
            .map(|did| realm.members.contains(&did))
    })
    .unwrap_or(false);
    if in_realm_directory {
        return true;
    }
    {
        let projection = state.projection.lock();
        {
            projection
                .member(realm_id, actor)
                .map(|membership| membership.state == "join")
        }
    }
    .unwrap_or(false)
}

pub(super) fn normalize_sidecar_context_ref(
    context_ref: &AgentSidecarContextRef,
) -> Result<Value, AppError> {
    let has_strand = context_ref.strand_id.is_some();
    let has_relation = context_ref.relation_id.is_some();
    if has_relation
        && (has_strand || context_ref.message_id.is_some() || context_ref.track_name.is_some())
    {
        return Err(AppError::invalid_param(
            "context_ref with relation_id must not include strand_id, message_id, or track_name",
        ));
    }
    if !has_relation && !has_strand {
        return Err(AppError::invalid_param(
            "context_ref must include either strand_id or relation_id",
        ));
    }
    if context_ref.message_id.is_some() && !has_strand {
        return Err(AppError::invalid_param(
            "context_ref.message_id requires strand_id",
        ));
    }
    serde_json::to_value(context_ref)
        .map_err(|err| AppError::internal(format!("context_ref serialization failed: {err}")))
}

pub(super) fn sidecar_context_target_ref(context_ref: &AgentSidecarContextRef) -> String {
    if let Some(relation_id) = &context_ref.relation_id {
        return relation_id.to_string();
    }
    if let Some(message_id) = &context_ref.message_id {
        return message_id.to_string();
    }
    context_ref
        .strand_id
        .as_ref()
        .expect("context_ref validated")
        .to_string()
}

pub(super) fn validate_sidecar_context_projection(
    state: &AppState,
    context_ref: &AgentSidecarContextRef,
) -> Result<(), AppError> {
    let projection = state.projection.lock();
    let realm_id = context_ref.realm_id.as_str();
    if let Some(relation_id) = &context_ref.relation_id {
        let relation = projection
            .relations
            .get(relation_id.as_str())
            .ok_or_else(|| AppError::not_found("context_ref.relation_id not found"))?;
        if relation.realm_id != realm_id {
            return Err(sidecar_failed_precondition(
                "context_ref_realm_mismatch",
                "context_ref.relation_id belongs to another Realm",
            ));
        }
        if relation.state != "active" {
            return Err(sidecar_failed_precondition(
                "relation_not_active",
                "context_ref.relation_id is not active",
            ));
        }
        return Ok(());
    }
    let Some(strand_id) = &context_ref.strand_id else {
        return Err(AppError::invalid_param(
            "context_ref must include strand_id or relation_id",
        ));
    };
    let strand = projection
        .strands
        .get(strand_id.as_str())
        .ok_or_else(|| AppError::not_found("context_ref.strand_id not found"))?;
    if strand.realm_id != realm_id {
        return Err(sidecar_failed_precondition(
            "context_ref_realm_mismatch",
            "context_ref.strand_id belongs to another Realm",
        ));
    }
    if let Some(message_id) = &context_ref.message_id {
        let message = projection
            .messages
            .get(message_id.as_str())
            .ok_or_else(|| AppError::not_found("context_ref.message_id not found"))?;
        if message.realm_id != realm_id || message.thread_id != strand_id.as_str() {
            return Err(sidecar_failed_precondition(
                "context_ref_realm_mismatch",
                "context_ref.message_id does not belong to the referenced Strand",
            ));
        }
    }
    Ok(())
}

pub(super) fn normalize_addressed_agents(
    controller: &str,
    body: &AgentSidecarThreadEnsureRequestBody,
) -> Result<Vec<String>, AppError> {
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for agent in &body.addressed_agent_ids {
        let agent = agent.as_str().trim();
        if agent == controller {
            return Err(sidecar_failed_precondition(
                CONTROLLER_IN_ADDRESSED_AGENTS,
                "addressed_agent_ids must not contain the controller",
            ));
        }
        if seen.insert(agent.to_owned()) {
            out.push(agent.to_owned());
        }
    }
    Ok(out)
}

pub(super) async fn eligible_sidecar_agents(
    state: &AppState,
    realm_id: &str,
    controller: &str,
    addressed_agents: &[String],
) -> Result<Vec<String>, AppError> {
    let records = state
        .persistence
        .agents()
        .list_for_controller(controller)
        .await
        .map_err(|err| AppError::internal(format!("agent list failed: {err}")))?;
    let mut eligible = BTreeSet::new();
    for record in records {
        if let Some(agent_id) = record.get("agent_id").and_then(Value::as_str)
            && agent_record_is_sidecar_eligible(state, realm_id, controller, &record)
        {
            eligible.insert(agent_id.to_owned());
        }
    }
    for addressed in addressed_agents {
        if !eligible.contains(addressed) {
            return Err(sidecar_failed_precondition(
                ADDRESSED_AGENT_NOT_ELIGIBLE,
                "addressed agent is not eligible for this sidecar Realm",
            ));
        }
    }
    Ok(eligible.into_iter().collect())
}

pub(super) fn agent_record_is_sidecar_eligible(
    state: &AppState,
    realm_id: &str,
    controller: &str,
    record: &Value,
) -> bool {
    let Some(agent_id) = record.get("agent_id").and_then(Value::as_str) else {
        return false;
    };
    if record.get("controller_id").and_then(Value::as_str) != Some(controller) {
        return false;
    }
    if record
        .get("state")
        .and_then(Value::as_str)
        .is_some_and(|state| state != "active")
    {
        return false;
    }
    if !realm_member_joined(state, realm_id, agent_id) {
        return false;
    }
    let projection = state.projection.lock();
    !matches!(
        projection.agent_lifecycles.get(agent_id),
        Some(AgentLifecycleState::Paused | AgentLifecycleState::Deactivated)
    ) && projection.agent_has_authorized_key(agent_id)
}

pub(super) fn controller_agent_circle_key(realm_id: &str, controller: &str) -> String {
    arkret_sdk::agent_sidecar_circle_key(realm_id, controller)
}

pub(super) fn sidecar_short_name(controller_agent_circle_key: &str) -> String {
    arkret_sdk::agent_sidecar_short_name(controller_agent_circle_key)
}

pub(super) fn find_sidecar_circle(
    state: &AppState,
    realm_id: &str,
    controller: &str,
    short_name: &str,
) -> Option<CircleId> {
    let projection = state.projection.lock();
    projection
        .circles
        .values()
        .find(|circle| {
            circle.realm_id == realm_id
                && circle.profile_ref.as_deref() == Some(arkret_sdk::PROFILE_AGENT_SIDECAR_THREAD)
                && circle.created_by == controller
                && circle.title == short_name
                && circle.directory_visibility == "members"
                && circle.state == crate::reducer::CircleLifecycleState::Active
        })
        .and_then(|circle| CircleId::new(circle.circle_id.clone()).ok())
}

pub(super) fn sidecar_actor_capability(circle_id: Option<&str>) -> Value {
    let mut value = json!({
        "action": arkret_sdk::CAP_ACTION_AGENT_SIDECAR_THREAD_ENSURE,
        "allowed": true,
    });
    if let Some(circle_id) = circle_id
        && let Some(object) = value.as_object_mut()
    {
        object.insert("circle_id".to_owned(), Value::String(circle_id.to_owned()));
    }
    value
}

pub(super) fn new_sidecar_operation(
    realm_id: &RealmId,
    kind: &'static str,
    payload: Value,
) -> Result<Operation, AppError> {
    let operation_id = OperationId::new(ids::generate_operation_id())
        .map_err(|err| AppError::internal(format!("generated operation id invalid: {err}")))?;
    Ok(Operation::create(
        operation_id,
        realm_id.clone(),
        kind,
        payload,
    ))
}

pub(super) async fn ensure_sidecar_circle(
    state: &AppState,
    controller: &str,
    realm_id: &RealmId,
    controller_agent_circle_key: &str,
    short_name: &str,
) -> Result<CircleId, AppError> {
    if let Some(circle_id) = find_sidecar_circle(state, realm_id.as_str(), controller, short_name) {
        return Ok(circle_id);
    }
    let circle_id = CircleId::new(ids::generate_circle_id())
        .map_err(|err| AppError::internal(format!("generated circle id invalid: {err}")))?;
    let object = json!({
        "id": circle_id,
        "schema": "ak.schema.circle.v1",
        "realm_id": realm_id,
        "profile_ref": arkret_sdk::PROFILE_AGENT_SIDECAR_THREAD,
        "title": short_name,
        "summary": "Controller-private AI sidecar scope",
        "display": {
            "short_name": short_name,
            "color_token": "slate",
            "symbol": { "glyph": "spark" },
        },
        "directory_visibility": "members",
        "join_rule": "invite",
        "history_visibility": "joined",
        "content_encryption_floor": "e2ee_required",
        "metadata_encryption_floor": "e2ee_required",
        "encryption_profile": "mls_rfc9420",
        "state": "active",
        "created_by": controller,
        "created_at": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
    });
    let payload = json!({
        "object": object,
        "sender": controller,
        "controller_id": controller,
        "controller_agent_circle_key": controller_agent_circle_key,
        "profile": arkret_sdk::PROFILE_AGENT_SIDECAR_THREAD,
        "sidecar_ensure_capability_verified": true,
        "actor_capability": sidecar_actor_capability(None),
    });
    let operation =
        new_sidecar_operation(realm_id, arkret_sdk::events::kinds::CIRCLE_CREATE, payload)?;
    accept_local_operations(state, controller, std::slice::from_ref(&operation))
        .await
        .map_err(sidecar_reducer_reject_to_app_error)?;
    find_sidecar_circle(state, realm_id.as_str(), controller, short_name)
        .ok_or_else(|| AppError::internal("sidecar Circle accepted but not projected"))
}

pub(super) fn circle_has_member(state: &AppState, circle_id: &str, actor: &str) -> bool {
    {
        let projection = state.projection.lock();
        {
            projection
                .circles
                .get(circle_id)
                .map(|circle| circle.members.contains(actor))
        }
    }
    .unwrap_or(false)
}

pub(super) async fn ensure_sidecar_member(
    state: &AppState,
    controller: &str,
    realm_id: &RealmId,
    circle_id: &CircleId,
    actor: &str,
) -> Result<(), AppError> {
    if circle_has_member(state, circle_id.as_str(), actor) {
        return Ok(());
    }
    let payload = json!({
        "circle_id": circle_id,
        "actor_id": actor,
        "membership": "join",
    });
    let operation = new_sidecar_operation(
        realm_id,
        arkret_sdk::events::kinds::CIRCLE_MEMBER_STATE,
        payload,
    )?;
    crate::routing::events::projection::accept_trusted_sidecar_member_operation(
        state, controller, &operation,
    )
    .await
    .map_err(sidecar_reducer_reject_to_app_error)
}

pub(super) fn find_sidecar_strand(
    state: &AppState,
    realm_id: &str,
    controller: &str,
    circle_id: &str,
    normalized_context_ref_digest: &str,
) -> Option<StrandId> {
    let projection = state.projection.lock();
    projection
        .strands
        .values()
        .find(|strand| {
            strand.realm_id == realm_id
                && strand.scope_circle_id.as_deref() == Some(circle_id)
                && strand.fields.get("sidecar_profile").and_then(Value::as_str)
                    == Some(arkret_sdk::PROFILE_AGENT_SIDECAR_THREAD)
                && strand.fields.get("controller_id").and_then(Value::as_str) == Some(controller)
                && strand
                    .fields
                    .get("normalized_context_ref_digest")
                    .and_then(Value::as_str)
                    == Some(normalized_context_ref_digest)
        })
        .and_then(|strand| StrandId::new(strand.strand_id.clone()).ok())
}

pub(super) async fn ensure_sidecar_strand(
    state: &AppState,
    controller: &str,
    realm_id: &RealmId,
    circle_id: &CircleId,
    normalized_context_ref: &Value,
    normalized_context_ref_digest: &str,
) -> Result<StrandId, AppError> {
    if let Some(strand_id) = find_sidecar_strand(
        state,
        realm_id.as_str(),
        controller,
        circle_id.as_str(),
        normalized_context_ref_digest,
    ) {
        return Ok(strand_id);
    }
    let strand_id = StrandId::new(ids::generate("strand"))
        .map_err(|err| AppError::internal(format!("generated strand id invalid: {err}")))?;
    let object = json!({
        "id": strand_id,
        "schema": "ak.schema.strand.v1",
        "realm_id": realm_id,
        "metadata": {
            "title": "AI sidecar",
            "summary": "Controller-private AI sidecar thread",
            "fields": {
                "sidecar_profile": arkret_sdk::PROFILE_AGENT_SIDECAR_THREAD,
                "controller_id": controller,
                "normalized_context_ref": normalized_context_ref,
                "normalized_context_ref_digest": normalized_context_ref_digest,
            },
        },
        "tracks": { "discussion": { "enabled": true, "is_primary": true } },
        "scope_circle_id": circle_id,
        "created_by": controller,
        "created_at": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
    });
    let payload = json!({
        "object": object,
    });
    let operation =
        new_sidecar_operation(realm_id, arkret_sdk::events::kinds::STRAND_CREATE, payload)?;
    accept_local_operations(state, controller, std::slice::from_ref(&operation))
        .await
        .map_err(sidecar_reducer_reject_to_app_error)?;
    find_sidecar_strand(
        state,
        realm_id.as_str(),
        controller,
        circle_id.as_str(),
        normalized_context_ref_digest,
    )
    .ok_or_else(|| AppError::internal("sidecar Strand accepted but not projected"))
}

pub(super) fn find_sidecar_relation(
    state: &AppState,
    realm_id: &str,
    circle_id: &str,
    private_strand_id: &str,
    target_ref: &str,
) -> Option<RelationId> {
    let projection = state.projection.lock();
    projection
        .relations
        .values()
        .find(|relation| {
            relation.realm_id == realm_id
                && relation.relation_kind == "agent_sidecar_of"
                && relation.scope_circle_id.as_deref() == Some(circle_id)
                && relation.from_ref.as_deref() == Some(private_strand_id)
                && relation.to_ref.as_deref() == Some(target_ref)
                && relation.state == "active"
        })
        .and_then(|relation| RelationId::new(relation.relation_id.clone()).ok())
}

pub(super) async fn ensure_sidecar_relation(
    state: &AppState,
    controller: &str,
    realm_id: &RealmId,
    circle_id: &CircleId,
    private_strand_id: &StrandId,
    target_ref: &str,
    normalized_context_ref_digest: &str,
    track_name: Option<&str>,
) -> Result<RelationId, AppError> {
    if let Some(relation_id) = find_sidecar_relation(
        state,
        realm_id.as_str(),
        circle_id.as_str(),
        private_strand_id.as_str(),
        target_ref,
    ) {
        return Ok(relation_id);
    }
    let relation_id = RelationId::new(ids::generate_relation_id())
        .map_err(|err| AppError::internal(format!("generated relation id invalid: {err}")))?;
    let mut fields = json!({
        "sidecar_profile": arkret_sdk::PROFILE_AGENT_SIDECAR_THREAD,
        "controller_id": controller,
        "normalized_context_ref_digest": normalized_context_ref_digest,
    });
    if let Some(track_name) = track_name
        && let Some(object) = fields.as_object_mut()
    {
        object.insert(
            "context_track_name".to_owned(),
            Value::String(track_name.to_owned()),
        );
    }
    let payload = json!({
        "relation": {
            "id": relation_id,
            "kind": "agent_sidecar_of",
            "from_ref": private_strand_id,
            "to_ref": target_ref,
            "scope_circle_id": circle_id,
            "fields": fields,
            "created_by": controller,
        }
    });
    let operation = new_sidecar_operation(
        realm_id,
        arkret_sdk::events::kinds::RELATION_CREATE,
        payload,
    )?;
    accept_local_operations(state, controller, std::slice::from_ref(&operation))
        .await
        .map_err(sidecar_reducer_reject_to_app_error)?;
    find_sidecar_relation(
        state,
        realm_id.as_str(),
        circle_id.as_str(),
        private_strand_id.as_str(),
        target_ref,
    )
    .ok_or_else(|| AppError::internal("sidecar Relation accepted but not projected"))
}

pub(super) async fn ensure_sidecar_thread_impl(
    aa: AuthArgs,
    body: AgentSidecarThreadEnsureRequestBody,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AgentSidecarThreadEnsureOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    ensure_sidecar_controller_request(&body, &session)?;
    let controller = body.controller_id.as_str();
    let realm_id = body.context_ref.realm_id.clone();
    authorize_sidecar_ensure(state, controller, realm_id.as_str()).await?;
    let normalized_context_ref = normalize_sidecar_context_ref(&body.context_ref)?;
    validate_sidecar_context_projection(state, &body.context_ref)?;
    let normalized_context_ref_digest =
        arkret_sdk::canonical::canonical_sha256(&normalized_context_ref)
            .map_err(|err| AppError::internal(format!("context_ref digest failed: {err}")))?;
    let target_ref = sidecar_context_target_ref(&body.context_ref);
    let addressed_agents = normalize_addressed_agents(controller, &body)?;
    tracing::info!(
        controller_id = controller,
        realm_id = %realm_id,
        target_ref = %target_ref,
        addressed_agent_count = addressed_agents.len(),
        normalized_context_ref_digest = %normalized_context_ref_digest,
        "agent sidecar ensure request validated"
    );
    let eligible_agents =
        eligible_sidecar_agents(state, realm_id.as_str(), controller, &addressed_agents).await?;
    let controller_agent_circle_key = controller_agent_circle_key(realm_id.as_str(), controller);
    let short_name = sidecar_short_name(&controller_agent_circle_key);
    let private_circle_id = ensure_sidecar_circle(
        state,
        controller,
        &realm_id,
        &controller_agent_circle_key,
        &short_name,
    )
    .await?;
    ensure_sidecar_member(state, controller, &realm_id, &private_circle_id, controller).await?;
    for agent in &eligible_agents {
        ensure_sidecar_member(state, controller, &realm_id, &private_circle_id, agent).await?;
    }
    let private_strand_id = ensure_sidecar_strand(
        state,
        controller,
        &realm_id,
        &private_circle_id,
        &normalized_context_ref,
        &normalized_context_ref_digest,
    )
    .await?;
    let private_relation_id = ensure_sidecar_relation(
        state,
        controller,
        &realm_id,
        &private_circle_id,
        &private_strand_id,
        &target_ref,
        &normalized_context_ref_digest,
        body.context_ref.track_name.as_deref(),
    )
    .await?;
    tracing::info!(
        controller_id = controller,
        realm_id = %realm_id,
        private_circle_id = %private_circle_id,
        private_strand_id = %private_strand_id,
        private_relation_id = %private_relation_id,
        eligible_agent_count = eligible_agents.len(),
        "agent sidecar ensure completed"
    );
    append_audit_log(
        state,
        Some(&session.actor),
        "ak.self.agent.sidecar_thread.command.ensure",
        json!({
            "controller_id": body.controller_id,
            "addressed_agent_ids": addressed_agents,
            "context_ref": normalized_context_ref,
            "normalized_context_ref_digest": normalized_context_ref_digest,
            "private_circle_id": private_circle_id,
            "private_strand_id": private_strand_id,
            "private_relation_id": private_relation_id,
        }),
        "accepted",
    )
    .await;
    json_ok(AgentSidecarThreadEnsureOutcome {
        ok: true,
        private_circle_id,
        private_strand_id,
        private_relation_id,
        pending_member_reconciliations: Vec::new(),
    })
}

#[endpoint(
    operation_id = "ak.self.agent.sidecar_thread.command.ensure",
    tags("agents"),
    summary = "Idempotently ensure the controller<->agent sidecar Circle exists",
    status_codes(200, 201, 400, 401, 403, 500)
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.agent.sidecar_thread.command.ensure"))]
pub(super) async fn ensure_sidecar_thread_canonical(
    aa: AuthArgs,
    body: JsonBody<AgentSidecarThreadEnsureRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AgentSidecarThreadEnsureOutcome> {
    ensure_sidecar_thread_impl(aa, body.into_inner(), depot, req).await
}
