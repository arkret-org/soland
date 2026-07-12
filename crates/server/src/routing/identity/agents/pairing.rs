use super::*;

#[endpoint(
    operation_id = "ak.open.agent_pairing.query.resolve",
    tags("open"),
    summary = "Resolve a short-lived agent pairing token"
)]
#[tracing::instrument(skip_all, fields(op = "ak.open.agent_pairing.query.resolve"))]
pub(super) async fn resolve_agent_pairing(
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AgentPairingBootstrap> {
    if agent_pairing_token_appears_in_url(req) {
        return Err(AppError::invalid_param(
            "pairing_token must be sent in the JSON body, never in URL path or query",
        )
        .with_status(StatusCode::BAD_REQUEST)
        .with_wire_code("schema_violation"));
    }
    let state = depot.get_typed::<AppState>().expect("state injected");
    let body = req
        .parse_json::<AgentPairingResolveRequestBody>()
        .await
        .map_err(|_| AppError::bad_json("invalid agent pairing resolve request body"))?;
    let pairing_token = body.pairing_token.trim();
    if !is_agent_pairing_token_shape(pairing_token) {
        return Err(agent_pairing_not_found());
    }
    let token = decode_agent_pairing_token(pairing_token).ok_or_else(agent_pairing_not_found)?;
    let pairing_request_id = token
        .get("r")
        .or_else(|| token.get("pairing_request_id"))
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(agent_pairing_not_found)?;
    let pairing_code = token
        .get("c")
        .or_else(|| token.get("pairing_code"))
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(agent_pairing_not_found)?;
    let record = lookup_pairing_record(state, pairing_request_id, pairing_code, None).await?;
    ensure_pairing_request_open(&record).map_err(|_| agent_pairing_not_found())?;
    let agent_id = pairing_record_string(&record, "agent_id")?;
    let pairing_expires_at = pairing_record_timestamp(&record, "pairing_expires_at")?;
    let bootstrap = AgentPairingBootstrap {
        arkret_base_url: state
            .config
            .public_base_url
            .trim_end_matches('/')
            .to_owned(),
        service_id: Did::new(state.config.service_id.clone()).map_err(|error| {
            AppError::internal(format!("configured service_id invalid: {error}"))
        })?,
        agent_id: Did::new(agent_id)
            .map_err(|error| AppError::internal(format!("agent principal DID invalid: {error}")))?,
        pairing_request_id: pairing_request_id.to_owned(),
        pairing_code: pairing_code.to_owned(),
        pairing_expires_at,
    };
    json_ok(bootstrap)
}

#[endpoint(
    operation_id = "ak.open.agent_pairing.command.submit_runtime_key_request",
    tags("open"),
    summary = "Submit an agent runtime key request for controller approval"
)]
#[tracing::instrument(
    skip_all,
    fields(op = "ak.open.agent_pairing.command.submit_runtime_key_request")
)]
pub(super) async fn submit_agent_runtime_key_request(
    body: JsonBody<AgentRuntimeApprovalRequestBody>,
    depot: &mut Depot,
) -> JsonResult<AgentRuntimeApprovalOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let body = body.into_inner();
    let pairing_code = body.pairing_code.trim();
    if pairing_code.is_empty() {
        return Err(AppError::invalid_param("pairing_code is required"));
    }
    let agent_id = body.agent_id.as_str();
    validate_agent_id(agent_id)?;
    if body.verification_method.trim().is_empty() {
        return Err(AppError::invalid_param("verification_method is required"));
    }
    if verification_method_principal(&body.verification_method) != agent_id {
        return Err(AppError::invalid_param(
            "verification_method DID must match agent_id",
        ));
    }
    let mut agent_record = lookup_pairing_record(
        state,
        &body.pairing_request_id,
        pairing_code,
        Some(agent_id),
    )
    .await?;
    ensure_pairing_request_open(&agent_record)?;
    ensure_pairing_request_id_matches(&agent_record, &body.pairing_request_id)?;
    let key_pair_body = agent_key_pair_body_from_runtime_approval(&body);
    verify_runtime_key_pair_proof_of_possession(
        &key_pair_body,
        agent_id,
        &state.config.service_id,
    )?;
    if let Some(attestation) = body.runtime_attestation.as_ref() {
        let kind = attestation
            .get("kind")
            .and_then(Value::as_str)
            .unwrap_or_default();
        return Err(AppError::unsupported_feature(format!(
            "runtime_attestation verifier is not wired; refusing kind `{kind}` fail-closed"
        )));
    }

    let approval_request_id = format!("agent_runtime_approval:{}", uuid::Uuid::now_v7());
    let requested_at = chrono::Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true);
    if let Some(object) = agent_record.as_object_mut() {
        object.insert(
            "approval_request_id".to_owned(),
            json!(approval_request_id.clone()),
        );
        object.insert(
            "runtime_key_request".to_owned(),
            runtime_key_request_for_controller(&body),
        );
        object.insert("approval_requested_at".to_owned(), json!(requested_at));
    }
    state
        .persistence
        .agents()
        .put(agent_record)
        .await
        .map_err(|err| {
            AppError::internal(format!("runtime approval request save failed: {err}"))
        })?;
    json_ok(AgentRuntimeApprovalOutcome {
        ok: true,
        approval_request_id,
        status: AgentStatus::PendingRuntimeKey,
    })
}

#[endpoint(
    operation_id = "ak.open.agent_pairing.query.runtime_key_request_status",
    tags("open"),
    summary = "Poll the controller decision for a submitted runtime key request"
)]
#[tracing::instrument(
    skip_all,
    fields(op = "ak.open.agent_pairing.query.runtime_key_request_status")
)]
pub(super) async fn agent_runtime_key_request_status(
    body: JsonBody<AgentRuntimeApprovalStatusRequestBody>,
    depot: &mut Depot,
) -> JsonResult<AgentRuntimeApprovalStatusOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let body = body.into_inner();
    let agent_record = lookup_pairing_record(
        state,
        &body.pairing_request_id,
        &body.pairing_code,
        Some(body.agent_id.as_str()),
    )
    .await?;
    json_ok(agent_runtime_key_request_status_outcome(
        &agent_record,
        &body,
        chrono::Utc::now(),
    )?)
}

/// Resolve the private pairing credential tuple without revealing which
/// component failed. Endpoint-specific lifecycle checks remain at the caller.
async fn lookup_pairing_record(
    state: &AppState,
    pairing_request_id: &str,
    pairing_code: &str,
    agent_id: Option<&str>,
) -> Result<Value, AppError> {
    if pairing_request_id.trim().is_empty() || pairing_code.trim().is_empty() {
        return Err(agent_pairing_not_found());
    }
    let record = state
        .persistence
        .agents()
        .get_by_pairing_request_id(pairing_request_id)
        .await
        .map_err(|err| AppError::internal(format!("agent pairing lookup failed: {err}")))?
        .ok_or_else(agent_pairing_not_found)?;
    if record.get("pairing_code").and_then(Value::as_str) != Some(pairing_code)
        || agent_id.is_some_and(|expected| {
            record.get("agent_id").and_then(Value::as_str) != Some(expected)
        })
    {
        return Err(agent_pairing_not_found());
    }
    Ok(record)
}

/// Pure decision core for the open runtime-key-request status poll.
///
/// Anti-enumeration: a record miss and a `pairing_code` /
/// `agent_id` mismatch are indistinguishable — every mismatch maps
/// to the same not_found as an unknown `pairing_request_id`. An open pairing
/// whose `pairing_expires_at` has passed is reported as `pairing_expired`
/// without waiting for the lazy-expiry write.
pub(super) fn agent_runtime_key_request_status_outcome(
    agent_record: &Value,
    body: &AgentRuntimeApprovalStatusRequestBody,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<AgentRuntimeApprovalStatusOutcome, AppError> {
    let pairing_code = body.pairing_code.trim();
    if pairing_code.is_empty() {
        return Err(agent_pairing_not_found());
    }
    if agent_record.get("pairing_code").and_then(Value::as_str) != Some(pairing_code) {
        return Err(agent_pairing_not_found());
    }
    if agent_record.get("agent_id").and_then(Value::as_str) != Some(body.agent_id.as_str()) {
        return Err(agent_pairing_not_found());
    }
    let status = match agent_record.get("state").and_then(Value::as_str) {
        Some("pending_runtime_key") => {
            let expired = pairing_record_timestamp(agent_record, "pairing_expires_at")
                .map(|expires_at| expires_at <= now)
                .unwrap_or(true);
            if expired {
                AgentStatus::PairingExpired
            } else {
                AgentStatus::PendingRuntimeKey
            }
        }
        Some("active") => AgentStatus::Active,
        Some("paused") => AgentStatus::Paused,
        Some("deactivated") => AgentStatus::Deactivated,
        Some("pairing_expired") => AgentStatus::PairingExpired,
        _ => return Err(agent_pairing_not_found()),
    };
    let record_string = |key: &str| {
        agent_record
            .get(key)
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .map(ToOwned::to_owned)
    };
    let approval_request_id = if status == AgentStatus::PendingRuntimeKey {
        record_string("approval_request_id")
    } else {
        None
    };
    let authorized_event_ref = record_string("authorized_event_ref")
        .map(EventId::new)
        .transpose()
        .map_err(|err| AppError::internal(format!("authorized event ref invalid: {err}")))?;
    Ok(AgentRuntimeApprovalStatusOutcome {
        ok: true,
        status,
        approval_request_id,
        authorized_event_ref,
        authorized_verification_method: record_string("authorized_verification_method"),
        authorized_public_key_digest: record_string("authorized_public_key_digest"),
    })
}

/// AKP-0008 (dev option B) — synthesize a controller-authored
/// `SessionRecord` so the server-side fan-out can author durable sub-events
/// as the controller (`actor_id == session.actor`). Only used under
/// `development_mode`; the resulting session is never persisted or returned.
#[endpoint(
    operation_id = "ak.gate.account.command.pair_agent_key",
    tags("agents"),
    summary = "Authorize an agent runtime key pair against the agent principal",
    status_codes(200, 400, 401, 403, 500)
)]
#[tracing::instrument(skip_all, fields(op = "ak.gate.account.command.pair_agent_key"))]
pub(super) async fn agent_key_pair(
    aa: AuthArgs,
    body: JsonBody<AgentKeyPairRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AgentKeyPairOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let body = body.into_inner();
    let agent_id = body.agent_id.as_str();
    validate_agent_id(agent_id)?;
    if body.verification_method.trim().is_empty() {
        return Err(AppError::invalid_param("verification_method is required"));
    }
    if verification_method_principal(&body.verification_method) != agent_id {
        return Err(AppError::invalid_param(
            "verification_method DID must match agent_id",
        ));
    }
    let agent_record = require_agent_controller(state, &session, agent_id).await?;
    ensure_pairing_request_open(&agent_record)?;
    ensure_pairing_request_id_matches(&agent_record, &body.pairing_request_id)?;
    let runtime_public_key_digest =
        runtime_public_key_digest(&body.public_key, &body.verification_method)?;
    verify_runtime_key_pair_proof_of_possession(&body, agent_id, &state.config.service_id)?;
    // The runtime-attestation verifier is not wired yet. Refuse every
    // supplied attestation fail-closed instead of accepting a shape-only
    // `self_asserted` placeholder as if it were a verified binding.
    if let Some(attestation) = body.runtime_attestation.as_ref() {
        let kind = attestation
            .get("kind")
            .and_then(Value::as_str)
            .unwrap_or_default();
        return Err(AppError::unsupported_feature(format!(
            "runtime_attestation verifier is not wired; refusing kind `{kind}` fail-closed"
        )));
    }
    let authorized_at = chrono::Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true);
    // AKP-0008 §4.5 / D3: the runtime key may become active only after a
    // reducer-visible `ak.agent.key.authorize` event exists. Development mode
    // still materializes the event with the local dev-proof path; production
    // requires inkson/coauth to provide a controller-signed durable event and
    // soland submits + rechecks it here.
    let event_id = if state.config.development_mode {
        let controller_session = controller_dev_session(&session.actor, state);
        let realm = ensure_self_realm(state, &controller_session).await?;
        // Snapshot the keys authorized before this pairing: on runtime
        // replacement re-pairing every prior active key is superseded in the
        // same accepted fan-out batch (key-management.md §3.6.1).
        let prior_key_ids = {
            let proj = state.projection.lock();
            proj.authorized_key_ids_for(agent_id)
        };
        let key_id = dev_fanout::agent_key_id_for_pairing(agent_id, &body.verification_method);
        let event_id = submit_durable_key_authorize(
            state,
            &controller_session,
            &realm,
            agent_id,
            &body.verification_method,
            &key_id,
        )
        .await?;
        let superseded: Vec<String> = prior_key_ids
            .into_iter()
            .filter(|prior| prior != &key_id)
            .collect();
        if !superseded.is_empty() {
            dev_fanout::submit_revoke_agent_keys(
                state,
                &controller_session,
                &realm,
                agent_id,
                &superseded,
                Some(arkret_wire_base::error_codes::REASON_SUPERSEDED_BY_REPAIRING),
            )
            .await?;
        }
        event_id
    } else {
        submit_production_key_authorize_event(
            state,
            &session,
            &body.authorize_event,
            &agent_record,
            agent_id,
            &body.verification_method,
            &runtime_public_key_digest,
        )
        .await?
    };
    let authorized_event_ref = EventId::new(event_id)
        .map_err(|err| AppError::internal(format!("authorize event id invalid: {err}")))?;
    // Pairing semantics: a provisioned agent starts `pending_runtime_key`;
    // flip to `active` ONLY after the durable key authorization has been
    // accepted (a failed submit above propagates via `?` and MUST NOT leave
    // the agent flipped to active).
    let mut updated_record = agent_record;
    if let Some(object) = updated_record.as_object_mut() {
        object.insert("state".to_owned(), json!("active"));
        object.insert("updated_at".to_owned(), json!(authorized_at));
        object.insert(
            "authorized_event_ref".to_owned(),
            json!(authorized_event_ref.as_str()),
        );
        // Retained so the open runtime-key-request status poll can hand the
        // runtime the exact key binding the controller approved; a polling
        // runtime whose key digest differs must treat the pairing as taken
        // by another runtime.
        object.insert(
            "authorized_verification_method".to_owned(),
            json!(body.verification_method),
        );
        object.insert(
            "authorized_public_key_digest".to_owned(),
            json!(runtime_public_key_digest),
        );
        // Consume the one-time pairing handle: a subsequent pair attempt on the
        // now-active agent is rejected until renew_pairing installs a fresh
        // `pairing_request_id` (runtime replacement re-pairing, §3.6.1).
        object.insert(
            "paired_pairing_request_id".to_owned(),
            json!(body.pairing_request_id),
        );
        object.remove("approval_request_id");
        object.remove("runtime_key_request");
        object.remove("approval_requested_at");
    }
    state
        .persistence
        .agents()
        .put(updated_record)
        .await
        .map_err(|err| AppError::internal(format!("agent state activation failed: {err}")))?;
    json_ok(AgentKeyPairOutcome {
        ok: true,
        authorized_event_ref,
    })
}

pub(super) async fn submit_production_key_authorize_event(
    state: &AppState,
    session: &SessionRecord,
    envelope: &Value,
    agent_record: &Value,
    agent_id: &str,
    verification_method: &str,
    runtime_public_key_digest: &str,
) -> Result<String, AppError> {
    ensure_key_authorize_event_matches_request(
        envelope,
        &session.actor,
        agent_record,
        agent_id,
        verification_method,
        runtime_public_key_digest,
        &state.config.service_id,
    )?;
    let outcome = submit_event_value(state, session, envelope.clone())
        .await
        .map_err(|error| {
            AppError::invalid_param(format!(
                "ak.agent.key.authorize submit failed: {}",
                error.message
            ))
            .with_status(error.status)
            .with_wire_code(error.code)
        })?;
    Ok(outcome.event_id)
}

pub(super) fn ensure_key_authorize_event_matches_request(
    envelope: &Value,
    controller: &str,
    agent_record: &Value,
    agent_id: &str,
    verification_method: &str,
    runtime_public_key_digest: &str,
    service_id: &str,
) -> Result<(), AppError> {
    if envelope.get("kind").and_then(Value::as_str) != Some("ak.agent.key.authorize") {
        return Err(AppError::invalid_param(
            "authorize_event.kind must be ak.agent.key.authorize",
        ));
    }
    if envelope.get("actor_id").and_then(Value::as_str) != Some(controller) {
        return Err(AppError::capability_denied(
            "authorize_event.actor_id must match the authenticated controller",
        ));
    }
    let payload = envelope
        .get("payload")
        .ok_or_else(|| AppError::invalid_param("authorize_event.payload is required"))?;
    if payload.get("agent_id").and_then(Value::as_str) != Some(agent_id) {
        return Err(AppError::invalid_param(
            "authorize_event.payload.agent_id must match the pairing request",
        ));
    }
    if payload.get("verification_method").and_then(Value::as_str) != Some(verification_method) {
        return Err(AppError::invalid_param(
            "authorize_event.payload.verification_method must match the pairing request",
        ));
    }
    if payload
        .get("accountable_principal_id")
        .and_then(Value::as_str)
        != Some(controller)
    {
        return Err(AppError::capability_denied(
            "authorize_event.payload.accountable_principal_id must match the authenticated controller",
        ));
    }
    ensure_authorize_event_scope_matches_requested(agent_record, payload)?;
    let audience = payload
        .get("audience")
        .and_then(Value::as_array)
        .ok_or_else(|| AppError::invalid_param("authorize_event.payload.audience is required"))?;
    if !audience
        .iter()
        .any(|value| value.as_str() == Some(service_id))
    {
        return Err(AppError::invalid_param(
            "authorize_event.payload.audience must include this principal server",
        ));
    }
    let expires_at = payload
        .get("expires_at")
        .and_then(Value::as_str)
        .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
        .ok_or_else(|| {
            AppError::invalid_param("authorize_event.payload.expires_at must be rfc3339")
        })?;
    if expires_at.with_timezone(&chrono::Utc) <= chrono::Utc::now() {
        return Err(pairing_failed_precondition(
            "authorize_event payload has expired",
        ));
    }
    if payload.get("public_key_digest").and_then(Value::as_str) != Some(runtime_public_key_digest) {
        return Err(AppError::invalid_param(
            "authorize_event.payload.public_key_digest must bind the runtime public_key",
        ));
    }
    let expected_digest = pairing_request_binding_digest(
        agent_record,
        controller,
        agent_id,
        verification_method,
        runtime_public_key_digest,
        service_id,
    )?;
    let approval_evidence = payload.get("approval_evidence").ok_or_else(|| {
        AppError::invalid_param("authorize_event.payload.approval_evidence is required")
    })?;
    if approval_evidence.get("kind").and_then(Value::as_str) != Some("pairing_request") {
        return Err(AppError::invalid_param(
            "authorize_event.payload.approval_evidence.kind must be pairing_request",
        ));
    }
    if approval_evidence.get("evidence_ref").is_some() {
        return Err(AppError::invalid_param(
            "authorize_event.payload.approval_evidence.ref must be absent for pairing_request evidence",
        ));
    }
    let pairing_request_id = pairing_record_string(agent_record, "pairing_request_id")?;
    if approval_evidence
        .get("pairing_request_id")
        .and_then(Value::as_str)
        != Some(pairing_request_id)
    {
        return Err(AppError::invalid_param(
            "authorize_event.payload.approval_evidence.pairing_request_id must match the pairing request",
        ));
    }
    if approval_evidence
        .get("request_canonical_digest")
        .and_then(Value::as_str)
        != Some(expected_digest.as_str())
    {
        return Err(AppError::invalid_param(
            "authorize_event.payload.approval_evidence.request_canonical_digest must bind the pairing request",
        ));
    }
    Ok(())
}

pub(super) fn ensure_pairing_request_open(agent_record: &Value) -> Result<(), AppError> {
    match agent_record.get("state").and_then(Value::as_str) {
        Some("pending_runtime_key") => {}
        Some("pairing_expired") => {
            return Err(pairing_failed_precondition("pairing request has expired"));
        }
        Some("active" | "paused") => {
            // Runtime replacement re-pairing (key-management.md §3.6.1): an
            // agent that already holds an authorized key MAY re-open pairing
            // in place (status unchanged, zero downtime); completing the fresh
            // handle supersedes every old active key. renew_pairing rotates
            // `pairing_request_id` while leaving the last consumed handle in
            // `paired_pairing_request_id`, so a live replacement handle exists
            // iff the current handle has not yet been consumed. Without one,
            // there is nothing to complete.
            if !agent_pairing_handle_is_open(agent_record) {
                return Err(pairing_failed_precondition(
                    "agent runtime key is already active",
                ));
            }
        }
        Some("deactivated") => {
            return Err(pairing_failed_precondition(
                "agent is not accepting runtime key pairing",
            ));
        }
        _ => {
            return Err(pairing_failed_precondition(
                "agent pairing state is not pending_runtime_key",
            ));
        }
    }
    let expires_at = pairing_record_timestamp(agent_record, "pairing_expires_at")?;
    if expires_at <= chrono::Utc::now() {
        return Err(pairing_failed_precondition("pairing request has expired"));
    }
    Ok(())
}

/// Whether the agent record carries an unconsumed pairing handle. The
/// completion transaction stamps `paired_pairing_request_id` with the handle
/// it consumed; renew_pairing installs a fresh `pairing_request_id` without
/// touching that stamp. A current handle that differs from the last consumed
/// one is therefore a live, single-use pairing handle.
fn agent_pairing_handle_is_open(agent_record: &Value) -> bool {
    let current = agent_record
        .get("pairing_request_id")
        .and_then(Value::as_str);
    let consumed = agent_record
        .get("paired_pairing_request_id")
        .and_then(Value::as_str);
    current.is_some() && current != consumed
}

pub(super) fn agent_record_reserves_selector_slug(
    agent_record: &Value,
    now: &chrono::DateTime<chrono::Utc>,
) -> bool {
    match agent_record.get("state").and_then(Value::as_str) {
        Some("active" | "paused") => true,
        Some("pending_runtime_key") => agent_record
            .get("pairing_expires_at")
            .and_then(Value::as_str)
            .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
            .map(|expires_at| expires_at.with_timezone(&chrono::Utc) > now.clone())
            .unwrap_or(true),
        Some("pairing_expired" | "deactivated") => false,
        _ => true,
    }
}

pub(super) fn ensure_pairing_request_id_matches(
    agent_record: &Value,
    supplied_pairing_request_id: &str,
) -> Result<(), AppError> {
    let expected = pairing_record_string(agent_record, "pairing_request_id")?;
    if expected != supplied_pairing_request_id {
        return Err(pairing_failed_precondition(
            "pairing_request_id does not match the open pairing request",
        ));
    }
    Ok(())
}

pub(super) fn agent_key_pair_body_from_runtime_approval(
    body: &AgentRuntimeApprovalRequestBody,
) -> AgentKeyPairRequestBody {
    AgentKeyPairRequestBody {
        pairing_request_id: body.pairing_request_id.clone(),
        agent_id: body.agent_id.clone(),
        verification_method: body.verification_method.clone(),
        public_key: body.public_key.clone(),
        proof_of_possession: body.proof_of_possession.clone(),
        runtime_attestation: body.runtime_attestation.clone(),
        authorize_event: Value::Null,
    }
}

pub(super) fn runtime_key_request_for_controller(body: &AgentRuntimeApprovalRequestBody) -> Value {
    json!({
        "pairing_request_id": body.pairing_request_id.clone(),
        "agent_id": body.agent_id.clone(),
        "verification_method": body.verification_method.clone(),
        "public_key": body.public_key.clone(),
        "proof_of_possession": body.proof_of_possession.clone(),
        "runtime_attestation": body.runtime_attestation.clone(),
    })
}

#[derive(serde::Deserialize)]
struct AgentKeyPairProofOfPossession {
    challenge: String,
    audience: String,
    request_canonical_digest: String,
    expires_at: chrono::DateTime<chrono::Utc>,
    signature: String,
}

pub(super) fn runtime_ed25519_public_key(
    public_key: &Value,
    verification_method: &str,
) -> Result<[u8; 32], AppError> {
    let key: PublicKey = serde_json::from_value(public_key.clone())
        .map_err(|error| AppError::invalid_param(format!("public_key invalid: {error}")))?;
    if key.kty != "OKP" {
        return Err(AppError::invalid_param("public_key.kty must be OKP"));
    }
    if key.alg != "Ed25519" && key.alg != "EdDSA" {
        return Err(AppError::invalid_param(
            "public_key.alg must be Ed25519 or EdDSA",
        ));
    }
    if key.kid != verification_method {
        return Err(AppError::invalid_param(
            "public_key.kid must match verification_method",
        ));
    }
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(key.key.as_bytes())
        .map_err(|_| AppError::invalid_param("public_key.key is not base64url"))?;
    bytes
        .try_into()
        .map_err(|_| AppError::invalid_param("public_key.key must be a 32-byte Ed25519 key"))
}

pub(super) fn verify_runtime_key_pair_proof_of_possession(
    body: &AgentKeyPairRequestBody,
    agent_id: &str,
    service_id: &str,
) -> Result<(), AppError> {
    let agent_id = Did::new(agent_id.to_owned())
        .map_err(|error| AppError::invalid_param(format!("agent_id invalid: {error}")))?;
    let public_key_bytes = runtime_ed25519_public_key(&body.public_key, &body.verification_method)?;
    let proof: AgentKeyPairProofOfPossession =
        serde_json::from_value(body.proof_of_possession.clone()).map_err(|error| {
            AppError::invalid_param(format!("proof_of_possession invalid: {error}"))
        })?;
    if proof.audience != service_id {
        return Err(AppError::invalid_param(
            "proof_of_possession.audience must match this principal server",
        ));
    }
    if proof.expires_at <= chrono::Utc::now() {
        return Err(pairing_failed_precondition(
            "proof_of_possession has expired",
        ));
    }
    let expected_digest = arkret_sdk::agent_key_pair_proof_request_binding_digest(
        &body.pairing_request_id,
        &agent_id,
        &body.verification_method,
        &body.public_key,
        body.runtime_attestation.as_ref(),
    )
    .map_err(|error| {
        AppError::invalid_param(format!(
            "proof_of_possession request binding failed: {error}"
        ))
    })?;
    if proof.request_canonical_digest != expected_digest.as_str() {
        return Err(AppError::invalid_param(
            "proof_of_possession.request_canonical_digest must bind the runtime key request",
        ));
    }
    let request_digest = Hash::new(proof.request_canonical_digest.clone())
        .map_err(|_| AppError::invalid_param("proof_of_possession digest is invalid"))?;
    let signing_input = arkret_sdk::agent::agent_key_pair_proof_signing_input(
        body.verification_method.clone(),
        proof.challenge,
        proof.audience,
        proof.expires_at,
        request_digest,
    );
    let signing_bytes = signing_input.canonical_bytes().map_err(|error| {
        AppError::invalid_param(format!("proof_of_possession signing input failed: {error}"))
    })?;
    let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&public_key_bytes)
        .map_err(|error| AppError::invalid_param(format!("public_key invalid: {error}")))?;
    let signature_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(proof.signature.as_bytes())
        .map_err(|_| AppError::invalid_param("proof_of_possession.signature is not base64url"))?;
    let signature = ed25519_dalek::Signature::from_slice(&signature_bytes).map_err(|_| {
        AppError::invalid_param("proof_of_possession.signature must be a 64-byte Ed25519 signature")
    })?;
    verifying_key
        .verify(&signing_bytes, &signature)
        .map_err(|_| AppError::invalid_param("proof_of_possession.signature is invalid"))?;
    Ok(())
}

pub(super) fn pairing_failed_precondition(reason: &'static str) -> AppError {
    AppError::new(ErrorCode::FailedPrecondition, reason)
        .with_status(StatusCode::PRECONDITION_FAILED)
        .with_reason_detail(reason)
}

pub(super) fn pairing_record_string<'a>(record: &'a Value, key: &str) -> Result<&'a str, AppError> {
    record
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| {
            pairing_failed_precondition("agent pairing metadata is incomplete")
                .with_reason_detail(format!("missing {key}"))
        })
}

pub(super) fn pairing_record_timestamp(
    record: &Value,
    key: &str,
) -> Result<chrono::DateTime<chrono::Utc>, AppError> {
    let value = pairing_record_string(record, key)?;
    chrono::DateTime::parse_from_rfc3339(value)
        .map(|timestamp| timestamp.with_timezone(&chrono::Utc))
        .map_err(|_| AppError::invalid_param(format!("agent pairing metadata {key} is invalid")))
}

pub(super) fn runtime_public_key_digest(
    public_key: &Value,
    verification_method: &str,
) -> Result<String, AppError> {
    runtime_ed25519_public_key(public_key, verification_method)?;
    arkret_sdk::agent_runtime_public_key_digest(public_key)
        .map(|digest| digest.as_str().to_owned())
        .map_err(|error| AppError::invalid_param(format!("public_key is invalid: {error}")))
}

pub(super) fn ensure_authorize_event_scope_matches_requested(
    agent_record: &Value,
    payload: &Value,
) -> Result<(), AppError> {
    let scope = payload.get("agent_key_scope").ok_or_else(|| {
        AppError::invalid_param("authorize_event.payload.agent_key_scope is required")
    })?;
    let actions = scope
        .get("actions")
        .and_then(Value::as_array)
        .filter(|actions| !actions.is_empty())
        .ok_or_else(|| {
            AppError::invalid_param("authorize_event.payload.agent_key_scope.actions is required")
        })?;
    if actions
        .iter()
        .any(|action| action.as_str().is_none_or(str::is_empty))
    {
        return Err(AppError::invalid_param(
            "authorize_event.payload.agent_key_scope.actions must be non-empty strings",
        ));
    }
    if let Some(expected) = agent_record
        .get("requested_scope")
        .filter(|value| !value.is_null())
        && scope != expected
    {
        return Err(AppError::invalid_param(
            "authorize_event.payload.agent_key_scope must match the provisioned requested_scope",
        ));
    }
    Ok(())
}

pub(super) fn pairing_request_binding_digest(
    agent_record: &Value,
    controller: &str,
    agent_id: &str,
    verification_method: &str,
    runtime_public_key_digest: &str,
    service_id: &str,
) -> Result<String, AppError> {
    let pairing_request_id = pairing_record_string(agent_record, "pairing_request_id")?;
    let pairing_code = pairing_record_string(agent_record, "pairing_code")?;
    let expires_at = pairing_record_string(agent_record, "pairing_expires_at")?;
    let controller = Did::new(controller.to_owned())
        .map_err(|error| AppError::invalid_param(format!("controller DID invalid: {error}")))?;
    let agent_id = Did::new(agent_id.to_owned())
        .map_err(|error| AppError::invalid_param(format!("agent DID invalid: {error}")))?;
    let runtime_public_key_digest = Hash::new(runtime_public_key_digest.to_owned())
        .map_err(|_| AppError::invalid_param("runtime_public_key_digest is invalid"))?;
    arkret_sdk::agent_key_pairing_request_binding_digest(
        &controller,
        &agent_id,
        verification_method,
        &runtime_public_key_digest,
        pairing_request_id,
        pairing_code,
        expires_at,
        service_id,
    )
    .map(|digest| digest.as_str().to_owned())
    .map_err(|error| {
        AppError::internal(format!(
            "pairing binding digest canonicalization failed: {error}"
        ))
    })
}

/// Generate a short human-relayable pairing code for the provision
/// outcome (`agent_provision_outcome.pairing_code`). 8 decimal digits
/// from the OS CSPRNG.
pub(super) fn generate_pairing_code() -> String {
    use rand::RngExt;
    let mut buf = [0u8; 4];
    rand::rng().fill(&mut buf);
    format!("{:08}", u32::from_be_bytes(buf) % 100_000_000)
}

pub(super) fn agent_pairing_token_appears_in_url(req: &Request) -> bool {
    req.uri().query().is_some_and(|query| {
        query.contains("pairing_token=")
            || query.contains("pairing_request_id=")
            || query.contains("token=")
    })
}

pub(super) fn is_agent_pairing_token_shape(value: &str) -> bool {
    (22..=512).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

pub(super) fn decode_agent_pairing_token(pairing_token: &str) -> Option<Value> {
    let bytes = URL_SAFE_NO_PAD.decode(pairing_token.as_bytes()).ok()?;
    serde_json::from_slice::<Value>(&bytes).ok()
}

pub(super) fn agent_pairing_not_found() -> AppError {
    AppError::not_found("agent pairing token not found")
}
