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
    let agent_id = record.id.as_str();
    let pairing_expires_at = required_pairing_expires_at(&record)?;
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
    let agent_record = lookup_pairing_record(
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
    let agent_did = Did::new(agent_id.to_owned())
        .map_err(|error| AppError::invalid_param(format!("agent_id invalid: {error}")))?;
    let public_key_digest = arkret_sdk::agent_runtime_public_key_digest(&body.public_key)
        .map_err(|error| AppError::invalid_param(format!("public_key invalid: {error}")))?;
    let runtime_attestation = runtime_attestation_value(body.runtime_attestation.as_ref())?;
    let attestation_digest = arkret_sdk::agent_runtime_attestation_digest(
        runtime_attestation.as_ref(),
    )
    .map_err(|error| AppError::invalid_param(format!("runtime_attestation invalid: {error}")))?;
    let binding_digest = arkret_sdk::agent_runtime_key_binding_digest_from_digests(
        &agent_did,
        &body.pairing_request_id,
        &body.verification_method,
        &public_key_digest,
        &attestation_digest,
    )
    .map_err(|error| AppError::invalid_param(format!("runtime key binding invalid: {error}")))?;
    let existing_binding = agent_record.runtime_key_binding_digest.as_deref();
    if existing_binding.is_some_and(|existing| existing != binding_digest.as_str()) {
        return Err(AppError::new(
            ErrorCode::Conflict,
            "a different runtime key binding is already pending for this pairing request",
        )
        .with_status(StatusCode::CONFLICT)
        .with_wire_code("agent_runtime_request_conflict"));
    }

    let controller_id = agent_record.controller_id.clone();
    let account = state
        .persistence
        .accounts()
        .get(&controller_id)
        .await
        .map_err(|error| AppError::internal(format!("controller account lookup failed: {error}")))?
        .ok_or_else(|| AppError::internal("controller account is missing"))?;
    let proposed_approval_request_id = agent_record
        .approval_request_id
        .clone()
        .unwrap_or_else(|| format!("agent_runtime_approval:{}", uuid::Uuid::now_v7()));
    let proposed_notification_id = agent_record
        .approval_notification_id
        .map(|id| ids::format_typed_uuid("notification", &id))
        .unwrap_or_else(|| ids::generate("notification"));
    let proposed_requested_at = agent_record
        .approval_requested_at
        .unwrap_or_else(chrono::Utc::now);
    let expires_at =
        required_pairing_expires_at(&agent_record)?.to_rfc3339_opts(SecondsFormat::Millis, true);
    let write = crate::persistence::AgentRuntimeApprovalWrite {
        agent_id: agent_id.to_owned(),
        pairing_request_id: body.pairing_request_id.to_string(),
        approval_request_id: proposed_approval_request_id.clone(),
        approval_notification_id: proposed_notification_id.clone(),
        approval_requested_at: proposed_requested_at,
        controller_account_id: account.id.clone(),
        recipient_service_id: state.config.service_id.clone(),
        runtime_key_binding_digest: binding_digest.as_str().to_owned(),
        runtime_public_key_digest: public_key_digest.as_str().to_owned(),
        runtime_attestation_digest: attestation_digest.as_str().to_owned(),
        runtime_key_request: runtime_key_request_for_controller(&body),
    };
    let stored = state
        .persistence
        .agents()
        .put_runtime_approval_if_compatible(&write)
        .await
        .map_err(|err| AppError::internal(format!("runtime approval request save failed: {err}")))?
        .ok_or_else(|| {
            AppError::new(
                ErrorCode::Conflict,
                "a different runtime key binding is already pending for this pairing request",
            )
            .with_status(StatusCode::CONFLICT)
            .with_wire_code("agent_runtime_request_conflict")
        })?;
    let approval_request_id = stored.approval_request_id.clone().ok_or_else(|| {
        pairing_failed_precondition("agent pairing metadata is incomplete")
            .with_reason_detail("missing approval_request_id")
    })?;
    let notification_id = stored
        .approval_notification_id
        .map(|id| ids::format_typed_uuid("notification", &id))
        .ok_or_else(|| {
            pairing_failed_precondition("agent pairing metadata is incomplete")
                .with_reason_detail("missing approval_notification_id")
        })?;
    let requested_at = stored
        .approval_requested_at
        .ok_or_else(|| {
            pairing_failed_precondition("agent pairing metadata is incomplete")
                .with_reason_detail("missing approval_requested_at")
        })?
        .to_rfc3339_opts(SecondsFormat::Millis, true);
    let projection_action = if existing_binding.is_none()
        && approval_request_id == proposed_approval_request_id
        && notification_id == proposed_notification_id
    {
        "add"
    } else {
        "update"
    };
    state
        .persistence
        .notifications()
        .put_account_delta(json!({
            "notification_id": notification_id.clone(),
            "recipient_id": controller_id,
            "controller_account_id": account.id.clone(),
            "recipient_service_id": state.config.service_id.clone(),
            "source_account_artifact_id": approval_request_id.clone(),
            "projection_action": projection_action,
            "projection_data": {
                "kind": "agent_runtime_approval",
                "approval_request_id": approval_request_id.clone(),
                "agent_id": agent_id,
                "requested_at": requested_at,
                "expires_at": expires_at,
            },
        }))
        .await
        .map_err(|error| {
            AppError::internal(format!(
                "runtime approval notification save failed: {error}"
            ))
        })?;
    let _ = state
        .event_broadcast
        .send(crate::state::EventNotification::account(
            account.id,
            state.config.service_id.clone(),
        ));
    json_ok(AgentRuntimeApprovalOutcome {
        ok: true,
        approval_request_id,
        status: agent_projection_from_record(&stored).status,
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
    res: &mut Response,
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
    res.headers_mut()
        .insert(salvo::http::header::RETRY_AFTER, "1".parse().unwrap());
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
) -> Result<AgentPrincipalRecord, AppError> {
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
    let record = reconcile_accepted_agent_authorization(state, record).await?;
    if record.pairing_code.as_deref() != Some(pairing_code)
        || agent_id.is_some_and(|expected| record.id != expected)
    {
        return Err(agent_pairing_not_found());
    }
    Ok(record)
}

pub(super) async fn reconcile_accepted_agent_authorization(
    state: &AppState,
    agent_record: AgentPrincipalRecord,
) -> Result<AgentPrincipalRecord, AppError> {
    let Some(approval_request_id) = agent_record.approval_request_id.clone() else {
        return Ok(agent_record);
    };
    let Some(runtime_request) = agent_record
        .runtime_key_request
        .as_ref()
        .filter(|value| value.is_object())
    else {
        return Ok(agent_record);
    };
    let agent_id = agent_record.id.clone();
    let controller_id = agent_record.controller_id.clone();
    let Some(pairing_request_id) = agent_record.pairing_request_id.clone() else {
        return Ok(agent_record);
    };
    let Some(verification_method) = runtime_request
        .get("verification_method")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
    else {
        return Ok(agent_record);
    };
    let Some(public_key_digest) = agent_record.runtime_public_key_digest.clone() else {
        return Ok(agent_record);
    };
    let expected_realm_id = agent_record.principal_control_realm_id.clone();
    let expected_authorization_ref = agent_record.controller_authorization_ref.clone();
    let expected_request_digest = pairing_request_binding_digest(
        &agent_record,
        &controller_id,
        &agent_id,
        &verification_method,
        &public_key_digest,
        &state.config.service_id,
    )?;
    let events = state
        .persistence
        .events()
        .snapshot_all()
        .await
        .map_err(|error| {
            AppError::internal(format!("authorization reconciliation failed: {error}"))
        })?;
    let accepted = events.into_iter().find(|event| {
        if event.kind != "ak.agent.key.authorize" || event.actor_id != agent_id {
            return false;
        }
        let envelope = &event.envelope;
        let payload = envelope.get("payload").unwrap_or(&Value::Null);
        let evidence = payload.get("approval_evidence").unwrap_or(&Value::Null);
        envelope.get("executed_by").and_then(Value::as_str) == Some(controller_id.as_str())
            && envelope.get("authorization_ref").and_then(Value::as_str)
                == Some(expected_authorization_ref.as_str())
            && envelope.get("realm_id").and_then(Value::as_str) == Some(expected_realm_id.as_str())
            && payload.get("agent_id").and_then(Value::as_str) == Some(agent_id.as_str())
            && payload.get("verification_method").and_then(Value::as_str)
                == Some(verification_method.as_str())
            && payload.get("public_key_digest").and_then(Value::as_str)
                == Some(public_key_digest.as_str())
            && payload
                .get("accountable_principal_id")
                .and_then(Value::as_str)
                == Some(controller_id.as_str())
            && payload
                .get("agent_key_scope")
                .is_some_and(|scope| agent_key_scope_within_requested_scope(&agent_record, scope))
            && payload
                .get("audience")
                .and_then(Value::as_array)
                .is_some_and(|audience| {
                    audience
                        .iter()
                        .any(|entry| entry.as_str() == Some(state.config.service_id.as_str()))
                })
            && evidence.get("kind").and_then(Value::as_str) == Some("pairing_request")
            && evidence.get("approved_by").and_then(Value::as_str) == Some(controller_id.as_str())
            && evidence.get("pairing_request_id").and_then(Value::as_str)
                == Some(pairing_request_id.as_str())
            && evidence
                .get("request_canonical_digest")
                .and_then(Value::as_str)
                == Some(expected_request_digest.as_str())
    });
    let Some(accepted) = accepted else {
        return Ok(agent_record);
    };
    let paired_request_digest =
        paired_request_digest_from_record_event(&agent_record, &accepted.envelope)?;

    let terminal_notification = account_notification_context(&agent_record);
    let activation = crate::persistence::AgentRuntimeActivation {
        agent_id: agent_id.clone(),
        approval_request_id: approval_request_id.clone(),
        runtime_key_binding_digest: agent_record
            .runtime_key_binding_digest
            .clone()
            .unwrap_or_default(),
        pairing_request_id,
        paired_request_digest,
        authorized_event_ref: accepted.event_id,
        authorized_verification_method: verification_method,
        authorized_public_key_digest: public_key_digest,
        authorized_at: accepted.received_at,
    };
    let activated = state
        .persistence
        .agents()
        .activate_runtime_if_current(&activation)
        .await
        .map_err(|error| {
            AppError::internal(format!(
                "authorization reconciliation persist failed: {error}"
            ))
        })?;
    if !activated {
        return state
            .persistence
            .agents()
            .get(&agent_id)
            .await
            .map_err(|error| {
                AppError::internal(format!(
                    "authorization reconciliation reload failed: {error}"
                ))
            })?
            .ok_or_else(|| {
                AppError::internal("Agent disappeared during authorization reconciliation")
            });
    }
    if let Some(context) = terminal_notification {
        finalize_terminal_account_notification(state, &agent_id, context, "approved").await?;
    }
    tracing::info!(
        agent_id,
        approval_request_id,
        "reconciled accepted Agent authorization into activation projection"
    );
    state
        .persistence
        .agents()
        .get(&agent_id)
        .await
        .map_err(|error| {
            AppError::internal(format!(
                "authorization reconciliation reload failed: {error}"
            ))
        })?
        .ok_or_else(|| AppError::internal("Agent disappeared after authorization reconciliation"))
}

/// Pure decision core for the open runtime-key-request status poll.
///
/// Anti-enumeration: a record miss and a `pairing_code` /
/// `agent_id` mismatch are indistinguishable — every mismatch maps
/// to the same not_found as an unknown `pairing_request_id`. An open pairing
/// whose `pairing_expires_at` has passed is reported as `pairing_expired`
/// without waiting for the lazy-expiry write.
pub(super) fn agent_runtime_key_request_status_outcome(
    agent_record: &AgentPrincipalRecord,
    body: &AgentRuntimeApprovalStatusRequestBody,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<AgentRuntimeApprovalStatusOutcome, AppError> {
    let pairing_code = body.pairing_code.trim();
    if pairing_code.is_empty() {
        return Err(agent_pairing_not_found());
    }
    if agent_record.pairing_code.as_deref() != Some(pairing_code) {
        return Err(agent_pairing_not_found());
    }
    if agent_record.id != body.agent_id.as_str() {
        return Err(agent_pairing_not_found());
    }
    let status = match agent_record.state.as_str() {
        "pending_runtime_key" => {
            let expired = agent_record
                .pairing_expires_at
                .is_none_or(|expires_at| expires_at <= now);
            if expired {
                AgentStatus::PairingExpired
            } else {
                AgentStatus::PendingRuntimeKey
            }
        }
        "active" => AgentStatus::Active,
        "paused" => AgentStatus::Paused,
        "deactivated" => AgentStatus::Deactivated,
        "pairing_expired" => AgentStatus::PairingExpired,
        _ => return Err(agent_pairing_not_found()),
    };
    let approval_request_id = if status == AgentStatus::PendingRuntimeKey {
        agent_record.approval_request_id.clone()
    } else {
        None
    };
    let authorized_event_ref = agent_record
        .authorized_event_ref
        .as_deref()
        .map(EventId::new)
        .transpose()
        .map_err(|err| AppError::internal(format!("authorized event ref invalid: {err}")))?;
    Ok(AgentRuntimeApprovalStatusOutcome {
        ok: true,
        status,
        approval_request_id,
        authorized_event_ref,
        authorized_verification_method: agent_record.authorized_verification_method.clone(),
        authorized_public_key_digest: agent_record.authorized_public_key_digest.clone(),
    })
}

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
    let body = body.into_inner();
    let event_id = body.authorize_event.event_id.as_str();
    let idempotency_key = req
        .headers()
        .get("idempotency-key")
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| AppError::missing_param("Idempotency-Key header is required"))?;
    if idempotency_key != event_id {
        return Err(
            AppError::conflict("Idempotency-Key must equal authorize_event.event_id")
                .with_wire_code("duplicate_conflict"),
        );
    }
    let service_authorized = agent_projection_service_authorized(state, req);
    let session = if service_authorized {
        let controller_id = body.authorize_event.executed_by.as_ref().ok_or_else(|| {
            AppError::capability_denied(
                "authorize_event.executed_by is required for delegated pairing",
            )
        })?;
        controller_service_session(controller_id.as_str(), state)
    } else {
        aa.authenticated_session(state, req).await?
    };
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
    let paired_request_digest = agent_key_pair_request_digest(&body)?;
    if agent_record.authorized_event_ref.as_deref() == Some(event_id) {
        let same_request = agent_record.paired_pairing_request_id.as_deref()
            == Some(body.pairing_request_id.as_str())
            && agent_record.paired_request_digest.as_deref()
                == Some(paired_request_digest.as_str());
        if !same_request {
            return Err(AppError::conflict(
                "authorize_event.event_id was already accepted for a different pairing request",
            )
            .with_wire_code("duplicate_conflict"));
        }
        if let Some(context) = account_notification_context(&agent_record) {
            finalize_terminal_account_notification(state, agent_id, context, "approved").await?;
        }
        return json_ok(AgentKeyPairOutcome {
            ok: true,
            authorized_event_ref: body.authorize_event.event_id.clone(),
        });
    }
    ensure_pairing_request_open(&agent_record)?;
    ensure_pairing_request_id_matches(&agent_record, &body.pairing_request_id)?;
    let runtime_public_key_digest =
        runtime_public_key_digest(&body.public_key, &body.verification_method)?;
    verify_runtime_key_pair_proof_of_possession(&body, agent_id, &state.config.service_id)?;
    ensure_current_runtime_key_request_matches(&agent_record, &body)?;
    let pcr_recovery = crate::routing::identity::managed_agent_pcr::project_agent_pcr_recovery(
        state,
        &agent_record,
    )
    .await?;
    if !pcr_recovery.is_ready() {
        return Err(AppError::new(
            ErrorCode::FailedPrecondition,
            "managed Agent PCR recovery backup is not ready for the current pre-commit frontier",
        )
        .with_status(StatusCode::PRECONDITION_FAILED)
        .with_wire_code("agent_pcr_recovery_not_ready"));
    }
    crate::routing::identity::managed_agent_pcr::validate_agent_controller_binding(
        state,
        &agent_record,
        chrono::Utc::now(),
    )
    .await?;
    let authorize_event_value = serde_json::to_value(&body.authorize_event)
        .map_err(|error| AppError::invalid_param(format!("authorize_event invalid: {error}")))?;
    let authorized_at = chrono::Utc::now();
    // Development and production consume the exact controller-signed Event
    // supplied by the client. A server-generated substitute would break the
    // Agent-PCR authorship and idempotency contract.
    let event_id = submit_production_key_authorize_event(
        state,
        &session,
        &authorize_event_value,
        &agent_record,
        agent_id,
        &body.verification_method,
        &runtime_public_key_digest,
    )
    .await?;
    let authorized_event_ref = EventId::new(event_id)
        .map_err(|err| AppError::internal(format!("authorize event id invalid: {err}")))?;
    // Pairing semantics: a provisioned agent starts `pending_runtime_key`;
    // flip to `active` ONLY after the durable key authorization has been
    // accepted (a failed submit above propagates via `?` and MUST NOT leave
    // the agent flipped to active).
    let terminal_notification = account_notification_context(&agent_record);
    let activation = crate::persistence::AgentRuntimeActivation {
        agent_id: agent_id.to_owned(),
        approval_request_id: agent_record.approval_request_id.clone().ok_or_else(|| {
            pairing_failed_precondition("agent pairing approval metadata is incomplete")
        })?,
        runtime_key_binding_digest: agent_record.runtime_key_binding_digest.clone().ok_or_else(
            || pairing_failed_precondition("agent runtime key binding metadata is incomplete"),
        )?,
        pairing_request_id: body.pairing_request_id.to_string(),
        paired_request_digest,
        authorized_event_ref: authorized_event_ref.as_str().to_owned(),
        authorized_verification_method: body.verification_method.to_string(),
        authorized_public_key_digest: runtime_public_key_digest.clone(),
        authorized_at,
    };
    // The compare-and-set below records the authorized binding fields for the
    // open status poll and consumes this approval for the current pairing
    // request atomically (including runtime replacement re-pairing, §3.6.1).
    let activated = state
        .persistence
        .agents()
        .activate_runtime_if_current(&activation)
        .await
        .map_err(|err| AppError::internal(format!("agent state activation failed: {err}")))?;
    if !activated {
        return Err(pairing_failed_precondition(
            "runtime approval was already consumed or changed",
        ));
    }
    if let Some(context) = terminal_notification {
        finalize_terminal_account_notification(state, agent_id, context, "approved").await?;
    }
    json_ok(AgentKeyPairOutcome {
        ok: true,
        authorized_event_ref,
    })
}

fn ensure_current_runtime_key_request_matches(
    agent_record: &AgentPrincipalRecord,
    body: &AgentKeyPairRequestBody,
) -> Result<(), AppError> {
    let current = agent_record
        .runtime_key_request
        .as_ref()
        .filter(|value| value.is_object())
        .ok_or_else(|| pairing_failed_precondition("runtime key request is no longer pending"))?;
    let runtime_attestation = runtime_attestation_value(body.runtime_attestation.as_ref())?;
    let public_key_value = serde_json::to_value(&body.public_key)
        .map_err(|error| AppError::invalid_param(format!("public_key invalid: {error}")))?;
    let proof_value = serde_json::to_value(&body.proof_of_possession).map_err(|error| {
        AppError::invalid_param(format!("proof_of_possession invalid: {error}"))
    })?;
    let fields_match = current.get("pairing_request_id").and_then(Value::as_str)
        == Some(body.pairing_request_id.as_str())
        && current.get("agent_id").and_then(Value::as_str) == Some(body.agent_id.as_str())
        && current.get("verification_method").and_then(Value::as_str)
            == Some(body.verification_method.as_str())
        && current.get("public_key") == Some(&public_key_value)
        && current.get("proof_of_possession") == Some(&proof_value)
        && current
            .get("runtime_attestation")
            .filter(|value| !value.is_null())
            == runtime_attestation.as_ref();
    if !fields_match {
        return Err(pairing_failed_precondition(
            "controller approval does not match the current runtime key request",
        ));
    }
    let agent_id = Did::new(body.agent_id.as_str().to_owned())
        .map_err(|error| AppError::invalid_param(format!("agent_id invalid: {error}")))?;
    let current_binding = arkret_sdk::agent_runtime_key_binding_digest(
        &agent_id,
        &body.pairing_request_id,
        &body.verification_method,
        &body.public_key,
        runtime_attestation.as_ref(),
    )
    .map_err(|error| AppError::invalid_param(format!("runtime key binding invalid: {error}")))?;
    if agent_record.runtime_key_binding_digest.as_deref() != Some(current_binding.as_str()) {
        return Err(pairing_failed_precondition(
            "runtime key binding changed after controller discovery",
        ));
    }
    Ok(())
}

pub(super) struct AccountNotificationContext {
    notification_id: String,
    recipient_id: String,
    controller_account_id: String,
    recipient_service_id: String,
    approval_request_id: String,
}

pub(super) fn account_notification_context(
    agent_record: &AgentPrincipalRecord,
) -> Option<AccountNotificationContext> {
    Some(AccountNotificationContext {
        notification_id: ids::format_typed_uuid(
            "notification",
            &agent_record.approval_notification_id?,
        ),
        recipient_id: agent_record.controller_id.clone(),
        controller_account_id: ids::format_typed_uuid(
            "account",
            &agent_record.controller_account_id?,
        ),
        recipient_service_id: agent_record.recipient_service_id.clone()?,
        approval_request_id: agent_record.approval_request_id.clone()?,
    })
}

pub(super) async fn persist_terminal_account_notification(
    state: &AppState,
    context: AccountNotificationContext,
    reason: &str,
) -> Result<(), AppError> {
    state
        .persistence
        .notifications()
        .put_account_delta(json!({
            "notification_id": context.notification_id,
            "recipient_id": context.recipient_id,
            "controller_account_id": context.controller_account_id.clone(),
            "recipient_service_id": context.recipient_service_id.clone(),
            "source_account_artifact_id": context.approval_request_id,
            "projection_action": "remove",
            "projection_data": {
                "kind": "agent_runtime_approval",
                "reason": reason,
            },
        }))
        .await
        .map_err(|error| {
            AppError::internal(format!(
                "terminal approval notification save failed: {error}"
            ))
        })?;
    let _ = state
        .event_broadcast
        .send(crate::state::EventNotification::account(
            context.controller_account_id,
            context.recipient_service_id,
        ));
    Ok(())
}

/// Persist the terminal notification delta before clearing the correlation
/// retained by the activation compare-and-set. If the process crashes after
/// either write, an exact pairing retry observes the accepted Event, repeats
/// the idempotent remove delta, and then clears the same approval id. This
/// prevents a durable activation from leaving a permanently visible approval.
async fn finalize_terminal_account_notification(
    state: &AppState,
    agent_id: &str,
    context: AccountNotificationContext,
    reason: &str,
) -> Result<(), AppError> {
    let approval_request_id = context.approval_request_id.clone();
    persist_terminal_account_notification(state, context, reason).await?;
    state
        .persistence
        .agents()
        .clear_runtime_approval_notification_if_current(agent_id, &approval_request_id)
        .await
        .map_err(|error| {
            AppError::internal(format!(
                "terminal approval correlation cleanup failed: {error}"
            ))
        })?;
    Ok(())
}

pub(super) async fn submit_production_key_authorize_event(
    state: &AppState,
    session: &SessionRecord,
    envelope: &Value,
    agent_record: &AgentPrincipalRecord,
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
    let delegated_session = delegated_agent_session(session, agent_id);
    let outcome = submit_event_value(state, &delegated_session, envelope.clone())
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
    agent_record: &AgentPrincipalRecord,
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
    if envelope.get("actor_id").and_then(Value::as_str) != Some(agent_id) {
        return Err(AppError::capability_denied(
            "authorize_event.actor_id must match the managed Agent principal",
        ));
    }
    if envelope.get("executed_by").and_then(Value::as_str) != Some(controller) {
        return Err(AppError::capability_denied(
            "authorize_event.executed_by must match the authenticated controller",
        ));
    }
    let expected_authorization_ref = agent_record.controller_authorization_ref.as_str();
    if expected_authorization_ref.is_empty() {
        return Err(AppError::capability_denied(
            "Agent has no controller delegation binding",
        ));
    }
    if envelope.get("authorization_ref").and_then(Value::as_str) != Some(expected_authorization_ref)
    {
        return Err(AppError::capability_denied(
            "authorize_event.authorization_ref must match the Agent DID controller delegation",
        ));
    }
    let expected_realm_id = agent_record.principal_control_realm_id.as_str();
    if expected_realm_id.is_empty() {
        return Err(AppError::capability_denied(
            "Agent has no authoritative Principal Control Realm binding",
        ));
    }
    if envelope.get("realm_id").and_then(Value::as_str) != Some(expected_realm_id) {
        return Err(AppError::capability_denied(
            "authorize_event.realm_id must match the Agent Principal Control Realm",
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
    ensure_authorize_event_scope_within_requested(agent_record, payload)?;
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
    if let Some(expires_at) = payload.get("expires_at") {
        let expires_at = expires_at
            .as_str()
            .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
            .ok_or_else(|| {
                AppError::invalid_param("authorize_event.payload.expires_at must be rfc3339")
            })?;
        if expires_at.with_timezone(&chrono::Utc) <= chrono::Utc::now() {
            return Err(pairing_failed_precondition(
                "authorize_event payload has expired",
            ));
        }
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
    if approval_evidence.get("approved_by").and_then(Value::as_str) != Some(controller) {
        return Err(AppError::capability_denied(
            "authorize_event.payload.approval_evidence.approved_by must match the authenticated controller",
        ));
    }
    let pairing_request_id = required_pairing_request_id(agent_record)?;
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

fn agent_key_pair_request_digest(body: &AgentKeyPairRequestBody) -> Result<String, AppError> {
    let value = serde_json::to_value(body)
        .map_err(|error| AppError::invalid_param(format!("pairing request invalid: {error}")))?;
    let canonical = arkret_sdk::canonical::canonical_json_bytes(&value).map_err(|error| {
        AppError::invalid_param(format!("pairing request canonicalization failed: {error}"))
    })?;
    Ok(arkret_sdk::canonical::sha256_digest(&canonical))
}

fn paired_request_digest_from_record_event(
    agent_record: &AgentPrincipalRecord,
    authorize_event: &Value,
) -> Result<String, AppError> {
    let mut request = agent_record
        .runtime_key_request
        .as_ref()
        .and_then(Value::as_object)
        .cloned()
        .ok_or_else(|| {
            AppError::internal("accepted Agent authorization has no persisted runtime request")
        })?;
    request.insert("authorize_event".to_owned(), authorize_event.clone());
    let canonical =
        arkret_sdk::canonical::canonical_json_bytes(&Value::Object(request)).map_err(|error| {
            AppError::internal(format!(
                "accepted pairing request canonicalization failed: {error}"
            ))
        })?;
    Ok(arkret_sdk::canonical::sha256_digest(&canonical))
}

pub(super) fn ensure_pairing_request_open(
    agent_record: &AgentPrincipalRecord,
) -> Result<(), AppError> {
    match agent_record.state.as_str() {
        "pending_runtime_key" => {}
        "pairing_expired" => {
            return Err(pairing_failed_precondition("pairing request has expired"));
        }
        "active" | "paused" => {
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
        "deactivated" => {
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
    let expires_at = required_pairing_expires_at(agent_record)?;
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
pub(super) fn agent_pairing_handle_is_open(agent_record: &AgentPrincipalRecord) -> bool {
    let current = agent_record.pairing_request_id.as_deref();
    let consumed = agent_record.paired_pairing_request_id.as_deref();
    current.is_some() && current != consumed
}

pub(super) fn agent_record_reserves_selector_slug(
    agent_record: &AgentPrincipalRecord,
    now: &chrono::DateTime<chrono::Utc>,
) -> bool {
    match agent_record.state.as_str() {
        "active" | "paused" => true,
        "pending_runtime_key" => agent_record
            .pairing_expires_at
            .map(|expires_at| expires_at > *now)
            .unwrap_or(true),
        "pairing_expired" | "deactivated" => false,
        _ => true,
    }
}

pub(super) fn ensure_pairing_request_id_matches(
    agent_record: &AgentPrincipalRecord,
    supplied_pairing_request_id: &str,
) -> Result<(), AppError> {
    let expected = required_pairing_request_id(agent_record)?;
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
        authorize_event: arkret_sdk::Event::new(
            "ak.agent.key.authorize",
            arkret_sdk::RealmId::new("ak:realm:01999999-0000-7000-8000-00000000feed").unwrap(),
            arkret_sdk::Did::new("did:web:agent.example").unwrap(),
            1,
            arkret_sdk::Hlc::new("01970e589d21-0004-a13f9c2e").unwrap(),
            json!({}),
        )
        .unwrap(),
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

fn runtime_attestation_value(
    runtime_attestation: Option<&arkret_sdk::AgentKeyAuthorizePayloadRuntimeAttestation>,
) -> Result<Option<Value>, AppError> {
    runtime_attestation
        .map(serde_json::to_value)
        .transpose()
        .map_err(|error| AppError::invalid_param(format!("runtime_attestation invalid: {error}")))
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
    public_key: &PublicKey,
    verification_method: &str,
) -> Result<[u8; 32], AppError> {
    if public_key.kty.as_str() != "OKP" {
        return Err(AppError::invalid_param("public_key.kty must be OKP"));
    }
    if public_key.alg.as_str() != "Ed25519" && public_key.alg.as_str() != "EdDSA" {
        return Err(AppError::invalid_param(
            "public_key.alg must be Ed25519 or EdDSA",
        ));
    }
    if public_key.kid.as_str() != verification_method {
        return Err(AppError::invalid_param(
            "public_key.kid must match verification_method",
        ));
    }
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(public_key.key.as_bytes())
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
    let proof: AgentKeyPairProofOfPossession = serde_json::from_value(
        serde_json::to_value(&body.proof_of_possession).map_err(|error| {
            AppError::invalid_param(format!("proof_of_possession invalid: {error}"))
        })?,
    )
    .map_err(|error| AppError::invalid_param(format!("proof_of_possession invalid: {error}")))?;
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
        &serde_json::to_value(&body.public_key)
            .map_err(|error| AppError::invalid_param(format!("public_key invalid: {error}")))?,
        runtime_attestation_value(body.runtime_attestation.as_ref())?.as_ref(),
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
        body.verification_method.to_string(),
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

fn required_pairing_request_id(record: &AgentPrincipalRecord) -> Result<&str, AppError> {
    record
        .pairing_request_id
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| incomplete_pairing_metadata("pairing_request_id"))
}

fn required_pairing_code(record: &AgentPrincipalRecord) -> Result<&str, AppError> {
    record
        .pairing_code
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| incomplete_pairing_metadata("pairing_code"))
}

fn required_pairing_expires_at(
    record: &AgentPrincipalRecord,
) -> Result<chrono::DateTime<chrono::Utc>, AppError> {
    record
        .pairing_expires_at
        .ok_or_else(|| incomplete_pairing_metadata("pairing_expires_at"))
}

fn incomplete_pairing_metadata(field: &str) -> AppError {
    pairing_failed_precondition("agent pairing metadata is incomplete")
        .with_reason_detail(format!("missing {field}"))
}

pub(super) fn runtime_public_key_digest(
    public_key: &PublicKey,
    verification_method: &str,
) -> Result<String, AppError> {
    runtime_ed25519_public_key(public_key, verification_method)?;
    arkret_sdk::agent_runtime_public_key_digest(public_key)
        .map(|digest| digest.as_str().to_owned())
        .map_err(|error| AppError::invalid_param(format!("public_key is invalid: {error}")))
}

pub(super) fn ensure_authorize_event_scope_within_requested(
    agent_record: &AgentPrincipalRecord,
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
    if !agent_key_scope_within_requested_scope(agent_record, scope) {
        return Err(AppError::invalid_param(
            "authorize_event.payload.agent_key_scope must be within the provisioned requested_scope",
        ));
    }
    Ok(())
}

pub(super) fn pairing_request_binding_digest(
    agent_record: &AgentPrincipalRecord,
    controller: &str,
    agent_id: &str,
    verification_method: &str,
    runtime_public_key_digest: &str,
    service_id: &str,
) -> Result<String, AppError> {
    let pairing_request_id = required_pairing_request_id(agent_record)?;
    let pairing_code = required_pairing_code(agent_record)?;
    let expires_at = required_pairing_expires_at(agent_record)?
        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
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
        &expires_at,
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

#[cfg(test)]
mod requested_scope_tests {
    use super::*;

    fn agent_record(requested_scope: Option<Value>) -> AgentPrincipalRecord {
        let mut record = AgentPrincipalRecord::new(
            "did:webvh:agent.example:agents:test".to_owned(),
            "did:webvh:controller.example:users:test".to_owned(),
            "ak:realm:019f6000-0000-7000-8000-000000000001".to_owned(),
            "did:webvh:agent.example:agents:test#controller".to_owned(),
            "pending_runtime_key".to_owned(),
            chrono::Utc::now(),
        );
        record.requested_scope = requested_scope;
        record
    }

    #[test]
    fn authorize_scope_may_narrow_but_cannot_widen_provision_ceiling() {
        let ceiling = json!({
            "actions": ["ak.message.create", "ak.self.events.command.submit"],
            "resources": [{
                "kind": "operation",
                "operation": "ak.self.events.command.submit"
            }],
            "constraints": [{"controller_approval_required": true}]
        });
        let payload = json!({
            "agent_key_scope": {
                "actions": ["ak.self.events.command.submit"],
                "resources": ceiling["resources"].clone(),
                "constraints": [
                    {"controller_approval_required": true},
                    {"rate_limit": {"max": 10}}
                ]
            }
        });
        assert!(
            ensure_authorize_event_scope_within_requested(
                &agent_record(Some(ceiling.clone())),
                &payload,
            )
            .is_ok()
        );

        let widened = json!({
            "agent_key_scope": {
                "actions": [
                    "ak.message.create",
                    "ak.reaction.add",
                    "ak.self.events.command.submit"
                ],
                "resources": ceiling["resources"].clone(),
                "constraints": ceiling["constraints"].clone()
            }
        });
        assert!(
            ensure_authorize_event_scope_within_requested(
                &agent_record(Some(ceiling.clone())),
                &widened,
            )
            .is_err()
        );

        let dropped_constraint = json!({
            "agent_key_scope": {
                "actions": ["ak.self.events.command.submit"],
                "resources": ceiling["resources"].clone()
            }
        });
        assert!(
            ensure_authorize_event_scope_within_requested(
                &agent_record(Some(ceiling.clone())),
                &dropped_constraint,
            )
            .is_err()
        );

        let escaped_resource = json!({
            "agent_key_scope": {
                "actions": ["ak.self.events.command.submit"],
                "resources": [{
                    "kind": "operation",
                    "operation": "ak.self.events.query.scan"
                }],
                "constraints": ceiling["constraints"].clone()
            }
        });
        assert!(
            ensure_authorize_event_scope_within_requested(
                &agent_record(Some(ceiling)),
                &escaped_resource,
            )
            .is_err()
        );
        assert!(
            ensure_authorize_event_scope_within_requested(&agent_record(None), &payload).is_err()
        );
    }

    #[test]
    fn account_notification_context_restores_typed_ids_from_persisted_uuids() {
        let mut record = agent_record(None);
        record.approval_notification_id = Some(
            uuid::Uuid::parse_str("019f6131-3dc4-76f1-ade6-00f4225a8528")
                .expect("valid notification uuid"),
        );
        record.controller_account_id = Some(
            uuid::Uuid::parse_str("019f6131-3dc4-76f1-ade6-00f4225a8529")
                .expect("valid account uuid"),
        );
        record.recipient_service_id = Some("did:webvh:soland.example".to_owned());
        record.approval_request_id = Some("agent_runtime_approval:test".to_owned());

        let context = account_notification_context(&record).expect("complete notification context");

        assert_eq!(
            context.notification_id,
            "ak:notification:019f6131-3dc4-76f1-ade6-00f4225a8528"
        );
        assert_eq!(
            context.controller_account_id,
            "ak:account:019f6131-3dc4-76f1-ade6-00f4225a8529"
        );
    }
}
