use salvo::oapi::endpoint;

use super::*;

#[endpoint(
    operation_id = "ak.open.agent_pairing.read.resolve",
    summary = "Resolve an agent pairing bootstrap",
    tags("agent_pairing")
)]
#[tracing::instrument(skip_all, fields(op = "ak.open.agent_pairing.read.resolve"))]
pub(super) async fn resolve_agent_pairing(
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AgentPairingBootstrap> {
    if agent_pairing_token_appears_in_url(req) {
        return Err(AppError::param_invalid(
            "pairing_token must be sent in the JSON body, never in URL path or query",
        )
        .with_status(StatusCode::BAD_REQUEST)
        .with_wire_code("schema_violation"));
    }
    let state = depot.get_typed::<AppState>().expect("state injected");
    let body = req
        .parse_json::<AgentPairingResolveRequestBody>()
        .await
        .map_err(|_| AppError::json_invalid("invalid agent pairing resolve request body"))?;
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
            .config()
            .public_base_url
            .trim_end_matches('/')
            .to_owned(),
        service_id: arkret_identifiers::DidCoreId::new(state.service_id().clone()).map_err(
            |error| AppError::internal(format!("configured service_id invalid: {error}")),
        )?,
        agent_id: arkret_wire::DidCoreId::new(agent_id)
            .map_err(|error| AppError::internal(format!("agent principal DID invalid: {error}")))?,
        pairing_request_id: arkret_wire::OpaqueLocalId::new(pairing_request_id.to_owned())
            .map_err(|error| {
                AppError::internal(format!("stored pairing request id invalid: {error}"))
            })?,
        pairing_code: pairing_code.to_owned(),
        pairing_expires_at,
    };
    json_ok(bootstrap)
}

#[endpoint(
    operation_id = "ak.open.agent_pairing.command.submit_runtime_key_request",
    summary = "Submit an agent runtime key request",
    tags("agent_pairing")
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
        return Err(AppError::param_invalid("pairing_code is required"));
    }
    let agent_id = body.agent_id.as_str();
    validate_agent_id(agent_id)?;
    if body.verification_method.trim().is_empty() {
        return Err(AppError::param_invalid("verification_method is required"));
    }
    if verification_method_principal(&body.verification_method)
        .is_none_or(|principal| principal.as_str() != agent_id)
    {
        return Err(AppError::param_invalid(
            "verification_method DID must project to agent_id",
        ));
    }
    if verification_method_agent_endpoint(&body.verification_method, agent_id).is_none() {
        return Err(AppError::param_invalid(
            "verification_method fragment must be the stable Agent endpoint device_id",
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
    verify_runtime_approval_proof_of_possession(
        &body,
        &agent_record,
        agent_id,
        state.service_id(),
    )?;
    let agent_did = arkret_wire::DidCoreId::new(agent_id.to_owned())
        .map_err(|error| AppError::param_invalid(format!("agent_id invalid: {error}")))?;
    let public_key_digest = arkret_signatures::agent::validate_agent_runtime_public_key(
        &body.public_key,
        &body.verification_method,
    )
    .map_err(|error| AppError::param_invalid(format!("public_key invalid: {error}")))?
    .runtime_request_digest;
    let runtime_attestation = runtime_attestation_value(body.runtime_attestation.as_ref())?;
    let attestation_digest =
        arkret_signatures::agent::agent_runtime_attestation_digest(runtime_attestation.as_ref())
            .map_err(|error| {
                AppError::param_invalid(format!("runtime_attestation invalid: {error}"))
            })?;
    let binding_digest = arkret_signatures::agent::agent_runtime_key_binding_digest_from_digests(
        &agent_did,
        &body.pairing_request_id,
        &body.verification_method,
        &public_key_digest,
        &attestation_digest,
    )
    .map_err(|error| AppError::param_invalid(format!("runtime key binding invalid: {error}")))?;
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
        .identities()
        .find_account_by_actor(soland_services::identity::FindAccountByActorQuery {
            actor_id: controller_id.clone(),
        })
        .await
        .map_err(|error| AppError::internal(format!("controller account lookup failed: {error}")))?
        .ok_or_else(|| AppError::internal("controller account is missing"))?;
    let proposed_approval_request_id =
        agent_record.approval_request_id.clone().unwrap_or_else(|| {
            arkret_wire::OpaqueLocalId::new(format!(
                "agent_runtime_approval:{}",
                uuid::Uuid::now_v7()
            ))
            .expect("generated approval request id must be valid")
        });
    let proposed_notification_id = agent_record
        .approval_notification_id
        .map(|id| ids::format_typed_uuid("notification", &id))
        .unwrap_or_else(|| ids::generate("notification"));
    let proposed_requested_at = agent_record
        .approval_requested_at
        .unwrap_or_else(chrono::Utc::now);
    let expires_at = required_pairing_expires_at(&agent_record)?;
    let write = soland_services::identity::StoreAgentRuntimeApprovalCommand {
        agent_id: agent_id.to_owned(),
        pairing_request_id: body.pairing_request_id.clone(),
        approval_request_id: proposed_approval_request_id.clone(),
        approval_notification_id: proposed_notification_id.clone(),
        approval_requested_at: proposed_requested_at,
        controller_account_id: account.account_id.clone(),
        recipient_service_id: state.service_id().clone(),
        runtime_key_binding_digest: binding_digest.as_str().to_owned(),
        runtime_public_key_digest: public_key_digest.as_str().to_owned(),
        runtime_attestation_digest: attestation_digest.as_str().to_owned(),
        runtime_key_request: runtime_key_request_for_controller(&body),
    };
    let stored = state
        .agent_pairings()
        .store_runtime_approval(&write)
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
    let requested_at = stored.approval_requested_at.ok_or_else(|| {
        pairing_failed_precondition("agent pairing metadata is incomplete")
            .with_reason_detail("missing approval_requested_at")
    })?;
    let delta =
        arkret_models_collaboration::sync_frames::account_sync::NotificationDelta::try_new(
            arkret_wire::NotificationId::new(notification_id.clone()).map_err(|error| {
                AppError::internal(format!("approval notification id is invalid: {error}"))
            })?,
            arkret_wire::NotificationKind::Agent,
            arkret_models_collaboration::sync_frames::account_sync::NotificationDeltaAction::Upsert,
            Some(
                arkret_models_collaboration::sync_frames::account_sync::NotificationData::AgentRuntimeApproval(
                    arkret_models_collaboration::sync_frames::account_sync::AgentRuntimeApprovalNotificationData {
                        kind: arkret_models_collaboration::sync_frames::account_sync::AccountNotificationDataKind::AgentRuntimeApproval,
                        approval_request_id: approval_request_id.clone(),
                        agent_id: body.agent_id.clone(),
                        requested_at,
                        expires_at,
                    },
                ),
            ),
        )
        .map_err(|error| {
            AppError::internal(format!("approval notification delta is invalid: {error}"))
        })?;
    state
        .deliveries()
        .store_account_delta(
            soland_services::delivery::StoreAccountNotificationDeltaCommand {
                record: soland_services::delivery::AccountNotificationDeltaWrite {
                    delta,
                    recipient_id: arkret_identifiers::DidCoreId::new(controller_id).map_err(
                        |error| {
                            AppError::internal(format!(
                                "approval notification recipient is invalid: {error}"
                            ))
                        },
                    )?,
                    controller_account_id: account.account_id.clone(),
                    recipient_service_id: arkret_identifiers::DidCoreId::new(
                        state.service_id().clone(),
                    )
                    .map_err(|error| {
                        AppError::internal(format!(
                            "approval notification service is invalid: {error}"
                        ))
                    })?,
                    source_account_artifact_id: approval_request_id.to_string(),
                },
            },
        )
        .await
        .map_err(|error| {
            AppError::internal(format!(
                "runtime approval notification save failed: {error}"
            ))
        })?;
    let _ = state.publish_event_notification(crate::state::EventNotification::account(
        account.account_id,
        state.service_id().clone(),
    ));
    json_ok(AgentRuntimeApprovalOutcome {
        ok: true,
        approval_request_id,
        status: agent_lifecycle_from_record(&stored),
    })
}

#[endpoint(
    operation_id = "ak.open.agent_pairing.read.runtime_key_request_status",
    summary = "Get an agent runtime key request status",
    tags("agent_pairing")
)]
#[tracing::instrument(
    skip_all,
    fields(op = "ak.open.agent_pairing.read.runtime_key_request_status")
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
        .agent_pairings()
        .pairing_record(pairing_request_id)
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
    let Some(runtime_request) = agent_record.runtime_key_request.as_ref() else {
        return Ok(agent_record);
    };
    let agent_id = agent_record.id.clone();
    let controller_id = agent_record.controller_id.clone();
    let Some(pairing_request_id) = agent_record.pairing_request_id.clone() else {
        return Ok(agent_record);
    };
    let verification_method = runtime_request.verification_method.to_string();
    let Some(public_key_digest) = agent_record.runtime_public_key_digest.clone() else {
        return Ok(agent_record);
    };
    let Some(pending_commit_intent) = agent_record.pending_pairing_commit_intent.clone() else {
        return Ok(agent_record);
    };
    let paired_request_digest = pending_commit_intent.request_digest;
    let pending_authorize_event_id = pending_commit_intent.authorize_event_id;
    let signing_key_binding = pending_commit_intent.signing_key_binding.ok_or_else(|| {
        pairing_failed_precondition(
            "pending pairing commit intent is missing its controller signing-key binding",
        )
    })?;
    let authorized_public_key_digest =
        arkret_signatures::agent_evidence::agent_signing_public_key_digest(
            &signing_key_binding.public_key,
        )
        .map_err(|reason| {
            pairing_failed_precondition("pending signing-key binding public key is invalid")
                .with_reason_detail(format!("{reason:?}"))
        })?;
    let expected_realm_id = agent_record.principal_control_realm_id.clone();
    let expected_authorization_ref = agent_record.controller_authorization_ref.clone();
    let expected_request_digest = pairing_request_binding_digest(
        &agent_record,
        &controller_id,
        &agent_id,
        &verification_method,
        state.service_id(),
    )?;
    let events = state
        .event_queries()
        .accepted_events_for_actor(&agent_id)
        .await
        .map_err(|error| {
            AppError::internal(format!("authorization reconciliation failed: {error}"))
        })?;
    let accepted = events.into_iter().find(|event| {
        if event.event_id != pending_authorize_event_id
            || event.kind != arkret_wire::event_kind_str::AGENT_KEY_AUTHORIZE
            || event.actor_id != agent_id
        {
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
                == Some(authorized_public_key_digest.as_str())
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
                        .any(|entry| entry.as_str() == Some(state.service_id().as_str()))
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
    let authorize_event: arkret_wire::Event = serde_json::from_value(accepted.envelope.clone())
        .map_err(|error| {
            AppError::internal(format!(
                "accepted Agent authorization Event is invalid: {error}"
            ))
        })?;
    let typed_agent_id = arkret_wire::DidCoreId::new(agent_id.clone())
        .map_err(|error| AppError::internal(format!("stored Agent DID is invalid: {error}")))?;
    let typed_verification_method =
        arkret_wire::DidUrl::new(verification_method.clone()).map_err(AppError::internal)?;
    validate_agent_signing_key_binding_parts(
        &signing_key_binding,
        &authorize_event,
        &typed_agent_id,
        &typed_verification_method,
        &controller_id,
        &public_key_digest,
        state,
    )
    .await?;

    // Durable storage is only the proposal half of an Agent authorization.
    // Activation requires a portable state witness proving that the exact
    // authorization Event is covered by the accepted, controller-signed PCR
    // frontier. Until the client publishes that successor Seal, keep both the
    // pairing handle and its account notification open.
    // This projection is updated only by accepted Seal application. Matching
    // both the SDK key id and Event id prevents a durable pending Event row or
    // a different active authorization from satisfying the witness gate.
    let authorization_status = state
        .projections()
        .snapshot()
        .active_agent_key_authorizations(&agent_id)
        .into_iter()
        .any(|(key_id, authorized_event_id)| {
            key_id == signing_key_binding.agent_key_id.as_str()
                && authorized_event_id == accepted.event_id
        })
        .then_some(arkret_models_identity::agent_signer_evidence::AgentAuthorizationStatus::Active);
    let authorization_is_witnessed = authorization_status_allows_activation(authorization_status);
    if !authorization_is_witnessed {
        return Ok(agent_record);
    }

    let terminal_notification = account_notification_context(&agent_record);
    let activation = soland_services::identity::ActivateAgentRuntimeCommand {
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
        authorized_public_key_digest: authorized_public_key_digest.as_str().to_owned(),
        authorized_signing_key_binding: signing_key_binding,
        authorized_at: accepted.received_at,
    };
    let activated = state
        .agent_pairings()
        .activate_runtime(&activation)
        .await
        .map_err(|error| {
            AppError::internal(format!(
                "authorization reconciliation persist failed: {error}"
            ))
        })?;
    if !activated {
        return state
            .agent_pairings()
            .agent(&agent_id)
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
        finalize_terminal_account_notification(
            state,
            &agent_id,
            context,
            arkret_models_collaboration::sync_frames::account_sync::AgentRuntimeApprovalRemovalReason::Approved,
        )
        .await?;
    }
    tracing::info!(
        agent_id,
        approval_request_id = %approval_request_id,
        "reconciled accepted Agent authorization into activation projection"
    );
    state
        .agent_pairings()
        .agent(&agent_id)
        .await
        .map_err(|error| {
            AppError::internal(format!(
                "authorization reconciliation reload failed: {error}"
            ))
        })?
        .ok_or_else(|| AppError::internal("Agent disappeared after authorization reconciliation"))
}

fn authorization_status_allows_activation(
    status: Option<arkret_models_identity::agent_signer_evidence::AgentAuthorizationStatus>,
) -> bool {
    status == Some(arkret_models_identity::agent_signer_evidence::AgentAuthorizationStatus::Active)
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
    // Two orthogonal axes (key-management.md §3.6.1): the lifecycle intent and
    // the derived runtime readiness. An expired bootstrap handle projects
    // pairing_expired; an expired replacement handle projects ready with no
    // authorized fields for this request, which the runtime treats as expired.
    let status = agent_lifecycle_from_record(agent_record);
    let bindings = agent_record.runtime_bindings().map_err(|error| {
        AppError::internal(format!(
            "persisted Agent runtime binding state is invalid: {error}"
        ))
    })?;
    let has_active_authorization = bindings.active_binding.is_some();
    let handle_live = bindings
        .open_handle
        .as_ref()
        .is_some_and(|handle| handle.is_live_at(now));
    let runtime_state = AgentRuntimeState::derive(has_active_authorization, handle_live);
    let approval_request_id = if runtime_state == AgentRuntimeState::PendingRuntimeKey {
        agent_record.approval_request_id.clone()
    } else {
        None
    };
    // Replacement pairing keeps the previous authorization active until the
    // new request is approved. Do not expose that previous binding as the
    // outcome for this handle: runtimes may reuse the same key digest, which
    // would otherwise make a pending replacement look approved and persist a
    // reference that is revoked as soon as replacement completes.
    let completed_binding = bindings.active_binding.as_ref().filter(|binding| {
        binding.completed_pairing_request_id.as_str() == body.pairing_request_id.as_str()
    });
    let authorized_event_ref =
        completed_binding.map(|binding| binding.authorized_event_ref.clone());
    let authorized_signing_key_binding =
        completed_binding.map(|binding| binding.signing_key_binding.clone());
    Ok(AgentRuntimeApprovalStatusOutcome {
        ok: true,
        status,
        runtime_state,
        approval_request_id,
        authorized_event_ref,
        authorized_verification_method: completed_binding
            .map(|binding| binding.verification_method.clone()),
        authorized_public_key_digest: completed_binding
            .map(|binding| binding.public_key_digest.to_string()),
        authorized_signing_key_binding,
    })
}

#[endpoint(
    operation_id = "ak.gate.account.command.pair_agent_key",
    summary = "Pair an agent device key",
    tags("agent_pairing")
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
    let event_id = body.authorize_event.event.event_id.as_str();
    let idempotency_key = req
        .headers()
        .get("idempotency-key")
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| AppError::param_missing("Idempotency-Key header is required"))?;
    if idempotency_key != event_id {
        return Err(AppError::conflict(
            "Idempotency-Key must equal authorize_event.event.event_id",
        )
        .with_wire_code("duplicate_conflict"));
    }
    let service_authorized = agent_projection_service_authorized(state, req);
    let session = if service_authorized {
        let controller_id = body
            .authorize_event
            .event
            .executed_by
            .as_ref()
            .ok_or_else(|| {
                AppError::capability_denied(
                    "authorize_event.executed_by is required for delegated pairing",
                )
            })?;
        let controller_device_id =
            service_pairing_controller_device_id(&body, controller_id.as_str())?;
        controller_service_session(controller_id.as_str(), &controller_device_id, state)
    } else {
        aa.authenticated_session(state, req).await?
    };
    let agent_id = body.agent_id.as_str();
    validate_agent_id(agent_id)?;
    if body.verification_method.trim().is_empty() {
        return Err(AppError::param_invalid("verification_method is required"));
    }
    if verification_method_principal(&body.verification_method)
        .is_none_or(|principal| principal.as_str() != agent_id)
    {
        return Err(AppError::param_invalid(
            "verification_method DID must project to agent_id",
        ));
    }
    if verification_method_agent_endpoint(&body.verification_method, agent_id).is_none() {
        return Err(AppError::param_invalid(
            "verification_method fragment must be the stable Agent endpoint device_id",
        ));
    }
    let agent_record = require_agent_controller(state, &session, agent_id).await?;
    let agent_record = reconcile_accepted_agent_authorization(state, agent_record).await?;
    validate_requested_scope_disclosure(&body, &agent_record, state).await?;
    validate_agent_key_authorize_effects(&body.authorize_event.event)?;
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
            finalize_terminal_account_notification(
                state,
                agent_id,
                context,
                arkret_models_collaboration::sync_frames::account_sync::AgentRuntimeApprovalRemovalReason::Approved,
            )
            .await?;
        }
        return json_ok(AgentKeyPairOutcome {
            ok: true,
            activation_state: AgentKeyPairActivationState::Active,
            authorize_event_ref: body.authorize_event.event.event_id.clone(),
            signing_key_binding: body.signing_key_binding,
        });
    }
    ensure_pairing_request_open(&agent_record)?;
    ensure_pairing_request_id_matches(&agent_record, &body.pairing_request_id)?;
    let runtime_public_key_digest =
        runtime_public_key_digest(&body.public_key, &body.verification_method)?;
    verify_runtime_key_pair_proof_of_possession(
        &body,
        &agent_record,
        agent_id,
        state.service_id(),
    )?;
    validate_agent_signing_key_binding(
        &body,
        &agent_record.controller_id,
        &runtime_public_key_digest,
        state,
    )
    .await?;
    ensure_current_runtime_key_request_matches(&agent_record, &body)?;
    crate::routing::identity::managed_agent_pcr::validate_agent_controller_binding(
        state,
        &agent_record,
        chrono::Utc::now(),
    )
    .await?;
    let commit_intent = soland_services::identity::RecordAgentPairingCommitIntentCommand {
        agent_id: agent_id.to_owned(),
        approval_request_id: agent_record.approval_request_id.clone().ok_or_else(|| {
            pairing_failed_precondition("agent pairing approval metadata is incomplete")
        })?,
        runtime_key_binding_digest: agent_record.runtime_key_binding_digest.clone().ok_or_else(
            || pairing_failed_precondition("agent runtime key binding metadata is incomplete"),
        )?,
        pairing_request_id: body.pairing_request_id.clone(),
        request_digest: paired_request_digest.clone(),
        authorize_event_id: event_id.to_owned(),
        signing_key_binding: body.signing_key_binding.clone(),
    };
    let committed = state
        .agent_pairings()
        .record_pairing_commit_intent(&commit_intent)
        .await
        .map_err(|error| {
            AppError::internal(format!(
                "agent pairing commit intent persist failed: {error}"
            ))
        })?;
    if committed.is_none() {
        let current = state
            .agent_pairings()
            .agent(agent_id)
            .await
            .map_err(|error| {
                AppError::internal(format!(
                    "agent pairing commit intent reload failed: {error}"
                ))
            })?;
        if current.as_ref().is_some_and(|record| {
            record
                .pending_pairing_commit_intent
                .as_ref()
                .is_some_and(|intent| {
                    intent.request_digest != paired_request_digest
                        || intent.authorize_event_id != event_id
                        || intent.signing_key_binding.as_ref() != Some(&body.signing_key_binding)
                })
        }) {
            return Err(AppError::conflict(
                "pairing handle is already bound to a different final request",
            )
            .with_wire_code("duplicate_conflict"));
        }
        return Err(pairing_failed_precondition(
            "runtime approval was already consumed or changed",
        ));
    }
    let authorize_event_value = serde_json::to_value(&body.authorize_event.event)
        .map_err(|error| AppError::param_invalid(format!("authorize_event invalid: {error}")))?;
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
        body.signing_key_binding.public_key_digest.as_str(),
        body.authorize_event.clone(),
    )
    .await?;
    let authorized_event_ref = EventId::new(event_id)
        .map_err(|err| AppError::internal(format!("authorize event id invalid: {err}")))?;
    // The Event is durable, but is intentionally not authorization state yet.
    // The controller client must publish the successor managed-PCR Seal and
    // retry this exact idempotent request. Reconciliation above performs the
    // only pending->active transition after portable evidence materializes.
    json_ok(AgentKeyPairOutcome {
        ok: true,
        activation_state: AgentKeyPairActivationState::AwaitingAcceptedFrontier,
        authorize_event_ref: authorized_event_ref,
        signing_key_binding: body.signing_key_binding,
    })
}

pub(super) fn service_pairing_controller_device_id(
    body: &AgentKeyPairRequestBody,
    controller_id: &str,
) -> Result<String, AppError> {
    let submission = &body.authorize_event;
    let agent_core = body.agent_id.clone();
    if submission.event.actor_id != agent_core
        || submission
            .authorization_lease
            .as_ref()
            .is_some_and(|lease| lease.actor_id != agent_core)
    {
        return Err(AppError::capability_denied(
            "delegated pairing Event and any delayed authorization lease must name the managed Agent",
        ));
    }
    if submission
        .event
        .executed_by
        .as_ref()
        .map(arkret_wire::DidCoreId::as_str)
        != Some(controller_id)
    {
        return Err(AppError::capability_denied(
            "delegated pairing Event executor must match the controller",
        ));
    }

    let verification_method = submission
        .event
        .proofs
        .first()
        .and_then(arkret_wire::EventProof::as_producer)
        .map(|proof| proof.verification_method.as_str())
        .ok_or_else(|| {
            AppError::capability_denied(
                "delegated pairing Event must carry a controller device proof",
            )
        })?;
    let (verification_method_principal, device_id) =
        verification_method.split_once('#').ok_or_else(|| {
            AppError::capability_denied(
                "delegated pairing Event proof must use a controller verification method",
            )
        })?;
    let verification_method_controller =
        arkret_wire::DidFullId::new(verification_method_principal.to_owned())
            .and_then(|full_id| arkret_wire::project_full_id_to_core_id(&full_id))
            .map_err(|_| {
                AppError::capability_denied(
                    "delegated pairing Event proof must use a controller verification method",
                )
            })?;
    if verification_method_controller.as_str() != controller_id {
        return Err(AppError::capability_denied(
            "delegated pairing Event proof must use a controller verification method",
        ));
    }
    arkret_wire::DeviceId::new(device_id.to_owned()).map_err(|_| {
        AppError::capability_denied(
            "delegated pairing Event proof must name a typed controller device",
        )
    })?;
    if submission
        .authorization_lease
        .as_ref()
        .is_some_and(|lease| lease.device_id.as_str() != device_id)
    {
        return Err(AppError::capability_denied(
            "delayed authorization lease device does not match the controller proof",
        ));
    }
    Ok(device_id.to_owned())
}

/// The canonical `ak.component.agent.key.v1` cell for one `(agent_id, key_id)`
/// pair, matching the registry's composite `cell_subject` derivation.
pub(super) fn agent_key_cell_ref(
    agent_id: &arkret_identifiers::DidCoreId,
    key_id: &str,
) -> Result<arkret_identifiers::CellRef, AppError> {
    let subject = arkret_wire::composite_subject(&[agent_id.as_str(), key_id])
        .map_err(|error| AppError::param_invalid(format!("agent key subject invalid: {error}")))?;
    arkret_identifiers::CellRef::new(format!("ak:cell:ak.component.agent.key.v1:{subject}"))
        .map_err(|error| AppError::param_invalid(format!("agent key cell invalid: {error}")))
}

fn validate_agent_key_authorize_effects(event: &arkret_wire::Event) -> Result<(), AppError> {
    let payload = serde_json::from_value::<
        arkret_models_collaboration::events_payloads::agent::AgentKeyAuthorizePayload,
    >(serde_json::to_value(&event.payload).map_err(|error| {
        AppError::param_invalid(format!("authorize_event.payload invalid: {error}"))
    })?)
    .map_err(|error| {
        AppError::param_invalid(format!("authorize_event.payload invalid: {error}"))
    })?;
    // v1 carries no producer `effects[]`: the writes are derived from
    // `kind + payload` by the registered contract (`event-and-patch.md`
    // §2.4.2). `ak.agent.key.authorize` projects an atomic or_set
    // remove-observed + add pair on the agent-key cell for
    // `(payload.agent_id, payload.key_id)` (`key-management.md` §3.6.1), so
    // the only thing to assert is that the contract derives exactly that pair
    // for this Event.
    let derived =
        arkret_schema::project_registered_cell_writes(event, arkret_canonical::DigestSuite::Sha256)
            .map_err(|error| {
                AppError::param_invalid(format!(
                    "authorize_event Agent key projection failed: {error}"
                ))
            })?;
    let expected_cell = agent_key_cell_ref(&payload.agent_id, &payload.key_id)?;
    if derived.len() != 2 || derived.iter().any(|write| write.cell != expected_cell) {
        return Err(AppError::param_invalid(
            "authorize_event must derive the atomic Agent key re-authorization pair on its own key cell",
        ));
    }
    Ok(())
}

async fn validate_agent_signing_key_binding(
    body: &AgentKeyPairRequestBody,
    controller_id: &str,
    runtime_public_key_digest: &str,
    state: &AppState,
) -> Result<(), AppError> {
    validate_agent_signing_key_binding_parts(
        &body.signing_key_binding,
        &body.authorize_event.event,
        &body.agent_id,
        &body.verification_method,
        controller_id,
        runtime_public_key_digest,
        state,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn validate_agent_signing_key_binding_parts(
    binding: &arkret_models_identity::agent_signer_evidence::AgentSigningKeyBinding,
    authorize_event: &arkret_wire::Event,
    agent_id: &arkret_wire::DidCoreId,
    verification_method: &arkret_wire::DidUrl,
    controller_id: &str,
    runtime_public_key_digest: &str,
    state: &AppState,
) -> Result<(), AppError> {
    let agent_actor_id = agent_id.clone();
    let payload = &authorize_event.payload;
    let expected_binding_digest = payload
        .get("signing_key_binding_digest")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            AppError::param_invalid(
                "authorize_event.payload.signing_key_binding_digest is required",
            )
        })?;
    let actual_binding_digest =
        arkret_signatures::agent_evidence::agent_signing_key_binding_digest(binding)
            .map_err(|reason| AppError::param_invalid(reason.as_str()))?;
    if actual_binding_digest.as_str() != expected_binding_digest {
        return Err(AppError::param_invalid(
            "authorize_event.payload.signing_key_binding_digest must bind signing_key_binding",
        ));
    }
    for (matches, field) in [
        (binding.agent_id == agent_actor_id, "agent_id"),
        (
            payload.get("key_id").and_then(Value::as_str) == Some(binding.agent_key_id.as_str()),
            "agent_key_id",
        ),
        (
            binding.verification_method == *verification_method,
            "verification_method",
        ),
        (
            binding.agent_key_authorize_event_id == authorize_event.event_id,
            "agent_key_authorize_event_id",
        ),
        (
            binding.controller_id.as_str() == controller_id,
            "controller_id",
        ),
    ] {
        if !matches {
            return Err(AppError::param_invalid(format!(
                "signing_key_binding {field} does not match the pairing request"
            )));
        }
    }
    let expected_authorization_digest = payload
        .get("public_key_digest")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            AppError::param_invalid("authorize_event.payload.public_key_digest is required")
        })
        .and_then(|value| {
            arkret_wire::Hash::new(value.to_owned())
                .map_err(|error| AppError::param_invalid(error.to_string()))
        })?;
    let expected_runtime_request_digest =
        arkret_wire::Hash::new(runtime_public_key_digest.to_owned())
            .map_err(|error| AppError::param_invalid(error.to_string()))?;
    arkret_signatures::agent_evidence::validate_agent_signing_key_binding_digest_domains(
        binding,
        verification_method,
        &expected_runtime_request_digest,
        &expected_authorization_digest,
    )
    .map_err(|reason| {
        AppError::param_invalid(format!(
            "signing_key_binding key material does not match its digest domains: {reason:?}"
        ))
    })?;
    let issued_at = payload
        .get("issued_at")
        .and_then(Value::as_str)
        .ok_or_else(|| AppError::param_invalid("authorize_event.payload.issued_at is required"))?;
    if arkret_canonical::format_timestamp_canonical(binding.issued_at) != issued_at {
        return Err(AppError::param_invalid(
            "signing_key_binding.issued_at must match authorize_event.payload.issued_at",
        ));
    }
    let payload_expires_at = payload.get("expires_at").and_then(Value::as_str);
    let binding_expires_at = binding
        .expires_at
        .map(arkret_canonical::format_timestamp_canonical);
    if binding_expires_at.as_deref() != payload_expires_at {
        return Err(AppError::param_invalid(
            "signing_key_binding.expires_at must match authorize_event.payload.expires_at",
        ));
    }
    let signing_bytes =
        arkret_signatures::agent_evidence::agent_signing_key_binding_signing_bytes(binding)
            .map_err(|reason| AppError::param_invalid(reason.as_str()))?;
    let proof_invalid = |reason: String| {
        AppError::param_invalid(format!(
            "signing_key_binding controller proof invalid: {reason}"
        ))
        .with_wire_code("agent_signing_key_mismatch")
    };
    // The controller proof is a principal-device detached JWS. Verify it
    // against the controller's explicit local account authority: the pairing
    // endpoint runs on the controller's Principal Server (the session was
    // already bound to the local controller account), so the authority
    // coordinate is `(controller_id, this service)` and the signer device is
    // the fragment of the controller proof's verification method.
    let controller_proof_method = binding.controller_proof.verification_method.as_str();
    let controller_device_id = controller_proof_method
        .rsplit_once('#')
        .map(|(_, fragment)| fragment)
        .ok_or_else(|| {
            proof_invalid("controller verification method has no device fragment".to_owned())
        })?;
    let controller_device_id = arkret_identifiers::DeviceId::new(controller_device_id.to_owned())
        .map_err(|error| {
        proof_invalid(format!(
            "controller verification method device fragment is invalid: {error}"
        ))
    })?;
    let authority = arkret_wire::PrincipalAuthorityKey::new(
        binding.controller_id.clone(),
        arkret_wire::DidCoreId::new(state.service_id().clone()).map_err(|error| {
            AppError::internal(format!("configured service_id invalid: {error}"))
        })?,
    );
    crate::jws_verify::verify_principal_authorized_jws_with_account_authority_async(
        &signing_bytes,
        binding.controller_proof.jws.as_str(),
        controller_proof_method,
        &authority,
        &controller_device_id,
        state,
    )
    .await
    .map_err(|error| proof_invalid(error.to_string()))
}

async fn validate_requested_scope_disclosure(
    body: &AgentKeyPairRequestBody,
    agent_record: &AgentPrincipalRecord,
    state: &AppState,
) -> Result<(), AppError> {
    let disclosure = &body.requested_scope_disclosure;
    disclosure.validate().map_err(|error| {
        AppError::param_invalid(format!("requested_scope_disclosure invalid: {error}"))
    })?;
    if disclosure.agent_id.as_str() != agent_record.id
        || disclosure.controller_id.as_str() != agent_record.controller_id
    {
        return Err(AppError::param_invalid(
            "requested_scope_disclosure principal binding does not match the Agent record",
        ));
    }
    if disclosure.verifier_service_id.as_str() != state.service_id()
        || disclosure.audience.as_str()
            != arkret_wire::ServiceOperationId::GATE_ACCOUNT_COMMAND_PAIR_AGENT_KEY
    {
        return Err(AppError::param_invalid(
            "requested_scope_disclosure verifier or audience does not match this operation",
        ));
    }
    let pairing_request_id = required_pairing_request_id(agent_record)?;
    let pairing_request_uuid = pairing_request_id
        .strip_prefix("agent_pairing_request:")
        .ok_or_else(|| incomplete_pairing_metadata("pairing_request_id"))?;
    if disclosure.request_id.as_str() != format!("ak:request:{pairing_request_uuid}")
        || disclosure.challenge.as_str() != pairing_request_id
    {
        return Err(AppError::param_invalid(
            "requested_scope_disclosure request or challenge does not match the open pairing request",
        ));
    }
    let now = chrono::Utc::now();
    if now < disclosure.issued_at || now > disclosure.expires_at {
        return Err(AppError::param_invalid(
            "requested_scope_disclosure presentation window is not active",
        ));
    }
    let stored_scope = agent_record.requested_scope.as_ref().ok_or_else(|| {
        AppError::new(
            ErrorCode::FailedPrecondition,
            "Agent record is missing its immutable requested_scope",
        )
    })?;
    let stored_scope: AgentKeyScope =
        serde_json::from_value(stored_scope.clone()).map_err(|error| {
            AppError::internal(format!("stored Agent requested_scope is invalid: {error}"))
        })?;
    let agent_id = arkret_wire::DidCoreId::new(agent_record.id.clone())
        .map_err(|error| AppError::internal(format!("stored Agent DID is invalid: {error}")))?;
    let controller_id = arkret_identifiers::DidCoreId::new(agent_record.controller_id.clone())
        .map_err(|error| {
            AppError::internal(format!("stored Agent controller DID is invalid: {error}"))
        })?;
    let stored_digest = arkret_signatures::agent::agent_requested_scope_digest(
        &agent_id,
        &controller_id,
        &stored_scope,
    )
    .map_err(|error| {
        AppError::internal(format!(
            "stored Agent requested_scope digest failed: {error}"
        ))
    })?;
    let disclosed_digest = arkret_signatures::agent::agent_requested_scope_digest(
        &disclosure.agent_id,
        &disclosure.controller_id,
        &disclosure.requested_scope,
    )
    .map_err(|error| AppError::param_invalid(error.to_string()))?;
    if disclosed_digest != stored_digest {
        return Err(AppError::param_invalid(
            "requested_scope_disclosure does not match the provisioned Agent ceiling",
        ));
    }
    let mut proof_errors = Vec::new();
    for proof in &disclosure.proofs {
        if proof.created_at < disclosure.issued_at || proof.created_at > disclosure.expires_at {
            proof_errors.push("proof created_at is outside the disclosure window".to_owned());
            continue;
        }
        if let Err(error) = crate::jws_verify::validate_verification_method_controller(
            disclosure.controller_id.as_str(),
            &proof.verification_method,
        ) {
            proof_errors.push(error);
            continue;
        }
        let binding_bytes = match disclosure.canonical_proof_binding_bytes(proof) {
            Ok(bytes) => bytes,
            Err(error) => {
                proof_errors.push(error.to_string());
                continue;
            }
        };
        let verification = if state.config().development_mode {
            crate::jws_verify::verify_jws_shape(
                &binding_bytes,
                &proof.jws,
                &proof.verification_method,
                disclosure.controller_id.as_str(),
            )
        } else {
            crate::jws_verify::verify_did_controlled_jws_async(
                &binding_bytes,
                &proof.jws,
                &proof.verification_method,
                disclosure.controller_id.as_str(),
                state,
            )
            .await
        };
        if verification.is_ok() {
            return Ok(());
        }
        proof_errors.push(verification.unwrap_err());
    }
    Err(AppError::param_invalid(format!(
        "requested_scope_disclosure has no valid controller proof: {}",
        proof_errors.join("; ")
    )))
}

fn ensure_current_runtime_key_request_matches(
    agent_record: &AgentPrincipalRecord,
    body: &AgentKeyPairRequestBody,
) -> Result<(), AppError> {
    let current = agent_record
        .runtime_key_request
        .as_ref()
        .ok_or_else(|| pairing_failed_precondition("runtime key request is no longer pending"))?;
    let fields_match = current.pairing_request_id == body.pairing_request_id
        && current.agent_id == body.agent_id
        && current.verification_method == body.verification_method
        && current.public_key == body.public_key
        && current.proof_of_possession == body.proof_of_possession
        && current.runtime_attestation == body.runtime_attestation;
    if !fields_match {
        return Err(pairing_failed_precondition(
            "controller approval does not match the current runtime key request",
        ));
    }
    let agent_id = arkret_wire::DidCoreId::new(body.agent_id.as_str().to_owned())
        .map_err(|error| AppError::param_invalid(format!("agent_id invalid: {error}")))?;
    let current_binding = arkret_signatures::agent::agent_runtime_key_binding_digest(
        &agent_id,
        &body.pairing_request_id,
        &body.verification_method,
        &body.public_key,
        runtime_attestation_value(body.runtime_attestation.as_ref())?.as_ref(),
    )
    .map_err(|error| AppError::param_invalid(format!("runtime key binding invalid: {error}")))?;
    if agent_record.runtime_key_binding_digest.as_deref() != Some(current_binding.as_str()) {
        return Err(pairing_failed_precondition(
            "runtime key binding changed after controller discovery",
        ));
    }
    Ok(())
}

pub(super) struct AccountNotificationContext {
    notification_id: arkret_wire::NotificationId,
    recipient_id: arkret_wire::DidCoreId,
    controller_account_id: String,
    recipient_service_id: arkret_wire::DidCoreId,
    approval_request_id: arkret_wire::OpaqueLocalId,
}

pub(super) fn account_notification_context(
    agent_record: &AgentPrincipalRecord,
) -> Option<AccountNotificationContext> {
    Some(AccountNotificationContext {
        notification_id: arkret_wire::NotificationId::new(ids::format_typed_uuid(
            "notification",
            &agent_record.approval_notification_id?,
        ))
        .ok()?,
        recipient_id: arkret_identifiers::DidCoreId::new(agent_record.controller_id.clone())
            .ok()?,
        controller_account_id: ids::format_typed_uuid(
            "account",
            &agent_record.controller_account_id?,
        ),
        recipient_service_id: arkret_identifiers::DidCoreId::new(
            agent_record.recipient_service_id.clone()?,
        )
        .ok()?,
        approval_request_id: agent_record.approval_request_id.clone()?,
    })
}

pub(super) async fn persist_terminal_account_notification(
    state: &AppState,
    context: AccountNotificationContext,
    reason: arkret_models_collaboration::sync_frames::account_sync::AgentRuntimeApprovalRemovalReason,
) -> Result<(), AppError> {
    let delta =
        arkret_models_collaboration::sync_frames::account_sync::NotificationDelta::try_new(
            context.notification_id,
            arkret_wire::NotificationKind::Agent,
            arkret_models_collaboration::sync_frames::account_sync::NotificationDeltaAction::Remove,
            Some(
                arkret_models_collaboration::sync_frames::account_sync::NotificationData::AgentRuntimeApprovalRemoval(
                    arkret_models_collaboration::sync_frames::account_sync::AgentRuntimeApprovalNotificationRemovalData {
                        kind: arkret_models_collaboration::sync_frames::account_sync::AccountNotificationDataKind::AgentRuntimeApproval,
                        reason,
                    },
                ),
            ),
        )
        .map_err(|error| {
            AppError::internal(format!("terminal notification delta is invalid: {error}"))
        })?;
    state
        .deliveries()
        .store_account_delta(
            soland_services::delivery::StoreAccountNotificationDeltaCommand {
                record: soland_services::delivery::AccountNotificationDeltaWrite {
                    delta,
                    recipient_id: context.recipient_id,
                    controller_account_id: context.controller_account_id.clone(),
                    recipient_service_id: context.recipient_service_id.clone(),
                    source_account_artifact_id: context.approval_request_id.to_string(),
                },
            },
        )
        .await
        .map_err(|error| {
            AppError::internal(format!(
                "terminal approval notification save failed: {error}"
            ))
        })?;
    let _ = state.publish_event_notification(crate::state::EventNotification::account(
        context.controller_account_id,
        context.recipient_service_id.to_string(),
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
    reason: arkret_models_collaboration::sync_frames::account_sync::AgentRuntimeApprovalRemovalReason,
) -> Result<(), AppError> {
    let approval_request_id = context.approval_request_id.clone();
    persist_terminal_account_notification(state, context, reason).await?;
    state
        .agent_pairings()
        .clear_approval_notification(agent_id, &approval_request_id)
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
    authorized_public_key_digest: &str,
    submission: arkret_wire::EventInitialSubmission,
) -> Result<String, AppError> {
    ensure_key_authorize_event_matches_request(
        envelope,
        &session.actor,
        agent_record,
        agent_id,
        verification_method,
        authorized_public_key_digest,
        state.service_id(),
    )?;
    let outcome = crate::routing::events::event_log::submit_initial_event_submission(
        state, session, submission,
    )
    .await
    .map_err(|error| {
        AppError::param_invalid(format!(
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
    authorized_public_key_digest: &str,
    service_id: &str,
) -> Result<(), AppError> {
    if envelope.get("kind").and_then(Value::as_str)
        != Some(arkret_wire::event_kind_str::AGENT_KEY_AUTHORIZE)
    {
        return Err(AppError::param_invalid(
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
        .ok_or_else(|| AppError::param_invalid("authorize_event.payload is required"))?;
    if payload.get("agent_id").and_then(Value::as_str) != Some(agent_id) {
        return Err(AppError::param_invalid(
            "authorize_event.payload.agent_id must match the pairing request",
        ));
    }
    if payload.get("verification_method").and_then(Value::as_str) != Some(verification_method) {
        return Err(AppError::param_invalid(
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
        .ok_or_else(|| AppError::param_invalid("authorize_event.payload.audience is required"))?;
    if !audience
        .iter()
        .any(|value| value.as_str() == Some(service_id))
    {
        return Err(AppError::param_invalid(
            "authorize_event.payload.audience must include this principal server",
        ));
    }
    if let Some(expires_at) = payload.get("expires_at") {
        let expires_at = expires_at
            .as_str()
            .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
            .ok_or_else(|| {
                AppError::param_invalid("authorize_event.payload.expires_at must be rfc3339")
            })?;
        if expires_at.with_timezone(&chrono::Utc) <= chrono::Utc::now() {
            return Err(pairing_failed_precondition(
                "authorize_event payload has expired",
            ));
        }
    }
    if payload.get("public_key_digest").and_then(Value::as_str)
        != Some(authorized_public_key_digest)
    {
        return Err(AppError::param_invalid(
            "authorize_event.payload.public_key_digest must bind the raw signing key",
        ));
    }
    let expected_digest = pairing_request_binding_digest(
        agent_record,
        controller,
        agent_id,
        verification_method,
        service_id,
    )?;
    let approval_evidence = payload.get("approval_evidence").ok_or_else(|| {
        AppError::param_invalid("authorize_event.payload.approval_evidence is required")
    })?;
    if approval_evidence.get("kind").and_then(Value::as_str) != Some("pairing_request") {
        return Err(AppError::param_invalid(
            "authorize_event.payload.approval_evidence.kind must be pairing_request",
        ));
    }
    if approval_evidence.get("evidence_ref").is_some() {
        return Err(AppError::param_invalid(
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
        return Err(AppError::param_invalid(
            "authorize_event.payload.approval_evidence.pairing_request_id must match the pairing request",
        ));
    }
    if approval_evidence
        .get("request_canonical_digest")
        .and_then(Value::as_str)
        != Some(expected_digest.as_str())
    {
        return Err(AppError::param_invalid(
            "authorize_event.payload.approval_evidence.request_canonical_digest must bind the pairing request",
        ));
    }
    Ok(())
}

fn agent_key_pair_request_digest(body: &AgentKeyPairRequestBody) -> Result<String, AppError> {
    let value = serde_json::to_value(body)
        .map_err(|error| AppError::param_invalid(format!("pairing request invalid: {error}")))?;
    let canonical = arkret_canonical::canonical_json_bytes(&value).map_err(|error| {
        AppError::param_invalid(format!("pairing request canonicalization failed: {error}"))
    })?;
    Ok(arkret_canonical::sha256_digest(&canonical))
}

pub(super) fn ensure_pairing_request_open(
    agent_record: &AgentPrincipalRecord,
) -> Result<(), AppError> {
    // Only the terminal lifecycle intent forbids completing a pairing
    // (key-management.md §3.6.1). Both active and paused agents may complete a
    // bootstrap or replacement handle; completion atomically supersedes any
    // prior active key with no forced pause. renew_pairing rotates
    // `pairing_request_id` while leaving the last consumed handle in
    // `paired_pairing_request_id`, so a live handle exists iff the current one
    // has not yet been consumed.
    if agent_record.state == AgentLifecycleState::Deactivated {
        return Err(pairing_failed_precondition(
            "agent is not accepting runtime key pairing",
        ));
    }
    if !agent_pairing_handle_is_open(agent_record) {
        return Err(pairing_failed_precondition(
            "agent has no open runtime key pairing handle",
        ));
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
    // A deactivated agent releases its slug. A keyed agent (ever completed a
    // first pairing) always reserves it. A never-keyed agent reserves the slug
    // only while its bootstrap window is still live; once it lapses the slug is
    // released for a fresh provision (key-management.md §3.6.1).
    if agent_record.state == AgentLifecycleState::Deactivated {
        return false;
    }
    if agent_record.authorized_event_ref.is_some() {
        return true;
    }
    agent_pairing_handle_is_open(agent_record)
        && agent_record
            .pairing_expires_at
            .map(|expires_at| expires_at > *now)
            .unwrap_or(false)
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

pub(super) fn runtime_key_request_for_controller(
    body: &AgentRuntimeApprovalRequestBody,
) -> arkret_models_collaboration::agent_operations::AgentRuntimeApprovalControllerProjection {
    arkret_models_collaboration::agent_operations::AgentRuntimeApprovalControllerProjection {
        pairing_request_id: body.pairing_request_id.clone(),
        agent_id: body.agent_id.clone(),
        verification_method: body.verification_method.clone(),
        public_key: body.public_key.clone(),
        proof_of_possession: body.proof_of_possession.clone(),
        runtime_attestation: body.runtime_attestation.clone(),
    }
}

fn runtime_attestation_value(
    runtime_attestation: Option<&arkret_models_collaboration::events_payloads::agent::AgentKeyAuthorizePayloadRuntimeAttestation>,
) -> Result<Option<Value>, AppError> {
    runtime_attestation
        .map(serde_json::to_value)
        .transpose()
        .map_err(|error| AppError::param_invalid(format!("runtime_attestation invalid: {error}")))
}

pub(super) fn runtime_ed25519_public_key(
    public_key: &PublicKey,
    verification_method: &str,
) -> Result<[u8; 32], AppError> {
    let verification_method = arkret_wire::DidUrl::new(verification_method.to_owned())
        .map_err(|error| AppError::param_invalid(error.to_string()))?;
    arkret_signatures::agent::validate_agent_runtime_public_key(public_key, &verification_method)
        .map(|validated| validated.raw_public_key)
        .map_err(|error| AppError::param_invalid(format!("public_key invalid: {error}")))
}

pub(super) fn verify_runtime_key_pair_proof_of_possession(
    body: &AgentKeyPairRequestBody,
    agent_record: &AgentPrincipalRecord,
    agent_id: &str,
    service_id: &str,
) -> Result<(), AppError> {
    verify_runtime_key_proof_of_possession(
        &body.pairing_request_id,
        &body.verification_method,
        &body.public_key,
        &body.proof_of_possession,
        body.runtime_attestation.as_ref(),
        required_pairing_code(agent_record)?,
        required_pairing_expires_at(agent_record)?,
        agent_id,
        service_id,
    )
}

fn verify_runtime_approval_proof_of_possession(
    body: &AgentRuntimeApprovalRequestBody,
    agent_record: &AgentPrincipalRecord,
    agent_id: &str,
    service_id: &str,
) -> Result<(), AppError> {
    verify_runtime_key_proof_of_possession(
        &body.pairing_request_id,
        &body.verification_method,
        &body.public_key,
        &body.proof_of_possession,
        body.runtime_attestation.as_ref(),
        required_pairing_code(agent_record)?,
        required_pairing_expires_at(agent_record)?,
        agent_id,
        service_id,
    )
}

fn verify_runtime_key_proof_of_possession(
    pairing_request_id: &arkret_wire::OpaqueLocalId,
    verification_method: &arkret_wire::DidUrl,
    public_key: &PublicKey,
    proof_of_possession: &arkret_models_collaboration::agent_operations::AgentRuntimeKeyPossessionProof,
    runtime_attestation: Option<&arkret_models_collaboration::events_payloads::agent::AgentKeyAuthorizePayloadRuntimeAttestation>,
    pairing_code: &str,
    pairing_expires_at: chrono::DateTime<chrono::Utc>,
    agent_id: &str,
    service_id: &str,
) -> Result<(), AppError> {
    let agent_id = arkret_wire::DidCoreId::new(agent_id.to_owned())
        .map_err(|error| AppError::param_invalid(format!("agent_id invalid: {error}")))?;
    let service_id = arkret_wire::DidCoreId::new(service_id.to_owned())
        .map_err(|error| AppError::internal(format!("configured service_id invalid: {error}")))?;
    let public_key_bytes = runtime_ed25519_public_key(public_key, verification_method)?;
    if proof_of_possession.audience != service_id {
        return Err(AppError::param_invalid(
            "proof_of_possession.audience must match this principal server",
        ));
    }
    let expected_binding =
        arkret_models_collaboration::agent_operations::agent_runtime_key_binding_digest(
            &agent_id,
            pairing_request_id,
            verification_method,
            public_key,
            runtime_attestation,
        )
        .map_err(|error| {
            AppError::param_invalid(format!("runtime key binding invalid: {error}"))
        })?;
    let signing_bytes = proof_of_possession
        .validate_shape(
            &agent_id,
            pairing_request_id,
            verification_method,
            public_key,
            &expected_binding,
            pairing_code,
            pairing_expires_at,
            chrono::Utc::now(),
        )
        .map_err(|error| {
            AppError::param_invalid(format!("proof_of_possession invalid: {error}"))
        })?;
    let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&public_key_bytes)
        .map_err(|error| AppError::param_invalid(format!("public_key invalid: {error}")))?;
    let signature_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(proof_of_possession.signature.as_bytes())
        .map_err(|_| AppError::param_invalid("proof_of_possession.signature is not base64url"))?;
    let signature = ed25519_dalek::Signature::from_slice(&signature_bytes).map_err(|_| {
        AppError::param_invalid("proof_of_possession.signature must be a 64-byte Ed25519 signature")
    })?;
    verifying_key
        .verify(&signing_bytes, &signature)
        .map_err(|_| AppError::param_invalid("proof_of_possession.signature is invalid"))?;
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
    let verification_method = arkret_wire::DidUrl::new(verification_method.to_owned())
        .map_err(|error| AppError::param_invalid(error.to_string()))?;
    arkret_signatures::agent::validate_agent_runtime_public_key(public_key, &verification_method)
        .map(|validated| validated.runtime_request_digest.as_str().to_owned())
        .map_err(|error| AppError::param_invalid(format!("public_key is invalid: {error}")))
}

pub(super) fn ensure_authorize_event_scope_within_requested(
    agent_record: &AgentPrincipalRecord,
    payload: &Value,
) -> Result<(), AppError> {
    let scope = payload.get("agent_key_scope").ok_or_else(|| {
        AppError::param_invalid("authorize_event.payload.agent_key_scope is required")
    })?;
    let actions = scope
        .get("actions")
        .and_then(Value::as_array)
        .filter(|actions| !actions.is_empty())
        .ok_or_else(|| {
            AppError::param_invalid("authorize_event.payload.agent_key_scope.actions is required")
        })?;
    if actions
        .iter()
        .any(|action| action.as_str().is_none_or(str::is_empty))
    {
        return Err(AppError::param_invalid(
            "authorize_event.payload.agent_key_scope.actions must be non-empty strings",
        ));
    }
    if !agent_key_scope_within_requested_scope(agent_record, scope) {
        return Err(AppError::param_invalid(
            "authorize_event.payload.agent_key_scope must be within the provisioned requested_scope",
        ));
    }
    Ok(())
}

pub(super) fn pairing_request_binding_digest(
    agent_record: &AgentPrincipalRecord,
    controller: &str,
    agent_id: &str,
    _verification_method: &str,
    service_id: &str,
) -> Result<String, AppError> {
    let pairing_request_id =
        arkret_wire::OpaqueLocalId::new(required_pairing_request_id(agent_record)?.to_owned())
            .map_err(|error| {
                AppError::internal(format!("stored pairing request id invalid: {error}"))
            })?;
    let pairing_code = required_pairing_code(agent_record)?;
    let expires_at = required_pairing_expires_at(agent_record)?;
    let controller = arkret_wire::DidCoreId::new(controller.to_owned())
        .map_err(|error| AppError::param_invalid(format!("controller DID invalid: {error}")))?;
    let agent_id = arkret_wire::DidCoreId::new(agent_id.to_owned())
        .map_err(|error| AppError::param_invalid(format!("agent DID invalid: {error}")))?;
    let audience = arkret_wire::DidCoreId::new(service_id.to_owned()).map_err(|error| {
        AppError::internal(format!("configured service core_id invalid: {error}"))
    })?;
    let runtime_key_binding_digest = Hash::new(
        agent_record
            .runtime_key_binding_digest
            .clone()
            .ok_or_else(|| incomplete_pairing_metadata("runtime_key_binding_digest"))?,
    )
    .map_err(|_| AppError::internal("stored runtime key binding digest is invalid"))?;
    let proof = &agent_record
        .runtime_key_request
        .as_ref()
        .ok_or_else(|| incomplete_pairing_metadata("runtime_key_request"))?
        .proof_of_possession;
    arkret_models_collaboration::agent_operations::agent_key_pairing_request_binding_digest(
        arkret_wire::ServiceOperationId::GATE_ACCOUNT_COMMAND_PAIR_AGENT_KEY,
        &controller,
        &agent_id,
        &pairing_request_id,
        pairing_code,
        expires_at,
        &audience,
        &runtime_key_binding_digest,
        proof,
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

    #[test]
    fn pairing_activation_requires_active_portable_authorization_evidence() {
        use arkret_models_identity::agent_signer_evidence::AgentAuthorizationStatus;

        assert!(!authorization_status_allows_activation(None));
        assert!(!authorization_status_allows_activation(Some(
            AgentAuthorizationStatus::Revoked
        )));
        assert!(!authorization_status_allows_activation(Some(
            AgentAuthorizationStatus::Conflicted
        )));
        assert!(authorization_status_allows_activation(Some(
            AgentAuthorizationStatus::Active
        )));
    }

    fn agent_record(requested_scope: Option<Value>) -> AgentPrincipalRecord {
        let mut record = AgentPrincipalRecord::new(
            "ak:did_core:web:agent.example".to_owned(),
            "ak:did_core:web:controller.example".to_owned(),
            "ak:realm:ASt7OPzypn1OkvoZOKtcz8H8ydfZ7fLDhL3nI1jLWTfX".to_owned(),
            arkret_wire::DidUrl::new("did:web:controller.example#controller").unwrap(),
            AgentLifecycleState::Active,
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
                    "operation": "ak.self.events.read.scan"
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
        record.recipient_service_id = Some("ak:did_core:web:soland.example".to_owned());
        record.approval_request_id =
            Some(arkret_wire::OpaqueLocalId::new("agent_runtime_approval:test").unwrap());

        let context = account_notification_context(&record).expect("complete notification context");

        assert_eq!(
            context.notification_id.as_str(),
            "ak:notification:019f6131-3dc4-76f1-ade6-00f4225a8528"
        );
        assert_eq!(
            context.controller_account_id,
            "ak:account:019f6131-3dc4-76f1-ade6-00f4225a8529"
        );
    }

    #[test]
    fn active_and_paused_agents_complete_pairing_without_forced_pause() {
        let now = chrono::Utc::now();
        let mut record = agent_record(None);
        record.pairing_request_id =
            Some(arkret_wire::OpaqueLocalId::new("agent_pairing_request:open").unwrap());
        record.pairing_expires_at = Some(now + chrono::Duration::minutes(5));

        // Both active and paused agents may complete an open bootstrap or
        // replacement handle; there is no forced pause (key-management.md
        // §3.6.1) and resume never interlocks with an open handle.
        record.state = AgentLifecycleState::Active;
        assert!(ensure_pairing_request_open(&record).is_ok());
        record.state = AgentLifecycleState::Paused;
        assert!(ensure_pairing_request_open(&record).is_ok());

        // Deactivation is terminal.
        record.state = AgentLifecycleState::Deactivated;
        assert!(ensure_pairing_request_open(&record).is_err());

        // A consumed handle is no longer open.
        record.state = AgentLifecycleState::Active;
        record.paired_pairing_request_id = record.pairing_request_id.clone();
        assert!(ensure_pairing_request_open(&record).is_err());

        // An expired handle is rejected.
        record.paired_pairing_request_id = None;
        record.pairing_expires_at = Some(now - chrono::Duration::seconds(1));
        assert!(ensure_pairing_request_open(&record).is_err());
    }
}
