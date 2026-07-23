use super::*;

const AGENT_PROVISION_ALLOCATION_TTL_HOURS: i64 = 24;

fn agent_provision_allocation_key(agent_id: &Did) -> String {
    format!("agent-provision-allocation:{}", agent_id.as_str())
}

fn agent_provision_allocation_hash(
    controller_id: &str,
    agent_id: &Did,
    principal_control_realm_id: &RealmId,
    display_name: Option<&str>,
    agent_slug: &str,
    avatar_blob_ref: Option<&str>,
    requested_scope: &Value,
    pairing_ttl_ms: Option<u64>,
) -> Result<String, AppError> {
    arkret_canonical::canonical_sha256(&json!({
        "controller_id": controller_id,
        "agent_id": agent_id,
        "principal_control_realm_id": principal_control_realm_id,
        "display_name": display_name,
        "slug": agent_slug,
        "avatar_blob_ref": avatar_blob_ref,
        "requested_scope": requested_scope,
        "pairing_ttl_ms": pairing_ttl_ms,
    }))
    .map(|digest| digest.to_string())
    .map_err(|error| {
        AppError::internal(format!("Agent provision allocation digest failed: {error}"))
    })
}

#[allow(clippy::too_many_arguments)]
async fn require_agent_provision_allocation(
    state: &AppState,
    controller_id: &str,
    agent_id: &Did,
    principal_control_realm_id: &RealmId,
    display_name: Option<&str>,
    agent_slug: &str,
    avatar_blob_ref: Option<&str>,
    requested_scope: &Value,
    pairing_ttl_ms: Option<u64>,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<soland_application::jobs::IdempotencyState, AppError> {
    let key = agent_provision_allocation_key(agent_id);
    let allocation = state
        .jobs_application()
        .idempotency_record(controller_id, &key)
        .await
        .map_err(|error| {
            AppError::internal(format!("Agent provision allocation lookup failed: {error}"))
        })?
        .filter(|record| record.expires_at > now && record.service_id == *state.service_id())
        .ok_or_else(|| {
            AppError::new(
                ErrorCode::FailedPrecondition,
                "Agent provision commit has no active server allocation",
            )
            .with_status(StatusCode::PRECONDITION_FAILED)
            .with_reason_code("agent_provision_allocation_missing")
        })?;
    let expected_hash = agent_provision_allocation_hash(
        controller_id,
        agent_id,
        principal_control_realm_id,
        display_name,
        agent_slug,
        avatar_blob_ref,
        requested_scope,
        pairing_ttl_ms,
    )?;
    if allocation.request_hash != expected_hash {
        return Err(AppError::new(
            ErrorCode::FailedPrecondition,
            "Agent provision commit differs from its server allocation",
        )
        .with_status(StatusCode::PRECONDITION_FAILED)
        .with_reason_code("agent_provision_allocation_mismatch"));
    }
    Ok(allocation)
}

#[handler]
#[tracing::instrument(skip_all, fields(op = "ak.self.agent.command.provision"))]
pub(super) async fn provision_agent(
    aa: AuthArgs,
    body: JsonBody<AgentProvisionRequestBody>,
    depot: &mut Depot,
    res: &mut Response,
    req: &mut Request,
) -> JsonResult<AgentProvisionOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let body = body.into_inner();
    // Spec `agent_provision_request_body` carries no controller_id —
    // the controller is ALWAYS the authenticated principal.
    let controller_id = session.actor.clone();
    let (
        prepared_ids,
        display_name,
        agent_slug,
        avatar_blob_ref,
        requested_scope_typed,
        provision_events,
        pairing_ttl_ms,
    ) = match body {
        AgentProvisionRequestBody::Prepare {
            display_name,
            slug,
            avatar_blob_ref,
            requested_scope,
            pairing_ttl_ms,
        } => (
            None,
            display_name,
            slug,
            avatar_blob_ref,
            requested_scope,
            None,
            pairing_ttl_ms,
        ),
        AgentProvisionRequestBody::Commit {
            agent_id,
            principal_control_realm_id,
            display_name,
            slug,
            avatar_blob_ref,
            requested_scope,
            provision_events,
            pairing_ttl_ms,
        } => (
            Some((agent_id, principal_control_realm_id)),
            display_name,
            slug,
            avatar_blob_ref,
            requested_scope,
            Some(provision_events),
            pairing_ttl_ms,
        ),
    };
    let display_name = display_name
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned);
    let agent_slug = arkret_wire::string_profiles::prepare_agent_slug(agent_slug.trim())
        .map_err(|err| AppError::invalid_param(format!("slug is invalid: {err}")))?;
    let avatar_blob_ref = avatar_blob_ref.map(|value| value.to_string());
    let now_utc = chrono::DateTime::<chrono::Utc>::from_timestamp_millis(
        chrono::Utc::now().timestamp_millis(),
    )
    .ok_or_else(|| AppError::internal("current agent provision timestamp is out of range"))?;
    validate_agent_slug(&agent_slug)
        .map_err(|err| AppError::invalid_param(format!("slug is invalid: {err}")))?;
    let requested_scope = serde_json::to_value(&requested_scope_typed)
        .map_err(|error| AppError::invalid_param(format!("requested_scope is invalid: {error}")))?;
    let active_recovery_policy = state
        .recovery_policy_application()
        .active_policy(&controller_id)
        .await
        .map_err(|error| {
            AppError::internal(format!("controller recovery policy lookup failed: {error}"))
        })?;
    if active_recovery_policy.is_none() {
        return Err(AppError::new(
            ErrorCode::FailedPrecondition,
            "controller must accept a recovery policy before provisioning a managed Agent",
        )
        .with_status(StatusCode::PRECONDITION_FAILED)
        .with_reason_code("recovery_policy_required"));
    }
    let controller_realm = require_controller_principal_control_realm(state, &session).await?;
    let existing = state
        .agent_pairing_application()
        .agents_for_controller(&controller_id)
        .await
        .map_err(|err| AppError::internal(format!("agent slug conflict check failed: {err}")))?;
    let mut existing: Vec<_> = existing.into_iter().collect();
    for record in existing.iter_mut() {
        *record = lazily_expire_pairing(state, record.clone()).await?;
    }
    if let Some((prepared_agent_id, prepared_realm_id)) = &prepared_ids
        && let Some(record) = existing
            .iter()
            .find(|record| record.id == prepared_agent_id.as_str())
    {
        let events = provision_events
            .as_ref()
            .expect("commit phase carries provision_events");
        let refs_match = record.provision_event_refs.as_ref().is_some_and(|refs| {
            refs.get("accountability_grant_event_id")
                .and_then(Value::as_str)
                == Some(events.accountability_grant.event_id.as_str())
                && refs.get("selector_claim_event_id").and_then(Value::as_str)
                    == Some(events.selector_claim.event_id.as_str())
        });
        if record.controller_id != controller_id
            || record.principal_control_realm_id != prepared_realm_id.as_str()
            || record.agent_slug.as_deref() != Some(agent_slug.as_str())
            || record.requested_scope.as_ref() != Some(&requested_scope)
            || !refs_match
        {
            return Err(AppError::conflict(
                "agent provision commit reuses an allocated agent_id with different inputs",
            ));
        }
        let requested_scope_digest = arkret_signatures::agent::agent_requested_scope_digest(
            prepared_agent_id,
            &Did::new(controller_id.clone())
                .map_err(|error| AppError::internal(format!("controller DID invalid: {error}")))?,
            &requested_scope_typed,
        )
        .map_err(|error| AppError::internal(format!("requested_scope digest failed: {error}")))?;
        let pairing_request_id = record.pairing_request_id.clone().ok_or_else(|| {
            AppError::internal("completed Agent provision is missing pairing_request_id")
        })?;
        let expires_at = record.pairing_expires_at.ok_or_else(|| {
            AppError::internal("completed Agent provision is missing pairing_expires_at")
        })?;
        res.status_code(StatusCode::CREATED);
        return json_ok(AgentProvisionOutcome::Complete {
            outcome: arkret_models_collaboration::agent_operations::AgentProvisionComplete {
                agent_id: prepared_agent_id.clone(),
                principal_control_realm_id: prepared_realm_id.clone(),
                controller_authorization_ref: record.controller_authorization_ref.clone(),
                requested_scope_digest,
                pcr_recovery: AgentProvisionPcrRecovery::default(),
                pairing_request_id,
                pairing_code: record.pairing_code.clone(),
                expires_at,
            },
        });
    }
    let provisioned_at = if let Some((prepared_agent_id, prepared_realm_id)) = &prepared_ids {
        require_agent_provision_allocation(
            state,
            &controller_id,
            prepared_agent_id,
            prepared_realm_id,
            display_name.as_deref(),
            &agent_slug,
            avatar_blob_ref.as_deref(),
            &requested_scope,
            pairing_ttl_ms,
            now_utc,
        )
        .await?
        .created_at
    } else {
        now_utc
    };
    if existing.iter().any(|record| {
        record.agent_slug.as_deref() == Some(agent_slug.as_str())
            && agent_record_reserves_selector_slug(record, &now_utc)
    }) {
        return Err(AppError::invalid_param(
            "slug is already bound to an active or open agent for this controller",
        ));
    }
    let (agent_principal_did, principal_control_realm_id) = match prepared_ids {
        Some(ids) => ids,
        None => {
            let agent_principal_did = Did::new(generate_agent_principal_did(state.service_id()))
                .map_err(|error| {
                    AppError::internal(format!("generated Agent DID invalid: {error}"))
                })?;
            let principal_control_realm_id =
                crate::routing::identity::managed_agent_pcr::allocate_principal_control_realm_id()?;
            let requested_scope_digest = arkret_signatures::agent::agent_requested_scope_digest(
                &agent_principal_did,
                &Did::new(controller_id.clone()).map_err(|error| {
                    AppError::internal(format!("controller DID invalid: {error}"))
                })?,
                &requested_scope_typed,
            )
            .map_err(|error| {
                AppError::internal(format!("requested_scope digest failed: {error}"))
            })?;
            let controller_authorization_ref =
                crate::routing::identity::managed_agent_pcr::controller_authorization_ref(
                    agent_principal_did.as_str(),
                );
            let outcome = AgentProvisionOutcome::AwaitingControllerEvents {
                agent_id: agent_principal_did,
                principal_control_realm_id,
                controller_realm_id: RealmId::new(controller_realm.clone()).map_err(|error| {
                    AppError::internal(format!("controller PCR id invalid: {error}"))
                })?,
                controller_authorization_ref,
                requested_scope_digest,
            };
            let AgentProvisionOutcome::AwaitingControllerEvents {
                agent_id,
                principal_control_realm_id,
                ..
            } = &outcome
            else {
                unreachable!("prepare outcome is awaiting controller events")
            };
            let allocation_hash = agent_provision_allocation_hash(
                &controller_id,
                agent_id,
                principal_control_realm_id,
                display_name.as_deref(),
                &agent_slug,
                avatar_blob_ref.as_deref(),
                &requested_scope,
                pairing_ttl_ms,
            )?;
            let allocation = soland_application::jobs::IdempotencyState {
                principal_id: controller_id.clone(),
                idempotency_key: agent_provision_allocation_key(agent_id),
                service_id: state.service_id().clone(),
                request_hash: allocation_hash,
                response_status: i32::from(StatusCode::OK.as_u16()),
                response_body: serde_json::to_value(&outcome).map_err(|error| {
                    AppError::internal(format!("Agent provision prepare outcome failed: {error}"))
                })?,
                created_at: now_utc,
                expires_at: now_utc + chrono::Duration::hours(AGENT_PROVISION_ALLOCATION_TTL_HOURS),
            };
            state
                .jobs_application()
                .store_idempotency_record(allocation)
                .await
                .map_err(|error| {
                    AppError::internal(format!(
                        "Agent provision allocation persist failed: {error}"
                    ))
                })?;
            return json_ok(outcome);
        }
    };
    let agent_id = agent_principal_did.to_string();
    let controller_did = Did::new(controller_id.clone())
        .map_err(|err| AppError::internal(format!("controller DID invalid: {err}")))?;
    let requested_scope_digest = arkret_signatures::agent::agent_requested_scope_digest(
        &agent_principal_did,
        &controller_did,
        &requested_scope_typed,
    )
    .map_err(|err| AppError::internal(format!("requested_scope digest failed: {err}")))?;
    let controller_authorization_ref =
        crate::routing::identity::managed_agent_pcr::controller_authorization_ref(&agent_id);
    let pairing_request_id = format!("agent_pairing_request:{}", uuid::Uuid::now_v7());
    let pairing_code = generate_pairing_code();
    let pairing_ttl_ms = pairing_ttl_ms
        .unwrap_or(15 * 60 * 1000)
        .min(12 * 60 * 60 * 1000);
    let expires_at = now_utc + chrono::Duration::milliseconds(pairing_ttl_ms as i64);
    // Persist the agent_principal row so list/get/lifecycle + grant/session
    // paths have a real principal to operate on (AKP-0008). Per the spec
    // agent lifecycle the agent starts `pending_runtime_key`; the gate
    // `ak.gate.account.command.pair_agent_key` flips it to `active` once the
    // runtime key is authorized.
    let (accountability_event, selector_event) = fanout_provision_subevents(
        state,
        &session,
        &controller_realm,
        &agent_id,
        &agent_slug,
        *provision_events.expect("commit phase carries provision_events"),
    )
    .await?;
    let provision_event_refs = json!({
        "accountability_grant_event_id": accountability_event,
        "selector_claim_event_id": selector_event,
    });
    crate::routing::identity::managed_agent_pcr::persist_managed_agent_did_binding(
        state,
        &agent_id,
        &controller_id,
        &principal_control_realm_id,
        &controller_authorization_ref,
        &requested_scope,
        &requested_scope_digest,
        provisioned_at,
    )
    .await?;
    let controller_account = state
        .identity_application()
        .find_account_by_actor(soland_application::identity::FindAccountByActorQuery {
            actor_id: session.actor.clone(),
        })
        .await
        .map_err(|error| AppError::internal(format!("controller account lookup failed: {error}")))?
        .ok_or_else(|| AppError::internal("controller account is missing"))?;
    let mut principal = AgentPrincipalRecord::new(
        agent_id.clone(),
        controller_id.clone(),
        principal_control_realm_id.as_str().to_owned(),
        controller_authorization_ref.clone(),
        "pending_runtime_key".to_owned(),
        provisioned_at,
    );
    principal.controller_account_id = Some(ids::typed_uuid_part_expect_internal(
        &controller_account.account_id,
    ));
    principal.recipient_service_id = Some(state.service_id().clone());
    principal.display_name = display_name.clone();
    principal.agent_slug = Some(agent_slug.clone());
    principal.avatar_blob_ref = avatar_blob_ref.clone();
    principal.requested_scope = Some(requested_scope);
    principal.accountability = None;
    principal.provision_event_refs = Some(provision_event_refs);
    principal.pairing_request_id = Some(pairing_request_id.clone());
    principal.pairing_code = Some(pairing_code.clone());
    principal.pairing_expires_at = Some(expires_at);
    state
        .agent_pairing_application()
        .save_agent(principal)
        .await
        .map_err(|err| AppError::internal(format!("agent persist failed: {err}")))?;
    append_audit_log(
        state,
        Some(&session.actor),
        "ak.self.agent.command.provision",
        json!({
            "agent_id": agent_id,
            "controller_id": controller_id,
            "display_name": display_name,
            "slug": agent_slug,
            "avatar_blob_ref": avatar_blob_ref,
            "pairing_request_id": pairing_request_id,
            "principal_control_realm_id": principal_control_realm_id,
            "controller_authorization_ref": controller_authorization_ref,
            "requested_scope_digest": requested_scope_digest,
        }),
        "accepted",
    )
    .await;
    res.status_code(StatusCode::CREATED);
    json_ok(AgentProvisionOutcome::Complete {
        outcome: arkret_models_collaboration::agent_operations::AgentProvisionComplete {
            agent_id: agent_principal_did,
            principal_control_realm_id,
            controller_authorization_ref,
            requested_scope_digest,
            pcr_recovery: AgentProvisionPcrRecovery::default(),
            pairing_request_id,
            pairing_code: Some(pairing_code),
            expires_at,
        },
    })
}

/// `ak.self.agent.command.renew_pairing` — re-open pairing for bootstrap or
/// for an explicitly paused agent (key-management.md §3.6.1). Two branches share the
/// one-time-handle invariant (the fresh `pairing_request_id` + `pairing_code`
/// replace the old tuple, which becomes permanently unresolvable through the
/// same anti-enumeration lookup; the PRINCIPAL is not one-time):
///
/// - Bootstrap re-open (`pending_runtime_key` / `pairing_expired`): status returns to
///   `pending_runtime_key` without changing Realm grants.
/// - Runtime replacement (`paused`): Agent status, existing keys, sessions, and grants all stay
///   untouched; completing the new pairing supersedes every old active key
///   (reason=`superseded_by_repairing`) in the pair transaction. The controller resumes explicitly.
///
/// `active` must transition to `paused` first; `deactivated` is terminal.
#[handler]
#[tracing::instrument(skip_all, fields(op = "ak.self.agent.command.renew_pairing"))]
pub(super) async fn renew_agent_pairing(
    aa: AuthArgs,
    agent_id: PathParam<String>,
    body: JsonBody<AgentRenewPairingRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AgentRenewPairingOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let agent_id = agent_id.into_inner();
    let body = body.into_inner();
    let record = require_agent_controller(state, &session, &agent_id).await?;
    // Lazy-expire first so a stale pending record renews through the same
    // state path as an observed-expired one.
    let record = lazily_expire_pairing(state, record).await?;
    crate::routing::identity::managed_agent_pcr::validate_agent_controller_binding(
        state,
        &record,
        chrono::Utc::now(),
    )
    .await?;
    let bootstrap_reopen = match record.state.as_str() {
        "pending_runtime_key" | "pairing_expired" => true,
        "paused" => false,
        "active" => {
            return Err(pairing_failed_precondition(
                "pause the agent before replacing its runtime",
            )
            .with_reason_detail("agent_pause_required"));
        }
        "deactivated" => {
            return Err(pairing_failed_precondition(
                "agent is deactivated; deactivation is terminal",
            )
            .with_reason_detail("agent_deactivated"));
        }
        _ => {
            return Err(pairing_failed_precondition(
                "agent state does not permit pairing renewal",
            ));
        }
    };
    if !state.config().development_mode {
        return Err(AppError::unsupported_feature(
            "production agent pairing renewal requires protocol-valid delegated fan-out",
        )
        .with_wire_code("agent_provision_fanout_unavailable"));
    }
    let now_utc = chrono::DateTime::<chrono::Utc>::from_timestamp_millis(
        chrono::Utc::now().timestamp_millis(),
    )
    .ok_or_else(|| AppError::internal("current agent pairing timestamp is out of range"))?;
    // `pairing_expired` does not reserve the slug, so a replacement agent may
    // have claimed it since. Renewing would then produce two open agents with
    // the same selector slug for one controller — reject like provision does.
    let agent_slug = record.agent_slug.clone().unwrap_or_default();
    if !agent_slug.is_empty() {
        let siblings = state
            .agent_pairing_application()
            .agents_for_controller(&session.actor)
            .await
            .map_err(|err| AppError::internal(format!("agent slug conflict check failed: {err}")))?
            .into_iter()
            .collect::<Vec<_>>();
        if siblings.iter().any(|sibling| {
            sibling.id != agent_id
                && sibling.agent_slug.as_deref() == Some(agent_slug.as_str())
                && agent_record_reserves_selector_slug(sibling, &now_utc)
        }) {
            return Err(pairing_failed_precondition(
                "slug is already bound to an active or open agent for this controller",
            ));
        }
    }
    let pairing_request_id = format!("agent_pairing_request:{}", uuid::Uuid::now_v7());
    let pairing_code = generate_pairing_code();
    let pairing_ttl_ms = body
        .pairing_ttl_ms
        .unwrap_or(15 * 60 * 1000)
        .min(12 * 60 * 60 * 1000);
    let expires_at = now_utc + chrono::Duration::milliseconds(pairing_ttl_ms as i64);
    let terminal_notification = account_notification_context(&record);
    let mut record = record;
    if bootstrap_reopen {
        record.state = "pending_runtime_key".to_owned();
        record.state_changed_at = Some(now_utc);
    }
    // Runtime replacement is not a state transition: the Agent stays paused
    // while the fresh handle is open and after it is consumed.
    record.pairing_request_id = Some(pairing_request_id.clone());
    record.pairing_code = Some(pairing_code.clone());
    record.pairing_expires_at = Some(expires_at);
    // A runtime-key request submitted against the dead handle must not
    // survive into the renewed pairing.
    record.approval_request_id = None;
    record.runtime_key_request = None;
    record.approval_requested_at = None;
    record.runtime_key_binding_digest = None;
    record.runtime_public_key_digest = None;
    record.runtime_attestation_digest = None;
    record.approval_notification_id = None;
    record.updated_at = now_utc;
    state
        .agent_pairing_application()
        .save_agent(record.clone())
        .await
        .map_err(|err| AppError::internal(format!("agent persist failed: {err}")))?;
    if let Some(context) = terminal_notification {
        persist_terminal_account_notification(state, context, "renewed").await?;
    }
    append_audit_log(
        state,
        Some(&session.actor),
        "ak.self.agent.command.renew_pairing",
        json!({
            "agent_id": agent_id,
            "controller_id": session.actor,
            "slug": agent_slug,
            "pairing_request_id": pairing_request_id,
            "mode": if bootstrap_reopen { "bootstrap_reopen" } else { "runtime_replacement" },
        }),
        "accepted",
    )
    .await;
    let agent_principal_did = arkret_identifiers::Did::new(agent_id)
        .map_err(|err| AppError::internal(format!("persisted agent DID invalid: {err}")))?;
    let principal_control_realm_id = RealmId::new(record.principal_control_realm_id.clone())
        .map_err(|error| AppError::internal(format!("persisted Agent PCR invalid: {error}")))?;
    let controller_authorization_ref = record.controller_authorization_ref.clone();
    let pcr_recovery =
        crate::routing::identity::managed_agent_pcr::project_agent_pcr_recovery(state, &record)
            .await?;
    let requested_scope_digest =
        crate::routing::identity::managed_agent_pcr::requested_scope_digest_for_record(&record)?;
    json_ok(AgentRenewPairingOutcome {
        agent_id: agent_principal_did,
        principal_control_realm_id,
        controller_authorization_ref,
        requested_scope_digest,
        pcr_recovery,
        pairing_mode: if bootstrap_reopen {
            AgentPairingMode::Bootstrap
        } else {
            AgentPairingMode::Replacement
        },
        pairing_request_id,
        pairing_code: Some(pairing_code),
        expires_at,
    })
}

#[handler]
#[tracing::instrument(skip_all, fields(op = "ak.self.agent.query.list"))]
pub(super) async fn list_agents(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AgentList> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let records = state
        .agent_pairing_application()
        .agents_for_controller(&session.actor)
        .await
        .map_err(|err| AppError::internal(format!("agent list failed: {err}")))?
        .into_iter()
        .collect::<Vec<_>>();
    // Lazily expire any agent past its pairing window before projecting, so
    // list reflects `pairing_expired` without changing Realm grants.
    let mut agents = Vec::with_capacity(records.len());
    for record in records {
        let record = reconcile_accepted_agent_authorization(state, record).await?;
        let record = lazily_expire_pairing(state, record).await?;
        agents.push(agent_projection_from_record(&record));
    }
    // spec `agent_list` = `{agents: [agent_projection], next_cursor?, has_more}`.
    json_ok(AgentList {
        agents,
        next_cursor: None,
        has_more: false,
    })
}

#[handler]
#[tracing::instrument(skip_all, fields(op = "ak.self.agent.resource.get"))]
pub(super) async fn get_agent(
    aa: AuthArgs,
    agent_id: PathParam<String>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AgentView> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let service_authorized = agent_projection_service_authorized(state, req);
    let session = if service_authorized {
        None
    } else {
        Some(aa.authenticated_session(state, req).await?)
    };
    let agent_id = agent_id.into_inner();
    validate_agent_id(&agent_id)?;
    let record = state
        .agent_pairing_application()
        .agent(&agent_id)
        .await
        .map_err(|err| AppError::internal(format!("agent get failed: {err}")))?
        .ok_or_else(|| AppError::not_found("agent not found"))?;
    // Controller-self only: hide others' agents behind 404 to avoid enumeration.
    if let Some(session) = session.as_ref()
        && record.controller_id != session.actor
    {
        return Err(AppError::not_found("agent not found"));
    }
    let record = reconcile_accepted_agent_authorization(state, record).await?;
    let record = lazily_expire_pairing(state, record).await?;
    crate::routing::identity::managed_agent_pcr::validate_agent_controller_binding(
        state,
        &record,
        chrono::Utc::now(),
    )
    .await?;
    let mut view = agent_view_from_record(state, &record).await?;
    if service_authorized && let Some(key_state) = view.key_state.as_mut() {
        key_state.pairing_code = None;
    }
    // Surface the agent's effective capability grants from the authz
    // projection so the controller UI can list and revoke them; the
    // persisted record itself never carries grants.
    view.grants = state
        .authorization_application()
        .grants_for_subject_all_realms(&agent_id)
        .into_iter()
        .filter_map(|grant| {
            Some(GrantSnapshot {
                grant_id: GrantId::new(grant.grant_id).ok()?,
                status: Some("active".to_owned()),
                grant_digest: None,
                expires_at: grant.expires_at,
            })
        })
        .collect();
    json_ok(view)
}

/// Lazily expire a `pending_runtime_key` agent whose pairing window has
/// elapsed. Pairing state is independent from Realm grants, so expiry never
/// creates, revokes, or rewrites a grant.
pub(super) async fn lazily_expire_pairing(
    state: &AppState,
    mut record: AgentPrincipalRecord,
) -> Result<AgentPrincipalRecord, AppError> {
    if !agent_pairing_handle_is_open(&record) {
        return Ok(record);
    }
    let expired = record
        .pairing_expires_at
        .map(|expires| chrono::Utc::now() > expires)
        .unwrap_or(false);
    if !expired {
        return Ok(record);
    }
    let agent_id = record.id.clone();
    let bootstrap_expired = record.state == "pending_runtime_key";
    let terminal_notification = account_notification_context(&record);
    let now = chrono::Utc::now();
    if bootstrap_expired {
        record.state = "pairing_expired".to_owned();
        record.state_changed_at = Some(now);
    }
    record.approval_request_id = None;
    record.runtime_key_request = None;
    record.approval_requested_at = None;
    record.runtime_key_binding_digest = None;
    record.runtime_public_key_digest = None;
    record.runtime_attestation_digest = None;
    record.approval_notification_id = None;
    record.updated_at = now;
    state
        .agent_pairing_application()
        .save_agent(record.clone())
        .await
        .map_err(|error| {
            AppError::internal(format!("failed to persist expired Agent pairing: {error}"))
        })?;
    if let Some(context) = terminal_notification
        && let Err(error) = persist_terminal_account_notification(state, context, "expired").await
    {
        tracing::error!(message = %error.message, agent_id, "failed to persist expired Agent approval notification");
    }
    Ok(record)
}

pub(super) async fn lifecycle_transition(
    state: &AppState,
    aa: &AuthArgs,
    req: &Request,
    agent_id: String,
    new_state: AgentLifecycleState,
    event_kind: &str,
    reason: Option<String>,
    sidecar_exposure_ack: Option<Value>,
    lifecycle_event: Option<arkret_wire::Event>,
) -> Result<AgentLifecycleOutcome, AppError> {
    let session = aa.authenticated_session(state, req).await?;
    let record = require_agent_controller(state, &session, &agent_id).await?;
    let terminal_notification = (event_kind == "ak.self.agent.deactivate")
        .then(|| account_notification_context(&record))
        .flatten();
    let sidecar_exposure_ack =
        normalize_sidecar_exposure_ack(sidecar_exposure_ack, &session.actor)?;
    // Never synthesize an Agent-authored control Event from a session request.
    // Pause/resume carry the exact SDK-authored envelope. Deactivate remains
    // fail-closed until its request can carry the complete lifecycle + key +
    // grant revocation Event bundle atomically.
    let Some(lifecycle_event) = lifecycle_event else {
        if state.config().development_mode {
            return Err(AppError::unsupported_feature(
                "operation requires a controller-signed delegated SDK Event",
            )
            .with_wire_code("controller_signed_event_required"));
        }
        return Err(AppError::unsupported_feature(
            "production agent lifecycle transitions require protocol-valid delegated fan-out",
        )
        .with_wire_code("agent_lifecycle_fanout_unavailable"));
    };
    // Resume re-disclosure (key-management.md §3.6.1): sidecar circles the
    // controller created while the agent was paused re-enter the agent's
    // eligibility set on resume, so the controller MUST explicitly
    // re-acknowledge them; silent resume is forbidden.
    if event_kind == "ak.self.agent.resume" {
        ensure_agent_resume_pairing_closed(&record, chrono::Utc::now())?;
        let paused_at = Some(record.updated_at);
        let new_sidecar_ids = controller_sidecar_circles_since(state, &session.actor, paused_at);
        if !new_sidecar_ids.is_empty() {
            let acked: std::collections::BTreeSet<String> = sidecar_exposure_ack
                .as_ref()
                .and_then(|ack| ack.get("sidecar_refs"))
                .and_then(Value::as_array)
                .map(|refs| {
                    refs.iter()
                        .filter_map(Value::as_str)
                        .map(ToOwned::to_owned)
                        .collect()
                })
                .unwrap_or_default();
            let missing: Vec<&String> = new_sidecar_ids
                .iter()
                .filter(|circle_id| !acked.contains(*circle_id))
                .collect();
            if !missing.is_empty() {
                return Err(AppError::new(
                    ErrorCode::FailedPrecondition,
                    format!(
                        "resume requires explicit sidecar exposure acknowledgement for {} sidecar circle(s) created while paused",
                        missing.len()
                    ),
                )
                .with_status(salvo::http::StatusCode::PRECONDITION_FAILED)
                .with_reason_code("sidecar_exposure_ack_required"));
            }
        }
    }
    let status_changed_at = chrono::Utc::now();
    // Read the current persisted state so the durable transition carries the
    // accurate `previous_status` (resume comes from `paused`, etc.).
    let previous_status = record.state.clone();
    // AKP-0008 §4.11 (dev option B): drive the FSM reducer with the durable
    // `ak.self.agent.{pause,resume,deactivate}` event authored as the Agent
    // and executed/signed by its controller, and on deactivate fan-out the revocation chain
    // (`ak.agent.key.revoke` + `ak.capability.revoke` for every grant the
    // agent holds). Production fails closed above.
    let realm = record.principal_control_realm_id.clone();
    let authorization_ref = record.controller_authorization_ref.clone();
    submit_durable_agent_lifecycle(
        state,
        &session,
        &realm,
        &agent_id,
        &authorization_ref,
        event_kind,
        &previous_status,
        reason.as_deref(),
        sidecar_exposure_ack.as_ref(),
        lifecycle_event,
    )
    .await?;
    if event_kind == "ak.self.agent.deactivate" {
        let (key_ids, grant_locations) = {
            let proj = state.projection_application().snapshot();
            (
                proj.authorized_key_ids_for(&agent_id),
                proj.unrevoked_grant_locations_for_subject(&agent_id),
            )
        };
        submit_revoke_agent_keys(
            state,
            &session,
            &realm,
            &agent_id,
            &authorization_ref,
            &key_ids,
            None,
        )
        .await?;
        submit_revoke_agent_grants(state, &session, &grant_locations).await?;
    }
    // Persist the lifecycle state transition on the agent_principal row so
    // list/get reflect the new status (the durable event drives the reducer
    // FSM; this row is the read-side projection consumed by the HTTP API).
    let mut updated_record = record;
    updated_record.state = new_state.as_wire_str().to_owned();
    updated_record.state_changed_at = Some(status_changed_at);
    updated_record.updated_at = status_changed_at;
    if event_kind == "ak.self.agent.pause"
        && previous_status == "active"
        && agent_pairing_handle_is_open(&updated_record)
    {
        // Invalidate any legacy replacement handle that was issued while the
        // Agent was active by an older deployment. The compliant flow pauses
        // first and only then calls renew_pairing, so a handle present at the
        // pause transition can never be part of the new flow.
        updated_record.paired_pairing_request_id = updated_record.pairing_request_id.clone();
        updated_record.pairing_code = None;
        updated_record.runtime_key_request = None;
        updated_record.approval_request_id = None;
        updated_record.approval_requested_at = None;
        updated_record.runtime_key_binding_digest = None;
        updated_record.runtime_public_key_digest = None;
        updated_record.runtime_attestation_digest = None;
        updated_record.approval_notification_id = None;
    }
    if event_kind == "ak.self.agent.deactivate" {
        updated_record.approval_request_id = None;
        updated_record.runtime_key_request = None;
        updated_record.approval_requested_at = None;
        updated_record.runtime_key_binding_digest = None;
        updated_record.runtime_public_key_digest = None;
        updated_record.runtime_attestation_digest = None;
        updated_record.approval_notification_id = None;
    }
    if matches!(
        new_state,
        AgentLifecycleState::Paused | AgentLifecycleState::Deactivated
    ) {
        sidecar::remove_agent_from_controller_sidecars(state, &session.actor, &agent_id).await?;
    }
    state
        .agent_pairing_application()
        .save_agent(updated_record)
        .await
        .map_err(|error| AppError::internal(format!("agent lifecycle persist failed: {error}")))?;
    if let Some(context) = terminal_notification {
        persist_terminal_account_notification(state, context, "deactivated").await?;
    }
    // spec `agent_lifecycle_state` = `operation_status_outcome` =
    // `{ok: true, status}` (status is the post-transition `agent_status`).
    Ok(AgentLifecycleOutcome {
        ok: true,
        status: new_state,
    })
}

/// Active Sidecar backing Circles owned by `controller` created strictly
/// after `since`. `since=None` fails closed by treating every Sidecar as new,
/// forcing an explicit acknowledgement.
fn controller_sidecar_circles_since(
    state: &AppState,
    controller: &str,
    since: Option<chrono::DateTime<chrono::Utc>>,
) -> Vec<String> {
    let projection = state.projection_application().snapshot();
    projection
        .sidecars
        .values()
        .filter(|sidecar| {
            sidecar.controller_id == controller
                && sidecar.state
                    == arkret_models_collaboration::agent_operations::AgentSidecarState::Active
                && since.is_none_or(|since| sidecar.created_at > since)
        })
        .map(|sidecar| sidecar.backing_circle_id.clone())
        .collect()
}

#[handler]
#[tracing::instrument(skip_all, fields(op = "ak.self.agent.command.pause"))]
pub(super) async fn pause_agent(
    aa: AuthArgs,
    agent_id: PathParam<String>,
    body: JsonBody<AgentPauseRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AgentLifecycleOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let body = body.into_inner();
    json_ok(
        lifecycle_transition(
            state,
            &aa,
            req,
            agent_id.into_inner(),
            AgentLifecycleState::Paused,
            "ak.self.agent.pause",
            body.reason,
            None,
            Some(body.lifecycle_event),
        )
        .await?,
    )
}

#[handler]
#[tracing::instrument(skip_all, fields(op = "ak.self.agent.command.resume"))]
pub(super) async fn resume_agent(
    aa: AuthArgs,
    agent_id: PathParam<String>,
    body: JsonBody<AgentResumeRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AgentLifecycleOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let body = body.into_inner();
    json_ok(
        lifecycle_transition(
            state,
            &aa,
            req,
            agent_id.into_inner(),
            AgentLifecycleState::Active,
            "ak.self.agent.resume",
            None,
            body.sidecar_exposure_ack
                .map(serde_json::to_value)
                .transpose()
                .map_err(|error| {
                    AppError::invalid_param(format!("sidecar_exposure_ack invalid: {error}"))
                })?,
            Some(body.lifecycle_event),
        )
        .await?,
    )
}

#[handler]
#[tracing::instrument(skip_all, fields(op = "ak.self.agent.command.deactivate"))]
pub(super) async fn deactivate_agent(
    aa: AuthArgs,
    agent_id: PathParam<String>,
    body: JsonBody<AgentDeactivateRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AgentLifecycleOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let body = body.into_inner();
    json_ok(
        lifecycle_transition(
            state,
            &aa,
            req,
            agent_id.into_inner(),
            AgentLifecycleState::Deactivated,
            "ak.self.agent.deactivate",
            body.reason,
            None,
            None,
        )
        .await?,
    )
}

#[handler]
#[tracing::instrument(skip_all, fields(op = "ak.self.agent.grant.command.attach"))]
pub(super) async fn attach_agent_grant(
    aa: AuthArgs,
    agent_id: PathParam<String>,
    body: JsonBody<AgentGrantAttachRequestBody>,
    depot: &mut Depot,
    res: &mut Response,
    req: &mut Request,
) -> JsonResult<AgentGrantAttachOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let agent_id = agent_id.into_inner();
    let record = require_agent_controller(state, &session, &agent_id).await?;
    crate::routing::identity::managed_agent_pcr::validate_agent_controller_binding(
        state,
        &record,
        chrono::Utc::now(),
    )
    .await?;
    let body = body.into_inner();
    if !agent_grant_within_requested_scope(
        &record,
        &body.grant.actions,
        &body.grant.resources,
        &body.grant.constraints,
    ) {
        return Err(AppError::new(
            ErrorCode::FailedPrecondition,
            "grant exceeds the immutable Agent requested_scope ceiling",
        )
        .with_status(StatusCode::PRECONDITION_FAILED)
        .with_wire_code("agent_grant_exceeds_requested_scope"));
    }
    if !state.config().development_mode {
        return Err(AppError::unsupported_feature(
            "production Agent grant attachment requires protocol-valid Event authoring",
        )
        .with_wire_code("agent_grant_fanout_unavailable"));
    }
    let grant_id = body.grant.id.clone();
    attach_agent_grant_event(state, &session, &agent_id, &body.grant).await?;
    append_audit_log(
        state,
        Some(&session.actor),
        "ak.self.agent.grant.command.attach",
        json!({
            "agent_id": agent_id,
            "grant_id": grant_id,
            "realm_id": body.grant.realm_id,
        }),
        "accepted",
    )
    .await;
    res.status_code(StatusCode::CREATED);
    // spec `agent_grant_attach_outcome` = `{ok, grant_id}`.
    json_ok(AgentGrantAttachOutcome { ok: true, grant_id })
}

#[handler]
#[tracing::instrument(skip_all, fields(op = "ak.self.agent.grant.resource.delete"))]
pub(super) async fn detach_agent_grant(
    aa: AuthArgs,
    agent_id: PathParam<String>,
    grant_id: PathParam<String>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AgentGrantDetachOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let agent_id = agent_id.into_inner();
    let grant_id = grant_id.into_inner();
    require_agent_controller(state, &session, &agent_id).await?;
    let typed_grant_id = GrantId::new(grant_id.clone())
        .map_err(|error| AppError::invalid_param(format!("grant_id is invalid: {error}")))?;
    if !state.config().development_mode {
        return Err(AppError::unsupported_feature(
            "production Agent grant detachment requires protocol-valid Event authoring",
        )
        .with_wire_code("agent_grant_fanout_unavailable"));
    }
    let locations = {
        let projection = state.projection_application().snapshot();
        projection
            .grant_locations_for_subject(&agent_id)
            .into_iter()
            .filter(|(candidate, _)| candidate == typed_grant_id.as_str())
            .collect::<Vec<_>>()
    };
    let [(matched_grant_id, realm_id)] = locations.as_slice() else {
        return Err(AppError::not_found("Agent capability grant not found"));
    };
    revoke_capability_grant(state, &session, realm_id, matched_grant_id).await?;
    let revoked_at = now();
    append_audit_log(
        state,
        Some(&session.actor),
        "ak.self.agent.grant.resource.delete",
        json!({
            "agent_id": agent_id,
            "grant_id": typed_grant_id,
            "realm_id": realm_id,
        }),
        "accepted",
    )
    .await;
    // spec `agent_grant_detach_outcome` = `{ok, revoked_at}`.
    json_ok(AgentGrantDetachOutcome {
        ok: true,
        revoked_at,
    })
}
