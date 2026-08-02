use salvo::oapi::endpoint;

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
) -> Result<soland_services::jobs::IdempotencyState, AppError> {
    let key = agent_provision_allocation_key(agent_id);
    let allocation = state
        .jobs()
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

#[endpoint(
    operation_id = "ak.self.agent.command.provision",
    summary = "Provision an agent",
    tags("agents")
)]
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
        .recovery_policies()
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
        .agent_pairings()
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
                == Some(events.accountability_grant.event.event_id.as_str())
                && refs.get("selector_claim_event_id").and_then(Value::as_str)
                    == Some(events.selector_claim.event.event_id.as_str())
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
                )?;
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
            let allocation = soland_services::jobs::IdempotencyState {
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
                .jobs()
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
        crate::routing::identity::managed_agent_pcr::controller_authorization_ref(&agent_id)?;
    let pairing_request_id =
        arkret_wire::OpaqueLocalId::new(format!("agent_pairing_request:{}", uuid::Uuid::now_v7()))
            .expect("generated pairing request id must be valid");
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
        controller_authorization_ref.as_str(),
        &requested_scope,
        &requested_scope_digest,
        provisioned_at,
    )
    .await?;
    let controller_account = state
        .identities()
        .find_account_by_actor(soland_services::identity::FindAccountByActorQuery {
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
        // Lifecycle intent axis only (key-management.md §3.6.1). A freshly
        // provisioned agent's intent is "active" (run it); the derived
        // runtime_state projects pending_runtime_key until first pairing.
        AgentLifecycleState::Active,
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
        .agent_pairings()
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

/// `ak.self.agent.command.renew_pairing` — re-open pairing for a bootstrap or
/// a runtime-replacement agent (key-management.md §3.6.1). Both branches share
/// the one-time-handle invariant (the fresh `pairing_request_id` +
/// `pairing_code` replace the old tuple, which becomes permanently unresolvable
/// through the same anti-enumeration lookup; the PRINCIPAL is not one-time):
///
/// - Bootstrap re-open (never-keyed agent): the derived runtime_state returns to
///   `pending_runtime_key` without changing the lifecycle intent or Realm grants.
/// - Runtime replacement (agent already holds an active key, lifecycle `active` or `paused`): the
///   lifecycle intent, existing keys, sessions, and grants all stay untouched and runtime_state
///   projects `replacing`; completing the new pairing supersedes every old active key
///   (reason=`superseded_by_repairing`) in the pair transaction, preserving the lifecycle intent —
///   an `active` agent needs no resume.
///
/// Re-opening is never a lifecycle transition and never requires a forced
/// pause; `deactivated` is terminal.
#[endpoint(
    operation_id = "ak.self.agent.command.renew_pairing",
    summary = "Renew an agent's pairing",
    tags("agents")
)]
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
    if record.state == AgentLifecycleState::Deactivated {
        return Err(
            pairing_failed_precondition("agent is deactivated; deactivation is terminal")
                .with_reason_detail("agent_deactivated"),
        );
    }
    // Bootstrap re-open for a never-keyed agent; runtime replacement for one
    // that already holds an active authorized key (key-management.md §3.6.1).
    // Both active and paused agents replace in place with no forced pause — the
    // lifecycle intent is preserved and completing the pairing atomically
    // supersedes the old key.
    let bootstrap_reopen = record.authorized_event_ref.is_none();
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
    // A never-keyed agent whose bootstrap window lapsed does not reserve the
    // slug, so a replacement agent may have claimed it since. Renewing would
    // then produce two open agents with the same selector slug for one
    // controller — reject like provision does.
    let agent_slug = record.agent_slug.clone().unwrap_or_default();
    if !agent_slug.is_empty() {
        let siblings = state
            .agent_pairings()
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
    let pairing_request_id =
        arkret_wire::OpaqueLocalId::new(format!("agent_pairing_request:{}", uuid::Uuid::now_v7()))
            .expect("generated pairing request id must be valid");
    let pairing_code = generate_pairing_code();
    let pairing_ttl_ms = body
        .pairing_ttl_ms
        .unwrap_or(15 * 60 * 1000)
        .min(12 * 60 * 60 * 1000);
    let expires_at = now_utc + chrono::Duration::milliseconds(pairing_ttl_ms as i64);
    let terminal_notification = account_notification_context(&record);
    let mut record = record;
    // Re-opening pairing is never a lifecycle transition (key-management.md
    // §3.6.1): the lifecycle intent stays exactly as it was and only the
    // derived runtime_state moves (to pending_runtime_key for bootstrap, or
    // replacing for runtime replacement) while the fresh handle is open.
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
    record.pending_pairing_commit_intent = None;
    record.approval_notification_id = None;
    record.updated_at = now_utc;
    state
        .agent_pairings()
        .save_agent(record.clone())
        .await
        .map_err(|err| AppError::internal(format!("agent persist failed: {err}")))?;
    if let Some(context) = terminal_notification {
        persist_terminal_account_notification(
            state,
            context,
            arkret_models_collaboration::sync_frames::account_sync::AgentRuntimeApprovalRemovalReason::Renewed,
        )
        .await?;
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

#[endpoint(
    operation_id = "ak.self.agent.query.list",
    summary = "List agents",
    tags("agents")
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.agent.query.list"))]
pub(super) async fn list_agents(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AgentList> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let records = state
        .agent_pairings()
        .agents_for_controller(&session.actor)
        .await
        .map_err(|err| AppError::internal(format!("agent list failed: {err}")))?
        .into_iter()
        .collect::<Vec<_>>();
    // Lazily expire any agent past its pairing window before projecting, so
    // the derived runtime_state reflects `pairing_expired` without changing the
    // lifecycle intent or Realm grants.
    let mut agents = Vec::with_capacity(records.len());
    for record in records {
        let record = reconcile_accepted_agent_authorization(state, record).await?;
        let record = lazily_expire_pairing(state, record).await?;
        let runtime_state = agent_runtime_state_from_record(
            &record,
            agent_has_active_authorization(state, &record.id),
            chrono::Utc::now(),
        );
        agents.push(agent_projection_from_record(&record, runtime_state));
    }
    // spec `agent_list` = `{agents: [agent_projection], next_cursor?, has_more}`.
    json_ok(AgentList {
        agents,
        next_cursor: None,
        has_more: false,
    })
}

#[endpoint(
    operation_id = "ak.self.agent.resource.get",
    summary = "Get one agent",
    tags("agents")
)]
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
        .agent_pairings()
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
    // Surface every durable, unrevoked grant so terminal deactivation can
    // author complete revocation coverage. The effective authz index supplies
    // optional display metadata, but pending or expired grants must not
    // disappear from the controller's revocation surface.
    let effective_grants = state
        .authorization()
        .grants_for_subject_all_realms(&agent_id)
        .into_iter()
        .map(|grant| {
            (
                (grant.grant_id, grant.realm_id),
                (grant.expires_at, "active".to_owned()),
            )
        })
        .collect::<BTreeMap<_, _>>();
    view.grants = state
        .projections()
        .snapshot()
        .unrevoked_grant_locations_for_subject(&agent_id)
        .into_iter()
        .filter_map(|(grant_id, realm_id)| {
            let display = effective_grants.get(&(grant_id.clone(), realm_id.clone()));
            Some(GrantSnapshot {
                grant_id: GrantId::new(grant_id).ok()?,
                realm_id: RealmId::new(realm_id).ok()?,
                status: display.map(|(_, status)| status.clone()),
                grant_digest: None,
                expires_at: display.and_then(|(expires_at, _)| *expires_at),
            })
        })
        .collect();
    json_ok(view)
}

/// Lazily clean up an agent whose open pairing window has elapsed. Pairing is
/// independent from the lifecycle intent and from Realm grants, so expiry never
/// changes the lifecycle, creates, revokes, or rewrites a grant; the derived
/// runtime_state simply falls to `pairing_expired` (never-keyed) or `ready`
/// (keyed) once the handle lapses (key-management.md §3.6.1).
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
    let terminal_notification = account_notification_context(&record);
    let now = chrono::Utc::now();
    // Pairing expiry is not a lifecycle transition (key-management.md §3.6.1):
    // the lifecycle intent is untouched, and the derived runtime_state falls to
    // pairing_expired (never-keyed) or ready (keyed) once the handle lapses.
    // Only the dead pending runtime-key request is cleaned up here.
    record.approval_request_id = None;
    record.runtime_key_request = None;
    record.approval_requested_at = None;
    record.runtime_key_binding_digest = None;
    record.runtime_public_key_digest = None;
    record.runtime_attestation_digest = None;
    record.approval_notification_id = None;
    record.updated_at = now;
    state
        .agent_pairings()
        .save_agent(record.clone())
        .await
        .map_err(|error| {
            AppError::internal(format!("failed to persist expired Agent pairing: {error}"))
        })?;
    if let Some(context) = terminal_notification
        && let Err(error) = persist_terminal_account_notification(
            state,
            context,
            arkret_models_collaboration::sync_frames::account_sync::AgentRuntimeApprovalRemovalReason::Expired,
        )
        .await
    {
        tracing::error!(message = %error.message, agent_id, "failed to persist expired Agent approval notification");
    }
    Ok(record)
}

pub(super) async fn lifecycle_transition(
    state: &AppState,
    session: &SessionRecord,
    agent_id: String,
    new_state: AgentLifecycleState,
    event_kind: &str,
    reason: Option<String>,
    sidecar_exposure_ack: Option<Value>,
    lifecycle_event: Option<arkret_wire::EventInitialSubmission>,
) -> Result<AgentLifecycleOutcome, AppError> {
    // Authentication is deliberately completed by the endpoint before this
    // helper is entered. A DPoP proof is single-use, so passing `AuthArgs` and
    // `Request` through here would verify the same proof twice and reject the
    // lifecycle command as a replay.
    let record = require_agent_controller(state, session, &agent_id).await?;
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
        // Resume is a pure lifecycle-intent write and MUST NOT interlock with an
        // open pairing handle (key-management.md §3.6.1): an in-flight
        // replacement handle keeps running across resume and closes only on
        // consumption or expiry.
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
    let previous_status = record.state;
    // Drive the FSM reducer with the exact durable
    // `ak.self.agent.{pause,resume,deactivate}` Event authored as the Agent and
    // executed/signed by its controller. Deactivate revocations are admitted
    // and rechecked by the endpoint before it calls this transition.
    let realm = record.principal_control_realm_id.clone();
    let authorization_ref = record.controller_authorization_ref.clone();
    submit_durable_agent_lifecycle(
        state,
        session,
        &realm,
        &agent_id,
        &authorization_ref,
        event_kind,
        previous_status.as_wire_str(),
        reason.as_deref(),
        sidecar_exposure_ack.as_ref(),
        lifecycle_event,
    )
    .await?;
    // Persist the lifecycle state transition on the agent_principal row so
    // list/get reflect the new status (the durable event drives the reducer
    // FSM; this row is the read-side projection consumed by the HTTP API).
    let mut updated_record = record;
    updated_record.state = new_state;
    updated_record.state_changed_at = Some(status_changed_at);
    updated_record.updated_at = status_changed_at;
    // Pause is a pure lifecycle-intent write and MUST NOT touch an open pairing
    // handle (key-management.md §3.6.1): pausing mid-replacement leaves the
    // handle live so the controller can still complete or let it expire.
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
        .agent_pairings()
        .save_agent(updated_record)
        .await
        .map_err(|error| AppError::internal(format!("agent lifecycle persist failed: {error}")))?;
    if let Some(context) = terminal_notification {
        persist_terminal_account_notification(
            state,
            context,
            arkret_models_collaboration::sync_frames::account_sync::AgentRuntimeApprovalRemovalReason::Deactivated,
        )
        .await?;
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
    let projection = state.projections().snapshot();
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

#[endpoint(
    operation_id = "ak.self.agent.command.pause",
    summary = "Pause an agent",
    tags("agents")
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.agent.command.pause"))]
pub(super) async fn pause_agent(
    aa: AuthArgs,
    agent_id: PathParam<String>,
    body: JsonBody<AgentPauseRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AgentLifecycleOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let body = body.into_inner();
    json_ok(
        lifecycle_transition(
            state,
            &session,
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

#[endpoint(
    operation_id = "ak.self.agent.command.resume",
    summary = "Resume an agent",
    tags("agents")
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.agent.command.resume"))]
pub(super) async fn resume_agent(
    aa: AuthArgs,
    agent_id: PathParam<String>,
    body: JsonBody<AgentResumeRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AgentLifecycleOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let body = body.into_inner();
    json_ok(
        lifecycle_transition(
            state,
            &session,
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

#[endpoint(
    operation_id = "ak.self.agent.command.deactivate",
    summary = "Deactivate an agent",
    tags("agents")
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.agent.command.deactivate"))]
pub(super) async fn deactivate_agent(
    aa: AuthArgs,
    agent_id: PathParam<String>,
    body: JsonBody<AgentDeactivateRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AgentLifecycleOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let agent_id = agent_id.into_inner();
    let record = require_agent_controller(state, &session, &agent_id).await?;
    let body = body.into_inner();
    let reason = body.reason.as_deref();

    validate_durable_agent_lifecycle(
        &session,
        &record.principal_control_realm_id,
        &agent_id,
        &record.controller_authorization_ref,
        "ak.self.agent.deactivate",
        record.state.as_wire_str(),
        reason,
        None,
        &body.lifecycle_event.event,
    )?;

    let (active_key_authorizations, active_key_ids, active_grant_locations, all_grant_locations) = {
        let projection = state.projections().snapshot();
        let active_key_authorizations = projection
            .active_agent_key_authorizations(&agent_id)
            .into_iter()
            .collect::<BTreeMap<_, _>>();
        (
            active_key_authorizations.clone(),
            active_key_authorizations.keys().cloned().collect(),
            projection
                .unrevoked_grant_locations_for_subject(&agent_id)
                .into_iter()
                .collect::<BTreeSet<_>>(),
            projection
                .grant_locations_for_subject(&agent_id)
                .into_iter()
                .collect::<BTreeSet<_>>(),
        )
    };

    let mut supplied_key_ids = BTreeSet::new();
    for event in &body.key_revocation_events {
        let key_id = validate_agent_key_revocation_event(
            &session,
            &record,
            &agent_id,
            reason,
            &active_key_authorizations,
            &event.event,
        )?;
        if !supplied_key_ids.insert(key_id) {
            return Err(AppError::invalid_param(
                "key_revocation_events contains a duplicate key_id",
            ));
        }
    }
    let mut supplied_grant_locations = BTreeSet::new();
    for event in &body.capability_revocation_events {
        let location = validate_agent_capability_revocation_event(&session, reason, &event.event)?;
        if !all_grant_locations.contains(&location) {
            return Err(AppError::capability_denied(
                "capability_revocation_events contains a grant not held by the Agent",
            ));
        }
        if !supplied_grant_locations.insert(location) {
            return Err(AppError::invalid_param(
                "capability_revocation_events contains a duplicate grant",
            ));
        }
    }
    require_deactivation_revocation_coverage(
        &active_key_ids,
        &supplied_key_ids,
        &active_grant_locations,
        &supplied_grant_locations,
    )?;

    for event in body.key_revocation_events {
        submit_signed_agent_event(state, &session, event).await?;
    }
    for event in body.capability_revocation_events {
        submit_signed_agent_event(state, &session, event).await?;
    }

    let (remaining_key_ids, remaining_grant_locations) = {
        let projection = state.projections().snapshot();
        (
            projection.authorized_key_ids_for(&agent_id),
            projection.unrevoked_grant_locations_for_subject(&agent_id),
        )
    };
    if !remaining_key_ids.is_empty() || !remaining_grant_locations.is_empty() {
        return Err(AppError::new(
            ErrorCode::FailedPrecondition,
            "Agent revocations were not fully projected; deactivation remains non-terminal",
        )
        .with_status(StatusCode::PRECONDITION_FAILED)
        .with_reason_code("agent_deactivation_revocations_incomplete"));
    }

    json_ok(
        lifecycle_transition(
            state,
            &session,
            agent_id,
            AgentLifecycleState::Deactivated,
            "ak.self.agent.deactivate",
            body.reason,
            None,
            Some(body.lifecycle_event),
        )
        .await?,
    )
}

fn validate_agent_key_revocation_event(
    session: &SessionRecord,
    record: &AgentPrincipalRecord,
    agent_id: &str,
    reason: Option<&str>,
    active_key_authorizations: &BTreeMap<String, String>,
    event: &arkret_wire::Event,
) -> Result<String, AppError> {
    if event.kind.as_str() != "ak.agent.key.revoke"
        || event.realm_id.as_str() != record.principal_control_realm_id
        || event.actor_id.as_str() != agent_id
        || event
            .executed_by
            .as_ref()
            .map(arkret_identifiers::Did::as_str)
            != Some(session.actor.as_str())
        || event.authorization_ref.as_deref() != Some(record.controller_authorization_ref.as_str())
    {
        return Err(AppError::capability_denied(
            "key_revocation_events does not match the managed Agent controller binding",
        ));
    }
    if event.proofs.is_empty() {
        return Err(
            AppError::invalid_param("key_revocation_events must carry a controller proof")
                .with_wire_code("controller_signed_event_required"),
        );
    }
    if event.payload.get("agent_id").and_then(Value::as_str) != Some(agent_id)
        || event.payload.get("revoked_by").and_then(Value::as_str) != Some(session.actor.as_str())
        || event.payload.get("reason").and_then(Value::as_str) != reason
    {
        return Err(AppError::invalid_param(
            "key_revocation_events payload does not match the requested deactivation",
        ));
    }
    let key_id = event
        .payload
        .get("key_id")
        .and_then(Value::as_str)
        .filter(|key_id| !key_id.is_empty())
        .map(ToOwned::to_owned)
        .ok_or_else(|| AppError::invalid_param("key_revocation_events key_id is required"))?;
    let authorized_event_ref = active_key_authorizations.get(&key_id).ok_or_else(|| {
        AppError::invalid_param("key_revocation_events key_id is not currently authorized")
    })?;
    let payload = serde_json::from_value::<
        arkret_models_collaboration::events_payloads::agent::AgentKeyRevokePayload,
    >(serde_json::to_value(&event.payload).map_err(|error| {
        AppError::invalid_param(format!("key_revocation_events payload invalid: {error}"))
    })?)
    .map_err(|error| {
        AppError::invalid_param(format!("key_revocation_events payload invalid: {error}"))
    })?;
    let authorized_event_ref =
        arkret_wire::EventId::new(authorized_event_ref.clone()).map_err(|error| {
            AppError::internal(format!(
                "active Agent authorization Event id invalid: {error}"
            ))
        })?;
    // v1 carries no producer `effects[]`: `ak.agent.key.revoke` projects a
    // single or_set remove-observed on the agent-key cell derived from
    // `(payload.agent_id, payload.key_id)`. Assert the registered contract
    // derives exactly that, rather than comparing a submitted array.
    let _ = &authorized_event_ref;
    let derived =
        arkret_schema::project_registered_cell_writes(event, arkret_canonical::DigestSuite::Sha256)
            .map_err(|error| {
                AppError::invalid_param(format!(
                    "key_revocation_events Agent key projection failed: {error}"
                ))
            })?;
    let expected_cell = super::pairing::agent_key_cell_ref(&payload.agent_id, &payload.key_id)?;
    if derived.len() != 1 || derived[0].cell != expected_cell {
        return Err(AppError::invalid_param(
            "key_revocation_events must derive a single Agent key revocation write on its own key cell",
        ));
    }
    Ok(key_id)
}

fn validate_agent_capability_revocation_event(
    session: &SessionRecord,
    reason: Option<&str>,
    event: &arkret_wire::Event,
) -> Result<(String, String), AppError> {
    if event.kind.as_str() != "ak.capability.revoke"
        || event.actor_id.as_str() != session.actor
        || event.executed_by.is_some()
        || event.authorization_ref.is_some()
    {
        return Err(AppError::capability_denied(
            "capability_revocation_events must be authored by the authenticated controller",
        ));
    }
    if event.proofs.is_empty() {
        return Err(AppError::invalid_param(
            "capability_revocation_events must carry a controller proof",
        )
        .with_wire_code("controller_signed_event_required"));
    }
    if event.payload.get("reason").and_then(Value::as_str) != reason {
        return Err(AppError::invalid_param(
            "capability_revocation_events reason does not match the deactivation request",
        ));
    }
    let grant_id = event
        .payload
        .get("grant_id")
        .and_then(Value::as_str)
        .filter(|grant_id| !grant_id.is_empty())
        .ok_or_else(|| {
            AppError::invalid_param("capability_revocation_events grant_id is required")
        })?;
    Ok((grant_id.to_owned(), event.realm_id.to_string()))
}

fn require_deactivation_revocation_coverage(
    active_key_ids: &BTreeSet<String>,
    supplied_key_ids: &BTreeSet<String>,
    active_grant_locations: &BTreeSet<(String, String)>,
    supplied_grant_locations: &BTreeSet<(String, String)>,
) -> Result<(), AppError> {
    if !active_key_ids.is_subset(supplied_key_ids) {
        return Err(AppError::new(
            ErrorCode::FailedPrecondition,
            "key_revocation_events does not cover every active Agent key",
        )
        .with_status(StatusCode::PRECONDITION_FAILED)
        .with_reason_code("agent_deactivation_revocations_incomplete"));
    }
    if !active_grant_locations.is_subset(supplied_grant_locations) {
        return Err(AppError::new(
            ErrorCode::FailedPrecondition,
            "capability_revocation_events does not cover every unrevoked Agent grant",
        )
        .with_status(StatusCode::PRECONDITION_FAILED)
        .with_reason_code("agent_deactivation_revocations_incomplete"));
    }
    Ok(())
}

#[endpoint(
    operation_id = "ak.self.agent.grant.command.attach",
    summary = "Attach a grant to an agent",
    tags("agents")
)]
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

#[endpoint(
    operation_id = "ak.self.agent.grant.resource.delete",
    summary = "Detach a grant from an agent",
    tags("agents")
)]
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
        let projection = state.projections().snapshot();
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

#[cfg(test)]
mod deactivation_tests {
    use super::*;

    #[test]
    fn lifecycle_transition_contract_uses_a_pre_authenticated_session() {
        // This compile-time contract keeps the transition layer below the HTTP
        // authentication boundary. In particular, it must not regain access
        // to AuthArgs/Request and consume a single-use DPoP proof twice.
        async fn call_transition(state: &AppState, session: &SessionRecord) {
            let _ = lifecycle_transition(
                state,
                session,
                "did:web:agent.example".to_owned(),
                AgentLifecycleState::Paused,
                "ak.self.agent.pause",
                None,
                None,
                None,
            )
            .await;
        }

        let _ = call_transition;
    }

    #[test]
    fn revocation_coverage_rejects_missing_active_key() {
        let active_keys = BTreeSet::from(["runtime-key-1".to_owned()]);
        let error = require_deactivation_revocation_coverage(
            &active_keys,
            &BTreeSet::new(),
            &BTreeSet::new(),
            &BTreeSet::new(),
        )
        .unwrap_err();

        assert_eq!(error.wire_code(), "failed_precondition");
        assert_eq!(
            error.reason_code.as_deref(),
            Some("agent_deactivation_revocations_incomplete")
        );
    }

    #[test]
    fn revocation_coverage_rejects_missing_unrevoked_grant() {
        let location = (
            "ak:grant:019f9700-0000-7000-8000-000000000001".to_owned(),
            "ak:realm:019f9700-0000-7000-8000-000000000002".to_owned(),
        );
        let error = require_deactivation_revocation_coverage(
            &BTreeSet::new(),
            &BTreeSet::new(),
            &BTreeSet::from([location]),
            &BTreeSet::new(),
        )
        .unwrap_err();

        assert_eq!(error.wire_code(), "failed_precondition");
    }

    #[test]
    fn revocation_coverage_accepts_complete_or_replayed_superset() {
        let active_keys = BTreeSet::from(["runtime-key-1".to_owned()]);
        let supplied_keys =
            BTreeSet::from(["runtime-key-1".to_owned(), "already-revoked-key".to_owned()]);
        let active_grants = BTreeSet::from([(
            "ak:grant:019f9700-0000-7000-8000-000000000001".to_owned(),
            "ak:realm:019f9700-0000-7000-8000-000000000002".to_owned(),
        )]);
        let supplied_grants = active_grants.clone();

        require_deactivation_revocation_coverage(
            &active_keys,
            &supplied_keys,
            &active_grants,
            &supplied_grants,
        )
        .unwrap();
    }
}
