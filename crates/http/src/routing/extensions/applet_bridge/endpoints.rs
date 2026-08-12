//! HTTP endpoint handlers and router assembly for the applet bridge.

use arkret_identifiers::{AppletId, RealmId};
use arkret_models_collaboration::account_lifecycle::AppletRevokeRequestBody;
use arkret_models_collaboration::http_bodies::AppletTransactionRequestBody;
use arkret_models_integration::{
    AppletActorView, AppletCapabilityRevokeIntent, AppletInstallOutcome, AppletInstallPlan,
    AppletInstallPreviewRequestBody, AppletInstallRequestBody, AppletManagedMembershipRemoval,
    AppletMembershipRemoveIntent, AppletPingOutcome, AppletProtocolMetadata, AppletRealmView,
    AppletRevokeEffectKind, AppletRevokeOutcome, AppletRevokePlan, AppletRevokePreviewOutcome,
    AppletRevokePreviewRequestBody, AppletRevokeSagaStatus, AppletRevokeStep,
    AppletRevokeStepStatus, AppletTransactionOutcome, ExternalRef, FieldDefinition,
    GhostActorProvisionOutcome, GhostActorProvisionRequestBody, ProtocolInstance,
};
use arkret_wire::{AppletRevokeMode, EventKind, Hash, ProtocolOperationId};
use salvo::http::StatusCode;
use salvo::oapi::extract::JsonBody;
use salvo::prelude::*;
use serde_json::{Value, json};
use soland_http::error::AppError;
use soland_http::result::{JsonResult, json_ok};

use super::super::applet_manifest::verify_manifest;
use super::ghost::{
    ensure_formal_ghost_provision_allowed, external_user_from_ghost_request, provision_ghost,
    revoke_applet_record_after_admin_gate, validate_ghost_actor_provision_request,
    validate_signed_ghost_provision_events,
};
use super::install::{
    append_portal_message, applet_response, approved_scopes_from_approval_request,
    approved_scopes_from_formal_install_events, build_install_plan, effective_scope_realm_id,
    parse_manifest, portal_message_payload, register_package_install, register_verified_applet,
    require_realm_admin, validate_applet_package,
};
use super::record::{
    accountability_chain, applet_display_name, applet_id_param, applet_record, applet_records,
    ensure_not_revoked, idempotency_key, persist_applet_record, query_value,
};
use super::signature::{
    VerifiedInboundTransactionSignature, require_inbound_transaction_signature,
};
use super::transaction::process_verified_transaction;
use super::types::{
    AppletGhostIngressOutcome, AppletGhostIngressRequestBody, AppletInstallPaths,
    AppletManifestRegisterRequestBody, AppletPortalMessageOutcome, AppletPortalMessageRequestBody,
    AppletProtocolDescribeOutcome, AppletRecord, AppletView, GhostActorRecord,
    SOLAND_EDGE_APPLET_ID,
};
use crate::routing::system::extract::AuthArgs;
use crate::state::AppState;

pub(in crate::routing::extensions) fn router() -> Router {
    Router::with_path("applets")
        .push(Router::with_path("register").post(register_endpoint))
        .push(
            Router::with_path("{applet_id}")
                .get(get_endpoint)
                .push(Router::with_path("ghosts").post(ghost_endpoint))
                .push(Router::with_path("bot/messages").post(bot_message_endpoint)),
        )
}

pub(in crate::routing::extensions) fn protocol_router() -> Router {
    Router::new()
        .push(
            Router::with_path("edge").push(
                Router::with_path("applet")
                    .push(Router::with_path("ping").get(protocol_ping_endpoint))
                    .push(Router::with_path("describe").get(protocol_describe_endpoint))
                    .push(
                        Router::with_path("transactions")
                            .hoop(require_inbound_transaction_signature)
                            .post(transaction_endpoint),
                    )
                    .push(Router::with_path("actors/{actor_id}").get(resolve_actor_endpoint))
                    .push(
                        Router::with_path("realms/{realm_id_or_alias}").get(resolve_realm_endpoint),
                    )
                    .push(Router::with_path("protocols/{protocol}").get(protocol_metadata_endpoint))
                    .push(
                        Router::with_path("third_party")
                            .push(Router::with_path("users").get(third_party_users_endpoint))
                            .push(
                                Router::with_path("locations").get(third_party_locations_endpoint),
                            ),
                    ),
            ),
        )
        .push(
            Router::with_path("self").push(
                Router::with_path("applets")
                    .push(
                        Router::with_path("install")
                            .push(Router::with_path("preview").post(install_preview_endpoint))
                            .post(install_endpoint),
                    )
                    .push(
                        Router::with_path("{applet_id}")
                            .push(
                                Router::with_path("ghosts/provision")
                                    .post(provision_ghost_actor_endpoint),
                            )
                            .push(
                                Router::with_path("revoke")
                                    .push(
                                        Router::with_path("preview").post(revoke_preview_endpoint),
                                    )
                                    .post(revoke_install_endpoint),
                            ),
                    ),
            ),
        )
}

#[salvo::oapi::endpoint(operation_id = "ak.edge.applet.read.ping", tags("extensions"))]
#[tracing::instrument(skip_all, fields(op = "ak.edge.applet.read.ping"))]
async fn protocol_ping_endpoint(depot: &mut Depot) -> JsonResult<AppletPingOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let service_id =
        arkret_identifiers::DidCoreId::new(state.service_id().clone()).map_err(|error| {
            AppError::internal(format!("configured service_id is invalid: {error}"))
        })?;
    json_ok(AppletPingOutcome {
        ok: true,
        applet_id: SOLAND_EDGE_APPLET_ID.to_owned(),
        service_id,
        protocol_version: "1.0".to_owned(),
    })
}

#[salvo::oapi::endpoint(operation_id = "ak.edge.applet.read.describe", tags("extensions"))]
#[tracing::instrument(skip_all, fields(op = "ak.edge.applet.read.describe"))]
async fn protocol_describe_endpoint() -> JsonResult<AppletProtocolDescribeOutcome> {
    json_ok(AppletProtocolDescribeOutcome {
        contract: "ak.applet.v1".to_owned(),
        install: AppletInstallPaths {
            preview_path: "/_arkret/self/applets/install/preview".to_owned(),
            commit_path: "/_arkret/self/applets/install".to_owned(),
            revoke_preview_path: "/_arkret/self/applets/{applet_id}/revoke/preview".to_owned(),
            revoke_path: "/_arkret/self/applets/{applet_id}/revoke".to_owned(),
            ghost_actor_provision_path: "/_arkret/self/applets/{applet_id}/ghosts/provision"
                .to_owned(),
        },
        transaction_path: "/_arkret/edge/applet/transactions".to_owned(),
        transaction_auth: json!({
            "mode": "rfc9421_http_message_signature",
            "required_headers": [
                "Signature",
                "Signature-Input",
                "Content-Digest",
                "Source-Service-ID",
                "Destination-Service-ID",
                "Idempotency-Key"
            ],
            "covered_components": [
                "@method",
                "@target-uri",
                "@authority",
                "content-digest",
                "source-service-id",
                "destination-service-id",
                "idempotency-key"
            ],
            "source_signature_anchor": "ak.applet.source_signature_anchor.v1",
            "bearer_only": false
        }),
        package_schema: "ak.schema.applet_package.v1".to_owned(),
    })
}

#[salvo::oapi::endpoint(
    operation_id = "ak.self.applet.install.command.preview",
    tags("extensions")
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.applet.install.command.preview"))]
async fn install_preview_endpoint(
    aa: AuthArgs,
    body: JsonBody<AppletInstallPreviewRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AppletInstallPlan> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let _session = aa.authenticated_session(state, req).await?;
    let mut preview = body.into_inner();
    validate_applet_package(state, &mut preview.applet_package)?;
    let approved_scopes = approved_scopes_from_approval_request(
        &preview.applet_package,
        &preview.effective_scope,
        &preview.approval_request,
    )?;
    let plan = build_install_plan(
        state,
        &preview.applet_package,
        &preview.effective_scope,
        approved_scopes,
    )
    .await?;
    json_ok(plan)
}

#[salvo::oapi::endpoint(operation_id = "ak.self.applet.command.install", tags("extensions"))]
#[tracing::instrument(skip_all, fields(op = "ak.self.applet.command.install"))]
async fn install_endpoint(
    aa: AuthArgs,
    body: JsonBody<AppletInstallRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
    res: &mut Response,
) -> JsonResult<AppletInstallOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let idempotency_key = idempotency_key(req)
        .ok_or_else(|| AppError::missing_param("Idempotency-Key header is required"))?;
    if idempotency_key.len() > 128 {
        return Err(AppError::invalid_param(
            "Idempotency-Key length exceeds 128 bytes",
        ));
    }
    let mut commit = body.into_inner();
    let body = serde_json::to_value(&commit)
        .map_err(|error| AppError::internal(format!("install commit serialize: {error}")))?;
    let body_digest = super::install::canonical_digest(&body)?;
    validate_applet_package(state, &mut commit.applet_package)?;
    let approved_scopes = approved_scopes_from_formal_install_events(&commit, &session.actor)?;
    let recomputed_plan = build_install_plan(
        state,
        &commit.applet_package,
        &commit.effective_scope,
        approved_scopes,
    )
    .await?;
    if recomputed_plan.plan_digest != commit.plan_digest {
        return Err(
            AppError::conflict("install plan digest does not match recomputed plan")
                .with_wire_code("applet_install_plan_mismatch"),
        );
    }

    // Governance gate: the canonical install write projects a
    // `ak.realm.admin`-scoped registration onto the effective_scope realm.
    // Authentication alone is insufficient â€” the actor MUST hold realm admin
    // over that realm. P1 projected capability grants into the authz index, so
    // `state.authorization().check` is authoritative here. fail-closed.
    require_realm_admin(state, &session.actor, &commit.effective_scope).await?;

    let response =
        register_package_install(state, &session, commit, idempotency_key, body_digest, res)
            .await?;
    json_ok(response)
}

#[salvo::oapi::endpoint(
    operation_id = "ak.self.applet.revoke.command.preview",
    tags("extensions")
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.applet.revoke.command.preview"))]
async fn revoke_preview_endpoint(
    aa: AuthArgs,
    body: JsonBody<AppletRevokePreviewRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AppletRevokePreviewOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let applet_id = applet_id_param(req)?;
    let preview = body.into_inner();
    let record = applet_record(state, &applet_id)
        .await?
        .ok_or_else(|| AppError::not_found("applet is not registered"))?;
    validate_revoke_scope(&record, &preview.effective_scope)?;
    require_realm_admin(state, &session.actor, &preview.effective_scope).await?;
    json_ok(build_revoke_plan(state, &record, &preview)?)
}

#[salvo::oapi::endpoint(operation_id = "ak.self.applet.command.revoke", tags("extensions"))]
#[tracing::instrument(skip_all, fields(op = "ak.self.applet.command.revoke"))]
async fn revoke_install_endpoint(
    aa: AuthArgs,
    body: JsonBody<AppletRevokeRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AppletRevokeOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let applet_id = applet_id_param(req)?;
    let idempotency_key = idempotency_key(req)
        .ok_or_else(|| AppError::missing_param("Idempotency-Key header is required"))?;
    if idempotency_key.len() > 128 {
        return Err(AppError::invalid_param(
            "Idempotency-Key length exceeds 128 bytes",
        ));
    }
    let revoke = body.into_inner();
    let request_value = serde_json::to_value(&revoke)
        .map_err(|error| AppError::invalid_param(format!("revoke request invalid: {error}")))?;
    let request_digest = arkret_canonical::canonical_sha256(&request_value)
        .map_err(|error| AppError::invalid_param(format!("revoke request invalid: {error}")))?;
    let mut record = applet_record(state, &applet_id)
        .await?
        .ok_or_else(|| AppError::not_found("applet is not registered"))?;
    validate_revoke_scope(&record, &revoke.effective_scope)?;
    require_realm_admin(state, &session.actor, &revoke.effective_scope).await?;

    // A durable execution owns the idempotency decision. Exact replay resumes
    // its persisted submissions even when the live projection has moved since
    // preview; conflicting bytes fail before any plan rebuild or side effect.
    let stored_outcome = load_stored_revoke_outcome(
        record.revoke_execution.as_ref(),
        state.service_id(),
        &session.actor,
        &idempotency_key,
        &request_digest,
    )?;

    if stored_outcome.is_none() {
        let preview = AppletRevokePreviewRequestBody {
            effective_scope: revoke.effective_scope.clone(),
            reason_code: revoke.reason_code.clone(),
            revoke_mode: revoke.revoke_mode,
        };
        let recomputed = build_revoke_plan(state, &record, &preview)?;
        if recomputed.revoke_plan_digest != revoke.revoke_plan_digest {
            return Err(AppError::conflict("revoke plan changed; preview again")
                .with_wire_code("failed_precondition"));
        }
        validate_revoke_submissions(&session.actor, &recomputed.revoke_plan, &revoke)?;
    }

    let mut outcome =
        if let Some(stored_outcome) = stored_outcome {
            stored_outcome
        } else {
            let operation_id =
                ProtocolOperationId::new(format!("ak:operation:{}", uuid::Uuid::now_v7()))
                    .map_err(AppError::internal)?;
            let mut steps =
                revoke
                    .capability_revoke_events
                    .iter()
                    .map(|submission| AppletRevokeStep {
                        effect_kind: AppletRevokeEffectKind::CapabilityRevokeEvent,
                        effect_ref: submission.event.event_id.to_string(),
                        status: AppletRevokeStepStatus::Pending,
                        reason_code: None,
                    })
                    .chain(revoke.membership_state_events.iter().map(|submission| {
                        AppletRevokeStep {
                            effect_kind: AppletRevokeEffectKind::MembershipStateEvent,
                            effect_ref: submission.event.event_id.to_string(),
                            status: AppletRevokeStepStatus::Pending,
                            reason_code: None,
                        }
                    }))
                    .collect::<Vec<_>>();
            if revoke_mode_fences_runtime(revoke.revoke_mode) {
                steps.push(AppletRevokeStep {
                    effect_kind: AppletRevokeEffectKind::LocalAppletFence,
                    effect_ref: applet_id.clone(),
                    status: AppletRevokeStepStatus::Pending,
                    reason_code: None,
                });
            }
            let outcome = AppletRevokeOutcome {
                ok: false,
                operation_id,
                revoke_plan_digest: revoke.revoke_plan_digest.clone(),
                status: AppletRevokeSagaStatus::InProgress,
                steps,
                revoked_refs: Vec::new(),
                rejected: Vec::new(),
            };
            persist_revoke_execution(
                state,
                &mut record,
                &session.actor,
                &idempotency_key,
                &request_digest,
                &request_value,
                &outcome,
            )
            .await?;
            outcome
        };

    if outcome.status == AppletRevokeSagaStatus::Complete {
        return json_ok(outcome);
    }

    let submissions = revoke
        .capability_revoke_events
        .iter()
        .cloned()
        .chain(revoke.membership_state_events.iter().cloned())
        .collect::<Vec<_>>();
    for (index, submission) in submissions.into_iter().enumerate() {
        if matches!(
            outcome.steps[index].status,
            AppletRevokeStepStatus::Accepted | AppletRevokeStepStatus::Duplicate
        ) {
            continue;
        }
        let effect_ref = outcome.steps[index].effect_ref.clone();
        outcome
            .rejected
            .retain(|item| item.requested_scope.as_deref() != Some(effect_ref.as_str()));
        outcome.steps[index].reason_code = None;
        match crate::routing::events::event_log::submit_initial_event_submission(
            state, &session, submission,
        )
        .await
        {
            Ok(accepted) => {
                outcome.steps[index].status = if accepted.duplicate {
                    AppletRevokeStepStatus::Duplicate
                } else {
                    AppletRevokeStepStatus::Accepted
                };
                outcome.revoked_refs.push(accepted.event_id);
                if record.revoked_at.is_none() {
                    record.revoked_at = Some(chrono::Utc::now());
                    record.status = "revoking".to_owned();
                    if let Some(fence) = outcome
                        .steps
                        .iter_mut()
                        .find(|step| step.effect_kind == AppletRevokeEffectKind::LocalAppletFence)
                    {
                        fence.status = AppletRevokeStepStatus::Accepted;
                    }
                }
            }
            Err(error) => {
                outcome.steps[index].status = AppletRevokeStepStatus::Rejected;
                outcome.steps[index].reason_code =
                    Some(arkret_wire::ReasonCode::from_wire(&error.code));
                outcome
                    .rejected
                    .push(arkret_models_integration::AppletRejectedItem {
                        requested_scope: Some(outcome.steps[index].effect_ref.clone()),
                        reason_code: arkret_wire::ReasonCode::from_wire(&error.code),
                    });
                outcome.status = AppletRevokeSagaStatus::PartiallyCompleted;
                persist_revoke_execution(
                    state,
                    &mut record,
                    &session.actor,
                    &idempotency_key,
                    &request_digest,
                    &request_value,
                    &outcome,
                )
                .await?;
                return json_ok(outcome);
            }
        }
        persist_revoke_execution(
            state,
            &mut record,
            &session.actor,
            &idempotency_key,
            &request_digest,
            &request_value,
            &outcome,
        )
        .await?;
    }

    if revoke_mode_fences_runtime(revoke.revoke_mode) {
        let local_outcome =
            revoke_applet_record_after_admin_gate(state, &session.actor, &applet_id).await?;
        outcome.revoked_refs.push(local_outcome.bot_actor_id);
        outcome.revoked_refs.extend(local_outcome.ghost_actor_ids);
    }
    outcome.revoked_refs.sort();
    outcome.revoked_refs.dedup();
    outcome.ok = true;
    outcome.status = AppletRevokeSagaStatus::Complete;
    if let Some(step) = outcome
        .steps
        .iter_mut()
        .find(|step| step.effect_kind == AppletRevokeEffectKind::LocalAppletFence)
    {
        step.status = AppletRevokeStepStatus::Accepted;
    }
    record = applet_record(state, &applet_id)
        .await?
        .ok_or_else(|| AppError::not_found("applet disappeared during revoke"))?;
    persist_revoke_execution(
        state,
        &mut record,
        &session.actor,
        &idempotency_key,
        &request_digest,
        &request_value,
        &outcome,
    )
    .await?;
    crate::routing::append_audit_log(
        state,
        Some(&session.actor),
        "applet.revoke",
        json!({
            "applet_id": applet_id,
            "operation_id": outcome.operation_id,
            "revoke_plan_digest": outcome.revoke_plan_digest,
            "status": outcome.status,
            "revoked_refs": outcome.revoked_refs,
        }),
        "accepted",
    )
    .await;
    json_ok(outcome)
}

fn validate_revoke_scope(
    record: &AppletRecord,
    effective_scope: &arkret_wire::ScopeRef,
) -> Result<(), AppError> {
    let scope_realm = effective_scope_realm_id(effective_scope);
    if record.portal_realm_id != scope_realm
        || record.effective_scope.as_ref() != Some(effective_scope)
    {
        return Err(
            AppError::conflict("effective_scope does not match active applet install")
                .with_wire_code("applet_effective_scope_mismatch"),
        );
    }
    Ok(())
}

fn load_stored_revoke_outcome(
    execution: Option<&Value>,
    principal_service_id: &str,
    admin_actor_id: &str,
    idempotency_key: &str,
    request_digest: &str,
) -> Result<Option<AppletRevokeOutcome>, AppError> {
    let Some(execution) = execution else {
        return Ok(None);
    };
    let binding_matches = execution
        .get("principal_service_id")
        .and_then(Value::as_str)
        == Some(principal_service_id)
        && execution.get("admin_actor_id").and_then(Value::as_str) == Some(admin_actor_id)
        && execution.get("idempotency_key").and_then(Value::as_str) == Some(idempotency_key)
        && execution.get("request_digest").and_then(Value::as_str) == Some(request_digest);
    if !binding_matches {
        return Err(AppError::conflict(
            "revoke idempotency key is already bound to a different service, actor, or canonical body",
        )
        .with_wire_code("duplicate_conflict"));
    }
    serde_json::from_value::<AppletRevokeOutcome>(
        execution.get("outcome").cloned().unwrap_or(Value::Null),
    )
    .map(Some)
    .map_err(|error| AppError::internal(format!("stored revoke saga is invalid: {error}")))
}

fn revoke_mode_fences_runtime(mode: AppletRevokeMode) -> bool {
    matches!(
        mode,
        AppletRevokeMode::RevokeAll | AppletRevokeMode::RevokeRuntimeOnly
    )
}

fn build_revoke_plan(
    state: &AppState,
    record: &AppletRecord,
    preview: &AppletRevokePreviewRequestBody,
) -> Result<AppletRevokePreviewOutcome, AppError> {
    if matches!(
        preview.revoke_mode,
        AppletRevokeMode::RevokeAll | AppletRevokeMode::RevokeDelegatedSessions
    ) {
        return Err(AppError::unsupported_feature(
            "delegated-session revoke preview requires an Account Authority enumeration binding",
        )
        .with_wire_code("failed_precondition"));
    }
    let response = record.install_response.as_ref().ok_or_else(|| {
        AppError::conflict("applet install projection is incomplete")
            .with_wire_code("applet_install_projection_incomplete")
    })?;
    if matches!(
        preview.revoke_mode,
        AppletRevokeMode::RevokeAll | AppletRevokeMode::RevokeWidgetOnly
    ) && response.widget_policy_ref.is_some()
    {
        return Err(AppError::unsupported_feature(
            "widget-token revoke preview requires the durable token inventory",
        )
        .with_wire_code("failed_precondition"));
    }
    let package = record.package.as_ref().ok_or_else(|| {
        AppError::conflict("applet install projection is missing package metadata")
            .with_wire_code("applet_install_projection_incomplete")
    })?;
    let mut capability_revocations = Vec::new();
    let mut membership_removals: Vec<AppletMembershipRemoveIntent> = Vec::new();
    if revoke_mode_fences_runtime(preview.revoke_mode) {
        let scope_realm_id = effective_scope_realm_id(&preview.effective_scope);
        let active_grant_ids = state
            .authorization()
            .grants_for_subject(package.service_id.as_str(), &scope_realm_id)
            .into_iter()
            .map(|grant| grant.grant_id)
            .collect::<std::collections::BTreeSet<_>>();
        for grant_id in &response.capability_grant_refs {
            if active_grant_ids.contains(grant_id.as_str()) {
                capability_revocations.push(AppletCapabilityRevokeIntent {
                    event_kind: EventKind::CapabilityRevoke.as_str().to_owned(),
                    grant_id: grant_id.clone(),
                    registration_epoch: package.registration_epoch.clone(),
                    reason_code: preview.reason_code.clone(),
                });
            }
        }
        if !response.membership_event_refs.is_empty() {
            return Err(AppError::unsupported_feature(
                "managed-membership revoke preview requires the current membership projection inventory",
            )
            .with_wire_code("failed_precondition"));
        }
    }
    capability_revocations
        .sort_by(|left, right| left.grant_id.as_str().cmp(right.grant_id.as_str()));
    membership_removals
        .sort_by(|left, right| left.member_id.as_str().cmp(right.member_id.as_str()));
    let plan = AppletRevokePlan {
        applet_id: AppletId::new(record.applet_id.clone())
            .map_err(|error| AppError::internal(format!("stored applet id is invalid: {error}")))?,
        effective_scope: preview.effective_scope.clone(),
        registration_epoch: package.registration_epoch.clone(),
        reason_code: preview.reason_code.clone(),
        revoke_mode: preview.revoke_mode,
        capability_revocations,
        membership_removals,
        widget_token_refs: Vec::new(),
        delegated_session_refs: Vec::new(),
    };
    let plan_value = serde_json::to_value(&plan).map_err(|error| {
        AppError::internal(format!("revoke plan serialization failed: {error}"))
    })?;
    let digest = arkret_canonical::canonical_sha256(&plan_value)
        .map_err(|error| AppError::internal(format!("revoke plan digest failed: {error}")))?;
    Ok(AppletRevokePreviewOutcome {
        revoke_plan_digest: Hash::new(digest).map_err(|error| {
            AppError::internal(format!("revoke plan digest is invalid: {error}"))
        })?,
        revoke_plan: plan,
    })
}

fn validate_revoke_submissions(
    admin_actor: &str,
    plan: &AppletRevokePlan,
    revoke: &AppletRevokeRequestBody,
) -> Result<(), AppError> {
    let expected_grants = plan
        .capability_revocations
        .iter()
        .map(|intent| intent.grant_id.as_str().to_owned())
        .collect::<std::collections::BTreeSet<_>>();
    let mut submitted_grants = std::collections::BTreeSet::new();
    for submission in &revoke.capability_revoke_events {
        let event = &submission.event;
        if event.kind != EventKind::CapabilityRevoke
            || event.actor_id.as_str() != admin_actor
            || event.scope_ref != plan.effective_scope
        {
            return Err(AppError::invalid_param(
                "capability revoke Event kind, actor, or scope does not match the plan",
            ));
        }
        let payload = &event.payload;
        let grant_id = payload
            .get("grant_id")
            .and_then(Value::as_str)
            .ok_or_else(|| AppError::invalid_param("capability revoke payload lacks grant_id"))?;
        if payload.get("reason").and_then(Value::as_str) != Some(plan.reason_code.as_str()) {
            return Err(AppError::invalid_param(
                "capability revoke reason does not match the plan",
            ));
        }
        if !submitted_grants.insert(grant_id.to_owned()) {
            return Err(AppError::invalid_param(
                "duplicate capability revoke target",
            ));
        }
    }
    if submitted_grants != expected_grants {
        return Err(AppError::conflict(
            "capability revoke Event set does not exactly match the current plan",
        )
        .with_wire_code("failed_precondition"));
    }

    let expected_members = plan
        .membership_removals
        .iter()
        .map(|intent| {
            (
                intent.member_id.as_str().to_owned(),
                match intent.membership {
                    AppletManagedMembershipRemoval::Leave => "leave",
                    AppletManagedMembershipRemoval::Remove => "remove",
                }
                .to_owned(),
            )
        })
        .collect::<std::collections::BTreeSet<_>>();
    let mut submitted_members = std::collections::BTreeSet::new();
    for submission in &revoke.membership_state_events {
        let event = &submission.event;
        if event.kind != EventKind::MemberState
            || event.actor_id.as_str() != admin_actor
            || event.scope_ref != plan.effective_scope
        {
            return Err(AppError::invalid_param(
                "membership Event kind, actor, or scope does not match the plan",
            ));
        }
        let payload = &event.payload;
        let member_id = payload
            .get("actor_id")
            .and_then(Value::as_str)
            .ok_or_else(|| AppError::invalid_param("membership payload lacks actor_id"))?;
        let membership = payload
            .get("membership")
            .and_then(Value::as_str)
            .ok_or_else(|| AppError::invalid_param("membership payload lacks membership"))?;
        if !matches!(membership, "leave" | "remove")
            || payload.get("reason").and_then(Value::as_str) != Some(plan.reason_code.as_str())
        {
            return Err(AppError::invalid_param(
                "membership transition or reason does not match the plan",
            ));
        }
        if !submitted_members.insert((member_id.to_owned(), membership.to_owned())) {
            return Err(AppError::invalid_param(
                "duplicate membership revoke target",
            ));
        }
    }
    if submitted_members != expected_members {
        return Err(AppError::conflict(
            "membership Event set does not exactly match the current plan",
        )
        .with_wire_code("failed_precondition"));
    }
    Ok(())
}

async fn persist_revoke_execution(
    state: &AppState,
    record: &mut AppletRecord,
    admin_actor_id: &str,
    idempotency_key: &str,
    request_digest: &str,
    request: &Value,
    outcome: &AppletRevokeOutcome,
) -> Result<(), AppError> {
    record.revoke_execution = Some(json!({
        "principal_service_id": state.service_id(),
        "admin_actor_id": admin_actor_id,
        "idempotency_key": idempotency_key,
        "request_digest": request_digest,
        "request": request,
        "outcome": outcome,
    }));
    persist_applet_record(state, record).await
}

#[salvo::oapi::endpoint(
    operation_id = "ak.self.applet.ghost.command.provision",
    tags("extensions")
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.applet.ghost.command.provision"))]
async fn provision_ghost_actor_endpoint(
    aa: AuthArgs,
    body: JsonBody<GhostActorProvisionRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
    res: &mut Response,
) -> JsonResult<GhostActorProvisionOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let path_applet_id = applet_id_param(req)?;
    let provision = body.into_inner();
    validate_ghost_actor_provision_request(&path_applet_id, &provision)?;
    if session.actor != provision.service_id.as_str() {
        return Err(AppError::capability_denied(
            "authenticated caller must be the installed Applet service DID",
        )
        .with_wire_code("applet_registration_unauthorized"));
    }
    let idempotency_key = idempotency_key(req)
        .ok_or_else(|| AppError::missing_param("Idempotency-Key header is required"))?;
    if idempotency_key.len() > 128 {
        return Err(AppError::invalid_param(
            "Idempotency-Key length exceeds 128 bytes",
        ));
    }
    let request_value = serde_json::to_value(&provision)
        .map_err(|error| AppError::invalid_param(format!("provision request invalid: {error}")))?;
    let request_digest = arkret_canonical::canonical_sha256(&request_value)
        .map_err(|error| AppError::invalid_param(format!("provision request invalid: {error}")))?
        .to_string();
    if let Some(replay) = state
        .jobs()
        .idempotency_record(&session.actor, &idempotency_key)
        .await
        .map_err(|error| AppError::internal(format!("idempotency lookup failed: {error}")))?
    {
        if replay.request_hash != request_digest {
            return Err(AppError::conflict(
                "Idempotency-Key was already used with different Ghost provisioning Events",
            )
            .with_wire_code("duplicate_conflict"));
        }
        let outcome: GhostActorProvisionOutcome = serde_json::from_value(replay.response_body)
            .map_err(|error| {
                AppError::internal(format!("stored Ghost provision outcome invalid: {error}"))
            })?;
        res.status_code(StatusCode::OK);
        return json_ok(outcome);
    }

    // Wire ids are validated at deserialization (typed AppletId/DidFullId/RealmId).
    let service_id = provision.service_id.clone();
    let ghost_actor_id = provision.ghost_actor_id.clone();
    // G3.S9 — ghost actor DID recorded against the applet MUST be a
    // well-formed bare DID scalar (no DID URL fragment).
    crate::routing::extensions::bot_actor::validate_extension_actor_did(ghost_actor_id.as_str())?;
    let realm_id = provision.realm_id.clone();

    let record = applet_record(state, &path_applet_id)
        .await?
        .ok_or_else(|| AppError::not_found("applet is not installed"))?;
    ensure_not_revoked(&record)?;
    ensure_formal_ghost_provision_allowed(&record, &provision)?;
    if let Some(existing) = record.ghosts.iter().find(|ghost| {
        ghost.external_id == provision.external_user_id
            || ghost.ghost_actor_id == provision.ghost_actor_id.as_str()
    }) {
        if existing.request_digest.as_deref() != Some(request_digest.as_str()) {
            return Err(AppError::conflict(
                "Ghost provisioning tuple already exists with different signed Events",
            )
            .with_wire_code("duplicate_conflict"));
        }
        let outcome = GhostActorProvisionOutcome {
            ghost_actor_id,
            profile_event_ref: existing.profile_event_ref.clone().ok_or_else(|| {
                AppError::internal("stored Ghost record is missing profile_event_ref")
            })?,
            accountability_grant_ref: existing.accountability_grant_ref.clone().ok_or_else(
                || AppError::internal("stored Ghost record is missing accountability_grant_ref"),
            )?,
            authorization_ref: existing.authorization_ref.clone().ok_or_else(|| {
                AppError::internal("stored Ghost record is missing authorization_ref")
            })?,
            display_name: existing.display_name.clone(),
        };
        res.status_code(StatusCode::OK);
        return json_ok(outcome);
    }

    let now = chrono::Utc::now();
    let authorization_ref =
        validate_signed_ghost_provision_events(state, &record, &provision).await?;
    let profile_event_ref = provision.profile_event.event_id.to_string();
    let accountability_grant_ref = provision.accountability_grant_event.event_id.to_string();
    let outcome = GhostActorProvisionOutcome {
        ghost_actor_id: ghost_actor_id.clone(),
        profile_event_ref: profile_event_ref.clone(),
        accountability_grant_ref: accountability_grant_ref.clone(),
        authorization_ref: authorization_ref.clone(),
        display_name: provision.display_name.clone(),
    };
    let ghost = GhostActorRecord {
        ghost_actor_id: ghost_actor_id.to_string(),
        external_id: provision.external_user_id.clone(),
        display_name: provision.display_name.clone(),
        request_digest: Some(request_digest.clone()),
        profile_event_ref: Some(profile_event_ref.clone()),
        accountability_grant_ref: Some(accountability_grant_ref.clone()),
        authorization_ref: Some(authorization_ref.clone()),
        created_at: now,
        revoked_at: None,
    };
    let commit_result = crate::routing::events::event_log::submit_ghost_provision_batch(
        state,
        service_id.as_str(),
        ghost_actor_id.as_str(),
        realm_id.as_str(),
        provision.accountability_grant_event.clone(),
        provision.profile_event.clone(),
        path_applet_id,
        serde_json::to_value(&ghost)
            .map_err(|error| AppError::internal(format!("Ghost record invalid: {error}")))?,
        crate::routing::events::event_log::EventCommitIdempotency {
            principal_id: session.actor.clone(),
            key: idempotency_key.clone(),
            service_id: state.service_id().clone(),
            request_hash: request_digest.clone(),
        },
        serde_json::to_value(&outcome)
            .map_err(|error| AppError::internal(format!("Ghost outcome invalid: {error}")))?,
    )
    .await;
    if let Err(error) = commit_result {
        // A replica or concurrent request may win after the optimistic lookup
        // above. Re-read the durable first response so an exact retry still
        // receives replay semantics; a different body remains a conflict.
        if matches!(error.code.as_str(), "duplicate" | "duplicate_conflict")
            && let Some(replay) = state
                .jobs()
                .idempotency_record(&session.actor, &idempotency_key)
                .await
                .map_err(|lookup_error| {
                    AppError::internal(format!("idempotency lookup failed: {lookup_error}"))
                })?
        {
            if replay.request_hash != request_digest {
                return Err(AppError::conflict(
                    "Idempotency-Key was already used with different Ghost provisioning Events",
                )
                .with_wire_code("duplicate_conflict"));
            }
            let replayed: GhostActorProvisionOutcome = serde_json::from_value(replay.response_body)
                .map_err(|decode_error| {
                    AppError::internal(format!(
                        "stored Ghost provision outcome invalid: {decode_error}"
                    ))
                })?;
            res.status_code(StatusCode::OK);
            return json_ok(replayed);
        }
        return Err(AppError::new(
            soland_http::error::ErrorCode::from_wire(&error.code)
                .unwrap_or(soland_http::error::ErrorCode::InvalidParam),
            error.message,
        )
        .with_status(error.status)
        .with_wire_code(error.code));
    }

    crate::routing::append_audit_log(
        state,
        Some(service_id.as_ref()),
        "applet.ghost_actor.provision",
        json!({
            "applet_id": provision.applet_id,
            "service_id": service_id,
            "ghost_actor_id": ghost_actor_id,
            "realm_id": realm_id,
            "profile_event_ref": profile_event_ref,
            "accountability_grant_ref": accountability_grant_ref,
            "authorization_ref": authorization_ref,
        }),
        "accepted",
    )
    .await;

    res.status_code(StatusCode::CREATED);
    json_ok(outcome)
}

#[salvo::oapi::endpoint(
    operation_id = "ak.edge.applet.command.transaction",
    tags("extensions")
)]
#[tracing::instrument(skip_all, fields(op = "ak.edge.applet.command.transaction"))]
async fn transaction_endpoint(
    body: JsonBody<AppletTransactionRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AppletTransactionOutcome> {
    let state = depot
        .get_typed::<AppState>()
        .expect("state injected")
        .clone();
    let idempotency_key = idempotency_key(req)
        .ok_or_else(|| AppError::missing_param("Idempotency-Key header is required"))?;
    if idempotency_key.len() > 128 {
        return Err(AppError::invalid_param(
            "Idempotency-Key length exceeds 128 bytes",
        ));
    }
    let transaction = body.into_inner();
    if transaction.events.is_empty() {
        return Err(AppError::invalid_param(
            "events must contain at least one event",
        ));
    }
    // The route hoop verifies the per-delivery RFC 9421 source signature
    // against the raw canonical body before this typed extractor or any event
    // processing runs. A successful verification is consumed exactly once.
    let verified = depot
        .remove_typed::<VerifiedInboundTransactionSignature>()
        .map_err(|_| AppError::internal("verified applet transaction signature is unavailable"))?;
    let outcome =
        process_verified_transaction(&state, transaction, &idempotency_key, verified).await?;
    json_ok(outcome)
}

#[salvo::oapi::endpoint(operation_id = "ak.edge.applet.actor.read.resolve", tags("extensions"))]
#[tracing::instrument(skip_all, fields(op = "ak.edge.applet.actor.read.resolve"))]
async fn resolve_actor_endpoint(
    req: &mut Request,
    depot: &mut Depot,
) -> JsonResult<AppletActorView> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let actor_id = req
        .param::<String>("actor_id")
        .ok_or_else(|| AppError::missing_param("actor_id path segment required"))?;
    if let Some(doc) = super::ghost::did_document_for_extension_actor(state, &actor_id).await? {
        let actor_id = arkret_identifiers::DidCoreId::new(actor_id)
            .map_err(|error| AppError::invalid_param(format!("actor_id is invalid: {error}")))?;
        return json_ok(AppletActorView {
            exists: true,
            actor_id: Some(actor_id),
            display_name: doc
                .get("display_name")
                .and_then(Value::as_str)
                .map(str::to_owned),
            external_ref: None,
        });
    }
    json_ok(AppletActorView {
        exists: false,
        actor_id: None,
        display_name: None,
        external_ref: None,
    })
}

#[salvo::oapi::endpoint(operation_id = "ak.edge.applet.realm.read.resolve", tags("extensions"))]
#[tracing::instrument(skip_all, fields(op = "ak.edge.applet.realm.read.resolve"))]
async fn resolve_realm_endpoint(
    req: &mut Request,
    depot: &mut Depot,
) -> JsonResult<AppletRealmView> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let realm_id_or_alias = req
        .param::<String>("realm_id_or_alias")
        .ok_or_else(|| AppError::missing_param("realm_id_or_alias path segment required"))?;
    let record = applet_records(state).await?.into_iter().find(|record| {
        record.portal_realm_id == realm_id_or_alias
            || record.namespace == realm_id_or_alias
            || record.applet_id == realm_id_or_alias
    });
    if let Some(record) = record {
        let realm_id = RealmId::new(record.portal_realm_id).map_err(|error| {
            AppError::internal(format!("stored applet portal realm_id is invalid: {error}"))
        })?;
        return json_ok(AppletRealmView {
            exists: true,
            realm_id: Some(realm_id),
            title: Some(applet_display_name(&record.manifest).unwrap_or(record.namespace)),
            external_ref: Some(ExternalRef {
                protocol: record
                    .package
                    .as_ref()
                    .and_then(|package| package.protocols.first().cloned())
                    .unwrap_or_else(|| "applet".to_owned()),
                external_id: record.applet_id,
                instance_id: record.install_id,
                display_name: None,
                url: None,
            }),
        });
    }
    json_ok(AppletRealmView {
        exists: false,
        realm_id: None,
        title: None,
        external_ref: None,
    })
}

#[salvo::oapi::endpoint(
    operation_id = "ak.edge.applet.read.protocol_metadata",
    tags("extensions")
)]
#[tracing::instrument(skip_all, fields(op = "ak.edge.applet.read.protocol_metadata"))]
async fn protocol_metadata_endpoint(
    req: &mut Request,
    depot: &mut Depot,
) -> JsonResult<AppletProtocolMetadata> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let protocol = req
        .param::<String>("protocol")
        .ok_or_else(|| AppError::missing_param("protocol path segment required"))?;
    let instances = applet_records(state)
        .await?
        .into_iter()
        .filter(|record| {
            record
                .package
                .as_ref()
                .map(|package| package.protocols.iter().any(|item| item == &protocol))
                .unwrap_or(false)
        })
        .map(|record| ProtocolInstance {
            instance_id: record.applet_id.clone(),
            display_name: applet_display_name(&record.manifest)
                .unwrap_or_else(|| record.namespace.clone()),
            external_ref: Some(ExternalRef {
                protocol: protocol.clone(),
                external_id: record.applet_id,
                instance_id: record.install_id,
                display_name: None,
                url: None,
            }),
        })
        .collect::<Vec<_>>();
    json_ok(AppletProtocolMetadata {
        protocol: protocol.clone(),
        display_name: format!("{protocol} applet protocol"),
        icon_blob_ref: None,
        field_definitions: [
            ("applet_id", true),
            ("service_id", false),
            ("status", false),
        ]
        .into_iter()
        .map(|(name, required)| {
            (
                name.to_owned(),
                FieldDefinition {
                    value_kind: "string".to_owned(),
                    required: required.then_some(true),
                    enum_values: None,
                    description: None,
                },
            )
        })
        .collect(),
        instances,
    })
}

#[salvo::oapi::endpoint(
    operation_id = "ak.edge.applet.third_party_users.read.list",
    tags("extensions")
)]
#[tracing::instrument(skip_all, fields(op = "ak.edge.applet.third_party_users.read.list"))]
async fn third_party_users_endpoint(
    req: &mut Request,
    depot: &mut Depot,
) -> JsonResult<AppletActorView> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let external_id = query_value(req, "user")
        .or_else(|| query_value(req, "user_id"))
        .or_else(|| query_value(req, "external_id"));
    if let Some(external_id) = external_id {
        for record in applet_records(state).await? {
            if let Some(ghost) = record
                .ghosts
                .iter()
                .find(|ghost| ghost.external_id == external_id)
            {
                let actor_id = arkret_identifiers::DidCoreId::new(ghost.ghost_actor_id.clone())
                    .map_err(|error| {
                        AppError::internal(format!("stored ghost actor id is invalid: {error}"))
                    })?;
                return json_ok(AppletActorView {
                    exists: true,
                    actor_id: Some(actor_id),
                    display_name: ghost.display_name.clone(),
                    external_ref: Some(ExternalRef {
                        protocol: record
                            .package
                            .as_ref()
                            .and_then(|package| package.protocols.first().cloned())
                            .unwrap_or_else(|| "applet".to_owned()),
                        external_id: ghost.external_id.clone(),
                        instance_id: record.install_id.clone(),
                        display_name: ghost.display_name.clone(),
                        url: None,
                    }),
                });
            }
        }
    }
    json_ok(AppletActorView {
        exists: false,
        actor_id: None,
        display_name: None,
        external_ref: None,
    })
}

#[salvo::oapi::endpoint(
    operation_id = "ak.edge.applet.third_party_locations.read.list",
    tags("extensions")
)]
#[tracing::instrument(
    skip_all,
    fields(op = "ak.edge.applet.third_party_locations.read.list")
)]
async fn third_party_locations_endpoint(
    req: &mut Request,
    depot: &mut Depot,
) -> JsonResult<AppletRealmView> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let location = query_value(req, "location")
        .or_else(|| query_value(req, "channel"))
        .or_else(|| query_value(req, "realm"));
    if let Some(location) = location
        && let Some(record) = applet_records(state)
            .await?
            .into_iter()
            .find(|record| record.namespace == location || record.portal_realm_id == location)
    {
        let realm_id = RealmId::new(record.portal_realm_id.clone()).map_err(|error| {
            AppError::internal(format!("stored applet portal realm_id is invalid: {error}"))
        })?;
        return json_ok(AppletRealmView {
            exists: true,
            realm_id: Some(realm_id),
            title: Some(applet_display_name(&record.manifest).unwrap_or(record.namespace.clone())),
            external_ref: Some(ExternalRef {
                protocol: record
                    .package
                    .as_ref()
                    .and_then(|package| package.protocols.first().cloned())
                    .unwrap_or_else(|| "applet".to_owned()),
                external_id: location,
                instance_id: record.install_id,
                display_name: None,
                url: None,
            }),
        });
    }
    json_ok(AppletRealmView {
        exists: false,
        realm_id: None,
        title: None,
        external_ref: None,
    })
}

#[salvo::oapi::endpoint(
    operation_id = "org.arkret.soland.applets.register",
    tags("extensions")
)]
#[tracing::instrument(skip_all, fields(op = "org.arkret.soland.applets.register"))]
async fn register_endpoint(
    aa: AuthArgs,
    body: JsonBody<AppletManifestRegisterRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
    res: &mut Response,
) -> JsonResult<AppletView> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let body = body.into_inner();
    let manifest = parse_manifest(&body)?;
    let trusted_registry_did = body
        .trusted_registry_did
        .as_deref()
        .unwrap_or(manifest.signer_did.as_str())
        .to_owned();
    let verified = verify_manifest(&manifest, &trusted_registry_did).map_err(|err| {
        AppError::invalid_param(format!("applet manifest verification failed: {err}"))
            .with_wire_code(err.code())
    })?;
    let idempotency_key = idempotency_key(req);
    let response = register_verified_applet(
        state,
        &session.actor,
        manifest,
        verified,
        idempotency_key,
        res,
    )
    .await?;
    json_ok(response)
}

#[salvo::oapi::endpoint(operation_id = "org.arkret.soland.applets.get", tags("extensions"))]
#[tracing::instrument(skip_all, fields(op = "org.arkret.soland.applets.get"))]
async fn get_endpoint(req: &mut Request, depot: &mut Depot) -> JsonResult<AppletView> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let applet_id = applet_id_param(req)?;
    let record = applet_record(state, &applet_id)
        .await?
        .ok_or_else(|| AppError::not_found("applet is not registered"))?;
    json_ok(applet_response(&record))
}

#[salvo::oapi::endpoint(
    operation_id = "org.arkret.soland.applets.ghosts.provision",
    tags("extensions")
)]
#[tracing::instrument(skip_all, fields(op = "org.arkret.soland.applets.ghosts.provision"))]
async fn ghost_endpoint(
    aa: AuthArgs,
    body: JsonBody<AppletGhostIngressRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AppletGhostIngressOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let _session = aa.authenticated_session(state, req).await?;
    let applet_id = applet_id_param(req)?;
    let body = body.into_inner();
    let (external_id, display_name) = external_user_from_ghost_request(&body)?;

    let (record, ghost) = provision_ghost(state, &applet_id, &external_id, display_name).await?;
    let message_result = if let Some(realm_id) = body.realm_id {
        if let Some(message) = portal_message_payload(&body.payload)? {
            Some(append_portal_message(state, &record, &ghost, &realm_id, message).await?)
        } else {
            None
        }
    } else {
        None
    };
    let accountability = accountability_chain(&record);
    let response = AppletGhostIngressOutcome {
        applet_id: record.applet_id,
        ghost_actor_id: ghost.ghost_actor_id,
        external_id: ghost.external_id,
        display_name: ghost.display_name,
        accountability,
        message_id: message_result
            .as_ref()
            .map(|message| message.message_id.clone()),
        event_id: message_result
            .as_ref()
            .map(|message| message.event_id.clone()),
        operation_id: message_result
            .as_ref()
            .map(|message| message.operation_id.clone()),
        realm_id: message_result
            .as_ref()
            .map(|message| message.realm_id.clone()),
        portal_realm_id: message_result.map(|message| message.portal_realm_id),
    };
    json_ok(response)
}

#[salvo::oapi::endpoint(
    operation_id = "org.arkret.soland.applets.bot.message",
    tags("extensions")
)]
#[tracing::instrument(skip_all, fields(op = "org.arkret.soland.applets.bot.message"))]
async fn bot_message_endpoint(
    aa: AuthArgs,
    body: JsonBody<AppletPortalMessageRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AppletPortalMessageOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let _session = aa.authenticated_session(state, req).await?;
    let applet_id = applet_id_param(req)?;
    let body = body.into_inner();
    let record = applet_record(state, &applet_id)
        .await?
        .ok_or_else(|| AppError::not_found("applet is not registered"))?;
    ensure_not_revoked(&record).map_err(|_| {
        AppError::capability_denied("bot actor capability has been revoked")
            .with_status(StatusCode::FORBIDDEN)
            .with_wire_code("bot_actor_revoked")
    })?;
    let content = portal_message_payload(&body.payload)?.ok_or_else(|| {
        AppError::invalid_param("payload.kind must be \"message\" and payload.text is required")
    })?;
    let synthetic_ghost = GhostActorRecord {
        ghost_actor_id: record.bot_actor_id.clone(),
        external_id: "bot".to_owned(),
        display_name: Some("Applet Bot".to_owned()),
        request_digest: None,
        profile_event_ref: None,
        accountability_grant_ref: None,
        authorization_ref: None,
        created_at: record.registered_at,
        revoked_at: None,
    };
    let message_result =
        append_portal_message(state, &record, &synthetic_ghost, &body.realm_id, content).await?;
    json_ok(message_result)
}

#[cfg(test)]
mod revoke_saga_tests {
    use super::*;

    fn completed_execution() -> Value {
        json!({
            "principal_service_id": "did:web:service-a.example",
            "admin_actor_id": "did:web:admin-a.example",
            "idempotency_key": "revoke-key",
            "request_digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "outcome": {
                "ok": true,
                "operation_id": "ak:operation:01904100-0000-7000-8000-000000000001",
                "revoke_plan_digest": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "status": "complete",
                "steps": []
            }
        })
    }

    #[test]
    fn completed_replay_loads_the_terminal_outcome() {
        let execution = completed_execution();
        let outcome = load_stored_revoke_outcome(
            Some(&execution),
            "did:web:service-a.example",
            "did:web:admin-a.example",
            "revoke-key",
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        )
        .unwrap()
        .unwrap();
        assert_eq!(outcome.status, AppletRevokeSagaStatus::Complete);
        assert!(outcome.ok);
    }

    #[test]
    fn replay_binding_rejects_another_actor_or_service() {
        let execution = completed_execution();
        for (service, actor) in [
            ("did:web:service-a.example", "did:web:admin-b.example"),
            ("did:web:service-b.example", "did:web:admin-a.example"),
        ] {
            let error = load_stored_revoke_outcome(
                Some(&execution),
                service,
                actor,
                "revoke-key",
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            )
            .unwrap_err();
            assert_eq!(
                error.wire_code_override.as_deref(),
                Some("duplicate_conflict")
            );
        }
    }

    #[test]
    fn widget_only_never_fences_the_runtime() {
        assert!(!revoke_mode_fences_runtime(
            AppletRevokeMode::RevokeWidgetOnly
        ));
        assert!(revoke_mode_fences_runtime(
            AppletRevokeMode::RevokeRuntimeOnly
        ));
    }
}
