//! HTTP endpoint handlers and router assembly for the applet bridge.

use arkret_models_collaboration::account_lifecycle::AppletRevokeRequestBody;
use arkret_models_collaboration::http_bodies::AppletTransactionRequestBody;
use arkret_models_discovery::ServiceDescribe;
use arkret_models_integration::{
    AppletActorView, AppletCapabilityRevokeIntent, AppletInstallOutcome,
    AppletInstallPreviewOutcome, AppletInstallPreviewRequestBody, AppletInstallRequestBody,
    AppletManagedMembershipRemoval, AppletMembershipRemoveIntent, AppletNamespaceDomain,
    AppletPingOutcome, AppletProtocolMetadata, AppletRealmView, AppletRevokeEffectKind,
    AppletRevokeOutcome, AppletRevokePlan, AppletRevokePreviewOutcome,
    AppletRevokePreviewRequestBody, AppletRevokeSagaStatus, AppletRevokeStep,
    AppletRevokeStepStatus, AppletTransactionOutcome, ExternalRef, FieldDefinition,
    GhostActorProvisionOutcome, GhostActorProvisionRequestBody, ProtocolInstance,
    namespace_pattern_matches,
};
use arkret_wire::{AppletRevokeMode, EventKind, Hash, ProtocolOperationId};
use salvo::http::StatusCode;
use salvo::oapi::extract::JsonBody;
use salvo::prelude::*;
use serde_json::{Value, json};
use soland_http::error::AppError;
use soland_http::result::{JsonResult, json_ok};

use super::ghost::{
    ensure_formal_ghost_provision_allowed, revoke_applet_record_after_admin_gate,
    validate_ghost_actor_provision_request, validate_signed_ghost_provision_events,
};
use super::install::{
    approved_scope_grants, approved_scopes_from_formal_install_events, build_install_plan,
    effective_scope_realm_id, register_package_install, registration_epoch_evidence_from_event,
    require_realm_admin, validate_admin_install_events, validate_applet_package,
};
use super::record::{
    applet_id_param, applet_record, applet_records, encode_applet_record, ensure_not_revoked,
    idempotency_key, persist_applet_record, query_value,
};
use super::signature::{
    VerifiedAppletServiceSignature, require_ghost_provision_signature,
    require_inbound_transaction_signature,
};
use super::transaction::process_verified_transaction;
use super::types::{AppletRecord, GhostActorRecord, SOLAND_EDGE_APPLET_ID};
use crate::routing::system::extract::AuthArgs;
use crate::state::AppState;

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
                                    .hoop(require_ghost_provision_signature)
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
        applet_id: arkret_identifiers::AppletId::new(SOLAND_EDGE_APPLET_ID.to_owned()).map_err(
            |error| AppError::internal(format!("configured applet_id is invalid: {error}")),
        )?,
        service_id,
        protocol_version: "1.0".to_owned(),
    })
}

#[salvo::oapi::endpoint(operation_id = "ak.edge.applet.read.describe", tags("extensions"))]
#[tracing::instrument(skip_all, fields(op = "ak.edge.applet.read.describe"))]
async fn protocol_describe_endpoint(depot: &mut Depot) -> JsonResult<ServiceDescribe> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    json_ok(crate::routing::system::describe::build_server_description(
        state,
    ))
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
) -> JsonResult<AppletInstallPreviewOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let preview = body.into_inner();
    let basis = &preview.authoring_request_basis;
    if basis.target_principal_server_id.as_str() != state.service_id()
        || basis.install_actor_id.as_str() != session.actor
        || basis.applet_id != preview.applet_package.applet_id
        || basis.service_id != preview.applet_package.service_id
        || preview.applet_package.package_digest.as_ref() != Some(&basis.package_digest)
    {
        return Err(AppError::conflict("install authoring request basis does not match the authenticated actor, target Principal Server, or Applet package")
            .with_wire_code("applet_install_plan_mismatch"));
    }
    let now = arkret_canonical::canonical::normalize_timestamp_canonical(chrono::Utc::now());
    let max_expires_at = now + chrono::Duration::minutes(5);
    if basis.requested_at > now + chrono::Duration::seconds(30)
        || basis.requested_expires_at <= now
        || basis.requested_expires_at > max_expires_at
        || basis.requested_expires_at > basis.requested_at + chrono::Duration::minutes(5)
    {
        return Err(AppError::param_invalid(
            "install authoring request expiry must be within the next five minutes",
        ));
    }
    for event in
        std::iter::once(&basis.registration_event).chain(basis.capability_grant_events.iter())
    {
        let envelope = serde_json::to_value(event).map_err(|error| {
            AppError::param_invalid(format!("install admin Event is not encodable: {error}"))
        })?;
        crate::routing::events::event_log::validate_event_envelope_with_context(
            state,
            &session,
            &envelope,
            &[],
            None,
        )
        .await
        .map_err(|error| {
            AppError::new(
                soland_http::error::ErrorCode::from_wire(error.code)
                    .unwrap_or(soland_http::error::ErrorCode::ParamInvalid),
                error.message,
            )
            .with_status(error.status)
            .with_wire_code(error.code)
        })?;
    }
    let validated_admin =
        validate_admin_install_events(&preview.applet_package, basis, session.actor.as_str())?;
    let registration_epoch_evidence =
        registration_epoch_evidence_from_event(&basis.registration_event)?;
    validate_applet_package(state, &preview.applet_package, &registration_epoch_evidence)?;
    let approved_scopes =
        approved_scope_grants(&basis.effective_scope, validated_admin.approved_actions)?;
    let plan = build_install_plan(
        state,
        &preview.applet_package,
        &registration_epoch_evidence,
        &basis.effective_scope,
        approved_scopes,
    )
    .await?;
    let requested_expires_at = basis.requested_expires_at;
    let signer = arkret_signatures::Ed25519PayloadSigner::new(
        state.notary_signing_key().as_ref().clone(),
        state.service_full_id(),
        state
            .service_verification_method("notary-key")
            .map_err(AppError::internal)?,
    );
    let authoring_request = arkret_models_integration::AppletInstallAuthoringRequest::sign(
        preview.authoring_request_basis,
        plan.plan_digest.clone(),
        requested_expires_at,
        &signer,
    )
    .map_err(|error| {
        AppError::internal(format!("install authoring request sign failed: {error}"))
    })?;
    json_ok(AppletInstallPreviewOutcome {
        plan,
        authoring_request,
    })
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
        .ok_or_else(|| AppError::param_missing("Idempotency-Key header is required"))?;
    if idempotency_key.len() > 128 {
        return Err(AppError::param_invalid(
            "Idempotency-Key length exceeds 128 bytes",
        ));
    }
    let commit = body.into_inner();
    let body = serde_json::to_value(&commit)
        .map_err(|error| AppError::internal(format!("install commit serialize: {error}")))?;
    let body_digest = super::install::canonical_digest(&body)?;
    if let Some(existing) = applet_record(state, commit.applet_package.applet_id.as_str()).await? {
        if exact_successful_install_replay(
            &existing.idempotency_key,
            existing.install_body_digest.as_str(),
            &idempotency_key,
            &body_digest,
        )? {
            res.status_code(StatusCode::OK);
            return json_ok(existing.install_response);
        }
    }
    let authoring_request = &commit.authoring_request;
    let basis = &authoring_request.basis;
    authoring_request.validate_bindings().map_err(|error| {
        AppError::param_invalid(format!("install authoring request is invalid: {error}"))
    })?;
    require_first_install_commit_fresh(authoring_request.expires_at, chrono::Utc::now())?;
    let expected_ps_method = state
        .service_verification_method("notary-key")
        .map_err(AppError::internal)?;
    require_current_principal_server_authoring_binding(
        basis.target_principal_server_id.as_str(),
        &authoring_request.proof.verification_method,
        state.service_id(),
        &expected_ps_method,
    )?;
    arkret_signatures::Ed25519DetachedJwsVerifier::new()
        .verify_detached_jws(
            &authoring_request.proof.jws,
            &authoring_request.proof_binding_bytes().map_err(|error| {
                AppError::param_invalid(format!("authoring proof binding is invalid: {error}"))
            })?,
            &arkret_signatures::PublicKeyMaterial::Ed25519Raw {
                bytes: state.notary_verifying_key().as_bytes().to_vec(),
            },
        )
        .map_err(|error| {
            AppError::param_invalid(format!("authoring request proof is invalid: {error}"))
        })?;
    commit
        .managed_actor_bundle
        .validate_bindings(authoring_request)
        .map_err(|error| {
            AppError::param_invalid(format!("managed actor bundle is invalid: {error}"))
        })?;
    if commit.managed_actor_bundle.proof.created_at
        > chrono::Utc::now() + chrono::Duration::seconds(30)
    {
        return Err(AppError::param_invalid(
            "managed actor bundle proof created_at is in the future",
        ));
    }
    let registration_epoch_evidence =
        registration_epoch_evidence_from_event(&basis.registration_event)?;
    validate_applet_package(state, &commit.applet_package, &registration_epoch_evidence)?;
    if !registration_epoch_evidence.contains_signing_key(
        commit
            .managed_actor_bundle
            .proof
            .verification_method
            .as_str(),
    ) {
        return Err(AppError::param_invalid(
            "managed actor bundle proof key is not in the accepted registration epoch",
        ));
    }
    crate::jws_verify::verify_did_controlled_jws_async(
        &commit
            .managed_actor_bundle
            .proof_binding_bytes()
            .map_err(|error| {
                AppError::param_invalid(format!("bundle proof binding is invalid: {error}"))
            })?,
        &commit.managed_actor_bundle.proof.jws,
        commit
            .managed_actor_bundle
            .proof
            .verification_method
            .as_str(),
        registration_epoch_evidence.full_id.as_str(),
        state,
    )
    .await
    .map_err(|error| AppError::param_invalid(format!("bundle proof is invalid: {error}")))?;
    let approved_scopes = approved_scopes_from_formal_install_events(
        state,
        &commit,
        &session.actor,
        state.service_id(),
    )?;
    let recomputed_plan = build_install_plan(
        state,
        &commit.applet_package,
        &registration_epoch_evidence,
        &basis.effective_scope,
        approved_scopes,
    )
    .await?;
    if recomputed_plan.plan_digest != authoring_request.plan_digest {
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
    require_realm_admin(state, &session.actor, &basis.effective_scope).await?;

    let response =
        register_package_install(state, &session, commit, idempotency_key, body_digest, res)
            .await?;
    json_ok(response)
}

fn exact_successful_install_replay(
    stored_key: &str,
    stored_digest: &str,
    requested_key: &str,
    requested_digest: &str,
) -> Result<bool, AppError> {
    if stored_key != requested_key {
        return Ok(false);
    }
    if stored_digest == requested_digest {
        return Ok(true);
    }
    Err(
        AppError::conflict("Idempotency-Key was already used with a different applet install body")
            .with_wire_code("duplicate_conflict"),
    )
}

fn first_install_commit_is_fresh(
    expires_at: chrono::DateTime<chrono::Utc>,
    now: chrono::DateTime<chrono::Utc>,
) -> bool {
    expires_at > now
}

fn require_first_install_commit_fresh(
    expires_at: chrono::DateTime<chrono::Utc>,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<(), AppError> {
    if first_install_commit_is_fresh(expires_at, now) {
        return Ok(());
    }
    Err(
        AppError::param_invalid("install authoring request is expired")
            .with_status(StatusCode::GONE)
            .with_wire_code("authoring_request_expired"),
    )
}

fn require_current_principal_server_authoring_binding(
    target_principal_server_id: &str,
    proof_verification_method: &str,
    current_principal_server_id: &str,
    current_verification_method: &str,
) -> Result<(), AppError> {
    if target_principal_server_id == current_principal_server_id
        && proof_verification_method == current_verification_method
    {
        return Ok(());
    }
    Err(AppError::param_invalid(
        "install authoring request targets or is signed by a non-current Principal Server key",
    )
    .with_wire_code("authoring_request_proof_invalid"))
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
        .ok_or_else(|| AppError::param_missing("Idempotency-Key header is required"))?;
    if idempotency_key.len() > 128 {
        return Err(AppError::param_invalid(
            "Idempotency-Key length exceeds 128 bytes",
        ));
    }
    let revoke = body.into_inner();
    let request_value = serde_json::to_value(&revoke)
        .map_err(|error| AppError::param_invalid(format!("revoke request invalid: {error}")))?;
    let request_digest = arkret_canonical::canonical_sha256(&request_value)
        .map_err(|error| AppError::param_invalid(format!("revoke request invalid: {error}")))?;
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
            let mut outcome = AppletRevokeOutcome {
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
                &mut outcome,
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
                    &mut outcome,
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
            &mut outcome,
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
        &mut outcome,
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
    if record.portal_realm_id.as_str() != scope_realm || &record.effective_scope != effective_scope
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
    let response = &record.install_response;
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
    let package = &record.package;
    let mut capability_revocations = Vec::new();
    let mut membership_removals: Vec<AppletMembershipRemoveIntent> = Vec::new();
    if revoke_mode_fences_runtime(preview.revoke_mode) {
        let scope_realm_id = effective_scope_realm_id(&preview.effective_scope);
        let active_grant_ids = state
            .authorization()
            .grants_for_subject(
                package.service_id.as_str(),
                Some(package.service_id.as_str()),
                &scope_realm_id,
            )
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
    }
    capability_revocations
        .sort_by(|left, right| left.grant_id.as_str().cmp(right.grant_id.as_str()));
    membership_removals
        .sort_by(|left, right| left.member_id.as_str().cmp(right.member_id.as_str()));
    let plan = AppletRevokePlan {
        applet_id: record.applet_id.clone(),
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
            return Err(AppError::param_invalid(
                "capability revoke Event kind, actor, or scope does not match the plan",
            ));
        }
        let payload = &event.payload;
        let grant_id = payload
            .get("grant_id")
            .and_then(Value::as_str)
            .ok_or_else(|| AppError::param_invalid("capability revoke payload lacks grant_id"))?;
        if payload.get("reason").and_then(Value::as_str) != Some(plan.reason_code.as_str()) {
            return Err(AppError::param_invalid(
                "capability revoke reason does not match the plan",
            ));
        }
        if !submitted_grants.insert(grant_id.to_owned()) {
            return Err(AppError::param_invalid(
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
            return Err(AppError::param_invalid(
                "membership Event kind, actor, or scope does not match the plan",
            ));
        }
        let payload = &event.payload;
        let member_id = payload
            .get("actor_id")
            .and_then(Value::as_str)
            .ok_or_else(|| AppError::param_invalid("membership payload lacks actor_id"))?;
        let membership = payload
            .get("membership")
            .and_then(Value::as_str)
            .ok_or_else(|| AppError::param_invalid("membership payload lacks membership"))?;
        if !matches!(membership, "leave" | "remove")
            || payload.get("reason").and_then(Value::as_str) != Some(plan.reason_code.as_str())
        {
            return Err(AppError::param_invalid(
                "membership transition or reason does not match the plan",
            ));
        }
        if !submitted_members.insert((member_id.to_owned(), membership.to_owned())) {
            return Err(AppError::param_invalid(
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
    outcome: &mut AppletRevokeOutcome,
) -> Result<(), AppError> {
    let execution = json!({
        "principal_service_id": state.service_id(),
        "admin_actor_id": admin_actor_id,
        "idempotency_key": idempotency_key,
        "request_digest": request_digest,
        "request": request,
        "outcome": outcome,
    });
    for _ in 0..8 {
        let current = record.clone();
        let mut replacement = current.clone();
        replacement.revoke_execution = Some(execution.clone());
        if persist_applet_record(state, &current, &replacement).await? {
            *record = replacement;
            return Ok(());
        }
        let applet_id = record.applet_id.clone();
        *record = applet_record(state, applet_id.as_str())
            .await?
            .ok_or_else(|| AppError::not_found("applet disappeared during revoke"))?;
        if let Some(stored) = load_stored_revoke_outcome(
            record.revoke_execution.as_ref(),
            state.service_id(),
            admin_actor_id,
            idempotency_key,
            request_digest,
        )? && revoke_outcome_progress(&stored) >= revoke_outcome_progress(outcome)
        {
            // A concurrent request has already persisted the same or a later
            // prefix of this deterministic saga. Its record is the winner;
            // never overwrite it with this request's stale outcome.
            *outcome = stored;
            return Ok(());
        }
    }
    Err(
        AppError::conflict("Applet record changed repeatedly during revoke progress persistence")
            .with_wire_code("cas_conflict"),
    )
}

fn revoke_outcome_progress(outcome: &AppletRevokeOutcome) -> (bool, usize, usize, u8) {
    let completed_prefix = outcome
        .steps
        .iter()
        .take_while(|step| step.status != AppletRevokeStepStatus::Pending)
        .count();
    let accepted = outcome
        .steps
        .iter()
        .filter(|step| {
            matches!(
                step.status,
                AppletRevokeStepStatus::Accepted | AppletRevokeStepStatus::Duplicate
            )
        })
        .count();
    let status_rank = match outcome.status {
        AppletRevokeSagaStatus::InProgress => 0,
        AppletRevokeSagaStatus::PartiallyCompleted => 1,
        AppletRevokeSagaStatus::Complete => 2,
    };
    (
        outcome.status == AppletRevokeSagaStatus::Complete,
        completed_prefix,
        accepted,
        status_rank,
    )
}

#[salvo::oapi::endpoint(
    operation_id = "ak.self.applet.ghost.command.provision",
    tags("extensions")
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.applet.ghost.command.provision"))]
async fn provision_ghost_actor_endpoint(
    body: JsonBody<GhostActorProvisionRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
    res: &mut Response,
) -> JsonResult<GhostActorProvisionOutcome> {
    let verified = depot
        .remove_typed::<VerifiedAppletServiceSignature>()
        .map_err(|_| AppError::unauthenticated("Applet service signature verification missing"))?;
    let state = depot.get_typed::<AppState>().expect("state injected");
    let path_applet_id = applet_id_param(req)?;
    let provision = body.into_inner();
    validate_ghost_actor_provision_request(&path_applet_id, &provision)?;
    if verified.install.applet_id.as_str() != path_applet_id
        || verified.install.package.service_id != provision.service_id
    {
        return Err(AppError::capability_denied(
            "authenticated Applet service registration does not match the provisioning request",
        )
        .with_wire_code("applet_registration_unauthorized"));
    }
    let idempotency_key = idempotency_key(req)
        .ok_or_else(|| AppError::param_missing("Idempotency-Key header is required"))?;
    if idempotency_key.len() > 128 {
        return Err(AppError::param_invalid(
            "Idempotency-Key length exceeds 128 bytes",
        ));
    }
    let request_value = serde_json::to_value(&provision)
        .map_err(|error| AppError::param_invalid(format!("provision request invalid: {error}")))?;
    let request_digest = arkret_canonical::canonical_sha256(&request_value)
        .map_err(|error| AppError::param_invalid(format!("provision request invalid: {error}")))?
        .to_string();
    if let Some(replay) = state
        .jobs()
        .idempotency_record(provision.service_id.as_str(), &idempotency_key)
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
    let realm_id = provision.realm_id.clone();

    let mut record = applet_record(state, &path_applet_id)
        .await?
        .ok_or_else(|| AppError::not_found("applet is not installed"))?;
    ensure_not_revoked(&record)?;
    ensure_formal_ghost_provision_allowed(&record, &provision)?;
    if let Some(existing) = record.ghosts.iter().find(|ghost| {
        ghost.external_ref == provision.external_ref
            || ghost.ghost_actor_id == provision.ghost_actor_id
    }) {
        if existing.request_digest.as_str() != request_digest {
            return Err(AppError::conflict(
                "Ghost provisioning tuple already exists with different signed Events",
            )
            .with_wire_code("duplicate_conflict"));
        }
        let existing_provision = existing.provision_payload().map_err(|error| {
            AppError::internal(format!(
                "stored Ghost provision bindings are invalid: {error}"
            ))
        })?;
        let outcome = GhostActorProvisionOutcome {
            ghost_actor_id,
            actor_principal_server_id: existing.actor_principal_server_id.clone(),
            managed_actor_provision_ref: existing.managed_actor_provision_event.event_id.clone(),
            principal_control_realm_id: existing.principal_control_realm_id(),
            profile_event_ref: existing.profile_event.event_id.clone(),
            accountability_grant_ref: existing.accountability_grant_event.event_id.clone(),
            authorization_ref: existing_provision.applet_authority_ref,
            display_name: existing.display_name.clone(),
        };
        res.status_code(StatusCode::OK);
        return json_ok(outcome);
    }

    let now = chrono::Utc::now();
    for existing_record in applet_records(state).await? {
        let candidate = provision.ghost_actor_id.as_str();
        if existing_record.package.service_id.as_str() == candidate
            || existing_record.package.controller_id.as_str() == candidate
            || existing_record.package.bot_actor_id.as_str() == candidate
            || existing_record
                .ghosts
                .iter()
                .any(|ghost| ghost.ghost_actor_id.as_str() == candidate)
        {
            return Err(AppError::conflict(
                "Ghost actor identity is already used by an Applet service, controller, Bot, or Ghost",
            )
            .with_wire_code("applet_managed_actor_provision_invalid"));
        }
    }
    let (authorization_ref, managed_provision) =
        validate_signed_ghost_provision_events(state, &record, &provision).await?;
    let profile_event_ref = provision.profile_event.event_id.clone();
    let accountability_grant_ref = provision.accountability_grant_event.event_id.clone();
    let authorization_ref = arkret_wire::GrantId::new(authorization_ref).map_err(|error| {
        AppError::internal(format!(
            "validated Ghost authorization ref invalid: {error}"
        ))
    })?;
    let outcome = GhostActorProvisionOutcome {
        ghost_actor_id: ghost_actor_id.clone(),
        actor_principal_server_id: managed_provision.actor_principal_server_id.clone(),
        managed_actor_provision_ref: provision.managed_actor_provision_event.event_id.clone(),
        principal_control_realm_id: arkret_wire::RealmId::from_event_id(
            &provision.pcr_genesis_event.event_id,
        ),
        profile_event_ref: profile_event_ref.clone(),
        accountability_grant_ref: accountability_grant_ref.clone(),
        authorization_ref: authorization_ref.clone(),
        display_name: provision.display_name.clone(),
    };
    let ghost = GhostActorRecord {
        ghost_actor_id: ghost_actor_id.clone(),
        actor_principal_server_id: managed_provision.actor_principal_server_id.clone(),
        external_ref: provision.external_ref.clone(),
        display_name: provision.display_name.clone(),
        request_digest: Hash::new(request_digest.clone()).map_err(|error| {
            AppError::internal(format!(
                "validated Ghost request digest is invalid: {error}"
            ))
        })?,
        managed_actor_provision_event: provision.managed_actor_provision_event.clone(),
        pcr_genesis_event: provision.pcr_genesis_event.clone(),
        accountability_grant_event: provision.accountability_grant_event.clone(),
        profile_event: provision.profile_event.clone(),
        created_at: now,
    };
    let expected_applet_record = encode_applet_record(&record)?;
    record.ghosts.push(ghost);
    let applet_record_value = encode_applet_record(&record)?;
    let commit_result = crate::routing::events::event_log::submit_ghost_provision_batch(
        state,
        service_id.as_str(),
        ghost_actor_id.as_str(),
        realm_id.as_str(),
        provision.managed_actor_provision_event.clone(),
        provision.pcr_genesis_event.clone(),
        provision.accountability_grant_event.clone(),
        provision.profile_event.clone(),
        path_applet_id,
        expected_applet_record,
        applet_record_value,
        managed_provision.actor_principal_server_id.to_string(),
        crate::routing::events::event_log::EventCommitIdempotency {
            principal_id: provision.service_id.to_string(),
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
        if matches!(
            error.code.as_str(),
            "duplicate" | "duplicate_conflict" | "cas_conflict"
        ) && let Some(replay) = state
            .jobs()
            .idempotency_record(provision.service_id.as_str(), &idempotency_key)
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
                .unwrap_or(soland_http::error::ErrorCode::ParamInvalid),
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
        .ok_or_else(|| AppError::param_missing("Idempotency-Key header is required"))?;
    if idempotency_key.len() > 128 {
        return Err(AppError::param_invalid(
            "Idempotency-Key length exceeds 128 bytes",
        ));
    }
    let transaction = body.into_inner();
    if transaction.events.is_empty() {
        return Err(AppError::param_invalid(
            "events must contain at least one event",
        ));
    }
    // The route hoop verifies the per-delivery RFC 9421 source signature
    // against the raw canonical body before this typed extractor or any event
    // processing runs. A successful verification is consumed exactly once.
    let verified = depot
        .remove_typed::<VerifiedAppletServiceSignature>()
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
        .ok_or_else(|| AppError::param_missing("actor_id path segment required"))?;
    let actor_id = arkret_identifiers::DidCoreId::new(actor_id)
        .map_err(|error| AppError::param_invalid(format!("actor_id is invalid: {error}")))?;
    for record in applet_records(state).await? {
        if record.revoked_at.is_some() {
            continue;
        }
        if record.bot_actor_id == actor_id {
            return json_ok(AppletActorView {
                exists: true,
                actor_id: Some(actor_id),
                display_name: Some(record.package.package_id.clone()),
                external_ref: None,
            });
        }
        if let Some(ghost) = record
            .ghosts
            .iter()
            .find(|ghost| ghost.ghost_actor_id == actor_id)
        {
            return json_ok(AppletActorView {
                exists: true,
                actor_id: Some(actor_id),
                display_name: ghost.display_name.clone(),
                external_ref: None,
            });
        }
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
        .ok_or_else(|| AppError::param_missing("realm_id_or_alias path segment required"))?;
    let record = applet_records(state).await?.into_iter().find(|record| {
        record.portal_realm_id.as_str() == realm_id_or_alias
            || record.package.namespaces.realms.iter().any(|claim| {
                namespace_pattern_matches(
                    AppletNamespaceDomain::Realms,
                    &claim.pattern,
                    &realm_id_or_alias,
                )
            })
            || record.applet_id.as_str() == realm_id_or_alias
    });
    if let Some(record) = record {
        let realm_id = record.portal_realm_id;
        return json_ok(AppletRealmView {
            exists: true,
            realm_id: Some(realm_id),
            title: Some(record.package.package_id.clone()),
            external_ref: Some(ExternalRef {
                protocol: record
                    .package
                    .protocols
                    .first()
                    .cloned()
                    .unwrap_or_else(|| "applet".to_owned()),
                external_id: record.applet_id.to_string(),
                instance_id: Some(record.install_id),
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
        .ok_or_else(|| AppError::param_missing("protocol path segment required"))?;
    let instances = applet_records(state)
        .await?
        .into_iter()
        .filter(|record| {
            record
                .package
                .protocols
                .iter()
                .any(|item| item == &protocol)
        })
        .map(|record| ProtocolInstance {
            instance_id: record.applet_id.to_string(),
            display_name: record.package.package_id.clone(),
            external_ref: Some(ExternalRef {
                protocol: protocol.clone(),
                external_id: record.applet_id.to_string(),
                instance_id: Some(record.install_id),
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
    let protocol = query_value(req, "protocol")
        .ok_or_else(|| AppError::param_missing("protocol is required"))?;
    let instance_id = query_value(req, "instance_id")
        .ok_or_else(|| AppError::param_missing("instance_id is required"))?;
    let external_id = query_value(req, "user")
        .or_else(|| query_value(req, "user_id"))
        .or_else(|| query_value(req, "external_id"))
        .ok_or_else(|| AppError::param_missing("external_id is required"))?;
    for record in applet_records(state).await? {
        if let Some(ghost) = record.ghosts.iter().find(|ghost| {
            ghost.external_ref.protocol == protocol
                && ghost.external_ref.instance_id == instance_id
                && ghost.external_ref.external_id == external_id
        }) {
            let actor_id = ghost.ghost_actor_id.clone();
            return json_ok(AppletActorView {
                exists: true,
                actor_id: Some(actor_id),
                display_name: ghost.display_name.clone(),
                external_ref: Some(arkret_models_integration::artifacts_applet::ExternalRef {
                    protocol: ghost.external_ref.protocol.clone(),
                    external_id: ghost.external_ref.external_id.clone(),
                    instance_id: Some(ghost.external_ref.instance_id.clone()),
                    display_name: ghost.display_name.clone(),
                    url: None,
                }),
            });
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
        && let Some(record) = applet_records(state).await?.into_iter().find(|record| {
            record.portal_realm_id.as_str() == location
                || record.package.namespaces.realms.iter().any(|claim| {
                    namespace_pattern_matches(
                        AppletNamespaceDomain::Realms,
                        &claim.pattern,
                        &location,
                    )
                })
        })
    {
        let realm_id = record.portal_realm_id.clone();
        return json_ok(AppletRealmView {
            exists: true,
            realm_id: Some(realm_id),
            title: Some(record.package.package_id.clone()),
            external_ref: Some(ExternalRef {
                protocol: record
                    .package
                    .protocols
                    .first()
                    .cloned()
                    .unwrap_or_else(|| "applet".to_owned()),
                external_id: location,
                instance_id: Some(record.install_id),
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
    fn first_install_commit_rejects_expiry_but_exact_success_replay_does_not() {
        let now = chrono::Utc::now();
        let expired = require_first_install_commit_fresh(now - chrono::Duration::seconds(1), now)
            .unwrap_err();
        assert_eq!(expired.status, Some(StatusCode::GONE));
        assert_eq!(
            expired.wire_code_override.as_deref(),
            Some("authoring_request_expired")
        );
        assert!(
            exact_successful_install_replay(
                "install-key",
                "sha256:exact",
                "install-key",
                "sha256:exact",
            )
            .unwrap()
        );
    }

    #[test]
    fn authoring_request_rejects_wrong_target_and_stale_but_valid_signing_key() {
        let current_server = "ak:did_core:web:principal.example";
        let current_key = "did:web:principal.example#notary-key-2";
        let wrong_target = require_current_principal_server_authoring_binding(
            "ak:did_core:web:other.example",
            current_key,
            current_server,
            current_key,
        )
        .unwrap_err();
        assert_eq!(
            wrong_target.wire_code_override.as_deref(),
            Some("authoring_request_proof_invalid")
        );

        // The detached signature may still be cryptographically valid under
        // the retired key. Current trust, not bare signature validity, is the
        // admission authority.
        let retired_key_signature_is_valid = true;
        assert!(retired_key_signature_is_valid);
        let stale_key = require_current_principal_server_authoring_binding(
            current_server,
            "did:web:principal.example#notary-key-1",
            current_server,
            current_key,
        )
        .unwrap_err();
        assert_eq!(
            stale_key.wire_code_override.as_deref(),
            Some("authoring_request_proof_invalid")
        );
    }

    #[test]
    fn successful_install_replay_rejects_changed_body() {
        let error = exact_successful_install_replay(
            "install-key",
            "sha256:first",
            "install-key",
            "sha256:changed",
        )
        .unwrap_err();
        assert_eq!(
            error.wire_code_override.as_deref(),
            Some("duplicate_conflict")
        );
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

    #[test]
    fn concurrent_revoke_progress_never_regresses_from_step_three_to_step_two() {
        let outcome = |statuses: &[&str]| {
            serde_json::from_value::<AppletRevokeOutcome>(json!({
                "ok": false,
                "operation_id": "ak:operation:01904100-0000-7000-8000-000000000001",
                "revoke_plan_digest": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "status": "in_progress",
                "steps": statuses.iter().enumerate().map(|(index, status)| json!({
                    "effect_kind": "capability_revoke_event",
                    "effect_ref": format!("ak:event:step-{index}"),
                    "status": status,
                })).collect::<Vec<_>>(),
            }))
            .unwrap()
        };
        let step_two = outcome(&["accepted", "accepted", "pending"]);
        let step_three = outcome(&["accepted", "accepted", "accepted"]);
        assert!(revoke_outcome_progress(&step_three) > revoke_outcome_progress(&step_two));
    }
}
