//! HTTP endpoint handlers and router assembly for the applet bridge.

use arkret_identifiers::{AppletId, Did, RealmId};
use arkret_models_collaboration::account_lifecycle::{
    AppletRevokeRequestBody, SessionRevokeOutcome, SessionRevokeRequestBody,
};
use arkret_models_collaboration::http_bodies::AppletTransactionRequestBody;
use arkret_models_integration::{
    AppletActorView, AppletInstallOutcome, AppletInstallPlan, AppletInstallPreviewRequestBody,
    AppletInstallRequestBody, AppletPingOutcome, AppletProtocolMetadata, AppletRealmView,
    AppletRevokeOutcome, AppletTransactionOutcome, ExternalRef, FieldType,
    GhostActorProvisionOutcome, GhostActorProvisionRequestBody, ProtocolInstance,
};
use arkret_wire::AppletRevokeMode;
use salvo::http::StatusCode;
use salvo::oapi::extract::JsonBody;
use salvo::prelude::*;
use serde_json::{Value, json};
use soland_http::error::AppError;
use soland_http::result::{JsonResult, json_ok};

use super::super::applet_manifest::verify_manifest;
use super::ghost::{
    ensure_formal_ghost_provision_allowed, external_user_from_ghost_request, provision_ghost,
    revoke_applet_record, revoke_applet_record_after_admin_gate,
    validate_ghost_actor_provision_request, validate_signed_ghost_provision_events,
};
use super::install::{
    append_portal_message, applet_response, approved_scopes_from_approval_request,
    build_install_plan, effective_scope_realm_id, parse_manifest, portal_message_payload,
    register_package_install, register_verified_applet, require_realm_admin,
    validate_applet_package,
};
use super::record::{
    accountability_chain, applet_display_name, applet_id_param, applet_record, applet_records,
    ensure_not_revoked, idempotency_key, query_value,
};
use super::signature::{
    VerifiedInboundTransactionSignature, require_inbound_transaction_signature,
};
use super::transaction::process_verified_transaction;
use super::types::{
    AppletGhostIngressOutcome, AppletGhostIngressRequestBody, AppletInstallPaths,
    AppletManifestRegisterRequestBody, AppletPortalMessageOutcome, AppletPortalMessageRequestBody,
    AppletProtocolDescribeOutcome, AppletRecord, AppletRevokeRecordOutcome, AppletView,
    GhostActorRecord, SOLAND_EDGE_APPLET_ID,
};
use crate::routing::identity::auth::revoke_delegated_sessions_for_applet;
use crate::routing::system::extract::AuthArgs;
use crate::state::AppState;

pub(in crate::routing::extensions) fn router() -> Router {
    Router::with_path("applets")
        .push(Router::with_path("register").post(register_endpoint))
        .push(
            Router::with_path("{applet_id}")
                .get(get_endpoint)
                .push(Router::with_path("ghosts").post(ghost_endpoint))
                .push(Router::with_path("bot/messages").post(bot_message_endpoint))
                .push(Router::with_path("revoke").post(revoke_endpoint)),
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
                            .push(Router::with_path("revoke").post(revoke_install_endpoint)),
                    ),
            ),
        )
}

#[handler]
#[tracing::instrument(skip_all, fields(op = "ak.edge.applet.query.ping"))]
async fn protocol_ping_endpoint(depot: &mut Depot) -> JsonResult<AppletPingOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let service_id = Did::new(state.service_id().clone()).map_err(|error| {
        AppError::internal(format!("configured service_id is invalid: {error}"))
    })?;
    json_ok(AppletPingOutcome {
        ok: true,
        applet_id: SOLAND_EDGE_APPLET_ID.to_owned(),
        service_id,
        protocol_version: "1.0".to_owned(),
    })
}

#[handler]
#[tracing::instrument(skip_all, fields(op = "ak.edge.applet.query.describe"))]
async fn protocol_describe_endpoint() -> JsonResult<AppletProtocolDescribeOutcome> {
    json_ok(AppletProtocolDescribeOutcome {
        contract: "ak.applet.v1".to_owned(),
        install: AppletInstallPaths {
            preview_path: "/_arkret/self/applets/install/preview".to_owned(),
            commit_path: "/_arkret/self/applets/install".to_owned(),
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

#[handler]
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

#[handler]
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
    let recomputed_plan = build_install_plan(
        state,
        &commit.applet_package,
        &commit.effective_scope,
        commit.approved_scopes.clone(),
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

    let response = register_package_install(
        state,
        &session.actor,
        commit,
        idempotency_key,
        body_digest,
        res,
    )
    .await?;
    json_ok(response)
}

#[handler]
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
    let revoke = body.into_inner();
    let record = applet_record(state, &applet_id)
        .await?
        .ok_or_else(|| AppError::not_found("applet is not registered"))?;
    let scope_realm = effective_scope_realm_id(&revoke.effective_scope);
    if record.portal_realm_id != scope_realm {
        return Err(
            AppError::conflict("effective_scope does not match active applet install")
                .with_wire_code("applet_effective_scope_mismatch"),
        );
    }
    // Governance gate: revoking a canonical install mutates the
    // realm-scoped registration; require `ak.realm.admin` over the install's
    // realm. fail-closed.
    require_realm_admin(state, &session.actor, &revoke.effective_scope).await?;
    let service_id = record
        .package
        .as_ref()
        .map(|package| package.service_id.to_string());
    let grant_refs = record
        .install_response
        .as_ref()
        .map(|response| {
            response
                .capability_grant_refs
                .iter()
                .map(|grant_id| grant_id.as_str().to_owned())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let mut revoked_refs = Vec::new();
    if matches!(
        revoke.revoke_mode,
        AppletRevokeMode::RevokeAll | AppletRevokeMode::RevokeRuntimeOnly
    ) {
        for grant_ref in &grant_refs {
            state
                .authorization()
                .mark_projected_grant_revoked(grant_ref);
            revoked_refs.push(grant_ref.clone());
        }
        let outcome =
            revoke_applet_record_after_admin_gate(state, &session.actor, &applet_id).await?;
        revoked_refs.push(outcome.bot_actor_id);
        revoked_refs.extend(outcome.ghost_actor_ids);
    }
    if matches!(
        revoke.revoke_mode,
        AppletRevokeMode::RevokeAll | AppletRevokeMode::RevokeDelegatedSessions
    ) {
        revoked_refs.extend(
            revoke_auth_side_delegated_sessions_for_applet(
                state,
                req,
                &record,
                &revoke,
                &grant_refs,
            )
            .await?,
        );
        revoked_refs.extend(
            revoke_delegated_sessions_for_applet(
                state,
                &applet_id,
                service_id.as_deref(),
                &grant_refs,
            )
            .await
            .map_err(AppError::internal)?,
        );
    }
    revoked_refs.sort();
    revoked_refs.dedup();
    crate::routing::append_audit_log(
        state,
        Some(&session.actor),
        "applet.revoke",
        json!({
            "applet_id": applet_id,
            "effective_scope_realm_id": scope_realm,
            "reason_code": revoke.reason_code,
            "revoke_mode": revoke.revoke_mode,
            "revoked_refs": revoked_refs,
        }),
        "accepted",
    )
    .await;
    json_ok(AppletRevokeOutcome {
        ok: true,
        revoked_refs,
        rejected: Vec::new(),
    })
}

async fn revoke_auth_side_delegated_sessions_for_applet(
    state: &AppState,
    req: &Request,
    record: &AppletRecord,
    revoke: &AppletRevokeRequestBody,
    grant_refs: &[String],
) -> Result<Vec<String>, AppError> {
    let Some(revoke_url) = session_grant_revoke_url(state)? else {
        return Ok(Vec::new());
    };
    let grant_jwt = soland_http::util::bearer_token(req)
        .map(str::to_owned)
        .ok_or_else(|| {
            AppError::unauthenticated(
                "applet delegated session revoke requires a presented session grant",
            )
        })?;
    let request = session_revoke_body_for_applet(record, revoke, grant_refs)?;
    let (revoke_url, client) = crate::security::validate_http_url_for_egress_with_pinned_client(
        &revoke_url,
        "applet delegated session revoke",
        state.config().development_mode,
        std::time::Duration::from_secs(10),
    )
    .map_err(AppError::capability_denied)?;
    let response = client
        .post(revoke_url)
        .bearer_auth(grant_jwt)
        .json(&request)
        .send()
        .await
        .map_err(|error| {
            AppError::new(
                soland_http::error::ErrorCode::TemporarilyUnavailable,
                format!("Auth-side applet delegated session revoke request failed: {error}"),
            )
        })?;
    let status = response.status();
    if status == reqwest::StatusCode::NOT_FOUND {
        return Ok(Vec::new());
    }
    if !status.is_success() {
        return Err(AppError::new(
            soland_http::error::ErrorCode::TemporarilyUnavailable,
            format!("Auth-side applet delegated session revoke was rejected: {status}"),
        ));
    }
    let outcome = response
        .json::<SessionRevokeOutcome>()
        .await
        .map_err(|error| {
            AppError::new(
                soland_http::error::ErrorCode::TemporarilyUnavailable,
                format!("invalid Auth-side applet delegated session revoke response: {error}"),
            )
        })?;
    Ok(outcome
        .revoked_grant_ids
        .into_iter()
        .map(|grant_id| grant_id.to_string())
        .collect())
}

fn session_grant_revoke_url(state: &AppState) -> Result<Option<String>, AppError> {
    let Some(introspection_url) = state.config().session_grant_introspection_url.as_deref() else {
        if state.config().development_mode {
            return Ok(None);
        }
        return Err(AppError::unsupported_feature(
            "applet delegated session revoke requires SOLAND_SESSION_GRANT_INTROSPECTION_URL",
        ));
    };
    introspection_url
        .strip_suffix("/session-grants/introspect")
        .map(|base| Some(format!("{base}/session-grants/revoke")))
        .ok_or_else(|| {
            AppError::unsupported_feature(
                "SOLAND_SESSION_GRANT_INTROSPECTION_URL must end in /session-grants/introspect so the Auth-side session-grants/revoke endpoint can be derived",
            )
        })
}

fn session_revoke_body_for_applet(
    record: &AppletRecord,
    revoke: &AppletRevokeRequestBody,
    grant_refs: &[String],
) -> Result<SessionRevokeRequestBody, AppError> {
    let package = record.package.as_ref().ok_or_else(|| {
        AppError::conflict("applet install projection is missing package metadata")
            .with_wire_code("applet_install_projection_incomplete")
    })?;
    let proof = revoke.proof.clone().ok_or_else(|| {
        AppError::capability_denied(
            "applet delegated session revoke requires a fresh session revoke lifecycle proof",
        )
    })?;
    Ok(SessionRevokeRequestBody {
        target_grant_id: None,
        target_device_id: None,
        all_sessions: None,
        applet_id: Some(AppletId::new(record.applet_id.clone()).map_err(|error| {
            AppError::internal(format!("stored applet_id is invalid: {error}"))
        })?),
        effective_scope: Some(match &revoke.effective_scope {
            arkret_wire::EffectiveScope::Realm { realm_id } => arkret_wire::EffectiveScope::Realm {
                realm_id: realm_id.clone(),
            },
            arkret_wire::EffectiveScope::Circle {
                realm_id,
                circle_id,
            } => arkret_wire::EffectiveScope::Circle {
                realm_id: realm_id.clone(),
                circle_id: circle_id.clone(),
            },
            _ => {
                return Err(AppError::invalid_param(
                    "unsupported applet effective scope",
                ));
            }
        }),
        registration_epoch: Some(package.registration_epoch.clone()),
        service_id: Some(package.service_id.clone()),
        capability_grant_refs: grant_refs.iter().map(ToString::to_string).collect(),
        proof: Some(proof),
    })
}

#[handler]
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

    // Wire ids are validated at deserialization (typed AppletId/Did/RealmId).
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

#[handler]
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

#[handler]
#[tracing::instrument(skip_all, fields(op = "ak.edge.applet.actor.query.resolve"))]
async fn resolve_actor_endpoint(
    req: &mut Request,
    depot: &mut Depot,
) -> JsonResult<AppletActorView> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let actor_id = req
        .param::<String>("actor_id")
        .ok_or_else(|| AppError::missing_param("actor_id path segment required"))?;
    if let Some(doc) = super::ghost::did_document_for_extension_actor(state, &actor_id).await? {
        let actor_id = Did::new(actor_id)
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

#[handler]
#[tracing::instrument(skip_all, fields(op = "ak.edge.applet.realm.query.resolve"))]
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

#[handler]
#[tracing::instrument(skip_all, fields(op = "ak.edge.applet.query.protocol_metadata"))]
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
        field_types: [
            ("applet_id", true),
            ("service_id", false),
            ("status", false),
        ]
        .into_iter()
        .map(|(name, required)| {
            (
                name.to_owned(),
                FieldType {
                    r#type: "string".to_owned(),
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

#[handler]
#[tracing::instrument(skip_all, fields(op = "ak.edge.applet.third_party_users.query.list"))]
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
                let actor_id = Did::new(ghost.ghost_actor_id.clone()).map_err(|error| {
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

#[handler]
#[tracing::instrument(
    skip_all,
    fields(op = "ak.edge.applet.third_party_locations.query.list")
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

#[handler]
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

#[handler]
#[tracing::instrument(skip_all, fields(op = "org.arkret.soland.applets.get"))]
async fn get_endpoint(req: &mut Request, depot: &mut Depot) -> JsonResult<AppletView> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let applet_id = applet_id_param(req)?;
    let record = applet_record(state, &applet_id)
        .await?
        .ok_or_else(|| AppError::not_found("applet is not registered"))?;
    json_ok(applet_response(&record))
}

#[handler]
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

#[handler]
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

#[handler]
#[tracing::instrument(skip_all, fields(op = "org.arkret.soland.applets.revoke"))]
async fn revoke_endpoint(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AppletRevokeRecordOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let applet_id = applet_id_param(req)?;
    json_ok(revoke_applet_record(state, &session.actor, &applet_id).await?)
}
