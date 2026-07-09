//! HTTP endpoint handlers and router assembly for the applet bridge.

use arkret_sdk::{
    AppletActorView, AppletPingOutcome, AppletProtocolMetadata, AppletRealmView, AppletRevokeMode,
    AppletRevokeOutcome, AppletTransactionOutcome, AppletTransactionRequestBody, Did,
    GhostActorProvisionOutcome, GhostActorProvisionRequestBody, InstallCommitOutcome,
    InstallCommitRequestBody, InstallPlan, InstallPreviewRequestBody, InstallRevokeRequestBody,
    RealmId, SessionRevokeOutcome, SessionRevokeRequestBody,
};
use salvo::http::StatusCode;
use salvo::oapi::extract::JsonBody;
use salvo::prelude::*;
use serde_json::{Value, json};

use super::super::applet_manifest::verify_manifest;
use super::ghost::{
    build_ghost_accountability_grant_event, build_ghost_profile_create_event,
    ensure_formal_ghost_provision_allowed, external_user_from_ghost_request,
    persist_formal_applet_event, provision_ghost, revoke_applet_record,
    revoke_applet_record_after_admin_gate, validate_ghost_actor_provision_request,
};
use super::install::{
    append_portal_message, applet_response, approved_scopes_from_approval_request,
    build_install_plan, effective_scope_realm_id, parse_manifest, portal_message_payload,
    register_package_install, register_verified_applet, require_realm_admin,
    validate_applet_package,
};
use super::record::{
    accountability_chain, applet_display_name, applet_id_param, applet_record, applet_records,
    ensure_not_revoked, idempotency_key, persist_applet_record, query_value,
};
use super::signature::verify_inbound_transaction_signature;
use super::transaction::process_verified_transaction;
use super::types::{
    AppletGhostIngressOutcome, AppletGhostIngressRequestBody, AppletInstallPaths,
    AppletManifestRegisterRequestBody, AppletPortalMessageOutcome, AppletPortalMessageRequestBody,
    AppletProtocolDescribeOutcome, AppletRecord, AppletRevokeRecordOutcome, AppletView,
    GhostActorRecord, SOLAND_EDGE_APPLET_ID,
};
use crate::error::AppError;
use crate::result::{JsonResult, json_ok};
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
                    .push(Router::with_path("transactions").post(transaction_endpoint))
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

#[endpoint(
    operation_id = "ck.edge.applet.query.ping",
    tags("applet"),
    summary = "Applet service liveness probe"
)]
#[tracing::instrument(skip_all, fields(op = "ck.edge.applet.query.ping"))]
async fn protocol_ping_endpoint(depot: &mut Depot) -> JsonResult<AppletPingOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let service_did = Did::new(state.config.service_did.clone()).map_err(|error| {
        AppError::internal(format!("configured service_did is invalid: {error}"))
    })?;
    json_ok(AppletPingOutcome {
        ok: true,
        applet_id: SOLAND_EDGE_APPLET_ID.to_owned(),
        service_did,
        protocol_version: "1.0".to_owned(),
    })
}

#[endpoint(
    operation_id = "ck.edge.applet.query.describe",
    tags("applet"),
    summary = "Describe soland's applet protocol support"
)]
#[tracing::instrument(skip_all, fields(op = "ck.edge.applet.query.describe"))]
async fn protocol_describe_endpoint() -> JsonResult<AppletProtocolDescribeOutcome> {
    json_ok(AppletProtocolDescribeOutcome {
        contract: "ck.applet.v1".to_owned(),
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
                "Source-Service-DID",
                "Destination-Service-DID",
                "Idempotency-Key"
            ],
            "covered_components": [
                "@method",
                "@target-uri",
                "@authority",
                "content-digest",
                "source-service-did",
                "destination-service-did",
                "idempotency-key"
            ],
            "source_signature_anchor": "ck.applet.source_signature_anchor.v1",
            "bearer_only": false
        }),
        package_schema: "ck.schema.applet_package.v1".to_owned(),
    })
}

#[endpoint(
    operation_id = "ck.self.applet.install.command.preview",
    tags("applet"),
    summary = "Preview a canonical applet install plan",
    status_codes(200, 400, 401, 403, 409)
)]
#[tracing::instrument(skip_all, fields(op = "ck.self.applet.install.command.preview"))]
async fn install_preview_endpoint(
    aa: AuthArgs,
    body: JsonBody<InstallPreviewRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<InstallPlan> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let _session = aa.authenticated_session(state, req).await?;
    let preview = body.into_inner();
    validate_applet_package(state, &preview.applet_package)?;
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

#[endpoint(
    operation_id = "ck.self.applet.command.install",
    tags("applet"),
    summary = "Commit a canonical applet install",
    status_codes(200, 201, 400, 401, 403, 409)
)]
#[tracing::instrument(skip_all, fields(op = "ck.self.applet.command.install"))]
async fn install_endpoint(
    aa: AuthArgs,
    body: JsonBody<InstallCommitRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
    res: &mut Response,
) -> JsonResult<InstallCommitOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let idempotency_key = idempotency_key(req)
        .ok_or_else(|| AppError::missing_param("Idempotency-Key header is required"))?;
    if idempotency_key.len() > 128 {
        return Err(AppError::invalid_param(
            "Idempotency-Key length exceeds 128 bytes",
        ));
    }
    let commit = body.into_inner();
    let body = serde_json::to_value(&commit)
        .map_err(|error| AppError::internal(format!("install commit serialize: {error}")))?;
    let body_digest = super::install::canonical_digest(&body)?;
    validate_applet_package(state, &commit.applet_package)?;
    let recomputed_plan = build_install_plan(
        state,
        &commit.applet_package,
        &commit.effective_scope,
        commit.approved_scopes.clone(),
    )
    .await?;
    let recomputed_digest = recomputed_plan
        .plan_digest
        .as_ref()
        .ok_or_else(|| AppError::internal("install plan missing digest"))?;
    if recomputed_digest != &commit.plan_digest {
        return Err(
            AppError::conflict("install plan digest does not match recomputed plan")
                .with_wire_code("applet_install_plan_mismatch"),
        );
    }

    // Governance gate: the canonical install write projects a
    // `ck.realm.admin`-scoped registration onto the effective_scope realm.
    // Authentication alone is insufficient — the actor MUST hold realm admin
    // over that realm. P1 projected capability grants into the authz index, so
    // `state.authz.check` is authoritative here. fail-closed.
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

#[endpoint(
    operation_id = "ck.self.applet.command.revoke",
    tags("applet"),
    summary = "Revoke a canonical applet install",
    status_codes(200, 400, 401, 403, 404, 409)
)]
#[tracing::instrument(skip_all, fields(op = "ck.self.applet.command.revoke"))]
async fn revoke_install_endpoint(
    aa: AuthArgs,
    body: JsonBody<InstallRevokeRequestBody>,
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
    // realm-scoped registration; require `ck.realm.admin` over the install's
    // realm. fail-closed.
    require_realm_admin(state, &session.actor, &revoke.effective_scope).await?;
    let service_did = record
        .package
        .as_ref()
        .map(|package| package.service_did.to_string());
    let grant_refs = record
        .install_response
        .as_ref()
        .map(|response| response.capability_grant_refs.clone())
        .unwrap_or_default();
    let mut revoked_refs = Vec::new();
    if matches!(
        revoke.revoke_mode,
        AppletRevokeMode::RevokeAll | AppletRevokeMode::RevokeRuntimeOnly
    ) {
        for grant_ref in &grant_refs {
            state.authz.mark_projected_grant_revoked(grant_ref);
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
                service_did.as_deref(),
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
    revoke: &InstallRevokeRequestBody,
    grant_refs: &[String],
) -> Result<Vec<String>, AppError> {
    let Some(revoke_url) = session_grant_revoke_url(state)? else {
        return Ok(Vec::new());
    };
    let grant_jwt = crate::routing::system::util::bearer_token(req)
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
        state.config.development_mode,
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
                crate::error::ErrorCode::TemporarilyUnavailable,
                format!("Auth-side applet delegated session revoke request failed: {error}"),
            )
        })?;
    let status = response.status();
    if status == reqwest::StatusCode::NOT_FOUND {
        return Ok(Vec::new());
    }
    if !status.is_success() {
        return Err(AppError::new(
            crate::error::ErrorCode::TemporarilyUnavailable,
            format!("Auth-side applet delegated session revoke was rejected: {status}"),
        ));
    }
    let outcome = response
        .json::<SessionRevokeOutcome>()
        .await
        .map_err(|error| {
            AppError::new(
                crate::error::ErrorCode::TemporarilyUnavailable,
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
    let Some(introspection_url) = state.config.session_grant_introspection_url.as_deref() else {
        if state.config.development_mode {
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
    revoke: &InstallRevokeRequestBody,
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
    let effective_scope = serde_json::to_value(&revoke.effective_scope).map_err(|error| {
        AppError::internal(format!("serialize applet effective_scope: {error}"))
    })?;
    Ok(SessionRevokeRequestBody {
        target_grant_id: None,
        target_device_id: None,
        all_sessions: None,
        applet_id: Some(record.applet_id.clone()),
        effective_scope: Some(effective_scope),
        registration_epoch: Some(package.registration_epoch.clone()),
        service_did: Some(package.service_did.clone()),
        capability_grant_refs: grant_refs.to_vec(),
        proof: Some(proof),
    })
}

#[endpoint(
    operation_id = "ck.self.applet.ghost.command.provision",
    tags("applet"),
    summary = "Provision an applet-managed Ghost Actor profile and accountability grant",
    status_codes(200, 201, 400, 401, 403, 404, 409, 500)
)]
#[tracing::instrument(skip_all, fields(op = "ck.self.applet.ghost.command.provision"))]
async fn provision_ghost_actor_endpoint(
    aa: AuthArgs,
    body: JsonBody<GhostActorProvisionRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
    res: &mut Response,
) -> JsonResult<GhostActorProvisionOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let _session = aa.authenticated_session(state, req).await?;
    let path_applet_id = applet_id_param(req)?;
    let provision = body.into_inner();
    validate_ghost_actor_provision_request(&path_applet_id, &provision)?;

    // Wire ids are validated at deserialization (typed AppletId/Did/RealmId).
    let applet_id = provision.applet_id.clone();
    let service_did = provision.service_did.clone();
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

    let now = chrono::Utc::now();
    let grant_event = build_ghost_accountability_grant_event(
        state,
        &record,
        &provision,
        &service_did,
        &ghost_actor_id,
        &realm_id,
        now,
    )
    .await?;
    let authorization_ref = grant_event.event_id.clone();

    let profile_event = build_ghost_profile_create_event(
        state,
        &record,
        &provision,
        applet_id,
        &service_did,
        &ghost_actor_id,
        &realm_id,
        &authorization_ref,
    )
    .await?;

    persist_formal_applet_event(state, grant_event).await?;
    persist_formal_applet_event(state, profile_event.clone()).await?;
    persist_formal_ghost_record(
        state,
        record,
        &ghost_actor_id,
        &provision.external_user_id,
        provision.display_name.clone(),
        now,
    )
    .await?;

    crate::routing::append_audit_log(
        state,
        Some(service_did.as_ref()),
        "applet.ghost_actor.provision",
        json!({
            "applet_id": provision.applet_id,
            "service_did": service_did,
            "ghost_actor_id": ghost_actor_id,
            "realm_id": realm_id,
            "profile_event_ref": profile_event.event_id,
            "accountability_grant_ref": authorization_ref,
        }),
        "accepted",
    )
    .await;

    res.status_code(StatusCode::CREATED);
    let outcome = GhostActorProvisionOutcome {
        ghost_actor_id,
        profile_event_ref: profile_event.event_id.clone(),
        accountability_grant_ref: authorization_ref.clone(),
        authorization_ref,
        display_name: provision.display_name,
    };
    json_ok(outcome)
}

async fn persist_formal_ghost_record(
    state: &AppState,
    mut record: AppletRecord,
    ghost_actor_id: &Did,
    external_id: &str,
    display_name: Option<String>,
    created_at: chrono::DateTime<chrono::Utc>,
) -> Result<(), AppError> {
    if record
        .ghosts
        .iter()
        .any(|ghost| ghost.ghost_actor_id == ghost_actor_id.as_str())
    {
        return Ok(());
    }
    record.ghosts.push(GhostActorRecord {
        ghost_actor_id: ghost_actor_id.to_string(),
        external_id: external_id.to_owned(),
        display_name,
        created_at,
        revoked_at: None,
    });
    persist_applet_record(state, &record).await
}

#[endpoint(
    operation_id = "ck.edge.applet.command.transaction",
    tags("applet"),
    summary = "Receive an applet transaction",
    status_codes(200, 400, 401, 403, 409)
)]
#[tracing::instrument(skip_all, fields(op = "ck.edge.applet.command.transaction"))]
async fn transaction_endpoint(
    body: JsonBody<AppletTransactionRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AppletTransactionOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
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
    // COT-03-001 / applet-integration.md §7.3.1: the app/bridge → arkret edge
    // inbound direction MUST carry a per-delivery RFC 9421 source signature and
    // the receiver MUST verify it before processing any event / side effect.
    // Plain `Authorization: Bearer` (no `Signature`) MUST be rejected. The
    // signing key anchor is the Applet registration `source_service_did`'s
    // current active verification method, and that service DID MUST hit an
    // active effective install (§4b.1).
    let verified =
        verify_inbound_transaction_signature(state, req, &transaction, &idempotency_key).await?;
    let outcome =
        process_verified_transaction(state, transaction, &idempotency_key, verified).await?;
    json_ok(outcome)
}

#[endpoint(
    operation_id = "ck.edge.applet.actor.query.resolve",
    tags("applet"),
    summary = "Resolve an applet actor"
)]
#[tracing::instrument(skip_all, fields(op = "ck.edge.applet.actor.query.resolve"))]
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
            external_ref: json!({
                "applet_id": doc.get("applet_id").cloned().unwrap_or(Value::Null),
                "accountability": doc.get("accountability").cloned().unwrap_or(Value::Null),
            }),
        });
    }
    json_ok(AppletActorView {
        exists: false,
        actor_id: None,
        display_name: None,
        external_ref: Value::Null,
    })
}

#[endpoint(
    operation_id = "ck.edge.applet.realm.query.resolve",
    tags("applet"),
    summary = "Resolve an applet realm"
)]
#[tracing::instrument(skip_all, fields(op = "ck.edge.applet.realm.query.resolve"))]
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
            external_ref: json!({"applet_id": record.applet_id}),
        });
    }
    json_ok(AppletRealmView {
        exists: false,
        realm_id: None,
        title: None,
        external_ref: Value::Null,
    })
}

#[endpoint(
    operation_id = "ck.edge.applet.query.protocol_metadata",
    tags("applet"),
    summary = "Read applet protocol metadata"
)]
#[tracing::instrument(skip_all, fields(op = "ck.edge.applet.query.protocol_metadata"))]
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
        .map(|record| {
            json!({
                "instance_id": record.applet_id.clone(),
                "display_name": applet_display_name(&record.manifest)
                    .unwrap_or_else(|| record.namespace.clone()),
                "external_ref": {
                    "protocol": protocol.clone(),
                    "external_id": record.applet_id.clone(),
                    "instance_id": record.install_id.clone(),
                },
                "service_did": record
                    .package
                    .as_ref()
                    .map(|package| package.service_did.to_string()),
                "status": record.status.clone(),
            })
        })
        .collect::<Vec<_>>();
    json_ok(AppletProtocolMetadata {
        protocol: protocol.clone(),
        display_name: format!("{protocol} applet protocol"),
        icon_blob_ref: None,
        field_types: json!({
            "applet_id": {"type": "string", "required": true},
            "service_did": {"type": "string"},
            "status": {"type": "string"},
        }),
        instances,
    })
}

#[endpoint(
    operation_id = "ck.edge.applet.third_party_users.query.list",
    tags("applet"),
    summary = "Resolve a third-party applet user"
)]
#[tracing::instrument(skip_all, fields(op = "ck.edge.applet.third_party_users.query.list"))]
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
                    external_ref: json!({
                        "external_id": ghost.external_id.clone(),
                        "applet_id": record.applet_id.clone(),
                    }),
                });
            }
        }
    }
    json_ok(AppletActorView {
        exists: false,
        actor_id: None,
        display_name: None,
        external_ref: Value::Null,
    })
}

#[endpoint(
    operation_id = "ck.edge.applet.third_party_locations.query.list",
    tags("applet"),
    summary = "Resolve a third-party applet location"
)]
#[tracing::instrument(
    skip_all,
    fields(op = "ck.edge.applet.third_party_locations.query.list")
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
            external_ref: json!({"location": location, "applet_id": record.applet_id}),
        });
    }
    json_ok(AppletRealmView {
        exists: false,
        realm_id: None,
        title: None,
        external_ref: Value::Null,
    })
}

#[endpoint(
    operation_id = "org.arkret.soland.applets.register",
    tags("extensions"),
    summary = "Register a verified applet manifest and issue a bot actor DID",
    status_codes(200, 201, 400, 401, 403, 409)
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

#[endpoint(
    operation_id = "org.arkret.soland.applets.get",
    tags("extensions"),
    summary = "Read applet bridge registration state"
)]
#[tracing::instrument(skip_all, fields(op = "org.arkret.soland.applets.get"))]
async fn get_endpoint(req: &mut Request, depot: &mut Depot) -> JsonResult<AppletView> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let applet_id = applet_id_param(req)?;
    let record = applet_record(state, &applet_id)
        .await?
        .ok_or_else(|| AppError::not_found("applet is not registered"))?;
    json_ok(applet_response(&record))
}

#[endpoint(
    operation_id = "org.arkret.soland.applets.ghosts.provision",
    tags("extensions"),
    summary = "Provision or reuse a ghost actor and optionally route a portal message"
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

#[endpoint(
    operation_id = "org.arkret.soland.applets.bot.message",
    tags("extensions"),
    summary = "Write a portal message as the applet bot actor"
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
        created_at: record.registered_at,
        revoked_at: None,
    };
    let message_result =
        append_portal_message(state, &record, &synthetic_ghost, &body.realm_id, content).await?;
    json_ok(message_result)
}

#[endpoint(
    operation_id = "org.arkret.soland.applets.revoke",
    tags("extensions"),
    summary = "Revoke an applet's bot and ghost capabilities"
)]
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
