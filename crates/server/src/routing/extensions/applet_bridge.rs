//! Applet package install, bot/ghost provisioning, and portal routing.
//!
//! This closes the runnable surface for the `extensions/applet-bridge`
//! contract: a verified Applet Package installs an applet, soland issues a
//! stable bot DID and `ck.applet.registration` projection, ghost DIDs can be
//! minted for external users, and portal messages are mirrored into the
//! canonical space timeline.

use std::collections::BTreeSet;

use cokret_sdk::{
    AccountabilityGrantPayload, AccountabilityScope, ActorProfileId, AppletActorView,
    AppletDelegatedEventAuthorization, AppletId, AppletPackage, AppletPingOutcome,
    AppletProtocolMetadata, AppletRealmView, AppletRevokeOutcome, AppletTransactionOutcome,
    AppletTransactionRequestBody, AppletWireNamespaces, ApprovedScope, Did, EffectiveScope, Event,
    EventRef, GhostActorProfileRequest, GhostActorProvisionOutcome, GhostActorProvisionRequestBody,
    Hash, Hlc, InstallCapabilityConstraint, InstallCommitOutcome, InstallCommitRequestBody,
    InstallDeniedScope, InstallE2eeEffect, InstallEventSubmission, InstallNamespaceConflict,
    InstallPlan, InstallPreviewRequestBody, InstallRevokeRequestBody, InstallWidgetEffect, Proof,
    RealmId, canonical,
};
use salvo::http::StatusCode;
use salvo::oapi::extract::JsonBody;
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::applet_manifest::{AppletManifest, VerifiedAppletManifest, verify_manifest};
use super::bot_actor::{self, BotActor, KIND_BOT, KIND_GHOST};
use crate::error::AppError;
use crate::reducer::AppletProjection;
use crate::result::{JsonResult, json_ok};
use crate::routing::events::strand::strand_id_from_realm_id;
use crate::routing::events::projection::projection_event_json;
use crate::routing::system::extract::AuthArgs;
use crate::routing::system::util::sha256_hex;
use crate::state::{
    AppState, CanonicalEventRecord, EventNotification, MessageRecord, ProjectionEventRecord,
};
use crate::{ids, kinds};

const EVENT_SCHEMA_ID: &str = "ck.schema.event.v1";
const SOLAND_EDGE_APPLET_ID: &str = "ck:applet:00000000-0000-7000-8000-000000000000";

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AppletRecord {
    pub applet_id: String,
    pub namespace: String,
    pub owner_actor_id: String,
    pub registry_did: String,
    pub bot_actor_id: String,
    pub portal_realm_id: String,
    pub capabilities: Vec<String>,
    pub manifest: AppletManifest,
    #[serde(default)]
    pub package: Option<AppletPackage>,
    #[serde(default)]
    pub namespaces: Option<AppletWireNamespaces>,
    #[serde(default)]
    pub allow_ghost_actors: bool,
    pub status: String,
    pub registered_at: chrono::DateTime<chrono::Utc>,
    #[serde(default)]
    pub revoked_at: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(default)]
    pub idempotency_key: Option<String>,
    #[serde(default)]
    pub install_body_digest: Option<String>,
    #[serde(default)]
    pub install_id: Option<String>,
    #[serde(default)]
    pub install_response: Option<InstallCommitOutcome>,
    #[serde(default)]
    pub ghosts: Vec<GhostActorRecord>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GhostActorRecord {
    pub ghost_actor_id: String,
    pub external_id: String,
    #[serde(default)]
    pub display_name: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    #[serde(default)]
    pub revoked_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct AppletRevokeRecordOutcome {
    pub applet_id: String,
    pub status: String,
    pub revoked_at: chrono::DateTime<chrono::Utc>,
    pub bot_actor_id: String,
    pub ghost_actor_ids: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct AppletInstallPaths {
    pub preview_path: String,
    pub commit_path: String,
    pub revoke_path: String,
    pub ghost_actor_provision_path: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct AppletProtocolDescribeOutcome {
    pub contract: String,
    pub install: AppletInstallPaths,
    pub transaction_path: String,
    pub package_schema: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct AppletManifestRegisterRequestBody {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manifest: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manifest_json: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manifest_signature: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trusted_registry_did: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct AppletView {
    pub applet_id: String,
    pub namespace: String,
    pub owner_actor_id: String,
    pub registry_did: String,
    pub bot_actor_id: String,
    pub portal_realm_id: String,
    pub capabilities: Vec<String>,
    pub status: String,
    pub registered_at: chrono::DateTime<chrono::Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<chrono::DateTime<chrono::Utc>>,
    pub ghost_actor_ids: Vec<String>,
    pub manifest: AppletManifest,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, ToSchema)]
pub struct AppletExternalUserInput {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct AppletGhostIngressRequestBody {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_user: Option<AppletExternalUserInput>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(default)]
    pub payload: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm_id: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct AppletPortalMessageRequestBody {
    pub realm_id: String,
    #[serde(default)]
    pub payload: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct AppletPortalMessageOutcome {
    pub message_id: String,
    pub event_id: String,
    pub operation_id: String,
    pub realm_id: String,
    pub portal_realm_id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct AppletGhostIngressOutcome {
    pub applet_id: String,
    pub ghost_actor_id: String,
    pub external_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    pub accountability: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub portal_realm_id: Option<String>,
}

pub(super) fn router() -> Router {
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

/// Compatibility copy of the applet ghost-provision surface under
/// `/_soland/self/applets/...`; the canonical route is mounted under
/// `/_cokret/self/applets/{applet_id}/ghosts/provision`.
pub(super) fn legacy_self_router() -> Router {
    Router::with_path("applets").push(
        Router::with_path("{applet_id}")
            .push(Router::with_path("ghosts/provision").post(provision_ghost_actor_endpoint)),
    )
}

pub(super) fn protocol_router() -> Router {
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
    let state = depot.obtain::<AppState>().expect("state injected");
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
            preview_path: "/_cokret/self/applets/install/preview".to_owned(),
            commit_path: "/_cokret/self/applets/install".to_owned(),
            revoke_path: "/_cokret/self/applets/{applet_id}/revoke".to_owned(),
            ghost_actor_provision_path: "/_cokret/self/applets/{applet_id}/ghosts/provision"
                .to_owned(),
        },
        transaction_path: "/_cokret/edge/applet/transactions".to_owned(),
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
    let state = depot.obtain::<AppState>().expect("state injected");
    let _session = aa.authenticated_session(state, req).await?;
    let preview = body.into_inner();
    validate_applet_package(&preview.applet_package)?;
    let approved_scopes = approved_scopes_from_actions(
        &preview.applet_package,
        &preview.effective_scope,
        &preview.approval_request.approve_actions,
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
    let state = depot.obtain::<AppState>().expect("state injected");
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
    let body_digest = canonical_digest(&body)?;
    validate_applet_package(&commit.applet_package)?;
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
    let state = depot.obtain::<AppState>().expect("state injected");
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
    let outcome = revoke_applet_record(state, &session.actor, &applet_id).await?;
    let mut revoked_refs = Vec::with_capacity(1 + outcome.ghost_actor_ids.len());
    revoked_refs.push(outcome.bot_actor_id);
    revoked_refs.extend(outcome.ghost_actor_ids);
    json_ok(AppletRevokeOutcome {
        ok: true,
        revoked_refs,
        rejected: Vec::new(),
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
    let state = depot.obtain::<AppState>().expect("state injected");
    let _session = aa.authenticated_session(state, req).await?;
    let path_applet_id = applet_id_param(req)?;
    let provision = body.into_inner();
    validate_ghost_actor_provision_request(&path_applet_id, &provision)?;

    // Wire ids are validated at deserialization (typed AppletId/Did/RealmId).
    let applet_id = provision.applet_id.clone();
    let service_did = provision.service_did.clone();
    let ghost_actor_id = provision.ghost_actor_id.clone();
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

    crate::routing::append_audit_log(
        state,
        Some(&service_did.to_string()),
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

#[endpoint(
    operation_id = "ck.edge.applet.command.transaction",
    tags("applet"),
    summary = "Receive an applet transaction",
    status_codes(200, 400, 401, 403, 409)
)]
#[tracing::instrument(skip_all, fields(op = "ck.edge.applet.command.transaction"))]
async fn transaction_endpoint(
    aa: AuthArgs,
    body: JsonBody<AppletTransactionRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AppletTransactionOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let _session = aa.authenticated_session(state, req).await?;
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
    json_ok(AppletTransactionOutcome {
        ok: true,
        rejected: Vec::new(),
        retry_after_ms: None,
    })
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
    let state = depot.obtain::<AppState>().expect("state injected");
    let actor_id = req
        .param::<String>("actor_id")
        .ok_or_else(|| AppError::missing_param("actor_id path segment required"))?;
    if let Some(doc) = did_document_for_extension_actor(state, &actor_id).await? {
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
    let state = depot.obtain::<AppState>().expect("state injected");
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
    let state = depot.obtain::<AppState>().expect("state injected");
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
    let state = depot.obtain::<AppState>().expect("state injected");
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
    let state = depot.obtain::<AppState>().expect("state injected");
    let location = query_value(req, "location")
        .or_else(|| query_value(req, "channel"))
        .or_else(|| query_value(req, "realm"));
    if let Some(location) = location {
        if let Some(record) = applet_records(state)
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
                title: Some(
                    applet_display_name(&record.manifest).unwrap_or(record.namespace.clone()),
                ),
                external_ref: json!({"location": location, "applet_id": record.applet_id}),
            });
        }
    }
    json_ok(AppletRealmView {
        exists: false,
        realm_id: None,
        title: None,
        external_ref: Value::Null,
    })
}

#[endpoint(
    operation_id = "org.cokret.soland.applets.register",
    tags("extensions"),
    summary = "Register a verified applet manifest and issue a bot actor DID",
    status_codes(200, 201, 400, 401, 403, 409)
)]
#[tracing::instrument(skip_all, fields(op = "org.cokret.soland.applets.register"))]
async fn register_endpoint(
    aa: AuthArgs,
    body: JsonBody<AppletManifestRegisterRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
    res: &mut Response,
) -> JsonResult<AppletView> {
    let state = depot.obtain::<AppState>().expect("state injected");
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
    operation_id = "org.cokret.soland.applets.get",
    tags("extensions"),
    summary = "Read applet bridge registration state"
)]
#[tracing::instrument(skip_all, fields(op = "org.cokret.soland.applets.get"))]
async fn get_endpoint(req: &mut Request, depot: &mut Depot) -> JsonResult<AppletView> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let applet_id = applet_id_param(req)?;
    let record = applet_record(state, &applet_id)
        .await?
        .ok_or_else(|| AppError::not_found("applet is not registered"))?;
    json_ok(applet_response(&record))
}

#[endpoint(
    operation_id = "org.cokret.soland.applets.ghosts.provision",
    tags("extensions"),
    summary = "Provision or reuse a ghost actor and optionally route a portal message"
)]
#[tracing::instrument(skip_all, fields(op = "org.cokret.soland.applets.ghosts.provision"))]
async fn ghost_endpoint(
    aa: AuthArgs,
    body: JsonBody<AppletGhostIngressRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AppletGhostIngressOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
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
    operation_id = "org.cokret.soland.applets.bot.message",
    tags("extensions"),
    summary = "Write a portal message as the applet bot actor"
)]
#[tracing::instrument(skip_all, fields(op = "org.cokret.soland.applets.bot.message"))]
async fn bot_message_endpoint(
    aa: AuthArgs,
    body: JsonBody<AppletPortalMessageRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AppletPortalMessageOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
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
    operation_id = "org.cokret.soland.applets.revoke",
    tags("extensions"),
    summary = "Revoke an applet's bot and ghost capabilities"
)]
#[tracing::instrument(skip_all, fields(op = "org.cokret.soland.applets.revoke"))]
async fn revoke_endpoint(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AppletRevokeRecordOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let applet_id = applet_id_param(req)?;
    json_ok(revoke_applet_record(state, &session.actor, &applet_id).await?)
}

async fn revoke_applet_record(
    state: &AppState,
    actor: &str,
    applet_id: &str,
) -> Result<AppletRevokeRecordOutcome, AppError> {
    let now = chrono::Utc::now();
    let mut record = applet_record(state, applet_id)
        .await?
        .ok_or_else(|| AppError::not_found("applet is not registered"))?;
    if record.owner_actor_id != actor {
        return Err(AppError::capability_denied(
            "only the registering actor can revoke this applet",
        ));
    }
    record.status = "revoked".to_owned();
    record.revoked_at = Some(now);
    for ghost in &mut record.ghosts {
        ghost.revoked_at.get_or_insert(now);
    }
    persist_applet_record(state, &record).await?;
    bot_actor::revoke_bot(&record.bot_actor_id);
    for ghost in &record.ghosts {
        bot_actor::revoke_bot(&ghost.ghost_actor_id);
    }
    crate::routing::append_audit_log(
        state,
        Some(actor),
        "extensions.applet.revoke",
        json!({
            "applet_id": record.applet_id,
            "bot_actor_id": record.bot_actor_id,
            "ghost_count": record.ghosts.len(),
        }),
        "accepted",
    )
    .await;
    Ok(AppletRevokeRecordOutcome {
        applet_id: record.applet_id,
        status: "revoked".to_owned(),
        revoked_at: now,
        bot_actor_id: record.bot_actor_id,
        ghost_actor_ids: record
            .ghosts
            .iter()
            .map(|ghost| ghost.ghost_actor_id.clone())
            .collect(),
    })
}

pub async fn did_document_for_extension_actor(
    state: &AppState,
    did: &str,
) -> Result<Option<Value>, AppError> {
    for record in applet_records(state).await? {
        if record.bot_actor_id == did {
            let status = if record.revoked_at.is_some() {
                "revoked"
            } else {
                "active"
            };
            return Ok(Some(extension_actor_id_document(
                did,
                "bot_actor",
                status,
                &record.owner_actor_id,
                &record,
                None,
            )));
        }
        if let Some(ghost) = record
            .ghosts
            .iter()
            .find(|ghost| ghost.ghost_actor_id == did)
        {
            let status = if record.revoked_at.is_some() || ghost.revoked_at.is_some() {
                "revoked"
            } else {
                "active"
            };
            return Ok(Some(extension_actor_id_document(
                did,
                "ghost_actor",
                status,
                &record.bot_actor_id,
                &record,
                Some(ghost),
            )));
        }
    }
    Ok(None)
}

#[derive(Clone)]
struct FormalAppletEvent {
    event_id: String,
    canonical: CanonicalEventRecord,
    projection: ProjectionEventRecord,
}

async fn build_ghost_accountability_grant_event(
    state: &AppState,
    record: &AppletRecord,
    provision: &GhostActorProvisionRequestBody,
    service_did: &Did,
    ghost_actor_id: &Did,
    realm_id: &RealmId,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<FormalAppletEvent, AppError> {
    let proof = production_payload_proof(
        state,
        service_did,
        "applet-accountability-grant",
        &json!({
            "issuer": service_did,
            "subject": ghost_actor_id,
            "applet_id": provision.applet_id,
            "realm_id": realm_id,
            "protocol": provision.protocol,
            "tenant": provision.tenant,
            "external_user_id": provision.external_user_id,
            "external_ref": provision.external_ref,
        }),
        now,
    )?;
    let grant = AccountabilityGrantPayload::new(
        service_did.clone(),
        ghost_actor_id.clone(),
        AccountabilityScope::Multiple(vec![
            "applet_ghost_actor".to_owned(),
            format!("applet:{}", provision.applet_id),
            format!("protocol:{}", provision.protocol),
            format!("tenant:{}", provision.tenant),
        ]),
        now - chrono::Duration::seconds(1),
        now + chrono::Duration::days(365),
        proof,
    );
    grant.validate_lifecycle_at(now).map_err(|error| {
        AppError::invalid_param(format!("accountability_grant invalid: {error}"))
    })?;
    let event = grant
        .to_event(
            realm_id.clone(),
            next_actor_seq(state, service_did.as_str()).await?,
            next_hlc(state)?,
            None,
        )
        .map_err(|error| {
            AppError::internal(format!("accountability grant event build failed: {error}"))
        })?;
    formal_event_from_sdk_event(
        state,
        event,
        service_did,
        "applet_ghost_accountability_grant",
        Some(service_did.as_str()),
        json!({
            "applet_id": record.applet_id,
            "service_did": service_did,
            "ghost_actor_id": ghost_actor_id,
            "protocol": provision.protocol,
            "tenant": provision.tenant,
            "external_user_id": provision.external_user_id,
            "external_ref": provision.external_ref,
        }),
    )
}

async fn build_ghost_profile_create_event(
    state: &AppState,
    record: &AppletRecord,
    provision: &GhostActorProvisionRequestBody,
    applet_id: AppletId,
    service_did: &Did,
    ghost_actor_id: &Did,
    realm_id: &RealmId,
    authorization_ref: &str,
) -> Result<FormalAppletEvent, AppError> {
    let display_name = provision
        .display_name
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(provision.external_user_id.as_str());
    let profile_id = ActorProfileId::new(cokret_sdk::new_prefixed_uuid7("ck:actor_profile:"))
        .map_err(|error| AppError::internal(format!("profile id generation failed: {error}")))?;
    let external_ref = json!({
        "schema": "ck.applet.ghost_actor.external_ref.v1",
        "protocol": provision.protocol,
        "tenant": provision.tenant,
        "external_user_id": provision.external_user_id,
        "realm_id": realm_id,
        "external_ref": provision.external_ref,
    });
    let mut accountable_principal_ids = vec![service_did.clone()];
    if let Ok(controller) = Did::new(record.registry_did.clone())
        && !accountable_principal_ids
            .iter()
            .any(|did| did == &controller)
    {
        accountable_principal_ids.push(controller);
    }
    let request = GhostActorProfileRequest::new(
        profile_id,
        ghost_actor_id.clone(),
        display_name,
        applet_id.clone(),
    )
    .with_realm_id(realm_id.clone())
    .with_accountable_principal_ids(accountable_principal_ids)
    .with_external_ref(external_ref);
    let authorization = AppletDelegatedEventAuthorization::new(
        service_did.clone(),
        authorization_ref.to_owned(),
        applet_id,
    );
    let mut event = request
        .profile_create_event(
            realm_id.clone(),
            next_actor_seq(state, ghost_actor_id.as_str()).await?,
            next_hlc(state)?,
            Some(&authorization),
        )
        .map_err(|error| {
            AppError::internal(format!("profile create event build failed: {error}"))
        })?;
    event
        .refs
        .push(EventRef::new(authorization_ref, "authorized_by"));
    formal_event_from_sdk_event(
        state,
        event,
        service_did,
        "applet_ghost_profile_create",
        Some(ghost_actor_id.as_str()),
        json!({
            "applet_id": record.applet_id,
            "service_did": service_did,
            "ghost_actor_id": ghost_actor_id,
            "authorization_ref": authorization_ref,
            "protocol": provision.protocol,
            "tenant": provision.tenant,
            "external_user_id": provision.external_user_id,
            "display_name": provision.display_name,
            "external_ref": provision.external_ref,
        }),
    )
}

async fn persist_formal_applet_event(
    state: &AppState,
    event: FormalAppletEvent,
) -> Result<(), AppError> {
    if let Err(error) = state.persistence.events().put(event.canonical).await {
        tracing::error!(%error, event_id = %event.event_id, "applet ghost provisioning: failed to persist canonical event");
        return Err(AppError::internal(
            "failed to persist ghost actor provisioning event",
        ));
    }
    let _ = state.event_broadcast.send(EventNotification::event(
        event.projection.realm_id.clone(),
        event.projection.event_id.clone(),
        projection_event_json(&event.projection),
    ));
    if let Err(error) = state
        .persistence
        .projection_events()
        .append(event.projection)
        .await
    {
        tracing::error!(%error, event_id = %event.event_id, "applet ghost provisioning: failed to persist projection event");
        return Err(AppError::internal(
            "failed to persist ghost actor provisioning projection",
        ));
    }
    Ok(())
}

fn formal_event_from_sdk_event(
    state: &AppState,
    event: Event,
    signing_did: &Did,
    operation_type: &str,
    sender: Option<&str>,
    projection_payload: Value,
) -> Result<FormalAppletEvent, AppError> {
    let event_id = event.event_id.to_string();
    let actor_id = event.actor_id.to_string();
    let actor_seq = event.actor_seq;
    let realm_id = event.realm_id.to_string();
    let kind = event.kind.clone();
    let mut envelope = serde_json::to_value(&event)
        .map_err(|error| AppError::internal(format!("event serialize failed: {error}")))?;
    let canonical_source = event_canonical_source(&envelope);
    let canonical_bytes = canonical::canonical_json_bytes(&canonical_source)
        .map_err(|error| AppError::internal(format!("event canonicalization failed: {error}")))?;
    let canonical_digest = canonical::sha256_digest(&canonical_bytes);
    let proof = event_proof(state, signing_did, &actor_id, &canonical_digest)?;
    envelope
        .as_object_mut()
        .ok_or_else(|| AppError::internal("event envelope is not an object"))?
        .insert("proofs".to_owned(), json!([proof]));

    let received_at = chrono::Utc::now();
    let canonical = CanonicalEventRecord {
        event_id: event_id.clone(),
        actor_id,
        actor_seq,
        realm_id: Some(realm_id.clone()),
        kind: kind.as_str().to_owned(),
        schema_id: EVENT_SCHEMA_ID.to_owned(),
        canonical_digest,
        canonical_bytes,
        envelope,
        received_at,
    };
    let projection = ProjectionEventRecord {
        event_id: event_id.clone(),
        realm_id,
        event_kind: kind.as_str().to_owned(),
        operation_type: operation_type.to_owned(),
        operation_id: Some(ids::generate_operation_id()),
        sender: sender.map(ToOwned::to_owned),
        payload: projection_payload,
        created_at: received_at,
    };
    Ok(FormalAppletEvent {
        event_id,
        canonical,
        projection,
    })
}

fn event_canonical_source(envelope: &Value) -> Value {
    let mut value = envelope.clone();
    if let Value::Object(object) = &mut value {
        object.remove("proofs");
        object.remove("unsigned");
        object.remove("canonical_digest");
        object.remove("canonical_hash");
    }
    value
}

fn event_proof(
    state: &AppState,
    signing_did: &Did,
    actor_id: &str,
    event_digest: &str,
) -> Result<Proof, AppError> {
    let created_at = chrono::Utc::now();
    let verification_method = format!("{signing_did}#applet-service-key");
    let binding = json!({
        "event_digest": event_digest,
        "actor_id": actor_id,
        "verification_method": verification_method,
        "created_at": created_at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
    });
    let binding_bytes = canonical::canonical_json_bytes(&binding).map_err(|error| {
        AppError::internal(format!("proof binding canonicalization failed: {error}"))
    })?;
    let jws =
        cokret_sdk::jws::sign_jws_ed25519(&binding_bytes, state.notary_signing_key().as_ref())
            .map_err(|error| AppError::internal(format!("event proof signing failed: {error}")))?;
    Ok(Proof {
        kind: "detached_jws".to_owned(),
        alg: "EdDSA".to_owned(),
        verification_method,
        event_digest: Hash::new(event_digest.to_owned())
            .map_err(|error| AppError::internal(format!("event digest invalid: {error}")))?,
        created_at,
        domain: None,
        audience: None,
        jws,
    })
}

fn production_payload_proof(
    state: &AppState,
    signing_did: &Did,
    label: &str,
    payload: &Value,
    created_at: chrono::DateTime<chrono::Utc>,
) -> Result<Proof, AppError> {
    let binding = json!({
        "label": label,
        "payload": payload,
        "created_at": created_at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
    });
    let binding_bytes = canonical::canonical_json_bytes(&binding).map_err(|error| {
        AppError::internal(format!(
            "accountability proof canonicalization failed: {error}"
        ))
    })?;
    let digest = canonical::sha256_digest(&binding_bytes);
    let jws =
        cokret_sdk::jws::sign_jws_ed25519(&binding_bytes, state.notary_signing_key().as_ref())
            .map_err(|error| {
                AppError::internal(format!("accountability proof signing failed: {error}"))
            })?;
    Ok(Proof {
        kind: "detached_jws".to_owned(),
        alg: "EdDSA".to_owned(),
        verification_method: format!("{signing_did}#applet-service-key"),
        event_digest: Hash::new(digest)
            .map_err(|error| AppError::internal(format!("proof digest invalid: {error}")))?,
        created_at,
        domain: None,
        audience: None,
        jws,
    })
}

async fn next_actor_seq(state: &AppState, actor_id: &str) -> Result<u64, AppError> {
    state
        .persistence
        .events()
        .max_actor_seq(actor_id)
        .await
        .map(|seq| seq.unwrap_or(0) + 1)
        .map_err(|error| AppError::internal(format!("event sequence lookup failed: {error}")))
}

fn next_hlc(state: &AppState) -> Result<Hlc, AppError> {
    Hlc::new(state.hlc.now()).map_err(|error| AppError::internal(format!("HLC invalid: {error}")))
}

fn validate_ghost_actor_provision_request(
    path_applet_id: &str,
    provision: &GhostActorProvisionRequestBody,
) -> Result<(), AppError> {
    if provision.schema != GhostActorProvisionRequestBody::SCHEMA {
        return Err(AppError::invalid_param(format!(
            "schema must be {}",
            GhostActorProvisionRequestBody::SCHEMA
        )));
    }
    if provision.applet_id.as_str() != path_applet_id {
        return Err(AppError::invalid_param(
            "body applet_id must match applet_id path segment",
        ));
    }
    for (field, value) in [
        ("protocol", provision.protocol.as_str()),
        ("tenant", provision.tenant.as_str()),
        ("external_user_id", provision.external_user_id.as_str()),
    ] {
        if value.trim().is_empty() {
            return Err(AppError::missing_param(format!("{field} is required")));
        }
    }
    if let Some(display_name) = provision.display_name.as_deref()
        && display_name.trim().is_empty()
    {
        return Err(AppError::invalid_param(
            "display_name must be omitted or non-empty",
        ));
    }
    if provision.external_ref.is_null() {
        return Err(AppError::missing_param("external_ref is required"));
    }
    Ok(())
}

fn ensure_formal_ghost_provision_allowed(
    record: &AppletRecord,
    provision: &GhostActorProvisionRequestBody,
) -> Result<(), AppError> {
    let package = record.package.as_ref().ok_or_else(|| {
        AppError::conflict("formal ghost provisioning requires package install")
            .with_wire_code("applet_install_required")
    })?;
    if package.service_did != provision.service_did {
        return Err(AppError::capability_denied(
            "service_did does not match installed applet package",
        ));
    }
    if record.portal_realm_id != provision.realm_id.as_str() {
        return Err(
            AppError::conflict("realm_id does not match installed applet effective scope")
                .with_wire_code("applet_effective_scope_mismatch"),
        );
    }
    if !record.allow_ghost_actors {
        return Err(AppError::capability_denied(
            "applet install does not grant ghost actor provisioning",
        ));
    }
    Ok(())
}

async fn register_package_install(
    state: &AppState,
    owner_actor_id: &str,
    commit: InstallCommitRequestBody,
    idempotency_key: String,
    body_digest: String,
    res: &mut Response,
) -> Result<InstallCommitOutcome, AppError> {
    let package = commit.applet_package;
    let applet_id = package.applet_id.clone();
    let namespace = package_namespace(&package);
    let realm_id = effective_scope_realm_id(&commit.effective_scope);
    let approved_actions = actions_from_approved_scopes(&commit.approved_scopes);

    if let Some(existing) = applet_record(state, &applet_id).await? {
        if existing.idempotency_key.as_deref() == Some(idempotency_key.as_str()) {
            if existing.install_body_digest.as_deref() == Some(body_digest.as_str())
                && let Some(response) = &existing.install_response
            {
                res.status_code(StatusCode::OK);
                return Ok(response.clone());
            }
            return Err(AppError::conflict(
                "Idempotency-Key was already used with a different applet install body",
            )
            .with_wire_code("duplicate_conflict"));
        }
        return Err(AppError::conflict("applet package id is already installed")
            .with_wire_code("applet_already_registered"));
    }

    let namespace_conflicts = namespace_conflicts_for(state, &package.namespaces).await?;
    if !namespace_conflicts.is_empty() {
        return Err(AppError::conflict("applet namespace is already claimed")
            .with_wire_code("applet_namespace_conflict"));
    }

    let now = chrono::Utc::now();
    let registration_event_ref = ids::generate_event_id();
    let capability_grant_refs = approved_actions
        .iter()
        .map(|_| ids::generate_grant_id())
        .collect::<Vec<_>>();
    let effective_status = if approved_actions.is_empty() {
        "rejected"
    } else if approved_actions.len() < package.requested_scopes.len() {
        "partially_installed"
    } else {
        "installed"
    };
    let install_id = ids::generate_install_id();
    let response = InstallCommitOutcome {
        ok: effective_status != "rejected",
        install_id,
        applet_id: applet_id.clone(),
        registration_event_ref: registration_event_ref.clone(),
        registration_epoch: package.registration_epoch.clone(),
        bot_actor_id: package.bot_actor_id.clone(),
        capability_grant_refs,
        membership_event_refs: Vec::new(),
        e2ee_authorization_refs: Vec::new(),
        widget_policy_ref: None,
        effective_status: effective_status.to_owned(),
        rejected: denied_scope_values(&package, &approved_actions)
            .into_iter()
            .map(|scope| {
                serde_json::to_value(scope)
                    .map_err(|error| AppError::internal(format!("denied scope serialize: {error}")))
            })
            .collect::<Result<Vec<_>, _>>()?,
    };
    let record = AppletRecord {
        applet_id: package.applet_id.clone(),
        namespace,
        owner_actor_id: owner_actor_id.to_owned(),
        registry_did: package.controller_did.to_string(),
        bot_actor_id: package.bot_actor_id.to_string(),
        portal_realm_id: realm_id,
        capabilities: approved_actions,
        manifest: manifest_from_package(&package),
        package: Some(package.clone()),
        namespaces: Some(package.namespaces.clone()),
        allow_ghost_actors: allow_ghost_actors_from_package(&package),
        status: effective_status.to_owned(),
        registered_at: now,
        revoked_at: None,
        idempotency_key: Some(idempotency_key),
        install_body_digest: Some(body_digest),
        install_id: Some(response.install_id.clone()),
        install_response: Some(response.clone()),
        ghosts: Vec::new(),
    };
    persist_applet_record(state, &record).await?;
    bot_actor::register_bot(BotActor {
        did: record.bot_actor_id.clone(),
        name: applet_display_name(&record.manifest).unwrap_or_else(|| record.namespace.clone()),
        kind: KIND_BOT.to_owned(),
        owner_actor_id: owner_actor_id.to_owned(),
        created_at: now,
        revoked_at: None,
    });
    update_applet_projection(state, &record);
    append_applet_registration_projection(state, &record, &registration_event_ref).await?;
    crate::routing::append_audit_log(
        state,
        Some(owner_actor_id),
        "applet.install",
        json!({
            "applet_id": record.applet_id,
            "namespace": record.namespace,
            "service_did": package.service_did,
            "bot_actor_id": record.bot_actor_id,
            "registration_event_ref": registration_event_ref,
            "registration_epoch": package.registration_epoch,
        }),
        "accepted",
    )
    .await;
    res.status_code(StatusCode::CREATED);
    Ok(response)
}

async fn append_applet_registration_projection(
    state: &AppState,
    record: &AppletRecord,
    event_id: &str,
) -> Result<(), AppError> {
    let Some(package) = record.package.as_ref() else {
        return Ok(());
    };
    let realm_id = record.portal_realm_id.clone();
    let projection_record = ProjectionEventRecord {
        event_id: event_id.to_owned(),
        realm_id,
        event_kind: kinds::CK_APPLET_REGISTRATION.to_owned(),
        operation_type: "applet_install_registration".to_owned(),
        operation_id: None,
        sender: Some(record.owner_actor_id.clone()),
        payload: registration_payload_from_package(package)?,
        created_at: chrono::Utc::now(),
    };
    let _ = state.event_broadcast.send(EventNotification::event(
        projection_record.realm_id.clone(),
        projection_record.event_id.clone(),
        projection_event_json(&projection_record),
    ));
    if let Err(error) = state
        .persistence
        .projection_events()
        .append(projection_record)
        .await
    {
        tracing::error!(%error, "applet install: failed to append registration projection");
        return Err(AppError::internal(
            "failed to persist applet registration projection",
        ));
    }
    Ok(())
}

fn update_applet_projection(state: &AppState, record: &AppletRecord) {
    let Some(package) = record.package.as_ref() else {
        return;
    };
    let now = chrono::Utc::now();
    let projection = AppletProjection {
        service_did: package.service_did.to_string(),
        namespace: record.namespace.clone(),
        manifest: Some(package.manifest_snapshot()),
        capabilities: Some(json!(record.capabilities)),
        registered_at: now,
        updated_at: now,
    };
    let mut guard = state.projection.lock().expect("projection lock");
    guard
        .applets
        .insert(package.service_did.to_string(), projection.clone());
    guard.applets.insert(record.applet_id.clone(), projection);
}

async fn register_verified_applet(
    state: &AppState,
    owner_actor_id: &str,
    manifest: AppletManifest,
    verified: VerifiedAppletManifest,
    idempotency_key: Option<String>,
    res: &mut Response,
) -> Result<AppletView, AppError> {
    let applet_id = verified.id.clone();
    let namespace = manifest_namespace(&manifest).unwrap_or_else(|| safe_token(&applet_id));
    if let Some(existing) = applet_record(state, &applet_id).await? {
        if idempotency_key.is_some()
            && existing.idempotency_key.as_deref() == idempotency_key.as_deref()
        {
            res.status_code(StatusCode::OK);
            return Ok(applet_response(&existing));
        }
        return Err(
            AppError::conflict("applet manifest id is already registered")
                .with_wire_code("applet_already_registered"),
        );
    }
    if applet_records(state).await?.into_iter().any(|record| {
        record.namespace == namespace
            && record.applet_id != applet_id
            && record.revoked_at.is_none()
    }) {
        return Err(AppError::conflict("applet namespace is already claimed")
            .with_wire_code("applet_namespace_conflict"));
    }

    let now = chrono::Utc::now();
    let bot_actor_id = bot_actor_id_for(&namespace, &applet_id);
    let portal_realm_id = portal_realm_id_for(&namespace, &applet_id);
    let record = AppletRecord {
        applet_id,
        namespace,
        owner_actor_id: owner_actor_id.to_owned(),
        registry_did: verified.signer_did,
        bot_actor_id: bot_actor_id.clone(),
        portal_realm_id,
        capabilities: verified.capabilities,
        manifest,
        package: None,
        namespaces: None,
        allow_ghost_actors: false,
        status: "registered".to_owned(),
        registered_at: now,
        revoked_at: None,
        idempotency_key,
        install_body_digest: None,
        install_id: None,
        install_response: None,
        ghosts: Vec::new(),
    };
    persist_applet_record(state, &record).await?;
    bot_actor::register_bot(BotActor {
        did: bot_actor_id,
        name: applet_display_name(&record.manifest).unwrap_or_else(|| record.namespace.clone()),
        kind: KIND_BOT.to_owned(),
        owner_actor_id: owner_actor_id.to_owned(),
        created_at: now,
        revoked_at: None,
    });
    crate::routing::append_audit_log(
        state,
        Some(owner_actor_id),
        "extensions.applet.register",
        json!({
            "applet_id": record.applet_id,
            "namespace": record.namespace,
            "registry_did": record.registry_did,
            "bot_actor_id": record.bot_actor_id,
            "portal_realm_id": record.portal_realm_id,
        }),
        "accepted",
    )
    .await;
    res.status_code(StatusCode::CREATED);
    Ok(applet_response(&record))
}

async fn provision_ghost(
    state: &AppState,
    applet_id: &str,
    external_id: &str,
    display_name: Option<String>,
) -> Result<(AppletRecord, GhostActorRecord), AppError> {
    let now = chrono::Utc::now();
    let mut record = applet_record(state, applet_id)
        .await?
        .ok_or_else(|| AppError::not_found("applet is not registered"))?;
    ensure_not_revoked(&record)?;
    if !record.allow_ghost_actors {
        return Err(AppError::capability_denied(
            "applet install does not grant ghost actor provisioning",
        ));
    }
    if let Some(existing) = record
        .ghosts
        .iter()
        .find(|ghost| ghost.external_id == external_id)
        .cloned()
    {
        return Ok((record, existing));
    }
    let ghost = GhostActorRecord {
        ghost_actor_id: ghost_actor_id_for(&record.namespace, applet_id, external_id),
        external_id: external_id.to_owned(),
        display_name,
        created_at: now,
        revoked_at: None,
    };
    record.ghosts.push(ghost.clone());
    persist_applet_record(state, &record).await?;
    bot_actor::register_bot(BotActor {
        did: ghost.ghost_actor_id.clone(),
        name: ghost
            .display_name
            .clone()
            .unwrap_or_else(|| ghost.external_id.clone()),
        kind: KIND_GHOST.to_owned(),
        owner_actor_id: record.owner_actor_id.clone(),
        created_at: now,
        revoked_at: None,
    });
    Ok((record, ghost))
}

async fn append_portal_message(
    state: &AppState,
    applet: &AppletRecord,
    ghost: &GhostActorRecord,
    realm_id: &str,
    content: Value,
) -> Result<AppletPortalMessageOutcome, AppError> {
    if !applet
        .capabilities
        .iter()
        .any(|capability| capability_allows_message_create(capability))
    {
        return Err(AppError::capability_denied(
            "applet install does not grant ck.message.create",
        ));
    }
    let operation_id = ids::generate_operation_id();
    let event_id = ids::generate_event_id();
    let thread_id = strand_id_from_realm_id(realm_id);
    let created_at = chrono::Utc::now();
    let content_with_portal = enrich_content_with_portal_metadata(content, applet, ghost);
    let message_record = MessageRecord {
        event_id: event_id.clone(),
        realm_id: realm_id.to_owned(),
        sender: ghost.ghost_actor_id.clone(),
        thread_id: thread_id.clone(),
        content: content_with_portal.clone(),
        encrypted: false,
        created_at,
    };
    if let Err(error) = state.persistence.messages().put(&message_record).await {
        tracing::error!(%error, "applet bridge: failed to persist portal MessageRecord");
        return Err(AppError::internal("failed to persist portal message"));
    }
    let projection_record = ProjectionEventRecord {
        event_id: event_id.clone(),
        realm_id: realm_id.to_owned(),
        event_kind: kinds::CK_MESSAGE_CREATE.to_owned(),
        operation_type: "applet_portal_ingress".to_owned(),
        operation_id: Some(operation_id.clone()),
        sender: Some(ghost.ghost_actor_id.clone()),
        payload: json!({
            "thread_id": thread_id,
            "content": content_with_portal,
            "encrypted": false,
            "portal_realm_id": applet.portal_realm_id,
            "applet_id": applet.applet_id,
            "bot_actor_id": applet.bot_actor_id,
            "ghost_actor_id": ghost.ghost_actor_id,
            "external_id": ghost.external_id,
        }),
        created_at,
    };
    let _ = state.event_broadcast.send(EventNotification::event(
        projection_record.realm_id.clone(),
        projection_record.event_id.clone(),
        projection_event_json(&projection_record),
    ));
    if let Err(error) = state
        .persistence
        .projection_events()
        .append(projection_record)
        .await
    {
        tracing::error!(%error, "applet bridge: failed to append projection event");
        return Err(AppError::internal("failed to persist portal projection"));
    }
    Ok(AppletPortalMessageOutcome {
        message_id: crate::routing::events::strand::message_id_from_event_id(&event_id),
        event_id,
        operation_id,
        realm_id: realm_id.to_owned(),
        portal_realm_id: applet.portal_realm_id.clone(),
    })
}

fn parse_manifest(body: &AppletManifestRegisterRequestBody) -> Result<AppletManifest, AppError> {
    let mut manifest_value = body
        .manifest
        .as_ref()
        .or(body.manifest_json.as_ref())
        .cloned()
        .ok_or_else(|| AppError::missing_param("manifest is required"))?;
    if let Some(signature) = body
        .signature
        .as_deref()
        .or(body.manifest_signature.as_deref())
        && manifest_value
            .get("signature")
            .and_then(Value::as_str)
            .unwrap_or("")
            .is_empty()
        && let Some(object) = manifest_value.as_object_mut()
    {
        object.insert("signature".to_owned(), Value::String(signature.to_owned()));
    }
    serde_json::from_value(manifest_value)
        .map_err(|err| AppError::bad_json(format!("manifest parse: {err}")))
}

fn external_user_from_ghost_request(
    body: &AppletGhostIngressRequestBody,
) -> Result<(String, Option<String>), AppError> {
    if let Some(external_user) = &body.external_user {
        let external_id = external_user
            .id
            .as_deref()
            .or(external_user.external_id.as_deref())
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| AppError::missing_param("external_user.id is required"))?;
        let display_name = external_user.display_name.clone();
        return Ok((external_id.to_owned(), display_name));
    }
    let external_id = body
        .external_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| AppError::missing_param("external_id is required"))?;
    let display_name = body.display_name.clone();
    Ok((external_id.to_owned(), display_name))
}

fn portal_message_payload(payload: &Value) -> Result<Option<Value>, AppError> {
    if payload.is_null() {
        return Ok(None);
    }
    let kind = payload
        .get("kind")
        .and_then(Value::as_str)
        .unwrap_or("message");
    if kind != "message" && kind != "ck.content.text" {
        return Ok(None);
    }
    let text = payload
        .get("text")
        .or_else(|| payload.get("body"))
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| AppError::invalid_param("payload.text is required"))?;
    Ok(Some(json!({
        "kind": "ck.content.text",
        "body": text,
    })))
}

fn enrich_content_with_portal_metadata(
    mut content: Value,
    applet: &AppletRecord,
    ghost: &GhostActorRecord,
) -> Value {
    if let Some(object) = content.as_object_mut() {
        object.insert(
            "portal".to_owned(),
            json!({
                "applet_id": applet.applet_id,
                "portal_realm_id": applet.portal_realm_id,
                "bot_actor_id": applet.bot_actor_id,
                "ghost_actor_id": ghost.ghost_actor_id,
                "external_id": ghost.external_id,
                "display_name": ghost.display_name,
            }),
        );
    }
    content
}

fn applet_response(record: &AppletRecord) -> AppletView {
    AppletView {
        applet_id: record.applet_id.clone(),
        namespace: record.namespace.clone(),
        owner_actor_id: record.owner_actor_id.clone(),
        registry_did: record.registry_did.clone(),
        bot_actor_id: record.bot_actor_id.clone(),
        portal_realm_id: record.portal_realm_id.clone(),
        capabilities: record.capabilities.clone(),
        status: record.status.clone(),
        registered_at: record.registered_at,
        revoked_at: record.revoked_at,
        ghost_actor_ids: record
            .ghosts
            .iter()
            .map(|ghost| ghost.ghost_actor_id.clone())
            .collect(),
        manifest: record.manifest.clone(),
    }
}

fn validate_applet_package(package: &AppletPackage) -> Result<(), AppError> {
    package
        .validate()
        .map_err(|error| AppError::invalid_param(format!("applet package invalid: {error}")))?;
    if let Some(expires_at) = package.expires_at
        && expires_at <= chrono::Utc::now()
    {
        return Err(AppError::conflict("applet package has expired")
            .with_wire_code("applet_package_expired"));
    }
    let expected_digest = package
        .compute_package_digest()
        .map_err(|error| AppError::internal(format!("package digest failed: {error}")))?;
    if package.package_digest.as_ref() != Some(&expected_digest) {
        return Err(
            AppError::invalid_param("applet package_digest does not match package body")
                .with_wire_code("schema_violation"),
        );
    }
    let proof = package
        .proof
        .as_ref()
        .ok_or_else(|| AppError::invalid_param("applet package proof is required"))?;
    proof.validate().map_err(|error| {
        AppError::invalid_param(format!("applet package proof invalid: {error}"))
    })?;
    let mut unsigned = package.clone();
    unsigned.proof = None;
    let expected_payload_digest = cokret_sdk::Hash::new(
        cokret_sdk::canonical::canonical_sha256(&unsigned)
            .map_err(|error| AppError::internal(format!("package proof digest failed: {error}")))?,
    )
    .map_err(|error| AppError::internal(format!("package proof digest invalid: {error}")))?;
    if proof.event_digest != expected_payload_digest {
        return Err(
            AppError::invalid_param("applet package proof payload_digest mismatch")
                .with_wire_code("proof_invalid"),
        );
    }
    Ok(())
}

fn approved_scopes_from_actions(
    package: &AppletPackage,
    scope: &EffectiveScope,
    approve_actions: &[String],
) -> Result<Vec<ApprovedScope>, AppError> {
    let requested = package
        .requested_scopes
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    let approved = approve_actions
        .iter()
        .filter(|action| requested.contains(*action))
        .cloned()
        .collect::<BTreeSet<_>>();
    if approved.is_empty() {
        return Ok(Vec::new());
    }
    let (realm_id, circle_ids) = match scope {
        EffectiveScope::Realm { realm_id } => (realm_id.clone(), Vec::new()),
        EffectiveScope::Circle {
            realm_id,
            circle_id,
        } => (realm_id.clone(), vec![circle_id.clone()]),
    };
    Ok(vec![ApprovedScope {
        actions: approved.into_iter().collect(),
        realm_ids: vec![realm_id],
        circle_ids,
        constraints: Vec::new(),
    }])
}

async fn build_install_plan(
    state: &AppState,
    package: &AppletPackage,
    scope: &EffectiveScope,
    approved_scopes: Vec<ApprovedScope>,
) -> Result<InstallPlan, AppError> {
    let namespace_conflicts = namespace_conflicts_for(state, &package.namespaces).await?;
    if !namespace_conflicts.is_empty() {
        return Err(AppError::conflict("applet namespace is already claimed")
            .with_wire_code("applet_namespace_conflict"));
    }
    let approved_actions = actions_from_approved_scopes(&approved_scopes);
    let denied_scopes = denied_scope_values(package, &approved_actions);
    let registration_payload = registration_payload_from_package(package)?;
    let package_digest = package
        .package_digest
        .clone()
        .ok_or_else(|| AppError::missing_param("applet_package.package_digest is required"))?;
    let seed = json!({
        "schema": "ck.schema.applet_install_plan.v1",
        "applet_id": package.applet_id,
        "package_digest": package_digest,
        "registration_epoch": package.registration_epoch,
        "effective_scope": scope,
        "requested_scopes": package.requested_scopes,
        "approved_scopes": approved_scopes,
        "denied_scopes": denied_scopes,
        "events_to_submit": [{
            "event_kind": kinds::CK_APPLET_REGISTRATION,
            "payload": registration_payload,
        }],
        "capability_constraints": capability_constraints_for_scope(scope),
        "namespace_conflicts": [],
        "e2ee_effect": e2ee_effect_for_package(package),
        "widget_effect": widget_effect_for_package(package),
        "warnings": [],
    });
    let plan_id = deterministic_plan_id(&seed)?;
    let mut plan = InstallPlan {
        schema: "ck.schema.applet_install_plan.v1".to_owned(),
        plan_id,
        applet_id: package.applet_id.clone(),
        package_digest,
        registration_epoch: package.registration_epoch.clone(),
        effective_scope: scope.clone(),
        requested_scopes: package.requested_scopes.clone(),
        approved_scopes,
        denied_scopes,
        events_to_submit: vec![InstallEventSubmission {
            event_kind: kinds::CK_APPLET_REGISTRATION.to_owned(),
            payload: registration_payload,
            refs: Vec::new(),
        }],
        capability_constraints: capability_constraints_for_scope(scope),
        namespace_conflicts: Vec::<InstallNamespaceConflict>::new(),
        e2ee_effect: e2ee_effect_for_package(package),
        widget_effect: widget_effect_for_package(package),
        warnings: Vec::new(),
        plan_digest: None,
    };
    let plan_digest = plan
        .compute_plan_digest()
        .map_err(|error| AppError::internal(format!("install plan digest failed: {error}")))?;
    plan.plan_digest = Some(plan_digest);
    Ok(plan)
}

fn registration_payload_from_package(package: &AppletPackage) -> Result<Value, AppError> {
    Ok(json!({
        "applet_id": package.applet_id,
        "service_did": package.service_did,
        "controller_did": package.controller_did,
        "base_url": package.base_url,
        "bot_actor_id": package.bot_actor_id,
        "protocols": package.protocols,
        "namespaces": package.namespaces,
        "receive_events": package.receive_events,
        "receive_ephemeral": package.receive_ephemeral,
        "rate_limited": package.rate_limited,
        "requested_scopes": package.requested_scopes,
        "registration_epoch": package.registration_epoch,
        "webhook_auth": package.webhook_auth,
        "manifest": package.manifest_snapshot(),
        "proof": package.proof,
        "created_at": package.created_at,
    }))
}

fn capability_constraints_for_scope(scope: &EffectiveScope) -> Vec<InstallCapabilityConstraint> {
    let mut params = json!({
        "realm_id": effective_scope_realm_id(scope),
    });
    if let EffectiveScope::Circle { circle_id, .. } = scope
        && let Some(params) = params.as_object_mut()
    {
        params.insert("circle_id".to_owned(), Value::String(circle_id.to_string()));
    }
    vec![InstallCapabilityConstraint {
        constraint_type: "effective_scope".to_owned(),
        params: Some(params),
    }]
}

fn e2ee_effect_for_package(package: &AppletPackage) -> InstallE2eeEffect {
    InstallE2eeEffect {
        requires_mls_join: package
            .e2ee_policy
            .get("allow_mls_join")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        plaintext_access: "policy_declared".to_owned(),
        authorization_refs: Vec::new(),
    }
}

fn widget_effect_for_package(package: &AppletPackage) -> InstallWidgetEffect {
    InstallWidgetEffect {
        allow_widget: package.widget.is_some(),
        policy_event_ref: None,
    }
}

fn deterministic_plan_id(plan_seed: &Value) -> Result<String, AppError> {
    let digest = canonical_digest(plan_seed)?;
    Ok(format!("ck:plan:{}", digest.trim_start_matches("sha256:")))
}

fn canonical_digest(value: &Value) -> Result<String, AppError> {
    cokret_sdk::canonical::canonical_sha256(value)
        .map_err(|error| AppError::internal(format!("canonical digest failed: {error}")))
}

fn actions_from_approved_scopes(scopes: &[ApprovedScope]) -> Vec<String> {
    scopes
        .iter()
        .flat_map(|scope| scope.actions.iter().cloned())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn denied_scope_values(
    package: &AppletPackage,
    approved_actions: &[String],
) -> Vec<InstallDeniedScope> {
    let approved = approved_actions.iter().collect::<BTreeSet<_>>();
    package
        .requested_scopes
        .iter()
        .filter(|scope| !approved.contains(scope))
        .map(|scope| InstallDeniedScope {
            requested_scope: scope.clone(),
            reason_code: "not_approved".to_owned(),
        })
        .collect()
}

async fn namespace_conflicts_for(
    state: &AppState,
    namespaces: &AppletWireNamespaces,
) -> Result<Vec<Value>, AppError> {
    let mut conflicts = Vec::new();
    for record in applet_records(state)
        .await?
        .into_iter()
        .filter(|record| record.revoked_at.is_none())
    {
        let Some(existing) = record.namespaces.as_ref() else {
            continue;
        };
        for conflict in namespaces.conflicts_with(existing) {
            conflicts.push(json!({
                "namespace": conflict.pattern,
                "existing_owner": record.applet_id,
                "resolution": "deny",
            }));
        }
    }
    Ok(conflicts)
}

fn effective_scope_realm_id(scope: &EffectiveScope) -> String {
    match scope {
        EffectiveScope::Realm { realm_id } | EffectiveScope::Circle { realm_id, .. } => {
            realm_id.to_string()
        }
    }
}

/// Governance gate for canonical applet install/revoke.
///
/// An authenticated session is not enough to register or revoke a realm-scoped
/// applet install: the actor MUST hold `ck.realm.admin` over the install's
/// effective_scope realm. P1 projected capability grants into the authz index,
/// so [`SolandAuthzEngine::check`] is authoritative here. Mirrors the ban gate
/// in `routing/events/operations/policy.rs::validate_member_state_policy`.
/// fail-closed: anything other than an explicit allow is rejected with
/// `applet_registration_unauthorized`.
async fn require_realm_admin(
    state: &AppState,
    actor: &str,
    scope: &EffectiveScope,
) -> Result<(), AppError> {
    let realm_id = effective_scope_realm_id(scope);
    let (owner, members) = realm_owner_and_members(state, &realm_id).await;
    if state
        .authz
        .check(
            actor,
            "ck.realm.admin",
            &realm_id,
            &realm_id,
            owner.as_deref(),
            &members,
            &[],
        )
        .allowed
    {
        return Ok(());
    }
    Err(
        AppError::capability_denied("actor lacks ck.realm.admin over the applet install realm")
            .with_wire_code("applet_registration_unauthorized"),
    )
}

/// Resolve the realm owner and member set, matching
/// `routing/events/operations.rs::realm_owner_and_members` (which is module
/// private). Both feed the authz check's owner/member implicit-grant logic.
async fn realm_owner_and_members(
    state: &AppState,
    realm_id: &str,
) -> (Option<String>, Vec<String>) {
    let owner = state
        .persistence
        .realm_meta()
        .get(realm_id)
        .await
        .ok()
        .flatten()
        .map(|meta| meta.owner);
    let members = state
        .realms
        .lock()
        .ok()
        .map(|realms| {
            if let Some(realm) = RealmId::new(realm_id.to_owned())
                .ok()
                .and_then(|id| realms.get(&id))
            {
                return realm.members.iter().map(ToString::to_string).collect();
            }
            Vec::new()
        })
        .unwrap_or_default();
    (owner, members)
}

fn manifest_from_package(package: &AppletPackage) -> AppletManifest {
    AppletManifest {
        id: package.applet_id.clone(),
        version: "1.0.0".to_owned(),
        signer_did: package.controller_did.to_string(),
        signature: package
            .proof
            .as_ref()
            .map(|proof| proof.jws.clone())
            .unwrap_or_default(),
        signer_public_key: String::new(),
        requested_capabilities: package.requested_scopes.clone(),
        schema_hash: package
            .package_digest
            .as_ref()
            .map(|hash| hash.to_string())
            .unwrap_or_default(),
        metadata: json!({
            "namespace": package_namespace(package),
            "display_name": package.package_id,
            "bridge_url": package.base_url,
            "claimed_profiles": package.claimed_profiles,
            "protocols": package.protocols,
        }),
    }
}

fn package_namespace(package: &AppletPackage) -> String {
    package
        .namespaces
        .handles
        .first()
        .or_else(|| package.namespaces.realms.first())
        .or_else(|| package.namespaces.actors.first())
        .map(|entry| safe_token(&entry.pattern))
        .unwrap_or_else(|| safe_token(&package.applet_id))
}

fn allow_ghost_actors_from_package(package: &AppletPackage) -> bool {
    package
        .ghost_policy
        .get("allow_ghost_actors")
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

fn capability_allows_message_create(capability: &str) -> bool {
    capability == "ck.message.create"
}

fn extension_actor_id_document(
    did: &str,
    actor_kind: &str,
    status: &str,
    controller: &str,
    applet: &AppletRecord,
    ghost: Option<&GhostActorRecord>,
) -> Value {
    let mut service = vec![json!({
        "id": format!("{did}#portal"),
        "type": "CokretPortalRealm",
        "serviceEndpoint": applet.portal_realm_id,
    })];
    if actor_kind == "bot_actor" {
        service.push(json!({
            "id": format!("{did}#applet"),
            "type": "CokretApplet",
            "serviceEndpoint": applet.applet_id,
        }));
    }
    let mut document = json!({
        "id": did,
        "type": actor_kind,
        "controller": controller,
        "status": status,
        "verificationMethod": [],
        "authentication": [],
        "service": service,
        "applet_id": applet.applet_id,
        "namespace": applet.namespace,
        "portal_realm_id": applet.portal_realm_id,
        "accountability": accountability_chain(applet),
    });
    if let Some(ghost) = ghost
        && let Some(object) = document.as_object_mut()
    {
        object.insert("external_id".to_owned(), json!(ghost.external_id));
        object.insert("display_name".to_owned(), json!(ghost.display_name));
    }
    document
}

fn accountability_chain(applet: &AppletRecord) -> Value {
    json!([
        {
            "kind": "bot_actor",
            "did": applet.bot_actor_id,
            "applet_id": applet.applet_id,
        },
        {
            "kind": "applet_registry",
            "did": applet.registry_did,
            "applet_id": applet.applet_id,
        }
    ])
}

async fn applet_record(
    state: &AppState,
    applet_id: &str,
) -> Result<Option<AppletRecord>, AppError> {
    let Some(value) = state
        .persistence
        .applets()
        .get(applet_id)
        .await
        .map_err(|error| {
            tracing::error!(%error, %applet_id, "failed to read applet record");
            AppError::internal("failed to read applet record")
        })?
    else {
        return Ok(None);
    };
    serde_json::from_value(value)
        .map(Some)
        .map_err(|error| AppError::internal(format!("stored applet record is invalid: {error}")))
}

async fn applet_records(state: &AppState) -> Result<Vec<AppletRecord>, AppError> {
    state
        .persistence
        .applets()
        .list()
        .await
        .map_err(|error| {
            tracing::error!(%error, "failed to list applet records");
            AppError::internal("failed to list applet records")
        })?
        .into_iter()
        .map(|value| {
            serde_json::from_value(value).map_err(|error| {
                AppError::internal(format!("stored applet record is invalid: {error}"))
            })
        })
        .collect()
}

async fn persist_applet_record(state: &AppState, record: &AppletRecord) -> Result<(), AppError> {
    let value = serde_json::to_value(record)
        .map_err(|error| AppError::internal(format!("applet record serialize failed: {error}")))?;
    state
        .persistence
        .applets()
        .put(&record.applet_id, value)
        .await
        .map_err(|error| {
            tracing::error!(%error, applet_id = %record.applet_id, "failed to persist applet record");
            AppError::internal("failed to persist applet record")
        })
}

fn ensure_not_revoked(record: &AppletRecord) -> Result<(), AppError> {
    if record.revoked_at.is_some() || record.status == "revoked" {
        return Err(AppError::conflict("applet has been revoked").with_wire_code("applet_revoked"));
    }
    Ok(())
}

fn manifest_namespace(manifest: &AppletManifest) -> Option<String> {
    manifest
        .metadata
        .get("namespace")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

fn applet_display_name(manifest: &AppletManifest) -> Option<String> {
    manifest
        .metadata
        .get("display_name")
        .or_else(|| manifest.metadata.get("name"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

fn bot_actor_id_for(namespace: &str, applet_id: &str) -> String {
    let safe = safe_token(namespace);
    let digest = sha256_hex(applet_id.as_bytes());
    format!("did:web:bot-{safe}-{}.soland.local", &digest[..12])
}

fn ghost_actor_id_for(namespace: &str, applet_id: &str, external_id: &str) -> String {
    let safe_external = safe_token(external_id);
    let digest = sha256_hex(format!("{applet_id}:{external_id}").as_bytes());
    format!(
        "did:web:ghost-{safe_external}-{}-{}.soland.local",
        safe_token(namespace),
        &digest[..12]
    )
}

fn portal_realm_id_for(namespace: &str, applet_id: &str) -> String {
    let digest = sha256_hex(applet_id.as_bytes());
    format!(
        "ck:realm:portal:{}:{}",
        safe_token(namespace),
        &digest[..12]
    )
}

fn safe_token(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
        } else if matches!(ch, '.' | '-' | '_' | ':') {
            out.push('-');
        }
    }
    let trimmed = out.trim_matches('-');
    if trimmed.is_empty() {
        "applet".to_owned()
    } else {
        trimmed.to_owned()
    }
}

fn query_value(req: &Request, key: &str) -> Option<String> {
    req.query::<String>(key)
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

fn idempotency_key(req: &Request) -> Option<String> {
    req.headers()
        .get("Idempotency-Key")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

fn applet_id_param(req: &Request) -> Result<String, AppError> {
    req.param::<String>("applet_id")
        .ok_or_else(|| AppError::missing_param("applet_id path segment required"))
}
