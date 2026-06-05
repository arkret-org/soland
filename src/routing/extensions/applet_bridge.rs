//! Applet package install, bot/ghost provisioning, and portal routing.
//!
//! This closes the runnable surface for the `extensions/applet-bridge`
//! contract: a verified Applet Package installs an applet, soland issues a
//! stable bot DID and `ck.applet.registration` projection, ghost DIDs can be
//! minted for external users, and portal messages are mirrored into the
//! canonical space timeline.

use std::collections::BTreeSet;
use std::sync::Mutex;

use cokret_sdk::{
    AppletPackage, AppletWireNamespaces, EffectiveScope, InstallCommitRequest,
    InstallPreviewRequest, InstallRevokeRequest,
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
use crate::routing::events::flow::flow_id_from_space_id;
use crate::routing::events::projection::projection_event_json;
use crate::routing::system::extract::AuthArgs;
use crate::routing::system::util::sha256_hex;
use crate::state::{AppState, EventNotification, MessageRecord, ProjectionEventRecord};
use crate::{ids, kinds};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AppletBridgeRecord {
    pub applet_id: String,
    pub namespace: String,
    pub owner_actor_did: String,
    pub registry_did: String,
    pub bot_actor_did: String,
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
    pub install_response: Option<Value>,
    #[serde(default)]
    pub ghosts: Vec<GhostActorRecord>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GhostActorRecord {
    pub ghost_actor_did: String,
    pub external_id: String,
    #[serde(default)]
    pub display_name: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    #[serde(default)]
    pub revoked_at: Option<chrono::DateTime<chrono::Utc>>,
}

static APPLET_BRIDGE_REGISTRY: Mutex<Vec<AppletBridgeRecord>> = Mutex::new(Vec::new());

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
                    .push(Router::with_path("{applet_id}/revoke").post(revoke_install_endpoint)),
            ),
        )
}

#[endpoint(
    operation_id = "ck.applet.ping",
    tags("applet"),
    summary = "Applet service liveness probe"
)]
#[tracing::instrument(skip_all, fields(op = "ck.applet.ping"))]
async fn protocol_ping_endpoint() -> JsonResult<Value> {
    json_ok(json!({
        "ok": true,
        "service": "soland",
        "surface": "ck.applet",
    }))
}

#[endpoint(
    operation_id = "ck.applet.describe",
    tags("applet"),
    summary = "Describe soland's applet protocol support"
)]
#[tracing::instrument(skip_all, fields(op = "ck.applet.describe"))]
async fn protocol_describe_endpoint() -> JsonResult<Value> {
    json_ok(json!({
        "contract": "ck.applet.v1",
        "install": {
            "preview_path": "/_cokret/self/applets/install/preview",
            "commit_path": "/_cokret/self/applets/install",
            "revoke_path": "/_cokret/self/applets/{applet_id}/revoke"
        },
        "transaction_path": "/_cokret/edge/applet/transactions",
        "package_schema": "ck.schema.applet_package.v1"
    }))
}

#[endpoint(
    operation_id = "ck.applet.install.preview",
    tags("applet"),
    summary = "Preview a canonical applet install plan",
    status_codes(200, 400, 401, 403, 409)
)]
#[tracing::instrument(skip_all, fields(op = "ck.applet.install.preview"))]
async fn install_preview_endpoint(
    aa: AuthArgs,
    body: JsonBody<Value>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<Value> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let _session = aa.authenticated_session(state, req).await?;
    let preview: InstallPreviewRequest = parse_typed_body(body.into_inner(), "install preview")?;
    validate_applet_package(&preview.applet_package)?;
    let approved_scopes = approved_scopes_from_actions(
        &preview.applet_package,
        &preview.effective_scope,
        &preview.approval_request.approve_actions,
    )?;
    let plan = build_install_plan(
        &preview.applet_package,
        &preview.effective_scope,
        approved_scopes,
    )?;
    json_ok(plan)
}

#[endpoint(
    operation_id = "ck.applet.install",
    tags("applet"),
    summary = "Commit a canonical applet install",
    status_codes(200, 201, 400, 401, 403, 409)
)]
#[tracing::instrument(skip_all, fields(op = "ck.applet.install"))]
async fn install_endpoint(
    aa: AuthArgs,
    body: JsonBody<Value>,
    depot: &mut Depot,
    req: &mut Request,
    res: &mut Response,
) -> JsonResult<Value> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let body = body.into_inner();
    let idempotency_key = idempotency_key(req)
        .ok_or_else(|| AppError::missing_param("Idempotency-Key header is required"))?;
    if idempotency_key.len() > 128 {
        return Err(AppError::invalid_param(
            "Idempotency-Key length exceeds 128 bytes",
        ));
    }
    let body_digest = canonical_digest(&body)?;
    let commit: InstallCommitRequest = parse_typed_body(body.clone(), "install commit")?;
    validate_applet_package(&commit.applet_package)?;
    let approved_scopes = serde_json::to_value(&commit.approved_scopes)
        .map_err(|error| AppError::internal(format!("approved_scopes serialize: {error}")))?;
    let approved_scopes = approved_scopes.as_array().cloned().unwrap_or_default();
    let recomputed_plan = build_install_plan(
        &commit.applet_package,
        &commit.effective_scope,
        approved_scopes,
    )?;
    let recomputed_digest = string_field(&recomputed_plan, "plan_digest")
        .ok_or_else(|| AppError::internal("install plan missing digest"))?;
    if recomputed_digest != commit.plan_digest.as_str() {
        return Err(
            AppError::conflict("install plan digest does not match recomputed plan")
                .with_wire_code("applet_install_plan_mismatch"),
        );
    }

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
    operation_id = "ck.applet.revoke",
    tags("applet"),
    summary = "Revoke a canonical applet install",
    status_codes(200, 400, 401, 403, 404, 409)
)]
#[tracing::instrument(skip_all, fields(op = "ck.applet.revoke"))]
async fn revoke_install_endpoint(
    aa: AuthArgs,
    body: JsonBody<Value>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<Value> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let applet_id = applet_id_param(req)?;
    let revoke: InstallRevokeRequest = parse_typed_body(body.into_inner(), "applet revoke")?;
    let record =
        applet_record(&applet_id).ok_or_else(|| AppError::not_found("applet is not registered"))?;
    if record
        .package
        .as_ref()
        .map(|package| package.registration_epoch.as_str())
        != Some(revoke.registration_epoch.as_str())
    {
        return Err(
            AppError::conflict("registration_epoch does not match active applet install")
                .with_wire_code("applet_registration_epoch_mismatch"),
        );
    }
    let scope_realm = effective_scope_realm_id(&revoke.effective_scope);
    if record.portal_realm_id != scope_realm {
        return Err(
            AppError::conflict("effective_scope does not match active applet install")
                .with_wire_code("applet_effective_scope_mismatch"),
        );
    }
    json_ok(revoke_applet_record(state, &session.actor, &applet_id).await?)
}

#[endpoint(
    operation_id = "ck.applet.transaction",
    tags("applet"),
    summary = "Receive an applet transaction",
    status_codes(200, 400, 401, 403, 409)
)]
#[tracing::instrument(skip_all, fields(op = "ck.applet.transaction"))]
async fn transaction_endpoint(
    aa: AuthArgs,
    body: JsonBody<Value>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<Value> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let _session = aa.authenticated_session(state, req).await?;
    let body = body.into_inner();

    if body.get("applet_id").is_none() {
        string_field(&body, "source_service_did")
            .ok_or_else(|| AppError::missing_param("source_service_did is required"))?;
        return json_ok(json!({"ok": true, "rejected": []}));
    }

    let applet_id = string_field(&body, "applet_id")
        .ok_or_else(|| AppError::missing_param("applet_id is required"))?;
    let realm_id = string_field(&body, "realm_id")
        .or_else(|| string_field(&body, "space_id"))
        .ok_or_else(|| AppError::missing_param("realm_id is required"))?;
    let payload = body.get("payload").cloned().unwrap_or(Value::Null);
    let content = portal_message_payload(&payload)?.ok_or_else(|| {
        AppError::invalid_param("payload.kind must be \"message\" and payload.text is required")
    })?;
    let (record, ghost) =
        if body.get("external_user").is_some() || body.get("external_id").is_some() {
            let (external_id, display_name) = external_user_from_body(&body)?;
            provision_ghost(applet_id, &external_id, display_name)?
        } else {
            let record = applet_record(applet_id)
                .ok_or_else(|| AppError::not_found("applet is not registered"))?;
            ensure_not_revoked(&record).map_err(|_| {
                AppError::capability_denied("bot actor capability has been revoked")
                    .with_status(StatusCode::FORBIDDEN)
                    .with_wire_code("bot_actor_revoked")
            })?;
            let ghost = GhostActorRecord {
                ghost_actor_did: record.bot_actor_did.clone(),
                external_id: "bot".to_owned(),
                display_name: Some("Applet Bot".to_owned()),
                created_at: record.registered_at,
                revoked_at: None,
            };
            (record, ghost)
        };
    let message_result = append_portal_message(state, &record, &ghost, realm_id, content).await?;
    let mut response = json!({
        "ok": true,
        "rejected": [],
        "ghost_actor_did": ghost.ghost_actor_did,
        "accountability": accountability_chain(&record),
    });
    merge_object(&mut response, message_result);
    json_ok(response)
}

#[endpoint(
    operation_id = "ck.applet.resolve_actor",
    tags("applet"),
    summary = "Resolve an applet actor"
)]
#[tracing::instrument(skip_all, fields(op = "ck.applet.resolve_actor"))]
async fn resolve_actor_endpoint(req: &mut Request) -> JsonResult<Value> {
    let actor_id = req
        .param::<String>("actor_id")
        .ok_or_else(|| AppError::missing_param("actor_id path segment required"))?;
    if let Some(doc) = did_document_for_extension_actor(&actor_id) {
        return json_ok(json!({
            "exists": true,
            "actor_id": actor_id,
            "display_name": doc.get("display_name").cloned().unwrap_or(Value::Null),
            "external_ref": {
                "applet_id": doc.get("applet_id").cloned().unwrap_or(Value::Null),
                "accountability": doc.get("accountability").cloned().unwrap_or(Value::Null),
            }
        }));
    }
    json_ok(json!({"exists": false}))
}

#[endpoint(
    operation_id = "ck.applet.resolve_realm",
    tags("applet"),
    summary = "Resolve an applet realm"
)]
#[tracing::instrument(skip_all, fields(op = "ck.applet.resolve_realm"))]
async fn resolve_realm_endpoint(req: &mut Request) -> JsonResult<Value> {
    let realm_id_or_alias = req
        .param::<String>("realm_id_or_alias")
        .ok_or_else(|| AppError::missing_param("realm_id_or_alias path segment required"))?;
    let record = APPLET_BRIDGE_REGISTRY
        .lock()
        .expect("applet bridge registry poisoned")
        .iter()
        .find(|record| {
            record.portal_realm_id == realm_id_or_alias
                || record.namespace == realm_id_or_alias
                || record.applet_id == realm_id_or_alias
        })
        .cloned();
    if let Some(record) = record {
        return json_ok(json!({
            "exists": true,
            "realm_id": record.portal_realm_id,
            "title": applet_display_name(&record.manifest).unwrap_or(record.namespace),
            "external_ref": {"applet_id": record.applet_id},
        }));
    }
    json_ok(json!({"exists": false}))
}

#[endpoint(
    operation_id = "ck.applet.protocol_metadata",
    tags("applet"),
    summary = "Read applet protocol metadata"
)]
#[tracing::instrument(skip_all, fields(op = "ck.applet.protocol_metadata"))]
async fn protocol_metadata_endpoint(req: &mut Request) -> JsonResult<Value> {
    let protocol = req
        .param::<String>("protocol")
        .ok_or_else(|| AppError::missing_param("protocol path segment required"))?;
    let applets = APPLET_BRIDGE_REGISTRY
        .lock()
        .expect("applet bridge registry poisoned")
        .iter()
        .filter(|record| {
            record
                .package
                .as_ref()
                .map(|package| package.protocols.iter().any(|item| item == &protocol))
                .unwrap_or(false)
        })
        .map(|record| {
            json!({
                "applet_id": record.applet_id,
                "service_did": record.package.as_ref().map(|package| package.service_did.to_string()),
                "status": record.status,
            })
        })
        .collect::<Vec<_>>();
    json_ok(json!({"protocol": protocol, "applets": applets}))
}

#[endpoint(
    operation_id = "ck.applet.third_party_users",
    tags("applet"),
    summary = "Resolve a third-party applet user"
)]
#[tracing::instrument(skip_all, fields(op = "ck.applet.third_party_users"))]
async fn third_party_users_endpoint(req: &mut Request) -> JsonResult<Value> {
    let external_id = query_value(req, "user")
        .or_else(|| query_value(req, "user_id"))
        .or_else(|| query_value(req, "external_id"));
    if let Some(external_id) = external_id {
        let guard = APPLET_BRIDGE_REGISTRY
            .lock()
            .expect("applet bridge registry poisoned");
        for record in guard.iter() {
            if let Some(ghost) = record
                .ghosts
                .iter()
                .find(|ghost| ghost.external_id == external_id)
            {
                return json_ok(json!({
                    "exists": true,
                    "actor_id": ghost.ghost_actor_did,
                    "external_ref": {"external_id": ghost.external_id, "applet_id": record.applet_id},
                }));
            }
        }
    }
    json_ok(json!({"exists": false}))
}

#[endpoint(
    operation_id = "ck.applet.third_party_locations",
    tags("applet"),
    summary = "Resolve a third-party applet location"
)]
#[tracing::instrument(skip_all, fields(op = "ck.applet.third_party_locations"))]
async fn third_party_locations_endpoint(req: &mut Request) -> JsonResult<Value> {
    let location = query_value(req, "location")
        .or_else(|| query_value(req, "channel"))
        .or_else(|| query_value(req, "realm"));
    let guard = APPLET_BRIDGE_REGISTRY
        .lock()
        .expect("applet bridge registry poisoned");
    if let Some(location) = location
        && let Some(record) = guard
            .iter()
            .find(|record| record.namespace == location || record.portal_realm_id == location)
    {
        return json_ok(json!({
            "exists": true,
            "realm_id": record.portal_realm_id,
            "external_ref": {"location": location, "applet_id": record.applet_id},
        }));
    }
    json_ok(json!({"exists": false}))
}

#[endpoint(
    operation_id = "ck.extension.soland.applets.register",
    tags("extensions"),
    summary = "Register a verified applet manifest and issue a bot actor DID",
    status_codes(200, 201, 400, 401, 403, 409)
)]
#[tracing::instrument(skip_all, fields(op = "ck.extension.soland.applets.register"))]
async fn register_endpoint(
    aa: AuthArgs,
    body: JsonBody<Value>,
    depot: &mut Depot,
    req: &mut Request,
    res: &mut Response,
) -> JsonResult<Value> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let body = body.into_inner();
    let manifest = parse_manifest(&body)?;
    let trusted_registry_did = string_field(&body, "trusted_registry_did")
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
    operation_id = "ck.extension.soland.applets.get",
    tags("extensions"),
    summary = "Read applet bridge registration state"
)]
#[tracing::instrument(skip_all, fields(op = "ck.extension.soland.applets.get"))]
async fn get_endpoint(req: &mut Request) -> JsonResult<Value> {
    let applet_id = applet_id_param(req)?;
    let record =
        applet_record(&applet_id).ok_or_else(|| AppError::not_found("applet is not registered"))?;
    json_ok(applet_response(&record))
}

#[endpoint(
    operation_id = "ck.extension.soland.applets.ghosts.provision",
    tags("extensions"),
    summary = "Provision or reuse a ghost actor and optionally route a portal message"
)]
#[tracing::instrument(skip_all, fields(op = "ck.extension.soland.applets.ghosts.provision"))]
async fn ghost_endpoint(
    aa: AuthArgs,
    body: JsonBody<Value>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<Value> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let _session = aa.authenticated_session(state, req).await?;
    let applet_id = applet_id_param(req)?;
    let body = body.into_inner();
    let (external_id, display_name) = external_user_from_body(&body)?;
    let payload = body.get("payload").cloned().unwrap_or(Value::Null);
    let realm_id = string_field(&body, "space_id").map(str::to_owned);

    let (record, ghost) = provision_ghost(&applet_id, &external_id, display_name)?;
    let mut response = json!({
        "applet_id": record.applet_id,
        "ghost_actor_did": ghost.ghost_actor_did,
        "external_id": ghost.external_id,
        "display_name": ghost.display_name,
        "accountability": accountability_chain(&record),
    });
    if let Some(realm_id) = realm_id {
        if let Some(message) = portal_message_payload(&payload)? {
            let message_result =
                append_portal_message(state, &record, &ghost, &realm_id, message).await?;
            merge_object(&mut response, message_result);
        }
    }
    json_ok(response)
}

#[endpoint(
    operation_id = "ck.extension.soland.applets.bot.message",
    tags("extensions"),
    summary = "Write a portal message as the applet bot actor"
)]
#[tracing::instrument(skip_all, fields(op = "ck.extension.soland.applets.bot.message"))]
async fn bot_message_endpoint(
    aa: AuthArgs,
    body: JsonBody<Value>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<Value> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let _session = aa.authenticated_session(state, req).await?;
    let applet_id = applet_id_param(req)?;
    let body = body.into_inner();
    let record =
        applet_record(&applet_id).ok_or_else(|| AppError::not_found("applet is not registered"))?;
    ensure_not_revoked(&record).map_err(|_| {
        AppError::capability_denied("bot actor capability has been revoked")
            .with_status(StatusCode::FORBIDDEN)
            .with_wire_code("bot_actor_revoked")
    })?;
    let realm_id = string_field(&body, "space_id")
        .ok_or_else(|| AppError::missing_param("realm_id is required"))?;
    let payload = body.get("payload").cloned().unwrap_or_else(|| body.clone());
    let content = portal_message_payload(&payload)?.ok_or_else(|| {
        AppError::invalid_param("payload.kind must be \"message\" and payload.text is required")
    })?;
    let synthetic_ghost = GhostActorRecord {
        ghost_actor_did: record.bot_actor_did.clone(),
        external_id: "bot".to_owned(),
        display_name: Some("Applet Bot".to_owned()),
        created_at: record.registered_at,
        revoked_at: None,
    };
    let message_result =
        append_portal_message(state, &record, &synthetic_ghost, realm_id, content).await?;
    json_ok(message_result)
}

#[endpoint(
    operation_id = "ck.extension.soland.applets.revoke",
    tags("extensions"),
    summary = "Revoke an applet's bot and ghost capabilities"
)]
#[tracing::instrument(skip_all, fields(op = "ck.extension.soland.applets.revoke"))]
async fn revoke_endpoint(aa: AuthArgs, depot: &mut Depot, req: &mut Request) -> JsonResult<Value> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let applet_id = applet_id_param(req)?;
    json_ok(revoke_applet_record(state, &session.actor, &applet_id).await?)
}

async fn revoke_applet_record(
    state: &AppState,
    actor: &str,
    applet_id: &str,
) -> Result<Value, AppError> {
    let now = chrono::Utc::now();
    let record = {
        let mut guard = APPLET_BRIDGE_REGISTRY
            .lock()
            .expect("applet bridge registry poisoned");
        let record = guard
            .iter_mut()
            .find(|record| record.applet_id == applet_id)
            .ok_or_else(|| AppError::not_found("applet is not registered"))?;
        if record.owner_actor_did != actor {
            return Err(AppError::capability_denied(
                "only the registering actor can revoke this applet",
            ));
        }
        record.status = "revoked".to_owned();
        record.revoked_at = Some(now);
        for ghost in &mut record.ghosts {
            ghost.revoked_at.get_or_insert(now);
        }
        record.clone()
    };
    bot_actor::revoke_bot(&record.bot_actor_did);
    for ghost in &record.ghosts {
        bot_actor::revoke_bot(&ghost.ghost_actor_did);
    }
    crate::routing::append_audit_log(
        state,
        Some(actor),
        "extensions.applet.revoke",
        json!({
            "applet_id": record.applet_id,
            "bot_actor_did": record.bot_actor_did,
            "ghost_count": record.ghosts.len(),
        }),
        "accepted",
    )
    .await;
    Ok(json!({
        "applet_id": record.applet_id,
        "status": "revoked",
        "revoked_at": now,
        "bot_actor_did": record.bot_actor_did,
        "ghost_actor_dids": record.ghosts.iter().map(|ghost| ghost.ghost_actor_did.clone()).collect::<Vec<_>>(),
    }))
}

pub fn did_document_for_extension_actor(did: &str) -> Option<Value> {
    let guard = APPLET_BRIDGE_REGISTRY
        .lock()
        .expect("applet bridge registry poisoned");
    for record in guard.iter() {
        if record.bot_actor_did == did {
            let status = if record.revoked_at.is_some() {
                "revoked"
            } else {
                "active"
            };
            return Some(extension_actor_did_document(
                did,
                "bot_actor",
                status,
                &record.owner_actor_did,
                record,
                None,
            ));
        }
        if let Some(ghost) = record
            .ghosts
            .iter()
            .find(|ghost| ghost.ghost_actor_did == did)
        {
            let status = if record.revoked_at.is_some() || ghost.revoked_at.is_some() {
                "revoked"
            } else {
                "active"
            };
            return Some(extension_actor_did_document(
                did,
                "ghost_actor",
                status,
                &record.bot_actor_did,
                record,
                Some(ghost),
            ));
        }
    }
    None
}

async fn register_package_install(
    state: &AppState,
    owner_actor_did: &str,
    commit: InstallCommitRequest,
    idempotency_key: String,
    body_digest: String,
    res: &mut Response,
) -> Result<Value, AppError> {
    let package = commit.applet_package;
    let applet_id = package.applet_id.clone();
    let namespace = package_namespace(&package);
    let realm_id = effective_scope_realm_id(&commit.effective_scope);
    let approved_actions = actions_from_approved_scope_values(
        &serde_json::to_value(&commit.approved_scopes)
            .map_err(|error| AppError::internal(format!("approved_scopes serialize: {error}")))?
            .as_array()
            .cloned()
            .unwrap_or_default(),
    );

    {
        let guard = APPLET_BRIDGE_REGISTRY
            .lock()
            .expect("applet bridge registry poisoned");
        if let Some(existing) = guard.iter().find(|record| record.applet_id == applet_id) {
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
    }

    let namespace_conflicts = namespace_conflicts_for(&package.namespaces);
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
    let response = json!({
        "ok": effective_status != "rejected",
        "install_id": install_id,
        "applet_id": applet_id,
        "registration_event_ref": registration_event_ref,
        "registration_epoch": package.registration_epoch,
        "bot_actor_id": package.bot_actor_id,
        "capability_grant_refs": capability_grant_refs,
        "membership_event_refs": [],
        "e2ee_authorization_refs": [],
        "widget_policy_ref": Value::Null,
        "effective_status": effective_status,
        "rejected": denied_scope_values(&package, &approved_actions),
    });
    let record = AppletBridgeRecord {
        applet_id: package.applet_id.clone(),
        namespace,
        owner_actor_did: owner_actor_did.to_owned(),
        registry_did: package.controller_did.to_string(),
        bot_actor_did: package.bot_actor_id.to_string(),
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
        install_id: response
            .get("install_id")
            .and_then(Value::as_str)
            .map(str::to_owned),
        install_response: Some(response.clone()),
        ghosts: Vec::new(),
    };
    bot_actor::register_bot(BotActor {
        did: record.bot_actor_did.clone(),
        name: applet_display_name(&record.manifest).unwrap_or_else(|| record.namespace.clone()),
        kind: KIND_BOT.to_owned(),
        owner_actor_did: owner_actor_did.to_owned(),
        created_at: now,
        revoked_at: None,
    });
    APPLET_BRIDGE_REGISTRY
        .lock()
        .expect("applet bridge registry poisoned")
        .push(record.clone());
    update_applet_projection(state, &record);
    append_applet_registration_projection(state, &record, &registration_event_ref).await?;
    crate::routing::append_audit_log(
        state,
        Some(owner_actor_did),
        "applet.install",
        json!({
            "applet_id": record.applet_id,
            "namespace": record.namespace,
            "service_did": package.service_did,
            "bot_actor_id": record.bot_actor_did,
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
    record: &AppletBridgeRecord,
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
        sender: Some(record.owner_actor_did.clone()),
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

fn update_applet_projection(state: &AppState, record: &AppletBridgeRecord) {
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
    owner_actor_did: &str,
    manifest: AppletManifest,
    verified: VerifiedAppletManifest,
    idempotency_key: Option<String>,
    res: &mut Response,
) -> Result<Value, AppError> {
    let applet_id = verified.id.clone();
    let namespace = manifest_namespace(&manifest).unwrap_or_else(|| safe_token(&applet_id));
    {
        let guard = APPLET_BRIDGE_REGISTRY
            .lock()
            .expect("applet bridge registry poisoned");
        if let Some(existing) = guard.iter().find(|record| record.applet_id == applet_id) {
            if idempotency_key.is_some()
                && existing.idempotency_key.as_deref() == idempotency_key.as_deref()
            {
                res.status_code(StatusCode::OK);
                return Ok(applet_response(existing));
            }
            return Err(
                AppError::conflict("applet manifest id is already registered")
                    .with_wire_code("applet_already_registered"),
            );
        }
        if guard.iter().any(|record| {
            record.namespace == namespace
                && record.applet_id != applet_id
                && record.revoked_at.is_none()
        }) {
            return Err(AppError::conflict("applet namespace is already claimed")
                .with_wire_code("applet_namespace_conflict"));
        }
    }

    let now = chrono::Utc::now();
    let bot_actor_did = bot_actor_did_for(&namespace, &applet_id);
    let portal_realm_id = portal_realm_id_for(&namespace, &applet_id);
    let allow_ghost_actors = verified
        .capabilities
        .iter()
        .any(|capability| capability_allows_ghost_actor(capability));
    let record = AppletBridgeRecord {
        applet_id,
        namespace,
        owner_actor_did: owner_actor_did.to_owned(),
        registry_did: verified.signer_did,
        bot_actor_did: bot_actor_did.clone(),
        portal_realm_id,
        capabilities: verified.capabilities,
        manifest,
        package: None,
        namespaces: None,
        allow_ghost_actors,
        status: "registered".to_owned(),
        registered_at: now,
        revoked_at: None,
        idempotency_key,
        install_body_digest: None,
        install_id: None,
        install_response: None,
        ghosts: Vec::new(),
    };
    bot_actor::register_bot(BotActor {
        did: bot_actor_did,
        name: applet_display_name(&record.manifest).unwrap_or_else(|| record.namespace.clone()),
        kind: KIND_BOT.to_owned(),
        owner_actor_did: owner_actor_did.to_owned(),
        created_at: now,
        revoked_at: None,
    });
    APPLET_BRIDGE_REGISTRY
        .lock()
        .expect("applet bridge registry poisoned")
        .push(record.clone());
    crate::routing::append_audit_log(
        state,
        Some(owner_actor_did),
        "extensions.applet.register",
        json!({
            "applet_id": record.applet_id,
            "namespace": record.namespace,
            "registry_did": record.registry_did,
            "bot_actor_did": record.bot_actor_did,
            "portal_realm_id": record.portal_realm_id,
        }),
        "accepted",
    )
    .await;
    res.status_code(StatusCode::CREATED);
    Ok(applet_response(&record))
}

fn provision_ghost(
    applet_id: &str,
    external_id: &str,
    display_name: Option<String>,
) -> Result<(AppletBridgeRecord, GhostActorRecord), AppError> {
    let now = chrono::Utc::now();
    let mut guard = APPLET_BRIDGE_REGISTRY
        .lock()
        .expect("applet bridge registry poisoned");
    let record = guard
        .iter_mut()
        .find(|record| record.applet_id == applet_id)
        .ok_or_else(|| AppError::not_found("applet is not registered"))?;
    ensure_not_revoked(record)?;
    if !record.allow_ghost_actors
        && !record
            .capabilities
            .iter()
            .any(|capability| capability_allows_ghost_actor(capability))
    {
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
        return Ok((record.clone(), existing));
    }
    let ghost = GhostActorRecord {
        ghost_actor_did: ghost_actor_did_for(&record.namespace, applet_id, external_id),
        external_id: external_id.to_owned(),
        display_name,
        created_at: now,
        revoked_at: None,
    };
    bot_actor::register_bot(BotActor {
        did: ghost.ghost_actor_did.clone(),
        name: ghost
            .display_name
            .clone()
            .unwrap_or_else(|| ghost.external_id.clone()),
        kind: KIND_GHOST.to_owned(),
        owner_actor_did: record.owner_actor_did.clone(),
        created_at: now,
        revoked_at: None,
    });
    record.ghosts.push(ghost.clone());
    Ok((record.clone(), ghost))
}

async fn append_portal_message(
    state: &AppState,
    applet: &AppletBridgeRecord,
    ghost: &GhostActorRecord,
    realm_id: &str,
    content: Value,
) -> Result<Value, AppError> {
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
    let thread_id = flow_id_from_space_id(realm_id);
    let created_at = chrono::Utc::now();
    let content_with_portal = enrich_content_with_portal_metadata(content, applet, ghost);
    let message_record = MessageRecord {
        event_id: event_id.clone(),
        realm_id: realm_id.to_owned(),
        sender: ghost.ghost_actor_did.clone(),
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
        sender: Some(ghost.ghost_actor_did.clone()),
        payload: json!({
            "thread_id": thread_id,
            "content": content_with_portal,
            "encrypted": false,
            "portal_realm_id": applet.portal_realm_id,
            "applet_id": applet.applet_id,
            "bot_actor_did": applet.bot_actor_did,
            "ghost_actor_did": ghost.ghost_actor_did,
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
    Ok(json!({
        "message_id": crate::routing::events::flow::message_id_from_event_id(&event_id),
        "event_id": event_id,
        "operation_id": operation_id,
        "realm_id": realm_id,
        "portal_realm_id": applet.portal_realm_id,
    }))
}

fn parse_manifest(body: &Value) -> Result<AppletManifest, AppError> {
    let mut manifest_value = body
        .get("manifest")
        .or_else(|| body.get("manifest_json"))
        .cloned()
        .ok_or_else(|| AppError::missing_param("manifest is required"))?;
    if let Some(signature) =
        string_field(body, "signature").or_else(|| string_field(body, "manifest_signature"))
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

fn external_user_from_body(body: &Value) -> Result<(String, Option<String>), AppError> {
    if let Some(external_user) = body.get("external_user").and_then(Value::as_object) {
        let external_id = external_user
            .get("id")
            .or_else(|| external_user.get("external_id"))
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| AppError::missing_param("external_user.id is required"))?;
        let display_name = external_user
            .get("display_name")
            .and_then(Value::as_str)
            .map(str::to_owned);
        return Ok((external_id.to_owned(), display_name));
    }
    let external_id = string_field(body, "external_id")
        .ok_or_else(|| AppError::missing_param("external_id is required"))?;
    let display_name = string_field(body, "display_name").map(str::to_owned);
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
    applet: &AppletBridgeRecord,
    ghost: &GhostActorRecord,
) -> Value {
    if let Some(object) = content.as_object_mut() {
        object.insert(
            "portal".to_owned(),
            json!({
                "applet_id": applet.applet_id,
                "portal_realm_id": applet.portal_realm_id,
                "bot_actor_did": applet.bot_actor_did,
                "ghost_actor_did": ghost.ghost_actor_did,
                "external_id": ghost.external_id,
                "display_name": ghost.display_name,
            }),
        );
    }
    content
}

fn applet_response(record: &AppletBridgeRecord) -> Value {
    json!({
        "applet_id": record.applet_id,
        "namespace": record.namespace,
        "owner_actor_did": record.owner_actor_did,
        "registry_did": record.registry_did,
        "bot_actor_did": record.bot_actor_did,
        "portal_realm_id": record.portal_realm_id,
        "capabilities": record.capabilities,
        "status": record.status,
        "registered_at": record.registered_at,
        "revoked_at": record.revoked_at,
        "ghost_actor_dids": record.ghosts.iter().map(|ghost| ghost.ghost_actor_did.clone()).collect::<Vec<_>>(),
        "manifest": record.manifest,
    })
}

fn parse_typed_body<T: serde::de::DeserializeOwned>(
    body: Value,
    label: &str,
) -> Result<T, AppError> {
    serde_json::from_value(body).map_err(|error| AppError::bad_json(format!("{label}: {error}")))
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
) -> Result<Vec<Value>, AppError> {
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
    Ok(vec![json!({
        "actions": approved.into_iter().collect::<Vec<_>>(),
        "realm_ids": [effective_scope_realm_id(scope)],
        "constraints": [],
    })])
}

fn build_install_plan(
    package: &AppletPackage,
    scope: &EffectiveScope,
    approved_scopes: Vec<Value>,
) -> Result<Value, AppError> {
    let namespace_conflicts = namespace_conflicts_for(&package.namespaces);
    if !namespace_conflicts.is_empty() {
        return Err(AppError::conflict("applet namespace is already claimed")
            .with_wire_code("applet_namespace_conflict"));
    }
    let approved_actions = actions_from_approved_scope_values(&approved_scopes);
    let denied_scopes = denied_scope_values(package, &approved_actions);
    let registration_payload = registration_payload_from_package(package)?;
    let seed = json!({
        "schema": "ck.schema.applet_install_plan.v1",
        "applet_id": package.applet_id,
        "package_digest": package.package_digest.as_ref().map(|hash| hash.to_string()).unwrap_or_default(),
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
    let mut plan = seed;
    plan.as_object_mut()
        .ok_or_else(|| AppError::internal("install plan seed is not an object"))?
        .insert("plan_id".to_owned(), Value::String(plan_id));
    let plan_digest = canonical_digest(&plan)?;
    plan.as_object_mut()
        .ok_or_else(|| AppError::internal("install plan is not an object"))?
        .insert("plan_digest".to_owned(), Value::String(plan_digest));
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

fn capability_constraints_for_scope(scope: &EffectiveScope) -> Vec<Value> {
    let mut constraint = json!({
        "constraint_type": "effective_scope",
        "params": {
            "realm_id": effective_scope_realm_id(scope),
        }
    });
    if let EffectiveScope::Circle { circle_id, .. } = scope
        && let Some(params) = constraint.get_mut("params").and_then(Value::as_object_mut)
    {
        params.insert("circle_id".to_owned(), Value::String(circle_id.to_string()));
    }
    vec![constraint]
}

fn e2ee_effect_for_package(package: &AppletPackage) -> Value {
    json!({
        "requires_mls_join": package
            .e2ee_policy
            .get("allow_mls_join")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        "plaintext_access": "policy_declared",
        "authorization_refs": [],
    })
}

fn widget_effect_for_package(package: &AppletPackage) -> Value {
    json!({
        "allow_widget": package.widget.is_some(),
        "policy_event_ref": Value::Null,
    })
}

fn deterministic_plan_id(plan_seed: &Value) -> Result<String, AppError> {
    let digest = canonical_digest(plan_seed)?;
    Ok(format!("ck:plan:{}", digest.trim_start_matches("sha256:")))
}

fn canonical_digest(value: &Value) -> Result<String, AppError> {
    cokret_sdk::canonical::canonical_sha256(value)
        .map_err(|error| AppError::internal(format!("canonical digest failed: {error}")))
}

fn actions_from_approved_scope_values(scopes: &[Value]) -> Vec<String> {
    scopes
        .iter()
        .filter_map(Value::as_object)
        .flat_map(|scope| {
            scope
                .get("actions")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .map(str::to_owned)
        })
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn denied_scope_values(package: &AppletPackage, approved_actions: &[String]) -> Vec<Value> {
    let approved = approved_actions.iter().collect::<BTreeSet<_>>();
    package
        .requested_scopes
        .iter()
        .filter(|scope| !approved.contains(scope))
        .map(|scope| {
            json!({
                "requested_scope": scope,
                "reason_code": "not_approved",
            })
        })
        .collect()
}

fn namespace_conflicts_for(namespaces: &AppletWireNamespaces) -> Vec<Value> {
    let guard = APPLET_BRIDGE_REGISTRY
        .lock()
        .expect("applet bridge registry poisoned");
    let mut conflicts = Vec::new();
    for record in guard.iter().filter(|record| record.revoked_at.is_none()) {
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
    conflicts
}

fn effective_scope_realm_id(scope: &EffectiveScope) -> String {
    match scope {
        EffectiveScope::Realm { realm_id } | EffectiveScope::Circle { realm_id, .. } => {
            realm_id.to_string()
        }
    }
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
        || package
            .requested_scopes
            .iter()
            .any(|capability| capability_allows_ghost_actor(capability))
}

fn capability_allows_message_create(capability: &str) -> bool {
    matches!(capability, "ck.message.create" | "message:write")
}

fn capability_allows_ghost_actor(capability: &str) -> bool {
    matches!(
        capability,
        "ck.applet.ghost.provision" | "actor:provision-ghost"
    )
}

fn extension_actor_did_document(
    did: &str,
    actor_kind: &str,
    status: &str,
    controller: &str,
    applet: &AppletBridgeRecord,
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

fn accountability_chain(applet: &AppletBridgeRecord) -> Value {
    json!([
        {
            "kind": "bot_actor",
            "did": applet.bot_actor_did,
            "applet_id": applet.applet_id,
        },
        {
            "kind": "applet_registry",
            "did": applet.registry_did,
            "applet_id": applet.applet_id,
        }
    ])
}

fn applet_record(applet_id: &str) -> Option<AppletBridgeRecord> {
    APPLET_BRIDGE_REGISTRY
        .lock()
        .expect("applet bridge registry poisoned")
        .iter()
        .find(|record| record.applet_id == applet_id)
        .cloned()
}

fn ensure_not_revoked(record: &AppletBridgeRecord) -> Result<(), AppError> {
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

fn bot_actor_did_for(namespace: &str, applet_id: &str) -> String {
    let safe = safe_token(namespace);
    let digest = sha256_hex(applet_id.as_bytes());
    format!("did:web:bot-{safe}-{}.soland.local", &digest[..12])
}

fn ghost_actor_did_for(namespace: &str, applet_id: &str, external_id: &str) -> String {
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

fn string_field<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
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

fn merge_object(target: &mut Value, source: Value) {
    let Some(target_object) = target.as_object_mut() else {
        return;
    };
    let Some(source_object) = source.as_object() else {
        return;
    };
    for (key, value) in source_object {
        target_object.insert(key.clone(), value.clone());
    }
}
