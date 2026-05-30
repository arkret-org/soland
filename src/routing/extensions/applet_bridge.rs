//! Applet bridge registration, bot/ghost provisioning, and portal routing.
//!
//! This closes the runnable surface for the `extensions/applet-bridge`
//! contract: a verified manifest registers an applet, soland issues a
//! stable bot DID, ghost DIDs can be minted for external users, and portal
//! messages are mirrored into the canonical space timeline.

use std::sync::Mutex;

use salvo::http::StatusCode;
use salvo::oapi::extract::JsonBody;
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::error::AppError;
use crate::ids;
use crate::kinds;
use crate::result::{JsonResult, json_ok};
use crate::routing::events::flow::flow_id_from_space_id;
use crate::routing::events::projection::projection_event_json;
use crate::routing::system::extract::AuthArgs;
use crate::routing::system::util::sha256_hex;
use crate::state::{AppState, EventNotification, MessageRecord, ProjectionEventRecord};

use super::applet_manifest::{AppletManifest, VerifiedAppletManifest, verify_manifest};
use super::bot_actor::{self, BotActor, KIND_BOT, KIND_GHOST};

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
    pub status: String,
    pub registered_at: chrono::DateTime<chrono::Utc>,
    #[serde(default)]
    pub revoked_at: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(default)]
    pub idempotency_key: Option<String>,
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

#[endpoint(
    operation_id = "cx.extension.soland.applets.register",
    tags("extensions"),
    summary = "Register a verified applet manifest and issue a bot actor DID",
    status_codes(200, 201, 400, 401, 403, 409)
)]
#[tracing::instrument(skip_all, fields(op = "cx.extension.soland.applets.register"))]
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
    operation_id = "cx.extension.soland.applets.get",
    tags("extensions"),
    summary = "Read applet bridge registration state"
)]
#[tracing::instrument(skip_all, fields(op = "cx.extension.soland.applets.get"))]
async fn get_endpoint(req: &mut Request) -> JsonResult<Value> {
    let applet_id = applet_id_param(req)?;
    let record =
        applet_record(&applet_id).ok_or_else(|| AppError::not_found("applet is not registered"))?;
    json_ok(applet_response(&record))
}

#[endpoint(
    operation_id = "cx.extension.soland.applets.ghosts.provision",
    tags("extensions"),
    summary = "Provision or reuse a ghost actor and optionally route a portal message"
)]
#[tracing::instrument(skip_all, fields(op = "cx.extension.soland.applets.ghosts.provision"))]
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
    let space_id = string_field(&body, "space_id").map(str::to_owned);

    let (record, ghost) = provision_ghost(&applet_id, &external_id, display_name)?;
    let mut response = json!({
        "applet_id": record.applet_id,
        "ghost_actor_did": ghost.ghost_actor_did,
        "external_id": ghost.external_id,
        "display_name": ghost.display_name,
        "accountability": accountability_chain(&record),
    });
    if let Some(space_id) = space_id {
        if let Some(message) = portal_message_payload(&payload)? {
            let message_result =
                append_portal_message(state, &record, &ghost, &space_id, message).await?;
            merge_object(&mut response, message_result);
        }
    }
    json_ok(response)
}

#[endpoint(
    operation_id = "cx.extension.soland.applets.bot.message",
    tags("extensions"),
    summary = "Write a portal message as the applet bot actor"
)]
#[tracing::instrument(skip_all, fields(op = "cx.extension.soland.applets.bot.message"))]
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
    let space_id = string_field(&body, "space_id")
        .ok_or_else(|| AppError::missing_param("space_id is required"))?;
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
        append_portal_message(state, &record, &synthetic_ghost, space_id, content).await?;
    json_ok(message_result)
}

#[endpoint(
    operation_id = "cx.extension.soland.applets.revoke",
    tags("extensions"),
    summary = "Revoke an applet's bot and ghost capabilities"
)]
#[tracing::instrument(skip_all, fields(op = "cx.extension.soland.applets.revoke"))]
async fn revoke_endpoint(aa: AuthArgs, depot: &mut Depot, req: &mut Request) -> JsonResult<Value> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let applet_id = applet_id_param(req)?;
    let now = chrono::Utc::now();
    let record = {
        let mut guard = APPLET_BRIDGE_REGISTRY
            .lock()
            .expect("applet bridge registry poisoned");
        let record = guard
            .iter_mut()
            .find(|record| record.applet_id == applet_id)
            .ok_or_else(|| AppError::not_found("applet is not registered"))?;
        if record.owner_actor_did != session.actor {
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
        Some(&session.actor),
        "extensions.applet.revoke",
        json!({
            "applet_id": record.applet_id,
            "bot_actor_did": record.bot_actor_did,
            "ghost_count": record.ghosts.len(),
        }),
        "accepted",
    )
    .await;
    json_ok(json!({
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
            return Some(extension_actor_did_document(
                did,
                "bot_actor",
                &record.status,
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
    let record = AppletBridgeRecord {
        applet_id,
        namespace,
        owner_actor_did: owner_actor_did.to_owned(),
        registry_did: verified.signer_did,
        bot_actor_did: bot_actor_did.clone(),
        portal_realm_id,
        capabilities: verified.capabilities,
        manifest,
        status: "registered".to_owned(),
        registered_at: now,
        revoked_at: None,
        idempotency_key,
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
    if !record
        .capabilities
        .iter()
        .any(|cap| cap == "actor:provision-ghost")
    {
        return Err(AppError::capability_denied(
            "applet manifest does not grant actor:provision-ghost",
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
    space_id: &str,
    content: Value,
) -> Result<Value, AppError> {
    if !applet.capabilities.iter().any(|cap| cap == "message:write") {
        return Err(AppError::capability_denied(
            "applet manifest does not grant message:write",
        ));
    }
    let operation_id = ids::generate_operation_id();
    let event_id = ids::generate_event_id();
    let thread_id = flow_id_from_space_id(space_id);
    let created_at = chrono::Utc::now();
    let content_with_portal = enrich_content_with_portal_metadata(content, applet, ghost);
    let message_record = MessageRecord {
        event_id: event_id.clone(),
        space_id: space_id.to_owned(),
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
        space_id: space_id.to_owned(),
        event_kind: kinds::CX_MESSAGE_CREATE.to_owned(),
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
        projection_record.space_id.clone(),
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
        "space_id": space_id,
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
    if kind != "message" && kind != "cx.content.text" {
        return Ok(None);
    }
    let text = payload
        .get("text")
        .or_else(|| payload.get("body"))
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| AppError::invalid_param("payload.text is required"))?;
    Ok(Some(json!({
        "kind": "cx.content.text",
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
        "type": "ContrixPortalRealm",
        "serviceEndpoint": applet.portal_realm_id,
    })];
    if actor_kind == "bot_actor" {
        service.push(json!({
            "id": format!("{did}#applet"),
            "type": "ContrixApplet",
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
        "cx:realm:portal:{}:{}",
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
