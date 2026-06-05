//! Dev-only admin collection surfaces.
//!
//! Surfaces:
//! - `GET /_soland/admin/{resource}` — paginated dev snapshot of one of the builtin admin
//!   collections (`actors`, `realms`, `spaces`, `devices`, `capabilities`, `federation`, `applets`,
//!   `agents`, `reports`, `invite-tokens`, `audit`, `policy`, `media`). `realms` are security
//!   boundaries; `spaces` are authorization-transparent navigation containers.
//!
//! Authorization is enforced by the shared `RequireAdmin` middleware with
//! the SDK `admin.read` scope before this handler runs. Further hardening
//! (durable cursor pagination, redaction policy, high-risk audit signing)
//! is tracked under `_todos.md` Q9.

use std::collections::BTreeMap;

use cokret_sdk::{Operation, OperationId, RealmId};
use salvo::oapi::extract::{JsonBody, PathParam, QueryParam};
use salvo::prelude::*;
use serde::Deserialize;
use serde_json::{Value, json};

use super::{
    accept_local_operations, append_audit_log, demo_actors, device_inventory_to_json,
    discussion_track_for_projection_event, flow_id_for_projection_event, flow_id_from_realm_id,
    flow_projection_for_realm, policy_document_to_response, projection_event_from_operation,
    sha256_hex,
};
use crate::error::{AppError, ErrorCode};
use crate::result::{JsonResult, json_ok};
use crate::routing::system::extract::AuthArgs;
use crate::state::{AppState, RealmDirectoryEntry, RealmMetaRecord};
use crate::{ids, kinds};

#[endpoint(
    operation_id = "ck.extension.soland.admin.collection",
    tags("admin"),
    summary = "Dev-only paginated admin snapshot of a named collection"
)]
#[tracing::instrument(skip_all, fields(op = "ck.extension.soland.admin.collection"))]
pub(super) async fn admin_collection(
    aa: AuthArgs,
    resource: PathParam<String>,
    limit: QueryParam<usize, false>,
    cursor: QueryParam<String, false>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<Value> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    if !state.config.development_mode && !state.config.is_admin_principal(&session.actor) {
        return Err(AppError::capability_denied(
            "admin collection API requires the caller DID to be listed in SOLAND_ADMIN_PRINCIPAL_DIDS",
        ));
    }
    let grant = super::introspect_admin_scopes(state, req, &session)
        .await
        .map_err(|error| {
            let http = error.http_status();
            AppError::capability_denied(format!("admin scope check failed: {error}"))
                .with_status(http)
        })?;
    if !grant.has_admin_scope(cokret_sdk::admin_scopes::ADMIN_READ) {
        return Err(AppError::capability_denied(
            "admin collection API requires admin.read scope",
        ));
    }
    let resource = resource.into_inner();
    let default_limit = state.config.admin_default_page_limit;
    let max_limit = state.config.admin_max_page_limit;
    let limit = limit
        .into_inner()
        .unwrap_or(default_limit)
        .clamp(1, max_limit);
    let cursor = cursor.into_inner();

    let (field, mut items) = match resource.as_str() {
        "actors" => ("actors", admin_actor_items(state).await),
        "realms" => ("realms", admin_realm_items(state).await),
        "spaces" => ("spaces", admin_space_container_items(state)),
        "devices" => ("devices", admin_device_items(state).await),
        "capabilities" => ("capabilities", admin_capability_items(state)),
        "federation" => ("federation", admin_federation_items(state).await),
        "applets" => ("applets", admin_applet_items(state)),
        "agents" => ("agents", admin_agent_items(state)),
        "reports" => (
            "reports",
            crate::routing::interop::moderation::visible_reports_for_actor(
                state,
                &session.actor,
                None,
            )
            .await,
        ),
        "invite-tokens" => ("invite_tokens", admin_invite_items(state).await),
        "audit" => (
            "audit",
            state
                .persistence
                .audit()
                .snapshot_all()
                .await
                .unwrap_or_default(),
        ),
        "policy" => ("policy", admin_policy_items(state).await),
        "media" => ("media", admin_media_items(state).await),
        _ => {
            return Err(AppError::not_found("admin resource not found"));
        }
    };
    items.sort_by_key(|left| left.to_string());
    let start = match cursor.as_deref() {
        Some(raw) => raw
            .parse::<usize>()
            .map_err(|_| AppError::invalid_param("invalid cursor"))?,
        None => 0,
    };
    let total = items.len();
    let mut page = items.into_iter().skip(start).collect::<Vec<_>>();
    let has_more = page.len() > limit;
    if has_more {
        page.truncate(limit);
    }
    let next_cursor = has_more.then(|| (start + limit).to_string());

    append_audit_log(
        state,
        Some(&session.actor),
        "admin.collection",
        json!({
            "resource": resource.clone(),
            "device_id": session.device_id,
            "count": page.len(),
        }),
        "accepted",
    )
    .await;

    let mut body = serde_json::Map::new();
    body.insert("resource".to_owned(), json!(resource));
    body.insert("data".to_owned(), json!(page.clone()));
    body.insert("items".to_owned(), json!(page.clone()));
    body.insert(field.to_owned(), json!(page));
    body.insert("total".to_owned(), json!(total));
    body.insert("next_cursor".to_owned(), json!(next_cursor));
    body.insert(
        "production_gap".to_owned(),
        json!("admin_authorization_and_durable_pagination"),
    );
    json_ok(Value::Object(body))
}

#[derive(Clone, Debug, Deserialize, salvo::oapi::ToSchema)]
pub(super) struct AdminCreateRealmRequest {
    #[serde(default)]
    title: String,
    #[serde(default)]
    topic: Option<String>,
    #[serde(default)]
    discoverability: Option<String>,
    #[serde(default, rename = "default_join_rule")]
    default_join_rule: Option<String>,
    #[serde(default)]
    is_encrypted: bool,
    realm_class: String,
}

#[endpoint(
    operation_id = "ck.extension.soland.admin.realm.create",
    tags("admin"),
    summary = "Create a Realm through the canonical operation pipeline"
)]
#[tracing::instrument(skip_all, fields(op = "ck.extension.soland.admin.realm.create"))]
pub(super) async fn admin_create_realm(
    aa: AuthArgs,
    body: JsonBody<AdminCreateRealmRequest>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<Value> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let body = body.into_inner();
    let title = body.title.trim();
    if title.is_empty() {
        return Err(AppError::invalid_param("title is required"));
    }
    if !matches!(
        body.realm_class.as_str(),
        "principal_control" | "collaboration"
    ) {
        return Err(AppError::invalid_param(
            "realm_class must be principal_control or collaboration",
        ));
    }
    let discoverability = body
        .discoverability
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or("invite_only");
    if !matches!(discoverability, "public" | "invite_only" | "private") {
        return Err(AppError::invalid_param(
            "discoverability must be public, invite_only, or private",
        ));
    }
    let realm_id = ids::generate_realm_id();
    let realm_scope = RealmId::new(realm_id.clone())
        .map_err(|error| AppError::invalid_param(format!("realm_id: {error}")))?;
    let mut object = json!({
        "id": realm_id,
        "title": title,
        "summary": body.topic.filter(|value| !value.trim().is_empty()),
        "default_discoverability": discoverability,
        "default_join_rule": body.default_join_rule.unwrap_or_else(|| "invite".to_owned()),
        "history_visibility": "joined",
        "encryption_profile": if body.is_encrypted { "mls_rfc9420" } else { "plaintext" },
        "realm_class": body.realm_class,
        "created_by": session.actor.clone(),
    });
    let payload = json!({
        "object": object,
        "sender": session.actor.clone(),
    });
    let op_id = OperationId::new(ids::generate_operation_id())
        .map_err(|error| AppError::invalid_param(format!("operation_id: {error}")))?;
    let operation = Operation::create(op_id, realm_scope, kinds::CK_REALM_CREATE, payload);
    accept_local_operations(state, &session.actor, std::slice::from_ref(&operation))
        .await
        .map_err(|reason| AppError::new(ErrorCode::FailedPrecondition, reason.to_owned()))?;
    json_ok(admin_get_realm_item(state, &realm_id).await?)
}

#[endpoint(
    operation_id = "ck.extension.soland.admin.realm.get",
    tags("admin"),
    summary = "Read a Realm security-boundary admin row"
)]
#[tracing::instrument(skip_all, fields(op = "ck.extension.soland.admin.realm.get"))]
pub(super) async fn admin_get_realm(
    realm_id: PathParam<String>,
    depot: &mut Depot,
) -> JsonResult<Value> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let realm_id = realm_id.into_inner();
    json_ok(admin_get_realm_item(state, &realm_id).await?)
}

#[endpoint(
    operation_id = "ck.extension.soland.admin.realm.delete",
    tags("admin"),
    summary = "Destroy a Realm through the canonical operation pipeline"
)]
#[tracing::instrument(skip_all, fields(op = "ck.extension.soland.admin.realm.delete"))]
pub(super) async fn admin_delete_realm(
    aa: AuthArgs,
    realm_id: PathParam<String>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<Value> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let realm_id = realm_id.into_inner();
    let realm_scope = RealmId::new(realm_id.clone())
        .map_err(|error| AppError::invalid_param(format!("realm_id: {error}")))?;
    admin_get_realm_item(state, &realm_id).await?;
    let payload = json!({
        "sender": session.actor.clone(),
    });
    let op_id = OperationId::new(ids::generate_operation_id())
        .map_err(|error| AppError::invalid_param(format!("operation_id: {error}")))?;
    let operation = Operation::create(op_id, realm_scope, kinds::CK_REALM_DESTROY, payload);
    accept_local_operations(state, &session.actor, std::slice::from_ref(&operation))
        .await
        .map_err(|reason| AppError::new(ErrorCode::FailedPrecondition, reason.to_owned()))?;
    json_ok(json!({ "realm_id": realm_id, "deleted": true }))
}

#[endpoint(
    operation_id = "ck.extension.soland.admin.realm.members",
    tags("admin"),
    summary = "List Realm members for the admin surface"
)]
#[tracing::instrument(skip_all, fields(op = "ck.extension.soland.admin.realm.members"))]
pub(super) async fn admin_list_realm_members(
    realm_id: PathParam<String>,
    depot: &mut Depot,
) -> JsonResult<Vec<Value>> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let realm_id = realm_id.into_inner();
    json_ok(admin_realm_member_items(state, &realm_id).await?)
}

async fn admin_actor_items(state: &AppState) -> Vec<Value> {
    demo_actors(state)
        .await
        .into_iter()
        .map(|mut actor| {
            if let Some(object) = actor.as_object_mut() {
                object.insert("kind".to_owned(), json!("actor"));
            }
            actor
        })
        .collect()
}

async fn admin_realm_items(state: &AppState) -> Vec<Value> {
    let meta: BTreeMap<String, _> = state
        .persistence
        .realm_meta()
        .list()
        .await
        .unwrap_or_default()
        .into_iter()
        .collect();
    // Snapshot the Realm registry under lock, then drop it: downstream
    // helpers (`flow_projection_for_realm` → plaintext-service policy)
    // reach back into `state.realms`, and `Mutex` is non-reentrant — holding
    // the guard across the map closure deadlocks on the second resource pass.
    let realm_snapshot: Vec<RealmDirectoryEntry> = {
        let realms = state.realms.lock().expect("realms lock");
        realms
            .search(Default::default())
            .into_iter()
            .cloned()
            .collect()
    };
    let mut items = Vec::new();
    for realm in realm_snapshot {
        let realm_id = realm.realm_id.as_str().to_owned();
        items.push(admin_realm_item_value(state, realm, meta.get(&realm_id).cloned()).await);
    }
    items
}

pub(super) async fn admin_get_realm_item(
    state: &AppState,
    realm_id: &str,
) -> Result<Value, AppError> {
    let realm_id_value = RealmId::new(realm_id.to_owned())
        .map_err(|error| AppError::invalid_param(format!("invalid realm_id: {error}")))?;
    let realm = {
        let realms = state.realms.lock().expect("realms lock");
        realms.get(&realm_id_value).cloned()
    }
    .ok_or_else(|| AppError::not_found("realm not found"))?;
    let realm_meta = state
        .persistence
        .realm_meta()
        .get(realm_id)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    Ok(admin_realm_item_value(state, realm, realm_meta).await)
}

pub(super) async fn admin_realm_member_items(
    state: &AppState,
    realm_id: &str,
) -> Result<Vec<Value>, AppError> {
    let realm_id_value = RealmId::new(realm_id.to_owned())
        .map_err(|error| AppError::invalid_param(format!("invalid realm_id: {error}")))?;
    let members = {
        let realms = state.realms.lock().expect("realms lock");
        realms.get(&realm_id_value).map(|realm| {
            realm
                .members
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
        })
    }
    .ok_or_else(|| AppError::not_found("realm not found"))?;
    let realm_meta = state
        .persistence
        .realm_meta()
        .get(realm_id)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    let owner = realm_meta.as_ref().map(|meta| meta.owner.as_str());
    let joined_at = realm_meta.as_ref().map(|meta| meta.created_at.to_rfc3339());
    Ok(members
        .into_iter()
        .map(|actor_id| {
            json!({
                "actor_id": actor_id,
                "membership": "join",
                "role": if owner == Some(actor_id.as_str()) { "owner" } else { "member" },
                "joined_at": joined_at,
            })
        })
        .collect())
}

async fn admin_realm_item_value(
    state: &AppState,
    realm: RealmDirectoryEntry,
    realm_meta: Option<RealmMetaRecord>,
) -> Value {
    let realm_id = realm.realm_id.as_str().to_owned();
    let flow =
        flow_projection_for_realm(state, &realm_id, &realm.name, realm.description.as_deref())
            .await;
    json!({
        "kind": "realm",
        "id": realm_id,
        "flow": flow,
        "flow_id": flow_id_from_realm_id(&realm_id),
        "realm_id": realm_id,
        "title": realm.name,
        "topic": realm.description,
        "category": realm.category,
        "tags": realm.tags,
        "public": realm.public,
        "member_count": realm.members.len(),
        "members": realm.members.iter().map(ToString::to_string).collect::<Vec<_>>(),
        "created_by": realm_meta.as_ref().map(|meta| meta.owner.clone()),
        "discoverability": realm_meta.as_ref().map(|meta| meta.discoverability.clone()),
        "history_visibility": realm_meta.as_ref().map(|meta| meta.history_visibility.clone()),
        "is_encrypted": realm_meta
            .as_ref()
            .and_then(|meta| meta.encryption_profile.as_deref())
            .is_some_and(|profile| profile != "plaintext"),
        "is_blocked": realm_meta.as_ref().is_some_and(|meta| meta.deleted),
        "plaintext_visible_services": realm_meta
            .as_ref()
            .map(|meta| meta.plaintext_visible_services.iter().cloned().collect::<Vec<_>>())
            .unwrap_or_default(),
        "deleted": realm_meta.as_ref().is_some_and(|meta| meta.deleted),
        "created_at": realm_meta.as_ref().map(|meta| meta.created_at),
        "updated_at": realm_meta.as_ref().map(|meta| meta.updated_at),
    })
}

fn admin_space_container_items(state: &AppState) -> Vec<Value> {
    let member_counts: BTreeMap<String, usize> = {
        let realms = state.realms.lock().expect("realms lock");
        realms
            .search(Default::default())
            .into_iter()
            .map(|realm| (realm.realm_id.as_str().to_owned(), realm.members.len()))
            .collect()
    };
    let projection = match state.projection.lock() {
        Ok(guard) => guard,
        Err(_) => return Vec::new(),
    };
    projection
        .space_containers
        .values()
        .map(|container| {
            json!({
                "id": container.container_space_id,
                "name": container.title,
                "realm_id": container.realm_id,
                "kind": container.kind,
                "member_count": member_counts.get(&container.realm_id).copied().unwrap_or_default(),
                "health": container.state.as_str(),
                "created_at": container.created_at,
                "parent_space_id": container.parent_ref,
            })
        })
        .collect()
}

async fn admin_device_items(state: &AppState) -> Vec<Value> {
    state
        .persistence
        .devices()
        .list()
        .await
        .map(|devices| {
            devices
                .into_iter()
                .map(|device| {
                    let mut value = device_inventory_to_json(&device);
                    if let Some(object) = value.as_object_mut() {
                        object.insert("kind".to_owned(), json!("device"));
                    }
                    value
                })
                .collect()
        })
        .unwrap_or_else(|_| {
            BTreeMap::<String, BTreeMap<String, Value>>::new()
                .iter()
                .flat_map(|(actor, devices)| {
                    devices.iter().map(move |(device_id, device)| {
                        json!({
                            "kind": "device",
                            "actor": actor,
                            "device_id": device_id,
                            "payload": device,
                        })
                    })
                })
                .collect()
        })
}

fn admin_capability_items(state: &AppState) -> Vec<Value> {
    // Same non-reentrant-lock concern as `admin_realm_items` — snapshot the
    // Realm list under lock, drop the guard, then call into authz.
    let realm_snapshot: Vec<RealmDirectoryEntry> = {
        let realms = state.realms.lock().expect("realms lock");
        realms
            .search(Default::default())
            .into_iter()
            .cloned()
            .collect()
    };
    realm_snapshot
        .into_iter()
        .flat_map(|realm| state.authz.grants_in_realm(realm.realm_id.as_str()))
        .map(|grant| json!(grant))
        .collect()
}

async fn admin_federation_items(state: &AppState) -> Vec<Value> {
    state
        .persistence
        .federation_operations()
        .snapshot_all()
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|operation| {
            let projected = projection_event_from_operation(&operation, None);
            json!({
                "kind": "federation_operation",
                "operation_id": operation.operation_id,
                "realm_id": operation.realm_id,
                "operation_type": operation.operation_type,
                "canonical_kind": kinds::canonical_kind_string(&operation),
                "flow_id": flow_id_for_projection_event(&projected),
                "track": discussion_track_for_projection_event(
                    &projected,
                    flow_id_for_projection_event(&projected).as_deref(),
                ),
                "digest": operation.operation_digest().ok(),
                "created_at": operation.created_at,
            })
        })
        .collect()
}

/// Snapshot of the in-memory applet registry maintained
/// by `reducer::ProjectionState::applets`. Each row is one applet
/// identified by `service_did`, with the latest registration metadata
/// (namespace, capabilities) and the most recent manifest (from
/// `ck.applet.discovery`). Empty until a `ck.applet.registration` or
/// `ck.applet.discovery` event has been accepted.
fn admin_applet_items(state: &AppState) -> Vec<Value> {
    let proj = match state.projection.lock() {
        Ok(guard) => guard,
        Err(_) => return Vec::new(),
    };
    proj.applets
        .values()
        .map(|applet| {
            json!({
                "service_did": applet.service_did,
                "namespace": applet.namespace,
                "manifest": applet.manifest,
                "capabilities": applet.capabilities,
                "registered_at": applet.registered_at.to_rfc3339(),
                "updated_at": applet.updated_at.to_rfc3339(),
            })
        })
        .collect()
}

/// Snapshot of the in-memory agent registry maintained
/// by `reducer::ProjectionState::agents`. One row per agent_id, with
/// the latest `ck.agent.endpoint` metadata.
fn admin_agent_items(state: &AppState) -> Vec<Value> {
    let proj = match state.projection.lock() {
        Ok(guard) => guard,
        Err(_) => return Vec::new(),
    };
    proj.agents
        .values()
        .map(|agent| {
            json!({
                "agent_id": agent.agent_id,
                "protocol": agent.protocol,
                "endpoint_url": agent.endpoint_url,
                "registered_at": agent.registered_at.to_rfc3339(),
                "updated_at": agent.updated_at.to_rfc3339(),
            })
        })
        .collect()
}

async fn admin_invite_items(state: &AppState) -> Vec<Value> {
    state
        .persistence
        .realm_invites()
        .snapshot_all()
        .await
        .unwrap_or_default()
        .iter()
        .map(|invite| {
            json!({
                "kind": "invite_token",
                "invite_id": invite.invite_id,
                "realm_id": invite.realm_id,
                "inviter": invite.inviter,
                "invitee": invite.invitee,
                "token_hash": format!("sha256:{}", sha256_hex(invite.invite_token.as_bytes())),
                "status": invite.status,
                "expires_at": invite.expires_at,
                "created_at": invite.created_at,
            })
        })
        .collect()
}

async fn admin_policy_items(state: &AppState) -> Vec<Value> {
    state
        .persistence
        .policy_documents()
        .snapshot_all()
        .await
        .unwrap_or_default()
        .iter()
        .map(|policy| json!(policy_document_to_response(policy)))
        .collect()
}

async fn admin_media_items(state: &AppState) -> Vec<Value> {
    state
        .persistence
        .blobs()
        .snapshot_all()
        .await
        .unwrap_or_default()
        .iter()
        .map(|blob| {
            json!({
                "kind": "media",
                "media_type": blob.media_type,
                "filename": blob.filename,
                "realm_id": blob.realm_id,
                "encrypted": blob.encryption.is_some(),
                "uploaded_by": blob.uploaded_by,
                "size": blob.size_bytes,
                "created_at": blob.created_at,
            })
        })
        .collect()
}
