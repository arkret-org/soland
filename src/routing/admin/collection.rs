//! Dev-only admin collection surfaces.
//!
//! Surfaces:
//! - `GET /api/v1/admin/{resource}` — paginated dev snapshot of one of the builtin admin
//!   collections (`actors`, `spaces`, `devices`, `capabilities`, `federation`, `applets`, `agents`,
//!   `reports`, `invite-tokens`, `audit`, `policy`, `media`).
//!
//! Authorization: in `development_mode` any authenticated bearer session
//! reaches the snapshot. In production mode the session actor MUST be listed
//! in `AppConfig::admin_principal_dids` (env `SOLAND_ADMIN_PRINCIPAL_DIDS`)
//! — empty list keeps the gate closed. Further hardening (durable cursor
//! pagination, redaction policy, high-risk audit signing) is tracked under
//! `_todos.md` Q9.

use std::collections::BTreeMap;

use salvo::oapi::extract::{PathParam, QueryParam};
use salvo::prelude::*;
use serde_json::{Value, json};

use super::{
    append_audit_log, demo_actors, device_inventory_to_json, discussion_track_for_projection_event,
    flow_id_for_projection_event, flow_id_from_space_id, flow_projection_for_space,
    policy_document_to_response, projection_event_from_operation, sha256_hex,
};
use crate::error::AppError;
use crate::kinds;
use crate::result::{JsonResult, json_ok};
use crate::routing::system::extract::AuthArgs;
use crate::state::{AppState, RealmDirectoryEntry};

#[endpoint(
    operation_id = "cx.extension.soland.admin.collection",
    tags("admin"),
    summary = "Dev-only paginated admin snapshot of a named collection"
)]
pub(super) async fn admin_collection(
    aa: AuthArgs,
    resource: PathParam<String>,
    limit: QueryParam<usize, false>,
    cursor: QueryParam<String, false>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<Value> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req)?;
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
    if !grant.has_admin_scope(contrix_sdk::admin_scopes::ADMIN_READ) {
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
        "actors" => ("actors", admin_actor_items(state)),
        "spaces" => ("spaces", admin_space_items(state)),
        "devices" => ("devices", admin_device_items(state)),
        "capabilities" => ("capabilities", admin_capability_items(state)),
        "federation" => ("federation", admin_federation_items(state)),
        "applets" => ("applets", admin_applet_items(state)),
        "agents" => ("agents", admin_agent_items(state)),
        "reports" => (
            "reports",
            state
                .persistence
                .moderation()
                .list_reports()
                .unwrap_or_default(),
        ),
        "invite-tokens" => ("invite_tokens", admin_invite_items(state)),
        "audit" => (
            "audit",
            state.persistence.audit().snapshot_all().unwrap_or_default(),
        ),
        "policy" => ("policy", admin_policy_items(state)),
        "media" => ("media", admin_media_items(state)),
        _ => {
            return Err(AppError::not_found("admin resource not found"));
        }
    };
    items.sort_by(|left, right| left.to_string().cmp(&right.to_string()));
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
    );

    let mut body = serde_json::Map::new();
    body.insert("resource".to_owned(), json!(resource));
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

fn admin_actor_items(state: &AppState) -> Vec<Value> {
    demo_actors(state)
        .into_iter()
        .map(|mut actor| {
            if let Some(object) = actor.as_object_mut() {
                object.insert("kind".to_owned(), json!("actor"));
            }
            actor
        })
        .collect()
}

fn admin_space_items(state: &AppState) -> Vec<Value> {
    let meta: BTreeMap<String, _> = state
        .persistence
        .realm_meta()
        .list()
        .unwrap_or_default()
        .into_iter()
        .collect();
    // Snapshot the space registry under lock, then drop it: downstream
    // helpers (`flow_projection_for_space` → `space_allows_plaintext_service`)
    // reach back into `state.realms`, and `Mutex` is non-reentrant — holding
    // the guard across the map closure deadlocks on the second resource pass.
    let space_snapshot: Vec<RealmDirectoryEntry> = {
        let spaces = state.realms.lock().expect("spaces lock");
        spaces
            .search(Default::default())
            .into_iter()
            .cloned()
            .collect()
    };
    space_snapshot
        .into_iter()
        .map(|space| {
            let space_id = space.realm_id.as_str().to_owned();
            let space_meta = meta.get(&space_id);
            let flow = flow_projection_for_space(
                state,
                &space_id,
                &space.name,
                space.description.as_deref(),
            );
            json!({
                "kind": "space",
                "flow": flow,
                "flow_id": flow_id_from_space_id(&space_id),
                "space_id": space_id,
                "title": space.name,
                "summary": space.description,
                "category": space.category,
                "tags": space.tags,
                "public": space.public,
                "members": space.members.iter().map(ToString::to_string).collect::<Vec<_>>(),
                "owner": space_meta.map(|meta| meta.owner.clone()),
                "discoverability": space_meta.map(|meta| meta.discoverability.clone()),
                "plaintext_visible_services": space_meta
                    .map(|meta| meta.plaintext_visible_services.iter().cloned().collect::<Vec<_>>())
                    .unwrap_or_default(),
                "deleted": space_meta.is_some_and(|meta| meta.deleted),
                "created_at": space_meta.map(|meta| meta.created_at),
                "updated_at": space_meta.map(|meta| meta.updated_at),
            })
        })
        .collect()
}

fn admin_device_items(state: &AppState) -> Vec<Value> {
    state
        .persistence
        .devices()
        .list()
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
    // Same non-reentrant-lock concern as `admin_space_items` — snapshot the
    // space list under lock, drop the guard, then call into authz.
    let space_snapshot: Vec<RealmDirectoryEntry> = {
        let spaces = state.realms.lock().expect("spaces lock");
        spaces
            .search(Default::default())
            .into_iter()
            .cloned()
            .collect()
    };
    space_snapshot
        .into_iter()
        .flat_map(|space| state.authz.grants_in_space(space.realm_id.as_str()))
        .map(|grant| json!(grant))
        .collect()
}

fn admin_federation_items(state: &AppState) -> Vec<Value> {
    state
        .persistence
        .federation_operations()
        .snapshot_all()
        .unwrap_or_default()
        .into_iter()
        .map(|operation| {
            let projected = projection_event_from_operation(&operation, None);
            json!({
                "kind": "federation_operation",
                "operation_id": operation.operation_id,
                "space_id": operation.space_id,
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
/// `cx.applet.discovery`). Empty until a `cx.applet.registration` or
/// `cx.applet.discovery` event has been accepted.
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
/// by `reducer::ProjectionState::agents`. One row per agent_did, with
/// the latest `cx.agent.endpoint` metadata.
fn admin_agent_items(state: &AppState) -> Vec<Value> {
    let proj = match state.projection.lock() {
        Ok(guard) => guard,
        Err(_) => return Vec::new(),
    };
    proj.agents
        .values()
        .map(|agent| {
            json!({
                "agent_did": agent.agent_did,
                "protocol": agent.protocol,
                "endpoint_url": agent.endpoint_url,
                "registered_at": agent.registered_at.to_rfc3339(),
                "updated_at": agent.updated_at.to_rfc3339(),
            })
        })
        .collect()
}

fn admin_invite_items(state: &AppState) -> Vec<Value> {
    state
        .persistence
        .space_invites()
        .snapshot_all()
        .unwrap_or_default()
        .iter()
        .map(|invite| {
            json!({
                "kind": "invite_token",
                "invite_id": invite.invite_id,
                "space_id": invite.space_id,
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

fn admin_policy_items(state: &AppState) -> Vec<Value> {
    state
        .persistence
        .policy_documents()
        .snapshot_all()
        .unwrap_or_default()
        .iter()
        .map(|policy| json!(policy_document_to_response(policy)))
        .collect()
}

fn admin_media_items(state: &AppState) -> Vec<Value> {
    state
        .persistence
        .blobs()
        .snapshot_all()
        .unwrap_or_default()
        .iter()
        .map(|blob| {
            json!({
                "kind": "media",
                "media_type": blob.media_type,
                "filename": blob.filename,
                "space_id": blob.space_id,
                "encrypted": blob.encryption.is_some(),
                "uploaded_by": blob.uploaded_by,
                "size": blob.size_bytes,
                "created_at": blob.created_at,
            })
        })
        .collect()
}
