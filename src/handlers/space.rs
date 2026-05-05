//! Space lifecycle + membership handlers.
//!
//! Surfaces:
//! - `POST   /api/v1/spaces` — create a space, optionally invite peers
//! - `POST   /api/v1/spaces/{space_id}/members` — owner adds a member
//! - `DELETE /api/v1/spaces/{space_id}/members/{member_did}` — owner removes a member
//! - `DELETE /api/v1/spaces/{space_id}` — owner soft-deletes the space
//! - `GET    /api/v1/spaces/{space_id}/export` — full event log + projection dump
//!
//! Visibility / membership query helpers (`space_has_member`, `space_visible_to`,
//! `space_id_accessible`, …) intentionally stay in `mod.rs` for now because they
//! are used by every other domain (federation, message, blob, directory, …).
//! They will move here once the directory layer is also extracted.

use chrono::Duration;
use contrix_sdk::{Did, SpaceId, SpaceSearchEntry};
use salvo::{http::StatusCode, prelude::*};
use serde_json::json;

use crate::{
    ids,
    state::{AppState, SpaceInviteRecord, SpaceMetaRecord},
    wire::{
        AddSpaceMemberRequest, CreateSpaceRequest, SpaceLifecycleResponse,
    },
};

use super::{
    append_audit_log, auth_or_render, generate_invite_token, is_valid_discoverability, now,
    record_space_lifecycle_operation, render_error, space_id_accessible, validate_did,
    validate_space_id,
};

#[handler]
pub async fn create_space(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(session) = auth_or_render(state, req, res) else {
        return;
    };
    let body = match req.parse_json::<CreateSpaceRequest>().await {
        Ok(body) => body,
        Err(_) => {
            render_error(
                res,
                StatusCode::BAD_REQUEST,
                "bad_json",
                "invalid create space request",
            );
            return;
        }
    };
    if body.title.trim().is_empty() {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "missing_param",
            "title is required",
        );
        return;
    }
    for invitee in &body.invitees {
        if validate_did(invitee).is_err() {
            render_error(
                res,
                StatusCode::BAD_REQUEST,
                "invalid_param",
                "invalid invitee did",
            );
            return;
        }
    }
    for service_did in &body.plaintext_visible_services {
        if validate_did(service_did).is_err() {
            render_error(
                res,
                StatusCode::BAD_REQUEST,
                "invalid_param",
                "invalid plaintext_visible_services did",
            );
            return;
        }
    }
    let discoverability = body.discoverability.clone().unwrap_or_else(|| {
        if body.public {
            "public".to_owned()
        } else {
            "invite_only".to_owned()
        }
    });
    if !is_valid_discoverability(&discoverability) {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "invalid discoverability",
        );
        return;
    }
    let invitees = body.invitees.clone();
    let plaintext_visible_services = body.plaintext_visible_services.clone();
    let space_id = ids::generate_space_id();
    let mut entry = SpaceSearchEntry::new(
        SpaceId::new(space_id.clone()).expect("generated valid space id"),
        body.title.trim(),
    );
    entry.description = body.summary;
    entry.public = discoverability == "public";
    entry
        .members
        .insert(Did::new(session.actor.clone()).expect("session did is valid"));

    state.spaces.lock().expect("spaces lock").upsert(entry);
    state.space_meta.lock().expect("space meta lock").insert(
        space_id.clone(),
        SpaceMetaRecord {
            owner: session.actor.clone(),
            deleted: false,
            discoverability: discoverability.clone(),
            plaintext_visible_services: plaintext_visible_services.iter().cloned().collect(),
            created_at: now(),
            updated_at: now(),
        },
    );
    let invite_records: Vec<_> = invitees
        .iter()
        .map(|invitee| {
            let invite_id = ids::generate_invite_id();
            let invite_token = generate_invite_token(&invite_id, &space_id, invitee);
            SpaceInviteRecord {
                invite_id,
                space_id: space_id.clone(),
                inviter: session.actor.clone(),
                invitee: Some(invitee.clone()),
                invite_token,
                status: "pending".to_owned(),
                expires_at: Some(now() + Duration::days(7)),
                created_at: now(),
            }
        })
        .collect();
    if !invite_records.is_empty() {
        let mut invite_store = state.space_invites.lock().expect("space invites lock");
        for invite in &invite_records {
            invite_store.insert(invite.invite_id.clone(), invite.clone());
        }
    }
    if let Err(error) = record_space_lifecycle_operation(
        state,
        &session.actor,
        &space_id,
        json!({
            "action": "create",
            "owner": session.actor.clone(),
            "members": [],
            "invitees": invitees,
            "invite_ids": invite_records
                .iter()
                .map(|invite| invite.invite_id.clone())
                .collect::<Vec<_>>(),
            "public": discoverability == "public",
            "discoverability": discoverability,
            "plaintext_visible_services": plaintext_visible_services,
        }),
    ) {
        render_error(
            res,
            StatusCode::CONFLICT,
            "repo_conflict",
            &error.to_string(),
        );
        return;
    }

    res.status_code(StatusCode::CREATED);
    append_audit_log(
        state,
        Some(&session.actor),
        "space.create",
        json!({"space_id": space_id.clone()}),
        "accepted",
    );
    render_space_lifecycle(state, res, &space_id);
}

#[handler]
pub async fn add_space_member(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(session) = auth_or_render(state, req, res) else {
        return;
    };
    let Some(space_id) = req.param::<String>("space_id") else {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "missing_param",
            "space_id is required",
        );
        return;
    };
    if !space_owner_matches(state, &space_id, &session.actor) {
        render_error(
            res,
            StatusCode::FORBIDDEN,
            "capability_denied",
            "only the space owner can add members",
        );
        return;
    }
    let body = match req.parse_json::<AddSpaceMemberRequest>().await {
        Ok(body) => body,
        Err(_) => {
            render_error(
                res,
                StatusCode::BAD_REQUEST,
                "bad_json",
                "invalid add member request",
            );
            return;
        }
    };
    if validate_did(&body.member).is_err() {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "invalid member did",
        );
        return;
    }
    let Ok(space_id_value) = SpaceId::new(space_id.clone()) else {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "invalid space_id",
        );
        return;
    };
    let mut spaces = state.spaces.lock().expect("spaces lock");
    let Some(mut entry) = spaces.get(&space_id_value).cloned() else {
        render_error(res, StatusCode::NOT_FOUND, "not_found", "not found");
        return;
    };
    entry
        .members
        .insert(Did::new(body.member.clone()).expect("validated did"));
    spaces.upsert(entry);
    drop(spaces);
    touch_space(state, &space_id);
    if let Err(error) = record_space_lifecycle_operation(
        state,
        &session.actor,
        &space_id,
        json!({
            "action": "member.add",
            "member": body.member.clone(),
            "membership": "join",
        }),
    ) {
        render_error(
            res,
            StatusCode::CONFLICT,
            "repo_conflict",
            &error.to_string(),
        );
        return;
    }
    append_audit_log(
        state,
        Some(&session.actor),
        "space.member.add",
        json!({"space_id": space_id.clone(), "member": body.member}),
        "accepted",
    );
    render_space_lifecycle(state, res, &space_id);
}

#[handler]
pub async fn remove_space_member(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(session) = auth_or_render(state, req, res) else {
        return;
    };
    let Some(space_id) = req.param::<String>("space_id") else {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "missing_param",
            "space_id is required",
        );
        return;
    };
    let Some(member_did) = req.param::<String>("member_did") else {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "missing_param",
            "member_did is required",
        );
        return;
    };
    if !space_owner_matches(state, &space_id, &session.actor) {
        render_error(
            res,
            StatusCode::FORBIDDEN,
            "capability_denied",
            "only the space owner can remove members",
        );
        return;
    }
    if member_did == session.actor {
        render_error(
            res,
            StatusCode::CONFLICT,
            "conflict",
            "owner cannot remove self",
        );
        return;
    }
    let Ok(space_id_value) = SpaceId::new(space_id.clone()) else {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "invalid space_id",
        );
        return;
    };
    let Ok(member) = Did::new(member_did) else {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "invalid member did",
        );
        return;
    };
    let mut spaces = state.spaces.lock().expect("spaces lock");
    let Some(mut entry) = spaces.get(&space_id_value).cloned() else {
        render_error(res, StatusCode::NOT_FOUND, "not_found", "not found");
        return;
    };
    entry.members.remove(&member);
    spaces.upsert(entry);
    drop(spaces);
    touch_space(state, &space_id);
    if let Err(error) = record_space_lifecycle_operation(
        state,
        &session.actor,
        &space_id,
        json!({
            "action": "member.remove",
            "member": member.to_string(),
            "membership": "leave",
        }),
    ) {
        render_error(
            res,
            StatusCode::CONFLICT,
            "repo_conflict",
            &error.to_string(),
        );
        return;
    }
    append_audit_log(
        state,
        Some(&session.actor),
        "space.member.remove",
        json!({"space_id": space_id.clone(), "member": member.to_string()}),
        "accepted",
    );
    render_space_lifecycle(state, res, &space_id);
}

#[handler]
pub async fn delete_space(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(session) = auth_or_render(state, req, res) else {
        return;
    };
    let Some(space_id) = req.param::<String>("space_id") else {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "missing_param",
            "space_id is required",
        );
        return;
    };
    if !space_owner_matches(state, &space_id, &session.actor) {
        render_error(
            res,
            StatusCode::FORBIDDEN,
            "capability_denied",
            "only the space owner can delete the space",
        );
        return;
    }
    {
        let mut meta = state.space_meta.lock().expect("space meta lock");
        let Some(record) = meta.get_mut(&space_id) else {
            render_error(res, StatusCode::NOT_FOUND, "not_found", "not found");
            return;
        };
        record.deleted = true;
        record.updated_at = now();
    }
    if let Err(error) = record_space_lifecycle_operation(
        state,
        &session.actor,
        &space_id,
        json!({
            "action": "delete",
            "deleted": true,
        }),
    ) {
        render_error(
            res,
            StatusCode::CONFLICT,
            "repo_conflict",
            &error.to_string(),
        );
        return;
    }
    append_audit_log(
        state,
        Some(&session.actor),
        "space.delete",
        json!({"space_id": space_id.clone()}),
        "accepted",
    );
    render_space_lifecycle(state, res, &space_id);
}

#[handler]
pub async fn export_space(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(session) = auth_or_render(state, req, res) else {
        return;
    };
    let Some(space_id) = req.param::<String>("space_id") else {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "missing_param",
            "space_id is required",
        );
        return;
    };
    if validate_space_id(&space_id).is_err() {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "invalid space_id",
        );
        return;
    }
    if !space_id_accessible(state, &space_id, Some(&session)) {
        render_error(res, StatusCode::NOT_FOUND, "not_found", "not found");
        return;
    }
    let operations = match state.repo.sync_space_operations(&space_id, None, 500) {
        Ok(page) => page.items,
        Err(error) => {
            render_error(
                res,
                StatusCode::CONFLICT,
                "repo_conflict",
                &error.to_string(),
            );
            return;
        }
    };
    let events = state
        .projection_events
        .lock()
        .expect("projection events lock")
        .iter()
        .filter(|event| event.space_id == space_id)
        .map(|event| {
            json!({
                "event_id": event.event_id,
                "event_type": event.event_type,
                "operation_type": event.operation_type,
                "operation_id": event.operation_id,
                "sender": event.sender,
                "payload": event.payload,
                "created_at": event.created_at,
            })
        })
        .collect::<Vec<_>>();
    res.render(Json(json!({
        "schema": "cx.export.space.v1",
        "space_id": space_id,
        "generated_at": now(),
        "operations": operations,
        "events": events,
    })));
}

// ── Helpers shared with the parent module ───────────────────────────────────
//
// Each is re-exported from `crate::handlers::*` so existing callers in `mod.rs`
// (e.g. `touch_space` from the projection writer at line ~12670) keep working.

pub fn render_space_lifecycle(state: &AppState, res: &mut Response, space_id: &str) {
    let Ok(space_id_value) = SpaceId::new(space_id.to_owned()) else {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "invalid space_id",
        );
        return;
    };
    let spaces = state.spaces.lock().expect("spaces lock");
    let meta = state.space_meta.lock().expect("space meta lock");
    let Some(record) = meta.get(space_id) else {
        render_error(res, StatusCode::NOT_FOUND, "not_found", "not found");
        return;
    };
    let members = spaces
        .get(&space_id_value)
        .map(|space| space.members.iter().map(ToString::to_string).collect())
        .unwrap_or_default();
    res.render(Json(SpaceLifecycleResponse {
        ok: true,
        space_id: space_id.to_owned(),
        owner: record.owner.clone(),
        members,
        deleted: record.deleted,
    }));
}

pub fn space_owner_matches(state: &AppState, space_id: &str, actor: &str) -> bool {
    state
        .space_meta
        .lock()
        .expect("space meta lock")
        .get(space_id)
        .is_some_and(|record| !record.deleted && record.owner == actor)
}

pub fn touch_space(state: &AppState, space_id: &str) {
    if let Some(record) = state
        .space_meta
        .lock()
        .expect("space meta lock")
        .get_mut(space_id)
    {
        record.updated_at = now();
    }
}
