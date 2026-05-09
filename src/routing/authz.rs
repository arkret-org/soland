//! Authorization HTTP surface.
//!
//! Surfaces:
//! - `POST /api/v1/authz/check`             — evaluate one (actor, action, resource)
//! - `GET  /api/v1/authz/effective-grants`  — direct grants visible to a subject
//! - `POST /api/v1/authz/grants`            — owner-issued grant
//! - `DELETE /api/v1/authz/grants/{grant_id}` — revoke
//! - `GET  /api/v1/authz/invites`           — pending invites visible to the actor
//!
//! The actual authorisation engine lives in `src/authz.rs` (the `state.authz`
//! field is shared). Stream-B in `_todos.md` covers the still-open work:
//! schema alignment (B-02 / B-04 / B-05), the 11 missing constraint types,
//! the 10 condition.kind types, the capability lattice, and grant/invite/policy
//! lifecycle integration.

use salvo::{http::StatusCode, prelude::*};
use serde_json::json;

use crate::{
    state::AppState,
    wire::{
        AuthzCheckRequest, AuthzCheckResponse, CreateGrantRequest, EffectiveGrantsResponse,
        InvitesResponse,
    },
};

use super::{
    append_audit_log, auth_or_render, facet_names_from_value, now, query_param, render_error,
};

#[endpoint]
pub async fn authz_check(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let body = match req.parse_json::<AuthzCheckRequest>().await {
        Ok(body) => body,
        Err(_) => {
            render_error(
                res,
                StatusCode::BAD_REQUEST,
                "bad_json",
                "invalid authz check request",
            );
            return;
        }
    };
    // Extract space_id from resource
    // Resource MUST be either a typed `cx:*:<uuid>` string (per spec M-15) or
    // an object {"kind":"<kind>","space_id":"<id>"}. The legacy bare
    // `space:<id>` form is no longer accepted; downstream code receives the
    // resource string verbatim and treats the matching `space_id` as the same
    // typed id.
    let (resource_str, space_id, resource_facets) = if let Some(s) = body.resource.as_str() {
        (s.to_owned(), s.to_owned(), Vec::new())
    } else if let Some(obj) = body.resource.as_object() {
        let kind = obj.get("kind").and_then(|v| v.as_str()).unwrap_or("space");
        let entity_id = obj
            .get("entity_id")
            .or_else(|| (kind == "entity").then(|| obj.get("id")).flatten())
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned);
        let projected_entity = entity_id.as_deref().and_then(|entity_id| {
            state
                .projection
                .lock()
                .expect("projection lock")
                .entities
                .get(entity_id)
                .cloned()
        });
        let sid = obj
            .get("space_id")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned)
            .or_else(|| {
                projected_entity
                    .as_ref()
                    .map(|entity| entity.space_id.clone())
            })
            .or_else(|| {
                (kind == "space")
                    .then(|| {
                        obj.get("id")
                            .and_then(|v| v.as_str())
                            .map(ToOwned::to_owned)
                    })
                    .flatten()
            })
            .unwrap_or_default();
        let resource = entity_id
            .as_ref()
            .map(|entity_id| format!("entity:{entity_id}"))
            .unwrap_or_else(|| format!("{kind}:{sid}"));
        let facets = facet_names_from_value(obj.get("facets"))
            .into_iter()
            .chain(
                projected_entity
                    .as_ref()
                    .filter(|_| obj.get("facets").is_none())
                    .map(|entity| entity.facets.clone())
                    .unwrap_or_default(),
            )
            .collect();
        (resource, sid, facets)
    } else {
        (String::new(), String::new(), Vec::new())
    };
    // Look up space owner and members
    let (owner, members) = {
        let owner = state
            .persistence
            .space_meta()
            .get(&space_id)
            .ok()
            .flatten()
            .map(|m| m.owner);
        let spaces = state.spaces.lock().expect("spaces lock");
        let members = spaces
            .get(
                &contrix_sdk::SpaceId::new(space_id.clone())
                    .unwrap_or_else(|_| contrix_sdk::SpaceId::new("cx:space:01904100-0000-7000-8000-ec4565bea379").unwrap()),
            )
            .map(|s| s.members.iter().map(|m| m.to_string()).collect::<Vec<_>>())
            .unwrap_or_default();
        (owner, members)
    };
    let result = state.authz.check(
        &body.actor,
        &body.action,
        &resource_str,
        &space_id,
        owner.as_deref(),
        &members,
        &resource_facets,
    );
    res.render(Json(AuthzCheckResponse {
        allowed: result.allowed,
        reason_code: (!result.allowed).then(|| result.reason.clone()),
        reason: if result.allowed {
            None
        } else {
            result.reason_detail.clone()
        },
        grants: result
            .grants
            .iter()
            .map(|g| {
                json!({
                    "grant_id": g.grant_id,
                    "subject": g.subject,
                    "actions": g.actions,
                    "resource": g.resource
                })
            })
            .collect(),
        obligations: Vec::new(),
    }));
}

#[endpoint]
pub async fn effective_grants(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let subject = query_param(req, "subject").unwrap_or_else(|| "did:web:alice.example".to_owned());
    let space_id = query_param(req, "space_id").unwrap_or_else(|| "*".to_owned());
    let grants = if space_id == "*" {
        // Return grants across all spaces
        state
            .persistence
            .space_meta()
            .list()
            .unwrap_or_default()
            .into_iter()
            .flat_map(|(sid, _)| state.authz.grants_for_subject(&subject, &sid))
            .map(|g| {
                json!({
                    "grant_id": g.grant_id,
                    "subject": g.subject,
                    "actions": g.actions,
                    "resources": [{"kind": "space", "space_id": g.space_id}]
                })
            })
            .collect::<Vec<_>>()
    } else {
        state
            .authz
            .grants_for_subject(&subject, &space_id)
            .iter()
            .map(|g| {
                json!({
                    "grant_id": g.grant_id,
                    "subject": g.subject,
                    "actions": g.actions,
                    "resources": [{"kind": "space", "space_id": g.space_id}]
                })
            })
            .collect::<Vec<_>>()
    };
    // Include default member grants if the user is a member of any space
    let default_grants = if grants.is_empty() {
        vec![json!({
            "subject": subject,
            "actions": ["space.read", "directory.search", "repo.read"],
            "resources": [{"kind": "space", "space_id": "*"}]
        })]
    } else {
        Vec::new()
    };
    let all_grants = [grants, default_grants].concat();
    res.render(Json(EffectiveGrantsResponse {
        grants: all_grants,
        state_hash: Some(
            "sha256:0000000000000000000000000000000000000000000000000000000000000000".to_owned(),
        ),
        evaluated_at: now(),
    }));
}

// ── Grant CRUD ──

#[endpoint]
pub async fn create_grant(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(session) = auth_or_render(state, req, res) else {
        return;
    };
    let body = match req.parse_json::<CreateGrantRequest>().await {
        Ok(body) => body,
        Err(_) => {
            render_error(
                res,
                StatusCode::BAD_REQUEST,
                "bad_json",
                "invalid grant request",
            );
            return;
        }
    };
    let constraints = body
        .constraints
        .into_iter()
        .map(|v| crate::authz::Constraint {
            constraint_type: v
                .get("type")
                .and_then(|t| t.as_str())
                .unwrap_or("unknown")
                .to_owned(),
            value: v,
        })
        .collect();
    let grant = state.authz.create_grant(
        body.space_id,
        session.actor.clone(),
        body.subject,
        body.resource,
        body.actions,
        constraints,
    );
    append_audit_log(
        state,
        Some(&session.actor),
        "authz.grant.create",
        json!({"grant_id": grant.grant_id.clone(), "subject": grant.subject.clone()}),
        "accepted",
    );
    res.render(Json(json!({
        "grant_id": grant.grant_id,
        "subject": grant.subject,
        "actions": grant.actions,
        "resource": grant.resource,
        "created_at": grant.created_at.to_rfc3339()
    })));
}

#[endpoint]
pub async fn revoke_grant(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(session) = auth_or_render(state, req, res) else {
        return;
    };
    let Some(grant_id) = req.param::<String>("grant_id") else {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "missing_param",
            "grant_id is required",
        );
        return;
    };
    if state.authz.revoke_grant(&grant_id) {
        append_audit_log(
            state,
            Some(&session.actor),
            "authz.grant.revoke",
            json!({"grant_id": grant_id.clone()}),
            "accepted",
        );
        res.render(Json(json!({ "revoked": true, "grant_id": grant_id })));
    } else {
        render_error(res, StatusCode::NOT_FOUND, "not_found", "grant not found");
    }
}

#[endpoint]
pub async fn invites(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(session) = auth_or_render(state, req, res) else {
        return;
    };
    let now = now();
    let invite_list = state
        .persistence
        .space_invites()
        .snapshot_all()
        .unwrap_or_default()
        .into_iter()
        .filter(|invite| {
            invite.status == "pending"
                && invite
                    .invitee
                    .as_deref()
                    .is_some_and(|invitee| invitee == session.actor)
                && invite.expires_at.is_none_or(|expires_at| expires_at > now)
        })
        .map(|invite| {
            json!({
                "invite_id": invite.invite_id,
                "space_id": invite.space_id,
                "inviter": invite.inviter,
                "invitee": invite.invitee,
                "invite_token": invite.invite_token,
                "status": invite.status,
                "expires_at": invite.expires_at,
                "created_at": invite.created_at,
            })
        })
        .collect();
    res.render(Json(InvitesResponse {
        invites: invite_list,
        next_cursor: None,
    }));
}
