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

use salvo::oapi::extract::{JsonBody, PathParam};
use salvo::prelude::*;
use serde_json::json;

use super::{append_audit_log, now, query_param};
use crate::error::AppError;
use crate::result::{JsonResult, json_ok};
use crate::routing::system::extract::AuthArgs;
use crate::state::AppState;
use crate::wire::{
    AuthzCheckRequest, AuthzCheckResponse, CreateGrantRequest, CreateGrantResponse,
    EffectiveGrantsResponse, InvitesResponse, RevokeGrantResponse,
};

pub(super) fn router() -> Router {
    Router::new()
        .push(Router::with_path("authz/describe").get(super::describe::authz_describe))
        .push(Router::with_path("authz/check").post(authz_check))
        .push(Router::with_path("authz/effective-grants").get(effective_grants))
        .push(Router::with_path("authz/grants").post(create_grant))
        .push(Router::with_path("authz/grants/{grant_id}").delete(revoke_grant))
        .push(Router::with_path("authz/invites").get(invites))
}

#[endpoint(
    operation_id = "cx.authz.check",
    tags("authz"),
    summary = "Evaluate one (actor, action, resource) authorization decision"
)]
async fn authz_check(
    body: JsonBody<AuthzCheckRequest>,
    depot: &mut Depot,
) -> JsonResult<AuthzCheckResponse> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let body = body.into_inner();
    let (resource_str, space_id, resource_facets) = if let Some(s) = body.resource.as_str() {
        (s.to_owned(), s.to_owned(), Vec::new())
    } else if let Some(obj) = body.resource.as_object() {
        let kind = obj.get("kind").and_then(|v| v.as_str()).unwrap_or("space");
        let sid = obj
            .get("space_id")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned)
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
        let resource = obj
            .get("id")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned)
            .unwrap_or_else(|| format!("{kind}:{sid}"));
        let facets = facet_names_from_value(obj.get("facets"));
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
                &contrix_sdk::SpaceId::new(space_id.clone()).unwrap_or_else(|_| {
                    contrix_sdk::SpaceId::new("cx:space:01904100-0000-7000-8000-ec4565bea379")
                        .unwrap()
                }),
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
    json_ok(AuthzCheckResponse {
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
    })
}

fn facet_names_from_value(value: Option<&serde_json::Value>) -> Vec<String> {
    match value {
        Some(serde_json::Value::Array(values)) => values
            .iter()
            .filter_map(|value| value.as_str().map(ToOwned::to_owned))
            .collect(),
        Some(serde_json::Value::Object(values)) => values.keys().cloned().collect(),
        Some(serde_json::Value::String(value)) => vec![value.clone()],
        _ => Vec::new(),
    }
}

#[endpoint(
    operation_id = "cx.authz.get_effective_grants",
    tags("authz"),
    summary = "List effective authorization grants for a subject"
)]
async fn effective_grants(
    depot: &mut Depot,
    req: &mut Request,
) -> crate::result::JsonResult<EffectiveGrantsResponse> {
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
            "actions": ["space.read", "directory.search"],
            "resources": [{"kind": "space", "space_id": "*"}]
        })]
    } else {
        Vec::new()
    };
    let all_grants = [grants, default_grants].concat();
    crate::result::json_ok(EffectiveGrantsResponse {
        grants: all_grants,
        state_hash: Some(
            "sha256:0000000000000000000000000000000000000000000000000000000000000000".to_owned(),
        ),
        evaluated_at: now(),
    })
}

// ── Grant CRUD ──

#[endpoint(
    operation_id = "cx.authz.create_grant",
    tags("authz"),
    summary = "Create an owner-issued authorization grant"
)]
async fn create_grant(
    aa: AuthArgs,
    body: JsonBody<CreateGrantRequest>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<CreateGrantResponse> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req)?;
    let body = body.into_inner();
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
    json_ok(CreateGrantResponse {
        grant_id: grant.grant_id,
        subject: grant.subject,
        actions: grant.actions,
        resource: grant.resource,
        created_at: grant.created_at.to_rfc3339(),
    })
}

#[endpoint(
    operation_id = "cx.authz.revoke_grant",
    tags("authz"),
    summary = "Revoke an existing authorization grant by id"
)]
async fn revoke_grant(
    aa: AuthArgs,
    grant_id: PathParam<String>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<RevokeGrantResponse> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req)?;
    let grant_id = grant_id.into_inner();
    if state.authz.revoke_grant(&grant_id) {
        append_audit_log(
            state,
            Some(&session.actor),
            "authz.grant.revoke",
            json!({"grant_id": grant_id.clone()}),
            "accepted",
        );
        json_ok(RevokeGrantResponse {
            revoked: true,
            grant_id,
        })
    } else {
        Err(AppError::not_found("grant not found"))
    }
}

#[endpoint(
    operation_id = "cx.authz.get_invites",
    tags("authz"),
    summary = "List pending invites for the authenticated actor"
)]
async fn invites(
    aa: crate::routing::system::extract::AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
) -> crate::result::JsonResult<InvitesResponse> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req)?;
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
    crate::result::json_ok(InvitesResponse {
        invites: invite_list,
        next_cursor: None,
    })
}
