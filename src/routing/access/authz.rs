//! Authorization HTTP surface.
//!
//! Surfaces:
//! - `POST /api/v1/authz/check`             — evaluate one (actor, action, resource)
//! - `GET  /api/v1/authz/effective-grants`  — direct grants visible to a subject
//! - `POST /api/v1/authz/grants`            — owner-issued grant
//! - `DELETE /api/v1/authz/grants/{grant_id}` — revoke
//! - `GET  /api/v1/authz/invites`           — pending invites visible to the actor
//!
//! The actual authorisation engine lives in `src/authz.rs` (the
//! `state.authz` field is shared). Still-open work: schema alignment,
//! the missing constraint types, the condition.kind types, the
//! capability lattice, and grant/invite/policy lifecycle integration.

use salvo::oapi::extract::{JsonBody, PathParam};
use salvo::prelude::*;
use serde_json::{Value, json};

use super::{append_audit_log, now, query_param};
use crate::error::AppError;
use crate::result::{JsonResult, json_ok};
use crate::routing::system::extract::AuthArgs;
use crate::state::AppState;
use crate::wire::{
    AuthzCheckReqBody, AuthzCheckResBody, CreateGrantRequest, CreateGrantResponse,
    EffectiveGrantsResBody, InvitesResponse, RevokeGrantResponse,
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
#[tracing::instrument(skip_all, fields(op = "cx.authz.check"))]
async fn authz_check(
    body: JsonBody<AuthzCheckReqBody>,
    depot: &mut Depot,
) -> JsonResult<AuthzCheckResBody> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let body = body.into_inner();
    let (resource_str, realm_id, resource_facets) = if let Some(s) = body.resource.as_str() {
        (s.to_owned(), s.to_owned(), Vec::new())
    } else if let Some(obj) = body.resource.as_object() {
        let kind = obj.get("kind").and_then(|v| v.as_str()).unwrap_or("realm");
        let sid = obj
            .get("realm_id")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned)
            .or_else(|| {
                obj.get("space_id")
                    .and_then(|v| v.as_str())
                    .map(ToOwned::to_owned)
            })
            .or_else(|| {
                (kind == "realm")
                    .then(|| {
                        obj.get("id")
                            .and_then(|v| v.as_str())
                            .map(ToOwned::to_owned)
                    })
                    .flatten()
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
        // SEL-1 (R3 spec-sync 2026-05-27, contrix-spec b47ff6ec) —
        // `kind=circle` resources MUST carry a `cx:circle:<uuid>`
        // identifier; accept either `circle_id` or the canonical `id`
        // field. The Circle is scoped to its parent Realm; the resource
        // resolver pairs it with the calling realm_id below.
        let resource = obj
            .get("id")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned)
            .or_else(|| {
                (kind == "circle")
                    .then(|| {
                        obj.get("circle_id")
                            .and_then(|v| v.as_str())
                            .map(ToOwned::to_owned)
                    })
                    .flatten()
            })
            .unwrap_or_else(|| format!("{kind}:{sid}"));
        let facets = facet_names_from_value(obj.get("facets"));
        (resource, sid, facets)
    } else {
        (String::new(), String::new(), Vec::new())
    };
    // Look up Realm owner and members.
    let (owner, members) = {
        let owner = state
            .persistence
            .realm_meta()
            .get(&realm_id)
            .await
            .ok()
            .flatten()
            .map(|m| m.owner);
        let spaces = state.realms.lock().expect("spaces lock");
        let members = contrix_sdk::RealmId::new(realm_id.clone())
            .ok()
            .and_then(|realm_id| spaces.get(&realm_id))
            .map(|s| s.members.iter().map(|m| m.to_string()).collect::<Vec<_>>())
            .unwrap_or_default();
        (owner, members)
    };
    let result = state.authz.check(
        &body.actor,
        &body.action,
        &resource_str,
        &realm_id,
        owner.as_deref(),
        &members,
        &resource_facets,
    );
    let matched_grants = result
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
        .collect::<Vec<_>>();
    json_ok(AuthzCheckResBody {
        allowed: result.allowed,
        reason_code: (!result.allowed).then(|| result.reason.clone()),
        reason: if result.allowed {
            None
        } else {
            result.reason_detail.clone()
        },
        grants: matched_grants.clone(),
        obligations: Vec::new(),
        decision_trace: json!({
            "actor": body.actor,
            "action": body.action,
            "resource": resource_str,
            "realm_id": realm_id,
            "matched_grants": matched_grants,
            "constraints": [],
            "missing_proofs": [],
            "cache": {
                "mode": "in_memory",
                "frontier": Value::Null
            }
        }),
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
#[tracing::instrument(skip_all, fields(op = "cx.authz.get_effective_grants"))]
async fn effective_grants(
    depot: &mut Depot,
    req: &mut Request,
) -> crate::result::JsonResult<EffectiveGrantsResBody> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let subject = query_param(req, "subject").unwrap_or_else(|| "did:web:alice.example".to_owned());
    let space_id = query_param(req, "space_id").unwrap_or_else(|| "*".to_owned());
    let grants = if space_id == "*" {
        // Return grants across all spaces
        state
            .persistence
            .realm_meta()
            .list()
            .await
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
    crate::result::json_ok(EffectiveGrantsResBody {
        grants: all_grants,
        state_digest: Some(
            "sha256:0000000000000000000000000000000000000000000000000000000000000000".to_owned(),
        ),
        evaluated_at: now(),
    })
}

// ── Grant CRUD ──

#[endpoint(
    operation_id = "cx.authz.create_grant",
    tags("authz"),
    summary = "Create an owner-issued or delegated authorization grant"
)]
#[tracing::instrument(skip_all, fields(op = "cx.authz.create_grant"))]
async fn create_grant(
    aa: AuthArgs,
    body: JsonBody<CreateGrantRequest>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<CreateGrantResponse> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let body = body.into_inner();
    // CXP-0007 P1.3.4: parse the typed `GrantConstraint` enum from each
    // raw JSON object on the wire. The SDK's typed enum uses
    // `constraint_type` as its tag; unknown variants are hard-rejected.
    let constraints: Vec<crate::authz::Constraint> = body
        .constraints
        .into_iter()
        .map(serde_json::from_value::<crate::authz::Constraint>)
        .collect::<Result<_, _>>()
        .map_err(|err| AppError::invalid_param(format!("invalid grant constraint: {err}")))?;
    let expires_at = parse_expires_at(body.expires_at.as_deref())?;
    let grant = if let Some(parent_grant_id) = body.delegated_from.as_deref() {
        match state.authz.create_delegated_grant(
            parent_grant_id,
            session.actor.clone(),
            body.subject,
            body.resource,
            body.actions,
            constraints,
            expires_at,
        ) {
            Ok(grant) => grant,
            Err(err) => return Err(delegation_error_to_app_error(err)),
        }
    } else {
        // Root grant: only the space owner MAY issue. capabilities.md §3
        // (Grant 由 issuer 持有,且 issuer MUST hold the action — owner does).
        require_space_owner(state, &body.space_id, &session.actor).await?;
        state.authz.create_grant_with_options(
            body.space_id,
            session.actor.clone(),
            body.subject,
            body.resource,
            body.actions,
            constraints,
            None,
            expires_at,
        )
    };
    let action_label = if grant.delegated_from.is_some() {
        "authz.grant.delegate"
    } else {
        "authz.grant.create"
    };
    append_audit_log(
        state,
        Some(&session.actor),
        action_label,
        json!({
            "grant_id": grant.grant_id.clone(),
            "issuer": grant.issuer.clone(),
            "subject": grant.subject.clone(),
            "actions": grant.actions.clone(),
            "resource": grant.resource.clone(),
            "expires_at": grant.expires_at.map(|dt| dt.to_rfc3339()),
            "delegated_from": grant.delegated_from.clone(),
        }),
        "accepted",
    );
    json_ok(CreateGrantResponse {
        grant_id: grant.grant_id,
        subject: grant.subject,
        actions: grant.actions,
        resource: grant.resource,
        created_at: grant.created_at.to_rfc3339(),
        expires_at: grant.expires_at.map(|dt| dt.to_rfc3339()),
        delegated_from: grant.delegated_from,
    })
}

fn parse_expires_at(
    value: Option<&str>,
) -> Result<Option<chrono::DateTime<chrono::Utc>>, AppError> {
    let Some(raw) = value else {
        return Ok(None);
    };
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    chrono::DateTime::parse_from_rfc3339(trimmed)
        .map(|dt| Some(dt.with_timezone(&chrono::Utc)))
        .map_err(|_| AppError::invalid_param("expires_at must be RFC 3339"))
}

async fn require_space_owner(
    state: &AppState,
    space_id: &str,
    actor: &str,
) -> Result<(), AppError> {
    let owner = state
        .persistence
        .realm_meta()
        .get(space_id)
        .await
        .ok()
        .flatten()
        .map(|meta| meta.owner);
    match owner.as_deref() {
        Some(value) if value == actor => Ok(()),
        Some(_) => Err(AppError::capability_denied(
            "only the space owner may issue root grants",
        )),
        None => Err(AppError::not_found("space not found")),
    }
}

fn delegation_error_to_app_error(err: crate::authz::DelegationError) -> AppError {
    use crate::authz::DelegationError;
    use salvo::http::StatusCode;
    // We don't have a canonical `failed_precondition` ErrorCode in the
    // registry; reuse `StateMismatch` as the base (semantically close — a
    // precondition on parent grant state failed) and override the wire
    // string so the test can assert the spec-canonical code.
    let state_mismatch = crate::error::ErrorCode::StateMismatch;
    match err {
        DelegationError::ParentNotFound => AppError::not_found("delegated_from grant not found"),
        DelegationError::ParentRevoked => {
            AppError::new(state_mismatch, "delegated_from grant is revoked")
                .with_status(StatusCode::PRECONDITION_FAILED)
                .with_wire_code("parent_revoked")
        }
        DelegationError::ParentExpired => {
            AppError::new(state_mismatch, "delegated_from grant has already expired")
                .with_status(StatusCode::PRECONDITION_FAILED)
                .with_wire_code("parent_expired")
        }
        DelegationError::NotGrantHolder => {
            AppError::capability_denied("delegator is not the subject of the parent grant")
                .with_wire_code("not_grant_holder")
        }
        DelegationError::ActionsNotHeld { offending } => AppError::new(
            state_mismatch,
            format!(
                "delegator does not hold action(s) {}",
                offending
                    .iter()
                    .map(|a| format!("`{a}`"))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        )
        .with_status(StatusCode::PRECONDITION_FAILED)
        .with_wire_code("capability_not_held"),
        DelegationError::OverExpire => AppError::new(
            state_mismatch,
            "delegated expires_at must be ≤ parent expires_at",
        )
        .with_status(StatusCode::PRECONDITION_FAILED)
        .with_wire_code("capability_over_expire"),
        DelegationError::ResourceOutOfScope => AppError::new(
            state_mismatch,
            "delegated resource is outside the parent's scope",
        )
        .with_status(StatusCode::PRECONDITION_FAILED)
        .with_wire_code("resource_out_of_scope"),
    }
}

#[endpoint(
    operation_id = "cx.authz.revoke_grant",
    tags("authz"),
    summary = "Revoke an existing authorization grant by id"
)]
#[tracing::instrument(skip_all, fields(op = "cx.authz.revoke_grant"))]
async fn revoke_grant(
    aa: AuthArgs,
    grant_id: PathParam<String>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<RevokeGrantResponse> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let grant_id = grant_id.into_inner();
    // Only the grant's issuer OR the space owner may revoke. capabilities.md
    // §12 — revocation is explicit, but limited to the chain of trust that
    // produced it.
    let Some(grant) = state.authz.get_grant(&grant_id) else {
        return Err(AppError::not_found("grant not found"));
    };
    if grant.issuer != session.actor {
        let owner = state
            .persistence
            .realm_meta()
            .get(&grant.space_id)
            .await
            .ok()
            .flatten()
            .map(|meta| meta.owner);
        if owner.as_deref() != Some(session.actor.as_str()) {
            return Err(AppError::capability_denied(
                "only the grant issuer or space owner may revoke this grant",
            ));
        }
    }
    let (revoked, cascade_revoked) = state.authz.revoke_grant_with_cascade(&grant_id);
    if revoked {
        append_audit_log(
            state,
            Some(&session.actor),
            "authz.grant.revoke",
            json!({
                "grant_id": grant_id.clone(),
                "issuer": grant.issuer,
                "subject": grant.subject,
                "actions": grant.actions,
                "cascade_revoked": cascade_revoked.clone(),
            }),
            "accepted",
        );
        json_ok(RevokeGrantResponse {
            revoked: true,
            grant_id,
            cascade_revoked,
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
#[tracing::instrument(skip_all, fields(op = "cx.authz.get_invites"))]
async fn invites(
    aa: crate::routing::system::extract::AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
) -> crate::result::JsonResult<InvitesResponse> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let now = now();
    let invite_list = state
        .persistence
        .space_invites()
        .snapshot_all()
        .await
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
