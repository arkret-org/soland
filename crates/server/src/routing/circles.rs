//! CKP-0007 — Circle administration HTTP surface.
//!
//! Hosts the `/_soland/self/circles/*` admin/CRUD layer (mounted under the
//! `/_soland/self` product surface; see `routing/mod.rs`). The Circle *data
//! model* `ck.circle.*` is spec-canonical; this HTTP surface is the self
//! convenience wrapper that builds the canonical operations.
//!
//! Namespace rule from CKP-0014 §5: circles are candidate operations. Until
//! they enter the formal catalog they MUST mount under `/_soland` (product
//! surface) and MUST NOT mount under `/_cokret` (protocol surface). Once
//! circles enter the catalog, this surface moves to `/_cokret/self/circles/*`.
//!
//! Each handler builds a `ck.circle.*` Operation and routes it through the standard
//! `accept_local_operations` pipeline so the reducer's invariants
//! (`circle_realm_mismatch`, `circle_member_must_be_realm_member`,
//! `circle_not_active`, the lifecycle transition matrix) fire identically
//! to events arriving over the wire.
//!
//! Routes (mirror of `/_soland/self/realms` / `/_soland/self/spaces` style):
//!
//! - `POST   /_soland/self/circles`                              create Circle
//! - `GET    /_soland/self/circles`                              list Circles (filtered by
//!   `realm_id` query)
//! - `GET    /_soland/self/circles/{circle_id}`                  read Circle
//! - `POST   /_soland/self/circles/{circle_id}/members`          add member
//! - `DELETE /_soland/self/circles/{circle_id}/members/{actor}`  remove member
//! - `POST   /_soland/self/circles/{circle_id}/scope-rotate`     rotate MLS scope (501 until wired)
//! - `POST   /_soland/self/circles/{circle_id}/archive`          archive Circle
//! - `POST   /_soland/self/circles/{circle_id}/tombstone`        tombstone Circle
//!
//! `scope-rotate` intentionally returns `501 unsupported_feature` until the
//! MLS genesis / commit / welcome cascade is wired end-to-end. It must not
//! acknowledge a rotation without actually changing the cryptographic scope.

use cokret_sdk::{Operation, OperationId, RealmId};
use salvo::http::StatusCode;
use salvo::oapi::extract::{JsonBody, PathParam, QueryParam};
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::json;

use super::{AuthArgs, accept_local_operations};
use crate::error::{AppError, ErrorCode};
use crate::ids;
use crate::kinds::{
    CK_CIRCLE_ARCHIVE, CK_CIRCLE_CREATE, CK_CIRCLE_MEMBER_STATE, CK_CIRCLE_TOMBSTONE,
};
use crate::reducer::CircleProjection;
use crate::result::{JsonResult, json_ok};
use crate::state::AppState;

pub(crate) fn router() -> Router {
    Router::with_path("circles")
        .get(list_circles)
        .post(post_circle)
        .push(Router::with_path("{circle_id}").get(get_circle))
        .push(
            Router::with_path("{circle_id}/members")
                .post(post_circle_member)
                .push(Router::with_path("{actor_id}").delete(delete_circle_member)),
        )
        .push(Router::with_path("{circle_id}/scope-rotate").post(post_scope_rotate))
        .push(Router::with_path("{circle_id}/archive").post(post_circle_archive))
        .push(Router::with_path("{circle_id}/tombstone").post(post_circle_tombstone))
}

// ── Response / request types ─────────────────────────────────────────────

#[derive(Clone, Debug, Serialize, Deserialize, salvo::oapi::ToSchema)]
pub struct CircleOutcome {
    pub circle_id: String,
    pub realm_id: String,
    pub title: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    pub directory_visibility: String,
    pub join_rule: String,
    pub history_visibility: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata_encryption_floor: Option<String>,
    pub encryption_profile: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mls_group_ref: Option<String>,
    pub state: String,
    pub members: Vec<String>,
    pub created_by: String,
    pub created_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_by: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, salvo::oapi::ToSchema)]
pub struct ListCirclesOutcome {
    pub realm_id: String,
    pub circles: Vec<CircleOutcome>,
}

#[derive(Clone, Debug, Serialize, Deserialize, salvo::oapi::ToSchema)]
pub struct CreateCircleRequestBody {
    pub realm_id: String,
    pub title: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub directory_visibility: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub join_rule: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub history_visibility: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata_encryption_floor: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encryption_profile: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, salvo::oapi::ToSchema)]
pub struct CircleMemberRequestBody {
    pub actor_id: String,
    /// Optional explicit member state. Defaults to `"active"`. Spec
    /// `ck.circle.member.state` enum: invited / active / removed / banned / left.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, salvo::oapi::ToSchema)]
pub struct CircleMembershipOutcome {
    pub circle_id: String,
    pub actor_id: String,
    pub state: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, salvo::oapi::ToSchema)]
pub struct CircleScopeRotateOutcome {
    pub circle_id: String,
    pub mls_group_ref: Option<String>,
    /// Reducer-emitted reason code on `Ignored`/`Rejected`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

impl From<&CircleProjection> for CircleOutcome {
    fn from(c: &CircleProjection) -> Self {
        Self {
            circle_id: c.circle_id.clone(),
            realm_id: c.realm_id.clone(),
            title: c.title.clone(),
            summary: c.summary.clone(),
            directory_visibility: c.directory_visibility.clone(),
            join_rule: c.join_rule.clone(),
            history_visibility: c.history_visibility.clone(),
            metadata_encryption_floor: c.metadata_encryption_floor.clone(),
            encryption_profile: c.encryption_profile.clone(),
            mls_group_ref: c.mls_group_ref.clone(),
            state: c.state.as_str().to_owned(),
            members: c.members.iter().cloned().collect(),
            created_by: c.created_by.clone(),
            created_at: c.created_at.to_rfc3339(),
            updated_by: c.updated_by.clone(),
            updated_at: c.updated_at.map(|t| t.to_rfc3339()),
        }
    }
}

// ── Handlers ────────────────────────────────────────────────────────────

#[endpoint(
    operation_id = "ck.self.circle.query.list",
    tags("circles"),
    summary = "List Circles visible to the caller within a given Realm"
)]
#[tracing::instrument(skip_all, fields(op = "ck.self.circle.query.list"))]
async fn list_circles(
    aa: AuthArgs,
    realm_id: QueryParam<String, true>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<ListCirclesOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let _session = aa.authenticated_session(state, req).await?;
    let realm_id = realm_id.into_inner();
    let projection = state.projection.lock().expect("projection mutex");
    let circles = projection
        .circles_for_realm(&realm_id)
        .iter()
        .map(|c| CircleOutcome::from(*c))
        .collect();
    json_ok(ListCirclesOutcome { realm_id, circles })
}

#[endpoint(
    operation_id = "ck.self.circle.resource.get",
    tags("circles"),
    summary = "Fetch a single Circle by id"
)]
#[tracing::instrument(skip_all, fields(op = "ck.self.circle.resource.get"))]
async fn get_circle(
    aa: AuthArgs,
    circle_id: PathParam<String>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<CircleOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let _session = aa.authenticated_session(state, req).await?;
    let circle_id = circle_id.into_inner();
    let projection = state.projection.lock().expect("projection mutex");
    let circle = projection
        .circle(&circle_id)
        .ok_or_else(|| AppError::not_found("circle not found"))?;
    json_ok(CircleOutcome::from(circle))
}

#[endpoint(
    operation_id = "ck.self.circle.command.create",
    tags("circles"),
    summary = "Create a Circle (ck.circle.create)"
)]
#[tracing::instrument(skip_all, fields(op = "ck.self.circle.command.create"))]
async fn post_circle(
    aa: AuthArgs,
    body: JsonBody<CreateCircleRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<CircleOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let body = body.into_inner();
    let realm_scope = RealmId::new(body.realm_id.clone())
        .map_err(|e| AppError::invalid_param(format!("realm_id: {e}")))?;
    let circle_id = ids::generate_circle_id();
    let object = json!({
        "id": circle_id,
        "realm_id": body.realm_id,
        "title": body.title,
        "summary": body.summary,
        "directory_visibility": body.directory_visibility.unwrap_or_else(|| "members".to_owned()),
        "join_rule": body.join_rule.unwrap_or_else(|| "invite".to_owned()),
        "history_visibility": body.history_visibility.unwrap_or_else(|| "joined".to_owned()),
        "metadata_encryption_floor": body.metadata_encryption_floor,
        "encryption_profile": body.encryption_profile.unwrap_or_else(|| "mls_rfc9420".to_owned()),
        "created_by": session.actor.clone(),
    });
    let payload = json!({"object": object, "sender": session.actor.clone()});
    let op_id = OperationId::new(ids::generate_operation_id())
        .map_err(|e| AppError::invalid_param(format!("operation_id: {e}")))?;
    let operation = Operation::create(op_id, realm_scope, CK_CIRCLE_CREATE, payload);
    accept_local_operations(state, &session.actor, std::slice::from_ref(&operation))
        .await
        .map_err(reducer_reject_to_app_error)?;
    let projection = state.projection.lock().expect("projection mutex");
    let circle = projection
        .circle(&circle_id)
        .ok_or_else(|| AppError::internal("circle create accepted but not projected"))?;
    json_ok(CircleOutcome::from(circle))
}

#[endpoint(
    operation_id = "ck.self.circle.member.command.add",
    tags("circles"),
    summary = "Add or change a Circle member (ck.circle.member.state)"
)]
#[tracing::instrument(skip_all, fields(op = "ck.self.circle.member.command.add"))]
async fn post_circle_member(
    aa: AuthArgs,
    circle_id: PathParam<String>,
    body: JsonBody<CircleMemberRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<CircleMembershipOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let circle_id = circle_id.into_inner();
    let body = body.into_inner();
    let realm_scope = circle_realm_scope(state, &circle_id)?;
    let target_state = body.state.clone().unwrap_or_else(|| "active".to_owned());
    // CKP-0007 strict-subset invariant (`Circle.members ⊆ Realm.members`) —
    // surfaced HERE, pre-projection, because `accept_local_operations` projects
    // fire-and-forget and does not propagate the reducer's `Rejected` effect
    // back to the HTTP caller. Without this gate, activating a non-member would
    // be silently dropped by the reducer yet return 200. We mirror the reducer's
    // `apply_circle_member_state` check (parent realm membership == "join") and
    // return the same canonical 422 wire code the reducer emits.
    if target_state == "active" {
        let realm_id = realm_scope.to_string();
        let parent_joined = {
            let projection = state.projection.lock().expect("projection mutex");
            projection
                .member(&realm_id, &body.actor_id)
                .map(|m| m.state == "join")
                .unwrap_or(false)
        };
        if !parent_joined {
            return Err(AppError::new(
                ErrorCode::FailedPrecondition,
                "circle reducer rejected: circle_member_must_be_realm_member",
            )
            .with_status(StatusCode::UNPROCESSABLE_ENTITY)
            .with_wire_code(CIRCLE_MEMBER_MUST_BE_REALM_MEMBER));
        }
    }
    // CKP-0007 §8 — authoritative capability decision for "pull another actor
    // into the Circle". When the requester is activating *someone else*, they
    // MUST hold `ck.circle.member.manage` (narrowed by `allowed_circle_ids`)
    // on this Circle. The engine evaluates the selector against the
    // `ck:circle:<uuid>` resource; we stamp the verdict into the operation so
    // the reducer's fail-closed second-line check can rely on it. A
    // self-service join (`actor == sender`) is left to the reducer's
    // `join_rule=open` gate.
    let pulling_other = body.actor_id != session.actor;
    let manage_verified = if target_state == "active" && pulling_other {
        let realm_id = realm_scope.to_string();
        let (owner, members) = circle_authz_principals(state, &realm_id).await;
        let verdict = state.authz.check(
            &session.actor,
            "ck.circle.member.manage",
            &circle_id,
            &realm_id,
            owner.as_deref(),
            &members,
            &[],
        );
        if !verdict.allowed {
            return Err(AppError::capability_denied(
                "ck.circle.member.manage required to add another actor to this Circle",
            )
            .with_wire_code(CIRCLE_MEMBER_MANAGE_CAPABILITY_REQUIRED));
        }
        true
    } else {
        false
    };
    let payload = json!({
        "circle_id": circle_id,
        "actor": body.actor_id,
        "state": target_state,
        "sender": session.actor.clone(),
        "manage_capability_verified": manage_verified,
        "actor_capability": {
            "action": "ck.circle.member.manage",
            "circle_id": circle_id,
            "allowed": manage_verified,
        },
    });
    let op_id = OperationId::new(ids::generate_operation_id())
        .map_err(|e| AppError::invalid_param(format!("operation_id: {e}")))?;
    let operation = Operation::create(op_id, realm_scope, CK_CIRCLE_MEMBER_STATE, payload);
    accept_local_operations(state, &session.actor, std::slice::from_ref(&operation))
        .await
        .map_err(reducer_reject_to_app_error)?;
    json_ok(CircleMembershipOutcome {
        circle_id,
        actor_id: body.actor_id,
        state: target_state,
    })
}

#[endpoint(
    operation_id = "ck.self.circle.member.resource.delete",
    tags("circles"),
    summary = "Remove a Circle member (ck.circle.member.state → removed)"
)]
#[tracing::instrument(skip_all, fields(op = "ck.self.circle.member.resource.delete"))]
async fn delete_circle_member(
    aa: AuthArgs,
    circle_id: PathParam<String>,
    actor_id: PathParam<String>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<CircleMembershipOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let circle_id = circle_id.into_inner();
    let actor_id = actor_id.into_inner();
    let realm_scope = circle_realm_scope(state, &circle_id)?;
    let payload = json!({
        "circle_id": circle_id,
        "actor": actor_id,
        "state": "removed",
        "sender": session.actor.clone(),
    });
    let op_id = OperationId::new(ids::generate_operation_id())
        .map_err(|e| AppError::invalid_param(format!("operation_id: {e}")))?;
    let operation = Operation::create(op_id, realm_scope, CK_CIRCLE_MEMBER_STATE, payload);
    accept_local_operations(state, &session.actor, std::slice::from_ref(&operation))
        .await
        .map_err(reducer_reject_to_app_error)?;
    json_ok(CircleMembershipOutcome {
        circle_id,
        actor_id,
        state: "removed".to_owned(),
    })
}

#[endpoint(
    operation_id = "ck.self.circle.command.rotate_scope",
    tags("circles"),
    summary = "Rotate the Circle's bound MLS group (CKP-0007)"
)]
#[tracing::instrument(skip_all, fields(op = "ck.self.circle.command.rotate_scope"))]
async fn post_scope_rotate(
    aa: AuthArgs,
    circle_id: PathParam<String>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<CircleScopeRotateOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let circle_id = circle_id.into_inner();
    let _realm_scope = circle_realm_scope(state, &circle_id)?;
    tracing::info!(
        actor = %session.actor,
        %circle_id,
        "circle scope rotation rejected because MLS key rotation is not implemented"
    );
    Err(AppError::unsupported_feature(
        "circle scope rotation requires MLS genesis/commit/welcome key rotation; no rotation was applied",
    )
    .with_status(StatusCode::NOT_IMPLEMENTED))
}

#[endpoint(
    operation_id = "ck.self.circle.command.archive",
    tags("circles"),
    summary = "Archive a Circle (ck.circle.archive)"
)]
#[tracing::instrument(skip_all, fields(op = "ck.self.circle.command.archive"))]
async fn post_circle_archive(
    aa: AuthArgs,
    circle_id: PathParam<String>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<CircleOutcome> {
    submit_circle_lifecycle(depot, req, aa, circle_id.into_inner(), CK_CIRCLE_ARCHIVE).await
}

#[endpoint(
    operation_id = "ck.self.circle.command.tombstone",
    tags("circles"),
    summary = "Tombstone a Circle (ck.circle.tombstone)"
)]
#[tracing::instrument(skip_all, fields(op = "ck.self.circle.command.tombstone"))]
async fn post_circle_tombstone(
    aa: AuthArgs,
    circle_id: PathParam<String>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<CircleOutcome> {
    submit_circle_lifecycle(depot, req, aa, circle_id.into_inner(), CK_CIRCLE_TOMBSTONE).await
}

async fn submit_circle_lifecycle(
    depot: &mut Depot,
    req: &mut Request,
    aa: AuthArgs,
    circle_id: String,
    kind: &'static str,
) -> JsonResult<CircleOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let realm_scope = circle_realm_scope(state, &circle_id)?;
    let payload = json!({
        "circle_id": circle_id,
        "sender": session.actor.clone(),
    });
    let op_id = OperationId::new(ids::generate_operation_id())
        .map_err(|e| AppError::invalid_param(format!("operation_id: {e}")))?;
    let operation = Operation::create(op_id, realm_scope, kind, payload);
    accept_local_operations(state, &session.actor, std::slice::from_ref(&operation))
        .await
        .map_err(reducer_reject_to_app_error)?;
    let projection = state.projection.lock().expect("projection mutex");
    // For tombstone the read-helper hides the row; fall back to direct
    // map lookup so the response still surfaces the terminal state.
    let response = projection
        .circle(&circle_id)
        .map(CircleOutcome::from)
        .or_else(|| {
            projection.circles.get(&circle_id).map(|c| CircleOutcome {
                state: "tombstoned".to_owned(),
                members: Vec::new(),
                ..CircleOutcome::from(c)
            })
        })
        .ok_or_else(|| AppError::not_found("circle not found"))?;
    json_ok(response)
}

/// CKP-0007 §8 — canonical reducer reason code when the requester lacks
/// `ck.circle.member.manage` for a cross-actor add. Kept in sync with the
/// reducer constant of the same name so the HTTP 403 and the reducer 422
/// surface the same wire code.
const CIRCLE_MEMBER_MANAGE_CAPABILITY_REQUIRED: &str = "circle_member_manage_capability_required";

/// CKP-0007 strict-subset invariant reason code (`Circle.members ⊆
/// Realm.members`). Kept in sync with the reducer constant of the same name so
/// the HTTP 422 and the reducer 422 surface the same wire code.
const CIRCLE_MEMBER_MUST_BE_REALM_MEMBER: &str = "circle_member_must_be_realm_member";

/// Resolve the `(owner, members)` pair the `SolandAuthzEngine::check` default-rule
/// path needs for a Realm. Mirrors the lookup in `routing/access/authz.rs`.
async fn circle_authz_principals(
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
        .map(|m| m.owner);
    let members = {
        let realms = state.realms.lock().expect("realms lock");
        RealmId::new(realm_id.to_owned())
            .ok()
            .and_then(|realm_id| realms.get(&realm_id))
            .map(|realm| {
                realm
                    .members
                    .iter()
                    .map(|member| member.to_string())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default()
    };
    (owner, members)
}

fn circle_realm_scope(state: &AppState, circle_id: &str) -> Result<RealmId, AppError> {
    let projection = state.projection.lock().expect("projection mutex");
    let realm_id = projection
        .circles
        .get(circle_id)
        .map(|c| c.realm_id.clone())
        .ok_or_else(|| AppError::not_found("circle not found"))?;
    drop(projection);
    RealmId::new(realm_id).map_err(|e| AppError::invalid_param(format!("realm_id: {e}")))
}

/// Map a reducer rejection reason string to an `AppError` whose wire
/// `code` is the canonical CKP-0007 reason (e.g. `circle_realm_mismatch`,
/// `circle_member_must_be_realm_member`). Returned as 422
/// `failed_precondition` so clients can branch on the reason directly.
fn reducer_reject_to_app_error(reason: &'static str) -> AppError {
    AppError::new(
        ErrorCode::FailedPrecondition,
        format!("circle reducer rejected: {reason}"),
    )
    .with_status(StatusCode::UNPROCESSABLE_ENTITY)
    .with_wire_code(reason)
}
