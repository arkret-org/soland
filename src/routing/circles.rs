//! CXP-0007 — Circle administration HTTP surface.
//!
//! Hosts the canonical `/api/v1/circles/*` admin/CRUD layer. Each handler
//! builds a `cx.circle.*` Operation and routes it through the standard
//! `accept_local_operations` pipeline so the reducer's invariants
//! (`circle_realm_mismatch`, `circle_member_must_be_realm_member`,
//! `circle_not_active`, the lifecycle transition matrix) fire identically
//! to events arriving over the wire.
//!
//! Routes (mirror of `/api/v1/realms` / `/api/v1/spaces` style):
//!
//! - `POST   /api/v1/circles`                              create Circle
//! - `GET    /api/v1/circles`                              list Circles (filtered by `realm_id` query)
//! - `GET    /api/v1/circles/{circle_id}`                  read Circle
//! - `POST   /api/v1/circles/{circle_id}/members`          add member
//! - `DELETE /api/v1/circles/{circle_id}/members/{actor}`  remove member
//! - `POST   /api/v1/circles/{circle_id}/scope-rotate`     rotate MLS scope (TODO)
//! - `POST   /api/v1/circles/{circle_id}/archive`          archive Circle
//! - `POST   /api/v1/circles/{circle_id}/tombstone`        tombstone Circle
//!
//! The `scope-rotate` route currently emits a `cx.circle.update` Move with a
//! reducer-side `mls_group_ref` rotation hook — full MLS-key plumbing lives
//! in `reducer/mls.rs` and is TODO(circle-rollout-P2A.4); see the inline
//! comment on `post_scope_rotate`.

use contrix_sdk::{Operation, OperationId, RealmId};
use salvo::http::StatusCode;
use salvo::oapi::extract::{JsonBody, PathParam, QueryParam};
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::json;

use super::{AuthArgs, accept_local_operations};
use crate::error::{AppError, ErrorCode};
use crate::ids;
use crate::kinds::{
    CX_CIRCLE_ARCHIVE, CX_CIRCLE_CREATE, CX_CIRCLE_MEMBER_STATE, CX_CIRCLE_TOMBSTONE,
    CX_CIRCLE_UPDATE,
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
                .push(
                    Router::with_path("{actor_did}").delete(delete_circle_member),
                ),
        )
        .push(Router::with_path("{circle_id}/scope-rotate").post(post_scope_rotate))
        .push(Router::with_path("{circle_id}/archive").post(post_circle_archive))
        .push(Router::with_path("{circle_id}/tombstone").post(post_circle_tombstone))
}

// ── Response / request types ─────────────────────────────────────────────

#[derive(Clone, Debug, Serialize, Deserialize, salvo::oapi::ToSchema)]
pub struct CircleResponse {
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
pub struct ListCirclesResponse {
    pub realm_id: String,
    pub circles: Vec<CircleResponse>,
}

#[derive(Clone, Debug, Serialize, Deserialize, salvo::oapi::ToSchema)]
pub struct CreateCircleRequest {
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
pub struct CircleMemberRequest {
    pub actor_did: String,
    /// Optional explicit member state. Defaults to `"active"`. Spec
    /// `cx.circle.member.state` enum: invited / active / removed / banned / left.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, salvo::oapi::ToSchema)]
pub struct CircleMembershipResponse {
    pub circle_id: String,
    pub actor_did: String,
    pub state: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, salvo::oapi::ToSchema)]
pub struct CircleScopeRotateResponse {
    pub circle_id: String,
    pub mls_group_ref: Option<String>,
    /// Reducer-emitted reason code on `Ignored`/`Rejected`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

impl From<&CircleProjection> for CircleResponse {
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
    operation_id = "cx.circles.list",
    tags("circles"),
    summary = "List Circles visible to the caller within a given Realm"
)]
#[tracing::instrument(skip_all, fields(op = "cx.circles.list"))]
async fn list_circles(
    aa: AuthArgs,
    realm_id: QueryParam<String, true>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<ListCirclesResponse> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let _session = aa.authenticated_session(state, req)?;
    let realm_id = realm_id.into_inner();
    let projection = state.projection.lock().expect("projection mutex");
    let circles = projection
        .circles_for_realm(&realm_id)
        .iter()
        .map(|c| CircleResponse::from(*c))
        .collect();
    json_ok(ListCirclesResponse { realm_id, circles })
}

#[endpoint(
    operation_id = "cx.circles.get",
    tags("circles"),
    summary = "Fetch a single Circle by id"
)]
#[tracing::instrument(skip_all, fields(op = "cx.circles.get"))]
async fn get_circle(
    aa: AuthArgs,
    circle_id: PathParam<String>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<CircleResponse> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let _session = aa.authenticated_session(state, req)?;
    let circle_id = circle_id.into_inner();
    let projection = state.projection.lock().expect("projection mutex");
    let circle = projection
        .circle(&circle_id)
        .ok_or_else(|| AppError::not_found("circle not found"))?;
    json_ok(CircleResponse::from(circle))
}

#[endpoint(
    operation_id = "cx.circles.create",
    tags("circles"),
    summary = "Create a Circle (cx.circle.create)"
)]
#[tracing::instrument(skip_all, fields(op = "cx.circles.create"))]
async fn post_circle(
    aa: AuthArgs,
    body: JsonBody<CreateCircleRequest>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<CircleResponse> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req)?;
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
    let operation = Operation::create(op_id, realm_scope, CX_CIRCLE_CREATE, payload);
    accept_local_operations(state, &session.actor, std::slice::from_ref(&operation))
        .map_err(reducer_reject_to_app_error)?;
    let projection = state.projection.lock().expect("projection mutex");
    let circle = projection
        .circle(&circle_id)
        .ok_or_else(|| AppError::internal("circle create accepted but not projected"))?;
    json_ok(CircleResponse::from(circle))
}

#[endpoint(
    operation_id = "cx.circles.members.add",
    tags("circles"),
    summary = "Add or change a Circle member (cx.circle.member.state)"
)]
#[tracing::instrument(skip_all, fields(op = "cx.circles.members.add"))]
async fn post_circle_member(
    aa: AuthArgs,
    circle_id: PathParam<String>,
    body: JsonBody<CircleMemberRequest>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<CircleMembershipResponse> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req)?;
    let circle_id = circle_id.into_inner();
    let body = body.into_inner();
    let realm_scope = circle_realm_scope(state, &circle_id)?;
    let target_state = body
        .state
        .clone()
        .unwrap_or_else(|| "active".to_owned());
    let payload = json!({
        "circle_id": circle_id,
        "actor": body.actor_did,
        "state": target_state,
        "sender": session.actor.clone(),
    });
    let op_id = OperationId::new(ids::generate_operation_id())
        .map_err(|e| AppError::invalid_param(format!("operation_id: {e}")))?;
    let operation = Operation::create(op_id, realm_scope, CX_CIRCLE_MEMBER_STATE, payload);
    accept_local_operations(state, &session.actor, std::slice::from_ref(&operation))
        .map_err(reducer_reject_to_app_error)?;
    json_ok(CircleMembershipResponse {
        circle_id,
        actor_did: body.actor_did,
        state: target_state,
    })
}

#[endpoint(
    operation_id = "cx.circles.members.remove",
    tags("circles"),
    summary = "Remove a Circle member (cx.circle.member.state → removed)"
)]
#[tracing::instrument(skip_all, fields(op = "cx.circles.members.remove"))]
async fn delete_circle_member(
    aa: AuthArgs,
    circle_id: PathParam<String>,
    actor_did: PathParam<String>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<CircleMembershipResponse> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req)?;
    let circle_id = circle_id.into_inner();
    let actor_did = actor_did.into_inner();
    let realm_scope = circle_realm_scope(state, &circle_id)?;
    let payload = json!({
        "circle_id": circle_id,
        "actor": actor_did,
        "state": "removed",
        "sender": session.actor.clone(),
    });
    let op_id = OperationId::new(ids::generate_operation_id())
        .map_err(|e| AppError::invalid_param(format!("operation_id: {e}")))?;
    let operation = Operation::create(op_id, realm_scope, CX_CIRCLE_MEMBER_STATE, payload);
    accept_local_operations(state, &session.actor, std::slice::from_ref(&operation))
        .map_err(reducer_reject_to_app_error)?;
    json_ok(CircleMembershipResponse {
        circle_id,
        actor_did,
        state: "removed".to_owned(),
    })
}

#[endpoint(
    operation_id = "cx.circles.scope_rotate",
    tags("circles"),
    summary = "Rotate the Circle's bound MLS group (CXP-0007)"
)]
#[tracing::instrument(skip_all, fields(op = "cx.circles.scope_rotate"))]
async fn post_scope_rotate(
    aa: AuthArgs,
    circle_id: PathParam<String>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<CircleScopeRotateResponse> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req)?;
    let circle_id = circle_id.into_inner();
    let realm_scope = circle_realm_scope(state, &circle_id)?;
    // TODO(circle-rollout-P2A.4): wire the actual MLS group rotation
    // (genesis -> commit -> welcome cascade) through `reducer/mls.rs`.
    // For now the route emits a `cx.circle.update` Move with an empty
    // patch so authz hooks fire and the reducer's `circle_not_active`
    // / `circle_already_terminal` precondition checks run.
    let payload = json!({
        "circle_id": circle_id,
        "patch": {},
        "scope_rotate": true,
        "sender": session.actor.clone(),
    });
    let op_id = OperationId::new(ids::generate_operation_id())
        .map_err(|e| AppError::invalid_param(format!("operation_id: {e}")))?;
    let operation = Operation::create(op_id, realm_scope, CX_CIRCLE_UPDATE, payload);
    accept_local_operations(state, &session.actor, std::slice::from_ref(&operation))
        .map_err(reducer_reject_to_app_error)?;
    let projection = state.projection.lock().expect("projection mutex");
    let circle = projection
        .circle(&circle_id)
        .ok_or_else(|| AppError::not_found("circle not found"))?;
    json_ok(CircleScopeRotateResponse {
        circle_id: circle.circle_id.clone(),
        mls_group_ref: circle.mls_group_ref.clone(),
        note: Some(
            "MLS scope rotation acknowledged; full key rotation is \
             TODO(circle-rollout-P2A.4)"
                .to_owned(),
        ),
    })
}

#[endpoint(
    operation_id = "cx.circles.archive",
    tags("circles"),
    summary = "Archive a Circle (cx.circle.archive)"
)]
#[tracing::instrument(skip_all, fields(op = "cx.circles.archive"))]
async fn post_circle_archive(
    aa: AuthArgs,
    circle_id: PathParam<String>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<CircleResponse> {
    submit_circle_lifecycle(depot, req, aa, circle_id.into_inner(), CX_CIRCLE_ARCHIVE).await
}

#[endpoint(
    operation_id = "cx.circles.tombstone",
    tags("circles"),
    summary = "Tombstone a Circle (cx.circle.tombstone)"
)]
#[tracing::instrument(skip_all, fields(op = "cx.circles.tombstone"))]
async fn post_circle_tombstone(
    aa: AuthArgs,
    circle_id: PathParam<String>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<CircleResponse> {
    submit_circle_lifecycle(depot, req, aa, circle_id.into_inner(), CX_CIRCLE_TOMBSTONE).await
}

async fn submit_circle_lifecycle(
    depot: &mut Depot,
    req: &mut Request,
    aa: AuthArgs,
    circle_id: String,
    kind: &'static str,
) -> JsonResult<CircleResponse> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req)?;
    let realm_scope = circle_realm_scope(state, &circle_id)?;
    let payload = json!({
        "circle_id": circle_id,
        "sender": session.actor.clone(),
    });
    let op_id = OperationId::new(ids::generate_operation_id())
        .map_err(|e| AppError::invalid_param(format!("operation_id: {e}")))?;
    let operation = Operation::create(op_id, realm_scope, kind, payload);
    accept_local_operations(state, &session.actor, std::slice::from_ref(&operation))
        .map_err(reducer_reject_to_app_error)?;
    let projection = state.projection.lock().expect("projection mutex");
    // For tombstone the read-helper hides the row; fall back to direct
    // map lookup so the response still surfaces the terminal state.
    let response = projection
        .circle(&circle_id)
        .map(CircleResponse::from)
        .or_else(|| {
            projection
                .circles
                .get(&circle_id)
                .map(|c| CircleResponse {
                    state: "tombstoned".to_owned(),
                    members: Vec::new(),
                    ..CircleResponse::from(c)
                })
        })
        .ok_or_else(|| AppError::not_found("circle not found"))?;
    json_ok(response)
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
/// `code` is the canonical CXP-0007 reason (e.g. `circle_realm_mismatch`,
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
