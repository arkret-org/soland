//! Admin-facing moderation endpoints — **operations-only** after the P2
//! governance migration.
//!
//! Moderation *truth* (decisions / lifts / appeals) is now carried by
//! protocol events submitted to `POST /_cokret/self/events` as self-authored
//! Moves and converged by the data/control-plane reducer
//! (`reducer/apply_moderation.rs`). The control plane holds no moderation
//! truth (content-moderation.md §2.6 "不经任何 /_soland/admin 写路径;治理状态
//! 完全由数据/控制面 reducer 收敛,运维管理面不持有 moderation 真相").
//!
//! The former `/decision`, `/decision/{id}/lift`,
//! `/appeals/{id}/{review,decision,close}` **write** endpoints have therefore
//! been taken offline. What remains here is operations-tooling convenience:
//!
//! ### Queue (operational triage only)
//! - `GET /queue` — local queue read served by [`super::spec`]; this suite does NOT re-bind it.
//! - `POST /queue/{id}/assign` — assign reviewer DIDs (queue routing only; not a moderation fact).
//! - `POST /queue/{id}/priority` — set priority (queue routing only).
//!
//! ### Appeals (read-only)
//! - `GET /appeals` — list (one record per appeal_id, latest event).
//! - `GET /appeals/{appeal_id}` — full history.
//!
//! The separation-of-duties / overturn↔lift / modify↔new-decision rules now
//! live in the reducer (`reducer/apply_moderation.rs`) + the ingest
//! capability gate (`routing/events/operations/policy.rs
//! ::validate_moderation_event_policy`); the helper checks below
//! ([`appeal_decision_overturn_paired_check`] / [`appeal_self_review_check`])
//! are retained for the reducer-level state-machine unit tests.

use chrono::Utc;
use salvo::oapi::extract::JsonBody;
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::audit::append_audit_log;
use super::require_admin_principal;
use crate::error::AppError;
use crate::result::{JsonResult, json_ok};
use crate::routing::system::extract::AuthArgs;
use crate::state::AppState;

pub(super) fn router() -> Router {
    Router::with_path("moderation")
        // `GET queue` is owned by `super::spec` to keep the single
        // `/_soland/admin/moderation/queue` URL
        // bound to exactly one handler; only the sub-paths live here.
        //
        // Decision / lift / appeal WRITE endpoints are intentionally absent:
        // those facts are now protocol events on /_cokret/self/events. Only
        // operational queue routing + read-only appeal views remain.
        .push(Router::with_path("queue/{id}/assign").post(assign_queue_item))
        .push(Router::with_path("queue/{id}/priority").post(prioritise_queue_item))
        .push(Router::with_path("appeals").get(list_appeals))
        .push(Router::with_path("appeals/{appeal_id}").get(get_appeal))
}

// ── Queue ────────────────────────────────────────────────────────────
//
// The local `GET /_soland/admin/moderation/queue` read lives in
// `super::spec`; the queue sub-actions (assign / priority) are below.

#[derive(Clone, Debug, Serialize, Deserialize, salvo::oapi::ToSchema)]
pub struct AssignReviewerReq {
    pub reviewers: Vec<String>,
}

#[endpoint(
    operation_id = "org.cokret.soland.admin.moderation.queue.assign",
    tags("admin", "moderation"),
    summary = "Assign reviewer DIDs to a queue item"
)]
#[tracing::instrument(
    skip_all,
    fields(op = "org.cokret.soland.admin.moderation.queue.assign")
)]
async fn assign_queue_item(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    body: JsonBody<AssignReviewerReq>,
) -> JsonResult<Value> {
    let item_id = req
        .param::<String>("id")
        .ok_or_else(|| AppError::invalid_param("id required"))?;
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let session = require_admin_principal(state, session)?;
    let mut item = state
        .persistence
        .moderation()
        .get_queue_item(&item_id)
        .await
        .ok()
        .flatten()
        .ok_or_else(|| AppError::not_found("queue item"))?;
    if let Some(obj) = item.as_object_mut() {
        obj.insert("assigned_to".to_owned(), json!(body.into_inner().reviewers));
        obj.insert("status".to_owned(), json!("reviewing"));
        obj.insert("updated_at".to_owned(), json!(Utc::now().to_rfc3339()));
    }
    state
        .persistence
        .moderation()
        .upsert_queue_item(item.clone())
        .await
        .map_err(|err| AppError::internal(err.to_string()))?;
    append_audit_log(
        state,
        Some(&session.actor),
        "admin.moderation.queue.assign",
        json!({ "id": item_id }),
        "ok",
    )
    .await;
    json_ok(item)
}

#[derive(Clone, Debug, Serialize, Deserialize, salvo::oapi::ToSchema)]
pub struct PrioritiseReq {
    /// `low` | `normal` | `high` | `urgent`.
    pub priority: String,
}

#[endpoint(
    operation_id = "org.cokret.soland.admin.moderation.queue.priority",
    tags("admin", "moderation"),
    summary = "Set priority on a queue item"
)]
#[tracing::instrument(
    skip_all,
    fields(op = "org.cokret.soland.admin.moderation.queue.priority")
)]
async fn prioritise_queue_item(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    body: JsonBody<PrioritiseReq>,
) -> JsonResult<Value> {
    let item_id = req
        .param::<String>("id")
        .ok_or_else(|| AppError::invalid_param("id required"))?;
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let session = require_admin_principal(state, session)?;
    let priority = body.into_inner().priority;
    if !matches!(priority.as_str(), "low" | "normal" | "high" | "urgent") {
        return Err(AppError::invalid_param(
            "priority must be one of low|normal|high|urgent",
        ));
    }
    let mut item = state
        .persistence
        .moderation()
        .get_queue_item(&item_id)
        .await
        .ok()
        .flatten()
        .ok_or_else(|| AppError::not_found("queue item"))?;
    if let Some(obj) = item.as_object_mut() {
        obj.insert("priority".to_owned(), json!(priority));
        obj.insert("updated_at".to_owned(), json!(Utc::now().to_rfc3339()));
    }
    state
        .persistence
        .moderation()
        .upsert_queue_item(item.clone())
        .await
        .map_err(|err| AppError::internal(err.to_string()))?;
    append_audit_log(
        state,
        Some(&session.actor),
        "admin.moderation.queue.priority",
        json!({ "id": item_id, "priority": priority }),
        "ok",
    )
    .await;
    json_ok(item)
}

// ── Appeals ──────────────────────────────────────────────────────────

#[endpoint(
    operation_id = "org.cokret.soland.admin.moderation.appeals.list",
    tags("admin", "moderation"),
    summary = "List moderation appeals (latest event per appeal)"
)]
#[tracing::instrument(
    skip_all,
    fields(op = "org.cokret.soland.admin.moderation.appeals.list")
)]
async fn list_appeals(aa: AuthArgs, depot: &mut Depot, req: &mut Request) -> JsonResult<Value> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let _ = require_admin_principal(state, session)?;
    let items = state
        .persistence
        .moderation()
        .list_appeals()
        .await
        .unwrap_or_default();
    json_ok(json!({ "items": items, "total": items.len() }))
}

#[endpoint(
    operation_id = "org.cokret.soland.admin.moderation.appeals.get",
    tags("admin", "moderation"),
    summary = "Full history of one moderation appeal"
)]
#[tracing::instrument(
    skip_all,
    fields(op = "org.cokret.soland.admin.moderation.appeals.get")
)]
async fn get_appeal(aa: AuthArgs, depot: &mut Depot, req: &mut Request) -> JsonResult<Value> {
    let appeal_id = req
        .param::<String>("appeal_id")
        .ok_or_else(|| AppError::invalid_param("appeal_id required"))?;
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let _ = require_admin_principal(state, session)?;
    let history = state
        .persistence
        .moderation()
        .appeal_history(&appeal_id)
        .await
        .map_err(|err| AppError::internal(err.to_string()))?;
    if history.is_empty() {
        return Err(AppError::not_found("appeal"));
    }
    json_ok(json!({ "appeal_id": appeal_id, "history": history }))
}
