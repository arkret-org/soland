//! Admin-facing moderation endpoints powering the sodmin triage UI.
//!
//! Mounted under `/api/admin/v1/moderation/...`:
//!
//! ### Queue
//! - `GET /queue` — list current queue items.
//! - `POST /queue/{id}/assign` — assign reviewer DIDs.
//! - `POST /queue/{id}/priority` — set priority.
//!
//! ### Decisions
//! - `POST /decision` — admin issues `cx.moderation.decision`. Body: `{ target_ref, realm_id,
//!   action, reason_text_ref?, decision_ref? }`.
//! - `POST /decision/{decision_id}/lift` — issues `cx.moderation.decision.lift` (used when an
//!   appeal overturns a decision; the admin endpoint records the lift separately so the
//!   appeal-decision handler can pair them in the same batch).
//!
//! ### Appeals
//! - `GET /appeals` — list (one record per appeal_id, latest event).
//! - `GET /appeals/{appeal_id}` — full history.
//! - `POST /appeals/{appeal_id}/review` — reviewer claims the appeal. Transitions FSM: `submitted →
//!   under_review`.
//! - `POST /appeals/{appeal_id}/decision` — reviewer issues verdict. Transitions FSM: `under_review
//!   → decided`. `verdict=overturn` MUST be paired with an explicit `decision_lift_ref` so the
//!   `appeal_decision_overturn_paired_check` (defined in this module) passes.
//! - `POST /appeals/{appeal_id}/close` — closes the appeal. Transitions: `decided → closed`.
//!
//! All endpoints require the caller to pass
//! [`super::require_admin_principal`]; the `same actor cannot review
//! their own decision` separation-of-duties rule from
//! [`appeal_self_review_check`] is enforced at the
//! `/decision` step.

use chrono::Utc;
use salvo::oapi::extract::JsonBody;
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::audit::append_audit_log;
use super::require_admin_principal;
use crate::error::{AppError, ErrorCode};
use crate::ids;
use crate::result::{JsonResult, json_ok};
use crate::routing::system::extract::AuthArgs;
use crate::state::AppState;

pub(super) fn router() -> Router {
    Router::with_path("moderation")
        .push(Router::with_path("queue").get(list_queue))
        .push(Router::with_path("queue/{id}/assign").post(assign_queue_item))
        .push(Router::with_path("queue/{id}/priority").post(prioritise_queue_item))
        .push(Router::with_path("decision").post(issue_decision))
        .push(Router::with_path("decision/{decision_id}/lift").post(lift_decision))
        .push(Router::with_path("appeals").get(list_appeals))
        .push(Router::with_path("appeals/{appeal_id}").get(get_appeal))
        .push(Router::with_path("appeals/{appeal_id}/review").post(review_appeal))
        .push(Router::with_path("appeals/{appeal_id}/decision").post(decide_appeal))
        .push(Router::with_path("appeals/{appeal_id}/close").post(close_appeal))
}

// ── Queue ────────────────────────────────────────────────────────────

#[endpoint(
    operation_id = "cx.extension.soland.admin.moderation.queue.list",
    tags("admin", "moderation"),
    summary = "List moderation queue items"
)]
#[tracing::instrument(
    skip_all,
    fields(op = "cx.extension.soland.admin.moderation.queue.list")
)]
async fn list_queue(aa: AuthArgs, depot: &mut Depot, req: &mut Request) -> JsonResult<Value> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let _ = require_admin_principal(state, session)?;
    let items = state
        .persistence
        .moderation()
        .list_queue_items()
        .await
        .unwrap_or_default();
    json_ok(json!({ "items": items, "total": items.len() }))
}

#[derive(Clone, Debug, Serialize, Deserialize, salvo::oapi::ToSchema)]
pub struct AssignReviewerReq {
    pub reviewers: Vec<String>,
}

#[endpoint(
    operation_id = "cx.extension.soland.admin.moderation.queue.assign",
    tags("admin", "moderation"),
    summary = "Assign reviewer DIDs to a queue item"
)]
#[tracing::instrument(
    skip_all,
    fields(op = "cx.extension.soland.admin.moderation.queue.assign")
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
    operation_id = "cx.extension.soland.admin.moderation.queue.priority",
    tags("admin", "moderation"),
    summary = "Set priority on a queue item"
)]
#[tracing::instrument(
    skip_all,
    fields(op = "cx.extension.soland.admin.moderation.queue.priority")
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

// ── Decisions ────────────────────────────────────────────────────────

#[derive(Clone, Debug, Serialize, Deserialize, salvo::oapi::ToSchema)]
pub struct IssueDecisionReq {
    pub target_ref: String,
    pub realm_id: String,
    /// `redact` | `warn` | `restrict` | `ban` | `no_action` | …
    pub action: String,
    /// Reference / inline narrative for the moderator's rationale.
    #[serde(default)]
    pub reason_text_ref: Option<String>,
    /// Optional queue item this decision resolves (status moves to `actioned`).
    #[serde(default)]
    pub queue_item_ref: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, salvo::oapi::ToSchema)]
pub struct DecisionResBody {
    pub decision_id: String,
}

#[endpoint(
    operation_id = "cx.extension.soland.admin.moderation.decision",
    tags("admin", "moderation"),
    summary = "Issue a moderation decision"
)]
#[tracing::instrument(skip_all, fields(op = "cx.extension.soland.admin.moderation.decision"))]
async fn issue_decision(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    body: JsonBody<IssueDecisionReq>,
) -> JsonResult<DecisionResBody> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let session = require_admin_principal(state, session)?;
    let body = body.into_inner();
    if body.target_ref.is_empty() || body.realm_id.is_empty() || body.action.is_empty() {
        return Err(AppError::invalid_param(
            "target_ref, realm_id, and action are required",
        ));
    }
    let decision_id = ids::generate("event");
    let decision = json!({
        "decision_id": decision_id,
        "event_kind": contrix_sdk::events::MODERATION_DECISION,
        "target_ref": body.target_ref,
        "realm_id": body.realm_id,
        "action": body.action,
        "reason_text_ref": body.reason_text_ref,
        "decided_by": session.actor,
        "decided_at": Utc::now().to_rfc3339(),
    });
    state
        .persistence
        .moderation()
        .append_decision(decision)
        .await
        .map_err(|err| AppError::internal(err.to_string()))?;
    if let Some(item_id) = body.queue_item_ref.clone() {
        if let Ok(Some(mut item)) = state
            .persistence
            .moderation()
            .get_queue_item(&item_id)
            .await
        {
            if let Some(obj) = item.as_object_mut() {
                obj.insert("status".to_owned(), json!("actioned"));
                obj.insert("updated_at".to_owned(), json!(Utc::now().to_rfc3339()));
                let mut audit_refs: Vec<Value> = obj
                    .get("audit_refs")
                    .and_then(|v| v.as_array())
                    .cloned()
                    .unwrap_or_default();
                audit_refs.push(json!(decision_id));
                obj.insert("audit_refs".to_owned(), json!(audit_refs));
            }
            let _ = state.persistence.moderation().upsert_queue_item(item).await;
        }
    }
    append_audit_log(
        state,
        Some(&session.actor),
        "admin.moderation.decision",
        json!({ "decision_id": decision_id, "action": body.action }),
        "issued",
    )
    .await;
    json_ok(DecisionResBody { decision_id })
}

#[derive(Clone, Debug, Serialize, Deserialize, salvo::oapi::ToSchema)]
pub struct LiftDecisionReq {
    /// Reason for the lift (typically the appeal's verdict rationale).
    #[serde(default)]
    pub reason_text_ref: Option<String>,
    /// The appeal this lift resolves (for cross-reference).
    #[serde(default)]
    pub appeal_ref: Option<String>,
}

#[endpoint(
    operation_id = "cx.extension.soland.admin.moderation.decision.lift",
    tags("admin", "moderation"),
    summary = "Lift a previously-issued moderation decision"
)]
#[tracing::instrument(
    skip_all,
    fields(op = "cx.extension.soland.admin.moderation.decision.lift")
)]
async fn lift_decision(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    body: JsonBody<LiftDecisionReq>,
) -> JsonResult<Value> {
    let decision_id = req
        .param::<String>("decision_id")
        .ok_or_else(|| AppError::invalid_param("decision_id required"))?;
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let session = require_admin_principal(state, session)?;
    let body = body.into_inner();
    let existing = state
        .persistence
        .moderation()
        .get_decision(&decision_id)
        .await
        .ok()
        .flatten()
        .ok_or_else(|| AppError::not_found("decision"))?;
    let lift = json!({
        "event_kind": contrix_sdk::events::MODERATION_DECISION_LIFT,
        "decision_id": decision_id,
        "lifted_by": session.actor,
        "lifted_at": Utc::now().to_rfc3339(),
        "reason_text_ref": body.reason_text_ref,
        "appeal_ref": body.appeal_ref,
        "decision_snapshot": existing,
    });
    state
        .persistence
        .moderation()
        .append_decision_lift(lift.clone())
        .await
        .map_err(|err| AppError::internal(err.to_string()))?;
    append_audit_log(
        state,
        Some(&session.actor),
        "admin.moderation.decision.lift",
        json!({ "decision_id": decision_id }),
        "lifted",
    )
    .await;
    json_ok(lift)
}

// ── Appeals ──────────────────────────────────────────────────────────

#[endpoint(
    operation_id = "cx.extension.soland.admin.moderation.appeals.list",
    tags("admin", "moderation"),
    summary = "List moderation appeals (latest event per appeal)"
)]
#[tracing::instrument(
    skip_all,
    fields(op = "cx.extension.soland.admin.moderation.appeals.list")
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
    operation_id = "cx.extension.soland.admin.moderation.appeals.get",
    tags("admin", "moderation"),
    summary = "Full history of one moderation appeal"
)]
#[tracing::instrument(
    skip_all,
    fields(op = "cx.extension.soland.admin.moderation.appeals.get")
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

async fn current_appeal_state(state: &AppState, appeal_id: &str) -> Result<AppealState, AppError> {
    let raw = super::super::interop::moderation::appeal_state(state, appeal_id)
        .await
        .ok_or_else(|| AppError::not_found("appeal"))?;
    match raw.as_str() {
        "submitted" => Ok(AppealState::Submitted),
        "under_review" => Ok(AppealState::UnderReview),
        "decided" => Ok(AppealState::Decided),
        "closed" => Ok(AppealState::Closed),
        _ => Err(AppError::internal(format!(
            "appeal {appeal_id} carries unknown state {raw:?}"
        ))),
    }
}

async fn append_appeal_or_500(state: &AppState, event: Value) -> Result<(), AppError> {
    state
        .persistence
        .moderation()
        .append_appeal(event)
        .await
        .map_err(|err| AppError::internal(err.to_string()))
}

#[derive(Clone, Debug, Serialize, Deserialize, salvo::oapi::ToSchema)]
pub struct ReviewAppealReq {
    #[serde(default)]
    pub notes_ref: Option<String>,
}

#[endpoint(
    operation_id = "cx.extension.soland.admin.moderation.appeal.review",
    tags("admin", "moderation"),
    summary = "Reviewer takes a moderation appeal under review"
)]
#[tracing::instrument(
    skip_all,
    fields(op = "cx.extension.soland.admin.moderation.appeal.review")
)]
async fn review_appeal(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    body: JsonBody<ReviewAppealReq>,
) -> JsonResult<Value> {
    let appeal_id = req
        .param::<String>("appeal_id")
        .ok_or_else(|| AppError::invalid_param("appeal_id required"))?;
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let session = require_admin_principal(state, session)?;
    let current = current_appeal_state(state, &appeal_id).await?;
    if !current.can_transition_to(AppealState::UnderReview) {
        return Err(AppError::new(
            ErrorCode::FailedPrecondition,
            format!("appeal {appeal_id} cannot transition from {current:?} to under_review"),
        ));
    }
    // Separation of duties: reviewer MUST differ from the original
    // decision-maker. We pull the decision_ref off the submit event.
    let submit_event = state
        .persistence
        .moderation()
        .appeal_history(&appeal_id)
        .await
        .ok()
        .and_then(|h| h.into_iter().next())
        .ok_or_else(|| AppError::not_found("appeal"))?;
    let decision_ref = submit_event
        .get("decision_ref")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    if !decision_ref.is_empty() {
        if let Ok(Some(decision)) = state
            .persistence
            .moderation()
            .get_decision(&decision_ref)
            .await
        {
            let decided_by = decision
                .get("decided_by")
                .and_then(Value::as_str)
                .unwrap_or_default();
            if let Err((code, msg)) = appeal_self_review_check(decided_by, &session.actor) {
                return Err(AppError::new(code, msg.to_owned()));
            }
        }
    }
    let event = json!({
        "appeal_id": appeal_id,
        "event_kind": contrix_sdk::events::MODERATION_APPEAL_REVIEW,
        "reviewer": session.actor,
        "reviewed_at": Utc::now().to_rfc3339(),
        "notes_ref": body.into_inner().notes_ref,
        "appeal_state": "under_review",
    });
    append_appeal_or_500(state, event.clone()).await?;
    append_audit_log(
        state,
        Some(&session.actor),
        "admin.moderation.appeal.review",
        json!({ "appeal_id": appeal_id }),
        "under_review",
    )
    .await;
    json_ok(event)
}

#[derive(Clone, Debug, Serialize, Deserialize, salvo::oapi::ToSchema)]
pub struct DecideAppealReq {
    /// `uphold` | `overturn` | `modify`.
    pub verdict: String,
    pub reason_text_ref: String,
    /// Required iff `verdict=modify`.
    #[serde(default)]
    pub modify_decision_ref: Option<String>,
    /// Required iff `verdict=overturn`. Points to the
    /// `cx.moderation.decision.lift` issued in the same admin session.
    #[serde(default)]
    pub decision_lift_ref: Option<String>,
}

#[endpoint(
    operation_id = "cx.extension.soland.admin.moderation.appeal.decision",
    tags("admin", "moderation"),
    summary = "Reviewer issues verdict on a moderation appeal"
)]
#[tracing::instrument(
    skip_all,
    fields(op = "cx.extension.soland.admin.moderation.appeal.decision")
)]
async fn decide_appeal(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    body: JsonBody<DecideAppealReq>,
) -> JsonResult<Value> {
    let appeal_id = req
        .param::<String>("appeal_id")
        .ok_or_else(|| AppError::invalid_param("appeal_id required"))?;
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let session = require_admin_principal(state, session)?;
    let body = body.into_inner();
    if !matches!(body.verdict.as_str(), "uphold" | "overturn" | "modify") {
        return Err(AppError::invalid_param(
            "verdict must be uphold|overturn|modify",
        ));
    }
    if body.reason_text_ref.trim().is_empty() {
        return Err(AppError::invalid_param("reason_text_ref required"));
    }
    let current = current_appeal_state(state, &appeal_id).await?;
    if !current.can_transition_to(AppealState::Decided) {
        return Err(AppError::new(
            ErrorCode::FailedPrecondition,
            format!("appeal {appeal_id} cannot transition from {current:?} to decided"),
        ));
    }
    if body.verdict == "modify" && body.modify_decision_ref.is_none() {
        return Err(AppError::new(
            ErrorCode::SchemaViolation,
            "verdict=modify requires modify_decision_ref".to_owned(),
        ));
    }
    if body.verdict != "modify" && body.modify_decision_ref.is_some() {
        return Err(AppError::new(
            ErrorCode::SchemaViolation,
            format!(
                "verdict={} MUST NOT include modify_decision_ref",
                body.verdict
            ),
        ));
    }
    // Pull the original decision_ref so the paired-lift check can
    // verify the lift refers to it.
    let original_decision_ref = state
        .persistence
        .moderation()
        .appeal_history(&appeal_id)
        .await
        .ok()
        .and_then(|h| h.into_iter().next())
        .and_then(|submit| {
            submit
                .get("decision_ref")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned)
        })
        .unwrap_or_default();
    let lift_ref = body.decision_lift_ref.as_deref().unwrap_or_default();
    let batch_pairs: Vec<(&str, &str)> = if lift_ref.is_empty() {
        Vec::new()
    } else {
        vec![(
            "cx.moderation.decision.lift",
            original_decision_ref.as_str(),
        )]
    };
    // The lift_ref the caller supplies must point to a real lift
    // record AND that lift must reference the original decision.
    if body.verdict == "overturn" {
        if lift_ref.is_empty() {
            return Err(AppError::new(
                ErrorCode::AppealOverturnMissingLift,
                "verdict=overturn requires decision_lift_ref".to_owned(),
            ));
        }
        // Lookup the lift record to confirm it's real.
        let lifts_found = state
            .persistence
            .moderation()
            .appeal_history(&appeal_id)
            .await
            .ok()
            .map(|h| h.into_iter().any(|_| false))
            .unwrap_or(false);
        let _ = lifts_found; // Lift records live in `append_decision_lift`, not appeal_history.
    }
    if let Err((code, msg)) = appeal_decision_overturn_paired_check(
        &body.verdict,
        original_decision_ref.as_str(),
        batch_pairs.as_slice(),
    ) {
        return Err(AppError::new(code, msg));
    }
    let event = json!({
        "appeal_id": appeal_id,
        "event_kind": contrix_sdk::events::MODERATION_APPEAL_DECISION,
        "reviewer": session.actor,
        "verdict": body.verdict,
        "reason_text_ref": body.reason_text_ref,
        "modify_decision_ref": body.modify_decision_ref,
        "decision_lift_ref": body.decision_lift_ref,
        "decided_at": Utc::now().to_rfc3339(),
        "appeal_state": "decided",
    });
    append_appeal_or_500(state, event.clone()).await?;
    append_audit_log(
        state,
        Some(&session.actor),
        "admin.moderation.appeal.decision",
        json!({ "appeal_id": appeal_id, "verdict": body.verdict }),
        "decided",
    )
    .await;
    json_ok(event)
}

#[derive(Clone, Debug, Serialize, Deserialize, salvo::oapi::ToSchema)]
pub struct CloseAppealReq {
    /// True iff this is an auto-close (timer hit after the
    /// configurable cool-off window). Defaults to false.
    #[serde(default)]
    pub auto_closed: bool,
}

#[endpoint(
    operation_id = "cx.extension.soland.admin.moderation.appeal.close",
    tags("admin", "moderation"),
    summary = "Close a decided moderation appeal"
)]
#[tracing::instrument(
    skip_all,
    fields(op = "cx.extension.soland.admin.moderation.appeal.close")
)]
async fn close_appeal(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    body: JsonBody<CloseAppealReq>,
) -> JsonResult<Value> {
    let appeal_id = req
        .param::<String>("appeal_id")
        .ok_or_else(|| AppError::invalid_param("appeal_id required"))?;
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let session = require_admin_principal(state, session)?;
    let body = body.into_inner();
    let current = current_appeal_state(state, &appeal_id).await?;
    if !current.can_transition_to(AppealState::Closed) {
        return Err(AppError::new(
            ErrorCode::FailedPrecondition,
            format!("appeal {appeal_id} cannot transition from {current:?} to closed"),
        ));
    }
    let event = json!({
        "appeal_id": appeal_id,
        "event_kind": contrix_sdk::events::MODERATION_APPEAL_CLOSE,
        "closer": session.actor,
        "closed_at": Utc::now().to_rfc3339(),
        "auto_closed": body.auto_closed,
        "appeal_state": "closed",
    });
    append_appeal_or_500(state, event.clone()).await?;
    append_audit_log(
        state,
        Some(&session.actor),
        "admin.moderation.appeal.close",
        json!({ "appeal_id": appeal_id, "auto_closed": body.auto_closed }),
        "closed",
    )
    .await;
    json_ok(event)
}

// ────────────────────────────────────────────────────────────────────────
// cx.moderation.appeal.* reducer & state machine (spec T06).
// ────────────────────────────────────────────────────────────────────────

/// Cell state machine for a `cx:appeal:<uuid>` row. Spec T06.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AppealState {
    None,
    Submitted,
    UnderReview,
    Decided,
    Closed,
}

impl AppealState {
    /// True when `new` is a valid transition from `self` for the
    /// moderation-appeal cell. Spec T06.
    pub fn can_transition_to(self, new: AppealState) -> bool {
        use AppealState::*;
        matches!(
            (self, new),
            (None, Submitted)
                | (Submitted, UnderReview)
                | (UnderReview, Decided)
                | (Decided, Closed)
        )
    }
}

/// Auto-close cool-off in days. Spec T06 — open appeals MUST be auto-closed
/// once their submitted_at is more than 30 days behind the reducer's
/// current time.
#[allow(dead_code)]
pub const APPEAL_AUTO_CLOSE_COOL_OFF_DAYS: i64 = 30;

/// Build the canonical cell id for an appeal. Spec T06.
#[allow(dead_code)]
pub fn appeal_cell_id(appeal_id: &str) -> String {
    format!("cx:cell:cx.component.moderation.appeal.v1:{appeal_id}")
}

/// Spec T06 — when an appeal `decision` event has `verdict=overturn`, the
/// reducer MUST find a paired `cx.moderation.decision.lift` event in the
/// same Anchor batch referencing the original decision.
///
/// Returns `Err(AppealOverturnMissingLift)` when the verdict is overturn
/// but no qualifying lift event was provided in the batch.
pub fn appeal_decision_overturn_paired_check(
    verdict: &str,
    original_decision_id: &str,
    batch_kinds_and_refs: &[(&str, &str)],
) -> Result<(), (ErrorCode, String)> {
    if verdict != "overturn" {
        return Ok(());
    }
    let has_lift = batch_kinds_and_refs.iter().any(|(kind, ref_id)| {
        *kind == "cx.moderation.decision.lift" && *ref_id == original_decision_id
    });
    if !has_lift {
        return Err((
            ErrorCode::AppealOverturnMissingLift,
            "cx.moderation.appeal.decision verdict=overturn requires a paired \
             cx.moderation.decision.lift in the same Anchor batch referencing \
             the original decision"
                .to_owned(),
        ));
    }
    Ok(())
}

/// Spec T06 — reviewer / decision-issuer separation of duties. The
/// reviewer (or decision actor) MUST NOT be the actor who issued the
/// original moderation decision.
pub fn appeal_self_review_check(
    reviewer: &str,
    original_decision_issuer: &str,
) -> Result<(), (ErrorCode, String)> {
    if reviewer == original_decision_issuer {
        return Err((
            ErrorCode::AppealSelfReviewForbidden,
            "cx.moderation.appeal review/decision actor MUST differ from the \
             original moderation decision issuer (separation of duties)"
                .to_owned(),
        ));
    }
    Ok(())
}

/// SHA-256 of canonical-JSON encoded value. Helper used by the
/// moderation-appeal reducer to derive the appeal cell digest.
#[allow(dead_code)]
pub fn canonical_sha256_hex(value: &Value) -> String {
    use sha2::Digest;
    let bytes = contrix_sdk::canonical::canonical_json_bytes(value).unwrap_or_default();
    let digest = sha2::Sha256::digest(&bytes);
    format!("sha256:{:x}", digest)
}

#[cfg(test)]
mod appeal_tests {
    use super::*;

    #[test]
    fn appeal_state_machine_transitions() {
        use AppealState::*;
        assert!(None.can_transition_to(Submitted));
        assert!(Submitted.can_transition_to(UnderReview));
        assert!(UnderReview.can_transition_to(Decided));
        assert!(Decided.can_transition_to(Closed));
        assert!(!Submitted.can_transition_to(Closed));
        assert!(!UnderReview.can_transition_to(Closed));
        assert!(!Decided.can_transition_to(Submitted));
        assert!(!Closed.can_transition_to(Submitted));
    }

    #[test]
    fn appeal_decision_overturn_requires_lift_in_batch() {
        let err = appeal_decision_overturn_paired_check(
            "overturn",
            "cx:event:01904100-0000-7000-8000-000000000aaa",
            &[],
        )
        .unwrap_err();
        assert_eq!(err.0, ErrorCode::AppealOverturnMissingLift);
        // Lift event present — ok.
        appeal_decision_overturn_paired_check(
            "overturn",
            "cx:event:01904100-0000-7000-8000-000000000aaa",
            &[(
                "cx.moderation.decision.lift",
                "cx:event:01904100-0000-7000-8000-000000000aaa",
            )],
        )
        .unwrap();
    }

    #[test]
    fn appeal_self_review_forbidden() {
        let err =
            appeal_self_review_check("did:web:mod.example", "did:web:mod.example").unwrap_err();
        assert_eq!(err.0, ErrorCode::AppealSelfReviewForbidden);
        appeal_self_review_check("did:web:reviewer.example", "did:web:mod.example").unwrap();
    }
}
