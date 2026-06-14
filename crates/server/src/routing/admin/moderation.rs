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
use crate::error::{AppError, ErrorCode};
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

// ────────────────────────────────────────────────────────────────────────
// ck.moderation.appeal.* reducer & state machine (spec T06).
// ────────────────────────────────────────────────────────────────────────

/// Cell state machine for a `ck:appeal:<uuid>` row. Spec T06.
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

/// Build the canonical cell id for an appeal. Spec T06.
#[allow(dead_code)]
pub fn appeal_cell_id(appeal_id: &str) -> String {
    format!("ck:cell:ck.component.moderation.appeal.v1:{appeal_id}")
}

/// Spec T06 — when an appeal `decision` event has `verdict=overturn`, the
/// reducer MUST find a paired `ck.moderation.decision.lift` event in the
/// same Seal batch referencing the original decision.
///
/// Returns `Err(AppealOverturnMissingLift)` when the verdict is overturn
/// but no qualifying lift event was provided in the batch.
///
/// Retained for documentation + unit coverage of the §5.5.2 pairing rule.
/// The authoritative enforcement now runs in the reducer
/// (`reducer/apply_moderation.rs`, surfaced at ingest by
/// `preflight_moderation_projection_reject`) against the projected
/// moderation_state cell rather than against an admin-supplied batch list.
#[allow(dead_code)]
pub fn appeal_decision_overturn_paired_check(
    verdict: &str,
    original_decision_id: &str,
    batch_kinds_and_refs: &[(&str, &str)],
) -> Result<(), (ErrorCode, String)> {
    if verdict != "overturn" {
        return Ok(());
    }
    let has_lift = batch_kinds_and_refs.iter().any(|(kind, ref_id)| {
        *kind == "ck.moderation.decision.lift" && *ref_id == original_decision_id
    });
    if !has_lift {
        return Err((
            ErrorCode::AppealOverturnMissingLift,
            "ck.moderation.appeal.decision verdict=overturn requires a paired \
             ck.moderation.decision.lift in the same Seal batch referencing \
             the original decision"
                .to_owned(),
        ));
    }
    Ok(())
}

/// Spec T06 — reviewer / decision-issuer separation of duties. The
/// reviewer (or decision actor) MUST NOT be the actor who issued the
/// original moderation decision.
///
/// Retained for documentation + unit coverage. The authoritative
/// enforcement now runs in the reducer
/// (`reducer/apply_moderation.rs::enforce_appeal_separation_of_duties`),
/// which reverse-resolves the original decision issuer from the projected
/// moderation_state cell.
#[allow(dead_code)]
pub fn appeal_self_review_check(
    reviewer: &str,
    original_decision_issuer: &str,
) -> Result<(), (ErrorCode, String)> {
    if reviewer == original_decision_issuer {
        return Err((
            ErrorCode::AppealSelfReviewForbidden,
            "ck.moderation.appeal review/decision actor MUST differ from the \
             original moderation decision issuer (separation of duties)"
                .to_owned(),
        ));
    }
    Ok(())
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
            "ck:event:01904100-0000-7000-8000-000000000aaa",
            &[],
        )
        .unwrap_err();
        assert_eq!(err.0, ErrorCode::AppealOverturnMissingLift);
        // Lift event present — ok.
        appeal_decision_overturn_paired_check(
            "overturn",
            "ck:event:01904100-0000-7000-8000-000000000aaa",
            &[(
                "ck.moderation.decision.lift",
                "ck:event:01904100-0000-7000-8000-000000000aaa",
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
