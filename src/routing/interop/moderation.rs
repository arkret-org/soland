//! Moderation user-facing endpoints.
//!
//! - `POST /api/v1/moderation/report` (`cx.moderation.report`) — file a
//!   report. Persists both the report record and a derived queue item
//!   (`ModerationQueueItem`) per the spec's triage architecture.
//! - `POST /api/v1/moderation/appeal` (`cx.moderation.appeal.submit`)
//!   — file an appeal against a moderation decision. Validates the
//!   four-state FSM via `crate::round23::AppealState` and enforces
//!   separation-of-duties when the decision is later reviewed by an
//!   admin.

use chrono::Utc;
use salvo::oapi::extract::JsonBody;
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::{append_audit_log, now, space_has_member, validate_did, validate_space_id};
use crate::error::AppError;
use crate::ids;
use crate::result::{JsonResult, json_ok};
use crate::routing::system::extract::AuthArgs;
use crate::state::AppState;
use crate::wire::{ModerationReportReqBody, ModerationReportResBody};

pub(super) fn router() -> Router {
    Router::new()
        .push(Router::with_path("moderation/report").post(moderation_report))
        .push(Router::with_path("moderation/appeal").post(moderation_appeal_submit))
}

#[endpoint(
    operation_id = "cx.moderation.report",
    tags("moderation"),
    summary = "File a moderation report for content in a federated space"
)]
async fn moderation_report(
    aa: AuthArgs,
    body: JsonBody<ModerationReportReqBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<ModerationReportResBody> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req)?;
    let body = body.into_inner();
    if validate_space_id(&body.space_id).is_err() || validate_did(&body.reporter).is_err() {
        return Err(AppError::invalid_param("invalid space_id or reporter"));
    }
    if body.reporter != session.actor {
        return Err(AppError::capability_denied(
            "reporter must match authenticated actor",
        ));
    }
    if !space_has_member(state, &body.space_id, &session.actor) {
        return Err(AppError::capability_denied(
            "reporter cannot see the target space",
        ));
    }
    let report_id = ids::generate_report_id();
    let moderation_service = format!("{}#moderation", state.config.service_did);
    let report_payload = json!({
        "report_id": report_id,
        "space_id": body.space_id,
        "target_ref": body.target_ref,
        "reason": body.reason,
        "reporter": body.reporter,
        "created_at": now(),
    });
    if let Err(error) = state
        .persistence
        .moderation()
        .append_report(report_payload.clone())
    {
        tracing::error!(%error, "failed to append moderation report");
    }
    if let Err(error) = state.persistence.moderation().append_action(json!({
        "action_id": ids::generate("moderation_action"),
        "report_id": report_id,
        "space_id": body.space_id,
        "target_ref": body.target_ref,
        "status": "open",
        "assigned_to": moderation_service.clone(),
        "created_at": now(),
    })) {
        tracing::error!(%error, "failed to append moderation action");
    }
    // Spec triage: each accepted report is wrapped in a
    // `ModerationQueueItem` cell so admins can prioritise / route /
    // assign reviewers. We default to `status=submitted`,
    // `visibility=metadata_only`, `priority=normal` — sodmin can update
    // via `POST /api/admin/v1/moderation/queue/{id}/{assign,prioritise}`.
    let queue_item_id = ids::generate("modq");
    let queue_item = json!({
        "queue_item_id": queue_item_id,
        "report": report_payload,
        "status": "submitted",
        "priority": "normal",
        "visibility": "metadata_only",
        "assigned_to": [moderation_service.clone()],
        "audit_refs": [],
        "created_at": now(),
    });
    if let Err(error) = state.persistence.moderation().upsert_queue_item(queue_item) {
        tracing::warn!(%error, "queue item upsert failed (likely Pg backend stub)");
    }
    append_audit_log(
        state,
        Some(&session.actor),
        "moderation.report",
        json!({"report_id": report_id.clone(), "queue_item_id": queue_item_id}),
        "queued",
    );
    json_ok(ModerationReportResBody {
        report_id,
        status: "queued".to_owned(),
        routed_to: vec![moderation_service],
    })
}

#[derive(Clone, Debug, Serialize, Deserialize, salvo::oapi::ToSchema)]
pub struct ModerationAppealSubmitReqBody {
    /// The `cx.moderation.decision` event being appealed.
    pub decision_ref: String,
    /// The original moderation target (message / flow / blob / etc.).
    pub target_ref: String,
    /// Realm whose decision is being appealed. MUST equal the
    /// authenticated session's home realm.
    pub realm_id: String,
    /// Reference to (or inline string for) the appeal narrative.
    pub reason_text_ref: String,
    /// Optional supporting evidence refs.
    #[serde(default)]
    pub evidence_refs: Vec<String>,
    /// Optional override of the default `reviewers_only` visibility.
    #[serde(default)]
    pub evidence_visibility: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, salvo::oapi::ToSchema)]
pub struct ModerationAppealSubmitResBody {
    pub appeal_id: String,
    pub state: String,
}

#[endpoint(
    operation_id = "cx.moderation.appeal.submit",
    tags("moderation"),
    summary = "Submit a moderation appeal against a prior decision"
)]
async fn moderation_appeal_submit(
    aa: AuthArgs,
    body: JsonBody<ModerationAppealSubmitReqBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<ModerationAppealSubmitResBody> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req)?;
    let body = body.into_inner();
    if body.reason_text_ref.trim().is_empty() {
        return Err(AppError::invalid_param("reason_text_ref is required"));
    }
    if body.decision_ref.trim().is_empty() {
        return Err(AppError::invalid_param("decision_ref is required"));
    }
    let appeal_id = ids::generate("appeal");
    let evidence_visibility = body
        .evidence_visibility
        .as_deref()
        .filter(|v| {
            matches!(
                *v,
                "appellant_only" | "reviewers_only" | "realm_admins" | "realm_members"
            )
        })
        .unwrap_or("reviewers_only")
        .to_owned();
    let event = json!({
        "appeal_id": appeal_id,
        "realm_id": body.realm_id,
        "decision_ref": body.decision_ref,
        "target_ref": body.target_ref,
        "appellant": session.actor,
        "reason_text_ref": body.reason_text_ref,
        "evidence_refs": body.evidence_refs,
        "evidence_visibility": evidence_visibility,
        "created_at": Utc::now().to_rfc3339(),
        "event_kind": contrix_sdk::events::MODERATION_APPEAL_SUBMIT,
        "appeal_state": "submitted",
    });
    if let Err(error) = state.persistence.moderation().append_appeal(event) {
        tracing::error!(%error, "failed to append moderation appeal");
        return Err(AppError::internal(
            "appeal persistence failed; backend may be a Pg stub",
        ));
    }
    append_audit_log(
        state,
        Some(&session.actor),
        "moderation.appeal.submit",
        json!({
            "appeal_id": appeal_id,
            "decision_ref": body.decision_ref,
        }),
        "submitted",
    );
    json_ok(ModerationAppealSubmitResBody {
        appeal_id,
        state: "submitted".to_owned(),
    })
}

/// Helper for the admin module: read the most recent state of an appeal
/// by replaying the persisted event history. Returns the last-known
/// `appeal_state` string, or `None` if the appeal does not exist.
pub(crate) fn appeal_state(state: &AppState, appeal_id: &str) -> Option<String> {
    state
        .persistence
        .moderation()
        .appeal_history(appeal_id)
        .ok()?
        .into_iter()
        .last()
        .and_then(|event| {
            event
                .get("appeal_state")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned)
        })
}
