//! Moderation report handler.
//!
//! Surface: `POST /api/v1/moderation/report`. Backed by
//! `state.persistence.moderation()`. Async review workflow + reducer
//! linkage are future work.

use salvo::oapi::extract::JsonBody;
use salvo::prelude::*;
use serde_json::json;

use super::{append_audit_log, now, space_has_member, validate_did, validate_space_id};
use crate::error::AppError;
use crate::ids;
use crate::result::{JsonResult, json_ok};
use crate::routing::system::extract::AuthArgs;
use crate::state::AppState;
use crate::wire::{ModerationReportReqBody, ModerationReportResBody};

pub(super) fn router() -> Router {
    Router::with_path("moderation/report").post(moderation_report)
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
    if let Err(error) = state.persistence.moderation().append_report(json!({
        "report_id": report_id,
        "space_id": body.space_id,
        "target_ref": body.target_ref,
        "reason": body.reason,
        "reporter": body.reporter,
    })) {
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
    append_audit_log(
        state,
        Some(&session.actor),
        "moderation.report",
        json!({"report_id": report_id.clone()}),
        "queued",
    );
    json_ok(ModerationReportResBody {
        report_id,
        status: "queued".to_owned(),
        routed_to: vec![moderation_service],
    })
}
