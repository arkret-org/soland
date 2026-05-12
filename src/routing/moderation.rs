//! Moderation report handler.
//!
//! Surface: `POST /api/v1/moderation/report`. Backed by
//! `state.persistence.moderation()`. Tier 6-D in `_todos.md` covers the async
//! review workflow + reducer linkage.

use salvo::{http::StatusCode, prelude::*};
use serde_json::json;

use crate::{
    ids,
    state::AppState,
    wire::{ModerationReportRequest, ModerationReportResponse},
};

use super::{
    append_audit_log, auth_or_render, now, render_error, space_has_member, validate_did,
    validate_space_id,
};

pub fn router() -> Router {
    Router::with_path("moderation/report").post(moderation_report)
}

#[endpoint]
async fn moderation_report(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(session) = auth_or_render(state, req, res) else {
        return;
    };
    let body = match req.parse_json::<ModerationReportRequest>().await {
        Ok(body) => body,
        Err(_) => {
            render_error(
                res,
                StatusCode::BAD_REQUEST,
                "bad_json",
                "invalid moderation report request",
            );
            return;
        }
    };
    if validate_space_id(&body.space_id).is_err() || validate_did(&body.reporter).is_err() {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "invalid space_id or reporter",
        );
        return;
    }
    if body.reporter != session.actor {
        render_error(
            res,
            StatusCode::FORBIDDEN,
            "capability_denied",
            "reporter must match authenticated actor",
        );
        return;
    }
    if !space_has_member(state, &body.space_id, &session.actor) {
        render_error(
            res,
            StatusCode::FORBIDDEN,
            "capability_denied",
            "reporter cannot see the target space",
        );
        return;
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
    res.render(Json(ModerationReportResponse {
        report_id,
        status: "queued".to_owned(),
        routed_to: vec![moderation_service],
    }));
}
