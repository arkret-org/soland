//! Moderation report handler.
//!
//! Surface: `POST /api/v1/moderation/report`. Backed by in-memory
//! `state.moderation_reports` + `state.moderation_actions`. Stream-E in
//! `_todos.md` covers the durable persistence + async workflow.

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

#[endpoint]
pub async fn moderation_report(depot: &mut Depot, req: &mut Request, res: &mut Response) {
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
    state
        .moderation_reports
        .lock()
        .expect("moderation lock")
        .push(json!({"report_id": report_id, "space_id": body.space_id, "target_ref": body.target_ref, "reason": body.reason, "reporter": body.reporter}));
    state
        .moderation_actions
        .lock()
        .expect("moderation action lock")
        .push(json!({
            "action_id": ids::generate("moderation_action"),
            "report_id": report_id,
            "space_id": body.space_id,
            "target_ref": body.target_ref,
            "status": "open",
            "assigned_to": moderation_service.clone(),
            "created_at": now(),
        }));
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
