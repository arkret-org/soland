//! Canonical `/api/v1/admin/*` endpoints from the public service spec.
//!
//! These are distinct from `/api/admin/v1/*`, which remains soland operator
//! infrastructure for anchor DAG, bottom-cell repair, and multisig internals.

use salvo::oapi::extract::{JsonBody, PathParam};
use salvo::prelude::*;
use serde_json::{Value, json};

use super::audit::append_audit_log;
use super::require_admin_principal;
use crate::error::AppError;
use crate::result::{JsonResult, json_ok};
use crate::routing::identity::auth::revoke_device_record;
use crate::routing::system::extract::AuthArgs;
use crate::state::AppState;

pub(super) fn router() -> Router {
    Router::with_path("admin")
        .push(Router::with_path("server/status").get(get_server_status))
        .push(Router::with_path("accounts/{account_id}/status").post(update_account_status))
        .push(Router::with_path("devices/{device_id}/revoke").post(revoke_device))
        .push(Router::with_path("moderation/queue").get(get_moderation_queue))
}

#[endpoint(
    operation_id = "cx.admin.get_server_status",
    tags("admin"),
    summary = "Read canonical service-admin status",
    status_codes(200, 401, 403, 500)
)]
#[tracing::instrument(skip_all, fields(op = "cx.admin.get_server_status"))]
async fn get_server_status(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<Value> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req)?;
    let session = require_admin_principal(state, session)?;
    let account_count = state
        .persistence
        .accounts()
        .list()
        .map(|items| items.len())
        .ok();
    let device_count = state
        .persistence
        .devices()
        .list()
        .map(|items| items.len())
        .ok();
    let realm_count = state
        .realms
        .lock()
        .expect("realms lock")
        .search(Default::default())
        .len();
    json_ok(json!({
        "status": "ok",
        "service_did": state.config.service_did.clone(),
        "storage": state.db.mode(),
        "development_mode": state.config.development_mode,
        "checked_by": session.actor,
        "generated_at": super::now().to_rfc3339(),
        "counts": {
            "accounts": account_count,
            "devices": device_count,
            "realms": realm_count,
        },
    }))
}

#[endpoint(
    operation_id = "cx.admin.update_account_status",
    tags("admin"),
    summary = "Set an account moderation status",
    status_codes(200, 400, 401, 403, 500)
)]
#[tracing::instrument(skip_all, fields(op = "cx.admin.update_account_status"))]
async fn update_account_status(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    account_id: PathParam<String>,
    body: JsonBody<Value>,
) -> JsonResult<Value> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req)?;
    let session = require_admin_principal(state, session)?;
    let account_id = account_id.into_inner();
    let body = body.into_inner();
    let status = body
        .get("status")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| AppError::invalid_param("status is required"))?;
    let reason = body
        .get("reason")
        .and_then(Value::as_str)
        .map(str::to_owned);
    append_audit_log(
        state,
        Some(&session.actor),
        "admin.account.set_status",
        json!({
            "account_id": account_id.clone(),
            "status": status,
            "reason": reason.clone(),
        }),
        "accepted",
    );
    json_ok(json!({
        "account_id": account_id,
        "status": status,
        "reason": reason,
        "updated_by": session.actor,
        "updated_at": super::now().to_rfc3339(),
    }))
}

#[endpoint(
    operation_id = "cx.admin.revoke_device",
    tags("admin"),
    summary = "Revoke a device as an administrator",
    status_codes(200, 400, 401, 403, 404, 500)
)]
#[tracing::instrument(skip_all, fields(op = "cx.admin.revoke_device"))]
async fn revoke_device(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    device_id: PathParam<String>,
    body: JsonBody<Value>,
) -> JsonResult<Value> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req)?;
    let session = require_admin_principal(state, session)?;
    let device_id = device_id.into_inner();
    let body = body.into_inner();
    let target_actor = body
        .get("actor")
        .or_else(|| body.get("account_id"))
        .and_then(Value::as_str)
        .map(str::to_owned)
        .or_else(|| {
            state.persistence.devices().list().ok().and_then(|devices| {
                devices
                    .into_iter()
                    .find(|record| record.device_id == device_id)
                    .map(|record| record.actor)
            })
        })
        .ok_or_else(|| AppError::not_found("device not found"))?;
    revoke_device_record(state, &target_actor, &device_id).map_err(AppError::internal)?;
    append_audit_log(
        state,
        Some(&session.actor),
        "admin.device.revoke",
        json!({
            "actor": target_actor.clone(),
            "device_id": device_id.clone(),
            "reason": body.get("reason").cloned(),
        }),
        "accepted",
    );
    json_ok(json!({
        "actor": target_actor,
        "device_id": device_id,
        "revoked_by": session.actor,
        "revoked_at": super::now().to_rfc3339(),
    }))
}

#[endpoint(
    operation_id = "cx.admin.get_moderation_queue",
    tags("admin", "moderation"),
    summary = "List canonical moderation queue items",
    status_codes(200, 401, 403, 500)
)]
#[tracing::instrument(skip_all, fields(op = "cx.admin.get_moderation_queue"))]
async fn get_moderation_queue(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<Value> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req)?;
    let _ = require_admin_principal(state, session)?;
    let items = state
        .persistence
        .moderation()
        .list_queue_items()
        .map_err(|error| AppError::internal(error.to_string()))?;
    let total = items.len();
    json_ok(json!({
        "items": items,
        "total": total,
        "generated_at": super::now().to_rfc3339(),
    }))
}
