//! Canonical `ck.admin.*` endpoints from the public service spec.
//!
//! Per cokret-spec `service-http-binding.md` §2.1 the admin surface is a
//! deployment-local namespace served at the bare `/admin/*` path (NOT under
//! the `/_cokret/...` protocol prefix). These canonical operations share that
//! `/admin/*` namespace with the soland operator infrastructure (anchor DAG,
//! bottom-cell repair, multisig — see [`super::anchor`]) and the admin
//! collection snapshot (see [`super::collection`]); salvo router fallthrough
//! keeps the three sub-trees from colliding.

use salvo::oapi::extract::{JsonBody, PathParam};
use salvo::prelude::*;
use serde_json::{Value, json};

use super::audit::append_audit_log;
use super::require_admin_principal;
use crate::error::AppError;
use crate::result::{JsonResult, json_ok};
use crate::routing::identity::account::{AccountLifecycleChange, set_account_lifecycle_state};
use crate::routing::identity::auth::revoke_device_record;
use crate::routing::system::extract::AuthArgs;
use crate::state::AppState;

pub(super) fn router() -> Router {
    Router::with_path("admin")
        .push(Router::with_path("server/status").get(get_server_status))
        .push(Router::with_path("accounts/{account_id}/status").post(update_account_status))
        .push(Router::with_path("accounts/{account_id}/lock").post(lock_account))
        .push(Router::with_path("accounts/{account_id}/unlock").post(unlock_account))
        .push(Router::with_path("accounts/{account_id}/suspend").post(suspend_account))
        .push(Router::with_path("accounts/{account_id}/unsuspend").post(unsuspend_account))
        .push(Router::with_path("accounts/{account_id}/deactivate").post(deactivate_account))
        .push(Router::with_path("devices/{device_id}/revoke").post(revoke_device))
        // `GET /_soland/admin/moderation/queue` (`ck.admin.get_moderation_queue`)
        // is the canonical queue read. The operator moderation suite in
        // `moderation.rs` owns the remaining `/_soland/admin/moderation/*`
        // sub-paths (queue/{id}/assign, decision, appeals) and
        // deliberately does NOT re-bind the bare `queue` GET to avoid
        // double-binding the single canonical URL.
        .push(Router::with_path("moderation/queue").get(get_moderation_queue))
}

#[endpoint(
    operation_id = "org.cokret.soland.admin.get_server_status",
    tags("admin"),
    summary = "Read canonical service-admin status",
    status_codes(200, 401, 403, 500)
)]
#[tracing::instrument(skip_all, fields(op = "org.cokret.soland.admin.get_server_status"))]
async fn get_server_status(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<Value> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let session = require_admin_principal(state, session)?;
    let account_count = state
        .persistence
        .accounts()
        .list()
        .await
        .map(|items| items.len())
        .ok();
    let device_count = state
        .persistence
        .devices()
        .list()
        .await
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
    operation_id = "org.cokret.soland.admin.update_account_status",
    tags("admin"),
    summary = "Set an account moderation status",
    status_codes(200, 400, 401, 403, 500)
)]
#[tracing::instrument(skip_all, fields(op = "org.cokret.soland.admin.update_account_status"))]
async fn update_account_status(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    account_id: PathParam<String>,
    body: JsonBody<Value>,
) -> JsonResult<Value> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let session = require_admin_principal(state, session)?;
    let account_id = account_id.into_inner();
    let body = body.into_inner();
    let status = body
        .get("status")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| AppError::invalid_param("status is required"))?;
    admin_set_account_status(state, &session.actor, &account_id, &status, body).await
}

#[endpoint(
    operation_id = "org.cokret.soland.admin.lock_account",
    tags("admin"),
    summary = "Lock an account and revoke active access",
    status_codes(200, 400, 401, 403, 404, 409, 500)
)]
#[tracing::instrument(skip_all, fields(op = "org.cokret.soland.admin.lock_account"))]
async fn lock_account(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    account_id: PathParam<String>,
    body: JsonBody<Value>,
) -> JsonResult<Value> {
    admin_account_state_action(aa, depot, req, account_id, body, "locked").await
}

#[endpoint(
    operation_id = "org.cokret.soland.admin.unlock_account",
    tags("admin"),
    summary = "Return a locked account to active state",
    status_codes(200, 400, 401, 403, 404, 409, 500)
)]
#[tracing::instrument(skip_all, fields(op = "org.cokret.soland.admin.unlock_account"))]
async fn unlock_account(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    account_id: PathParam<String>,
    body: JsonBody<Value>,
) -> JsonResult<Value> {
    admin_account_state_action(aa, depot, req, account_id, body, "active").await
}

#[endpoint(
    operation_id = "org.cokret.soland.admin.suspend_account",
    tags("admin"),
    summary = "Suspend an account while leaving existing sessions to expire naturally",
    status_codes(200, 400, 401, 403, 404, 409, 500)
)]
#[tracing::instrument(skip_all, fields(op = "org.cokret.soland.admin.suspend_account"))]
async fn suspend_account(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    account_id: PathParam<String>,
    body: JsonBody<Value>,
) -> JsonResult<Value> {
    admin_account_state_action(aa, depot, req, account_id, body, "suspended").await
}

#[endpoint(
    operation_id = "org.cokret.soland.admin.unsuspend_account",
    tags("admin"),
    summary = "Return a suspended account to active state",
    status_codes(200, 400, 401, 403, 404, 409, 500)
)]
#[tracing::instrument(skip_all, fields(op = "org.cokret.soland.admin.unsuspend_account"))]
async fn unsuspend_account(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    account_id: PathParam<String>,
    body: JsonBody<Value>,
) -> JsonResult<Value> {
    admin_account_state_action(aa, depot, req, account_id, body, "active").await
}

#[endpoint(
    operation_id = "org.cokret.soland.admin.deactivate_account",
    tags("admin"),
    summary = "Deactivate an account and revoke active access",
    status_codes(200, 400, 401, 403, 404, 409, 500)
)]
#[tracing::instrument(skip_all, fields(op = "org.cokret.soland.admin.deactivate_account"))]
async fn deactivate_account(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    account_id: PathParam<String>,
    body: JsonBody<Value>,
) -> JsonResult<Value> {
    admin_account_state_action(aa, depot, req, account_id, body, "deactivated").await
}

async fn admin_account_state_action(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    account_id: PathParam<String>,
    body: JsonBody<Value>,
    next_state: &str,
) -> JsonResult<Value> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let session = require_admin_principal(state, session)?;
    admin_set_account_status(
        state,
        &session.actor,
        &account_id.into_inner(),
        next_state,
        body.into_inner(),
    )
    .await
}

async fn admin_set_account_status(
    state: &AppState,
    admin_actor: &str,
    account_id: &str,
    next_state: &str,
    body: Value,
) -> JsonResult<Value> {
    let reason = body
        .get("reason")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned);
    let change =
        set_account_lifecycle_state(state, account_id, next_state, admin_actor, reason.clone())
            .await?;
    append_audit_log(
        state,
        Some(admin_actor),
        "admin.account.set_status",
        json!({
            "account_id": account_id,
            "status": next_state,
            "reason": reason,
        }),
        "accepted",
    )
    .await;
    json_ok(account_lifecycle_change_response(change))
}

fn account_lifecycle_change_response(change: AccountLifecycleChange) -> Value {
    let did = change.did;
    let state = change.state;
    let changed_by = change.changed_by;
    let changed_at = change.changed_at.to_rfc3339();
    json!({
        "account_id": did.clone(),
        "did": did,
        "previous_state": change.previous_state,
        "state": state.clone(),
        "status": state,
        "reason": change.reason,
        "updated_by": changed_by.clone(),
        "changed_by": changed_by,
        "updated_at": changed_at.clone(),
        "changed_at": changed_at,
        "sessions_revoked": change.sessions_revoked,
        "devices_revoked": change.devices_revoked,
    })
}

#[endpoint(
    operation_id = "org.cokret.soland.admin.revoke_device",
    tags("admin"),
    summary = "Revoke a device as an administrator",
    status_codes(200, 400, 401, 403, 404, 500)
)]
#[tracing::instrument(skip_all, fields(op = "org.cokret.soland.admin.revoke_device"))]
async fn revoke_device(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    device_id: PathParam<String>,
    body: JsonBody<Value>,
) -> JsonResult<Value> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let session = require_admin_principal(state, session)?;
    let device_id = device_id.into_inner();
    let body = body.into_inner();
    let mut target_actor = body
        .get("actor")
        .or_else(|| body.get("account_id"))
        .and_then(Value::as_str)
        .map(str::to_owned);
    if target_actor.is_none() {
        target_actor = state
            .persistence
            .devices()
            .list()
            .await
            .ok()
            .and_then(|devices| {
                devices
                    .into_iter()
                    .find(|record| record.device_id == device_id)
                    .map(|record| record.actor)
            });
    }
    let target_actor = target_actor.ok_or_else(|| AppError::not_found("device not found"))?;
    revoke_device_record(state, &target_actor, &device_id)
        .await
        .map_err(AppError::internal)?;
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
    )
    .await;
    json_ok(json!({
        "actor": target_actor,
        "device_id": device_id,
        "revoked_by": session.actor,
        "revoked_at": super::now().to_rfc3339(),
    }))
}

#[endpoint(
    operation_id = "org.cokret.soland.admin.get_moderation_queue",
    tags("admin", "moderation"),
    summary = "List canonical moderation queue items",
    status_codes(200, 401, 403, 500)
)]
#[tracing::instrument(skip_all, fields(op = "org.cokret.soland.admin.get_moderation_queue"))]
async fn get_moderation_queue(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<Value> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let _ = require_admin_principal(state, session)?;
    let items = state
        .persistence
        .moderation()
        .list_queue_items()
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    let total = items.len();
    json_ok(json!({
        "items": items,
        "total": total,
        "generated_at": super::now().to_rfc3339(),
    }))
}
