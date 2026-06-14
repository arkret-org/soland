//! Product-local soland operator endpoints.
//!
//! The public Cokret protocol namespace does not define `ck.admin.*`
//! operations. soland serves operator-only controls under `/_soland/admin/*`
//! with local `org.cokret.soland.*` operation IDs. These endpoints share that
//! namespace with the soland operator infrastructure (seal DAG, bottom-cell
//! repair, multisig -- see [`super::seal`]) and the admin collection snapshot
//! (see [`super::collection`]); salvo router fallthrough keeps the three
//! sub-trees from colliding.

use salvo::oapi::extract::{JsonBody, PathParam};
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::audit::append_audit_log;
use super::require_admin_principal;
use crate::error::AppError;
use crate::result::{JsonResult, json_ok};
use crate::routing::identity::account::{AccountLifecycleChange, set_account_lifecycle_state};
use crate::routing::identity::auth::revoke_device_record;
use crate::routing::system::extract::AuthArgs;
use crate::state::AppState;

#[derive(Clone, Debug, Serialize, Deserialize, salvo::oapi::ToSchema)]
struct AdminServerStatusCounts {
    accounts: Option<usize>,
    devices: Option<usize>,
    realms: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize, salvo::oapi::ToSchema)]
struct AdminServerStatusOutcome {
    status: String,
    service_did: String,
    storage: String,
    development_mode: bool,
    checked_by: String,
    generated_at: String,
    counts: AdminServerStatusCounts,
}

#[derive(Clone, Debug, Serialize, Deserialize, salvo::oapi::ToSchema)]
struct AdminAccountStatusRequestBody {
    status: String,
    #[serde(default)]
    reason: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, salvo::oapi::ToSchema)]
struct AdminAccountStateActionRequestBody {
    #[serde(default)]
    reason: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, salvo::oapi::ToSchema)]
struct AdminAccountLifecycleOutcome {
    account_id: String,
    did: String,
    previous_state: String,
    state: String,
    status: String,
    reason: Option<String>,
    updated_by: String,
    changed_by: String,
    updated_at: String,
    changed_at: String,
    sessions_revoked: usize,
    devices_revoked: usize,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, salvo::oapi::ToSchema)]
struct AdminRevokeDeviceRequestBody {
    #[serde(default)]
    actor: Option<String>,
    #[serde(default)]
    account_id: Option<String>,
    #[serde(default)]
    reason: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, salvo::oapi::ToSchema)]
struct AdminRevokeDeviceOutcome {
    actor: String,
    device_id: String,
    revoked_by: String,
    revoked_at: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, salvo::oapi::ToSchema)]
struct AdminModerationQueueOutcome {
    items: Vec<Value>,
    total: usize,
    generated_at: String,
}

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
        // `GET /_soland/admin/moderation/queue` is the local queue read.
        // The operator moderation suite in
        // `moderation.rs` owns the remaining `/_soland/admin/moderation/*`
        // sub-paths (queue/{id}/assign, decision, appeals) and
        // deliberately does NOT re-bind the bare `queue` GET to avoid
        // double-binding the single URL.
        .push(Router::with_path("moderation/queue").get(get_moderation_queue))
}

#[endpoint(
    operation_id = "org.cokret.soland.admin.get_server_status",
    tags("admin"),
    summary = "Read operator admin status",
    status_codes(200, 401, 403, 500)
)]
#[tracing::instrument(skip_all, fields(op = "org.cokret.soland.admin.get_server_status"))]
async fn get_server_status(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AdminServerStatusOutcome> {
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
    json_ok(AdminServerStatusOutcome {
        status: "ok".to_owned(),
        service_did: state.config.service_did.clone(),
        storage: state.db.mode().to_owned(),
        development_mode: state.config.development_mode,
        checked_by: session.actor,
        generated_at: super::now().to_rfc3339(),
        counts: AdminServerStatusCounts {
            accounts: account_count,
            devices: device_count,
            realms: realm_count,
        },
    })
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
    body: JsonBody<AdminAccountStatusRequestBody>,
) -> JsonResult<AdminAccountLifecycleOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let session = require_admin_principal(state, session)?;
    let account_id = account_id.into_inner();
    let body = body.into_inner();
    let status = body.status.trim();
    if status.is_empty() {
        return Err(AppError::invalid_param("status is required"));
    }
    let status = status.to_owned();
    admin_set_account_status(state, &session.actor, &account_id, &status, body.reason).await
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
    body: JsonBody<AdminAccountStateActionRequestBody>,
) -> JsonResult<AdminAccountLifecycleOutcome> {
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
    body: JsonBody<AdminAccountStateActionRequestBody>,
) -> JsonResult<AdminAccountLifecycleOutcome> {
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
    body: JsonBody<AdminAccountStateActionRequestBody>,
) -> JsonResult<AdminAccountLifecycleOutcome> {
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
    body: JsonBody<AdminAccountStateActionRequestBody>,
) -> JsonResult<AdminAccountLifecycleOutcome> {
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
    body: JsonBody<AdminAccountStateActionRequestBody>,
) -> JsonResult<AdminAccountLifecycleOutcome> {
    admin_account_state_action(aa, depot, req, account_id, body, "deactivated").await
}

async fn admin_account_state_action(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    account_id: PathParam<String>,
    body: JsonBody<AdminAccountStateActionRequestBody>,
    next_state: &str,
) -> JsonResult<AdminAccountLifecycleOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let session = require_admin_principal(state, session)?;
    admin_set_account_status(
        state,
        &session.actor,
        &account_id.into_inner(),
        next_state,
        body.into_inner().reason,
    )
    .await
}

async fn admin_set_account_status(
    state: &AppState,
    admin_actor: &str,
    account_id: &str,
    next_state: &str,
    reason: Option<String>,
) -> JsonResult<AdminAccountLifecycleOutcome> {
    let reason = reason
        .as_deref()
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

fn account_lifecycle_change_response(
    change: AccountLifecycleChange,
) -> AdminAccountLifecycleOutcome {
    let did = change.did;
    let state = change.state;
    let changed_by = change.changed_by;
    let changed_at = change.changed_at.to_rfc3339();
    AdminAccountLifecycleOutcome {
        account_id: did.clone(),
        did,
        previous_state: change.previous_state,
        state: state.clone(),
        status: state,
        reason: change.reason,
        updated_by: changed_by.clone(),
        changed_by,
        updated_at: changed_at.clone(),
        changed_at,
        sessions_revoked: change.sessions_revoked,
        devices_revoked: change.devices_revoked,
    }
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
    body: JsonBody<AdminRevokeDeviceRequestBody>,
) -> JsonResult<AdminRevokeDeviceOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let session = require_admin_principal(state, session)?;
    let device_id = device_id.into_inner();
    let body = body.into_inner();
    let mut target_actor = body.actor.or(body.account_id);
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
            "reason": body.reason,
        }),
        "accepted",
    )
    .await;
    json_ok(AdminRevokeDeviceOutcome {
        actor: target_actor,
        device_id,
        revoked_by: session.actor,
        revoked_at: super::now().to_rfc3339(),
    })
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
) -> JsonResult<AdminModerationQueueOutcome> {
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
    json_ok(AdminModerationQueueOutcome {
        items,
        total,
        generated_at: super::now().to_rfc3339(),
    })
}
