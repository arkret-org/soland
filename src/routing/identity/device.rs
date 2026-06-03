//! Device-pairing handlers.
//!
//! Surfaces:
//! - `POST /_cokret/self/devices/pairing-challenge` — current device asks the server to mint a
//!   short-lived pairing challenge for a new sibling device
//! - `POST /_cokret/self/devices/authorize-pairing` — current device authorises the sibling and registers
//!   it in the device inventory
//!
//! Both routes are scaffolds: the proof at `body.proof` is accepted as
//! `{"alg":"dev-none"}` by default and the authorization event is built
//! but NOT yet pushed into the canonical operation stream (durable
//! persistence + revocation propagation are future work).

use salvo::oapi::extract::JsonBody;
use salvo::prelude::*;
use serde_json::{Value, json};

use super::{AuthArgs, append_audit_log, device_inventory_to_json, now, sha256_hex};
use crate::error::AppError;
use crate::state::{AppState, DeviceInventoryRecord};
use crate::{JsonResult, ids, json_ok};

pub(super) fn router() -> Router {
    Router::new()
        .push(Router::with_path("devices").get(device_list))
        .push(Router::with_path("devices/pairing-challenge").post(device_pairing_challenge))
        .push(Router::with_path("devices/authorize-pairing").post(device_authorize_pairing))
        .push(Router::with_path("devices/{device_id}/revoke").post(device_revoke))
        .push(Router::with_path("devices/{device_id}/rename").post(device_rename))
}

#[endpoint(
    operation_id = "cx.devices.list",
    tags("devices"),
    summary = "List active devices for the authenticated principal",
    status_codes(200, 401, 500)
)]
#[tracing::instrument(skip_all, fields(op = "cx.devices.list"))]
async fn device_list(aa: AuthArgs, depot: &mut Depot, req: &mut Request) -> JsonResult<Value> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let devices = state
        .persistence
        .devices()
        .list_for_actor(&session.actor)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
        .into_iter()
        .map(|record| {
            let mut value = device_inventory_to_json(&record);
            if let Some(object) = value.as_object_mut() {
                object.insert(
                    "is_current_session_device".to_owned(),
                    json!(record.device_id == session.device_id),
                );
            }
            value
        })
        .collect::<Vec<_>>();
    json_ok(json!({
        "actor": session.actor,
        "current_device_id": session.device_id,
        "devices": devices,
    }))
}

#[endpoint(
    operation_id = "cx.devices.revoke",
    tags("devices"),
    summary = "Revoke a sibling device. Self-revoke (revoking the calling session's own device) is rejected with cannot_self_revoke",
    status_codes(200, 400, 401, 404, 500)
)]
#[tracing::instrument(skip_all, fields(op = "cx.devices.revoke"))]
async fn device_revoke(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    device_id: salvo::oapi::extract::PathParam<String>,
) -> JsonResult<Value> {
    // Spec: identity/device-lifecycle.md §7 — a device MUST NOT revoke
    // itself (avoids self-lockout); revocation MUST be issued from a
    // peer / sibling device that is still controlled by the principal.
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let target_device_id = device_id.into_inner();
    if target_device_id == session.device_id {
        return Err(AppError::invalid_param(
            "a device cannot revoke itself; revoke from a peer device",
        )
        .with_wire_code("cannot_self_revoke"));
    }
    let existing = state
        .persistence
        .devices()
        .get(&session.actor, &target_device_id)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    let Some(_record) = existing else {
        return Err(AppError::not_found("device not found"));
    };
    super::auth::revoke_device_record(state, &session.actor, &target_device_id)
        .await
        .map_err(AppError::internal)?;
    append_audit_log(
        state,
        Some(&session.actor),
        "device.revoke",
        json!({
            "revoked_device_id": target_device_id.clone(),
            "by_device_id": session.device_id,
        }),
        "accepted",
    )
    .await;
    json_ok(json!({
        "revoked_device_id": target_device_id,
        "revoked_at": now().to_rfc3339(),
    }))
}

/// Maximum length (in Unicode scalar values) of a device `display_name`,
/// aligned with the actor / profile `display_name` bound in
/// `cokret-spec` (`models/actor.md`, `discovery/profiles-presence.md`).
const DEVICE_DISPLAY_NAME_MAX_CHARS: usize = 128;

#[endpoint(
    operation_id = "cx.devices.rename",
    tags("devices"),
    summary = "Rename a device the caller controls (update its user-facing display_name)",
    status_codes(200, 400, 401, 404, 500)
)]
#[tracing::instrument(skip_all, fields(op = "cx.devices.rename"))]
async fn device_rename(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    device_id: salvo::oapi::extract::PathParam<String>,
    body: JsonBody<Value>,
) -> JsonResult<Value> {
    // Spec: crypto-media/device-lifecycle.md §4 — `display_name` is the
    // optional, user-facing, mutable device name; the canonical id is
    // always `device_id`. Renaming only touches display metadata, never
    // device trust / authorization state.
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let target_device_id = device_id.into_inner();
    let body = body.into_inner();
    let display_name = body
        .get("display_name")
        .and_then(|value| value.as_str())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| AppError::missing_param("display_name is required"))?;
    if display_name.chars().count() > DEVICE_DISPLAY_NAME_MAX_CHARS {
        return Err(AppError::invalid_param(format!(
            "display_name must be at most {DEVICE_DISPLAY_NAME_MAX_CHARS} characters"
        ))
        .with_wire_code("display_name_too_long"));
    }
    let existing = state
        .persistence
        .devices()
        .get(&session.actor, &target_device_id)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    let Some(mut record) = existing else {
        return Err(AppError::not_found("device not found"));
    };
    if record.revoked_at.is_some() {
        return Err(AppError::invalid_param("cannot rename a revoked device")
            .with_wire_code("device_revoked"));
    }
    let updated_at = now();
    record.display_name = Some(display_name.to_owned());
    if let Some(object) = record.payload.as_object_mut() {
        object.insert("display_name".to_owned(), json!(display_name));
        object.insert("last_seen_at".to_owned(), json!(updated_at));
    }
    record.updated_at = updated_at;
    state
        .persistence
        .devices()
        .put(&record)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    append_audit_log(
        state,
        Some(&session.actor),
        "device.rename",
        json!({
            "device_id": target_device_id,
            "by_device_id": session.device_id,
            "display_name": display_name,
        }),
        "accepted",
    )
    .await;
    let mut value = device_inventory_to_json(&record);
    if let Some(object) = value.as_object_mut() {
        object.insert(
            "is_current_session_device".to_owned(),
            json!(record.device_id == session.device_id),
        );
    }
    json_ok(value)
}

#[endpoint(
    operation_id = "cx.devices.pairing_challenge",
    tags("devices"),
    summary = "Mint a short-lived device pairing challenge"
)]
#[tracing::instrument(skip_all, fields(op = "cx.devices.pairing_challenge"))]
async fn device_pairing_challenge(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    body: JsonBody<Value>,
) -> JsonResult<Value> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let body = body.into_inner();
    let device_id = body
        .get("device_id")
        .and_then(|value| value.as_str())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| AppError::missing_param("device_id is required"))?;
    let challenge_id = ids::generate("device_pairing");
    let expires_at = now() + chrono::Duration::minutes(5);
    let nonce = ids::generate("nonce");
    let canonical = json!({
        "challenge_id": challenge_id,
        "actor": session.actor.clone(),
        "authorizing_device_id": session.device_id.clone(),
        "device_id": device_id,
        "nonce": nonce,
        "expires_at": expires_at,
    });
    append_audit_log(
        state,
        Some(&session.actor),
        "device.pairing_challenge",
        json!({
            "device_id": session.device_id,
            "target_device_id": device_id,
            "challenge_id": challenge_id,
        }),
        "accepted",
    )
    .await;
    json_ok(json!({
        "challenge_id": challenge_id,
        "actor": session.actor,
        "authorizing_device_id": session.device_id,
        "device_id": device_id,
        "expires_at": expires_at,
        "methods": ["same_account_session", "out_of_band_code"],
        "challenge": {
            "type": "sha256-dev",
            "nonce": nonce,
            "canonical": canonical,
            "digest": format!("sha256:{}", sha256_hex(canonical.to_string().as_bytes())),
        },
        "production_gap": "device_pairing_proof_verification",
    }))
}

#[endpoint(
    operation_id = "cx.devices.authorize_pairing",
    tags("devices"),
    summary = "Authorise and register a paired sibling device"
)]
#[tracing::instrument(skip_all, fields(op = "cx.devices.authorize_pairing"))]
async fn device_authorize_pairing(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    body: JsonBody<Value>,
) -> JsonResult<Value> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let body = body.into_inner();
    let device_id = body
        .get("device_id")
        .and_then(|value| value.as_str())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| AppError::missing_param("device_id is required"))?;
    let challenge_id = body
        .get("challenge_id")
        .and_then(|value| value.as_str())
        .unwrap_or("dev-unbound-challenge");
    let created_at = now();
    let device = DeviceInventoryRecord {
        actor: session.actor.clone(),
        device_id: device_id.to_owned(),
        display_name: body
            .get("display_name")
            .and_then(|value| value.as_str())
            .map(ToOwned::to_owned),
        verification_state: "verified".to_owned(),
        payload: json!({
            "pairing": {
                "challenge_id": challenge_id,
                "authorized_by_device_id": session.device_id,
                "authorized_at": created_at,
                "proof": body.get("proof").cloned().unwrap_or_else(|| json!({"alg": "dev-none"})),
            }
        }),
        created_at,
        updated_at: created_at,
        revoked_at: None,
    };
    state
        .persistence
        .devices()
        .put(&device)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    let device_json = device_inventory_to_json(&device);
    let authorization_event = json!({
        "event_id": ids::generate_event_id(),
        "event_kind": "cx.device.pairing.authorized",
        "actor": session.actor.clone(),
        "device_id": device_id,
        "authorized_by_device_id": session.device_id.clone(),
        "challenge_id": challenge_id,
        "created_at": created_at,
    });
    append_audit_log(
        state,
        Some(&session.actor),
        "device.authorize_pairing",
        json!({
            "device_id": session.device_id,
            "target_device_id": device_id,
            "challenge_id": challenge_id,
            "authorization_event": authorization_event,
        }),
        "accepted",
    )
    .await;
    json_ok(json!({
        "status": "authorized",
        "device": device_json,
        "authorization_event": authorization_event,
        "production_gap": "authorization_event_not_yet_in_operation_stream",
    }))
}
