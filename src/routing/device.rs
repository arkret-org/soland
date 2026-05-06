//! Device-pairing handlers.
//!
//! Surfaces:
//! - `POST /api/v1/devices/pairing-challenge` — current device asks the
//!   server to mint a short-lived pairing challenge for a new sibling device
//! - `POST /api/v1/devices/authorize-pairing` — current device authorises the
//!   sibling and registers it in the device inventory
//!
//! Both routes are scaffolds: the proof at `body.proof` is accepted as
//! `{"alg":"dev-none"}` by default and the authorization event is built but
//! NOT yet pushed into the canonical operation stream (Stream-F-2 in
//! `_todos.md` covers durable persistence + revocation propagation).

use salvo::oapi::extract::JsonBody;
use salvo::prelude::*;
use serde_json::{Value, json};

use crate::{
    JsonResult,
    error::AppError,
    ids, json_ok,
    state::{AppState, DeviceInventoryRecord},
};

use super::{
    AuthArgs, append_audit_log, device_inventory_to_json, now, sha256_hex, validate_device_id,
};

#[endpoint(
    operation_id = "cx.devices.pairing_challenge",
    tags("devices"),
    summary = "Mint a short-lived device pairing challenge",
)]
pub async fn device_pairing_challenge(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    body: JsonBody<Value>,
) -> JsonResult<Value> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req)?;
    let body = body.into_inner();
    let device_id = body
        .get("device_id")
        .and_then(|value| value.as_str())
        .ok_or_else(|| AppError::missing_param("device_id is required"))?;
    if validate_device_id(device_id).is_err() {
        return Err(AppError::invalid_param("invalid device_id"));
    }
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
    );
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
    summary = "Authorise and register a paired sibling device",
)]
pub async fn device_authorize_pairing(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    body: JsonBody<Value>,
) -> JsonResult<Value> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req)?;
    let body = body.into_inner();
    let device_id = body
        .get("device_id")
        .and_then(|value| value.as_str())
        .ok_or_else(|| AppError::missing_param("device_id is required"))?;
    if validate_device_id(device_id).is_err() {
        return Err(AppError::invalid_param("invalid device_id"));
    }
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
        .map_err(|error| AppError::internal(error.to_string()))?;
    let device_json = device_inventory_to_json(&device);
    state
        .devices
        .lock()
        .expect("devices lock")
        .entry(session.actor.clone())
        .or_default()
        .insert(device_id.to_owned(), device_json.clone());
    let authorization_event = json!({
        "event_id": ids::generate_event_id(),
        "event_type": "cx.device.pairing.authorized",
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
    );
    json_ok(json!({
        "status": "authorized",
        "device": device_json,
        "authorization_event": authorization_event,
        "production_gap": "authorization_event_not_yet_in_operation_stream",
    }))
}
