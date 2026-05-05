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

use salvo::{http::StatusCode, prelude::*};
use serde_json::{Value, json};

use crate::{
    ids,
    state::{AppState, DeviceInventoryRecord},
};

use super::{
    append_audit_log, auth_or_render, device_inventory_to_json, now, render_error, sha256_hex,
    validate_device_id,
};

#[handler]
pub async fn device_pairing_challenge(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(session) = auth_or_render(state, req, res) else {
        return;
    };
    let body = match req.parse_json::<Value>().await {
        Ok(body) => body,
        Err(_) => {
            render_error(
                res,
                StatusCode::BAD_REQUEST,
                "bad_json",
                "invalid pairing request",
            );
            return;
        }
    };
    let Some(device_id) = body.get("device_id").and_then(|value| value.as_str()) else {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "missing_param",
            "device_id is required",
        );
        return;
    };
    if validate_device_id(device_id).is_err() {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "invalid device_id",
        );
        return;
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
    res.render(Json(json!({
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
    })));
}

#[handler]
pub async fn device_authorize_pairing(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(session) = auth_or_render(state, req, res) else {
        return;
    };
    let body = match req.parse_json::<Value>().await {
        Ok(body) => body,
        Err(_) => {
            render_error(
                res,
                StatusCode::BAD_REQUEST,
                "bad_json",
                "invalid pairing authorization request",
            );
            return;
        }
    };
    let Some(device_id) = body.get("device_id").and_then(|value| value.as_str()) else {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "missing_param",
            "device_id is required",
        );
        return;
    };
    if validate_device_id(device_id).is_err() {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "invalid device_id",
        );
        return;
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
    if let Err(error) = state.persistence.devices().put(&device) {
        render_error(
            res,
            StatusCode::INTERNAL_SERVER_ERROR,
            "persistence_error",
            &error.to_string(),
        );
        return;
    }
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
    res.render(Json(json!({
        "status": "authorized",
        "device": device_json,
        "authorization_event": authorization_event,
        "production_gap": "authorization_event_not_yet_in_operation_stream",
    })));
}
