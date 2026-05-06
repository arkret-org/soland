//! E2EE key surfaces.
//!
//! Surfaces:
//! - `POST /api/v1/keys/upload` — upload device + principal + recovery + agent
//!   + session keys, MLS key packages, fallback + one-time keys
//! - `POST /api/v1/keys/query`  — fetch device key bundles for a peer set
//!   (revoked devices are filtered out at read time, see auth.rs::is_device_revoked)
//! - `POST /api/v1/keys/claim`  — claim one-time keys (drains the per-device pool)
//!
//! `state.device_keys` and `state.one_time_keys` are still in-memory; F-2 in
//! `_todos.md` covers persistence + reducer A13 (`cx.device.{authorized,
//! revoked, list_update}`) write-through. The encrypted-backup CRUD lives
//! separately in `routing/key_backup_restore.rs`.

use salvo::{http::StatusCode, prelude::*};
use serde_json::json;

use crate::{
    state::{AppState, DeviceInventoryRecord},
    wire::{
        KeysClaimRequest, KeysClaimResponse, KeysQueryRequest, KeysQueryResponse,
        KeysUploadRequest, KeysUploadResponse,
    },
};

use super::{
    auth_or_render, device_inventory_to_json, is_device_revoked, now, render_error,
    validate_device_id,
};

#[endpoint]
pub async fn keys_upload(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(session) = auth_or_render(state, req, res) else {
        return;
    };
    if is_device_revoked(state, &session.actor, &session.device_id) {
        render_error(
            res,
            StatusCode::UNAUTHORIZED,
            "unauthenticated",
            "device revoked",
        );
        return;
    }
    let body = match req.parse_json::<KeysUploadRequest>().await {
        Ok(body) => body,
        Err(_) => {
            render_error(
                res,
                StatusCode::BAD_REQUEST,
                "bad_json",
                "invalid keys upload request",
            );
            return;
        }
    };
    if validate_device_id(&body.device_id).is_err() {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "invalid device_id",
        );
        return;
    }
    if body.device_id != session.device_id {
        render_error(
            res,
            StatusCode::FORBIDDEN,
            "capability_denied",
            "session device does not match upload device",
        );
        return;
    }
    let key_payload = json!({
            "device_id": body.device_id.clone(),
            "device_keys": body.device_keys.clone(),
            "principal_signing_keys": body.principal_signing_keys.clone(),
            "recovery_keys": body.recovery_keys.clone(),
            "session_keys": body.session_keys.clone(),
            "agent_keys": body.agent_keys.clone(),
            "fallback_keys": body.fallback_keys.clone(),
            "device_signature": body.device_signature.clone(),
            "mls_key_packages": body.mls_key_packages.clone(),
            "backup_restore_keys": body.backup_restore_keys.clone(),
            "updated_at": now()
    });
    state.device_keys.lock().expect("device keys lock").insert(
        (session.actor.clone(), body.device_id.clone()),
        key_payload.clone(),
    );
    // TODO(P0 durable-state): persist device_keys, one_time_keys, fallback_keys
    // and MLS key packages in the dedicated Pg tables instead of this memory cache.
    let current_device = match state
        .persistence
        .devices()
        .get(&session.actor, &body.device_id)
    {
        Ok(device) => device,
        Err(error) => {
            render_error(
                res,
                StatusCode::INTERNAL_SERVER_ERROR,
                "persistence_error",
                &error.to_string(),
            );
            return;
        }
    };
    let updated_at = now();
    let previous_payload = current_device
        .as_ref()
        .map(|device| device.payload.clone())
        .unwrap_or_else(|| json!({"device_id": body.device_id.clone()}));
    let device = DeviceInventoryRecord {
        actor: session.actor.clone(),
        device_id: body.device_id.clone(),
        display_name: current_device
            .as_ref()
            .and_then(|device| device.display_name.clone()),
        verification_state: current_device
            .as_ref()
            .map(|device| device.verification_state.clone())
            .unwrap_or_else(|| "unverified".to_owned()),
        payload: json!({
            "device_id": body.device_id.clone(),
            "display_name": current_device
                .as_ref()
                .and_then(|device| device.display_name.clone()),
            "verification": current_device
                .as_ref()
                .map(|device| device.verification_state.as_str())
                .unwrap_or("unverified"),
            "last_key_upload_at": updated_at,
            "inventory": previous_payload,
        }),
        created_at: current_device
            .as_ref()
            .map(|device| device.created_at)
            .unwrap_or(updated_at),
        updated_at,
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
    state
        .devices
        .lock()
        .expect("devices lock")
        .entry(session.actor.clone())
        .or_default()
        .insert(body.device_id.clone(), device_inventory_to_json(&device));
    state
        .one_time_keys
        .lock()
        .expect("one time keys lock")
        .insert((session.actor, body.device_id), body.one_time_keys.clone());
    res.render(Json(KeysUploadResponse {
        one_time_key_counts: json!({"signed_curve25519": body.one_time_keys.len()}),
        fallback_keys: body.fallback_keys,
    }));
}

#[endpoint]
pub async fn keys_query(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    if auth_or_render(state, req, res).is_none() {
        return;
    }
    let body = req
        .parse_json::<KeysQueryRequest>()
        .await
        .unwrap_or(KeysQueryRequest {
            device_keys: Default::default(),
            timeout_ms: None,
        });
    let keys = state.device_keys.lock().expect("device keys lock");
    let mut result = serde_json::Map::new();
    for (actor, devices) in body.device_keys {
        let mut actor_keys = serde_json::Map::new();
        for device_id in devices {
            if is_device_revoked(state, &actor, &device_id) {
                continue;
            }
            if let Some(key) = keys.get(&(actor.clone(), device_id.clone())) {
                actor_keys.insert(device_id, key.clone());
            }
        }
        result.insert(actor, json!(actor_keys));
    }
    res.render(Json(KeysQueryResponse {
        device_keys: json!(result),
        failures: json!({}),
    }));
}

#[endpoint]
pub async fn keys_claim(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    if auth_or_render(state, req, res).is_none() {
        return;
    }
    let body = req
        .parse_json::<KeysClaimRequest>()
        .await
        .unwrap_or(KeysClaimRequest {
            one_time_keys: Default::default(),
        });
    let mut stored = state.one_time_keys.lock().expect("one time keys lock");
    let mut claimed = serde_json::Map::new();
    for (actor, devices) in body.one_time_keys {
        let mut device_map = serde_json::Map::new();
        for (device_id, _algorithm) in devices {
            if let Some(keys) = stored.get_mut(&(actor.clone(), device_id.clone()))
                && let Some(key) = keys.pop()
            {
                device_map.insert(device_id, key);
            }
        }
        claimed.insert(actor, json!(device_map));
    }
    res.render(Json(KeysClaimResponse {
        one_time_keys: json!(claimed),
        failures: json!({}),
    }));
}
