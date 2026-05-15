//! E2EE key surfaces.
//!
//! Surfaces:
//! - `POST /api/v1/keys/upload` - upload one-time / fallback prekeys with the current device
//!   signature.
//! - `POST /api/v1/keys/query` - fetch device key bundles for a peer set.
//! - `POST /api/v1/keys/claim` - claim one-time keys, draining the per-device pool.

use salvo::http::StatusCode;
use salvo::prelude::*;
use serde_json::json;

use super::{auth_or_render, is_device_revoked, now, render_error, validate_device_id};
use crate::state::{AppState, DeviceInventoryRecord};
use crate::wire::{
    KeysClaimRequest, KeysClaimResponse, KeysQueryRequest, KeysQueryResponse, KeysUploadRequest,
    KeysUploadResponse,
};

pub(super) fn router() -> Router {
    Router::new()
        .push(Router::with_path("keys/upload").post(keys_upload))
        .push(Router::with_path("keys/query").post(keys_query))
        .push(Router::with_path("keys/claim").post(keys_claim))
}

#[endpoint]
async fn keys_upload(depot: &mut Depot, req: &mut Request, res: &mut Response) {
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
    if body.device_id.trim().is_empty() {
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

    let one_time_key_count = body.one_time_keys.len() as u64;
    let mut one_time_key_alg_counts: std::collections::BTreeMap<String, u64> =
        std::collections::BTreeMap::new();
    for key in &body.one_time_keys {
        let alg = key
            .get("algorithm")
            .and_then(|value| value.as_str())
            .or_else(|| key.get("alg").and_then(|value| value.as_str()))
            .unwrap_or("signed_curve25519")
            .to_owned();
        *one_time_key_alg_counts.entry(alg).or_insert(0) += 1;
    }
    let key_payload = json!({
        "device_id": body.device_id.clone(),
        "device_keys": body.device_keys.clone(),
        "principal_signing_keys": body.principal_signing_keys.clone(),
        "recovery_keys": body.recovery_keys.clone(),
        "session_keys": body.session_keys.clone(),
        "agent_keys": body.agent_keys.clone(),
        "mls_key_packages": body.mls_key_packages.clone(),
        "backup_restore_keys": body.backup_restore_keys.clone(),
        "fallback_keys": body.fallback_keys.clone(),
        "device_signature": body.device_signature.clone(),
        "updated_at": now(),
    });
    if let Err(error) = state.persistence.device_keys().put(
        session.actor.clone(),
        body.device_id.clone(),
        key_payload.clone(),
    ) {
        tracing::error!(%error, "failed to persist device keys");
    }

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

    if let Err(error) =
        state
            .persistence
            .one_time_keys()
            .put(session.actor, body.device_id, body.one_time_keys)
    {
        tracing::error!(%error, "failed to persist one-time keys");
    }

    let mut counts_value = serde_json::Map::new();
    counts_value.insert("total".to_owned(), json!(one_time_key_count));
    for (alg, count) in one_time_key_alg_counts {
        counts_value.insert(alg, json!(count));
    }
    res.render(Json(KeysUploadResponse {
        one_time_key_counts: json!(counts_value),
        fallback_keys: body.fallback_keys,
    }));
}

#[endpoint]
async fn keys_query(depot: &mut Depot, req: &mut Request, res: &mut Response) {
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
    let store = state.persistence.device_keys();
    let mut result = serde_json::Map::new();
    for (actor, devices) in body.device_keys {
        let mut actor_keys = serde_json::Map::new();
        for device_id in devices {
            if is_device_revoked(state, &actor, &device_id) {
                continue;
            }
            if let Ok(Some(key)) = store.get(&actor, &device_id) {
                actor_keys.insert(device_id, key);
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
async fn keys_claim(depot: &mut Depot, req: &mut Request, res: &mut Response) {
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
    let store = state.persistence.one_time_keys();
    let mut claimed = serde_json::Map::new();
    for (actor, devices) in body.one_time_keys {
        let mut device_map = serde_json::Map::new();
        for (device_id, _algorithm) in devices {
            if let Ok(Some(key)) = store.claim(&actor, &device_id) {
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
