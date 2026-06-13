//! E2EE key surfaces.
//!
//! Surfaces:
//! - `POST /_cokret/self/keys/upload` - upload one-time / fallback prekeys with the current device
//!   signature.
//! - `POST /_cokret/self/keys/query` - fetch device key bundles for a peer set.
//! - `POST /_cokret/self/keys/claim` - claim one-time keys, draining the per-device pool.

use std::collections::BTreeMap;

use salvo::oapi::extract::JsonBody;
use salvo::prelude::*;
use serde_json::json;

use super::{is_device_revoked, now};
use crate::error::AppError;
use crate::result::{JsonResult, json_ok};
use crate::routing::system::extract::AuthArgs;
use crate::state::{AppState, DeviceInventoryRecord};
use crate::wire::{
    KeysClaimOutcome, KeysClaimRequestBody, KeysQueryOutcome, KeysQueryRequestBody,
    KeysUploadOutcome, KeysUploadRequestBody,
};

pub(super) fn router() -> Router {
    Router::new()
        .push(Router::with_path("keys/upload").post(keys_upload))
        .push(Router::with_path("keys/query").post(keys_query))
        .push(Router::with_path("keys/claim").post(keys_claim))
}

#[endpoint(
    operation_id = "ck.self.keys.upload.create",
    tags("keys"),
    summary = "Upload device + one-time keys for the current session device"
)]
#[tracing::instrument(skip_all, fields(op = "ck.self.keys.upload.create"))]
async fn keys_upload(
    aa: AuthArgs,
    body: JsonBody<KeysUploadRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<KeysUploadOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    if is_device_revoked(state, &session.actor, &session.device_id).await {
        return Err(AppError::unauthenticated("device revoked"));
    }

    let body = body.into_inner();
    let device_id = body.device_id.as_str().to_owned();
    if device_id != session.device_id {
        return Err(AppError::capability_denied(
            "session device does not match upload device",
        ));
    }

    let one_time_key_count = body.one_time_keys.len() as u64;
    let mut one_time_key_alg_counts = BTreeMap::new();
    for key_id in body.one_time_keys.keys() {
        let algorithm = key_id.split(':').next().unwrap_or(key_id.as_str());
        *one_time_key_alg_counts
            .entry(algorithm.to_owned())
            .or_insert(0) += 1;
    }
    let one_time_keys = body.one_time_keys;
    let fallback_keys = body.fallback_keys;
    let key_payload = json!({
        "device_id": device_id.clone(),
        "one_time_keys": one_time_keys.clone(),
        "fallback_keys": fallback_keys.clone(),
        "device_signature": body.device_signature.clone(),
        "updated_at": now(),
    });
    if let Err(error) = state
        .persistence
        .device_keys()
        .put(
            session.actor.clone(),
            device_id.clone(),
            key_payload.clone(),
        )
        .await
    {
        tracing::error!(%error, "failed to persist device keys");
    }

    let current_device = state
        .persistence
        .devices()
        .get(&session.actor, &device_id)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    let updated_at = now();
    let previous_payload = current_device
        .as_ref()
        .map(|device| device.payload.clone())
        .unwrap_or_else(|| json!({"device_id": device_id.clone()}));
    let device = DeviceInventoryRecord {
        actor: session.actor.clone(),
        device_id: device_id.clone(),
        display_name: current_device
            .as_ref()
            .and_then(|device| device.display_name.clone()),
        verification_state: current_device
            .as_ref()
            .map(|device| device.verification_state.clone())
            .unwrap_or_else(|| "unverified".to_owned()),
        payload: json!({
            "device_id": device_id.clone(),
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
    state
        .persistence
        .devices()
        .put(&device)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;

    if let Err(error) = state
        .persistence
        .one_time_keys()
        .put(
            session.actor,
            device_id,
            one_time_keys.into_values().collect(),
        )
        .await
    {
        tracing::error!(%error, "failed to persist one-time keys");
    }

    one_time_key_alg_counts.insert("total".to_owned(), one_time_key_count);
    json_ok(KeysUploadOutcome {
        one_time_key_counts: one_time_key_alg_counts,
        fallback_keys,
    })
}

#[endpoint(
    operation_id = "ck.self.keys.query.lookup",
    tags("keys"),
    summary = "Fetch device key bundles for a peer set"
)]
#[tracing::instrument(skip_all, fields(op = "ck.self.keys.query.lookup"))]
async fn keys_query(
    aa: AuthArgs,
    body: JsonBody<KeysQueryRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<KeysQueryOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let _ = aa.authenticated_session(state, req).await?;

    let body = body.into_inner();
    let store = state.persistence.device_keys();
    let mut result = BTreeMap::new();
    for (actor, devices) in body.device_keys {
        let mut actor_keys = BTreeMap::new();
        for device_id in devices {
            if is_device_revoked(state, actor.as_str(), device_id.as_str()).await {
                continue;
            }
            if let Ok(Some(key)) = store.get(actor.as_str(), device_id.as_str()).await {
                actor_keys.insert(device_id, key);
            }
        }
        result.insert(actor, actor_keys);
    }
    json_ok(KeysQueryOutcome {
        device_keys: result,
        failures: Vec::new(),
    })
}

#[endpoint(
    operation_id = "ck.self.keys.command.claim",
    tags("keys"),
    summary = "Claim one-time keys, draining the per-device pool"
)]
#[tracing::instrument(skip_all, fields(op = "ck.self.keys.command.claim"))]
async fn keys_claim(
    aa: AuthArgs,
    body: JsonBody<KeysClaimRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<KeysClaimOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let _ = aa.authenticated_session(state, req).await?;

    let body = body.into_inner();
    let store = state.persistence.one_time_keys();
    let mut claimed = BTreeMap::new();
    for (actor, devices) in body.one_time_keys {
        let mut device_map = BTreeMap::new();
        for (device_id, _algorithm) in devices {
            if let Ok(Some(key)) = store.claim(actor.as_str(), device_id.as_str()).await {
                device_map.insert(device_id, key);
            }
        }
        claimed.insert(actor, device_map);
    }
    json_ok(KeysClaimOutcome {
        one_time_keys: claimed,
        failures: Vec::new(),
    })
}
