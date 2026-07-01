//! `GET`/`PUT /_soland/admin/settings` — read and hot-swap the mutable
//! operational overlay ([`crate::runtime_settings::RuntimeSettings`]).
//!
//! - `GET` returns the full **effective** settings (env defaults with any persisted overrides
//!   applied).
//! - `PUT` takes a **partial** `{ key: value }` object and changes only the keys present (PATCH
//!   semantics). Each changed key is upserted into its own `server_settings` row (keys never sent
//!   keep following their env default), then the whole snapshot is atomically hot-swapped via
//!   [`arc_swap::ArcSwap`] so the next request — rate limiter, admin allowlist, federation fanout —
//!   observes the change with no restart.
//!
//! Gated by the shared `RequireAdmin` hoop like the rest of `/_soland/admin/*`
//! (the same posture under which `control.rs` serves its admin writes).
//!
//! Boundary reminder: this endpoint deliberately does NOT touch Tier-1 boot
//! config (bind address, `DATABASE_URL`, service DID, TLS paths, signing
//! seeds). Those are secrets or pre-DB bootstrap and stay in env.

use std::sync::Arc;

use salvo::http::StatusCode;
use salvo::prelude::*;
use serde_json::{Map, Value};

use super::AuthArgs;
use crate::error::{AppError, ErrorCode};
use crate::runtime_settings::{self, RuntimeSettings};
use crate::state::AppState;
use crate::{JsonResult, json_ok};

pub(super) fn router() -> Router {
    Router::with_path("admin/settings")
        .get(get_settings)
        .put(put_settings)
}

fn encode(settings: &RuntimeSettings) -> Result<Value, AppError> {
    serde_json::to_value(settings)
        .map_err(|error| AppError::internal(format!("encode settings: {error}")))
}

#[handler]
async fn get_settings(depot: &mut Depot, req: &mut Request) -> JsonResult<Value> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let _session = AuthArgs::default()
        .authenticated_session(state, req)
        .await?;
    json_ok(encode(&state.settings())?)
}

#[handler]
async fn put_settings(depot: &mut Depot, req: &mut Request) -> JsonResult<Value> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = AuthArgs::default()
        .authenticated_session(state, req)
        .await?;

    let patch: Map<String, Value> = req.parse_json().await.map_err(|error| {
        AppError::new(
            ErrorCode::InvalidParam,
            format!("settings body must be a JSON object of key -> value: {error}"),
        )
        .with_status(StatusCode::BAD_REQUEST)
    })?;
    if patch.is_empty() {
        return Err(AppError::new(
            ErrorCode::InvalidParam,
            "settings patch must set at least one key".to_owned(),
        )
        .with_status(StatusCode::BAD_REQUEST));
    }

    // Validate the whole patch against a working copy before touching the DB,
    // so an unknown key or bad shape rejects the entire request atomically.
    let mut next = (*state.settings()).clone();
    for (key, value) in &patch {
        next.apply_key(key, value.clone()).map_err(|error| {
            AppError::new(ErrorCode::InvalidParam, error.to_string())
                .with_status(StatusCode::BAD_REQUEST)
        })?;
    }

    // Persist each changed key as its own row, using the post-normalization
    // canonical value so the stored row always matches what is enforced.
    // Memory-mode deployments skip persistence and keep the swap only.
    if let Some(pool) = state.db.pool.as_ref() {
        for key in patch.keys() {
            let canonical = next
                .key_value(key)
                .map_err(|error| AppError::internal(format!("encode setting `{key}`: {error}")))?;
            runtime_settings::store_override(pool, key, &canonical, &session.actor)
                .await
                .map_err(|error| AppError::internal(format!("persist setting `{key}`: {error}")))?;
        }
    }
    state.settings.store(Arc::new(next.clone()));

    let changed_keys: Vec<&String> = patch.keys().collect();
    super::audit::append_audit_log(
        state,
        Some(&session.actor),
        "org.cokret.soland.admin.settings.update",
        serde_json::json!({ "changed_keys": changed_keys }),
        "ok",
    )
    .await;
    json_ok(encode(&next)?)
}
