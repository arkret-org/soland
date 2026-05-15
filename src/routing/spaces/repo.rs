//! Repository / commit-log surface.
//!
//! Surfaces:
//! - `GET  /api/v1/repo/describe`     — repo manifest (repo_did, signature suites, limits).
//! - `POST /api/v1/repo/operations`   — fetch operations by id (returns
//!   `missing[]` for ids that don't resolve in the projection).
//!
//! Today repo is a thin scaffold over the projection — the durable commit
//! log + Merkle history lives behind `/api/v1/events` / `/api/v1/events/batch-get`.
//! This module exists so the typed describe contract is visible at the
//! advertised path; deeper commit submission lives in
//! `crate::routing::events::event_log` (`POST /api/v1/events`).

use salvo::http::StatusCode;
use salvo::prelude::*;
use serde_json::{Value, json};

use super::render_error;
use crate::state::AppState;

pub(super) fn router() -> Router {
    Router::new()
        .push(Router::with_path("repo/describe").get(repo_describe))
        .push(Router::with_path("repo/operations").post(repo_operations))
}

#[endpoint]
async fn repo_describe(depot: &mut Depot, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    res.render(Json(json!({
        "contract": "contrix.rest.repo_describe.v1",
        "version": "2026-05-15-scaffold",
        "repo_did": state.config.service_did.clone(),
        "head_commit": Value::Null,
        "supported_signatures": ["ed25519-jcs-2022", "eddsa-jcs-2022"],
        "limits": {
            "max_operations_per_commit": 1000,
            "max_commit_bytes": 16 * 1024 * 1024,
        },
    })));
}

#[endpoint]
async fn repo_operations(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let body = match req.parse_json::<Value>().await {
        Ok(value) => value,
        Err(_) => {
            render_error(
                res,
                StatusCode::BAD_REQUEST,
                "bad_json",
                "invalid repo operations request",
            );
            return;
        }
    };
    let ids: Vec<String> = body
        .get("operation_ids")
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(|value| value.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();

    let mut operations: Vec<Value> = Vec::new();
    let mut missing: Vec<String> = Vec::new();
    for id in &ids {
        match state.persistence.events().get(id) {
            Ok(Some(record)) => {
                operations.push(json!({
                    "operation_id": record.event_id,
                    "kind": record.kind,
                    "space_id": record.space_id,
                    "actor": record.actor_id,
                    "schema_id": record.schema_id,
                    "canonical_digest": record.canonical_digest,
                    "envelope": record.envelope,
                    "received_at": record.received_at,
                }));
            }
            _ => missing.push(id.clone()),
        }
    }

    res.render(Json(json!({
        "operations": operations,
        "missing": missing,
    })));
}
