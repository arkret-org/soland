//! Server-to-server federation handlers.
//!
//! Surfaces:
//! - `PUT /api/v1/federation/transactions/{txn_id}` (idempotent inbound txn)
//! - `POST /api/v1/federation/push-operations`
//! - `GET /api/v1/federation/pull-operations`
//! - `GET /api/v1/federation/space-members`
//! - `POST /api/v1/federation/verify-actor`
//!
//! Stream-C in `_todos.md` covers the production gaps: RFC 9421 transcript
//! (B-06), idempotency (M-20), validation_class instead of bool (M-19),
//! revocation fanout (M-18), and durable persistence beyond
//! `state.federation_operations`.

use chrono::Duration;
use contrix_sdk::SpaceId;
use salvo::{http::StatusCode, prelude::*};
use serde_json::json;

use crate::{
    ids,
    state::{AppState, FederationTransactionRecord},
};

use super::{
    ingest_federation_operations, now, operation_is_visible, query_flag, query_param,
    redaction_targets_from_operations, render_error, sha256_hex, sync_token, validate_space_id,
};

#[endpoint]
pub async fn federation_transaction(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let txn_id = req.param::<String>("txn_id").unwrap_or_else(sync_token);
    if !is_valid_federation_txn_id(&txn_id) {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "invalid federation transaction id",
        );
        return;
    }
    let body = match req
        .parse_json::<contrix_sdk::FederationTransactionRequest>()
        .await
    {
        Ok(body) => body,
        Err(_) => {
            render_error(
                res,
                StatusCode::BAD_REQUEST,
                "bad_json",
                "invalid federation transaction request",
            );
            return;
        }
    };
    let content_digest = match federation_request_digest(&body) {
        Ok(digest) => digest,
        Err(message) => {
            render_error(res, StatusCode::BAD_REQUEST, "invalid_param", message);
            return;
        }
    };
    match state
        .persistence
        .federation_transactions()
        .get(body.origin.as_str(), &txn_id)
    {
        Ok(Some(record)) if record.content_digest == content_digest => {
            res.render(Json(record.response));
            return;
        }
        Ok(Some(_)) => {
            render_error(
                res,
                StatusCode::CONFLICT,
                "duplicate_conflict",
                "federation transaction id was reused with different content",
            );
            return;
        }
        Ok(None) => {}
        Err(error) => {
            if error.to_string().contains("invalid_cursor") {
                render_error(
                    res,
                    StatusCode::BAD_REQUEST,
                    "invalid_cursor",
                    "cursor not found",
                );
                return;
            }
            render_error(
                res,
                StatusCode::INTERNAL_SERVER_ERROR,
                "persistence_error",
                &error.to_string(),
            );
            return;
        }
    }
    if !verify_federation_origin(body.origin.as_str()) {
        render_error(
            res,
            StatusCode::UNAUTHORIZED,
            "invalid_origin",
            "federation origin must be a valid DID",
        );
        return;
    }
    if !federation_destination_matches(state, body.destination.as_str()) {
        render_error(
            res,
            StatusCode::FORBIDDEN,
            "invalid_destination",
            "federation transaction destination does not match this service",
        );
        return;
    }
    let ingest = ingest_federation_operations(state, body.origin.as_str(), body.operations);
    let response = contrix_sdk::FederationTransactionResponse {
        ok: true,
        accepted: ingest.accepted,
        rejected: ingest.rejected,
        next_retry_at: None,
    };
    let response_value = match serde_json::to_value(&response) {
        Ok(value) => value,
        Err(error) => {
            render_error(
                res,
                StatusCode::INTERNAL_SERVER_ERROR,
                "serialization_error",
                &error.to_string(),
            );
            return;
        }
    };
    let now = now();
    let record = FederationTransactionRecord {
        origin: body.origin.to_string(),
        txn_id,
        destination: body.destination.to_string(),
        space_id: None,
        content_digest,
        status: "accepted".to_owned(),
        response: response_value,
        received_at: now,
        processed_at: Some(now),
    };
    if let Err(error) = state.persistence.federation_transactions().put(&record) {
        render_error(
            res,
            StatusCode::INTERNAL_SERVER_ERROR,
            "persistence_error",
            &error.to_string(),
        );
        return;
    }
    res.render(Json(response));
}

#[endpoint]
pub async fn federation_push_operations(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let body = match req
        .parse_json::<contrix_sdk::FederationPushOperationsRequest>()
        .await
    {
        Ok(body) => body,
        Err(_) => {
            render_error(
                res,
                StatusCode::BAD_REQUEST,
                "bad_json",
                "invalid federation push operations request",
            );
            return;
        }
    };
    if !verify_federation_origin(body.origin.as_str()) {
        render_error(
            res,
            StatusCode::UNAUTHORIZED,
            "invalid_origin",
            "federation origin must be a valid DID",
        );
        return;
    }
    if !federation_destination_matches(state, body.destination.as_str()) {
        render_error(
            res,
            StatusCode::FORBIDDEN,
            "invalid_destination",
            "federation push destination does not match this service",
        );
        return;
    }
    let ingest = ingest_federation_operations(state, body.origin.as_str(), body.operations);
    res.render(Json(contrix_sdk::FederationPushOperationsResponse {
        accepted: ingest.accepted,
        rejected: ingest.rejected,
        quarantine: Vec::new(),
    }));
}

#[endpoint]
pub async fn federation_pull_operations(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(space_id) = query_param(req, "space_id") else {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "missing_param",
            "space_id is required",
        );
        return;
    };
    if validate_space_id(&space_id).is_err() {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "invalid space_id",
        );
        return;
    }
    let after_cursor = query_param(req, "after_cursor");
    let limit = query_param(req, "limit")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(100)
        .min(100);
    let space_operations: Vec<_> = state
        .federation_operations
        .lock()
        .expect("federation lock")
        .iter()
        .filter(|operation| operation.space_id.as_str() == space_id)
        .cloned()
        .collect();
    let redacted = redaction_targets_from_operations(&space_operations);
    let snapshot_bootstrap = query_flag(req, "snapshot_bootstrap").then(|| {
        let manifest = json!({
            "type": "snapshot_bootstrap",
            "space_id": space_id,
            "snapshot_ref": ids::generate_snapshot_id(),
            "operation_count": space_operations.len(),
            "created_at": now(),
        });
        let state_hash = format!("sha256:{}", sha256_hex(manifest.to_string().as_bytes()));
        json!({
            "manifest": manifest,
            "state_hash": state_hash,
            "chunks": [],
            "via_services": [state.config.service_did.clone()],
        })
    });
    let mut seen_cursor = after_cursor.is_none();
    let mut operations = Vec::new();
    for operation in space_operations {
        if !seen_cursor {
            seen_cursor = Some(operation.operation_id.as_str()) == after_cursor.as_deref();
            continue;
        }
        if !operation_is_visible(&operation, &redacted) {
            continue;
        }
        if operations.len() == limit + 1 {
            break;
        }
        operations.push(operation);
    }
    let has_more = operations.len() > limit;
    if has_more {
        operations.truncate(limit);
    }
    let next_cursor = operations
        .last()
        .map(|operation| operation.operation_id.to_string())
        .or_else(|| Some(sync_token()));
    res.render(Json(contrix_sdk::FederationPullOperationsResponse {
        operations,
        snapshot_bootstrap,
        next_cursor,
        has_more,
    }));
}

#[endpoint]
pub async fn federation_space_members(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(space_id) = query_param(req, "space_id") else {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "missing_param",
            "space_id is required",
        );
        return;
    };
    let Ok(space_id_value) = SpaceId::new(space_id.clone()) else {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "invalid space_id",
        );
        return;
    };
    let members = state
        .spaces
        .lock()
        .expect("spaces lock")
        .get(&space_id_value)
        .map(|space| {
            space
                .members
                .iter()
                .map(|principal_id| contrix_sdk::MemberRef {
                    principal_id: principal_id.clone(),
                    membership: json!({"membership": "join"}),
                })
                .collect()
        })
        .unwrap_or_default();
    res.render(Json(contrix_sdk::FederationSpaceMembersResponse {
        members,
        membership_frontier: sync_token(),
        next_cursor: None,
    }));
}

#[endpoint]
pub async fn federation_verify_actor(req: &mut Request, res: &mut Response) {
    let body = match req
        .parse_json::<contrix_sdk::FederationVerifyActorRequest>()
        .await
    {
        Ok(body) => body,
        Err(_) => {
            render_error(
                res,
                StatusCode::BAD_REQUEST,
                "bad_json",
                "invalid federation verify actor request",
            );
            return;
        }
    };
    res.render(Json(contrix_sdk::FederationVerifyActorResponse {
        valid: true,
        actor_id: body.actor_id.clone(),
        verified_key_id: Some(format!("{}#dev", body.actor_id)),
        key_log_head: None,
        did_document_ref: Some(format!("{}#document", body.actor_id)),
        expires_at: Some(now() + Duration::minutes(5)),
        warnings: Vec::new(),
    }));
}

fn verify_federation_origin(origin: &str) -> bool {
    if !origin.starts_with("did:") {
        return false;
    }
    let rest = &origin[4..];
    if let Some(colon_pos) = rest.find(':') {
        let method = &rest[..colon_pos];
        let name = &rest[colon_pos + 1..];
        !method.is_empty() && method.chars().all(|c| c.is_ascii_lowercase()) && !name.is_empty()
    } else {
        false
    }
}

fn federation_destination_matches(state: &AppState, destination: &str) -> bool {
    destination == state.config.service_did
}

fn is_valid_federation_txn_id(value: &str) -> bool {
    let value = value.trim();
    !value.is_empty()
        && value.len() <= 128
        && value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.' | ':' | '$'))
}

fn federation_request_digest(
    body: &contrix_sdk::FederationTransactionRequest,
) -> Result<String, &'static str> {
    let value =
        serde_json::to_value(body).map_err(|_| "federation transaction must serialize to JSON")?;
    contrix_sdk::canonical::canonical_sha256(&value)
        .map_err(|_| "federation transaction must be canonical JSON")
}
