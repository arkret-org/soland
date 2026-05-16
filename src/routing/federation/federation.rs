//! Server-to-server federation handlers.
//!
//! Surfaces:
//! - `PUT /api/v1/federation/transactions/{txn_id}` (idempotent inbound txn)
//! - `POST /api/v1/federation/push-operations`
//! - `GET /api/v1/federation/pull-operations`
//! - `GET /api/v1/federation/space-members`
//! - `POST /api/v1/federation/verify-actor`
//! - **MAL-12 round 25**: `GET /api/v1/federation/anchors?space_id=...` (peer-pull: list
//!   locally-held Anchors for a Space) + `POST /api/v1/federation/anchors` (peer-push: accept
//!   Anchor envelopes for replication). The wire path is identical for both
//!   [`crate::config::FederationPolicy::Mesh`] and [`crate::config::FederationPolicy::Hub`]; only
//!   the outbound routing decision (broadcast vs hub-only) differs.
//!
//! Stream-C in `_todos.md` covers the production gaps: RFC 9421 transcript
//! (B-06), idempotency (M-20), validation_class instead of bool (M-19),
//! revocation fanout (M-18), and durable persistence beyond
//! `state.federation_operations`.

use chrono::Duration;
use contrix_sdk::state_res::AnchorStore;
use contrix_sdk::{Anchor, SpaceId};
use salvo::http::StatusCode;
use salvo::oapi::extract::{JsonBody, QueryParam};
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::json;

use super::{
    ingest_federation_operations, now, operation_is_visible, query_flag, query_param,
    redaction_targets_from_operations, render_error, sha256_hex, sync_token, validate_space_id,
};
use crate::error::AppError;
use crate::ids;
use crate::result::{JsonResult, json_ok};
use crate::state::{AppState, FederationTransactionRecord};

#[endpoint]
pub(super) async fn federation_transaction(
    depot: &mut Depot,
    req: &mut Request,
    res: &mut Response,
) {
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
pub(super) async fn federation_push_operations(
    depot: &mut Depot,
    req: &mut Request,
    res: &mut Response,
) {
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
pub(super) async fn federation_pull_operations(
    depot: &mut Depot,
    req: &mut Request,
    res: &mut Response,
) {
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
    let space_operations = state
        .persistence
        .federation_operations()
        .list_for_space(&space_id)
        .unwrap_or_default();
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
pub(super) async fn federation_space_members(
    depot: &mut Depot,
    req: &mut Request,
    res: &mut Response,
) {
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
pub(super) async fn federation_verify_actor(req: &mut Request, res: &mut Response) {
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

// ── MAL-12 round 25 — Anchor pull/push (federation/anchors) ──────────────

#[derive(Clone, Debug, Default, Serialize, Deserialize, salvo::oapi::ToSchema)]
pub struct FederationAnchorsResponse {
    pub anchors: Vec<Anchor>,
    /// Echo of [`crate::config::FederationPolicy::as_str`] so the calling
    /// peer can reason about whether to fan out to other nodes.
    pub policy: String,
    pub next_cursor: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, salvo::oapi::ToSchema)]
pub struct FederationAnchorsPushRequest {
    pub origin: String,
    pub anchors: Vec<Anchor>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, salvo::oapi::ToSchema)]
pub struct FederationAnchorsPushResponse {
    pub accepted: Vec<String>,
    pub rejected: Vec<serde_json::Value>,
}

#[endpoint(
    operation_id = "cx.federation.anchors.pull",
    tags("federation"),
    summary = "Pull locally-held Anchors for a Space (federation peer-pull)"
)]
pub(super) async fn federation_anchors_pull(
    depot: &mut Depot,
    space_id: QueryParam<String, true>,
) -> JsonResult<FederationAnchorsResponse> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let space_id = space_id.into_inner();
    if validate_space_id(&space_id).is_err() {
        return Err(AppError::invalid_param("invalid space_id"));
    }
    let space =
        SpaceId::new(space_id).map_err(|_| AppError::invalid_param("invalid space_id"))?;
    let leaves = state.anchor_store.list_leaves(&space).unwrap_or_default();
    let mut anchors: Vec<Anchor> = Vec::with_capacity(leaves.len());
    for leaf in &leaves {
        if let Ok(Some(a)) = state.anchor_store.get(leaf) {
            anchors.push(a);
        }
    }
    json_ok(FederationAnchorsResponse {
        anchors,
        policy: state.config.federation_policy.as_str().to_owned(),
        next_cursor: None,
    })
}

#[endpoint(
    operation_id = "cx.federation.anchors.push",
    tags("federation"),
    summary = "Accept Anchor envelopes from a federation peer (peer-push)"
)]
pub(super) async fn federation_anchors_push(
    depot: &mut Depot,
    body: JsonBody<FederationAnchorsPushRequest>,
) -> JsonResult<FederationAnchorsPushResponse> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let body = body.into_inner();
    if !verify_federation_origin(&body.origin) {
        return Err(AppError::new(
            crate::error::ErrorCode::Unauthenticated,
            "federation origin must be a valid DID",
        )
        .with_status(StatusCode::UNAUTHORIZED));
    }
    let mut accepted: Vec<String> = Vec::new();
    let mut rejected: Vec<serde_json::Value> = Vec::new();
    for anchor in body.anchors {
        let id_str = anchor.id.to_string();
        // Only accept Anchors whose declared id matches the canonical hash
        // — otherwise a peer could overwrite our DAG with junk.
        match anchor.derive_id() {
            Ok(derived) if derived == anchor.id => {}
            _ => {
                rejected.push(json!({"id": id_str, "reason": "id_mismatch"}));
                continue;
            }
        }
        if let Err(error) = state.anchor_store.put(&anchor) {
            rejected.push(
                json!({"id": id_str, "reason": "persistence_error", "message": error.to_string()}),
            );
            continue;
        }
        accepted.push(id_str);
    }
    json_ok(FederationAnchorsPushResponse { accepted, rejected })
}

/// MAL-12 round 25 — outbound Move broadcast helper. Each accepted Move
/// goes to:
/// - [`FederationPolicy::Mesh`]: every peer in `state.config.federation_peers`.
/// - [`FederationPolicy::Hub`]: only the first peer (`federation_peers[0]`).
///
/// Returns the list of peer URLs the broadcast targeted; the actual HTTP
/// dispatch is fire-and-forget (best-effort) and runs on a background
/// tokio task so the inbound write path never blocks on a slow peer.
#[allow(dead_code)]
pub fn broadcast_move_to_peers(state: &AppState, move_id: &str) -> Vec<String> {
    use crate::config::FederationPolicy;
    let peers: Vec<String> = match state.config.federation_policy {
        FederationPolicy::Mesh => state.config.federation_peers.clone(),
        FederationPolicy::Hub => state
            .config
            .federation_peers
            .first()
            .cloned()
            .into_iter()
            .collect(),
    };
    for peer in &peers {
        let peer = peer.clone();
        let move_id_owned = move_id.to_owned();
        tokio::spawn(async move {
            // Best-effort fan-out. Real outbound transcript signing /
            // retry-with-jitter lives behind this entry point in a
            // follow-up; for now we just log so ops can see the
            // broadcast list.
            tracing::debug!(%peer, move_id = %move_id_owned, "federation broadcast move");
        });
    }
    peers
}

/// Symmetric helper for Anchor replication. The hub policy still pushes
/// to a single upstream so the broadcast list is `[hub]`; mesh fans out
/// to every peer.
#[allow(dead_code)]
pub fn broadcast_anchor_to_peers(state: &AppState, anchor_id: &str) -> Vec<String> {
    use crate::config::FederationPolicy;
    let peers: Vec<String> = match state.config.federation_policy {
        FederationPolicy::Mesh => state.config.federation_peers.clone(),
        FederationPolicy::Hub => state
            .config
            .federation_peers
            .first()
            .cloned()
            .into_iter()
            .collect(),
    };
    for peer in &peers {
        let peer = peer.clone();
        let anchor_id_owned = anchor_id.to_owned();
        tokio::spawn(async move {
            tracing::debug!(%peer, anchor_id = %anchor_id_owned, "federation broadcast anchor");
        });
    }
    peers
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::str::FromStr;

    use super::*;
    use crate::config::{AppConfig, FederationPolicy};
    use crate::db::Db;
    use crate::state::AppState;

    fn config_with_policy(policy: FederationPolicy, peers: Vec<String>) -> AppConfig {
        AppConfig {
            bind: SocketAddr::from_str("127.0.0.1:0").unwrap(),
            public_base_url: "http://test".to_owned(),
            service_did: "did:web:test.local".to_owned(),
            tls_cert_path: None,
            tls_key_path: None,
            database_url: None,
            object_storage: crate::config::ObjectStorageConfig::local(std::env::temp_dir()),
            cors_allow_origin: None,
            auth_server_url: None,
            development_mode: true,
            oauth_introspection_url: None,
            oauth_introspection_bearer: None,
            session_grant_introspection_url: None,
            session_grant_introspection_bearer: None,
            did_resolver_allow_methods: vec!["web".to_owned()],
            embedded_webvh_provider_enabled: false,
            embedded_webvh_registration_bearer: None,
            external_webvh_provider_url: None,
            external_webvh_provider_active: false,
            default_webvh_provider_id: None,
            jws_replay_window_seconds: 0,
            jws_replay_window_per_family: AppConfig::default_replay_overrides(),
            anchorer_signing_key_seed: None,
            use_keystore: false,
            federation_policy: policy,
            federation_peers: peers,
            admin_default_page_limit: 100,
            admin_max_page_limit: 1000,
            admin_principal_dids: Vec::new(),
            push_bridge_cache_ttl_seconds: 900,
            push_bridge_trusted_service_dids: Vec::new(),
            compaction_min_anchor_age_seconds: 604_800,
            compaction_min_witnesses: 1,
            compaction_preserve_genesis: true,
            compaction_prune_only_singleton_successors: true,
        }
    }

    #[tokio::test]
    async fn mesh_policy_broadcasts_to_every_peer() {
        let cfg = config_with_policy(
            FederationPolicy::Mesh,
            vec![
                "https://peer-a.example".to_owned(),
                "https://peer-b.example".to_owned(),
                "https://peer-c.example".to_owned(),
            ],
        );
        let state = AppState::new(cfg, Db { pool: None });
        let targets = broadcast_move_to_peers(&state, "cx:move:sha256:01");
        assert_eq!(targets.len(), 3);
    }

    #[tokio::test]
    async fn hub_policy_broadcasts_to_hub_only() {
        let cfg = config_with_policy(
            FederationPolicy::Hub,
            vec![
                "https://hub.example".to_owned(),
                "https://peer-b.example".to_owned(),
                "https://peer-c.example".to_owned(),
            ],
        );
        let state = AppState::new(cfg, Db { pool: None });
        let targets = broadcast_move_to_peers(&state, "cx:move:sha256:02");
        assert_eq!(targets, vec!["https://hub.example".to_owned()]);
    }

    #[tokio::test]
    async fn empty_peers_list_is_a_no_op() {
        let cfg = config_with_policy(FederationPolicy::Mesh, Vec::new());
        let state = AppState::new(cfg, Db { pool: None });
        let targets = broadcast_anchor_to_peers(&state, "cx:anchor:sha256:01");
        assert!(targets.is_empty());
    }
}
