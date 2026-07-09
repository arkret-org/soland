use serde_json::{Value, json};

use super::endpoints::FederationOperationFrontierOutcome;
use super::outbound::{
    FederationPeerTarget, configured_peer_targets, enqueue_outbound_for,
    record_outbound_fanout_attempt,
};
use super::sha256_hex;
use crate::error::AppError;
use crate::state::AppState;

pub(super) fn configured_peer_from_backfill_body(
    state: &AppState,
    body: &Value,
) -> Result<FederationPeerTarget, AppError> {
    let peer_url = body
        .get("peer_url")
        .and_then(Value::as_str)
        .map(|value| value.trim().trim_end_matches('/').to_owned())
        .filter(|value| !value.is_empty());
    let peer_did = body
        .get("peer_did")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let peers = configured_peer_targets(state);
    let matched = peers.into_iter().find(|peer| {
        peer_url.as_deref().is_some_and(|url| peer.url == url)
            || peer_did.is_some_and(|did| peer.did == did)
    });
    matched.ok_or_else(|| {
        AppError::invalid_param(
            "peer_url or peer_did must match a configured SOLAND_FEDERATION_PEERS entry",
        )
    })
}

pub(super) async fn pull_operations_page(
    state: &AppState,
    peer: &FederationPeerTarget,
    realm_id: &str,
    after_cursor: Option<&str>,
    limit: usize,
) -> Result<arkret_sdk::FederationPullOperationsOutcome, AppError> {
    let mut url = reqwest::Url::parse(&format!("{}/_arkret/peer/events", peer.url))
        .map_err(|error| AppError::invalid_param(format!("invalid peer_url: {error}")))?;
    {
        let mut query = url.query_pairs_mut();
        query.append_pair("realm_id", realm_id);
        query.append_pair("limit", &limit.to_string());
        if let Some(after_cursor) = after_cursor.filter(|value| !value.is_empty()) {
            query.append_pair("after_cursor", after_cursor);
        }
    }
    let (url, client) = crate::security::validate_http_url_for_egress_with_pinned_client(
        url.as_str(),
        "peer events query",
        state.config.development_mode,
        crate::routing::federation::outbox::REQUEST_TIMEOUT,
    )
    .map_err(AppError::capability_denied)?;
    let response = client
        .get(url.clone())
        .send()
        .await
        .map_err(|error| AppError::internal(format!("federation pull from {url}: {error}")))?;
    let status = response.status();
    let text = response
        .text()
        .await
        .map_err(|error| AppError::internal(format!("read federation pull response: {error}")))?;
    if !status.is_success() {
        return Err(AppError::internal(format!(
            "federation pull from {url} returned {status}: {text}"
        )));
    }
    serde_json::from_str::<arkret_sdk::FederationPullOperationsOutcome>(&text)
        .map_err(|error| AppError::internal(format!("parse federation pull response: {error}")))
}

#[cfg(test)]
pub(super) async fn operation_frontier_value(state: &AppState, realm_id: &str) -> Value {
    serde_json::to_value(operation_frontier_outcome(state, realm_id).await)
        .unwrap_or_else(|_| Value::Null)
}

pub(super) async fn operation_frontier_outcome(
    state: &AppState,
    realm_id: &str,
) -> FederationOperationFrontierOutcome {
    let operations = state
        .persistence
        .federation_operations()
        .list_for_realm(realm_id)
        .await
        .unwrap_or_default();
    let mut operation_ids = operations
        .iter()
        .map(|operation| operation.operation_id.to_string())
        .collect::<Vec<_>>();
    operation_ids.sort();
    let latest_operation_id = operation_ids.last().cloned();
    let digest_payload = json!({
        "realm_id": realm_id,
        "operation_ids": operation_ids.clone(),
    });
    let frontier_digest = arkret_sdk::canonical::canonical_sha256(&digest_payload)
        .map(|digest| {
            if digest.starts_with("sha256:") {
                digest
            } else {
                format!("sha256:{digest}")
            }
        })
        .unwrap_or_else(|_| {
            format!(
                "sha256:{}",
                sha256_hex(digest_payload.to_string().as_bytes())
            )
        });
    FederationOperationFrontierOutcome {
        realm_id: realm_id.to_owned(),
        operation_count: operations.len(),
        operation_ids,
        latest_operation_id,
        frontier_digest,
    }
}

pub(super) fn is_valid_federation_txn_id(value: &str) -> bool {
    let value = value.trim();
    !value.is_empty()
        && value.len() <= 128
        && value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.' | ':' | '$'))
}

pub(super) fn federation_request_digest(
    body: &arkret_sdk::FederationTransactionRequestBody,
) -> Result<String, &'static str> {
    let value =
        serde_json::to_value(body).map_err(|_| "federation transaction must serialize to JSON")?;
    arkret_sdk::canonical::canonical_sha256(&value)
        .map_err(|_| "federation transaction must be canonical JSON")
}

/// Outbound Move broadcast helper. Each accepted Move
/// goes to:
/// - [`FederationFanoutTopology::Mesh`]: every peer in `state.config.federation_peers`.
/// - [`FederationFanoutTopology::Hub`]: only the first peer (`federation_peers[0]`).
///
/// Returns the list of peer URLs the broadcast targeted. This helper persists
/// the retry transcript and durable outbox row; the actual HTTP dispatch still
/// happens later in the federation outbox worker.
pub async fn broadcast_move_to_peers(state: &AppState, move_id: &str) -> Vec<String> {
    let peers = configured_peer_targets(state);
    for peer in &peers {
        let peer_url = peer.url.clone();
        record_outbound_fanout_attempt(state, "move", move_id, peer.url.as_str()).await;
        // G3.S0 — durable enqueue. The transcript persisted above remains
        // the human-readable audit record; the outbox row is what the
        // background dispatcher (`routing::federation::outbox`) actually
        // POSTs. Failures to enqueue are logged but don't fail the
        // inbound write — the transcript still gives operators a way to
        // re-trigger delivery once the storage hiccup clears.
        enqueue_outbound_for(state, "move", move_id, peer).await;
        tracing::debug!(
            worker = "federation_outbox_enqueue",
            peer = %peer_url,
            move_id = %move_id,
            "federation broadcast move signed request transcript persisted for retry worker"
        );
    }
    peers.into_iter().map(|peer| peer.url).collect()
}

/// Symmetric helper for Seal replication. The hub policy still pushes
/// to a single upstream so the broadcast list is `[hub]`; mesh fans out
/// to every peer.
pub async fn broadcast_seal_to_peers(state: &AppState, seal_id: &str) -> Vec<String> {
    let peers = configured_peer_targets(state);
    for peer in &peers {
        let peer_url = peer.url.clone();
        record_outbound_fanout_attempt(state, "seal", seal_id, peer.url.as_str()).await;
        // G3.S0 — durable enqueue (see broadcast_move_to_peers).
        enqueue_outbound_for(state, "seal", seal_id, peer).await;
        tracing::debug!(
            worker = "federation_outbox_enqueue",
            peer = %peer_url,
            seal_id = %seal_id,
            "federation broadcast seal signed request transcript persisted for retry worker"
        );
    }
    peers.into_iter().map(|peer| peer.url).collect()
}

/// Resolve the configured peer base URL for a destination service DID, if the
/// deployment lists it in `federation_peers` (and the deployment peer policy
/// does not deny it). Used by federation senders (e.g. contact fact delivery)
/// that address a target by its home Principal Server service DID.
pub(crate) fn peer_url_for_service_did(state: &AppState, service_did: &str) -> Option<String> {
    configured_peer_targets(state)
        .into_iter()
        .find(|peer| peer.did == service_did)
        .map(|peer| peer.url)
}
