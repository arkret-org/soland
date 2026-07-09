//! Stream-F (Wave 2C) — `ck.audit.erasure_receipt` cross-Principal-
//! Server fanout.
//!
//! Spec: `arkret-spec/spec/v1/zh/models/realm-and-space.md` §2.5.2.
//!
//! ## Surface
//!
//! - [`fanout_erasure_receipt`] — called from the projection write path after a
//!   `ck.audit.erasure_receipt` lands. Looks up the federation peer set for the affected Realm
//!   (currently `config.federation_peers` — the full peer set acts as the conservative super-set of
//!   "peers that have received content from the Realm"; once per-Realm membership tracking ships
//!   this scopes down), seeds the receipt's `peer_status` map, and lets the canonical Event fanout
//!   path deliver the accepted receipt envelope to peers.
//! - [`sweep_erasure_fanout_timeouts`] — called from the periodic timeout job
//!   (`crate::routing::federation::erasure_fanout_worker`). Scans
//!   `state.projection.erasure_receipts`; for each receipt that has any peer with
//!   `acked_at.is_none()` and whose `recorded_at` age exceeds
//!   `config.erasure_propagation_window_ms`, flips `fanout_status = "incomplete"`.
//! - [`spawn`] — spawns the periodic sweep on the current tokio runtime. Mirrors the
//!   `multisig_watchdog` / `federation_outbox` dispatcher contract.
//!
//! ## What this lands
//!
//! Real per-peer `sent_at` stamping. Real 7-day default timeout window with `incomplete` flip. The
//! peer ACK path (inbound `ck.audit.erasure_receipt` referencing the same
//! `receipt_id`) is wired up but currently relies on the reducer
//! observing a follow-up receipt — full inbound-ACK correlation lands
//! when the federation inbound handler grows a typed
//! `erasure_receipt.peer_ack` branch.

use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use cokret_sdk::{Did, Operation, OperationId, RealmId};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::reducer::FanoutPeerStatus;
use crate::state::AppState;

/// How often the timeout-sweep worker wakes up. Bounded well below
/// the 7-day default window so a missed tick only delays the
/// `incomplete` flip by a few minutes, not days.
pub const DEFAULT_SWEEP_INTERVAL: Duration = Duration::from_secs(60 * 60); // 1 hour

/// Outbox endpoint for canonical peer Event fanout.
const ERASURE_RECEIPT_OUTBOX_ENDPOINT: &str = "/_cokret/peer/events";

#[derive(Clone, Debug, PartialEq, Eq)]
struct ErasurePeerTarget {
    url: String,
    did: String,
}

/// Stream-F (Wave 2C) — federation fanout for a freshly-recorded
/// `ck.audit.erasure_receipt`. Enqueues one outbox row per
/// federation peer and seeds the receipt's `peer_status` map. No-op
/// when the receipt has no `scope.realm_id` (account-private scope)
/// or when `config.federation_peers` is empty.
///
/// Spec `realm-and-space.md` §2.5.2 requires pushing to every federation
/// peer that has ever received content from the Realm. We use the full
/// configured peer set as a
/// conservative super-set; per-Realm peer-set tracking ships when
/// the federation membership projection grows that surface.
pub async fn fanout_erasure_receipt(state: &AppState, receipt_id: &str) {
    let receipt_snapshot = {
        let proj = state.projection.lock();
        proj.erasure_receipts
            .iter()
            .rev()
            .find(|r| r.receipt_id.as_deref() == Some(receipt_id))
            .cloned()
    };
    let Some(receipt) = receipt_snapshot else {
        tracing::debug!(
            target = "erasure_fanout",
            receipt_id,
            "no matching receipt in projection — skipping fanout"
        );
        return;
    };
    let Some(scope_realm_id) = receipt.scope_realm_id.clone() else {
        return;
    };
    let Ok(operation_id) = OperationId::new(crate::ids::generate_operation_id()) else {
        return;
    };
    let Ok(realm_id) = RealmId::new(scope_realm_id) else {
        return;
    };
    let operation = Operation::create(
        operation_id,
        realm_id,
        cokret_sdk::events::kinds::AUDIT_ERASURE_RECEIPT,
        receipt.payload,
    );
    fanout_erasure_receipt_operation(state, &operation).await;
}

/// Fan out a durable `ck.audit.erasure_receipt` operation through the normal
/// federation push batch wire shape.
pub async fn fanout_erasure_receipt_operation(state: &AppState, operation: &Operation) {
    if state.settings().federation_peers.is_empty() {
        return;
    }
    let now = Utc::now();
    let peers = configured_erasure_peer_targets(state);
    if peers.is_empty() {
        return;
    }
    let receipt_id = operation
        .payload
        .get("receipt_id")
        .and_then(Value::as_str)
        .unwrap_or(operation.operation_id.as_str());

    // Snapshot the receipt we're acting on. Done under lock so the
    // peer_status seed observes the same record the reducer just
    // pushed; we re-lock once below to write the seeded statuses
    // back, releasing in between so the outbox enqueue (which may
    // hit persistence) does not stall the projection lock.
    let receipt_snapshot = {
        let proj = state.projection.lock();
        proj.erasure_receipts
            .iter()
            .rev()
            .find(|r| r.receipt_id.as_deref() == Some(receipt_id))
            .cloned()
    };
    let Some(receipt) = receipt_snapshot else {
        tracing::debug!(
            target = "erasure_fanout",
            receipt_id,
            "no matching receipt in projection — skipping fanout"
        );
        return;
    };
    // No scope.realm_id → account-private erasure, no peer fanout.
    if receipt.scope_realm_id.is_none() {
        return;
    }
    persist_erasure_operation_for_pull(state, operation).await;

    let mut sent_statuses: std::collections::BTreeMap<String, FanoutPeerStatus> =
        std::collections::BTreeMap::new();
    for peer in &peers {
        let Some(payload_json) = erasure_push_payload(state, operation, peer) else {
            sent_statuses.insert(
                peer.did.clone(),
                FanoutPeerStatus {
                    sent_at: None,
                    acked_at: None,
                    outcome: Some("encode_failed".to_owned()),
                },
            );
            continue;
        };
        // Deterministic idempotency key — `sha256(origin || peer ||
        // "erasure_receipt" || operation_id)`. A restart-time replay
        // of the same receipt collapses onto the pre-existing
        // outbox row instead of double-pushing.
        let mut hasher = Sha256::new();
        hasher.update(state.config.service_did.as_bytes());
        hasher.update(b"|");
        hasher.update(peer.did.as_bytes());
        hasher.update(b"|");
        hasher.update(b"erasure_receipt");
        hasher.update(b"|");
        hasher.update(operation.operation_id.as_str().as_bytes());
        let idempotency_key = format!(
            "ak:outbox:erasure_receipt:{}",
            hex::encode(hasher.finalize())
        );

        match crate::routing::federation::outbox::enqueue_outbound(
            state,
            peer.url.as_str(),
            peer.did.as_str(),
            ERASURE_RECEIPT_OUTBOX_ENDPOINT,
            &idempotency_key,
            &payload_json,
        )
        .await
        {
            Ok(_row) => {
                sent_statuses.insert(
                    peer.did.clone(),
                    FanoutPeerStatus {
                        sent_at: Some(now),
                        acked_at: None,
                        outcome: None,
                    },
                );
                tracing::info!(
                    target = "erasure_fanout",
                    receipt_id,
                    peer = %peer.url,
                    peer_did = %peer.did,
                    "erasure receipt enqueued for federation peer"
                );
            }
            Err(error) => {
                // Persistence hiccup — still seed an entry so the
                // timeout sweep can flip the receipt to `incomplete`
                // if no ACK ever lands; just leave sent_at empty so
                // ops can tell the difference between "never enqueued"
                // and "enqueued but unacked".
                sent_statuses.insert(
                    peer.did.clone(),
                    FanoutPeerStatus {
                        sent_at: None,
                        acked_at: None,
                        outcome: Some(format!("enqueue_failed: {error}")),
                    },
                );
                tracing::warn!(
                    target = "erasure_fanout",
                    receipt_id,
                    peer = %peer.url,
                    peer_did = %peer.did,
                    %error,
                    "failed to enqueue erasure receipt for federation peer"
                );
            }
        }
    }

    // Write the seeded peer_status back onto the receipt record.
    if let Some(record) = state
        .projection
        .lock()
        .erasure_receipts
        .iter_mut()
        .rev()
        .find(|r| r.receipt_id.as_deref() == Some(receipt_id))
    {
        record.peer_status = sent_statuses;
    }
}

fn erasure_push_payload(
    state: &AppState,
    operation: &Operation,
    peer: &ErasurePeerTarget,
) -> Option<String> {
    let origin = Did::new(state.config.service_did.clone()).ok()?;
    let destination = Did::new(peer.did.clone()).ok()?;
    let realm_id = RealmId::new(operation.realm_id.to_string()).ok()?;
    let body = cokret_sdk::FederationPushOperationsRequestBody {
        origin,
        destination,
        realm_id,
        service_binding_ref: format!(
            "{}#federation-erasure-receipt:{}",
            state.config.service_did,
            operation.operation_id.as_str()
        ),
        operations: vec![operation.clone()],
    };
    serde_json::to_value(&body)
        .ok()
        .and_then(|value| cokret_sdk::canonical::canonical_json_bytes(&value).ok())
        .and_then(|bytes| String::from_utf8(bytes).ok())
}

async fn persist_erasure_operation_for_pull(state: &AppState, operation: &Operation) {
    let store = state.persistence.federation_operations();
    match store.contains(operation.operation_id.as_str()).await {
        Ok(true) => {}
        Ok(false) => {
            if let Err(error) = store.append(operation.clone()).await {
                tracing::warn!(
                    %error,
                    operation_id = %operation.operation_id,
                    "failed to persist erasure receipt operation in federation pull log"
                );
            }
        }
        Err(error) => {
            tracing::warn!(
                %error,
                operation_id = %operation.operation_id,
                "failed to check erasure receipt operation in federation pull log"
            );
        }
    }
}

fn configured_erasure_peer_targets(state: &AppState) -> Vec<ErasurePeerTarget> {
    use crate::config::FederationFanoutTopology;
    let settings = state.settings();
    let entries: Vec<String> = match settings.federation_fanout_topology {
        FederationFanoutTopology::Mesh => settings.federation_peers.clone(),
        FederationFanoutTopology::Hub => settings
            .federation_peers
            .first()
            .cloned()
            .into_iter()
            .collect(),
    };
    entries
        .into_iter()
        .filter_map(|entry| parse_erasure_peer_target(&entry))
        .collect()
}

fn parse_erasure_peer_target(entry: &str) -> Option<ErasurePeerTarget> {
    let entry = entry.trim();
    if entry.is_empty() {
        return None;
    }
    let (left, right) = entry
        .split_once('|')
        .map(|(left, right)| (left.trim(), right.trim()))
        .unwrap_or((entry, entry));
    if left.is_empty() || right.is_empty() {
        return None;
    }
    if left.starts_with("did:") && !right.starts_with("did:") {
        Some(ErasurePeerTarget {
            url: right.trim_end_matches('/').to_owned(),
            did: left.to_owned(),
        })
    } else {
        Some(ErasurePeerTarget {
            url: left.trim_end_matches('/').to_owned(),
            did: right.to_owned(),
        })
    }
}

/// Stream-F (Wave 2C) — one pass of the erasure-receipt timeout sweep.
/// Pulled out so unit tests can drive deterministic single-tick
/// behaviour without a tokio runtime.
///
/// Returns the number of receipts whose `fanout_status` was flipped
/// to `incomplete` this pass.
pub fn sweep_erasure_fanout_timeouts(state: &AppState) -> usize {
    let window_ms = state.config.erasure_propagation_window_ms;
    let now = Utc::now();
    let window = chrono::Duration::milliseconds(window_ms as i64);

    let mut proj = state.projection.lock();
    let mut flipped = 0_usize;
    for receipt in proj.erasure_receipts.iter_mut() {
        if receipt.fanout_status == "incomplete" || receipt.fanout_status == "complete" {
            continue; // terminal — sweep is a no-op once decided
        }
        if receipt.peer_status.is_empty() {
            // No peers to wait on (account-private scope or empty
            // peer set). Leave the receipt in its initial state.
            continue;
        }
        let any_unacked = receipt.peer_status.values().any(|p| p.acked_at.is_none());
        if !any_unacked {
            // All peers acknowledged — promote to `complete`.
            receipt.fanout_status = "complete".to_owned();
            continue;
        }
        let age = now - receipt.recorded_at;
        if age > window {
            receipt.fanout_status = "incomplete".to_owned();
            flipped += 1;
            tracing::warn!(
                target = "erasure_fanout",
                receipt_id = ?receipt.receipt_id,
                window_ms,
                age_ms = age.num_milliseconds(),
                unacked_peers = receipt
                    .peer_status
                    .values()
                    .filter(|p| p.acked_at.is_none())
                    .count(),
                "erasure receipt federation fanout flipped to incomplete (timeout window lapsed)"
            );
        }
    }
    flipped
}

/// Background worker driving [`sweep_erasure_fanout_timeouts`] on a
/// periodic tick. Mirrors the federation outbox dispatcher contract:
/// returns `None` (no-op) when `federation_outbound_enabled` is
/// false; callers `.abort()` the returned handle at shutdown.
pub fn spawn(state: AppState) -> Option<Arc<tokio::task::JoinHandle<()>>> {
    if !state.config.federation_outbound_enabled {
        return None;
    }
    let interval = DEFAULT_SWEEP_INTERVAL;
    let task = tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // Skip the immediate first tick so we don't fire before the
        // rest of AppState is wired up.
        ticker.tick().await;
        loop {
            ticker.tick().await;
            let flipped = sweep_erasure_fanout_timeouts(&state);
            if flipped > 0 {
                tracing::info!(
                    target = "erasure_fanout",
                    worker = "erasure_fanout_sweep",
                    flipped,
                    "erasure receipt fanout sweep flipped receipts to incomplete"
                );
            }
        }
    });
    Some(Arc::new(task))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::reducer::ErasureReceiptRecord;

    fn fake_state() -> AppState {
        // Reuse the federation::tests config builder via a thin
        // wrapper — it returns an AppState with empty peer set by
        // default. We bend the public AppState shape just enough to
        // inject federation_peers + erasure_propagation_window_ms
        // for the test.
        crate::routing::federation::federation::test_app_state_with_peers(
            vec!["http://127.0.0.1:9|did:web:peer1.example".to_owned()],
            500,
        )
    }

    #[tokio::test]
    async fn fanout_seeds_peer_status_with_sent_at() {
        let state = fake_state();
        // Inject a receipt with a scope.realm_id.
        {
            let mut proj = state.projection.lock();
            proj.erasure_receipts.push(ErasureReceiptRecord {
                receipt_id: Some("r1".to_owned()),
                issuer: Some("did:web:origin.example".to_owned()),
                subject_kind: Some("realm".to_owned()),
                subject_ref: None,
                outcome: "completed".to_owned(),
                storage_boundary: Some("projection_store".to_owned()),
                scope_realm_id: Some("ak:realm:01904100-0000-7000-8000-deadbeefcafe".to_owned()),
                fanout_status: "pending".to_owned(),
                peer_status: std::collections::BTreeMap::new(),
                recorded_at: Utc::now(),
                payload: json!({
                    "receipt_id": "r1",
                    "schema": "ck.schema.erasure_receipt.v1",
                    "subject": {"kind": "principal", "ref": "did:web:alice.example"},
                    "outcome": "completed",
                    "scope": {
                        "storage_boundary": "projection_store",
                        "realm_id": "ak:realm:01904100-0000-7000-8000-deadbeefcafe"
                    }
                }),
            });
        }
        fanout_erasure_receipt(&state, "r1").await;
        let (peer_status_len, peer_sent, peer_unacked) = {
            let proj = state.projection.lock();
            let record = proj
                .erasure_receipts
                .iter()
                .find(|r| r.receipt_id.as_deref() == Some("r1"))
                .unwrap();
            let peer = record.peer_status.get("did:web:peer1.example").unwrap();
            (
                record.peer_status.len(),
                peer.sent_at.is_some(),
                peer.acked_at.is_none(),
            )
        };
        assert_eq!(peer_status_len, 1);
        assert!(peer_sent, "sent_at must be stamped on enqueue");
        assert!(peer_unacked);
        let outbox = state
            .persistence
            .federation_outbox()
            .snapshot_all()
            .await
            .unwrap();
        assert_eq!(outbox.len(), 1);
        assert_eq!(outbox[0].peer_url, "http://127.0.0.1:9");
        assert_eq!(outbox[0].peer_did, "did:web:peer1.example");
        let body: serde_json::Value = serde_json::from_str(&outbox[0].payload_json).unwrap();
        assert_eq!(body["origin"], "did:web:test.local");
        assert_eq!(body["destination"], "did:web:peer1.example");
        assert_eq!(
            body["operations"][0]["object_type"],
            cokret_sdk::events::kinds::AUDIT_ERASURE_RECEIPT
        );
    }

    #[test]
    fn timeout_sweep_flips_to_incomplete_after_window() {
        let state = fake_state();
        // Receipt is 1s old; window is 500ms (set by fake_state).
        let old = Utc::now() - chrono::Duration::seconds(1);
        {
            let mut proj = state.projection.lock();
            let mut peers = std::collections::BTreeMap::new();
            peers.insert(
                "did:web:peer1.example".to_owned(),
                FanoutPeerStatus {
                    sent_at: Some(old),
                    acked_at: None,
                    outcome: None,
                },
            );
            proj.erasure_receipts.push(ErasureReceiptRecord {
                receipt_id: Some("r-timeout".to_owned()),
                issuer: None,
                subject_kind: None,
                subject_ref: None,
                outcome: "completed".to_owned(),
                storage_boundary: None,
                scope_realm_id: Some("ak:realm:r-timeout".to_owned()),
                fanout_status: "pending".to_owned(),
                peer_status: peers,
                recorded_at: old,
                payload: json!({}),
            });
        }
        let flipped = sweep_erasure_fanout_timeouts(&state);
        assert_eq!(flipped, 1);
        let proj = state.projection.lock();
        let record = proj
            .erasure_receipts
            .iter()
            .find(|r| r.receipt_id.as_deref() == Some("r-timeout"))
            .unwrap();
        assert_eq!(record.fanout_status, "incomplete");
    }
}
