//! Stream-F (Wave 2C) — `cx.audit.erasure_receipt` cross-Principal-
//! Server fanout.
//!
//! Spec: `contrix-spec/spec/v1/zh/models/realm-and-space.md` §2.5.2.
//!
//! ## Surface
//!
//! - [`fanout_erasure_receipt`] — called from the projection write
//!   path after a `cx.audit.erasure_receipt` lands. Looks up the
//!   federation peer set for the affected Realm (currently
//!   `config.federation_peers` — the full peer set acts as the
//!   conservative super-set of "peers that have received content from
//!   the Realm"; once per-Realm membership tracking ships this scopes
//!   down), enqueues one outbound `cx.audit.erasure_receipt`
//!   envelope per peer into the federation outbox, and seeds the
//!   receipt's `peer_status` map.
//! - [`sweep_erasure_fanout_timeouts`] — called from the periodic
//!   timeout job (`crate::routing::federation::erasure_fanout_worker`).
//!   Scans `state.projection.erasure_receipts`; for each receipt that
//!   has any peer with `acked_at.is_none()` and whose `recorded_at`
//!   age exceeds `config.erasure_propagation_window_ms`, flips
//!   `fanout_status = "incomplete"`.
//! - [`spawn`] — spawns the periodic sweep on the current tokio
//!   runtime. Mirrors the `multisig_watchdog` / `federation_outbox`
//!   dispatcher contract.
//!
//! ## What this lands
//!
//! Real outbox enqueue per peer. Real per-peer `sent_at` stamping.
//! Real 7-day default timeout window with `incomplete` flip. The peer
//! ACK path (inbound `cx.audit.erasure_receipt` referencing the same
//! `receipt_id`) is wired up but currently relies on the reducer
//! observing a follow-up receipt — full inbound-ACK correlation lands
//! when the federation inbound handler grows a typed
//! `erasure_receipt.peer_ack` branch.

use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::reducer::FanoutPeerStatus;
use crate::state::AppState;

/// How often the timeout-sweep worker wakes up. Bounded well below
/// the 7-day default window so a missed tick only delays the
/// `incomplete` flip by a few minutes, not days.
pub const DEFAULT_SWEEP_INTERVAL: Duration = Duration::from_secs(60 * 60); // 1 hour

/// Outbox endpoint used for federated erasure-receipt envelopes. Peers
/// accept these via the same `push-operations` ingest used for any
/// other audit event; the receiving reducer dispatches on the canonical
/// kind string and lands the receipt in its own `erasure_receipts`
/// projection.
const ERASURE_RECEIPT_OUTBOX_ENDPOINT: &str = "/api/v1/federation/push-operations";

/// Stream-F (Wave 2C) — federation fanout for a freshly-recorded
/// `cx.audit.erasure_receipt`. Enqueues one outbox row per
/// federation peer and seeds the receipt's `peer_status` map. No-op
/// when the receipt has no `scope.realm_id` (account-private scope)
/// or when `config.federation_peers` is empty.
///
/// Spec `realm-and-space.md` §2.5.2: "推送到每个曾经接收过该 Realm
/// 内容的 federation peer". We use the full configured peer set as a
/// conservative super-set; per-Realm peer-set tracking ships when
/// the federation membership projection grows that surface.
pub fn fanout_erasure_receipt(state: &AppState, receipt_id: &str) {
    if state.config.federation_peers.is_empty() {
        return;
    }
    let now = Utc::now();
    let peers: Vec<String> = state.config.federation_peers.clone();

    // Snapshot the receipt we're acting on. Done under lock so the
    // peer_status seed observes the same record the reducer just
    // pushed; we re-lock once below to write the seeded statuses
    // back, releasing in between so the outbox enqueue (which may
    // hit persistence) does not stall the projection lock.
    let receipt_snapshot = {
        let Ok(proj) = state.projection.lock() else {
            return;
        };
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

    // Build the federated envelope. We retransmit the canonical
    // erasure receipt payload verbatim so the peer's reducer applies
    // the identical scope/outcome/proof bundle the local reducer
    // already accepted.
    let envelope = json!({
        "schema": "cx.federation.outbound.audit_erasure_receipt.v1",
        "origin": state.config.service_did,
        "kind": crate::kinds::CX_AUDIT_ERASURE_RECEIPT,
        "receipt": receipt.payload,
    });

    let mut sent_statuses: std::collections::BTreeMap<String, FanoutPeerStatus> =
        std::collections::BTreeMap::new();
    for peer in &peers {
        // Deterministic idempotency key — `sha256(origin || peer ||
        // "erasure_receipt" || receipt_id)`. A restart-time replay
        // of the same receipt collapses onto the pre-existing
        // outbox row instead of double-pushing.
        let mut hasher = Sha256::new();
        hasher.update(state.config.service_did.as_bytes());
        hasher.update(b"|");
        hasher.update(peer.as_bytes());
        hasher.update(b"|");
        hasher.update(b"erasure_receipt");
        hasher.update(b"|");
        hasher.update(receipt_id.as_bytes());
        let idempotency_key = format!("cx:outbox:erasure_receipt:{:x}", hasher.finalize());

        let payload_bytes =
            contrix_sdk::canonical::canonical_json_bytes(&envelope).unwrap_or_default();
        let payload_json =
            String::from_utf8(payload_bytes).unwrap_or_else(|_| envelope.to_string());
        match crate::routing::federation::outbox::enqueue_outbound(
            state,
            peer,
            peer,
            ERASURE_RECEIPT_OUTBOX_ENDPOINT,
            &idempotency_key,
            &payload_json,
        ) {
            Ok(_row) => {
                sent_statuses.insert(
                    peer.clone(),
                    FanoutPeerStatus {
                        sent_at: Some(now),
                        acked_at: None,
                        outcome: None,
                    },
                );
                tracing::info!(
                    target = "erasure_fanout",
                    receipt_id,
                    %peer,
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
                    peer.clone(),
                    FanoutPeerStatus {
                        sent_at: None,
                        acked_at: None,
                        outcome: Some(format!("enqueue_failed: {error}")),
                    },
                );
                tracing::warn!(
                    target = "erasure_fanout",
                    receipt_id,
                    %peer,
                    %error,
                    "failed to enqueue erasure receipt for federation peer"
                );
            }
        }
    }

    // Write the seeded peer_status back onto the receipt record.
    if let Ok(mut proj) = state.projection.lock()
        && let Some(record) = proj
            .erasure_receipts
            .iter_mut()
            .rev()
            .find(|r| r.receipt_id.as_deref() == Some(receipt_id))
    {
        record.peer_status = sent_statuses;
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

    let Ok(mut proj) = state.projection.lock() else {
        return 0;
    };
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
    use super::*;
    use crate::reducer::ErasureReceiptRecord;

    fn fake_state() -> AppState {
        // Reuse the federation::tests config builder via a thin
        // wrapper — it returns an AppState with empty peer set by
        // default. We bend the public AppState shape just enough to
        // inject federation_peers + erasure_propagation_window_ms
        // for the test.
        crate::routing::federation::federation::test_app_state_with_peers(
            vec!["did:web:peer1.example".to_owned()],
            500,
        )
    }

    #[test]
    fn fanout_seeds_peer_status_with_sent_at() {
        let state = fake_state();
        // Inject a receipt with a scope.realm_id.
        {
            let mut proj = state.projection.lock().unwrap();
            proj.erasure_receipts.push(ErasureReceiptRecord {
                receipt_id: Some("r1".to_owned()),
                issuer: Some("did:web:origin.example".to_owned()),
                subject_kind: Some("realm".to_owned()),
                subject_ref: None,
                outcome: "completed".to_owned(),
                storage_boundary: Some("projection_store".to_owned()),
                scope_realm_id: Some("cx:realm:01904100-0000-7000-8000-deadbeefcafe".to_owned()),
                fanout_status: "pending".to_owned(),
                peer_status: std::collections::BTreeMap::new(),
                recorded_at: Utc::now(),
                payload: json!({
                    "receipt_id": "r1",
                    "outcome": "completed",
                    "scope": {
                        "storage_boundary": "projection_store",
                        "realm_id": "cx:realm:01904100-0000-7000-8000-deadbeefcafe"
                    }
                }),
            });
        }
        fanout_erasure_receipt(&state, "r1");
        let proj = state.projection.lock().unwrap();
        let record = proj
            .erasure_receipts
            .iter()
            .find(|r| r.receipt_id.as_deref() == Some("r1"))
            .unwrap();
        assert_eq!(record.peer_status.len(), 1);
        let peer = record.peer_status.get("did:web:peer1.example").unwrap();
        assert!(peer.sent_at.is_some(), "sent_at must be stamped on enqueue");
        assert!(peer.acked_at.is_none());
    }

    #[test]
    fn timeout_sweep_flips_to_incomplete_after_window() {
        let state = fake_state();
        // Receipt is 1s old; window is 500ms (set by fake_state).
        let old = Utc::now() - chrono::Duration::seconds(1);
        {
            let mut proj = state.projection.lock().unwrap();
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
                scope_realm_id: Some("cx:realm:r-timeout".to_owned()),
                fanout_status: "pending".to_owned(),
                peer_status: peers,
                recorded_at: old,
                payload: json!({}),
            });
        }
        let flipped = sweep_erasure_fanout_timeouts(&state);
        assert_eq!(flipped, 1);
        let proj = state.projection.lock().unwrap();
        let record = proj
            .erasure_receipts
            .iter()
            .find(|r| r.receipt_id.as_deref() == Some("r-timeout"))
            .unwrap();
        assert_eq!(record.fanout_status, "incomplete");
    }
}
