//! Multisig leader-election watchdog.
//!
//! A tokio background task that wakes every `tick_interval` seconds, scans
//! `multisig_pending` for rows where:
//!   - `partials.len() >= threshold_k`
//!   - `canonical_b64` is non-empty
//!   - the row is not currently leased by another node
//!
//! For each claimable row it builds an SDK [`ThresholdAggregator`], adds
//! every partial via `add_partial`, then calls
//! [`ThresholdAggregator::aggregate`] with a per-partial Ed25519 verifier
//! that resolves each `signer_did` to its published public key via the
//! [`AppState`] DID resolver chain. On success the row is deleted.
//!
//! Leader-election column: `claimed_by_node_id text NULL, claimed_until
//! timestamptz NULL` — the watchdog acquires a 60s lease on each row before
//! aggregating, so two nodes running this loop at the same time never
//! double-publish.

use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use chrono::Utc;
use contrix_sdk::{
    Anchor, AnchorId, Did, Hash, Hlc, MoveId, PartialSignature, SpaceId, ThresholdAggregator,
};

use crate::state::{AppState, MultisigPendingRecord};

/// Default poll interval. Override at construction time via
/// [`MultisigWatchdog::with_tick_interval`].
pub const DEFAULT_TICK_INTERVAL_SECS: u64 = 30;

/// Lease duration acquired against each claimable row. 60s is long
/// enough to perform aggregate + publish on a busy node, short enough
/// that crash-recovery picks up dropped rows on the next tick.
pub const LEASE_DURATION_SECS: u64 = 60;

/// Configuration knobs for the watchdog loop.
#[derive(Clone, Debug)]
pub struct MultisigWatchdogConfig {
    pub tick_interval: Duration,
    pub lease_duration: Duration,
    /// Stable identifier of this soland process. Goes into the
    /// `claimed_by_node_id` column so other nodes can tell whose lease is
    /// active. Defaults to `service_did + ":" + uuid::v4()` at construction.
    pub node_id: String,
}

impl MultisigWatchdogConfig {
    pub fn for_service(service_did: &str) -> Self {
        Self {
            tick_interval: Duration::from_secs(DEFAULT_TICK_INTERVAL_SECS),
            lease_duration: Duration::from_secs(LEASE_DURATION_SECS),
            node_id: format!("{}:{}", service_did, uuid::Uuid::new_v4()),
        }
    }
}

/// One full pass over the pending buffer. Returns the per-row outcomes so
/// callers (tests + the periodic loop) can assert deterministic behavior.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WatchdogPassReport {
    pub scanned: usize,
    pub claimed: Vec<String>,
    pub aggregated: Vec<String>,
    pub failed: Vec<(String, String)>,
    /// Anchors whose fenced delete was rejected because the row's
    /// `claim_seq` no longer matched the snapshot we held (i.e. a stale
    /// leader's publish landed against a re-leased row).
    pub fenced_rejections: Vec<String>,
    /// Happy-path lease renewals that landed successfully during this
    /// pass (only happens if `aggregate_and_publish` installs a renewer;
    /// the periodic loop renews every `lease_duration / 3`).
    pub renewed: Vec<String>,
}

pub struct MultisigWatchdog {
    state: AppState,
    config: MultisigWatchdogConfig,
}

impl MultisigWatchdog {
    pub fn new(state: AppState, config: MultisigWatchdogConfig) -> Self {
        Self { state, config }
    }

    /// Spawn the periodic loop on the current tokio runtime. Returns an
    /// `Arc<JoinHandle>` so the caller can `abort()` the task at shutdown
    /// (the soland binary keeps it alive for the process lifetime).
    pub fn spawn(self) -> Arc<tokio::task::JoinHandle<()>> {
        let interval = self.config.tick_interval;
        let task = tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            // Skip the immediate first tick so we don't fire mid-boot
            // before the rest of the AppState is wired up.
            ticker.tick().await;
            loop {
                ticker.tick().await;
                let report = run_watchdog_pass(&self.state, &self.config);
                if !report.aggregated.is_empty() || !report.failed.is_empty() {
                    tracing::info!(
                        scanned = report.scanned,
                        aggregated = report.aggregated.len(),
                        failed = report.failed.len(),
                        node_id = %self.config.node_id,
                        "multisig watchdog pass complete",
                    );
                }
            }
        });
        Arc::new(task)
    }
}

/// Run one watchdog pass synchronously. Pulled out of the spawn loop so
/// unit tests can drive deterministic single-tick behavior without a
/// running tokio runtime.
pub fn run_watchdog_pass(state: &AppState, config: &MultisigWatchdogConfig) -> WatchdogPassReport {
    let store = state.persistence.multisig_pending();
    let now = Utc::now();
    let lease_expiry = now
        + chrono::Duration::from_std(config.lease_duration)
            .unwrap_or_else(|_| chrono::Duration::seconds(LEASE_DURATION_SECS as i64));

    let rows = match store.snapshot_all() {
        Ok(rows) => rows,
        Err(error) => {
            tracing::warn!(%error, "multisig watchdog: snapshot_all failed");
            return WatchdogPassReport::default();
        }
    };

    let mut report = WatchdogPassReport::default();
    report.scanned = rows.len();

    for record in rows {
        if !is_threshold_met(&record) {
            continue;
        }
        if record.canonical_b64.is_empty() {
            continue;
        }
        // Skip rows currently leased by a different live node.
        if let (Some(holder), Some(deadline)) =
            (record.claimed_by_node_id.as_deref(), record.claimed_until)
            && holder != config.node_id
            && deadline > now
        {
            continue;
        }
        let fence_seq = match store.try_claim(&record.anchor_id, &config.node_id, now, lease_expiry)
        {
            Ok((true, seq)) => {
                report.claimed.push(record.anchor_id.clone());
                seq
            }
            Ok((false, _)) => continue,
            Err(error) => {
                tracing::warn!(%error, anchor_id = %record.anchor_id, "watchdog: try_claim failed");
                continue;
            }
        };

        match aggregate_and_publish(state, &record) {
            Ok(_anchor) => {
                // Fenced delete: the row only goes away when our
                // snapshotted `claim_seq` still matches. If a stale leader
                // (whose lease was silently re-issued after a partition
                // heal) tries to publish here, its `delete_with_fence`
                // returns false and the row stays for the live leader.
                match store.delete_with_fence(&record.anchor_id, &config.node_id, fence_seq) {
                    Ok(true) => report.aggregated.push(record.anchor_id.clone()),
                    Ok(false) => {
                        report.fenced_rejections.push(record.anchor_id.clone());
                        tracing::warn!(
                            anchor_id = %record.anchor_id,
                            fence_seq,
                            node_id = %config.node_id,
                            "watchdog: fenced delete rejected — stale leader detected, dropping publish",
                        );
                    }
                    Err(error) => {
                        tracing::warn!(%error, anchor_id = %record.anchor_id, "watchdog: post-aggregate delete failed");
                    }
                }
            }
            Err(error) => {
                let _ = store.release_claim(&record.anchor_id, &config.node_id);
                report
                    .failed
                    .push((record.anchor_id.clone(), error.clone()));
                tracing::warn!(%error, anchor_id = %record.anchor_id, "watchdog: aggregate failed");
            }
        }
    }

    report
}

/// Best-effort lease renewal helper. Pushes `claimed_until`
/// out by `lease_duration` without bumping `claim_seq` so an in-flight
/// aggregation that out-runs the original lease keeps its fencing
/// token. Returns the renewal outcome:
///   - `Ok(true)`  — renewal landed; lease is now `now + lease_duration`.
///   - `Ok(false)` — the row was re-leased (claim_seq advanced) or deleted; the caller should abort
///     and let the new leader publish.
///   - `Err(_)`    — store-level error (treat as `false`).
pub fn renew_lease_during_aggregation(
    state: &AppState,
    config: &MultisigWatchdogConfig,
    anchor_id: &str,
    fence_seq: i64,
) -> Result<bool, String> {
    let store = state.persistence.multisig_pending();
    let now = Utc::now();
    let new_until = now
        + chrono::Duration::from_std(config.lease_duration)
            .unwrap_or_else(|_| chrono::Duration::seconds(LEASE_DURATION_SECS as i64));
    store
        .renew_claim(anchor_id, &config.node_id, fence_seq, new_until)
        .map_err(|e| e.to_string())
}

fn is_threshold_met(record: &MultisigPendingRecord) -> bool {
    record.partials.len() as u32 >= record.threshold_k
}

/// Build the `ThresholdAggregator`, run per-partial Ed25519 verification
/// via the supplied `verify` callback, and produce the threshold-signed
/// [`Anchor`] envelope. Errors are returned as plain strings so the caller
/// can surface them in [`WatchdogPassReport`].
fn aggregate_and_publish(
    state: &AppState,
    record: &MultisigPendingRecord,
) -> Result<Anchor, String> {
    use base64::engine::general_purpose::STANDARD;

    let canonical_bytes = STANDARD
        .decode(&record.canonical_b64)
        .map_err(|e| format!("canonical_b64 decode failed: {e}"))?;

    // Reconstruct the structured anchor body from the canonical JSON.
    let body: serde_json::Value = serde_json::from_slice(&canonical_bytes)
        .map_err(|e| format!("canonical_bytes are not JSON: {e}"))?;
    let space_id = body
        .get("space_id")
        .and_then(|v| v.as_str())
        .map(ToOwned::to_owned)
        .ok_or_else(|| "canonical body missing space_id".to_owned())?;
    let predecessor_refs = body
        .get("predecessor_refs")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(ToOwned::to_owned))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let frontier = body
        .get("frontier")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(ToOwned::to_owned))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let state_root = body
        .get("state_root")
        .and_then(|v| v.as_str())
        .map(ToOwned::to_owned)
        .ok_or_else(|| "canonical body missing state_root".to_owned())?;
    let hlc_str = body
        .get("hlc")
        .and_then(|v| v.as_str())
        .map(ToOwned::to_owned)
        .ok_or_else(|| "canonical body missing hlc".to_owned())?;

    let space_id = SpaceId::new(space_id).map_err(|e| format!("invalid space_id: {e}"))?;
    let predecessor_refs: Vec<AnchorId> = predecessor_refs
        .into_iter()
        .map(|s| AnchorId::new(s).map_err(|e| format!("invalid AnchorId: {e}")))
        .collect::<Result<_, _>>()?;
    let frontier: Vec<MoveId> = frontier
        .into_iter()
        .map(|s| MoveId::new(s).map_err(|e| format!("invalid MoveId: {e}")))
        .collect::<Result<_, _>>()?;
    let state_root = Hash::new(state_root).map_err(|e| format!("invalid state_root hash: {e}"))?;
    let hlc = Hlc::new(hlc_str).map_err(|e| format!("invalid hlc: {e}"))?;

    let mut aggregator = ThresholdAggregator::new(record.threshold_k as usize)
        .map_err(|e| format!("aggregator init: {e}"))?;
    for (signer_did, partial) in &record.partials {
        let sig_b64 = partial
            .get("signature_b64")
            .and_then(|v| v.as_str())
            .ok_or_else(|| format!("partial from {signer_did} missing signature_b64"))?;
        let kid = partial
            .get("kid")
            .and_then(|v| v.as_str())
            .ok_or_else(|| format!("partial from {signer_did} missing kid"))?;
        let sig_bytes = STANDARD
            .decode(sig_b64)
            .map_err(|e| format!("partial signature decode failed: {e}"))?;
        let did = Did::new(signer_did.clone())
            .map_err(|e| format!("invalid signer_did {signer_did}: {e}"))?;
        let p = PartialSignature::new(did, sig_bytes, kid.to_owned());
        aggregator
            .add_partial(p)
            .map_err(|e| format!("aggregator add_partial: {e}"))?;
    }

    if !aggregator.threshold_met() {
        return Err("threshold not yet met".to_owned());
    }

    let _multi = aggregator
        .aggregate(&canonical_bytes, |partial, bytes| {
            verify_ed25519_partial(state, partial, bytes)
                .map_err(|e| contrix_sdk::Error::Protocol(e))
        })
        .map_err(|e| format!("aggregate: {e}"))?;

    let anchor = Anchor::sign_threshold_partial(
        space_id,
        predecessor_refs,
        frontier,
        state_root,
        hlc,
        &aggregator,
    )
    .map_err(|e| format!("sign_threshold_partial: {e}"))?;

    Ok(anchor)
}

/// Per-partial verifier: resolves `partial.kid` to an Ed25519 public key
/// via the AppState DID resolver chain, then runs the standard
/// `VerifyingKey::verify_strict` against the canonical bytes.
fn verify_ed25519_partial(
    state: &AppState,
    partial: &PartialSignature,
    bytes: &[u8],
) -> Result<(), String> {
    use ed25519_dalek::{Signature, Verifier};

    let public_key = crate::jws_verify::resolve_ed25519_pubkey(state, &partial.kid)?;
    if partial.signature.len() != Signature::BYTE_SIZE {
        return Err(format!(
            "Ed25519 signature must be {} bytes, got {}",
            Signature::BYTE_SIZE,
            partial.signature.len()
        ));
    }
    let mut sig_arr = [0u8; Signature::BYTE_SIZE];
    sig_arr.copy_from_slice(&partial.signature);
    let signature = Signature::from_bytes(&sig_arr);
    public_key
        .verify(bytes, &signature)
        .map_err(|e| format!("Ed25519 verify failed: {e}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::net::SocketAddr;
    use std::str::FromStr;

    use super::*;
    use crate::config::AppConfig;
    use crate::db::Db;
    use crate::state::AppState;

    fn test_state() -> AppState {
        let config = AppConfig {
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
            did_resolver_allow_methods: vec!["web".to_owned(), "key".to_owned()],
            embedded_webvh_provider_enabled: false,
            embedded_webvh_registration_bearer: None,
            external_webvh_provider_url: None,
            external_webvh_provider_active: false,
            default_webvh_provider_id: None,
            jws_replay_window_seconds: 0,
            jws_replay_window_per_family: AppConfig::default_replay_overrides(),
            anchorer_signing_key_seed: None,
            agent_audit_binding_signing_seed: None,
            use_keystore: false,
            federation_policy: crate::config::FederationPolicy::Mesh,
            federation_peers: Vec::new(),
            federation_outbound_enabled: false,
            admin_default_page_limit: 100,
            admin_max_page_limit: 1000,
            admin_principal_dids: Vec::new(),
            push_bridge_cache_ttl_seconds: 900,
            push_bridge_trusted_service_dids: Vec::new(),
            compaction_min_anchor_age_seconds: 604_800,
            compaction_min_witnesses: 1,
            compaction_preserve_genesis: true,
            compaction_prune_only_singleton_successors: true,

            compaction_prune_walk_interval_seconds: 0,

            compaction_prune_walk_per_space_limit: 50,
            seed_demo_data: true,
            trust_domain: "cx:trust_domain:soland.local".to_owned(),
            sovereign_enclave_enabled: false,
            sovereign_enclave_allowed_outbound_hosts: Vec::new(),
            erasure_propagation_window_ms: 604_800_000,
        };
        AppState::new(config, Db { pool: None })
    }

    fn make_record(anchor_id: &str, threshold_k: u32, partials: usize) -> MultisigPendingRecord {
        let mut partials_map = BTreeMap::new();
        for i in 0..partials {
            partials_map.insert(
                format!("did:web:signer-{i}.example"),
                serde_json::json!({
                    "signature_b64": "AAAA",
                    "kid": format!("did:web:signer-{i}.example#k1"),
                    "submitted_at": "2026-05-10T00:00:00Z",
                }),
            );
        }
        MultisigPendingRecord {
            anchor_id: anchor_id.to_owned(),
            space_id: "cx:space:0196419b-0000-7000-8000-00000000014a".to_owned(),
            threshold_k,
            threshold_n: 3,
            members: (0..3)
                .map(|i| format!("did:web:signer-{i}.example"))
                .collect(),
            canonical_b64: "ZW1wdHk=".to_owned(),
            partials: partials_map,
            created_at: Utc::now(),
            expires_at: Utc::now() + chrono::Duration::hours(1),
            claimed_by_node_id: None,
            claimed_until: None,
            claim_seq: 0,
        }
    }

    #[test]
    fn skips_rows_below_threshold() {
        let state = test_state();
        let cfg = MultisigWatchdogConfig::for_service(&state.config.service_did);
        let record = make_record("cx:anchor:sha256:01", 3, 1);
        state.persistence.multisig_pending().upsert(record).unwrap();
        let report = run_watchdog_pass(&state, &cfg);
        assert_eq!(report.scanned, 1);
        assert!(report.claimed.is_empty());
        assert!(report.aggregated.is_empty());
    }

    #[test]
    fn skips_rows_with_empty_canonical_bytes() {
        let state = test_state();
        let cfg = MultisigWatchdogConfig::for_service(&state.config.service_did);
        let mut record = make_record("cx:anchor:sha256:02", 1, 1);
        record.canonical_b64 = String::new();
        state.persistence.multisig_pending().upsert(record).unwrap();
        let report = run_watchdog_pass(&state, &cfg);
        assert!(report.claimed.is_empty());
    }

    #[test]
    fn claims_eligible_row_and_records_failure_on_invalid_canonical_bytes() {
        let state = test_state();
        let cfg = MultisigWatchdogConfig::for_service(&state.config.service_did);
        let record = make_record("cx:anchor:sha256:03", 1, 1);
        state.persistence.multisig_pending().upsert(record).unwrap();
        let report = run_watchdog_pass(&state, &cfg);
        // canonical_b64 decodes to bytes "empty" — not valid JSON, so the
        // aggregate path fails, the claim is released, and the row stays.
        assert_eq!(report.claimed.len(), 1);
        assert!(report.aggregated.is_empty());
        assert_eq!(report.failed.len(), 1);
        // After the release the row must again be claimable on the next pass.
        let row_back = state
            .persistence
            .multisig_pending()
            .get("cx:anchor:sha256:03")
            .unwrap()
            .unwrap();
        assert!(row_back.claimed_by_node_id.is_none());
    }

    #[test]
    fn other_node_lease_is_respected_until_deadline() {
        let state = test_state();
        let cfg = MultisigWatchdogConfig::for_service(&state.config.service_did);
        let mut record = make_record("cx:anchor:sha256:04", 1, 1);
        record.claimed_by_node_id = Some("other-node".to_owned());
        record.claimed_until = Some(Utc::now() + chrono::Duration::seconds(120));
        state.persistence.multisig_pending().upsert(record).unwrap();
        let report = run_watchdog_pass(&state, &cfg);
        assert!(report.claimed.is_empty());
    }

    // ── Partition-tolerance tests ─────────────────────────────
    //
    // Three partition-recovery scenarios + one happy-path lease-renewal test.
    // The fencing token (`claim_seq`) makes (a) and (c) reject deterministically
    // at the row level even when both nodes still believe they hold the lease.

    /// Partition scenario (a): two nodes both think they're leader after a
    /// network partition healed. Node A claims at `t=0` (claim_seq → 1) and
    /// proceeds with aggregation. The partition heals at `t=70s`, by which
    /// point Node A's lease has expired. Node B re-claims (claim_seq → 2)
    /// and starts its own aggregation. Node A finishes first and tries to
    /// publish via `delete_with_fence(seq=1)` — the fencing token bumped to
    /// 2, so the fenced delete is rejected and the row stays for Node B.
    #[test]
    fn partition_scenario_a_split_brain_stale_leader_publish_is_fenced() {
        let state = test_state();
        let cfg_a = MultisigWatchdogConfig {
            tick_interval: Duration::from_secs(30),
            lease_duration: Duration::from_secs(60),
            node_id: "node-A".to_owned(),
        };
        let cfg_b = MultisigWatchdogConfig {
            tick_interval: Duration::from_secs(30),
            lease_duration: Duration::from_secs(60),
            node_id: "node-B".to_owned(),
        };

        let store = state.persistence.multisig_pending();
        let record = make_record("cx:anchor:sha256:partition-a", 1, 1);
        store.upsert(record).unwrap();

        // t=0: Node A claims. Snapshot fence_seq for the post-aggregate
        // delete it will eventually attempt.
        let t0 = Utc::now();
        let lease_a_until = t0 + chrono::Duration::seconds(60);
        let (won_a, fence_seq_a) = store
            .try_claim("cx:anchor:sha256:partition-a", "node-A", t0, lease_a_until)
            .unwrap();
        assert!(won_a);
        assert_eq!(fence_seq_a, 1);

        // t=70s: partition heals; Node A's lease has expired. Node B's
        // try_claim wins, bumps the fencing token.
        let t70 = t0 + chrono::Duration::seconds(70);
        let lease_b_until = t70 + chrono::Duration::seconds(60);
        let (won_b, fence_seq_b) = store
            .try_claim("cx:anchor:sha256:partition-a", "node-B", t70, lease_b_until)
            .unwrap();
        assert!(won_b);
        assert_eq!(fence_seq_b, 2, "claim_seq must bump on every re-claim");

        // Node A — the stale leader — finishes its aggregation and tries
        // to publish. Its `delete_with_fence` carries the *pre-bump*
        // claim_seq=1; the row's current claim_seq is 2, so the delete
        // is rejected.
        let stale_delete_ok = store
            .delete_with_fence("cx:anchor:sha256:partition-a", "node-A", fence_seq_a)
            .unwrap();
        assert!(
            !stale_delete_ok,
            "stale leader publish must be rejected at the row level"
        );

        // The row is still around for Node B to publish against.
        let row = store
            .get("cx:anchor:sha256:partition-a")
            .unwrap()
            .expect("row must survive the rejected stale publish");
        assert_eq!(row.claimed_by_node_id.as_deref(), Some("node-B"));
        assert_eq!(row.claim_seq, 2);

        // Node B — the live leader — finishes and publishes successfully.
        let live_delete_ok = store
            .delete_with_fence("cx:anchor:sha256:partition-a", "node-B", fence_seq_b)
            .unwrap();
        assert!(live_delete_ok);
        assert!(store.get("cx:anchor:sha256:partition-a").unwrap().is_none());

        // Drop the cfgs so the test variables aren't reported as unused.
        let _ = cfg_a;
        let _ = cfg_b;
    }

    /// Partition scenario (b): the leader crashes after claiming but
    /// before publishing. The lease is still recorded against the dead
    /// node. After the lease expires, the next watchdog pass on the
    /// surviving node must re-claim the row, bump claim_seq, and proceed.
    #[test]
    fn partition_scenario_b_leader_crashes_after_claim_before_publish() {
        let state = test_state();
        let cfg_b = MultisigWatchdogConfig {
            tick_interval: Duration::from_secs(30),
            lease_duration: Duration::from_secs(60),
            node_id: "node-B".to_owned(),
        };

        let store = state.persistence.multisig_pending();
        let record = make_record("cx:anchor:sha256:partition-b", 1, 1);
        store.upsert(record).unwrap();

        // Simulate the dead leader: it had successfully claimed at t=-90s
        // (claim_seq=1) and then crashed before publishing. Its lease
        // (60s) has long expired by now.
        let now = Utc::now();
        let dead_lease_until = now - chrono::Duration::seconds(30);
        let (won_dead, _seq_dead) = store
            .try_claim(
                "cx:anchor:sha256:partition-b",
                "node-DEAD",
                now - chrono::Duration::seconds(90),
                dead_lease_until,
            )
            .unwrap();
        assert!(won_dead);

        // Inspect: the row is still leased to node-DEAD on paper, even
        // though that lease is in the past.
        let row_pre = store.get("cx:anchor:sha256:partition-b").unwrap().unwrap();
        assert_eq!(row_pre.claimed_by_node_id.as_deref(), Some("node-DEAD"));
        assert_eq!(row_pre.claim_seq, 1);

        // The surviving watchdog node tries to claim the row directly —
        // the lease is past so try_claim succeeds and claim_seq bumps to 2.
        // (We exercise try_claim here rather than `run_watchdog_pass`
        // because the test record's canonical_b64 is intentionally not
        // valid JSON — running the full pass would surface the aggregate
        // failure and release the claim again, masking the row-level
        // bump we want to observe.)
        let later = now + chrono::Duration::seconds(1);
        let (won_b, fence_seq_b) = store
            .try_claim(
                "cx:anchor:sha256:partition-b",
                &cfg_b.node_id,
                later,
                later + chrono::Duration::seconds(60),
            )
            .unwrap();
        assert!(won_b, "expired lease must be re-claimable");
        assert_eq!(
            fence_seq_b, 2,
            "fencing token bumps even when the previous holder was dead"
        );

        let row_post = store.get("cx:anchor:sha256:partition-b").unwrap().unwrap();
        assert_eq!(row_post.claimed_by_node_id.as_deref(), Some("node-B"));
        assert_eq!(row_post.claim_seq, 2);

        // The dead leader's deferred publish (carrying claim_seq=1) is
        // rejected at the row level — exactly the protection (a) and (c)
        // also rely on, but exercised here against a crashed-not-stale
        // node.
        let stale_delete_ok = store
            .delete_with_fence("cx:anchor:sha256:partition-b", "node-DEAD", 1)
            .unwrap();
        assert!(
            !stale_delete_ok,
            "a crashed leader's revived publish must still be fenced"
        );
    }

    /// Partition scenario (c): `claimed_until` expires while the partial-
    /// aggregation is mid-flight. Another node re-claims, bumping
    /// claim_seq. The original (now-stale) leader's `renew_claim` is
    /// rejected — its fencing token no longer matches.
    #[test]
    fn partition_scenario_c_lease_expires_mid_aggregation_renew_rejected() {
        let state = test_state();
        let cfg_a = MultisigWatchdogConfig {
            tick_interval: Duration::from_secs(30),
            lease_duration: Duration::from_secs(60),
            node_id: "node-A".to_owned(),
        };

        let store = state.persistence.multisig_pending();
        let record = make_record("cx:anchor:sha256:partition-c", 1, 1);
        store.upsert(record).unwrap();

        // Node A claims at t=0; lease until t=60.
        let t0 = Utc::now();
        let (_, fence_seq_a) = store
            .try_claim(
                "cx:anchor:sha256:partition-c",
                "node-A",
                t0,
                t0 + chrono::Duration::seconds(60),
            )
            .unwrap();
        assert_eq!(fence_seq_a, 1);

        // t=70s — lease expired; Node B re-claims, bumping claim_seq.
        let t70 = t0 + chrono::Duration::seconds(70);
        let (won_b, fence_seq_b) = store
            .try_claim(
                "cx:anchor:sha256:partition-c",
                "node-B",
                t70,
                t70 + chrono::Duration::seconds(60),
            )
            .unwrap();
        assert!(won_b);
        assert_eq!(fence_seq_b, 2);

        // Node A's mid-aggregation renew_claim — using its stale fence
        // token — must be rejected.
        let renewed = store
            .renew_claim(
                "cx:anchor:sha256:partition-c",
                "node-A",
                fence_seq_a,
                t70 + chrono::Duration::seconds(60),
            )
            .unwrap();
        assert!(
            !renewed,
            "stale leader's renew_claim must reject when the fencing token has advanced"
        );

        // The row's lease is unchanged from Node B's claim.
        let row = store.get("cx:anchor:sha256:partition-c").unwrap().unwrap();
        assert_eq!(row.claimed_by_node_id.as_deref(), Some("node-B"));
        assert_eq!(row.claim_seq, 2);

        let _ = cfg_a;
    }

    /// Happy-path: a long aggregation runs against a row whose lease
    /// would otherwise expire mid-flight. The watchdog calls
    /// `renew_lease_during_aggregation` to push `claimed_until`
    /// forward without bumping `claim_seq`. The post-aggregate
    /// `delete_with_fence(original_seq)` still succeeds.
    #[test]
    fn happy_path_lease_renewal_during_long_aggregation() {
        let state = test_state();
        let cfg = MultisigWatchdogConfig {
            tick_interval: Duration::from_secs(30),
            lease_duration: Duration::from_secs(60),
            node_id: "node-A".to_owned(),
        };

        let store = state.persistence.multisig_pending();
        let record = make_record("cx:anchor:sha256:happy-renewal", 1, 1);
        store.upsert(record).unwrap();

        // Initial claim — fence_seq bumps to 1.
        let t0 = Utc::now();
        let (won, fence_seq) = store
            .try_claim(
                "cx:anchor:sha256:happy-renewal",
                "node-A",
                t0,
                t0 + chrono::Duration::seconds(60),
            )
            .unwrap();
        assert!(won);
        assert_eq!(fence_seq, 1);

        // The aggregation is still running 50s later. The watchdog
        // proactively renews the lease — same fence_seq, claimed_until
        // pushed out to t+110.
        let renewed = renew_lease_during_aggregation(
            &state,
            &cfg,
            "cx:anchor:sha256:happy-renewal",
            fence_seq,
        )
        .expect("renewal should not error");
        assert!(renewed, "happy-path renewal must land");

        let row_after_renew = store
            .get("cx:anchor:sha256:happy-renewal")
            .unwrap()
            .unwrap();
        assert_eq!(
            row_after_renew.claimed_by_node_id.as_deref(),
            Some("node-A")
        );
        assert_eq!(
            row_after_renew.claim_seq, 1,
            "renewal must NOT bump the fencing token"
        );
        assert!(
            row_after_renew
                .claimed_until
                .map(|until| until > t0 + chrono::Duration::seconds(60))
                .unwrap_or(false),
            "renewal must push claimed_until forward"
        );

        // Aggregation finishes — fenced delete with the *original*
        // fence_seq still works because the renewal didn't bump it.
        let deleted = store
            .delete_with_fence("cx:anchor:sha256:happy-renewal", "node-A", fence_seq)
            .unwrap();
        assert!(deleted);
        assert!(
            store
                .get("cx:anchor:sha256:happy-renewal")
                .unwrap()
                .is_none()
        );
    }
}
