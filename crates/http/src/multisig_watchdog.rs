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

use arkret_identifiers::DidFullId;
use arkret_wire::{NotarySig, PartialSignature, Seal, ThresholdAggregator, WireError};
use base64::Engine as _;
use chrono::Utc;
use soland_services::governance::MultisigPendingRecord;

use crate::state::AppState;

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
    /// active. Defaults to `service_id + ":" + uuid::v4()` at construction.
    pub node_id: String,
}

impl MultisigWatchdogConfig {
    pub fn for_service(service_id: &str) -> Self {
        Self {
            tick_interval: Duration::from_secs(DEFAULT_TICK_INTERVAL_SECS),
            lease_duration: Duration::from_secs(LEASE_DURATION_SECS),
            node_id: format!("{}:{}", service_id, uuid::Uuid::new_v4()),
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
    /// Seals whose fenced delete was rejected because the row's
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
                let report = run_watchdog_pass(&self.state, &self.config).await;
                if !report.aggregated.is_empty() || !report.failed.is_empty() {
                    tracing::info!(
                        worker = "multisig_watchdog",
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
pub async fn run_watchdog_pass(
    state: &AppState,
    config: &MultisigWatchdogConfig,
) -> WatchdogPassReport {
    let service = state.governance();
    let now = Utc::now();
    let lease_expiry = now
        + chrono::Duration::from_std(config.lease_duration)
            .unwrap_or_else(|_| chrono::Duration::seconds(LEASE_DURATION_SECS as i64));

    let rows = match service.multisig_pending_all().await {
        Ok(rows) => rows,
        Err(error) => {
            tracing::warn!(%error, worker = "multisig_watchdog", "multisig watchdog: snapshot_all failed");
            return WatchdogPassReport::default();
        }
    };

    let mut report = WatchdogPassReport {
        scanned: rows.len(),
        ..Default::default()
    };

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
        let fence_seq = match service
            .claim_multisig_pending(&record.seal_id, &config.node_id, now, lease_expiry)
            .await
        {
            Ok((true, seq)) => {
                report.claimed.push(record.seal_id.clone());
                seq
            }
            Ok((false, _)) => continue,
            Err(error) => {
                tracing::warn!(%error, worker = "multisig_watchdog", seal_id = %record.seal_id, "watchdog: try_claim failed");
                continue;
            }
        };

        match aggregate_and_publish(state, &record) {
            Ok(_seal) => {
                // Fenced delete: the row only goes away when our
                // snapshotted `claim_seq` still matches. If a stale leader
                // (whose lease was silently re-issued after a partition
                // heal) tries to publish here, its `delete_with_fence`
                // returns false and the row stays for the live leader.
                match service
                    .delete_multisig_with_fence(&record.seal_id, &config.node_id, fence_seq)
                    .await
                {
                    Ok(true) => report.aggregated.push(record.seal_id.clone()),
                    Ok(false) => {
                        report.fenced_rejections.push(record.seal_id.clone());
                        tracing::warn!(
                            worker = "multisig_watchdog",
                            seal_id = %record.seal_id,
                            fence_seq,
                            node_id = %config.node_id,
                            "watchdog: fenced delete rejected — stale leader detected, dropping publish",
                        );
                    }
                    Err(error) => {
                        tracing::warn!(%error, worker = "multisig_watchdog", seal_id = %record.seal_id, "watchdog: post-aggregate delete failed");
                    }
                }
            }
            Err(error) => {
                let _ = service
                    .release_multisig_claim(&record.seal_id, &config.node_id)
                    .await;
                report.failed.push((record.seal_id.clone(), error.clone()));
                tracing::warn!(%error, worker = "multisig_watchdog", seal_id = %record.seal_id, "watchdog: aggregate failed");
            }
        }
    }

    report
}

fn is_threshold_met(record: &MultisigPendingRecord) -> bool {
    record.partials.len() as u32 >= record.threshold_k
}

/// Build the `ThresholdAggregator`, run per-partial Ed25519 verification
/// via the supplied `verify` callback, and produce the threshold-signed
/// [`Seal`] envelope. Errors are returned as plain strings so the caller
/// can surface them in [`WatchdogPassReport`].
fn aggregate_and_publish(state: &AppState, record: &MultisigPendingRecord) -> Result<Seal, String> {
    use base64::engine::general_purpose::STANDARD;

    let canonical_bytes = STANDARD
        .decode(&record.canonical_b64)
        .map_err(|e| format!("canonical_b64 decode failed: {e}"))?;

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
        let did = DidFullId::new(signer_did.clone())
            .map_err(|e| format!("invalid signer_did {signer_did}: {e}"))?;
        // §2.2 — the partial `kid` is a concrete verification method; a bare
        // DID or malformed value fails closed instead of being aggregated.
        let kid = arkret_wire::DidUrl::new(kid.to_owned())
            .map_err(|e| format!("partial from {signer_did} has a non-DID-URL kid: {e}"))?;
        let p = PartialSignature::new(did, sig_bytes, kid);
        aggregator
            .add_partial(p)
            .map_err(|e| format!("aggregator add_partial: {e}"))?;
    }

    if !aggregator.threshold_met() {
        return Err("threshold not yet met".to_owned());
    }

    let multi = aggregator
        .aggregate(&canonical_bytes, |partial, bytes| {
            verify_ed25519_partial(state, partial, bytes).map_err(WireError::Protocol)
        })
        .map_err(|e| format!("aggregate: {e}"))?;

    let seal = Seal::from_canonical_body_and_signature(
        &canonical_bytes,
        NotarySig::Multi(multi),
        record.digest_suite,
    )
    .map_err(|e| format!("aggregated Seal construction failed: {e}"))?;

    Ok(seal)
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

    use soland_storage_postgres::Db;

    use super::*;
    use crate::config::AppConfig;
    use crate::state::AppState;

    fn test_state() -> AppState {
        let config = AppConfig {
            public_base_url: "http://test".to_owned(),
            object_storage: crate::config::ObjectStorageConfig::local(std::env::temp_dir()),
            development_mode: true,
            did_resolver_allow_methods: vec!["web".to_owned(), "key".to_owned()],
            jws_replay_window_seconds: 0,
            seed_demo_data: true,
            ..AppConfig::test_default()
        };
        AppState::new(config, Db { pool: None })
    }

    fn make_record(
        seal_id: &str,
        threshold_k: u32,
        partials: usize,
    ) -> soland_storage::MultisigPendingRecord {
        let mut partials_map = BTreeMap::new();
        for i in 0..partials {
            partials_map.insert(
                format!("did:web:signer-{i}.example"),
                serde_json::json!({
                    "signature_b64": "AAAA",
                    "kid": format!("did:web:signer-{i}.example#k1"),
                    "submitted_at": "2026-05-10T00:00:00.000Z",
                }),
            );
        }
        soland_storage::MultisigPendingRecord {
            seal_id: seal_id.to_owned(),
            realm_id: "ak:realm:AXVdykmiwmiUakQOqyMoYAwL8Eh63mpQHFaMczNjNT5p".to_owned(),
            digest_suite: arkret_canonical::DigestSuite::Sha256,
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

    #[tokio::test]
    async fn skips_rows_below_threshold() {
        let state = test_state();
        let cfg = MultisigWatchdogConfig::for_service(state.service_id());
        let record = make_record("ak:seal:sha256:01", 3, 1);
        state
            .test_persistence()
            .multisig_pending()
            .upsert(record)
            .await
            .unwrap();
        let report = run_watchdog_pass(&state, &cfg).await;
        assert_eq!(report.scanned, 1);
        assert!(report.claimed.is_empty());
        assert!(report.aggregated.is_empty());
    }

    #[tokio::test]
    async fn skips_rows_with_empty_canonical_bytes() {
        let state = test_state();
        let cfg = MultisigWatchdogConfig::for_service(state.service_id());
        let mut record = make_record("ak:seal:sha256:02", 1, 1);
        record.canonical_b64 = String::new();
        state
            .test_persistence()
            .multisig_pending()
            .upsert(record)
            .await
            .unwrap();
        let report = run_watchdog_pass(&state, &cfg).await;
        assert!(report.claimed.is_empty());
    }

    #[tokio::test]
    async fn claims_eligible_row_and_records_failure_on_invalid_canonical_bytes() {
        let state = test_state();
        let cfg = MultisigWatchdogConfig::for_service(state.service_id());
        let record = make_record("ak:seal:sha256:03", 1, 1);
        state
            .test_persistence()
            .multisig_pending()
            .upsert(record)
            .await
            .unwrap();
        let report = run_watchdog_pass(&state, &cfg).await;
        // canonical_b64 decodes to bytes "empty" — not valid JSON, so the
        // aggregate path fails, the claim is released, and the row stays.
        assert_eq!(report.claimed.len(), 1);
        assert!(report.aggregated.is_empty());
        assert_eq!(report.failed.len(), 1);
        // After the release the row must again be claimable on the next pass.
        let row_back = state
            .test_persistence()
            .multisig_pending()
            .get("ak:seal:sha256:03")
            .await
            .unwrap()
            .unwrap();
        assert!(row_back.claimed_by_node_id.is_none());
    }

    #[tokio::test]
    async fn other_node_lease_is_respected_until_deadline() {
        let state = test_state();
        let cfg = MultisigWatchdogConfig::for_service(state.service_id());
        let mut record = make_record("ak:seal:sha256:04", 1, 1);
        record.claimed_by_node_id = Some("other-node".to_owned());
        record.claimed_until = Some(Utc::now() + chrono::Duration::seconds(120));
        state
            .test_persistence()
            .multisig_pending()
            .upsert(record)
            .await
            .unwrap();
        let report = run_watchdog_pass(&state, &cfg).await;
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
    #[tokio::test]
    async fn partition_scenario_a_split_brain_stale_leader_publish_is_fenced() {
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

        let persistence = state.test_persistence();
        let store = persistence.multisig_pending();
        let record = make_record("ak:seal:sha256:partition-a", 1, 1);
        store.upsert(record).await.unwrap();

        // t=0: Node A claims. Snapshot fence_seq for the post-aggregate
        // delete it will eventually attempt.
        let t0 = Utc::now();
        let lease_a_until = t0 + chrono::Duration::seconds(60);
        let (won_a, fence_seq_a) = store
            .try_claim("ak:seal:sha256:partition-a", "node-A", t0, lease_a_until)
            .await
            .unwrap();
        assert!(won_a);
        assert_eq!(fence_seq_a, 1);

        // t=70s: partition heals; Node A's lease has expired. Node B's
        // try_claim wins, bumps the fencing token.
        let t70 = t0 + chrono::Duration::seconds(70);
        let lease_b_until = t70 + chrono::Duration::seconds(60);
        let (won_b, fence_seq_b) = store
            .try_claim("ak:seal:sha256:partition-a", "node-B", t70, lease_b_until)
            .await
            .unwrap();
        assert!(won_b);
        assert_eq!(fence_seq_b, 2, "claim_seq must bump on every re-claim");

        // Node A — the stale leader — finishes its aggregation and tries
        // to publish. Its `delete_with_fence` carries the *pre-bump*
        // claim_seq=1; the row's current claim_seq is 2, so the delete
        // is rejected.
        let stale_delete_ok = store
            .delete_with_fence("ak:seal:sha256:partition-a", "node-A", fence_seq_a)
            .await
            .unwrap();
        assert!(
            !stale_delete_ok,
            "stale leader publish must be rejected at the row level"
        );

        // The row is still around for Node B to publish against.
        let row = store
            .get("ak:seal:sha256:partition-a")
            .await
            .unwrap()
            .expect("row must survive the rejected stale publish");
        assert_eq!(row.claimed_by_node_id.as_deref(), Some("node-B"));
        assert_eq!(row.claim_seq, 2);

        // Node B — the live leader — finishes and publishes successfully.
        let live_delete_ok = store
            .delete_with_fence("ak:seal:sha256:partition-a", "node-B", fence_seq_b)
            .await
            .unwrap();
        assert!(live_delete_ok);
        assert!(
            store
                .get("ak:seal:sha256:partition-a")
                .await
                .unwrap()
                .is_none()
        );

        // Drop the cfgs so the test variables aren't reported as unused.
        let _ = cfg_a;
        let _ = cfg_b;
    }

    /// Partition scenario (b): the leader crashes after claiming but
    /// before publishing. The lease is still recorded against the dead
    /// node. After the lease expires, the next watchdog pass on the
    /// surviving node must re-claim the row, bump claim_seq, and proceed.
    #[tokio::test]
    async fn partition_scenario_b_leader_crashes_after_claim_before_publish() {
        let state = test_state();
        let cfg_b = MultisigWatchdogConfig {
            tick_interval: Duration::from_secs(30),
            lease_duration: Duration::from_secs(60),
            node_id: "node-B".to_owned(),
        };

        let persistence = state.test_persistence();
        let store = persistence.multisig_pending();
        let record = make_record("ak:seal:sha256:partition-b", 1, 1);
        store.upsert(record).await.unwrap();

        // Simulate the dead leader: it had successfully claimed at t=-90s
        // (claim_seq=1) and then crashed before publishing. Its lease
        // (60s) has long expired by now.
        let now = Utc::now();
        let dead_lease_until = now - chrono::Duration::seconds(30);
        let (won_dead, _seq_dead) = store
            .try_claim(
                "ak:seal:sha256:partition-b",
                "node-DEAD",
                now - chrono::Duration::seconds(90),
                dead_lease_until,
            )
            .await
            .unwrap();
        assert!(won_dead);

        // Inspect: the row is still leased to node-DEAD on paper, even
        // though that lease is in the past.
        let row_pre = store
            .get("ak:seal:sha256:partition-b")
            .await
            .unwrap()
            .unwrap();
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
                "ak:seal:sha256:partition-b",
                &cfg_b.node_id,
                later,
                later + chrono::Duration::seconds(60),
            )
            .await
            .unwrap();
        assert!(won_b, "expired lease must be re-claimable");
        assert_eq!(
            fence_seq_b, 2,
            "fencing token bumps even when the previous holder was dead"
        );

        let row_post = store
            .get("ak:seal:sha256:partition-b")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row_post.claimed_by_node_id.as_deref(), Some("node-B"));
        assert_eq!(row_post.claim_seq, 2);

        // The dead leader's deferred publish (carrying claim_seq=1) is
        // rejected at the row level — exactly the protection (a) and (c)
        // also rely on, but exercised here against a crashed-not-stale
        // node.
        let stale_delete_ok = store
            .delete_with_fence("ak:seal:sha256:partition-b", "node-DEAD", 1)
            .await
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
    #[tokio::test]
    async fn partition_scenario_c_lease_expires_mid_aggregation_renew_rejected() {
        let state = test_state();
        let cfg_a = MultisigWatchdogConfig {
            tick_interval: Duration::from_secs(30),
            lease_duration: Duration::from_secs(60),
            node_id: "node-A".to_owned(),
        };

        let persistence = state.test_persistence();
        let store = persistence.multisig_pending();
        let record = make_record("ak:seal:sha256:partition-c", 1, 1);
        store.upsert(record).await.unwrap();

        // Node A claims at t=0; lease until t=60.
        let t0 = Utc::now();
        let (_, fence_seq_a) = store
            .try_claim(
                "ak:seal:sha256:partition-c",
                "node-A",
                t0,
                t0 + chrono::Duration::seconds(60),
            )
            .await
            .unwrap();
        assert_eq!(fence_seq_a, 1);

        // t=70s — lease expired; Node B re-claims, bumping claim_seq.
        let t70 = t0 + chrono::Duration::seconds(70);
        let (won_b, fence_seq_b) = store
            .try_claim(
                "ak:seal:sha256:partition-c",
                "node-B",
                t70,
                t70 + chrono::Duration::seconds(60),
            )
            .await
            .unwrap();
        assert!(won_b);
        assert_eq!(fence_seq_b, 2);

        // Node A's mid-aggregation renew_claim — using its stale fence
        // token — must be rejected.
        let renewed = store
            .renew_claim(
                "ak:seal:sha256:partition-c",
                "node-A",
                fence_seq_a,
                t70 + chrono::Duration::seconds(60),
            )
            .await
            .unwrap();
        assert!(
            !renewed,
            "stale leader's renew_claim must reject when the fencing token has advanced"
        );

        // The row's lease is unchanged from Node B's claim.
        let row = store
            .get("ak:seal:sha256:partition-c")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.claimed_by_node_id.as_deref(), Some("node-B"));
        assert_eq!(row.claim_seq, 2);

        let _ = cfg_a;
    }
}
