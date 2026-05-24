//! MAL-11 compaction prune walk worker.
//!
//! A tokio background task that wakes every
//! [`AppConfig::compaction_prune_walk_interval_seconds`] seconds, walks
//! every live Space's anchor DAG, evaluates each candidate Anchor against
//! [`contrix_sdk::CompactionPolicy::is_eligible`], and prunes the eligible
//! ones via [`AnchorStore::prune_predecessor`]. Bounded per-Space by
//! [`AppConfig::compaction_prune_walk_per_space_limit`] so a single tick
//! never tries to prune a huge backlog at once — further candidates land
//! on the next pass.
//!
//! ## When to enable
//!
//! Disabled by default (`SOLAND_COMPACTION_PRUNE_WALK_INTERVAL_SECS=0`).
//! Enable when the deployment observes anchor-DAG growth or Pg dead-tuple
//! pressure on the `anchors` table; the explicit `POST
//! /api/admin/v1/spaces/{space_id}/anchor-dag/prune?anchor_id=...`
//! endpoint remains the operator-driven path either way and continues to
//! work whether or not the worker is running.
//!
//! ## What it does NOT do
//!
//! - **No lease coordination**. Single-process worker today; multi-node
//!   deployments running the worker simultaneously will all try to prune
//!   the same candidates. `prune_predecessor` is structurally idempotent
//!   (a second call on an already-pruned anchor returns
//!   [`StoreError::NotFound`]) so duplicates fail soft rather than
//!   corrupt the DAG, but a real multi-node cluster wants a lease layer
//!   on top of this (see [`multisig_watchdog`] for the pattern).
//! - **No metrics surface**. The pass returns a [`CompactorPassReport`]
//!   so tests + callers can inspect outcomes; a `tracing::info!` line is
//!   logged when anything was pruned or rejected.
//! - **No back-pressure on Pg**. The walk just iterates and prunes; for
//!   very large DAGs the operator should bound the per-Space limit
//!   conservatively (default 50/pass) and accept that catching up takes
//!   multiple passes.

use std::collections::{BTreeSet, VecDeque};
use std::sync::Arc;
use std::time::Duration;

use contrix_sdk::state_res::AnchorStore;
use contrix_sdk::{Anchor, AnchorId, PruneCandidate, PruneEligibility, SpaceId};

use crate::state::AppState;

/// Outcome of one prune-walk pass. Tracks every Space visited + the
/// per-candidate verdicts so tests can assert deterministic behavior.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CompactorPassReport {
    /// Number of Spaces inspected this pass.
    pub spaces_scanned: usize,
    /// Number of candidate Anchors evaluated (across all Spaces).
    pub candidates_evaluated: usize,
    /// Anchor ids that were successfully pruned this pass.
    pub pruned: Vec<String>,
    /// Anchor ids that the store rejected (e.g. not-found because another
    /// pass already pruned them).
    pub prune_errors: Vec<(String, String)>,
    /// Per-Space candidates that the policy rejected (kept for tests; not
    /// every reject is interesting — `TooYoung` will be the common case
    /// when the worker first turns on).
    pub policy_rejects: Vec<(String, &'static str)>,
}

/// Spawn the periodic prune-walk loop on the current tokio runtime.
/// Returns an `Arc<JoinHandle>` so the caller (typically `main.rs`) can
/// `abort()` it at shutdown.
///
/// No-op (returns `None`) when
/// [`AppConfig::compaction_prune_walk_interval_seconds`] is zero —
/// i.e. the worker is disabled. The explicit prune endpoint still works.
pub fn spawn(state: AppState) -> Option<Arc<tokio::task::JoinHandle<()>>> {
    let interval_secs = state.config.compaction_prune_walk_interval_seconds;
    if interval_secs == 0 {
        return None;
    }
    let interval = Duration::from_secs(interval_secs);
    let per_space_limit = state.config.compaction_prune_walk_per_space_limit.max(1);
    let task = tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        // Skip the immediate first tick so we don't fire mid-boot before
        // the rest of AppState is wired.
        ticker.tick().await;
        loop {
            ticker.tick().await;
            let report = run_compactor_pass(&state, per_space_limit);
            if !report.pruned.is_empty() || !report.prune_errors.is_empty() {
                tracing::info!(
                    worker = "compactor",
                    spaces_scanned = report.spaces_scanned,
                    candidates_evaluated = report.candidates_evaluated,
                    pruned = report.pruned.len(),
                    rejected = report.prune_errors.len(),
                    "MAL-11 compactor pass complete",
                );
            }
        }
    });
    Some(Arc::new(task))
}

/// Run one synchronous prune-walk pass. Pulled out of [`spawn`] so unit
/// tests can drive deterministic single-tick behavior without a running
/// tokio runtime.
pub fn run_compactor_pass(state: &AppState, per_space_limit: usize) -> CompactorPassReport {
    let mut report = CompactorPassReport::default();
    let spaces: Vec<SpaceId> = {
        let registry = state.realms.lock().expect("spaces lock");
        registry
            .search(Default::default())
            .into_iter()
            .filter_map(|space| SpaceId::new(space.realm_id.to_string()).ok())
            .collect()
    };
    report.spaces_scanned = spaces.len();
    let policy = state.config.compaction_policy();
    let anchor_store = state.anchor_store.as_ref();
    let now_ms = chrono::Utc::now().timestamp_millis();

    for space_id in &spaces {
        let candidates = match collect_candidate_anchors(anchor_store, space_id, per_space_limit) {
            Ok(c) => c,
            Err(error) => {
                tracing::warn!(
                    %error,
                    worker = "compactor",
                    space_id = %space_id,
                    "compactor: failed to enumerate candidate anchors",
                );
                continue;
            }
        };
        let mut pruned_this_space = 0usize;
        for candidate_id in candidates {
            if pruned_this_space >= per_space_limit {
                break;
            }
            let Ok(Some(candidate)) = anchor_store.get(&candidate_id) else {
                continue;
            };
            report.candidates_evaluated += 1;
            let diagnostics = evaluate_candidate(anchor_store, space_id, &candidate, now_ms);
            let prune_candidate = PruneCandidate {
                candidate: &candidate,
                age_seconds: diagnostics.age_seconds,
                compaction_witnesses: diagnostics.compaction_witnesses,
                successor_count: diagnostics.successor_count,
                is_genesis: diagnostics.is_genesis,
            };
            match policy.is_eligible(&prune_candidate) {
                PruneEligibility::Eligible => {
                    match anchor_store.prune_predecessor(space_id, &candidate_id) {
                        Ok(_) => {
                            report.pruned.push(candidate_id.as_str().to_owned());
                            pruned_this_space += 1;
                        }
                        Err(error) => {
                            report
                                .prune_errors
                                .push((candidate_id.as_str().to_owned(), error.to_string()));
                        }
                    }
                }
                other => {
                    report
                        .policy_rejects
                        .push((candidate_id.as_str().to_owned(), eligibility_wire(&other)));
                }
            }
        }
    }
    report
}

/// Collect candidate anchor ids by walking backward from each leaf via
/// `predecessor_refs`. Leaves are excluded (we never prune a leaf — there
/// would be nothing to rewire its successor pointer through), and we
/// short-circuit once we have ~ `per_space_limit * 3` candidates so very
/// deep DAGs don't allocate unboundedly per pass. Excess candidates land
/// on the next tick.
///
/// Returns anchor ids in BFS order from the leaves; that's a stable
/// traversal that doesn't favor any particular fork.
fn collect_candidate_anchors(
    anchor_store: &dyn AnchorStore,
    space_id: &SpaceId,
    per_space_limit: usize,
) -> Result<Vec<AnchorId>, String> {
    let leaves = anchor_store
        .list_leaves(space_id)
        .map_err(|e| e.to_string())?;
    let mut visited: BTreeSet<String> = BTreeSet::new();
    // Initialize visited with leaves so we don't propose them as
    // candidates — the policy's `successor_count > 0` requirement would
    // reject every leaf anyway (their successor set is empty), but
    // pre-filtering keeps the candidate stream short.
    for leaf in &leaves {
        visited.insert(leaf.as_str().to_owned());
    }
    let mut queue: VecDeque<AnchorId> = leaves.into_iter().collect();
    let mut candidates: Vec<AnchorId> = Vec::new();
    // Soft cap so a deep DAG doesn't allocate unboundedly. Excess
    // candidates are picked up on the next pass.
    let soft_cap = per_space_limit.saturating_mul(3).max(64);
    while let Some(next) = queue.pop_front() {
        if candidates.len() >= soft_cap {
            break;
        }
        // Inspect this anchor's parents — they become candidates.
        let anchor: Anchor = match anchor_store.get(&next).map_err(|e| e.to_string())? {
            Some(a) => a,
            None => continue,
        };
        for parent in &anchor.predecessor_refs {
            if !visited.insert(parent.as_str().to_owned()) {
                continue;
            }
            candidates.push(parent.clone());
            queue.push_back(parent.clone());
        }
    }
    Ok(candidates)
}

/// Diagnostics block matching the per-candidate inputs the admin prune
/// endpoint computes. Kept private — the worker doesn't surface this on
/// any wire shape; tests inspect it via `evaluate_candidate` directly.
#[derive(Clone, Debug, PartialEq, Eq)]
struct CandidateDiagnostics {
    age_seconds: u64,
    compaction_witnesses: u32,
    successor_count: usize,
    is_genesis: bool,
}

fn evaluate_candidate(
    anchor_store: &dyn AnchorStore,
    space_id: &SpaceId,
    candidate: &Anchor,
    now_ms: i64,
) -> CandidateDiagnostics {
    let candidate_id = candidate.id.clone();
    let successors = anchor_store
        .successors(space_id, &candidate_id)
        .unwrap_or_default();
    let successor_count = successors.len();
    let mut compaction_witnesses: u32 = 0;
    let mut visited: BTreeSet<String> = BTreeSet::new();
    let mut stack: Vec<AnchorId> = successors.clone();
    while let Some(next_id) = stack.pop() {
        if !visited.insert(next_id.as_str().to_owned()) {
            continue;
        }
        if let Ok(Some(succ_anchor)) = anchor_store.get(&next_id) {
            if succ_anchor.kind.is_compaction() {
                compaction_witnesses = compaction_witnesses.saturating_add(1);
            }
            if let Ok(next_succs) = anchor_store.successors(space_id, &next_id) {
                stack.extend(next_succs);
            }
        }
    }
    let is_genesis = match anchor_store.genesis(space_id) {
        Ok(Some(g)) => g.as_str() == candidate_id.as_str(),
        _ => false,
    };
    let age_seconds = match crate::jws_verify::physical_millis_from_hlc(candidate.hlc.as_str()) {
        Some(ms) => ((now_ms - ms).max(0) as u64) / 1000,
        None => 0,
    };
    CandidateDiagnostics {
        age_seconds,
        compaction_witnesses,
        successor_count,
        is_genesis,
    }
}

fn eligibility_wire(eligibility: &PruneEligibility) -> &'static str {
    match eligibility {
        PruneEligibility::Eligible => "eligible",
        PruneEligibility::TooYoung { .. } => "too_young",
        PruneEligibility::InsufficientWitnesses { .. } => "insufficient_witnesses",
        PruneEligibility::PreservedGenesis => "preserved_genesis",
        PruneEligibility::ForkPoint { .. } => "fork_point",
        PruneEligibility::CompactionItself => "compaction_itself",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AppConfig, FederationPolicy, ObjectStorageConfig};
    use crate::db::Db;
    use std::collections::BTreeMap;
    use std::net::SocketAddr;
    use std::str::FromStr;

    fn test_config() -> AppConfig {
        AppConfig {
            bind: SocketAddr::from_str("127.0.0.1:0").unwrap(),
            public_base_url: "http://test".to_owned(),
            service_did: "did:web:test.local".to_owned(),
            tls_cert_path: None,
            tls_key_path: None,
            database_url: None,
            object_storage: ObjectStorageConfig::local(std::env::temp_dir()),
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
            jws_replay_window_per_family: BTreeMap::new(),
            anchorer_signing_key_seed: None,
            agent_audit_binding_signing_seed: None,
            use_keystore: false,
            federation_policy: FederationPolicy::Mesh,
            federation_peers: Vec::new(),
            federation_outbound_enabled: false,
            admin_default_page_limit: 100,
            admin_max_page_limit: 1000,
            admin_principal_dids: Vec::new(),
            push_bridge_cache_ttl_seconds: 900,
            push_bridge_trusted_service_dids: Vec::new(),
            // Aggressive policy for tests: 0-age + 0 witnesses + don't
            // require the singleton-successor / preserve-genesis guards so
            // any non-leaf becomes prunable.
            compaction_min_anchor_age_seconds: 0,
            compaction_min_witnesses: 0,
            compaction_preserve_genesis: false,
            compaction_prune_only_singleton_successors: false,
            compaction_prune_walk_interval_seconds: 0,
            compaction_prune_walk_per_space_limit: 50,
            seed_demo_data: true,
            trust_domain: "cx:trust_domain:soland.local".to_owned(),
            sovereign_enclave_enabled: false,
            sovereign_enclave_allowed_outbound_hosts: Vec::new(),
            erasure_propagation_window_ms: 604_800_000,
        }
    }

    #[test]
    fn fresh_state_produces_zero_prunes() {
        // `AppState::new` seeds a demo Space (so `spaces_scanned` may be
        // 1 here, not 0), but a freshly-built state has zero Anchors in
        // the in-memory anchor_store, so the walk produces no candidates
        // and no prunes.
        let state = AppState::new(test_config(), Db { pool: None });
        let report = run_compactor_pass(&state, 50);
        assert_eq!(report.candidates_evaluated, 0);
        assert!(report.pruned.is_empty());
        assert!(report.prune_errors.is_empty());
    }

    #[test]
    fn spawn_is_noop_when_interval_is_zero() {
        let state = AppState::new(test_config(), Db { pool: None });
        // interval=0 means worker disabled — `spawn` returns None.
        assert!(spawn(state).is_none());
    }
}
