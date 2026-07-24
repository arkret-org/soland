//! MAL-11 compaction prune walk worker.
//!
//! A tokio background task that wakes every
//! [`AppConfig::compaction_prune_walk_interval_seconds`] seconds, walks
//! every live Realm's seal DAG, evaluates each candidate Seal against
//! [`arkret_state::CompactionPolicy::is_eligible`], and prunes the eligible
//! ones via [`SealStore::prune_predecessor`]. Bounded per-Realm by
//! [`AppConfig::compaction_prune_walk_per_realm_limit`] so a single tick
//! never tries to prune a huge backlog at once — further candidates land
//! on the next pass.
//!
//! ## When to enable
//!
//! Disabled by default (`SOLAND_COMPACTION_PRUNE_WALK_INTERVAL_SECS=0`).
//! Enable when the deployment observes seal-DAG growth or Pg dead-tuple
//! pressure on the `seals` table; the explicit `POST
//! /_soland/admin/realms/{realm_id}/seal-dag/prune?seal_id=...`
//! endpoint remains the operator-driven path either way and continues to
//! work whether or not the worker is running.
//!
//! ## What it does NOT do
//!
//! - **No lease coordination**. Single-process worker today; multi-node deployments running the
//!   worker simultaneously will all try to prune the same candidates. `prune_predecessor` is
//!   structurally idempotent (a second call on an already-pruned seal returns
//!   [`StoreError::NotFound`]) so duplicates fail soft rather than corrupt the DAG, but a real
//!   multi-node cluster wants a lease layer on top of this (see [`multisig_watchdog`] for the
//!   pattern).
//! - **No metrics surface**. The pass returns a [`CompactorPassReport`] so tests + callers can
//!   inspect outcomes; a `tracing::info!` line is logged when anything was pruned or rejected.
//! - **No back-pressure on Pg**. The walk just iterates and prunes; for very large DAGs the
//!   operator should bound the per-Realm limit conservatively (default 50/pass) and accept that
//!   catching up takes multiple passes.

use std::collections::{BTreeSet, VecDeque};
use std::sync::Arc;
use std::time::Duration;

use arkret_identifiers::{RealmId, SealId};
use arkret_state::{PruneCandidate, PruneEligibility};
use arkret_wire::Seal;

use crate::state::AppState;

/// Outcome of one prune-walk pass. Tracks every Realm visited + the
/// per-candidate verdicts so tests can assert deterministic behavior.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CompactorPassReport {
    /// Number of Realms inspected this pass.
    pub realms_scanned: usize,
    /// Number of candidate Seals evaluated (across all Realms).
    pub candidates_evaluated: usize,
    /// Seal ids that were successfully pruned this pass.
    pub pruned: Vec<String>,
    /// Seal ids that the store rejected (e.g. not-found because another
    /// pass already pruned them).
    pub prune_errors: Vec<(String, String)>,
    /// Per-Realm candidates that the policy rejected (kept for tests; not
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
    let interval_secs = state.config().compaction_prune_walk_interval_seconds;
    if interval_secs == 0 {
        return None;
    }
    let interval = Duration::from_secs(interval_secs);
    let per_realm_limit = state.config().compaction_prune_walk_per_realm_limit.max(1);
    let task = tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        // Skip the immediate first tick so we don't fire mid-boot before
        // the rest of AppState is wired.
        ticker.tick().await;
        loop {
            ticker.tick().await;
            let report = run_compactor_pass(&state, per_realm_limit);
            if !report.pruned.is_empty() || !report.prune_errors.is_empty() {
                tracing::info!(
                    worker = "compactor",
                    realms_scanned = report.realms_scanned,
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
pub fn run_compactor_pass(state: &AppState, per_realm_limit: usize) -> CompactorPassReport {
    let mut report = CompactorPassReport::default();
    let realms: Vec<RealmId> = {
        let registry = state.realm_directory().snapshot();
        registry
            .search(Default::default())
            .into_iter()
            .filter_map(|realm| RealmId::new(realm.realm_id.to_string()).ok())
            .collect()
    };
    report.realms_scanned = realms.len();
    let policy = state.config().compaction_policy();
    let projections = state.projections();
    let now_ms = chrono::Utc::now().timestamp_millis();

    for realm_id in &realms {
        let candidates = match collect_candidate_seals(projections, realm_id, per_realm_limit) {
            Ok(c) => c,
            Err(error) => {
                tracing::warn!(
                    %error,
                    worker = "compactor",
                    realm_id = %realm_id,
                    "compactor: failed to enumerate candidate seals",
                );
                continue;
            }
        };
        let mut pruned_this_realm = 0usize;
        for candidate_id in candidates {
            if pruned_this_realm >= per_realm_limit {
                break;
            }
            let Ok(Some(candidate)) = projections.seal_by_id(&candidate_id) else {
                continue;
            };
            report.candidates_evaluated += 1;
            let diagnostics = evaluate_candidate(projections, realm_id, &candidate, now_ms);
            let prune_candidate = PruneCandidate {
                candidate: &candidate,
                age_seconds: diagnostics.age_seconds,
                compaction_witnesses: diagnostics.compaction_witnesses,
                successor_count: diagnostics.successor_count,
                is_genesis: diagnostics.is_genesis,
            };
            match policy.is_eligible(&prune_candidate) {
                PruneEligibility::Eligible => {
                    match projections.prune_seal_predecessor(realm_id, &candidate_id) {
                        Ok(_) => {
                            report.pruned.push(candidate_id.as_str().to_owned());
                            pruned_this_realm += 1;
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

/// Collect candidate seal ids by walking backward from each leaf via
/// `predecessor_refs`. Leaves are excluded (we never prune a leaf — there
/// would be nothing to rewire its successor pointer through), and we
/// short-circuit once we have ~ `per_realm_limit * 3` candidates so very
/// deep DAGs don't allocate unboundedly per pass. Excess candidates land
/// on the next tick.
///
/// Returns seal ids in BFS order from the leaves; that's a stable
/// traversal that doesn't favor any particular fork.
fn collect_candidate_seals(
    projections: &soland_services::projection::ProjectionService,
    realm_id: &RealmId,
    per_realm_limit: usize,
) -> Result<Vec<SealId>, String> {
    let leaves = projections
        .realm_seal_leaves(realm_id)
        .map_err(|e| e.to_string())?;
    let mut visited: BTreeSet<String> = BTreeSet::new();
    // Initialize visited with leaves so we don't propose them as
    // candidates — the policy's `successor_count > 0` requirement would
    // reject every leaf anyway (their successor set is empty), but
    // pre-filtering keeps the candidate stream short.
    for leaf in &leaves {
        visited.insert(leaf.as_str().to_owned());
    }
    let mut queue: VecDeque<SealId> = leaves.into_iter().collect();
    let mut candidates: Vec<SealId> = Vec::new();
    // Soft cap so a deep DAG doesn't allocate unboundedly. Excess
    // candidates are picked up on the next pass.
    let soft_cap = per_realm_limit.saturating_mul(3).max(64);
    while let Some(next) = queue.pop_front() {
        if candidates.len() >= soft_cap {
            break;
        }
        // Inspect this seal's parents — they become candidates.
        let seal: Seal = match projections.seal_by_id(&next).map_err(|e| e.to_string())? {
            Some(a) => a,
            None => continue,
        };
        for parent in &seal.predecessor_refs {
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
    projections: &soland_services::projection::ProjectionService,
    realm_id: &RealmId,
    candidate: &Seal,
    now_ms: i64,
) -> CandidateDiagnostics {
    let candidate_id = candidate.id.clone();
    let successors = projections
        .seal_successors(realm_id, &candidate_id)
        .unwrap_or_default();
    let successor_count = successors.len();
    let mut compaction_witnesses: u32 = 0;
    let mut visited: BTreeSet<String> = BTreeSet::new();
    let mut stack: Vec<SealId> = successors.clone();
    while let Some(next_id) = stack.pop() {
        if !visited.insert(next_id.as_str().to_owned()) {
            continue;
        }
        if let Ok(Some(succ_seal)) = projections.seal_by_id(&next_id) {
            if succ_seal.kind.is_compaction() {
                compaction_witnesses = compaction_witnesses.saturating_add(1);
            }
            if let Ok(next_succs) = projections.seal_successors(realm_id, &next_id) {
                stack.extend(next_succs);
            }
        }
    }
    let is_genesis = match projections.genesis_seal_id(realm_id) {
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
    use std::collections::BTreeMap;

    use soland_storage_postgres::Db;

    use super::*;
    use crate::config::{AppConfig, ObjectStorageConfig};

    fn test_config() -> AppConfig {
        AppConfig {
            public_base_url: "http://test".to_owned(),
            object_storage: ObjectStorageConfig::local(std::env::temp_dir()),
            development_mode: true,
            did_resolver_allow_methods: vec!["web".to_owned(), "key".to_owned()],
            jws_replay_window_seconds: 0,
            jws_replay_window_per_family: BTreeMap::new(),
            seal_compaction_min_age_seconds: 0,
            compaction_min_witnesses: 0,
            compaction_preserve_genesis: false,
            compaction_prune_only_singleton_successors: false,
            seed_demo_data: true,
            ..AppConfig::test_default()
        }
    }

    #[test]
    fn fresh_state_produces_zero_prunes() {
        // `AppState::new` seeds a demo Realm (so `realms_scanned` may be
        // 1 here, not 0), but a freshly-built state has zero Seals in
        // the in-memory seal_store, so the walk produces no candidates
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


