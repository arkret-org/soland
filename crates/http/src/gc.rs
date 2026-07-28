//! Snapshot/GC scanner.
//!
//! Walks the durable Control Event + Seal stores and lists Control Moves that
//! are NOT referenced by any live Seal coverage set AND that are not pending.
//! Such Control Moves are MAY-GC candidates per the spec; the scanner does NOT
//! actually delete (yet) — it only enumerates.
//!
//! A Control Move is an ordinary Event carrying `seal_basis`
//! (`event-auth-state-resolution.md` §5), so candidates are keyed by canonical
//! `event_digest`, not by a Move id.
//!
//! Two entry points:
//!   - [`scan_gc_candidates`] — pure function over an [`AppState`], used by both the admin endpoint
//!     and the cargo-runnable bin.
//!   - `bin/soland-gc-scan.rs` — `cargo run --bin soland-gc-scan -- --realm-id <id> --dry-run`.

use arkret_identifiers::{Hash, RealmId};

use crate::state::AppState;

/// One GC candidate row. Keep the surface tiny — sodmin / ops only need
/// enough to render a list view; full Event bytes are a follow-up.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, salvo::oapi::ToSchema)]
pub struct GcCandidate {
    /// Canonical `event_digest` of the sealed Control Move.
    pub event_digest: String,
    pub realm_id: String,
    pub issuer: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// Reason this Control Move is GC-eligible, e.g. "not_in_live_seal_coverage".
    pub reason: String,
}

/// Scan one Realm's Control Event + Seal stores and emit GC candidates.
///
/// A Control Move is a candidate when ALL hold:
///   - It is in the sealed control-event log (`list_sealed`) — i.e. it was part of some Seal
///     coverage set.
///   - That referencing Seal is NOT a current leaf — i.e. its coverage has been superseded.
///   - The Control Move is NOT in any current leaf coverage set.
///   - The Control Move is NOT in the pending pool (`list_pending_for_notary`).
pub fn scan_gc_candidates(state: &AppState, realm_id: &RealmId) -> Vec<GcCandidate> {
    let projections = state.projections();

    // 1) Pending Control Move digests — never GC.
    let pending = projections
        .pending_control_events_for_notary(realm_id, None, 4096)
        .unwrap_or_default();
    let pending_digests: std::collections::HashSet<String> = pending
        .iter()
        .filter_map(|event| event.event_digest().ok())
        .collect();

    // 2) Union of current leaf-Seal coverage. Control Moves still covered by live leaves are also
    //    out of scope for GC.
    let leaves = projections.realm_seal_leaves(realm_id).unwrap_or_default();
    let mut live_coverage: std::collections::HashSet<String> = std::collections::HashSet::new();
    if let Ok(covered) = projections.predecessor_covered_events(&leaves) {
        live_coverage.extend(covered.into_iter().map(|digest| digest.to_string()));
    }

    // 3) Walk the sealed control-event log; emit those that are neither pending nor live-covered.
    let mut candidates: Vec<GcCandidate> = Vec::new();
    let mut cursor: Option<Hash> = None;
    loop {
        let page = match projections.sealed_control_events(realm_id, cursor.as_ref(), 256) {
            Ok(page) if !page.is_empty() => page,
            _ => break,
        };
        let next_cursor = page
            .last()
            .and_then(|record| record.event.event_digest().ok())
            .and_then(|digest| Hash::new(digest).ok());
        for record in page {
            let Ok(digest) = record.event.event_digest() else {
                continue;
            };
            if pending_digests.contains(&digest) {
                continue;
            }
            if live_coverage.contains(&digest) {
                continue;
            }
            candidates.push(GcCandidate {
                event_digest: digest,
                realm_id: realm_id.to_string(),
                issuer: record.event.actor_id.to_string(),
                created_at: record.event.created_at,
                reason: "not_in_live_seal_coverage".to_owned(),
            });
        }
        cursor = next_cursor;
        // Avoid infinite loop on backends that don't support cursor.
        if cursor.is_none() {
            break;
        }
    }

    candidates
}

/// Scan every Realm we know about. Used by the admin endpoint when no
/// `realm_id` is provided.
pub fn scan_all_realms(state: &AppState) -> Vec<GcCandidate> {
    let realm_ids: Vec<RealmId> = {
        let realms = state.realm_directory().snapshot();
        realms
            .search(Default::default())
            .into_iter()
            .filter_map(|entry| RealmId::new(entry.realm_id.to_string()).ok())
            .collect()
    };
    realm_ids
        .iter()
        .flat_map(|id| scan_gc_candidates(state, id))
        .collect()
}
