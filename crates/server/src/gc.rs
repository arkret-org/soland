//! Snapshot/GC scanner.
//!
//! Walks the durable Move + Seal stores and lists Moves that are NOT
//! referenced by any live Seal coverage set AND that have no active
//! pending Move ref. Such Moves are MAY-GC candidates per the spec; the
//! scanner does NOT actually delete (yet) — it only enumerates.
//!
//! Two entry points:
//!   - [`scan_gc_candidates`] — pure function over an [`AppState`], used by both the admin endpoint
//!     and the cargo-runnable bin.
//!   - `bin/soland-gc-scan.rs` — `cargo run --bin soland-gc-scan -- --realm-id <id> --dry-run`.

use cokret_sdk::state_res::{MoveStore, SealStore, union_predecessor_covered_events};
use cokret_sdk::{Move, MoveId, RealmId};

use crate::state::AppState;

/// One GC candidate row. Keep the surface tiny — sodmin / ops only need
/// enough to render a list view; full Move bytes are a follow-up.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, salvo::oapi::ToSchema)]
pub struct GcCandidate {
    pub move_id: String,
    pub realm_id: String,
    pub issuer: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// Reason this Move is GC-eligible, e.g. "not_in_live_seal_coverage".
    pub reason: String,
}

/// Scan one Realm's Move + Seal stores and emit GC candidates.
///
/// A Move is a candidate when ALL hold:
///   - It is in the sealed-Move log (`list_sealed`) — i.e. it was part of some Seal coverage set.
///   - That referencing Seal is NOT a current leaf — i.e. its coverage has been superseded.
///   - The Move is NOT in any current leaf coverage set.
///   - The Move is NOT in the pending pool (`list_pending_for_notary`).
pub fn scan_gc_candidates(state: &AppState, realm_id: &RealmId) -> Vec<GcCandidate> {
    let move_store = state.move_store.as_ref();
    let seal_store = state.seal_store.as_ref();

    // 1) Pending Move IDs — never GC.
    let pending: Vec<Move> = move_store
        .list_pending_for_notary(realm_id, None, 4096)
        .unwrap_or_default();
    let pending_ids: std::collections::HashSet<String> =
        pending.iter().map(|m| m.id.to_string()).collect();

    // 2) Union of current leaf-Seal coverage. Moves still covered by live leaves are also out of
    //    scope for GC.
    let leaves = seal_store.list_leaves(realm_id).unwrap_or_default();
    let mut live_coverage: std::collections::HashSet<String> = std::collections::HashSet::new();
    if let Ok(covered) = union_predecessor_covered_events(&leaves, seal_store) {
        live_coverage.extend(covered.into_iter().map(|move_id| move_id.to_string()));
    }

    // 3) Walk the sealed-Move log; emit those that are neither pending nor live-covered.
    let mut candidates: Vec<GcCandidate> = Vec::new();
    let mut cursor: Option<MoveId> = None;
    loop {
        let page = match move_store.list_sealed(realm_id, cursor.as_ref(), 256) {
            Ok(page) if !page.is_empty() => page,
            _ => break,
        };
        let next_cursor = page.last().map(|record| record.move_value.id.clone());
        for record in page {
            let id = record.move_value.id.to_string();
            if pending_ids.contains(&id) {
                continue;
            }
            if live_coverage.contains(&id) {
                continue;
            }
            candidates.push(GcCandidate {
                move_id: id,
                realm_id: realm_id.to_string(),
                issuer: record.move_value.issuer.to_string(),
                created_at: record.move_value.sig.created_at,
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
        let realms = state.realms.lock().expect("realms lock");
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
