//! Snapshot/GC scanner.
//!
//! Walks the durable Move + Anchor stores and lists Moves that are NOT
//! referenced by any Anchor frontier AND that have no active pending Move
//! ref. Such Moves are MAY-GC candidates per the spec; the scanner does
//! NOT actually delete (yet) — it only enumerates.
//!
//! Two entry points:
//!   - [`scan_gc_candidates`] — pure function over an [`AppState`], used by both the admin endpoint
//!     and the cargo-runnable bin.
//!   - `bin/soland-gc-scan.rs` — `cargo run --bin soland-gc-scan -- \ --space-id <id> --dry-run`.

use contrix_sdk::state_res::{AnchorStore, MoveStore};
use contrix_sdk::{Move, MoveId, SpaceId};

use crate::state::AppState;

/// One GC candidate row. Keep the surface tiny — sodmin / ops only need
/// enough to render a list view; full Move bytes are a follow-up.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, salvo::oapi::ToSchema)]
pub struct GcCandidate {
    pub move_id: String,
    pub space_id: String,
    pub issuer: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// Reason this Move is GC-eligible, e.g. "not_in_any_anchor_frontier".
    pub reason: String,
}

/// Scan one space's Move + Anchor stores and emit GC candidates.
///
/// A Move is a candidate when ALL hold:
///   - It is in the anchored-Move log (`list_anchored`) — i.e. it was part of some Anchor's
///     frontier at some point.
///   - That referencing Anchor is NOT a current leaf — i.e. its frontier has been superseded.
///   - The Move is NOT in any current leaf's frontier (transitively, we compute the union of
///     leaf-Anchor frontiers).
///   - The Move is NOT in the pending pool (`list_pending_for_anchorer`).
pub fn scan_gc_candidates(state: &AppState, space_id: &SpaceId) -> Vec<GcCandidate> {
    let move_store = state.move_store.as_ref();
    let anchor_store = state.anchor_store.as_ref();

    // 1) Pending Move IDs — never GC.
    let pending: Vec<Move> = move_store
        .list_pending_for_anchorer(space_id, None, 4096)
        .unwrap_or_default();
    let pending_ids: std::collections::HashSet<String> =
        pending.iter().map(|m| m.id.to_string()).collect();

    // 2) Union of current leaf-Anchor frontiers. Moves still on the live frontier are also out of
    //    scope for GC.
    let leaves = anchor_store.list_leaves(space_id).unwrap_or_default();
    let mut live_frontier: std::collections::HashSet<String> = std::collections::HashSet::new();
    for leaf_id in &leaves {
        if let Ok(Some(anchor)) = anchor_store.get(leaf_id) {
            for move_id in &anchor.frontier {
                live_frontier.insert(move_id.to_string());
            }
        }
    }

    // 3) Walk the anchored-Move log; emit those that are neither pending nor on the live frontier.
    let mut candidates: Vec<GcCandidate> = Vec::new();
    let mut cursor: Option<MoveId> = None;
    loop {
        let page = match move_store.list_anchored(space_id, cursor.as_ref(), 256) {
            Ok(page) if !page.is_empty() => page,
            _ => break,
        };
        let next_cursor = page.last().map(|record| record.move_value.id.clone());
        for record in page {
            let id = record.move_value.id.to_string();
            if pending_ids.contains(&id) {
                continue;
            }
            if live_frontier.contains(&id) {
                continue;
            }
            candidates.push(GcCandidate {
                move_id: id,
                space_id: space_id.to_string(),
                issuer: record.move_value.issuer.to_string(),
                created_at: record.move_value.sig.created_at,
                reason: "not_in_any_anchor_frontier".to_owned(),
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

/// Scan every Space we know about. Used by the admin endpoint when no
/// `space_id` is provided.
pub fn scan_all_spaces(state: &AppState) -> Vec<GcCandidate> {
    let space_ids: Vec<SpaceId> = {
        let spaces = state.realms.lock().expect("spaces lock");
        spaces
            .search(Default::default())
            .into_iter()
            .filter_map(|entry| SpaceId::new(entry.realm_id.to_string()).ok())
            .collect()
    };
    space_ids
        .iter()
        .flat_map(|id| scan_gc_candidates(state, id))
        .collect()
}
