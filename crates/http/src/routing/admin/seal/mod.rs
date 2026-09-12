//! Read-oriented notary, Bottom, and Seal chain admin surface.
//!
//! Endpoints:
//! - `GET  /_soland/admin/realms/{realm_id}/notary` — typed notary cell value (`{kind, notary:
//!   NotaryValue, paused}`).
//! - `GET  /_soland/admin/realms/{realm_id}/bottom` — list cells whose join produced a `Bottom`
//!   diagnostic.
//! - `GET  /_soland/admin/bottom` — global cross-Realm list.
//! - `GET  /_soland/admin/realms/{realm_id}/seal-chain` — confirmed head + covered events +
//!   state_root
//!   snapshot.
//!
//! Principal/notary-key authoring is intentionally absent. Signed recovery moves, notary
//! reconfiguration and compaction Seals must arrive through their protocol
//! owners rather than being forged by the operator service.

use soland_http::error::AppError;

use super::AuthArgs;
use crate::app_error;

mod bottom;
mod chain;
mod gc;
mod notary;

#[cfg(test)]
mod tests;

pub(super) use bottom::{admin_list_bottom_global, admin_list_realm_bottom};
pub(super) use chain::admin_get_seal_chain;
pub(super) use gc::admin_list_gc_candidates;
pub(super) use notary::admin_get_notary;

/// Build the canonical notary cell ref for a Space.
pub(super) fn notary_cell_for(_realm_id: &str) -> Result<arkret_identifiers::CellRef, AppError> {
    arkret_identifiers::CellRef::new(arkret_wire::REALM_NOTARY_CELL.to_owned())
        .map_err(|e| app_error!(InternalError, "invalid canonical Realm notary cell: {e}"))
}
