//! Internal federation helpers.
//!
//! The formal server-to-server HTTP surface is `/_arkret/peer/*`. This module keeps
//! trust-header utilities and local migration helpers that are not mounted as peer routes.
//!
//! Production gaps: `validation_class` instead of bool, reducer-profile
//! digest enforcement, revocation fanout, and a long-running retry daemon.
//! Outbound Move/Seal broadcast helpers persist a per-peer signed request
//! transcript plus retry/durability metadata before returning targets so cotest
//! can observe the durable boundary instead of a purely opaque log.

use super::{
    ingest_federation_operations, now, operation_is_visible, redaction_targets_from_operations,
    sha256_hex, sync_token,
};
use crate::state::AppState;

mod actor_signature;
mod backfill;
mod endpoints;
mod inbound_policy;
mod outbound;
mod profile_intersection;
mod signature;
mod wire;

/// Placeholder status stamped by `try_begin` while an inbound federation
/// transaction is being ingested. A row in this state means some worker
/// claimed the `(origin, txn_id)` idempotency slot but has not yet written
/// the final response.
const FEDERATION_TXN_STATUS_PROCESSING: &str = "processing";

/// How long a `processing` placeholder is honoured before a retry may take
/// the slot over. A claim older than this means the claiming worker crashed
/// between `try_begin` and the finalising `put` (the ingest path itself is
/// non-blocking), so the transaction would otherwise be stuck returning
/// `temporarily_unavailable` forever.
const FEDERATION_TXN_PROCESSING_TAKEOVER_SECS: i64 = 60;

fn verify_federation_origin(origin: &str) -> bool {
    if !origin.starts_with("did:") {
        return false;
    }
    let rest = &origin[4..];
    if let Some(colon_pos) = rest.find(':') {
        let method = &rest[..colon_pos];
        let name = &rest[colon_pos + 1..];
        !method.is_empty() && method.chars().all(|c| c.is_ascii_lowercase()) && !name.is_empty()
    } else {
        false
    }
}

fn federation_destination_matches(state: &AppState, destination: &str) -> bool {
    destination == state.service_id
}

// Router-facing endpoint handlers, re-exported at the original
// `routing::federation::federation::<handler>` path so the parent module's
// `router()` assembly is unchanged.
// Test-only re-exports so `federation_tests.rs` (`use super::*`) keeps
// resolving the helpers it exercises after the structural split.
#[cfg(test)]
use actor_signature::federation_verify_actor_digest;
#[cfg(test)]
use arkret_sdk::{Operation, RealmId};
#[cfg(test)]
use backfill::operation_frontier_value;
// Cross-module helpers consumed elsewhere in `crate::routing`.
pub(crate) use backfill::peer_url_for_service_id;
// Outbound broadcast helpers used by the parent module's Move/Seal handlers.
pub use backfill::{broadcast_move_to_peers, broadcast_seal_to_peers};
// Imports re-exported for `federation_tests.rs` (`use super::*`) which relies
// on these names resolving through the module that hosts `mod tests`.
#[cfg(test)]
use chrono::{Duration, Utc};
pub(super) use endpoints::{
    federation_actor_events, federation_backfill_operations, federation_operation_frontier,
    federation_pull_operations, federation_push_operations, federation_realm_members,
    federation_seals_pull, federation_seals_push, federation_transaction, federation_verify_actor,
};
pub(super) use inbound_policy::ensure_private_inbound_write_rail_local;
// Local inbound write-rail guard, used by the parent module's Move/Seal
// ingest handlers (`super::federation::ensure_private_inbound_write_rail_local`).
pub(crate) use inbound_policy::federation_actor_origin_acceptable;
pub(crate) use outbound::configured_peer_targets;
#[cfg(test)]
pub(crate) use outbound::test_app_state_with_peers;
#[cfg(test)]
use outbound::{next_retry_at, run_outbound_fanout_retry_pass_at};
pub(crate) use profile_intersection::federation_profile_intersection_for_peer;
#[cfg(test)]
use salvo::http::StatusCode;
#[cfg(test)]
use serde_json::{Value, json};
pub(crate) use signature::trust_domain_from_service_id;
pub(in crate::routing) use signature::{
    signature_authority, signature_target_uri, verify_inbound_peer_http_signature,
};
#[cfg(test)]
use signature::{validate_federation_headers, validate_signature_params};
pub(crate) use wire::{
    FederationTrustHeaders, delivery_binding_handed_over_response, delivery_binding_stale_response,
};


#[cfg(test)]
#[path = "../federation_tests.rs"]
mod tests;
