//! Internal federation helpers.
//!
//! The formal server-to-server HTTP surface is `/_arkret/peer/*`. This module keeps
//! trust-header utilities and deployment-local read diagnostics.
//!
//! Production gaps: `validation_class` instead of bool and revocation fanout.

use super::{now, sync_token};

mod actor_signature;
mod endpoints;
mod inbound_policy;
mod outbound;
mod profile_intersection;
mod signature;
mod wire;

// Router-facing endpoint handlers, re-exported at the original
// `routing::federation::federation::<handler>` path so the parent module's
// `router()` assembly is unchanged.
// Test-only re-exports so `federation_tests.rs` (`use super::*`) keeps
// resolving the helpers it exercises after the structural split.
// Imports re-exported for `federation_tests.rs` (`use super::*`) which relies
// on these names resolving through the module that hosts `mod tests`.
pub(crate) use endpoints::FederationSealsOutcome;
pub(super) use endpoints::{
    federation_actor_events, federation_realm_members, federation_seals_pull,
    federation_verify_actor,
};
pub(crate) use inbound_policy::federation_actor_origin_acceptable;
pub(crate) use outbound::{
    configured_peer_targets, peer_trust_domain_for_service_id, peer_url_for_service_id,
};
pub(crate) use profile_intersection::federation_profile_intersection_for_peer;
#[cfg(test)]
use salvo::http::StatusCode;
pub(crate) use signature::trust_domain_from_service_id;
pub(in crate::routing) use signature::{
    signature_authority, signature_target_uri, verify_inbound_peer_http_signature,
};
#[cfg(test)]
use signature::{validate_federation_headers, validate_signature_input};
pub(crate) use wire::{
    FederationTrustHeaders, delivery_binding_handed_over_response, delivery_binding_stale_response,
};

#[cfg(test)]
#[path = "../federation_tests.rs"]
mod tests;
