//! Federation surface helpers.
//!
//! The formal server-to-server HTTP surface is `/_arkret/peer/*`; this module
//! holds the trust-header, signature and outbound-dispatch utilities that
//! surface is built from, plus the operator seal-signing router.
//!
//! Production gaps: `validation_class` instead of bool and revocation fanout.

use salvo::prelude::*;

pub(crate) mod erasure_receipts;
pub mod frontier_exchange;
mod frontier_reduction;
mod inbound_policy;
pub(crate) mod move_seal;
mod outbound;
pub mod outbox;
pub mod outbox_operator;
mod profile_intersection;
pub mod rhrk_acquisition;
mod signature;
pub(crate) mod well_known;
mod wire;

pub(crate) use inbound_policy::{
    federation_mls_actor_route_acceptable, joined_actor_for_principal_route,
};
pub(crate) use outbound::{
    configured_peer_targets, peer_url_for_service_id, resolved_peer_base_url, resolved_peer_route,
    resolved_peer_target,
};
pub(crate) use profile_intersection::federation_profile_intersection_for_peer;
#[cfg(test)]
use salvo::http::StatusCode;
// SPEC-CR-001 — `signature_authority` / `signature_target_uri` are reused by
// `identity::session_pop` so self-PoP and the federation rail reconstruct the
// signed `@target-uri` / `@authority` identically.
pub(in crate::routing) use signature::{
    signature_authority, signature_target_uri, verify_inbound_peer_http_signature,
};
#[cfg(test)]
use signature::{validate_federation_headers, validate_signature_input};
pub use well_known::well_known_arkret_router;
pub(crate) use wire::FederationTrustHeaders;

use super::AuthArgs;

#[cfg(test)]
#[path = "federation_tests.rs"]
mod tests;

/// RFC 9530 `Content-Digest` structured-field value over `bytes`:
/// `sha-256=:<base64(SHA256(bytes))>:`.
///
/// Single source of truth for the federation S2S surface — the outbound
/// dispatcher, the per-peer outbox, and the invite delivery rail all derive the
/// same header from this helper so the wire byte encoding / base64 variant can
/// never drift between sign and verify. Callers decide which bytes to feed (raw
/// body vs canonical JSON); this only maps `bytes -> header string`.
pub(crate) fn rfc9530_content_digest(bytes: &[u8]) -> String {
    soland_http::http_signature::rfc9530_content_digest(bytes)
}

/// DID verification method used by the service's persistent assertion key
/// for federation HTTP Message Signatures. Service identity bootstrap
/// publishes this method in the Provider-registered DID document.
pub fn federation_service_signature_key_id(service_did: &str) -> String {
    format!("{service_did}#federation-fanout-key")
}

/// Operator seal-signing endpoint (`POST /_soland/admin/seals/sign`). Mounted
/// at the bare deployment-local `/admin/*` namespace on the root router
/// (NOT under `/_arkret/...`), alongside the rest of the admin surface.
pub fn admin_seal_sign_router() -> Router {
    move_seal::api_admin_router()
}
