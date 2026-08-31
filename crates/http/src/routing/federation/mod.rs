use salvo::prelude::*;

#[allow(clippy::module_inception)]
pub(crate) mod federation;
pub mod frontier_exchange;
mod frontier_reduction;
pub(crate) mod move_seal;
pub mod outbox;
pub mod outbox_operator;
pub mod rrk_acquisition;
pub(crate) mod well_known;

// SPEC-CR-001 — reused by `identity::session_pop` so self-PoP and the
// federation rail reconstruct the signed `@target-uri` / `@authority`
// identically.
pub(in crate::routing) use federation::{signature_authority, signature_target_uri};
pub use well_known::well_known_arkret_router;

use super::{AuthArgs, now, sync_token};

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

/// Deployment-local read-only federation diagnostics, mounted at
/// `/_soland/peer/federation/*`.
///
/// This is NOT the protocol federation surface: the cross-vendor S2S entry
/// point is the `peer_federation` surface group at `/_arkret/peer/*`
/// (outbound dispatch in this repo only ever targets `/_arkret/peer/events`).
/// The routes below expose deployment-local read/verification diagnostics only;
/// every federation write is accepted exclusively through
/// `POST /_arkret/peer/events`.
pub fn router() -> Router {
    Router::with_path("federation")
        .push(Router::with_path("realm-members").get(federation::federation_realm_members))
        .push(
            Router::with_path("actors/{actor_id}/events").get(federation::federation_actor_events),
        )
        .push(Router::with_path("verify-actor").post(federation::federation_verify_actor))
        .push(Router::with_path("seals").get(federation::federation_seals_pull))
}
