use salvo::prelude::*;

pub mod erasure_fanout;
#[allow(clippy::module_inception)]
pub(crate) mod federation;
pub mod frontier_exchange;
pub(crate) mod move_seal;
pub mod outbox;
pub(crate) mod stubs;

// SPEC-CR-001 — reused by `identity::session_pop` so self-PoP and the
// federation rail reconstruct the signed `@target-uri` / `@authority`
// identically.
pub(in crate::routing) use federation::{signature_authority, signature_target_uri};
pub use stubs::well_known_cokret_router;

use super::{
    AuthArgs, ingest_federation_operations, now, operation_is_visible,
    redaction_targets_from_operations, sha256_hex, sync_token,
};

/// RFC 9530 `Content-Digest` structured-field value over `bytes`:
/// `sha-256=:<base64(SHA256(bytes))>:`.
///
/// Single source of truth for the federation S2S surface — the outbound
/// dispatcher, the per-peer outbox, and the invite delivery rail all derive the
/// same header from this helper so the wire byte encoding / base64 variant can
/// never drift between sign and verify. Callers decide which bytes to feed (raw
/// body vs canonical JSON); this only maps `bytes -> header string`.
pub(crate) fn rfc9530_content_digest(bytes: &[u8]) -> String {
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD;
    use sha2::{Digest, Sha256};
    format!("sha-256=:{}:", STANDARD.encode(Sha256::digest(bytes)))
}

/// Operator seal-signing endpoint (`POST /_soland/admin/seals/sign`). Mounted
/// at the bare deployment-local `/admin/*` namespace on the root router
/// (NOT under `/_cokret/...`), alongside the rest of the admin surface.
pub fn admin_seal_sign_router() -> Router {
    move_seal::api_admin_router()
}

/// Deployment-local inbound federation rail, mounted at `/_soland/peer/*`.
///
/// This is NOT the protocol federation surface: the cross-vendor S2S entry
/// point is the `peer_federation` surface group at `/_cokret/peer/*`
/// (outbound dispatch in this repo only ever targets `/_cokret/peer/events`).
/// The routes below (Matrix-style transactions, operations push/pull/
/// backfill/frontier, Move/Seal direct ingest, realm-members,
/// verify-actor) exist for local testing and operations; describe advertises
/// them under `profile_limitations` as `federation.private_inbound_rail` so
/// remote peers cannot mistake them for an interop contract. Long-term plan:
/// converge Move/Seal ingest into the `/_cokret/peer/events` envelope
/// channel and downgrade or delete this rail.
pub fn router() -> Router {
    Router::new().push(move_seal::router()).push(
        Router::with_path("federation")
            .push(
                Router::with_path("transactions/{txn_id}").post(federation::federation_transaction),
            )
            .push(
                Router::with_path("operations")
                    .post(federation::federation_push_operations)
                    .get(federation::federation_pull_operations),
            )
            .push(
                Router::with_path("operations/backfill")
                    .post(federation::federation_backfill_operations),
            )
            .push(
                Router::with_path("operations/frontier")
                    .get(federation::federation_operation_frontier),
            )
            .push(Router::with_path("realm-members").get(federation::federation_realm_members))
            .push(
                Router::with_path("actors/{actor_id}/events")
                    .get(federation::federation_actor_events),
            )
            .push(Router::with_path("verify-actor").post(federation::federation_verify_actor))
            .push(
                Router::with_path("seals")
                    .get(federation::federation_seals_pull)
                    .post(federation::federation_seals_push),
            ),
    )
}
