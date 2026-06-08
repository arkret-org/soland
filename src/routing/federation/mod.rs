use salvo::prelude::*;

pub mod erasure_fanout;
#[allow(clippy::module_inception)]
pub(crate) mod federation;
pub(crate) mod move_anchor;
pub mod outbox;
pub(crate) mod stubs;

pub use stubs::well_known_cokret_router;

use super::{
    AuthArgs, ingest_federation_operations, now, operation_is_visible,
    redaction_targets_from_operations, sha256_hex, sync_token, validate_did,
};

/// Operator anchor-signing endpoint (`POST /_soland/admin/anchors/sign`). Mounted
/// at the bare deployment-local `/admin/*` namespace on the root router
/// (NOT under `/_cokret/...`), alongside the rest of the admin surface.
pub fn admin_anchor_sign_router() -> Router {
    move_anchor::api_admin_router()
}

pub fn router() -> Router {
    Router::new().push(move_anchor::router()).push(
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
                Router::with_path("anchors")
                    .get(federation::federation_anchors_pull)
                    .post(federation::federation_anchors_push),
            ),
    )
}
