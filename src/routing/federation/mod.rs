use salvo::prelude::*;

mod federation;
pub(crate) mod move_anchor;
pub mod outbox;

use super::{
    AuthArgs, ingest_federation_operations, now, operation_is_visible,
    redaction_targets_from_operations, sha256_hex, sync_token, validate_space_id,
};

pub fn router() -> Router {
    Router::new()
        .push(move_anchor::router())
        .push(move_anchor::api_admin_router())
        .push(
            Router::with_path("federation/transactions/{txn_id}")
                .put(federation::federation_transaction),
        )
        .push(
            Router::with_path("federation/push-operations")
                .post(federation::federation_push_operations),
        )
        .push(
            Router::with_path("federation/pull-operations")
                .get(federation::federation_pull_operations),
        )
        .push(
            Router::with_path("federation/space-members").get(federation::federation_space_members),
        )
        .push(
            Router::with_path("federation/verify-actor").post(federation::federation_verify_actor),
        )
        .push(
            Router::with_path("federation/anchors")
                .get(federation::federation_anchors_pull)
                .post(federation::federation_anchors_push),
        )
}
