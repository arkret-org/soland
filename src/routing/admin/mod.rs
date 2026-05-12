use salvo::prelude::*;

mod anchor;
pub(crate) mod audit;
mod cells;
mod collection;
mod control;

use super::system::util;
use super::{
    AuthArgs, auth_or_render, demo_actors, device_inventory_to_json,
    discussion_track_for_projection_event, flow_id_for_projection_event, flow_id_from_space_id,
    flow_projection_for_space, now, policy_document_to_response, projection_event_from_operation,
    query_param, render_error, sha256_hex,
};
use audit::append_audit_log;

pub fn router() -> Router {
    Router::new()
        .push(cells::router())
        .push(Router::with_path("admin/{resource}").get(collection::admin_collection))
        .push(control::router())
        .push(audit::router())
}

pub fn admin_router() -> Router {
    Router::with_path("api/admin/v1")
        .oapi_tag("admin")
        .push(Router::with_path("spaces/{space_id}/anchorer").get(anchor::admin_get_anchorer))
        .push(
            Router::with_path("spaces/{space_id}/anchorer/reconfigure")
                .post(anchor::admin_reconfigure_anchorer),
        )
        .push(
            Router::with_path("spaces/{space_id}/anchorer/rotate-signing-key")
                .post(anchor::admin_rotate_signing_key),
        )
        .push(Router::with_path("spaces/{space_id}/bottom").get(anchor::admin_list_space_bottom))
        .push(Router::with_path("bottom").get(anchor::admin_list_bottom_global))
        .push(
            Router::with_path("spaces/{space_id}/bottom/{cell_id}/repair")
                .post(anchor::admin_repair_bottom),
        )
        .push(Router::with_path("spaces/{space_id}/anchor-dag").get(anchor::admin_get_anchor_dag))
        .push(
            Router::with_path("spaces/{space_id}/anchor-dag/compact")
                .post(anchor::admin_compact_anchor_dag),
        )
        .push(
            Router::with_path("spaces/{space_id}/multisig/pending")
                .get(anchor::admin_list_multisig_pending),
        )
        .push(
            Router::with_path("spaces/{space_id}/multisig/{anchor_id}/partial")
                .post(anchor::admin_submit_multisig_partial),
        )
        .push(
            Router::with_path("spaces/{space_id}/gc-candidates")
                .get(anchor::admin_list_gc_candidates),
        )
}
