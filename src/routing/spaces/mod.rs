use salvo::prelude::*;

pub(super) mod directory;
mod index;
mod reaction;
mod read_marker;
mod relation;
pub(super) mod space;

use super::{
    AuthArgs, accept_local_operations, append_audit_log, authenticated_session,
    default_discussion_track, device_inventory_to_json, effective_read_receipt_policy_for_space,
    flow_id_from_space_id, generate_invite_token, handle_for_did, invite_token_space_id,
    is_space_deleted, is_valid_discoverability, normalize_handle, now,
    space_discoverability, space_resolvable_to, space_search_discoverability,
    space_search_visible_to, validate_did, validate_space_id,
};

pub fn router() -> Router {
    Router::new()
        .push(space::router())
        .push(reaction::router())
        .push(
            Router::with_path("read-markers")
                .post(read_marker::set_read_marker)
                .get(read_marker::get_read_markers),
        )
        .push(Router::with_path("receipts/read").post(read_marker::send_read_receipt))
        .push(relation::router())
        .push(directory::router())
        .push(index::router())
}
