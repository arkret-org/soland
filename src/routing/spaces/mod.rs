use salvo::prelude::*;

pub(super) mod directory;
mod index;
mod reaction;
mod read_cursor;
mod relation;
pub(super) mod space;

use super::{
    AuthArgs, accept_local_operations, authenticated_session, default_discussion_track,
    device_inventory_to_json, flow_id_from_space_id, handle_for_did, invite_token_space_id,
    is_space_deleted, normalize_handle, now, sha256_hex, space_discoverability, space_has_member,
    space_resolvable_to, space_search_discoverability, space_search_visible_to, validate_space_id,
};

pub fn router() -> Router {
    Router::new()
        .push(space::router())
        .push(reaction::router())
        .push(
            Router::with_path("read-cursors")
                .post(read_cursor::set_read_cursor)
                .get(read_cursor::get_read_cursors),
        )
        .push(relation::router())
        .push(directory::router())
        .push(index::router())
}
