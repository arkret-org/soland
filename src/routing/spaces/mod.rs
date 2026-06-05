use salvo::prelude::*;

pub(super) mod directory;
mod index;
mod reaction;
mod read_cursor;
mod relation;
pub(super) mod space;

use super::{
    AuthArgs, accept_local_operations, authenticated_session, default_discussion_track,
    device_inventory_to_json, flow_id_from_realm_id, handle_for_did, invite_token_matches_realm,
    invite_token_realm_id, is_realm_deleted, normalize_handle, now, realm_discoverability,
    realm_has_member, realm_history_visibility, realm_resolvable_to, realm_search_discoverability,
    realm_search_visible_to, sha256_hex, validate_realm_id,
};

/// `self`-segment spaces surface (spaces, reactions, read-cursors,
/// relations, projection index). The directory surface is split out into
/// [`find_router`] because directory discovery belongs to the `find` trust
/// segment, not `self`.
pub fn router() -> Router {
    protocol_router()
}

pub fn protocol_router() -> Router {
    Router::new()
}

pub fn legacy_router() -> Router {
    Router::new()
        .push(space::router())
        .push(reaction::router())
        .push(
            Router::with_path("read-cursors")
                .post(read_cursor::set_read_cursor)
                .get(read_cursor::get_read_cursors),
        )
        .push(relation::router())
        .push(index::router())
}

/// `find`-segment directory discovery surface (`/_cokret/find/directory/*`).
pub fn find_router() -> Router {
    directory::protocol_router()
}

pub fn find_legacy_router() -> Router {
    directory::legacy_router()
}
