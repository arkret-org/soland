use salvo::prelude::*;

pub(crate) mod agent_bridge;
pub(super) mod applet_bridge;
pub(super) mod event_log;
pub(super) mod frontier;
pub(super) mod peer;
// Strand + projection helpers are `pub(crate)` so the MIMI interop
// facade can reuse the canonical space→strand mapping + projection-event
// JSON shape when ingesting MIMI traffic into the Cokret timeline.
pub(super) mod notify;
pub(super) mod operations;
pub(crate) mod projection;
pub(super) mod projection_query;
pub(crate) mod strand;
pub(super) mod sync;

use operations::{
    validate_agent_participation_ceiling, validate_agent_reply_participation,
    validate_content_encryption_floor, validate_operation_policy, validate_operation_semantics,
};
use projection::{
    augment_timeline_message_json, backfill_gap_events, projected_event_page,
    projection_event_json, sync_timeline_message_json_with_projection, truncate_gap_events,
};
use strand::{
    default_discussion_track, discussion_track_for_projection_event, message_id_from_event_id,
    strand_id_for_projection_event, strand_id_from_realm_id, strand_projection_for_realm,
};

use super::{
    TO_DEVICE_PAGE_LIMIT, append_audit_log, auth_or_render, authenticated_session,
    device_message_envelopes_after, is_json_integer, is_realm_deleted, is_valid_discoverability,
    is_valid_sha256_digest, now, parse_snapshot_ref, prune_expired_typing, query_param,
    query_param_all, realm_allows_plaintext_service, realm_discoverability,
    realm_event_visible_to_session, realm_has_member, realm_history_visibility,
    realm_id_accessible, realm_visible_to, render_error, sha256_hex, snapshot_bundle_for_realm,
    snapshot_manifest_for_realm, touch_realm, typing_ephemeral_for_realm, validate_did,
    validate_space_id,
};

pub fn router() -> Router {
    Router::new()
        .push(sync::protocol_router())
        .push(event_log::router())
        .push(projection_query::protocol_router())
}

pub fn peer_router() -> Router {
    peer::router()
}

pub fn legacy_router() -> Router {
    Router::new()
        .push(sync::legacy_router())
        .push(event_log::router())
        .push(projection_query::legacy_router())
}
