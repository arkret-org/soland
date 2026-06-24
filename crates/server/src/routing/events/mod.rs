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
pub(crate) mod read_receipts;
pub(crate) mod strand;
pub(super) mod sync;

use operations::{
    validate_agent_participation_ceiling, validate_agent_reply_participation,
    validate_content_encryption_floor, validate_operation_policy, validate_operation_semantics,
};
use projection::{
    augment_timeline_message_json, projected_event_page, projection_event_json,
    sync_timeline_message_json_with_projection,
};
use strand::{
    default_discussion_track, discussion_track_for_projection_event, message_id_from_event_id,
    strand_id_for_projection_event, strand_id_from_realm_id, strand_projection_for_realm,
};

use super::{
    TO_DEVICE_PAGE_LIMIT, append_audit_log, auth_or_render, authenticated_session,
    device_message_envelopes_after, has_pending_call_signals_for_subscriber,
    has_pending_typing_for_subscriber, is_json_integer, is_realm_deleted, is_valid_discoverability,
    is_valid_hash_digest, now, prune_expired_typing, query_param, query_param_all,
    realm_allows_plaintext_service_for_data_class, realm_discoverability,
    realm_event_visible_to_session, realm_has_member, realm_history_visibility,
    realm_id_accessible, realm_visible_to, render_error, sha256_hex, snapshot_manifest_for_realm,
    touch_realm, typing_ephemeral_for_realm, validate_did, validate_space_id,
};

pub fn router() -> Router {
    Router::new()
        .push(sync::protocol_router())
        .push(event_log::router())
        .push(projection_query::protocol_router())
}

/// Product-private (`/_soland/self/*`) projection read surface: single-Strand
/// object read with materialized `fields`, and the relation edge list. These
/// stay off the canonical `/_cokret/*` protocol root per
/// `service-http-binding.md` §2.1.3 (relation / object direct reads beyond the
/// declared Realm-scoped read binding belong to the implementation private
/// surface).
pub fn local_router() -> Router {
    projection_query::local_router()
}

pub fn peer_router() -> Router {
    peer::router()
}
