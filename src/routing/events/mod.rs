use salvo::prelude::*;

pub(crate) mod agent_bridge;
pub(super) mod applet_bridge;
pub(super) mod event_log;
pub(super) mod flow;
pub(super) mod messages;
pub(super) mod operations;
pub(super) mod projection;
pub(super) mod projection_query;
pub(super) mod sync;

use event_log::events_query_durable_scope_impl;
use flow::{
    default_discussion_track, discussion_track_for_projection_event, flow_id_for_projection_event,
    flow_id_from_space_id, flow_projection_for_space, message_id_from_event_id,
};
use operations::{validate_operation_policy, validate_operation_semantics};
use projection::{
    backfill_gap_events, project_accepted_operations, projected_event_page, projection_event_json, sync_timeline_message_json, truncate_gap_events,
};

use super::{
    append_audit_log, auth_or_render, authenticated_session, device_message_events_after,
    is_json_integer, is_space_deleted, is_valid_discoverability, is_valid_sha256_digest, now,
    parse_snapshot_ref, prune_acked_device_messages,
    prune_expired_typing, query_param, query_param_all, render_error, sha256_hex,
    snapshot_bundle_for_space, space_allows_plaintext_service, space_discoverability,
    space_has_member, space_id_accessible, space_visible_to, touch_space,
    typing_ephemeral_for_space, validate_did, validate_space_id,
};

pub fn router() -> Router {
    Router::new()
        .push(sync::router())
        .push(event_log::router())
        .push(messages::router())
        .push(projection_query::router())
}
