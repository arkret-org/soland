//! Flow ID derivation + discussion-track projection helpers.
//!
//! Flow IDs are derived from Space IDs via `cx:space:` → `cx:flow:` re-tagging
//! (sha256 fallback for unrecognised prefixes). The discussion-track
//! projection wraps the same flow_id with a default `discussion` shape for
//! account sync and admin snapshots.
//!
//! All fns are `pub` because sync/projection writers consume them.
//! Stream-A5 in `_todos.md` will lift this into a real `cx.flow.*` reducer
//! state once the wire schema lands; for now it's a derivation layer the
//! server fakes for clients that already speak the flow protocol.

use serde_json::json;

use super::{now, sha256_hex, space_allows_plaintext_service, space_discoverability};
use crate::state::{AppState, ProjectionEventRecord};

pub fn retag_typed_id(value: &str, from_prefix: &str, to_prefix: &str) -> Option<String> {
    value
        .strip_prefix(from_prefix)
        .map(|suffix| format!("{to_prefix}{suffix}"))
}

pub fn derived_flow_id(seed: &str) -> String {
    let digest = sha256_hex(seed.as_bytes());
    format!("cx:flow:{}", &digest[..26])
}

pub fn flow_id_from_space_id(space_id: &str) -> String {
    retag_typed_id(space_id, "cx:space:", "cx:flow:").unwrap_or_else(|| derived_flow_id(space_id))
}

pub fn message_id_from_event_id(event_id: &str) -> String {
    retag_typed_id(event_id, "cx:event:", "cx:message:")
        .unwrap_or_else(|| format!("cx:message:{event_id}"))
}

pub fn default_discussion_track(flow_id: &str, track_id: &str) -> serde_json::Value {
    json!({
        "track_id": track_id,
        "track_kind": "discussion",
        "flow_id": flow_id,
        "enabled": true,
        "history_visibility": "joined",
        "visibility": "joined",
    })
}

pub fn flow_id_for_projection_event(event: &ProjectionEventRecord) -> Option<String> {
    event
        .payload
        .get("flow_id")
        .and_then(|value| value.as_str())
        .map(ToOwned::to_owned)
        .or_else(|| Some(flow_id_from_space_id(&event.space_id)))
}

pub fn discussion_track_for_projection_event(
    event: &ProjectionEventRecord,
    flow_id: Option<&str>,
) -> Option<serde_json::Value> {
    let flow_id = flow_id?;
    let track_id = event
        .payload
        .get("thread_id")
        .and_then(|value| value.as_str())
        .unwrap_or(event.space_id.as_str());
    Some(default_discussion_track(flow_id, track_id))
}

pub fn flow_history_visibility_for_space(state: &AppState, space_id: &str) -> &'static str {
    if space_discoverability(state, space_id) == "public" {
        "shared"
    } else {
        "joined"
    }
}

pub fn flow_projection_for_space(
    state: &AppState,
    space_id: &str,
    title: &str,
    summary: Option<&str>,
) -> serde_json::Value {
    let meta = state.persistence.space_meta().get(space_id).ok().flatten();
    let owner = meta
        .as_ref()
        .map(|meta| meta.owner.clone())
        .unwrap_or_else(|| state.config.service_did.clone());
    let created_at = meta
        .as_ref()
        .map(|meta| meta.created_at)
        .unwrap_or_else(now);
    let updated_at = meta
        .as_ref()
        .map(|meta| meta.updated_at)
        .unwrap_or(created_at);
    let deleted = meta.as_ref().is_some_and(|meta| meta.deleted);
    json!({
        "id": flow_id_from_space_id(space_id),
        "flow_id": flow_id_from_space_id(space_id),
        "type": "flow",
        "schema": "cx.schema.flow.v1",
        "space_id": space_id,
        "kind": "room",
        "title": title,
        "description": summary,
        "state": if deleted { "archived" } else { "active" },
        "primary_track": "discussion",
        "tracks": {
            "synthesis": {
                "enabled": false,
                "fields": {}
            },
            "discussion": {
                "enabled": true,
                "room_kind": "discussion",
                "history_visibility": flow_history_visibility_for_space(state, space_id),
                "encryption_profile": if space_allows_plaintext_service(state, space_id) { "none" } else { "mls_rfc9420" },
                "fields": {}
            }
        },
        "created_by": owner,
        "created_at": created_at,
        "updated_by": owner,
        "updated_at": updated_at
    })
}
