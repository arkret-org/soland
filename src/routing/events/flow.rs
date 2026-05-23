//! Flow ID derivation + discussion-track projection helpers.
//!
//! Flow IDs are derived from Realm/Space IDs via typed-id → `cx:flow:` re-tagging
//! (sha256 fallback for unrecognised prefixes). v1 Message payloads expose the
//! discussion track as the const string `discussion`.
//!
//! All fns are `pub` because sync/projection writers consume them.
//! This is a derivation layer the server fakes for clients that already
//! speak the flow protocol; a future real `cx.flow.*` reducer state
//! will replace it once the wire schema lands.

use serde_json::json;

use super::{now, realm_allows_plaintext_service, realm_discoverability, sha256_hex};
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
    retag_typed_id(space_id, "cx:realm:", "cx:flow:")
        .or_else(|| retag_typed_id(space_id, "cx:space:", "cx:flow:"))
        .unwrap_or_else(|| derived_flow_id(space_id))
}

pub fn message_id_from_event_id(event_id: &str) -> String {
    retag_typed_id(event_id, "cx:event:", "cx:message:")
        .unwrap_or_else(|| format!("cx:message:{event_id}"))
}

pub fn default_discussion_track(_flow_id: &str, _track_id: &str) -> serde_json::Value {
    json!("discussion")
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
    if realm_discoverability(state, space_id) == "public" {
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
    let meta = state.persistence.realm_meta().get(space_id).ok().flatten();
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
    // `kind: "room"` and `room_kind` were removed in revision 0a5ab85
    // (see contrix-spec `artifacts/registry/forbidden-wire-fields.json`
    // entries `kind=room` and `room_kind`); Space is the v1 boundary and
    // the Flow.kind discriminator MUST be a v1 value (e.g. "discussion").
    json!({
        "id": flow_id_from_space_id(space_id),
        "flow_id": flow_id_from_space_id(space_id),
        "type": "flow",
        "schema": "cx.schema.flow.v1",
        "space_id": space_id,
        "kind": "discussion",
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
                "track_kind": "discussion",
                "history_visibility": flow_history_visibility_for_space(state, space_id),
                "encryption_profile": if realm_allows_plaintext_service(state, space_id) { "none" } else { "mls_rfc9420" },
                "fields": {}
            }
        },
        "created_by": owner,
        "created_at": created_at,
        "updated_by": owner,
        "updated_at": updated_at
    })
}
