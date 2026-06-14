//! Strand ID derivation + discussion-track projection helpers.
//!
//! Strand IDs are derived from Realm IDs via typed-id → `ck:strand:` re-tagging
//! (sha256 fallback for unrecognised prefixes). v1 Message payloads expose the
//! discussion track as the const string `discussion`.
//!
//! All fns are `pub` because sync/projection writers consume them.
//! This is a derivation layer the server fakes for clients that already
//! speak the strand protocol; a future real `ck.strand.*` reducer state
//! will replace it once the wire schema lands.

use serde_json::json;

use super::{now, realm_allows_plaintext_service, realm_discoverability, sha256_hex};
use crate::state::{AppState, ProjectionEventRecord};

pub fn retag_typed_id(value: &str, from_prefix: &str, to_prefix: &str) -> Option<String> {
    value
        .strip_prefix(from_prefix)
        .map(|suffix| format!("{to_prefix}{suffix}"))
}

pub fn derived_strand_id(seed: &str) -> String {
    let digest = sha256_hex(seed.as_bytes());
    format!("ck:strand:{}", &digest[..26])
}

pub fn strand_id_from_realm_id(realm_id: &str) -> String {
    retag_typed_id(realm_id, "ck:realm:", "ck:strand:")
        .unwrap_or_else(|| derived_strand_id(realm_id))
}

pub fn message_id_from_event_id(event_id: &str) -> String {
    retag_typed_id(event_id, "ck:event:", "ck:message:")
        .unwrap_or_else(|| format!("ck:message:{event_id}"))
}

pub fn default_discussion_track(_strand_id: &str, _track_id: &str) -> serde_json::Value {
    json!("discussion")
}

pub fn strand_id_for_projection_event(event: &ProjectionEventRecord) -> Option<String> {
    event
        .payload
        .get("strand_id")
        .and_then(|value| value.as_str())
        .map(ToOwned::to_owned)
        .or_else(|| Some(strand_id_from_realm_id(&event.realm_id)))
}

pub fn discussion_track_for_projection_event(
    event: &ProjectionEventRecord,
    strand_id: Option<&str>,
) -> Option<serde_json::Value> {
    let strand_id = strand_id?;
    let track_id = event
        .payload
        .get("thread_id")
        .and_then(|value| value.as_str())
        .unwrap_or(event.realm_id.as_str());
    Some(default_discussion_track(strand_id, track_id))
}

pub async fn strand_history_visibility_for_realm(state: &AppState, realm_id: &str) -> &'static str {
    if realm_discoverability(state, realm_id).await == "public" {
        "shared"
    } else {
        "joined"
    }
}

pub async fn strand_projection_for_realm(
    state: &AppState,
    realm_id: &str,
    title: &str,
    summary: Option<&str>,
) -> serde_json::Value {
    let meta = state
        .persistence
        .realm_meta()
        .get(realm_id)
        .await
        .ok()
        .flatten();
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
    let history_visibility = strand_history_visibility_for_realm(state, realm_id).await;
    // `kind: "room"` and `room_kind` were removed in revision 0a5ab85
    // (see cokret-spec `artifacts/registry/forbidden-wire-fields.json`
    // entries `kind=room` and `room_kind`); Realm is the v1 boundary and
    // the Strand.kind discriminator MUST be a v1 value (e.g. "discussion").
    json!({
        "id": strand_id_from_realm_id(realm_id),
        "strand_id": strand_id_from_realm_id(realm_id),
        "type": "strand",
        "schema": "ck.schema.strand.v1",
        "realm_id": realm_id,
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
                "history_visibility": history_visibility,
                "encryption_profile": if realm_allows_plaintext_service(state, realm_id).await { "none" } else { "mls_rfc9420" },
                "fields": {}
            }
        },
        "created_by": owner,
        "created_at": created_at,
        "updated_by": owner,
        "updated_at": updated_at
    })
}
