//! Account aggregate + snapshot handlers + the cursor-helper machinery they share
//! with events and device-message modules.
//!
//! Surfaces for the current sync/event wire layout:
//! - `GET  /_cokret/self/account/describe`
//! - `GET  /_cokret/self/account/subscribe`       — `ck.self.account.stream.subscribe`
//!   (account-aggregate NDJSON: timeline, presence, typing, to_device).
//! - `POST /_cokret/self/ephemeral`               — `ck.self.ephemeral.command.send` (broadcast
//!   ephemeral)
//! - `GET  /_cokret/self/events/subscribe`        — `ck.self.events.stream.subscribe`. Multi-Realm
//!   / multi-actor stream; frame `kind` field replaces `type`.
//! - `GET  /_cokret/self/events`                  — `ck.self.events.query.scan` (replaces
//!   `ck.events.list` + `ck.sync.backfill` via `direction=forward|backward`).
//! - `GET  /_cokret/self/snapshot/head`
//!
//! `SyncCursor`, `SyncCursorError`, `parse_and_validate_sync_cursor`,
//! `decode_sync_cursor_value`, `sync_token_for_client_sync`, `sync_filter_digest`,
//! are `pub` because sibling routing modules reuse them. They
//! live here because the cursor lifecycle is sealed to account subscribe.
//!
//! The implementation is split across submodules; this module file owns the
//! shared imports / constants, the protocol router, the scope-selector helpers,
//! and re-exports the per-topic items so `sync::xxx` paths and the `super::*`
//! views in `snapshot.rs` / `sync_tests.rs` keep resolving unchanged.

pub(crate) use std::collections::{BTreeMap, BTreeSet};
pub(crate) use std::time::Duration;

pub(crate) use base64::Engine;
pub(crate) use base64::engine::general_purpose::URL_SAFE_NO_PAD;
pub(crate) use bytes::Bytes;
pub(crate) use chrono::{DateTime, Duration as ChronoDuration, SecondsFormat, Utc};
pub(crate) use cokret_sdk::http::EventsQueryOutcome;
pub(crate) use cokret_sdk::lattice::CellState;
pub(crate) use cokret_sdk::{PresenceStatus, RealmId};
pub(crate) use futures_util::stream::StreamExt;
pub(crate) use salvo::http::{StatusCode, header};
pub(crate) use salvo::prelude::*;
pub(crate) use serde_json::{Value, json};
pub(crate) use tokio::sync::broadcast::error::RecvError;

pub(crate) use super::projection::{
    actor_erased_in_realm, retention_tombstone_for_event, tombstone_timeline_event_for_retention,
    tombstone_timeline_event_value,
};
use super::{
    TO_DEVICE_PAGE_LIMIT, augment_timeline_message_json, authenticated_session,
    default_discussion_track, device_message_envelopes_after,
    has_pending_call_signals_for_subscriber, is_realm_deleted, now, projected_event_page,
    projection_event_json, prune_expired_typing, query_param, realm_discoverability,
    realm_event_visible_to_session, realm_has_member, realm_history_visibility,
    realm_id_accessible, realm_visible_to, render_error, sha256_hex, snapshot_manifest_for_realm,
    strand_id_from_realm_id, strand_projection_for_realm,
    sync_timeline_message_json_with_projection, typing_ephemeral_for_realm, validate_did,
};
pub(crate) use crate::ids;
pub(crate) use crate::persistence::SyncCursorRecord;
pub(crate) use crate::reducer::ProjectionState;
pub(crate) use crate::state::{
    AppState, HandleClaimDigestInput, HandleClaimEvidenceRecord, PresenceRecord,
    ProjectionEventRecord, RealmDirectoryEntry, RealmMetaRecord, SessionRecord,
};
pub(crate) use crate::wire::{EventsQueryPostRequestBody, SyncDescription, SyncRequestBody};

pub(crate) const TIMELINE_POSITION_SUBTICKS: i64 = 1024;
pub(crate) const PERSONAL_BLOCKLIST_DATA_TYPES: &[&str] =
    &["ck.account.blocklist", "ck.account.blocklist.v1"];
pub(crate) const PRESENCE_ONLINE_TTL_SECONDS: i64 = 3;
pub(crate) const HANDLE_CLAIMS_INLINE_MAX_BYTES: usize = 8 * 1024;
/// Default reconnect guard advertised on subscribe terminal control frames.
/// Shared by `account_subscribe` (subscribe.rs) and `events_subscribe`
/// (events_query.rs).
pub(crate) const SUBSCRIBE_RECONNECT_AFTER_MS: u64 = 10_000;
/// Maximum lifetime of an issued sync cursor (mirrors the 1h TTL minted by
/// [`sync_token_for_client_sync`]). A revocation record is retained for at
/// least this long so a leaked cursor cannot outlive its revocation.
pub(crate) const CURSOR_MAX_TTL_SECONDS: i64 = 3600;

mod snapshot;
pub(crate) use snapshot::*;
mod cursor;
mod ephemeral;
// `spawn_sync_cursor_ttl_sweeper` is `pub` (boot worker entry re-exported at
// `crate::routing::spawn_sync_cursor_ttl_sweeper` for `main`); the explicit
// `pub use` overrides the `pub(crate)` glob above for this one name.
pub use cursor::spawn_sync_cursor_ttl_sweeper;
pub(crate) use cursor::*;
mod subscribe;
pub(crate) use subscribe::*;
mod events_query;
pub(crate) use events_query::*;

pub(super) fn protocol_router() -> Router {
    Router::new()
        .push(Router::with_path("account/describe").get(subscribe::account_describe))
        .push(Router::with_path("account/subscribe").get(subscribe::account_subscribe))
        .push(Router::with_path("account/cursor/revoke").post(cursor::account_cursor_revoke))
        .push(Router::with_path("ephemeral").post(ephemeral::submit_ephemeral))
        .push(Router::with_path("snapshot/head").get(events_query::snapshot_head))
}

pub(crate) fn scope_selector_to_realm_id(value: &str) -> Result<String, crate::error::AppError> {
    if RealmId::new(value.to_owned()).is_ok() {
        return Ok(value.to_owned());
    }
    Err(crate::error::AppError::invalid_param("invalid realm_id"))
}

pub(crate) fn normalize_scope_selectors(
    values: Vec<String>,
) -> Result<Vec<String>, crate::error::AppError> {
    values
        .into_iter()
        .map(|value| scope_selector_to_realm_id(&value))
        .collect()
}

#[cfg(test)]
#[path = "sync_tests.rs"]
mod tests;
