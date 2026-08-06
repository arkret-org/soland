//! Account aggregate + snapshot handlers + the cursor-helper machinery they share
//! with events and device-message modules.
//!
//! Surfaces for the current sync/event wire layout:
//! - `GET  /_arkret/self/account/describe`
//! - `GET  /_arkret/self/account/subscribe`       — `ak.self.account.stream.subscribe`
//!   (account-aggregate NDJSON: timeline, account data, to_device).
//! - `POST /_arkret/self/signal`                  — `ak.self.signal.command.send` (Signal Extension
//!   send rail; encrypted-only)
//! - `GET  /_arkret/self/signal/subscribe`        — `ak.self.signal.stream.subscribe` (Signal
//!   Extension receive rail; verbatim envelope NDJSON)
//! - `GET  /_arkret/self/events/subscribe`        — `ak.self.events.stream.subscribe`. Multi-Realm
//!   / multi-actor stream; frame `kind` field replaces `type`.
//! - `GET  /_arkret/self/events`                  — `ak.self.events.read.scan` (replaces
//!   `ak.events.list` + `ak.sync.backfill` via `direction=forward|backward`).
//! - `GET  /_arkret/self/snapshot/head`
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

pub(crate) use arkret_identifiers::RealmId;
pub(crate) use arkret_models_collaboration::http_bodies::EventsQueryOutcome;
pub(crate) use base64::Engine;
pub(crate) use base64::engine::general_purpose::URL_SAFE_NO_PAD;
pub(crate) use bytes::Bytes;
pub(crate) use chrono::{DateTime, Duration as ChronoDuration, Utc};
pub(crate) use futures_util::stream::StreamExt;
pub(crate) use salvo::http::{StatusCode, header};
pub(crate) use salvo::prelude::*;
pub(crate) use serde_json::{Value, json};
pub(crate) use soland_services::events::{
    ProjectedEvent as ProjectionEventRecord, RealmMetadata as RealmMetaRecord,
};
pub(crate) use soland_services::identity::SessionIdentityState as SessionRecord;
pub(crate) use soland_services::projection::ProjectionSnapshot as ProjectionState;
pub(crate) use soland_services::sync::CursorState as SyncCursorRecord;
pub(crate) use tokio::sync::broadcast::error::RecvError;

use super::super::identity::device_messages::prune_device_messages_for_limits;
#[cfg(test)]
pub(crate) use super::strand::strand_id_from_realm_id;
use super::{
    TO_DEVICE_PAGE_LIMIT, authenticated_session, device_message_envelopes_after, is_realm_deleted,
    now, projected_event_page, projected_event_page_for_realms_through,
    projected_event_replay_upper_bound, projection_event_json, query_param,
    realm_event_visible_to_session, realm_has_member, realm_id_accessible, realm_visible_to,
    render_error, sha256_hex, snapshot_manifest_for_realm, validate_did,
};
pub(crate) use crate::ids;
pub(crate) use crate::state::{
    AppState, HandleClaimDigestInput, HandleClaimEvidenceRecord, RealmDirectoryEntry,
};
pub(crate) use crate::wire::{EventsQueryPostRequestBody, SyncRequestBody};

pub(crate) const TIMELINE_POSITION_SUBTICKS: i64 = 1024;
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
pub(crate) mod signal;
// `spawn_sync_cursor_ttl_sweeper` is `pub` (boot worker entry re-exported at
// `crate::routing::spawn_sync_cursor_ttl_sweeper` for `main`); the explicit
// `pub use` overrides the `pub(crate)` glob above for this one name.
pub use cursor::spawn_sync_cursor_ttl_sweeper;
pub(crate) use cursor::*;
mod subscribe;
pub(crate) use subscribe::*;
mod events_query;
pub(crate) use events_query::*;
pub(crate) mod websocket;

pub(super) fn protocol_router() -> Router {
    Router::new()
        .push(Router::with_path("account/describe").get(subscribe::account_describe))
        .push(Router::with_path("account/subscribe").get(subscribe::account_subscribe))
        .push(Router::with_path("account/cursor/revoke").post(cursor::account_cursor_revoke))
        .push(Router::with_path("signal").post(signal::submit_signal))
        .push(Router::with_path("signal/subscribe").get(signal::signal_subscribe))
        .push(Router::with_path("snapshot/head").get(events_query::snapshot_head))
}

pub(crate) fn scope_selector_to_realm_id(
    value: &str,
) -> Result<String, soland_http::error::AppError> {
    if RealmId::new(value.to_owned()).is_ok() {
        return Ok(value.to_owned());
    }
    Err(soland_http::error::AppError::invalid_param(
        "invalid realm_id",
    ))
}

pub(crate) fn normalize_scope_selectors(
    values: Vec<String>,
) -> Result<Vec<String>, soland_http::error::AppError> {
    values
        .into_iter()
        .map(|value| scope_selector_to_realm_id(&value))
        .collect()
}

#[cfg(test)]
#[path = "sync_tests.rs"]
mod tests;
