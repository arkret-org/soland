//! Stateful sync-cursor lifecycle: token minting, HMAC handle derivation,
//! durable handle persistence, parse/validate, revocation, and the EventsSubscribe
//! dropped/resync frame helper. Shared with sibling routing modules through
//! `sync.rs` re-exports.

use super::*;

#[derive(Debug, Default)]
pub struct SyncCursor {
    /// Visible timeline frontier per Realm.
    pub positions: BTreeMap<String, i64>,
    /// Account aggregate projection frontier per Realm. This is a
    /// server-internal cursor vector carried inside the opaque handle binding;
    /// it is intentionally separate from `positions.realms` so metadata-only
    /// deltas cannot mask later visible timeline events.
    pub account_positions: BTreeMap<String, i64>,
    /// Device-list aggregate frontier per tracked principal.
    pub device_list_positions: BTreeMap<String, i64>,
    pub to_device_position: i64,
    /// Account-private notification projection high-water position.
    pub notification_position: i64,
    /// `ctx.issued_at_ms` from the stateful handle. Used for forward-progress
    /// pruning of older handles after a client proves it persisted a cursor.
    /// Per-Realm account projection freshness lives in `account_positions`,
    /// not here.
    pub issued_at_ms: Option<i64>,
}

#[derive(Debug)]
pub(crate) struct EventsQueryCursor {
    pub event_id: String,
}

#[derive(Debug)]
pub enum SyncCursorError {
    Invalid(&'static str),
    Mismatch(&'static str),
    Integrity(&'static str),
    Expired,
    /// The cursor authority was revoked via `ak.self.account.command.revoke_cursor.v1`.
    /// Surfaced as `cursor_revoked`; MUST be raised before any server-side
    /// state advancement (to-device ack, account-subscribe resume, wait-for
    /// barrier release, dropped/resync recovery).
    Revoked,
}

pub(crate) const STREAM_CURSOR_PURPOSE: &str = "stream";
pub(crate) const BARRIER_CURSOR_PURPOSE: &str = "barrier";

fn cursor_principal_device(session: Option<&SessionIdentityState>) -> (String, String) {
    let principal_id = session
        .map(|session| session.actor.clone())
        .unwrap_or_else(|| "anonymous".to_owned());
    let device_id = session
        .map(|session| session.device_id.clone())
        .unwrap_or_else(|| "anonymous".to_owned());
    (principal_id, device_id)
}

pub async fn sync_token_for_client_sync(
    state: &AppState,
    session: Option<&SessionIdentityState>,
    filter: Option<&serde_json::Value>,
    realms_positions: BTreeMap<String, i64>,
    account_realms_positions: BTreeMap<String, i64>,
    device_list_positions: BTreeMap<String, i64>,
    to_device_position: i64,
) -> String {
    sync_token_for_client_sync_frontiers(
        state,
        session,
        filter,
        realms_positions,
        account_realms_positions,
        device_list_positions,
        to_device_position,
        0,
    )
    .await
}

pub async fn sync_token_for_client_sync_frontiers(
    state: &AppState,
    session: Option<&SessionIdentityState>,
    filter: Option<&serde_json::Value>,
    realms_positions: BTreeMap<String, i64>,
    account_realms_positions: BTreeMap<String, i64>,
    device_list_positions: BTreeMap<String, i64>,
    to_device_position: i64,
    notification_position: i64,
) -> String {
    let issued_at = chrono::Utc::now();
    let (principal_id, device_id) = cursor_principal_device(session);
    let device_positions = BTreeMap::from([(device_id.clone(), issued_at.timestamp_micros())]);
    let filter_digest = sync_filter_digest(filter);
    let positions = json!({
        "realms": realms_positions,
        "account_realms": account_realms_positions,
        "device_lists": device_list_positions,
        "devices": device_positions,
        "to_device": to_device_position,
        "notifications": notification_position
    });
    // Deterministic handle: HMAC over the binding content (positions
    // included, per-mint `devices` wall-clock stamp excluded), so an
    // unchanged frontier re-mints the SAME handle and the upsert only
    // refreshes the row's expiry instead of growing the table.
    let binding = stream_cursor_handle_binding_with_notification_position(
        &principal_id,
        &device_id,
        state.service_id(),
        &filter_digest,
        &realms_positions,
        &account_realms_positions,
        &device_list_positions,
        to_device_position,
        notification_position,
    );
    let handle = derive_cursor_handle(state.sync().cursor_hmac_key(), &binding);
    let cursor = arkret_hlc::Cursor::new_at(issued_at, 60 * 60 * 1000)
        .expect("one-hour stream cursor is valid")
        .with_stateful_handle(handle.clone());
    let issued_at_ms = cursor.issued_at.timestamp_millis();
    let expires_at_ms = cursor.expires_at.timestamp_millis();
    upsert_sync_cursor_record(
        state,
        CursorState {
            handle: handle.clone(),
            binding_subject: Some(principal_id),
            device_id: Some(device_id),
            service_id: state.service_id().clone(),
            filter_digest: Some(filter_digest),
            purpose: STREAM_CURSOR_PURPOSE.to_owned(),
            positions: Some(positions),
            target: None,
            issued_at_ms,
            expires_at_ms,
        },
    )
    .await;
    cursor.encode().expect("SDK cursor encoding cannot fail")
}

pub(crate) async fn sync_token_for_events_query(
    state: &AppState,
    session: Option<&SessionIdentityState>,
    filter_digest: &str,
    event_id: &str,
) -> String {
    let issued_at = chrono::Utc::now();
    let (principal_id, device_id) = cursor_principal_device(session);
    let target = json!({ "event_id": event_id });
    let binding = events_query_cursor_handle_binding(
        &principal_id,
        &device_id,
        state.service_id(),
        filter_digest,
        &target,
    );
    let handle = derive_cursor_handle(state.sync().cursor_hmac_key(), &binding);
    let cursor = arkret_hlc::Cursor::new_at(issued_at, 60 * 60 * 1000)
        .expect("one-hour stream cursor is valid")
        .with_stateful_handle(handle.clone());
    let issued_at_ms = cursor.issued_at.timestamp_millis();
    let expires_at_ms = cursor.expires_at.timestamp_millis();
    upsert_sync_cursor_record(
        state,
        CursorState {
            handle: handle.clone(),
            binding_subject: Some(principal_id),
            device_id: Some(device_id),
            service_id: state.service_id().clone(),
            filter_digest: Some(filter_digest.to_owned()),
            purpose: STREAM_CURSOR_PURPOSE.to_owned(),
            positions: None,
            target: Some(target),
            issued_at_ms,
            expires_at_ms,
        },
    )
    .await;
    cursor.encode().expect("SDK cursor encoding cannot fail")
}

pub(crate) async fn sync_barrier_token_for_event(
    state: &AppState,
    session: &SessionIdentityState,
    event_id: &str,
) -> String {
    let issued_at = chrono::Utc::now();
    let target = json!({ "event_id": event_id });
    let binding = barrier_cursor_handle_binding(
        &session.actor,
        &session.device_id,
        state.service_id(),
        &target,
    );
    let handle = derive_cursor_handle(state.sync().cursor_hmac_key(), &binding);
    let cursor = arkret_hlc::Cursor::new_at(issued_at, 60 * 60 * 1000)
        .expect("one-hour barrier cursor is valid")
        .with_barrier()
        .with_stateful_handle(handle.clone());
    let issued_at_ms = cursor.issued_at.timestamp_millis();
    let expires_at_ms = cursor.expires_at.timestamp_millis();
    upsert_sync_cursor_record(
        state,
        CursorState {
            handle,
            binding_subject: Some(session.actor.clone()),
            device_id: Some(session.device_id.clone()),
            service_id: state.service_id().clone(),
            filter_digest: None,
            purpose: BARRIER_CURSOR_PURPOSE.to_owned(),
            positions: None,
            target: Some(target),
            issued_at_ms,
            expires_at_ms,
        },
    )
    .await;
    cursor.encode().expect("SDK cursor encoding cannot fail")
}

pub(crate) async fn sync_token_for_state(state: &AppState) -> String {
    sync_token_for_state_positions(state, BTreeMap::new()).await
}

async fn sync_token_for_state_positions(
    state: &AppState,
    realms_positions: BTreeMap<String, i64>,
) -> String {
    let issued_at = chrono::Utc::now();
    let binding = service_cursor_handle_binding(state.service_id(), &realms_positions);
    let handle = derive_cursor_handle(state.sync().cursor_hmac_key(), &binding);
    let cursor = arkret_hlc::Cursor::new_at(issued_at, 60 * 60 * 1000)
        .expect("one-hour stream cursor is valid")
        .with_stateful_handle(handle.clone());
    let issued_at_ms = cursor.issued_at.timestamp_millis();
    let expires_at_ms = cursor.expires_at.timestamp_millis();
    upsert_sync_cursor_record(
        state,
        CursorState {
            handle: handle.clone(),
            binding_subject: None,
            device_id: None,
            service_id: state.service_id().clone(),
            filter_digest: None,
            purpose: STREAM_CURSOR_PURPOSE.to_owned(),
            positions: Some(json!({
                "realms": realms_positions,
                "account_realms": {},
                "device_lists": {},
                "devices": {},
                "to_device": 0
            })),
            target: None,
            issued_at_ms,
            expires_at_ms,
        },
    )
    .await;
    cursor.encode().expect("SDK cursor encoding cannot fail")
}

#[cfg(test)]
pub(crate) fn encode_sync_cursor_value(cursor: Value) -> String {
    let bytes = arkret_canonical::canonical_json_bytes(&cursor)
        .unwrap_or_else(|_| cursor.to_string().into_bytes());
    format!("ak:cursor:{}", URL_SAFE_NO_PAD.encode(bytes))
}

/// Deterministic, unguessable stateful cursor handle.
///
/// `handle = base64url( HMAC-SHA256(cursor_key, canonical_binding)[..16] )`.
///
/// Keyed (HMAC, not a bare hash): a bare hash of the binding inputs — all of
/// which a caller knows (its own/another device id, the realm positions) —
/// would be forgeable, letting an attacker mint a victim device's handle and
/// advance its `to_device` ack to prune undelivered Welcomes. The server-secret
/// `cursor_key` makes the handle unguessable while keeping it deterministic, so
/// identical bindings (same positions) map to the same handle (no per-poll
/// churn, no new row). 16 bytes → 128 bits → ≥22 base64url chars, satisfying
/// `cursor.schema.json` `h`.
pub(crate) fn derive_cursor_handle(cursor_key: &[u8], canonical_binding: &[u8]) -> String {
    use hmac::{Hmac, KeyInit, Mac};
    use sha2::Sha256;
    let mut mac = <Hmac<Sha256>>::new_from_slice(cursor_key).expect("HMAC accepts any key length");
    mac.update(canonical_binding);
    let tag = mac.finalize().into_bytes();
    URL_SAFE_NO_PAD.encode(&tag[..16])
}

pub(crate) fn stream_cursor_handle_binding_with_notification_position(
    principal_id: &str,
    device_id: &str,
    service_id: &str,
    filter_digest: &str,
    realms_positions: &BTreeMap<String, i64>,
    account_realms_positions: &BTreeMap<String, i64>,
    device_list_positions: &BTreeMap<String, i64>,
    to_device_position: i64,
    notification_position: i64,
) -> Vec<u8> {
    let binding = json!({
        "principal_id": principal_id,
        "device_id": device_id,
        "service_id": service_id,
        "filter_digest": filter_digest,
        "purpose": STREAM_CURSOR_PURPOSE,
        "realms": realms_positions,
        "account_realms": account_realms_positions,
        "device_lists": device_list_positions,
        "to_device": to_device_position,
        "notifications": notification_position,
    });
    arkret_canonical::canonical_json_bytes(&binding)
        .unwrap_or_else(|_| binding.to_string().into_bytes())
}

pub(crate) fn events_query_cursor_handle_binding(
    principal_id: &str,
    device_id: &str,
    service_id: &str,
    filter_digest: &str,
    target: &Value,
) -> Vec<u8> {
    let binding = json!({
        "principal_id": principal_id,
        "device_id": device_id,
        "service_id": service_id,
        "filter_digest": filter_digest,
        "purpose": STREAM_CURSOR_PURPOSE,
        "target": target,
    });
    arkret_canonical::canonical_json_bytes(&binding)
        .unwrap_or_else(|_| binding.to_string().into_bytes())
}

fn barrier_cursor_handle_binding(
    principal_id: &str,
    device_id: &str,
    service_id: &str,
    target: &Value,
) -> Vec<u8> {
    let binding = json!({
        "principal_id": principal_id,
        "device_id": device_id,
        "service_id": service_id,
        "purpose": BARRIER_CURSOR_PURPOSE,
        "target": target,
    });
    arkret_canonical::canonical_json_bytes(&binding)
        .unwrap_or_else(|_| binding.to_string().into_bytes())
}

/// Canonical byte string the GENERIC service-level cursor handle is derived
/// from (`sync_token_for_state`: empty positions, no session binding). Shaped
/// differently from the stream binding so the two namespaces
/// can never collide.
fn service_cursor_handle_binding(
    service_id: &str,
    realms_positions: &BTreeMap<String, i64>,
) -> Vec<u8> {
    let binding = json!({
        "kind": "generic",
        "purpose": STREAM_CURSOR_PURPOSE,
        "service_id": service_id,
        "realms": realms_positions,
        "account_realms": {},
        "device_lists": {},
        "to_device": 0,
    });
    arkret_canonical::canonical_json_bytes(&binding)
        .unwrap_or_else(|_| binding.to_string().into_bytes())
}

/// How often the durable sync-cursor handle table is swept for expired rows.
/// Stream cursors live 1h, so a 15-minute cadence keeps the table within a
/// small constant factor of the active-stream count without measurable load
/// (one indexed DELETE per pass).
const SYNC_CURSOR_TTL_SWEEP_INTERVAL: Duration = Duration::from_secs(900);

/// Spawn the periodic TTL sweep for the durable sync-cursor handle table.
///
/// Forward-progress pruning (on cursor presentation) already caps per-stream
/// rows; this sweep is the backstop that clears rows whose client never came
/// back, replacing the old lookup-time-only lazy deletion that let
/// superseded handles accumulate until restart.
pub fn spawn_sync_cursor_ttl_sweeper(
    state: AppState,
) -> std::sync::Arc<tokio::task::JoinHandle<()>> {
    let task = tokio::spawn(async move {
        let mut ticker = tokio::time::interval(SYNC_CURSOR_TTL_SWEEP_INTERVAL);
        // Skip the immediate first tick so we don't fire mid-boot.
        ticker.tick().await;
        loop {
            ticker.tick().await;
            let now = chrono::Utc::now();
            let now_ms = now.timestamp_millis();
            match state.sync().prune_expired_cursors(now_ms).await {
                Ok(0) => {}
                Ok(pruned) => tracing::debug!(
                    worker = "sync_cursor_ttl_sweep",
                    pruned,
                    "expired sync cursor handles pruned"
                ),
                Err(error) => tracing::warn!(
                    worker = "sync_cursor_ttl_sweep",
                    %error,
                    "sync cursor TTL sweep failed"
                ),
            }
            // api-conventions.md §6 — the generic `Idempotency-Key` cache shares
            // this periodic sweep so its mapping table stays bounded by the
            // per-record TTL instead of growing with every keyed write.
            match state.jobs().prune_expired_idempotency(now).await {
                Ok(0) => {}
                Ok(pruned) => tracing::debug!(
                    worker = "sync_cursor_ttl_sweep",
                    pruned,
                    "expired idempotency keys pruned"
                ),
                Err(error) => tracing::warn!(
                    worker = "sync_cursor_ttl_sweep",
                    %error,
                    "idempotency key TTL sweep failed"
                ),
            }
        }
    });
    std::sync::Arc::new(task)
}

/// Persist (or expiry-refresh) the handle row behind a freshly-minted cursor.
///
/// A failed write is downgraded to a warning rather than failing the sync
/// response: the client still gets its data, and if the row never lands the
/// next `after=` presentation fails handle lookup and the client recovers
/// through the spec's full-resync path (client-sync.md §12.3).
async fn upsert_sync_cursor_record(state: &AppState, record: CursorState) {
    if let Err(error) = state.sync().upsert_cursor(&record).await {
        tracing::warn!(%error, handle = %record.handle, "sync cursor handle upsert failed");
    }
}

async fn stored_sync_cursor_by_handle(
    state: &AppState,
    handle: &str,
) -> Result<Value, SyncCursorError> {
    let record = stored_sync_cursor_record_by_handle(state, handle).await?;
    Ok(stored_value_from_sync_cursor_record(record))
}

async fn stored_sync_cursor_record_by_handle(
    state: &AppState,
    handle: &str,
) -> Result<CursorState, SyncCursorError> {
    state
        .sync()
        .cursor(handle)
        .await
        .map_err(|error| {
            tracing::warn!(%error, handle, "sync cursor handle lookup failed");
            SyncCursorError::Integrity("sync cursor handle lookup failed")
        })?
        .ok_or(SyncCursorError::Integrity("sync cursor handle is unknown"))
}

/// Rebuild the in-memory `{ctx, positions, target?, expires_at_ms}` stored
/// shape from a persisted row. Generic rows reconstruct a ctx WITHOUT
/// `binding_subject`/`device_id`, which `parse_and_validate_sync_cursor` rejects
/// by construction.
fn stored_value_from_sync_cursor_record(record: CursorState) -> Value {
    let mut ctx = serde_json::Map::new();
    if let Some(binding_subject) = record.binding_subject {
        ctx.insert("binding_subject".to_owned(), Value::String(binding_subject));
    }
    if let Some(device_id) = record.device_id {
        ctx.insert("device_id".to_owned(), Value::String(device_id));
    }
    ctx.insert("service_id".to_owned(), Value::String(record.service_id));
    ctx.insert("purpose".to_owned(), Value::String(record.purpose));
    if let Some(filter_digest) = record.filter_digest {
        ctx.insert("filter_digest".to_owned(), Value::String(filter_digest));
    }
    ctx.insert("issued_at_ms".to_owned(), json!(record.issued_at_ms));
    let mut stored = json!({
        "ctx": Value::Object(ctx),
        "expires_at_ms": record.expires_at_ms,
    });
    if let Some(positions) = record.positions {
        stored["positions"] = positions;
    }
    if let Some(target) = record.target {
        stored["target"] = target;
    }
    stored
}

fn cursor_position_map(
    positions_value: &Value,
    key: &'static str,
    missing_error: Option<&'static str>,
) -> Result<BTreeMap<String, i64>, SyncCursorError> {
    let Some(map) = positions_value.get(key).and_then(Value::as_object) else {
        return match missing_error {
            Some(message) => Err(SyncCursorError::Integrity(message)),
            None => Ok(BTreeMap::new()),
        };
    };
    Ok(map
        .iter()
        .filter_map(|(realm_id, position)| {
            position
                .as_i64()
                .map(|position| (realm_id.clone(), position))
        })
        .collect())
}

pub async fn parse_and_validate_sync_cursor(
    token: &str,
    state: &AppState,
    session: Option<&SessionIdentityState>,
    filter: Option<&serde_json::Value>,
    now_ms: i64,
) -> Result<SyncCursor, SyncCursorError> {
    let cursor = decode_sync_cursor(token, now_ms)?;
    if cursor.purpose != arkret_hlc::CursorPurpose::Stream {
        return Err(SyncCursorError::Invalid(
            "after must be a v1 account cursor",
        ));
    }
    // Revocation is checked before TTL / integrity so a revoked authority
    // always surfaces `cursor_revoked` and never advances server-side state
    // (to-device ack, subscribe resume, wait-for barrier, dropped recovery).
    // `this_cursor` matches the exact token by digest; `same_device` /
    // `same_session` match the authenticated session's (principal, device),
    // which the cursor is bound to and re-verified against below.
    if cursor_authority_revoked(state, token, session, now_ms) {
        return Err(SyncCursorError::Revoked);
    }
    let handle = cursor.h.as_str();
    let stored = stored_sync_cursor_by_handle(state, handle).await?;
    if stored
        .get("expires_at_ms")
        .and_then(|expires_at| expires_at.as_i64())
        .is_none_or(|expires_at| expires_at <= now_ms)
    {
        let _ = state.sync().delete_cursor(handle).await;
        return Err(SyncCursorError::Integrity("sync cursor handle has expired"));
    }
    let ctx = stored
        .get("ctx")
        .and_then(|ctx| ctx.as_object())
        .ok_or(SyncCursorError::Integrity("cursor handle is missing ctx"))?;
    let expected_binding_subject = session
        .map(|session| session.actor.as_str())
        .unwrap_or("anonymous");
    let expected_device = session
        .map(|session| session.device_id.as_str())
        .unwrap_or("anonymous");
    if ctx
        .get("purpose")
        .and_then(|purpose| purpose.as_str())
        .is_none_or(|purpose| purpose != STREAM_CURSOR_PURPOSE)
    {
        return Err(SyncCursorError::Integrity(
            "cursor handle purpose does not match account stream",
        ));
    }
    if ctx
        .get("binding_subject")
        .and_then(|subject| subject.as_str())
        .is_none_or(|subject| subject != expected_binding_subject)
    {
        return Err(SyncCursorError::Mismatch(
            "cursor binding subject does not match request actor",
        ));
    }
    if ctx
        .get("device_id")
        .and_then(|device| device.as_str())
        .is_none_or(|device| device != expected_device)
    {
        return Err(SyncCursorError::Mismatch(
            "cursor device does not match request device",
        ));
    }
    if ctx
        .get("service_id")
        .and_then(|service| service.as_str())
        .is_none_or(|service| service != state.service_id())
    {
        return Err(SyncCursorError::Mismatch(
            "cursor service does not match this service DID",
        ));
    }
    let expected_filter_digest = sync_filter_digest(filter);
    if ctx
        .get("filter_digest")
        .and_then(|filter_digest| filter_digest.as_str())
        .is_none_or(|filter_digest| filter_digest != expected_filter_digest)
    {
        return Err(SyncCursorError::Mismatch(
            "cursor filter digest does not match request filter",
        ));
    }
    let positions_value = stored.get("positions").ok_or(SyncCursorError::Integrity(
        "cursor handle is missing positions",
    ))?;
    let positions = cursor_position_map(
        positions_value,
        "realms",
        Some("cursor handle is missing positions.realms"),
    )?;
    let account_positions = cursor_position_map(
        positions_value,
        "account_realms",
        Some("cursor handle is missing positions.account_realms"),
    )?;
    let device_list_positions = cursor_position_map(positions_value, "device_lists", None)?;
    let to_device_position = positions_value
        .get("to_device")
        .and_then(|position| position.as_i64())
        .unwrap_or_default();
    let notification_position = positions_value
        .get("notifications")
        .and_then(|position| position.as_i64())
        .unwrap_or_default();
    let issued_at_ms = ctx.get("issued_at_ms").and_then(|value| value.as_i64());
    Ok(SyncCursor {
        positions,
        account_positions,
        device_list_positions,
        to_device_position,
        notification_position,
        issued_at_ms,
    })
}

pub(crate) async fn parse_and_validate_events_query_cursor(
    token: &str,
    state: &AppState,
    session: Option<&SessionIdentityState>,
    filter_digest: &str,
    now_ms: i64,
) -> Result<EventsQueryCursor, SyncCursorError> {
    if !token.starts_with("ak:cursor:") {
        return Err(SyncCursorError::Invalid(
            "events query cursor must be a ak:cursor token",
        ));
    }
    let cursor = decode_sync_cursor(token, now_ms)?;
    if cursor.purpose != arkret_hlc::CursorPurpose::Stream {
        return Err(SyncCursorError::Integrity(
            "cursor purpose does not match stream",
        ));
    }
    if cursor_authority_revoked(state, token, session, now_ms) {
        return Err(SyncCursorError::Revoked);
    }
    let handle = cursor.h.as_str();
    let record = stored_sync_cursor_record_by_handle(state, handle).await?;
    if record.expires_at_ms <= now_ms {
        let _ = state.sync().delete_cursor(handle).await;
        return Err(SyncCursorError::Integrity("sync cursor handle has expired"));
    }
    if record.purpose.as_str() != STREAM_CURSOR_PURPOSE {
        return Err(SyncCursorError::Integrity(
            "cursor handle purpose does not match stream",
        ));
    }
    let (expected_binding_subject, expected_device) = cursor_principal_device(session);
    if record.binding_subject.as_deref() != Some(expected_binding_subject.as_str()) {
        return Err(SyncCursorError::Mismatch(
            "cursor binding subject does not match request actor",
        ));
    }
    if record.device_id.as_deref() != Some(expected_device.as_str()) {
        return Err(SyncCursorError::Mismatch(
            "cursor device does not match request device",
        ));
    }
    if record.service_id.as_str() != state.service_id().as_str() {
        return Err(SyncCursorError::Mismatch(
            "cursor service does not match this service DID",
        ));
    }
    if record.filter_digest.as_deref() != Some(filter_digest) {
        return Err(SyncCursorError::Mismatch(
            "cursor filter digest does not match request filter",
        ));
    }
    let target = record
        .target
        .as_ref()
        .and_then(|target| target.get("event_id"))
        .and_then(Value::as_str)
        .ok_or(SyncCursorError::Integrity(
            "events query cursor handle is missing target.event_id",
        ))?;
    if arkret_identifiers::EventId::new(target).is_err() {
        return Err(SyncCursorError::Integrity(
            "events query cursor target must be an event id",
        ));
    }
    Ok(EventsQueryCursor {
        event_id: target.to_owned(),
    })
}

pub(crate) async fn parse_and_validate_barrier_cursor(
    token: &str,
    state: &AppState,
    session: &SessionIdentityState,
    now_ms: i64,
) -> Result<String, SyncCursorError> {
    let cursor = decode_sync_cursor(token, now_ms)?;
    if cursor.purpose != arkret_hlc::CursorPurpose::Barrier {
        return Err(SyncCursorError::Invalid(
            "X-Arkret-Wait-For requires a barrier cursor",
        ));
    }
    if cursor_authority_revoked(state, token, Some(session), now_ms) {
        return Err(SyncCursorError::Revoked);
    }
    let record = stored_sync_cursor_record_by_handle(state, cursor.h.as_str()).await?;
    if record.expires_at_ms <= now_ms {
        let _ = state.sync().delete_cursor(cursor.h.as_str()).await;
        return Err(SyncCursorError::Integrity(
            "barrier cursor handle has expired",
        ));
    }
    if record.purpose != BARRIER_CURSOR_PURPOSE {
        return Err(SyncCursorError::Integrity(
            "cursor handle purpose does not match barrier",
        ));
    }
    if record.binding_subject.as_deref() != Some(session.actor.as_str()) {
        return Err(SyncCursorError::Mismatch(
            "barrier cursor binding subject does not match request actor",
        ));
    }
    if record.device_id.as_deref() != Some(session.device_id.as_str()) {
        return Err(SyncCursorError::Mismatch(
            "barrier cursor device does not match request device",
        ));
    }
    if record.service_id != *state.service_id() {
        return Err(SyncCursorError::Mismatch(
            "barrier cursor service does not match this service DID",
        ));
    }
    let event_id = record
        .target
        .as_ref()
        .and_then(|target| target.get("event_id"))
        .and_then(Value::as_str)
        .ok_or(SyncCursorError::Integrity(
            "barrier cursor handle is missing target.event_id",
        ))?;
    if arkret_identifiers::EventId::new(event_id).is_err() {
        return Err(SyncCursorError::Integrity(
            "barrier cursor target must be an event id",
        ));
    }
    Ok(event_id.to_owned())
}

fn decode_sync_cursor(token: &str, now_ms: i64) -> Result<arkret_hlc::Cursor, SyncCursorError> {
    arkret_hlc::Cursor::decode_at(token, now_ms).map_err(|error| {
        if error.to_string().contains("cursor has expired") {
            SyncCursorError::Expired
        } else {
            SyncCursorError::Invalid("cursor must use the canonical SDK wire profile")
        }
    })
}

#[cfg(test)]
pub fn decode_sync_cursor_value(token: &str) -> Result<serde_json::Value, SyncCursorError> {
    let cursor = arkret_hlc::Cursor::decode(token)
        .map_err(|_| SyncCursorError::Invalid("cursor must use the canonical SDK wire profile"))?;
    serde_json::to_value(cursor)
        .map_err(|_| SyncCursorError::Invalid("cursor cannot be represented as JSON"))
}

const FILTER_DIGEST_COLLECTION_KEYS: &[&str] =
    &["realms", "actors", "event_types", "not_event_types", "kind"];
const FILTER_DIGEST_FALSE_DEFAULT_KEYS: &[&str] =
    &["lazy_load_members", "include_redundant_members"];

pub(crate) fn normalized_filter_digest_value(filter: Option<&serde_json::Value>) -> Value {
    filter
        .map(normalize_filter_digest_collections)
        .unwrap_or_else(|| json!({}))
}

fn normalize_filter_digest_collections(value: &Value) -> Value {
    match value {
        Value::Object(object) => {
            let mut normalized = serde_json::Map::new();
            for (key, value) in object {
                if FILTER_DIGEST_FALSE_DEFAULT_KEYS.contains(&key.as_str())
                    && value == &Value::Bool(false)
                {
                    continue;
                }
                let value = if FILTER_DIGEST_COLLECTION_KEYS.contains(&key.as_str()) {
                    normalize_filter_digest_string_collection(value)
                } else {
                    normalize_filter_digest_collections(value)
                };
                if FILTER_DIGEST_COLLECTION_KEYS.contains(&key.as_str())
                    && matches!(&value, Value::Array(values) if values.is_empty())
                {
                    continue;
                }
                normalized.insert(key.clone(), value);
            }
            Value::Object(normalized)
        }
        Value::Array(values) => Value::Array(
            values
                .iter()
                .map(normalize_filter_digest_collections)
                .collect(),
        ),
        _ => value.clone(),
    }
}

fn normalize_filter_digest_string_collection(value: &Value) -> Value {
    let Value::Array(values) = value else {
        return normalize_filter_digest_collections(value);
    };
    let Some(strings) = values
        .iter()
        .map(Value::as_str)
        .collect::<Option<BTreeSet<_>>>()
    else {
        return Value::Array(
            values
                .iter()
                .map(normalize_filter_digest_collections)
                .collect(),
        );
    };
    Value::Array(
        strings
            .into_iter()
            .map(|value| Value::String(value.to_owned()))
            .collect(),
    )
}

pub fn sync_filter_digest(filter: Option<&serde_json::Value>) -> String {
    let filter = normalized_filter_digest_value(filter);
    let binding = json!({
        "filter": filter,
    });
    arkret_canonical::canonical_sha256(&binding)
        .unwrap_or_else(|_| arkret_canonical::sha256_digest(binding.to_string().as_bytes()))
}

/// `POST /_arkret/self/account/cursor/revoke` — `ak.self.account.command.revoke_cursor.v1`.
///
/// High-assurance optional endpoint: record a previously issued cursor
/// authority in the revocation set until its maximum TTL would have elapsed.
/// A revoked cursor thereafter returns `cursor_revoked` from
/// [`parse_and_validate_sync_cursor`] and never advances to-device ack,
/// account-subscribe resume position, wait-for barrier state, or dropped
/// recovery state. `revoke_scope` controls breadth (`this_cursor` default,
/// `same_device`, `same_session`).
#[salvo::oapi::endpoint(
    operation_id = "ak.self.account.command.revoke_cursor",
    summary = "Revoke an account read cursor",
    tags("account")
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.account.command.revoke_cursor.v1"))]
pub(super) async fn account_cursor_revoke(
    aa: crate::routing::system::extract::AuthArgs,
    body: salvo::oapi::extract::JsonBody<
        arkret_models_identity::account::AccountCursorRevokeRequestBody,
    >,
    depot: &mut Depot,
    req: &mut Request,
) -> soland_http::result::JsonResult<arkret_models_identity::account::AccountCursorRevokeOutcome> {
    use soland_http::error::AppError;
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let body = body.into_inner();

    let cursor = body.cursor.trim();
    if !cursor.starts_with("ak:cursor:") || cursor.len() <= "ak:cursor:".len() {
        return Err(AppError::param_invalid("cursor must be a ak:cursor token"));
    }
    let reason_code = body.reason_code.as_str().trim();
    if reason_code.is_empty() {
        return Err(AppError::param_invalid("reason_code is required"));
    }
    let scope = body.revoke_scope;
    let scope_value = match scope {
        arkret_models_identity::account::CursorRevokeScope::ThisCursor => "this_cursor",
        arkret_models_identity::account::CursorRevokeScope::SameDevice => "same_device",
        arkret_models_identity::account::CursorRevokeScope::SameSession => "same_session",
    };

    let revoked_at = now();
    let expires_at = revoked_at + chrono::Duration::seconds(CURSOR_MAX_TTL_SECONDS);
    let device_id = if matches!(
        scope,
        arkret_models_identity::account::CursorRevokeScope::ThisCursor
    ) {
        None
    } else {
        Some(session.device_id.clone())
    };
    let application_record = soland_services::sync::CursorRevocationState {
        cursor_digest: sha256_hex(cursor.as_bytes()),
        principal_id: session.actor.clone(),
        device_id,
        scope: scope_value.to_owned(),
        reason_code: reason_code.to_owned(),
        revoked_at,
        expires_at,
    };
    // Durable first (fail-closed): a revocation that is only cached in
    // memory would silently un-revoke on the next restart, which defeats
    // the high-assurance purpose of this endpoint. Only after the ledger
    // write succeeds do we update the in-memory cache that
    // `cursor_authority_revoked` consults.
    state
        .sync()
        .record_cursor_revocation(&application_record)
        .await
        .map_err(|error| {
            AppError::internal(format!("failed to persist cursor revocation: {error}"))
        })?;
    state.sync().cache_cursor_revocation(application_record);

    crate::json_ok(
        arkret_models_identity::account::AccountCursorRevokeOutcome {
            revoked: true,
            expires_at,
            revoke_scope_effective: Some(scope),
        },
    )
}

/// Returns `true` when `token` (or the authenticated session it is bound to)
/// has an active revocation recorded by [`account_cursor_revoke`]. Prunes
/// entries past their GC horizon as a side effect.
fn cursor_authority_revoked(
    state: &AppState,
    token: &str,
    session: Option<&SessionIdentityState>,
    now_ms: i64,
) -> bool {
    let digest = sha256_hex(token.as_bytes());
    state.sync().cursor_authority_revoked(
        &digest,
        session.map(|session| session.actor.as_str()),
        session.map(|session| session.device_id.as_str()),
        chrono::DateTime::from_timestamp_millis(now_ms).unwrap_or_else(chrono::Utc::now),
    )
}
