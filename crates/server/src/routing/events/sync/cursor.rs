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
    /// The cursor authority was revoked via `ck.self.account.command.revoke_cursor`.
    /// Surfaced as `cursor_revoked`; MUST be raised before any server-side
    /// state advancement (to-device ack, account-subscribe resume, wait-for
    /// barrier release, dropped/resync recovery).
    Revoked,
}

pub(crate) const EVENTS_QUERY_CURSOR_PURPOSE: &str = "events_query";

fn cursor_principal_device(session: Option<&SessionRecord>) -> (String, String) {
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
    session: Option<&SessionRecord>,
    filter: Option<&serde_json::Value>,
    realms_positions: BTreeMap<String, i64>,
    account_realms_positions: BTreeMap<String, i64>,
    device_list_positions: BTreeMap<String, i64>,
    to_device_position: i64,
) -> String {
    let issued_at = chrono::Utc::now();
    let expires_at = issued_at + ChronoDuration::hours(1);
    let (principal_id, device_id) = cursor_principal_device(session);
    let device_positions = BTreeMap::from([(device_id.clone(), issued_at.timestamp_micros())]);
    let filter_digest = sync_filter_digest(filter);
    let issued_at_ms = issued_at.timestamp_millis();
    let expires_at_ms = expires_at.timestamp_millis();
    let positions = json!({
        "realms": realms_positions,
        "account_realms": account_realms_positions,
        "device_lists": device_list_positions,
        "devices": device_positions,
        "to_device": to_device_position
    });
    // Deterministic handle: HMAC over the binding content (positions
    // included, per-mint `devices` wall-clock stamp excluded), so an
    // unchanged frontier re-mints the SAME handle and the upsert only
    // refreshes the row's expiry instead of growing the table.
    let binding = stream_cursor_handle_binding(
        &principal_id,
        &device_id,
        &state.config.service_did,
        &filter_digest,
        &realms_positions,
        &account_realms_positions,
        &device_list_positions,
        to_device_position,
    );
    let handle = derive_cursor_handle(&state.sync_cursor_hmac_key, &binding);
    upsert_sync_cursor_record(
        state,
        SyncCursorRecord {
            handle: handle.clone(),
            principal_id: Some(principal_id),
            device_id: Some(device_id),
            service_id: state.config.service_did.clone(),
            filter_digest: Some(filter_digest),
            purpose: "stream".to_owned(),
            positions: Some(positions),
            target: None,
            issued_at_ms,
            expires_at_ms,
        },
    )
    .await;
    let cursor = json!({
        "v": "1",
        "purpose": "stream",
        "t": issued_at.to_rfc3339_opts(SecondsFormat::Millis, true),
        "x": expires_at_ms,
        "h": handle
    });
    encode_sync_cursor_value(cursor)
}

pub(crate) async fn sync_token_for_events_query(
    state: &AppState,
    session: Option<&SessionRecord>,
    filter_digest: &str,
    event_id: &str,
) -> String {
    let issued_at = chrono::Utc::now();
    let expires_at = issued_at + ChronoDuration::hours(1);
    let issued_at_ms = issued_at.timestamp_millis();
    let expires_at_ms = expires_at.timestamp_millis();
    let (principal_id, device_id) = cursor_principal_device(session);
    let target = json!({ "event_id": event_id });
    let binding = events_query_cursor_handle_binding(
        &principal_id,
        &device_id,
        &state.config.service_did,
        filter_digest,
        &target,
    );
    let handle = derive_cursor_handle(&state.sync_cursor_hmac_key, &binding);
    upsert_sync_cursor_record(
        state,
        SyncCursorRecord {
            handle: handle.clone(),
            principal_id: Some(principal_id),
            device_id: Some(device_id),
            service_id: state.config.service_did.clone(),
            filter_digest: Some(filter_digest.to_owned()),
            purpose: EVENTS_QUERY_CURSOR_PURPOSE.to_owned(),
            positions: None,
            target: Some(target),
            issued_at_ms,
            expires_at_ms,
        },
    )
    .await;
    encode_sync_cursor_value(json!({
        "v": "1",
        "purpose": EVENTS_QUERY_CURSOR_PURPOSE,
        "t": issued_at.to_rfc3339_opts(SecondsFormat::Millis, true),
        "x": expires_at_ms,
        "h": handle
    }))
}

pub(crate) async fn sync_token_for_state(state: &AppState) -> String {
    sync_token_for_state_positions(state, BTreeMap::new()).await
}

async fn sync_token_for_state_positions(
    state: &AppState,
    realms_positions: BTreeMap<String, i64>,
) -> String {
    let issued_at = chrono::Utc::now();
    let expires_at = issued_at + ChronoDuration::hours(1);
    let issued_at_ms = issued_at.timestamp_millis();
    let expires_at_ms = expires_at.timestamp_millis();
    let binding = service_cursor_handle_binding(&state.config.service_did, &realms_positions);
    let handle = derive_cursor_handle(&state.sync_cursor_hmac_key, &binding);
    upsert_sync_cursor_record(
        state,
        SyncCursorRecord {
            handle: handle.clone(),
            principal_id: None,
            device_id: None,
            service_id: state.config.service_did.clone(),
            filter_digest: None,
            purpose: "stream".to_owned(),
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
    encode_sync_cursor_value(json!({
            "v": "1",
            "purpose": "stream",
            "t": issued_at.to_rfc3339_opts(SecondsFormat::Millis, true),
            "x": expires_at_ms,
            "h": handle
    }))
}

pub(crate) fn encode_sync_cursor_value(cursor: Value) -> String {
    let bytes = cokret_sdk::canonical::canonical_json_bytes(&cursor)
        .unwrap_or_else(|_| cursor.to_string().into_bytes());
    format!("ck:cursor:{}", URL_SAFE_NO_PAD.encode(bytes))
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

/// Canonical byte string a STREAM cursor handle is derived from.
///
/// Excludes the per-mint `positions.devices` timestamp (it is a wall-clock
/// stamp, not a content position; including it would defeat determinism — see
/// `_cursor_todos.md` C1). Includes every field the integrity check binds, so a
/// cross-binding handle never collides.
pub(crate) fn stream_cursor_handle_binding(
    principal_id: &str,
    device_id: &str,
    service_id: &str,
    filter_digest: &str,
    realms_positions: &BTreeMap<String, i64>,
    account_realms_positions: &BTreeMap<String, i64>,
    device_list_positions: &BTreeMap<String, i64>,
    to_device_position: i64,
) -> Vec<u8> {
    let binding = json!({
        "principal_id": principal_id,
        "device_id": device_id,
        "service_id": service_id,
        "filter_digest": filter_digest,
        "purpose": "stream",
        "realms": realms_positions,
        "account_realms": account_realms_positions,
        "device_lists": device_list_positions,
        "to_device": to_device_position,
    });
    cokret_sdk::canonical::canonical_json_bytes(&binding)
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
        "purpose": EVENTS_QUERY_CURSOR_PURPOSE,
        "target": target,
    });
    cokret_sdk::canonical::canonical_json_bytes(&binding)
        .unwrap_or_else(|_| binding.to_string().into_bytes())
}

/// Canonical byte string the GENERIC service-level cursor handle is derived
/// from (`sync_token_for_state`: empty positions, no session binding). Shaped
/// differently from [`stream_cursor_handle_binding`] so the two namespaces
/// can never collide.
fn service_cursor_handle_binding(
    service_id: &str,
    realms_positions: &BTreeMap<String, i64>,
) -> Vec<u8> {
    let binding = json!({
        "kind": "generic",
        "purpose": "stream",
        "service_id": service_id,
        "realms": realms_positions,
        "account_realms": {},
        "device_lists": {},
        "to_device": 0,
    });
    cokret_sdk::canonical::canonical_json_bytes(&binding)
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
            let now_ms = chrono::Utc::now().timestamp_millis();
            match state.persistence.sync_cursors().prune_expired(now_ms).await {
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
async fn upsert_sync_cursor_record(state: &AppState, record: SyncCursorRecord) {
    if let Err(error) = state.persistence.sync_cursors().upsert(&record).await {
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
) -> Result<SyncCursorRecord, SyncCursorError> {
    state
        .persistence
        .sync_cursors()
        .get(handle)
        .await
        .map_err(|error| {
            tracing::warn!(%error, handle, "sync cursor handle lookup failed");
            SyncCursorError::Integrity("sync cursor handle lookup failed")
        })?
        .ok_or(SyncCursorError::Integrity("sync cursor handle is unknown"))
}

/// Rebuild the in-memory `{ctx, positions, target?, expires_at_ms}` stored
/// shape from a persisted row. Generic rows reconstruct a ctx WITHOUT
/// `principal_id`/`device_id`, which `parse_and_validate_sync_cursor` rejects
/// by construction.
fn stored_value_from_sync_cursor_record(record: SyncCursorRecord) -> Value {
    let mut ctx = serde_json::Map::new();
    if let Some(principal_id) = record.principal_id {
        ctx.insert("principal_id".to_owned(), Value::String(principal_id));
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

fn has_inline_cursor_body_marker(value: &Value) -> bool {
    value.get("_mac").is_some()
        || value.get("_sig").is_some()
        || value.get("positions").is_some()
        || value.get("scope").is_some()
        || value.get("s").is_some()
        || value.get("d").is_some()
        || value.get("target").is_some()
        || value.get("_filter_digest").is_some()
        || value.get("filter_digest").is_some()
        || value.get("issuer_kid").is_some()
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
    session: Option<&SessionRecord>,
    filter: Option<&serde_json::Value>,
    now_ms: i64,
) -> Result<SyncCursor, SyncCursorError> {
    let value = decode_sync_cursor_value(token)?;
    if value
        .get("v")
        .and_then(|v| v.as_str())
        .is_none_or(|v| v != "1")
        || value
            .get("purpose")
            .and_then(|purpose| purpose.as_str())
            .is_none_or(|purpose| purpose != "stream")
    {
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
    let Some(expires_at) = value.get("x").and_then(|expires_at| expires_at.as_i64()) else {
        return Err(SyncCursorError::Invalid("after cursor must contain x"));
    };
    if expires_at <= now_ms {
        return Err(SyncCursorError::Expired);
    }
    if has_inline_cursor_body_marker(&value)
        || value.get("_ctx").is_some()
        || value.get("_positions").is_some()
    {
        return Err(SyncCursorError::Integrity(
            "core cursor must use stateful handle form",
        ));
    };
    let Some(handle) = value.get("h").and_then(|h| h.as_str()) else {
        return Err(SyncCursorError::Integrity("after cursor must contain h"));
    };
    if validate_cursor_handle(handle).is_err() {
        return Err(SyncCursorError::Invalid("invalid cursor handle"));
    }
    let stored = stored_sync_cursor_by_handle(state, handle).await?;
    if stored
        .get("expires_at_ms")
        .and_then(|expires_at| expires_at.as_i64())
        .is_none_or(|expires_at| expires_at <= now_ms)
    {
        let _ = state.persistence.sync_cursors().delete(handle).await;
        return Err(SyncCursorError::Integrity("sync cursor handle has expired"));
    }
    let ctx = stored
        .get("ctx")
        .and_then(|ctx| ctx.as_object())
        .ok_or(SyncCursorError::Integrity("cursor handle is missing ctx"))?;
    let expected_principal = session
        .map(|session| session.actor.as_str())
        .unwrap_or("anonymous");
    let expected_device = session
        .map(|session| session.device_id.as_str())
        .unwrap_or("anonymous");
    if ctx
        .get("purpose")
        .and_then(|purpose| purpose.as_str())
        .is_none_or(|purpose| purpose != "stream")
    {
        return Err(SyncCursorError::Integrity(
            "cursor handle purpose does not match account stream",
        ));
    }
    if ctx
        .get("principal_id")
        .and_then(|principal| principal.as_str())
        .is_none_or(|principal| principal != expected_principal)
    {
        return Err(SyncCursorError::Mismatch(
            "cursor principal does not match request actor",
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
        .is_none_or(|service| service != state.config.service_did)
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
    let issued_at_ms = ctx.get("issued_at_ms").and_then(|value| value.as_i64());
    Ok(SyncCursor {
        positions,
        account_positions,
        device_list_positions,
        to_device_position,
        issued_at_ms,
    })
}

pub(crate) async fn parse_and_validate_events_query_cursor(
    token: &str,
    state: &AppState,
    session: Option<&SessionRecord>,
    filter_digest: &str,
    now_ms: i64,
) -> Result<EventsQueryCursor, SyncCursorError> {
    if !token.starts_with("ck:cursor:") {
        return Err(SyncCursorError::Invalid(
            "events query cursor must be a ck:cursor token",
        ));
    }
    let value = decode_sync_cursor_value(token)?;
    if value
        .get("v")
        .and_then(|v| v.as_str())
        .is_none_or(|v| v != "1")
    {
        return Err(SyncCursorError::Invalid(
            "events query cursor must be a v1 cursor",
        ));
    }
    if value
        .get("purpose")
        .and_then(|purpose| purpose.as_str())
        .is_none_or(|purpose| purpose != EVENTS_QUERY_CURSOR_PURPOSE)
    {
        return Err(SyncCursorError::Integrity(
            "cursor purpose does not match events query",
        ));
    }
    if cursor_authority_revoked(state, token, session, now_ms) {
        return Err(SyncCursorError::Revoked);
    }
    let Some(expires_at) = value.get("x").and_then(|expires_at| expires_at.as_i64()) else {
        return Err(SyncCursorError::Invalid(
            "events query cursor must contain x",
        ));
    };
    if expires_at <= now_ms {
        return Err(SyncCursorError::Expired);
    }
    if has_inline_cursor_body_marker(&value)
        || value.get("_ctx").is_some()
        || value.get("_positions").is_some()
    {
        return Err(SyncCursorError::Integrity(
            "events query cursor must use stateful handle form",
        ));
    };
    let Some(handle) = value.get("h").and_then(|h| h.as_str()) else {
        return Err(SyncCursorError::Integrity(
            "events query cursor must contain h",
        ));
    };
    if validate_cursor_handle(handle).is_err() {
        return Err(SyncCursorError::Invalid("invalid cursor handle"));
    }
    let record = stored_sync_cursor_record_by_handle(state, handle).await?;
    if record.expires_at_ms <= now_ms {
        let _ = state.persistence.sync_cursors().delete(handle).await;
        return Err(SyncCursorError::Integrity("sync cursor handle has expired"));
    }
    if record.purpose.as_str() != EVENTS_QUERY_CURSOR_PURPOSE {
        return Err(SyncCursorError::Integrity(
            "cursor handle purpose does not match events query",
        ));
    }
    let (expected_principal, expected_device) = cursor_principal_device(session);
    if record.principal_id.as_deref() != Some(expected_principal.as_str()) {
        return Err(SyncCursorError::Mismatch(
            "cursor principal does not match request actor",
        ));
    }
    if record.device_id.as_deref() != Some(expected_device.as_str()) {
        return Err(SyncCursorError::Mismatch(
            "cursor device does not match request device",
        ));
    }
    if record.service_id.as_str() != state.config.service_did.as_str() {
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
    if !target.starts_with("ck:event:") {
        return Err(SyncCursorError::Integrity(
            "events query cursor target must be an event id",
        ));
    }
    Ok(EventsQueryCursor {
        event_id: target.to_owned(),
    })
}

pub fn decode_sync_cursor_value(token: &str) -> Result<serde_json::Value, SyncCursorError> {
    let Some(encoded) = token.strip_prefix("ck:cursor:") else {
        return Err(SyncCursorError::Invalid(
            "after must use a ck:cursor account token",
        ));
    };
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| SyncCursorError::Invalid("after cursor must be valid base64url"))?;
    serde_json::from_slice(&bytes)
        .map_err(|_| SyncCursorError::Invalid("after cursor must contain JSON"))
}

pub fn sync_filter_digest(filter: Option<&serde_json::Value>) -> String {
    let empty_filter = json!({});
    let binding = json!({
        "filter": filter.unwrap_or(&empty_filter),
    });
    cokret_sdk::canonical::canonical_sha256(&binding)
        .unwrap_or_else(|_| cokret_sdk::canonical::sha256_digest(binding.to_string().as_bytes()))
}

/// `POST /_cokret/self/account/cursor/revoke` — `ck.self.account.command.revoke_cursor`.
///
/// High-assurance optional endpoint: record a previously issued cursor
/// authority in the revocation set until its maximum TTL would have elapsed.
/// A revoked cursor thereafter returns `cursor_revoked` from
/// [`parse_and_validate_sync_cursor`] and never advances to-device ack,
/// account-subscribe resume position, wait-for barrier state, or dropped
/// recovery state. `revoke_scope` controls breadth (`this_cursor` default,
/// `same_device`, `same_session`).
#[endpoint(
    operation_id = "ck.self.account.command.revoke_cursor",
    tags("sync"),
    summary = "Revoke a previously issued cursor authority",
    status_codes(200, 400, 401, 500)
)]
#[tracing::instrument(skip_all, fields(op = "ck.self.account.command.revoke_cursor"))]
pub(super) async fn account_cursor_revoke(
    aa: crate::routing::system::extract::AuthArgs,
    body: salvo::oapi::extract::JsonBody<cokret_sdk::AccountCursorRevokeRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> crate::result::JsonResult<cokret_sdk::AccountCursorRevokeOutcome> {
    use crate::error::AppError;
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let body = body.into_inner();

    let cursor = body.cursor.trim();
    if !cursor.starts_with("ck:cursor:") || cursor.len() <= "ck:cursor:".len() {
        return Err(AppError::invalid_param("cursor must be a ck:cursor token"));
    }
    let reason_code = body.reason_code.trim();
    if reason_code.is_empty() {
        return Err(AppError::invalid_param("reason_code is required"));
    }
    let scope = body.revoke_scope;
    let scope_value = match scope {
        cokret_sdk::CursorRevokeScope::ThisCursor => "this_cursor",
        cokret_sdk::CursorRevokeScope::SameDevice => "same_device",
        cokret_sdk::CursorRevokeScope::SameSession => "same_session",
    };

    let revoked_at = now();
    let expires_at = revoked_at + ChronoDuration::seconds(CURSOR_MAX_TTL_SECONDS);
    let device_id = if matches!(scope, cokret_sdk::CursorRevokeScope::ThisCursor) {
        None
    } else {
        Some(session.device_id.clone())
    };
    let record = crate::state::CursorRevocation {
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
        .persistence
        .sync_cursors()
        .record_revocation(&record)
        .await
        .map_err(|error| {
            AppError::internal(format!("failed to persist cursor revocation: {error}"))
        })?;
    {
        let now_ms = revoked_at.timestamp_millis();
        let mut revocations = state
            .sync_cursor_revocations
            .lock()
            .expect("sync cursor revocations lock");
        revocations.retain(|entry| entry.expires_at.timestamp_millis() > now_ms);
        revocations.push(record);
    }

    crate::json_ok(cokret_sdk::AccountCursorRevokeOutcome {
        revoked: true,
        expires_at,
        revoke_scope_effective: Some(scope),
    })
}

/// Returns `true` when `token` (or the authenticated session it is bound to)
/// has an active revocation recorded by [`account_cursor_revoke`]. Prunes
/// entries past their GC horizon as a side effect.
fn cursor_authority_revoked(
    state: &AppState,
    token: &str,
    session: Option<&SessionRecord>,
    now_ms: i64,
) -> bool {
    let mut revocations = state
        .sync_cursor_revocations
        .lock()
        .expect("sync cursor revocations lock");
    revocations.retain(|entry| entry.expires_at.timestamp_millis() > now_ms);
    if revocations.is_empty() {
        return false;
    }
    let digest = sha256_hex(token.as_bytes());
    revocations.iter().any(|entry| match entry.scope.as_str() {
        "this_cursor" => entry.cursor_digest == digest,
        // soland's stateful cursor binds (principal, device); `same_session`
        // is enforced at the same granularity as `same_device`.
        "same_device" | "same_session" => session.is_some_and(|session| {
            entry.principal_id == session.actor
                && entry.device_id.as_deref() == Some(session.device_id.as_str())
        }),
        _ => false,
    })
}

/// Spec B1.5 — when an implementation would emit a `Dropped` frame but
/// cannot supply a resume cursor, the wire-breaking rule downgrades to
/// `ResyncRequired`. Callers use [`dropped_or_resync`] to construct the
/// correct frame body from an optional cursor.
///
/// Note: the cursor type expected by `EventsSubscribeFrameBody::Dropped`
/// is the typed-id `cokret_identifiers::Cursor` (`ck:cursor:<base64url>`),
/// NOT the `cokret_sdk::Cursor` struct produced by `cursor::Cursor::new()`.
/// The typed-id is exposed as `cokret_sdk::identifiers::Cursor`.
pub fn dropped_or_resync(
    cursor: Option<cokret_sdk::identifiers::Cursor>,
    reason: impl Into<String>,
    reconnect_after_ms: Option<u64>,
) -> cokret_sdk::EventsSubscribeFrameBody {
    let reason = reason.into();
    match cursor {
        Some(cursor) => cokret_sdk::EventsSubscribeFrameBody::Dropped {
            cursor,
            reason,
            reconnect_after_ms,
        },
        None => cokret_sdk::EventsSubscribeFrameBody::ResyncRequired {
            reason,
            reconnect_after_ms,
        },
    }
}

/// Spec T03 — minimum length of a base64url cursor handle to supply
/// ≥128-bit entropy. Spec tightened `h.minLength` from 16 → 22.
pub const CURSOR_HANDLE_MIN_LENGTH: usize = 22;

/// Validate an inbound cursor handle (post-base64url-decode is callers'
/// responsibility). Spec T03 — rejects shorter than 22 chars.
pub fn validate_cursor_handle(handle: &str) -> Result<(), (crate::error::ErrorCode, &'static str)> {
    if handle.len() < CURSOR_HANDLE_MIN_LENGTH {
        return Err((
            crate::error::ErrorCode::CursorIntegrityInvalid,
            "cursor handle MUST be at least 22 base64url characters \
             (≥128-bit entropy); spec tightening",
        ));
    }
    if !handle
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_'))
    {
        return Err((
            crate::error::ErrorCode::CursorIntegrityInvalid,
            "cursor handle MUST be base64url (no padding)",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod cursor_frame_tests {
    use super::*;

    #[test]
    fn dropped_without_cursor_downgrades_to_resync() {
        let body = dropped_or_resync(None, "broadcast_lag", Some(10_000));
        assert!(matches!(
            body,
            cokret_sdk::EventsSubscribeFrameBody::ResyncRequired { .. }
        ));
        let cursor = cokret_sdk::identifiers::Cursor::new("ck:cursor:resume").unwrap();
        let body = dropped_or_resync(Some(cursor), "broadcast_lag", Some(10_000));
        assert!(matches!(
            body,
            cokret_sdk::EventsSubscribeFrameBody::Dropped {
                reconnect_after_ms: Some(10_000),
                ..
            }
        ));
    }

    #[test]
    fn cursor_handle_minimum_length_enforced() {
        // 22-char handle should pass.
        let ok = "a".repeat(22);
        validate_cursor_handle(&ok).unwrap();
        // 21-char handle must fail.
        let bad = "a".repeat(21);
        let err = validate_cursor_handle(&bad).unwrap_err();
        assert_eq!(err.0, crate::error::ErrorCode::CursorIntegrityInvalid);
    }
}
