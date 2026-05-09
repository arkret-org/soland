//! Signed Event Envelope ingestion + read API (`/api/v1/events/*`).
//!
//! Surfaces:
//! - `GET  /api/v1/events/describe`  — declare the active event registry,
//!   schema/reducer profiles, and limits.
//! - `POST /api/v1/events`           — submit one canonical Event Envelope.
//!   The active profile is `cx.profile.event_envelope_minimal.v1`; batched
//!   submit is intentionally rejected.
//! - `GET  /api/v1/events/{event_id}` — fetch one envelope.
//! - `POST /api/v1/events/batch-get`  — fetch up to `MAX_EVENT_BATCH_GET`.
//! - `GET  /api/v1/events`            — paginated list (filtered by actor / space).
//! - `GET  /api/v1/events/frontier`   — per-actor / per-space frontier.
//!
//! The 22-fn validator block (`validate_event_envelope` + helpers) lives at
//! the bottom of this file — it was the largest still-coupled cluster in
//! `mod.rs` but its only outward dependency is the shared
//! `validate_no_removed_legacy_contracts` helper, which stays in `mod.rs`
//! because the operation/sync/repo paths also call it.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use salvo::{http::StatusCode, prelude::*};
use serde_json::{Value, json};

use crate::{
    artifacts,
    state::{AppState, CanonicalEventRecord, SessionRecord},
    wire::{
        EventBatchGetRequest, EventBatchGetResponse, EventDescribeResponse, EventReadResponse,
        EventSubmitResponse, EventsFrontierResponse, EventsPageResponse, sync_token,
    },
};

use super::{
    append_audit_log, auth_or_render, now, query_param, render_error, sha256_hex,
    space_has_member, validate_did, validate_no_removed_legacy_contracts, validate_space_id,
};

const MAX_EVENT_BYTES: usize = 64 * 1024;
const MAX_EVENT_PREV_REFS: usize = 32;
const MAX_EVENT_AUTH_REFS: usize = 64;
const MAX_EVENT_BATCH_GET: usize = 100;

#[endpoint]
pub async fn events_describe(depot: &mut Depot, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let event_kinds = artifacts::active_durable_event_kinds()
        .iter()
        .cloned()
        .collect::<Vec<_>>();
    res.render(Json(EventDescribeResponse {
        service_did: state.config.service_did.clone(),
        protocol_version: "1.0".to_owned(),
        primary_write_path: "/api/v1/events".to_owned(),
        event_envelope: json!({
            "schema": "cx.schema.event.v1",
            "required_fields": [
                "event_id",
                "kind",
                "schema_id",
                "actor_id",
                "actor_seq",
                "canonical_digest",
                "proofs"
            ],
            "hashing": {
                "canonical_digest": "sha256 over the Event Envelope JSON with canonical_digest removed",
                "proof_payload_hash": "sha256 over payload/body/content JSON"
            },
            "causality": {
                "actor_seq": "strictly increasing per actor",
                "prev_refs": "must reference accepted events",
                "auth_refs": "must reference accepted authorization events"
            }
        }),
        supported_profiles: vec![
            "cx.profile.event_envelope_minimal.v1".to_owned(),
            "cx.profile.events_http_json.v1".to_owned(),
        ],
        registry: json!({
            "source": "contrix-spec/spec/v1/artifacts",
            "event_kind_registry_version": artifacts::event_kind_registry()["version"].clone(),
            "schema_registry_version": artifacts::schema_registry()["version"].clone(),
            "operation_registry_version": artifacts::operation_registry()["version"].clone(),
            "id_kind_registry_version": artifacts::id_kind_registry()["version"].clone(),
            "event_kinds": event_kinds,
            "schema_ids": artifacts::schema_ids().into_iter().collect::<Vec<_>>(),
            "operation_count": artifacts::operation_ids().len(),
            "id_kind_count": artifacts::id_kind_forms().len(),
            "id_profile": "cx.id.typed-prefix.v1"
        }),
        schema_profile: "cx.schema.core.v1".to_owned(),
        reducer_profile: "cx.reducer.v1".to_owned(),
        limits: json!({
            "max_event_bytes": MAX_EVENT_BYTES,
            "max_batch_size": 1,
            "max_batch_get": MAX_EVENT_BATCH_GET,
            "max_prev_refs": MAX_EVENT_PREV_REFS,
            "max_auth_refs": MAX_EVENT_AUTH_REFS,
            "max_list_limit": 100
        }),
        capabilities: json!({
            "single_event_submit": true,
            "batch_submit": false,
            "batch_receipt": false,
            "read_by_event_id": true,
            "batch_get": true,
            "list_by_actor_or_space": true,
            "frontier": true,
            "snapshot": false,
            "witness": false,
            "high_assurance": false
        }),
    }));
}

#[endpoint]
pub async fn submit_event(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(session) = auth_or_render(state, req, res) else {
        return;
    };
    let envelope = match req.parse_json::<Value>().await {
        Ok(body) => body,
        Err(_) => {
            render_error(
                res,
                StatusCode::BAD_REQUEST,
                "bad_json",
                "invalid event envelope",
            );
            return;
        }
    };
    if envelope.as_array().is_some()
        || envelope
            .get("events")
            .and_then(Value::as_array)
            .is_some_and(|events| !events.is_empty())
    {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "batch_not_supported",
            "POST /api/v1/events accepts one Event Envelope in the active profile",
        );
        return;
    }
    let Ok(raw_bytes) = serde_json::to_vec(&envelope) else {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "bad_json",
            "event envelope cannot be encoded",
        );
        return;
    };
    if raw_bytes.len() > MAX_EVENT_BYTES {
        render_error(
            res,
            StatusCode::PAYLOAD_TOO_LARGE,
            "event_too_large",
            "event envelope exceeds max_event_bytes",
        );
        return;
    }

    let parsed = match validate_event_envelope(state, &session, &envelope) {
        Ok(parsed) => parsed,
        Err(error) => {
            render_error(res, error.status, error.code, error.message);
            return;
        }
    };

    let received_at = now();
    let store = state.persistence.events();
    if let Ok(Some(existing)) = store.get(&parsed.event_id) {
        if existing.canonical_bytes == parsed.canonical_bytes {
            let response = event_submit_response(
                state,
                "duplicate",
                existing.event_id.clone(),
                existing.canonical_digest.clone(),
                existing.received_at,
                true,
            );
            res.render(Json(response));
            return;
        }
        append_audit_log(
            state,
            Some(&session.actor),
            "events.submit",
            json!({
                "event_id": parsed.event_id,
                "reason": "duplicate_conflict",
                "canonical_digest": parsed.canonical_digest
            }),
            "duplicate_conflict",
        );
        render_error(
            res,
            StatusCode::CONFLICT,
            "duplicate_conflict",
            "event_id already exists with different canonical bytes",
        );
        return;
    }
    if let Ok(Some(max_seq)) = store.max_actor_seq(&parsed.actor_id)
        && parsed.actor_seq <= max_seq
    {
        render_error(
            res,
            StatusCode::CONFLICT,
            "actor_seq_conflict",
            "actor_seq must be strictly increasing for the actor",
        );
        return;
    }
    for prev_ref in &parsed.prev_refs {
        if !store.contains(prev_ref).unwrap_or(false) {
            render_error(
                res,
                StatusCode::CONFLICT,
                "missing_dependency",
                "prev_refs must reference accepted events",
            );
            return;
        }
    }
    for auth_ref in &parsed.auth_refs {
        if !store.contains(auth_ref).unwrap_or(false) {
            render_error(
                res,
                StatusCode::CONFLICT,
                "missing_auth_ref",
                "auth_refs must reference accepted authorization events",
            );
            return;
        }
    }

    if let Err(error) = store.put(CanonicalEventRecord {
        event_id: parsed.event_id.clone(),
        actor_id: parsed.actor_id.clone(),
        actor_seq: parsed.actor_seq,
        space_id: parsed.space_id.clone(),
        kind: parsed.kind.clone(),
        schema_id: parsed.schema_id.clone(),
        canonical_digest: parsed.canonical_digest.clone(),
        canonical_bytes: parsed.canonical_bytes.clone(),
        envelope,
        received_at,
    }) {
        tracing::error!(%error, "failed to persist canonical event");
        render_error(
            res,
            StatusCode::INTERNAL_SERVER_ERROR,
            "persistence_error",
            "events store unavailable",
        );
        return;
    }
    append_audit_log(
        state,
        Some(&session.actor),
        "events.submit",
        json!({
            "event_id": parsed.event_id.clone(),
            "space_id": parsed.space_id.clone(),
            "kind": parsed.kind.clone(),
            "canonical_digest": parsed.canonical_digest.clone()
        }),
        "accepted",
    );
    res.render(Json(event_submit_response(
        state,
        "accepted",
        parsed.event_id,
        parsed.canonical_digest,
        received_at,
        false,
    )));
}

#[endpoint]
pub async fn get_event(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(session) = auth_or_render(state, req, res) else {
        return;
    };
    let Some(event_id) = req.param::<String>("event_id") else {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "missing_param",
            "event_id is required",
        );
        return;
    };
    let Some(record) = state.persistence.events().get(&event_id).ok().flatten() else {
        render_error(res, StatusCode::NOT_FOUND, "not_found", "event not found");
        return;
    };
    if !event_visible_to_session(state, &record, &session) {
        render_error(res, StatusCode::NOT_FOUND, "not_found", "event not found");
        return;
    }
    res.render(Json(event_read_response(&record)));
}

#[endpoint]
pub async fn batch_get_events(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(session) = auth_or_render(state, req, res) else {
        return;
    };
    let body = match req.parse_json::<EventBatchGetRequest>().await {
        Ok(body) => body,
        Err(_) => {
            render_error(
                res,
                StatusCode::BAD_REQUEST,
                "bad_json",
                "invalid batch-get request",
            );
            return;
        }
    };
    if body.event_ids.len() > MAX_EVENT_BATCH_GET {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "limit_exceeded",
            "too many event_ids requested",
        );
        return;
    }
    let store = state.persistence.events();
    let mut found = Vec::new();
    let mut missing = Vec::new();
    for event_id in body.event_ids {
        match store.get(&event_id).ok().flatten() {
            Some(record) if event_visible_to_session(state, &record, &session) => {
                found.push(event_read_response(&record));
            }
            _ => missing.push(event_id),
        }
    }
    res.render(Json(EventBatchGetResponse {
        events: found,
        missing,
        unauthorized: Vec::new(),
    }));
}

/// Internal durable-Event-store reader, kept for actor-scoped audit reads
/// that bypass the projection layer. Not wired to a public route after C17 —
/// the canonical `cx.events.query` path at `GET /api/v1/events` goes to the
/// projection-aware handler in `routing/sync.rs::events_query` so message
/// timeline reads keep working through `/api/v1/messages/send` →
/// `events_query` round-trips.
///
/// Supports the spec C17 multi-value selector `spaces[]` ∪ `actors[]` (via
/// repeated query args) **and** real backward iteration (`direction=backward`
/// returns events older than `from` cursor in reverse time order, with
/// `prev_cursor` driving further pages).
/// Plain async helper version of [`events_query_durable_scope`] so other
/// handlers (e.g. the projection-aware `routing::sync::events_query`) can
/// dispatch to the durable-store reader when the C17 selector contains only
/// `actors[]` (no `spaces[]`). Both the `#[endpoint]` wrapper and the
/// sync-side dispatcher call this impl.
pub async fn events_query_durable_scope_impl(
    depot: &mut Depot,
    req: &mut Request,
    res: &mut Response,
) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(session) = auth_or_render(state, req, res) else {
        return;
    };
    // C17 selector: `actors[]` ∪ `spaces[]` repeated query args. Aggressive
    // cleanup (2026-05-09): legacy singular `actor_id` / `space_id` removed —
    // clients MUST emit the repeated-arg form per spec.
    let actors = super::query_param_all(req, "actors");
    let spaces = super::query_param_all(req, "spaces");
    for actor in &actors {
        if validate_did(actor).is_err() {
            render_error(
                res,
                StatusCode::BAD_REQUEST,
                "invalid_param",
                &format!("invalid actor: {actor}"),
            );
            return;
        }
    }
    for space in &spaces {
        if validate_space_id(space).is_err() {
            render_error(
                res,
                StatusCode::BAD_REQUEST,
                "invalid_param",
                &format!("invalid space: {space}"),
            );
            return;
        }
    }
    // C17 cursor parameter: `from` replaces legacy `cursor`. Legacy name removed.
    let cursor = query_param(req, "from");
    // C17 direction: forward (default) | backward — backward returns events
    // older than `from` in reverse time order.
    let direction = query_param(req, "direction").unwrap_or_else(|| "forward".to_owned());
    if direction != "forward" && direction != "backward" {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "direction must be 'forward' or 'backward'",
        );
        return;
    }
    let _until = query_param(req, "until"); // upper-bound cursor — TODO follow-up.
    let limit = query_param(req, "limit")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(50)
        .clamp(1, 100);
    let actors_set: std::collections::BTreeSet<&str> =
        actors.iter().map(String::as_str).collect();
    let spaces_set: std::collections::BTreeSet<&str> =
        spaces.iter().map(String::as_str).collect();
    let mut records = state
        .persistence
        .events()
        .snapshot_all()
        .unwrap_or_default()
        .into_iter()
        .filter(|record| {
            // Spec selector semantics: union — match actor OR space membership.
            // Empty selector means "all reachable" (handler will still gate
            // through `event_visible_to_session`).
            if actors_set.is_empty() && spaces_set.is_empty() {
                return true;
            }
            let actor_match = actors_set.contains(record.actor_id.as_str());
            let space_match = record
                .space_id
                .as_deref()
                .is_some_and(|s| spaces_set.contains(s));
            actor_match || space_match
        })
        .filter(|record| event_visible_to_session(state, record, &session))
        .collect::<Vec<_>>();
    records.sort_by(|left, right| {
        left.received_at
            .cmp(&right.received_at)
            .then_with(|| left.event_id.cmp(&right.event_id))
    });
    if direction == "backward" {
        records.reverse();
    }
    let start = cursor
        .as_deref()
        .and_then(|cursor| records.iter().position(|record| record.event_id == cursor))
        .map(|index| index + 1)
        .unwrap_or(0);
    let mut page = records
        .into_iter()
        .skip(start)
        .take(limit + 1)
        .collect::<Vec<_>>();
    let has_more = page.len() > limit;
    if has_more {
        page.truncate(limit);
    }
    let next_cursor = has_more
        .then(|| page.last().map(|record| record.event_id.clone()))
        .flatten();
    let frontier = events_frontier_json(&page);
    let events = page.iter().map(event_read_response).collect();
    res.render(Json(EventsPageResponse {
        events,
        next_cursor,
        frontier,
    }));
}

/// Salvo `#[endpoint]` wrapper around [`events_query_durable_scope_impl`] so
/// the actor-scoped durable-store reader can be wired to a route directly
/// (currently used only as a fallback dispatched from `routing::sync::events_query`
/// when the C17 selector has no `spaces[]`).
#[endpoint]
pub async fn events_query_durable_scope(
    depot: &mut Depot,
    req: &mut Request,
    res: &mut Response,
) {
    events_query_durable_scope_impl(depot, req, res).await
}

#[endpoint]
pub async fn events_frontier(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(session) = auth_or_render(state, req, res) else {
        return;
    };
    let actor_id = query_param(req, "actor_id");
    let space_id = query_param(req, "space_id");
    let events = state
        .persistence
        .events()
        .snapshot_all()
        .unwrap_or_default();
    let mut actor_frontier: BTreeMap<String, u64> = BTreeMap::new();
    let mut space_frontier: BTreeMap<String, Value> = BTreeMap::new();
    for record in &events {
        if actor_id
            .as_deref()
            .is_some_and(|actor| actor != record.actor_id)
        {
            continue;
        }
        if space_id.as_deref() != record.space_id.as_deref() && space_id.is_some() {
            continue;
        }
        if !event_visible_to_session(state, record, &session) {
            continue;
        }
        actor_frontier
            .entry(record.actor_id.clone())
            .and_modify(|seq| *seq = (*seq).max(record.actor_seq))
            .or_insert(record.actor_seq);
        if let Some(space_id) = record.space_id.as_deref() {
            space_frontier.insert(
                space_id.to_owned(),
                json!({
                    "event_id": record.event_id.clone(),
                    "actor_seq": record.actor_seq,
                    "canonical_digest": record.canonical_digest.clone()
                }),
            );
        }
    }
    res.render(Json(EventsFrontierResponse {
        actor_frontier,
        space_frontier,
        frontier: json!({"storage": state.db.mode(), "generated_at": now()}),
    }));
}

// ── Validator block ─────────────────────────────────────────────────────────

#[derive(Debug)]
struct ValidatedEventEnvelope {
    event_id: String,
    actor_id: String,
    actor_seq: u64,
    space_id: Option<String>,
    kind: String,
    schema_id: String,
    prev_refs: Vec<String>,
    auth_refs: Vec<String>,
    canonical_digest: String,
    canonical_bytes: Vec<u8>,
}

#[derive(Debug)]
struct EventValidationError {
    status: StatusCode,
    code: &'static str,
    message: &'static str,
}

fn event_validation_error(
    status: StatusCode,
    code: &'static str,
    message: &'static str,
) -> EventValidationError {
    EventValidationError {
        status,
        code,
        message,
    }
}

fn validate_event_envelope(
    state: &AppState,
    session: &SessionRecord,
    envelope: &Value,
) -> Result<ValidatedEventEnvelope, EventValidationError> {
    let object = envelope.as_object().ok_or_else(|| {
        event_validation_error(
            StatusCode::BAD_REQUEST,
            "invalid_event_envelope",
            "Event Envelope must be a JSON object",
        )
    })?;
    validate_no_removed_legacy_contracts(envelope).map_err(|_| {
        event_validation_error(
            StatusCode::BAD_REQUEST,
            "legacy_contract_removed",
            "removed legacy subject/room/card contract is forbidden on the active v1 wire",
        )
    })?;
    validate_event_critical_features(object)?;

    let event_id = event_string_field(object, &["event_id"]).ok_or_else(|| {
        event_validation_error(
            StatusCode::BAD_REQUEST,
            "missing_param",
            "event_id is required",
        )
    })?;
    if !is_valid_event_id(&event_id) {
        return Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "event_id must use the cx:event: typed prefix",
        ));
    }

    let kind = event_string_field(object, &["kind", "type"]).ok_or_else(|| {
        event_validation_error(StatusCode::BAD_REQUEST, "missing_param", "kind is required")
    })?;
    if !artifacts::active_durable_event_kinds().contains(&kind) {
        return Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            "unknown_event_kind",
            "event kind is not in the active registry",
        ));
    }

    let schema_id = event_string_field(object, &["schema_id", "schema"]).ok_or_else(|| {
        event_validation_error(
            StatusCode::BAD_REQUEST,
            "missing_param",
            "schema_id is required",
        )
    })?;
    if !schema_id.starts_with("cx.schema.") {
        return Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "schema_id must use the cx.schema.* profile",
        ));
    }
    if !event_schema_is_active(state, &schema_id) {
        return Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            "unknown_schema",
            "schema_id is not in the active schema registry",
        ));
    }

    let actor_id = event_string_field(object, &["actor_id", "sender"]).ok_or_else(|| {
        event_validation_error(
            StatusCode::BAD_REQUEST,
            "missing_param",
            "actor_id is required",
        )
    })?;
    if validate_did(&actor_id).is_err() {
        return Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "actor_id must be a DID",
        ));
    }
    if actor_id != session.actor {
        return Err(event_validation_error(
            StatusCode::FORBIDDEN,
            "actor_session_mismatch",
            "event actor_id must match the bearer session actor",
        ));
    }

    let actor_seq = object
        .get("actor_seq")
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            event_validation_error(
                StatusCode::BAD_REQUEST,
                "missing_param",
                "actor_seq is required",
            )
        })?;
    if actor_seq == 0 {
        return Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "actor_seq must be greater than zero",
        ));
    }

    let space_id = event_string_field(object, &["space_id"]);
    if let Some(space_id) = space_id.as_deref() {
        if validate_space_id(space_id).is_err() {
            return Err(event_validation_error(
                StatusCode::BAD_REQUEST,
                "invalid_param",
                "space_id must use the cx:space: typed prefix",
            ));
        }
        if !space_has_member(state, space_id, &session.actor) {
            return Err(event_validation_error(
                StatusCode::FORBIDDEN,
                "policy_denied",
                "actor is not a member of the event Space",
            ));
        }
    }

    if let Some(device_id) = event_string_field(object, &["device_id"])
        && device_id != session.device_id
    {
        return Err(event_validation_error(
            StatusCode::FORBIDDEN,
            "device_session_mismatch",
            "event device_id must match the bearer session device",
        ));
    }
    validate_event_audience_fields(object, state, session)?;

    let prev_refs = event_ref_list(object, "prev_refs", MAX_EVENT_PREV_REFS)?;
    let auth_refs = event_ref_list(object, "auth_refs", MAX_EVENT_AUTH_REFS)?;
    let canonical_source = event_canonical_source(envelope);
    let canonical_bytes = serde_json::to_vec(&canonical_source).map_err(|_| {
        event_validation_error(
            StatusCode::BAD_REQUEST,
            "invalid_event_envelope",
            "event envelope cannot be canonicalized",
        )
    })?;
    let canonical_digest = event_digest(&canonical_bytes);
    let provided_digest = event_string_field(object, &["canonical_digest", "canonical_hash"])
        .ok_or_else(|| {
            event_validation_error(
                StatusCode::BAD_REQUEST,
                "missing_param",
                "canonical_digest is required",
            )
        })?;
    if provided_digest != canonical_digest {
        return Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            "canonical_digest_mismatch",
            "canonical_digest does not match the Event Envelope canonical bytes",
        ));
    }
    validate_event_proofs(object, state, session, &actor_id, envelope)?;

    Ok(ValidatedEventEnvelope {
        event_id,
        actor_id,
        actor_seq,
        space_id,
        kind,
        schema_id,
        prev_refs,
        auth_refs,
        canonical_digest,
        canonical_bytes,
    })
}

fn validate_event_critical_features(
    object: &serde_json::Map<String, Value>,
) -> Result<(), EventValidationError> {
    let supported = [
        "cx.event_envelope.v1",
        "cx.event_envelope_minimal.v1",
        "cx.proof.payload_hash.v1",
    ];
    for key in ["crit", "critical", "critical_features"] {
        let Some(value) = object.get(key) else {
            continue;
        };
        let features = match value {
            Value::Array(values) => values
                .iter()
                .map(|value| value.as_str().map(ToOwned::to_owned))
                .collect::<Option<Vec<_>>>(),
            Value::String(value) => Some(vec![value.clone()]),
            _ => None,
        }
        .ok_or_else(|| {
            event_validation_error(
                StatusCode::BAD_REQUEST,
                "invalid_param",
                "critical features must be strings",
            )
        })?;
        for feature in features {
            if !supported.contains(&feature.as_str()) {
                return Err(event_validation_error(
                    StatusCode::BAD_REQUEST,
                    "unsupported_critical_feature",
                    "unknown critical Event feature is not supported",
                ));
            }
        }
    }
    Ok(())
}

fn event_schema_is_active(state: &AppState, schema_id: &str) -> bool {
    state
        .persistence
        .schemas()
        .get(schema_id)
        .ok()
        .flatten()
        .is_some_and(|schema| schema.active)
}

fn validate_event_audience_fields(
    object: &serde_json::Map<String, Value>,
    state: &AppState,
    session: &SessionRecord,
) -> Result<(), EventValidationError> {
    if let Some(audience) = event_string_field(object, &["audience"])
        && audience != state.config.service_did
    {
        return Err(event_validation_error(
            StatusCode::FORBIDDEN,
            "audience_mismatch",
            "event audience must bind to this service DID",
        ));
    }
    if let Some(domain) = event_string_field(object, &["domain"])
        && domain != state.config.service_did
    {
        return Err(event_validation_error(
            StatusCode::FORBIDDEN,
            "domain_mismatch",
            "event domain must bind to this service DID",
        ));
    }
    if let Some(device_id) = event_string_field(object, &["device_id"])
        && device_id != session.device_id
    {
        return Err(event_validation_error(
            StatusCode::FORBIDDEN,
            "device_session_mismatch",
            "event device_id must match the bearer session device",
        ));
    }
    Ok(())
}

fn validate_event_proofs(
    object: &serde_json::Map<String, Value>,
    state: &AppState,
    session: &SessionRecord,
    actor_id: &str,
    envelope: &Value,
) -> Result<(), EventValidationError> {
    let proofs = object
        .get("proofs")
        .or_else(|| object.get("signatures"))
        .and_then(Value::as_array)
        .ok_or_else(|| {
            event_validation_error(
                StatusCode::BAD_REQUEST,
                "missing_param",
                "proofs are required",
            )
        })?;
    if proofs.is_empty() {
        return Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            "missing_param",
            "proofs must contain at least one proof",
        ));
    }
    let payload_digest = event_payload_digest(envelope);
    for proof in proofs {
        let Some(proof_object) = proof.as_object() else {
            return Err(event_validation_error(
                StatusCode::BAD_REQUEST,
                "invalid_proof",
                "event proofs must be JSON objects",
            ));
        };
        let payload_hash =
            event_string_field(proof_object, &["payload_hash"]).ok_or_else(|| {
                event_validation_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_proof",
                    "proof payload_hash is required",
                )
            })?;
        if payload_hash != payload_digest {
            return Err(event_validation_error(
                StatusCode::BAD_REQUEST,
                "proof_payload_hash_mismatch",
                "proof payload_hash does not match the event payload",
            ));
        }
        validate_event_audience_fields(proof_object, state, session)?;
        if let Some(device_id) = event_string_field(proof_object, &["device_id"])
            && device_id != session.device_id
        {
            return Err(event_validation_error(
                StatusCode::FORBIDDEN,
                "device_session_mismatch",
                "proof device_id must match the bearer session device",
            ));
        }
        for key in ["verification_method", "kid", "signer"] {
            let Some(value) = event_string_field(proof_object, &[key]) else {
                continue;
            };
            if value != actor_id && !value.starts_with(&format!("{actor_id}#")) {
                return Err(event_validation_error(
                    StatusCode::FORBIDDEN,
                    "invalid_proof",
                    "proof verification method must be rooted in actor_id",
                ));
            }
        }
    }
    Ok(())
}

fn event_string_field(object: &serde_json::Map<String, Value>, keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|key| object.get(*key).and_then(Value::as_str))
        .map(ToOwned::to_owned)
}

fn event_ref_list(
    object: &serde_json::Map<String, Value>,
    key: &str,
    max_len: usize,
) -> Result<Vec<String>, EventValidationError> {
    let Some(value) = object.get(key) else {
        return Ok(Vec::new());
    };
    let Some(values) = value.as_array() else {
        return Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "event reference lists must be arrays",
        ));
    };
    if values.len() > max_len {
        return Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            "limit_exceeded",
            "event reference list exceeds the active profile limit",
        ));
    }
    values
        .iter()
        .map(|value| {
            let Some(event_id) = value.as_str() else {
                return Err(event_validation_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_param",
                    "event references must be strings",
                ));
            };
            if !is_valid_event_id(event_id) {
                return Err(event_validation_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_param",
                    "event references must use the cx:event: typed prefix",
                ));
            }
            Ok(event_id.to_owned())
        })
        .collect()
}

fn event_canonical_source(envelope: &Value) -> Value {
    let mut value = envelope.clone();
    if let Value::Object(object) = &mut value {
        object.remove("canonical_digest");
        object.remove("canonical_hash");
    }
    value
}

fn event_payload_digest(envelope: &Value) -> String {
    let payload = envelope
        .get("payload")
        .or_else(|| envelope.get("body"))
        .or_else(|| envelope.get("content"))
        .cloned()
        .unwrap_or(Value::Null);
    let bytes = serde_json::to_vec(&payload).expect("payload value serializes");
    event_digest(&bytes)
}

fn event_digest(bytes: &[u8]) -> String {
    format!("sha256:{}", sha256_hex(bytes))
}

fn is_valid_event_id(value: &str) -> bool {
    let Some(rest) = value.strip_prefix("cx:event:") else {
        return false;
    };
    !rest.is_empty()
        && value.len() <= 160
        && rest
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.' | ':'))
}

fn event_submit_response(
    state: &AppState,
    status: &str,
    event_id: String,
    canonical_digest: String,
    received_at: DateTime<Utc>,
    idempotent: bool,
) -> EventSubmitResponse {
    EventSubmitResponse {
        status: status.to_owned(),
        event_id: event_id.clone(),
        canonical_digest: canonical_digest.clone(),
        sync_token: sync_token(),
        received_at,
        receipt: json!({
            "service_did": state.config.service_did.clone(),
            "profile": "cx.profile.event_envelope_minimal.v1",
            "event_id": event_id,
            "canonical_digest": canonical_digest,
            "received_at": received_at,
            "idempotent": idempotent
        }),
    }
}

fn event_read_response(record: &CanonicalEventRecord) -> EventReadResponse {
    EventReadResponse {
        event: record.envelope.clone(),
        metadata: json!({
            "event_id": record.event_id.clone(),
            "actor_id": record.actor_id.clone(),
            "actor_seq": record.actor_seq,
            "space_id": record.space_id.clone(),
            "kind": record.kind.clone(),
            "schema_id": record.schema_id.clone(),
            "canonical_digest": record.canonical_digest.clone(),
            "received_at": record.received_at
        }),
    }
}

fn events_frontier_json(records: &[CanonicalEventRecord]) -> Value {
    let mut actors: BTreeMap<String, u64> = BTreeMap::new();
    let mut spaces: BTreeMap<String, String> = BTreeMap::new();
    for record in records {
        actors
            .entry(record.actor_id.clone())
            .and_modify(|seq| *seq = (*seq).max(record.actor_seq))
            .or_insert(record.actor_seq);
        if let Some(space_id) = record.space_id.as_deref() {
            spaces.insert(space_id.to_owned(), record.event_id.clone());
        }
    }
    json!({
        "actors": actors,
        "spaces": spaces,
        "event_count": records.len()
    })
}

fn event_visible_to_session(
    state: &AppState,
    record: &CanonicalEventRecord,
    session: &SessionRecord,
) -> bool {
    if record.actor_id == session.actor {
        return true;
    }
    record
        .space_id
        .as_deref()
        .is_some_and(|space_id| space_has_member(state, space_id, &session.actor))
}

/// C14 / read-receipts §2.5: scan the durable Event store for the most
/// recent `cx.space.read_receipt_policy` event in `space_id` and return
/// `(disclosure, visibility, scope_overrides_allowed)` from its payload.
/// Returns `None` when no policy event has been written for this Space —
/// caller treats that as the spec default `Optional` / `Members` /
/// `scope_overrides_allowed=true`.
///
/// Used by future ephemeral `cx.receipt.read` fanout handlers to enforce
/// the policy: when `disclosure="disabled"`, drop the receipt and return
/// HTTP 403 with errcode `policy_violation`. When `visibility="private"`,
/// fanout only to the original sender of the referenced event.
///
/// **Note**: this is a linear scan of the durable event store. For the
/// production fanout path it should be projected into `AppState` once the
/// reducer kind delegates from `Ignored` to a real projection.
pub fn effective_read_receipt_policy_for_space(
    state: &AppState,
    space_id: &str,
) -> Option<(String, String, bool)> {
    // C14 fast path: in-memory ProjectionState cache populated by
    // `project_read_receipt_policy` when the canonical state event lands.
    if let Ok(proj) = state.projection.lock() {
        if let Some(snapshot) = proj.read_receipt_policies.get(space_id) {
            return Some((
                snapshot.disclosure.clone(),
                snapshot.visibility.clone(),
                snapshot.scope_overrides_allowed,
            ));
        }
    }
    // Cold-path fallback: linear scan of the durable Event store. Used at
    // boot before the projection has been rehydrated, or when a server is
    // running with persistence disabled.
    let records = state.persistence.events().snapshot_all().ok()?;
    let mut latest: Option<&CanonicalEventRecord> = None;
    for record in &records {
        // CanonicalEventRecord uses `kind` (not event_kind) for the
        // canonical Contrix event kind string.
        if record.kind != "cx.space.read_receipt_policy" {
            continue;
        }
        if record.space_id.as_deref() != Some(space_id) {
            continue;
        }
        match latest {
            Some(prev) if prev.received_at >= record.received_at => {}
            _ => latest = Some(record),
        }
    }
    let record = latest?;
    // The policy state lives on the envelope payload; CanonicalEventRecord
    // stores the full envelope, so we drill down to `envelope.payload`.
    let payload = record.envelope.get("payload").and_then(Value::as_object)?;
    let disclosure = payload
        .get("disclosure")
        .and_then(Value::as_str)
        .unwrap_or("optional")
        .to_owned();
    let visibility = payload
        .get("visibility")
        .and_then(Value::as_str)
        .unwrap_or("members")
        .to_owned();
    let scope_overrides_allowed = payload
        .get("scope_overrides_allowed")
        .and_then(Value::as_bool)
        .unwrap_or(true);
    Some((disclosure, visibility, scope_overrides_allowed))
}
