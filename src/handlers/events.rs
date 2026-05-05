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

#[handler]
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
            "source": "contrix-spec/artifacts",
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

#[handler]
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
    let mut events = state.events.lock().expect("events lock");
    if let Some(existing) = events.get(&parsed.event_id) {
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
        drop(events);
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
    if let Some(max_seq) = events
        .values()
        .filter(|record| record.actor_id == parsed.actor_id)
        .map(|record| record.actor_seq)
        .max()
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
        if !events.contains_key(prev_ref) {
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
        if !events.contains_key(auth_ref) {
            render_error(
                res,
                StatusCode::CONFLICT,
                "missing_auth_ref",
                "auth_refs must reference accepted authorization events",
            );
            return;
        }
    }

    events.insert(
        parsed.event_id.clone(),
        CanonicalEventRecord {
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
        },
    );
    drop(events);
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

#[handler]
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
    let events = state.events.lock().expect("events lock");
    let Some(record) = events.get(&event_id) else {
        render_error(res, StatusCode::NOT_FOUND, "not_found", "event not found");
        return;
    };
    if !event_visible_to_session(state, record, &session) {
        render_error(res, StatusCode::NOT_FOUND, "not_found", "event not found");
        return;
    }
    res.render(Json(event_read_response(record)));
}

#[handler]
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
    let events = state.events.lock().expect("events lock");
    let mut found = Vec::new();
    let mut missing = Vec::new();
    for event_id in body.event_ids {
        match events.get(&event_id) {
            Some(record) if event_visible_to_session(state, record, &session) => {
                found.push(event_read_response(record));
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

#[handler]
pub async fn list_events(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(session) = auth_or_render(state, req, res) else {
        return;
    };
    let actor_id = query_param(req, "actor_id");
    let space_id = query_param(req, "space_id");
    if let Some(actor_id) = actor_id.as_deref()
        && validate_did(actor_id).is_err()
    {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "invalid actor_id",
        );
        return;
    }
    if let Some(space_id) = space_id.as_deref()
        && validate_space_id(space_id).is_err()
    {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "invalid space_id",
        );
        return;
    }
    let cursor = query_param(req, "cursor");
    let limit = query_param(req, "limit")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(50)
        .clamp(1, 100);
    let events = state.events.lock().expect("events lock");
    let mut records = events
        .values()
        .filter(|record| {
            actor_id
                .as_deref()
                .is_none_or(|actor| actor == record.actor_id)
        })
        .filter(|record| space_id.as_deref() == record.space_id.as_deref() || space_id.is_none())
        .filter(|record| event_visible_to_session(state, record, &session))
        .cloned()
        .collect::<Vec<_>>();
    records.sort_by(|left, right| {
        left.received_at
            .cmp(&right.received_at)
            .then_with(|| left.event_id.cmp(&right.event_id))
    });
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

#[handler]
pub async fn events_frontier(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(session) = auth_or_render(state, req, res) else {
        return;
    };
    let actor_id = query_param(req, "actor_id");
    let space_id = query_param(req, "space_id");
    let events = state.events.lock().expect("events lock");
    let mut actor_frontier: BTreeMap<String, u64> = BTreeMap::new();
    let mut space_frontier: BTreeMap<String, Value> = BTreeMap::new();
    for record in events.values() {
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
        .schemas
        .lock()
        .expect("schemas lock")
        .get(schema_id)
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
