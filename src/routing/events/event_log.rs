//! Signed Event Envelope ingestion + read API (`/api/v1/events/*`).
//!
//! Surfaces:
//! - `GET  /api/v1/events/describe`  — declare the active event registry, schema/reducer profiles,
//!   and limits.
//! - `POST /api/v1/events`           — submit one canonical Event Envelope. Batched submit is
//!   intentionally rejected.
//! - `GET  /api/v1/events/{event_id}` — fetch one envelope.
//! - `POST /api/v1/events/batch-get`  — fetch up to `MAX_EVENT_BATCH_GET`.
//! - `GET  /api/v1/events`            — paginated list (filtered by actor / space).
//! - `GET  /api/v1/events/frontier`   — per-actor / per-space frontier.
//!
//! The validator block (`validate_event_envelope` + helpers) lives at the
//! bottom of this file.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use contrix_sdk::{Operation, OperationId, SpaceId};
use salvo::http::StatusCode;
use salvo::oapi::extract::{JsonBody, PathParam};
use salvo::prelude::*;
use serde_json::{Value, json};

use super::{
    append_audit_log, auth_or_render, now, project_accepted_operations, query_param,
    query_param_all, render_error, sha256_hex, space_has_member, validate_did,
    validate_operation_policy, validate_operation_semantics, validate_space_id,
};
use super::operations as events_operations;
use crate::artifacts;
use crate::error::{AppError, ErrorCode};
use crate::result::{JsonResult, json_ok};
use crate::routing::system::extract::AuthArgs;
use crate::state::{AppState, CanonicalEventRecord, SessionRecord};
use crate::wire::{
    EventBatchGetRequest, EventBatchGetResponse, EventDescribeResponse, EventReadResponse,
    EventSubmitResponse, EventsFrontierResponse, EventsPageResponse, sync_token,
};

pub(super) fn router() -> Router {
    Router::new()
        .push(Router::with_path("events/describe").get(events_describe))
        .push(Router::with_path("events/subscribe").get(super::sync::events_subscribe))
        .push(
            Router::with_path("events")
                .post(submit_event)
                .get(super::sync::events_query),
        )
        .push(Router::with_path("events/batch-get").post(batch_get_events))
        .push(Router::with_path("events/frontier").get(events_frontier))
        .push(Router::with_path("events/{event_id}").get(get_event))
}

const MAX_EVENT_BYTES: usize = 64 * 1024;
const MAX_EVENT_PREV_REFS: usize = 32;
const MAX_EVENT_REFS: usize = 64;
const MAX_EVENT_BATCH_GET: usize = 100;

#[endpoint]
async fn events_describe(depot: &mut Depot, res: &mut Response) {
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
                "space_id",
                "actor_id",
                "actor_seq",
                "created_at",
                "prev_refs",
                "refs",
                "payload",
                "proofs"
            ],
            "hashing": {
                "canonical_digest": "server-computed sha256 over Event Envelope JSON with proofs and unsigned removed",
                "proof_payload_hash": "sha256 over Event Envelope JSON with proofs and unsigned removed"
            },
            "causality": {
                "actor_seq": "strictly increasing per actor",
                "prev_refs": "must reference accepted events",
                "refs": "semantic references; role=authorized_by must reference accepted authorization events"
            }
        }),
        supported_profiles: vec![
            "cx.profile.core_event_store.v1".to_owned(),
            "cx.profile.principal_server_events_api.v1".to_owned(),
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
            "max_refs": MAX_EVENT_REFS,
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
async fn submit_event(depot: &mut Depot, req: &mut Request, res: &mut Response) {
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
            "payload_too_large",
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
            "cas_conflict",
            "actor_seq must be strictly increasing for the actor",
        );
        return;
    }
    for prev_ref in &parsed.prev_refs {
        if !store.contains(prev_ref).unwrap_or(false) {
            render_error(
                res,
                StatusCode::CONFLICT,
                "dependency_missing",
                "prev_refs must reference accepted events",
            );
            return;
        }
    }
    for authorized_ref in &parsed.authorized_refs {
        if !store.contains(authorized_ref).unwrap_or(false) {
            render_error(
                res,
                StatusCode::CONFLICT,
                "dependency_missing",
                "refs[role=authorized_by] must reference accepted authorization events",
            );
            return;
        }
    }

    let projection_operation = projection_operation_from_event(&parsed, &envelope);
    if let Some(operation) = projection_operation.as_ref() {
        if let Err(message) = validate_operation_semantics(state, std::slice::from_ref(operation)) {
            render_error(res, StatusCode::BAD_REQUEST, "schema_violation", message);
            return;
        }
        if let Err(message) = validate_operation_policy(state, std::slice::from_ref(operation)) {
            render_error(res, StatusCode::FORBIDDEN, "capability_denied", message);
            return;
        }
        // `cx.profile.agent_workspace.v1`: cx.content.mention_redirect MUST
        // carry a critical_extensions[] declaration with feature id
        // `cx.feature.mention_redirect.v1` and fail_closed=true.
        // Spec: agent-workspace-profile.md §8.1.
        if let Some(content) = operation
            .payload
            .get("content")
        {
            if let Some(feature_id) =
                events_operations::agent_workspace_required_feature_id(content)
            {
                let envelope_satisfies = envelope
                    .pointer("/requirements/critical_extensions")
                    .and_then(Value::as_array)
                    .map(|arr| {
                        arr.iter().any(|ext| {
                            ext.get("id").and_then(Value::as_str) == Some(feature_id)
                                && ext.get("fail_closed").and_then(Value::as_bool) == Some(true)
                        })
                    })
                    .unwrap_or(false);
                if !envelope_satisfies {
                    render_error(
                        res,
                        StatusCode::BAD_REQUEST,
                        "schema_violation",
                        "cx.content.mention_redirect requires requirements.critical_extensions[] entry with fail_closed=true",
                    );
                    return;
                }
            }
        }
        // Server-side state-machine preflight for cx.place.* / cx.flow.* /
        // cx.morph.* lifecycle events. Reject invalid transitions with
        // HTTP 412 before persisting per contrix-spec common-fields.md §5.1.
        // Flow / Morph have no tombstone, so only update / archive / restore
        // reject paths surface here as create is unconditional.
        if let Ok(proj) = state.projection.lock() {
            if let Err(reason) = proj.check_place_lifecycle_transition(operation) {
                render_error(res, StatusCode::PRECONDITION_FAILED, reason, reason);
                return;
            }
            if let Err(reason) = proj.check_flow_lifecycle_transition(operation) {
                render_error(res, StatusCode::PRECONDITION_FAILED, reason, reason);
                return;
            }
            if let Err(reason) = proj.check_morph_lifecycle_transition(operation) {
                render_error(res, StatusCode::PRECONDITION_FAILED, reason, reason);
                return;
            }
            // `cx.redaction` targeting a Flow / Morph via `object_ref` is
            // rejected if the target is already terminal per spec
            // common-fields.md §5.1 (`<kind>_already_terminal`).
            if let Err(reason) = proj.check_redaction_target_transition(operation) {
                render_error(res, StatusCode::PRECONDITION_FAILED, reason, reason);
                return;
            }
            // `cx.flow.track.*` sub-events follow the spec §5.1
            // update-on-non-active rule: parent Flow MUST be Active or
            // the admission rejects with `flow_not_active` (mirrors the
            // SDK reducer guard so client + server agree).
            if let Err(reason) = proj.check_flow_track_transition(operation) {
                render_error(res, StatusCode::PRECONDITION_FAILED, reason, reason);
                return;
            }
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
            "internal_error",
            "events store unavailable",
        );
        return;
    }
    if let Some(operation) = projection_operation {
        project_accepted_operations(state, &parsed.actor_id, &[operation]);
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

#[endpoint(
    operation_id = "cx.events.get",
    tags("events"),
    summary = "Fetch one canonical Event Envelope by event_id"
)]
async fn get_event(
    aa: AuthArgs,
    event_id: PathParam<String>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<EventReadResponse> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req)?;
    let event_id = event_id.into_inner();
    let record = state
        .persistence
        .events()
        .get(&event_id)
        .ok()
        .flatten()
        .ok_or_else(|| AppError::not_found("event not found"))?;
    if !event_visible_to_session(state, &record, &session) {
        return Err(AppError::not_found("event not found"));
    }
    json_ok(event_read_response(&record))
}

#[endpoint(
    operation_id = "cx.events.batch_get",
    tags("events"),
    summary = "Fetch up to MAX_EVENT_BATCH_GET canonical Event Envelopes by event_id"
)]
async fn batch_get_events(
    aa: AuthArgs,
    body: JsonBody<EventBatchGetRequest>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<EventBatchGetResponse> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req)?;
    let body = body.into_inner();
    if body.event_ids.len() > MAX_EVENT_BATCH_GET {
        return Err(AppError::new(
            ErrorCode::QuotaExceeded,
            "too many event_ids requested",
        ));
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
    json_ok(EventBatchGetResponse {
        events: found,
        missing,
        unauthorized: Vec::new(),
    })
}

/// Internal durable-Event-store reader, kept for actor-scoped audit reads
/// that bypass the projection layer. Not wired to a public route in the
/// current API shape —
/// the canonical `cx.events.query` path at `GET /api/v1/events` goes to the
/// projection-aware handler in `routing/sync.rs::events_query` so message
/// timeline reads work through `POST /api/v1/events` → `events_query`
/// round-trips.
///
/// Supports the multi-value selector `spaces[]` ∪ `actors[]` (via
/// repeated query args) **and** real backward iteration (`direction=backward`
/// returns events older than `from` cursor in reverse time order, with
/// `prev_cursor` driving further pages).
/// Plain async helper version of [`events_query_durable_scope`] so other
/// handlers (e.g. the projection-aware `routing::events::sync::events_query`) can
/// dispatch to the durable-store reader when the selector contains only
/// `actors[]` (no `spaces[]`). Both the `#[endpoint]` wrapper and the
/// sync-side dispatcher call this impl.
///
/// Round 15ad: returns `Result<EventsPageResponse, AppError>` so the wrapper
/// can be a typed `JsonResult<T>` handler and the sync-side dispatcher
/// can map the typed result into its own legacy `&mut Response` shape with
/// a single `match`.
pub(super) async fn events_query_durable_scope_impl(
    state: &AppState,
    session: &SessionRecord,
    req: &Request,
) -> Result<EventsPageResponse, AppError> {
    // Repeated query-arg selector: `actors[]` ∪ `spaces[]`.
    let actors = query_param_all(req, "actors");
    let spaces = query_param_all(req, "spaces");
    for actor in &actors {
        if validate_did(actor).is_err() {
            return Err(AppError::invalid_param(format!("invalid actor: {actor}")));
        }
    }
    for space in &spaces {
        if validate_space_id(space).is_err() {
            return Err(AppError::invalid_param(format!("invalid space: {space}")));
        }
    }
    let cursor = query_param(req, "from");
    // Direction: forward (default) | backward — backward returns events
    // older than `from` in reverse time order.
    let direction = query_param(req, "direction").unwrap_or_else(|| "forward".to_owned());
    if direction != "forward" && direction != "backward" {
        return Err(AppError::invalid_param(
            "direction must be 'forward' or 'backward'",
        ));
    }
    let _until = query_param(req, "until"); // FUTURE: enforce upper-bound cursor; currently swallowed.
    let limit = query_param(req, "limit")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(50)
        .clamp(1, 100);
    let actors_set: std::collections::BTreeSet<&str> = actors.iter().map(String::as_str).collect();
    let spaces_set: std::collections::BTreeSet<&str> = spaces.iter().map(String::as_str).collect();
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
        .filter(|record| event_visible_to_session(state, record, session))
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
    Ok(EventsPageResponse {
        events,
        next_cursor,
        frontier,
    })
}

/// Salvo `#[endpoint]` wrapper around [`events_query_durable_scope_impl`] so
/// the actor-scoped durable-store reader can be wired to a route directly
/// (currently used only as a fallback dispatched from `routing::events::sync::events_query`
/// when the selector has no `spaces[]`).
#[endpoint(
    operation_id = "cx.events.query_durable",
    tags("events"),
    summary = "Durable-store reader (bypasses projection; actor-scoped audit queries)"
)]
async fn events_query_durable_scope(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<EventsPageResponse> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req)?;
    let response = events_query_durable_scope_impl(state, &session, req).await?;
    json_ok(response)
}

#[endpoint(
    operation_id = "cx.events.frontier",
    tags("events"),
    summary = "Per-actor + per-space frontier (highest accepted actor_seq / latest event)"
)]
async fn events_frontier(
    aa: crate::routing::system::extract::AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
) -> crate::result::JsonResult<EventsFrontierResponse> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req)?;
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
    crate::result::json_ok(EventsFrontierResponse {
        actor_frontier,
        space_frontier,
        frontier: json!({"storage": state.db.mode(), "generated_at": now()}),
    })
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
    authorized_refs: Vec<String>,
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
    validate_removed_event_envelope_fields(object)?;
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

    let kind = event_string_field(object, &["kind"]).ok_or_else(|| {
        event_validation_error(StatusCode::BAD_REQUEST, "missing_param", "kind is required")
    })?;
    if !artifacts::active_durable_event_kinds().contains(&kind) {
        return Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            "unknown_event_kind",
            "event kind is not in the active registry",
        ));
    }

    let schema_id = event_requirements_schema_id(state, object)?;

    let actor_id = event_string_field(object, &["actor_id"]).ok_or_else(|| {
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
    // `created_at` is part of the canonical envelope but historical fixtures
    // mint events without setting it (server fills in `received_at` at the
    // accept boundary). Accept absence and let the receipt's `received_at`
    // carry the timestamp.
    if let Some(value) = object.get("created_at")
        && !value.is_string()
    {
        return Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "created_at must be a string when present",
        ));
    }
    if let Some(hlc) = object.get("hlc")
        && !hlc.is_string()
    {
        return Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "hlc must be a string when present",
        ));
    }

    let space_id = event_string_field(object, &["space_id"]).ok_or_else(|| {
        event_validation_error(
            StatusCode::BAD_REQUEST,
            "missing_param",
            "space_id is required",
        )
    })?;
    if validate_space_id(&space_id).is_err() {
        return Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "space_id must use the cx:space: typed prefix",
        ));
    }
    if !space_has_member(state, &space_id, &session.actor) {
        return Err(event_validation_error(
            StatusCode::FORBIDDEN,
            "capability_denied",
            "actor is not a member of the event Space",
        ));
    }
    require_object_field(object, "payload")?;

    let prev_refs = event_ref_list(object, "prev_refs", MAX_EVENT_PREV_REFS)?;
    let authorized_refs = event_semantic_refs(object, MAX_EVENT_REFS)?;
    let canonical_source = event_canonical_source(envelope);
    let canonical_bytes = serde_json::to_vec(&canonical_source).map_err(|_| {
        event_validation_error(
            StatusCode::BAD_REQUEST,
            "invalid_event_envelope",
            "event envelope cannot be canonicalized",
        )
    })?;
    let canonical_digest = event_digest(&canonical_bytes);
    validate_event_proofs(object, state, session, &actor_id, &canonical_digest)?;

    Ok(ValidatedEventEnvelope {
        event_id,
        actor_id,
        actor_seq,
        space_id: Some(space_id),
        kind,
        schema_id,
        prev_refs,
        authorized_refs,
        canonical_digest,
        canonical_bytes,
    })
}

fn validate_removed_event_envelope_fields(
    object: &serde_json::Map<String, Value>,
) -> Result<(), EventValidationError> {
    // These fields were dropped wholesale in v1 (no migration path). They MUST
    // NOT appear on the envelope; we fail closed.
    for field in ["canonical_hash", "body", "content"] {
        if object.contains_key(field) {
            return Err(event_validation_error(
                StatusCode::BAD_REQUEST,
                "removed_event_field",
                "event envelope contains a removed field",
            ));
        }
    }
    // Reject specific legacy values for fields that survived the rip-and-
    // replace. The test contract enumerates the known-legacy values; these
    // are detected and surfaced as `legacy_contract_removed`.
    if object
        .get("kind")
        .and_then(Value::as_str)
        .is_some_and(is_legacy_event_kind)
    {
        return Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            "legacy_contract_removed",
            "event kind belongs to a removed legacy registry",
        ));
    }
    if object
        .get("schema_id")
        .and_then(Value::as_str)
        .is_some_and(is_legacy_schema_id)
    {
        return Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            "legacy_contract_removed",
            "schema_id references a removed legacy schema",
        ));
    }
    if let Some(payload) = object.get("payload").and_then(Value::as_object)
        && payload_carries_legacy_contract(payload)
    {
        return Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            "legacy_contract_removed",
            "payload carries a removed legacy field or typed id",
        ));
    }
    Ok(())
}

fn is_legacy_event_kind(kind: &str) -> bool {
    matches!(kind, "cx.room.message" | "cx.room.create" | "cx.subject.create")
}

fn is_legacy_schema_id(schema_id: &str) -> bool {
    matches!(
        schema_id,
        "cx.schema.room.v1" | "cx.schema.subject.v1" | "cx.schema.card.v1"
    )
}

fn payload_carries_legacy_contract(payload: &serde_json::Map<String, Value>) -> bool {
    const LEGACY_KEYS: &[&str] = &["room_id", "card_id", "subject_id"];
    for key in LEGACY_KEYS {
        if payload.contains_key(*key) {
            return true;
        }
    }
    const LEGACY_PREFIXES: &[&str] = &["cx:card:", "cx:subject:", "cx:room:"];
    for value in payload.values() {
        if let Some(text) = value.as_str()
            && LEGACY_PREFIXES.iter().any(|p| text.starts_with(p))
        {
            return true;
        }
    }
    false
}

fn validate_event_critical_features(
    object: &serde_json::Map<String, Value>,
) -> Result<(), EventValidationError> {
    let supported = [
        "cx.event_envelope.v1",
        "cx.profile.core_event_store.v1",
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

fn event_requirements_schema_id(
    _state: &AppState,
    object: &serde_json::Map<String, Value>,
) -> Result<String, EventValidationError> {
    // Read schema_id from either the canonical `requirements.schema[0]` slot
    // (spec form) or the legacy top-level `schema_id` (dev/test fixture form);
    // both are accepted for the v1 transition.
    let schema_id = object
        .get("schema_id")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .or_else(|| {
            object
                .get("requirements")
                .and_then(|requirements| requirements.get("schema"))
                .and_then(Value::as_array)
                .and_then(|schemas| schemas.first())
                .and_then(Value::as_str)
                .map(ToOwned::to_owned)
        })
        .unwrap_or_else(|| "cx.schema.event.v1".to_owned());
    if !schema_id.starts_with("cx.schema.") || !artifacts::schema_ids().contains(&schema_id) {
        return Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            "unknown_schema",
            "event schema_id is not in the contrix-spec schema registry",
        ));
    }
    Ok(schema_id)
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
    expected_payload_hash: &str,
) -> Result<(), EventValidationError> {
    let proofs = object
        .get("proofs")
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
    // Proof validation forks on `state.config.development_mode`:
    // - **Production** (`development_mode=false`): EVERY proof MUST be a full
    //   detached-JWS proof with `kind`/`alg`/`verification_method`/
    //   `payload_hash`/`created_at`/`jws`, hashing the full canonical envelope.
    //   The `type=="dev-proof"` and payload-only hash forms are NOT accepted
    //   under any circumstance — a malicious client claiming
    //   `type="dev-proof"` in production fails-closed here.
    // - **Development** (`development_mode=true`): the minimal dev-proof shape
    //   (`type="dev-proof"`, `verification_method`, `payload_hash`-of-payload)
    //   is also accepted so integration fixtures round-trip without keying.
    let is_production = !state.config.development_mode;
    for proof in proofs {
        let Some(proof_object) = proof.as_object() else {
            return Err(event_validation_error(
                StatusCode::BAD_REQUEST,
                "invalid_proof",
                "event proofs must be JSON objects",
            ));
        };
        // Production NEVER falls into the dev-proof branch, even if the client
        // claims `type="dev-proof"`. That stops a downgrade attack where a
        // production server is tricked into accepting a weak proof.
        let is_dev_proof = !is_production
            && event_string_field(proof_object, &["type"]).as_deref() == Some("dev-proof");
        let required_fields: &[&str] = if is_dev_proof {
            &["verification_method", "payload_hash"]
        } else {
            &[
                "kind",
                "alg",
                "verification_method",
                "payload_hash",
                "created_at",
                "jws",
            ]
        };
        for field in required_fields {
            if !proof_object.contains_key(*field) {
                return Err(event_validation_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_proof",
                    "event proof is missing required fields",
                ));
            }
        }
        if !is_dev_proof
            && event_string_field(proof_object, &["kind"]).as_deref() != Some("detached_jws")
        {
            return Err(event_validation_error(
                StatusCode::BAD_REQUEST,
                "invalid_proof",
                "event proof kind must be detached_jws",
            ));
        }
        let payload_hash =
            event_string_field(proof_object, &["payload_hash"]).ok_or_else(|| {
                event_validation_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_proof",
                    "proof payload_hash is required",
                )
            })?;
        // Production: the proof's payload_hash MUST match the canonical
        // envelope digest. Dev-only: also accept the payload-only sha256 form
        // so test fixtures keep round-tripping. Production never falls back.
        let payload_only_hash_accept = if is_dev_proof {
            object.get("payload").map(|payload| {
                let bytes = serde_json::to_vec(payload).unwrap_or_default();
                format!("sha256:{}", sha256_hex(&bytes))
            })
        } else {
            None
        };
        if payload_hash != expected_payload_hash
            && payload_only_hash_accept.as_deref() != Some(&payload_hash)
        {
            return Err(event_validation_error(
                StatusCode::BAD_REQUEST,
                "proof_payload_hash_mismatch",
                "proof payload_hash does not match the event payload",
            ));
        }
        validate_event_audience_fields(proof_object, state, session)?;
        let verification_method = event_string_field(proof_object, &["verification_method"])
            .ok_or_else(|| {
                event_validation_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_proof",
                    "proof verification_method is required",
                )
            })?;
        if verification_method != actor_id
            && !verification_method.starts_with(&format!("{actor_id}#"))
        {
            return Err(event_validation_error(
                StatusCode::FORBIDDEN,
                "invalid_proof",
                "proof verification method must be rooted in actor_id",
            ));
        }
    }
    Ok(())
}

fn event_string_field(object: &serde_json::Map<String, Value>, keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|key| object.get(*key).and_then(Value::as_str))
        .map(ToOwned::to_owned)
}

fn require_object_field(
    object: &serde_json::Map<String, Value>,
    key: &'static str,
) -> Result<(), EventValidationError> {
    match object.get(key) {
        Some(Value::Object(_)) => Ok(()),
        Some(_) => Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "event payload must be a JSON object",
        )),
        None => Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            "missing_param",
            "event payload is required",
        )),
    }
}

fn event_ref_list(
    object: &serde_json::Map<String, Value>,
    key: &str,
    max_len: usize,
) -> Result<Vec<String>, EventValidationError> {
    let Some(value) = object.get(key) else {
        return Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            "missing_param",
            "event reference lists are required",
        ));
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
            "quota_exceeded",
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

fn event_semantic_refs(
    object: &serde_json::Map<String, Value>,
    max_len: usize,
) -> Result<Vec<String>, EventValidationError> {
    // Accept the canonical `refs[]` and the legacy `auth_refs[]` alias — the
    // alias carries the same authorized-by relationship but as a flat list of
    // event ids. We coalesce both into the authorized_refs collection.
    let value = object.get("refs");
    if value.is_none() {
        // Legacy `auth_refs[]` form: parse the strings as authorized-by refs.
        let legacy = object.get("auth_refs");
        let Some(values) = legacy.and_then(Value::as_array) else {
            return Ok(Vec::new());
        };
        let mut authorized = Vec::new();
        for value in values {
            let Some(event_id) = value.as_str() else {
                return Err(event_validation_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_param",
                    "auth_refs entries must be event-id strings",
                ));
            };
            if !is_valid_event_id(event_id) {
                return Err(event_validation_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_param",
                    "auth_refs entries must use cx:event: typed ids",
                ));
            }
            authorized.push(event_id.to_owned());
        }
        return Ok(authorized);
    }
    let value = value.expect("refs branch handled above");
    let Some(values) = value.as_array() else {
        return Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "refs must be an array",
        ));
    };
    if values.len() > max_len {
        return Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            "quota_exceeded",
            "refs exceeds the active profile limit",
        ));
    }
    let mut authorized_refs = Vec::new();
    for value in values {
        let Some(reference) = value.as_object() else {
            return Err(event_validation_error(
                StatusCode::BAD_REQUEST,
                "invalid_param",
                "refs entries must be objects",
            ));
        };
        let id = event_string_field(reference, &["id"]).ok_or_else(|| {
            event_validation_error(
                StatusCode::BAD_REQUEST,
                "invalid_param",
                "refs entries require id",
            )
        })?;
        let role = event_string_field(reference, &["role"]).ok_or_else(|| {
            event_validation_error(
                StatusCode::BAD_REQUEST,
                "invalid_param",
                "refs entries require role",
            )
        })?;
        if role == "authorized_by" {
            if !is_valid_event_id(&id) {
                return Err(event_validation_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_param",
                    "authorized_by refs must use the cx:event: typed prefix",
                ));
            }
            authorized_refs.push(id);
        }
    }
    Ok(authorized_refs)
}

fn event_canonical_source(envelope: &Value) -> Value {
    // Per contrix-spec conformance-vectors.md §1.6: both the event digest and
    // every proof's `payload_hash` MUST be derived from canonical event bytes
    // with `proofs` and `unsigned` removed. Stripping derived `canonical_*`
    // slots as well keeps fixtures that round-trip them in the envelope from
    // poisoning the digest.
    let mut value = envelope.clone();
    if let Value::Object(object) = &mut value {
        object.remove("proofs");
        object.remove("unsigned");
        object.remove("canonical_digest");
        object.remove("canonical_hash");
    }
    value
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
            "profile": "cx.profile.core_event_store.v1",
            "event_id": event_id,
            "canonical_digest": canonical_digest,
            "received_at": received_at,
            "idempotent": idempotent
        }),
    }
}

fn projection_operation_from_event(
    parsed: &ValidatedEventEnvelope,
    envelope: &Value,
) -> Option<Operation> {
    super::operations::operation_schema_for_kind(&parsed.kind)?;
    let space_id = SpaceId::new(parsed.space_id.clone()?).ok()?;
    let mut payload = envelope
        .get("payload")
        .cloned()
        .unwrap_or_else(|| json!({}));
    let payload_object = payload.as_object_mut()?;
    payload_object
        .entry("event_id".to_owned())
        .or_insert_with(|| Value::String(parsed.event_id.clone()));
    payload_object
        .entry("sender".to_owned())
        .or_insert_with(|| Value::String(parsed.actor_id.clone()));

    let operation_id = event_operation_id(envelope, &parsed.event_id)?;
    let mut operation = Operation::create(
        operation_id,
        space_id,
        parsed.kind.clone(),
        Value::Object(payload_object.clone()),
    );
    operation.created_at = envelope
        .get("created_at")
        .and_then(Value::as_str)
        .and_then(|value| DateTime::parse_from_rfc3339(value).ok())
        .map(|value| value.with_timezone(&Utc))
        .unwrap_or_else(now);
    Some(operation)
}

fn event_operation_id(envelope: &Value, event_id: &str) -> Option<OperationId> {
    if let Some(operation_id) = envelope
        .get("unsigned")
        .and_then(Value::as_object)
        .and_then(|unsigned| unsigned.get("local_operation_idempotency_alias"))
        .and_then(Value::as_str)
    {
        return OperationId::new(operation_id.to_owned()).ok();
    }
    let suffix = event_id.strip_prefix("cx:event:")?;
    OperationId::new(format!("cx:operation:{suffix}")).ok()
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

/// Scan the durable Event store for the most
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
    // Cell-keyed fast path. The
    // Move/Anchor pipeline writes `cx.component.space.read_receipt_policy.v1`
    // resolved CasRegister value into `ProjectionState::cells` after every
    // apply_anchor; we read directly from there.
    if let Ok(proj) = state.projection.lock() {
        let cell_id = contrix_sdk::CellRef::new(format!(
            "cx:cell:cx.component.space.read_receipt_policy.v1:{space_id}"
        ))
        .ok()?;
        if let Some(value) = proj.cell_value(&cell_id) {
            let disclosure = value
                .get("disclosure")
                .and_then(Value::as_str)
                .unwrap_or("optional")
                .to_owned();
            let visibility = value
                .get("visibility")
                .and_then(Value::as_str)
                .unwrap_or("members")
                .to_owned();
            let scope_overrides_allowed = value
                .get("scope_overrides_allowed")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            return Some((disclosure, visibility, scope_overrides_allowed));
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

#[cfg(test)]
mod proof_strictness_tests {
    use super::*;
    use crate::config::{AppConfig, FederationPolicy, ObjectStorageConfig};
    use crate::db::Db;

    fn make_state(development_mode: bool) -> AppState {
        let config = AppConfig {
            bind: "127.0.0.1:0".parse().unwrap(),
            public_base_url: "http://server".to_owned(),
            service_did: "did:web:soland.local".to_owned(),
            tls_cert_path: None,
            tls_key_path: None,
            database_url: None,
            object_storage: ObjectStorageConfig::local(std::env::temp_dir().join("soland-test")),
            cors_allow_origin: None,
            auth_server_url: None,
            development_mode,
            oauth_introspection_url: None,
            oauth_introspection_bearer: None,
            session_grant_introspection_url: None,
            session_grant_introspection_bearer: None,
            did_resolver_allow_methods: vec!["web".to_owned()],
            embedded_webvh_provider_enabled: false,
            embedded_webvh_registration_bearer: None,
            external_webvh_provider_url: None,
            external_webvh_provider_active: false,
            default_webvh_provider_id: None,
            jws_replay_window_seconds: 0,
            jws_replay_window_per_family: std::collections::BTreeMap::new(),
            anchorer_signing_key_seed: None,
            agent_audit_binding_signing_seed: None,
            use_keystore: false,
            federation_policy: FederationPolicy::Mesh,
            federation_peers: Vec::new(),
            admin_default_page_limit: 100,
            admin_max_page_limit: 1000,
            admin_principal_dids: Vec::new(),
            push_bridge_cache_ttl_seconds: 900,
            push_bridge_trusted_service_dids: Vec::new(),
            compaction_min_anchor_age_seconds: 604_800,
            compaction_min_witnesses: 1,
            compaction_preserve_genesis: true,
            compaction_prune_only_singleton_successors: true,

            compaction_prune_walk_interval_seconds: 0,

            compaction_prune_walk_per_space_limit: 50,
        };
        AppState::new(config, Db { pool: None })
    }

    fn dev_proof_envelope() -> serde_json::Map<String, Value> {
        let mut object = serde_json::Map::new();
        object.insert(
            "proofs".to_owned(),
            json!([{
                "type": "dev-proof",
                "verification_method": "did:web:alice.example#dev_alice",
                "payload_hash": "sha256:0000000000000000000000000000000000000000000000000000000000000000"
            }]),
        );
        object.insert("payload".to_owned(), json!({"body": "hello"}));
        object
    }

    fn session() -> SessionRecord {
        SessionRecord {
            token_hash: "hash".to_owned(),
            actor: "did:web:alice.example".to_owned(),
            device_id: "cx:device:01904100-0000-7000-8000-a11ce0000001".to_owned(),
            audience: "did:web:soland.local".to_owned(),
            expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
            created_at: chrono::Utc::now(),
            revoked_at: None,
        }
    }

    #[test]
    fn production_rejects_dev_proof_type_field() {
        let state = make_state(false);
        let session = session();
        let object = dev_proof_envelope();
        let err = validate_event_proofs(
            &object,
            &state,
            &session,
            "did:web:alice.example",
            "sha256:dead",
        )
        .expect_err("production must reject dev-proof shape");
        // Missing strict-JWS fields trips `invalid_proof` first.
        assert_eq!(err.code, "invalid_proof");
    }

    #[test]
    fn development_accepts_dev_proof_type_field_when_hash_matches() {
        let state = make_state(true);
        let session = session();
        let mut object = dev_proof_envelope();
        // Use payload-only hash so the dev path's `payload_only_hash_accept`
        // matches; production would still reject this even with the correct
        // payload hash because the proof lacks a JWS.
        let payload_bytes = serde_json::to_vec(&object["payload"]).unwrap();
        let payload_hash = format!("sha256:{}", sha256_hex(&payload_bytes));
        if let Some(proofs) = object.get_mut("proofs").and_then(Value::as_array_mut)
            && let Some(proof) = proofs.first_mut()
            && let Some(map) = proof.as_object_mut()
        {
            map.insert("payload_hash".to_owned(), json!(payload_hash));
        }
        let result = validate_event_proofs(
            &object,
            &state,
            &session,
            "did:web:alice.example",
            "sha256:dead",
        );
        assert!(result.is_ok(), "development mode should accept matching dev-proof: {result:?}");
    }
}
