//! Signed Event Envelope ingestion + read API (`/_cokret/self/events/*`).
//!
//! Surfaces:
//! - `GET  /_cokret/self/events/describe`  — declare the active event registry, schema/reducer
//!   profiles, and limits.
//! - `POST /_cokret/self/events`           — submit one canonical Event Envelope or an `events[]`
//!   account-client batch.
//! - `GET  /_cokret/self/events/{event_id}` — fetch one envelope.
//! - `POST /_cokret/self/events/resolve`    — resolve up to `MAX_EVENT_RESOLVE`.
//! - `GET  /_cokret/self/events`            — paginated list (filtered by actor / realm).
//! - `GET  /_cokret/self/events/frontier`   — per-actor / per-realm frontier.
//!
//! The validator block (`validate_event_envelope` + helpers) lives at the
//! bottom of this file.

use std::collections::BTreeMap;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Duration, Utc};
use cokret_sdk::http::{
    EventView, EventsQueryOutcome, EventsResolveOutcome, EventsResolveRequestBody,
    EventsSubmitOutcome, EventsSubmitStatus,
};
use cokret_sdk::{
    Audience, Event, EventId, EventRef, EventsSubmitFederationRequestBody, Hash, Hlc, Operation,
    OperationId, Proof, RealmId, TypedTrustDomainId, canonical, proof_kind,
};
use ed25519_dalek::Verifier as _;
use salvo::http::StatusCode;
use salvo::oapi::extract::{JsonBody, PathParam};
use salvo::prelude::*;
use serde_json::{Value, json};

use super::projection::{retention_tombstone_for_event, retention_tombstone_payload_value};
use super::{
    append_audit_log, auth_or_render, is_valid_sha256_digest, now, query_param, query_param_all,
    realm_allows_plaintext_service, realm_event_visible_to_session, realm_has_member, render_error,
    sha256_hex, validate_agent_participation_ceiling, validate_agent_reply_participation,
    validate_content_encryption_floor, validate_did, validate_operation_policy,
    validate_operation_semantics, validate_space_id,
};
use crate::error::{AppError, ErrorCode, error_http_status};
use crate::result::{JsonResult, json_ok};
use crate::routing::organizations;
use crate::routing::policy_gate::{self, PolicyGateSurface};
use crate::routing::system::extract::AuthArgs;
use crate::state::{AppState, CanonicalEventRecord, SessionRecord};
use crate::wire::{SolandEventsFrontierState, describe};
use crate::{artifacts, kinds};

pub(super) fn router() -> Router {
    Router::new()
        .push(Router::with_path("events/describe").get(events_describe))
        .push(Router::with_path("events/subscribe").get(super::sync::events_subscribe))
        .push(
            Router::with_path("events")
                .post(submit_event)
                .get(super::sync::events_query),
        )
        .push(Router::with_path("events/query").post(super::sync::events_query_post))
        .push(Router::with_path("events/resolve").post(resolve_events))
        .push(Router::with_path("events/frontier").get(events_frontier))
        .push(Router::with_path("events/{event_id}").get(get_event))
}

const MAX_EVENT_BYTES: usize = 64 * 1024;
const MAX_EVENT_PREV_REFS: usize = 32;
const MAX_EVENT_REFS: usize = 64;
const MAX_EVENT_RESOLVE: usize = 100;
const MAX_EVENT_SUBMIT_BATCH: usize = 100;

#[endpoint]
#[tracing::instrument(skip_all, fields(op = "events_describe"))]
async fn events_describe(depot: &mut Depot) -> JsonResult<cokret_sdk::ServerDescription> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let mut description = describe(
        &state.config.service_did,
        &state.config.public_base_url,
        state.db.mode(),
        state.config.development_mode,
        state.config.oauth_introspection_url.is_some(),
        state.config.auth_server_url.as_deref(),
        &state.config.trust_domain,
    );
    crate::routing::system::describe::apply_claim_level_partition(
        &mut description,
        state.verified_profiles.as_ref(),
    );
    if let Some(limits) = description.limits.as_object_mut() {
        limits.insert("max_event_bytes".to_owned(), json!(MAX_EVENT_BYTES));
        limits.insert("max_prev_refs".to_owned(), json!(MAX_EVENT_PREV_REFS));
        limits.insert("max_refs".to_owned(), json!(MAX_EVENT_REFS));
        limits.insert("max_batch_size".to_owned(), json!(MAX_EVENT_SUBMIT_BATCH));
        limits.insert("max_resolve".to_owned(), json!(MAX_EVENT_RESOLVE));
        limits.insert("max_list_limit".to_owned(), json!(100));
    }
    json_ok(description)
}

#[endpoint]
#[tracing::instrument(skip_all, fields(op = "submit_event"))]
async fn submit_event(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
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
    if envelope.get("service_binding_ref").is_some() {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "schema_violation",
            "federation peer event submission uses /_cokret/peer/events",
        );
        return;
    }
    let Some(session) = auth_or_render(state, req, res).await else {
        return;
    };
    if envelope.get("envelopes").is_some() {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "schema_violation",
            "ck.self.events.submit batch/federation request uses events[], not envelopes[]",
        );
        return;
    }
    match batch_envelopes_from_submit_body(&envelope) {
        Ok(Some(envelopes)) => {
            submit_event_batch(state, &session, envelopes, res).await;
            return;
        }
        Ok(None) => {}
        Err(error) => {
            render_submit_one_error(res, error);
            return;
        }
    }
    if envelope.as_array().is_some() {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "schema_violation",
            "POST /_cokret/self/events batch body must be an object with events[]",
        );
        return;
    }
    let envelope_for_chaos = envelope.clone();
    match submit_event_value(state, &session, envelope).await {
        Ok(response) => {
            maybe_delay_test_chaos_breakpoint(state, &envelope_for_chaos, &response).await;
            res.render(Json(response.outcome));
        }
        Err(error) => render_submit_one_error(res, error),
    }
}

async fn maybe_delay_test_chaos_breakpoint(
    state: &AppState,
    envelope: &Value,
    response: &SubmittedEventOutcome,
) {
    if !state.config.development_mode {
        return;
    }
    let Ok(breakpoint) = std::env::var("SOLAND_TEST_CHAOS_BREAKPOINT") else {
        return;
    };
    if !matches!(
        breakpoint.as_str(),
        "post_commit_pre_response" | "post_wal_pre_response"
    ) {
        return;
    }
    let delay_ms = std::env::var("SOLAND_TEST_CHAOS_DELAY_MS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(0);
    if delay_ms == 0 {
        return;
    }
    let operation_id = envelope_operation_id(envelope);
    if let Ok(expected) = std::env::var("SOLAND_TEST_CHAOS_OPERATION_ID")
        && Some(expected.as_str()) != operation_id.as_deref()
        && expected != response.event_id
    {
        return;
    }
    tracing::warn!(
        breakpoint = %breakpoint,
        delay_ms,
        event_id = %response.event_id,
        operation_id = ?operation_id,
        "test chaos delay before event response"
    );
    tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
}

fn envelope_operation_id(envelope: &Value) -> Option<String> {
    envelope
        .get("unsigned")
        .and_then(Value::as_object)
        .and_then(|unsigned| unsigned.get("local_operation_idempotency_alias"))
        .and_then(Value::as_str)
        .filter(|value| value.starts_with("ck:operation:"))
        .map(ToOwned::to_owned)
}

#[endpoint(
    operation_id = "ck.self.events.get",
    tags("events"),
    summary = "Fetch one canonical Event Envelope by event_id"
)]
#[tracing::instrument(skip_all, fields(op = "ck.self.events.get"))]
async fn get_event(
    aa: AuthArgs,
    event_id: PathParam<String>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<EventView> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let event_id = event_id.into_inner();
    let record = state
        .persistence
        .events()
        .get(&event_id)
        .await
        .ok()
        .flatten()
        .ok_or_else(|| AppError::not_found("event not found"))?;
    if !event_visible_to_session(state, &record, &session).await {
        return Err(AppError::not_found("event not found"));
    }
    event_view_for_state(state, &record)
}

#[endpoint(
    operation_id = "ck.self.events.resolve",
    tags("events"),
    summary = "Resolve up to MAX_EVENT_RESOLVE canonical Event Envelopes by event_id"
)]
#[tracing::instrument(skip_all, fields(op = "ck.self.events.resolve"))]
async fn resolve_events(
    aa: AuthArgs,
    body: JsonBody<EventsResolveRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<EventsResolveOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let body = body.into_inner();
    if body.event_ids.len() + body.event_digests.len() > MAX_EVENT_RESOLVE {
        return Err(AppError::new(
            ErrorCode::QuotaExceeded,
            "too many events requested",
        ));
    }
    let store = state.persistence.events();
    let mut found = Vec::new();
    let mut missing = Vec::new();
    for event_id in body.event_ids {
        let event_id_string = event_id.to_string();
        match store.get(&event_id_string).await.ok().flatten() {
            Some(record) if event_visible_to_session(state, &record, &session).await => {
                found.push(sdk_event_for_state(state, &record)?);
            }
            _ => missing.push(event_id_string),
        }
    }
    json_ok(EventsResolveOutcome {
        events: found,
        missing,
        unauthorized: Vec::new(),
    })
}

/// Internal durable-Event-store reader, kept for actor-scoped audit reads
/// that bypass the projection layer. Not wired to a public route in the
/// current API shape —
/// the canonical `ck.self.events.query` path at `GET /_cokret/self/events` goes to the
/// projection-aware handler in `routing/sync.rs::events_query` so message
/// timeline reads work through `POST /_cokret/self/events` → `events_query`
/// round-trips.
///
/// Supports the multi-value selector `realms[]` ∪ `actors[]` (via
/// repeated query args) **and** real backward iteration (`direction=backward`
/// returns events older than `from` cursor in reverse time order, with
/// `prev_cursor` driving further pages).
/// Plain async helper version of [`events_query_durable_scope`] so other
/// handlers (e.g. the projection-aware `routing::events::sync::events_query`) can
/// dispatch to the durable-store reader when the selector contains only
/// `actors[]` (no `realms[]`). Both the `#[endpoint]` wrapper and the
/// sync-side dispatcher call this impl.
///
/// Returns `Result<EventsQueryOutcome, AppError>` so the wrapper can be a
/// typed `JsonResult<T>` handler and the sync-side dispatcher can map the
/// typed result into its own `&mut Response` shape with a single `match`.
pub(super) async fn events_query_durable_scope_impl(
    state: &AppState,
    session: &SessionRecord,
    req: &Request,
) -> Result<EventsQueryOutcome, AppError> {
    // Repeated query-arg selector: `actors[]` ∪ `realms[]`.
    let mut actors = query_param_all(req, "actors");
    if let Some(single) = query_param(req, "actor").or_else(|| query_param(req, "actor_id")) {
        if !actors.contains(&single) {
            actors.push(single);
        }
    }
    let mut realms = query_param_all(req, "realms");
    if let Some(single) = query_param(req, "realm_id") {
        if !realms.contains(&single) {
            realms.push(single);
        }
    }
    for actor in &actors {
        if validate_did(actor).is_err() {
            return Err(AppError::invalid_param(format!("invalid actor: {actor}")));
        }
    }
    for realm in &mut realms {
        if RealmId::new(realm.clone()).is_err() {
            return Err(AppError::invalid_param(format!("invalid realm: {realm}")));
        }
    }
    // Round C44 (spec dc01ad7): query refactor — `from` / `until` /
    // `direction` removed. `after=<cursor>` paginates forward; `before=<cursor>`
    // paginates backward. Specifying both is an `invalid_param`; specifying
    // neither defaults to forward-from-start.
    let after = query_param(req, "after");
    let before = query_param(req, "before");
    if after.is_some() && before.is_some() {
        return Err(AppError::invalid_param(
            "specify either 'after' or 'before', not both",
        ));
    }
    let (cursor, direction) = match (after, before) {
        (Some(cursor), None) => (Some(cursor), "forward"),
        (None, Some(cursor)) => (Some(cursor), "backward"),
        (None, None) => (None, "forward"),
        (Some(_), Some(_)) => unreachable!("validated above"),
    };
    let limit = query_param(req, "limit")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(50)
        .clamp(1, 100);
    let actors_set: std::collections::BTreeSet<&str> = actors.iter().map(String::as_str).collect();
    let realms_set: std::collections::BTreeSet<&str> = realms.iter().map(String::as_str).collect();
    let scoped = state
        .persistence
        .events()
        .snapshot_all()
        .await
        .unwrap_or_default()
        .into_iter()
        .filter(|record| {
            // Spec selector semantics: union — match actor OR realm membership.
            // Empty selector means "all reachable" (handler will still gate
            // through `event_visible_to_session`).
            if actors_set.is_empty() && realms_set.is_empty() {
                return true;
            }
            let actor_match = actors_set.contains(record.actor_id.as_str());
            let realm_match = record
                .realm_id
                .as_deref()
                .is_some_and(|realm| realms_set.contains(realm));
            actor_match || realm_match
        });
    let mut records = Vec::new();
    for record in scoped {
        if event_visible_to_session(state, &record, session).await {
            records.push(record);
        }
    }
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
    let events = page
        .iter()
        .map(|record| sdk_event_for_state(state, record))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(EventsQueryOutcome {
        events,
        next_cursor,
        prev_cursor: None,
        has_more,
    })
}

/// Salvo `#[endpoint]` wrapper around [`events_query_durable_scope_impl`] so
/// the actor-scoped durable-store reader can be wired to a route directly
/// (currently used only as a fallback dispatched from `routing::events::sync::events_query`
/// when the selector has no `realms[]`).
#[endpoint(
    operation_id = "ck.events.query_durable",
    tags("events"),
    summary = "Durable-store reader (bypasses projection; actor-scoped audit queries)"
)]
#[tracing::instrument(skip_all, fields(op = "ck.events.query_durable"))]
async fn events_query_durable_scope(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<EventsQueryOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let response = events_query_durable_scope_impl(state, &session, req).await?;
    json_ok(response)
}

#[endpoint(
    operation_id = "ck.self.events.frontier",
    tags("events"),
    summary = "Per-actor + per-realm frontier (highest accepted actor_seq / latest event)"
)]
#[tracing::instrument(skip_all, fields(op = "ck.self.events.frontier"))]
async fn events_frontier(
    aa: crate::routing::system::extract::AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
) -> crate::result::JsonResult<SolandEventsFrontierState> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let actor_id = query_param(req, "actor_id").or_else(|| query_param(req, "actor"));
    let realm_selector = query_param(req, "realm_id");
    if actor_id.is_none() && realm_selector.is_none() {
        return Err(AppError::invalid_param(
            "events.frontier requires at least one of realm_id or actor_id",
        ));
    }
    let internal_realm_selector = match realm_selector.as_deref() {
        Some(value) if RealmId::new(value.to_owned()).is_ok() => Some(value.to_owned()),
        Some(_) => return Err(AppError::invalid_param("invalid realm_id")),
        None => None,
    };
    let events = state
        .persistence
        .events()
        .snapshot_all()
        .await
        .unwrap_or_default();
    let mut actor_frontier: BTreeMap<String, u64> = BTreeMap::new();
    let mut realm_frontier: BTreeMap<String, Value> = BTreeMap::new();
    let mut realm_latest: BTreeMap<String, (DateTime<Utc>, String)> = BTreeMap::new();
    for record in &events {
        if actor_id
            .as_deref()
            .is_some_and(|actor| actor != record.actor_id)
        {
            continue;
        }
        let record_realm_id = canonical_realm_id_for_record(record);
        if internal_realm_selector.as_deref() != record_realm_id.as_deref()
            && internal_realm_selector.is_some()
        {
            continue;
        }
        if !event_visible_to_session(state, record, &session).await {
            continue;
        }
        actor_frontier
            .entry(record.actor_id.clone())
            .and_modify(|seq| *seq = (*seq).max(record.actor_seq))
            .or_insert(record.actor_seq);
        if let Some(realm_id) = record_realm_id {
            let replace = frontier_entry_is_newer(&realm_latest, &realm_id, record);
            if replace {
                realm_latest.insert(
                    realm_id.clone(),
                    (record.received_at, record.event_id.clone()),
                );
                realm_frontier.insert(
                    realm_id,
                    json!({
                        "event_id": record.event_id.clone(),
                        "actor_seq": record.actor_seq,
                        "canonical_digest": record.canonical_digest.clone()
                    }),
                );
            }
        }
    }

    let generated_at = now();
    let frontier = json!({
        "storage": state.db.mode(),
        "generated_at": generated_at,
        "events_frontier": {
            "frontier": realm_frontier.clone(),
            "actor_seq_upper_bounds": actor_frontier.clone(),
        },
    });
    crate::result::json_ok(SolandEventsFrontierState {
        actor_frontier,
        realm_frontier,
        frontier,
    })
}

// ── Validator block ─────────────────────────────────────────────────────────

#[derive(Debug)]
struct ValidatedEventEnvelope {
    event_id: String,
    actor_id: String,
    device_id: String,
    actor_seq: u64,
    realm_id: String,
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
    message: String,
}

#[derive(Debug)]
pub(in crate::routing) struct SubmitOneError {
    pub status: StatusCode,
    pub code: String,
    pub message: String,
}

#[derive(Debug)]
pub(in crate::routing) struct SubmittedEventOutcome {
    pub event_id: String,
    pub duplicate: bool,
    pub outcome: EventsSubmitOutcome,
}

impl SubmitOneError {
    fn new(status: StatusCode, code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            status,
            code: code.into(),
            message: message.into(),
        }
    }
}

impl From<EventValidationError> for SubmitOneError {
    fn from(error: EventValidationError) -> Self {
        Self::new(error.status, error.code, error.message)
    }
}

fn event_validation_error(
    status: StatusCode,
    code: &'static str,
    message: impl Into<String>,
) -> EventValidationError {
    EventValidationError {
        status,
        code,
        message: message.into(),
    }
}

fn render_submit_one_error(res: &mut Response, error: SubmitOneError) {
    render_error(res, error.status, &error.code, &error.message);
}

fn batch_envelopes_from_submit_body(body: &Value) -> Result<Option<Vec<Value>>, SubmitOneError> {
    let Some(envelopes_value) = body.get("events") else {
        return Ok(None);
    };
    let Some(envelopes) = envelopes_value.as_array() else {
        return Err(SubmitOneError::new(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            "events submit batch requires events[] array",
        ));
    };
    if envelopes.is_empty() {
        return Err(SubmitOneError::new(
            StatusCode::BAD_REQUEST,
            "missing_param",
            "events submit batch must contain at least one envelope",
        ));
    }
    if envelopes.len() > MAX_EVENT_SUBMIT_BATCH {
        return Err(SubmitOneError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "payload_too_large",
            "events submit batch exceeds max batch size",
        ));
    }
    Ok(Some(envelopes.clone()))
}

async fn submit_event_batch(
    state: &AppState,
    session: &SessionRecord,
    envelopes: Vec<Value>,
    res: &mut Response,
) {
    let mut accepted = Vec::new();
    let mut duplicate = Vec::new();
    let mut rejected = Vec::new();

    for envelope in envelopes {
        let id = event_string_field_from_value(&envelope, "event_id")
            .unwrap_or_else(|| "unknown".to_owned());
        match submit_event_value(state, session, envelope).await {
            Ok(response) => {
                accepted.push(response.event_id.clone());
                if response.duplicate {
                    duplicate.push(response.event_id);
                }
            }
            Err(error) => rejected.push(json!({
                "id": id,
                "reason_code": error.code,
                "detail": error.message,
            })),
        }
    }

    let status = if !rejected.is_empty() {
        EventsSubmitStatus::Partial
    } else if accepted.len() == duplicate.len() && !duplicate.is_empty() {
        EventsSubmitStatus::Duplicate
    } else {
        EventsSubmitStatus::Accepted
    };
    res.render(Json(events_submit_outcome(
        status,
        accepted,
        duplicate,
        rejected,
        Some(super::sync::sync_token_for_state(state)),
    )));
}

pub(super) async fn submit_federation_events(
    state: &AppState,
    req: &Request,
    body: Value,
    res: &mut Response,
) {
    let Some(object) = body.as_object() else {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "schema_violation",
            "ck.peer.events.submit body must be an object",
        );
        return;
    };
    for key in object.keys() {
        if !matches!(
            key.as_str(),
            "service_binding_ref" | "events" | "idempotency_key"
        ) {
            render_error(
                res,
                StatusCode::BAD_REQUEST,
                "schema_violation",
                "ck.peer.events.submit permits only service_binding_ref, events, and idempotency_key",
            );
            return;
        }
    }

    let trust_headers =
        match crate::routing::federation::federation::FederationTrustHeaders::from_salvo_request(
            req,
        ) {
            Ok(headers) => headers,
            Err(violation) => {
                render_error(
                    res,
                    StatusCode::BAD_REQUEST,
                    violation.error_code(),
                    &violation.message(),
                );
                return;
            }
        };
    let expected_destination = match TypedTrustDomainId::new(state.config.trust_domain.clone()) {
        Ok(value) => value,
        Err(error) => {
            tracing::error!(%error, "configured trust_domain failed typed validation");
            render_error(
                res,
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "service trust_domain is invalid",
            );
            return;
        }
    };
    if trust_headers
        .verify_destination(&expected_destination)
        .is_err()
    {
        render_error(
            res,
            StatusCode::CONFLICT,
            "cross_domain_replay_rejected",
            "federation Destination-Trust-Domain header does not match this service",
        );
        return;
    }
    let request_hash = match canonical::canonical_sha256(&body) {
        Ok(value) => value,
        Err(error) => {
            render_error(
                res,
                StatusCode::BAD_REQUEST,
                "schema_violation",
                &format!("ck.peer.events.submit body is not canonical-hashable: {error}"),
            );
            return;
        }
    };
    if request_hash != trust_headers.request_canonical_digest.as_str() {
        crate::metrics::record_digest_mismatch("events_federation_request_binding");
        render_error(
            res,
            StatusCode::CONFLICT,
            "cross_domain_replay_rejected",
            "Request-Canonical-Digest does not match the canonical request body",
        );
        return;
    }

    let submit = match serde_json::from_value::<EventsSubmitFederationRequestBody>(body) {
        Ok(value) => value,
        Err(error) => {
            render_error(
                res,
                StatusCode::BAD_REQUEST,
                "schema_violation",
                &format!("invalid ck.peer.events.submit shape: {error}"),
            );
            return;
        }
    };
    if let Err((code, message)) =
        SolandEventsSubmitRequestBody::validate_federation_binding(&submit)
    {
        render_error(res, StatusCode::BAD_REQUEST, code, &message);
        return;
    }
    if submit.events.is_empty() {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "missing_param",
            "ck.peer.events.submit must contain at least one event",
        );
        return;
    }
    if submit.events.len() > MAX_EVENT_SUBMIT_BATCH {
        render_error(
            res,
            StatusCode::PAYLOAD_TOO_LARGE,
            "payload_too_large",
            "ck.peer.events.submit exceeds max batch size",
        );
        return;
    }

    let binding_realm = submit.service_binding_ref.realm_id.as_str().to_owned();
    let mut accepted = Vec::new();
    let mut duplicate = Vec::new();
    let mut rejected = Vec::new();
    let created_at = now();
    let source_trust_domain = trust_headers.source_trust_domain.as_str().to_owned();

    for envelope in submit.events {
        let id = event_string_field_from_value(&envelope, "event_id")
            .unwrap_or_else(|| "unknown".to_owned());
        let event_realm = event_string_field_from_value(&envelope, "realm_id");
        if event_realm.as_deref() != Some(binding_realm.as_str()) {
            rejected.push(json!({
                "id": id,
                "reason_code": "schema_violation",
                "detail": "event realm_id must match service_binding_ref.realm_id",
            }));
            continue;
        }
        let Some(actor) = event_string_field_from_value(&envelope, "actor_id") else {
            rejected.push(json!({
                "id": id,
                "reason_code": "missing_param",
                "detail": "actor_id is required",
            }));
            continue;
        };
        if validate_did(&actor).is_err() {
            rejected.push(json!({
                "id": id,
                "reason_code": "invalid_param",
                "detail": "actor_id must be a DID",
            }));
            continue;
        }
        let device_id = event_string_field_from_value(&envelope, "device_id")
            .unwrap_or_else(|| format!("federation:{source_trust_domain}"));
        let session = SessionRecord {
            token_hash: format!("federation:{source_trust_domain}:{}", request_hash),
            actor,
            device_id,
            audience: state.config.service_did.clone(),
            expires_at: created_at + Duration::minutes(5),
            created_at,
            revoked_at: None,
        };
        match submit_event_value(state, &session, envelope).await {
            Ok(response) => {
                accepted.push(response.event_id.clone());
                if response.duplicate {
                    duplicate.push(response.event_id);
                }
            }
            Err(error) => rejected.push(json!({
                "id": id,
                "reason_code": error.code,
                "detail": error.message,
            })),
        }
    }

    let status = if !rejected.is_empty() {
        EventsSubmitStatus::Partial
    } else if accepted.len() == duplicate.len() && !duplicate.is_empty() {
        EventsSubmitStatus::Duplicate
    } else {
        EventsSubmitStatus::Accepted
    };
    let status_label = events_submit_status_label(status);
    append_audit_log(
        state,
        None,
        "peer.events.submit",
        json!({
            "realm_id": binding_realm,
            "source_trust_domain": source_trust_domain,
            "request_canonical_digest": request_hash,
            "accepted": accepted,
            "duplicate": duplicate,
            "rejected_count": rejected.len()
        }),
        status_label,
    )
    .await;
    res.render(Json(events_submit_outcome(
        status,
        accepted,
        duplicate,
        rejected,
        Some(super::sync::sync_token_for_state(state)),
    )));
}

fn event_string_field_from_value(value: &Value, field: &str) -> Option<String> {
    value
        .as_object()
        .and_then(|object| event_string_field(object, &[field]))
}

fn events_submit_status_label(status: EventsSubmitStatus) -> &'static str {
    match status {
        EventsSubmitStatus::Accepted => "accepted",
        EventsSubmitStatus::Duplicate => "duplicate",
        EventsSubmitStatus::Partial => "partial",
    }
}

fn events_submit_outcome(
    status: EventsSubmitStatus,
    accepted: Vec<String>,
    duplicate: Vec<String>,
    rejected: Vec<Value>,
    cursor: Option<String>,
) -> EventsSubmitOutcome {
    EventsSubmitOutcome {
        status,
        accepted: accepted
            .into_iter()
            .filter_map(|event_id| EventId::new(event_id).ok())
            .collect(),
        duplicate: duplicate
            .into_iter()
            .filter_map(|event_id| EventId::new(event_id).ok())
            .collect(),
        rejected,
        actor_frontier: Value::Null,
        realm_frontier: Value::Null,
        cursor,
    }
}

pub(in crate::routing) async fn submit_event_value(
    state: &AppState,
    session: &SessionRecord,
    mut envelope: Value,
) -> Result<SubmittedEventOutcome, SubmitOneError> {
    let raw_bytes = serde_json::to_vec(&envelope).map_err(|_| {
        SubmitOneError::new(
            StatusCode::BAD_REQUEST,
            "bad_json",
            "event envelope cannot be encoded",
        )
    })?;
    if raw_bytes.len() > MAX_EVENT_BYTES {
        return Err(SubmitOneError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "payload_too_large",
            "event envelope exceeds max_event_bytes",
        ));
    }

    let parsed = validate_event_envelope(state, session, &envelope).await?;
    let received_at = now();
    let store = state.persistence.events();
    if let Ok(Some(existing)) = store.get(&parsed.event_id).await {
        if existing.canonical_bytes == parsed.canonical_bytes {
            return Ok(event_submit_response(
                state,
                EventsSubmitStatus::Duplicate,
                existing.event_id.clone(),
            ));
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
        )
        .await;
        return Err(SubmitOneError::new(
            StatusCode::CONFLICT,
            "duplicate_conflict",
            "event_id already exists with different canonical bytes",
        ));
    }
    if let Ok(Some(max_seq)) = store.max_actor_seq(&parsed.actor_id).await
        && parsed.actor_seq <= max_seq
    {
        return Err(SubmitOneError::new(
            StatusCode::CONFLICT,
            "cas_conflict",
            "actor_seq must be strictly increasing for the actor",
        ));
    }
    for prev_ref in &parsed.prev_refs {
        if !store.contains(prev_ref).await.unwrap_or(false) {
            return Err(SubmitOneError::new(
                StatusCode::CONFLICT,
                "dependency_missing",
                "prev_refs must reference accepted events",
            ));
        }
    }
    for authorized_ref in &parsed.authorized_refs {
        if !store.contains(authorized_ref).await.unwrap_or(false) {
            return Err(SubmitOneError::new(
                StatusCode::CONFLICT,
                "dependency_missing",
                "refs[role=authorized_by] must reference accepted authorization events",
            ));
        }
    }

    let projection_operation = projection_operation_from_event(&parsed, &envelope);
    tracing::debug!(
        event_id = %parsed.event_id,
        kind = %parsed.kind,
        realm_id = %parsed.realm_id,
        has_projection = projection_operation.is_some(),
        "submit_event"
    );
    let mut flow_status_audit_payload = None;
    if let Some(operation) = projection_operation.as_ref() {
        if let Err(message) = validate_operation_semantics(state, std::slice::from_ref(operation)) {
            return Err(SubmitOneError::new(
                StatusCode::BAD_REQUEST,
                "schema_violation",
                message,
            ));
        }
        if let Err(reason) =
            validate_content_encryption_floor(state, std::slice::from_ref(operation)).await
        {
            return Err(SubmitOneError::new(
                StatusCode::PRECONDITION_FAILED,
                reason,
                reason,
            ));
        }
        // CKP-0016 — reject agent_participation ceiling writes that widen
        // the parent scope's ceiling (tighten-only invariant).
        if let Err(reason) =
            validate_agent_participation_ceiling(state, std::slice::from_ref(operation)).await
        {
            return Err(SubmitOneError::new(
                StatusCode::PRECONDITION_FAILED,
                reason,
                reason,
            ));
        }
        // CKP-0016 §5.2 — a native personal agent may only author messages
        // where its effective participation `reply` bit is true.
        if let Err(reason) =
            validate_agent_reply_participation(state, std::slice::from_ref(operation)).await
        {
            return Err(SubmitOneError::new(StatusCode::FORBIDDEN, reason, reason));
        }
        if let Err(message) =
            validate_operation_policy(state, std::slice::from_ref(operation)).await
        {
            let (status, code) =
                crate::routing::events::operations::operation_policy_reason_code(message);
            return Err(SubmitOneError::new(status, code, message));
        }
        if let Err(rejection) = policy_gate::enforce_operation_policy_server(
            state,
            &parsed.actor_id,
            operation,
            PolicyGateSurface::LocalSubmit,
        )
        .await
        {
            return Err(SubmitOneError::new(
                rejection.status,
                rejection.code,
                rejection.message,
            ));
        }
        if let Ok(proj) = state.projection.lock() {
            if let Err(reason) = proj.check_space_container_lifecycle_transition(operation) {
                return Err(SubmitOneError::new(
                    StatusCode::PRECONDITION_FAILED,
                    reason,
                    reason,
                ));
            }
            if let Err(reason) = proj.check_flow_lifecycle_transition(operation) {
                return Err(SubmitOneError::new(
                    StatusCode::PRECONDITION_FAILED,
                    reason,
                    reason,
                ));
            }
            if let Err(reason) = proj.check_flow_status_transition(operation) {
                return Err(SubmitOneError::new(
                    StatusCode::PRECONDITION_FAILED,
                    reason,
                    reason,
                ));
            }
            flow_status_audit_payload =
                proj.flow_status_transition_audit_payload(operation, &parsed.actor_id);
            if let Err(reason) = proj.check_morph_lifecycle_transition(operation) {
                return Err(SubmitOneError::new(
                    StatusCode::PRECONDITION_FAILED,
                    reason,
                    reason,
                ));
            }
            if let Err(reason) = proj.check_redaction_target_transition(operation) {
                return Err(SubmitOneError::new(
                    StatusCode::PRECONDITION_FAILED,
                    reason,
                    reason,
                ));
            }
            if let Err(reason) = proj.check_flow_tracks_transition(operation) {
                return Err(SubmitOneError::new(
                    StatusCode::PRECONDITION_FAILED,
                    reason,
                    reason,
                ));
            }
            if let Err(reason) = proj.check_bottom_cell_transition(operation) {
                return Err(SubmitOneError::new(
                    StatusCode::PRECONDITION_FAILED,
                    reason,
                    reason,
                ));
            }
            if let Err(reason) = proj.check_membership_join_admission(operation) {
                return Err(SubmitOneError::new(
                    StatusCode::PRECONDITION_FAILED,
                    reason,
                    reason,
                ));
            }
            if let Some(reason) = preflight_mls_projection_reject(&proj, operation) {
                return Err(SubmitOneError::new(
                    StatusCode::PRECONDITION_FAILED,
                    reason.clone(),
                    reason,
                ));
            }
        }
    }

    // SEC-04 — receiver-side independent 24h inception-key online-window cap
    // (`identity/key-management.md` §5.0.1 step 5). When an inception-bootstrap
    // self-authorization (`ck.device.authorize` / `ck.session.grant` carrying a
    // `refs[role=did_inception]` evidence ref) is signed by the inception key,
    // the receiver MUST anchor on the verifiable bootstrap timestamp
    // (`did:webvh` entry-0 `versionTime`) and reject the event when the
    // inception key age exceeds the 24h protocol hard cap — regardless of any
    // longer window the deployment self-reports. Runs against the full envelope
    // because the `did_inception` evidence ref lives on the envelope `refs[]`,
    // not on the projection operation payload.
    enforce_inception_key_online_window(state, &parsed, &envelope).await?;

    // CKP-0007: a message's effective circle-scope is derived from its Flow
    // (spec: `scope_circle_id` is a Flow field, never carried on the message).
    // Stamp the authoritative top-level `effective_scope` onto the stored
    // envelope so read-path visibility gating hides circle-scoped messages
    // from realm members outside the Circle. The Flow scope is durable
    // (projection_flows.scope_circle_id), so this survives restart.
    if parsed.kind == kinds::CK_MESSAGE_CREATE
        && let Some(flow_id) = envelope
            .get("payload")
            .and_then(|payload| payload.get("flow_id"))
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
    {
        let scope = state
            .projection
            .lock()
            .ok()
            .and_then(|proj| proj.flow_scope_circle_id(&flow_id));
        if let Some(scope) = scope
            && let Some(object) = envelope.as_object_mut()
        {
            object.insert("effective_scope".to_owned(), Value::String(scope));
        }
    }

    let envelope_for_bootstrap = envelope.clone();
    if let Err(error) = store
        .put(CanonicalEventRecord {
            event_id: parsed.event_id.clone(),
            actor_id: parsed.actor_id.clone(),
            actor_seq: parsed.actor_seq,
            realm_id: Some(parsed.realm_id.clone()),
            kind: parsed.kind.clone(),
            schema_id: parsed.schema_id.clone(),
            canonical_digest: parsed.canonical_digest.clone(),
            canonical_bytes: parsed.canonical_bytes.clone(),
            envelope,
            received_at,
        })
        .await
    {
        tracing::error!(%error, "failed to persist canonical event");
        return Err(SubmitOneError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            "events store unavailable",
        ));
    }
    if let Some(operation) = projection_operation {
        super::projection::project_accepted_operations_from_device(
            state,
            &parsed.actor_id,
            &parsed.device_id,
            &[operation],
        )
        .await;
    }
    if !session.token_hash.starts_with("federation:") {
        enqueue_peer_event_fanout(state, &parsed, &envelope_for_bootstrap).await;
    }
    if let Some(payload) = flow_status_audit_payload {
        append_audit_log(
            state,
            Some(&parsed.actor_id),
            "incident.status.transition",
            payload,
            "accepted",
        )
        .await;
    }
    if parsed.kind == "ck.realm.create"
        && let Some(envelope_object) = envelope_for_bootstrap.as_object()
    {
        bootstrap_realm_member_index(state, &parsed.realm_id, &parsed.actor_id, envelope_object)
            .await;
        organizations::record_realm_organizations_from_event(
            state,
            &parsed.realm_id,
            &envelope_for_bootstrap,
        );
    }
    append_encrypted_message_franking(state, &parsed, &envelope_for_bootstrap).await;
    append_audit_log(
        state,
        Some(&session.actor),
        "events.submit",
        json!({
            "event_id": parsed.event_id.clone(),
            "realm_id": parsed.realm_id.clone(),
            "kind": parsed.kind.clone(),
            "canonical_digest": parsed.canonical_digest.clone()
        }),
        "accepted",
    )
    .await;
    Ok(event_submit_response(
        state,
        EventsSubmitStatus::Accepted,
        parsed.event_id,
    ))
}

async fn enqueue_peer_event_fanout(
    state: &AppState,
    parsed: &ValidatedEventEnvelope,
    envelope: &Value,
) {
    let peers = configured_peer_event_targets(state);
    if peers.is_empty() {
        return;
    }
    let event_id = parsed.event_id.as_str();
    let binding_payload = json!({
        "domain": "ck.peer.events.submit.service_binding.v1",
        "realm_id": parsed.realm_id,
        "event_id": event_id,
        "canonical_digest": parsed.canonical_digest,
    });
    let service_binding_ref = json!({
        "realm_id": parsed.realm_id,
        "realm_policy_digest": canonical_json_hash(&binding_payload),
        "membership_frontier": [event_id],
        "delivery_binding_frontier": [event_id],
        "destination_service_type": "principal_server",
        "reducer_profile_digest": canonical_json_hash(&json!({
            "domain": "ck.peer.events.submit.reducer_profile.v1",
            "profile": "ck.reducer.v1",
        })),
    });
    let mut hasher_input = Vec::new();
    hasher_input.extend_from_slice(state.config.service_did.as_bytes());
    hasher_input.extend_from_slice(b"|");
    hasher_input.extend_from_slice(event_id.as_bytes());
    hasher_input.extend_from_slice(b"|");
    hasher_input.extend_from_slice(parsed.canonical_digest.as_bytes());
    let idempotency_key = format!("ck:outbox:event:{}", sha256_hex(&hasher_input));
    let body = json!({
        "service_binding_ref": service_binding_ref,
        "events": [envelope],
        "idempotency_key": idempotency_key,
    });
    let payload = match canonical::canonical_json_bytes(&body)
        .ok()
        .and_then(|bytes| String::from_utf8(bytes).ok())
    {
        Some(payload) => payload,
        None => {
            tracing::warn!(event_id, "failed to encode ck.peer.events.submit body");
            return;
        }
    };
    for (peer_url, peer_did) in peers {
        if peer_did == state.config.service_did {
            continue;
        }
        if let Err(error) = crate::routing::federation::outbox::enqueue_outbound(
            state,
            peer_url.as_str(),
            peer_did.as_str(),
            "/_cokret/peer/events",
            &idempotency_key,
            &payload,
        )
        .await
        {
            tracing::warn!(
                %error,
                event_id,
                peer = %peer_url,
                peer_did = %peer_did,
                "failed to enqueue ck.peer.events.submit fanout"
            );
        }
    }
}

fn configured_peer_event_targets(state: &AppState) -> Vec<(String, String)> {
    let entries = match state.config.federation_policy {
        crate::config::FederationPolicy::Mesh => state.config.federation_peers.clone(),
        crate::config::FederationPolicy::Hub => state
            .config
            .federation_peers
            .first()
            .cloned()
            .into_iter()
            .collect(),
    };
    entries
        .into_iter()
        .filter_map(|entry| {
            let trimmed = entry.trim();
            let (url, did) = trimmed.split_once('|')?;
            let url = url.trim().trim_end_matches('/').to_owned();
            let did = did.trim().to_owned();
            if url.is_empty() || validate_did(&did).is_err() {
                None
            } else {
                Some((url, did))
            }
        })
        .collect()
}

fn canonical_json_hash(value: &Value) -> String {
    canonical::canonical_sha256(value).unwrap_or_else(|_| {
        let bytes = serde_json::to_vec(value).unwrap_or_default();
        format!("sha256:{}", sha256_hex(&bytes))
    })
}

fn preflight_mls_projection_reject(
    proj: &crate::reducer::ProjectionState,
    operation: &Operation,
) -> Option<String> {
    let kind = kinds::canonical_kind_string(operation);
    match kind.as_str() {
        kinds::CK_MLS_KEYPACKAGE
        | kinds::CK_MLS_WELCOME
        | kinds::CK_MLS_GENESIS
        | kinds::CK_MLS_COMMIT => {
            let mut snapshot = proj.clone();
            let effect = match kind.as_str() {
                kinds::CK_MLS_KEYPACKAGE => {
                    match operation.payload.get("action").and_then(Value::as_str) {
                        Some("publish") => {
                            crate::reducer::mls::apply_keypackage_publish(&mut snapshot, operation)
                        }
                        Some("claim") => {
                            crate::reducer::mls::apply_keypackage_claim(&mut snapshot, operation)
                        }
                        Some(other) => crate::reducer::ProjectionEffect::Rejected {
                            reason: format!("mls_keypackage_action_unknown:{other}"),
                        },
                        None => crate::reducer::ProjectionEffect::Rejected {
                            reason: "mls_keypackage_action_missing".to_owned(),
                        },
                    }
                }
                kinds::CK_MLS_WELCOME => {
                    crate::reducer::mls::apply_welcome_enqueue(&mut snapshot, operation)
                }
                kinds::CK_MLS_GENESIS => {
                    crate::reducer::mls::apply_group_genesis(&mut snapshot, operation)
                }
                kinds::CK_MLS_COMMIT => {
                    crate::reducer::mls::apply_commit_epoch(&mut snapshot, operation)
                }
                _ => crate::reducer::ProjectionEffect::Ignored,
            };
            match effect {
                crate::reducer::ProjectionEffect::Rejected { reason } => Some(reason),
                _ => None,
            }
        }
        _ => None,
    }
}

fn event_realm_id(object: &serde_json::Map<String, Value>) -> Result<String, EventValidationError> {
    if let Some(realm_id) = event_string_field(object, &["realm_id"]) {
        if RealmId::new(realm_id.clone()).is_err() {
            return Err(event_validation_error(
                StatusCode::BAD_REQUEST,
                "invalid_param",
                "realm_id must use the ck:realm: typed prefix",
            ));
        }
        return Ok(realm_id.clone());
    }

    Err(event_validation_error(
        StatusCode::BAD_REQUEST,
        "missing_param",
        "realm_id is required",
    ))
}

async fn validate_event_envelope(
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
            "event_id must use the ck:event: typed prefix",
        ));
    }

    let kind = event_string_field(object, &["kind"]).ok_or_else(|| {
        event_validation_error(StatusCode::BAD_REQUEST, "missing_param", "kind is required")
    })?;
    // Round R2/R3 (T02/T23) — reject ephemeral kinds & receipt-object-only
    // kinds at the submit entrypoint. Aggressive mode: no compat path —
    // pre-Round-R2/R3 senders MUST switch to ck.schema.ephemeral_envelope.v1
    // (broadcast forms) or ck.schema.device_message.v1 (ck.key.verification.*).
    if let Some((code, reason)) = events_submit_pre_admit_check(&kind) {
        return Err(event_validation_error(
            error_http_status(code),
            code.as_str(),
            reason,
        ));
    }
    if !artifacts::active_local_operation_event_kinds().contains(&kind)
        && kind != kinds::CK_CONFLICT_REPAIR
    {
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

    // REDU-7 / CKP-0008 / CKP-0009 (R3 spec-sync 2026-05-27,
    // cokret-spec b47ff6ec) — Envelope `actor_kind` is reducer-managed:
    // reject any client-supplied value with the spec-canonical
    // `actor_kind_reducer_managed` reason code. The reducer derives the
    // canonical `EnvelopeActorKind` (Native/Ghost/Service/Agent) from
    // the Actor Profile after the bearer-session derivation lands.
    // TODO(P2-impl): once the deep reducer pipeline runs here, stamp the
    // canonical `EnvelopeActorKind` onto the persisted projection envelope.
    if object.get("actor_kind").is_some() {
        return Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            crate::error::reasons::ACTOR_KIND_REDUCER_MANAGED,
            "envelope.actor_kind is reducer-managed; clients MUST NOT supply it",
        ));
    }

    // CKP-0008 / CKP-0009 — when `executed_by` is present the reducer MUST
    // verify the DID resolved from `proof.verification_method` matches
    // `executed_by` (signs-as-X-on-behalf-of-Y attribution proof). This
    // check uses the FIRST proof's verification_method as the proxy for
    // the resolver-derived DID; deep DID-document resolution can replace
    // the prefix match once the agent runtime authorization plumbing
    // lands.
    if let Some(executed_by) = event_string_field(object, &["executed_by"]) {
        if validate_did(&executed_by).is_err() {
            return Err(event_validation_error(
                StatusCode::BAD_REQUEST,
                "invalid_param",
                "executed_by must be a DID",
            ));
        }
        let proofs = object
            .get("proofs")
            .and_then(Value::as_array)
            .and_then(|arr| arr.first())
            .and_then(Value::as_object);
        let vm = proofs.and_then(|proof| event_string_field(proof, &["verification_method"]));
        let vm_did = vm
            .as_deref()
            .map(|raw| raw.split_once('#').map_or(raw, |(did, _)| did));
        if vm_did != Some(executed_by.as_str()) {
            return Err(event_validation_error(
                StatusCode::FORBIDDEN,
                "executed_by_mismatch",
                "envelope.executed_by must match the DID derived from proof.verification_method",
            ));
        }
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
    validate_event_time_fields(state, object)?;

    let realm_id = event_realm_id(object)?;
    // Round R2/R3 (T07) + Stream-F (Wave 1B) — Realm in terminal state
    // (`ck.realm.tombstone` OR `ck.realm.destroy` applied) refuses every
    // non-audit-class write. Spec `realm-and-space.md` §2.5 / §2.5.1.
    let realm_terminal = state
        .projection
        .lock()
        .map(|proj| proj.realm_is_in_terminal_state(&realm_id))
        .unwrap_or(false);
    if let Some((code, reason)) = terminal_realm_check(realm_terminal, &kind) {
        return Err(event_validation_error(
            error_http_status(code),
            code.as_str(),
            reason,
        ));
    }
    // Spec realm-and-space.md §2.6 — `ck.realm.create` is the genesis
    // event for both the Realm metadata cell AND the creator's first
    // member-state cell. The reducer MUST treat `created_by`
    // as already-a-member when admitting this event; otherwise spec-
    // correct clients can never bootstrap a Realm through the canonical
    // event-submission path. The submit_event commit path (below)
    // materialises the member set in state.realms immediately after
    // store.put succeeds, so any follow-up facet event in the same
    // session naturally passes the regular realm_has_member check.
    let is_realm_create_bootstrap = kind == "ck.realm.create"
        && realm_create_actor_is_creator(object, &session.actor)
        && !realm_exists_in_index(state, &realm_id);
    let is_invite_acceptance_join =
        member_join_accepts_pending_invite(state, object, &session.actor, &realm_id).await;
    // A private cross-PS invite delivery (`POST /_cokret/peer/invites`) submits
    // the inviter-signed `ck.invite.create` on the *recipient* PS so the local
    // subject can list + accept it. That realm lives on the inviter's PS, so the
    // recipient PS has no member record for it — yet it MUST still record the
    // pending invite for its subject. Admit `ck.invite.create` from its own
    // inviter into a realm this PS does not host (spec invite-addressing.md §5).
    let is_foreign_invite_delivery = kind == "ck.invite.create"
        && invite_create_actor_is_inviter(object, &session.actor)
        && !realm_exists_in_index(state, &realm_id);
    if !is_realm_create_bootstrap
        && !is_invite_acceptance_join
        && !is_foreign_invite_delivery
        && !realm_has_member(state, &realm_id, &session.actor).await
    {
        return Err(event_validation_error(
            StatusCode::FORBIDDEN,
            "capability_denied",
            "actor is not a member of the event Realm",
        ));
    }
    require_object_field(object, "payload")?;
    // CKP-0007 (spec b7d35be) — hard-reject any wire payload that carries a
    // field listed in `forbidden-wire-fields.json` (sourced from the SDK's
    // `is_forbidden_wire_field`). Receivers MUST refuse the legacy field
    // names outright; no compat path. Spec floor 2b0d70d.
    if let Some(field) = first_forbidden_wire_field(object.get("payload")) {
        return Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            "forbidden_wire_field",
            format!(
                "payload carries forbidden wire field {field:?} \
                 (spec/v1/artifacts/registry/forbidden-wire-fields.json)"
            ),
        ));
    }
    validate_event_schema_and_payload(state, &kind, &schema_id, envelope, object)?;
    if kind == kinds::CK_MEMBER_IDENTITY_UPDATE {
        validate_member_identity_proof(state, object.get("payload").unwrap_or(&Value::Null))?;
    }
    validate_audit_accessed_payload(&kind, object)?;
    validate_sender_commitment_binding(object)?;
    // Round R2/R3 (T08) — cross_domain replay defence MUST run BEFORE the
    // signature check (verified below in `validate_event_proofs`). Aggressive
    // mode: payload missing the new required fields surfaces as
    // schema_violation here; payload with mismatched trust_domain surfaces as
    // the registered `cross_domain_replay_rejected` (409) code.
    if kind == "ck.cross_signing.reset" {
        let payload = object.get("payload").cloned().unwrap_or(Value::Null);
        if let Err((code, reason)) =
            cross_signing_reset_replay_check(&payload, &event_id, &state.config.trust_domain)
        {
            return Err(event_validation_error(
                error_http_status(code),
                code.as_str(),
                &reason,
            ));
        }
    }
    // Round R2/R3 (T09 + T12) — realm.policy_components hard ceiling,
    // e2ee_relaxed mutex, and media plaintext triple binding. Active
    // profile set comes from the submitted policy-components payload;
    // cross-policy bindings come from the materialized Realm metadata /
    // MLS cells, with the current payload used only for same-event writes.
    if kind == "ck.realm.policy_components" {
        let payload = object.get("payload").cloned().unwrap_or(Value::Null);
        let policy_components = policy_components_value_from_state_payload(&payload);
        // Best-effort: collect active profiles from the payload's own
        // `profiles[]` field plus any payload-asserted "active_profiles".
        let mut active_profiles: Vec<String> = policy_components
            .get("profiles")
            .and_then(Value::as_array)
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(ToOwned::to_owned))
                    .collect()
            })
            .unwrap_or_default();
        if let Some(extra) = policy_components
            .get("active_profiles")
            .and_then(Value::as_array)
        {
            for v in extra {
                if let Some(s) = v.as_str() {
                    active_profiles.push(s.to_owned());
                }
            }
        }
        let media_plaintext_service_present =
            projected_media_plaintext_service_present(state, &realm_id, policy_components).await;
        let mls_governance_binding_covers_policy_root =
            projected_mls_governance_binding_covers_policy_root(
                state,
                &realm_id,
                policy_components,
            );
        let binding_discussion_metadata_digest =
            projected_mls_governance_binding_metadata_digest(state, &realm_id);
        if let Err((code, reason)) = realm_policy_components_check(
            policy_components,
            &active_profiles,
            media_plaintext_service_present,
            mls_governance_binding_covers_policy_root,
            binding_discussion_metadata_digest.as_deref(),
        ) {
            return Err(event_validation_error(
                error_http_status(code),
                code.as_str(),
                &reason,
            ));
        }
    }
    // Round R2/R3 (T04) — Anchor frontier entries MUST be sha256:<hex>.
    // We tighten the validator on the events ingest side for the
    // `ck.realm.anchor.submit` payload shape used by federation push;
    // the deeper canonical-bytes path uses SDK `anchor_canonical_bytes`
    // which already excludes id + anchorer_sig (anchorer.rs:217).
    if let Some(frontier) = object
        .get("payload")
        .and_then(|p| p.get("frontier"))
        .and_then(Value::as_array)
    {
        let entries: Vec<String> = frontier
            .iter()
            .filter_map(|v| v.as_str().map(ToOwned::to_owned))
            .collect();
        if let Err((code, reason)) =
            crate::routing::federation::move_anchor::validate_anchor_frontier_entries(&entries)
        {
            return Err(event_validation_error(
                error_http_status(code),
                code.as_str(),
                &reason,
            ));
        }
    }

    let prev_refs = event_ref_list(object, "prev_refs", MAX_EVENT_PREV_REFS)?;
    let authorized_refs = event_semantic_refs(object, state, MAX_EVENT_REFS)?;
    let canonical_bytes = event_canonical_bytes(envelope)?;
    let canonical_digest = event_digest(&canonical_bytes);
    validate_flow_watch_audit_pair(
        state,
        &kind,
        object,
        &event_id,
        &actor_id,
        &canonical_digest,
    )
    .await?;
    validate_event_proofs(object, state, session, &actor_id, &canonical_digest).await?;
    let device_id =
        event_string_field(object, &["device_id"]).unwrap_or_else(|| session.device_id.clone());

    Ok(ValidatedEventEnvelope {
        event_id,
        actor_id,
        device_id,
        actor_seq,
        realm_id,
        kind,
        schema_id,
        prev_refs,
        authorized_refs,
        canonical_digest,
        canonical_bytes,
    })
}

async fn projected_media_plaintext_service_present(
    state: &AppState,
    realm_id: &str,
    payload: &Value,
) -> bool {
    payload_declares_media_plaintext_service(payload, &state.config.service_did)
        || realm_allows_plaintext_service(state, realm_id).await
}

fn payload_declares_media_plaintext_service(payload: &Value, service_did: &str) -> bool {
    payload
        .pointer("/plaintext_visible_services")
        .and_then(Value::as_array)
        .is_some_and(|services| {
            services.iter().any(|service| match service {
                Value::String(value) => value == service_did || value == "media_plaintext",
                Value::Object(object) => {
                    let purpose_matches =
                        object.get("purpose").and_then(Value::as_str) == Some("media_plaintext");
                    let service_matches = object
                        .get("service_did")
                        .or_else(|| object.get("did"))
                        .and_then(Value::as_str)
                        .is_none_or(|value| value == service_did);
                    purpose_matches && service_matches
                }
                _ => false,
            })
        })
}

fn projected_mls_governance_binding_covers_policy_root(
    state: &AppState,
    realm_id: &str,
    payload: &Value,
) -> bool {
    let expected_policy_root = payload_mls_governance_policy_root(payload);
    let Some(projection) = state.projection.lock().ok() else {
        return expected_policy_root.is_some();
    };
    let mut observed_realm_mls_cell = false;
    for (cell, cell_state) in &projection.cells {
        let cell_id = cell.as_str();
        let is_mls_cell = cell_id.contains("ck.component.mls.epoch.v1")
            || cell_id.contains("ck.component.mls_epoch.v1")
            || cell_id.contains("ck.component.mls.covered_frontier.v1");
        if !is_mls_cell {
            continue;
        }
        let cokret_sdk::lattice::CellState::Value(value) = cell_state else {
            continue;
        };
        if !value_targets_realm(value, realm_id) {
            continue;
        }
        observed_realm_mls_cell = true;
        if mls_governance_value_covers_policy_root(value, expected_policy_root) {
            return true;
        }
    }
    !observed_realm_mls_cell && expected_policy_root.is_some()
}

/// SEC-03 — project the `discussion_metadata_digest` the realm's current MLS
/// epoch governance binding covers, so [`realm_policy_components_check`] can
/// recompute the `media_service_decrypts` fact and reject a stale / forged
/// binding (`media-service-binding.md` §8.2 rule 5). Mirrors the cell-selection
/// logic of [`projected_mls_governance_binding_covers_policy_root`]; returns the
/// digest from the first realm-targeting MLS cell that carries one, or `None`
/// when no projected binding advertises a digest (in which case the digest gate
/// is skipped and only policy_root coverage applies).
fn projected_mls_governance_binding_metadata_digest(
    state: &AppState,
    realm_id: &str,
) -> Option<String> {
    let projection = state.projection.lock().ok()?;
    for (cell, cell_state) in &projection.cells {
        let cell_id = cell.as_str();
        let is_mls_cell = cell_id.contains("ck.component.mls.epoch.v1")
            || cell_id.contains("ck.component.mls_epoch.v1")
            || cell_id.contains("ck.component.mls.covered_frontier.v1");
        if !is_mls_cell {
            continue;
        }
        let cokret_sdk::lattice::CellState::Value(value) = cell_state else {
            continue;
        };
        if !value_targets_realm(value, realm_id) {
            continue;
        }
        if let Some(digest) = mls_governance_value_discussion_metadata_digest(value) {
            return Some(digest.to_owned());
        }
    }
    None
}

/// SEC-03 — read the `discussion_metadata_digest` from a projected MLS cell
/// value, checking the same binding sub-objects that
/// [`mls_governance_value_covers_policy_root`] inspects for `policy_root`.
fn mls_governance_value_discussion_metadata_digest(value: &Value) -> Option<&str> {
    [
        value.pointer("/governance_binding/discussion_metadata_digest"),
        value.pointer("/mls_governance_binding/discussion_metadata_digest"),
        value.pointer("/discussion_metadata_digest"),
    ]
    .into_iter()
    .flatten()
    .find_map(|candidate| {
        candidate
            .as_str()
            .filter(|digest| !digest.trim().is_empty())
    })
}

fn payload_mls_governance_policy_root(payload: &Value) -> Option<&str> {
    payload
        .pointer("/mls_governance_binding/policy_root")
        .or_else(|| payload.pointer("/governance_binding/policy_root"))
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
}

fn value_targets_realm(value: &Value, realm_id: &str) -> bool {
    if value.get("space_id").is_some() {
        return false;
    }
    value
        .get("realm_id")
        .and_then(Value::as_str)
        .is_none_or(|value| value == realm_id)
}

fn mls_governance_value_covers_policy_root(
    value: &Value,
    expected_policy_root: Option<&str>,
) -> bool {
    let candidates = [
        value.pointer("/governance_binding/policy_root"),
        value.pointer("/mls_governance_binding/policy_root"),
        value.pointer("/policy_root"),
    ];
    candidates.iter().flatten().any(|candidate| {
        candidate.as_str().is_some_and(|policy_root| {
            !policy_root.trim().is_empty()
                && expected_policy_root.is_none_or(|expected| expected == policy_root)
        })
    })
}

fn validate_event_critical_features(
    object: &serde_json::Map<String, Value>,
) -> Result<(), EventValidationError> {
    let supported = [
        "ck.event_envelope.v1",
        "ck.profile.core_event_store.v1",
        "ck.proof.event_digest.v1",
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
    let Some(critical_extensions) = object
        .get("requirements")
        .and_then(|requirements| requirements.get("critical_extensions"))
    else {
        return Ok(());
    };
    let Some(critical_extensions) = critical_extensions.as_array() else {
        return Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            "requirements.critical_extensions must be an array",
        ));
    };
    for extension in critical_extensions {
        let (id, fail_closed) = match extension {
            Value::String(id) => (id.as_str(), true),
            Value::Object(object) => {
                let id = object.get("id").and_then(Value::as_str).ok_or_else(|| {
                    event_validation_error(
                        StatusCode::BAD_REQUEST,
                        "schema_violation",
                        "requirements.critical_extensions[].id is required",
                    )
                })?;
                let fail_closed = object
                    .get("fail_closed")
                    .and_then(Value::as_bool)
                    .unwrap_or(true);
                (id, fail_closed)
            }
            _ => {
                return Err(event_validation_error(
                    StatusCode::BAD_REQUEST,
                    "schema_violation",
                    "requirements.critical_extensions entries must be strings or objects",
                ));
            }
        };
        if fail_closed && !supported.contains(&id) {
            return Err(event_validation_error(
                StatusCode::NOT_IMPLEMENTED,
                "unsupported_feature",
                "unknown requirements.critical_extensions entry is not supported",
            ));
        }
    }
    Ok(())
}

const SENDER_COMMITMENT_FEATURE: &str = "ck.profile.franking.sender_commitment.v1";
const CK_AUDIT_ACCESSED: &str = "ck.audit.accessed";
const CK_MODERATION_FRANKING_PROOF: &str = "ck.moderation.franking_proof";
const MANAGE_OTHERS_AUDIT_MISSING: &str = "manage_others_audit_missing";

async fn append_encrypted_message_franking(
    state: &AppState,
    parsed: &ValidatedEventEnvelope,
    envelope: &Value,
) {
    if parsed.kind != "ck.message.create" {
        return;
    }
    let Some(policy) = audit_disclosure_policy_for_realm(state, &parsed.realm_id).await else {
        return;
    };
    if policy.get("enabled").and_then(Value::as_bool) == Some(false) {
        return;
    }
    let Some(ciphertext_digest) = encrypted_message_ciphertext_digest(envelope) else {
        return;
    };
    let mut proof = json!({
        "kind": CK_MODERATION_FRANKING_PROOF,
        "realm_id": parsed.realm_id,
        "target_event_id": parsed.event_id,
        "sender_did": parsed.actor_id,
        "receiving_service_did": state.config.service_did,
        "ciphertext_digest": ciphertext_digest,
        "event_canonical_digest": parsed.canonical_digest,
        "timestamp": now(),
        "audit_disclosure_policy": {
            "agent_id": policy.get("agent_id").cloned().unwrap_or(Value::Null),
            "trigger": policy.get("trigger").cloned().unwrap_or(Value::Null),
        },
    });
    let proof_digest = franking_proof_digest(&proof);
    proof["proof_digest"] = json!(proof_digest);
    append_audit_log(
        state,
        Some(&parsed.actor_id),
        CK_MODERATION_FRANKING_PROOF,
        proof,
        "accepted",
    )
    .await;
}

fn encrypted_message_ciphertext_digest(envelope: &Value) -> Option<String> {
    for pointer in [
        "/payload/encrypted_content/digests/ciphertext",
        "/payload/encrypted_content/ciphertext_digest",
        "/payload/ciphertext_digest",
    ] {
        if let Some(digest) = envelope.pointer(pointer).and_then(Value::as_str)
            && is_valid_sha256_digest(digest)
        {
            return Some(digest.to_owned());
        }
    }
    envelope
        .pointer("/payload/encrypted_content/ciphertext")
        .and_then(Value::as_str)
        .map(|ciphertext| format!("sha256:{}", sha256_hex(ciphertext.as_bytes())))
}

async fn audit_disclosure_policy_for_realm(state: &AppState, realm_id: &str) -> Option<Value> {
    state
        .persistence
        .events()
        .snapshot_all()
        .await
        .ok()?
        .into_iter()
        .filter(|record| {
            record.kind == kinds::CK_REALM_CREATE
                && canonical_realm_id_for_record(record).as_deref() == Some(realm_id)
        })
        .rev()
        .find_map(|record| {
            record
                .envelope
                .pointer("/payload/object/audit_disclosure_policy")
                .or_else(|| record.envelope.pointer("/payload/audit_disclosure_policy"))
                .cloned()
        })
}

fn franking_proof_digest(proof: &Value) -> String {
    let material = json!({
        "kind": proof.get("kind").and_then(Value::as_str).unwrap_or(CK_MODERATION_FRANKING_PROOF),
        "target_event_id": proof.get("target_event_id").and_then(Value::as_str).unwrap_or_default(),
        "sender_did": proof.get("sender_did").and_then(Value::as_str).unwrap_or_default(),
        "receiving_service_did": proof.get("receiving_service_did").and_then(Value::as_str).unwrap_or_default(),
        "ciphertext_digest": proof.get("ciphertext_digest").and_then(Value::as_str).unwrap_or_default(),
        "event_canonical_digest": proof.get("event_canonical_digest").and_then(Value::as_str).unwrap_or_default(),
    });
    let bytes = serde_json::to_vec(&material).unwrap_or_default();
    format!("sha256:{}", sha256_hex(&bytes))
}

fn validate_sender_commitment_binding(
    object: &serde_json::Map<String, Value>,
) -> Result<(), EventValidationError> {
    if !event_requirements_features(object).any(|feature| feature == SENDER_COMMITMENT_FEATURE) {
        return Ok(());
    }
    let Some(declared_digest) = object
        .get("payload")
        .and_then(|payload| payload.get("franking"))
        .and_then(|franking| franking.get("sender_commitment_digest"))
        .and_then(Value::as_str)
        .filter(|digest| is_valid_sha256_digest(digest))
    else {
        return Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            "sender_commitment_missing",
            "sender commitment digest is required",
        ));
    };
    let Some(commitment) = object
        .get("unsigned")
        .and_then(|unsigned| unsigned.get("franking"))
        .and_then(|franking| franking.get("sender_commitment"))
    else {
        return Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            "sender_commitment_missing",
            "unsigned.franking.sender_commitment is required",
        ));
    };
    let commitment_bytes = canonical::canonical_json_bytes(commitment).map_err(|_| {
        event_validation_error(
            StatusCode::BAD_REQUEST,
            "sender_commitment_invalid",
            "sender commitment cannot be canonicalized",
        )
    })?;
    let expected_digest = format!("sha256:{}", sha256_hex(&commitment_bytes));
    if declared_digest != expected_digest {
        return Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            "sender_commitment_invalid",
            "sender commitment digest does not match unsigned sidecar",
        ));
    }
    Ok(())
}

fn event_requirements_features(
    object: &serde_json::Map<String, Value>,
) -> impl Iterator<Item = &str> {
    object
        .get("requirements")
        .and_then(|requirements| requirements.get("features"))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
}

fn validate_audit_accessed_payload(
    kind: &str,
    object: &serde_json::Map<String, Value>,
) -> Result<(), EventValidationError> {
    if kind != CK_AUDIT_ACCESSED {
        return Ok(());
    }
    let payload = object
        .get("payload")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            event_validation_error(
                StatusCode::BAD_REQUEST,
                "schema_violation",
                "ck.audit.accessed payload must be an object",
            )
        })?;
    const ALLOWED: &[&str] = &[
        "access_kind",
        "accessed_at",
        "cell_head_after",
        "cell_head_before",
        "paired_event_digest",
        "paired_event_id",
        "purpose",
        "ryw_required",
        "target_actor_id",
        "target_cell_id",
        "target_ref",
        "writer_did",
    ];
    if payload.keys().any(|key| !ALLOWED.contains(&key.as_str())) {
        return Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            "ck.audit.accessed payload contains an unknown field",
        ));
    }
    let access_kind = required_payload_string(payload, "access_kind")?;
    if !matches!(
        access_kind.as_str(),
        "watch_set_others"
            | "watch_audit_read"
            | "e2ee_plaintext_release"
            | "join_application_review"
            | "policy_audit_read"
            | "other"
    ) {
        return Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            "ck.audit.accessed access_kind is invalid",
        ));
    }
    let writer_did = required_payload_string(payload, "writer_did")?;
    validate_did(&writer_did).map_err(|_| {
        event_validation_error(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            "ck.audit.accessed writer_did must be a DID",
        )
    })?;
    if object.get("actor_id").and_then(Value::as_str) != Some(writer_did.as_str()) {
        return Err(event_validation_error(
            StatusCode::FORBIDDEN,
            "actor_session_mismatch",
            "ck.audit.accessed writer_did must match actor_id",
        ));
    }
    let target_ref = required_payload_string(payload, "target_ref")?;
    if !target_ref.starts_with("ck:") {
        return Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            "ck.audit.accessed target_ref must be a typed object ref",
        ));
    }
    if required_payload_string(payload, "purpose")?
        .trim()
        .is_empty()
    {
        return Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            "ck.audit.accessed purpose must be non-empty",
        ));
    }
    let accessed_at = required_payload_string(payload, "accessed_at")?;
    DateTime::parse_from_rfc3339(&accessed_at).map_err(|_| {
        event_validation_error(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            "ck.audit.accessed accessed_at must be RFC3339",
        )
    })?;
    match access_kind.as_str() {
        "watch_set_others" => {
            validate_watch_audit_payload_fields(payload)?;
            for field in ["paired_event_id", "paired_event_digest"] {
                let value = required_payload_string(payload, field)?;
                if (field == "paired_event_id" && !is_valid_event_id(&value))
                    || (field == "paired_event_digest" && !is_valid_sha256_digest(&value))
                {
                    return Err(event_validation_error(
                        StatusCode::BAD_REQUEST,
                        "schema_violation",
                        "ck.audit.accessed paired event fields are invalid",
                    ));
                }
            }
            for field in ["cell_head_before", "cell_head_after"] {
                if !payload.get(field).is_some_and(|value| {
                    value.is_null() || value.as_str().is_some_and(is_valid_sha256_digest)
                }) {
                    return Err(event_validation_error(
                        StatusCode::BAD_REQUEST,
                        "schema_violation",
                        "ck.audit.accessed cell heads must be null or sha256 digest",
                    ));
                }
            }
        }
        "watch_audit_read" => {
            validate_watch_audit_payload_fields(payload)?;
        }
        _ => {}
    }
    Ok(())
}

fn validate_watch_audit_payload_fields(
    payload: &serde_json::Map<String, Value>,
) -> Result<(), EventValidationError> {
    let target_actor = required_payload_string(payload, "target_actor_id")?;
    validate_did(&target_actor).map_err(|_| {
        event_validation_error(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            "ck.audit.accessed target_actor_id must be a DID",
        )
    })?;
    let target_cell_id = required_payload_string(payload, "target_cell_id")?;
    if !target_cell_id.starts_with("ck:cell:") {
        return Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            "ck.audit.accessed target_cell_id must use ck:cell:",
        ));
    }
    Ok(())
}

fn required_payload_string(
    payload: &serde_json::Map<String, Value>,
    field: &'static str,
) -> Result<String, EventValidationError> {
    payload
        .get(field)
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .ok_or_else(|| {
            event_validation_error(
                StatusCode::BAD_REQUEST,
                "schema_violation",
                format!("ck.audit.accessed requires {field}"),
            )
        })
}

async fn validate_flow_watch_audit_pair(
    state: &AppState,
    kind: &str,
    object: &serde_json::Map<String, Value>,
    event_id: &str,
    actor_id: &str,
    canonical_digest: &str,
) -> Result<(), EventValidationError> {
    if kind != kinds::CK_FLOW_WATCH_SET {
        return Ok(());
    }
    let payload = object
        .get("payload")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            event_validation_error(
                StatusCode::BAD_REQUEST,
                "schema_violation",
                "flow watch payload must be an object",
            )
        })?;
    let target_actor = payload
        .get("watcher_actor_id")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            event_validation_error(
                StatusCode::BAD_REQUEST,
                "schema_violation",
                "flow watch payload requires watcher_actor_id",
            )
        })?;
    if target_actor == actor_id {
        return Ok(());
    }
    if payload.get("level").and_then(Value::as_str) == Some("muted")
        || payload
            .get("level_public")
            .and_then(Value::as_bool)
            .unwrap_or(false)
    {
        return Err(event_validation_error(
            StatusCode::PRECONDITION_FAILED,
            MANAGE_OTHERS_AUDIT_MISSING,
            "manage_others flow watch writes cannot set muted or public levels",
        ));
    }
    let audit_refs = event_refs_with_role(object, "audit_pair")?;
    let Some(audit_ref) = audit_refs.first() else {
        return Err(manage_others_audit_error(
            "cross-actor flow watch writes require refs[role=audit_pair]",
        ));
    };
    if audit_refs.len() != 1 {
        return Err(manage_others_audit_error(
            "cross-actor flow watch writes require exactly one audit_pair ref",
        ));
    }
    let audit_record = state
        .persistence
        .events()
        .get(audit_ref)
        .await
        .map_err(|_| manage_others_audit_error("audit_pair event lookup failed"))?
        .ok_or_else(|| manage_others_audit_error("audit_pair event is not accepted"))?;
    if audit_record.kind != CK_AUDIT_ACCESSED {
        return Err(manage_others_audit_error(
            "audit_pair ref must point to ck.audit.accessed",
        ));
    }
    let audit_payload = audit_record
        .envelope
        .get("payload")
        .and_then(Value::as_object)
        .ok_or_else(|| manage_others_audit_error("audit_pair payload is invalid"))?;
    let flow_id = payload.get("flow_id").and_then(Value::as_str).unwrap_or("");
    let checks = [
        ("access_kind", "watch_set_others"),
        ("writer_did", actor_id),
        ("target_actor_id", target_actor),
        ("target_ref", flow_id),
        ("paired_event_id", event_id),
        ("paired_event_digest", canonical_digest),
    ];
    for (field, expected) in checks {
        if audit_payload.get(field).and_then(Value::as_str) != Some(expected) {
            return Err(manage_others_audit_error(
                "audit_pair payload does not match the flow watch event",
            ));
        }
    }
    Ok(())
}

fn event_refs_with_role(
    object: &serde_json::Map<String, Value>,
    role: &str,
) -> Result<Vec<String>, EventValidationError> {
    let Some(values) = object.get("refs").and_then(Value::as_array) else {
        return Ok(Vec::new());
    };
    let mut refs = Vec::new();
    for value in values {
        let Some(reference) = value.as_object() else {
            continue;
        };
        if reference.get("role").and_then(Value::as_str) == Some(role) {
            let id = reference.get("id").and_then(Value::as_str).ok_or_else(|| {
                event_validation_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_param",
                    "refs entries require id",
                )
            })?;
            if !is_valid_event_id(id) {
                return Err(event_validation_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_param",
                    "audit_pair refs must use ck:event: typed ids",
                ));
            }
            refs.push(id.to_owned());
        }
    }
    Ok(refs)
}

fn manage_others_audit_error(message: impl Into<String>) -> EventValidationError {
    event_validation_error(
        StatusCode::PRECONDITION_FAILED,
        MANAGE_OTHERS_AUDIT_MISSING,
        message,
    )
}

fn validate_event_time_fields(
    state: &AppState,
    object: &serde_json::Map<String, Value>,
) -> Result<(), EventValidationError> {
    let created_at_value = object.get("created_at");
    if created_at_value.is_some_and(|value| !value.is_string()) {
        return Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "created_at must be a string",
        ));
    }
    match created_at_value.and_then(Value::as_str) {
        Some(value) => canonical::validate_timestamp_canonical(value).map_err(|_| {
            event_validation_error(
                StatusCode::BAD_REQUEST,
                "invalid_param",
                "created_at must use canonical RFC3339 UTC form",
            )
        })?,
        None if !state.config.development_mode => {
            return Err(event_validation_error(
                StatusCode::BAD_REQUEST,
                "missing_param",
                "created_at is required in production mode",
            ));
        }
        None => {}
    }

    let hlc_value = object.get("hlc");
    if hlc_value.is_some_and(|value| !value.is_string()) {
        return Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "hlc must be a string",
        ));
    }
    match hlc_value.and_then(Value::as_str) {
        Some(value) => {
            Hlc::new(value).map_err(|_| {
                event_validation_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_param",
                    "hlc must use canonical lower-hex HLC form",
                )
            })?;
        }
        None if !state.config.development_mode => {
            return Err(event_validation_error(
                StatusCode::BAD_REQUEST,
                "missing_param",
                "hlc is required in production mode",
            ));
        }
        None => {}
    }

    Ok(())
}

fn validate_event_schema_and_payload(
    state: &AppState,
    kind: &str,
    _schema_id: &str,
    envelope: &Value,
    object: &serde_json::Map<String, Value>,
) -> Result<(), EventValidationError> {
    if !state.config.development_mode {
        let registry = cokret_sdk::schema::schema_registry_from_default_spec_artifacts()
            .map_err(|_| {
                event_validation_error(
                    StatusCode::BAD_REQUEST,
                    "schema_violation",
                    "event schema registry could not be loaded",
                )
            })?
            .ok_or_else(|| {
                event_validation_error(
                    StatusCode::BAD_REQUEST,
                    "schema_violation",
                    "event schema registry is unavailable",
                )
            })?;
        registry
            .validate_value("ck.schema.event.v1", envelope)
            .map_err(|_| {
                event_validation_error(
                    StatusCode::BAD_REQUEST,
                    "schema_violation",
                    "event envelope violates ck.schema.event.v1",
                )
            })?;
    }

    let payload = object.get("payload").ok_or_else(|| {
        event_validation_error(
            StatusCode::BAD_REQUEST,
            "missing_param",
            "event payload is required",
        )
    })?;
    // R3.2 wire-breaking deny validators (MIU-SOL-1 / HC-SOL-3). These run
    // ahead of the registered payload-schema validator so a forbidden
    // field surfaces the precise R3.2 reason code rather than a generic
    // `schema_violation` from the SDK catalog.
    validate_r3_2_wire_shape(kind, payload)?;
    if kind == kinds::CK_CONFLICT_REPAIR {
        return validate_conflict_repair_event_payload(payload);
    }
    if matches!(
        kind,
        kinds::CK_SPACE_CONTAINER_ARCHIVE
            | kinds::CK_SPACE_CONTAINER_RESTORE
            | kinds::CK_SPACE_CONTAINER_TOMBSTONE
    ) {
        return validate_space_container_lifecycle_payload(payload);
    }
    cokret_sdk::schema::event_payload_validator_catalog()
        .validate_payload(kind, payload)
        .map_err(|error| {
            event_validation_error(
                StatusCode::BAD_REQUEST,
                "schema_violation",
                format!("event payload violates the registered payload schema: {error}"),
            )
        })?;
    validate_realm_create_policy_constraints(kind, payload)?;
    Ok(())
}

/// R3.2 (cokret-spec @ b56cab1) — wire-breaking deny validators applied on
/// the event ingest path.
///
/// - MIU-SOL-1: `ck.member.identity.update` payloads MUST NOT carry the removed handle fields
///   (`primary_handle` / `handles[]` / `verified_handle`).
/// - HC-SOL-3: message event payloads carrying mention references MUST use the v2 shape
///   (`subject_id` authoritative); the legacy `subject` / `handle` / `display_snapshot` shape is
///   rejected.
///
/// Each maps a [`crate::wire_validators::WireRejection`] to a
/// `schema_violation`-class [`EventValidationError`] carrying the precise
/// R3.2 reason code.
fn validate_r3_2_wire_shape(kind: &str, payload: &Value) -> Result<(), EventValidationError> {
    if kind == kinds::CK_MEMBER_IDENTITY_UPDATE {
        crate::wire_validators::member_identity::validate_member_identity_update_payload(payload)
            .map_err(wire_rejection_to_validation_error)?;
    }
    if matches!(kind, kinds::CK_MESSAGE_CREATE | kinds::CK_MESSAGE_REVISE)
        && let Some(content) = payload.get("content")
    {
        crate::wire_validators::mention::validate_content_mention_references(content)
            .map_err(wire_rejection_to_validation_error)?;
    }
    Ok(())
}

fn wire_rejection_to_validation_error(
    rejection: crate::wire_validators::WireRejection,
) -> EventValidationError {
    event_validation_error(StatusCode::BAD_REQUEST, rejection.reason, rejection.message)
}

fn validate_member_identity_proof(
    state: &AppState,
    payload: &Value,
) -> Result<(), EventValidationError> {
    let Some(identity_payload) = payload.get("identity_payload") else {
        return Ok(());
    };
    let Some(member_identity_value) = identity_payload.get("member_identity") else {
        if identity_payload.get("encrypted_payload").is_some() {
            return Err(event_validation_error(
                StatusCode::NOT_IMPLEMENTED,
                "unsupported_feature",
                "encrypted MemberIdentity proof verification is not wired; refusing fail-closed",
            ));
        }
        return Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            "identity_payload must carry member_identity or encrypted_payload",
        ));
    };
    let identity: cokret_sdk::MemberIdentity =
        serde_json::from_value(member_identity_value.clone()).map_err(|error| {
            event_validation_error(
                StatusCode::BAD_REQUEST,
                "schema_violation",
                format!("MemberIdentity payload shape is invalid: {error}"),
            )
        })?;
    let payload_realm = payload.get("realm_id").and_then(Value::as_str);
    let payload_actor = payload.get("actor_id").and_then(Value::as_str);
    if payload_realm != Some(identity.realm_id.as_str())
        || payload_actor != Some(identity.actor_id.as_str())
    {
        return Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            "MemberIdentity realm_id/actor_id must match the update payload subject",
        ));
    }
    let canonical_bytes = identity.canonical_payload_bytes().map_err(|error| {
        event_validation_error(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            format!("MemberIdentity canonical payload failed: {error}"),
        )
    })?;
    let payload_digest = identity.canonical_payload_sha256().map_err(|error| {
        event_validation_error(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            format!("MemberIdentity payload digest failed: {error}"),
        )
    })?;
    if identity.proof.payload_digest.as_str() != payload_digest {
        crate::metrics::record_digest_mismatch("member_identity_payload_digest");
        return Err(event_validation_error(
            StatusCode::CONFLICT,
            "proof_event_digest_mismatch",
            "MemberIdentityProof.payload_digest does not match the canonical payload",
        ));
    }
    if !matches!(
        identity.proof.signature_algorithm,
        cokret_sdk::MemberIdentitySignatureAlgorithm::Ed25519
    ) {
        return Err(event_validation_error(
            StatusCode::NOT_IMPLEMENTED,
            "unsupported_feature",
            "only Ed25519 MemberIdentityProof.signature_algorithm is supported",
        ));
    }
    crate::jws_verify::validate_verification_method_controller(
        identity.subject_id.as_str(),
        &identity.proof.verification_method,
    )
    .map_err(|error| {
        event_validation_error(
            StatusCode::FORBIDDEN,
            "proof_invalid",
            format!("MemberIdentity proof controller mismatch: {error}"),
        )
    })?;
    let public_key =
        crate::jws_verify::resolve_ed25519_pubkey(state, &identity.proof.verification_method)
            .map_err(|error| {
                event_validation_error(
                    StatusCode::FORBIDDEN,
                    "proof_invalid",
                    format!("MemberIdentity proof verification key resolution failed: {error}"),
                )
            })?;
    let signature_bytes = URL_SAFE_NO_PAD
        .decode(identity.proof.signature.as_bytes())
        .map_err(|error| {
            event_validation_error(
                StatusCode::BAD_REQUEST,
                "proof_invalid",
                format!("MemberIdentity proof signature is not base64url: {error}"),
            )
        })?;
    let signature_array: [u8; 64] = signature_bytes.try_into().map_err(|_| {
        event_validation_error(
            StatusCode::BAD_REQUEST,
            "proof_invalid",
            "MemberIdentity proof signature must be 64 bytes",
        )
    })?;
    let signature = ed25519_dalek::Signature::from_bytes(&signature_array);
    public_key
        .verify(&canonical_bytes, &signature)
        .map_err(|error| {
            event_validation_error(
                StatusCode::FORBIDDEN,
                "proof_invalid",
                format!("MemberIdentity proof signature verification failed: {error}"),
            )
        })
}

fn validate_conflict_repair_event_payload(payload: &Value) -> Result<(), EventValidationError> {
    let Some(object) = payload.as_object() else {
        return Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            "conflict repair payload must be an object",
        ));
    };
    let cell_id = object
        .get("cell_id")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            event_validation_error(
                StatusCode::BAD_REQUEST,
                "schema_violation",
                "conflict repair payload requires cell_id",
            )
        })?;
    if !cell_id.starts_with("ck:cell:") {
        return Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            "conflict repair cell_id must use ck:cell:",
        ));
    }
    let heads = object
        .get("conflict_heads")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            event_validation_error(
                StatusCode::BAD_REQUEST,
                "schema_violation",
                "conflict repair payload requires conflict_heads",
            )
        })?;
    if heads.len() < 2
        || heads
            .iter()
            .any(|head| head.as_str().is_none_or(|value| value.trim().is_empty()))
    {
        return Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            "conflict repair conflict_heads must contain at least two non-empty strings",
        ));
    }
    if object
        .get("recovery_capability_ref")
        .and_then(Value::as_str)
        .is_none_or(|value| value.trim().is_empty())
    {
        return Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            "conflict repair payload requires recovery_capability_ref",
        ));
    }
    if !object.contains_key("winner_value") {
        return Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            "conflict repair payload requires winner_value",
        ));
    }
    Ok(())
}

fn validate_realm_create_policy_constraints(
    kind: &str,
    payload: &Value,
) -> Result<(), EventValidationError> {
    if kind != kinds::CK_REALM_CREATE {
        return Ok(());
    }
    let Some(object) = payload.get("object").and_then(Value::as_object) else {
        return Ok(());
    };
    let history_visibility = object
        .get("history_visibility")
        .and_then(Value::as_str)
        .unwrap_or("joined");
    let encryption_profile = object
        .get("encryption_profile")
        .and_then(Value::as_str)
        .unwrap_or("none");
    if history_visibility == "world_readable" && encryption_profile != "none" {
        return Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            "incompatible_history_with_encryption",
            "world_readable history requires encryption_profile=none",
        ));
    }
    if history_visibility == "restricted"
        && object
            .get("history_sharing_policy")
            .and_then(Value::as_object)
            .is_none()
    {
        return Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            "history_sharing_policy_missing",
            "restricted history_visibility requires an effective history_sharing_policy",
        ));
    }
    Ok(())
}

fn validate_space_container_lifecycle_payload(payload: &Value) -> Result<(), EventValidationError> {
    let Some(object) = payload.as_object() else {
        return Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            "space lifecycle payload must be an object",
        ));
    };
    let target = object
        .get("space_id")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            event_validation_error(
                StatusCode::BAD_REQUEST,
                "schema_violation",
                "space lifecycle payload requires space_id",
            )
        })?;
    if validate_space_id(target).is_err() {
        return Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            "space lifecycle payload space_id must use ck:space:",
        ));
    }
    if object.get("target_ref").is_some() {
        return Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            "space lifecycle payload must use space_id, not target_ref",
        ));
    }
    Ok(())
}

fn event_requirements_schema_id(
    state: &AppState,
    object: &serde_json::Map<String, Value>,
) -> Result<String, EventValidationError> {
    let canonical_schema_id = object
        .get("requirements")
        .and_then(|requirements| requirements.get("schema"))
        .and_then(Value::as_array)
        .and_then(|schemas| schemas.first())
        .and_then(Value::as_str)
        .map(ToOwned::to_owned);
    if !state.config.development_mode && canonical_schema_id.is_none() {
        return Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            "missing_param",
            "requirements.schema[] is required in production mode",
        ));
    }
    let schema_id = canonical_schema_id
        .or_else(|| {
            object
                .get("schema_id")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned)
        })
        .unwrap_or_else(|| "ck.schema.event.v1".to_owned());
    if !schema_id.starts_with("ck.schema.") || !artifacts::schema_ids().contains(&schema_id) {
        return Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            "unknown_schema",
            "event schema_id is not in the cokret-spec schema registry",
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

async fn validate_event_proofs(
    object: &serde_json::Map<String, Value>,
    state: &AppState,
    session: &SessionRecord,
    actor_id: &str,
    expected_payload_digest: &str,
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
    // - **Production** (`development_mode=false`): EVERY proof MUST be a full detached-JWS proof
    //   with `kind`/`alg`/`verification_method`/ `event_digest`/`created_at`/`jws`, hashing the
    //   full canonical envelope. The `type=="dev-proof"` and payload-only hash forms are NOT
    //   accepted under any circumstance — a malicious client claiming `type="dev-proof"` in
    //   production fails-closed here.
    // - **Development** (`development_mode=true`): the minimal dev-proof shape (`type="dev-proof"`,
    //   `verification_method`, `payload_digest`-of-payload) is also accepted so integration
    //   fixtures round-trip without keying.
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
            &["verification_method", "payload_digest"]
        } else {
            &[
                "kind",
                "alg",
                "verification_method",
                "event_digest",
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
        if !is_dev_proof && event_string_field(proof_object, &["alg"]).as_deref() != Some("EdDSA") {
            return Err(event_validation_error(
                StatusCode::BAD_REQUEST,
                "invalid_proof",
                "event proof alg must be EdDSA",
            ));
        }
        let proof_digest_key = if is_dev_proof {
            "payload_digest"
        } else {
            "event_digest"
        };
        let proof_event_digest =
            event_string_field(proof_object, &[proof_digest_key]).ok_or_else(|| {
                event_validation_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_proof",
                    "proof event_digest is required",
                )
            })?;
        // Production: the proof's event_digest MUST match the canonical
        // envelope digest. Dev-only: also accept the payload-only sha256 form
        // so test fixtures keep round-tripping. Production never falls back.
        let payload_only_hash_accept = if is_dev_proof {
            object.get("payload").map(|payload| {
                let bytes = canonical::canonical_json_bytes(payload).unwrap_or_default();
                format!("sha256:{}", sha256_hex(&bytes))
            })
        } else {
            None
        };
        if proof_event_digest != expected_payload_digest
            && payload_only_hash_accept.as_deref() != Some(&proof_event_digest)
        {
            return Err(event_validation_error(
                StatusCode::BAD_REQUEST,
                "proof_event_digest_mismatch",
                "proof event_digest does not match the event payload",
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
        if is_production {
            let jws = event_string_field(proof_object, &["jws"]).ok_or_else(|| {
                event_validation_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_proof",
                    "proof jws is required",
                )
            })?;
            let created_at =
                event_string_field(proof_object, &["created_at"]).ok_or_else(|| {
                    event_validation_error(
                        StatusCode::BAD_REQUEST,
                        "invalid_proof",
                        "proof created_at is required",
                    )
                })?;
            let proof_binding_bytes = event_proof_binding_bytes(
                &proof_event_digest,
                actor_id,
                &verification_method,
                &created_at,
                proof_object,
            )?;
            // 高风险:event proof 验签前强制 DID 文档新鲜度门禁
            // (fail-closed-on-stale)。陈旧/缺证据的缓存公钥不得用于验签。
            let actor_did = cokret_sdk::Did::new(actor_id.to_owned()).map_err(|error| {
                event_validation_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_proof",
                    format!("event proof actor_id is not a valid DID: {error}"),
                )
            })?;
            crate::jws_verify::enforce_high_risk_did_freshness(state, &actor_did)
                .await
                .map_err(|reason| {
                    tracing::debug!(%reason, "event proof DID freshness gate failed");
                    event_validation_error(
                        StatusCode::BAD_REQUEST,
                        "stale_did_document",
                        "event proof DID document is stale or unavailable for verification",
                    )
                })?;
            crate::jws_verify::verify_jws_ed25519(
                &proof_binding_bytes,
                &jws,
                &verification_method,
                actor_id,
                state,
            )
            .map_err(|reason| {
                tracing::debug!(%reason, "event proof JWS verification failed");
                event_validation_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_proof",
                    "event proof JWS verification failed",
                )
            })?;
        }
    }
    Ok(())
}

fn event_proof_binding_bytes(
    event_digest: &str,
    actor_id: &str,
    verification_method: &str,
    created_at: &str,
    proof_object: &serde_json::Map<String, Value>,
) -> Result<Vec<u8>, EventValidationError> {
    let mut binding = serde_json::Map::new();
    binding.insert("event_digest".to_owned(), json!(event_digest));
    binding.insert("actor_id".to_owned(), json!(actor_id));
    binding.insert("verification_method".to_owned(), json!(verification_method));
    binding.insert("created_at".to_owned(), json!(created_at));
    for optional in ["domain", "audience"] {
        if let Some(value) = proof_object.get(optional) {
            binding.insert(optional.to_owned(), value.clone());
        }
    }
    canonical::canonical_json_bytes(&Value::Object(binding)).map_err(|error| {
        event_validation_error(
            StatusCode::BAD_REQUEST,
            "invalid_proof",
            format!("proof binding canonicalization failed: {error}"),
        )
    })
}

fn event_string_field(object: &serde_json::Map<String, Value>, keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|key| object.get(*key).and_then(Value::as_str))
        .map(ToOwned::to_owned)
}

/// True iff a `ck.realm.create` event's `payload.object.created_by`
/// matches the session actor. Spec realm-and-space.md §2.6 — this is the
/// genesis-member condition that lets the create event bypass the regular
/// `realm_has_member` check.
fn realm_create_actor_is_creator(object: &serde_json::Map<String, Value>, actor: &str) -> bool {
    object
        .get("payload")
        .and_then(|payload| payload.get("object"))
        .and_then(|create_object| create_object.get("created_by"))
        .and_then(Value::as_str)
        .is_some_and(|creator| creator == actor)
}

/// True when a `ck.invite.create` event is signed by its own inviter. The
/// inviter is the payload `inviter`/`sender`/`issuer` when present; otherwise
/// the top-level `actor_id` (the signer) is authoritative. Used to admit a
/// cross-PS invite delivery on a recipient PS that does not host the realm.
fn invite_create_actor_is_inviter(object: &serde_json::Map<String, Value>, actor: &str) -> bool {
    let inviter = object
        .get("payload")
        .and_then(|payload| {
            payload
                .get("inviter")
                .or_else(|| payload.get("sender"))
                .or_else(|| payload.get("issuer"))
                .and_then(Value::as_str)
        })
        .or_else(|| object.get("actor_id").and_then(Value::as_str));
    inviter.is_some_and(|inviter| inviter == actor)
}

async fn member_join_accepts_pending_invite(
    state: &AppState,
    object: &serde_json::Map<String, Value>,
    actor: &str,
    realm_id: &str,
) -> bool {
    let kind = object.get("kind").and_then(Value::as_str);
    // Two canonical invite-acceptance shapes are admitted for a
    // not-yet-member invitee (spec invite-addressing.md / event-kind-registry):
    //   1. `ck.member.state{membership:join, invite_ref}` — the join-cascade form;
    //   2. `ck.invite.accept{invite_ref|invite_id}` — the dedicated accept event.
    // Both resolve a *pending* invite whose `invitee == actor`, so a fresh
    // invitee can close their own invite through either path without first
    // being a realm member. Previously only (1) was exempt, so a spec-correct
    // `ck.invite.accept` from the invitee was rejected with `capability_denied`.
    let is_member_state_join = kind == Some(kinds::CK_MEMBER_STATE);
    let is_invite_accept = kind == Some("ck.invite.accept");
    if !is_member_state_join && !is_invite_accept {
        return false;
    }
    let Some(payload) = object.get("payload") else {
        return false;
    };
    if is_member_state_join && payload.get("membership").and_then(Value::as_str) != Some("join") {
        return false;
    }
    let target_actor = payload
        .get("actor_id")
        .or_else(|| payload.get("member"))
        .or_else(|| payload.get("invitee"))
        .and_then(Value::as_str)
        .unwrap_or(actor);
    if target_actor != actor {
        return false;
    }
    let Some(invite_id) = payload
        .get("invite_ref")
        .or_else(|| payload.get("invite_id"))
        .and_then(Value::as_str)
    else {
        return false;
    };
    if crate::ids::parse_typed_uuid(invite_id, "invite").is_none() {
        return false;
    }
    let Ok(Some(invite)) = state.persistence.realm_invites().get(invite_id).await else {
        return false;
    };
    if invite.status != "pending" || invite.invitee.as_deref() != Some(actor) {
        return false;
    }
    if invite
        .expires_at
        .is_some_and(|expires_at| expires_at <= now())
    {
        return false;
    }
    invite.realm_id == realm_id
}

/// Quick existence probe against the in-memory `state.realms` index used
/// by the regular `realm_has_member` check. Used to gate the
/// `ck.realm.create` bootstrap path so a duplicate-create attempt (where
/// the Realm already has members) falls back to the normal member check.
fn realm_exists_in_index(state: &AppState, realm_id: &str) -> bool {
    let Ok(realm_id_typed) = cokret_sdk::RealmId::new(realm_id.to_owned()) else {
        return false;
    };
    state
        .realms
        .lock()
        .map(|realms| realms.get(&realm_id_typed).is_some())
        .unwrap_or(false)
}

/// Spec realm-and-space.md §2.6 step 2 — when a `ck.realm.create` event
/// commits, materialise the in-memory Realm index entry with the
/// creator as the first member so subsequent facet events (join_rule /
/// history_visibility / discovery / policy_components / ...) from the
/// same actor pass the regular `realm_has_member` check without a
/// separate `ck.member.state(join)` event.
///
/// Extracted out of `submit_event` (called once after `store.put`
/// succeeds for a `ck.realm.create` event) so the canonical Event
/// Envelope path owns Realm bootstrap state.
async fn bootstrap_realm_member_index(
    state: &AppState,
    realm_id: &str,
    actor: &str,
    object: &serde_json::Map<String, Value>,
) {
    let Ok(realm_id_typed) = cokret_sdk::RealmId::new(realm_id.to_owned()) else {
        tracing::warn!(%realm_id, "bootstrap_realm_member_index: invalid realm_id shape");
        return;
    };
    let Ok(actor_typed) = cokret_sdk::Did::new(actor.to_owned()) else {
        tracing::warn!(%actor, "bootstrap_realm_member_index: invalid actor DID");
        return;
    };
    let payload_object = object
        .get("payload")
        .and_then(|payload| payload.get("object"));
    let title = payload_object
        .and_then(|create_object| create_object.get("title"))
        .and_then(Value::as_str)
        .unwrap_or("");
    let summary = payload_object
        .and_then(|create_object| create_object.get("summary"))
        .and_then(Value::as_str)
        .map(ToOwned::to_owned);
    let discoverability = payload_object
        .and_then(|create_object| create_object.get("default_discoverability"))
        .and_then(Value::as_str)
        .unwrap_or("invite_only")
        .to_owned();
    let history_visibility = payload_object
        .and_then(|create_object| create_object.get("history_visibility"))
        .and_then(Value::as_str)
        .unwrap_or("shared")
        .to_owned();
    let encryption_profile = payload_object
        .and_then(|create_object| create_object.get("encryption_profile"))
        .and_then(Value::as_str)
        .map(ToOwned::to_owned);
    let history_sharing_policy = payload_object
        .and_then(|create_object| create_object.get("history_sharing_policy"))
        .cloned();
    let history_sharing_policy_digest = history_sharing_policy
        .as_ref()
        .and_then(canonical_value_digest);
    let preview_policy = payload_object
        .and_then(|create_object| create_object.get("preview_policy"))
        .cloned();
    let preview_policy_digest = preview_policy.as_ref().and_then(canonical_value_digest);
    let plaintext_visible_services = object
        .get("payload")
        .and_then(|payload| payload.get("plaintext_visible_services"))
        .or_else(|| {
            payload_object.and_then(|create_object| create_object.get("plaintext_visible_services"))
        })
        .and_then(Value::as_array)
        .map(|services| {
            services
                .iter()
                .filter_map(|service| service.as_str().map(ToOwned::to_owned))
                .collect()
        })
        .unwrap_or_default();
    let minimal_metadata_realm =
        payload_object.is_some_and(crate::kinds::payload_declares_minimal_metadata_realm);
    let mut entry = crate::state::RealmDirectoryEntry::new(realm_id_typed.clone(), title);
    entry.description = summary.clone();
    entry.public = discoverability == "public";
    entry.members.insert(actor_typed);
    if let Ok(mut realms) = state.realms.lock() {
        realms.upsert(entry);
    }
    let meta = crate::state::RealmMetaRecord {
        owner: actor.to_owned(),
        deleted: false,
        discoverability,
        history_visibility,
        history_sharing_policy,
        history_sharing_policy_digest,
        preview_policy,
        preview_policy_digest,
        encryption_profile,
        plaintext_visible_services,
        minimal_metadata_realm,
        created_at: super::now(),
        updated_at: super::now(),
    };
    if let Err(error) = state.persistence.realm_meta().put(realm_id, &meta).await {
        tracing::error!(%error, %realm_id, "bootstrap_realm_member_index: failed to persist Realm meta record");
    }
}

fn canonical_value_digest(value: &Value) -> Option<String> {
    let bytes = canonical::canonical_json_bytes(value).ok()?;
    Some(canonical::sha256_digest(bytes))
}

/// CKP-0007 — recursively scan `value` for the first key listed in the SDK's
/// [`cokret_sdk::forbidden_wire_fields::FORBIDDEN_WIRE_FIELDS`] hard-reject
/// set. Receivers MUST refuse the legacy field names outright. Returns the
/// offending field name when one is present, otherwise `None`.
///
/// The walk descends into nested objects and arrays so a forbidden key carried
/// inside `patch`, `object`, or any other sub-tree also fails. Callers that
/// need to inspect only the top-level payload object can pass
/// `value.as_object()` directly — the recursive form handles both shapes.
fn first_forbidden_wire_field(value: Option<&Value>) -> Option<&'static str> {
    fn walk(value: &Value) -> Option<&'static str> {
        match value {
            Value::Object(map) => {
                for (key, child) in map {
                    if cokret_sdk::forbidden_wire_fields::is_forbidden_wire_field(key) {
                        // Translate the wire key back to the SDK's canonical
                        // &'static str so the caller's error message uses a
                        // stable identifier.
                        return cokret_sdk::forbidden_wire_fields::FORBIDDEN_WIRE_FIELDS
                            .iter()
                            .copied()
                            .find(|name| *name == key.as_str());
                    }
                    if let Some(found) = walk(child) {
                        return Some(found);
                    }
                }
                None
            }
            Value::Array(items) => items.iter().find_map(walk),
            _ => None,
        }
    }
    value.and_then(walk)
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
                    "event references must use the ck:event: typed prefix",
                ));
            }
            Ok(event_id.to_owned())
        })
        .collect()
}

/// SEC-04 — `did_inception` evidence ref roles. Inception-bootstrap
/// self-authorizations (`identity/key-management.md` §5.0.1 step 4) attach a
/// `refs[]` entry with `role="did_inception"` (`critical=true`) pointing at the
/// `did:webvh` entry-0 versionId. Its presence is what distinguishes an
/// inception-key-signed control event from the post-bootstrap §5.1 path (step 7
/// / §5.0.3: subsequent `ck.device.authorize` MUST be `authorized_by` an
/// already-anchored device and therefore carry no `did_inception` ref).
const DID_INCEPTION_REF_ROLE: &str = "did_inception";

/// SEC-04 — receiver-side independent enforcement of the 24h inception-key
/// online-window hard cap (`identity/key-management.md` §5.0.1 step 5,
/// "接收端独立 enforce").
///
/// Only inception-key-signed control events are gated: a
/// `ck.device.authorize` / `ck.session.grant` whose envelope `refs[]` carries a
/// `role="did_inception"` evidence ref. For those, the receiver anchors on the
/// `did:webvh` entry-0 `versionTime` (the verifiable bootstrap timestamp) and
/// computes the inception-key age against its own local clock via the SDK
/// [`cokret_sdk::model::inception_key_age_exceeded`]; an age past the 24h hard
/// cap is rejected with reason `inception_key_window_exceeded`, regardless of
/// any longer deployment-self-reported window.
///
/// **Conservative fail-closed (mirrors `webvh_validation` `versionTime`
/// handling):** when the gate applies but the entry-0 `versionTime` anchor is
/// missing / unparseable / the local webvh log is absent, the event is rejected
/// rather than admitted. We never substitute `now` to "pass" the check.
///
/// **Honest scope boundary:** the anchor is read from this server's *locally
/// hosted / cached* `did:webvh` log (`persistence.webvh().list_log_events`).
/// When this soland is the principal's webvh host (the v1-core
/// inception-bootstrap topology, since the genesis `ck.device.authorize` is
/// submitted to the same principal server that wrote entry-0) the anchor is
/// available and the gate runs at submit time. When the principal's webvh log
/// is hosted elsewhere and not cached here, the gate fails closed (rejects the
/// inception-key-signed event), which is the conservative SEC-04 default — it
/// never silently admits.
async fn enforce_inception_key_online_window(
    state: &AppState,
    parsed: &ValidatedEventEnvelope,
    envelope: &Value,
) -> Result<(), SubmitOneError> {
    // Only inception-key-signed control events are subject to the 24h cap.
    if parsed.kind != "ck.device.authorize" && parsed.kind != "ck.session.grant" {
        return Ok(());
    }
    let Some(object) = envelope.as_object() else {
        return Ok(());
    };
    // Post-bootstrap §5.1 device authorizations carry no `did_inception` ref
    // (they are `authorized_by` an anchored device), so they are not gated.
    if !envelope_has_did_inception_ref(object) {
        return Ok(());
    }

    // Resolve the principal DID whose entry-0 anchors the inception key. For an
    // inception-bootstrap self-authorization the `actor_id` IS the principal;
    // we also accept an explicit `payload.principal_id` / `payload.subject` for
    // session grants. Fail closed when no `did:webvh` principal can be derived.
    let principal_did = inception_principal_did(object, &parsed.actor_id);
    let Some(principal_did) = principal_did else {
        return Err(SubmitOneError::new(
            StatusCode::FORBIDDEN,
            crate::error::reasons::INCEPTION_KEY_WINDOW_EXCEEDED,
            "inception-key-signed control event lacks a resolvable did:webvh principal for the \
             entry-0 online-window anchor",
        ));
    };

    // Anchor on the locally hosted/cached entry-0 `versionTime`. Missing log,
    // missing entry-0, or an unparseable timestamp all fail closed.
    let anchor = inception_bootstrap_anchor(state, &principal_did).await;
    let Some(bootstrap_ts) = anchor else {
        return Err(SubmitOneError::new(
            StatusCode::FORBIDDEN,
            crate::error::reasons::INCEPTION_KEY_WINDOW_EXCEEDED,
            "inception-bootstrap entry-0 versionTime anchor is missing or unparseable; refusing to \
             admit an inception-key-signed control event without a verifiable online-window anchor",
        ));
    };

    if cokret_sdk::model::inception_key_age_exceeded(bootstrap_ts, now()) {
        return Err(SubmitOneError::new(
            StatusCode::FORBIDDEN,
            crate::error::reasons::INCEPTION_KEY_WINDOW_EXCEEDED,
            "inception key online window exceeded the 24h protocol hard cap",
        ));
    }
    Ok(())
}

/// SEC-04 — `true` when the envelope `refs[]` carries a `role="did_inception"`
/// evidence ref (the inception-bootstrap self-authorization marker).
fn envelope_has_did_inception_ref(object: &serde_json::Map<String, Value>) -> bool {
    object
        .get("refs")
        .and_then(Value::as_array)
        .is_some_and(|refs| {
            refs.iter().any(|reference| {
                reference
                    .get("role")
                    .and_then(Value::as_str)
                    .is_some_and(|role| role == DID_INCEPTION_REF_ROLE)
            })
        })
}

/// SEC-04 — derive the principal DID whose `did:webvh` entry-0 anchors the
/// inception key, preferring an explicit `payload.principal_id` / `subject`,
/// falling back to the envelope `actor_id` (the self-authorization case). Only
/// `did:webvh` principals carry an entry-0 anchor in this gate; other methods
/// return `None` (handled as fail-closed by the caller).
fn inception_principal_did(
    object: &serde_json::Map<String, Value>,
    actor_id: &str,
) -> Option<String> {
    let payload = object.get("payload").and_then(Value::as_object);
    let candidate = payload
        .and_then(|payload| {
            payload
                .get("principal_id")
                .or_else(|| payload.get("subject"))
                .and_then(Value::as_str)
        })
        .unwrap_or(actor_id);
    candidate
        .starts_with("did:webvh:")
        .then(|| candidate.to_owned())
}

/// SEC-04 — read the verifiable inception-bootstrap timestamp: the `versionTime`
/// of the lowest-`seq` (entry-0 / genesis) record in this server's locally
/// hosted/cached `did:webvh` log for `did`. Returns `None` (fail-closed for the
/// caller) when the log is absent, has no genesis entry, or the genesis
/// `versionTime` is missing / not RFC3339.
async fn inception_bootstrap_anchor(
    state: &AppState,
    did: &str,
) -> Option<chrono::DateTime<chrono::Utc>> {
    let events = state.persistence.webvh().list_log_events(did).await.ok()?;
    let genesis = events.iter().min_by_key(|record| record.seq)?;
    let version_time = genesis
        .operation
        .get("versionTime")
        .and_then(Value::as_str)?;
    chrono::DateTime::parse_from_rfc3339(version_time)
        .ok()
        .map(|parsed| parsed.with_timezone(&chrono::Utc))
}

fn event_semantic_refs(
    object: &serde_json::Map<String, Value>,
    _state: &AppState,
    max_len: usize,
) -> Result<Vec<String>, EventValidationError> {
    let Some(value) = object.get("refs") else {
        return Ok(Vec::new());
    };
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
                    "authorized_by refs must use the ck:event: typed prefix",
                ));
            }
            authorized_refs.push(id);
        }
    }
    Ok(authorized_refs)
}

fn event_canonical_source(envelope: &Value) -> Value {
    // Per cokret-spec conformance-vectors.md §1.6: both the event digest and
    // every proof's `event_digest` MUST be derived from canonical event bytes
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

fn event_canonical_bytes(envelope: &Value) -> Result<Vec<u8>, EventValidationError> {
    canonical::canonical_json_bytes(&event_canonical_source(envelope)).map_err(|_| {
        event_validation_error(
            StatusCode::BAD_REQUEST,
            "invalid_event_envelope",
            "event envelope cannot be canonicalized",
        )
    })
}

fn event_digest(bytes: &[u8]) -> String {
    format!("sha256:{}", sha256_hex(bytes))
}

fn is_valid_event_id(value: &str) -> bool {
    let Some(rest) = value.strip_prefix("ck:event:") else {
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
    status: EventsSubmitStatus,
    event_id: String,
) -> SubmittedEventOutcome {
    let duplicate = matches!(status, EventsSubmitStatus::Duplicate);
    SubmittedEventOutcome {
        event_id: event_id.clone(),
        duplicate,
        outcome: events_submit_outcome(
            status,
            vec![event_id.clone()],
            if duplicate {
                vec![event_id]
            } else {
                Vec::new()
            },
            Vec::new(),
            Some(super::sync::sync_token_for_state(state)),
        ),
    }
}

fn projection_operation_from_event(
    parsed: &ValidatedEventEnvelope,
    envelope: &Value,
) -> Option<Operation> {
    if super::operations::operation_schema_for_kind(&parsed.kind).is_none() {
        tracing::debug!(kind = %parsed.kind, "projection: no schema for kind");
        return None;
    }
    let realm_id_raw = parsed.realm_id.clone();
    let realm_id = match RealmId::new(realm_id_raw.clone()) {
        Ok(value) => value,
        Err(error) => {
            tracing::debug!(kind = %parsed.kind, realm_id = %realm_id_raw, %error, "projection: RealmId::new failed");
            return None;
        }
    };
    let mut payload = envelope
        .get("payload")
        .cloned()
        .unwrap_or_else(|| json!({}));
    let Some(payload_object) = payload.as_object_mut() else {
        tracing::debug!(kind = %parsed.kind, "projection: payload not an object");
        return None;
    };
    payload_object
        .entry("event_id".to_owned())
        .or_insert_with(|| Value::String(parsed.event_id.clone()));
    payload_object
        .entry("sender".to_owned())
        .or_insert_with(|| Value::String(parsed.actor_id.clone()));
    if parsed.kind == kinds::CK_RELATION_CREATE {
        normalize_relation_create_payload(payload_object, parsed);
    }
    if let Some(target_ref) = payload_object
        .get("target_ref")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
    {
        if target_ref.starts_with("ck:flow:") {
            payload_object
                .entry("flow_id".to_owned())
                .or_insert_with(|| Value::String(target_ref.clone()));
        }
        if target_ref.starts_with("ck:morph:") {
            payload_object
                .entry("morph_id".to_owned())
                .or_insert_with(|| Value::String(target_ref));
        }
    }
    if !payload_object.contains_key("thread_id")
        && let Some(flow_id) = payload_object
            .get("flow_id")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
    {
        payload_object.insert("thread_id".to_owned(), Value::String(flow_id));
    }
    if matches!(
        parsed.kind.as_str(),
        "ck.consent.grant" | "ck.consent.revoke"
    ) {
        payload_object
            .entry("actor_seq".to_owned())
            .or_insert_with(|| Value::from(parsed.actor_seq));
    }
    if parsed.kind == kinds::CK_MORPH_SCHEMA_MIGRATE {
        if let Some(authorization_ref) = parsed.authorized_refs.first() {
            payload_object
                .entry("authorization_ref".to_owned())
                .or_insert_with(|| Value::String(authorization_ref.clone()));
        }
        payload_object
            .entry("capability_action".to_owned())
            .or_insert_with(|| Value::String("ck.morph.schema.migrate".to_owned()));
    }
    if let Some(anchor_ref) = envelope.get("anchor_ref").and_then(Value::as_str) {
        payload_object
            .entry("anchor_ref".to_owned())
            .or_insert_with(|| Value::String(anchor_ref.to_owned()));
    }

    let Some(operation_id) = event_operation_id(envelope, &parsed.event_id) else {
        tracing::debug!(kind = %parsed.kind, event_id = %parsed.event_id, "projection: event_operation_id failed");
        return None;
    };
    let mut operation = Operation::create(
        operation_id,
        realm_id,
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

fn normalize_relation_create_payload(
    payload_object: &mut serde_json::Map<String, Value>,
    parsed: &ValidatedEventEnvelope,
) {
    if let Some(relation) = payload_object
        .get("relation")
        .and_then(Value::as_object)
        .cloned()
    {
        if let Some(id) = relation
            .get("id")
            .or_else(|| relation.get("relation_id"))
            .and_then(Value::as_str)
        {
            payload_object
                .entry("relation_id".to_owned())
                .or_insert_with(|| Value::String(id.to_owned()));
        }
        if let Some(relation_kind) = relation
            .get("relation_kind")
            .or_else(|| relation.get("kind"))
            .and_then(Value::as_str)
        {
            payload_object
                .entry("relation_kind".to_owned())
                .or_insert_with(|| Value::String(relation_kind.to_owned()));
        }
        for field in ["from_ref", "to_ref", "rank", "fields"] {
            if let Some(value) = relation.get(field) {
                payload_object
                    .entry(field.to_owned())
                    .or_insert_with(|| value.clone());
            }
        }
    }

    if !payload_object.contains_key("relation_id")
        && !payload_object.contains_key("id")
        && let Some(suffix) = parsed.event_id.strip_prefix("ck:event:")
    {
        payload_object.insert(
            "relation_id".to_owned(),
            Value::String(format!("ck:relation:{suffix}")),
        );
    }
}

fn event_operation_id(envelope: &Value, event_id: &str) -> Option<OperationId> {
    // Prefer the client-supplied alias when it's a valid OperationId
    // (`ck:operation:<uuid v7>` per `cokret-rust-sdk/identifiers`).
    // Older yougen builds shipped the event_id (ck:event:) verbatim in
    // this slot; soland MUST NOT silently drop projection for such
    // events ── fall through to the event_id-derived form so the
    // projection chain (`project_accepted_operations` →
    // `project_membership_operation` → RealmInviteRecord write) still
    // runs. The alias-when-present remains the dedupe key for clients
    // that submit it correctly.
    if let Some(alias) = envelope
        .get("unsigned")
        .and_then(Value::as_object)
        .and_then(|unsigned| unsigned.get("local_operation_idempotency_alias"))
        .and_then(Value::as_str)
        && let Ok(operation_id) = OperationId::new(alias.to_owned())
    {
        return Some(operation_id);
    }
    let suffix = event_id.strip_prefix("ck:event:")?;
    OperationId::new(format!("ck:operation:{suffix}")).ok()
}

/// CKP-0007 — resolve the canonical `effective_scope` for an Event
/// Envelope on read. Returns `Some(circle_id)` when the envelope (or its
/// payload) names a Circle scope, `Some("realm:<realm_id>")` when the
/// scope is the Realm default, or `None` when neither can be derived.
fn effective_scope_for_envelope(envelope: &Value) -> Option<String> {
    let object = envelope.as_object()?;
    // Server-stamped authoritative scope. For messages this is set at ingest
    // from the message's Flow (see submit_event_value); it always wins.
    if let Some(scope) = object.get("effective_scope").and_then(Value::as_str) {
        return Some(scope.to_owned());
    }
    // Messages NEVER carry their own scope (spec: `scope_circle_id` is a Flow
    // field, not a message field). A message's effective circle-scope is the
    // server-stamped `effective_scope` above, derived from its Flow at ingest.
    // There is deliberately no client-supplied fallback, so a message cannot
    // spoof its own visibility scope.
    if object.get("kind").and_then(Value::as_str) == Some(kinds::CK_MESSAGE_CREATE) {
        return None;
    }
    // Non-message events (e.g. ck.flow.create / ck.flow.update) legitimately
    // carry the object's own `scope_circle_id`.
    let payload = object.get("payload").and_then(Value::as_object)?;
    if let Some(scope_circle_id) = payload.get("scope_circle_id").and_then(Value::as_str) {
        return Some(scope_circle_id.to_owned());
    }
    if let Some(payload_object) = payload.get("object").and_then(Value::as_object)
        && let Some(scope_circle_id) = payload_object
            .get("scope_circle_id")
            .and_then(Value::as_str)
    {
        return Some(scope_circle_id.to_owned());
    }
    None
}

pub(super) fn event_view_for_state(
    state: &AppState,
    record: &CanonicalEventRecord,
) -> JsonResult<EventView> {
    json_ok(EventView {
        event: sdk_event_for_state(state, record)?,
        visibility: event_visibility_metadata(state, record),
        receipts: Vec::new(),
    })
}

pub(super) fn sdk_event_for_state(
    state: &AppState,
    record: &CanonicalEventRecord,
) -> Result<Event, AppError> {
    sdk_event_from_record(
        record,
        retention_tombstone_for_event(state, &record.event_id),
    )
}

fn sdk_event_from_record(
    record: &CanonicalEventRecord,
    tombstone: Option<crate::state::RetentionTombstoneRecord>,
) -> Result<Event, AppError> {
    let object = record
        .envelope
        .as_object()
        .ok_or_else(|| AppError::internal("stored event envelope is not an object"))?;
    let realm_id = canonical_realm_id_for_record(record)
        .ok_or_else(|| AppError::internal("stored event missing realm_id"))?;
    let realm_id = RealmId::new(realm_id).map_err(|error| AppError::internal(error.to_string()))?;
    let event_id = EventId::new(record.event_id.clone())
        .map_err(|error| AppError::internal(error.to_string()))?;
    let actor_id = cokret_sdk::Did::new(record.actor_id.clone())
        .map_err(|error| AppError::internal(error.to_string()))?;
    let created_at = object
        .get("created_at")
        .and_then(Value::as_str)
        .and_then(|value| DateTime::parse_from_rfc3339(value).ok())
        .map(|value| value.with_timezone(&Utc))
        .unwrap_or(record.received_at);
    let hlc = object
        .get("hlc")
        .and_then(Value::as_str)
        .and_then(|value| Hlc::new(value.to_owned()).ok())
        .unwrap_or_else(|| synthetic_hlc(record.received_at));
    let mut payload = object.get("payload").cloned().unwrap_or_else(|| json!({}));
    let mut unsigned: BTreeMap<String, Value> = object
        .get("unsigned")
        .cloned()
        .and_then(|value| serde_json::from_value(value).ok())
        .unwrap_or_default();
    if let Some(tombstone) = tombstone {
        payload = retention_tombstone_payload_value(&payload, &tombstone);
        unsigned.insert("retention_tombstone".to_owned(), json!(true));
        unsigned.insert("retention_state".to_owned(), json!("tombstoned"));
        unsigned.insert(
            "retention_reason".to_owned(),
            json!(tombstone.reason.as_str()),
        );
        unsigned.insert(
            "retention_expired_at".to_owned(),
            json!(tombstone.expired_at.to_rfc3339()),
        );
        unsigned.insert(
            "retention_tombstoned_at".to_owned(),
            json!(tombstone.tombstoned_at.to_rfc3339()),
        );
        unsigned.insert(
            "retention_anchor_preserved".to_owned(),
            json!(tombstone.anchored),
        );
        unsigned.insert("physical_delete".to_owned(), json!(false));
    }
    Ok(Event {
        event_id,
        kind: record.kind.clone(),
        realm_id: realm_id.clone(),
        actor_id,
        actor_seq: record.actor_seq,
        created_at,
        hlc,
        prev_refs: event_id_list(object.get("prev_refs"))?,
        effective_scope: sdk_effective_scope(record, &realm_id),
        refs: event_refs(object.get("refs")),
        preconditions: json_array_field(object, "preconditions"),
        effects: json_array_field(object, "effects"),
        anchor_ref: object
            .get("anchor_ref")
            .and_then(Value::as_str)
            .and_then(|value| cokret_sdk::AnchorId::new(value.to_owned()).ok()),
        requirements: object
            .get("requirements")
            .cloned()
            .and_then(|value| serde_json::from_value(value).ok())
            .unwrap_or_default(),
        redacts: object
            .get("redacts")
            .and_then(Value::as_str)
            .and_then(|value| EventId::new(value.to_owned()).ok()),
        content: payload,
        executed_by: object
            .get("executed_by")
            .and_then(Value::as_str)
            .and_then(|value| cokret_sdk::Did::new(value.to_owned()).ok()),
        authorization_ref: object
            .get("authorization_ref")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned),
        actor_kind: object
            .get("actor_kind")
            .cloned()
            .and_then(|value| serde_json::from_value(value).ok()),
        unsigned,
        proofs: sdk_event_proofs(record, object, created_at)?,
    })
}

fn event_visibility_metadata(state: &AppState, record: &CanonicalEventRecord) -> Value {
    let mut metadata = json!({
        "event_id": record.event_id.clone(),
        "actor_id": record.actor_id.clone(),
        "actor_seq": record.actor_seq,
        "realm_id": canonical_realm_id_for_record(record),
        "kind": record.kind.clone(),
        "schema_id": record.schema_id.clone(),
        "canonical_digest": record.canonical_digest.clone(),
        "received_at": record.received_at,
    });
    if let Some(scope) = effective_scope_for_envelope(&record.envelope) {
        metadata["effective_scope"] = json!(scope);
    }
    if let Some(tombstone) = retention_tombstone_for_event(state, &record.event_id) {
        metadata["retention_state"] = json!("tombstoned");
        metadata["retention_reason"] = json!(tombstone.reason.as_str());
        metadata["retention_expired_at"] = json!(tombstone.expired_at.to_rfc3339());
        metadata["retention_tombstoned_at"] = json!(tombstone.tombstoned_at.to_rfc3339());
        metadata["retention_anchor_preserved"] = json!(tombstone.anchored);
        metadata["physical_delete"] = json!(false);
    }
    metadata
}

fn event_id_list(value: Option<&Value>) -> Result<Vec<EventId>, AppError> {
    let Some(values) = value.and_then(Value::as_array) else {
        return Ok(Vec::new());
    };
    values
        .iter()
        .filter_map(Value::as_str)
        .map(|value| {
            EventId::new(value.to_owned()).map_err(|error| AppError::internal(error.to_string()))
        })
        .collect()
}

fn event_refs(value: Option<&Value>) -> Vec<EventRef> {
    value
        .cloned()
        .and_then(|value| serde_json::from_value(value).ok())
        .unwrap_or_default()
}

fn json_array_field<T>(object: &serde_json::Map<String, Value>, field: &str) -> Vec<T>
where
    T: serde::de::DeserializeOwned,
{
    object
        .get(field)
        .cloned()
        .and_then(|value| serde_json::from_value(value).ok())
        .unwrap_or_default()
}

fn sdk_effective_scope(
    record: &CanonicalEventRecord,
    realm_id: &RealmId,
) -> Option<cokret_sdk::model::EffectiveScope> {
    if let Some(scope) = record
        .envelope
        .get("effective_scope")
        .cloned()
        .and_then(|value| serde_json::from_value(value).ok())
    {
        return Some(scope);
    }
    match effective_scope_for_envelope(&record.envelope).as_deref() {
        Some(scope) if scope.starts_with("ck:circle:") => {
            cokret_sdk::CircleId::new(scope.to_owned())
                .ok()
                .map(|circle_id| cokret_sdk::model::EffectiveScope::Circle {
                    realm_id: realm_id.clone(),
                    circle_id,
                })
        }
        Some(scope) if scope.starts_with("realm:") => {
            Some(cokret_sdk::model::EffectiveScope::Realm {
                realm_id: realm_id.clone(),
            })
        }
        _ => None,
    }
}

fn synthetic_hlc(received_at: DateTime<Utc>) -> Hlc {
    let millis = received_at.timestamp_millis().max(0) as u64;
    Hlc::new(format!("{millis:012x}-0000-00000000")).expect("synthetic HLC is valid")
}

fn sdk_event_proofs(
    record: &CanonicalEventRecord,
    object: &serde_json::Map<String, Value>,
    created_at: DateTime<Utc>,
) -> Result<Vec<Proof>, AppError> {
    if let Some(proofs) = object
        .get("proofs")
        .cloned()
        .and_then(|value| serde_json::from_value::<Vec<Proof>>(value).ok())
        .filter(|proofs| !proofs.is_empty())
    {
        return Ok(proofs);
    }
    let proof = object
        .get("proofs")
        .and_then(Value::as_array)
        .and_then(|proofs| proofs.first())
        .and_then(Value::as_object);
    let verification_method = proof
        .and_then(|proof| proof.get("verification_method"))
        .and_then(Value::as_str)
        .unwrap_or("did:web:soland.local#dev")
        .to_owned();
    let domain = proof
        .and_then(|proof| proof.get("domain"))
        .or_else(|| object.get("domain"))
        .and_then(Value::as_str)
        .map(ToOwned::to_owned);
    let audience = proof
        .and_then(|proof| proof.get("audience"))
        .or_else(|| object.get("audience"))
        .and_then(sdk_audience);
    let event_digest = Hash::new(record.canonical_digest.clone())
        .map_err(|error| AppError::internal(error.to_string()))?;
    Ok(vec![Proof {
        kind: proof_kind::DETACHED_JWS.to_owned(),
        alg: proof
            .and_then(|proof| proof.get("alg"))
            .and_then(Value::as_str)
            .unwrap_or("EdDSA")
            .to_owned(),
        verification_method,
        event_digest,
        created_at,
        domain,
        audience,
        jws: proof
            .and_then(|proof| proof.get("jws").or_else(|| proof.get("detached_jws")))
            .and_then(Value::as_str)
            .unwrap_or("ZGV2..c2ln")
            .to_owned(),
    }])
}

fn sdk_audience(value: &Value) -> Option<Audience> {
    if let Some(single) = value.as_str() {
        return Some(Audience::Single(single.to_owned()));
    }
    value.as_array().map(|items| {
        Audience::Multiple(
            items
                .iter()
                .filter_map(Value::as_str)
                .map(ToOwned::to_owned)
                .collect(),
        )
    })
}

fn frontier_entry_is_newer(
    latest: &BTreeMap<String, (DateTime<Utc>, String)>,
    key: &str,
    record: &CanonicalEventRecord,
) -> bool {
    latest.get(key).is_none_or(|(received_at, event_id)| {
        record.received_at > *received_at
            || (record.received_at == *received_at && record.event_id.as_str() > event_id.as_str())
    })
}

pub(super) fn canonical_realm_id_for_record(record: &CanonicalEventRecord) -> Option<String> {
    record
        .envelope
        .get("realm_id")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .or_else(|| record.realm_id.as_deref().map(normalize_persisted_realm_id))
}

fn normalize_persisted_realm_id(id: &str) -> String {
    id.to_owned()
}

pub(super) async fn event_visible_to_session(
    state: &AppState,
    record: &CanonicalEventRecord,
    session: &SessionRecord,
) -> bool {
    if record.actor_id == session.actor {
        return true;
    }
    match canonical_realm_id_for_record(record) {
        Some(realm_id) => {
            realm_event_visible_to_session(
                state,
                &realm_id,
                record.received_at,
                Some(&record.actor_id),
                Some(session),
            )
            .await
                && circle_event_visible_to_session(state, record, session)
        }
        None => false,
    }
}

fn circle_event_visible_to_session(
    state: &AppState,
    record: &CanonicalEventRecord,
    session: &SessionRecord,
) -> bool {
    let Some(scope_circle_id) = effective_scope_for_envelope(&record.envelope)
        .filter(|scope| scope.starts_with("ck:circle:"))
    else {
        return true;
    };
    if record.actor_id == session.actor {
        return true;
    }
    state
        .projection
        .lock()
        .expect("projection mutex")
        .circle_scope_visible_to_actor(&scope_circle_id, &session.actor)
}

/// Scan the durable Event store for the most
/// recent `ck.realm.read_receipt_policy` event in `realm_id` and return
/// `(disclosure, visibility, scope_overrides_allowed)` from its payload.
/// Returns `None` when no policy event has been written for this Realm —
/// caller treats that as the spec default `Optional` / `Members` /
/// `scope_overrides_allowed=true`.
///
/// Used by future ephemeral `ck.receipt.read` fanout handlers to enforce
/// the policy: when `disclosure="disabled"`, drop the receipt and return
/// HTTP 403 with `error.code` `policy_violation`. When `visibility="private"`,
/// fanout only to the original sender of the referenced event.
///
/// **Note**: this is a linear scan of the durable event store. For the
/// production fanout path it should be projected into `AppState` once the
/// reducer kind delegates from `Ignored` to a real projection.
pub async fn effective_read_receipt_policy_for_realm(
    state: &AppState,
    realm_id: &str,
) -> Option<(String, String, bool)> {
    // Cell-keyed fast path. The Move/Anchor pipeline writes the
    // `ck.component.realm.read_receipt_policy.v1` resolved CasRegister
    // value into `ProjectionState::cells` after every apply_anchor; we
    // read directly from there. (R1.2 renamed the cell family from
    // `ck.component.realm.read_receipt_policy.v1` along with the event
    // kind.)
    if let Ok(proj) = state.projection.lock() {
        let cell_id = cokret_sdk::CellRef::new(format!(
            "ck:cell:ck.component.realm.read_receipt_policy.v1:{realm_id}"
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
    let records = state.persistence.events().snapshot_all().await.ok()?;
    let mut latest: Option<&CanonicalEventRecord> = None;
    for record in &records {
        // CanonicalEventRecord uses `kind` (not event_kind) for the
        // canonical Cokret event kind string.
        if record.kind != "ck.realm.read_receipt_policy" {
            continue;
        }
        if canonical_realm_id_for_record(record).as_deref() != Some(realm_id) {
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

// ════════════════════════════════════════════════════════════════════════
// events.submit discriminated request + admission gates
// (spec B1.6 / T02 / T07 / T08 / T09 / T12 / T23).
// ════════════════════════════════════════════════════════════════════════

/// Spec B1.6 — discriminated `/_cokret/self/events` POST body. Single is the
/// pre-existing canonical Event Envelope; batch and federation are the new
/// typed shapes.
///
/// Wire-breaking: producers MUST use spec `events[]`; producers that
/// include the `service_binding_ref` are routed to [`Self::Federation`].
/// Client-account writes omit `service_binding_ref`; federation writes are
/// gated by federation authentication.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum SolandEventsSubmitRequestBody {
    /// Federation form — `service_binding_ref` is REQUIRED and all 6
    /// fields validated.
    Federation(EventsSubmitFederationRequestBody),
    /// Batch form — multiple envelopes, optional `idempotency_key`.
    Batch(cokret_sdk::EventsSubmitBatchRequestBody),
    /// Single Event Envelope (legacy / dominant shape).
    Single(Value),
}

impl SolandEventsSubmitRequestBody {
    /// Classify an incoming JSON body without consuming it. Returns the
    /// discriminator name for tracing / metrics.
    #[allow(dead_code)]
    pub fn shape(body: &Value) -> &'static str {
        if body.get("service_binding_ref").is_some() {
            "federation"
        } else if body.get("events").is_some() {
            "batch"
        } else {
            "single"
        }
    }

    /// Spec B1.6 — validate the `service_binding_ref` carried on a
    /// federation submit. All 6 fields MUST be populated and well-shaped
    /// per SDK typed validators (already enforced by deserialisation); we
    /// additionally reject `membership_frontier` and
    /// `delivery_binding_frontier` if they are non-empty arrays containing
    /// duplicates.
    pub fn validate_federation_binding(
        req: &EventsSubmitFederationRequestBody,
    ) -> Result<(), (&'static str, String)> {
        let binding = &req.service_binding_ref;
        for (name, frontier) in [
            ("membership_frontier", &binding.membership_frontier),
            (
                "delivery_binding_frontier",
                &binding.delivery_binding_frontier,
            ),
        ] {
            let mut seen = std::collections::BTreeSet::new();
            for entry in frontier {
                if !seen.insert(entry.as_str()) {
                    return Err((
                        cokret_sdk::ERROR_CODE_SCHEMA_VIOLATION,
                        format!("{name} contains duplicate entry {:?}", entry.as_str()),
                    ));
                }
            }
        }
        if binding.destination_service_type.trim().is_empty() {
            return Err((
                cokret_sdk::ERROR_CODE_SCHEMA_VIOLATION,
                "service_binding_ref.destination_service_type MUST be a non-empty string"
                    .to_owned(),
            ));
        }
        Ok(())
    }
}

/// Reject any event kind that is ephemeral or receipt-object-only at the
/// `ck.self.events.submit` entrypoint. Spec T02 + T23.
///
/// Returns the canonical [`ErrorCode`] + human reason when the kind MUST be
/// rejected; returns `None` when the kind is fine to forward to the
/// existing durable-event validator pipeline.
pub fn events_submit_pre_admit_check(kind: &str) -> Option<(ErrorCode, &'static str)> {
    if cokret_sdk::events::is_ephemeral_kind(kind) {
        return Some((
            ErrorCode::SchemaViolation,
            "ephemeral kind MUST be carried via ck.schema.ephemeral_envelope.v1 \
             (broadcast forms) or ck.schema.device_message.v1 \
             (ck.key.verification.* to-device); not durable ck.self.events.submit",
        ));
    }
    if cokret_sdk::events::is_receipt_object_only(kind) {
        return Some((
            ErrorCode::SchemaViolation,
            "ck.event_batch_receipt is a receipt object only; \
             never accepted as Event.kind",
        ));
    }
    if kind == crate::kinds::CK_MORPH_SCHEMA_MIGRATE {
        return Some((
            ErrorCode::SchemaViolation,
            "ck.morph.schema_migrate is not admitted until its reducer projection is implemented",
        ));
    }
    None
}

/// Reject any non-audit-class write on a Realm whose lifecycle state is
/// terminal (`ck.realm.tombstone` or `ck.realm.destroy` applied). Spec T07.
///
/// Returns `Some((ErrorCode::RealmTerminalState, reason))` when the write
/// MUST be rejected; `None` otherwise.
pub fn terminal_realm_check(
    realm_in_terminal_state: bool,
    kind: &str,
) -> Option<(ErrorCode, &'static str)> {
    if realm_in_terminal_state && !crate::kinds::is_audit_kind(kind) {
        return Some((
            ErrorCode::RealmTerminalState,
            "Realm has reached ck.realm.tombstone or ck.realm.destroy \
             terminal state; only audit-class events are accepted",
        ));
    }
    None
}

fn policy_components_value_from_state_payload(payload: &Value) -> &Value {
    payload.get("value").unwrap_or(payload)
}

/// `ck.cross_signing.reset` payload trust-domain & reset_event_id check.
/// Spec T08.
///
/// Verification order MUST be:
/// 1. `payload.trust_domain` equals server's configured trust_domain (else
///    `cross_domain_replay_rejected`)
/// 2. `payload.reset_event_id` equals the enclosing Event's id (else `reset_event_id_mismatch`)
/// 3. signature check (existing path; not implemented here)
pub fn cross_signing_reset_replay_check(
    payload: &Value,
    event_id: &str,
    server_trust_domain: &str,
) -> Result<(), (ErrorCode, String)> {
    let payload_td = payload
        .get("trust_domain")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            (
                ErrorCode::SchemaViolation,
                "cross_signing.reset payload missing required `trust_domain` \
                 field (wire-breaking)"
                    .to_owned(),
            )
        })?;
    if TypedTrustDomainId::new(payload_td).is_err() {
        return Err((
            ErrorCode::SchemaViolation,
            "cross_signing.reset.trust_domain must match \
             ck:trust_domain:<scope> per spec"
                .to_owned(),
        ));
    }
    if payload_td != server_trust_domain {
        return Err((
            ErrorCode::CrossDomainReplayRejected,
            "cross_signing.reset.trust_domain does not match this \
             Principal Server's configured trust_domain"
                .to_owned(),
        ));
    }
    let payload_reset_event_id = payload
        .get("reset_event_id")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            (
                ErrorCode::SchemaViolation,
                "cross_signing.reset payload missing required \
                     `reset_event_id` field (wire-breaking)"
                    .to_owned(),
            )
        })?;
    if cokret_sdk::EventId::new(payload_reset_event_id).is_err() {
        return Err((
            ErrorCode::SchemaViolation,
            "cross_signing.reset.reset_event_id must be a ck:event:<uuidv7>".to_owned(),
        ));
    }
    if payload_reset_event_id != event_id {
        return Err((
            ErrorCode::ResetEventIdMismatch,
            "cross_signing.reset.reset_event_id must equal the enclosing \
             Event.event_id"
                .to_owned(),
        ));
    }
    Ok(())
}

/// Validate a `ck.realm.policy_components` payload. Spec T09 + T12 + SEC-03.
///
/// Checks (in order):
/// 1. `relaxed_window_max_ms <= 300_000` (T09 hard ceiling)
/// 2. `ck.profile.e2ee_relaxed.v1` not active with any audit compliance profile (T09 mutex)
/// 3. When `media_service_decrypts=true`, all governance bindings are present (T12).
/// 4. SEC-03 — when `media_service_decrypts=true`, independently recompute the
///    `discussion_metadata_digest` from the §10.5.1 rule 1–3 policy cell value
///    (`media_service_decrypts` + the authorised `plaintext_visible_services`) and fail closed with
///    `mls_governance_binding_stale` when it disagrees with the digest the projected governance
///    binding covers. This is the server-side mirror of `media-service-binding.md` §8.2 rule 5 /
///    negative vector `ck.vector.webrtc.media_plaintext_downgrade.v1` case (d): the fact that media
///    is service-decryptable MUST be derivable from member-visible metadata, not asserted out of
///    band. `binding_discussion_metadata_digest` is the digest the current epoch governance binding
///    covers, as projected from the realm's MLS cell; `None` means the binding carried no digest,
///    in which case only the legacy policy_root coverage gate (check 3) applies.
pub fn realm_policy_components_check(
    payload: &Value,
    active_profiles: &[String],
    media_plaintext_service_present: bool,
    mls_governance_binding_covers_policy_root: bool,
    binding_discussion_metadata_digest: Option<&str>,
) -> Result<(), (ErrorCode, String)> {
    if let Some(join_policy) = payload.get("join_policy") {
        crate::reducer::validate_join_policy_payload(join_policy).map_err(|reason| {
            (
                ErrorCode::SchemaViolation,
                format!("ck.realm.policy_components.join_policy invalid: {reason}"),
            )
        })?;
    }

    // (1) T09 — relaxed_window_max_ms ceiling.
    if let Some(window) = payload
        .pointer("/e2ee_relaxed/relaxed_window_max_ms")
        .and_then(Value::as_u64)
    {
        let window_u32 = u32::try_from(window).unwrap_or(u32::MAX);
        if cokret_sdk::validate_relaxed_window_ms(window_u32).is_err() {
            return Err((
                ErrorCode::RelaxedWindowExceedsCeiling,
                format!(
                    "e2ee_relaxed.relaxed_window_max_ms={window} exceeds absolute \
                     hard ceiling of {}ms",
                    cokret_sdk::EPHEMERAL_ABSOLUTE_HARD_CEILING_MS
                ),
            ));
        }
    }

    // (2) T09 — e2ee_relaxed.v1 mutex against audit compliance.
    let relaxed_active = active_profiles
        .iter()
        .any(|p| p == "ck.profile.e2ee_relaxed.v1")
        || payload
            .pointer("/e2ee_relaxed/profile")
            .and_then(Value::as_str)
            == Some("ck.profile.e2ee_relaxed.v1");
    let compliance_active = active_profiles
        .iter()
        .any(|p| crate::kinds::AUDIT_COMPLIANCE_PROFILES.contains(&p.as_str()));
    if relaxed_active && compliance_active {
        return Err((
            ErrorCode::E2eeRelaxedDisallowedInComplianceProfile,
            "ck.profile.e2ee_relaxed.v1 is mutually exclusive with audit \
             compliance profiles (attested_audit.e2ee.v1 / \
             disclosed_audit.e2ee.v1)"
                .to_owned(),
        ));
    }

    // (3) T12 — media_service_decrypts triple binding.
    if payload
        .get("media_service_decrypts")
        .and_then(Value::as_bool)
        == Some(true)
    {
        if !media_plaintext_service_present {
            return Err((
                ErrorCode::MediaPlaintextServiceNotAuthorised,
                "media_service_decrypts=true requires the SFU/MCU service DID \
                 to be listed in plaintext_visible_services[] with \
                 purpose=media_plaintext"
                    .to_owned(),
            ));
        }
        if !mls_governance_binding_covers_policy_root {
            return Err((
                ErrorCode::MlsGovernanceBindingStale,
                "media_service_decrypts=true requires the current MLS epoch \
                 governance binding's policy_root to cover the active media \
                 plaintext policy"
                    .to_owned(),
            ));
        }
        // (4) SEC-03 — independently recompute the discussion_metadata_digest
        // from the §10.5.1 rule 1–3 policy cell value and reject when it
        // disagrees with what the governance binding covers. We only have a
        // digest to compare against when the projected binding actually carried
        // one; absent it, check (3) above is the strongest server-side gate.
        if let Some(covered_digest) = binding_discussion_metadata_digest {
            let recomputed = recompute_media_decrypt_metadata_digest(payload).ok_or((
                ErrorCode::MlsGovernanceBindingStale,
                "media_service_decrypts=true policy cell could not be canonicalised \
                 for discussion_metadata_digest recomputation"
                    .to_owned(),
            ))?;
            let covered = cokret_sdk::Hash::new(covered_digest.to_owned()).map_err(|_| {
                (
                    ErrorCode::MlsGovernanceBindingStale,
                    "governance binding discussion_metadata_digest is not a valid \
                     sha256 hash"
                        .to_owned(),
                )
            })?;
            if cokret_sdk::model::verify_media_decrypt_metadata(&covered, &recomputed).is_err() {
                return Err((
                    ErrorCode::MlsGovernanceBindingStale,
                    "media_service_decrypts=true fact recomputed from the policy \
                     cell value does not match the governance binding's \
                     discussion_metadata_digest (media-service-binding.md §8.2 rule 5)"
                        .to_owned(),
                ));
            }
        }
    }
    Ok(())
}

/// SEC-03 — build a `cokret_sdk::model::MediaDecryptPolicyValue`
/// from a `ck.realm.policy_components` payload and derive its canonical
/// `discussion_metadata_digest`. Returns `None` only when the SDK's canonical
/// digest derivation fails (it never does for well-formed input), so callers
/// treat that as a fail-closed mismatch.
///
/// The recomputed value mirrors §10.5.1 rule 1 (`media_service_decrypts`) and
/// rule 2 (the `purpose=media_plaintext` service DIDs in
/// `plaintext_visible_services[]`). Service-DID extraction matches the shapes
/// [`payload_declares_media_plaintext_service`] already accepts (bare string,
/// `media_plaintext` sentinel, or `{purpose, service_did|did}` object) so the
/// digest input is consistent with the rule-2 presence gate; non-DID / sentinel
/// entries that carry no concrete DID are skipped because the SDK digest is
/// defined over concrete service DIDs.
fn recompute_media_decrypt_metadata_digest(payload: &Value) -> Option<cokret_sdk::Hash> {
    use cokret_sdk::model::{
        MediaDecryptPolicyValue, MediaPlaintextService, derive_media_decrypt_metadata_digest,
    };

    let media_service_decrypts = payload
        .get("media_service_decrypts")
        .and_then(Value::as_bool)
        .unwrap_or(false);

    let mut plaintext_visible_services = Vec::new();
    if let Some(services) = payload
        .pointer("/plaintext_visible_services")
        .and_then(Value::as_array)
    {
        for service in services {
            let did_str = match service {
                // A bare string entry is the service DID itself; the
                // `media_plaintext` sentinel carries no concrete DID.
                Value::String(value) if value != "media_plaintext" => Some(value.as_str()),
                Value::Object(object) => {
                    let purpose_ok =
                        object.get("purpose").and_then(Value::as_str) == Some("media_plaintext");
                    if purpose_ok {
                        object
                            .get("service_did")
                            .or_else(|| object.get("did"))
                            .and_then(Value::as_str)
                    } else {
                        None
                    }
                }
                _ => None,
            };
            if let Some(did_str) = did_str
                && let Ok(service_did) = cokret_sdk::Did::new(did_str.to_owned())
            {
                plaintext_visible_services.push(MediaPlaintextService { service_did });
            }
        }
    }

    let value = MediaDecryptPolicyValue {
        media_service_decrypts,
        plaintext_visible_services,
    };
    derive_media_decrypt_metadata_digest(&value).ok()
}

#[cfg(test)]
mod admission_tests {
    use super::*;

    #[test]
    fn ephemeral_kind_rejected_at_submit_entry() {
        for kind in [
            "ck.call.signal",
            "ck.presence",
            "ck.typing",
            "ck.receipt.read",
            "ck.key.verification.start",
            "ck.key.verification.accept",
            "ck.key.verification.mac",
        ] {
            let result = events_submit_pre_admit_check(kind);
            assert!(
                matches!(result, Some((ErrorCode::SchemaViolation, _))),
                "ephemeral kind {kind} must be rejected by submit entry"
            );
        }
    }

    #[test]
    fn receipt_object_kind_rejected_at_submit_entry() {
        assert!(matches!(
            events_submit_pre_admit_check("ck.event_batch_receipt"),
            Some((ErrorCode::SchemaViolation, _))
        ));
    }

    #[test]
    fn unimplemented_morph_schema_migrate_rejected_at_submit_entry() {
        assert!(matches!(
            events_submit_pre_admit_check(crate::kinds::CK_MORPH_SCHEMA_MIGRATE),
            Some((ErrorCode::SchemaViolation, _))
        ));
    }

    #[test]
    fn durable_kind_passes_submit_entry() {
        assert!(events_submit_pre_admit_check("ck.message.create").is_none());
        assert!(events_submit_pre_admit_check("ck.realm.create").is_none());
    }

    #[test]
    fn terminal_realm_blocks_non_audit_kind() {
        let blocked = terminal_realm_check(true, "ck.message.create");
        assert!(matches!(blocked, Some((ErrorCode::RealmTerminalState, _))));
        let audit_ok = terminal_realm_check(true, "ck.audit.accessed");
        assert!(audit_ok.is_none());
        let live_ok = terminal_realm_check(false, "ck.message.create");
        assert!(live_ok.is_none());
    }

    #[test]
    fn cross_signing_reset_replay_rejects_wrong_trust_domain() {
        let payload = json!({
            "trust_domain": "ck:trust_domain:other.example",
            "reset_event_id": "ck:event:01904100-0000-7000-8000-000000000001",
        });
        let err = cross_signing_reset_replay_check(
            &payload,
            "ck:event:01904100-0000-7000-8000-000000000001",
            "ck:trust_domain:soland.local",
        )
        .unwrap_err();
        assert_eq!(err.0, ErrorCode::CrossDomainReplayRejected);
    }

    #[test]
    fn cross_signing_reset_replay_rejects_wrong_event_id() {
        let payload = json!({
            "trust_domain": "ck:trust_domain:soland.local",
            "reset_event_id": "ck:event:01904100-0000-7000-8000-000000000002",
        });
        let err = cross_signing_reset_replay_check(
            &payload,
            "ck:event:01904100-0000-7000-8000-000000000001",
            "ck:trust_domain:soland.local",
        )
        .unwrap_err();
        assert_eq!(err.0, ErrorCode::ResetEventIdMismatch);
    }

    #[test]
    fn cross_signing_reset_replay_passes_when_matched() {
        let payload = json!({
            "trust_domain": "ck:trust_domain:soland.local",
            "reset_event_id": "ck:event:01904100-0000-7000-8000-000000000001",
        });
        cross_signing_reset_replay_check(
            &payload,
            "ck:event:01904100-0000-7000-8000-000000000001",
            "ck:trust_domain:soland.local",
        )
        .unwrap();
    }

    #[test]
    fn realm_policy_components_relaxed_window_ceiling() {
        let payload = json!({"e2ee_relaxed": {"relaxed_window_max_ms": 300_001 }});
        let err = realm_policy_components_check(&payload, &[], false, false, None).unwrap_err();
        assert_eq!(err.0, ErrorCode::RelaxedWindowExceedsCeiling);
    }

    #[test]
    fn realm_policy_components_e2ee_relaxed_compliance_mutex() {
        let payload = json!({"e2ee_relaxed": {"profile": "ck.profile.e2ee_relaxed.v1"}});
        let err = realm_policy_components_check(
            &payload,
            &["ck.profile.attested_audit.e2ee.v1".to_owned()],
            false,
            false,
            None,
        )
        .unwrap_err();
        assert_eq!(err.0, ErrorCode::E2eeRelaxedDisallowedInComplianceProfile);
    }

    #[test]
    fn realm_policy_components_media_plaintext_triple_binding() {
        let payload = json!({"media_service_decrypts": true});
        let err = realm_policy_components_check(&payload, &[], false, true, None).unwrap_err();
        assert_eq!(err.0, ErrorCode::MediaPlaintextServiceNotAuthorised);
        let err2 = realm_policy_components_check(&payload, &[], true, false, None).unwrap_err();
        assert_eq!(err2.0, ErrorCode::MlsGovernanceBindingStale);
        // No binding digest projected → only the policy_root coverage gate runs.
        realm_policy_components_check(&payload, &[], true, true, None).unwrap();
    }

    #[test]
    fn realm_policy_components_media_decrypt_digest_recompute_gate() {
        // SEC-03 — `media_service_decrypts=true` with an authorised plaintext
        // service: the digest the governance binding covers MUST equal the
        // digest recomputed from the policy cell value, else fail closed with
        // `mls_governance_binding_stale` (media-service-binding.md §8.2 rule 5).
        use cokret_sdk::model::{
            MediaDecryptPolicyValue, MediaPlaintextService, derive_media_decrypt_metadata_digest,
        };

        let service_did = "did:web:sfu.example";
        let payload = json!({
            "media_service_decrypts": true,
            "plaintext_visible_services": [
                {"purpose": "media_plaintext", "service_did": service_did}
            ]
        });

        // Honest digest derived from the same policy cell value the server sees.
        let honest = derive_media_decrypt_metadata_digest(&MediaDecryptPolicyValue {
            media_service_decrypts: true,
            plaintext_visible_services: vec![MediaPlaintextService {
                service_did: cokret_sdk::Did::new(service_did.to_owned()).unwrap(),
            }],
        })
        .unwrap();

        // Matching digest → accepted.
        realm_policy_components_check(&payload, &[], true, true, Some(honest.as_str())).unwrap();

        // Mismatching digest (attacker asserts decrypt fact not covered by the
        // member-visible metadata) → rejected, fail closed.
        let stale = format!("sha256:{}", "c".repeat(64));
        let err =
            realm_policy_components_check(&payload, &[], true, true, Some(&stale)).unwrap_err();
        assert_eq!(err.0, ErrorCode::MlsGovernanceBindingStale);

        // A malformed covered digest is also rejected (cannot be trusted).
        let err = realm_policy_components_check(&payload, &[], true, true, Some("not-a-hash"))
            .unwrap_err();
        assert_eq!(err.0, ErrorCode::MlsGovernanceBindingStale);
    }

    #[test]
    fn events_submit_shape_classifies_three_forms() {
        let single = json!({"event_id": "x"});
        let batch = json!({"events": []});
        let federation = json!({"events": [], "service_binding_ref": {"realm_id": "x"}});
        assert_eq!(SolandEventsSubmitRequestBody::shape(&single), "single");
        assert_eq!(SolandEventsSubmitRequestBody::shape(&batch), "batch");
        assert_eq!(
            SolandEventsSubmitRequestBody::shape(&federation),
            "federation"
        );
    }

    #[test]
    fn federation_binding_rejects_duplicate_frontier_entries() {
        let req = EventsSubmitFederationRequestBody {
            service_binding_ref: cokret_sdk::FederationServiceBindingRef {
                realm_id: RealmId::new("ck:realm:01904100-0000-7000-8000-000000000001").unwrap(),
                realm_policy_digest: cokret_sdk::Hash::new(format!("sha256:{}", "1".repeat(64)))
                    .unwrap(),
                membership_frontier: vec![
                    cokret_sdk::EventId::new("ck:event:01904100-0000-7000-8000-000000000001")
                        .unwrap(),
                    cokret_sdk::EventId::new("ck:event:01904100-0000-7000-8000-000000000001")
                        .unwrap(),
                ],
                delivery_binding_frontier: Vec::new(),
                destination_service_type: "principal_server".to_owned(),
                reducer_profile_digest: cokret_sdk::Hash::new(format!("sha256:{}", "2".repeat(64)))
                    .unwrap(),
            },
            events: Vec::new(),
            idempotency_key: None,
        };
        let err = SolandEventsSubmitRequestBody::validate_federation_binding(&req).unwrap_err();
        assert_eq!(err.0, cokret_sdk::ERROR_CODE_SCHEMA_VIOLATION);
    }
}

#[cfg(test)]
mod proof_strictness_tests {
    use super::*;
    use crate::config::{AppConfig, FederationPolicy, ObjectStorageConfig};
    use crate::db::Db;

    pub(super) fn make_state(development_mode: bool) -> AppState {
        let config = AppConfig {
            bind: "127.0.0.1:0".parse().unwrap(),
            metrics_bind: "127.0.0.1:0".parse().unwrap(),
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
            did_resolver_allow_methods: vec!["web".to_owned(), "key".to_owned()],
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
            federation_outbound_enabled: false,
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

            compaction_prune_walk_per_realm_limit: 50,
            seed_demo_data: true,
            trust_domain: "ck:trust_domain:soland.local".to_owned(),
            sovereign_enclave_enabled: false,
            sovereign_enclave_allowed_outbound_hosts: Vec::new(),
            erasure_propagation_window_ms: 604_800_000,
            log_format: crate::config::LogFormat::Plain,
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
                "payload_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000"
            }]),
        );
        object.insert("payload".to_owned(), json!({"body": "hello"}));
        object
    }

    fn session() -> SessionRecord {
        SessionRecord {
            token_hash: "hash".to_owned(),
            actor: "did:web:alice.example".to_owned(),
            device_id: "ck:device:01904100-0000-7000-8000-a11ce0000001".to_owned(),
            audience: "did:web:soland.local".to_owned(),
            expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
            created_at: chrono::Utc::now(),
            revoked_at: None,
        }
    }

    /// 测试辅助:为 `did` ingest 一条新鲜的 webvh 文档(put_document 会以
    /// ingest 时刻权威标注 fetched_at/expires_at),使高风险新鲜度门禁通过。
    async fn ingest_fresh_webvh_document(state: &AppState, did: &str) {
        let now = chrono::Utc::now();
        state
            .persistence
            .webvh()
            .put_document(crate::state::WebvhDocumentRecord {
                did: did.to_owned(),
                did_document: json!({ "id": did, "verificationMethod": [] }),
                key_log_head: Some("sha256:head".to_owned()),
                seq: 1,
                method_evidence: json!({ "mode": "test" }),
                // 占位值,put_document 会以 ingest 时刻覆盖。
                fetched_at: now,
                expires_at: now,
                updated_at: now,
            })
            .await
            .expect("ingest fresh webvh document");
    }

    fn did_key_for(signing_key: &ed25519_dalek::SigningKey) -> String {
        let mut bytes = Vec::with_capacity(34);
        bytes.extend_from_slice(&[0xed, 0x01]);
        bytes.extend_from_slice(signing_key.verifying_key().as_bytes());
        format!("did:key:z{}", bs58::encode(bytes).into_string())
    }

    fn signed_member_identity_payload(signing_key: &ed25519_dalek::SigningKey) -> (String, Value) {
        use ed25519_dalek::Signer as _;

        let did = did_key_for(signing_key);
        let did_key_fragment = did.strip_prefix("did:key:").expect("did:key prefix");
        let verification_method = format!("{did}#{did_key_fragment}");
        let realm_id =
            cokret_sdk::RealmId::new("ck:realm:01904100-0000-7000-8000-a11ce0000001".to_owned())
                .unwrap();
        let actor_id = cokret_sdk::Did::new(did.clone()).unwrap();
        let subject_id = actor_id.clone();
        let zero_hash = cokret_sdk::Hash::new(format!("sha256:{}", "0".repeat(64))).unwrap();
        let mut identity = cokret_sdk::MemberIdentity::new(
            realm_id.clone(),
            actor_id.clone(),
            subject_id,
            cokret_sdk::DisplayProfile {
                display_name: "Alice".to_owned(),
                avatar_blob_ref: None,
            },
            chrono::Utc::now(),
            cokret_sdk::MemberIdentityProof {
                verification_method,
                signature_algorithm: cokret_sdk::MemberIdentitySignatureAlgorithm::Ed25519,
                payload_digest: zero_hash,
                signature: "AA".to_owned(),
            },
        );
        let canonical_bytes = identity.canonical_payload_bytes().unwrap();
        identity.proof.payload_digest =
            cokret_sdk::Hash::new(identity.canonical_payload_sha256().unwrap()).unwrap();
        identity.proof.signature =
            URL_SAFE_NO_PAD.encode(signing_key.sign(&canonical_bytes).to_bytes());
        let payload = json!({
            "realm_id": realm_id.as_str(),
            "actor_id": actor_id.as_str(),
            "segment": "member_identity",
            "identity_payload": {
                "member_identity": identity
            }
        });
        (did, payload)
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn member_identity_plaintext_ed25519_proof_verifies() {
        let state = make_state(false);
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let (_, payload) = signed_member_identity_payload(&signing_key);

        validate_member_identity_proof(&state, &payload)
            .expect("valid MemberIdentity proof should verify");
    }

    #[test]
    fn member_identity_tampered_payload_fails_closed() {
        let state = make_state(false);
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[8u8; 32]);
        let (_, mut payload) = signed_member_identity_payload(&signing_key);
        payload["identity_payload"]["member_identity"]["display_profile"]["display_name"] =
            json!("Mallory");

        let err = validate_member_identity_proof(&state, &payload)
            .expect_err("tampered MemberIdentity payload must fail");
        assert_eq!(err.code, "proof_event_digest_mismatch");
    }

    #[test]
    fn member_identity_encrypted_payload_is_unsupported_fail_closed() {
        let state = make_state(false);
        let payload = json!({
            "realm_id": "ck:realm:01904100-0000-7000-8000-a11ce0000001",
            "actor_id": "did:key:z6MkeTG3bFFSLYVU7VqhgZxqr6YzpaGrQtFMh1uvqGy1vDnP",
            "segment": "member_identity",
            "identity_payload": {
                "encrypted_payload": {
                    "alg": "stub"
                }
            }
        });

        let err = validate_member_identity_proof(&state, &payload)
            .expect_err("encrypted MemberIdentity proof verification is not wired");
        assert_eq!(err.code, "unsupported_feature");
    }

    #[test]
    fn unknown_fail_closed_critical_extension_is_not_implemented() {
        let envelope = json!({
            "requirements": {
                "critical_extensions": [{
                    "id": "ck.extension.unknown",
                    "fail_closed": true
                }]
            }
        });
        let object = envelope.as_object().unwrap();

        let err = validate_event_critical_features(object)
            .expect_err("unknown fail-closed extensions must reject writes");

        assert_eq!(err.status, StatusCode::NOT_IMPLEMENTED);
        assert_eq!(err.code, "unsupported_feature");
    }

    #[test]
    fn unknown_advisory_critical_extension_is_ignored() {
        let envelope = json!({
            "requirements": {
                "critical_extensions": [{
                    "id": "ck.extension.unknown",
                    "fail_closed": false
                }]
            }
        });
        let object = envelope.as_object().unwrap();

        validate_event_critical_features(object)
            .expect("non-fail-closed extensions are advisory and may be ignored");
    }

    #[tokio::test]
    async fn policy_components_media_plaintext_reads_realm_meta() {
        let state = make_state(true);
        let realm_id = "ck:realm:01904100-0000-7000-8000-a11ce0000001";
        let now = chrono::Utc::now();
        state
            .persistence
            .realm_meta()
            .put(
                realm_id,
                &crate::state::RealmMetaRecord {
                    owner: "did:web:alice.example".to_owned(),
                    deleted: false,
                    discoverability: "restricted".to_owned(),
                    history_visibility: "joined".to_owned(),
                    history_sharing_policy: None,
                    history_sharing_policy_digest: None,
                    preview_policy: None,
                    preview_policy_digest: None,
                    encryption_profile: Some("mls_rfc9420".to_owned()),
                    plaintext_visible_services: std::collections::BTreeSet::from([state
                        .config
                        .service_did
                        .clone()]),
                    minimal_metadata_realm: false,
                    created_at: now,
                    updated_at: now,
                },
            )
            .await
            .unwrap();

        let payload = json!({ "media_service_decrypts": true });

        assert!(projected_media_plaintext_service_present(&state, realm_id, &payload).await);
    }

    #[tokio::test]
    async fn minimal_metadata_realm_rejects_non_hidden_aad() {
        // SEC-08 — a minimal-metadata Realm rejects an encrypted message whose
        // aad_visibility_event_id is not `hidden`, and accepts `hidden`.
        let state = make_state(true);
        let realm_id = "ck:realm:01904100-0000-7000-8000-a11ce0000002";
        let now = chrono::Utc::now();
        state
            .persistence
            .realm_meta()
            .put(
                realm_id,
                &crate::state::RealmMetaRecord {
                    owner: "did:web:alice.example".to_owned(),
                    deleted: false,
                    discoverability: "restricted".to_owned(),
                    history_visibility: "joined".to_owned(),
                    history_sharing_policy: None,
                    history_sharing_policy_digest: None,
                    preview_policy: None,
                    preview_policy_digest: None,
                    encryption_profile: Some("mls_rfc9420".to_owned()),
                    plaintext_visible_services: std::collections::BTreeSet::new(),
                    minimal_metadata_realm: true,
                    created_at: now,
                    updated_at: now,
                },
            )
            .await
            .unwrap();

        let encrypted_envelope = |visibility: &str| {
            json!({
                "flow_id": "ck:flow:01904100-0000-7000-8000-000000000001",
                "track_name": "main",
                "encrypted_content": {
                    "scheme": "mls-rfc9420",
                    "version": "1.0",
                    "group_id": "base64url",
                    "epoch": 12,
                    "content_type": "application/json",
                    "ciphertext": "base64url",
                    "aad_visibility_event_id": visibility,
                    "aad": {
                        "realm_id": realm_id,
                        "event_kind": "ck.message.create"
                    }
                }
            })
        };
        let message_op = |payload: serde_json::Value| {
            cokret_sdk::Operation::create(
                cokret_sdk::OperationId::new("ck:operation:01904100-0000-7000-8000-57d7d85564c5")
                    .unwrap(),
                cokret_sdk::RealmId::new(realm_id.to_owned()).unwrap(),
                kinds::CK_MESSAGE_CREATE,
                payload,
            )
        };

        // Non-hidden aad → rejected.
        let routing = message_op(encrypted_envelope("routing_digest"));
        let err = validate_operation_policy(&state, std::slice::from_ref(&routing))
            .await
            .unwrap_err();
        assert!(err.contains("aad_visibility_event_id=hidden"));

        // Encrypted envelope with no discriminator → fail closed.
        let mut no_disc = encrypted_envelope("hidden");
        no_disc["encrypted_content"]
            .as_object_mut()
            .unwrap()
            .remove("aad_visibility_event_id");
        let missing = message_op(no_disc);
        assert!(
            validate_operation_policy(&state, std::slice::from_ref(&missing))
                .await
                .is_err()
        );

        // hidden aad → accepted (other policy gates are satisfied here).
        let hidden = message_op(encrypted_envelope("hidden"));
        validate_operation_policy(&state, std::slice::from_ref(&hidden))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn non_minimal_metadata_realm_allows_any_aad() {
        // SEC-08 — a Realm that did not declare the profile is unaffected: a
        // non-hidden aad encrypted message passes this gate.
        let state = make_state(true);
        let realm_id = "ck:realm:01904100-0000-7000-8000-a11ce0000003";
        let now = chrono::Utc::now();
        state
            .persistence
            .realm_meta()
            .put(
                realm_id,
                &crate::state::RealmMetaRecord {
                    owner: "did:web:alice.example".to_owned(),
                    deleted: false,
                    discoverability: "restricted".to_owned(),
                    history_visibility: "joined".to_owned(),
                    history_sharing_policy: None,
                    history_sharing_policy_digest: None,
                    preview_policy: None,
                    preview_policy_digest: None,
                    encryption_profile: Some("mls_rfc9420".to_owned()),
                    plaintext_visible_services: std::collections::BTreeSet::new(),
                    minimal_metadata_realm: false,
                    created_at: now,
                    updated_at: now,
                },
            )
            .await
            .unwrap();

        let op = cokret_sdk::Operation::create(
            cokret_sdk::OperationId::new("ck:operation:01904100-0000-7000-8000-57d7d85564c6")
                .unwrap(),
            cokret_sdk::RealmId::new(realm_id.to_owned()).unwrap(),
            kinds::CK_MESSAGE_CREATE,
            json!({
                "flow_id": "ck:flow:01904100-0000-7000-8000-000000000001",
                "track_name": "main",
                "encrypted_content": {
                    "scheme": "mls-rfc9420",
                    "version": "1.0",
                    "group_id": "base64url",
                    "epoch": 12,
                    "content_type": "application/json",
                    "ciphertext": "base64url",
                    "aad_visibility_event_id": "routing_digest",
                    "aad": {"realm_id": realm_id, "event_kind": "ck.message.create"}
                }
            }),
        );
        validate_operation_policy(&state, std::slice::from_ref(&op))
            .await
            .unwrap();
    }

    #[test]
    fn policy_components_mls_governance_reads_projection_cell() {
        let state = make_state(true);
        let realm_id = "ck:realm:01904100-0000-7000-8000-a11ce0000001";
        let policy_root = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        {
            let mut projection = state.projection.lock().unwrap();
            projection.cells.insert(
                cokret_sdk::CellRef::new(
                    "ck:cell:ck.component.mls.epoch.v1:ck:mls_group:unit-test".to_owned(),
                )
                .unwrap(),
                cokret_sdk::lattice::CellState::Value(json!({
                    "realm_id": realm_id,
                    "epoch": 7,
                    "governance_binding": {
                        "policy_root": policy_root
                    }
                })),
            );
        }

        let matching = json!({
            "mls_governance_binding": {
                "policy_root": policy_root
            }
        });
        let stale = json!({
            "mls_governance_binding": {
                "policy_root": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
            }
        });

        assert!(projected_mls_governance_binding_covers_policy_root(
            &state, realm_id, &matching
        ));
        assert!(!projected_mls_governance_binding_covers_policy_root(
            &state, realm_id, &stale
        ));
    }

    #[test]
    fn production_requires_canonical_event_time_fields() {
        let state = make_state(false);
        let mut object = serde_json::Map::new();

        let err = validate_event_time_fields(&state, &object)
            .expect_err("production requires created_at");
        assert_eq!(err.code, "missing_param");
        assert!(err.message.contains("created_at"));

        object.insert("created_at".to_owned(), json!("2026-05-17T00:00:00Z"));
        let err = validate_event_time_fields(&state, &object).expect_err("production requires hlc");
        assert_eq!(err.code, "missing_param");
        assert!(err.message.contains("hlc"));

        object.insert("hlc".to_owned(), json!("019041000000-0000-AABBCCDD"));
        let err = validate_event_time_fields(&state, &object)
            .expect_err("uppercase HLC is not canonical");
        assert_eq!(err.code, "invalid_param");

        object.insert("hlc".to_owned(), json!("019041000000-0000-aabbccdd"));
        validate_event_time_fields(&state, &object).expect("canonical timestamps accepted");
    }

    #[test]
    fn development_keeps_fixture_time_field_compatibility() {
        let state = make_state(true);
        let object = serde_json::Map::new();
        validate_event_time_fields(&state, &object)
            .expect("development fixtures may omit event time fields");
    }

    #[test]
    fn production_requires_requirements_schema() {
        let state = make_state(false);
        let mut object = serde_json::Map::new();

        let err = event_requirements_schema_id(&state, &object)
            .expect_err("production requires requirements.schema[]");
        assert_eq!(err.code, "missing_param");

        object.insert(
            "requirements".to_owned(),
            json!({ "schema": ["ck.schema.event.v1"] }),
        );
        assert_eq!(
            event_requirements_schema_id(&state, &object).unwrap(),
            "ck.schema.event.v1"
        );
    }

    #[test]
    fn event_canonical_bytes_use_sdk_canonical_json() {
        let envelope = json!({
            "z": 1,
            "a": {"b": 2, "a": 1},
            "unsigned": {"age_ms": 10},
            "proofs": [{"type": "dev-proof"}],
            "canonical_digest": "sha256:old"
        });
        let bytes = event_canonical_bytes(&envelope).unwrap();
        let text = String::from_utf8(bytes).unwrap();
        assert_eq!(text, r#"{"a":{"a":1,"b":2},"z":1}"#);
    }

    #[test]
    fn event_canonical_bytes_reject_non_canonical_numbers() {
        let envelope = json!({
            "payload": {"rank": 1.5},
            "proofs": [{"type": "dev-proof"}]
        });
        let err = event_canonical_bytes(&envelope).expect_err("floats are not canonical JSON");
        assert_eq!(err.code, "invalid_event_envelope");
    }

    #[test]
    fn event_payload_validator_rejects_registered_payload_shape_errors() {
        let state = make_state(true);
        let envelope = json!({
            "payload": {
                "flow_id": "ck:flow:01904100-0000-7000-8000-f10dc0000001"
            }
        });
        let object = envelope.as_object().unwrap();
        let err = validate_event_schema_and_payload(
            &state,
            "ck.flow.move",
            "ck.schema.event.v1",
            &envelope,
            object,
        )
        .expect_err("flow.move without target/rank must fail payload validation");
        assert_eq!(err.code, "schema_violation");
    }

    #[test]
    fn member_state_invite_accept_uses_canonical_invite_ref() {
        let state = make_state(true);
        let valid = json!({
            "payload": {
                "actor_id": "did:web:bob.example",
                "membership": "join",
                "reason": "invite_accept",
                "invite_ref": "ck:invite:01904100-0000-7000-8000-000000000001",
                "delivery_status": "unroutable"
            }
        });
        validate_event_schema_and_payload(
            &state,
            "ck.member.state",
            "ck.schema.event.v1",
            &valid,
            valid.as_object().unwrap(),
        )
        .expect("ck.member.state invite accept should allow invite_ref");
    }

    #[test]
    fn event_payload_validator_enforces_flow_update_object_patch_schema() {
        let state = make_state(true);
        let flow_id = "ck:flow:01904100-0000-7000-8000-f10dc0000001";
        let valid = json!({
            "payload": {
                "target_ref": flow_id,
                "patch": {
                    "fields.document": {
                        "$op": "set",
                        "value": { "blocks": [] }
                    }
                }
            }
        });
        validate_event_schema_and_payload(
            &state,
            "ck.flow.update",
            "ck.schema.event.v1",
            &valid,
            valid.as_object().unwrap(),
        )
        .expect("canonical ck.flow.update object_patch_payload should validate");

        let invalid_patch_op = json!({
            "payload": {
                "target_ref": flow_id,
                "patch": {
                    "fields.document": {
                        "$op": "replace",
                        "value": { "blocks": [] }
                    }
                }
            }
        });
        let err = validate_event_schema_and_payload(
            &state,
            "ck.flow.update",
            "ck.schema.event.v1",
            &invalid_patch_op,
            invalid_patch_op.as_object().unwrap(),
        )
        .expect_err("ck.flow.update patch operations must match ck.patch.v1 exactly");
        assert_eq!(err.code, "schema_violation");
    }

    #[test]
    fn event_payload_validator_catalog_covers_active_standard_durable_events() {
        let catalog = cokret_sdk::schema::event_payload_validator_catalog();
        let event_kinds = artifacts::active_durable_event_kinds()
            .iter()
            .map(String::as_str)
            .filter(|kind| cokret_sdk::events::is_standard_event_kind(kind))
            .collect::<Vec<_>>();
        let missing = catalog.missing_payload_validators_for(event_kinds.iter().copied());
        assert!(
            missing.is_empty(),
            "missing payload validators: {missing:?}"
        );
        assert!(
            event_kinds.len() > 20,
            "catalog coverage test should cover the active registry, not a fixture subset"
        );
    }

    #[test]
    fn event_payload_validator_enforces_object_patch_family_schema() {
        let catalog = cokret_sdk::schema::event_payload_validator_catalog();
        let object_patch_kinds = [
            "ck.realm.update",
            "ck.flow.update",
            "ck.morph.update",
            "ck.space.update",
            "ck.profile.update",
            "ck.profile.realm_override",
        ];
        let missing = catalog.missing_payload_validators_for(object_patch_kinds);
        assert!(
            missing.is_empty(),
            "missing object_patch validators: {missing:?}"
        );

        for event_kind in object_patch_kinds {
            let patch = if matches!(event_kind, "ck.flow.update" | "ck.morph.update") {
                json!({ "metadata.title": { "$op": "set", "value": "Roadmap" } })
            } else {
                json!({ "title": { "$op": "set", "value": "Roadmap" } })
            };
            catalog
                .validate_payload(
                    event_kind,
                    &json!({
                            "target_ref": "ck:flow:01904100-0000-7000-8000-f10dc0000001",
                            "patch": patch
                    }),
                )
                .unwrap_or_else(|err| {
                    panic!("{event_kind} must accept canonical object_patch_payload: {err}");
                });
            assert!(
                catalog
                    .validate_payload(
                        event_kind,
                        &json!({
                            "target_ref": "ck:flow:01904100-0000-7000-8000-f10dc0000001",
                            "patch": {
                                "title": { "$op": "replace", "value": "Roadmap" }
                            }
                        }),
                    )
                    .is_err(),
                "{event_kind} must reject patch ops outside ck.patch.v1"
            );
        }

        catalog
            .validate_payload(
                "ck.flow.tracks.update",
                &json!({
                    "flow_id": "ck:flow:01904100-0000-7000-8000-f10dc0000001",
                    "tracks": {
                        "discussion": {
                            "enabled": true,
                            "is_primary": true
                        }
                    }
                }),
            )
            .unwrap_or_else(|err| {
                panic!("ck.flow.tracks.update must accept canonical tracks map payload: {err}");
            });
        assert!(
            catalog
                .validate_payload(
                    "ck.flow.tracks.update",
                    &json!({
                        "type": "legacy_track_update",
                        "flow_id": "ck:flow:01904100-0000-7000-8000-f10dc0000001",
                    }),
                )
                .is_err(),
            "ck.flow.tracks.update must still reject retired `type` discriminators"
        );
    }

    #[test]
    fn realm_create_rejects_world_readable_encrypted_history() {
        let state = make_state(true);
        let realm_id = "ck:realm:01904100-0000-7000-8000-a11ce0000001";
        let envelope = json!({
            "payload": {
                "object": {
                    "id": realm_id,
                    "schema": "ck.schema.realm.v1",
                    "title": "encrypted public history",
                    "created_by": "did:web:alice.example",
                    "trust_domain": "ck:trust_domain:soland.local",
                    "schema_refs": ["ck.schema.realm.v1"],
                    "default_discoverability": "listed",
                    "default_join_rule": "invite",
                    "history_visibility": "world_readable",
                    "encryption_profile": "mls_rfc9420",
                    "security_class": "standard",
                    "federation_policy": "restricted",
                    "anchor_profile": "single_did",
                    "digest_algorithm": "sha256",
                    "anchorer": {
                        "type": "single_did",
                        "did": "did:web:alice.example",
                        "recovery_members": ["did:web:recovery.example"],
                        "controller_organization": "did:web:organization.primary.example",
                        "recovery_controller_organizations": ["did:web:organization.recovery.example"]
                    },
                    "created_at": "2026-05-17T00:00:00Z"
                }
            }
        });
        let object = envelope.as_object().unwrap();
        let err = validate_event_schema_and_payload(
            &state,
            "ck.realm.create",
            "ck.schema.event.v1",
            &envelope,
            object,
        )
        .expect_err("encrypted world-readable Realm history must fail closed");
        assert_eq!(err.code, "incompatible_history_with_encryption");
    }

    #[tokio::test]
    async fn production_rejects_dev_proof_type_field() {
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
        .await
        .expect_err("production must reject dev-proof shape");
        // Missing strict-JWS fields trips `invalid_proof` first.
        assert_eq!(err.code, "invalid_proof");
    }

    #[tokio::test]
    async fn development_accepts_dev_proof_type_field_when_hash_matches() {
        let state = make_state(true);
        let session = session();
        let mut object = dev_proof_envelope();
        // Use payload-only hash so the dev path's `payload_only_hash_accept`
        // matches; production would still reject this even with the correct
        // payload hash because the proof lacks a JWS.
        let payload_bytes = canonical::canonical_json_bytes(&object["payload"]).unwrap();
        let payload_digest = format!("sha256:{}", sha256_hex(&payload_bytes));
        if let Some(proofs) = object.get_mut("proofs").and_then(Value::as_array_mut)
            && let Some(proof) = proofs.first_mut()
            && let Some(map) = proof.as_object_mut()
        {
            map.insert("payload_digest".to_owned(), json!(payload_digest));
        }
        let result = validate_event_proofs(
            &object,
            &state,
            &session,
            "did:web:alice.example",
            "sha256:dead",
        )
        .await;
        assert!(
            result.is_ok(),
            "development mode should accept matching dev-proof: {result:?}"
        );
    }

    #[tokio::test]
    async fn production_rejects_full_proof_without_valid_jws_signature() {
        let state = make_state(false);
        let session = session();
        // 先 ingest 一条新鲜的 webvh 文档,使高风险新鲜度门禁通过,
        // 从而让本测试聚焦于其本意:JWS 签名验证失败。
        ingest_fresh_webvh_document(&state, "did:web:alice.example").await;
        let canonical_bytes = br#"{"actor_id":"did:web:alice.example","event_id":"ck:event:test"}"#;
        let event_digest = format!("sha256:{}", sha256_hex(canonical_bytes));
        let mut object = serde_json::Map::new();
        object.insert(
            "proofs".to_owned(),
            json!([{
                "kind": "detached_jws",
                "alg": "EdDSA",
                "verification_method": "did:web:alice.example#k1",
                "event_digest": event_digest,
                "created_at": "2026-05-17T00:00:00Z",
                "jws": "eyJhbGciOiJFZERTQSJ9..AAAAAAAA"
            }]),
        );
        object.insert("payload".to_owned(), json!({"body": "hello"}));

        let err = validate_event_proofs(
            &object,
            &state,
            &session,
            "did:web:alice.example",
            &format!("sha256:{}", sha256_hex(canonical_bytes)),
        )
        .await
        .expect_err("production must reject unsigned/fake JWS proofs");
        assert_eq!(err.code, "invalid_proof");
        assert!(
            err.message.contains("JWS verification failed"),
            "unexpected message: {}",
            err.message
        );
    }

    /// L3 — 高风险 event proof 路径在 DID 文档陈旧/无 ingest 记录时
    /// fail-closed,且在 JWS 验签之前先被新鲜度门禁拦下。
    #[tokio::test]
    async fn production_event_proof_fails_closed_when_did_document_stale() {
        let state = make_state(false);
        let session = session();
        // 刻意不 ingest 任何 webvh 文档:actor 在持久化层无新鲜度证据。
        let canonical_bytes = br#"{"actor_id":"did:web:alice.example","event_id":"ck:event:test"}"#;
        let event_digest = format!("sha256:{}", sha256_hex(canonical_bytes));
        let mut object = serde_json::Map::new();
        object.insert(
            "proofs".to_owned(),
            json!([{
                "kind": "detached_jws",
                "alg": "EdDSA",
                "verification_method": "did:web:alice.example#k1",
                "event_digest": event_digest,
                "created_at": "2026-05-17T00:00:00Z",
                "jws": "eyJhbGciOiJFZERTQSJ9..AAAAAAAA"
            }]),
        );
        object.insert("payload".to_owned(), json!({"body": "hello"}));

        let err = validate_event_proofs(
            &object,
            &state,
            &session,
            "did:web:alice.example",
            &format!("sha256:{}", sha256_hex(canonical_bytes)),
        )
        .await
        .expect_err("stale/missing DID document must fail closed before JWS verify");
        assert_eq!(err.code, "stale_did_document");
    }

    /// T5.3 (Round 22) — pin the SDK production-verifier surface used by
    /// soland's federation / event paths. The hand-rolled
    /// `dev_proof_in_production` gate above rejects `type == "dev-proof"`
    /// and the `"a..b"` / empty placeholder JWS specifically (those are
    /// soland-shape concerns the SDK doesn't know about). The SDK
    /// `ProductionVerifier::assert_production_proof` enforces the
    /// orthogonal rule that the wire `Proof.kind` MUST NOT be in
    /// `core::DEV_PROOF_KINDS` (`dev` / `test` / `mock` / `stub` /
    /// `dummy`). Together they're the spec's full dev-proof gate. This
    /// test asserts the SDK rule still bites on a `kind="dev"` proof —
    /// so soland callers that switch to `ProductionVerifier::wrap(...)`
    /// inherit the same fail-closed semantics they get inline today.
    #[test]
    fn soland_dev_proof_gate_matches_sdk_production_verifier() {
        use cokret_sdk::signatures::{ProductionVerifier, build_proof_envelope};
        use cokret_sdk::{Audience, Hash};

        struct Noop;
        impl cokret_sdk::signatures::EventVerifier for Noop {
            fn verify(
                &self,
                _: &[u8],
                _: &[u8],
                _: &cokret_sdk::signatures::PublicKeyMaterial,
            ) -> std::result::Result<(), cokret_sdk::signatures::VerifierError> {
                Ok(())
            }
            fn algorithm(&self) -> &str {
                "EdDSA"
            }
        }
        let verifier = ProductionVerifier::wrap(Noop);
        // A proof with a kind in the SDK's DEV_PROOF_KINDS allowlist —
        // must be rejected with DevProofRejected.
        let dev = build_proof_envelope(
            "dev",
            "EdDSA",
            "did:web:alice.example#k1",
            Hash::new("sha256:0000000000000000000000000000000000000000000000000000000000000000")
                .unwrap(),
            None,
            None::<Audience>,
            "a..b",
        );
        let sdk_err = verifier
            .assert_production_proof(&dev)
            .expect_err("SDK ProductionVerifier must reject dev-kind proof");
        assert!(matches!(
            sdk_err,
            cokret_sdk::signatures::VerifierError::DevProofRejected(_)
        ));

        // A proof with kind="detached_jws" — SDK accepts the kind
        // (signature still has to verify separately).
        let prod = build_proof_envelope(
            cokret_sdk::signatures::detached_jws_kind(),
            "EdDSA",
            "did:web:alice.example#k1",
            Hash::new("sha256:0000000000000000000000000000000000000000000000000000000000000000")
                .unwrap(),
            None,
            None::<Audience>,
            "header..sig",
        );
        verifier
            .assert_production_proof(&prod)
            .expect("SDK ProductionVerifier must accept detached_jws kind");
    }
}

#[cfg(test)]
mod inception_key_window_tests {
    //! SEC-04 — receiver-side independent 24h inception-key online-window cap
    //! (`identity/key-management.md` §5.0.1 step 5). These tests exercise the
    //! gate directly against the locally hosted `did:webvh` entry-0
    //! `versionTime` anchor.
    use super::proof_strictness_tests::make_state;
    use super::*;
    use crate::state::WebvhLogRecord;

    const PRINCIPAL_DID: &str =
        "did:webvh:zScidExample0000000000000000000000:test.example:webvh:alice";

    fn parsed(kind: &str) -> ValidatedEventEnvelope {
        ValidatedEventEnvelope {
            event_id: "ck:event:01904100-0000-7000-8000-a11ce0000001".to_owned(),
            actor_id: PRINCIPAL_DID.to_owned(),
            actor_seq: 1,
            realm_id: "ck:realm:01904100-0000-7000-8000-a11ce0000001".to_owned(),
            device_id: "ck:device:x".to_owned(),
            kind: kind.to_owned(),
            schema_id: "ck.schema.event.v1".to_owned(),
            prev_refs: Vec::new(),
            authorized_refs: Vec::new(),
            canonical_digest: format!("sha256:{}", "0".repeat(64)),
            canonical_bytes: Vec::new(),
        }
    }

    /// Inception-bootstrap self-authorization: a `ck.device.authorize` whose
    /// envelope `refs[]` carries the `role="did_inception"` evidence ref.
    fn inception_bootstrap_envelope() -> Value {
        json!({
            "event_id": "ck:event:01904100-0000-7000-8000-a11ce0000001",
            "kind": "ck.device.authorize",
            "actor_id": PRINCIPAL_DID,
            "refs": [
                {"id": "1-zEntryZeroVersionId", "role": "did_inception", "critical": true}
            ],
            "payload": {"principal_id": PRINCIPAL_DID, "device_id": "ck:device:x"}
        })
    }

    /// Post-bootstrap §5.1 device authorization: `authorized_by` an anchored
    /// device, with NO `did_inception` ref.
    fn anchored_device_envelope() -> Value {
        json!({
            "event_id": "ck:event:01904100-0000-7000-8000-a11ce0000002",
            "kind": "ck.device.authorize",
            "actor_id": PRINCIPAL_DID,
            "refs": [
                {"id": "ck:event:01904100-0000-7000-8000-a11ce0000001", "role": "authorized_by"}
            ],
            "payload": {"principal_id": PRINCIPAL_DID, "device_id": "ck:device:y"}
        })
    }

    async fn seed_entry_zero(state: &AppState, version_time: &str) {
        state
            .persistence
            .webvh()
            .append_log_event(WebvhLogRecord {
                event_digest: format!("sha256:{}", "1".repeat(64)),
                did: PRINCIPAL_DID.to_owned(),
                // did.rs writes the genesis entry with seq=1 (versionId "1-..");
                // the gate anchors on the lowest-seq record regardless.
                seq: 1,
                operation: json!({
                    "versionId": "1-zEntryZeroVersionId",
                    "versionTime": version_time,
                    "parameters": {"method": "did:webvh:1.0"},
                    "state": {"id": PRINCIPAL_DID},
                }),
                created_at: now(),
            })
            .await
            .expect("seed entry-0");
    }

    #[tokio::test]
    async fn rejects_when_self_reported_window_is_long_but_age_exceeds_24h() {
        // Anchor entry-0 ~48h before "now"; the deployment may self-report a
        // longer window, but the receiver's independent 24h cap MUST reject.
        let state = make_state(true);
        let bootstrap = now() - chrono::Duration::hours(48);
        seed_entry_zero(&state, &bootstrap.to_rfc3339()).await;
        let err = enforce_inception_key_online_window(
            &state,
            &parsed("ck.device.authorize"),
            &inception_bootstrap_envelope(),
        )
        .await
        .expect_err("inception key older than 24h must be rejected");
        assert_eq!(
            err.code,
            crate::error::reasons::INCEPTION_KEY_WINDOW_EXCEEDED
        );
        assert_eq!(err.status, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn admits_when_inception_key_age_under_24h() {
        let state = make_state(true);
        let bootstrap = now() - chrono::Duration::hours(1);
        seed_entry_zero(&state, &bootstrap.to_rfc3339()).await;
        enforce_inception_key_online_window(
            &state,
            &parsed("ck.device.authorize"),
            &inception_bootstrap_envelope(),
        )
        .await
        .expect("inception key under 24h must be admitted");
    }

    #[tokio::test]
    async fn fails_closed_when_entry_zero_version_time_missing() {
        // Inception-bootstrap event but NO local entry-0 anchor → conservative
        // reject, never silently admit.
        let state = make_state(true);
        let err = enforce_inception_key_online_window(
            &state,
            &parsed("ck.device.authorize"),
            &inception_bootstrap_envelope(),
        )
        .await
        .expect_err("missing entry-0 anchor must fail closed");
        assert_eq!(
            err.code,
            crate::error::reasons::INCEPTION_KEY_WINDOW_EXCEEDED
        );
    }

    #[tokio::test]
    async fn fails_closed_when_version_time_unparseable() {
        let state = make_state(true);
        seed_entry_zero(&state, "not-a-timestamp").await;
        let err = enforce_inception_key_online_window(
            &state,
            &parsed("ck.device.authorize"),
            &inception_bootstrap_envelope(),
        )
        .await
        .expect_err("unparseable versionTime must fail closed");
        assert_eq!(
            err.code,
            crate::error::reasons::INCEPTION_KEY_WINDOW_EXCEEDED
        );
    }

    #[tokio::test]
    async fn anchored_device_authorize_is_not_gated() {
        // A post-bootstrap device.authorize (no did_inception ref) is NOT
        // subject to the inception-key window even when an old entry-0 exists.
        let state = make_state(true);
        let bootstrap = now() - chrono::Duration::hours(72);
        seed_entry_zero(&state, &bootstrap.to_rfc3339()).await;
        enforce_inception_key_online_window(
            &state,
            &parsed("ck.device.authorize"),
            &anchored_device_envelope(),
        )
        .await
        .expect("anchored-device authorize must not be gated by the inception window");
    }

    #[tokio::test]
    async fn session_grant_signed_by_inception_key_is_gated() {
        let state = make_state(true);
        let bootstrap = now() - chrono::Duration::hours(48);
        seed_entry_zero(&state, &bootstrap.to_rfc3339()).await;
        let envelope = json!({
            "event_id": "ck:event:01904100-0000-7000-8000-a11ce0000003",
            "kind": "ck.session.grant",
            "actor_id": PRINCIPAL_DID,
            "refs": [
                {"id": "1-zEntryZeroVersionId", "role": "did_inception", "critical": true}
            ],
            "payload": {"subject": PRINCIPAL_DID}
        });
        let err =
            enforce_inception_key_online_window(&state, &parsed("ck.session.grant"), &envelope)
                .await
                .expect_err("inception-key-signed session.grant past 24h must be rejected");
        assert_eq!(
            err.code,
            crate::error::reasons::INCEPTION_KEY_WINDOW_EXCEEDED
        );
    }

    #[tokio::test]
    async fn unrelated_kind_is_ignored() {
        let state = make_state(true);
        enforce_inception_key_online_window(
            &state,
            &parsed("ck.message.create"),
            &inception_bootstrap_envelope(),
        )
        .await
        .expect("non-control kinds are never gated");
    }
}
