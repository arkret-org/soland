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
use crate::wire::{EventsFrontierAccountClientState, describe};
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

mod validation;
use validation::*;
mod sdk_projection;
pub(crate) use sdk_projection::*;

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
        state.config.resumable_upload_incomplete_ttl_seconds,
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
            "ck.self.events.command.submit batch/federation request uses events[], not envelopes[]",
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
    operation_id = "ck.self.events.resource.get",
    tags("events"),
    summary = "Fetch one canonical Event Envelope by event_id"
)]
#[tracing::instrument(skip_all, fields(op = "ck.self.events.resource.get"))]
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
    operation_id = "ck.self.events.query.resolve",
    tags("events"),
    summary = "Resolve up to MAX_EVENT_RESOLVE canonical Event Envelopes by event_id"
)]
#[tracing::instrument(skip_all, fields(op = "ck.self.events.query.resolve"))]
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
/// the canonical `ck.self.events.query.scan` path at `GET /_cokret/self/events` goes to the
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
        snapshot_bootstrap: None,
        next_cursor,
        prev_cursor: None,
        has_more,
        range_completeness: Value::Null,
    })
}

/// Salvo `#[endpoint]` wrapper around [`events_query_durable_scope_impl`] so
/// the actor-scoped durable-store reader can be wired to a route directly
/// (currently used only as a fallback dispatched from `routing::events::sync::events_query`
/// when the selector has no `realms[]`).
#[endpoint(
    operation_id = "org.cokret.soland.events.query_durable",
    tags("events"),
    summary = "Durable-store reader (bypasses projection; actor-scoped audit queries)"
)]
#[tracing::instrument(skip_all, fields(op = "org.cokret.soland.events.query_durable"))]
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
    operation_id = "ck.self.events.query.frontier",
    tags("events"),
    summary = "Actor frontier or Realm Seal view (registered seal_basis / seal_ref sourcing)"
)]
#[tracing::instrument(skip_all, fields(op = "ck.self.events.query.frontier"))]
async fn events_frontier(
    aa: crate::routing::system::extract::AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
) -> crate::result::JsonResult<EventsFrontierAccountClientState> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let actor_id = query_param(req, "actor_id").or_else(|| query_param(req, "actor"));
    let realm_selector = query_param(req, "realm_id");
    if actor_id.is_none() && realm_selector.is_none() {
        return Err(AppError::invalid_param(
            "events.frontier requires at least one of realm_id or actor_id",
        ));
    }

    // Realm selector → Realm Seal view `{realm_id, seal_id,
    // control_event_set_root, state_root, hlc}`: the registered sourcing for
    // single-leaf Control Move `seal_basis` (`leaves=[seal_id]`) and
    // DataEvent `seal_ref`. Takes precedence when both selectors are passed.
    if let Some(realm_value) = realm_selector {
        let realm_id = RealmId::new(realm_value.clone())
            .map_err(|_| AppError::invalid_param("invalid realm_id"))?;
        let own_pcr =
            crate::routing::identity::recovery::principal_control_realm_for_did(&session.actor);
        let accessible = realm_value == own_pcr
            || crate::routing::spaces::space::realm_id_accessible(
                state,
                &realm_value,
                Some(&session),
            )
            .await;
        if !accessible {
            // Same code as invisible-event reads: existence must not leak.
            return Err(AppError::not_found("realm not found"));
        }
        let head = crate::notary::ensure_realm_seal_head(state, &realm_id)
            .map_err(|e| AppError::internal(format!("seal head unavailable: {e}")))?;
        let Some(seal) = head else {
            return Err(AppError::not_found(
                "realm has no accepted Seal on this deployment",
            ));
        };
        return crate::result::json_ok(EventsFrontierAccountClientState {
            frontier: json!({
                "realm_id": realm_id.as_str(),
                "seal_id": seal.id.as_str(),
                "control_event_set_root": seal.control_event_set_root.as_str(),
                "state_root": seal.state_root.as_str(),
                "hlc": seal.hlc.as_str(),
            }),
            receipts: None,
        });
    }

    // Actor selector → `{actor_id, actor_seq, event_id}`: highest accepted
    // actor_seq among events visible to the caller.
    let actor = actor_id.expect("selector presence checked above");
    let events = state
        .persistence
        .events()
        .snapshot_all()
        .await
        .unwrap_or_default();
    let mut best: Option<(u64, String)> = None;
    for record in &events {
        if record.actor_id != actor {
            continue;
        }
        if !event_visible_to_session(state, record, &session).await {
            continue;
        }
        if best.as_ref().is_none_or(|(seq, _)| record.actor_seq > *seq) {
            best = Some((record.actor_seq, record.event_id.clone()));
        }
    }
    let Some((actor_seq, event_id)) = best else {
        // Same code regardless of "unknown actor" vs "nothing visible":
        // private DIDs must not leak through the frontier surface.
        return Err(AppError::not_found("no visible events for actor"));
    };
    crate::result::json_ok(EventsFrontierAccountClientState {
        frontier: json!({
            "actor_id": actor,
            "actor_seq": actor_seq,
            "event_id": event_id,
        }),
        receipts: None,
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
        Some(super::sync::sync_token_for_state(state).await),
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
            "ck.peer.events.command.submit body must be an object",
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
                "ck.peer.events.command.submit permits only service_binding_ref, events, and idempotency_key",
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
                &format!("ck.peer.events.command.submit body is not canonical-hashable: {error}"),
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
                &format!("invalid ck.peer.events.command.submit shape: {error}"),
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
            "ck.peer.events.command.submit must contain at least one event",
        );
        return;
    }
    if submit.events.len() > MAX_EVENT_SUBMIT_BATCH {
        render_error(
            res,
            StatusCode::PAYLOAD_TOO_LARGE,
            "payload_too_large",
            "ck.peer.events.command.submit exceeds max batch size",
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
        // SOL-02-007 — bind the envelope actor to the asserted source trust
        // domain BEFORE constructing a session, instead of leaving author
        // identity entirely to the downstream proof chain. Two acceptance
        // paths:
        //   1. the actor's home trust domain (derived from its DID host, same derivation as the
        //      service-DID → trust-domain rule) equals the `source-trust-domain` header; or
        //   2. the actor is already a member of the binding Realm in the local membership index
        //      (the source domain is then relaying for a known member; identity is re-verified
        //      downstream by `validate_event_envelope`'s proof checks).
        if !federation_actor_origin_acceptable(state, &actor, &source_trust_domain, &binding_realm)
            .await
        {
            rejected.push(json!({
                "id": id,
                "reason_code": "capability_denied",
                "detail": "actor_id home domain does not match source-trust-domain and the actor is not a known member of the binding realm",
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
        Some(super::sync::sync_token_for_state(state).await),
    )));
}

fn event_string_field_from_value(value: &Value, field: &str) -> Option<String> {
    value
        .as_object()
        .and_then(|object| event_string_field(object, &[field]))
}

/// SOL-02-007 — federation actor↔source binding. Accept the envelope actor
/// when its derived home trust domain equals the asserted
/// `source-trust-domain`, or when the actor is already present in the local
/// membership index of the binding Realm (the source domain relays for a
/// known member; proofs are still verified downstream).
async fn federation_actor_origin_acceptable(
    state: &AppState,
    actor: &str,
    source_trust_domain: &str,
    binding_realm: &str,
) -> bool {
    let actor_home_domain =
        crate::routing::federation::federation::trust_domain_from_service_did(actor);
    if actor_home_domain == source_trust_domain {
        return true;
    }
    realm_has_member(state, binding_realm, actor).await
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
        quarantine: Vec::new(),
        actor_frontier: Value::Null,
        realm_frontier: Value::Null,
        cursor,
        original_outcome: None,
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
            )
            .await);
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
        {
            // Admission checks below are mandatory and MUST NOT be skipped
            // (fail-closed). The projection lock is the poison-free
            // `state::Mutex`, so acquiring it cannot fail and this block
            // always runs.
            let proj = state.projection.lock().expect("projection lock");
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
    // the receiver MUST seal on the verifiable bootstrap timestamp
    // (`did:webvh` entry-0 `versionTime`) and reject the event when the
    // inception key age exceeds the 24h protocol hard cap — regardless of any
    // longer window the deployment self-reports. Runs against the full envelope
    // because the `did_inception` evidence ref lives on the envelope `refs[]`,
    // not on the projection operation payload.
    enforce_inception_key_online_window(state, &parsed, &envelope).await?;

    // SPEC-SOL-003 follow-through — an accepted durable `ck.device.revoke`
    // is the canonical revocation trigger (device-lifecycle.md §2.2).
    // Validate the revocation against the submitting session, then flip the
    // device record the auth gate reads BEFORE persisting the event: a
    // failed flip rejects the submission (no event-without-enforcement),
    // while a flipped record with a failed persist only over-revokes — the
    // safe direction, the peer device can resubmit.
    if parsed.kind == "ck.device.revoke" {
        let target_device_id = validate_device_revoke_submission(session, &parsed, &envelope)?;
        crate::routing::identity::auth::revoke_device_record(
            state,
            &parsed.actor_id,
            &target_device_id,
        )
        .await
        .map_err(|error| {
            SubmitOneError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                format!("device revocation enforcement failed: {error}"),
            )
        })?;
        append_audit_log(
            state,
            Some(&parsed.actor_id),
            "device.revoke",
            json!({
                "revoked_device_id": target_device_id,
                "by_device_id": session.device_id.clone(),
                "via": "ck.device.revoke",
                "event_id": parsed.event_id.clone(),
            }),
            "accepted",
        )
        .await;
    }

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
    Ok(event_submit_response(state, EventsSubmitStatus::Accepted, parsed.event_id).await)
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
        "domain": "ck.peer.events.command.submit.service_binding.v1",
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
        "reducer_profile_digest": cokret_sdk::FEDERATION_MINIMAL_REDUCER_PROFILE_DIGEST,
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
            tracing::warn!(
                event_id,
                "failed to encode ck.peer.events.command.submit body"
            );
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
                "failed to enqueue ck.peer.events.command.submit fanout"
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
/// already-sealed device and therefore carry no `did_inception` ref).
const DID_INCEPTION_REF_ROLE: &str = "did_inception";

/// SEC-04 — receiver-side independent enforcement of the 24h inception-key
/// online-window hard cap (`identity/key-management.md` §5.0.1 step 5,
/// receiver-side independent enforcement).
///
/// Only inception-key-signed control events are gated: a
/// `ck.device.authorize` / `ck.session.grant` whose envelope `refs[]` carries a
/// `role="did_inception"` evidence ref. For those, the receiver seals on the
/// `did:webvh` entry-0 `versionTime` (the verifiable bootstrap timestamp) and
/// computes the inception-key age against its own local clock via the SDK
/// [`cokret_sdk::model::inception_key_age_exceeded`]; an age past the 24h hard
/// cap is rejected with reason `inception_key_window_exceeded`, regardless of
/// any longer deployment-self-reported window.
///
/// **Conservative fail-closed (mirrors `webvh_validation` `versionTime`
/// handling):** when the gate applies but the entry-0 `versionTime` seal is
/// missing / unparseable / the local webvh log is absent, the event is rejected
/// rather than admitted. We never substitute `now` to "pass" the check.
///
/// **Honest scope boundary:** the seal is read from this server's *locally
/// hosted / cached* `did:webvh` log (`persistence.webvh().list_log_events`).
/// When this soland is the principal's webvh host (the v1-core
/// inception-bootstrap topology, since the genesis `ck.device.authorize` is
/// submitted to the same principal server that wrote entry-0) the seal is
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
    // (they are `authorized_by` an sealed device), so they are not gated.
    if !envelope_has_did_inception_ref(object) {
        return Ok(());
    }

    // Resolve the principal DID whose entry-0 seals the inception key. For an
    // inception-bootstrap self-authorization the `actor_id` IS the principal;
    // we also accept an explicit `payload.principal_id` / `payload.subject` for
    // session grants. Fail closed when no `did:webvh` principal can be derived.
    let principal_did = inception_principal_did(object, &parsed.actor_id);
    let Some(principal_did) = principal_did else {
        return Err(SubmitOneError::new(
            StatusCode::FORBIDDEN,
            crate::error::reasons::INCEPTION_KEY_WINDOW_EXCEEDED,
            "inception-key-signed control event lacks a resolvable did:webvh principal for the \
             entry-0 online-window seal",
        ));
    };

    // Seal on the locally hosted/cached entry-0 `versionTime`. Missing log,
    // missing entry-0, or an unparseable timestamp all fail closed.
    let seal = inception_bootstrap_seal(state, &principal_did).await;
    let Some(bootstrap_ts) = seal else {
        return Err(SubmitOneError::new(
            StatusCode::FORBIDDEN,
            crate::error::reasons::INCEPTION_KEY_WINDOW_EXCEEDED,
            "inception-bootstrap entry-0 versionTime seal is missing or unparseable; refusing to \
             admit an inception-key-signed control event without a verifiable online-window seal",
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

/// SEC-04 — derive the principal DID whose `did:webvh` entry-0 seals the
/// inception key, preferring an explicit `payload.principal_id` / `subject`,
/// falling back to the envelope `actor_id` (the self-authorization case). Only
/// `did:webvh` principals carry an entry-0 seal in this gate; other methods
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
async fn inception_bootstrap_seal(
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
        let expected_reducer_digest = cokret_sdk::FEDERATION_MINIMAL_REDUCER_PROFILE_DIGEST;
        let actual_reducer_digest = binding.reducer_profile_digest.to_string();
        if actual_reducer_digest != expected_reducer_digest {
            return Err((
                cokret_sdk::ERROR_CODE_REDUCER_PROFILE_MISMATCH,
                format!(
                    "service_binding_ref.reducer_profile_digest mismatch: expected {expected_reducer_digest}, got {actual_reducer_digest}"
                ),
            ));
        }
        Ok(())
    }
}

/// Reject any event kind that is ephemeral or receipt-object-only at the
/// `ck.self.events.command.submit` entrypoint. Spec T02 + T23.
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
             (ck.key.verification.* to-device); not durable ck.self.events.command.submit",
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

    #[test]
    fn federation_binding_rejects_reducer_profile_digest_mismatch() {
        let event_id =
            cokret_sdk::EventId::new("ck:event:01904100-0000-7000-8000-000000000001").unwrap();
        let req = EventsSubmitFederationRequestBody {
            service_binding_ref: cokret_sdk::FederationServiceBindingRef {
                realm_id: RealmId::new("ck:realm:01904100-0000-7000-8000-000000000001").unwrap(),
                realm_policy_digest: cokret_sdk::Hash::new(format!("sha256:{}", "1".repeat(64)))
                    .unwrap(),
                membership_frontier: vec![event_id.clone()],
                delivery_binding_frontier: vec![event_id],
                destination_service_type: "principal_server".to_owned(),
                reducer_profile_digest: cokret_sdk::Hash::new(format!("sha256:{}", "2".repeat(64)))
                    .unwrap(),
            },
            events: Vec::new(),
            idempotency_key: None,
        };

        let err = SolandEventsSubmitRequestBody::validate_federation_binding(&req).unwrap_err();
        assert_eq!(err.0, cokret_sdk::ERROR_CODE_REDUCER_PROFILE_MISMATCH);
    }

    #[test]
    fn federation_binding_accepts_registry_reducer_profile_digest() {
        let event_id =
            cokret_sdk::EventId::new("ck:event:01904100-0000-7000-8000-000000000001").unwrap();
        let req = EventsSubmitFederationRequestBody {
            service_binding_ref: cokret_sdk::FederationServiceBindingRef {
                realm_id: RealmId::new("ck:realm:01904100-0000-7000-8000-000000000001").unwrap(),
                realm_policy_digest: cokret_sdk::Hash::new(format!("sha256:{}", "1".repeat(64)))
                    .unwrap(),
                membership_frontier: vec![event_id.clone()],
                delivery_binding_frontier: vec![event_id],
                destination_service_type: "principal_server".to_owned(),
                reducer_profile_digest: cokret_sdk::Hash::new(
                    cokret_sdk::FEDERATION_MINIMAL_REDUCER_PROFILE_DIGEST,
                )
                .unwrap(),
            },
            events: Vec::new(),
            idempotency_key: None,
        };

        SolandEventsSubmitRequestBody::validate_federation_binding(&req).unwrap();
    }
}

#[cfg(test)]
#[path = "event_log_inception_key_window_tests.rs"]
mod inception_key_window_tests;
#[cfg(test)]
#[path = "event_log_proof_strictness_tests.rs"]
mod proof_strictness_tests;
