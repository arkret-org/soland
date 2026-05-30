//! Signed Event Envelope ingestion + read API (`/api/v1/events/*`).
//!
//! Surfaces:
//! - `GET  /api/v1/events/describe`  — declare the active event registry, schema/reducer profiles,
//!   and limits.
//! - `POST /api/v1/events`           — submit one canonical Event Envelope,
//!   an `events[]` batch, or a federation `service_binding_ref` + `events[]` batch.
//! - `GET  /api/v1/events/{event_id}` — fetch one envelope.
//! - `POST /api/v1/events/resolve`    — resolve up to `MAX_EVENT_RESOLVE`.
//! - `GET  /api/v1/events`            — paginated list (filtered by actor / realm).
//! - `GET  /api/v1/events/frontier`   — per-actor / per-realm frontier.
//!
//! The validator block (`validate_event_envelope` + helpers) lives at the
//! bottom of this file.

use std::collections::BTreeMap;

use chrono::{DateTime, Duration, Utc};
use contrix_sdk::{
    EventsSubmitFederationRequest, Hlc, Operation, OperationId, RealmId, TypedTrustDomainId,
    canonical,
};
use salvo::http::StatusCode;
use salvo::oapi::extract::{JsonBody, PathParam};
use salvo::prelude::*;
use serde_json::{Value, json};

use super::projection::{retention_tombstone_for_event, retention_tombstone_payload_value};
use super::{
    append_audit_log, auth_or_render, is_valid_sha256_digest, now, project_accepted_operations,
    query_param, query_param_all, realm_allows_plaintext_service, realm_event_visible_to_session,
    realm_has_member, render_error, sha256_hex, validate_content_encryption_floor, validate_did,
    validate_operation_policy, validate_operation_semantics, validate_space_id,
};
use crate::error::{AppError, ErrorCode, error_http_status};
use crate::result::{JsonResult, json_ok};
use crate::routing::organizations;
use crate::routing::policy_gate::{self, PolicyGateSurface};
use crate::routing::system::extract::AuthArgs;
use crate::state::{AppState, CanonicalEventRecord, SessionRecord};
use crate::wire::{
    EventDescribeResponse, EventReadResponse, EventResolveRequest, EventResolveResponse,
    EventSubmitResponse, EventsFrontierResBody, EventsPageResponse,
};
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
                "realm_id",
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
                "proof_payload_digest": "sha256 over Event Envelope JSON with proofs and unsigned removed"
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
            "max_prev_refs": MAX_EVENT_PREV_REFS,
            "max_refs": MAX_EVENT_REFS,
            "max_batch_size": MAX_EVENT_SUBMIT_BATCH,
            "max_resolve": MAX_EVENT_RESOLVE,
            "max_list_limit": 100
        }),
        capabilities: json!({
            "single_event_submit": true,
            "batch_submit": true,
            "federation_submit": true,
            "batch_receipt": false,
            "read_by_event_id": true,
            "resolve": true,
            "list_by_actor_or_realm": true,
            "list_by_actor_or_space": true,
            "frontier": true,
            "snapshot": false,
            "witness": false,
            "high_assurance": false
        }),
    }));
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
        submit_federation_events(state, req, envelope, res).await;
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
            "cx.events.submit batch/federation request uses events[], not envelopes[]",
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
            "POST /api/v1/events batch body must be an object with events[]",
        );
        return;
    }
    let envelope_for_chaos = envelope.clone();
    match submit_event_value(state, &session, envelope).await {
        Ok(response) => {
            maybe_delay_test_chaos_breakpoint(state, &envelope_for_chaos, &response).await;
            res.render(Json(response));
        }
        Err(error) => render_submit_one_error(res, error),
    }
}

async fn maybe_delay_test_chaos_breakpoint(
    state: &AppState,
    envelope: &Value,
    response: &EventSubmitResponse,
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
        .filter(|value| value.starts_with("cx:operation:"))
        .map(ToOwned::to_owned)
}

#[endpoint(
    operation_id = "cx.events.get",
    tags("events"),
    summary = "Fetch one canonical Event Envelope by event_id"
)]
#[tracing::instrument(skip_all, fields(op = "cx.events.get"))]
async fn get_event(
    aa: AuthArgs,
    event_id: PathParam<String>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<EventReadResponse> {
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
    json_ok(event_read_response_for_state(state, &record))
}

#[endpoint(
    operation_id = "cx.events.resolve",
    tags("events"),
    summary = "Resolve up to MAX_EVENT_RESOLVE canonical Event Envelopes by event_id"
)]
#[tracing::instrument(skip_all, fields(op = "cx.events.resolve"))]
async fn resolve_events(
    aa: AuthArgs,
    body: JsonBody<EventResolveRequest>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<EventResolveResponse> {
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
        match store.get(&event_id).await.ok().flatten() {
            Some(record) if event_visible_to_session(state, &record, &session).await => {
                found.push(event_read_response_for_state(state, &record));
            }
            _ => missing.push(event_id),
        }
    }
    json_ok(EventResolveResponse {
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
/// Supports the multi-value selector `realms[]` ∪ `actors[]` (via
/// repeated query args) **and** real backward iteration (`direction=backward`
/// returns events older than `from` cursor in reverse time order, with
/// `prev_cursor` driving further pages).
/// Plain async helper version of [`events_query_durable_scope`] so other
/// handlers (e.g. the projection-aware `routing::events::sync::events_query`) can
/// dispatch to the durable-store reader when the selector contains only
/// `actors[]` (no `spaces[]`). Both the `#[endpoint]` wrapper and the
/// sync-side dispatcher call this impl.
///
/// Returns `Result<EventsPageResponse, AppError>` so the wrapper can be a
/// typed `JsonResult<T>` handler and the sync-side dispatcher can map the
/// typed result into its own `&mut Response` shape with a single `match`.
pub(super) async fn events_query_durable_scope_impl(
    state: &AppState,
    session: &SessionRecord,
    req: &Request,
) -> Result<EventsPageResponse, AppError> {
    // Repeated query-arg selector: `actors[]` ∪ `realms[]`.
    let mut actors = query_param_all(req, "actors");
    if let Some(single) = query_param(req, "actor").or_else(|| query_param(req, "actor_id")) {
        if !actors.contains(&single) {
            actors.push(single);
        }
    }
    let mut spaces = query_param_all(req, "realms");
    if let Some(single) = query_param(req, "realm_id") {
        if !spaces.contains(&single) {
            spaces.push(single);
        }
    }
    for actor in &actors {
        if validate_did(actor).is_err() {
            return Err(AppError::invalid_param(format!("invalid actor: {actor}")));
        }
    }
    for space in &mut spaces {
        if RealmId::new(space.clone()).is_err() {
            return Err(AppError::invalid_param(format!("invalid realm: {space}")));
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
    let spaces_set: std::collections::BTreeSet<&str> = spaces.iter().map(String::as_str).collect();
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
            if actors_set.is_empty() && spaces_set.is_empty() {
                return true;
            }
            let actor_match = actors_set.contains(record.actor_id.as_str());
            let space_match = record
                .space_id
                .as_deref()
                .is_some_and(|s| spaces_set.contains(s));
            actor_match || space_match
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
    let frontier = events_frontier_json(&page);
    let events = page
        .iter()
        .map(|record| event_read_response_for_state(state, record))
        .collect();
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
#[tracing::instrument(skip_all, fields(op = "cx.events.query_durable"))]
async fn events_query_durable_scope(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<EventsPageResponse> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let response = events_query_durable_scope_impl(state, &session, req).await?;
    json_ok(response)
}

#[endpoint(
    operation_id = "cx.events.frontier",
    tags("events"),
    summary = "Per-actor + per-realm frontier (highest accepted actor_seq / latest event)"
)]
#[tracing::instrument(skip_all, fields(op = "cx.events.frontier"))]
async fn events_frontier(
    aa: crate::routing::system::extract::AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
) -> crate::result::JsonResult<EventsFrontierResBody> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let actor_id = query_param(req, "actor_id").or_else(|| query_param(req, "actor"));
    let realm_selector = query_param(req, "realm_id");
    let internal_space_selector = match realm_selector.as_deref() {
        Some(value) if RealmId::new(value.to_owned()).is_ok() => Some(value.to_owned()),
        Some(_) => return Err(AppError::invalid_param("invalid realm_id")),
        None => None,
    };
    // Round C47 (spec e10b6ad): `peer_role` ∈ {account_client,
    // federation_peer, anonymous_health}; default `account_client`.
    // federation_peer additionally returns `frontier_root`, per-actor
    // `actor_seq_upper_bounds`, and a service signature; anonymous_health
    // returns only the frontier_root summary.
    // Round 4 (B1.4) — peer_role routes to one of three typed response
    // variants. The legacy single-shape response is wire-broken. We parse
    // via the SDK helper so unknown values surface as invalid_param.
    let peer_role_raw = query_param(req, "peer_role");
    let peer_role = match crate::round4::parse_peer_role(peer_role_raw.as_deref()) {
        Ok(pr) => pr,
        Err(msg) => {
            return Err(AppError::invalid_param(msg));
        }
    };
    let events = state
        .persistence
        .events()
        .snapshot_all()
        .await
        .unwrap_or_default();
    let mut actor_frontier: BTreeMap<String, u64> = BTreeMap::new();
    let mut realm_frontier: BTreeMap<String, Value> = BTreeMap::new();
    let mut space_frontier: BTreeMap<String, Value> = BTreeMap::new();
    let mut realm_latest: BTreeMap<String, (DateTime<Utc>, String)> = BTreeMap::new();
    let mut space_latest: BTreeMap<String, (DateTime<Utc>, String)> = BTreeMap::new();
    for record in &events {
        if actor_id
            .as_deref()
            .is_some_and(|actor| actor != record.actor_id)
        {
            continue;
        }
        if internal_space_selector.as_deref() != record.space_id.as_deref()
            && internal_space_selector.is_some()
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
        if let Some(space_id) = record.space_id.as_deref() {
            if let Some(realm_id) = canonical_realm_id_for_record(record) {
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
            let replace = frontier_entry_is_newer(&space_latest, space_id, record);
            if replace {
                space_latest.insert(
                    space_id.to_owned(),
                    (record.received_at, record.event_id.clone()),
                );
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
    }

    // Round 4 (B1.4) — build the typed SDK response variant. The legacy
    // `frontier` JSON envelope is retained alongside for the existing
    // ResBody wire shape (consumers that haven't migrated to the typed
    // `events_frontier_v2` field yet), but the typed variant is the
    // canonical shape per spec a77b995.
    use contrix_sdk::Did as SdkDid;
    let service_did = SdkDid::new(state.config.service_did.clone())
        .unwrap_or_else(|_| SdkDid::new("did:web:soland.local".to_owned()).unwrap());
    let latest_space_event_ids = space_frontier.iter().filter_map(|(space, entry)| {
        entry
            .get("event_id")
            .and_then(Value::as_str)
            .map(|event_id| (space.clone(), vec![event_id.to_owned()]))
    });
    let typed_space_frontier = crate::round4::typed_space_frontier(latest_space_event_ids);
    let typed_actor_bounds = crate::round4::typed_actor_upper_bounds(actor_frontier.clone());
    let generated_at = now();
    let selected_realm_id = realm_selector
        .as_deref()
        .and_then(|value| RealmId::new(value.to_owned()).ok());
    let frontier_root = crate::round4::frontier_root(&typed_space_frontier, &typed_actor_bounds)
        .map_err(|error| AppError::internal(format!("frontier_root: {error}")))?;
    let federation_signature = if matches!(peer_role, contrix_sdk::FrontierPeerRole::FederationPeer)
    {
        let signing_key = state.anchorer_signing_key();
        Some(
            crate::round4::sign_frontier_root(
                &service_did,
                selected_realm_id.as_ref(),
                generated_at,
                &frontier_root,
                signing_key.as_ref(),
            )
            .map_err(|error| AppError::internal(format!("frontier signature: {error}")))?,
        )
    } else {
        None
    };
    let federation_binding = if matches!(peer_role, contrix_sdk::FrontierPeerRole::FederationPeer) {
        let binding_realm = selected_realm_id.clone().unwrap_or_else(|| {
            RealmId::new("cx:realm:00000000-0000-7000-8000-000000000000".to_owned())
                .expect("built-in fallback realm id is valid")
        });
        let service_binding_ref = crate::round4::frontier_service_binding_ref(
            &binding_realm,
            &typed_space_frontier,
            &typed_actor_bounds,
        )
        .map_err(|error| AppError::internal(format!("frontier service binding: {error}")))?;
        Some(crate::round4::FederationFrontierBinding {
            service_binding_ref,
            frontier_root: frontier_root.clone(),
            receipts: Vec::new(),
            signatures: federation_signature.iter().cloned().collect::<Vec<Value>>(),
        })
    } else {
        None
    };
    let typed_response = crate::round4::build_typed_frontier_response(
        peer_role,
        &service_did,
        typed_space_frontier,
        typed_actor_bounds,
        federation_binding,
    );
    // Render the JSON wire envelope. anonymous_health MUST strip
    // receipts / actor_seq_upper_bounds / per-space frontier — the
    // typed builder already does this; we mirror it onto the legacy
    // `frontier` envelope for back-compat.
    let peer_role_str = match peer_role {
        contrix_sdk::FrontierPeerRole::AccountClient => "account_client",
        contrix_sdk::FrontierPeerRole::FederationPeer => "federation_peer",
        contrix_sdk::FrontierPeerRole::AnonymousHealth => "anonymous_health",
    };
    let mut frontier = json!({
        "storage": state.db.mode(),
        "generated_at": generated_at,
        "peer_role": peer_role_str,
        "events_frontier_v2": serde_json::to_value(&typed_response).unwrap_or(Value::Null),
    });
    match peer_role {
        contrix_sdk::FrontierPeerRole::FederationPeer => {
            if let Some(obj) = frontier.as_object_mut() {
                obj.insert(
                    "frontier_root".to_owned(),
                    Value::String(frontier_root.as_str().to_owned()),
                );
                obj.insert(
                    "actor_seq_upper_bounds".to_owned(),
                    serde_json::to_value(&actor_frontier).unwrap_or(Value::Null),
                );
                obj.insert(
                    "signature".to_owned(),
                    federation_signature.unwrap_or(Value::Null),
                );
            }
        }
        contrix_sdk::FrontierPeerRole::AnonymousHealth => {
            // Strip everything that would leak per-tenant state.
            if let Some(obj) = frontier.as_object_mut() {
                obj.insert(
                    "frontier_root".to_owned(),
                    Value::String(frontier_root.as_str().to_owned()),
                );
                obj.insert("retry_after_ms".to_owned(), Value::from(60_000));
                obj.insert(
                    "cache_expires_at".to_owned(),
                    Value::String((generated_at + Duration::seconds(60)).to_rfc3339()),
                );
            }
            // Clear actor_frontier + realm/space frontier in the legacy envelope.
            return crate::result::json_ok(EventsFrontierResBody {
                actor_frontier: BTreeMap::new(),
                realm_frontier: BTreeMap::new(),
                space_frontier: BTreeMap::new(),
                frontier,
            });
        }
        contrix_sdk::FrontierPeerRole::AccountClient => {}
    }
    crate::result::json_ok(EventsFrontierResBody {
        actor_frontier,
        realm_frontier,
        space_frontier,
        frontier,
    })
}

// ── Validator block ─────────────────────────────────────────────────────────

#[derive(Debug)]
struct ValidatedEventEnvelope {
    event_id: String,
    actor_id: String,
    actor_seq: u64,
    realm_id: String,
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
    message: String,
}

#[derive(Debug)]
struct SubmitOneError {
    status: StatusCode,
    code: String,
    message: String,
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
                if response.status == "duplicate" {
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
        "partial"
    } else if accepted.len() == duplicate.len() && !duplicate.is_empty() {
        "duplicate"
    } else {
        "accepted"
    };
    res.render(Json(json!({
        "status": status,
        "accepted": accepted,
        "duplicate": duplicate,
        "rejected": rejected,
        "cursor": super::sync::sync_token_for_state(state),
    })));
}

async fn submit_federation_events(
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
            "federation cx.events.submit body must be an object",
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
                "federation cx.events.submit permits only service_binding_ref, events, and idempotency_key",
            );
            return;
        }
    }

    let trust_headers = match crate::round4::FederationTrustHeaders::from_salvo_request(req) {
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
                &format!("federation request body is not canonical-hashable: {error}"),
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

    let submit = match serde_json::from_value::<EventsSubmitFederationRequest>(body) {
        Ok(value) => value,
        Err(error) => {
            render_error(
                res,
                StatusCode::BAD_REQUEST,
                "schema_violation",
                &format!("invalid federation cx.events.submit shape: {error}"),
            );
            return;
        }
    };
    if let Err((code, message)) =
        crate::round4::EventsSubmitRequest::validate_federation_binding(&submit)
    {
        render_error(res, StatusCode::BAD_REQUEST, code, &message);
        return;
    }
    if submit.events.is_empty() {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "missing_param",
            "federation cx.events.submit must contain at least one event",
        );
        return;
    }
    if submit.events.len() > MAX_EVENT_SUBMIT_BATCH {
        render_error(
            res,
            StatusCode::PAYLOAD_TOO_LARGE,
            "payload_too_large",
            "federation cx.events.submit exceeds max batch size",
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
        let session = SessionRecord {
            token_hash: format!("federation:{source_trust_domain}:{}", request_hash),
            actor,
            device_id: format!("federation:{source_trust_domain}"),
            audience: state.config.service_did.clone(),
            expires_at: created_at + Duration::minutes(5),
            created_at,
            revoked_at: None,
        };
        match submit_event_value(state, &session, envelope).await {
            Ok(response) => {
                accepted.push(response.event_id.clone());
                if response.status == "duplicate" {
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
        "partial"
    } else if accepted.len() == duplicate.len() && !duplicate.is_empty() {
        "duplicate"
    } else {
        "accepted"
    };
    append_audit_log(
        state,
        None,
        "events.submit.federation",
        json!({
            "realm_id": binding_realm,
            "source_trust_domain": source_trust_domain,
            "request_canonical_digest": request_hash,
            "accepted": accepted,
            "duplicate": duplicate,
            "rejected_count": rejected.len()
        }),
        status,
    )
    .await;
    res.render(Json(json!({
        "status": status,
        "accepted": accepted,
        "duplicate": duplicate,
        "rejected": rejected,
        "cursor": super::sync::sync_token_for_state(state),
    })));
}

fn event_string_field_from_value(value: &Value, field: &str) -> Option<String> {
    value
        .as_object()
        .and_then(|object| event_string_field(object, &[field]))
}

async fn submit_event_value(
    state: &AppState,
    session: &SessionRecord,
    envelope: Value,
) -> Result<EventSubmitResponse, SubmitOneError> {
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
                "duplicate",
                existing.event_id.clone(),
                existing.canonical_digest.clone(),
                existing.received_at,
                true,
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
        space_id = ?parsed.space_id,
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
        if let Err(message) =
            validate_operation_policy(state, std::slice::from_ref(operation)).await
        {
            return Err(SubmitOneError::new(
                StatusCode::FORBIDDEN,
                "capability_denied",
                message,
            ));
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
            if let Some(reason) = preflight_mls_projection_reject(&proj, operation) {
                return Err(SubmitOneError::new(
                    StatusCode::PRECONDITION_FAILED,
                    reason.clone(),
                    reason,
                ));
            }
        }
    }

    let envelope_for_bootstrap = envelope.clone();
    if let Err(error) = store
        .put(CanonicalEventRecord {
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
        project_accepted_operations(state, &parsed.actor_id, &[operation]).await;
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
    if parsed.kind == "cx.realm.create"
        && let Some(space_id_str) = parsed.space_id.as_deref()
        && let Some(envelope_object) = envelope_for_bootstrap.as_object()
    {
        bootstrap_realm_member_index(state, space_id_str, &parsed.actor_id, envelope_object).await;
        organizations::record_realm_organizations_from_event(
            state,
            space_id_str,
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
            "space_id": parsed.space_id.clone(),
            "kind": parsed.kind.clone(),
            "canonical_digest": parsed.canonical_digest.clone()
        }),
        "accepted",
    )
    .await;
    Ok(event_submit_response(
        state,
        "accepted",
        parsed.event_id,
        parsed.canonical_digest,
        received_at,
        false,
    ))
}

fn preflight_mls_projection_reject(
    proj: &crate::reducer::ProjectionState,
    operation: &Operation,
) -> Option<String> {
    let kind = kinds::canonical_kind_string(operation);
    match kind.as_str() {
        kinds::CX_MLS_KEYPACKAGE
        | kinds::CX_MLS_WELCOME
        | kinds::CX_MLS_GENESIS
        | kinds::CX_MLS_COMMIT => {
            let mut snapshot = proj.clone();
            let effect = match kind.as_str() {
                kinds::CX_MLS_KEYPACKAGE => {
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
                kinds::CX_MLS_WELCOME => {
                    crate::reducer::mls::apply_welcome_enqueue(&mut snapshot, operation)
                }
                kinds::CX_MLS_GENESIS => {
                    crate::reducer::mls::apply_group_genesis(&mut snapshot, operation)
                }
                kinds::CX_MLS_COMMIT => {
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

fn event_scope_ids(
    object: &serde_json::Map<String, Value>,
) -> Result<(String, String), EventValidationError> {
    if let Some(realm_id) = event_string_field(object, &["realm_id"]) {
        if RealmId::new(realm_id.clone()).is_err() {
            return Err(event_validation_error(
                StatusCode::BAD_REQUEST,
                "invalid_param",
                "realm_id must use the cx:realm: typed prefix",
            ));
        }
        return Ok((realm_id.clone(), realm_id));
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
            "event_id must use the cx:event: typed prefix",
        ));
    }

    let kind = event_string_field(object, &["kind"]).ok_or_else(|| {
        event_validation_error(StatusCode::BAD_REQUEST, "missing_param", "kind is required")
    })?;
    // R1.2 (Realm/Space reversal) — hard_reject the pre-rename security
    // `cx.space.<event>` and container `cx.place.*` wire kinds with a
    // distinct reason_code so clients can detect they need to upgrade.
    // The reversal moved the security namespace from `cx.space.*` to
    // `cx.realm.*` and the container namespace from `cx.place.*` to
    // `cx.space.*`; both lists below name the pre-rename kinds that are
    // now extinct on the wire.
    if matches!(
        kind.as_str(),
        "cx.space.upgrade"
            | "cx.space.organization"
            | "cx.space.policy"
            | "cx.space.join_rule"
            | "cx.space.history_visibility"
            | "cx.space.discovery"
            | "cx.space.policy_server"
            | "cx.space.policy_components"
            | "cx.space.history_sharing_policy"
            | "cx.space.delivery_binding_policy"
            | "cx.space.asset_privacy_policy"
            | "cx.space.read_receipt_policy"
            | "cx.space.moderation_policy"
            | "cx.space.plaintext_visible_services"
            | "cx.space.media_service"
            | "cx.space.schema"
            | "cx.space.audit_policy_downgrade"
            | "cx.space.destroy"
            | "cx.space.freeze"
            | "cx.space.notification.audit"
            | "cx.space.child"
    ) {
        return Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            "realm_kind_renamed_in_v1",
            "this security-namespace `cx.space.*` kind was renamed to \
             `cx.realm.*` in v1 (Realm/Space reversal)",
        ));
    }
    if kind.as_str().starts_with("cx.place.") {
        return Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            "place_kind_renamed_to_space",
            "the container namespace `cx.place.*` was renamed to \
             `cx.space.*` in v1 (Realm/Space reversal)",
        ));
    }
    // Round R2/R3 (T02/T23) — reject ephemeral kinds & receipt-object-only
    // kinds at the submit entrypoint. Aggressive mode: no compat path —
    // pre-Round-R2/R3 senders MUST switch to cx.schema.ephemeral_envelope.v1
    // (broadcast forms) or cx.schema.device_message.v1 (cx.key.verification.*).
    if let Some((code, reason)) = crate::round23::events_submit_pre_admit_check(&kind) {
        return Err(event_validation_error(
            error_http_status(code),
            code.as_str(),
            reason,
        ));
    }
    if !artifacts::active_durable_event_kinds().contains(&kind) && kind != kinds::CX_CONFLICT_REPAIR
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

    // REDU-7 / CXP-0008 / CXP-0009 (R3 spec-sync 2026-05-27,
    // contrix-spec b47ff6ec) — Envelope `actor_kind` is reducer-managed:
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

    // CXP-0008 / CXP-0009 — when `executed_by` is present the reducer MUST
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

    let (realm_id, space_id) = event_scope_ids(object)?;
    // Round R2/R3 (T07) + Stream-F (Wave 1B) — Realm in terminal state
    // (`cx.realm.tombstone` OR `cx.realm.destroy` applied) refuses every
    // non-audit-class write. Spec `realm-and-space.md` §2.5 / §2.5.1.
    let realm_terminal = state
        .projection
        .lock()
        .map(|proj| proj.space_is_in_terminal_state(&space_id))
        .unwrap_or(false);
    if let Some((code, reason)) = crate::round23::terminal_realm_check(realm_terminal, &kind) {
        return Err(event_validation_error(
            error_http_status(code),
            code.as_str(),
            reason,
        ));
    }
    // Spec realm-and-space.md §2.6 — `cx.realm.create` is the genesis
    // event for both the Realm metadata cell AND the creator's first
    // member-state cell. The reducer MUST treat `created_by`
    // as already-a-member when admitting this event; otherwise spec-
    // correct clients can never bootstrap a Realm through the canonical
    // event-submission path. The submit_event commit path (below)
    // materialises the member set in state.realms immediately after
    // store.put succeeds, so any follow-up facet event in the same
    // session naturally passes the regular realm_has_member check.
    let is_realm_create_bootstrap = kind == "cx.realm.create"
        && realm_create_actor_is_creator(object, &session.actor)
        && !space_exists_in_index(state, &space_id);
    let is_invite_acceptance_join =
        member_join_accepts_pending_invite(state, object, &session.actor, &space_id).await;
    if !is_realm_create_bootstrap
        && !is_invite_acceptance_join
        && !realm_has_member(state, &space_id, &session.actor).await
    {
        return Err(event_validation_error(
            StatusCode::FORBIDDEN,
            "capability_denied",
            "actor is not a member of the event Realm",
        ));
    }
    require_object_field(object, "payload")?;
    // CXP-0007 (spec b7d35be) — hard-reject any wire payload that carries a
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
    validate_audit_accessed_payload(&kind, object)?;
    validate_sender_commitment_binding(object)?;
    // Round R2/R3 (T08) — cross_domain replay defence MUST run BEFORE the
    // signature check (verified below in `validate_event_proofs`). Aggressive
    // mode: payload missing the new required fields surfaces as
    // schema_violation here; payload with mismatched trust_domain surfaces as
    // the registered `cross_domain_replay_rejected` (409) code.
    if kind == "cx.cross_signing.reset" {
        let payload = object.get("payload").cloned().unwrap_or(Value::Null);
        if let Err((code, reason)) = crate::round23::cross_signing_reset_replay_check(
            &payload,
            &event_id,
            &state.config.trust_domain,
        ) {
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
    if kind == "cx.realm.policy_components" {
        let payload = object.get("payload").cloned().unwrap_or(Value::Null);
        // Best-effort: collect active profiles from the payload's own
        // `profiles[]` field plus any payload-asserted "active_profiles".
        let mut active_profiles: Vec<String> = payload
            .get("profiles")
            .and_then(Value::as_array)
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(ToOwned::to_owned))
                    .collect()
            })
            .unwrap_or_default();
        if let Some(extra) = payload.get("active_profiles").and_then(Value::as_array) {
            for v in extra {
                if let Some(s) = v.as_str() {
                    active_profiles.push(s.to_owned());
                }
            }
        }
        let media_plaintext_service_present =
            projected_media_plaintext_service_present(state, &space_id, &payload).await;
        let mls_governance_binding_covers_policy_root =
            projected_mls_governance_binding_covers_policy_root(state, &space_id, &payload);
        if let Err((code, reason)) = crate::round23::realm_policy_components_check(
            &payload,
            &active_profiles,
            media_plaintext_service_present,
            mls_governance_binding_covers_policy_root,
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
    // `cx.realm.anchor.submit` payload shape used by federation push;
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
        if let Err((code, reason)) = crate::round23::validate_anchor_frontier_entries(&entries) {
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
    validate_event_proofs(
        object,
        state,
        session,
        &actor_id,
        &canonical_digest,
        &canonical_bytes,
    )?;

    Ok(ValidatedEventEnvelope {
        event_id,
        actor_id,
        actor_seq,
        realm_id,
        space_id: Some(space_id),
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
        let is_mls_cell = cell_id.contains("cx.component.mls.epoch.v1")
            || cell_id.contains("cx.component.mls_epoch.v1")
            || cell_id.contains("cx.component.mls.covered_frontier.v1");
        if !is_mls_cell {
            continue;
        }
        let contrix_sdk::lattice::CellState::Value(value) = cell_state else {
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

fn payload_mls_governance_policy_root(payload: &Value) -> Option<&str> {
    payload
        .pointer("/mls_governance_binding/policy_root")
        .or_else(|| payload.pointer("/governance_binding/policy_root"))
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
}

fn value_targets_realm(value: &Value, realm_id: &str) -> bool {
    ["realm_id", "space_id"].iter().all(|field| {
        value
            .get(*field)
            .and_then(Value::as_str)
            .is_none_or(|value| value == realm_id)
    })
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
        "cx.event_envelope.v1",
        "cx.profile.core_event_store.v1",
        "cx.proof.payload_digest.v1",
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

const SENDER_COMMITMENT_FEATURE: &str = "cx.profile.franking.sender_commitment.v1";
const CX_AUDIT_ACCESSED: &str = "cx.audit.accessed";
const CX_MODERATION_FRANKING_PROOF: &str = "cx.moderation.franking_proof";
const MANAGE_OTHERS_AUDIT_MISSING: &str = "manage_others_audit_missing";

async fn append_encrypted_message_franking(
    state: &AppState,
    parsed: &ValidatedEventEnvelope,
    envelope: &Value,
) {
    if parsed.kind != "cx.message.create" {
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
        "kind": CX_MODERATION_FRANKING_PROOF,
        "space_id": parsed.realm_id,
        "target_event_id": parsed.event_id,
        "sender_did": parsed.actor_id,
        "receiving_service_did": state.config.service_did,
        "ciphertext_digest": ciphertext_digest,
        "event_canonical_digest": parsed.canonical_digest,
        "timestamp": now(),
        "audit_disclosure_policy": {
            "agent_did": policy.get("agent_did").cloned().unwrap_or(Value::Null),
            "trigger": policy.get("trigger").cloned().unwrap_or(Value::Null),
        },
    });
    let proof_digest = franking_proof_digest(&proof);
    proof["proof_digest"] = json!(proof_digest);
    append_audit_log(
        state,
        Some(&parsed.actor_id),
        CX_MODERATION_FRANKING_PROOF,
        proof,
        "accepted",
    )
    .await;
}

fn encrypted_message_ciphertext_digest(envelope: &Value) -> Option<String> {
    for pointer in [
        "/payload/encrypted_payload/digests/ciphertext",
        "/payload/encrypted_payload/ciphertext_digest",
        "/payload/ciphertext_digest",
    ] {
        if let Some(digest) = envelope.pointer(pointer).and_then(Value::as_str)
            && is_valid_sha256_digest(digest)
        {
            return Some(digest.to_owned());
        }
    }
    envelope
        .pointer("/payload/encrypted_payload/ciphertext")
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
            record.kind == kinds::CX_REALM_CREATE && record.space_id.as_deref() == Some(realm_id)
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
        "kind": proof.get("kind").and_then(Value::as_str).unwrap_or(CX_MODERATION_FRANKING_PROOF),
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
    if kind != CX_AUDIT_ACCESSED {
        return Ok(());
    }
    let payload = object
        .get("payload")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            event_validation_error(
                StatusCode::BAD_REQUEST,
                "schema_violation",
                "cx.audit.accessed payload must be an object",
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
        "target_actor_did",
        "target_cell_id",
        "target_ref",
        "writer_did",
    ];
    if payload.keys().any(|key| !ALLOWED.contains(&key.as_str())) {
        return Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            "cx.audit.accessed payload contains an unknown field",
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
            "cx.audit.accessed access_kind is invalid",
        ));
    }
    let writer_did = required_payload_string(payload, "writer_did")?;
    validate_did(&writer_did).map_err(|_| {
        event_validation_error(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            "cx.audit.accessed writer_did must be a DID",
        )
    })?;
    if object.get("actor_id").and_then(Value::as_str) != Some(writer_did.as_str()) {
        return Err(event_validation_error(
            StatusCode::FORBIDDEN,
            "actor_session_mismatch",
            "cx.audit.accessed writer_did must match actor_id",
        ));
    }
    let target_ref = required_payload_string(payload, "target_ref")?;
    if !target_ref.starts_with("cx:") {
        return Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            "cx.audit.accessed target_ref must be a typed object ref",
        ));
    }
    if required_payload_string(payload, "purpose")?
        .trim()
        .is_empty()
    {
        return Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            "cx.audit.accessed purpose must be non-empty",
        ));
    }
    let accessed_at = required_payload_string(payload, "accessed_at")?;
    DateTime::parse_from_rfc3339(&accessed_at).map_err(|_| {
        event_validation_error(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            "cx.audit.accessed accessed_at must be RFC3339",
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
                        "cx.audit.accessed paired event fields are invalid",
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
                        "cx.audit.accessed cell heads must be null or sha256 digest",
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
    let target_actor = required_payload_string(payload, "target_actor_did")?;
    validate_did(&target_actor).map_err(|_| {
        event_validation_error(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            "cx.audit.accessed target_actor_did must be a DID",
        )
    })?;
    let target_cell_id = required_payload_string(payload, "target_cell_id")?;
    if !target_cell_id.starts_with("cx:cell:") {
        return Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            "cx.audit.accessed target_cell_id must use cx:cell:",
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
                format!("cx.audit.accessed requires {field}"),
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
    if kind != kinds::CX_FLOW_WATCH_SET {
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
    if audit_record.kind != CX_AUDIT_ACCESSED {
        return Err(manage_others_audit_error(
            "audit_pair ref must point to cx.audit.accessed",
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
        ("target_actor_did", target_actor),
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
                    "audit_pair refs must use cx:event: typed ids",
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
        let registry = contrix_sdk::schema::schema_registry_from_default_spec_artifacts()
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
            .validate_value("cx.schema.event.v1", envelope)
            .map_err(|_| {
                event_validation_error(
                    StatusCode::BAD_REQUEST,
                    "schema_violation",
                    "event envelope violates cx.schema.event.v1",
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
    if kind == kinds::CX_CONFLICT_REPAIR {
        return validate_conflict_repair_event_payload(payload);
    }
    if matches!(
        kind,
        kinds::CX_SPACE_CONTAINER_ARCHIVE
            | kinds::CX_SPACE_CONTAINER_RESTORE
            | kinds::CX_SPACE_CONTAINER_TOMBSTONE
    ) {
        return validate_space_container_lifecycle_payload(payload);
    }
    contrix_sdk::schema::event_payload_validator_catalog()
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

/// R3.2 (contrix-spec @ b56cab1) — wire-breaking deny validators applied on
/// the event ingest path.
///
/// - MIU-SOL-1: `cx.member.identity.update` payloads MUST NOT carry the
///   removed handle fields (`primary_handle` / `handles[]` /
///   `verified_handle`).
/// - HC-SOL-3: message event payloads carrying mention references MUST use
///   the v2 shape (`subject_id` authoritative); the legacy
///   `subject` / `handle` / `display_snapshot` shape is rejected.
///
/// Each maps a [`crate::wire_validators::WireRejection`] to a
/// `schema_violation`-class [`EventValidationError`] carrying the precise
/// R3.2 reason code.
fn validate_r3_2_wire_shape(kind: &str, payload: &Value) -> Result<(), EventValidationError> {
    if kind == kinds::CX_MEMBER_IDENTITY_UPDATE {
        crate::wire_validators::member_identity::validate_member_identity_update_payload(payload)
            .map_err(wire_rejection_to_validation_error)?;
    }
    if matches!(kind, kinds::CX_MESSAGE_CREATE | kinds::CX_MESSAGE_REVISE)
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
    if !cell_id.starts_with("cx:cell:") {
        return Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            "conflict repair cell_id must use cx:cell:",
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
    if kind != kinds::CX_REALM_CREATE {
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
            "space lifecycle payload space_id must use cx:space:",
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
    expected_payload_digest: &str,
    canonical_bytes: &[u8],
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
    //   `payload_digest`/`created_at`/`jws`, hashing the full canonical envelope.
    //   The `type=="dev-proof"` and payload-only hash forms are NOT accepted
    //   under any circumstance — a malicious client claiming
    //   `type="dev-proof"` in production fails-closed here.
    // - **Development** (`development_mode=true`): the minimal dev-proof shape
    //   (`type="dev-proof"`, `verification_method`, `payload_digest`-of-payload)
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
            &["verification_method", "payload_digest"]
        } else {
            &[
                "kind",
                "alg",
                "verification_method",
                "payload_digest",
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
        let payload_digest =
            event_string_field(proof_object, &["payload_digest"]).ok_or_else(|| {
                event_validation_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_proof",
                    "proof payload_digest is required",
                )
            })?;
        // Production: the proof's payload_digest MUST match the canonical
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
        if payload_digest != expected_payload_digest
            && payload_only_hash_accept.as_deref() != Some(&payload_digest)
        {
            return Err(event_validation_error(
                StatusCode::BAD_REQUEST,
                "proof_payload_digest_mismatch",
                "proof payload_digest does not match the event payload",
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
            crate::jws_verify::verify_jws_ed25519(
                canonical_bytes,
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

fn event_string_field(object: &serde_json::Map<String, Value>, keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|key| object.get(*key).and_then(Value::as_str))
        .map(ToOwned::to_owned)
}

/// True iff a `cx.realm.create` event's `payload.object.created_by`
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

async fn member_join_accepts_pending_invite(
    state: &AppState,
    object: &serde_json::Map<String, Value>,
    actor: &str,
    space_id: &str,
) -> bool {
    if object.get("kind").and_then(Value::as_str) != Some(kinds::CX_MEMBER_STATE) {
        return false;
    }
    let Some(payload) = object.get("payload") else {
        return false;
    };
    if payload.get("membership").and_then(Value::as_str) != Some("join") {
        return false;
    }
    let target_actor = payload
        .get("actor_id")
        .or_else(|| payload.get("member"))
        .and_then(Value::as_str)
        .unwrap_or(actor);
    if target_actor != actor {
        return false;
    }
    let Some(invite_id) = payload.get("invite_id").and_then(Value::as_str) else {
        return false;
    };
    if crate::ids::parse_typed_uuid(invite_id, "invite").is_none() {
        return false;
    }
    let Ok(Some(invite)) = state.persistence.space_invites().get(invite_id).await else {
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
    invite.space_id.replacen("cx:space:", "cx:realm:", 1)
        == space_id.replacen("cx:space:", "cx:realm:", 1)
}

/// Quick existence probe against the in-memory `state.realms` index used
/// by the regular `realm_has_member` check. Used to gate the
/// `cx.realm.create` bootstrap path so a duplicate-create attempt (where
/// the Realm already has members) falls back to the normal member check.
fn space_exists_in_index(state: &AppState, space_id: &str) -> bool {
    let Ok(space_id_typed) = contrix_sdk::RealmId::new(space_id.to_owned()) else {
        return false;
    };
    state
        .realms
        .lock()
        .map(|spaces| spaces.get(&space_id_typed).is_some())
        .unwrap_or(false)
}

/// Spec realm-and-space.md §2.6 step 2 — when a `cx.realm.create` event
/// commits, materialise the in-memory Realm index entry with the
/// creator as the first member so subsequent facet events (join_rule /
/// history_visibility / discovery / policy_components / ...) from the
/// same actor pass the regular `realm_has_member` check without a
/// separate `cx.member.state(join)` event.
///
/// Extracted out of `submit_event` (called once after `store.put`
/// succeeds for a `cx.realm.create` event) so the canonical Event
/// Envelope path owns Realm bootstrap state.
async fn bootstrap_realm_member_index(
    state: &AppState,
    space_id: &str,
    actor: &str,
    object: &serde_json::Map<String, Value>,
) {
    let Ok(space_id_typed) = contrix_sdk::RealmId::new(space_id.to_owned()) else {
        tracing::warn!(%space_id, "bootstrap_realm_member_index: invalid realm_id shape");
        return;
    };
    let Ok(actor_typed) = contrix_sdk::Did::new(actor.to_owned()) else {
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
    let mut entry = crate::state::RealmDirectoryEntry::new(space_id_typed.clone(), title);
    entry.description = summary.clone();
    entry.public = discoverability == "public";
    entry.members.insert(actor_typed);
    if let Ok(mut spaces) = state.realms.lock() {
        spaces.upsert(entry);
    }
    let meta = crate::state::RealmMetaRecord {
        owner: actor.to_owned(),
        deleted: false,
        discoverability,
        history_visibility,
        encryption_profile,
        plaintext_visible_services,
        created_at: super::now(),
        updated_at: super::now(),
    };
    if let Err(error) = state.persistence.realm_meta().put(space_id, &meta).await {
        tracing::error!(%error, %space_id, "bootstrap_realm_member_index: failed to persist Realm meta record");
    }
}

/// CXP-0007 — recursively scan `value` for the first key listed in the SDK's
/// [`contrix_sdk::forbidden_wire_fields::FORBIDDEN_WIRE_FIELDS`] hard-reject
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
                    if contrix_sdk::forbidden_wire_fields::is_forbidden_wire_field(key) {
                        // Translate the wire key back to the SDK's canonical
                        // &'static str so the caller's error message uses a
                        // stable identifier.
                        return contrix_sdk::forbidden_wire_fields::FORBIDDEN_WIRE_FIELDS
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
                    "event references must use the cx:event: typed prefix",
                ));
            }
            Ok(event_id.to_owned())
        })
        .collect()
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
    // every proof's `payload_digest` MUST be derived from canonical event bytes
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
        sync_token: super::sync::sync_token_for_state(state),
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
    if matches!(
        parsed.kind.as_str(),
        "cx.consent.grant" | "cx.consent.revoke"
    ) {
        payload_object
            .entry("actor_seq".to_owned())
            .or_insert_with(|| Value::from(parsed.actor_seq));
    }
    if parsed.kind == kinds::CX_MORPH_SCHEMA_MIGRATE {
        if let Some(authorization_ref) = parsed.authorized_refs.first() {
            payload_object
                .entry("authorization_ref".to_owned())
                .or_insert_with(|| Value::String(authorization_ref.clone()));
        }
        payload_object
            .entry("capability_action".to_owned())
            .or_insert_with(|| Value::String("cx.morph.schema.migrate".to_owned()));
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

fn event_operation_id(envelope: &Value, event_id: &str) -> Option<OperationId> {
    // Prefer the client-supplied alias when it's a valid OperationId
    // (`cx:operation:<uuid v7>` per `contrix-rust-sdk/identifiers`).
    // Older yougen builds shipped the event_id (cx:event:) verbatim in
    // this slot; soland MUST NOT silently drop projection for such
    // events ── fall through to the event_id-derived form so the
    // projection chain (`project_accepted_operations` →
    // `project_membership_operation` → SpaceInviteRecord write) still
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
    let suffix = event_id.strip_prefix("cx:event:")?;
    OperationId::new(format!("cx:operation:{suffix}")).ok()
}

pub(super) fn event_read_response(record: &CanonicalEventRecord) -> EventReadResponse {
    let realm_id = canonical_realm_id_for_record(record);
    // CXP-0007 (spec b7d35be) — surface `effective_scope` on read so
    // clients can branch on Circle vs Realm-default scope without
    // re-deriving from the envelope. The field is sourced from either
    // the envelope's top-level `effective_scope` or the payload-side
    // `scope_circle_id`, whichever the writer populated.
    let effective_scope = effective_scope_for_envelope(&record.envelope);
    let mut metadata = json!({
        "event_id": record.event_id.clone(),
        "actor_id": record.actor_id.clone(),
        "actor_seq": record.actor_seq,
        "realm_id": realm_id,
        "space_id": record.space_id.clone(),
        "kind": record.kind.clone(),
        "schema_id": record.schema_id.clone(),
        "canonical_digest": record.canonical_digest.clone(),
        "received_at": record.received_at,
    });
    if let Some(scope) = effective_scope {
        metadata
            .as_object_mut()
            .expect("metadata is object")
            .insert("effective_scope".to_owned(), Value::String(scope));
    }
    EventReadResponse {
        event: record.envelope.clone(),
        metadata,
    }
}

/// CXP-0007 — resolve the canonical `effective_scope` for an Event
/// Envelope on read. Returns `Some(circle_id)` when the envelope (or its
/// payload) names a Circle scope, `Some("realm:<realm_id>")` when the
/// scope is the Realm default, or `None` when neither can be derived.
fn effective_scope_for_envelope(envelope: &Value) -> Option<String> {
    let object = envelope.as_object()?;
    if let Some(scope) = object.get("effective_scope").and_then(Value::as_str) {
        return Some(scope.to_owned());
    }
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

pub(super) fn event_read_response_for_state(
    state: &AppState,
    record: &CanonicalEventRecord,
) -> EventReadResponse {
    let mut response = event_read_response(record);
    if let Some(tombstone) = retention_tombstone_for_event(state, &record.event_id) {
        if let Some(object) = response.event.as_object_mut() {
            let payload = object.get("payload").cloned().unwrap_or(Value::Null);
            object.insert(
                "payload".to_owned(),
                retention_tombstone_payload_value(&payload, &tombstone),
            );
            object.insert("retention_tombstone".to_owned(), json!(true));
        }
        if let Some(metadata) = response.metadata.as_object_mut() {
            metadata.insert("retention_state".to_owned(), json!("tombstoned"));
            metadata.insert(
                "retention_reason".to_owned(),
                json!(tombstone.reason.as_str()),
            );
            metadata.insert(
                "retention_expired_at".to_owned(),
                json!(tombstone.expired_at.to_rfc3339()),
            );
            metadata.insert(
                "retention_tombstoned_at".to_owned(),
                json!(tombstone.tombstoned_at.to_rfc3339()),
            );
            metadata.insert(
                "retention_anchor_preserved".to_owned(),
                json!(tombstone.anchored),
            );
            metadata.insert("physical_delete".to_owned(), json!(false));
        }
    }
    response
}

pub(super) fn events_frontier_json(records: &[CanonicalEventRecord]) -> Value {
    let mut actors: BTreeMap<String, u64> = BTreeMap::new();
    let mut realms: BTreeMap<String, (DateTime<Utc>, String)> = BTreeMap::new();
    let mut spaces: BTreeMap<String, (DateTime<Utc>, String)> = BTreeMap::new();
    for record in records {
        actors
            .entry(record.actor_id.clone())
            .and_modify(|seq| *seq = (*seq).max(record.actor_seq))
            .or_insert(record.actor_seq);
        if let Some(realm_id) = canonical_realm_id_for_record(record) {
            if frontier_entry_is_newer(&realms, &realm_id, record) {
                realms.insert(realm_id, (record.received_at, record.event_id.clone()));
            }
        }
        if let Some(space_id) = record.space_id.as_deref() {
            if frontier_entry_is_newer(&spaces, space_id, record) {
                spaces.insert(
                    space_id.to_owned(),
                    (record.received_at, record.event_id.clone()),
                );
            }
        }
    }
    let realms = realms
        .into_iter()
        .map(|(id, (_, event_id))| (id, event_id))
        .collect::<BTreeMap<_, _>>();
    let spaces = spaces
        .into_iter()
        .map(|(id, (_, event_id))| (id, event_id))
        .collect::<BTreeMap<_, _>>();
    json!({
        "actors": actors,
        "realms": realms,
        "spaces": spaces,
        "event_count": records.len()
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

fn canonical_realm_id_for_record(record: &CanonicalEventRecord) -> Option<String> {
    record
        .envelope
        .get("realm_id")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .or_else(|| record.space_id.clone())
}

pub(super) async fn event_visible_to_session(
    state: &AppState,
    record: &CanonicalEventRecord,
    session: &SessionRecord,
) -> bool {
    if record.actor_id == session.actor {
        return true;
    }
    match record.space_id.as_deref() {
        Some(space_id) => {
            realm_event_visible_to_session(
                state,
                space_id,
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
        .filter(|scope| scope.starts_with("cx:circle:"))
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
/// recent `cx.realm.read_receipt_policy` event in `space_id` and return
/// `(disclosure, visibility, scope_overrides_allowed)` from its payload.
/// Returns `None` when no policy event has been written for this Space —
/// caller treats that as the spec default `Optional` / `Members` /
/// `scope_overrides_allowed=true`.
///
/// Used by future ephemeral `cx.receipt.read` fanout handlers to enforce
/// the policy: when `disclosure="disabled"`, drop the receipt and return
/// HTTP 403 with `error.code` `policy_violation`. When `visibility="private"`,
/// fanout only to the original sender of the referenced event.
///
/// **Note**: this is a linear scan of the durable event store. For the
/// production fanout path it should be projected into `AppState` once the
/// reducer kind delegates from `Ignored` to a real projection.
pub async fn effective_read_receipt_policy_for_space(
    state: &AppState,
    space_id: &str,
) -> Option<(String, String, bool)> {
    // Cell-keyed fast path. The Move/Anchor pipeline writes the
    // `cx.component.realm.read_receipt_policy.v1` resolved CasRegister
    // value into `ProjectionState::cells` after every apply_anchor; we
    // read directly from there. (R1.2 renamed the cell family from
    // `cx.component.space.read_receipt_policy.v1` along with the event
    // kind.)
    if let Ok(proj) = state.projection.lock() {
        let cell_id = contrix_sdk::CellRef::new(format!(
            "cx:cell:cx.component.realm.read_receipt_policy.v1:{space_id}"
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
        // canonical Contrix event kind string.
        if record.kind != "cx.realm.read_receipt_policy" {
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

            compaction_prune_walk_per_space_limit: 50,
            seed_demo_data: true,
            trust_domain: "cx:trust_domain:soland.local".to_owned(),
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
            device_id: "cx:device:01904100-0000-7000-8000-a11ce0000001".to_owned(),
            audience: "did:web:soland.local".to_owned(),
            expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
            created_at: chrono::Utc::now(),
            revoked_at: None,
        }
    }

    #[tokio::test]
    async fn policy_components_media_plaintext_reads_realm_meta() {
        let state = make_state(true);
        let realm_id = "cx:realm:01904100-0000-7000-8000-a11ce0000001";
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
                    encryption_profile: Some("mls_rfc9420".to_owned()),
                    plaintext_visible_services: std::collections::BTreeSet::from([state
                        .config
                        .service_did
                        .clone()]),
                    created_at: now,
                    updated_at: now,
                },
            )
            .await
            .unwrap();

        let payload = json!({ "media_service_decrypts": true });

        assert!(projected_media_plaintext_service_present(&state, realm_id, &payload).await);
    }

    #[test]
    fn policy_components_mls_governance_reads_projection_cell() {
        let state = make_state(true);
        let realm_id = "cx:realm:01904100-0000-7000-8000-a11ce0000001";
        let policy_root = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        {
            let mut projection = state.projection.lock().unwrap();
            projection.cells.insert(
                contrix_sdk::CellRef::new(
                    "cx:cell:cx.component.mls.epoch.v1:cx:mls_group:unit-test".to_owned(),
                )
                .unwrap(),
                contrix_sdk::lattice::CellState::Value(json!({
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
            json!({ "schema": ["cx.schema.event.v1"] }),
        );
        assert_eq!(
            event_requirements_schema_id(&state, &object).unwrap(),
            "cx.schema.event.v1"
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
                "flow_id": "cx:flow:01904100-0000-7000-8000-f10dc0000001"
            }
        });
        let object = envelope.as_object().unwrap();
        let err = validate_event_schema_and_payload(
            &state,
            "cx.flow.move",
            "cx.schema.event.v1",
            &envelope,
            object,
        )
        .expect_err("flow.move without target/rank must fail payload validation");
        assert_eq!(err.code, "schema_violation");
    }

    #[test]
    fn event_payload_validator_enforces_flow_update_object_patch_schema() {
        let state = make_state(true);
        let flow_id = "cx:flow:01904100-0000-7000-8000-f10dc0000001";
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
            "cx.flow.update",
            "cx.schema.event.v1",
            &valid,
            valid.as_object().unwrap(),
        )
        .expect("canonical cx.flow.update object_patch_payload should validate");

        let legacy_top_level_fields = json!({
            "payload": {
                "flow_id": flow_id,
                "fields": {
                    "document": { "blocks": [] }
                }
            }
        });
        let err = validate_event_schema_and_payload(
            &state,
            "cx.flow.update",
            "cx.schema.event.v1",
            &legacy_top_level_fields,
            legacy_top_level_fields.as_object().unwrap(),
        )
        .expect_err("cx.flow.update without payload.patch must fail object_patch_payload");
        assert_eq!(err.code, "schema_violation");

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
            "cx.flow.update",
            "cx.schema.event.v1",
            &invalid_patch_op,
            invalid_patch_op.as_object().unwrap(),
        )
        .expect_err("cx.flow.update patch operations must match cx.patch.v1 exactly");
        assert_eq!(err.code, "schema_violation");
    }

    #[test]
    fn event_payload_validator_catalog_covers_active_standard_durable_events() {
        let catalog = contrix_sdk::schema::event_payload_validator_catalog();
        let event_kinds = artifacts::active_durable_event_kinds()
            .iter()
            .map(String::as_str)
            .filter(|kind| contrix_sdk::events::is_standard_event_kind(kind))
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
        let catalog = contrix_sdk::schema::event_payload_validator_catalog();
        let object_patch_kinds = [
            "cx.realm.update",
            "cx.flow.update",
            "cx.flow.tracks.update",
            "cx.morph.update",
            "cx.profile.update",
            "cx.profile.space_override",
        ];
        let missing = catalog.missing_payload_validators_for(object_patch_kinds);
        assert!(
            missing.is_empty(),
            "missing object_patch validators: {missing:?}"
        );

        for event_kind in object_patch_kinds {
            catalog
                .validate_payload(
                    event_kind,
                    &json!({
                            "target_ref": "cx:flow:01904100-0000-7000-8000-f10dc0000001",
                            "patch": {
                                "title": { "$op": "set", "value": "Roadmap" }
                            }
                    }),
                )
                .unwrap_or_else(|err| {
                    panic!("{event_kind} must accept canonical object_patch_payload: {err}");
                });
            assert!(
                catalog
                    .validate_payload(event_kind, &json!({ "title": "Roadmap" }))
                    .is_err(),
                "{event_kind} must reject legacy non-patch update payloads"
            );
            assert!(
                catalog
                    .validate_payload(
                        event_kind,
                        &json!({
                            "target_ref": "cx:flow:01904100-0000-7000-8000-f10dc0000001",
                            "patch": {
                                "title": { "$op": "replace", "value": "Roadmap" }
                            }
                        }),
                    )
                    .is_err(),
                "{event_kind} must reject patch ops outside cx.patch.v1"
            );
        }
    }

    #[test]
    fn realm_create_rejects_world_readable_encrypted_history() {
        let state = make_state(true);
        let realm_id = "cx:realm:01904100-0000-7000-8000-a11ce0000001";
        let envelope = json!({
            "payload": {
                "object": {
                    "id": realm_id,
                    "schema": "cx.schema.realm.v1",
                    "title": "encrypted public history",
                    "created_by": "did:web:alice.example",
                    "trust_domain": "cx:trust_domain:soland.local",
                    "schema_refs": ["cx.schema.realm.v1"],
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
            "cx.realm.create",
            "cx.schema.event.v1",
            &envelope,
            object,
        )
        .expect_err("encrypted world-readable Realm history must fail closed");
        assert_eq!(err.code, "incompatible_history_with_encryption");
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
            b"canonical-event",
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
            b"canonical-event",
        );
        assert!(
            result.is_ok(),
            "development mode should accept matching dev-proof: {result:?}"
        );
    }

    #[test]
    fn production_rejects_full_proof_without_valid_jws_signature() {
        let state = make_state(false);
        let session = session();
        let canonical_bytes = br#"{"actor_id":"did:web:alice.example","event_id":"cx:event:test"}"#;
        let payload_digest = format!("sha256:{}", sha256_hex(canonical_bytes));
        let mut object = serde_json::Map::new();
        object.insert(
            "proofs".to_owned(),
            json!([{
                "kind": "detached_jws",
                "alg": "EdDSA",
                "verification_method": "did:web:alice.example#k1",
                "payload_digest": payload_digest,
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
            canonical_bytes,
        )
        .expect_err("production must reject unsigned/fake JWS proofs");
        assert_eq!(err.code, "invalid_proof");
        assert!(
            err.message.contains("JWS verification failed"),
            "unexpected message: {}",
            err.message
        );
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
        use contrix_sdk::Audience;
        use contrix_sdk::Hash;
        use contrix_sdk::signatures::{ProductionVerifier, build_proof_envelope};

        struct Noop;
        impl contrix_sdk::signatures::EventVerifier for Noop {
            fn verify(
                &self,
                _: &[u8],
                _: &[u8],
                _: &contrix_sdk::signatures::PublicKeyMaterial,
            ) -> std::result::Result<(), contrix_sdk::signatures::VerifierError> {
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
            contrix_sdk::signatures::VerifierError::DevProofRejected(_)
        ));

        // A proof with kind="detached_jws" — SDK accepts the kind
        // (signature still has to verify separately).
        let prod = build_proof_envelope(
            contrix_sdk::signatures::detached_jws_kind(),
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
