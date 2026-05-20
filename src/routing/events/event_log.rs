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
use contrix_sdk::{Hlc, Operation, OperationId, SpaceId, canonical};
use salvo::http::StatusCode;
use salvo::oapi::extract::{JsonBody, PathParam};
use salvo::prelude::*;
use serde_json::{Value, json};

use super::operations as events_operations;
use super::{
    append_audit_log, auth_or_render, is_valid_sha256_digest, now, project_accepted_operations,
    query_param, query_param_all, render_error, sha256_hex, space_has_member, validate_did,
    validate_operation_policy, validate_operation_semantics, validate_space_id,
};
use crate::error::{AppError, ErrorCode};
use crate::result::{JsonResult, json_ok};
use crate::routing::system::extract::AuthArgs;
use crate::state::{AppState, CanonicalEventRecord, SessionRecord};
use crate::wire::{
    EventBatchGetRequest, EventBatchGetResponse, EventDescribeResponse, EventReadResponse,
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
            render_error(res, error.status, error.code, &error.message);
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
        if let Some(content) = operation.payload.get("content") {
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
            // `cx.flow.tracks.update` follows the spec §5.1
            // update-on-non-active rule: parent Flow MUST be Active or
            // the admission rejects with `flow_not_active` (mirrors the
            // SDK reducer guard so client + server agree).
            if let Err(reason) = proj.check_flow_tracks_transition(operation) {
                render_error(res, StatusCode::PRECONDITION_FAILED, reason, reason);
                return;
            }
        }
    }
    // Clone the envelope before passing to store.put — the bootstrap
    // branch below still needs to read payload.object.* for
    // cx.realm.create. Negligible cost: the envelope is already in
    // memory and the alternative is fetching it back out of the
    // store, which serialises through I/O.
    let envelope_for_bootstrap = envelope.clone();
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
    // Spec realm-and-space.md §2.6 — `cx.realm.create` commit MUST
    // atomically seed the creator into the Realm's member set so
    // facet events from the same actor that arrive afterwards (even
    // in the same client batch) pass the regular space_has_member
    // check. The validator above already lets the create event through
    // without the check; here we make sure subsequent events see a
    // populated index.
    if parsed.kind == "cx.realm.create"
        && let Some(space_id_str) = parsed.space_id.as_deref()
        && let Some(envelope_object) = envelope_for_bootstrap.as_object()
    {
        bootstrap_realm_member_index(
            state,
            space_id_str,
            &parsed.actor_id,
            envelope_object,
        );
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
/// Returns `Result<EventsPageResponse, AppError>` so the wrapper can be a
/// typed `JsonResult<T>` handler and the sync-side dispatcher can map the
/// typed result into its own `&mut Response` shape with a single `match`.
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
) -> crate::result::JsonResult<EventsFrontierResBody> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req)?;
    let actor_id = query_param(req, "actor_id");
    let space_id = query_param(req, "space_id");
    // Round C47 (spec e10b6ad): `peer_role` ∈ {account_client,
    // federation_peer, anonymous_health}; default `account_client`.
    // federation_peer additionally returns `frontier_root`, per-actor
    // `actor_seq_upper_bounds`, and a service signature; anonymous_health
    // returns only the frontier_root summary. TODO(C47 Lane B4): wire real
    // Merkle root commitment + service-signature envelope.
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
        .unwrap_or_default();
    let mut actor_frontier: BTreeMap<String, u64> = BTreeMap::new();
    let mut space_frontier: BTreeMap<String, Value> = BTreeMap::new();
    // Round 4 (B1.4) — collect a parallel SpaceId → Vec<EventId> map so
    // the typed response variants can be built without re-parsing the
    // string forms.
    let mut space_to_event_ids: BTreeMap<String, Vec<String>> = BTreeMap::new();
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
            space_to_event_ids
                .entry(space_id.to_owned())
                .or_default()
                .push(record.event_id.clone());
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
    let typed_space_frontier =
        crate::round4::typed_space_frontier(space_to_event_ids.clone());
    let typed_actor_bounds =
        crate::round4::typed_actor_upper_bounds(actor_frontier.clone());
    let typed_response = crate::round4::build_typed_frontier_response(
        peer_role,
        &service_did,
        typed_space_frontier,
        typed_actor_bounds,
        None,
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
        "generated_at": now(),
        "peer_role": peer_role_str,
        "events_frontier_v2": serde_json::to_value(&typed_response).unwrap_or(Value::Null),
    });
    match peer_role {
        contrix_sdk::FrontierPeerRole::FederationPeer => {
            if let Some(obj) = frontier.as_object_mut() {
                // TODO(round4-fed-frontier-signature): compute the real
                // frontier_root + sign over canonical-JSON. Until then,
                // the typed `events_frontier_v2` envelope carries the
                // placeholder service_binding_ref + zero-hash root.
                obj.insert("frontier_root".to_owned(), Value::Null);
                obj.insert(
                    "actor_seq_upper_bounds".to_owned(),
                    serde_json::to_value(&actor_frontier).unwrap_or(Value::Null),
                );
                obj.insert("signature".to_owned(), Value::Null);
            }
        }
        contrix_sdk::FrontierPeerRole::AnonymousHealth => {
            // Strip everything that would leak per-tenant state.
            if let Some(obj) = frontier.as_object_mut() {
                obj.insert("frontier_root".to_owned(), Value::Null);
            }
            // Clear actor_frontier + space_frontier in the legacy envelope.
            return crate::result::json_ok(EventsFrontierResBody {
                actor_frontier: BTreeMap::new(),
                space_frontier: BTreeMap::new(),
                frontier,
            });
        }
        contrix_sdk::FrontierPeerRole::AccountClient => {}
    }
    crate::result::json_ok(EventsFrontierResBody {
        actor_frontier,
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
            code.http_status(),
            code.as_str(),
            reason,
        ));
    }
    // Round R2/R3 (T07) — Realm in terminal state (cx.realm.destroy applied)
    // refuses every non-audit-class write.
    let realm_destroyed = if let Some(space_id) = event_string_field(object, &["space_id"]) {
        state
            .projection
            .lock()
            .map(|proj| proj.space_is_destroyed(&space_id))
            .unwrap_or(false)
    } else {
        false
    };
    if let Some((code, reason)) = crate::round23::terminal_realm_check(realm_destroyed, &kind) {
        return Err(event_validation_error(
            code.http_status(),
            code.as_str(),
            reason,
        ));
    }

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
    validate_event_time_fields(state, object)?;

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
    // Spec realm-and-space.md §2.6 — `cx.realm.create` is the genesis
    // event for both the Realm metadata cell AND the creator's first
    // member-state cell. The reducer MUST treat `created_by_principal`
    // as already-a-member when admitting this event; otherwise spec-
    // correct clients can never bootstrap a Realm through the canonical
    // event-submission path. The submit_event commit path (below)
    // materialises the member set in state.spaces immediately after
    // store.put succeeds, so any follow-up facet event in the same
    // session naturally passes the regular space_has_member check.
    let is_realm_create_bootstrap = kind == "cx.realm.create"
        && realm_create_actor_is_creator(object, &session.actor)
        && !space_exists_in_index(state, &space_id);
    if !is_realm_create_bootstrap && !space_has_member(state, &space_id, &session.actor) {
        return Err(event_validation_error(
            StatusCode::FORBIDDEN,
            "capability_denied",
            "actor is not a member of the event Space",
        ));
    }
    require_object_field(object, "payload")?;
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
            return Err(event_validation_error(code.http_status(), code.as_str(), &reason));
        }
    }
    // Round R2/R3 (T09 + T12) — realm.policy_components hard ceiling, e2ee_relaxed
    // mutex, and media plaintext triple binding. Active profile set + bindings
    // come from the projection; TODO(round23-T12) plumb full per-Realm projection
    // for `plaintext_visible_services[]` and MLS governance binding policy_root.
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
        // TODO(round23-T12): replace these `false` defaults with reads from
        // the per-Realm projection (`plaintext_visible_services[].purpose=media_plaintext`
        // + current `cx.component.mls.epoch.v1` governance binding policy_root).
        let media_plaintext_service_present = payload
            .pointer("/plaintext_visible_services")
            .and_then(Value::as_array)
            .is_some_and(|arr| {
                arr.iter().any(|svc| {
                    svc.get("purpose").and_then(Value::as_str) == Some("media_plaintext")
                })
            });
        let mls_governance_binding_covers_policy_root = payload
            .pointer("/mls_governance_binding/policy_root")
            .is_some();
        if let Err((code, reason)) = crate::round23::realm_policy_components_check(
            &payload,
            &active_profiles,
            media_plaintext_service_present,
            mls_governance_binding_covers_policy_root,
        ) {
            return Err(event_validation_error(code.http_status(), code.as_str(), &reason));
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
            return Err(event_validation_error(code.http_status(), code.as_str(), &reason));
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
    )?;
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
        space_id: Some(space_id),
        kind,
        schema_id,
        prev_refs,
        authorized_refs,
        canonical_digest,
        canonical_bytes,
    })
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

const SENDER_COMMITMENT_FEATURE: &str = "cx.profile.franking.sender_commitment.v1";
const CX_AUDIT_ACCESSED: &str = "cx.audit.accessed";
const MANAGE_OTHERS_AUDIT_MISSING: &str = "manage_others_audit_missing";

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

fn event_requirements_features<'a>(
    object: &'a serde_json::Map<String, Value>,
) -> impl Iterator<Item = &'a str> {
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
        "watch_manage_others"
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
        "watch_manage_others" => {
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

fn validate_flow_watch_audit_pair(
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
        .get("actor_did")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            event_validation_error(
                StatusCode::BAD_REQUEST,
                "schema_violation",
                "flow watch payload requires actor_did",
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
        ("access_kind", "watch_manage_others"),
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
    contrix_sdk::schema::event_payload_validator_catalog()
        .validate_payload(kind, payload)
        .map_err(|error| {
            event_validation_error(
                StatusCode::BAD_REQUEST,
                "schema_violation",
                format!("event payload violates the registered payload schema: {error}"),
            )
        })?;
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
    expected_payload_hash: &str,
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
        if !is_dev_proof && event_string_field(proof_object, &["alg"]).as_deref() != Some("EdDSA") {
            return Err(event_validation_error(
                StatusCode::BAD_REQUEST,
                "invalid_proof",
                "event proof alg must be EdDSA",
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
                let bytes = canonical::canonical_json_bytes(payload).unwrap_or_default();
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

/// True iff a `cx.realm.create` event's `payload.object.created_by_principal`
/// matches the session actor. Spec realm-and-space.md §2.6 — this is the
/// genesis-member condition that lets the create event bypass the regular
/// `space_has_member` check.
fn realm_create_actor_is_creator(
    object: &serde_json::Map<String, Value>,
    actor: &str,
) -> bool {
    object
        .get("payload")
        .and_then(|payload| payload.get("object"))
        .and_then(|create_object| create_object.get("created_by_principal"))
        .and_then(Value::as_str)
        .is_some_and(|creator| creator == actor)
}

/// Quick existence probe against the in-memory `state.spaces` index used
/// by the regular `space_has_member` check. Used to gate the
/// `cx.realm.create` bootstrap path so a duplicate-create attempt (where
/// the Realm already has members) falls back to the normal member check.
fn space_exists_in_index(state: &AppState, space_id: &str) -> bool {
    let Ok(space_id_typed) = contrix_sdk::SpaceId::new(space_id.to_owned()) else {
        return false;
    };
    state
        .spaces
        .lock()
        .map(|spaces| spaces.get(&space_id_typed).is_some())
        .unwrap_or(false)
}

/// Spec realm-and-space.md §2.6 step 2 — when a `cx.realm.create` event
/// commits, materialise the in-memory Realm index entry with the
/// creator as the first member so subsequent facet events (join_rule /
/// history_visibility / discovery / policy_components / ...) from the
/// same actor pass the regular `space_has_member` check without a
/// separate `cx.member.state(join)` event.
///
/// Extracted out of `submit_event` (called once after `store.put`
/// succeeds for a `cx.realm.create` event) so the private REST
/// `POST /api/v1/spaces` endpoint can be deprecated without losing
/// the bootstrap path.
fn bootstrap_realm_member_index(
    state: &AppState,
    space_id: &str,
    actor: &str,
    object: &serde_json::Map<String, Value>,
) {
    let Ok(space_id_typed) = contrix_sdk::SpaceId::new(space_id.to_owned()) else {
        tracing::warn!(%space_id, "bootstrap_realm_member_index: invalid space_id shape");
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
    let mut entry = contrix_sdk::SpaceSearchEntry::new(space_id_typed.clone(), title);
    entry.description = summary.clone();
    entry.public = discoverability == "public";
    entry.members.insert(actor_typed);
    if let Ok(mut spaces) = state.spaces.lock() {
        spaces.upsert(entry);
    }
    let meta = crate::state::SpaceMetaRecord {
        owner: actor.to_owned(),
        deleted: false,
        discoverability,
        history_visibility,
        encryption_profile,
        plaintext_visible_services: std::collections::BTreeSet::new(),
        created_at: super::now(),
        updated_at: super::now(),
    };
    if let Err(error) = state.persistence.space_meta().put(space_id, &meta) {
        tracing::error!(%error, %space_id, "bootstrap_realm_member_index: failed to persist SpaceMetaRecord");
    }
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
/// recent `cx.realm.read_receipt_policy` event in `space_id` and return
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
    let records = state.persistence.events().snapshot_all().ok()?;
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
            seed_demo_data: true,
            trust_domain: "cx:trust_domain:soland.local".to_owned(),
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

        object.insert("hlc".to_owned(), json!("019041000000-00000000-AABBCCDD"));
        let err = validate_event_time_fields(&state, &object)
            .expect_err("uppercase HLC is not canonical");
        assert_eq!(err.code, "invalid_param");

        object.insert("hlc".to_owned(), json!("019041000000-00000000-aabbccdd"));
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
        let payload_hash = format!("sha256:{}", sha256_hex(canonical_bytes));
        let mut object = serde_json::Map::new();
        object.insert(
            "proofs".to_owned(),
            json!([{
                "kind": "detached_jws",
                "alg": "EdDSA",
                "verification_method": "did:web:alice.example#k1",
                "payload_hash": payload_hash,
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
