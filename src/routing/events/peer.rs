use std::collections::{BTreeMap, BTreeSet};

use chrono::SecondsFormat;
use cokret_sdk::http::{EventsQueryOutcome, EventsResolveOutcome, EventsResolveRequestBody};
use cokret_sdk::{Did, EventsQueryPostRequestBody, RealmId, canonical};
use salvo::http::StatusCode;
use salvo::prelude::*;
use serde_json::{Value, json};

use super::{
    is_realm_deleted, is_valid_sha256_digest, now, query_param, query_param_all, render_error,
    validate_did,
};
use crate::error::AppError;
use crate::result::{JsonResult, json_ok};
use crate::state::{AppState, CanonicalEventRecord};

const HEADER_SOURCE_SERVICE_DID: &str = "source-service-did";
const HEADER_DESTINATION_SERVICE_DID: &str = "destination-service-did";
const MAX_PEER_EVENTS_QUERY_LIMIT: usize = 100;
const MAX_PEER_EVENTS_RESOLVE: usize = 100;

pub(super) fn router() -> Router {
    Router::new()
        .push(Router::with_path("events/describe").get(peer_events_describe))
        .push(
            Router::with_path("events")
                .post(peer_events_submit)
                .get(peer_events_query),
        )
        .push(Router::with_path("events/query").post(peer_events_query_post))
        .push(Router::with_path("events/resolve").post(peer_events_resolve))
        .push(Router::with_path("events/frontier").get(peer_events_frontier))
        .push(Router::with_path("snapshot/head").get(peer_snapshot_head))
}

#[endpoint(
    operation_id = "ck.peer.events.describe",
    tags("peer"),
    summary = "Describe the federation peer Events API"
)]
#[tracing::instrument(skip_all, fields(op = "ck.peer.events.describe"))]
async fn peer_events_describe(depot: &mut Depot) -> JsonResult<Value> {
    let state = depot.obtain::<AppState>().expect("state injected");
    json_ok(json!({
        "service_did": state.config.service_did.clone(),
        "protocol_version": "1.0",
        "primary_write_path": "/_cokret/peer/events",
        // `ck.peer.snapshot.head` is intentionally NOT declared: soland
        // cannot produce a real signed `ck.schema.snapshot.v1` manifest yet,
        // and spec service-surface.md §5.2 / service-http-binding.md §6.1
        // forbid declaring (or stub-serving) the operation in that state —
        // the endpoint returns `not_implemented` instead.
        "supported_operations": [
            "ck.peer.events.describe",
            "ck.peer.events.submit",
            "ck.peer.events.query",
            "ck.peer.events.query_post",
            "ck.peer.events.resolve",
            "ck.peer.events.frontier",
            "ck.peer.invites.submit"
        ],
        "supported_profiles": [
            "ck.profile.federation_minimal.v1"
        ],
        "supported_bindings": [
            "http-message-signature",
            "source-service-did",
            "destination-service-did",
            "source-trust-domain",
            "destination-trust-domain",
            "request-canonical-digest"
        ],
        "limits": {
            "max_batch_size": 100,
            "max_query_limit": MAX_PEER_EVENTS_QUERY_LIMIT,
            "max_resolve": MAX_PEER_EVENTS_RESOLVE
        }
    }))
}

#[handler]
#[tracing::instrument(skip_all, fields(op = "ck.peer.events.submit"))]
async fn peer_events_submit(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let body = match req.parse_json::<Value>().await {
        Ok(body) => body,
        Err(_) => {
            render_error(
                res,
                StatusCode::BAD_REQUEST,
                "bad_json",
                "invalid ck.peer.events.submit request body",
            );
            return;
        }
    };
    if let Err(error) = validate_peer_request(state, req, Some(&body)) {
        render_app_error(res, error);
        return;
    }
    super::event_log::submit_federation_events(state, req, body, res).await;
}

#[endpoint(
    operation_id = "ck.peer.events.query",
    tags("peer"),
    summary = "Query federation-visible Event Envelopes"
)]
#[tracing::instrument(skip_all, fields(op = "ck.peer.events.query"))]
async fn peer_events_query(depot: &mut Depot, req: &mut Request) -> JsonResult<EventsQueryOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
    validate_peer_request(state, req, None)?;
    let parts = PeerEventsQueryParts::from_query(req)?;
    peer_events_query_response(state, parts).await
}

#[endpoint(
    operation_id = "ck.peer.events.query_post",
    tags("peer"),
    summary = "Query federation-visible Event Envelopes with a JSON body"
)]
#[tracing::instrument(skip_all, fields(op = "ck.peer.events.query_post"))]
async fn peer_events_query_post(
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<EventsQueryOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let body = parse_json_body(req, "invalid ck.peer.events.query request body").await?;
    validate_peer_request(state, req, Some(&body))?;
    let request =
        serde_json::from_value::<EventsQueryPostRequestBody>(body.clone()).map_err(|error| {
            schema_violation(format!("invalid ck.peer.events.query shape: {error}"))
        })?;
    let parts = PeerEventsQueryParts::from_body(request)?;
    peer_events_query_response(state, parts).await
}

#[endpoint(
    operation_id = "ck.peer.events.resolve",
    tags("peer"),
    summary = "Resolve federation-visible Event Envelopes by id or digest"
)]
#[tracing::instrument(skip_all, fields(op = "ck.peer.events.resolve"))]
async fn peer_events_resolve(
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<EventsResolveOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let body = parse_json_body(req, "invalid ck.peer.events.resolve request body").await?;
    validate_peer_request(state, req, Some(&body))?;
    let request = serde_json::from_value::<EventsResolveRequestBody>(body).map_err(|error| {
        schema_violation(format!("invalid ck.peer.events.resolve shape: {error}"))
    })?;
    if request.event_ids.len() + request.event_digests.len() > MAX_PEER_EVENTS_RESOLVE {
        return Err(AppError::new(
            crate::error::ErrorCode::PayloadTooLarge,
            "too many events requested",
        )
        .with_status(StatusCode::PAYLOAD_TOO_LARGE)
        .with_wire_code("payload_too_large"));
    }
    for digest in &request.event_digests {
        if !is_valid_sha256_digest(digest.as_str()) {
            return Err(AppError::invalid_param(format!(
                "invalid event digest: {digest}"
            )));
        }
    }
    let include_payload = request.include_payload.unwrap_or(true);
    let requested_ids = request
        .event_ids
        .iter()
        .map(|event_id| event_id.as_str())
        .collect::<BTreeSet<_>>();
    let requested_digests = request
        .event_digests
        .iter()
        .map(|digest| digest.as_str())
        .collect::<BTreeSet<_>>();
    let records = state
        .persistence
        .events()
        .snapshot_all()
        .await
        .map_err(|error| AppError::internal(format!("peer events resolve: {error}")))?;
    let mut events = Vec::new();
    let mut found_ids = BTreeSet::new();
    let mut found_digests = BTreeSet::new();
    for record in records {
        let id_match = requested_ids.contains(record.event_id.as_str());
        let digest_match = requested_digests.contains(record.canonical_digest.as_str());
        if !id_match && !digest_match {
            continue;
        }
        found_ids.insert(record.event_id.clone());
        found_digests.insert(record.canonical_digest.clone());
        let mut event = super::event_log::sdk_event_for_state(state, &record)?;
        if !include_payload {
            event.content = Value::Null;
        }
        events.push(event);
    }
    let mut missing = Vec::new();
    for id in request.event_ids {
        if !found_ids.contains(id.as_str()) {
            missing.push(id.to_string());
        }
    }
    for digest in request.event_digests {
        if !found_digests.contains(digest.as_str()) {
            missing.push(digest.to_string());
        }
    }
    json_ok(EventsResolveOutcome {
        events,
        missing,
        unauthorized: Vec::new(),
    })
}

#[endpoint(
    operation_id = "ck.peer.events.frontier",
    tags("peer"),
    summary = "Read a signed federation peer frontier"
)]
#[tracing::instrument(skip_all, fields(op = "ck.peer.events.frontier"))]
async fn peer_events_frontier(depot: &mut Depot, req: &mut Request) -> JsonResult<Value> {
    let state = depot.obtain::<AppState>().expect("state injected");
    validate_peer_request(state, req, None)?;
    let realm_id = query_param(req, "realm_id")
        .ok_or_else(|| AppError::missing_param("realm_id is required"))?;
    let realm_id =
        RealmId::new(realm_id).map_err(|_| AppError::invalid_param("invalid realm_id"))?;
    if is_realm_deleted(state, realm_id.as_str()).await {
        return Err(AppError::not_found("not found"));
    }
    let records = state
        .persistence
        .events()
        .snapshot_all()
        .await
        .map_err(|error| AppError::internal(format!("peer frontier: {error}")))?;
    let mut actor_frontier: BTreeMap<String, u64> = BTreeMap::new();
    let mut actor_heads: BTreeMap<String, (u64, chrono::DateTime<chrono::Utc>, String)> =
        BTreeMap::new();
    let mut max_hlc: Option<String> = None;
    for record in records.iter().filter(|record| {
        super::event_log::canonical_realm_id_for_record(record).as_deref()
            == Some(realm_id.as_str())
    }) {
        actor_frontier
            .entry(record.actor_id.clone())
            .and_modify(|seq| *seq = (*seq).max(record.actor_seq))
            .or_insert(record.actor_seq);
        if let Some(hlc) = record.envelope.get("hlc").and_then(Value::as_str) {
            max_hlc = match max_hlc {
                Some(current) if current.as_str() >= hlc => Some(current),
                _ => Some(hlc.to_owned()),
            };
        }
        let replace =
            actor_heads
                .get(&record.actor_id)
                .is_none_or(|(seq, received_at, event_id)| {
                    record.actor_seq > *seq
                        || (record.actor_seq == *seq && record.received_at > *received_at)
                        || (record.actor_seq == *seq
                            && record.received_at == *received_at
                            && record.event_id.as_str() > event_id.as_str())
                });
        if replace {
            actor_heads.insert(
                record.actor_id.clone(),
                (
                    record.actor_seq,
                    record.received_at,
                    record.event_id.clone(),
                ),
            );
        }
    }
    let heads = actor_heads
        .values()
        .map(|(_, _, event_id)| event_id.clone())
        .collect::<Vec<_>>();
    let typed_realm_frontier =
        super::frontier::typed_realm_frontier([(realm_id.as_str().to_owned(), heads.clone())]);
    let typed_actor_bounds = super::frontier::typed_actor_upper_bounds(actor_frontier.clone());
    let frontier_root = super::frontier::frontier_root(&typed_realm_frontier, &typed_actor_bounds)
        .map_err(|error| AppError::internal(format!("frontier_root: {error}")))?;
    let service_did = Did::new(state.config.service_did.clone())
        .map_err(|_| AppError::internal("service_did is invalid"))?;
    let observed_at = now();
    let signature = super::frontier::sign_frontier_root(
        &service_did,
        Some(&realm_id),
        observed_at,
        &frontier_root,
        state.anchorer_signing_key().as_ref(),
    )
    .map_err(|error| AppError::internal(format!("frontier signature: {error}")))?;
    let mut response = json!({
        "realm_id": realm_id.as_str(),
        "heads": heads,
        "frontier_root": frontier_root.as_str(),
        "actor_seq_upper_bounds": actor_frontier,
        "witness_receipts": [],
        "observed_at": observed_at.to_rfc3339_opts(SecondsFormat::Millis, true),
        "issuer": service_did.as_str(),
        "signature": signature,
    });
    if let Some(max_hlc) = max_hlc
        && let Some(object) = response.as_object_mut()
    {
        object.insert("max_hlc".to_owned(), Value::String(max_hlc));
    }
    json_ok(response)
}

/// Spec resolution (2026-06-11): `ck.peer.snapshot.head` returns the full
/// signed `ck.schema.snapshot.v1` manifest. soland cannot produce a real
/// Snapshot detached proof yet, and the spec forbids serving a dev-signed
/// stand-in (`signature` / `authority_binding` / `event_set_commitment`
/// MUST NOT be fabricated — service-http-binding.md §6.1, service-surface.md
/// §5.2). The operation is therefore undeclared and the endpoint fails
/// closed with `not_implemented` until a real signing path lands. The
/// dev snapshot bundle remains reachable on the `/_soland/` product face
/// (`org.cokret.soland.sync.snapshot_chunk`).
#[endpoint(
    operation_id = "ck.peer.snapshot.head",
    tags("peer"),
    summary = "Read a federation peer snapshot head (not implemented)"
)]
#[tracing::instrument(skip_all, fields(op = "ck.peer.snapshot.head"))]
async fn peer_snapshot_head(depot: &mut Depot, req: &mut Request) -> JsonResult<Value> {
    let state = depot.obtain::<AppState>().expect("state injected");
    validate_peer_request(state, req, None)?;
    Err(AppError::new(
        crate::error::ErrorCode::NotImplemented,
        "ck.peer.snapshot.head is not implemented: this deployment cannot \
         produce a signed ck.schema.snapshot.v1 manifest",
    ))
}

#[derive(Debug)]
struct PeerEventsQueryParts {
    realms: Vec<String>,
    actors: Vec<String>,
    after: Option<String>,
    before: Option<String>,
    order: String,
    limit: usize,
    kind_filter: Option<String>,
}

impl PeerEventsQueryParts {
    fn from_query(req: &Request) -> Result<Self, AppError> {
        let mut realms = query_param_all(req, "realms");
        if let Some(realm_id) = query_param(req, "realm_id")
            && !realms.contains(&realm_id)
        {
            realms.push(realm_id);
        }
        let mut actors = query_param_all(req, "actors");
        for key in ["actor", "actor_id"] {
            if let Some(actor) = query_param(req, key)
                && !actors.contains(&actor)
            {
                actors.push(actor);
            }
        }
        let kind_filter = query_param(req, "kind")
            .or_else(|| query_param(req, "filters.kind"))
            .or_else(|| query_param(req, "filters[kind]"));
        let parts = Self {
            realms,
            actors,
            after: query_param(req, "after"),
            before: query_param(req, "before"),
            order: query_param(req, "order").unwrap_or_else(|| "default".to_owned()),
            limit: query_param(req, "limit")
                .and_then(|value| value.parse::<usize>().ok())
                .unwrap_or(MAX_PEER_EVENTS_QUERY_LIMIT)
                .clamp(1, MAX_PEER_EVENTS_QUERY_LIMIT),
            kind_filter,
        };
        parts.validate()?;
        Ok(parts)
    }

    fn from_body(body: EventsQueryPostRequestBody) -> Result<Self, AppError> {
        let kind_filter = parse_kind_filter(body.filters.as_ref())?;
        let parts = Self {
            realms: body
                .realms
                .into_iter()
                .map(|realm| realm.into_string())
                .collect(),
            actors: body
                .actors
                .into_iter()
                .map(|actor| actor.into_string())
                .collect(),
            after: body.after.map(|cursor| cursor.into_string()),
            before: body.before.map(|cursor| cursor.into_string()),
            order: body.order.unwrap_or_else(|| "default".to_owned()),
            limit: body
                .limit
                .map(|limit| limit as usize)
                .unwrap_or(MAX_PEER_EVENTS_QUERY_LIMIT)
                .clamp(1, MAX_PEER_EVENTS_QUERY_LIMIT),
            kind_filter,
        };
        parts.validate()?;
        Ok(parts)
    }

    fn validate(&self) -> Result<(), AppError> {
        if self.realms.is_empty() && self.actors.is_empty() {
            return Err(AppError::missing_param(
                "ck.peer.events.query requires at least one of realms[] / actors[]",
            ));
        }
        if self.after.is_some() && self.before.is_some() {
            return Err(AppError::invalid_param(
                "specify either 'after' or 'before', not both",
            ));
        }
        if !matches!(self.order.as_str(), "default" | "ascending" | "descending") {
            return Err(AppError::invalid_param(
                "order must be default, ascending, or descending",
            ));
        }
        for realm in &self.realms {
            RealmId::new(realm.clone())
                .map_err(|_| AppError::invalid_param(format!("invalid realm: {realm}")))?;
        }
        for actor in &self.actors {
            if validate_did(actor).is_err() {
                return Err(AppError::invalid_param(format!("invalid actor: {actor}")));
            }
        }
        if let Some(kind) = &self.kind_filter
            && (!kind.starts_with("ck.") || kind.contains(' '))
        {
            return Err(AppError::invalid_param(format!(
                "invalid event kind: {kind}"
            )));
        }
        Ok(())
    }

    fn backward(&self) -> bool {
        self.order == "descending" || (self.order == "default" && self.before.is_some())
    }
}

async fn peer_events_query_response(
    state: &AppState,
    parts: PeerEventsQueryParts,
) -> JsonResult<EventsQueryOutcome> {
    let realms_set = parts
        .realms
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let actors_set = parts
        .actors
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let mut records = state
        .persistence
        .events()
        .snapshot_all()
        .await
        .map_err(|error| AppError::internal(format!("peer events query: {error}")))?
        .into_iter()
        .filter(|record| {
            peer_record_matches(
                record,
                &realms_set,
                &actors_set,
                parts.kind_filter.as_deref(),
            )
        })
        .collect::<Vec<_>>();
    records.sort_by(|left, right| {
        left.received_at
            .cmp(&right.received_at)
            .then_with(|| left.event_id.cmp(&right.event_id))
    });
    let backward = parts.backward();
    if backward {
        records.reverse();
    }
    let cursor = if backward {
        parts.before.as_deref()
    } else {
        parts.after.as_deref()
    };
    let start = cursor
        .and_then(|cursor| records.iter().position(|record| record.event_id == cursor))
        .map(|index| index + 1)
        .unwrap_or(0);
    let mut page = records
        .into_iter()
        .skip(start)
        .take(parts.limit + 1)
        .collect::<Vec<_>>();
    let has_more = page.len() > parts.limit;
    if has_more {
        page.truncate(parts.limit);
    }
    let page_cursor = has_more
        .then(|| page.last().map(|record| record.event_id.clone()))
        .flatten();
    let (next_cursor, prev_cursor) = if backward {
        (None, page_cursor)
    } else {
        (page_cursor, None)
    };
    let events = page
        .iter()
        .map(|record| super::event_log::sdk_event_for_state(state, record))
        .collect::<Result<Vec<_>, _>>()?;
    json_ok(EventsQueryOutcome {
        events,
        next_cursor,
        prev_cursor,
        has_more,
    })
}

fn peer_record_matches(
    record: &CanonicalEventRecord,
    realms: &BTreeSet<&str>,
    actors: &BTreeSet<&str>,
    kind_filter: Option<&str>,
) -> bool {
    if let Some(kind) = kind_filter
        && record.kind != kind
    {
        return false;
    }
    let realm_match = realms.is_empty()
        || super::event_log::canonical_realm_id_for_record(record)
            .as_deref()
            .is_some_and(|realm_id| realms.contains(realm_id));
    let actor_match = actors.is_empty() || actors.contains(record.actor_id.as_str());
    realm_match && actor_match
}

fn parse_kind_filter(filters: Option<&Value>) -> Result<Option<String>, AppError> {
    let Some(filters) = filters else {
        return Ok(None);
    };
    let Some(object) = filters.as_object() else {
        return Err(schema_violation("filters must be an object"));
    };
    let unsupported = object
        .keys()
        .filter(|key| key.as_str() != "kind")
        .cloned()
        .collect::<Vec<_>>();
    if !unsupported.is_empty() {
        return Err(AppError::unsupported_feature(format!(
            "unsupported peer events filter keys: {}",
            unsupported.join(", ")
        )));
    }
    Ok(object
        .get("kind")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned))
}

async fn parse_json_body(req: &mut Request, message: &'static str) -> Result<Value, AppError> {
    req.parse_json::<Value>()
        .await
        .map_err(|_| AppError::bad_json(message))
}

pub(in crate::routing) fn validate_peer_request(
    state: &AppState,
    req: &Request,
    body: Option<&Value>,
) -> Result<(), AppError> {
    let trust_headers =
        crate::routing::federation::federation::FederationTrustHeaders::from_salvo_request(req)
            .map_err(|violation| {
                schema_violation(violation.message()).with_wire_code(violation.error_code())
            })?;
    let expected_destination =
        cokret_sdk::TypedTrustDomainId::new(state.config.trust_domain.clone())
            .map_err(|_| AppError::internal("service trust_domain is invalid"))?;
    trust_headers
        .verify_destination(&expected_destination)
        .map_err(|_| {
            cross_domain_replay("Destination-Trust-Domain header does not match this service")
        })?;
    let source_service_did = required_header(req, HEADER_SOURCE_SERVICE_DID)?;
    if validate_did(&source_service_did).is_err() {
        return Err(schema_violation("source-service-did must be a DID"));
    }
    let destination_service_did = required_header(req, HEADER_DESTINATION_SERVICE_DID)?;
    if validate_did(&destination_service_did).is_err() {
        return Err(schema_violation("destination-service-did must be a DID"));
    }
    if destination_service_did != state.config.service_did {
        return Err(cross_domain_replay(
            "destination-service-did header does not match this service",
        ));
    }
    if let Some(body) = body {
        let request_hash = canonical::canonical_sha256(body).map_err(|error| {
            schema_violation(format!("request body is not canonical-hashable: {error}"))
        })?;
        if request_hash != trust_headers.request_canonical_digest.as_str() {
            crate::metrics::record_digest_mismatch("peer_request_binding");
            return Err(cross_domain_replay(
                "Request-Canonical-Digest does not match the canonical request body",
            ));
        }
    }
    // federation.md §3.2/§6: all `/_cokret/peer/*` requests MUST be authenticated
    // with an RFC 9421 HTTP Message Signature verified against the sender's
    // service DID key, and the local peer deny policy MUST be enforced inbound.
    // The bare trust-header checks above are necessary but not sufficient; the
    // signature verification (which also re-binds the request-canonical-digest and
    // runs the deny policy) is the authoritative gate.
    crate::routing::federation::federation::verify_inbound_peer_http_signature(
        state, req, body,
    )?;
    Ok(())
}

fn required_header(req: &Request, name: &'static str) -> Result<String, AppError> {
    req.headers()
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .ok_or_else(|| schema_violation(format!("required federation header {name} missing")))
}

pub(in crate::routing) fn schema_violation(message: impl Into<String>) -> AppError {
    AppError::invalid_param(message)
        .with_status(StatusCode::BAD_REQUEST)
        .with_wire_code("schema_violation")
}

pub(in crate::routing) fn cross_domain_replay(message: impl Into<String>) -> AppError {
    AppError::conflict(message)
        .with_status(StatusCode::CONFLICT)
        .with_wire_code("cross_domain_replay_rejected")
}

fn render_app_error(res: &mut Response, error: AppError) {
    render_error(res, error.http_status(), error.wire_code(), &error.message);
}
