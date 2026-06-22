use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, SecondsFormat, Utc};
use cokret_sdk::http::{EventsQueryOutcome, EventsResolveOutcome, EventsResolveRequestBody};
use cokret_sdk::{Did, EventId, EventsQueryPostRequestBody, Hash, RealmId, canonical};
use salvo::http::StatusCode;
use salvo::prelude::*;
use serde::Serialize;
use serde_json::{Value, json};

use super::{
    is_realm_deleted, is_valid_hash_digest, now, query_param, query_param_all, render_error,
    validate_did,
};
use crate::error::AppError;
use crate::persistence::PeerEventsPageQuery;
use crate::result::{JsonResult, json_ok};
use crate::state::{AppState, CanonicalEventRecord, RealmMetaRecord};

const HEADER_SOURCE_SERVICE_DID: &str = "source-service-did";
const HEADER_DESTINATION_SERVICE_DID: &str = "destination-service-did";
const MAX_PEER_EVENTS_QUERY_LIMIT: usize = 100;
const MAX_PEER_EVENTS_RESOLVE: usize = 100;

#[derive(Debug, Serialize, ToSchema)]
struct PeerEventsDescribeOutcome {
    service_did: Did,
    protocol_version: String,
    primary_write_path: String,
    supported_operations: Vec<String>,
    supported_profiles: Vec<String>,
    supported_bindings: Vec<String>,
    limits: PeerEventsDescribeLimits,
}

#[derive(Debug, Serialize, ToSchema)]
struct PeerEventsDescribeLimits {
    max_batch_size: usize,
    max_query_limit: usize,
    max_resolve: usize,
}

#[derive(Debug, Serialize, ToSchema)]
struct PeerEventsFrontierOutcome {
    realm_id: RealmId,
    heads: Vec<EventId>,
    frontier_root: Hash,
    actor_seq_upper_bounds: BTreeMap<Did, u64>,
    witness_receipts: Vec<Value>,
    observed_at: String,
    issuer: Did,
    signature: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_hlc: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
struct PeerSnapshotHeadOutcome {}

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
    operation_id = "ck.peer.events.query.describe",
    tags("peer"),
    summary = "Describe the federation peer Events API"
)]
#[tracing::instrument(skip_all, fields(op = "ck.peer.events.query.describe"))]
async fn peer_events_describe(depot: &mut Depot) -> JsonResult<PeerEventsDescribeOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let service_did = Did::new(state.config.service_did.clone())
        .map_err(|_| AppError::internal("service_did is invalid"))?;
    json_ok(PeerEventsDescribeOutcome {
        service_did,
        protocol_version: "1.0".to_owned(),
        primary_write_path: "/_cokret/peer/events".to_owned(),
        supported_operations: vec![
            "ck.peer.events.query.describe".to_owned(),
            "ck.peer.events.command.submit".to_owned(),
            "ck.peer.events.query.scan".to_owned(),
            "ck.peer.events.query.scan_body".to_owned(),
            "ck.peer.events.query.resolve".to_owned(),
            "ck.peer.events.query.frontier".to_owned(),
            "ck.peer.invites.command.submit".to_owned(),
        ],
        supported_profiles: vec!["ck.profile.federation_minimal.v1".to_owned()],
        supported_bindings: vec![
            "http-message-signature".to_owned(),
            "source-service-did".to_owned(),
            "destination-service-did".to_owned(),
            "source-trust-domain".to_owned(),
            "destination-trust-domain".to_owned(),
            "request-canonical-digest".to_owned(),
        ],
        limits: PeerEventsDescribeLimits {
            max_batch_size: 100,
            max_query_limit: MAX_PEER_EVENTS_QUERY_LIMIT,
            max_resolve: MAX_PEER_EVENTS_RESOLVE,
        },
    })
}

#[handler]
#[tracing::instrument(skip_all, fields(op = "ck.peer.events.command.submit"))]
async fn peer_events_submit(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let body_value = match req.parse_json::<Value>().await {
        Ok(body) => body,
        Err(_) => {
            render_error(
                res,
                StatusCode::BAD_REQUEST,
                "bad_json",
                "invalid ck.peer.events.command.submit request body",
            );
            return;
        }
    };
    if let Err(error) = validate_peer_request(state, req, Some(&body_value)) {
        render_app_error(res, error);
        return;
    }
    super::event_log::submit_federation_events(state, req, body_value, res).await;
}

#[endpoint(
    operation_id = "ck.peer.events.query.scan",
    tags("peer"),
    summary = "Query federation-visible Event Envelopes"
)]
#[tracing::instrument(skip_all, fields(op = "ck.peer.events.query.scan"))]
async fn peer_events_query(depot: &mut Depot, req: &mut Request) -> JsonResult<EventsQueryOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
    validate_peer_request(state, req, None)?;
    let source_service_did = source_service_did_from_request(req)?;
    let parts = PeerEventsQueryParts::from_query(req)?;
    peer_events_query_response(state, source_service_did, parts).await
}

#[endpoint(
    operation_id = "ck.peer.events.query.scan_body",
    tags("peer"),
    summary = "Query federation-visible Event Envelopes with a JSON body"
)]
#[tracing::instrument(skip_all, fields(op = "ck.peer.events.query.scan_body"))]
async fn peer_events_query_post(
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<EventsQueryOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let request = parse_json_body::<EventsQueryPostRequestBody>(
        req,
        "invalid ck.peer.events.query.scan request body",
    )
    .await?;
    let body = serde_json::to_value(&request).map_err(|error| {
        AppError::internal(format!("peer events query request serialize: {error}"))
    })?;
    validate_peer_request(state, req, Some(&body))?;
    let source_service_did = source_service_did_from_request(req)?;
    let parts = PeerEventsQueryParts::from_body(request)?;
    peer_events_query_response(state, source_service_did, parts).await
}

#[endpoint(
    operation_id = "ck.peer.events.query.resolve",
    tags("peer"),
    summary = "Resolve federation-visible Event Envelopes by id or digest"
)]
#[tracing::instrument(skip_all, fields(op = "ck.peer.events.query.resolve"))]
async fn peer_events_resolve(
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<EventsResolveOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let request = parse_json_body::<EventsResolveRequestBody>(
        req,
        "invalid ck.peer.events.query.resolve request body",
    )
    .await?;
    let body = serde_json::to_value(&request).map_err(|error| {
        AppError::internal(format!("peer events resolve request serialize: {error}"))
    })?;
    validate_peer_request(state, req, Some(&body))?;
    let source_service_did = source_service_did_from_request(req)?;
    if request.event_ids.len() + request.event_digests.len() > MAX_PEER_EVENTS_RESOLVE {
        return Err(AppError::new(
            crate::error::ErrorCode::PayloadTooLarge,
            "too many events requested",
        )
        .with_status(StatusCode::PAYLOAD_TOO_LARGE)
        .with_wire_code("payload_too_large"));
    }
    for digest in &request.event_digests {
        if !is_valid_hash_digest(digest.as_str()) {
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
    let authz = PeerReadAuthz::build(state, &source_service_did, &records).await?;
    let mut events = Vec::new();
    let mut found_ids = BTreeSet::new();
    let mut found_digests = BTreeSet::new();
    for record in records {
        let id_match = requested_ids.contains(record.event_id.as_str());
        let digest_match = requested_digests.contains(record.canonical_digest.as_str());
        if !id_match && !digest_match {
            continue;
        }
        if !authz.record_visible(&record) {
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
    operation_id = "ck.peer.events.query.frontier",
    tags("peer"),
    summary = "Read a signed federation peer frontier"
)]
#[tracing::instrument(skip_all, fields(op = "ck.peer.events.query.frontier"))]
async fn peer_events_frontier(
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<PeerEventsFrontierOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
    validate_peer_request(state, req, None)?;
    let source_service_did = source_service_did_from_request(req)?;
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
    let authz = PeerReadAuthz::build(state, &source_service_did, &records).await?;
    if !authz.frontier_visible_for_realm(realm_id.as_str()) {
        return Err(AppError::not_found("not found"));
    }
    let visible_realm_records = records
        .iter()
        .filter(|record| {
            super::event_log::canonical_realm_id_for_record(record).as_deref()
                == Some(realm_id.as_str())
                && authz.record_visible(record)
        })
        .collect::<Vec<_>>();
    let mut actor_frontier: BTreeMap<String, u64> = BTreeMap::new();
    let mut max_hlc: Option<String> = None;
    for record in &visible_realm_records {
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
    }
    let mut heads = visible_realm_records
        .iter()
        .filter(|record| {
            actor_frontier
                .get(record.actor_id.as_str())
                .is_some_and(|seq| *seq == record.actor_seq)
        })
        .map(|record| record.event_id.clone())
        .collect::<Vec<_>>();
    heads.sort();
    heads.dedup();
    let typed_heads = heads
        .iter()
        .map(|event_id| {
            EventId::new(event_id.clone())
                .map_err(|_| AppError::internal("stored frontier event_id is invalid"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let typed_actor_frontier = actor_frontier
        .iter()
        .map(|(actor_id, seq)| {
            Ok((
                Did::new(actor_id.clone())
                    .map_err(|_| AppError::internal("stored frontier actor_id is invalid"))?,
                *seq,
            ))
        })
        .collect::<Result<BTreeMap<_, _>, AppError>>()?;
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
        state.notary_signing_key().as_ref(),
    )
    .map_err(|error| AppError::internal(format!("frontier signature: {error}")))?;
    json_ok(PeerEventsFrontierOutcome {
        realm_id,
        heads: typed_heads,
        frontier_root,
        actor_seq_upper_bounds: typed_actor_frontier,
        witness_receipts: Vec::new(),
        observed_at: observed_at.to_rfc3339_opts(SecondsFormat::Millis, true),
        issuer: service_did,
        signature,
        max_hlc,
    })
}

/// Spec resolution (2026-06-11): `ck.peer.snapshot.query.manifest_head` returns the full
/// signed `ck.schema.snapshot.v1` manifest. soland cannot produce a real
/// Snapshot detached proof yet, and the spec forbids serving a dev-signed
/// stand-in (`signature` / `authority_binding` / `event_set_commitment`
/// MUST NOT be fabricated — service-http-binding.md §6.1, service-surface.md
/// §5.2). The operation is therefore undeclared and the endpoint fails
/// closed with `not_implemented` until a real signing path lands. The
/// dev snapshot bundle remains reachable on the `/_soland/` product face
/// (`org.cokret.soland.sync.snapshot_chunk`).
#[endpoint(
    operation_id = "ck.peer.snapshot.query.manifest_head",
    tags("peer"),
    summary = "Read a federation peer snapshot head (not implemented)"
)]
#[tracing::instrument(skip_all, fields(op = "ck.peer.snapshot.query.manifest_head"))]
async fn peer_snapshot_head(
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<PeerSnapshotHeadOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
    validate_peer_request(state, req, None)?;
    Err(AppError::new(
        crate::error::ErrorCode::NotImplemented,
        "ck.peer.snapshot.query.manifest_head is not implemented: this deployment cannot \
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
        let kind = query_param(req, "kind");
        let kinds = query_param_all(req, "kinds");
        if kinds.len() > 1 {
            return Err(AppError::unsupported_feature(
                "multiple peer events kind filters are not supported",
            ));
        }
        if let (Some(kind), Some(kinds)) = (kind.as_deref(), kinds.first().map(String::as_str))
            && kind != kinds
        {
            return Err(AppError::invalid_param(
                "kind and kinds filters must match when both are present",
            ));
        }
        let kind_filter = kind
            .or_else(|| kinds.into_iter().next())
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
                "ck.peer.events.query.scan requires at least one of realms[] / actors[]",
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
        if self.before.is_some() {
            true
        } else if self.after.is_some() {
            false
        } else {
            self.order != "ascending"
        }
    }

    fn active_cursor(&self) -> Option<&str> {
        self.before.as_deref().or(self.after.as_deref())
    }

    fn filters_for_digest(&self) -> Value {
        match self.kind_filter.as_deref() {
            Some(kind) => json!({ "kind": kind }),
            None => json!({}),
        }
    }
}

#[derive(Clone, Debug)]
struct PeerReadAuthz {
    source_service_did: String,
    realm_meta: BTreeMap<String, RealmMetaRecord>,
    realm_endpoints: BTreeMap<String, Vec<PeerRealmEndpoint>>,
    realm_members: BTreeMap<String, BTreeMap<String, PeerMembership>>,
    circles: BTreeMap<String, PeerCircleState>,
    circle_members: BTreeMap<String, BTreeMap<String, PeerMembership>>,
}

#[derive(Clone, Debug)]
struct PeerRealmEndpoint {
    role: String,
    visibility_scope: PeerEndpointVisibility,
    plaintext_visible: bool,
    authorized_at: DateTime<Utc>,
    expires_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PeerEndpointVisibility {
    MetadataOnly,
    EncryptedEvents,
    PlaintextEvents,
}

#[derive(Clone, Debug)]
struct PeerMembership {
    joined_at: DateTime<Utc>,
    invited_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug)]
struct PeerCircleState {
    realm_id: String,
    history_visibility: String,
    active: bool,
}

impl PeerReadAuthz {
    async fn build(
        state: &AppState,
        source_service_did: &str,
        records: &[CanonicalEventRecord],
    ) -> Result<Self, AppError> {
        let realm_meta = state
            .persistence
            .realm_meta()
            .list()
            .await
            .map_err(|error| AppError::internal(format!("peer realm metadata: {error}")))?
            .into_iter()
            .collect::<BTreeMap<_, _>>();
        let circles = state
            .projection
            .lock()
            .map_err(|_| AppError::internal("projection mutex poisoned"))?
            .circles
            .iter()
            .map(|(circle_id, circle)| {
                (
                    circle_id.clone(),
                    PeerCircleState {
                        realm_id: circle.realm_id.clone(),
                        history_visibility: circle.history_visibility.clone(),
                        active: circle.state == crate::reducer::CircleLifecycleState::Active,
                    },
                )
            })
            .collect::<BTreeMap<_, _>>();
        let mut authz = Self {
            source_service_did: source_service_did.to_owned(),
            realm_meta,
            realm_endpoints: BTreeMap::new(),
            realm_members: BTreeMap::new(),
            circles,
            circle_members: BTreeMap::new(),
        };
        let mut ordered = records.iter().collect::<Vec<_>>();
        ordered.sort_by(|left, right| {
            left.received_at
                .cmp(&right.received_at)
                .then_with(|| left.event_id.cmp(&right.event_id))
        });
        for record in ordered {
            authz.apply_record(record);
        }
        Ok(authz)
    }

    fn apply_record(&mut self, record: &CanonicalEventRecord) {
        self.apply_realm_endpoint_record(record);
        self.apply_member_record(record);
        self.apply_circle_member_record(record);
    }

    fn record_visible(&self, record: &CanonicalEventRecord) -> bool {
        let Some(realm_id) = super::event_log::canonical_realm_id_for_record(record) else {
            return false;
        };
        let Some(meta) = self.realm_meta.get(&realm_id) else {
            return false;
        };
        if meta.deleted {
            return false;
        }
        if !self.source_has_realm_scope(&realm_id) {
            return false;
        }
        let event_time = record_event_time(record);
        let needs_plaintext = record_requires_private_plaintext_visibility(record, meta);
        if needs_plaintext && !self.source_can_receive_plaintext(&realm_id) {
            return false;
        }
        if let Some(circle_id) = record_scope_circle_id(record) {
            return self.circle_record_visible(&realm_id, &circle_id, event_time);
        }
        self.realm_record_visible(&realm_id, meta, event_time, needs_plaintext)
    }

    fn frontier_visible_for_realm(&self, realm_id: &str) -> bool {
        self.realm_meta
            .get(realm_id)
            .is_some_and(|meta| !meta.deleted)
            && self
                .realm_endpoints
                .get(realm_id)
                .is_some_and(|endpoints| endpoints.iter().any(PeerRealmEndpoint::allows_frontier))
    }

    fn source_has_realm_scope(&self, realm_id: &str) -> bool {
        self.realm_members
            .get(realm_id)
            .is_some_and(|members| !members.is_empty())
            || self
                .realm_endpoints
                .get(realm_id)
                .is_some_and(|endpoints| !endpoints.is_empty())
    }

    fn source_scoped_realms(&self) -> Vec<String> {
        let realms = self
            .realm_members
            .keys()
            .chain(self.realm_endpoints.keys())
            .filter(|realm_id| {
                self.realm_meta
                    .get(realm_id.as_str())
                    .is_some_and(|meta| !meta.deleted)
            })
            .cloned()
            .collect::<BTreeSet<_>>();
        realms
            .iter()
            .filter(|realm_id| self.source_has_realm_scope(realm_id.as_str()))
            .cloned()
            .collect()
    }

    fn realm_record_visible(
        &self,
        realm_id: &str,
        meta: &RealmMetaRecord,
        event_time: DateTime<Utc>,
        needs_plaintext: bool,
    ) -> bool {
        if self.realm_endpoints.get(realm_id).is_some_and(|endpoints| {
            endpoints
                .iter()
                .any(|endpoint| endpoint.allows_event(event_time, meta, needs_plaintext))
        }) {
            return true;
        }
        self.realm_members.get(realm_id).is_some_and(|members| {
            members.values().any(|member| {
                history_visibility_allows(meta.history_visibility.as_str(), member, event_time)
            })
        })
    }

    fn circle_record_visible(
        &self,
        realm_id: &str,
        circle_id: &str,
        event_time: DateTime<Utc>,
    ) -> bool {
        let Some(circle) = self.circles.get(circle_id) else {
            return false;
        };
        if !circle.active || circle.realm_id != realm_id {
            return false;
        }
        let Some(realm_members) = self.realm_members.get(realm_id) else {
            return false;
        };
        let Some(circle_members) = self.circle_members.get(circle_id) else {
            return false;
        };
        realm_members.iter().any(|(actor, realm_member)| {
            circle_members.get(actor).is_some_and(|circle_member| {
                history_visibility_allows(
                    circle.history_visibility.as_str(),
                    circle_member,
                    event_time,
                ) && history_visibility_allows("joined", realm_member, event_time)
            })
        })
    }

    fn source_can_receive_plaintext(&self, realm_id: &str) -> bool {
        let Some(meta) = self.realm_meta.get(realm_id) else {
            return false;
        };
        if meta.history_visibility == "world_readable" {
            return true;
        }
        if !meta
            .plaintext_visible_services
            .contains(self.source_service_did.as_str())
        {
            return false;
        }
        self.realm_members
            .get(realm_id)
            .is_some_and(|members| !members.is_empty())
            || self.realm_endpoints.get(realm_id).is_some_and(|endpoints| {
                endpoints.iter().any(|endpoint| {
                    endpoint.plaintext_visible
                        || endpoint.visibility_scope == PeerEndpointVisibility::PlaintextEvents
                })
            })
    }

    fn apply_member_record(&mut self, record: &CanonicalEventRecord) {
        if record.kind != crate::kinds::CK_MEMBER_STATE {
            return;
        }
        let Some(realm_id) = super::event_log::canonical_realm_id_for_record(record) else {
            return;
        };
        let Some(payload) = record_payload(record) else {
            return;
        };
        let Some(actor) = payload
            .get("actor_id")
            .and_then(Value::as_str)
            .or_else(|| payload.get("actor").and_then(Value::as_str))
        else {
            return;
        };
        let membership = payload
            .get("membership")
            .and_then(Value::as_str)
            .or_else(|| payload.get("state").and_then(Value::as_str))
            .unwrap_or_default();
        match membership {
            "join" | "active" => {
                let Some(binding) = payload.get("delivery_binding").and_then(Value::as_object)
                else {
                    self.remove_realm_member(&realm_id, actor);
                    return;
                };
                let source_matches = binding
                    .get("recipient_service_did")
                    .and_then(Value::as_str)
                    .is_some_and(|did| did == self.source_service_did);
                let routable = payload
                    .get("delivery_status")
                    .and_then(Value::as_str)
                    .is_none_or(|status| status == "routable");
                if !source_matches || !routable || !binding_expiry_allows(binding.get("expires_at"))
                {
                    self.remove_realm_member(&realm_id, actor);
                    return;
                }
                let previous = self
                    .realm_members
                    .get(&realm_id)
                    .and_then(|members| members.get(actor));
                let membership = PeerMembership {
                    joined_at: previous
                        .map(|member| member.joined_at)
                        .unwrap_or_else(|| record_event_time(record)),
                    invited_at: previous.and_then(|member| member.invited_at),
                };
                self.realm_members
                    .entry(realm_id)
                    .or_default()
                    .insert(actor.to_owned(), membership);
            }
            "invite" | "invited" => {
                if let Some(member) = self
                    .realm_members
                    .entry(realm_id)
                    .or_default()
                    .get_mut(actor)
                {
                    member
                        .invited_at
                        .get_or_insert_with(|| record_event_time(record));
                }
            }
            "leave" | "ban" | "removed" | "banned" | "left" => {
                self.remove_realm_member(&realm_id, actor);
            }
            _ => {}
        }
    }

    fn remove_realm_member(&mut self, realm_id: &str, actor: &str) {
        if let Some(members) = self.realm_members.get_mut(realm_id) {
            members.remove(actor);
            if members.is_empty() {
                self.realm_members.remove(realm_id);
            }
        }
    }

    fn apply_circle_member_record(&mut self, record: &CanonicalEventRecord) {
        if record.kind != crate::kinds::CK_CIRCLE_MEMBER_STATE {
            return;
        }
        let Some(payload) = record_payload(record) else {
            return;
        };
        let Some(circle_id) = payload.get("circle_id").and_then(Value::as_str) else {
            return;
        };
        let Some(actor) = payload
            .get("actor")
            .and_then(Value::as_str)
            .or_else(|| payload.get("actor_id").and_then(Value::as_str))
        else {
            return;
        };
        let state = payload
            .get("state")
            .and_then(Value::as_str)
            .or_else(|| payload.get("membership").and_then(Value::as_str))
            .unwrap_or_default();
        match state {
            "join" | "active" => {
                let previous = self
                    .circle_members
                    .get(circle_id)
                    .and_then(|members| members.get(actor));
                let membership = PeerMembership {
                    joined_at: previous
                        .map(|member| member.joined_at)
                        .unwrap_or_else(|| record_event_time(record)),
                    invited_at: previous.and_then(|member| member.invited_at),
                };
                self.circle_members
                    .entry(circle_id.to_owned())
                    .or_default()
                    .insert(actor.to_owned(), membership);
            }
            "invite" | "invited" => {
                if let Some(member) = self
                    .circle_members
                    .entry(circle_id.to_owned())
                    .or_default()
                    .get_mut(actor)
                {
                    member
                        .invited_at
                        .get_or_insert_with(|| record_event_time(record));
                }
            }
            "leave" | "ban" | "removed" | "banned" | "left" => {
                if let Some(members) = self.circle_members.get_mut(circle_id) {
                    members.remove(actor);
                    if members.is_empty() {
                        self.circle_members.remove(circle_id);
                    }
                }
            }
            _ => {}
        }
    }

    fn apply_realm_endpoint_record(&mut self, record: &CanonicalEventRecord) {
        let Some(realm_id) = super::event_log::canonical_realm_id_for_record(record) else {
            return;
        };
        let Some(sync_endpoints) =
            record_payload_field(record, "sync_endpoints").and_then(Value::as_array)
        else {
            return;
        };
        self.realm_endpoints.remove(&realm_id);
        let mut endpoints = Vec::new();
        for endpoint in sync_endpoints {
            let Some(object) = endpoint.as_object() else {
                continue;
            };
            if object.get("did").and_then(Value::as_str) != Some(self.source_service_did.as_str()) {
                continue;
            }
            let Some(role) = object.get("role").and_then(Value::as_str) else {
                continue;
            };
            let expires_at = object
                .get("expires_at")
                .and_then(Value::as_str)
                .and_then(parse_rfc3339);
            if expires_at.is_some_and(|expires_at| expires_at <= Utc::now()) {
                continue;
            }
            endpoints.push(PeerRealmEndpoint {
                role: role.to_owned(),
                visibility_scope: object
                    .get("visibility_scope")
                    .and_then(Value::as_str)
                    .map(PeerEndpointVisibility::from_wire)
                    .unwrap_or_else(|| {
                        if object
                            .get("plaintext_visible")
                            .and_then(Value::as_bool)
                            .unwrap_or(false)
                        {
                            PeerEndpointVisibility::PlaintextEvents
                        } else {
                            PeerEndpointVisibility::EncryptedEvents
                        }
                    }),
                plaintext_visible: object
                    .get("plaintext_visible")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
                authorized_at: record_event_time(record),
                expires_at,
            });
        }
        if !endpoints.is_empty() {
            self.realm_endpoints.insert(realm_id, endpoints);
        }
    }
}

impl PeerRealmEndpoint {
    fn allows_event(
        &self,
        event_time: DateTime<Utc>,
        meta: &RealmMetaRecord,
        needs_plaintext: bool,
    ) -> bool {
        if self
            .expires_at
            .is_some_and(|expires_at| expires_at <= Utc::now())
        {
            return false;
        }
        if !matches!(
            self.role.as_str(),
            "primary" | "mirror" | "sync" | "federation_peer" | "notary"
        ) {
            return false;
        }
        if self.visibility_scope == PeerEndpointVisibility::MetadataOnly {
            return false;
        }
        if needs_plaintext
            && !(self.plaintext_visible
                && self.visibility_scope == PeerEndpointVisibility::PlaintextEvents)
        {
            return false;
        }
        match meta.history_visibility.as_str() {
            "world_readable" | "shared" => true,
            "joined" | "invited" => event_time >= self.authorized_at,
            _ => false,
        }
    }

    fn allows_frontier(&self) -> bool {
        if self
            .expires_at
            .is_some_and(|expires_at| expires_at <= Utc::now())
        {
            return false;
        }
        matches!(
            self.role.as_str(),
            "primary" | "mirror" | "sync" | "federation_peer" | "notary"
        ) && self.visibility_scope != PeerEndpointVisibility::MetadataOnly
    }
}

impl PeerEndpointVisibility {
    fn from_wire(value: &str) -> Self {
        match value {
            "plaintext_events" => Self::PlaintextEvents,
            "encrypted_events" => Self::EncryptedEvents,
            _ => Self::MetadataOnly,
        }
    }
}

fn history_visibility_allows(
    history_visibility: &str,
    member: &PeerMembership,
    event_time: DateTime<Utc>,
) -> bool {
    match history_visibility {
        "world_readable" | "shared" => true,
        "joined" => event_time >= member.joined_at,
        "invited" => event_time >= member.invited_at.unwrap_or(member.joined_at),
        _ => false,
    }
}

fn record_requires_private_plaintext_visibility(
    record: &CanonicalEventRecord,
    meta: &RealmMetaRecord,
) -> bool {
    if meta.history_visibility == "world_readable" {
        return false;
    }
    let Some(payload) = record_payload(record) else {
        return true;
    };
    !(payload.get("encrypted_content").is_some() || payload.get("encrypted_payload").is_some())
}

fn record_scope_circle_id(record: &CanonicalEventRecord) -> Option<String> {
    let object = record.envelope.as_object()?;
    if let Some(scope) = object.get("effective_scope") {
        if let Some(scope) = scope.as_str()
            && scope.starts_with("ck:circle:")
        {
            return Some(scope.to_owned());
        }
        if let Some(circle_id) = scope.get("circle_id").and_then(Value::as_str)
            && circle_id.starts_with("ck:circle:")
        {
            return Some(circle_id.to_owned());
        }
    }
    let payload = object.get("payload").and_then(Value::as_object)?;
    payload
        .get("scope_circle_id")
        .and_then(Value::as_str)
        .or_else(|| {
            payload
                .get("object")
                .and_then(Value::as_object)
                .and_then(|object| object.get("scope_circle_id"))
                .and_then(Value::as_str)
        })
        .filter(|scope| scope.starts_with("ck:circle:"))
        .map(ToOwned::to_owned)
}

fn record_payload(record: &CanonicalEventRecord) -> Option<&serde_json::Map<String, Value>> {
    record.envelope.get("payload").and_then(Value::as_object)
}

fn record_payload_field<'a>(record: &'a CanonicalEventRecord, field: &str) -> Option<&'a Value> {
    let payload = record_payload(record)?;
    payload
        .get(field)
        .or_else(|| {
            payload
                .get("object")
                .and_then(Value::as_object)
                .and_then(|object| object.get(field))
        })
        .or_else(|| {
            payload
                .get("patch")
                .and_then(Value::as_object)
                .and_then(|patch| patch.get(field))
        })
}

fn record_event_time(record: &CanonicalEventRecord) -> DateTime<Utc> {
    record
        .envelope
        .get("created_at")
        .and_then(Value::as_str)
        .and_then(parse_rfc3339)
        .unwrap_or(record.received_at)
}

fn parse_rfc3339(value: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value)
        .ok()
        .map(|dt| dt.with_timezone(&Utc))
}

fn binding_expiry_allows(value: Option<&Value>) -> bool {
    value
        .and_then(Value::as_str)
        .and_then(parse_rfc3339)
        .is_none_or(|expires_at| expires_at > Utc::now())
}

async fn peer_events_query_response(
    state: &AppState,
    source_service_did: String,
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
    let filter_digest = peer_events_query_scope_digest(&source_service_did, &parts);
    let cursor_event_id =
        peer_events_query_cursor_event_id(state, parts.active_cursor(), &filter_digest).await?;
    let authz_records = state
        .persistence
        .events()
        .peer_authz_state_records()
        .await
        .map_err(|error| AppError::internal(format!("peer events query: {error}")))?;
    let authz = PeerReadAuthz::build(state, &source_service_did, &authz_records).await?;
    let backward = parts.backward();
    let query_realms = if parts.realms.is_empty() {
        authz.source_scoped_realms()
    } else {
        parts.realms.clone()
    };
    if query_realms.is_empty() {
        return json_ok(EventsQueryOutcome {
            events: Vec::new(),
            snapshot_bootstrap: None,
            next_cursor: None,
            prev_cursor: None,
            has_more: false,
            range_completeness: Value::Null,
        });
    }
    let candidate_limit = peer_events_candidate_limit(parts.limit);
    let mut scan_cursor_event_id = cursor_event_id;
    let mut visible = Vec::new();
    loop {
        let candidates = state
            .persistence
            .events()
            .peer_events_query_page(&PeerEventsPageQuery {
                realms: query_realms.clone(),
                actors: parts.actors.clone(),
                kind_filter: parts.kind_filter.clone(),
                cursor_event_id: scan_cursor_event_id.clone(),
                backward,
                limit: candidate_limit,
            })
            .await
            .map_err(|error| AppError::internal(format!("peer events query page: {error}")))?;
        let candidate_count = candidates.len();
        let next_scan_cursor = candidates.last().map(|record| record.event_id.clone());
        for record in candidates {
            if peer_record_matches(
                &record,
                &realms_set,
                &actors_set,
                parts.kind_filter.as_deref(),
            ) && authz.record_visible(&record)
            {
                visible.push(record);
                if visible.len() > parts.limit {
                    break;
                }
            }
        }
        if visible.len() > parts.limit || candidate_count < candidate_limit {
            break;
        }
        let Some(next_scan_cursor) = next_scan_cursor else {
            break;
        };
        scan_cursor_event_id = Some(next_scan_cursor);
    }
    let has_more = visible.len() > parts.limit;
    if has_more {
        visible.truncate(parts.limit);
    }
    let page_cursor_event_id = has_more
        .then(|| visible.last().map(|record| record.event_id.clone()))
        .flatten();
    let page_cursor = match page_cursor_event_id {
        Some(event_id) => Some(
            super::sync::sync_token_for_events_query(state, None, &filter_digest, &event_id).await,
        ),
        None => None,
    };
    let (next_cursor, prev_cursor) = if backward {
        (None, page_cursor)
    } else {
        (page_cursor, None)
    };
    let events = visible
        .iter()
        .map(|record| super::event_log::sdk_event_for_state(state, record))
        .collect::<Result<Vec<_>, _>>()?;
    json_ok(EventsQueryOutcome {
        events,
        snapshot_bootstrap: None,
        next_cursor,
        prev_cursor,
        has_more,
        range_completeness: Value::Null,
    })
}

fn peer_events_candidate_limit(page_limit: usize) -> usize {
    page_limit
        .saturating_mul(4)
        .max(MAX_PEER_EVENTS_QUERY_LIMIT)
        .min(MAX_PEER_EVENTS_QUERY_LIMIT * 5)
}

fn peer_events_query_scope_digest(
    source_service_did: &str,
    parts: &PeerEventsQueryParts,
) -> String {
    let realms = parts
        .realms
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let actors = parts
        .actors
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let binding = json!({
        "operation_id": "ck.peer.events.query.scan",
        "source_service_did": source_service_did,
        "realms": realms,
        "actors": actors,
        "filters": parts.filters_for_digest(),
        "order": parts.order.as_str(),
    });
    super::sync::sync_filter_digest(Some(&binding))
}

async fn peer_events_query_cursor_event_id(
    state: &AppState,
    cursor: Option<&str>,
    filter_digest: &str,
) -> Result<Option<String>, AppError> {
    let Some(cursor) = cursor else {
        return Ok(None);
    };
    super::sync::parse_and_validate_events_query_cursor(
        cursor,
        state,
        None,
        filter_digest,
        Utc::now().timestamp_millis(),
    )
    .await
    .map(|cursor| Some(cursor.event_id))
    .map_err(peer_events_query_cursor_error)
}

fn peer_events_query_cursor_error(error: super::sync::SyncCursorError) -> AppError {
    match error {
        super::sync::SyncCursorError::Expired => {
            AppError::new(crate::error::ErrorCode::CursorExpired, "cursor has expired")
        }
        super::sync::SyncCursorError::Invalid(message) => AppError::invalid_param(message),
        super::sync::SyncCursorError::Mismatch(message)
        | super::sync::SyncCursorError::Integrity(message) => {
            AppError::new(crate::error::ErrorCode::CursorIntegrityInvalid, message)
        }
        super::sync::SyncCursorError::Revoked => AppError::new(
            crate::error::ErrorCode::CursorRevoked,
            "cursor authority has been revoked",
        ),
    }
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

async fn parse_json_body<T>(req: &mut Request, message: &'static str) -> Result<T, AppError>
where
    T: serde::de::DeserializeOwned,
{
    req.parse_json::<T>()
        .await
        .map_err(|_| AppError::bad_json(message))
}

pub(in crate::routing) fn validate_peer_request(
    state: &AppState,
    req: &Request,
    body: Option<&Value>,
) -> Result<(), AppError> {
    let expected_destination =
        cokret_sdk::TypedTrustDomainId::new(state.config.trust_domain.clone())
            .map_err(|_| AppError::internal("service trust_domain is invalid"))?;
    if let Some(body) = body {
        let trust_headers =
            crate::routing::federation::federation::FederationTrustHeaders::from_salvo_request(req)
                .map_err(|violation| {
                    schema_violation(violation.message()).with_wire_code(violation.error_code())
                })?;
        trust_headers
            .verify_destination(&expected_destination)
            .map_err(|_| {
                cross_domain_replay("Destination-Trust-Domain header does not match this service")
            })?;
        let request_hash = canonical::canonical_sha256(body).map_err(|error| {
            schema_violation(format!("request body is not canonical-hashable: {error}"))
        })?;
        if request_hash != trust_headers.request_canonical_digest.as_str() {
            crate::metrics::record_digest_mismatch("peer_request_binding");
            return Err(cross_domain_replay(
                "Request-Canonical-Digest does not match the canonical request body",
            ));
        }
    } else {
        if req.headers().contains_key("content-digest")
            || req.headers().contains_key("request-canonical-digest")
        {
            return Err(schema_violation(
                "GET peer read requests must not carry body digest headers",
            ));
        }
        if let Some(signature_input) = req
            .headers()
            .get("signature-input")
            .and_then(|value| value.to_str().ok())
        {
            let signature_input = signature_input.to_ascii_lowercase();
            if signature_input.contains("\"content-digest\"")
                || signature_input.contains("\"request-canonical-digest\"")
            {
                return Err(schema_violation(
                    "GET peer read Signature-Input must not bind body digest components",
                ));
            }
        }
        let destination_trust_domain = required_header(req, "destination-trust-domain")?;
        let destination_trust_domain =
            cokret_sdk::TypedTrustDomainId::new(destination_trust_domain)
                .map_err(|_| schema_violation("destination-trust-domain must be a trust domain"))?;
        if destination_trust_domain != expected_destination {
            return Err(cross_domain_replay(
                "Destination-Trust-Domain header does not match this service",
            ));
        }
        let source_trust_domain = required_header(req, "source-trust-domain")?;
        cokret_sdk::TypedTrustDomainId::new(source_trust_domain)
            .map_err(|_| schema_violation("source-trust-domain must be a trust domain"))?;
    }
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
    // federation.md §3.2/§6: all `/_cokret/peer/*` requests MUST be authenticated
    // with an RFC 9421 HTTP Message Signature verified against the sender's
    // service DID key, and the local peer deny policy MUST be enforced inbound.
    // The bare trust-header checks above are necessary but not sufficient; the
    // signature verification (which also re-binds POST body digests and runs
    // the deny policy) is the authoritative gate.
    crate::routing::federation::federation::verify_inbound_peer_http_signature(state, req, body)?;
    Ok(())
}

fn source_service_did_from_request(req: &Request) -> Result<String, AppError> {
    required_header(req, HEADER_SOURCE_SERVICE_DID)
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
