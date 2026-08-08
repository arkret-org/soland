use std::collections::{BTreeMap, BTreeSet};

use arkret_identifiers::{Did, EventId, RealmId};
use arkret_models_collaboration::event_query::{
    EventsQueryPostRequestBody, PeerEventsDescribeRequestBody, PeerEventsFrontierRequestBody,
};
use arkret_models_collaboration::event_sync::{
    EventsFrontierFederationPeerState, EventsSubmitFederationRequestBody, MAX_FEDERATED_EVENTS,
};
use arkret_models_collaboration::http_bodies::{
    EventsQueryOutcome, PeerEventsResolveOutcome, PeerEventsResolveRequestBody,
};
use arkret_wire::{CbaProofBundle, SignalRelayOutcome, SignalRelayRequest};
use chrono::{DateTime, Utc};
use salvo::http::StatusCode;
use salvo::prelude::*;
use serde::Serialize;
use serde_json::{Value, json};
use soland_http::error::AppError;
use soland_http::result::{JsonResult, json_ok};
use soland_services::events::{
    CanonicalEventRecord, PeerEventsPageQuery, RealmMetadata as RealmMetaRecord,
};

use super::{is_realm_deleted, is_valid_hash_digest, now, query_param, render_error, validate_did};
use crate::state::AppState;

const HEADER_SOURCE_SERVICE_ID: &str = "source-service-id";
const HEADER_DESTINATION_SERVICE_ID: &str = "destination-service-id";
const MAX_PEER_EVENTS_READ_LIMIT: usize = 100;
const MAX_PEER_EVENTS_RESOLVE: usize = 1024;

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
struct PeerEventsDescribeOutcome {
    service_id: Did,
    protocol_version: String,
    primary_write_path: String,
    supported_operations: Vec<String>,
    supported_profiles: Vec<String>,
    supported_bindings: Vec<String>,
    limits: PeerEventsDescribeLimits,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
struct PeerEventsDescribeLimits {
    max_batch_item_count: usize,
    max_query_limit: usize,
    max_resolve: usize,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
struct PeerSnapshotHeadOutcome {}

pub(super) fn router() -> Router {
    Router::new()
        .push(Router::with_path("events/describe").query(peer_events_describe))
        .push(
            Router::with_path("events")
                .post(peer_events_submit)
                .query(peer_events_read_body),
        )
        .push(Router::with_path("events/resolve").query(peer_events_resolve))
        .push(Router::with_path("events/frontier").query(peer_events_frontier))
        .push(Router::with_path("snapshot/head").get(peer_snapshot_head))
        .push(Router::with_path("signal").post(peer_signal_relay))
}

#[salvo::oapi::endpoint(operation_id = "ak.peer.signal.command.relay", tags("events"))]
#[tracing::instrument(skip_all, fields(op = "ak.peer.signal.command.relay"))]
async fn peer_signal_relay(depot: &mut Depot, req: &mut Request) -> JsonResult<SignalRelayOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    if req.headers().contains_key("idempotency-key") {
        return Err(schema_violation(
            "ak.peer.signal.command.relay forbids Idempotency-Key",
        ));
    }
    validate_peer_request(state, req, true).await?;
    validate_signal_signature_window(req)?;
    let request = parse_json_body::<SignalRelayRequest>(
        req,
        "invalid ak.peer.signal.command.relay request body",
    )
    .await?;
    request
        .validate()
        .map_err(|error| schema_violation(error.to_string()))?;
    let source_service_id = source_service_id_from_request(req)?;
    for envelope in request.signals {
        if let Err(error) =
            super::sync::signal::accept_peer_signal(state, &source_service_id, &envelope).await
        {
            tracing::debug!(
                %error,
                realm_id = %request.realm_id,
                "peer signal item silently dropped"
            );
        }
    }
    json_ok(SignalRelayOutcome::ACCEPTED)
}

fn validate_signal_signature_window(req: &Request) -> Result<(), AppError> {
    let signature_input =
        soland_http::http_signature::parse_signature_input_header(req).map_err(|error| {
            schema_violation(format!("invalid Signal relay Signature-Input: {error}"))
        })?;
    if signature_input.expires < signature_input.created
        || signature_input.expires - signature_input.created > 5
    {
        return Err(AppError::capability_denied(
            "Signal relay signature validity window must be at most 5 seconds",
        ));
    }
    Ok(())
}

#[salvo::oapi::endpoint(operation_id = "ak.peer.events.read.describe", tags("events"))]
#[tracing::instrument(skip_all, fields(op = "ak.peer.events.read.describe"))]
async fn peer_events_describe(
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<PeerEventsDescribeOutcome> {
    if req.method().as_str() == "QUERY" {
        parse_json_body::<PeerEventsDescribeRequestBody>(
            req,
            "invalid ak.peer.events.read.describe request body",
        )
        .await?;
    }
    let state = depot.get_typed::<AppState>().expect("state injected");
    let service_id = Did::new(state.service_id().clone())
        .map_err(|_| AppError::internal("service_id is invalid"))?;
    json_ok(PeerEventsDescribeOutcome {
        service_id,
        protocol_version: "1.0".to_owned(),
        primary_write_path: "/_arkret/peer/events".to_owned(),
        supported_operations: vec![
            "ak.peer.events.read.describe".to_owned(),
            "ak.peer.events.command.submit".to_owned(),
            "ak.peer.events.read.scan".to_owned(),
            "ak.peer.events.read.resolve".to_owned(),
            "ak.peer.events.read.frontier".to_owned(),
            "ak.peer.invites.command.submit".to_owned(),
            "ak.peer.signal.command.relay".to_owned(),
        ],
        supported_profiles: vec![
            "ak.profile.federation_minimal.v1".to_owned(),
            "ak.profile.signal_peer_relay.v1".to_owned(),
        ],
        supported_bindings: vec![
            "http-message-signature".to_owned(),
            "source-service-id".to_owned(),
            "destination-service-id".to_owned(),
            "source-trust-domain".to_owned(),
            "destination-trust-domain".to_owned(),
        ],
        limits: PeerEventsDescribeLimits {
            max_batch_item_count: MAX_FEDERATED_EVENTS,
            max_query_limit: MAX_PEER_EVENTS_READ_LIMIT,
            max_resolve: MAX_PEER_EVENTS_RESOLVE,
        },
    })
}

#[salvo::oapi::endpoint(operation_id = "ak.peer.events.command.submit", tags("events"))]
#[tracing::instrument(skip_all, fields(op = "ak.peer.events.command.submit"))]
async fn peer_events_submit(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.get_typed::<AppState>().expect("state injected");
    if let Err(error) = validate_peer_request(state, req, true).await {
        render_app_error(res, error);
        return;
    }
    let body_value = match req.parse_json::<Value>().await {
        Ok(body) => body,
        Err(_) => {
            render_error(
                res,
                StatusCode::BAD_REQUEST,
                "bad_json",
                "invalid ak.peer.events.command.submit request body",
            );
            return;
        }
    };
    if let Err(error) =
        serde_json::from_value::<EventsSubmitFederationRequestBody>(body_value.clone())
    {
        render_app_error(
            res,
            schema_violation(format!(
                "invalid ak.peer.events.command.submit request body: {error}"
            )),
        );
        return;
    }
    super::event_log::submit_federation_events(state, req, body_value, res).await;
}

#[salvo::oapi::endpoint(operation_id = "ak.peer.events.read.scan", tags("events"))]
#[tracing::instrument(skip_all, fields(op = "ak.peer.events.read.scan"))]
async fn peer_events_read_body(
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<EventsQueryOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    validate_peer_request(state, req, true).await?;
    let request = parse_json_body::<EventsQueryPostRequestBody>(
        req,
        "invalid ak.peer.events.read.scan request body",
    )
    .await?;
    let source_service_id = source_service_id_from_request(req)?;
    let parts = PeerEventsQueryParts::from_body(request)?;
    peer_events_query_response(state, source_service_id, parts).await
}

#[salvo::oapi::endpoint(operation_id = "ak.peer.events.read.resolve", tags("events"))]
#[tracing::instrument(skip_all, fields(op = "ak.peer.events.read.resolve"))]
async fn peer_events_resolve(
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<PeerEventsResolveOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    validate_peer_request(state, req, true).await?;
    let request = parse_json_body::<PeerEventsResolveRequestBody>(
        req,
        "invalid ak.peer.events.read.resolve request body",
    )
    .await?;
    request
        .validate()
        .map_err(|error| AppError::invalid_param(error.to_string()))?;
    let source_service_id = source_service_id_from_request(req)?;
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
        .event_queries()
        .canonical_events()
        .await
        .map_err(|error| AppError::internal(format!("peer events resolve: {error}")))?;
    let authz = PeerReadAuthz::build(state, &source_service_id, &records).await?;
    let mut events = Vec::new();
    let mut found_ids = BTreeSet::new();
    let mut found_digests = BTreeSet::new();
    for record in records {
        if record.realm_id.as_deref() != Some(request.realm_id.as_str()) {
            continue;
        }
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
            event.payload.clear();
        }
        events.push(event);
    }
    events.sort_by(|left, right| left.event_id.as_str().cmp(right.event_id.as_str()));
    let mut missing_event_ids = Vec::new();
    for id in &request.event_ids {
        if !found_ids.contains(id.as_str()) {
            missing_event_ids.push(id.clone());
        }
    }
    let mut missing_event_digests = Vec::new();
    for digest in &request.event_digests {
        if !found_digests.contains(digest.as_str()) {
            missing_event_digests.push(digest.clone());
        }
    }
    let mut cba_proof_bundles = Vec::new();
    let mut missing_seal_refs = Vec::new();
    for seal_ref in &request.seal_refs {
        if !authz.frontier_visible_for_realm(request.realm_id.as_str()) {
            missing_seal_refs.push(seal_ref.clone());
            continue;
        }
        match peer_cba_bundle_for_seal(state, seal_ref) {
            Ok(Some(bundle))
                if bundle
                    .seals
                    .iter()
                    .all(|seal| seal.realm_id == request.realm_id) =>
            {
                cba_proof_bundles.push(bundle);
            }
            _ => missing_seal_refs.push(seal_ref.clone()),
        }
    }
    cba_proof_bundles.sort_by(|left, right| {
        left.target_seal_ref
            .as_str()
            .cmp(right.target_seal_ref.as_str())
    });
    let outcome = PeerEventsResolveOutcome {
        events,
        cba_proof_bundles,
        missing_event_ids,
        missing_event_digests,
        missing_seal_refs,
    };
    outcome
        .validate_structural()
        .map_err(|error| AppError::internal(error.to_string()))?;
    let response_bytes = arkret_canonical::canonical_json_bytes(&outcome)
        .map_err(|error| AppError::internal(format!("peer resolve response: {error}")))?;
    let budget = request.max_response_bytes.unwrap_or(8 * 1024 * 1024) as usize;
    if response_bytes.len() > budget {
        return Err(AppError::new(
            soland_http::error::ErrorCode::LimitExceeded,
            "peer dependency response exceeds max_response_bytes",
        ));
    }
    json_ok(outcome)
}

fn peer_cba_bundle_for_seal(
    state: &AppState,
    target_seal_ref: &arkret_identifiers::SealId,
) -> Result<Option<CbaProofBundle>, AppError> {
    let mut pending = vec![target_seal_ref.clone()];
    let mut by_id = BTreeMap::new();
    while let Some(seal_id) = pending.pop() {
        if by_id.contains_key(&seal_id) {
            continue;
        }
        let Some(seal) = state.projections().seal_by_id(&seal_id).map_err(|error| {
            AppError::internal(format!("peer resolve read Seal {seal_id}: {error}"))
        })?
        else {
            return Ok(None);
        };
        pending.extend(seal.predecessor_refs.iter().cloned());
        by_id.insert(seal_id, seal);
    }
    if by_id.len() > arkret_wire::cba_proof_bundle::MAX_BUNDLE_SEALS {
        return Err(AppError::new(
            soland_http::error::ErrorCode::LimitExceeded,
            "peer Seal prerequisite closure exceeds the v1 limit",
        ));
    }
    Ok(Some(CbaProofBundle {
        target_seal_ref: target_seal_ref.clone(),
        seals: by_id.into_values().collect(),
        control_moves: Vec::new(),
        inclusion_proofs: Vec::new(),
        availability_proofs: Vec::new(),
    }))
}

#[salvo::oapi::endpoint(operation_id = "ak.peer.events.read.frontier", tags("events"))]
#[tracing::instrument(skip_all, fields(op = "ak.peer.events.read.frontier"))]
async fn peer_events_frontier(
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<EventsFrontierFederationPeerState> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let has_body = req.method().as_str() == "QUERY";
    validate_peer_request(state, req, has_body).await?;
    let source_service_id = source_service_id_from_request(req)?;
    let realm_id = if has_body {
        parse_json_body::<PeerEventsFrontierRequestBody>(
            req,
            "invalid ak.peer.events.read.frontier request body",
        )
        .await?
        .realm_id
        .into_string()
    } else {
        query_param(req, "realm_id")
            .ok_or_else(|| AppError::missing_param("realm_id is required"))?
    };
    let realm_id =
        RealmId::new(realm_id).map_err(|_| AppError::invalid_param("invalid realm_id"))?;
    if is_realm_deleted(state, realm_id.as_str()).await {
        return Err(AppError::not_found("not found"));
    }
    let records = state
        .event_queries()
        .canonical_events()
        .await
        .map_err(|error| AppError::internal(format!("peer frontier: {error}")))?;
    let authz = PeerReadAuthz::build(state, &source_service_id, &records).await?;
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
    let service_id = Did::new(state.service_id().clone())
        .map_err(|_| AppError::internal("service_id is invalid"))?;
    let observed_at = now();
    let signature = super::frontier::sign_frontier_root(
        &service_id,
        Some(&realm_id),
        observed_at,
        &frontier_root,
        state.notary_signing_key().as_ref(),
    )
    .map_err(|error| AppError::internal(format!("frontier signature: {error}")))?;
    json_ok(EventsFrontierFederationPeerState {
        realm_id,
        heads: typed_heads,
        frontier_root,
        actor_seq_upper_bounds: typed_actor_frontier,
        witness_receipts: Vec::new(),
        observed_at: arkret_canonical::format_timestamp_canonical(observed_at),
        issuer: service_id,
        signature: signature
            .as_object()
            .expect("frontier signature must be an object")
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect(),
        max_hlc,
    })
}

/// Spec resolution (2026-06-11): `ak.peer.snapshot.read.manifest_head` returns the full
/// signed `ak.schema.snapshot.v1` manifest. soland cannot produce a real
/// Snapshot detached proof yet, and the spec forbids serving a dev-signed
/// stand-in (`signature` / `authority_binding` / `event_set_commitment`
/// MUST NOT be fabricated — service-http-binding.md §6.1, service-surface.md
/// §5.2). The operation is therefore undeclared and the endpoint fails
/// closed with `not_implemented` until a real signing path lands. The
/// dev snapshot bundle remains reachable on the `/_soland/` product face
/// (`org.arkret.soland.sync.snapshot_chunk`).
#[salvo::oapi::endpoint(operation_id = "ak.peer.snapshot.read.manifest_head", tags("events"))]
#[tracing::instrument(skip_all, fields(op = "ak.peer.snapshot.read.manifest_head"))]
async fn peer_snapshot_head(
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<PeerSnapshotHeadOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    validate_peer_request(state, req, false).await?;
    Err(AppError::new(
        soland_http::error::ErrorCode::NotImplemented,
        "ak.peer.snapshot.read.manifest_head is not implemented: this deployment cannot \
         produce a signed ak.schema.snapshot.v1 manifest",
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
    fn from_body(body: EventsQueryPostRequestBody) -> Result<Self, AppError> {
        let filters = body
            .filters
            .as_ref()
            .and_then(|filters| serde_json::to_value(filters).ok());
        let kind_filter = parse_kind_filter(filters.as_ref())?;
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
                .unwrap_or(MAX_PEER_EVENTS_READ_LIMIT)
                .clamp(1, MAX_PEER_EVENTS_READ_LIMIT),
            kind_filter,
        };
        parts.validate()?;
        Ok(parts)
    }

    fn validate(&self) -> Result<(), AppError> {
        if self.realms.is_empty() && self.actors.is_empty() {
            return Err(AppError::missing_param(
                "ak.peer.events.read.scan requires at least one of realms[] / actors[]",
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
            && (!kind.starts_with("ak.") || kind.contains(' '))
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
    source_service_id: String,
    realm_meta: BTreeMap<String, RealmMetaRecord>,
    realm_endpoints: BTreeMap<String, Vec<PeerRealmEndpoint>>,
    realm_members: BTreeMap<String, BTreeMap<String, PeerMembership>>,
    pending_realm_invites: BTreeMap<(String, String), PendingPeerInvite>,
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
struct PendingPeerInvite {
    invitee: String,
    invited_at: DateTime<Utc>,
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
        source_service_id: &str,
        records: &[CanonicalEventRecord],
    ) -> Result<Self, AppError> {
        let realm_meta = state
            .realms()
            .realm_metadata_list()
            .await
            .map_err(|error| AppError::internal(format!("peer realm metadata: {error}")))?
            .into_iter()
            .collect::<BTreeMap<_, _>>();
        let circles = state
            .projections()
            .snapshot()
            .circles
            .iter()
            .map(|(circle_id, circle)| {
                (
                    circle_id.clone(),
                    PeerCircleState {
                        realm_id: circle.realm_id.clone(),
                        history_visibility: circle.history_visibility.clone(),
                        active: circle.state.as_str() == "active",
                    },
                )
            })
            .collect::<BTreeMap<_, _>>();
        let mut authz = Self {
            source_service_id: source_service_id.to_owned(),
            realm_meta,
            realm_endpoints: BTreeMap::new(),
            realm_members: BTreeMap::new(),
            pending_realm_invites: BTreeMap::new(),
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
        self.apply_invite_record(record);
        self.apply_member_record(record);
        self.apply_circle_member_record(record);
    }

    fn apply_invite_record(&mut self, record: &CanonicalEventRecord) {
        let Some(realm_id) = super::event_log::canonical_realm_id_for_record(record) else {
            return;
        };
        let Some(payload) = record_payload(record) else {
            return;
        };
        match record.kind.as_str() {
            arkret_wire::EventKind::INVITE_CREATE => {
                let Some(invite_id) = payload.get("invite_id").and_then(Value::as_str) else {
                    return;
                };
                let Some(invitee) = payload.get("invitee").and_then(Value::as_str) else {
                    return;
                };
                let source_matches = payload
                    .get("invite_delivery_target")
                    .and_then(Value::as_object)
                    .and_then(|target| target.get("recipient_service_id"))
                    .and_then(Value::as_str)
                    .is_some_and(|service_id| service_id == self.source_service_id);
                if source_matches {
                    self.pending_realm_invites.insert(
                        (realm_id, invite_id.to_owned()),
                        PendingPeerInvite {
                            invitee: invitee.to_owned(),
                            invited_at: record_event_time(record),
                        },
                    );
                }
            }
            arkret_wire::EventKind::INVITE_ACCEPT => {
                let Some(invite_id) = payload
                    .get("invite_id")
                    .or_else(|| payload.get("invite_ref"))
                    .and_then(Value::as_str)
                else {
                    return;
                };
                let Some(invite) = self
                    .pending_realm_invites
                    .remove(&(realm_id.clone(), invite_id.to_owned()))
                else {
                    return;
                };
                if record.actor_id != invite.invitee {
                    return;
                }
                self.realm_members.entry(realm_id).or_default().insert(
                    invite.invitee,
                    PeerMembership {
                        joined_at: record_event_time(record),
                        invited_at: Some(invite.invited_at),
                    },
                );
            }
            _ => {}
        }
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
            .contains(self.source_service_id.as_str())
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
        if record.kind != arkret_wire::EventKind::MEMBER_STATE {
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
                    .get("recipient_service_id")
                    .and_then(Value::as_str)
                    .is_some_and(|did| did == self.source_service_id);
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
        if record.kind != arkret_wire::EventKind::CIRCLE_MEMBER_STATE {
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
        if record.kind != arkret_wire::EventKind::REALM_POLICY_BUNDLE {
            return;
        }
        let Some(realm_id) = super::event_log::canonical_realm_id_for_record(record) else {
            return;
        };
        // The policy bundle is a complete CAS-register restatement. Omission
        // in a newer revision clears the preceding endpoint set.
        self.realm_endpoints.remove(&realm_id);
        let Some(sync_endpoints) =
            record_payload_field(record, "sync_endpoints").and_then(Value::as_array)
        else {
            return;
        };
        let mut endpoints = Vec::new();
        for endpoint in sync_endpoints {
            let Some(object) = endpoint.as_object() else {
                continue;
            };
            if object.get("did").and_then(Value::as_str) != Some(self.source_service_id.as_str()) {
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
    let scope = object.get("scope_ref")?.as_object()?;
    if scope.get("kind").and_then(Value::as_str) != Some("circle") {
        return None;
    }
    scope
        .get("circle_id")
        .and_then(Value::as_str)
        .filter(|scope| scope.starts_with("ak:circle:"))
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
    source_service_id: String,
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
    let filter_digest = peer_events_query_scope_digest(&source_service_id, &parts);
    let cursor_event_id =
        peer_events_query_cursor_event_id(state, parts.active_cursor(), &filter_digest).await?;
    let authz_records = state
        .event_queries()
        .peer_authz_state_records()
        .await
        .map_err(|error| AppError::internal(format!("peer events query: {error}")))?;
    let authz = PeerReadAuthz::build(state, &source_service_id, &authz_records).await?;
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
            range_completeness: None,
        });
    }
    let candidate_limit = peer_events_candidate_limit(parts.limit);
    let mut scan_cursor_event_id = cursor_event_id;
    let mut visible = Vec::new();
    loop {
        let candidates = state
            .event_queries()
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
        range_completeness: None,
    })
}

fn peer_events_candidate_limit(page_limit: usize) -> usize {
    page_limit
        .saturating_mul(4)
        .clamp(MAX_PEER_EVENTS_READ_LIMIT, MAX_PEER_EVENTS_READ_LIMIT * 5)
}

fn peer_events_query_scope_digest(source_service_id: &str, parts: &PeerEventsQueryParts) -> String {
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
        "operation_id": "ak.peer.events.read.scan",
        "source_service_id": source_service_id,
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
        super::sync::SyncCursorError::Expired => AppError::new(
            soland_http::error::ErrorCode::CursorExpired,
            "cursor has expired",
        ),
        super::sync::SyncCursorError::Invalid(message) => AppError::invalid_param(message),
        super::sync::SyncCursorError::Mismatch(message)
        | super::sync::SyncCursorError::Integrity(message) => AppError::new(
            soland_http::error::ErrorCode::CursorIntegrityInvalid,
            message,
        ),
        super::sync::SyncCursorError::Revoked => AppError::new(
            soland_http::error::ErrorCode::CursorRevoked,
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

pub(in crate::routing) async fn validate_peer_request(
    state: &AppState,
    req: &mut Request,
    has_body: bool,
) -> Result<(), AppError> {
    let expected_destination =
        arkret_identifiers::TypedTrustDomainId::new(state.config().trust_domain.clone())
            .map_err(|_| AppError::internal("service trust_domain is invalid"))?;
    if has_body {
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
    } else {
        if req.headers().contains_key("content-digest") {
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
            if signature_input.contains("\"content-digest\"") {
                return Err(schema_violation(
                    "GET peer read Signature-Input must not bind body digest components",
                ));
            }
        }
        let destination_trust_domain = required_header(req, "destination-trust-domain")?;
        let destination_trust_domain =
            arkret_identifiers::TypedTrustDomainId::new(destination_trust_domain)
                .map_err(|_| schema_violation("destination-trust-domain must be a trust domain"))?;
        if destination_trust_domain != expected_destination {
            return Err(cross_domain_replay(
                "Destination-Trust-Domain header does not match this service",
            ));
        }
        let source_trust_domain = required_header(req, "source-trust-domain")?;
        arkret_identifiers::TypedTrustDomainId::new(source_trust_domain)
            .map_err(|_| schema_violation("source-trust-domain must be a trust domain"))?;
    }
    let source_service_id = required_header(req, HEADER_SOURCE_SERVICE_ID)?;
    if validate_did(&source_service_id).is_err() {
        return Err(schema_violation("source-service-id must be a DID"));
    }
    let destination_service_id = required_header(req, HEADER_DESTINATION_SERVICE_ID)?;
    if validate_did(&destination_service_id).is_err() {
        return Err(schema_violation("destination-service-id must be a DID"));
    }
    if destination_service_id != *state.service_id() {
        return Err(cross_domain_replay(
            "destination-service-id header does not match this service",
        ));
    }
    // federation.md §3.2/§6: all `/_arkret/peer/*` requests MUST be authenticated
    // with an RFC 9421 HTTP Message Signature verified against the sender's
    // service DID key, and the local peer deny policy MUST be enforced inbound.
    // The bare trust-header checks above are necessary but not sufficient; the
    // signature verification (which also re-binds POST body digests and runs
    // the deny policy) is the authoritative gate.
    crate::routing::federation::federation::verify_inbound_peer_http_signature(
        state, req, has_body,
    )
    .await?;
    Ok(())
}

fn source_service_id_from_request(req: &Request) -> Result<String, AppError> {
    required_header(req, HEADER_SOURCE_SERVICE_ID)
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
