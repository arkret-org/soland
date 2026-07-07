use std::collections::BTreeSet;

use chrono::Duration;
use cokret_sdk::{Did, RealmId};
use salvo::http::StatusCode;
use salvo::oapi::extract::{JsonBody, PathParam, QueryParam};
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::actor_signature::{
    federation_verify_actor_digest, federation_verify_actor_unsigned_digest,
    verify_federation_actor_signature,
};
use super::backfill::{
    configured_peer_from_backfill_body, federation_request_digest, is_valid_federation_txn_id,
    operation_frontier_outcome, pull_operations_page,
};
use super::inbound_policy::{
    MAX_INBOUND_FEDERATION_OPERATIONS, enforce_inbound_operation_batch_policy,
    ensure_private_inbound_read_rail_local, ensure_private_inbound_write_rail_local,
};
use super::signature::{
    origin_key_state_digest_for_service, validate_federation_headers,
    validate_federation_request_binding, verify_inbound_push_http_signature,
    verify_inbound_transaction_http_signature,
};
use super::wire::{FederationTrustHeaders, mark_response_historical_only};
use super::{
    federation_destination_matches, ingest_federation_operations, now, operation_is_visible,
    redaction_targets_from_operations, sync_token, verify_federation_origin,
};
use crate::error::AppError;
use crate::ids;
use crate::result::{JsonResult, json_ok};
use crate::state::{AppState, FederationTransactionRecord};

#[derive(Clone, Debug, Serialize, Deserialize, salvo::oapi::ToSchema)]
pub(in crate::routing::federation::federation) struct FederationActorEventsOutcome {
    actor: String,
    events: Vec<Value>,
    erasure_receipts: Vec<Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize, salvo::oapi::ToSchema)]
#[serde(deny_unknown_fields)]
pub(in crate::routing::federation::federation) struct FederationBackfillOperationsRequestBody {
    realm_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    peer_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    peer_did: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    limit: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    max_pages: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    after_cursor: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, salvo::oapi::ToSchema)]
pub(in crate::routing::federation::federation) struct FederationOperationFrontierOutcome {
    pub(in crate::routing::federation::federation) realm_id: String,
    pub(in crate::routing::federation::federation) operation_count: usize,
    pub(in crate::routing::federation::federation) operation_ids: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(in crate::routing::federation::federation) latest_operation_id: Option<String>,
    pub(in crate::routing::federation::federation) frontier_digest: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, salvo::oapi::ToSchema)]
pub(in crate::routing::federation::federation) struct FederationBackfillOperationsOutcome {
    peer_url: String,
    peer_did: String,
    realm_id: String,
    pulled: usize,
    accepted: Vec<String>,
    rejected: Vec<Value>,
    pages: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    next_cursor: Option<String>,
    has_more: bool,
    frontier_before: FederationOperationFrontierOutcome,
    frontier_after: FederationOperationFrontierOutcome,
}

#[endpoint(
    operation_id = "org.cokret.soland.federation.transaction",
    tags("federation"),
    summary = "Idempotent inbound server-to-server federation transaction"
)]
#[tracing::instrument(skip_all, fields(op = "org.cokret.soland.federation.transaction"))]
pub(crate) async fn federation_transaction(
    txn_id: PathParam<String>,
    body: JsonBody<cokret_sdk::FederationTransactionRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<cokret_sdk::FederationTransactionOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    ensure_private_inbound_write_rail_local(state)?;
    let txn_id = txn_id.into_inner();
    if !is_valid_federation_txn_id(&txn_id) {
        return Err(AppError::invalid_param("invalid federation transaction id"));
    }
    let body = body.into_inner();
    let content_digest = federation_request_digest(&body).map_err(AppError::invalid_param)?;
    // Round 4 (B1.7) — federation trust-domain headers are now part
    // of the hard admission boundary. Missing / malformed headers are
    // schema_violation; destination or request-digest mismatch is
    // cross_domain_replay_rejected.
    let trust_headers = FederationTrustHeaders::from_salvo_request(req).map_err(|violation| {
        AppError::new(
            crate::error::ErrorCode::SchemaViolation,
            violation.message(),
        )
        .with_status(StatusCode::BAD_REQUEST)
    })?;
    let expected_destination = cokret_sdk::TypedTrustDomainId::new(
        state.config.trust_domain.clone(),
    )
    .map_err(|error| AppError::internal(format!("configured trust_domain invalid: {error}")))?;
    validate_federation_headers(&trust_headers, &expected_destination, &content_digest)?;
    verify_inbound_transaction_http_signature(state, req, &body).await?;
    let fragment = trust_headers.transcript_fragment();
    tracing::trace!(transcript_fragment = %fragment, "round-4 federation transcript fragment");
    // Round 4 (B1.8) — round-4 federation idempotency cache key. The
    // composite carries (source_did, dest_did, request_canonical_digest,
    // idempotency_key, origin_key_state_digest). When the strict key
    // matches a cached entry the receiver returns the cached body
    // unchanged; when the strict key misses but the canonical-replay
    // key matches, the cached body is returned marked
    // `reason_code=historical_only` (no fresh side effects).
    //
    // The request_canonical_digest comes from the round-4 federation
    // headers. The origin key-state digest is derived from the same
    // service verification key that passed the HTTP Message Signature
    // check, so idempotency no longer falls back to placeholder material.
    let origin_key_state_digest = origin_key_state_digest_for_service(state, body.origin.as_str())?;
    let origin_verification_method = format!("{}#federation-fanout-key", body.origin.as_str());
    let local_peer_policy_digest =
        local_peer_policy_digest_for_transaction(state, body.origin.as_str(), &body)?;
    // Whether this request is taking over a stale `processing` claim left by
    // a worker that crashed between `try_begin` and the finalising `put`.
    let mut stale_claim_takeover = false;
    match state
        .persistence
        .federation_transactions()
        .get(body.origin.as_str(), &txn_id)
        .await
    {
        // Another request claimed this (origin, txn_id) and is still
        // ingesting. Matched before the cached-response arm so a
        // placeholder row is never decoded as a final outcome.
        Ok(Some(record)) if record.status == super::FEDERATION_TXN_STATUS_PROCESSING => {
            if record.content_digest != content_digest {
                return Err(AppError::new(
                    crate::error::ErrorCode::DuplicateConflict,
                    "federation transaction id was reused with different content",
                ));
            }
            let claim_age_secs = now()
                .signed_duration_since(record.received_at)
                .num_seconds();
            if claim_age_secs < super::FEDERATION_TXN_PROCESSING_TAKEOVER_SECS {
                return Err(AppError::new(
                    crate::error::ErrorCode::TemporarilyUnavailable,
                    "federation transaction is being processed by a concurrent delivery; retry",
                ));
            }
            stale_claim_takeover = true;
        }
        Ok(Some(record)) if record.content_digest == content_digest => {
            // Round R2/R3 (T14) + Round 4 (B1.8) — cache hit MUST re-do
            // capability check. We re-validate origin & destination
            // before serving cached response so a revoked peer cannot
            // keep mining responses.
            if !verify_federation_origin(body.origin.as_str()) {
                return Err(AppError::unauthenticated(
                    "federation origin must be a valid DID (cache re-verification)",
                ));
            }
            if crate::security::federation_origin_denied(body.origin.as_str()) {
                return Err(AppError::capability_denied(
                    "federation origin is denied by deployment peer policy \
                     (cache re-verification)",
                ));
            }
            if !federation_destination_matches(state, body.destination.as_str()) {
                return Err(AppError::capability_denied(
                    "federation transaction destination does not match this service \
                     (cache re-verification)",
                ));
            }
            enforce_inbound_operation_batch_policy(
                state,
                body.origin.as_str(),
                body.operations.as_slice(),
            )
            .await?;
            // Round 4 (B1.8) — detect a canonical-replay hit (txn_id +
            // request_canonical_digest match, but origin_key_state_digest
            // has rotated since the cached entry was minted). Such a
            // hit is marked historical_only after reauthorization and
            // never repeats side effects.
            let mut response_value = record.response.clone();
            let strict_cache_hit = record.origin_verification_method.as_deref()
                == Some(origin_verification_method.as_str())
                && record.service_binding_ref.as_deref() == Some(body.service_binding_ref.as_str())
                && record.origin_key_state_digest.as_deref()
                    == Some(origin_key_state_digest.as_str())
                && record.local_peer_policy_digest.as_deref()
                    == Some(local_peer_policy_digest.as_str());
            if !strict_cache_hit {
                response_value = mark_response_historical_only(response_value);
            }
            let response: cokret_sdk::FederationTransactionOutcome =
                serde_json::from_value(response_value).map_err(|error| {
                    AppError::internal(format!("cached federation response decode: {error}"))
                })?;
            return json_ok(response);
        }
        Ok(Some(_)) => {
            return Err(AppError::new(
                crate::error::ErrorCode::DuplicateConflict,
                "federation transaction id was reused with different content",
            ));
        }
        Ok(None) => {}
        Err(error) => {
            return Err(AppError::internal(error.to_string()));
        }
    }
    if !verify_federation_origin(body.origin.as_str()) {
        return Err(AppError::unauthenticated(
            "federation origin must be a valid DID",
        ));
    }
    if crate::security::federation_origin_denied(body.origin.as_str()) {
        return Err(AppError::capability_denied(
            "federation origin is denied by deployment peer policy",
        ));
    }
    if !federation_destination_matches(state, body.destination.as_str()) {
        return Err(AppError::capability_denied(
            "federation transaction destination does not match this service",
        ));
    }
    let origin = body.origin.to_string();
    let destination = body.destination.to_string();
    let operations = body.operations;
    enforce_inbound_operation_batch_policy(state, &origin, &operations).await?;
    // Claim the (origin, txn_id) idempotency slot *before* the
    // side-effecting ingest. Without this, two concurrent deliveries of the
    // same txn_id both observed `get == None` above and both executed the
    // operation batch (TOCTOU). The placeholder insert is atomic
    // (`ON CONFLICT DO NOTHING`); only the winner ingests, the loser asks
    // the peer to retry (it will then hit the winner's cached response).
    // A `stale_claim_takeover` skips the claim — the placeholder row
    // already exists and is past its takeover horizon.
    if !stale_claim_takeover {
        let placeholder = FederationTransactionRecord {
            origin: origin.clone(),
            txn_id: txn_id.clone(),
            destination: destination.clone(),
            realm_id: None,
            content_digest: content_digest.clone(),
            origin_verification_method: Some(origin_verification_method.clone()),
            service_binding_ref: Some(body.service_binding_ref.clone()),
            origin_key_state_digest: Some(origin_key_state_digest.clone()),
            local_peer_policy_digest: Some(local_peer_policy_digest.clone()),
            status: super::FEDERATION_TXN_STATUS_PROCESSING.to_owned(),
            response: Value::Null,
            received_at: now(),
            processed_at: None,
        };
        let claimed = state
            .persistence
            .federation_transactions()
            .try_begin(&placeholder)
            .await
            .map_err(|error| AppError::internal(error.to_string()))?;
        if !claimed {
            return Err(AppError::new(
                crate::error::ErrorCode::TemporarilyUnavailable,
                "federation transaction is being processed by a concurrent delivery; retry",
            ));
        }
    }
    let ingest = ingest_federation_operations(state, &origin, operations).await;
    let response = cokret_sdk::FederationTransactionOutcome {
        ok: true,
        accepted: ingest.accepted,
        rejected: ingest.rejected,
        next_retry_at: None,
        historical_only: false,
        reason_code: None,
        original_outcome: None,
    };
    let response_value =
        serde_json::to_value(&response).map_err(|error| AppError::internal(error.to_string()))?;
    let now = now();
    let record = FederationTransactionRecord {
        origin,
        txn_id,
        destination,
        realm_id: None,
        content_digest,
        origin_verification_method: Some(origin_verification_method),
        service_binding_ref: Some(body.service_binding_ref),
        origin_key_state_digest: Some(origin_key_state_digest),
        local_peer_policy_digest: Some(local_peer_policy_digest),
        status: "accepted".to_owned(),
        response: response_value,
        received_at: now,
        processed_at: Some(now),
    };
    state
        .persistence
        .federation_transactions()
        .put(&record)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    json_ok(response)
}

fn local_peer_policy_digest_for_transaction(
    state: &AppState,
    origin_service_did: &str,
    body: &cokret_sdk::FederationTransactionRequestBody,
) -> Result<String, AppError> {
    let live_settings = state.settings();
    let mut federation_peers = live_settings.federation_peers.clone();
    federation_peers.sort();
    federation_peers.dedup();
    let realm_ids = body
        .operations
        .iter()
        .map(|operation| operation.realm_id.as_str().to_owned())
        .collect::<BTreeSet<_>>();
    let realm_policies = {
        let projection = state.projection.lock();
        realm_ids
            .iter()
            .map(|realm_id| {
                json!({
                    "realm_id": realm_id,
                    "federation_policy": projection
                        .realm_federation_policy(realm_id)
                        .unwrap_or_else(|| "open".to_owned()),
                })
            })
            .collect::<Vec<_>>()
    };
    let moderation_policies = {
        let policies = state.realm_moderation_policies.lock();
        realm_ids
            .iter()
            .filter_map(|realm_id| {
                policies.get(realm_id).map(|record| {
                    json!({
                        "realm_id": record.realm_id.as_str(),
                        "payload": record.payload.clone(),
                        "updated_at": record.updated_at.to_rfc3339(),
                    })
                })
            })
            .collect::<Vec<_>>()
    };
    let policy_state = json!({
        "schema": "ck.federation.local_peer_policy_digest.v1",
        "source_service_did": origin_service_did,
        "destination_service_did": body.destination.as_str(),
        "service_binding_ref": body.service_binding_ref.as_str(),
        "fanout_topology": live_settings.federation_fanout_topology.as_str(),
        "federation_peers": federation_peers,
        "source_denied": crate::security::federation_origin_denied(origin_service_did),
        "max_inbound_operations": MAX_INBOUND_FEDERATION_OPERATIONS,
        "realm_policies": realm_policies,
        "realm_moderation_policies": moderation_policies,
    });
    let canonical =
        cokret_sdk::canonical::canonical_json_bytes(&policy_state).map_err(|error| {
            AppError::internal(format!(
                "federation local peer policy digest canonicalization: {error}"
            ))
        })?;
    Ok(cokret_sdk::canonical::sha256_digest(&canonical))
}

#[endpoint(
    operation_id = "org.cokret.soland.federation.push_operations",
    tags("federation"),
    summary = "Accept a batch of operations pushed from a peer service"
)]
#[tracing::instrument(skip_all, fields(op = "org.cokret.soland.federation.push_operations"))]
pub(crate) async fn federation_push_operations(
    body: JsonBody<cokret_sdk::FederationPushOperationsRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<cokret_sdk::FederationPushOperationsOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    ensure_private_inbound_write_rail_local(state)?;
    let body = body.into_inner();
    if !verify_federation_origin(body.origin.as_str()) {
        return Err(AppError::unauthenticated(
            "federation origin must be a valid DID",
        ));
    }
    if crate::security::federation_origin_denied(body.origin.as_str()) {
        return Err(AppError::capability_denied(
            "federation origin is denied by deployment peer policy",
        ));
    }
    if !federation_destination_matches(state, body.destination.as_str()) {
        return Err(AppError::capability_denied(
            "federation push destination does not match this service",
        ));
    }
    verify_inbound_push_http_signature(state, req, &body).await?;
    let origin = body.origin.to_string();
    let operations = body.operations;
    enforce_inbound_operation_batch_policy(state, &origin, &operations).await?;
    let ingest = ingest_federation_operations(state, &origin, operations).await;
    json_ok(cokret_sdk::FederationPushOperationsOutcome {
        accepted: ingest.accepted,
        rejected: ingest.rejected,
        quarantine: Vec::new(),
    })
}

#[endpoint(
    operation_id = "org.cokret.soland.federation.actor_events",
    tags("federation"),
    summary = "Debug/read model: list projection events for a federated actor"
)]
#[tracing::instrument(skip_all, fields(op = "org.cokret.soland.federation.actor_events"))]
pub(crate) async fn federation_actor_events(
    actor_id: PathParam<String>,
    depot: &mut Depot,
) -> JsonResult<FederationActorEventsOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    ensure_private_inbound_read_rail_local(state)?;
    let actor = actor_id.into_inner();
    if Did::new(actor.clone()).is_err() {
        return Err(AppError::invalid_param("invalid actor_id"));
    }
    // SOL-SEC-04 — bound the table load so this (development-mode) debug read
    // cannot full-scan an arbitrarily large projection table into memory.
    const FEDERATION_ACTOR_EVENTS_SCAN_CAP: usize = 10_000;
    let mut events = state
        .persistence
        .projection_events()
        .snapshot_capped(FEDERATION_ACTOR_EVENTS_SCAN_CAP)
        .await
        .unwrap_or_default()
        .into_iter()
        .filter(|event| projection_event_matches_actor(event, &actor))
        .collect::<Vec<_>>();
    events.sort_by(|left, right| {
        left.created_at
            .cmp(&right.created_at)
            .then_with(|| left.event_id.cmp(&right.event_id))
    });

    let erasure_receipts = {
        let projection = state.projection.lock();
        for event in &mut events {
            crate::routing::events::projection::tombstone_projection_event_for_erased_actor(
                &projection,
                event,
            );
        }
        projection
            .erasure_receipts
            .iter()
            .filter(|receipt| receipt.subject_ref.as_deref() == Some(actor.as_str()))
            .map(|receipt| receipt.payload.clone())
            .collect::<Vec<_>>()
    };
    let events = events
        .iter()
        .map(crate::routing::events::projection::projection_event_json)
        .collect::<Vec<_>>();
    json_ok(FederationActorEventsOutcome {
        actor,
        events,
        erasure_receipts,
    })
}

fn projection_event_matches_actor(
    event: &crate::state::ProjectionEventRecord,
    actor: &str,
) -> bool {
    crate::routing::events::projection::projection_event_actor(event) == Some(actor)
        || event
            .payload
            .get("subject")
            .and_then(Value::as_object)
            .and_then(|subject| subject.get("ref"))
            .and_then(Value::as_str)
            == Some(actor)
}

#[endpoint(
    operation_id = "org.cokret.soland.federation.pull_operations",
    tags("federation"),
    summary = "Pull a page of operations for a federated Realm, with optional snapshot bootstrap"
)]
#[tracing::instrument(skip_all, fields(op = "org.cokret.soland.federation.pull_operations"))]
pub(crate) async fn federation_pull_operations(
    realm_id: QueryParam<String, true>,
    after_cursor: QueryParam<String, false>,
    limit: QueryParam<usize, false>,
    snapshot_bootstrap: QueryParam<bool, false>,
    depot: &mut Depot,
) -> JsonResult<cokret_sdk::FederationPullOperationsOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    ensure_private_inbound_read_rail_local(state)?;
    let realm_id = realm_id.into_inner();
    if cokret_sdk::RealmId::new(realm_id.clone()).is_err() {
        return Err(AppError::invalid_param("invalid realm_id"));
    }
    let realm_id_typed =
        cokret_sdk::RealmId::new(realm_id.clone()).expect("realm_id was validated");
    let after_cursor: Option<String> = after_cursor.into_inner();
    let limit = limit.into_inner().unwrap_or(100).min(100);
    let want_snapshot_bootstrap = snapshot_bootstrap.into_inner().unwrap_or(false);
    let realm_operations = state
        .persistence
        .federation_operations()
        .list_for_realm(&realm_id)
        .await
        .unwrap_or_default();
    let redacted = redaction_targets_from_operations(&realm_operations);
    let snapshot_bootstrap = want_snapshot_bootstrap.then(|| {
        let snapshot_join_candidate = crate::notary::ensure_realm_seal_head(state, &realm_id_typed)
            .ok()
            .flatten()
            .map(|seal| {
                json!({
                    "realm_id": realm_id.clone(),
                    "service_did": state.config.service_did.clone(),
                    "service_type": "principal_server",
                    "role": "primary",
                    "endpoint": state.config.public_base_url.clone(),
                    "operations": ["ck.self.events.command.submit"],
                    "join_methods": ["invite_accept", "member_join", "knock", "application"],
                    "priority": 0,
                    "source": "directory_ingest",
                    "seal_basis": {
                        "leaves": [seal.id],
                        "control_event_set_root": seal.control_event_set_root,
                        "state_root": seal.state_root,
                    },
                    "as_of": now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
                    "expires_at": (now() + Duration::minutes(10)).to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
                })
            });
        let manifest = json!({
            "type": "snapshot_bootstrap",
            "realm_id": realm_id,
            "id": ids::generate_snapshot_id(),
            "operation_count": realm_operations.len(),
            "created_at": now(),
        });
        let state_digest = cokret_sdk::canonical::sha256_digest(manifest.to_string().as_bytes());
        json!({
            "manifest": manifest,
            "state_digest": state_digest,
            "chunks": [],
            "join_candidates": snapshot_join_candidate.into_iter().collect::<Vec<_>>(),
        })
    });
    let mut seen_cursor = after_cursor.is_none();
    let mut operations = Vec::new();
    for operation in realm_operations {
        if !seen_cursor {
            seen_cursor = Some(operation.operation_id.as_str()) == after_cursor.as_deref();
            continue;
        }
        if !operation_is_visible(&operation, &redacted) {
            continue;
        }
        if !operation_history_visible_for_federation_pull(state, &operation).await {
            continue;
        }
        if operations.len() == limit + 1 {
            break;
        }
        operations.push(operation);
    }
    let has_more = operations.len() > limit;
    if has_more {
        operations.truncate(limit);
    }
    let next_cursor = match operations
        .last()
        .map(|operation| operation.operation_id.to_string())
    {
        Some(next_cursor) => Some(next_cursor),
        None => Some(sync_token(state).await),
    };
    json_ok(cokret_sdk::FederationPullOperationsOutcome {
        operations,
        snapshot_bootstrap,
        next_cursor,
        has_more,
    })
}

#[endpoint(
    operation_id = "org.cokret.soland.federation.backfill_operations",
    tags("federation"),
    summary = "Pull missing operations from a configured federation peer and ingest them locally"
)]
#[tracing::instrument(
    skip_all,
    fields(op = "org.cokret.soland.federation.backfill_operations")
)]
pub(crate) async fn federation_backfill_operations(
    body: JsonBody<FederationBackfillOperationsRequestBody>,
    depot: &mut Depot,
) -> JsonResult<FederationBackfillOperationsOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    ensure_private_inbound_write_rail_local(state)?;
    let body = body.into_inner();
    let realm_id = body.realm_id.trim().to_owned();
    if realm_id.is_empty() {
        return Err(AppError::missing_param("realm_id is required"));
    }
    if cokret_sdk::RealmId::new(realm_id.clone()).is_err() {
        return Err(AppError::invalid_param("invalid realm_id"));
    }
    let body_value = serde_json::to_value(&body)
        .map_err(|error| AppError::internal(format!("backfill request serialize: {error}")))?;
    let peer = configured_peer_from_backfill_body(state, &body_value)?;
    let limit = body.limit.unwrap_or(100).clamp(1, 100) as usize;
    let max_pages = body.max_pages.unwrap_or(16).clamp(1, 64) as usize;
    let mut after_cursor = body.after_cursor;
    let frontier_before = operation_frontier_outcome(state, &realm_id).await;
    let mut accepted = Vec::new();
    let mut rejected = Vec::new();
    let mut pulled = 0usize;
    let mut pages = 0usize;
    let mut peer_next_cursor = None;
    let mut peer_has_more = false;
    for _ in 0..max_pages {
        pages += 1;
        let page =
            pull_operations_page(state, &peer, &realm_id, after_cursor.as_deref(), limit).await?;
        pulled += page.operations.len();
        peer_next_cursor = page.next_cursor.clone();
        peer_has_more = page.has_more;
        let mut visible_operations = Vec::new();
        for operation in page.operations {
            if operation_history_visible_for_federation_pull(state, &operation).await {
                visible_operations.push(operation);
            } else {
                rejected.push(json!({
                    "operation_id": operation.operation_id,
                    "code": "history_not_visible",
                    "message": "operation hidden by history_visibility",
                }));
            }
        }
        let result =
            ingest_federation_operations(state, peer.did.as_str(), visible_operations).await;
        accepted.extend(
            result
                .accepted
                .into_iter()
                .map(|operation_id| operation_id.to_string()),
        );
        rejected.extend(result.rejected);
        after_cursor = peer_next_cursor.clone();
        if !peer_has_more {
            break;
        }
    }
    let frontier_after = operation_frontier_outcome(state, &realm_id).await;
    json_ok(FederationBackfillOperationsOutcome {
        peer_url: peer.url,
        peer_did: peer.did,
        realm_id,
        pulled,
        accepted,
        rejected,
        pages,
        next_cursor: peer_next_cursor,
        has_more: peer_has_more,
        frontier_before,
        frontier_after,
    })
}

async fn operation_history_visible_for_federation_pull(
    state: &AppState,
    operation: &cokret_sdk::Operation,
) -> bool {
    state
        .persistence
        .realm_meta()
        .get(operation.realm_id.as_str())
        .await
        .ok()
        .flatten()
        .map(|meta| {
            matches!(
                meta.history_visibility.as_str(),
                "world_readable" | "shared"
            )
        })
        .unwrap_or(false)
}

#[endpoint(
    operation_id = "org.cokret.soland.federation.operation_frontier",
    tags("federation"),
    summary = "Return the operation frontier used by federation pull/backfill convergence checks"
)]
#[tracing::instrument(
    skip_all,
    fields(op = "org.cokret.soland.federation.operation_frontier")
)]
pub(crate) async fn federation_operation_frontier(
    realm_id: QueryParam<String, true>,
    depot: &mut Depot,
) -> JsonResult<FederationOperationFrontierOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    ensure_private_inbound_read_rail_local(state)?;
    let realm_id = realm_id.into_inner();
    if cokret_sdk::RealmId::new(realm_id.clone()).is_err() {
        return Err(AppError::invalid_param("invalid realm_id"));
    }
    json_ok(operation_frontier_outcome(state, &realm_id).await)
}

#[endpoint(
    operation_id = "org.cokret.soland.federation.realm_members",
    tags("federation"),
    summary = "List Realm memberships for a federated Realm"
)]
#[tracing::instrument(skip_all, fields(op = "org.cokret.soland.federation.realm_members"))]
pub(crate) async fn federation_realm_members(
    realm_id: QueryParam<String, true>,
    depot: &mut Depot,
) -> JsonResult<cokret_sdk::FederationRealmMemberList> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    ensure_private_inbound_read_rail_local(state)?;
    let realm_id_value = RealmId::new(realm_id.into_inner())
        .map_err(|_| AppError::invalid_param("invalid realm_id"))?;
    let members = state
        .realms
        .lock()
        .get(&realm_id_value)
        .map(|realm| {
            realm
                .members
                .iter()
                .map(|principal_id| cokret_sdk::MemberRef {
                    principal_id: principal_id.clone(),
                    membership: json!({"membership": "join"}),
                })
                .collect()
        })
        .unwrap_or_default();
    json_ok(cokret_sdk::FederationRealmMemberList {
        members,
        membership_frontier: sync_token(state).await,
        next_cursor: None,
    })
}

#[endpoint(
    operation_id = "org.cokret.soland.federation.verify_actor",
    tags("federation"),
    summary = "Verify a federated actor's signature against the local DID resolver"
)]
#[tracing::instrument(skip_all, fields(op = "org.cokret.soland.federation.verify_actor"))]
pub(crate) async fn federation_verify_actor(
    body: JsonBody<cokret_sdk::FederationVerifyActorRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<cokret_sdk::FederationVerifyActorOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let body = body.into_inner();
    let request_hash = federation_verify_actor_digest(&body).map_err(|message| {
        AppError::new(crate::error::ErrorCode::SchemaViolation, message)
            .with_status(StatusCode::BAD_REQUEST)
    })?;
    validate_federation_request_binding(&state.config.trust_domain, req, &request_hash)?;

    if state.config.development_mode {
        // SOL-SEC-02 — even in development_mode the actor signature is NOT
        // verified here, so the outcome MUST NOT report `valid: true`. A
        // misconfigured production deployment with development_mode=true would
        // otherwise unconditionally accept any peer's actor verification
        // request. Fail closed: report `valid: false` and explain that the
        // signature was skipped, rather than asserting a verification that did
        // not happen.
        return json_ok(cokret_sdk::FederationVerifyActorOutcome {
            valid: false,
            actor_id: body.actor_id.clone(),
            verified_key_id: None,
            key_log_head: None,
            did_document_ref: Some(format!("{}#document", body.actor_id)),
            expires_at: Some(now() + Duration::minutes(5)),
            warnings: vec![
                "development_mode skipped actor signature verification; valid=false because no \
                 signature was checked"
                    .to_owned(),
            ],
        });
    }

    let unsigned_request_digest =
        federation_verify_actor_unsigned_digest(&body).map_err(|message| {
            AppError::new(crate::error::ErrorCode::SchemaViolation, message)
                .with_status(StatusCode::BAD_REQUEST)
        })?;
    let verification =
        verify_federation_actor_signature(state, &body, &unsigned_request_digest).await?;

    json_ok(cokret_sdk::FederationVerifyActorOutcome {
        valid: true,
        actor_id: body.actor_id.clone(),
        verified_key_id: Some(verification.verified_key_id),
        key_log_head: Some(verification.key_log_head),
        did_document_ref: Some(verification.did_document_ref),
        expires_at: Some(now() + Duration::minutes(5)),
        warnings: Vec::new(),
    })
}

// ── Seal pull/push (federation/seals) ──────────────

#[derive(Clone, Debug, Default, Serialize, Deserialize, salvo::oapi::ToSchema)]
pub struct FederationSealsOutcome {
    pub seals: Vec<cokret_sdk::Seal>,
    /// Echo of [`crate::config::FederationFanoutTopology::as_str`] so the calling
    /// peer can reason about whether to fan out to other nodes.
    pub fanout_topology: String,
    pub next_cursor: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, salvo::oapi::ToSchema)]
pub struct FederationSealsPushRequestBody {
    pub origin: String,
    pub seals: Vec<cokret_sdk::Seal>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, salvo::oapi::ToSchema)]
pub struct FederationSealsPushOutcome {
    pub accepted: Vec<String>,
    pub rejected: Vec<serde_json::Value>,
}

#[endpoint(
    operation_id = "org.cokret.soland.federation.seals.pull",
    tags("federation"),
    summary = "Pull locally-held Seals for a Realm (federation peer-pull)"
)]
#[tracing::instrument(skip_all, fields(op = "org.cokret.soland.federation.seals.pull"))]
pub(crate) async fn federation_seals_pull(
    depot: &mut Depot,
    realm_id: QueryParam<String, true>,
) -> JsonResult<FederationSealsOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    ensure_private_inbound_read_rail_local(state)?;
    let realm_id = realm_id.into_inner();
    if cokret_sdk::RealmId::new(realm_id.clone()).is_err() {
        return Err(AppError::invalid_param("invalid realm_id"));
    }
    let realm = RealmId::new(realm_id).map_err(|_| AppError::invalid_param("invalid realm_id"))?;
    let leaves = state.seal_store.list_leaves(&realm).unwrap_or_default();
    let mut seals: Vec<cokret_sdk::Seal> = Vec::with_capacity(leaves.len());
    for leaf in &leaves {
        if let Ok(Some(a)) = state.seal_store.get(leaf) {
            seals.push(a);
        }
    }
    json_ok(FederationSealsOutcome {
        seals,
        fanout_topology: state
            .settings()
            .federation_fanout_topology
            .as_str()
            .to_owned(),
        next_cursor: None,
    })
}

#[endpoint(
    operation_id = "org.cokret.soland.federation.seals.push",
    tags("federation"),
    summary = "Accept Seal envelopes from a federation peer (peer-push)"
)]
#[tracing::instrument(skip_all, fields(op = "org.cokret.soland.federation.seals.push"))]
pub(crate) async fn federation_seals_push(
    req: &mut Request,
    depot: &mut Depot,
    body: JsonBody<FederationSealsPushRequestBody>,
) -> JsonResult<FederationSealsPushOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    ensure_private_inbound_write_rail_local(state)?;
    let body = body.into_inner();
    if !verify_federation_origin(&body.origin) {
        return Err(AppError::new(
            crate::error::ErrorCode::Unauthenticated,
            "federation origin must be a valid DID",
        )
        .with_status(StatusCode::UNAUTHORIZED));
    }
    // SOL-SEC-02 (federation.md §1 / §3.2) — a self-consistent `derive_id`
    // check is NOT source authenticity: without these gates any reachable
    // caller could push arbitrary id-consistent Seals into `seal_store`. Bring
    // this push surface up to the protocol rail's strength:
    //   1. enforce the local origin deny policy, then
    //   2. verify the inbound RFC 9421 HTTP Message Signature (binds origin / destination trust
    //      headers + the canonical body digest), exactly like `/_cokret/peer/*` and the sibling
    //      `federation_push_operations`.
    if crate::security::federation_origin_denied(body.origin.as_str()) {
        return Err(AppError::capability_denied(
            "federation seals push origin is denied by local peer policy",
        )
        .with_wire_code("federation_origin_denied"));
    }
    let body_value = serde_json::to_value(&body).map_err(|error| {
        AppError::internal(format!("federation seals push body serialize: {error}"))
    })?;
    super::verify_inbound_peer_http_signature(state, req, Some(&body_value)).await?;
    //   3. bind every Move the Seal encapsulates (its `delta` entries) to the authenticated origin,
    //      exactly like the sibling `federation_transaction` / `federation_push_operations` tracks
    //      run `federation_actor_origin_acceptable` per operation. A signed peer MUST NOT be able
    //      to push Seals covering Moves authored in a trust domain it does not speak for.
    let origin_trust_domain = super::signature::trust_domain_from_service_did(&body.origin);
    let mut accepted: Vec<String> = Vec::new();
    let mut rejected: Vec<serde_json::Value> = Vec::new();
    'seals: for seal in body.seals {
        let id_str = seal.id.to_string();
        // Only accept Seals whose declared id matches the canonical hash
        // — otherwise a peer could overwrite our DAG with junk.
        match seal.derive_id() {
            Ok(derived) if derived == seal.id => {}
            _ => {
                rejected.push(json!({"id": id_str, "reason": "id_mismatch"}));
                continue;
            }
        }
        for move_id in &seal.delta {
            let Ok(Some(enclosed_move)) = state.move_store.get(move_id) else {
                // A Move we cannot resolve locally has no attributable
                // author; accepting the Seal would smuggle unattributed
                // writes into the DAG, so fail closed.
                rejected.push(json!({
                    "id": id_str,
                    "reason": "missing_move",
                    "move_id": move_id.as_str(),
                }));
                continue 'seals;
            };
            if !super::inbound_policy::federation_actor_origin_acceptable(
                state,
                enclosed_move.issuer.as_str(),
                &origin_trust_domain,
                seal.realm_id.as_str(),
            )
            .await
            {
                rejected.push(json!({
                    "id": id_str,
                    "reason": "federation_actor_origin_rejected",
                    "move_id": move_id.as_str(),
                }));
                continue 'seals;
            }
        }
        if let Err(error) = state.seal_store.put(&seal) {
            rejected.push(
                json!({"id": id_str, "reason": "persistence_error", "message": error.to_string()}),
            );
            continue;
        }
        accepted.push(id_str);
    }
    json_ok(FederationSealsPushOutcome { accepted, rejected })
}
