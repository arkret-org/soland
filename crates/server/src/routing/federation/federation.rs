//! Internal federation helpers.
//!
//! The formal server-to-server HTTP surface is `/_cokret/peer/*`. This module keeps
//! trust-header utilities and local migration helpers that are not mounted as peer routes.
//!
//! Production gaps: `validation_class` instead of bool, reducer-profile
//! digest enforcement, revocation fanout, and a long-running retry daemon.
//! Outbound Move/Seal broadcast helpers persist a per-peer signed request
//! transcript plus retry/durability metadata before returning targets so cotest
//! can observe the durable boundary instead of a purely opaque log.

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use chrono::{DateTime, Duration, Utc};
use cokret_sdk::state_res::SealStore;
use cokret_sdk::{Did, Operation, RealmId, Seal};
use ed25519_dalek::{Signature, Signer as _, SigningKey, Verifier as _, VerifyingKey};
use salvo::http::StatusCode;
use salvo::oapi::extract::{JsonBody, PathParam, QueryParam};
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::{
    ingest_federation_operations, now, operation_is_visible, redaction_targets_from_operations,
    sha256_hex, sync_token, validate_did,
};
use crate::error::AppError;
use crate::ids;
#[cfg(test)]
use crate::kinds;
use crate::result::{JsonResult, json_ok};
use crate::routing::policy_gate::{self, PolicyGateSurface};
use crate::state::{AppState, FederationTransactionRecord};

const MAX_INBOUND_FEDERATION_OPERATIONS: usize = 500;

/// SPEC-CR-008 (federation.md §4.0) — the cross-deployment federation Event
/// receive rail is converged onto a single track: `POST /_cokret/peer/events`
/// (`ck.peer.events.command.submit`). The `/_soland/peer/*` inbound
/// *write* surface (transactions, operations push/backfill, seals push) is a
/// deployment-local test/ops rail only and MUST NOT serve as a cross-vendor
/// interop entry point: it MUST NOT accept Move/Anchor/Operation pushes from a
/// remote federation peer.
///
/// This guard fail-closes those write tracks outside deployment-local mode so
/// the only inbound interop posture is the protocol track. Read-only debug
/// tracks (pull/frontier/realm-members/actor-events/seals-pull) are not gated:
/// they expose no interop write surface. When the rail is disabled the error
/// points callers at the canonical receive track.
pub(super) fn ensure_private_inbound_write_rail_local(state: &AppState) -> Result<(), AppError> {
    if state.config.development_mode {
        return Ok(());
    }
    Err(AppError::unsupported_feature(
        "the /_soland/peer/* inbound write rail is a deployment-local test/ops affordance and is \
         not a cross-deployment federation interop entry point; submit sealed Event Envelopes to \
         the protocol track POST /_cokret/peer/events (ck.peer.events.command.submit) instead",
    )
    .with_wire_code("federation_interop_track_only"))
}

/// Placeholder status stamped by `try_begin` while an inbound federation
/// transaction is being ingested. A row in this state means some worker
/// claimed the `(origin, txn_id)` idempotency slot but has not yet written
/// the final response.
const FEDERATION_TXN_STATUS_PROCESSING: &str = "processing";

/// How long a `processing` placeholder is honoured before a retry may take
/// the slot over. A claim older than this means the claiming worker crashed
/// between `try_begin` and the finalising `put` (the ingest path itself is
/// non-blocking), so the transaction would otherwise be stuck returning
/// `temporarily_unavailable` forever.
const FEDERATION_TXN_PROCESSING_TAKEOVER_SECS: i64 = 60;

#[derive(Clone, Debug, PartialEq, Eq)]
struct FederationPeerTarget {
    url: String,
    did: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, salvo::oapi::ToSchema)]
pub(super) struct FederationActorEventsOutcome {
    actor: String,
    events: Vec<Value>,
    erasure_receipts: Vec<Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize, salvo::oapi::ToSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct FederationBackfillOperationsRequestBody {
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
pub(super) struct FederationOperationFrontierOutcome {
    realm_id: String,
    operation_count: usize,
    operation_ids: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    latest_operation_id: Option<String>,
    frontier_digest: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, salvo::oapi::ToSchema)]
pub(super) struct FederationBackfillOperationsOutcome {
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
pub(super) async fn federation_transaction(
    txn_id: PathParam<String>,
    body: JsonBody<cokret_sdk::FederationTransactionRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<cokret_sdk::FederationTransactionOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
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
    verify_inbound_transaction_http_signature(state, req, &body)?;
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
    let idem_key = Some(FederationIdempotencyKey {
        source_did: body.origin.to_string(),
        dest_did: body.destination.to_string(),
        request_canonical_digest: trust_headers.request_canonical_digest.as_str().to_owned(),
        idempotency_key: txn_id.clone(),
        origin_key_state_digest,
    });
    let _service_binding = FederationIdempotencyServiceBinding {
        source_service_did: body.origin.to_string(),
        verification_method: idem_key
            .as_ref()
            .expect("federation idempotency key")
            .strict(),
        service_binding_ref: idem_key
            .as_ref()
            .expect("federation idempotency key")
            .canonical_replay(),
        origin_key_state_digest: idem_key
            .as_ref()
            .expect("federation idempotency key")
            .origin_key_state_digest
            .clone(),
    };
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
        Ok(Some(record)) if record.status == FEDERATION_TXN_STATUS_PROCESSING => {
            if record.content_digest != content_digest {
                return Err(AppError::new(
                    crate::error::ErrorCode::DuplicateConflict,
                    "federation transaction id was reused with different content",
                ));
            }
            let claim_age_secs = now()
                .signed_duration_since(record.received_at)
                .num_seconds();
            if claim_age_secs < FEDERATION_TXN_PROCESSING_TAKEOVER_SECS {
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
            // Round 4 (B1.8) — detect a canonical-replay hit (txn_id +
            // request_canonical_digest match, but origin_key_state_digest
            // has rotated since the cached entry was minted). Such a
            // hit MUST be marked `reason_code=historical_only` and
            // MUST NOT trigger fresh side effects. We approximate the
            // detection here by checking whether the `record.status`
            // already names the cached origin's key generation —
            // soland doesn't yet persist `origin_key_state_digest` on
            // the federation_transactions row, so for now we only
            // mark when the headers carry an explicit `historical_only`
            // hint. TODO(federation-historical-key-rotation): persist the
            // origin's key state hash on the cached record so a real
            // rotation triggers historical_only automatically.
            let mut response_value = record.response.clone();
            let request_signals_historical = req
                .headers()
                .get("X-Cokret-Origin-Key-Rotated")
                .and_then(|v| v.to_str().ok())
                .map(|s| matches!(s, "true" | "1" | "yes"))
                .unwrap_or(false);
            if request_signals_historical {
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
            status: FEDERATION_TXN_STATUS_PROCESSING.to_owned(),
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

#[endpoint(
    operation_id = "org.cokret.soland.federation.push_operations",
    tags("federation"),
    summary = "Accept a batch of operations pushed from a peer service"
)]
#[tracing::instrument(skip_all, fields(op = "org.cokret.soland.federation.push_operations"))]
pub(super) async fn federation_push_operations(
    body: JsonBody<cokret_sdk::FederationPushOperationsRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<cokret_sdk::FederationPushOperationsOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
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
    verify_inbound_push_http_signature(state, req, &body)?;
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
pub(super) async fn federation_actor_events(
    actor_id: PathParam<String>,
    depot: &mut Depot,
) -> JsonResult<FederationActorEventsOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let actor = actor_id.into_inner();
    if Did::new(actor.clone()).is_err() {
        return Err(AppError::invalid_param("invalid actor_id"));
    }
    let mut events = state
        .persistence
        .projection_events()
        .snapshot_all()
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

    let erasure_receipts = if let Ok(projection) = state.projection.lock() {
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
    } else {
        Vec::new()
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

async fn enforce_inbound_operation_batch_policy(
    state: &AppState,
    origin_service_did: &str,
    operations: &[Operation],
) -> Result<(), AppError> {
    if operations.len() > MAX_INBOUND_FEDERATION_OPERATIONS {
        return Err(AppError::new(
            crate::error::ErrorCode::PayloadTooLarge,
            format!(
                "federation operation batch exceeds limit: {} > {}",
                operations.len(),
                MAX_INBOUND_FEDERATION_OPERATIONS
            ),
        )
        .with_status(StatusCode::PAYLOAD_TOO_LARGE)
        .with_wire_code("payload_too_large"));
    }
    for operation in operations {
        enforce_realm_federation_policy(
            state,
            operation.realm_id.as_str(),
            origin_service_did,
            None,
            FederationDirection::Inbound,
        )?;
        enforce_realm_moderation_federation_policy(
            state,
            operation.realm_id.as_str(),
            origin_service_did,
            None,
            FederationDirection::Inbound,
        )?;
        policy_gate::enforce_operation_policy_server(
            state,
            operation_actor_id(operation).unwrap_or(origin_service_did),
            operation,
            PolicyGateSurface::FederationInbound {
                origin_service_did: origin_service_did.to_owned(),
            },
        )
        .await
        .map_err(app_error_from_policy_gate)?;
    }
    Ok(())
}

fn app_error_from_policy_gate(rejection: policy_gate::PolicyGateRejection) -> AppError {
    AppError::new(crate::error::ErrorCode::CapabilityDenied, rejection.message)
        .with_status(rejection.status)
        .with_wire_code(rejection.code)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FederationDirection {
    Inbound,
    Outbound,
}

fn enforce_realm_federation_policy(
    state: &AppState,
    realm_id: &str,
    peer_did: &str,
    peer_url: Option<&str>,
    direction: FederationDirection,
) -> Result<(), AppError> {
    let policy = state
        .projection
        .lock()
        .map_err(|error| AppError::internal(format!("projection lock: {error}")))?
        .realm_federation_policy(realm_id)
        .unwrap_or_else(|| "open".to_owned());
    match policy.as_str() {
        "open" | "mesh" | "hub" => Ok(()),
        "closed" | "disabled" => Err(AppError::capability_denied(
            "realm federation_policy forbids federation",
        )
        .with_wire_code("realm_federation_policy_closed")),
        "quarantine" => Err(AppError::capability_denied(
            "realm federation_policy is quarantine; live federation is blocked",
        )
        .with_wire_code("realm_federation_policy_quarantine")),
        "restricted" => {
            if direction == FederationDirection::Outbound
                || configured_peer_matches(state, peer_did, peer_url)
            {
                Ok(())
            } else {
                Err(AppError::capability_denied(
                    "realm federation_policy=restricted requires a configured peer",
                )
                .with_wire_code("realm_federation_policy_restricted"))
            }
        }
        _ => Err(
            AppError::capability_denied("realm federation_policy has an unsupported value")
                .with_wire_code("realm_federation_policy_invalid"),
        ),
    }
}

fn enforce_realm_moderation_federation_policy(
    state: &AppState,
    realm_id: &str,
    peer_did: &str,
    peer_url: Option<&str>,
    direction: FederationDirection,
) -> Result<(), AppError> {
    let record = state
        .realm_moderation_policies
        .lock()
        .expect("realm moderation policies lock")
        .get(realm_id)
        .cloned();
    let Some(record) = record else {
        return Ok(());
    };
    if let Some(reason) =
        moderation_policy_denies_federation(&record.payload, peer_did, peer_url, direction)
    {
        return Err(
            AppError::capability_denied(reason).with_wire_code("realm_moderation_policy_denied")
        );
    }
    Ok(())
}

fn moderation_policy_denies_federation(
    policy: &Value,
    peer_did: &str,
    peer_url: Option<&str>,
    direction: FederationDirection,
) -> Option<String> {
    let allowlist_enforced = ["allowlist_enforced", "federation_allowlist_enforced"]
        .iter()
        .any(|key| policy.get(key).and_then(Value::as_bool) == Some(true));
    let mut explicitly_allowed = false;

    for key in ["rules", "targets", "server_targets", "federation_targets"] {
        let Some(entries) = policy.get(key).and_then(Value::as_array) else {
            continue;
        };
        for entry in entries {
            if !moderation_target_matches_peer(entry, peer_did, peer_url) {
                continue;
            }
            let action = moderation_action(entry);
            if moderation_action_allows_federation(action, direction) {
                explicitly_allowed = true;
            }
            if moderation_action_denies_federation(action, direction) {
                return Some(format!(
                    "realm moderation policy blocks federation peer {peer_did}"
                ));
            }
        }
    }

    if allowlist_enforced && !explicitly_allowed {
        return Some(format!(
            "realm moderation policy allowlist does not include federation peer {peer_did}"
        ));
    }
    None
}

fn moderation_action(entry: &Value) -> &str {
    entry
        .get("action")
        .or_else(|| entry.get("effect"))
        .or_else(|| entry.get("polarity"))
        .or_else(|| entry.get("mode"))
        .and_then(Value::as_str)
        .unwrap_or_default()
}

fn moderation_action_denies_federation(action: &str, direction: FederationDirection) -> bool {
    matches!(
        action,
        "deny" | "block" | "defederate" | "deny_federation" | "block_federation"
    ) || matches!(
        (direction, action),
        (
            FederationDirection::Inbound,
            "deny_inbound" | "block_inbound"
        ) | (
            FederationDirection::Outbound,
            "deny_outbound" | "block_outbound"
        )
    )
}

fn moderation_action_allows_federation(action: &str, direction: FederationDirection) -> bool {
    matches!(
        action,
        "allow" | "allow_federation" | "allow_peer" | "allow_server"
    ) || matches!(
        (direction, action),
        (FederationDirection::Inbound, "allow_inbound")
            | (FederationDirection::Outbound, "allow_outbound")
    )
}

fn moderation_target_matches_peer(entry: &Value, peer_did: &str, peer_url: Option<&str>) -> bool {
    let target = entry.get("target").unwrap_or(entry);
    let kind = target
        .get("kind")
        .or_else(|| entry.get("kind"))
        .and_then(Value::as_str)
        .unwrap_or_default();
    let server_kind = matches!(
        kind,
        "server" | "service" | "service_did" | "peer" | "federation_peer" | "federation_server"
    );
    let did_matches = ["did", "service_did", "server_did", "peer_did", "target_did"]
        .iter()
        .filter_map(|key| target.get(*key).or_else(|| entry.get(*key)))
        .any(|value| value.as_str() == Some(peer_did));
    let string_target_matches = target.as_str() == Some(peer_did);
    let url_matches = peer_url.is_some_and(|peer_url| {
        ["url", "base_url", "peer_url", "server_url"]
            .iter()
            .filter_map(|key| target.get(*key).or_else(|| entry.get(*key)))
            .any(|value| value.as_str() == Some(peer_url))
    });
    server_kind && (did_matches || string_target_matches || url_matches)
}

fn configured_peer_matches(state: &AppState, peer_did: &str, peer_url: Option<&str>) -> bool {
    state
        .config
        .federation_peers
        .iter()
        .filter_map(|entry| parse_peer_target(entry))
        .any(|peer| {
            peer.did == peer_did
                || peer_url
                    .is_some_and(|url| peer.url.trim_end_matches('/') == url.trim_end_matches('/'))
        })
}

fn operation_actor_id(operation: &Operation) -> Option<&str> {
    [
        "sender",
        "actor",
        "actor_id",
        "member",
        "subject",
        "created_by",
        "updated_by",
    ]
    .iter()
    .find_map(|field| operation.payload.get(*field).and_then(Value::as_str))
    .filter(|did| validate_did(did).is_ok())
}

#[endpoint(
    operation_id = "org.cokret.soland.federation.pull_operations",
    tags("federation"),
    summary = "Pull a page of operations for a federated Realm, with optional snapshot bootstrap"
)]
#[tracing::instrument(skip_all, fields(op = "org.cokret.soland.federation.pull_operations"))]
pub(super) async fn federation_pull_operations(
    realm_id: QueryParam<String, true>,
    after_cursor: QueryParam<String, false>,
    limit: QueryParam<usize, false>,
    snapshot_bootstrap: QueryParam<bool, false>,
    depot: &mut Depot,
) -> JsonResult<cokret_sdk::FederationPullOperationsOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let realm_id = realm_id.into_inner();
    if cokret_sdk::RealmId::new(realm_id.clone()).is_err() {
        return Err(AppError::invalid_param("invalid realm_id"));
    }
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
            "join_candidates": [{
                "realm_id": realm_id,
                "service_did": state.config.service_did.clone(),
                "service_type": "principal_server",
                "role": "primary",
                "endpoint": state.config.public_base_url.clone(),
                "operations": ["ck.self.events.command.submit"],
                "join_methods": ["invite_accept", "member_join", "knock", "application"],
                "priority": 0,
                "source": "directory_ingest",
                "as_of": now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
                "expires_at": (now() + Duration::minutes(10)).to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            }],
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
pub(super) async fn federation_backfill_operations(
    body: JsonBody<FederationBackfillOperationsRequestBody>,
    depot: &mut Depot,
) -> JsonResult<FederationBackfillOperationsOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
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
        let result = ingest_federation_operations(state, peer.did.as_str(), page.operations).await;
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

#[endpoint(
    operation_id = "org.cokret.soland.federation.operation_frontier",
    tags("federation"),
    summary = "Return the operation frontier used by federation pull/backfill convergence checks"
)]
#[tracing::instrument(
    skip_all,
    fields(op = "org.cokret.soland.federation.operation_frontier")
)]
pub(super) async fn federation_operation_frontier(
    realm_id: QueryParam<String, true>,
    depot: &mut Depot,
) -> JsonResult<FederationOperationFrontierOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
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
pub(super) async fn federation_realm_members(
    realm_id: QueryParam<String, true>,
    depot: &mut Depot,
) -> JsonResult<cokret_sdk::FederationRealmMemberList> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let realm_id_value = RealmId::new(realm_id.into_inner())
        .map_err(|_| AppError::invalid_param("invalid realm_id"))?;
    let members = state
        .realms
        .lock()
        .expect("realms lock")
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
pub(super) async fn federation_verify_actor(
    body: JsonBody<cokret_sdk::FederationVerifyActorRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<cokret_sdk::FederationVerifyActorOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let body = body.into_inner();
    let request_hash = federation_verify_actor_digest(&body).map_err(|message| {
        AppError::new(crate::error::ErrorCode::SchemaViolation, message)
            .with_status(StatusCode::BAD_REQUEST)
    })?;
    validate_federation_request_binding(&state.config.trust_domain, req, &request_hash)?;

    if state.config.development_mode {
        return json_ok(cokret_sdk::FederationVerifyActorOutcome {
            valid: true,
            actor_id: body.actor_id.clone(),
            verified_key_id: None,
            key_log_head: None,
            did_document_ref: Some(format!("{}#document", body.actor_id)),
            expires_at: Some(now() + Duration::minutes(5)),
            warnings: vec![
                "development_mode accepted request binding without actor signature verification"
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

fn validate_federation_request_binding(
    trust_domain: &str,
    req: &Request,
    request_hash: &str,
) -> Result<(), AppError> {
    let headers = FederationTrustHeaders::from_salvo_request(req).map_err(|violation| {
        AppError::new(
            crate::error::ErrorCode::SchemaViolation,
            violation.message(),
        )
        .with_status(StatusCode::BAD_REQUEST)
    })?;
    let expected_destination = cokret_sdk::TypedTrustDomainId::new(trust_domain.to_owned())
        .map_err(|error| AppError::internal(format!("configured trust_domain invalid: {error}")))?;
    validate_federation_headers(&headers, &expected_destination, request_hash)
}

fn validate_federation_headers(
    headers: &FederationTrustHeaders,
    expected_destination: &cokret_sdk::TypedTrustDomainId,
    request_hash: &str,
) -> Result<(), AppError> {
    headers
        .verify_destination(expected_destination)
        .map_err(|_| {
            AppError::new(
                crate::error::ErrorCode::CrossDomainReplayRejected,
                "federation Destination-Trust-Domain header does not match this service",
            )
            .with_status(StatusCode::CONFLICT)
        })?;
    if request_hash != headers.request_canonical_digest.as_str() {
        crate::metrics::record_digest_mismatch("federation_request_binding");
        return Err(AppError::new(
            crate::error::ErrorCode::CrossDomainReplayRejected,
            "Request-Canonical-Digest does not match the canonical request body",
        )
        .with_status(StatusCode::CONFLICT));
    }
    Ok(())
}

fn verify_inbound_push_http_signature(
    state: &AppState,
    req: &Request,
    body: &cokret_sdk::FederationPushOperationsRequestBody,
) -> Result<(), AppError> {
    let body_value = serde_json::to_value(body).map_err(|error| {
        AppError::internal(format!(
            "federation push body serialization failed: {error}"
        ))
    })?;
    verify_inbound_federation_http_signature(
        state,
        req,
        &body_value,
        body.origin.as_str(),
        body.destination.as_str(),
        "federation_push",
    )
}

fn verify_inbound_transaction_http_signature(
    state: &AppState,
    req: &Request,
    body: &cokret_sdk::FederationTransactionRequestBody,
) -> Result<(), AppError> {
    let body_value = serde_json::to_value(body).map_err(|error| {
        AppError::internal(format!(
            "federation transaction body serialization failed: {error}"
        ))
    })?;
    verify_inbound_federation_http_signature(
        state,
        req,
        &body_value,
        body.origin.as_str(),
        body.destination.as_str(),
        "federation_transaction",
    )
}

fn verify_inbound_federation_http_signature(
    state: &AppState,
    req: &Request,
    body_value: &Value,
    body_origin: &str,
    body_destination: &str,
    metric_label: &'static str,
) -> Result<(), AppError> {
    let body_bytes = cokret_sdk::canonical::canonical_json_bytes(body_value).map_err(|error| {
        AppError::new(
            crate::error::ErrorCode::SchemaViolation,
            format!("federation request body is not canonical JSON: {error}"),
        )
        .with_status(StatusCode::BAD_REQUEST)
    })?;
    let expected_content_digest = content_digest_header(&body_bytes);
    let expected_request_digest = cokret_sdk::canonical::sha256_digest(&body_bytes);
    validate_federation_request_binding(&state.config.trust_domain, req, &expected_request_digest)?;

    let content_digest = required_header(req, "content-digest")?;
    if content_digest != expected_content_digest {
        crate::metrics::record_digest_mismatch(&format!("{metric_label}_content_digest"));
        return Err(signature_error(
            "Content-Digest does not match federation canonical request body",
        ));
    }
    let request_digest = required_header(req, "request-canonical-digest")?;
    if request_digest != expected_request_digest {
        crate::metrics::record_digest_mismatch(&format!("{metric_label}_request_digest"));
        return Err(signature_error(
            "Request-Canonical-Digest does not match federation canonical request body",
        ));
    }

    let source_service_did = required_header(req, "source-service-did")?;
    let destination_service_did = required_header(req, "destination-service-did")?;
    let source_trust_domain = required_header(req, "source-trust-domain")?;
    let destination_trust_domain = required_header(req, "destination-trust-domain")?;
    if destination_service_did != body_destination
        || destination_service_did != state.config.service_did
    {
        return Err(signature_error(
            "Destination-Service-DID does not match the federation request destination",
        ));
    }
    if destination_trust_domain != state.config.trust_domain {
        return Err(signature_error(
            "Destination-Trust-Domain does not match this service",
        ));
    }
    let expected_source_trust_domain = trust_domain_from_service_did(&source_service_did);
    if source_trust_domain != expected_source_trust_domain {
        return Err(signature_error(
            "Source-Trust-Domain does not match Source-Service-DID",
        ));
    }

    let target_uri = signature_target_uri(req, state);
    let authority = signature_authority(req, state);
    let endpoint_digest =
        validate_destination_authority(state, req, &authority, &destination_service_did)?;
    let method = req.method().as_str().to_ascii_uppercase();
    let outer_params = signature_params(req, "signature-input")?;
    validate_signature_params(&outer_params, &source_service_did, "outer")?;
    let outer_base = federation_http_signature_base(
        &method,
        &target_uri,
        &authority,
        &content_digest,
        &source_service_did,
        &destination_service_did,
        &source_trust_domain,
        &destination_trust_domain,
        &request_digest,
        endpoint_digest.as_deref(),
        &outer_params,
    );
    verify_signature_header(
        state,
        req,
        "signature",
        &source_service_did,
        &outer_base,
        "outer",
    )?;

    if source_service_did != body_origin {
        verify_relay_inner_signature(
            state,
            req,
            &method,
            &target_uri,
            &content_digest,
            body_origin,
            &source_service_did,
            &destination_service_did,
            &request_digest,
        )?;
    }

    Ok(())
}

/// Verify the inbound RFC 9421 HTTP Message Signature for a spec-canonical
/// `/_cokret/peer/*` request and enforce the local peer deny policy.
///
/// Unlike [`verify_inbound_federation_http_signature`] (the private
/// `/_soland/peer/federation/*` track, which carries a typed body with an
/// `origin`/`destination` field and an optional relay-inner signature), the
/// canonical peer surface authenticates purely on the federation trust headers:
/// the origin is the `source-service-did` header, so there is no relay-inner
/// hop to verify. The function handles both bodied requests (POST submit /
/// query_post / resolve / invites / contacts) and bodyless GETs (query /
/// frontier / snapshot.head), binding the signature to an empty-body
/// Content-Digest in the latter case.
pub(in crate::routing) fn verify_inbound_peer_http_signature(
    state: &AppState,
    req: &Request,
    body: Option<&Value>,
) -> Result<(), AppError> {
    let body_bytes = match body {
        Some(value) => cokret_sdk::canonical::canonical_json_bytes(value).map_err(|error| {
            AppError::new(
                crate::error::ErrorCode::SchemaViolation,
                format!("peer request body is not canonical JSON: {error}"),
            )
            .with_status(StatusCode::BAD_REQUEST)
        })?,
        None => Vec::new(),
    };
    let expected_content_digest = content_digest_header(&body_bytes);
    let expected_request_digest = cokret_sdk::canonical::sha256_digest(&body_bytes);
    validate_federation_request_binding(&state.config.trust_domain, req, &expected_request_digest)?;

    let content_digest = required_header(req, "content-digest")?;
    if content_digest != expected_content_digest {
        crate::metrics::record_digest_mismatch("peer_request_content_digest");
        return Err(signature_error(
            "Content-Digest does not match peer canonical request body",
        ));
    }
    let request_digest = required_header(req, "request-canonical-digest")?;
    if request_digest != expected_request_digest {
        crate::metrics::record_digest_mismatch("peer_request_request_digest");
        return Err(signature_error(
            "Request-Canonical-Digest does not match peer canonical request body",
        ));
    }

    let source_service_did = required_header(req, "source-service-did")?;
    let destination_service_did = required_header(req, "destination-service-did")?;
    let source_trust_domain = required_header(req, "source-trust-domain")?;
    let destination_trust_domain = required_header(req, "destination-trust-domain")?;

    // federation.md §5: `deny` MUST be evaluated before `allow` and machine-level
    // defederation MUST take effect on inbound as well as outbound. Run it after
    // the source DID is parsed but before the (fail-closed) signature check.
    if crate::security::federation_origin_denied(&source_service_did) {
        return Err(AppError::new(
            crate::error::ErrorCode::CapabilityDenied,
            "peer is denied by local federation policy",
        )
        .with_status(StatusCode::FORBIDDEN)
        .with_wire_code("federation_peer_denied"));
    }

    if destination_service_did != state.config.service_did {
        return Err(signature_error(
            "Destination-Service-DID does not match this service",
        ));
    }
    if destination_trust_domain != state.config.trust_domain {
        return Err(signature_error(
            "Destination-Trust-Domain does not match this service",
        ));
    }
    let expected_source_trust_domain = trust_domain_from_service_did(&source_service_did);
    if source_trust_domain != expected_source_trust_domain {
        return Err(signature_error(
            "Source-Trust-Domain does not match Source-Service-DID",
        ));
    }

    let target_uri = signature_target_uri(req, state);
    let authority = signature_authority(req, state);
    let endpoint_digest =
        validate_destination_authority(state, req, &authority, &destination_service_did)?;
    let method = req.method().as_str().to_ascii_uppercase();
    let outer_params = signature_params(req, "signature-input")?;
    validate_signature_params(&outer_params, &source_service_did, "outer")?;
    let outer_base = federation_http_signature_base(
        &method,
        &target_uri,
        &authority,
        &content_digest,
        &source_service_did,
        &destination_service_did,
        &source_trust_domain,
        &destination_trust_domain,
        &request_digest,
        endpoint_digest.as_deref(),
        &outer_params,
    );
    verify_signature_header(
        state,
        req,
        "signature",
        &source_service_did,
        &outer_base,
        "outer",
    )
}

#[allow(clippy::too_many_arguments)]
fn verify_relay_inner_signature(
    state: &AppState,
    req: &Request,
    method: &str,
    target_uri: &str,
    content_digest: &str,
    origin_service_did: &str,
    relay_service_did: &str,
    destination_service_did: &str,
    request_digest: &str,
) -> Result<(), AppError> {
    let inner_params = signature_params(req, "relay-inner-signature-input")?;
    validate_signature_params(&inner_params, origin_service_did, "relay inner")?;
    let inner_base = format!(
        "\"@method\": {method}\n\
         \"@target-uri\": {target_uri}\n\
         \"content-digest\": {content_digest}\n\
         \"origin-service-did\": {origin_service_did}\n\
         \"relay-service-did\": {relay_service_did}\n\
         \"destination-service-did\": {destination_service_did}\n\
         \"request-canonical-digest\": {request_digest}\n\
         \"@signature-params\": {inner_params}",
    );
    verify_signature_header(
        state,
        req,
        "relay-inner-signature",
        origin_service_did,
        &inner_base,
        "relay inner",
    )
}

#[allow(clippy::too_many_arguments)]
fn federation_http_signature_base(
    method: &str,
    target_uri: &str,
    authority: &str,
    content_digest: &str,
    source_service_did: &str,
    destination_service_did: &str,
    source_trust_domain: &str,
    destination_trust_domain: &str,
    request_digest: &str,
    destination_service_endpoint_digest: Option<&str>,
    signature_params: &str,
) -> String {
    // federation.md §3.2 line 180/185: when a Destination-Service-Endpoint-Digest
    // is present it MUST be a covered component of the signature transcript so the
    // signer commits to the destination endpoint (anti virtual-host confusion on
    // shared ingress). Single-endpoint deployments omit it and the component is
    // simply absent from the base.
    let endpoint_component = destination_service_endpoint_digest
        .map(|digest| format!("\"destination-service-endpoint-digest\": {digest}\n"))
        .unwrap_or_default();
    format!(
        "\"@method\": {method}\n\
         \"@target-uri\": {target_uri}\n\
         \"@authority\": {authority}\n\
         \"content-digest\": {content_digest}\n\
         \"source-service-did\": {source_service_did}\n\
         \"destination-service-did\": {destination_service_did}\n\
         \"source-trust-domain\": {source_trust_domain}\n\
         \"destination-trust-domain\": {destination_trust_domain}\n\
         \"request-canonical-digest\": {request_digest}\n\
         {endpoint_component}\
         \"@signature-params\": {signature_params}",
    )
}

/// federation.md §3.2 line 105-106: verify the signed `@authority` host matches
/// the endpoint registered for the Destination-Service-DID. Because the inbound
/// path already enforces `destination_service_did == this service`, the
/// authoritative endpoint is this service's own published `public_base_url`.
///
/// Returns the `Destination-Service-Endpoint-Digest` to bind into the transcript
/// when the request carries that header (required on shared ingress, line 180);
/// when present it MUST equal the sha256 digest of the registered endpoint
/// canonical URL.
fn validate_destination_authority(
    state: &AppState,
    req: &Request,
    authority: &str,
    destination_service_did: &str,
) -> Result<Option<String>, AppError> {
    // The registered endpoint authority for this (destination) service.
    if let Some(expected_authority) = public_base_url_authority(state) {
        if !authority.eq_ignore_ascii_case(&expected_authority) {
            crate::metrics::record_digest_mismatch("federation_authority_mismatch");
            return Err(signature_error(
                "signed @authority host does not match the Destination-Service-DID endpoint",
            ));
        }
    }

    // Optional endpoint-digest binding (conditional-required on shared ingress).
    let observed = req
        .headers()
        .get("destination-service-endpoint-digest")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned);
    if let Some(observed_digest) = observed {
        let expected_digest = cokret_sdk::canonical::sha256_digest(
            state
                .config
                .public_base_url
                .trim_end_matches('/')
                .as_bytes(),
        );
        if observed_digest != expected_digest {
            crate::metrics::record_digest_mismatch("federation_endpoint_digest_mismatch");
            return Err(signature_error(
                "Destination-Service-Endpoint-Digest does not match the registered endpoint",
            ));
        }
        // Sanity: the digest must be for *this* service's destination DID.
        debug_assert_eq!(destination_service_did, state.config.service_did);
        return Ok(Some(observed_digest));
    }
    Ok(None)
}

fn required_header(req: &Request, name: &str) -> Result<String, AppError> {
    req.headers()
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .ok_or_else(|| signature_error(format!("missing required federation header: {name}")))
}

fn signature_params(req: &Request, header_name: &str) -> Result<String, AppError> {
    required_header(req, header_name)?
        .strip_prefix("sig1=")
        .map(ToOwned::to_owned)
        .ok_or_else(|| signature_error(format!("{header_name} must contain sig1 parameters")))
}

fn validate_signature_params(
    signature_params: &str,
    expected_service_did: &str,
    label: &str,
) -> Result<(), AppError> {
    let expected_keyid = format!("{expected_service_did}#federation-fanout-key");
    let observed_keyid = signature_param_value(signature_params, "keyid").ok_or_else(|| {
        signature_error(format!(
            "{label} Signature-Input missing keyid; key_rotation_hint=refresh_origin_service_did"
        ))
    })?;
    if observed_keyid != expected_keyid {
        return Err(signature_error(format!(
            "{label} Signature-Input keyid mismatch; key_rotation_hint=refresh_origin_service_did"
        )));
    }
    if signature_param_value(signature_params, "alg").as_deref() != Some("ed25519") {
        return Err(signature_error(format!(
            "{label} Signature-Input alg must be ed25519"
        )));
    }
    let now = Utc::now().timestamp();
    // federation.md §3.2: `created` and `expires` are MUST-present signature
    // parameters; the freshness window is normative and is the only protocol-level
    // replay backstop on the inbound write path (an evicted replay cache MUST NOT
    // allow a byte-for-byte replay that falls outside this window). Fail closed when
    // either is absent or unparsable rather than silently accepting the signature.
    let created = signature_param_value(signature_params, "created")
        .and_then(|value| value.parse::<i64>().ok())
        .ok_or_else(|| {
            signature_error(format!(
                "{label} Signature-Input missing required `created` parameter"
            ))
        })?;
    let expires = signature_param_value(signature_params, "expires")
        .and_then(|value| value.parse::<i64>().ok())
        .ok_or_else(|| {
            signature_error(format!(
                "{label} Signature-Input missing required `expires` parameter"
            ))
        })?;
    // `created` MUST be within ±30s of local clock (both directions).
    if (created - now).abs() > 30 {
        return Err(signature_error(format!(
            "{label} signature created timestamp outside ±30s clock-skew window"
        )));
    }
    // Window width MUST NOT exceed 300s.
    if expires < created || expires - created > 300 {
        return Err(signature_error(format!(
            "{label} signature validity window exceeds 300s"
        )));
    }
    // `expires` MUST be in the future relative to local clock.
    if expires < now {
        return Err(signature_error(format!("{label} signature is expired")));
    }
    Ok(())
}

fn signature_param_value(signature_params: &str, key: &str) -> Option<String> {
    signature_params.split(';').skip(1).find_map(|part| {
        let (name, value) = part.split_once('=')?;
        if name.trim() != key {
            return None;
        }
        Some(value.trim().trim_matches('"').to_owned())
    })
}

fn verify_signature_header(
    state: &AppState,
    req: &Request,
    header_name: &str,
    service_did: &str,
    signature_base: &str,
    label: &str,
) -> Result<(), AppError> {
    let signature_header = required_header(req, header_name)?;
    let signature = decode_signature_header(&signature_header).map_err(|message| {
        signature_error(format!(
            "{label} signature decode failed: {message}; key_rotation_hint=refresh_origin_service_did"
        ))
    })?;
    let verifying_key = verifying_key_for_service_did(state, service_did)?;
    verifying_key
        .verify(signature_base.as_bytes(), &signature)
        .map_err(|_| {
            signature_error(format!(
                "{label} signature verification failed; key_rotation_hint=refresh_origin_service_did"
            ))
        })
}

fn origin_key_state_digest_for_service(
    state: &AppState,
    service_did: &str,
) -> Result<String, AppError> {
    let verifying_key = verifying_key_for_service_did(state, service_did)?;
    let mut hasher = Sha256::new();
    hasher.update(b"soland:federation-origin-key-state:v1:");
    hasher.update(service_did.as_bytes());
    hasher.update(verifying_key.to_bytes());
    Ok(format!("sha256:{}", hex::encode(hasher.finalize())))
}

fn decode_signature_header(value: &str) -> Result<Signature, &'static str> {
    let signature_b64 = value
        .strip_prefix("sig1=:")
        .and_then(|value| value.strip_suffix(':'))
        .ok_or("Signature header must use sig1=:base64: form")?;
    let signature_bytes = STANDARD
        .decode(signature_b64)
        .map_err(|_| "Signature header base64 is invalid")?;
    Signature::from_slice(&signature_bytes).map_err(|_| "Signature header is not Ed25519 length")
}

fn verifying_key_for_service_did(
    state: &AppState,
    service_did: &str,
) -> Result<VerifyingKey, AppError> {
    if service_did == state.config.service_did {
        return Ok(state.notary_signing_key().verifying_key());
    }
    if let Some(key) = configured_peer_verifying_key(service_did)? {
        return Ok(key);
    }
    if state.config.development_mode {
        tracing::warn!(
            service_did,
            "development_mode accepted deterministic federation service key fallback"
        );
        return Ok(development_service_signing_key(service_did).verifying_key());
    }
    let verification_method = format!("{service_did}#federation-fanout-key");
    if let Ok(key) = crate::jws_verify::resolve_ed25519_pubkey(state, &verification_method) {
        return Ok(key);
    }
    Err(signature_error(
        "source service key unavailable; key_rotation_hint=refresh_origin_service_did",
    ))
}

fn configured_peer_verifying_key(service_did: &str) -> Result<Option<VerifyingKey>, AppError> {
    let Ok(raw) = std::env::var("SOLAND_FEDERATION_PEER_PUBLIC_KEYS") else {
        return Ok(None);
    };
    let expected_method = format!("{service_did}#federation-fanout-key");
    for entry in raw.split([',', ';', '\n']) {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        let Some((id, material)) = entry
            .split_once('=')
            .or_else(|| entry.split_once(':'))
            .map(|(id, material)| (id.trim(), material.trim()))
        else {
            continue;
        };
        if id != service_did && id != expected_method {
            continue;
        }
        return decode_peer_verifying_key(material)
            .map(Some)
            .map_err(|message| signature_error(format!("peer public key invalid: {message}")));
    }
    Ok(None)
}

fn decode_peer_verifying_key(material: &str) -> Result<VerifyingKey, String> {
    let bytes = URL_SAFE_NO_PAD
        .decode(material.as_bytes())
        .or_else(|_| STANDARD.decode(material.as_bytes()))
        .map_err(|error| format!("public key is not base64/base64url: {error}"))?;
    if bytes.len() != 32 {
        return Err(format!(
            "Ed25519 public key must be 32 bytes, got {}",
            bytes.len()
        ));
    }
    let mut raw = [0u8; 32];
    raw.copy_from_slice(&bytes);
    VerifyingKey::from_bytes(&raw).map_err(|error| format!("invalid Ed25519 key: {error}"))
}

fn development_service_signing_key(service_did: &str) -> SigningKey {
    let mut hasher = Sha256::new();
    hasher.update(b"soland:notary-ephemeral:");
    hasher.update(service_did.as_bytes());
    let seed: [u8; 32] = hasher.finalize().into();
    SigningKey::from_bytes(&seed)
}

pub(in crate::routing) fn signature_target_uri(req: &Request, state: &AppState) -> String {
    let scheme = req
        .uri()
        .scheme_str()
        .map(ToOwned::to_owned)
        .or_else(|| public_base_url_scheme(state))
        .unwrap_or_else(|| "http".to_owned());
    let authority = signature_authority(req, state);
    let path_and_query = req
        .uri()
        .path_and_query()
        .map(|value| value.as_str())
        .unwrap_or_else(|| req.uri().path());
    format!("{scheme}://{authority}{path_and_query}")
}

pub(in crate::routing) fn signature_authority(req: &Request, state: &AppState) -> String {
    req.uri()
        .authority()
        .map(|authority| authority.as_str().to_owned())
        .or_else(|| {
            req.headers()
                .get("host")
                .and_then(|value| value.to_str().ok())
                .map(ToOwned::to_owned)
        })
        .or_else(|| public_base_url_authority(state))
        .unwrap_or_else(|| "server".to_owned())
}

fn public_base_url_scheme(state: &AppState) -> Option<String> {
    reqwest::Url::parse(&state.config.public_base_url)
        .ok()
        .map(|url| url.scheme().to_owned())
}

fn public_base_url_authority(state: &AppState) -> Option<String> {
    let url = reqwest::Url::parse(&state.config.public_base_url).ok()?;
    let host = url.host_str()?;
    Some(
        url.port()
            .map(|port| format!("{host}:{port}"))
            .unwrap_or_else(|| host.to_owned()),
    )
}

pub(crate) fn trust_domain_from_service_did(service_did: &str) -> String {
    let scope = service_did
        .strip_prefix("did:web:")
        .or_else(|| service_did.strip_prefix("did:key:"))
        .or_else(|| service_did.strip_prefix("did:webvh:"))
        .unwrap_or(service_did)
        .to_ascii_lowercase()
        .replace(':', ".");
    format!("ck:trust_domain:{scope}")
}

fn signature_error(message: impl Into<String>) -> AppError {
    AppError::unauthenticated(message.into())
}

fn federation_verify_actor_digest(
    body: &cokret_sdk::FederationVerifyActorRequestBody,
) -> Result<String, &'static str> {
    let value = serde_json::to_value(body)
        .map_err(|_| "federation verify-actor request must serialize to JSON")?;
    cokret_sdk::canonical::canonical_sha256(&value)
        .map_err(|_| "federation verify-actor request must be canonical JSON")
}

fn federation_verify_actor_unsigned_digest(
    body: &cokret_sdk::FederationVerifyActorRequestBody,
) -> Result<String, &'static str> {
    let mut value = serde_json::to_value(body)
        .map_err(|_| "federation verify-actor request must serialize to JSON")?;
    let Some(object) = value.as_object_mut() else {
        return Err("federation verify-actor request must serialize to a JSON object");
    };
    object.remove("signature");
    cokret_sdk::canonical::canonical_sha256(&value)
        .map_err(|_| "federation verify-actor unsigned request must be canonical JSON")
}

/// Federation actor signature transcript v1.
///
/// The actor signs the canonical JSON bytes of this object. It deliberately
/// covers the digest of the verify-actor request with `signature` removed:
/// signing the full body would be self-referential because the signature field
/// is populated after signing. The HTTP federation trust headers still bind
/// the complete request body, including `signature`.
fn federation_verify_actor_signature_transcript(
    body: &cokret_sdk::FederationVerifyActorRequestBody,
    unsigned_request_digest: &str,
) -> Value {
    let scope_id = body.realm_id.as_ref().map(|value| value.as_str());
    json!({
        "type": "ck.federation.verify_actor.signature.v1",
        "actor_id": body.actor_id.as_str(),
        "purpose": body.purpose,
        "challenge": body.challenge,
        "signed_payload_digest": body.signed_payload_digest.as_ref().map(|digest| digest.as_str()),
        "realm_id": scope_id,
        "request_binding_digest": unsigned_request_digest,
    })
}

struct VerifiedFederationActor {
    verified_key_id: String,
    did_document_ref: String,
    key_log_head: cokret_sdk::Hash,
}

struct FederationActorSignature {
    verification_method: String,
    sig_b64: Option<String>,
    jws: Option<String>,
}

async fn verify_federation_actor_signature(
    state: &AppState,
    body: &cokret_sdk::FederationVerifyActorRequestBody,
    unsigned_request_digest: &str,
) -> Result<VerifiedFederationActor, AppError> {
    let actor_signature = parse_federation_actor_signature(&body.signature)?;
    // High-risk path: enforce DID document freshness before federation receive
    // signature verification (fail-closed-on-stale).
    let resolved_key = crate::jws_verify::resolve_ed25519_verification_key_for_did_fresh(
        state,
        &body.actor_id,
        &actor_signature.verification_method,
    )
    .await
    .map_err(|error| {
        if error == "verification method controller does not match DID" {
            actor_signature_error("actor verification method controller does not match actor_id")
        } else {
            actor_signature_error(format!("actor verification key invalid: {error}"))
        }
    })?;

    let transcript = federation_verify_actor_signature_transcript(body, unsigned_request_digest);
    let transcript_bytes = cokret_sdk::canonical::canonical_json_bytes(&transcript)
        .map_err(|error| AppError::internal(format!("verify-actor transcript failed: {error}")))?;

    if let Some(jws) = actor_signature.jws.as_deref() {
        crate::jws_verify::verify_jws_ed25519(
            &transcript_bytes,
            jws,
            &actor_signature.verification_method,
            body.actor_id.as_str(),
            state,
        )
        .map_err(|error| {
            actor_signature_error(format!("actor JWS verification failed: {error}"))
        })?;
    } else {
        let sig_b64 = actor_signature.sig_b64.as_deref().ok_or_else(|| {
            actor_signature_error("actor signature requires `sig` or detached `jws`")
        })?;
        let raw = URL_SAFE_NO_PAD
            .decode(sig_b64.as_bytes())
            .or_else(|_| STANDARD.decode(sig_b64.as_bytes()))
            .map_err(|_| actor_signature_error("actor signature is not base64/base64url"))?;
        let signature = Signature::from_slice(&raw)
            .map_err(|_| actor_signature_error("actor signature must be 64 Ed25519 bytes"))?;
        resolved_key
            .public_key
            .verify(&transcript_bytes, &signature)
            .map_err(|_| actor_signature_error("actor signature verification failed"))?;
    }

    Ok(VerifiedFederationActor {
        verified_key_id: resolved_key.verification_method,
        did_document_ref: resolved_key.did_document_ref,
        key_log_head: resolved_key.key_log_head,
    })
}

fn parse_federation_actor_signature(value: &Value) -> Result<FederationActorSignature, AppError> {
    let object = value
        .as_object()
        .ok_or_else(|| actor_signature_error("actor signature must be an object"))?;
    let verification_method = object
        .get("kid")
        .or_else(|| object.get("key_id"))
        .or_else(|| object.get("verification_method"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| actor_signature_error("actor signature missing kid"))?
        .to_owned();
    let alg = object
        .get("alg")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| actor_signature_error("actor signature missing alg"))?
        .to_owned();
    if !matches!(alg.as_str(), "Ed25519" | "EdDSA") {
        return Err(actor_signature_error(
            "actor signature alg must be Ed25519 or EdDSA",
        ));
    }
    let sig_b64 = object
        .get("sig")
        .or_else(|| object.get("signature"))
        .or_else(|| object.get("signature_b64"))
        .and_then(Value::as_str)
        .map(ToOwned::to_owned);
    let jws = object
        .get("jws")
        .or_else(|| object.get("detached_jws"))
        .and_then(Value::as_str)
        .map(ToOwned::to_owned);
    if sig_b64.is_none() && jws.is_none() {
        return Err(actor_signature_error(
            "actor signature missing sig or detached jws",
        ));
    }
    Ok(FederationActorSignature {
        verification_method,
        sig_b64,
        jws,
    })
}

fn actor_signature_error(message: impl Into<String>) -> AppError {
    AppError::new(crate::error::ErrorCode::InvalidSignature, message.into())
        .with_status(StatusCode::UNAUTHORIZED)
}

fn verify_federation_origin(origin: &str) -> bool {
    if !origin.starts_with("did:") {
        return false;
    }
    let rest = &origin[4..];
    if let Some(colon_pos) = rest.find(':') {
        let method = &rest[..colon_pos];
        let name = &rest[colon_pos + 1..];
        !method.is_empty() && method.chars().all(|c| c.is_ascii_lowercase()) && !name.is_empty()
    } else {
        false
    }
}

fn federation_destination_matches(state: &AppState, destination: &str) -> bool {
    destination == state.config.service_did
}

fn configured_peer_from_backfill_body(
    state: &AppState,
    body: &Value,
) -> Result<FederationPeerTarget, AppError> {
    let peer_url = body
        .get("peer_url")
        .and_then(Value::as_str)
        .map(|value| value.trim().trim_end_matches('/').to_owned())
        .filter(|value| !value.is_empty());
    let peer_did = body
        .get("peer_did")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let peers = configured_peer_targets(state);
    let matched = peers.into_iter().find(|peer| {
        peer_url.as_deref().is_some_and(|url| peer.url == url)
            || peer_did.is_some_and(|did| peer.did == did)
    });
    matched.ok_or_else(|| {
        AppError::invalid_param(
            "peer_url or peer_did must match a configured SOLAND_FEDERATION_PEERS entry",
        )
    })
}

async fn pull_operations_page(
    state: &AppState,
    peer: &FederationPeerTarget,
    realm_id: &str,
    after_cursor: Option<&str>,
    limit: usize,
) -> Result<cokret_sdk::FederationPullOperationsOutcome, AppError> {
    let mut url = reqwest::Url::parse(&format!("{}/_cokret/peer/events", peer.url))
        .map_err(|error| AppError::invalid_param(format!("invalid peer_url: {error}")))?;
    {
        let mut query = url.query_pairs_mut();
        query.append_pair("realm_id", realm_id);
        query.append_pair("limit", &limit.to_string());
        if let Some(after_cursor) = after_cursor.filter(|value| !value.is_empty()) {
            query.append_pair("after_cursor", after_cursor);
        }
    }
    let (url, client) = crate::security::validate_http_url_for_egress_with_pinned_client(
        url.as_str(),
        "peer events query",
        state.config.development_mode,
        crate::routing::federation::outbox::REQUEST_TIMEOUT,
    )
    .map_err(AppError::capability_denied)?;
    let response = client
        .get(url.clone())
        .send()
        .await
        .map_err(|error| AppError::internal(format!("federation pull from {url}: {error}")))?;
    let status = response.status();
    let text = response
        .text()
        .await
        .map_err(|error| AppError::internal(format!("read federation pull response: {error}")))?;
    if !status.is_success() {
        return Err(AppError::internal(format!(
            "federation pull from {url} returned {status}: {text}"
        )));
    }
    serde_json::from_str::<cokret_sdk::FederationPullOperationsOutcome>(&text)
        .map_err(|error| AppError::internal(format!("parse federation pull response: {error}")))
}

async fn operation_frontier_value(state: &AppState, realm_id: &str) -> Value {
    serde_json::to_value(operation_frontier_outcome(state, realm_id).await)
        .unwrap_or_else(|_| Value::Null)
}

async fn operation_frontier_outcome(
    state: &AppState,
    realm_id: &str,
) -> FederationOperationFrontierOutcome {
    let operations = state
        .persistence
        .federation_operations()
        .list_for_realm(&realm_id)
        .await
        .unwrap_or_default();
    let mut operation_ids = operations
        .iter()
        .map(|operation| operation.operation_id.to_string())
        .collect::<Vec<_>>();
    operation_ids.sort();
    let latest_operation_id = operation_ids.last().cloned();
    let digest_payload = json!({
        "realm_id": realm_id,
        "operation_ids": operation_ids.clone(),
    });
    let frontier_digest = cokret_sdk::canonical::canonical_sha256(&digest_payload)
        .map(|digest| {
            if digest.starts_with("sha256:") {
                digest
            } else {
                format!("sha256:{digest}")
            }
        })
        .unwrap_or_else(|_| {
            format!(
                "sha256:{}",
                sha256_hex(digest_payload.to_string().as_bytes())
            )
        });
    FederationOperationFrontierOutcome {
        realm_id: realm_id.to_owned(),
        operation_count: operations.len(),
        operation_ids,
        latest_operation_id,
        frontier_digest,
    }
}

fn is_valid_federation_txn_id(value: &str) -> bool {
    let value = value.trim();
    !value.is_empty()
        && value.len() <= 128
        && value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.' | ':' | '$'))
}

fn federation_request_digest(
    body: &cokret_sdk::FederationTransactionRequestBody,
) -> Result<String, &'static str> {
    let value =
        serde_json::to_value(body).map_err(|_| "federation transaction must serialize to JSON")?;
    cokret_sdk::canonical::canonical_sha256(&value)
        .map_err(|_| "federation transaction must be canonical JSON")
}

// ── Seal pull/push (federation/seals) ──────────────

#[derive(Clone, Debug, Default, Serialize, Deserialize, salvo::oapi::ToSchema)]
pub struct FederationSealsOutcome {
    pub seals: Vec<Seal>,
    /// Echo of [`crate::config::FederationPolicy::as_str`] so the calling
    /// peer can reason about whether to fan out to other nodes.
    pub policy: String,
    pub next_cursor: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, salvo::oapi::ToSchema)]
pub struct FederationSealsPushRequestBody {
    pub origin: String,
    pub seals: Vec<Seal>,
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
pub(super) async fn federation_seals_pull(
    depot: &mut Depot,
    realm_id: QueryParam<String, true>,
) -> JsonResult<FederationSealsOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let realm_id = realm_id.into_inner();
    if cokret_sdk::RealmId::new(realm_id.clone()).is_err() {
        return Err(AppError::invalid_param("invalid realm_id"));
    }
    let realm = RealmId::new(realm_id).map_err(|_| AppError::invalid_param("invalid realm_id"))?;
    let leaves = state.seal_store.list_leaves(&realm).unwrap_or_default();
    let mut seals: Vec<Seal> = Vec::with_capacity(leaves.len());
    for leaf in &leaves {
        if let Ok(Some(a)) = state.seal_store.get(leaf) {
            seals.push(a);
        }
    }
    json_ok(FederationSealsOutcome {
        seals,
        policy: state.config.federation_policy.as_str().to_owned(),
        next_cursor: None,
    })
}

#[endpoint(
    operation_id = "org.cokret.soland.federation.seals.push",
    tags("federation"),
    summary = "Accept Seal envelopes from a federation peer (peer-push)"
)]
#[tracing::instrument(skip_all, fields(op = "org.cokret.soland.federation.seals.push"))]
pub(super) async fn federation_seals_push(
    depot: &mut Depot,
    body: JsonBody<FederationSealsPushRequestBody>,
) -> JsonResult<FederationSealsPushOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
    ensure_private_inbound_write_rail_local(state)?;
    let body = body.into_inner();
    if !verify_federation_origin(&body.origin) {
        return Err(AppError::new(
            crate::error::ErrorCode::Unauthenticated,
            "federation origin must be a valid DID",
        )
        .with_status(StatusCode::UNAUTHORIZED));
    }
    let mut accepted: Vec<String> = Vec::new();
    let mut rejected: Vec<serde_json::Value> = Vec::new();
    for seal in body.seals {
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

/// Outbound Move broadcast helper. Each accepted Move
/// goes to:
/// - [`FederationPolicy::Mesh`]: every peer in `state.config.federation_peers`.
/// - [`FederationPolicy::Hub`]: only the first peer (`federation_peers[0]`).
///
/// Returns the list of peer URLs the broadcast targeted. This helper persists
/// the retry transcript and durable outbox row; the actual HTTP dispatch still
/// happens later in the federation outbox worker.
pub async fn broadcast_move_to_peers(state: &AppState, move_id: &str) -> Vec<String> {
    let peers = configured_peer_targets(state);
    for peer in &peers {
        let peer_url = peer.url.clone();
        record_outbound_fanout_attempt(state, "move", move_id, peer.url.as_str()).await;
        // G3.S0 — durable enqueue. The transcript persisted above remains
        // the human-readable audit record; the outbox row is what the
        // background dispatcher (`routing::federation::outbox`) actually
        // POSTs. Failures to enqueue are logged but don't fail the
        // inbound write — the transcript still gives operators a way to
        // re-trigger delivery once the storage hiccup clears.
        enqueue_outbound_for(state, "move", move_id, peer).await;
        tracing::debug!(
            worker = "federation_outbox_enqueue",
            peer = %peer_url,
            move_id = %move_id,
            "federation broadcast move signed request transcript persisted for retry worker"
        );
    }
    peers.into_iter().map(|peer| peer.url).collect()
}

/// Symmetric helper for Seal replication. The hub policy still pushes
/// to a single upstream so the broadcast list is `[hub]`; mesh fans out
/// to every peer.
pub async fn broadcast_seal_to_peers(state: &AppState, seal_id: &str) -> Vec<String> {
    let peers = configured_peer_targets(state);
    for peer in &peers {
        let peer_url = peer.url.clone();
        record_outbound_fanout_attempt(state, "seal", seal_id, peer.url.as_str()).await;
        // G3.S0 — durable enqueue (see broadcast_move_to_peers).
        enqueue_outbound_for(state, "seal", seal_id, peer).await;
        tracing::debug!(
            worker = "federation_outbox_enqueue",
            peer = %peer_url,
            seal_id = %seal_id,
            "federation broadcast seal signed request transcript persisted for retry worker"
        );
    }
    peers.into_iter().map(|peer| peer.url).collect()
}

/// Resolve the configured peer base URL for a destination service DID, if the
/// deployment lists it in `federation_peers` (and the deployment peer policy
/// does not deny it). Used by federation senders (e.g. contact fact delivery)
/// that address a target by its home Principal Server service DID.
pub(crate) fn peer_url_for_service_did(state: &AppState, service_did: &str) -> Option<String> {
    configured_peer_targets(state)
        .into_iter()
        .find(|peer| peer.did == service_did)
        .map(|peer| peer.url)
}

fn configured_peer_targets(state: &AppState) -> Vec<FederationPeerTarget> {
    use crate::config::FederationPolicy;
    let entries: Vec<String> = match state.config.federation_policy {
        FederationPolicy::Mesh => state.config.federation_peers.clone(),
        FederationPolicy::Hub => state
            .config
            .federation_peers
            .first()
            .cloned()
            .into_iter()
            .collect(),
    };
    entries
        .into_iter()
        .filter_map(|entry| parse_peer_target(&entry))
        .filter(|peer| {
            let denied = crate::security::federation_peer_denied(&peer.url, &peer.did);
            if denied {
                tracing::warn!(
                    peer_url = %peer.url,
                    peer_did = %peer.did,
                    "configured federation peer denied by deployment peer policy"
                );
            }
            !denied
        })
        .collect()
}

fn parse_peer_target(entry: &str) -> Option<FederationPeerTarget> {
    let entry = entry.trim();
    if entry.is_empty() {
        return None;
    }
    let (left, right) = entry
        .split_once('|')
        .map(|(left, right)| (left.trim(), right.trim()))
        .unwrap_or((entry, entry));
    if left.is_empty() || right.is_empty() {
        return None;
    }
    if left.starts_with("did:") && !right.starts_with("did:") {
        Some(FederationPeerTarget {
            url: right.trim_end_matches('/').to_owned(),
            did: left.to_owned(),
        })
    } else {
        Some(FederationPeerTarget {
            url: left.trim_end_matches('/').to_owned(),
            did: right.to_owned(),
        })
    }
}

/// G3.S0 — bridge from the existing broadcast_*_to_peers helpers to the
/// durable outbox. Computes the canonical request body the dispatcher
/// will POST and inserts a `federation_outbox` row keyed by
/// `(peer, resource_kind, resource_id)`. The idempotency key is
/// deterministic so a restart-time re-broadcast collapses onto the
/// existing row (UNIQUE INDEX on `peer_did, idempotency_key`) instead
/// of creating a duplicate.
async fn enqueue_outbound_for(
    state: &AppState,
    resource_kind: &str,
    resource_id: &str,
    peer: &FederationPeerTarget,
) {
    let endpoint = match resource_kind {
        "seal" => "/_cokret/peer/events",
        _ => "/_cokret/peer/events",
    };
    let payload = json!({
        "schema": format!("ck.federation.outbound.{resource_kind}.v1"),
        "origin": state.config.service_did,
        "destination": peer.did.as_str(),
        "resource_kind": resource_kind,
        "resource_id": resource_id,
        "endpoint": endpoint,
    });
    // Reuse the SDK canonicalizer that already underpins the transcript
    // signing path so the body bytes the dispatcher POSTs are identical
    // to what the signature transcript covers — important once full
    // RFC 9421 signing lands.
    let payload_bytes = cokret_sdk::canonical::canonical_json_bytes(&payload)
        .unwrap_or_else(|_| serde_json::to_vec(&payload).unwrap_or_default());
    let payload_json =
        String::from_utf8(payload_bytes.clone()).unwrap_or_else(|_| payload.to_string());
    // Deterministic Idempotency-Key per spec `federation.md` §8.5 —
    // `sha256(origin || destination || resource_kind || resource_id)`
    // gives the (origin, destination, key) tuple the receiver dedupes
    // against. Restart-time re-broadcast hits the UNIQUE INDEX and
    // collapses to the existing outbox row.
    let mut hasher = Sha256::new();
    hasher.update(state.config.service_did.as_bytes());
    hasher.update(b"|");
    hasher.update(peer.did.as_bytes());
    hasher.update(b"|");
    hasher.update(resource_kind.as_bytes());
    hasher.update(b"|");
    hasher.update(resource_id.as_bytes());
    let idempotency_key = format!("ck:outbox:{}", hex::encode(hasher.finalize()));
    if let Err(error) = crate::routing::federation::outbox::enqueue_outbound(
        state,
        peer.url.as_str(),
        peer.did.as_str(),
        endpoint,
        &idempotency_key,
        &payload_json,
    )
    .await
    {
        tracing::warn!(
            %error,
            peer = %peer.url,
            peer_did = %peer.did,
            resource_kind,
            resource_id,
            "failed to enqueue federation outbox row (transcript still persisted)"
        );
    }
}

async fn record_outbound_fanout_attempt(
    state: &AppState,
    resource_kind: &str,
    resource_id: &str,
    peer: &str,
) {
    let peer_hash = sha256_hex(peer.as_bytes());
    let resource_hash = sha256_hex(resource_id.as_bytes());
    let txn_id = format!(
        "outbound_{resource_kind}:{}:{}",
        &peer_hash[..16],
        &resource_hash[..16]
    );
    let attempted_at = now();
    let attempt = 1_u32;
    let retry_policy = json!({
        "initial_backoff_ms": 30_000,
        "max_backoff_ms": 300_000,
        "max_attempts": 8,
        "jitter": "deterministic_floor_until_background_daemon_lands"
    });
    let next_retry_at = attempted_at + Duration::seconds(30);
    let target_path = match resource_kind {
        "seal" => "/_cokret/peer/events",
        _ => "/_cokret/peer/events",
    };
    let intent = json!({
        "schema": "ck.federation.outbound_fanout.intent.v1",
        "origin": state.config.service_did,
        "destination": peer,
        "resource_kind": resource_kind,
        "resource_id": resource_id,
        "target_path": target_path,
        "attempt": attempt,
        "created_at": attempted_at,
    });
    let signing = signed_fanout_intent_evidence(state, peer, target_path, &intent, attempted_at);
    let transcript = json!({
        "schema": "ck.federation.outbound_fanout.transcript.v1",
        "direction": "outbound",
        "resource_kind": resource_kind,
        "resource_id": resource_id,
        "peer": peer,
        "target_path": target_path,
        "origin": state.config.service_did,
        "attempt": attempt,
        "state": "retry_scheduled",
        "intent": intent,
        "signing": signing,
        "dispatch_attempt": {
            "status": "signed_request_prepared",
            "method": "POST",
            "peer": peer,
            "path": target_path,
            "signature_scheme": "rfc9421-http-message-signatures",
            "prepared_at": attempted_at,
            "peer_response_recorded": false
        },
        "per_peer_state": {
            "peer": peer,
            "state": "retry_scheduled",
            "last_attempt_at": attempted_at,
            "next_retry_at": next_retry_at,
            "attempt": attempt,
            "accepted_by_peer": false,
            "last_error": {
                "code": "peer_delivery_not_confirmed",
                "message": "signed outbound federation request prepared; peer response not yet recorded"
            }
        },
        "retry": {
            "status": "retry_scheduled",
            "attempt": attempt,
            "next_retry_at": next_retry_at,
            "policy": retry_policy,
            "worker": "run_outbound_fanout_retry_pass",
            "durable": true
        },
        "durability": {
            "status": "persisted_before_dispatch",
            "store": "federation_transactions",
            "record_key": {
                "origin": state.config.service_did,
                "txn_id": txn_id
            },
            "content_digest_scope": "transcript_json"
        },
        "limitations": {
            "profile": "ck.profile.principal_server.v1",
            "full_conformance": false,
            "remaining": [
                "long-running retry daemon scheduling",
                "peer response verification and quarantine",
                "revocation fanout"
            ]
        }
    });
    let digest = format!(
        "sha256:{}",
        sha256_hex(&serde_json::to_vec(&transcript).unwrap_or_default())
    );
    let now = now();
    let record = FederationTransactionRecord {
        origin: state.config.service_did.clone(),
        txn_id,
        destination: peer.to_owned(),
        realm_id: None,
        content_digest: digest,
        status: "outbound_fanout_retry_scheduled".to_owned(),
        response: transcript,
        received_at: now,
        processed_at: Some(attempted_at),
    };
    if let Err(error) = state
        .persistence
        .federation_transactions()
        .put(&record)
        .await
    {
        tracing::warn!(
            %error,
            %peer,
            resource_kind,
            resource_id,
            "failed to persist outbound federation fanout transcript"
        );
    }
}

fn signed_fanout_intent_evidence(
    state: &AppState,
    peer: &str,
    target_path: &str,
    intent: &serde_json::Value,
    attempted_at: DateTime<Utc>,
) -> serde_json::Value {
    let canonical_bytes = cokret_sdk::canonical::canonical_json_bytes(intent)
        .unwrap_or_else(|_| serde_json::to_vec(intent).unwrap_or_default());
    let payload_digest = cokret_sdk::canonical::sha256_digest(&canonical_bytes);
    let protected_header = br#"{"alg":"EdDSA","typ":"ck.federation.outbound_fanout.intent.v1"}"#;
    let protected_b64u = URL_SAFE_NO_PAD.encode(protected_header);
    let payload_b64u = URL_SAFE_NO_PAD.encode(&canonical_bytes);
    let signing_input = format!("{protected_b64u}.{payload_b64u}");
    let signature = state.notary_signing_key().sign(signing_input.as_bytes());
    let signature_b64u = URL_SAFE_NO_PAD.encode(signature.to_bytes());
    let jws = format!("{protected_b64u}..{signature_b64u}");
    let key_origin = match state.notary_signing_key_origin() {
        crate::config::NotarySigningKeyOrigin::Configured => "configured",
        crate::config::NotarySigningKeyOrigin::Ephemeral => "ephemeral",
    };
    json!({
        "status": "intent_signed",
        "scheme": "ed25519-detached-jws",
        "verification_method": format!("{}#federation-fanout-key", state.config.service_did),
        "payload_digest": payload_digest,
        "jws": jws,
        "key_origin": key_origin,
        "http_message_signatures": http_message_signature_evidence(
            state,
            peer,
            target_path,
            &canonical_bytes,
            &payload_digest,
            attempted_at,
            key_origin,
        )
    })
}

fn http_message_signature_evidence(
    state: &AppState,
    peer: &str,
    target_path: &str,
    body_bytes: &[u8],
    payload_digest: &str,
    attempted_at: DateTime<Utc>,
    key_origin: &str,
) -> Value {
    let created = attempted_at.timestamp();
    let content_digest = content_digest_header(body_bytes);
    let keyid = format!("{}#federation-fanout-key", state.config.service_did);
    let signature_params = format!(
        "(\"@method\" \"@path\" \"content-digest\" \"x-cokret-fanout-digest\");created={created};keyid=\"{keyid}\";alg=\"ed25519\""
    );
    let signature_input_header = format!("sig1={signature_params}");
    let signature_base = format!(
        "\"@method\": POST\n\"@path\": {target_path}\n\"content-digest\": {content_digest}\n\"x-cokret-fanout-digest\": {payload_digest}\n\"@signature-params\": {signature_params}"
    );
    let signature = state.notary_signing_key().sign(signature_base.as_bytes());
    let signature_header = format!("sig1=:{}:", STANDARD.encode(signature.to_bytes()));
    json!({
        "status": "emitted",
        "scheme": "rfc9421-http-message-signatures",
        "request": {
            "method": "POST",
            "peer": peer,
            "path": target_path,
        },
        "covered_components": [
            "@method",
            "@path",
            "content-digest",
            "x-cokret-fanout-digest"
        ],
        "headers": {
            "content-digest": content_digest,
            "signature-input": signature_input_header,
            "signature": signature_header,
            "x-cokret-fanout-digest": payload_digest
        },
        "signature_base": signature_base,
        "verification_material": {
            "keyid": keyid,
            "alg": "ed25519",
            "key_origin": key_origin,
            "public_key_material": "service DID document verification method"
        }
    })
}

fn content_digest_header(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    format!("sha-256=:{}:", STANDARD.encode(digest))
}

#[cfg(test)]
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct OutboundFanoutRetryReport {
    pub scanned: usize,
    pub due: usize,
    pub retried: usize,
    pub dead_lettered: usize,
    pub skipped: usize,
}

#[cfg(test)]
async fn run_outbound_fanout_retry_pass_at(
    state: &AppState,
    node_id: &str,
    limit: usize,
    now: DateTime<Utc>,
) -> crate::persistence::PersistenceResult<OutboundFanoutRetryReport> {
    let mut report = OutboundFanoutRetryReport::default();
    if limit == 0 {
        return Ok(report);
    }

    let records = state
        .persistence
        .federation_transactions()
        .snapshot_all()
        .await?;
    for record in records {
        report.scanned += 1;
        if record.origin != state.config.service_did || !record.txn_id.starts_with("outbound_") {
            report.skipped += 1;
            continue;
        }
        if !matches!(
            record.status.as_str(),
            "outbound_fanout_limited" | "outbound_fanout_retry_scheduled"
        ) {
            report.skipped += 1;
            continue;
        }
        let Some(next_retry_at) = next_retry_at(&record.response) else {
            report.skipped += 1;
            continue;
        };
        if next_retry_at > now {
            report.skipped += 1;
            continue;
        }
        if report.retried + report.dead_lettered >= limit {
            break;
        }

        report.due += 1;
        let updated = update_retry_record(record, node_id, now);
        if updated.status == "outbound_fanout_dead_letter" {
            report.dead_lettered += 1;
        } else {
            report.retried += 1;
        }
        state
            .persistence
            .federation_transactions()
            .put(&updated)
            .await?;
    }

    Ok(report)
}

#[cfg(test)]
fn next_retry_at(response: &Value) -> Option<DateTime<Utc>> {
    response
        .pointer("/per_peer_state/next_retry_at")
        .and_then(Value::as_str)
        .and_then(|value| DateTime::parse_from_rfc3339(value).ok())
        .map(|value| value.with_timezone(&Utc))
}

#[cfg(test)]
fn update_retry_record(
    record: FederationTransactionRecord,
    node_id: &str,
    now: DateTime<Utc>,
) -> FederationTransactionRecord {
    let mut response = record.response.clone();
    let attempt = response
        .pointer("/per_peer_state/attempt")
        .and_then(Value::as_u64)
        .unwrap_or(1)
        + 1;
    let max_attempts = response
        .pointer("/retry/policy/max_attempts")
        .and_then(Value::as_u64)
        .unwrap_or(8);
    let lease_until = now + Duration::seconds(60);
    let lease = json!({
        "holder": node_id,
        "leased_at": now,
        "lease_until": lease_until,
        "fence": format!("{}:{attempt}", record.txn_id)
    });

    let (status, peer_state, next_retry) = if attempt >= max_attempts {
        ("outbound_fanout_dead_letter", "dead_letter", Value::Null)
    } else {
        let backoff_ms = retry_backoff_ms(&response, attempt);
        (
            "outbound_fanout_retry_scheduled",
            "retry_scheduled",
            json!(now + Duration::milliseconds(backoff_ms as i64)),
        )
    };

    response["state"] = Value::String(peer_state.to_owned());
    response["attempt"] = json!(attempt);
    response["per_peer_state"]["state"] = Value::String(peer_state.to_owned());
    response["per_peer_state"]["attempt"] = json!(attempt);
    response["per_peer_state"]["last_attempt_at"] = json!(now);
    response["per_peer_state"]["next_retry_at"] = next_retry.clone();
    response["per_peer_state"]["lease"] = lease.clone();
    response["per_peer_state"]["accepted_by_peer"] = Value::Bool(false);
    response["per_peer_state"]["last_error"] = if status == "outbound_fanout_dead_letter" {
        json!({
            "code": "max_attempts_exhausted",
            "message": "outbound federation delivery reached the durable retry limit"
        })
    } else {
        json!({
            "code": "peer_delivery_not_confirmed",
            "message": "durable retry pass claimed the transcript; signed delivery still awaits peer confirmation"
        })
    };
    response["retry"]["status"] = if status == "outbound_fanout_dead_letter" {
        Value::String("dead_lettered".to_owned())
    } else {
        Value::String("retry_scheduled".to_owned())
    };
    response["retry"]["attempt"] = json!(attempt);
    response["retry"]["next_retry_at"] = next_retry;
    response["retry"]["lease"] = lease;
    response["retry"]["last_worker"] = json!({
        "node_id": node_id,
        "observed_at": now,
    });

    let digest = format!(
        "sha256:{}",
        sha256_hex(&serde_json::to_vec(&response).unwrap_or_default())
    );
    FederationTransactionRecord {
        status: status.to_owned(),
        response,
        content_digest: digest,
        processed_at: Some(now),
        ..record
    }
}

#[cfg(test)]
fn retry_backoff_ms(response: &Value, attempt: u64) -> u64 {
    let initial = response
        .pointer("/retry/policy/initial_backoff_ms")
        .and_then(Value::as_u64)
        .unwrap_or(30_000);
    let max = response
        .pointer("/retry/policy/max_backoff_ms")
        .and_then(Value::as_u64)
        .unwrap_or(300_000);
    let multiplier = 1_u64
        .checked_shl((attempt.saturating_sub(1)) as u32)
        .unwrap_or(u64::MAX);
    initial.saturating_mul(multiplier).min(max)
}

/// Stream-F (Wave 2C) — test-only helper that materialises an
/// `AppState` with the given federation peer set and erasure-receipt
/// propagation window. Lives behind `cfg(test)` so it's only compiled
/// for the test runner. Used by the
/// `crate::routing::federation::erasure_fanout::tests` module to
/// drive deterministic fanout + sweep behaviour without standing up
/// the full HTTP server.
#[cfg(test)]
pub(crate) fn test_app_state_with_peers(
    peers: Vec<String>,
    erasure_propagation_window_ms: u64,
) -> crate::state::AppState {
    use std::net::SocketAddr;
    use std::str::FromStr;

    use crate::config::{AppConfig, FederationPolicy};
    use crate::db::Db;
    use crate::state::AppState;

    let cfg = AppConfig {
        bind: SocketAddr::from_str("127.0.0.1:0").unwrap(),
        metrics_bind: SocketAddr::from_str("127.0.0.1:0").unwrap(),
        public_base_url: "http://test".to_owned(),
        service_did: "did:web:test.local".to_owned(),
        tls_cert_path: None,
        tls_key_path: None,
        database_url: None,
        object_storage: crate::config::ObjectStorageConfig::local(std::env::temp_dir()),
        ice: crate::config::IceServersConfig::default(),
        cors_allow_origin: None,
        auth_server_url: None,
        development_mode: true,
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
        jws_replay_window_per_family: AppConfig::default_replay_overrides(),
        notary_signing_key_seed: None,
        agent_audit_binding_signing_seed: None,
        use_keystore: false,
        federation_policy: FederationPolicy::Mesh,
        federation_peers: peers,
        federation_outbound_enabled: false,
        admin_default_page_limit: 100,
        admin_max_page_limit: 1000,
        admin_principal_dids: Vec::new(),
        push_bridge_cache_ttl_seconds: 900,
        push_bridge_trusted_service_dids: Vec::new(),
        resumable_upload_dir: std::path::PathBuf::from("./soland-resumable-uploads"),
        resumable_upload_incomplete_ttl_seconds: 86_400,
        seal_compaction_min_age_seconds: 604_800,
        compaction_min_witnesses: 1,
        compaction_preserve_genesis: true,
        compaction_prune_only_singleton_successors: true,
        compaction_prune_walk_interval_seconds: 0,
        compaction_prune_walk_per_realm_limit: 50,
        seed_demo_data: false,
        trust_domain: "ck:trust_domain:soland.local".to_owned(),
        sovereign_enclave_enabled: false,
        sovereign_enclave_allowed_outbound_hosts: Vec::new(),
        erasure_propagation_window_ms,
        log_format: crate::config::LogFormat::Plain,
    };
    AppState::new(cfg, Db { pool: None })
}

#[cfg(test)]
#[path = "federation_tests.rs"]
mod tests;

// ════════════════════════════════════════════════════════════════════════
// Federation S2S trust-domain headers, idempotency cache key, delivery
// binding handover (spec B1.7 / B1.8 / B1.9 / T14).
// ════════════════════════════════════════════════════════════════════════

/// Spec B1.7 — the three federation trust-domain headers that MUST appear
/// on every inbound federation request.
#[derive(Debug, Clone)]
pub(crate) struct FederationTrustHeaders {
    pub source_trust_domain: cokret_sdk::TypedTrustDomainId,
    pub destination_trust_domain: cokret_sdk::TypedTrustDomainId,
    pub request_canonical_digest: cokret_sdk::Hash,
}

impl FederationTrustHeaders {
    /// Spec B1.7 — extract + validate the three headers from a salvo
    /// `Request`. Returns the typed triple on success or a
    /// [`HeaderViolation`] on the first missing / malformed header.
    pub(crate) fn from_salvo_request(req: &salvo::http::Request) -> Result<Self, HeaderViolation> {
        let header_value = |name: &str| -> Result<&str, HeaderViolation> {
            let value = req
                .headers()
                .get(name)
                .ok_or_else(|| HeaderViolation::Missing(name.to_owned()))?;
            value
                .to_str()
                .map_err(|_| HeaderViolation::Malformed(name.to_owned()))
        };
        let source = header_value(cokret_sdk::HEADER_SOURCE_TRUST_DOMAIN)?.to_owned();
        let destination = header_value(cokret_sdk::HEADER_DESTINATION_TRUST_DOMAIN)?.to_owned();
        let canonical_hash = header_value(cokret_sdk::HEADER_REQUEST_CANONICAL_DIGEST)?.to_owned();
        let source = cokret_sdk::TypedTrustDomainId::new(source).map_err(|_| {
            HeaderViolation::Malformed(cokret_sdk::HEADER_SOURCE_TRUST_DOMAIN.to_owned())
        })?;
        let destination = cokret_sdk::TypedTrustDomainId::new(destination).map_err(|_| {
            HeaderViolation::Malformed(cokret_sdk::HEADER_DESTINATION_TRUST_DOMAIN.to_owned())
        })?;
        let canonical_hash = cokret_sdk::Hash::new(canonical_hash).map_err(|_| {
            HeaderViolation::Malformed(cokret_sdk::HEADER_REQUEST_CANONICAL_DIGEST.to_owned())
        })?;
        Ok(Self {
            source_trust_domain: source,
            destination_trust_domain: destination,
            request_canonical_digest: canonical_hash,
        })
    }

    /// Spec B1.7 — verify the inbound `destination_trust_domain` matches
    /// the receiver's configured trust domain. Mismatch →
    /// `cross_domain_replay_rejected`.
    pub(crate) fn verify_destination(
        &self,
        expected: &cokret_sdk::TypedTrustDomainId,
    ) -> Result<(), &'static str> {
        if self.destination_trust_domain != *expected {
            return Err(cokret_sdk::ERROR_CODE_CROSS_DOMAIN_REPLAY_REJECTED);
        }
        Ok(())
    }

    /// Spec B1.7 — build the canonical signing-transcript fragment for
    /// inclusion in the message-signature transcript. Delegates to the SDK
    /// helper to keep producer + consumer byte-for-byte identical.
    pub(crate) fn transcript_fragment(&self) -> String {
        cokret_sdk::federation_trust_domain_transcript_fragment(
            &self.source_trust_domain,
            &self.destination_trust_domain,
            &self.request_canonical_digest,
        )
    }
}

/// Spec B1.7 — reasons a federation header check can fail.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum HeaderViolation {
    Missing(String),
    Malformed(String),
}

impl HeaderViolation {
    pub(crate) fn error_code(&self) -> &'static str {
        cokret_sdk::ERROR_CODE_SCHEMA_VIOLATION
    }

    pub(crate) fn message(&self) -> String {
        match self {
            Self::Missing(name) => format!("required federation header {name} missing"),
            Self::Malformed(name) => format!("federation header {name} malformed"),
        }
    }
}

/// Spec B1.8 — composite idempotency cache key. The pre-existing key did
/// NOT incorporate `request_canonical_digest` or `origin_key_state_digest`;
/// a replay after key revocation could mine fresh side effects. This key
/// mixes both in so a cache hit requires the key state to be unchanged.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct FederationIdempotencyKey {
    pub source_did: String,
    pub dest_did: String,
    pub request_canonical_digest: String,
    pub idempotency_key: String,
    pub origin_key_state_digest: String,
}

impl FederationIdempotencyKey {
    /// Strict key — equal to a cached entry only when ALL fields match,
    /// including the origin's current key state hash.
    pub(crate) fn strict(&self) -> String {
        let canonical = cokret_sdk::canonical::canonical_json_bytes(&json!({
            "source_did": self.source_did,
            "dest_did": self.dest_did,
            "request_canonical_digest": self.request_canonical_digest,
            "idempotency_key": self.idempotency_key,
            "origin_key_state_digest": self.origin_key_state_digest,
        }))
        .unwrap_or_default();
        cokret_sdk::canonical::sha256_digest(&canonical)
    }

    /// Canonical-replay key — drops `origin_key_state_digest`. Used to
    /// detect a replay AFTER the source service rotated its keys.
    pub(crate) fn canonical_replay(&self) -> String {
        let canonical = cokret_sdk::canonical::canonical_json_bytes(&json!({
            "source_did": self.source_did,
            "dest_did": self.dest_did,
            "request_canonical_digest": self.request_canonical_digest,
            "idempotency_key": self.idempotency_key,
        }))
        .unwrap_or_default();
        cokret_sdk::canonical::sha256_digest(&canonical)
    }
}

/// Spec T14 — fields added to the federation idempotency cache key so a
/// replay after key revoke is recognised as a stale historical request
/// rather than a fresh one.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub(crate) struct FederationIdempotencyServiceBinding {
    pub source_service_did: String,
    pub verification_method: String,
    pub service_binding_ref: String,
    pub origin_key_state_digest: String,
}

/// Spec T14 — marker set on a cached federation response that is replayed
/// after the source service rotated its verification key.
pub(crate) const HISTORICAL_ONLY_MARKER: &str = "historical_only";

/// Spec B1.8 — mark a federation response with
/// `reason_code=historical_only`. Receivers MUST set this whenever the
/// cache hit was a canonical-replay (post-key-rotation) rather than a
/// strict-key hit.
pub(crate) fn mark_response_historical_only(mut response: Value) -> Value {
    if let Some(object) = response.as_object_mut() {
        object.insert(
            "reason_code".to_owned(),
            Value::String(cokret_sdk::ERROR_CODE_HISTORICAL_ONLY.to_owned()),
        );
        object.insert(HISTORICAL_ONLY_MARKER.to_owned(), Value::Bool(true));
    }
    response
}

/// Spec B1.9 — emit-shape for `delivery_binding_stale` (409). Returned
/// when a peer attempts to push events using a stale delivery binding. The
/// response carries the new recipient service DID and a frontier the sender
/// should replay from after re-binding.
#[allow(dead_code)]
pub(crate) fn delivery_binding_stale_response(
    new_recipient_service_did: &Did,
    handover_frontier: &[cokret_sdk::EventId],
) -> Value {
    json!({
        "ok": false,
        "error": {
            "code": cokret_sdk::ERROR_CODE_DELIVERY_BINDING_STALE,
            "message": "delivery binding is stale; rebind to the new recipient service",
            "details": {
                "new_recipient_service_did": new_recipient_service_did.as_str(),
                "handover_frontier": handover_frontier
                    .iter()
                    .map(|e| e.as_str())
                    .collect::<Vec<_>>(),
            }
        }
    })
}

/// Spec B1.9 — emit-shape for `delivery_binding_handed_over` (409).
/// Returned when the inbound delivery is a duplicate of a binding that has
/// already been handed over to the new recipient.
#[allow(dead_code)]
pub(crate) fn delivery_binding_handed_over_response(new_recipient_service_did: &Did) -> Value {
    json!({
        "ok": false,
        "error": {
            "code": cokret_sdk::ERROR_CODE_DELIVERY_BINDING_HANDED_OVER,
            "message": "delivery binding has already been handed over to the new recipient",
            "details": {
                "new_recipient_service_did": new_recipient_service_did.as_str(),
            }
        }
    })
}

#[cfg(test)]
mod federation_wire_tests {
    use super::*;

    #[test]
    fn federation_idempotency_strict_key_changes_with_key_state_digest() {
        let mut key = FederationIdempotencyKey {
            source_did: "did:web:alice.example".to_owned(),
            dest_did: "did:web:bob.example".to_owned(),
            request_canonical_digest: "sha256:abc".to_owned(),
            idempotency_key: "idem-1".to_owned(),
            origin_key_state_digest: "sha256:state-A".to_owned(),
        };
        let strict_a = key.strict();
        let replay_a = key.canonical_replay();
        key.origin_key_state_digest = "sha256:state-B".to_owned();
        let strict_b = key.strict();
        let replay_b = key.canonical_replay();
        assert_ne!(strict_a, strict_b);
        assert_eq!(replay_a, replay_b);
    }

    #[test]
    fn historical_only_marker_set() {
        let response = mark_response_historical_only(json!({"ok": true}));
        assert_eq!(
            response.get("reason_code").and_then(Value::as_str),
            Some(cokret_sdk::ERROR_CODE_HISTORICAL_ONLY)
        );
        assert_eq!(
            response.get("historical_only").and_then(Value::as_bool),
            Some(true)
        );
    }

    #[test]
    fn delivery_binding_stale_response_carries_new_service_and_frontier() {
        let response = delivery_binding_stale_response(
            &Did::new("did:web:bob.example").unwrap(),
            &[cokret_sdk::EventId::new("ck:event:01904100-0000-7000-8000-000000000001").unwrap()],
        );
        assert_eq!(
            response.pointer("/error/code").and_then(Value::as_str),
            Some(cokret_sdk::ERROR_CODE_DELIVERY_BINDING_STALE)
        );
        assert_eq!(
            response
                .pointer("/error/details/new_recipient_service_did")
                .and_then(Value::as_str),
            Some("did:web:bob.example")
        );
    }
}
