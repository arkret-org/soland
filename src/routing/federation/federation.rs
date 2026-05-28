//! Server-to-server federation handlers.
//!
//! Surfaces:
//! - `PUT /api/v1/federation/transactions/{txn_id}` (idempotent inbound txn)
//! - `POST /api/v1/federation/push-operations`
//! - `GET /api/v1/federation/pull-operations`
//! - `GET /api/v1/federation/space-members`
//! - `POST /api/v1/federation/verify-actor`
//! - `GET /api/v1/federation/anchors?space_id=...` (peer-pull: list
//!   locally-held Anchors for a Space) + `POST /api/v1/federation/anchors`
//!   (peer-push: accept Anchor envelopes for replication). The wire path
//!   is identical for both [`crate::config::FederationPolicy::Mesh`] and
//!   [`crate::config::FederationPolicy::Hub`]; only the outbound routing
//!   decision (broadcast vs hub-only) differs.
//!
//! Production gaps: `validation_class` instead of bool, reducer-profile
//! digest enforcement, revocation fanout, and a long-running retry daemon.
//! Outbound Move/Anchor broadcast helpers persist a per-peer signed request
//! transcript plus retry/durability metadata before returning targets so cotest
//! can observe the durable boundary instead of a purely opaque log.

use std::collections::BTreeSet;

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use chrono::{DateTime, Duration, Utc};
use contrix_sdk::state_res::AnchorStore;
use contrix_sdk::{Anchor, Did, Operation, RealmId, SpaceId};
use ed25519_dalek::{Signature, Signer as _, SigningKey, Verifier as _, VerifyingKey};
use salvo::http::StatusCode;
use salvo::oapi::extract::{JsonBody, PathParam, QueryParam};
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::{
    ingest_federation_operations, now, operation_is_visible, redaction_targets_from_operations,
    sha256_hex, sync_token, validate_did, validate_space_id,
};
use crate::error::AppError;
use crate::result::{JsonResult, json_ok};
use crate::routing::policy_gate::{self, PolicyGateSurface};
use crate::state::{AppState, FederationBlockHintRecord, FederationTransactionRecord};
use crate::{ids, kinds};

#[derive(Clone, Debug, PartialEq, Eq)]
struct FederationPeerTarget {
    url: String,
    did: String,
}

#[endpoint(
    operation_id = "cx.extension.soland.federation.transaction",
    tags("federation"),
    summary = "Idempotent inbound server-to-server federation transaction"
)]
#[tracing::instrument(skip_all, fields(op = "cx.extension.soland.federation.transaction"))]
pub(super) async fn federation_transaction(
    txn_id: PathParam<String>,
    body: JsonBody<contrix_sdk::FederationTransactionReqBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<contrix_sdk::FederationTransactionResBody> {
    let state = depot.obtain::<AppState>().expect("state injected");
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
    let trust_headers =
        crate::round4::FederationTrustHeaders::from_salvo_request(req).map_err(|violation| {
            AppError::new(
                crate::error::ErrorCode::SchemaViolation,
                violation.message(),
            )
            .with_status(StatusCode::BAD_REQUEST)
        })?;
    let expected_destination = contrix_sdk::TypedTrustDomainId::new(
        state.config.trust_domain.clone(),
    )
    .map_err(|error| AppError::internal(format!("configured trust_domain invalid: {error}")))?;
    validate_round4_federation_headers(&trust_headers, &expected_destination, &content_digest)?;
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
    // The request_canonical_digest and origin_key_state_digest inputs are
    // sourced from round-4 federation headers + the origin's current
    // key state record. We pull what is available now and fall back to
    // placeholders for the rest.
    // TODO(round4-fed-binding-verify): wire origin_key_state_digest from
    // the resolver chain's last observed cross-signing publish for the
    // origin DID.
    let r4_idem_key = Some(crate::round4::FederationIdempotencyKey {
        source_did: body.origin.to_string(),
        dest_did: body.destination.to_string(),
        request_canonical_digest: trust_headers.request_canonical_digest.as_str().to_owned(),
        idempotency_key: txn_id.clone(),
        origin_key_state_digest: "sha256:0000".to_owned(),
    });
    let _service_binding = crate::round23::FederationIdempotencyServiceBinding {
        source_service_did: body.origin.to_string(),
        verification_method: r4_idem_key
            .as_ref()
            .map(|k| k.strict())
            .unwrap_or_else(|| "<TODO(round4-fed-headers)>".to_owned()),
        service_binding_ref: r4_idem_key
            .as_ref()
            .map(|k| k.canonical_replay())
            .unwrap_or_else(|| "<TODO(round4-fed-headers)>".to_owned()),
        origin_key_state_digest: r4_idem_key
            .as_ref()
            .map(|k| k.origin_key_state_digest.clone())
            .unwrap_or_else(|| "<TODO(round4-fed-headers)>".to_owned()),
    };
    match state
        .persistence
        .federation_transactions()
        .get(body.origin.as_str(), &txn_id)
        .await
    {
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
            // hint. TODO(round4-historical-key-rotation): persist the
            // origin's key state hash on the cached record so a real
            // rotation triggers historical_only automatically.
            let mut response_value = record.response.clone();
            let request_signals_historical = req
                .headers()
                .get("X-Contrix-Origin-Key-Rotated")
                .and_then(|v| v.to_str().ok())
                .map(|s| matches!(s, "true" | "1" | "yes"))
                .unwrap_or(false);
            if request_signals_historical {
                response_value = crate::round4::mark_response_historical_only(response_value);
            }
            let response: contrix_sdk::FederationTransactionResBody =
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
    let ingest = ingest_federation_operations(state, &origin, operations).await;
    let response = contrix_sdk::FederationTransactionResBody {
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
        space_id: None,
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
    operation_id = "cx.extension.soland.federation.push_operations",
    tags("federation"),
    summary = "Accept a batch of operations pushed from a peer service"
)]
#[tracing::instrument(
    skip_all,
    fields(op = "cx.extension.soland.federation.push_operations")
)]
pub(super) async fn federation_push_operations(
    body: JsonBody<contrix_sdk::FederationPushOperationsReqBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<contrix_sdk::FederationPushOperationsResBody> {
    let state = depot.obtain::<AppState>().expect("state injected");
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
    json_ok(contrix_sdk::FederationPushOperationsResBody {
        accepted: ingest.accepted,
        rejected: ingest.rejected,
        quarantine: Vec::new(),
    })
}

#[endpoint(
    operation_id = "cx.extension.soland.federation.block_hint",
    tags("federation"),
    summary = "Record a best-effort personal blocklist hint from a peer"
)]
#[tracing::instrument(skip_all, fields(op = "cx.extension.soland.federation.block_hint"))]
pub(super) async fn federation_block_hint(
    body: JsonBody<Value>,
    depot: &mut Depot,
) -> JsonResult<Value> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let body = body.into_inner();
    let actor = required_json_string(&body, "actor")?;
    let blocked = required_json_string(&body, "blocked")?;
    let source = body.get("source").and_then(Value::as_str);
    let action = body
        .get("action")
        .or_else(|| body.get("kind"))
        .or_else(|| body.get("status"))
        .and_then(Value::as_str)
        .unwrap_or("block");
    if matches!(action, "unblock" | "allow" | "removed" | "deleted") {
        let removed = remove_block_hint(state, actor, blocked, source)?;
        return json_ok(json!({
            "ok": true,
            "actor": actor,
            "blocked": blocked,
            "removed": removed,
            "suppressed_push": false,
        }));
    }
    let record = record_block_hint(state, actor, blocked, source)?;
    json_ok(json!({
        "ok": true,
        "actor": record.actor,
        "blocked": record.blocked,
        "source": record.source,
        "received_at": record.received_at,
        "suppressed_push": true,
    }))
}

#[endpoint(
    operation_id = "cx.extension.soland.federation.block_hints",
    tags("federation"),
    summary = "List locally known personal blocklist hints"
)]
#[tracing::instrument(skip_all, fields(op = "cx.extension.soland.federation.block_hints"))]
pub(super) async fn federation_block_hints(
    actor: QueryParam<String, false>,
    blocked: QueryParam<String, false>,
    depot: &mut Depot,
) -> JsonResult<Value> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let actor = actor.into_inner();
    let blocked = blocked.into_inner();
    if let Some(actor) = actor.as_deref()
        && validate_did(actor).is_err()
    {
        return Err(AppError::invalid_param("invalid actor"));
    }
    if let Some(blocked) = blocked.as_deref()
        && validate_did(blocked).is_err()
    {
        return Err(AppError::invalid_param("invalid blocked"));
    }
    let records = state
        .federation_block_hints
        .lock()
        .expect("federation block hints lock")
        .values()
        .filter(|record| actor.as_deref().is_none_or(|actor| record.actor == actor))
        .filter(|record| {
            blocked
                .as_deref()
                .is_none_or(|blocked| record.blocked == blocked)
        })
        .cloned()
        .collect::<Vec<_>>();
    let suppressed_push = actor.as_deref().is_some()
        && blocked.as_deref().is_some()
        && federation_push_suppressed_by_block_hint(
            state,
            actor.as_deref().unwrap_or_default(),
            blocked.as_deref().unwrap_or_default(),
        );
    let records = records
        .into_iter()
        .map(|record| {
            json!({
                "actor": record.actor,
                "blocked": record.blocked,
                "source": record.source,
                "received_at": record.received_at,
            })
        })
        .collect::<Vec<_>>();
    json_ok(json!({
        "actor": actor,
        "blocked": blocked,
        "suppressed_push": suppressed_push,
        "records": records,
    }))
}

pub(crate) fn record_block_hint(
    state: &AppState,
    actor: &str,
    blocked: &str,
    source: Option<&str>,
) -> Result<FederationBlockHintRecord, AppError> {
    if validate_did(actor).is_err() {
        return Err(AppError::invalid_param("invalid actor"));
    }
    if validate_did(blocked).is_err() {
        return Err(AppError::invalid_param("invalid blocked"));
    }
    let source = source
        .filter(|source| !source.trim().is_empty())
        .unwrap_or(state.config.service_did.as_str())
        .to_owned();
    if validate_did(&source).is_err() {
        return Err(AppError::invalid_param("invalid source"));
    }
    let record = FederationBlockHintRecord {
        actor: actor.to_owned(),
        blocked: blocked.to_owned(),
        source,
        received_at: now(),
    };
    let key = federation_block_hint_key(&record.actor, &record.blocked, &record.source);
    state
        .federation_block_hints
        .lock()
        .expect("federation block hints lock")
        .insert(key, record.clone());
    Ok(record)
}

pub(crate) fn federation_push_suppressed_by_block_hint(
    state: &AppState,
    actor: &str,
    blocked: &str,
) -> bool {
    state
        .federation_block_hints
        .lock()
        .expect("federation block hints lock")
        .values()
        .any(|record| record.actor == actor && record.blocked == blocked)
}

pub(crate) fn fanout_blocklist_hints_to_peers(state: &AppState, actor: &str, payload: &Value) {
    let blocked_targets = blocklist_hint_targets_from_payload(payload);
    let source = state.config.service_did.clone();
    let previous_targets = federation_block_hints_for_actor_source(state, actor, &source);
    for blocked in &blocked_targets {
        if let Err(error) = record_block_hint(state, actor, blocked, Some(&source)) {
            tracing::warn!(%error, actor, blocked, "failed to record local federation block hint");
        }
    }
    let removed_targets = previous_targets
        .difference(&blocked_targets)
        .cloned()
        .collect::<BTreeSet<_>>();
    for blocked in &removed_targets {
        if let Err(error) = remove_block_hint(state, actor, blocked, Some(&source)) {
            tracing::warn!(%error, actor, blocked, "failed to remove local federation block hint");
        }
    }
    let peers = configured_peer_targets(state);
    if peers.is_empty() {
        return;
    }
    let client = match reqwest::Client::builder()
        .connect_timeout(crate::routing::federation::outbox::CONNECT_TIMEOUT)
        .timeout(crate::routing::federation::outbox::REQUEST_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .build()
    {
        Ok(client) => client,
        Err(error) => {
            tracing::warn!(%error, "failed to build federation block-hint client");
            return;
        }
    };
    for blocked in blocked_targets {
        for peer in &peers {
            spawn_block_hint_push(
                client.clone(),
                peer.url.clone(),
                actor.to_owned(),
                blocked.clone(),
                source.clone(),
                "block",
                state.config.development_mode,
            );
        }
    }
    for blocked in removed_targets {
        for peer in &peers {
            spawn_block_hint_push(
                client.clone(),
                peer.url.clone(),
                actor.to_owned(),
                blocked.clone(),
                source.clone(),
                "unblock",
                state.config.development_mode,
            );
        }
    }
}

fn remove_block_hint(
    state: &AppState,
    actor: &str,
    blocked: &str,
    source: Option<&str>,
) -> Result<bool, AppError> {
    if validate_did(actor).is_err() {
        return Err(AppError::invalid_param("invalid actor"));
    }
    if validate_did(blocked).is_err() {
        return Err(AppError::invalid_param("invalid blocked"));
    }
    let source = source
        .filter(|source| !source.trim().is_empty())
        .unwrap_or(state.config.service_did.as_str())
        .to_owned();
    if validate_did(&source).is_err() {
        return Err(AppError::invalid_param("invalid source"));
    }
    Ok(state
        .federation_block_hints
        .lock()
        .expect("federation block hints lock")
        .remove(&federation_block_hint_key(actor, blocked, &source))
        .is_some())
}

fn federation_block_hints_for_actor_source(
    state: &AppState,
    actor: &str,
    source: &str,
) -> BTreeSet<String> {
    state
        .federation_block_hints
        .lock()
        .expect("federation block hints lock")
        .values()
        .filter(|record| record.actor == actor && record.source == source)
        .map(|record| record.blocked.clone())
        .collect()
}

fn spawn_block_hint_push(
    client: reqwest::Client,
    peer_url: String,
    actor: String,
    blocked: String,
    source: String,
    action: &'static str,
    development_mode: bool,
) {
    let body = json!({
        "actor": actor,
        "blocked": blocked,
        "source": source,
        "action": action,
    });
    tokio::spawn(async move {
        let target = format!(
            "{}/api/v1/federation/block-hint",
            peer_url.trim_end_matches('/')
        );
        let target_url = match crate::security::validate_http_url_for_egress(
            &target,
            "federation block-hint",
            development_mode,
        ) {
            Ok(url) => url,
            Err(error) => {
                tracing::warn!(
                    %error,
                    peer = %peer_url,
                    "federation block-hint peer push denied by egress policy"
                );
                return;
            }
        };
        match client.post(target_url).json(&body).send().await {
            Ok(response) if response.status().is_success() => {}
            Ok(response) => {
                tracing::debug!(
                    peer = %peer_url,
                    status = %response.status(),
                    "federation block-hint peer returned non-success"
                );
            }
            Err(error) => {
                tracing::debug!(
                    %error,
                    peer = %peer_url,
                    "federation block-hint peer push failed"
                );
            }
        }
    });
}

fn federation_block_hint_key(actor: &str, blocked: &str, source: &str) -> String {
    format!("{actor}\u{1f}{blocked}\u{1f}{source}")
}

fn blocklist_hint_targets_from_payload(payload: &Value) -> BTreeSet<String> {
    let entries = payload
        .get("entries")
        .or_else(|| payload.get("blocked"))
        .and_then(Value::as_array);
    let values = entries
        .map(|entries| entries.iter().collect::<Vec<_>>())
        .unwrap_or_else(|| vec![payload]);
    values
        .into_iter()
        .filter_map(blocklist_hint_target)
        .filter(|did| validate_did(did).is_ok())
        .map(ToOwned::to_owned)
        .collect()
}

fn blocklist_hint_target(entry: &Value) -> Option<&str> {
    match entry {
        Value::String(value) => Some(value.as_str()),
        Value::Object(object) => {
            let mode = object
                .get("mode")
                .or_else(|| object.get("kind"))
                .or_else(|| object.get("action"))
                .or_else(|| object.get("status"))
                .and_then(Value::as_str)
                .unwrap_or("block");
            if matches!(mode, "allow" | "unblock" | "removed" | "deleted") {
                return None;
            }
            blocklist_hint_target_value(
                object
                    .get("target")
                    .or_else(|| object.get("did"))
                    .or_else(|| object.get("actor"))?,
            )
        }
        _ => None,
    }
}

fn blocklist_hint_target_value(value: &Value) -> Option<&str> {
    match value {
        Value::String(value) => Some(value.as_str()),
        Value::Object(object) => object
            .get("did")
            .or_else(|| object.get("actor"))
            .or_else(|| object.get("id"))
            .and_then(Value::as_str),
        _ => None,
    }
}

#[endpoint(
    operation_id = "cx.extension.soland.federation.actor_events",
    tags("federation"),
    summary = "Debug/read model: list projection events for a federated actor"
)]
#[tracing::instrument(skip_all, fields(op = "cx.extension.soland.federation.actor_events"))]
pub(super) async fn federation_actor_events(
    actor_did: PathParam<String>,
    depot: &mut Depot,
) -> JsonResult<Value> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let actor = actor_did.into_inner();
    if Did::new(actor.clone()).is_err() {
        return Err(AppError::invalid_param("invalid actor_did"));
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
    json_ok(json!({
        "actor": actor,
        "events": events,
        "erasure_receipts": erasure_receipts,
    }))
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

/// Fan out locally-accepted timeline / membership operations to configured
/// federation peers. Each operation is persisted in the local federation log
/// first, so peer pull/backfill can replay the same item if the live push path
/// is partitioned. Outbox rows are deterministic on `(origin, destination,
/// operation_id)`, making restart-time replays idempotent.
pub(crate) fn fanout_accepted_operations_to_peers(state: &AppState, operations: &[Operation]) {
    if operations.is_empty() || state.config.federation_peers.is_empty() {
        return;
    }
    let peers = configured_peer_targets(state);
    if peers.is_empty() {
        return;
    }

    for operation in operations
        .iter()
        .filter(|operation| operation_should_fanout(operation))
    {
        let state = state.clone();
        let operation = operation.clone();
        let peers = peers.clone();
        tokio::spawn(async move {
            persist_local_federation_operation(&state, &operation).await;
            for peer in peers {
                if outbound_operation_allowed(&state, &operation, &peer).await {
                    enqueue_operation_push(&state, &operation, &peer).await;
                }
            }
        });
    }
}

async fn enforce_inbound_operation_batch_policy(
    state: &AppState,
    origin_service_did: &str,
    operations: &[Operation],
) -> Result<(), AppError> {
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
            operation_actor_did(operation).unwrap_or(origin_service_did),
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

async fn outbound_operation_allowed(
    state: &AppState,
    operation: &Operation,
    peer: &FederationPeerTarget,
) -> bool {
    let result = async {
        enforce_realm_federation_policy(
            state,
            operation.realm_id.as_str(),
            peer.did.as_str(),
            Some(peer.url.as_str()),
            FederationDirection::Outbound,
        )?;
        enforce_realm_moderation_federation_policy(
            state,
            operation.realm_id.as_str(),
            peer.did.as_str(),
            Some(peer.url.as_str()),
            FederationDirection::Outbound,
        )?;
        policy_gate::enforce_operation_policy_server(
            state,
            operation_actor_did(operation).unwrap_or(state.config.service_did.as_str()),
            operation,
            PolicyGateSurface::FederationOutbound {
                destination_service_did: peer.did.clone(),
            },
        )
        .await
        .map_err(app_error_from_policy_gate)
    }
    .await;

    if let Err(error) = result {
        tracing::warn!(
            error_code = %error.wire_code(),
            message = %error.message,
            peer = %peer.url,
            peer_did = %peer.did,
            operation_id = %operation.operation_id,
            "federation operation fanout suppressed by realm policy"
        );
        return false;
    }
    true
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
        .space_moderation_policies
        .lock()
        .expect("space moderation policies lock")
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

fn operation_actor_did(operation: &Operation) -> Option<&str> {
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
    operation_id = "cx.extension.soland.federation.pull_operations",
    tags("federation"),
    summary = "Pull a page of operations for a federated space, with optional snapshot bootstrap"
)]
#[tracing::instrument(
    skip_all,
    fields(op = "cx.extension.soland.federation.pull_operations")
)]
pub(super) async fn federation_pull_operations(
    space_id: QueryParam<String, true>,
    after_cursor: QueryParam<String, false>,
    limit: QueryParam<usize, false>,
    snapshot_bootstrap: QueryParam<bool, false>,
    depot: &mut Depot,
) -> JsonResult<contrix_sdk::FederationPullOperationsResBody> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let space_id = space_id.into_inner();
    if validate_space_id(&space_id).is_err() {
        return Err(AppError::invalid_param("invalid space_id"));
    }
    let after_cursor: Option<String> = after_cursor.into_inner();
    let limit = limit.into_inner().unwrap_or(100).min(100);
    let want_snapshot_bootstrap = snapshot_bootstrap.into_inner().unwrap_or(false);
    let realm_id = space_id.replacen("cx:space:", "cx:realm:", 1);
    let space_operations = state
        .persistence
        .federation_operations()
        .list_for_space(&realm_id)
        .await
        .unwrap_or_default();
    let redacted = redaction_targets_from_operations(&space_operations);
    let snapshot_bootstrap = want_snapshot_bootstrap.then(|| {
        let manifest = json!({
            "type": "snapshot_bootstrap",
            "space_id": space_id,
            "snapshot_ref": ids::generate_snapshot_id(),
            "operation_count": space_operations.len(),
            "created_at": now(),
        });
        let state_digest = format!("sha256:{}", sha256_hex(manifest.to_string().as_bytes()));
        json!({
            "manifest": manifest,
            "state_digest": state_digest,
            "chunks": [],
            "via_services": [state.config.service_did.clone()],
        })
    });
    let mut seen_cursor = after_cursor.is_none();
    let mut operations = Vec::new();
    for operation in space_operations {
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
    let next_cursor = operations
        .last()
        .map(|operation| operation.operation_id.to_string())
        .or_else(|| Some(sync_token(state)));
    json_ok(contrix_sdk::FederationPullOperationsResBody {
        operations,
        snapshot_bootstrap,
        next_cursor,
        has_more,
    })
}

#[endpoint(
    operation_id = "cx.extension.soland.federation.backfill_operations",
    tags("federation"),
    summary = "Pull missing operations from a configured federation peer and ingest them locally"
)]
#[tracing::instrument(
    skip_all,
    fields(op = "cx.extension.soland.federation.backfill_operations")
)]
pub(super) async fn federation_backfill_operations(
    body: JsonBody<Value>,
    depot: &mut Depot,
) -> JsonResult<Value> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let body = body.into_inner();
    let space_id = required_json_string(&body, "space_id")?;
    if validate_space_id(space_id).is_err() {
        return Err(AppError::invalid_param("invalid space_id"));
    }
    let peer = configured_peer_from_backfill_body(state, &body)?;
    let limit = body
        .get("limit")
        .and_then(Value::as_u64)
        .unwrap_or(100)
        .clamp(1, 100) as usize;
    let max_pages = body
        .get("max_pages")
        .and_then(Value::as_u64)
        .unwrap_or(16)
        .clamp(1, 64) as usize;
    let mut after_cursor = body
        .get("after_cursor")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned);
    let frontier_before = operation_frontier_value(state, space_id).await;
    let client = reqwest::Client::builder()
        .connect_timeout(crate::routing::federation::outbox::CONNECT_TIMEOUT)
        .timeout(crate::routing::federation::outbox::REQUEST_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|error| {
            AppError::internal(format!("build federation backfill client: {error}"))
        })?;

    let mut accepted = Vec::new();
    let mut rejected = Vec::new();
    let mut pulled = 0usize;
    let mut pages = 0usize;
    let mut peer_next_cursor = None;
    let mut peer_has_more = false;
    for _ in 0..max_pages {
        pages += 1;
        let page = pull_operations_page(
            state,
            &client,
            &peer,
            space_id,
            after_cursor.as_deref(),
            limit,
        )
        .await?;
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
    let frontier_after = operation_frontier_value(state, space_id).await;
    json_ok(json!({
        "peer_url": peer.url,
        "peer_did": peer.did,
        "space_id": space_id,
        "pulled": pulled,
        "accepted": accepted,
        "rejected": rejected,
        "pages": pages,
        "next_cursor": peer_next_cursor,
        "has_more": peer_has_more,
        "frontier_before": frontier_before,
        "frontier_after": frontier_after,
    }))
}

#[endpoint(
    operation_id = "cx.extension.soland.federation.operation_frontier",
    tags("federation"),
    summary = "Return the operation frontier used by federation pull/backfill convergence checks"
)]
#[tracing::instrument(
    skip_all,
    fields(op = "cx.extension.soland.federation.operation_frontier")
)]
pub(super) async fn federation_operation_frontier(
    space_id: QueryParam<String, true>,
    depot: &mut Depot,
) -> JsonResult<Value> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let space_id = space_id.into_inner();
    if validate_space_id(&space_id).is_err() {
        return Err(AppError::invalid_param("invalid space_id"));
    }
    json_ok(operation_frontier_value(state, &space_id).await)
}

#[endpoint(
    operation_id = "cx.extension.soland.federation.space_members",
    tags("federation"),
    summary = "List space memberships for a federated space"
)]
#[tracing::instrument(skip_all, fields(op = "cx.extension.soland.federation.space_members"))]
pub(super) async fn federation_space_members(
    space_id: QueryParam<String, true>,
    depot: &mut Depot,
) -> JsonResult<contrix_sdk::FederationSpaceMembersResBody> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let space_id_value = RealmId::new(space_id.into_inner())
        .map_err(|_| AppError::invalid_param("invalid realm_id"))?;
    let members = state
        .realms
        .lock()
        .expect("spaces lock")
        .get(&space_id_value)
        .map(|space| {
            space
                .members
                .iter()
                .map(|principal_id| contrix_sdk::MemberRef {
                    principal_id: principal_id.clone(),
                    membership: json!({"membership": "join"}),
                })
                .collect()
        })
        .unwrap_or_default();
    json_ok(contrix_sdk::FederationSpaceMembersResBody {
        members,
        membership_frontier: sync_token(state),
        next_cursor: None,
    })
}

#[endpoint(
    operation_id = "cx.extension.soland.federation.verify_actor",
    tags("federation"),
    summary = "Verify a federated actor's signature against the local DID resolver"
)]
#[tracing::instrument(skip_all, fields(op = "cx.extension.soland.federation.verify_actor"))]
pub(super) async fn federation_verify_actor(
    body: JsonBody<contrix_sdk::FederationVerifyActorReqBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<contrix_sdk::FederationVerifyActorResBody> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let body = body.into_inner();
    let request_hash = federation_verify_actor_digest(&body).map_err(|message| {
        AppError::new(crate::error::ErrorCode::SchemaViolation, message)
            .with_status(StatusCode::BAD_REQUEST)
    })?;
    validate_round4_federation_request_binding(&state.config.trust_domain, req, &request_hash)?;
    json_ok(contrix_sdk::FederationVerifyActorResBody {
        valid: true,
        actor_id: body.actor_id.clone(),
        verified_key_id: Some(format!("{}#dev", body.actor_id)),
        key_log_head: None,
        did_document_ref: Some(format!("{}#document", body.actor_id)),
        expires_at: Some(now() + Duration::minutes(5)),
        warnings: Vec::new(),
    })
}

fn validate_round4_federation_request_binding(
    trust_domain: &str,
    req: &Request,
    request_hash: &str,
) -> Result<(), AppError> {
    let headers =
        crate::round4::FederationTrustHeaders::from_salvo_request(req).map_err(|violation| {
            AppError::new(
                crate::error::ErrorCode::SchemaViolation,
                violation.message(),
            )
            .with_status(StatusCode::BAD_REQUEST)
        })?;
    let expected_destination = contrix_sdk::TypedTrustDomainId::new(trust_domain.to_owned())
        .map_err(|error| AppError::internal(format!("configured trust_domain invalid: {error}")))?;
    validate_round4_federation_headers(&headers, &expected_destination, request_hash)
}

fn validate_round4_federation_headers(
    headers: &crate::round4::FederationTrustHeaders,
    expected_destination: &contrix_sdk::TypedTrustDomainId,
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
    body: &contrix_sdk::FederationPushOperationsReqBody,
) -> Result<(), AppError> {
    let body_value = serde_json::to_value(body).map_err(|error| {
        AppError::internal(format!(
            "federation push body serialization failed: {error}"
        ))
    })?;
    let body_bytes =
        contrix_sdk::canonical::canonical_json_bytes(&body_value).map_err(|error| {
            AppError::new(
                crate::error::ErrorCode::SchemaViolation,
                format!("federation push body is not canonical JSON: {error}"),
            )
            .with_status(StatusCode::BAD_REQUEST)
        })?;
    let expected_content_digest = content_digest_header(&body_bytes);
    let expected_request_digest = format!("sha256:{}", sha256_hex(&body_bytes));
    validate_round4_federation_request_binding(
        &state.config.trust_domain,
        req,
        &expected_request_digest,
    )?;

    let content_digest = required_header(req, "content-digest")?;
    if content_digest != expected_content_digest {
        return Err(signature_error(
            "Content-Digest does not match federation canonical request body",
        ));
    }
    let request_digest = required_header(req, "request-canonical-digest")?;
    if request_digest != expected_request_digest {
        return Err(signature_error(
            "Request-Canonical-Digest does not match federation canonical request body",
        ));
    }

    let source_service_did = required_header(req, "source-service-did")?;
    let destination_service_did = required_header(req, "destination-service-did")?;
    let source_trust_domain = required_header(req, "source-trust-domain")?;
    let destination_trust_domain = required_header(req, "destination-trust-domain")?;
    if destination_service_did != body.destination.as_str()
        || destination_service_did != state.config.service_did
    {
        return Err(signature_error(
            "Destination-Service-DID does not match the federation push destination",
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

    if source_service_did != body.origin.as_str() {
        verify_relay_inner_signature(
            state,
            req,
            &method,
            &target_uri,
            &content_digest,
            body.origin.as_str(),
            &source_service_did,
            &destination_service_did,
            &request_digest,
        )?;
    }

    Ok(())
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
    signature_params: &str,
) -> String {
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
         \"@signature-params\": {signature_params}",
    )
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
    if let Some(created) = signature_param_value(signature_params, "created")
        .and_then(|value| value.parse::<i64>().ok())
    {
        if created > now + 300 {
            return Err(signature_error(format!(
                "{label} signature created timestamp is in the future"
            )));
        }
    }
    if let Some(expires) = signature_param_value(signature_params, "expires")
        .and_then(|value| value.parse::<i64>().ok())
    {
        if expires < now {
            return Err(signature_error(format!("{label} signature is expired")));
        }
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
        return Ok(state.anchorer_signing_key().verifying_key());
    }
    if let Some(key) = configured_peer_verifying_key(service_did)? {
        return Ok(key);
    }
    let verification_method = format!("{service_did}#federation-fanout-key");
    if let Ok(key) = crate::jws_verify::resolve_ed25519_pubkey(state, &verification_method) {
        return Ok(key);
    }
    if state.config.development_mode {
        return Ok(development_service_signing_key(service_did).verifying_key());
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
    hasher.update(b"soland:anchorer-ephemeral:");
    hasher.update(service_did.as_bytes());
    let seed: [u8; 32] = hasher.finalize().into();
    SigningKey::from_bytes(&seed)
}

fn signature_target_uri(req: &Request, state: &AppState) -> String {
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

fn signature_authority(req: &Request, state: &AppState) -> String {
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

fn trust_domain_from_service_did(service_did: &str) -> String {
    let scope = service_did
        .strip_prefix("did:web:")
        .or_else(|| service_did.strip_prefix("did:key:"))
        .or_else(|| service_did.strip_prefix("did:webvh:"))
        .unwrap_or(service_did)
        .to_ascii_lowercase()
        .replace(':', ".");
    format!("cx:trust_domain:{scope}")
}

fn signature_error(message: impl Into<String>) -> AppError {
    AppError::unauthenticated(message.into())
}

fn federation_verify_actor_digest(
    body: &contrix_sdk::FederationVerifyActorReqBody,
) -> Result<String, &'static str> {
    let value = serde_json::to_value(body)
        .map_err(|_| "federation verify-actor request must serialize to JSON")?;
    contrix_sdk::canonical::canonical_sha256(&value)
        .map_err(|_| "federation verify-actor request must be canonical JSON")
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

fn required_json_string<'a>(body: &'a Value, key: &str) -> Result<&'a str, AppError> {
    body.get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| AppError::missing_param(format!("{key} is required")))
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
    client: &reqwest::Client,
    peer: &FederationPeerTarget,
    space_id: &str,
    after_cursor: Option<&str>,
    limit: usize,
) -> Result<contrix_sdk::FederationPullOperationsResBody, AppError> {
    let mut url = reqwest::Url::parse(&format!("{}/api/v1/federation/pull-operations", peer.url))
        .map_err(|error| AppError::invalid_param(format!("invalid peer_url: {error}")))?;
    {
        let mut query = url.query_pairs_mut();
        query.append_pair("space_id", space_id);
        query.append_pair("limit", &limit.to_string());
        if let Some(after_cursor) = after_cursor.filter(|value| !value.is_empty()) {
            query.append_pair("after_cursor", after_cursor);
        }
    }
    crate::security::validate_url_for_egress(
        &url,
        "federation pull-operations",
        crate::security::private_networks_allowed(state.config.development_mode),
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
    serde_json::from_str::<contrix_sdk::FederationPullOperationsResBody>(&text)
        .map_err(|error| AppError::internal(format!("parse federation pull response: {error}")))
}

async fn operation_frontier_value(state: &AppState, space_id: &str) -> Value {
    let realm_id = space_id.replacen("cx:space:", "cx:realm:", 1);
    let operations = state
        .persistence
        .federation_operations()
        .list_for_space(&realm_id)
        .await
        .unwrap_or_default();
    let mut operation_ids = operations
        .iter()
        .map(|operation| operation.operation_id.to_string())
        .collect::<Vec<_>>();
    operation_ids.sort();
    let latest_operation_id = operation_ids.last().cloned();
    let digest_payload = json!({
        "space_id": realm_id,
        "operation_ids": operation_ids,
    });
    let frontier_digest = contrix_sdk::canonical::canonical_sha256(&digest_payload)
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
    json!({
        "space_id": realm_id,
        "operation_count": operations.len(),
        "operation_ids": digest_payload["operation_ids"].clone(),
        "latest_operation_id": latest_operation_id,
        "frontier_digest": frontier_digest,
    })
}

fn operation_should_fanout(operation: &Operation) -> bool {
    kinds::operation_is_message_create(operation)
        || kinds::operation_is_invite(operation)
        || kinds::operation_is_membership(operation)
        || kinds::operation_is_realm_lifecycle(operation)
}

async fn persist_local_federation_operation(state: &AppState, operation: &Operation) {
    let store = state.persistence.federation_operations();
    match store.contains(operation.operation_id.as_str()).await {
        Ok(true) => {}
        Ok(false) => {
            if let Err(error) = store.append(operation.clone()).await {
                tracing::warn!(
                    %error,
                    operation_id = %operation.operation_id,
                    "failed to persist local federation operation"
                );
            }
        }
        Err(error) => {
            tracing::warn!(
                %error,
                operation_id = %operation.operation_id,
                "failed to check local federation operation log"
            );
        }
    }
}

async fn enqueue_operation_push(
    state: &AppState,
    operation: &Operation,
    peer: &FederationPeerTarget,
) {
    let Ok(origin) = Did::new(state.config.service_did.clone()) else {
        tracing::warn!(
            service_did = %state.config.service_did,
            "local service_did is not a DID; skipping federation operation fanout"
        );
        return;
    };
    let Ok(destination) = Did::new(peer.did.clone()) else {
        tracing::warn!(
            peer = %peer.url,
            peer_did = %peer.did,
            operation_id = %operation.operation_id,
            "federation peer entry lacks a valid destination DID; use base_url|did"
        );
        return;
    };
    let Ok(space_id) = SpaceId::new(operation.realm_id.to_string()) else {
        tracing::warn!(
            operation_id = %operation.operation_id,
            realm_id = %operation.realm_id,
            "operation realm_id is not federation-addressable"
        );
        return;
    };

    let body = contrix_sdk::FederationPushOperationsReqBody {
        origin,
        destination,
        space_id,
        service_binding_ref: format!(
            "{}#federation-push-operations:{}",
            state.config.service_did,
            operation.operation_id.as_str()
        ),
        operations: vec![operation.clone()],
    };
    let payload = match serde_json::to_value(&body)
        .ok()
        .and_then(|value| contrix_sdk::canonical::canonical_json_bytes(&value).ok())
        .and_then(|bytes| String::from_utf8(bytes).ok())
    {
        Some(payload) => payload,
        None => {
            tracing::warn!(
                operation_id = %operation.operation_id,
                "failed to encode federation operation push body"
            );
            return;
        }
    };

    let mut hasher = Sha256::new();
    hasher.update(state.config.service_did.as_bytes());
    hasher.update(b"|");
    hasher.update(peer.did.as_bytes());
    hasher.update(b"|operation|");
    hasher.update(operation.operation_id.as_str().as_bytes());
    let idempotency_key = format!("cx:outbox:operation:{:x}", hasher.finalize());

    record_outbound_fanout_attempt(
        state,
        "operation",
        operation.operation_id.as_str(),
        peer.url.as_str(),
    );
    if let Err(error) = crate::routing::federation::outbox::enqueue_outbound(
        state,
        peer.url.as_str(),
        peer.did.as_str(),
        "/api/v1/federation/push-operations",
        &idempotency_key,
        &payload,
    )
    .await
    {
        tracing::warn!(
            %error,
            peer = %peer.url,
            peer_did = %peer.did,
            operation_id = %operation.operation_id,
            "failed to enqueue federation operation push"
        );
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
    body: &contrix_sdk::FederationTransactionReqBody,
) -> Result<String, &'static str> {
    let value =
        serde_json::to_value(body).map_err(|_| "federation transaction must serialize to JSON")?;
    contrix_sdk::canonical::canonical_sha256(&value)
        .map_err(|_| "federation transaction must be canonical JSON")
}

// ── Anchor pull/push (federation/anchors) ──────────────

#[derive(Clone, Debug, Default, Serialize, Deserialize, salvo::oapi::ToSchema)]
pub struct FederationAnchorsResponse {
    pub anchors: Vec<Anchor>,
    /// Echo of [`crate::config::FederationPolicy::as_str`] so the calling
    /// peer can reason about whether to fan out to other nodes.
    pub policy: String,
    pub next_cursor: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, salvo::oapi::ToSchema)]
pub struct FederationAnchorsPushRequest {
    pub origin: String,
    pub anchors: Vec<Anchor>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, salvo::oapi::ToSchema)]
pub struct FederationAnchorsPushResponse {
    pub accepted: Vec<String>,
    pub rejected: Vec<serde_json::Value>,
}

#[endpoint(
    operation_id = "cx.extension.soland.federation.anchors.pull",
    tags("federation"),
    summary = "Pull locally-held Anchors for a Space (federation peer-pull)"
)]
#[tracing::instrument(skip_all, fields(op = "cx.extension.soland.federation.anchors.pull"))]
pub(super) async fn federation_anchors_pull(
    depot: &mut Depot,
    space_id: QueryParam<String, true>,
) -> JsonResult<FederationAnchorsResponse> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let space_id = space_id.into_inner();
    if validate_space_id(&space_id).is_err() {
        return Err(AppError::invalid_param("invalid space_id"));
    }
    let space = SpaceId::new(space_id).map_err(|_| AppError::invalid_param("invalid space_id"))?;
    let leaves = state.anchor_store.list_leaves(&space).unwrap_or_default();
    let mut anchors: Vec<Anchor> = Vec::with_capacity(leaves.len());
    for leaf in &leaves {
        if let Ok(Some(a)) = state.anchor_store.get(leaf) {
            anchors.push(a);
        }
    }
    json_ok(FederationAnchorsResponse {
        anchors,
        policy: state.config.federation_policy.as_str().to_owned(),
        next_cursor: None,
    })
}

#[endpoint(
    operation_id = "cx.extension.soland.federation.anchors.push",
    tags("federation"),
    summary = "Accept Anchor envelopes from a federation peer (peer-push)"
)]
#[tracing::instrument(skip_all, fields(op = "cx.extension.soland.federation.anchors.push"))]
pub(super) async fn federation_anchors_push(
    depot: &mut Depot,
    body: JsonBody<FederationAnchorsPushRequest>,
) -> JsonResult<FederationAnchorsPushResponse> {
    let state = depot.obtain::<AppState>().expect("state injected");
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
    for anchor in body.anchors {
        let id_str = anchor.id.to_string();
        // Only accept Anchors whose declared id matches the canonical hash
        // — otherwise a peer could overwrite our DAG with junk.
        match anchor.derive_id() {
            Ok(derived) if derived == anchor.id => {}
            _ => {
                rejected.push(json!({"id": id_str, "reason": "id_mismatch"}));
                continue;
            }
        }
        if let Err(error) = state.anchor_store.put(&anchor) {
            rejected.push(
                json!({"id": id_str, "reason": "persistence_error", "message": error.to_string()}),
            );
            continue;
        }
        accepted.push(id_str);
    }
    json_ok(FederationAnchorsPushResponse { accepted, rejected })
}

/// Outbound Move broadcast helper. Each accepted Move
/// goes to:
/// - [`FederationPolicy::Mesh`]: every peer in `state.config.federation_peers`.
/// - [`FederationPolicy::Hub`]: only the first peer (`federation_peers[0]`).
///
/// Returns the list of peer URLs the broadcast targeted; the actual HTTP
/// dispatch is fire-and-forget (best-effort) and runs on a background
/// tokio task so the inbound write path never blocks on a slow peer.
pub fn broadcast_move_to_peers(state: &AppState, move_id: &str) -> Vec<String> {
    let peers = configured_peer_targets(state);
    for peer in &peers {
        record_outbound_fanout_attempt(state, "move", move_id, peer.url.as_str());
        // G3.S0 — durable enqueue. The transcript persisted above remains
        // the human-readable audit record; the outbox row is what the
        // background dispatcher (`routing::federation::outbox`) actually
        // POSTs. Failures to enqueue are logged but don't fail the
        // inbound write — the transcript still gives operators a way to
        // re-trigger delivery once the storage hiccup clears.
        enqueue_outbound_for(state, "move", move_id, peer);
        let peer_url = peer.url.clone();
        let move_id_owned = move_id.to_owned();
        tokio::spawn(async move {
            tracing::debug!(
                worker = "federation_outbox_enqueue",
                peer = %peer_url,
                move_id = %move_id_owned,
                "federation broadcast move signed request transcript persisted for retry worker"
            );
        });
    }
    peers.into_iter().map(|peer| peer.url).collect()
}

/// Symmetric helper for Anchor replication. The hub policy still pushes
/// to a single upstream so the broadcast list is `[hub]`; mesh fans out
/// to every peer.
pub fn broadcast_anchor_to_peers(state: &AppState, anchor_id: &str) -> Vec<String> {
    let peers = configured_peer_targets(state);
    for peer in &peers {
        record_outbound_fanout_attempt(state, "anchor", anchor_id, peer.url.as_str());
        // G3.S0 — durable enqueue (see broadcast_move_to_peers).
        enqueue_outbound_for(state, "anchor", anchor_id, peer);
        let peer_url = peer.url.clone();
        let anchor_id_owned = anchor_id.to_owned();
        tokio::spawn(async move {
            tracing::debug!(
                worker = "federation_outbox_enqueue",
                peer = %peer_url,
                anchor_id = %anchor_id_owned,
                "federation broadcast anchor signed request transcript persisted for retry worker"
            );
        });
    }
    peers.into_iter().map(|peer| peer.url).collect()
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
        "anchor" => "/api/v1/federation/anchors",
        _ => "/api/v1/federation/push-operations",
    };
    let payload = json!({
        "schema": format!("cx.federation.outbound.{resource_kind}.v1"),
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
    let payload_bytes = contrix_sdk::canonical::canonical_json_bytes(&payload)
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
    let idempotency_key = format!("cx:outbox:{:x}", hasher.finalize());
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
        "anchor" => "/api/v1/federation/anchors",
        _ => "/api/v1/federation/push-operations",
    };
    let intent = json!({
        "schema": "cx.federation.outbound_fanout.intent.v1",
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
        "schema": "cx.federation.outbound_fanout.transcript.v1",
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
            "profile": "cx.profile.principal_server.v1",
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
        space_id: None,
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
    let canonical_bytes = contrix_sdk::canonical::canonical_json_bytes(intent)
        .unwrap_or_else(|_| serde_json::to_vec(intent).unwrap_or_default());
    let payload_digest = format!("sha256:{}", sha256_hex(&canonical_bytes));
    let protected_header = br#"{"alg":"EdDSA","typ":"cx.federation.outbound_fanout.intent.v1"}"#;
    let protected_b64u = URL_SAFE_NO_PAD.encode(protected_header);
    let payload_b64u = URL_SAFE_NO_PAD.encode(&canonical_bytes);
    let signing_input = format!("{protected_b64u}.{payload_b64u}");
    let signature = state.anchorer_signing_key().sign(signing_input.as_bytes());
    let signature_b64u = URL_SAFE_NO_PAD.encode(signature.to_bytes());
    let jws = format!("{protected_b64u}..{signature_b64u}");
    let key_origin = match state.anchorer_signing_key_origin() {
        crate::config::AnchorerSigningKeyOrigin::Configured => "configured",
        crate::config::AnchorerSigningKeyOrigin::Ephemeral => "ephemeral",
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
        "(\"@method\" \"@path\" \"content-digest\" \"x-contrix-fanout-digest\");created={created};keyid=\"{keyid}\";alg=\"ed25519\""
    );
    let signature_input_header = format!("sig1={signature_params}");
    let signature_base = format!(
        "\"@method\": POST\n\"@path\": {target_path}\n\"content-digest\": {content_digest}\n\"x-contrix-fanout-digest\": {payload_digest}\n\"@signature-params\": {signature_params}"
    );
    let signature = state.anchorer_signing_key().sign(signature_base.as_bytes());
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
            "x-contrix-fanout-digest"
        ],
        "headers": {
            "content-digest": content_digest,
            "signature-input": signature_input_header,
            "signature": signature_header,
            "x-contrix-fanout-digest": payload_digest
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
fn run_outbound_fanout_retry_pass_at(
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
        anchorer_signing_key_seed: None,
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
        compaction_min_anchor_age_seconds: 604_800,
        compaction_min_witnesses: 1,
        compaction_preserve_genesis: true,
        compaction_prune_only_singleton_successors: true,
        compaction_prune_walk_interval_seconds: 0,
        compaction_prune_walk_per_space_limit: 50,
        seed_demo_data: false,
        trust_domain: "cx:trust_domain:soland.local".to_owned(),
        sovereign_enclave_enabled: false,
        sovereign_enclave_allowed_outbound_hosts: Vec::new(),
        erasure_propagation_window_ms,
        log_format: crate::config::LogFormat::Plain,
    };
    AppState::new(cfg, Db { pool: None })
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::str::FromStr;

    use super::*;
    use crate::config::{AppConfig, FederationPolicy};
    use crate::db::Db;
    use crate::state::AppState;

    fn config_with_policy(policy: FederationPolicy, peers: Vec<String>) -> AppConfig {
        AppConfig {
            bind: SocketAddr::from_str("127.0.0.1:0").unwrap(),
            metrics_bind: SocketAddr::from_str("127.0.0.1:0").unwrap(),
            public_base_url: "http://test".to_owned(),
            service_did: "did:web:test.local".to_owned(),
            tls_cert_path: None,
            tls_key_path: None,
            database_url: None,
            object_storage: crate::config::ObjectStorageConfig::local(std::env::temp_dir()),
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
            anchorer_signing_key_seed: None,
            agent_audit_binding_signing_seed: None,
            use_keystore: false,
            federation_policy: policy,
            federation_peers: peers,
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
        }
    }

    fn verify_actor_body() -> contrix_sdk::FederationVerifyActorReqBody {
        contrix_sdk::FederationVerifyActorReqBody {
            actor_id: contrix_sdk::Did::new("did:web:alice.example").unwrap(),
            challenge: Some("challenge-1".to_owned()),
            signed_payload_digest: None,
            signature: serde_json::json!({
                "kid": "did:web:alice.example#key-1",
                "alg": "EdDSA",
                "sig": "test-signature"
            }),
            purpose: "federation.verify_actor".to_owned(),
            space_id: None,
        }
    }

    fn trust_domain(value: &str) -> contrix_sdk::TypedTrustDomainId {
        contrix_sdk::TypedTrustDomainId::new(value.to_owned()).unwrap()
    }

    fn federation_headers(digest: &str) -> crate::round4::FederationTrustHeaders {
        crate::round4::FederationTrustHeaders {
            source_trust_domain: trust_domain("cx:trust_domain:peer.example"),
            destination_trust_domain: trust_domain("cx:trust_domain:soland.local"),
            request_canonical_digest: contrix_sdk::Hash::new(digest.to_owned()).unwrap(),
        }
    }

    #[test]
    fn verify_actor_digest_uses_canonical_json() {
        let body = verify_actor_body();
        let value = serde_json::to_value(&body).unwrap();
        let expected = contrix_sdk::canonical::canonical_sha256(&value).unwrap();

        assert_eq!(federation_verify_actor_digest(&body).unwrap(), expected);
    }

    #[test]
    fn verify_actor_headers_accept_matching_canonical_digest() {
        let body = verify_actor_body();
        let digest = federation_verify_actor_digest(&body).unwrap();
        let headers = federation_headers(&digest);

        validate_round4_federation_headers(
            &headers,
            &trust_domain("cx:trust_domain:soland.local"),
            &digest,
        )
        .expect("matching digest and destination accepted");
    }

    #[test]
    fn verify_actor_headers_reject_digest_mismatch() {
        let body = verify_actor_body();
        let digest = federation_verify_actor_digest(&body).unwrap();
        let headers = federation_headers(&format!("sha256:{}", "0".repeat(64)));

        let error = validate_round4_federation_headers(
            &headers,
            &trust_domain("cx:trust_domain:soland.local"),
            &digest,
        )
        .expect_err("mismatched digest rejected");

        assert_eq!(
            error.code,
            crate::error::ErrorCode::CrossDomainReplayRejected
        );
        assert_eq!(error.http_status(), StatusCode::CONFLICT);
    }

    #[test]
    fn verify_actor_headers_reject_destination_mismatch() {
        let body = verify_actor_body();
        let digest = federation_verify_actor_digest(&body).unwrap();
        let headers = federation_headers(&digest);

        let error = validate_round4_federation_headers(
            &headers,
            &trust_domain("cx:trust_domain:other.example"),
            &digest,
        )
        .expect_err("wrong destination rejected");

        assert_eq!(
            error.code,
            crate::error::ErrorCode::CrossDomainReplayRejected
        );
        assert_eq!(error.http_status(), StatusCode::CONFLICT);
    }

    #[test]
    fn block_hint_records_and_suppresses_push_direction() {
        let cfg = config_with_policy(FederationPolicy::Mesh, Vec::new());
        let state = AppState::new(cfg, Db { pool: None });

        let record = record_block_hint(
            &state,
            "did:web:alice.example",
            "did:web:bob.example",
            Some("did:web:peer.example"),
        )
        .expect("valid block hint records");

        assert_eq!(record.actor, "did:web:alice.example");
        assert_eq!(record.blocked, "did:web:bob.example");
        assert!(federation_push_suppressed_by_block_hint(
            &state,
            "did:web:alice.example",
            "did:web:bob.example"
        ));
        assert!(!federation_push_suppressed_by_block_hint(
            &state,
            "did:web:bob.example",
            "did:web:alice.example"
        ));
    }

    #[test]
    fn blocklist_hint_targets_ignore_unblock_entries() {
        let payload = json!({
            "entries": [
                {"target": {"kind": "actor", "did": "did:web:bob.example"}, "mode": "block"},
                {"target": {"did": "did:web:mallory.example"}, "status": "removed"},
                {"target": {"kind": "actor", "did": "did:web:trent.example"}, "mode": "unblock"},
                "did:web:carol.example",
                {"target": "not-a-did", "kind": "block"}
            ]
        });

        let targets = blocklist_hint_targets_from_payload(&payload);

        assert!(targets.contains("did:web:bob.example"));
        assert!(targets.contains("did:web:carol.example"));
        assert!(!targets.contains("did:web:mallory.example"));
        assert!(!targets.contains("did:web:trent.example"));
        assert!(!targets.contains("not-a-did"));
    }

    #[tokio::test]
    async fn mesh_policy_broadcasts_to_every_peer() {
        let cfg = config_with_policy(
            FederationPolicy::Mesh,
            vec![
                "https://peer-a.example".to_owned(),
                "https://peer-b.example".to_owned(),
                "https://peer-c.example".to_owned(),
            ],
        );
        let state = AppState::new(cfg, Db { pool: None });
        let targets = broadcast_move_to_peers(&state, "sha256:01");
        assert_eq!(targets.len(), 3);
        let peer_hash = sha256_hex("https://peer-a.example".as_bytes());
        let move_hash = sha256_hex("sha256:01".as_bytes());
        let txn_id = format!("outbound_move:{}:{}", &peer_hash[..16], &move_hash[..16]);
        let transcript = state
            .persistence
            .federation_transactions()
            .get("did:web:test.local", &txn_id)
            .await
            .unwrap()
            .expect("outbound transcript persisted");
        assert_eq!(transcript.destination, "https://peer-a.example");
        assert_eq!(transcript.status, "outbound_fanout_retry_scheduled");
        assert_eq!(
            transcript.response["schema"],
            "cx.federation.outbound_fanout.transcript.v1"
        );
        assert_eq!(transcript.response["signing"]["status"], "intent_signed");
        assert_eq!(
            transcript.response["signing"]["http_message_signatures"]["status"],
            "emitted"
        );
        assert_eq!(
            transcript.response["dispatch_attempt"]["status"],
            "signed_request_prepared"
        );
        assert!(
            transcript.response["signing"]["http_message_signatures"]["headers"]["signature"]
                .as_str()
                .unwrap()
                .starts_with("sig1=:")
        );
        assert!(
            transcript.response["signing"]["payload_digest"]
                .as_str()
                .unwrap()
                .starts_with("sha256:")
        );
        assert!(
            transcript.response["signing"]["jws"]
                .as_str()
                .unwrap()
                .contains("..")
        );
        assert_eq!(transcript.response["retry"]["status"], "retry_scheduled");
        assert_eq!(
            transcript.response["durability"]["status"],
            "persisted_before_dispatch"
        );
        assert_eq!(
            transcript.response["per_peer_state"]["state"],
            "retry_scheduled"
        );
        assert_eq!(
            transcript.response["limitations"]["full_conformance"],
            serde_json::json!(false)
        );
    }

    #[tokio::test]
    async fn hub_policy_broadcasts_to_hub_only() {
        let cfg = config_with_policy(
            FederationPolicy::Hub,
            vec![
                "https://hub.example".to_owned(),
                "https://peer-b.example".to_owned(),
                "https://peer-c.example".to_owned(),
            ],
        );
        let state = AppState::new(cfg, Db { pool: None });
        let targets = broadcast_move_to_peers(&state, "sha256:02");
        assert_eq!(targets, vec!["https://hub.example".to_owned()]);
    }

    #[tokio::test]
    async fn empty_peers_list_is_a_no_op() {
        let cfg = config_with_policy(FederationPolicy::Mesh, Vec::new());
        let state = AppState::new(cfg, Db { pool: None });
        let targets = broadcast_anchor_to_peers(&state, "cx:anchor:sha256:01");
        assert!(targets.is_empty());
    }

    #[tokio::test]
    async fn local_invite_membership_and_message_operations_enqueue_push_bodies_idempotently() {
        let cfg = config_with_policy(
            FederationPolicy::Mesh,
            vec!["http://127.0.0.1:9|did:web:peer.example".to_owned()],
        );
        let state = AppState::new(cfg, Db { pool: None });
        let realm_id = RealmId::new("cx:realm:01904100-0000-7000-8000-000000000051").unwrap();
        let invite = Operation::create(
            contrix_sdk::OperationId::new("cx:operation:01904100-0000-7000-8000-000000000052")
                .unwrap(),
            realm_id.clone(),
            kinds::CX_MEMBER_STATE,
            json!({
                "actor_id": "did:web:bob.example",
                "member": "did:web:bob.example",
                "membership": "invite"
            }),
        );
        let invite_create = Operation::create(
            contrix_sdk::OperationId::new("cx:operation:01904100-0000-7000-8000-000000000055")
                .unwrap(),
            realm_id.clone(),
            kinds::CX_INVITE_CREATE,
            json!({
                "invite_id": "cx:invite:01904100-0000-7000-8000-000000000056",
                "invitee": "did:web:carol.example",
                "sender": "did:web:alice.example",
                "expires_at": "2030-01-01T00:00:00Z"
            }),
        );
        let message = Operation::create(
            contrix_sdk::OperationId::new("cx:operation:01904100-0000-7000-8000-000000000053")
                .unwrap(),
            realm_id,
            kinds::CX_MESSAGE_CREATE,
            json!({
                "event_id": "cx:event:01904100-0000-7000-8000-000000000054",
                "sender": "did:web:alice.example",
                "thread_id": "cx:flow:01904100-0000-7000-8000-000000000051",
                "content": {"kind": "cx.content.text", "body": "hello federation"}
            }),
        );

        crate::routing::events::projection::project_accepted_operations(
            &state,
            "did:web:alice.example",
            &[invite.clone(), invite_create.clone(), message.clone()],
        )
        .await;

        let outbox = state
            .persistence
            .federation_outbox()
            .snapshot_all()
            .await
            .unwrap();
        assert_eq!(outbox.len(), 3);
        assert!(outbox.iter().all(|row| row.peer_url == "http://127.0.0.1:9"
            && row.peer_did == "did:web:peer.example"
            && row.endpoint == "/api/v1/federation/push-operations"));
        let payloads = outbox
            .iter()
            .map(|row| serde_json::from_str::<Value>(&row.payload_json).unwrap())
            .collect::<Vec<_>>();
        assert!(
            payloads
                .iter()
                .all(|body| body["origin"] == "did:web:test.local"
                    && body["destination"] == "did:web:peer.example"
                    && body["space_id"] == "cx:realm:01904100-0000-7000-8000-000000000051")
        );
        let pushed_ids = payloads
            .iter()
            .flat_map(|body| body["operations"].as_array().unwrap().iter())
            .map(|operation| operation["operation_id"].as_str().unwrap().to_owned())
            .collect::<std::collections::BTreeSet<_>>();
        assert!(pushed_ids.contains(invite.operation_id.as_str()));
        assert!(pushed_ids.contains(invite_create.operation_id.as_str()));
        assert!(pushed_ids.contains(message.operation_id.as_str()));

        let projected_invite = state
            .persistence
            .space_invites()
            .get("cx:invite:01904100-0000-7000-8000-000000000056")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            projected_invite.invitee.as_deref(),
            Some("did:web:carol.example")
        );
        assert_eq!(projected_invite.inviter, "did:web:alice.example");
        assert_eq!(projected_invite.status, "pending");

        let federation_log = state
            .persistence
            .federation_operations()
            .snapshot_all()
            .await
            .unwrap();
        assert_eq!(federation_log.len(), 3);

        crate::routing::events::projection::project_accepted_operations(
            &state,
            "did:web:alice.example",
            &[invite, invite_create, message],
        )
        .await;
        assert_eq!(
            state
                .persistence
                .federation_outbox()
                .snapshot_all()
                .await
                .unwrap()
                .len(),
            3,
            "operation fanout replays must collapse on deterministic outbox keys"
        );
        assert_eq!(
            state
                .persistence
                .federation_operations()
                .snapshot_all()
                .await
                .unwrap()
                .len(),
            3,
            "local federation operation log must not duplicate replayed operations"
        );
    }

    #[tokio::test]
    async fn operation_frontier_tracks_persisted_operation_ids() {
        let cfg = config_with_policy(FederationPolicy::Mesh, Vec::new());
        let state = AppState::new(cfg, Db { pool: None });
        let realm_id = RealmId::new("cx:realm:01904100-0000-7000-8000-000000000061").unwrap();
        let first = Operation::create(
            contrix_sdk::OperationId::new("cx:operation:01904100-0000-7000-8000-000000000062")
                .unwrap(),
            realm_id.clone(),
            kinds::CX_MESSAGE_CREATE,
            json!({"content": {"kind": "cx.content.text", "body": "one"}}),
        );
        let second = Operation::create(
            contrix_sdk::OperationId::new("cx:operation:01904100-0000-7000-8000-000000000063")
                .unwrap(),
            realm_id,
            kinds::CX_MESSAGE_CREATE,
            json!({"content": {"kind": "cx.content.text", "body": "two"}}),
        );
        state
            .persistence
            .federation_operations()
            .append(first.clone())
            .await
            .unwrap();
        let before =
            operation_frontier_value(&state, "cx:realm:01904100-0000-7000-8000-000000000061");
        state
            .persistence
            .federation_operations()
            .append(second.clone())
            .await
            .unwrap();
        let after =
            operation_frontier_value(&state, "cx:realm:01904100-0000-7000-8000-000000000061");

        assert_eq!(before["operation_count"], 1);
        assert_eq!(after["operation_count"], 2);
        assert_eq!(
            after["latest_operation_id"],
            second.operation_id.to_string()
        );
        assert_ne!(before["frontier_digest"], after["frontier_digest"]);
        assert!(
            after["operation_ids"]
                .as_array()
                .unwrap()
                .iter()
                .any(|value| value == first.operation_id.as_str())
        );
    }

    #[tokio::test]
    async fn anchor_fanout_records_anchor_target_and_retry_metadata() {
        let cfg = config_with_policy(
            FederationPolicy::Mesh,
            vec!["https://peer-anchor.example".to_owned()],
        );
        let state = AppState::new(cfg, Db { pool: None });
        let targets = broadcast_anchor_to_peers(&state, "cx:anchor:sha256:02");
        assert_eq!(targets, vec!["https://peer-anchor.example".to_owned()]);

        let peer_hash = sha256_hex("https://peer-anchor.example".as_bytes());
        let anchor_hash = sha256_hex("cx:anchor:sha256:02".as_bytes());
        let txn_id = format!(
            "outbound_anchor:{}:{}",
            &peer_hash[..16],
            &anchor_hash[..16]
        );
        let transcript = state
            .persistence
            .federation_transactions()
            .get("did:web:test.local", &txn_id)
            .await
            .unwrap()
            .expect("outbound anchor transcript persisted");
        assert_eq!(
            transcript.response["target_path"],
            "/api/v1/federation/anchors"
        );
        assert_eq!(transcript.response["intent"]["resource_kind"], "anchor");
        assert_eq!(
            transcript.response["retry"]["policy"]["initial_backoff_ms"],
            serde_json::json!(30_000)
        );
        assert!(transcript.response["per_peer_state"]["next_retry_at"].is_string());
    }

    #[tokio::test]
    async fn retry_pass_claims_due_outbound_transcript_and_reschedules() {
        let cfg = config_with_policy(
            FederationPolicy::Mesh,
            vec!["https://peer-retry.example".to_owned()],
        );
        let state = AppState::new(cfg, Db { pool: None });
        broadcast_move_to_peers(&state, "sha256:retry");

        let peer_hash = sha256_hex("https://peer-retry.example".as_bytes());
        let move_hash = sha256_hex("sha256:retry".as_bytes());
        let txn_id = format!("outbound_move:{}:{}", &peer_hash[..16], &move_hash[..16]);
        let before = state
            .persistence
            .federation_transactions()
            .get("did:web:test.local", &txn_id)
            .await
            .unwrap()
            .expect("outbound transcript persisted");
        let due_at = next_retry_at(&before.response).expect("next retry");

        let report =
            run_outbound_fanout_retry_pass_at(&state, "node-a", 10, due_at + Duration::seconds(1))
                .unwrap();
        assert_eq!(report.due, 1);
        assert_eq!(report.retried, 1);
        assert_eq!(report.dead_lettered, 0);

        let after = state
            .persistence
            .federation_transactions()
            .get("did:web:test.local", &txn_id)
            .await
            .unwrap()
            .expect("updated outbound transcript persisted");
        assert_eq!(after.status, "outbound_fanout_retry_scheduled");
        assert_eq!(
            after.response["per_peer_state"]["attempt"],
            serde_json::json!(2)
        );
        assert_eq!(
            after.response["per_peer_state"]["lease"]["holder"],
            "node-a"
        );
        assert_eq!(after.response["retry"]["status"], "retry_scheduled");
        assert!(after.response["per_peer_state"]["next_retry_at"].is_string());
    }
}
