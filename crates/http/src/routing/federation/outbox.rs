//! G3.S0 — durable outbound federation HTTP delivery.
//!
//! ## Surface
//!
//! - [`enqueue_outbound`] — synchronous insert into the `federation_outbox` table. Called by the
//!   standard peer-event post-commit path. Returns the row's [`FederationOutboxRecord`] (newly
//!   inserted or pre-existing when `(peer_did, idempotency_key)` already matched a prior row).
//! - [`FederationDispatcher`] / [`spawn`] — background tokio task. Polls the outbox every
//!   [`POLL_INTERVAL`], picks up to [`POLL_BATCH_LIMIT`] rows whose `next_attempt_at <= now`, POSTs
//!   each one to its peer with the spec-required headers, and writes the resulting delivery state
//!   (`delivered_at`, `last_status`, `last_response_excerpt`, `next_attempt_at`, `attempts`) back
//!   to the row.
//!
//! ## What this lands today
//!
//! Real HTTP POST. Real `Idempotency-Key` + `Content-Digest` (RFC 9530)
//! headers. RFC 9421-style HTTP Message Signature headers over the
//! federation transcript. Exponential backoff capped at 1h. Permanent
//! 4xx handling. Retry-cap "give up" handling. The integration suite
//! pins the contract — see `soland/tests/federation_outbox.rs`.
//!
//! ## What's deferred
//!
//! - **Operator replay API**. Terminal failures are mirrored into `federation_outbox_dead_letter`,
//!   but there is not yet an HTTP endpoint that re-queues them with a fresh idempotency key.
//!
//! ## Parallel-work coordination
//!
//! - DOES NOT touch `reducer.rs` — G3.Y0 / G3.S3 own that.
//! - DOES NOT change the inbound federation handler shape — G2.T1 owns that.
//! - DOES NOT introduce a new HTTP client — reuses the existing `reqwest` async client soland
//!   already pulls in.

use std::sync::Arc;
use std::time::Duration;

use soland_http::http_signature::{self, SignatureBaseComponent};
use uuid::Uuid;

use crate::state::AppState;

/// How often the dispatcher polls the outbox when idle.
pub const POLL_INTERVAL: Duration = Duration::from_secs(5);
/// Maximum rows the dispatcher claims per poll. Keeps a backlog from
/// monopolizing the tokio runtime; subsequent ticks drain the rest.
pub const POLL_BATCH_LIMIT: usize = 32;
/// Per-request connect timeout — keep this short so a dead peer can't
/// stall the entire dispatcher loop.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// Per-request full-response timeout.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// Maximum delivery attempts before the worker gives up. Matches the
/// spec recommendation in `federation.md` §8 (≈ 10 attempts ≈ ~1h
/// wallclock with the capped exponential backoff below).
pub const MAX_ATTEMPTS: i32 = 10;
/// Sentinel `last_status` written when the worker gives up after the
/// attempts cap. Negative so it cannot collide with any real HTTP code.
pub const GAVE_UP_STATUS_SENTINEL: i32 = -1;
/// Sentinel `last_status` written when a row is suppressed by the
/// deployment egress policy before any socket is opened.
pub const EGRESS_POLICY_DENIED_STATUS_SENTINEL: i32 = -2;
/// Sentinel written when peer Event HTTP transport succeeded but the typed
/// `EventsSubmitOutcome` reported a partial or otherwise non-success result.
pub const PEER_EVENT_OUTCOME_REJECTED_STATUS_SENTINEL: i32 = -3;
/// Cap on the response excerpt we persist. 1 KiB matches the spec's
/// postmortem-evidence size budget.
const RESPONSE_EXCERPT_BYTES: usize = 1024;

#[derive(Clone, Debug)]
struct FederationDispatchState {
    id: String,
    peer_did: String,
    peer_url: String,
    endpoint: String,
    idempotency_key: String,
    payload_json: String,
    attempts: i32,
    next_attempt_at: i64,
    last_status: Option<i32>,
    last_response_excerpt: Option<String>,
    created_at: i64,
    delivered_at: Option<i64>,
}

/// Compute the unix-second `now` the dispatcher and the enqueue path
/// agree on. Wraps `chrono::Utc::now()` so unit tests can swap the
/// clock without leaking `chrono` through the trait surfaces.
fn now_unix_secs() -> i64 {
    chrono::Utc::now().timestamp()
}

fn persistence_delivery(
    record: soland_services::federation::PendingFederationDelivery,
) -> FederationDispatchState {
    FederationDispatchState {
        id: record.delivery.id,
        peer_did: record.delivery.peer_did,
        peer_url: record.delivery.peer_url,
        endpoint: record.delivery.endpoint,
        idempotency_key: record.delivery.idempotency_key,
        payload_json: record.delivery.payload_json,
        attempts: record.attempts,
        next_attempt_at: record.next_attempt_at,
        last_status: record.last_status,
        last_response_excerpt: record.last_response_excerpt,
        created_at: record.delivery.created_at,
        delivered_at: record.delivered_at,
    }
}

fn application_delivery(
    record: &FederationDispatchState,
) -> soland_services::federation::PendingFederationDelivery {
    soland_services::federation::PendingFederationDelivery {
        delivery: soland_services::federation::FederationDeliveryRecord {
            id: record.id.clone(),
            peer_did: record.peer_did.clone(),
            peer_url: record.peer_url.clone(),
            endpoint: record.endpoint.clone(),
            idempotency_key: record.idempotency_key.clone(),
            payload_json: record.payload_json.clone(),
            created_at: record.created_at,
        },
        attempts: record.attempts,
        next_attempt_at: record.next_attempt_at,
        last_status: record.last_status,
        last_response_excerpt: record.last_response_excerpt.clone(),
        delivered_at: record.delivered_at,
    }
}

/// G3.S0 — synchronous outbox enqueue.
///
/// Inserts one row per `(peer, resource)` tuple. Idempotent on
/// `(peer_did, idempotency_key)`: a re-enqueue (e.g. restart-time
/// re-broadcast of an already-sealed Move) returns the pre-existing
/// row instead of creating a duplicate, matching the spec's
/// `Idempotency-Key`-bound replay semantics in `federation.md` §8.5.
///
/// Returns the persisted [`FederationOutboxRecord`] so call sites can
/// log the row id without re-fetching.
pub async fn enqueue_outbound(
    state: &AppState,
    peer_url: &str,
    peer_did: &str,
    endpoint: &str,
    idempotency_key: &str,
    payload_json: &str,
) -> soland_services::ServiceResult<soland_services::federation::FederationDeliveryRecord> {
    let now = now_unix_secs();
    let result = state
        .federation()
        .enqueue_delivery(
            soland_services::federation::EnqueueFederationDeliveryCommand {
                delivery: soland_services::federation::FederationDeliveryRecord {
                    id: Uuid::new_v4().to_string(),
                    peer_did: peer_did.to_owned(),
                    peer_url: peer_url.trim_end_matches('/').to_owned(),
                    endpoint: endpoint.to_owned(),
                    idempotency_key: idempotency_key.to_owned(),
                    payload_json: payload_json.to_owned(),
                    created_at: now,
                },
            },
        )
        .await?;
    Ok(result)
}

pub(crate) fn rfc9421_sign(
    state: &AppState,
    headers: reqwest::header::HeaderMap,
    method: &str,
    target_url: &str,
    body: &[u8],
) -> reqwest::header::HeaderMap {
    rfc9421_sign_with_window(state, headers, method, target_url, body, 300)
}

fn rfc9421_sign_with_window(
    state: &AppState,
    mut headers: reqwest::header::HeaderMap,
    method: &str,
    target_url: &str,
    body: &[u8],
    validity_seconds: i64,
) -> reqwest::header::HeaderMap {
    let request_canonical_digest = arkret_canonical::sha256_digest(body);
    insert_header_if_valid(
        &mut headers,
        "request-canonical-digest",
        &request_canonical_digest,
    );

    let created = now_unix_secs();
    let expires = created + validity_seconds;
    let keyid = super::federation_service_signature_key_id(state.service_id());
    let mut covered = vec![
        "\"@method\"",
        "\"@target-uri\"",
        "\"@authority\"",
        "\"content-digest\"",
        "\"source-service-id\"",
        "\"destination-service-id\"",
        "\"source-trust-domain\"",
        "\"destination-trust-domain\"",
        "\"request-canonical-digest\"",
    ];
    let idempotency_key = header_value(&headers, "idempotency-key");
    if idempotency_key.is_some() {
        covered.push("\"idempotency-key\"");
    }
    let covered = covered.join(" ");
    let signature_params = format!(
        "({covered});created={created};expires={expires};keyid=\"{keyid}\";alg=\"ed25519\"",
    );
    let signature_input = format!("sig1={signature_params}");
    let authority = authority_from_target_url(target_url);

    let content_digest = header_value(&headers, "content-digest").unwrap_or_default();
    let source_service_id = header_value(&headers, "source-service-id").unwrap_or_default();
    let destination_service_id =
        header_value(&headers, "destination-service-id").unwrap_or_default();
    let source_trust_domain = header_value(&headers, "source-trust-domain").unwrap_or_default();
    let destination_trust_domain =
        header_value(&headers, "destination-trust-domain").unwrap_or_default();
    let signature_base = http_signature::signature_base(
        &[
            SignatureBaseComponent::required("@method", method),
            SignatureBaseComponent::required("@target-uri", target_url),
            SignatureBaseComponent::required("@authority", &authority),
            SignatureBaseComponent::required("content-digest", &content_digest),
            SignatureBaseComponent::required("source-service-id", &source_service_id),
            SignatureBaseComponent::required("destination-service-id", &destination_service_id),
            SignatureBaseComponent::required("source-trust-domain", &source_trust_domain),
            SignatureBaseComponent::required("destination-trust-domain", &destination_trust_domain),
            SignatureBaseComponent::required("request-canonical-digest", &request_canonical_digest),
            SignatureBaseComponent::optional("idempotency-key", idempotency_key.as_deref()),
        ],
        &signature_params,
    );
    let signature = arkret_signatures::http_signature::sign_message(
        signature_base.as_bytes(),
        &state.notary_signing_key(),
    );
    let signature_header = format!("sig1=:{signature}:");

    insert_header_if_valid(&mut headers, "signature-input", &signature_input);
    insert_header_if_valid(&mut headers, "signature", &signature_header);
    headers
}

/// Send one Signal peer relay request without a durable outbox or retry.
pub(crate) async fn relay_signal_once(
    state: &AppState,
    peer_url: &str,
    peer_did: &str,
    request: &arkret_wire::SignalRelayRequest,
) -> Result<(), String> {
    request.validate().map_err(|error| error.to_string())?;
    let body =
        arkret_canonical::canonical_json_bytes(request).map_err(|error| error.to_string())?;
    let target = format!("{}/_arkret/peer/signal", peer_url.trim_end_matches('/'));
    let (parsed_url, client) = crate::security::validate_http_url_for_egress_with_pinned_client(
        &target,
        "Signal peer relay",
        state.config().development_mode,
        Duration::from_secs(5),
    )?;
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(
        reqwest::header::CONTENT_TYPE,
        reqwest::header::HeaderValue::from_static("application/json"),
    );
    insert_header_if_valid(
        &mut headers,
        "content-digest",
        &content_digest_header_value(&body),
    );
    insert_header_if_valid(&mut headers, "source-service-id", state.service_id());
    insert_header_if_valid(&mut headers, "destination-service-id", peer_did);
    insert_header_if_valid(
        &mut headers,
        "source-trust-domain",
        &state.config().trust_domain,
    );
    insert_header_if_valid(
        &mut headers,
        "destination-trust-domain",
        &trust_domain_from_service_id(peer_did),
    );
    let headers = rfc9421_sign_with_window(state, headers, "POST", &target, &body, 5);
    let response = client
        .post(parsed_url)
        .headers(headers)
        .body(body)
        .send()
        .await
        .map_err(|error| error.to_string())?;
    if !response.status().is_success() {
        return Err(format!(
            "Signal peer relay returned HTTP {}",
            response.status()
        ));
    }
    let outcome = response
        .json::<arkret_wire::SignalRelayOutcome>()
        .await
        .map_err(|error| error.to_string())?;
    outcome.validate().map_err(|error| error.to_string())
}

fn authority_from_target_url(target_url: &str) -> String {
    let Ok(url) = reqwest::Url::parse(target_url) else {
        return String::new();
    };
    let Some(host) = url.host_str() else {
        return String::new();
    };
    url.port()
        .map(|port| format!("{host}:{port}"))
        .unwrap_or_else(|| host.to_owned())
}

pub(crate) fn insert_header_if_valid(
    headers: &mut reqwest::header::HeaderMap,
    name: &'static str,
    value: &str,
) {
    if let Ok(value) = reqwest::header::HeaderValue::from_str(value) {
        headers.insert(name, value);
    }
}

fn header_value(headers: &reqwest::header::HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(ToOwned::to_owned)
}

fn trust_domain_from_service_id(service_id: &str) -> String {
    super::federation::trust_domain_from_service_id(service_id)
}

/// Compute the RFC 9530 `Content-Digest` header value for a body.
pub(crate) fn content_digest_header_value(body: &[u8]) -> String {
    super::rfc9530_content_digest(body)
}

/// Truncate a response body for the `last_response_excerpt` column.
fn excerpt(body: &str) -> String {
    if body.len() <= RESPONSE_EXCERPT_BYTES {
        body.to_owned()
    } else {
        // Avoid splitting a multi-byte char mid-sequence.
        let mut end = RESPONSE_EXCERPT_BYTES;
        while end > 0 && !body.is_char_boundary(end) {
            end -= 1;
        }
        body[..end].to_owned()
    }
}

fn peer_event_application_failure(endpoint: &str, body: &str) -> Option<&'static str> {
    if endpoint == "/_soland/peer/federation/operations" {
        return match serde_json::from_str::<serde_json::Value>(body)
            .ok()
            .and_then(|value| {
                value
                    .get("rejected")
                    .and_then(serde_json::Value::as_array)
                    .cloned()
            }) {
            Some(rejected) if rejected.is_empty() => None,
            Some(_) => Some("partial_peer_operation_outcome"),
            None => Some("invalid_peer_operation_outcome"),
        };
    }
    if endpoint != "/_arkret/peer/events" {
        return None;
    }
    match serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .and_then(|value| {
            value
                .get("status")
                .and_then(|status| status.as_str())
                .map(str::to_owned)
        })
        .as_deref()
    {
        Some("accepted" | "duplicate") => None,
        Some("partial") => Some("partial_peer_event_outcome"),
        Some("historical_only") => Some("historical_only_peer_event_outcome"),
        _ => Some("invalid_peer_event_outcome"),
    }
}

#[derive(Debug, PartialEq, Eq)]
enum PeerEventPartialRetry {
    Rebuilt {
        payload_json: String,
        idempotency_key: String,
    },
}

fn peer_event_partial_retry(
    endpoint: &str,
    request_body: &str,
    response_body: &str,
) -> Option<PeerEventPartialRetry> {
    if endpoint != "/_arkret/peer/events" {
        return None;
    }
    let outcome: arkret_models_collaboration::http_bodies::EventsSubmitOutcome =
        serde_json::from_str(response_body).ok()?;
    if outcome.status != arkret_models_collaboration::http_bodies::EventsSubmitStatus::Partial
        || outcome.rejected.is_empty()
        || !outcome.quarantine.is_empty()
        || outcome
            .rejected
            .iter()
            .any(|item| item.reason_code != "dependency_missing")
    {
        return None;
    }

    let pending_ids = outcome
        .rejected
        .iter()
        .map(|item| item.id.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    let mut request: arkret_models_collaboration::event_sync::EventsSubmitFederationRequestBody =
        serde_json::from_str(request_body).ok()?;
    request
        .events
        .retain(|submission| pending_ids.contains(submission.event.event_id.as_str()));
    if request.events.is_empty() {
        return None;
    }
    let retained_events: Vec<arkret_wire::Event> =
        request.transported_events().cloned().collect::<Vec<_>>();
    request.signer_key_evidence.retain(|evidence| {
        retained_events
            .iter()
            .any(|event| evidence.matches_event_proof(event, &evidence.verification_method))
    });
    if let Some(bundle) = &mut request.agent_signer_evidence_bundle {
        bundle.evidence.retain(|evidence| {
            let binding = &evidence.signing_key_binding;
            retained_events.iter().any(|event| {
                event.applet_id.is_none()
                    && event.executed_by.as_ref().unwrap_or(&event.actor_id) == &binding.agent_id
                    && event.proofs.iter().any(|proof| {
                        proof.verification_method == binding.verification_method.as_str()
                    })
            })
        });
        if bundle.evidence.is_empty() {
            request.agent_signer_evidence_bundle = None;
        }
    }

    let required_targets = retained_events
        .iter()
        .flat_map(|event| {
            event.seal_ref.iter().chain(
                event
                    .seal_basis
                    .iter()
                    .flat_map(|basis| basis.leaves.iter()),
            )
        })
        .collect::<std::collections::BTreeSet<_>>();
    request
        .cba_proof_bundles
        .retain(|bundle| required_targets.contains(&bundle.target_seal_ref));
    request.validate_federation_transport().ok()?;
    let bytes = arkret_canonical::canonical_json_bytes(&request).ok()?;
    let payload_json = String::from_utf8(bytes.clone()).ok()?;
    let idempotency_key = format!(
        "ak:outbox:partial:{}",
        arkret_canonical::sha256_digest(&bytes)
    );
    Some(PeerEventPartialRetry::Rebuilt {
        payload_json,
        idempotency_key,
    })
}

/// Compute the next retry timestamp for a retryable failure. Doubles
/// the backoff on each attempt and caps at 1h.
fn next_backoff_unix_secs(attempts: i32, now: i64) -> i64 {
    // 2^attempts * 5, capped at 3600 (1h). The cast saturates because
    // 2^30 already exceeds the cap.
    let raw = (attempts as u32).min(20);
    let backoff = 5u64.saturating_mul(1u64 << raw).min(3_600);
    now + backoff as i64
}

/// Causal dependency misses are expected while a related batch is still in
/// flight. Retry them on the next dispatcher tick instead of applying the
/// exponential transport-failure backoff.
fn causal_dependencies_pending(body: &str) -> bool {
    matches!(
        serde_json::from_str::<serde_json::Value>(body)
            .ok()
            .and_then(|value| {
                value
                    .pointer("/error/code")
                    .and_then(|code| code.as_str())
                    .map(str::to_owned)
            })
            .as_deref(),
        Some("dependency_missing" | "direct_binding_dependencies_pending")
    )
}

/// Background outbound federation dispatcher.
pub struct FederationDispatcher {
    state: AppState,
}

impl FederationDispatcher {
    pub fn new(state: AppState) -> Self {
        Self { state }
    }

    /// Spawn the dispatcher loop on the current tokio runtime. Returns
    /// a `JoinHandle` the caller can `abort()` at shutdown.
    pub fn spawn(self) -> Arc<tokio::task::JoinHandle<()>> {
        let task = tokio::spawn(async move {
            let mut ticker = tokio::time::interval(POLL_INTERVAL);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                ticker.tick().await;
                if let Err(error) = self.run_one_pass().await {
                    tracing::warn!(
                        %error,
                        worker = "federation_outbox",
                        target = "federation_outbox",
                        "federation outbox pass failed (will retry on next tick)"
                    );
                }
            }
        });
        Arc::new(task)
    }

    /// Run one dispatch pass. Pulled out of [`spawn`] so the
    /// integration test can drive the loop deterministically.
    pub async fn run_one_pass(&self) -> Result<(), String> {
        let now = now_unix_secs();
        let rows = self
            .state
            .federation()
            .pending_deliveries(now, POLL_BATCH_LIMIT)
            .await
            .map_err(|e| e.to_string())?;
        for row in rows {
            self.deliver_one(persistence_delivery(row)).await;
        }
        Ok(())
    }

    /// Deliver a single row. The result is recorded back to the outbox.
    async fn deliver_one(&self, mut row: FederationDispatchState) {
        let url = format!("{}{}", row.peer_url, row.endpoint);
        let body_bytes = row.payload_json.as_bytes().to_vec();
        // SOL-03-002: build a per-delivery client that pins the validated IPs
        // (egress check and connection resolve to the same addresses), closing
        // the DNS-rebinding TOCTOU window. Peer URLs vary per delivery, so the
        // pinning is per-row rather than on the long-lived `self.client`.
        let (parsed_url, client) =
            match crate::security::validate_http_url_for_egress_with_pinned_client(
                &url,
                "federation outbox",
                self.state.config().development_mode,
                REQUEST_TIMEOUT,
            ) {
                Ok(pair) => pair,
                Err(error) => {
                    row.attempts = row.attempts.saturating_add(1);
                    row.delivered_at = Some(now_unix_secs());
                    row.last_status = Some(EGRESS_POLICY_DENIED_STATUS_SENTINEL);
                    row.last_response_excerpt =
                        Some(excerpt(&format!("egress_policy_denied: {error}")));
                    tracing::warn!(
                        target = "federation_outbox",
                        worker = "federation_outbox",
                        outbox_id = %row.id,
                        peer_did = %row.peer_did,
                        endpoint = %row.endpoint,
                        %error,
                        "federation outbox delivery denied by egress policy"
                    );
                    if let Err(error) = self
                        .state
                        .federation()
                        .record_delivery_attempt(&application_delivery(&row))
                        .await
                    {
                        tracing::warn!(
                            %error,
                            worker = "federation_outbox",
                            outbox_id = %row.id,
                            target = "federation_outbox",
                            "failed to persist federation outbox egress-policy denial"
                        );
                    }
                    return;
                }
            };

        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            reqwest::header::CONTENT_TYPE,
            reqwest::header::HeaderValue::from_static("application/json"),
        );
        // The private operations rail uses its legacy federation signature
        // transcript, which does not cover Idempotency-Key. Outbox persistence
        // still deduplicates the delivery by this key; only the HTTP header is
        // omitted for that wire profile.
        if row.endpoint != "/_soland/peer/federation/operations"
            && let Ok(value) = reqwest::header::HeaderValue::from_str(&row.idempotency_key)
        {
            headers.insert("idempotency-key", value);
        }
        let digest = content_digest_header_value(&body_bytes);
        if let Ok(value) = reqwest::header::HeaderValue::from_str(&digest) {
            headers.insert("content-digest", value);
        }
        insert_header_if_valid(&mut headers, "source-service-id", self.state.service_id());
        insert_header_if_valid(&mut headers, "destination-service-id", &row.peer_did);
        insert_header_if_valid(
            &mut headers,
            "source-trust-domain",
            &self.state.config().trust_domain,
        );
        insert_header_if_valid(
            &mut headers,
            "destination-trust-domain",
            &trust_domain_from_service_id(&row.peer_did),
        );
        let headers = rfc9421_sign(&self.state, headers, "POST", &url, &body_bytes);

        let response = client
            .post(parsed_url)
            .headers(headers)
            .body(body_bytes)
            .send()
            .await;

        row.attempts = row.attempts.saturating_add(1);
        match response {
            Ok(resp) => {
                let status = resp.status().as_u16() as i32;
                let body_text = resp.text().await.unwrap_or_default();
                row.last_status = Some(status);
                row.last_response_excerpt = Some(excerpt(&body_text));
                let application_failure = peer_event_application_failure(&row.endpoint, &body_text);
                if (200..300).contains(&status) && application_failure.is_none() {
                    row.delivered_at = Some(now_unix_secs());
                    crate::metrics::record_federation_retry_state("delivered");
                    tracing::info!(
                        target = "federation_outbox",
                        worker = "federation_outbox",
                        outbox_id = %row.id,
                        peer_did = %row.peer_did,
                        endpoint = %row.endpoint,
                        status,
                        "federation outbox delivery succeeded"
                    );
                } else if (200..300).contains(&status) {
                    match peer_event_partial_retry(&row.endpoint, &row.payload_json, &body_text) {
                        Some(PeerEventPartialRetry::Rebuilt {
                            payload_json,
                            idempotency_key,
                        }) => {
                            row.payload_json = payload_json;
                            row.idempotency_key = idempotency_key;
                            self.schedule_retry(&mut row, status, true).await;
                        }
                        None => {
                            self.mark_application_failure(
                                &mut row,
                                application_failure.expect("checked as present"),
                            )
                            .await;
                        }
                    }
                } else if is_retryable_status(status) {
                    let dependencies_pending = causal_dependencies_pending(&body_text);
                    self.schedule_retry(&mut row, status, dependencies_pending)
                        .await;
                } else {
                    // Permanent 4xx — record and stop retrying.
                    self.mark_terminal_failure(&mut row, status).await;
                }
            }
            Err(error) => {
                // Network error / timeout — always retryable.
                row.last_status = None;
                row.last_response_excerpt = Some(excerpt(&format!("network_error: {error}")));
                self.schedule_retry(&mut row, 0, false).await;
            }
        }

        if let Err(error) = self
            .state
            .federation()
            .record_delivery_attempt(&application_delivery(&row))
            .await
        {
            tracing::warn!(
                %error,
                worker = "federation_outbox",
                outbox_id = %row.id,
                target = "federation_outbox",
                "failed to persist federation outbox row after delivery attempt"
            );
        }
    }

    async fn schedule_retry(
        &self,
        row: &mut FederationDispatchState,
        observed_status: i32,
        dependencies_pending: bool,
    ) {
        if row.attempts >= MAX_ATTEMPTS {
            // Out of retries — mark as gave-up with the sentinel status
            // so observability tools can distinguish "permanent 4xx" from
            // "exceeded retry budget on a retryable error".
            row.delivered_at = Some(now_unix_secs());
            row.last_status = Some(GAVE_UP_STATUS_SENTINEL);
            self.insert_dead_letter(row, GAVE_UP_STATUS_SENTINEL, "retry_budget_exhausted")
                .await;
            crate::metrics::record_federation_retry_state("retry_budget_exhausted");
            tracing::warn!(
                target = "federation_outbox",
                worker = "federation_outbox",
                outbox_id = %row.id,
                peer_did = %row.peer_did,
                attempts = row.attempts,
                observed_status,
                "federation outbox giving up after MAX_ATTEMPTS (dead-letter follow-up pending)"
            );
        } else {
            row.next_attempt_at = if dependencies_pending {
                now_unix_secs()
            } else {
                next_backoff_unix_secs(row.attempts, now_unix_secs())
            };
            crate::metrics::record_federation_retry_state("retry_scheduled");
        }
    }

    async fn mark_terminal_failure(&self, row: &mut FederationDispatchState, status: i32) {
        row.delivered_at = Some(now_unix_secs());
        self.insert_dead_letter(row, status, "terminal_http_status")
            .await;
        crate::metrics::record_federation_retry_state("terminal_http_status");
        tracing::warn!(
            target = "federation_outbox",
            worker = "federation_outbox",
            outbox_id = %row.id,
            peer_did = %row.peer_did,
            endpoint = %row.endpoint,
            status,
            attempts = row.attempts,
            response_excerpt = ?row.last_response_excerpt,
            "federation outbox permanent failure (4xx, no retry, dead-letter follow-up pending)"
        );
    }

    async fn mark_application_failure(
        &self,
        row: &mut FederationDispatchState,
        reason: &'static str,
    ) {
        row.delivered_at = Some(now_unix_secs());
        row.last_status = Some(PEER_EVENT_OUTCOME_REJECTED_STATUS_SENTINEL);
        self.insert_dead_letter(row, PEER_EVENT_OUTCOME_REJECTED_STATUS_SENTINEL, reason)
            .await;
        crate::metrics::record_federation_retry_state(reason);
        tracing::warn!(
            target: "federation_outbox",
            worker = "federation_outbox",
            outbox_id = %row.id,
            peer_did = %row.peer_did,
            endpoint = %row.endpoint,
            reason,
            response_excerpt = ?row.last_response_excerpt,
            "federation outbox peer Event outcome requires dead-letter follow-up"
        );
    }

    async fn insert_dead_letter(
        &self,
        row: &FederationDispatchState,
        terminal_status: i32,
        reason: &str,
    ) {
        let failed_at = row.delivered_at.unwrap_or_else(now_unix_secs);
        let record = soland_services::federation::FederationDeadLetter {
            id: Uuid::new_v4().to_string(),
            outbox_id: row.id.clone(),
            peer_did: row.peer_did.clone(),
            endpoint: row.endpoint.clone(),
            idempotency_key: row.idempotency_key.clone(),
            terminal_status,
            attempts: row.attempts,
            response_excerpt: row.last_response_excerpt.clone(),
            failed_at,
            reason: reason.to_owned(),
        };
        // P5 (5.4) — bump the DLQ counter at the *decision* boundary
        // (we have given up on this row) rather than the persistence
        // outcome so an alert fires even if the durable ledger write
        // also failed.
        crate::metrics::record_federation_outbox_dead_letter();
        if let Err(error) = self.state.federation().record_dead_letter(&record).await {
            tracing::warn!(
                %error,
                outbox_id = %row.id,
                target = "federation_outbox",
                "failed to insert federation outbox dead-letter row"
            );
        }
    }
}

/// Spawn the dispatcher if `config.federation_outbound_enabled` is true.
/// Returns `None` (no-op) when disabled — mirrors the compactor's spawn
/// contract.
pub fn spawn(state: AppState) -> Option<Arc<tokio::task::JoinHandle<()>>> {
    if !state.config().federation_outbound_enabled {
        return None;
    }
    Some(FederationDispatcher::new(state).spawn())
}

/// Whether a non-2xx status code should be retried (per `federation.md`
/// §8 + standard HTTP semantics).
fn is_retryable_status(status: i32) -> bool {
    matches!(status, 408 | 429) || (500..600).contains(&status)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_doubles_then_caps_at_one_hour() {
        let base: i64 = 1_000_000;
        // 2^0 * 5 = 5
        assert_eq!(next_backoff_unix_secs(0, base) - base, 5);
        // 2^1 * 5 = 10
        assert_eq!(next_backoff_unix_secs(1, base) - base, 10);
        // 2^9 * 5 = 2560
        assert_eq!(next_backoff_unix_secs(9, base) - base, 2560);
        // 2^20 * 5 saturates well above 3600 — clamps to cap.
        assert_eq!(next_backoff_unix_secs(20, base) - base, 3_600);
    }

    #[test]
    fn retryable_status_classification_matches_spec() {
        assert!(is_retryable_status(500));
        assert!(is_retryable_status(503));
        assert!(is_retryable_status(408));
        assert!(is_retryable_status(429));
        assert!(!is_retryable_status(200));
        assert!(!is_retryable_status(400));
        assert!(!is_retryable_status(401));
        assert!(!is_retryable_status(404));
    }

    #[test]
    fn causal_dependency_responses_are_classified_for_prompt_retry() {
        assert!(causal_dependencies_pending(
            r#"{"ok":false,"error":{"code":"dependency_missing"}}"#
        ));
        assert!(causal_dependencies_pending(
            r#"{"ok":false,"error":{"code":"direct_binding_dependencies_pending"}}"#
        ));
        assert!(!causal_dependencies_pending(
            r#"{"ok":false,"error":{"code":"service_unavailable"}}"#
        ));
        assert!(!causal_dependencies_pending("not json"));
    }

    #[test]
    fn content_digest_matches_rfc_9530_shape() {
        let body = br#"{"hello":"world"}"#;
        let header = content_digest_header_value(body);
        assert!(header.starts_with("sha-256=:"));
        assert!(header.ends_with(':'));
    }

    #[test]
    fn peer_event_partial_outcome_is_not_transport_success() {
        assert_eq!(
            peer_event_application_failure(
                "/_arkret/peer/events",
                r#"{"status":"partial","accepted":[],"rejected":[{"id":"ak:event:test"}]}"#
            ),
            Some("partial_peer_event_outcome")
        );
        assert_eq!(
            peer_event_application_failure(
                "/_arkret/peer/events",
                r#"{"status":"accepted","accepted":["ak:event:test"]}"#
            ),
            None
        );
        assert_eq!(
            peer_event_application_failure("/_arkret/peer/contacts", r#"{"status":"partial"}"#),
            None
        );
        assert_eq!(
            peer_event_application_failure(
                "/_soland/peer/federation/operations",
                r#"{"accepted":[],"rejected":[{"id":"ak:operation:test","reason_code":"capability_denied"}]}"#
            ),
            Some("partial_peer_operation_outcome")
        );
        assert_eq!(
            peer_event_application_failure(
                "/_soland/peer/federation/operations",
                r#"{"accepted":["ak:operation:test"],"rejected":[]}"#
            ),
            None
        );
    }

    #[test]
    fn all_pending_peer_event_partial_requires_a_parseable_request_for_a_fresh_key() {
        let response = r#"{
            "status":"partial",
            "accepted":[],
            "rejected":[{
                "id":"ak:event:019f0000-0000-7000-8000-000000000001",
                "reason_code":"dependency_missing",
                "missing_seal_refs":["ak:seal:sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]
            }]
        }"#;
        assert!(peer_event_partial_retry("/_arkret/peer/events", "not-read", response).is_none());
    }

    #[test]
    fn partial_success_rebuilds_only_pending_events_with_a_new_header_key() {
        // offline-publication.md 2.1 -- a federated Event travels inside an
        // EventFederationSubmission: the Event, the lease it was published
        // under, and the original ingress receipts. `validate_federation_transport`
        // binds every one of those digests, so the fixture computes them instead
        // of asserting placeholders: the retry rebuilder has to carry the whole
        // submission through, and it must never re-stamp a receipt.
        let realm_id =
            arkret_identifiers::RealmId::new("ak:realm:019f0000-0000-7000-8000-000000000000")
                .unwrap();
        let actor_id = arkret_identifiers::Did::new("did:web:alice.example").unwrap();
        let scope_ref = arkret_wire::ScopeRef::Realm {
            realm_id: realm_id.clone(),
        };
        let authority_set_policy = arkret_wire::AuthoritySetPolicy {
            schema: arkret_wire::AUTHORITY_SET_POLICY_SCHEMA.to_owned(),
            authority_set_id: "ak.authority_set.realm_admission.v1".to_owned(),
            policy_kind: arkret_wire::AuthoritySetPolicyKind::RealmAdmission,
            scope_ref: scope_ref.clone(),
            source: arkret_wire::AuthoritySetPolicySource {
                source_kind: arkret_wire::AuthoritySetSourceKind::RealmControl,
                source_ref: format!("ak:seal:sha256:{}", "d".repeat(64)),
                source_digest: arkret_identifiers::Hash::new(format!("sha256:{}", "c".repeat(64)))
                    .unwrap(),
                generation_ref: "1".to_owned(),
            },
            authorization_rules: vec![arkret_wire::AuthoritySetAuthorizationRule {
                rule_id: "realm_admission".to_owned(),
                issuer_role: arkret_wire::AuthoritySetIssuerRole::RealmAdmission,
                allowed_actions: vec!["ak.message.create".to_owned()],
                issuers: vec![arkret_wire::AuthoritySetIssuer {
                    verification_method: arkret_wire::DidUrl::new(
                        "did:web:authority.example#key-1",
                    )
                    .unwrap(),
                }],
                threshold: 1,
            }],
        };
        let authority_set_ref = arkret_wire::offline_publication::AuthoritySetRef {
            authority_set_id: authority_set_policy.authority_set_id.clone(),
            authority_set_digest: authority_set_policy.digest().unwrap(),
        };
        let issued_at: chrono::DateTime<chrono::Utc> = "2026-07-26T00:00:00.000Z".parse().unwrap();
        let received_at: chrono::DateTime<chrono::Utc> =
            "2026-07-26T00:00:01.000Z".parse().unwrap();

        let submission = |suffix: &str, lease_suffix: &str, receipt_suffix: &str| {
            let mut event = arkret_wire::Event::new_with_id_at(
                arkret_identifiers::EventId::new(format!(
                    "ak:event:019f0000-0000-7000-8000-{suffix}"
                ))
                .unwrap(),
                arkret_wire::events::EventKind::MESSAGE_CREATE,
                arkret_wire::ScopeRef::Realm {
                    realm_id: realm_id.clone(),
                },
                actor_id.clone(),
                1,
                arkret_identifiers::Hlc::new("019f00000000-0000-a11ce001").unwrap(),
                serde_json::json!({}),
                issued_at,
            )
            .unwrap();
            // A data-plane reducer input is a DataEvent: it MUST carry
            // `seal_ref` + `auth_context` (`event-and-patch.md` 2.4).
            event.seal_ref = Some(
                arkret_identifiers::SealId::new(format!("ak:seal:sha256:{}", "d".repeat(64)))
                    .unwrap(),
            );
            event.auth_context = Some(arkret_wire::event_envelope::AuthContext {
                did: actor_id.clone(),
                key_id: "did:web:alice.example#device-1".to_owned(),
                key_epoch: 0,
                credential_epoch: None,
            });
            let event_digest =
                arkret_identifiers::Hash::new(event.event_digest().unwrap()).unwrap();
            event.proofs = vec![arkret_wire::primitives::Proof {
                kind: "detached_jws".to_owned(),
                alg: "EdDSA".to_owned(),
                verification_method: "did:web:alice.example#device-1".to_owned(),
                event_digest: event_digest.clone(),
                created_at: issued_at,
                domain: None,
                audience: None,
                proof_purpose: None,
                jws: "a..b".to_owned(),
            }];
            let event_digest =
                arkret_identifiers::Hash::new(event.event_digest().unwrap()).unwrap();

            let mut lease = arkret_wire::offline_publication::AuthorizationLease {
                authorization_lease_id: arkret_identifiers::AuthorizationLeaseId::new(format!(
                    "ak:authorization_lease:019f0000-0000-7000-8000-{lease_suffix}"
                ))
                .unwrap(),
                basis_ref: arkret_wire::offline_publication::LeaseBasisRef::Seal(
                    arkret_identifiers::SealId::new(format!("ak:seal:sha256:{}", "d".repeat(64)))
                        .unwrap(),
                ),
                actor_id: actor_id.clone(),
                device_id: arkret_identifiers::DeviceId::new(
                    "ak:device:019f0000-0000-7000-8000-00000000de01",
                )
                .unwrap(),
                scope_ref: scope_ref.clone(),
                action: "ak.message.create".to_owned(),
                authorization_rule_id: "realm_admission".to_owned(),
                risk_tier: arkret_wire::offline_publication::RiskTier::Medium,
                issued_at,
                expires_at: issued_at + chrono::Duration::hours(4),
                authority_set_ref: authority_set_ref.clone(),
                authority_set_policy: authority_set_policy.clone(),
                proofs: Vec::new(),
            };
            let lease_digest = lease.lease_digest().unwrap();
            lease.proofs = vec![arkret_wire::primitives::PayloadProof {
                kind: "detached_jws".to_owned(),
                alg: "EdDSA".to_owned(),
                verification_method: "did:web:authority.example#key-1".to_owned(),
                payload_digest: lease_digest,
                created_at: issued_at,
                domain: None,
                audience: None,
                proof_purpose: None,
                jws: "a..b".to_owned(),
            }];

            let mut receipt = arkret_wire::offline_publication::IngressReceipt {
                receipt_id: arkret_identifiers::ReceiptId::new(format!(
                    "ak:receipt:019f0000-0000-7000-8000-{receipt_suffix}"
                ))
                .unwrap(),
                event_digest,
                authorization_lease_id: lease.authorization_lease_id.clone(),
                received_at,
                service_id: arkret_identifiers::Did::new("did:web:alpha.example").unwrap(),
                authority_set_ref: authority_set_ref.clone(),
                proofs: Vec::new(),
            };
            let receipt_digest = receipt.receipt_digest().unwrap();
            receipt.proofs = vec![arkret_wire::primitives::PayloadProof {
                kind: "detached_jws".to_owned(),
                alg: "EdDSA".to_owned(),
                verification_method: "did:web:alpha.example#notary-key".to_owned(),
                payload_digest: receipt_digest,
                created_at: received_at,
                domain: None,
                audience: None,
                proof_purpose: None,
                jws: "a..b".to_owned(),
            }];

            arkret_wire::EventFederationSubmission {
                event,
                authorization_lease: lease,
                ingress_receipts: vec![receipt],
                control_proposal_receipt: None,
            }
        };

        let request = arkret_models_collaboration::event_sync::EventsSubmitFederationRequestBody {
            service_binding_ref:
                arkret_models_collaboration::event_sync::FederationServiceBindingRef {
                    realm_id: realm_id.clone(),
                    realm_policy_digest: arkret_identifiers::Hash::new(format!(
                        "sha256:{}",
                        "b".repeat(64)
                    ))
                    .unwrap(),
                    membership_frontier: Vec::new(),
                    delivery_binding_frontier: Vec::new(),
                    destination_service_kind: "principal_server".to_owned(),
                    reducer_profile_digest: arkret_identifiers::Hash::new(format!(
                        "sha256:{}",
                        "c".repeat(64)
                    ))
                    .unwrap(),
                },
            events: vec![
                submission("000000000001", "00000000ae01", "00000000ce01"),
                submission("000000000002", "00000000ae02", "00000000ce02"),
            ],
            cba_proof_bundles: Vec::new(),
            signer_key_evidence: Vec::new(),
            agent_signer_evidence_bundle: None,
        };
        let pending_event_id = request.events[1].event.event_id.as_str().to_owned();
        let original_receipt =
            serde_json::to_value(&request.events[1].ingress_receipts[0]).unwrap();
        let response = format!(
            r#"{{
            "status":"partial",
            "accepted":["{}"],
            "rejected":[{{
                "id":"{pending_event_id}",
                "reason_code":"dependency_missing",
                "missing_seal_refs":["ak:seal:sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]
            }}]
        }}"#,
            request.events[0].event.event_id.as_str()
        );
        let Some(PeerEventPartialRetry::Rebuilt {
            payload_json,
            idempotency_key,
        }) = peer_event_partial_retry(
            "/_arkret/peer/events",
            &serde_json::to_string(&request).unwrap(),
            &response,
        )
        else {
            panic!("expected a rebuilt partial retry");
        };
        let rebuilt: serde_json::Value = serde_json::from_str(&payload_json).unwrap();
        assert_eq!(rebuilt["events"].as_array().unwrap().len(), 1);
        assert_eq!(rebuilt["events"][0]["event"]["event_id"], pending_event_id);
        assert_eq!(
            rebuilt["events"][0]["ingress_receipts"][0], original_receipt,
            "the retry carries the original ingress receipt byte-identically"
        );
        assert!(rebuilt.get("idempotency_key").is_none());
        assert!(idempotency_key.starts_with("ak:outbox:partial:sha256:"));
    }

    #[test]
    fn excerpt_truncates_at_one_kib_on_char_boundary() {
        let body = "a".repeat(2048);
        let trimmed = excerpt(&body);
        assert_eq!(trimmed.len(), RESPONSE_EXCERPT_BYTES);
    }
}
