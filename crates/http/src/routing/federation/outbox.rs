//! G3.S0 — durable outbound federation HTTP delivery.
//!
//! ## Surface
//!
//! - [`enqueue_outbound`] — synchronous insert into the `federation_outbox` table, for the few call
//!   sites that are not themselves inside an Event commit transaction. Every path that accepts an
//!   Event builds its outbox rows *before* the commit and hands them to the storage unit-of-work
//!   instead.
//! - [`FederationDispatcher`] / [`spawn`] — background tokio task. Every [`POLL_INTERVAL`] it
//!   atomically claims up to [`POLL_BATCH_LIMIT`] due rows under a lease, POSTs each one to its
//!   peer with the spec-required headers, and applies the resulting terminal-or-retry transition
//!   under the same lease token.
//!
//! ## Delivery guarantees
//!
//! - source outbox to peer ingress: **at-least-once**;
//! - peer reducer side effect: idempotent on `(source, destination, idempotency_key,
//!   canonical_digest)` (`sync/federation.md` §8.5);
//! - every intent ends as `delivered`, `policy_suppressed`, `dead_lettered` or `superseded`;
//! - **no** exactly-once transport is promised.
//!
//! ## Two retry classes (`sync/federation.md` §8.5 + §4.1)
//!
//! - **Transport retry** — no response was received at all (timeout, connection reset, DNS). Same
//!   canonical body, same `Idempotency-Key`, fresh short-lived HTTP Message Signature, `attempts +
//!   1`, exponential backoff with bounded jitter and never earlier than the peer's `Retry-After`.
//! - **Semantic resubmission** — a response *was* received and requires re-evaluation
//!   (`dependency_missing`, partial outcome). The old attempt is terminated as `superseded`, the
//!   batch is mechanically diffed down to the still-unconfirmed Events, and a brand-new intent with
//!   a **new** `Idempotency-Key` is inserted in the same transaction. Reusing the old key here
//!   would keep hitting the receiver's cached failure.
//!
//! ## Parallel-work coordination
//!
//! - DOES NOT touch `reducer.rs` — G3.Y0 / G3.S3 own that.
//! - DOES NOT change the inbound federation handler shape — G2.T1 owns that.
//! - DOES NOT introduce a new HTTP client — reuses the existing `reqwest` async client soland
//!   already pulls in.

use std::sync::Arc;
use std::time::Duration;

use arkret_signatures::http_signature::{
    Component, SignedRequestParts, canonical_message, format_signature_input_component_list,
    parse_signature_input,
};
use rand::RngExt;
use soland_services::federation::{
    ClaimFederationDeliveriesCommand, FederationDeadLetter, FederationDeliveryOutcome,
    FederationDeliveryRecord, FederationPolicyResolution, PendingFederationDelivery,
    RecordFederationAttemptCommand,
};
use uuid::Uuid;

use crate::state::AppState;

/// How often the dispatcher polls the outbox when idle.
pub const POLL_INTERVAL: Duration = Duration::from_secs(5);
/// Maximum rows the dispatcher claims per poll. Keeps a backlog from
/// monopolizing the tokio runtime; subsequent ticks drain the rest.
pub const POLL_BATCH_LIMIT: usize = 32;
/// How long a claimed row stays owned by one worker. Comfortably longer than
/// [`REQUEST_TIMEOUT`] so a slow peer never causes a second worker to take the
/// row over mid-flight, but short enough that a crashed worker's backlog
/// resumes promptly.
pub const LEASE_DURATION_SECS: i64 = 120;
/// Per-request full-response timeout.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// Maximum transport attempts before the row is dead-lettered. Matches the
/// spec recommendation in `federation.md` §8 (≈ 10 attempts ≈ ~1h wallclock
/// with the capped exponential backoff below).
pub const MAX_ATTEMPTS: i32 = 10;
/// Maximum semantic resubmissions for one delivery intent chain. Independent
/// of the transport budget: `federation.md` §4.1 caps automatic re-submission
/// of a convergent dependency quarantine and requires the sender to stop and
/// raise an operator diagnostic instead of polling forever.
pub const MAX_SEMANTIC_ATTEMPTS: i32 = 8;
/// Transport backoff base — `5 * 2^attempts`, capped at 1h.
const TRANSPORT_BACKOFF_BASE_SECS: u64 = 5;
const TRANSPORT_BACKOFF_CAP_SECS: u64 = 3_600;
/// Semantic (dependency) backoff — `federation.md` §4.1 requires a start of
/// at least 1s and an upper bound of at least 60s, with jitter.
const SEMANTIC_BACKOFF_BASE_SECS: u64 = 1;
const SEMANTIC_BACKOFF_CAP_SECS: u64 = 300;
/// Fraction of the computed backoff spread randomly on top of it, so a fleet
/// that failed together does not retry together when the peer recovers.
const BACKOFF_JITTER_RATIO: f64 = 0.25;
/// Rows revalidated per pass when the egress policy version changed.
const POLICY_REVALIDATION_BATCH_LIMIT: usize = 32;
/// Cap on the response excerpt we persist. 1 KiB matches the spec's
/// postmortem-evidence size budget.
const RESPONSE_EXCERPT_BYTES: usize = 1024;

/// Stable `last_error_code` values. These are the operator-facing failure
/// vocabulary; they are also the `reason` on the dead-letter ledger rows.
pub mod error_code {
    pub const TRANSPORT_ERROR: &str = "transport_error";
    pub const RETRYABLE_HTTP_STATUS: &str = "retryable_http_status";
    pub const TERMINAL_HTTP_STATUS: &str = "terminal_http_status";
    pub const EGRESS_POLICY_DENIED: &str = "egress_policy_denied";
    pub const RETRY_BUDGET_EXHAUSTED: &str = "retry_budget_exhausted";
    pub const SEMANTIC_RETRY_BUDGET_EXHAUSTED: &str = "semantic_retry_budget_exhausted";
    pub const DEPENDENCY_MISSING: &str = "dependency_missing";
}

/// Compute the unix-second `now` the dispatcher and the enqueue path
/// agree on. Wraps `chrono::Utc::now()` so unit tests can swap the
/// clock without leaking `chrono` through the trait surfaces.
fn now_unix_secs() -> i64 {
    chrono::Utc::now().timestamp()
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
) -> reqwest::header::HeaderMap {
    rfc9421_sign_with_window(state, headers, method, target_url, 300)
}

fn rfc9421_sign_with_window(
    state: &AppState,
    mut headers: reqwest::header::HeaderMap,
    method: &str,
    target_url: &str,
    validity_seconds: i64,
) -> reqwest::header::HeaderMap {
    let created = now_unix_secs();
    let expires = created + validity_seconds;
    let keyid = super::federation_service_signature_key_id(state.service_id());
    let mut covered = vec![
        Component::Method,
        Component::TargetUri,
        Component::Authority,
        Component::Header("content-digest".to_owned()),
        Component::Header("source-service-id".to_owned()),
        Component::Header("destination-service-id".to_owned()),
        Component::Header("source-trust-domain".to_owned()),
        Component::Header("destination-trust-domain".to_owned()),
    ];
    let idempotency_key = header_value(&headers, "idempotency-key");
    if idempotency_key.is_some() {
        covered.push(Component::Header("idempotency-key".to_owned()));
    }
    let signature_input = format!(
        "{};created={created};expires={expires};keyid=\"{keyid}\";alg=\"ed25519\"",
        format_signature_input_component_list("sig1", &covered)
            .expect("federation signature component profile is valid")
    );
    let parsed_signature_input =
        parse_signature_input(&signature_input).expect("generated Signature-Input is valid");
    let authority = authority_from_target_url(target_url);
    let request = SignedRequestParts {
        method: method.to_owned(),
        target_uri: target_url.to_owned(),
        authority,
        path: String::new(),
        headers: headers
            .iter()
            .filter_map(|(name, value)| {
                value
                    .to_str()
                    .ok()
                    .map(|value| (name.as_str().to_owned(), value.to_owned()))
            })
            .collect(),
        body_digest: header_value(&headers, "content-digest"),
    };
    let signature_base = canonical_message(&request, &parsed_signature_input)
        .expect("generated federation signature components are present");
    let signature = arkret_signatures::http_signature::sign_message(
        &signature_base,
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
    let headers = rfc9421_sign_with_window(state, headers, "POST", &target, 5);
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

/// A rebuilt request that replaces a finished transport identity.
#[derive(Debug, PartialEq, Eq)]
struct SemanticResubmission {
    payload_json: String,
    idempotency_key: String,
}

/// `sync/federation.md` §8.5 — once a response has been received the old
/// `Idempotency-Key` is spent; re-evaluation MUST use a new one. The key is a
/// pure function of `(previous key, resubmission ordinal, new canonical body)`
/// so a crash between "decided to resubmit" and "wrote the successor row"
/// recomputes the same key, and the `(peer, idempotency_key)` unique index
/// collapses the replay instead of double-sending.
fn semantic_resubmission_key(
    previous_key: &str,
    semantic_attempts: i32,
    payload_json: &str,
) -> String {
    let mut input = Vec::new();
    input.extend_from_slice(previous_key.as_bytes());
    input.push(0);
    input.extend_from_slice(semantic_attempts.to_string().as_bytes());
    input.push(0);
    input.extend_from_slice(payload_json.as_bytes());
    format!(
        "ak:outbox:resubmit:{}",
        arkret_canonical::sha256_digest(&input)
    )
}

/// Whole-batch rejection that is convergent once the dependency lands. The
/// request body is unchanged (nothing was accepted), but the transport
/// identity is spent, so the resubmission still needs a fresh key.
fn dependency_resubmission(
    previous_key: &str,
    semantic_attempts: i32,
    request_body: &str,
) -> SemanticResubmission {
    SemanticResubmission {
        payload_json: request_body.to_owned(),
        idempotency_key: semantic_resubmission_key(previous_key, semantic_attempts, request_body),
    }
}

/// Mechanically diff a `partial` outcome down to the Events the receiver has
/// not confirmed, per `operations-sync.md` §5 ("subtract `accepted ∪
/// duplicate`, then reassemble"), and mint a fresh key for the remainder.
fn peer_event_partial_retry(
    endpoint: &str,
    request_body: &str,
    response_body: &str,
    previous_key: &str,
    semantic_attempts: i32,
) -> Option<SemanticResubmission> {
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
            .any(|item| item.reason_code != arkret_wire::ReasonCode::DependencyMissing)
    {
        return None;
    }

    let pending_ids = outcome
        .rejected
        .iter()
        .map(|item| item.id.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    let mut request: arkret_models_collaboration::event_sync::EventsSubmitFederationBatchRequestBody =
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
            let admission_evidence = match evidence {
                arkret_models_collaboration::agent_signer_evidence::AgentSignerEvidence::CurrentAdmission {
                    admission_evidence,
                    ..
                }
                | arkret_models_collaboration::agent_signer_evidence::AgentSignerEvidence::HistoricalEvent {
                    admission_evidence,
                    ..
                } => admission_evidence,
            };
            let binding = &admission_evidence
                .agent_authority_snapshot
                .core
                .signing_key_binding;
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
    let payload_json = String::from_utf8(bytes).ok()?;
    let idempotency_key = semantic_resubmission_key(previous_key, semantic_attempts, &payload_json);
    Some(SemanticResubmission {
        payload_json,
        idempotency_key,
    })
}

/// Exponential backoff with bounded jitter.
///
/// The deterministic part doubles per attempt and clamps at `cap`; the jitter
/// adds `[0, BACKOFF_JITTER_RATIO * delay]` so a fleet that failed against the
/// same peer does not stampede it the moment it recovers
/// (`federation.md` §4.1 requires jitter on convergent resubmission, §8.1
/// forbids retry storms generally).
fn backoff_delay_secs(attempts: i32, base: u64, cap: u64) -> u64 {
    let shift = (attempts.max(0) as u32).min(20);
    let delay = base.saturating_mul(1u64 << shift).min(cap);
    let spread = ((delay as f64) * BACKOFF_JITTER_RATIO) as u64;
    if spread == 0 {
        return delay;
    }
    delay + rand::rng().random_range(0..=spread)
}

fn transport_backoff_unix_secs(attempts: i32, now: i64) -> i64 {
    now + backoff_delay_secs(
        attempts,
        TRANSPORT_BACKOFF_BASE_SECS,
        TRANSPORT_BACKOFF_CAP_SECS,
    ) as i64
}

fn semantic_backoff_unix_secs(semantic_attempts: i32, now: i64) -> i64 {
    now + backoff_delay_secs(
        semantic_attempts.saturating_sub(1),
        SEMANTIC_BACKOFF_BASE_SECS,
        SEMANTIC_BACKOFF_CAP_SECS,
    ) as i64
}

/// The peer's own pacing instruction, as an absolute unix second.
///
/// `Retry-After` wins; the canonical `retry_after_ms` in the error envelope is
/// the fallback when the header is absent (`federation.md` §8.1 / §8.5).
fn peer_requested_retry_at(
    headers: &reqwest::header::HeaderMap,
    body: &str,
    now: i64,
) -> Option<i64> {
    if let Some(value) = headers
        .get(reqwest::header::RETRY_AFTER)
        .and_then(|value| value.to_str().ok())
    {
        let value = value.trim();
        if let Ok(seconds) = value.parse::<i64>() {
            return Some(now + seconds.max(0));
        }
        if let Ok(date) = chrono::DateTime::parse_from_rfc2822(value) {
            return Some(date.timestamp().max(now));
        }
    }
    let value: serde_json::Value = serde_json::from_str(body).ok()?;
    let retry_after_ms = value
        .pointer("/error/retry_after_ms")
        .or_else(|| value.pointer("/retry_after_ms"))?
        .as_i64()?;
    Some(now + retry_after_ms.max(0).div_euclid(1_000))
}

/// Whether a received response asks the sender to re-evaluate and resubmit
/// rather than replay the same transport identity.
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
    /// Durable-enough worker identity for the lease ledger: which process
    /// currently owns a row. Regenerated per process, which is exactly the
    /// granularity a crash-takeover needs to be attributable.
    worker_id: String,
}

impl FederationDispatcher {
    pub fn new(state: AppState) -> Self {
        let worker_id = format!("{}#{}", state.service_id(), Uuid::new_v4());
        Self { state, worker_id }
    }

    pub fn worker_id(&self) -> &str {
        &self.worker_id
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
        self.revalidate_policy_suppressed().await;
        let now = now_unix_secs();
        // One random token per pass. A row re-claimed by anyone (including this
        // worker on a later pass) gets a different token, which is exactly what
        // invalidates an in-flight holder's late write.
        let lease_token = Uuid::new_v4().to_string();
        let rows = self
            .state
            .federation()
            .claim_deliveries(ClaimFederationDeliveriesCommand {
                now,
                limit: POLL_BATCH_LIMIT,
                lease_owner: self.worker_id.clone(),
                lease_token: lease_token.clone(),
                lease_duration_secs: LEASE_DURATION_SECS,
            })
            .await
            .map_err(|e| e.to_string())?;
        for row in rows {
            self.deliver_one(row).await;
        }
        Ok(())
    }

    /// `federation.md` §4.4 — a row the local egress policy suppressed is not
    /// a delivery and not a network failure. It returns to the queue only when
    /// the policy version actually changed *and* the target revalidates; a
    /// bare restart never bypasses a policy that still denies the peer.
    async fn revalidate_policy_suppressed(&self) {
        let policy_version =
            crate::security::egress_policy_version(self.state.config().development_mode);
        let rows = match self
            .state
            .federation()
            .policy_suppressed_stale(&policy_version, POLICY_REVALIDATION_BATCH_LIMIT)
            .await
        {
            Ok(rows) => rows,
            Err(error) => {
                tracing::warn!(
                    %error,
                    worker = "federation_outbox",
                    target = "federation_outbox",
                    "failed to read policy-suppressed federation outbox rows"
                );
                return;
            }
        };
        for row in rows {
            let url = format!("{}{}", row.delivery.peer_url, row.delivery.endpoint);
            // §8 is re-checked here for the same reason the URL gate is: a
            // released row goes straight back to the wire, so a policy that
            // still denies the peer must still deny it after a version bump.
            let peer_trust_domain = super::federation::peer_trust_domain_for_service_id(
                &self.state,
                &row.delivery.peer_did,
            );
            let trust_domain_denied = crate::security::federation_outbound_trust_domain_denial(
                &row.delivery.peer_did,
                peer_trust_domain.as_deref(),
            )
            .is_some();
            let egress_ok = !trust_domain_denied
                && crate::security::validate_http_url_for_egress(
                    &url,
                    "federation outbox",
                    self.state.config().development_mode,
                )
                .is_ok();
            let resolution = if egress_ok {
                FederationPolicyResolution::Release {
                    next_attempt_at: now_unix_secs(),
                }
            } else {
                FederationPolicyResolution::Repin {
                    policy_version: policy_version.clone(),
                }
            };
            let released = matches!(resolution, FederationPolicyResolution::Release { .. });
            match self
                .state
                .federation()
                .resolve_policy_suppressed(&row.delivery.id, resolution)
                .await
            {
                Ok(true) if released => {
                    crate::metrics::record_federation_retry_state("policy_suppressed_released");
                    tracing::info!(
                        target = "federation_outbox",
                        worker = "federation_outbox",
                        outbox_id = %row.delivery.id,
                        peer_did = %row.delivery.peer_did,
                        "federation outbox row revalidated under the new egress policy"
                    );
                }
                Ok(_) => {}
                Err(error) => tracing::warn!(
                    %error,
                    worker = "federation_outbox",
                    outbox_id = %row.delivery.id,
                    target = "federation_outbox",
                    "failed to resolve policy-suppressed federation outbox row"
                ),
            }
        }
    }

    /// Deliver a single claimed row and apply its transition under the lease.
    async fn deliver_one(&self, row: PendingFederationDelivery) {
        let Some(lease_token) = row.lease_token.clone() else {
            tracing::error!(
                target = "federation_outbox",
                worker = "federation_outbox",
                outbox_id = %row.delivery.id,
                "claimed federation outbox row carries no lease token"
            );
            return;
        };
        let url = format!("{}{}", row.delivery.peer_url, row.delivery.endpoint);
        // `sovereign-deployment.md` §8 — the target service_id's trust_domain
        // MUST be checked against the local federation_allowlist BEFORE the
        // request leaves, and the sender MUST NOT rely on the receiver to
        // refuse. The URL egress gate below cannot stand in for this: it
        // decides on the host, and §8 binds the decision to the peer's
        // service_id.
        let peer_trust_domain = super::federation::peer_trust_domain_for_service_id(
            &self.state,
            &row.delivery.peer_did,
        );
        if let Some(reason) = crate::security::federation_outbound_trust_domain_denial(
            &row.delivery.peer_did,
            peer_trust_domain.as_deref(),
        ) {
            tracing::warn!(
                target = "federation_outbox",
                worker = "federation_outbox",
                outbox_id = %row.delivery.id,
                peer_did = %row.delivery.peer_did,
                endpoint = %row.delivery.endpoint,
                %reason,
                "federation outbox delivery suppressed by sovereign outbound trust_domain policy"
            );
            crate::metrics::record_federation_retry_state("policy_suppressed");
            // Same discipline as the egress denial below: no socket was
            // opened, so this MUST NOT consume the transport retry budget.
            self.commit(RecordFederationAttemptCommand {
                id: row.delivery.id.clone(),
                lease_token,
                attempts: row.attempts,
                semantic_attempts: row.semantic_attempts,
                last_http_status: None,
                last_error_code: Some(error_code::EGRESS_POLICY_DENIED.to_owned()),
                last_response_excerpt: Some(excerpt(&reason)),
                observed_at: now_unix_secs(),
                outcome: FederationDeliveryOutcome::PolicySuppressed {
                    policy_version: crate::security::egress_policy_version(
                        self.state.config().development_mode,
                    ),
                },
            })
            .await;
            return;
        }
        let body_bytes = row.delivery.payload_json.as_bytes().to_vec();
        // SOL-03-002: build a per-delivery client that pins the validated IPs
        // (egress check and connection resolve to the same addresses), closing
        // the DNS-rebinding TOCTOU window. Peer URLs vary per delivery, so the
        // pinning is per-row rather than on a long-lived client.
        let (parsed_url, client) =
            match crate::security::validate_http_url_for_egress_with_pinned_client(
                &url,
                "federation outbox",
                self.state.config().development_mode,
                REQUEST_TIMEOUT,
            ) {
                Ok(pair) => pair,
                Err(error) => {
                    tracing::warn!(
                        target = "federation_outbox",
                        worker = "federation_outbox",
                        outbox_id = %row.delivery.id,
                        peer_did = %row.delivery.peer_did,
                        endpoint = %row.delivery.endpoint,
                        %error,
                        "federation outbox delivery suppressed by egress policy"
                    );
                    crate::metrics::record_federation_retry_state("policy_suppressed");
                    // A policy denial never opened a socket, so it MUST NOT
                    // consume the transport retry budget.
                    self.commit(RecordFederationAttemptCommand {
                        id: row.delivery.id.clone(),
                        lease_token,
                        attempts: row.attempts,
                        semantic_attempts: row.semantic_attempts,
                        last_http_status: None,
                        last_error_code: Some(error_code::EGRESS_POLICY_DENIED.to_owned()),
                        last_response_excerpt: Some(excerpt(&format!(
                            "egress_policy_denied: {error}"
                        ))),
                        observed_at: now_unix_secs(),
                        outcome: FederationDeliveryOutcome::PolicySuppressed {
                            policy_version: crate::security::egress_policy_version(
                                self.state.config().development_mode,
                            ),
                        },
                    })
                    .await;
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
        if row.delivery.endpoint != "/_soland/peer/federation/operations"
            && let Ok(value) = reqwest::header::HeaderValue::from_str(&row.delivery.idempotency_key)
        {
            headers.insert("idempotency-key", value);
        }
        let digest = content_digest_header_value(&body_bytes);
        if let Ok(value) = reqwest::header::HeaderValue::from_str(&digest) {
            headers.insert("content-digest", value);
        }
        insert_header_if_valid(&mut headers, "source-service-id", self.state.service_id());
        insert_header_if_valid(
            &mut headers,
            "destination-service-id",
            &row.delivery.peer_did,
        );
        insert_header_if_valid(
            &mut headers,
            "source-trust-domain",
            &self.state.config().trust_domain,
        );
        insert_header_if_valid(
            &mut headers,
            "destination-trust-domain",
            &trust_domain_from_service_id(&row.delivery.peer_did),
        );
        // A transport retry keeps the body and the key but always re-signs:
        // the signature window is short-lived and the old one has expired.
        let headers = rfc9421_sign(&self.state, headers, "POST", &url);

        let response = client
            .post(parsed_url)
            .headers(headers)
            .body(body_bytes)
            .send()
            .await;

        let attempts = row.attempts.saturating_add(1);
        let now = now_unix_secs();
        let command = match response {
            Ok(resp) => {
                let status = resp.status().as_u16() as i32;
                let response_headers = resp.headers().clone();
                let body_text = resp.text().await.unwrap_or_default();
                self.classify_response(
                    &row,
                    &lease_token,
                    attempts,
                    status,
                    &response_headers,
                    &body_text,
                    now,
                )
            }
            Err(error) => {
                // No response at all — transport retry: same body, same key.
                self.transport_retry(
                    &row,
                    &lease_token,
                    attempts,
                    None,
                    error_code::TRANSPORT_ERROR,
                    excerpt(&format!("network_error: {error}")),
                    None,
                    now,
                )
            }
        };
        self.commit(command).await;
    }

    #[allow(clippy::too_many_arguments)]
    fn classify_response(
        &self,
        row: &PendingFederationDelivery,
        lease_token: &str,
        attempts: i32,
        status: i32,
        headers: &reqwest::header::HeaderMap,
        body_text: &str,
        now: i64,
    ) -> RecordFederationAttemptCommand {
        let response_excerpt = excerpt(body_text);
        let transport_succeeded = (200..300).contains(&status);
        // The typed outcome only classifies a *successful* transport. On a
        // non-2xx the status is the verdict: an error envelope that happens not
        // to look like an `EventsSubmitOutcome` must not be mistaken for an
        // application-level rejection and skip the retry classification below.
        let application_failure = transport_succeeded
            .then(|| peer_event_application_failure(&row.delivery.endpoint, body_text))
            .flatten();
        if transport_succeeded && application_failure.is_none() {
            crate::metrics::record_federation_retry_state("delivered");
            tracing::info!(
                target = "federation_outbox",
                worker = "federation_outbox",
                outbox_id = %row.delivery.id,
                peer_did = %row.delivery.peer_did,
                endpoint = %row.delivery.endpoint,
                status,
                "federation outbox delivery succeeded"
            );
            return RecordFederationAttemptCommand {
                id: row.delivery.id.clone(),
                lease_token: lease_token.to_owned(),
                attempts,
                semantic_attempts: row.semantic_attempts,
                last_http_status: Some(status),
                last_error_code: None,
                last_response_excerpt: Some(response_excerpt),
                observed_at: now,
                outcome: FederationDeliveryOutcome::Delivered,
            };
        }

        // A response was received. Anything that needs re-evaluation is a
        // semantic resubmission with a brand-new key, never a replay of this
        // transport identity (`federation.md` §8.5).
        let semantic_attempts = row.semantic_attempts.saturating_add(1);
        let resubmission = if transport_succeeded {
            peer_event_partial_retry(
                &row.delivery.endpoint,
                &row.delivery.payload_json,
                body_text,
                &row.delivery.idempotency_key,
                semantic_attempts,
            )
        } else if causal_dependencies_pending(body_text) {
            Some(dependency_resubmission(
                &row.delivery.idempotency_key,
                semantic_attempts,
                &row.delivery.payload_json,
            ))
        } else {
            None
        };

        if let Some(resubmission) = resubmission {
            let reason = application_failure.unwrap_or(error_code::DEPENDENCY_MISSING);
            if semantic_attempts > MAX_SEMANTIC_ATTEMPTS {
                // `federation.md` §4.1: bounded resubmission. Stop the loop and
                // hand the case to an operator instead of polling forever.
                return self.dead_letter(
                    row,
                    lease_token,
                    attempts,
                    Some(status),
                    error_code::SEMANTIC_RETRY_BUDGET_EXHAUSTED,
                    response_excerpt,
                    now,
                );
            }
            let next_attempt_at = peer_requested_retry_at(headers, body_text, now)
                .unwrap_or(0)
                .max(semantic_backoff_unix_secs(semantic_attempts, now));
            crate::metrics::record_federation_retry_state("semantic_resubmission");
            crate::metrics::record_federation_retry_delay(next_attempt_at - now);
            tracing::info!(
                target = "federation_outbox",
                worker = "federation_outbox",
                outbox_id = %row.delivery.id,
                peer_did = %row.delivery.peer_did,
                endpoint = %row.delivery.endpoint,
                status,
                reason,
                semantic_attempts,
                "federation outbox attempt superseded by a resubmission with a fresh key"
            );
            return RecordFederationAttemptCommand {
                id: row.delivery.id.clone(),
                lease_token: lease_token.to_owned(),
                attempts,
                semantic_attempts,
                last_http_status: Some(status),
                last_error_code: Some(reason.to_owned()),
                last_response_excerpt: Some(response_excerpt),
                observed_at: now,
                outcome: FederationDeliveryOutcome::Superseded {
                    delivery: Box::new(FederationDeliveryRecord {
                        id: Uuid::new_v4().to_string(),
                        peer_did: row.delivery.peer_did.clone(),
                        peer_url: row.delivery.peer_url.clone(),
                        endpoint: row.delivery.endpoint.clone(),
                        idempotency_key: resubmission.idempotency_key,
                        payload_json: resubmission.payload_json,
                        created_at: now,
                    }),
                    next_attempt_at,
                },
            };
        }

        if let Some(reason) = application_failure {
            // 2xx transport, non-success application outcome that no diff can
            // converge — terminal.
            return self.dead_letter(
                row,
                lease_token,
                attempts,
                Some(status),
                reason,
                response_excerpt,
                now,
            );
        }

        if is_retryable_status(status) {
            return self.transport_retry(
                row,
                lease_token,
                attempts,
                Some(status),
                error_code::RETRYABLE_HTTP_STATUS,
                response_excerpt,
                peer_requested_retry_at(headers, body_text, now),
                now,
            );
        }

        tracing::warn!(
            target = "federation_outbox",
            worker = "federation_outbox",
            outbox_id = %row.delivery.id,
            peer_did = %row.delivery.peer_did,
            endpoint = %row.delivery.endpoint,
            status,
            attempts,
            "federation outbox permanent failure (no retry, dead-lettered)"
        );
        self.dead_letter(
            row,
            lease_token,
            attempts,
            Some(status),
            error_code::TERMINAL_HTTP_STATUS,
            response_excerpt,
            now,
        )
    }

    /// Same transport identity, later. The peer's `Retry-After` is a floor:
    /// exponential backoff may push the retry later, never earlier.
    #[allow(clippy::too_many_arguments)]
    fn transport_retry(
        &self,
        row: &PendingFederationDelivery,
        lease_token: &str,
        attempts: i32,
        status: Option<i32>,
        failure_code: &str,
        response_excerpt: String,
        peer_retry_at: Option<i64>,
        now: i64,
    ) -> RecordFederationAttemptCommand {
        if attempts >= MAX_ATTEMPTS {
            return self.dead_letter(
                row,
                lease_token,
                attempts,
                status,
                error_code::RETRY_BUDGET_EXHAUSTED,
                response_excerpt,
                now,
            );
        }
        let next_attempt_at =
            transport_backoff_unix_secs(attempts, now).max(peer_retry_at.unwrap_or(0));
        crate::metrics::record_federation_retry_state("retry_scheduled");
        crate::metrics::record_federation_retry_delay(next_attempt_at - now);
        RecordFederationAttemptCommand {
            id: row.delivery.id.clone(),
            lease_token: lease_token.to_owned(),
            attempts,
            semantic_attempts: row.semantic_attempts,
            last_http_status: status,
            last_error_code: Some(failure_code.to_owned()),
            last_response_excerpt: Some(response_excerpt),
            observed_at: now,
            outcome: FederationDeliveryOutcome::Retry { next_attempt_at },
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn dead_letter(
        &self,
        row: &PendingFederationDelivery,
        lease_token: &str,
        attempts: i32,
        status: Option<i32>,
        reason: &str,
        response_excerpt: String,
        now: i64,
    ) -> RecordFederationAttemptCommand {
        // P5 (5.4) — bump the DLQ counter at the *decision* boundary (we have
        // given up on this row) rather than the persistence outcome, so an
        // alert fires even if the whole transaction later fails.
        crate::metrics::record_federation_outbox_dead_letter(reason);
        crate::metrics::record_federation_retry_state(reason);
        tracing::warn!(
            target = "federation_outbox",
            worker = "federation_outbox",
            outbox_id = %row.delivery.id,
            peer_did = %row.delivery.peer_did,
            endpoint = %row.delivery.endpoint,
            ?status,
            attempts,
            reason,
            "federation outbox row dead-lettered"
        );
        RecordFederationAttemptCommand {
            id: row.delivery.id.clone(),
            lease_token: lease_token.to_owned(),
            attempts,
            semantic_attempts: row.semantic_attempts,
            last_http_status: status,
            last_error_code: Some(reason.to_owned()),
            last_response_excerpt: Some(response_excerpt.clone()),
            observed_at: now,
            // Terminal state and failure ledger travel in one transaction, so
            // "stopped delivering" and "has evidence" can never disagree.
            outcome: FederationDeliveryOutcome::DeadLettered(Box::new(FederationDeadLetter {
                id: Uuid::new_v4().to_string(),
                outbox_id: row.delivery.id.clone(),
                peer_did: row.delivery.peer_did.clone(),
                endpoint: row.delivery.endpoint.clone(),
                idempotency_key: row.delivery.idempotency_key.clone(),
                last_http_status: status,
                attempts,
                response_excerpt: Some(response_excerpt),
                reason: reason.to_owned(),
                failed_at: now,
                requeued_outbox_id: None,
                requeued_by: None,
                requeue_reason: None,
                requeue_request_digest: None,
                requeued_at: None,
            })),
        }
    }

    async fn commit(&self, command: RecordFederationAttemptCommand) {
        let outbox_id = command.id.clone();
        match self
            .state
            .federation()
            .record_delivery_attempt(command)
            .await
        {
            Ok(true) => {}
            Ok(false) => {
                crate::metrics::record_federation_outbox_lease_takeover();
                tracing::warn!(
                    worker = "federation_outbox",
                    outbox_id = %outbox_id,
                    target = "federation_outbox",
                    "federation outbox lease moved on mid-delivery; discarding this worker's result"
                );
            }
            Err(error) => tracing::warn!(
                %error,
                worker = "federation_outbox",
                outbox_id = %outbox_id,
                target = "federation_outbox",
                "failed to persist federation outbox transition after delivery attempt"
            ),
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
    fn transport_backoff_doubles_caps_at_one_hour_and_carries_jitter() {
        let base: i64 = 1_000_000;
        for (attempts, deterministic) in [(0_i32, 5_i64), (1, 10), (9, 2_560), (20, 3_600)] {
            let mut observed = std::collections::BTreeSet::new();
            for _ in 0..64 {
                let delay = transport_backoff_unix_secs(attempts, base) - base;
                // The deterministic floor is never undercut, and the jitter is
                // bounded so backoff stays predictable for capacity planning.
                assert!(delay >= deterministic, "attempts={attempts} delay={delay}");
                assert!(
                    delay <= deterministic + (deterministic as f64 * BACKOFF_JITTER_RATIO) as i64,
                    "attempts={attempts} delay={delay}"
                );
                observed.insert(delay);
            }
            // Anything above the 1s floor must actually spread, or a whole
            // fleet retries in lockstep the moment a peer recovers.
            assert!(observed.len() > 1, "attempts={attempts} produced no jitter");
        }
    }

    #[test]
    fn semantic_backoff_starts_at_one_second_and_bounds_above_a_minute() {
        let base: i64 = 1_000_000;
        // `federation.md` §4.1 — start >= 1s, upper bound >= 60s, with jitter.
        assert!(semantic_backoff_unix_secs(1, base) - base >= 1);
        assert!(semantic_backoff_unix_secs(20, base) - base >= 60);
        assert!(
            semantic_backoff_unix_secs(20, base) - base
                <= SEMANTIC_BACKOFF_CAP_SECS as i64
                    + (SEMANTIC_BACKOFF_CAP_SECS as f64 * BACKOFF_JITTER_RATIO) as i64
        );
    }

    #[test]
    fn peer_retry_after_header_and_body_are_honoured() {
        // A present-day `now`, so the fixed HTTP-date below is genuinely in the
        // past and exercises the clamp rather than the ordering.
        let now = 1_800_000_000;
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            reqwest::header::RETRY_AFTER,
            reqwest::header::HeaderValue::from_static("120"),
        );
        assert_eq!(peer_requested_retry_at(&headers, "", now), Some(now + 120));

        let mut dated = reqwest::header::HeaderMap::new();
        dated.insert(
            reqwest::header::RETRY_AFTER,
            reqwest::header::HeaderValue::from_static("Sun, 06 Nov 1994 08:49:37 GMT"),
        );
        // Past dates clamp to `now` — a peer can delay us, never rush us.
        assert_eq!(peer_requested_retry_at(&dated, "", now), Some(now));

        // Header absent: the canonical `retry_after_ms` in the error envelope.
        assert_eq!(
            peer_requested_retry_at(
                &reqwest::header::HeaderMap::new(),
                r#"{"error":{"code":"rate_limited","retry_after_ms":4500}}"#,
                now,
            ),
            Some(now + 4)
        );
        assert_eq!(
            peer_requested_retry_at(&reqwest::header::HeaderMap::new(), "not json", now),
            None
        );
    }

    #[test]
    fn semantic_resubmission_keys_are_deterministic_and_never_reuse_the_old_key() {
        let first = semantic_resubmission_key("ak:outbox:event:sha256:aa", 1, "{}");
        let again = semantic_resubmission_key("ak:outbox:event:sha256:aa", 1, "{}");
        let next_round = semantic_resubmission_key("ak:outbox:event:sha256:aa", 2, "{}");
        // Deterministic: a crash between "decided to resubmit" and "wrote the
        // successor" recomputes the same key, so the unique index collapses it.
        assert_eq!(first, again);
        // But each resubmission round is a distinct transport identity, even
        // when the body is byte-identical (whole-batch dependency rejection).
        assert_ne!(first, next_round);
        assert_ne!(first, "ak:outbox:event:sha256:aa");
        assert!(first.starts_with("ak:outbox:resubmit:sha256:"));
    }

    #[test]
    fn whole_batch_dependency_rejection_resubmits_the_same_body_under_a_new_key() {
        let body = r#"{"events":[]}"#;
        let resubmission = dependency_resubmission("ak:outbox:event:sha256:aa", 1, body);
        assert_eq!(resubmission.payload_json, body);
        assert_ne!(resubmission.idempotency_key, "ak:outbox:event:sha256:aa");
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
                "id":"ak:event:AR-4MwpAcHt7pmjO-Cab9s-33ymPZefvcpl666_jGxiY",
                "reason_code":"dependency_missing",
                "missing_seal_refs":["ak:seal:sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]
            }]
        }"#;
        assert!(
            peer_event_partial_retry(
                "/_arkret/peer/events",
                "not-read",
                response,
                "ak:outbox:event:sha256:aa",
                1,
            )
            .is_none()
        );
    }

    #[test]
    fn partial_success_rebuilds_only_pending_events_with_a_new_header_key() {
        // offline-publication.md 2.1 -- a federated Event travels inside an
        // EventFederationSubmission: the Event, the lease it was published
        // under, and the original ingress receipts. `validate_federation_transport`
        // binds every one of those digests, so the fixture computes them instead
        // of asserting placeholders: the retry rebuilder has to carry the whole
        // submission through, and it must never re-stamp a receipt.
        let realm_id = arkret_identifiers::RealmId::new(
            "ak:realm:Ad45OVvW8PvF-UFqAF8ApvgyX0o6xBWwpg8UvABbuY40",
        )
        .unwrap();
        let actor_id = arkret_identifiers::Did::new("did:web:alice.example").unwrap();
        let scope_ref = arkret_wire::ScopeRef::Realm {
            realm_id: realm_id.clone(),
        };
        let authority_set_policy = arkret_wire::AuthoritySetPolicy {
            schema: arkret_wire::SchemaId::AUTHORITY_SET_POLICY_V1.to_owned(),
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
            let mut event = arkret_wire::Event::new_with_derived_id_at(
                arkret_wire::EventKind::MESSAGE_CREATE,
                arkret_wire::ScopeRef::Realm {
                    realm_id: realm_id.clone(),
                },
                actor_id.clone(),
                1,
                arkret_identifiers::Hlc::new("019f00000000-0000-a11ce001").unwrap(),
                serde_json::json!({"fixture_suffix": suffix}),
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
            event.event_id = event
                .derive_event_id()
                .expect("fixture Event id follows the completed digest payload");
            let event_digest =
                arkret_identifiers::Hash::new(event.event_digest().unwrap()).unwrap();
            event.proofs = vec![arkret_wire::primitives::Proof {
                kind: "detached_jws".to_owned(),
                verification_method: arkret_wire::DidUrl::new("did:web:alice.example#device-1")
                    .unwrap(),
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
                verification_method: arkret_wire::DidUrl::new("did:web:authority.example#key-1")
                    .unwrap(),
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
                verification_method: arkret_wire::DidUrl::new("did:web:alpha.example#notary-key")
                    .unwrap(),
                payload_digest: receipt_digest,
                created_at: received_at,
                domain: None,
                audience: None,
                proof_purpose: None,
                jws: "a..b".to_owned(),
            }];

            arkret_wire::EventFederationSubmission {
                event,
                authorization_lease: Some(lease),
                ingress_receipts: vec![receipt],
                control_proposal_ack: None,
                membership_compensation_evidence: None,
            }
        };

        let request =
            arkret_models_collaboration::event_sync::EventsSubmitFederationBatchRequestBody {
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
        let previous_key = "ak:outbox:event:sha256:aa";
        let Some(SemanticResubmission {
            payload_json,
            idempotency_key,
        }) = peer_event_partial_retry(
            "/_arkret/peer/events",
            &serde_json::to_string(&request).unwrap(),
            &response,
            previous_key,
            1,
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
        // The response was received, so the old transport identity is spent
        // (`federation.md` §8.5): the remainder travels under a fresh key.
        assert!(idempotency_key.starts_with("ak:outbox:resubmit:sha256:"));
        assert_ne!(idempotency_key, previous_key);
    }

    #[test]
    fn excerpt_truncates_at_one_kib_on_char_boundary() {
        let body = "a".repeat(2048);
        let trimmed = excerpt(&body);
        assert_eq!(trimmed.len(), RESPONSE_EXCERPT_BYTES);
    }
}
