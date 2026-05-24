//! G3.S0 — durable outbound federation HTTP delivery.
//!
//! ## Surface
//!
//! - [`enqueue_outbound`] — synchronous insert into the
//!   `federation_outbox` table. Called from
//!   [`super::federation::broadcast_move_to_peers`] (and the symmetric
//!   anchor helper) after the per-peer transcript is persisted. Returns
//!   the row's [`FederationOutboxRecord`] (newly-inserted or pre-existing
//!   when `(peer_did, idempotency_key)` already matched a prior row).
//! - [`FederationDispatcher`] / [`spawn`] — background tokio task. Polls
//!   the outbox every [`POLL_INTERVAL`], picks up to
//!   [`POLL_BATCH_LIMIT`] rows whose `next_attempt_at <= now`, POSTs each
//!   one to its peer with the spec-required headers, and writes the
//!   resulting delivery state (`delivered_at`, `last_status`,
//!   `last_response_excerpt`, `next_attempt_at`, `attempts`) back to the
//!   row.
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
//! - **Operator replay API**. Terminal failures are mirrored into
//!   `federation_outbox_dead_letter`, but there is not yet an HTTP
//!   endpoint that re-queues them with a fresh idempotency key.
//!
//! ## Parallel-work coordination
//!
//! - DOES NOT touch `reducer.rs` — G3.Y0 / G3.S3 own that.
//! - DOES NOT change the inbound federation handler shape — G2.T1 owns
//!   that.
//! - DOES NOT introduce a new HTTP client — reuses the existing
//!   `reqwest` async client soland already pulls in.

use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use ed25519_dalek::Signer as _;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::persistence::PersistenceResult;
use crate::state::{AppState, FederationOutboxDeadLetterRecord, FederationOutboxRecord};

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
/// Cap on the response excerpt we persist. 1 KiB matches the spec's
/// postmortem-evidence size budget.
const RESPONSE_EXCERPT_BYTES: usize = 1024;

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
/// re-broadcast of an already-anchored Move) returns the pre-existing
/// row instead of creating a duplicate, matching the spec's
/// `Idempotency-Key`-bound replay semantics in `federation.md` §8.5.
///
/// Returns the persisted [`FederationOutboxRecord`] so call sites can
/// log the row id without re-fetching.
pub fn enqueue_outbound(
    state: &AppState,
    peer_url: &str,
    peer_did: &str,
    endpoint: &str,
    idempotency_key: &str,
    payload_json: &str,
) -> PersistenceResult<FederationOutboxRecord> {
    let store = state.persistence.federation_outbox();
    let now = now_unix_secs();
    let candidate = FederationOutboxRecord {
        id: Uuid::new_v4().to_string(),
        peer_did: peer_did.to_owned(),
        peer_url: peer_url.trim_end_matches('/').to_owned(),
        endpoint: endpoint.to_owned(),
        idempotency_key: idempotency_key.to_owned(),
        payload_json: payload_json.to_owned(),
        attempts: 0,
        next_attempt_at: now,
        last_status: None,
        last_response_excerpt: None,
        created_at: now,
        delivered_at: None,
    };
    let inserted = store.enqueue(&candidate)?;
    if inserted {
        Ok(candidate)
    } else {
        // The UNIQUE INDEX on (peer_did, idempotency_key) collided —
        // return the existing row so callers can still observe the
        // outbox state without a follow-up lookup.
        let existing = store
            .snapshot_all()?
            .into_iter()
            .find(|row| {
                row.peer_did == candidate.peer_did
                    && row.idempotency_key == candidate.idempotency_key
            })
            .unwrap_or(candidate);
        Ok(existing)
    }
}

fn rfc9421_sign(
    state: &AppState,
    mut headers: reqwest::header::HeaderMap,
    method: &str,
    target_url: &str,
    body: &[u8],
) -> reqwest::header::HeaderMap {
    let request_canonical_digest = format!("sha256:{:x}", Sha256::digest(body));
    insert_header_if_valid(
        &mut headers,
        "request-canonical-digest",
        &request_canonical_digest,
    );

    let created = now_unix_secs();
    let keyid = format!("{}#federation-fanout-key", state.config.service_did);
    let covered = [
        "\"@method\"",
        "\"@target-uri\"",
        "\"content-digest\"",
        "\"source-service-did\"",
        "\"destination-service-did\"",
        "\"source-trust-domain\"",
        "\"destination-trust-domain\"",
        "\"request-canonical-digest\"",
    ]
    .join(" ");
    let signature_params =
        format!("({covered});created={created};keyid=\"{keyid}\";alg=\"ed25519\"",);
    let signature_input = format!("sig1={signature_params}");

    let signature_base = format!(
        "\"@method\": {}\n\
         \"@target-uri\": {}\n\
         \"content-digest\": {}\n\
         \"source-service-did\": {}\n\
         \"destination-service-did\": {}\n\
         \"source-trust-domain\": {}\n\
         \"destination-trust-domain\": {}\n\
         \"request-canonical-digest\": {}\n\
         \"@signature-params\": {}",
        method.to_ascii_uppercase(),
        target_url,
        header_value(&headers, "content-digest").unwrap_or_default(),
        header_value(&headers, "source-service-did").unwrap_or_default(),
        header_value(&headers, "destination-service-did").unwrap_or_default(),
        header_value(&headers, "source-trust-domain").unwrap_or_default(),
        header_value(&headers, "destination-trust-domain").unwrap_or_default(),
        request_canonical_digest,
        signature_params,
    );
    let signature = state.anchorer_signing_key().sign(signature_base.as_bytes());
    let signature_header = format!("sig1=:{}:", STANDARD.encode(signature.to_bytes()));

    insert_header_if_valid(&mut headers, "signature-input", &signature_input);
    insert_header_if_valid(&mut headers, "signature", &signature_header);
    headers
}

fn insert_header_if_valid(
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

fn trust_domain_from_service_did(service_did: &str) -> String {
    let scope = service_did
        .strip_prefix("did:web:")
        .or_else(|| service_did.strip_prefix("did:key:"))
        .or_else(|| service_did.strip_prefix("did:webvh:"))
        .unwrap_or(service_did)
        .replace(':', ".");
    format!("cx:trust_domain:{scope}")
}

/// Compute the RFC 9530 `Content-Digest` header value for a body.
fn content_digest_header_value(body: &[u8]) -> String {
    let digest = Sha256::digest(body);
    format!("sha-256=:{}:", STANDARD.encode(digest))
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

/// Compute the next retry timestamp for a retryable failure. Doubles
/// the backoff on each attempt and caps at 1h.
fn next_backoff_unix_secs(attempts: i32, now: i64) -> i64 {
    // 2^attempts * 5, capped at 3600 (1h). The cast saturates because
    // 2^30 already exceeds the cap.
    let raw = (attempts as u32).min(20);
    let backoff = 5u64.saturating_mul(1u64 << raw).min(3_600);
    now + backoff as i64
}

/// Build the reqwest client the dispatcher uses for every outbound
/// POST. Pulled out so the integration test can re-use the exact same
/// timeouts the production worker hits.
fn build_http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(REQUEST_TIMEOUT)
        .build()
        .expect("federation dispatcher reqwest client must build")
}

/// Background outbound federation dispatcher.
pub struct FederationDispatcher {
    state: AppState,
    client: reqwest::Client,
}

impl FederationDispatcher {
    pub fn new(state: AppState) -> Self {
        Self {
            state,
            client: build_http_client(),
        }
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
            .persistence
            .federation_outbox()
            .pending_due(now, POLL_BATCH_LIMIT)
            .map_err(|e| e.to_string())?;
        for row in rows {
            self.deliver_one(row).await;
        }
        Ok(())
    }

    /// Deliver a single row. The result is recorded back to the outbox.
    async fn deliver_one(&self, mut row: FederationOutboxRecord) {
        let url = format!("{}{}", row.peer_url, row.endpoint);
        let body_bytes = row.payload_json.as_bytes().to_vec();

        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            reqwest::header::CONTENT_TYPE,
            reqwest::header::HeaderValue::from_static("application/json"),
        );
        if let Ok(value) = reqwest::header::HeaderValue::from_str(&row.idempotency_key) {
            headers.insert("idempotency-key", value);
        }
        let digest = content_digest_header_value(&body_bytes);
        if let Ok(value) = reqwest::header::HeaderValue::from_str(&digest) {
            headers.insert("content-digest", value);
        }
        insert_header_if_valid(
            &mut headers,
            "source-service-did",
            &self.state.config.service_did,
        );
        insert_header_if_valid(&mut headers, "destination-service-did", &row.peer_did);
        insert_header_if_valid(
            &mut headers,
            "source-trust-domain",
            &self.state.config.trust_domain,
        );
        insert_header_if_valid(
            &mut headers,
            "destination-trust-domain",
            &trust_domain_from_service_did(&row.peer_did),
        );
        let headers = rfc9421_sign(&self.state, headers, "POST", &url, &body_bytes);

        let response = self
            .client
            .post(&url)
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
                if (200..300).contains(&status) {
                    row.delivered_at = Some(now_unix_secs());
                    tracing::info!(
                        target = "federation_outbox",
                        worker = "federation_outbox",
                        outbox_id = %row.id,
                        peer_did = %row.peer_did,
                        endpoint = %row.endpoint,
                        status,
                        "federation outbox delivery succeeded"
                    );
                } else if is_retryable_status(status) {
                    self.schedule_retry(&mut row, status);
                } else {
                    // Permanent 4xx — record and stop retrying.
                    self.mark_terminal_failure(&mut row, status);
                }
            }
            Err(error) => {
                // Network error / timeout — always retryable.
                row.last_status = None;
                row.last_response_excerpt = Some(excerpt(&format!("network_error: {error}")));
                self.schedule_retry(&mut row, 0);
            }
        }

        if let Err(error) = self.state.persistence.federation_outbox().update(&row) {
            tracing::warn!(
                %error,
                worker = "federation_outbox",
                outbox_id = %row.id,
                target = "federation_outbox",
                "failed to persist federation outbox row after delivery attempt"
            );
        }
    }

    fn schedule_retry(&self, row: &mut FederationOutboxRecord, observed_status: i32) {
        if row.attempts >= MAX_ATTEMPTS {
            // Out of retries — mark as gave-up with the sentinel status
            // so observability tools can distinguish "permanent 4xx" from
            // "exceeded retry budget on a retryable error".
            row.delivered_at = Some(now_unix_secs());
            row.last_status = Some(GAVE_UP_STATUS_SENTINEL);
            self.insert_dead_letter(row, GAVE_UP_STATUS_SENTINEL, "retry_budget_exhausted");
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
            row.next_attempt_at = next_backoff_unix_secs(row.attempts, now_unix_secs());
        }
    }

    fn mark_terminal_failure(&self, row: &mut FederationOutboxRecord, status: i32) {
        row.delivered_at = Some(now_unix_secs());
        self.insert_dead_letter(row, status, "terminal_http_status");
        tracing::warn!(
            target = "federation_outbox",
            worker = "federation_outbox",
            outbox_id = %row.id,
            peer_did = %row.peer_did,
            endpoint = %row.endpoint,
            status,
            attempts = row.attempts,
            "federation outbox permanent failure (4xx, no retry, dead-letter follow-up pending)"
        );
    }

    fn insert_dead_letter(&self, row: &FederationOutboxRecord, terminal_status: i32, reason: &str) {
        let failed_at = row.delivered_at.unwrap_or_else(now_unix_secs);
        let record = FederationOutboxDeadLetterRecord {
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
        if let Err(error) = self
            .state
            .persistence
            .federation_outbox()
            .insert_dead_letter(&record)
        {
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
    if !state.config.federation_outbound_enabled {
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
    fn content_digest_matches_rfc_9530_shape() {
        let body = br#"{"hello":"world"}"#;
        let header = content_digest_header_value(body);
        assert!(header.starts_with("sha-256=:"));
        assert!(header.ends_with(':'));
    }

    #[test]
    fn excerpt_truncates_at_one_kib_on_char_boundary() {
        let body = "a".repeat(2048);
        let trimmed = excerpt(&body);
        assert_eq!(trimmed.len(), RESPONSE_EXCERPT_BYTES);
    }
}
