use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use chrono::{DateTime, Duration, Utc};
use ed25519_dalek::Signer as _;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::{now, sha256_hex};
use crate::state::{AppState, FederationTransactionRecord};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct FederationPeerTarget {
    pub(crate) url: String,
    pub(crate) did: String,
}

pub(crate) fn configured_peer_targets(state: &AppState) -> Vec<FederationPeerTarget> {
    use crate::config::FederationPolicy;
    let settings = state.settings();
    let entries: Vec<String> = match settings.federation_policy {
        FederationPolicy::Mesh => settings.federation_peers.clone(),
        FederationPolicy::Hub => settings
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

pub(super) fn parse_peer_target(entry: &str) -> Option<FederationPeerTarget> {
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
pub(super) async fn enqueue_outbound_for(
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

pub(super) async fn record_outbound_fanout_attempt(
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
        origin_verification_method: None,
        service_binding_ref: None,
        origin_key_state_digest: None,
        local_peer_policy_digest: None,
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

pub(super) fn content_digest_header(bytes: &[u8]) -> String {
    crate::routing::federation::rfc9530_content_digest(bytes)
}

#[cfg(test)]
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(super) struct OutboundFanoutRetryReport {
    pub scanned: usize,
    pub due: usize,
    pub retried: usize,
    pub dead_lettered: usize,
    pub skipped: usize,
}

#[cfg(test)]
pub(super) async fn run_outbound_fanout_retry_pass_at(
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
pub(super) fn next_retry_at(response: &Value) -> Option<DateTime<Utc>> {
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
    use soland_data::Db;
    use crate::state::AppState;

    let cfg = AppConfig {
        public_base_url: "http://test".to_owned(),
        service_did: "did:web:test.local".to_owned(),
        object_storage: crate::config::ObjectStorageConfig::local(std::env::temp_dir()),
        development_mode: true,
        did_resolver_allow_methods: vec!["web".to_owned()],
        jws_replay_window_seconds: 0,
        federation_peers: peers,
        erasure_propagation_window_ms,
        ..AppConfig::test_default()
    };
    AppState::new(cfg, Db { pool: None })
}
