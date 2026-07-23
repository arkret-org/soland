//! G3.S2 — end-to-end integration test for the outbound policy server
//! client + obligation executor.
//!
//! Spins up a tiny in-process mock policy server (a `tokio::net::TcpListener`
//! that hand-crafts a fixed JSON response) and exercises:
//!
//! 1. `policy_server_integration_hits_mock` — happy path: a configured realm causes
//!    [`crate::authz::check_with_policy_server`] to POST the `/policy/check` request to the mock
//!    and propagate the returned decision.
//! 2. `policy_server_integration_timeout_fails_closed` — when the mock is unresponsive (listener
//!    never accepts), the client deadline elapses and the merged decision flips to deny with the
//!    canonical `policy_server_timeout` reason code.
//!
//! These cover the contract Wave B test
//! `cotest/e2e/tests/authz/policy-server-check.spec.ts` formalises at
//! the wire layer; cotest's playwright suite drives the same shape via
//! a Node-side mock at `MOCK_POLICY_SERVER_PORT`.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use arkret_identifiers::{Did, Hash, RealmId};
use arkret_identity::{DidDocument, DidResolver, DidWebResolver};
use arkret_models_collaboration::governance::policy_check::{
    PolicyCheckBoundTo, PolicyCheckOutcome, PolicyCheckRequestBody, PolicyCheckSignature,
    PolicyCheckSource,
};
use arkret_wire::{AuthzDecision, FreshnessState};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::{Signer, SigningKey};
use serde::Serialize;
use serde_json::Value;
use soland_application::authorization::{AuthorizationApplicationService, RealmPolicyServerConfig};
use soland_http::authz::obligation_executor::RequestContext;
use soland_http::authz::policy_client::{
    PolicyCheckRequestInput, PolicyClient, PolicyFrontierSnapshot,
};
use soland_http::authz::{MergedAuthzDecision, SolandAuthzEngine, check_with_policy_server};

const REALM_ID: &str = "ak:realm:01904100-0000-7000-8000-000000000001";
const POLICY_SERVER_DID: &str = "did:web:policy.example.com";

fn config_for(url: &str, timeout_ms: u64) -> RealmPolicyServerConfig {
    RealmPolicyServerConfig {
        realm_id: REALM_ID.to_owned(),
        policy_server_did: POLICY_SERVER_DID.to_owned(),
        policy_server_url: url.to_owned(),
        cache_ttl_seconds: 60,
        timeout_ms,
        on_timeout: "fail_closed".to_owned(),
        updated_at: chrono::Utc::now(),
    }
}

fn input(bypass_cache: bool) -> PolicyCheckRequestInput {
    PolicyCheckRequestInput {
        request_id: "polreq_integ".to_owned(),
        realm_id: RealmId::new(REALM_ID).unwrap(),
        actor_id: Did::new("did:web:alice.example").unwrap(),
        action: "ak.message.create".to_owned(),
        source_service_id: Did::new(
            "did:webvh:z2dmjYwAPJzv5CZsnAzt8auVZRn1GfuxhpK2t3Q3K3rj4B1x:soland.local:webvh:service",
        )
        .unwrap(),
        source_service_type: "principal_server".to_owned(),
        source_ip_digest: Hash::new(format!("sha256:{}", "b".repeat(64))).unwrap(),
        signed_transport: true,
        event_preview: Value::Null,
        auth_context: Value::Null,
        expected_frontiers: zero_frontiers(),
        bypass_cache,
    }
}

fn zero_frontiers() -> PolicyFrontierSnapshot {
    let zero = Hash::new(format!("sha256:{}", "0".repeat(64))).unwrap();
    PolicyFrontierSnapshot::new(zero.clone(), zero.clone(), zero)
}

fn policy_signing_key() -> SigningKey {
    SigningKey::from_bytes(&[23u8; 32])
}

fn policy_resolver(signing: &SigningKey) -> Arc<dyn DidResolver + Send + Sync> {
    let mut resolver = DidWebResolver::new();
    resolver
        .insert(DidDocument::new(
            Did::new(POLICY_SERVER_DID).unwrap(),
            format!("{POLICY_SERVER_DID}#key-1"),
            ed25519_public_multibase(signing),
        ))
        .unwrap();
    Arc::new(resolver)
}

fn ed25519_public_multibase(signing: &SigningKey) -> String {
    let mut bytes = vec![0xed, 0x01];
    bytes.extend_from_slice(signing.verifying_key().as_bytes());
    format!("z{}", bs58::encode(bytes).into_string())
}

fn wire_request(input: &PolicyCheckRequestInput) -> PolicyCheckRequestBody {
    PolicyCheckRequestBody {
        request_id: input.request_id.clone(),
        realm_id: input.realm_id.clone(),
        actor_id: input.actor_id.clone(),
        device_id: None,
        action: input.action.clone(),
        request_canonical_digest: input.canonical_request_hash(),
        source: PolicyCheckSource {
            service_id: input.source_service_id.clone(),
            service_type: input.source_service_type.clone(),
            source_ip_digest: Some(input.source_ip_digest.clone()),
            signed_transport: input.signed_transport,
        },
        event_preview: serde_json::from_value(input.event_preview.clone()).ok(),
        auth_context: serde_json::from_value(input.auth_context.clone()).ok(),
    }
}

fn mock_allow_response(
    input: &PolicyCheckRequestInput,
    signing: &SigningKey,
) -> PolicyCheckOutcome {
    let request = wire_request(input);
    let now = chrono::Utc::now();
    let expires_at =
        chrono::DateTime::<chrono::Utc>::from_timestamp(now.timestamp() + 60, 0).unwrap();
    let mut response = PolicyCheckOutcome {
        request_id: request.request_id.clone(),
        decision: AuthzDecision::Allow,
        bound_to: PolicyCheckBoundTo {
            realm_id: request.realm_id.clone(),
            actor_id: request.actor_id.clone(),
            action: request.action.clone(),
            request_canonical_digest: request.request_canonical_digest.clone(),
            policy_server_id: Did::new(POLICY_SERVER_DID).unwrap(),
        },
        freshness_state: FreshnessState::Fresh,
        auth_state_digest: input.expected_frontiers.auth_state_digest.clone(),
        policy_frontier_digest: input.expected_frontiers.policy_frontier_digest.clone(),
        membership_frontier_digest: input.expected_frontiers.membership_frontier_digest.clone(),
        signature: PolicyCheckSignature {
            kid: format!("{POLICY_SERVER_DID}#key-1"),
            sig: String::new(),
        },
        reason_code: "ok".to_owned(),
        expires_at,
        next_retry_at: None,
        obligations: Vec::new(),
    };
    let transcript = policy_decision_transcript_bytes(&request, &response);
    response.signature.sig = URL_SAFE_NO_PAD.encode(signing.sign(&transcript).to_bytes());
    response
}

#[derive(Debug, Serialize)]
struct PolicyDecisionTranscript<'a> {
    kind: &'a str,
    request_id: &'a str,
    decision: &'a AuthzDecision,
    bound_to: &'a PolicyCheckBoundTo,
    freshness_state: &'a FreshnessState,
    auth_state_digest: &'a Hash,
    policy_frontier_digest: &'a Hash,
    membership_frontier_digest: &'a Hash,
    reason_code: &'a str,
    expires_at: &'a str,
    #[serde(skip_serializing_if = "<[_]>::is_empty")]
    obligations: &'a [Value],
}

fn policy_decision_transcript_bytes(
    request: &PolicyCheckRequestBody,
    response: &PolicyCheckOutcome,
) -> Vec<u8> {
    let expires_at = arkret_canonical::format_timestamp_canonical(response.expires_at);
    let transcript = PolicyDecisionTranscript {
        kind: "ak.policy.check.transcript.v1",
        request_id: request.request_id.as_str(),
        decision: &response.decision,
        bound_to: &response.bound_to,
        freshness_state: &response.freshness_state,
        auth_state_digest: &response.auth_state_digest,
        policy_frontier_digest: &response.policy_frontier_digest,
        membership_frontier_digest: &response.membership_frontier_digest,
        reason_code: response.reason_code.as_str(),
        expires_at: expires_at.as_str(),
        obligations: &response.obligations,
    };
    arkret_canonical::canonical_json_bytes(&transcript).unwrap()
}

/// G3.S2 — soland calls coauth's `/policy/check` end-to-end. Asserts
/// the mock receives the POST and the merged authz decision reflects
/// the mock's `Allow` response.
#[tokio::test]
async fn policy_server_integration_hits_mock() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let hit_count = Arc::new(AtomicUsize::new(0));
    let hit_count_clone = hit_count.clone();
    let signing = policy_signing_key();
    let policy_input = input(true);
    let body_json = serde_json::to_string(&mock_allow_response(&policy_input, &signing)).unwrap();
    tokio::spawn(async move {
        if let Ok((mut sock, _)) = listener.accept().await {
            hit_count_clone.fetch_add(1, Ordering::SeqCst);
            let mut buf = [0u8; 8192];
            let _ = tokio::io::AsyncReadExt::read(&mut sock, &mut buf).await;
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                body_json.len(),
                body_json
            );
            let _ = tokio::io::AsyncWriteExt::write_all(&mut sock, resp.as_bytes()).await;
        }
    });

    let url = format!("http://{addr}/_arkret/self/policy/check");
    let cfg = config_for(&url, 2000);
    let client = PolicyClient::new(
        reqwest::Client::new(),
        "did:webvh:z2dmjYwAPJzv5CZsnAzt8auVZRn1GfuxhpK2t3Q3K3rj4B1x:soland.local:webvh:service",
    )
    .with_private_network_egress(true)
    .with_policy_did_resolver(policy_resolver(&signing));
    let engine = AuthorizationApplicationService::new(Arc::new(SolandAuthzEngine::new()));

    let mut ctx = RequestContext {
        realm_id: REALM_ID.to_owned(),
        actor_id: "did:web:alice.example".to_owned(),
        action: "ak.message.create".to_owned(),
        mfa_completed: true,
        mfa_requested: false,
        request_rate_counter: 0,
    };

    let decision = check_with_policy_server(
        &engine,
        "did:web:alice.example",
        // Use the registered read capability so the LOCAL owner check passes
        // before the remote policy decision is evaluated.
        "ak.event.read",
        "ak:realm:01904100-0000-7000-8000-000000000001",
        REALM_ID,
        Some("did:web:alice.example"),
        &[],
        &[],
        Some(&client),
        Some(cfg),
        Some(policy_input),
        &mut ctx,
    )
    .await;

    assert!(
        decision.is_allowed(),
        "merged decision should be allow when both local + remote allow; got {decision:?}"
    );
    assert_eq!(
        hit_count.load(Ordering::SeqCst),
        1,
        "mock policy server should have received exactly one POST"
    );
}

/// G3.S2 — when the mock is unresponsive (listener never accepts),
/// the per-realm `timeout_ms` deadline elapses and the merged decision
/// is a remote-deny with a canonical timeout reason code.
#[tokio::test]
async fn policy_server_integration_timeout_fails_closed() {
    // Bind a listener but never `accept` — the client will time out.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    // Hold the listener alive for the test window so the connect itself
    // doesn't ECONNREFUSED; we want the read deadline to fire.
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(5)).await;
        drop(listener);
    });

    let url = format!("http://{addr}/_arkret/self/policy/check");
    let cfg = config_for(&url, 250);
    let client = PolicyClient::new(
        reqwest::Client::new(),
        "did:webvh:z2dmjYwAPJzv5CZsnAzt8auVZRn1GfuxhpK2t3Q3K3rj4B1x:soland.local:webvh:service",
    )
    .with_private_network_egress(true);
    let engine = AuthorizationApplicationService::new(Arc::new(SolandAuthzEngine::new()));

    let mut ctx = RequestContext {
        realm_id: REALM_ID.to_owned(),
        actor_id: "did:web:alice.example".to_owned(),
        action: "ak.message.create".to_owned(),
        mfa_completed: true,
        mfa_requested: false,
        request_rate_counter: 0,
    };

    let decision = check_with_policy_server(
        &engine,
        "did:web:alice.example",
        "ak.event.read",
        "ak:realm:01904100-0000-7000-8000-000000000001",
        REALM_ID,
        Some("did:web:alice.example"),
        &[],
        &[],
        Some(&client),
        Some(cfg),
        Some(input(true)),
        &mut ctx,
    )
    .await;

    match decision {
        MergedAuthzDecision::RemoteDeny { remote, .. } => {
            assert!(matches!(remote.decision, AuthzDecision::HardDeny));
            let reason = remote.reason_code.as_str();
            assert!(
                reason == "policy_server_timeout"
                    || reason == "policy_server_transport_error"
                    || reason == "policy_server_denied_on_timeout",
                "expected timeout-class reason_code, got {reason}"
            );
            // Proxy signature marker — audit consumers branch on this.
            assert!(
                remote
                    .signature
                    .kid
                    .starts_with("did:webvh:z2dmjYwAPJzv5CZsnAzt8auVZRn1GfuxhpK2t3Q3K3rj4B1x:soland.local:webvh:service#proxy-"),
                "synthetic timeout response must be marked as proxy: {}",
                remote.signature.kid
            );
        }
        other => panic!("expected RemoteDeny on timeout, got {other:?}"),
    }
}
