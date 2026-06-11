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

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use cokret_sdk::identity::{DidDocument, DidResolver, DidWebResolver};
use cokret_sdk::model::AuthzDecision;
use cokret_sdk::{
    Did, Hash, PolicyCheckBoundTo, PolicyCheckOutcome, PolicyCheckRequestBody,
    PolicyCheckSignature, PolicyCheckSource, RealmId,
};
use ed25519_dalek::{Signer, SigningKey};
use serde::Serialize;
use serde_json::Value;
use soland::authz::obligation_executor::RequestContext;
use soland::authz::policy_client::{PolicyCheckRequestInput, PolicyClient};
use soland::authz::{SolandAuthzEngine, MergedAuthzDecision, check_with_policy_server};
use soland::reducer::RealmPolicyServerConfig;

const REALM_ID: &str = "ck:realm:01904100-0000-7000-8000-000000000001";
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
        action: "ck.message.create".to_owned(),
        source_service_did: Did::new("did:web:soland.local").unwrap(),
        source_service_type: "principal_server".to_owned(),
        source_ip_digest: Hash::new(format!("sha256:{}", "b".repeat(64))).unwrap(),
        signed_transport: serde_json::json!({"signed": true}),
        event_preview: Value::Null,
        auth_context: Value::Null,
        bypass_cache,
    }
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
        action: input.action.clone(),
        request_canonical_digest: input.canonical_request_hash(),
        source: PolicyCheckSource {
            service_did: input.source_service_did.clone(),
            service_type: input.source_service_type.clone(),
        },
        source_ip_digest: input.source_ip_digest.clone(),
        signed_transport: input.signed_transport.clone(),
        event_preview: input.event_preview.clone(),
        auth_context: input.auth_context.clone(),
    }
}

fn mock_allow_response(
    input: &PolicyCheckRequestInput,
    signing: &SigningKey,
) -> PolicyCheckOutcome {
    let request = wire_request(input);
    let zero = Hash::new(format!("sha256:{}", "0".repeat(64))).unwrap();
    let now = chrono::Utc::now();
    let expires_at =
        chrono::DateTime::<chrono::Utc>::from_timestamp(now.timestamp() + 60, 0).unwrap();
    let mut response = PolicyCheckOutcome {
        decision: AuthzDecision::Allow,
        bound_to: PolicyCheckBoundTo {
            realm_id: request.realm_id.clone(),
            actor_id: request.actor_id.clone(),
            action: request.action.clone(),
            request_canonical_digest: request.request_canonical_digest.clone(),
            policy_server_id: Did::new(POLICY_SERVER_DID).unwrap(),
        },
        auth_state_digest: zero.clone(),
        policy_frontier_digest: zero.clone(),
        membership_frontier_digest: zero,
        signature: PolicyCheckSignature {
            kid: format!("{POLICY_SERVER_DID}#key-1"),
            sig: String::new(),
        },
        reason_code: Some("ok".to_owned()),
        expires_at: Some(expires_at),
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
    auth_state_digest: &'a Hash,
    policy_frontier_digest: &'a Hash,
    membership_frontier_digest: &'a Hash,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason_code: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    expires_at: Option<&'a str>,
    #[serde(skip_serializing_if = "<[_]>::is_empty")]
    obligations: &'a [Value],
}

fn policy_decision_transcript_bytes(
    request: &PolicyCheckRequestBody,
    response: &PolicyCheckOutcome,
) -> Vec<u8> {
    let expires_at = response
        .expires_at
        .as_ref()
        .map(|ts| ts.format("%Y-%m-%dT%H:%M:%SZ").to_string());
    let transcript = PolicyDecisionTranscript {
        kind: "ck.policy.check.transcript.v1",
        request_id: request.request_id.as_str(),
        decision: &response.decision,
        bound_to: &response.bound_to,
        auth_state_digest: &response.auth_state_digest,
        policy_frontier_digest: &response.policy_frontier_digest,
        membership_frontier_digest: &response.membership_frontier_digest,
        reason_code: response.reason_code.as_deref(),
        expires_at: expires_at.as_deref(),
        obligations: &response.obligations,
    };
    cokret_sdk::canonical::canonical_json_bytes(&transcript).unwrap()
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

    let url = format!("http://{addr}/_cokret/self/policy/check");
    let cfg = config_for(&url, 2000);
    let client = PolicyClient::new(reqwest::Client::new(), "did:web:soland.local")
        .with_private_network_egress(true)
        .with_policy_did_resolver(policy_resolver(&signing));
    let engine = SolandAuthzEngine::new();

    let mut ctx = RequestContext {
        realm_id: REALM_ID.to_owned(),
        actor_id: "did:web:alice.example".to_owned(),
        action: "ck.message.create".to_owned(),
        mfa_completed: true,
        mfa_requested: false,
        request_rate_counter: 0,
    };

    let decision = check_with_policy_server(
        &engine,
        "did:web:alice.example",
        // Use `read` so the LOCAL capability check passes via the
        // member-default rule (engine.check needs alice in `members`).
        "read",
        "ck:realm:01904100-0000-7000-8000-000000000001",
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

    let url = format!("http://{addr}/_cokret/self/policy/check");
    let cfg = config_for(&url, 250);
    let client = PolicyClient::new(reqwest::Client::new(), "did:web:soland.local")
        .with_private_network_egress(true);
    let engine = SolandAuthzEngine::new();

    let mut ctx = RequestContext {
        realm_id: REALM_ID.to_owned(),
        actor_id: "did:web:alice.example".to_owned(),
        action: "ck.message.create".to_owned(),
        mfa_completed: true,
        mfa_requested: false,
        request_rate_counter: 0,
    };

    let decision = check_with_policy_server(
        &engine,
        "did:web:alice.example",
        "read",
        "ck:realm:01904100-0000-7000-8000-000000000001",
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
            assert!(matches!(remote.decision, AuthzDecision::Deny));
            let reason = remote.reason_code.as_deref().unwrap_or("");
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
                    .starts_with("did:web:soland.local#proxy-"),
                "synthetic timeout response must be marked as proxy: {}",
                remote.signature.kid
            );
        }
        other => panic!("expected RemoteDeny on timeout, got {other:?}"),
    }
}
