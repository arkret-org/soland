//! G3.S2 — end-to-end integration test for the outbound policy server
//! client + obligation executor.
//!
//! Spins up a tiny in-process mock policy server (a `tokio::net::TcpListener`
//! that hand-crafts a fixed JSON response) and exercises:
//!
//! 1. `policy_server_integration_hits_mock` — happy path: a configured
//!    realm causes [`crate::authz::check_with_policy_server`] to POST the
//!    `/policy/check` request to the mock and propagate the returned
//!    decision.
//! 2. `policy_server_integration_timeout_fails_closed` — when the mock
//!    is unresponsive (listener never accepts), the client deadline
//!    elapses and the merged decision flips to deny with the canonical
//!    `policy_server_timeout` reason code.
//!
//! These cover the contract Wave B test
//! `cotest/e2e/tests/authz/policy-server-check.spec.ts` formalises at
//! the wire layer; cotest's playwright suite drives the same shape via
//! a Node-side mock at `MOCK_POLICY_SERVER_PORT`.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use contrix_sdk::model::AuthzDecision;
use contrix_sdk::{
    Did, Hash, PolicyCheckBoundTo, PolicyCheckResponse, PolicyCheckSignature, RealmId,
};
use serde_json::Value;
use soland::authz::obligation_executor::RequestContext;
use soland::authz::policy_client::{PolicyCheckRequestInput, PolicyClient};
use soland::authz::{AuthzEngine, MergedAuthzDecision, check_with_policy_server};
use soland::reducer::RealmPolicyServerConfig;

const REALM_ID: &str = "cx:realm:01904100-0000-7000-8000-000000000001";
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
        actor: Did::new("did:web:alice.example").unwrap(),
        action: "cx.message.create".to_owned(),
        source_service_did: Did::new("did:web:soland.local").unwrap(),
        source_service_type: "principal_server".to_owned(),
        source_ip_digest: Hash::new(format!("sha256:{}", "b".repeat(64))).unwrap(),
        signed_transport: serde_json::json!({"signed": true}),
        event_preview: Value::Null,
        auth_context: Value::Null,
        bypass_cache,
    }
}

fn mock_allow_response() -> PolicyCheckResponse {
    let zero = Hash::new(format!("sha256:{}", "0".repeat(64))).unwrap();
    PolicyCheckResponse {
        decision: AuthzDecision::Allow,
        bound_to: PolicyCheckBoundTo {
            realm_id: RealmId::new(REALM_ID).unwrap(),
            actor: Did::new("did:web:alice.example").unwrap(),
            action: "cx.message.create".to_owned(),
            request_canonical_digest: zero.clone(),
            policy_server_id: Did::new(POLICY_SERVER_DID).unwrap(),
        },
        auth_state_digest: zero.clone(),
        policy_frontier_digest: zero.clone(),
        membership_frontier_digest: zero,
        signature: PolicyCheckSignature {
            kid: format!("{POLICY_SERVER_DID}#key-1"),
            sig: "stub-sig".to_owned(),
        },
        reason_code: Some("ok".to_owned()),
        expires_at: Some(chrono::Utc::now() + chrono::Duration::seconds(60)),
        obligations: Vec::new(),
    }
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
    let body_json = serde_json::to_string(&mock_allow_response()).unwrap();
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

    let url = format!("http://{addr}/api/v1/policy/check");
    let cfg = config_for(&url, 2000);
    let client = PolicyClient::new(reqwest::Client::new(), "did:web:soland.local");
    let engine = AuthzEngine::new();

    let mut ctx = RequestContext {
        realm_id: REALM_ID.to_owned(),
        actor_did: "did:web:alice.example".to_owned(),
        action: "cx.message.create".to_owned(),
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
        "cx:realm:01904100-0000-7000-8000-000000000001",
        REALM_ID,
        Some("did:web:alice.example"),
        &[],
        &[],
        REALM_ID,
        Some(&client),
        Some(cfg),
        Some(input(true)),
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

    let url = format!("http://{addr}/api/v1/policy/check");
    let cfg = config_for(&url, 250);
    let client = PolicyClient::new(reqwest::Client::new(), "did:web:soland.local");
    let engine = AuthzEngine::new();

    let mut ctx = RequestContext {
        realm_id: REALM_ID.to_owned(),
        actor_did: "did:web:alice.example".to_owned(),
        action: "cx.message.create".to_owned(),
        mfa_completed: true,
        mfa_requested: false,
        request_rate_counter: 0,
    };

    let decision = check_with_policy_server(
        &engine,
        "did:web:alice.example",
        "read",
        "cx:realm:01904100-0000-7000-8000-000000000001",
        REALM_ID,
        Some("did:web:alice.example"),
        &[],
        &[],
        REALM_ID,
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
