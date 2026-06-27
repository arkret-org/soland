use std::net::SocketAddr;
use std::str::FromStr;

use super::*;
use crate::config::{AppConfig, FederationPolicy};
use crate::db::Db;
use crate::error::AppError;
use crate::state::AppState;

const FEDERATION_AUTH_FAILURE_MESSAGE_FOR_TEST: &str = "federation request authentication failed";

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
        ice: crate::config::IceServersConfig::default(),
        livekit: crate::config::LiveKitConfig::default(),
        cors_allow_origin: None,
        account_authority_url: None,
        oidc_client_id: None,
        development_mode: true,
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
        federation_policy: policy,
        federation_peers: peers,
        federation_outbound_enabled: false,
        federation_replica_observer: false,
        admin_default_page_limit: 100,
        admin_max_page_limit: 1000,
        admin_principal_dids: Vec::new(),
        to_device_queue_capacity: 10_000,
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
        seed_demo_data: true,
        trust_domain: "ck:trust_domain:soland.local".to_owned(),
        receive_policy_constraints: None,
        sovereign_enclave_enabled: false,
        sovereign_enclave_allowed_outbound_hosts: Vec::new(),
        candidate_join_policy_enabled: false,
        erasure_propagation_window_ms: 604_800_000,
        log_format: crate::config::LogFormat::Plain,
    }
}

fn verify_actor_body() -> cokret_sdk::FederationVerifyActorRequestBody {
    cokret_sdk::FederationVerifyActorRequestBody {
        actor_id: cokret_sdk::Did::new("did:web:alice.example").unwrap(),
        challenge: Some("challenge-1".to_owned()),
        signed_payload_digest: None,
        signature: serde_json::json!({
            "kid": "did:web:alice.example#key-1",
            "alg": "EdDSA",
            "sig": "test-signature"
        }),
        purpose: "federation.verify_actor".to_owned(),
        realm_id: None,
    }
}

fn trust_domain(value: &str) -> cokret_sdk::TypedTrustDomainId {
    cokret_sdk::TypedTrustDomainId::new(value.to_owned()).unwrap()
}

fn federation_headers(digest: &str) -> FederationTrustHeaders {
    FederationTrustHeaders {
        source_trust_domain: trust_domain("ck:trust_domain:peer.example"),
        destination_trust_domain: trust_domain("ck:trust_domain:soland.local"),
        request_canonical_digest: cokret_sdk::Hash::new(digest.to_owned()).unwrap(),
    }
}

#[test]
fn verify_actor_digest_uses_canonical_json() {
    let body = verify_actor_body();
    let value = serde_json::to_value(&body).unwrap();
    let expected = cokret_sdk::canonical::canonical_sha256(&value).unwrap();

    assert_eq!(federation_verify_actor_digest(&body).unwrap(), expected);
}

#[test]
fn verify_actor_headers_accept_matching_canonical_digest() {
    let body = verify_actor_body();
    let digest = federation_verify_actor_digest(&body).unwrap();
    let headers = federation_headers(&digest);

    validate_federation_headers(
        &headers,
        &trust_domain("ck:trust_domain:soland.local"),
        &digest,
    )
    .expect("matching digest and destination accepted");
}

#[test]
fn verify_actor_headers_reject_digest_mismatch() {
    let body = verify_actor_body();
    let digest = federation_verify_actor_digest(&body).unwrap();
    let headers = federation_headers(&format!("sha256:{}", "0".repeat(64)));

    let error = validate_federation_headers(
        &headers,
        &trust_domain("ck:trust_domain:soland.local"),
        &digest,
    )
    .expect_err("mismatched digest rejected");

    assert_eq!(error.code, crate::error::ErrorCode::Unauthenticated);
    assert_eq!(error.wire_code(), "unauthenticated");
    assert_eq!(error.http_status(), StatusCode::UNAUTHORIZED);
    assert_eq!(error.message, FEDERATION_AUTH_FAILURE_MESSAGE_FOR_TEST);
}

#[test]
fn verify_actor_headers_reject_destination_mismatch() {
    let body = verify_actor_body();
    let digest = federation_verify_actor_digest(&body).unwrap();
    let headers = federation_headers(&digest);

    let error = validate_federation_headers(
        &headers,
        &trust_domain("ck:trust_domain:other.example"),
        &digest,
    )
    .expect_err("wrong destination rejected");

    assert_eq!(error.code, crate::error::ErrorCode::Unauthenticated);
    assert_eq!(error.wire_code(), "unauthenticated");
    assert_eq!(error.http_status(), StatusCode::UNAUTHORIZED);
    assert_eq!(error.message, FEDERATION_AUTH_FAILURE_MESSAGE_FOR_TEST);
}

#[test]
fn private_inbound_write_rail_fails_closed_outside_development_mode() {
    let mut config = config_with_policy(FederationPolicy::Mesh, Vec::new());
    config.development_mode = false;
    let state = AppState::new(config, Db { pool: None });

    let error = ensure_private_inbound_write_rail_local(&state)
        .expect_err("private inbound write rail must fail closed in production mode");

    assert_eq!(error.http_status(), StatusCode::NOT_IMPLEMENTED);
    assert_eq!(error.wire_code(), "federation_interop_track_only");
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
    let targets = broadcast_move_to_peers(&state, "sha256:01").await;
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
        "ck.federation.outbound_fanout.transcript.v1"
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
    let targets = broadcast_move_to_peers(&state, "sha256:02").await;
    assert_eq!(targets, vec!["https://hub.example".to_owned()]);
}

#[tokio::test]
async fn empty_peers_list_is_a_no_op() {
    let cfg = config_with_policy(FederationPolicy::Mesh, Vec::new());
    let state = AppState::new(cfg, Db { pool: None });
    let targets = broadcast_seal_to_peers(&state, "ck:seal:sha256:01").await;
    assert!(targets.is_empty());
}

#[tokio::test]
async fn local_invite_membership_and_message_operations_project_invite() {
    let cfg = config_with_policy(
        FederationPolicy::Mesh,
        vec!["http://127.0.0.1:9|did:web:peer.example".to_owned()],
    );
    let state = AppState::new(cfg, Db { pool: None });
    let realm_id = RealmId::new("ck:realm:01904100-0000-7000-8000-000000000051").unwrap();
    let invite = Operation::create(
        cokret_sdk::OperationId::new("ck:operation:01904100-0000-7000-8000-000000000052").unwrap(),
        realm_id.clone(),
        cokret_sdk::events::kinds::MEMBER_STATE,
        json!({
            "actor_id": "did:web:bob.example",
            "member": "did:web:bob.example",
            "membership": "invite"
        }),
    );
    let invite_create = Operation::create(
        cokret_sdk::OperationId::new("ck:operation:01904100-0000-7000-8000-000000000055").unwrap(),
        realm_id.clone(),
        cokret_sdk::events::kinds::INVITE_CREATE,
        json!({
            "invite_id": "ck:invite:01904100-0000-7000-8000-000000000056",
            "invitee": "did:web:carol.example",
            "invite_delivery_target": {
                "recipient_service_did": "did:web:test.local",
                "recipient_service_type": "principal_server"
            },
            "introduction_evidence_digest": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
            "sender": "did:web:alice.example",
            "expires_at": "2030-01-01T00:00:00Z"
        }),
    );
    let message = Operation::create(
        cokret_sdk::OperationId::new("ck:operation:01904100-0000-7000-8000-000000000053").unwrap(),
        realm_id,
        cokret_sdk::events::kinds::MESSAGE_CREATE,
        json!({
            "event_id": "ck:event:01904100-0000-7000-8000-000000000054",
            "sender": "did:web:alice.example",
            "thread_id": "ck:strand:01904100-0000-7000-8000-000000000051",
            "content": {"kind": "ck.content.text", "body": "hello federation"}
        }),
    );

    crate::routing::events::projection::project_accepted_operations(
        &state,
        "did:web:alice.example",
        &[invite.clone(), invite_create.clone(), message.clone()],
    )
    .await;

    let projected_invite = state
        .persistence
        .realm_invites()
        .get("ck:invite:01904100-0000-7000-8000-000000000056")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        projected_invite.invitee.as_deref(),
        Some("did:web:carol.example")
    );
    assert_eq!(projected_invite.inviter, "did:web:alice.example");
    assert_eq!(projected_invite.status, "pending");
    assert_eq!(
        projected_invite
            .invite_delivery_target
            .as_ref()
            .and_then(|target| target.get("recipient_service_did"))
            .and_then(Value::as_str),
        Some("did:web:test.local")
    );
    assert_eq!(
        projected_invite.introduction_evidence_digest.as_deref(),
        Some("sha256:1111111111111111111111111111111111111111111111111111111111111111")
    );
}

#[tokio::test]
async fn operation_frontier_tracks_persisted_operation_ids() {
    let cfg = config_with_policy(FederationPolicy::Mesh, Vec::new());
    let state = AppState::new(cfg, Db { pool: None });
    let realm_id = RealmId::new("ck:realm:01904100-0000-7000-8000-000000000061").unwrap();
    let first = Operation::create(
        cokret_sdk::OperationId::new("ck:operation:01904100-0000-7000-8000-000000000062").unwrap(),
        realm_id.clone(),
        cokret_sdk::events::kinds::MESSAGE_CREATE,
        json!({"content": {"kind": "ck.content.text", "body": "one"}}),
    );
    let second = Operation::create(
        cokret_sdk::OperationId::new("ck:operation:01904100-0000-7000-8000-000000000063").unwrap(),
        realm_id,
        cokret_sdk::events::kinds::MESSAGE_CREATE,
        json!({"content": {"kind": "ck.content.text", "body": "two"}}),
    );
    state
        .persistence
        .federation_operations()
        .append(first.clone())
        .await
        .unwrap();
    let before =
        operation_frontier_value(&state, "ck:realm:01904100-0000-7000-8000-000000000061").await;
    state
        .persistence
        .federation_operations()
        .append(second.clone())
        .await
        .unwrap();
    let after =
        operation_frontier_value(&state, "ck:realm:01904100-0000-7000-8000-000000000061").await;

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
async fn seal_fanout_records_seal_target_and_retry_metadata() {
    let cfg = config_with_policy(
        FederationPolicy::Mesh,
        vec!["https://peer-seal.example".to_owned()],
    );
    let state = AppState::new(cfg, Db { pool: None });
    let targets = broadcast_seal_to_peers(&state, "ck:seal:sha256:02").await;
    assert_eq!(targets, vec!["https://peer-seal.example".to_owned()]);

    let peer_hash = sha256_hex("https://peer-seal.example".as_bytes());
    let seal_hash = sha256_hex("ck:seal:sha256:02".as_bytes());
    let txn_id = format!("outbound_seal:{}:{}", &peer_hash[..16], &seal_hash[..16]);
    let transcript = state
        .persistence
        .federation_transactions()
        .get("did:web:test.local", &txn_id)
        .await
        .unwrap()
        .expect("outbound seal transcript persisted");
    assert_eq!(transcript.response["target_path"], "/_cokret/peer/events");
    assert_eq!(transcript.response["intent"]["resource_kind"], "seal");
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
    broadcast_move_to_peers(&state, "sha256:retry").await;

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
            .await
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

// --- validate_signature_params freshness window (federation.md §3.2) ---

const SIG_TEST_DID: &str = "did:web:test.local";

fn sig_params(extra: &str) -> String {
    format!(
        "sig1=(\"@method\");keyid=\"{SIG_TEST_DID}#federation-fanout-key\";alg=\"ed25519\"{extra}"
    )
}

#[test]
fn validate_signature_params_accepts_fresh_window() {
    let now = Utc::now().timestamp();
    let params = sig_params(&format!(";created={now};expires={}", now + 120));
    validate_signature_params(&params, SIG_TEST_DID, "test")
        .expect("fresh signature within ±30s / 300s window must pass");
}

#[test]
fn validate_signature_params_rejects_missing_created() {
    let now = Utc::now().timestamp();
    let params = sig_params(&format!(";expires={}", now + 120));
    let err = validate_signature_params(&params, SIG_TEST_DID, "test")
        .expect_err("missing `created` must fail closed");
    assert_signature_param_rejection_is_minimal(err);
}

#[test]
fn validate_signature_params_rejects_missing_expires() {
    let now = Utc::now().timestamp();
    let params = sig_params(&format!(";created={now}"));
    let err = validate_signature_params(&params, SIG_TEST_DID, "test")
        .expect_err("missing `expires` must fail closed");
    assert_signature_param_rejection_is_minimal(err);
}

#[test]
fn validate_signature_params_rejects_past_clock_skew() {
    let now = Utc::now().timestamp();
    // created 60s in the past exceeds the ±30s window.
    let params = sig_params(&format!(";created={};expires={}", now - 60, now + 120));
    let err = validate_signature_params(&params, SIG_TEST_DID, "test")
        .expect_err("created beyond -30s skew must fail closed");
    assert_signature_param_rejection_is_minimal(err);
}

#[test]
fn validate_signature_params_rejects_future_clock_skew() {
    let now = Utc::now().timestamp();
    let params = sig_params(&format!(";created={};expires={}", now + 60, now + 120));
    let err = validate_signature_params(&params, SIG_TEST_DID, "test")
        .expect_err("created beyond +30s skew must fail closed");
    assert_signature_param_rejection_is_minimal(err);
}

#[test]
fn validate_signature_params_rejects_window_over_300s() {
    let now = Utc::now().timestamp();
    let params = sig_params(&format!(";created={now};expires={}", now + 400));
    let err = validate_signature_params(&params, SIG_TEST_DID, "test")
        .expect_err("validity window over 300s must fail closed");
    assert_signature_param_rejection_is_minimal(err);
}

#[test]
fn validate_signature_params_rejects_already_expired() {
    let now = Utc::now().timestamp();
    // created within skew but expires already past.
    let params = sig_params(&format!(";created={};expires={}", now - 20, now - 1));
    let err = validate_signature_params(&params, SIG_TEST_DID, "test")
        .expect_err("already-expired signature must fail closed");
    assert_signature_param_rejection_is_minimal(err);
}

fn assert_signature_param_rejection_is_minimal(err: AppError) {
    assert_eq!(err.code, crate::error::ErrorCode::Unauthenticated);
    assert_eq!(err.wire_code(), "unauthenticated");
    assert_eq!(err.http_status(), StatusCode::UNAUTHORIZED);
    assert_eq!(err.message, FEDERATION_AUTH_FAILURE_MESSAGE_FOR_TEST);
}
