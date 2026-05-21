//! G3.S0 integration test — covers the `routing::federation::outbox`
//! enqueue → background-dispatch → success-recording loop.
//!
//! The test spins up a tiny TCP mock peer (mirroring the pattern
//! `tests/http_api.rs::spawn_oauth_introspection_server` uses for the
//! introspection-mock case so we don't add a new dev dependency),
//! enqueues an outbox row directly, runs one dispatcher pass, then
//! asserts:
//!
//!   1. The mock peer received exactly one POST with the
//!      spec-required `Idempotency-Key` + `Content-Digest` headers
//!      (RFC 9530, and the deterministic key shape G3.S0 emits).
//!   2. The outbox row was marked `delivered_at IS NOT NULL` and
//!      `last_status` records the mock's 2xx response.
//!
//! The dispatcher's background loop is NOT spawned here — we drive
//! `FederationDispatcher::run_one_pass` directly so the test stays
//! deterministic without sleeping for the 5s poll interval.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::sync::mpsc;
use std::time::Duration;

use soland::config::{AppConfig, FederationPolicy, ObjectStorageConfig};
use soland::db::Db;
use soland::routing::federation::outbox::{FederationDispatcher, enqueue_outbound};
use soland::state::AppState;

/// Spin up a single-shot HTTP/1.1 mock peer on a random local port.
/// Returns the base URL the dispatcher posts to + a channel receiver
/// that the test reads the captured raw request from after the worker
/// finishes its delivery pass.
fn spawn_mock_peer() -> (String, mpsc::Receiver<String>) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept");
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        // Read the request headers + (most of) the body. For a tiny
        // test payload one read is enough — production servers loop,
        // but here we just want to inspect the captured bytes.
        let mut buffer = [0_u8; 8192];
        let read = stream.read(&mut buffer).unwrap_or(0);
        let request = String::from_utf8_lossy(&buffer[..read]).to_string();
        let body = b"{\"accepted\":true}";
        let response = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
            body.len(),
        );
        let _ = stream.write_all(response.as_bytes());
        let _ = stream.write_all(body);
        let _ = tx.send(request);
    });
    (url, rx)
}

fn outbox_test_config() -> AppConfig {
    AppConfig {
        bind: "127.0.0.1:0".parse().unwrap(),
        public_base_url: "http://server".to_owned(),
        service_did: "did:web:soland-outbox.local".to_owned(),
        tls_cert_path: None,
        tls_key_path: None,
        database_url: None,
        object_storage: ObjectStorageConfig::local(std::env::temp_dir().join("soland-outbox-test")),
        cors_allow_origin: None,
        auth_server_url: None,
        development_mode: true,
        oauth_introspection_url: None,
        oauth_introspection_bearer: None,
        session_grant_introspection_url: None,
        session_grant_introspection_bearer: None,
        did_resolver_allow_methods: vec!["web".to_owned(), "key".to_owned()],
        embedded_webvh_provider_enabled: false,
        embedded_webvh_registration_bearer: None,
        external_webvh_provider_url: None,
        external_webvh_provider_active: false,
        default_webvh_provider_id: None,
        jws_replay_window_seconds: 0,
        jws_replay_window_per_family: BTreeMap::new(),
        anchorer_signing_key_seed: None,
        agent_audit_binding_signing_seed: None,
        use_keystore: false,
        federation_policy: FederationPolicy::Mesh,
        federation_peers: Vec::new(),
        // Worker is driven manually via run_one_pass — leave the
        // boot-time spawn off so we don't race the background loop.
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
        trust_domain: "cx:trust_domain:soland-outbox.local".to_owned(),
        sovereign_enclave_enabled: false,
        sovereign_enclave_allowed_outbound_hosts: Vec::new(),
        erasure_propagation_window_ms: 604_800_000,
    }
}

#[tokio::test]
async fn enqueue_then_dispatch_delivers_payload_with_spec_headers() {
    let (peer_url, request_rx) = spawn_mock_peer();
    let state = AppState::new(outbox_test_config(), Db { pool: None });

    // Enqueue one outbound row — same path broadcast_move_to_peers
    // funnels through after computing the deterministic idempotency
    // key.
    let row = enqueue_outbound(
        &state,
        &peer_url,
        "did:web:peer.example",
        "/api/v1/federation/push-operations",
        "cx:outbox:test-idem-key-0001",
        r#"{"resource":"sha256:01"}"#,
    )
    .expect("enqueue must succeed");
    assert!(
        row.delivered_at.is_none(),
        "freshly enqueued row should be undelivered"
    );

    // Drive one dispatch pass synchronously.
    let dispatcher = FederationDispatcher::new(state.clone());
    dispatcher
        .run_one_pass()
        .await
        .expect("dispatch pass must succeed");

    // Wait briefly for the mock peer thread to publish the captured
    // request; the dispatcher's send-and-read-response is already
    // complete by this point so this is just the thread-handoff wait.
    let captured = request_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("mock peer should have received exactly one request");

    // Header assertions — Idempotency-Key + Content-Digest are
    // mandatory on every outbound POST per spec federation.md §3.2 + §8.5.
    let lower = captured.to_ascii_lowercase();
    assert!(
        lower.contains("idempotency-key: cx:outbox:test-idem-key-0001"),
        "captured request missing Idempotency-Key header; got: {captured}"
    );
    assert!(
        lower.contains("content-digest: sha-256=:"),
        "captured request missing Content-Digest (RFC 9530) header; got: {captured}"
    );
    assert!(
        captured.starts_with("POST /api/v1/federation/push-operations"),
        "request line should target the configured endpoint; got: {captured}"
    );
    assert!(
        captured.contains("{\"resource\":\"sha256:01\"}"),
        "captured request body should match enqueued payload; got: {captured}"
    );

    // Outbox row must be marked delivered with the mock's 2xx status.
    let updated = state
        .persistence
        .federation_outbox()
        .get(&row.id)
        .expect("outbox lookup")
        .expect("row still present");
    assert!(
        updated.delivered_at.is_some(),
        "row should be marked delivered after a 2xx response, got: {updated:?}"
    );
    assert_eq!(
        updated.last_status,
        Some(200),
        "last_status should record the 2xx the mock peer returned"
    );
    assert_eq!(
        updated.attempts, 1,
        "exactly one delivery attempt should be recorded for a first-pass 2xx",
    );
}
