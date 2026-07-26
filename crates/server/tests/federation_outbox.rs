//! G3.S0 integration test — covers the `routing::federation::outbox`
//! enqueue → background-dispatch → success-recording loop.
//!
//! The test spins up a tiny TCP mock peer so we don't add a new dev dependency,
//! enqueues an outbox row directly, runs one dispatcher pass, then
//! asserts:
//!
//!   1. The mock peer received exactly one POST with the spec-required `Idempotency-Key` +
//!      `Content-Digest` headers (RFC 9530, and the deterministic key shape G3.S0 emits).
//!   2. The outbox row was marked `delivered_at IS NOT NULL` and `last_status` records the mock's
//!      2xx response.
//!
//! The dispatcher's background loop is NOT spawned here — we drive
//! `FederationDispatcher::run_one_pass` directly so the test stays
//! deterministic without sleeping for the 5s poll interval.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::sync::mpsc;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use ed25519_dalek::{Signature, SigningKey, Verifier as _, VerifyingKey};
use sha2::{Digest, Sha256};
use soland_http::config::{AppConfig, ObjectStorageConfig};
use soland_http::routing::federation::outbox::{FederationDispatcher, enqueue_outbound};
use soland_http::state::AppState;
use soland_test_support::AppStateTestExt as _;

const PEER_DID: &str = "did:web:peer.example";
const FEDERATION_ENDPOINT: &str = "/_arkret/peer/events";
const IDEMPOTENCY_KEY: &str = "ak:outbox:test-idem-key-0001";
const PAYLOAD_JSON: &str = r#"{"resource":"sha256:01"}"#;

struct CapturedSignedRequestBody {
    captured: String,
    target_uri: String,
    state: AppState,
    row_id: String,
}

/// Spin up a single-shot HTTP/1.1 mock peer on a random local port.
/// Returns the base URL the dispatcher posts to + a channel receiver
/// that the test reads the captured raw request from after the worker
/// finishes its delivery pass.
fn spawn_mock_peer() -> (String, mpsc::Receiver<String>) {
    spawn_mock_peer_with_status("200 OK", br#"{"status":"accepted"}"#)
}

fn spawn_mock_peer_with_status(
    status: &'static str,
    body: &'static [u8],
) -> (String, mpsc::Receiver<String>) {
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
        let response = format!(
            "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
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
        object_storage: ObjectStorageConfig::local(std::env::temp_dir().join("soland-outbox-test")),
        development_mode: true,
        did_resolver_allow_methods: vec!["web".to_owned(), "key".to_owned()],
        jws_replay_window_seconds: 0,
        jws_replay_window_per_family: BTreeMap::new(),
        trust_domain: "ak:trust_domain:soland-outbox.local".to_owned(),
        ..soland_test_support::app_config()
    }
}

#[tokio::test]
async fn enqueue_then_dispatch_delivers_payload_with_spec_headers() {
    let captured = capture_signed_request().await;

    // Header assertions — Idempotency-Key, Content-Digest, trust-domain
    // binding, and RFC 9421 Signature headers are mandatory on every
    // outbound POST per spec federation.md §3.2 + §8.5.
    let lower = captured.captured.to_ascii_lowercase();
    assert!(
        lower.contains("idempotency-key: ak:outbox:test-idem-key-0001"),
        "captured request missing Idempotency-Key header; got: {}",
        captured.captured
    );
    assert!(
        lower.contains("content-digest: sha-256=:"),
        "captured request missing Content-Digest (RFC 9530) header; got: {}",
        captured.captured
    );
    assert!(
        lower.contains(&format!(
            "source-service-id: {}",
            captured.state.service_id().to_ascii_lowercase()
        )),
        "captured request missing Source-Service-ID binding; got: {}",
        captured.captured
    );
    assert!(
        lower.contains("destination-service-id: did:web:peer.example"),
        "captured request missing Destination-Service-ID binding; got: {}",
        captured.captured
    );
    assert!(
        lower.contains("source-trust-domain: ak:trust_domain:soland-outbox.local"),
        "captured request missing Source-Trust-Domain binding; got: {}",
        captured.captured
    );
    assert!(
        lower.contains("destination-trust-domain: ak:trust_domain:peer.example"),
        "captured request missing Destination-Trust-Domain binding; got: {}",
        captured.captured
    );
    assert!(
        lower.contains("request-canonical-digest: sha256:"),
        "captured request missing Request-Canonical-Digest binding; got: {}",
        captured.captured
    );
    assert!(
        lower.contains("signature-input: sig1=")
            && lower.contains("\"@authority\"")
            && lower.contains(&format!(
                "keyid=\"{}#federation-fanout-key\"",
                captured.state.service_id().to_ascii_lowercase()
            )),
        "captured request missing RFC 9421 Signature-Input; got: {}",
        captured.captured
    );
    assert!(
        lower.contains("signature: sig1=:"),
        "captured request missing RFC 9421 Signature; got: {}",
        captured.captured
    );
    assert!(
        captured.captured.starts_with("POST /_arkret/peer/events"),
        "request line should target the configured endpoint; got: {}",
        captured.captured
    );
    assert!(
        captured.captured.contains(PAYLOAD_JSON),
        "captured request body should match enqueued payload; got: {}",
        captured.captured
    );
    assert_http_signature_verifies(&captured.captured, &captured.target_uri, &captured.state);

    // Outbox row must be marked delivered with the mock's 2xx status.
    let updated = captured
        .state
        .test_persistence()
        .federation_outbox()
        .get(&captured.row_id)
        .await
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

#[tokio::test]
async fn outbound_signature_rejects_body_digest_tamper() {
    let captured = capture_signed_request().await;
    let mut headers = parse_headers(&captured.captured);
    let original_digest = headers
        .get("content-digest")
        .expect("content-digest header")
        .to_owned();
    let tampered_digest = test_content_digest_header_value(br#"{"resource":"sha256:tampered"}"#);
    assert_ne!(
        original_digest, tampered_digest,
        "body tamper must produce a distinct Content-Digest binding"
    );
    headers.insert("content-digest".to_owned(), tampered_digest);

    let verifying_key = captured.state.notary_signing_key().verifying_key();
    assert!(
        !http_signature_verifies_with_headers(&headers, &captured.target_uri, &verifying_key),
        "changing the body digest after signing must invalidate the RFC 9421 transcript"
    );
}

#[tokio::test]
async fn permanent_4xx_routes_to_dead_letter() {
    let (peer_url, request_rx) =
        spawn_mock_peer_with_status("404 Not Found", br#"{"error":"unknown_peer"}"#);
    let state = soland_test_support::app_state(outbox_test_config());
    let row = enqueue_outbound(
        &state,
        &peer_url,
        PEER_DID,
        FEDERATION_ENDPOINT,
        IDEMPOTENCY_KEY,
        PAYLOAD_JSON,
    )
    .await
    .expect("enqueue must succeed");

    FederationDispatcher::new(state.clone())
        .run_one_pass()
        .await
        .expect("dispatch pass must succeed");
    let _ = request_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("mock peer should have received request");

    let updated = state
        .test_persistence()
        .federation_outbox()
        .get(&row.id)
        .await
        .expect("outbox lookup")
        .expect("row still present");
    assert!(updated.delivered_at.is_some());
    assert_eq!(updated.last_status, Some(404));
    assert_eq!(updated.attempts, 1);

    let dead_letters = state
        .test_persistence()
        .federation_outbox()
        .dead_letters_snapshot()
        .await
        .expect("dead-letter snapshot");
    assert_eq!(dead_letters.len(), 1);
    let dead = &dead_letters[0];
    assert_eq!(dead.outbox_id, row.id);
    assert_eq!(dead.peer_did, PEER_DID);
    assert_eq!(dead.terminal_status, 404);
    assert_eq!(dead.reason, "terminal_http_status");
    assert!(
        dead.response_excerpt
            .as_deref()
            .is_some_and(|body| body.contains("unknown_peer"))
    );
}

#[tokio::test]
async fn outbound_signature_rejects_missing_trust_domain_component() {
    let captured = capture_signed_request().await;
    let mut headers = parse_headers(&captured.captured);
    headers.remove("destination-trust-domain");

    let verifying_key = captured.state.notary_signing_key().verifying_key();
    assert!(
        !http_signature_verifies_with_headers(&headers, &captured.target_uri, &verifying_key),
        "missing destination trust-domain must fail verification"
    );
}

#[tokio::test]
async fn outbound_signature_rejects_trust_domain_mismatch() {
    let captured = capture_signed_request().await;
    let mut headers = parse_headers(&captured.captured);
    headers.insert(
        "destination-trust-domain".to_owned(),
        "ak:trust_domain:evil.example".to_owned(),
    );

    let verifying_key = captured.state.notary_signing_key().verifying_key();
    assert!(
        !http_signature_verifies_with_headers(&headers, &captured.target_uri, &verifying_key),
        "trust-domain mismatch must fail verification"
    );
}

#[tokio::test]
async fn outbound_enqueue_is_idempotent_for_same_peer_and_key() {
    let state = soland_test_support::app_state(outbox_test_config());

    let first = enqueue_outbound(
        &state,
        "http://127.0.0.1:9",
        PEER_DID,
        FEDERATION_ENDPOINT,
        IDEMPOTENCY_KEY,
        PAYLOAD_JSON,
    )
    .await
    .expect("first enqueue");
    let second = enqueue_outbound(
        &state,
        "http://127.0.0.1:9",
        PEER_DID,
        FEDERATION_ENDPOINT,
        IDEMPOTENCY_KEY,
        PAYLOAD_JSON,
    )
    .await
    .expect("second enqueue with same peer/key");

    assert_eq!(
        first.id, second.id,
        "same peer + idempotency key must return the original outbox row"
    );
    let snapshot = state
        .test_persistence()
        .federation_outbox()
        .snapshot_all()
        .await
        .expect("outbox snapshot");
    assert_eq!(
        snapshot.len(),
        1,
        "idempotent replay must not create a duplicate outbox row"
    );
}

#[tokio::test]
async fn outbound_signature_fails_after_service_key_rotation() {
    let captured = capture_signed_request().await;
    let headers = parse_headers(&captured.captured);
    let original_key = captured.state.notary_signing_key().verifying_key();
    assert!(
        http_signature_verifies_with_headers(&headers, &captured.target_uri, &original_key),
        "sanity: original service key should verify the signed request"
    );

    let rotated_key = SigningKey::from_bytes(&[7_u8; 32]).verifying_key();
    assert!(
        !http_signature_verifies_with_headers(&headers, &captured.target_uri, &rotated_key),
        "service-key rotation/revoke must invalidate replay of the old signed request"
    );
}

async fn capture_signed_request() -> CapturedSignedRequestBody {
    let (peer_url, request_rx) = spawn_mock_peer();
    let state = soland_test_support::app_state(outbox_test_config());

    // Enqueue one outbound row through the standard peer-event delivery path.
    // funnels through after computing the deterministic idempotency
    // key.
    let row = enqueue_outbound(
        &state,
        &peer_url,
        PEER_DID,
        FEDERATION_ENDPOINT,
        IDEMPOTENCY_KEY,
        PAYLOAD_JSON,
    )
    .await
    .expect("enqueue must succeed");
    let persistence = state.test_persistence();
    let pending = persistence
        .federation_outbox()
        .get(&row.id)
        .await
        .expect("outbox query")
        .expect("freshly enqueued row remains pending");
    assert!(pending.delivered_at.is_none());

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

    CapturedSignedRequestBody {
        captured,
        target_uri: format!("{peer_url}{FEDERATION_ENDPOINT}"),
        state,
        row_id: row.id,
    }
}

fn assert_http_signature_verifies(captured: &str, target_uri: &str, state: &AppState) {
    let headers = parse_headers(captured);
    let verifying_key = state.notary_signing_key().verifying_key();
    assert!(
        http_signature_verifies_with_headers(&headers, target_uri, &verifying_key),
        "RFC 9421 signature should verify against service key"
    );
}

fn http_signature_verifies_with_headers(
    headers: &BTreeMap<String, String>,
    target_uri: &str,
    verifying_key: &VerifyingKey,
) -> bool {
    let signature_input = headers
        .get("signature-input")
        .and_then(|value| value.strip_prefix("sig1="));
    let Some(signature_params) = signature_input else {
        return false;
    };
    let signature_b64 = headers
        .get("signature")
        .and_then(|value| value.strip_prefix("sig1=:"))
        .and_then(|value| value.strip_suffix(':'));
    let Some(signature_b64) = signature_b64 else {
        return false;
    };
    let Ok(signature_bytes) = STANDARD.decode(signature_b64) else {
        return false;
    };
    let Ok(signature) = Signature::from_slice(&signature_bytes) else {
        return false;
    };

    let (
        Some(content_digest),
        Some(source_service_id),
        Some(destination_service_id),
        Some(source_trust_domain),
        Some(destination_trust_domain),
        Some(request_canonical_digest),
    ) = (
        headers.get("content-digest"),
        headers.get("source-service-id"),
        headers.get("destination-service-id"),
        headers.get("source-trust-domain"),
        headers.get("destination-trust-domain"),
        headers.get("request-canonical-digest"),
    )
    else {
        return false;
    };
    let authority = authority_from_target_uri(target_uri);

    let mut signature_base = format!(
        "\"@method\": POST\n\
         \"@target-uri\": {target_uri}\n\
         \"@authority\": {authority}\n\
         \"content-digest\": {content_digest}\n\
         \"source-service-id\": {source_service_id}\n\
         \"destination-service-id\": {destination_service_id}\n\
         \"source-trust-domain\": {source_trust_domain}\n\
         \"destination-trust-domain\": {destination_trust_domain}\n\
         \"request-canonical-digest\": {request_canonical_digest}",
    );
    if let Some(idempotency_key) = headers.get("idempotency-key") {
        signature_base.push_str(&format!("\n\"idempotency-key\": {idempotency_key}"));
    }
    signature_base.push_str(&format!("\n\"@signature-params\": {signature_params}"));

    verifying_key
        .verify(signature_base.as_bytes(), &signature)
        .is_ok()
}

fn authority_from_target_uri(target_uri: &str) -> String {
    let Ok(url) = reqwest::Url::parse(target_uri) else {
        return String::new();
    };
    let Some(host) = url.host_str() else {
        return String::new();
    };
    url.port()
        .map(|port| format!("{host}:{port}"))
        .unwrap_or_else(|| host.to_owned())
}

fn test_content_digest_header_value(body: &[u8]) -> String {
    let digest = Sha256::digest(body);
    format!("sha-256=:{}:", STANDARD.encode(digest))
}

fn parse_headers(captured: &str) -> BTreeMap<String, String> {
    let mut headers = BTreeMap::new();
    for line in captured.lines().skip(1) {
        if line.trim().is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            headers.insert(name.to_ascii_lowercase(), value.trim().to_owned());
        }
    }
    headers
}
