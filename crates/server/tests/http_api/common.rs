//! Shared helpers, fixtures, and imports for the soland HTTP-API integration test binary.
//!
//! Originally lived inline at the top of the monolithic `http_api` test before the
//! file was split into per-domain submodules. All items are reachable
//! to siblings via `super::common::*` from the `main.rs` integration-test root.

pub(crate) use std::sync::LazyLock;
use std::sync::OnceLock;
pub(crate) use std::sync::atomic::{AtomicU64, Ordering};
pub(crate) use std::time::Duration;

pub(crate) use arkret_identifiers::{Did, DidCoreId, OperationId, RealmId, new_prefixed_uuid7};
pub(crate) use base64::Engine;
pub(crate) use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
pub(crate) use ed25519_dalek::{Signature, Signer, SigningKey, Verifier};
pub(crate) use futures_util::StreamExt;
pub(crate) use salvo::http::StatusCode;
pub(crate) use salvo::test::ResponseExt;
pub(crate) use serde_json::Value;
pub(crate) use sha2::{Digest, Sha256};
pub(crate) use soland_domain::artifacts;
pub(crate) use soland_http::config::{AppConfig, IceServersConfig};
pub(crate) use soland_http::ratelimit::RateLimiterConfig;
pub(crate) use soland_http::state::{AppState, RealmDirectoryEntry};
pub(crate) use soland_http::{
    service, service_with_rate_limiter_config, service_with_request_size_limit,
};
pub(crate) use soland_storage::{RealmInviteRecord, RealmMetaRecord, WebvhDocumentRecord};
pub(crate) use soland_storage_postgres::Db;
pub(crate) use soland_test_support::AppStateTestExt;

/// Protocol-aware test request factory. Production clients choose an exact
/// operation before sending; the integration harness derives that same exact
/// selector from the canonical registry so unrelated handler tests do not
/// duplicate 260 static header literals. Selector-negative tests must use
/// `salvo::test::TestClient` directly.
pub(crate) struct TestClient;

impl TestClient {
    fn select(
        method: salvo::http::Method,
        url: impl AsRef<str>,
        builder: salvo::test::RequestBuilder,
    ) -> salvo::test::RequestBuilder {
        let path = url::Url::parse(url.as_ref())
            .expect("test request URL is absolute")
            .path()
            .to_owned();
        let operation = if matches!(
            method,
            salvo::http::Method::POST
                | salvo::http::Method::PATCH
                | salvo::http::Method::HEAD
                | salvo::http::Method::DELETE
        ) && (path == "/_arkret/self/blob/resumable"
            || path.starts_with("/_arkret/self/blob/resumable/"))
        {
            Some(arkret_wire::ServiceOperationId::SelfBlobUploadCreateV1)
        } else {
            arkret_wire::ServiceOperationId::from_http_request(method.as_str(), &path)
        };
        match operation {
            Some(operation) => builder.add_header("Arkret-Operation", operation.as_str(), true),
            None => builder,
        }
    }

    pub(crate) fn get(url: impl AsRef<str>) -> salvo::test::RequestBuilder {
        Self::select(
            salvo::http::Method::GET,
            url.as_ref(),
            salvo::test::TestClient::get(url.as_ref()),
        )
    }

    pub(crate) fn post(url: impl AsRef<str>) -> salvo::test::RequestBuilder {
        Self::select(
            salvo::http::Method::POST,
            url.as_ref(),
            salvo::test::TestClient::post(url.as_ref()),
        )
    }

    pub(crate) fn put(url: impl AsRef<str>) -> salvo::test::RequestBuilder {
        Self::select(
            salvo::http::Method::PUT,
            url.as_ref(),
            salvo::test::TestClient::put(url.as_ref()),
        )
    }

    pub(crate) fn query(url: impl AsRef<str>) -> salvo::test::RequestBuilder {
        Self::select(
            salvo::http::Method::QUERY,
            url.as_ref(),
            salvo::test::TestClient::query(url.as_ref()),
        )
    }

    pub(crate) fn delete(url: impl AsRef<str>) -> salvo::test::RequestBuilder {
        Self::select(
            salvo::http::Method::DELETE,
            url.as_ref(),
            salvo::test::TestClient::delete(url.as_ref()),
        )
    }

    pub(crate) fn head(url: impl AsRef<str>) -> salvo::test::RequestBuilder {
        Self::select(
            salvo::http::Method::HEAD,
            url.as_ref(),
            salvo::test::TestClient::head(url.as_ref()),
        )
    }

    pub(crate) fn options(url: impl AsRef<str>) -> salvo::test::RequestBuilder {
        salvo::test::TestClient::options(url)
    }

    pub(crate) fn patch(url: impl AsRef<str>) -> salvo::test::RequestBuilder {
        Self::select(
            salvo::http::Method::PATCH,
            url.as_ref(),
            salvo::test::TestClient::patch(url.as_ref()),
        )
    }
}

/// Derived, never copied: the demo Realm id is `retype(genesis.event_id)` and
/// moves with any `arkret-spec` change that touches the genesis payload.
pub(crate) fn demo_realm_id() -> &'static str {
    static ID: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| {
        soland_test_support::app_state(test_config())
            .development_demo_realm_id()
            .to_string()
    });
    &ID
}
/// Fixed REST-style TURN shared secret installed by `test_config()` so the
/// derived TURN credential is deterministic in assertions. Mirrors
/// `SOLAND_TURN_SHARED_SECRET`.
pub(crate) const SOLAND_TEST_TURN_SHARED_SECRET: &str = "soland-test-turn-shared-secret-0123456789";
pub(crate) const ACCOUNT_REGISTER_BEARER: &str = "soland-test-account-register-bearer";
pub(crate) static TEST_EVENT_SEQ: AtomicU64 = AtomicU64::new(10_000);
static DEMO_REALM_ACTOR_FRONTIER_EVENT_ID: OnceLock<String> = OnceLock::new();
static TEST_EVENT_SIGNER_DID: LazyLock<String> = LazyLock::new(|| {
    let key = SigningKey::from_bytes(&[21_u8; 32]);
    format!(
        "did:key:{}",
        arkret_canonical::ed25519_pubkey_to_did_key_multibase(key.verifying_key().as_bytes())
    )
});

pub(crate) fn test_event_signer_did() -> &'static str {
    TEST_EVENT_SIGNER_DID.as_str()
}

/// Project a fixture's DID onto the stable core id that account-data AAD,
/// key derivation and owner projections are bound to.
pub(crate) fn fixture_actor_core_id(actor: &str) -> DidCoreId {
    arkret_wire::project_did_to_core_id(&Did::new(actor.to_owned()).expect("fixture actor DID"))
        .expect("fixture actor DID projects to a core id")
}
/// Render a timestamp exactly as the SDK's canonical wire serializer does
/// (fixed milliseconds, `Z` suffix). The canonical deserializer rejects every
/// other RFC 3339 spelling, so hand-built fixture JSON must use this.
pub(crate) fn canonical_timestamp(at: chrono::DateTime<chrono::Utc>) -> String {
    at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

pub(crate) fn test_config() -> AppConfig {
    AppConfig {
        ice: IceServersConfig {
            // `webrtc-signaling.md` §4.1 — fix the REST-style TURN shared secret
            // so the derived credential is deterministic for assertions.
            turn_shared_secret: Some(SOLAND_TEST_TURN_SHARED_SECRET.to_owned()),
            ..IceServersConfig::default()
        },
        development_mode: true,
        embedded_webvh_registration_bearer: Some(ACCOUNT_REGISTER_BEARER.to_owned()),
        // Tests use fixed-time HLC fixtures; window=0 disables replay-window
        // enforcement so they keep passing.
        jws_replay_window_seconds: 0,
        jws_replay_window_per_family: std::collections::BTreeMap::new(),
        resumable_upload_dir: std::env::temp_dir().join("soland-test-resumable-uploads"),
        seed_demo_data: true,
        ..soland_test_support::app_config()
    }
}

pub(crate) fn test_state_with_service_id(service_id: &str) -> AppState {
    if let Ok(did) = arkret_wire::Did::new(service_id.to_owned()) {
        return soland_test_support::app_state_with_service_did(test_config(), did);
    }
    let state = soland_test_support::app_state(test_config());
    assert_eq!(
        state.service_id(),
        service_id,
        "a core-only test service id must match the fixture identity"
    );
    state
}

pub(crate) fn app() -> salvo::Service {
    service(soland_test_support::app_state(test_config()))
}

pub(crate) fn app_from_state(state: AppState) -> salvo::Service {
    service(state)
}

pub(crate) fn advertises_operation(describe: &Value, operation_id: &str) -> bool {
    describe["supported_operation_bundles"]
        .as_array()
        .is_some_and(|bundles| {
            bundles
                .iter()
                .filter_map(Value::as_str)
                .filter_map(arkret_wire::operation_bundle_descriptor)
                .flat_map(|bundle| bundle.members)
                .any(|binding| binding.operation_id.as_str() == operation_id)
        })
}

/// Return the canonical RFC 9457 Arkret problem code encoded by the problem
/// type URI. Error responses are closed problem-detail objects; tests must not
/// depend on the removed legacy `{ "error": { ... } }` envelope.
pub(crate) fn problem_code(body: &Value) -> &str {
    body["type"]
        .as_str()
        .and_then(|problem_type| problem_type.rsplit('/').next())
        .filter(|code| !code.is_empty())
        .expect("response must contain a canonical Arkret problem type URI")
}

/// Prepare the closed authority-authored self-principal PCR submission path.
///
/// These Control Moves still carry the HTTP-issued authorization lease, but
/// the PCR authority is already the actor's live authority. Attaching a second
/// Control Proposal Ack would create an invalid circular approval surface.
pub(crate) async fn prepare_self_principal_pcr_initial_submissions(
    state: &AppState,
    token: &str,
    events: Vec<arkret_wire::Event>,
) -> Vec<arkret_wire::EventInitialSubmission> {
    let authorization_leases = issue_authorization_leases(state, token, &events).await;
    events
        .into_iter()
        .zip(authorization_leases)
        .map(|(event, authorization_lease)| {
            let submission = arkret_wire::EventInitialSubmission {
                event,
                authorization_lease: Some(authorization_lease),
                cba_proof_bundles: Vec::new(),
                control_proposal_ack: None,
                membership_compensation_evidence: None,
            };
            submission
                .validate_structural_in_context(
                    arkret_wire::EventSubmitContext::Standard,
                    arkret_canonical::DigestSuite::Sha256,
                )
                .expect("authority-authored self-principal PCR initial submission");
            submission
        })
        .collect()
}

async fn issue_authorization_leases(
    state: &AppState,
    token: &str,
    events: &[arkret_wire::Event],
) -> Vec<arkret_wire::AuthorizationLease> {
    assert!(
        !events.is_empty() && events.iter().all(|event| event.seal_basis.is_some()),
        "standard initial submissions require non-empty sealed Events"
    );
    let lease_request = arkret_wire::AuthorizationLeaseIssueRequestBody {
        events: events.to_vec(),
        intents: Vec::new(),
    };
    let lease_request_body = arkret_canonical::canonical_json_bytes(&lease_request)
        .expect("canonical authorization lease request");
    let request_key = new_prefixed_uuid7("lease-");
    let mut lease_response = TestClient::post("http://server/_arkret/self/authorization-leases")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("Idempotency-Key", request_key, true)
        .add_header("content-type", "application/json", true)
        .body(lease_request_body)
        .send(&app_from_state(state.clone()))
        .await;
    let lease_status = lease_response.status_code;
    let lease_body: Value = lease_response
        .take_json()
        .await
        .expect("authorization lease response body");
    assert_eq!(
        lease_status,
        Some(StatusCode::OK),
        "authorization lease failed: {lease_body}"
    );
    let lease_outcome: arkret_wire::AuthorizationLeaseIssueOutcome =
        serde_json::from_value(lease_body).expect("authorization lease outcome");
    assert_eq!(
        lease_outcome.authorization_leases.len(),
        events.len(),
        "authorization lease cardinality"
    );

    lease_outcome.authorization_leases
}

/// Persist one accepted bootstrap Seal together with the exact direct cell
/// effects committed by its closed Event unit.
pub(crate) fn seed_seal_with_direct_event_effects(
    state: &AppState,
    seal: &arkret_wire::Seal,
    events: &[&arkret_wire::Event],
    projector: &impl Fn(
        &arkret_wire::Event,
    ) -> Result<Vec<arkret_wire::cba::ProjectedCellWrite>, String>,
) {
    let mut event_digests = events
        .iter()
        .map(|event| {
            arkret_wire::Hash::new(
                event
                    .event_digest_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
                    .expect("bootstrap Event digest"),
            )
            .unwrap()
        })
        .collect::<Vec<_>>();
    event_digests.sort_by(|left, right| left.as_str().cmp(right.as_str()));
    assert_eq!(
        event_digests, seal.delta,
        "bootstrap Event unit must exactly match Seal delta"
    );

    let mut ops = Vec::new();
    for event in events {
        let digest = arkret_wire::Hash::new(
            event
                .event_digest_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
                .expect("bootstrap Event digest"),
        )
        .unwrap();
        for write in projector(event).expect("bootstrap Event projection") {
            let effect = write
                .as_direct()
                .expect("bootstrap Event projection must not depend on pre-state");
            ops.push((
                effect.cell_id,
                arkret_state::lattice::ordered_log::IssuedOp {
                    issuer_id: event.actor_id.clone(),
                    op: arkret_state::lattice::SealedOp::new(digest.clone(), effect.op),
                },
            ));
        }
    }
    assert_eq!(
        fixture_sealed_state_root(&seal.realm_id, &ops),
        seal.state_root,
        "bootstrap sealed effects must match Seal state_root"
    );
    state
        .test_put_seal(seal, arkret_canonical::DigestSuite::Sha256)
        .expect("bootstrap Seal");
    state
        .test_append_sealed_effects(&seal.realm_id, &seal.id, &ops)
        .expect("bootstrap sealed effects");
}

fn fixture_sealed_state_root(
    realm: &RealmId,
    ops: &[(
        arkret_identifiers::CellRef,
        arkret_state::lattice::ordered_log::IssuedOp,
    )],
) -> arkret_identifiers::Hash {
    let registry = soland_services::projection::ProjectionService::sdk_cell_registry();
    let mut grouped: std::collections::BTreeMap<
        arkret_identifiers::CellRef,
        Vec<arkret_state::lattice::ordered_log::IssuedOp>,
    > = std::collections::BTreeMap::new();
    for (cell, op) in ops {
        grouped.entry(cell.clone()).or_default().push(op.clone());
    }
    let mut post_state = std::collections::BTreeMap::new();
    for (cell, cell_ops) in grouped {
        let binding = registry
            .resolve(realm, &cell)
            .expect("fixture cell family is registered");
        post_state.insert(
            cell.clone(),
            arkret_state::join_cell(binding.lattice.as_ref(), &cell, &cell_ops),
        );
    }
    arkret_state::compute_state_root(&post_state, arkret_canonical::DigestSuite::Sha256)
        .expect("fixture state_root")
}

pub(crate) fn app_state_for_postgres(config: AppConfig, db: Db) -> AppState {
    let pool = db.pool.clone().expect("postgres test requires a pool");
    let persistence_store: std::sync::Arc<dyn soland_storage::PersistenceStore> =
        std::sync::Arc::new(soland_storage_postgres::PgPersistenceStore::new(pool));
    let persistence =
        soland_services::persistence::PersistenceHandle::from_shared(persistence_store.clone());
    let identity = soland_test_support::fixture_service_identity(&config);
    let signing_seed = soland_test_support::fixture_signing_seed(&config, &identity);
    let resolution_commitment = arkret_models_identity::ResolutionCommitment {
        did: arkret_wire::Did::new(
            identity
                .identity()
                .expect("fixture serving identity")
                .service_id
                .to_string(),
        )
        .expect("fixture service DID"),
        method_history_head: format!("sha256:{}", "0".repeat(64)),
        version_id: "fixture-v1".to_owned(),
    };
    let state = soland::runtime::build_app_state(
        config,
        db,
        persistence,
        identity,
        resolution_commitment,
        signing_seed,
    )
    .expect("postgres test AppState");
    soland_test_support::register_persistence(&state, persistence_store);
    state
}

pub(crate) async fn account_subscribe_frame(
    state: AppState,
    token: Option<&str>,
    query: &str,
) -> serde_json::Value {
    let url = if query.is_empty() {
        "http://server/_arkret/self/account/subscribe".to_owned()
    } else {
        format!("http://server/_arkret/self/account/subscribe?{query}")
    };
    let mut request = TestClient::get(url);
    if let Some(token) = token {
        request = request.add_header("authorization", format!("Bearer {token}"), true);
    }
    let mut response = request.send(&app_from_state(state)).await;
    let body = take_first_response_chunk(&mut response).await;
    serde_json::from_str(body.lines().next().unwrap()).unwrap()
}

pub(crate) async fn take_first_response_chunk(response: &mut salvo::Response) -> String {
    let frame = response
        .body
        .next()
        .await
        .expect("response body must contain a frame")
        .expect("response body frame must be readable");
    let bytes = frame
        .into_data()
        .expect("first response frame must be data");
    String::from_utf8(bytes.to_vec()).expect("response body must be utf-8")
}

pub(crate) fn decode_cursor(token: &str) -> Value {
    let encoded = token
        .strip_prefix("ak:cursor:")
        .expect("structured cursor prefix");
    let bytes = URL_SAFE_NO_PAD.decode(encoded).expect("base64url cursor");
    serde_json::from_slice(&bytes).expect("cursor json")
}

pub(crate) fn encode_cursor(cursor: &Value) -> String {
    format!("ak:cursor:{}", URL_SAFE_NO_PAD.encode(cursor.to_string()))
}

pub(crate) fn signed_federation_push_headers(
    origin: &str,
    destination: &str,
    destination_trust_domain: &str,
    target_uri: &str,
    body: &Value,
) -> Vec<(&'static str, String)> {
    signed_federation_request_headers(SignedFederationRequest {
        method: "POST",
        origin,
        destination,
        destination_trust_domain,
        target_uri,
        body,
        source_trust_domain_override: None,
        idempotency_key: None,
    })
}

pub(crate) fn signed_federation_query_headers(
    origin: &str,
    destination: &str,
    destination_trust_domain: &str,
    target_uri: &str,
    body: &Value,
) -> Vec<(&'static str, String)> {
    signed_federation_request_headers(SignedFederationRequest {
        method: "QUERY",
        origin,
        destination,
        destination_trust_domain,
        target_uri,
        body,
        source_trust_domain_override: None,
        idempotency_key: None,
    })
}

pub(crate) fn signed_federation_push_headers_with_idempotency(
    origin: &str,
    destination: &str,
    destination_trust_domain: &str,
    target_uri: &str,
    body: &Value,
    idempotency_key: &str,
) -> Vec<(&'static str, String)> {
    signed_federation_request_headers(SignedFederationRequest {
        method: "POST",
        origin,
        destination,
        destination_trust_domain,
        target_uri,
        body,
        source_trust_domain_override: Some(destination_trust_domain),
        idempotency_key: Some(idempotency_key),
    })
}

pub(crate) fn signed_federation_push_headers_same_trust(
    origin: &str,
    destination: &str,
    trust_domain: &str,
    target_uri: &str,
    body: &Value,
) -> Vec<(&'static str, String)> {
    signed_federation_request_headers(SignedFederationRequest {
        method: "POST",
        origin,
        destination,
        destination_trust_domain: trust_domain,
        target_uri,
        body,
        source_trust_domain_override: Some(trust_domain),
        idempotency_key: None,
    })
}

struct SignedFederationRequest<'a> {
    method: &'a str,
    origin: &'a str,
    destination: &'a str,
    destination_trust_domain: &'a str,
    target_uri: &'a str,
    body: &'a Value,
    source_trust_domain_override: Option<&'a str>,
    idempotency_key: Option<&'a str>,
}

fn signed_federation_request_headers(
    request: SignedFederationRequest<'_>,
) -> Vec<(&'static str, String)> {
    let SignedFederationRequest {
        method,
        origin,
        destination,
        destination_trust_domain,
        target_uri,
        body,
        source_trust_domain_override,
        idempotency_key,
    } = request;
    let origin_did =
        arkret_wire::Did::new(origin.to_owned()).expect("federation test origin must be a DID");
    let origin_id = arkret_wire::project_did_to_core_id(&origin_did)
        .expect("federation test origin must project to a service core ID");
    let body_bytes = arkret_canonical::canonical_json_bytes(body).unwrap();
    let content_digest = format!("sha-256=:{}:", STANDARD.encode(Sha256::digest(&body_bytes)));
    let source_trust_domain = source_trust_domain_override
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| trust_domain_from_service_id(origin_did.as_str()));
    let created = chrono::Utc::now().timestamp();
    let expires = created + 300;
    let keyid = format!("{origin_did}#federation-fanout-key");
    let operation = reqwest::Url::parse(target_uri)
        .ok()
        .and_then(|url| arkret_wire::ServiceOperationId::from_http_request(method, url.path()));
    let mut covered_components = vec![
        "\"@method\"",
        "\"@target-uri\"",
        "\"@authority\"",
        "\"content-digest\"",
        "\"source-service-id\"",
        "\"destination-service-id\"",
        "\"source-trust-domain\"",
        "\"destination-trust-domain\"",
    ];
    if operation.is_some() {
        covered_components.push("\"arkret-operation\"");
    }
    if idempotency_key.is_some() {
        covered_components.push("\"idempotency-key\"");
    }
    let covered_components = covered_components.join(" ");
    let signature_params = format!(
        "({covered_components});created={created};expires={expires};keyid=\"{keyid}\";alg=\"ed25519\"",
    );
    let authority = authority_from_target_uri(target_uri);
    let mut signature_base = format!(
        "\"@method\": {method}\n\
         \"@target-uri\": {target_uri}\n\
         \"@authority\": {authority}\n\
         \"content-digest\": {content_digest}\n\
         \"source-service-id\": {origin_id}\n\
         \"destination-service-id\": {destination}\n\
         \"source-trust-domain\": {source_trust_domain}\n\
         \"destination-trust-domain\": {destination_trust_domain}",
    );
    if let Some(operation) = operation {
        signature_base.push_str(&format!("\n\"arkret-operation\": {}", operation.as_str()));
    }
    if let Some(idempotency_key) = idempotency_key {
        signature_base.push_str(&format!("\n\"idempotency-key\": {idempotency_key}"));
    }
    signature_base.push_str(&format!("\n\"@signature-params\": {signature_params}"));
    let signature =
        development_service_signing_key(origin_id.as_str()).sign(signature_base.as_bytes());
    let mut headers = vec![
        ("content-digest", content_digest),
        ("source-service-id", origin_id.to_string()),
        ("destination-service-id", destination.to_owned()),
        ("source-trust-domain", source_trust_domain),
        (
            "destination-trust-domain",
            destination_trust_domain.to_owned(),
        ),
        ("signature-input", format!("sig1={signature_params}")),
        (
            "signature",
            format!("sig1=:{}:", STANDARD.encode(signature.to_bytes())),
        ),
    ];
    if let Some(idempotency_key) = idempotency_key {
        headers.push(("idempotency-key", idempotency_key.to_owned()));
    }
    if let Some(operation) = operation {
        headers.push(("arkret-operation", operation.as_str().to_owned()));
    }
    headers
}

pub(crate) fn authority_from_target_uri(target_uri: &str) -> String {
    let Ok(url) = reqwest::Url::parse(target_uri) else {
        return "server".to_owned();
    };
    let Some(host) = url.host_str() else {
        return "server".to_owned();
    };
    url.port()
        .map(|port| format!("{host}:{port}"))
        .unwrap_or_else(|| host.to_owned())
}

pub(crate) fn development_service_signing_key(service_id: &str) -> SigningKey {
    let mut hasher = Sha256::new();
    hasher.update(b"soland:notary-ephemeral:");
    hasher.update(service_id.as_bytes());
    let seed: [u8; 32] = hasher.finalize().into();
    SigningKey::from_bytes(&seed)
}

pub(crate) fn trust_domain_from_service_id(service_id: &str) -> String {
    let scope = service_id
        .strip_prefix("did:web:")
        .or_else(|| service_id.strip_prefix("did:key:"))
        .or_else(|| service_id.strip_prefix("did:webvh:"))
        .unwrap_or(service_id)
        .to_ascii_lowercase()
        .replace(':', ".");
    format!("ak:trust_domain:{scope}")
}

pub(crate) async fn dev_token(state: AppState) -> String {
    let actor = "did:web:alice.example";
    let device_id = "ak:device:01904100-0000-7000-8000-a11ce0000001";
    let token = dev_token_for_device(state.clone(), actor, device_id, "Alice Desktop").await;
    project_test_authorized_device(
        &state,
        actor,
        device_id,
        &SigningKey::from_bytes(&[21_u8; 32]),
    )
    .await;
    token
}

pub(crate) async fn dev_token_for_device(
    state: AppState,
    actor: &str,
    device_id: &str,
    display_name: &str,
) -> String {
    let actor_core = arkret_wire::project_did_to_core_id(
        &Did::new(actor.to_owned()).expect("fixture actor DID"),
    )
    .expect("fixture actor core id");
    let login: Value = TestClient::post("http://server/_soland/gate/auth/dev-login")
        .json(&serde_json::json!({
            "actor": actor_core,
            "device_id": device_id,
            "display_name": display_name
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    login["session_credential"].as_str().unwrap().to_owned()
}

pub(crate) async fn verified_dev_token_for_device(
    state: AppState,
    actor: &str,
    device_id: &str,
    display_name: &str,
) -> String {
    let token = dev_token_for_device(state.clone(), actor, device_id, display_name).await;
    project_test_authorized_device(
        &state,
        actor,
        device_id,
        &SigningKey::from_bytes(&[21_u8; 32]),
    )
    .await;
    token
}

pub(crate) async fn seed_did_document_also_known_as(state: &AppState, did: &str, aliases: &[&str]) {
    let now = chrono::DateTime::<chrono::Utc>::from_timestamp_millis(
        chrono::Utc::now().timestamp_millis(),
    )
    .unwrap();
    let aliases = aliases
        .iter()
        .map(|alias| Value::String((*alias).to_owned()))
        .collect::<Vec<_>>();
    state
        .test_persistence()
        .webvh()
        .put_document(WebvhDocumentRecord {
            did: did.to_owned(),
            did_document: serde_json::json!({
                "id": did,
                "alsoKnownAs": aliases,
                "verificationMethod": [],
                "authentication": [],
                "assertionMethod": [],
                "service": [{
                    "id": format!("{did}#soland"),
                    "type": "ArkretPrincipalServer",
                    "serviceEndpoint": "/_arkret"
                }]
            }),
            key_log_head: None,
            seq: 0,
            method_evidence: serde_json::json!({"mode": "test_fixture"}),
            fetched_at: now,
            expires_at: now + chrono::Duration::minutes(15),
            updated_at: now,
        })
        .await
        .unwrap();
}

pub(crate) async fn seed_test_realm(
    state: &AppState,
    owner: &str,
    title: &str,
    summary: Option<&str>,
    discoverability: &str,
    plaintext_visible_services: &[&str],
    invitees: &[&str],
) -> Value {
    let realm_id =
        soland_test_support::cba_basis::seed_event_derived_realm_genesis_event(state, owner, title)
            .await;
    let typed_realm_id = RealmId::new(realm_id.clone()).unwrap();
    let owner_did =
        arkret_wire::project_did_to_core_id(&Did::new(owner.to_owned()).unwrap()).unwrap();
    let now = chrono::DateTime::<chrono::Utc>::from_timestamp_millis(
        chrono::Utc::now().timestamp_millis(),
    )
    .unwrap();

    let mut entry = RealmDirectoryEntry::new(
        typed_realm_id,
        title,
        soland_services::events::DirectoryProvenance::LocalOnly,
    );
    entry.description = summary.map(ToOwned::to_owned);
    entry.public = discoverability == "public";
    entry.members.insert(owner_did);
    state.test_realms().lock().upsert(entry);

    let plaintext_visible_services: std::collections::BTreeSet<String> = plaintext_visible_services
        .iter()
        .map(|value| (*value).to_owned())
        .collect();
    let plaintext_visible_service_classes = plaintext_visible_services
        .iter()
        .map(|service| {
            (
                service.clone(),
                std::collections::BTreeSet::from([
                    arkret_wire::PlaintextDataClassKind::MessageContent,
                    arkret_wire::PlaintextDataClassKind::AttachmentPlaintext,
                    arkret_wire::PlaintextDataClassKind::AttachmentPreview,
                    arkret_wire::PlaintextDataClassKind::Thumbnail,
                    arkret_wire::PlaintextDataClassKind::FullTextIndex,
                    arkret_wire::PlaintextDataClassKind::NotificationSummary,
                    arkret_wire::PlaintextDataClassKind::MediaPlaintext,
                ]),
            )
        })
        .collect();
    state
        .test_persistence()
        .realm_meta()
        .put(
            &realm_id,
            &RealmMetaRecord {
                owner: fixture_actor_core_id(owner).to_string(),
                deleted: false,
                discoverability: discoverability.to_owned(),
                history_access: "since_join".to_owned(),
                preview_policy: None,
                preview_policy_digest: None,
                asset_privacy_policy: None,
                asset_privacy_policy_digest: None,
                encryption_profile: None,
                plaintext_visible_services,
                plaintext_visible_service_classes,
                minimal_metadata_realm: false,
                created_at: now,
                updated_at: now,
            },
        )
        .await
        .unwrap();
    let seal_signer = soland_services::identity::FrozenEd25519NotarySigner::from_seed(
        state.notary_signing_key().to_bytes(),
        state.service_did(),
        state.service_verification_method("notary-key").unwrap(),
    );
    let bootstrap_seal = arkret_wire::Seal::sign_single(
        RealmId::new(realm_id.clone()).unwrap(),
        Vec::new(),
        Vec::new(),
        arkret_identifiers::Hash::new(format!("sha256:{}", "0".repeat(64))).unwrap(),
        arkret_identifiers::Hlc::new(format!(
            "{:012x}-0000-aabbccdd",
            now.timestamp_millis().max(0) as u64
        ))
        .unwrap(),
        arkret_canonical::DigestSuite::Sha256,
        &seal_signer,
    )
    .unwrap();
    state
        .test_put_seal(&bootstrap_seal, arkret_canonical::DigestSuite::Sha256)
        .unwrap();
    let seal_basis = bootstrap_seal.seal_basis();
    let owner_core = arkret_wire::project_did_to_core_id(
        &Did::new(owner.to_owned()).expect("fixture realm owner DID"),
    )
    .expect("fixture realm owner core DID");
    let recipient_id =
        DidCoreId::new(state.service_id().clone()).expect("fixture recipient service core DID");
    let current_record_url = format!(
        "https://soland.local{}",
        arkret_models_identity::canonical_service_current_record_path(&recipient_id)
    );

    // The private invite delivery token is transport material, not part of the
    // Invite object (`governance-objects.md` §5.3), so it is returned to the
    // caller here instead of being read back out of an invite read model.
    let mut seeded_invite_tokens: Vec<String> = Vec::new();
    for invitee_id in invitees {
        let invitee_core = arkret_wire::project_did_to_core_id(
            &Did::new((*invitee_id).to_owned()).expect("fixture invitee_id DID"),
        )
        .expect("fixture invitee_id core DID");
        let invite_event_id = arkret_identifiers::EventId::new(
            signed_canonical_event(
                "seed-test-realm-invite",
                arkret_wire::EventKind::InviteCreate.as_str(),
                owner,
                "ak:device:01904100-0000-7000-8000-a11ce0000001",
                &realm_id,
                TEST_EVENT_SEQ.fetch_add(1, Ordering::Relaxed),
                Vec::new(),
                serde_json::json!({}),
            )["event_id"]
                .as_str()
                .expect("fixture invite Event id")
                .to_owned(),
        )
        .expect("fixture invite EventId");
        let invite_id = arkret_identifiers::InviteId::from_event_id(&invite_event_id).to_string();
        let invite_token = new_prefixed_uuid7("ak:invite-token:");
        state
            .test_persistence()
            .realm_invites()
            .put(RealmInviteRecord {
                invite_id,
                realm_id: realm_id.clone(),
                inviter_id: owner_core.to_string(),
                invitee_id: Some(invitee_core.to_string()),
                invite_delivery_target: Some(serde_json::json!({
                    "recipient_id": recipient_id,
                    "service_resolution": {
                        "current_record_url": current_record_url
                    },
                    "recipient_kind": "principal_server"
                })),
                introduction_evidence_digest: Some(format!("sha256:{}", "1".repeat(64))),
                third_party_invite: None,
                invite_token: invite_token.clone(),
                status: "pending".to_owned(),
                claim_nonces: std::collections::BTreeMap::new(),
                expires_at: None,
                created_at: now,
                updated_at: None,
            })
            .await
            .unwrap();
        seeded_invite_tokens.push(invite_token);
    }

    serde_json::json!({
        "ok": true,
        "realm_id": realm_id,
        "owner_id": owner,
        "members": [{"did": owner}],
        "seal_basis": seal_basis,
        "deleted": false,
        "seeded_invite_tokens": seeded_invite_tokens
    })
}

pub(crate) fn add_test_realm_member(state: &AppState, realm_id: &str, member: &str) -> Value {
    let typed_realm_id = RealmId::new(realm_id.to_owned()).unwrap();
    let member_did = Did::new(member.to_owned()).unwrap();
    let member_core = arkret_wire::project_did_to_core_id(&member_did).unwrap();
    let member_core_string = member_core.to_string();
    let now = chrono::DateTime::<chrono::Utc>::from_timestamp_millis(
        chrono::Utc::now().timestamp_millis(),
    )
    .unwrap();
    let mut realms = state.test_realms().lock();
    if let Some(mut entry) = realms.get(&typed_realm_id).cloned() {
        entry.members.insert(member_core);
        let members = realm_member_roster(&entry);
        realms.upsert(entry);
        drop(realms);
        state.test_projection().lock().members.insert(
            (realm_id.to_owned(), member_core_string.clone()),
            soland_domain::reducer::SolandMembershipState {
                member: member_core_string,
                realm_id: realm_id.to_owned(),
                state: "join".to_owned(),
                role: "member".to_owned(),
                delivery_status: None,
                recipient_id: None,
                recipient_service_resolution: None,
                membership_event_ref: None,
                delivery_binding_frontier: None,
                delivery_binding_expires_at: None,
                invited_at: None,
                joined_at: now,
                updated_at: now,
                reason: None,
            },
        );
        serde_json::json!({
            "ok": true,
            "realm_id": realm_id,
            "members": members,
            "deleted": false
        })
    } else {
        serde_json::json!({"ok": false, "error": "realm_not_found"})
    }
}

pub(crate) fn remove_test_realm_member(state: &AppState, realm_id: &str, member: &str) -> Value {
    let typed_realm_id = RealmId::new(realm_id.to_owned()).unwrap();
    let member_did = Did::new(member.to_owned()).unwrap();
    let member_core = arkret_wire::project_did_to_core_id(&member_did).unwrap();
    let member_core_string = member_core.to_string();
    let mut realms = state.test_realms().lock();
    if let Some(mut entry) = realms.get(&typed_realm_id).cloned() {
        entry.members.remove(&member_core);
        let members = realm_member_roster(&entry);
        realms.upsert(entry);
        drop(realms);
        state
            .test_projection()
            .lock()
            .members
            .remove(&(realm_id.to_owned(), member_core_string));
        serde_json::json!({
            "ok": true,
            "realm_id": realm_id,
            "members": members,
            "deleted": false
        })
    } else {
        serde_json::json!({"ok": false, "error": "realm_not_found"})
    }
}

fn realm_member_roster(entry: &RealmDirectoryEntry) -> Vec<Value> {
    // HDLREN-4/5 (arkret-spec @ 7157ee8) — roster rows MUST NOT carry
    // `handle` / `handle_uri` directly; identity is resolved through the
    // `ak.member.identity.update` events surfaced via
    // `MemberRosterEntry.identity_event_ids[]`. The test helper now only
    // emits `{did}` to match the spec wire shape.
    entry
        .members
        .iter()
        .map(|did| {
            let did_str = did.as_str();
            let mut row = serde_json::Map::new();
            row.insert("did".to_owned(), serde_json::json!(did_str));
            Value::Object(row)
        })
        .collect()
}

pub(crate) async fn delete_test_realm(state: &AppState, realm_id: &str) -> Value {
    let persistence = state.test_persistence();
    let store = persistence.realm_meta();
    if let Some(mut meta) = store.get(realm_id).await.unwrap() {
        meta.deleted = true;
        meta.updated_at = chrono::Utc::now();
        store.put(realm_id, &meta).await.unwrap();
    }
    serde_json::json!({
        "ok": true,
        "realm_id": realm_id,
        "deleted": true
    })
}

/// The MLS group every E2EE fixture ciphertext in this test suite names.
pub(crate) const FIXTURE_MLS_GROUP_ID: &str = "httpApiFixtureMlsGroup01";

pub(crate) fn encrypted_envelope(content_type: &str, ciphertext: &str) -> Value {
    serde_json::json!({
        "scheme": "mls_rfc9420",
        "version": 1,
        "group_id": FIXTURE_MLS_GROUP_ID,
        "epoch": 1,
        "content_type": content_type,
        "ciphertext": ciphertext,
        "authentication_tag": "opaque-tag",
        "aad": {"suite": "test"},
        "key_ref": {"kid": "did:web:alice.example#device"},
        "digests": {
            "ciphertext": "sha256:0000000000000000000000000000000000000000000000000000000000000000"
        }
    })
}

pub(crate) fn sha256_json(value: &Value) -> String {
    let bytes = arkret_canonical::canonical_json_bytes(value)
        .unwrap_or_else(|_| serde_json::to_vec(value).unwrap());
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

pub(crate) fn multipart_blob_upload_body(
    content: impl AsRef<[u8]>,
    media_type: &str,
) -> (String, Vec<u8>) {
    let content = content.as_ref();
    let boundary = format!(
        "arkret-test-{}",
        hex::encode(Sha256::digest(content))
            .chars()
            .take(16)
            .collect::<String>()
    );
    let mut body = Vec::new();
    body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
    body.extend_from_slice(b"Content-Disposition: form-data; name=\"size_bytes\"\r\n\r\n");
    body.extend_from_slice(content.len().to_string().as_bytes());
    body.extend_from_slice(format!("\r\n--{boundary}\r\n").as_bytes());
    body.extend_from_slice(
        b"Content-Disposition: form-data; name=\"content\"; filename=\"blob\"\r\n",
    );
    body.extend_from_slice(format!("Content-Type: {media_type}\r\n\r\n").as_bytes());
    body.extend_from_slice(content);
    body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    (format!("multipart/form-data; boundary={boundary}"), body)
}

pub(crate) fn expected_strand_id_for_scope(scope_id: &str) -> String {
    arkret_identifiers::RealmId::new(scope_id.to_owned())
        .map(|realm_id| {
            arkret_identifiers::StrandId::from_event_id(&realm_id.event_id()).to_string()
        })
        .unwrap_or_else(|_| {
            let event_id = arkret_identifiers::EventId::from_digest(
                arkret_canonical::DigestSuite::Sha256,
                arkret_canonical::sha256_bytes(scope_id.as_bytes()),
            );
            arkret_identifiers::StrandId::from_event_id(&event_id).to_string()
        })
}

pub(crate) fn event_canonical_digest(event: &Value) -> String {
    // The digest the server computes is sha256 over the SDK Event digest
    // preimage (`event_canonical_bytes` -> `Event::digest_payload`), so this
    // helper calls the same SDK function rather than restating the exclusion
    // rule. Its previous hand-rolled copy kept `event_id` and `actor_kind` in
    // the preimage and stripped two slots (`canonical_digest`,
    // `canonical_hash`) that no longer exist on the envelope, which made every
    // digest it produced unreachable for the server.
    sha256_json(&arkret_wire::event_digest_preimage(event).expect("event envelope is an object"))
}

pub(crate) fn authored_space_id(event: &Value) -> arkret_identifiers::SpaceId {
    let event_id = arkret_identifiers::EventId::new(authored_event_id(event).to_owned())
        .expect("authored fixture Event has canonical event_id");
    arkret_identifiers::SpaceId::from_event_id(&event_id)
}

pub(crate) fn authored_strand_id(event: &Value) -> arkret_identifiers::StrandId {
    let event_id = arkret_identifiers::EventId::new(authored_event_id(event).to_owned())
        .expect("authored fixture Event has canonical event_id");
    arkret_identifiers::StrandId::from_event_id(&event_id)
}

pub(crate) fn authored_morph_id(event: &Value) -> arkret_identifiers::MorphId {
    let event_id = arkret_identifiers::EventId::new(authored_event_id(event).to_owned())
        .expect("authored fixture Event has canonical event_id");
    arkret_identifiers::MorphId::from_event_id(&event_id)
}

pub(crate) fn authored_relation_id(event: &Value) -> arkret_identifiers::RelationId {
    let event_id = arkret_identifiers::EventId::new(authored_event_id(event).to_owned())
        .expect("authored fixture Event has canonical event_id");
    arkret_identifiers::RelationId::from_event_id(&event_id)
}

#[expect(
    clippy::too_many_arguments,
    reason = "the fixture mirrors the complete canonical event envelope"
)]
pub(crate) fn signed_canonical_event(
    event_id: &str,
    kind: &str,
    actor_id: &str,
    device_id: &str,
    realm_id: &str,
    actor_seq: u64,
    prev_refs: Vec<&str>,
    payload: Value,
) -> Value {
    caller_signed_event(
        event_id, kind, actor_id, device_id, realm_id, actor_seq, prev_refs, payload,
    )
    .build_value()
}

/// The shared caller-signed envelope builder, bound to this binary's fixture
/// basis family.
///
/// `soland_test_support::signed_event` owns the envelope: the CBA plane switch,
/// the device signature and the optional `head_eq` guard are the same everywhere
/// and used to be restated per test binary. What stays here is only which
/// fixture basis these HTTP fixtures seal — a different id domain than the one
/// the standalone integration binaries use, so the two families do not
/// renumber each other's Seals.
#[expect(
    clippy::too_many_arguments,
    reason = "the fixture mirrors the complete canonical event envelope"
)]
pub(crate) fn caller_signed_event<'a>(
    _event_id: &'a str,
    kind: &'a str,
    actor_id: &'a str,
    device_id: &'a str,
    realm_id: &'a str,
    actor_seq: u64,
    prev_refs: Vec<&'a str>,
    payload: Value,
) -> soland_test_support::signed_event::CallerSignedEvent<'a> {
    soland_test_support::signed_event::CallerSignedEvent::new(
        kind, actor_id, device_id, realm_id, payload,
    )
    .with_actor_seq(actor_seq)
    .with_prev_refs(prev_refs)
    .with_fixture_basis(HTTP_API_FIXTURE_BASIS)
}

pub(crate) fn resign_canonical_event(event: &mut Value) {
    let verification_method = arkret_wire::DidUrl::new(
        event["proofs"][0]["verification_method"]
            .as_str()
            .expect("fixture verification method")
            .to_owned(),
    )
    .expect("fixture verification method is a DID URL");
    let mut typed: arkret_wire::Event =
        serde_json::from_value(event.clone()).expect("fixture Event roundtrip");
    typed.proofs.clear();
    let signer = arkret_signatures::Ed25519PayloadSigner::from_did_key_seed(
        [21_u8; 32],
        arkret_identity::verification_method_did(verification_method.as_str()).unwrap(),
        verification_method.clone(),
    );
    let created_at = typed.created_at;
    let mut typed = arkret_wire::AuthoredEvent::finalize_with_digest_suite(
        typed,
        arkret_canonical::DigestSuite::Sha256,
    )
    .expect("fixture envelope finalizes");
    arkret_signatures::sign_event(
        &mut typed,
        &signer,
        &verification_method,
        arkret_signatures::SignEventOptions::new().with_created_at(created_at),
    )
    .expect("SDK Event signer re-signs mutated HTTP fixture");
    let typed = typed.into_event();
    *event = serde_json::to_value(typed).expect("re-signed fixture serializes");
}

// `attach_invite_create_effects` is gone with the producer `effects[]` array:
// the v1 `Event` envelope has no such member (it is `deny_unknown_fields`), and
// the `ak.invite.create` writes are receiver-projected from the registered
// contract. The invite fixtures now carry only the Control Move `seal_basis`.

pub(crate) fn signed_event_envelope(event_id: &str, actor_seq: u64, prev_refs: Vec<&str>) -> Value {
    let payload = serde_json::json!({
        "strand_id": "ak:strand:AR3ud0srmtpodQ47XfsVC4uD75mQDAGaKLEww6VGMZZC",
        "track_name": "discussion",
        "content": {
            "kind": "ak.content.text",
            "body": format!("event body {actor_seq}"),
            "format": "plain"
        }
    });
    signed_canonical_event(
        event_id,
        "ak.message.create",
        "did:web:alice.example",
        "01904100-0000-7000-8000-a11ce0000001",
        demo_realm_id(),
        actor_seq,
        prev_refs,
        payload,
    )
}

/// Return the content-bound id from an Event value that was just authored.
///
/// The string passed into the historical fixture builders is only a stable
/// fixture label now that Event ids are derived from signed content. Chained
/// fixtures must cite the id the builder actually produced, rather than that
/// label.
pub(crate) fn authored_event_id(event: &Value) -> &str {
    event["event_id"]
        .as_str()
        .expect("authored fixture Event has a content-bound event_id")
}

pub(crate) fn signed_message_event_envelope(
    actor: &str,
    realm_id: &str,
    _thread_id: &str,
    content: Value,
    encrypted: bool,
) -> Value {
    let event_id = soland_test_support::fixture_content_bound_id("ak:event:");
    let actor_seq = TEST_EVENT_SEQ.fetch_add(1, Ordering::Relaxed);
    let mut payload = serde_json::json!({
        "strand_id": expected_strand_id_for_scope(realm_id),
        "track_name": "discussion",
    });
    if encrypted {
        let epoch = content.get("epoch").and_then(Value::as_u64).unwrap_or(0);
        let ciphertext = content
            .get("ciphertext")
            .and_then(Value::as_str)
            .unwrap_or("Y2lwaGVydGV4dA");
        let encrypted_payload = serde_json::json!({
            "version": "1.0",
            "content_type": "application/vnd.arkret.message+json",
            "encryption_context": {
                "epoch": epoch,
                "group_state_ref": "ak:event:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19"
            },
            "ciphertext": ciphertext
        });
        payload["encrypted_content"] = encrypted_payload;
    } else {
        let mut content = content;
        if let Some(object) = content.as_object_mut()
            && object.get("body").is_some()
            && object.get("kind").is_none()
        {
            object.insert(
                "kind".to_owned(),
                Value::String("ak.content.text".to_owned()),
            );
        }
        payload["content"] = content;
    }
    signed_canonical_event(
        &event_id,
        "ak.message.create",
        actor,
        "01904100-0000-7000-8000-a11ce0000001",
        realm_id,
        actor_seq,
        Vec::new(),
        payload,
    )
}

pub(crate) fn signed_actor_private_event_envelope(
    actor: &str,
    device_id: &str,
    realm_id: &str,
    kind: &str,
    payload: Value,
) -> Value {
    let event_id = soland_test_support::fixture_content_bound_id("ak:event:");
    signed_canonical_event(
        &event_id,
        kind,
        actor,
        device_id,
        realm_id,
        TEST_EVENT_SEQ.fetch_add(1, Ordering::Relaxed),
        Vec::new(),
        payload,
    )
}

pub(crate) async fn move_event_to_actor_realm_frontier(
    state: &AppState,
    token: &str,
    actor: &str,
    realm_id: &str,
    event: &mut Value,
) {
    // A DataEvent's `seal_ref` MUST resolve to a verified control-plane Seal of
    // this Realm (`event-auth-state-resolution.md` §4.3(1)), so the basis Seal
    // the envelope builder named has to be accepted before the Event is sent.
    seed_test_realm_basis_seal(state, realm_id, actor).await;
    let actor_core = arkret_wire::project_did_to_core_id(
        &Did::new(actor.to_owned()).expect("fixture frontier actor DID"),
    )
    .expect("fixture frontier actor core DID");
    let frontier_value: Value = TestClient::query("http://server/_arkret/self/events/frontier")
        .json(
            &arkret_models_collaboration::event_query::EventsFrontierRequestBody {
                actor_id: actor_core,
                realm_id: Some(
                    RealmId::new(realm_id.to_owned()).expect("fixture frontier Realm id"),
                ),
            },
        )
        .add_header("authorization", format!("Bearer {token}"), true)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .expect("typed HTTP fixture actor Realm frontier");
    let frontier: arkret_models_collaboration::event_sync::EventsFrontierState =
        serde_json::from_value(frontier_value.clone()).unwrap_or_else(|error| {
            panic!("invalid typed HTTP fixture actor Realm frontier: {error}; {frontier_value}")
        });
    let arkret_models_collaboration::event_sync::EventsFrontierView::RealmActor(frontier) =
        frontier.frontier
    else {
        panic!("combined Realm+actor selector returned the wrong variant");
    };
    event["actor_seq"] = Value::Number(frontier.next_actor_seq.into());
    event["prev_refs"] =
        serde_json::to_value(frontier.frontier_event_ids).expect("frontier Event ids serialize");
    resign_canonical_event(event);
}

pub(crate) async fn submit_actor_private_event(
    state: AppState,
    token: &str,
    actor: &str,
    device_id: &str,
    realm_id: &str,
    kind: &str,
    payload: Value,
) -> Value {
    let mut event = signed_actor_private_event_envelope(actor, device_id, realm_id, kind, payload);
    move_event_to_actor_realm_frontier(&state, token, actor, realm_id, &mut event).await;
    TestClient::post("http://server/_arkret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&event)
        .send(&app_from_state(state))
        .await
        .take_json()
        .await
        .unwrap()
}

pub(crate) async fn post_message_event(
    state: AppState,
    token: &str,
    actor: &str,
    realm_id: &str,
    thread_id: &str,
    content: Value,
    encrypted: bool,
) -> StatusCode {
    let mut event = signed_message_event_envelope(actor, realm_id, thread_id, content, encrypted);
    move_event_to_actor_realm_frontier(&state, token, actor, realm_id, &mut event).await;
    TestClient::post("http://server/_arkret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&event)
        .send(&app_from_state(state))
        .await
        .status_code
        .unwrap()
}

pub(crate) async fn submit_message_event(
    state: AppState,
    token: &str,
    actor: &str,
    realm_id: &str,
    thread_id: &str,
    content: Value,
    encrypted: bool,
) -> Value {
    if !encrypted {
        authorize_test_plaintext_message_service(&state, actor, realm_id).await;
    }
    let mut event = signed_message_event_envelope(actor, realm_id, thread_id, content, encrypted);
    move_event_to_actor_realm_frontier(&state, token, actor, realm_id, &mut event).await;
    let mut response: Value = TestClient::post("http://server/_arkret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&event)
        .send(&app_from_state(state))
        .await
        .take_json()
        .await
        .unwrap();
    if response["event_id"].is_null()
        && let Some(event_id) = response["accepted"]
            .as_array()
            .and_then(|events| events.first())
    {
        response["event_id"] = event_id.clone();
    }
    if response["sync_token"].is_null() && !response["cursor"].is_null() {
        response["sync_token"] = response["cursor"].clone();
    }
    if let Some(event_id) = response["event_id"].as_str() {
        let event_id = event_id.to_owned();
        let event_token = event_id.strip_prefix("ak:event:").unwrap_or(&event_id);
        response["operation_id"] = Value::String(projected_operation_id(&event_id));
        response["kind"] = Value::String("ak.message.create".to_owned());
        response["message_id"] = Value::String(format!("ak:message:{event_token}"));
        response["realm_id"] = Value::String(realm_id.to_owned());
        response["source_realm_id"] = Value::String(realm_id.to_owned());
        response["sender"] = Value::String(actor.to_owned());
        response["encrypted"] = Value::Bool(encrypted);
        response["canonical_event_envelope"] = Value::Bool(true);
    }
    assert!(
        response["event_id"].as_str().is_some(),
        "submit_message_event response missing event_id: {response}"
    );
    response
}

pub(crate) async fn authorize_test_plaintext_message_service(
    state: &AppState,
    actor: &str,
    realm_id: &str,
) {
    let now = chrono::Utc::now();
    let mut meta = state
        .test_persistence()
        .realm_meta()
        .get(realm_id)
        .await
        .unwrap()
        .unwrap_or_else(|| RealmMetaRecord {
            owner: fixture_actor_core_id(actor).to_string(),
            deleted: false,
            discoverability: "invite_only".to_owned(),
            history_access: "since_join".to_owned(),
            preview_policy: None,
            preview_policy_digest: None,
            asset_privacy_policy: None,
            asset_privacy_policy_digest: None,
            encryption_profile: Some("none".to_owned()),
            plaintext_visible_services: Default::default(),
            plaintext_visible_service_classes: Default::default(),
            minimal_metadata_realm: false,
            created_at: now,
            updated_at: now,
        });
    meta.plaintext_visible_services
        .insert(state.service_id().clone());
    meta.plaintext_visible_service_classes
        .entry(state.service_id().clone())
        .or_default()
        .insert(arkret_wire::PlaintextDataClassKind::MessageContent);
    meta.updated_at = now;
    state
        .test_persistence()
        .realm_meta()
        .put(realm_id, &meta)
        .await
        .unwrap();
}

pub(crate) async fn register_account(
    state: AppState,
    did: &str,
    handle: &str,
    device_id: &str,
) -> String {
    let did = Did::new(did.to_owned()).expect("fixture account DID");
    let principal_id = fixture_actor_core_id(did.as_str());
    let registered: Value = TestClient::post("http://server/_soland/gate/account/project")
        .json(&serde_json::json!({
            "principal_id": principal_id,
            "did": did,
            "display_name": handle.trim_start_matches('@'),
            "device_id": device_id
        }))
        .add_header(
            "authorization",
            format!("Bearer {ACCOUNT_REGISTER_BEARER}"),
            true,
        )
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(
        registered["principal_id"],
        principal_id.as_str(),
        "register response: {registered}"
    );

    let login: Value = TestClient::post("http://server/_soland/gate/auth/dev-login")
        .json(&serde_json::json!({
            "actor": principal_id,
            "device_id": device_id,
            "display_name": handle.trim_start_matches('@')
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    login["session_credential"].as_str().unwrap().to_owned()
}

/// Seed a deployment-local account/localpart binding for directory tests.
///
/// service-http-binding.md §3.3 keeps bare handles out of the protocol
/// account-register DTO. The product fixture endpoint accepts a localpart;
/// protocol directory reads then expose its canonical `<localpart>:<domain>`
/// claim (discovery-directory.md §9).
pub(crate) async fn register_account_with_handle(
    state: AppState,
    did: &str,
    handle: &str,
    device_id: &str,
) -> String {
    let localpart = handle
        .split_once(':')
        .map(|(localpart, _)| localpart)
        .expect("canonical handle fixture");
    let registered: Value = TestClient::post("http://server/_soland/self/account/register")
        .json(&serde_json::json!({
            "did": did,
            "handle": format!("@{localpart}"),
            "display_name": handle,
            "device_id": device_id
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(
        registered["principal_id"],
        fixture_actor_core_id(did).as_str(),
        "register response: {registered}"
    );

    let login: Value = TestClient::post("http://server/_soland/gate/auth/dev-login")
        .json(&serde_json::json!({
            "actor": fixture_actor_core_id(did),
            "device_id": device_id,
            "display_name": handle
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    login["session_credential"].as_str().unwrap().to_owned()
}

// T6.1 — describe response partitioning, T1.4 — dev-mode posture surface,
// and T8.3 — hardening block. The test fixtures for these checks live in
// the http_api integration suite and are exercised via the helpers below.

// MIMI facade writes map into the canonical Arkret reducer chain via the
// four reducer-bound mappings: room_update, submit_message, notify, and
// report_abuse. See the live test suite for the executable coverage.

pub(crate) fn test_ed25519_multibase_public(signing: &SigningKey) -> String {
    let mut bytes = Vec::with_capacity(34);
    bytes.extend_from_slice(&[0xed, 0x01]);
    bytes.extend_from_slice(signing.verifying_key().as_bytes());
    format!("z{}", bs58::encode(bytes).into_string())
}

pub(crate) fn test_ephemeral_device_signing_key(actor: &str, device_id: &str) -> SigningKey {
    let mut hasher = Sha256::new();
    hasher.update(b"soland:test:ephemeral-device-key:");
    hasher.update(actor.as_bytes());
    hasher.update([0]);
    hasher.update(device_id.as_bytes());
    SigningKey::from_bytes(&hasher.finalize().into())
}

/// Persist a verified device for `actor` carrying an authoritative
/// `device_public_key` (the shape the session-grant exchange and the
/// `ak.device.authorize` projection both write), so the signing-key directory
/// can resolve it.
pub(crate) async fn seed_verified_device_with_public_key(
    state: &AppState,
    actor: &str,
    device_id: &str,
    signing_key: &SigningKey,
) {
    project_test_authorized_device(state, actor, device_id, signing_key).await;
}

/// Project an accepted `ak.device.authorize` fixture so strict principal-device
/// proof consumers can resolve both the device key and its PCR authority realm.
pub(crate) async fn project_test_authorized_device(
    state: &AppState,
    actor: &str,
    device_id: &str,
    signing_key: &SigningKey,
) -> String {
    let actor_did = Did::new(actor.to_owned()).expect("fixture actor DID");
    let actor_core =
        arkret_wire::project_did_to_core_id(&actor_did).expect("fixture actor core DID");
    let principal_server_id = arkret_identifiers::DidCoreId::new(state.service_id().to_owned())
        .expect("fixture local principal server core DID");
    let realm_id =
        soland_test_support::cba_basis::fixture_principal_control_realm_create_for_server(
            actor,
            principal_server_id.clone(),
        )
        .realm_id
        .clone();
    soland_test_support::cba_basis::seed_realm_genesis_event(state, realm_id.as_str(), actor).await;
    soland_test_support::cba_basis::seed_realm_basis(
        state,
        realm_id.as_str(),
        actor,
        soland_test_support::cba_basis::FixtureBasis::shared(&[]),
    )
    .await;
    let snapshot = state.test_projections().snapshot();
    let genesis_value = snapshot
        .realm_genesis_cell_value(realm_id.as_str())
        .cloned()
        .expect("fixture PCR genesis cell");
    let reducer_profile = snapshot
        .realm_reducer_profile(realm_id.as_str())
        .map(|profile| Value::String(profile.to_owned()))
        .expect("fixture PCR reducer profile cell");
    state
        .test_projections()
        .conformance_install_realm_bootstrap_facets(&realm_id, genesis_value, reducer_profile);
    let genesis_record = state
        .test_persistence()
        .events()
        .realm_events_newest_first(realm_id.as_str())
        .await
        .expect("fixture PCR event lookup")
        .into_iter()
        .find(|record| record.kind == arkret_wire::EventKind::RealmCreate.as_str())
        .expect("fixture PCR genesis Event");
    let genesis: arkret_wire::Event =
        serde_json::from_value(genesis_record.envelope).expect("typed PCR genesis Event");
    let mut event = arkret_wire::test_support::raw_event_at(
        arkret_wire::EventKind::DeviceAuthorize.as_str(),
        arkret_wire::ScopeRef::Realm {
            realm_id: realm_id.clone(),
        },
        actor_core.clone(),
        principal_server_id.clone(),
        1,
        arkret_identifiers::Hlc::new("019041000000-0000-00000001").unwrap(),
        serde_json::json!({
            "principal_id": actor_core,
            "device_id": device_id,
            "device_public_key_did": test_ed25519_multibase_public(signing_key),
            "hpke_key": "z6LSTestAuthorizedDeviceHpkeKey",
            "algorithms": ["ak.hpke_x25519_aead_chacha20poly1305.v1", "ak.mls.v1"],
            "authorized_by": actor_core,
            "not_before": "2026-05-25T00:00:00.000Z",
            "authorization_binding_kind": "registration_anchor",
            "device_signature": "c2ln"
        }),
        chrono::Utc::now(),
    )
    .expect("device authorize fixture Event");
    event.prev_refs = vec![genesis.event_id.clone()];
    event
        .refresh_content_bound_identity_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
        .expect("device authorize fixture identity");
    let event = soland_test_support::signed_event::sign_fixture_event(
        event,
        actor,
        device_id,
        signing_key.to_bytes(),
    );
    let operation = arkret_event_draft::ProjectedEventOperation::from_accepted_event(
        arkret_identifiers::OperationId::new(arkret_identifiers::new_prefixed_uuid7(
            "ak:operation:",
        ))
        .unwrap(),
        arkret_wire::OperationKind::Create,
        None,
        &event,
        arkret_canonical::DigestSuite::Sha256,
    )
    .expect("projected device authorization");
    let event_id = operation.context.event_id.to_string();
    state
        .test_persistence()
        .events()
        .put(soland_test_support::signed_event::canonical_event_record(
            &event,
            Some(realm_id.as_str()),
            chrono::Utc::now(),
        ))
        .await
        .expect("persist accepted device authorization Event");
    let authority_key = arkret_wire::PrincipalAuthorityKey::new(
        genesis.actor_id.clone(),
        genesis.principal_server_id.clone(),
    );
    let persistence = state.test_persistence();
    let resolutions = persistence.principal_resolutions();
    if resolutions
        .by_authority_key(&authority_key)
        .await
        .expect("read principal authority pair")
        .is_none()
    {
        let resolution = resolutions
            .compare_and_set(
                None,
                soland_storage::PrincipalResolutionRecord {
                    authority_key,
                    pcr_realm_id: realm_id.clone(),
                    genesis_event: genesis.clone(),
                    current_event: genesis.clone(),
                    projection: arkret_models_identity::PrincipalResolutionProjection {
                        did: actor_did,
                        method_history_head: format!("sha256:{}", "1".repeat(64)),
                        version_id: "1-QmTestAuthority".to_owned(),
                        resolution_event_ref: genesis.event_id.to_string(),
                        updated_at: genesis.created_at,
                    },
                },
            )
            .await
            .expect("persist principal authority pair");
        assert!(matches!(
            resolution,
            soland_storage::PrincipalResolutionCasResult::Applied(_)
        ));
    }
    soland_test_support::project_accepted_operations(state, actor_core.as_str(), &[operation])
        .await;
    let mut projected_device = state
        .test_persistence()
        .devices()
        .get(actor_core.as_str(), device_id)
        .await
        .expect("read projected authorized device")
        .expect("projected authorized device");
    projected_device
        .payload
        .as_object_mut()
        .expect("projected authorized device payload")
        .insert("authorized_generation_ref".to_owned(), serde_json::json!(1));
    state
        .test_persistence()
        .devices()
        .put(&projected_device)
        .await
        .expect("persist fixture authorized device generation");
    assert_eq!(
        projected_device.payload["device_public_key"],
        test_ed25519_multibase_public(signing_key),
        "projected authorized device must retain its signing key"
    );
    event_id
}

// ── Signal Extension rail (`sync/signal.md`) test fixtures ──────────────────
//
// `POST /_arkret/self/signal` admits an encrypted-only `SignalEnvelope`. There
// is no plaintext branch, so every Signal integration test needs the same three
// things seeded: a bearer session, an authoritative device signing key the
// device directory resolves (the proof is verified by
// `arkret_signatures::verify_ed25519_signal_proof`, not merely parsed), and an
// accepted Seal in the target Realm for `seal_ref` to resolve to.

/// The additional data-plane actions this suite's DataEvents exercise.
///
/// `capability_refs.rs::validate_data_event_capability_refs` decides coverage
/// per receiver-derived cell, over the effective grants the governance basis at
/// `seal_ref` yields for the actor — so the basis has to name every data-plane
/// kind a test submits, and nothing beyond it. The owner bootstrap grant
/// already covers `ak.message.create`; a second, explicit grant carries only
/// the other actions instead of masking owner-message authorization with a
/// duplicate.
const FIXTURE_DATA_PLANE_GRANT_ACTIONS: [&str; 9] = [
    "ak.morph.create",
    "ak.morph.update",
    "ak.relation.create",
    "ak.rsvp.set",
    "ak.space.create",
    "ak.strand.create",
    // `non_event_surface` in the capability-action registry: it authorizes a
    // read rather than an Event kind, and the authz check surface resolves it
    // from the same effective grant set.
    "ak.strand.read",
    "ak.strand.tracks.update",
    "ak.strand.update",
];

/// The accepted Seal a fixture Event names, plus the sealed cell effects that
/// Seal's coverage produces.
///
/// A `seal_ref` is not a token: `event-auth-state-resolution.md` §4.1(3) /
/// §4.3(2) make the verifier resolve the actor's whole effective capability set
/// from the state at that Seal, and soland does exactly that
/// (`capability_refs.rs::data_event_state_at_seal_ref` →
/// `arkret_state::effective_state_at`, which joins the cell log filtered by the
/// Seal's covered Control-Move digests). An empty Seal therefore authorizes
/// nothing, and no per-test patch can fix that — the Realm has to have sealed a
/// real genesis unit.
///
/// So the basis is keyed by `(realm, subject)` and seals one closed unit:
///
/// 1. the registered `ak.component.realm.authority_root.v1` singleton of `realm-and-space.md` §2.5
///    — the only authority genesis establishes, whose controller holds effective `ak.realm.owner`;
/// 2. the owner's own first governance grant
///    ([`soland_services::conformance_basis::OWNER_BOOTSTRAP_GRANT_ACTIONS`]) — `issuer ==
///    subject`, one Realm-wide resource selector, a typed `realm_root` authority ref, and the
///    embedded `capability-action-registry.json` digest;
/// 3. the explicit content grant that carries [`FIXTURE_DATA_PLANE_GRANT_ACTIONS`].
///
/// MLS security-frontier admission is independent from this ordinary Event
/// authorization basis.
/// This binary's fixture basis family.
///
/// The id domain is this binary's own so the HTTP fixtures keep the Seal ids
/// they had before the builder moved into `soland-test-support`; the cache
/// itself is the shared one, which is what lets [`test_cited_basis_seal`] find a
/// Seal whichever family minted it.
pub(crate) const HTTP_API_FIXTURE_BASIS: soland_test_support::cba_basis::FixtureBasis<'static> =
    soland_test_support::cba_basis::FixtureBasis::in_domain(
        "soland:http_api:realm-basis:",
        &FIXTURE_DATA_PLANE_GRANT_ACTIONS,
    );

fn test_realm_basis(
    state: &AppState,
    realm_id: &str,
    subject: &str,
) -> soland_services::conformance_basis::ConformanceRealmBasis {
    let subject_core = arkret_wire::project_did_to_core_id(
        &arkret_identifiers::Did::new(subject.to_owned()).expect("fixture basis subject DID"),
    )
    .expect("fixture basis subject projection");
    soland_test_support::cba_basis::realm_basis(
        state,
        realm_id,
        &subject_core,
        HTTP_API_FIXTURE_BASIS,
    )
}

pub(crate) fn test_realm_basis_for_principal_server(
    state: &AppState,
    realm_id: &str,
    subject: &str,
    principal_server_id: &str,
) -> soland_services::conformance_basis::ConformanceRealmBasis {
    let subject_core = fixture_actor_core_id(subject);
    soland_test_support::cba_basis::realm_basis_for_principal_server(
        state,
        realm_id,
        &subject_core,
        principal_server_id,
        HTTP_API_FIXTURE_BASIS,
    )
}

pub(crate) async fn seed_test_realm_basis_seal_for_principal_server(
    state: &AppState,
    realm_id: &str,
    subject: &str,
    principal_server_id: &str,
) -> arkret_wire::SealId {
    let realm = RealmId::new(realm_id.to_owned()).expect("fixture Realm id");
    let basis =
        test_realm_basis_for_principal_server(state, realm_id, subject, principal_server_id);
    state
        .test_put_seal(&basis.seal, arkret_canonical::DigestSuite::Sha256)
        .unwrap();
    state
        .test_append_sealed_effects(&realm, &basis.seal.id, &basis.ops)
        .unwrap();
    for grant in &basis.grants {
        if let Some(grant) =
            soland_domain::reducer::engine_grant_from_cell_body(&grant.grant_id, &grant.body, false)
        {
            state.upsert_projected_grant_for_test(grant);
        }
    }
    seed_realm_genesis_event(state, realm_id, "did:web:alice.example").await;
    basis.seal.id
}

/// Store the Realm's canonical `ak.realm.create`.
///
/// The Control Proposal decision policy is read from this Event, so a Realm
/// without one answers `quorum_unreachable` on every Control Move and
/// `internal_error` on the governance-proof surfaces. A fixture that stands a
/// Realm up out of band still owes it its genesis Event.
pub(crate) async fn seed_realm_genesis_event(
    state: &AppState,
    realm_id: &str,
    subject: &str,
) -> arkret_identifiers::Hash {
    soland_test_support::cba_basis::seed_realm_genesis_event(state, realm_id, subject).await;
    let record = state
        .test_persistence()
        .events()
        .realm_events_newest_first(realm_id)
        .await
        .expect("fixture Realm genesis lookup")
        .into_iter()
        .find(|record| record.kind == arkret_wire::EventKind::RealmCreate.as_str())
        .expect("fixture Realm genesis Event");
    arkret_identifiers::Hash::new(record.canonical_digest)
        .expect("fixture genesis Event digest is a hash")
}

/// The Seal a fixture Event names in `seal_ref` / `seal_basis`.
pub(crate) fn test_realm_basis_seal(realm_id: &str, subject: &str) -> arkret_wire::Seal {
    test_realm_basis(
        &soland_test_support::app_state(test_config()),
        realm_id,
        subject,
    )
    .seal
}

/// The fixture basis Seal an already-built Event cites.
///
/// Federation disclosure is keyed off the transported Event, not off its actor:
/// `event_sync.rs::validate_federation_transport` refuses a `cba_proof_bundles`
/// entry that is not reachable from some transported `seal_ref` or
/// `seal_basis.leaves` entry. So a fixture that re-authors an Event after the
/// envelope was built has to disclose the Seal the envelope still names.
pub(crate) fn test_cited_basis_seal(event: &arkret_wire::Event) -> arkret_wire::Seal {
    let cited = event
        .seal_ref
        .as_ref()
        .or_else(|| {
            event
                .seal_basis
                .as_ref()
                .and_then(|basis| basis.leaves.first())
        })
        .expect("fixture Event cites a basis Seal");
    soland_test_support::cba_basis::basis_seal_with_id(cited)
        .expect("cited Seal was built by this fixture")
}

/// Put the genesis unit of `realm_id` in place for `subject`.
///
/// A DataEvent `seal_ref` MUST resolve to a verified control-plane Seal of the
/// same Realm (`event-auth-state-resolution.md` §4.3(1)) **and** the governance
/// state that Seal covers MUST authorize the Event's derived writes, so both
/// the Seal object and its sealed cell effects have to exist before the Event
/// is admitted. The cell writes are OR-Set adds under a fixed tag, so repeating
/// this for the same Realm/subject is idempotent.
pub(crate) async fn seed_test_realm_basis_seal(
    state: &AppState,
    realm_id: &str,
    subject: &str,
) -> arkret_wire::SealId {
    let realm = RealmId::new(realm_id.to_owned()).expect("fixture Realm id");
    let basis = test_realm_basis(state, realm_id, subject);
    state
        .test_put_seal(&basis.seal, arkret_canonical::DigestSuite::Sha256)
        .unwrap();
    state
        .test_append_sealed_effects(&realm, &basis.seal.id, &basis.ops)
        .unwrap();
    // Keep the synthetic setup honest: the head Seal must reconstruct the
    // grant cells it claims to cover through the same historical-state path
    // production DataEvent admission uses. Merely filling the live authz
    // index below would otherwise let a broken Seal fixture masquerade as a
    // valid governance basis.
    let historical_state = state
        .test_effective_state_at(std::slice::from_ref(&basis.seal.id), &realm)
        .expect("fixture basis historical state");
    let subject_core = arkret_wire::project_did_to_core_id(
        &Did::new(subject.to_owned()).expect("fixture basis subject DID"),
    )
    .expect("fixture basis subject core DID");
    for expected in &basis.grants {
        let cell = arkret_identifiers::CellRef::new(format!(
            "ak:cell:ak.component.capability.grant.v1:{}",
            expected.grant_id
        ))
        .expect("fixture capability cell");
        let cell_state = historical_state.get(&cell).unwrap_or_else(|| {
            panic!(
                "fixture grant cell {cell} is absent at the head Seal; visible cells: {:?}",
                historical_state.keys().collect::<Vec<_>>()
            )
        });
        let projected = soland_domain::reducer::engine_grant_from_capability_cell_state(
            &expected.grant_id,
            cell_state,
        )
        .unwrap_or_else(|| {
            panic!("fixture grant must be reconstructible at the head Seal: {cell_state:?}")
        });
        assert_eq!(projected.subject_id, subject_core);
        assert_eq!(projected.realm_id, realm_id);
        assert!(
            !projected.actions.is_empty(),
            "fixture grant must retain its registered actions"
        );
    }
    // Accepting a capability Event is what fills the authz index the
    // `authz/check` surface reads. Sealing the basis directly skips that, so
    // run the same refresh the accept path runs.
    for grant in &basis.grants {
        if let Some(grant) =
            soland_domain::reducer::engine_grant_from_cell_body(&grant.grant_id, &grant.body, false)
        {
            state.upsert_projected_grant_for_test(grant);
        }
    }
    // The demo Realm identity is derived from its one canonical genesis
    // fixture, whose creator is fixed independently of whichever subject a
    // test grants capabilities to. Reusing `subject` here silently authored a
    // different genesis Event whenever a server or Bob grant was requested.
    let genesis_subject = if realm_id == demo_realm_id() {
        "did:web:alice.example"
    } else {
        subject
    };
    seed_realm_genesis_event(state, realm_id, genesis_subject).await;
    basis.seal.id
}

/// Seal the demo Realm's genesis unit for the actor [`dev_token`] logs in.
///
/// The stateless envelope builders (`signed_space_event`,
/// `signed_strand_event`, `signed_morph_event`, …) all author demo-Realm
/// DataEvents as `did:web:alice.example` and name that Realm's basis Seal in
/// `seal_ref`; a test that POSTs one has to put the Seal and the governance
/// state it covers in place first. Tests that instead make the *server*
/// materialize the demo Realm's first canonical Seal must not call this — see
/// [`test_realm_uncovered_basis_seal`].
pub(crate) async fn seed_demo_realm_basis(state: &AppState) -> arkret_wire::SealId {
    let seal_id = seed_test_realm_basis_seal(state, demo_realm_id(), "did:web:alice.example").await;
    let frontier_event_id = state
        .test_persistence()
        .events()
        .realm_events_newest_first(demo_realm_id())
        .await
        .expect("demo Realm bootstrap frontier")
        .into_iter()
        .filter(|record| record.actor_id == fixture_actor_core_id("did:web:alice.example").as_str())
        .max_by_key(|record| record.actor_seq)
        .expect("demo Realm bootstrap has an Alice frontier Event")
        .event_id;
    if let Some(existing) = DEMO_REALM_ACTOR_FRONTIER_EVENT_ID.get() {
        assert_eq!(
            existing, &frontier_event_id,
            "demo bootstrap frontier is stable"
        );
    } else {
        let _ = DEMO_REALM_ACTOR_FRONTIER_EVENT_ID.set(frontier_event_id);
    }
    seal_id
}

/// Put an accepted Seal in `realm_id` so a Signal can name it as its Seal basis.
pub(crate) async fn seed_signal_basis_seal(
    state: &AppState,
    realm_id: &str,
    subject: &str,
) -> arkret_wire::SealId {
    seed_test_realm_basis_seal(state, realm_id, subject).await
}

/// A bearer session plus the device signing key the Signal proof is made with.
///
/// The returned key is the one the device directory now authorizes for
/// `device_id`, so an envelope signed with any other key fails the §3(4) device
/// proof rather than a structural check.
pub(crate) async fn seed_signal_sender_device(
    state: &AppState,
    actor: &str,
    device_id: &str,
    display_name: &str,
) -> (String, SigningKey) {
    let token = dev_token_for_device(state.clone(), actor, device_id, display_name).await;
    let signing_key = test_ephemeral_device_signing_key(actor, device_id);
    project_test_authorized_device(state, actor, device_id, &signing_key).await;
    (token, signing_key)
}

/// Build a fully signed `SignalEnvelope`.
///
/// `opaque_payload` only varies the ciphertext: nothing the server may read
/// lives in it. It exists so two Signals in one test differ in
/// `envelope_digest` and are not collapsed by the §2 replay suppression.
#[expect(
    clippy::too_many_arguments,
    reason = "the fixture exposes every server-visible header member of the envelope"
)]
pub(crate) fn signed_signal_envelope(
    realm_id: &str,
    scope_ref: arkret_wire::ScopeRef,
    sender_actor: &str,
    sender_device: &str,
    seal_ref: &arkret_wire::SealId,
    signal_class: arkret_wire::SignalClass,
    sent_at: chrono::DateTime<chrono::Utc>,
    ttl_seconds: i64,
    opaque_payload: &str,
    signing_key: &SigningKey,
) -> arkret_wire::SignalEnvelope {
    let sent_at = chrono::DateTime::from_timestamp_millis(sent_at.timestamp_millis()).unwrap();
    // `signal.md` §1 — the method is the directory lookup key and MUST equal
    // `{sender_actor_id}#{sender_device_id}` verbatim.
    let verification_method = arkret_wire::DidUrl::new(format!("{sender_actor}#{sender_device}"))
        .expect("fixture verification method is a DID URL");
    let mut envelope = arkret_wire::SignalEnvelope {
        realm_id: RealmId::new(realm_id.to_owned()).unwrap(),
        scope_ref,
        sender_actor_id: fixture_actor_core_id(sender_actor),
        sender_device_id: arkret_identifiers::DeviceId::new(sender_device.to_owned()).unwrap(),
        seal_ref: seal_ref.clone(),
        signal_class,
        sent_at,
        expires_at: sent_at + chrono::Duration::seconds(ttl_seconds),
        encrypted_payload: arkret_wire::SignalEncryptedPayload {
            scheme: arkret_wire::SIGNAL_AEAD_SCHEME.to_owned(),
            key_ref: arkret_wire::SignalKeyRef {
                algorithm: "MLS-EXPORTER-AEAD".to_owned(),
                group_state_ref: "ak:event:AdIAmf-J5rIPxEomGXwJblJdhNg-TllVN8uRTI85EUIM".to_owned(),
            },
            purpose: arkret_wire::SIGNAL_AEAD_PURPOSE.to_owned(),
            aead_profile: "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519".to_owned(),
            epoch: 7,
            nonce: "AAAAAAAAAAAAAAAA".to_owned(),
            ciphertext: URL_SAFE_NO_PAD.encode(opaque_payload.as_bytes()),
            aad_digest: arkret_identifiers::Hash::new(format!("sha256:{}", "0".repeat(64)))
                .unwrap(),
        },
        proof: arkret_wire::SignalProof {
            kind: "detached_jws".to_owned(),
            verification_method: verification_method.clone(),
            envelope_digest: arkret_identifiers::Hash::new(format!("sha256:{}", "0".repeat(64)))
                .unwrap(),
            created_at: sent_at,
            domain: None,
            audience: None,
            jws: String::new(),
        },
    };
    envelope.encrypted_payload.aad_digest = envelope.expected_aad_digest().unwrap();
    envelope.proof.envelope_digest = envelope.envelope_digest().unwrap();
    let binding = envelope.proof_binding_bytes().unwrap();
    envelope.proof.jws = arkret_signatures::Ed25519DetachedJwsSigner::new(
        signing_key.clone(),
        verification_method.as_str().to_owned(),
    )
    .sign_detached_jws(&binding);
    envelope
}

/// `POST /_arkret/self/signal` — `ak.self.signal.command.send.v1`.
pub(crate) async fn post_signal(
    state: AppState,
    token: &str,
    envelope: &arkret_wire::SignalEnvelope,
) -> salvo::http::Response {
    TestClient::post("http://server/_arkret/self/signal")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("content-type", "application/json", true)
        .body(
            arkret_canonical::canonical_json_bytes(envelope)
                .expect("fixture signal envelope is canonicalizable"),
        )
        .send(&app_from_state(state))
        .await
}

/// Seed an active Circle with a joined member set in the reducer projection.
///
/// The Circle is the only scope discriminator a Signal exposes to the server, so
/// it is what the §3(2) live send-eligibility and the receiver-side fanout
/// checks are decided against.
pub(crate) fn seed_test_circle(
    state: &AppState,
    realm_id: &str,
    circle_id: &str,
    members: &[&str],
) {
    let now = chrono::Utc::now();
    let mut projection = state.test_projection().lock();
    projection.circles.insert(
        circle_id.to_owned(),
        soland_domain::reducer::CircleProjection {
            circle_id: circle_id.to_owned(),
            realm_id: realm_id.to_owned(),
            profile_ref: None,
            title: "Signal scope".to_owned(),
            summary: None,
            display: serde_json::json!({
                "short_name": "Signal",
                "color_token": "slate",
                "symbol": {"glyph": "ring"}
            }),
            directory_visibility: "members".to_owned(),
            join_rule: "invite".to_owned(),
            history_access: "since_join".to_owned(),
            content_encryption_floor: None,
            metadata_encryption_floor: None,
            encryption_profile: "none".to_owned(),
            content_scheme: None,
            durability_policy: None,
            mls_group_ref: None,
            state: soland_domain::reducer::CircleLifecycleState::Active,
            state_changed_at: None,
            created_by: members
                .first()
                .map(|member| fixture_actor_core_id(member).to_string())
                .unwrap_or_default(),
            created_at: now,
            updated_by: None,
            updated_at: None,
            members: members
                .iter()
                .map(|member| fixture_actor_core_id(member).to_string())
                .collect(),
        },
    );
    for member in members {
        let member = fixture_actor_core_id(member).to_string();
        projection.circle_memberships.insert(
            (circle_id.to_owned(), member.clone()),
            soland_domain::reducer::CircleMembershipState {
                circle_id: circle_id.to_owned(),
                member,
                state: "join".to_owned(),
                invited_at: None,
                joined_at: now,
                updated_at: now,
            },
        );
    }
}

/// Drain one `GET /_arkret/self/signal/subscribe` connection.
///
/// §4 forbids a per-payload-type stream frame kind, so the stream is exactly
/// verbatim `SignalEnvelope` lines plus bounded transport control frames. The
/// control frames are dropped here and every envelope line is decoded back into
/// the strong type, which is also the assertion that it was relayed verbatim.
pub(crate) async fn signal_subscribe_envelopes(
    state: AppState,
    token: &str,
    max_duration_ms: u64,
) -> Vec<arkret_wire::SignalEnvelope> {
    let mut response = TestClient::get(format!(
        "http://server/_arkret/self/signal/subscribe\
         ?max_duration_ms={max_duration_ms}&heartbeat_ms=600000"
    ))
    .add_header("authorization", format!("Bearer {token}"), true)
    .send(&app_from_state(state))
    .await;
    let mut envelopes = Vec::new();
    while let Some(Ok(frame)) = response.body.next().await {
        let Ok(bytes) = frame.into_data() else {
            continue;
        };
        for line in String::from_utf8_lossy(&bytes).lines() {
            if line.trim().is_empty() {
                continue;
            }
            let value: Value = serde_json::from_str(line).expect("signal stream emits NDJSON");
            // `signal.md` §4.1 — every frame on this stream is tagged: the data
            // frame is `{kind:"signal", envelope}` and the control frames are
            // `heartbeat` / `drain` / `unauthorized`. Skipping every tagged line
            // discards the data frames along with the control ones.
            match value.get("kind").and_then(Value::as_str) {
                Some("signal") => envelopes.push(
                    serde_json::from_value(value["envelope"].clone())
                        .expect("signal subscribe relays a verbatim SignalEnvelope"),
                ),
                Some("heartbeat" | "drain" | "unauthorized") => continue,
                other => panic!("unexpected signal stream frame kind {other:?}: {value}"),
            }
        }
    }
    envelopes
}

#[expect(
    clippy::too_many_arguments,
    reason = "the fixture exposes each signed did:webvh proof component"
)]
pub(crate) fn test_embedded_webvh_proof(
    principal_server_url: &str,
    local_id: &str,
    did_public_key_multibase: &str,
    update_public_key_multibase: &str,
    next_update_public_key_multibase: &str,
    did_key_fragment: &str,
    update_signing: &SigningKey,
    version_time: &str,
) -> Value {
    let method_authority = test_webvh_method_authority(principal_server_url);
    let placeholder_did = format!("did:webvh:{{SCID}}:{method_authority}:webvh:{local_id}");
    let did_key_id = format!("{placeholder_did}#{did_key_fragment}");
    let skeleton = serde_json::json!({
        "versionId": "{SCID}",
        "versionTime": version_time,
        "parameters": {
            "scid": "{SCID}",
            "method": "did:webvh:1.0",
            "updateKeys": [update_public_key_multibase],
            "nextKeyHashes": [arkret_canonical::sha256_multihash_base58btc(
                next_update_public_key_multibase.as_bytes()
            )],
        },
        "state": {
            "@context": ["https://www.w3.org/ns/did/v1"],
            "id": placeholder_did,
            "verificationMethod": [{
                "id": did_key_id,
                "type": "Multikey",
                "controller": placeholder_did,
                "publicKeyMultibase": did_public_key_multibase,
            }],
            "authentication": [did_key_id],
            "assertionMethod": [did_key_id],
            "alsoKnownAs": ["acct:alice@example.com"],
            "service": [{
                "id": format!("{placeholder_did}#soland"),
                "type": "ArkretPrincipalServer",
                "serviceEndpoint": principal_server_url.trim_end_matches('/'),
            }],
        },
    });
    let scid = test_scid(&skeleton);
    let mut entry = test_replace_scid(skeleton, &scid);
    let entry_hash = test_webvh_entry_hash(&entry, &scid);
    if let Value::Object(map) = &mut entry {
        map.insert(
            "versionId".to_owned(),
            Value::String(format!("1-{entry_hash}")),
        );
    }
    // The single eddsa-jcs-2022 implementation lives in the SDK; the fixture
    // must sign exactly the bytes soland's verifier reconstructs.
    arkret_signatures::build_eddsa_jcs_2022_proof(
        &entry,
        update_signing,
        &format!("did:key:{update_public_key_multibase}#{update_public_key_multibase}"),
        arkret_signatures::DataIntegrityProofPurpose::AssertionMethod,
    )
    .unwrap()
}

pub(crate) fn test_webvh_method_authority(url: &str) -> String {
    let authority = url
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(url)
        .trim_end_matches('/')
        .split('/')
        .next()
        .unwrap_or(url);
    authority.replace(':', "%3A")
}

pub(crate) fn test_scid(value: &Value) -> String {
    let canonical = arkret_canonical::canonical_json_bytes(value).unwrap();
    arkret_canonical::sha256_multihash_base58btc(&canonical)
}

/// did:webvh v1.0 entry-hash preimage: drop `proof`, set `versionId` to the
/// predecessor anchor (the SCID for the inception entry).
pub(crate) fn test_webvh_entry_hash(value: &Value, prev_anchor: &str) -> String {
    let mut clone = value.clone();
    if let Value::Object(map) = &mut clone {
        map.remove("proof");
        map.insert(
            "versionId".to_owned(),
            Value::String(prev_anchor.to_owned()),
        );
    }
    let canonical = arkret_canonical::canonical_json_bytes(&clone).unwrap();
    arkret_canonical::sha256_multihash_base58btc(&canonical)
}

pub(crate) fn test_replace_scid(value: Value, scid: &str) -> Value {
    serde_json::from_str(
        &serde_json::to_string(&value)
            .unwrap()
            .replace("{SCID}", scid),
    )
    .unwrap()
}

// `standard_entity_types_and_reverse_domain_custom_types_work` and
// `view_endpoints_project_common_presentation_shapes` were deleted in
// round 6: the `entity` / `view` abstraction they exercised never landed in
// `arkret-spec/v1`. Typed objects in the protocol are `ak:strand:` / `ak:space:`
// / `ak:morph:` / `ak:relation:` / `ak:view:`, each with its own dedicated
// event kind; presentation concerns belong on `ak.view.*` events going
// through the reducer, not on a free-form `/_arkret/self/entities` /
// `/_arkret/self/views` scaffold.

/// Build a signed container `ak.space.*` event envelope for the Space
/// (container) state-machine integration test. Mirrors [`signed_event_envelope`]
/// but with a custom `kind` + `payload`; container lifecycle events do not
/// carry a message body.
pub(crate) fn signed_space_event(
    event_id: &str,
    authoring_step: u64,
    kind: &str,
    mut payload: Value,
    prev_refs: Vec<&str>,
) -> Value {
    let actor_seq = fixture_actor_seq(authoring_step);
    let prev_refs = fixture_prev_refs(prev_refs);
    normalize_space_container_payload(kind, &mut payload);
    payload = typed_space_container_payload(kind, payload);
    signed_canonical_event(
        event_id,
        kind,
        "did:web:alice.example",
        "01904100-0000-7000-8000-a11ce0000001",
        demo_realm_id(),
        actor_seq,
        prev_refs,
        payload,
    )
}

pub(crate) fn normalize_space_container_payload(kind: &str, payload: &mut Value) {
    let Some(object) = payload.as_object_mut() else {
        return;
    };
    if kind == "ak.space.create"
        && let Some(space) = object.get_mut("object").and_then(Value::as_object_mut)
    {
        space.remove("id");
        space
            .entry("schema".to_owned())
            .or_insert_with(|| Value::String("ak.schema.space.v1".to_owned()));
        space
            .entry("realm_id".to_owned())
            .or_insert_with(|| Value::String(demo_realm_id().to_owned()));
        space
            .entry("created_at".to_owned())
            .or_insert_with(|| Value::String("2026-05-17T00:00:00.000Z".to_owned()));
    }
}

fn typed_space_container_payload(kind: &str, payload: Value) -> Value {
    match kind {
        arkret_wire::event_kind_str::SPACE_ARCHIVE | arkret_wire::event_kind_str::SPACE_RESTORE => {
            serde_json::to_value(
                arkret_models_collaboration::object_lifecycle::SpaceStateTransitionPayload {
                    space_id: required_space_id(&payload, "space_id"),
                    reason: optional_string(&payload, "reason"),
                    effective_at: None,
                },
            )
            .expect("space lifecycle payload serialization")
        }
        arkret_wire::event_kind_str::SPACE_TOMBSTONE => serde_json::to_value(
            arkret_models_collaboration::object_lifecycle::SpaceObjectTombstonePayload {
                space_id: required_space_id(&payload, "space_id"),
                reason: optional_string(&payload, "reason"),
                replacement_space_id: optional_space_id(&payload, "replacement_space_id"),
                replacement_event_id: optional_event_ref(&payload, "replacement_event_id"),
                effective_at: None,
            },
        )
        .expect("space tombstone payload serialization"),
        _ => payload,
    }
}

fn required_space_id(payload: &Value, field: &str) -> arkret_identifiers::SpaceId {
    let value = payload
        .get(field)
        .and_then(Value::as_str)
        .expect("space lifecycle payload requires space_id");
    arkret_identifiers::SpaceId::new(value.to_owned()).expect("valid space id")
}

fn optional_space_id(payload: &Value, field: &str) -> Option<arkret_identifiers::SpaceId> {
    payload.get(field).and_then(Value::as_str).map(|value| {
        arkret_identifiers::SpaceId::new(value.to_owned()).expect("valid optional space id")
    })
}

fn optional_event_ref(payload: &Value, field: &str) -> Option<arkret_wire::EventRef> {
    payload
        .get(field)
        .map(|value| serde_json::from_value(value.clone()).expect("valid optional event ref"))
}

fn optional_string(payload: &Value, field: &str) -> Option<String> {
    payload
        .get(field)
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
}

// End-to-end check that the server-side Space-container state-machine guard
// rejects illegal lifecycle transitions with HTTP 412 + the spec-canonical
// reason_code per `arkret-spec/v1/zh/models/common-fields.md §5.1`.
// Reducer-level unit coverage lives in `src/reducer.rs::tests`; this test
// verifies the wire mapping (`event_log::submit_event` →
// `check_space_container_lifecycle_transition` →
// `StatusCode::PRECONDITION_FAILED`).

/// Build a signed `ak.strand.*` event envelope for the Strand state-machine
/// integration test. Mirror of `signed_space_event` with Strand payload
/// normalization selected from the event kind.
pub(crate) fn signed_strand_event(
    event_id: &str,
    authoring_step: u64,
    kind: &str,
    mut payload: Value,
    prev_refs: Vec<&str>,
) -> Value {
    let actor_seq = fixture_actor_seq(authoring_step);
    let prev_refs = fixture_prev_refs(prev_refs);
    normalize_strand_payload(kind, &mut payload);
    signed_canonical_event(
        event_id,
        kind,
        "did:web:alice.example",
        "01904100-0000-7000-8000-a11ce0000001",
        demo_realm_id(),
        actor_seq,
        prev_refs,
        payload,
    )
}

pub(crate) fn normalize_strand_payload(kind: &str, payload: &mut Value) {
    let Some(object) = payload.as_object_mut() else {
        return;
    };
    if kind == "ak.strand.create"
        && let Some(strand) = object.get_mut("object").and_then(Value::as_object_mut)
    {
        strand.remove("id");
        strand
            .entry("schema".to_owned())
            .or_insert_with(|| Value::String("ak.schema.strand.v1".to_owned()));
        strand
            .entry("realm_id".to_owned())
            .or_insert_with(|| Value::String(demo_realm_id().to_owned()));
        strand
            .entry("created_at".to_owned())
            .or_insert_with(|| Value::String("2026-05-17T00:00:00.000Z".to_owned()));
        strand
            .entry("stage".to_owned())
            .or_insert_with(|| Value::String("draft".to_owned()));
        strand.entry("tracks".to_owned()).or_insert_with(|| {
            serde_json::json!({
                "discussion": {
                    "is_primary": true,
                    "profile": "discussion"
                }
            })
        });
    }
    // Every Strand kind that addresses an existing Strand identifies it by
    // `payload.target_ref`: that is the `cell_subject` the registered contract
    // reads (`contract-registry.json`), and `event-payload.schema.json`'s
    // Strand payload classes close over `target_ref` with
    // `additionalProperties:false`, so a `strand_id` member is not merely an
    // alias — it has no place on the wire.
    if matches!(
        kind,
        "ak.strand.archive" | "ak.strand.restore" | "ak.strand.tombstone" | "ak.strand.update"
    ) {
        if !object.contains_key("target_ref") {
            if let Some(strand_id) = object.get("strand_id").and_then(Value::as_str) {
                object.insert("target_ref".to_owned(), Value::String(strand_id.to_owned()));
            } else if let Some(object_ref) = object.get("object_ref").and_then(Value::as_str) {
                object.insert(
                    "target_ref".to_owned(),
                    Value::String(object_ref.to_owned()),
                );
            }
        }
        object.remove("strand_id");
        object.remove("object_ref");
    }
}

/// Build a signed `ak.morph.*` event envelope.
pub(crate) fn signed_morph_event(
    event_id: &str,
    authoring_step: u64,
    kind: &str,
    mut payload: Value,
    prev_refs: Vec<&str>,
) -> Value {
    let actor_seq = fixture_actor_seq(authoring_step);
    let prev_refs = fixture_prev_refs(prev_refs);
    normalize_morph_payload(kind, &mut payload);
    payload = typed_morph_payload(kind, payload);
    signed_canonical_event(
        event_id,
        kind,
        "did:web:alice.example",
        "01904100-0000-7000-8000-a11ce0000001",
        demo_realm_id(),
        actor_seq,
        prev_refs,
        payload,
    )
}

pub(crate) fn normalize_morph_payload(kind: &str, payload: &mut Value) {
    let Some(object) = payload.as_object_mut() else {
        return;
    };
    if kind == "ak.morph.create"
        && let Some(morph) = object.get_mut("object").and_then(Value::as_object_mut)
    {
        morph.remove("id");
        morph
            .entry("schema".to_owned())
            .or_insert_with(|| Value::String("ak.schema.morph.v1".to_owned()));
        morph
            .entry("realm_id".to_owned())
            .or_insert_with(|| Value::String(demo_realm_id().to_owned()));
        morph
            .entry("created_at".to_owned())
            .or_insert_with(|| Value::String("2026-05-17T00:00:00.000Z".to_owned()));
        morph
            .entry("stage".to_owned())
            .or_insert_with(|| Value::String("draft".to_owned()));
        morph
            .entry("schema_refs".to_owned())
            .or_insert_with(|| serde_json::json!(["ak.schema.morph.v1"]));
    }
}

fn typed_morph_payload(kind: &str, payload: Value) -> Value {
    match kind {
        arkret_wire::event_kind_str::MORPH_ARCHIVE => {
            arkret_models_collaboration::governance::realm_lifecycle::ObjectLifecyclePayload::new(
                required_string(&payload, "target_ref", "morph lifecycle target_ref"),
            )
            .with_target_state("archived")
            .to_value()
            .expect("morph archive payload serialization")
        }
        arkret_wire::event_kind_str::MORPH_RESTORE => {
            arkret_models_collaboration::governance::realm_lifecycle::ObjectLifecyclePayload::new(
                required_string(&payload, "target_ref", "morph lifecycle target_ref"),
            )
            .with_target_state("active")
            .to_value()
            .expect("morph restore payload serialization")
        }
        arkret_wire::event_kind_str::MORPH_UPDATE => {
            let morph_id = arkret_identifiers::MorphId::new(required_string(
                &payload,
                "target_ref",
                "morph update target_ref",
            ))
            .expect("valid morph id");
            let patch: arkret_wire::Patch = serde_json::from_value(
                payload
                    .get("patch")
                    .cloned()
                    .expect("morph update payload requires patch"),
            )
            .expect("valid morph update patch");
            arkret_models_collaboration::events_payloads::MorphUpdatePayload::for_morph(
                morph_id, patch,
            )
            .expect("valid morph update payload")
            .to_value()
            .expect("morph update payload serialization")
        }
        _ => payload,
    }
}

fn required_string(payload: &Value, field: &str, context: &str) -> String {
    payload
        .get(field)
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| panic!("{context} is required"))
}

/// Build a signed relation event envelope for read-model projection tests.
pub(crate) fn signed_relation_event(
    event_id: &str,
    authoring_step: u64,
    mut payload: Value,
    prev_refs: Vec<&str>,
) -> Value {
    let actor_seq = fixture_actor_seq(authoring_step);
    let prev_refs = fixture_prev_refs(prev_refs);
    payload["relation_id"] = Value::String(event_id.replacen("ak:event:", "ak:relation:", 1));
    payload = typed_relation_create_payload(payload);
    signed_canonical_event(
        event_id,
        "ak.relation.create",
        "did:web:alice.example",
        "01904100-0000-7000-8000-a11ce0000001",
        demo_realm_id(),
        actor_seq,
        prev_refs,
        payload,
    )
}

fn typed_relation_create_payload(payload: Value) -> Value {
    // The typed DTO mints its own relation id; this only asserts the caller
    // supplied one, so the binding is intentionally discarded.
    let _relation_id = relation_payload_str(&payload, &["relation_id", "id"])
        .expect("relation create payload requires relation_id");
    let kind = relation_payload_str(&payload, &["relation_kind", "kind"])
        .expect("relation create payload requires kind");
    let from_ref = relation_payload_str(&payload, &["from_ref", "from"])
        .expect("relation create payload requires from_ref");
    let to_ref = relation_payload_str(&payload, &["to_ref", "to"])
        .expect("relation create payload requires to_ref");
    let rank = relation_payload_str(&payload, &["rank"]);
    // `#/$defs/relation_create_object` is the whole Relation object minus the
    // id, so the typed payload carries every required object member.
    let relation = arkret_models_collaboration::objects::relation::Relation {
        schema: arkret_wire::SchemaId::RELATION_V1.to_owned(),
        id: None,
        realm_id: arkret_wire::RealmId::new(demo_realm_id().to_owned()).expect("fixture realm id"),
        scope_circle_id: None,
        effective_scope: None,
        relation_kind: arkret_wire::RelationKind::from_wire(&kind),
        from_ref,
        to_ref,
        rank: None,
        fields: Default::default(),
        state: None,
        state_changed_at: None,
        created_by: arkret_wire::DidCoreId::new("ak:did_core:web:alice.example".to_owned())
            .expect("fixture actor id"),
        created_at: "2026-08-18T00:00:00.000Z"
            .parse()
            .expect("fixture created_at"),
        updated_by: None,
        updated_at: None,
    };
    let mut typed =
        arkret_models_collaboration::governance::membership_invite::RelationCreatePayload::new(
            relation,
        );
    if let Some(rank) = rank {
        typed = typed.with_rank(rank);
    }
    typed
        .to_value()
        .expect("relation create payload serialization")
}

fn relation_payload_str(payload: &Value, fields: &[&str]) -> Option<String> {
    fields
        .iter()
        .find_map(|field| payload.get(*field).and_then(Value::as_str))
        .or_else(|| {
            payload
                .get("relation")
                .and_then(Value::as_object)
                .and_then(|relation| {
                    fields
                        .iter()
                        .find_map(|field| relation.get(*field).and_then(Value::as_str))
                })
        })
        .map(ToOwned::to_owned)
}

// Round 13 — end-to-end check that Strand / Morph lifecycle state-machine
// guards map to HTTP 412 + canonical reason_code per spec §5.1. Combined
// Strand+Morph in one test to keep the suite small.

/// Build a signed `ak.redaction` event envelope, used by round 14b to
/// test object-level redaction (Strand / Morph). Mirror of
/// `signed_event_envelope` for the redaction kind. The spec schema
/// registry doesn't carry a dedicated `ak.schema.redaction.v1` —
/// `ak.redaction` is `category=message` per event-kind-registry, so
/// reuses `ak.schema.message.v1`.
pub(crate) fn signed_redaction_event(
    event_id: &str,
    authoring_step: u64,
    mut payload: Value,
    prev_refs: Vec<&str>,
) -> Value {
    let actor_seq = fixture_actor_seq(authoring_step);
    let prev_refs = fixture_prev_refs(prev_refs);
    if let Some(object) = payload.as_object_mut()
        && !object.contains_key("target_ref")
        && let Some(object_ref) = object.get("object_ref").cloned()
    {
        object.insert("target_ref".to_owned(), object_ref);
    }
    if let Some(object) = payload.as_object_mut() {
        object.remove("object_ref");
        object.remove("by");
    }
    signed_canonical_event(
        event_id,
        "ak.redaction",
        "did:web:alice.example",
        "01904100-0000-7000-8000-a11ce0000001",
        demo_realm_id(),
        actor_seq,
        prev_refs,
        payload,
    )
}

/// Lifecycle/projection scenarios number their authoring operations from one,
/// while the wire actor chain starts at sequence zero.
fn fixture_actor_seq(authoring_step: u64) -> u64 {
    authoring_step
        .checked_add(7)
        .expect("HTTP fixture authoring sequence")
}

fn fixture_prev_refs(prev_refs: Vec<&str>) -> Vec<&str> {
    if prev_refs.is_empty() {
        vec![
            DEMO_REALM_ACTOR_FRONTIER_EVENT_ID
                .get()
                .expect("seed_demo_realm_basis must run before authoring demo Realm Events")
                .as_str(),
        ]
    } else {
        prev_refs
    }
}

fn projected_operation_id(event_id: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"ak:operation:soland-event-projection:v1:");
    hasher.update(event_id.as_bytes());
    let digest = hasher.finalize();
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x70;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    format!("ak:operation:{}", uuid::Uuid::from_bytes(bytes))
}

/// The Event admission state machine's debug-codegen stack frame exceeds the
/// default 2 MiB libtest thread stack on Windows, so any test that drives it
/// overflows and aborts the whole binary before libtest can print a
/// `test result:` line.
///
/// `RUST_MIN_STACK` is not a fix: `work/done/2026-08-17-1805` forbids pinning
/// it in `.cargo/config.toml` or CI, and an environment variable that every
/// caller must remember is not a property of the test. The affected tests run
/// their body on a dedicated thread with headroom instead.
pub(crate) const DEEP_STACK_BYTES: usize = 8 * 1024 * 1024;

/// Run one async test body on a [`DEEP_STACK_BYTES`] thread with a
/// current-thread Tokio runtime.
pub(crate) fn run_on_deep_stack<F>(name: &'static str, body: impl FnOnce() -> F + Send + 'static)
where
    F: Future<Output = ()>,
{
    run_on_deep_stack_with(name, RuntimeFlavor::CurrentThread, body);
}

/// [`run_on_deep_stack`] for a test that needs
/// `#[tokio::test(flavor = "multi_thread")]` semantics.
pub(crate) fn run_on_deep_stack_multi_thread<F>(
    name: &'static str,
    body: impl FnOnce() -> F + Send + 'static,
) where
    F: Future<Output = ()>,
{
    run_on_deep_stack_with(name, RuntimeFlavor::MultiThread, body);
}

#[derive(Clone, Copy)]
enum RuntimeFlavor {
    CurrentThread,
    CurrentThreadPaused,
    MultiThread,
}

/// [`run_on_deep_stack`] for a test that needs `#[tokio::test(start_paused = true)]`
/// semantics.
pub(crate) fn run_on_deep_stack_paused<F>(
    name: &'static str,
    body: impl FnOnce() -> F + Send + 'static,
) where
    F: Future<Output = ()>,
{
    run_on_deep_stack_with(name, RuntimeFlavor::CurrentThreadPaused, body);
}

fn run_on_deep_stack_with<F>(
    name: &'static str,
    flavor: RuntimeFlavor,
    body: impl FnOnce() -> F + Send + 'static,
) where
    F: Future<Output = ()>,
{
    let joined = std::thread::Builder::new()
        .stack_size(DEEP_STACK_BYTES)
        .spawn(move || {
            let mut builder = match flavor {
                RuntimeFlavor::MultiThread => tokio::runtime::Builder::new_multi_thread(),
                RuntimeFlavor::CurrentThread | RuntimeFlavor::CurrentThreadPaused => {
                    tokio::runtime::Builder::new_current_thread()
                }
            };
            builder.enable_all();
            if matches!(flavor, RuntimeFlavor::CurrentThreadPaused) {
                builder.start_paused(true);
            }
            builder
                .build()
                .unwrap_or_else(|error| panic!("build the {name} test runtime: {error}"))
                .block_on(body());
        })
        .unwrap_or_else(|error| panic!("spawn the {name} test thread: {error}"))
        .join();
    // Re-raise the original payload so the assertion message libtest reports is
    // the one the test body produced, not a generic "thread panicked".
    if let Err(payload) = joined {
        std::panic::resume_unwind(payload);
    }
}
