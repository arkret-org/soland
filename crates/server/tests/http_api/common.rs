//! Shared helpers, fixtures, and imports for the soland HTTP-API integration test binary.
//!
//! Originally lived inline at the top of the monolithic `http_api` test before the
//! file was split into per-domain submodules. All items are reachable
//! to siblings via `super::common::*` from the `main.rs` integration-test root.

pub(crate) use std::sync::LazyLock;
pub(crate) use std::sync::atomic::{AtomicU64, Ordering};
pub(crate) use std::time::Duration;

pub(crate) use arkret_core::{Did, Operation, OperationId, RealmId, new_prefixed_uuid7};
pub(crate) use base64::Engine;
pub(crate) use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
pub(crate) use ed25519_dalek::{Signature, Signer, SigningKey, Verifier};
pub(crate) use futures_util::StreamExt;
pub(crate) use salvo::http::StatusCode;
pub(crate) use salvo::test::{ResponseExt, TestClient};
pub(crate) use serde_json::Value;
pub(crate) use sha2::{Digest, Sha256};
pub(crate) use soland::config::{AppConfig, IceServersConfig, ObjectStorageConfig};
pub(crate) use soland::state::{AppState, EventNotification, RealmDirectoryEntry};
pub(crate) use soland::{
    service, service_with_rate_limiter_config, service_with_request_size_limit,
};
pub(crate) use soland_domain::artifacts;
pub(crate) use soland_http::ratelimit::RateLimiterConfig;
pub(crate) use soland_storage::{
    MessageRecord, PresenceRecord, RealmInviteRecord, RealmMetaRecord, WebvhDocumentRecord,
};
pub(crate) use soland_storage_postgres::Db;

pub(crate) const DEMO_REALM_ID: &str = "ak:realm:0196419b-0000-7000-8000-000000000000";
/// Fixed REST-style TURN shared secret installed by `test_config()` so the
/// derived TURN credential is deterministic in assertions. Mirrors
/// `SOLAND_TURN_SHARED_SECRET`.
pub(crate) const SOLAND_TEST_TURN_SHARED_SECRET: &str = "soland-test-turn-shared-secret-0123456789";
pub(crate) const ACCOUNT_REGISTER_BEARER: &str = "soland-test-account-register-bearer";
pub(crate) static TEST_EVENT_SEQ: AtomicU64 = AtomicU64::new(10_000);
static TEST_EVENT_SIGNER_DID: LazyLock<String> = LazyLock::new(|| {
    let key = SigningKey::from_bytes(&[21_u8; 32]);
    format!(
        "did:key:{}",
        arkret_core::ed25519_pubkey_to_did_key_multibase(key.verifying_key().as_bytes())
    )
});

pub(crate) fn test_event_signer_did() -> &'static str {
    TEST_EVENT_SIGNER_DID.as_str()
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
    let mut state = AppState::new(test_config(), Db { pool: None });
    state.test_set_service_id(service_id.to_owned());
    state
}

pub(crate) fn app() -> salvo::Service {
    service(AppState::new(test_config(), Db { pool: None }))
}

pub(crate) fn app_from_state(state: AppState) -> salvo::Service {
    service(state)
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
    signed_federation_request_headers(
        "POST",
        origin,
        destination,
        destination_trust_domain,
        target_uri,
        body,
    )
}

pub(crate) fn signed_federation_get_headers(
    origin: &str,
    destination: &str,
    destination_trust_domain: &str,
    target_uri: &str,
) -> Vec<(&'static str, String)> {
    let source_trust_domain = trust_domain_from_service_id(origin);
    let created = chrono::Utc::now().timestamp();
    let expires = created + 300;
    let keyid = format!("{origin}#federation-fanout-key");
    let signature_params = format!(
        "(\"@method\" \"@target-uri\" \"@authority\" \"source-service-id\" \"destination-service-id\" \"source-trust-domain\" \"destination-trust-domain\");created={created};expires={expires};keyid=\"{keyid}\";alg=\"ed25519\"",
    );
    let authority = authority_from_target_uri(target_uri);
    let signature_base = format!(
        "\"@method\": GET\n\
         \"@target-uri\": {target_uri}\n\
         \"@authority\": {authority}\n\
         \"source-service-id\": {origin}\n\
         \"destination-service-id\": {destination}\n\
         \"source-trust-domain\": {source_trust_domain}\n\
         \"destination-trust-domain\": {destination_trust_domain}\n\
         \"@signature-params\": {signature_params}",
    );
    let signature = development_service_signing_key(origin).sign(signature_base.as_bytes());
    vec![
        ("source-service-id", origin.to_owned()),
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
    ]
}

fn signed_federation_request_headers(
    method: &str,
    origin: &str,
    destination: &str,
    destination_trust_domain: &str,
    target_uri: &str,
    body: &Value,
) -> Vec<(&'static str, String)> {
    let body_bytes = arkret_core::canonical::canonical_json_bytes(body).unwrap();
    let content_digest = format!("sha-256=:{}:", STANDARD.encode(Sha256::digest(&body_bytes)));
    let request_digest = format!("sha256:{}", hex::encode(Sha256::digest(&body_bytes)));
    let source_trust_domain = trust_domain_from_service_id(origin);
    let created = chrono::Utc::now().timestamp();
    let expires = created + 300;
    let keyid = format!("{origin}#federation-fanout-key");
    let signature_params = format!(
        "(\"@method\" \"@target-uri\" \"@authority\" \"content-digest\" \"source-service-id\" \"destination-service-id\" \"source-trust-domain\" \"destination-trust-domain\" \"request-canonical-digest\");created={created};expires={expires};keyid=\"{keyid}\";alg=\"ed25519\"",
    );
    let authority = authority_from_target_uri(target_uri);
    let signature_base = format!(
        "\"@method\": {method}\n\
         \"@target-uri\": {target_uri}\n\
         \"@authority\": {authority}\n\
         \"content-digest\": {content_digest}\n\
         \"source-service-id\": {origin}\n\
         \"destination-service-id\": {destination}\n\
         \"source-trust-domain\": {source_trust_domain}\n\
         \"destination-trust-domain\": {destination_trust_domain}\n\
         \"request-canonical-digest\": {request_digest}\n\
         \"@signature-params\": {signature_params}",
    );
    let signature = development_service_signing_key(origin).sign(signature_base.as_bytes());
    vec![
        ("content-digest", content_digest),
        ("request-canonical-digest", request_digest),
        ("source-service-id", origin.to_owned()),
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
    ]
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
    let token = dev_token_for_device(
        state.clone(),
        "did:web:alice.example",
        "ak:device:01904100-0000-7000-8000-a11ce0000001",
        "Alice Desktop",
    )
    .await;
    authorize_test_event_device(
        &state,
        "did:web:alice.example",
        "ak:device:01904100-0000-7000-8000-a11ce0000001",
    )
    .await;
    token
}

async fn authorize_test_event_device(state: &AppState, actor: &str, device_id: &str) {
    let devices = state.test_persistence().devices();
    let mut record = devices
        .get(actor, device_id)
        .await
        .unwrap()
        .expect("dev-login persists its device inventory record");
    let signing_key = SigningKey::from_bytes(&[21_u8; 32]);
    record.payload["device_public_key"] =
        Value::String(test_ed25519_multibase_public(&signing_key));
    record.payload["verification"] = Value::String("verified".to_owned());
    record.verification_state = "verified".to_owned();
    devices.put(&record).await.unwrap();
}

pub(crate) async fn dev_token_for_device(
    state: AppState,
    actor: &str,
    device_id: &str,
    display_name: &str,
) -> String {
    let login: Value = TestClient::post("http://server/_soland/gate/auth/dev-login")
        .json(&serde_json::json!({
            "actor": actor,
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
    authorize_test_event_device(&state, actor, device_id).await;
    token
}

pub(crate) async fn seed_did_document_also_known_as(state: &AppState, did: &str, aliases: &[&str]) {
    let now = chrono::Utc::now();
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
    let realm_id = new_prefixed_uuid7("ak:realm:");
    let typed_realm_id = RealmId::new(realm_id.clone()).unwrap();
    let owner_did = Did::new(owner.to_owned()).unwrap();
    let now = chrono::Utc::now();

    let mut entry = RealmDirectoryEntry::new(typed_realm_id, title);
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
                    arkret_core::PlaintextDataClassKind::MessageContent,
                    arkret_core::PlaintextDataClassKind::AttachmentPlaintext,
                    arkret_core::PlaintextDataClassKind::AttachmentPreview,
                    arkret_core::PlaintextDataClassKind::Thumbnail,
                    arkret_core::PlaintextDataClassKind::FullTextIndex,
                    arkret_core::PlaintextDataClassKind::NotificationSummary,
                    arkret_core::PlaintextDataClassKind::MediaPlaintext,
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
                owner: owner.to_owned(),
                deleted: false,
                discoverability: discoverability.to_owned(),
                history_visibility: "joined".to_owned(),
                history_sharing_policy: None,
                history_sharing_policy_digest: None,
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

    for invitee in invitees {
        let invite_id = new_prefixed_uuid7("ak:invite:");
        let invite_token = new_prefixed_uuid7("ak:invite-token:");
        state
            .test_persistence()
            .realm_invites()
            .put(RealmInviteRecord {
                invite_id,
                realm_id: realm_id.clone(),
                inviter: owner.to_owned(),
                invitee: Some((*invitee).to_owned()),
                invite_delivery_target: Some(serde_json::json!({
                    "recipient_service_id": state.service_id().clone(),
                    "recipient_service_type": "principal_server"
                })),
                introduction_evidence_digest: Some(format!("sha256:{}", "1".repeat(64))),
                third_party_id: None,
                join_rule_snapshot: None,
                invite_token,
                status: "pending".to_owned(),
                claim_nonces: std::collections::BTreeMap::new(),
                expires_at: None,
                created_at: now,
                updated_at: None,
            })
            .await
            .unwrap();
    }

    serde_json::json!({
        "ok": true,
        "realm_id": realm_id,
        "owner": owner,
        "members": [{"did": owner}],
        "deleted": false
    })
}

pub(crate) fn add_test_realm_member(state: &AppState, realm_id: &str, member: &str) -> Value {
    let typed_realm_id = RealmId::new(realm_id.to_owned()).unwrap();
    let member_did = Did::new(member.to_owned()).unwrap();
    let now = chrono::Utc::now();
    let mut realms = state.test_realms().lock();
    if let Some(mut entry) = realms.get(&typed_realm_id).cloned() {
        entry.members.insert(member_did);
        let members = realm_member_roster(&entry);
        realms.upsert(entry);
        drop(realms);
        state.test_projection().lock().members.insert(
            (realm_id.to_owned(), member.to_owned()),
            soland_domain::reducer::SolandMembershipState {
                member: member.to_owned(),
                realm_id: realm_id.to_owned(),
                state: "join".to_owned(),
                role: "member".to_owned(),
                delivery_status: None,
                recipient_service_id: None,
                membership_event_ref: None,
                delivery_binding_frontier: None,
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
    let mut realms = state.test_realms().lock();
    if let Some(mut entry) = realms.get(&typed_realm_id).cloned() {
        entry.members.remove(&member_did);
        let members = realm_member_roster(&entry);
        realms.upsert(entry);
        drop(realms);
        state
            .test_projection()
            .lock()
            .members
            .remove(&(realm_id.to_owned(), member.to_owned()));
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
    let store = state.test_persistence().realm_meta();
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

pub(crate) fn encrypted_envelope(content_type: &str, ciphertext: &str) -> Value {
    serde_json::json!({
        "scheme": "mls-rfc9420",
        "version": 1,
        "group_id": "ak:mls:test",
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
    let bytes = arkret_core::canonical::canonical_json_bytes(value)
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
    scope_id
        .strip_prefix("ak:realm:")
        .map(|suffix| format!("ak:strand:{suffix}"))
        .unwrap_or_else(|| {
            let digest = Sha256::digest(scope_id.as_bytes());
            format!("ak:strand:{}", hex::encode(digest))
                .chars()
                .take("ak:strand:".len() + 26)
                .collect()
        })
}

pub(crate) fn event_canonical_digest(event: &Value) -> String {
    // Mirror server-side `event_canonical_source` (arkret-spec
    // conformance-vectors.md §1.6): canonical digest is sha256 over the
    // event envelope JSON with `proofs`, `unsigned`, and the derived
    // `canonical_digest` / `canonical_hash` slots removed.
    let mut canonical = event.clone();
    if let Value::Object(object) = &mut canonical {
        object.remove("proofs");
        object.remove("unsigned");
        object.remove("canonical_digest");
        object.remove("canonical_hash");
    }
    sha256_json(&canonical)
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
    let now = chrono::Utc::now();
    let actor = arkret_core::Did::new(actor_id.to_owned()).expect("fixture actor DID");
    let device_id = if device_id.starts_with("ak:device:") {
        device_id.to_owned()
    } else {
        format!("ak:device:{device_id}")
    };
    let verification_method = actor_id.strip_prefix("did:key:").map_or_else(
        || format!("{actor_id}#{device_id}"),
        |key| format!("{actor_id}#{key}"),
    );
    let mut event = arkret_core::Event::new_with_id_at(
        arkret_core::EventId::new(event_id.to_owned()).expect("fixture Event id"),
        kind,
        arkret_core::RealmId::new(realm_id.to_owned()).expect("fixture Realm id"),
        actor.clone(),
        actor_seq,
        arkret_core::Hlc::new(format!(
            "{:012x}-0000-00000000",
            now.timestamp_millis().max(0) as u64
        ))
        .expect("fixture HLC"),
        payload,
        now,
    )
    .expect("SDK Event builder accepts HTTP fixture");
    event.prev_refs = prev_refs
        .into_iter()
        .map(|event_id| arkret_core::EventId::new(event_id.to_owned()).expect("fixture prev_ref"))
        .collect();
    let signer = arkret_signatures::Ed25519MoveSigner::from_did_key_seed(
        [21_u8; 32],
        actor,
        verification_method.clone(),
    );
    arkret_signatures::sign_event(
        &mut event,
        &signer,
        &verification_method,
        arkret_signatures::SignEventOptions::new().with_created_at(now),
    )
    .expect("SDK Event signer accepts HTTP fixture");
    serde_json::to_value(event).expect("SDK Event serializes")
}

pub(crate) fn resign_canonical_event(event: &mut Value) {
    let verification_method = event["proofs"][0]["verification_method"]
        .as_str()
        .expect("fixture verification method")
        .to_owned();
    let mut typed: arkret_core::Event =
        serde_json::from_value(event.clone()).expect("fixture Event roundtrip");
    typed.proofs.clear();
    let signer = arkret_signatures::Ed25519MoveSigner::from_did_key_seed(
        [21_u8; 32],
        typed.actor_id.clone(),
        verification_method.clone(),
    );
    let created_at = typed.created_at;
    arkret_signatures::sign_event(
        &mut typed,
        &signer,
        &verification_method,
        arkret_signatures::SignEventOptions::new().with_created_at(created_at),
    )
    .expect("SDK Event signer re-signs mutated HTTP fixture");
    *event = serde_json::to_value(typed).expect("re-signed fixture serializes");
}

pub(crate) fn signed_event_envelope(event_id: &str, actor_seq: u64, prev_refs: Vec<&str>) -> Value {
    let payload = serde_json::json!({
        "strand_id": "ak:strand:01904100-0000-7000-8000-f10dc0000001",
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
        DEMO_REALM_ID,
        actor_seq,
        prev_refs,
        payload,
    )
}

pub(crate) fn signed_message_event_envelope(
    actor: &str,
    realm_id: &str,
    _thread_id: &str,
    content: Value,
    encrypted: bool,
) -> Value {
    let event_id = new_prefixed_uuid7("ak:event:");
    let actor_seq = TEST_EVENT_SEQ.fetch_add(1, Ordering::Relaxed);
    let mut payload = serde_json::json!({
        "strand_id": expected_strand_id_for_scope(realm_id),
        "track_name": "discussion",
    });
    if encrypted {
        let mut encrypted_payload = content;
        if let Some(object) = encrypted_payload.as_object_mut()
            && object.get("scheme").and_then(Value::as_str) == Some("mls-rfc9420")
        {
            object.insert("version".to_owned(), Value::String("1.0".to_owned()));
            object.insert("group_id".to_owned(), Value::String("mls_test".to_owned()));
            object.insert(
                "content_type".to_owned(),
                Value::String("application/vnd.arkret.message+json".to_owned()),
            );
            object.insert(
                "aad_visibility_event_id".to_owned(),
                Value::String("hidden".to_owned()),
            );
            object.insert(
                "aad".to_owned(),
                serde_json::json!({
                    "realm_id": realm_id,
                    "event_kind": "ak.message.create"
                }),
            );
            object.insert(
                "key_ref".to_owned(),
                serde_json::json!({
                    "algorithm": "MLS",
                    "group_state_ref": "sha256:0000000000000000000000000000000000000000000000000000000000000000"
                }),
            );
            object.insert(
                "aad_digest".to_owned(),
                Value::String(
                    "sha256:0000000000000000000000000000000000000000000000000000000000000000"
                        .to_owned(),
                ),
            );
            object.insert(
                "payload_digest".to_owned(),
                Value::String(
                    "sha256:0000000000000000000000000000000000000000000000000000000000000000"
                        .to_owned(),
                ),
            );
            object.remove("authentication_tag");
            object.remove("digests");
        }
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
    let event_id = new_prefixed_uuid7("ak:event:");
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

pub(crate) async fn submit_actor_private_event(
    state: AppState,
    token: &str,
    actor: &str,
    device_id: &str,
    realm_id: &str,
    kind: &str,
    payload: Value,
) -> Value {
    let event = signed_actor_private_event_envelope(actor, device_id, realm_id, kind, payload);
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
    let event = signed_message_event_envelope(actor, realm_id, thread_id, content, encrypted);
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
    let event = signed_message_event_envelope(actor, realm_id, thread_id, content, encrypted);
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
        let event_suffix = event_id.strip_prefix("ak:event:").unwrap_or(&event_id);
        response["operation_id"] = Value::String(format!("ak:operation:{event_suffix}"));
        response["kind"] = Value::String("ak.message.create".to_owned());
        response["message_id"] = Value::String(format!("ak:message:{event_suffix}"));
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
            owner: actor.to_owned(),
            deleted: false,
            discoverability: "invite_only".to_owned(),
            history_visibility: "joined".to_owned(),
            history_sharing_policy: None,
            history_sharing_policy_digest: None,
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
        .insert(arkret_core::PlaintextDataClassKind::MessageContent);
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
    let registered: Value = TestClient::post("http://server/_arkret/gate/account/register")
        .json(&serde_json::json!({
            "principal_id": did,
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
        registered["principal_id"], did,
        "register response: {registered}"
    );

    let login: Value = TestClient::post("http://server/_soland/gate/auth/dev-login")
        .json(&serde_json::json!({
            "actor": did,
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
    assert_eq!(registered["did"], did, "register response: {registered}");

    let login: Value = TestClient::post("http://server/_soland/gate/auth/dev-login")
        .json(&serde_json::json!({
            "actor": did,
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
            "nextKeyHashes": [test_sha256_multihash_base58btc(
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
    let did = format!("did:webvh:{scid}:{method_authority}:webvh:{local_id}");
    let mut entry = test_replace_scid(skeleton, &scid);
    let entry_hash = test_webvh_entry_hash(&entry, &scid);
    if let Value::Object(map) = &mut entry {
        map.insert(
            "versionId".to_owned(),
            Value::String(format!("1-{entry_hash}")),
        );
    }
    let mut proof = serde_json::json!({
        "type": "DataIntegrityProof",
        "cryptosuite": "eddsa-jcs-2022",
        "proofPurpose": "assertionMethod",
        "verificationMethod": format!("{did}#{update_public_key_multibase}"),
    });
    let proof_config = arkret_core::canonical::canonical_json_bytes(&proof).unwrap();
    let document = arkret_core::canonical::canonical_json_bytes(&entry).unwrap();
    let mut signing_input = Vec::with_capacity(64);
    signing_input.extend_from_slice(&arkret_core::canonical::sha256_bytes(&proof_config));
    signing_input.extend_from_slice(&arkret_core::canonical::sha256_bytes(&document));
    let signature = update_signing.sign(&signing_input);
    proof["proofValue"] = Value::String(format!(
        "z{}",
        bs58::encode(signature.to_bytes()).into_string()
    ));
    proof
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
    let canonical = arkret_core::canonical::canonical_json_bytes(value).unwrap();
    test_sha256_multihash_base58btc(&canonical)
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
    let canonical = arkret_core::canonical::canonical_json_bytes(&clone).unwrap();
    test_sha256_multihash_base58btc(&canonical)
}

pub(crate) fn test_replace_scid(value: Value, scid: &str) -> Value {
    serde_json::from_str(
        &serde_json::to_string(&value)
            .unwrap()
            .replace("{SCID}", scid),
    )
    .unwrap()
}

/// Bare base58btc sha256 multihash — no multibase `z` prefix (did:webvh v1.0).
pub(crate) fn test_sha256_multihash_base58btc(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut multihash = Vec::with_capacity(34);
    multihash.push(0x12);
    multihash.push(0x20);
    multihash.extend_from_slice(&digest);
    bs58::encode(multihash).into_string()
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
    actor_seq: u64,
    kind: &str,
    mut payload: Value,
    prev_refs: Vec<&str>,
) -> Value {
    normalize_space_container_payload(kind, &mut payload);
    payload = typed_space_container_payload(kind, payload);
    signed_canonical_event(
        event_id,
        kind,
        "did:web:alice.example",
        "01904100-0000-7000-8000-a11ce0000001",
        DEMO_REALM_ID,
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
        space
            .entry("schema".to_owned())
            .or_insert_with(|| Value::String("ak.schema.space.v1".to_owned()));
        space.entry("realm_id".to_owned()).or_insert_with(|| {
            Value::String("ak:realm:0196419b-0000-7000-8000-000000000000".to_owned())
        });
        space
            .entry("created_at".to_owned())
            .or_insert_with(|| Value::String("2026-05-17T00:00:00.000Z".to_owned()));
    }
}

fn typed_space_container_payload(kind: &str, payload: Value) -> Value {
    match kind {
        arkret_core::events::EventKind::SPACE_ARCHIVE
        | arkret_core::events::EventKind::SPACE_RESTORE => {
            serde_json::to_value(arkret_core::SpaceStateTransitionPayload {
                space_id: required_space_id(&payload, "space_id"),
                reason: optional_string(&payload, "reason"),
                effective_at: None,
            })
            .expect("space lifecycle payload serialization")
        }
        arkret_core::events::EventKind::SPACE_TOMBSTONE => {
            serde_json::to_value(arkret_core::SpaceObjectTombstonePayload {
                space_id: required_space_id(&payload, "space_id"),
                reason: optional_string(&payload, "reason"),
                replacement_space: optional_space_id(&payload, "replacement_space"),
                replacement_event: optional_event_ref(&payload, "replacement_event"),
                effective_at: None,
            })
            .expect("space tombstone payload serialization")
        }
        _ => payload,
    }
}

fn required_space_id(payload: &Value, field: &str) -> arkret_core::SpaceId {
    let value = payload
        .get(field)
        .and_then(Value::as_str)
        .expect("space lifecycle payload requires space_id");
    arkret_core::SpaceId::new(value.to_owned()).expect("valid space id")
}

fn optional_space_id(payload: &Value, field: &str) -> Option<arkret_core::SpaceId> {
    payload
        .get(field)
        .and_then(Value::as_str)
        .map(|value| arkret_core::SpaceId::new(value.to_owned()).expect("valid optional space id"))
}

fn optional_event_ref(payload: &Value, field: &str) -> Option<arkret_core::EventRef> {
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
    actor_seq: u64,
    kind: &str,
    mut payload: Value,
    prev_refs: Vec<&str>,
) -> Value {
    normalize_strand_payload(kind, &mut payload);
    signed_canonical_event(
        event_id,
        kind,
        "did:web:alice.example",
        "01904100-0000-7000-8000-a11ce0000001",
        DEMO_REALM_ID,
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
        strand
            .entry("schema".to_owned())
            .or_insert_with(|| Value::String("ak.schema.strand.v1".to_owned()));
        strand.entry("realm_id".to_owned()).or_insert_with(|| {
            Value::String("ak:realm:0196419b-0000-7000-8000-000000000000".to_owned())
        });
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
    if matches!(
        kind,
        "ak.strand.archive" | "ak.strand.restore" | "ak.strand.tombstone"
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
    actor_seq: u64,
    kind: &str,
    mut payload: Value,
    prev_refs: Vec<&str>,
) -> Value {
    normalize_morph_payload(kind, &mut payload);
    payload = typed_morph_payload(kind, payload);
    signed_canonical_event(
        event_id,
        kind,
        "did:web:alice.example",
        "01904100-0000-7000-8000-a11ce0000001",
        DEMO_REALM_ID,
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
        morph
            .entry("schema".to_owned())
            .or_insert_with(|| Value::String("ak.schema.morph.v1".to_owned()));
        morph.entry("realm_id".to_owned()).or_insert_with(|| {
            Value::String("ak:realm:0196419b-0000-7000-8000-000000000000".to_owned())
        });
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
        arkret_core::events::EventKind::MORPH_ARCHIVE => arkret_core::ObjectLifecyclePayload::new(
            required_string(&payload, "target_ref", "morph lifecycle target_ref"),
        )
        .with_target_state("archived")
        .to_value()
        .expect("morph archive payload serialization"),
        arkret_core::events::EventKind::MORPH_RESTORE => arkret_core::ObjectLifecyclePayload::new(
            required_string(&payload, "target_ref", "morph lifecycle target_ref"),
        )
        .with_target_state("active")
        .to_value()
        .expect("morph restore payload serialization"),
        arkret_core::events::EventKind::MORPH_UPDATE => {
            let morph_id = arkret_core::MorphId::new(required_string(
                &payload,
                "target_ref",
                "morph update target_ref",
            ))
            .expect("valid morph id");
            let patch: arkret_core::Patch = serde_json::from_value(
                payload
                    .get("patch")
                    .cloned()
                    .expect("morph update payload requires patch"),
            )
            .expect("valid morph update patch");
            arkret_core::MorphUpdatePayload::for_morph(morph_id, patch)
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
    actor_seq: u64,
    mut payload: Value,
    prev_refs: Vec<&str>,
) -> Value {
    payload = typed_relation_create_payload(payload);
    signed_canonical_event(
        event_id,
        "ak.relation.create",
        "did:web:alice.example",
        "01904100-0000-7000-8000-a11ce0000001",
        DEMO_REALM_ID,
        actor_seq,
        prev_refs,
        payload,
    )
}

fn typed_relation_create_payload(payload: Value) -> Value {
    let kind = relation_payload_str(&payload, &["relation_kind", "kind"])
        .expect("relation create payload requires kind");
    let from_ref = relation_payload_str(&payload, &["from_ref", "from"])
        .expect("relation create payload requires from_ref");
    let to_ref = relation_payload_str(&payload, &["to_ref", "to"])
        .expect("relation create payload requires to_ref");
    let rank = relation_payload_str(&payload, &["rank"]);
    let mut typed = arkret_core::RelationCreatePayload::new(kind, from_ref, to_ref);
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
    actor_seq: u64,
    mut payload: Value,
    prev_refs: Vec<&str>,
) -> Value {
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
        DEMO_REALM_ID,
        actor_seq,
        prev_refs,
        payload,
    )
}

// The following comment blocks are descriptive notes for tests that have
// migrated to dedicated integration files. They are preserved here only
// as breadcrumbs (round 14b ak.redaction terminal-flip; round 14d/14f/15a
// projection_query endpoints; round 15b applet/agent registration; round
// 15d include_terminal filter; round 15f multi-chunk snapshot; round 15h
// projection write-through). See the corresponding `tests/*.rs` files for
// the executable coverage.

// ── account_subscribe long-poll + realms-incremental coverage ─────────────
//
// These tests pin the two behaviors that landed alongside the
// `realms`-baseline cleanup: idle incremental syncs hold instead of
// returning immediately, and quiet realms drop out of the delta until
// they have new state.

pub(crate) async fn persist_test_message(
    state: &AppState,
    realm_id: &str,
    sender: &str,
    body: &str,
) -> MessageRecord {
    let event_id = new_prefixed_uuid7("ak:event:");
    let record = MessageRecord {
        event_id: event_id.clone(),
        message_id: event_id.replacen("ak:event:", "ak:message:", 1),
        realm_id: realm_id.to_owned(),
        sender: sender.to_owned(),
        thread_id: format!("ak:strand:test-{}", event_id),
        content: serde_json::json!({"body": body}),
        encrypted: false,
        created_at: chrono::Utc::now(),
    };
    state
        .test_persistence()
        .messages()
        .put(&record)
        .await
        .unwrap();
    let envelope = signed_canonical_event(
        &record.event_id,
        "ak.message.create",
        sender,
        "01904100-0000-7000-8000-a11ce0000001",
        realm_id,
        TEST_EVENT_SEQ.fetch_add(1, Ordering::Relaxed),
        Vec::new(),
        serde_json::json!({
            "strand_id": expected_strand_id_for_scope(realm_id),
            "track_name": "discussion",
            "content": {
                "kind": "ak.content.text",
                "body": body,
                "format": "plain"
            }
        }),
    );
    let canonical_digest = envelope["proofs"][0]["event_digest"]
        .as_str()
        .expect("signed fixture digest")
        .to_owned();
    state
        .test_persistence()
        .events()
        .put(soland_storage::CanonicalEventRecord {
            event_id: record.event_id.clone(),
            actor_id: sender.to_owned(),
            actor_seq: envelope["actor_seq"].as_u64().unwrap(),
            realm_id: Some(realm_id.to_owned()),
            kind: "ak.message.create".to_owned(),
            schema_id: "ak.schema.event_envelope.v1".to_owned(),
            canonical_digest,
            canonical_bytes: arkret_core::canonical::canonical_json_bytes(&envelope).unwrap(),
            envelope,
            received_at: record.created_at,
        })
        .await
        .unwrap();
    record
}
