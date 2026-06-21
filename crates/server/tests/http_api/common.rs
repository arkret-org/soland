//! Shared helpers, fixtures, and imports for the soland HTTP-API integration test binary.
//!
//! Originally lived inline at the top of `tests/http_api.rs` before the
//! file was split into per-domain submodules. All items are reachable
//! to siblings via `super::common::*` (re-exported by `http_api.rs`).

#![allow(dead_code)]

pub(crate) use std::sync::atomic::{AtomicU64, Ordering};
pub(crate) use std::time::Duration;

pub(crate) use base64::Engine;
pub(crate) use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
pub(crate) use cokret_sdk::{Did, Operation, OperationId, RealmId, new_prefixed_uuid7};
pub(crate) use ed25519_dalek::{Signature, Signer, SigningKey, Verifier};
pub(crate) use salvo::http::StatusCode;
pub(crate) use salvo::test::{ResponseExt, TestClient};
pub(crate) use serde_json::Value;
pub(crate) use sha2::{Digest, Sha256};
pub(crate) use soland::config::{AppConfig, IceServersConfig, LiveKitConfig, ObjectStorageConfig};
pub(crate) use soland::db::Db;
pub(crate) use soland::ratelimit::RateLimiterConfig;
pub(crate) use soland::state::{
    AppState, EventNotification, MessageRecord, PresenceRecord, RealmDirectoryEntry,
    RealmInviteRecord, RealmMetaRecord,
};
pub(crate) use soland::{
    artifacts, service, service_with_rate_limiter_config, service_with_request_size_limit,
};

pub(crate) const DEMO_REALM_ID: &str = "ck:realm:0196419b-0000-7000-8000-000000000000";
/// Fixed REST-style TURN shared secret installed by `test_config()` so the
/// derived TURN credential is deterministic in assertions. Mirrors
/// `SOLAND_TURN_SHARED_SECRET`.
pub(crate) const SOLAND_TEST_TURN_SHARED_SECRET: &str = "soland-test-turn-shared-secret-0123456789";
pub(crate) static TEST_EVENT_SEQ: AtomicU64 = AtomicU64::new(10_000);
pub(crate) fn test_config() -> AppConfig {
    AppConfig {
        bind: "127.0.0.1:0".parse().unwrap(),
        metrics_bind: "127.0.0.1:0".parse().unwrap(),
        public_base_url: "http://server".to_owned(),
        service_did: "did:web:soland.local".to_owned(),
        tls_cert_path: None,
        tls_key_path: None,
        database_url: None,
        object_storage: ObjectStorageConfig::local(std::env::temp_dir().join("soland-test-blobs")),
        ice: IceServersConfig {
            // `webrtc-signaling.md` §4.1 — fix the REST-style TURN shared secret
            // so the derived credential is deterministic for assertions.
            turn_shared_secret: Some(SOLAND_TEST_TURN_SHARED_SECRET.to_owned()),
            ..IceServersConfig::default()
        },
        livekit: LiveKitConfig::default(),
        cors_allow_origin: None,
        account_authority_url: None,
        oidc_client_id: None,
        development_mode: true,
        session_grant_introspection_url: None,
        session_grant_introspection_bearer: None,
        did_resolver_allow_methods: vec!["web".to_owned(), "key".to_owned(), "uuid".to_owned()],
        embedded_webvh_provider_enabled: false,
        embedded_webvh_registration_bearer: None,
        external_webvh_provider_url: None,
        external_webvh_provider_active: false,
        default_webvh_provider_id: None,
        // Tests use fixed-time HLC fixtures; window=0 disables replay-window
        // enforcement so they keep passing.
        jws_replay_window_seconds: 0,
        jws_replay_window_per_family: std::collections::BTreeMap::new(),
        notary_signing_key_seed: None,
        agent_audit_binding_signing_seed: None,
        use_keystore: false,
        federation_policy: soland::config::FederationPolicy::Mesh,
        federation_peers: Vec::new(),
        federation_outbound_enabled: false,
        admin_default_page_limit: 100,
        admin_max_page_limit: 1000,
        admin_principal_dids: Vec::new(),
        to_device_queue_capacity: 10_000,
        push_bridge_cache_ttl_seconds: 900,
        push_bridge_trusted_service_dids: Vec::new(),
        resumable_upload_dir: std::env::temp_dir().join("soland-test-resumable-uploads"),
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
        erasure_propagation_window_ms: 604_800_000,
        log_format: soland::config::LogFormat::Plain,
    }
}

pub(crate) fn test_config_with_service_did(service_did: &str) -> AppConfig {
    AppConfig {
        service_did: service_did.to_owned(),
        ..test_config()
    }
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
        "http://server/_cokret/self/account/subscribe".to_owned()
    } else {
        format!("http://server/_cokret/self/account/subscribe?{query}")
    };
    let mut request = TestClient::get(url);
    if let Some(token) = token {
        request = request.add_header("authorization", format!("Bearer {token}"), true);
    }
    let body = request
        .send(&app_from_state(state))
        .await
        .take_string()
        .await
        .unwrap();
    serde_json::from_str(body.lines().next().unwrap()).unwrap()
}

pub(crate) fn decode_cursor(token: &str) -> Value {
    let encoded = token
        .strip_prefix("ck:cursor:")
        .expect("structured cursor prefix");
    let bytes = URL_SAFE_NO_PAD.decode(encoded).expect("base64url cursor");
    serde_json::from_slice(&bytes).expect("cursor json")
}

pub(crate) fn encode_cursor(cursor: &Value) -> String {
    format!("ck:cursor:{}", URL_SAFE_NO_PAD.encode(cursor.to_string()))
}

pub(crate) fn signed_federation_push_headers(
    origin: &str,
    destination: &str,
    target_uri: &str,
    body: &Value,
) -> Vec<(&'static str, String)> {
    signed_federation_request_headers("POST", origin, destination, target_uri, body)
}

pub(crate) fn signed_federation_transaction_headers(
    origin: &str,
    destination: &str,
    target_uri: &str,
    body: &Value,
) -> Vec<(&'static str, String)> {
    signed_federation_request_headers("PUT", origin, destination, target_uri, body)
}

pub(crate) fn signed_federation_get_headers(
    origin: &str,
    destination: &str,
    target_uri: &str,
) -> Vec<(&'static str, String)> {
    let source_trust_domain = trust_domain_from_service_did(origin);
    let destination_trust_domain = trust_domain_from_service_did(destination);
    let created = chrono::Utc::now().timestamp();
    let expires = created + 300;
    let keyid = format!("{origin}#federation-fanout-key");
    let signature_params = format!(
        "(\"@method\" \"@target-uri\" \"@authority\" \"source-service-did\" \"destination-service-did\" \"source-trust-domain\" \"destination-trust-domain\");created={created};expires={expires};keyid=\"{keyid}\";alg=\"ed25519\"",
    );
    let authority = authority_from_target_uri(target_uri);
    let signature_base = format!(
        "\"@method\": GET\n\
         \"@target-uri\": {target_uri}\n\
         \"@authority\": {authority}\n\
         \"source-service-did\": {origin}\n\
         \"destination-service-did\": {destination}\n\
         \"source-trust-domain\": {source_trust_domain}\n\
         \"destination-trust-domain\": {destination_trust_domain}\n\
         \"@signature-params\": {signature_params}",
    );
    let signature = development_service_signing_key(origin).sign(signature_base.as_bytes());
    vec![
        ("source-service-did", origin.to_owned()),
        ("destination-service-did", destination.to_owned()),
        ("source-trust-domain", source_trust_domain),
        ("destination-trust-domain", destination_trust_domain),
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
    target_uri: &str,
    body: &Value,
) -> Vec<(&'static str, String)> {
    let body_bytes = cokret_sdk::canonical::canonical_json_bytes(body).unwrap();
    let content_digest = format!("sha-256=:{}:", STANDARD.encode(Sha256::digest(&body_bytes)));
    let request_digest = format!("sha256:{}", hex::encode(Sha256::digest(&body_bytes)));
    let source_trust_domain = trust_domain_from_service_did(origin);
    let destination_trust_domain = trust_domain_from_service_did(destination);
    let created = chrono::Utc::now().timestamp();
    let expires = created + 300;
    let keyid = format!("{origin}#federation-fanout-key");
    let signature_params = format!(
        "(\"@method\" \"@target-uri\" \"@authority\" \"content-digest\" \"source-service-did\" \"destination-service-did\" \"source-trust-domain\" \"destination-trust-domain\" \"request-canonical-digest\");created={created};expires={expires};keyid=\"{keyid}\";alg=\"ed25519\"",
    );
    let authority = authority_from_target_uri(target_uri);
    let signature_base = format!(
        "\"@method\": {method}\n\
         \"@target-uri\": {target_uri}\n\
         \"@authority\": {authority}\n\
         \"content-digest\": {content_digest}\n\
         \"source-service-did\": {origin}\n\
         \"destination-service-did\": {destination}\n\
         \"source-trust-domain\": {source_trust_domain}\n\
         \"destination-trust-domain\": {destination_trust_domain}\n\
         \"request-canonical-digest\": {request_digest}\n\
         \"@signature-params\": {signature_params}",
    );
    let signature = development_service_signing_key(origin).sign(signature_base.as_bytes());
    vec![
        ("content-digest", content_digest),
        ("request-canonical-digest", request_digest),
        ("source-service-did", origin.to_owned()),
        ("destination-service-did", destination.to_owned()),
        ("source-trust-domain", source_trust_domain),
        ("destination-trust-domain", destination_trust_domain),
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

pub(crate) fn development_service_signing_key(service_did: &str) -> SigningKey {
    let mut hasher = Sha256::new();
    hasher.update(b"soland:notary-ephemeral:");
    hasher.update(service_did.as_bytes());
    let seed: [u8; 32] = hasher.finalize().into();
    SigningKey::from_bytes(&seed)
}

pub(crate) fn trust_domain_from_service_did(service_did: &str) -> String {
    let scope = service_did
        .strip_prefix("did:web:")
        .or_else(|| service_did.strip_prefix("did:key:"))
        .or_else(|| service_did.strip_prefix("did:webvh:"))
        .unwrap_or(service_did)
        .to_ascii_lowercase()
        .replace(':', ".");
    format!("ck:trust_domain:{scope}")
}

pub(crate) async fn dev_token(state: AppState) -> String {
    dev_token_for_device(
        state,
        "did:web:alice.example",
        "ck:device:01904100-0000-7000-8000-a11ce0000001",
        "Alice Desktop",
    )
    .await
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

pub(crate) async fn seed_test_realm(
    state: &AppState,
    owner: &str,
    title: &str,
    summary: Option<&str>,
    discoverability: &str,
    plaintext_visible_services: &[&str],
    invitees: &[&str],
) -> Value {
    let realm_id = new_prefixed_uuid7("ck:realm:");
    let typed_realm_id = RealmId::new(realm_id.clone()).unwrap();
    let owner_did = Did::new(owner.to_owned()).unwrap();
    let now = chrono::Utc::now();

    let mut entry = RealmDirectoryEntry::new(typed_realm_id, title);
    entry.description = summary.map(ToOwned::to_owned);
    entry.public = discoverability == "public";
    entry.members.insert(owner_did);
    state.realms.lock().unwrap().upsert(entry);

    let plaintext_visible_services = plaintext_visible_services
        .iter()
        .map(|value| (*value).to_owned())
        .collect();
    state
        .persistence
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
                encryption_profile: None,
                plaintext_visible_services,
                minimal_metadata_realm: false,
                created_at: now,
                updated_at: now,
            },
        )
        .await
        .unwrap();

    for invitee in invitees {
        let invite_id = new_prefixed_uuid7("ck:invite:");
        let invite_token = new_prefixed_uuid7("ck:invite-token:");
        state
            .persistence
            .realm_invites()
            .put(RealmInviteRecord {
                invite_id,
                realm_id: realm_id.clone(),
                inviter: owner.to_owned(),
                invitee: Some((*invitee).to_owned()),
                invite_delivery_target: Some(serde_json::json!({
                    "recipient_service_did": state.config.service_did.clone(),
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
    let mut realms = state.realms.lock().unwrap();
    if let Some(mut entry) = realms.get(&typed_realm_id).cloned() {
        entry.members.insert(member_did);
        let members = realm_member_roster(&entry);
        realms.upsert(entry);
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
    let mut realms = state.realms.lock().unwrap();
    if let Some(mut entry) = realms.get(&typed_realm_id).cloned() {
        entry.members.remove(&member_did);
        let members = realm_member_roster(&entry);
        realms.upsert(entry);
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
    // HDLREN-4/5 (cokret-spec @ 7157ee8) — roster rows MUST NOT carry
    // `handle` / `handle_uri` directly; identity is resolved through the
    // `ck.member.identity.update` events surfaced via
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
    let store = state.persistence.realm_meta();
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
        "group_id": "ck:mls:test",
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
    let bytes = cokret_sdk::canonical::canonical_json_bytes(value)
        .unwrap_or_else(|_| serde_json::to_vec(value).unwrap());
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

pub(crate) fn expected_strand_id_for_scope(scope_id: &str) -> String {
    scope_id
        .strip_prefix("ck:realm:")
        .map(|suffix| format!("ck:strand:{suffix}"))
        .unwrap_or_else(|| {
            let digest = Sha256::digest(scope_id.as_bytes());
            format!("ck:strand:{}", hex::encode(digest))
                .chars()
                .take("ck:strand:".len() + 26)
                .collect()
        })
}

pub(crate) fn event_canonical_digest(event: &Value) -> String {
    // Mirror server-side `event_canonical_source` (cokret-spec
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

pub(crate) fn signed_event_envelope(event_id: &str, actor_seq: u64, prev_refs: Vec<&str>) -> Value {
    let payload = serde_json::json!({
        "strand_id": "ck:strand:01904100-0000-7000-8000-f10dc0000001",
        "track_name": "discussion",
        "content": {
            "kind": "ck.content.text",
            "body": format!("event body {actor_seq}"),
            "format": "plain"
        }
    });
    let mut event = serde_json::json!({
        "event_id": event_id,
        "kind": "ck.message.create",
        "schema_id": "ck.schema.message.v1",
        "actor_id": "did:web:alice.example",
        "actor_seq": actor_seq,
        "realm_id": "ck:realm:0196419b-0000-7000-8000-000000000000",
        "device_id": "ck:device:01904100-0000-7000-8000-a11ce0000001",
        "audience": "did:web:soland.local",
        "domain": "did:web:soland.local",
        "prev_refs": prev_refs,
        "auth_refs": [],
        "payload": payload.clone(),
        "proofs": [{
            "type": "dev-proof",
            "verification_method": "did:web:alice.example#01904100-0000-7000-8000-a11ce0000001",
            "device_id": "ck:device:01904100-0000-7000-8000-a11ce0000001",
            "audience": "did:web:soland.local",
            "domain": "did:web:soland.local",
            "payload_digest": sha256_json(&payload)
        }]
    });
    event["canonical_digest"] = Value::String(event_canonical_digest(&event));
    event
}

pub(crate) fn signed_message_event_envelope(
    actor: &str,
    realm_id: &str,
    _thread_id: &str,
    content: Value,
    encrypted: bool,
) -> Value {
    let event_id = new_prefixed_uuid7("ck:event:");
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
                Value::String("application/vnd.cokret.message+json".to_owned()),
            );
            object.insert(
                "aad_visibility_event_id".to_owned(),
                Value::String("hidden".to_owned()),
            );
            object.insert(
                "aad".to_owned(),
                serde_json::json!({
                    "realm_id": realm_id,
                    "event_kind": "ck.message.create"
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
                Value::String("ck.content.text".to_owned()),
            );
        }
        payload["content"] = content;
    }
    let mut event = serde_json::json!({
        "event_id": event_id,
        "kind": "ck.message.create",
        "schema_id": "ck.schema.message.v1",
        "actor_id": actor,
        "actor_seq": actor_seq,
        "realm_id": realm_id,
        "device_id": "ck:device:01904100-0000-7000-8000-a11ce0000001",
        "audience": "did:web:soland.local",
        "domain": "did:web:soland.local",
        "prev_refs": [],
        "auth_refs": [],
        "payload": payload,
        "proofs": [{
            "type": "dev-proof",
            "verification_method": format!("{actor}#01904100-0000-7000-8000-a11ce0000001"),
            "device_id": "ck:device:01904100-0000-7000-8000-a11ce0000001",
            "audience": "did:web:soland.local",
            "domain": "did:web:soland.local",
            "payload_digest": sha256_json(&payload)
        }]
    });
    event["canonical_digest"] = Value::String(event_canonical_digest(&event));
    event
}

pub(crate) fn signed_actor_private_event_envelope(
    actor: &str,
    device_id: &str,
    realm_id: &str,
    kind: &str,
    payload: Value,
) -> Value {
    let mut event = serde_json::json!({
        "event_id": new_prefixed_uuid7("ck:event:"),
        "kind": kind,
        "schema_id": "ck.schema.event.v1",
        "actor_id": actor,
        "actor_seq": TEST_EVENT_SEQ.fetch_add(1, Ordering::Relaxed),
        "realm_id": realm_id,
        "device_id": device_id,
        "audience": "did:web:soland.local",
        "domain": "did:web:soland.local",
        "prev_refs": [],
        "auth_refs": [],
        "payload": payload,
        "proofs": [{
            "type": "dev-proof",
            "verification_method": format!("{actor}#{device_id}"),
            "device_id": device_id,
            "audience": "did:web:soland.local",
            "domain": "did:web:soland.local",
            "payload_digest": sha256_json(&payload)
        }]
    });
    event["canonical_digest"] = Value::String(event_canonical_digest(&event));
    event
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
    TestClient::post("http://server/_cokret/self/events")
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
    TestClient::post("http://server/_cokret/self/events")
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
    let event = signed_message_event_envelope(actor, realm_id, thread_id, content, encrypted);
    let mut response: Value = TestClient::post("http://server/_cokret/self/events")
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
        let event_suffix = event_id.strip_prefix("ck:event:").unwrap_or(&event_id);
        response["operation_id"] = Value::String(format!("ck:operation:{event_suffix}"));
        response["kind"] = Value::String("ck.message.create".to_owned());
        response["message_id"] = Value::String(format!("ck:message:{event_suffix}"));
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

pub(crate) async fn register_account(
    state: AppState,
    did: &str,
    handle: &str,
    device_id: &str,
) -> String {
    let registered: Value = TestClient::post("http://server/_cokret/gate/account/register")
        .json(&serde_json::json!({
            "principal_id": did,
            "display_name": handle.trim_start_matches('@'),
            "device_id": device_id
        }))
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

// T6.1 — describe response partitioning, T1.4 — dev-mode posture surface,
// and T8.3 — hardening block. The test fixtures for these checks live in
// the http_api integration suite and are exercised via the helpers below.

// MIMI facade writes map into the canonical Cokret reducer chain via the
// four reducer-bound mappings: room_update, submit_message, notify, and
// report_abuse. See the live test suite for the executable coverage.

pub(crate) fn test_ed25519_multibase_public(signing: &SigningKey) -> String {
    let mut bytes = Vec::with_capacity(34);
    bytes.extend_from_slice(&[0xed, 0x01]);
    bytes.extend_from_slice(signing.verifying_key().as_bytes());
    format!("z{}", bs58::encode(bytes).into_string())
}

pub(crate) fn test_embedded_webvh_proof(
    principal_server_url: &str,
    local_id: &str,
    did_public_key_multibase: &str,
    update_public_key_multibase: &str,
    did_key_fragment: &str,
    update_signing: &SigningKey,
    version_time: &str,
) -> Value {
    let method_authority = test_webvh_method_authority(principal_server_url);
    let placeholder_did = format!("did:webvh:{{SCID}}:{method_authority}:webvh:{local_id}");
    let did_key_id = format!("{placeholder_did}#{did_key_fragment}");
    let skeleton = serde_json::json!({
        "versionId": "0-{SCID}",
        "versionTime": version_time,
        "parameters": {
            "scid": "{SCID}",
            "method": "did:webvh:1.0",
            "updateKeys": [update_public_key_multibase],
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
                "type": "CokretPrincipalServer",
                "serviceEndpoint": principal_server_url.trim_end_matches('/'),
            }],
        },
    });
    let scid = test_scid(&skeleton);
    let did = format!("did:webvh:{scid}:{method_authority}:webvh:{local_id}");
    let mut entry = test_replace_scid(skeleton, &scid);
    let entry_hash = test_webvh_entry_hash(&entry);
    if let Value::Object(map) = &mut entry {
        map.insert(
            "versionId".to_owned(),
            Value::String(format!("1-{entry_hash}")),
        );
    }
    let payload = cokret_sdk::canonical::canonical_json_bytes(&entry).unwrap();
    let signature = update_signing.sign(&payload);
    serde_json::json!({
        "type": "DataIntegrityProof",
        "cryptosuite": "eddsa-jcs-2022",
        "proofPurpose": "authentication",
        "verificationMethod": format!("{did}#{update_public_key_multibase}"),
        "proofValue": format!("z{}", bs58::encode(signature.to_bytes()).into_string()),
    })
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
    let canonical = cokret_sdk::canonical::canonical_json_bytes(value).unwrap();
    test_sha256_multihash_multibase(&canonical)
}

pub(crate) fn test_webvh_entry_hash(value: &Value) -> String {
    let mut clone = value.clone();
    if let Value::Object(map) = &mut clone {
        map.remove("proof");
        map.remove("versionId");
    }
    let canonical = cokret_sdk::canonical::canonical_json_bytes(&clone).unwrap();
    test_sha256_multihash_multibase(&canonical)
}

pub(crate) fn test_replace_scid(value: Value, scid: &str) -> Value {
    serde_json::from_str(
        &serde_json::to_string(&value)
            .unwrap()
            .replace("{SCID}", scid),
    )
    .unwrap()
}

pub(crate) fn test_sha256_multihash_multibase(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut multihash = Vec::with_capacity(34);
    multihash.push(0x12);
    multihash.push(0x20);
    multihash.extend_from_slice(&digest);
    format!("z{}", bs58::encode(multihash).into_string())
}

// `standard_entity_types_and_reverse_domain_custom_types_work` and
// `view_endpoints_project_common_presentation_shapes` were deleted in
// round 6: the `entity` / `view` abstraction they exercised never landed in
// `cokret-spec/v1`. Typed objects in the protocol are `ck:strand:` / `ck:space:`
// / `ck:morph:` / `ck:relation:` / `ck:view:`, each with its own dedicated
// event kind; presentation concerns belong on `ck.view.*` events going
// through the reducer, not on a free-form `/_cokret/self/entities` /
// `/_cokret/self/views` scaffold.

/// Build a signed container `ck.space.*` event envelope for the Space
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
    let mut event = serde_json::json!({
        "event_id": event_id,
        "kind": kind,
        "schema_id": "ck.schema.space.v1",
        "actor_id": "did:web:alice.example",
        "actor_seq": actor_seq,
        "realm_id": "ck:realm:0196419b-0000-7000-8000-000000000000",
        "created_at": "2026-05-17T00:00:00Z",
        "device_id": "ck:device:01904100-0000-7000-8000-a11ce0000001",
        "audience": "did:web:soland.local",
        "domain": "did:web:soland.local",
        "prev_refs": prev_refs,
        "auth_refs": [],
        "payload": payload.clone(),
        "proofs": [{
            "type": "dev-proof",
            "verification_method": "did:web:alice.example#01904100-0000-7000-8000-a11ce0000001",
            "device_id": "ck:device:01904100-0000-7000-8000-a11ce0000001",
            "audience": "did:web:soland.local",
            "domain": "did:web:soland.local",
            "payload_digest": sha256_json(&payload)
        }]
    });
    event["canonical_digest"] = Value::String(event_canonical_digest(&event));
    event
}

pub(crate) fn normalize_space_container_payload(kind: &str, payload: &mut Value) {
    let Some(object) = payload.as_object_mut() else {
        return;
    };
    if kind == "ck.space.create" {
        if let Some(space) = object.get_mut("object").and_then(Value::as_object_mut) {
            space
                .entry("schema".to_owned())
                .or_insert_with(|| Value::String("ck.schema.space.v1".to_owned()));
            space.entry("realm_id".to_owned()).or_insert_with(|| {
                Value::String("ck:realm:0196419b-0000-7000-8000-000000000000".to_owned())
            });
            space
                .entry("created_at".to_owned())
                .or_insert_with(|| Value::String("2026-05-17T00:00:00Z".to_owned()));
        }
    }
}

// End-to-end check that the server-side Space-container state-machine guard
// rejects illegal lifecycle transitions with HTTP 412 + the spec-canonical
// reason_code per `cokret-spec/v1/zh/models/common-fields.md §5.1`.
// Reducer-level unit coverage lives in `src/reducer.rs::tests`; this test
// verifies the wire mapping (`event_log::submit_event` →
// `check_space_container_lifecycle_transition` →
// `StatusCode::PRECONDITION_FAILED`).

/// Build a signed `ck.strand.*` event envelope for the Strand state-machine
/// integration test. Mirror of `signed_space_event` with a Strand-specific
/// schema_id.
pub(crate) fn signed_strand_event(
    event_id: &str,
    actor_seq: u64,
    kind: &str,
    mut payload: Value,
    prev_refs: Vec<&str>,
) -> Value {
    normalize_strand_payload(kind, &mut payload);
    let mut event = serde_json::json!({
        "event_id": event_id,
        "kind": kind,
        "schema_id": "ck.schema.strand.v1",
        "actor_id": "did:web:alice.example",
        "actor_seq": actor_seq,
        "realm_id": "ck:realm:0196419b-0000-7000-8000-000000000000",
        "created_at": "2026-05-17T00:00:00Z",
        "device_id": "ck:device:01904100-0000-7000-8000-a11ce0000001",
        "audience": "did:web:soland.local",
        "domain": "did:web:soland.local",
        "prev_refs": prev_refs,
        "auth_refs": [],
        "payload": payload.clone(),
        "proofs": [{
            "type": "dev-proof",
            "verification_method": "did:web:alice.example#01904100-0000-7000-8000-a11ce0000001",
            "device_id": "ck:device:01904100-0000-7000-8000-a11ce0000001",
            "audience": "did:web:soland.local",
            "domain": "did:web:soland.local",
            "payload_digest": sha256_json(&payload)
        }]
    });
    event["canonical_digest"] = Value::String(event_canonical_digest(&event));
    event
}

pub(crate) fn normalize_strand_payload(kind: &str, payload: &mut Value) {
    let Some(object) = payload.as_object_mut() else {
        return;
    };
    if kind == "ck.strand.create" {
        if let Some(strand) = object.get_mut("object").and_then(Value::as_object_mut) {
            strand
                .entry("schema".to_owned())
                .or_insert_with(|| Value::String("ck.schema.strand.v1".to_owned()));
            strand.entry("realm_id".to_owned()).or_insert_with(|| {
                Value::String("ck:realm:0196419b-0000-7000-8000-000000000000".to_owned())
            });
            strand
                .entry("created_at".to_owned())
                .or_insert_with(|| Value::String("2026-05-17T00:00:00Z".to_owned()));
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
    }
    if matches!(
        kind,
        "ck.strand.archive" | "ck.strand.restore" | "ck.strand.tombstone"
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
    if kind == "ck.strand.update" {
        if !object.contains_key("target_ref")
            && let Some(strand_id) = object.get("strand_id").and_then(Value::as_str)
        {
            object.insert("target_ref".to_owned(), Value::String(strand_id.to_owned()));
        }
        object.remove("strand_id");
    }
}

/// Build a signed `ck.morph.*` event envelope.
pub(crate) fn signed_morph_event(
    event_id: &str,
    actor_seq: u64,
    kind: &str,
    mut payload: Value,
    prev_refs: Vec<&str>,
) -> Value {
    normalize_morph_payload(kind, &mut payload);
    let mut event = serde_json::json!({
        "event_id": event_id,
        "kind": kind,
        "schema_id": "ck.schema.morph.v1",
        "actor_id": "did:web:alice.example",
        "actor_seq": actor_seq,
        "realm_id": "ck:realm:0196419b-0000-7000-8000-000000000000",
        "created_at": "2026-05-17T00:00:00Z",
        "device_id": "ck:device:01904100-0000-7000-8000-a11ce0000001",
        "audience": "did:web:soland.local",
        "domain": "did:web:soland.local",
        "prev_refs": prev_refs,
        "auth_refs": [],
        "payload": payload.clone(),
        "proofs": [{
            "type": "dev-proof",
            "verification_method": "did:web:alice.example#01904100-0000-7000-8000-a11ce0000001",
            "device_id": "ck:device:01904100-0000-7000-8000-a11ce0000001",
            "audience": "did:web:soland.local",
            "domain": "did:web:soland.local",
            "payload_digest": sha256_json(&payload)
        }]
    });
    event["canonical_digest"] = Value::String(event_canonical_digest(&event));
    event
}

pub(crate) fn normalize_morph_payload(kind: &str, payload: &mut Value) {
    let Some(object) = payload.as_object_mut() else {
        return;
    };
    if kind == "ck.morph.create" {
        if let Some(morph) = object.get_mut("object").and_then(Value::as_object_mut) {
            morph
                .entry("schema".to_owned())
                .or_insert_with(|| Value::String("ck.schema.morph.v1".to_owned()));
            morph.entry("realm_id".to_owned()).or_insert_with(|| {
                Value::String("ck:realm:0196419b-0000-7000-8000-000000000000".to_owned())
            });
            morph
                .entry("created_at".to_owned())
                .or_insert_with(|| Value::String("2026-05-17T00:00:00Z".to_owned()));
            morph
                .entry("stage".to_owned())
                .or_insert_with(|| Value::String("draft".to_owned()));
            morph
                .entry("schema_refs".to_owned())
                .or_insert_with(|| serde_json::json!(["ck.schema.morph.v1"]));
        }
    }
}

/// Build a signed relation event envelope for read-model projection tests.
pub(crate) fn signed_relation_event(
    event_id: &str,
    actor_seq: u64,
    mut payload: Value,
    prev_refs: Vec<&str>,
) -> Value {
    let mut normalized_payload = None;
    if let Some(object) = payload.as_object_mut() {
        let relation_id = object.remove("relation_id").or_else(|| object.remove("id"));
        let relation_kind = object
            .remove("relation_kind")
            .or_else(|| object.remove("kind"));
        let from_ref = object.remove("from_ref").or_else(|| object.remove("from"));
        let to_ref = object.remove("to_ref").or_else(|| object.remove("to"));
        if let (Some(relation_id), Some(relation_kind), Some(from_ref), Some(to_ref)) =
            (relation_id, relation_kind, from_ref, to_ref)
        {
            let mut relation = serde_json::Map::new();
            relation.insert("id".to_owned(), relation_id);
            relation.insert(
                "schema".to_owned(),
                Value::String("ck.schema.relation.v1".to_owned()),
            );
            relation.insert(
                "realm_id".to_owned(),
                Value::String(DEMO_REALM_ID.to_owned()),
            );
            relation.insert("relation_kind".to_owned(), relation_kind);
            relation.insert("from_ref".to_owned(), from_ref);
            relation.insert("to_ref".to_owned(), to_ref);
            relation.insert(
                "created_by".to_owned(),
                Value::String("did:web:alice.example".to_owned()),
            );
            relation.insert(
                "created_at".to_owned(),
                Value::String("2026-05-17T00:00:00Z".to_owned()),
            );
            if let Some(fields) = object.remove("fields") {
                relation.insert("fields".to_owned(), fields);
            }
            if let Some(rank) = object.remove("rank") {
                relation.insert("rank".to_owned(), rank);
            }
            normalized_payload = Some(serde_json::json!({ "relation": Value::Object(relation) }));
        } else {
            object.remove("fields");
        }
    }
    if let Some(next_payload) = normalized_payload {
        payload = next_payload;
    }
    let mut event = serde_json::json!({
        "event_id": event_id,
        "kind": "ck.relation.create",
        "schema_id": "ck.schema.event_payload.v1",
        "actor_id": "did:web:alice.example",
        "actor_seq": actor_seq,
        "realm_id": DEMO_REALM_ID,
        "created_at": "2026-05-17T00:00:00Z",
        "device_id": "ck:device:01904100-0000-7000-8000-a11ce0000001",
        "audience": "did:web:soland.local",
        "domain": "did:web:soland.local",
        "prev_refs": prev_refs,
        "auth_refs": [],
        "payload": payload.clone(),
        "proofs": [{
            "type": "dev-proof",
            "verification_method": "did:web:alice.example#01904100-0000-7000-8000-a11ce0000001",
            "device_id": "ck:device:01904100-0000-7000-8000-a11ce0000001",
            "audience": "did:web:soland.local",
            "domain": "did:web:soland.local",
            "payload_digest": sha256_json(&payload)
        }]
    });
    event["canonical_digest"] = Value::String(event_canonical_digest(&event));
    event
}

// Round 13 — end-to-end check that Strand / Morph lifecycle state-machine
// guards map to HTTP 412 + canonical reason_code per spec §5.1. Combined
// Strand+Morph in one test to keep the suite small.

/// Build a signed `ck.redaction` event envelope, used by round 14b to
/// test object-level redaction (Strand / Morph). Mirror of
/// `signed_event_envelope` for the redaction kind. The spec schema
/// registry doesn't carry a dedicated `ck.schema.redaction.v1` —
/// `ck.redaction` is `category=message` per event-kind-registry, so
/// reuses `ck.schema.message.v1`.
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
    let mut event = serde_json::json!({
        "event_id": event_id,
        "kind": "ck.redaction",
        "schema_id": "ck.schema.message.v1",
        "actor_id": "did:web:alice.example",
        "actor_seq": actor_seq,
        "realm_id": DEMO_REALM_ID,
        "device_id": "ck:device:01904100-0000-7000-8000-a11ce0000001",
        "audience": "did:web:soland.local",
        "domain": "did:web:soland.local",
        "prev_refs": prev_refs,
        "auth_refs": [],
        "payload": payload.clone(),
        "proofs": [{
            "type": "dev-proof",
            "verification_method": "did:web:alice.example#01904100-0000-7000-8000-a11ce0000001",
            "device_id": "ck:device:01904100-0000-7000-8000-a11ce0000001",
            "audience": "did:web:soland.local",
            "domain": "did:web:soland.local",
            "payload_digest": sha256_json(&payload)
        }]
    });
    event["canonical_digest"] = Value::String(event_canonical_digest(&event));
    event
}

// The following comment blocks are descriptive notes for tests that have
// migrated to dedicated integration files. They are preserved here only
// as breadcrumbs (round 14b ck.redaction terminal-flip; round 14d/14f/15a
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
    let event_id = new_prefixed_uuid7("ck:event:");
    let record = MessageRecord {
        event_id: event_id.clone(),
        realm_id: realm_id.to_owned(),
        sender: sender.to_owned(),
        thread_id: format!("ck:strand:test-{}", event_id),
        content: serde_json::json!({"body": body}),
        encrypted: false,
        created_at: chrono::Utc::now(),
    };
    state.persistence.messages().put(&record).await.unwrap();
    record
}
