use serde_json::json;

use super::*;
use crate::db::Db;
use crate::state::DirectConversationBindingRecord;

fn test_config() -> crate::config::AppConfig {
    crate::config::AppConfig {
        bind: "127.0.0.1:0".parse().unwrap(),
        metrics_bind: "127.0.0.1:0".parse().unwrap(),
        public_base_url: "http://server".to_owned(),
        service_did: "did:web:soland.local".to_owned(),
        tls_cert_path: None,
        tls_key_path: None,
        database_url: None,
        object_storage: crate::config::ObjectStorageConfig::local(
            std::env::temp_dir().join("soland-direct-conversation-policy-test-blobs"),
        ),
        ice: crate::config::IceServersConfig::default(),
        livekit: crate::config::LiveKitConfig::default(),
        cors_allow_origin: None,
        auth_server_url: None,
        oidc_client_id: None,
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
        jws_replay_window_per_family: std::collections::BTreeMap::new(),
        notary_signing_key_seed: Some([9u8; 32]),
        agent_audit_binding_signing_seed: None,
        use_keystore: false,
        federation_policy: crate::config::FederationPolicy::Mesh,
        federation_peers: Vec::new(),
        federation_outbound_enabled: false,
        admin_default_page_limit: 100,
        admin_max_page_limit: 1000,
        admin_principal_dids: Vec::new(),
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
        sovereign_enclave_enabled: false,
        sovereign_enclave_allowed_outbound_hosts: Vec::new(),
        erasure_propagation_window_ms: 604_800_000,
        log_format: crate::config::LogFormat::Plain,
    }
}

fn state_with_direct_binding() -> (AppState, cokret_sdk::RealmId) {
    let state = AppState::new(test_config(), Db { pool: None });
    let realm_id =
        cokret_sdk::RealmId::new("ck:realm:01904100-0000-7000-8000-000000000601".to_owned())
            .unwrap();
    let now = chrono::Utc::now();
    state
        .direct_conversation_bindings
        .lock()
        .expect("direct_conversation_bindings lock")
        .insert(
            "did:web:alice.example\0did:web:bob.example".to_owned(),
            DirectConversationBindingRecord {
                participants_unordered: vec![
                    "did:web:alice.example".to_owned(),
                    "did:web:bob.example".to_owned(),
                ],
                realm_id: realm_id.to_string(),
                main_strand_id: "ck:strand:01904100-0000-7000-8000-000000000601".to_owned(),
                binding_event_ref: "ck:event:01904100-0000-7000-8000-000000000601".to_owned(),
                state: "active".to_owned(),
                created_at: now,
                updated_at: now,
            },
        );
    (state, realm_id)
}

fn op(
    realm_id: cokret_sdk::RealmId,
    seed: &str,
    kind: &str,
    payload: serde_json::Value,
) -> Operation {
    Operation::create(
        cokret_sdk::OperationId::new(format!("ck:operation:01904100-0000-7000-8000-{seed}"))
            .unwrap(),
        realm_id,
        kind,
        payload,
    )
}

#[tokio::test]
async fn active_direct_conversation_rejects_invite_space_and_third_party_member() {
    let (state, realm_id) = state_with_direct_binding();

    let invite = op(
        realm_id.clone(),
        "000000000601",
        kinds::CK_INVITE_CREATE,
        json!({
            "invite_id": "ck:invite:01904100-0000-7000-8000-000000000601",
            "inviter": "did:web:alice.example",
            "invitee": "did:web:charlie.example",
            "invite_delivery_target": {
                "recipient_service_did": "did:web:soland.local",
                "recipient_service_type": "principal_server"
            },
            "introduction_evidence_digest": "sha256:1111111111111111111111111111111111111111111111111111111111111111"
        }),
    );
    assert_eq!(
        validate_operation_policy(&state, &[invite])
            .await
            .unwrap_err(),
        "direct_conversation_invite_forbidden"
    );

    let space_create = op(
        realm_id.clone(),
        "000000000602",
        kinds::CK_SPACE_CONTAINER_CREATE,
        json!({
            "space_id": "ck:space:01904100-0000-7000-8000-000000000602",
            "title": "Third participant space"
        }),
    );
    assert_eq!(
        validate_operation_policy(&state, &[space_create])
            .await
            .unwrap_err(),
        "direct_conversation_space_forbidden"
    );

    let member_add = op(
        realm_id,
        "000000000603",
        kinds::CK_MEMBER_STATE,
        json!({
            "actor_id": "did:web:charlie.example",
            "membership": "invite",
            "sender": "did:web:alice.example"
        }),
    );
    assert_eq!(
        validate_operation_policy(&state, &[member_add])
            .await
            .unwrap_err(),
        "direct_conversation_third_party_member_forbidden"
    );
}
