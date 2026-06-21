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

fn test_state() -> AppState {
    AppState::new(test_config(), Db { pool: None })
}

fn grant_moderation_decision(state: &AppState, realm_id: &cokret_sdk::RealmId, actor: &str) {
    state.authz.create_grant(
        realm_id.to_string(),
        "did:web:owner.example".to_owned(),
        actor.to_owned(),
        realm_id.to_string(),
        vec![kinds::CK_MODERATION_DECISION.to_owned()],
        Vec::new(),
    );
}

fn grant_call_action(state: &AppState, realm_id: &cokret_sdk::RealmId, actor: &str, action: &str) {
    state.authz.create_grant(
        realm_id.to_string(),
        "did:web:owner.example".to_owned(),
        actor.to_owned(),
        realm_id.to_string(),
        vec![action.to_owned()],
        Vec::new(),
    );
}

async fn register_agent_selection(
    state: &AppState,
    realm_id: &cokret_sdk::RealmId,
    agent_principal_id: &str,
    reply: bool,
    act_on_behalf: bool,
) {
    let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    state
        .persistence
        .agents()
        .put(json!({
            "agent_principal_id": agent_principal_id,
            "controller_did": "did:web:alice.example",
            "agent_id": "summary",
            "display_name": "Summary",
            "agent_slug": "summary",
            "state": "active",
            "created_at": now,
            "updated_at": now,
        }))
        .await
        .expect("agent record");
    let realm_uuid = realm_id
        .as_str()
        .strip_prefix("ck:realm:")
        .expect("realm id prefix");
    state
        .persistence
        .agent_participation()
        .put_selection(json!({
            "agent_principal_id": agent_principal_id,
            "scope_kind": "realm",
            "scope_key": format!("realm:{realm_uuid}"),
            "realm_id": realm_id.as_str(),
            "scope": { "kind": "realm", "realm_id": realm_id.as_str() },
            "reply": reply,
            "accept_third_party_mention": false,
            "act_on_behalf": act_on_behalf,
        }))
        .await
        .expect("agent participation selection");
}

fn act_on_behalf_message(
    realm_id: cokret_sdk::RealmId,
    seed: &str,
    agent_principal_id: &str,
    authorization_ref: Option<&str>,
    approval: Option<(&str, &str)>,
) -> Operation {
    let mut payload = json!({
        "sender": "did:web:alice.example",
        "executed_by": agent_principal_id,
        "content": [{"type": "text", "text": "approved"}],
    });
    if let Some(authorization_ref) = authorization_ref {
        payload
            .as_object_mut()
            .expect("payload object")
            .insert("authorization_ref".to_owned(), json!(authorization_ref));
    }
    if let Some((request_id, approval_nonce)) = approval {
        let object = payload.as_object_mut().expect("payload object");
        object.insert("approval_request_id".to_owned(), json!(request_id));
        object.insert("approval_nonce".to_owned(), json!(approval_nonce));
    }
    op(realm_id, seed, kinds::CK_MESSAGE_CREATE, payload)
}

fn insert_approved_agent_action(
    state: &AppState,
    message: &Operation,
    request_id: &str,
    agent_principal_id: &str,
    approval_nonce: &str,
) {
    let payload_digest = cokret_sdk::canonical::canonical_sha256(&message.payload).unwrap();
    state
        .projection
        .lock()
        .expect("projection")
        .agent_action_requests
        .insert(
            request_id.to_owned(),
            crate::reducer::AgentActionRequestProjection {
                request_id: request_id.to_owned(),
                agent_principal_id: agent_principal_id.to_owned(),
                status: crate::reducer::AgentActionRequestStatus::Approved,
                requested_at: message.created_at - chrono::Duration::minutes(1),
                resolved_at: Some(message.created_at),
                resolution_event_id: Some(
                    "ck:event:01904100-0000-7000-8000-0000000007aa".to_owned(),
                ),
                cancel_reason: None,
                approval: Some(crate::reducer::AgentActionApprovalProjection {
                    approval_id: "ck:agent_approval:01904100-0000-7000-8000-0000000007aa"
                        .to_owned(),
                    proposed_action: kinds::CK_MESSAGE_CREATE.to_owned(),
                    target: json!({
                        "kind": "realm",
                        "realm_id": message.realm_id.as_str(),
                    }),
                    approved_payload_digest: payload_digest,
                    approval_nonce: approval_nonce.to_owned(),
                    expires_at: message.created_at + chrono::Duration::minutes(10),
                }),
            },
        );
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

#[tokio::test]
async fn act_on_behalf_agent_requires_participation_bit() {
    let state = test_state();
    let realm_id =
        cokret_sdk::RealmId::new("ck:realm:01904100-0000-7000-8000-000000000701".to_owned())
            .unwrap();
    let agent = "did:web:agent.example";
    register_agent_selection(&state, &realm_id, agent, true, false).await;
    let grant = state.authz.create_grant(
        realm_id.to_string(),
        "did:web:alice.example".to_owned(),
        agent.to_owned(),
        realm_id.to_string(),
        vec![kinds::CK_MESSAGE_CREATE.to_owned()],
        Vec::new(),
    );
    let message = act_on_behalf_message(
        realm_id,
        "000000000701",
        agent,
        Some(grant.grant_id.as_str()),
        None,
    );

    assert_eq!(
        validate_agent_reply_participation(&state, &[message])
            .await
            .unwrap_err(),
        "agent_act_on_behalf_not_permitted"
    );
}

#[tokio::test]
async fn act_on_behalf_agent_requires_authorization_ref_covering_action() {
    let state = test_state();
    let realm_id =
        cokret_sdk::RealmId::new("ck:realm:01904100-0000-7000-8000-000000000702".to_owned())
            .unwrap();
    let agent = "did:web:agent.example";
    register_agent_selection(&state, &realm_id, agent, true, true).await;
    let grant = state.authz.create_grant(
        realm_id.to_string(),
        "did:web:alice.example".to_owned(),
        agent.to_owned(),
        realm_id.to_string(),
        vec![kinds::CK_REACTION_ADD.to_owned()],
        Vec::new(),
    );
    let message = act_on_behalf_message(
        realm_id,
        "000000000702",
        agent,
        Some(grant.grant_id.as_str()),
        None,
    );

    assert_eq!(
        validate_agent_reply_participation(&state, &[message])
            .await
            .unwrap_err(),
        "agent_act_on_behalf_authorization_ref_scope"
    );
}

#[tokio::test]
async fn act_on_behalf_agent_allows_effective_selection_and_active_grant() {
    let state = test_state();
    let realm_id =
        cokret_sdk::RealmId::new("ck:realm:01904100-0000-7000-8000-000000000703".to_owned())
            .unwrap();
    let agent = "did:web:agent.example";
    register_agent_selection(&state, &realm_id, agent, true, true).await;
    let grant = state.authz.create_grant(
        realm_id.to_string(),
        "did:web:alice.example".to_owned(),
        agent.to_owned(),
        realm_id.to_string(),
        vec![kinds::CK_MESSAGE_CREATE.to_owned()],
        Vec::new(),
    );
    let message = act_on_behalf_message(
        realm_id,
        "000000000703",
        agent,
        Some(grant.grant_id.as_str()),
        Some(("request-703", "nonce-703")),
    );
    insert_approved_agent_action(&state, &message, "request-703", agent, "nonce-703");

    validate_agent_reply_participation(&state, &[message])
        .await
        .expect("effective act-on-behalf grant should pass");
}

#[tokio::test]
async fn act_on_behalf_agent_requires_fresh_approval_request() {
    let state = test_state();
    let realm_id =
        cokret_sdk::RealmId::new("ck:realm:01904100-0000-7000-8000-000000000704".to_owned())
            .unwrap();
    let agent = "did:web:agent.example";
    register_agent_selection(&state, &realm_id, agent, true, true).await;
    let grant = state.authz.create_grant(
        realm_id.to_string(),
        "did:web:alice.example".to_owned(),
        agent.to_owned(),
        realm_id.to_string(),
        vec![kinds::CK_MESSAGE_CREATE.to_owned()],
        Vec::new(),
    );
    let message = act_on_behalf_message(
        realm_id,
        "000000000704",
        agent,
        Some(grant.grant_id.as_str()),
        Some(("request-704", "nonce-704")),
    );

    assert_eq!(
        validate_agent_reply_participation(&state, &[message])
            .await
            .unwrap_err(),
        "agent_act_on_behalf_approval_request_missing"
    );
}

#[tokio::test]
async fn act_on_behalf_agent_consumes_approval_nonce_once() {
    let state = test_state();
    let realm_id =
        cokret_sdk::RealmId::new("ck:realm:01904100-0000-7000-8000-000000000705".to_owned())
            .unwrap();
    let agent = "did:web:agent.example";
    register_agent_selection(&state, &realm_id, agent, true, true).await;
    let grant = state.authz.create_grant(
        realm_id.to_string(),
        "did:web:alice.example".to_owned(),
        agent.to_owned(),
        realm_id.to_string(),
        vec![kinds::CK_MESSAGE_CREATE.to_owned()],
        Vec::new(),
    );
    let message = act_on_behalf_message(
        realm_id,
        "000000000705",
        agent,
        Some(grant.grant_id.as_str()),
        Some(("request-705", "nonce-705")),
    );
    insert_approved_agent_action(&state, &message, "request-705", agent, "nonce-705");

    validate_agent_reply_participation(&state, std::slice::from_ref(&message))
        .await
        .expect("first approval nonce use should pass");
    assert_eq!(
        validate_agent_reply_participation(&state, &[message])
            .await
            .unwrap_err(),
        cokret_sdk::error::REASON_APPROVAL_NONCE_REUSED
    );
}

#[tokio::test]
async fn circle_scoped_relation_update_and_delete_require_circle_membership() {
    let state = test_state();
    let realm_id =
        cokret_sdk::RealmId::new("ck:realm:01904100-0000-7000-8000-000000000801".to_owned())
            .unwrap();
    let circle_id = "ck:circle:01904100-0000-7000-8000-000000000801";
    let relation_id = "ck:relation:01904100-0000-7000-8000-000000000801";
    let now = chrono::Utc::now();
    {
        let mut projection = state.projection.lock().expect("projection mutex");
        let mut members = std::collections::BTreeSet::new();
        members.insert("did:web:alice.example".to_owned());
        projection.circles.insert(
            circle_id.to_owned(),
            crate::reducer::CircleProjection {
                circle_id: circle_id.to_owned(),
                realm_id: realm_id.to_string(),
                title: "Private".to_owned(),
                summary: None,
                directory_visibility: "private".to_owned(),
                join_rule: "invite".to_owned(),
                history_visibility: "joined".to_owned(),
                content_encryption_floor: None,
                metadata_encryption_floor: None,
                encryption_profile: "none".to_owned(),
                mls_group_ref: None,
                state: crate::reducer::CircleLifecycleState::Active,
                state_changed_at: None,
                created_by: "did:web:alice.example".to_owned(),
                created_at: now,
                updated_by: None,
                updated_at: None,
                members,
            },
        );
        projection.relations.insert(
            relation_id.to_owned(),
            crate::reducer::SolandRelationState {
                relation_id: relation_id.to_owned(),
                realm_id: realm_id.to_string(),
                relation_kind: "confidential_discussion_of".to_owned(),
                scope_circle_id: Some(circle_id.to_owned()),
                from_ref: Some("ck:strand:01904100-0000-7000-8000-000000000811".to_owned()),
                to_ref: Some("ck:strand:01904100-0000-7000-8000-000000000812".to_owned()),
                fields: Default::default(),
                state: "active".to_owned(),
                source_event_id: Some("ck:event:01904100-0000-7000-8000-000000000801".to_owned()),
                source_event_digest: Some(
                    "sha256:1111111111111111111111111111111111111111111111111111111111111111"
                        .to_owned(),
                ),
                created_at: now,
                updated_at: now,
            },
        );
    }

    let bob_update = op(
        realm_id.clone(),
        "000000000802",
        kinds::CK_RELATION_UPDATE,
        json!({
            "relation_id": relation_id,
            "sender": "did:web:bob.example",
            "fields": {"label": "nope"}
        }),
    );
    assert_eq!(
        validate_operation_policy(&state, &[bob_update])
            .await
            .unwrap_err(),
        "circle_scope_membership_required"
    );

    let alice_update = op(
        realm_id.clone(),
        "000000000803",
        kinds::CK_RELATION_UPDATE,
        json!({
            "relation_id": relation_id,
            "sender": "did:web:alice.example",
            "fields": {"label": "ok"}
        }),
    );
    validate_operation_policy(&state, &[alice_update])
        .await
        .expect("circle member can update scoped relation");

    let bob_delete = op(
        realm_id,
        "000000000804",
        kinds::CK_RELATION_DELETE,
        json!({
            "relation_id": relation_id,
            "sender": "did:web:bob.example"
        }),
    );
    assert_eq!(
        validate_operation_policy(&state, &[bob_delete])
            .await
            .unwrap_err(),
        "circle_scope_membership_required"
    );
}

#[tokio::test]
async fn moderation_decision_checks_issuer_capability_not_sender_spoof() {
    let state = test_state();
    let realm_id =
        cokret_sdk::RealmId::new("ck:realm:01904100-0000-7000-8000-000000000901".to_owned())
            .unwrap();
    grant_moderation_decision(&state, &realm_id, "did:web:moderator.example");
    let decision = op(
        realm_id,
        "000000000901",
        kinds::CK_MODERATION_DECISION,
        json!({
            "sender": "did:web:moderator.example",
            "issuer": "did:web:impostor.example",
            "target_ref": "ck:message:01904100-0000-7000-8000-000000000901",
            "decision": "quarantine",
            "request_canonical_digest": "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
        }),
    );

    assert_eq!(
        validate_operation_policy(&state, &[decision])
            .await
            .unwrap_err(),
        "moderation_actor_mismatch"
    );
}

#[tokio::test]
async fn moderation_decision_allows_authorized_issuer() {
    let state = test_state();
    let realm_id =
        cokret_sdk::RealmId::new("ck:realm:01904100-0000-7000-8000-000000000902".to_owned())
            .unwrap();
    grant_moderation_decision(&state, &realm_id, "did:web:moderator.example");
    let decision = op(
        realm_id,
        "000000000902",
        kinds::CK_MODERATION_DECISION,
        json!({
            "sender": "did:web:moderator.example",
            "issuer": "did:web:moderator.example",
            "target_ref": "ck:message:01904100-0000-7000-8000-000000000902",
            "decision": "quarantine",
            "request_canonical_digest": "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
        }),
    );

    validate_operation_policy(&state, &[decision])
        .await
        .expect("issuer with matching moderation capability should pass");
}

#[tokio::test]
async fn moderation_decision_rejects_missing_issuer_even_with_sender_grant() {
    let state = test_state();
    let realm_id =
        cokret_sdk::RealmId::new("ck:realm:01904100-0000-7000-8000-000000000903".to_owned())
            .unwrap();
    grant_moderation_decision(&state, &realm_id, "did:web:moderator.example");
    let decision = op(
        realm_id,
        "000000000903",
        kinds::CK_MODERATION_DECISION,
        json!({
            "sender": "did:web:moderator.example",
            "target_ref": "ck:message:01904100-0000-7000-8000-000000000903",
            "decision": "quarantine",
            "request_canonical_digest": "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        }),
    );

    assert_eq!(
        validate_operation_policy(&state, &[decision])
            .await
            .unwrap_err(),
        "moderation_decision_issuer_missing"
    );
}

#[tokio::test]
async fn call_recording_start_defaults_to_record_capability() {
    let state = test_state();
    let realm_id =
        cokret_sdk::RealmId::new("ck:realm:01904100-0000-7000-8000-000000000904".to_owned())
            .unwrap();
    grant_call_action(
        &state,
        &realm_id,
        "did:web:recorder.example",
        cokret_sdk::CAP_ACTION_CALL_RECORD,
    );
    let start = op(
        realm_id,
        "000000000904",
        cokret_sdk::events::kinds::CALL_RECORDING_START,
        json!({
            "sender": "did:web:recorder.example",
            "call_id": "ck:call:01904100-0000-7000-8000-000000000904",
            "recording_id": "recording-904"
        }),
    );

    validate_operation_policy(&state, &[start])
        .await
        .expect("ck.call.record should authorize recording capture");
}

#[tokio::test]
async fn call_recording_start_transcript_requires_transcribe_capability() {
    let state = test_state();
    let realm_id =
        cokret_sdk::RealmId::new("ck:realm:01904100-0000-7000-8000-000000000905".to_owned())
            .unwrap();
    grant_call_action(
        &state,
        &realm_id,
        "did:web:recorder.example",
        cokret_sdk::CAP_ACTION_CALL_RECORD,
    );
    let start = op(
        realm_id,
        "000000000905",
        cokret_sdk::events::kinds::CALL_RECORDING_START,
        json!({
            "sender": "did:web:recorder.example",
            "call_id": "ck:call:01904100-0000-7000-8000-000000000905",
            "recording_id": "transcript-905",
            "capture_kind": "transcript"
        }),
    );

    assert_eq!(
        validate_operation_policy(&state, &[start])
            .await
            .unwrap_err(),
        crate::error::reasons::TRANSCRIPTION_DENIED
    );
    assert_eq!(
        operation_policy_reason_code(crate::error::reasons::TRANSCRIPTION_DENIED),
        (
            salvo::http::StatusCode::FORBIDDEN,
            crate::error::reasons::TRANSCRIPTION_DENIED
        )
    );
}

#[tokio::test]
async fn call_recording_start_transcript_allows_transcribe_capability() {
    let state = test_state();
    let realm_id =
        cokret_sdk::RealmId::new("ck:realm:01904100-0000-7000-8000-000000000906".to_owned())
            .unwrap();
    grant_call_action(
        &state,
        &realm_id,
        "did:web:recorder.example",
        cokret_sdk::CAP_ACTION_CALL_TRANSCRIBE,
    );
    let start = op(
        realm_id,
        "000000000906",
        cokret_sdk::events::kinds::CALL_RECORDING_START,
        json!({
            "sender": "did:web:recorder.example",
            "call_id": "ck:call:01904100-0000-7000-8000-000000000906",
            "recording_id": "transcript-906",
            "capture_kind": "transcript"
        }),
    );

    validate_operation_policy(&state, &[start])
        .await
        .expect("ck.call.transcribe should authorize transcript capture");
}
