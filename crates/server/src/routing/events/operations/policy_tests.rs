use serde_json::json;

use super::*;
use crate::db::Db;
use crate::state::{CanonicalEventRecord, DirectConversationBindingRecord};

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
        account_authority_url: None,
        oidc_client_id: None,
        development_mode: true,
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

#[test]
fn service_attested_device_authorize_binding_accepts_projection_metadata() {
    let state = test_state();
    let payload = json!({
        "principal_id": "did:webvh:zQmZcDaFwUR8yQCZRkXoYEBi9hdzMSCCLASUVdwT1J4Qyc6:local.host:webvh:01kvqwpxssfq3bqm15rcd0g99x",
        "device_id": "ck:device:019eefcb-5882-7861-bc30-3033fa32dcf6",
        "device_public_key": "z6MkjHNtpwuhc2QSXzkf4DWoWp7eSMKB9PzfdnvaLB7kb3dG",
        "authorized_by": "did:key:z6MknBuwKMPAzbhp6EwCnaxsEDk4G2KFeWRu273gYVuTY5jw",
        "not_before": "2026-06-22T14:45:51Z",
        "enrollment_authority_binding": {
            "kind": "service_attested",
            "authority_did": "did:key:z6MknBuwKMPAzbhp6EwCnaxsEDk4G2KFeWRu273gYVuTY5jw",
            "authorization_ref": "did:webvh:zQmZcDaFwUR8yQCZRkXoYEBi9hdzMSCCLASUVdwT1J4Qyc6:local.host:webvh:01kvqwpxssfq3bqm15rcd0g99x#enrollment-authority"
        },
        "event_id": "ck:event:019eefcb-7fb2-7890-bffd-1f2035356fbf",
        "sender": "did:webvh:zQmZcDaFwUR8yQCZRkXoYEBi9hdzMSCCLASUVdwT1J4Qyc6:local.host:webvh:01kvqwpxssfq3bqm15rcd0g99x",
        "hlc": "019eefcb7d18-0000-8adcfdb5",
        "executed_by": "did:key:z6MknBuwKMPAzbhp6EwCnaxsEDk4G2KFeWRu273gYVuTY5jw",
        "authorization_ref": "did:webvh:zQmZcDaFwUR8yQCZRkXoYEBi9hdzMSCCLASUVdwT1J4Qyc6:local.host:webvh:01kvqwpxssfq3bqm15rcd0g99x#enrollment-authority"
    });

    crate::routing::identity::cross_signing::validate_device_authorize_binding(&state, &payload)
        .unwrap();
}

fn grant_circle_action(
    state: &AppState,
    realm_id: &cokret_sdk::RealmId,
    circle_id: &str,
    actor: &str,
    action: &str,
) {
    state.authz.create_grant(
        realm_id.to_string(),
        "did:web:owner.example".to_owned(),
        actor.to_owned(),
        circle_id.to_owned(),
        vec![action.to_owned()],
        vec![crate::authz::Constraint::AllowedCircleIds {
            allowed_circle_ids: std::collections::BTreeSet::from([cokret_sdk::CircleId::new(
                circle_id.to_owned(),
            )
            .expect("valid circle id")]),
        }],
    );
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

fn seed_read_receipt_inheritance(
    state: &AppState,
    parent_realm_id: &str,
    child_realm_id: &str,
    parent_policy: serde_json::Value,
) {
    use cokret_sdk::lattice::CellState;

    let now = chrono::Utc::now();
    let mut projection = state.projection.lock().expect("projection mutex");
    let cell_id = cokret_sdk::CellRef::new(format!(
        "ck:cell:ck.component.realm.read_receipt_policy.v1:{parent_realm_id}"
    ))
    .expect("valid read receipt policy cell ref");
    projection
        .cells
        .insert(cell_id, CellState::Value(parent_policy));
    projection
        .realm_links
        .entry(child_realm_id.to_owned())
        .or_default()
        .push(crate::reducer::RealmLinkState {
            realm_id: child_realm_id.to_owned(),
            target_realm_id: parent_realm_id.to_owned(),
            link_kind: "governed_by".to_owned(),
            status: "active".to_owned(),
            label: None,
            commitment: None,
            created_at: now,
            updated_at: now,
        });
    projection.realm_inheritance_policies.insert(
        child_realm_id.to_owned(),
        crate::reducer::RealmInheritancePolicyState {
            realm_id: child_realm_id.to_owned(),
            operation_id: "ck:operation:01904100-0000-7000-8000-000000009901".to_owned(),
            source_realm_id: parent_realm_id.to_owned(),
            allowed_policies: vec!["ck.realm.read_receipt_policy".to_owned()],
            allowed_capability_bundles: Vec::new(),
            max_depth: 1,
            updated_at: now,
        },
    );
}

#[tokio::test]
async fn read_receipt_child_policy_rejects_visibility_loosening() {
    let state = test_state();
    let parent_realm = "ck:realm:01904100-0000-7000-8000-000000009911";
    let child_realm =
        cokret_sdk::RealmId::new("ck:realm:01904100-0000-7000-8000-000000009912".to_owned())
            .unwrap();
    seed_read_receipt_inheritance(
        &state,
        parent_realm,
        child_realm.as_str(),
        json!({
            "disclosure": "optional",
            "visibility": "private",
            "scope_overrides_allowed": true
        }),
    );

    let child_policy = op(
        child_realm,
        "000000009913",
        kinds::CK_REALM_READ_RECEIPT_POLICY,
        json!({
            "disclosure": "optional",
            "visibility": "public"
        }),
    );
    assert_eq!(
        validate_operation_policy(&state, &[child_policy])
            .await
            .unwrap_err(),
        "policy_denied"
    );
}

#[tokio::test]
async fn read_receipt_child_policy_rejects_required_floor_without_escape() {
    let state = test_state();
    let parent_realm = "ck:realm:01904100-0000-7000-8000-000000009921";
    let child_realm =
        cokret_sdk::RealmId::new("ck:realm:01904100-0000-7000-8000-000000009922".to_owned())
            .unwrap();
    seed_read_receipt_inheritance(
        &state,
        parent_realm,
        child_realm.as_str(),
        json!({
            "disclosure": "required",
            "visibility": "members",
            "scope_overrides_allowed": true
        }),
    );

    let child_policy = op(
        child_realm,
        "000000009923",
        kinds::CK_REALM_READ_RECEIPT_POLICY,
        json!({
            "disclosure": "disabled",
            "visibility": "private"
        }),
    );
    assert_eq!(
        validate_operation_policy(&state, &[child_policy])
            .await
            .unwrap_err(),
        cokret_sdk::ERROR_CODE_READ_RECEIPT_COMPLIANCE_FLOOR_VIOLATED
    );
}

#[tokio::test]
async fn read_receipt_child_policy_allows_required_floor_escape() {
    let state = test_state();
    let parent_realm = "ck:realm:01904100-0000-7000-8000-000000009931";
    let child_realm =
        cokret_sdk::RealmId::new("ck:realm:01904100-0000-7000-8000-000000009932".to_owned())
            .unwrap();
    seed_read_receipt_inheritance(
        &state,
        parent_realm,
        child_realm.as_str(),
        json!({
            "disclosure": "required",
            "visibility": "members",
            "scope_overrides_allowed": true,
            "allow_child_privacy_tightening_against_required": true
        }),
    );

    let child_policy = op(
        child_realm,
        "000000009933",
        kinds::CK_REALM_READ_RECEIPT_POLICY,
        json!({
            "disclosure": "disabled",
            "visibility": "private"
        }),
    );
    validate_operation_policy(&state, &[child_policy])
        .await
        .expect("parent escape allows compliance-floor privacy tightening");
}

#[tokio::test]
async fn read_receipt_child_policy_rejects_any_change_when_overrides_disabled() {
    let state = test_state();
    let parent_realm = "ck:realm:01904100-0000-7000-8000-000000009941";
    let child_realm =
        cokret_sdk::RealmId::new("ck:realm:01904100-0000-7000-8000-000000009942".to_owned())
            .unwrap();
    seed_read_receipt_inheritance(
        &state,
        parent_realm,
        child_realm.as_str(),
        json!({
            "disclosure": "optional",
            "visibility": "members",
            "scope_overrides_allowed": false
        }),
    );

    let child_policy = op(
        child_realm,
        "000000009943",
        kinds::CK_REALM_READ_RECEIPT_POLICY,
        json!({
            "disclosure": "disabled",
            "visibility": "private"
        }),
    );
    assert_eq!(
        validate_operation_policy(&state, &[child_policy])
            .await
            .unwrap_err(),
        "policy_denied"
    );
}

async fn put_agent_participation_ceiling(
    state: &AppState,
    scope_kind: &str,
    scope_key: String,
    realm_id: &str,
    reply: bool,
    accept_third_party_mention: bool,
    act_on_behalf: bool,
) {
    state
        .persistence
        .agent_participation()
        .put_ceiling(json!({
            "scope_kind": scope_kind,
            "scope_key": scope_key,
            "realm_id": realm_id,
            "reply": reply,
            "accept_third_party_mention": accept_third_party_mention,
            "act_on_behalf": act_on_behalf,
        }))
        .await
        .expect("agent participation ceiling");
}

#[tokio::test]
async fn strand_agent_participation_ceiling_cannot_widen_circle_parent() {
    let state = test_state();
    let realm_id =
        cokret_sdk::RealmId::new("ck:realm:01904100-0000-7000-8000-000000009951".to_owned())
            .unwrap();
    let circle_id = "ck:circle:01904100-0000-7000-8000-000000009952";
    let strand_id = "ck:strand:01904100-0000-7000-8000-000000009953";
    put_agent_participation_ceiling(
        &state,
        "circle",
        crate::routing::agent_participation::circle_scope_key(realm_id.as_str(), circle_id),
        realm_id.as_str(),
        true,
        false,
        false,
    )
    .await;

    let strand_create = op(
        realm_id,
        "000000009954",
        kinds::CK_STRAND_CREATE,
        json!({
            "sender": "did:web:alice.example",
            "object": {
                "id": strand_id,
                "realm_id": "ck:realm:01904100-0000-7000-8000-000000009951",
                "scope_circle_id": circle_id,
                "metadata": {"title": "Scoped"},
                "agent_participation": {
                    "reply": true,
                    "accept_third_party_mention": true,
                    "act_on_behalf": false
                }
            }
        }),
    );

    assert_eq!(
        validate_agent_participation_ceiling(&state, &[strand_create])
            .await
            .unwrap_err(),
        "agent_participation_ceiling_widen"
    );
}

#[tokio::test]
async fn strand_selection_is_capped_by_enclosing_circle_ceiling() {
    let state = test_state();
    let realm_id =
        cokret_sdk::RealmId::new("ck:realm:01904100-0000-7000-8000-000000009961".to_owned())
            .unwrap();
    let circle_id = "ck:circle:01904100-0000-7000-8000-000000009962";
    let strand_id =
        cokret_sdk::StrandId::new("ck:strand:01904100-0000-7000-8000-000000009963".to_owned())
            .unwrap();
    {
        let mut projection = state.projection.lock().expect("projection mutex");
        projection.strands.insert(
            strand_id.as_str().to_owned(),
            crate::reducer::StrandProjection {
                strand_id: strand_id.as_str().to_owned(),
                realm_id: realm_id.to_string(),
                tracks: Default::default(),
                title: "Scoped".to_owned(),
                summary: None,
                fields: Default::default(),
                state: crate::reducer::ObjectLifecycleState::Active,
                state_changed_at: None,
                created_by: "did:web:alice.example".to_owned(),
                created_at: chrono::Utc::now(),
                history_basis_seals: Vec::new(),
                updated_by: None,
                updated_at: None,
                scope_circle_id: Some(circle_id.to_owned()),
            },
        );
    }
    put_agent_participation_ceiling(
        &state,
        "circle",
        crate::routing::agent_participation::circle_scope_key(realm_id.as_str(), circle_id),
        realm_id.as_str(),
        true,
        false,
        false,
    )
    .await;

    let scope = cokret_sdk::models::AgentParticipationScope::Strand {
        realm_id,
        strand_id,
    };
    let ceiling =
        crate::routing::agent_participation::resolve_effective_ceiling(&state, &scope).await;
    assert!(!ceiling.accept_third_party_mention);
    let selection = cokret_sdk::models::AgentParticipation {
        reply: true,
        accept_third_party_mention: true,
        act_on_behalf: false,
    };
    assert!(matches!(
        cokret_sdk::models::validate_selection_within_ceiling(ceiling, selection),
        Err(cokret_sdk::models::AgentParticipationError::ExceedsCeiling { .. })
    ));
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

fn agent_context(agent_principal_id: &str, authorization_ref: &str) -> serde_json::Value {
    json!({
        "agent_id": agent_principal_id,
        "operator_or_controller": "did:web:alice.example",
        "authorization_ref": authorization_ref,
        "execution_purpose": "test_action",
    })
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
        let object = payload.as_object_mut().expect("payload object");
        object.insert("authorization_ref".to_owned(), json!(authorization_ref));
        object.insert(
            "agent_context".to_owned(),
            agent_context(agent_principal_id, authorization_ref),
        );
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
                    proposed_action: kinds::canonical_kind_string(message),
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

async fn insert_agent_interop_session_start(
    state: &AppState,
    realm_id: &cokret_sdk::RealmId,
    seed: &str,
    actor: &str,
    session_id: &str,
) {
    state
        .persistence
        .events()
        .put(CanonicalEventRecord {
            event_id: format!("ck:event:01904100-0000-7000-8000-{seed}"),
            actor_id: actor.to_owned(),
            actor_seq: 1,
            realm_id: Some(realm_id.to_string()),
            kind: kinds::CK_AGENT_INTEROP_SESSION_START.to_owned(),
            schema_id: "ck.schema.event.v1".to_owned(),
            canonical_digest: "sha256:test".to_owned(),
            canonical_bytes: Vec::new(),
            envelope: json!({
                "actor_id": actor,
                "kind": kinds::CK_AGENT_INTEROP_SESSION_START,
                "realm_id": realm_id.to_string(),
                "payload": {
                    "sender": actor,
                    "session_id": session_id,
                    "counterparty_agent": "did:web:remote-agent.example",
                    "protocol": "mcp",
                    "capability_grant": "ck:grant:01904100-0000-7000-8000-0000000000ff"
                }
            }),
            received_at: chrono::Utc::now(),
        })
        .await
        .expect("store agent interop session start");
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
async fn act_on_behalf_agent_non_message_write_requires_authorization_ref() {
    let state = test_state();
    let realm_id =
        cokret_sdk::RealmId::new("ck:realm:01904100-0000-7000-8000-0000000007a2".to_owned())
            .unwrap();
    let agent = "did:web:agent.example";
    register_agent_selection(&state, &realm_id, agent, true, true).await;
    let operation = op(
        realm_id,
        "0000000007a2",
        kinds::CK_STRAND_CREATE,
        json!({
            "sender": "did:web:alice.example",
            "executed_by": agent,
            "object": {
                "id": "ck:strand:01904100-0000-7000-8000-0000000007a2",
                "metadata": {"title": "Work"}
            }
        }),
    );

    assert_eq!(
        validate_agent_reply_participation(&state, &[operation])
            .await
            .unwrap_err(),
        "agent_act_on_behalf_authorization_ref_missing"
    );
}

#[tokio::test]
async fn act_on_behalf_agent_strand_write_requires_agent_context() {
    let state = test_state();
    let realm_id =
        cokret_sdk::RealmId::new("ck:realm:01904100-0000-7000-8000-0000000007c1".to_owned())
            .unwrap();
    let agent = "did:web:agent.example";
    register_agent_selection(&state, &realm_id, agent, true, true).await;
    let grant = state.authz.create_grant(
        realm_id.to_string(),
        "did:web:alice.example".to_owned(),
        agent.to_owned(),
        realm_id.to_string(),
        vec![kinds::CK_STRAND_CREATE.to_owned()],
        Vec::new(),
    );
    let operation = op(
        realm_id,
        "0000000007c1",
        kinds::CK_STRAND_CREATE,
        json!({
            "sender": "did:web:alice.example",
            "executed_by": agent,
            "authorization_ref": grant.grant_id,
            "object": {
                "id": "ck:strand:01904100-0000-7000-8000-0000000007c1",
                "metadata": {"title": "Work"}
            }
        }),
    );

    assert_eq!(
        validate_agent_reply_participation(&state, &[operation])
            .await
            .unwrap_err(),
        "agent_context_missing"
    );
}

#[tokio::test]
async fn act_on_behalf_agent_relation_write_rejects_context_authorization_mismatch() {
    let state = test_state();
    let realm_id =
        cokret_sdk::RealmId::new("ck:realm:01904100-0000-7000-8000-0000000007c2".to_owned())
            .unwrap();
    let agent = "did:web:agent.example";
    register_agent_selection(&state, &realm_id, agent, true, true).await;
    let envelope_grant = state.authz.create_grant(
        realm_id.to_string(),
        "did:web:alice.example".to_owned(),
        agent.to_owned(),
        realm_id.to_string(),
        vec![kinds::CK_RELATION_CREATE.to_owned()],
        Vec::new(),
    );
    let context_grant = state.authz.create_grant(
        realm_id.to_string(),
        "did:web:alice.example".to_owned(),
        agent.to_owned(),
        realm_id.to_string(),
        vec![kinds::CK_RELATION_CREATE.to_owned()],
        Vec::new(),
    );
    let operation = op(
        realm_id,
        "0000000007c2",
        kinds::CK_RELATION_CREATE,
        json!({
            "sender": "did:web:alice.example",
            "executed_by": agent,
            "authorization_ref": envelope_grant.grant_id,
            "agent_context": agent_context(agent, context_grant.grant_id.as_str()),
            "relation_id": "ck:relation:01904100-0000-7000-8000-0000000007c2",
            "relation_kind": "references",
            "from_ref": "ck:strand:01904100-0000-7000-8000-0000000007c2",
            "to_ref": "ck:strand:01904100-0000-7000-8000-0000000007c3"
        }),
    );

    assert_eq!(
        validate_agent_reply_participation(&state, &[operation])
            .await
            .unwrap_err(),
        "agent_context_authorization_ref_mismatch"
    );
}

#[tokio::test]
async fn provenance_actor_kind_agent_requires_agent_context_for_non_message_write() {
    let state = test_state();
    let realm_id =
        cokret_sdk::RealmId::new("ck:realm:01904100-0000-7000-8000-0000000007c3".to_owned())
            .unwrap();
    let operation = op(
        realm_id,
        "0000000007c3",
        kinds::CK_RELATION_CREATE,
        json!({
            "sender": "did:web:alice.example",
            "provenance": {
                "actor_kind": "agent"
            },
            "relation_id": "ck:relation:01904100-0000-7000-8000-0000000007c3",
            "relation_kind": "references",
            "from_ref": "ck:strand:01904100-0000-7000-8000-0000000007c4",
            "to_ref": "ck:strand:01904100-0000-7000-8000-0000000007c5"
        }),
    );

    assert_eq!(
        validate_agent_reply_participation(&state, &[operation])
            .await
            .unwrap_err(),
        "agent_context_missing"
    );
}

#[tokio::test]
async fn act_on_behalf_agent_view_write_allows_valid_agent_context_and_approval() {
    let state = test_state();
    let realm_id =
        cokret_sdk::RealmId::new("ck:realm:01904100-0000-7000-8000-0000000007c4".to_owned())
            .unwrap();
    let agent = "did:web:agent.example";
    register_agent_selection(&state, &realm_id, agent, true, true).await;
    let grant = state.authz.create_grant(
        realm_id.to_string(),
        "did:web:alice.example".to_owned(),
        agent.to_owned(),
        realm_id.to_string(),
        vec![kinds::CK_VIEW_CREATE.to_owned()],
        Vec::new(),
    );
    let grant_id = grant.grant_id.clone();
    let operation = op(
        realm_id,
        "0000000007c4",
        kinds::CK_VIEW_CREATE,
        json!({
            "sender": "did:web:alice.example",
            "executed_by": agent,
            "authorization_ref": grant_id.as_str(),
            "agent_context": agent_context(agent, grant_id.as_str()),
            "view_id": "ck:view:01904100-0000-7000-8000-0000000007c4",
            "approval_request_id": "request-7c4",
            "approval_nonce": "nonce-7c4"
        }),
    );
    insert_approved_agent_action(&state, &operation, "request-7c4", agent, "nonce-7c4");

    validate_agent_reply_participation(&state, &[operation])
        .await
        .expect("valid agent_context must allow non-message act-on-behalf writes");
}

#[tokio::test]
async fn act_on_behalf_agent_unknown_kind_rejects_authorization_action() {
    let state = test_state();
    let realm_id =
        cokret_sdk::RealmId::new("ck:realm:01904100-0000-7000-8000-0000000007c5".to_owned())
            .unwrap();
    let agent = "did:web:agent.example";
    register_agent_selection(&state, &realm_id, agent, true, true).await;
    let grant = state.authz.create_grant(
        realm_id.to_string(),
        "did:web:alice.example".to_owned(),
        agent.to_owned(),
        realm_id.to_string(),
        vec!["*".to_owned()],
        Vec::new(),
    );
    let grant_id = grant.grant_id.clone();
    let operation = op(
        realm_id,
        "0000000007c5",
        "ck.agent.unknown.write",
        json!({
            "sender": "did:web:alice.example",
            "executed_by": agent,
            "authorization_ref": grant_id.as_str(),
            "agent_context": agent_context(agent, grant_id.as_str()),
        }),
    );

    assert_eq!(
        validate_agent_reply_participation(&state, &[operation])
            .await
            .unwrap_err(),
        "agent_act_on_behalf_authorization_action_unsupported"
    );
}

#[tokio::test]
async fn reply_agent_unknown_kind_rejects_context_authorization_action() {
    let state = test_state();
    let realm_id =
        cokret_sdk::RealmId::new("ck:realm:01904100-0000-7000-8000-0000000007c6".to_owned())
            .unwrap();
    let agent = "did:web:agent.example";
    register_agent_selection(&state, &realm_id, agent, true, true).await;
    let grant = state.authz.create_grant(
        realm_id.to_string(),
        "did:web:alice.example".to_owned(),
        agent.to_owned(),
        realm_id.to_string(),
        vec!["*".to_owned()],
        Vec::new(),
    );
    let grant_id = grant.grant_id.clone();
    let operation = op(
        realm_id,
        "0000000007c6",
        "ck.agent.unknown.reply",
        json!({
            "sender": agent,
            "agent_context": agent_context(agent, grant_id.as_str()),
        }),
    );

    assert_eq!(
        validate_agent_reply_participation(&state, &[operation])
            .await
            .unwrap_err(),
        "agent_context_authorization_action_unsupported"
    );
}

#[tokio::test]
async fn profile_accountable_principal_requires_active_grant() {
    let state = test_state();
    let realm_id =
        cokret_sdk::RealmId::new("ck:realm:01904100-0000-7000-8000-0000000007a3".to_owned())
            .unwrap();
    let profile = op(
        realm_id,
        "0000000007a3",
        "ck.profile.create",
        json!({
            "principal_id": "did:web:agent.example",
            "display_name": "Agent",
            "accountable_principal_ids": ["did:web:alice.example"]
        }),
    );

    assert_eq!(
        validate_operation_policy(&state, &[profile])
            .await
            .unwrap_err(),
        crate::error::reasons::ACCOUNTABILITY_GRANT_MISSING
    );
}

#[tokio::test]
async fn profile_accountable_principal_rejects_batch_grant_signed_by_other_actor() {
    let state = test_state();
    let realm_id =
        cokret_sdk::RealmId::new("ck:realm:01904100-0000-7000-8000-0000000007a4".to_owned())
            .unwrap();
    let profile = op(
        realm_id.clone(),
        "0000000007a4",
        "ck.profile.create",
        json!({
            "sender": "did:web:agent.example",
            "principal_id": "did:web:agent.example",
            "display_name": "Agent",
            "accountable_principal_ids": ["did:web:alice.example"]
        }),
    );
    let fake_grant = op(
        realm_id,
        "0000000007a5",
        "ck.identity.accountability_grant",
        json!({
            "sender": "did:web:mallory.example",
            "issuer": "did:web:alice.example",
            "subject": "did:web:agent.example",
            "grant_status": "active",
            "not_before": "2026-01-01T00:00:00Z",
            "expires_at": "2099-01-01T00:00:00Z"
        }),
    );

    assert_eq!(
        validate_operation_policy(&state, &[fake_grant, profile])
            .await
            .unwrap_err(),
        crate::error::reasons::ACCOUNTABILITY_GRANT_MISSING
    );
}

#[tokio::test]
async fn profile_accountable_principal_rejects_stored_grant_signed_by_other_actor() {
    let state = test_state();
    let realm_id =
        cokret_sdk::RealmId::new("ck:realm:01904100-0000-7000-8000-0000000007a6".to_owned())
            .unwrap();
    state
        .persistence
        .events()
        .put(CanonicalEventRecord {
            event_id: "ck:event:01904100-0000-7000-8000-0000000007a6".to_owned(),
            actor_id: "did:web:mallory.example".to_owned(),
            actor_seq: 1,
            realm_id: Some(realm_id.to_string()),
            kind: "ck.identity.accountability_grant".to_owned(),
            schema_id: "ck.schema.event.v1".to_owned(),
            canonical_digest: "sha256:test".to_owned(),
            canonical_bytes: Vec::new(),
            envelope: json!({
                "actor_id": "did:web:mallory.example",
                "kind": "ck.identity.accountability_grant",
                "realm_id": realm_id.to_string(),
                "payload": {
                    "issuer": "did:web:alice.example",
                    "subject": "did:web:agent.example",
                    "grant_status": "active",
                    "not_before": "2026-01-01T00:00:00Z",
                    "expires_at": "2099-01-01T00:00:00Z"
                }
            }),
            received_at: chrono::Utc::now(),
        })
        .await
        .expect("store fake accountability grant");
    let profile = op(
        realm_id,
        "0000000007a7",
        "ck.profile.create",
        json!({
            "sender": "did:web:agent.example",
            "principal_id": "did:web:agent.example",
            "display_name": "Agent",
            "accountable_principal_ids": ["did:web:alice.example"]
        }),
    );

    assert_eq!(
        validate_operation_policy(&state, &[profile])
            .await
            .unwrap_err(),
        crate::error::reasons::ACCOUNTABILITY_GRANT_MISSING
    );
}

#[tokio::test]
async fn circle_member_manage_rejects_forged_verdict_without_grant() {
    let state = test_state();
    let realm_id =
        cokret_sdk::RealmId::new("ck:realm:01904100-0000-7000-8000-000000000881".to_owned())
            .unwrap();
    let member_add = op(
        realm_id,
        "000000000881",
        kinds::CK_CIRCLE_MEMBER_STATE,
        json!({
            "sender": "did:web:alice.example",
            "circle_id": "ck:circle:01904100-0000-7000-8000-000000000881",
            "actor": "did:web:bob.example",
            "membership": "join",
            "manage_capability_verified": true,
            "actor_capability": {
                "action": "ck.circle.member.manage",
                "circle_id": "ck:circle:01904100-0000-7000-8000-000000000881",
                "allowed": true
            }
        }),
    );

    assert_eq!(
        validate_operation_policy(&state, &[member_add])
            .await
            .unwrap_err(),
        "circle_member_manage_capability_required"
    );
}

#[tokio::test]
async fn circle_member_manage_allows_explicit_circle_scoped_grant() {
    let state = test_state();
    let realm_id =
        cokret_sdk::RealmId::new("ck:realm:01904100-0000-7000-8000-000000000882".to_owned())
            .unwrap();
    let circle_id = "ck:circle:01904100-0000-7000-8000-000000000882";
    grant_circle_action(
        &state,
        &realm_id,
        circle_id,
        "did:web:alice.example",
        "ck.circle.member.manage",
    );
    let member_add = op(
        realm_id,
        "000000000882",
        kinds::CK_CIRCLE_MEMBER_STATE,
        json!({
            "sender": "did:web:alice.example",
            "circle_id": circle_id,
            "actor": "did:web:bob.example",
            "membership": "join",
            "manage_capability_verified": true,
            "actor_capability": {
                "action": "ck.circle.member.manage",
                "circle_id": circle_id,
                "allowed": true
            }
        }),
    );

    validate_operation_policy(&state, &[member_add])
        .await
        .expect("circle-scoped grant authorizes member management");
}

#[tokio::test]
async fn circle_lifecycle_requires_circle_manage_grant() {
    let state = test_state();
    let realm_id =
        cokret_sdk::RealmId::new("ck:realm:01904100-0000-7000-8000-000000000883".to_owned())
            .unwrap();
    let circle_id = "ck:circle:01904100-0000-7000-8000-000000000883";
    let tombstone = op(
        realm_id.clone(),
        "000000000883",
        kinds::CK_CIRCLE_TOMBSTONE,
        json!({
            "sender": "did:web:alice.example",
            "circle_id": circle_id
        }),
    );

    assert_eq!(
        validate_operation_policy(&state, &[tombstone.clone()])
            .await
            .unwrap_err(),
        "circle_manage_capability_required"
    );

    grant_circle_action(
        &state,
        &realm_id,
        circle_id,
        "did:web:alice.example",
        "ck.circle.manage",
    );
    validate_operation_policy(&state, &[tombstone])
        .await
        .expect("circle-scoped manage grant authorizes lifecycle");
}

#[tokio::test]
async fn agent_interop_session_status_allows_start_actor_in_batch() {
    let state = test_state();
    let realm_id =
        cokret_sdk::RealmId::new("ck:realm:01904100-0000-7000-8000-0000000007b1".to_owned())
            .unwrap();
    let session_id = "ck:agent_interop_session:01904100-0000-7000-8000-0000000007b1";
    let start = op(
        realm_id.clone(),
        "0000000007b1",
        kinds::CK_AGENT_INTEROP_SESSION_START,
        json!({
            "sender": "did:web:alice.example",
            "session_id": session_id,
            "counterparty_agent": "did:web:remote-agent.example",
            "protocol": "mcp",
            "capability_grant": "ck:grant:01904100-0000-7000-8000-0000000007b1"
        }),
    );
    let status = op(
        realm_id,
        "0000000007b2",
        kinds::CK_AGENT_INTEROP_SESSION_STATUS,
        json!({
            "sender": "did:web:alice.example",
            "session_id": session_id,
            "status": "working"
        }),
    );

    validate_operation_policy(&state, &[start, status])
        .await
        .expect("start actor can write status for its own session");
}

#[tokio::test]
async fn agent_interop_session_status_rejects_other_actor() {
    let state = test_state();
    let realm_id =
        cokret_sdk::RealmId::new("ck:realm:01904100-0000-7000-8000-0000000007b3".to_owned())
            .unwrap();
    let session_id = "ck:agent_interop_session:01904100-0000-7000-8000-0000000007b3";
    insert_agent_interop_session_start(
        &state,
        &realm_id,
        "0000000007b3",
        "did:web:alice.example",
        session_id,
    )
    .await;
    let status = op(
        realm_id,
        "0000000007b4",
        kinds::CK_AGENT_INTEROP_SESSION_STATUS,
        json!({
            "sender": "did:web:bob.example",
            "session_id": session_id,
            "status": "working"
        }),
    );

    assert_eq!(
        validate_operation_policy(&state, &[status])
            .await
            .unwrap_err(),
        "interop_session_writer_unauthorized"
    );
    assert_eq!(
        operation_policy_reason_code("interop_session_writer_unauthorized"),
        (
            salvo::http::StatusCode::FORBIDDEN,
            "interop_session_writer_unauthorized"
        )
    );
}

#[tokio::test]
async fn agent_interop_session_status_rejects_realm_grant_without_session_scope() {
    let state = test_state();
    let realm_id =
        cokret_sdk::RealmId::new("ck:realm:01904100-0000-7000-8000-0000000007b5".to_owned())
            .unwrap();
    let session_id = "ck:agent_interop_session:01904100-0000-7000-8000-0000000007b5";
    insert_agent_interop_session_start(
        &state,
        &realm_id,
        "0000000007b5",
        "did:web:alice.example",
        session_id,
    )
    .await;
    state.authz.create_grant(
        realm_id.to_string(),
        "did:web:alice.example".to_owned(),
        "did:web:bob.example".to_owned(),
        realm_id.to_string(),
        vec!["ck.agent.interop_session.stream_status".to_owned()],
        Vec::new(),
    );
    let status = op(
        realm_id,
        "0000000007b6",
        kinds::CK_AGENT_INTEROP_SESSION_STATUS,
        json!({
            "sender": "did:web:bob.example",
            "session_id": session_id,
            "status": "working"
        }),
    );

    assert_eq!(
        validate_operation_policy(&state, &[status])
            .await
            .unwrap_err(),
        "interop_session_writer_unauthorized"
    );
}

#[tokio::test]
async fn agent_interop_session_status_allows_session_scoped_delegate() {
    let state = test_state();
    let realm_id =
        cokret_sdk::RealmId::new("ck:realm:01904100-0000-7000-8000-0000000007b7".to_owned())
            .unwrap();
    let session_id = "ck:agent_interop_session:01904100-0000-7000-8000-0000000007b7";
    insert_agent_interop_session_start(
        &state,
        &realm_id,
        "0000000007b7",
        "did:web:alice.example",
        session_id,
    )
    .await;
    let session = cokret_sdk::AgentInteropSessionId::new(session_id.to_owned())
        .expect("valid agent interop session id");
    state.authz.create_grant(
        realm_id.to_string(),
        "did:web:alice.example".to_owned(),
        "did:web:bob.example".to_owned(),
        realm_id.to_string(),
        vec!["ck.agent.interop_session.stream_status".to_owned()],
        vec![crate::authz::Constraint::AllowedSessionIds {
            allowed_session_ids: std::collections::BTreeSet::from([session]),
        }],
    );
    let status = op(
        realm_id,
        "0000000007b8",
        kinds::CK_AGENT_INTEROP_SESSION_STATUS,
        json!({
            "sender": "did:web:bob.example",
            "session_id": session_id,
            "status": "working"
        }),
    );

    validate_operation_policy(&state, &[status])
        .await
        .expect("session-scoped delegate can write status for listed session");
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
                history_basis_seals: Vec::new(),
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
