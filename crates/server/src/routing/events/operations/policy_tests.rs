use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::{Signer as _, SigningKey};
use serde_json::json;
use soland_data::Db;

use super::*;
use crate::state::{CanonicalEventRecord, DeviceInventoryRecord, DirectConversationBindingRecord};

fn test_config() -> crate::config::AppConfig {
    crate::config::AppConfig {
        object_storage: crate::config::ObjectStorageConfig::local(
            std::env::temp_dir().join("soland-direct-conversation-policy-test-blobs"),
        ),
        development_mode: true,
        did_resolver_allow_methods: vec!["web".to_owned(), "key".to_owned()],
        jws_replay_window_seconds: 0,
        jws_replay_window_per_family: std::collections::BTreeMap::new(),
        notary_signing_key_seed: Some([9u8; 32]),
        seed_demo_data: true,
        ..crate::config::AppConfig::test_default()
    }
}

fn state_with_direct_binding() -> (AppState, arkret_sdk::RealmId) {
    let state = AppState::new(test_config(), Db { pool: None });
    let realm_id =
        arkret_sdk::RealmId::new("ak:realm:01904100-0000-7000-8000-000000000601".to_owned())
            .unwrap();
    let now = chrono::Utc::now();
    state.direct_conversation_bindings.lock().insert(
        "did:web:alice.example\0did:web:bob.example".to_owned(),
        DirectConversationBindingRecord {
            participants_unordered: vec![
                "did:web:alice.example".to_owned(),
                "did:web:bob.example".to_owned(),
            ],
            realm_id: realm_id.to_string(),
            main_strand_id: "ak:strand:01904100-0000-7000-8000-000000000601".to_owned(),
            binding_event_ref: "ak:event:01904100-0000-7000-8000-000000000601".to_owned(),
            state: "active".to_owned(),
            created_at: now,
            updated_at: now,
        },
    );
    (state, realm_id)
}

fn op(
    realm_id: arkret_sdk::RealmId,
    seed: &str,
    kind: &str,
    payload: serde_json::Value,
) -> Operation {
    Operation::create(
        arkret_sdk::OperationId::new(format!("ak:operation:01904100-0000-7000-8000-{seed}"))
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
        "device_id": "ak:device:019eefcb-5882-7861-bc30-3033fa32dcf6",
        "device_public_key": "z6MkjHNtpwuhc2QSXzkf4DWoWp7eSMKB9PzfdnvaLB7kb3dG",
        "hpke_key": "z6LSgy7T8CEsMDMzk1e4EBFVX8CDXWWzvkFZWSXhsC97zjcM",
        "algorithms": ["ck.hpke_x25519_aead_chacha20poly1305.v1", "ck.mls.v1"],
        "authorized_by": "did:key:z6MknBuwKMPAzbhp6EwCnaxsEDk4G2KFeWRu273gYVuTY5jw",
        "not_before": "2026-06-22T14:45:51Z",
        "enrollment_authority_binding": {
            "kind": "service_attested",
            "authority_did": "did:key:z6MknBuwKMPAzbhp6EwCnaxsEDk4G2KFeWRu273gYVuTY5jw",
            "authorization_ref": "did:webvh:zQmZcDaFwUR8yQCZRkXoYEBi9hdzMSCCLASUVdwT1J4Qyc6:local.host:webvh:01kvqwpxssfq3bqm15rcd0g99x#enrollment-authority"
        },
        "event_id": "ak:event:019eefcb-7fb2-7890-bffd-1f2035356fbf",
        "sender": "did:webvh:zQmZcDaFwUR8yQCZRkXoYEBi9hdzMSCCLASUVdwT1J4Qyc6:local.host:webvh:01kvqwpxssfq3bqm15rcd0g99x",
        "hlc": "019eefcb7d18-0000-8adcfdb5",
        "executed_by": "did:key:z6MknBuwKMPAzbhp6EwCnaxsEDk4G2KFeWRu273gYVuTY5jw",
        "authorization_ref": "did:webvh:zQmZcDaFwUR8yQCZRkXoYEBi9hdzMSCCLASUVdwT1J4Qyc6:local.host:webvh:01kvqwpxssfq3bqm15rcd0g99x#enrollment-authority"
    });

    crate::routing::identity::cross_signing::validate_device_authorize_binding(&state, &payload)
        .unwrap();
}

fn signed_service_attested_device_authorize_payload(
    device_signer: &SigningKey,
    signing_key: &SigningKey,
) -> serde_json::Value {
    let device_public_key =
        arkret_sdk::ed25519_pubkey_to_did_key_multibase(device_signer.verifying_key().as_bytes());
    let mut payload = json!({
        "principal_id": "did:webvh:zQmZcDaFwUR8yQCZRkXoYEBi9hdzMSCCLASUVdwT1J4Qyc6:local.host:webvh:01kvqwpxssfq3bqm15rcd0g99x",
        "device_id": "ak:device:019eefcb-5882-7861-bc30-3033fa32dcf6",
        "device_public_key": device_public_key,
        "hpke_key": "z6LSgy7T8CEsMDMzk1e4EBFVX8CDXWWzvkFZWSXhsC97zjcM",
        "algorithms": ["ck.hpke_x25519_aead_chacha20poly1305.v1", "ck.mls.v1"],
        "device_key_algorithm": "EdDSA",
        "authorized_by": "did:key:z6MknBuwKMPAzbhp6EwCnaxsEDk4G2KFeWRu273gYVuTY5jw",
        "not_before": "2026-06-22T14:45:51Z",
        "enrollment_authority_binding": {
            "kind": "service_attested",
            "authority_did": "did:key:z6MknBuwKMPAzbhp6EwCnaxsEDk4G2KFeWRu273gYVuTY5jw",
            "authorization_ref": "did:webvh:zQmZcDaFwUR8yQCZRkXoYEBi9hdzMSCCLASUVdwT1J4Qyc6:local.host:webvh:01kvqwpxssfq3bqm15rcd0g99x#enrollment-authority"
        }
    });
    let typed: arkret_sdk::DeviceAuthorizePayload =
        serde_json::from_value(payload.clone()).expect("typed device authorize payload");
    let input = typed
        .device_possession_signature_input()
        .expect("device signature input");
    let signature = signing_key.sign(&input);
    payload["device_signature"] = json!(URL_SAFE_NO_PAD.encode(signature.to_bytes()));
    payload
}

#[test]
fn device_authorize_validates_device_possession_signature() {
    let state = test_state();
    let device_signer = SigningKey::from_bytes(&[7u8; 32]);
    let payload = signed_service_attested_device_authorize_payload(&device_signer, &device_signer);

    crate::routing::identity::cross_signing::validate_device_authorize_binding(&state, &payload)
        .unwrap();
}

#[test]
fn device_authorize_rejects_signature_from_wrong_device_key() {
    let state = test_state();
    let device_signer = SigningKey::from_bytes(&[7u8; 32]);
    let wrong_signer = SigningKey::from_bytes(&[8u8; 32]);
    let payload = signed_service_attested_device_authorize_payload(&device_signer, &wrong_signer);

    assert_eq!(
        crate::routing::identity::cross_signing::validate_device_authorize_binding(
            &state, &payload
        ),
        Err("device_authorize_device_signature_invalid")
    );
}

fn grant_circle_action(
    state: &AppState,
    realm_id: &arkret_sdk::RealmId,
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
            allowed_circle_ids: std::collections::BTreeSet::from([arkret_sdk::CircleId::new(
                circle_id.to_owned(),
            )
            .expect("valid circle id")]),
        }],
    );
}

fn grant_moderation_decision(state: &AppState, realm_id: &arkret_sdk::RealmId, actor: &str) {
    state.authz.create_grant(
        realm_id.to_string(),
        "did:web:owner.example".to_owned(),
        actor.to_owned(),
        realm_id.to_string(),
        vec![arkret_sdk::events::kinds::MODERATION_DECISION.to_owned()],
        Vec::new(),
    );
}

fn grant_call_action(state: &AppState, realm_id: &arkret_sdk::RealmId, actor: &str, action: &str) {
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
    use arkret_sdk::lattice::CellState;

    let now = chrono::Utc::now();
    let mut projection = state.projection.lock();
    let cell_id = arkret_sdk::CellRef::new(format!(
        "ak:cell:ck.component.realm.read_receipt_policy.v1:{parent_realm_id}"
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
            operation_id: "ak:operation:01904100-0000-7000-8000-000000009901".to_owned(),
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
    let parent_realm = "ak:realm:01904100-0000-7000-8000-000000009911";
    let child_realm =
        arkret_sdk::RealmId::new("ak:realm:01904100-0000-7000-8000-000000009912".to_owned())
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
        arkret_sdk::events::kinds::REALM_READ_RECEIPT_POLICY,
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
    let parent_realm = "ak:realm:01904100-0000-7000-8000-000000009921";
    let child_realm =
        arkret_sdk::RealmId::new("ak:realm:01904100-0000-7000-8000-000000009922".to_owned())
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
        arkret_sdk::events::kinds::REALM_READ_RECEIPT_POLICY,
        json!({
            "disclosure": "disabled",
            "visibility": "private"
        }),
    );
    assert_eq!(
        validate_operation_policy(&state, &[child_policy])
            .await
            .unwrap_err(),
        arkret_sdk::ERROR_CODE_READ_RECEIPT_COMPLIANCE_FLOOR_VIOLATED
    );
}

#[tokio::test]
async fn read_receipt_child_policy_allows_required_floor_escape() {
    let state = test_state();
    let parent_realm = "ak:realm:01904100-0000-7000-8000-000000009931";
    let child_realm =
        arkret_sdk::RealmId::new("ak:realm:01904100-0000-7000-8000-000000009932".to_owned())
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
        arkret_sdk::events::kinds::REALM_READ_RECEIPT_POLICY,
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
    let parent_realm = "ak:realm:01904100-0000-7000-8000-000000009941";
    let child_realm =
        arkret_sdk::RealmId::new("ak:realm:01904100-0000-7000-8000-000000009942".to_owned())
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
        arkret_sdk::events::kinds::REALM_READ_RECEIPT_POLICY,
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
        arkret_sdk::RealmId::new("ak:realm:01904100-0000-7000-8000-000000009951".to_owned())
            .unwrap();
    let circle_id = "ak:circle:01904100-0000-7000-8000-000000009952";
    let strand_id = "ak:strand:01904100-0000-7000-8000-000000009953";
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
        arkret_sdk::events::kinds::STRAND_CREATE,
        json!({
            "sender": "did:web:alice.example",
            "object": {
                "id": strand_id,
                "realm_id": "ak:realm:01904100-0000-7000-8000-000000009951",
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
        arkret_sdk::RealmId::new("ak:realm:01904100-0000-7000-8000-000000009961".to_owned())
            .unwrap();
    let circle_id = "ak:circle:01904100-0000-7000-8000-000000009962";
    let strand_id =
        arkret_sdk::StrandId::new("ak:strand:01904100-0000-7000-8000-000000009963".to_owned())
            .unwrap();
    {
        let mut projection = state.projection.lock();
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

    let scope = arkret_sdk::models::AgentParticipationScope::Strand {
        realm_id,
        strand_id,
    };
    let ceiling =
        crate::routing::agent_participation::resolve_effective_ceiling(&state, &scope).await;
    assert!(!ceiling.accept_third_party_mention);
    let selection = arkret_sdk::models::AgentParticipation {
        reply: true,
        accept_third_party_mention: true,
        act_on_behalf: false,
    };
    assert!(matches!(
        arkret_sdk::models::validate_selection_within_ceiling(ceiling, selection),
        Err(arkret_sdk::models::AgentParticipationError::ExceedsCeiling { .. })
    ));
}

async fn register_agent_selection(
    state: &AppState,
    realm_id: &arkret_sdk::RealmId,
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
        .strip_prefix("ak:realm:")
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

fn reply_message(
    realm_id: arkret_sdk::RealmId,
    seed: &str,
    agent_principal_id: &str,
    authorization_ref: &str,
) -> Operation {
    op(
        realm_id,
        seed,
        arkret_sdk::events::kinds::MESSAGE_CREATE,
        json!({
            "sender": agent_principal_id,
            "content": [{"type": "text", "text": "agent reply"}],
            "agent_context": agent_context(agent_principal_id, authorization_ref),
        }),
    )
}

fn act_on_behalf_message(
    realm_id: arkret_sdk::RealmId,
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
    op(
        realm_id,
        seed,
        arkret_sdk::events::kinds::MESSAGE_CREATE,
        payload,
    )
}

fn insert_approved_agent_action(
    state: &AppState,
    message: &Operation,
    request_id: &str,
    agent_principal_id: &str,
    approval_nonce: &str,
) {
    let payload_digest = arkret_sdk::canonical::canonical_sha256(&message.payload).unwrap();
    state.projection.lock().agent_action_requests.insert(
        request_id.to_owned(),
        crate::reducer::AgentActionRequestProjection {
            request_id: request_id.to_owned(),
            agent_principal_id: agent_principal_id.to_owned(),
            status: crate::reducer::AgentActionRequestStatus::Approved,
            requested_at: message.created_at - chrono::Duration::minutes(1),
            resolved_at: Some(message.created_at),
            resolution_event_id: Some("ak:event:01904100-0000-7000-8000-0000000007aa".to_owned()),
            cancel_reason: None,
            approval: Some(crate::reducer::AgentActionApprovalProjection {
                approval_id: "ak:agent_approval:01904100-0000-7000-8000-0000000007aa".to_owned(),
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
    realm_id: &arkret_sdk::RealmId,
    seed: &str,
    actor: &str,
    session_id: &str,
) {
    state
        .persistence
        .events()
        .put(CanonicalEventRecord {
            event_id: format!("ak:event:01904100-0000-7000-8000-{seed}"),
            actor_id: actor.to_owned(),
            actor_seq: 1,
            realm_id: Some(realm_id.to_string()),
            kind: arkret_sdk::events::kinds::AGENT_INTEROP_SESSION_START.to_owned(),
            schema_id: "ck.schema.event.v1".to_owned(),
            canonical_digest: "sha256:test".to_owned(),
            canonical_bytes: Vec::new(),
            envelope: json!({
                "actor_id": actor,
                "kind": arkret_sdk::events::kinds::AGENT_INTEROP_SESSION_START,
                "realm_id": realm_id.to_string(),
                "payload": {
                    "sender": actor,
                    "session_id": session_id,
                    "counterparty_agent": "did:web:remote-agent.example",
                    "protocol": "mcp",
                    "capability_grant": "ak:grant:01904100-0000-7000-8000-0000000000ff"
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
        arkret_sdk::events::kinds::INVITE_CREATE,
        json!({
            "invite_id": "ak:invite:01904100-0000-7000-8000-000000000601",
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
        arkret_sdk::events::kinds::SPACE_CREATE,
        json!({
            "space_id": "ak:space:01904100-0000-7000-8000-000000000602",
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
        arkret_sdk::events::kinds::MEMBER_STATE,
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
        arkret_sdk::RealmId::new("ak:realm:01904100-0000-7000-8000-000000000701".to_owned())
            .unwrap();
    let agent = "did:web:agent.example";
    register_agent_selection(&state, &realm_id, agent, true, false).await;
    let grant = state.authz.create_grant(
        realm_id.to_string(),
        "did:web:alice.example".to_owned(),
        agent.to_owned(),
        realm_id.to_string(),
        vec![arkret_sdk::events::kinds::MESSAGE_CREATE.to_owned()],
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
        arkret_sdk::RealmId::new("ak:realm:01904100-0000-7000-8000-000000000702".to_owned())
            .unwrap();
    let agent = "did:web:agent.example";
    register_agent_selection(&state, &realm_id, agent, true, true).await;
    let grant = state.authz.create_grant(
        realm_id.to_string(),
        "did:web:alice.example".to_owned(),
        agent.to_owned(),
        realm_id.to_string(),
        vec![arkret_sdk::events::kinds::REACTION_ADD.to_owned()],
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
        arkret_sdk::RealmId::new("ak:realm:01904100-0000-7000-8000-0000000007a2".to_owned())
            .unwrap();
    let agent = "did:web:agent.example";
    register_agent_selection(&state, &realm_id, agent, true, true).await;
    let operation = op(
        realm_id,
        "0000000007a2",
        arkret_sdk::events::kinds::STRAND_CREATE,
        json!({
            "sender": "did:web:alice.example",
            "executed_by": agent,
            "object": {
                "id": "ak:strand:01904100-0000-7000-8000-0000000007a2",
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
        arkret_sdk::RealmId::new("ak:realm:01904100-0000-7000-8000-0000000007c1".to_owned())
            .unwrap();
    let agent = "did:web:agent.example";
    register_agent_selection(&state, &realm_id, agent, true, true).await;
    let grant = state.authz.create_grant(
        realm_id.to_string(),
        "did:web:alice.example".to_owned(),
        agent.to_owned(),
        realm_id.to_string(),
        vec![arkret_sdk::events::kinds::STRAND_CREATE.to_owned()],
        Vec::new(),
    );
    let operation = op(
        realm_id,
        "0000000007c1",
        arkret_sdk::events::kinds::STRAND_CREATE,
        json!({
            "sender": "did:web:alice.example",
            "executed_by": agent,
            "authorization_ref": grant.grant_id,
            "object": {
                "id": "ak:strand:01904100-0000-7000-8000-0000000007c1",
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
async fn native_agent_member_target_uses_sender_for_agent_write_detection() {
    let state = test_state();
    let realm_id =
        arkret_sdk::RealmId::new("ak:realm:01904100-0000-7000-8000-0000000007b1".to_owned())
            .unwrap();
    let agent = "did:web:agent.example";
    register_agent_selection(&state, &realm_id, agent, true, true).await;
    let operation = op(
        realm_id,
        "0000000007b1",
        arkret_sdk::events::kinds::MEMBER_STATE,
        json!({
            "sender": "did:web:alice.example",
            "actor_id": agent,
            "membership": "join",
            "realm_id": "ak:realm:01904100-0000-7000-8000-0000000007b1",
            "delivery_status": "unroutable"
        }),
    );

    validate_agent_reply_participation(&state, &[operation])
        .await
        .expect("membership target must not be treated as the executing agent");
}

#[tokio::test]
async fn act_on_behalf_agent_relation_write_rejects_context_authorization_mismatch() {
    let state = test_state();
    let realm_id =
        arkret_sdk::RealmId::new("ak:realm:01904100-0000-7000-8000-0000000007c2".to_owned())
            .unwrap();
    let agent = "did:web:agent.example";
    register_agent_selection(&state, &realm_id, agent, true, true).await;
    let envelope_grant = state.authz.create_grant(
        realm_id.to_string(),
        "did:web:alice.example".to_owned(),
        agent.to_owned(),
        realm_id.to_string(),
        vec![arkret_sdk::events::kinds::RELATION_CREATE.to_owned()],
        Vec::new(),
    );
    let context_grant = state.authz.create_grant(
        realm_id.to_string(),
        "did:web:alice.example".to_owned(),
        agent.to_owned(),
        realm_id.to_string(),
        vec![arkret_sdk::events::kinds::RELATION_CREATE.to_owned()],
        Vec::new(),
    );
    let operation = op(
        realm_id,
        "0000000007c2",
        arkret_sdk::events::kinds::RELATION_CREATE,
        json!({
            "sender": "did:web:alice.example",
            "executed_by": agent,
            "authorization_ref": envelope_grant.grant_id,
            "agent_context": agent_context(agent, context_grant.grant_id.as_str()),
            "relation_id": "ak:relation:01904100-0000-7000-8000-0000000007c2",
            "relation_kind": "references",
            "from_ref": "ak:strand:01904100-0000-7000-8000-0000000007c2",
            "to_ref": "ak:strand:01904100-0000-7000-8000-0000000007c3"
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
        arkret_sdk::RealmId::new("ak:realm:01904100-0000-7000-8000-0000000007c3".to_owned())
            .unwrap();
    let operation = op(
        realm_id,
        "0000000007c3",
        arkret_sdk::events::kinds::RELATION_CREATE,
        json!({
            "sender": "did:web:alice.example",
            "provenance": {
                "actor_kind": "agent"
            },
            "relation_id": "ak:relation:01904100-0000-7000-8000-0000000007c3",
            "relation_kind": "references",
            "from_ref": "ak:strand:01904100-0000-7000-8000-0000000007c4",
            "to_ref": "ak:strand:01904100-0000-7000-8000-0000000007c5"
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
        arkret_sdk::RealmId::new("ak:realm:01904100-0000-7000-8000-0000000007c4".to_owned())
            .unwrap();
    let agent = "did:web:agent.example";
    register_agent_selection(&state, &realm_id, agent, true, true).await;
    let grant = state.authz.create_grant(
        realm_id.to_string(),
        "did:web:alice.example".to_owned(),
        agent.to_owned(),
        realm_id.to_string(),
        vec![arkret_sdk::events::kinds::VIEW_CREATE.to_owned()],
        Vec::new(),
    );
    let grant_id = grant.grant_id.clone();
    let operation = op(
        realm_id,
        "0000000007c4",
        arkret_sdk::events::kinds::VIEW_CREATE,
        json!({
            "sender": "did:web:alice.example",
            "executed_by": agent,
            "authorization_ref": grant_id.as_str(),
            "agent_context": agent_context(agent, grant_id.as_str()),
            "view_id": "ak:view:01904100-0000-7000-8000-0000000007c4",
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
        arkret_sdk::RealmId::new("ak:realm:01904100-0000-7000-8000-0000000007c5".to_owned())
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
        arkret_sdk::RealmId::new("ak:realm:01904100-0000-7000-8000-0000000007c6".to_owned())
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
async fn reply_agent_lifecycle_state_blocks_writes_even_with_participation() {
    let state = test_state();
    let realm_id =
        arkret_sdk::RealmId::new("ak:realm:01904100-0000-7000-8000-0000000007c7".to_owned())
            .unwrap();
    let agent = "did:web:agent.example";
    register_agent_selection(&state, &realm_id, agent, true, false).await;
    let grant = state.authz.create_grant(
        realm_id.to_string(),
        "did:web:alice.example".to_owned(),
        agent.to_owned(),
        realm_id.to_string(),
        vec![arkret_sdk::events::kinds::MESSAGE_CREATE.to_owned()],
        Vec::new(),
    );
    let mut record = state
        .persistence
        .agents()
        .get(agent)
        .await
        .expect("agent lookup")
        .expect("agent record");
    record["state"] = json!("paused");
    state
        .persistence
        .agents()
        .put(record)
        .await
        .expect("agent record update");
    let operation = reply_message(realm_id, "0000000007c7", agent, grant.grant_id.as_str());

    assert_eq!(
        validate_agent_reply_participation(&state, &[operation])
            .await
            .unwrap_err(),
        "agent_paused"
    );
}

#[tokio::test]
async fn reply_agent_projected_deactivation_blocks_writes_even_with_active_record() {
    let state = test_state();
    let realm_id =
        arkret_sdk::RealmId::new("ak:realm:01904100-0000-7000-8000-0000000007c8".to_owned())
            .unwrap();
    let agent = "did:web:agent.example";
    register_agent_selection(&state, &realm_id, agent, true, false).await;
    let grant = state.authz.create_grant(
        realm_id.to_string(),
        "did:web:alice.example".to_owned(),
        agent.to_owned(),
        realm_id.to_string(),
        vec![arkret_sdk::events::kinds::MESSAGE_CREATE.to_owned()],
        Vec::new(),
    );
    state.projection.lock().agent_lifecycles.insert(
        agent.to_owned(),
        arkret_sdk::AgentLifecycleState::Deactivated,
    );
    let operation = reply_message(realm_id, "0000000007c8", agent, grant.grant_id.as_str());

    assert_eq!(
        validate_agent_reply_participation(&state, &[operation])
            .await
            .unwrap_err(),
        "agent_deactivated"
    );
}

#[tokio::test]
async fn profile_accountable_principal_requires_active_grant() {
    let state = test_state();
    let realm_id =
        arkret_sdk::RealmId::new("ak:realm:01904100-0000-7000-8000-0000000007a3".to_owned())
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
        arkret_sdk::RealmId::new("ak:realm:01904100-0000-7000-8000-0000000007a4".to_owned())
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
        arkret_sdk::RealmId::new("ak:realm:01904100-0000-7000-8000-0000000007a6".to_owned())
            .unwrap();
    state
        .persistence
        .events()
        .put(CanonicalEventRecord {
            event_id: "ak:event:01904100-0000-7000-8000-0000000007a6".to_owned(),
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
        arkret_sdk::RealmId::new("ak:realm:01904100-0000-7000-8000-000000000881".to_owned())
            .unwrap();
    let member_add = op(
        realm_id,
        "000000000881",
        arkret_sdk::events::kinds::CIRCLE_MEMBER_STATE,
        json!({
            "sender": "did:web:alice.example",
            "circle_id": "ak:circle:01904100-0000-7000-8000-000000000881",
            "actor_id": "did:web:bob.example",
            "membership": "join",
            "manage_capability_verified": true,
            "actor_capability": {
                "action": "ck.circle.member.manage",
                "circle_id": "ak:circle:01904100-0000-7000-8000-000000000881",
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
        arkret_sdk::RealmId::new("ak:realm:01904100-0000-7000-8000-000000000882".to_owned())
            .unwrap();
    let circle_id = "ak:circle:01904100-0000-7000-8000-000000000882";
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
        arkret_sdk::events::kinds::CIRCLE_MEMBER_STATE,
        json!({
            "sender": "did:web:alice.example",
            "circle_id": circle_id,
            "actor_id": "did:web:bob.example",
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
        arkret_sdk::RealmId::new("ak:realm:01904100-0000-7000-8000-000000000883".to_owned())
            .unwrap();
    let circle_id = "ak:circle:01904100-0000-7000-8000-000000000883";
    let tombstone = op(
        realm_id.clone(),
        "000000000883",
        arkret_sdk::events::kinds::CIRCLE_TOMBSTONE,
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
        arkret_sdk::RealmId::new("ak:realm:01904100-0000-7000-8000-0000000007b1".to_owned())
            .unwrap();
    let session_id = "ak:agent_interop_session:01904100-0000-7000-8000-0000000007b1";
    let start = op(
        realm_id.clone(),
        "0000000007b1",
        arkret_sdk::events::kinds::AGENT_INTEROP_SESSION_START,
        json!({
            "sender": "did:web:alice.example",
            "session_id": session_id,
            "counterparty_agent": "did:web:remote-agent.example",
            "protocol": "mcp",
            "capability_grant": "ak:grant:01904100-0000-7000-8000-0000000007b1"
        }),
    );
    let status = op(
        realm_id,
        "0000000007b2",
        arkret_sdk::events::kinds::AGENT_INTEROP_SESSION_STATUS,
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
        arkret_sdk::RealmId::new("ak:realm:01904100-0000-7000-8000-0000000007b3".to_owned())
            .unwrap();
    let session_id = "ak:agent_interop_session:01904100-0000-7000-8000-0000000007b3";
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
        arkret_sdk::events::kinds::AGENT_INTEROP_SESSION_STATUS,
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
        arkret_sdk::RealmId::new("ak:realm:01904100-0000-7000-8000-0000000007b5".to_owned())
            .unwrap();
    let session_id = "ak:agent_interop_session:01904100-0000-7000-8000-0000000007b5";
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
        arkret_sdk::events::kinds::AGENT_INTEROP_SESSION_STATUS,
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
        arkret_sdk::RealmId::new("ak:realm:01904100-0000-7000-8000-0000000007b7".to_owned())
            .unwrap();
    let session_id = "ak:agent_interop_session:01904100-0000-7000-8000-0000000007b7";
    insert_agent_interop_session_start(
        &state,
        &realm_id,
        "0000000007b7",
        "did:web:alice.example",
        session_id,
    )
    .await;
    let session = arkret_sdk::AgentInteropSessionId::new(session_id.to_owned())
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
        arkret_sdk::events::kinds::AGENT_INTEROP_SESSION_STATUS,
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
        arkret_sdk::RealmId::new("ak:realm:01904100-0000-7000-8000-000000000703".to_owned())
            .unwrap();
    let agent = "did:web:agent.example";
    register_agent_selection(&state, &realm_id, agent, true, true).await;
    let grant = state.authz.create_grant(
        realm_id.to_string(),
        "did:web:alice.example".to_owned(),
        agent.to_owned(),
        realm_id.to_string(),
        vec![arkret_sdk::events::kinds::MESSAGE_CREATE.to_owned()],
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
        arkret_sdk::RealmId::new("ak:realm:01904100-0000-7000-8000-000000000704".to_owned())
            .unwrap();
    let agent = "did:web:agent.example";
    register_agent_selection(&state, &realm_id, agent, true, true).await;
    let grant = state.authz.create_grant(
        realm_id.to_string(),
        "did:web:alice.example".to_owned(),
        agent.to_owned(),
        realm_id.to_string(),
        vec![arkret_sdk::events::kinds::MESSAGE_CREATE.to_owned()],
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
        arkret_sdk::RealmId::new("ak:realm:01904100-0000-7000-8000-000000000705".to_owned())
            .unwrap();
    let agent = "did:web:agent.example";
    register_agent_selection(&state, &realm_id, agent, true, true).await;
    let grant = state.authz.create_grant(
        realm_id.to_string(),
        "did:web:alice.example".to_owned(),
        agent.to_owned(),
        realm_id.to_string(),
        vec![arkret_sdk::events::kinds::MESSAGE_CREATE.to_owned()],
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
        arkret_sdk::error::REASON_APPROVAL_NONCE_REUSED
    );
}

#[tokio::test]
async fn circle_scoped_relation_update_and_delete_require_circle_membership() {
    let state = test_state();
    let realm_id =
        arkret_sdk::RealmId::new("ak:realm:01904100-0000-7000-8000-000000000801".to_owned())
            .unwrap();
    let circle_id = "ak:circle:01904100-0000-7000-8000-000000000801";
    let relation_id = "ak:relation:01904100-0000-7000-8000-000000000801";
    let now = chrono::Utc::now();
    {
        let mut projection = state.projection.lock();
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
                from_ref: Some("ak:strand:01904100-0000-7000-8000-000000000811".to_owned()),
                to_ref: Some("ak:strand:01904100-0000-7000-8000-000000000812".to_owned()),
                fields: Default::default(),
                state: "active".to_owned(),
                source_event_id: Some("ak:event:01904100-0000-7000-8000-000000000801".to_owned()),
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
        arkret_sdk::events::kinds::RELATION_UPDATE,
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
        arkret_sdk::events::kinds::RELATION_UPDATE,
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
        arkret_sdk::events::kinds::RELATION_TOMBSTONE,
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
        arkret_sdk::RealmId::new("ak:realm:01904100-0000-7000-8000-000000000901".to_owned())
            .unwrap();
    grant_moderation_decision(&state, &realm_id, "did:web:moderator.example");
    let decision = op(
        realm_id,
        "000000000901",
        arkret_sdk::events::kinds::MODERATION_DECISION,
        json!({
            "sender": "did:web:moderator.example",
            "issuer": "did:web:impostor.example",
            "target_ref": "ak:message:01904100-0000-7000-8000-000000000901",
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
        arkret_sdk::RealmId::new("ak:realm:01904100-0000-7000-8000-000000000902".to_owned())
            .unwrap();
    grant_moderation_decision(&state, &realm_id, "did:web:moderator.example");
    let decision = op(
        realm_id,
        "000000000902",
        arkret_sdk::events::kinds::MODERATION_DECISION,
        json!({
            "sender": "did:web:moderator.example",
            "issuer": "did:web:moderator.example",
            "target_ref": "ak:message:01904100-0000-7000-8000-000000000902",
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
        arkret_sdk::RealmId::new("ak:realm:01904100-0000-7000-8000-000000000903".to_owned())
            .unwrap();
    grant_moderation_decision(&state, &realm_id, "did:web:moderator.example");
    let decision = op(
        realm_id,
        "000000000903",
        arkret_sdk::events::kinds::MODERATION_DECISION,
        json!({
            "sender": "did:web:moderator.example",
            "target_ref": "ak:message:01904100-0000-7000-8000-000000000903",
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
        arkret_sdk::RealmId::new("ak:realm:01904100-0000-7000-8000-000000000904".to_owned())
            .unwrap();
    grant_call_action(
        &state,
        &realm_id,
        "did:web:recorder.example",
        arkret_sdk::CAP_ACTION_CALL_RECORD,
    );
    let start = op(
        realm_id,
        "000000000904",
        arkret_sdk::events::kinds::CALL_RECORDING_START,
        json!({
            "sender": "did:web:recorder.example",
            "call_id": "ak:call:01904100-0000-7000-8000-000000000904",
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
        arkret_sdk::RealmId::new("ak:realm:01904100-0000-7000-8000-000000000905".to_owned())
            .unwrap();
    grant_call_action(
        &state,
        &realm_id,
        "did:web:recorder.example",
        arkret_sdk::CAP_ACTION_CALL_RECORD,
    );
    let start = op(
        realm_id,
        "000000000905",
        arkret_sdk::events::kinds::CALL_RECORDING_START,
        json!({
            "sender": "did:web:recorder.example",
            "call_id": "ak:call:01904100-0000-7000-8000-000000000905",
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
        arkret_sdk::RealmId::new("ak:realm:01904100-0000-7000-8000-000000000906".to_owned())
            .unwrap();
    grant_call_action(
        &state,
        &realm_id,
        "did:web:recorder.example",
        arkret_sdk::CAP_ACTION_CALL_TRANSCRIBE,
    );
    let start = op(
        realm_id,
        "000000000906",
        arkret_sdk::events::kinds::CALL_RECORDING_START,
        json!({
            "sender": "did:web:recorder.example",
            "call_id": "ak:call:01904100-0000-7000-8000-000000000906",
            "recording_id": "transcript-906",
            "capture_kind": "transcript"
        }),
    );

    validate_operation_policy(&state, &[start])
        .await
        .expect("ck.call.transcribe should authorize transcript capture");
}

#[tokio::test]
async fn mls_prejoin_history_rejects_non_history_capable_content_scheme() {
    let state = test_state();
    let realm_id =
        arkret_sdk::RealmId::new("ak:realm:01904100-0000-7000-8000-00000000c100".to_owned())
            .unwrap();
    let create = op(
        realm_id.clone(),
        "00000000c101",
        arkret_sdk::events::kinds::REALM_CREATE,
        json!({
            "object": {
                "id": realm_id.as_str(),
                "title": "Prejoin history",
                "history_visibility": "shared",
                "encryption_profile": "mls_rfc9420"
            }
        }),
    );
    let strict_scheme = op(
        realm_id,
        "00000000c102",
        arkret_sdk::events::kinds::REALM_POLICY_COMPONENTS,
        json!({
            "value": {
                "content_scheme": "mls-rfc9420"
            }
        }),
    );

    let reason = validate_operation_policy(&state, &[create, strict_scheme])
        .await
        .unwrap_err();
    assert_eq!(
        reason,
        arkret_sdk::error::REASON_HISTORY_VISIBILITY_REQUIRES_HISTORY_CAPABLE_SCHEME
    );
    assert_eq!(
        operation_policy_reason_code(reason),
        (
            salvo::http::StatusCode::PRECONDITION_FAILED,
            "failed_precondition"
        )
    );
}

#[tokio::test]
async fn mls_prejoin_history_accepts_exporter_aead_content_scheme() {
    let state = test_state();
    let realm_id =
        arkret_sdk::RealmId::new("ak:realm:01904100-0000-7000-8000-00000000c200".to_owned())
            .unwrap();
    let create = op(
        realm_id.clone(),
        "00000000c201",
        arkret_sdk::events::kinds::REALM_CREATE,
        json!({
            "object": {
                "id": realm_id.as_str(),
                "title": "Prejoin history",
                "history_visibility": "shared",
                "encryption_profile": "mls_rfc9420"
            }
        }),
    );
    let exporter_scheme = op(
        realm_id,
        "00000000c202",
        arkret_sdk::events::kinds::REALM_POLICY_COMPONENTS,
        json!({
            "value": {
                "content_scheme": "mls-exporter-aead-v1"
            }
        }),
    );

    validate_operation_policy(&state, &[create, exporter_scheme])
        .await
        .expect("pre-join history is valid when the MLS realm declares exporter-AEAD");
}

#[tokio::test]
async fn mls_prejoin_history_accepts_create_object_exporter_aead_content_scheme() {
    let state = test_state();
    let realm_id =
        arkret_sdk::RealmId::new("ak:realm:01904100-0000-7000-8000-00000000c210".to_owned())
            .unwrap();
    let create = op(
        realm_id.clone(),
        "00000000c211",
        arkret_sdk::events::kinds::REALM_CREATE,
        json!({
            "object": {
                "id": realm_id.as_str(),
                "title": "Prejoin history",
                "history_visibility": "shared",
                "encryption_profile": "mls_rfc9420",
                "content_scheme": "mls-exporter-aead-v1"
            }
        }),
    );

    validate_operation_policy(&state, &[create])
        .await
        .expect("pre-join history is valid when ck.realm.create declares exporter-AEAD");
}

#[tokio::test]
async fn mls_prejoin_history_rejects_create_object_strict_content_scheme() {
    let state = test_state();
    let realm_id =
        arkret_sdk::RealmId::new("ak:realm:01904100-0000-7000-8000-00000000c220".to_owned())
            .unwrap();
    let create = op(
        realm_id.clone(),
        "00000000c221",
        arkret_sdk::events::kinds::REALM_CREATE,
        json!({
            "object": {
                "id": realm_id.as_str(),
                "title": "Prejoin history",
                "history_visibility": "shared",
                "encryption_profile": "mls_rfc9420",
                "content_scheme": "mls-rfc9420"
            }
        }),
    );

    let reason = validate_operation_policy(&state, &[create])
        .await
        .unwrap_err();
    assert_eq!(
        reason,
        arkret_sdk::error::REASON_HISTORY_VISIBILITY_REQUIRES_HISTORY_CAPABLE_SCHEME
    );
}

#[tokio::test]
async fn mls_strict_existing_realm_rejects_prejoin_history_update() {
    use arkret_sdk::lattice::CellState;

    let state = test_state();
    let realm_id =
        arkret_sdk::RealmId::new("ak:realm:01904100-0000-7000-8000-00000000c300".to_owned())
            .unwrap();
    let now = chrono::Utc::now();
    state
        .persistence
        .realm_meta()
        .put(
            realm_id.as_str(),
            &crate::state::RealmMetaRecord {
                owner: "did:web:alice.example".to_owned(),
                deleted: false,
                discoverability: "invite_only".to_owned(),
                history_visibility: "joined".to_owned(),
                history_sharing_policy: None,
                history_sharing_policy_digest: None,
                preview_policy: None,
                preview_policy_digest: None,
                asset_privacy_policy: None,
                asset_privacy_policy_digest: None,
                encryption_profile: Some("mls_rfc9420".to_owned()),
                plaintext_visible_services: std::collections::BTreeSet::new(),
                plaintext_visible_service_classes: std::collections::BTreeMap::new(),
                minimal_metadata_realm: false,
                created_at: now,
                updated_at: now,
            },
        )
        .await
        .expect("realm meta stored");
    {
        let mut projection = state.projection.lock();
        let cell_id = arkret_sdk::CellRef::new(format!(
            "ak:cell:ck.component.realm.policy_components.v1:{}",
            realm_id.as_str()
        ))
        .expect("valid policy_components cell ref");
        projection.cells.insert(
            cell_id,
            CellState::Value(json!({
                "content_scheme": "mls-rfc9420"
            })),
        );
    }
    let history_visibility = op(
        realm_id,
        "00000000c301",
        arkret_sdk::events::kinds::REALM_HISTORY_VISIBILITY,
        json!({
            "value": "shared"
        }),
    );

    assert_eq!(
        validate_operation_policy(&state, &[history_visibility])
            .await
            .unwrap_err(),
        arkret_sdk::error::REASON_HISTORY_VISIBILITY_REQUIRES_HISTORY_CAPABLE_SCHEME
    );
}

// encryption-and-audit.md §2.10.8 — an RRK-targeted `ck.realm_key.share` (to a
// declared recovery recipient) is accepted by the share-policy gate even though
// the recipient is NOT a member and the realm carries no history-sharing policy.
// The discriminator is structural: `recipient_principal_id` is a current
// `durability_policy.recovery_recipients[].principal_id`.
#[tokio::test]
async fn realm_key_share_rrk_targeted_is_accepted_for_recovery_recipient() {
    use arkret_sdk::lattice::CellState;

    let state = test_state();
    let realm_id =
        arkret_sdk::RealmId::new("ak:realm:01904100-0000-7000-8000-00000000d100".to_owned())
            .unwrap();
    let recovery_principal = "did:web:hr.example";

    // Seed the projected policy_components cell with an exporter-AEAD scheme +
    // org RRK durability policy naming `recovery_principal` as a recipient.
    {
        let mut projection = state.projection.lock();
        let cell_id = arkret_sdk::CellRef::new(format!(
            "ak:cell:ck.component.realm.policy_components.v1:{}",
            realm_id.as_str()
        ))
        .expect("valid policy_components cell ref");
        projection.cells.insert(
            cell_id,
            CellState::Value(json!({
                "content_scheme": "mls-exporter-aead-v1",
                "durability_policy": {
                    "mode": "org_recovery_key",
                    "recovery_recipients": [{
                        "recipient_id": "rrk-1",
                        "principal_id": recovery_principal,
                        "verification_method": format!("{recovery_principal}#rrk-1")
                    }]
                }
            })),
        );
    }

    let share = op(
        realm_id.clone(),
        "00000000d100",
        arkret_sdk::events::kinds::REALM_KEY_SHARE,
        json!({
            "share_class": "realm_recovery_key",
            "recipient_principal_id": recovery_principal,
            "recipient_verification_method": format!("{recovery_principal}#rrk-1"),
            "recovery_recipient_id": "rrk-1",
            "sender_device_id": "ak:device:01904100-0000-7000-8000-00000000d1d2",
            "sender_device_signature": {"alg": "EdDSA", "kid": "k", "sig": "s"},
            "key_scope": {
                "effective_scope": {"kind": "realm", "realm_id": realm_id.as_str()},
                "policy_digest": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
                "from_epoch": 1,
                "to_epoch": 3
            },
            "ciphertext": "hpke-sealed-history-secret",
            "created_at": "2026-06-25T00:00:00Z"
        }),
    );

    validate_realm_key_share_policy(&state, &share)
        .await
        .expect("RRK-targeted share to a recovery recipient must be accepted");
}

#[tokio::test]
async fn realm_key_share_member_device_accepts_projection_metadata() {
    let state = test_state();
    let realm_id =
        arkret_sdk::RealmId::new("ak:realm:01904100-0000-7000-8000-00000000d300".to_owned())
            .unwrap();
    let now = chrono::DateTime::parse_from_rfc3339("2026-07-05T00:00:00Z")
        .unwrap()
        .with_timezone(&chrono::Utc);
    let bob = "did:web:bob.example";
    let bob_device = "ak:device:01904100-0000-7000-8000-00000000d3d1";

    state
        .persistence
        .realm_meta()
        .put(
            realm_id.as_str(),
            &crate::state::RealmMetaRecord {
                owner: "did:web:alice.example".to_owned(),
                deleted: false,
                discoverability: "invite_only".to_owned(),
                history_visibility: "shared".to_owned(),
                history_sharing_policy: Some(json!({
                    "version": 1,
                    "default_key_share": "event_time_visibility",
                    "pre_join_history": "allow_if_visibility_allows",
                    "allowed_key_sources": ["verified_member_device"],
                    "allowed_receiver_states": ["active_member"],
                    "audit": {
                        "share_audit_event_required": false,
                        "access_audit_required": false
                    }
                })),
                history_sharing_policy_digest: Some(
                    "sha256:1111111111111111111111111111111111111111111111111111111111111111"
                        .to_owned(),
                ),
                preview_policy: None,
                preview_policy_digest: None,
                asset_privacy_policy: None,
                asset_privacy_policy_digest: None,
                encryption_profile: Some("mls_rfc9420".to_owned()),
                plaintext_visible_services: std::collections::BTreeSet::new(),
                plaintext_visible_service_classes: std::collections::BTreeMap::new(),
                minimal_metadata_realm: false,
                created_at: now,
                updated_at: now,
            },
        )
        .await
        .expect("realm meta stored");
    state
        .persistence
        .devices()
        .put(&DeviceInventoryRecord {
            actor: bob.to_owned(),
            device_id: bob_device.to_owned(),
            display_name: None,
            verification_state: "verified".to_owned(),
            payload: json!({"algorithms": ["ck.hpke_x25519_aead_chacha20poly1305.v1"]}),
            created_at: now,
            updated_at: now,
            revoked_at: None,
        })
        .await
        .expect("device stored");
    {
        let mut projection = state.projection.lock();
        projection.members.insert(
            (realm_id.to_string(), bob.to_owned()),
            crate::reducer::SolandMembershipState {
                member: bob.to_owned(),
                realm_id: realm_id.to_string(),
                state: "join".to_owned(),
                role: "member".to_owned(),
                delivery_status: Some("routable".to_owned()),
                recipient_service_did: Some("did:web:local.host".to_owned()),
                membership_event_ref: Some(
                    "ak:event:01904100-0000-7000-8000-00000000d3aa".to_owned(),
                ),
                delivery_binding_frontier: None,
                invited_at: Some(now),
                joined_at: now,
                updated_at: now,
            },
        );
    }

    let share = op(
        realm_id.clone(),
        "00000000d300",
        arkret_sdk::events::kinds::REALM_KEY_SHARE,
        json!({
            "share_class": "member_device",
            "recipient_principal_id": bob,
            "recipient_device_id": bob_device,
            "sender_device_id": "ak:device:01904100-0000-7000-8000-00000000d3d2",
            "sender_device_signature": {"alg": "EdDSA", "kid": "k", "sig": "s"},
            "key_scope": {
                "effective_scope": {"kind": "realm", "realm_id": realm_id.as_str()},
                "policy_digest": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
                "from_epoch": 1,
                "to_epoch": 3
            },
            "ciphertext": "sealed-history-secret",
            "created_at": "2026-07-05T00:00:00Z",
            "event_id": "ak:event:01904100-0000-7000-8000-00000000d300",
            "sender": "did:web:alice.example",
            "hlc": "2026-07-05T00:00:00Z/node/1"
        }),
    );

    validate_realm_key_share_policy(&state, &share)
        .await
        .expect("projected member-device share metadata must not poison policy parsing");
}

// A non-recovery, non-member recipient with no history-sharing policy still
// fails closed — the RRK branch only applies to declared recovery recipients.
#[tokio::test]
async fn realm_key_share_non_recovery_recipient_without_policy_is_rejected() {
    use arkret_sdk::lattice::CellState;

    let state = test_state();
    let realm_id =
        arkret_sdk::RealmId::new("ak:realm:01904100-0000-7000-8000-00000000d200".to_owned())
            .unwrap();
    {
        let mut projection = state.projection.lock();
        let cell_id = arkret_sdk::CellRef::new(format!(
            "ak:cell:ck.component.realm.policy_components.v1:{}",
            realm_id.as_str()
        ))
        .expect("valid policy_components cell ref");
        projection.cells.insert(
            cell_id,
            CellState::Value(json!({
                "content_scheme": "mls-exporter-aead-v1",
                "durability_policy": {
                    "mode": "org_recovery_key",
                    "recovery_recipients": [{
                        "recipient_id": "rrk-1",
                        "principal_id": "did:web:hr.example",
                        "verification_method": "did:web:hr.example#rrk-1"
                    }]
                }
            })),
        );
    }

    let share = op(
        realm_id.clone(),
        "00000000d200",
        arkret_sdk::events::kinds::REALM_KEY_SHARE,
        json!({
            "share_class": "member_device",
            "recipient_principal_id": "did:web:stranger.example",
            "recipient_device_id": "ak:device:01904100-0000-7000-8000-00000000d2d1",
            "sender_device_id": "ak:device:01904100-0000-7000-8000-00000000d2d2",
            "sender_device_signature": {"alg": "EdDSA", "kid": "k", "sig": "s"},
            "key_scope": {
                "effective_scope": {"kind": "realm", "realm_id": realm_id.as_str()},
                "policy_digest": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
                "from_epoch": 1,
                "to_epoch": 3
            },
            "ciphertext": "sealed",
            "created_at": "2026-06-25T00:00:00Z"
        }),
    );

    let result = validate_realm_key_share_policy(&state, &share).await;
    assert_eq!(
        result,
        Err("history_sharing_policy_missing"),
        "a non-recovery recipient with no history-sharing policy must fail closed"
    );
}
