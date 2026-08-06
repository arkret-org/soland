use arkret_models_collaboration::agent_operations::AgentLifecycleState;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::{Signer as _, SigningKey};
use serde_json::json;
use soland_services::events::CanonicalEventRecord;
use soland_services::identity::DirectConversationBindingRecord;
use soland_storage_postgres::Db;

use super::*;

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

fn state_with_direct_binding() -> (AppState, arkret_identifiers::RealmId) {
    let state = AppState::new(test_config(), Db { pool: None });
    let realm_id = arkret_identifiers::RealmId::new(
        "ak:realm:01904100-0000-8000-8000-000000000601".to_owned(),
    )
    .unwrap();
    let now = chrono::Utc::now();
    let alice = arkret_identifiers::Did::new("did:web:alice.example".to_owned()).unwrap();
    let bob = arkret_identifiers::Did::new("did:web:bob.example".to_owned()).unwrap();
    let strand_id =
        arkret_identifiers::StrandId::new("ak:strand:01904100-0000-8000-8000-000000000601")
            .unwrap();
    let realm_create = op(
        realm_id.clone(),
        "000000000691",
        arkret_wire::EventKind::REALM_CREATE,
        serde_json::to_value(arkret_models_collaboration::objects::direct_conversation::direct_conversation_realm_create_payload(
            realm_id.clone(),
            alice.clone(),
            arkret_identifiers::TypedTrustDomainId::new(state.config().trust_domain.clone())
                .unwrap(),
            arkret_models_collaboration::objects::realm::NotaryProfile::SingleDid,
            arkret_wire::notary::NotaryValue::single_did(alice.clone()),
            arkret_policy::current_capability_action_registry_digest().unwrap(),
            now,
        ))
        .unwrap(),
    );
    let mut peer_join = op(
        realm_id.clone(),
        "000000000692",
        arkret_wire::EventKind::MEMBER_STATE,
        arkret_models_collaboration::objects::direct_conversation::direct_conversation_member_join_payload(
            realm_id.clone(),
            bob,
            arkret_models_identity::DeliveryStatus::Unroutable,
        )
        .to_value()
        .unwrap(),
    );
    peer_join.payload["sender"] = json!("did:web:alice.example");
    let strand_create = op(
        realm_id.clone(),
        "000000000693",
        arkret_wire::EventKind::STRAND_CREATE,
        serde_json::to_value(arkret_models_collaboration::objects::direct_conversation::direct_conversation_main_strand_create_payload(
            strand_id,
            realm_id.clone(),
            alice,
            now,
        ))
        .unwrap(),
    );
    {
        let mut projection = state.test_projection().lock();
        projection.apply(&realm_create, state.hlc());
        projection.apply(&peer_join, state.hlc());
        projection.apply(&strand_create, state.hlc());
    }
    state.contacts().install_direct_binding(
        "did:web:alice.example\0did:web:bob.example".to_owned(),
        DirectConversationBindingRecord {
            participants_unordered: vec![
                "did:web:alice.example".to_owned(),
                "did:web:bob.example".to_owned(),
            ],
            realm_id: realm_id.to_string(),
            main_strand_id: "ak:strand:01904100-0000-8000-8000-000000000601".to_owned(),
            binding_event_ref: "ak:event:01904100-0000-8000-8000-000000000601".to_owned(),
            state: "active".to_owned(),
            authoring_context: None,
            created_at: now,
            updated_at: now,
        },
    );
    (state, realm_id)
}

fn op(
    realm_id: arkret_identifiers::RealmId,
    seed: &str,
    kind: &str,
    payload: serde_json::Value,
) -> Operation {
    Operation::create(
        arkret_identifiers::OperationId::new(format!(
            "ak:operation:01904100-0000-7000-8000-{seed}"
        ))
        .unwrap(),
        realm_id,
        kind,
        payload,
    )
}

fn accountability_grant_payload(status: &str, expires_at: &str) -> serde_json::Value {
    json!({
        "schema": "ak.schema.accountability_grant.v1",
        "sender": "did:web:alice.example",
        "issuer": "did:web:alice.example",
        "subject": "did:web:agent.example",
        "accountability_scope": "agent_operator",
        "not_before": "2026-01-01T00:00:00.000Z",
        "expires_at": expires_at,
        "grant_status": status,
        "proof": {
            "kind": "detached_jws",
            "verification_method": "did:web:alice.example#key-1",
            "payload_digest": format!("sha256:{}", "3".repeat(64)),
            "created_at": "2026-01-01T00:00:00.000Z",
            "jws": "AAAA.BBBB.CCCC"
        }
    })
}

fn realm_with_proposal_policy(
    realm_id: arkret_identifiers::RealmId,
    decision_ms: u64,
    absolute_ms: u64,
    max_defers: u8,
) -> arkret_models_collaboration::objects::realm::Realm {
    let owner = arkret_identifiers::Did::new("did:web:alice.example".to_owned()).unwrap();
    let mut realm = arkret_models_collaboration::objects::realm::Realm::new(
        realm_id,
        "Proposal policy test",
        owner.clone(),
        arkret_identifiers::TypedTrustDomainId::new("ak:trust_domain:test".to_owned()).unwrap(),
        arkret_wire::CORE_REDUCER_PROFILE,
        arkret_models_collaboration::objects::realm::NotaryProfile::SingleDid,
        arkret_wire::notary::NotaryValue::single_did(owner),
        arkret_policy::current_capability_action_registry_digest().unwrap(),
    );
    realm.proposal_decision_window_ms = Some(decision_ms);
    realm.proposal_absolute_deadline_ms = Some(absolute_ms);
    realm.max_proposal_defers = Some(max_defers);
    realm
}

#[test]
fn realm_create_proposal_policy_uses_sdk_cross_field_validator() {
    let state = test_state();
    let cases = [
        (91_000, 90_000, 0, false),
        (90_000, 90_000, 0, true),
        (90_000, 90_000, 1, false),
    ];
    for (index, (decision, absolute, defers, expected_valid)) in cases.into_iter().enumerate() {
        let realm_id = arkret_identifiers::RealmId::new(format!(
            "ak:realm:01904100-0000-8000-8000-0000000007b{index}"
        ))
        .unwrap();
        let operation = op(
            realm_id.clone(),
            &format!("0000000007b{index}"),
            arkret_wire::EventKind::REALM_CREATE,
            json!({
                "object": realm_with_proposal_policy(realm_id, decision, absolute, defers)
            }),
        );
        assert_eq!(
            validate_operation_semantics(&state, &[operation]).is_ok(),
            expected_valid
        );
    }
}

#[test]
fn realm_update_validates_the_complete_candidate_before_projection() {
    let state = test_state();
    let realm_id = arkret_identifiers::RealmId::new(
        "ak:realm:01904100-0000-8000-8000-0000000007b3".to_owned(),
    )
    .unwrap();
    let create = op(
        realm_id.clone(),
        "0000000007b3",
        arkret_wire::EventKind::REALM_CREATE,
        json!({
            "object": realm_with_proposal_policy(realm_id.clone(), 30_000, 90_000, 2)
        }),
    );
    state.test_projection().lock().apply(&create, state.hlc());
    let mut invalid_update = op(
        realm_id,
        "0000000007b4",
        arkret_wire::EventKind::REALM_UPDATE,
        json!({
            "patch": {
                "proposal_decision_window_ms": 90_000,
                "proposal_absolute_deadline_ms": 90_000,
                "max_proposal_defers": 1
            }
        }),
    );
    invalid_update.canonical_event_digest = Some(format!("sha256:{}", "a".repeat(64)));

    assert_eq!(
        validate_operation_semantics(&state, &[invalid_update]),
        Err("Realm control proposal decision policy is invalid")
    );
    assert_eq!(
        state
            .test_projection()
            .lock()
            .realm_metadata_cell_value("ak:realm:01904100-0000-8000-8000-0000000007b3")
            .and_then(|value| value.get("proposal_decision_window_ms"))
            .and_then(serde_json::Value::as_u64),
        Some(30_000)
    );
}

#[test]
fn view_admission_rejects_retired_collection_and_actor_lifecycle_fields() {
    let realm_id =
        arkret_identifiers::RealmId::new("ak:realm:01904100-0000-8000-8000-000000000611").unwrap();
    for definition in [
        json!({"collection": {"page_size": 50}}),
        json!({"collection": {"selection_policy": "multiple"}}),
        json!({"collection": {"grouping": {"wip_limit_enforcement": "warn"}}}),
        json!({"state": "tombstoned", "state_changed_at": "2026-07-17T00:00:00.000Z"}),
    ] {
        let operation = op(
            realm_id.clone(),
            "000000000611",
            arkret_wire::EventKind::VIEW_UPDATE,
            json!({
                "view_id": "ak:view:01904100-0000-8000-8000-000000000611",
                "patch": definition
            }),
        );
        assert_eq!(
            validate_view_payload(&operation),
            Err(arkret_wire::ErrorCode::SCHEMA_VIOLATION)
        );
    }
    let current = op(
        realm_id,
        "000000000612",
        arkret_wire::EventKind::VIEW_UPDATE,
        json!({
            "view_id": "ak:view:01904100-0000-8000-8000-000000000611",
            "patch": {"state": "tombstoned"}
        }),
    );
    validate_view_payload(&current).unwrap();
}

#[test]
fn shared_view_events_never_carry_a_private_view() {
    // `models/views.md` §3.1: a `visibility="private"` View lives only in
    // `ak.views.private.<view_id>` account data. Admission is what keeps the
    // shared surface clean — a private View that is refused entry to the Event
    // log can never surface from a shared View query, so this is the read-side
    // guarantee as well as the write-side one.
    let realm_id =
        arkret_identifiers::RealmId::new("ak:realm:01904100-0000-8000-8000-000000000613").unwrap();
    let private_view = json!({
        "id": "ak:view:01904100-0000-8000-8000-000000000613",
        "schema": "ak.schema.view.v1",
        "realm_id": realm_id.as_str(),
        "kind": "collection",
        "visibility": "private",
        "title": "personal board",
        "query": {"realm_id": realm_id.as_str()},
        "created_by": "did:web:alice.example",
        "created_at": "2026-07-30T00:00:00.000Z"
    });
    for (seed, kind, payload) in [
        (
            "000000000613",
            arkret_wire::EventKind::VIEW_CREATE,
            json!({
                "view_id": "ak:view:01904100-0000-8000-8000-000000000613",
                "object": private_view.clone()
            }),
        ),
        (
            "000000000614",
            arkret_wire::EventKind::VIEW_UPDATE,
            json!({
                "view_id": "ak:view:01904100-0000-8000-8000-000000000613",
                "patch": {"visibility": "private"}
            }),
        ),
        (
            "000000000615",
            arkret_wire::EventKind::VIEW_RECONCILE,
            json!({
                "view_id": "ak:view:01904100-0000-8000-8000-000000000613",
                "definition": private_view.clone()
            }),
        ),
        (
            "000000000616",
            arkret_wire::EventKind::VIEW_UPDATE,
            json!({
                "view_id": "ak:view:01904100-0000-8000-8000-000000000613",
                "visibility": "private"
            }),
        ),
    ] {
        let operation = op(realm_id.clone(), seed, kind, payload);
        assert_eq!(
            validate_view_payload(&operation),
            Err("private_view_requires_account_data"),
            "{kind} must refuse a private View on the shared Event surface"
        );
    }

    // The same shapes with the shared visibility are admitted, so the rejection
    // above is about `visibility`, not about the payload shape.
    let mut shared_view = private_view;
    shared_view["visibility"] = json!("shared");
    let shared = op(
        realm_id,
        "000000000617",
        arkret_wire::EventKind::VIEW_CREATE,
        json!({
            "view_id": "ak:view:01904100-0000-8000-8000-000000000613",
            "object": shared_view
        }),
    );
    validate_view_payload(&shared).unwrap();
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
        "algorithms": ["ak.hpke_x25519_aead_chacha20poly1305.v1", "ak.mls.v1"],
        "authorized_by": "did:key:z6MknBuwKMPAzbhp6EwCnaxsEDk4G2KFeWRu273gYVuTY5jw",
        "not_before": "2026-06-22T14:45:51.000Z",
        "enrollment_authority_binding": {
            "kind": "service_attested",
            "authority_did": "did:key:z6MknBuwKMPAzbhp6EwCnaxsEDk4G2KFeWRu273gYVuTY5jw",
            "authorization_ref": "did:webvh:zQmZcDaFwUR8yQCZRkXoYEBi9hdzMSCCLASUVdwT1J4Qyc6:local.host:webvh:01kvqwpxssfq3bqm15rcd0g99x#enrollment-authority"
        },
        "event_id": "ak:event:019eefcb-8fb2-8890-bffd-1f2035356fbf",
        "sender": "did:webvh:zQmZcDaFwUR8yQCZRkXoYEBi9hdzMSCCLASUVdwT1J4Qyc6:local.host:webvh:01kvqwpxssfq3bqm15rcd0g99x",
        "hlc": "019eefcb7d18-0000-8adcfdb5",
        "executed_by": "did:key:z6MknBuwKMPAzbhp6EwCnaxsEDk4G2KFeWRu273gYVuTY5jw",
        "authorization_ref": "did:webvh:zQmZcDaFwUR8yQCZRkXoYEBi9hdzMSCCLASUVdwT1J4Qyc6:local.host:webvh:01kvqwpxssfq3bqm15rcd0g99x#enrollment-authority",
        "accepted_event_id": "ak:event:019eefcb-8fb2-8890-bffd-1f2035356fbf"
    });

    crate::routing::identity::cross_signing::validate_device_authorize_binding(&state, &payload)
        .unwrap();
}

fn signed_service_attested_device_authorize_payload(
    device_signer: &SigningKey,
    signing_key: &SigningKey,
) -> serde_json::Value {
    let device_public_key = arkret_canonical::ed25519_pubkey_to_did_key_multibase(
        device_signer.verifying_key().as_bytes(),
    );
    let mut payload = json!({
        "principal_id": "did:webvh:zQmZcDaFwUR8yQCZRkXoYEBi9hdzMSCCLASUVdwT1J4Qyc6:local.host:webvh:01kvqwpxssfq3bqm15rcd0g99x",
        "device_id": "ak:device:019eefcb-5882-7861-bc30-3033fa32dcf6",
        "device_public_key": device_public_key,
        "hpke_key": "z6LSgy7T8CEsMDMzk1e4EBFVX8CDXWWzvkFZWSXhsC97zjcM",
        "algorithms": ["ak.hpke_x25519_aead_chacha20poly1305.v1", "ak.mls.v1"],
        "device_key_algorithm": "Ed25519",
        "authorized_by": "did:key:z6MknBuwKMPAzbhp6EwCnaxsEDk4G2KFeWRu273gYVuTY5jw",
        "not_before": "2026-06-22T14:45:51.000Z",
        "enrollment_authority_binding": {
            "kind": "service_attested",
            "authority_did": "did:key:z6MknBuwKMPAzbhp6EwCnaxsEDk4G2KFeWRu273gYVuTY5jw",
            "authorization_ref": "did:webvh:zQmZcDaFwUR8yQCZRkXoYEBi9hdzMSCCLASUVdwT1J4Qyc6:local.host:webvh:01kvqwpxssfq3bqm15rcd0g99x#enrollment-authority"
        }
    });
    let typed: arkret_models_collaboration::events_payloads::device_identity::DeviceAuthorizePayload =
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
    realm_id: &arkret_identifiers::RealmId,
    circle_id: &str,
    actor: &str,
    action: &str,
) {
    crate::authz::install_projected_grant(
        state.authorization(),
        realm_id.to_string(),
        "did:web:owner.example".to_owned(),
        actor.to_owned(),
        circle_id.to_owned(),
        vec![action.to_owned()],
        vec![crate::authz::Constraint::AllowedCircleIds {
            allowed_circle_ids: std::collections::BTreeSet::from([
                arkret_identifiers::CircleId::new(circle_id.to_owned()).expect("valid circle id"),
            ]),
        }],
    );
}

fn grant_moderation_decision(
    state: &AppState,
    realm_id: &arkret_identifiers::RealmId,
    actor: &str,
) {
    crate::authz::install_projected_grant(
        state.authorization(),
        realm_id.to_string(),
        "did:web:owner.example".to_owned(),
        actor.to_owned(),
        realm_id.to_string(),
        vec![arkret_wire::EventKind::MODERATION_DECISION.to_owned()],
        Vec::new(),
    );
}

fn grant_call_action(
    state: &AppState,
    realm_id: &arkret_identifiers::RealmId,
    actor: &str,
    action: &str,
) {
    crate::authz::install_projected_grant(
        state.authorization(),
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
    use arkret_state::lattice::CellState;

    let now = chrono::Utc::now();
    let mut projection = state.test_projection().lock();
    let cell_id = arkret_identifiers::CellRef::new(format!(
        "ak:cell:ak.component.realm.read_receipt_policy.v1:{parent_realm_id}"
    ))
    .expect("valid read receipt policy cell ref");
    projection
        .cells
        .insert(cell_id, CellState::Value(parent_policy));
    projection
        .realm_links
        .entry(child_realm_id.to_owned())
        .or_default()
        .push(soland_domain::reducer::RealmLinkState {
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
        soland_domain::reducer::RealmInheritancePolicyState {
            realm_id: child_realm_id.to_owned(),
            operation_id: "ak:operation:01904100-0000-7000-8000-000000009901".to_owned(),
            source_realm_id: parent_realm_id.to_owned(),
            allowed_policies: vec!["ak.realm.read_receipt_policy".to_owned()],
            allowed_capability_bundles: Vec::new(),
            max_depth: 1,
            updated_at: now,
        },
    );
}

#[tokio::test]
async fn read_receipt_child_policy_rejects_visibility_loosening() {
    let state = test_state();
    let parent_realm = "ak:realm:01904100-0000-8000-8000-000000009911";
    let child_realm = arkret_identifiers::RealmId::new(
        "ak:realm:01904100-0000-8000-8000-000000009912".to_owned(),
    )
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
        arkret_wire::EventKind::REALM_READ_RECEIPT_POLICY,
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
    let parent_realm = "ak:realm:01904100-0000-8000-8000-000000009921";
    let child_realm = arkret_identifiers::RealmId::new(
        "ak:realm:01904100-0000-8000-8000-000000009922".to_owned(),
    )
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
        arkret_wire::EventKind::REALM_READ_RECEIPT_POLICY,
        json!({
            "disclosure": "disabled",
            "visibility": "private"
        }),
    );
    assert_eq!(
        validate_operation_policy(&state, &[child_policy])
            .await
            .unwrap_err(),
        arkret_wire::ErrorCode::READ_RECEIPT_COMPLIANCE_FLOOR_VIOLATED
    );
}

#[tokio::test]
async fn read_receipt_child_policy_allows_required_floor_escape() {
    let state = test_state();
    let parent_realm = "ak:realm:01904100-0000-8000-8000-000000009931";
    let child_realm = arkret_identifiers::RealmId::new(
        "ak:realm:01904100-0000-8000-8000-000000009932".to_owned(),
    )
    .unwrap();
    seed_read_receipt_inheritance(
        &state,
        parent_realm,
        child_realm.as_str(),
        json!({
            "disclosure": "required",
            "visibility": "members",
            "scope_overrides_allowed": true,
            "receipt_compliance_opt_in": {
                "child_privacy_tightening_against_required": true
            }
        }),
    );

    let child_policy = op(
        child_realm,
        "000000009933",
        arkret_wire::EventKind::REALM_READ_RECEIPT_POLICY,
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
    let parent_realm = "ak:realm:01904100-0000-8000-8000-000000009941";
    let child_realm = arkret_identifiers::RealmId::new(
        "ak:realm:01904100-0000-8000-8000-000000009942".to_owned(),
    )
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
        arkret_wire::EventKind::REALM_READ_RECEIPT_POLICY,
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
        .agent_participations()
        .store_ceiling(json!({
            "scope_kind": scope_kind,
            "scope_key": scope_key,
            "realm_id": realm_id,
            "reply_message": reply,
            "reaction_add": false,
            "reaction_remove": false,
            "accept_third_party_mention": accept_third_party_mention,
            "act_on_behalf": act_on_behalf,
        }))
        .await
        .expect("agent participation ceiling");
}

#[tokio::test]
async fn strand_agent_participation_ceiling_cannot_widen_circle_parent() {
    let state = test_state();
    let realm_id = arkret_identifiers::RealmId::new(
        "ak:realm:01904100-0000-8000-8000-000000009951".to_owned(),
    )
    .unwrap();
    let circle_id = "ak:circle:01904100-0000-8000-8000-000000009952";
    let strand_id = "ak:strand:01904100-0000-8000-8000-000000009953";
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
        arkret_wire::EventKind::STRAND_CREATE,
        json!({
            "sender": "did:web:alice.example",
            "object": {
                "id": strand_id,
                "realm_id": "ak:realm:01904100-0000-8000-8000-000000009951",
                "scope_circle_id": circle_id,
                "metadata": {"title": "Scoped"},
                "agent_participation": {
                    "native_agent": {
                        "reply_message": true,
                        "reaction_add": false,
                        "reaction_remove": false,
                        "accept_third_party_mention": true,
                        "act_on_behalf": false
                    }
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
    let realm_id = arkret_identifiers::RealmId::new(
        "ak:realm:01904100-0000-8000-8000-000000009961".to_owned(),
    )
    .unwrap();
    let circle_id = "ak:circle:01904100-0000-8000-8000-000000009962";
    let strand_id = arkret_identifiers::StrandId::new(
        "ak:strand:01904100-0000-8000-8000-000000009963".to_owned(),
    )
    .unwrap();
    {
        let mut projection = state.test_projection().lock();
        projection.strands.insert(
            strand_id.as_str().to_owned(),
            soland_domain::reducer::StrandProjection {
                strand_id: strand_id.as_str().to_owned(),
                realm_id: realm_id.to_string(),
                tracks: Default::default(),
                title: "Scoped".to_owned(),
                summary: None,
                fields: Default::default(),
                state: soland_domain::reducer::ObjectLifecycleState::Active,
                state_changed_at: None,
                created_by: "did:web:alice.example".to_owned(),
                created_at: chrono::Utc::now(),
                history_basis_seals: Vec::new(),
                updated_by: None,
                updated_at: None,
                schema_refs: Vec::new(),
                schedule_revision_heads: Vec::new(),
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

    let scope =
        arkret_models_collaboration::governance::agent_participation::ParticipationScope::Strand {
            realm_id,
            strand_id,
        };
    let ceiling =
        crate::routing::agent_participation::resolve_effective_ceiling(&state, &scope).await;
    assert!(!ceiling.accept_third_party_mention);
    let selection =
        arkret_models_collaboration::governance::agent_participation::ParticipationBits {
            reply_message: true,
            reaction_add: true,
            reaction_remove: false,
            accept_third_party_mention: true,
            act_on_behalf: false,
        };
    let effective =
        arkret_models_collaboration::governance::agent_participation::effective_participation(
            ceiling, selection,
        );
    assert!(selection.accept_third_party_mention);
    assert!(!effective.accept_third_party_mention);
}

async fn register_agent_selection(
    state: &AppState,
    realm_id: &arkret_identifiers::RealmId,
    agent_id: &str,
    reply: bool,
    act_on_behalf: bool,
) {
    let mut record = soland_services::identity::AgentPairingState::new(
        agent_id.to_owned(),
        "did:web:alice.example".to_owned(),
        "ak:realm:01904100-0000-8000-8000-000000000001".to_owned(),
        arkret_wire::DidUrl::new(format!("{agent_id}#managed-controller")).unwrap(),
        AgentLifecycleState::Active,
        chrono::Utc::now(),
    );
    record.display_name = Some("Summary".to_owned());
    record.agent_slug = Some("summary".to_owned());
    state
        .agent_pairings()
        .save_agent(record)
        .await
        .expect("agent record");
    let realm_uuid = realm_id
        .as_str()
        .strip_prefix("ak:realm:")
        .expect("realm id prefix");
    assert!(
        state
            .agent_participations()
            .compare_and_swap_selection(
                json!({
                    "agent_id": agent_id,
                    "scope_kind": "realm",
                    "scope_key": format!("realm:{realm_uuid}"),
                    "realm_id": realm_id.as_str(),
                    "scope": { "kind": "realm", "realm_id": realm_id.as_str() },
                    "version": 1,
                    "reply_message": reply,
                    "reaction_add": false,
                    "reaction_remove": false,
                    "accept_third_party_mention": false,
                    "act_on_behalf": act_on_behalf,
                }),
                0
            )
            .await
            .expect("agent participation selection")
    );
}

async fn register_native_agent_membership_context(
    state: &AppState,
    realm_id: &arkret_identifiers::RealmId,
    encrypted: bool,
    with_claimable_keypackage: bool,
) {
    let controller = "did:web:alice.example";
    let agent = "did:web:agent.example";
    let now = chrono::Utc::now();
    let mut record = soland_storage::AgentPrincipalRecord::new(
        agent.to_owned(),
        controller.to_owned(),
        "ak:realm:01904100-0000-8000-8000-000000000001".to_owned(),
        arkret_wire::DidUrl::new(format!("{agent}#managed-controller")).unwrap(),
        AgentLifecycleState::Active,
        now,
    );
    record.agent_slug = Some("summary".to_owned());
    let authorize_event_id = "ak:event:01904100-0000-8000-8000-0000000007d2";
    let verification_method = "did:web:agent.example#runtime-1";
    if with_claimable_keypackage {
        record.authorized_event_ref = Some(authorize_event_id.to_owned());
        record.authorized_verification_method = Some(verification_method.to_owned());
    }
    state
        .test_persistence()
        .agents()
        .put(record)
        .await
        .expect("agent record");
    let accountability_grant_payload = json!({
        "schema": "ak.schema.accountability_grant.v1",
        "issuer": controller,
        "subject": agent,
        "accountability_scope": "agent_operator",
        "grant_status": "active",
        "not_before": "2026-01-01T00:00:00.000Z",
        "expires_at": "2099-01-01T00:00:00.000Z",
        "proof": {
            "kind": "detached_jws",
            "verification_method": "did:web:alice.example#key-1",
            "payload_digest": format!("sha256:{}", "3".repeat(64)),
            "created_at": "2026-01-01T00:00:00.000Z",
            "jws": "test"
        }
    });
    serde_json::from_value::<
        arkret_models_collaboration::governance::accountability::AccountabilityGrantPayload,
    >(accountability_grant_payload.clone())
    .expect("standard accountability grant payload");
    state
        .test_persistence()
        .events()
        .put(soland_storage::CanonicalEventRecord {
            event_id: "ak:event:01904100-0000-8000-8000-0000000007d1".to_owned(),
            actor_id: controller.to_owned(),
            actor_seq: 1,
            realm_id: Some("ak:realm:01904100-0000-8000-8000-000000000001".to_owned()),
            kind: "ak.identity.accountability_grant".to_owned(),
            schema_id: "ak.schema.event.v1".to_owned(),
            canonical_digest: "sha256:test".to_owned(),
            canonical_bytes: Vec::new(),
            envelope: json!({
                "actor_id": controller,
                "executed_by": controller,
                "kind": "ak.identity.accountability_grant",
                "payload": accountability_grant_payload
            }),
            received_at: now,
        })
        .await
        .expect("accountability grant");
    state
        .test_persistence()
        .realm_meta()
        .put(
            realm_id.as_str(),
            &soland_storage::RealmMetaRecord {
                owner: controller.to_owned(),
                deleted: false,
                discoverability: "invite_only".to_owned(),
                history_visibility: "joined".to_owned(),
                history_sharing_policy: None,
                history_sharing_policy_digest: None,
                preview_policy: None,
                preview_policy_digest: None,
                asset_privacy_policy: None,
                asset_privacy_policy_digest: None,
                encryption_profile: encrypted.then(|| "mls_rfc9420".to_owned()),
                plaintext_visible_services: std::collections::BTreeSet::new(),
                plaintext_visible_service_classes: std::collections::BTreeMap::new(),
                minimal_metadata_realm: false,
                aad_visibility_ceiling: Default::default(),
                created_at: now,
                updated_at: now,
            },
        )
        .await
        .expect("realm meta");
    state.test_projection().lock().members.insert(
        (realm_id.to_string(), controller.to_owned()),
        soland_domain::reducer::SolandMembershipState {
            member: controller.to_owned(),
            realm_id: realm_id.to_string(),
            state: "join".to_owned(),
            role: "owner".to_owned(),
            delivery_status: Some("unroutable".to_owned()),
            recipient_service_id: None,
            membership_event_ref: None,
            delivery_binding_frontier: None,
            invited_at: None,
            joined_at: now,
            updated_at: now,
            reason: None,
        },
    );

    if !with_claimable_keypackage {
        return;
    }
    let device_id = "ak:device:01904100-0000-7000-8000-0000000007d1";
    let authorize_payload = json!({
        "agent_id": agent,
        "key_id": "ak:agent_key:01904100-0000-7000-8000-0000000007d2",
        "verification_method": verification_method,
        "public_key_digest": format!("sha256:{}", "4".repeat(64)),
        "accountable_principal_id": controller,
        "agent_key_scope": {"actions": ["ak.message.create"]},
        "audience": [state.service_id().as_str()],
        "issued_at": "2026-01-01T00:00:00.000Z",
        "expires_at": "2099-01-01T00:00:00.000Z"
    });
    let authorize_event = arkret_wire::Event::new(
        arkret_wire::EventKind::AGENT_KEY_AUTHORIZE,
        arkret_wire::ScopeRef::Realm {
            realm_id: realm_id.clone(),
        },
        arkret_identifiers::Did::new(agent.to_owned()).unwrap(),
        1,
        arkret_identifiers::Hlc::new("019041000000-0001-000007d2").unwrap(),
        authorize_payload.clone(),
    )
    .unwrap();
    let mut authorize_envelope = serde_json::to_value(authorize_event).unwrap();
    authorize_envelope["event_id"] = json!(authorize_event_id);
    state
        .test_persistence()
        .events()
        .put(soland_storage::CanonicalEventRecord {
            event_id: authorize_event_id.to_owned(),
            actor_id: agent.to_owned(),
            actor_seq: 1,
            realm_id: Some(realm_id.to_string()),
            kind: arkret_wire::EventKind::AGENT_KEY_AUTHORIZE.to_owned(),
            schema_id: "ak.schema.event.v1".to_owned(),
            canonical_digest: format!("sha256:{}", "5".repeat(64)),
            canonical_bytes: Vec::new(),
            envelope: authorize_envelope,
            received_at: now,
        })
        .await
        .expect("Agent key authorization Event");
    let authorize_projection = op(
        realm_id.clone(),
        "0000000007d4",
        arkret_wire::EventKind::AGENT_KEY_AUTHORIZE,
        json!({
            "agent_id": agent,
            "key_id": "ak:agent_key:01904100-0000-7000-8000-0000000007d2",
            "accepted_event_id": authorize_event_id,
            "verification_method": verification_method,
        }),
    );
    state
        .test_projection()
        .lock()
        .apply(&authorize_projection, state.hlc());
    state.test_projection().lock().mls_key_packages.insert(
        "ak:mls_keypackage:01904100-0000-7000-8000-0000000007d1".to_owned(),
        soland_domain::reducer::MlsKeyPackage {
            id: "ak:mls_keypackage:01904100-0000-7000-8000-0000000007d1".to_owned(),
            keypackage_ref: "ak:mls_keypackage:01904100-0000-7000-8000-0000000007d1".to_owned(),
            keypackage_digest: format!("sha256:{}", "1".repeat(64)),
            actor_id: agent.to_owned(),
            device_id: device_id.to_owned(),
            lifetime: soland_domain::reducer::KeyPackageLifetime {
                not_before: now.timestamp() - 60,
                not_after: now.timestamp() + 3600,
            },
            key_package_bytes: vec![1, 2, 3],
            capabilities: vec!["mimi.content.v1".to_owned(), "ak.content.v1".to_owned()],
            capabilities_digest: format!("sha256:{}", "2".repeat(64)),
            device_signature: json!({"kid": "test", "sig": "test"}),
            last_resort: false,
            last_resort_realm_id: None,
            claimed_by: None,
            ssk_generation: None,
            device_authorize_event_id: None,
            agent_key_authorize_event_id: Some(authorize_event_id.to_owned()),
            claimed_at: None,
            claim_expires_at_unix_ms: None,
            consumed_at: None,
            created_at: now.timestamp(),
        },
    );
}

#[tokio::test]
async fn encrypted_realm_native_agent_join_requires_claimable_keypackage() {
    let state = test_state();
    let realm_id =
        arkret_identifiers::RealmId::new("ak:realm:01904100-0000-8000-8000-0000000007d1").unwrap();
    register_native_agent_membership_context(&state, &realm_id, true, false).await;
    let operation = op(
        realm_id,
        "0000000007d1",
        arkret_wire::EventKind::MEMBER_STATE,
        json!({
            "sender": "did:web:alice.example",
            "actor_id": "did:web:agent.example",
            "membership": "join",
            "reason": "controller_add_agent",
            "delivery_status": "unroutable"
        }),
    );

    assert_eq!(
        validate_member_state_policy_for_test(&state, &operation)
            .await
            .unwrap_err(),
        soland_services::operation_semantics::REASON_KEYPACKAGE_NOT_FOUND
    );
}

#[tokio::test]
async fn encrypted_realm_native_agent_join_accepts_standard_claimable_keypackage() {
    let state = test_state();
    let realm_id =
        arkret_identifiers::RealmId::new("ak:realm:01904100-0000-8000-8000-0000000007d2").unwrap();
    register_native_agent_membership_context(&state, &realm_id, true, true).await;
    let operation = op(
        realm_id,
        "0000000007d2",
        arkret_wire::EventKind::MEMBER_STATE,
        json!({
            "sender": "did:web:alice.example",
            "actor_id": "did:web:agent.example",
            "membership": "join",
            "reason": "controller_add_agent",
            "delivery_status": "unroutable"
        }),
    );

    validate_member_state_policy_for_test(&state, &operation)
        .await
        .expect("standard claimable KeyPackage satisfies encrypted admission precondition");
}

#[tokio::test]
async fn plaintext_realm_native_agent_join_does_not_require_keypackage() {
    let state = test_state();
    let realm_id =
        arkret_identifiers::RealmId::new("ak:realm:01904100-0000-8000-8000-0000000007d3").unwrap();
    register_native_agent_membership_context(&state, &realm_id, false, false).await;
    let operation = op(
        realm_id,
        "0000000007d3",
        arkret_wire::EventKind::MEMBER_STATE,
        json!({
            "sender": "did:web:alice.example",
            "actor_id": "did:web:agent.example",
            "membership": "join",
            "reason": "controller_add_agent",
            "delivery_status": "unroutable"
        }),
    );

    validate_member_state_policy_for_test(&state, &operation)
        .await
        .expect("plaintext Realm membership does not require MLS material");
}

fn agent_context(agent_id: &str, authorization_ref: &str) -> serde_json::Value {
    json!({
        "agent_id": agent_id,
        "operator_or_controller": "did:web:alice.example",
        "authorization_ref": authorization_ref,
        "execution_purpose": "test_action",
    })
}

fn reply_message(
    realm_id: arkret_identifiers::RealmId,
    seed: &str,
    agent_id: &str,
    authorization_ref: &str,
) -> Operation {
    op(
        realm_id,
        seed,
        arkret_wire::EventKind::MESSAGE_CREATE,
        json!({
            "sender": agent_id,
            "content": [{"type": "text", "text": "agent reply"}],
            "agent_context": agent_context(agent_id, authorization_ref),
        }),
    )
}

fn act_on_behalf_message(
    realm_id: arkret_identifiers::RealmId,
    seed: &str,
    agent_id: &str,
    authorization_ref: Option<&str>,
    approval: Option<(&str, &str)>,
) -> Operation {
    let mut payload = json!({
        "sender": "did:web:alice.example",
        "executed_by": agent_id,
        "content": [{"type": "text", "text": "approved"}],
    });
    if let Some(authorization_ref) = authorization_ref {
        let object = payload.as_object_mut().expect("payload object");
        object.insert("authorization_ref".to_owned(), json!(authorization_ref));
        object.insert(
            "agent_context".to_owned(),
            agent_context(agent_id, authorization_ref),
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
        arkret_wire::EventKind::MESSAGE_CREATE,
        payload,
    )
}

fn insert_approved_agent_action(
    state: &AppState,
    message: &Operation,
    request_id: &str,
    agent_id: &str,
    approval_nonce: &str,
) {
    let payload_digest = arkret_canonical::canonical_sha256(&message.payload).unwrap();
    state.test_projection().lock().agent_action_requests.insert(
        request_id.to_owned(),
        soland_domain::reducer::AgentActionRequestProjection {
            request_id: request_id.to_owned(),
            agent_id: agent_id.to_owned(),
            status: soland_domain::reducer::AgentActionRequestStatus::Approved,
            requested_at: message.created_at - chrono::Duration::minutes(1),
            resolved_at: Some(message.created_at),
            resolution_event_id: Some("ak:event:01904100-0000-8000-8000-0000000007aa".to_owned()),
            cancel_reason: None,
            approval: Some(soland_domain::reducer::AgentActionApprovalProjection {
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

#[tokio::test]
async fn active_direct_conversation_rejects_invite_space_and_third_party_member() {
    let (state, realm_id) = state_with_direct_binding();

    let invite = op(
        realm_id.clone(),
        "000000000601",
        arkret_wire::EventKind::INVITE_CREATE,
        json!({
            "invite_id": "ak:invite:01904100-0000-7000-8000-000000000601",
            "inviter": "did:web:alice.example",
            "invitee": "did:web:charlie.example",
            "invite_delivery_target": {
                "recipient_service_id": "did:webvh:z2dmjYwAPJzv5CZsnAzt8auVZRn1GfuxhpK2t3Q3K3rj4B1x:soland.local:webvh:service",
                "recipient_service_kind": "principal_server"
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
        arkret_wire::EventKind::SPACE_CREATE,
        json!({
            "space_id": "ak:space:01904100-0000-8000-8000-000000000602",
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
        arkret_wire::EventKind::MEMBER_STATE,
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
async fn direct_conversation_role_fails_closed_when_binding_cache_is_missing() {
    let (state, realm_id) = state_with_direct_binding();
    state
        .contacts()
        .replace_runtime_direct_bindings(std::iter::empty());

    let invite = op(
        realm_id.clone(),
        "000000000604",
        arkret_wire::EventKind::INVITE_CREATE,
        json!({
            "invite_id": "ak:invite:01904100-0000-7000-8000-000000000604",
            "inviter": "did:web:alice.example",
            "invitee": "did:web:charlie.example"
        }),
    );
    assert_eq!(
        validate_operation_policy(&state, &[invite])
            .await
            .unwrap_err(),
        "direct_conversation_invite_forbidden"
    );

    let member_add = op(
        realm_id,
        "000000000605",
        arkret_wire::EventKind::MEMBER_STATE,
        json!({
            "actor_id": "did:web:charlie.example",
            "membership": "join",
            "sender": "did:web:alice.example"
        }),
    );
    assert_eq!(
        validate_operation_policy(&state, &[member_add])
            .await
            .unwrap_err(),
        "direct_conversation_member_count_invalid"
    );
}

#[tokio::test]
async fn act_on_behalf_agent_requires_participation_bit() {
    let state = test_state();
    let realm_id = arkret_identifiers::RealmId::new(
        "ak:realm:01904100-0000-8000-8000-000000000701".to_owned(),
    )
    .unwrap();
    let agent = "did:web:agent.example";
    register_agent_selection(&state, &realm_id, agent, true, false).await;
    let grant = crate::authz::install_projected_grant(
        state.authorization(),
        realm_id.to_string(),
        "did:web:alice.example".to_owned(),
        agent.to_owned(),
        realm_id.to_string(),
        vec![arkret_wire::EventKind::MESSAGE_CREATE.to_owned()],
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
    let realm_id = arkret_identifiers::RealmId::new(
        "ak:realm:01904100-0000-8000-8000-000000000702".to_owned(),
    )
    .unwrap();
    let agent = "did:web:agent.example";
    register_agent_selection(&state, &realm_id, agent, true, true).await;
    let grant = crate::authz::install_projected_grant(
        state.authorization(),
        realm_id.to_string(),
        "did:web:alice.example".to_owned(),
        agent.to_owned(),
        realm_id.to_string(),
        vec![arkret_wire::EventKind::REACTION_ADD.to_owned()],
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
    let realm_id = arkret_identifiers::RealmId::new(
        "ak:realm:01904100-0000-8000-8000-0000000007a2".to_owned(),
    )
    .unwrap();
    let agent = "did:web:agent.example";
    register_agent_selection(&state, &realm_id, agent, true, true).await;
    let operation = op(
        realm_id,
        "0000000007a2",
        arkret_wire::EventKind::STRAND_CREATE,
        json!({
            "sender": "did:web:alice.example",
            "executed_by": agent,
            "object": {
                "id": "ak:strand:01904100-0000-8000-8000-0000000007a2",
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
    let realm_id = arkret_identifiers::RealmId::new(
        "ak:realm:01904100-0000-8000-8000-0000000007c1".to_owned(),
    )
    .unwrap();
    let agent = "did:web:agent.example";
    register_agent_selection(&state, &realm_id, agent, true, true).await;
    let grant = crate::authz::install_projected_grant(
        state.authorization(),
        realm_id.to_string(),
        "did:web:alice.example".to_owned(),
        agent.to_owned(),
        realm_id.to_string(),
        vec![arkret_wire::EventKind::STRAND_CREATE.to_owned()],
        Vec::new(),
    );
    let operation = op(
        realm_id,
        "0000000007c1",
        arkret_wire::EventKind::STRAND_CREATE,
        json!({
            "sender": "did:web:alice.example",
            "executed_by": agent,
            "authorization_ref": grant.grant_id,
            "object": {
                "id": "ak:strand:01904100-0000-8000-8000-0000000007c1",
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
    let realm_id = arkret_identifiers::RealmId::new(
        "ak:realm:01904100-0000-8000-8000-0000000007b1".to_owned(),
    )
    .unwrap();
    let agent = "did:web:agent.example";
    register_agent_selection(&state, &realm_id, agent, true, true).await;
    let operation = op(
        realm_id,
        "0000000007b1",
        arkret_wire::EventKind::MEMBER_STATE,
        json!({
            "sender": "did:web:alice.example",
            "actor_id": agent,
            "membership": "join",
            "realm_id": "ak:realm:01904100-0000-8000-8000-0000000007b1",
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
    let realm_id = arkret_identifiers::RealmId::new(
        "ak:realm:01904100-0000-8000-8000-0000000007c2".to_owned(),
    )
    .unwrap();
    let agent = "did:web:agent.example";
    register_agent_selection(&state, &realm_id, agent, true, true).await;
    let envelope_grant = crate::authz::install_projected_grant(
        state.authorization(),
        realm_id.to_string(),
        "did:web:alice.example".to_owned(),
        agent.to_owned(),
        realm_id.to_string(),
        vec![arkret_wire::EventKind::RELATION_CREATE.to_owned()],
        Vec::new(),
    );
    let context_grant = crate::authz::install_projected_grant(
        state.authorization(),
        realm_id.to_string(),
        "did:web:alice.example".to_owned(),
        agent.to_owned(),
        realm_id.to_string(),
        vec![arkret_wire::EventKind::RELATION_CREATE.to_owned()],
        Vec::new(),
    );
    let operation = op(
        realm_id,
        "0000000007c2",
        arkret_wire::EventKind::RELATION_CREATE,
        json!({
            "sender": "did:web:alice.example",
            "executed_by": agent,
            "authorization_ref": envelope_grant.grant_id,
            "agent_context": agent_context(agent, context_grant.grant_id.as_str()),
            "relation_id": "ak:relation:01904100-0000-8000-8000-0000000007c2",
            "relation_kind": "references",
            "from_ref": "ak:strand:01904100-0000-8000-8000-0000000007c2",
            "to_ref": "ak:strand:01904100-0000-8000-8000-0000000007c3"
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
    let realm_id = arkret_identifiers::RealmId::new(
        "ak:realm:01904100-0000-8000-8000-0000000007c3".to_owned(),
    )
    .unwrap();
    let operation = op(
        realm_id,
        "0000000007c3",
        arkret_wire::EventKind::RELATION_CREATE,
        json!({
            "sender": "did:web:alice.example",
            "provenance": {
                "actor_kind": "agent"
            },
            "relation_id": "ak:relation:01904100-0000-8000-8000-0000000007c3",
            "relation_kind": "references",
            "from_ref": "ak:strand:01904100-0000-8000-8000-0000000007c4",
            "to_ref": "ak:strand:01904100-0000-8000-8000-0000000007c5"
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
    let realm_id = arkret_identifiers::RealmId::new(
        "ak:realm:01904100-0000-8000-8000-0000000007c4".to_owned(),
    )
    .unwrap();
    let agent = "did:web:agent.example";
    register_agent_selection(&state, &realm_id, agent, true, true).await;
    let grant = crate::authz::install_projected_grant(
        state.authorization(),
        realm_id.to_string(),
        "did:web:alice.example".to_owned(),
        agent.to_owned(),
        realm_id.to_string(),
        vec![arkret_wire::EventKind::VIEW_CREATE.to_owned()],
        Vec::new(),
    );
    let grant_id = grant.grant_id.clone();
    let operation = op(
        realm_id,
        "0000000007c4",
        arkret_wire::EventKind::VIEW_CREATE,
        json!({
            "sender": "did:web:alice.example",
            "executed_by": agent,
            "authorization_ref": grant_id.as_str(),
            "agent_context": agent_context(agent, grant_id.as_str()),
            "view_id": "ak:view:01904100-0000-8000-8000-0000000007c4",
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
    let realm_id = arkret_identifiers::RealmId::new(
        "ak:realm:01904100-0000-8000-8000-0000000007c5".to_owned(),
    )
    .unwrap();
    let agent = "did:web:agent.example";
    register_agent_selection(&state, &realm_id, agent, true, true).await;
    let grant = crate::authz::install_projected_grant(
        state.authorization(),
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
        "ak.agent.unknown.write",
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
    let realm_id = arkret_identifiers::RealmId::new(
        "ak:realm:01904100-0000-8000-8000-0000000007c6".to_owned(),
    )
    .unwrap();
    let agent = "did:web:agent.example";
    register_agent_selection(&state, &realm_id, agent, true, true).await;
    let grant = crate::authz::install_projected_grant(
        state.authorization(),
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
        "ak.agent.unknown.reply",
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
    let realm_id = arkret_identifiers::RealmId::new(
        "ak:realm:01904100-0000-8000-8000-0000000007c7".to_owned(),
    )
    .unwrap();
    let agent = "did:web:agent.example";
    register_agent_selection(&state, &realm_id, agent, true, false).await;
    let grant = crate::authz::install_projected_grant(
        state.authorization(),
        realm_id.to_string(),
        "did:web:alice.example".to_owned(),
        agent.to_owned(),
        realm_id.to_string(),
        vec![arkret_wire::EventKind::MESSAGE_CREATE.to_owned()],
        Vec::new(),
    );
    let mut record = state
        .agent_pairings()
        .agent(agent)
        .await
        .expect("agent lookup")
        .expect("agent record");
    record.state = AgentLifecycleState::Paused;
    state
        .agent_pairings()
        .save_agent(record)
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
    let realm_id = arkret_identifiers::RealmId::new(
        "ak:realm:01904100-0000-8000-8000-0000000007c8".to_owned(),
    )
    .unwrap();
    let agent = "did:web:agent.example";
    register_agent_selection(&state, &realm_id, agent, true, false).await;
    let grant = crate::authz::install_projected_grant(
        state.authorization(),
        realm_id.to_string(),
        "did:web:alice.example".to_owned(),
        agent.to_owned(),
        realm_id.to_string(),
        vec![arkret_wire::EventKind::MESSAGE_CREATE.to_owned()],
        Vec::new(),
    );
    state.test_projection().lock().agent_lifecycles.insert(
        agent.to_owned(),
        arkret_models_collaboration::agent_operations::AgentLifecycleState::Deactivated,
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
    let realm_id = arkret_identifiers::RealmId::new(
        "ak:realm:01904100-0000-8000-8000-0000000007a3".to_owned(),
    )
    .unwrap();
    let profile = op(
        realm_id,
        "0000000007a3",
        "ak.profile.create",
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
        arkret_wire::ReasonCode::ACCOUNTABILITY_GRANT_MISSING
    );
}

#[tokio::test]
async fn profile_accountable_principal_rejects_batch_grant_signed_by_other_actor() {
    let state = test_state();
    let realm_id = arkret_identifiers::RealmId::new(
        "ak:realm:01904100-0000-8000-8000-0000000007a4".to_owned(),
    )
    .unwrap();
    let profile = op(
        realm_id.clone(),
        "0000000007a4",
        "ak.profile.create",
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
        "ak.identity.accountability_grant",
        json!({
            "sender": "did:web:mallory.example",
            "issuer": "did:web:alice.example",
            "subject": "did:web:agent.example",
            "grant_status": "active",
            "not_before": "2026-01-01T00:00:00.000Z",
            "expires_at": "2099-01-01T00:00:00.000Z"
        }),
    );

    assert_eq!(
        validate_operation_policy(&state, &[fake_grant, profile])
            .await
            .unwrap_err(),
        arkret_wire::ReasonCode::ACCOUNTABILITY_GRANT_MISSING
    );
}

#[tokio::test]
async fn profile_accountable_principal_accepts_active_atomic_grant() {
    let state = test_state();
    let realm_id = arkret_identifiers::RealmId::new(
        "ak:realm:01904100-0000-8000-8000-0000000007a8".to_owned(),
    )
    .unwrap();
    let grant = op(
        realm_id.clone(),
        "0000000007a8",
        arkret_wire::EventKind::IDENTITY_ACCOUNTABILITY_GRANT,
        accountability_grant_payload("active", "2099-01-01T00:00:00.000Z"),
    );
    let profile = op(
        realm_id,
        "0000000007a9",
        "ak.profile.create",
        json!({
            "sender": "did:web:agent.example",
            "principal_id": "did:web:agent.example",
            "display_name": "Agent",
            "accountable_principal_ids": ["did:web:alice.example"]
        }),
    );

    validate_operation_policy(&state, &[grant, profile])
        .await
        .expect("active atomic grant must satisfy the profile");
}

#[tokio::test]
async fn profile_accountable_principal_atomic_revoke_wins() {
    let state = test_state();
    let realm_id = arkret_identifiers::RealmId::new(
        "ak:realm:01904100-0000-8000-8000-0000000007aa".to_owned(),
    )
    .unwrap();
    let grant = op(
        realm_id.clone(),
        "0000000007aa",
        arkret_wire::EventKind::IDENTITY_ACCOUNTABILITY_GRANT,
        accountability_grant_payload("active", "2099-01-01T00:00:00.000Z"),
    );
    let revoke = op(
        realm_id.clone(),
        "0000000007ab",
        arkret_wire::EventKind::IDENTITY_ACCOUNTABILITY_GRANT,
        accountability_grant_payload("revoked", "2099-01-01T00:00:00.000Z"),
    );
    let profile = op(
        realm_id,
        "0000000007ac",
        "ak.profile.update",
        json!({
            "sender": "did:web:agent.example",
            "principal_id": "did:web:agent.example",
            "display_name": "Agent",
            "accountable_principal_ids": ["did:web:alice.example"]
        }),
    );

    assert_eq!(
        validate_operation_policy(&state, &[grant, revoke, profile])
            .await
            .unwrap_err(),
        arkret_wire::ReasonCode::ACCOUNTABILITY_GRANT_MISSING
    );
}

#[tokio::test]
async fn profile_accountability_uses_signed_frozen_time() {
    let state = test_state();
    let realm_id = arkret_identifiers::RealmId::new(
        "ak:realm:01904100-0000-8000-8000-0000000007ad".to_owned(),
    )
    .unwrap();
    let grant = op(
        realm_id.clone(),
        "0000000007ad",
        arkret_wire::EventKind::IDENTITY_ACCOUNTABILITY_GRANT,
        accountability_grant_payload("active", "2026-06-01T00:00:00.000Z"),
    );
    let mut profile = op(
        realm_id,
        "0000000007ae",
        "ak.profile.update",
        json!({
            "sender": "did:web:agent.example",
            "principal_id": "did:web:agent.example",
            "display_name": "Agent",
            "accountable_principal_ids": ["did:web:alice.example"]
        }),
    );
    profile.created_at = chrono::DateTime::parse_from_rfc3339("2026-05-01T00:00:00.000Z")
        .unwrap()
        .with_timezone(&chrono::Utc);

    validate_operation_policy(&state, &[grant, profile])
        .await
        .expect("grant validity must use the profile Event's signed time, not wall clock");
}

#[tokio::test]
async fn profile_accountable_principal_rejects_stored_grant_signed_by_other_actor() {
    let state = test_state();
    let realm_id = arkret_identifiers::RealmId::new(
        "ak:realm:01904100-0000-8000-8000-0000000007a6".to_owned(),
    )
    .unwrap();
    state
        .event_queries()
        .store_canonical_event(CanonicalEventRecord {
            event_id: "ak:event:01904100-0000-8000-8000-0000000007a6".to_owned(),
            actor_id: "did:web:mallory.example".to_owned(),
            actor_seq: 1,
            realm_id: Some(realm_id.to_string()),
            kind: "ak.identity.accountability_grant".to_owned(),
            schema_id: "ak.schema.event.v1".to_owned(),
            canonical_digest: "sha256:test".to_owned(),
            canonical_bytes: Vec::new(),
            envelope: json!({
                "actor_id": "did:web:mallory.example",
                "kind": "ak.identity.accountability_grant",
                "realm_id": realm_id.to_string(),
                "payload": {
                    "issuer": "did:web:alice.example",
                    "subject": "did:web:agent.example",
                    "grant_status": "active",
                    "not_before": "2026-01-01T00:00:00.000Z",
                    "expires_at": "2099-01-01T00:00:00.000Z"
                }
            }),
            received_at: chrono::Utc::now(),
        })
        .await
        .expect("store fake accountability grant");
    let profile = op(
        realm_id,
        "0000000007a7",
        "ak.profile.create",
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
        arkret_wire::ReasonCode::ACCOUNTABILITY_GRANT_MISSING
    );
}

#[tokio::test]
async fn circle_member_manage_rejects_forged_verdict_without_grant() {
    let state = test_state();
    let realm_id = arkret_identifiers::RealmId::new(
        "ak:realm:01904100-0000-8000-8000-000000000881".to_owned(),
    )
    .unwrap();
    let member_add = op(
        realm_id,
        "000000000881",
        arkret_wire::EventKind::CIRCLE_MEMBER_STATE,
        json!({
            "sender": "did:web:alice.example",
            "circle_id": "ak:circle:01904100-0000-8000-8000-000000000881",
            "actor_id": "did:web:bob.example",
            "membership": "join",
            "manage_capability_verified": true,
            "actor_capability": {
                "action": "ak.circle.member.manage",
                "circle_id": "ak:circle:01904100-0000-8000-8000-000000000881",
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
    let realm_id = arkret_identifiers::RealmId::new(
        "ak:realm:01904100-0000-8000-8000-000000000882".to_owned(),
    )
    .unwrap();
    let circle_id = "ak:circle:01904100-0000-8000-8000-000000000882";
    grant_circle_action(
        &state,
        &realm_id,
        circle_id,
        "did:web:alice.example",
        "ak.circle.member.manage",
    );
    let member_add = op(
        realm_id,
        "000000000882",
        arkret_wire::EventKind::CIRCLE_MEMBER_STATE,
        json!({
            "sender": "did:web:alice.example",
            "circle_id": circle_id,
            "actor_id": "did:web:bob.example",
            "membership": "join",
            "manage_capability_verified": true,
            "actor_capability": {
                "action": "ak.circle.member.manage",
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
    let realm_id = arkret_identifiers::RealmId::new(
        "ak:realm:01904100-0000-8000-8000-000000000883".to_owned(),
    )
    .unwrap();
    let circle_id = "ak:circle:01904100-0000-8000-8000-000000000883";
    let tombstone = op(
        realm_id.clone(),
        "000000000883",
        arkret_wire::EventKind::CIRCLE_TOMBSTONE,
        json!({
            "sender": "did:web:alice.example",
            "circle_id": circle_id
        }),
    );

    assert_eq!(
        validate_operation_policy(&state, std::slice::from_ref(&tombstone))
            .await
            .unwrap_err(),
        "circle_manage_capability_required"
    );

    grant_circle_action(
        &state,
        &realm_id,
        circle_id,
        "did:web:alice.example",
        "ak.circle.manage",
    );
    validate_operation_policy(&state, &[tombstone])
        .await
        .expect("circle-scoped manage grant authorizes lifecycle");
}

#[tokio::test]
async fn act_on_behalf_agent_allows_effective_selection_and_active_grant() {
    let state = test_state();
    let realm_id = arkret_identifiers::RealmId::new(
        "ak:realm:01904100-0000-8000-8000-000000000703".to_owned(),
    )
    .unwrap();
    let agent = "did:web:agent.example";
    register_agent_selection(&state, &realm_id, agent, true, true).await;
    let grant = crate::authz::install_projected_grant(
        state.authorization(),
        realm_id.to_string(),
        "did:web:alice.example".to_owned(),
        agent.to_owned(),
        realm_id.to_string(),
        vec![arkret_wire::EventKind::MESSAGE_CREATE.to_owned()],
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
    let realm_id = arkret_identifiers::RealmId::new(
        "ak:realm:01904100-0000-8000-8000-000000000704".to_owned(),
    )
    .unwrap();
    let agent = "did:web:agent.example";
    register_agent_selection(&state, &realm_id, agent, true, true).await;
    let grant = crate::authz::install_projected_grant(
        state.authorization(),
        realm_id.to_string(),
        "did:web:alice.example".to_owned(),
        agent.to_owned(),
        realm_id.to_string(),
        vec![arkret_wire::EventKind::MESSAGE_CREATE.to_owned()],
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
    let realm_id = arkret_identifiers::RealmId::new(
        "ak:realm:01904100-0000-8000-8000-000000000705".to_owned(),
    )
    .unwrap();
    let agent = "did:web:agent.example";
    register_agent_selection(&state, &realm_id, agent, true, true).await;
    let grant = crate::authz::install_projected_grant(
        state.authorization(),
        realm_id.to_string(),
        "did:web:alice.example".to_owned(),
        agent.to_owned(),
        realm_id.to_string(),
        vec![arkret_wire::EventKind::MESSAGE_CREATE.to_owned()],
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
        arkret_wire::ReasonCode::APPROVAL_NONCE_REUSED
    );
}

#[tokio::test]
async fn circle_scoped_relation_update_and_delete_require_circle_membership() {
    let state = test_state();
    let realm_id = arkret_identifiers::RealmId::new(
        "ak:realm:01904100-0000-8000-8000-000000000801".to_owned(),
    )
    .unwrap();
    let circle_id = "ak:circle:01904100-0000-8000-8000-000000000801";
    let relation_id = "ak:relation:01904100-0000-8000-8000-000000000801";
    let now = chrono::Utc::now();
    {
        let mut projection = state.test_projection().lock();
        let mut members = std::collections::BTreeSet::new();
        members.insert("did:web:alice.example".to_owned());
        projection.circles.insert(
            circle_id.to_owned(),
            soland_domain::reducer::CircleProjection {
                circle_id: circle_id.to_owned(),
                realm_id: realm_id.to_string(),
                profile_ref: None,
                title: "Private".to_owned(),
                summary: None,
                display: serde_json::json!({"short_name":"Private","color_token":"slate","symbol":{"glyph":"ring"}}),
                directory_visibility: "private".to_owned(),
                join_rule: "invite".to_owned(),
                history_visibility: "joined".to_owned(),
                content_encryption_floor: None,
                metadata_encryption_floor: None,
                encryption_profile: "none".to_owned(),
                mls_group_ref: None,
                state: soland_domain::reducer::CircleLifecycleState::Active,
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
            soland_domain::reducer::SolandRelationState {
                relation_id: relation_id.to_owned(),
                realm_id: realm_id.to_string(),
                relation_kind: "confidential_discussion_of".to_owned(),
                scope_circle_id: Some(circle_id.to_owned()),
                from_ref: Some("ak:strand:01904100-0000-8000-8000-000000000811".to_owned()),
                to_ref: Some("ak:strand:01904100-0000-8000-8000-000000000812".to_owned()),
                fields: Default::default(),
                state: "active".to_owned(),
                source_event_id: Some("ak:event:01904100-0000-8000-8000-000000000801".to_owned()),
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
        arkret_wire::EventKind::RELATION_UPDATE,
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
        arkret_wire::EventKind::RELATION_UPDATE,
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
        arkret_wire::EventKind::RELATION_TOMBSTONE,
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
    let realm_id = arkret_identifiers::RealmId::new(
        "ak:realm:01904100-0000-8000-8000-000000000901".to_owned(),
    )
    .unwrap();
    grant_moderation_decision(&state, &realm_id, "did:web:moderator.example");
    let decision = op(
        realm_id,
        "000000000901",
        arkret_wire::EventKind::MODERATION_DECISION,
        json!({
            "sender": "did:web:moderator.example",
            "issuer": "did:web:impostor.example",
            "target_ref": "ak:message:01904100-0000-8000-8000-000000000901",
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
    let realm_id = arkret_identifiers::RealmId::new(
        "ak:realm:01904100-0000-8000-8000-000000000902".to_owned(),
    )
    .unwrap();
    grant_moderation_decision(&state, &realm_id, "did:web:moderator.example");
    let decision = op(
        realm_id,
        "000000000902",
        arkret_wire::EventKind::MODERATION_DECISION,
        json!({
            "sender": "did:web:moderator.example",
            "issuer": "did:web:moderator.example",
            "target_ref": "ak:message:01904100-0000-8000-8000-000000000902",
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
    let realm_id = arkret_identifiers::RealmId::new(
        "ak:realm:01904100-0000-8000-8000-000000000903".to_owned(),
    )
    .unwrap();
    grant_moderation_decision(&state, &realm_id, "did:web:moderator.example");
    let decision = op(
        realm_id,
        "000000000903",
        arkret_wire::EventKind::MODERATION_DECISION,
        json!({
            "sender": "did:web:moderator.example",
            "target_ref": "ak:message:01904100-0000-8000-8000-000000000903",
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
    let realm_id = arkret_identifiers::RealmId::new(
        "ak:realm:01904100-0000-8000-8000-000000000904".to_owned(),
    )
    .unwrap();
    grant_call_action(
        &state,
        &realm_id,
        "did:web:recorder.example",
        arkret_wire::CapabilityActionId::CALL_RECORD,
    );
    let start = op(
        realm_id,
        "000000000904",
        arkret_wire::EventKind::CALL_RECORDING_START,
        json!({
            "sender": "did:web:recorder.example",
            "call_id": "ak:call:01904100-0000-7000-8000-000000000904",
            "recording_id": "recording-904",
            "recording_agent": "did:web:recorder.example",
            "capture_kind": "recording",
            "mode": "audio_video",
            "visible_notice": true,
            "result": {
                "recording_start_event_id": "ak:event:01904100-0000-8000-8000-000000000904",
                "retention": {"consent_confirmed": true}
            }
        }),
    );

    validate_operation_policy(&state, &[start])
        .await
        .expect("ak.call.record should authorize recording capture");
}

#[tokio::test]
async fn call_recording_start_transcript_requires_transcribe_capability() {
    let state = test_state();
    let realm_id = arkret_identifiers::RealmId::new(
        "ak:realm:01904100-0000-8000-8000-000000000905".to_owned(),
    )
    .unwrap();
    grant_call_action(
        &state,
        &realm_id,
        "did:web:recorder.example",
        arkret_wire::CapabilityActionId::CALL_RECORD,
    );
    let start = op(
        realm_id,
        "000000000905",
        arkret_wire::EventKind::CALL_RECORDING_START,
        json!({
            "sender": "did:web:recorder.example",
            "call_id": "ak:call:01904100-0000-7000-8000-000000000905",
            "recording_id": "transcript-905",
            "recording_agent": "did:web:recorder.example",
            "capture_kind": "transcript",
            "mode": "audio",
            "visible_notice": true,
            "result": {
                "transcript_start_event_id": "ak:event:01904100-0000-8000-8000-000000000905",
                "retention": {"consent_confirmed": true}
            }
        }),
    );

    assert_eq!(
        validate_operation_policy(&state, &[start])
            .await
            .unwrap_err(),
        arkret_wire::ReasonCode::TRANSCRIPTION_DENIED
    );
    assert_eq!(
        operation_policy_reason_code(arkret_wire::ReasonCode::TRANSCRIPTION_DENIED),
        (
            salvo::http::StatusCode::FORBIDDEN,
            arkret_wire::ReasonCode::TRANSCRIPTION_DENIED
        )
    );
}

#[tokio::test]
async fn call_recording_start_transcript_allows_transcribe_capability() {
    let state = test_state();
    let realm_id = arkret_identifiers::RealmId::new(
        "ak:realm:01904100-0000-8000-8000-000000000906".to_owned(),
    )
    .unwrap();
    grant_call_action(
        &state,
        &realm_id,
        "did:web:recorder.example",
        arkret_wire::CapabilityActionId::CALL_TRANSCRIBE,
    );
    let start = op(
        realm_id,
        "000000000906",
        arkret_wire::EventKind::CALL_RECORDING_START,
        json!({
            "sender": "did:web:recorder.example",
            "call_id": "ak:call:01904100-0000-7000-8000-000000000906",
            "recording_id": "transcript-906",
            "recording_agent": "did:web:recorder.example",
            "capture_kind": "transcript",
            "mode": "audio",
            "visible_notice": true,
            "result": {
                "transcript_start_event_id": "ak:event:01904100-0000-8000-8000-000000000906",
                "retention": {"consent_confirmed": true}
            }
        }),
    );

    validate_operation_policy(&state, &[start])
        .await
        .expect("ak.call.transcribe should authorize transcript capture");
}

#[tokio::test]
async fn call_recording_start_rejects_missing_mode_and_noncanonical_recording_id() {
    let state = test_state();
    let realm_id = arkret_identifiers::RealmId::new(
        "ak:realm:01904100-0000-8000-8000-000000000907".to_owned(),
    )
    .unwrap();
    grant_call_action(
        &state,
        &realm_id,
        "did:web:recorder.example",
        arkret_wire::CapabilityActionId::CALL_RECORD,
    );
    let payload = json!({
        "sender": "did:web:recorder.example",
        "call_id": "ak:call:01904100-0000-7000-8000-000000000907",
        "recording_id": "recording-907",
        "recording_agent": "did:web:recorder.example",
        "capture_kind": "recording",
        "visible_notice": true,
        "result": {
            "recording_start_event_id": "ak:event:01904100-0000-8000-8000-000000000907",
            "retention": {"consent_confirmed": true}
        }
    });
    let missing_mode = op(
        realm_id.clone(),
        "000000000907",
        arkret_wire::EventKind::CALL_RECORDING_START,
        payload.clone(),
    );
    assert_eq!(
        validate_operation_policy(&state, &[missing_mode])
            .await
            .unwrap_err(),
        arkret_wire::ErrorCode::SCHEMA_VIOLATION
    );

    let mut invalid_recording_id_payload = payload;
    invalid_recording_id_payload["recording_id"] = json!("recording id");
    invalid_recording_id_payload["mode"] = json!("audio_video");
    let invalid_recording_id = op(
        realm_id,
        "000000000908",
        arkret_wire::EventKind::CALL_RECORDING_START,
        invalid_recording_id_payload,
    );
    assert_eq!(
        validate_operation_policy(&state, &[invalid_recording_id])
            .await
            .unwrap_err(),
        arkret_wire::ErrorCode::SCHEMA_VIOLATION
    );
}

#[tokio::test]
async fn mls_prejoin_history_rejects_non_history_capable_content_scheme() {
    let state = test_state();
    let realm_id = arkret_identifiers::RealmId::new(
        "ak:realm:01904100-0000-8000-8000-00000000c100".to_owned(),
    )
    .unwrap();
    let create = op(
        realm_id.clone(),
        "00000000c101",
        arkret_wire::EventKind::REALM_CREATE,
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
        arkret_wire::EventKind::REALM_POLICY_BUNDLE,
        json!({
            "policy_revision": 1,
            "content_scheme": "mls_rfc9420"
        }),
    );

    let reason = validate_operation_policy(&state, &[create, strict_scheme])
        .await
        .unwrap_err();
    assert_eq!(
        reason,
        arkret_wire::ReasonCode::HISTORY_VISIBILITY_REQUIRES_HISTORY_CAPABLE_SCHEME
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
    let realm_id = arkret_identifiers::RealmId::new(
        "ak:realm:01904100-0000-8000-8000-00000000c200".to_owned(),
    )
    .unwrap();
    let create = op(
        realm_id.clone(),
        "00000000c201",
        arkret_wire::EventKind::REALM_CREATE,
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
        arkret_wire::EventKind::REALM_POLICY_BUNDLE,
        json!({
            "policy_revision": 1,
            "content_scheme": "mls_exporter_aead_v1"
        }),
    );

    validate_operation_policy(&state, &[create, exporter_scheme])
        .await
        .expect("pre-join history is valid when the MLS realm declares exporter-AEAD");
}

#[tokio::test]
async fn mls_prejoin_history_accepts_create_object_exporter_aead_content_scheme() {
    let state = test_state();
    let realm_id = arkret_identifiers::RealmId::new(
        "ak:realm:01904100-0000-8000-8000-00000000c210".to_owned(),
    )
    .unwrap();
    let create = op(
        realm_id.clone(),
        "00000000c211",
        arkret_wire::EventKind::REALM_CREATE,
        json!({
            "object": {
                "id": realm_id.as_str(),
                "title": "Prejoin history",
                "history_visibility": "shared",
                "encryption_profile": "mls_rfc9420",
                "content_scheme": "mls_exporter_aead_v1"
            }
        }),
    );

    validate_operation_policy(&state, &[create])
        .await
        .expect("pre-join history is valid when ak.realm.create declares exporter-AEAD");
}

#[tokio::test]
async fn mls_prejoin_history_rejects_create_object_strict_content_scheme() {
    let state = test_state();
    let realm_id = arkret_identifiers::RealmId::new(
        "ak:realm:01904100-0000-8000-8000-00000000c220".to_owned(),
    )
    .unwrap();
    let create = op(
        realm_id.clone(),
        "00000000c221",
        arkret_wire::EventKind::REALM_CREATE,
        json!({
            "object": {
                "id": realm_id.as_str(),
                "title": "Prejoin history",
                "history_visibility": "shared",
                "encryption_profile": "mls_rfc9420",
                "content_scheme": "mls_rfc9420"
            }
        }),
    );

    let reason = validate_operation_policy(&state, &[create])
        .await
        .unwrap_err();
    assert_eq!(
        reason,
        arkret_wire::ReasonCode::HISTORY_VISIBILITY_REQUIRES_HISTORY_CAPABLE_SCHEME
    );
}

#[tokio::test]
async fn mls_strict_existing_realm_rejects_prejoin_history_update() {
    use arkret_state::lattice::CellState;

    let state = test_state();
    let realm_id = arkret_identifiers::RealmId::new(
        "ak:realm:01904100-0000-8000-8000-00000000c300".to_owned(),
    )
    .unwrap();
    let now = chrono::Utc::now();
    state
        .realms()
        .store_realm_metadata(
            realm_id.as_str(),
            soland_services::events::RealmMetadata {
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
                aad_visibility_ceiling: Default::default(),
                created_at: now,
                updated_at: now,
            },
        )
        .await
        .expect("realm meta stored");
    {
        let mut projection = state.test_projection().lock();
        projection.realm_policy_bundle_cells.insert(
            realm_id.to_string(),
            CellState::Value(json!({
                "content_scheme": "mls_rfc9420"
            })),
        );
    }
    let history_visibility = op(
        realm_id,
        "00000000c301",
        arkret_wire::EventKind::REALM_HISTORY_VISIBILITY,
        json!({
            "value": "shared"
        }),
    );

    assert_eq!(
        validate_operation_policy(&state, &[history_visibility])
            .await
            .unwrap_err(),
        arkret_wire::ReasonCode::HISTORY_VISIBILITY_REQUIRES_HISTORY_CAPABLE_SCHEME
    );
}

// encryption-and-audit.md §2.10.8 — an RRK-targeted `ak.realm_key.share` (to a
// declared recovery recipient) is accepted by the share-policy gate even though
// the recipient is NOT a member and the realm carries no history-sharing policy.
// The discriminator is structural: `recipient_principal_id` is a current
// `durability_policy.recovery_recipients[].principal_id`.
#[tokio::test]
async fn realm_key_share_rrk_targeted_is_accepted_for_recovery_recipient() {
    use arkret_state::lattice::CellState;

    let state = test_state();
    let realm_id = arkret_identifiers::RealmId::new(
        "ak:realm:01904100-0000-8000-8000-00000000d100".to_owned(),
    )
    .unwrap();
    let recovery_principal = "did:web:hr.example";

    // Seed the projected policy_bundle cell with an exporter-AEAD scheme +
    // org RRK durability policy naming `recovery_principal` as a recipient.
    {
        let mut projection = state.test_projection().lock();
        projection.realm_policy_bundle_cells.insert(
            realm_id.to_string(),
            CellState::Value(json!({
                "content_scheme": "mls_exporter_aead_v1",
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
        arkret_wire::EventKind::REALM_KEY_SHARE,
        json!({
            "share_kind": "realm_recovery_key",
            "recipient_principal_id": recovery_principal,
            "recipient_verification_method": format!("{recovery_principal}#rrk-1"),
            "recovery_recipient_id": "rrk-1",
            "sender_device_id": "ak:device:01904100-0000-7000-8000-00000000d1d2",
            "source_authorization_ref": "ak:event:01904100-0000-8000-8000-00000000d1a1",
            "sender_device_signature": {"signature_algorithm": "Ed25519", "kid": "k", "sig": "s"},
            "key_scope": {
                "effective_scope": {"kind": "realm", "realm_id": realm_id.as_str()},
                "policy_digest": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
                "from_epoch": 1,
                "to_epoch": 3
            },
            "ciphertext": "hpke-sealed-history-secret",
            "created_at": "2026-06-25T00:00:00.000Z"
        }),
    );

    validate_realm_key_share_policy(&state, &share)
        .await
        .expect("RRK-targeted share to a recovery recipient must be accepted");
}

#[tokio::test]
async fn realm_key_share_member_device_accepts_projection_metadata() {
    let state = test_state();
    let realm_id = arkret_identifiers::RealmId::new(
        "ak:realm:01904100-0000-8000-8000-00000000d300".to_owned(),
    )
    .unwrap();
    let now = chrono::DateTime::parse_from_rfc3339("2026-07-05T00:00:00.000Z")
        .unwrap()
        .with_timezone(&chrono::Utc);
    let bob = "did:web:bob.example";
    let bob_device = "ak:device:01904100-0000-7000-8000-00000000d3d1";

    state
        .realms()
        .store_realm_metadata(
            realm_id.as_str(),
            soland_services::events::RealmMetadata {
                owner: "did:web:alice.example".to_owned(),
                deleted: false,
                discoverability: "invite_only".to_owned(),
                history_visibility: "shared".to_owned(),
                history_sharing_policy: Some(json!({
                    "version": 1,
                    "default_key_share": "event_time_visibility",
                    "pre_join_history": "visibility_condition_allowed",
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
                aad_visibility_ceiling: Default::default(),
                created_at: now,
                updated_at: now,
            },
        )
        .await
        .expect("realm meta stored");
    state
        .identities()
        .save_device(soland_services::identity::SaveDeviceCommand {
            actor_id: bob.to_owned(),
            device_id: bob_device.to_owned(),
            display_name: None,
            device: soland_services::identity::DeviceIdentity {
                actor_id: bob.to_owned(),
                device_id: bob_device.to_owned(),
                display_name: None,
                verification_state: "verified".to_owned(),
                payload: json!({"algorithms": ["ak.hpke_x25519_aead_chacha20poly1305.v1"]}),
                created_at: now,
                updated_at: now,
                revoked_at: None,
            },
        })
        .await
        .expect("device stored");
    {
        let mut projection = state.test_projection().lock();
        projection.members.insert(
            (realm_id.to_string(), bob.to_owned()),
            soland_domain::reducer::SolandMembershipState {
                member: bob.to_owned(),
                realm_id: realm_id.to_string(),
                state: "join".to_owned(),
                role: "member".to_owned(),
                delivery_status: Some("routable".to_owned()),
                recipient_service_id: Some("did:web:local.host".to_owned()),
                membership_event_ref: Some(
                    "ak:event:01904100-0000-8000-8000-00000000d3aa".to_owned(),
                ),
                delivery_binding_frontier: None,
                invited_at: Some(now),
                joined_at: now,
                updated_at: now,
                reason: None,
            },
        );
    }

    let share = op(
        realm_id.clone(),
        "00000000d300",
        arkret_wire::EventKind::REALM_KEY_SHARE,
        json!({
            "share_kind": "member_device",
            "recipient_principal_id": bob,
            "recipient_device_id": bob_device,
            "sender_device_id": "ak:device:01904100-0000-7000-8000-00000000d3d2",
            "source_authorization_ref": "ak:event:01904100-0000-8000-8000-00000000d3a1",
            "sender_device_signature": {"signature_algorithm": "Ed25519", "kid": "k", "sig": "s"},
            "key_scope": {
                "effective_scope": {"kind": "realm", "realm_id": realm_id.as_str()},
                "policy_digest": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
                "from_epoch": 1,
                "to_epoch": 3
            },
            "ciphertext": "sealed-history-secret",
            "created_at": "2026-07-05T00:00:00.000Z",
            "event_id": "ak:event:01904100-0000-8000-8000-00000000d300",
            "sender": "did:web:alice.example",
            "hlc": "2026-07-05T00:00:00.000Z/node/1"
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
    use arkret_state::lattice::CellState;

    let state = test_state();
    let realm_id = arkret_identifiers::RealmId::new(
        "ak:realm:01904100-0000-8000-8000-00000000d200".to_owned(),
    )
    .unwrap();
    {
        let mut projection = state.test_projection().lock();
        projection.realm_policy_bundle_cells.insert(
            realm_id.to_string(),
            CellState::Value(json!({
                "content_scheme": "mls_exporter_aead_v1",
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
        arkret_wire::EventKind::REALM_KEY_SHARE,
        json!({
            "share_kind": "member_device",
            "recipient_principal_id": "did:web:stranger.example",
            "recipient_device_id": "ak:device:01904100-0000-7000-8000-00000000d2d1",
            "sender_device_id": "ak:device:01904100-0000-7000-8000-00000000d2d2",
            "source_authorization_ref": "ak:event:01904100-0000-8000-8000-00000000d2a1",
            "sender_device_signature": {"signature_algorithm": "Ed25519", "kid": "k", "sig": "s"},
            "key_scope": {
                "effective_scope": {"kind": "realm", "realm_id": realm_id.as_str()},
                "policy_digest": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
                "from_epoch": 1,
                "to_epoch": 3
            },
            "ciphertext": "sealed",
            "created_at": "2026-06-25T00:00:00.000Z"
        }),
    );

    let result = validate_realm_key_share_policy(&state, &share).await;
    assert_eq!(
        result,
        Err("history_sharing_policy_missing"),
        "a non-recovery recipient with no history-sharing policy must fail closed"
    );
}
