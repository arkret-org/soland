use chrono::{TimeZone, Timelike};
use soland_storage_postgres::Db;

use super::*;
use crate::config::AppConfig;

fn test_state() -> AppState {
    AppState::new(AppConfig::test_default(), Db { pool: None })
}

fn remote_test_state(peer_service_id: &str) -> AppState {
    let mut config = AppConfig::test_default();
    config.development_mode = true;
    config.federation_peers = vec![format!("http://127.0.0.1:4101|{peer_service_id}")];
    AppState::new(config, Db { pool: None })
}

fn install_active_direct_binding_fixture(
    state: &AppState,
    pair_key: &str,
    realm_id: &str,
    main_strand_id: &str,
    alice: &str,
    bob: &str,
) {
    let timestamp = now();
    state.contacts().install_direct_binding(
        pair_key.to_owned(),
        DirectConversationBindingRecord {
            participants_unordered: sorted_participants(alice, bob),
            realm_id: realm_id.to_owned(),
            main_strand_id: main_strand_id.to_owned(),
            binding_event_ref: crate::ids::generate_event_id(),
            state: "active".to_owned(),
            authoring_context: None,
            created_at: timestamp,
            updated_at: timestamp,
        },
    );
    assert!(active_direct_binding(state, pair_key).is_some());
}

#[test]
fn legacy_direct_commit_detection_requires_exact_epoch_cas_precondition() {
    let group_id = "ak:mls_group:019fbba2-0000-7000-8000-000000000001";
    let epoch_cell = arkret_state::mls_move::mls_epoch_cell_id(group_id).unwrap();
    let envelope = |preconditions: Value| {
        json!({
            "kind": arkret_wire::EventKind::MLS_COMMIT,
            "payload": {
                "mls_group_id": group_id,
                "base_epoch": 0,
                "next_epoch": 1
            },
            "preconditions": preconditions
        })
    };

    assert!(legacy_direct_commit_missing_epoch_precondition(
        &envelope(json!([])),
        group_id
    ));
    assert!(legacy_direct_commit_missing_epoch_precondition(
        &envelope(json!([{
            "cell": epoch_cell.as_str(),
            "predicate": { "op": "head_eq", "value": 7 }
        }])),
        group_id
    ));
    assert!(!legacy_direct_commit_missing_epoch_precondition(
        &envelope(json!([{
            "cell": epoch_cell.as_str(),
            "predicate": { "op": "head_eq", "value": 0 }
        }])),
        group_id
    ));
}

#[test]
fn expired_direct_materialization_allocates_a_fresh_candidate() {
    let observed_at = chrono::Utc::now();
    assert_eq!(
        pending_direct_materialization_disposition(
            observed_at + chrono::Duration::seconds(1),
            observed_at,
        ),
        PendingDirectMaterializationDisposition::ReuseByteIdentical,
        "an unexpired draft must be returned byte-identically without another claim",
    );
    assert_eq!(
        pending_direct_materialization_disposition(observed_at, observed_at),
        PendingDirectMaterializationDisposition::AllocateFreshCandidate,
        "the claim is no longer reusable at its expiry boundary",
    );
    assert_eq!(
        pending_direct_materialization_disposition(
            observed_at - chrono::Duration::seconds(1),
            observed_at,
        ),
        PendingDirectMaterializationDisposition::AllocateFreshCandidate,
        "an expired single-use claim must not be renewed for the same Realm/group",
    );
}

#[tokio::test]
async fn remote_direct_claim_draft_is_durable_and_transport_bound() {
    let peer_service_id = "did:web:beta.example";
    let state = remote_test_state(peer_service_id);
    let actor = "did:web:alice.example";
    let peer = "did:web:bob.example";
    let pair_key = direct_pair_key(&state, actor, peer).unwrap();
    let (binding, draft) =
        prepare_remote_direct_keypackage_claim(&state, &pair_key, actor, peer, peer_service_id)
            .await
            .unwrap();
    assert_eq!(binding.state, "authoring_required");
    assert_eq!(draft.request.requester.as_str(), actor);
    assert_eq!(draft.request.target_principal_id.as_str(), peer);
    assert_eq!(draft.request.intended_realm_id.as_str(), binding.realm_id);
    assert_eq!(
        draft.request.strand_id.as_ref().unwrap().as_str(),
        binding.main_strand_id
    );
    assert_eq!(draft.request.pair_key.as_ref().unwrap().as_str(), pair_key);
    assert_eq!(
        draft.transport_binding.source_service_id.as_str(),
        state.service_id()
    );
    assert_eq!(
        draft.transport_binding.destination_service_id.as_str(),
        peer_service_id
    );
    let persisted = state
        .test_persistence()
        .direct_conversation_bindings()
        .get(&pair_key)
        .await
        .unwrap()
        .expect("durable authoring reservation");
    assert!(persisted.authoring_context.is_some());

    let (_, retry_draft) =
        prepare_remote_direct_keypackage_claim(&state, &pair_key, actor, peer, peer_service_id)
            .await
            .unwrap();
    assert_eq!(
        retry_draft.request.claim_request_id,
        draft.request.claim_request_id
    );
}

#[test]
fn direct_realm_create_payload_is_sdk_schema_valid() {
    let state = test_state();
    let created_at = chrono::Utc.with_ymd_and_hms(2026, 7, 6, 0, 0, 0).unwrap();
    let payload = direct_realm_create_payload(
        &state,
        arkret_identifiers::RealmId::new("ak:realm:01964137-0000-7000-8000-000000000101").unwrap(),
        "did:web:alice.example",
        created_at,
    )
    .unwrap();

    arkret_schema::event_payload_validator_catalog()
        .unwrap()
        .validate_payload(arkret_wire::EventKind::REALM_CREATE, &payload)
        .unwrap();
    assert!(payload.get("plaintext_visible_services").is_none());

    let object = payload
        .get("object")
        .and_then(Value::as_object)
        .expect("realm object");
    assert_eq!(
        object
            .get("default_discoverability")
            .and_then(Value::as_str),
        Some("invite_only")
    );
    assert_eq!(
        object.get("created_at").and_then(Value::as_str),
        Some("2026-07-06T00:00:00.000Z")
    );
}

#[test]
fn direct_member_join_payload_is_sdk_schema_valid() {
    let payload = direct_member_join_payload(
        arkret_identifiers::RealmId::new("ak:realm:01964137-0000-7000-8000-000000000101").unwrap(),
        "did:web:bob.example",
    )
    .unwrap();

    arkret_schema::event_payload_validator_catalog()
        .unwrap()
        .validate_payload(arkret_wire::EventKind::MEMBER_STATE, &payload)
        .unwrap();
    assert_eq!(
        payload.get("membership").and_then(Value::as_str),
        Some("join")
    );
    assert_eq!(
        payload.get("realm_id").and_then(Value::as_str),
        Some("ak:realm:01964137-0000-7000-8000-000000000101")
    );
    assert_eq!(
        payload.get("actor_id").and_then(Value::as_str),
        Some("did:web:bob.example")
    );
    assert_eq!(
        payload.get("delivery_status").and_then(Value::as_str),
        Some("unroutable")
    );
    assert!(payload.get("delivery_binding").is_none());
}

#[test]
fn direct_strand_create_payload_is_sdk_schema_valid() {
    let created_at = chrono::Utc.with_ymd_and_hms(2026, 7, 6, 0, 0, 0).unwrap();
    let realm_id =
        arkret_identifiers::RealmId::new("ak:realm:01964137-0000-7000-8000-000000000101").unwrap();
    let strand_id = "ak:strand:01964137-0000-7000-8000-000000000102";
    let payload = direct_strand_create_payload(
        realm_id.clone(),
        strand_id,
        "did:web:alice.example",
        created_at,
    )
    .unwrap();

    arkret_schema::event_payload_validator_catalog()
        .unwrap()
        .validate_payload(arkret_wire::EventKind::STRAND_CREATE, &payload)
        .unwrap();

    let object = payload
        .get("object")
        .and_then(Value::as_object)
        .expect("strand object");
    assert!(object.get("kind").is_none());
    assert!(object.get("title").is_none());
    assert_eq!(
        payload
            .pointer("/object/metadata/title")
            .and_then(Value::as_str),
        Some("Direct conversation")
    );
    assert_eq!(
        payload
            .pointer("/object/tracks/discussion/is_primary")
            .and_then(Value::as_bool),
        Some(true)
    );
    assert_eq!(
        object.get("created_at").and_then(Value::as_str),
        Some("2026-07-06T00:00:00.000Z")
    );

    let state = test_state();
    let mut event = unsigned_direct_materialization_event(
        &state,
        "did:web:alice.example",
        "ak:event:01964137-0000-7000-8000-000000000103",
        realm_id.as_str(),
        arkret_wire::EventKind::STRAND_CREATE,
        payload,
    )
    .unwrap();
    attach_create_cell_contract(
        &mut event,
        "ak.component.strand.object.v1",
        strand_id,
        false,
    )
    .unwrap();
    assert!(
        event.preconditions.is_empty(),
        "data-plane strand draft must not carry Move preconditions"
    );
    // v1 carries no producer `effects[]`: the single write on the Strand object
    // cell is what the registered `ak.strand.create` contract derives from
    // `kind + payload` (`event-and-patch.md` §2.4.2). Asserting the derived set
    // is the surviving form of the old "the draft declares exactly one effect".
    let derived = arkret_schema::project_registered_cell_writes(
        &event,
        arkret_canonical::DigestSuite::Sha256,
    )
    .expect("direct strand draft projects its registered cell writes");
    assert_eq!(derived.len(), 1);
    assert_eq!(
        derived[0].cell.as_str(),
        format!("ak:cell:ak.component.strand.object.v1:{strand_id}")
    );
}

#[tokio::test]
async fn direct_realm_genesis_projects_peer_as_timeline_reader() {
    let state = test_state();
    let realm_id = crate::ids::generate_realm_id();
    let main_strand_id = crate::ids::generate("strand");
    let alice = "did:web:alice.example";
    let bob = "did:web:bob.example";
    let pair_key = direct_pair_key(&state, alice, bob).unwrap();

    submit_direct_realm_genesis(&state, &realm_id, &main_strand_id, alice, bob, None)
        .await
        .unwrap();
    install_active_direct_binding_fixture(
        &state,
        &pair_key,
        &realm_id,
        &main_strand_id,
        alice,
        bob,
    );

    assert!(
        crate::routing::spaces::space::realm_has_member_by_id(&state, &realm_id, bob).await,
        "direct peer must be present in the realm member index"
    );
    let joined_at =
        crate::routing::spaces::space::realm_member_joined_at_for_id(&state, &realm_id, bob)
            .await
            .expect("direct peer joined_at projection");
    {
        let projection = state.test_projection().lock();
        let member = projection.member(&realm_id, bob).expect("projected peer");
        assert_eq!(member.state, "join");
    }

    let encrypted_content: arkret_models_crypto::encrypted_envelope::EncryptedEnvelope = serde_json::from_value(json!({
        "scheme": "mls_rfc9420",
        "version": "1.0",
        "group_id": "mls_test",
        "epoch": 1,
        "content_type": "application/vnd.arkret.message+json",
        "aad_visibility_event_id": "hidden",
        "aad": {
            "realm_id": realm_id,
            "event_kind": "ak.message.create"
        },
        "key_ref": {
            "algorithm": "MLS",
            "group_state_ref": "sha256:0000000000000000000000000000000000000000000000000000000000000000"
        },
        "ciphertext": "b3BhcXVl",
        "aad_digest": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
        "payload_digest": "sha256:2222222222222222222222222222222222222222222222222222222222222222"
    }))
    .unwrap();
    let message_payload =
        arkret_models_collaboration::events_payloads::MessageCreatePayload::with_encrypted_content(
            arkret_identifiers::StrandId::new(main_strand_id.clone()).unwrap(),
            "discussion",
            encrypted_content,
        )
        .to_value()
        .unwrap();
    let mut message_op = arkret_event_draft::Operation::create(
        direct_operation_id().unwrap(),
        arkret_identifiers::RealmId::new(realm_id.clone()).unwrap(),
        arkret_wire::EventKind::MESSAGE_CREATE,
        message_payload,
    );
    let event_id = message_op.operation_id.to_string();
    message_op.created_at = (joined_at + chrono::TimeDelta::seconds(1))
        .with_nanosecond(0)
        .expect("post-join message time can be rounded to canonical seconds");
    crate::routing::accept_local_operations(&state, alice, std::slice::from_ref(&message_op))
        .await
        .unwrap();

    let page =
        crate::routing::events::projection::projected_event_page(&state, &realm_id, None, 50)
            .await
            .unwrap()
            .expect("direct timeline projection page");
    let message = page
        .items
        .iter()
        .find(|event| event.event_id == event_id)
        .expect("message projection event");
    let bob_session = soland_services::identity::SessionIdentityState {
        token_hash: "test".to_owned(),
        actor: bob.to_owned(),
        device_id: "ak:device:01904100-0000-7000-8000-000000000001".to_owned(),
        audience: "test".to_owned(),
        session_public_key: None,
        agent_session: None,
        expires_at: joined_at + chrono::TimeDelta::hours(1),
        created_at: joined_at,
        revoked_at: None,
    };
    assert!(
        crate::routing::spaces::space::realm_event_visible_to_session(
            &state,
            &realm_id,
            message.created_at,
            message.sender.as_deref(),
            Some(&bob_session),
        )
        .await,
        "direct peer must pass realm event visibility for post-join messages"
    );
}

#[tokio::test]
async fn participant_leave_retires_direct_binding() {
    let state = test_state();
    let realm_id = crate::ids::generate_realm_id();
    let main_strand_id = crate::ids::generate("strand");
    let alice = "did:web:alice.example";
    let bob = "did:web:bob.example";
    let pair_key = direct_pair_key(&state, alice, bob).unwrap();

    submit_direct_realm_genesis(&state, &realm_id, &main_strand_id, alice, bob, None)
        .await
        .unwrap();
    install_active_direct_binding_fixture(
        &state,
        &pair_key,
        &realm_id,
        &main_strand_id,
        alice,
        bob,
    );

    let leave_payload = arkret_models_collaboration::governance::membership_invite::MembershipPayload::transition(
        arkret_models_collaboration::governance::membership_invite::MembershipPayloadState::Leave,
        arkret_identifiers::Did::new(bob.to_owned()).unwrap(),
        "direct conversation participant left",
    )
    .to_value()
    .unwrap();
    let leave = arkret_event_draft::Operation::create(
        direct_operation_id().unwrap(),
        arkret_identifiers::RealmId::new(realm_id).unwrap(),
        arkret_wire::EventKind::MEMBER_STATE,
        leave_payload,
    );
    crate::routing::accept_local_operations(&state, bob, std::slice::from_ref(&leave))
        .await
        .unwrap();

    assert!(active_direct_binding(&state, &pair_key).is_none());
    assert_eq!(
        state
            .contacts()
            .direct_binding(&pair_key)
            .expect("retired binding")
            .state,
        "retired"
    );
}
