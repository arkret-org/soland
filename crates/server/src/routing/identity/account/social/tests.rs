use chrono::{TimeZone, Timelike};
use soland_data::Db;

use super::*;
use crate::config::AppConfig;

fn test_state() -> AppState {
    AppState::new(AppConfig::test_default(), Db { pool: None })
}

#[test]
fn direct_realm_create_payload_is_sdk_schema_valid() {
    let state = test_state();
    let created_at = chrono::Utc.with_ymd_and_hms(2026, 7, 6, 0, 0, 0).unwrap();
    let payload = direct_realm_create_payload(
        &state,
        cokret_sdk::RealmId::new("ck:realm:01964137-0000-7000-8000-000000000101").unwrap(),
        "did:web:alice.example",
        created_at,
    )
    .unwrap();

    cokret_sdk::schema::event_payload_validator_catalog()
        .unwrap()
        .validate_payload(cokret_sdk::events::kinds::REALM_CREATE, &payload)
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
        object
            .get("fields")
            .and_then(|fields| fields.get("conversation_kind"))
            .and_then(Value::as_str),
        Some("direct_message")
    );
    assert_eq!(
        object.get("created_at").and_then(Value::as_str),
        Some("2026-07-06T00:00:00Z")
    );
}

#[test]
fn direct_member_join_payload_is_sdk_schema_valid() {
    let payload = direct_member_join_payload(
        cokret_sdk::RealmId::new("ck:realm:01964137-0000-7000-8000-000000000101").unwrap(),
        "did:web:bob.example",
    )
    .unwrap();

    cokret_sdk::schema::event_payload_validator_catalog()
        .unwrap()
        .validate_payload(cokret_sdk::events::kinds::MEMBER_STATE, &payload)
        .unwrap();
    assert_eq!(
        payload.get("membership").and_then(Value::as_str),
        Some("join")
    );
    assert_eq!(
        payload.get("realm_id").and_then(Value::as_str),
        Some("ck:realm:01964137-0000-7000-8000-000000000101")
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
    let payload = direct_strand_create_payload(
        cokret_sdk::RealmId::new("ck:realm:01964137-0000-7000-8000-000000000101").unwrap(),
        "ck:strand:01964137-0000-7000-8000-000000000102",
        "did:web:alice.example",
        created_at,
    )
    .unwrap();

    cokret_sdk::schema::event_payload_validator_catalog()
        .unwrap()
        .validate_payload(cokret_sdk::events::kinds::STRAND_CREATE, &payload)
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
        Some("2026-07-06T00:00:00Z")
    );
}

#[tokio::test]
async fn direct_realm_genesis_projects_peer_as_timeline_reader() {
    let state = test_state();
    let realm_id = crate::ids::generate_realm_id();
    let main_strand_id = crate::ids::generate("strand");
    let alice = "did:web:alice.example";
    let bob = "did:web:bob.example";

    submit_direct_realm_genesis(&state, &realm_id, &main_strand_id, alice, bob)
        .await
        .unwrap();

    assert!(
        crate::routing::spaces::space::realm_has_member_by_id(&state, &realm_id, bob).await,
        "direct peer must be present in the realm member index"
    );
    let joined_at =
        crate::routing::spaces::space::realm_member_joined_at_for_id(&state, &realm_id, bob)
            .await
            .expect("direct peer joined_at projection");
    {
        let projection = state.projection.lock();
        let member = projection.member(&realm_id, bob).expect("projected peer");
        assert_eq!(member.state, "join");
    }

    let message_id = crate::ids::generate("message");
    let encrypted_content = json!({
        "scheme": "mls-rfc9420",
        "version": "1.0",
        "group_id": "mls_test",
        "epoch": 1,
        "content_type": "application/vnd.cokret.message+json",
        "aad_visibility_event_id": "hidden",
        "aad": {
            "realm_id": realm_id,
            "event_kind": "ck.message.create"
        },
        "key_ref": {
            "algorithm": "MLS",
            "group_state_ref": "sha256:0000000000000000000000000000000000000000000000000000000000000000"
        },
        "ciphertext": "b3BhcXVl",
        "aad_digest": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
        "payload_digest": "sha256:2222222222222222222222222222222222222222222222222222222222222222"
    });
    let message_payload = cokret_sdk::models::MessageCreatePayload::with_encrypted_content(
        cokret_sdk::StrandId::new(main_strand_id.clone()).unwrap(),
        "discussion",
        encrypted_content,
    )
    .with_message_id(message_id.clone())
    .to_value()
    .unwrap();
    let mut message_op = cokret_sdk::Operation::create(
        direct_operation_id().unwrap(),
        cokret_sdk::RealmId::new(realm_id.clone()).unwrap(),
        cokret_sdk::events::kinds::MESSAGE_CREATE,
        message_payload,
    );
    let event_id = message_op.operation_id.to_string();
    message_op.created_at = joined_at
        .with_nanosecond(0)
        .expect("joined_at can be rounded to canonical seconds");
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
    let bob_session = crate::state::SessionRecord {
        token_hash: "test".to_owned(),
        actor: bob.to_owned(),
        device_id: "ck:device:01904100-0000-7000-8000-000000000001".to_owned(),
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
