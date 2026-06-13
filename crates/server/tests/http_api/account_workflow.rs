//! Integration tests — `account_workflow` domain.
//!
//! Helpers live in [`super::common`]; pull them in via `use`.

#![allow(unused_imports)]
use super::common::*;

#[tokio::test]
async fn account_viewer_returns_device_summaries() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;

    let viewer: Value = TestClient::get("http://server/_cokret/self/account/viewer")
        .add_header("authorization", format!("Bearer {token}"), true)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();

    assert_eq!(viewer["principal_id"], "did:web:alice.example");
    assert_eq!(viewer["state"], "active");
    let devices = viewer["devices"].as_array().expect("viewer devices array");
    assert_eq!(devices.len(), 1);
    assert_eq!(
        devices[0]["device_id"],
        "ck:device:01904100-0000-7000-8000-a11ce0000001"
    );
    assert_eq!(devices[0]["display_name"], "Alice Desktop");
    assert_eq!(devices[0]["status"], "active");
}

#[tokio::test]
async fn account_contacts_and_realm_lifecycle_workflow() {
    let state = AppState::new(test_config(), Db { pool: None });
    let alice = dev_token(state.clone()).await;
    let bob = register_account(
        state.clone(),
        "did:web:bob.example",
        "@bob",
        "ck:device:01904100-0000-7000-8000-b0b0b0000002",
    )
    .await;

    let duplicate = TestClient::post("http://server/_soland/self/account/register")
        .json(&serde_json::json!({
            "did": "did:web:bob.example",
            "handle": "@bob",
            "device_id": "ck:device:01904100-0000-7000-8000-b0b0b0000022"
        }))
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(duplicate.status_code.unwrap().as_u16(), 409);

    let hidden_bob: Value = TestClient::post("http://server/_cokret/find/directory/search-users")
        .json(&serde_json::json!({"query": "bob"}))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert!(hidden_bob["users"].as_array().unwrap().is_empty());

    let me: Value = TestClient::get("http://server/_soland/self/account/me")
        .add_header("authorization", format!("Bearer {bob}"), true)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(me["did"], "did:web:bob.example");

    let contact_request: Value = TestClient::post("http://server/_soland/self/contacts/request")
        .add_header("authorization", format!("Bearer {alice}"), true)
        .json(&serde_json::json!({"target": "did:web:bob.example"}))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(contact_request["state"], "pending_outgoing");
    let contact_request_id = contact_request["request_event_ref"]
        .as_str()
        .unwrap()
        .to_owned();

    let duplicate_contact_request: Value =
        TestClient::post("http://server/_soland/self/contacts/request")
            .add_header("authorization", format!("Bearer {alice}"), true)
            .json(&serde_json::json!({"target": "did:web:bob.example"}))
            .send(&app_from_state(state.clone()))
            .await
            .take_json()
            .await
            .unwrap();
    assert_eq!(duplicate_contact_request["state"], "pending_outgoing");

    let accepted: Value = TestClient::post("http://server/_soland/self/contacts/respond")
        .add_header("authorization", format!("Bearer {bob}"), true)
        .json(&serde_json::json!({
            "request_id": contact_request_id,
            "requester": "did:web:alice.example",
            "action": "accept"
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(accepted["state"], "accepted");

    let accepted_again: Value = TestClient::post("http://server/_soland/self/contacts/respond")
        .add_header("authorization", format!("Bearer {bob}"), true)
        .json(&serde_json::json!({
            "request_id": contact_request["request_event_ref"],
            "requester": "did:web:alice.example",
            "action": "accept"
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(accepted_again["state"], "accepted");

    let reject_after_accept = TestClient::post("http://server/_soland/self/contacts/respond")
        .add_header("authorization", format!("Bearer {bob}"), true)
        .json(&serde_json::json!({
            "request_id": contact_request["request_event_ref"],
            "requester": "did:web:alice.example",
            "action": "reject"
        }))
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(reject_after_accept.status_code.unwrap().as_u16(), 409);

    let bob_contacts: Value = TestClient::get("http://server/_soland/self/contacts")
        .add_header("authorization", format!("Bearer {bob}"), true)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(bob_contacts["contacts"].as_array().unwrap().len(), 1);

    let visible_bob: Value = TestClient::post("http://server/_cokret/find/directory/search-users")
        .add_header("authorization", format!("Bearer {alice}"), true)
        .json(&serde_json::json!({"query": "bob"}))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(visible_bob["users"][0]["did"], "did:web:bob.example");

    let created_realm = seed_test_realm(
        &state,
        "did:web:alice.example",
        "Workflow Realm",
        Some("created by lifecycle workflow"),
        "invite_only",
        &["did:web:soland.local"],
        &[],
    )
    .await;
    let realm_id = created_realm["realm_id"].as_str().unwrap().to_owned();
    assert!(realm_id.starts_with("ck:realm:"));
    assert_eq!(created_realm["owner"], "did:web:alice.example");

    let hidden_realm: Value =
        TestClient::post("http://server/_cokret/find/directory/search-realms")
            .json(&serde_json::json!({"query": "Workflow Realm"}))
            .send(&app_from_state(state.clone()))
            .await
            .take_json()
            .await
            .unwrap();
    assert!(hidden_realm["realms"].as_array().unwrap().is_empty());

    let invite_realm = seed_test_realm(
        &state,
        "did:web:alice.example",
        "Invite Token Realm",
        None,
        "invite_only",
        &[],
        &["did:web:bob.example"],
    )
    .await;
    let invite_realm_id = invite_realm["realm_id"].as_str().unwrap().to_owned();
    let bob_invites: Value = TestClient::get("http://server/_cokret/self/authz/invites")
        .add_header("authorization", format!("Bearer {bob}"), true)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(bob_invites["invites"].as_array().unwrap().len(), 1);
    assert_eq!(bob_invites["invites"][0]["realm_id"], invite_realm_id);
    assert_eq!(
        bob_invites["invites"][0]["third_party_id"]["recipient_service_did"],
        "did:web:soland.local"
    );
    assert_eq!(
        bob_invites["invites"][0]["join_rule_snapshot"]["introduction_evidence_digest"],
        format!("sha256:{}", "1".repeat(64))
    );
    let invite_token = bob_invites["invites"][0]["join_rule_snapshot"]["invite_token"]
        .as_str()
        .unwrap()
        .to_owned();
    let invalid_invite_resolve =
        TestClient::post("http://server/_cokret/find/directory/resolve-realm")
            .json(&serde_json::json!({"invite_token": "ck:invite-token:invalid"}))
            .send(&app_from_state(state.clone()))
            .await;
    assert_eq!(invalid_invite_resolve.status_code.unwrap().as_u16(), 404);
    let invite_resolve: Value =
        TestClient::post("http://server/_cokret/find/directory/resolve-realm")
            .json(&serde_json::json!({"invite_token": invite_token}))
            .send(&app_from_state(state.clone()))
            .await
            .take_json()
            .await
            .unwrap();
    assert_eq!(invite_resolve["realm_preview"]["realm_id"], invite_realm_id);

    let listed_realm = seed_test_realm(
        &state,
        "did:web:alice.example",
        "Listed Directory Realm",
        None,
        "listed",
        &[],
        &[],
    )
    .await;
    let listed_realm_id = listed_realm["realm_id"].as_str().unwrap().to_owned();
    let listed_search: Value =
        TestClient::post("http://server/_cokret/find/directory/search-realms")
            .json(&serde_json::json!({"query": "Listed Directory Realm"}))
            .send(&app_from_state(state.clone()))
            .await
            .take_json()
            .await
            .unwrap();
    assert_eq!(
        listed_search["realms"][0]["realm_id"],
        listed_realm_id.as_str()
    );
    let anonymous_sync_after_listed =
        account_subscribe_frame(state.clone(), None, "catchup=true").await;
    assert!(
        !anonymous_sync_after_listed["realms"]
            .as_object()
            .unwrap()
            .contains_key(&listed_realm_id)
    );

    let unlisted_realm = seed_test_realm(
        &state,
        "did:web:alice.example",
        "Unlisted Directory Realm",
        None,
        "unlisted",
        &[],
        &[],
    )
    .await;
    let unlisted_realm_id = unlisted_realm["realm_id"].as_str().unwrap().to_owned();
    let unlisted_search: Value =
        TestClient::post("http://server/_cokret/find/directory/search-realms")
            .json(&serde_json::json!({"query": "Unlisted Directory Realm"}))
            .send(&app_from_state(state.clone()))
            .await
            .take_json()
            .await
            .unwrap();
    assert!(unlisted_search["realms"].as_array().unwrap().is_empty());
    let unlisted_resolve: Value =
        TestClient::post("http://server/_cokret/find/directory/resolve-realm")
            .json(&serde_json::json!({"realm_id": unlisted_realm_id.clone()}))
            .send(&app_from_state(state.clone()))
            .await
            .take_json()
            .await
            .unwrap();
    assert_eq!(
        unlisted_resolve["realm_preview"]["realm_id"],
        unlisted_realm_id
    );

    let anonymous_resolve = TestClient::post("http://server/_cokret/find/directory/resolve-realm")
        .json(&serde_json::json!({"realm_id": realm_id}))
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(anonymous_resolve.status_code.unwrap().as_u16(), 404);

    let owner_resolve: Value =
        TestClient::post("http://server/_cokret/find/directory/resolve-realm")
            .add_header("authorization", format!("Bearer {alice}"), true)
            .json(&serde_json::json!({"realm_id": realm_id}))
            .send(&app_from_state(state.clone()))
            .await
            .take_json()
            .await
            .unwrap();
    assert_eq!(owner_resolve["realm_preview"]["realm_id"], realm_id);

    let locked_realm = seed_test_realm(
        &state,
        "did:web:alice.example",
        "Locked Plaintext Realm",
        None,
        "invite_only",
        &[],
        &[],
    )
    .await;
    let locked_realm_id = locked_realm["realm_id"].as_str().unwrap();
    let plaintext_without_service = post_message_event(
        state.clone(),
        &alice,
        "did:web:alice.example",
        locked_realm_id,
        locked_realm_id,
        serde_json::json!({"body": "should be denied"}),
        false,
    )
    .await;
    assert_eq!(plaintext_without_service.as_u16(), 403);

    let invalid_encrypted = post_message_event(
        state.clone(),
        &alice,
        "did:web:alice.example",
        locked_realm_id,
        locked_realm_id,
        serde_json::json!({"ciphertext": "opaque"}),
        true,
    )
    .await;
    assert_eq!(invalid_encrypted.as_u16(), 400);

    let encrypted_message = submit_message_event(
        state.clone(),
        &alice,
        "did:web:alice.example",
        locked_realm_id,
        locked_realm_id,
        encrypted_envelope("ck.message.v1", "opaque-ciphertext"),
        true,
    )
    .await;
    assert!(
        encrypted_message["event_id"]
            .as_str()
            .unwrap()
            .starts_with("ck:event:")
    );

    let bob_private_sync = account_subscribe_frame(state.clone(), Some(&bob), "catchup=true").await;
    assert!(
        !bob_private_sync["realms"]
            .as_object()
            .unwrap()
            .contains_key(&realm_id)
    );

    let with_bob = add_test_realm_member(&state, &realm_id, "did:web:bob.example");
    assert!(
        with_bob["members"]
            .as_array()
            .unwrap()
            .iter()
            .any(|member| member["did"] == "did:web:bob.example")
    );

    let sent_message = submit_message_event(
        state.clone(),
        &alice,
        "did:web:alice.example",
        &realm_id,
        "ck:flow:workflow",
        serde_json::json!({"body": "hello workflow"}),
        false,
    )
    .await;
    assert!(
        sent_message["operation_id"]
            .as_str()
            .unwrap()
            .starts_with("ck:operation:")
    );
    assert_eq!(sent_message["realm_id"], realm_id);
    assert_eq!(sent_message["source_realm_id"], realm_id);
    let send_cursor = decode_cursor(sent_message["sync_token"].as_str().unwrap());
    assert_eq!(send_cursor["v"], "1");
    assert!(send_cursor["h"].as_str().is_some_and(|h| h.len() >= 22));
    assert!(send_cursor.get("_positions").is_none());

    let invalid_block_message = post_message_event(
        state.clone(),
        &alice,
        "did:web:alice.example",
        &realm_id,
        "ck:flow:workflow",
        serde_json::json!({"kind": "ck.content.composite", "body": "invalid", "parts": [{"kind": "ck.content.image", "body": "image"}]}),
        false,
    )
    .await;
    assert_eq!(invalid_block_message.as_u16(), 400);

    let non_canonical_message = post_message_event(
        state.clone(),
        &alice,
        "did:web:alice.example",
        &realm_id,
        "ck:flow:workflow",
        serde_json::json!({"kind": "ck.content.location", "body": "location", "latitude": 31.2304, "longitude": 121.4737}),
        false,
    )
    .await;
    assert_eq!(non_canonical_message.as_u16(), 400);

    let invalid_mention_message = post_message_event(
        state.clone(),
        &alice,
        "did:web:alice.example",
        &realm_id,
        "ck:flow:workflow",
        serde_json::json!({"body": "bad mention", "mentions": [{"type": "actor", "did": "alice"}]}),
        false,
    )
    .await;
    assert_eq!(invalid_mention_message.as_u16(), 400);

    let block_message = submit_message_event(
        state.clone(),
        &alice,
        "did:web:alice.example",
        &realm_id,
        "ck:flow:workflow",
        serde_json::json!({
            "kind": "ck.content.composite",
            "body": "structured hello",
            "mentions": [
                "did:web:bob.example",
                {"type": "flow", "flow_id": "ck:flow:01904100-0000-7000-8000-170d4f3bfc7b"}
            ],
            "parts": [
                {"kind": "ck.content.text", "body": "structured hello"},
                {"kind": "ck.content.location", "body": "location", "latitude": 312304000, "longitude": 1214737000},
                {"kind": "ck.content.poll", "body": "ship?", "question": "ship?", "options": ["yes", "no"]}
            ]
        }),
        false,
    )
    .await;
    assert!(
        block_message["event_id"]
            .as_str()
            .is_some_and(|event_id| event_id.starts_with("ck:event:")),
        "block message response: {block_message}"
    );

    let workflow_thread_id = expected_flow_id_for_scope(&realm_id);
    let thread: Value = TestClient::get(format!(
        "http://server/_soland/self/index/thread?thread_id={workflow_thread_id}"
    ))
    .add_header("authorization", format!("Bearer {alice}"), true)
    .send(&app_from_state(state.clone()))
    .await
    .take_json()
    .await
    .unwrap();
    assert_eq!(thread["events"][0]["content"]["body"], "hello workflow");

    let message_search: Value = TestClient::post("http://server/_soland/self/index/search")
        .add_header("authorization", format!("Bearer {alice}"), true)
        .json(&serde_json::json!({
            "query": "workflow",
            "realm_ids": [realm_id],
            "object_kinds": ["message"]
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(
        message_search["results"][0]["event_id"],
        sent_message["event_id"]
    );

    let notifications: Value =
        TestClient::get("http://server/_soland/self/index/notifications?actor=did:web:bob.example")
            .send(&app_from_state(state.clone()))
            .await
            .take_json()
            .await
            .unwrap();
    assert_eq!(notifications["unread_count"], 2);
    assert!(
        notifications["notifications"]
            .as_array()
            .unwrap()
            .iter()
            .any(|notification| notification["event_ref"] == sent_message["event_id"])
    );

    let sync_with_message =
        account_subscribe_frame(state.clone(), Some(&alice), "catchup=true").await;
    let synced_members = sync_with_message["realms"][&realm_id]["members"]
        .as_array()
        .unwrap();
    assert!(
        synced_members
            .iter()
            .any(|member| member["actor_id"] == "did:web:alice.example")
    );
    assert!(
        synced_members
            .iter()
            .any(|member| member["actor_id"] == "did:web:bob.example")
    );
    assert_eq!(
        sync_with_message["realms"][&realm_id]["summary"]["members"],
        sync_with_message["realms"][&realm_id]["members"]
    );
    let cursor = decode_cursor(
        sync_with_message["cursor"]
            .as_str()
            .unwrap_or_else(|| panic!("sync response missing cursor: {sync_with_message}")),
    );
    assert_eq!(cursor["v"], "1");
    assert_eq!(cursor["purpose"], "stream");
    assert!(cursor["t"].as_str().is_some());
    assert!(cursor["x"].as_i64().unwrap() > 0);
    assert!(cursor["h"].as_str().is_some_and(|h| h.len() >= 22));
    assert!(cursor.get("_ctx").is_none());
    assert!(cursor.get("_positions").is_none());
    assert!(cursor.get("_mac").is_none());
    assert!(cursor.get("_sig").is_none());
    assert!(cursor.get("issuer_kid").is_none());
    assert_eq!(
        sync_with_message["realms"][&realm_id]["timeline"]["events"][0]["event_id"],
        sent_message["event_id"]
    );
    assert_eq!(
        sync_with_message["realms"][&realm_id]["timeline"]["events"][0]["flow_id"],
        expected_flow_id_for_scope(&realm_id)
    );
    // Message v1 exposes the timeline track as the const string `discussion`.
    assert_eq!(
        sync_with_message["realms"][&realm_id]["timeline"]["events"][0]["track_name"],
        "discussion"
    );
    assert_eq!(
        sync_with_message["realms"][&realm_id]["summary"]["flow"]["schema"],
        "ck.schema.flow.v1"
    );

    // After the realms-incremental optimisation a fully-quiet realm
    // is omitted from incremental delta frames. The client keeps its
    // cached projection; only realms that genuinely changed appear.
    // `max_wait_ms=0` opts out of long-poll so the test returns
    // immediately instead of holding for the default window.
    let incremental_noop = account_subscribe_frame(
        state.clone(),
        Some(&alice),
        &format!(
            "catchup=true&max_wait_ms=0&after={}",
            sync_with_message["cursor"].as_str().unwrap()
        ),
    )
    .await;
    assert!(
        incremental_noop["realms"][&realm_id].is_null(),
        "unchanged realm should be absent from incremental noop delta: {incremental_noop}"
    );

    tokio::time::sleep(Duration::from_millis(2)).await;
    let second_message = submit_message_event(
        state.clone(),
        &alice,
        "did:web:alice.example",
        &realm_id,
        "ck:flow:workflow",
        serde_json::json!({"body": "second workflow"}),
        false,
    )
    .await;
    let incremental_after_message = account_subscribe_frame(
        state.clone(),
        Some(&alice),
        &format!(
            "catchup=true&max_wait_ms=0&after={}",
            sync_with_message["cursor"].as_str().unwrap()
        ),
    )
    .await;
    let incremental_events = incremental_after_message["realms"][&realm_id]["timeline"]["events"]
        .as_array()
        .unwrap();
    assert_eq!(incremental_events.len(), 1);
    assert_eq!(
        incremental_events[0]["event_id"],
        second_message["event_id"]
    );

    let mismatch = TestClient::get(format!(
        "http://server/_cokret/self/account/subscribe?catchup=true&after={}",
        sync_with_message["cursor"].as_str().unwrap()
    ))
    .add_header("authorization", format!("Bearer {bob}"), true)
    .send(&app_from_state(state.clone()))
    .await;
    assert_eq!(mismatch.status_code.unwrap().as_u16(), 400);

    let filter_mismatch = TestClient::get(format!(
        "http://server/_cokret/self/account/subscribe?catchup=true&after={}&filter=%7B%22realms%22%3A%5B%22{}%22%5D%7D",
        sync_with_message["cursor"].as_str().unwrap(),
        realm_id
    ))
        .add_header("authorization", format!("Bearer {alice}"), true)
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(filter_mismatch.status_code.unwrap().as_u16(), 400);

    let mut expired_cursor = cursor.clone();
    expired_cursor["x"] = serde_json::json!(1);
    let mut expired = TestClient::get(format!(
        "http://server/_cokret/self/account/subscribe?catchup=true&after={}",
        encode_cursor(&expired_cursor)
    ))
    .add_header("authorization", format!("Bearer {alice}"), true)
    .send(&app_from_state(state.clone()))
    .await;
    assert_eq!(expired.status_code.unwrap(), StatusCode::GONE);
    let expired_body: Value = expired.take_json().await.unwrap();
    assert_eq!(expired_body["error"]["code"], "cursor_expired");

    let exported: Value = TestClient::get(format!(
        "http://server/_cokret/self/realms/{realm_id}/export"
    ))
    .add_header("authorization", format!("Bearer {alice}"), true)
    .send(&app_from_state(state.clone()))
    .await
    .take_json()
    .await
    .unwrap();
    assert_eq!(exported["schema"], "ck.export.realm.v1");
    assert!(
        exported["operations"]
            .as_array()
            .unwrap()
            .iter()
            .any(|operation| operation["operation_id"] == sent_message["operation_id"])
    );

    let waited_sync = account_subscribe_frame(state.clone(), Some(&alice), "catchup=true").await;
    assert_eq!(
        waited_sync["realms"][&realm_id]["timeline"]["events"][0]["event_id"],
        sent_message["event_id"]
    );

    let invalid_wait = TestClient::get("http://server/_cokret/self/account/subscribe?catchup=true")
        .add_header("authorization", format!("Bearer {alice}"), true)
        .add_header("x-cokret-wait-for", "not-a-sync-token", true)
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(invalid_wait.status_code.unwrap().as_u16(), 400);

    // Protocol snapshot head fails closed: soland cannot produce a signed
    // ck.schema.snapshot.v1 manifest, so `ck.self.snapshot.query.manifest_head` answers
    // `not_implemented` (spec service-surface.md §5.2).
    let mut protocol_head = TestClient::get(format!(
        "http://server/_cokret/self/snapshot/head?realm_id={realm_id}"
    ))
    .send(&app_from_state(state.clone()))
    .await;
    assert_eq!(protocol_head.status_code.unwrap().as_u16(), 501);
    let protocol_head_body: Value = protocol_head.take_json().await.unwrap();
    assert_eq!(protocol_head_body["error"]["code"], "not_implemented");

    // The deployment-local dev snapshot head lives on the product face.
    let snapshot: Value = TestClient::get(format!(
        "http://server/_soland/self/sync/snapshot-head?realm_id={realm_id}"
    ))
    .send(&app_from_state(state.clone()))
    .await
    .take_json()
    .await
    .unwrap();
    assert_eq!(snapshot["frontier"]["message_count"], 3);
    assert!(snapshot["id"].as_str().unwrap().starts_with("ck:snapshot:"));
    assert!(
        !snapshot["dev_digest"]["digest"]
            .as_str()
            .unwrap()
            .is_empty()
    );
    // Snapshot v1 (round 9): chunk_id is now a typed integer in the SDK
    // shape; small test states fit in a single 256 KiB chunk so chunk[0]
    // .digest is the state_digest and chunk_count == 1.
    assert_eq!(snapshot["chunks"][0]["chunk_id"], 0);
    assert_eq!(snapshot["chunks"][0]["digest"], snapshot["state_digest"]);
    assert_eq!(snapshot["chunk_count"], 1);
    assert_eq!(
        snapshot["merkle_root"].as_str().unwrap(),
        snapshot["state_digest"].as_str().unwrap(),
        "single-chunk Merkle root collapses to the leaf digest"
    );
    // GeneratorProof envelope is present + carries a non-empty signature.
    let proof = &snapshot["generator_proof"];
    assert!(proof.is_object(), "generator_proof must be present");
    assert!(
        !proof["signature"]["jws"].as_str().unwrap().is_empty(),
        "generator_proof.signature.jws must be non-empty"
    );
    assert_eq!(proof["chunk_count"], 1);
    assert_eq!(
        proof["realm_id"].as_str().unwrap(),
        realm_id,
        "generator_proof.realm_id matches the snapshot Realm"
    );

    let snapshot_chunk: Value = TestClient::get(format!(
        "http://server/_soland/self/sync/snapshot-chunk?snapshot_ref={}&chunk_id=0",
        snapshot["id"].as_str().unwrap()
    ))
    .send(&app_from_state(state.clone()))
    .await
    .take_json()
    .await
    .unwrap();
    assert_eq!(snapshot_chunk["digest"], snapshot["state_digest"]);
    assert_eq!(snapshot_chunk["verified"], true);
    assert!(!snapshot_chunk["bytes_base64"].as_str().unwrap().is_empty());
    // Snapshot v1: chunk responses surface the audit-path so receivers
    // can verify the chunk against the head's merkle_root without
    // trusting the chunk source.
    assert!(snapshot_chunk["audit_path"].is_array());
    assert_eq!(
        snapshot_chunk["tree_size"], 1,
        "single-chunk tree has tree_size == 1"
    );
    assert_eq!(
        snapshot_chunk["merkle_root"].as_str().unwrap(),
        snapshot["merkle_root"].as_str().unwrap(),
        "chunk merkle_root matches head merkle_root"
    );

    let kicked = remove_test_realm_member(&state, &realm_id, "did:web:bob.example");
    assert!(
        !kicked["members"]
            .as_array()
            .unwrap()
            .iter()
            .any(|member| member["did"] == "did:web:bob.example")
    );

    let deleted = delete_test_realm(&state, &realm_id).await;
    assert_eq!(deleted["deleted"], true);

    let directory: Value = TestClient::post("http://server/_cokret/find/directory/search-realms")
        .json(&serde_json::json!({"query": "Workflow Realm"}))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert!(directory["realms"].as_array().unwrap().is_empty());

    let index: Value = TestClient::post("http://server/_soland/self/index/query")
        .json(&serde_json::json!({"realm_ids": [realm_id]}))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert!(index["results"].as_array().unwrap().is_empty());

    let sync = account_subscribe_frame(state.clone(), None, "catchup=true").await;
    assert!(!sync["realms"].as_object().unwrap().contains_key(&realm_id));

    let audit_events: Value = TestClient::get("http://server/_soland/admin/audit/events?limit=20")
        .add_header("authorization", format!("Bearer {alice}"), true)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert!(!audit_events["events"].as_array().unwrap().is_empty());
    let audit_page_one: Value = TestClient::get("http://server/_soland/admin/audit/events?limit=1")
        .add_header("authorization", format!("Bearer {alice}"), true)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    let audit_cursor = audit_page_one["next_cursor"]
        .as_str()
        .expect("audit page should expose next cursor");
    let audit_page_two: Value = TestClient::get(format!(
        "http://server/_soland/admin/audit/events?limit=1&cursor={audit_cursor}"
    ))
    .add_header("authorization", format!("Bearer {alice}"), true)
    .send(&app_from_state(state.clone()))
    .await
    .take_json()
    .await
    .unwrap();
    assert_ne!(
        audit_page_one["events"][0]["audit_id"],
        audit_page_two["events"][0]["audit_id"]
    );
    let forbidden_audit =
        TestClient::get("http://server/_soland/admin/audit/events?actor=did:web:bob.example")
            .add_header("authorization", format!("Bearer {alice}"), true)
            .send(&app_from_state(state.clone()))
            .await;
    assert_eq!(forbidden_audit.status_code.unwrap().as_u16(), 403);

    let logout: Value = TestClient::post("http://server/_soland/gate/auth/logout")
        .add_header("authorization", format!("Bearer {bob}"), true)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(logout["revoked"], true);
    {
        let sessions = state.persistence.sessions().snapshot_all().await.unwrap();
        assert!(!sessions.iter().any(|session| session.token_hash == bob));
        let bob_session = sessions
            .iter()
            .find(|session| session.actor == "did:web:bob.example")
            .expect("hashed bob session remains for revocation audit");
        assert_ne!(bob_session.token_hash, bob);
        assert_eq!(bob_session.audience, "did:web:soland.local");
        assert!(bob_session.revoked_at.is_some());
    }
    let revoked_me = TestClient::get("http://server/_soland/self/account/me")
        .add_header("authorization", format!("Bearer {bob}"), true)
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(revoked_me.status_code.unwrap().as_u16(), 401);

    let audit_actions: std::collections::BTreeSet<_> = state
        .persistence
        .audit()
        .snapshot_all()
        .await
        .unwrap()
        .iter()
        .filter_map(|entry| entry["action"].as_str().map(ToOwned::to_owned))
        .collect();
    for expected in ["account.register", "auth.dev_login", "auth.logout"] {
        assert!(audit_actions.contains(expected));
    }
}
