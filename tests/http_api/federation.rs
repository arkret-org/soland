//! Integration tests — `federation` domain.
//!
//! Helpers live in [`super::common`]; pull them in via `use`.

#![allow(unused_imports)]
use super::common::*;

#[tokio::test]
async fn federation_accepts_idempotent_replayed_operations() {
    let state = AppState::new(test_config(), Db { pool: None });
    let push_url = "http://server/api/v1/federation/push-operations";
    let operation = Operation::create(
        OperationId::new("cx:operation:01904100-0000-7000-8000-4b147e97831e").unwrap(),
        RealmId::new("cx:realm:01904100-0000-7000-8000-20d6cfd24be6").unwrap(),
        kinds::CX_MESSAGE_CREATE,
        serde_json::json!({
            "event_id": "cx:event:01904100-0000-7000-8000-19d11d370b0e",
            "sender": "did:web:remote.example",
            "thread_id": "cx:flow:federation",
            "body": "from federation"
        }),
    );

    let first_body = serde_json::json!({
        "origin": "did:web:remote.example",
        "destination": "did:web:soland.local",
        "space_id": "cx:realm:01904100-0000-7000-8000-20d6cfd24be6",
        "service_binding_ref": "did:web:remote.example#soland",
        "operations": [operation.clone()]
    });
    let mut first_req = TestClient::post(push_url).json(&first_body);
    for (name, value) in signed_federation_push_headers(
        "did:web:remote.example",
        "did:web:soland.local",
        push_url,
        &first_body,
    ) {
        first_req = first_req.add_header(name, value, true);
    }
    let first: Value = first_req
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(
        first["accepted"][0],
        "cx:operation:01904100-0000-7000-8000-4b147e97831e"
    );
    assert!(first["rejected"].as_array().unwrap().is_empty());

    let unsigned = TestClient::post(push_url)
        .json(&first_body)
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(unsigned.status_code.unwrap().as_u16(), 401);

    let pulled: Value = TestClient::get(
        "http://server/api/v1/federation/pull-operations?space_id=cx:realm:01904100-0000-7000-8000-20d6cfd24be6",
    )
    .send(&app_from_state(state.clone()))
    .await
    .take_json()
    .await
    .unwrap();
    assert_eq!(
        pulled["operations"][0]["operation_id"],
        "cx:operation:01904100-0000-7000-8000-4b147e97831e"
    );

    let bootstrap: Value = TestClient::get(
        "http://server/api/v1/federation/pull-operations?space_id=cx:realm:01904100-0000-7000-8000-20d6cfd24be6&snapshot_bootstrap=true",
    )
    .send(&app_from_state(state.clone()))
    .await
    .take_json()
    .await
    .unwrap();
    assert_eq!(
        bootstrap["snapshot_bootstrap"]["manifest"]["space_id"],
        "cx:realm:01904100-0000-7000-8000-20d6cfd24be6"
    );
    assert!(
        bootstrap["snapshot_bootstrap"]["state_digest"]
            .as_str()
            .unwrap()
            .starts_with("sha256:")
    );

    let replay_body = serde_json::json!({
        "origin": "did:web:remote.example",
        "destination": "did:web:soland.local",
        "space_id": "cx:realm:01904100-0000-7000-8000-20d6cfd24be6",
        "service_binding_ref": "did:web:remote.example#soland",
        "operations": [operation]
    });
    let mut replay_req = TestClient::post(push_url).json(&replay_body);
    for (name, value) in signed_federation_push_headers(
        "did:web:remote.example",
        "did:web:soland.local",
        push_url,
        &replay_body,
    ) {
        replay_req = replay_req.add_header(name, value, true);
    }
    let replay: Value = replay_req
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(
        replay["accepted"][0],
        "cx:operation:01904100-0000-7000-8000-4b147e97831e"
    );
    assert!(replay["rejected"].as_array().unwrap().is_empty());
    let after_replay: Value = TestClient::get(
        "http://server/api/v1/federation/pull-operations?space_id=cx:realm:01904100-0000-7000-8000-20d6cfd24be6",
    )
    .send(&app_from_state(state.clone()))
    .await
    .take_json()
    .await
    .unwrap();
    assert_eq!(
        after_replay["operations"].as_array().unwrap().len(),
        1,
        "idempotent replay must not duplicate the stored operation"
    );

    let invalid_operation = Operation::create(
        OperationId::new("cx:operation:01904100-0000-7000-8000-1cac81a395b6").unwrap(),
        RealmId::new("cx:realm:01904100-0000-7000-8000-20d6cfd24be6").unwrap(),
        kinds::CX_MESSAGE_CREATE,
        serde_json::json!({
            "event_id": "cx:event:01904100-0000-7000-8000-97aea7e40a20",
            "sender": "did:web:remote.example",
            "encrypted": true,
            "content": {"ciphertext": "missing-envelope-fields"}
        }),
    );
    let invalid_body = serde_json::json!({
        "origin": "did:web:remote.example",
        "destination": "did:web:soland.local",
        "space_id": "cx:realm:01904100-0000-7000-8000-20d6cfd24be6",
        "service_binding_ref": "did:web:remote.example#soland",
        "operations": [invalid_operation]
    });
    let mut invalid_req = TestClient::post(push_url).json(&invalid_body);
    for (name, value) in signed_federation_push_headers(
        "did:web:remote.example",
        "did:web:soland.local",
        push_url,
        &invalid_body,
    ) {
        invalid_req = invalid_req.add_header(name, value, true);
    }
    let invalid_push: Value = invalid_req
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert!(invalid_push["accepted"].as_array().unwrap().is_empty());
    assert_eq!(invalid_push["rejected"][0]["reason"], "invalid_semantics");

    let redaction = Operation::create(
        OperationId::new("cx:operation:01904100-0000-7000-8000-fd0b34f35181").unwrap(),
        RealmId::new("cx:realm:01904100-0000-7000-8000-20d6cfd24be6").unwrap(),
        kinds::CX_MESSAGE_REDACT,
        serde_json::json!({
            "event_id": "cx:event:01904100-0000-7000-8000-9494a7271728",
            "target_event_id": "cx:event:01904100-0000-7000-8000-19d11d370b0e"
        }),
    );
    let redaction_body = serde_json::json!({
        "origin": "did:web:remote.example",
        "destination": "did:web:soland.local",
        "space_id": "cx:realm:01904100-0000-7000-8000-20d6cfd24be6",
        "service_binding_ref": "did:web:remote.example#soland",
        "operations": [redaction]
    });
    let mut redaction_req = TestClient::post(push_url).json(&redaction_body);
    for (name, value) in signed_federation_push_headers(
        "did:web:remote.example",
        "did:web:soland.local",
        push_url,
        &redaction_body,
    ) {
        redaction_req = redaction_req.add_header(name, value, true);
    }
    let redaction_push: Value = redaction_req
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(
        redaction_push["accepted"][0],
        "cx:operation:01904100-0000-7000-8000-fd0b34f35181"
    );

    let redacted_pull: Value = TestClient::get(
        "http://server/api/v1/federation/pull-operations?space_id=cx:realm:01904100-0000-7000-8000-20d6cfd24be6",
    )
    .send(&app_from_state(state.clone()))
    .await
    .take_json()
    .await
    .unwrap();
    assert!(redacted_pull["operations"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn federation_push_rejects_bad_rfc9421_and_missing_relay_inner_signature() {
    let state = AppState::new(test_config(), Db { pool: None });
    let push_url = "http://server/api/v1/federation/push-operations";
    let operation = Operation::create(
        OperationId::new("cx:operation:01904100-0000-7000-8000-7e173b950001").unwrap(),
        RealmId::new("cx:realm:01904100-0000-7000-8000-7e173b950002").unwrap(),
        kinds::CX_MESSAGE_CREATE,
        serde_json::json!({
            "event_id": "cx:event:01904100-0000-7000-8000-7e173b950003",
            "sender": "did:web:remote.example",
            "thread_id": "cx:flow:federation-bad-signature",
            "body": "bad signature should not land"
        }),
    );
    let body = serde_json::json!({
        "origin": "did:web:remote.example",
        "destination": "did:web:soland.local",
        "space_id": "cx:realm:01904100-0000-7000-8000-7e173b950002",
        "service_binding_ref": "did:web:remote.example#soland",
        "operations": [operation]
    });

    let mut tampered_req = TestClient::post(push_url).json(&body);
    for (name, value) in signed_federation_push_headers(
        "did:web:remote.example",
        "did:web:soland.local",
        push_url,
        &body,
    ) {
        let value = if name == "signature" {
            format!("sig1=:{}:", STANDARD.encode([0_u8; 64]))
        } else {
            value
        };
        tampered_req = tampered_req.add_header(name, value, true);
    }
    let mut tampered = tampered_req.send(&app_from_state(state.clone())).await;
    assert_eq!(tampered.status_code.unwrap().as_u16(), 401);
    let tampered_body = tampered.take_string().await.unwrap();
    assert!(tampered_body.contains("key_rotation_hint=refresh_origin_service_did"));

    let mut relay_req = TestClient::post(push_url).json(&body);
    for (name, value) in signed_federation_push_headers(
        "did:web:relay.example",
        "did:web:soland.local",
        push_url,
        &body,
    ) {
        relay_req = relay_req.add_header(name, value, true);
    }
    let mut relay = relay_req.send(&app_from_state(state)).await;
    assert_eq!(relay.status_code.unwrap().as_u16(), 401);
    let relay_body = relay.take_string().await.unwrap();
    assert!(relay_body.contains("relay-inner-signature-input"));
}

#[tokio::test]
async fn federation_transactions_are_idempotent_by_origin_and_body() {
    let state = AppState::new(test_config(), Db { pool: None });
    let operation = Operation::create(
        OperationId::new("cx:operation:01904100-0000-7000-8000-91a2f2e7a3b4").unwrap(),
        RealmId::new("cx:realm:01904100-0000-7000-8000-788d17d38a52").unwrap(),
        kinds::CX_MESSAGE_CREATE,
        serde_json::json!({
            "event_id": "cx:event:01904100-0000-7000-8000-f10d061a12a7",
            "sender": "did:web:remote.example",
            "thread_id": "cx:flow:federation-txn",
            "body": "transaction body"
        }),
    );

    let transaction_body = serde_json::json!({
        "origin": "did:web:remote.example",
        "destination": "did:web:soland.local",
        "service_binding_ref": "did:web:remote.example#soland",
        "operations": [operation]
    });
    let first: Value = TestClient::put("http://server/api/v1/federation/transactions/txn-idem")
        .json(&transaction_body)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(
        first["accepted"][0],
        "cx:operation:01904100-0000-7000-8000-91a2f2e7a3b4"
    );

    let duplicate: Value = TestClient::put("http://server/api/v1/federation/transactions/txn-idem")
        .json(&transaction_body)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(
        duplicate["accepted"][0],
        "cx:operation:01904100-0000-7000-8000-91a2f2e7a3b4"
    );
    assert!(duplicate["rejected"].as_array().unwrap().is_empty());

    let conflict = TestClient::put("http://server/api/v1/federation/transactions/txn-idem")
        .json(&serde_json::json!({
            "origin": "did:web:remote.example",
            "destination": "did:web:soland.local",
            "service_binding_ref": "did:web:remote.example#soland",
            "operations": [],
            "receipts": [{"changed": true}]
        }))
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(conflict.status_code.unwrap().as_u16(), 409);

    let wrong_destination =
        TestClient::put("http://server/api/v1/federation/transactions/txn-wrong-destination")
            .json(&serde_json::json!({
                "origin": "did:web:remote.example",
                "destination": "did:web:other.example",
                "service_binding_ref": "did:web:remote.example#soland",
                "operations": []
            }))
            .send(&app_from_state(state.clone()))
            .await;
    assert_eq!(wrong_destination.status_code.unwrap().as_u16(), 403);
}
