//! Integration tests — `policy_snapshot` domain.
//!
//! Helpers live in [`super::common`]; pull them in via `use`.

#![allow(unused_imports)]
use super::common::*;

#[tokio::test]
async fn policy_check_and_validation_work() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;

    let policy: Value = TestClient::post("http://server/api/v1/policy/check")
        .json(&serde_json::json!({
            "request_id": "req1",
            "realm_id": "cx:realm:0196419b-0000-7000-8000-000000000000",
            "request_canonical_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            "action": "message.send",
            "actor": "did:web:alice.example",
            "source": {"service": "soland"}
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(policy["decision"], "allow");
    assert_eq!(policy["decision_trace"]["request_id"], "req1");
    assert_eq!(policy["decision_trace"]["actor"], "did:web:alice.example");
    assert_eq!(policy["decision_trace"]["action"], "message.send");
    assert_eq!(policy["decision_trace"]["cache"]["mode"], "in_memory");

    let unauthenticated_policy = TestClient::post("http://server/api/v1/policies")
        .json(&serde_json::json!({
            "scope": "cx:realm:0196419b-0000-7000-8000-000000000000",
            "subject_ref": "did:web:alice.example",
            "policy_type": "message.send",
            "effect": "deny"
        }))
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(
        unauthenticated_policy.status_code,
        Some(StatusCode::UNAUTHORIZED)
    );

    let policy_document: Value = TestClient::post("http://server/api/v1/policies")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({
            "scope": "cx:realm:0196419b-0000-7000-8000-000000000000",
            "subject_ref": "did:web:alice.example",
            "policy_type": "message.send",
            "effect": "deny",
            "actions": ["message.send"],
            "resource": {"kind": "realm", "realm_id": "cx:realm:0196419b-0000-7000-8000-000000000000"},
            "obligations": [{"type": "audit", "level": "high"}]
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    let policy_id = policy_document["policy_id"].as_str().unwrap().to_owned();
    assert_eq!(policy_document["payload"]["effect"], "deny");

    let policies: Value = TestClient::get("http://server/api/v1/policies")
        .add_header("authorization", format!("Bearer {token}"), true)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(policies["policies"].as_array().unwrap().len(), 1);

    let denied: Value = TestClient::post("http://server/api/v1/policy/check")
        .json(&serde_json::json!({
            "request_id": "req2",
            "realm_id": "cx:realm:0196419b-0000-7000-8000-000000000000",
            "request_canonical_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            "action": "message.send",
            "actor": "did:web:alice.example",
            "source": {"service": "soland", "kind": "realm"}
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(denied["decision"], "deny");
    assert_eq!(denied["reason_code"], "policy_denied");
    assert_eq!(denied["policy_id"], policy_id);
    assert_eq!(denied["obligations"][0]["type"], "audit");
    assert_eq!(denied["decision_trace"]["request_id"], "req2");
    assert_eq!(denied["decision_trace"]["matched_policy"], policy_id);
    assert_eq!(denied["decision_trace"]["obligations"][0]["level"], "high");
    assert!(denied["decision_trace"]["missing_proofs"].is_array());

    let deleted: Value = TestClient::delete(format!("http://server/api/v1/policies/{policy_id}"))
        .add_header("authorization", format!("Bearer {token}"), true)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(deleted["ok"], true);

    let allowed_again: Value = TestClient::post("http://server/api/v1/policy/check")
        .json(&serde_json::json!({
            "request_id": "req3",
            "realm_id": "cx:realm:0196419b-0000-7000-8000-000000000000",
            "request_canonical_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            "action": "message.send",
            "actor": "did:web:alice.example",
            "source": {"service": "soland"}
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(allowed_again["decision"], "allow");

    let invalid = TestClient::post("http://server/api/v1/auth/dev-login")
        .json(&serde_json::json!({
            "actor": "alice",
            "device_id": "bad-device"
        }))
        .send(&app())
        .await;
    assert_eq!(invalid.status_code.unwrap().as_u16(), 400);
}

#[tokio::test]
async fn snapshot_v2_audit_path_verifies_against_merkle_root() {
    // B4: end-to-end snapshot v2 wire shape check. The single-chunk
    // case is exercised inline in `account_contacts_and_space_lifecycle_workflow`
    // — this test focuses on the SDK round-trip: head publishes a
    // generator-proof + merkle_root; chunk returns a chunk-bytes +
    // audit_path; `SnapshotMerkleTree::verify(root, leaf, idx, path, n)`
    // accepts the result. For a single-chunk snapshot the audit path is
    // empty and the leaf digest IS the root, so verify reduces to
    // `leaf == root` — but the wire-shape contract is what matters here.
    let state = AppState::new(test_config(), Db { pool: None });
    let space = seed_test_realm(
        &state,
        "did:web:alice.example",
        "snapshot-v2-test",
        Some("B4 snapshot v2 wire-shape test"),
        "public",
        &[],
        &[],
    );
    let space_id = space["space_id"].as_str().unwrap().to_owned();

    let head: Value = TestClient::get(format!(
        "http://server/api/v1/snapshot/head?realm_id={space_id}"
    ))
    .send(&app_from_state(state.clone()))
    .await
    .take_json()
    .await
    .unwrap();

    // Wire shape — v2 fields all present.
    assert!(head["merkle_root"].is_string());
    assert!(head["chunk_count"].is_number());
    assert!(head["chunk_bytes"].is_number());
    assert!(head["total_bytes"].is_number());
    let proof = &head["generator_proof"];
    assert_eq!(
        proof["realm_id"].as_str().unwrap(),
        space_id,
        "generator_proof binds the snapshot to its Realm"
    );
    assert_eq!(
        proof["merkle_root"].as_str().unwrap(),
        head["merkle_root"].as_str().unwrap()
    );
    assert!(
        !proof["signature"]["jws"].as_str().unwrap().is_empty(),
        "generator_proof.signature.jws is populated"
    );

    // Walk every chunk: pull the chunk, verify the audit path round-trips
    // through `SnapshotMerkleTree::verify`.
    let chunk_count = head["chunk_count"].as_u64().unwrap();
    let tree_size = chunk_count as usize;
    let snapshot_ref = head["snapshot_ref"].as_str().unwrap();
    let root = contrix_sdk::Hash::new(head["merkle_root"].as_str().unwrap().to_owned()).unwrap();
    for chunk_id in 0..chunk_count {
        let chunk: Value = TestClient::get(format!(
            "http://server/api/v1/sync/snapshot-chunk?snapshot_ref={snapshot_ref}&chunk_id={chunk_id}"
        ))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
        assert_eq!(chunk["chunk_id"], chunk_id);
        let leaf = contrix_sdk::Hash::new(chunk["digest"].as_str().unwrap().to_owned()).unwrap();
        let audit_path: Vec<contrix_sdk::Hash> = chunk["audit_path"]
            .as_array()
            .unwrap()
            .iter()
            .map(|h| contrix_sdk::Hash::new(h.as_str().unwrap().to_owned()).unwrap())
            .collect();
        assert!(
            contrix_sdk::SnapshotMerkleTree::verify(
                &root,
                &leaf,
                chunk_id as usize,
                &audit_path,
                tree_size,
            ),
            "audit_path for chunk {chunk_id} must reconstruct to merkle_root"
        );
    }

    // Out-of-range chunk_id returns 404, not a placeholder.
    let oob = TestClient::get(format!(
        "http://server/api/v1/sync/snapshot-chunk?snapshot_ref={snapshot_ref}&chunk_id={chunk_count}"
    ))
    .send(&app_from_state(state.clone()))
    .await;
    assert_eq!(oob.status_code.unwrap().as_u16(), 404);
}

#[tokio::test]
async fn snapshot_v2_multi_chunk_fixture_verifies_non_empty_audit_path() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;

    let space = seed_test_realm(
        &state,
        "did:web:alice.example",
        "snapshot-v2-multi-chunk-test",
        Some("B4 follow-up: ensure multi-chunk audit_path verifies"),
        "public",
        &[],
        &[],
    );
    let space_id = space["space_id"].as_str().unwrap().to_owned();

    // 64 messages × ~4 KB body each ≈ 256 KB serialized — should land
    // ≥ 2 chunks once the snapshot wrapper + per-message JSON overhead
    // is included. Body is a deterministic ASCII pattern so the test is
    // reproducible run-to-run.
    //
    // Snapshot's `messages` array comes from the MessageRecord store, now
    // populated by canonical `POST /api/v1/events` projection.
    let body_text: String = (0..40)
        .map(|i| {
            format!(
                "para{:02}: lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor.\n",
                i
            )
        })
        .collect();
    let messages_to_submit = 80u64;
    for seq in 1..=messages_to_submit {
        let resp = submit_message_event(
            state.clone(),
            &token,
            "did:web:alice.example",
            &space_id,
            &format!("cx:flow:multi-chunk-{:02}", seq % 4),
            serde_json::json!({"body": body_text, "msgtype": "m.text", "seq": seq}),
            false,
        )
        .await;
        assert!(
            resp["event_id"].is_string(),
            "send failed at seq {seq}: {resp:?}"
        );
    }

    let head: Value = TestClient::get(format!(
        "http://server/api/v1/snapshot/head?realm_id={space_id}"
    ))
    .send(&app_from_state(state.clone()))
    .await
    .take_json()
    .await
    .unwrap();
    let chunk_count = head["chunk_count"].as_u64().unwrap();
    let total_bytes = head["total_bytes"].as_u64().unwrap();
    assert!(
        chunk_count >= 2,
        "expected multi-chunk snapshot but got chunk_count={chunk_count} \
         (total_bytes={total_bytes}); bump message count + body size if \
         this regresses"
    );
    assert!(
        total_bytes > 256 * 1024,
        "expected total_bytes > 256 KiB to force the chunker but got {total_bytes}"
    );

    // For each chunk, audit_path MUST be non-empty (multi-chunk case)
    // AND reconstruct to merkle_root via SnapshotMerkleTree::verify.
    let snapshot_ref = head["snapshot_ref"].as_str().unwrap();
    let root = contrix_sdk::Hash::new(head["merkle_root"].as_str().unwrap().to_owned()).unwrap();
    let tree_size = chunk_count as usize;
    let mut any_non_empty_path = false;
    for chunk_id in 0..chunk_count {
        let chunk: Value = TestClient::get(format!(
            "http://server/api/v1/sync/snapshot-chunk?snapshot_ref={snapshot_ref}&chunk_id={chunk_id}"
        ))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
        let leaf = contrix_sdk::Hash::new(chunk["digest"].as_str().unwrap().to_owned()).unwrap();
        let audit_path: Vec<contrix_sdk::Hash> = chunk["audit_path"]
            .as_array()
            .unwrap()
            .iter()
            .map(|h| contrix_sdk::Hash::new(h.as_str().unwrap().to_owned()).unwrap())
            .collect();
        if !audit_path.is_empty() {
            any_non_empty_path = true;
        }
        assert!(
            contrix_sdk::SnapshotMerkleTree::verify(
                &root,
                &leaf,
                chunk_id as usize,
                &audit_path,
                tree_size,
            ),
            "audit_path for chunk {chunk_id}/{chunk_count} must reconstruct to merkle_root"
        );
    }
    assert!(
        any_non_empty_path,
        "at least one chunk MUST have a non-empty audit_path in a multi-chunk snapshot \
         (this is the codepath single-chunk fixtures don't exercise)"
    );
}
