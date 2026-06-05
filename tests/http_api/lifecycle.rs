//! Integration tests — `lifecycle` domain.
//!
//! Helpers live in [`super::common`]; pull them in via `use`.

#![allow(unused_imports)]
use super::common::*;

#[tokio::test]
async fn space_container_lifecycle_state_machine_returns_412_for_illegal_transitions() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;
    let container_space_id = "ck:space:01904100-0000-7000-8000-c10dc0000001";

    // 1) ck.space.create — Active.
    let create_event = signed_space_event(
        "ck:event:01904100-0000-7000-8000-d10dc0000001",
        1,
        "ck.space.create",
        serde_json::json!({
            "object": {
                "id": container_space_id,
                "realm_id": "ck:realm:0196419b-0000-7000-8000-000000000000",
                "kind": "list",
                "title": "Roadmap",
                "created_by": "did:web:alice.example",
            }
        }),
        Vec::new(),
    );
    let create_response: Value = TestClient::post("http://server/_cokret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&create_event)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(create_response["status"], "accepted");

    // 2) ck.space.restore on Active → 412 space_not_archived.
    let bad_restore = signed_space_event(
        "ck:event:01904100-0000-7000-8000-d10dc0000002",
        2,
        "ck.space.restore",
        serde_json::json!({ "space_id": container_space_id }),
        vec!["ck:event:01904100-0000-7000-8000-d10dc0000001"],
    );
    let mut bad_restore_response = TestClient::post("http://server/_cokret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&bad_restore)
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(
        bad_restore_response.status_code.unwrap().as_u16(),
        412,
        "restore on Active must yield HTTP 412 failed_precondition"
    );
    let body: Value = bad_restore_response.take_json().await.unwrap();
    assert_eq!(body["error"]["code"], "space_not_archived");

    // 3) ck.space.archive — legal (Active → Archived).
    let archive_event = signed_space_event(
        "ck:event:01904100-0000-7000-8000-d10dc0000003",
        3,
        "ck.space.archive",
        serde_json::json!({ "space_id": container_space_id }),
        vec!["ck:event:01904100-0000-7000-8000-d10dc0000001"],
    );
    let archive_response: Value = TestClient::post("http://server/_cokret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&archive_event)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(archive_response["status"], "accepted");

    // 4) ck.space.restore — legal now (Archived → Active).
    let good_restore = signed_space_event(
        "ck:event:01904100-0000-7000-8000-d10dc0000004",
        4,
        "ck.space.restore",
        serde_json::json!({ "space_id": container_space_id }),
        vec!["ck:event:01904100-0000-7000-8000-d10dc0000003"],
    );
    let restore_response: Value = TestClient::post("http://server/_cokret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&good_restore)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(restore_response["status"], "accepted");

    // 5) ck.space.tombstone — legal (Active → Tombstoned).
    let tombstone_event = signed_space_event(
        "ck:event:01904100-0000-7000-8000-d10dc0000005",
        5,
        "ck.space.tombstone",
        serde_json::json!({ "space_id": container_space_id }),
        vec!["ck:event:01904100-0000-7000-8000-d10dc0000004"],
    );
    let tombstone_response: Value = TestClient::post("http://server/_cokret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&tombstone_event)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(tombstone_response["status"], "accepted");

    // 6) ck.space.tombstone again on Tombstoned → 412 space_already_terminal.
    let bad_tombstone = signed_space_event(
        "ck:event:01904100-0000-7000-8000-d10dc0000006",
        6,
        "ck.space.tombstone",
        serde_json::json!({ "space_id": container_space_id }),
        vec!["ck:event:01904100-0000-7000-8000-d10dc0000005"],
    );
    let mut bad_tombstone_response = TestClient::post("http://server/_cokret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&bad_tombstone)
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(
        bad_tombstone_response.status_code.unwrap().as_u16(),
        412,
        "tombstone-again on Tombstoned must yield HTTP 412 failed_precondition"
    );
    let body: Value = bad_tombstone_response.take_json().await.unwrap();
    assert_eq!(body["error"]["code"], "space_already_terminal");

    // 7) ck.space.restore on Tombstoned → 412 space_not_archived (terminal
    // state cannot be revived even though tombstone-vs-restore are different
    // transitions).
    let bad_restore_terminal = signed_space_event(
        "ck:event:01904100-0000-7000-8000-d10dc0000007",
        7,
        "ck.space.restore",
        serde_json::json!({ "space_id": container_space_id }),
        vec!["ck:event:01904100-0000-7000-8000-d10dc0000005"],
    );
    let mut bad_restore_terminal_response = TestClient::post("http://server/_cokret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&bad_restore_terminal)
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(
        bad_restore_terminal_response.status_code.unwrap().as_u16(),
        412
    );
    let body: Value = bad_restore_terminal_response.take_json().await.unwrap();
    assert_eq!(body["error"]["code"], "space_not_archived");
}

#[tokio::test]
async fn flow_morph_lifecycle_state_machine_returns_412_for_illegal_transitions() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;
    let flow_id = "ck:flow:01904100-0000-7000-8000-e10dc0000001";
    let morph_id = "ck:morph:01904100-0000-7000-8000-e20dc0000001";

    // ── Flow path ────────────────────────────────────────────────────

    // 1) flow create — Active.
    let create_flow = signed_flow_event(
        "ck:event:01904100-0000-7000-8000-e10ec0000001",
        1,
        "ck.flow.create",
        serde_json::json!({
            "object": {
                "id": flow_id,
                "realm_id": DEMO_REALM_ID,
                "metadata": { "title": "Launch flow" },
                "created_by": "did:web:alice.example",
            }
        }),
        Vec::new(),
    );
    let response: Value = TestClient::post("http://server/_cokret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&create_flow)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(response["status"], "accepted");

    // 2) flow restore on Active → 412 flow_not_archived.
    let bad_restore = signed_flow_event(
        "ck:event:01904100-0000-7000-8000-e10ec0000002",
        2,
        "ck.flow.restore",
        serde_json::json!({ "flow_id": flow_id }),
        vec!["ck:event:01904100-0000-7000-8000-e10ec0000001"],
    );
    let mut resp = TestClient::post("http://server/_cokret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&bad_restore)
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(resp.status_code.unwrap().as_u16(), 412);
    let body: Value = resp.take_json().await.unwrap();
    assert_eq!(body["error"]["code"], "flow_not_archived");

    // 3) flow archive — legal.
    let archive = signed_flow_event(
        "ck:event:01904100-0000-7000-8000-e10ec0000003",
        3,
        "ck.flow.archive",
        serde_json::json!({ "flow_id": flow_id }),
        vec!["ck:event:01904100-0000-7000-8000-e10ec0000001"],
    );
    let resp: Value = TestClient::post("http://server/_cokret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&archive)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(resp["status"], "accepted", "redact flow response: {resp}");

    // 4) flow archive again on Archived → 412 flow_not_active.
    let bad_archive = signed_flow_event(
        "ck:event:01904100-0000-7000-8000-e10ec0000004",
        4,
        "ck.flow.archive",
        serde_json::json!({ "flow_id": flow_id }),
        vec!["ck:event:01904100-0000-7000-8000-e10ec0000003"],
    );
    let mut resp = TestClient::post("http://server/_cokret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&bad_archive)
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(resp.status_code.unwrap().as_u16(), 412);
    let body: Value = resp.take_json().await.unwrap();
    assert_eq!(body["error"]["code"], "flow_not_active");

    // 5) flow update on Archived → 412 flow_not_active.
    let bad_update = signed_flow_event(
        "ck:event:01904100-0000-7000-8000-e10ec0000005",
        5,
        "ck.flow.update",
        serde_json::json!({
            "target_ref": flow_id,
            "flow_id": flow_id,
            "patch": { "metadata": { "title": "Edit while archived" } }
        }),
        vec!["ck:event:01904100-0000-7000-8000-e10ec0000003"],
    );
    let mut resp = TestClient::post("http://server/_cokret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&bad_update)
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(resp.status_code.unwrap().as_u16(), 412);
    let body: Value = resp.take_json().await.unwrap();
    assert_eq!(body["error"]["code"], "flow_not_active");

    // 6) flow restore — legal now.
    let good_restore = signed_flow_event(
        "ck:event:01904100-0000-7000-8000-e10ec0000006",
        6,
        "ck.flow.restore",
        serde_json::json!({ "flow_id": flow_id }),
        vec!["ck:event:01904100-0000-7000-8000-e10ec0000003"],
    );
    let resp: Value = TestClient::post("http://server/_cokret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&good_restore)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(resp["status"], "accepted", "redact flow response: {resp}");

    // ── Morph path ───────────────────────────────────────────────────

    let create_morph = signed_morph_event(
        "ck:event:01904100-0000-7000-8000-e20ec0000001",
        7,
        "ck.morph.create",
        serde_json::json!({
            "object": {
                "id": morph_id,
                "realm_id": DEMO_REALM_ID,
                "morph_type": "task",
                "metadata": { "title": "Backfill" },
                "created_by": "did:web:alice.example",
            }
        }),
        Vec::new(),
    );
    let resp: Value = TestClient::post("http://server/_cokret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&create_morph)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(resp["status"], "accepted", "create morph response: {resp}");

    // morph restore on Active → 412 morph_not_archived.
    let bad_morph_restore = signed_morph_event(
        "ck:event:01904100-0000-7000-8000-e20ec0000002",
        8,
        "ck.morph.restore",
        serde_json::json!({ "morph_id": morph_id }),
        vec!["ck:event:01904100-0000-7000-8000-e20ec0000001"],
    );
    let mut resp = TestClient::post("http://server/_cokret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&bad_morph_restore)
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(resp.status_code.unwrap().as_u16(), 412);
    let body: Value = resp.take_json().await.unwrap();
    assert_eq!(body["error"]["code"], "morph_not_archived");

    // morph archive — legal.
    let morph_archive = signed_morph_event(
        "ck:event:01904100-0000-7000-8000-e20ec0000003",
        9,
        "ck.morph.archive",
        serde_json::json!({ "morph_id": morph_id }),
        vec!["ck:event:01904100-0000-7000-8000-e20ec0000001"],
    );
    let resp: Value = TestClient::post("http://server/_cokret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&morph_archive)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(resp["status"], "accepted");

    // morph update on Archived → 412 morph_not_active.
    let bad_morph_update = signed_morph_event(
        "ck:event:01904100-0000-7000-8000-e20ec0000004",
        10,
        "ck.morph.update",
        serde_json::json!({
            "target_ref": morph_id,
            "morph_id": morph_id,
            "patch": { "metadata": { "title": "Renamed" } }
        }),
        vec!["ck:event:01904100-0000-7000-8000-e20ec0000003"],
    );
    let mut resp = TestClient::post("http://server/_cokret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&bad_morph_update)
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(resp.status_code.unwrap().as_u16(), 412);
    let body: Value = resp.take_json().await.unwrap();
    assert_eq!(body["error"]["code"], "morph_not_active");
}

#[tokio::test]
async fn encrypted_realm_rejects_plaintext_flow_content_before_event_log_persist() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;
    let now = chrono::Utc::now();
    state
        .persistence
        .realm_meta()
        .put(
            DEMO_REALM_ID,
            &RealmMetaRecord {
                owner: "did:web:alice.example".to_owned(),
                deleted: false,
                discoverability: "invite_only".to_owned(),
                history_visibility: "joined".to_owned(),
                history_sharing_policy: None,
                history_sharing_policy_digest: None,
                preview_policy: None,
                preview_policy_digest: None,
                encryption_profile: Some("mls_rfc9420".to_owned()),
                plaintext_visible_services: std::collections::BTreeSet::new(),
                minimal_metadata_realm: false,
                created_at: now,
                updated_at: now,
            },
        )
        .await
        .unwrap();

    let flow_id = "ck:flow:01904100-0000-7000-8000-e30dc0000001";
    let create_flow = signed_flow_event(
        "ck:event:01904100-0000-7000-8000-e30ec0000001",
        1,
        "ck.flow.create",
        serde_json::json!({
            "object": {
                "id": flow_id,
                "realm_id": DEMO_REALM_ID,
                "metadata": { "title": "Encrypted realm metadata title" },
                "created_by": "did:web:alice.example",
            }
        }),
        Vec::new(),
    );
    let response: Value = TestClient::post("http://server/_cokret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&create_flow)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(response["status"], "accepted");

    let plaintext_body_update = signed_flow_event(
        "ck:event:01904100-0000-7000-8000-e30ec0000002",
        2,
        "ck.flow.update",
        serde_json::json!({
            "target_ref": flow_id,
            "flow_id": flow_id,
            "patch": {
                "content": {
                    "$op": "set",
                    "value": "private body must be encrypted"
                }
            }
        }),
        vec!["ck:event:01904100-0000-7000-8000-e30ec0000001"],
    );
    let mut response = TestClient::post("http://server/_cokret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&plaintext_body_update)
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(response.status_code.unwrap().as_u16(), 412);
    let body: Value = response.take_json().await.unwrap();
    assert_eq!(body["error"]["code"], "content_encryption_floor_violation");
    assert!(
        state
            .persistence
            .events()
            .get("ck:event:01904100-0000-7000-8000-e30ec0000002")
            .await
            .unwrap()
            .is_none(),
        "rejected plaintext content event must not be persisted"
    );
}

#[tokio::test]
async fn flow_update_status_fsm_rejects_skipped_terminal_transitions() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;
    let task_flow_id = "ck:flow:01904100-0000-7000-8000-f51dc0000001";
    let incident_flow_id = "ck:flow:01904100-0000-7000-8000-f51dc0000002";

    let create_task = signed_flow_event(
        "ck:event:01904100-0000-7000-8000-f51ec0000001",
        1,
        "ck.flow.create",
        serde_json::json!({
            "object": {
                "id": task_flow_id,
                "realm_id": DEMO_REALM_ID,
                "metadata": { "title": "Implement login", "fields": { "status": "todo" } },
                "created_by": "did:web:alice.example",
            }
        }),
        Vec::new(),
    );
    let resp: Value = TestClient::post("http://server/_cokret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&create_task)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(resp["status"], "accepted");

    let bad_done = signed_flow_event(
        "ck:event:01904100-0000-7000-8000-f51ec0000002",
        2,
        "ck.flow.update",
        serde_json::json!({
            "target_ref": task_flow_id,
            "flow_id": task_flow_id,
            "patch": { "metadata": { "fields": { "status": "done" } } }
        }),
        vec!["ck:event:01904100-0000-7000-8000-f51ec0000001"],
    );
    let mut resp = TestClient::post("http://server/_cokret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&bad_done)
        .send(&app_from_state(state.clone()))
        .await;
    let body: Value = resp.take_json().await.unwrap();
    assert_eq!(resp.status_code.unwrap().as_u16(), 412, "{body}");
    assert_eq!(body["error"]["code"], "flow_status_transition_invalid");

    let good_in_progress = signed_flow_event(
        "ck:event:01904100-0000-7000-8000-f51ec0000003",
        3,
        "ck.flow.update",
        serde_json::json!({
            "target_ref": task_flow_id,
            "flow_id": task_flow_id,
            "patch": { "metadata": { "fields": { "status": "in_progress" } } }
        }),
        vec!["ck:event:01904100-0000-7000-8000-f51ec0000001"],
    );
    let resp: Value = TestClient::post("http://server/_cokret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&good_in_progress)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(resp["status"], "accepted");

    let good_done = signed_flow_event(
        "ck:event:01904100-0000-7000-8000-f51ec0000004",
        4,
        "ck.flow.update",
        serde_json::json!({
            "target_ref": task_flow_id,
            "flow_id": task_flow_id,
            "patch": { "metadata": { "fields": { "status": "done" } } }
        }),
        vec!["ck:event:01904100-0000-7000-8000-f51ec0000003"],
    );
    let resp: Value = TestClient::post("http://server/_cokret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&good_done)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(resp["status"], "accepted");

    let create_incident = signed_flow_event(
        "ck:event:01904100-0000-7000-8000-f51ec0000005",
        5,
        "ck.flow.create",
        serde_json::json!({
            "object": {
                "id": incident_flow_id,
                "realm_id": DEMO_REALM_ID,
                "metadata": { "title": "SEV-2 checkout outage", "fields": { "status": "investigating" } },
                "created_by": "did:web:alice.example",
            }
        }),
        vec!["ck:event:01904100-0000-7000-8000-f51ec0000004"],
    );
    let resp: Value = TestClient::post("http://server/_cokret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&create_incident)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(resp["status"], "accepted");

    let bad_resolved = signed_flow_event(
        "ck:event:01904100-0000-7000-8000-f51ec0000006",
        6,
        "ck.flow.update",
        serde_json::json!({
            "target_ref": incident_flow_id,
            "flow_id": incident_flow_id,
            "patch": { "metadata": { "fields": { "status": "resolved" } } }
        }),
        vec!["ck:event:01904100-0000-7000-8000-f51ec0000005"],
    );
    let mut resp = TestClient::post("http://server/_cokret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&bad_resolved)
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(resp.status_code.unwrap().as_u16(), 412);
    let body: Value = resp.take_json().await.unwrap();
    assert_eq!(body["error"]["code"], "flow_status_transition_invalid");

    let audit_events: Value = TestClient::get(
        "http://server/_soland/admin/audit/events?actor=did:web:alice.example&limit=50",
    )
    .add_header("authorization", format!("Bearer {token}"), true)
    .send(&app_from_state(state.clone()))
    .await
    .take_json()
    .await
    .unwrap();
    let status_transitions: Vec<&Value> = audit_events["events"]
        .as_array()
        .expect("audit events array")
        .iter()
        .filter(|event| event["action"] == "incident.status.transition")
        .collect();
    assert_eq!(
        status_transitions.len(),
        2,
        "only accepted status transitions should be audited"
    );
    let first_transition = &status_transitions[0]["payload"];
    assert_eq!(status_transitions[0]["actor"], "did:web:alice.example");
    assert_eq!(status_transitions[0]["outcome"], "accepted");
    assert_eq!(first_transition["kind"], "incident.status.transition");
    assert_eq!(first_transition["actor"], "did:web:alice.example");
    assert_eq!(first_transition["flow_id"], task_flow_id);
    assert_eq!(first_transition["incident_id"], task_flow_id);
    assert_eq!(first_transition["realm_id"], DEMO_REALM_ID);
    assert_eq!(first_transition["from"], "todo");
    assert_eq!(first_transition["to"], "in_progress");
    assert_eq!(first_transition["timestamp"], "2026-05-17T00:00:00+00:00");

    let second_transition = &status_transitions[1]["payload"];
    assert_eq!(second_transition["actor"], "did:web:alice.example");
    assert_eq!(second_transition["flow_id"], task_flow_id);
    assert_eq!(second_transition["incident_id"], task_flow_id);
    assert_eq!(second_transition["realm_id"], DEMO_REALM_ID);
    assert_eq!(second_transition["from"], "in_progress");
    assert_eq!(second_transition["to"], "done");
    assert_eq!(second_transition["timestamp"], "2026-05-17T00:00:00+00:00");
}

#[tokio::test]
async fn redaction_targeting_flow_morph_flips_to_redacted_and_rejects_terminal_repeat() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;
    let flow_id = "ck:flow:01904100-0000-7000-8000-f10dc0000001";
    let morph_id = "ck:morph:01904100-0000-7000-8000-f20dc0000001";

    // ── Flow path ────────────────────────────────────────────────────

    let create_flow = signed_flow_event(
        "ck:event:01904100-0000-7000-8000-f10ec0000001",
        1,
        "ck.flow.create",
        serde_json::json!({
            "object": {
                "id": flow_id,
                "realm_id": DEMO_REALM_ID,
                "metadata": { "title": "Sensitive flow" },
                "created_by": "did:web:alice.example",
            }
        }),
        Vec::new(),
    );
    let resp: Value = TestClient::post("http://server/_cokret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&create_flow)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(resp["status"], "accepted");

    // First redaction — legal (Active source).
    let redact1 = signed_redaction_event(
        "ck:event:01904100-0000-7000-8000-f10ec0000002",
        2,
        serde_json::json!({
            "target_event_id": "ck:event:01904100-0000-7000-8000-f10ec0000001",
            "object_ref": flow_id,
            "by": "did:web:alice.example",
            "reason": "policy",
        }),
        vec!["ck:event:01904100-0000-7000-8000-f10ec0000001"],
    );
    let resp: Value = TestClient::post("http://server/_cokret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&redact1)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(resp["status"], "accepted", "redact flow response: {resp}");

    // Confirm projection flipped to Redacted.
    {
        let proj = state.projection.lock().unwrap();
        let flow = proj.flows.get(flow_id).expect("flow projection");
        assert_eq!(
            flow.state.as_str(),
            "redacted",
            "Flow MUST be in Redacted terminal state after ck.redaction with object_ref"
        );
    }

    // Second redaction against terminal Flow → 412 flow_already_terminal.
    let redact2 = signed_redaction_event(
        "ck:event:01904100-0000-7000-8000-f10ec0000003",
        3,
        serde_json::json!({
            "target_event_id": "ck:event:01904100-0000-7000-8000-f10ec0000001",
            "object_ref": flow_id,
        }),
        vec!["ck:event:01904100-0000-7000-8000-f10ec0000002"],
    );
    let mut resp = TestClient::post("http://server/_cokret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&redact2)
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(resp.status_code.unwrap().as_u16(), 412);
    let body: Value = resp.take_json().await.unwrap();
    assert_eq!(body["error"]["code"], "flow_already_terminal");

    // ── Morph path ───────────────────────────────────────────────────

    let create_morph = signed_morph_event(
        "ck:event:01904100-0000-7000-8000-f20ec0000001",
        4,
        "ck.morph.create",
        serde_json::json!({
            "object": {
                "id": morph_id,
                "realm_id": DEMO_REALM_ID,
                "morph_type": "task",
                "metadata": { "title": "Sensitive task" },
                "created_by": "did:web:alice.example",
            }
        }),
        Vec::new(),
    );
    let resp: Value = TestClient::post("http://server/_cokret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&create_morph)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(resp["status"], "accepted");

    let morph_redact = signed_redaction_event(
        "ck:event:01904100-0000-7000-8000-f20ec0000002",
        5,
        serde_json::json!({
            "target_event_id": "ck:event:01904100-0000-7000-8000-f20ec0000001",
            "object_ref": morph_id,
        }),
        vec!["ck:event:01904100-0000-7000-8000-f20ec0000001"],
    );
    let resp: Value = TestClient::post("http://server/_cokret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&morph_redact)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(resp["status"], "accepted");
    {
        let proj = state.projection.lock().unwrap();
        let morph = proj.morphs.get(morph_id).expect("morph projection");
        assert_eq!(morph.state.as_str(), "redacted");
    }

    // Second morph redaction → 412 morph_already_terminal.
    let bad_morph_redact = signed_redaction_event(
        "ck:event:01904100-0000-7000-8000-f20ec0000003",
        6,
        serde_json::json!({
            "target_event_id": "ck:event:01904100-0000-7000-8000-f20ec0000001",
            "object_ref": morph_id,
        }),
        vec!["ck:event:01904100-0000-7000-8000-f20ec0000002"],
    );
    let mut resp = TestClient::post("http://server/_cokret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&bad_morph_redact)
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(resp.status_code.unwrap().as_u16(), 412);
    let body: Value = resp.take_json().await.unwrap();
    assert_eq!(body["error"]["code"], "morph_already_terminal");
}

#[tokio::test]
async fn flow_tracks_update_rejected_when_parent_flow_archived() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;
    let flow_id = "ck:flow:01904100-0000-7000-8000-aabbccdd0001";

    let create_flow = signed_flow_event(
        "ck:event:01904100-0000-7000-8000-aabbcc000001",
        1,
        "ck.flow.create",
        serde_json::json!({
            "object": {
                "id": flow_id,
                "realm_id": DEMO_REALM_ID,
                "metadata": { "title": "Launch flow" },
                "created_by": "did:web:alice.example",
            }
        }),
        Vec::new(),
    );
    let resp: Value = TestClient::post("http://server/_cokret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&create_flow)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(resp["status"], "accepted");

    let tracks_active = signed_flow_event(
        "ck:event:01904100-0000-7000-8000-aabbcc000002",
        2,
        "ck.flow.tracks.update",
        serde_json::json!({
            "flow_id": flow_id,
            "patch": {"tracks": {"discussion": {"profile": "discussion"}}}
        }),
        vec!["ck:event:01904100-0000-7000-8000-aabbcc000001"],
    );
    let resp: Value = TestClient::post("http://server/_cokret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&tracks_active)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(resp["status"], "accepted");

    let archive = signed_flow_event(
        "ck:event:01904100-0000-7000-8000-aabbcc000003",
        3,
        "ck.flow.archive",
        serde_json::json!({ "flow_id": flow_id }),
        vec!["ck:event:01904100-0000-7000-8000-aabbcc000002"],
    );
    let resp: Value = TestClient::post("http://server/_cokret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&archive)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(resp["status"], "accepted");

    let tracks_archived = signed_flow_event(
        "ck:event:01904100-0000-7000-8000-aabbcc000004",
        4,
        "ck.flow.tracks.update",
        serde_json::json!({
            "flow_id": flow_id,
            "patch": {"tracks": {"synthesis": {"profile": "synthesis"}}}
        }),
        vec!["ck:event:01904100-0000-7000-8000-aabbcc000003"],
    );
    let mut resp = TestClient::post("http://server/_cokret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&tracks_archived)
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(resp.status_code.unwrap().as_u16(), 412);
    let body: Value = resp.take_json().await.unwrap();
    assert_eq!(body["error"]["code"], "flow_not_active");
}
