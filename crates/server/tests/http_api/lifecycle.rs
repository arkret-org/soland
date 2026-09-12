//! Integration tests — `lifecycle` domain.
//!
//! Helpers live in [`super::common`]; pull them in via `use`.

use super::common::*;

fn online_submission(event: &Value) -> Vec<u8> {
    arkret_canonical::canonical_json_bytes(&arkret_wire::EventInitialSubmission::online(
        serde_json::from_value(event.clone()).expect("canonical lifecycle Event"),
    ))
    .expect("canonical online submission")
}

fn assert_failed_precondition(body: &Value, reason_code: &str) {
    assert_eq!(problem_code(body), "failed_precondition", "{body}");
    assert_eq!(body["reason_code"], reason_code, "{body}");
}

#[test]
fn space_container_lifecycle_state_machine_returns_409_for_illegal_transitions() {
    run_on_deep_stack(
        "space_container_lifecycle_state_machine_returns_409_for_illegal_transitions",
        space_container_lifecycle_state_machine_returns_409_for_illegal_transitions_body,
    );
}

async fn space_container_lifecycle_state_machine_returns_409_for_illegal_transitions_body() {
    let state = soland_test_support::app_state(test_config());
    let token = dev_token(state.clone()).await;
    // Every fixture ordinary Event below names the demo Realm's basis Seal in
    // `seal_ref`; that Seal and the founding unit it covers have to be accepted
    // before the first submit (`event-auth-state-resolution.md` §4.3).
    seed_demo_realm_basis(&state).await;
    // 1) ak.space.create — Active.
    let create_event = signed_space_event(
        "ak:event:AaLLS5MBK9ZVOHxvl_O9aWN7Bz2217aW6vd5yNj2oMvJ",
        1,
        "ak.space.create",
        serde_json::json!({
            "object": {
                "realm_id": demo_realm_id(),
                "kind": "list",
                "title": "Roadmap",
                "created_by": fixture_account_actor(&state, "did:web:alice.example"),
            }
        }),
        Vec::new(),
    );
    let container_space_id = authored_space_id(&create_event).to_string();
    let create_event_id = authored_event_id(&create_event).to_string();
    let create_response: Value = TestClient::post("http://server/_arkret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("content-type", "application/json", true)
        .body(online_submission(&create_event))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(
        create_response["status"], "accepted",
        "create space response: {create_response}"
    );

    // 2) ak.space.restore on Active → 409 failed_precondition / space_not_archived.
    let bad_restore = signed_space_event(
        "ak:event:AQqydUAtT4cUGYSa4edg4XtUcMVnfTmb_SZAsk-4mKUk",
        2,
        "ak.space.restore",
        serde_json::json!({ "space_id": container_space_id }),
        vec![create_event_id.as_str()],
    );
    let mut bad_restore_response = TestClient::post("http://server/_arkret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("content-type", "application/json", true)
        .body(online_submission(&bad_restore))
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(
        bad_restore_response.status_code.unwrap().as_u16(),
        409,
        "restore on Active must yield HTTP 409 failed_precondition"
    );
    let body: Value = bad_restore_response.take_json().await.unwrap();
    assert_failed_precondition(&body, "space_not_archived");

    // 3) ak.space.archive — legal (Active → Archived).
    let archive_event = signed_space_event(
        "ak:event:AakTFdudKJWfMQau5quUIGRBxMp44OqopWDjQB7nFbei",
        2,
        "ak.space.archive",
        serde_json::json!({ "space_id": container_space_id }),
        vec![create_event_id.as_str()],
    );
    let archive_event_id = authored_event_id(&archive_event).to_string();
    let archive_response: Value = TestClient::post("http://server/_arkret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("content-type", "application/json", true)
        .body(online_submission(&archive_event))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(archive_response["status"], "accepted", "{archive_response}");

    // 4) ak.space.restore — legal now (Archived → Active).
    let good_restore = signed_space_event(
        "ak:event:AbbLE6SexdBTT4Kc_bEwvCiLCCD6z0IHeT_nAgfoy86_",
        3,
        "ak.space.restore",
        serde_json::json!({ "space_id": container_space_id }),
        vec![archive_event_id.as_str()],
    );
    let restore_event_id = authored_event_id(&good_restore).to_string();
    let restore_response: Value = TestClient::post("http://server/_arkret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("content-type", "application/json", true)
        .body(online_submission(&good_restore))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(restore_response["status"], "accepted", "{restore_response}");

    // 5) ak.space.tombstone — legal (Active → Tombstoned).
    let tombstone_event = signed_space_event(
        "ak:event:AYbT2BPApw-fr0FoniIEJBMemO4EwBREcSF5fhYLwq-b",
        4,
        "ak.space.tombstone",
        serde_json::json!({ "space_id": container_space_id }),
        vec![restore_event_id.as_str()],
    );
    let tombstone_event_id = authored_event_id(&tombstone_event).to_string();
    let tombstone_response: Value = TestClient::post("http://server/_arkret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("content-type", "application/json", true)
        .body(online_submission(&tombstone_event))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(
        tombstone_response["status"], "accepted",
        "{tombstone_response}"
    );

    // 6) ak.space.tombstone again on Tombstoned → 409 failed_precondition.
    let bad_tombstone = signed_space_event(
        "ak:event:ARhZZVbQxuR1v7ah8wTKdzhxLe9tzc6DXrxV7BeAE-FI",
        5,
        "ak.space.tombstone",
        serde_json::json!({ "space_id": container_space_id }),
        vec![tombstone_event_id.as_str()],
    );
    let mut bad_tombstone_response = TestClient::post("http://server/_arkret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("content-type", "application/json", true)
        .body(online_submission(&bad_tombstone))
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(
        bad_tombstone_response.status_code.unwrap().as_u16(),
        409,
        "tombstone-again on Tombstoned must yield HTTP 409 failed_precondition"
    );
    let body: Value = bad_tombstone_response.take_json().await.unwrap();
    assert_failed_precondition(&body, "space_already_terminal");

    // 7) ak.space.restore on Tombstoned → 409 failed_precondition (terminal
    // state cannot be revived even though tombstone-vs-restore are different
    // transitions).
    let bad_restore_terminal = signed_space_event(
        "ak:event:AWI5bnKNGIfpSf3SEXUmq4MLSYfFz7xOtzQEcWAYHjdR",
        5,
        "ak.space.restore",
        serde_json::json!({ "space_id": container_space_id }),
        vec![tombstone_event_id.as_str()],
    );
    let mut bad_restore_terminal_response = TestClient::post("http://server/_arkret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("content-type", "application/json", true)
        .body(online_submission(&bad_restore_terminal))
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(
        bad_restore_terminal_response.status_code.unwrap().as_u16(),
        409
    );
    let body: Value = bad_restore_terminal_response.take_json().await.unwrap();
    assert_failed_precondition(&body, "space_not_archived");
}

#[test]
fn strand_morph_lifecycle_state_machine_returns_409_for_illegal_transitions() {
    run_on_deep_stack(
        "strand_morph_lifecycle_state_machine_returns_409_for_illegal_transitions",
        strand_morph_lifecycle_state_machine_returns_409_for_illegal_transitions_body,
    );
}

async fn strand_morph_lifecycle_state_machine_returns_409_for_illegal_transitions_body() {
    let state = soland_test_support::app_state(test_config());
    let token = dev_token(state.clone()).await;
    // Every fixture ordinary Event below names the demo Realm's basis Seal in
    // `seal_ref`; that Seal and the founding unit it covers have to be accepted
    // before the first submit (`event-auth-state-resolution.md` §4.3).
    seed_demo_realm_basis(&state).await;
    // ── Strand path ────────────────────────────────────────────────────

    // 1) strand create — Active.
    let create_strand = signed_strand_event(
        "ak:event:ATZD78F3yp8_BMkenKRQf-T0DVwuVrS0iTeBv37J4BjS",
        1,
        "ak.strand.create",
        serde_json::json!({
            "object": {
                "realm_id": demo_realm_id(),
                "metadata": { "title": "Launch strand" },
                "created_by": fixture_account_actor(&state, "did:web:alice.example"),
            }
        }),
        Vec::new(),
    );
    let strand_id = authored_strand_id(&create_strand).to_string();
    let create_strand_event_id = authored_event_id(&create_strand).to_string();
    let response: Value = TestClient::post("http://server/_arkret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("content-type", "application/json", true)
        .body(online_submission(&create_strand))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(response["status"], "accepted", "{response}");

    // 2) strand restore on Active → 409 failed_precondition.
    let bad_restore = signed_strand_event(
        "ak:event:AahY66rgDDqzUKbVoQoZ8lYUvURTufyOkN13hjUKJbG2",
        2,
        "ak.strand.restore",
        serde_json::json!({ "strand_id": strand_id }),
        vec![create_strand_event_id.as_str()],
    );
    let mut resp = TestClient::post("http://server/_arkret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("content-type", "application/json", true)
        .body(online_submission(&bad_restore))
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(resp.status_code.unwrap().as_u16(), 409);
    let body: Value = resp.take_json().await.unwrap();
    assert_failed_precondition(&body, "strand_not_archived");

    // 3) strand archive — legal.
    let archive = signed_strand_event(
        "ak:event:AZRNDKJ0_e8sAu2KTEq3-Rz5hmYnUtg-PowD_DWSYozH",
        2,
        "ak.strand.archive",
        serde_json::json!({ "strand_id": strand_id }),
        vec![create_strand_event_id.as_str()],
    );
    let archive_event_id = authored_event_id(&archive).to_string();
    let resp: Value = TestClient::post("http://server/_arkret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("content-type", "application/json", true)
        .body(online_submission(&archive))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(resp["status"], "accepted", "redact strand response: {resp}");

    // 4) strand archive again on Archived → 409 failed_precondition.
    let bad_archive = signed_strand_event(
        "ak:event:AZPkZX-ZWiKPMGSiQ9UGk4WLhLf7l8Y1StwwpxGBtTBM",
        3,
        "ak.strand.archive",
        serde_json::json!({ "strand_id": strand_id }),
        vec![archive_event_id.as_str()],
    );
    let mut resp = TestClient::post("http://server/_arkret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("content-type", "application/json", true)
        .body(online_submission(&bad_archive))
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(resp.status_code.unwrap().as_u16(), 409);
    let body: Value = resp.take_json().await.unwrap();
    assert_failed_precondition(&body, "strand_not_active");

    // 5) strand update on Archived → 409 failed_precondition.
    let bad_update = signed_strand_event(
        "ak:event:AfNCpTjcXlRqF0M6y3zXf3ADQStSnGjt15sgSI35lh25",
        3,
        "ak.strand.update",
        serde_json::json!({
            "target_ref": strand_id,
            "patch": { "metadata": { "title": "Edit while archived" } }
        }),
        vec![archive_event_id.as_str()],
    );
    let mut resp = TestClient::post("http://server/_arkret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("content-type", "application/json", true)
        .body(online_submission(&bad_update))
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(resp.status_code.unwrap().as_u16(), 409);
    let body: Value = resp.take_json().await.unwrap();
    assert_failed_precondition(&body, "strand_not_active");

    // 6) strand restore — legal now.
    let good_restore = signed_strand_event(
        "ak:event:AVsys1otipNhlhja_WdYu8lBaiDjJyJ17aSo2_7I87sa",
        3,
        "ak.strand.restore",
        serde_json::json!({ "strand_id": strand_id }),
        vec![archive_event_id.as_str()],
    );
    let restored_strand_event_id = authored_event_id(&good_restore).to_string();
    let resp: Value = TestClient::post("http://server/_arkret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("content-type", "application/json", true)
        .body(online_submission(&good_restore))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(resp["status"], "accepted", "redact strand response: {resp}");

    // ── Morph path ───────────────────────────────────────────────────

    let create_morph = signed_morph_event(
        "ak:event:AWS4D20F26_660O-iwVuHxItkfWOJJtywb7amH5EWa5P",
        4,
        "ak.morph.create",
        serde_json::json!({
            "object": {
                "realm_id": demo_realm_id(),
                "morph_kind": "task",
                "metadata": { "title": "Backfill" },
                "created_by": fixture_account_actor(&state, "did:web:alice.example"),
            }
        }),
        vec![restored_strand_event_id.as_str()],
    );
    let morph_id = authored_morph_id(&create_morph).to_string();
    let create_morph_event_id = authored_event_id(&create_morph).to_string();
    let resp: Value = TestClient::post("http://server/_arkret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("content-type", "application/json", true)
        .body(online_submission(&create_morph))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(resp["status"], "accepted", "create morph response: {resp}");

    // morph restore on Active → 409 failed_precondition.
    let bad_morph_restore = signed_morph_event(
        "ak:event:AfHKvu9n9w6tlbjGZhTXcXOhc-1CUav2YR5xi22aaMK5",
        5,
        "ak.morph.restore",
        serde_json::json!({ "target_ref": morph_id }),
        vec![create_morph_event_id.as_str()],
    );
    let mut resp = TestClient::post("http://server/_arkret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("content-type", "application/json", true)
        .body(online_submission(&bad_morph_restore))
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(resp.status_code.unwrap().as_u16(), 409);
    let body: Value = resp.take_json().await.unwrap();
    assert_failed_precondition(&body, "morph_not_archived");

    // morph archive — legal.
    let morph_archive = signed_morph_event(
        "ak:event:Ae2E94jjYEWco-GK4wyBIaT0hY9Z2qauoP0V6mzUnHA-",
        5,
        "ak.morph.archive",
        serde_json::json!({ "target_ref": morph_id }),
        vec![create_morph_event_id.as_str()],
    );
    let morph_archive_event_id = authored_event_id(&morph_archive).to_string();
    let resp: Value = TestClient::post("http://server/_arkret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("content-type", "application/json", true)
        .body(online_submission(&morph_archive))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(resp["status"], "accepted", "{resp}");

    // morph update on Archived → 409 failed_precondition.
    let bad_morph_update = signed_morph_event(
        "ak:event:Ace9y26dKliWWB5Ya_CivuvVkz5oyHfWJPmdK873UlIP",
        6,
        "ak.morph.update",
        serde_json::json!({
            "target_ref": morph_id,
            "patch": { "metadata": { "title": "Renamed" } }
        }),
        vec![morph_archive_event_id.as_str()],
    );
    let mut resp = TestClient::post("http://server/_arkret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("content-type", "application/json", true)
        .body(online_submission(&bad_morph_update))
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(resp.status_code.unwrap().as_u16(), 409);
    let body: Value = resp.take_json().await.unwrap();
    assert_failed_precondition(&body, "morph_not_active");
}

#[test]
fn encrypted_realm_rejects_plaintext_strand_content_before_event_log_persist() {
    run_on_deep_stack(
        "encrypted_realm_rejects_plaintext_strand_content_before_event_log_persist",
        encrypted_realm_rejects_plaintext_strand_content_before_event_log_persist_body,
    );
}

async fn encrypted_realm_rejects_plaintext_strand_content_before_event_log_persist_body() {
    let state = soland_test_support::app_state(test_config());
    let token = dev_token(state.clone()).await;
    // Every fixture ordinary Event below names the demo Realm's basis Seal in
    // `seal_ref`; that Seal and the founding unit it covers have to be accepted
    // before the first submit (`event-auth-state-resolution.md` §4.3).
    seed_demo_realm_basis(&state).await;
    let now = chrono::Utc::now();
    state
        .test_persistence()
        .realm_meta()
        .put(
            demo_realm_id(),
            &RealmMetaRecord {
                owner: "did:web:alice.example".to_owned(),
                deleted: false,
                discoverability: "invite_only".to_owned(),
                history_access: "since_join".to_owned(),
                preview_policy: None,
                preview_policy_digest: None,
                asset_privacy_policy: None,
                asset_privacy_policy_digest: None,
                encryption_profile: Some("mls_rfc9420".to_owned()),
                plaintext_visible_services: std::collections::BTreeSet::new(),
                plaintext_visible_service_classes: Default::default(),
                minimal_metadata_realm: false,
                created_at: now,
                updated_at: now,
            },
        )
        .await
        .unwrap();

    // Content admission is decoupled from `encryption_profile` (the MLS
    // mechanism) and gated on the effective `content_encryption_floor`. The
    // Realm raises its floor to `e2ee_required` via `ak.realm.policy_bundle`;
    // the reducer projection then rejects plaintext private Strand content.
    {
        let hlc = soland_domain::hlc::ServerHlc::new("lifecycle-test");
        let mut projection = state.test_projection().lock();
        projection.apply(
            &arkret_event_draft::test_support::raw_projected_operation(
                arkret_identifiers::OperationId::new(format!(
                    "ak:operation:{}",
                    uuid::Uuid::now_v7()
                ))
                .unwrap(),
                arkret_identifiers::RealmId::new(demo_realm_id()).unwrap(),
                arkret_wire::EventKind::RealmPolicyBundle.as_str(),
                serde_json::json!({
                    "policy_revision": 1,
                    "content_encryption_floor": "e2ee_required"
                }),
            ),
            &hlc,
        );
    }

    let create_strand = signed_strand_event(
        "ak:event:AVCdPpKuXMmkhDTnoVs7_fgmwYo67vCJayKAPIjAK_n8",
        1,
        "ak.strand.create",
        serde_json::json!({
            "object": {
                "realm_id": demo_realm_id(),
                "metadata": { "title": "Encrypted realm metadata title" },
                "created_by": fixture_account_actor(&state, "did:web:alice.example"),
            }
        }),
        Vec::new(),
    );
    let strand_id = authored_strand_id(&create_strand).to_string();
    let create_strand_event_id = authored_event_id(&create_strand).to_string();
    let response: Value = TestClient::post("http://server/_arkret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("content-type", "application/json", true)
        .body(online_submission(&create_strand))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(response["status"], "accepted", "{response}");

    let plaintext_body_update = signed_strand_event(
        "ak:event:AewChiBUHOonuK6nJ0FrjxCf0157tUGRV5B3-nNgwqxx",
        2,
        "ak.strand.update",
        serde_json::json!({
            "target_ref": strand_id,
            "patch": {
                "content": {
                    "$op": "set",
                    "value": "private body must be encrypted"
                }
            }
        }),
        vec![create_strand_event_id.as_str()],
    );
    let plaintext_update_event_id = authored_event_id(&plaintext_body_update).to_string();
    let mut response = TestClient::post("http://server/_arkret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("content-type", "application/json", true)
        .body(online_submission(&plaintext_body_update))
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(response.status_code.unwrap().as_u16(), 409);
    let body: Value = response.take_json().await.unwrap();
    assert_failed_precondition(&body, "content_encryption_floor_violation");
    assert!(
        state
            .test_persistence()
            .events()
            .get(&plaintext_update_event_id)
            .await
            .unwrap()
            .is_none(),
        "rejected plaintext content event must not be persisted"
    );
    for content in [
        serde_json::json!({"kind":"ak.content.text", "body":"private message"}),
        serde_json::json!({
            "kind":"ak.content.poll", "body":"private poll",
            "poll": {"kind":"disclosed", "max_selections":1, "answers":[
                {"id":"yes", "text":{"kind":"ak.content.text", "body":"Yes"}},
                {"id":"no", "text":{"kind":"ak.content.text", "body":"No"}}
            ]}
        }),
    ] {
        let plaintext_message = signed_strand_event(
            "ak:event:AewChiBUHOonuK6nJ0FrjxCf0157tUGRV5B3-nNgwqxx",
            2,
            "ak.message.create",
            serde_json::json!({
                "strand_id":strand_id, "track_name":"discussion", "content":content
            }),
            vec![create_strand_event_id.as_str()],
        );
        let event_id = authored_event_id(&plaintext_message).to_string();
        let mut response = TestClient::post("http://server/_arkret/self/events")
            .add_header("authorization", format!("Bearer {token}"), true)
            .add_header("content-type", "application/json", true)
            .body(online_submission(&plaintext_message))
            .send(&app_from_state(state.clone()))
            .await;
        assert_eq!(response.status_code.unwrap().as_u16(), 409);
        let body: Value = response.take_json().await.unwrap();
        assert_failed_precondition(&body, "content_encryption_floor_violation");
        assert!(
            state
                .test_persistence()
                .events()
                .get(&event_id)
                .await
                .unwrap()
                .is_none()
        );
    }
}

#[test]
fn strand_metadata_fields_status_has_no_private_transition_transition() {
    run_on_deep_stack(
        "strand_metadata_fields_status_has_no_private_transition_transition",
        strand_metadata_fields_status_has_no_private_transition_transition_body,
    );
}

/// Ruling `2026-09-04-1752`: v1 registers no Realm workflow profile, so nothing
/// legitimises a server-side `stage` transition matrix. soland used to run a private
/// `todo -> in_progress -> done` / `investigating -> mitigated -> resolved` transition over
/// `metadata.fields.status` and reject "skipped" transitions with
/// `strand_status_transition_invalid` — a reason code no registry ever declared, on a key
/// that is `hard_reject` forbidden wire (`forbidden-wire-fields.json`, replacement: the
/// top-level `stage` field). The transition, that reason code and the synthetic
/// `incident.status.transition` audit row are all deleted.
///
/// What this test pins is the deletion plus the landed forbidden-wire surface:
/// `metadata.fields.status` is rejected as `schema_violation` on shape
/// (registry-projected through `arkret_wire::forbidden_wire`), identically for
/// every value, and no private verdict or audit row appears.
async fn strand_metadata_fields_status_has_no_private_transition_transition_body() {
    let state = soland_test_support::app_state(test_config());
    let token = dev_token(state.clone()).await;
    // Every fixture ordinary Event below names the demo Realm's basis Seal in
    // `seal_ref`; that Seal and the founding unit it covers have to be accepted
    // before the first submit (`event-auth-state-resolution.md` §4.3).
    seed_demo_realm_basis(&state).await;
    let create_task = signed_strand_event(
        "ak:event:ARJp5CM3oF37j3lgzRCd3l8t_x6SRQnSAG48K1y3xzbk",
        1,
        "ak.strand.create",
        serde_json::json!({
            "object": {
                "realm_id": demo_realm_id(),
                "metadata": { "title": "Implement login", "fields": { "jira_status": "todo" } },
                "created_by": fixture_account_actor(&state, "did:web:alice.example"),
            }
        }),
        Vec::new(),
    );
    let task_strand_id = authored_strand_id(&create_task).to_string();
    let create_task_event_id = authored_event_id(&create_task).to_string();
    let resp: Value = TestClient::post("http://server/_arkret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("content-type", "application/json", true)
        .body(online_submission(&create_task))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(resp["status"], "accepted", "{resp}");

    // A domain-named key is ordinary opaque profile data and stays accepted; only the
    // bare `status` spelling is reserved. Both halves of this A/B use the same nested
    // patch shape, so the only difference under test is the field name.
    let domain_named = signed_strand_event(
        "ak:event:AamjDwNA62hX10_JO_rxjuHZCdr-NgRw5mfVW6bO3gpy",
        2,
        "ak.strand.update",
        serde_json::json!({
            "target_ref": task_strand_id,
            "patch": { "metadata": { "fields": { "jira_status": "in_progress" } } }
        }),
        vec![create_task_event_id.as_str()],
    );
    let domain_named_event_id = authored_event_id(&domain_named).to_string();
    let resp: Value = TestClient::post("http://server/_arkret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("content-type", "application/json", true)
        .body(online_submission(&domain_named))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(resp["status"], "accepted", "{resp}");

    // The reserved spelling is rejected on shape, not on transition legality. The old
    // private transition would have *accepted* `todo -> in_progress` here and only rejected a
    // "skipped" transition; now the field never reaches a reducer at all, so both a
    // legal-looking and an illegal-looking value fail identically.
    //
    // Rejected events are never persisted, so they do not advance the actor's
    // accepted sequence: every forbidden attempt below re-presents the same next
    // actor_seq chained onto `domain_named` (the sibling-fork guard counts only
    // accepted events, so the repeated sequence never trips it).
    for (event_id, next_status) in [
        (
            "ak:event:AaWPwCCNsebvhtJh4Z0HrO1s5LdTYCV7PxT2DWTyGI7A",
            "in_progress",
        ),
        (
            "ak:event:AaexLcShPPSDr6Qd8AMPKY_A6Nreb1IYA_7aJ96gaixo",
            "done",
        ),
    ] {
        let forbidden = signed_strand_event(
            event_id,
            3,
            "ak.strand.update",
            serde_json::json!({
                "target_ref": task_strand_id,
                "patch": { "metadata": { "fields": { "status": next_status } } }
            }),
            vec![domain_named_event_id.as_str()],
        );
        let forbidden_event_id = authored_event_id(&forbidden).to_string();
        let mut resp = TestClient::post("http://server/_arkret/self/events")
            .add_header("authorization", format!("Bearer {token}"), true)
            .add_header("content-type", "application/json", true)
            .body(online_submission(&forbidden))
            .send(&app_from_state(state.clone()))
            .await;
        let body: Value = resp.take_json().await.unwrap();
        assert_ne!(
            body["reason_code"], "strand_status_transition_invalid",
            "the private status transition was deleted by ruling 2026-09-04-1752: {body}"
        );
        assert_eq!(
            problem_code(&body),
            "schema_violation",
            "metadata.fields.status is forbidden wire, not a failed transition: {body}"
        );
        assert!(
            state
                .test_persistence()
                .events()
                .get(&forbidden_event_id)
                .await
                .unwrap()
                .is_none(),
            "a rejected forbidden-wire event must not be persisted"
        );
    }

    // Create payloads are held to the same registry: `metadata.fields.status`
    // in an `ak.strand.create` object is rejected before anything projects.
    let forbidden_create_id = soland_test_support::fixture_content_bound_id("ak:event:");
    let forbidden_create = signed_strand_event(
        &forbidden_create_id,
        3,
        "ak.strand.create",
        serde_json::json!({
            "object": {
                "realm_id": demo_realm_id(),
                "metadata": { "title": "Forbidden at birth", "fields": { "status": "todo" } },
                "created_by": fixture_account_actor(&state, "did:web:alice.example"),
            }
        }),
        vec![domain_named_event_id.as_str()],
    );
    let forbidden_create_event_id = authored_event_id(&forbidden_create).to_string();
    let mut resp = TestClient::post("http://server/_arkret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("content-type", "application/json", true)
        .body(online_submission(&forbidden_create))
        .send(&app_from_state(state.clone()))
        .await;
    let body: Value = resp.take_json().await.unwrap();
    assert_eq!(
        problem_code(&body),
        "schema_violation",
        "metadata.fields.status is forbidden wire at create: {body}"
    );
    assert!(
        state
            .test_persistence()
            .events()
            .get(&forbidden_create_event_id)
            .await
            .unwrap()
            .is_none(),
        "a rejected forbidden-wire create must not be persisted"
    );

    // No audit trail is synthesised for it either: the old code appended an
    // `incident.status.transition` audit row per accepted private transition.
    let audit_events: Value = TestClient::get("http://server/_soland/admin/audit/events?limit=50")
        .add_header("authorization", format!("Bearer {token}"), true)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert!(
        audit_events["events"]
            .as_array()
            .expect("audit events array")
            .iter()
            .all(|event| event["action"] != "incident.status.transition"),
        "the incident.status.transition audit action belonged to the deleted private transition"
    );
}

#[test]
fn redaction_targeting_strand_morph_flips_to_redacted_and_rejects_terminal_repeat() {
    run_on_deep_stack(
        "redaction_targeting_strand_morph_flips_to_redacted_and_rejects_terminal_repeat",
        redaction_targeting_strand_morph_flips_to_redacted_and_rejects_terminal_repeat_body,
    );
}

async fn redaction_targeting_strand_morph_flips_to_redacted_and_rejects_terminal_repeat_body() {
    let state = soland_test_support::app_state(test_config());
    let token = dev_token(state.clone()).await;
    // Every fixture ordinary Event below names the demo Realm's basis Seal in
    // `seal_ref`; that Seal and the founding unit it covers have to be accepted
    // before the first submit (`event-auth-state-resolution.md` §4.3).
    seed_demo_realm_basis(&state).await;
    // ── Strand path ────────────────────────────────────────────────────

    let create_strand = signed_strand_event(
        "ak:event:AUdcg_tWaOx2mq2N-8743W9xEP8Q35yxM87nNC95OxlN",
        1,
        "ak.strand.create",
        serde_json::json!({
            "object": {
                "realm_id": demo_realm_id(),
                "metadata": { "title": "Sensitive strand" },
                "created_by": fixture_account_actor(&state, "did:web:alice.example"),
            }
        }),
        Vec::new(),
    );
    let strand_id = authored_strand_id(&create_strand).to_string();
    let create_strand_event_id = authored_event_id(&create_strand).to_string();
    let resp: Value = TestClient::post("http://server/_arkret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("content-type", "application/json", true)
        .body(online_submission(&create_strand))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(resp["status"], "accepted", "{resp}");

    // First redaction — legal (Active source).
    let redact1 = signed_redaction_event(
        "ak:event:AelSfWbyB8v5LgV4tW6Voo4vol9OLm5vk2JL25-09qH5",
        2,
        serde_json::json!({
            "target_ref": strand_id,
            "reason": "policy",
        }),
        vec![create_strand_event_id.as_str()],
    );
    let redact1_event_id = authored_event_id(&redact1).to_string();
    let resp: Value = TestClient::post("http://server/_arkret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("content-type", "application/json", true)
        .body(online_submission(&redact1))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(resp["status"], "accepted", "redact strand response: {resp}");

    // Confirm projection flipped to Redacted.
    {
        let proj = state.test_projection().lock();
        let strand = proj.strands.get(&strand_id).expect("strand projection");
        assert_eq!(
            strand.state.as_str(),
            "redacted",
            "Strand MUST be in Redacted terminal state after ak.redaction with target_ref"
        );
    }

    // Second redaction against terminal Strand → 409 failed_precondition.
    let redact2 = signed_redaction_event(
        "ak:event:Af_iozNXHubayuuNSBTFtswzAG4pYMhCPxsig0BaqpcJ",
        3,
        serde_json::json!({
            "target_ref": strand_id,
        }),
        vec![redact1_event_id.as_str()],
    );
    let mut resp = TestClient::post("http://server/_arkret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("content-type", "application/json", true)
        .body(online_submission(&redact2))
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(resp.status_code.unwrap().as_u16(), 409);
    let body: Value = resp.take_json().await.unwrap();
    assert_failed_precondition(&body, "strand_already_terminal");

    // ── Morph path ───────────────────────────────────────────────────

    let create_morph = signed_morph_event(
        "ak:event:AVq4vwCqZOh70AyqBd46bxUJMSJrBe8BWv8V2T0cBAjW",
        3,
        "ak.morph.create",
        serde_json::json!({
            "object": {
                "realm_id": demo_realm_id(),
                "morph_kind": "task",
                "metadata": { "title": "Sensitive task" },
                "created_by": fixture_account_actor(&state, "did:web:alice.example"),
            }
        }),
        vec![redact1_event_id.as_str()],
    );
    let morph_id = authored_morph_id(&create_morph).to_string();
    let create_morph_event_id = authored_event_id(&create_morph).to_string();
    let resp: Value = TestClient::post("http://server/_arkret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("content-type", "application/json", true)
        .body(online_submission(&create_morph))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(resp["status"], "accepted", "{resp}");

    let morph_redact = signed_redaction_event(
        "ak:event:AWdTHwE9vmQuc2JFQa19-QCQN3SOZO0jtz0V_9XHBaEm",
        4,
        serde_json::json!({
            "target_ref": morph_id,
        }),
        vec![create_morph_event_id.as_str()],
    );
    let morph_redact_event_id = authored_event_id(&morph_redact).to_string();
    let resp: Value = TestClient::post("http://server/_arkret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("content-type", "application/json", true)
        .body(online_submission(&morph_redact))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(resp["status"], "accepted", "{resp}");
    {
        let proj = state.test_projection().lock();
        let morph = proj.morphs.get(&morph_id).expect("morph projection");
        assert_eq!(morph.state.as_str(), "redacted");
    }

    // Second morph redaction → 409 failed_precondition.
    let bad_morph_redact = signed_redaction_event(
        "ak:event:AVkZqRN5bQRdfamwQE6j990HnY7y06adtMhPMaxVAAyV",
        5,
        serde_json::json!({
            "target_ref": morph_id,
        }),
        vec![morph_redact_event_id.as_str()],
    );
    let mut resp = TestClient::post("http://server/_arkret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("content-type", "application/json", true)
        .body(online_submission(&bad_morph_redact))
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(resp.status_code.unwrap().as_u16(), 409);
    let body: Value = resp.take_json().await.unwrap();
    assert_failed_precondition(&body, "morph_already_terminal");
}

#[test]
fn strand_tracks_update_rejected_when_parent_strand_archived() {
    run_on_deep_stack(
        "strand_tracks_update_rejected_when_parent_strand_archived",
        strand_tracks_update_rejected_when_parent_strand_archived_body,
    );
}

async fn strand_tracks_update_rejected_when_parent_strand_archived_body() {
    let state = soland_test_support::app_state(test_config());
    let token = dev_token(state.clone()).await;
    // Every fixture ordinary Event below names the demo Realm's basis Seal in
    // `seal_ref`; that Seal and the founding unit it covers have to be accepted
    // before the first submit (`event-auth-state-resolution.md` §4.3).
    seed_demo_realm_basis(&state).await;
    let create_strand = signed_strand_event(
        "ak:event:ATpaZ1zjrxoRo57u72V4mEAxUhkLtA_hT1yZrFUmss6m",
        1,
        "ak.strand.create",
        serde_json::json!({
            "object": {
                "realm_id": demo_realm_id(),
                "metadata": { "title": "Launch strand" },
                "created_by": fixture_account_actor(&state, "did:web:alice.example"),
            }
        }),
        Vec::new(),
    );
    let strand_id = authored_strand_id(&create_strand).to_string();
    let create_strand_event_id = authored_event_id(&create_strand).to_string();
    let resp: Value = TestClient::post("http://server/_arkret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("content-type", "application/json", true)
        .body(online_submission(&create_strand))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(resp["status"], "accepted", "{resp}");

    let tracks_active = signed_strand_event(
        "ak:event:AVgyhwIJQd2GqlQhwdYb5iVK_6c73aQU6iR5ppKF5K77",
        2,
        "ak.strand.tracks.update",
        serde_json::json!({
            "target_ref": strand_id,
            "patch": {"tracks.discussion.profile": {"$op": "set", "value": "discussion"}}
        }),
        vec![create_strand_event_id.as_str()],
    );
    let tracks_active_event_id = authored_event_id(&tracks_active).to_string();
    let resp: Value = TestClient::post("http://server/_arkret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("content-type", "application/json", true)
        .body(online_submission(&tracks_active))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(resp["status"], "accepted", "tracks update response: {resp}");

    let archive = signed_strand_event(
        "ak:event:AYstzDvHBVnvumPzWgZsRG-iI46FnNF1EwpelBrSP10E",
        3,
        "ak.strand.archive",
        serde_json::json!({ "strand_id": strand_id }),
        vec![tracks_active_event_id.as_str()],
    );
    let archive_event_id = authored_event_id(&archive).to_string();
    let resp: Value = TestClient::post("http://server/_arkret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("content-type", "application/json", true)
        .body(online_submission(&archive))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(resp["status"], "accepted", "{resp}");

    let tracks_archived = signed_strand_event(
        "ak:event:AVPm8wEiPopL7E4JtCyB4z4LSZ9OZqHcjoCtMpd5QSkO",
        4,
        "ak.strand.tracks.update",
        serde_json::json!({
            "target_ref": strand_id,
            "patch": {"tracks.synthesis.profile": {"$op": "set", "value": "synthesis"}}
        }),
        vec![archive_event_id.as_str()],
    );
    let mut resp = TestClient::post("http://server/_arkret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("content-type", "application/json", true)
        .body(online_submission(&tracks_archived))
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(resp.status_code.unwrap().as_u16(), 409);
    let body: Value = resp.take_json().await.unwrap();
    assert_failed_precondition(&body, "strand_not_active");
}
