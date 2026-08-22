//! Integration tests — `ak.self.realm.join_application.read.list` pagination
//! cursor.
//!
//! api-conventions.md §7 requires the single opaque `ak:cursor:` token type on
//! every list surface; encoding.md §8 pins the canonical core body and the
//! error-code closed set. The list endpoint historically leaked the bare
//! `application_ref` as its cursor — these tests hold the canonical wire form
//! and the closed-set error mapping in place.

use soland_storage::{JoinApplicationCommand, JoinApplicationMutation};

use super::common::*;

fn join_config() -> AppConfig {
    AppConfig {
        candidate_join_policy_enabled: true,
        ..test_config()
    }
}

fn hash(fill: char) -> String {
    format!("sha256:{}", fill.to_string().repeat(64))
}

fn seeded_application(fill: char, applicant_core: &str) -> soland_storage::JoinApplicationRecord {
    serde_json::from_value(serde_json::json!({
        "application_ref": hash(fill),
        "receipt": {
            "candidate_kind": "member.application",
            "realm_id": demo_realm_id(),
            "applicant_actor_id": applicant_core,
            "knock_ref": format!("ak:event:AYqyX_pkT3hbwKscye0o3wq75G7axNkEMZADE88iy_g{fill}"),
            "policy_version_digest": hash('e'),
            "application_revision_digest": hash('f'),
            "private_body_digest": hash('d'),
            "submitted_at": "2026-08-01T00:00:00.000Z",
            "application_receipt_digest": hash(fill),
            "proof": {
                "kind": "detached_jws",
                "verification_method": "did:web:alice.example#device",
                "payload_digest": hash(fill),
                "created_at": "2026-08-01T00:00:00.000Z",
                "jws": "eyJhbGciOiJFZDI1NTE5In0..AQ"
            }
        },
        "private_body": {
            "mode": "server_protected",
            "answers": [],
            "gate_proofs": []
        },
        "status": "awaiting_review",
        "applicant_visibility": "reviewer_only",
        "expires_at": "2027-01-01T00:00:00.000Z",
        "reviews": [],
        "required_accept_refs": [],
        "invite_consumed": false,
        "audit_entries": [],
        "updated_at": "2026-08-01T00:00:00.000Z"
    }))
    .expect("seed record deserializes")
}

async fn seed_applications(state: &AppState, applicant_core: &str, fills: &[char]) {
    for fill in fills {
        let record = seeded_application(*fill, applicant_core);
        let outcome = state
            .test_persistence()
            .join_applications()
            .execute(JoinApplicationCommand {
                principal_id: applicant_core.to_owned(),
                idempotency_key: format!("seed-{fill}"),
                request_hash: format!("seed-request-{fill}"),
                idempotency_expires_at: chrono::Utc::now() + chrono::Duration::days(1),
                mutation: JoinApplicationMutation::Submit {
                    record: Box::new(record),
                    max_open_applications: 16,
                    cooldown_after_reject_seconds: 0,
                },
            })
            .await
            .expect("seed submit applies");
        assert!(matches!(
            outcome,
            soland_storage::JoinApplicationCommandOutcome::Applied { .. }
        ));
    }
}

async fn list_page(state: AppState, token: &str, query: &str) -> (Option<StatusCode>, Value) {
    let realm = demo_realm_id().replace(':', "%3A");
    let url = format!("http://server/_arkret/self/realms/{realm}/join-applications{query}");
    let mut response = TestClient::get(url)
        .add_header("authorization", format!("Bearer {token}"), true)
        .send(&app_from_state(state))
        .await;
    let status = response.status_code;
    let body: Value = response.take_json().await.unwrap();
    (status, body)
}

#[test]
fn join_application_list_paginates_with_opaque_canonical_cursor() {
    run_on_deep_stack(
        "join_application_list_paginates_with_opaque_canonical_cursor",
        join_application_list_paginates_with_opaque_canonical_cursor_body,
    );
}

async fn join_application_list_paginates_with_opaque_canonical_cursor_body() {
    let state = soland_test_support::app_state(join_config());
    let token = dev_token(state.clone()).await;
    let applicant = fixture_actor_core_id("did:web:alice.example");
    seed_applications(&state, applicant.as_str(), &['a', 'b', 'c']).await;

    let (status, first) = list_page(state.clone(), &token, "?limit=2").await;
    assert_eq!(status, Some(StatusCode::OK), "{first}");
    assert_eq!(
        first["applications"].as_array().unwrap().len(),
        2,
        "{first}"
    );
    let next_cursor = first["next_cursor"]
        .as_str()
        .expect("first page carries next_cursor");
    // api-conventions.md §7: single opaque cursor type; the bare
    // application_ref wire form is a spec violation.
    assert!(
        next_cursor.starts_with("ak:cursor:"),
        "next_cursor must be an opaque ak:cursor token, got {next_cursor}"
    );
    assert!(
        !next_cursor.contains("sha256"),
        "cursor must not leak the raw application_ref: {next_cursor}"
    );

    let encoded_cursor = next_cursor.replace(':', "%3A");
    let (status, second) = list_page(
        state.clone(),
        &token,
        &format!("?limit=2&cursor={encoded_cursor}"),
    )
    .await;
    assert_eq!(status, Some(StatusCode::OK), "{second}");
    let second_refs: Vec<&str> = second["applications"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| entry["application_ref"].as_str().unwrap())
        .collect();
    assert_eq!(second_refs, vec![hash('c').as_str()], "{second}");
    assert!(second["next_cursor"].is_null(), "{second}");

    // Continuation is bound to the requesting principal+device: replaying the
    // cursor from a different device is a binding mismatch ->
    // `cursor_integrity_invalid` (encoding.md §8.3.1).
    let other_device_token = verified_dev_token_for_device(
        state.clone(),
        "did:web:alice.example",
        "ak:device:01904100-0000-7000-8000-a11ce0000002",
        "Alice Laptop",
    )
    .await;
    let (status, cross_device) = list_page(
        state.clone(),
        &other_device_token,
        &format!("?limit=2&cursor={encoded_cursor}"),
    )
    .await;
    assert_ne!(status, Some(StatusCode::OK));
    assert_eq!(
        cross_device["error"]["code"], "cursor_integrity_invalid",
        "{cross_device}"
    );
}

#[test]
fn join_application_list_rejects_bare_application_ref_cursor() {
    run_on_deep_stack(
        "join_application_list_rejects_bare_application_ref_cursor",
        join_application_list_rejects_bare_application_ref_cursor_body,
    );
}

async fn join_application_list_rejects_bare_application_ref_cursor_body() {
    let state = soland_test_support::app_state(join_config());
    let token = dev_token(state.clone()).await;
    let applicant = fixture_actor_core_id("did:web:alice.example");
    seed_applications(&state, applicant.as_str(), &['a', 'b']).await;

    // The pre-convergence wire form (bare application_ref) MUST now be
    // rejected as a cursor syntax failure: top-level `param_invalid` with
    // reason `invalid_cursor` (encoding.md §8.3 closed set).
    let bare = hash('a').replace(':', "%3A");
    let (status, rejected) = list_page(state.clone(), &token, &format!("?cursor={bare}")).await;
    assert_eq!(status, Some(StatusCode::BAD_REQUEST), "{rejected}");
    assert_eq!(rejected["error"]["code"], "param_invalid", "{rejected}");
    assert_eq!(
        rejected["error"]["details"]["reason_code"], "invalid_cursor",
        "{rejected}"
    );

    // A canonical SDK cursor whose handle was never minted by this service is
    // a handle-lookup failure -> `cursor_integrity_invalid`, never a syntax
    // error (encoding.md §8.3.1).
    let foreign = arkret_wire::cursor::Cursor::new_at(chrono::Utc::now(), 60_000)
        .unwrap()
        .encode()
        .unwrap()
        .replace(':', "%3A");
    let (status, foreign_rejected) =
        list_page(state.clone(), &token, &format!("?cursor={foreign}")).await;
    assert_ne!(status, Some(StatusCode::OK));
    assert_eq!(
        foreign_rejected["error"]["code"], "cursor_integrity_invalid",
        "{foreign_rejected}"
    );
}
