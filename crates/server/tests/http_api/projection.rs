//! Integration tests — `projection` domain.
//!
//! Helpers live in [`super::common`]; pull them in via `use`.

use super::common::*;

#[test]
fn projection_space_containers_endpoint_reports_lifecycle_state() {
    run_on_deep_stack(
        "projection_space_containers_endpoint_reports_lifecycle_state",
        projection_space_containers_endpoint_reports_lifecycle_state_body,
    );
}

async fn projection_space_containers_endpoint_reports_lifecycle_state_body() {
    let state = soland_test_support::app_state(test_config());
    let token = dev_token(state.clone()).await;
    // Every fixture DataEvent below names the demo Realm's basis Seal in
    // `seal_ref`; that Seal and the founding unit it covers have to be accepted
    // before the first submit (`event-auth-state-resolution.md` §4.3).
    seed_demo_realm_basis(&state).await;
    let realm_id = demo_realm_id();
    // ── auth required ──────────────────────────────────────────────────
    let unauth = TestClient::get(format!(
        "http://server/_arkret/self/realms/{realm_id}/spaces"
    ))
    .send(&app_from_state(state.clone()))
    .await;
    assert_eq!(unauth.status_code.unwrap().as_u16(), 401);

    // ── seed: create + archive a Space container ────────────────────────
    let create_event = signed_space_event(
        "ak:event:AUdcg_tWaOx2mq2N-8743W9xEP8Q35yxM87nNC95OxlN",
        1,
        "ak.space.create",
        serde_json::json!({
            "object": {
                "realm_id": realm_id,
                "kind": "list",
                "title": "Hydration target",
                "created_by": fixture_actor_core_id("did:web:alice.example"),
            }
        }),
        Vec::new(),
    );
    let container_space_id = authored_space_id(&create_event).to_string();
    let create_event_id = authored_event_id(&create_event).to_string();
    let r: Value = TestClient::post("http://server/_arkret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&create_event)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(
        r["status"], "accepted",
        "create space container response: {r}"
    );

    let archive_event = signed_space_event(
        "ak:event:AelSfWbyB8v5LgV4tW6Voo4vol9OLm5vk2JL25-09qH5",
        2,
        "ak.space.archive",
        serde_json::json!({ "space_id": container_space_id }),
        vec![create_event_id.as_str()],
    );
    let archive_event_id = authored_event_id(&archive_event).to_string();
    let r: Value = TestClient::post("http://server/_arkret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&archive_event)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(
        r["status"], "accepted",
        "archive space container response: {r}"
    );

    // ── projection now reports archived ───────────────────────────────
    let body: Value = TestClient::get(format!(
        "http://server/_arkret/self/realms/{realm_id}/spaces"
    ))
    .add_header("authorization", format!("Bearer {token}"), true)
    .send(&app_from_state(state.clone()))
    .await
    .take_json()
    .await
    .unwrap();
    assert_eq!(body["realm_id"], realm_id);
    let spaces = body["spaces"].as_array().unwrap();
    let row = spaces
        .iter()
        .find(|p| p["space_id"] == container_space_id)
        .expect("space container not in projection response");
    assert_eq!(row["state"], "archived");
    assert_eq!(row["title"], "Hydration target");

    // ── restore + re-fetch → active ───────────────────────────────────
    let restore_event = signed_space_event(
        "ak:event:Af_iozNXHubayuuNSBTFtswzAG4pYMhCPxsig0BaqpcJ",
        3,
        "ak.space.restore",
        serde_json::json!({ "space_id": container_space_id }),
        vec![archive_event_id.as_str()],
    );
    let r: Value = TestClient::post("http://server/_arkret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&restore_event)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(
        r["status"], "accepted",
        "restore space container response: {r}"
    );

    let body: Value = TestClient::get(format!(
        "http://server/_arkret/self/realms/{realm_id}/spaces"
    ))
    .add_header("authorization", format!("Bearer {token}"), true)
    .send(&app_from_state(state.clone()))
    .await
    .take_json()
    .await
    .unwrap();
    let row = body["spaces"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["space_id"] == container_space_id)
        .expect("space container still missing post-restore");
    assert_eq!(row["state"], "active");
}

#[test]
fn current_board_and_strand_projection_survives_since_join_history_cut() {
    run_on_deep_stack(
        "current_board_and_strand_projection_survives_since_join_history_cut",
        current_board_and_strand_projection_survives_since_join_history_cut_body,
    );
}

async fn current_board_and_strand_projection_survives_since_join_history_cut_body() {
    let state = soland_test_support::app_state(test_config());
    let alice = dev_token(state.clone()).await;
    seed_demo_realm_basis(&state).await;
    let realm_id = demo_realm_id();

    let board_create = signed_space_event(
        "ak:event:AfDT9W9G2btP1vV9vyBWqRVVC3v3VBEA2lBTMtMJn5xo",
        1,
        "ak.space.create",
        serde_json::json!({
            "object": {
                "realm_id": realm_id,
                "kind": "board",
                "title": "Pre-join release board",
                "created_by": fixture_actor_core_id("did:web:alice.example"),
            }
        }),
        Vec::new(),
    );
    let board_id = authored_space_id(&board_create).to_string();
    let board_event_id = authored_event_id(&board_create).to_string();
    let response: Value = TestClient::post("http://server/_arkret/self/events")
        .add_header("authorization", format!("Bearer {alice}"), true)
        .json(&board_create)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(response["status"], "accepted", "board create: {response}");

    let strand_create = signed_strand_event(
        "ak:event:AZnjKqvxd4P1vCU8AkgNMe-GNZRVm_pUFmuBAggKXZcp",
        2,
        "ak.strand.create",
        serde_json::json!({
            "object": {
                "realm_id": realm_id,
                "metadata": { "title": "Pre-join current card" },
                "created_by": fixture_actor_core_id("did:web:alice.example"),
            }
        }),
        vec![board_event_id.as_str()],
    );
    let strand_id = authored_strand_id(&strand_create).to_string();
    let response: Value = TestClient::post("http://server/_arkret/self/events")
        .add_header("authorization", format!("Bearer {alice}"), true)
        .json(&strand_create)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(response["status"], "accepted", "strand create: {response}");

    let bob = register_account(
        state.clone(),
        "did:web:bob.example",
        "@bob",
        "ak:device:01904100-0000-7000-8000-b0b0b0002201",
    )
    .await;
    add_test_realm_member(&state, realm_id, "did:web:bob.example");

    let spaces: Value = TestClient::get(format!(
        "http://server/_arkret/self/realms/{realm_id}/spaces"
    ))
    .add_header("authorization", format!("Bearer {bob}"), true)
    .send(&app_from_state(state.clone()))
    .await
    .take_json()
    .await
    .unwrap();
    let board = spaces["spaces"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["space_id"] == board_id)
        .expect("current pre-join Board must remain in the active member baseline");
    assert_eq!(board["title"], "Pre-join release board");

    let strands: Value = TestClient::get(format!(
        "http://server/_arkret/self/realms/{realm_id}/strands"
    ))
    .add_header("authorization", format!("Bearer {bob}"), true)
    .send(&app_from_state(state.clone()))
    .await
    .take_json()
    .await
    .unwrap();
    let strand = strands["strands"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["strand_id"] == strand_id)
        .expect("current pre-join Strand must remain in the active member baseline");
    assert_eq!(strand["title"], "Pre-join current card");
}

#[test]
fn projection_strands_endpoint_reports_lifecycle_state() {
    run_on_deep_stack(
        "projection_strands_endpoint_reports_lifecycle_state",
        projection_strands_endpoint_reports_lifecycle_state_body,
    );
}

async fn projection_strands_endpoint_reports_lifecycle_state_body() {
    let state = soland_test_support::app_state(test_config());
    let token = dev_token(state.clone()).await;
    // Every fixture DataEvent below names the demo Realm's basis Seal in
    // `seal_ref`; that Seal and the founding unit it covers have to be accepted
    // before the first submit (`event-auth-state-resolution.md` §4.3).
    seed_demo_realm_basis(&state).await;
    let realm_id = demo_realm_id();
    let board_space_id = "ak:space:AVGlCsZA7qED4Oetfq2bCHssiEOshSrFXp7N2ozFnGNE";
    let list_space_id = "ak:space:ARLoPxFc4GPO50Iyec6Jgmc44pLU7zoS5J_ON1ilo5TL";

    let create_event = signed_strand_event(
        "ak:event:AVq4vwCqZOh70AyqBd46bxUJMSJrBe8BWv8V2T0cBAjW",
        1,
        "ak.strand.create",
        serde_json::json!({
            "object": {
                "realm_id": realm_id,
                "metadata": {
                    "title": "Hydration strand",
                    "fields": {
                        "board_space_id": board_space_id,
                        "list_space_id": list_space_id,
                        "rank": "r007",
                    },
                },
                "created_by": fixture_actor_core_id("did:web:alice.example"),
            }
        }),
        Vec::new(),
    );
    let strand_id = authored_strand_id(&create_event).to_string();
    let create_event_id = authored_event_id(&create_event).to_string();
    let r: Value = TestClient::post("http://server/_arkret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&create_event)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(r["status"], "accepted");

    let archive_event = signed_strand_event(
        "ak:event:AWdTHwE9vmQuc2JFQa19-QCQN3SOZO0jtz0V_9XHBaEm",
        2,
        "ak.strand.archive",
        serde_json::json!({ "strand_id": strand_id }),
        vec![create_event_id.as_str()],
    );
    let r: Value = TestClient::post("http://server/_arkret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&archive_event)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(r["status"], "accepted");

    let body: Value = TestClient::get(format!(
        "http://server/_arkret/self/realms/{realm_id}/strands"
    ))
    .add_header("authorization", format!("Bearer {token}"), true)
    .send(&app_from_state(state.clone()))
    .await
    .take_json()
    .await
    .unwrap();
    let row = body["strands"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["strand_id"] == strand_id)
        .expect("strand not in projection response");
    assert_eq!(row["state"], "archived");
    assert_eq!(row["board_space_id"], board_space_id);
    assert_eq!(row["list_space_id"], list_space_id);
    assert_eq!(row["rank"], "r007");
}

#[test]
fn projection_morphs_endpoint_reports_lifecycle_state() {
    run_on_deep_stack(
        "projection_morphs_endpoint_reports_lifecycle_state",
        projection_morphs_endpoint_reports_lifecycle_state_body,
    );
}

async fn projection_morphs_endpoint_reports_lifecycle_state_body() {
    let state = soland_test_support::app_state(test_config());
    let token = dev_token(state.clone()).await;
    // Every fixture DataEvent below names the demo Realm's basis Seal in
    // `seal_ref`; that Seal and the founding unit it covers have to be accepted
    // before the first submit (`event-auth-state-resolution.md` §4.3).
    seed_demo_realm_basis(&state).await;
    let realm_id = demo_realm_id();
    let create_event = signed_morph_event(
        "ak:event:AbLufeiJbhmgUZnOn6cv9IGg8IV6Ad_Z4jl-DO49vFNw",
        1,
        "ak.morph.create",
        serde_json::json!({
            "object": {
                "realm_id": realm_id,
                "morph_kind": "task",
                "metadata": { "title": "Hydration morph" },
                "created_by": fixture_actor_core_id("did:web:alice.example"),
            }
        }),
        Vec::new(),
    );
    let morph_id = authored_morph_id(&create_event).to_string();
    let create_event_id = authored_event_id(&create_event).to_string();
    let r: Value = TestClient::post("http://server/_arkret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&create_event)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(r["status"], "accepted");

    // Initial state — Active.
    let body: Value = TestClient::get(format!(
        "http://server/_arkret/self/realms/{realm_id}/morphs"
    ))
    .add_header("authorization", format!("Bearer {token}"), true)
    .send(&app_from_state(state.clone()))
    .await
    .take_json()
    .await
    .unwrap();
    let row = body["morphs"]
        .as_array()
        .unwrap()
        .iter()
        .find(|m| m["morph_id"] == morph_id)
        .expect("morph not in projection response");
    assert_eq!(row["state"], "active");
    assert_eq!(row["morph_kind"], "task");

    // Archive → state flips to `archived`.
    let archive_event = signed_morph_event(
        "ak:event:AbhoorI_PB5CpEEggShtKObleN6n0rDI4kM9AFEFC_qt",
        2,
        "ak.morph.archive",
        serde_json::json!({ "target_ref": morph_id }),
        vec![create_event_id.as_str()],
    );
    let r: Value = TestClient::post("http://server/_arkret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&archive_event)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(r["status"], "accepted");

    let body: Value = TestClient::get(format!(
        "http://server/_arkret/self/realms/{realm_id}/morphs"
    ))
    .add_header("authorization", format!("Bearer {token}"), true)
    .send(&app_from_state(state.clone()))
    .await
    .take_json()
    .await
    .unwrap();
    let row = body["morphs"]
        .as_array()
        .unwrap()
        .iter()
        .find(|m| m["morph_id"] == morph_id)
        .expect("morph not in projection response");
    assert_eq!(row["state"], "archived");

    // Unauthenticated → 401, no body leak.
    let unauth = TestClient::get(format!(
        "http://server/_arkret/self/realms/{realm_id}/morphs"
    ))
    .send(&app_from_state(state.clone()))
    .await;
    assert_eq!(unauth.status_code, Some(StatusCode::UNAUTHORIZED));
}

#[test]
fn projection_morphs_endpoint_filters_circle_scope() {
    run_on_deep_stack(
        "projection_morphs_endpoint_filters_circle_scope",
        projection_morphs_endpoint_filters_circle_scope_body,
    );
}

async fn projection_morphs_endpoint_filters_circle_scope_body() {
    let state = soland_test_support::app_state(test_config());
    let alice = dev_token(state.clone()).await;
    let bob = register_account(
        state.clone(),
        "did:web:bob.example",
        "@bob",
        "ak:device:01904100-0000-7000-8000-b0b0b0002001",
    )
    .await;
    let seeded_realm = seed_test_realm(
        &state,
        "did:web:alice.example",
        "Circle-scoped projection",
        None,
        "public",
        &[],
        &[],
    )
    .await;
    let realm_id = seeded_realm["realm_id"].as_str().unwrap();
    add_test_realm_member(&state, realm_id, "did:web:bob.example");
    let mut realm_meta = state
        .test_persistence()
        .realm_meta()
        .get(realm_id)
        .await
        .unwrap()
        .expect("demo Realm metadata");
    realm_meta.history_access = "all_history_for_current_members".to_owned();
    state
        .test_persistence()
        .realm_meta()
        .put(realm_id, &realm_meta)
        .await
        .unwrap();
    let circle_id = "ak:circle:AaoI0eSDbNn9UbtaAcQ_nZHyPjZqsTaKjh-Qt69GL7AY";
    let public_morph_id = "ak:morph:AbL77hQgJqY_yxFrkREfxYWuYi5MMp_siievgaFRHul-";
    let scoped_morph_id = "ak:morph:AY3ZBaN9HyOPM0trqiqxgRF55LCqTq_vfDZwTVOegTLG";
    let now = chrono::DateTime::<chrono::Utc>::from_timestamp_millis(
        chrono::Utc::now().timestamp_millis(),
    )
    .unwrap();

    {
        let mut projection = state.test_projection().lock();
        projection.circles.insert(
            circle_id.to_owned(),
            soland_domain::reducer::CircleProjection {
                circle_id: circle_id.to_owned(),
                realm_id: realm_id.to_owned(),
                profile_ref: None,
                title: "Need to know".to_owned(),
                summary: None,
                display: serde_json::json!({"short_name":"Need","color_token":"slate","symbol":{"glyph":"ring"}}),
                directory_visibility: "members".to_owned(),
                join_rule: "invite".to_owned(),
                history_access: "since_join".to_owned(),
                content_encryption_floor: None,
                metadata_encryption_floor: None,
                encryption_profile: "none".to_owned(),
                content_scheme: None,
                durability_policy: None,
                mls_group_ref: None,
                state: soland_domain::reducer::CircleLifecycleState::Active,
                state_changed_at: None,
                created_by: fixture_actor_core_id("did:web:alice.example").to_string(),
                created_at: now,
                updated_by: None,
                updated_at: None,
                members: std::collections::BTreeSet::from([
                    fixture_actor_core_id("did:web:alice.example").to_string(),
                ]),
            },
        );
        let alice_actor_id = fixture_actor_core_id("did:web:alice.example").to_string();
        projection.circle_memberships.insert(
            (circle_id.to_owned(), alice_actor_id.clone()),
            soland_domain::reducer::CircleMembershipState {
                circle_id: circle_id.to_owned(),
                member: alice_actor_id,
                state: "join".to_owned(),
                invited_at: None,
                joined_at: now,
                updated_at: now,
            },
        );
        for (morph_id, scope_circle_id) in [
            (public_morph_id, None),
            (scoped_morph_id, Some(circle_id.to_owned())),
        ] {
            projection.morphs.insert(
                morph_id.to_owned(),
                soland_domain::reducer::MorphProjection {
                    morph_id: morph_id.to_owned(),
                    realm_id: realm_id.to_owned(),
                    scope_circle_id,
                    morph_kind: "task".to_owned(),
                    title: Some("Scoped task".to_owned()),
                    fields: Default::default(),
                    schema_refs: Vec::new(),
                    facets: Default::default(),
                    versions: Vec::new(),
                    content: None,
                    encrypted_content: None,
                    state: soland_domain::reducer::ObjectLifecycleState::Active,
                    state_changed_at: None,
                    created_by: fixture_actor_core_id("did:web:alice.example").to_string(),
                    created_at: now,
                    history_basis_seals: Vec::new(),
                    updated_by: None,
                    updated_at: None,
                },
            );
        }
    }

    let bob_body: Value = TestClient::get(format!(
        "http://server/_arkret/self/realms/{realm_id}/morphs"
    ))
    .add_header("authorization", format!("Bearer {bob}"), true)
    .send(&app_from_state(state.clone()))
    .await
    .take_json()
    .await
    .unwrap();
    let bob_morphs = bob_body["morphs"].as_array().unwrap();
    assert!(bob_morphs.iter().any(|m| m["morph_id"] == public_morph_id));
    assert!(!bob_morphs.iter().any(|m| m["morph_id"] == scoped_morph_id));

    let alice_body: Value = TestClient::get(format!(
        "http://server/_arkret/self/realms/{realm_id}/morphs"
    ))
    .add_header("authorization", format!("Bearer {alice}"), true)
    .send(&app_from_state(state.clone()))
    .await
    .take_json()
    .await
    .unwrap();
    let alice_morphs = alice_body["morphs"].as_array().unwrap();
    assert!(
        alice_morphs
            .iter()
            .any(|m| m["morph_id"] == public_morph_id)
    );
    assert!(
        alice_morphs
            .iter()
            .any(|m| m["morph_id"] == scoped_morph_id)
    );
}

#[test]
fn projection_document_endpoint_reports_body_versions_relations_and_range_comments() {
    run_on_deep_stack(
        "projection_document_endpoint_reports_body_versions_relations_and_range_comments",
        projection_document_endpoint_reports_body_versions_relations_and_range_comments_body,
    );
}

async fn projection_document_endpoint_reports_body_versions_relations_and_range_comments_body() {
    let state = soland_test_support::app_state(test_config());
    let token = dev_token(state.clone()).await;
    // Every fixture DataEvent below names the demo Realm's basis Seal in
    // `seal_ref`; that Seal and the founding unit it covers have to be accepted
    // before the first submit (`event-auth-state-resolution.md` §4.3).
    seed_demo_realm_basis(&state).await;
    let realm_id = demo_realm_id();
    let relation_event_id = "ak:event:AcFfzgdHkT6eFkto1gjLaKniVuMXx9sD0GKQwk8BXykz";

    let initial_body = serde_json::json!({
        "schema_version": 1,
        "blocks": [{
            "id": "b1",
            "kind": "Paragraph",
            "content": "abcdefghij"
        }]
    });
    let create_event = signed_morph_event(
        "ak:event:AU43XAN9qvYmiLq0Zndni0ZUowntoof4TrNoT4sOTDFO",
        1,
        "ak.morph.create",
        serde_json::json!({
            "object": {
                "realm_id": realm_id,
                "morph_kind": "document",
                "metadata": { "title": "Postmortem draft" },
                "schema_refs": ["ak.schema.morph.v1"],
                "facets": {
                    "documentable": {}
                },
                "fields": {
                    "document": initial_body
                },
                "created_by": fixture_actor_core_id("did:web:alice.example"),
            }
        }),
        Vec::new(),
    );
    let morph_id = authored_morph_id(&create_event).to_string();
    let create_event_id = authored_event_id(&create_event).to_string();
    let create_response: Value = TestClient::post("http://server/_arkret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&create_event)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    if create_response["status"] != "accepted" {
        panic!("create document morph response: {create_response}");
    }

    let incident_event = signed_strand_event(
        "ak:event:AbO9-oAaWlgrGpmyvBa0nCCezz3tKAulGGURXg8FNx1L",
        2,
        "ak.strand.create",
        serde_json::json!({
            "object": {
                "realm_id": realm_id,
                "metadata": { "title": "Incident target" },
                "created_by": fixture_actor_core_id("did:web:alice.example"),
            }
        }),
        vec![create_event_id.as_str()],
    );
    let incident_ref = authored_strand_id(&incident_event).to_string();
    let incident_event_id = authored_event_id(&incident_event).to_string();
    let incident_response: Value = TestClient::post("http://server/_arkret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&incident_event)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(
        incident_response["status"], "accepted",
        "create incident strand response: {incident_response}"
    );

    let relation_event = signed_relation_event(
        relation_event_id,
        3,
        serde_json::json!({
            "kind": "references",
            "from_ref": morph_id,
            "to_ref": incident_ref,
        }),
        vec![create_event_id.as_str(), incident_event_id.as_str()],
    );
    let relation_id = authored_relation_id(&relation_event).to_string();
    let relation_response: Value = TestClient::post("http://server/_arkret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&relation_event)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(
        relation_response["status"], "accepted",
        "create document relation response: {relation_response}"
    );

    let comment_response = submit_message_event(
        state.clone(),
        &token,
        "did:web:alice.example",
        realm_id,
        &morph_id,
        serde_json::json!({
            "kind": "ak.content.text",
            "morph_id": morph_id,
            "anchor_range": {
                "target_ref": morph_id,
                "start": 2,
                "end": 9
            },
            "body": "tighten this section"
        }),
        false,
    )
    .await;
    if comment_response["canonical_event_envelope"] != true {
        panic!("create document comment response: {comment_response}");
    }

    let updated_body = serde_json::json!({
        "schema_version": 1,
        "blocks": [{
            "id": "b1",
            "kind": "Paragraph",
            "content": "abc"
        }]
    });
    let mut update_event = signed_morph_event(
        "ak:event:AYa4hdRhqjN-fcVxPWwm-pemVGqlziP_lfBqznpOjbX4",
        20_000,
        "ak.morph.update",
        serde_json::json!({
            "target_ref": morph_id,
            "patch": {
                "fields": {
                    "$op": "set",
                    "value": {
                        "document": updated_body
                    }
                }
            }
        }),
        vec![create_event_id.as_str()],
    );
    move_event_to_actor_realm_frontier(
        &state,
        &token,
        "did:web:alice.example",
        realm_id,
        &mut update_event,
    )
    .await;
    let update_response: Value = TestClient::post("http://server/_arkret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&update_event)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(
        update_response["status"], "accepted",
        "update document morph response: {update_response}"
    );

    let body: Value = TestClient::get(format!(
        "http://server/_arkret/self/realms/{realm_id}/morphs/{morph_id}"
    ))
    .add_header("authorization", format!("Bearer {token}"), true)
    .send(&app_from_state(state.clone()))
    .await
    .take_json()
    .await
    .unwrap();
    assert_eq!(
        body["document"]["morph_id"], morph_id,
        "document projection response: {body}"
    );
    assert_eq!(body["document"]["realm_id"], realm_id);
    assert_eq!(body["document"]["morph_kind"], "document");
    assert_eq!(body["document"]["body"], updated_body);
    assert_eq!(body["document"]["fields"]["document"], updated_body);
    assert_eq!(body["document"]["schema_refs"][0], "ak.schema.morph.v1");
    assert_eq!(body["document"]["facets"][0], "documentable");

    let versions = body["versions"].as_array().expect("versions array");
    assert_eq!(versions.len(), 2);
    assert_eq!(versions[0]["body"], initial_body);
    assert_eq!(versions[1]["body"], updated_body);
    assert_ne!(versions[0]["body_digest"], versions[1]["body_digest"]);

    let relation = body["relations"]
        .as_array()
        .expect("relations array")
        .iter()
        .find(|relation| relation["relation_id"] == relation_id)
        .expect("document relation projected");
    assert_eq!(relation["relation_kind"], "references");
    assert_eq!(relation["from"], morph_id);
    assert_eq!(relation["to"], incident_ref);
    assert_eq!(relation["reference_projection"]["status"], "accessible");

    let comment = body["comments"]
        .as_array()
        .expect("comments array")
        .iter()
        .find(|comment| comment["body"] == "tighten this section")
        .expect("document range comment projected");
    assert_eq!(comment["anchor_range"]["start"], 2);
    assert_eq!(comment["anchor_range"]["end"], 9);
    assert_eq!(comment["state"], "orphaned");
    assert_eq!(body["cursor_presence_entries"].as_array().unwrap().len(), 0);
}

#[test]
fn projection_document_relations_return_lazy_and_locked_stubs() {
    run_on_deep_stack(
        "projection_document_relations_return_lazy_and_locked_stubs",
        projection_document_relations_return_lazy_and_locked_stubs_body,
    );
}

async fn projection_document_relations_return_lazy_and_locked_stubs_body() {
    let state = soland_test_support::app_state(test_config());
    let token = dev_token(state.clone()).await;
    // Every fixture DataEvent below names the demo Realm's basis Seal in
    // `seal_ref`; that Seal and the founding unit it covers have to be accepted
    // before the first submit (`event-auth-state-resolution.md` §4.3).
    seed_demo_realm_basis(&state).await;
    let realm_id = demo_realm_id();
    let morph_id = "ak:morph:AZSXE5WVNu8KIIPUpTYq1ZlfJVUrbrezmj3lKVks2d0N";
    let same_target_ref = "ak:strand:AQPqQQ86Xu0oki28I-vHxUaqNx9y9BGncx-7heOYTZwg";
    let lazy_target_ref = "ak:strand:Ac6u1DKNseulQmYSXes-UrvL-zM0RBPYlUadifIq6wSs";
    let locked_target_ref = "ak:strand:AdArKwEUPOig86r2oe5VHuOdnLhv5KQ3nWVa1HKuRcQK";
    let accessible_relation_id = "ak:relation:AcyuB-mIWNzTvMpkqn1Lz9JVfZo8ky6fKeSSK2hljxcw";
    let lazy_relation_id = "ak:relation:Abi-xNgrrLAUCnl_-BL_YG0QIHAewzPQ21f2ex9W5NOL";
    let locked_relation_id = "ak:relation:AZRfgHsyj3msAfmFFn7FnKYtmmjXhIXVUhAqxOKq_H5p";

    let lazy_realm = seed_test_realm(
        &state,
        "did:web:bob.example",
        "Lazy target Realm",
        None,
        "invite_only",
        &[],
        &[],
    )
    .await;
    let lazy_realm_id = lazy_realm["realm_id"].as_str().unwrap().to_owned();
    add_test_realm_member(&state, &lazy_realm_id, "did:web:alice.example");
    let locked_realm = seed_test_realm(
        &state,
        "did:web:bob.example",
        "Locked target Realm",
        None,
        "secret",
        &[],
        &[],
    )
    .await;
    let locked_realm_id = locked_realm["realm_id"].as_str().unwrap().to_owned();

    let now = chrono::DateTime::<chrono::Utc>::from_timestamp_millis(
        chrono::Utc::now().timestamp_millis(),
    )
    .unwrap();
    let strand = |strand_id: &str, strand_realm_id: &str, title: &str| {
        soland_domain::reducer::StrandProjection {
            strand_id: strand_id.to_owned(),
            realm_id: strand_realm_id.to_owned(),
            tracks: Default::default(),
            title: title.to_owned(),
            summary: None,
            content: None,
            encrypted_content: None,
            fields: Default::default(),
            state: soland_domain::reducer::ObjectLifecycleState::Active,
            state_changed_at: None,
            created_by: fixture_actor_core_id("did:web:alice.example").to_string(),
            created_at: now,
            history_basis_seals: Vec::new(),
            updated_by: None,
            updated_at: None,
            schema_refs: Vec::new(),
            schedule_revision_heads: Vec::new(),
            scope_circle_id: None,
        }
    };
    let relation = |relation_id: &str,
                    target_ref: &str,
                    role: &str|
     -> soland_domain::reducer::SolandRelationState {
        let mut fields = std::collections::BTreeMap::new();
        fields.insert("role".to_owned(), serde_json::json!(role));
        fields.insert("preview_title".to_owned(), serde_json::json!(role));
        soland_domain::reducer::SolandRelationState {
            relation_id: relation_id.to_owned(),
            realm_id: realm_id.to_owned(),
            relation_kind: "references".to_owned(),
            scope_circle_id: None,
            from_ref: Some(morph_id.to_owned()),
            to_ref: Some(target_ref.to_owned()),
            fields,
            state: "active".to_owned(),
            source_event_id: None,
            source_event_digest: Some(format!("sha256:{}", "1".repeat(64))),
            created_at: now,
            history_basis_seals: Vec::new(),
            updated_at: now,
        }
    };

    {
        let mut projection = state.test_projection().lock();
        let mut fields = std::collections::BTreeMap::new();
        fields.insert(
            "document".to_owned(),
            serde_json::json!({
                "schema_version": 1,
                "blocks": []
            }),
        );
        projection.morphs.insert(
            morph_id.to_owned(),
            soland_domain::reducer::MorphProjection {
                morph_id: morph_id.to_owned(),
                realm_id: realm_id.to_owned(),
                scope_circle_id: None,
                morph_kind: "document".to_owned(),
                title: Some("Reference audit".to_owned()),
                fields,
                schema_refs: Vec::new(),
                facets: Default::default(),
                versions: Vec::new(),
                content: None,
                encrypted_content: None,
                state: soland_domain::reducer::ObjectLifecycleState::Active,
                state_changed_at: None,
                created_by: fixture_actor_core_id("did:web:alice.example").to_string(),
                created_at: now,
                history_basis_seals: Vec::new(),
                updated_by: None,
                updated_at: None,
            },
        );
        projection.strands.insert(
            same_target_ref.to_owned(),
            strand(same_target_ref, realm_id, "Same Realm Target"),
        );
        projection.strands.insert(
            lazy_target_ref.to_owned(),
            strand(lazy_target_ref, &lazy_realm_id, "Cross Realm Secret Title"),
        );
        projection.strands.insert(
            locked_target_ref.to_owned(),
            strand(locked_target_ref, &locked_realm_id, "Locked Secret Title"),
        );
        projection.relations.insert(
            accessible_relation_id.to_owned(),
            relation(accessible_relation_id, same_target_ref, "same_realm"),
        );
        projection.relations.insert(
            lazy_relation_id.to_owned(),
            relation(
                lazy_relation_id,
                lazy_target_ref,
                "Cross Realm Secret Title",
            ),
        );
        projection.relations.insert(
            locked_relation_id.to_owned(),
            relation(locked_relation_id, locked_target_ref, "Locked Secret Title"),
        );
    }

    let body: Value = TestClient::get(format!(
        "http://server/_arkret/self/realms/{realm_id}/morphs/{morph_id}"
    ))
    .add_header("authorization", format!("Bearer {token}"), true)
    .send(&app_from_state(state.clone()))
    .await
    .take_json()
    .await
    .unwrap();
    let relations = body["relations"]
        .as_array()
        .unwrap_or_else(|| panic!("relations array missing from response: {body}"));
    let accessible = relations
        .iter()
        .find(|relation| relation["relation_id"] == accessible_relation_id)
        .expect("same-Realm relation projected");
    assert_eq!(accessible["reference_projection"]["status"], "accessible");
    assert_eq!(accessible["to"], same_target_ref);
    assert_eq!(accessible["fields"]["role"], "same_realm");

    let lazy = relations
        .iter()
        .find(|relation| relation["relation_id"] == lazy_relation_id)
        .expect("cross-Realm relation projected");
    assert_eq!(lazy["reference_projection"]["status"], "lazy_link");
    assert_eq!(lazy["lazy_link"], true);
    assert!(lazy.get("to").is_none());
    assert!(lazy.get("fields").is_none());
    let lazy_wire = serde_json::to_string(lazy).unwrap();
    assert!(!lazy_wire.contains(lazy_target_ref));
    assert!(!lazy_wire.contains(&lazy_realm_id));
    assert!(!lazy_wire.contains("Cross Realm Secret Title"));

    let locked = relations
        .iter()
        .find(|relation| relation["relation_id"] == locked_relation_id)
        .expect("locked relation projected");
    assert_eq!(locked["reference_projection"]["status"], "locked");
    assert_eq!(locked["locked"], true);
    assert!(locked.get("to").is_none());
    assert!(locked.get("fields").is_none());
    let locked_wire = serde_json::to_string(locked).unwrap();
    assert!(!locked_wire.contains(locked_target_ref));
    assert!(!locked_wire.contains(&locked_realm_id));
    assert!(!locked_wire.contains("Locked Secret Title"));
}

#[test]
fn projection_endpoints_hide_terminal_state_by_default() {
    run_on_deep_stack(
        "projection_endpoints_hide_terminal_state_by_default",
        projection_endpoints_hide_terminal_state_by_default_body,
    );
}

async fn projection_endpoints_hide_terminal_state_by_default_body() {
    let state = soland_test_support::app_state(test_config());
    let token = dev_token(state.clone()).await;
    // Every fixture DataEvent below names the demo Realm's basis Seal in
    // `seal_ref`; that Seal and the founding unit it covers have to be accepted
    // before the first submit (`event-auth-state-resolution.md` §4.3).
    seed_demo_realm_basis(&state).await;
    let realm_id = demo_realm_id();
    // Create + tombstone a Space container.
    let create_space = signed_space_event(
        "ak:event:AVwC-xute0mcjLNt1it-wqD5SraAbhf7KsUjT_Tv9grH",
        1,
        "ak.space.create",
        serde_json::json!({
            "object": {
                "realm_id": realm_id,
                "kind": "list",
                "title": "Doomed Space",
                "created_by": fixture_actor_core_id("did:web:alice.example"),
            }
        }),
        Vec::new(),
    );
    let container_space_id = authored_space_id(&create_space).to_string();
    let create_space_event_id = authored_event_id(&create_space).to_string();
    let r: Value = TestClient::post("http://server/_arkret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&create_space)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(r["status"], "accepted");

    let tombstone_space = signed_space_event(
        "ak:event:AfJ4izKSeLkHMvYwpbNP_Yno6umiglzFWWUkUafcBw5N",
        2,
        "ak.space.tombstone",
        serde_json::json!({ "space_id": container_space_id }),
        vec![create_space_event_id.as_str()],
    );
    let tombstone_space_event_id = authored_event_id(&tombstone_space).to_string();
    let r: Value = TestClient::post("http://server/_arkret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&tombstone_space)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(r["status"], "accepted");

    // Default Space-container projection — tombstoned Space container is hidden.
    let body: Value = TestClient::get(format!(
        "http://server/_arkret/self/realms/{realm_id}/spaces"
    ))
    .add_header("authorization", format!("Bearer {token}"), true)
    .send(&app_from_state(state.clone()))
    .await
    .take_json()
    .await
    .unwrap();
    assert!(
        body["spaces"]
            .as_array()
            .unwrap()
            .iter()
            .all(|p| p["space_id"] != container_space_id),
        "tombstoned Space container MUST be hidden from default projection listing"
    );

    // Explicit include_terminal=true — tombstoned Space container is visible.
    let body: Value = TestClient::get(format!(
        "http://server/_arkret/self/realms/{realm_id}/spaces?include_terminal=true"
    ))
    .add_header("authorization", format!("Bearer {token}"), true)
    .send(&app_from_state(state.clone()))
    .await
    .take_json()
    .await
    .unwrap();
    let row = body["spaces"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["space_id"] == container_space_id)
        .expect("tombstoned Space container MUST appear when include_terminal=true");
    assert_eq!(row["state"], "tombstoned");

    // Create a Strand + redact it.
    let create_strand = signed_strand_event(
        "ak:event:AR5VsTJWq7zLZRRth7JFR3vqEy7fASYv2N-naDM4sXBm",
        3,
        "ak.strand.create",
        serde_json::json!({
            "object": {
                "realm_id": realm_id,
                "metadata": { "title": "Doomed Strand" },
                "created_by": fixture_actor_core_id("did:web:alice.example"),
            }
        }),
        vec![tombstone_space_event_id.as_str()],
    );
    let strand_id = authored_strand_id(&create_strand).to_string();
    let create_strand_event_id = authored_event_id(&create_strand).to_string();
    let r: Value = TestClient::post("http://server/_arkret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&create_strand)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(r["status"], "accepted");

    let redact_strand = signed_redaction_event(
        "ak:event:ASbsF6NRXo3Daa7ewI4CDLCLWwaSq3z9if2gB1drYnFu",
        4,
        serde_json::json!({
            "target_ref": strand_id,
        }),
        vec![create_strand_event_id.as_str()],
    );
    let r: Value = TestClient::post("http://server/_arkret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&redact_strand)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(r["status"], "accepted");

    // Default Strand listing — redacted Strand hidden.
    let body: Value = TestClient::get(format!(
        "http://server/_arkret/self/realms/{realm_id}/strands"
    ))
    .add_header("authorization", format!("Bearer {token}"), true)
    .send(&app_from_state(state.clone()))
    .await
    .take_json()
    .await
    .unwrap();
    assert!(
        body["strands"]
            .as_array()
            .unwrap()
            .iter()
            .all(|f| f["strand_id"] != strand_id),
        "redacted Strand MUST be hidden from default projection listing"
    );

    // Explicit include_terminal=true — redacted Strand visible.
    let body: Value = TestClient::get(format!(
        "http://server/_arkret/self/realms/{realm_id}/strands?include_terminal=true"
    ))
    .add_header("authorization", format!("Bearer {token}"), true)
    .send(&app_from_state(state.clone()))
    .await
    .take_json()
    .await
    .unwrap();
    let row = body["strands"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["strand_id"] == strand_id)
        .expect("redacted Strand MUST appear when include_terminal=true");
    assert_eq!(row["state"], "redacted");
}

#[test]
fn projection_persistence_write_through_mirrors_lifecycle_events() {
    run_on_deep_stack(
        "projection_persistence_write_through_mirrors_lifecycle_events",
        projection_persistence_write_through_mirrors_lifecycle_events_body,
    );
}

async fn projection_persistence_write_through_mirrors_lifecycle_events_body() {
    let state = soland_test_support::app_state(test_config());
    let token = dev_token(state.clone()).await;
    // Every fixture DataEvent below names the demo Realm's basis Seal in
    // `seal_ref`; that Seal and the founding unit it covers have to be accepted
    // before the first submit (`event-auth-state-resolution.md` §4.3).
    seed_demo_realm_basis(&state).await;
    // Space container: create + archive → persistence has state=archived.
    let create_space = signed_space_event(
        "ak:event:AVC_FSWCcLty3gxBqBei6I5k-lvJYjaoGgLXNgVHazO-",
        1,
        "ak.space.create",
        serde_json::json!({
            "object": {
                "realm_id": demo_realm_id(),
                "kind": "list",
                "title": "Persistent Space",
                "created_by": fixture_actor_core_id("did:web:alice.example"),
            }
        }),
        Vec::new(),
    );
    let container_space_id = authored_space_id(&create_space).to_string();
    let create_space_event_id = authored_event_id(&create_space).to_string();
    let r: Value = TestClient::post("http://server/_arkret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&create_space)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(r["status"], "accepted");

    let archive_space = signed_space_event(
        "ak:event:AUuP-624T75y-LdWRnnY7YldZTBllvuImOiLA22BDCLH",
        2,
        "ak.space.archive",
        serde_json::json!({ "space_id": container_space_id }),
        vec![create_space_event_id.as_str()],
    );
    let archive_space_event_id = authored_event_id(&archive_space).to_string();
    let r: Value = TestClient::post("http://server/_arkret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&archive_space)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(r["status"], "accepted");

    let space_row = state
        .test_persistence()
        .space_container_projections()
        .get(&container_space_id)
        .await
        .unwrap()
        .expect("space projection MUST be mirrored to persistence after create+archive");
    assert_eq!(space_row.state, "archived");
    assert_eq!(space_row.title, "Persistent Space");

    // list_for_realm + snapshot_all reach the same row.
    let by_space = state
        .test_persistence()
        .space_container_projections()
        .list_for_realm(demo_realm_id())
        .await
        .unwrap();
    assert!(
        by_space
            .iter()
            .any(|p| p.container_space_id == container_space_id),
        "list_for_realm MUST surface the persisted space container"
    );
    let snapshot = state
        .test_persistence()
        .space_container_projections()
        .snapshot_all()
        .await
        .unwrap();
    assert!(
        snapshot
            .iter()
            .any(|p| p.container_space_id == container_space_id)
    );

    // Strand: create + redact → persistence has state=redacted.
    let create_strand = signed_strand_event(
        "ak:event:AS7tV8pSS7nJTsUlSWtwFVnfbB0Y7qjZbKVumXBBPwap",
        3,
        "ak.strand.create",
        serde_json::json!({
            "object": {
                "realm_id": demo_realm_id(),
                "metadata": { "title": "Persistent Strand" },
                "created_by": fixture_actor_core_id("did:web:alice.example"),
            }
        }),
        vec![archive_space_event_id.as_str()],
    );
    let strand_id = authored_strand_id(&create_strand).to_string();
    let create_strand_event_id = authored_event_id(&create_strand).to_string();
    let r: Value = TestClient::post("http://server/_arkret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&create_strand)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(r["status"], "accepted");
    let strand_row = state
        .test_persistence()
        .strand_projections()
        .get(&strand_id)
        .await
        .unwrap()
        .expect("strand projection MUST be mirrored to persistence after create");
    assert_eq!(strand_row.state, "active");
    assert_eq!(strand_row.title, "Persistent Strand");

    let redact_strand = signed_redaction_event(
        "ak:event:ASJ1A-Nm-TdJt8UpH49Yoyt1AbJZDV088rk_6hKn2Ica",
        4,
        serde_json::json!({
            "target_ref": strand_id,
        }),
        vec![create_strand_event_id.as_str()],
    );
    let redact_strand_event_id = authored_event_id(&redact_strand).to_string();
    let r: Value = TestClient::post("http://server/_arkret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&redact_strand)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(r["status"], "accepted");
    let strand_row = state
        .test_persistence()
        .strand_projections()
        .get(&strand_id)
        .await
        .unwrap()
        .expect("strand projection MUST still exist after redaction");
    assert_eq!(
        strand_row.state, "redacted",
        "ak.redaction with target_ref MUST flip strand projection in persistence too"
    );

    // Morph: create + archive → persistence has state=archived.
    let create_morph = signed_morph_event(
        "ak:event:Af08fVvN-6nEKxePh4mvCpBxYyn3ddLOvXny4eJivcIL",
        5,
        "ak.morph.create",
        serde_json::json!({
            "object": {
                "realm_id": demo_realm_id(),
                "morph_kind": "task",
                "metadata": { "title": "Persistent Morph" },
                "created_by": fixture_actor_core_id("did:web:alice.example"),
            }
        }),
        vec![redact_strand_event_id.as_str()],
    );
    let morph_id = authored_morph_id(&create_morph).to_string();
    let create_morph_event_id = authored_event_id(&create_morph).to_string();
    let r: Value = TestClient::post("http://server/_arkret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&create_morph)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(r["status"], "accepted");

    let archive_morph = signed_morph_event(
        "ak:event:ATSAw2P5r0xmIXMIfmGX1CQTp7Ek_KsgknkDWTFMXYXO",
        6,
        "ak.morph.archive",
        serde_json::json!({ "target_ref": morph_id }),
        vec![create_morph_event_id.as_str()],
    );
    let r: Value = TestClient::post("http://server/_arkret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&archive_morph)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(r["status"], "accepted");
    let morph_row = state
        .test_persistence()
        .morph_projections()
        .get(&morph_id)
        .await
        .unwrap()
        .expect("morph projection MUST be mirrored to persistence");
    assert_eq!(morph_row.state, "archived");
    assert_eq!(morph_row.morph_kind, "task");
}
