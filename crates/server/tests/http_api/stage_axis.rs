//! Integration tests — canonical business-progression `stage` axis.
//!
//! Spec: `models/common-fields.md` §5.3 and `models/strand-and-message.md` §3.2.
//! `ak.<kind>.stage.set` is the single wire path that mutates `stage` /
//! `stage_changed_at`; ruling `2026-09-04-1752` settled that v1 registers no
//! Realm workflow-profile carrier, so the core reducer enforces only the six
//! §5.3.3 hard invariants and imposes no direction between the eight values.
//!
//! Helpers live in [`super::common`]; pull them in via `use`.

use super::common::*;

fn strand_view(state: &AppState, strand_id: &str) -> Value {
    let projection = state.test_projection().lock();
    let strand = projection
        .strands
        .get(strand_id)
        .expect("strand is projected");
    serde_json::json!({
        "state": strand.state.as_str(),
        "stage": strand
            .stage
            .as_ref()
            .map(soland_domain::reducer::object_stage_wire_value),
        "stage_changed_at": strand.stage_changed_at,
    })
}

#[test]
fn strand_stage_set_is_the_single_writable_path_for_the_stage_axis() {
    run_on_deep_stack(
        "strand_stage_set_is_the_single_writable_path_for_the_stage_axis",
        strand_stage_set_is_the_single_writable_path_for_the_stage_axis_body,
    );
}

/// The end-to-end shape the joint Kanban case asserts: a Strand created at
/// `planned` is advanced straight to `done` by `ak.strand.stage.set` — no
/// intermediate `in_progress` — and the object read surface hands the
/// canonical `stage` plus the reducer-derived `stage_changed_at` back.
async fn strand_stage_set_is_the_single_writable_path_for_the_stage_axis_body() {
    let state = soland_test_support::app_state(test_config());
    let token = dev_token(state.clone()).await;
    // Every fixture DataEvent below names the demo Realm's basis Seal in
    // `seal_ref`; that Seal and the founding unit it covers have to be accepted
    // before the first submit (`event-auth-state-resolution.md` §4.3).
    seed_demo_realm_basis(&state).await;

    let create = signed_strand_event(
        "ak:event:AYq3EJDIMPtb4L2FLwSJ8FLLNiV9xX5S4JHDbGmPy7Yv",
        1,
        "ak.strand.create",
        serde_json::json!({
            "object": {
                "realm_id": demo_realm_id(),
                "metadata": { "title": "Implement login" },
                "stage": "planned",
                "created_by": fixture_account_actor(&state, "did:web:alice.example"),
            }
        }),
        Vec::new(),
    );
    let strand_id = authored_strand_id(&create).to_string();
    let create_event_id = authored_event_id(&create).to_string();
    let resp: Value = TestClient::post("http://server/_arkret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&create)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(resp["status"], "accepted", "{resp}");

    // Create initializes the axis. It is not a transition, so `stage_changed_at`
    // stays absent (`common-fields.md` §5.3.3 rule 3).
    let before = strand_view(&state, &strand_id);
    assert_eq!(before["stage"], "planned", "{before}");
    assert!(before["stage_changed_at"].is_null(), "{before}");

    let read: Value = TestClient::get(format!("http://server/_soland/self/strands/{strand_id}"))
        .add_header("authorization", format!("Bearer {token}"), true)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(read["stage"], "planned", "{read}");
    assert!(read.get("stage_changed_at").is_none(), "{read}");

    // `planned -> done` skips `in_progress`. The deleted private transition rejected
    // exactly this; the core reducer has no direction rule at all (§5.3.3).
    let advance = signed_strand_event(
        "ak:event:AZv0YWJ8Q7t3bnvpDGRJMHEG7XoKbFZ8Ea5R4qbNfHzT",
        2,
        "ak.strand.stage.set",
        serde_json::json!({ "strand_id": strand_id, "stage": "done" }),
        vec![create_event_id.as_str()],
    );
    let advance_event_id = authored_event_id(&advance).to_string();
    let resp: Value = TestClient::post("http://server/_arkret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&advance)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(resp["status"], "accepted", "{resp}");

    let after = strand_view(&state, &strand_id);
    assert_eq!(after["stage"], "done", "{after}");
    assert!(
        !after["stage_changed_at"].is_null(),
        "a real transition writes the reducer-derived timestamp: {after}"
    );
    // `stage` and `state` are orthogonal: `done` never archives the object.
    assert_eq!(after["state"], "active", "{after}");

    let read: Value = TestClient::get(format!("http://server/_soland/self/strands/{strand_id}"))
        .add_header("authorization", format!("Bearer {token}"), true)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(read["stage"], "done", "{read}");
    assert!(
        read.get("stage_changed_at").is_some(),
        "the object read surface returns the updated stage_changed_at: {read}"
    );

    // Ruling 2026-09-05-2030 — `ak.self.strand.read.list` is the cross-implementation
    // carrier for the stage axis, so the canonical list surface has to return the
    // whole lifecycle cluster and not just its `state` half. A value only the
    // product-private object read can produce is not interoperable.
    let listed: Value = TestClient::get(format!(
        "http://server/_arkret/self/realms/{}/strands",
        demo_realm_id()
    ))
    .add_header("authorization", format!("Bearer {token}"), true)
    .send(&app_from_state(state.clone()))
    .await
    .take_json()
    .await
    .unwrap();
    let row = listed["strands"]
        .as_array()
        .expect("canonical Strand list")
        .iter()
        .find(|row| row["strand_id"] == strand_id.as_str())
        .unwrap_or_else(|| panic!("Strand missing from the canonical list: {listed}"))
        .clone();
    assert_eq!(row["stage"], "done", "{row}");
    assert!(
        row["stage_changed_at"].is_string(),
        "the canonical list surface carries stage_changed_at next to stage: {row}"
    );
    assert_eq!(row["state"], "active", "{row}");

    // §5.3.3 rules 5-6 — the axis is single-sourced and its reserved
    // `metadata.fields.*` spellings are forbidden wire. A capability's
    // `allowed_write_fields` is matched against the patch's top-level keys, so
    // these `metadata`-rooted patches clear the capability gate and are refused
    // on shape.
    for patch in [
        serde_json::json!({ "metadata": { "fields": { "stage": "draft" } } }),
        serde_json::json!({
            "metadata": { "fields": { "stage_changed_at": "2030-01-01T00:00:00.000Z" } }
        }),
    ] {
        let forbidden = signed_strand_event(
            "ak:event:AbT8dnGCcqYbwZ0oR6t9NqW7yv5wOxKcT3sJvHYFvL4m",
            3,
            "ak.strand.update",
            serde_json::json!({ "target_ref": strand_id, "patch": patch }),
            vec![advance_event_id.as_str()],
        );
        let mut resp = TestClient::post("http://server/_arkret/self/events")
            .add_header("authorization", format!("Bearer {token}"), true)
            .json(&forbidden)
            .send(&app_from_state(state.clone()))
            .await;
        let body: Value = resp.take_json().await.unwrap();
        assert_eq!(
            problem_code(&body),
            "schema_violation",
            "reserved metadata.fields stage spellings are forbidden wire: {body}"
        );
    }

    // The canonical top-level paths are refused too. Which gate answers first
    // depends on the grant: `allowed_write_fields` is matched against the patch
    // root key, and this fixture's `ak.strand.update` grant covers `metadata`,
    // not `stage`, so admission stops here at the capability gate before the
    // forbidden-wire gate runs. Either refusal keeps the axis unwritable
    // through `ak.strand.update`; the shape gate itself is pinned directly by
    // the reducer test `strand_update_patch_on_the_stage_axis_is_refused`.
    for patch in [
        serde_json::json!({ "stage": "draft" }),
        serde_json::json!({ "stage_changed_at": "2030-01-01T00:00:00.000Z" }),
    ] {
        let forbidden = signed_strand_event(
            "ak:event:AbT8dnGCcqYbwZ0oR6t9NqW7yv5wOxKcT3sJvHYFvL4m",
            3,
            "ak.strand.update",
            serde_json::json!({ "target_ref": strand_id, "patch": patch }),
            vec![advance_event_id.as_str()],
        );
        let mut resp = TestClient::post("http://server/_arkret/self/events")
            .add_header("authorization", format!("Bearer {token}"), true)
            .json(&forbidden)
            .send(&app_from_state(state.clone()))
            .await;
        let body: Value = resp.take_json().await.unwrap();
        assert!(
            matches!(
                problem_code(&body),
                "capability_denied" | "schema_violation"
            ),
            "ak.strand.update must not carry the stage axis: {body}"
        );
    }
    let unchanged = strand_view(&state, &strand_id);
    assert_eq!(unchanged["stage"], "done", "{unchanged}");
    assert_eq!(
        unchanged["stage_changed_at"], after["stage_changed_at"],
        "a refused patch leaves the reducer-derived timestamp alone: {unchanged}"
    );

    // §5.3.3 rule 2 — advancing an archived object fails closed; the Strand has
    // to be restored first.
    let archive = signed_strand_event(
        "ak:event:AcM5Zt1uKpQ2Wj7XeNrBvL9oYdSaCgHkTFm3XbPzQwRn",
        3,
        "ak.strand.archive",
        serde_json::json!({ "strand_id": strand_id }),
        vec![advance_event_id.as_str()],
    );
    let archive_event_id = authored_event_id(&archive).to_string();
    let resp: Value = TestClient::post("http://server/_arkret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&archive)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(resp["status"], "accepted", "{resp}");

    let on_archived = signed_strand_event(
        "ak:event:AdN6auH2LqR3Xk8YfOscWmA0ZeTbDhIlUGn4YcQ0RxSo",
        4,
        "ak.strand.stage.set",
        serde_json::json!({ "strand_id": strand_id, "stage": "in_progress" }),
        vec![archive_event_id.as_str()],
    );
    let mut resp = TestClient::post("http://server/_arkret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&on_archived)
        .send(&app_from_state(state.clone()))
        .await;
    let body: Value = resp.take_json().await.unwrap();
    assert_eq!(problem_code(&body), "failed_precondition", "{body}");
    assert_eq!(body["reason_code"], "strand_not_active", "{body}");
    let still_done = strand_view(&state, &strand_id);
    assert_eq!(still_done["stage"], "done", "{still_done}");
}

#[test]
fn morph_stage_set_writes_the_same_axis_as_strand() {
    run_on_deep_stack(
        "morph_stage_set_writes_the_same_axis_as_strand",
        morph_stage_set_writes_the_same_axis_as_strand_body,
    );
}

/// `ak.morph.stage.set` is the Morph half of the same contract
/// (`common-fields.md` §5.3.1): same eight values, same reducer-derived
/// timestamp, same absence of a direction rule.
async fn morph_stage_set_writes_the_same_axis_as_strand_body() {
    let state = soland_test_support::app_state(test_config());
    let token = dev_token(state.clone()).await;
    seed_demo_realm_basis(&state).await;

    let create = signed_morph_event(
        "ak:event:AeP7bvI3MrS4Yl9ZgPtdXnB1AfUcEiJmVHo5ZdR1SyTp",
        1,
        "ak.morph.create",
        serde_json::json!({
            "object": {
                "realm_id": demo_realm_id(),
                "morph_kind": "task",
                "metadata": { "title": "Backfill" },
                "stage": "planned",
                "created_by": fixture_account_actor(&state, "did:web:alice.example"),
            }
        }),
        Vec::new(),
    );
    let morph_id = authored_morph_id(&create).to_string();
    let create_event_id = authored_event_id(&create).to_string();
    let resp: Value = TestClient::post("http://server/_arkret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&create)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(resp["status"], "accepted", "{resp}");

    {
        let projection = state.test_projection().lock();
        let morph = projection.morphs.get(&morph_id).expect("morph projected");
        assert_eq!(morph.stage, Some(arkret_wire::ObjectStage::Planned));
        assert_eq!(morph.stage_changed_at, None);
    }

    let advance = signed_morph_event(
        "ak:event:AfQ8cwJ4NsT5Zm0AhQueYoC2BgVdFjKnWIp6AeS2TzUq",
        2,
        "ak.morph.stage.set",
        serde_json::json!({ "morph_id": morph_id, "stage": "done" }),
        vec![create_event_id.as_str()],
    );
    let resp: Value = TestClient::post("http://server/_arkret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&advance)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(resp["status"], "accepted", "{resp}");

    {
        let projection = state.test_projection().lock();
        let morph = projection.morphs.get(&morph_id).expect("morph projected");
        assert_eq!(morph.stage, Some(arkret_wire::ObjectStage::Done));
        assert!(
            morph.stage_changed_at.is_some(),
            "a real Morph transition writes the reducer-derived timestamp"
        );
        assert_eq!(
            morph.state,
            soland_domain::reducer::ObjectLifecycleState::Active,
            "stage=done must not archive the Morph"
        );
    }

    // The Morph half of ruling 2026-09-05-2030: same cluster, same carrier.
    let listed: Value = TestClient::get(format!(
        "http://server/_arkret/self/realms/{}/morphs",
        demo_realm_id()
    ))
    .add_header("authorization", format!("Bearer {token}"), true)
    .send(&app_from_state(state.clone()))
    .await
    .take_json()
    .await
    .unwrap();
    let row = listed["morphs"]
        .as_array()
        .expect("canonical Morph list")
        .iter()
        .find(|row| row["morph_id"] == morph_id.as_str())
        .unwrap_or_else(|| panic!("Morph missing from the canonical list: {listed}"))
        .clone();
    assert_eq!(row["stage"], "done", "{row}");
    assert!(
        row["stage_changed_at"].is_string(),
        "the canonical list surface carries stage_changed_at next to stage: {row}"
    );
    assert_eq!(row["state"], "active", "{row}");
}
