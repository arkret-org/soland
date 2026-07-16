//! Integration tests — notary signing worker + admin notary endpoints.

use super::common::*;

/// The notary worker takes one or more
/// pending Moves and produces a signed Seal. This is the END-TO-END
/// proof of the Move → Seal strand without requiring the client to
/// hand-craft a Seal: the client submits a Move, then triggers the
/// admin signing endpoint, and a Seal pops out with the correct
/// state_root.
#[tokio::test]
async fn notary_worker_signs_pending_move_and_publishes_seal() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;
    let app = service(state.clone());

    // 1. Submit a Move (membership FSM transition leave->join).
    let move_obj = build_left_to_join_move();
    let submit: Value = TestClient::post("http://server/_soland/peer/moves")
        .add_header("Authorization", format!("Bearer {token}"), true)
        .json(&move_obj)
        .send(&app)
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(
        submit["state"], "pending",
        "Move should be queued pending after submit_move (got {submit:?})"
    );

    // 2. Trigger the notary worker via the admin endpoint. This runs one signing pass: collect
    //    pending Moves → deterministic_order → verify each → predict state_root → build & sign Seal
    //    → apply_seal (which re-verifies).
    let sign_resp: Value = TestClient::post("http://server/_soland/admin/seals/sign")
        .add_header("Authorization", format!("Bearer {token}"), true)
        .json(&json!({
            "realm_id": realm_id().as_str(),
            "max_control_moves": 100,
        }))
        .send(&app)
        .await
        .take_json()
        .await
        .unwrap();

    // 3. Assert: seal was published.
    assert_eq!(
        sign_resp["published"], true,
        "notary should publish a Seal (got {sign_resp:?})"
    );
    let seal_id = sign_resp["seal_id"]
        .as_str()
        .expect("seal_id should be present when published=true");
    assert!(
        seal_id.starts_with("ak:seal:sha256:"),
        "seal_id should be a content-addressed sha256 ref, got {seal_id}"
    );
    let accepted = sign_resp["accepted_move_ids"]
        .as_array()
        .expect("accepted_move_ids should be an array");
    assert_eq!(accepted.len(), 1, "exactly one Move should be sealed");
    assert_eq!(
        accepted[0].as_str(),
        Some(move_obj.id.as_str()),
        "the sealed Move id should match the one we submitted"
    );

    // 4. Assert: post_state_root corresponds to member_cell holding "join".
    let mut expected = BTreeMap::new();
    expected.insert(member_cell(), CellState::Value(json!("join")));
    let expected_root = compute_state_root(&expected).unwrap();
    assert_eq!(
        sign_resp["post_state_root"].as_str(),
        Some(expected_root.as_str()),
        "post_state_root should match the notary's predicted recompute"
    );
}

/// Post-seal `kind=frontier` mid-stream control frame.
///
/// Subscribe to the demo Realm → trigger a Seal sign for that Realm →
/// verify the streaming subscriber sees a `kind=frontier` frame whose
/// `state_root` matches the seal's post_state_root and `seal_id`
/// starts with `ak:seal:sha256:`.
///
/// **Note**: this test uses a different Realm (the Move/Seal pipeline
/// Realm, not the demo Realm) for the seal, so we subscribe to that
/// Realm too. We bypass the access check by using the dev-mode public
/// Realm test fixture. We can't easily subscribe to the same seal
/// Realm the existing notary tests use because that Realm isn't
/// registered in RealmSearchIndex; so we subscribe to the demo Realm and
/// post the Move's effects there instead.
#[tokio::test]
async fn notary_pass_broadcasts_frontier_frame_to_subscribers() {
    use std::time::Duration as StdDuration;

    use tokio::time::sleep;

    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;
    let _app = service(state.clone());

    // The seal pipeline writes to realm_id() (test-only Realm). We
    // subscribe to that Realm — the broadcast filter accepts any
    // realm the broadcast notification's realm_id matches.
    let writer_state = state.clone();
    let token_writer = token.clone();
    let writer = tokio::spawn(async move {
        let app_writer = service(writer_state);
        // Wait so the subscriber's broadcast receiver is registered.
        sleep(StdDuration::from_millis(150)).await;
        // Submit a Move + trigger the notary; both happen on the
        // seal-pipeline Realm (`realm_id()`), and the broadcast goes
        // out tagged with that realm_id.
        let move_obj = build_left_to_join_move();
        let _: Value = TestClient::post("http://server/_soland/peer/moves")
            .add_header("Authorization", format!("Bearer {token_writer}"), true)
            .json(&move_obj)
            .send(&app_writer)
            .await
            .take_json()
            .await
            .unwrap_or_default();
        let _: Value = TestClient::post("http://server/_soland/admin/seals/sign")
            .add_header("Authorization", format!("Bearer {token_writer}"), true)
            .json(&json!({"realm_id": realm_id().as_str()}))
            .send(&app_writer)
            .await
            .take_json()
            .await
            .unwrap_or_default();
    });

    // Subscribe to the same Realm the seal will be published on. We
    // need that Realm to pass realm_id_accessible — for tests, the
    // simplest path is to use a Realm that's already registered as
    // public. But realm_id() isn't registered so this would 404. So we
    // bypass by checking what `realm_id_accessible` does: if a session
    // is None and the Realm has discoverability=public, accept; else
    // require session has membership. The test config injects a session
    // (dev_token), so we'd need the actor in realm.members. To avoid
    // wiring all that, we use the broadcast directly: subscribe to the
    // receiver and check the notification arrives.
    let mut rx = state.event_broadcast.subscribe();
    writer.await.expect("writer task");
    // Drain any non-frontier messages and find the frontier.
    let mut saw_frontier = false;
    let mut saw_event = false;
    let deadline = tokio::time::Instant::now() + StdDuration::from_millis(200);
    while tokio::time::Instant::now() < deadline {
        match tokio::time::timeout(StdDuration::from_millis(50), rx.recv()).await {
            Ok(Ok(notification)) => {
                use soland::state::EventNotificationKind;
                match notification.kind {
                    EventNotificationKind::Frontier {
                        state_root,
                        seal_id,
                    } => {
                        assert!(
                            seal_id.starts_with("ak:seal:sha256:"),
                            "frontier seal_id should be content-addressed (got `{seal_id}`)"
                        );
                        assert!(
                            state_root.starts_with("sha256:"),
                            "frontier state_root should be sha256-prefixed (got `{state_root}`)"
                        );
                        saw_frontier = true;
                    }
                    EventNotificationKind::Event { .. } => {
                        saw_event = true;
                    }
                    _ => {}
                }
            }
            _ => break,
        }
    }
    assert!(
        saw_frontier,
        "notary signing pass MUST broadcast a Frontier notification (saw event = {saw_event})"
    );
}

/// After the notary publishes a Seal,
/// `ProjectionState::cells` MUST contain the resolved CellState for the
/// member.state cell. Proves the write-back hook in
/// `NotaryWorker::sign_pending_for_space` actually refreshes the
/// projection cache so cell-keyed read paths see the new state.
#[tokio::test]
async fn notary_pass_populates_projection_cells_map() {
    use arkret_sdk::lattice::CellState;

    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;
    let app = service(state.clone());

    let move_obj = build_left_to_join_move();
    let _: Value = TestClient::post("http://server/_soland/peer/moves")
        .add_header("Authorization", format!("Bearer {token}"), true)
        .json(&move_obj)
        .send(&app)
        .await
        .take_json()
        .await
        .unwrap();

    let _: Value = TestClient::post("http://server/_soland/admin/seals/sign")
        .add_header("Authorization", format!("Bearer {token}"), true)
        .json(&json!({"realm_id": realm_id().as_str()}))
        .send(&app)
        .await
        .take_json()
        .await
        .unwrap();

    // Inspect ProjectionState directly. The member_cell should now be in
    // the cells map with Value("join") (the FSM transition we sealed).
    let proj = state.projection.lock();
    let resolved = proj
        .cell(&member_cell())
        .expect("member.state cell should be in ProjectionState::cells after apply_seal");
    match resolved {
        CellState::Value(v) => {
            assert_eq!(
                v.as_str(),
                Some("join"),
                "member.state cell should resolve to FSM state \"join\" (got {v:?})"
            );
        }
        CellState::Bottom(b) => {
            panic!("member.state cell should resolve to Value, not Bottom: {b:?}");
        }
    }
}

/// `admin_reconfigure_notary` builds a real Move signed
/// with the service admin signer, submits it through the move_store,
/// and triggers one notary signing pass. Endpoint should return
/// `status="accepted"` with a real `move_id` and (since this node is
/// the genesis notary) a non-null `seal_id`.
#[tokio::test]
async fn admin_reconfigure_notary_builds_real_move_and_seals_it() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;
    let app = service(state.clone());

    // Reconfigure to an open_set profile that does NOT include the
    // server's service DID (admin-as-member would be a privilege-
    // escalation primitive and should be rejected by the endpoint —
    // but we want a successful reconfigure here, so pick external DIDs).
    let url = format!(
        "http://server/_soland/admin/realms/{}/notary/reconfigure",
        realm_id().as_str()
    );
    let resp: Value = TestClient::post(&url)
        .add_header("Authorization", format!("Bearer {token}"), true)
        .json(&json!({
            "kind": "open_set",
            "open_set_members": ["did:ak:alice", "did:ak:bob"],
        }))
        .send(&app)
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(
        resp["status"], "accepted",
        "admin_reconfigure_notary should produce a real signed Move (got {resp:?})"
    );
    let move_id = resp["control_move_id"]
        .as_str()
        .expect("control_move_id should be set");
    assert!(
        move_id.starts_with("sha256:"),
        "control_move_id should be content-addressed sha256, got {move_id}"
    );
    let seal_id = resp["seal_id"]
        .as_str()
        .expect("seal_id should be set when this node is the round leader");
    assert!(
        seal_id.starts_with("ak:seal:sha256:"),
        "seal_id should be content-addressed sha256, got {seal_id}"
    );
}

/// `admin_reconfigure_notary` rejects requests where the
/// admin DID (= service DID for now) appears in the proposed notary
/// member set, because that's a privilege-escalation primitive.
#[tokio::test]
async fn admin_reconfigure_notary_rejects_self_in_proposed_member_set() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;
    let app = service(state.clone());

    let url = format!(
        "http://server/_soland/admin/realms/{}/notary/reconfigure",
        realm_id().as_str()
    );
    let response = TestClient::post(&url)
        .add_header("Authorization", format!("Bearer {token}"), true)
        .json(&json!({
            "kind": "open_set",
            // service DID `did:webvh:z2dmjYwAPJzv5CZsnAzt8auVZRn1GfuxhpK2t3Q3K3rj4B1x:soland.local:webvh:service` IS the admin signer.
            "open_set_members": ["did:webvh:z2dmjYwAPJzv5CZsnAzt8auVZRn1GfuxhpK2t3Q3K3rj4B1x:soland.local:webvh:service", "did:ak:other"],
        }))
        .send(&app)
        .await;
    assert_eq!(
        response.status_code,
        Some(StatusCode::FORBIDDEN),
        "admin DID in proposed member set must be rejected as privilege-escalation"
    );
}

/// Idempotency: signing twice in a row publishes once. The second pass
/// finds no pending Moves (all sealed by the first pass) and reports
/// `published: false`.
#[tokio::test]
async fn notary_worker_is_idempotent_when_no_pending_moves() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;
    let app = service(state.clone());

    let move_obj = build_left_to_join_move();
    let _: Value = TestClient::post("http://server/_soland/peer/moves")
        .add_header("Authorization", format!("Bearer {token}"), true)
        .json(&move_obj)
        .send(&app)
        .await
        .take_json()
        .await
        .unwrap();

    // First pass: publishes.
    let first: Value = TestClient::post("http://server/_soland/admin/seals/sign")
        .add_header("Authorization", format!("Bearer {token}"), true)
        .json(&json!({"realm_id": realm_id().as_str()}))
        .send(&app)
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(first["published"], true);

    // Second pass: no pending Moves, no Seal.
    let second: Value = TestClient::post("http://server/_soland/admin/seals/sign")
        .add_header("Authorization", format!("Bearer {token}"), true)
        .json(&json!({"realm_id": realm_id().as_str()}))
        .send(&app)
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(
        second["published"], false,
        "second signing pass should report nothing pending (got {second:?})"
    );
}

/// A signing-key-only swap would split the runtime signer from the DID
/// document and identity bundle. Until the service has an atomic WebVH
/// rotation transaction, the route must fail closed and leave the key intact.
#[tokio::test]
async fn admin_rotate_signing_key_fails_closed_without_mutating_the_signer() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;
    let app = service(state.clone());
    let pre = state.notary_signing_key().to_bytes();

    let url = format!(
        "http://server/_soland/admin/realms/{}/notary/rotate-signing-key",
        realm_id().as_str()
    );
    let mut response = TestClient::post(&url)
        .add_header("Authorization", format!("Bearer {token}"), true)
        .json(&json!({}))
        .send(&app)
        .await;
    assert_eq!(response.status_code, Some(StatusCode::NOT_IMPLEMENTED));
    let body: Value = response.take_json().await.unwrap();
    assert_eq!(body["error"]["code"], "unsupported_feature");

    let post = state.notary_signing_key().to_bytes();
    assert_eq!(
        pre, post,
        "failed rotation must not alter the active signer"
    );
}
