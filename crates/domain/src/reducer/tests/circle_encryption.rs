use super::*;

fn apply_policy_bundle(
    state: &mut ProjectionState,
    hlc: &ServerHlc,
    realm: &str,
    mut payload: serde_json::Value,
) -> ProjectionEffect {
    let next_revision = state
        .realm_policy_bundle_cell_value(realm)
        .and_then(|value| value.get("policy_revision"))
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0)
        + 1;
    payload
        .as_object_mut()
        .expect("policy bundle fixture is an object")
        .insert(
            "policy_revision".to_owned(),
            serde_json::json!(next_revision),
        );
    state.apply(
        &make_operation(arkret_wire::EventKind::REALM_POLICY_BUNDLE, realm, payload),
        hlc,
    )
}

// ── AKP-0007 §8 — Circle member one-way add authorization ───────────
//
// Seed a Realm with `alice` (manage holder) + `bob` joined, plus a
// non-member `mallory`, and an `invite`-rule Circle. Exercise the reducer's
// fail-closed second-line check directly.

fn seed_circle_authz_state() -> (ProjectionState, ServerHlc, String, String) {
    let realm = "ak:realm:ASk_eoIHpJ8N_FKjxDcSCUURWkTNTCM3Ry9G5DEyb2gX".to_owned();
    let circle = "ak:circle:AUiSHUfqumU5_UtRrOIga2jjSmucw5MpSQdam3TtzPQu".to_owned();
    let mut state = ProjectionState::new();
    let now = chrono::Utc::now();
    let join_member = |state: &mut ProjectionState, did: &str| {
        state.members.insert(
            (realm.clone(), did.to_owned()),
            SolandMembershipState {
                member: did.to_owned(),
                realm_id: realm.clone(),
                state: "join".to_owned(),
                role: "member".to_owned(),
                delivery_status: None,
                recipient_service_id: None,
                membership_event_ref: None,
                delivery_binding_frontier: None,
                invited_at: None,
                joined_at: now,
                updated_at: now,
                reason: None,
            },
        );
    };
    join_member(&mut state, "did:web:alice");
    join_member(&mut state, "did:web:bob");
    // mallory is intentionally NOT a Realm member.
    state.circles.insert(
        circle.clone(),
        CircleProjection {
            circle_id: circle.clone(),
            realm_id: realm.clone(),
            profile_ref: None,
            title: "Ops".to_owned(),
            summary: None,
            display: serde_json::json!({"short_name":"Ops","color_token":"slate","symbol":{"glyph":"ring"}}),
            directory_visibility: "members".to_owned(),
            join_rule: "invite".to_owned(),
            history_visibility: "joined".to_owned(),
            content_encryption_floor: None,
            metadata_encryption_floor: None,
            encryption_profile: "mls_rfc9420".to_owned(),
            mls_group_ref: None,
            state: CircleLifecycleState::Active,
            state_changed_at: None,
            created_by: "did:web:alice".to_owned(),
            created_at: now,
            updated_by: None,
            updated_at: None,
            members: BTreeSet::new(),
        },
    );
    (state, ServerHlc::new("test"), realm, circle)
}

#[test]
fn circle_manage_pull_realm_member_succeeds() {
    // alice holds `ak.circle.member.manage` (verdict stamped by the HTTP
    // surface). She pulls the already-joined Realm member bob into the
    // Circle; bob performs no action and lands in `members` immediately.
    let (mut state, hlc, realm, circle) = seed_circle_authz_state();
    let op = make_operation(
        arkret_wire::EventKind::CIRCLE_MEMBER_STATE,
        &realm,
        serde_json::json!({
            "circle_id": circle,
            "actor_id": "did:web:bob",
            "membership": "join",
            "sender": "did:web:alice",
            "manage_capability_verified": true,
        }),
    );
    let effect = state.apply(&op, &hlc);
    assert!(
        matches!(effect, ProjectionEffect::CircleMemberStateChanged { .. }),
        "manage-backed pull should be accepted, got {effect:?}"
    );
    assert!(
        state.circles[&circle].members.contains("did:web:bob"),
        "bob must be an active Circle member with no accept step"
    );
}

#[test]
fn circle_pull_without_manage_rejected() {
    // alice attempts to pull bob in WITHOUT a stamped manage verdict
    // (e.g. the HTTP gate was bypassed). The reducer fails closed.
    let (mut state, hlc, realm, circle) = seed_circle_authz_state();
    let op = make_operation(
        arkret_wire::EventKind::CIRCLE_MEMBER_STATE,
        &realm,
        serde_json::json!({
            "circle_id": circle,
            "actor_id": "did:web:bob",
            "membership": "join",
            "sender": "did:web:alice",
        }),
    );
    assert!(
        matches!(
            state.apply(&op, &hlc),
            ProjectionEffect::Rejected { reason }
                if reason == CIRCLE_MEMBER_MANAGE_CAPABILITY_REQUIRED
        ),
        "cross-actor add without manage capability must be rejected"
    );
    assert!(!state.circles[&circle].members.contains("did:web:bob"));
}

#[test]
fn circle_pull_non_realm_member_rejected() {
    // Even with a valid manage verdict, pulling a non-Realm member in
    // violates the strict-subset invariant.
    let (mut state, hlc, realm, circle) = seed_circle_authz_state();
    let op = make_operation(
        arkret_wire::EventKind::CIRCLE_MEMBER_STATE,
        &realm,
        serde_json::json!({
            "circle_id": circle,
            "actor_id": "did:web:mallory",
            "membership": "join",
            "sender": "did:web:alice",
            "manage_capability_verified": true,
        }),
    );
    assert!(
        matches!(
            state.apply(&op, &hlc),
            ProjectionEffect::Rejected { reason }
                if reason == "circle_member_must_be_realm_member"
        ),
        "non-Realm member must be rejected regardless of manage capability"
    );
}

#[test]
fn circle_self_join_requires_open_rule() {
    // bob self-joins an `invite`-rule Circle without manage → rejected; an
    // explicit manage verdict can authorize self-add on a non-open Circle; an
    // `open` Circle lets a joined Realm member add themselves with no manage
    // capability.
    let (mut state, hlc, realm, circle) = seed_circle_authz_state();
    let op_invite = make_operation(
        arkret_wire::EventKind::CIRCLE_MEMBER_STATE,
        &realm,
        serde_json::json!({
            "circle_id": circle, "actor_id": "did:web:bob",
            "membership": "join", "sender": "did:web:bob",
        }),
    );
    assert!(
        matches!(
            state.apply(&op_invite, &hlc),
            ProjectionEffect::Rejected { reason } if reason == CIRCLE_JOIN_NOT_OPEN
        ),
        "self-join on a non-open Circle must be rejected"
    );
    let op_invite_with_manage = make_operation(
        arkret_wire::EventKind::CIRCLE_MEMBER_STATE,
        &realm,
        serde_json::json!({
            "circle_id": circle, "actor_id": "did:web:alice",
            "membership": "join", "sender": "did:web:alice",
            "manage_capability_verified": true,
        }),
    );
    assert!(
        matches!(
            state.apply(&op_invite_with_manage, &hlc),
            ProjectionEffect::CircleMemberStateChanged { .. }
        ),
        "self-join on a non-open Circle must be accepted with explicit manage"
    );
    assert!(state.circles[&circle].members.contains("did:web:alice"));
    // Flip the Circle to open and retry.
    state.circles.get_mut(&circle).unwrap().join_rule = "public".to_owned();
    let op_open = make_operation(
        arkret_wire::EventKind::CIRCLE_MEMBER_STATE,
        &realm,
        serde_json::json!({
            "circle_id": circle, "actor_id": "did:web:bob",
            "membership": "join", "sender": "did:web:bob",
        }),
    );
    assert!(
        matches!(
            state.apply(&op_open, &hlc),
            ProjectionEffect::CircleMemberStateChanged { .. }
        ),
        "self-join on an open Circle must be accepted"
    );
    assert!(state.circles[&circle].members.contains("did:web:bob"));
}

// AKP — encryption-floor one-way ratchet (realm-and-space.md §2.5,
// circle.md §7). Vectors: ak.vector.e2ee.content_floor_downgrade_rejected,
// ak.vector.e2ee.metadata_floor_downgrade_rejected, ak.vector.e2ee.in_place_enable.
#[test]
fn content_floor_ratchet_allows_upgrade_then_rejects_downgrade() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let realm = "ak:realm:Adf3DLZoUazXJZ2LuNbfkSARy3KNCMJc9FAdPevb2Quf";
    let apply_floor = |state: &mut ProjectionState, floor: Option<&str>| {
        let payload = match floor {
            Some(f) => serde_json::json!({ "content_encryption_floor": f }),
            None => serde_json::json!({}),
        };
        apply_policy_bundle(state, &hlc, realm, payload)
    };
    // baseline allow_plaintext -> projected
    assert!(matches!(
        apply_floor(&mut state, Some("allow_plaintext")),
        ProjectionEffect::RealmPolicyBundleProjected { .. }
    ));
    // in-place enable: allow_plaintext -> e2ee_required is accepted
    assert!(matches!(
        apply_floor(&mut state, Some("e2ee_required")),
        ProjectionEffect::RealmPolicyBundleProjected { .. }
    ));
    // downgrade e2ee_required -> allow_plaintext is rejected
    assert!(matches!(
        apply_floor(&mut state, Some("allow_plaintext")),
        ProjectionEffect::Rejected { reason } if reason == arkret_wire::ReasonCode::CONTENT_ENCRYPTION_FLOOR_DOWNGRADE
    ));
    // dropping the floor by omission is also a downgrade
    assert!(matches!(
        apply_floor(&mut state, None),
        ProjectionEffect::Rejected { reason } if reason == arkret_wire::ReasonCode::CONTENT_ENCRYPTION_FLOOR_DOWNGRADE
    ));
}

#[test]
fn metadata_floor_ratchet_rejects_downgrade() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let realm = "ak:realm:ASsEoTdZTKBwj6I0KNzFzWw0bfaKHScCL8uIPwx33cH8";
    let apply_meta = |state: &mut ProjectionState, level: &str| {
        apply_policy_bundle(
            state,
            &hlc,
            realm,
            serde_json::json!({ "metadata_encryption_floor": level }),
        )
    };
    assert!(matches!(
        apply_meta(&mut state, "e2ee_required"),
        ProjectionEffect::RealmPolicyBundleProjected { .. }
    ));
    // tightening to the same level is fine; lowering is rejected
    assert!(matches!(
        apply_meta(&mut state, "allow_plaintext"),
        ProjectionEffect::Rejected { reason } if reason == arkret_wire::ReasonCode::METADATA_ENCRYPTION_FLOOR_DOWNGRADE
    ));
}

// realm-and-space.md history-sharing — one-way `content_scheme` ratchet.
// `mls_rfc9420` < `mls_exporter_aead_v1`; once the realm negotiates the
// exporter-AEAD scheme it MUST NOT fall back to the application-message scheme.
#[test]
fn content_scheme_ratchet_allows_upgrade_then_rejects_downgrade() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let realm = "ak:realm:ASReu6ls3Ao5vTK0TGXBCAvLLQChFejCEmN9KaSceZOt";
    let apply_scheme = |state: &mut ProjectionState, scheme: Option<&str>| {
        let payload = match scheme {
            Some(s) => serde_json::json!({ "content_scheme": s }),
            None => serde_json::json!({}),
        };
        apply_policy_bundle(state, &hlc, realm, payload)
    };
    // baseline mls_rfc9420 -> projected
    assert!(matches!(
        apply_scheme(&mut state, Some("mls_rfc9420")),
        ProjectionEffect::RealmPolicyBundleProjected { .. }
    ));
    // upgrade rfc9420 -> exporter-aead is accepted
    assert!(matches!(
        apply_scheme(&mut state, Some("mls_exporter_aead_v1")),
        ProjectionEffect::RealmPolicyBundleProjected { .. }
    ));
    // re-asserting the same scheme is an idempotent no-op (accepted)
    assert!(matches!(
        apply_scheme(&mut state, Some("mls_exporter_aead_v1")),
        ProjectionEffect::RealmPolicyBundleProjected { .. }
    ));
    // downgrade exporter-aead -> rfc9420 is rejected
    assert!(matches!(
        apply_scheme(&mut state, Some("mls_rfc9420")),
        ProjectionEffect::Rejected { reason } if reason == CONTENT_SCHEME_DOWNGRADE
    ));
    // dropping the scheme by omission is also a downgrade
    assert!(matches!(
        apply_scheme(&mut state, None),
        ProjectionEffect::Rejected { reason } if reason == CONTENT_SCHEME_DOWNGRADE
    ));
}

// An unknown `content_scheme` enum value is rejected outright, even on a realm
// that has not yet committed to any scheme.
#[test]
fn content_scheme_rejects_unknown_value() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let realm = "ak:realm:AdX3Acd0WvYOiVl9-lqFGgGa8xxz2Z5P3Zcp5ply14zF";
    let effect = apply_policy_bundle(
        &mut state,
        &hlc,
        realm,
        serde_json::json!({ "content_scheme": "aes-gcm-siv-handrolled" }),
    );
    assert!(matches!(
        effect,
        ProjectionEffect::Rejected { reason } if reason == CONTENT_SCHEME_DOWNGRADE
    ));
}

#[test]
fn prejoin_history_rejects_strict_content_scheme_on_mls_realm() {
    use arkret_state::lattice::CellState;

    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("history-scheme");
    let realm = "ak:realm:AT7NHZtjTsuzRThBF8kLDDkl9394Uno1fO21jOiLjo-U";
    state.realm_create_cells.insert(
        realm.to_owned(),
        CellState::Value(serde_json::json!([{
            "encryption_profile": "mls_rfc9420",
            "history_visibility": "shared"
        }])),
    );
    assert_eq!(
        state.realm_encryption_profile(realm).as_deref(),
        Some("mls_rfc9420")
    );
    assert_eq!(
        state.realm_history_visibility(realm).as_deref(),
        Some("shared")
    );

    let effect = apply_policy_bundle(
        &mut state,
        &hlc,
        realm,
        serde_json::json!({ "content_scheme": "mls_rfc9420" }),
    );
    assert!(
        matches!(
            &effect,
            ProjectionEffect::Rejected { reason }
                if reason
                    == arkret_wire::ReasonCode::HISTORY_VISIBILITY_REQUIRES_HISTORY_CAPABLE_SCHEME
        ),
        "expected history/content-scheme rejection, got {effect:?}"
    );
}

#[test]
fn prejoin_history_accepts_exporter_aead_scheme_on_mls_realm() {
    use arkret_state::lattice::CellState;

    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("history-scheme-ok");
    let realm = "ak:realm:AQ5hB6Hsk2fZA-x-ErLhDAYuzeu8Y_gLzUPe2VZUa8Z8";
    state.realm_create_cells.insert(
        realm.to_owned(),
        CellState::Value(serde_json::json!([{
            "encryption_profile": "mls_rfc9420",
            "history_visibility": "shared"
        }])),
    );

    let effect = apply_policy_bundle(
        &mut state,
        &hlc,
        realm,
        serde_json::json!({ "content_scheme": "mls_exporter_aead_v1" }),
    );
    assert!(matches!(
        effect,
        ProjectionEffect::RealmPolicyBundleProjected { .. }
    ));
}

#[test]
fn content_scheme_falls_back_to_realm_create_log() {
    use arkret_state::lattice::CellState;

    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("history-scheme-create");
    let realm = "ak:realm:ATJpGWcxXQSxhpRxXI7xH5XTDhzIUCqOy5m6bXv454ge";
    state.realm_create_cells.insert(
        realm.to_owned(),
        CellState::Value(serde_json::json!([{
            "encryption_profile": "mls_rfc9420",
            "history_visibility": "shared",
            "content_scheme": "mls_exporter_aead_v1"
        }])),
    );

    assert_eq!(
        state.realm_content_scheme(realm).as_deref(),
        Some("mls_exporter_aead_v1")
    );
    let effect = apply_policy_bundle(
        &mut state,
        &hlc,
        realm,
        serde_json::json!({ "content_scheme": "mls_rfc9420" }),
    );
    assert!(matches!(
        effect,
        ProjectionEffect::Rejected { reason } if reason == CONTENT_SCHEME_DOWNGRADE
    ));
}

// realm-and-space.md §2.3.1 — `durability_policy.mode != none` is only valid on
// a `content_scheme=mls_exporter_aead_v1` realm. Declaring an org RRK on a realm
// that has not committed to the exporter-AEAD scheme MUST
// `durability_scheme_incompatible`.
#[test]
fn durability_policy_requires_exporter_aead_scheme() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("durability-scheme");
    let realm = "ak:realm:ARM_okyR4stVa2JmCJPyJcnwpoxsI3jimzSgJEra7UL0";
    let recipient = serde_json::json!({
        "recipient_id": "rrk-1",
        "principal_id": "did:web:hr.example",
        "verification_method": "did:web:hr.example#rrk-1"
    });
    // No scheme committed yet (defaults to mls_rfc9420) → incompatible.
    let effect = apply_policy_bundle(
        &mut state,
        &hlc,
        realm,
        serde_json::json!({
            "durability_policy": {
                "mode": "org_recovery_key",
                "recovery_recipients": [recipient]
            }
        }),
    );
    assert!(matches!(
        effect,
        ProjectionEffect::Rejected { reason } if reason == arkret_wire::ReasonCode::DURABILITY_SCHEME_INCOMPATIBLE
    ));
}

// A `durability_policy.mode != none` declared together with (or after) the
// `mls_exporter_aead_v1` scheme is accepted and projected.
#[test]
fn durability_policy_accepted_on_exporter_aead_scheme() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("durability-ok");
    let realm = "ak:realm:AcfJePA6div26qnIQkrT20tbJtdJ79JSjQFTRuB8pA7T";
    let recipient = serde_json::json!({
        "recipient_id": "rrk-1",
        "principal_id": "did:web:hr.example",
        "verification_method": "did:web:hr.example#rrk-1"
    });
    // Same-update set of scheme + durability policy is accepted.
    let effect = apply_policy_bundle(
        &mut state,
        &hlc,
        realm,
        serde_json::json!({
            "content_scheme": "mls_exporter_aead_v1",
            "durability_policy": {
                "mode": "org_recovery_key",
                "recovery_recipients": [recipient]
            }
        }),
    );
    assert!(matches!(
        effect,
        ProjectionEffect::RealmPolicyBundleProjected { .. }
    ));
    let projected = state
        .realm_durability_policy(realm)
        .expect("durability policy projected");
    assert!(matches!(
        projected.mode,
        arkret_models_collaboration::objects::realm::DurabilityMode::OrgRecoveryKey
    ));
    assert_eq!(projected.recovery_recipients.len(), 1);
}

// `mode != none` with an empty `recovery_recipients` array is structurally
// invalid → `durability_policy_invalid`.
#[test]
fn durability_policy_rejects_empty_recipients() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("durability-empty");
    let realm = "ak:realm:AQxJQaLWacjxt_NW7mRMxg7nFhvaLcCnmR-020-l4hIa";
    let effect = apply_policy_bundle(
        &mut state,
        &hlc,
        realm,
        serde_json::json!({
            "content_scheme": "mls_exporter_aead_v1",
            "durability_policy": {
                "mode": "org_recovery_key",
                "recovery_recipients": []
            }
        }),
    );
    assert!(matches!(
        effect,
        ProjectionEffect::Rejected { reason } if reason == DURABILITY_POLICY_INVALID
    ));
}

// `mode=threshold` requires `threshold.{k,n}` with `n == len(recovery_recipients)`.
#[test]
fn durability_policy_threshold_validates_k_of_n() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("durability-threshold");
    let realm = "ak:realm:AQxy0zXCpXmA_8kcoWOSePqrAA7vI9NsCp7RMO8ha6ak";
    let recipients = serde_json::json!([
        {"recipient_id": "rrk-1", "principal_id": "did:web:a.example", "verification_method": "did:web:a.example#rrk"},
        {"recipient_id": "rrk-2", "principal_id": "did:web:b.example", "verification_method": "did:web:b.example#rrk"}
    ]);
    // n=3 but only 2 recipients → invalid.
    let effect = apply_policy_bundle(
        &mut state,
        &hlc,
        realm,
        serde_json::json!({
            "content_scheme": "mls_exporter_aead_v1",
            "durability_policy": {
                "mode": "threshold",
                "recovery_recipients": recipients,
                "threshold": {"k": 2, "n": 3}
            }
        }),
    );
    assert!(matches!(
        effect,
        ProjectionEffect::Rejected { reason } if reason == DURABILITY_POLICY_INVALID
    ));
}
