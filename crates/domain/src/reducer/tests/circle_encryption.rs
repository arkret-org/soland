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
        &make_operation(arkret_wire::EventKind::RealmPolicyBundle, realm, payload),
        hlc,
    )
}

/// Seed an accepted MLS group Genesis whose governance binding freezes the
/// create-locked `content_scheme` / `durability_policy` pair
/// (realm-and-space.md sections 2.3 and 2.3.1). These two values live nowhere
/// else: the policy bundle cannot carry them.
fn seed_mls_genesis_with_binding(
    state: &mut ProjectionState,
    realm: &str,
    scope: arkret_wire::ScopeRef,
    content_scheme: Option<&str>,
    durability_policy: Option<&str>,
) {
    let group_id = scope.canonical_mls_group_id().unwrap();
    state.mls_commit_epochs.insert(
        MlsCommitEpochKey::new(realm, &group_id),
        MlsCommitEpoch {
            group_id: group_id.clone(),
            effective_scope: serde_json::to_value(&scope).unwrap(),
            epoch: 0,
            leader_actor_id: account_actor_string("ak:did_core:web:alice.example"),
            creator_device_id: "ak:device:01904100-0000-7000-8000-00000000c501".to_owned(),
            genesis_event_ref: "ak:event:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19".to_owned(),
            committed_at: 0,
            governance_binding: {
                let mut binding = serde_json::json!({
                    "realm_id": realm,
                    "mls_group_id": group_id,
                    "effective_scope": scope
                });
                let object = binding.as_object_mut().expect("binding object");
                if let Some(scheme) = content_scheme {
                    object.insert("content_scheme".to_owned(), serde_json::json!(scheme));
                }
                if let Some(policy) = durability_policy {
                    object.insert("durability_policy".to_owned(), serde_json::json!(policy));
                }
                binding
            },
            accepted_commit_digest: None,
            accepted_commit_ref: None,
            accepted_from_epoch: None,
            frontier_contested: false,
        },
    );
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
        let actor = account_actor_string(did);
        state.members.insert(
            (realm.clone(), actor.clone()),
            SolandMembershipState {
                member: actor,
                realm_id: realm.clone(),
                state: "join".to_owned(),
                role: "member".to_owned(),
                membership_event_ref: None,
                invited_at: None,
                joined_at: now,
                updated_at: now,
                reason: None,
            },
        );
    };
    join_member(&mut state, "ak:did_core:web:alice");
    join_member(&mut state, "ak:did_core:web:bob");
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
            history_access: "since_join".to_owned(),
            content_encryption_floor: None,
            metadata_encryption_floor: None,
            encryption_profile: "mls_rfc9420".to_owned(),
            content_scheme: Some("mls_rfc9420".to_owned()),
            durability_policy: None,
            mls_group_ref: None,
            state: CircleLifecycleState::Active,
            state_changed_at: None,
            created_by: account_actor_string("ak:did_core:web:alice"),
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
        arkret_wire::EventKind::CircleMemberState,
        &realm,
        serde_json::json!({
            "circle_id": circle,
            "member_id": account_actor("ak:did_core:web:bob"),
            "membership": "join",
            "sender": "ak:did_core:web:alice",
            "manage_capability_verified": true,
        }),
    );
    let effect = state.apply(&op, &hlc);
    assert!(
        matches!(effect, ProjectionEffect::CircleMemberStateChanged { .. }),
        "manage-backed pull should be accepted, got {effect:?}"
    );
    assert!(
        state.circles[&circle]
            .members
            .contains(&account_actor_string("ak:did_core:web:bob")),
        "bob must be an active Circle member with no accept step"
    );
}

#[test]
fn circle_pull_without_manage_rejected() {
    // alice attempts to pull bob in WITHOUT a stamped manage verdict
    // (e.g. the HTTP gate was bypassed). The reducer fails closed.
    let (mut state, hlc, realm, circle) = seed_circle_authz_state();
    let op = make_operation(
        arkret_wire::EventKind::CircleMemberState,
        &realm,
        serde_json::json!({
            "circle_id": circle,
            "member_id": account_actor("ak:did_core:web:bob"),
            "membership": "join",
            "sender": "ak:did_core:web:alice",
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
    assert!(
        !state.circles[&circle]
            .members
            .contains(&account_actor_string("ak:did_core:web:bob"))
    );
}

#[test]
fn circle_pull_non_realm_member_rejected() {
    // Even with a valid manage verdict, pulling a non-Realm member in
    // violates the strict-subset invariant.
    let (mut state, hlc, realm, circle) = seed_circle_authz_state();
    let op = make_operation(
        arkret_wire::EventKind::CircleMemberState,
        &realm,
        serde_json::json!({
            "circle_id": circle,
            "member_id": account_actor("ak:did_core:web:mallory"),
            "membership": "join",
            "sender": "ak:did_core:web:alice",
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
        arkret_wire::EventKind::CircleMemberState,
        &realm,
        serde_json::json!({
            "circle_id": circle, "member_id": account_actor("ak:did_core:web:bob"),
            "membership": "join", "sender": "ak:did_core:web:bob",
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
        arkret_wire::EventKind::CircleMemberState,
        &realm,
        serde_json::json!({
            "circle_id": circle, "member_id": account_actor("ak:did_core:web:alice"),
            "membership": "join", "sender": "ak:did_core:web:alice",
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
    assert!(
        state.circles[&circle]
            .members
            .contains(&account_actor_string("ak:did_core:web:alice"))
    );
    // Flip the Circle to open and retry.
    state.circles.get_mut(&circle).unwrap().join_rule = "public".to_owned();
    let op_open = make_operation(
        arkret_wire::EventKind::CircleMemberState,
        &realm,
        serde_json::json!({
            "circle_id": circle, "member_id": account_actor("ak:did_core:web:bob"),
            "membership": "join", "sender": "ak:did_core:web:bob",
        }),
    );
    assert!(
        matches!(
            state.apply(&op_open, &hlc),
            ProjectionEffect::CircleMemberStateChanged { .. }
        ),
        "self-join on an open Circle must be accepted"
    );
    assert!(
        state.circles[&circle]
            .members
            .contains(&account_actor_string("ak:did_core:web:bob"))
    );
}

#[test]
fn mls_circle_omitting_local_content_floor_inherits_parent_floor() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let realm = "ak:realm:AeJtxSuVLOh3OyPfR_18iXMUd0pL2wKdXB5RBZtF2u7Q";
    let now = chrono::Utc::now();
    state.realm_states.insert(
        realm.to_owned(),
        SolandRealmState {
            realm_id: realm.to_owned(),
            owner: Some(account_actor_string("ak:did_core:web:alice.example")),
            title: Some("Encrypted Realm".to_owned()),
            deleted: false,

            created_at: now,
            updated_at: now,
            trust_domain: None,
            terminal_state: None,
            successor_realm_id: None,
            default_strand_id: None,
        },
    );
    assert!(matches!(
        apply_policy_bundle(
            &mut state,
            &hlc,
            realm,
            serde_json::json!({"content_encryption_floor": "e2ee_required"}),
        ),
        ProjectionEffect::RealmPolicyBundleProjected { .. }
    ));

    let effect = state.apply(
        &make_operation(
            arkret_wire::EventKind::CircleCreate,
            realm,
            serde_json::json!({
                "object": {
                    "realm_id": realm,
                    "title": "Inherited floor",
                    "directory_visibility": "members",
                    "join_rule": "invite",
                    "history_access": "since_join",
                    "encryption_profile": "mls_rfc9420",
                    "content_scheme": "mls_rfc9420",
                    "created_by": account_actor("ak:did_core:web:alice.example"),
                    "created_at": now,
                }
            }),
        ),
        &hlc,
    );
    assert!(
        matches!(effect, ProjectionEffect::CircleLifecycle { .. }),
        "an omitted Circle-local floor inherits the e2ee parent floor: {effect:?}"
    );
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
            None => serde_json::json!({ "federation_policy": "open" }),
        };
        apply_policy_bundle(state, &hlc, realm, payload)
    };
    // baseline allow_plaintext -> projected
    let baseline = apply_floor(&mut state, Some("allow_plaintext"));
    assert!(
        matches!(
            baseline,
            ProjectionEffect::RealmPolicyBundleProjected { .. }
        ),
        "baseline policy projection failed: {baseline:?}"
    );
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
    let omitted = apply_floor(&mut state, None);
    assert!(
        matches!(
            omitted,
            ProjectionEffect::Rejected { ref reason } if reason == arkret_wire::ReasonCode::CONTENT_ENCRYPTION_FLOOR_DOWNGRADE
        ),
        "omitted content floor returned {omitted:?}"
    );
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

// realm-and-space.md §2.3 / §2.3.1 — `content_scheme` and `durability_policy`
// are frozen by the accepted MLS group Genesis and are read from the winning
// epoch tuple's governance binding, never from mutable policy state.
#[test]
fn content_scheme_and_durability_read_the_accepted_genesis_binding() {
    let mut state = ProjectionState::new();
    let realm = "ak:realm:AcfJePA6div26qnIQkrT20tbJtdJ79JSjQFTRuB8pA7T";
    assert_eq!(state.realm_content_scheme(realm), None);
    assert_eq!(state.realm_durability_policy(realm), None);

    seed_mls_genesis_with_binding(
        &mut state,
        realm,
        arkret_wire::ScopeRef::Realm {
            realm_id: arkret_identifiers::RealmId::new(realm.to_owned()).unwrap(),
        },
        Some("mls_exporter_aead_v1"),
        Some("organization_recovery_key"),
    );
    assert_eq!(
        state.realm_content_scheme(realm).as_deref(),
        Some("mls_exporter_aead_v1")
    );
    assert_eq!(
        state.realm_durability_policy(realm),
        Some(arkret_wire::DurabilityPolicy::OrganizationRecoveryKey)
    );
}

// A Circle group is independent: its own Genesis binding never becomes the
// parent Realm's effective scheme.
#[test]
fn a_circle_group_genesis_does_not_supply_the_realm_scheme() {
    let mut state = ProjectionState::new();
    let realm = "ak:realm:AQxJQaLWacjxt_NW7mRMxg7nFhvaLcCnmR-020-l4hIa";
    let circle = "ak:circle:ATOTi3sw4NO_6LjlHGedSYTeT3Leu2J3Tb49M1gn9cFN";
    seed_mls_genesis_with_binding(
        &mut state,
        realm,
        arkret_wire::ScopeRef::Circle {
            realm_id: arkret_identifiers::RealmId::new(realm.to_owned()).unwrap(),
            circle_id: arkret_identifiers::CircleId::new(circle.to_owned()).unwrap(),
        },
        Some("mls_exporter_aead_v1"),
        Some("organization_recovery_key"),
    );
    assert_eq!(state.realm_content_scheme(realm), None);
    assert_eq!(state.realm_durability_policy(realm), None);
}
