use super::*;
use crate::reducer::*;

// ── CKP-0007 §8 — Circle member one-way add authorization ───────────
//
// Seed a Realm with `alice` (manage holder) + `bob` joined, plus a
// non-member `mallory`, and an `invite`-rule Circle. Exercise the reducer's
// fail-closed second-line check directly.

fn seed_circle_authz_state() -> (ProjectionState, ServerHlc, String, String) {
    let realm = "ak:realm:01904100-0000-7000-8000-c1c1c1c1c1c1".to_owned();
    let circle = "ak:circle:01904100-0000-7000-8000-aaaaaaaaaaaa".to_owned();
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
                recipient_service_did: None,
                membership_event_ref: None,
                delivery_binding_frontier: None,
                invited_at: None,
                joined_at: now,
                updated_at: now,
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
            title: "Ops".to_owned(),
            summary: None,
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
    // alice holds `ck.circle.member.manage` (verdict stamped by the HTTP
    // surface). She pulls the already-joined Realm member bob into the
    // Circle; bob performs no action and lands in `members` immediately.
    let (mut state, hlc, realm, circle) = seed_circle_authz_state();
    let op = make_operation(
        arkret_sdk::events::kinds::CIRCLE_MEMBER_STATE,
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
        arkret_sdk::events::kinds::CIRCLE_MEMBER_STATE,
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
        arkret_sdk::events::kinds::CIRCLE_MEMBER_STATE,
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
        arkret_sdk::events::kinds::CIRCLE_MEMBER_STATE,
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
        arkret_sdk::events::kinds::CIRCLE_MEMBER_STATE,
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
    state.circles.get_mut(&circle).unwrap().join_rule = "open".to_owned();
    let op_open = make_operation(
        arkret_sdk::events::kinds::CIRCLE_MEMBER_STATE,
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

// CKP — encryption-floor one-way ratchet (realm-and-space.md §2.5,
// circle.md §7). Vectors: ak.vector.e2ee.content_floor_downgrade_rejected,
// ak.vector.e2ee.metadata_floor_downgrade_rejected, ak.vector.e2ee.in_place_enable.
#[test]
fn content_floor_ratchet_allows_upgrade_then_rejects_downgrade() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let realm = "ak:realm:01904100-0000-7000-8000-cfc039892061";
    let apply_floor = |state: &mut ProjectionState, floor: Option<&str>| {
        let payload = match floor {
            Some(f) => serde_json::json!({ "content_encryption_floor": f }),
            None => serde_json::json!({}),
        };
        state.apply(
            &make_operation(
                arkret_sdk::events::kinds::REALM_POLICY_COMPONENTS,
                realm,
                payload,
            ),
            &hlc,
        )
    };
    // baseline allow_plaintext -> projected
    assert!(matches!(
        apply_floor(&mut state, Some("allow_plaintext")),
        ProjectionEffect::RealmPolicyComponentsProjected { .. }
    ));
    // in-place enable: allow_plaintext -> e2ee_required is accepted
    assert!(matches!(
        apply_floor(&mut state, Some("e2ee_required")),
        ProjectionEffect::RealmPolicyComponentsProjected { .. }
    ));
    // downgrade e2ee_required -> allow_plaintext is rejected
    assert!(matches!(
        apply_floor(&mut state, Some("allow_plaintext")),
        ProjectionEffect::Rejected { reason } if reason == CONTENT_ENCRYPTION_FLOOR_DOWNGRADE
    ));
    // dropping the floor by omission is also a downgrade
    assert!(matches!(
        apply_floor(&mut state, None),
        ProjectionEffect::Rejected { reason } if reason == CONTENT_ENCRYPTION_FLOOR_DOWNGRADE
    ));
}

#[test]
fn metadata_floor_ratchet_rejects_downgrade() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let realm = "ak:realm:01904100-0000-7000-8000-cfc039892062";
    let apply_meta = |state: &mut ProjectionState, level: &str| {
        state.apply(
            &make_operation(
                arkret_sdk::events::kinds::REALM_POLICY_COMPONENTS,
                realm,
                serde_json::json!({ "metadata_encryption_floor": level }),
            ),
            &hlc,
        )
    };
    assert!(matches!(
        apply_meta(&mut state, "e2ee_required"),
        ProjectionEffect::RealmPolicyComponentsProjected { .. }
    ));
    // tightening to the same level is fine; lowering is rejected
    assert!(matches!(
        apply_meta(&mut state, "allow_plaintext"),
        ProjectionEffect::Rejected { reason } if reason == METADATA_ENCRYPTION_FLOOR_DOWNGRADE
    ));
}

// realm-and-space.md history-sharing — one-way `content_scheme` ratchet.
// `mls-rfc9420` < `mls-exporter-aead-v1`; once the realm negotiates the
// exporter-AEAD scheme it MUST NOT fall back to the application-message scheme.
#[test]
fn content_scheme_ratchet_allows_upgrade_then_rejects_downgrade() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let realm = "ak:realm:01904100-0000-7000-8000-cfc039892063";
    let apply_scheme = |state: &mut ProjectionState, scheme: Option<&str>| {
        let payload = match scheme {
            Some(s) => serde_json::json!({ "content_scheme": s }),
            None => serde_json::json!({}),
        };
        state.apply(
            &make_operation(
                arkret_sdk::events::kinds::REALM_POLICY_COMPONENTS,
                realm,
                payload,
            ),
            &hlc,
        )
    };
    // baseline mls-rfc9420 -> projected
    assert!(matches!(
        apply_scheme(&mut state, Some("mls-rfc9420")),
        ProjectionEffect::RealmPolicyComponentsProjected { .. }
    ));
    // upgrade rfc9420 -> exporter-aead is accepted
    assert!(matches!(
        apply_scheme(&mut state, Some("mls-exporter-aead-v1")),
        ProjectionEffect::RealmPolicyComponentsProjected { .. }
    ));
    // re-asserting the same scheme is an idempotent no-op (accepted)
    assert!(matches!(
        apply_scheme(&mut state, Some("mls-exporter-aead-v1")),
        ProjectionEffect::RealmPolicyComponentsProjected { .. }
    ));
    // downgrade exporter-aead -> rfc9420 is rejected
    assert!(matches!(
        apply_scheme(&mut state, Some("mls-rfc9420")),
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
    let realm = "ak:realm:01904100-0000-7000-8000-cfc039892064";
    let effect = state.apply(
        &make_operation(
            arkret_sdk::events::kinds::REALM_POLICY_COMPONENTS,
            realm,
            serde_json::json!({ "content_scheme": "aes-gcm-siv-handrolled" }),
        ),
        &hlc,
    );
    assert!(matches!(
        effect,
        ProjectionEffect::Rejected { reason } if reason == CONTENT_SCHEME_DOWNGRADE
    ));
}

#[test]
fn prejoin_history_rejects_strict_content_scheme_on_mls_realm() {
    use arkret_sdk::lattice::CellState;

    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("history-scheme");
    let realm = "ak:realm:01904100-0000-7000-8000-d0d0d0d0c001";
    let create_cell =
        arkret_sdk::CellRef::new(format!("ak:cell:ck.component.realm.create.v1:{realm}"))
            .expect("valid create cell ref");
    state.cells.insert(
        create_cell,
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

    let effect = state.apply(
        &make_operation(
            arkret_sdk::events::kinds::REALM_POLICY_COMPONENTS,
            realm,
            serde_json::json!({ "content_scheme": "mls-rfc9420" }),
        ),
        &hlc,
    );
    assert!(
        matches!(
            &effect,
            ProjectionEffect::Rejected { reason }
                if reason
                    == arkret_sdk::error::REASON_HISTORY_VISIBILITY_REQUIRES_HISTORY_CAPABLE_SCHEME
        ),
        "expected history/content-scheme rejection, got {effect:?}"
    );
}

#[test]
fn prejoin_history_accepts_exporter_aead_scheme_on_mls_realm() {
    use arkret_sdk::lattice::CellState;

    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("history-scheme-ok");
    let realm = "ak:realm:01904100-0000-7000-8000-d0d0d0d0c002";
    let create_cell =
        arkret_sdk::CellRef::new(format!("ak:cell:ck.component.realm.create.v1:{realm}"))
            .expect("valid create cell ref");
    state.cells.insert(
        create_cell,
        CellState::Value(serde_json::json!([{
            "encryption_profile": "mls_rfc9420",
            "history_visibility": "shared"
        }])),
    );

    let effect = state.apply(
        &make_operation(
            arkret_sdk::events::kinds::REALM_POLICY_COMPONENTS,
            realm,
            serde_json::json!({ "content_scheme": "mls-exporter-aead-v1" }),
        ),
        &hlc,
    );
    assert!(matches!(
        effect,
        ProjectionEffect::RealmPolicyComponentsProjected { .. }
    ));
}

#[test]
fn content_scheme_falls_back_to_realm_create_log() {
    use arkret_sdk::lattice::CellState;

    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("history-scheme-create");
    let realm = "ak:realm:01904100-0000-7000-8000-d0d0d0d0c012";
    let create_cell =
        arkret_sdk::CellRef::new(format!("ak:cell:ck.component.realm.create.v1:{realm}"))
            .expect("valid create cell ref");
    state.cells.insert(
        create_cell,
        CellState::Value(serde_json::json!([{
            "encryption_profile": "mls_rfc9420",
            "history_visibility": "shared",
            "content_scheme": "mls-exporter-aead-v1"
        }])),
    );

    assert_eq!(
        state.realm_content_scheme(realm).as_deref(),
        Some("mls-exporter-aead-v1")
    );
    let effect = state.apply(
        &make_operation(
            arkret_sdk::events::kinds::REALM_POLICY_COMPONENTS,
            realm,
            serde_json::json!({ "content_scheme": "mls-rfc9420" }),
        ),
        &hlc,
    );
    assert!(matches!(
        effect,
        ProjectionEffect::Rejected { reason } if reason == CONTENT_SCHEME_DOWNGRADE
    ));
}

// realm-and-space.md §2.3.1 — `durability_policy.mode != none` is only valid on
// a `content_scheme=mls-exporter-aead-v1` realm. Declaring an org RRK on a realm
// that has not committed to the exporter-AEAD scheme MUST
// `durability_scheme_incompatible`.
#[test]
fn durability_policy_requires_exporter_aead_scheme() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("durability-scheme");
    let realm = "ak:realm:01904100-0000-7000-8000-d0d0d0d0d001";
    let recipient = serde_json::json!({
        "recipient_id": "rrk-1",
        "principal_id": "did:web:hr.example",
        "verification_method": "did:web:hr.example#rrk-1"
    });
    // No scheme committed yet (defaults to mls-rfc9420) → incompatible.
    let effect = state.apply(
        &make_operation(
            arkret_sdk::events::kinds::REALM_POLICY_COMPONENTS,
            realm,
            serde_json::json!({
                "durability_policy": {
                    "mode": "org_recovery_key",
                    "recovery_recipients": [recipient]
                }
            }),
        ),
        &hlc,
    );
    assert!(matches!(
        effect,
        ProjectionEffect::Rejected { reason } if reason == DURABILITY_SCHEME_INCOMPATIBLE
    ));
}

// A `durability_policy.mode != none` declared together with (or after) the
// `mls-exporter-aead-v1` scheme is accepted and projected.
#[test]
fn durability_policy_accepted_on_exporter_aead_scheme() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("durability-ok");
    let realm = "ak:realm:01904100-0000-7000-8000-d0d0d0d0d002";
    let recipient = serde_json::json!({
        "recipient_id": "rrk-1",
        "principal_id": "did:web:hr.example",
        "verification_method": "did:web:hr.example#rrk-1"
    });
    // Same-update set of scheme + durability policy is accepted.
    let effect = state.apply(
        &make_operation(
            arkret_sdk::events::kinds::REALM_POLICY_COMPONENTS,
            realm,
            serde_json::json!({
                "content_scheme": "mls-exporter-aead-v1",
                "durability_policy": {
                    "mode": "org_recovery_key",
                    "recovery_recipients": [recipient]
                }
            }),
        ),
        &hlc,
    );
    assert!(matches!(
        effect,
        ProjectionEffect::RealmPolicyComponentsProjected { .. }
    ));
    let projected = state
        .realm_durability_policy(realm)
        .expect("durability policy projected");
    assert!(matches!(
        projected.mode,
        arkret_sdk::models::DurabilityMode::OrgRecoveryKey
    ));
    assert_eq!(projected.recovery_recipients.len(), 1);
}

// `mode != none` with an empty `recovery_recipients` array is structurally
// invalid → `durability_policy_invalid`.
#[test]
fn durability_policy_rejects_empty_recipients() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("durability-empty");
    let realm = "ak:realm:01904100-0000-7000-8000-d0d0d0d0d003";
    let effect = state.apply(
        &make_operation(
            arkret_sdk::events::kinds::REALM_POLICY_COMPONENTS,
            realm,
            serde_json::json!({
                "content_scheme": "mls-exporter-aead-v1",
                "durability_policy": {
                    "mode": "org_recovery_key",
                    "recovery_recipients": []
                }
            }),
        ),
        &hlc,
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
    let realm = "ak:realm:01904100-0000-7000-8000-d0d0d0d0d004";
    let recipients = serde_json::json!([
        {"recipient_id": "rrk-1", "principal_id": "did:web:a.example", "verification_method": "did:web:a.example#rrk"},
        {"recipient_id": "rrk-2", "principal_id": "did:web:b.example", "verification_method": "did:web:b.example#rrk"}
    ]);
    // n=3 but only 2 recipients → invalid.
    let effect = state.apply(
        &make_operation(
            arkret_sdk::events::kinds::REALM_POLICY_COMPONENTS,
            realm,
            serde_json::json!({
                "content_scheme": "mls-exporter-aead-v1",
                "durability_policy": {
                    "mode": "threshold",
                    "recovery_recipients": recipients,
                    "threshold": {"k": 2, "n": 3}
                }
            }),
        ),
        &hlc,
    );
    assert!(matches!(
        effect,
        ProjectionEffect::Rejected { reason } if reason == DURABILITY_POLICY_INVALID
    ));
}
