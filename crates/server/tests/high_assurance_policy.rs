//! Integration tests for R3.4 — `security_class=high_assurance` Realm
//! policy enforcement.
//!
//! A Realm declared with `security_class=high_assurance` MUST keep
//! `federation_policy ∈ {closed, restricted, quarantine}`. Any update
//! that tries to set `federation_policy=open` MUST be rejected with
//! `high_assurance_federation_policy_invalid`.
//!
//! These tests drive the reducer directly so they stay focused on the
//! policy guard; the HTTP path that submits these events runs through
//! the standard event-log ingestion in `tests/http_api/`.

use arkret_sdk::Operation;
use serde_json::{Value, json};
use soland::hlc::ServerHlc;
use soland::reducer::{ProjectionEffect, ProjectionState};

const REALM_HA: &str = "ak:realm:01904100-0000-7000-8000-aaaaaaaaaaaa";
const REALM_STANDARD: &str = "ak:realm:01904100-0000-7000-8000-bbbbbbbbbbbb";

fn op(kind: &str, realm_id: &str, payload: Value) -> Operation {
    Operation::create(
        arkret_sdk::OperationId::new(format!("ak:operation:{}", uuid::Uuid::now_v7())).unwrap(),
        arkret_sdk::RealmId::new(realm_id).unwrap(),
        kind,
        payload,
    )
}

/// Creating a high_assurance Realm with `federation_policy=open` MUST
/// be rejected at the reducer.
#[test]
fn high_assurance_rejects_open_federation_at_create() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let bad = op(
        arkret_sdk::events::EventKind::REALM_CREATE,
        REALM_HA,
        json!({
            "object": {
                "created_by": "did:web:alice",
                "title": "Compliance Vault",
                "security_class": "high_assurance",
                "federation_policy": "open",
            },
        }),
    );
    match state.apply(&bad, &hlc) {
        ProjectionEffect::Rejected { reason } => {
            assert_eq!(reason, "high_assurance_federation_policy_invalid");
        }
        other => {
            panic!("expected Rejected(high_assurance_federation_policy_invalid), got {other:?}")
        }
    }
}

/// Creating a high_assurance Realm with `federation_policy ∈ {closed,
/// restricted, quarantine}` is accepted.
#[test]
fn high_assurance_accepts_closed_restricted_and_quarantine() {
    for fp in &["closed", "restricted", "quarantine"] {
        let mut state = ProjectionState::new();
        let hlc = ServerHlc::new("test");
        let good = op(
            arkret_sdk::events::EventKind::REALM_CREATE,
            REALM_HA,
            json!({
                "object": {
                    "created_by": "did:web:alice",
                    "title": "Compliance Vault",
                    "security_class": "high_assurance",
                    "federation_policy": *fp,
                },
            }),
        );
        let effect = state.apply(&good, &hlc);
        assert!(
            matches!(effect, ProjectionEffect::RealmLifecycle { .. }),
            "expected RealmLifecycle for federation_policy={fp}, got {effect:?}"
        );
        // Subsequent reads see the projected security_class.
        assert_eq!(
            state.realm_security_class(REALM_HA).as_deref(),
            Some("high_assurance")
        );
    }
}

/// After a high_assurance Realm exists, a later `ak.realm.update` that
/// tries to switch `federation_policy=open` MUST be rejected even
/// though the update event itself doesn't carry security_class.
#[test]
fn high_assurance_rejects_post_create_open_federation_update() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");

    // First: create as high_assurance + restricted.
    let create = op(
        arkret_sdk::events::EventKind::REALM_CREATE,
        REALM_HA,
        json!({
            "object": {
                "created_by": "did:web:alice",
                "title": "Compliance Vault",
                "security_class": "high_assurance",
                "federation_policy": "restricted",
            },
        }),
    );
    assert!(matches!(
        state.apply(&create, &hlc),
        ProjectionEffect::RealmLifecycle { .. }
    ));

    // Mirror the create event into the organization cell too — in real
    // operation `ak.realm.update` carries the canonical
    // security_class/federation_policy snapshot. We do a follow-up
    // update to install both fields into the cas-register cell so the
    // R3.4 guard has a projected value to look up.
    let update_to_restricted = op(
        arkret_sdk::events::EventKind::REALM_UPDATE,
        REALM_HA,
        json!({
            "owner": "did:web:alice",
            "security_class": "high_assurance",
            "federation_policy": "restricted",
        }),
    );
    let effect = state.apply(&update_to_restricted, &hlc);
    assert!(
        matches!(effect, ProjectionEffect::RealmLifecycle { .. }),
        "first update must succeed, got {effect:?}"
    );

    // Now: try to switch to federation_policy=open without restating
    // security_class. The reducer MUST consult the projected
    // security_class and reject.
    let bad_update = op(
        arkret_sdk::events::EventKind::REALM_UPDATE,
        REALM_HA,
        json!({
            "federation_policy": "open",
        }),
    );
    match state.apply(&bad_update, &hlc) {
        ProjectionEffect::Rejected { reason } => {
            assert_eq!(reason, "high_assurance_federation_policy_invalid");
        }
        other => {
            panic!("expected Rejected(high_assurance_federation_policy_invalid), got {other:?}")
        }
    }
}

#[test]
fn realm_update_rejects_encryption_profile_patch() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let create = op(
        arkret_sdk::events::EventKind::REALM_CREATE,
        REALM_STANDARD,
        json!({
            "object": {
                "created_by": "did:web:alice",
                "title": "Encrypted Room",
                "encryption_profile": "mls_rfc9420",
            },
        }),
    );
    assert!(matches!(
        state.apply(&create, &hlc),
        ProjectionEffect::RealmLifecycle { .. }
    ));
    assert_eq!(
        state.realm_encryption_profile(REALM_STANDARD).as_deref(),
        Some("mls_rfc9420")
    );

    let downgrade = op(
        arkret_sdk::events::EventKind::REALM_UPDATE,
        REALM_STANDARD,
        json!({
            "patch": {
                "encryption_profile": "none",
            },
        }),
    );
    match state.apply(&downgrade, &hlc) {
        ProjectionEffect::Rejected { reason } => {
            assert_eq!(reason, "realm_encryption_profile_create_locked");
        }
        other => panic!("expected Rejected(realm_encryption_profile_create_locked), got {other:?}"),
    }
    assert_eq!(
        state.realm_encryption_profile(REALM_STANDARD).as_deref(),
        Some("mls_rfc9420")
    );
}

/// Standard Realms (no security_class set) freely accept
/// `federation_policy=open` — this guard is high_assurance-specific.
#[test]
fn standard_realm_accepts_open_federation_policy() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let good = op(
        arkret_sdk::events::EventKind::REALM_CREATE,
        REALM_STANDARD,
        json!({
            "object": {
                "created_by": "did:web:alice",
                "title": "Public Room",
                "federation_policy": "open",
            },
        }),
    );
    let effect = state.apply(&good, &hlc);
    assert!(
        matches!(effect, ProjectionEffect::RealmLifecycle { .. }),
        "expected RealmLifecycle for standard realm + open federation_policy, got {effect:?}"
    );
}

/// Once a high_assurance Realm exists, trying to *downgrade* it to a
/// standard class via an update + simultaneously open the federation is
/// still rejected — the payload-level effective_security_class still
/// resolves to high_assurance (since payload is high_assurance) and the
/// guard fires.
#[test]
fn high_assurance_rejects_simultaneous_open_in_same_payload() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let bad = op(
        arkret_sdk::events::EventKind::REALM_UPDATE,
        REALM_HA,
        json!({
            "security_class": "high_assurance",
            "federation_policy": "open",
        }),
    );
    match state.apply(&bad, &hlc) {
        ProjectionEffect::Rejected { reason } => {
            assert_eq!(reason, "high_assurance_federation_policy_invalid");
        }
        other => {
            panic!("expected Rejected(high_assurance_federation_policy_invalid), got {other:?}")
        }
    }
}
