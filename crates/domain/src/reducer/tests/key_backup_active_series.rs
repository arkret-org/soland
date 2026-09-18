use serde_json::{Value, json};

use super::*;

const REALM: &str = "ak:realm:Af9DRPZ6jo28Ku6bsJX3iOs5fu2GLdPa5mI-lkvcujvM";
const ACTOR: &str = "ak:did_core:web:alice.example";
const ACTIVE_SERIES: &str = "ak:backup_series:01964137-1000-7000-8000-000000000000";
const PREVIOUS_SERIES: &str = "ak:backup_series:01964137-1000-7000-8000-000000000001";

/// The committed Realm-stream position the active-series selection was taken
/// against.
///
/// `KeyBackupActiveSeriesSourceRef` is a closed `(commit_ref,
/// device_generation_ref)` pair and `CommittedEventRef` is a closed
/// `(event_id, commit_id, stream_ref, stream_position)` tuple, so the fixture
/// is built through the SDK types rather than hand-written JSON that only the
/// test believes in.
fn source_ref() -> Value {
    let commit_ref = arkret_wire::CommittedEventRef {
        event_id: arkret_wire::EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [3; 32]),
        commit_id: arkret_wire::RealmCommitId::from_digest([4; 32]),
        stream_ref: arkret_wire::CommitStreamRef::Realm {
            realm_id: arkret_identifiers::RealmId::new(REALM).unwrap(),
        },
        stream_position: 0,
    };
    json!({
        "commit_ref": commit_ref,
        "device_generation_ref": 2
    })
}

fn active_series_payload() -> Value {
    json!({
        "schema": "ak.schema.key_backup_active_series.v1",
        "actor_id": account_actor(ACTOR),
        "backup_kind": "secret_storage",
        "active_series_id": ACTIVE_SERIES,
        "series_pointer_version": 1,
        "previous_series_ids": [PREVIOUS_SERIES],
        "source_ref": source_ref(),
        "issued_at": "2026-04-27T00:00:00.000Z",
        "auth_data": {
            "verification_method": "did:web:alice.example#ak_device_01964137",
            "signature_algorithm": "Ed25519",
            "signature": "signature-base64url-placeholder",
            "device_authorize_event_id": "ak:event:ATyaOl1JkDDCC-6ZytsgoAKvlQJ6s6NJuDC_bmWKARBa"
        }
    })
}

#[test]
fn key_backup_active_series_projects_pointer_and_facet() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("key-backup-active-series");

    let effect = state.apply(
        &make_operation(
            arkret_wire::EventKind::KeyBackupActiveSeries,
            REALM,
            active_series_payload(),
        ),
        &hlc,
    );

    let actor = account_actor_string(ACTOR);
    assert!(
        matches!(
            effect,
            ProjectionEffect::KeyBackupActiveSeriesProjected {
                ref actor_id,
                ref backup_kind,
                ref active_series_id,
            } if actor_id == &actor
                && backup_kind == "secret_storage"
                && active_series_id == ACTIVE_SERIES
        ),
        "active-series pointer should project: {effect:?}"
    );
    let projected = state
        .key_backup_active_series(&actor, "secret_storage")
        .expect("active series projection");
    assert_eq!(projected.active_series_id, ACTIVE_SERIES);
    assert_eq!(projected.series_pointer_version, 1);
    assert_eq!(projected.previous_series_ids, vec![PREVIOUS_SERIES]);
    assert_eq!(
        projected.auth_data.device_authorize_event_id.as_str(),
        "ak:event:ATyaOl1JkDDCC-6ZytsgoAKvlQJ6s6NJuDC_bmWKARBa"
    );

    let active_series = FacetRef::composite(
        facet::KEY_BACKUP_ACTIVE_SERIES,
        &[actor.as_str(), "secret_storage"],
    );
    assert!(state.facet_value(REALM, &active_series).is_some());
    assert!(
        state
            .facet_value(REALM, &active_series)
            .is_some_and(|value| value.get("accepted_event_id").is_none())
    );
}

#[test]
fn key_backup_active_series_rejects_active_series_in_previous_set() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("key-backup-active-series-previous");
    let mut payload = active_series_payload();
    payload["previous_series_ids"] = json!([ACTIVE_SERIES]);

    let effect = state.apply(
        &make_operation(
            arkret_wire::EventKind::KeyBackupActiveSeries,
            REALM,
            payload,
        ),
        &hlc,
    );

    assert!(
        matches!(
            effect,
            ProjectionEffect::Rejected { ref reason }
                if reason == "key_backup_active_series_active_in_previous"
        ),
        "active series listed in previous_series_ids must fail closed: {effect:?}"
    );
}

#[test]
fn key_backup_active_series_enforces_contiguous_pointer_versions() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("key-backup-active-series-version");
    let mut gap = active_series_payload();
    gap["series_pointer_version"] = json!(2);

    let initial_gap = state.apply(
        &make_operation(arkret_wire::EventKind::KeyBackupActiveSeries, REALM, gap),
        &hlc,
    );
    assert!(
        matches!(
            initial_gap,
            ProjectionEffect::Rejected { ref reason }
                if reason == "key_backup_active_series_pointer_version_gap"
        ),
        "a first pointer version other than 1 is a gap: {initial_gap:?}"
    );

    let accepted = state.apply(
        &make_operation(
            arkret_wire::EventKind::KeyBackupActiveSeries,
            REALM,
            active_series_payload(),
        ),
        &hlc,
    );
    assert!(
        matches!(
            accepted,
            ProjectionEffect::KeyBackupActiveSeriesProjected { .. }
        ),
        "pointer version 1 should project: {accepted:?}"
    );

    let duplicate = state.apply(
        &make_operation(
            arkret_wire::EventKind::KeyBackupActiveSeries,
            REALM,
            active_series_payload(),
        ),
        &hlc,
    );
    assert!(
        matches!(duplicate, ProjectionEffect::Ignored),
        "an identical replay is a no-op: {duplicate:?}"
    );

    let mut fork = active_series_payload();
    fork["issued_at"] = json!("2026-07-18T00:00:01.000Z");
    let fork = state.apply(
        &make_operation(arkret_wire::EventKind::KeyBackupActiveSeries, REALM, fork),
        &hlc,
    );
    assert!(
        matches!(
            fork,
            ProjectionEffect::Rejected { ref reason }
                if reason == "key_backup_active_series_pointer_version_fork"
        ),
        "a second distinct record at the same pointer version forks: {fork:?}"
    );
}
