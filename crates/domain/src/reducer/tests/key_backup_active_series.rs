use serde_json::{Value, json};

use super::*;

const REALM: &str = "ak:realm:Af9DRPZ6jo28Ku6bsJX3iOs5fu2GLdPa5mI-lkvcujvM";
const ACTOR: &str = "ak:did_core:web:alice.example";
const ACTIVE_SERIES: &str = "ak:backup_series:01964137-1000-7000-8000-000000000000";
const PREVIOUS_SERIES: &str = "ak:backup_series:01964137-1000-7000-8000-000000000001";

fn active_series_payload() -> Value {
    json!({
        "schema": "ak.schema.key_backup_active_series.v1",
        "actor_id": ACTOR,
        "backup_kind": "secret_storage",
        "active_series_id": ACTIVE_SERIES,
        "series_pointer_version": 1,
        "previous_series_ids": [PREVIOUS_SERIES],
        "frontier_ref": {
            "frontier_digest": "sha256:3333333333333333333333333333333333333333333333333333333333333333",
            "seal_ref": "ak:seal:sha256:4444444444444444444444444444444444444444444444444444444444444444",
            "device_generation_ref": 2
        },
        "issued_at": "2026-04-27T00:00:00.000Z",
        "auth_data": {
            "verification_method": "did:web:alice.example#ak_device_01964137",
            "signature_algorithm": "Ed25519",
            "signature": "signature-base64url-placeholder",
            "signed_fields": [
                "schema",
                "actor_id",
                "backup_kind",
                "active_series_id",
                "series_pointer_version",
                "previous_series_ids",
                "frontier_ref",
                "issued_at"
            ],
            "device_authorize_event_id": "ak:event:ATyaOl1JkDDCC-6ZytsgoAKvlQJ6s6NJuDC_bmWKARBa"
        }
    })
}

#[test]
fn key_backup_active_series_projects_pointer_and_cell() {
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

    assert!(matches!(
        effect,
        ProjectionEffect::KeyBackupActiveSeriesProjected {
            ref actor_id,
            ref backup_kind,
            ref active_series_id,
        } if actor_id == ACTOR
            && backup_kind == "secret_storage"
            && active_series_id == ACTIVE_SERIES
    ));
    let projected = state
        .key_backup_active_series(ACTOR, "secret_storage")
        .expect("active series projection");
    assert_eq!(projected.active_series_id, ACTIVE_SERIES);
    assert_eq!(projected.series_pointer_version, 1);
    assert_eq!(projected.previous_series_ids, vec![PREVIOUS_SERIES]);
    assert_eq!(
        projected.auth_data.device_authorize_event_id.as_str(),
        "ak:event:ATyaOl1JkDDCC-6ZytsgoAKvlQJ6s6NJuDC_bmWKARBa"
    );

    let subject = arkret_wire::composite_subject(&[ACTOR, "secret_storage"])
        .expect("active series composite subject");
    let cell = arkret_identifiers::CellRef::new(format!(
        "ak:cell:ak.component.key_backup.active_series.v1:{subject}"
    ))
    .expect("active series cell ref");
    assert!(state.cell_value(&cell).is_some());
    assert!(
        state
            .cell_value(&cell)
            .is_some_and(|value| value.get("accepted_event_id").is_none())
    );
}

#[test]
fn key_backup_active_series_requires_complete_signed_fields() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("key-backup-active-series-signed-fields");
    let mut payload = active_series_payload();
    payload["auth_data"]["signed_fields"] = json!([
        "schema",
        "actor_id",
        "backup_kind",
        "active_series_id",
        "series_pointer_version",
        "previous_series_ids",
        "issued_at"
    ]);

    let effect = state.apply(
        &make_operation(
            arkret_wire::EventKind::KeyBackupActiveSeries,
            REALM,
            payload,
        ),
        &hlc,
    );

    assert!(matches!(
        effect,
        ProjectionEffect::Rejected { ref reason }
            if reason == "key_backup_active_series_signed_fields_incomplete"
    ));
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

    assert!(matches!(
        effect,
        ProjectionEffect::Rejected { ref reason }
            if reason == "key_backup_active_series_active_in_previous"
    ));
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
    assert!(matches!(
        initial_gap,
        ProjectionEffect::Rejected { ref reason }
            if reason == "key_backup_active_series_pointer_version_gap"
    ));

    let accepted = state.apply(
        &make_operation(
            arkret_wire::EventKind::KeyBackupActiveSeries,
            REALM,
            active_series_payload(),
        ),
        &hlc,
    );
    assert!(matches!(
        accepted,
        ProjectionEffect::KeyBackupActiveSeriesProjected { .. }
    ));

    let duplicate = state.apply(
        &make_operation(
            arkret_wire::EventKind::KeyBackupActiveSeries,
            REALM,
            active_series_payload(),
        ),
        &hlc,
    );
    assert!(matches!(duplicate, ProjectionEffect::Ignored));

    let mut fork = active_series_payload();
    fork["issued_at"] = json!("2026-07-18T00:00:01.000Z");
    let fork = state.apply(
        &make_operation(arkret_wire::EventKind::KeyBackupActiveSeries, REALM, fork),
        &hlc,
    );
    assert!(matches!(
        fork,
        ProjectionEffect::Rejected { ref reason }
            if reason == "key_backup_active_series_pointer_version_fork"
    ));
}
