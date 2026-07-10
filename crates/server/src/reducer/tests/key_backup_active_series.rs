use serde_json::{Value, json};

use super::*;

const REALM: &str = "ak:realm:0196419b-0000-7000-8000-000000000001";
const ACTOR: &str = "did:web:alice.example";
const ACTIVE_SERIES: &str = "ak:backup_series:01964137-1000-7000-8000-000000000000";
const PREVIOUS_SERIES: &str = "ak:backup_series:01964137-1000-7000-8000-000000000001";

fn active_series_payload() -> Value {
    json!({
        "schema": "ak.schema.key_backup_active_series.v1",
        "actor_id": ACTOR,
        "backup_class": "secret_storage",
        "active_series_id": ACTIVE_SERIES,
        "previous_series_ids": [PREVIOUS_SERIES],
        "frontier_ref": {
            "frontier_digest": "sha256:3333333333333333333333333333333333333333333333333333333333333333",
            "seal_ref": "ak:seal:sha256:4444444444444444444444444444444444444444444444444444444444444444",
            "ssk_generation": 2
        },
        "issued_at": "2026-04-27T00:00:00Z",
        "auth_data": {
            "verification_method": "did:web:alice.example#ck_device_01964137",
            "signature_algorithm": "Ed25519",
            "signature": "signature-base64url-placeholder",
            "signed_fields": [
                "schema",
                "actor_id",
                "backup_class",
                "active_series_id",
                "previous_series_ids",
                "frontier_ref",
                "issued_at"
            ],
            "ssk_generation": 2
        }
    })
}

#[test]
fn key_backup_active_series_projects_pointer_and_cell() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("key-backup-active-series");

    let effect = state.apply(
        &make_operation(
            arkret_sdk::events::kinds::KEY_BACKUP_ACTIVE_SERIES,
            REALM,
            active_series_payload(),
        ),
        &hlc,
    );

    assert!(matches!(
        effect,
        ProjectionEffect::KeyBackupActiveSeriesProjected {
            ref actor_id,
            ref backup_class,
            ref active_series_id,
        } if actor_id == ACTOR
            && backup_class == "secret_storage"
            && active_series_id == ACTIVE_SERIES
    ));
    let projected = state
        .key_backup_active_series(ACTOR, "secret_storage")
        .expect("active series projection");
    assert_eq!(projected.active_series_id, ACTIVE_SERIES);
    assert_eq!(projected.previous_series_ids, vec![PREVIOUS_SERIES]);
    assert_eq!(projected.ssk_generation, 2);

    let cell = arkret_sdk::CellRef::new(format!(
        "ak:cell:ak.component.key_backup.active_series.v1:{ACTOR}::secret_storage"
    ))
    .expect("active series cell ref");
    assert!(state.cell_value(&cell).is_some());
}

#[test]
fn key_backup_active_series_requires_complete_signed_fields() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("key-backup-active-series-signed-fields");
    let mut payload = active_series_payload();
    payload["auth_data"]["signed_fields"] = json!([
        "schema",
        "actor_id",
        "backup_class",
        "active_series_id",
        "previous_series_ids",
        "issued_at"
    ]);

    let effect = state.apply(
        &make_operation(
            arkret_sdk::events::kinds::KEY_BACKUP_ACTIVE_SERIES,
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
            arkret_sdk::events::kinds::KEY_BACKUP_ACTIVE_SERIES,
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
fn key_backup_active_series_rejects_frontier_ssk_mismatch() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("key-backup-active-series-ssk");
    let mut payload = active_series_payload();
    payload["frontier_ref"]["ssk_generation"] = json!(1);

    let effect = state.apply(
        &make_operation(
            arkret_sdk::events::kinds::KEY_BACKUP_ACTIVE_SERIES,
            REALM,
            payload,
        ),
        &hlc,
    );

    assert!(matches!(
        effect,
        ProjectionEffect::Rejected { ref reason }
            if reason == "key_backup_active_series_ssk_generation_mismatch"
    ));
}
