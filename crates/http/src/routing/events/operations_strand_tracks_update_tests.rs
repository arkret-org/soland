use arkret_event_draft::Operation;
use serde_json::json;

use super::*;

fn op(payload: serde_json::Value) -> Operation {
    Operation::create(
        arkret_identifiers::OperationId::new("ak:operation:01904100-0000-7000-8000-57d7d85564c5")
            .unwrap(),
        arkret_identifiers::RealmId::new("ak:realm:AQptIWDEF2d4jlsnzTQVXGqZs6h-vPkYXuYqwewKqIjr")
            .unwrap(),
        arkret_wire::EventKind::STRAND_TRACKS_UPDATE,
        payload,
    )
}

#[test]
fn canonical_strand_tracks_update_accepts_patch_payload() {
    let operation = op(json!({
        "strand_id": "ak:strand:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
        "patch": {
            "tracks": {
                "discussion": {"profile": "discussion"}
            }
        }
    }));
    assert_eq!(
        kinds::canonical_kind_for_operation(&operation),
        Some(arkret_wire::EventKind::STRAND_TRACKS_UPDATE)
    );
    let schema = operation_schema_for_kind(arkret_wire::EventKind::STRAND_TRACKS_UPDATE).unwrap();
    assert!(validate_operation_schema(&operation, schema).is_ok());
}

#[test]
fn canonical_strand_tracks_update_accepts_tracks_payload() {
    let operation = op(json!({
        "strand_id": "ak:strand:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
        "tracks": {
            "review": {"profile": "review"}
        }
    }));
    let schema = operation_schema_for_kind(arkret_wire::EventKind::STRAND_TRACKS_UPDATE).unwrap();
    assert!(validate_operation_schema(&operation, schema).is_ok());
}

#[test]
fn canonical_strand_tracks_update_requires_strand_id_and_patch_or_tracks() {
    let schema = operation_schema_for_kind(arkret_wire::EventKind::STRAND_TRACKS_UPDATE).unwrap();

    let missing_strand_id = op(json!({
        "tracks": {
            "discussion": {"profile": "discussion"}
        }
    }));
    assert_eq!(
        validate_operation_schema(&missing_strand_id, schema),
        Err("strand tracks update requires strand_id")
    );

    let missing_patch_or_tracks = op(json!({
        "strand_id": "ak:strand:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19"
    }));
    assert_eq!(
        validate_operation_schema(&missing_patch_or_tracks, schema),
        Err("strand tracks update requires patch or tracks")
    );
}

#[test]
fn encrypted_realm_strand_content_detector_matches_content_only_boundary() {
    let strand_id = "ak:strand:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19";
    let content_update = strand_position_op(
        arkret_wire::EventKind::STRAND_UPDATE,
        json!({
            "target_ref": strand_id,
            "patch": {
                "content": {"$op": "set", "value": {"kind": "ak.content.text", "body": "private description"}}
            }
        }),
    );
    assert!(strand_operation_carries_plaintext_private_content(
        &content_update
    ));

    let summary_update = strand_position_op(
        arkret_wire::EventKind::STRAND_UPDATE,
        json!({
            "target_ref": strand_id,
            "patch": {
                "metadata": {"$op": "set", "value": {"summary": "wire metadata"}}
            }
        }),
    );
    assert!(!strand_operation_carries_plaintext_private_content(
        &summary_update
    ));

    let sdk_encrypted_content_update = strand_position_op(
        arkret_wire::EventKind::STRAND_UPDATE,
        json!({
            "target_ref": strand_id,
            "patch": {
                "content": {
                    "$op": "set",
                    "value": {
                        "scheme": "mls_rfc9420",
                        "group_id": "CK_space_01904100_0000_7000_8000_000000000001",
                        "epoch": 1,
                        "content_type": "application/vnd.arkret.strand.patch-value+json",
                        "ciphertext": "T1BBUVVFX0NJUEhFUlRFWFQ",
                        "payload_digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                    }
                }
            }
        }),
    );
    assert!(!strand_operation_carries_plaintext_private_content(
        &sdk_encrypted_content_update
    ));

    let ciphertext_label_content_update = strand_position_op(
        arkret_wire::EventKind::STRAND_UPDATE,
        json!({
            "target_ref": strand_id,
            "patch": {
                "content": {
                    "$op": "set",
                    "value": {
                        "ciphertext": "not enough envelope metadata"
                    }
                }
            }
        }),
    );
    assert!(strand_operation_carries_plaintext_private_content(
        &ciphertext_label_content_update
    ));

    let title_create = strand_position_op(
        arkret_wire::EventKind::STRAND_CREATE,
        json!({
            "object": {
                "id": strand_id,
                "metadata": {"title": "wire metadata"}
            }
        }),
    );
    assert!(!strand_operation_carries_plaintext_private_content(
        &title_create
    ));
}

#[test]
fn create_locked_encryption_profile_detector_matches_update_shapes() {
    let direct_patch = strand_position_op(
        arkret_wire::EventKind::CIRCLE_UPDATE,
        json!({
            "patch": {
                "encryption_profile": "none"
            }
        }),
    );
    assert!(operation_touches_encryption_profile(&direct_patch));

    let pointer_patch = strand_position_op(
        arkret_wire::EventKind::CIRCLE_UPDATE,
        json!({
            "circle_id": "ak:circle:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
            "patch": {
                "/object/encryption_profile": {
                    "$op": "replace",
                    "value": "none"
                }
            }
        }),
    );
    assert!(operation_touches_encryption_profile(&pointer_patch));

    let metadata_patch = strand_position_op(
        arkret_wire::EventKind::REALM_PROFILE,
        json!({
            "patch": {
                "title": "Still mutable"
            }
        }),
    );
    assert!(!operation_touches_encryption_profile(&metadata_patch));
}

fn strand_position_op(kind: &'static str, payload: serde_json::Value) -> Operation {
    Operation::create(
        arkret_identifiers::OperationId::new("ak:operation:01904100-0000-7000-8000-57d7d85564c6")
            .unwrap(),
        arkret_identifiers::RealmId::new("ak:realm:AQptIWDEF2d4jlsnzTQVXGqZs6h-vPkYXuYqwewKqIjr")
            .unwrap(),
        kind,
        payload,
    )
}

#[test]
fn canonical_strand_move_requires_board_target_and_rank() {
    let schema = operation_schema_for_kind(arkret_wire::EventKind::STRAND_MOVE).unwrap();
    let operation = strand_position_op(
        arkret_wire::EventKind::STRAND_MOVE,
        json!({
            "board_space_id": "ak:space:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
            "strand_id": "ak:strand:ASeIBHNVQyeIcU4aBIt2t2BF_ikuVMH0kNru_HgO_gG1",
            "target_space_id": "ak:space:AcsFZ3o2tOdN3EFpNceeLV-aI3jZkB9S34_4YIwJ5DLy",
            "rank": "a1"
        }),
    );
    assert!(validate_operation_schema(&operation, schema).is_ok());

    let missing_target = strand_position_op(
        arkret_wire::EventKind::STRAND_MOVE,
        json!({
            "board_space_id": "ak:space:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
            "strand_id": "ak:strand:ASeIBHNVQyeIcU4aBIt2t2BF_ikuVMH0kNru_HgO_gG1",
            "rank": "a1"
        }),
    );
    assert_eq!(
        validate_operation_schema(&missing_target, schema),
        Err("strand move operation requires target_space_id")
    );
}

#[test]
fn canonical_strand_reorder_requires_board_space_and_rank() {
    let schema = operation_schema_for_kind(arkret_wire::EventKind::STRAND_REORDER).unwrap();
    let operation = strand_position_op(
        arkret_wire::EventKind::STRAND_REORDER,
        json!({
            "board_space_id": "ak:space:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
            "strand_id": "ak:strand:ASeIBHNVQyeIcU4aBIt2t2BF_ikuVMH0kNru_HgO_gG1",
            "space_id": "ak:space:AcsFZ3o2tOdN3EFpNceeLV-aI3jZkB9S34_4YIwJ5DLy",
            "rank": "a1"
        }),
    );
    assert!(validate_operation_schema(&operation, schema).is_ok());
}

fn space_container_op(kind: &'static str, payload: serde_json::Value) -> Operation {
    Operation::create(
        arkret_identifiers::OperationId::new("ak:operation:01904100-0000-7000-8000-57d7d85564c7")
            .unwrap(),
        arkret_identifiers::RealmId::new("ak:realm:AQptIWDEF2d4jlsnzTQVXGqZs6h-vPkYXuYqwewKqIjr")
            .unwrap(),
        kind,
        payload,
    )
}

#[test]
fn canonical_space_update_requires_space_id_and_patch() {
    let schema = operation_schema_for_kind(arkret_wire::EventKind::SPACE_UPDATE).unwrap();
    let operation = space_container_op(
        arkret_wire::EventKind::SPACE_UPDATE,
        json!({
            "space_id": "ak:space:AcsFZ3o2tOdN3EFpNceeLV-aI3jZkB9S34_4YIwJ5DLy",
            "patch": {"title": "Launch v2"}
        }),
    );
    assert!(validate_operation_schema(&operation, schema).is_ok());

    let removed_target_ref = space_container_op(
        arkret_wire::EventKind::SPACE_UPDATE,
        json!({
            "target_ref": "ak:space:AcsFZ3o2tOdN3EFpNceeLV-aI3jZkB9S34_4YIwJ5DLy",
            "patch": {"title": "Launch v2"}
        }),
    );
    assert_eq!(
        validate_operation_schema(&removed_target_ref, schema),
        Err("space update operation requires space_id")
    );

    let missing_space_id = space_container_op(
        arkret_wire::EventKind::SPACE_UPDATE,
        json!({"patch": {"title": "Launch v2"}}),
    );
    assert_eq!(
        validate_operation_schema(&missing_space_id, schema),
        Err("space update operation requires space_id")
    );
}

#[test]
fn canonical_space_parent_requires_space_id_and_expected_parent() {
    let schema = operation_schema_for_kind(arkret_wire::EventKind::SPACE_PARENT).unwrap();
    let operation = space_container_op(
        arkret_wire::EventKind::SPACE_PARENT,
        json!({
            "space_id": "ak:space:AcsFZ3o2tOdN3EFpNceeLV-aI3jZkB9S34_4YIwJ5DLy",
            "parent_space_id": "ak:space:ARELvWOpF6BRrks3DlbQy-9XIE6aAQQumDQp7fA4ApeM",
            "expected_parent_space_id": null
        }),
    );
    assert!(validate_operation_schema(&operation, schema).is_ok());

    let missing_expected = space_container_op(
        arkret_wire::EventKind::SPACE_PARENT,
        json!({
            "space_id": "ak:space:AcsFZ3o2tOdN3EFpNceeLV-aI3jZkB9S34_4YIwJ5DLy",
            "parent_space_id": "ak:space:ARELvWOpF6BRrks3DlbQy-9XIE6aAQQumDQp7fA4ApeM"
        }),
    );
    assert_eq!(
        validate_operation_schema(&missing_expected, schema),
        Err("space parent operation requires expected_parent_space_id")
    );
}
