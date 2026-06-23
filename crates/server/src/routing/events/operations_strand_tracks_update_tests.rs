use cokret_sdk::Operation;
use serde_json::json;

use super::*;

fn op(payload: serde_json::Value) -> Operation {
    Operation::create(
        cokret_sdk::OperationId::new("ck:operation:01904100-0000-7000-8000-57d7d85564c5").unwrap(),
        cokret_sdk::RealmId::new("ck:realm:01904100-0000-7000-8000-668e2181b41d").unwrap(),
        cokret_sdk::events::kinds::STRAND_TRACKS_UPDATE,
        payload,
    )
}

#[test]
fn canonical_strand_tracks_update_accepts_patch_payload() {
    let operation = op(json!({
        "strand_id": "ck:strand:01904100-0000-7000-8000-000000000001",
        "patch": {
            "tracks": {
                "discussion": {"profile": "discussion"}
            }
        }
    }));
    assert_eq!(
        kinds::canonical_kind_for_operation(&operation),
        Some(cokret_sdk::events::kinds::STRAND_TRACKS_UPDATE)
    );
    let schema =
        operation_schema_for_kind(cokret_sdk::events::kinds::STRAND_TRACKS_UPDATE).unwrap();
    assert!(validate_operation_schema(&operation, schema).is_ok());
}

#[test]
fn canonical_strand_tracks_update_accepts_tracks_payload() {
    let operation = op(json!({
        "strand_id": "ck:strand:01904100-0000-7000-8000-000000000001",
        "tracks": {
            "review": {"profile": "review"}
        }
    }));
    let schema =
        operation_schema_for_kind(cokret_sdk::events::kinds::STRAND_TRACKS_UPDATE).unwrap();
    assert!(validate_operation_schema(&operation, schema).is_ok());
}

#[test]
fn canonical_strand_tracks_update_requires_strand_id_and_patch_or_tracks() {
    let schema =
        operation_schema_for_kind(cokret_sdk::events::kinds::STRAND_TRACKS_UPDATE).unwrap();

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
        "strand_id": "ck:strand:01904100-0000-7000-8000-000000000001"
    }));
    assert_eq!(
        validate_operation_schema(&missing_patch_or_tracks, schema),
        Err("strand tracks update requires patch or tracks")
    );
}

#[test]
fn encrypted_realm_strand_content_detector_matches_content_only_boundary() {
    let strand_id = "ck:strand:01904100-0000-7000-8000-000000000001";
    let content_update = strand_position_op(
        cokret_sdk::events::kinds::STRAND_UPDATE,
        json!({
            "target_ref": strand_id,
            "patch": {
                "content": {"$op": "set", "value": {"kind": "ck.content.text", "body": "private description"}}
            }
        }),
    );
    assert!(strand_operation_carries_plaintext_private_content(
        &content_update
    ));

    let summary_update = strand_position_op(
        cokret_sdk::events::kinds::STRAND_UPDATE,
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
        cokret_sdk::events::kinds::STRAND_UPDATE,
        json!({
            "target_ref": strand_id,
            "patch": {
                "content": {
                    "$op": "set",
                    "value": {
                        "scheme": "mls-rfc9420",
                        "group_id": "CK_space_01904100_0000_7000_8000_000000000001",
                        "epoch": 1,
                        "content_type": "application/vnd.cokret.strand.patch-value+json",
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
        cokret_sdk::events::kinds::STRAND_UPDATE,
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
        cokret_sdk::events::kinds::STRAND_CREATE,
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
        cokret_sdk::events::kinds::REALM_UPDATE,
        json!({
            "patch": {
                "encryption_profile": "none"
            }
        }),
    );
    assert!(operation_touches_encryption_profile(&direct_patch));

    let pointer_patch = strand_position_op(
        cokret_sdk::events::kinds::CIRCLE_UPDATE,
        json!({
            "circle_id": "ck:circle:01904100-0000-7000-8000-000000000001",
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
        cokret_sdk::events::kinds::REALM_UPDATE,
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
        cokret_sdk::OperationId::new("ck:operation:01904100-0000-7000-8000-57d7d85564c6").unwrap(),
        cokret_sdk::RealmId::new("ck:realm:01904100-0000-7000-8000-668e2181b41d").unwrap(),
        kind,
        payload,
    )
}

#[test]
fn canonical_strand_move_requires_board_target_and_rank() {
    let schema = operation_schema_for_kind(cokret_sdk::events::kinds::STRAND_MOVE).unwrap();
    let operation = strand_position_op(
        cokret_sdk::events::kinds::STRAND_MOVE,
        json!({
            "board_space_id": "ck:space:01904100-0000-7000-8000-000000000001",
            "strand_id": "ck:strand:01904100-0000-7000-8000-000000000002",
            "target_space_id": "ck:space:01904100-0000-7000-8000-000000000003",
            "rank": "a1"
        }),
    );
    assert!(validate_operation_schema(&operation, schema).is_ok());

    let missing_target = strand_position_op(
        cokret_sdk::events::kinds::STRAND_MOVE,
        json!({
            "board_space_id": "ck:space:01904100-0000-7000-8000-000000000001",
            "strand_id": "ck:strand:01904100-0000-7000-8000-000000000002",
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
    let schema = operation_schema_for_kind(cokret_sdk::events::kinds::STRAND_REORDER).unwrap();
    let operation = strand_position_op(
        cokret_sdk::events::kinds::STRAND_REORDER,
        json!({
            "board_space_id": "ck:space:01904100-0000-7000-8000-000000000001",
            "strand_id": "ck:strand:01904100-0000-7000-8000-000000000002",
            "space_id": "ck:space:01904100-0000-7000-8000-000000000003",
            "rank": "a1"
        }),
    );
    assert!(validate_operation_schema(&operation, schema).is_ok());
}

fn space_container_op(kind: &'static str, payload: serde_json::Value) -> Operation {
    Operation::create(
        cokret_sdk::OperationId::new("ck:operation:01904100-0000-7000-8000-57d7d85564c7").unwrap(),
        cokret_sdk::RealmId::new("ck:realm:01904100-0000-7000-8000-668e2181b41d").unwrap(),
        kind,
        payload,
    )
}

#[test]
fn canonical_space_update_requires_space_id_and_patch() {
    let schema = operation_schema_for_kind(cokret_sdk::events::kinds::SPACE_UPDATE).unwrap();
    let operation = space_container_op(
        cokret_sdk::events::kinds::SPACE_UPDATE,
        json!({
            "space_id": "ck:space:01904100-0000-7000-8000-000000000003",
            "patch": {"title": "Launch v2"}
        }),
    );
    assert!(validate_operation_schema(&operation, schema).is_ok());

    let removed_target_ref = space_container_op(
        cokret_sdk::events::kinds::SPACE_UPDATE,
        json!({
            "target_ref": "ck:space:01904100-0000-7000-8000-000000000003",
            "patch": {"title": "Launch v2"}
        }),
    );
    assert_eq!(
        validate_operation_schema(&removed_target_ref, schema),
        Err("space update operation requires space_id")
    );

    let missing_space_id = space_container_op(
        cokret_sdk::events::kinds::SPACE_UPDATE,
        json!({"patch": {"title": "Launch v2"}}),
    );
    assert_eq!(
        validate_operation_schema(&missing_space_id, schema),
        Err("space update operation requires space_id")
    );
}

#[test]
fn canonical_space_parent_requires_space_id_and_expected_parent() {
    let schema = operation_schema_for_kind(cokret_sdk::events::kinds::SPACE_PARENT).unwrap();
    let operation = space_container_op(
        cokret_sdk::events::kinds::SPACE_PARENT,
        json!({
            "space_id": "ck:space:01904100-0000-7000-8000-000000000003",
            "parent_space_id": "ck:space:01904100-0000-7000-8000-000000000004",
            "expected_parent_space_id": null
        }),
    );
    assert!(validate_operation_schema(&operation, schema).is_ok());

    let missing_expected = space_container_op(
        cokret_sdk::events::kinds::SPACE_PARENT,
        json!({
            "space_id": "ck:space:01904100-0000-7000-8000-000000000003",
            "parent_space_id": "ck:space:01904100-0000-7000-8000-000000000004"
        }),
    );
    assert_eq!(
        validate_operation_schema(&missing_expected, schema),
        Err("space parent operation requires expected_parent_space_id")
    );
}
