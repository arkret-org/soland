use contrix_sdk::Operation;
use serde_json::Value;

pub const CX_MESSAGE_CREATE: &str = "cx.message.create";
pub const CX_MESSAGE_REVISE: &str = "cx.message.revise";
pub const CX_MESSAGE_REDACT: &str = "cx.message.redact";
pub const CX_REACTION_ADD: &str = "cx.reaction.add";
pub const CX_REACTION_REMOVE: &str = "cx.reaction.remove";
pub const CX_ENTITY_CREATE: &str = "cx.entity.create";
pub const CX_ENTITY_UPDATE: &str = "cx.entity.update";
pub const CX_ENTITY_DELETE: &str = "cx.entity.delete";
pub const CX_RELATION_CREATE: &str = "cx.relation.create";
pub const CX_RELATION_UPDATE: &str = "cx.relation.update";
pub const CX_RELATION_DELETE: &str = "cx.relation.delete";
pub const CX_FIELD_POSITION_MOVE: &str = "cx.field.position.move";
pub const CX_FIELD_POSITION_REORDER: &str = "cx.field.position.reorder";
pub const CX_CONTAINER_MOVE_ITEM: &str = "cx.container.move_item";
pub const CX_CONTAINER_REBALANCE: &str = "cx.container.rebalance";
pub const CX_MEMBER_STATE: &str = "cx.member.state";
pub const CX_READ_MARKER: &str = "cx.read.marker";
pub const CX_SPACE_CREATE: &str = "cx.space.create";
pub const CX_SPACE_UPDATE: &str = "cx.space.update";
pub const CX_SPACE_DESTROY: &str = "cx.space.destroy";
pub const CX_REDACTION: &str = "cx.redaction";
pub const LEGACY_KIND_MIGRATION_PROFILE: &str = "cx.profile.legacy_kind_migration.v1";

pub fn canonical_kind_for_operation(operation: &Operation) -> Option<&'static str> {
    canonical_kind_for_payload(&operation.object_type, &operation.payload)
}

pub fn canonical_kind_string(operation: &Operation) -> String {
    canonical_kind_for_operation(operation)
        .unwrap_or(operation.object_type.as_str())
        .to_owned()
}

pub fn canonical_kind_for_payload(object_type: &str, _payload: &Value) -> Option<&'static str> {
    canonical_registered_kind(object_type)
}

fn canonical_registered_kind(object_type: &str) -> Option<&'static str> {
    match object_type {
        CX_MESSAGE_CREATE => Some(CX_MESSAGE_CREATE),
        CX_MESSAGE_REVISE => Some(CX_MESSAGE_REVISE),
        CX_MESSAGE_REDACT => Some(CX_MESSAGE_REDACT),
        CX_REDACTION => Some(CX_REDACTION),
        CX_REACTION_ADD => Some(CX_REACTION_ADD),
        CX_REACTION_REMOVE => Some(CX_REACTION_REMOVE),
        CX_ENTITY_CREATE => Some(CX_ENTITY_CREATE),
        CX_ENTITY_UPDATE => Some(CX_ENTITY_UPDATE),
        CX_ENTITY_DELETE => Some(CX_ENTITY_DELETE),
        CX_RELATION_CREATE => Some(CX_RELATION_CREATE),
        CX_RELATION_UPDATE => Some(CX_RELATION_UPDATE),
        CX_RELATION_DELETE => Some(CX_RELATION_DELETE),
        CX_FIELD_POSITION_MOVE => Some(CX_FIELD_POSITION_MOVE),
        CX_FIELD_POSITION_REORDER => Some(CX_FIELD_POSITION_REORDER),
        CX_CONTAINER_MOVE_ITEM => Some(CX_CONTAINER_MOVE_ITEM),
        CX_CONTAINER_REBALANCE => Some(CX_CONTAINER_REBALANCE),
        CX_READ_MARKER => Some(CX_READ_MARKER),
        CX_SPACE_CREATE | CX_SPACE_UPDATE | CX_SPACE_DESTROY => Some(match object_type {
            CX_SPACE_CREATE => CX_SPACE_CREATE,
            CX_SPACE_DESTROY => CX_SPACE_DESTROY,
            _ => CX_SPACE_UPDATE,
        }),
        CX_MEMBER_STATE => Some(CX_MEMBER_STATE),
        _ => None,
    }
}

pub fn operation_is_message_create(operation: &Operation) -> bool {
    canonical_kind_for_operation(operation) == Some(CX_MESSAGE_CREATE)
}

pub fn operation_is_redaction(operation: &Operation) -> bool {
    matches!(
        canonical_kind_for_operation(operation),
        Some(CX_MESSAGE_REDACT | CX_REDACTION)
    )
}

pub fn operation_is_membership(operation: &Operation) -> bool {
    canonical_kind_for_operation(operation) == Some(CX_MEMBER_STATE)
}

pub fn operation_is_space_lifecycle(operation: &Operation) -> bool {
    canonical_kind_for_operation(operation).is_some_and(is_space_lifecycle_kind)
}

pub fn is_redaction_kind(kind: &str) -> bool {
    matches!(kind, CX_MESSAGE_REDACT | CX_REDACTION | "redaction")
}

pub fn is_membership_kind(kind: &str) -> bool {
    kind == CX_MEMBER_STATE
}

pub fn is_space_lifecycle_kind(kind: &str) -> bool {
    matches!(kind, CX_SPACE_CREATE | CX_SPACE_UPDATE | CX_SPACE_DESTROY)
}
