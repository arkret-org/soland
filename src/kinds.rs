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
pub const CX_FIELD_POSITION_MOVE: &str = "cx.field_position.move";
pub const CX_FIELD_POSITION_REORDER: &str = "cx.field_position.reorder";
pub const CX_CONTAINER_MOVE_ITEM: &str = "cx.container.move_item";
pub const CX_CONTAINER_REBALANCE: &str = "cx.container.rebalance";
pub const CX_LEGACY_TASK_MOVE: &str = "cx.task.move";
pub const CX_LEGACY_TASK_REORDER: &str = "cx.task.reorder";
pub const CX_LEGACY_RELATION_MOVE: &str = "cx.relation.move";
pub const CX_LEGACY_RELATION_REBALANCE: &str = "cx.relation.rebalance";
pub const CX_MEMBERSHIP_JOIN: &str = "cx.membership.join";
pub const CX_MEMBERSHIP_LEAVE: &str = "cx.membership.leave";
pub const CX_MEMBERSHIP_KICK: &str = "cx.membership.kick";
pub const CX_MEMBERSHIP_BAN: &str = "cx.membership.ban";
pub const CX_MEMBERSHIP_UNBAN: &str = "cx.membership.unban";
pub const CX_MEMBERSHIP_KNOCK: &str = "cx.membership.knock";
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

pub fn canonical_kind_for_payload(object_type: &str, payload: &Value) -> Option<&'static str> {
    canonical_registered_kind(object_type, payload).or_else(|| {
        legacy_kind_enabled(payload).then(|| legacy_kind_for_payload(object_type, payload))?
    })
}

pub fn canonical_kind_for_local_payload(
    object_type: &str,
    payload: &Value,
) -> Option<&'static str> {
    canonical_registered_kind(object_type, payload)
        .or_else(|| legacy_kind_for_payload(object_type, payload))
}

fn canonical_registered_kind(object_type: &str, _payload: &Value) -> Option<&'static str> {
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
        CX_MEMBERSHIP_JOIN | CX_MEMBERSHIP_LEAVE | CX_MEMBERSHIP_KICK | CX_MEMBERSHIP_BAN
        | CX_MEMBERSHIP_UNBAN | CX_MEMBERSHIP_KNOCK => Some(match object_type {
            CX_MEMBERSHIP_LEAVE => CX_MEMBERSHIP_LEAVE,
            CX_MEMBERSHIP_KICK => CX_MEMBERSHIP_KICK,
            CX_MEMBERSHIP_BAN => CX_MEMBERSHIP_BAN,
            CX_MEMBERSHIP_UNBAN => CX_MEMBERSHIP_UNBAN,
            CX_MEMBERSHIP_KNOCK => CX_MEMBERSHIP_KNOCK,
            _ => CX_MEMBERSHIP_JOIN,
        }),
        _ => None,
    }
}

fn legacy_kind_for_payload(object_type: &str, payload: &Value) -> Option<&'static str> {
    match object_type {
        "message" => Some(CX_MESSAGE_CREATE),
        "message.revise" | "message.edit" => Some(CX_MESSAGE_REVISE),
        "redaction" => Some(CX_MESSAGE_REDACT),
        "reaction" | "reaction.add" | "message.react" => Some(CX_REACTION_ADD),
        "reaction.remove" | "message.unreact" => Some(CX_REACTION_REMOVE),
        "entity" | "entity.create" => Some(CX_ENTITY_CREATE),
        "entity.update" => Some(CX_ENTITY_UPDATE),
        "entity.delete" => Some(CX_ENTITY_DELETE),
        "relation" | "relation.create" => Some(CX_RELATION_CREATE),
        "relation.update" => Some(CX_RELATION_UPDATE),
        "relation.delete" => Some(CX_RELATION_DELETE),
        CX_LEGACY_TASK_MOVE | "task.move" => Some(CX_FIELD_POSITION_MOVE),
        CX_LEGACY_TASK_REORDER | "task.reorder" => Some(CX_FIELD_POSITION_REORDER),
        CX_LEGACY_RELATION_MOVE | "relation.move" => Some(CX_CONTAINER_MOVE_ITEM),
        CX_LEGACY_RELATION_REBALANCE | "relation.rebalance" => Some(CX_CONTAINER_REBALANCE),
        "read_marker" => Some(CX_READ_MARKER),
        "membership" | "space.lifecycle" => Some(legacy_membership_or_space_kind(payload)),
        _ => None,
    }
}

fn legacy_kind_enabled(payload: &Value) -> bool {
    payload
        .get("migration_profile")
        .and_then(|value| value.as_str())
        == Some(LEGACY_KIND_MIGRATION_PROFILE)
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
    canonical_kind_for_operation(operation).is_some_and(is_membership_kind)
}

pub fn operation_is_space_lifecycle(operation: &Operation) -> bool {
    canonical_kind_for_operation(operation).is_some_and(is_space_lifecycle_kind)
}

pub fn is_redaction_kind(kind: &str) -> bool {
    matches!(kind, CX_MESSAGE_REDACT | CX_REDACTION | "redaction")
}

pub fn is_membership_kind(kind: &str) -> bool {
    matches!(
        kind,
        CX_MEMBERSHIP_JOIN
            | CX_MEMBERSHIP_LEAVE
            | CX_MEMBERSHIP_KICK
            | CX_MEMBERSHIP_BAN
            | CX_MEMBERSHIP_UNBAN
            | CX_MEMBERSHIP_KNOCK
    )
}

pub fn is_space_lifecycle_kind(kind: &str) -> bool {
    matches!(kind, CX_SPACE_CREATE | CX_SPACE_UPDATE | CX_SPACE_DESTROY)
}

fn legacy_membership_or_space_kind(payload: &Value) -> &'static str {
    if payload.get("membership").is_some() || payload.get("member").is_some() {
        return membership_kind_from_payload(payload);
    }
    match payload
        .get("action")
        .and_then(|value| value.as_str())
        .unwrap_or_default()
    {
        "create" => CX_SPACE_CREATE,
        "delete" | "destroy" => CX_SPACE_DESTROY,
        _ => CX_SPACE_UPDATE,
    }
}

fn membership_kind_from_payload(payload: &Value) -> &'static str {
    match payload
        .get("membership")
        .or_else(|| payload.get("action"))
        .and_then(|value| value.as_str())
        .unwrap_or("join")
    {
        "leave" | "member.remove" => CX_MEMBERSHIP_LEAVE,
        "kick" | "member.kick" => CX_MEMBERSHIP_KICK,
        "ban" => CX_MEMBERSHIP_BAN,
        "unban" => CX_MEMBERSHIP_UNBAN,
        "knock" => CX_MEMBERSHIP_KNOCK,
        _ => CX_MEMBERSHIP_JOIN,
    }
}
