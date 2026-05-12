//! Operation envelope + payload validators.
//!
//! Surfaces:
//! - `OperationPayloadSchema` / `PayloadRequirement` — per-kind required / optional / enum field
//!   schemas.
//! - `validate_operation_semantics` / `validate_operation_schema` — the entrypoint validators
//!   called from `repo::submit_commit`, `projection::project_accepted_operations`, and the
//!   federation ingest path.
//! - `validate_operation_policy` — high-level policy gate (plaintext-Space gating + B-09 redact
//!   constraints).
//! - `validate_canonical_json_value` (+ `_inner`) — the canonical-JSON shape gate that operation
//!   payloads MUST pass.
//! - `validate_content_blocks` / `validate_mentions` / `validate_content_block` — message body
//!   shape.
//! - `validate_encrypted_payload_envelope` — `cx.profile.encrypted_payload.v1` envelope shape (MLS
//!   sender / scheme / version / `key_ref`).
//! - `validate_device_message_payload` — to-device payload shape.
//! - `validate_no_removed_legacy_contracts` (+ scanners) — kicks payloads that reference the
//!   removed legacy `cx.subject.*` / `cx.room.*` / `cx.card.*` contracts.
//! - `validate_rfc3339_utc_z` — UTC-Z timestamp shape.
//! - `canonical_json_digest` — sha256 over canonical-JSON bytes.
//!
//! Spec items still pending here are tracked in `_todos.md` (notably
//! Stream-A19 for B-09 redact `actor_seq` preservation, B-22 for
//! encrypted-attachment `key_ref` shape, and the operation-schema gaps
//! around the 100+ event kinds the reducer doesn't cover yet).

use contrix_sdk::{Hash, Operation};
use serde_json::Value;

use super::{is_json_integer, is_valid_entity_type, is_valid_sha256_digest, validate_did};
use crate::kinds;
use crate::state::AppState;

#[derive(Clone, Copy)]
pub struct OperationPayloadSchema {
    schema_id: &'static str,
    requirements: &'static [PayloadRequirement],
    validate: Option<fn(&Operation) -> Result<(), &'static str>>,
}

#[derive(Clone, Copy)]
pub enum PayloadRequirement {
    Required(&'static str, &'static str),
    AnyOf(&'static [&'static str], &'static str),
}

const MESSAGE_CREATE_FIELDS: &[&str] = &["body", "content", "event_id"];
const MESSAGE_TARGET_FIELDS: &[&str] = &["target_event_id", "event_id", "target"];
const MESSAGE_CONTENT_FIELDS: &[&str] = &["content", "body"];
const REDACTION_TARGET_FIELDS: &[&str] = &["target_event_id", "target", "redacts"];
const REACTION_TARGET_FIELDS: &[&str] = &[
    "event_id",
    "target_event_id",
    "message_id",
    "target_message_id",
];
const REACTION_ACTOR_FIELDS: &[&str] = &["actor", "sender"];
const REACTION_KEY_FIELDS: &[&str] = &["key", "reaction", "reaction_key"];
const ENTITY_ID_FIELDS: &[&str] = &["entity_id", "id"];
const ENTITY_TYPE_FIELDS: &[&str] = &["entity_type", "type"];
const RELATION_ID_FIELDS: &[&str] = &["relation_id", "id"];
const RELATION_KIND_FIELDS: &[&str] = &["relation_kind", "kind"];
const RELATION_FROM_FIELDS: &[&str] = &["from", "from_entity_id"];
const RELATION_TO_FIELDS: &[&str] = &["to", "to_entity_id"];
const MEMBER_ACTOR_FIELDS: &[&str] = &["member", "actor", "sender"];
const READ_MARKER_ACTOR_FIELDS: &[&str] = &["actor", "sender"];

const MESSAGE_CREATE_REQUIREMENTS: &[PayloadRequirement] = &[PayloadRequirement::AnyOf(
    MESSAGE_CREATE_FIELDS,
    "message operation requires body, content, or event_id",
)];
const MESSAGE_REVISE_REQUIREMENTS: &[PayloadRequirement] = &[
    PayloadRequirement::AnyOf(
        MESSAGE_TARGET_FIELDS,
        "message revision requires target_event_id",
    ),
    PayloadRequirement::AnyOf(
        MESSAGE_CONTENT_FIELDS,
        "message revision requires content or body",
    ),
];
const REDACTION_REQUIREMENTS: &[PayloadRequirement] = &[PayloadRequirement::AnyOf(
    REDACTION_TARGET_FIELDS,
    "redaction operation requires target_event_id",
)];
const REACTION_REQUIREMENTS: &[PayloadRequirement] = &[
    PayloadRequirement::AnyOf(
        REACTION_TARGET_FIELDS,
        "reaction operation requires target event",
    ),
    PayloadRequirement::AnyOf(REACTION_ACTOR_FIELDS, "reaction operation requires actor"),
    PayloadRequirement::AnyOf(
        REACTION_KEY_FIELDS,
        "reaction operation requires reaction key",
    ),
];
const ENTITY_CREATE_REQUIREMENTS: &[PayloadRequirement] = &[
    PayloadRequirement::AnyOf(ENTITY_ID_FIELDS, "entity operation requires entity_id"),
    PayloadRequirement::AnyOf(ENTITY_TYPE_FIELDS, "entity create requires entity_type"),
];
const ENTITY_ID_REQUIREMENTS: &[PayloadRequirement] = &[PayloadRequirement::AnyOf(
    ENTITY_ID_FIELDS,
    "entity operation requires entity_id",
)];
const RELATION_CREATE_REQUIREMENTS: &[PayloadRequirement] = &[
    PayloadRequirement::AnyOf(
        RELATION_ID_FIELDS,
        "relation operation requires relation_id",
    ),
    PayloadRequirement::AnyOf(
        RELATION_KIND_FIELDS,
        "relation create requires relation_kind",
    ),
    PayloadRequirement::AnyOf(RELATION_FROM_FIELDS, "relation create requires from"),
    PayloadRequirement::AnyOf(RELATION_TO_FIELDS, "relation create requires to"),
];
const RELATION_ID_REQUIREMENTS: &[PayloadRequirement] = &[PayloadRequirement::AnyOf(
    RELATION_ID_FIELDS,
    "relation operation requires relation_id",
)];
const MEMBERSHIP_REQUIREMENTS: &[PayloadRequirement] = &[
    PayloadRequirement::AnyOf(MEMBER_ACTOR_FIELDS, "membership operation requires member"),
    PayloadRequirement::Required(
        "membership",
        "membership operation requires member and membership",
    ),
];
const SPACE_LIFECYCLE_REQUIREMENTS: &[PayloadRequirement] = &[PayloadRequirement::Required(
    "action",
    "space lifecycle operation requires action",
)];
const READ_MARKER_REQUIREMENTS: &[PayloadRequirement] = &[
    PayloadRequirement::AnyOf(
        READ_MARKER_ACTOR_FIELDS,
        "read marker operation requires actor",
    ),
    PayloadRequirement::Required("event_id", "read marker operation requires event_id"),
];

const REMOVED_LEGACY_TYPED_ID_PREFIXES: &[&str] = &["cx:subject:", "cx:room:", "cx:card:"];
const REMOVED_LEGACY_SCHEMA_IDS: &[&str] = &[
    "cx.schema.subject.v1",
    "cx.schema.room.v1",
    "cx.schema.card.v1",
];
const REMOVED_LEGACY_EVENT_PREFIXES: &[&str] = &["cx.subject.", "cx.room.", "cx.card."];
const ACTIVE_WIRE_LEGACY_CONTRACT_ERROR: &str =
    "removed legacy subject/room/card contract is forbidden on the active v1 wire";

pub fn is_removed_legacy_contract_string(value: &str) -> bool {
    REMOVED_LEGACY_TYPED_ID_PREFIXES
        .iter()
        .any(|prefix| value.starts_with(prefix))
        || REMOVED_LEGACY_SCHEMA_IDS
            .iter()
            .any(|schema_id| value == *schema_id)
        || REMOVED_LEGACY_EVENT_PREFIXES
            .iter()
            .any(|prefix| value.starts_with(prefix))
}

pub fn value_contains_removed_legacy_contract(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::String(value) => is_removed_legacy_contract_string(value),
        serde_json::Value::Array(values) => {
            values.iter().any(value_contains_removed_legacy_contract)
        }
        serde_json::Value::Object(object) => object.iter().any(|(key, value)| {
            matches!(key.as_str(), "room_id" | "card_id" | "subject_id")
                || value_contains_removed_legacy_contract(value)
        }),
        _ => false,
    }
}

pub fn validate_no_removed_legacy_contracts(value: &serde_json::Value) -> Result<(), &'static str> {
    if value_contains_removed_legacy_contract(value) {
        Err(ACTIVE_WIRE_LEGACY_CONTRACT_ERROR)
    } else {
        Ok(())
    }
}

pub fn validate_operation_semantics(
    state: &AppState,
    operations: &[Operation],
) -> Result<(), &'static str> {
    let schemas = state.persistence.schemas();
    for operation in operations {
        operation
            .validate_payload_object()
            .map_err(|_| "operation payload must be a JSON object")?;
        if is_removed_legacy_contract_string(operation.object_type.as_str())
            || operation
                .object_id
                .as_deref()
                .is_some_and(is_removed_legacy_contract_string)
        {
            return Err(ACTIVE_WIRE_LEGACY_CONTRACT_ERROR);
        }
        validate_no_removed_legacy_contracts(&operation.payload)?;
        validate_canonical_json_value(&operation.payload)?;
        let Some(kind) = kinds::canonical_kind_for_operation(operation) else {
            return Err("unregistered operation kind");
        };
        let Some(schema) = operation_schema_for_kind(kind) else {
            return Err("unregistered operation kind");
        };
        let registered = schemas
            .get(schema.schema_id)
            .ok()
            .flatten()
            .is_some_and(|record| record.active && record.kind == "operation");
        if !registered {
            return Err("operation schema is not registered");
        }
        validate_operation_schema(operation, schema)?;
    }
    Ok(())
}

pub fn operation_schema_for_kind(kind: &str) -> Option<OperationPayloadSchema> {
    let schema = match kind {
        kinds::CX_MESSAGE_CREATE => OperationPayloadSchema {
            schema_id: "cx.schema.operation.message_create.v1",
            requirements: MESSAGE_CREATE_REQUIREMENTS,
            validate: Some(validate_message_operation_payload),
        },
        kinds::CX_MESSAGE_REVISE => OperationPayloadSchema {
            schema_id: "cx.schema.operation.message_revise.v1",
            requirements: MESSAGE_REVISE_REQUIREMENTS,
            validate: Some(validate_message_operation_payload),
        },
        kinds::CX_MESSAGE_REDACT | kinds::CX_REDACTION => OperationPayloadSchema {
            schema_id: "cx.schema.operation.redaction.v1",
            requirements: REDACTION_REQUIREMENTS,
            validate: None,
        },
        kinds::CX_REACTION_ADD | kinds::CX_REACTION_REMOVE => OperationPayloadSchema {
            schema_id: "cx.schema.operation.reaction.v1",
            requirements: REACTION_REQUIREMENTS,
            validate: None,
        },
        kinds::CX_ENTITY_CREATE => OperationPayloadSchema {
            schema_id: "cx.schema.operation.entity_create.v1",
            requirements: ENTITY_CREATE_REQUIREMENTS,
            validate: Some(validate_entity_create_operation_payload),
        },
        kinds::CX_ENTITY_UPDATE | kinds::CX_ENTITY_DELETE => OperationPayloadSchema {
            schema_id: "cx.schema.operation.entity_mutation.v1",
            requirements: ENTITY_ID_REQUIREMENTS,
            validate: None,
        },
        kinds::CX_RELATION_CREATE => OperationPayloadSchema {
            schema_id: "cx.schema.operation.relation_create.v1",
            requirements: RELATION_CREATE_REQUIREMENTS,
            validate: None,
        },
        kinds::CX_RELATION_UPDATE | kinds::CX_RELATION_DELETE => OperationPayloadSchema {
            schema_id: "cx.schema.operation.relation_mutation.v1",
            requirements: RELATION_ID_REQUIREMENTS,
            validate: None,
        },
        kinds::CX_READ_MARKER => OperationPayloadSchema {
            schema_id: "cx.schema.operation.read_marker.v1",
            requirements: READ_MARKER_REQUIREMENTS,
            validate: None,
        },
        kind if kinds::is_membership_kind(kind) => OperationPayloadSchema {
            schema_id: "cx.schema.operation.membership.v1",
            requirements: MEMBERSHIP_REQUIREMENTS,
            validate: None,
        },
        kind if kinds::is_space_lifecycle_kind(kind) => OperationPayloadSchema {
            schema_id: "cx.schema.operation.space_lifecycle.v1",
            requirements: SPACE_LIFECYCLE_REQUIREMENTS,
            validate: None,
        },
        kind if matches!(
            kind,
            kinds::CX_FIELD_POSITION_MOVE | kinds::CX_FIELD_POSITION_REORDER
        ) =>
        {
            OperationPayloadSchema {
                schema_id: "cx.schema.operation.entity_mutation.v1",
                requirements: ENTITY_ID_REQUIREMENTS,
                validate: None,
            }
        }
        kind if matches!(
            kind,
            kinds::CX_CONTAINER_MOVE_ITEM | kinds::CX_CONTAINER_REBALANCE
        ) =>
        {
            OperationPayloadSchema {
                schema_id: "cx.schema.operation.relation_mutation.v1",
                requirements: RELATION_ID_REQUIREMENTS,
                validate: None,
            }
        }
        _ => return None,
    };
    Some(schema)
}

pub fn validate_operation_schema(
    operation: &Operation,
    schema: OperationPayloadSchema,
) -> Result<(), &'static str> {
    for requirement in schema.requirements {
        match requirement {
            PayloadRequirement::Required(field, message) => {
                if !payload_field_present(&operation.payload, field) {
                    return Err(message);
                }
            }
            PayloadRequirement::AnyOf(fields, message) => {
                if !fields
                    .iter()
                    .any(|field| payload_field_present(&operation.payload, field))
                {
                    return Err(message);
                }
            }
        }
    }
    if let Some(validate) = schema.validate {
        validate(operation)?;
    }
    Ok(())
}

pub fn payload_field_present(payload: &serde_json::Value, field: &str) -> bool {
    payload.get(field).is_some_and(|value| !value.is_null())
}

pub fn validate_message_operation_payload(operation: &Operation) -> Result<(), &'static str> {
    if operation
        .payload
        .get("encrypted")
        .and_then(|value| value.as_bool())
        .unwrap_or(false)
    {
        let Some(content) = operation.payload.get("content") else {
            return Err("encrypted message operation requires content envelope");
        };
        validate_encrypted_payload_envelope(content)?;
    } else if let Some(content) = operation.payload.get("content") {
        validate_content_blocks(content)?;
        validate_mentions(content)?;
    }
    Ok(())
}

pub fn validate_entity_create_operation_payload(operation: &Operation) -> Result<(), &'static str> {
    let Some(entity_type) = operation
        .payload
        .get("entity_type")
        .or_else(|| operation.payload.get("type"))
        .and_then(Value::as_str)
    else {
        return Err("entity create requires string entity_type");
    };
    if is_valid_entity_type(entity_type) {
        Ok(())
    } else {
        Err("entity_type must be a supported cx.* object type or a reverse-domain custom type")
    }
}

pub fn validate_operation_policy(
    state: &AppState,
    operations: &[Operation],
) -> Result<(), &'static str> {
    for operation in operations {
        if kinds::operation_is_message_create(operation)
            && !message_operation_is_encrypted(operation)
            && known_space_denies_plaintext_service(state, operation.space_id.as_str())
        {
            return Err(
                "private plaintext message operations require this service in plaintext_visible_services",
            );
        }
    }
    Ok(())
}

pub fn message_operation_is_encrypted(operation: &Operation) -> bool {
    operation
        .payload
        .get("encrypted")
        .and_then(|value| value.as_bool())
        .unwrap_or(false)
}

pub fn known_space_denies_plaintext_service(state: &AppState, space_id: &str) -> bool {
    state
        .persistence
        .space_meta()
        .get(space_id)
        .ok()
        .flatten()
        .is_some_and(|record| {
            record.discoverability != "public"
                && !record
                    .plaintext_visible_services
                    .contains(&state.config.service_did)
        })
}

pub fn validate_device_message_payload(content: &serde_json::Value) -> Result<(), &'static str> {
    let Some(message) = content.as_object() else {
        return Err("device message must be a JSON object");
    };
    if !message
        .get("type")
        .and_then(|value| value.as_str())
        .is_some_and(|value| !value.trim().is_empty())
    {
        return Err("device message requires type");
    }
    let Some(envelope) = message.get("content") else {
        return Err("device message requires encrypted content envelope");
    };
    validate_encrypted_payload_envelope(envelope)
}

pub fn validate_content_blocks(content: &serde_json::Value) -> Result<(), &'static str> {
    let Some(blocks) = content.get("blocks") else {
        return Ok(());
    };
    let Some(blocks) = blocks.as_array() else {
        return Err("content.blocks must be an array");
    };
    if blocks.is_empty() {
        return Err("content.blocks must not be empty");
    }
    for block in blocks {
        validate_content_block(block)?;
    }
    Ok(())
}

pub fn validate_mentions(content: &serde_json::Value) -> Result<(), &'static str> {
    let Some(mentions) = content.get("mentions") else {
        return Ok(());
    };
    let Some(mentions) = mentions.as_array() else {
        return Err("mentions must be an array");
    };
    for mention in mentions {
        if let Some(did) = mention.as_str() {
            validate_did(did).map_err(|_| "mention DID is invalid")?;
            continue;
        }
        let Some(mention) = mention.as_object() else {
            return Err("mention must be a DID string or reference object");
        };
        match mention.get("type").and_then(|value| value.as_str()) {
            Some("actor") => {
                let Some(did) = mention.get("did").and_then(|value| value.as_str()) else {
                    return Err("actor mention requires did");
                };
                validate_did(did).map_err(|_| "mention DID is invalid")?;
            }
            Some("entity") => {
                if !mention
                    .get("entity_id")
                    .and_then(|value| value.as_str())
                    .is_some_and(|value| value.starts_with("cx:entity:"))
                {
                    return Err("entity mention requires entity_id");
                }
            }
            _ => return Err("mention type must be actor or entity"),
        }
    }
    Ok(())
}

pub fn validate_canonical_json_value(value: &serde_json::Value) -> Result<(), &'static str> {
    validate_canonical_json_value_inner(value, true)
}

pub fn validate_canonical_json_value_inner(
    value: &serde_json::Value,
    root: bool,
) -> Result<(), &'static str> {
    match value {
        serde_json::Value::Number(number) => {
            if number.as_i64().is_none() && number.as_u64().is_none() {
                return Err("canonical JSON does not allow floating point numbers");
            }
        }
        serde_json::Value::Array(values) => {
            for value in values {
                validate_canonical_json_value_inner(value, false)?;
            }
        }
        serde_json::Value::Object(object) => {
            let mut prev_key: Option<&str> = None;
            for key in object.keys() {
                // snake_case validation: lowercase alphanumeric and underscores,
                // with an exception for $-prefixed JSON Schema fields ($id, $schema, $ref, etc.).
                if key.is_empty() {
                    return Err("canonical JSON field name must not be empty");
                }
                let name_part = if let Some(stripped) = key.strip_prefix('$') {
                    if stripped.is_empty() {
                        return Err("canonical JSON field name '$' alone is not valid");
                    }
                    stripped
                } else {
                    key.as_str()
                };
                if !name_part
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
                {
                    return Err(
                        "canonical JSON field name must be snake_case (lowercase alphanumeric and underscores)",
                    );
                }
                if name_part.starts_with('_') || name_part.ends_with('_') {
                    return Err("canonical JSON field name must not start or end with underscore");
                }
                if name_part.contains("__") {
                    return Err(
                        "canonical JSON field name must not contain consecutive underscores",
                    );
                }
                // Unicode code point ascending order.
                if let Some(prev) = prev_key {
                    if key.as_bytes() <= prev.as_bytes() {
                        return Err("canonical JSON object keys must be sorted in ascending order");
                    }
                }
                prev_key = Some(key);
            }
            for value in object.values() {
                validate_canonical_json_value_inner(value, false)?;
            }
            // RFC3339 UTC Z timestamp validation for fields named *_at or *_at_ms.
            for (key, value) in object {
                if key.ends_with("_at") {
                    if let Some(s) = value.as_str() {
                        validate_rfc3339_utc_z(s)?;
                    }
                }
            }
        }
        _ => {}
    }
    // At the top level, attempt a canonical byte roundtrip to ensure full compliance.
    if root {
        if let Err(_) = contrix_sdk::canonical::canonical_json_bytes(value) {
            return Err("value fails canonical JSON byte serialization");
        }
    }
    Ok(())
}

pub fn validate_rfc3339_utc_z(s: &str) -> Result<(), &'static str> {
    // Must end with 'Z' (UTC) and contain 'T' separator.
    if !s.ends_with('Z') {
        return Err("timestamp must use UTC 'Z' suffix");
    }
    if !s.contains('T') {
        return Err("timestamp must use 'T' date-time separator");
    }
    // Basic structural validation: YYYY-MM-DDTHH:MM:SS...Z
    let date_part = &s[..s.find('T').unwrap()];
    let time_part = &s[s.find('T').unwrap() + 1..s.len() - 1];
    let date_segments: Vec<&str> = date_part.split('-').collect();
    if date_segments.len() != 3 {
        return Err("timestamp date must be YYYY-MM-DD");
    }
    if date_segments[0].len() != 4 || date_segments[1].len() != 2 || date_segments[2].len() != 2 {
        return Err("timestamp date segments must be zero-padded");
    }
    // Time must have at least HH:MM:SS.
    let time_segments: Vec<&str> = time_part.split(':').collect();
    if time_segments.len() < 3 {
        return Err("timestamp time must be HH:MM:SS[Z]");
    }
    Ok(())
}

/// Compute a canonical SHA-256 digest of a JSON value using SDK canonical encoding.
#[allow(dead_code)]
pub fn canonical_json_digest(value: &serde_json::Value) -> Result<Hash, String> {
    contrix_sdk::canonical::canonical_sha256(value)
        .and_then(|digest| {
            Hash::new(digest).map_err(|e| contrix_sdk::Error::Protocol(e.to_string()))
        })
        .map_err(|e| e.to_string())
}

pub fn validate_content_block(block: &serde_json::Value) -> Result<(), &'static str> {
    let Some(block) = block.as_object() else {
        return Err("content block must be a JSON object");
    };
    // Per spec 2026-05-09 (C21): content_block.type → content_block.kind.
    // Accept new `kind` only; v1 not yet released → no compat for legacy `type`.
    let Some(block_kind) = block.get("kind").and_then(|value| value.as_str()) else {
        return Err("content block requires kind");
    };
    match block_kind {
        "text" | "formatted_text" => {
            if !block
                .get("text")
                .and_then(|value| value.as_str())
                .is_some_and(|value| !value.trim().is_empty())
            {
                return Err("text content block requires text");
            }
        }
        "code" => {
            if !block
                .get("text")
                .and_then(|value| value.as_str())
                .is_some_and(|value| !value.is_empty())
            {
                return Err("code content block requires text");
            }
        }
        "image" | "video" | "audio" | "file" => {
            let has_blob_ref = block
                .get("blob_ref")
                .and_then(|value| value.as_str())
                .is_some_and(|value| value.starts_with("cx:blob:sha256:"));
            let has_url = block
                .get("url")
                .and_then(|value| value.as_str())
                .is_some_and(|value| !value.trim().is_empty());
            if !has_blob_ref && !has_url {
                return Err("media content block requires blob_ref or url");
            }
        }
        "location" => {
            if !block.get("latitude").is_some_and(is_json_integer)
                || !block.get("longitude").is_some_and(is_json_integer)
            {
                return Err("location content block requires latitude and longitude");
            }
        }
        "poll" => {
            if !block
                .get("question")
                .and_then(|value| value.as_str())
                .is_some_and(|value| !value.trim().is_empty())
                || !block
                    .get("options")
                    .and_then(|value| value.as_array())
                    .is_some_and(|options| options.len() >= 2)
            {
                return Err("poll content block requires question and at least two options");
            }
        }
        _ => return Err("unsupported content block type"),
    }
    Ok(())
}

pub fn validate_encrypted_payload_envelope(
    content: &serde_json::Value,
) -> Result<(), &'static str> {
    let Some(envelope) = content.as_object() else {
        return Err("encrypted content must be a JSON object");
    };
    for field in [
        "scheme",
        "group_id",
        "content_type",
        "ciphertext",
        "authentication_tag",
    ] {
        if !envelope
            .get(field)
            .and_then(|value| value.as_str())
            .is_some_and(|value| !value.trim().is_empty())
        {
            return Err("encrypted content envelope is missing required string fields");
        }
    }
    if !envelope
        .get("version")
        .is_some_and(|value| value.as_u64().is_some() || value.as_str().is_some())
    {
        return Err("encrypted content envelope requires version");
    }
    if !envelope
        .get("epoch")
        .is_some_and(|value| value.as_u64().is_some())
    {
        return Err("encrypted content envelope requires numeric epoch");
    }
    if !envelope.get("aad").is_some() {
        return Err("encrypted content envelope requires aad");
    }
    if !envelope
        .get("key_ref")
        .is_some_and(|value| value.is_object() || value.as_str().is_some())
    {
        return Err("encrypted content envelope requires key_ref");
    }
    let Some(digests) = envelope.get("digests").and_then(|value| value.as_object()) else {
        return Err("encrypted content envelope requires digests");
    };
    if digests.is_empty() {
        return Err("encrypted content envelope requires digests");
    }
    if !digests.values().all(|value| {
        value
            .as_str()
            .is_some_and(|digest| is_valid_sha256_digest(digest))
    }) {
        return Err("encrypted content envelope digests must be sha256:<64 lowercase hex>");
    }
    Ok(())
}
