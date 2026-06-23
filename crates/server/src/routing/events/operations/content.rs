use super::*;

pub(crate) async fn realm_requires_content_encryption(state: &AppState, realm_id: &str) -> bool {
    let store = state.persistence.realm_meta();
    let realm_meta = store.get(realm_id).await.ok().flatten();
    realm_meta.is_some_and(|record| {
        encryption_profile_requires_content_encryption(record.encryption_profile.as_deref())
    })
}

/// Whether the Realm's effective `content_encryption_floor` requires E2EE
/// content, read from the authoritative reducer projection (set by
/// `ck.realm.policy_components`). This is independent of `encryption_profile`,
/// which only declares the encryption mechanism: a `mls_rfc9420` Realm admits
/// plaintext content until its content floor is raised to `e2ee_required`
/// (realm-and-space.md §2.3 / §2.5, circle.md §7). The floor is a one-way
/// ratchet enforced by the reducer, so this read can only flip false→true.
pub(crate) fn realm_content_floor_requires_e2ee(state: &AppState, realm_id: &str) -> bool {
    state
        .projection
        .lock()
        .ok()
        .and_then(|projection| projection.realm_content_encryption_floor(realm_id))
        .as_deref()
        == Some("e2ee_required")
}

pub(crate) fn encryption_profile_requires_content_encryption(profile: Option<&str>) -> bool {
    // Current soland RealmMetaRecord projects the encryption mechanism but not
    // the separate content_encryption_floor field yet. Treat any non-plaintext
    // profile as content-only E2EE for Strand content admission.
    profile
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .is_some_and(|profile| !matches!(profile, "none" | "plaintext" | "allow_plaintext"))
}

pub(crate) fn operation_circle_encryption_profile(operation: &Operation) -> Option<&str> {
    operation
        .payload
        .get("object")
        .and_then(|object| object.get("encryption_profile"))
        .and_then(Value::as_str)
        .or_else(|| {
            operation
                .payload
                .get("encryption_profile")
                .and_then(Value::as_str)
        })
}

pub(crate) fn operation_touches_encryption_profile(operation: &Operation) -> bool {
    operation.payload.get("encryption_profile").is_some()
        || operation
            .payload
            .get("object")
            .is_some_and(|object| value_has_direct_field(object, "encryption_profile"))
        || patch_touches_field(&operation.payload, "encryption_profile")
}

fn value_has_direct_field(value: &Value, field: &str) -> bool {
    value
        .as_object()
        .is_some_and(|object| object.contains_key(field))
}

fn patch_touches_field(payload: &Value, field: &str) -> bool {
    payload
        .get("patch")
        .and_then(Value::as_object)
        .is_some_and(|patch| {
            patch
                .iter()
                .any(|(key, value)| patch_entry_touches_field(key, value, field))
        })
}

fn patch_entry_touches_field(key: &str, value: &Value, field: &str) -> bool {
    patch_key_touches_field(key, field)
        || (key == "object" && patch_operation_value_has_direct_field(value, field))
}

fn patch_key_touches_field(key: &str, field: &str) -> bool {
    let dotted = format!("{field}.");
    let pointer = format!("/{field}");
    let pointer_child = format!("/{field}/");
    let object_dotted = format!("object.{field}");
    let object_dotted_child = format!("object.{field}.");
    let object_pointer = format!("/object/{field}");
    let object_pointer_child = format!("/object/{field}/");
    key == field
        || key.starts_with(&dotted)
        || key == pointer
        || key.starts_with(&pointer_child)
        || key == object_dotted
        || key.starts_with(&object_dotted_child)
        || key == object_pointer
        || key.starts_with(&object_pointer_child)
}

fn patch_operation_value_has_direct_field(value: &Value, field: &str) -> bool {
    value
        .get("value")
        .unwrap_or(value)
        .as_object()
        .is_some_and(|object| object.contains_key(field))
}

pub(crate) fn strand_operation_carries_plaintext_private_content(operation: &Operation) -> bool {
    match kinds::canonical_kind_for_operation(operation) {
        Some(cokret_sdk::events::kinds::STRAND_CREATE) => [
            &["synthesis"][..],
            &["object", "synthesis"][..],
            &["content"][..],
            &["object", "content"][..],
            &["attachments"][..],
            &["object", "attachments"][..],
        ]
        .iter()
        .any(|path| {
            value_at_path(&operation.payload, path).is_some_and(value_is_plaintext_content)
        }),
        Some(cokret_sdk::events::kinds::STRAND_UPDATE) => patch_touches_plaintext_content_path(
            &operation.payload,
            &["synthesis", "content", "attachments"],
        ),
        _ => false,
    }
}

fn value_at_path<'a>(value: &'a Value, path: &[&str]) -> Option<&'a Value> {
    let mut current = value;
    for segment in path {
        current = current.get(*segment)?;
    }
    Some(current)
}

fn value_is_plaintext_content(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::String(text) => !text.trim().is_empty(),
        Value::Array(values) => !values.is_empty(),
        Value::Object(object) => {
            !object.is_empty()
                && !encrypted_payload_value(value)
                && !object
                    .get("encrypted_content")
                    .is_some_and(encrypted_payload_value)
        }
        Value::Bool(_) | Value::Number(_) => true,
    }
}

fn encrypted_payload_value(value: &Value) -> bool {
    validate_encrypted_payload_envelope(value).is_ok() || sdk_encrypted_payload_value(value)
}

// Strand content-floor admission only needs to distinguish ciphertext-shaped
// content from plaintext. Message/device validators still enforce the stricter
// wire envelope shape through `validate_encrypted_payload_envelope`.
fn sdk_encrypted_payload_value(value: &Value) -> bool {
    let Some(envelope) = value.as_object() else {
        return false;
    };
    for field in ["scheme", "group_id", "content_type", "ciphertext"] {
        if envelope
            .get(field)
            .and_then(Value::as_str)
            .is_none_or(|value| value.trim().is_empty())
        {
            return false;
        }
    }
    envelope
        .get("epoch")
        .is_some_and(|value| value.as_u64().is_some())
        && envelope
            .get("payload_digest")
            .and_then(Value::as_str)
            .is_some_and(is_valid_hash_digest)
}

fn patch_operation_value_is_plaintext_content(value: &Value) -> bool {
    if let Some(object) = value.as_object()
        && object.get("$op").and_then(Value::as_str) == Some("unset")
    {
        return false;
    }
    value.get("value").map_or_else(
        || value_is_plaintext_content(value),
        value_is_plaintext_content,
    )
}

fn patch_value_contains_plaintext_content_path(value: &Value, path: &str) -> bool {
    let Some(candidate) = value.get("value").unwrap_or(value).pointer(&format!(
        "/{}",
        path.split('.').collect::<Vec<_>>().join("/")
    )) else {
        return false;
    };
    value_is_plaintext_content(candidate)
}

fn patch_touches_plaintext_content_path(payload: &Value, private_paths: &[&str]) -> bool {
    payload
        .get("patch")
        .and_then(Value::as_object)
        .is_some_and(|patch| {
            patch.iter().any(|(key, value)| {
                private_paths.iter().any(|private_path| {
                    if key == private_path || key.starts_with(&format!("{private_path}.")) {
                        patch_operation_value_is_plaintext_content(value)
                    } else if let Some(suffix) = private_path.strip_prefix(&format!("{key}.")) {
                        patch_value_contains_plaintext_content_path(value, suffix)
                    } else {
                        false
                    }
                })
            })
        })
}

pub fn message_operation_is_encrypted(operation: &Operation) -> bool {
    operation
        .payload
        .get("encrypted")
        .and_then(|value| value.as_bool())
        .unwrap_or(false)
        || operation.payload.get("encrypted_content").is_some()
}

pub async fn known_realm_denies_plaintext_service(state: &AppState, realm_id: &str) -> bool {
    state
        .persistence
        .realm_meta()
        .get(realm_id)
        .await
        .ok()
        .flatten()
        .is_some_and(|record| {
            !(record.allows_plaintext_data_class(
                &state.config.service_did,
                cokret_sdk::PlaintextDataClassKind::MessageContent,
            ) || record.discoverability == "public"
                && record.history_visibility == "world_readable")
        })
}

// Transport-shape check for a to-device target. `DeviceMessageTarget` already
// guarantees the outer object shape, a present `kind`, and a present `content`
// at deserialization, so the only runtime checks left are a non-blank `kind`
// and a JSON-object `content`.
//
// Per crypto-media/device-lifecycle.md §7, to-device content SHOULD be
// end-to-end encrypted, but cleartext is explicitly permitted for capability
// discovery and verification bootstrap (`ck.key.verification.*`), and the
// secret-share request (`ck.secret.request`) carries only a one-time HPKE
// public key. The secret response (`ck.secret.send`) is HPKE-sealed but uses
// its own envelope shape (§10.7), not the MLS Realm `encrypted_envelope`. The
// to-device queue is zero-knowledge and does not validate E2EE content
// semantics; it only requires a content object so routing and
// `DeviceMessageEnvelope` materialization succeed. Forcing the MLS
// `encrypted_envelope` shape here would reject the very `ck.key.verification.*`
// strand advertised by the device_messages describe surface.
pub fn validate_device_message_target(target: &DeviceMessageTarget) -> Result<(), &'static str> {
    if target.kind.trim().is_empty() {
        return Err("device message requires kind");
    }
    if !target.content.is_object() {
        return Err("device message content must be a JSON object");
    }
    Ok(())
}

pub fn validate_content_blocks(content: &serde_json::Value) -> Result<(), &'static str> {
    if content.get("blocks").is_some() {
        return Err("content.blocks is not permitted; use content.parts");
    }
    validate_content_block(content)
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
        if mention.get("kind").and_then(Value::as_str) == Some("audience_mention") {
            validate_audience_mention_object(mention)?;
            continue;
        }
        if let Some(subject_id) = mention.get("subject_id").and_then(|value| value.as_str()) {
            validate_did(subject_id).map_err(|_| "mention subject_id is invalid")?;
            continue;
        }
        match mention.get("type").and_then(|value| value.as_str()) {
            Some("actor") => {
                let Some(did) = mention.get("did").and_then(|value| value.as_str()) else {
                    return Err("actor mention requires did");
                };
                validate_did(did).map_err(|_| "mention DID is invalid")?;
            }
            Some("strand") => {
                if !mention
                    .get("strand_id")
                    .and_then(|value| value.as_str())
                    .is_some_and(|value| value.starts_with("ck:strand:"))
                {
                    return Err("strand mention requires strand_id");
                }
            }
            _ => return Err("mention type must be actor or strand"),
        }
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AudienceMentionNode {
    audience: String,
}

impl AudienceMentionNode {
    pub(crate) fn audience(&self) -> &str {
        &self.audience
    }
}

pub(crate) fn operation_audience_mentions(
    operation: &Operation,
) -> Result<Vec<AudienceMentionNode>, &'static str> {
    let mut mentions = Vec::new();
    if let Some(content) = operation.payload.get("content") {
        collect_audience_mentions(content, &mut mentions)?;
    }
    if operation.payload.get("encrypted_content").is_some()
        && operation
            .payload
            .get("audience_mention_routing_hint")
            .is_some()
    {
        return Err("audience_mention_routing_hint unsupported without explicit E2EE profile");
    }
    Ok(mentions)
}

pub fn validate_audience_mentions(content: &serde_json::Value) -> Result<(), &'static str> {
    let mut mentions = Vec::new();
    collect_audience_mentions(content, &mut mentions)?;
    Ok(())
}

fn collect_audience_mentions(
    value: &serde_json::Value,
    out: &mut Vec<AudienceMentionNode>,
) -> Result<(), &'static str> {
    match value {
        Value::Object(object) => {
            if object.get("kind").and_then(Value::as_str) == Some("audience_mention") {
                let node = validate_audience_mention_object(object)?;
                out.push(node);
                return Ok(());
            }
            for value in object.values() {
                collect_audience_mentions(value, out)?;
            }
        }
        Value::Array(values) => {
            for value in values {
                collect_audience_mentions(value, out)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn validate_audience_mention_object(
    object: &serde_json::Map<String, Value>,
) -> Result<AudienceMentionNode, &'static str> {
    let audience = object
        .get("audience")
        .and_then(Value::as_str)
        .ok_or("audience_mention requires audience")?;
    if !AUDIENCE_MENTION_ALLOWED_AUDIENCES.contains(&audience) {
        return Err("audience_mention audience is invalid");
    }
    if object
        .get("mention_text_original")
        .and_then(Value::as_str)
        .is_some_and(|token| token.trim().eq_ignore_ascii_case("@online"))
    {
        return Err("presence-filtered audience mention requires an explicit profile");
    }
    if object
        .get("mention_text_original")
        .and_then(Value::as_str)
        .is_some_and(|token| token.trim().eq_ignore_ascii_case("@here"))
        && audience != "strand_engaged"
    {
        return Err("@here MUST map to audience strand_engaged");
    }
    Ok(AudienceMentionNode {
        audience: audience.to_owned(),
    })
}

/// Validate the keys of a `ck.patch.v1` map as patch *paths* per
/// `event-and-patch.md` §4.2.1. Unlike canonical JSON field names, a patch path
/// is a dot-separated sequence of snake_case identifier / quoted-identifier /
/// selector segments (e.g. `metadata.title`, `metadata.fields.review_status`).
/// Op values are validated separately by the canonical-JSON recursion.
fn validate_patch_map_paths(
    patch: &serde_json::Map<String, serde_json::Value>,
) -> Result<(), &'static str> {
    for path in patch.keys() {
        validate_patch_path(path)?;
    }
    Ok(())
}

pub(crate) fn validate_operation_patch_semantics(
    operation: &Operation,
) -> Result<(), &'static str> {
    let Some(patch) = operation.payload.get("patch").and_then(Value::as_object) else {
        return Ok(());
    };
    validate_patch_semantic_safety(patch)
}

pub(crate) fn validate_patch_semantic_safety(
    patch: &serde_json::Map<String, Value>,
) -> Result<(), &'static str> {
    for (path, value) in patch {
        if patch_path_targets_reducer_managed(path) {
            return Err(crate::error::reasons::PATCH_PATH_REDUCER_MANAGED);
        }
        if patch_op_removes_value(value) && patch_path_targets_redactable_unset(path) {
            return Err(crate::error::reasons::PATCH_UNSET_REDACTABLE_FIELD);
        }
    }
    Ok(())
}

fn patch_path_targets_reducer_managed(path: &str) -> bool {
    const FIELDS: &[&str] = &[
        "id",
        "schema",
        "realm_id",
        "created_by",
        "created_at",
        "updated_by",
        "updated_at",
        "state",
        "state_changed_at",
        "stage_changed_at",
        "deleted_at",
        "effective_scope",
        "actor_kind",
    ];
    let root = patch_segment_head(path.split('.').next().unwrap_or_default());
    if root == Some("object") {
        let second = path.split('.').nth(1).unwrap_or_default();
        return patch_segment_head(second).is_some_and(|field| FIELDS.contains(&field));
    }
    root.is_some_and(|field| FIELDS.contains(&field))
}

fn patch_path_targets_redactable_unset(path: &str) -> bool {
    const PATHS: &[&str] = &[
        "content",
        "encrypted_content",
        "encrypted_metadata",
        "encrypted_payload",
        "body",
        "attachments",
        "summary",
        "metadata.summary",
        "metadata.fields.summary",
    ];
    if path == "metadata" {
        return true;
    }
    PATHS
        .iter()
        .any(|redactable| path == *redactable || path.starts_with(&format!("{redactable}.")))
}

fn patch_segment_head(segment: &str) -> Option<&str> {
    if segment.starts_with('`') {
        return None;
    }
    let head = segment.split_once('[').map_or(segment, |(head, _)| head);
    (!head.is_empty()).then_some(head)
}

fn patch_op_removes_value(value: &Value) -> bool {
    value
        .as_object()
        .and_then(|object| object.get("$op").and_then(Value::as_str))
        .is_some_and(|op| matches!(op, "unset" | "remove"))
}

/// Validate a single patch path against the §4.2.1 ABNF. Returns the canonical
/// `patch_path_invalid` family reason on any violation.
fn validate_patch_path(path: &str) -> Result<(), &'static str> {
    const PATCH_PATH_INVALID: &str = "patch path is invalid (patch_path_invalid)";
    // §4.2.1 / §4.2.2: max 1024 bytes, max 16 segments.
    if path.is_empty() {
        return Err(PATCH_PATH_INVALID);
    }
    if path.len() > 1024 {
        return Err(PATCH_PATH_INVALID);
    }
    let mut segments = 0usize;
    for segment in path.split('.') {
        segments += 1;
        if segments > 16 {
            return Err(PATCH_PATH_INVALID);
        }
        if !patch_path_segment_is_valid(segment) {
            return Err(PATCH_PATH_INVALID);
        }
    }
    Ok(())
}

/// A single patch path segment: a snake_case identifier, an identifier with a
/// trailing stable-key selector (`field[key="..."]`), or a backtick-quoted
/// literal for non-snake_case keys (`\`Weird Key\``).
fn patch_path_segment_is_valid(segment: &str) -> bool {
    if segment.is_empty() {
        return false;
    }
    // Backtick-quoted identifier: `...` (literal backtick escaped as ``).
    if let Some(inner) = segment
        .strip_prefix('`')
        .and_then(|rest| rest.strip_suffix('`'))
    {
        return !inner.is_empty() && inner.chars().all(|c| ('\u{20}'..='\u{7f}').contains(&c));
    }
    // Selector segment: identifier "[" key-name "=" selector-value "]".
    if let Some(open) = segment.find('[') {
        let Some(rest) = segment.strip_suffix(']') else {
            return false;
        };
        let (head, selector) = (&segment[..open], &rest[open + 1..]);
        let Some((key_name, value)) = selector.split_once('=') else {
            return false;
        };
        return patch_path_identifier_is_valid(head)
            && patch_path_identifier_is_valid(key_name)
            // selector-value is a (JCS canonical) JSON string: quoted, non-empty.
            && value.len() >= 2
            && value.starts_with('"')
            && value.ends_with('"');
    }
    patch_path_identifier_is_valid(segment)
}

/// `^[a-z][a-z0-9_]{0,63}$` — the §4.2.1 identifier production.
fn patch_path_identifier_is_valid(identifier: &str) -> bool {
    let mut chars = identifier.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !first.is_ascii_lowercase() {
        return false;
    }
    if identifier.len() > 64 {
        return false;
    }
    chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

pub fn validate_canonical_json_value(value: &serde_json::Value) -> Result<(), &'static str> {
    validate_canonical_json_value_inner(value, true)
}

pub fn validate_canonical_json_value_inner(
    value: &serde_json::Value,
    root: bool,
) -> Result<(), &'static str> {
    match value {
        serde_json::Value::Number(number)
            if number.as_i64().is_none() && number.as_u64().is_none() =>
        {
            return Err("canonical JSON does not allow floating point numbers");
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
                if let Some(prev) = prev_key
                    && key.as_bytes() <= prev.as_bytes()
                {
                    return Err("canonical JSON object keys must be sorted in ascending order");
                }
                prev_key = Some(key);
            }
            for (key, value) in object {
                // A `patch` map is a ck.schema.patch.v1 (`ck.patch.v1`) field
                // delta: its keys are patch *paths* (dotted snake_case segments
                // per event-and-patch.md §4.2.1), not canonical JSON field names,
                // so they are validated as paths and their op values are recursed
                // into directly, bypassing the structural snake_case/no-dot
                // field-name rule that the generic object branch would impose.
                if key == "patch"
                    && let serde_json::Value::Object(patch) = value
                {
                    validate_patch_map_paths(patch)?;
                    for patch_value in patch.values() {
                        validate_canonical_json_value_inner(patch_value, false)?;
                    }
                    continue;
                }
                validate_canonical_json_value_inner(value, false)?;
            }
            // RFC3339 UTC Z timestamp validation for fields named *_at or *_at_ms.
            for (key, value) in object {
                if key.ends_with("_at")
                    && let Some(s) = value.as_str()
                {
                    cokret_sdk::canonical::validate_timestamp_canonical(s).map_err(
                        |_| "timestamp must be canonical RFC 3339 UTC (YYYY-MM-DDTHH:MM:SSZ)",
                    )?;
                }
            }
        }
        _ => {}
    }
    // At the top level, attempt a canonical byte roundtrip to ensure full compliance.
    if root && cokret_sdk::canonical::canonical_json_bytes(value).is_err() {
        return Err("value fails canonical JSON byte serialization");
    }
    Ok(())
}

pub fn validate_content_block(block: &serde_json::Value) -> Result<(), &'static str> {
    let Some(block) = block.as_object() else {
        return Err("content block must be a JSON object");
    };
    let Some(block_kind) = block.get("kind").and_then(|value| value.as_str()) else {
        return Err("content block requires kind");
    };
    if block.get("blocks").is_some() {
        return Err("content.blocks is not permitted; use content.parts");
    }
    let block_kind = block_kind.strip_prefix("ck.content.").unwrap_or(block_kind);
    match block_kind {
        "composite" => {
            let Some(parts) = block.get("parts").and_then(|value| value.as_array()) else {
                return Err("composite content block requires parts");
            };
            if parts.is_empty() {
                return Err("content.parts must not be empty");
            }
            for part in parts {
                validate_content_block(part)?;
            }
        }
        "text" | "formatted_text" => {
            if block
                .get("text")
                .or_else(|| block.get("body"))
                .and_then(|value| value.as_str())
                .is_none_or(|value| value.trim().is_empty())
            {
                return Err("text content block requires text");
            }
        }
        "code" => {
            if block
                .get("text")
                .or_else(|| block.get("body"))
                .and_then(|value| value.as_str())
                .is_none_or(str::is_empty)
            {
                return Err("code content block requires text");
            }
        }
        "image" | "video" | "audio" | "file" => {
            let has_blob_ref = block
                .get("blob_ref")
                .and_then(|value| value.as_str())
                .is_some_and(|value| value.starts_with("ck:blob:sha256:"));
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
            if block
                .get("question")
                .and_then(|value| value.as_str())
                .is_none_or(|value| value.trim().is_empty())
                || block
                    .get("options")
                    .and_then(|value| value.as_array())
                    .is_none_or(|options| options.len() < 2)
            {
                return Err("poll content block requires question and at least two options");
            }
        }
        "poll.response" => {
            if block
                .get("poll_id")
                .and_then(|value| value.as_str())
                .is_none_or(|value| value.trim().is_empty())
                || !(block
                    .get("choice")
                    .and_then(|value| value.as_str())
                    .is_some()
                    || block
                        .get("choices")
                        .and_then(|value| value.as_array())
                        .is_some_and(|choices| !choices.is_empty()))
            {
                return Err("poll response content block requires poll_id and choice");
            }
        }
        "poll.close" => {
            if block
                .get("poll_id")
                .and_then(|value| value.as_str())
                .is_none_or(|value| value.trim().is_empty())
            {
                return Err("poll close content block requires poll_id");
            }
        }
        "audience_mention" => {
            validate_audience_mention_object(block)?;
        }
        _ => return Err("unsupported content block type"),
    }
    Ok(())
}
