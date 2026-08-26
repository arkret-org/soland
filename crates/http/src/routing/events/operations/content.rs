use super::*;

pub(crate) async fn realm_requires_content_encryption(state: &AppState, realm_id: &str) -> bool {
    let realm_meta = state.realms().realm_metadata(realm_id).await.ok().flatten();
    realm_meta.is_some_and(|record| {
        encryption_profile_requires_content_encryption(record.encryption_profile.as_deref())
    })
}

/// Whether the Realm's effective `content_encryption_floor` requires E2EE
/// content, read from the authoritative reducer projection (set by
/// `ak.realm.policy_bundle`). This is independent of `encryption_profile`,
/// which only declares the encryption mechanism: a `mls_rfc9420` Realm admits
/// plaintext content until its content floor is raised to `e2ee_required`
/// (realm-and-space.md §2.3 / §2.5, circle.md §7). The floor is a one-way
/// ratchet enforced by the reducer, so this read can only flip false→true.
pub(crate) fn realm_content_floor_requires_e2ee(state: &AppState, realm_id: &str) -> bool {
    {
        let projection = state.projections().snapshot();
        projection.realm_content_encryption_floor(realm_id)
    }
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
        Some(arkret_wire::EventKind::StrandCreate) => [
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
        Some(arkret_wire::EventKind::StrandUpdate) => patch_touches_plaintext_content_path(
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
    validate_encrypted_payload_envelope(value).is_ok()
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
        .realms()
        .realm_metadata(realm_id)
        .await
        .ok()
        .flatten()
        .is_some_and(|record| {
            !record.allows_plaintext_data_class(
                state.service_id(),
                arkret_wire::PlaintextDataClassKind::MessageContent,
            )
        })
}

pub fn validate_content_blocks(content: &serde_json::Value) -> Result<(), &'static str> {
    validate_content_block(content)
}

/// Canonical mention admission for a Message Content Block tree.
///
/// The only admissible shapes are the spec AST nodes — `{"kind":"mention"}`
/// with a `did_core_id` `subject_id` and `{"kind":"audience_mention"}` with a
/// closed `audience` — both parsed by the SDK models that own the wire types.
pub fn validate_mentions(content: &serde_json::Value) -> Result<(), &'static str> {
    arkret_models_collaboration::events_payloads::collect_mention_nodes(content)
        .map(|_| ())
        .map_err(|error| error.message())
}

pub(crate) fn operation_audience_mentions(
    operation: &Operation,
) -> Result<Vec<arkret_models_collaboration::events_payloads::AudienceMention>, &'static str> {
    let mentions = match operation.payload.get("content") {
        Some(content) => audience_mention_nodes(content)?,
        None => Vec::new(),
    };
    Ok(mentions)
}

/// Direct-mention subject DIDs carried by a Message Content Block tree.
pub(crate) fn mention_subject_ids(
    content: &serde_json::Value,
) -> Result<Vec<arkret_identifiers::DidCoreId>, &'static str> {
    arkret_models_collaboration::events_payloads::collect_mention_subject_ids(content)
        .map_err(|error| error.message())
}

fn audience_mention_nodes(
    content: &serde_json::Value,
) -> Result<Vec<arkret_models_collaboration::events_payloads::AudienceMention>, &'static str> {
    arkret_models_collaboration::events_payloads::collect_audience_mention_nodes(content)
        .map_err(|error| error.message())
}

/// Which object kind an object-patch Event kind writes, when the kind names one.
///
/// This is payload knowledge - which object family the Event patches - and
/// deliberately NOT a copy of any reducer-managed path list: the paths stay in
/// `arkret_wire::patch::reducer_managed_patch_reason`, whose canonical source is
/// `registry/reducer-managed-path-registry.json`. Knowing the kind is what lets
/// the registered per-kind carve-outs through; the object-agnostic superset has
/// none, so it refuses the `ak.view.update` patch that `views.md` 3.1 defines as
/// the only way to tombstone a shared View.
pub(crate) fn patched_object_kind(kind: &arkret_wire::EventKind) -> Option<&'static str> {
    match kind {
        arkret_wire::EventKind::ProfileUpdate => Some("actor_profile"),
        arkret_wire::EventKind::CircleUpdate => Some("circle"),
        arkret_wire::EventKind::MorphUpdate => Some("morph"),
        arkret_wire::EventKind::RelationUpdate => Some("relation"),
        arkret_wire::EventKind::SpaceUpdate => Some("space"),
        arkret_wire::EventKind::StrandUpdate | arkret_wire::EventKind::StrandTracksUpdate => {
            Some("strand")
        }
        arkret_wire::EventKind::ViewUpdate => Some("view"),
        _ => None,
    }
}

pub(crate) fn validate_operation_patch_semantics(
    kind: &arkret_wire::EventKind,
    operation: &Operation,
) -> Result<(), &'static str> {
    let Some(patch) = operation.payload.get("patch").and_then(Value::as_object) else {
        return Ok(());
    };
    soland_domain::reducer::validate_patch_semantic_safety(patch, patched_object_kind(kind))
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
            // Field-name constraints belong to JSON Schema declarations, not
            // canonical JSON bytes. The kind-specific schema pass owns Arkret
            // property names and map-key grammars; raw external documents must
            // retain their native field names.
            for value in object.values() {
                validate_canonical_json_value_inner(value, false)?;
            }
            // Generic payload traversal accepts the two canonical timestamp
            // profiles used by v1: ordinary artifact fields use whole seconds,
            // while Event-bound create-object fields use fixed milliseconds so
            // `payload.object.created_at == Event.created_at` remains possible.
            // Kind-specific validators still enforce the narrower profile for
            // fields such as invite expiry.
            for (key, value) in object {
                if key.ends_with("_at")
                    && let Some(s) = value.as_str()
                {
                    let canonical_seconds =
                        arkret_canonical::validate_timestamp_canonical(s).is_ok();
                    let canonical_millis =
                        arkret_canonical::validate_timestamp_canonical(s).is_ok();
                    if !canonical_seconds && !canonical_millis {
                        return Err(
                            "timestamp must use canonical RFC 3339 UTC whole-second or fixed-millisecond form",
                        );
                    }
                }
            }
        }
        _ => {}
    }
    // At the top level, attempt a canonical byte roundtrip to ensure full compliance.
    if root && arkret_canonical::canonical_json_bytes(value).is_err() {
        return Err("value fails canonical JSON byte serialization");
    }
    Ok(())
}

pub fn validate_content_block(block: &serde_json::Value) -> Result<(), &'static str> {
    arkret_models_collaboration::events_payloads::validate_content_block(block)
        .map_err(|error| error.message())
}
