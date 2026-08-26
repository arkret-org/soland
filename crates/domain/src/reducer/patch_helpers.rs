//! Strand / Morph patch + object-field helpers and push-route cell helpers.
//!
//! Split out of the `reducer` mod file; re-exported there so sibling
//! `apply_*` modules' `super::*` access and the
//! `crate::reducer::REALM_DESTROY_FANOUT_WINDOW_DAYS` path stay unchanged.

use std::collections::BTreeMap;

use arkret_event_draft::ProjectedEventOperation as Operation;
use serde_json::Value;

use super::{DocumentVersionProjection, StrandProjection};

pub(crate) fn utc_timestamp_z(now: chrono::DateTime<chrono::Utc>) -> String {
    arkret_canonical::format_timestamp_canonical(now)
}

pub(crate) fn object_field_string(
    object: &serde_json::Map<String, Value>,
    field_name: &str,
) -> Option<String> {
    // spec 9dabf26: Strand profile fields live under `metadata.fields`, not at
    // the object root. The Strand-position component (board_space_id /
    // list_space_id / rank) is read from there.
    object
        .get("metadata")
        .and_then(Value::as_object)
        .and_then(|metadata| metadata.get("fields"))
        .and_then(Value::as_object)
        .and_then(|fields| fields.get(field_name))
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(ToOwned::to_owned)
}

pub(crate) fn component_field_string(
    payload: &Value,
    family: &str,
    field_name: &str,
) -> Option<String> {
    payload
        .get("components")
        .and_then(Value::as_array)
        .and_then(|components| {
            components.iter().find(|component| {
                component
                    .get("family")
                    .and_then(Value::as_str)
                    .is_some_and(|value| value == family)
            })
        })
        .and_then(|component| component.get(field_name))
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(ToOwned::to_owned)
}

pub(crate) fn strand_position_from_create_payload(
    payload: &Value,
    object: &serde_json::Map<String, Value>,
) -> Option<(String, String, Option<String>)> {
    let board_space_id = object_field_string(object, "board_space_id").or_else(|| {
        component_field_string(
            payload,
            arkret_wire::CellFamilyId::STRAND_POSITION_V1,
            "board_space_id",
        )
    })?;
    let list_space_id = object_field_string(object, "list_space_id").or_else(|| {
        component_field_string(
            payload,
            arkret_wire::CellFamilyId::STRAND_POSITION_V1,
            "list_space_id",
        )
    })?;
    let rank = object_field_string(object, "rank").or_else(|| {
        component_field_string(
            payload,
            arkret_wire::CellFamilyId::STRAND_POSITION_V1,
            "rank",
        )
    });
    Some((board_space_id, list_space_id, rank))
}

pub(crate) fn strand_position_from_lifecycle_payload(
    payload: &Value,
) -> Option<(String, String, Option<String>)> {
    let board_space_id = payload
        .get("board_space_id")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())?
        .to_owned();
    let list_space_id = payload
        .get("target_space_id")
        .or_else(|| payload.get("space_id"))
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())?
        .to_owned();
    let rank = payload
        .get("rank")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(ToOwned::to_owned);
    Some((board_space_id, list_space_id, rank))
}

pub(crate) enum PatchAction<'a> {
    Set(&'a Value),
    Unset,
    Ignore,
}

pub(crate) fn patch_action(value: &Value) -> PatchAction<'_> {
    let Some(object) = value.as_object() else {
        return PatchAction::Set(value);
    };
    let Some(op) = object.get("$op").and_then(Value::as_str) else {
        return PatchAction::Set(value);
    };
    match op {
        "set" | "add" => object
            .get("value")
            .map(PatchAction::Set)
            .unwrap_or(PatchAction::Ignore),
        "unset" | "remove" => PatchAction::Unset,
        _ => PatchAction::Ignore,
    }
}

pub(crate) fn patch_string_value(
    patch: &serde_json::Map<String, Value>,
    path: &str,
) -> Option<Option<String>> {
    match patch.get(path).map(patch_action)? {
        PatchAction::Set(value) => value
            .as_str()
            .filter(|value| !value.trim().is_empty())
            .map(|value| Some(value.to_owned())),
        PatchAction::Unset => Some(None),
        PatchAction::Ignore => None,
    }
}

pub fn validate_patch_semantic_safety(
    patch: &serde_json::Map<String, Value>,
    object_kind: Option<&str>,
) -> Result<(), &'static str> {
    for (path, value) in patch {
        if patch_path_targets_reducer_managed(path, object_kind) {
            return Err(arkret_wire::ReasonCode::PATCH_PATH_REDUCER_MANAGED);
        }
        if patch_op_removes_value(value) && patch_path_targets_redactable_unset(path) {
            return Err(arkret_wire::ReasonCode::PATCH_UNSET_REDACTABLE_FIELD);
        }
    }
    Ok(())
}

/// Whether a patch path addresses a field the generic update surface does not
/// own, decided against the registered set of `object_kind` when it is known.
///
/// The path set is the canonical projection of
/// `registry/reducer-managed-path-registry.json` and is owned by
/// `arkret_wire::patch::reducer_managed_patch_reason`; this module never spells
/// its own list. `None` means the object kind was not proven, so the
/// conservative object-agnostic superset applies and no registered carve-out is
/// honoured (`event-and-patch.md` 4.2.5).
fn patch_path_targets_reducer_managed(path: &str, object_kind: Option<&str>) -> bool {
    let root = patch_segment_head(path.split('.').next().unwrap_or_default());
    let field = if root == Some("object") {
        patch_segment_head(path.split('.').nth(1).unwrap_or_default())
    } else {
        root
    };
    let Some(field) = field else {
        return false;
    };
    if let Some(object_kind) = object_kind {
        return arkret_wire::patch::reducer_managed_patch_reason(object_kind, field).is_some();
    }
    arkret_wire::generated::REDUCER_MANAGED_ANY_OBJECT_PATCH_PATHS.contains(&field)
}

/// Whether a patch path addresses a registered redactable content-carrier slot.
///
/// The slot set is the canonical projection of
/// `registry/redactable-field-registry.json`; this module never spells its own
/// list. `metadata`, `metadata.summary`, `encrypted_metadata`, `body` and
/// `attachments` are ordinary optional members, not content slots, so their
/// `$op="unset"` MUST be accepted (`event-and-patch.md` §4.2.4).
fn patch_path_targets_redactable_unset(path: &str) -> bool {
    arkret_wire::generated::REDACTABLE_FIELD_PATHS
        .iter()
        .any(|slot| path == *slot || path.starts_with(&format!("{slot}.")))
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

pub(crate) fn strand_status_patch_target(payload: &Value) -> Result<Option<String>, &'static str> {
    let Some(patch) = payload.get("patch").and_then(Value::as_object) else {
        return Ok(None);
    };
    let value = patch
        .get("metadata.fields.status")
        .or_else(|| {
            patch
                .get("metadata.fields")
                .and_then(|fields_patch| match patch_action(fields_patch) {
                    PatchAction::Set(value) => value.get("status"),
                    PatchAction::Unset | PatchAction::Ignore => None,
                })
        })
        .or_else(|| {
            patch
                .get("metadata")
                .and_then(|metadata_patch| match patch_action(metadata_patch) {
                    PatchAction::Set(value) => {
                        value.get("fields").and_then(|fields| fields.get("status"))
                    }
                    PatchAction::Unset | PatchAction::Ignore => None,
                })
        });
    let Some(value) = value else {
        return Ok(None);
    };
    match patch_action(value) {
        PatchAction::Set(value) => value
            .as_str()
            .filter(|value| !value.trim().is_empty())
            .map(|value| Some(value.to_owned()))
            .ok_or("strand_status_invalid"),
        PatchAction::Unset => Err("strand_status_invalid"),
        PatchAction::Ignore => Ok(None),
    }
}

pub(crate) fn patch_metadata_string_value(
    patch: &serde_json::Map<String, Value>,
    key: &str,
) -> Option<Option<String>> {
    let dotted = format!("metadata.{key}");
    if let Some(value) = patch_string_value(patch, &dotted) {
        return Some(value);
    }
    patch
        .get("metadata")
        .and_then(|metadata_patch| match patch_action(metadata_patch) {
            PatchAction::Set(value) => value.get(key).and_then(|value| {
                value
                    .as_str()
                    .filter(|value| !value.trim().is_empty())
                    .map(|value| Some(value.to_owned()))
            }),
            PatchAction::Unset => Some(None),
            PatchAction::Ignore => None,
        })
}

pub(crate) fn strand_metadata_fields_value(value: &Value) -> Option<BTreeMap<String, Value>> {
    value.as_object().map(|fields| {
        fields
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect::<BTreeMap<_, _>>()
    })
}

pub(crate) fn apply_metadata_fields_value(fields: &mut BTreeMap<String, Value>, value: &Value) {
    if let Some(values) = strand_metadata_fields_value(value) {
        for (field_name, field_value) in values {
            fields.insert(field_name, field_value);
        }
    }
}

pub(crate) fn strand_status_transition_allowed(current: &str, next: &str) -> bool {
    if current == next {
        return true;
    }
    match current {
        "todo" => next == "in_progress",
        "in_progress" => matches!(next, "done" | "blocked"),
        "blocked" => matches!(next, "in_progress" | "cancelled"),
        "investigating" => next == "mitigated",
        "mitigated" => next == "resolved",
        _ => true,
    }
}

pub(crate) fn strand_id_from_payload(payload: &Value) -> Option<&str> {
    payload
        .get("target_ref")
        .and_then(Value::as_str)
        .filter(|value| value.starts_with("ak:strand:"))
}

pub(crate) fn check_strand_status_patch(
    strand: &StrandProjection,
    payload: &Value,
) -> Result<Option<String>, &'static str> {
    let Some(next_status) = strand_status_patch_target(payload)? else {
        return Ok(None);
    };
    let Some(current_status) = strand.fields.get("status").and_then(Value::as_str) else {
        return Ok(Some(next_status));
    };
    if strand_status_transition_allowed(current_status, &next_status) {
        return Ok(Some(next_status));
    }
    Err("strand_status_transition_invalid")
}

pub(crate) fn apply_strand_fields_patch(
    fields: &mut BTreeMap<String, Value>,
    patch: &serde_json::Map<String, Value>,
) {
    for (path, value) in patch {
        if path == "metadata" {
            match patch_action(value) {
                PatchAction::Set(Value::Object(metadata)) => {
                    if let Some(value) = metadata.get("fields") {
                        apply_metadata_fields_value(fields, value);
                    }
                }
                PatchAction::Unset => fields.clear(),
                PatchAction::Set(_) | PatchAction::Ignore => {}
            }
            continue;
        }
        if path == "metadata.fields" {
            match patch_action(value) {
                PatchAction::Set(value) => apply_metadata_fields_value(fields, value),
                PatchAction::Unset => fields.clear(),
                PatchAction::Ignore => {}
            }
            continue;
        }
        let Some(field_name) = path.strip_prefix("metadata.fields.") else {
            continue;
        };
        if field_name.is_empty() {
            continue;
        }
        match patch_action(value) {
            PatchAction::Set(value) => {
                fields.insert(field_name.to_owned(), value.clone());
            }
            PatchAction::Unset => {
                fields.remove(field_name);
            }
            PatchAction::Ignore => {}
        }
    }
}

/// Apply a `ak.strand.update`-style patch to a Morph's `fields` map. Unlike Strand
/// (whose profile fields moved under `metadata.fields` in spec 9dabf26), the
/// Morph object keeps `fields` at the object root (morph.schema.json), so its
/// patch paths are root-level `fields` / `fields.<name>`.
pub(crate) fn apply_morph_fields_patch(
    fields: &mut BTreeMap<String, Value>,
    patch: &serde_json::Map<String, Value>,
) {
    for (path, value) in patch {
        if path == "fields" {
            match patch_action(value) {
                PatchAction::Set(value) => apply_metadata_fields_value(fields, value),
                PatchAction::Unset => fields.clear(),
                PatchAction::Ignore => {}
            }
            continue;
        }
        let Some(field_name) = path.strip_prefix("fields.") else {
            continue;
        };
        if field_name.is_empty() {
            continue;
        }
        match patch_action(value) {
            PatchAction::Set(value) => {
                fields.insert(field_name.to_owned(), value.clone());
            }
            PatchAction::Unset => {
                fields.remove(field_name);
            }
            PatchAction::Ignore => {}
        }
    }
}

pub(crate) fn object_map_to_fields(object: Option<&Value>) -> BTreeMap<String, Value> {
    object
        .and_then(Value::as_object)
        .map(|fields| {
            fields
                .iter()
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect::<BTreeMap<_, _>>()
        })
        .unwrap_or_default()
}

pub(crate) fn string_array_field(
    object: &serde_json::Map<String, Value>,
    key: &str,
) -> Vec<String> {
    let Some(value) = object.get(key) else {
        return Vec::new();
    };
    if let Some(items) = value.as_array() {
        return items
            .iter()
            .filter_map(Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .map(ToOwned::to_owned)
            .collect::<Vec<_>>();
    }
    value
        .as_object()
        .map(|items| {
            items
                .iter()
                .filter_map(|(facet, enabled)| enabled.as_bool().unwrap_or(true).then_some(facet))
                .filter(|value| !value.trim().is_empty())
                .cloned()
                .collect::<Vec<_>>()
        })
        .unwrap_or_default()
}

pub(crate) fn projection_object_realm_id(
    object: &serde_json::Map<String, Value>,
    operation: &Operation,
) -> String {
    object
        .get("realm_id")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| operation.realm_id.to_string())
}

pub fn morph_document_body(fields: &BTreeMap<String, Value>) -> Option<Value> {
    fields
        .get("document")
        .or_else(|| fields.get("body"))
        .cloned()
        .filter(|value| !value.is_null())
}

pub(crate) fn document_version_from_operation(
    morph_id: &str,
    operation: &Operation,
    body: Value,
) -> DocumentVersionProjection {
    let event_id = operation.context.event_id.to_string();
    let body_digest = arkret_canonical::canonical_sha256(&body)
        .unwrap_or_else(|_| arkret_canonical::sha256_digest(body.to_string().as_bytes()));
    DocumentVersionProjection {
        version_id: format!("{morph_id}:version:{event_id}"),
        event_id,
        author: operation.context.sender.to_string(),
        created_at: operation.created_at,
        body_digest,
        body,
    }
}

/// Spec T07 — federation fanout window for erasure receipts emitted by
/// `ak.realm.destroy`. Spec: 30 days.
pub const REALM_DESTROY_FANOUT_WINDOW_DAYS: i64 = 30;

/// Human-facing redaction justification. Both redaction payload classes
/// (`message_redact_payload`, `cross_object_redaction_payload`) are closed and
/// register exactly one such member, `reason`; alternative spellings are not
/// wire-reachable.
pub(crate) fn redaction_human_reason(payload: &Value) -> Option<String> {
    payload
        .get("reason")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}
