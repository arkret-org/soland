//! Strand / Morph patch + object-field helpers, push-route cell helpers,
//! and conflict-repair helpers.
//!
//! Split out of the `reducer` mod file; re-exported there so sibling
//! `apply_*` modules' `super::*` access and the
//! `crate::reducer::REALM_DESTROY_FANOUT_WINDOW_DAYS` path stay unchanged.

use std::collections::BTreeMap;

use arkret_event_draft::Operation;
use arkret_identifiers::CellRef;
use serde_json::Value;

use super::{DocumentVersionProjection, PushRouteCellValue, PushRouteSubject, StrandProjection};

/// `morph.md` §4.1 S3 — the opt-in Realm profile id that permits breaking /
/// transformation schema migrations. Mirrors
/// `artifacts/profiles/conformance-profiles.json#/profile_requirements`.
pub(crate) const MORPH_SCHEMA_MIGRATION_TRANSFORMATIONS_PROFILE: &str =
    "ak.profile.morph.schema_migration_transformations.v1";

/// `morph.md` §4.1 — the canonical transformation rule ids understood by the
/// `ak.profile.morph.schema_migration_transformations.v1`
/// `transformation_rules_v1_grammar` dialect. Covers the four cases the profile
/// `deterministic_transformation_must` requires (identity, rename, type
/// widening, default backfill). Rules outside this set are rejected fail-closed
/// at registration with `unsupported_transformation_rule` — never partially
/// applied.
pub(crate) const SUPPORTED_MORPH_TRANSFORMATION_RULE_IDS: &[&str] = &[
    "ak.transform.identity.v1",
    "ak.transform.rename.v1",
    "ak.transform.type_widen.v1",
    "ak.transform.default_backfill.v1",
];

/// Extract a `string[]` field directly from an operation payload `Value`.
pub(crate) fn string_array_field_from_payload(payload: &Value, key: &str) -> Vec<String> {
    payload
        .as_object()
        .map(|object| string_array_field(object, key))
        .unwrap_or_default()
}

/// Order-insensitive, duplicate-collapsing set equality over two `schema_refs`
/// vectors. Used for the `from_schema_refs[]` optimistic-concurrency check.
pub(crate) fn string_sets_equal(left: &[String], right: &[String]) -> bool {
    let left_set: std::collections::BTreeSet<&str> = left.iter().map(String::as_str).collect();
    let right_set: std::collections::BTreeSet<&str> = right.iter().map(String::as_str).collect();
    left_set == right_set
}

/// Deterministic, replay-safe application of `transformation_rules[]` to a
/// Morph `fields` map (`morph.md` §4.1 S3 transformation arm). Pure over
/// `(fields, rules)`: identical inputs yield byte-identical outputs across
/// implementations and repeat invocations (rules are applied in declared
/// order; no clock / randomness). Returns the canonical reason string on a
/// malformed or unsupported rule so the caller rejects without a partial apply.
pub(crate) fn apply_morph_transformation_rules(
    fields: &BTreeMap<String, Value>,
    rules: &[Value],
) -> Result<BTreeMap<String, Value>, &'static str> {
    let mut next = fields.clone();
    for rule in rules {
        let Some(rule_object) = rule.as_object() else {
            return Err("unsupported_transformation_rule");
        };
        let rule_id = rule_object
            .get("rule")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if !SUPPORTED_MORPH_TRANSFORMATION_RULE_IDS.contains(&rule_id) {
            return Err("unsupported_transformation_rule");
        }
        match rule_id {
            "ak.transform.identity.v1" => {}
            "ak.transform.rename.v1" | "ak.transform.type_widen.v1" => {
                let Some(from) = rule_object.get("from").and_then(Value::as_str) else {
                    return Err("unsupported_transformation_rule");
                };
                let Some(to) = rule_object.get("to").and_then(Value::as_str) else {
                    return Err("unsupported_transformation_rule");
                };
                if let Some(value) = next.remove(from) {
                    next.insert(to.to_owned(), value);
                }
            }
            "ak.transform.default_backfill.v1" => {
                let Some(field) = rule_object.get("to").and_then(Value::as_str) else {
                    return Err("unsupported_transformation_rule");
                };
                let Some(default_value) = rule_object.get("value") else {
                    return Err("unsupported_transformation_rule");
                };
                next.entry(field.to_owned())
                    .or_insert_with(|| default_value.clone());
            }
            _ => return Err("unsupported_transformation_rule"),
        }
    }
    Ok(next)
}

pub(crate) fn conflict_heads_from_payload(payload: &Value) -> Vec<String> {
    payload
        .get("conflict_heads")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|head| head.as_str().map(ToOwned::to_owned))
        .filter(|head| !head.trim().is_empty())
        .collect()
}

pub(crate) fn bottom_head_ids(bottom: &arkret_wire::Bottom) -> std::collections::BTreeSet<String> {
    bottom
        .heads
        .iter()
        .filter_map(|head| head.get("move_id").and_then(Value::as_str))
        .map(ToOwned::to_owned)
        .collect()
}

pub(crate) fn augment_repair_winner_value(
    winner: Value,
    heads: &[String],
    operation_id: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> Value {
    let repair_of = Value::Array(heads.iter().cloned().map(Value::String).collect());
    let updated_at = utc_timestamp_z(now);
    match winner {
        Value::Object(mut object) => {
            object.insert("repair_of".to_owned(), repair_of);
            object.insert(
                "operation_id".to_owned(),
                Value::String(operation_id.to_owned()),
            );
            object.insert("updated_at".to_owned(), Value::String(updated_at));
            Value::Object(object)
        }
        other => serde_json::json!({
            "value": other,
            "repair_of": repair_of,
            "operation_id": operation_id,
            "updated_at": updated_at,
        }),
    }
}

pub(crate) fn utc_timestamp_z(now: chrono::DateTime<chrono::Utc>) -> String {
    arkret_canonical::format_timestamp_canonical(now)
}

pub(crate) fn empty_push_route_cell() -> PushRouteCellValue {
    PushRouteCellValue {
        push_target_id: None,
        push_gateway_did: None,
        encryption_key: None,
        capabilities: Vec::new(),
        revoked: false,
        revoked_targets: Vec::new(),
    }
}

pub(crate) fn push_route_cell_ref(subject: &PushRouteSubject) -> Option<CellRef> {
    let cell_subject = arkret_wire::composite_subject(&[
        subject.recipient_service_id.as_str(),
        subject.principal_id.as_str(),
        subject.device_id.as_str(),
        subject.push_route.as_str(),
    ])
    .ok()?;
    CellRef::new(format!(
        "ak:cell:ak.component.device.push_route.v1:{cell_subject}"
    ))
    .ok()
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
        component_field_string(payload, "ak.component.strand.position.v1", "board_space_id")
    })?;
    let list_space_id = object_field_string(object, "list_space_id").or_else(|| {
        component_field_string(payload, "ak.component.strand.position.v1", "list_space_id")
    })?;
    let rank = object_field_string(object, "rank")
        .or_else(|| component_field_string(payload, "ak.component.strand.position.v1", "rank"));
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
        .or_else(|| payload.get("list_space_id"))
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

pub(crate) fn validate_patch_semantic_safety(
    patch: &serde_json::Map<String, Value>,
) -> Result<(), &'static str> {
    for (path, value) in patch {
        if patch_path_targets_reducer_managed(path) {
            return Err(arkret_wire::ReasonCode::PATCH_PATH_REDUCER_MANAGED);
        }
        if patch_op_removes_value(value) && patch_path_targets_redactable_unset(path) {
            return Err(arkret_wire::ReasonCode::PATCH_UNSET_REDACTABLE_FIELD);
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
    let event_id = operation
        .payload
        .get("event_id")
        .and_then(Value::as_str)
        .unwrap_or(operation.operation_id.as_str())
        .to_owned();
    let body_digest = arkret_canonical::canonical_sha256(&body)
        .unwrap_or_else(|_| arkret_canonical::sha256_digest(body.to_string().as_bytes()));
    DocumentVersionProjection {
        version_id: format!("{morph_id}:version:{event_id}"),
        event_id,
        author: operation
            .payload
            .get("sender")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned(),
        created_at: operation.created_at,
        body_digest,
        body,
    }
}

/// Spec T07 — federation fanout window for erasure receipts emitted by
/// `ak.realm.destroy`. Spec: 30 days.
pub const REALM_DESTROY_FANOUT_WINDOW_DAYS: i64 = 30;

/// Extract the operator-supplied human reason from a redaction payload,
/// preferring an explicit `human_reason` over the machine `reason` /
/// `reason_text` fields. Returns `None` when no non-empty reason is
/// present.
pub(crate) fn redaction_human_reason(payload: &Value) -> Option<String> {
    ["human_reason", "reason", "reason_text"]
        .iter()
        .find_map(|field| {
            payload
                .get(*field)
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToOwned::to_owned)
        })
}
