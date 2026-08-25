use arkret_event_draft::ProjectedEventOperation as Operation;
use serde_json::Value;
use soland_services::operation_semantics as kinds;

// Canonical home of these payload-field readers is `soland_storage::projection`
// (re-exported at the storage crate root); the signatures and bodies were
// identical, so this module re-exports them instead of keeping copies.
pub(super) use soland_storage::{first_string_field, object_string_field, patch_string_field};

fn operation_updates_realm_metadata(operation: &Operation) -> bool {
    matches!(
        kinds::canonical_kind_for_operation(operation),
        Some(arkret_wire::EventKind::RealmProfile)
    )
}

pub(super) fn operation_realm_title(operation: &Operation) -> Option<&str> {
    // `ensure_projected_realm` runs for every accepted event in a Realm. Space,
    // Strand, and other child-object events also carry `object.title` or a
    // `patch.title`; those titles must never be interpreted as Realm metadata.
    if !operation_updates_realm_metadata(operation) {
        return None;
    }
    first_string_field(&operation.payload, &["title"])
}

pub(super) fn operation_realm_summary(operation: &Operation) -> Option<&str> {
    if !operation_updates_realm_metadata(operation) {
        return None;
    }
    first_string_field(&operation.payload, &["summary"])
}

pub(super) fn operation_realm_discoverability(operation: &Operation) -> Option<&str> {
    (kinds::canonical_kind_for_operation(operation) == Some(arkret_wire::EventKind::RealmDiscovery))
        .then(|| operation.payload.get("value").and_then(Value::as_str))
        .flatten()
}

pub(super) fn operation_realm_class(operation: &Operation) -> Option<&str> {
    object_string_field(operation, &["realm_class"])
        .or_else(|| patch_string_field(operation, "realm_class"))
}

pub(super) fn operation_realm_default_join_rule(operation: &Operation) -> Option<&str> {
    (kinds::canonical_kind_for_operation(operation) == Some(arkret_wire::EventKind::RealmJoinRule))
        .then(|| operation.payload.get("value").and_then(Value::as_str))
        .flatten()
        .or_else(|| object_string_field(operation, &["default_join_rule"]))
        .or_else(|| patch_string_field(operation, "default_join_rule"))
}

pub(super) fn operation_realm_history_access(operation: &Operation) -> Option<&str> {
    match kinds::canonical_kind_for_operation(operation) {
        Some(arkret_wire::EventKind::RealmCreate) => {
            object_string_field(operation, &["history_access"])
        }
        Some(arkret_wire::EventKind::RealmHistoryAccess) => {
            operation.payload.get("to").and_then(Value::as_str)
        }
        _ => None,
    }
}

pub(super) fn operation_realm_preview_policy(operation: &Operation) -> Option<Value> {
    match kinds::canonical_kind_for_operation(operation) {
        Some(arkret_wire::EventKind::RealmPreviewPolicy) => operation.payload.get("value").cloned(),
        Some(arkret_wire::EventKind::RealmCreate) => operation
            .payload
            .get("object")
            .and_then(|object| object.get("preview_policy"))
            .cloned(),
        _ => None,
    }
}

pub(super) fn operation_realm_asset_privacy_policy(operation: &Operation) -> Option<Value> {
    match kinds::canonical_kind_for_operation(operation) {
        Some(arkret_wire::EventKind::RealmAssetPrivacyPolicy) => {
            operation.payload.get("value").cloned()
        }
        Some(arkret_wire::EventKind::RealmCreate) => operation
            .payload
            .get("object")
            .and_then(|object| object.get("asset_privacy_policy"))
            .cloned(),
        _ => None,
    }
}

// Converged to the single crate-root canonical-digest helper (delegates
// to SDK `canonical_sha256`); re-exported so projection call sites keep
// referencing `canonical_value_digest`.
pub(super) use crate::canonical_value_digest;

pub(super) fn is_valid_history_access(value: &str) -> bool {
    matches!(value, "since_join" | "all_history_for_current_members")
}

pub(super) fn operation_realm_encryption_profile(operation: &Operation) -> Option<&str> {
    first_string_field(&operation.payload, &["encryption_profile"])
        .or_else(|| object_string_field(operation, &["encryption_profile"]))
        .or_else(|| patch_string_field(operation, "encryption_profile"))
}

pub fn retention_ttl_seconds_from_value(value: &Value) -> Option<i64> {
    if let Some(seconds) = value.get("ttl_seconds").and_then(Value::as_i64) {
        return (seconds > 0).then_some(seconds);
    }
    if let Some(days) = value.get("ttl_days").and_then(Value::as_i64) {
        return (days > 0).then_some(days.saturating_mul(86_400));
    }
    if let Some(ttl) = value.get("ttl").and_then(Value::as_str) {
        return parse_retention_ttl_string(ttl);
    }
    if let Some(ttl) = value.as_str() {
        return parse_retention_ttl_string(ttl);
    }
    None
}

fn parse_retention_ttl_string(value: &str) -> Option<i64> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    let (digits, multiplier) = if let Some(days) = value.strip_suffix('d') {
        (days, 86_400)
    } else if let Some(hours) = value.strip_suffix('h') {
        (hours, 3_600)
    } else if let Some(minutes) = value.strip_suffix('m') {
        (minutes, 60)
    } else if let Some(seconds) = value.strip_suffix('s') {
        (seconds, 1)
    } else if let Some(days) = value
        .strip_prefix('P')
        .and_then(|rest| rest.strip_suffix('D'))
    {
        (days, 86_400)
    } else {
        (value, 1)
    };
    let amount = digits.trim().parse::<i64>().ok()?;
    (amount > 0).then_some(amount.saturating_mul(multiplier))
}
