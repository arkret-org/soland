use arkret_sdk::Operation;
use serde_json::Value;
use soland_domain::kinds;
use soland_storage::RetentionPolicyRecord;

use crate::state::AppState;

pub(super) fn first_string_field<'a>(value: &'a Value, keys: &[&str]) -> Option<&'a str> {
    keys.iter()
        .find_map(|key| value.get(*key).and_then(Value::as_str))
}

pub(super) fn object_string_field<'a>(operation: &'a Operation, keys: &[&str]) -> Option<&'a str> {
    operation
        .payload
        .get("object")
        .and_then(|object| first_string_field(object, keys))
}

pub(super) fn patch_string_field<'a>(operation: &'a Operation, field: &str) -> Option<&'a str> {
    let patch_value = operation
        .payload
        .get("patch")
        .and_then(|patch| patch.get(field))?;
    match patch_value {
        Value::String(value) => Some(value.as_str()),
        Value::Object(op) if op.get("$op").and_then(Value::as_str) == Some("set") => {
            op.get("value").and_then(Value::as_str)
        }
        _ => None,
    }
}

pub(super) fn operation_realm_title(operation: &Operation) -> Option<&str> {
    first_string_field(&operation.payload, &["realm_title", "title"])
        .or_else(|| object_string_field(operation, &["title"]))
        .or_else(|| patch_string_field(operation, "title"))
}

pub(super) fn operation_realm_summary(operation: &Operation) -> Option<&str> {
    first_string_field(&operation.payload, &["realm_summary", "summary"])
        .or_else(|| object_string_field(operation, &["summary"]))
        .or_else(|| patch_string_field(operation, "summary"))
}

pub(super) fn operation_realm_alias_input(operation: &Operation) -> Option<&str> {
    first_string_field(&operation.payload, &["realm_alias", "alias"])
        .or_else(|| object_string_field(operation, &["alias"]))
        .or_else(|| patch_string_field(operation, "alias"))
}

pub(super) fn operation_realm_discoverability(operation: &Operation) -> Option<&str> {
    first_string_field(&operation.payload, &["discoverability"])
        .or_else(|| object_string_field(operation, &["default_discoverability", "discoverability"]))
        .or_else(|| patch_string_field(operation, "default_discoverability"))
        .or_else(|| patch_string_field(operation, "discoverability"))
}

pub(super) fn operation_realm_history_visibility(operation: &Operation) -> Option<&str> {
    operation
        .payload
        .get("value")
        .and_then(Value::as_str)
        .or_else(|| first_string_field(&operation.payload, &["history_visibility"]))
        .or_else(|| object_string_field(operation, &["history_visibility"]))
        .or_else(|| patch_string_field(operation, "history_visibility"))
}

pub(super) fn operation_realm_history_sharing_policy(operation: &Operation) -> Option<Value> {
    match kinds::canonical_kind_for_operation(operation) {
        Some(arkret_sdk::events::EventKind::REALM_HISTORY_SHARING_POLICY) => {
            operation.payload.get("value").cloned()
        }
        Some(arkret_sdk::events::EventKind::REALM_CREATE) => operation
            .payload
            .get("object")
            .and_then(|object| object.get("history_sharing_policy"))
            .cloned(),
        _ => None,
    }
}

pub(super) fn operation_realm_preview_policy(operation: &Operation) -> Option<Value> {
    match kinds::canonical_kind_for_operation(operation) {
        Some(arkret_sdk::events::EventKind::REALM_PREVIEW_POLICY) => {
            operation.payload.get("value").cloned()
        }
        Some(arkret_sdk::events::EventKind::REALM_CREATE) => operation
            .payload
            .get("object")
            .and_then(|object| object.get("preview_policy"))
            .cloned(),
        _ => None,
    }
}

pub(super) fn operation_realm_asset_privacy_policy(operation: &Operation) -> Option<Value> {
    match kinds::canonical_kind_for_operation(operation) {
        Some(arkret_sdk::events::EventKind::REALM_ASSET_PRIVACY_POLICY) => {
            operation.payload.get("value").cloned()
        }
        Some(arkret_sdk::events::EventKind::REALM_CREATE) => operation
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

pub(super) fn is_valid_history_visibility(value: &str) -> bool {
    matches!(
        value,
        "world_readable" | "shared" | "invited" | "joined" | "restricted"
    )
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

pub(super) fn operation_retention_ttl_seconds(operation: &Operation) -> Option<i64> {
    operation
        .payload
        .get("retention_policy")
        .and_then(retention_ttl_seconds_from_value)
        .or_else(|| {
            operation
                .payload
                .get("object")
                .and_then(|object| object.get("retention_policy"))
                .and_then(retention_ttl_seconds_from_value)
        })
        .or_else(|| {
            operation
                .payload
                .get("patch")
                .and_then(|patch| patch.get("retention_policy"))
                .and_then(|patch_value| {
                    if patch_value.get("$op").and_then(Value::as_str) == Some("set") {
                        patch_value
                            .get("value")
                            .and_then(retention_ttl_seconds_from_value)
                    } else {
                        retention_ttl_seconds_from_value(patch_value)
                    }
                })
        })
}

pub async fn project_retention_policy_from_operation(
    state: &AppState,
    origin: &str,
    operation: &Operation,
) {
    let Some(ttl_seconds) = operation_retention_ttl_seconds(operation) else {
        return;
    };
    let record = RetentionPolicyRecord {
        realm_id: operation.realm_id.to_string(),
        ttl_seconds,
        updated_by: origin.to_owned(),
        updated_at: operation.created_at,
    };
    if let Err(error) = state.retention_policies_store().put(&record).await {
        tracing::warn!(
            %error,
            realm_id = %record.realm_id,
            "failed to persist retention policy projection"
        );
        return;
    }
    state
        .retention_policies
        .lock()
        .insert(record.realm_id.clone(), record);
}
