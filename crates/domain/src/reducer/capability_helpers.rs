//! Shared helpers for ordinary local capability grants.

use std::collections::BTreeSet;

use serde_json::Value;

pub(crate) fn string_set_field(value: &Value, field: &str) -> BTreeSet<String> {
    value
        .get(field)
        .map(|value| match value {
            Value::String(value) => std::iter::once(value.clone()).collect(),
            Value::Array(values) => values
                .iter()
                .filter_map(Value::as_str)
                .map(ToOwned::to_owned)
                .collect(),
            _ => BTreeSet::new(),
        })
        .unwrap_or_default()
}

pub(crate) fn value_array_field(value: &Value, field: &str) -> Vec<Value> {
    value
        .get(field)
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
}

/// Whether admission stamped an authoritative local Circle-manage verdict.
pub(crate) fn payload_asserts_circle_manage(payload: &Value, circle_id: &str) -> bool {
    if payload
        .get("manage_capability_verified")
        .and_then(Value::as_bool)
        == Some(true)
    {
        return true;
    }
    let Some(capability) = payload
        .get("actor_capability")
        .filter(|value| value.is_object())
    else {
        return false;
    };
    capability.get("action").and_then(Value::as_str)
        == Some(arkret_wire::CapabilityActionId::CIRCLE_MEMBER_MANAGE)
        && capability.get("allowed").and_then(Value::as_bool) == Some(true)
        && capability
            .get("circle_id")
            .and_then(Value::as_str)
            .is_none_or(|value| value == circle_id)
}
