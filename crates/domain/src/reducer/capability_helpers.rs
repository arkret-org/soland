//! The Circle-manage verdict admission stamps into a payload.

use serde_json::Value;

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
