//! Join / admission policy validation and encryption-floor helpers.
//!
//! Split out of the `reducer` mod file; re-exported there so the
//! `crate::reducer::validate_join_policy_payload` public path and the
//! sibling `apply_*` modules' `super::*` access stay unchanged.

use std::collections::BTreeSet;

use cokret_sdk::Operation;
use serde_json::Value;

pub(crate) const REALM_ENCRYPTION_PROFILE_CREATE_LOCKED: &str =
    "realm_encryption_profile_create_locked";
pub(crate) const CIRCLE_ENCRYPTION_PROFILE_CREATE_LOCKED: &str =
    "circle_encryption_profile_create_locked";
pub(crate) const CIRCLE_ENCRYPTION_BELOW_REALM_FLOOR: &str = "circle_encryption_below_realm_floor";
/// CKP-0007 §8 — pulling *another* actor into a Circle (none/left → active by
/// an actor other than the target) requires the requester to hold
/// `ck.circle.member.manage` (narrowed by `allowed_circle_ids`) on this Circle.
/// The HTTP surface runs the authoritative `SolandAuthzEngine::check` and stamps a
/// verdict into the operation payload; the reducer fails closed when that
/// verdict is absent or false, so an unauthorised one-way add is rejected even
/// if it bypasses the HTTP gate.
pub(crate) const CIRCLE_MEMBER_MANAGE_CAPABILITY_REQUIRED: &str =
    "circle_member_manage_capability_required";
/// CKP-0007 §8 — a self-service join (none/left → active *by the target actor*)
/// is only permitted on an `open` Circle. Self-joining a non-`open` Circle must
/// go through an invite/manage path.
pub(crate) const CIRCLE_JOIN_NOT_OPEN: &str = "circle_join_not_open";
/// One-way ratchet: effective `content_encryption_floor` MUST be monotonically
/// non-decreasing. Lowering `e2ee_required` back to `allow_plaintext` is rejected.
pub(crate) const CONTENT_ENCRYPTION_FLOOR_DOWNGRADE: &str = "content_encryption_floor_downgrade";
/// One-way ratchet: effective metadata encryption floor MUST be monotonically
/// non-decreasing (`allow_plaintext < e2ee_required`).
pub(crate) const METADATA_ENCRYPTION_FLOOR_DOWNGRADE: &str = "metadata_encryption_floor_downgrade";

/// R1.2 — pure validation for a `ck.member.state{join,routable}`
/// `delivery_binding` against a projected
/// `ck.realm.delivery_binding_policy` payload. Returns `Ok(())` when the
/// binding is admissible; `Err(reason_code)` otherwise. Reason codes
/// mirror the spec join-policy.md §5.1 catalogue.
pub(crate) fn enforce_delivery_binding_policy(
    policy: &Value,
    binding: &serde_json::Map<String, Value>,
) -> Result<(), &'static str> {
    let binding_source = binding
        .get("binding_source")
        .and_then(Value::as_str)
        .unwrap_or("");
    let recipient_service_did = binding
        .get("recipient_service_did")
        .and_then(Value::as_str)
        .unwrap_or("");

    // `allow_binding_sources` is an explicit allow-list. Missing or
    // empty means "no source admissible" — fail closed.
    let allow_sources: Vec<&str> = policy
        .get("allow_binding_sources")
        .and_then(Value::as_array)
        .map(|arr| arr.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    if !allow_sources.contains(&binding_source) {
        return Err("binding_source_not_allowed");
    }
    // `did_document_default` requires the toggle even if the source list
    // includes it (spec §5.1.3 — organization/compliance Realms must set
    // `allow_did_document_default=false`).
    if binding_source == "did_document_default"
        && !policy
            .get("allow_did_document_default")
            .and_then(Value::as_bool)
            .unwrap_or(false)
    {
        return Err("binding_source_not_allowed");
    }

    // `allowed_recipient_services`: empty allow-list means unrestricted
    // (per spec, the policy may omit the list to opt out of explicit
    // recipient pinning); non-empty list MUST contain the binding's
    // recipient_service_did.
    let allowed_recipients: Vec<&str> = policy
        .get("allowed_recipient_services")
        .and_then(Value::as_array)
        .map(|arr| arr.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    if !allowed_recipients.is_empty() && !allowed_recipients.contains(&recipient_service_did) {
        return Err("recipient_service_not_allowed");
    }

    // `binding_source=explicit` requires a signed `service_acceptance_ref`.
    if binding_source == "explicit"
        && !binding
            .get("service_acceptance_ref")
            .map(|v| v.is_string())
            .unwrap_or(false)
    {
        return Err("service_acceptance_missing");
    }

    // Frontier check: if the policy declares `policy_frontier`, the
    // binding's carried `delivery_binding_frontier` MUST match or
    // exceed it lexicographically. Missing carried frontier = stale.
    if let Some(policy_frontier) = policy.get("policy_frontier").and_then(Value::as_str) {
        let carried = binding
            .get("delivery_binding_frontier")
            .and_then(Value::as_str);
        match carried {
            None => return Err("delivery_binding_stale"),
            Some(c) if c < policy_frontier => return Err("delivery_binding_stale"),
            _ => {}
        }
    }
    Ok(())
}

pub(crate) fn state_payload_value(payload: &Value) -> &Value {
    payload.get("value").unwrap_or(payload)
}

/// Validate the Join Policy subset that the reducer must enforce before
/// accepting the policy-components cell. The full Join Policy model has
/// several gate families; this validator focuses on reducer-hard invariants:
/// unique gate IDs and non-empty `principal_admission` selectors.
pub fn validate_join_policy_payload(join_policy: &Value) -> Result<(), &'static str> {
    let Some(object) = join_policy.as_object() else {
        return Err("join_policy must be an object");
    };
    let Some(gates) = object.get("gates").and_then(Value::as_array) else {
        return Err("join_policy requires gates");
    };
    if gates.is_empty() {
        return Err("join_policy requires at least one gate");
    }
    let mut seen_gate_ids = BTreeSet::new();
    for gate in gates {
        let Some(gate) = gate.as_object() else {
            return Err("join_policy gates must be objects");
        };
        let Some(gate_id) = gate.get("gate_id").and_then(Value::as_str) else {
            return Err("join_policy gate requires gate_id");
        };
        if gate_id.is_empty() || !seen_gate_ids.insert(gate_id.to_owned()) {
            return Err("join_policy_duplicate_gate_id");
        }
        if gate.get("kind").and_then(Value::as_str) == Some("principal_admission") {
            validate_principal_admission_gate(gate)?;
        }
    }
    Ok(())
}

pub(crate) fn validate_principal_admission_gate(
    gate: &serde_json::Map<String, Value>,
) -> Result<(), &'static str> {
    let has_allowed_methods = validate_did_method_list(gate, "allowed_did_methods")?;
    let has_allowed_dids = validate_did_list(gate, "allowed_principal_dids")?;
    let has_denied_dids = validate_did_list(gate, "denied_principal_dids")?;
    if !(has_allowed_methods || has_allowed_dids || has_denied_dids) {
        return Err("principal_admission_requires_selector");
    }
    Ok(())
}

pub(crate) fn validate_did_method_list(
    object: &serde_json::Map<String, Value>,
    field: &str,
) -> Result<bool, &'static str> {
    let Some(value) = object.get(field) else {
        return Ok(false);
    };
    let Some(values) = value.as_array() else {
        return Err("principal_admission_methods_invalid");
    };
    for value in values {
        let Some(method) = value.as_str() else {
            return Err("principal_admission_methods_invalid");
        };
        if normalize_policy_did_method(method).is_none() {
            return Err("principal_admission_methods_invalid");
        }
    }
    Ok(!values.is_empty())
}

pub(crate) fn validate_did_list(
    object: &serde_json::Map<String, Value>,
    field: &str,
) -> Result<bool, &'static str> {
    let Some(value) = object.get(field) else {
        return Ok(false);
    };
    let Some(values) = value.as_array() else {
        return Err("principal_admission_dids_invalid");
    };
    for value in values {
        let Some(did) = value.as_str() else {
            return Err("principal_admission_dids_invalid");
        };
        if cokret_sdk::Did::new(did.to_owned()).is_err() {
            return Err("principal_admission_dids_invalid");
        }
    }
    Ok(!values.is_empty())
}

pub(crate) fn normalize_policy_did_method(value: &str) -> Option<&str> {
    let method = value.strip_prefix("did:")?;
    (!method.is_empty()
        && method
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit()))
    .then_some(method)
}

pub(crate) fn principal_admission_gate_allows(
    gate: &serde_json::Map<String, Value>,
    member: &str,
) -> bool {
    if !principal_admission_gate_has_selector(gate) {
        return false;
    }
    let Ok(member_did) = cokret_sdk::Did::new(member.to_owned()) else {
        return false;
    };
    if did_list_contains(gate, "denied_principal_dids", member) {
        return false;
    }
    if did_list_non_empty(gate, "allowed_principal_dids")
        && !did_list_contains(gate, "allowed_principal_dids", member)
    {
        return false;
    }
    let method = member_did.method();
    if let Some(methods) = gate.get("allowed_did_methods").and_then(Value::as_array)
        && !methods.is_empty()
        && !methods.iter().any(|value| {
            value
                .as_str()
                .and_then(normalize_policy_did_method)
                .is_some_and(|allowed| allowed == method)
        })
    {
        return false;
    }
    true
}

pub(crate) fn principal_admission_gate_has_selector(gate: &serde_json::Map<String, Value>) -> bool {
    did_list_non_empty(gate, "allowed_principal_dids")
        || did_list_non_empty(gate, "denied_principal_dids")
        || gate
            .get("allowed_did_methods")
            .and_then(Value::as_array)
            .is_some_and(|values| !values.is_empty())
}

pub(crate) fn did_list_non_empty(gate: &serde_json::Map<String, Value>, field: &str) -> bool {
    gate.get(field)
        .and_then(Value::as_array)
        .is_some_and(|values| !values.is_empty())
}

pub(crate) fn did_list_contains(
    gate: &serde_json::Map<String, Value>,
    field: &str,
    did: &str,
) -> bool {
    gate.get(field)
        .and_then(Value::as_array)
        .is_some_and(|values| values.iter().any(|value| value.as_str() == Some(did)))
}

pub(crate) fn operation_encryption_profile(operation: &Operation) -> Option<&str> {
    operation
        .payload
        .get("encryption_profile")
        .and_then(Value::as_str)
        .or_else(|| {
            operation
                .payload
                .get("object")
                .and_then(|object| object.get("encryption_profile"))
                .and_then(Value::as_str)
        })
}

pub(crate) fn operation_touches_encryption_profile(operation: &Operation) -> bool {
    operation.payload.get("encryption_profile").is_some()
        || operation
            .payload
            .get("object")
            .is_some_and(|object| value_has_direct_field(object, "encryption_profile"))
        || operation_patch_touches_field(&operation.payload, "encryption_profile")
}

pub(crate) fn value_has_direct_field(value: &Value, field: &str) -> bool {
    value
        .as_object()
        .is_some_and(|object| object.contains_key(field))
}

pub(crate) fn operation_patch_touches_field(payload: &Value, field: &str) -> bool {
    payload
        .get("patch")
        .and_then(Value::as_object)
        .is_some_and(|patch| {
            patch.iter().any(|(key, value)| {
                patch_key_touches_field(key, field)
                    || (key == "object" && patch_value_has_direct_field(value, field))
            })
        })
}

pub(crate) fn patch_key_touches_field(key: &str, field: &str) -> bool {
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

pub(crate) fn patch_value_has_direct_field(value: &Value, field: &str) -> bool {
    value
        .get("value")
        .unwrap_or(value)
        .as_object()
        .is_some_and(|object| object.contains_key(field))
}

pub(crate) fn encryption_profile_requires_content_encryption(profile: Option<&str>) -> bool {
    profile
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .is_some_and(|profile| !matches!(profile, "none" | "plaintext" | "allow_plaintext"))
}

/// Extract an encryption-floor field from a `ck.realm.policy_components`
/// value, accepting both the top-level and `/components/`-nested wire forms
/// (mirrors `realm_join_policy_cell_value`).
pub(crate) fn policy_floor_field<'a>(value: &'a Value, field: &str) -> Option<&'a str> {
    value
        .get(field)
        .or_else(|| value.pointer(&format!("/components/{field}")))
        .and_then(Value::as_str)
}

/// Ordinal rank for `content_encryption_floor` (`allow_plaintext < e2ee_required`).
/// `None` / unknown values rank as `allow_plaintext` (0); spec default is
/// `allow_plaintext` (realm-and-space.md §2.3, circle.md §7).
pub(crate) fn content_floor_rank(floor: Option<&str>) -> u8 {
    match floor.map(str::trim) {
        Some("e2ee_required") => 1,
        _ => 0,
    }
}

/// Ordinal rank for the metadata encryption floor
/// (`allow_plaintext < e2ee_required`), symmetric with the content floor.
/// `None` / unknown ranks as `allow_plaintext` (0).
pub(crate) fn metadata_floor_rank(floor: Option<&str>) -> u8 {
    match floor.map(str::trim) {
        Some("e2ee_required") => 1,
        _ => 0,
    }
}
