pub use arkret_policy::authz::delegation::{
    Grant, GrantConstraint as Constraint, grant_effective_expiry, is_grant_expired,
    max_delegation_depth,
};
use serde_json::{Map, Value};

const SELECTOR_SHORTHAND_MAX_BYTES: usize = 4096;
const SELECTOR_TOKEN_MAX: usize = 256;
const SELECTOR_DISJUNCTION_MAX: usize = 16;
const SELECTOR_CONJUNCTION_MAX: usize = 64;
const SELECTOR_TERM_MAX_BYTES: usize = 1024;
const SELECTOR_JSON_MAX_BYTES: usize = 64 * 1024;
const RESOURCE_SELECTOR_KNOWN_FIELDS: &[&str] = &[
    "kind",
    "realm_id",
    "space_id",
    "circle_id",
    "object_kind",
    "object_ref",
    "strand_id",
    "message_id",
    "morph_id",
    "morph_kind",
    "relation_kind",
    "relation_id",
    "view_id",
    "event_id",
    "actor_id",
    "schema_ref",
    "policy_id",
    "invite_id",
    "blob_ref",
    "match_scope",
];
const RESOURCE_SELECTOR_KINDS: &[&str] = &[
    "realm",
    "space",
    "circle",
    "strand",
    "message",
    "morph",
    "object",
    "relation",
    "view",
    "event",
    "actor",
    "schema",
    "policy",
    "invite",
    "notification",
    "read_cursor",
    "blob",
    "*",
];

pub fn resource_matches(pattern: &str, resource: &str) -> bool {
    if pattern == "*" {
        return false;
    }
    let resources = resource
        .split(',')
        .map(str::trim)
        .filter(|resource| !resource.is_empty())
        .collect::<Vec<_>>();
    if resources.is_empty() {
        return false;
    }
    pattern.split(',').any(|alternative| {
        let alternative = alternative.trim();
        !alternative.is_empty()
            && alternative.split('+').map(str::trim).all(|term| {
                !term.is_empty()
                    && resources
                        .iter()
                        .any(|resource| resource_term_matches(term, resource))
            })
    })
}

fn resource_term_matches(pattern: &str, resource: &str) -> bool {
    if pattern == "*" {
        return false;
    }
    if pattern == resource {
        return true;
    }
    match pattern {
        "realm" => return resource.starts_with("ak:realm:"),
        "space" => return resource.starts_with("ak:space:"),
        "circle" => return resource.starts_with("ak:circle:"),
        "strand" => return resource.starts_with("ak:strand:"),
        "message" => {
            return resource.starts_with("ak:message:") || resource.starts_with("ak:event:");
        }
        "morph" => return resource.starts_with("ak:morph:"),
        "object" => return is_canonical_object_ref(resource),
        "relation" => return resource.starts_with("ak:relation:"),
        "view" => return resource.starts_with("ak:view:"),
        "event" => return resource.starts_with("ak:event:"),
        "actor" => return resource.starts_with("did:") || resource.starts_with("ak:actor:"),
        "schema" => {
            return resource.starts_with("ak:schema:") || resource.starts_with("ak.schema.");
        }
        "policy" => return resource.starts_with("ak:policy:"),
        "invite" => return resource.starts_with("ak:invite:"),
        "notification" => return resource.starts_with("ak:notification:"),
        "read_cursor" => return resource.starts_with("ak:read_cursor:"),
        "blob" => return resource.starts_with("ak:blob:"),
        _ => {}
    }
    pattern
        .strip_suffix('*')
        .is_some_and(|prefix| resource.starts_with(prefix))
}

fn is_canonical_object_ref(value: &str) -> bool {
    [
        "ak:realm:",
        "ak:space:",
        "ak:circle:",
        "ak:strand:",
        "ak:message:",
        "ak:morph:",
        "ak:relation:",
        "ak:view:",
        "ak:event:",
        "ak:policy:",
        "ak:invite:",
        "ak:blob:",
    ]
    .iter()
    .any(|prefix| value.starts_with(prefix))
}

pub fn validate_capability_actions(actions: &[String]) -> Result<(), &'static str> {
    if actions.is_empty() {
        return Err("capability_grant_actions_empty");
    }
    for action in actions {
        validate_capability_action(action)?;
    }
    Ok(())
}

fn validate_capability_action(action: &str) -> Result<(), &'static str> {
    if action.contains('*') {
        return Err("capability_grant_action_wildcard_forbidden");
    }
    let mut segments = action.split('.');
    if segments.next() != Some("ak") {
        return Err("capability_grant_action_invalid");
    }
    let mut saw_segment = false;
    for segment in segments {
        saw_segment = true;
        if segment.is_empty()
            || !segment
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
        {
            return Err("capability_grant_action_invalid");
        }
    }
    if !saw_segment {
        return Err("capability_grant_action_invalid");
    }
    match arkret_schema::embedded_capability_action(action) {
        Ok(Some(_)) => Ok(()),
        Ok(None) => Err("capability_grant_action_unknown"),
        Err(_) => Err("capability_action_registry_unavailable"),
    }
}

pub fn validate_resource_pattern(pattern: &str) -> Result<(), &'static str> {
    let pattern = pattern.trim();
    if pattern == "*" {
        return Err("capability_grant_resource_wildcard_forbidden");
    }
    if pattern.len() > SELECTOR_SHORTHAND_MAX_BYTES {
        return Err("selector_too_complex");
    }
    if pattern.is_empty() {
        return Err("capability_grant_resource_invalid");
    }
    let alternatives = pattern.split(',').collect::<Vec<_>>();
    if alternatives.len() > SELECTOR_DISJUNCTION_MAX {
        return Err("selector_too_complex");
    }
    let mut term_count = 0usize;
    for alternative in alternatives {
        for term in alternative.split('+') {
            let term = term.trim();
            if term.is_empty() {
                return Err("capability_grant_resource_invalid");
            }
            if term.len() > SELECTOR_TERM_MAX_BYTES {
                return Err("selector_too_complex");
            }
            validate_resource_selector_term(term)?;
            term_count += 1;
        }
    }
    let token_count = term_count + pattern.matches(',').count() + pattern.matches('+').count();
    if token_count > SELECTOR_TOKEN_MAX || term_count > SELECTOR_CONJUNCTION_MAX {
        return Err("selector_too_complex");
    }
    Ok(())
}

pub fn validate_resource_selector_object(map: &Map<String, Value>) -> Result<(), &'static str> {
    let json_bytes = serde_json::to_vec(map).map_err(|_| "capability_grant_resources_invalid")?;
    if json_bytes.len() > SELECTOR_JSON_MAX_BYTES {
        return Err("selector_too_complex");
    }
    if map
        .keys()
        .any(|key| !RESOURCE_SELECTOR_KNOWN_FIELDS.contains(&key.as_str()))
    {
        return Err("capability_grant_resources_invalid");
    }
    let Some(kind) = map.get("kind").and_then(Value::as_str) else {
        return Err("capability_grant_resources_invalid");
    };
    if !RESOURCE_SELECTOR_KINDS.contains(&kind) {
        return Err("capability_grant_resources_invalid");
    }
    let match_scope = map
        .get("match_scope")
        .and_then(Value::as_str)
        .unwrap_or("exact");
    if !matches!(match_scope, "exact" | "children" | "subtree" | "realm_wide") {
        return Err("capability_grant_resources_invalid");
    }
    if match_scope == "realm_wide" && map.get("realm_id").and_then(Value::as_str).is_none() {
        return Err("capability_grant_resources_invalid");
    }
    if matches!(match_scope, "children" | "subtree") && kind != "space" {
        return Err("capability_grant_resources_invalid");
    }
    if matches!(match_scope, "children" | "subtree")
        && map
            .get("space_id")
            .and_then(Value::as_str)
            .is_none_or(|value| value.trim().is_empty())
    {
        return Err("capability_grant_resources_invalid");
    }
    if match_scope == "realm_wide" && !matches!(kind, "realm" | "space" | "circle") {
        return Err("capability_grant_resources_invalid");
    }
    if matches!(kind, "space" | "circle" | "notification" | "read_cursor")
        && map.get("realm_id").and_then(Value::as_str).is_none()
    {
        return Err("capability_grant_resources_invalid");
    }
    if map.get("actor_id").and_then(Value::as_str) == Some("*")
        || (kind == "actor" && map.get("actor_id").and_then(Value::as_str).is_none())
    {
        return Err("selector_actor_wildcard_forbidden");
    }
    if selector_uses_governance_wildcard(map) {
        return Err("selector_governance_wildcard_forbidden");
    }
    for value in map.values() {
        validate_selector_field_value(value)?;
    }
    Ok(())
}

fn validate_selector_field_value(value: &Value) -> Result<(), &'static str> {
    match value {
        Value::String(value) if value.len() > SELECTOR_TERM_MAX_BYTES => {
            Err("selector_too_complex")
        }
        Value::Array(values) => {
            for value in values {
                validate_selector_field_value(value)?;
            }
            Ok(())
        }
        Value::Object(object) => {
            for value in object.values() {
                validate_selector_field_value(value)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn validate_resource_selector_term(term: &str) -> Result<(), &'static str> {
    if term == "*" {
        return Err("capability_grant_resource_wildcard_forbidden");
    }
    if term == "actor:*" {
        return Err("selector_actor_wildcard_forbidden");
    }
    if selector_term_uses_governance_wildcard(term) {
        return Err("selector_governance_wildcard_forbidden");
    }
    Ok(())
}

fn selector_term_uses_governance_wildcard(term: &str) -> bool {
    if term == "policy:*"
        || (term.starts_with("policy:") && term.ends_with(":*"))
        || term == "schema:*"
        || (term.starts_with("schema:") && term.ends_with(":*"))
    {
        return true;
    }
    object_selector_tail(term).is_some_and(|tail| matches!(tail.as_str(), "policy" | "schema"))
}

fn object_selector_tail(term: &str) -> Option<String> {
    let remainder = term.strip_prefix("object:")?;
    if remainder == "*" {
        return None;
    }
    if let Some(tail) = remainder.strip_prefix("*:") {
        return (!tail.is_empty()).then(|| tail.to_owned());
    }
    let parts = remainder.split(':').collect::<Vec<_>>();
    if parts.len() <= 3 || parts[0] != "ak" || parts[1] != "realm" || parts[2].is_empty() {
        return None;
    }
    let tail = parts[3..].join(":");
    (!tail.is_empty()).then_some(tail)
}

fn selector_uses_governance_wildcard(map: &Map<String, Value>) -> bool {
    match map.get("kind").and_then(Value::as_str) {
        Some("policy") => {
            selector_field_missing_or_wildcard(map, "policy_id")
                || selector_field_missing_or_wildcard(map, "realm_id")
        }
        Some("schema") => {
            selector_field_missing_or_wildcard(map, "schema_ref")
                || selector_field_missing_or_wildcard(map, "realm_id")
        }
        Some("object") => {
            let object_kind = map.get("object_kind").and_then(Value::as_str);
            let object_ref = map.get("object_ref").and_then(Value::as_str);
            let governance_type = matches!(object_kind, Some("policy" | "schema"));
            let governance_ref = object_ref.is_some_and(|value| {
                value.starts_with("ak:policy:") || value.starts_with("ak:schema:")
            });
            (governance_type
                && (selector_field_missing_or_wildcard(map, "object_ref")
                    || selector_field_missing_or_wildcard(map, "realm_id")))
                || (governance_ref && selector_field_missing_or_wildcard(map, "realm_id"))
        }
        _ => false,
    }
}

fn selector_field_missing_or_wildcard(map: &Map<String, Value>, field: &str) -> bool {
    map.get(field)
        .and_then(Value::as_str)
        .is_none_or(|value| value == "*")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn realm_wide_realm_selector_matches_owner_grant_contract() {
        let selector = serde_json::json!({
            "kind": "realm",
            "realm_id": "ak:realm:019f9000-0000-7000-8000-000000000001",
            "match_scope": "realm_wide"
        });
        assert!(
            validate_resource_selector_object(selector.as_object().unwrap()).is_ok(),
            "realm-and-space.md §2.5 requires this exact selector shape"
        );
    }
}
