use arkret_identifiers::{
    BlobRef, CircleId, DidCoreId, EventId, InviteId, MessageId, MorphId, NotificationId, PolicyId,
    ReadCursorId, RealmId, RelationId, SpaceId, StrandId, ViewId,
};
pub use arkret_policy::authz::authority::{
    Grant, GrantConstraint, IssuerAuthorityRef, grant_effective_expiry, is_grant_expired,
    max_authority_depth,
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
    // A kind term matches only a canonical value of that id-kind. The `ak:`
    // prefix alone is not the value space: `id-kind-registry.json` fixes each
    // kind's payload (UUIDv7, 44-char Event token, or suite-tagged digest), so
    // a grant term must not be satisfied by a string that merely opens with
    // the right kind segment.
    match pattern {
        "realm" => return RealmId::new(resource).is_ok(),
        "space" => return SpaceId::new(resource).is_ok(),
        "circle" => return CircleId::new(resource).is_ok(),
        "strand" => return StrandId::new(resource).is_ok(),
        "message" => {
            return MessageId::new(resource).is_ok() || EventId::new(resource).is_ok();
        }
        "morph" => return MorphId::new(resource).is_ok(),
        "object" => return is_canonical_object_ref(resource),
        "relation" => return RelationId::new(resource).is_ok(),
        "view" => return ViewId::new(resource).is_ok(),
        "event" => return EventId::new(resource).is_ok(),
        "actor" => return DidCoreId::new(resource).is_ok(),
        // `schema` is deliberately the one coarse branch left: it is not an
        // `id-kind-registry.json` kind at all (neither `id_kinds` nor
        // `special_forms` declares it), so no SDK newtype owns its value
        // space. `resource-selector-grammar.md` defines `schema_ref` as a
        // schema *registry* id (`ak.schema.<name>.v<n>` or a reverse-domain
        // id), and `ak:schema:` appears nowhere in the spec — it is not a v1
        // spelling and must not match here.
        "schema" => return resource.starts_with("ak.schema."),
        "policy" => return PolicyId::new(resource).is_ok(),
        "invite" => return InviteId::new(resource).is_ok(),
        "notification" => return NotificationId::new(resource).is_ok(),
        "read_cursor" => return ReadCursorId::new(resource).is_ok(),
        "blob" => return is_typed_blob_ref(resource),
        _ => {}
    }
    pattern
        .strip_suffix('*')
        .is_some_and(|prefix| resource.starts_with(prefix))
}

/// A blob reference in one of its two typed wire forms: the content-addressed
/// `ak:blob:<suite>:<digest>` or the `ak:blob:<uuidv7>` metadata id.
///
/// `BlobRef` additionally accepts a bare `<suite>:<digest>` digest. That form
/// carries no kind segment, and `id-kind-registry.json` storage rules make the
/// `<kind>` segment part of the canonical wire value, so a bare digest never
/// names a blob resource here.
pub fn is_typed_blob_ref(value: &str) -> bool {
    value.starts_with("ak:blob:") && BlobRef::new(value).is_ok()
}

fn is_canonical_object_ref(value: &str) -> bool {
    RealmId::new(value).is_ok()
        || SpaceId::new(value).is_ok()
        || CircleId::new(value).is_ok()
        || StrandId::new(value).is_ok()
        || MessageId::new(value).is_ok()
        || MorphId::new(value).is_ok()
        || RelationId::new(value).is_ok()
        || ViewId::new(value).is_ok()
        || EventId::new(value).is_ok()
        || PolicyId::new(value).is_ok()
        || InviteId::new(value).is_ok()
        || is_typed_blob_ref(value)
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
                // `policy` is a typed UUIDv7 kind and is validated; `schema`
                // has no registered id-kind and is matched by its registry-id
                // spelling.
                PolicyId::new(value).is_ok() || value.starts_with("ak.schema.")
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
            "realm_id": "ak:realm:AYcO0aKZZvKELI-s58wUjRHsrz5v8Y51T0_sGUTciDVw",
            "match_scope": "realm_wide"
        });
        assert!(
            validate_resource_selector_object(selector.as_object().unwrap()).is_ok(),
            "realm-and-space.md §2.5 requires this exact selector shape"
        );
    }

    #[test]
    fn actor_selector_accepts_only_did_core_resources() {
        assert!(resource_matches(
            "actor",
            "ak:did_core:webvh:z6mkactorfixture"
        ));
        assert!(!resource_matches("actor", "did:web:actor.example"));
        assert!(!resource_matches("actor", "ak:member:z6mkactorfixture"));
    }

    // A kind term is satisfied by a canonical id of that kind, never by a
    // string that merely opens with the kind segment.
    #[test]
    fn kind_terms_reject_a_kind_prefix_without_a_canonical_payload() {
        assert!(resource_matches(
            "event",
            "ak:event:AZXoIs9BRSgujgrZ-dLgogRh6YCdLWfJAZWdPXg8qD9D"
        ));
        assert!(!resource_matches("event", "ak:event:not-a-token"));
        assert!(!resource_matches("event", "ak:event:"));

        assert!(resource_matches(
            "message",
            "ak:message:AZXoIs9BRSgujgrZ-dLgogRh6YCdLWfJAZWdPXg8qD9D"
        ));
        assert!(!resource_matches("message", "ak:message:1"));

        assert!(resource_matches(
            "realm",
            "ak:realm:AYcO0aKZZvKELI-s58wUjRHsrz5v8Y51T0_sGUTciDVw"
        ));
        assert!(!resource_matches("realm", "ak:realm:local-fixture"));

        assert!(resource_matches(
            "policy",
            "ak:policy:01964137-0000-7000-8000-000000000777"
        ));
        assert!(!resource_matches("policy", "ak:policy:default"));
    }

    #[test]
    fn blob_terms_require_the_typed_wire_form() {
        assert!(resource_matches(
            "blob",
            &format!("ak:blob:sha256:{}", "a".repeat(64))
        ));
        assert!(resource_matches(
            "blob",
            "ak:blob:01964137-0000-7000-8000-000000000777"
        ));
        assert!(!resource_matches("blob", "ak:blob:abc"));
        // A bare digest carries no kind segment, so it names no blob resource.
        assert!(!resource_matches(
            "blob",
            &format!("sha256:{}", "a".repeat(64))
        ));
    }

    #[test]
    fn object_terms_reject_non_canonical_members_of_every_kind() {
        assert!(resource_matches(
            "object",
            "ak:strand:AZXoIs9BRSgujgrZ-dLgogRh6YCdLWfJAZWdPXg8qD9D"
        ));
        assert!(!resource_matches("object", "ak:strand:main"));
        assert!(!resource_matches("object", "ak:blob:abc"));
    }
}
