//! Capability-grant / inheritance-policy derivation helpers.
//!
//! Free functions and snapshot types used by `apply_capability.rs`,
//! `apply_realm_lifecycle.rs`, and the capability/inheritance dispatch
//! paths. Split out of the `reducer` mod file; re-exported there
//! (`pub(crate) use`) so sibling `super::*` consumers keep resolving them.

use std::collections::BTreeSet;

use arkret_identifiers::CellRef;
use arkret_state::lattice::CellState;
use serde_json::Value;

use super::{ProjectionState, RealmInheritancePolicyState};

pub(crate) const CAPABILITY_GRANT_CELL_PREFIX: &str = "ak:cell:ak.component.capability.grant.v1:";

#[derive(Clone, Debug)]
pub(crate) struct CapabilityGrantSnapshot {
    pub(crate) realm_id: Option<String>,
    pub(crate) actions: BTreeSet<String>,
    pub(crate) resources: Vec<Value>,
    pub(crate) constraints: Vec<Value>,
    pub(crate) capability_bundles: BTreeSet<String>,
    pub(crate) expires_at: Option<chrono::DateTime<chrono::Utc>>,
    pub(crate) revoked: bool,
}

#[derive(Clone, Debug)]
pub(crate) struct DerivedCapabilityEvaluation {
    pub(crate) effective_actions: Vec<String>,
    pub(crate) effective_resources: Vec<Value>,
}

pub(crate) fn is_capability_bearing_realm_link_kind(link_kind: &str) -> bool {
    matches!(link_kind, "governed_by" | "inherits_policy_from")
}

pub(crate) fn active_capability_inheritance_link_kind<'a>(
    state: &'a ProjectionState,
    realm_id: &str,
    source_realm_id: &str,
) -> Result<Option<&'a str>, &'static str> {
    if realm_id == source_realm_id {
        return Ok(None);
    }
    let mut saw_active_non_bearing_link = false;
    if let Some(rows) = state.realm_links.get(realm_id) {
        for row in rows {
            if row.target_realm_id != source_realm_id || row.status != "active" {
                continue;
            }
            if is_capability_bearing_realm_link_kind(&row.link_kind) {
                return Ok(Some(row.link_kind.as_str()));
            }
            saw_active_non_bearing_link = true;
        }
    }
    if saw_active_non_bearing_link {
        Err("realm_inheritance_link_kind_not_capability_bearing")
    } else {
        Err("realm_inheritance_parent_link_missing")
    }
}

pub(crate) fn has_active_realm_link_to_source(
    state: &ProjectionState,
    realm_id: &str,
    source_realm_id: &str,
) -> bool {
    state
        .realm_links
        .get(realm_id)
        .map(|rows| {
            rows.iter()
                .any(|row| row.target_realm_id == source_realm_id && row.status == "active")
        })
        .unwrap_or(false)
}

pub(crate) fn string_set_field(value: &Value, field: &str) -> BTreeSet<String> {
    value
        .get(field)
        .map(string_set_from_value)
        .unwrap_or_default()
}

pub(crate) fn string_set_from_value(value: &Value) -> BTreeSet<String> {
    match value {
        Value::String(s) => std::iter::once(s.clone()).collect(),
        Value::Array(values) => values
            .iter()
            .filter_map(Value::as_str)
            .map(ToOwned::to_owned)
            .collect(),
        _ => BTreeSet::new(),
    }
}

pub(crate) fn value_array_field(value: &Value, field: &str) -> Vec<Value> {
    value
        .get(field)
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
}

pub fn inheritance_allowed_policies(payload: &Value) -> Vec<String> {
    let mut out = string_set_field(payload, "allowed_policies");
    if let Some(inherits) = payload.get("inherits") {
        out.extend(string_set_field(inherits, "policy_rules"));
    }
    out.into_iter().collect()
}

pub(crate) fn inheritance_allowed_capability_bundles(payload: &Value) -> Vec<String> {
    let mut out = string_set_field(payload, "allowed_capability_bundles");
    if let Some(inherits) = payload.get("inherits") {
        out.extend(string_set_field(inherits, "capability_bundles"));
    }
    out.into_iter().collect()
}

pub(crate) fn derive_requested_actions(payload: &Value) -> BTreeSet<String> {
    let mut out = string_set_field(payload, "actions");
    out.extend(string_set_field(payload, "capabilities"));
    out
}

/// `capability-grant.schema.json` names the grant's selector list `resources`
/// and is `additionalProperties:false` over the grant root, so `resources` is
/// the only carrier a grant can present.
pub(crate) fn derive_requested_resources(payload: &Value) -> Vec<Value> {
    value_array_field(payload, "resources")
}

pub(crate) fn derive_requested_capability_bundles(payload: &Value) -> BTreeSet<String> {
    let mut out = string_set_field(payload, "capability_bundles");
    out.extend(string_set_field(payload, "allowed_capability_bundles"));
    out
}

pub(crate) fn expiry_from_payload(payload: &Value) -> Option<chrono::DateTime<chrono::Utc>> {
    payload
        .get("expires_at")
        .and_then(Value::as_str)
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .map(|dt| dt.with_timezone(&chrono::Utc))
}

pub(crate) fn parse_rfc3339_utc(
    value: &Value,
    field: &str,
) -> Option<chrono::DateTime<chrono::Utc>> {
    value
        .get(field)
        .and_then(Value::as_str)
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .map(|dt| dt.with_timezone(&chrono::Utc))
}

pub(crate) fn capability_grant_cells(
    state: &ProjectionState,
) -> impl Iterator<Item = (&CellRef, &Value)> {
    state.cells.iter().filter_map(|(cell_ref, cell_state)| {
        if !cell_ref.as_str().starts_with(CAPABILITY_GRANT_CELL_PREFIX) {
            return None;
        }
        match cell_state {
            CellState::Value(value) => Some((cell_ref, value)),
            CellState::Bottom(_) => None,
        }
    })
}

pub(crate) fn grant_ids_match(value: &Value, id: &str) -> bool {
    ["id", "grant_id"]
        .into_iter()
        .any(|field| value.get(field).and_then(Value::as_str) == Some(id))
}

pub(crate) fn grant_snapshot_from_value(value: &Value) -> CapabilityGrantSnapshot {
    let body = value
        .get("grant")
        .filter(|grant| grant.is_object())
        .unwrap_or(value);

    let mut actions = string_set_field(body, "actions");
    actions.extend(string_set_field(value, "actions"));

    let mut resources = value_array_field(body, "resources");
    resources.extend(value_array_field(value, "resources"));

    let mut constraints = value_array_field(body, "constraints");
    constraints.extend(value_array_field(value, "constraints"));

    let mut capability_bundles = string_set_field(body, "capability_bundles");
    capability_bundles.extend(string_set_field(value, "capability_bundles"));

    let realm_id = body
        .get("realm_id")
        .and_then(Value::as_str)
        .or_else(|| value.get("realm_id").and_then(Value::as_str))
        .map(ToOwned::to_owned);

    let expires_at = constraints
        .iter()
        .filter(|constraint| {
            constraint.get("constraint_kind").and_then(Value::as_str) == Some("temporal")
        })
        .filter_map(|constraint| parse_rfc3339_utc(constraint, "expires_at"))
        .min();

    let revoked = body
        .get("revoked")
        .and_then(Value::as_bool)
        .unwrap_or(false)
        || value
            .get("revoked")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        || body.get("revoked_at").is_some()
        || body.get("revoked_by").is_some()
        || value.get("revoked_at").is_some()
        || value.get("revoked_by").is_some();

    CapabilityGrantSnapshot {
        realm_id,
        actions,
        resources,
        constraints,
        capability_bundles,
        expires_at,
        revoked,
    }
}

pub(crate) fn grant_snapshot_from_cell_item(
    requested_ref: &str,
    item: &Value,
) -> Option<CapabilityGrantSnapshot> {
    let tag_matches = item.get("tag").and_then(Value::as_str) == Some(requested_ref);
    if let Some(value) = item.get("value")
        && (tag_matches || grant_ids_match(value, requested_ref))
    {
        return Some(grant_snapshot_from_value(value));
    }
    if tag_matches || grant_ids_match(item, requested_ref) {
        return Some(grant_snapshot_from_value(item));
    }
    None
}

pub(crate) fn find_capability_grant(
    state: &ProjectionState,
    requested_ref: &str,
) -> Option<CapabilityGrantSnapshot> {
    for (_cell_ref, value) in capability_grant_cells(state) {
        if let Some(items) = value.as_array() {
            for item in items {
                if let Some(grant) = grant_snapshot_from_cell_item(requested_ref, item) {
                    return Some(grant);
                }
            }
        } else if let Some(grant) = grant_snapshot_from_cell_item(requested_ref, value) {
            return Some(grant);
        }
    }
    None
}

/// AKP-0007 §8 — does the operation payload carry an authoritative
/// `ak.circle.member.manage` verdict for `circle_id`?
///
/// The Circle HTTP surface (`/_arkret/self/circles/{id}/members`) runs the
/// real `SolandAuthzEngine::check(sender, "ak.circle.member.manage",
/// "ak:circle:<44-char event token>", …)` — which evaluates the grant's `allowed_circle_ids`
/// selector — and stamps the result into the operation payload before handing
/// it to the reducer. The reducer treats this as a fail-closed assertion:
/// absent / false / mismatched-circle ⇒ not authorised.
///
/// Accepted shapes (any one suffices):
///   - `manage_capability_verified: true`
///   - `actor_capability: { action: "ak.circle.member.manage", circle_id: "ak:circle:…", allowed:
///     true }`
pub(crate) fn payload_asserts_circle_manage(payload: &Value, circle_id: &str) -> bool {
    if payload
        .get("manage_capability_verified")
        .and_then(Value::as_bool)
        == Some(true)
    {
        return true;
    }
    let Some(cap) = payload.get("actor_capability").filter(|v| v.is_object()) else {
        return false;
    };
    let action_ok = cap
        .get("action")
        .and_then(Value::as_str)
        .is_some_and(|a| a == arkret_wire::CapabilityActionId::CIRCLE_MEMBER_MANAGE);
    let allowed_ok = cap.get("allowed").and_then(Value::as_bool) == Some(true);
    // The stamped verdict MUST be scoped to *this* Circle (mirrors the
    // `allowed_circle_ids` selector the engine evaluated). A verdict that omits
    // `circle_id` is accepted (the engine already bound it), but a mismatched
    // id is rejected.
    let circle_ok = cap
        .get("circle_id")
        .and_then(Value::as_str)
        .is_none_or(|c| c == circle_id);
    action_ok && allowed_ok && circle_ok
}

pub(crate) fn validate_derived_capability(
    grant: &CapabilityGrantSnapshot,
    policy: &RealmInheritancePolicyState,
    payload: &Value,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<DerivedCapabilityEvaluation, &'static str> {
    if grant.revoked {
        return Err("capability_derived_source_grant_revoked");
    }
    if grant.expires_at.is_some_and(|expires_at| expires_at <= now) {
        return Err("capability_derived_source_grant_expired");
    }
    if grant
        .realm_id
        .as_deref()
        .is_some_and(|id| id != policy.source_realm_id)
    {
        return Err("capability_derived_source_grant_realm_mismatch");
    }

    let allowed_bundles: BTreeSet<String> =
        policy.allowed_capability_bundles.iter().cloned().collect();
    if !grant.capability_bundles.is_empty()
        && grant
            .capability_bundles
            .iter()
            .any(|bundle| !allowed_bundles.contains(bundle))
    {
        return Err("capability_derived_source_bundle_not_allowed");
    }

    let requested_bundles = derive_requested_capability_bundles(payload);
    if requested_bundles
        .iter()
        .any(|bundle| !allowed_bundles.contains(bundle))
    {
        return Err("capability_derived_bundle_not_allowed");
    }

    let requested_actions = derive_requested_actions(payload);
    if requested_actions
        .iter()
        .any(|action| !grant.actions.contains(action))
    {
        return Err("capability_derived_action_widening");
    }

    let requested_resources = derive_requested_resources(payload);
    if !requested_resources.is_empty()
        && requested_resources
            .iter()
            .any(|resource| !grant.resources.iter().any(|source| source == resource))
    {
        return Err("capability_derived_resource_widening");
    }

    if let Some(derived_expires_at) = expiry_from_payload(payload)
        && grant
            .expires_at
            .is_some_and(|source_expires_at| derived_expires_at > source_expires_at)
    {
        return Err("capability_derived_expiry_widening");
    }

    let requested_constraints = value_array_field(payload, "constraints");
    if !requested_constraints.is_empty()
        && grant.constraints.iter().any(|source| {
            !requested_constraints
                .iter()
                .any(|derived| derived == source)
        })
    {
        return Err("capability_derived_constraint_widening");
    }

    let effective_actions = if requested_actions.is_empty() {
        grant.actions.iter().cloned().collect()
    } else {
        requested_actions.into_iter().collect()
    };
    let effective_resources = if requested_resources.is_empty() {
        grant.resources.clone()
    } else {
        requested_resources
    };
    Ok(DerivedCapabilityEvaluation {
        effective_actions,
        effective_resources,
    })
}

#[cfg(test)]
mod alias_tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn capability_derivation_ignores_unregistered_bundle_carriers() {
        let payload = json!({
            "capability_bundles": ["canonical"],
            "bundle_ids": ["legacy-ids"],
            "bundles": ["legacy-plural"],
            "bundle": {"id": "legacy-wrapper", "actions": ["legacy-action"]},
            "actions": ["canonical-action"],
            "resources": [{"kind": "realm"}],
            "expires_at": "2026-09-02T00:00:00.000Z"
        });
        assert_eq!(
            derive_requested_capability_bundles(&payload),
            BTreeSet::from(["canonical".to_owned()])
        );
        assert_eq!(
            derive_requested_actions(&payload),
            BTreeSet::from(["canonical-action".to_owned()])
        );
        assert_eq!(derive_requested_resources(&payload).len(), 1);
        assert_eq!(
            expiry_from_payload(&payload),
            Some("2026-09-02T00:00:00Z".parse().unwrap())
        );
    }

    #[test]
    fn grant_lookup_ignores_non_grant_identifier_spellings() {
        assert!(grant_ids_match(&json!({"id": "grant-1"}), "grant-1"));
        assert!(grant_ids_match(&json!({"grant_id": "grant-1"}), "grant-1"));
        for field in ["capability_id", "event_id", "operation_id"] {
            assert!(!grant_ids_match(&json!({field: "grant-1"}), "grant-1"));
        }
        assert!(!grant_ids_match(
            &json!({"grant": {"id": "grant-1"}}),
            "grant-1"
        ));
    }
}
