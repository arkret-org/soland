//! P1 — capability control-plane projection.
//!
//! Projects `ak.capability.grant` / `ak.capability.revoke` /
//! `ak.capability.delegate` into the canonical cells declared by
//! `event-kind-registry.json`:
//!
//! - grant / revoke → `ak.component.capability.grant.v1` (or_set, one cell per `payload.grant_id`).
//! - delegate → `ak.component.capability.delegate.v1` (or_set, one cell per `payload.grant_id`)
//!   plus a `parent_grant_id` chain reference.
//!
//! Convergence rules (capabilities.md §12.1):
//! - **grant** = or_set **add**. The add dot is the reducer-deterministic
//!   `ak:operation:<operation_id>` (the soland reducer's per-event handle; the spec's
//!   `ak:event:<event_id>:<effect_index>` is the wire form). value = the canonical grant snapshot.
//! - **revoke** = or_set **observed-remove** on the *same* grant cell. We mark the surviving add(s)
//!   `revoked` (the read path filters `revoked*`). Terminal: a later re-add of the same `grant_id`
//!   MUST NOT revive a removed add — once a cell holds a revoked entry for the grant, every add
//!   carries the revoked tombstone forward.
//! - `bottom` is **inert** for or_set: we never produce a Bottom cell here.
//!
//! Acceptance / fail-closed: the envelope-level CBA discipline is enforced at
//! event ingest: DataEvents use `seal_ref`/`auth_context`, while reducer-input
//! Control Moves with effects must carry `seal_basis.leaves`. The reducer
//! trusts that gate and does the *structural* acceptance checks reachable at
//! the `Operation` boundary — a present
//! `grant_id`, a parseable issuer, and (for grant) a non-empty grant body.
//! Missing structural inputs ⇒ `Rejected` (P3 fail-closed), never a silent
//! no-op. This mirrors `apply_capability_derived`, which likewise validates
//! structure/causality against projected cells rather than re-running the
//! Seal acceptance judgment.

use super::*;

const RESOURCE_SELECTOR_MAX_ITEMS: usize = 256;
const RESOURCE_SELECTOR_JSON_MAX_BYTES: usize = 64 * 1024;

/// Map a cell grant body's resource selectors to the engine `Grant`'s
/// comma-disjoined `resource` String.
fn engine_resource_from_body(body: &Value, realm_id: &str) -> String {
    engine_resources_from_body(body, realm_id)
        .into_iter()
        .collect::<Vec<_>>()
        .join(",")
        .trim()
        .to_owned()
}

fn selector_string_field<'a>(selector: &'a Value, field: &str) -> Option<&'a str> {
    selector
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
}

fn selector_realm_id<'a>(selector: &'a Value, fallback: &'a str) -> &'a str {
    selector_string_field(selector, "realm_id")
        .or_else(|| selector_string_field(selector, "id").filter(|id| id.starts_with("ak:realm:")))
        .unwrap_or(fallback)
}

fn normalize_selector_object(selector: &Value, realm_id: &str) -> Option<String> {
    if let Some(id) = selector_string_field(selector, "id") {
        return Some(id.to_owned());
    }
    if let Some(object_ref) = selector_string_field(selector, "object_ref") {
        return Some(object_ref.to_owned());
    }
    let kind = selector.get("kind").and_then(Value::as_str)?;
    let match_scope = selector
        .get("match_scope")
        .and_then(Value::as_str)
        .unwrap_or("exact");
    match kind {
        "*" => Some("*".to_owned()),
        "realm" => Some(selector_realm_id(selector, realm_id).to_owned()),
        "space" => match match_scope {
            "realm_wide" => Some("space".to_owned()),
            "children" => {
                selector_string_field(selector, "space_id").map(|id| format!("space_child_of:{id}"))
            }
            "subtree" => selector_string_field(selector, "space_id")
                .map(|id| format!("space_subtree_of:{id}")),
            _ => selector_string_field(selector, "space_id").map(ToOwned::to_owned),
        },
        "circle" => selector_string_field(selector, "circle_id")
            .map(ToOwned::to_owned)
            .or_else(|| (match_scope == "realm_wide").then(|| "circle".to_owned())),
        "strand" => selector_string_field(selector, "strand_id")
            .map(ToOwned::to_owned)
            .or_else(|| Some("strand".to_owned())),
        "message" => selector_string_field(selector, "message_id")
            .map(ToOwned::to_owned)
            .or_else(|| Some("message".to_owned())),
        "morph" => selector_string_field(selector, "morph_id")
            .map(ToOwned::to_owned)
            .or_else(|| Some("morph".to_owned())),
        "relation" => selector_string_field(selector, "relation_id")
            .map(ToOwned::to_owned)
            .or_else(|| Some("relation".to_owned())),
        "view" => selector_string_field(selector, "view_id")
            .map(ToOwned::to_owned)
            .or_else(|| Some("view".to_owned())),
        "event" => selector_string_field(selector, "event_id")
            .map(ToOwned::to_owned)
            .or_else(|| Some("event".to_owned())),
        "actor" => selector_string_field(selector, "actor_id").map(ToOwned::to_owned),
        "schema" => selector_string_field(selector, "schema_ref")
            .map(ToOwned::to_owned)
            .or_else(|| Some("schema".to_owned())),
        "policy" => selector_string_field(selector, "policy_id")
            .map(ToOwned::to_owned)
            .or_else(|| Some("policy".to_owned())),
        "invite" => selector_string_field(selector, "invite_id")
            .map(ToOwned::to_owned)
            .or_else(|| Some("invite".to_owned())),
        "notification" => Some("notification".to_owned()),
        "read_cursor" => Some("read_cursor".to_owned()),
        "blob" => selector_string_field(selector, "blob_ref")
            .map(ToOwned::to_owned)
            .or_else(|| Some("blob".to_owned())),
        "object" => selector_string_field(selector, "object_type")
            .map(ToOwned::to_owned)
            .or_else(|| Some("object".to_owned())),
        _ => None,
    }
}

fn engine_resources_from_body(body: &Value, realm_id: &str) -> Vec<String> {
    let mut selectors = value_array_field(body, "resources");
    selectors.extend(value_array_field(body, "resource_selectors"));
    let mut resources = Vec::new();
    for selector in &selectors {
        match selector {
            Value::String(s) if !s.is_empty() => resources.push(s.clone()),
            Value::Object(_) => {
                if let Some(resource) = normalize_selector_object(selector, realm_id) {
                    resources.push(resource);
                }
            }
            _ => {}
        }
    }
    resources
}

fn engine_constraints_from_body(body: &Value) -> Vec<crate::capability::Constraint> {
    value_array_field(body, "constraints")
        .into_iter()
        .filter_map(|constraint| {
            serde_json::from_value(constraint.clone()).ok().or_else(|| {
                let mut canonical = constraint.as_object()?.clone();
                if canonical.get("constraint_type").and_then(Value::as_str)
                    != Some("scope_limitation")
                    || !canonical.contains_key("allowed_circle_ids")
                {
                    return None;
                }
                canonical.insert(
                    "constraint_type".to_owned(),
                    Value::String("allowed_circle_ids".to_owned()),
                );
                serde_json::from_value(Value::Object(canonical)).ok()
            })
        })
        .collect()
}

/// Build an engine-shaped `Grant` from a projected grant cell body. Returns
/// `None` only when the body has no actions (a grant with no actions cannot
/// authorize anything and must not enter the index).
fn engine_grant_from_cell_body(
    grant_id: &str,
    body: &Value,
    revoked: bool,
) -> Option<crate::capability::Grant> {
    if validate_grant_body_scope(body).is_err() {
        return None;
    }
    let realm_id = body
        .get("realm_id")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let issuer = body
        .get("issuer")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let subject = body
        .get("subject")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let actions: Vec<String> = string_set_field(body, "actions").into_iter().collect();
    if actions.is_empty() {
        return None;
    }
    let resource = engine_resource_from_body(body, &realm_id);
    let capability_action_registry_digest = body
        .get("capability_action_registry_digest")
        .and_then(Value::as_str)
        .and_then(|value| arkret_identifiers::Hash::new(value.to_owned()).ok());
    let constraints = engine_constraints_from_body(body);
    let created_at = body
        .get("issued_at")
        .or_else(|| body.get("created_at"))
        .and_then(Value::as_str)
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .map(|dt| dt.with_timezone(&chrono::Utc))
        .unwrap_or_else(chrono::Utc::now);
    let expires_at = body
        .get("expires_at")
        .and_then(Value::as_str)
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .map(|dt| dt.with_timezone(&chrono::Utc));
    let delegated_from = body
        .get("parent_grant_id")
        .or_else(|| body.get("delegated_from"))
        .and_then(Value::as_str)
        .map(ToOwned::to_owned);
    Some(crate::capability::Grant {
        grant_id: grant_id.to_owned(),
        realm_id,
        issuer,
        subject,
        resource,
        actions,
        capability_action_registry_digest,
        constraints,
        revoked,
        created_at,
        delegated_from,
        expires_at,
    })
}

pub fn engine_grant_from_capability_cell_state(
    grant_id: &str,
    cell_state: &CellState,
) -> Option<crate::capability::Grant> {
    let CellState::Value(Value::Array(items)) = cell_state else {
        return None;
    };
    if items.is_empty() {
        return None;
    }
    let revoked = items.iter().any(|item| {
        let value = item.get("value").unwrap_or(item);
        grant_snapshot_from_value(value).revoked
    });
    let last = items.last()?;
    let body = last.get("value").unwrap_or(last);
    engine_grant_from_cell_body(grant_id, body, revoked)
}

fn validate_grant_body_scope(body: &Value) -> Result<(), &'static str> {
    let actions = validate_grant_actions(body)?;
    crate::capability::validate_capability_actions(&actions)?;
    validate_capability_registry_binding(body, &actions)?;
    validate_grant_resources(body)
}

fn validate_capability_registry_binding(
    body: &Value,
    actions: &[String],
) -> Result<(), &'static str> {
    let digest = match body.get("capability_action_registry_digest") {
        None => None,
        Some(Value::String(value)) if value.starts_with("sha256:") => Some(
            arkret_identifiers::Hash::new(value.clone())
                .map_err(|_| "capability_grant_registry_digest_invalid")?,
        ),
        Some(_) => return Err("capability_grant_registry_digest_invalid"),
    };
    arkret_policy::validate_capability_action_registry_binding(actions, digest.as_ref())
        .map_err(|_| "capability_registry_basis_unavailable")
}

/// capabilities.md §8 — grants whose subject is an agent principal must carry
/// every registry-required typed constraint, and any `risk_tier=high` action
/// (or an action whose registry `required_constraints` list `expires_at`)
/// additionally requires a finite effective expiry. Low/medium-risk agent
/// grants may be non-expiring (revocation-governed, longevity-safe). Actions
/// absent from the registry default to high (registry fail-closed rule).
fn validate_agent_subject_grant_constraints(
    body: &Value,
    subject_is_agent: impl Fn(&str) -> bool,
) -> Result<(), &'static str> {
    use arkret_schema::CapabilityRiskTier;

    let Some(subject) = body.get("subject").and_then(Value::as_str) else {
        return Ok(());
    };
    if !subject_is_agent(subject) {
        return Ok(());
    }
    let Some(actions) = body.get("actions").and_then(Value::as_array) else {
        return Ok(());
    };
    let has_finite_expiry = body_effective_expires_at(body).is_some();
    for action in actions.iter().filter_map(Value::as_str) {
        let descriptor = arkret_schema::embedded_capability_action(action)
            .ok()
            .flatten();
        let (risk_tier, required_constraints) = match descriptor {
            Some(descriptor) => (
                descriptor.risk_tier,
                descriptor.required_constraints.as_slice(),
            ),
            // Unregistered action: registry_rules default it to high.
            None => (CapabilityRiskTier::High, &[] as &[String]),
        };
        let expiry_required = risk_tier == CapabilityRiskTier::High
            || required_constraints
                .iter()
                .any(|constraint| constraint == "expires_at");
        if expiry_required && !has_finite_expiry {
            return Err("agent_grant_expiry_required");
        }
        for required in required_constraints {
            if required == "expires_at" {
                continue;
            }
            if !grant_has_constraint(body, required) {
                return Err("agent_grant_constraint_missing");
            }
        }
    }
    Ok(())
}

/// A registry `required_constraints` token is satisfied when some declared
/// constraint object either carries a field of that name or names it as its
/// `constraint_type`.
fn grant_has_constraint(body: &Value, token: &str) -> bool {
    let Some(constraints) = body.get("constraints").and_then(Value::as_array) else {
        return false;
    };
    constraints.iter().any(|constraint| {
        constraint.get(token).is_some()
            || constraint.get("constraint_type").and_then(Value::as_str) == Some(token)
    })
}

fn validate_grant_actions(body: &Value) -> Result<Vec<String>, &'static str> {
    let Some(actions) = body.get("actions").and_then(Value::as_array) else {
        return Err("capability_grant_actions_empty");
    };
    if actions.is_empty() {
        return Err("capability_grant_actions_empty");
    }
    actions
        .iter()
        .map(|action| {
            action
                .as_str()
                .map(ToOwned::to_owned)
                .ok_or("capability_grant_action_invalid")
        })
        .collect()
}

fn validate_grant_resources(body: &Value) -> Result<(), &'static str> {
    let mut selectors = Vec::new();
    if let Some(resources) = body.get("resources") {
        let Some(resources) = resources.as_array() else {
            return Err("capability_grant_resources_invalid");
        };
        selectors.extend(resources.iter());
    }
    if let Some(resource_selectors) = body.get("resource_selectors") {
        let Some(resource_selectors) = resource_selectors.as_array() else {
            return Err("capability_grant_resources_invalid");
        };
        selectors.extend(resource_selectors.iter());
    }
    if selectors.is_empty() {
        return Err("capability_grant_resources_empty");
    }
    if selectors.len() > RESOURCE_SELECTOR_MAX_ITEMS {
        return Err("selector_too_complex");
    }
    let json_bytes =
        serde_json::to_vec(&selectors).map_err(|_| "capability_grant_resources_invalid")?;
    if json_bytes.len() > RESOURCE_SELECTOR_JSON_MAX_BYTES {
        return Err("selector_too_complex");
    }
    for selector in selectors {
        validate_resource_selector(selector)?;
    }
    Ok(())
}

fn validate_resource_selector(selector: &Value) -> Result<(), &'static str> {
    match selector {
        Value::String(pattern) => crate::capability::validate_resource_pattern(pattern),
        Value::Object(map) => crate::capability::validate_resource_selector_object(map),
        _ => Err("capability_grant_resources_invalid"),
    }
}

/// or_set add dot for a capability event. Deterministic per accepted event.
fn capability_add_dot(operation: &Operation) -> String {
    operation.operation_id.to_string()
}

/// Pull the canonical grant body out of a `ak.capability.grant` /
/// `ak.capability.delegate` payload. Accepts both the canonical wrapper
/// `{grant_id, grant: {…}}` (SDK `CapabilityGrantBuilder`) and a flat
/// payload that already *is* the grant body.
fn grant_body(payload: &Value) -> &Value {
    payload
        .get("grant")
        .filter(|grant| grant.is_object())
        .unwrap_or(payload)
}

/// Extract the issuer DID from a capability grant payload (top-level or
/// inside the embedded `grant` body).
fn grant_issuer(payload: &Value) -> Option<String> {
    grant_body(payload)
        .get("issuer")
        .and_then(Value::as_str)
        .or_else(|| payload.get("issuer").and_then(Value::as_str))
        .map(ToOwned::to_owned)
}

fn grant_parent_ref(payload: &Value) -> Option<&str> {
    let body = grant_body(payload);
    body.get("parent_grant_id")
        .or_else(|| body.get("delegated_from"))
        .or_else(|| payload.get("parent_grant_id"))
        .or_else(|| payload.get("delegated_from"))
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
}

fn grant_realm_id<'a>(body: &'a Value, operation: &'a Operation) -> &'a str {
    body.get("realm_id")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| operation.realm_id.as_str())
}

fn grant_expires_at(body: &Value) -> Option<chrono::DateTime<chrono::Utc>> {
    body.get("expires_at")
        .and_then(Value::as_str)
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .map(|dt| dt.with_timezone(&chrono::Utc))
}

fn body_effective_expires_at(body: &Value) -> Option<chrono::DateTime<chrono::Utc>> {
    let top_level = grant_expires_at(body);
    let constraint_expiry = value_array_field(body, "constraints")
        .into_iter()
        .filter_map(|constraint| {
            let constraint_type = constraint
                .get("constraint_type")
                .and_then(Value::as_str)
                .or_else(|| constraint.get("type").and_then(Value::as_str));
            if constraint_type != Some("temporal") {
                return None;
            }
            constraint
                .get("expires_at")
                .and_then(Value::as_str)
                .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
                .map(|dt| dt.with_timezone(&chrono::Utc))
        })
        .min();
    match (top_level, constraint_expiry) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (Some(a), None) => Some(a),
        (None, Some(b)) => Some(b),
        (None, None) => None,
    }
}

fn body_max_delegation_depth(body: &Value) -> Option<u32> {
    value_array_field(body, "constraints")
        .into_iter()
        .filter_map(|constraint| {
            let constraint_type = constraint
                .get("constraint_type")
                .and_then(Value::as_str)
                .or_else(|| constraint.get("type").and_then(Value::as_str));
            if constraint_type != Some("delegation_control") {
                return None;
            }
            constraint
                .get("max_delegation_depth")
                .and_then(Value::as_u64)
                .and_then(|value| u32::try_from(value).ok())
        })
        .min()
}

/// Build the canonical or_set item value stored under a grant cell. We keep
/// the full grant body so the existing `grant_snapshot_from_value` reader
/// (actions / resources / constraints / realm_id / expires_at / revoked)
/// resolves it unchanged, and stamp a normalized `grant_id` / `realm_id`.
fn grant_item_value(
    operation: &Operation,
    grant_id: &str,
    revoked: bool,
    now: chrono::DateTime<chrono::Utc>,
) -> Value {
    let mut body = grant_body(&operation.payload).clone();
    if !body.is_object() {
        body = serde_json::json!({});
    }
    if let Value::Object(map) = &mut body {
        map.insert("grant_id".to_owned(), Value::String(grant_id.to_owned()));
        map.entry("realm_id".to_owned())
            .or_insert_with(|| Value::String(operation.realm_id.to_string()));
        if revoked {
            map.insert("revoked".to_owned(), Value::Bool(true));
            map.entry("revoked_at".to_owned()).or_insert_with(|| {
                Value::String(arkret_canonical::format_timestamp_canonical(now))
            });
        }
    }
    body
}

impl ProjectionState {
    fn capability_grant_cell_ref(grant_id: &str) -> Option<CellRef> {
        CellRef::new(format!(
            "ak:cell:ak.component.capability.grant.v1:{grant_id}"
        ))
        .ok()
    }

    fn capability_delegate_cell_ref(grant_id: &str) -> Option<CellRef> {
        CellRef::new(format!(
            "ak:cell:ak.component.capability.delegate.v1:{grant_id}"
        ))
        .ok()
    }

    /// Read the current or_set item array for a grant cell (empty when the
    /// cell is absent / Bottom / not an array).
    fn capability_cell_items(&self, cell_ref: &CellRef) -> Vec<Value> {
        match self.cells.get(cell_ref) {
            Some(CellState::Value(Value::Array(items))) => items.clone(),
            _ => Vec::new(),
        }
    }

    pub fn issuer_has_projected_capability(
        &self,
        issuer: &str,
        realm_id: &str,
        action: &str,
        resource: &str,
    ) -> bool {
        if self
            .realm_states
            .get(realm_id)
            .and_then(|realm| realm.owner.as_deref())
            .is_some_and(|owner| owner == issuer)
        {
            return true;
        }
        const CELL_PREFIX: &str = "ak:cell:ak.component.capability.grant.v1:";
        let resource_expr = self.authz_resource_expr(realm_id, resource);
        self.cells.iter().any(|(cell_ref, cell_state)| {
            let Some(grant_id) = cell_ref.as_str().strip_prefix(CELL_PREFIX) else {
                return false;
            };
            let Some(grant) = engine_grant_from_capability_cell_state(grant_id, cell_state) else {
                return false;
            };
            grant.realm_id == realm_id
                && grant.subject == issuer
                && !grant.revoked
                && grant
                    .expires_at
                    .is_none_or(|expires_at| expires_at > chrono::Utc::now())
                && grant.actions.iter().any(|candidate| candidate == action)
                && crate::capability::resource_matches(&grant.resource, &resource_expr)
        })
    }

    fn validate_grant_issuer_upper_bound(&self, operation: &Operation) -> Result<(), &'static str> {
        if let Some(parent_grant_id) = grant_parent_ref(&operation.payload) {
            return self.validate_delegated_grant_issuer_upper_bound(operation, parent_grant_id);
        }
        let body = grant_body(&operation.payload);
        let issuer = grant_issuer(&operation.payload).ok_or("capability_grant_issuer_missing")?;
        let actions = validate_grant_actions(body)?;
        let realm_id = grant_realm_id(body, operation);
        let resources = engine_resources_from_body(body, realm_id);
        if resources.is_empty() {
            return Err("capability_grant_resources_empty");
        }
        for action in &actions {
            for resource in &resources {
                if !self.issuer_has_projected_capability(&issuer, realm_id, action, resource) {
                    return Err("grant_exceeds_issuer_authority");
                }
            }
        }
        Ok(())
    }

    fn validate_delegated_grant_issuer_upper_bound(
        &self,
        operation: &Operation,
        parent_grant_id: &str,
    ) -> Result<(), &'static str> {
        let parent = self
            .effective_engine_grant(parent_grant_id)
            .ok_or("grant_revoked_upstream")?;
        if parent.revoked || crate::capability::is_grant_expired(&parent, operation.created_at) {
            return Err("grant_revoked_upstream");
        }
        let body = grant_body(&operation.payload);
        let issuer = grant_issuer(&operation.payload).ok_or("capability_grant_issuer_missing")?;
        if issuer != parent.subject {
            return Err("grant_exceeds_issuer_authority");
        }
        let realm_id = grant_realm_id(body, operation);
        if realm_id != parent.realm_id {
            return Err("grant_exceeds_issuer_authority");
        }
        let actions = validate_grant_actions(body)?;
        for action in &actions {
            if !parent.actions.iter().any(|candidate| candidate == action) {
                return Err("grant_exceeds_issuer_authority");
            }
        }
        let resources = engine_resources_from_body(body, realm_id);
        if resources.is_empty() {
            return Err("capability_grant_resources_empty");
        }
        for resource in &resources {
            let resource_expr = self.authz_resource_expr(realm_id, resource);
            if !crate::capability::resource_matches(&parent.resource, &resource_expr) {
                return Err("grant_exceeds_issuer_authority");
            }
        }
        if let Some(parent_depth) = crate::capability::max_delegation_depth(&parent) {
            if parent_depth == 0 {
                return Err("delegation_depth_exceeded");
            }
            match body_max_delegation_depth(body) {
                Some(child_depth) if child_depth <= parent_depth.saturating_sub(1) => {}
                _ => return Err("delegation_depth_exceeded"),
            }
        }
        let child_expires_at = body_effective_expires_at(body);
        if let Some(parent_expires_at) = crate::capability::grant_effective_expiry(&parent) {
            let Some(child_expires_at) = child_expires_at else {
                return Err("delegation_expiry_widening");
            };
            if child_expires_at > parent_expires_at {
                return Err("delegation_expiry_widening");
            }
        }
        Ok(())
    }

    /// True when any existing or_set item for this cell is already
    /// observed-removed (revoked). Drives the §12.1 terminal rule: once a
    /// grant_id has been revoked, re-adds stay revoked.
    fn capability_cell_has_revoked_item(items: &[Value]) -> bool {
        items.iter().any(|item| {
            let value = item.get("value").unwrap_or(item);
            grant_snapshot_from_value(value).revoked
        })
    }

    /// P1 — derive the engine-shaped effective `Grant` for one grant cell so
    /// the projection driver can fold it into the `SolandAuthzEngine` read
    /// index. Returns `None` when the cell is absent / carries no resolvable
    /// grant body. The returned `revoked` flag is set when *any* surviving
    /// add for this grant_id is observed-removed (the §12.1 terminal rule
    /// means a re-add never revives, so a single revoked item makes the whole
    /// grant_id revoked).
    pub fn effective_engine_grant(&self, grant_id: &str) -> Option<crate::capability::Grant> {
        let cell_ref = Self::capability_grant_cell_ref(grant_id)?;
        let items = self.capability_cell_items(&cell_ref);
        if items.is_empty() {
            return None;
        }
        let revoked = Self::capability_cell_has_revoked_item(&items);
        // Use the most recent add's body for the live grant attributes
        // (actions / resource / subject / issuer). All adds for a grant_id
        // describe the same grant; the last one wins on attributes.
        let last = items.last()?;
        let body = last.get("value").unwrap_or(last);
        engine_grant_from_cell_body(grant_id, body, revoked)
    }

    /// P1 — project `ak.capability.grant` as an or_set add on the grant cell.
    pub(crate) fn apply_capability_grant(
        &mut self,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
    ) -> ProjectionEffect {
        let Some(grant_id) = operation
            .payload
            .get("grant_id")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
        else {
            return ProjectionEffect::Rejected {
                reason: "capability_grant_id_missing".to_owned(),
            };
        };
        // Structural acceptance: a grant MUST name its issuer (capabilities.md
        // §3 — the grant is held by the issuer; the issuer MUST hold the
        // action). Missing issuer ⇒ fail closed.
        if grant_issuer(&operation.payload).is_none() {
            return ProjectionEffect::Rejected {
                reason: "capability_grant_issuer_missing".to_owned(),
            };
        }
        if let Err(reason) = validate_grant_body_scope(grant_body(&operation.payload)) {
            return ProjectionEffect::Rejected {
                reason: reason.to_owned(),
            };
        }
        if let Err(reason) =
            validate_agent_subject_grant_constraints(grant_body(&operation.payload), |subject| {
                self.agent_lifecycles.contains_key(subject)
            })
        {
            return ProjectionEffect::Rejected {
                reason: reason.to_owned(),
            };
        }
        if let Err(reason) = self.validate_grant_issuer_upper_bound(operation) {
            return ProjectionEffect::Rejected {
                reason: reason.to_owned(),
            };
        }
        let realm_id = operation.realm_id.to_string();
        let Some(cell_ref) = Self::capability_grant_cell_ref(&grant_id) else {
            return ProjectionEffect::Rejected {
                reason: "capability_grant_cell_ref_invalid".to_owned(),
            };
        };

        let mut items = self.capability_cell_items(&cell_ref);
        // §12.1 terminal: a re-add of an already observed-removed grant_id
        // does NOT revive. Carry the revoked tombstone onto the new add.
        let terminal_revoked = Self::capability_cell_has_revoked_item(&items);
        let value = grant_item_value(operation, &grant_id, terminal_revoked, now);
        items.push(serde_json::json!({
            "tag": capability_add_dot(operation),
            "value": value,
        }));
        self.cells
            .insert(cell_ref, CellState::Value(Value::Array(items)));

        ProjectionEffect::CapabilityGrantProjected { grant_id, realm_id }
    }

    /// Apply the one ordinary-Realm founding grant after the server has
    /// validated the complete `create -> founding grant` protocol unit.
    /// Genesis cannot use the ordinary issuer-upper-bound check because this
    /// grant establishes that very first bound.
    pub fn apply_validated_realm_founding_grant(
        &mut self,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
    ) -> ProjectionEffect {
        let Some(grant_id) = operation
            .payload
            .get("grant_id")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
        else {
            return ProjectionEffect::Rejected {
                reason: "capability_grant_id_missing".to_owned(),
            };
        };
        if grant_issuer(&operation.payload).is_none() {
            return ProjectionEffect::Rejected {
                reason: "capability_grant_issuer_missing".to_owned(),
            };
        }
        let Some(cell_ref) = Self::capability_grant_cell_ref(&grant_id) else {
            return ProjectionEffect::Rejected {
                reason: "capability_grant_cell_ref_invalid".to_owned(),
            };
        };
        let mut items = self.capability_cell_items(&cell_ref);
        let terminal_revoked = Self::capability_cell_has_revoked_item(&items);
        let value = grant_item_value(operation, &grant_id, terminal_revoked, now);
        items.push(serde_json::json!({
            "tag": capability_add_dot(operation),
            "value": value,
        }));
        self.cells
            .insert(cell_ref, CellState::Value(Value::Array(items)));
        ProjectionEffect::CapabilityGrantProjected {
            grant_id,
            realm_id: operation.realm_id.to_string(),
        }
    }

    /// P1 — project `ak.capability.revoke` as an or_set observed-remove on the
    /// target grant cell. The revoke locates the cell by the top-level
    /// `grant_id` (capabilities.md §12 — payload carries the grant_id, no
    /// frontier). Idempotent: revoking an already-revoked grant is a no-op
    /// converge.
    pub(crate) fn apply_capability_revoke(
        &mut self,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
    ) -> ProjectionEffect {
        let Some(grant_id) = operation
            .payload
            .get("grant_id")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
        else {
            return ProjectionEffect::Rejected {
                reason: "capability_revoke_grant_id_missing".to_owned(),
            };
        };
        let realm_id = operation.realm_id.to_string();
        let Some(cell_ref) = Self::capability_grant_cell_ref(&grant_id) else {
            return ProjectionEffect::Rejected {
                reason: "capability_revoke_cell_ref_invalid".to_owned(),
            };
        };

        let mut items = self.capability_cell_items(&cell_ref);
        let revoked_at = arkret_canonical::format_timestamp_canonical(now);
        if items.is_empty() {
            // Revoke-before-grant (or revoke of a grant this server never
            // projected): write a tombstone-only item so the terminal rule
            // holds and a later re-grant of the same grant_id stays revoked.
            items.push(serde_json::json!({
                "tag": capability_add_dot(operation),
                "value": {
                    "grant_id": grant_id,
                    "realm_id": realm_id,
                    "revoked": true,
                    "revoked_at": revoked_at,
                },
            }));
        } else {
            // Observed-remove: mark every surviving add for this grant_id
            // revoked (terminal). Multi-issuer concurrent revoke converges on
            // the or_set dedup semantics — repeated revoke is idempotent.
            for item in &mut items {
                let target = if item.get("value").is_some() {
                    item.get_mut("value").expect("value present")
                } else {
                    item
                };
                if let Value::Object(map) = target {
                    map.insert("revoked".to_owned(), Value::Bool(true));
                    map.entry("revoked_at".to_owned())
                        .or_insert_with(|| Value::String(revoked_at.clone()));
                }
            }
        }
        self.cells
            .insert(cell_ref, CellState::Value(Value::Array(items)));

        ProjectionEffect::CapabilityRevokeProjected { grant_id, realm_id }
    }

    /// P1 — project `ak.capability.delegate` into the delegate or_set cell.
    /// Same convergence as grant (add-dot keyed by operation_id), plus a
    /// `parent_grant_id` chain reference (capabilities.md §10). A delegate
    /// MUST name its parent grant; missing parent ⇒ fail closed.
    pub(crate) fn apply_capability_delegate(
        &mut self,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
    ) -> ProjectionEffect {
        let Some(grant_id) = operation
            .payload
            .get("grant_id")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
        else {
            return ProjectionEffect::Rejected {
                reason: "capability_delegate_grant_id_missing".to_owned(),
            };
        };
        let body = grant_body(&operation.payload);
        let parent_grant_id = body
            .get("parent_grant_id")
            .and_then(Value::as_str)
            .or_else(|| {
                operation
                    .payload
                    .get("parent_grant_id")
                    .and_then(Value::as_str)
            })
            .map(ToOwned::to_owned);
        let Some(parent) = parent_grant_id.clone() else {
            return ProjectionEffect::Rejected {
                reason: "capability_delegate_parent_missing".to_owned(),
            };
        };
        if grant_issuer(&operation.payload).is_none() {
            return ProjectionEffect::Rejected {
                reason: "capability_delegate_issuer_missing".to_owned(),
            };
        }
        if let Err(reason) = validate_grant_body_scope(body) {
            return ProjectionEffect::Rejected {
                reason: reason.to_owned(),
            };
        }
        if let Err(reason) = validate_agent_subject_grant_constraints(body, |subject| {
            self.agent_lifecycles.contains_key(subject)
        }) {
            return ProjectionEffect::Rejected {
                reason: reason.to_owned(),
            };
        }
        if let Err(reason) = self.validate_delegated_grant_issuer_upper_bound(operation, &parent) {
            return ProjectionEffect::Rejected {
                reason: reason.to_owned(),
            };
        }
        let realm_id = operation.realm_id.to_string();
        let Some(cell_ref) = Self::capability_delegate_cell_ref(&grant_id) else {
            return ProjectionEffect::Rejected {
                reason: "capability_delegate_cell_ref_invalid".to_owned(),
            };
        };

        let mut items = self.capability_cell_items(&cell_ref);
        let terminal_revoked = Self::capability_cell_has_revoked_item(&items);
        let mut value = grant_item_value(operation, &grant_id, terminal_revoked, now);
        if let Value::Object(map) = &mut value {
            map.insert("parent_grant_id".to_owned(), Value::String(parent.clone()));
        }
        items.push(serde_json::json!({
            "tag": capability_add_dot(operation),
            "value": value,
            // refs[role="parent_grant"] — delegation chain anchor (§10).
            "refs": [{ "role": "parent_grant", "id": parent }],
        }));
        self.cells
            .insert(cell_ref, CellState::Value(Value::Array(items)));

        ProjectionEffect::CapabilityDelegateProjected {
            grant_id,
            realm_id,
            parent_grant_id,
        }
    }

    /// Resolve a delegated grant's parent grant id from its delegate cell
    /// (`refs[role="parent_grant"]` / `value.parent_grant_id`). Returns `None`
    /// for root grants (no delegate cell) — which terminates the chain walk.
    fn delegate_parent_of(&self, grant_id: &str) -> Option<String> {
        let cell_ref = Self::capability_delegate_cell_ref(grant_id)?;
        let items = self.capability_cell_items(&cell_ref);
        let last = items.last()?;
        let body = last.get("value").unwrap_or(last);
        body.get("parent_grant_id")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
    }

    /// capabilities.md §10.2 — DFS the parent chain of an incoming
    /// `ak.capability.delegate(child_grant_id, parent_grant_id)`; reject the
    /// whole delegation with `delegation_cycle` if the new child closes a cycle
    /// (appears as one of its own ancestors) or the chain already contains one.
    /// A `delegation_cycle` MUST NOT project even if each grant looks valid
    /// individually. Runs at ingest (pre-commit) so the cyclic edge never enters
    /// the delegate cell / authz index.
    pub fn check_delegation_cycle(&self, operation: &Operation) -> Result<(), &'static str> {
        if crate::kinds::canonical_kind_for_operation(operation)
            != Some(arkret_wire::events::EventKind::CAPABILITY_DELEGATE)
        {
            return Ok(());
        }
        let body = grant_body(&operation.payload);
        let Some(grant_id) = operation.payload.get("grant_id").and_then(Value::as_str) else {
            return Ok(());
        };
        let parent = body
            .get("parent_grant_id")
            .and_then(Value::as_str)
            .or_else(|| {
                operation
                    .payload
                    .get("parent_grant_id")
                    .and_then(Value::as_str)
            });
        let Some(parent) = parent else {
            return Ok(());
        };
        let mut visited: std::collections::HashSet<String> = std::collections::HashSet::new();
        visited.insert(grant_id.to_owned());
        let mut cursor = Some(parent.to_owned());
        while let Some(node) = cursor {
            if node == grant_id || !visited.insert(node.clone()) {
                return Err("delegation_cycle");
            }
            cursor = self.delegate_parent_of(&node);
        }
        Ok(())
    }

    /// Project `ak.agent.key.authorize`: record the authorized key for the
    /// agent. Realm grants are independent from key pairing. Idempotent: a
    /// re-authorization of the same key id converges.
    pub(crate) fn apply_agent_key_authorize(&mut self, operation: &Operation) -> ProjectionEffect {
        let Some(agent_id) = operation
            .payload
            .get("agent_id")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
        else {
            return ProjectionEffect::Rejected {
                reason: "agent_key_authorize_missing_agent_id".to_owned(),
            };
        };
        let Some(key_id) = operation
            .payload
            .get("key_id")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
        else {
            return ProjectionEffect::Rejected {
                reason: "agent_key_authorize_missing_key_id".to_owned(),
            };
        };
        let Some(authorized_event_ref) = operation
            .payload
            .get("accepted_event_id")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
        else {
            return ProjectionEffect::Rejected {
                reason: "agent_key_authorize_missing_accepted_event_id".to_owned(),
            };
        };
        let active = self
            .agent_authorized_keys
            .get(&agent_id)
            .cloned()
            .unwrap_or_default();
        let supersedes = match operation.payload.get("supersedes") {
            None => Vec::new(),
            Some(Value::Array(values)) => {
                let mut parsed = Vec::with_capacity(values.len());
                for value in values {
                    let Some(key_id) = value.get("key_id").and_then(Value::as_str) else {
                        return ProjectionEffect::Rejected {
                            reason: "agent_key_supersedes_invalid".to_owned(),
                        };
                    };
                    let Some(event_ref) = value.get("authorized_event_ref").and_then(Value::as_str)
                    else {
                        return ProjectionEffect::Rejected {
                            reason: "agent_key_supersedes_invalid".to_owned(),
                        };
                    };
                    parsed.push((key_id.to_owned(), event_ref.to_owned()));
                }
                parsed
            }
            Some(_) => {
                return ProjectionEffect::Rejected {
                    reason: "agent_key_supersedes_invalid".to_owned(),
                };
            }
        };
        let pairing_replacement = operation
            .payload
            .get("approval_evidence")
            .and_then(|evidence| evidence.get("kind"))
            .and_then(Value::as_str)
            == Some("pairing_request")
            && !active.is_empty();
        let replacing_other_keys = active.keys().any(|active_key| active_key != &key_id);
        if pairing_replacement {
            let expected: std::collections::BTreeSet<_> = active
                .iter()
                .map(|(active_key, event_ref)| (active_key.clone(), event_ref.clone()))
                .collect();
            let supplied: std::collections::BTreeSet<_> = supersedes.iter().cloned().collect();
            if supplied.len() != supersedes.len() || supplied != expected {
                return ProjectionEffect::Rejected {
                    reason: "agent_key_supersedes_state_mismatch".to_owned(),
                };
            }
        } else if replacing_other_keys {
            let expected: std::collections::BTreeSet<_> = active
                .iter()
                .filter(|(active_key, _)| *active_key != &key_id)
                .map(|(active_key, event_ref)| (active_key.clone(), event_ref.clone()))
                .collect();
            let supplied: std::collections::BTreeSet<_> = supersedes.iter().cloned().collect();
            if supplied.len() != supersedes.len() || supplied != expected {
                return ProjectionEffect::Rejected {
                    reason: "agent_key_supersedes_state_mismatch".to_owned(),
                };
            }
        } else if !supersedes.is_empty() {
            return ProjectionEffect::Rejected {
                reason: "agent_key_supersedes_state_mismatch".to_owned(),
            };
        }
        let active = self
            .agent_authorized_keys
            .entry(agent_id.clone())
            .or_default();
        for (superseded_key, _) in supersedes {
            active.remove(&superseded_key);
        }
        active.insert(key_id.clone(), authorized_event_ref);
        ProjectionEffect::AgentKeyAuthorizeProjected { agent_id, key_id }
    }

    /// AKP-0008 §4.11 — project `ak.agent.key.revoke`: remove the key from
    /// the agent's authorized-key set (idempotent).
    pub(crate) fn apply_agent_key_revoke(&mut self, operation: &Operation) -> ProjectionEffect {
        let Some(agent_id) = operation
            .payload
            .get("agent_id")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
        else {
            return ProjectionEffect::Rejected {
                reason: "agent_key_revoke_missing_agent_id".to_owned(),
            };
        };
        let Some(key_id) = operation
            .payload
            .get("key_id")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
        else {
            return ProjectionEffect::Rejected {
                reason: "agent_key_revoke_missing_key_id".to_owned(),
            };
        };
        if let Some(keys) = self.agent_authorized_keys.get_mut(&agent_id) {
            keys.remove(&key_id);
            if keys.is_empty() {
                self.agent_authorized_keys.remove(&agent_id);
            }
        }
        ProjectionEffect::AgentKeyRevokeProjected { agent_id, key_id }
    }

    /// Every persisted capability grant for `subject_did`, paired with the
    /// Realm that governs its grant cell. Revocation must be submitted in
    /// this Realm; a controller PCR is not a cross-Realm revocation surface.
    pub fn grant_locations_for_subject(&self, subject_did: &str) -> Vec<(String, String)> {
        let cell_prefix = "ak:cell:ak.component.capability.grant.v1:";
        let mut locations = std::collections::BTreeSet::new();
        for (cell_ref, cell_state) in &self.cells {
            if !cell_ref.as_str().starts_with(cell_prefix) {
                continue;
            }
            let CellState::Value(Value::Array(items)) = cell_state else {
                continue;
            };
            for item in items {
                let body = item.get("value").unwrap_or(item);
                let subject_matches = body
                    .get("subject")
                    .and_then(Value::as_str)
                    .map(|subject| subject == subject_did)
                    .unwrap_or(false);
                if subject_matches
                    && let Some(grant_id) = body
                        .get("grant_id")
                        .or_else(|| body.get("id"))
                        .and_then(Value::as_str)
                    && let Some(realm_id) = body.get("realm_id").and_then(Value::as_str)
                {
                    locations.insert((grant_id.to_owned(), realm_id.to_owned()));
                }
            }
        }
        locations.into_iter().collect()
    }

    /// Non-terminal grants for `subject_did`, including pending Agent grants
    /// that are durable but not yet in the effective authz index.
    pub fn unrevoked_grant_locations_for_subject(
        &self,
        subject_did: &str,
    ) -> Vec<(String, String)> {
        self.grant_locations_for_subject(subject_did)
            .into_iter()
            .filter(|(grant_id, _)| {
                let Some(cell_ref) = Self::capability_grant_cell_ref(grant_id) else {
                    return false;
                };
                let items = self.capability_cell_items(&cell_ref);
                !items.is_empty() && !Self::capability_cell_has_revoked_item(&items)
            })
            .collect()
    }

    /// `sync/federation.md` §4.4 Capability Revoke Fanout — the set of peer
    /// service DIDs whose federation service delegation for `realm_id` has been
    /// revoked. A "service delegation" is a capability grant whose `subject` is
    /// a service DID (`did:`-prefixed). Once such a grant carries a revoked
    /// tombstone (or_set observed-remove, terminal per capabilities.md §12.1),
    /// the source Principal Server MUST stop pushing future events for that
    /// Realm to the revoked peer. Scanning the grant cells keeps this derivable
    /// from durable capability events with no extra durable column.
    pub fn federation_delivery_revoked_peers(
        &self,
        realm_id: &str,
    ) -> std::collections::BTreeSet<String> {
        let cell_prefix = "ak:cell:ak.component.capability.grant.v1:";
        let mut revoked: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        for (cell_ref, cell_state) in &self.cells {
            if !cell_ref.as_str().starts_with(cell_prefix) {
                continue;
            }
            let CellState::Value(Value::Array(items)) = cell_state else {
                continue;
            };
            // Terminal or_set semantics: if any surviving add for this grant
            // cell is revoked, the whole grant_id is revoked (capabilities.md
            // §12.1). Snapshot subject + grant realm from the latest add.
            let any_revoked = items.iter().any(|item| {
                let body = item.get("value").unwrap_or(item);
                body.get("revoked")
                    .and_then(Value::as_bool)
                    .unwrap_or(false)
            });
            if !any_revoked {
                continue;
            }
            let Some(last) = items.last() else {
                continue;
            };
            let body = last.get("value").unwrap_or(last);
            let grant_realm = body
                .get("realm_id")
                .and_then(Value::as_str)
                .unwrap_or_default();
            if grant_realm != realm_id {
                continue;
            }
            if let Some(subject) = body.get("subject").and_then(Value::as_str)
                && subject.starts_with("did:")
            {
                revoked.insert(subject.to_owned());
            }
        }
        revoked
    }

    /// AKP-0008 §4.11 — the authorized key ids the agent currently holds
    /// (for the deactivate `ak.agent.key.revoke` fan-out).
    pub fn authorized_key_ids_for(&self, agent_id: &str) -> Vec<String> {
        self.agent_authorized_keys
            .get(agent_id)
            .map(|keys| keys.keys().cloned().collect())
            .unwrap_or_default()
    }

    pub fn active_agent_key_authorizations(&self, agent_id: &str) -> Vec<(String, String)> {
        self.agent_authorized_keys
            .get(agent_id)
            .map(|keys| {
                keys.iter()
                    .map(|(key_id, event_ref)| (key_id.clone(), event_ref.clone()))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// True when the agent principal has at least one accepted, non-revoked
    /// agent key authorization.
    pub fn agent_has_authorized_key(&self, agent_id: &str) -> bool {
        self.agent_authorized_keys
            .get(agent_id)
            .map(|keys| !keys.is_empty())
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod agent_key_tests {
    use arkret_event_draft::Operation;
    use arkret_identifiers::{OperationId, RealmId};
    use arkret_wire::OperationType;
    use serde_json::json;

    use crate::reducer::{ProjectionState, SolandRealmState};

    const AGENT: &str = "did:web:agent.example";
    const REALM: &str = "ak:realm:01970000-0000-7000-8000-000000000000";
    const GRANT: &str = "ak:grant:01970000-0000-7000-8000-0000000000a1";
    const GRANT_2: &str = "ak:grant:01970000-0000-7000-8000-0000000000a2";
    const GRANT_3: &str = "ak:grant:01970000-0000-7000-8000-0000000000a3";

    fn op(kind_object_type: &str, payload: serde_json::Value) -> Operation {
        Operation {
            schema: "ak.schema.operation.v1".to_owned(),
            operation_id: OperationId::new("ak:operation:01970000-0000-7000-8000-0000000000ff")
                .unwrap(),
            record_type: "operation".to_owned(),
            operation_type: OperationType::Create,
            realm_id: RealmId::new(REALM.to_owned()).unwrap(),
            object_id: None,
            object_type: kind_object_type.to_owned(),
            payload,
            refs: Vec::new(),
            idempotency_key: None,
            created_at: chrono::Utc::now(),
            canonical_event_digest: None,
        }
    }

    fn grant_payload(
        grant_id: &str,
        issuer: &str,
        subject: &str,
        actions: serde_json::Value,
        resources: serde_json::Value,
    ) -> serde_json::Value {
        json!({
            "grant_id": grant_id,
            "grant": {
                "id": grant_id,
                "schema": "ak.schema.capability_grant.v1",
                "realm_id": REALM,
                "issuer": issuer,
                "subject": subject,
                "actions": actions,
                "resources": resources,
            }
        })
    }

    fn seed_realm_owner(state: &mut ProjectionState) {
        let now = chrono::Utc::now();
        state.realm_states.insert(
            REALM.to_owned(),
            SolandRealmState {
                realm_id: REALM.to_owned(),
                owner: Some("did:web:alice.example".to_owned()),
                title: None,
                deleted: false,
                archived: false,
                frozen: false,
                freeze_expires_at: None,
                created_at: now,
                updated_at: now,
                trust_domain: None,
                terminal_state: None,
                successor_realm_id: None,
                default_strand_id: None,
                active_profiles: Vec::new(),
            },
        );
    }

    #[test]
    fn aggregate_admin_grant_requires_registry_basis() {
        let body = json!({
            "actions": ["ak.realm.admin"],
            "resources": [{ "kind": "realm", "realm_id": REALM }]
        });
        assert_eq!(
            super::validate_grant_body_scope(&body),
            Err("capability_registry_basis_unavailable")
        );
    }

    #[test]
    fn aggregate_admin_grant_accepts_current_registry_basis() {
        let digest = arkret_policy::current_capability_action_registry_digest().unwrap();
        let body = json!({
            "actions": ["ak.realm.admin"],
            "resources": [{ "kind": "realm", "realm_id": REALM }],
            "capability_action_registry_digest": digest,
        });
        assert_eq!(super::validate_grant_body_scope(&body), Ok(()));
    }

    #[test]
    fn runtime_replacement_requires_exact_supersedes_and_is_atomic() {
        let mut state = ProjectionState::default();
        let old_event = "ak:event:01970000-0000-7000-8000-000000000011";
        let new_event = "ak:event:01970000-0000-7000-8000-000000000012";
        let old_key = "ak:agent_key:old";
        let new_key = "ak:agent_key:new";

        assert!(matches!(
            state.apply_agent_key_authorize(&op(
                "agent_key_authorize",
                json!({
                    "agent_id": AGENT,
                    "key_id": old_key,
                    "accepted_event_id": old_event,
                }),
            )),
            crate::reducer::ProjectionEffect::AgentKeyAuthorizeProjected { .. }
        ));

        let rejected = state.apply_agent_key_authorize(&op(
            "agent_key_authorize",
            json!({
                "agent_id": AGENT,
                "key_id": new_key,
                "accepted_event_id": new_event,
            }),
        ));
        assert!(matches!(
            rejected,
            crate::reducer::ProjectionEffect::Rejected { reason }
                if reason == "agent_key_supersedes_state_mismatch"
        ));
        assert_eq!(
            state.active_agent_key_authorizations(AGENT),
            vec![(old_key.to_owned(), old_event.to_owned())],
            "a rejected replacement must not partially alter active authorization state"
        );

        let accepted = state.apply_agent_key_authorize(&op(
            "agent_key_authorize",
            json!({
                "agent_id": AGENT,
                "key_id": new_key,
                "accepted_event_id": new_event,
                "supersedes": [{
                    "key_id": old_key,
                    "authorized_event_ref": old_event,
                }],
            }),
        ));
        assert!(matches!(
            accepted,
            crate::reducer::ProjectionEffect::AgentKeyAuthorizeProjected { .. }
        ));
        assert_eq!(
            state.active_agent_key_authorizations(AGENT),
            vec![(new_key.to_owned(), new_event.to_owned())]
        );
    }

    #[test]
    fn pairing_replacement_of_same_key_requires_exact_supersedes() {
        let mut state = ProjectionState::default();
        let old_event = "ak:event:01970000-0000-7000-8000-000000000021";
        let new_event = "ak:event:01970000-0000-7000-8000-000000000022";
        let key_id = "ak:agent_key:stable";

        assert!(matches!(
            state.apply_agent_key_authorize(&op(
                "agent_key_authorize",
                json!({
                    "agent_id": AGENT,
                    "key_id": key_id,
                    "accepted_event_id": old_event,
                }),
            )),
            crate::reducer::ProjectionEffect::AgentKeyAuthorizeProjected { .. }
        ));

        let rejected = state.apply_agent_key_authorize(&op(
            "agent_key_authorize",
            json!({
                "agent_id": AGENT,
                "key_id": key_id,
                "accepted_event_id": new_event,
                "approval_evidence": { "kind": "pairing_request" },
            }),
        ));
        assert!(matches!(
            rejected,
            crate::reducer::ProjectionEffect::Rejected { reason }
                if reason == "agent_key_supersedes_state_mismatch"
        ));
        assert_eq!(
            state.active_agent_key_authorizations(AGENT),
            vec![(key_id.to_owned(), old_event.to_owned())]
        );

        let accepted = state.apply_agent_key_authorize(&op(
            "agent_key_authorize",
            json!({
                "agent_id": AGENT,
                "key_id": key_id,
                "accepted_event_id": new_event,
                "approval_evidence": { "kind": "pairing_request" },
                "supersedes": [{
                    "key_id": key_id,
                    "authorized_event_ref": old_event,
                }],
            }),
        ));
        assert!(matches!(
            accepted,
            crate::reducer::ProjectionEffect::AgentKeyAuthorizeProjected { .. }
        ));
        assert_eq!(
            state.active_agent_key_authorizations(AGENT),
            vec![(key_id.to_owned(), new_event.to_owned())]
        );
    }

    #[test]
    fn root_grant_without_issuer_upper_bound_is_rejected() {
        let mut state = ProjectionState::default();
        seed_realm_owner(&mut state);
        let effect = state.apply_capability_grant(
            &op(
                "capability_grant",
                grant_payload(
                    GRANT_2,
                    "did:web:bob.example",
                    AGENT,
                    json!(["ak.message.create"]),
                    json!([{ "kind": "realm", "realm_id": REALM }]),
                ),
            ),
            chrono::Utc::now(),
        );
        assert!(matches!(
            effect,
            crate::reducer::ProjectionEffect::Rejected { reason }
                if reason == "grant_exceeds_issuer_authority"
        ));
    }

    #[test]
    fn root_grant_is_limited_to_issuer_effective_authority() {
        let mut state = ProjectionState::default();
        seed_realm_owner(&mut state);
        let effect = state.apply_capability_grant(
            &op(
                "capability_grant",
                grant_payload(
                    GRANT,
                    "did:web:alice.example",
                    "did:web:bob.example",
                    json!(["ak.message.create"]),
                    json!([{ "kind": "realm", "realm_id": REALM }]),
                ),
            ),
            chrono::Utc::now(),
        );
        assert!(matches!(
            effect,
            crate::reducer::ProjectionEffect::CapabilityGrantProjected { .. }
        ));
        let allowed = state.apply_capability_grant(
            &op(
                "capability_grant",
                grant_payload(
                    GRANT_2,
                    "did:web:bob.example",
                    AGENT,
                    json!(["ak.message.create"]),
                    json!([{ "kind": "realm", "realm_id": REALM }]),
                ),
            ),
            chrono::Utc::now(),
        );
        assert!(matches!(
            allowed,
            crate::reducer::ProjectionEffect::CapabilityGrantProjected { .. }
        ));
        let denied = state.apply_capability_grant(
            &op(
                "capability_grant",
                grant_payload(
                    GRANT_3,
                    "did:web:bob.example",
                    AGENT,
                    json!(["ak.reaction.add"]),
                    json!([{ "kind": "realm", "realm_id": REALM }]),
                ),
            ),
            chrono::Utc::now(),
        );
        assert!(matches!(
            denied,
            crate::reducer::ProjectionEffect::Rejected { reason }
                if reason == "grant_exceeds_issuer_authority"
        ));
    }

    #[test]
    fn delegated_grant_cannot_outlive_parent_expiry() {
        let mut state = ProjectionState::default();
        seed_realm_owner(&mut state);
        let parent_expiry = chrono::Utc::now() + chrono::Duration::hours(1);
        let child_expiry = parent_expiry + chrono::Duration::hours(1);
        let mut parent = grant_payload(
            GRANT,
            "did:web:alice.example",
            "did:web:bob.example",
            json!(["ak.message.create"]),
            json!([{ "kind": "realm", "realm_id": REALM }]),
        );
        parent["grant"]["expires_at"] =
            json!(arkret_canonical::format_timestamp_canonical(parent_expiry));
        let parent_effect =
            state.apply_capability_grant(&op("capability_grant", parent), chrono::Utc::now());
        assert!(matches!(
            parent_effect,
            crate::reducer::ProjectionEffect::CapabilityGrantProjected { .. }
        ));

        let mut child = grant_payload(
            GRANT_2,
            "did:web:bob.example",
            AGENT,
            json!(["ak.message.create"]),
            json!([{ "kind": "realm", "realm_id": REALM }]),
        );
        child["grant"]["parent_grant_id"] = json!(GRANT);
        child["grant"]["expires_at"] =
            json!(arkret_canonical::format_timestamp_canonical(child_expiry));
        let child_effect =
            state.apply_capability_grant(&op("capability_grant", child), chrono::Utc::now());
        assert!(matches!(
            child_effect,
            crate::reducer::ProjectionEffect::Rejected { reason }
                if reason == "delegation_expiry_widening"
        ));
    }

    #[test]
    fn delegated_grant_from_revoked_parent_is_rejected() {
        let mut state = ProjectionState::default();
        seed_realm_owner(&mut state);
        let parent = grant_payload(
            GRANT,
            "did:web:alice.example",
            "did:web:bob.example",
            json!(["ak.message.create"]),
            json!([{ "kind": "realm", "realm_id": REALM }]),
        );
        let parent_effect =
            state.apply_capability_grant(&op("capability_grant", parent), chrono::Utc::now());
        assert!(matches!(
            parent_effect,
            crate::reducer::ProjectionEffect::CapabilityGrantProjected { .. }
        ));
        let revoke_effect = state.apply_capability_revoke(
            &op("capability_revoke", json!({ "grant_id": GRANT })),
            chrono::Utc::now(),
        );
        assert!(matches!(
            revoke_effect,
            crate::reducer::ProjectionEffect::CapabilityRevokeProjected { .. }
        ));

        let mut child = grant_payload(
            GRANT_2,
            "did:web:bob.example",
            AGENT,
            json!(["ak.message.create"]),
            json!([{ "kind": "realm", "realm_id": REALM }]),
        );
        child["grant"]["parent_grant_id"] = json!(GRANT);
        child["grant"]["expires_at"] = json!(arkret_canonical::format_timestamp_canonical(
            chrono::Utc::now() + chrono::Duration::minutes(30)
        ));
        let child_effect =
            state.apply_capability_grant(&op("capability_grant", child), chrono::Utc::now());
        assert!(matches!(
            child_effect,
            crate::reducer::ProjectionEffect::Rejected { reason }
                if reason == "grant_revoked_upstream"
        ));
    }
}

#[cfg(test)]
mod delegation_cycle_tests {
    use arkret_event_draft::Operation;
    use arkret_identifiers::{OperationId, RealmId};
    use serde_json::json;

    use crate::reducer::{ProjectionState, SolandRealmState};

    const REALM: &str = "ak:realm:01970000-0000-7000-8000-000000000000";
    const G_A: &str = "ak:grant:01970000-0000-7000-8000-00000000a001";
    const G_B: &str = "ak:grant:01970000-0000-7000-8000-00000000b002";
    const G_C: &str = "ak:grant:01970000-0000-7000-8000-00000000c003";

    fn delegate_op(grant_id: &str, parent_grant_id: &str) -> Operation {
        delegate_op_with_constraints(grant_id, parent_grant_id, json!([]))
    }

    fn delegate_op_with_constraints(
        grant_id: &str,
        parent_grant_id: &str,
        constraints: serde_json::Value,
    ) -> Operation {
        Operation::create(
            OperationId::new("ak:operation:01970000-0000-7000-8000-0000000000fe").unwrap(),
            RealmId::new(REALM.to_owned()).unwrap(),
            arkret_wire::events::EventKind::CAPABILITY_DELEGATE,
            json!({
                "grant_id": grant_id,
                "grant": {
                    "issuer": "did:web:alice.example",
                    "parent_grant_id": parent_grant_id,
                    "actions": ["ak.message.create"],
                    "resources": [{ "kind": "realm", "realm_id": REALM }],
                    "constraints": constraints,
                }
            }),
        )
    }

    fn root_grant_op(grant_id: &str, issuer: &str, subject: &str) -> Operation {
        root_grant_op_with_constraints(grant_id, issuer, subject, json!([]))
    }

    fn root_grant_op_with_constraints(
        grant_id: &str,
        issuer: &str,
        subject: &str,
        constraints: serde_json::Value,
    ) -> Operation {
        Operation::create(
            OperationId::new("ak:operation:01970000-0000-7000-8000-0000000000fd").unwrap(),
            RealmId::new(REALM.to_owned()).unwrap(),
            arkret_wire::events::EventKind::CAPABILITY_GRANT,
            json!({
                "grant_id": grant_id,
                "grant": {
                    "issuer": issuer,
                    "subject": subject,
                    "actions": ["ak.message.create"],
                    "resources": [{ "kind": "realm", "realm_id": REALM }],
                    "constraints": constraints,
                }
            }),
        )
    }

    fn seed_realm_owner(state: &mut ProjectionState) {
        let now = chrono::Utc::now();
        state.realm_states.insert(
            REALM.to_owned(),
            SolandRealmState {
                realm_id: REALM.to_owned(),
                owner: Some("did:web:alice.example".to_owned()),
                title: None,
                deleted: false,
                archived: false,
                frozen: false,
                freeze_expires_at: None,
                created_at: now,
                updated_at: now,
                trust_domain: None,
                terminal_state: None,
                successor_realm_id: None,
                default_strand_id: None,
                active_profiles: Vec::new(),
            },
        );
    }

    fn proj_with_chain() -> ProjectionState {
        // Project g_b delegated from root g_a, so the chain is g_a <- g_b.
        let mut proj = ProjectionState::default();
        seed_realm_owner(&mut proj);
        proj.apply_capability_grant(
            &root_grant_op(G_A, "did:web:alice.example", "did:web:alice.example"),
            chrono::Utc::now(),
        );
        proj.apply_capability_delegate(&delegate_op(G_B, G_A), chrono::Utc::now());
        proj
    }

    #[test]
    fn delegate_closing_a_cycle_is_rejected() {
        // g_a delegated from g_b would close g_a <- g_b <- g_a.
        let proj = proj_with_chain();
        assert_eq!(
            proj.check_delegation_cycle(&delegate_op(G_A, G_B)),
            Err("delegation_cycle")
        );
    }

    #[test]
    fn self_delegation_is_rejected() {
        let proj = ProjectionState::default();
        assert_eq!(
            proj.check_delegation_cycle(&delegate_op(G_A, G_A)),
            Err("delegation_cycle")
        );
    }

    #[test]
    fn acyclic_delegation_is_allowed() {
        // g_c delegated from g_b: chain g_b <- g_c over existing g_a <- g_b.
        let proj = proj_with_chain();
        assert!(proj.check_delegation_cycle(&delegate_op(G_C, G_B)).is_ok());
    }

    #[test]
    fn delegated_grant_must_decrement_parent_depth() {
        let mut proj = ProjectionState::default();
        seed_realm_owner(&mut proj);
        proj.apply_capability_grant(
            &root_grant_op_with_constraints(
                G_A,
                "did:web:alice.example",
                "did:web:alice.example",
                json!([{ "constraint_type": "delegation_control", "max_delegation_depth": 1 }]),
            ),
            chrono::Utc::now(),
        );
        let rejected = proj.apply_capability_delegate(&delegate_op(G_B, G_A), chrono::Utc::now());
        assert!(matches!(
            rejected,
            crate::reducer::ProjectionEffect::Rejected { reason }
                if reason == "delegation_depth_exceeded"
        ));

        let allowed = proj.apply_capability_delegate(
            &delegate_op_with_constraints(
                G_C,
                G_A,
                json!([{ "constraint_type": "delegation_control", "max_delegation_depth": 0 }]),
            ),
            chrono::Utc::now(),
        );
        assert!(matches!(
            allowed,
            crate::reducer::ProjectionEffect::CapabilityDelegateProjected { .. }
        ));
    }

    #[test]
    fn delegated_grant_rejects_when_parent_depth_exhausted() {
        let mut proj = ProjectionState::default();
        seed_realm_owner(&mut proj);
        proj.apply_capability_grant(
            &root_grant_op_with_constraints(
                G_A,
                "did:web:alice.example",
                "did:web:alice.example",
                json!([{ "constraint_type": "delegation_control", "max_delegation_depth": 0 }]),
            ),
            chrono::Utc::now(),
        );
        let rejected = proj.apply_capability_delegate(
            &delegate_op_with_constraints(
                G_B,
                G_A,
                json!([{ "constraint_type": "delegation_control", "max_delegation_depth": 0 }]),
            ),
            chrono::Utc::now(),
        );
        assert!(matches!(
            rejected,
            crate::reducer::ProjectionEffect::Rejected { reason }
                if reason == "delegation_depth_exceeded"
        ));
    }
}

#[cfg(test)]
mod federation_revoke_fanout_tests {
    use arkret_event_draft::Operation;
    use arkret_identifiers::{OperationId, RealmId};
    use serde_json::json;

    use crate::reducer::{ProjectionEffect, ProjectionState, SolandRealmState};

    const REALM: &str = "ak:realm:01970000-0000-7000-8000-000000000000";
    const OTHER_REALM: &str = "ak:realm:01970000-0000-7000-8000-000000000001";
    const OWNER: &str = "did:web:alice.example";
    const PEER_SERVICE_ID: &str = "did:web:beta.example";
    const GRANT: &str = "ak:grant:01970000-0000-7000-8000-0000000000d1";

    fn capability_op(operation_id: &str, kind: &str, payload: serde_json::Value) -> Operation {
        Operation::create(
            OperationId::new(operation_id.to_owned()).unwrap(),
            RealmId::new(REALM.to_owned()).unwrap(),
            kind,
            payload,
        )
    }

    fn seed_realm_owner(state: &mut ProjectionState) {
        let now = chrono::Utc::now();
        state.realm_states.insert(
            REALM.to_owned(),
            SolandRealmState {
                realm_id: REALM.to_owned(),
                owner: Some(OWNER.to_owned()),
                title: None,
                deleted: false,
                archived: false,
                frozen: false,
                freeze_expires_at: None,
                created_at: now,
                updated_at: now,
                trust_domain: None,
                terminal_state: None,
                successor_realm_id: None,
                default_strand_id: None,
                active_profiles: Vec::new(),
            },
        );
    }

    fn delivery_binding_grant_payload() -> serde_json::Value {
        let registry_digest = arkret_policy::current_capability_action_registry_digest()
            .expect("embedded capability action registry");
        json!({
            "grant_id": GRANT,
            "grant": {
                "id": GRANT,
                "schema": "ak.schema.capability_grant.v1",
                "realm_id": REALM,
                "issuer": OWNER,
                "subject": PEER_SERVICE_ID,
                // The realm-level admin capability governs the delivery-binding
                // policy. `ak.realm.delivery_binding_policy` is an event kind,
                // not a registered capability action, so the grant carries the
                // registered `ak.realm.admin` action that authorizes it.
                "actions": ["ak.realm.admin"],
                "capability_action_registry_digest": registry_digest,
                "resources": [{ "kind": "realm", "realm_id": REALM }],
            }
        })
    }

    #[test]
    fn revoking_service_delegation_marks_peer_delivery_revoked() {
        let mut state = ProjectionState::default();
        seed_realm_owner(&mut state);
        let now = chrono::Utc::now();

        // Before any grant: nothing revoked.
        assert!(state.federation_delivery_revoked_peers(REALM).is_empty());

        // Grant β's federation delivery binding service delegation. An active
        // grant MUST NOT appear in the revoked set.
        let effect = state.apply_capability_grant(
            &capability_op(
                "ak:operation:01970000-0000-7000-8000-0000000000a1",
                arkret_wire::events::EventKind::CAPABILITY_GRANT,
                delivery_binding_grant_payload(),
            ),
            now,
        );
        assert!(
            matches!(effect, ProjectionEffect::CapabilityGrantProjected { .. }),
            "grant must project before revoke: {effect:?}"
        );
        assert!(
            state.federation_delivery_revoked_peers(REALM).is_empty(),
            "active service delegation must not be reported as revoked"
        );

        // Revoke it: the peer service DID is now delivery-revoked for this Realm.
        let effect = state.apply_capability_revoke(
            &capability_op(
                "ak:operation:01970000-0000-7000-8000-0000000000a2",
                arkret_wire::events::EventKind::CAPABILITY_REVOKE,
                json!({ "grant_id": GRANT, "realm_id": REALM }),
            ),
            now,
        );
        assert!(
            matches!(effect, ProjectionEffect::CapabilityRevokeProjected { .. }),
            "revoke must project: {effect:?}"
        );
        let revoked = state.federation_delivery_revoked_peers(REALM);
        assert!(
            revoked.contains(PEER_SERVICE_ID),
            "revoked service delegation peer MUST be reported"
        );

        // Scope check: another Realm sees no revocation from this grant.
        assert!(
            state
                .federation_delivery_revoked_peers(OTHER_REALM)
                .is_empty(),
            "revocation is scoped to the grant's Realm"
        );
    }
}
