//! Capability commands materialize a confirmed sequenced safety set.
//!
//! Registered add/remove operations use the SDK state model. Revocation
//! removes active entries; the remaining safety revision prevents an old
//! grant Event from reviving them. Rebuildable historical metadata supports
//! routing and history queries but never grants current authority.

use arkret_wire::CapabilityActionId;

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
    selector_string_field(selector, "realm_id").unwrap_or(fallback)
}

fn normalize_selector_object(selector: &Value, realm_id: &str) -> Option<String> {
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
        "object" => selector_string_field(selector, "object_kind")
            .map(ToOwned::to_owned)
            .or_else(|| Some("object".to_owned())),
        _ => None,
    }
}

/// `capability-grant.schema.json` names the selector list `resources`; the
/// grant root is `additionalProperties:false`, so there is no second carrier.
fn engine_resources_from_body(body: &Value, realm_id: &str) -> Vec<String> {
    let selectors = value_array_field(body, "resources");
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

fn engine_constraints_from_body(body: &Value) -> Option<Vec<crate::capability::GrantConstraint>> {
    value_array_field(body, "constraints")
        .into_iter()
        .map(|constraint| serde_json::from_value(constraint.clone()).ok())
        .collect()
}

/// Build an engine-shaped `Grant` from a projected grant cell body. Returns
/// `None` only when the body has no actions (a grant with no actions cannot
/// authorize anything and must not enter the index).
pub fn engine_grant_from_cell_body(
    grant_id: &str,
    body: &Value,
    revoked: bool,
) -> Option<crate::capability::Grant> {
    let authority_projection = body;
    let body = grant_body(body);
    if validate_grant_body_scope(body).is_err() {
        return None;
    }
    let realm_id = body
        .get("realm_id")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let issuer = body
        .get("issuer_id")
        .cloned()
        .and_then(|value| serde_json::from_value::<arkret_wire::ActorId>(value).ok())?;
    let subject = body
        .get("subject")
        .cloned()
        .and_then(|value| serde_json::from_value::<arkret_wire::ActorId>(value).ok())?;
    let actions: Vec<String> = string_set_field(body, "actions").into_iter().collect();
    if actions.is_empty() {
        return None;
    }
    let resource = engine_resource_from_body(body, &realm_id);
    let constraints = engine_constraints_from_body(body)?;
    let created_at = body
        .get("issued_at")
        .and_then(Value::as_str)
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .map(|dt| dt.with_timezone(&chrono::Utc))
        .unwrap_or_else(chrono::Utc::now);
    let issuer_authority_refs = engine_authority_refs_from_body(body);
    let authority_depth = authority_projection
        .get("authority_depth")
        .or_else(|| body.get("authority_depth"))
        .and_then(Value::as_u64);
    let authority_root_refs = authority_projection
        .get("authority_root_refs")
        .or_else(|| body.get("authority_root_refs"))
        .cloned()
        .and_then(|value| serde_json::from_value(value).ok())
        .unwrap_or_default();
    Some(crate::capability::Grant {
        grant_id: grant_id.to_owned(),
        realm_id,
        issuer_id: issuer,
        subject_id: subject,
        resource,
        actions,
        constraints,
        revoked,
        created_at,
        issuer_authority_refs,
        authority_depth,
        authority_root_refs,
    })
}

/// Resolve one settled `capability.grant` facet value into the engine shape.
///
/// A revoked or relinquished grant keeps its facet with a JSON `null` value so
/// a replay of the original grant Event cannot revive it; that tombstone
/// resolves to `None`.
pub fn engine_grant_from_capability_facet(
    grant_id: &str,
    value: &Value,
) -> Option<crate::capability::Grant> {
    if value.is_null() {
        return None;
    }
    engine_grant_from_cell_body(grant_id, value, false)
}

/// The single active-grant predicate for the accepted capability projection.
///
/// Realm pin, active-set membership, effective expiry from temporal constraints,
/// and action / resource
/// matching all live here so a fix to any one of them cannot be applied at one
/// call site while another keeps admitting the grant. Callers layer their own
/// usage constraint — a specific issuer, a named `grant_id`, or holder
/// de-duplication — on top of this.
///
/// `resource_expr` MUST already be expanded through
/// `ProjectionState::authz_resource_expr`; `evaluation_basis` is the caller's
/// admission / evaluation timestamp.
fn projected_grant_is_active_for(
    grant: &crate::capability::Grant,
    realm_id: &str,
    action: &str,
    resource_expr: &str,
    evaluation_basis: chrono::DateTime<chrono::Utc>,
) -> bool {
    grant.realm_id == realm_id
        && !grant.revoked
        && !crate::capability::is_grant_expired(grant, evaluation_basis)
        && grant.actions.iter().any(|candidate| candidate == action)
        && crate::capability::resource_matches(&grant.resource, resource_expr)
}

/// Operational sibling of [`projected_grant_is_active_for`]: identical except
/// the action test admits a registry-anchored aggregate expansion.
///
/// Kept as a separate function rather than a flag so no caller can flip "does
/// this holder carry the action" into "may this holder author that Event" by
/// passing the wrong boolean.
fn projected_grant_covers_action(
    grant: &crate::capability::Grant,
    realm_id: &str,
    action: &str,
    resource_expr: &str,
    evaluation_basis: chrono::DateTime<chrono::Utc>,
) -> bool {
    grant.realm_id == realm_id
        && !grant.revoked
        && !crate::capability::is_grant_expired(grant, evaluation_basis)
        && grant_action_covers(grant, action)
        && crate::capability::resource_matches(&grant.resource, resource_expr)
}

fn validate_grant_body_scope(body: &Value) -> Result<(), &'static str> {
    let actions = validate_grant_actions(body)?;
    crate::capability::validate_capability_actions(&actions)?;
    validate_grant_resources(body)
}

/// capabilities.md §8 — grants whose subject is an agent/service principal
/// must carry
/// every registry-required typed constraint, and any `risk_tier=high` action
/// (or an action whose registry `required_constraints` list `expires_at`)
/// additionally requires a finite effective expiry. Low/medium-risk agent
/// grants may be non-expiring (revocation-governed, longevity-safe). Actions
/// absent from the registry default to high (registry fail-closed rule).
fn validate_nonhuman_subject_grant_constraints(
    body: &Value,
    subject_is_agent_or_service: impl Fn(&arkret_wire::ActorId) -> bool,
) -> Result<(), &'static str> {
    use arkret_schema::CapabilityRiskTier;

    let Some(subject) = body
        .get("subject")
        .and_then(|value| serde_json::from_value::<arkret_wire::ActorId>(value.clone()).ok())
    else {
        return Ok(());
    };
    if !subject_is_agent_or_service(&subject) {
        return Ok(());
    }
    let Some(actions) = body.get("actions").and_then(Value::as_array) else {
        return Ok(());
    };
    let has_finite_expiry = body_effective_expires_at(body).is_some();
    for action in actions.iter().filter_map(Value::as_str) {
        let descriptor = arkret_schema::capability_action(action);
        let (risk_tier, required_constraints) = match descriptor {
            Some(descriptor) => (descriptor.risk_tier, descriptor.required_constraints),
            // Unregistered action: registry_rules default it to high.
            None => (CapabilityRiskTier::High, &[] as &[&str]),
        };
        let expiry_required =
            risk_tier == CapabilityRiskTier::High || required_constraints.contains(&"expires_at");
        if expiry_required && !has_finite_expiry {
            return Err("agent_grant_expiry_required");
        }
        for required in required_constraints {
            if *required == "expires_at" {
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
/// `constraint_kind`.
fn grant_has_constraint(body: &Value, token: &str) -> bool {
    let Some(constraints) = body.get("constraints").and_then(Value::as_array) else {
        return false;
    };
    constraints.iter().any(|constraint| {
        constraint.get(token).is_some()
            || constraint.get("constraint_kind").and_then(Value::as_str) == Some(token)
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

/// `capability-grant.schema.json` requires `resources` and forbids any other
/// root selector carrier, so the grant body has exactly one list to validate.
fn validate_grant_resources(body: &Value) -> Result<(), &'static str> {
    let mut selectors = Vec::new();
    if let Some(resources) = body.get("resources") {
        let Some(resources) = resources.as_array() else {
            return Err("capability_grant_resources_invalid");
        };
        selectors.extend(resources.iter());
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

/// True when a projected grant authorizes authoring under `action`.
///
/// `capabilities.md` section 3.2 answers Event admission over
/// `target_event_kinds`. A verbatim action match is unconditional; an aggregate
/// expansion uses the immutable action coverage compiled into the Realm's
/// supported profile.
fn grant_action_covers(grant: &crate::capability::Grant, action: &str) -> bool {
    if grant.actions.iter().any(|candidate| candidate == action) {
        return true;
    }
    grant
        .actions
        .iter()
        .any(|holder| arkret_policy::action_covers_event_kinds(holder, action).unwrap_or(false))
}

/// Pull the canonical grant body out of an `ak.capability.grant` payload.
/// Accepts the canonical genesis wrapper `{grant: {…}}` and a flat payload
/// that already *is* the grant body.
fn grant_body(payload: &Value) -> &Value {
    payload
        .get("grant")
        .filter(|grant| grant.is_object())
        .unwrap_or(payload)
}

fn genesis_grant_id(operation: &Operation) -> String {
    arkret_identifiers::GrantId::from_event_id(&operation.context.event_id).to_string()
}

/// Extract the exact issuer ActorId from a capability grant payload (top-level or
/// inside the embedded `grant` body).
fn grant_issuer(payload: &Value) -> Option<arkret_wire::ActorId> {
    grant_body(payload)
        .get("issuer_id")
        .cloned()
        .and_then(|value| serde_json::from_value(value).ok())
}

/// The grant ids a grant names in `issuer_authority_refs[]`.
///
/// `realm_root` entries are rooted terminals and deliberately contribute
/// nothing here: they end a walk rather than continue it.
/// `scalability-constraints.md` §3 caps the authority chain at 4; the walk
/// budget is deliberately larger so a pathological graph is reported as a
/// cycle rather than silently truncated.
const MAX_AUTHORITY_WALK: usize = 64;

/// The typed refs a projected grant body carries, in the runtime shape the
/// policy engine walks.
fn engine_authority_refs_from_body(body: &Value) -> Vec<crate::capability::IssuerAuthorityRef> {
    body.get("issuer_authority_refs")
        .and_then(Value::as_array)
        .map(|refs| {
            refs.iter()
                .filter_map(|entry| match entry.get("kind").and_then(Value::as_str) {
                    Some("grant") => entry.get("grant_id").and_then(Value::as_str).map(|id| {
                        crate::capability::IssuerAuthorityRef::Grant {
                            grant_id: id.to_owned(),
                        }
                    }),
                    Some("realm_authority") => serde_json::from_value(entry.clone()).ok(),
                    _ => None,
                })
                .collect()
        })
        .unwrap_or_default()
}

fn grant_authority_grant_refs(payload: &Value) -> Vec<String> {
    grant_authority_grant_refs_in(grant_body(payload))
}

fn grant_authority_grant_refs_in(body: &Value) -> Vec<String> {
    body.get("issuer_authority_refs")
        .and_then(Value::as_array)
        .map(|refs| {
            refs.iter()
                .filter(|entry| entry.get("kind").and_then(Value::as_str) == Some("grant"))
                .filter_map(|entry| entry.get("grant_id").and_then(Value::as_str))
                .filter(|value| !value.trim().is_empty())
                .map(ToOwned::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

/// `authority_depth` / `authority_root_refs[]` for a grant, derived from its
/// refs. Both are reducer-owned: an author cannot misreport how far its
/// authority spread or which root it came from. `None` means a `grant` ref is
/// not projected yet — the caller MUST go pending rather than guess a depth.
pub fn derive_authority_audit(
    body: &Value,
    resolve: &dyn Fn(&str) -> Option<(u64, Vec<Value>)>,
) -> Option<(u64, Vec<Value>)> {
    let refs = body.get("issuer_authority_refs")?.as_array()?;
    if refs.is_empty() {
        return None;
    }
    let mut depth = 0_u64;
    let mut roots: Vec<Value> = Vec::new();
    for entry in refs {
        match entry.get("kind").and_then(Value::as_str) {
            Some("realm_authority") => {
                depth = depth.max(0);
                if !roots.contains(entry) {
                    roots.push(entry.clone());
                }
            }
            Some("grant") => {
                let grant_id = entry.get("grant_id").and_then(Value::as_str)?;
                let (parent_depth, parent_roots) = resolve(grant_id)?;
                depth = depth.max(parent_depth.checked_add(1)?);
                for root in parent_roots {
                    if !roots.contains(&root) {
                        roots.push(root);
                    }
                }
            }
            _ => return None,
        }
    }
    if roots.is_empty() {
        return None;
    }
    roots.sort_by_key(|root| root.to_string());
    Some((depth, roots))
}

fn grant_realm_id<'a>(body: &'a Value, operation: &'a Operation) -> &'a str {
    body.get("realm_id")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| operation.realm_id.as_str())
}

fn body_effective_expires_at(body: &Value) -> Option<chrono::DateTime<chrono::Utc>> {
    value_array_field(body, "constraints")
        .into_iter()
        .filter_map(|constraint| {
            let constraint_kind = constraint.get("constraint_kind").and_then(Value::as_str);
            if constraint_kind != Some("temporal") {
                return None;
            }
            constraint
                .get("expires_at")
                .and_then(Value::as_str)
                .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
                .map(|dt| dt.with_timezone(&chrono::Utc))
        })
        .min()
}

fn body_max_authority_depth(body: &Value) -> Option<u32> {
    value_array_field(body, "constraints")
        .into_iter()
        .filter_map(|constraint| {
            let constraint_kind = constraint.get("constraint_kind").and_then(Value::as_str);
            if constraint_kind != Some("authority_control")
                || constraint.get("constraint_subkind").is_some()
            {
                return None;
            }
            constraint
                .get("max_authority_depth")
                .and_then(Value::as_u64)
                .and_then(|value| u32::try_from(value).ok())
        })
        .min()
}

fn body_has_terminal_authority_control(body: &Value) -> bool {
    let ordinary_controls = value_array_field(body, "constraints")
        .into_iter()
        .filter(|constraint| {
            constraint.get("constraint_kind").and_then(Value::as_str) == Some("authority_control")
                && constraint.get("constraint_subkind").is_none()
        })
        .collect::<Vec<_>>();
    !ordinary_controls.is_empty()
        && ordinary_controls.iter().all(|constraint| {
            constraint
                .get("max_authority_depth")
                .and_then(Value::as_u64)
                == Some(0)
                && !constraint
                    .get("authority_regrant_allowed")
                    .and_then(Value::as_bool)
                    .unwrap_or(false)
        })
}

/// Build historical metadata without changing the canonical safety Cell value.
fn grant_metadata_value(operation: &Operation, grant_id: &str) -> Value {
    let mut body = grant_body(&operation.payload).clone();
    if let Value::Object(map) = &mut body {
        map.insert("grant_id".to_owned(), Value::String(grant_id.to_owned()));
        map.entry("realm_id".to_owned())
            .or_insert_with(|| Value::String(operation.realm_id.to_string()));
    }
    body
}

impl ProjectionState {
    /// Settled body of one grant facet, in whichever Realm projected it.
    /// `None` covers both "never projected" and "revoked".
    pub(crate) fn capability_grant_value(&self, grant_id: &str) -> Option<&Value> {
        self.facets
            .iter()
            .find(|(key, _)| {
                key.1.facet() == facet::CAPABILITY_GRANT && key.1.subject() == grant_id
            })
            .map(|(_, settled)| &settled.value)
            .filter(|value| !value.is_null())
    }

    /// Every grant currently projected on a `capability.grant` facet, resolved
    /// to its effective engine shape. No realm / action / resource / temporal
    /// filtering happens here — that is [`projected_grant_is_active_for`]'s
    /// single responsibility.
    fn projected_capability_grants(&self) -> impl Iterator<Item = crate::capability::Grant> + '_ {
        self.facets.iter().filter_map(|(key, settled)| {
            if key.1.facet() != facet::CAPABILITY_GRANT {
                return None;
            }
            let grant_id = key.1.subject();
            let mut grant = engine_grant_from_capability_facet(grant_id, &settled.value)?;
            if grant.realm_id.is_empty() {
                grant.realm_id = self
                    .capability_grant_metadata
                    .get(grant_id)?
                    .realm_id
                    .clone();
            }
            Some(grant)
        })
    }

    /// Literal action match only — the grant names `action` verbatim.
    ///
    /// Separate from [`Self::issuer_has_projected_capability`] because an
    /// aggregate expansion answers "may this holder author that Event", which
    /// is a different question from "does this holder actually carry that
    /// action". Governance and owner checks want the second one.
    pub fn issuer_holds_literal_capability(
        &self,
        issuer: &arkret_wire::ActorId,
        realm_id: &str,
        action: &str,
        resource: &str,
        evaluation_basis: chrono::DateTime<chrono::Utc>,
    ) -> bool {
        let resource_expr = self.authz_resource_expr(realm_id, resource);
        self.projected_capability_grants().any(|grant| {
            &grant.subject_id == issuer
                && projected_grant_is_active_for(
                    &grant,
                    realm_id,
                    action,
                    &resource_expr,
                    evaluation_basis,
                )
                && self.grant_authority_is_live_for(
                    &grant,
                    action,
                    &resource_expr,
                    evaluation_basis,
                )
        })
    }

    /// Operational coverage: may `issuer` directly author under `action`?
    ///
    /// A literal hit needs no registry basis. An aggregate expansion
    /// re-interprets a historical signature under a registry snapshot, so it is
    /// anchored to the basis the grant itself names and fails closed when that
    /// snapshot is unknown. The expansion is the SDK's
    /// `action_covers_event_kinds`, which already guards the empty-coverage
    /// (non-Event surface) case.
    ///
    /// `evaluation_basis` is the caller's admission / evaluation timestamp; the
    /// projection never reads the wall clock on its own.
    pub fn issuer_has_projected_capability(
        &self,
        issuer: &arkret_wire::ActorId,
        realm_id: &str,
        action: &str,
        resource: &str,
        evaluation_basis: chrono::DateTime<chrono::Utc>,
    ) -> bool {
        let resource_expr = self.authz_resource_expr(realm_id, resource);
        self.projected_capability_grants().any(|grant| {
            &grant.subject_id == issuer
                && projected_grant_covers_action(
                    &grant,
                    realm_id,
                    action,
                    &resource_expr,
                    evaluation_basis,
                )
                && self.grant_authority_is_live_for(
                    &grant,
                    action,
                    &resource_expr,
                    evaluation_basis,
                )
        })
    }

    /// True when `actor` currently speaks for this Realm's owner aggregate.
    ///
    /// Two sources, both revocable-by-governance and neither of them a
    /// membership or `realm_states[..].owner` fallback:
    /// 1. `actor` is the controller of the registered authority-root cell;
    /// 2. `actor` holds a live, verbatim `ak.realm.owner` co-owner grant.
    pub fn actor_holds_effective_realm_owner(
        &self,
        realm_id: &str,
        actor: &arkret_wire::ActorId,
        evaluation_basis: chrono::DateTime<chrono::Utc>,
    ) -> bool {
        let actor_value = serde_json::to_value(actor).unwrap_or(Value::Null);
        if self
            .realm_authority_root(realm_id)
            .and_then(|root| root.get("controller_actor_id"))
            == Some(&actor_value)
        {
            return true;
        }
        self.issuer_holds_literal_capability(
            actor,
            realm_id,
            CapabilityActionId::REALM_OWNER,
            realm_id,
            evaluation_basis,
        )
    }

    /// True when `actor` speaks for the Realm owner aggregate and that
    /// aggregate operationally covers `action` in the Realm reducer profile's
    /// compiled action set.
    ///
    /// This is intentionally narrower than [`Self::actor_governs_realm`]: a
    /// generic authorization preflight must not turn owner grant authority
    /// into direct access to non-Event endpoints, nor may it authorize the two
    /// root-control-only Realm lifecycle actions.
    pub fn realm_owner_operationally_covers_action(
        &self,
        realm_id: &str,
        actor: &arkret_wire::ActorId,
        action: &str,
        evaluation_basis: chrono::DateTime<chrono::Utc>,
    ) -> bool {
        self.actor_holds_effective_realm_owner(realm_id, actor, evaluation_basis)
            && arkret_policy::owner_may_author_action(action).unwrap_or(false)
    }

    /// The shared Realm-governance predicate over projected capability state.
    ///
    /// A governance decision (join review, ban, applet install, ...) is allowed
    /// when `actor` either speaks for the Realm owner aggregate or holds one of
    /// `actions` verbatim. Realm membership and the discardable
    /// `realm_states[..].owner` presentation mirror are never inputs. Every
    /// review surface routes through this one function so the two legs cannot
    /// drift apart per surface.
    pub fn actor_governs_realm(
        &self,
        realm_id: &str,
        actor: &arkret_wire::ActorId,
        actions: &[&str],
        evaluation_basis: chrono::DateTime<chrono::Utc>,
    ) -> bool {
        self.actor_holds_effective_realm_owner(realm_id, actor, evaluation_basis)
            || actions.iter().any(|action| {
                self.issuer_holds_literal_capability(
                    actor,
                    realm_id,
                    action,
                    realm_id,
                    evaluation_basis,
                )
            })
    }

    /// Owner-aggregate leg of the section 3.2 issuer upper bound.
    ///
    /// Matching is by action id against the reducer profile's compiled
    /// `grant_authority_actions` (through `arkret_policy::owner_may_grant`),
    /// which additionally rejects `root_control_only` / `subject_only` /
    /// `reducer_only`. A profile action is reachable only when that exact
    /// action is compiled into the list; Realm schema refs and ServiceDescribe
    /// cannot widen this ceiling. Event-kind coverage is never substituted.
    fn owner_may_issue_grant_for(
        &self,
        issuer: &arkret_wire::ActorId,
        realm_id: &str,
        action: &str,
        evaluation_basis: chrono::DateTime<chrono::Utc>,
    ) -> bool {
        if !self.actor_holds_effective_realm_owner(realm_id, issuer, evaluation_basis) {
            return false;
        }
        arkret_policy::owner_may_grant(action).unwrap_or(false)
    }

    #[allow(clippy::too_many_arguments)]
    fn applet_non_event_grant_authority_matches(
        &self,
        issuer: &arkret_wire::ActorId,
        realm_id: &str,
        action: &str,
        resource: &str,
        body: &Value,
        evaluation_basis: chrono::DateTime<chrono::Utc>,
    ) -> bool {
        let Some(subject) = body
            .get("subject")
            .cloned()
            .and_then(|value| serde_json::from_value::<arkret_wire::ActorId>(value).ok())
        else {
            return false;
        };
        let Some(constraints) = body.get("constraints").and_then(Value::as_array) else {
            return false;
        };
        let Some(applet_id) = constraints
            .iter()
            .filter(|constraint| {
                constraint.get("constraint_subkind").and_then(Value::as_str)
                    == Some("applet_authority")
            })
            .map(|constraint| constraint.get("applet_id").and_then(Value::as_str))
            .collect::<Option<Vec<_>>>()
            .filter(|values| values.len() == 1)
            .and_then(|values| arkret_wire::AppletId::new(values[0].to_owned()).ok())
        else {
            return false;
        };
        let Some(registration) = self.applets.get(&applet_id) else {
            return false;
        };
        let Some(registration_scope_ref) = registration.registration_scope_ref.as_ref() else {
            return false;
        };
        let resources = value_array_field(body, "resources");
        if resources.len() != 1 || resources.first() != Some(registration_scope_ref) {
            return false;
        }

        registration.claimed_profiles.iter().any(|profile_id| {
            let Some(rule) =
                arkret_wire::generated::profile_requirements::non_event_grant_authority_rule(
                    profile_id, action,
                )
            else {
                return false;
            };
            if rule.required_registration_event_kind
                != arkret_wire::EventKind::AppletRegistration.as_str()
                || rule.required_claimed_profile != profile_id
                || rule.subject_binding != "registration.service_id"
                || rule.scope_binding != "grant.resource_exact_registration_scope"
                || rule.epoch_binding != "constraint.registration_epoch_exact_registration"
                || rule.requested_action_binding != "grant.action_in_registration.requested_scopes"
                || arkret_wire::ActorId::service(registration.service_id.clone()) != subject
                || !registration
                    .capabilities
                    .as_ref()
                    .and_then(Value::as_array)
                    .is_some_and(|actions| {
                        actions
                            .iter()
                            .any(|candidate| candidate.as_str() == Some(action))
                    })
                // conformance-profiles.json marks the applet bridge rule
                // `issuer_owner_authority_allowed`: the Realm owner aggregate
                // satisfies the issuer leg exactly like a verbatim
                // `rule.issuer_action` holder. Every other leg of the rule -
                // registration, scope, epoch, evidence - is unchanged.
                || !(self.issuer_holds_literal_capability(
                    issuer,
                    realm_id,
                    rule.issuer_action,
                    resource,
                    evaluation_basis,
                ) || self.actor_holds_effective_realm_owner(
                    realm_id,
                    issuer,
                    evaluation_basis,
                ))
            {
                return false;
            }
            constraints.iter().any(|constraint| {
                constraint.get("constraint_kind").and_then(Value::as_str)
                    == Some(rule.required_constraint_kind)
                    && constraint.get("constraint_subkind").and_then(Value::as_str)
                        == Some(rule.required_constraint_subkind)
                    && constraint.get("applet_id").and_then(Value::as_str)
                        == Some(registration.applet_id.as_str())
                    && constraint.get("executed_by").cloned().and_then(|value| {
                        serde_json::from_value::<arkret_wire::ActorId>(value).ok()
                    }) == Some(arkret_wire::ActorId::service(
                        registration.service_id.clone(),
                    ))
                    && constraint.get("registration_epoch").and_then(Value::as_str)
                        == Some(registration.registration_epoch.as_str())
            })
        })
    }

    fn validate_grant_issuer_upper_bound(&self, operation: &Operation) -> Result<(), &'static str> {
        // capabilities.md §10: grant refs cover the child jointly. Each named
        // Every grant ref must be live and held by the issuer, while each
        // action/resource pair may be supplied by any one authority ref.
        let grant_refs = grant_authority_grant_refs(&operation.payload);
        if !grant_refs.is_empty() {
            let body = grant_body(&operation.payload);
            let issuer =
                grant_issuer(&operation.payload).ok_or("capability_grant_issuer_missing")?;
            let realm_id = grant_realm_id(body, operation);
            let authorities = grant_refs
                .iter()
                .map(|authority_grant_id| {
                    self.effective_engine_grant(authority_grant_id)
                        .ok_or("grant_revoked_upstream")
                })
                .collect::<Result<Vec<_>, _>>()?;
            for parent in &authorities {
                self.validate_parent_authority_constraints(
                    operation, body, &issuer, realm_id, parent,
                )?;
            }
            let actions = validate_grant_actions(body)?;
            let resources = engine_resources_from_body(body, realm_id);
            if resources.is_empty() {
                return Err("capability_grant_resources_empty");
            }
            for action in &actions {
                for resource in &resources {
                    let resource_expr = self.authz_resource_expr(realm_id, resource);
                    if !authorities.iter().any(|parent| {
                        parent.actions.iter().any(|holder_action| {
                            arkret_policy::action_grants_authority_for(holder_action, action)
                                .unwrap_or(false)
                        }) && crate::capability::resource_matches(&parent.resource, &resource_expr)
                            && self.grant_authority_is_live_for(
                                parent,
                                action,
                                &resource_expr,
                                operation.created_at,
                            )
                    }) {
                        return Err("grant_exceeds_issuer_authority");
                    }
                }
            }
            return Ok(());
        }
        let body = grant_body(&operation.payload);
        let issuer = grant_issuer(&operation.payload).ok_or("capability_grant_issuer_missing")?;
        let actions = validate_grant_actions(body)?;
        let realm_id = grant_realm_id(body, operation);
        let resources = engine_resources_from_body(body, realm_id);
        if resources.is_empty() {
            return Err("capability_grant_resources_empty");
        }
        let issuer_value = serde_json::to_value(&issuer).unwrap_or(Value::Null);
        let root_ref_valid = engine_authority_refs_from_body(body)
            .iter()
            .any(|authority_ref| match authority_ref {
                crate::capability::IssuerAuthorityRef::RealmAuthority {
                    realm_id: root_realm_id,
                    governance_station_id,
                    authority_generation,
                    ..
                } => {
                    root_realm_id == realm_id
                        && self.realm_authority_root(realm_id).is_some_and(|root| {
                            root.get("controller_actor_id")
                                .is_some_and(|value| value == &issuer_value)
                                && root.get("governance_station_id").and_then(Value::as_str)
                                    == Some(governance_station_id.as_str())
                                && root.get("authority_generation").and_then(Value::as_u64)
                                    == Some(*authority_generation)
                        })
                }
                crate::capability::IssuerAuthorityRef::Grant { .. } => false,
            });
        if !root_ref_valid {
            return Err("realm_authority_controller_mismatch");
        }
        for action in &actions {
            // The owner aggregate is Realm-wide, so it is resolved once per
            // action rather than per resource selector.
            let owner_authorized =
                self.owner_may_issue_grant_for(&issuer, realm_id, action, operation.created_at);
            for resource in &resources {
                if !owner_authorized
                    && !self.issuer_has_projected_capability(
                        &issuer,
                        realm_id,
                        action,
                        resource,
                        operation.created_at,
                    )
                    && !self.applet_non_event_grant_authority_matches(
                        &issuer,
                        realm_id,
                        action,
                        resource,
                        body,
                        operation.created_at,
                    )
                {
                    return Err("grant_exceeds_issuer_authority");
                }
            }
        }
        Ok(())
    }

    fn validate_parent_authority_constraints(
        &self,
        operation: &Operation,
        body: &Value,
        issuer: &arkret_wire::ActorId,
        realm_id: &str,
        parent: &crate::capability::Grant,
    ) -> Result<(), &'static str> {
        if parent.revoked || crate::capability::is_grant_expired(parent, operation.created_at) {
            return Err("grant_revoked_upstream");
        }
        if issuer != &parent.subject_id {
            return Err("grant_exceeds_issuer_authority");
        }
        if realm_id != parent.realm_id {
            return Err("grant_exceeds_issuer_authority");
        }
        let has_authority_control = parent.constraints.iter().any(|constraint| {
            matches!(
                constraint,
                crate::capability::GrantConstraint::AuthorityControl {
                    constraint_subkind: None,
                    ..
                }
            )
        });
        if !has_authority_control {
            return Err("authority_regrant_denied");
        }
        let child_depth = body_max_authority_depth(body);
        let parent_allows_regrant =
            arkret_policy::authz::authority::authority_regrant_allowed(parent);
        let parent_depth = crate::capability::max_authority_depth(parent);
        if parent_depth == Some(0) {
            return Err(if parent_allows_regrant {
                "authority_depth_exceeded"
            } else {
                "authority_regrant_denied"
            });
        }
        if !parent_allows_regrant {
            if !body_has_terminal_authority_control(body) {
                return Err("authority_regrant_denied");
            }
        } else if let Some(parent_depth) = parent_depth {
            match child_depth {
                Some(child_depth) if child_depth <= parent_depth.saturating_sub(1) => {}
                _ => return Err("authority_depth_exceeded"),
            }
        }
        let child_expires_at = body_effective_expires_at(body);
        if let Some(parent_expires_at) = crate::capability::grant_effective_expiry(parent) {
            let Some(child_expires_at) = child_expires_at else {
                return Err("authority_expiry_widening");
            };
            if child_expires_at > parent_expires_at {
                return Err("authority_expiry_widening");
            }
        }
        Ok(())
    }

    /// Materialize a grant only while it is still live.
    pub fn effective_engine_grant(&self, grant_id: &str) -> Option<crate::capability::Grant> {
        let body = self.capability_grant_value(grant_id)?;
        let mut grant = engine_grant_from_cell_body(grant_id, body, false)?;
        if grant.realm_id.is_empty() {
            grant.realm_id = self
                .capability_grant_metadata
                .get(grant_id)?
                .realm_id
                .clone();
        }
        // Sealed cells contain the registry-projected grant body. Authority
        // depth/root audit fields are reducer-derived and therefore are not
        // producer-authored members of that body. Re-derive them from the
        // authoritative ref graph after a cell-store reload instead of
        // treating their absence as an unresolved parent.
        if (grant.authority_depth.is_none() || grant.authority_root_refs.is_empty())
            && let Some((depth, roots)) = self.projected_authority_audit(grant_id)
            && let Ok(authority_root_refs) = serde_json::from_value(Value::Array(roots))
        {
            grant.authority_depth = Some(depth);
            grant.authority_root_refs = authority_root_refs;
        }
        Some(grant)
    }

    /// Resolve the current liveness of the authority chain behind `grant`.
    ///
    /// A root ref is stable across controller transfer and is invalidated only
    /// when the Realm terminates, the root disappears, or its authority
    /// generation changes. A grant ref is a live edge: the parent must still
    /// authorize the child issuer, action, and resource, and its own authority
    /// chain must remain live. No descendant cells are rewritten when an
    /// ancestor is revoked or a root generation is reset.
    fn grant_authority_is_live_for(
        &self,
        grant: &crate::capability::Grant,
        action: &str,
        resource_expr: &str,
        evaluation_basis: chrono::DateTime<chrono::Utc>,
    ) -> bool {
        let mut visiting = std::collections::BTreeSet::new();
        self.grant_authority_is_live_for_inner(
            grant,
            action,
            resource_expr,
            evaluation_basis,
            &mut visiting,
        )
    }

    fn grant_authority_is_live_for_inner(
        &self,
        grant: &crate::capability::Grant,
        action: &str,
        resource_expr: &str,
        evaluation_basis: chrono::DateTime<chrono::Utc>,
        visiting: &mut std::collections::BTreeSet<String>,
    ) -> bool {
        if !visiting.insert(grant.grant_id.clone()) {
            return false;
        }
        let live = grant
            .issuer_authority_refs
            .iter()
            .any(|authority_ref| match authority_ref {
                crate::capability::IssuerAuthorityRef::RealmAuthority {
                    realm_id,
                    authority_generation,
                    ..
                } => {
                    !self.realm_is_in_terminal_state(realm_id)
                        && self.realm_authority_root(realm_id).is_some_and(|root| {
                            root.get("authority_generation").and_then(Value::as_u64)
                                == Some(*authority_generation)
                        })
                }
                crate::capability::IssuerAuthorityRef::Grant { grant_id } => {
                    let Some(parent) = self.effective_engine_grant(grant_id) else {
                        return false;
                    };
                    parent.subject_id == grant.issuer_id
                        && !parent.revoked
                        && !crate::capability::is_grant_expired(&parent, evaluation_basis)
                        && parent.actions.iter().any(|holder_action| {
                            arkret_policy::action_grants_authority_for(holder_action, action)
                                .unwrap_or(false)
                        })
                        && crate::capability::resource_matches(&parent.resource, resource_expr)
                        && self.grant_authority_is_live_for_inner(
                            &parent,
                            action,
                            resource_expr,
                            evaluation_basis,
                            visiting,
                        )
                }
            });
        visiting.remove(&grant.grant_id);
        live
    }

    /// P1 — project `ak.capability.grant` as an confirmed safety-set add on the grant cell.
    pub(crate) fn apply_capability_grant(
        &mut self,
        operation: &Operation,
        _now: chrono::DateTime<chrono::Utc>,
    ) -> ProjectionEffect {
        // Grant identity is the genesis Event identity with a typed prefix.
        // Reject producer-supplied copies even at this internal boundary so a
        // caller cannot bypass the closed wire schema and pick a cell key.
        if operation.payload.get("grant_id").is_some()
            || grant_body(&operation.payload).get("id").is_some()
        {
            return ProjectionEffect::Rejected {
                reason: "capability_grant_id_must_be_event_derived".to_owned(),
            };
        }
        let grant_id = genesis_grant_id(operation);
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
            validate_nonhuman_subject_grant_constraints(grant_body(&operation.payload), |subject| {
                let subject_key = subject.canonical_key().ok();
                matches!(subject, arkret_wire::ActorId::Service { .. })
                    || subject_key
                        .as_deref()
                        .is_some_and(|subject| self.agent_lifecycles.contains_key(subject))
                    || self.applets.values().any(|registration| {
                        &registration.service_id == subject.signing_principal_id()
                    })
            })
        {
            return ProjectionEffect::Rejected {
                reason: reason.to_owned(),
            };
        }
        if let Some(unresolved_grant_id) = grant_authority_grant_refs(&operation.payload)
            .into_iter()
            .find(|authority_grant_id| self.effective_engine_grant(authority_grant_id).is_none())
        {
            let known_removed = self.facets.iter().any(|(key, settled)| {
                key.1.facet() == facet::CAPABILITY_GRANT
                    && key.1.subject() == unresolved_grant_id
                    && settled.value.is_null()
            });
            if known_removed {
                return ProjectionEffect::Rejected {
                    reason: "grant_revoked_upstream".to_owned(),
                };
            }
            return self.queue_pending_replay(
                unresolved_grant_id,
                operation,
                "capability_authority_refs_unresolved",
            );
        }
        if let Err(reason) = self.validate_grant_issuer_upper_bound(operation) {
            return ProjectionEffect::Rejected {
                reason: reason.to_owned(),
            };
        }
        let realm_id = operation.realm_id.to_string();
        let target = FacetRef::new(facet::CAPABILITY_GRANT, &grant_id);

        // A removal keeps the facet with a null value. Replaying the original
        // grant Event must not revive that grant.
        if self
            .facet_value(&realm_id, &target)
            .is_some_and(Value::is_null)
        {
            return ProjectionEffect::CapabilityGrantProjected { grant_id, realm_id };
        }
        let mut value = operation.payload.clone();
        // capabilities.md §10 — `authority_depth` and `authority_root_refs[]`
        // are reducer-derived, so an author cannot misreport how far its
        // authority spread or which root it came from. A `grant` ref that is
        // not projected yet leaves them uncomputable, and the contract is
        // explicit that we go pending rather than guess a depth.
        let Some((authority_depth, authority_root_refs)) =
            derive_authority_audit(grant_body(&operation.payload), &|grant_id| {
                self.projected_authority_audit(grant_id)
            })
        else {
            return self.queue_pending_replay(
                grant_authority_grant_refs(&operation.payload)
                    .into_iter()
                    .next()
                    .unwrap_or_else(|| grant_id.clone()),
                operation,
                "capability_authority_refs_unresolved",
            );
        };
        if let Value::Object(map) = &mut value {
            map.insert(
                "authority_depth".to_owned(),
                Value::Number(authority_depth.into()),
            );
            map.insert(
                "authority_root_refs".to_owned(),
                Value::Array(authority_root_refs),
            );
        }
        self.set_facet(&realm_id, target, grant_body(&value).clone());
        let mut metadata = grant_metadata_value(operation, &grant_id);
        if let Some(object) = metadata.as_object_mut() {
            object.insert(
                "authority_depth".to_owned(),
                value["authority_depth"].clone(),
            );
            object.insert(
                "authority_root_refs".to_owned(),
                value["authority_root_refs"].clone(),
            );
        }
        if let Some(grant) = engine_grant_from_cell_body(&grant_id, &metadata, false) {
            self.capability_grant_metadata
                .insert(grant_id.clone(), grant);
        }

        ProjectionEffect::CapabilityGrantProjected { grant_id, realm_id }
    }

    /// P1 — project `ak.capability.revoke` as an confirmed safety-set removal on the
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
        let Some(target) = self
            .effective_engine_grant(&grant_id)
            .or_else(|| self.capability_grant_metadata.get(&grant_id).cloned())
        else {
            return self.queue_pending_replay(grant_id, operation, "capability_target_unresolved");
        };
        let actor_is_target_issuer = operation.context.sender == target.issuer_id;
        let sender_value = serde_json::to_value(&operation.context.sender).unwrap_or(Value::Null);
        let actor_is_target_realm_controller = self
            .realm_authority_root(&target.realm_id)
            .and_then(|root| root.get("controller_actor_id"))
            == Some(&sender_value);
        if !actor_is_target_issuer && !actor_is_target_realm_controller {
            return ProjectionEffect::Rejected {
                reason: "grant_revoke_not_authorized".to_owned(),
            };
        }
        self.remove_capability_grant(operation, &grant_id, now)
    }

    /// Project the subject-only `ak.capability.relinquish` control move.
    /// The target subject may always reduce its own authority; no revoke grant
    /// is required and no other principal may use this path.
    pub(crate) fn apply_capability_relinquish(
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
                reason: "capability_relinquish_grant_id_missing".to_owned(),
            };
        };
        let Some(target) = self
            .effective_engine_grant(&grant_id)
            .or_else(|| self.capability_grant_metadata.get(&grant_id).cloned())
        else {
            return self.queue_pending_replay(grant_id, operation, "capability_target_unresolved");
        };
        if operation.context.sender != target.subject_id {
            return ProjectionEffect::Rejected {
                reason: "grant_relinquish_not_subject".to_owned(),
            };
        }
        self.remove_capability_grant(operation, &grant_id, now)
    }

    fn remove_capability_grant(
        &mut self,
        operation: &Operation,
        grant_id: &str,
        _now: chrono::DateTime<chrono::Utc>,
    ) -> ProjectionEffect {
        let realm_id = operation.realm_id.to_string();
        // The facet survives the removal carrying a JSON `null`: a replay of
        // the original grant Event must not revive what was revoked.
        self.set_facet(
            &realm_id,
            FacetRef::new(facet::CAPABILITY_GRANT, grant_id),
            Value::Null,
        );
        if let Some(grant) = self.capability_grant_metadata.get_mut(grant_id) {
            grant.revoked = true;
        }

        if crate::kinds::canonical_kind_for_operation(operation)
            == Some(arkret_wire::EventKind::CapabilityRelinquish)
        {
            ProjectionEffect::CapabilityRelinquishProjected {
                grant_id: grant_id.to_owned(),
                realm_id,
            }
        } else {
            ProjectionEffect::CapabilityRevokeProjected {
                grant_id: grant_id.to_owned(),
                realm_id,
            }
        }
    }

    /// The materialized `(authority_depth, authority_root_refs)` of a grant
    /// already in the projection, or `None` when it has not landed yet.
    fn projected_authority_audit(&self, grant_id: &str) -> Option<(u64, Vec<Value>)> {
        self.projected_authority_audit_inner(grant_id, &std::collections::BTreeSet::new())
    }

    /// Resolve the immutable authority audit of a projected grant.
    pub fn capability_authority_audit(&self, grant_id: &str) -> Option<(u64, Vec<Value>)> {
        self.projected_authority_audit(grant_id)
    }

    fn projected_authority_audit_inner(
        &self,
        grant_id: &str,
        visiting: &std::collections::BTreeSet<String>,
    ) -> Option<(u64, Vec<Value>)> {
        if visiting.len() >= MAX_AUTHORITY_WALK || visiting.contains(grant_id) {
            return None;
        }
        let mut visiting = visiting.clone();
        visiting.insert(grant_id.to_owned());
        let body = self.capability_grant_value(grant_id)?;
        let stored_depth = body.get("authority_depth").and_then(Value::as_u64);
        let stored_roots = body
            .get("authority_root_refs")
            .and_then(Value::as_array)
            .cloned();
        if let (Some(depth), Some(roots)) = (stored_depth, stored_roots)
            && !roots.is_empty()
        {
            return Some((depth, roots));
        }
        derive_authority_audit(grant_body(body), &|parent_grant_id| {
            self.projected_authority_audit_inner(parent_grant_id, &visiting)
        })
    }

    /// The grant ids a projected grant names as `kind="grant"` authority refs.
    /// A grant that only names `realm_authority` refs returns an empty set,
    /// which terminates a walk: a root is a terminal, never an edge.
    fn authority_grant_refs_of(&self, grant_id: &str) -> Vec<String> {
        self.capability_grant_value(grant_id)
            .map(grant_authority_grant_refs_in)
            .unwrap_or_default()
    }

    /// capabilities.md §10.2 — DFS the authority graph of an incoming
    /// `ak.capability.grant` and reject the whole Event with `authority_cycle`
    /// if it would close a cycle. `realm_root` refs are rooted terminals and
    /// produce no edge, so the walk always terminates at a root or at the
    /// depth ceiling. A cycle MUST NOT project even if each grant looks valid
    /// individually; this runs at ingest so the cyclic edge never reaches the
    /// grant cell or the authz index.
    pub fn check_authority_cycle(&self, operation: &Operation) -> Result<(), &'static str> {
        if crate::kinds::canonical_kind_for_operation(operation)
            != Some(arkret_wire::EventKind::CapabilityGrant)
        {
            return Ok(());
        }
        let grant_id = genesis_grant_id(operation);
        let mut visited: std::collections::HashSet<String> = std::collections::HashSet::new();
        visited.insert(grant_id.clone());
        let mut pending = grant_authority_grant_refs(&operation.payload);
        while let Some(node) = pending.pop() {
            if node == grant_id {
                return Err("authority_cycle");
            }
            if !visited.insert(node.clone()) {
                continue;
            }
            if visited.len() > MAX_AUTHORITY_WALK {
                return Err("authority_cycle");
            }
            pending.extend(self.authority_grant_refs_of(&node));
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
        let authorized_event_ref = operation.context.accepted_event_id.to_string();
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

    /// Every persisted capability grant for the exact `subject_id`, paired with the
    /// Realm that governs its grant cell. Revocation must be submitted in
    /// this Realm; a controller PCR is not a cross-Realm revocation surface.
    pub fn grant_locations_for_subject(
        &self,
        subject_id: &arkret_wire::ActorId,
    ) -> Vec<(String, String)> {
        self.capability_grant_metadata
            .values()
            .filter(|grant| &grant.subject_id == subject_id)
            .map(|grant| (grant.grant_id.clone(), grant.realm_id.clone()))
            .collect()
    }

    /// Non-terminal grants for `subject_id`, including pending Agent grants
    /// that are durable but not yet in the effective authz index.
    pub fn unrevoked_grant_locations_for_subject(
        &self,
        subject_id: &arkret_wire::ActorId,
    ) -> Vec<(String, String)> {
        self.grant_locations_for_subject(subject_id)
            .into_iter()
            .filter(|(grant_id, _)| self.capability_grant_value(grant_id).is_some())
            .collect()
    }

    /// Confirmed historical revocations identify peer fanout destinations.
    /// This metadata is rebuilt from grant Events; the empty active safety
    /// set remains the sole current authorization result after removal.
    pub fn federation_delivery_revoked_peers(
        &self,
        realm_id: &str,
    ) -> std::collections::BTreeSet<String> {
        self.capability_grant_metadata
            .values()
            .filter(|grant| grant.revoked && grant.realm_id == realm_id)
            .filter_map(|grant| match &grant.subject_id {
                arkret_wire::ActorId::Service { service_id } => Some(service_id.to_string()),
                arkret_wire::ActorId::Account { .. } => None,
            })
            .collect()
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

/// Regression suite for the Realm owner aggregate (`capabilities.md` §3.2).
///
/// Genesis registers an authority-root cell and nothing else; its controller
/// holds effective `ak.realm.owner`. These cases pin the boundaries of what
/// that does and does not confer, because every one of them is a place where a
/// plausible-looking widening silently hands out authority nobody granted.
#[cfg(test)]
#[path = "apply_capability_tests.rs"]
mod tests;
