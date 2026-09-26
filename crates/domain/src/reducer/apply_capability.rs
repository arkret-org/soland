//! Capability commands materialize a confirmed sequenced safety set.
//!
//! Registered add/remove operations use the SDK state model. Revocation
//! removes active entries; the remaining safety revision prevents an old
//! grant Event from reviving them. Rebuildable historical metadata supports
//! routing and history queries but never grants current authority.

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
        .and_then(Value::as_u64)?;
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

/// Whether a projected grant is live for `action` on `resource_expr`: Realm pin,
/// active-set membership, effective expiry from temporal constraints, and an
/// action test that admits a registry-anchored aggregate expansion.
///
/// `resource_expr` MUST already be expanded through
/// `ProjectionState::authz_resource_expr`; `evaluation_basis` is the caller's
/// admission / evaluation timestamp.
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
                    Some("realm_root") => serde_json::from_value(entry.clone()).ok(),
                    _ => None,
                })
                .collect()
        })
        .unwrap_or_default()
}

/// `authority_depth` / `authority_root_refs[]` for a grant, derived from its
/// refs. Both are reducer-owned: an author cannot misreport how far its
/// authority spread or which root it came from. `None` means a `grant` ref is
/// not projected yet — the caller MUST go pending rather than guess a depth.
///
/// `authz/capabilities.md` section 10 fixes the arithmetic: a `realm_root` ref
/// sits at depth 0 and the grant itself is `max(refs.depth) + 1`, so a root
/// controller's direct grant is 1 and a member's re-grant is 2.
/// `capability-grant.schema.json` carries the same rule as `minimum: 1` on
/// `authority_depth`, which a root-only grant cannot satisfy without the final
/// increment.
pub fn derive_authority_audit(
    body: &Value,
    resolve: &dyn Fn(&str) -> Option<(u64, Vec<Value>)>,
) -> Option<(u64, Vec<Value>)> {
    let refs = body.get("issuer_authority_refs")?.as_array()?;
    if refs.is_empty() {
        return None;
    }
    let mut deepest_ref = 0_u64;
    let mut roots: Vec<Value> = Vec::new();
    for entry in refs {
        match entry.get("kind").and_then(Value::as_str) {
            Some("realm_root") => {
                if !roots.contains(entry) {
                    roots.push(entry.clone());
                }
            }
            Some("grant") => {
                let grant_id = entry.get("grant_id").and_then(Value::as_str)?;
                let (parent_depth, parent_roots) = resolve(grant_id)?;
                deepest_ref = deepest_ref.max(parent_depth);
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
    Some((deepest_ref.checked_add(1)?, roots))
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
        // D3+: materialized grants carry required authority audit members.
        // Missing fields fail closed during decoding; never synthesize them
        // from the rebuildable in-memory graph.
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
                crate::capability::IssuerAuthorityRef::RealmRoot {
                    realm_id,
                    authority_generation,
                    ..
                } => {
                    !self.realm_is_in_terminal_state(realm_id.as_str())
                        && self
                            .realm_authority_root(realm_id.as_str())
                            .is_some_and(|root| {
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
