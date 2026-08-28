//! P1 — capability control-plane projection.
//!
//! Projects `ak.capability.grant` / `ak.capability.revoke` /
//! the canonical cells declared by
//! `event-kind-registry.json`:
//!
//! - grant / revoke → `ak.component.capability.grant.v1` (or_set, one cell per GrantId). plus its
//!   `issuer_authority_refs` chain references.
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
//! an Event-derived `grant_id`, a parseable issuer, and (for grant) a non-empty grant body.
//! Missing structural inputs ⇒ `Rejected` (P3 fail-closed), never a silent
//! no-op. This mirrors `apply_capability_derived`, which likewise validates
//! structure/causality against projected cells rather than re-running the
//! Seal acceptance judgment.

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
        .get("issuer")
        .and_then(Value::as_str)
        .and_then(|value| arkret_identifiers::DidCoreId::new(value.to_owned()).ok())?;
    let issuer_principal_server_id = body
        .get("issuer_principal_server_id")
        .and_then(Value::as_str)?
        .to_owned();
    let issuer_principal_server_id =
        arkret_identifiers::DidCoreId::new(issuer_principal_server_id).ok()?;
    let subject = body
        .get("subject")
        .and_then(Value::as_str)
        .and_then(|value| arkret_identifiers::DidCoreId::new(value.to_owned()).ok())?;
    let subject_principal_server_id = body
        .get("subject_principal_server_id")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .map(arkret_identifiers::DidCoreId::new)
        .transpose()
        .ok()?;
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
    let authority_depth = body.get("authority_depth").and_then(Value::as_u64);
    let authority_root_refs = body
        .get("authority_root_refs")
        .cloned()
        .and_then(|value| serde_json::from_value(value).ok())
        .unwrap_or_default();
    Some(crate::capability::Grant {
        grant_id: grant_id.to_owned(),
        realm_id,
        issuer_id: issuer,
        issuer_principal_server_id,
        subject_id: subject,
        subject_principal_server_id,
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

/// The single active-grant predicate for the accepted capability projection.
///
/// Realm pin, revocation tombstone, effective expiry from temporal constraints,
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
    subject_is_agent_or_service: impl Fn(&str) -> bool,
) -> Result<(), &'static str> {
    use arkret_schema::CapabilityRiskTier;

    let Some(subject) = body.get("subject").and_then(Value::as_str) else {
        return Ok(());
    };
    if !subject_is_agent_or_service(subject) {
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

/// The 0-based index of `ak.component.capability.grant.v1` in the
/// `ak.capability.grant` registry `cell_writes[]`. The contract declares
/// exactly one write, so the dot's third segment is `0`.
const CAPABILITY_GRANT_WRITE_INDEX: usize = 0;

/// or_set add dot for a capability grant.
///
/// `event-and-patch.md` §2.4.2 fixes the dot to
/// `ak:event:<event_id>:<write_index>` and states outright that reading the
/// third segment as anything else — a payload index, arrival order, or a local
/// counter — produces different dot sets across implementations. This used to
/// return the soland-local `ak:operation:<uuid>` handle, which is not that
/// value at all: a peer folding the same Event derived a different tag, so the
/// two OR-Sets could never converge and an `or_set_remove_observed` issued
/// elsewhere could not name soland's add.
///
/// The format itself is pinned by `ak.vector.encoding.or_set_dot_and_batch_tag.v1`,
/// so it is read from the SDK rather than re-spelled here.
fn capability_add_dot(operation: &Operation) -> Option<String> {
    let event_id = operation.context.event_id.as_str();
    Some(arkret_schema::or_set_dot(
        event_id,
        CAPABILITY_GRANT_WRITE_INDEX,
    ))
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

/// Extract the issuer DID from a capability grant payload (top-level or
/// inside the embedded `grant` body).
fn grant_issuer(payload: &Value) -> Option<String> {
    grant_body(payload)
        .get("issuer")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
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
                    Some("realm_root") => Some(crate::capability::IssuerAuthorityRef::RealmRoot {
                        realm_id: entry
                            .get("realm_id")
                            .and_then(Value::as_str)
                            .unwrap_or_default()
                            .to_owned(),
                        cell_ref: entry
                            .get("cell_ref")
                            .and_then(Value::as_str)
                            .unwrap_or_default()
                            .to_owned(),
                        controller_epoch_at_issuance: entry
                            .get("controller_epoch_at_issuance")
                            .and_then(Value::as_u64)
                            .unwrap_or_default(),
                        authority_generation: entry
                            .get("authority_generation")
                            .and_then(Value::as_u64)
                            .unwrap_or_default(),
                    }),
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
    arkret_schema::derive_capability_authority_audit(body, &|grant_id| {
        resolve(grant_id).map(|(authority_depth, authority_root_refs)| {
            arkret_schema::CapabilityAuthorityAudit {
                authority_depth,
                authority_root_refs,
            }
        })
    })
    .ok()
    .map(|audit| (audit.authority_depth, audit.authority_root_refs))
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
        map.insert("id".to_owned(), Value::String(grant_id.to_owned()));
        map.entry("realm_id".to_owned())
            .or_insert_with(|| Value::String(operation.realm_id.to_string()));
        map.insert(
            "issuer_principal_server_id".to_owned(),
            Value::String(operation.context.principal_server_id.to_string()),
        );
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

    /// Read the current or_set item array for a grant cell (empty when the
    /// cell is absent / Bottom / not an array).
    fn capability_cell_items(&self, cell_ref: &CellRef) -> Vec<Value> {
        match self.cells.get(cell_ref) {
            Some(CellState::Value(Value::Array(items))) => items.clone(),
            _ => Vec::new(),
        }
    }

    /// Every grant currently projected on a `ak.component.capability.grant.v1`
    /// cell, resolved to its effective engine shape (latest add body + carried
    /// revocation tombstone). No realm / action / resource / temporal filtering
    /// happens here — that is [`projected_grant_is_active_for`]'s single
    /// responsibility.
    fn projected_capability_grants(&self) -> impl Iterator<Item = crate::capability::Grant> + '_ {
        const CELL_PREFIX: &str = "ak:cell:ak.component.capability.grant.v1:";
        self.cells.iter().filter_map(|(cell_ref, cell_state)| {
            let grant_id = cell_ref.as_str().strip_prefix(CELL_PREFIX)?;
            engine_grant_from_capability_cell_state(grant_id, cell_state)
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
        issuer: &str,
        issuer_principal_server_id: &str,
        realm_id: &str,
        action: &str,
        resource: &str,
        evaluation_basis: chrono::DateTime<chrono::Utc>,
    ) -> bool {
        let resource_expr = self.authz_resource_expr(realm_id, resource);
        self.projected_capability_grants().any(|grant| {
            grant.subject_id.as_str() == issuer
                && grant
                    .subject_principal_server_id
                    .as_ref()
                    .map(arkret_identifiers::DidCoreId::as_str)
                    == Some(issuer_principal_server_id)
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
        issuer: &str,
        issuer_principal_server_id: &str,
        realm_id: &str,
        action: &str,
        resource: &str,
        evaluation_basis: chrono::DateTime<chrono::Utc>,
    ) -> bool {
        let resource_expr = self.authz_resource_expr(realm_id, resource);
        self.projected_capability_grants().any(|grant| {
            grant.subject_id.as_str() == issuer
                && grant
                    .subject_principal_server_id
                    .as_ref()
                    .map(arkret_identifiers::DidCoreId::as_str)
                    == Some(issuer_principal_server_id)
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

    /// Same active-grant predicate as [`Self::issuer_has_projected_capability`],
    /// additionally pinned to one named `grant_id` — used when a receipt cites
    /// the specific grant it was issued under.
    pub fn projected_capability_grant_matches(
        &self,
        grant_id: &str,
        subject: &str,
        subject_principal_server_id: &str,
        realm_id: &str,
        action: &str,
        resource: &str,
        evaluation_basis: chrono::DateTime<chrono::Utc>,
    ) -> bool {
        let Some(grant) = self.effective_engine_grant(grant_id) else {
            return false;
        };
        let resource_expr = self.authz_resource_expr(realm_id, resource);
        grant.subject_id.as_str() == subject
            && grant
                .subject_principal_server_id
                .as_ref()
                .map(arkret_identifiers::DidCoreId::as_str)
                == Some(subject_principal_server_id)
            && projected_grant_covers_action(
                &grant,
                realm_id,
                action,
                &resource_expr,
                evaluation_basis,
            )
            && self.grant_authority_is_live_for(&grant, action, &resource_expr, evaluation_basis)
    }

    /// Distinct subjects holding `action` **verbatim** in this Realm.
    ///
    /// Deliberately unexpanded. This count drives the join-review quorum
    /// fallback, where the denominator is the set of principals a Realm
    /// actually appointed as reviewers. Expanding it through the aggregate
    /// would silently fold every owner and aggregate holder into "eligible
    /// reviewers" and move the majority threshold without any governance Event
    /// saying so.
    pub fn projected_capability_holder_count(
        &self,
        realm_id: &str,
        action: &str,
        evaluation_basis: chrono::DateTime<chrono::Utc>,
    ) -> usize {
        let resource_expr = self.authz_resource_expr(realm_id, realm_id);
        self.projected_capability_grants()
            .filter(|grant| {
                projected_grant_is_active_for(
                    grant,
                    realm_id,
                    action,
                    &resource_expr,
                    evaluation_basis,
                ) && self.grant_authority_is_live_for(
                    grant,
                    action,
                    &resource_expr,
                    evaluation_basis,
                )
            })
            .map(|grant| grant.subject_id)
            .collect::<std::collections::BTreeSet<_>>()
            .len()
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
        actor: &str,
        actor_principal_server_id: &str,
        evaluation_basis: chrono::DateTime<chrono::Utc>,
    ) -> bool {
        if self
            .realm_authority_root(realm_id)
            .is_some_and(|root| root.controller_id.as_str() == actor)
        {
            return true;
        }
        self.issuer_holds_literal_capability(
            actor,
            actor_principal_server_id,
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
        actor: &str,
        actor_principal_server_id: &str,
        action: &str,
        evaluation_basis: chrono::DateTime<chrono::Utc>,
    ) -> bool {
        self.actor_holds_effective_realm_owner(
            realm_id,
            actor,
            actor_principal_server_id,
            evaluation_basis,
        ) && arkret_policy::owner_may_author_action(action).unwrap_or(false)
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
        actor: &str,
        actor_principal_server_id: &str,
        actions: &[&str],
        evaluation_basis: chrono::DateTime<chrono::Utc>,
    ) -> bool {
        self.actor_holds_effective_realm_owner(
            realm_id,
            actor,
            actor_principal_server_id,
            evaluation_basis,
        ) || actions.iter().any(|action| {
            self.issuer_holds_literal_capability(
                actor,
                actor_principal_server_id,
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
        issuer: &str,
        issuer_principal_server_id: &str,
        realm_id: &str,
        action: &str,
        evaluation_basis: chrono::DateTime<chrono::Utc>,
    ) -> bool {
        if !self.actor_holds_effective_realm_owner(
            realm_id,
            issuer,
            issuer_principal_server_id,
            evaluation_basis,
        ) {
            return false;
        }
        arkret_policy::owner_may_grant(action).unwrap_or(false)
    }

    #[allow(clippy::too_many_arguments)]
    fn applet_non_event_grant_authority_matches(
        &self,
        issuer: &str,
        issuer_principal_server_id: &str,
        realm_id: &str,
        action: &str,
        resource: &str,
        body: &Value,
        evaluation_basis: chrono::DateTime<chrono::Utc>,
    ) -> bool {
        let Some(subject) = body.get("subject").and_then(Value::as_str) else {
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
                || registration.service_id != subject
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
                    issuer_principal_server_id,
                    realm_id,
                    rule.issuer_action,
                    resource,
                    evaluation_basis,
                ) || self.actor_holds_effective_realm_owner(
                    realm_id,
                    issuer,
                    issuer_principal_server_id,
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
                    && constraint.get("executed_by").and_then(Value::as_str)
                        == Some(registration.service_id.as_str())
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
        let root_ref_valid = engine_authority_refs_from_body(body)
            .iter()
            .any(|authority_ref| match authority_ref {
                crate::capability::IssuerAuthorityRef::RealmRoot {
                    realm_id: root_realm_id,
                    cell_ref,
                    controller_epoch_at_issuance,
                    authority_generation,
                } => {
                    root_realm_id == realm_id
                        && cell_ref == arkret_wire::REALM_AUTHORITY_ROOT_CELL
                        && self.realm_authority_root(realm_id).is_some_and(|root| {
                            root.controller_id.as_str() == issuer
                                && root.controller_epoch == *controller_epoch_at_issuance
                                && root.authority_generation == *authority_generation
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
            let owner_authorized = self.owner_may_issue_grant_for(
                &issuer,
                operation.context.principal_server_id.as_str(),
                realm_id,
                action,
                operation.created_at,
            );
            for resource in &resources {
                if !owner_authorized
                    && !self.issuer_has_projected_capability(
                        &issuer,
                        operation.context.principal_server_id.as_str(),
                        realm_id,
                        action,
                        resource,
                        operation.created_at,
                    )
                    && !self.applet_non_event_grant_authority_matches(
                        &issuer,
                        operation.context.principal_server_id.as_str(),
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
        issuer: &str,
        realm_id: &str,
        parent: &crate::capability::Grant,
    ) -> Result<(), &'static str> {
        if parent.revoked || crate::capability::is_grant_expired(parent, operation.created_at) {
            return Err("grant_revoked_upstream");
        }
        if issuer != parent.subject_id.as_str()
            || parent
                .subject_principal_server_id
                .as_ref()
                .map(arkret_identifiers::DidCoreId::as_str)
                != Some(operation.context.principal_server_id.as_str())
        {
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
        let mut grant = engine_grant_from_cell_body(grant_id, body, revoked)?;
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
                crate::capability::IssuerAuthorityRef::RealmRoot {
                    realm_id,
                    cell_ref,
                    authority_generation,
                    ..
                } => {
                    cell_ref == arkret_wire::REALM_AUTHORITY_ROOT_CELL
                        && !self.realm_is_in_terminal_state(realm_id)
                        && self
                            .realm_authority_root(realm_id)
                            .is_some_and(|root| root.authority_generation == *authority_generation)
                }
                crate::capability::IssuerAuthorityRef::Grant { grant_id } => {
                    let Some(parent) = self.effective_engine_grant(grant_id) else {
                        return false;
                    };
                    parent.subject_id == grant.issuer_id
                        && parent
                            .subject_principal_server_id
                            .as_ref()
                            .map(arkret_identifiers::DidCoreId::as_str)
                            == Some(grant.issuer_principal_server_id.as_str())
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

    /// P1 — project `ak.capability.grant` as an or_set add on the grant cell.
    pub(crate) fn apply_capability_grant(
        &mut self,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
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
                self.agent_lifecycles.contains_key(subject)
                    || self
                        .applets
                        .values()
                        .any(|registration| registration.service_id == subject)
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
        let Some(cell_ref) = Self::capability_grant_cell_ref(&grant_id) else {
            return ProjectionEffect::Rejected {
                reason: "capability_grant_cell_ref_invalid".to_owned(),
            };
        };

        let mut items = self.capability_cell_items(&cell_ref);
        // §12.1 terminal: a re-add of an already observed-removed grant_id
        // does NOT revive. Carry the revoked tombstone onto the new add.
        let terminal_revoked = Self::capability_cell_has_revoked_item(&items);
        let mut value = grant_item_value(operation, &grant_id, terminal_revoked, now);
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
        // Fail closed rather than invent a tag: an add whose dot is not the
        // registered one is unremovable by any conforming observed-remove.
        let Some(tag) = capability_add_dot(operation) else {
            return ProjectionEffect::Rejected {
                reason: "capability_add_dot_unresolved".to_owned(),
            };
        };
        items.push(serde_json::json!({
            "tag": tag,
            "value": value,
        }));
        self.cells
            .insert(cell_ref, CellState::Value(Value::Array(items)));

        ProjectionEffect::CapabilityGrantProjected { grant_id, realm_id }
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
        let Some(target) = self.effective_engine_grant(&grant_id) else {
            return self.queue_pending_replay(grant_id, operation, "capability_target_unresolved");
        };
        let actor_is_target_issuer = operation.context.sender.as_str() == target.issuer_id.as_str();
        let actor_is_target_realm_controller = self
            .realm_authority_root(&target.realm_id)
            .is_some_and(|root| root.controller_id.as_str() == operation.context.sender.as_str());
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
        let Some(target) = self.effective_engine_grant(&grant_id) else {
            return self.queue_pending_replay(grant_id, operation, "capability_target_unresolved");
        };
        if operation.context.sender.as_str() != target.subject_id.as_str() {
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
        now: chrono::DateTime<chrono::Utc>,
    ) -> ProjectionEffect {
        let realm_id = operation.realm_id.to_string();
        let Some(cell_ref) = Self::capability_grant_cell_ref(grant_id) else {
            return ProjectionEffect::Rejected {
                reason: "capability_revoke_cell_ref_invalid".to_owned(),
            };
        };

        let mut items = self.capability_cell_items(&cell_ref);
        let revoked_at = arkret_canonical::format_timestamp_canonical(now);
        debug_assert!(!items.is_empty(), "unknown grants go dependency-pending");
        // Observed-remove: mark every surviving add for this grant_id removed
        // (terminal). Repeated revoke/relinquish is idempotent.
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
        self.cells
            .insert(cell_ref, CellState::Value(Value::Array(items)));

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

    /// Resolve the immutable authority audit used by the registry projector.
    pub fn capability_authority_audit(
        &self,
        grant_id: &str,
    ) -> Option<arkret_schema::CapabilityAuthorityAudit> {
        self.projected_authority_audit(grant_id)
            .map(
                |(authority_depth, authority_root_refs)| arkret_schema::CapabilityAuthorityAudit {
                    authority_depth,
                    authority_root_refs,
                },
            )
    }

    /// Project one Event using this deterministic projection's authority basis.
    pub fn project_registered_cell_writes(
        &self,
        event: &arkret_wire::Event,
        digest_suite: arkret_canonical::DigestSuite,
    ) -> Result<Vec<arkret_wire::cba::ProjectedCellWrite>, arkret_schema::EventCellContractError>
    {
        arkret_schema::project_registered_cell_writes_with_authority_resolver(
            event,
            digest_suite,
            &|grant_id| self.capability_authority_audit(grant_id),
        )
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
        let cell_ref = Self::capability_grant_cell_ref(grant_id)?;
        let items = self.capability_cell_items(&cell_ref);
        let last = items.last()?;
        let body = last.get("value").unwrap_or(last);
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
    /// A grant that only names `realm_root` refs returns an empty set, which
    /// terminates a walk: a root is a terminal, never an edge.
    fn authority_grant_refs_of(&self, grant_id: &str) -> Vec<String> {
        let Some(cell_ref) = Self::capability_grant_cell_ref(grant_id) else {
            return Vec::new();
        };
        let items = self.capability_cell_items(&cell_ref);
        let Some(last) = items.last() else {
            return Vec::new();
        };
        let body = last.get("value").unwrap_or(last);
        grant_authority_grant_refs_in(body)
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

    /// Every persisted capability grant for `subject_did`, paired with the
    /// Realm that governs its grant cell. Revocation must be submitted in
    /// this Realm; a controller PCR is not a cross-Realm revocation surface.
    pub fn grant_locations_for_subject(
        &self,
        subject_did: &str,
        subject_principal_server_id: &str,
    ) -> Vec<(String, String)> {
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
                    .unwrap_or(false)
                    && body
                        .get("subject_principal_server_id")
                        .and_then(Value::as_str)
                        == Some(subject_principal_server_id);
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
        subject_principal_server_id: &str,
    ) -> Vec<(String, String)> {
        self.grant_locations_for_subject(subject_did, subject_principal_server_id)
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
                && subject.starts_with("ak:did_core:")
            {
                revoked.insert(subject.to_owned());
            }
        }
        revoked
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
