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
        "object" => selector_string_field(selector, "object_kind")
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
                if canonical.get("constraint_kind").and_then(Value::as_str)
                    != Some("scope_limitation")
                    || !canonical.contains_key("allowed_circle_ids")
                {
                    return None;
                }
                canonical.insert(
                    "constraint_kind".to_owned(),
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
        issuer,
        subject,
        resource,
        actions,
        capability_action_registry_digest,
        constraints,
        revoked,
        created_at,
        issuer_authority_refs,
        authority_depth,
        authority_root_refs,
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

/// The single active-grant predicate for the accepted capability projection.
///
/// Realm pin, revocation tombstone, effective expiry (top-level `expires_at`
/// and the `temporal` constraint, stricter side wins) and action / resource
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

#[cfg(test)]
mod cba_capability_cell_tests {
    use arkret_state::lattice::CellState;
    use serde_json::{Value, json};

    use super::engine_grant_from_capability_cell_state;

    #[test]
    fn engine_grant_reads_registry_projected_wrapper() {
        let grant_id = "ak:grant:AVrFZlvgUn-7TZ-JmuAqj5zeywh7lJ6SQmpb3MNF95Q7";
        let realm_id = "ak:realm:AW629k2g_XE37cPwN8MimS3euJY2Vc__Knn5F9_x0pic";
        let registry_digest = arkret_policy::current_capability_action_registry_digest().unwrap();
        let state = CellState::Value(Value::Array(vec![json!({
            "tag": "ak:event:AY_KsmK6yLixEOrtHaJQKVPxqvToAwftLv3kDhf3WwDk:0",
            "value": {
                "grant_id": grant_id,
                "grant": {
                    "id": grant_id,
                    "realm_id": realm_id,
                    "issuer": "did:web:owner.example",
                    "issuer_authority_refs": [{
                        "kind": "realm_root",
                        "realm_id": realm_id,
                        "cell_ref": "ak:cell:ak.component.realm.authority_root.v1:null",
                        "controller_epoch_at_issuance": 0,
                        "authority_generation": 0
                    }],
                    "subject": "did:web:owner.example",
                    "actions": ["ak.realm.admin"],
                    "capability_action_registry_digest": registry_digest,
                    "resources": [{
                        "kind": "realm",
                        "realm_id": realm_id,
                        "match_scope": "realm_wide"
                    }],
                    "issued_at": "2026-07-28T00:00:00.000Z"
                }
            }
        })]));

        let grant = engine_grant_from_capability_cell_state(grant_id, &state)
            .expect("the CBA registry wrapper must resolve to an effective grant");
        assert_eq!(grant.grant_id, grant_id);
        assert_eq!(grant.realm_id, realm_id);
        assert_eq!(grant.subject, "did:web:owner.example");
        assert!(
            grant
                .actions
                .iter()
                .any(|action| action == "ak.realm.admin")
        );
    }
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

/// True when a projected grant authorizes authoring under `action`.
///
/// `capabilities.md` section 3.2 answers Event admission over
/// `target_event_kinds`. A verbatim action match is unconditional; an aggregate
/// expansion is a re-reading of the issuer's signature under a
/// capability-action registry snapshot, so it is anchored to the basis the
/// grant itself names and fails closed as
/// `capability_registry_basis_unavailable` when that snapshot is not the one
/// this build embeds. The receiver never falls back to its own registry.
fn grant_action_covers(grant: &crate::capability::Grant, action: &str) -> bool {
    if grant.actions.iter().any(|candidate| candidate == action) {
        return true;
    }
    if arkret_policy::require_registry_basis(grant.capability_action_registry_digest.as_ref())
        .is_err()
    {
        return false;
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

/// The `event_id` a fixture Operation carries so [`capability_add_dot`] can
/// derive its registered dot, mirroring what
/// `sdk_projection::projection_operation_from_event` injects on the submit
/// path.
///
/// Hashes the fixture Operation id into a valid v1 SHA-256 Event identity.
/// Fixtures that reuse one Operation id across calls keep sharing one dot —
/// the idempotent re-add the previous `ak:operation:` tag also produced.
#[cfg(test)]
fn fixture_event_id_for_operation(operation_id: &str) -> String {
    let digest = arkret_identifiers::Hash::new(arkret_canonical::sha256_digest(operation_id))
        .expect("fixture digest is typed");
    arkret_identifiers::EventId::from_event_digest(&digest)
        .expect("SHA-256 is a registered Event digest suite")
        .to_string()
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

fn genesis_grant_id(payload: &Value) -> Option<String> {
    payload
        .get("event_id")
        .and_then(Value::as_str)
        .and_then(|value| arkret_identifiers::EventId::new(value.to_owned()).ok())
        .map(|event_id| arkret_identifiers::GrantId::from_event_id(&event_id).to_string())
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
    let mut depth: u64 = 0;
    let mut roots: Vec<Value> = Vec::new();
    let refs = body
        .get("issuer_authority_refs")
        .and_then(Value::as_array)?;
    for entry in refs {
        match entry.get("kind").and_then(Value::as_str) {
            Some("realm_root") => {
                let realm_id = entry.get("realm_id")?.as_str()?;
                let cell_ref = entry.get("cell_ref")?.as_str()?;
                let authority_generation = entry.get("authority_generation")?.as_u64()?;
                roots.push(serde_json::json!({
                    "kind": "realm_root",
                    "realm_id": realm_id,
                    "cell_ref": cell_ref,
                    "authority_generation": authority_generation,
                }));
            }
            Some("grant") => {
                let grant_id = entry.get("grant_id").and_then(Value::as_str)?;
                let (parent_depth, parent_roots) = resolve(grant_id)?;
                depth = depth.max(parent_depth);
                roots.extend(parent_roots);
            }
            _ => return None,
        }
    }
    // Deduplicate on (realm_id, cell_ref, authority_generation) and sort
    // canonically: controller_epoch_at_issuance is per-grant issuance audit and
    // deliberately not part of root identity.
    let identity = |root: &Value| {
        Some(format!(
            "{}\u{1f}{}\u{1f}{}",
            root.get("realm_id")?.as_str()?,
            root.get("cell_ref")?.as_str()?,
            root.get("authority_generation")?.as_u64()?,
        ))
    };
    if roots.iter().any(|root| identity(root).is_none()) {
        return None;
    }
    roots.sort_by_key(&identity);
    roots.dedup_by_key(|root| identity(root));
    (!roots.is_empty()).then_some((depth + 1, roots))
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
            let constraint_kind = constraint
                .get("constraint_kind")
                .and_then(Value::as_str)
                .or_else(|| constraint.get("type").and_then(Value::as_str));
            if constraint_kind != Some("temporal") {
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

fn body_max_authority_depth(body: &Value) -> Option<u32> {
    value_array_field(body, "constraints")
        .into_iter()
        .filter_map(|constraint| {
            let constraint_kind = constraint
                .get("constraint_kind")
                .and_then(Value::as_str)
                .or_else(|| constraint.get("type").and_then(Value::as_str));
            if constraint_kind != Some("authority_control") {
                return None;
            }
            constraint
                .get("max_authority_depth")
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
        map.insert("id".to_owned(), Value::String(grant_id.to_owned()));
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
        realm_id: &str,
        action: &str,
        resource: &str,
        evaluation_basis: chrono::DateTime<chrono::Utc>,
    ) -> bool {
        let resource_expr = self.authz_resource_expr(realm_id, resource);
        self.projected_capability_grants().any(|grant| {
            grant.subject == issuer
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
        realm_id: &str,
        action: &str,
        resource: &str,
        evaluation_basis: chrono::DateTime<chrono::Utc>,
    ) -> bool {
        let resource_expr = self.authz_resource_expr(realm_id, resource);
        self.projected_capability_grants().any(|grant| {
            grant.subject == issuer
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
        realm_id: &str,
        action: &str,
        resource: &str,
        evaluation_basis: chrono::DateTime<chrono::Utc>,
    ) -> bool {
        let Some(grant) = self.effective_engine_grant(grant_id) else {
            return false;
        };
        let resource_expr = self.authz_resource_expr(realm_id, resource);
        grant.subject == subject
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
            .map(|grant| grant.subject)
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
            realm_id,
            CapabilityActionId::REALM_OWNER,
            realm_id,
            evaluation_basis,
        )
    }

    /// True when `actor` speaks for the Realm owner aggregate and that
    /// aggregate operationally covers `action` in the registry snapshot bound
    /// into the authority-root cell.
    ///
    /// This is intentionally narrower than [`Self::actor_governs_realm`]: a
    /// generic authorization preflight must not turn owner grant authority
    /// into direct access to non-Event endpoints, nor may it authorize the two
    /// root-control-only Realm lifecycle actions.
    pub fn realm_owner_operationally_covers_action(
        &self,
        realm_id: &str,
        actor: &str,
        action: &str,
        evaluation_basis: chrono::DateTime<chrono::Utc>,
    ) -> bool {
        self.actor_holds_effective_realm_owner(realm_id, actor, evaluation_basis)
            && arkret_policy::owner_may_author_action(
                action,
                self.realm_authority_registry_basis(realm_id).as_ref(),
            )
            .unwrap_or(false)
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
    /// Matching is by action id against the registry's
    /// `grant_authority_actions` (through `arkret_policy::owner_may_grant`),
    /// which additionally rejects `root_control_only` / `subject_only` /
    /// `reducer_only` actions and requires a profile action to be registered as
    /// owner-grantable by an active profile. Event-kind coverage is never
    /// substituted here.
    fn owner_may_issue_grant_for(
        &self,
        issuer: &str,
        realm_id: &str,
        action: &str,
        evaluation_basis: chrono::DateTime<chrono::Utc>,
    ) -> bool {
        if !self.actor_holds_effective_realm_owner(realm_id, issuer, evaluation_basis) {
            return false;
        }
        let basis = self.realm_authority_registry_basis(realm_id);
        arkret_policy::owner_may_grant(
            action,
            basis.as_ref(),
            &self.realm_declared_profiles(realm_id),
        )
        .unwrap_or(false)
    }

    /// Profile ids the Realm has declared in its `schema_refs`
    /// (`capabilities.md` section 3.2).
    ///
    /// Read from the Realm's own metadata rather than a deployment-wide list:
    /// owner grant authority over a profile action is a per-Realm question,
    /// and a profile the Realm never claimed must not widen its owner
    /// ceiling. The declaration is the whole condition — there is no second
    /// per-action whitelist — and a grantable action still passes its
    /// profile's own registration / constraint / evidence gates downstream.
    fn realm_declared_profiles(&self, realm_id: &str) -> Vec<String> {
        // `realm_create_log()` is an ordered-log audit projection whose entry
        // is only the Realm id. Profile activation belongs to the authoritative
        // create-locked realm-genesis cell, exposed through this shared query.
        self.realm_schema_refs(realm_id)
            .into_iter()
            .filter(|reference| {
                arkret_schema::generated::profile_requirements::PROFILE_REQUIREMENTS
                    .contains_key(reference.as_str())
            })
            .collect()
    }

    #[allow(clippy::too_many_arguments)]
    fn applet_non_event_grant_authority_matches(
        &self,
        issuer: &str,
        realm_id: &str,
        action: &str,
        resource: &str,
        body: &Value,
        evaluation_basis: chrono::DateTime<chrono::Utc>,
    ) -> bool {
        let Some(subject) = body.get("subject").and_then(Value::as_str) else {
            return false;
        };
        let Some(registration) = self.applets.get(subject) else {
            return false;
        };
        let Some(registration_scope_ref) = registration.registration_scope_ref.as_ref() else {
            return false;
        };
        let resources = value_array_field(body, "resources");
        let resource_selectors = value_array_field(body, "resource_selectors");
        if resources.len() != 1
            || !resource_selectors.is_empty()
            || resources.first() != Some(registration_scope_ref)
        {
            return false;
        }
        let Some(constraints) = body.get("constraints").and_then(Value::as_array) else {
            return false;
        };

        registration.claimed_profiles.iter().any(|profile_id| {
            let Some(rule) =
                arkret_schema::generated::profile_requirements::non_event_grant_authority_rule(
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
                    realm_id,
                    rule.issuer_action,
                    resource,
                    evaluation_basis,
                ) || self.actor_holds_effective_realm_owner(realm_id, issuer, evaluation_basis))
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
                                && body
                                    .get("capability_action_registry_digest")
                                    .and_then(Value::as_str)
                                    .is_none_or(|digest| {
                                        digest == root.capability_action_registry_digest.as_str()
                                    })
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
        issuer: &str,
        realm_id: &str,
        parent: &crate::capability::Grant,
    ) -> Result<(), &'static str> {
        if parent.revoked || crate::capability::is_grant_expired(parent, operation.created_at) {
            return Err("grant_revoked_upstream");
        }
        if issuer != parent.subject {
            return Err("grant_exceeds_issuer_authority");
        }
        if realm_id != parent.realm_id {
            return Err("grant_exceeds_issuer_authority");
        }
        if let Some(parent_depth) = crate::capability::max_authority_depth(parent) {
            if parent_depth == 0 {
                return Err("authority_depth_exceeded");
            }
            match body_max_authority_depth(body) {
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
                    parent.subject == grant.issuer
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
        let Some(grant_id) = genesis_grant_id(&operation.payload) else {
            return ProjectionEffect::Rejected {
                reason: "capability_grant_event_id_missing".to_owned(),
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
            validate_nonhuman_subject_grant_constraints(grant_body(&operation.payload), |subject| {
                self.agent_lifecycles.contains_key(subject) || self.applets.contains_key(subject)
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
        let actor_is_target_issuer = operation.context.sender.as_str() == target.issuer;
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
        if operation.context.sender.as_str() != target.subject {
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
        let Some(grant_id) = genesis_grant_id(&operation.payload) else {
            return Ok(());
        };
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
    use arkret_event_draft::ProjectedEventOperation as Operation;
    use arkret_identifiers::{OperationId, RealmId};
    use arkret_wire::EventKind;
    use serde_json::json;

    use crate::reducer::{ProjectionState, SolandRealmState};

    const AGENT: &str = "did:web:agent.example";
    const REALM: &str = "ak:realm:AfCwsnvdJeIf2T8CEXlUwnunThfVLY8R2SI54sTEapiS";
    const GRANT: &str = "ak:grant:AYOGN6zLytw3AP-JRSpnGwuq8CjgA5Tq_YDSH1IzUT77";
    const GRANT_2: &str = "ak:grant:AWj0q-Z4gw_sS6wsl8gtEwhi3abA99IaQU-csCcBHFVz";
    const GRANT_3: &str = "ak:grant:Af-etF0vTHwlpJOwEu53s_Pq08WOwxuO7UxIWltAiAmk";
    const OWNER_GRANT: &str = "ak:grant:Aam5L1XcrHrrRfNk_9wOcpOu9263GPwRPTjzYXdIgYb0";
    const REALM_OWNER: &str = "did:web:alice.example";

    #[test]
    fn agent_and_service_high_risk_grants_require_finite_expiry() {
        let high_risk = json!({
            "subject": AGENT,
            "actions": ["ak.capability.revoke"],
            "resources": [{"kind": "realm", "realm_id": REALM}]
        });
        assert_eq!(
            super::validate_nonhuman_subject_grant_constraints(&high_risk, |_| true),
            Err("agent_grant_expiry_required")
        );

        let low_risk = json!({
            "subject": AGENT,
            "actions": ["ak.reaction.add"],
            "resources": [{"kind": "realm", "realm_id": REALM}]
        });
        assert_eq!(
            super::validate_nonhuman_subject_grant_constraints(&low_risk, |_| true),
            Ok(())
        );
    }

    fn op(event_kind: EventKind, mut payload: serde_json::Value) -> Operation {
        const OPERATION_ID: &str = "ak:operation:01970000-0000-7000-8000-0000000000ff";
        let object = payload.as_object_mut().expect("test payload object");
        object
            .entry("sender".to_owned())
            .or_insert_with(|| serde_json::Value::String(REALM_OWNER.to_owned()));
        if let Some(accepted_event_id) = object.remove("accepted_event_id") {
            object.insert("event_id".to_owned(), accepted_event_id);
        }
        object.entry("event_id".to_owned()).or_insert_with(|| {
            serde_json::Value::String(super::fixture_event_id_for_operation(OPERATION_ID))
        });
        let accepted_scope_ref = object.remove("accepted_scope_ref");
        let executed_by = object.remove("executed_by");
        let mut operation = arkret_event_draft::test_support::raw_projected_operation(
            OperationId::new(OPERATION_ID).unwrap(),
            RealmId::new(REALM.to_owned()).unwrap(),
            event_kind,
            payload,
        );
        if let Some(accepted_scope_ref) = accepted_scope_ref {
            operation.context.accepted_scope_ref =
                serde_json::from_value(accepted_scope_ref).unwrap();
        }
        if let Some(executed_by) = executed_by {
            operation.context.executed_by = Some(serde_json::from_value(executed_by).unwrap());
        }
        operation
    }

    fn grant_payload(
        grant_id: &str,
        issuer: &str,
        subject: &str,
        actions: serde_json::Value,
        resources: serde_json::Value,
    ) -> serde_json::Value {
        let event_id = grant_id.replacen("ak:grant:", "ak:event:", 1);
        json!({
            "event_id": event_id,
            "grant": {
                "schema": arkret_wire::SchemaId::CAPABILITY_V1,
                "realm_id": REALM,
                "issuer": issuer,
                "issuer_authority_refs": [{
                    "kind": "realm_root",
                    "realm_id": REALM,
                    "cell_ref": "ak:cell:ak.component.realm.authority_root.v1:null",
                    "controller_epoch_at_issuance": 0,
                    "authority_generation": 0
                }],
                "subject": subject,
                "actions": actions,
                "resources": resources,
            }
        })
    }

    fn seed_realm_authority(state: &mut ProjectionState) {
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
        crate::reducer::tests::install_realm_authority_root(state, REALM, REALM_OWNER);
        // Genesis authority is the authority-root cell, not a founding grant.
        // The owner's own bootstrap grant therefore goes through the ordinary
        // issuer-upper-bound path and is authorized by the owner aggregate.
        let mut owner_grant = grant_payload(
            OWNER_GRANT,
            REALM_OWNER,
            REALM_OWNER,
            json!(["ak.realm.admin", "ak.message.create"]),
            json!([{ "kind": "realm", "realm_id": REALM }]),
        );
        owner_grant["grant"]["capability_action_registry_digest"] =
            json!(arkret_policy::current_capability_action_registry_digest().unwrap());
        let effect =
            state.apply_capability_grant(&op(EventKind::CapabilityGrant, owner_grant), now);
        assert!(matches!(
            effect,
            crate::reducer::ProjectionEffect::CapabilityGrantProjected { .. }
        ));
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
        let old_event = "ak:event:AVI3AO2X2rB2hMfALczp6qgYt73z3AwmGo2isSyuWZGo";
        let new_event = "ak:event:AQ985E-2w6lvWUxeIPTXvhe07EuX-DPPiDaS3_w-r37V";
        let old_key = "ak:agent_key:old";
        let new_key = "ak:agent_key:new";

        assert!(matches!(
            state.apply_agent_key_authorize(&op(
                EventKind::AgentKeyAuthorize,
                json!({
                    "agent_id": AGENT,
                    "key_id": old_key,
                    "accepted_event_id": old_event,
                }),
            )),
            crate::reducer::ProjectionEffect::AgentKeyAuthorizeProjected { .. }
        ));

        let rejected = state.apply_agent_key_authorize(&op(
            EventKind::AgentKeyAuthorize,
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
            EventKind::AgentKeyAuthorize,
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
        let old_event = "ak:event:AV97PI2Y6Qum1pZ62jB1P6M_I7KjPy5KVQxs3bDBUkws";
        let new_event = "ak:event:AcQWkV0enAXbpr18oGw1oRi_yX4oOxV_-eTJTh_5RzRv";
        let key_id = "ak:agent_key:stable";

        assert!(matches!(
            state.apply_agent_key_authorize(&op(
                EventKind::AgentKeyAuthorize,
                json!({
                    "agent_id": AGENT,
                    "key_id": key_id,
                    "accepted_event_id": old_event,
                }),
            )),
            crate::reducer::ProjectionEffect::AgentKeyAuthorizeProjected { .. }
        ));

        let rejected = state.apply_agent_key_authorize(&op(
            EventKind::AgentKeyAuthorize,
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
            EventKind::AgentKeyAuthorize,
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
        seed_realm_authority(&mut state);
        let effect = state.apply_capability_grant(
            &op(
                EventKind::CapabilityGrant,
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
                if reason == "realm_authority_controller_mismatch"
        ));
    }

    #[test]
    fn root_grant_is_limited_to_issuer_effective_authority() {
        let mut state = ProjectionState::default();
        seed_realm_authority(&mut state);
        let effect = state.apply_capability_grant(
            &op(
                EventKind::CapabilityGrant,
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
        let mut allowed_operation = op(
            EventKind::CapabilityGrant,
            grant_payload(
                GRANT_2,
                "did:web:bob.example",
                AGENT,
                json!(["ak.message.create"]),
                json!([{ "kind": "realm", "realm_id": REALM }]),
            ),
        );
        allowed_operation.payload["grant"]["issuer_authority_refs"] =
            json!([{ "kind": "grant", "grant_id": GRANT }]);
        let allowed = state.apply_capability_grant(&allowed_operation, chrono::Utc::now());
        assert!(matches!(
            allowed,
            crate::reducer::ProjectionEffect::CapabilityGrantProjected { .. }
        ));
        let mut denied_operation = op(
            EventKind::CapabilityGrant,
            grant_payload(
                GRANT_3,
                "did:web:bob.example",
                AGENT,
                json!(["ak.reaction.add"]),
                json!([{ "kind": "realm", "realm_id": REALM }]),
            ),
        );
        denied_operation.payload["grant"]["issuer_authority_refs"] =
            json!([{ "kind": "grant", "grant_id": GRANT }]);
        let denied = state.apply_capability_grant(&denied_operation, chrono::Utc::now());
        assert!(matches!(
            denied,
            crate::reducer::ProjectionEffect::Rejected { reason }
                if reason == "grant_exceeds_issuer_authority"
        ));
    }

    fn project_bridge_registration(state: &mut ProjectionState) {
        let effect = state.apply_applet_registration(
            &op(
                EventKind::AppletRegistration,
                json!({
                    "applet_id": "ak:applet:01970000-0000-7000-8000-0000000000b0",
                    "service_id": "did:web:bridge.example",
                    "namespace": "bridge",
                    "claimed_profiles": [
                        "ak.profile.applet_service.v1",
                        "ak.profile.applet_bridge.v1"
                    ],
                    "requested_scopes": ["ak.applet.ghost.provision"],
                    "registration_epoch": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
                    "accepted_scope_ref": { "kind": "realm", "realm_id": REALM },
                }),
            ),
            chrono::Utc::now(),
        );
        assert!(matches!(
            effect,
            crate::reducer::ProjectionEffect::AppletProjectionUpdated { .. }
        ));
    }

    fn bridge_grant_payload() -> serde_json::Value {
        let mut payload = grant_payload(
            GRANT_2,
            "did:web:alice.example",
            "did:web:bridge.example",
            json!(["ak.applet.ghost.provision"]),
            json!([{ "kind": "realm", "realm_id": REALM }]),
        );
        payload["grant"]["expires_at"] = json!("2099-01-01T00:00:00.000Z");
        payload["grant"]["constraints"] = json!([{
            "constraint_kind": "authority_control",
            "constraint_subkind": "applet_authority",
            "applet_id": "ak:applet:01970000-0000-7000-8000-0000000000b0",
            "executed_by": "did:web:bridge.example",
            "registration_epoch": "sha256:1111111111111111111111111111111111111111111111111111111111111111"
        }]);
        payload
    }

    #[test]
    fn applet_bridge_non_event_grant_uses_exact_profile_rule() {
        let mut state = ProjectionState::default();
        seed_realm_authority(&mut state);
        project_bridge_registration(&mut state);
        let effect = state.apply_capability_grant(
            &op(EventKind::CapabilityGrant, bridge_grant_payload()),
            chrono::Utc::now(),
        );
        assert!(matches!(
            effect,
            crate::reducer::ProjectionEffect::CapabilityGrantProjected { .. }
        ));
    }

    #[test]
    fn realm_owner_without_admin_grant_cannot_issue_applet_non_event_grant() {
        let mut state = ProjectionState::default();
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
        project_bridge_registration(&mut state);
        let effect = state
            .apply_capability_grant(&op(EventKind::CapabilityGrant, bridge_grant_payload()), now);
        assert!(matches!(
            effect,
            crate::reducer::ProjectionEffect::Rejected { reason }
                if reason == "realm_authority_controller_mismatch"
        ));
    }

    #[test]
    fn applet_bridge_non_event_grant_rejects_profile_and_binding_mutations() {
        let mut state = ProjectionState::default();
        seed_realm_authority(&mut state);
        project_bridge_registration(&mut state);
        let base = bridge_grant_payload();
        let mut mutations = Vec::new();

        let mut wrong_subject = base.clone();
        wrong_subject["grant"]["subject"] = json!("did:web:other.example");
        mutations.push(wrong_subject);
        let mut wrong_epoch = base.clone();
        wrong_epoch["grant"]["constraints"][0]["registration_epoch"] =
            json!("sha256:2222222222222222222222222222222222222222222222222222222222222222");
        mutations.push(wrong_epoch);
        let mut wrong_applet = base.clone();
        wrong_applet["grant"]["constraints"][0]["applet_id"] =
            json!("ak:applet:01970000-0000-7000-8000-0000000000b1");
        mutations.push(wrong_applet);
        let mut wrong_subkind = base.clone();
        wrong_subkind["grant"]["constraints"][0]["constraint_subkind"] =
            json!("max_authority_depth");
        mutations.push(wrong_subkind);
        let mut widened_scope = base;
        widened_scope["grant"]["resources"] = json!(["*"]);
        mutations.push(widened_scope);

        for payload in mutations {
            assert_eq!(
                state.validate_grant_issuer_upper_bound(&op(EventKind::CapabilityGrant, payload)),
                Err("grant_exceeds_issuer_authority")
            );
        }
    }

    #[test]
    fn regranted_grant_cannot_outlive_its_ref_expiry() {
        let mut state = ProjectionState::default();
        seed_realm_authority(&mut state);
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
        let parent_effect = state
            .apply_capability_grant(&op(EventKind::CapabilityGrant, parent), chrono::Utc::now());
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
        child["grant"]["issuer_authority_refs"] = json!([{ "kind": "grant", "grant_id": GRANT }]);
        child["grant"]["expires_at"] =
            json!(arkret_canonical::format_timestamp_canonical(child_expiry));
        let child_effect = state
            .apply_capability_grant(&op(EventKind::CapabilityGrant, child), chrono::Utc::now());
        assert!(matches!(
            child_effect,
            crate::reducer::ProjectionEffect::Rejected { reason }
                if reason == "authority_expiry_widening"
        ));
    }

    #[test]
    fn regranted_grant_from_a_revoked_ref_is_rejected() {
        let mut state = ProjectionState::default();
        seed_realm_authority(&mut state);
        let parent = grant_payload(
            GRANT,
            "did:web:alice.example",
            "did:web:bob.example",
            json!(["ak.message.create"]),
            json!([{ "kind": "realm", "realm_id": REALM }]),
        );
        let parent_effect = state
            .apply_capability_grant(&op(EventKind::CapabilityGrant, parent), chrono::Utc::now());
        assert!(matches!(
            parent_effect,
            crate::reducer::ProjectionEffect::CapabilityGrantProjected { .. }
        ));
        let revoke_effect = state.apply_capability_revoke(
            &op(EventKind::CapabilityRevoke, json!({ "grant_id": GRANT })),
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
        child["grant"]["issuer_authority_refs"] = json!([{ "kind": "grant", "grant_id": GRANT }]);
        child["grant"]["expires_at"] = json!(arkret_canonical::format_timestamp_canonical(
            chrono::Utc::now() + chrono::Duration::minutes(30)
        ));
        let child_effect = state
            .apply_capability_grant(&op(EventKind::CapabilityGrant, child), chrono::Utc::now());
        assert!(matches!(
            child_effect,
            crate::reducer::ProjectionEffect::Rejected { reason }
                if reason == "grant_revoked_upstream"
        ));
    }

    #[test]
    fn ancestor_revoke_invalidates_child_without_rewriting_child_cell() {
        let mut state = ProjectionState::default();
        seed_realm_authority(&mut state);
        let now = chrono::Utc::now();
        let parent = grant_payload(
            GRANT,
            REALM_OWNER,
            "did:web:bob.example",
            json!(["ak.message.create"]),
            json!([{ "kind": "realm", "realm_id": REALM }]),
        );
        assert!(matches!(
            state.apply_capability_grant(&op(EventKind::CapabilityGrant, parent), now),
            crate::reducer::ProjectionEffect::CapabilityGrantProjected { .. }
        ));
        let mut child = grant_payload(
            GRANT_2,
            "did:web:bob.example",
            AGENT,
            json!(["ak.message.create"]),
            json!([{ "kind": "realm", "realm_id": REALM }]),
        );
        child["grant"]["issuer_authority_refs"] = json!([{ "kind": "grant", "grant_id": GRANT }]);
        child["sender"] = json!("did:web:bob.example");
        assert!(matches!(
            state.apply_capability_grant(&op(EventKind::CapabilityGrant, child), now),
            crate::reducer::ProjectionEffect::CapabilityGrantProjected { .. }
        ));
        assert!(state.issuer_has_projected_capability(
            AGENT,
            REALM,
            "ak.message.create",
            REALM,
            now,
        ));
        let child_cell = ProjectionState::capability_grant_cell_ref(GRANT_2).unwrap();
        let child_before = state.cells.get(&child_cell).cloned();

        assert!(matches!(
            state.apply_capability_revoke(
                &op(EventKind::CapabilityRevoke, json!({ "grant_id": GRANT })),
                now,
            ),
            crate::reducer::ProjectionEffect::CapabilityRevokeProjected { .. }
        ));
        assert!(!state.issuer_has_projected_capability(
            AGENT,
            REALM,
            "ak.message.create",
            REALM,
            now,
        ));
        assert_eq!(state.cells.get(&child_cell).cloned(), child_before);
    }

    #[test]
    fn root_transfer_preserves_grant_but_generation_reset_invalidates_it() {
        let mut state = ProjectionState::default();
        seed_realm_authority(&mut state);
        let now = chrono::Utc::now();
        let grant = grant_payload(
            GRANT,
            REALM_OWNER,
            AGENT,
            json!(["ak.message.create"]),
            json!([{ "kind": "realm", "realm_id": REALM }]),
        );
        assert!(matches!(
            state.apply_capability_grant(&op(EventKind::CapabilityGrant, grant), now),
            crate::reducer::ProjectionEffect::CapabilityGrantProjected { .. }
        ));

        let mut root = state.realm_authority_root(REALM).unwrap();
        root.controller_id = arkret_identifiers::Did::new("did:web:bob.example").unwrap();
        root.controller_epoch += 1;
        state.realm_null_subject_cells.insert(
            (
                REALM.to_owned(),
                arkret_wire::REALM_AUTHORITY_ROOT_CELL.to_owned(),
            ),
            arkret_state::lattice::CellState::Value(serde_json::to_value(&root).unwrap()),
        );
        assert!(state.issuer_has_projected_capability(
            AGENT,
            REALM,
            "ak.message.create",
            REALM,
            now,
        ));

        root.authority_generation += 1;
        state.realm_null_subject_cells.insert(
            (
                REALM.to_owned(),
                arkret_wire::REALM_AUTHORITY_ROOT_CELL.to_owned(),
            ),
            arkret_state::lattice::CellState::Value(serde_json::to_value(root).unwrap()),
        );
        assert!(!state.issuer_has_projected_capability(
            AGENT,
            REALM,
            "ak.message.create",
            REALM,
            now,
        ));
    }

    #[test]
    fn unknown_revoke_is_pending_and_relinquish_is_subject_only() {
        let mut state = ProjectionState::default();
        seed_realm_authority(&mut state);
        let now = chrono::Utc::now();
        let unknown = state.apply_capability_revoke(
            &op(EventKind::CapabilityRevoke, json!({ "grant_id": GRANT_3 })),
            now,
        );
        assert!(matches!(
            unknown,
            crate::reducer::ProjectionEffect::PendingReplayQueued { ref target_ref, .. }
                if target_ref == GRANT_3
        ));
        assert!(
            ProjectionState::capability_grant_cell_ref(GRANT_3)
                .is_some_and(|cell| !state.cells.contains_key(&cell))
        );

        let grant = grant_payload(
            GRANT,
            REALM_OWNER,
            AGENT,
            json!(["ak.message.create"]),
            json!([{ "kind": "realm", "realm_id": REALM }]),
        );
        state.apply_capability_grant(&op(EventKind::CapabilityGrant, grant), now);
        let rejected = state.apply_capability_relinquish(
            &op(
                arkret_wire::EventKind::CapabilityRelinquish,
                json!({ "grant_id": GRANT, "sender": "did:web:mallory.example" }),
            ),
            now,
        );
        assert!(matches!(
            rejected,
            crate::reducer::ProjectionEffect::Rejected { reason }
                if reason == "grant_relinquish_not_subject"
        ));
        let relinquished = state.apply_capability_relinquish(
            &op(
                arkret_wire::EventKind::CapabilityRelinquish,
                json!({ "grant_id": GRANT, "sender": AGENT }),
            ),
            now,
        );
        assert!(matches!(
            relinquished,
            crate::reducer::ProjectionEffect::CapabilityRelinquishProjected { .. }
        ));
        assert!(state.effective_engine_grant(GRANT).unwrap().revoked);
    }
}

#[cfg(test)]
mod authority_cycle_tests {
    use arkret_event_draft::ProjectedEventOperation as Operation;
    use arkret_identifiers::{OperationId, RealmId};
    use serde_json::json;

    use crate::reducer::{ProjectionState, SolandRealmState};

    const REALM: &str = "ak:realm:AfCwsnvdJeIf2T8CEXlUwnunThfVLY8R2SI54sTEapiS";
    const G_A: &str = "ak:grant:AY8nTS0IYFI6o2WxxtlIGtu1bu_J1zcv4KXXmyb5hV1q";
    const G_B: &str = "ak:grant:AVi9st41v9B8lGcU9SB244GCIBji2eJm4HrPJo16jLcS";
    const G_C: &str = "ak:grant:AdWiF-Xct4sJV_hkG8VRIEzHTssfJ4YBilfE98t_Perb";

    /// A re-grant: same `ak.capability.grant` kind as a root issue, with a
    /// `grant` authority ref instead of a `realm_root` one. That ref type is
    /// the only thing that distinguishes the two.
    fn regrant_op(grant_id: &str, authority_grant_id: &str) -> Operation {
        regrant_op_with_constraints(grant_id, authority_grant_id, json!([]))
    }

    fn regrant_op_with_constraints(
        grant_id: &str,
        authority_grant_id: &str,
        constraints: serde_json::Value,
    ) -> Operation {
        const OPERATION_ID: &str = "ak:operation:01970000-0000-7000-8000-0000000000fe";
        arkret_event_draft::test_support::raw_projected_operation(
            OperationId::new(OPERATION_ID).unwrap(),
            RealmId::new(REALM.to_owned()).unwrap(),
            arkret_wire::EventKind::CapabilityGrant.as_str(),
            json!({
                "event_id": arkret_identifiers::EventId::from_token_bytes(
                    arkret_identifiers::GrantId::new(grant_id.to_owned())
                        .expect("fixture grant id")
                        .token_bytes(),
                )
                .expect("fixture grant is Event-derived")
                .to_string(),
                "grant": {
                    "issuer": "did:web:alice.example",
                    "issuer_authority_refs": [
                        { "kind": "grant", "grant_id": authority_grant_id }
                    ],
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
        const OPERATION_ID: &str = "ak:operation:01970000-0000-7000-8000-0000000000fd";
        arkret_event_draft::test_support::raw_projected_operation(
            OperationId::new(OPERATION_ID).unwrap(),
            RealmId::new(REALM.to_owned()).unwrap(),
            arkret_wire::EventKind::CapabilityGrant.as_str(),
            json!({
                "event_id": grant_id.replacen("ak:grant:", "ak:event:", 1),
                "grant": {
                    "issuer": issuer,
                    "issuer_authority_refs": [{
                        "kind": "realm_root",
                        "realm_id": REALM,
                        "cell_ref": "ak:cell:ak.component.realm.authority_root.v1:null",
                        "controller_epoch_at_issuance": 0,
                        "authority_generation": 0
                    }],
                    "subject": subject,
                    "issuer_authority_refs": [{
                        "kind": "realm_root",
                        "realm_id": REALM,
                        "cell_ref": "ak:cell:ak.component.realm.authority_root.v1:null",
                        "controller_epoch_at_issuance": 0,
                        "authority_generation": 0
                    }],
                    "actions": ["ak.message.create"],
                    "resources": [{ "kind": "realm", "realm_id": REALM }],
                    "constraints": constraints,
                }
            }),
        )
    }

    fn seed_realm_owner(state: &mut ProjectionState) {
        let now = chrono::Utc::now();
        crate::reducer::tests::install_realm_authority_root(state, REALM, "did:web:alice.example");
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
        // Project g_b issued under root g_a, so the chain is g_a <- g_b.
        let mut proj = ProjectionState::default();
        seed_realm_owner(&mut proj);
        proj.apply_capability_grant(
            &root_grant_op(G_A, "did:web:alice.example", "did:web:alice.example"),
            chrono::Utc::now(),
        );
        proj.apply_capability_grant(&regrant_op(G_B, G_A), chrono::Utc::now());
        proj
    }

    #[test]
    fn regrant_closing_a_cycle_is_rejected() {
        // g_a issued under g_b would close g_a <- g_b <- g_a.
        let proj = proj_with_chain();
        assert_eq!(
            proj.check_authority_cycle(&regrant_op(G_A, G_B)),
            Err("authority_cycle")
        );
    }

    #[test]
    fn self_referential_authority_is_rejected() {
        let proj = ProjectionState::default();
        assert_eq!(
            proj.check_authority_cycle(&regrant_op(G_A, G_A)),
            Err("authority_cycle")
        );
    }

    #[test]
    fn acyclic_authority_is_allowed() {
        // g_c issued under g_b: chain g_b <- g_c over existing g_a <- g_b.
        let proj = proj_with_chain();
        assert!(proj.check_authority_cycle(&regrant_op(G_C, G_B)).is_ok());
    }

    #[test]
    fn regranted_grant_must_decrement_ref_depth() {
        let mut proj = ProjectionState::default();
        seed_realm_owner(&mut proj);
        proj.apply_capability_grant(
            &root_grant_op_with_constraints(
                G_A,
                "did:web:alice.example",
                "did:web:alice.example",
                json!([{ "constraint_kind": "authority_control", "max_authority_depth": 1 }]),
            ),
            chrono::Utc::now(),
        );
        let rejected = proj.apply_capability_grant(&regrant_op(G_B, G_A), chrono::Utc::now());
        assert!(matches!(
            rejected,
            crate::reducer::ProjectionEffect::Rejected { reason }
                if reason == "authority_depth_exceeded"
        ));

        let allowed = proj.apply_capability_grant(
            &regrant_op_with_constraints(
                G_C,
                G_A,
                json!([{ "constraint_kind": "authority_control", "max_authority_depth": 0 }]),
            ),
            chrono::Utc::now(),
        );
        assert!(matches!(
            allowed,
            crate::reducer::ProjectionEffect::CapabilityGrantProjected { .. }
        ));
    }

    #[test]
    fn regrant_derives_parent_audit_after_sealed_cell_reload() {
        let mut proj = ProjectionState::default();
        seed_realm_owner(&mut proj);
        assert!(matches!(
            proj.apply_capability_grant(
                &root_grant_op_with_constraints(
                    G_A,
                    "did:web:alice.example",
                    "did:web:alice.example",
                    json!([{ "constraint_kind": "authority_control", "max_authority_depth": 1 }]),
                ),
                chrono::Utc::now(),
            ),
            crate::reducer::ProjectionEffect::CapabilityGrantProjected { .. }
        ));

        // CellStore persists the registry-projected producer body; simulate
        // the authoritative reload that replaces the live enriched cache.
        let parent_cell = ProjectionState::capability_grant_cell_ref(G_A).unwrap();
        let arkret_state::lattice::CellState::Value(serde_json::Value::Array(items)) =
            proj.cells.get_mut(&parent_cell).unwrap()
        else {
            panic!("capability parent cell must be an or_set");
        };
        for item in items {
            let body = if item.get("value").is_some() {
                item.get_mut("value").unwrap()
            } else {
                item
            };
            body.as_object_mut().unwrap().remove("authority_depth");
            body.as_object_mut().unwrap().remove("authority_root_refs");
        }

        let parent = proj.effective_engine_grant(G_A).unwrap();
        assert_eq!(parent.authority_depth, Some(1));
        assert_eq!(parent.authority_root_refs.len(), 1);
        let child = proj.apply_capability_grant(
            &regrant_op_with_constraints(
                G_C,
                G_A,
                json!([{ "constraint_kind": "authority_control", "max_authority_depth": 0 }]),
            ),
            chrono::Utc::now(),
        );
        assert!(matches!(
            child,
            crate::reducer::ProjectionEffect::CapabilityGrantProjected { .. }
        ));
        let child = proj.effective_engine_grant(G_C).unwrap();
        assert_eq!(child.authority_depth, Some(2));
        assert_eq!(child.authority_root_refs.len(), 1);
    }

    #[test]
    fn regranted_grant_rejects_when_ref_depth_exhausted() {
        let mut proj = ProjectionState::default();
        seed_realm_owner(&mut proj);
        proj.apply_capability_grant(
            &root_grant_op_with_constraints(
                G_A,
                "did:web:alice.example",
                "did:web:alice.example",
                json!([{ "constraint_kind": "authority_control", "max_authority_depth": 0 }]),
            ),
            chrono::Utc::now(),
        );
        let rejected = proj.apply_capability_grant(
            &regrant_op_with_constraints(
                G_B,
                G_A,
                json!([{ "constraint_kind": "authority_control", "max_authority_depth": 0 }]),
            ),
            chrono::Utc::now(),
        );
        assert!(matches!(
            rejected,
            crate::reducer::ProjectionEffect::Rejected { reason }
                if reason == "authority_depth_exceeded"
        ));
    }
}

#[cfg(test)]
mod federation_revoke_fanout_tests {
    use arkret_event_draft::ProjectedEventOperation as Operation;
    use arkret_identifiers::{OperationId, RealmId};
    use serde_json::json;

    use crate::reducer::{ProjectionEffect, ProjectionState, SolandRealmState};

    const REALM: &str = "ak:realm:AfCwsnvdJeIf2T8CEXlUwnunThfVLY8R2SI54sTEapiS";
    const OTHER_REALM: &str = "ak:realm:ARib7U2kHFo1ErdwrDDP0057R6D3jtBM74RcEz4Pw4Jy";
    const OWNER: &str = "did:web:alice.example";
    const PEER_SERVICE_ID: &str = "did:web:beta.example";
    const GRANT: &str = "ak:grant:AZqtjPe_dBMbCiO1AaO3pl249mYTX42jAeK7WbxsUOP_";
    const OWNER_GRANT: &str = "ak:grant:AftcsV-S3Qgkuf_flS2xTzy_TzSq42hZip4BUCG8D6qv";

    fn capability_op(
        operation_id: &str,
        kind: impl AsRef<str>,
        mut payload: serde_json::Value,
    ) -> Operation {
        let object = payload.as_object_mut().expect("test payload object");
        object
            .entry("sender".to_owned())
            .or_insert_with(|| serde_json::Value::String(OWNER.to_owned()));
        object.entry("event_id".to_owned()).or_insert_with(|| {
            serde_json::Value::String(super::fixture_event_id_for_operation(operation_id))
        });
        arkret_event_draft::test_support::raw_projected_operation(
            OperationId::new(operation_id.to_owned()).unwrap(),
            RealmId::new(REALM.to_owned()).unwrap(),
            kind.as_ref(),
            payload,
        )
    }

    fn seed_realm_authority(state: &mut ProjectionState) {
        let now = chrono::Utc::now();
        crate::reducer::tests::install_realm_authority_root(state, REALM, OWNER);
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
        let registry_digest = arkret_policy::current_capability_action_registry_digest()
            .expect("embedded capability action registry");
        let owner_grant = capability_op(
            "ak:operation:01970000-0000-7000-8000-0000000000a0",
            arkret_wire::EventKind::CapabilityGrant,
            json!({
                "event_id": OWNER_GRANT.replacen("ak:grant:", "ak:event:", 1),
                "grant": {
                    "schema": arkret_wire::SchemaId::CAPABILITY_V1,
                    "realm_id": REALM,
                    "issuer": OWNER,
                    "issuer_authority_refs": [{
                        "kind": "realm_root",
                        "realm_id": REALM,
                        "cell_ref": "ak:cell:ak.component.realm.authority_root.v1:null",
                        "controller_epoch_at_issuance": 0,
                        "authority_generation": 0
                    }],
                    "subject": OWNER,
                    "actions": ["ak.realm.admin"],
                    "capability_action_registry_digest": registry_digest,
                    "resources": [{ "kind": "realm", "realm_id": REALM }],
                }
            }),
        );
        assert!(matches!(
            state.apply_capability_grant(&owner_grant, now),
            ProjectionEffect::CapabilityGrantProjected { .. }
        ));
    }

    fn delivery_binding_grant_payload() -> serde_json::Value {
        let registry_digest = arkret_policy::current_capability_action_registry_digest()
            .expect("embedded capability action registry");
        json!({
            "event_id": GRANT.replacen("ak:grant:", "ak:event:", 1),
            "grant": {
                "schema": arkret_wire::SchemaId::CAPABILITY_V1,
                "realm_id": REALM,
                "issuer": OWNER,
                "issuer_authority_refs": [{
                    "kind": "realm_root",
                    "realm_id": REALM,
                    "cell_ref": "ak:cell:ak.component.realm.authority_root.v1:null",
                    "controller_epoch_at_issuance": 0,
                    "authority_generation": 0
                }],
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
        seed_realm_authority(&mut state);
        let now = chrono::Utc::now();

        // Before any grant: nothing revoked.
        assert!(state.federation_delivery_revoked_peers(REALM).is_empty());

        // Grant β's federation delivery binding service delegation. An active
        // grant MUST NOT appear in the revoked set.
        let effect = state.apply_capability_grant(
            &capability_op(
                "ak:operation:01970000-0000-7000-8000-0000000000a1",
                arkret_wire::EventKind::CapabilityGrant,
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
                arkret_wire::EventKind::CapabilityRevoke,
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

/// Regression suite for the Realm owner aggregate (`capabilities.md` §3.2).
///
/// Genesis registers an authority-root cell and nothing else; its controller
/// holds effective `ak.realm.owner`. These cases pin the boundaries of what
/// that does and does not confer, because every one of them is a place where a
/// plausible-looking widening silently hands out authority nobody granted.
#[cfg(test)]
mod realm_owner_authority_tests {
    use arkret_event_draft::ProjectedEventOperation as Operation;
    use arkret_identifiers::{OperationId, RealmId};
    use arkret_wire::CapabilityActionId;
    use serde_json::json;

    use crate::reducer::{ProjectionEffect, ProjectionState, SolandRealmState};

    const REALM: &str = "ak:realm:ATKefSdBA52dfl_b0kwuiBO-JG0nPTlnS_bXWGh3Z57K";
    const OWNER: &str = "did:web:owner.example";
    const CO_OWNER: &str = "did:web:co-owner.example";
    const STRANGER: &str = "did:web:stranger.example";

    fn grant_op(
        operation_slot: &str,
        grant_id: &str,
        issuer: &str,
        subject: &str,
        actions: serde_json::Value,
    ) -> Operation {
        let operation_id =
            format!("ak:operation:01980000-0000-7000-8000-0000000000{operation_slot}");
        arkret_event_draft::test_support::raw_projected_operation(
            OperationId::new(operation_id.clone()).unwrap(),
            RealmId::new(REALM.to_owned()).unwrap(),
            arkret_wire::EventKind::CapabilityGrant.as_str(),
            json!({
                "event_id": grant_id.replacen("ak:grant:", "ak:event:", 1),
                "grant": {
                    "schema": arkret_wire::SchemaId::CAPABILITY_V1,
                    "realm_id": REALM,
                    "issuer": issuer,
                    "issuer_authority_refs": [{
                        "kind": "realm_root",
                        "realm_id": REALM,
                        "cell_ref": "ak:cell:ak.component.realm.authority_root.v1:null",
                        "controller_epoch_at_issuance": 0,
                        "authority_generation": 0
                    }],
                    "subject": subject,
                    "actions": actions,
                    "capability_action_registry_digest":
                        arkret_policy::current_capability_action_registry_digest().unwrap(),
                    "resources": [{
                        "kind": "realm",
                        "realm_id": REALM,
                        "match_scope": "realm_wide"
                    }],
                    "issued_at": "2026-01-01T00:00:00.000Z",
                }
            }),
        )
    }

    fn grant_id(slot: &str) -> String {
        let operation_id = format!("ak:operation:01980000-0000-7000-8000-0000000000{slot}");
        let event_id =
            arkret_identifiers::EventId::new(super::fixture_event_id_for_operation(&operation_id))
                .expect("fixture event id");
        arkret_identifiers::GrantId::from_event_id(&event_id).to_string()
    }

    /// A Realm whose `realm_states` mirror names `mirror_owner` but whose
    /// authority root is controlled by `controller` (when supplied).
    fn realm(controller: Option<&str>, mirror_owner: Option<&str>) -> ProjectionState {
        let mut state = ProjectionState::default();
        let now = chrono::Utc::now();
        state.realm_states.insert(
            REALM.to_owned(),
            SolandRealmState {
                realm_id: REALM.to_owned(),
                owner: mirror_owner.map(ToOwned::to_owned),
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
        if let Some(controller) = controller {
            crate::reducer::tests::install_realm_authority_root(&mut state, REALM, controller);
        }
        state
    }

    fn declare_profiles(state: &mut ProjectionState, profiles: &[&str]) {
        state.realm_null_subject_cells.insert(
            (REALM.to_owned(), arkret_wire::REALM_GENESIS_CELL.to_owned()),
            arkret_state::lattice::CellState::Value(json!({
                "schema_refs": profiles,
            })),
        );
    }

    fn issue(state: &mut ProjectionState, operation: &Operation) -> ProjectionEffect {
        let mut operation = operation.clone();
        let issuer = super::grant_issuer(&operation.payload).unwrap_or_default();
        let current_controller = state
            .realm_authority_root(REALM)
            .map(|root| root.controller_id.to_string());
        if current_controller.as_deref() != Some(issuer.as_str())
            && let Some(parent) = state
                .projected_capability_grants()
                .find(|grant| grant.subject == issuer && !grant.revoked)
        {
            operation.payload["grant"]["issuer_authority_refs"] = serde_json::json!([{
                "kind": "grant",
                "grant_id": parent.grant_id,
            }]);
        }
        state.apply_capability_grant(&operation, chrono::Utc::now())
    }

    fn projected(effect: &ProjectionEffect) -> bool {
        matches!(effect, ProjectionEffect::CapabilityGrantProjected { .. })
    }

    fn rejected_reason(effect: &ProjectionEffect) -> Option<&str> {
        match effect {
            ProjectionEffect::Rejected { reason } => Some(reason.as_str()),
            _ => None,
        }
    }

    #[test]
    fn only_the_authority_root_controller_is_the_owner() {
        // A forged `realm_states[..].owner` is a discardable presentation
        // mirror. It never authorizes anything; only the registered cell does.
        let forged = realm(None, Some(OWNER));
        assert!(!forged.actor_holds_effective_realm_owner(REALM, OWNER, chrono::Utc::now()));
        assert!(!forged.actor_governs_realm(REALM, OWNER, &["ak.realm.admin"], chrono::Utc::now()));

        let rooted = realm(Some(OWNER), Some(STRANGER));
        assert!(rooted.actor_holds_effective_realm_owner(REALM, OWNER, chrono::Utc::now()));
        assert!(!rooted.actor_holds_effective_realm_owner(REALM, STRANGER, chrono::Utc::now()));
    }

    #[test]
    fn authority_root_owner_has_only_registered_operational_coverage() {
        let rooted = realm(Some(OWNER), None);
        let now = chrono::Utc::now();
        assert!(rooted.realm_owner_operationally_covers_action(
            REALM,
            OWNER,
            "ak.invite.create",
            now
        ));
        assert!(rooted.realm_owner_operationally_covers_action(
            REALM,
            OWNER,
            "ak.realm.profile",
            now
        ));
        assert!(!rooted.realm_owner_operationally_covers_action(
            REALM,
            OWNER,
            "ak.audit.export",
            now
        ));
        assert!(!rooted.realm_owner_operationally_covers_action(
            REALM,
            OWNER,
            "ak.realm.destroy",
            now
        ));
        assert!(!rooted.realm_owner_operationally_covers_action(
            REALM,
            STRANGER,
            "ak.invite.create",
            now
        ));
    }

    #[test]
    fn owner_signs_the_core_actions_its_grant_authority_set_names() {
        let mut state = realm(Some(OWNER), None);
        // An Event-plane action, a non-Event surface, a key-distribution
        // action, and the aggregate itself: all four are owner-grantable.
        for (slot, action) in [
            ("a1", "ak.strand.create"),
            ("a2", "ak.strand.admin"),
            ("a3", "ak.audit.export"),
            ("a4", "ak.realm_key.share"),
        ] {
            let id = grant_id(slot);
            let effect = issue(
                &mut state,
                &grant_op(slot, &id, OWNER, OWNER, json!([action])),
            );
            assert!(projected(&effect), "owner must sign {action}: {effect:?}");
            // ...and the literal grant it just signed is then usable.
            assert!(
                state.issuer_holds_literal_capability(
                    OWNER,
                    REALM,
                    action,
                    REALM,
                    chrono::Utc::now()
                ),
                "{action} must be held verbatim after issuance"
            );
        }
    }

    #[test]
    fn owner_may_issue_calendar_rsvp_only_when_calendar_profile_is_declared() {
        let now = chrono::Utc::now();
        let mut calendar = realm(Some(OWNER), None);
        declare_profiles(
            &mut calendar,
            &["ak.schema.realm.v1", "ak.profile.calendar_event.v1"],
        );
        assert!(calendar.owner_may_issue_grant_for(
            OWNER,
            REALM,
            CapabilityActionId::RSVP_SET,
            now,
        ));

        let mut unrelated = realm(Some(OWNER), None);
        declare_profiles(
            &mut unrelated,
            &["ak.profile.calendar_notification_dispatch.v1"],
        );
        assert!(!unrelated.owner_may_issue_grant_for(
            OWNER,
            REALM,
            CapabilityActionId::RSVP_SET,
            now,
        ));

        let absent = realm(Some(OWNER), None);
        assert!(
            !absent.owner_may_issue_grant_for(OWNER, REALM, CapabilityActionId::RSVP_SET, now,)
        );
    }

    #[test]
    fn owner_appoints_a_co_owner_who_is_then_an_owner_too() {
        let mut state = realm(Some(OWNER), None);
        let id = grant_id("b1");
        let effect = issue(
            &mut state,
            &grant_op("b1", &id, OWNER, CO_OWNER, json!(["ak.realm.owner"])),
        );
        assert!(
            projected(&effect),
            "owner may appoint a co-owner: {effect:?}"
        );
        assert!(state.actor_holds_effective_realm_owner(REALM, CO_OWNER, chrono::Utc::now()));

        // The co-owner's authority is the same aggregate, so it can sign on.
        let regranted = grant_id("b2");
        assert!(projected(&issue(
            &mut state,
            &grant_op(
                "b2",
                &regranted,
                CO_OWNER,
                STRANGER,
                json!(["ak.strand.create"])
            ),
        )));
    }

    #[test]
    fn owner_never_reaches_the_two_root_control_only_actions() {
        let state = realm(Some(OWNER), None);
        let basis = state.realm_authority_registry_basis(REALM);
        for action in ["ak.realm.destroy", "ak.realm.tombstone"] {
            assert!(
                !arkret_policy::owner_may_grant(action, basis.as_ref(), &[]).unwrap(),
                "{action} is root_control_only and is not owner-grantable"
            );
            assert!(
                !arkret_policy::action_covers_event_kinds(CapabilityActionId::REALM_OWNER, action)
                    .unwrap(),
                "{action} is outside the owner aggregate's operational coverage"
            );
        }
    }

    #[test]
    fn realm_admin_alone_cannot_sign_out_strand_create() {
        // `ak.realm.admin` is an aggregate, but `ak.strand.create` is in
        // neither its coverage set nor its grant-authority set.
        let mut state = realm(Some(OWNER), None);
        let admin = grant_id("c1");
        assert!(projected(&issue(
            &mut state,
            &grant_op("c1", &admin, OWNER, STRANGER, json!(["ak.realm.admin"])),
        )));
        let escalation = grant_id("c2");
        let effect = issue(
            &mut state,
            &grant_op(
                "c2",
                &escalation,
                STRANGER,
                STRANGER,
                json!(["ak.strand.create"]),
            ),
        );
        assert_eq!(
            rejected_reason(&effect),
            Some("grant_exceeds_issuer_authority")
        );
    }

    #[test]
    fn capability_grant_alone_signs_out_nothing() {
        // Holding the grant *verb* is not holding any authority to grant.
        let mut state = realm(Some(OWNER), None);
        let granter = grant_id("d1");
        assert!(projected(&issue(
            &mut state,
            &grant_op(
                "d1",
                &granter,
                OWNER,
                STRANGER,
                json!(["ak.capability.grant"])
            ),
        )));
        for (slot, action) in [("d2", "ak.strand.create"), ("d3", "ak.realm.admin")] {
            let id = grant_id(slot);
            let effect = issue(
                &mut state,
                &grant_op(slot, &id, STRANGER, STRANGER, json!([action])),
            );
            assert_eq!(
                rejected_reason(&effect),
                Some("grant_exceeds_issuer_authority"),
                "ak.capability.grant must not confer authority over {action}"
            );
        }
    }

    #[test]
    fn a_non_event_child_is_not_satisfied_by_operational_coverage() {
        // `ak.audit.export` has an empty `target_event_kinds`; without the
        // empty-set guard every aggregate would vacuously "cover" it.
        assert!(
            !arkret_policy::action_covers_event_kinds(
                CapabilityActionId::REALM_OWNER,
                "ak.audit.export"
            )
            .unwrap()
        );
        let mut state = realm(Some(OWNER), None);
        let owner_grant = grant_id("e1");
        let owner_issue = issue(
            &mut state,
            &grant_op(
                "e1",
                &owner_grant,
                OWNER,
                CO_OWNER,
                json!(["ak.realm.owner"]),
            ),
        );
        assert!(
            projected(&owner_issue),
            "owner grant failed: {owner_issue:?}"
        );
        // The co-owner holds the aggregate, but not the non-Event surface it
        // does not cover.
        assert!(!state.issuer_has_projected_capability(
            CO_OWNER,
            REALM,
            "ak.audit.export",
            REALM,
            chrono::Utc::now()
        ));
        assert!(state.issuer_has_projected_capability(
            CO_OWNER,
            REALM,
            "ak.strand.create",
            REALM,
            chrono::Utc::now()
        ));
    }

    #[test]
    fn same_target_event_kind_does_not_confer_grant_authority() {
        // `ak.agent.sidecar.write` and `ak.message.create` both target
        // `ak.message.create`, so the owner aggregate *covers* the sidecar
        // action operationally - but the issuer upper bound is answered over
        // action ids, and the profile-gated action is not in the owner's
        // grant-authority set.
        assert!(
            arkret_policy::action_covers_event_kinds(
                CapabilityActionId::REALM_OWNER,
                "ak.agent.sidecar.write"
            )
            .unwrap()
        );
        let mut state = realm(Some(OWNER), None);
        let id = grant_id("f1");
        let effect = issue(
            &mut state,
            &grant_op(
                "f1",
                &id,
                OWNER,
                STRANGER,
                json!(["ak.agent.sidecar.write"]),
            ),
        );
        assert_eq!(
            rejected_reason(&effect),
            Some("grant_exceeds_issuer_authority"),
            "no active profile registers ak.agent.sidecar.write as owner-grantable"
        );
    }

    #[test]
    fn aggregate_expansion_requires_the_grants_own_registry_basis() {
        // A grant that names no registry snapshot cannot be re-read through
        // the aggregate: the expansion fails closed rather than falling back
        // to the receiver's embedded registry.
        let mut state = realm(Some(OWNER), None);
        let id = grant_id("9a");
        let mut unanchored = grant_op("9a", &id, OWNER, CO_OWNER, json!(["ak.realm.owner"]));
        unanchored
            .payload
            .get_mut("grant")
            .and_then(serde_json::Value::as_object_mut)
            .unwrap()
            .remove("capability_action_registry_digest");
        // The grant body itself is refused, so nothing enters the index.
        assert_eq!(
            rejected_reason(&issue(&mut state, &unanchored)),
            Some("capability_registry_basis_unavailable")
        );
        assert!(!state.actor_holds_effective_realm_owner(REALM, CO_OWNER, chrono::Utc::now()));
    }
}
