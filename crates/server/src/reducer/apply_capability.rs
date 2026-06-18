//! P1 — capability control-plane projection.
//!
//! Projects `ck.capability.grant` / `ck.capability.revoke` /
//! `ck.capability.delegate` into the canonical cells declared by
//! `event-kind-registry.json`:
//!
//! - grant / revoke → `ck.component.capability.grant.v1` (or_set, one cell per `payload.grant_id`).
//! - delegate → `ck.component.capability.delegate.v1` (or_set, one cell per `payload.grant_id`)
//!   plus a `parent_grant_id` chain reference.
//!
//! Convergence rules (capabilities.md §12.1):
//! - **grant** = or_set **add**. The add dot is the reducer-deterministic
//!   `ck:operation:<operation_id>` (the soland reducer's per-event handle; the spec's
//!   `ck:event:<event_id>:<effect_index>` is the wire form). value = the canonical grant snapshot.
//! - **revoke** = or_set **observed-remove** on the *same* grant cell. We mark the surviving add(s)
//!   `revoked` (the read path filters `revoked*`). Terminal: a later re-add of the same `grant_id`
//!   MUST NOT revive a removed add — once a cell holds a revoked entry for the grant, every add
//!   carries the revoked tombstone forward.
//! - `bottom` is **inert** for or_set: we never produce a Bottom cell here.
//!
//! Acceptance / fail-closed: the envelope-level `seal_basis` discipline
//! (`oneOf(seal_ref+auth_context XOR seal_basis)` for reducer-input control
//! kinds) is enforced at event ingest (event-envelope schema, CBA §5 /
//! v0.3.1 audit #12); the reducer trusts that gate and does the *structural*
//! acceptance checks reachable at the `Operation` boundary — a present
//! `grant_id`, a parseable issuer, and (for grant) a non-empty grant body.
//! Missing structural inputs ⇒ `Rejected` (P3 fail-closed), never a silent
//! no-op. This mirrors `apply_capability_derived`, which likewise validates
//! structure/causality against projected cells rather than re-running the
//! Seal acceptance judgment.

use super::*;

/// Map a cell grant body's resource selectors to the engine `Grant`'s single
/// `resource` String.
/// Precedence: an explicit string selector / `id` wins; a realm-kind
/// selector resolves to its `id` (or the grant's realm); everything else
/// (wildcard / empty) falls back to `*` so the grant is not silently
/// narrowed out of the index.
fn engine_resource_from_body(body: &Value, realm_id: &str) -> String {
    let mut selectors = value_array_field(body, "resources");
    selectors.extend(value_array_field(body, "resource_selectors"));
    for selector in &selectors {
        match selector {
            Value::String(s) if !s.is_empty() => return s.clone(),
            Value::Object(_) => {
                if let Some(id) = selector.get("id").and_then(Value::as_str) {
                    if !id.is_empty() {
                        return id.to_owned();
                    }
                }
                match selector.get("kind").and_then(Value::as_str) {
                    Some("*") => return "*".to_owned(),
                    Some("realm") => return realm_id.to_owned(),
                    _ => {}
                }
            }
            _ => {}
        }
    }
    "*".to_owned()
}

/// Build an engine-shaped `Grant` from a projected grant cell body. Returns
/// `None` only when the body has no actions (a grant with no actions cannot
/// authorize anything and must not enter the index).
fn engine_grant_from_cell_body(
    grant_id: &str,
    body: &Value,
    revoked: bool,
) -> Option<crate::authz::Grant> {
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
    let constraints = value_array_field(body, "constraints")
        .into_iter()
        .filter_map(|c| serde_json::from_value(c).ok())
        .collect();
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
    Some(crate::authz::Grant {
        grant_id: grant_id.to_owned(),
        realm_id,
        issuer,
        subject,
        resource,
        actions,
        constraints,
        revoked,
        created_at,
        delegated_from,
        expires_at,
    })
}

/// or_set add dot for a capability event. Deterministic per accepted event.
fn capability_add_dot(operation: &Operation) -> String {
    operation.operation_id.to_string()
}

/// Pull the canonical grant body out of a `ck.capability.grant` /
/// `ck.capability.delegate` payload. Accepts both the canonical wrapper
/// `{grant_id, grant: {…}}` (SDK `CapabilityGrantBuilder`) and a flat
/// payload that already *is* the grant body.
fn grant_body<'a>(payload: &'a Value) -> &'a Value {
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
            map.entry("revoked_at".to_owned())
                .or_insert_with(|| Value::String(now.to_rfc3339()));
        }
    }
    body
}

impl ProjectionState {
    fn capability_grant_cell_ref(grant_id: &str) -> Option<CellRef> {
        CellRef::new(format!(
            "ck:cell:ck.component.capability.grant.v1:{grant_id}"
        ))
        .ok()
    }

    fn capability_delegate_cell_ref(grant_id: &str) -> Option<CellRef> {
        CellRef::new(format!(
            "ck:cell:ck.component.capability.delegate.v1:{grant_id}"
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
    pub fn effective_engine_grant(&self, grant_id: &str) -> Option<crate::authz::Grant> {
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
        // CKP-0008 §4.3.2 / §4.9 — fail closed: a grant still carrying
        // `effective_after_first_authorized_key == true` is durable but
        // inactive (the agent has not completed runtime pairing). The reducer
        // clears this flag in `apply_agent_key_authorize` once an accepted
        // `ck.agent.key.authorize` lands, after which the grant enters the
        // engine read index. Until then it MUST NOT authorize anything.
        if body
            .get("effective_after_first_authorized_key")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
            return None;
        }
        engine_grant_from_cell_body(grant_id, body, revoked)
    }

    /// P1 — project `ck.capability.grant` as an or_set add on the grant cell.
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

    /// P1 — project `ck.capability.revoke` as an or_set observed-remove on the
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
        let revoked_at = now.to_rfc3339();
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

    /// P1 — project `ck.capability.delegate` into the delegate or_set cell.
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
    /// `ck.capability.delegate(child_grant_id, parent_grant_id)`; reject the
    /// whole delegation with `delegation_cycle` if the new child closes a cycle
    /// (appears as one of its own ancestors) or the chain already contains one.
    /// A `delegation_cycle` MUST NOT project even if each grant looks valid
    /// individually. Runs at ingest (pre-commit) so the cyclic edge never enters
    /// the delegate cell / authz index.
    pub fn check_delegation_cycle(&self, operation: &Operation) -> Result<(), &'static str> {
        if crate::kinds::canonical_kind_for_operation(operation)
            != Some(crate::kinds::CK_CAPABILITY_DELEGATE)
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

    /// CKP-0008 §4.5 / D3 — project `ck.agent.key.authorize`: record the
    /// authorized key for the agent and clear
    /// `effective_after_first_authorized_key` on every pending capability
    /// grant the agent holds (§4.3.2 — pairing completion activates the
    /// inactive provisioning grants). Idempotent: a re-authorization of the
    /// same key id converges, and grants already cleared stay cleared.
    pub(crate) fn apply_agent_key_authorize(&mut self, operation: &Operation) -> ProjectionEffect {
        let Some(agent_principal_id) = operation
            .payload
            .get("agent_principal_id")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
        else {
            return ProjectionEffect::Rejected {
                reason: "agent_key_authorize_missing_agent_principal_id".to_owned(),
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
        self.agent_authorized_keys
            .entry(agent_principal_id.clone())
            .or_default()
            .insert(key_id.clone());
        let cleared_grant_ids = self.clear_pending_grant_flags_for(&agent_principal_id);
        ProjectionEffect::AgentKeyAuthorizeProjected {
            agent_principal_id,
            key_id,
            cleared_grant_ids,
        }
    }

    /// CKP-0008 §4.11 — project `ck.agent.key.revoke`: remove the key from
    /// the agent's authorized-key set (idempotent).
    pub(crate) fn apply_agent_key_revoke(&mut self, operation: &Operation) -> ProjectionEffect {
        let Some(agent_principal_id) = operation
            .payload
            .get("agent_principal_id")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
        else {
            return ProjectionEffect::Rejected {
                reason: "agent_key_revoke_missing_agent_principal_id".to_owned(),
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
        if let Some(keys) = self.agent_authorized_keys.get_mut(&agent_principal_id) {
            keys.remove(&key_id);
            if keys.is_empty() {
                self.agent_authorized_keys.remove(&agent_principal_id);
            }
        }
        ProjectionEffect::AgentKeyRevokeProjected {
            agent_principal_id,
            key_id,
        }
    }

    /// CKP-0008 §4.11 — every grant id whose subject is `subject_did`
    /// (across all capability grant cells, including revoked ones so the
    /// deactivate fan-out can idempotently re-revoke). Used by the lifecycle
    /// deactivate path to fan-out `ck.capability.revoke`.
    pub fn grant_ids_for_subject(&self, subject_did: &str) -> Vec<String> {
        let cell_prefix = "ck:cell:ck.component.capability.grant.v1:";
        let mut ids = Vec::new();
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
                if subject_matches {
                    if let Some(grant_id) = body
                        .get("grant_id")
                        .or_else(|| body.get("id"))
                        .and_then(Value::as_str)
                    {
                        if !ids.iter().any(|existing| existing == grant_id) {
                            ids.push(grant_id.to_owned());
                        }
                    }
                }
            }
        }
        ids
    }

    /// CKP-0008 §4.11 — the authorized key ids the agent currently holds
    /// (for the deactivate `ck.agent.key.revoke` fan-out).
    pub fn authorized_key_ids_for(&self, agent_principal_id: &str) -> Vec<String> {
        self.agent_authorized_keys
            .get(agent_principal_id)
            .map(|keys| keys.iter().cloned().collect())
            .unwrap_or_default()
    }

    /// True when the agent principal has at least one accepted, non-revoked
    /// agent key authorization. The capability evaluator fail-closes
    /// `effective_after_first_authorized_key` grants until this is true.
    pub fn agent_has_authorized_key(&self, agent_principal_id: &str) -> bool {
        self.agent_authorized_keys
            .get(agent_principal_id)
            .map(|keys| !keys.is_empty())
            .unwrap_or(false)
    }

    /// Clear `effective_after_first_authorized_key` on every capability grant
    /// cell whose subject is `agent_principal_id`. Returns the grant ids that
    /// were flipped from inactive to active.
    fn clear_pending_grant_flags_for(&mut self, agent_principal_id: &str) -> Vec<String> {
        let mut cleared = Vec::new();
        let cell_prefix = "ck:cell:ck.component.capability.grant.v1:";
        let target_refs: Vec<CellRef> = self
            .cells
            .keys()
            .filter(|cell_ref| cell_ref.as_str().starts_with(cell_prefix))
            .cloned()
            .collect();
        for cell_ref in target_refs {
            let CellState::Value(Value::Array(items)) = self.cells.get(&cell_ref).cloned().unwrap()
            else {
                continue;
            };
            let mut mutated = false;
            let mut grant_id_for_cell = None;
            let new_items: Vec<Value> = items
                .into_iter()
                .map(|mut item| {
                    let body = if item.get("value").is_some() {
                        item.get_mut("value")
                    } else {
                        Some(&mut item)
                    };
                    if let Some(Value::Object(map)) = body {
                        let subject_matches = map
                            .get("subject")
                            .and_then(Value::as_str)
                            .map(|subject| subject == agent_principal_id)
                            .unwrap_or(false);
                        if subject_matches {
                            grant_id_for_cell = map
                                .get("grant_id")
                                .or_else(|| map.get("id"))
                                .and_then(Value::as_str)
                                .map(ToOwned::to_owned);
                            if map
                                .get("effective_after_first_authorized_key")
                                .and_then(Value::as_bool)
                                .unwrap_or(false)
                            {
                                map.insert(
                                    "effective_after_first_authorized_key".to_owned(),
                                    Value::Bool(false),
                                );
                                mutated = true;
                            }
                        }
                    }
                    item
                })
                .collect();
            if mutated {
                self.cells
                    .insert(cell_ref, CellState::Value(Value::Array(new_items)));
                if let Some(grant_id) = grant_id_for_cell {
                    cleared.push(grant_id);
                }
            }
        }
        cleared
    }
}

#[cfg(test)]
mod agent_key_flag_tests {
    use cokret_sdk::models::{Operation, OperationType};
    use cokret_sdk::{OperationId, RealmId};
    use serde_json::json;

    use crate::reducer::ProjectionState;

    const AGENT: &str = "did:web:agent.example";
    const REALM: &str = "ck:realm:01970000-0000-7000-8000-000000000000";
    const GRANT: &str = "ck:grant:01970000-0000-7000-8000-0000000000a1";

    fn op(kind_object_type: &str, payload: serde_json::Value) -> Operation {
        Operation {
            schema: "ck.schema.operation.v1".to_owned(),
            operation_id: OperationId::new("ck:operation:01970000-0000-7000-8000-0000000000ff")
                .unwrap(),
            record_type: "operation".to_owned(),
            operation_type: OperationType::Create,
            realm_id: RealmId::new(REALM.to_owned()).unwrap(),
            object_id: None,
            object_type: kind_object_type.to_owned(),
            payload,
            idempotency_key: None,
            created_at: chrono::Utc::now(),
        }
    }

    fn pending_grant_payload() -> serde_json::Value {
        json!({
            "grant_id": GRANT,
            "grant": {
                "id": GRANT,
                "schema": "ck.schema.capability_grant.v1",
                "realm_id": REALM,
                "issuer": "did:web:alice.example",
                "subject": AGENT,
                "actions": ["ck.message.create"],
                "resources": [{ "kind": "realm", "realm_id": REALM }],
                "effective_after_first_authorized_key": true,
            }
        })
    }

    #[test]
    fn pending_grant_is_fail_closed_until_key_authorize() {
        let mut state = ProjectionState::default();
        let now = chrono::Utc::now();
        // Pending grant: flagged inactive ⇒ NOT in the engine index.
        state.apply_capability_grant(&op("capability_grant", pending_grant_payload()), now);
        assert!(
            state.effective_engine_grant(GRANT).is_none(),
            "effective_after_first_authorized_key grant MUST fail closed before pairing"
        );
        assert!(!state.agent_has_authorized_key(AGENT));
        assert_eq!(state.grant_ids_for_subject(AGENT), vec![GRANT.to_owned()]);

        // Pairing: ck.agent.key.authorize clears the flag for the agent.
        let effect = state.apply_agent_key_authorize(&op(
            "agent_key_authorize",
            json!({ "agent_principal_id": AGENT, "key_id": "ck:agent_key:dev1" }),
        ));
        match effect {
            crate::reducer::ProjectionEffect::AgentKeyAuthorizeProjected {
                cleared_grant_ids,
                ..
            } => assert_eq!(cleared_grant_ids, vec![GRANT.to_owned()]),
            other => panic!("expected AgentKeyAuthorizeProjected, got {other:?}"),
        }
        assert!(state.agent_has_authorized_key(AGENT));
        let grant = state
            .effective_engine_grant(GRANT)
            .expect("grant active after pairing");
        assert_eq!(grant.subject, AGENT);
        assert!(grant.actions.iter().any(|a| a == "ck.message.create"));

        // Revoking the key removes the authorized-key marker.
        state.apply_agent_key_revoke(&op(
            "agent_key_revoke",
            json!({ "agent_principal_id": AGENT, "key_id": "ck:agent_key:dev1" }),
        ));
        assert!(!state.agent_has_authorized_key(AGENT));
    }
}

#[cfg(test)]
mod delegation_cycle_tests {
    use cokret_sdk::{Operation, OperationId, RealmId};
    use serde_json::json;

    use crate::reducer::ProjectionState;

    const REALM: &str = "ck:realm:01970000-0000-7000-8000-000000000000";
    const G_A: &str = "ck:grant:01970000-0000-7000-8000-00000000a001";
    const G_B: &str = "ck:grant:01970000-0000-7000-8000-00000000b002";
    const G_C: &str = "ck:grant:01970000-0000-7000-8000-00000000c003";

    fn delegate_op(grant_id: &str, parent_grant_id: &str) -> Operation {
        Operation::create(
            OperationId::new("ck:operation:01970000-0000-7000-8000-0000000000fe").unwrap(),
            RealmId::new(REALM.to_owned()).unwrap(),
            crate::kinds::CK_CAPABILITY_DELEGATE,
            json!({
                "grant_id": grant_id,
                "grant": {
                    "issuer": "did:web:alice.example",
                    "parent_grant_id": parent_grant_id,
                }
            }),
        )
    }

    fn proj_with_chain() -> ProjectionState {
        // Project g_b delegated from root g_a, so the chain is g_a <- g_b.
        let mut proj = ProjectionState::default();
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
}
