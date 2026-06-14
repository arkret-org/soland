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
//!   `ck:event:<event_id>:<effect_index>` is the wire form). value = the canonical
//!   grant snapshot.
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
}
