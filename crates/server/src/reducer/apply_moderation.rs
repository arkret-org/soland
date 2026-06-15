//! P2 — moderation control-plane projection.
//!
//! Migrates moderation from an `/_soland/admin` write path onto protocol
//! events. Projects the six active moderation kinds into the canonical cells
//! declared by `event-kind-registry.json`:
//!
//! - `ck.moderation.decision` → `ck.component.moderation_state.v1` (or_set, one cell per
//!   `payload.decision_id`). The add value is the decision snapshot (`issuer` / `target_ref` /
//!   `verdict` / `realm_id`), so the appeal separation-of-duties check can reverse-resolve the
//!   original decision issuer from the cell.
//! - `ck.moderation.decision.lift` → observed-remove / supersede on the same cell keyed by
//!   `payload.decision_ref`. Terminal per content-moderation.md §2.6 (same §12.1 rule as
//!   capabilities): once a decision_id is lifted, a later re-add stays lifted.
//! - `ck.moderation.appeal.{submit,review,decision,close}` → `ck.component.moderation.appeal.v1`
//!   (fsm, one cell per `payload.appeal_id`). Deterministic state machine (none) → submitted →
//!   under_review → decided → closed, with `close` also reachable from submitted / under_review
//!   (appellant withdrawal or an authorized close service). content-moderation.md §5.5.
//!
//! Reducer-enforced §5.5.2 constraints (surfaced at ingest by the
//! `preflight_moderation_projection_reject` snapshot run, mirroring the MLS
//! preflight):
//! - **separation of duties** — an appeal `review` / `decision` `reviewer` MUST NOT equal the
//!   issuer of the appealed `decision_ref` decision (looked up from the moderation_state cell).
//!   Violations reject with `appeal_self_review_forbidden`.
//! - **overturn ↔ lift atomic** — a `verdict=overturn` decision requires the moderation_state cell
//!   for `decision_ref` to already show the decision lifted. With ordered-submit-batch semantics
//!   the paired `ck.moderation.decision.lift` is projected before the appeal decision, so the cell
//!   already reflects it; otherwise `appeal_overturn_missing_lift`.
//! - **modify ↔ new decision atomic** — a `verdict=modify` decision requires `modify_decision_ref`
//!   to name a decision already present (and not lifted) in the moderation_state cell; otherwise
//!   `appeal_modify_missing_decision`.
//!
//! `close` is a manual / authorized action — the reducer projects no auto-
//! close timer, cool-off window, or timer-service check (content-moderation.md
//! §5.5.2; spec §5.5 deleted the cool-off path).

use super::*;

/// Canonical closed verdict enum for `ck.moderation.appeal.decision`
/// (content-moderation.md §5.5.1.1 / moderation-appeal.schema.json).
const APPEAL_VERDICTS: [&str; 3] = ["uphold", "overturn", "modify"];

/// or_set add dot for a moderation event projected from the
/// `Operation` boundary. Deterministic per accepted event (mirrors
/// `apply_capability::capability_add_dot`).
fn moderation_add_dot(operation: &Operation) -> String {
    operation.operation_id.to_string()
}

fn payload_str(operation: &Operation, field: &str) -> Option<String> {
    operation
        .payload
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(ToOwned::to_owned)
}

/// The issuer of a moderation decision. The wire payload may name it
/// `issuer` (canonical) or `decided_by` (admin-era snapshot); accept either
/// so a decision projected by either path reverse-resolves consistently.
fn decision_issuer(operation: &Operation) -> Option<String> {
    payload_str(operation, "issuer").or_else(|| payload_str(operation, "decided_by"))
}

impl ProjectionState {
    fn moderation_state_cell_ref(decision_id: &str) -> Option<CellRef> {
        CellRef::new(format!(
            "ck:cell:ck.component.moderation_state.v1:{decision_id}"
        ))
        .ok()
    }

    fn moderation_appeal_cell_ref(appeal_id: &str) -> Option<CellRef> {
        CellRef::new(format!(
            "ck:cell:ck.component.moderation.appeal.v1:{appeal_id}"
        ))
        .ok()
    }

    /// Read the current or_set item array for a moderation_state cell (empty
    /// when the cell is absent / Bottom / not an array).
    fn moderation_cell_items(&self, cell_ref: &CellRef) -> Vec<Value> {
        match self.cells.get(cell_ref) {
            Some(CellState::Value(Value::Array(items))) => items.clone(),
            _ => Vec::new(),
        }
    }

    /// True when any surviving or_set item on this moderation_state cell is
    /// observed-removed (lifted). Drives the §2.6 terminal rule: once a
    /// decision_id is lifted, re-adds stay lifted.
    fn moderation_cell_has_lifted_item(items: &[Value]) -> bool {
        items.iter().any(|item| {
            let value = item.get("value").unwrap_or(item);
            value
                .get("lifted")
                .and_then(Value::as_bool)
                .unwrap_or(false)
        })
    }

    /// True when the moderation_state cell for `decision_id` exists and is
    /// NOT lifted — i.e. there is a live decision under this id. Used by the
    /// `modify` atomicity check (the new decision MUST already be present).
    pub(crate) fn moderation_decision_is_live(&self, decision_id: &str) -> bool {
        let Some(cell_ref) = Self::moderation_state_cell_ref(decision_id) else {
            return false;
        };
        let items = self.moderation_cell_items(&cell_ref);
        !items.is_empty() && !Self::moderation_cell_has_lifted_item(&items)
    }

    /// True when the moderation_state cell for `decision_id` exists and is
    /// lifted. Used by the `overturn` atomicity check.
    pub(crate) fn moderation_decision_is_lifted(&self, decision_id: &str) -> bool {
        let Some(cell_ref) = Self::moderation_state_cell_ref(decision_id) else {
            return false;
        };
        let items = self.moderation_cell_items(&cell_ref);
        !items.is_empty() && Self::moderation_cell_has_lifted_item(&items)
    }

    /// Reverse-resolve the issuer of the decision named by `decision_id` from
    /// the moderation_state cell. Returns `None` when the decision was never
    /// projected here (causal / backfill tolerance — separation-of-duties is
    /// only enforced when we can observe the original decision's issuer).
    pub(crate) fn moderation_decision_issuer(&self, decision_id: &str) -> Option<String> {
        let cell_ref = Self::moderation_state_cell_ref(decision_id)?;
        let items = self.moderation_cell_items(&cell_ref);
        items.iter().rev().find_map(|item| {
            let value = item.get("value").unwrap_or(item);
            value
                .get("issuer")
                .and_then(Value::as_str)
                .filter(|s| !s.trim().is_empty())
                .map(ToOwned::to_owned)
        })
    }

    /// The current FSM state value for an appeal cell (`None` when the cell
    /// is absent / Bottom / not a state object).
    pub(crate) fn moderation_appeal_state(&self, appeal_id: &str) -> Option<String> {
        let cell_ref = Self::moderation_appeal_cell_ref(appeal_id)?;
        match self.cells.get(&cell_ref) {
            Some(CellState::Value(value)) => value
                .get("state")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned),
            _ => None,
        }
    }

    /// The `appellant` anchored on the appeal cell at submit time. Used by
    /// the capability gate (policy.rs) to authorize the appellant-withdrawal
    /// close path (`closer == appellant`).
    pub(crate) fn moderation_appeal_appellant(&self, appeal_id: &str) -> Option<String> {
        let cell_ref = Self::moderation_appeal_cell_ref(appeal_id)?;
        match self.cells.get(&cell_ref) {
            Some(CellState::Value(value)) => value
                .get("appellant")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned),
            _ => None,
        }
    }

    /// P2 — project `ck.moderation.decision` as an or_set add on the
    /// moderation_state cell keyed by `payload.decision_id`.
    pub(crate) fn apply_moderation_decision(
        &mut self,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
    ) -> ProjectionEffect {
        let Some(decision_id) = payload_str(operation, "decision_id") else {
            return ProjectionEffect::Rejected {
                reason: "moderation_decision_id_missing".to_owned(),
            };
        };
        // Structural acceptance: a sealed decision MUST name its issuer so the
        // appeal separation-of-duties reverse lookup is well-defined. Missing
        // issuer ⇒ fail closed.
        let Some(issuer) = decision_issuer(operation) else {
            return ProjectionEffect::Rejected {
                reason: "moderation_decision_issuer_missing".to_owned(),
            };
        };
        let realm_id = operation.realm_id.to_string();
        let Some(cell_ref) = Self::moderation_state_cell_ref(&decision_id) else {
            return ProjectionEffect::Rejected {
                reason: "moderation_decision_cell_ref_invalid".to_owned(),
            };
        };

        let mut items = self.moderation_cell_items(&cell_ref);
        // §2.6 terminal: a re-add of an already-lifted decision_id does NOT
        // revive. Carry the lifted tombstone onto the new add.
        let terminal_lifted = Self::moderation_cell_has_lifted_item(&items);
        let mut value = operation.payload.clone();
        if let Value::Object(map) = &mut value {
            map.insert("decision_id".to_owned(), Value::String(decision_id.clone()));
            map.insert("issuer".to_owned(), Value::String(issuer));
            map.entry("realm_id".to_owned())
                .or_insert_with(|| Value::String(realm_id.clone()));
            if terminal_lifted {
                map.insert("lifted".to_owned(), Value::Bool(true));
                map.entry("lifted_at".to_owned())
                    .or_insert_with(|| Value::String(now.to_rfc3339()));
            }
        }
        items.push(serde_json::json!({
            "tag": moderation_add_dot(operation),
            "value": value,
        }));
        self.cells
            .insert(cell_ref, CellState::Value(Value::Array(items)));

        ProjectionEffect::ModerationDecisionProjected {
            decision_id,
            realm_id,
        }
    }

    /// P2 — project `ck.moderation.decision.lift` as an or_set observed-remove
    /// / supersede on the moderation_state cell keyed by `payload.decision_ref`.
    /// Idempotent: lifting an already-lifted decision converges.
    pub(crate) fn apply_moderation_decision_lift(
        &mut self,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
    ) -> ProjectionEffect {
        // The lift's cell subject is `payload.decision_ref` (event-kind-
        // registry). Accept `decision_id` as a fallback for the admin-era
        // snapshot shape.
        let Some(decision_id) = payload_str(operation, "decision_ref")
            .or_else(|| payload_str(operation, "decision_id"))
        else {
            return ProjectionEffect::Rejected {
                reason: "moderation_lift_decision_ref_missing".to_owned(),
            };
        };
        let realm_id = operation.realm_id.to_string();
        let Some(cell_ref) = Self::moderation_state_cell_ref(&decision_id) else {
            return ProjectionEffect::Rejected {
                reason: "moderation_lift_cell_ref_invalid".to_owned(),
            };
        };

        let mut items = self.moderation_cell_items(&cell_ref);
        let lifted_at = now.to_rfc3339();
        if items.is_empty() {
            // Lift-before-decision (or lift of a decision this server never
            // projected): write a tombstone-only item so the terminal rule
            // holds and a later re-add of the same decision_id stays lifted.
            items.push(serde_json::json!({
                "tag": moderation_add_dot(operation),
                "value": {
                    "decision_id": decision_id,
                    "realm_id": realm_id,
                    "lifted": true,
                    "lifted_at": lifted_at,
                },
            }));
        } else {
            // Observed-remove: mark every surviving add for this decision_id
            // lifted (terminal). Repeated lift is idempotent.
            for item in &mut items {
                let target = if item.get("value").is_some() {
                    item.get_mut("value").expect("value present")
                } else {
                    item
                };
                if let Value::Object(map) = target {
                    map.insert("lifted".to_owned(), Value::Bool(true));
                    map.entry("lifted_at".to_owned())
                        .or_insert_with(|| Value::String(lifted_at.clone()));
                }
            }
        }
        self.cells
            .insert(cell_ref, CellState::Value(Value::Array(items)));

        ProjectionEffect::ModerationDecisionLifted {
            decision_id,
            realm_id,
        }
    }

    /// P2 — project the four `ck.moderation.appeal.*` kinds onto the appeal
    /// fsm cell. `target_state` is the post-transition state; the reducer
    /// validates the transition is legal from the current cell state and the
    /// §5.5.2 reducer constraints.
    pub(crate) fn apply_moderation_appeal(
        &mut self,
        operation: &Operation,
        target_state: &str,
    ) -> ProjectionEffect {
        let Some(appeal_id) = payload_str(operation, "appeal_id") else {
            return ProjectionEffect::Rejected {
                reason: "moderation_appeal_id_missing".to_owned(),
            };
        };
        let realm_id = operation.realm_id.to_string();
        let Some(cell_ref) = Self::moderation_appeal_cell_ref(&appeal_id) else {
            return ProjectionEffect::Rejected {
                reason: "moderation_appeal_cell_ref_invalid".to_owned(),
            };
        };

        // Realm binding: appeal payload realm_id MUST equal the enclosing
        // Event realm_id (content-moderation.md §5.5.2). The wire validator
        // also checks this; the reducer fails closed defensively.
        if let Some(payload_realm) = payload_str(operation, "realm_id") {
            if payload_realm != realm_id {
                return ProjectionEffect::Rejected {
                    reason: "moderation_appeal_realm_mismatch".to_owned(),
                };
            }
        }

        let current = self.moderation_appeal_state(&appeal_id);

        // FSM transition guard. (none)→submitted, submitted→under_review,
        // under_review→decided, {submitted,under_review,decided}→closed.
        let transition_ok = match (current.as_deref(), target_state) {
            (None, "submitted") => true,
            (Some("submitted"), "under_review") => true,
            (Some("under_review"), "decided") => true,
            (Some("submitted"), "closed")
            | (Some("under_review"), "closed")
            | (Some("decided"), "closed") => true,
            _ => false,
        };
        if !transition_ok {
            return ProjectionEffect::Rejected {
                reason: format!(
                    "moderation_appeal_invalid_transition:{}->{}",
                    current.as_deref().unwrap_or("none"),
                    target_state
                ),
            };
        }

        // Per-kind §5.5.2 constraints.
        if let Err(reason) = self.check_moderation_appeal_constraints(operation, target_state) {
            return ProjectionEffect::Rejected {
                reason: reason.to_owned(),
            };
        }

        // Build / patch the fsm cell value. Carry forward submit-time
        // identity fields (appellant / decision_ref) needed by later
        // transitions' constraint checks.
        let mut value = match self.cells.get(&cell_ref) {
            Some(CellState::Value(Value::Object(map))) => Value::Object(map.clone()),
            _ => Value::Object(serde_json::Map::new()),
        };
        if let Value::Object(map) = &mut value {
            map.insert("appeal_id".to_owned(), Value::String(appeal_id.clone()));
            map.insert("realm_id".to_owned(), Value::String(realm_id.clone()));
            map.insert("state".to_owned(), Value::String(target_state.to_owned()));
            // On submit, anchor the identity fields used by SoD / atomicity.
            if target_state == "submitted" {
                if let Some(appellant) = payload_str(operation, "appellant") {
                    map.insert("appellant".to_owned(), Value::String(appellant));
                }
                if let Some(decision_ref) = payload_str(operation, "decision_ref") {
                    map.insert("decision_ref".to_owned(), Value::String(decision_ref));
                }
                if let Some(target_ref) = payload_str(operation, "target_ref") {
                    map.insert("target_ref".to_owned(), Value::String(target_ref));
                }
            }
            if target_state == "decided" {
                if let Some(verdict) = payload_str(operation, "verdict") {
                    map.insert("verdict".to_owned(), Value::String(verdict));
                }
            }
        }
        self.cells.insert(cell_ref, CellState::Value(value));

        ProjectionEffect::ModerationAppealProjected {
            appeal_id,
            realm_id,
            new_state: target_state.to_owned(),
        }
    }

    /// §5.5.2 reducer constraints for an appeal transition. Returns the
    /// canonical reason_code on violation.
    fn check_moderation_appeal_constraints(
        &self,
        operation: &Operation,
        target_state: &str,
    ) -> Result<(), &'static str> {
        let appeal_id = payload_str(operation, "appeal_id").unwrap_or_default();
        match target_state {
            // review: reviewer ≠ original decision issuer (separation of duties).
            "under_review" => {
                self.enforce_appeal_separation_of_duties(&appeal_id, operation)?;
                Ok(())
            }
            // decision: SoD + verdict-specific atomicity (overturn↔lift,
            // modify↔new decision).
            "decided" => {
                self.enforce_appeal_separation_of_duties(&appeal_id, operation)?;
                let verdict =
                    payload_str(operation, "verdict").ok_or("moderation_appeal_verdict_missing")?;
                if !APPEAL_VERDICTS.contains(&verdict.as_str()) {
                    return Err("schema_violation");
                }
                // Resolve the appealed decision_ref from the submit-time cell.
                let decision_ref = self.moderation_appeal_decision_ref(&appeal_id);
                match verdict.as_str() {
                    "overturn" => {
                        let Some(decision_ref) = decision_ref else {
                            return Err("appeal_overturn_missing_lift");
                        };
                        // The paired lift MUST already be projected (ordered
                        // batch: lift before this decision), so the
                        // moderation_state cell shows decision_ref lifted.
                        if !self.moderation_decision_is_lifted(&decision_ref) {
                            return Err("appeal_overturn_missing_lift");
                        }
                        Ok(())
                    }
                    "modify" => {
                        let modify_ref = payload_str(operation, "modify_decision_ref")
                            .ok_or("appeal_modify_missing_decision")?;
                        // The new decision MUST already be present (ordered
                        // batch: new decision before this appeal decision).
                        if !self.moderation_decision_is_live(&modify_ref) {
                            return Err("appeal_modify_missing_decision");
                        }
                        Ok(())
                    }
                    // uphold: original decision stands, no pairing required.
                    _ => Ok(()),
                }
            }
            // close: reviewer close OR appellant withdrawal. Withdrawal is
            // authorized by closer == appellant; otherwise the capability gate
            // (policy.rs) covers reviewer authority. No SoD restriction on
            // close per §5.5.2 (appellant may close their own appeal).
            "closed" => Ok(()),
            _ => Ok(()),
        }
    }

    /// Read the `decision_ref` anchored on the appeal cell at submit time.
    fn moderation_appeal_decision_ref(&self, appeal_id: &str) -> Option<String> {
        let cell_ref = Self::moderation_appeal_cell_ref(appeal_id)?;
        match self.cells.get(&cell_ref) {
            Some(CellState::Value(value)) => value
                .get("decision_ref")
                .and_then(Value::as_str)
                .filter(|s| !s.trim().is_empty())
                .map(ToOwned::to_owned),
            _ => None,
        }
    }

    /// separation-of-duties: the review/decision `reviewer` MUST NOT equal the
    /// issuer of the appealed decision. The appealed decision is resolved via
    /// the appeal cell's `decision_ref` → moderation_state cell issuer. When
    /// the original decision was never projected here we cannot enforce (causal
    /// tolerance) and accept.
    fn enforce_appeal_separation_of_duties(
        &self,
        appeal_id: &str,
        operation: &Operation,
    ) -> Result<(), &'static str> {
        let Some(reviewer) = payload_str(operation, "reviewer") else {
            // No reviewer named — schema validator catches this; reducer
            // tolerates absence (constraint is reviewer-relative).
            return Ok(());
        };
        let Some(decision_ref) = self.moderation_appeal_decision_ref(appeal_id) else {
            return Ok(());
        };
        let Some(issuer) = self.moderation_decision_issuer(&decision_ref) else {
            return Ok(());
        };
        if reviewer == issuer {
            return Err("appeal_self_review_forbidden");
        }
        Ok(())
    }
}

/// Map an appeal event kind to its target FSM state. Used by the dispatch
/// adapter and the ingest preflight.
pub(crate) fn appeal_target_state(kind: &str) -> Option<&'static str> {
    use crate::kinds::*;
    match kind {
        CK_MODERATION_APPEAL_SUBMIT => Some("submitted"),
        CK_MODERATION_APPEAL_REVIEW => Some("under_review"),
        CK_MODERATION_APPEAL_DECISION => Some("decided"),
        CK_MODERATION_APPEAL_CLOSE => Some("closed"),
        _ => None,
    }
}
