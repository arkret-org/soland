//! P2 — moderation control-plane projection.
//!
//! Migrates moderation from an `/_soland/admin` write path onto protocol
//! events. Projects the six active moderation kinds into the canonical cells
//! declared by `event-kind-registry.json`:
//!
//! - `ak.moderation.decision` -> `ak.component.moderation_state.v1` (or_set, one cell per
//!   `payload.target_ref`). The add value is the decision snapshot (`decision_id` / `issuer` /
//!   `target_ref` / `decision` / `realm_id`), so the appeal separation-of-duties check can
//!   reverse-resolve the original decision issuer from the cell.
//! - `ak.moderation.decision.lift` -> observed-remove / supersede on the same target cell. It marks
//!   entries whose `decision_id` matches `payload.decision_ref` as lifted. Terminal per
//!   content-moderation.md §2.6 (same §12.1 rule as capabilities): once a decision_id is lifted, a
//!   later re-add stays lifted.
//! - `ak.moderation.appeal.{submit,review,decision,close}` → `ak.component.moderation.appeal.v1`
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
//!   the paired `ak.moderation.decision.lift` is projected before the appeal decision, so the cell
//!   already reflects it; otherwise `appeal_overturn_missing_lift`.
//! - **modify ↔ new decision atomic** — a `verdict=modify` decision requires `modify_decision_ref`
//!   to name a decision already present (and not lifted) in the moderation_state cell; otherwise
//!   `appeal_modify_missing_decision`.
//!
//! `close` is a manual / authorized action — the reducer projects no auto-
//! close timer, cool-off window, or timer-service check (content-moderation.md
//! §5.5.2; spec §5.5 deleted the cool-off path).

use super::*;

/// Canonical closed verdict enum for `ak.moderation.appeal.decision`
/// (content-moderation.md §5.5.1.1 / moderation-appeal.schema.json).
const APPEAL_VERDICTS: [&str; 3] = ["uphold", "overturn", "modify"];

fn payload_str(operation: &Operation, field: &str) -> Option<String> {
    operation
        .payload
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(ToOwned::to_owned)
}

fn payload_ref(operation: &Operation, field: &str) -> Option<String> {
    let value = operation.payload.get(field)?;
    value
        .as_str()
        .filter(|value| !value.trim().is_empty())
        .map(ToOwned::to_owned)
        .or_else(|| {
            value
                .get("id")
                .or_else(|| value.get("object_ref"))
                .and_then(Value::as_str)
                .filter(|value| !value.trim().is_empty())
                .map(ToOwned::to_owned)
        })
}

/// The issuer of a moderation decision. The wire payload may name it
/// `issuer` (canonical) or `decided_by` (admin-era snapshot); accept either
/// so a decision projected by either path reverse-resolves consistently.
fn decision_issuer(operation: &Operation) -> Option<String> {
    payload_str(operation, "issuer").or_else(|| payload_str(operation, "decided_by"))
}

fn moderation_decision_id(operation: &Operation) -> String {
    payload_str(operation, "decision_id")
        .or_else(|| payload_str(operation, "event_id"))
        .unwrap_or_else(|| operation.operation_id.to_string())
}

fn moderation_request_canonical_digest(operation: &Operation) -> Option<String> {
    payload_str(operation, "request_canonical_digest").or_else(|| {
        operation
            .payload
            .get("policy_decision_ref")
            .and_then(|value| value.get("request_canonical_digest"))
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .map(ToOwned::to_owned)
    })
}

fn moderation_add_tag(decision_kind: &str, issuer: &str, request_digest: &str) -> String {
    format!("{decision_kind}:{issuer}:{request_digest}")
}

impl ProjectionState {
    fn moderation_state_cell_ref(target_ref: &str) -> Option<CellRef> {
        CellRef::new(format!(
            "ak:cell:ak.component.moderation_state.v1:{target_ref}"
        ))
        .ok()
    }

    fn moderation_appeal_cell_ref(appeal_id: &str) -> Option<CellRef> {
        CellRef::new(format!(
            "ak:cell:ak.component.moderation.appeal.v1:{appeal_id}"
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

    fn moderation_items_for_decision(&self, decision_id: &str) -> Vec<Value> {
        self.cells
            .iter()
            .filter(|(cell_ref, _)| {
                cell_ref
                    .as_str()
                    .starts_with("ak:cell:ak.component.moderation_state.v1:")
            })
            .flat_map(|(_, state)| match state {
                CellState::Value(Value::Array(items)) => items.clone(),
                _ => Vec::new(),
            })
            .filter(|item| {
                let value = item.get("value").unwrap_or(item);
                value
                    .get("decision_id")
                    .and_then(Value::as_str)
                    .is_some_and(|value| value == decision_id)
            })
            .collect()
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
        let items = self.moderation_items_for_decision(decision_id);
        !items.is_empty() && !Self::moderation_cell_has_lifted_item(&items)
    }

    /// True when the moderation_state cell for `decision_id` exists and is
    /// lifted. Used by the `overturn` atomicity check.
    pub(crate) fn moderation_decision_is_lifted(&self, decision_id: &str) -> bool {
        let items = self.moderation_items_for_decision(decision_id);
        !items.is_empty() && Self::moderation_cell_has_lifted_item(&items)
    }

    /// Reverse-resolve the issuer of the decision named by `decision_id` from
    /// the moderation_state cell. Returns `None` when the decision was never
    /// projected here (causal / backfill tolerance — separation-of-duties is
    /// only enforced when we can observe the original decision's issuer).
    pub(crate) fn moderation_decision_issuer(&self, decision_id: &str) -> Option<String> {
        let items = self.moderation_items_for_decision(decision_id);
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
    pub fn moderation_appeal_appellant(&self, appeal_id: &str) -> Option<String> {
        let cell_ref = Self::moderation_appeal_cell_ref(appeal_id)?;
        match self.cells.get(&cell_ref) {
            Some(CellState::Value(value)) => value
                .get("appellant")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned),
            _ => None,
        }
    }

    /// P2 — project `ak.moderation.decision` as an or_set add on the
    /// moderation_state cell keyed by `payload.target_ref`.
    pub(crate) fn apply_moderation_decision(
        &mut self,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
    ) -> ProjectionEffect {
        let decision_id = moderation_decision_id(operation);
        let Some(target_ref) = payload_ref(operation, "target_ref") else {
            return ProjectionEffect::Rejected {
                reason: "moderation_decision_target_ref_missing".to_owned(),
            };
        };
        let Some(decision_kind) =
            payload_str(operation, "decision").or_else(|| payload_str(operation, "action"))
        else {
            return ProjectionEffect::Rejected {
                reason: "moderation_decision_kind_missing".to_owned(),
            };
        };
        if !matches!(
            decision_kind.as_str(),
            "hard_deny" | "quarantine" | "require_review"
        ) {
            return ProjectionEffect::Rejected {
                reason: "moderation_decision_kind_invalid".to_owned(),
            };
        }
        // Structural acceptance: a sealed decision MUST name its issuer so the
        // appeal separation-of-duties reverse lookup is well-defined. Missing
        // issuer ⇒ fail closed.
        let Some(issuer) = decision_issuer(operation) else {
            return ProjectionEffect::Rejected {
                reason: "moderation_decision_issuer_missing".to_owned(),
            };
        };
        let Some(request_digest) = moderation_request_canonical_digest(operation) else {
            return ProjectionEffect::Rejected {
                reason: "moderation_request_canonical_digest_missing".to_owned(),
            };
        };
        let realm_id = operation.realm_id.to_string();
        let Some(cell_ref) = Self::moderation_state_cell_ref(&target_ref) else {
            return ProjectionEffect::Rejected {
                reason: "moderation_decision_cell_ref_invalid".to_owned(),
            };
        };

        let mut items = self.moderation_cell_items(&cell_ref);
        // §2.6 terminal: a re-add of an already-lifted decision_id does NOT
        // revive. Carry the lifted tombstone onto the new add.
        let terminal_lifted = Self::moderation_cell_has_lifted_item(
            &self.moderation_items_for_decision(&decision_id),
        );
        let tag = moderation_add_tag(&decision_kind, &issuer, &request_digest);
        let mut value = operation.payload.clone();
        if let Value::Object(map) = &mut value {
            map.insert("decision_id".to_owned(), Value::String(decision_id.clone()));
            map.insert("target_ref".to_owned(), Value::String(target_ref));
            map.insert("decision".to_owned(), Value::String(decision_kind));
            map.insert("issuer".to_owned(), Value::String(issuer));
            map.insert(
                "request_canonical_digest".to_owned(),
                Value::String(request_digest),
            );
            map.entry("realm_id".to_owned())
                .or_insert_with(|| Value::String(realm_id.clone()));
            if terminal_lifted {
                map.insert("lifted".to_owned(), Value::Bool(true));
                map.entry("lifted_at".to_owned())
                    .or_insert_with(|| Value::String(now.to_rfc3339()));
            }
        }
        items.push(serde_json::json!({
            "tag": tag,
            "value": value,
        }));
        self.cells
            .insert(cell_ref, CellState::Value(Value::Array(items)));

        ProjectionEffect::ModerationDecisionProjected {
            decision_id,
            realm_id,
        }
    }

    /// P2 — project `ak.moderation.decision.lift` as an or_set observed-remove
    /// / supersede on the moderation_state cell keyed by `payload.target_ref`.
    /// Idempotent: lifting an already-lifted decision converges.
    pub(crate) fn apply_moderation_decision_lift(
        &mut self,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
    ) -> ProjectionEffect {
        let Some(decision_id) = payload_str(operation, "decision_ref")
            .or_else(|| payload_str(operation, "decision_id"))
        else {
            return ProjectionEffect::Rejected {
                reason: "moderation_lift_decision_ref_missing".to_owned(),
            };
        };
        let Some(target_ref) = payload_ref(operation, "target_ref") else {
            return ProjectionEffect::Rejected {
                reason: "moderation_lift_target_ref_missing".to_owned(),
            };
        };
        let realm_id = operation.realm_id.to_string();
        let Some(cell_ref) = Self::moderation_state_cell_ref(&target_ref) else {
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
                "tag": format!("lift:{}:{}", decision_id, operation.operation_id),
                "value": {
                    "decision_id": decision_id.clone(),
                    "target_ref": target_ref.clone(),
                    "realm_id": realm_id.clone(),
                    "lifted": true,
                    "lifted_at": lifted_at,
                },
            }));
        } else {
            // Observed-remove: mark every surviving add for this decision_id
            // lifted (terminal). Repeated lift is idempotent.
            let mut lifted_any = false;
            for item in &mut items {
                let target = if item.get("value").is_some() {
                    item.get_mut("value").expect("value present")
                } else {
                    item
                };
                if let Value::Object(map) = target {
                    if map.get("decision_id").and_then(Value::as_str) != Some(decision_id.as_str())
                    {
                        continue;
                    }
                    map.insert("lifted".to_owned(), Value::Bool(true));
                    map.entry("lifted_at".to_owned())
                        .or_insert_with(|| Value::String(lifted_at.clone()));
                    lifted_any = true;
                }
            }
            if !lifted_any {
                items.push(serde_json::json!({
                    "tag": format!("lift:{}:{}", decision_id, operation.operation_id),
                    "value": {
                        "decision_id": decision_id.clone(),
                        "target_ref": target_ref.clone(),
                        "realm_id": realm_id.clone(),
                        "lifted": true,
                        "lifted_at": lifted_at,
                    },
                }));
            }
        }
        self.cells
            .insert(cell_ref, CellState::Value(Value::Array(items)));

        ProjectionEffect::ModerationDecisionLifted {
            decision_id,
            realm_id,
        }
    }

    /// P2 — project the four `ak.moderation.appeal.*` kinds onto the appeal
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
        if let Some(payload_realm) = payload_str(operation, "realm_id")
            && payload_realm != realm_id
        {
            return ProjectionEffect::Rejected {
                reason: "moderation_appeal_realm_mismatch".to_owned(),
            };
        }

        let current = self.moderation_appeal_state(&appeal_id);

        // FSM transition guard. (none)→submitted, submitted→under_review,
        // under_review→decided, decided→closed. The only early close is
        // appellant withdrawal from submitted/under_review.
        let transition_ok = match (current.as_deref(), target_state) {
            (None, "submitted") => true,
            (Some("submitted"), "under_review") => true,
            (Some("under_review"), "decided") => true,
            (Some("submitted"), "closed") | (Some("under_review"), "closed") => {
                self.is_appellant_withdrawal_close(&appeal_id, operation)
            }
            (Some("decided"), "closed") => true,
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
            if target_state == "decided"
                && let Some(verdict) = payload_str(operation, "verdict")
            {
                map.insert("verdict".to_owned(), Value::String(verdict));
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
            "submitted" => {
                self.enforce_no_active_duplicate_appeal(&appeal_id, operation)?;
                Ok(())
            }
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
            // authorized by closer == appellant and close_reason, otherwise
            // the capability gate (policy.rs) covers reviewer authority after
            // decided. No SoD restriction on close per §5.5.2.
            "closed" => Ok(()),
            _ => Ok(()),
        }
    }

    fn is_appellant_withdrawal_close(&self, appeal_id: &str, operation: &Operation) -> bool {
        if payload_str(operation, "close_reason").as_deref() != Some("appellant_withdrawn") {
            return false;
        }
        let Some(closer) = payload_str(operation, "closer") else {
            return false;
        };
        self.moderation_appeal_appellant(appeal_id).as_deref() == Some(closer.as_str())
    }

    fn enforce_no_active_duplicate_appeal(
        &self,
        appeal_id: &str,
        operation: &Operation,
    ) -> Result<(), &'static str> {
        let Some(decision_ref) = payload_str(operation, "decision_ref") else {
            return Ok(());
        };
        let Some(appellant) = payload_str(operation, "appellant") else {
            return Ok(());
        };
        for cell in self.cells.values() {
            let Some(value) = (match cell {
                CellState::Value(Value::Object(value)) => Some(value),
                _ => None,
            }) else {
                continue;
            };
            if value.get("appeal_id").and_then(Value::as_str) == Some(appeal_id) {
                continue;
            }
            if value.get("decision_ref").and_then(Value::as_str) != Some(decision_ref.as_str())
                || value.get("appellant").and_then(Value::as_str) != Some(appellant.as_str())
            {
                continue;
            }
            if value.get("state").and_then(Value::as_str) != Some("closed") {
                return Err("moderation_appeal_duplicate_active");
            }
        }
        Ok(())
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
    match kind {
        arkret_core::events::EventKind::MODERATION_APPEAL_SUBMIT => Some("submitted"),
        arkret_core::events::EventKind::MODERATION_APPEAL_REVIEW => Some("under_review"),
        arkret_core::events::EventKind::MODERATION_APPEAL_DECISION => Some("decided"),
        arkret_core::events::EventKind::MODERATION_APPEAL_CLOSE => Some("closed"),
        _ => None,
    }
}
