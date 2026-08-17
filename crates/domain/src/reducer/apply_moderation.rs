//! P2 — moderation control-plane projection.
//!
//! Migrates moderation from an `/_soland/admin` write path onto protocol
//! events. Projects the six active moderation kinds into the canonical cells
//! declared by `event-kind-registry.json`:
//!
//! - `ak.moderation.decision` -> `ak.component.moderation_state.v1` (or_set add, one cell per
//!   `payload.target_ref`). The add tag is the registered dot `ak:event:<event_id>:<write_index>`
//!   (`event-and-patch.md` §2.4.2); the add value is the decision snapshot (`decision_id` /
//!   `issuer` / `target_ref` / `decision` / `realm_id`), so the appeal separation-of-duties check
//!   can reverse-resolve the original decision issuer from the cell.
//! - `ak.moderation.decision.lift` -> `or_set_remove_dots` on the same target cell, removing
//!   exactly the dots enumerated in `payload.observed_dots[]` (content-moderation.md §2.6). It is
//!   deliberately NOT a bulk remove keyed by `decision_id`: §2.6 forbids `or_set_remove_observed`
//!   here by name, because lifting one review must not implicitly lift another issuer's decision. A
//!   replacement decision issued in the same batch is a new dot on the same cell and coexists with
//!   what survived (§2.6 last paragraph), so an add is never pre-tombstoned.
//! - `ak.moderation.appeal.{submit,review,decision,close}` → `ak.component.moderation.appeal.v1`
//!   (fsm, one cell per appeal id). Submit derives that id by retyping its Event id; later events
//!   carry `payload.appeal_id`. Deterministic state machine (none) → submitted → under_review →
//!   decided → closed, with `close` also reachable from submitted / under_review (appellant
//!   withdrawal or an authorized close service). content-moderation.md §5.5.
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

use arkret_models_collaboration::governance::moderation_appeal::AppealDecision;

use super::*;

fn payload_str(operation: &Operation, field: &str) -> Option<String> {
    operation
        .payload
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(ToOwned::to_owned)
}

fn appeal_verdict(operation: &Operation) -> Result<AppealDecision, &'static str> {
    operation
        .typed_payload::<arkret_wire::event_spec::ModerationAppealDecision>()
        .map(|payload| payload.decision)
        .map_err(|_| "schema_violation")
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

/// The 0-based index of `ak.component.moderation_state.v1` in the
/// `ak.moderation.decision` registry `cell_writes[]`. The contract declares
/// exactly one write.
const MODERATION_DECISION_WRITE_INDEX: usize = 0;

/// or_set add dot for `ak.moderation.decision`.
///
/// The registry row projects `{"kind":"or_set_add","tag":{"dot":true}}`, so the
/// tag is the registered dot of `event-and-patch.md` §2.4.2 —
/// `ak:event:<event_id>:<write_index>`. This used to be
/// `<decision_kind>:<issuer>:<request_digest>`, which no peer folding the same
/// Event would reproduce, and which `ak.moderation.decision.lift` cannot name:
/// `content-moderation.md` §5.5.1 makes lift remove producer-enumerated
/// `observed_dots[]`, and those dots are this value.
fn moderation_add_tag(operation: &Operation) -> Option<String> {
    let event_id = operation.context.event_id.as_str();
    Some(arkret_schema::or_set_dot(
        event_id,
        MODERATION_DECISION_WRITE_INDEX,
    ))
}

/// The removal set of `ak.moderation.decision.lift`.
///
/// `content-moderation.md` §2.6: the payload MUST carry `observed_dots[]`, the
/// removal set is byte-equal to it, and every dot's `event_id` segment MUST
/// equal the full `decision_ref` Event token. A dot appends `:<write_index>`
/// to that token; §2.4.2 provides no `event_ref -> dot`
/// derivation, so the two are checked against each other rather than one being
/// computed from the other. Returns `None` — fail closed — when the field is
/// absent, empty, malformed, or names a dot belonging to another decision.
fn moderation_lift_observed_dots(operation: &Operation, decision_ref: &str) -> Option<Vec<String>> {
    let dots = operation.payload.get("observed_dots")?.as_array()?;
    if dots.is_empty() {
        return None;
    }
    let expected_prefix = format!("{decision_ref}:");
    dots.iter()
        .map(|dot| {
            let dot = dot.as_str()?;
            let write_index = dot.strip_prefix(&expected_prefix)?;
            (!write_index.is_empty() && write_index.bytes().all(|byte| byte.is_ascii_digit()))
                .then(|| dot.to_owned())
        })
        .collect()
}

fn moderation_value_targets_ref(value: &Value, target_ref: &str) -> bool {
    let Some(value_target_ref) = value.get("target_ref").and_then(Value::as_str) else {
        return false;
    };
    value_target_ref == target_ref
        || message_event_id_from_ref(value_target_ref) == message_event_id_from_ref(target_ref)
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

    /// Fold every live decision for one target using the normative tightening
    /// order `hard_deny > quarantine > require_review > none`.
    ///
    /// Arrival order and issuer count are deliberately irrelevant: the cell
    /// is an OR-Set and concurrent decisions are ordinary joinable state.
    pub fn effective_moderation_verdict(&self, target_ref: &str) -> &'static str {
        let mut rank = 0_u8;
        for (cell_ref, state) in &self.cells {
            if !cell_ref
                .as_str()
                .starts_with("ak:cell:ak.component.moderation_state.v1:")
            {
                continue;
            }
            let CellState::Value(Value::Array(items)) = state else {
                continue;
            };
            for item in items {
                let value = item.get("value").unwrap_or(item);
                if !moderation_value_targets_ref(value, target_ref) {
                    continue;
                }
                if value
                    .get("lifted")
                    .and_then(Value::as_bool)
                    .unwrap_or(false)
                {
                    continue;
                }
                rank = rank.max(match value.get("decision").and_then(Value::as_str) {
                    Some("hard_deny") => 3,
                    Some("quarantine") => 2,
                    Some("require_review") => 1,
                    Some("dismiss" | "soft_deny") | None => 0,
                    // Corrupt/unregistered values fail closed. Admission never
                    // emits these, but a damaged projection must not weaken a
                    // surviving moderation decision.
                    Some(_) => 3,
                });
            }
        }
        match rank {
            3 => "hard_deny",
            2 => "quarantine",
            1 => "require_review",
            _ => "none",
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
    pub(crate) fn apply_moderation_decision(&mut self, operation: &Operation) -> ProjectionEffect {
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
            "hard_deny" | "quarantine" | "require_review" | "dismiss"
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
        if decision_kind == "dismiss" {
            if arkret_identifiers::EventId::new(target_ref.as_str()).is_err() {
                return ProjectionEffect::Rejected {
                    reason: "moderation_dismiss_requires_report_event".to_owned(),
                };
            }
            return ProjectionEffect::ModerationDecisionProjected {
                decision_id,
                realm_id,
            };
        }
        let Some(cell_ref) = Self::moderation_state_cell_ref(&target_ref) else {
            return ProjectionEffect::Rejected {
                reason: "moderation_decision_cell_ref_invalid".to_owned(),
            };
        };

        let mut items = self.moderation_cell_items(&cell_ref);
        let Some(tag) = moderation_add_tag(operation) else {
            return ProjectionEffect::Rejected {
                reason: "moderation_decision_add_dot_unresolved".to_owned(),
            };
        };
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

    /// P2 — project `ak.moderation.decision.lift` as the registered
    /// `or_set_remove_dots` on the moderation_state cell keyed by
    /// `payload.target_ref`.
    ///
    /// `content-moderation.md` §2.6 makes the removal set **byte-equal** to
    /// `payload.observed_dots[]`, and requires each dot's `event_id` segment to
    /// equal the `decision_ref` uuid — that pair is the machine-readable form of
    /// "解除一条 review 不得隐式 lift 其它 issuer 的 decision". This used to
    /// select by `decision_id` and mark every matching add lifted, which is the
    /// `or_set_remove_observed` shape §2.6 forbids by name for exactly that
    /// reason. Idempotent: re-lifting an already-removed dot converges.
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
        let Some(observed_dots) = moderation_lift_observed_dots(operation, &decision_id) else {
            return ProjectionEffect::Rejected {
                reason: "moderation_lift_observed_dots_invalid".to_owned(),
            };
        };
        let realm_id = operation.realm_id.to_string();
        let Some(cell_ref) = Self::moderation_state_cell_ref(&target_ref) else {
            return ProjectionEffect::Rejected {
                reason: "moderation_lift_cell_ref_invalid".to_owned(),
            };
        };

        let mut items = self.moderation_cell_items(&cell_ref);
        let lifted_at = arkret_canonical::format_timestamp_canonical(now);
        for dot in &observed_dots {
            let existing = items
                .iter_mut()
                .find(|item| item.get("tag").and_then(Value::as_str) == Some(dot.as_str()));
            match existing {
                Some(item) => {
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
                // Lift-before-decision, or a decision this server never
                // projected. An OR-Set remove has to record the dot, or a later
                // add carrying it would revive what was already removed.
                None => items.push(serde_json::json!({
                    "tag": dot,
                    "value": {
                        "decision_id": decision_id.clone(),
                        "target_ref": target_ref.clone(),
                        "realm_id": realm_id.clone(),
                        "lifted": true,
                        "lifted_at": lifted_at,
                    },
                })),
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
        let appeal_id = if target_state == "submitted" {
            if operation.payload.get("appeal_id").is_some() {
                return ProjectionEffect::Rejected {
                    reason: "moderation_appeal_submit_id_must_be_event_derived".to_owned(),
                };
            }
            let Some(appeal_id) =
                arkret_identifiers::EventId::new(operation.context.event_id.to_string())
                    .ok()
                    .map(|event_id| {
                        arkret_identifiers::TypedAppealId::from_event_id(&event_id).to_string()
                    })
            else {
                return ProjectionEffect::Rejected {
                    reason: "moderation_appeal_submit_event_id_required".to_owned(),
                };
            };
            appeal_id
        } else {
            let Some(appeal_id) = payload_str(operation, "appeal_id") else {
                return ProjectionEffect::Rejected {
                    reason: "moderation_appeal_id_missing".to_owned(),
                };
            };
            appeal_id
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
        if let Err(reason) =
            self.check_moderation_appeal_constraints(&appeal_id, operation, target_state)
        {
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
                && let Ok(verdict) = appeal_verdict(operation)
            {
                map.insert(
                    "decision".to_owned(),
                    serde_json::to_value(verdict)
                        .expect("AppealDecision serialization cannot fail"),
                );
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
        appeal_id: &str,
        operation: &Operation,
        target_state: &str,
    ) -> Result<(), &'static str> {
        match target_state {
            "submitted" => {
                self.enforce_no_active_duplicate_appeal(appeal_id, operation)?;
                Ok(())
            }
            // review: reviewer ≠ original decision issuer (separation of duties).
            "under_review" => {
                self.enforce_appeal_separation_of_duties(appeal_id, operation)?;
                Ok(())
            }
            // decision: SoD + verdict-specific atomicity (overturn↔lift,
            // modify↔new decision).
            "decided" => {
                self.enforce_appeal_separation_of_duties(appeal_id, operation)?;
                let verdict = appeal_verdict(operation)?;
                // Resolve the appealed decision_ref from the submit-time cell.
                let decision_ref = self.moderation_appeal_decision_ref(appeal_id);
                match verdict {
                    AppealDecision::Overturn => {
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
                    AppealDecision::Modify => {
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
                    AppealDecision::Uphold => Ok(()),
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
pub(crate) fn appeal_target_state(kind: &arkret_wire::EventKind) -> Option<&'static str> {
    match kind {
        arkret_wire::EventKind::ModerationAppealSubmit => Some("submitted"),
        arkret_wire::EventKind::ModerationAppealReview => Some("under_review"),
        arkret_wire::EventKind::ModerationAppealDecision => Some("decided"),
        arkret_wire::EventKind::ModerationAppealClose => Some("closed"),
        _ => None,
    }
}
