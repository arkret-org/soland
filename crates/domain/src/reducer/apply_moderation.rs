//! P2 — moderation control-plane projection.
//!
//! Migrates moderation from an `/_soland/admin` write path onto protocol
//! events. Projects the active moderation kinds into the canonical cells
//! declared by `event-kind-registry.json`:
//!
//! - `ak.moderation.decision` -> `ak.component.moderation_state.v1` (or_set add, one cell per
//!   `payload.target_ref`). The add tag is the registered dot `ak:event:<event_id>:<write_index>`
//!   (`event-and-patch.md` §2.4.2); the add value is the decision snapshot (`decision_id` /
//!   `issuer` / `target_ref` / `decision` / `realm_id`).
//! - `ak.moderation.decision.lift` -> `or_set_remove_dots` on the same target cell, removing
//!   exactly the dots enumerated in `payload.observed_dot_ids[]` (content-moderation.md §2.6). It
//!   is deliberately NOT a bulk remove keyed by `decision_id`: §2.6 forbids
//!   `or_set_remove_observed` here by name, because lifting one review must not implicitly lift
//!   another issuer's decision. A replacement decision issued in the same batch is a new dot on the
//!   same cell and coexists with what survived (§2.6 last paragraph), so an add is never
//!   pre-tombstoned.
use super::*;

fn payload_str(operation: &Operation, field: &str) -> Option<String> {
    operation
        .payload
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(ToOwned::to_owned)
}

/// The canonical issuer named by the accepted moderation decision payload.
fn decision_issuer(operation: &Operation) -> Option<String> {
    payload_str(operation, "issuer_id")
}

fn moderation_request_canonical_digest(operation: &Operation) -> Option<String> {
    payload_str(operation, "request_canonical_digest")
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
/// `observed_dot_ids[]`, and those dots are this value.
fn moderation_add_tag(operation: &Operation) -> Option<String> {
    let event_id = operation.context.event_id.as_str();
    Some(arkret_schema::or_set_dot(
        event_id,
        MODERATION_DECISION_WRITE_INDEX,
    ))
}

/// The removal set of `ak.moderation.decision.lift`.
///
/// `content-moderation.md` §2.6: the payload MUST carry `observed_dot_ids[]`, the
/// removal set is byte-equal to it, and every dot's `event_id` segment MUST
/// equal the full `decision_ref` Event token. A dot appends `:<write_index>`
/// to that token; §2.4.2 provides no `event_ref -> dot`
/// derivation, so the two are checked against each other rather than one being
/// computed from the other. Returns `None` — fail closed — when the field is
/// absent, empty, malformed, or names a dot belonging to another decision.
fn moderation_lift_observed_dots(operation: &Operation, decision_ref: &str) -> Option<Vec<String>> {
    let dots = operation.payload.get("observed_dot_ids")?.as_array()?;
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

    /// Read the current or_set item array for a moderation_state cell (empty
    /// when the cell is absent / Bottom / not an array).
    fn moderation_cell_items(&self, cell_ref: &CellRef) -> Vec<Value> {
        match self.cells.get(cell_ref) {
            Some(ResolvedCellState::Value(Value::Array(items))) => items.clone(),
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
            let ResolvedCellState::Value(Value::Array(items)) = state else {
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

    #[cfg(test)]
    fn moderation_items_for_decision(&self, decision_id: &str) -> Vec<Value> {
        self.cells
            .iter()
            .filter(|(cell_ref, _)| {
                cell_ref
                    .as_str()
                    .starts_with("ak:cell:ak.component.moderation_state.v1:")
            })
            .flat_map(|(_, state)| match state {
                ResolvedCellState::Value(Value::Array(items)) => items.clone(),
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
    #[cfg(test)]
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
    #[cfg(test)]
    pub(crate) fn moderation_decision_is_live(&self, decision_id: &str) -> bool {
        let items = self.moderation_items_for_decision(decision_id);
        !items.is_empty() && !Self::moderation_cell_has_lifted_item(&items)
    }

    /// True when the moderation_state cell for `decision_id` exists and is
    /// lifted. Used by the `overturn` atomicity check.
    #[cfg(test)]
    pub(crate) fn moderation_decision_is_lifted(&self, decision_id: &str) -> bool {
        let items = self.moderation_items_for_decision(decision_id);
        !items.is_empty() && Self::moderation_cell_has_lifted_item(&items)
    }

    /// Reverse-resolve the issuer of the decision named by `decision_id` from
    /// the moderation_state cell. Returns `None` when the decision was never
    /// projected here (causal / backfill tolerance — separation-of-duties is
    /// only enforced when we can observe the original decision's issuer).
    #[cfg(test)]
    pub(crate) fn moderation_decision_issuer(&self, decision_id: &str) -> Option<String> {
        if let Some(decision) = self.moderation_decisions.get(decision_id) {
            return Some(decision.issuer_id.to_string());
        }
        let items = self.moderation_items_for_decision(decision_id);
        items.iter().rev().find_map(|item| {
            let value = item.get("value").unwrap_or(item);
            value
                .get("issuer_id")
                .and_then(Value::as_str)
                .filter(|s| !s.trim().is_empty())
                .map(ToOwned::to_owned)
        })
    }

    /// P2 — project `ak.moderation.decision` as an or_set add on the
    /// moderation_state cell keyed by `payload.target_ref`.
    pub(crate) fn apply_moderation_decision(&mut self, operation: &Operation) -> ProjectionEffect {
        let decision_id = operation.context.event_id.to_string();
        let Some(target_ref) = payload_str(operation, "target_ref") else {
            return ProjectionEffect::Rejected {
                reason: "moderation_decision_target_ref_missing".to_owned(),
            };
        };
        let Some(decision_kind) = payload_str(operation, "decision") else {
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
        // Structural acceptance: a sealed decision MUST name its issuer.
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
            let Ok(decision) =
                operation.typed_payload::<arkret_wire::event_spec::ModerationDecision>()
            else {
                return ProjectionEffect::Rejected {
                    reason: "moderation_decision_payload_invalid".to_owned(),
                };
            };
            self.moderation_decisions
                .insert(decision_id.clone(), decision);
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
        let Ok(decision) = operation.typed_payload::<arkret_wire::event_spec::ModerationDecision>()
        else {
            return ProjectionEffect::Rejected {
                reason: "moderation_decision_payload_invalid".to_owned(),
            };
        };
        self.moderation_decisions
            .insert(decision_id.clone(), decision);
        let mut value = operation.payload.clone();
        if let Value::Object(map) = &mut value {
            map.insert("decision_id".to_owned(), Value::String(decision_id.clone()));
            map.insert("target_ref".to_owned(), Value::String(target_ref));
            map.insert("decision".to_owned(), Value::String(decision_kind));
            map.insert("issuer_id".to_owned(), Value::String(issuer));
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
            .insert(cell_ref, ResolvedCellState::Value(Value::Array(items)));

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
    /// `payload.observed_dot_ids[]`, and requires each dot's `event_id` segment to
    /// equal the `decision_ref` uuid — that pair is the machine-readable form of
    /// "lifting one review must not implicitly lift another issuer's decision". This used to
    /// select by `decision_id` and mark every matching add lifted, which is the
    /// `or_set_remove_observed` shape §2.6 forbids by name for exactly that
    /// reason. Idempotent: re-lifting an already-removed dot converges.
    pub(crate) fn apply_moderation_decision_lift(
        &mut self,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
    ) -> ProjectionEffect {
        let Some(decision_id) = payload_str(operation, "decision_ref") else {
            return ProjectionEffect::Rejected {
                reason: "moderation_lift_decision_ref_missing".to_owned(),
            };
        };
        let Some(target_ref) = payload_str(operation, "target_ref") else {
            return ProjectionEffect::Rejected {
                reason: "moderation_lift_target_ref_missing".to_owned(),
            };
        };
        let Some(observed_dot_ids) = moderation_lift_observed_dots(operation, &decision_id) else {
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
        for dot in &observed_dot_ids {
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
            .insert(cell_ref, ResolvedCellState::Value(Value::Array(items)));

        ProjectionEffect::ModerationDecisionLifted {
            decision_id,
            realm_id,
        }
    }
}
