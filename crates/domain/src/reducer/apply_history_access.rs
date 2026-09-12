use super::*;

const REALM_HISTORY_ACCESS_CELL: &str = "ak:cell:ak.component.realm.history_access.v1:null";
const CIRCLE_HISTORY_ACCESS_FAMILY: &str = arkret_wire::CellFamilyId::CIRCLE_HISTORY_ACCESS_V1;

fn valid_history_access(value: &str) -> bool {
    matches!(value, "since_join" | "all_history_for_current_members")
}

fn valid_ratchet(from: &str, to: &str) -> bool {
    matches!(
        (from, to),
        ("all_history_for_current_members", "since_join") | ("since_join", "since_join")
    )
}

impl ProjectionState {
    pub(crate) fn apply_realm_history_access(&mut self, operation: &Operation) -> ProjectionEffect {
        let from = operation.payload.get("from").and_then(Value::as_str);
        let Some(to) = operation.payload.get("to").and_then(Value::as_str) else {
            return ProjectionEffect::Rejected {
                reason: arkret_wire::ErrorCode::SCHEMA_VIOLATION.to_owned(),
            };
        };
        if !valid_history_access(to) {
            return ProjectionEffect::Rejected {
                reason: arkret_wire::ErrorCode::SCHEMA_VIOLATION.to_owned(),
            };
        }

        let realm_id = operation.realm_id.to_string();
        let key = (realm_id.clone(), REALM_HISTORY_ACCESS_CELL.to_owned());
        let current = self
            .realm_null_subject_cells
            .get(&key)
            .and_then(|state| match state {
                ResolvedCellState::Value(Value::String(value)) => Some(value.as_str()),
                _ => None,
            });
        match current {
            None if from.is_none() => {}
            None => {
                return ProjectionEffect::Rejected {
                    reason: arkret_wire::ErrorCode::CAS_CONFLICT.to_owned(),
                };
            }
            Some(current) => {
                if from != Some(current) {
                    return ProjectionEffect::Rejected {
                        reason: arkret_wire::ErrorCode::CAS_CONFLICT.to_owned(),
                    };
                }
                if !valid_ratchet(current, to) {
                    return ProjectionEffect::Rejected {
                        reason: "history_access_widening_forbidden".to_owned(),
                    };
                }
            }
        }
        if (self.realm_is_direct_conversation(&realm_id)
            || self.realm_is_principal_control(&realm_id))
            && to != "since_join"
        {
            return ProjectionEffect::Rejected {
                reason: "history_access_profile_fixed".to_owned(),
            };
        }

        self.realm_null_subject_cells
            .insert(key, ResolvedCellState::Value(Value::String(to.to_owned())));
        ProjectionEffect::RealmBootstrapFacetProjected {
            realm_id,
            kind: arkret_wire::EventKind::RealmHistoryAccess
                .as_str()
                .to_owned(),
        }
    }

    pub(crate) fn apply_circle_history_access(
        &mut self,
        operation: &Operation,
    ) -> ProjectionEffect {
        let Some(circle_id) = operation
            .payload
            .get("circle_id")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
        else {
            return ProjectionEffect::Rejected {
                reason: arkret_wire::ErrorCode::SCHEMA_VIOLATION.to_owned(),
            };
        };
        let from = operation.payload.get("from").and_then(Value::as_str);
        let Some(to) = operation.payload.get("to").and_then(Value::as_str) else {
            return ProjectionEffect::Rejected {
                reason: arkret_wire::ErrorCode::SCHEMA_VIOLATION.to_owned(),
            };
        };
        if !valid_history_access(to) {
            return ProjectionEffect::Rejected {
                reason: arkret_wire::ErrorCode::SCHEMA_VIOLATION.to_owned(),
            };
        }
        let Some(circle) = self.circles.get_mut(&circle_id) else {
            return ProjectionEffect::Rejected {
                reason: "circle_not_found".to_owned(),
            };
        };
        if circle.realm_id != operation.realm_id.as_str() {
            return ProjectionEffect::Rejected {
                reason: "circle_realm_mismatch".to_owned(),
            };
        }
        if from != Some(circle.history_access.as_str()) {
            return ProjectionEffect::Rejected {
                reason: arkret_wire::ErrorCode::CAS_CONFLICT.to_owned(),
            };
        }
        if !valid_ratchet(circle.history_access.as_str(), to) {
            return ProjectionEffect::Rejected {
                reason: "history_access_widening_forbidden".to_owned(),
            };
        }

        circle.history_access = to.to_owned();
        let Ok(cell) = arkret_identifiers::CellRef::new(format!(
            "ak:cell:{CIRCLE_HISTORY_ACCESS_FAMILY}:{circle_id}"
        )) else {
            return ProjectionEffect::Rejected {
                reason: arkret_wire::ReasonCode::REDUCER_PROJECTION_FAILED.to_owned(),
            };
        };
        self.cells
            .insert(cell, ResolvedCellState::Value(Value::String(to.to_owned())));
        ProjectionEffect::CircleLifecycle {
            circle_id,
            new_state: CircleLifecycleState::Active,
        }
    }
}
