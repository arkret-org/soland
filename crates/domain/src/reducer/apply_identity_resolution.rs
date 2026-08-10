use super::*;

const RESOLUTION_CELL: &str = super::apply_realm_lifecycle::PRINCIPAL_RESOLUTION_CELL;

impl ProjectionState {
    /// Read the resolution singleton of one explicitly selected PCR.
    ///
    /// Multiple PCRs may share a principal core, so this API deliberately
    /// cannot discover a supposedly global current PCR from `principal_id`.
    pub fn principal_resolution_for_realm(&self, realm_id: &str) -> Option<&Value> {
        self.realm_null_subject_cell_value(realm_id, "ak.component.identity.resolution.v1")
    }

    pub(crate) fn apply_identity_resolution_update(
        &mut self,
        operation: &Operation,
    ) -> ProjectionEffect {
        let principal_id = operation.context.sender.as_str();
        if !self.realm_is_principal_control(operation.realm_id.as_str())
            || self
                .realm_states
                .get(operation.realm_id.as_str())
                .and_then(|realm| realm.owner.as_deref())
                != Some(principal_id)
        {
            return ProjectionEffect::Rejected {
                reason: "identity_resolution_wrong_realm".to_owned(),
            };
        }
        let Some(current) = self
            .realm_null_subject_cells
            .get(&(operation.realm_id.to_string(), RESOLUTION_CELL.to_owned()))
            .and_then(|state| match state {
                CellState::Value(value) => Some(value.clone()),
                CellState::Bottom(_) => None,
            })
        else {
            return ProjectionEffect::Rejected {
                reason: "identity_resolution_missing".to_owned(),
            };
        };
        let Some(next) = operation.payload.get("next").and_then(Value::as_object) else {
            return ProjectionEffect::Rejected {
                reason: arkret_wire::ErrorCode::SCHEMA_VIOLATION.to_owned(),
            };
        };
        let valid_next = next
            .get("full_id")
            .and_then(Value::as_str)
            .and_then(|value| arkret_wire::DidFullId::new(value.to_owned()).ok())
            .and_then(|full_id| arkret_wire::project_full_id_to_core_id(&full_id).ok())
            .is_some_and(|projected| projected.as_str() == principal_id)
            && next
                .get("method_history_head")
                .and_then(Value::as_str)
                .is_some_and(|value| !value.is_empty())
            && next
                .get("version_id")
                .and_then(Value::as_str)
                .is_some_and(|value| !value.is_empty());
        if !valid_next
            || operation
                .payload
                .get("previous_resolution_event_ref")
                .and_then(Value::as_str)
                != current.get("resolution_event_ref").and_then(Value::as_str)
            || operation
                .payload
                .get("previous_method_history_head")
                .and_then(Value::as_str)
                != current.get("method_history_head").and_then(Value::as_str)
        {
            return ProjectionEffect::Rejected {
                reason: "identity_resolution_predecessor_mismatch".to_owned(),
            };
        }
        let preconditions = &operation.context.preconditions;
        if preconditions.len() != 1
            || preconditions[0].cell.as_str() != RESOLUTION_CELL
            || preconditions[0].predicate.op != arkret_wire::cba::PredicateOp::HeadEq
            || preconditions[0].predicate.value.as_ref() != Some(&current)
        {
            return ProjectionEffect::Rejected {
                reason: arkret_wire::ErrorCode::FAILED_PRECONDITION.to_owned(),
            };
        }

        let mut expected = next.clone();
        expected.insert(
            "resolution_event_ref".to_owned(),
            Value::String(operation.context.accepted_event_id.to_string()),
        );
        expected.insert(
            "updated_at".to_owned(),
            Value::String(utc_timestamp_z(operation.created_at)),
        );
        let expected = Value::Object(expected);
        let projected = self
            .projected_cell_writes()
            .iter()
            .filter(|write| write.cell.as_str() == RESOLUTION_CELL)
            .filter_map(ProjectedCellWrite::as_direct)
            .collect::<Vec<_>>();
        if projected.len() != 1
            || projected[0].op.op_type != arkret_wire::cba::LatticeOpType::Set
            || projected[0].op.value.as_ref() != Some(&expected)
        {
            return ProjectionEffect::Rejected {
                reason: arkret_wire::ReasonCode::REDUCER_PROJECTION_FAILED.to_owned(),
            };
        }
        self.realm_null_subject_cells.insert(
            (operation.realm_id.to_string(), RESOLUTION_CELL.to_owned()),
            CellState::Value(expected),
        );
        ProjectionEffect::RealmLifecycle {
            realm_id: operation.realm_id.to_string(),
            action: operation.event_kind.as_str().to_owned(),
        }
    }
}
