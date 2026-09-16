use super::*;

impl ProjectionState {
    /// Read the resolution singleton of one explicitly selected PCR.
    ///
    /// Multiple PCRs may share a principal core, so this API deliberately
    /// cannot discover a supposedly global current PCR from `principal_id`.
    pub fn principal_resolution_for_realm(&self, realm_id: &str) -> Option<&Value> {
        self.facet_value(realm_id, &FacetRef::singleton(facet::IDENTITY_RESOLUTION))
    }

    pub(crate) fn apply_identity_resolution_update(
        &mut self,
        operation: &Operation,
    ) -> ProjectionEffect {
        let actor_id = operation.context.sender.to_string();
        let principal_id = operation.context.sender.signing_principal_id();
        if !self.realm_is_principal_control(operation.realm_id.as_str())
            || self
                .realm_states
                .get(operation.realm_id.as_str())
                .and_then(|realm| realm.owner.as_deref())
                != Some(actor_id.as_str())
        {
            return ProjectionEffect::Rejected {
                reason: "identity_resolution_wrong_realm".to_owned(),
            };
        }
        let realm_id = operation.realm_id.to_string();
        let resolution = FacetRef::singleton(facet::IDENTITY_RESOLUTION);
        if self.facet_value(&realm_id, &resolution).is_none() {
            return ProjectionEffect::Rejected {
                reason: "identity_resolution_missing".to_owned(),
            };
        }
        let Some(next) = operation.payload.get("next").and_then(Value::as_object) else {
            return ProjectionEffect::Rejected {
                reason: arkret_wire::ErrorCode::SCHEMA_VIOLATION.to_owned(),
            };
        };
        let valid_next = next
            .get("did")
            .and_then(Value::as_str)
            .and_then(|value| arkret_wire::Did::new(value.to_owned()).ok())
            .and_then(|did| arkret_wire::project_did_to_core_id(&did).ok())
            .is_some_and(|projected| &projected == principal_id)
            && next
                .get("method_history_head")
                .and_then(Value::as_str)
                .is_some_and(|value| !value.is_empty())
            && next
                .get("version_id")
                .and_then(Value::as_str)
                .is_some_and(|value| !value.is_empty());
        if !valid_next {
            return ProjectionEffect::Rejected {
                reason: "identity_resolution_predecessor_mismatch".to_owned(),
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
        self.set_facet(&realm_id, resolution, Value::Object(expected));
        ProjectionEffect::RealmLifecycle {
            realm_id,
            action: operation.event_kind.as_str().to_owned(),
        }
    }
}
