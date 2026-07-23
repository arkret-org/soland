use super::*;

impl ProjectionState {
    pub(crate) fn apply_sidecar_create(&mut self, operation: &Operation) -> ProjectionEffect {
        let Some(object) = operation.payload.get("object") else {
            return ProjectionEffect::Rejected {
                reason: "sidecar_create_invalid".to_owned(),
            };
        };
        let Ok(sidecar) = serde_json::from_value::<
            arkret_models_collaboration::agent_operations::AgentSidecar,
        >(object.clone()) else {
            return ProjectionEffect::Rejected {
                reason: "sidecar_create_invalid".to_owned(),
            };
        };
        if sidecar.validate().is_err() || sidecar.realm_id != operation.realm_id {
            return ProjectionEffect::Rejected {
                reason: "sidecar_create_invalid".to_owned(),
            };
        }
        if let Some(existing) = self.sidecars.values().find(|existing| {
            existing.realm_id == sidecar.realm_id.as_str()
                && existing.controller_id == sidecar.controller_id.as_str()
                && existing.state
                    != arkret_models_collaboration::agent_operations::AgentSidecarState::Tombstoned
        }) {
            return if existing.sidecar_id == sidecar.id.as_str() {
                ProjectionEffect::Ignored
            } else {
                ProjectionEffect::Rejected {
                    reason: "sidecar_singleton_conflict".to_owned(),
                }
            };
        }
        let projection = SidecarProjection {
            sidecar_id: sidecar.id.to_string(),
            realm_id: sidecar.realm_id.to_string(),
            controller_id: sidecar.controller_id.to_string(),
            backing_circle_id: sidecar.backing_circle_id.to_string(),
            encryption_profile: sidecar.encryption_profile,
            state: sidecar.state,
            state_changed_at: sidecar.state_changed_at,
            created_at: sidecar.created_at,
            updated_at: sidecar.updated_at,
        };
        self.sidecars
            .insert(projection.sidecar_id.clone(), projection);
        let control_ref = operation
            .payload
            .get("event_id")
            .and_then(Value::as_str)
            .unwrap_or_else(|| operation.operation_id.as_str())
            .to_owned();
        self.sidecar_create_refs
            .insert(sidecar.id.to_string(), control_ref);
        ProjectionEffect::Ignored
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create(sidecar_id: &str) -> Operation {
        Operation::create(
            arkret_identifiers::OperationId::new(
                "ak:operation:01964137-0000-7000-8000-000000000040",
            )
            .unwrap(),
            arkret_identifiers::RealmId::new("ak:realm:01964137-0000-7000-8000-000000000030")
                .unwrap(),
            arkret_wire::events::EventKind::SIDECAR_CREATE,
            serde_json::json!({"object": {
                "id": sidecar_id,
                "schema": "ak.schema.agent_sidecar.v1",
                "realm_id": "ak:realm:01964137-0000-7000-8000-000000000030",
                "controller_id": "did:web:example.com:users:alice",
                "backing_circle_id": "ak:circle:01964137-0000-7000-8000-000000000041",
                "encryption_profile": "mls_rfc9420",
                "state": "active",
                "created_at": "2026-07-20T00:00:00.000Z"
            }}),
        )
    }

    #[test]
    fn sidecar_create_projects_and_enforces_singleton() {
        let mut state = ProjectionState::default();
        let first = create("ak:sidecar:01964137-0000-7000-8000-000000000042");
        assert!(matches!(
            state.apply(&first, &ServerHlc::new("sidecar-test")),
            ProjectionEffect::Ignored
        ));
        assert_eq!(state.sidecars.len(), 1);
        assert_eq!(
            state
                .sidecar_create_refs
                .get("ak:sidecar:01964137-0000-7000-8000-000000000042"),
            Some(&"ak:operation:01964137-0000-7000-8000-000000000040".to_owned())
        );

        let second = create("ak:sidecar:01964137-0000-7000-8000-000000000043");
        assert!(matches!(
            state.apply(&second, &ServerHlc::new("sidecar-test")),
            ProjectionEffect::Rejected { reason } if reason == "sidecar_singleton_conflict"
        ));
    }
}
