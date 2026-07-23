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

    /// `ak.agent.sidecar.exchange.control` (zh/models/sidecar.md §7.2.3).
    /// The Event is a durable, controller-authored ordered-log entry whose
    /// plaintext only controller devices can read: the reducer verifies the
    /// outer routing shape and the Sidecar backing-Circle scope, then leaves
    /// projections untouched — exchange folding is client-side only. One
    /// uniform rejection reason avoids Sidecar existence disclosure.
    pub(crate) fn apply_sidecar_exchange_control(
        &mut self,
        operation: &Operation,
    ) -> ProjectionEffect {
        const REASON: &str = "sidecar_exchange_control_forbidden";
        let Some(strand_id) = operation.payload.get("strand_id").and_then(Value::as_str) else {
            return ProjectionEffect::Rejected {
                reason: REASON.to_owned(),
            };
        };
        if !operation
            .payload
            .get("encrypted_payload")
            .is_some_and(Value::is_object)
        {
            return ProjectionEffect::Rejected {
                reason: REASON.to_owned(),
            };
        }
        let sidecar_scoped = self
            .strand_scope_circle_id(strand_id)
            .is_some_and(|circle_id| {
                self.sidecars
                    .values()
                    .any(|sidecar| sidecar.backing_circle_id == circle_id)
            });
        if !sidecar_scoped {
            return ProjectionEffect::Rejected {
                reason: REASON.to_owned(),
            };
        }
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

    fn exchange_control(strand_id: &str, payload: serde_json::Value) -> Operation {
        Operation::create(
            arkret_identifiers::OperationId::new(
                "ak:operation:01964137-0000-7000-8000-000000000050",
            )
            .unwrap(),
            arkret_identifiers::RealmId::new("ak:realm:01964137-0000-7000-8000-000000000030")
                .unwrap(),
            arkret_wire::events::EventKind::AGENT_SIDECAR_EXCHANGE_CONTROL,
            serde_json::json!({
                "strand_id": strand_id,
                "encrypted_payload": payload,
            }),
        )
    }

    #[test]
    fn exchange_control_requires_sidecar_backing_scope_and_stays_projection_free() {
        let mut state = ProjectionState::default();
        state.apply(
            &create("ak:sidecar:01964137-0000-7000-8000-000000000042"),
            &ServerHlc::new("sidecar-test"),
        );
        let private_strand = "ak:strand:01964137-0000-7000-8000-000000000044";
        state.strands.insert(
            private_strand.to_owned(),
            crate::reducer::projections::StrandProjection {
                strand_id: private_strand.to_owned(),
                realm_id: "ak:realm:01964137-0000-7000-8000-000000000030".to_owned(),
                tracks: BTreeMap::new(),
                title: String::new(),
                summary: None,
                fields: BTreeMap::new(),
                state: crate::reducer::projections::ObjectLifecycleState::Active,
                state_changed_at: None,
                created_by: "did:web:example.com:users:alice".to_owned(),
                created_at: chrono::Utc::now(),
                history_basis_seals: Vec::new(),
                updated_by: None,
                updated_at: None,
                scope_circle_id: Some("ak:circle:01964137-0000-7000-8000-000000000041".to_owned()),
            },
        );

        let before = state.clone();
        let accepted = exchange_control(private_strand, serde_json::json!({"ciphertext": "AAA"}));
        assert!(matches!(
            state.apply(&accepted, &ServerHlc::new("sidecar-test")),
            ProjectionEffect::Ignored
        ));
        assert_eq!(
            state.sidecars, before.sidecars,
            "exchange control never mutates server projections"
        );
        assert_eq!(state.strands, before.strands);

        let ordinary_strand = "ak:strand:01964137-0000-7000-8000-000000000045";
        let outside_scope = exchange_control(ordinary_strand, serde_json::json!({"c": "AAA"}));
        assert!(matches!(
            state.apply(&outside_scope, &ServerHlc::new("sidecar-test")),
            ProjectionEffect::Rejected { reason } if reason == "sidecar_exchange_control_forbidden"
        ));

        let plaintext = exchange_control(private_strand, serde_json::Value::Null);
        assert!(matches!(
            state.apply(&plaintext, &ServerHlc::new("sidecar-test")),
            ProjectionEffect::Rejected { reason } if reason == "sidecar_exchange_control_forbidden"
        ));
    }
}
