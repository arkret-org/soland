use arkret_models_collaboration::agent_operations::{
    AgentSidecarEncryptionProfile, AgentSidecarExchangeControlPayload, AgentSidecarState,
};
use arkret_models_collaboration::sidecar_operations::{
    SidecarContextAttachPayload, SidecarContextRef,
};

use super::*;

fn event_derived_sidecar_id(event_ref: &str) -> Option<String> {
    let event_id = arkret_identifiers::EventId::new(event_ref.to_owned()).ok()?;
    let uuid = event_id.as_str().strip_prefix("ak:event:")?;
    arkret_identifiers::SidecarId::new(format!("ak:sidecar:{uuid}"))
        .ok()
        .map(|id| id.to_string())
}

fn context_key(context_ref: &SidecarContextRef) -> String {
    match context_ref {
        SidecarContextRef::Relation { relation_id } => format!("relation:{relation_id}"),
        SidecarContextRef::Strand { strand_id } => format!("strand:{strand_id}"),
    }
}

impl ProjectionState {
    pub(crate) fn apply_sidecar_create(&mut self, operation: &Operation) -> ProjectionEffect {
        let Some(event_ref) = operation.payload.get("event_id").and_then(Value::as_str) else {
            return ProjectionEffect::Rejected {
                reason: "sidecar_create_invalid".to_owned(),
            };
        };
        let Some(sidecar_id) = event_derived_sidecar_id(event_ref) else {
            return ProjectionEffect::Rejected {
                reason: "sidecar_create_invalid".to_owned(),
            };
        };
        let Some(controller_id) = operation.actor() else {
            return ProjectionEffect::Rejected {
                reason: "sidecar_create_invalid".to_owned(),
            };
        };
        let wire_payload = projection_context_stripped_payload(&operation.payload);
        let Some(payload) = wire_payload.as_object() else {
            return ProjectionEffect::Rejected {
                reason: "sidecar_create_invalid".to_owned(),
            };
        };
        let encryption_profile = serde_json::from_value::<AgentSidecarEncryptionProfile>(
            payload
                .get("encryption_profile")
                .cloned()
                .unwrap_or(Value::Null),
        );
        if payload.len() != 1
            || !matches!(
                encryption_profile,
                Ok(AgentSidecarEncryptionProfile::MlsRfc9420)
            )
        {
            return ProjectionEffect::Rejected {
                reason: "sidecar_create_invalid".to_owned(),
            };
        }
        if let Some(existing) = self.sidecars.values().find(|existing| {
            existing.realm_id == operation.realm_id.as_str()
                && existing.controller_id == controller_id.as_str()
                && existing.state != AgentSidecarState::Tombstoned
        }) {
            return if existing.sidecar_id == sidecar_id {
                ProjectionEffect::Ignored
            } else {
                ProjectionEffect::Rejected {
                    reason: "sidecar_singleton_conflict".to_owned(),
                }
            };
        }
        self.sidecars.insert(
            sidecar_id.clone(),
            SidecarProjection {
                sidecar_id: sidecar_id.clone(),
                realm_id: operation.realm_id.to_string(),
                controller_id: controller_id.to_string(),
                encryption_profile: AgentSidecarEncryptionProfile::MlsRfc9420,
                state: AgentSidecarState::Active,
                state_changed_at: None,
                created_at: operation.created_at,
                updated_at: None,
            },
        );
        self.sidecar_create_refs
            .insert(sidecar_id, event_ref.to_owned());
        ProjectionEffect::Ignored
    }

    pub(crate) fn apply_sidecar_context_attach(
        &mut self,
        operation: &Operation,
    ) -> ProjectionEffect {
        let Some(attach_event_ref) = operation.payload.get("event_id").and_then(Value::as_str)
        else {
            return ProjectionEffect::Rejected {
                reason: "sidecar_context_attach_invalid".to_owned(),
            };
        };
        if arkret_identifiers::EventId::new(attach_event_ref.to_owned()).is_err() {
            return ProjectionEffect::Rejected {
                reason: "sidecar_context_attach_invalid".to_owned(),
            };
        }
        let Ok(payload) = serde_json::from_value::<SidecarContextAttachPayload>(
            projection_context_stripped_payload(&operation.payload),
        ) else {
            return ProjectionEffect::Rejected {
                reason: "sidecar_context_attach_invalid".to_owned(),
            };
        };
        if payload.validate().is_err() {
            return ProjectionEffect::Rejected {
                reason: "sidecar_context_attach_invalid".to_owned(),
            };
        }
        let Some(sidecar) = self.sidecars.get(payload.sidecar_id.as_str()) else {
            return ProjectionEffect::Rejected {
                reason: "sidecar_context_attach_invalid".to_owned(),
            };
        };
        if sidecar.realm_id != operation.realm_id.as_str()
            || operation.actor().as_ref().map(|id| id.as_str())
                != Some(sidecar.controller_id.as_str())
        {
            return ProjectionEffect::Rejected {
                reason: "sidecar_context_attach_invalid".to_owned(),
            };
        }
        let source_exists_in_realm = match &payload.source_context_ref {
            SidecarContextRef::Relation { relation_id } => self
                .relations
                .get(relation_id.as_str())
                .is_some_and(|relation| relation.realm_id == sidecar.realm_id),
            SidecarContextRef::Strand { strand_id } => self
                .strands
                .get(strand_id.as_str())
                .is_some_and(|strand| strand.realm_id == sidecar.realm_id),
        };
        if !source_exists_in_realm {
            return ProjectionEffect::Rejected {
                reason: "sidecar_context_attach_invalid".to_owned(),
            };
        }

        let key = (
            payload.sidecar_id.to_string(),
            context_key(&payload.source_context_ref),
        );
        match self.sidecar_contexts.get(&key) {
            None if payload.version != 1 || payload.predecessor_event_ref.is_some() => {
                return ProjectionEffect::Rejected {
                    reason: "sidecar_context_attach_invalid".to_owned(),
                };
            }
            Some(previous)
                if payload.version != previous.version + 1
                    || payload
                        .predecessor_event_ref
                        .as_ref()
                        .map(ToString::to_string)
                        != Some(previous.attach_event_ref.clone()) =>
            {
                return ProjectionEffect::Rejected {
                    reason: "sidecar_context_attach_invalid".to_owned(),
                };
            }
            _ => {}
        }
        let normalized_context_ref = serde_json::to_value(&payload.source_context_ref)
            .expect("SidecarContextRef serialization is infallible");
        self.sidecar_contexts.insert(
            key,
            SidecarContextProjection {
                sidecar_id: payload.sidecar_id.to_string(),
                normalized_context_ref,
                version: payload.version,
                predecessor_event_ref: payload.predecessor_event_ref.map(|id| id.to_string()),
                attach_event_ref: attach_event_ref.to_owned(),
                created_at: operation.created_at,
            },
        );
        ProjectionEffect::Ignored
    }

    /// The encrypted exchange log is projection-free. Admission binds it to
    /// an existing native Sidecar context mapping; no Circle/Strand surrogate
    /// is consulted or created.
    pub(crate) fn apply_sidecar_exchange_control(
        &mut self,
        operation: &Operation,
    ) -> ProjectionEffect {
        const REASON: &str = "sidecar_exchange_control_forbidden";
        let Ok(payload) = serde_json::from_value::<AgentSidecarExchangeControlPayload>(
            projection_context_stripped_payload(&operation.payload),
        ) else {
            return ProjectionEffect::Rejected {
                reason: REASON.to_owned(),
            };
        };
        let Some(sidecar) = self.sidecars.get(payload.sidecar_id.as_str()) else {
            return ProjectionEffect::Rejected {
                reason: REASON.to_owned(),
            };
        };
        if sidecar.realm_id != operation.realm_id.as_str()
            || operation.actor().as_ref().map(|id| id.as_str())
                != Some(sidecar.controller_id.as_str())
            || payload.encrypted_payload.validate().is_err()
            || !self.sidecar_contexts.contains_key(&(
                payload.sidecar_id.to_string(),
                context_key(&payload.source_context_ref),
            ))
        {
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

    fn create(event_suffix: &str) -> Operation {
        Operation::create(
            arkret_identifiers::OperationId::new(
                "ak:operation:01964137-0000-7000-8000-000000000040",
            )
            .unwrap(),
            arkret_identifiers::RealmId::new(
                "ak:realm:AQcksDTzb8Sxrn1BUVVlHtH4vBOy99RKUB4EwOq_413b",
            )
            .unwrap(),
            arkret_wire::EventKind::SIDECAR_CREATE,
            serde_json::json!({
                "encryption_profile": "mls_rfc9420",
                "event_id": format!("ak:event:{event_suffix}"),
                "sender": "did:web:example.com:users:alice"
            }),
        )
    }

    #[test]
    fn sidecar_create_retypes_event_and_never_creates_circle_membership() {
        let mut state = ProjectionState::default();
        let first = create("01964137-0000-8000-8000-000000000042");
        assert!(matches!(
            state.apply(&first, &ServerHlc::new("sidecar-test")),
            ProjectionEffect::Ignored
        ));
        assert!(
            state
                .sidecars
                .contains_key("ak:sidecar:AUbhLbszCE22Bm-rjOxxh9NLjudxjc1Jm38OX5PZttdw")
        );
        assert!(state.circles.is_empty());
        assert!(state.circle_memberships.is_empty());
        assert_eq!(
            state
                .sidecar_create_refs
                .get("ak:sidecar:AUbhLbszCE22Bm-rjOxxh9NLjudxjc1Jm38OX5PZttdw")
                .map(String::as_str),
            Some("ak:event:AUbhLbszCE22Bm-rjOxxh9NLjudxjc1Jm38OX5PZttdw")
        );

        let second = create("01964137-0000-8000-8000-000000000043");
        assert!(matches!(
            state.apply(&second, &ServerHlc::new("sidecar-test")),
            ProjectionEffect::Rejected { reason } if reason == "sidecar_singleton_conflict"
        ));
    }
}
