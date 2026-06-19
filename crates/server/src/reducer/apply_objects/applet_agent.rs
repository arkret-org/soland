//! `ProjectionState::apply_applet_*` / `apply_agent_*` reducers. Inherent-impl
//! block on `ProjectionState`; methods resolve by type, so cross-family
//! `self.apply_*` / `self.check_*` calls are unaffected.

use super::*;

impl ProjectionState {
    /// Apply `ck.applet.registration`. Upserts the
    /// AppletProjection keyed by `service_did`. Re-registration with
    /// the same DID is allowed (replace capabilities + bump
    /// updated_at), matching the spec convention that registration is
    /// idempotent for the same identity.
    pub(crate) fn apply_applet_registration(
        &mut self,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
    ) -> ProjectionEffect {
        let Some(service_did) = operation
            .payload
            .get("service_did")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned)
        else {
            return ProjectionEffect::Rejected {
                reason: "applet_registration_missing_service_did".to_owned(),
            };
        };
        let namespace = operation
            .payload
            .get("namespace")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_owned();
        let capabilities = operation.payload.get("capabilities").cloned();
        let existing_manifest = self
            .applets
            .get(&service_did)
            .and_then(|p| p.manifest.clone());
        let registered_at = self
            .applets
            .get(&service_did)
            .map(|p| p.registered_at)
            .unwrap_or(now);
        let projection = AppletProjection {
            service_did: service_did.clone(),
            namespace,
            manifest: existing_manifest,
            capabilities,
            registered_at,
            updated_at: now,
        };
        self.applets.insert(service_did.clone(), projection);
        ProjectionEffect::AppletProjectionUpdated { service_did }
    }

    /// Apply `ck.applet.discovery`. Updates the manifest
    /// on an existing AppletProjection. If the applet hasn't registered
    /// yet (causal / backfill window), creates a stub entry with the
    /// manifest and empty namespace; subsequent registration will fill
    /// in the namespace + capabilities.
    pub(crate) fn apply_applet_discovery(
        &mut self,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
    ) -> ProjectionEffect {
        let Some(service_did) = operation
            .payload
            .get("service_did")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned)
        else {
            return ProjectionEffect::Rejected {
                reason: "applet_discovery_missing_service_did".to_owned(),
            };
        };
        let manifest = operation.payload.get("manifest").cloned();
        let entry = self
            .applets
            .entry(service_did.clone())
            .or_insert_with(|| AppletProjection {
                service_did: service_did.clone(),
                namespace: String::new(),
                manifest: None,
                capabilities: None,
                registered_at: now,
                updated_at: now,
            });
        entry.manifest = manifest;
        entry.updated_at = now;
        ProjectionEffect::AppletProjectionUpdated { service_did }
    }

    /// Apply `ck.agent.endpoint`. Upserts the SolandAgentProjection keyed by
    /// `agent_id`. If the payload carries an endpoint URL field it
    /// is captured into the projection so the bridge can echo it back
    /// on `interop_session.result`.
    pub(crate) fn apply_agent_endpoint(
        &mut self,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
    ) -> ProjectionEffect {
        let Some(agent_id) = operation
            .payload
            .get("agent_id")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned)
        else {
            return ProjectionEffect::Rejected {
                reason: "agent_endpoint_missing_agent_id".to_owned(),
            };
        };
        match self
            .agent_lifecycles
            .get(&agent_id)
            .copied()
            .unwrap_or_default()
        {
            AgentLifecycleState::Active => {}
            AgentLifecycleState::Paused => {
                return ProjectionEffect::Rejected {
                    reason: "agent_paused".to_owned(),
                };
            }
            AgentLifecycleState::Deactivated => {
                return ProjectionEffect::Rejected {
                    reason: "agent_deactivated".to_owned(),
                };
            }
        }
        let first_endpoint = operation
            .payload
            .get("endpoints")
            .and_then(|v| v.as_array())
            .and_then(|items| items.first());
        let protocol = operation
            .payload
            .get("protocol")
            .and_then(|v| v.as_str())
            .or_else(|| {
                first_endpoint
                    .and_then(|v| v.get("protocol"))
                    .and_then(|v| v.as_str())
            })
            .unwrap_or("")
            .to_owned();
        let endpoint_url = operation
            .payload
            .get("endpoint_url")
            .and_then(|v| v.as_str())
            .or_else(|| {
                first_endpoint
                    .and_then(|v| v.get("endpoint_url"))
                    .and_then(|v| v.as_str())
            })
            .or_else(|| {
                first_endpoint
                    .and_then(|v| v.get("url"))
                    .and_then(|v| v.as_str())
            })
            .map(ToOwned::to_owned);
        let registered_at = self
            .agents
            .get(&agent_id)
            .map(|p| p.registered_at)
            .unwrap_or(now);
        let projection = SolandAgentProjection {
            agent_id: agent_id.clone(),
            protocol,
            endpoint_url,
            registered_at,
            updated_at: now,
        };
        self.agents.insert(agent_id.clone(), projection);
        ProjectionEffect::AgentProjectionUpdated { agent_id }
    }

    /// REDU-1 (R3 spec-sync 2026-05-27, cokret-spec b47ff6ec) — apply
    /// an `ck.agent.{pause,resume,deactivate}` FSM transition. The
    /// lattice is `fsm` with `bottom=reject`; allowed transitions are:
    ///   - Active → Paused                 via `ck.self.agent.pause`
    ///   - Paused → Active                 via `ck.self.agent.resume`
    ///   - {Active,Paused} → Deactivated   via `ck.self.agent.deactivate`
    ///
    /// `Deactivated` is terminal — any further transition (including a
    /// resume) is rejected.
    pub fn apply_agent_lifecycle(
        &mut self,
        operation: &Operation,
        target: AgentLifecycleState,
    ) -> ProjectionEffect {
        let Some(agent_principal_id) = operation
            .payload
            .get("agent_principal_id")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned)
        else {
            return ProjectionEffect::Rejected {
                reason: "agent_lifecycle_missing_agent_principal_id".to_owned(),
            };
        };
        let current = self
            .agent_lifecycles
            .get(&agent_principal_id)
            .copied()
            .unwrap_or_default();
        // FSM guard. Terminal `Deactivated` rejects any transition.
        let allowed = match (current, target) {
            (AgentLifecycleState::Active, AgentLifecycleState::Paused)
            | (AgentLifecycleState::Paused, AgentLifecycleState::Active)
            | (AgentLifecycleState::Active, AgentLifecycleState::Deactivated)
            | (AgentLifecycleState::Paused, AgentLifecycleState::Deactivated) => true,
            // Idempotent identity transitions are accepted as no-op
            // (the FSM lattice deduplicates redundant pause/resume).
            (a, b) if a == b => true,
            // Bottom=reject; specifically deactivate is terminal so
            // any resume/pause after deactivate is rejected with the
            // spec-canonical `agent_deactivated` reason code.
            _ => false,
        };
        if !allowed {
            let reason = if current == AgentLifecycleState::Deactivated {
                "agent_deactivated"
            } else {
                "invalid_agent_lifecycle_transition"
            };
            return ProjectionEffect::Rejected {
                reason: reason.to_owned(),
            };
        }
        self.agent_lifecycles
            .insert(agent_principal_id.clone(), target);
        if matches!(
            target,
            AgentLifecycleState::Paused | AgentLifecycleState::Deactivated
        ) {
            self.revoke_agent_runtime_bindings(&agent_principal_id, target, operation);
        }
        ProjectionEffect::AgentLifecycleProjected {
            agent_principal_id,
            new_state: target,
        }
    }

    pub(crate) fn apply_agent_action_request(&mut self, operation: &Operation) -> ProjectionEffect {
        let Some(agent_principal_id) = operation
            .payload
            .get("agent_principal_id")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned)
        else {
            return ProjectionEffect::Rejected {
                reason: "agent_action_request_missing_agent_principal_id".to_owned(),
            };
        };
        let Some(request_id) = operation
            .payload
            .get("request_id")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned)
        else {
            return ProjectionEffect::Rejected {
                reason: "agent_action_request_missing_request_id".to_owned(),
            };
        };
        match self
            .agent_lifecycles
            .get(&agent_principal_id)
            .copied()
            .unwrap_or_default()
        {
            AgentLifecycleState::Active => {}
            AgentLifecycleState::Paused => {
                return ProjectionEffect::Rejected {
                    reason: "agent_paused".to_owned(),
                };
            }
            AgentLifecycleState::Deactivated => {
                return ProjectionEffect::Rejected {
                    reason: "agent_deactivated".to_owned(),
                };
            }
        }

        let should_insert = self
            .agent_action_requests
            .get(&request_id)
            .is_none_or(|existing| existing.status == AgentActionRequestStatus::Pending);
        if should_insert {
            self.agent_action_requests.insert(
                request_id.clone(),
                AgentActionRequestProjection {
                    request_id,
                    agent_principal_id,
                    status: AgentActionRequestStatus::Pending,
                    requested_at: operation.created_at,
                    resolved_at: None,
                    resolution_event_id: None,
                    cancel_reason: None,
                },
            );
        }
        ProjectionEffect::AgentPrivateEventAccepted {
            kind: crate::kinds::CK_AGENT_ACTION_REQUEST,
            event_id: operation.operation_id.to_string(),
        }
    }

    pub(crate) fn apply_agent_action_resolution(
        &mut self,
        operation: &Operation,
        status: AgentActionRequestStatus,
    ) -> ProjectionEffect {
        let Some(request_id) = operation
            .payload
            .get("request_id")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned)
        else {
            return ProjectionEffect::Rejected {
                reason: "agent_action_resolution_missing_request_id".to_owned(),
            };
        };
        if let Some(request) = self.agent_action_requests.get_mut(&request_id)
            && request.status == AgentActionRequestStatus::Pending
        {
            request.status = status;
            request.resolved_at = Some(operation.created_at);
            request.resolution_event_id = Some(operation.operation_id.to_string());
            request.cancel_reason = None;
        }
        let kind = match status {
            AgentActionRequestStatus::Approved => crate::kinds::CK_AGENT_ACTION_APPROVE,
            AgentActionRequestStatus::Rejected => crate::kinds::CK_AGENT_ACTION_REJECT,
            AgentActionRequestStatus::Pending | AgentActionRequestStatus::Cancelled => {
                crate::kinds::CK_AGENT_ACTION_REQUEST
            }
        };
        ProjectionEffect::AgentPrivateEventAccepted {
            kind,
            event_id: operation.operation_id.to_string(),
        }
    }

    fn revoke_agent_runtime_bindings(
        &mut self,
        agent_principal_id: &str,
        target: AgentLifecycleState,
        operation: &Operation,
    ) {
        self.agents.remove(agent_principal_id);
        let reason = match target {
            AgentLifecycleState::Paused => "agent_paused",
            AgentLifecycleState::Deactivated => "agent_deactivated",
            AgentLifecycleState::Active => return,
        };
        for request in self.agent_action_requests.values_mut() {
            if request.agent_principal_id == agent_principal_id
                && request.status == AgentActionRequestStatus::Pending
            {
                request.status = AgentActionRequestStatus::Cancelled;
                request.resolved_at = Some(operation.created_at);
                request.resolution_event_id = Some(operation.operation_id.to_string());
                request.cancel_reason = Some(reason.to_owned());
            }
        }
    }
}
