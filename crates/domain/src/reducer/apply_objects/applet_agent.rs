//! `ProjectionState::apply_applet_*` / `apply_agent_*` reducers. Inherent-impl
//! block on `ProjectionState`; methods resolve by type, so cross-family
//! `self.apply_*` / `self.check_*` calls are unaffected.

use super::*;

impl ProjectionState {
    /// Apply `ak.applet.registration`. Upserts the
    /// AppletProjection keyed by `applet_id`. Re-registration with
    /// the same Applet id is allowed (replace capabilities + bump
    /// updated_at), matching the spec convention that registration is
    /// idempotent for the same identity.
    pub(crate) fn apply_applet_registration(
        &mut self,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
    ) -> ProjectionEffect {
        let Some(service_id) = operation
            .payload
            .get("service_id")
            .and_then(|v| v.as_str())
            .and_then(|value| arkret_identifiers::DidCoreId::new(value.to_owned()).ok())
        else {
            return ProjectionEffect::Rejected {
                reason: "applet_registration_missing_service_id".to_owned(),
            };
        };
        let Some(applet_id) = operation
            .payload
            .get("applet_id")
            .and_then(|value| value.as_str())
            .and_then(|value| arkret_wire::AppletId::new(value.to_owned()).ok())
        else {
            return ProjectionEffect::Rejected {
                reason: "applet_registration_missing_applet_id".to_owned(),
            };
        };
        let Some(registration_epoch) = operation
            .payload
            .get("registration_epoch")
            .and_then(|value| value.as_str())
            .map(ToOwned::to_owned)
        else {
            return ProjectionEffect::Rejected {
                reason: "applet_registration_missing_registration_epoch".to_owned(),
            };
        };
        let Some(claimed_profiles) = operation
            .payload
            .get("claimed_profiles")
            .and_then(|value| value.as_array())
            .map(|values| {
                values
                    .iter()
                    .filter_map(|value| value.as_str().map(ToOwned::to_owned))
                    .collect::<Vec<_>>()
            })
            .filter(|values| !values.is_empty())
        else {
            return ProjectionEffect::Rejected {
                reason: "applet_registration_missing_claimed_profiles".to_owned(),
            };
        };
        let registration_scope_ref =
            serde_json::to_value(&operation.context.accepted_scope_ref).ok();
        let capabilities = operation.payload.get("requested_scopes").cloned();
        let registered_at = self
            .applets
            .get(&applet_id)
            .map(|p| p.registered_at)
            .unwrap_or(now);
        let projection = AppletProjection {
            applet_id: applet_id.clone(),
            service_id: service_id.clone(),
            capabilities,
            claimed_profiles,
            registration_epoch,
            registration_scope_ref,
            registered_at,
            updated_at: now,
        };
        self.applets.insert(applet_id.clone(), projection);
        ProjectionEffect::AppletProjectionUpdated { applet_id }
    }

    /// Apply `ak.applet.discovery` to an existing exact Applet projection.
    /// Discovery never creates a service-keyed or empty-id placeholder.
    pub(crate) fn apply_applet_discovery(
        &mut self,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
    ) -> ProjectionEffect {
        let Some(applet_id) = operation
            .payload
            .get("resource_id")
            .and_then(|v| v.as_str())
            .and_then(|value| arkret_wire::AppletId::new(value.to_owned()).ok())
        else {
            return ProjectionEffect::Rejected {
                reason: "applet_discovery_missing_applet_id".to_owned(),
            };
        };
        let Some(_discovery_value) = operation
            .payload
            .get("value")
            .filter(|value| {
                value
                    .get("resource_kind")
                    .and_then(serde_json::Value::as_str)
                    == Some("applet")
            })
            .cloned()
        else {
            return ProjectionEffect::Rejected {
                reason: "applet_discovery_resource_kind_mismatch".to_owned(),
            };
        };
        let Some(entry) = self.applets.get_mut(&applet_id) else {
            return ProjectionEffect::Rejected {
                reason: "applet_discovery_unknown_applet_id".to_owned(),
            };
        };
        entry.updated_at = now;
        ProjectionEffect::AppletProjectionUpdated { applet_id }
    }

    /// REDU-1 (R3 spec-sync 2026-05-27, arkret-spec b47ff6ec) — apply
    /// an `ak.agent.{pause,resume,deactivate}` FSM transition. The
    /// lattice is `fsm` with `bottom=reject`; allowed transitions are:
    ///   - Active → Paused                 via `ak.self.agent.pause`
    ///   - Paused → Active                 via `ak.self.agent.resume`
    ///   - {Active,Paused} → Deactivated   via `ak.self.agent.deactivate`
    ///
    /// `Deactivated` is terminal — any further transition (including a
    /// resume) is rejected.
    pub fn apply_agent_lifecycle(
        &mut self,
        operation: &Operation,
        target: AgentLifecycleState,
    ) -> ProjectionEffect {
        let Some(agent_id) = operation
            .payload
            .get("agent_id")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned)
        else {
            return ProjectionEffect::Rejected {
                reason: "agent_lifecycle_missing_agent_id".to_owned(),
            };
        };
        let current = self
            .agent_lifecycles
            .get(&agent_id)
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
        self.agent_lifecycles.insert(agent_id.clone(), target);
        if matches!(
            target,
            AgentLifecycleState::Paused | AgentLifecycleState::Deactivated
        ) {
            self.revoke_agent_runtime_bindings(&agent_id, target, operation);
        }
        ProjectionEffect::AgentLifecycleProjected {
            agent_id,
            new_state: target,
        }
    }

    pub(crate) fn apply_agent_action_request(&mut self, operation: &Operation) -> ProjectionEffect {
        let Some(agent_id) = operation
            .payload
            .get("agent_id")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned)
        else {
            return ProjectionEffect::Rejected {
                reason: "agent_action_request_missing_agent_id".to_owned(),
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

        let should_insert = self
            .agent_action_requests
            .get(&request_id)
            .is_none_or(|existing| existing.status == AgentActionRequestStatus::Pending);
        if should_insert {
            self.agent_action_requests.insert(
                request_id.clone(),
                AgentActionRequestProjection {
                    request_id,
                    agent_id,
                    status: AgentActionRequestStatus::Pending,
                    requested_at: operation.created_at,
                    resolved_at: None,
                    resolution_event_id: None,
                    cancel_reason: None,
                    approval: None,
                },
            );
        }
        ProjectionEffect::AgentPrivateEventAccepted {
            kind: arkret_wire::EventKind::AgentActionRequest,
            event_id: operation.operation_id.to_string(),
        }
    }

    pub(crate) fn apply_agent_action_resolution(
        &mut self,
        operation: &Operation,
        status: AgentActionRequestStatus,
    ) -> ProjectionEffect {
        let Some(request_key) = operation
            .payload
            .get("request_id")
            .or_else(|| operation.payload.get("draft_id"))
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned)
        else {
            return ProjectionEffect::Rejected {
                reason: "agent_action_resolution_missing_request_or_draft_id".to_owned(),
            };
        };
        if let Some(request) = self.agent_action_requests.get_mut(&request_key)
            && request.status == AgentActionRequestStatus::Pending
        {
            let approval = if status == AgentActionRequestStatus::Approved {
                let Some(approval_id) = operation
                    .payload
                    .get("approval_id")
                    .and_then(|v| v.as_str())
                    .map(ToOwned::to_owned)
                else {
                    return ProjectionEffect::Rejected {
                        reason: "agent_action_approval_missing_approval_id".to_owned(),
                    };
                };
                let Some(proposed_action) = operation
                    .payload
                    .get("proposed_action")
                    .and_then(|v| v.as_str())
                    .map(ToOwned::to_owned)
                else {
                    return ProjectionEffect::Rejected {
                        reason: "agent_action_approval_missing_proposed_action".to_owned(),
                    };
                };
                let Some(target) = operation.payload.get("target").cloned() else {
                    return ProjectionEffect::Rejected {
                        reason: "agent_action_approval_missing_target".to_owned(),
                    };
                };
                let Some(approved_payload_digest) = operation
                    .payload
                    .get("approved_payload_digest")
                    .and_then(|v| v.as_str())
                    .map(ToOwned::to_owned)
                else {
                    return ProjectionEffect::Rejected {
                        reason: "agent_action_approval_missing_payload_digest".to_owned(),
                    };
                };
                let Some(approval_nonce) = operation
                    .payload
                    .get("approval_nonce")
                    .and_then(|v| v.as_str())
                    .map(ToOwned::to_owned)
                else {
                    return ProjectionEffect::Rejected {
                        reason: "agent_action_approval_missing_nonce".to_owned(),
                    };
                };
                let Some(expires_at) = operation
                    .payload
                    .get("expires_at")
                    .and_then(|v| v.as_str())
                    .and_then(|value| {
                        chrono::DateTime::parse_from_rfc3339(value)
                            .ok()
                            .map(|dt| dt.with_timezone(&chrono::Utc))
                    })
                else {
                    return ProjectionEffect::Rejected {
                        reason: "agent_action_approval_missing_expires_at".to_owned(),
                    };
                };
                Some(AgentActionApprovalProjection {
                    approval_id,
                    proposed_action,
                    target,
                    approved_payload_digest,
                    approval_nonce,
                    expires_at,
                })
            } else {
                None
            };
            request.status = status;
            request.resolved_at = Some(operation.created_at);
            request.resolution_event_id = Some(operation.operation_id.to_string());
            request.cancel_reason = None;
            request.approval = approval;
        }
        let kind = match status {
            AgentActionRequestStatus::Approved => arkret_wire::EventKind::AgentActionApprove,
            AgentActionRequestStatus::Rejected => arkret_wire::EventKind::AgentActionReject,
            AgentActionRequestStatus::Pending | AgentActionRequestStatus::Cancelled => {
                arkret_wire::EventKind::AgentActionRequest
            }
        };
        ProjectionEffect::AgentPrivateEventAccepted {
            kind,
            event_id: operation.operation_id.to_string(),
        }
    }

    fn revoke_agent_runtime_bindings(
        &mut self,
        agent_id: &str,
        target: AgentLifecycleState,
        operation: &Operation,
    ) {
        let reason = match target {
            AgentLifecycleState::Paused => "agent_paused",
            AgentLifecycleState::Deactivated => "agent_deactivated",
            AgentLifecycleState::Active => return,
        };
        for request in self.agent_action_requests.values_mut() {
            if request.agent_id == agent_id && request.status == AgentActionRequestStatus::Pending {
                request.status = AgentActionRequestStatus::Cancelled;
                request.resolved_at = Some(operation.created_at);
                request.resolution_event_id = Some(operation.operation_id.to_string());
                request.cancel_reason = Some(reason.to_owned());
            }
        }
    }
}
