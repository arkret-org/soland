use arkret_models_collaboration::events_payloads::{PolicyActionStatePayload, PolicyActionSubject};
use arkret_schema::{ApprovalRequirementEligibility, capability_action_descriptor};
use arkret_wire::CapabilityActionId;

use super::*;

/// Admission-time checks of a closed `ak.policy.action` payload beyond its
/// SDK shape: the action is a registered capability action, and a required
/// approval names an action with a registered approval evidence carrier.
fn validate_policy_action(payload: &PolicyActionStatePayload) -> Result<(), &'static str> {
    payload
        .validate()
        .map_err(|_| arkret_wire::ErrorCode::SCHEMA_VIOLATION)?;
    let action = CapabilityActionId::from_wire(payload.value.action.as_str())
        .ok_or(arkret_wire::ErrorCode::SCHEMA_VIOLATION)?;
    if payload.value.approval_required {
        let descriptor = capability_action_descriptor(action);
        if descriptor.approval_evidence_carrier_id.is_none()
            || descriptor.approval_requirement_eligibility
                == ApprovalRequirementEligibility::IneligibleNoRegisteredCarrier
        {
            return Err(arkret_wire::ErrorCode::SCHEMA_VIOLATION);
        }
    }
    Ok(())
}

impl ProjectionState {
    /// Project the complete Policy document. The accepted payload has already
    /// passed the JSON schema; parsing the SDK's closed type here retains the
    /// semantic `policy_id == document id` check at the write boundary.
    pub(crate) fn apply_policy_set(&mut self, operation: &Operation) -> ProjectionEffect {
        let payload = match operation.typed_payload::<arkret_wire::event_spec::PolicySet>() {
            Ok(payload) if payload.validate().is_ok() => payload,
            _ => {
                return ProjectionEffect::Rejected {
                    reason: arkret_wire::ErrorCode::SCHEMA_VIOLATION.to_owned(),
                };
            }
        };
        let policy_id = payload.policy_id.to_string();
        let realm_id = operation.realm_id.to_string();
        let Some(value) = operation.payload.get("value").cloned() else {
            return ProjectionEffect::Rejected {
                reason: arkret_wire::ErrorCode::SCHEMA_VIOLATION.to_owned(),
            };
        };
        self.set_facet(&realm_id, FacetRef::new(facet::POLICY, &policy_id), value);
        ProjectionEffect::PolicyProjected {
            policy_id,
            realm_id,
        }
    }

    /// Project one Policy approval configuration into one of two disjoint
    /// selector namespaces. The policy branch requires the referenced Policy
    /// to exist in this exact Realm. The Realm-local branch binds its opaque
    /// name to `(action, policy_scope)` on first write and cannot later move it.
    pub(crate) fn apply_policy_action(&mut self, operation: &Operation) -> ProjectionEffect {
        let payload = match operation.typed_payload::<arkret_wire::event_spec::PolicyAction>() {
            Ok(payload) => payload,
            Err(_) => {
                return ProjectionEffect::Rejected {
                    reason: arkret_wire::ErrorCode::SCHEMA_VIOLATION.to_owned(),
                };
            }
        };
        if let Err(reason) = validate_policy_action(&payload) {
            return ProjectionEffect::Rejected {
                reason: reason.to_owned(),
            };
        }
        let realm_id = operation.realm_id.to_string();
        let Some(value) = operation.payload.get("value").cloned() else {
            return ProjectionEffect::Rejected {
                reason: arkret_wire::ErrorCode::SCHEMA_VIOLATION.to_owned(),
            };
        };

        let subject = match payload.subject() {
            Ok(subject) => subject,
            Err(_) => {
                return ProjectionEffect::Rejected {
                    reason: arkret_wire::ErrorCode::SCHEMA_VIOLATION.to_owned(),
                };
            }
        };
        let (selector_kind, selector, target) = match subject {
            PolicyActionSubject::Policy(policy_id) => {
                let policy_id = policy_id.to_string();
                if self
                    .facet_value(&realm_id, &FacetRef::new(facet::POLICY, &policy_id))
                    .is_none()
                {
                    return ProjectionEffect::Rejected {
                        reason: "policy_action_policy_unavailable".to_owned(),
                    };
                }
                let action = payload.value.action.as_str();
                (
                    "policy_ref",
                    format!("{policy_id}/{action}"),
                    FacetRef::composite(
                        facet::POLICY_ACTION_POLICY_REF,
                        &[policy_id.as_str(), action],
                    ),
                )
            }
            PolicyActionSubject::Action(action_id) => {
                let target = FacetRef::new(facet::POLICY_ACTION_REALM_ACTION, action_id.as_str());
                if let Some(current) = self.facet_value(&realm_id, &target)
                    && (current.get("action").and_then(Value::as_str)
                        != Some(payload.value.action.as_str())
                        || current.get("policy_scope").and_then(Value::as_str)
                            != Some(payload.value.policy_scope.as_str()))
                {
                    return ProjectionEffect::Rejected {
                        reason: arkret_wire::ErrorCode::CAS_CONFLICT.to_owned(),
                    };
                }
                ("realm_action", action_id.as_str().to_owned(), target)
            }
        };

        self.set_facet(&realm_id, target, value);
        ProjectionEffect::PolicyActionProjected {
            selector_kind,
            selector,
            realm_id,
        }
    }
}
