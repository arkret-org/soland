use arkret_schema::{ApprovalRequirementEligibility, capability_action_descriptor};
use arkret_wire::{CapabilityActionId, PolicyId};
use serde::Deserialize;

use super::*;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyActionStatePayload {
    #[serde(default)]
    policy_id: Option<PolicyId>,
    #[serde(default)]
    action_id: Option<String>,
    value: PolicyActionValue,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyActionValue {
    action: CapabilityActionId,
    approval_required: bool,
    approval_quorum: u64,
    policy_scope: String,
}

impl PolicyActionValue {
    fn validate(&self) -> Result<(), &'static str> {
        if self.approval_quorum == 0 || !valid_policy_scope(&self.policy_scope) {
            return Err(arkret_wire::ErrorCode::SCHEMA_VIOLATION);
        }
        if self.approval_required {
            let descriptor = capability_action_descriptor(self.action);
            if descriptor.approval_evidence_carrier_id.is_none()
                || descriptor.approval_requirement_eligibility
                    == ApprovalRequirementEligibility::IneligibleNoRegisteredCarrier
            {
                // The registry token `approval_carrier_unregistered` remains
                // reserved, so production must not emit it yet. The accepted
                // active failure shape for an unrepresentable configuration is
                // the generic closed-contract rejection.
                return Err(arkret_wire::ErrorCode::SCHEMA_VIOLATION);
            }
        }
        Ok(())
    }
}

fn valid_policy_scope(scope: &str) -> bool {
    !scope.is_empty()
        && !scope.chars().any(char::is_whitespace)
        && (scope.starts_with("ak:") || scope.starts_with("did:"))
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
        let payload =
            match serde_json::from_value::<PolicyActionStatePayload>(operation.payload.clone()) {
                Ok(payload) if payload.value.validate().is_ok() => payload,
                Ok(payload) => {
                    return ProjectionEffect::Rejected {
                        reason: payload
                            .value
                            .validate()
                            .expect_err("guard established invalid value")
                            .to_owned(),
                    };
                }
                Err(_) => {
                    return ProjectionEffect::Rejected {
                        reason: arkret_wire::ErrorCode::SCHEMA_VIOLATION.to_owned(),
                    };
                }
            };
        let realm_id = operation.realm_id.to_string();
        let Some(value) = operation.payload.get("value").cloned() else {
            return ProjectionEffect::Rejected {
                reason: arkret_wire::ErrorCode::SCHEMA_VIOLATION.to_owned(),
            };
        };

        let (selector_kind, selector, target) = match (&payload.policy_id, &payload.action_id) {
            (Some(policy_id), None) => {
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
            (None, Some(action_id)) if !action_id.is_empty() && !action_id.starts_with("ak:") => {
                let target = FacetRef::new(facet::POLICY_ACTION_REALM_ACTION, action_id);
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
                ("realm_action", action_id.clone(), target)
            }
            _ => {
                return ProjectionEffect::Rejected {
                    reason: arkret_wire::ErrorCode::SCHEMA_VIOLATION.to_owned(),
                };
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
