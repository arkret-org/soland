//! Capability-based authorization engine.
//!
//! Evaluates grants to determine whether an actor may perform an action
//! on a resource within a space. Default rules:
//! - Owner gets all actions
//! - Member gets read, send, react, edit_own
//! - Explicit grants override defaults

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};

use crate::ids;

/// A capability grant.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Grant {
    pub grant_id: String,
    pub space_id: String,
    pub issuer: String,
    pub subject: String,
    pub resource: String,
    pub actions: Vec<String>,
    #[serde(default)]
    pub constraints: Vec<Constraint>,
    pub revoked: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Constraint {
    pub constraint_type: String,
    pub value: serde_json::Value,
}

/// Result of an authorization check.
#[derive(Clone, Debug, Serialize)]
pub struct AuthzResult {
    pub allowed: bool,
    pub reason: String,
    pub reason_detail: Option<String>,
    pub grants: Vec<Grant>,
}

/// Thread-safe authorization engine.
#[derive(Clone)]
pub struct AuthzEngine {
    grants: Arc<Mutex<BTreeMap<String, Grant>>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum GrantDecision {
    Deny,
    Quarantine,
    Allow,
    RequireReview,
}

impl AuthzEngine {
    pub fn new() -> Self {
        Self {
            grants: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }

    /// Create a new grant.
    pub fn create_grant(
        &self,
        space_id: String,
        issuer: String,
        subject: String,
        resource: String,
        actions: Vec<String>,
        constraints: Vec<Constraint>,
    ) -> Grant {
        let grant = Grant {
            grant_id: ids::generate_grant_id(),
            space_id,
            issuer,
            subject,
            resource,
            actions,
            constraints,
            revoked: false,
            created_at: chrono::Utc::now(),
        };
        self.grants
            .lock()
            .expect("grants lock")
            .insert(grant.grant_id.clone(), grant.clone());
        grant
    }

    /// Revoke a grant.
    pub fn revoke_grant(&self, grant_id: &str) -> bool {
        let mut grants = self.grants.lock().expect("grants lock");
        if let Some(grant) = grants.get_mut(grant_id) {
            grant.revoked = true;
            true
        } else {
            false
        }
    }

    /// Get all grants for a subject in a space.
    pub fn grants_for_subject(&self, subject: &str, space_id: &str) -> Vec<Grant> {
        self.grants
            .lock()
            .expect("grants lock")
            .values()
            .filter(|g| g.subject == subject && g.space_id == space_id && !g.revoked)
            .cloned()
            .collect()
    }

    /// Get all grants in a space.
    pub fn grants_in_space(&self, space_id: &str) -> Vec<Grant> {
        self.grants
            .lock()
            .expect("grants lock")
            .values()
            .filter(|g| g.space_id == space_id && !g.revoked)
            .cloned()
            .collect()
    }

    /// Check if an actor can perform an action on a resource.
    ///
    /// Default rules (when no explicit grants exist):
    /// - Owner of the space → all actions allowed
    /// - Member of the space → read, send, react, edit_own allowed
    /// - Everyone else → denied
    pub fn check(
        &self,
        actor: &str,
        action: &str,
        resource: &str,
        space_id: &str,
        owner: Option<&str>,
        members: &[String],
        resource_facets: &[String],
    ) -> AuthzResult {
        // Check explicit grants first
        let matching_grants: Vec<Grant> = self
            .grants
            .lock()
            .expect("grants lock")
            .values()
            .filter(|g| {
                !g.revoked
                    && g.space_id == space_id
                    && g.subject == actor
                    && g.actions.iter().any(|a| a == action || a == "*")
                    && resource_matches(&g.resource, resource)
            })
            .cloned()
            .collect();

        let mut satisfied_grants: Vec<Grant> = Vec::new();
        let mut first_constraint_reason: Option<String> = None;

        for grant in matching_grants {
            let mut failures = Vec::new();
            let constraints_ok = grant
                .constraints
                .iter()
                .filter(|constraint| !is_decision_constraint(constraint))
                .all(|constraint| {
                    if let Some(reason) =
                        evaluate_constraint(constraint, actor, resource, resource_facets)
                    {
                        failures.push(reason);
                        false
                    } else {
                        true
                    }
                });
            if constraints_ok {
                satisfied_grants.push(grant);
            } else if first_constraint_reason.is_none() {
                first_constraint_reason = failures.into_iter().next();
            }
        }
        if !satisfied_grants.is_empty() {
            if let Some(decision) = highest_priority_decision(&satisfied_grants) {
                return match decision {
                    GrantDecision::Deny => AuthzResult {
                        allowed: false,
                        reason: "explicit_deny".to_owned(),
                        reason_detail: None,
                        grants: satisfied_grants,
                    },
                    GrantDecision::Quarantine => AuthzResult {
                        allowed: false,
                        reason: "quarantine".to_owned(),
                        reason_detail: None,
                        grants: satisfied_grants,
                    },
                    GrantDecision::Allow => AuthzResult {
                        allowed: true,
                        reason: "explicit_grant".to_owned(),
                        reason_detail: None,
                        grants: satisfied_grants,
                    },
                    GrantDecision::RequireReview => AuthzResult {
                        allowed: false,
                        reason: "require_review".to_owned(),
                        reason_detail: None,
                        grants: satisfied_grants,
                    },
                };
            }
        }

        if let Some(reason_detail) = first_constraint_reason {
            return AuthzResult {
                allowed: false,
                reason: "constraints_not_satisfied".to_owned(),
                reason_detail: Some(reason_detail),
                grants: Vec::new(),
            };
        }

        // Default rules
        if owner.is_some_and(|o| o == actor) {
            return AuthzResult {
                allowed: true,
                reason: "owner".to_owned(),
                reason_detail: None,
                grants: Vec::new(),
            };
        }

        if members.iter().any(|m| m == actor) {
            let member_actions = ["read", "send", "react", "edit_own", "space.read"];
            if member_actions.contains(&action) {
                return AuthzResult {
                    allowed: true,
                    reason: "member".to_owned(),
                    reason_detail: None,
                    grants: Vec::new(),
                };
            }
        }

        AuthzResult {
            allowed: false,
            reason: "capability_denied".to_owned(),
            reason_detail: None,
            grants: Vec::new(),
        }
    }
}

impl Default for AuthzEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// Check if a grant resource pattern matches the requested resource.
fn resource_matches(pattern: &str, resource: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    // Exact match
    if pattern == resource {
        return true;
    }
    // Prefix match with wildcard: "space:cx:space:123:*"
    if let Some(prefix) = pattern.strip_suffix('*') {
        return resource.starts_with(prefix);
    }
    false
}

/// Pick the resulting decision over a set of satisfied grants.
///
/// Per Contrix v1 (spec optimization round, _todos B3/B5): the three non-allow
/// decisions — `deny`, `quarantine`, `require_review` — are each *any-hit-wins*
/// in that priority order. `allow` is only the diagnostic fallback when no
/// non-allow decision was raised, so it ranks lowest. This avoids the previous
/// quirk where an `allow` constraint could mask a co-resident `require_review`
/// constraint.
fn highest_priority_decision(grants: &[Grant]) -> Option<GrantDecision> {
    if grants
        .iter()
        .any(|grant| grant_decision(grant) == GrantDecision::Deny)
    {
        return Some(GrantDecision::Deny);
    }
    if grants
        .iter()
        .any(|grant| grant_decision(grant) == GrantDecision::Quarantine)
    {
        return Some(GrantDecision::Quarantine);
    }
    if grants
        .iter()
        .any(|grant| grant_decision(grant) == GrantDecision::RequireReview)
    {
        return Some(GrantDecision::RequireReview);
    }
    if grants
        .iter()
        .any(|grant| grant_decision(grant) == GrantDecision::Allow)
    {
        return Some(GrantDecision::Allow);
    }
    None
}

fn grant_decision(grant: &Grant) -> GrantDecision {
    grant
        .constraints
        .iter()
        .find_map(decision_from_constraint)
        .unwrap_or(GrantDecision::Allow)
}

fn is_decision_constraint(constraint: &Constraint) -> bool {
    decision_from_constraint(constraint).is_some()
}

fn decision_from_constraint(constraint: &Constraint) -> Option<GrantDecision> {
    if !matches!(
        constraint.constraint_type.as_str(),
        "decision" | "effect" | "policy"
    ) {
        return None;
    }
    let value = constraint
        .value
        .get("decision")
        .or_else(|| constraint.value.get("effect"))
        .or_else(|| constraint.value.get("value"))
        .and_then(|value| value.as_str())?;
    match value {
        "deny" => Some(GrantDecision::Deny),
        "quarantine" => Some(GrantDecision::Quarantine),
        "allow" => Some(GrantDecision::Allow),
        "require_review" => Some(GrantDecision::RequireReview),
        _ => None,
    }
}

/// Evaluate a constraint. Returns `None` when the constraint is satisfied,
/// or `Some(reason_text)` when it fails.
fn evaluate_constraint(
    constraint: &Constraint,
    _actor: &str,
    _resource: &str,
    resource_facets: &[String],
) -> Option<String> {
    match constraint.constraint_type.as_str() {
        "temporal" => {
            // Check if the grant hasn't expired
            if let Some(expires_at) = constraint.value.get("expires_at").and_then(|v| v.as_str())
                && let Ok(expires) = chrono::DateTime::parse_from_rfc3339(expires_at)
            {
                return if chrono::Utc::now() < expires.with_timezone(&chrono::Utc) {
                    None
                } else {
                    Some("temporal constraint expired".to_owned())
                };
            }
            None
        }
        "allowed_object_facets" => {
            // Resource must carry at least one of the listed facets. When the
            // resource itself reports no facets, fail-closed — the grant is
            // facet-bound and an unfaceted target falls outside its scope.
            //
            // Round 6 renamed this from `allowed_entity_facets` (the entity
            // scaffold was dropped). The check works on any spec-typed object
            // resource that carries a `facets` field; `cx:flow:` / `cx:place:`
            // / `cx:morph:` projections all surface facets through the same
            // cell-family registry.
            let allowed: Vec<String> = constraint
                .value
                .get("facets")
                .and_then(|value| value.as_array())
                .map(|array| {
                    array
                        .iter()
                        .filter_map(|value| value.as_str().map(ToOwned::to_owned))
                        .collect()
                })
                .unwrap_or_default();
            if allowed.is_empty() {
                return None;
            }
            let satisfied = resource_facets
                .iter()
                .any(|facet| allowed.iter().any(|allow| allow == facet));
            if satisfied {
                None
            } else {
                Some(format!(
                    "allowed_object_facets constraint not satisfied: resource lacks any of {allowed:?}"
                ))
            }
        }
        "delegation_control" => {
            // Check delegation depth
            None // v1: always pass
        }
        _ => None, // Unknown constraints pass
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn owner_gets_all_actions() {
        let engine = AuthzEngine::new();
        let result = engine.check(
            "did:web:alice",
            "manage_space",
            "space:cx:space:1",
            "cx:space:1",
            Some("did:web:alice"),
            &[],
            &[],
        );
        assert!(result.allowed);
        assert_eq!(result.reason, "owner");
    }

    #[test]
    fn member_gets_read_only() {
        let engine = AuthzEngine::new();
        let members = vec!["did:web:bob".to_owned()];
        let result = engine.check(
            "did:web:bob",
            "read",
            "space:cx:space:1",
            "cx:space:1",
            Some("did:web:alice"),
            &members,
            &[],
        );
        assert!(result.allowed);
        assert_eq!(result.reason, "member");

        let denied = engine.check(
            "did:web:bob",
            "manage_space",
            "space:cx:space:1",
            "cx:space:1",
            Some("did:web:alice"),
            &members,
            &[],
        );
        assert!(!denied.allowed);
    }

    #[test]
    fn explicit_grant_overrides_default() {
        let engine = AuthzEngine::new();
        engine.create_grant(
            "cx:space:1".to_owned(),
            "did:web:alice".to_owned(),
            "did:web:bob".to_owned(),
            "*".to_owned(),
            vec!["manage_space".to_owned()],
            vec![],
        );
        let result = engine.check(
            "did:web:bob",
            "manage_space",
            "space:cx:space:1",
            "cx:space:1",
            Some("did:web:alice"),
            &[],
            &[],
        );
        assert!(result.allowed);
        assert_eq!(result.reason, "explicit_grant");
    }

    #[test]
    fn explicit_deny_overrides_allow() {
        let engine = AuthzEngine::new();
        engine.create_grant(
            "cx:space:1".to_owned(),
            "did:web:alice".to_owned(),
            "did:web:bob".to_owned(),
            "*".to_owned(),
            vec!["send".to_owned()],
            vec![Constraint {
                constraint_type: "decision".to_owned(),
                value: serde_json::json!({"decision": "allow"}),
            }],
        );
        engine.create_grant(
            "cx:space:1".to_owned(),
            "did:web:alice".to_owned(),
            "did:web:bob".to_owned(),
            "*".to_owned(),
            vec!["send".to_owned()],
            vec![Constraint {
                constraint_type: "decision".to_owned(),
                value: serde_json::json!({"decision": "deny"}),
            }],
        );
        let result = engine.check(
            "did:web:bob",
            "send",
            "space:cx:space:1",
            "cx:space:1",
            Some("did:web:alice"),
            &[],
            &[],
        );
        assert!(!result.allowed);
        assert_eq!(result.reason, "explicit_deny");
    }

    #[test]
    fn require_review_and_quarantine_outrank_allow() {
        // Per spec B5: deny / quarantine / require_review are each
        // any-hit-wins; allow is the diagnostic fallback only.
        let engine = AuthzEngine::new();
        engine.create_grant(
            "cx:space:1".to_owned(),
            "did:web:alice".to_owned(),
            "did:web:bob".to_owned(),
            "*".to_owned(),
            vec!["send".to_owned()],
            vec![Constraint {
                constraint_type: "decision".to_owned(),
                value: serde_json::json!({"decision": "require_review"}),
            }],
        );
        engine.create_grant(
            "cx:space:1".to_owned(),
            "did:web:alice".to_owned(),
            "did:web:bob".to_owned(),
            "*".to_owned(),
            vec!["send".to_owned()],
            vec![Constraint {
                constraint_type: "decision".to_owned(),
                value: serde_json::json!({"decision": "allow"}),
            }],
        );
        let reviewed = engine.check(
            "did:web:bob",
            "send",
            "space:cx:space:1",
            "cx:space:1",
            Some("did:web:alice"),
            &[],
            &[],
        );
        assert!(!reviewed.allowed, "require_review must outrank allow");
        assert_eq!(reviewed.reason, "require_review");

        engine.create_grant(
            "cx:space:1".to_owned(),
            "did:web:alice".to_owned(),
            "did:web:bob".to_owned(),
            "*".to_owned(),
            vec!["send".to_owned()],
            vec![Constraint {
                constraint_type: "decision".to_owned(),
                value: serde_json::json!({"decision": "quarantine"}),
            }],
        );
        let quarantined = engine.check(
            "did:web:bob",
            "send",
            "space:cx:space:1",
            "cx:space:1",
            Some("did:web:alice"),
            &[],
            &[],
        );
        assert!(!quarantined.allowed);
        assert_eq!(quarantined.reason, "quarantine");
    }

    #[test]
    fn revoked_grant_denied() {
        let engine = AuthzEngine::new();
        let grant = engine.create_grant(
            "cx:space:1".to_owned(),
            "did:web:alice".to_owned(),
            "did:web:bob".to_owned(),
            "*".to_owned(),
            vec!["manage_space".to_owned()],
            vec![],
        );
        engine.revoke_grant(&grant.grant_id);
        let result = engine.check(
            "did:web:bob",
            "manage_space",
            "space:cx:space:1",
            "cx:space:1",
            Some("did:web:alice"),
            &[],
            &[],
        );
        assert!(!result.allowed);
    }

    #[test]
    fn stranger_denied() {
        let engine = AuthzEngine::new();
        let result = engine.check(
            "did:web:eve",
            "read",
            "space:cx:space:1",
            "cx:space:1",
            Some("did:web:alice"),
            &[],
            &[],
        );
        assert!(!result.allowed);
    }
}
