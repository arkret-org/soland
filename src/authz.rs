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
    pub grants: Vec<Grant>,
}

/// Thread-safe authorization engine.
#[derive(Clone)]
pub struct AuthzEngine {
    grants: Arc<Mutex<BTreeMap<String, Grant>>>,
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

        if !matching_grants.is_empty() {
            // Check constraints
            let all_constraints_satisfied = matching_grants.iter().all(|g| {
                g.constraints
                    .iter()
                    .all(|c| evaluate_constraint(c, actor, resource))
            });
            if all_constraints_satisfied {
                return AuthzResult {
                    allowed: true,
                    reason: "explicit_grant".to_owned(),
                    grants: matching_grants,
                };
            }
        }

        // Default rules
        if owner.is_some_and(|o| o == actor) {
            return AuthzResult {
                allowed: true,
                reason: "owner".to_owned(),
                grants: Vec::new(),
            };
        }

        if members.iter().any(|m| m == actor) {
            let member_actions = ["read", "send", "react", "edit_own", "space.read"];
            if member_actions.contains(&action) {
                return AuthzResult {
                    allowed: true,
                    reason: "member".to_owned(),
                    grants: Vec::new(),
                };
            }
        }

        AuthzResult {
            allowed: false,
            reason: "capability_denied".to_owned(),
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

/// Evaluate a constraint. Returns true if the constraint is satisfied.
fn evaluate_constraint(constraint: &Constraint, _actor: &str, _resource: &str) -> bool {
    match constraint.constraint_type.as_str() {
        "temporal" => {
            // Check if the grant hasn't expired
            if let Some(expires_at) = constraint.value.get("expires_at").and_then(|v| v.as_str())
                && let Ok(expires) = chrono::DateTime::parse_from_rfc3339(expires_at)
            {
                return chrono::Utc::now() < expires.with_timezone(&chrono::Utc);
            }
            true
        }
        "type_restriction" => {
            // Restrict to specific entity types
            true // v1: always pass
        }
        "delegation_control" => {
            // Check delegation depth
            true // v1: always pass
        }
        _ => true, // Unknown constraints pass
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
        );
        assert!(result.allowed);
        assert_eq!(result.reason, "explicit_grant");
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
        );
        assert!(!result.allowed);
    }
}
