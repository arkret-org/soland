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
///
/// `delegated_from` carries the parent grant_id when this grant was issued
/// by a non-owner via delegation (capabilities.md §10). Revoking the parent
/// cascade-revokes the child via [`AuthzEngine::revoke_grant`].
///
/// `expires_at` is an optional top-level convenience denormalization of the
/// temporal constraint inside `constraints[]`. When both forms are present
/// the stricter of the two wins. Spec source: capabilities.md §3 +
/// `cx.schema.capability.v1`.
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
    #[serde(default)]
    pub delegated_from: Option<String>,
    #[serde(default)]
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
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

/// Why a delegation request was rejected. Surfaced through HTTP as
/// `capability_not_held` / `capability_over_expire` / `parent_revoked` /
/// `not_grant_holder` / `grant_not_found`. See capabilities.md §10.
#[derive(Clone, Debug)]
pub enum DelegationError {
    /// Parent grant_id is unknown to this engine.
    ParentNotFound,
    /// Parent grant exists but is revoked (directly or via cascade).
    ParentRevoked,
    /// Parent grant exists but its `expires_at` is already in the past.
    ParentExpired,
    /// Caller is not the subject of the parent grant — only the holder of a
    /// capability MAY further delegate it.
    NotGrantHolder,
    /// Delegated `actions[]` carries an action the parent doesn't hold.
    /// capabilities.md §10 (再授权不得扩大动作范围) — `capability_not_held`.
    ActionsNotHeld { offending: String },
    /// Child `expires_at` is later than parent `expires_at` (or child unset
    /// while parent is set). capabilities.md §10 (再授权不得扩大资源范围) +
    /// `cx.schema.capability.v1` temporal constraint — `capability_over_expire`.
    OverExpire,
    /// Delegated `resource` falls outside parent's `resource` scope.
    /// Returned today for documentation symmetry; v1 only enforces exact
    /// match or parent="*" pattern; richer subsumption lands when typed
    /// resource selectors arrive (see authz/resource-selector-grammar.md).
    ResourceOutOfScope,
}

impl AuthzEngine {
    pub fn new() -> Self {
        Self {
            grants: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }

    /// Create a new owner-issued (root) grant. Use [`Self::create_delegated_grant`]
    /// when the issuer is a non-owner re-delegating a capability they hold.
    pub fn create_grant(
        &self,
        space_id: String,
        issuer: String,
        subject: String,
        resource: String,
        actions: Vec<String>,
        constraints: Vec<Constraint>,
    ) -> Grant {
        self.create_grant_with_options(
            space_id,
            issuer,
            subject,
            resource,
            actions,
            constraints,
            None,
            None,
        )
    }

    /// Full-form constructor used by both root and delegated paths.
    /// `expires_at` here is the top-level convenience denormalization; the
    /// constraints[] temporal entry, if present, still wins on the stricter
    /// side at check time.
    #[allow(clippy::too_many_arguments)]
    pub fn create_grant_with_options(
        &self,
        space_id: String,
        issuer: String,
        subject: String,
        resource: String,
        actions: Vec<String>,
        constraints: Vec<Constraint>,
        delegated_from: Option<String>,
        expires_at: Option<chrono::DateTime<chrono::Utc>>,
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
            delegated_from,
            expires_at,
        };
        self.grants
            .lock()
            .expect("grants lock")
            .insert(grant.grant_id.clone(), grant.clone());
        grant
    }

    /// Issue a delegated grant. capabilities.md §10:
    /// - caller MUST be the subject of `parent_grant_id`
    /// - delegated actions MUST be a subset of the parent's
    /// - delegated expiry MUST NOT exceed the parent's
    /// - resource MUST NOT widen the parent's scope
    pub fn create_delegated_grant(
        &self,
        parent_grant_id: &str,
        issuer: String,
        subject: String,
        resource: String,
        actions: Vec<String>,
        constraints: Vec<Constraint>,
        expires_at: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Result<Grant, DelegationError> {
        let parent = {
            let grants = self.grants.lock().expect("grants lock");
            grants
                .get(parent_grant_id)
                .cloned()
                .ok_or(DelegationError::ParentNotFound)?
        };
        if parent.revoked {
            return Err(DelegationError::ParentRevoked);
        }
        if parent.subject != issuer {
            return Err(DelegationError::NotGrantHolder);
        }
        let parent_effective_expiry = grant_effective_expiry(&parent);
        if let Some(parent_expiry) = parent_effective_expiry
            && parent_expiry <= chrono::Utc::now()
        {
            return Err(DelegationError::ParentExpired);
        }
        let parent_actions_wildcard = parent.actions.iter().any(|action| action == "*");
        if !parent_actions_wildcard {
            for action in &actions {
                if action != "*" && !parent.actions.contains(action) {
                    return Err(DelegationError::ActionsNotHeld {
                        offending: action.clone(),
                    });
                }
            }
            if actions.iter().any(|action| action == "*") {
                // child requesting wildcard while parent is not wildcard
                return Err(DelegationError::ActionsNotHeld {
                    offending: "*".to_owned(),
                });
            }
        }
        if !resource_within(&parent.resource, &resource) {
            return Err(DelegationError::ResourceOutOfScope);
        }
        if let Some(parent_expiry) = parent_effective_expiry {
            match expires_at {
                None => return Err(DelegationError::OverExpire),
                Some(child_expiry) if child_expiry > parent_expiry => {
                    return Err(DelegationError::OverExpire);
                }
                _ => {}
            }
        }
        Ok(self.create_grant_with_options(
            parent.space_id.clone(),
            issuer,
            subject,
            resource,
            actions,
            constraints,
            Some(parent_grant_id.to_owned()),
            expires_at,
        ))
    }

    /// Revoke a grant and cascade to every delegated descendant.
    /// Returns `(true, cascade_ids)` when the named grant existed, where
    /// `cascade_ids` enumerates all descendants whose state flipped to
    /// `revoked` as part of this call (does NOT include `grant_id` itself).
    pub fn revoke_grant_with_cascade(&self, grant_id: &str) -> (bool, Vec<String>) {
        let mut grants = self.grants.lock().expect("grants lock");
        if !grants.contains_key(grant_id) {
            return (false, Vec::new());
        }
        // Mark target revoked first.
        if let Some(grant) = grants.get_mut(grant_id) {
            grant.revoked = true;
        }
        // BFS through delegated children, collecting + marking.
        let mut cascade = Vec::new();
        let mut frontier: Vec<String> = vec![grant_id.to_owned()];
        while let Some(parent_id) = frontier.pop() {
            let children: Vec<String> = grants
                .values()
                .filter(|g| g.delegated_from.as_deref() == Some(parent_id.as_str()))
                .map(|g| g.grant_id.clone())
                .collect();
            for child_id in children {
                if let Some(child) = grants.get_mut(&child_id)
                    && !child.revoked
                {
                    child.revoked = true;
                    cascade.push(child_id.clone());
                    frontier.push(child_id);
                }
            }
        }
        (true, cascade)
    }

    /// Backwards-compatible wrapper around [`Self::revoke_grant_with_cascade`].
    pub fn revoke_grant(&self, grant_id: &str) -> bool {
        self.revoke_grant_with_cascade(grant_id).0
    }

    /// Look up a grant by id. Returns `None` if unknown.
    pub fn get_grant(&self, grant_id: &str) -> Option<Grant> {
        self.grants
            .lock()
            .expect("grants lock")
            .get(grant_id)
            .cloned()
    }

    /// Get all grants for a subject in a space. Filters out revoked,
    /// expired, and cascade-broken grants so callers see only the
    /// *effective* set (capabilities.md §11).
    pub fn grants_for_subject(&self, subject: &str, space_id: &str) -> Vec<Grant> {
        let snapshot = self.grants.lock().expect("grants lock").clone();
        let now = chrono::Utc::now();
        snapshot
            .values()
            .filter(|g| {
                g.subject == subject
                    && g.space_id == space_id
                    && !g.revoked
                    && !is_grant_expired(g, now)
                    && delegation_chain_intact(&snapshot, &g.grant_id, now)
            })
            .cloned()
            .collect()
    }

    /// Get all (non-revoked, non-expired, chain-intact) grants in a space.
    pub fn grants_in_space(&self, space_id: &str) -> Vec<Grant> {
        let snapshot = self.grants.lock().expect("grants lock").clone();
        let now = chrono::Utc::now();
        snapshot
            .values()
            .filter(|g| {
                g.space_id == space_id
                    && !g.revoked
                    && !is_grant_expired(g, now)
                    && delegation_chain_intact(&snapshot, &g.grant_id, now)
            })
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
        // Check explicit grants first. Delegated grants drop out if any
        // ancestor in the chain is revoked or expired (capabilities.md §3.3
        // cascade + §10 delegation chain integrity).
        let snapshot = self.grants.lock().expect("grants lock").clone();
        let now = chrono::Utc::now();
        let matching_grants: Vec<Grant> = snapshot
            .values()
            .filter(|g| {
                !g.revoked
                    && g.space_id == space_id
                    && g.subject == actor
                    && g.actions.iter().any(|a| a == action || a == "*")
                    && resource_matches(&g.resource, resource)
                    && !is_grant_expired(g, now)
                    && delegation_chain_intact(&snapshot, &g.grant_id, now)
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

/// Returns the effective expiry for a grant, taking the stricter of the
/// top-level `expires_at` and any `constraint_type=temporal` entry inside
/// `constraints[]`. `None` means the grant never expires.
fn grant_effective_expiry(grant: &Grant) -> Option<chrono::DateTime<chrono::Utc>> {
    let top_level = grant.expires_at;
    let from_constraint = grant.constraints.iter().find_map(|constraint| {
        if constraint.constraint_type == "temporal" {
            constraint
                .value
                .get("expires_at")
                .and_then(|value| value.as_str())
                .and_then(|raw| chrono::DateTime::parse_from_rfc3339(raw).ok())
                .map(|dt| dt.with_timezone(&chrono::Utc))
        } else {
            None
        }
    });
    match (top_level, from_constraint) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (Some(a), None) => Some(a),
        (None, Some(b)) => Some(b),
        (None, None) => None,
    }
}

fn is_grant_expired(grant: &Grant, now: chrono::DateTime<chrono::Utc>) -> bool {
    grant_effective_expiry(grant).is_some_and(|expiry| now >= expiry)
}

/// Returns `true` iff every ancestor in the delegation chain rooted at
/// `grant_id` is still active (not revoked, not expired). A grant with no
/// `delegated_from` is trivially chain-intact. Cycles defended by a visit
/// budget(should never occur in practice — `delegated_from` is set at
/// creation time and the engine has no edit API).
fn delegation_chain_intact(
    snapshot: &BTreeMap<String, Grant>,
    grant_id: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> bool {
    let mut current = grant_id;
    let mut visited: usize = 0;
    while let Some(grant) = snapshot.get(current) {
        if visited > 64 {
            return false;
        }
        visited += 1;
        if grant.revoked || is_grant_expired(grant, now) {
            return false;
        }
        match &grant.delegated_from {
            Some(parent) => current = parent.as_str(),
            None => return true,
        }
    }
    // Parent_grant_id pointed at an unknown grant — broken chain.
    false
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

/// Check whether `child` resource is within the scope `parent` permits.
/// v1 only supports exact match and `parent="*"`; prefix-wildcard parents
/// (`pattern="...:*"`) accept any child sharing the prefix. Richer typed
/// resource selectors land later (authz/resource-selector-grammar.md).
fn resource_within(parent: &str, child: &str) -> bool {
    if parent == "*" {
        return true;
    }
    if parent == child {
        return true;
    }
    if let Some(prefix) = parent.strip_suffix('*') {
        return child.starts_with(prefix);
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
            // The check works on any spec-typed object resource that
            // carries a `facets` field; `cx:flow:` / `cx:place:` /
            // `cx:morph:` projections all surface facets through the
            // same cell-family registry.
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
