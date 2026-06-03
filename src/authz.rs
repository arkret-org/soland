//! Capability-based authorization engine.
//!
//! Evaluates grants to determine whether an actor may perform an action
//! on a resource within a space. Default rules:
//! - Owner gets all actions
//! - Member gets read, send, react, edit_own
//! - Explicit grants override defaults
//!
//! ## G3.S2 — policy server integration
//!
//! [`AuthzEngine::check`] is the LOCAL capability decision. The
//! remote `/policy/check` round-trip lives in [`policy_client`], and
//! the post-decision side-effect set lives in [`obligation_executor`].
//! The integration helper [`check_with_policy_server`] composes the
//! two so request handlers can hand off the merge logic to one call.

// G3.S2 — policy-server outbound + obligation executor.
pub mod obligation_executor;
pub mod policy_client;

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

// Delegation primitives — `Grant`, `Constraint` (alias of `GrantConstraint`),
// `DelegationError`, and the chain-integrity / cascade / expiry helpers —
// live in the SDK so yougen and sodmin admin can call them client-side. See
// `contrix_sdk::authz::delegation` (crates/sdk/src/authz/delegation.rs).
pub use contrix_sdk::authz::delegation::{
    DelegationError, Grant, GrantConstraint as Constraint, GrantDecisionVerdict, GrantReqBody,
    delegation_chain_intact, grant_effective_expiry, is_grant_expired, resource_within,
    revoke_with_cascade,
};
use serde::Serialize;

use crate::ids;

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

    /// Issue a delegated grant. Per capabilities.md §10:
    /// - caller MUST be the subject of `parent_grant_id`
    /// - delegated actions MUST be a subset of the parent's
    /// - delegated expiry MUST NOT exceed the parent's
    /// - resource MUST NOT widen the parent's scope
    ///
    /// Thin wrapper around [`contrix_sdk::authz::delegation::create_delegated_grant`]:
    /// the SDK helper does the pure validation work; this method snapshots the
    /// engine's grant table, runs the check, assigns a server-issued grant id,
    /// and persists. yougen / sodmin call the SDK helper directly for client-side
    /// pre-validation (skipping the persist step).
    #[allow(clippy::too_many_arguments)]
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
        let parent_space_id = {
            let grants = self.grants.lock().expect("grants lock");
            grants
                .get(parent_grant_id)
                .map(|g| g.space_id.clone())
                .ok_or(DelegationError::ParentNotFound)?
        };
        let snapshot: Vec<Grant> = self
            .grants
            .lock()
            .expect("grants lock")
            .values()
            .cloned()
            .collect();
        let request = GrantReqBody {
            // Parent's space_id is authoritative for delegated children
            // (the wire `space_id` argument is informational only; the SDK
            // helper does not check it). Use the parent's so persisted
            // child matches.
            space_id: parent_space_id,
            issuer,
            subject,
            resource,
            actions,
            constraints,
            expires_at,
        };
        let mut child = contrix_sdk::authz::delegation::create_delegated_grant(
            parent_grant_id,
            &request,
            &snapshot,
            chrono::Utc::now(),
        )?;
        // SDK leaves grant_id empty for caller-supplied id allocation.
        child.grant_id = ids::generate_grant_id();
        self.grants
            .lock()
            .expect("grants lock")
            .insert(child.grant_id.clone(), child.clone());
        Ok(child)
    }

    /// Revoke a grant and cascade to every delegated descendant.
    /// Returns `(true, cascade_ids)` when the named grant existed, where
    /// `cascade_ids` enumerates all descendants whose state flipped to
    /// `revoked` as part of this call (does NOT include `grant_id` itself).
    ///
    /// The cascade *plan* (which ids would be revoked) comes from
    /// [`contrix_sdk::authz::delegation::revoke_with_cascade`]; this method
    /// applies the resulting mutation to the engine's in-memory map.
    pub fn revoke_grant_with_cascade(&self, grant_id: &str) -> (bool, Vec<String>) {
        let mut grants = self.grants.lock().expect("grants lock");
        if !grants.contains_key(grant_id) {
            return (false, Vec::new());
        }
        // Mark target revoked first.
        if let Some(grant) = grants.get_mut(grant_id) {
            grant.revoked = true;
        }
        let snapshot: Vec<Grant> = grants.values().cloned().collect();
        let cascade = revoke_with_cascade(&snapshot, grant_id);
        for child_id in &cascade {
            if let Some(child) = grants.get_mut(child_id) {
                child.revoked = true;
            }
        }
        (true, cascade)
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
        let snapshot: Vec<Grant> = self
            .grants
            .lock()
            .expect("grants lock")
            .values()
            .cloned()
            .collect();
        let now = chrono::Utc::now();
        snapshot
            .iter()
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
        let snapshot: Vec<Grant> = self
            .grants
            .lock()
            .expect("grants lock")
            .values()
            .cloned()
            .collect();
        let now = chrono::Utc::now();
        snapshot
            .iter()
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
    #[allow(clippy::too_many_arguments)]
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
        let snapshot: Vec<Grant> = self
            .grants
            .lock()
            .expect("grants lock")
            .values()
            .cloned()
            .collect();
        let now = chrono::Utc::now();
        let matching_grants: Vec<Grant> = snapshot
            .iter()
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
            let member_actions = [
                "read",
                "send",
                "react",
                "edit_own",
                "realm.read",
                "space.read",
            ];
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
///
/// CXP-0007 / SEL-1 (R3 spec-sync 2026-05-27, cokret-spec b47ff6ec) —
/// the spec resource-selector enum admits `realm`, `space`, `flow`,
/// `morph`, `circle`, `actor`. soland's resource matcher accepts the
/// `ck:circle:<uuid>` typed-id form alongside the existing space /
/// realm forms, plus a `circle` keyword selector that resolves to
/// "any ck:circle:<uuid>" so policy-authoring tools can express
/// circle-wide grants without enumerating each circle.
fn resource_matches(pattern: &str, resource: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    // Exact match
    if pattern == resource {
        return true;
    }
    // SEL-1 — selector-kind keyword form. `circle` matches any
    // `ck:circle:<uuid>` resource (mirrors `realm` / `space` semantics
    // expected by the resource selector enum). Also support the
    // namespaced `circle:ck:circle:<uuid>` form for symmetry with the
    // pre-existing `space:ck:space:<uuid>` pattern.
    if pattern == "circle" {
        return resource.starts_with("ck:circle:");
    }
    if pattern == "realm" {
        return resource.starts_with("ck:realm:");
    }
    if pattern == "space" {
        return resource.starts_with("ck:space:");
    }
    if pattern == "flow" {
        return resource.starts_with("ck:flow:");
    }
    if pattern == "morph" {
        return resource.starts_with("ck:morph:");
    }
    if pattern == "actor" {
        return resource.starts_with("did:") || resource.starts_with("ck:actor:");
    }
    // Prefix match with wildcard: "space:ck:space:123:*" or
    // "ck:circle:<uuid>:*".
    if let Some(prefix) = pattern.strip_suffix('*') {
        return resource.starts_with(prefix);
    }
    false
}

/// Pick the resulting decision over a set of satisfied grants.
///
/// Per Cokret v1 (spec optimization round, _todos B3/B5): the three non-allow
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
    match constraint {
        Constraint::Decision { decision } => Some(match decision {
            GrantDecisionVerdict::Deny => GrantDecision::Deny,
            GrantDecisionVerdict::Quarantine => GrantDecision::Quarantine,
            GrantDecisionVerdict::Allow => GrantDecision::Allow,
            GrantDecisionVerdict::RequireReview => GrantDecision::RequireReview,
        }),
        _ => None,
    }
}

/// Evaluate a constraint. Returns `None` when the constraint is satisfied,
/// or `Some(reason_text)` when it fails.
fn evaluate_constraint(
    constraint: &Constraint,
    _actor: &str,
    resource: &str,
    resource_facets: &[String],
) -> Option<String> {
    match constraint {
        Constraint::Temporal { expires_at, .. } => {
            // Check if the grant hasn't expired
            if let Some(expires) = expires_at {
                return if chrono::Utc::now() < *expires {
                    None
                } else {
                    Some("temporal constraint expired".to_owned())
                };
            }
            None
        }
        Constraint::AllowedCircleIds { allowed_circle_ids } => {
            // CXP-0007 (spec b7d35be) — narrow a Circle-management
            // capability (`cx.circle.manage`, `cx.circle.member.manage`,
            // `cx.circle.member.add.others`, `cx.circle.audit`) to a
            // specific Circle id set. The spec
            // `capability-action-registry.json` declares
            // `required_constraints=["allowed_circle_ids"]` on each
            // gated action; unconstrained Realm-wide grants for these
            // actions MUST be rejected (a separate guard at grant-issue
            // time).
            //
            // Evaluation contract: the resource selector for a Circle
            // capability is of the form `ck:circle:<uuid>` (mirrors the
            // `ck:space:<uuid>` pattern used by `realm.*` / `space.*`
            // grants). If the resource looks like a Circle id, it MUST
            // be a member of the allowed set; otherwise the constraint
            // does not apply and silently passes (caller-policy: any
            // non-Circle resource is out of this constraint's scope).
            if allowed_circle_ids.is_empty() {
                return Some(
                    "allowed_circle_ids constraint requires a non-empty allow list".to_owned(),
                );
            }
            if !resource.starts_with("ck:circle:") {
                // Constraint is Circle-scoped — non-Circle resources are
                // out of scope; pass through.
                return None;
            }
            if allowed_circle_ids.iter().any(|c| c.as_ref() == resource) {
                None
            } else {
                let allowed: Vec<&str> = allowed_circle_ids.iter().map(AsRef::as_ref).collect();
                Some(format!(
                    "allowed_circle_ids constraint not satisfied: {resource:?} not in {allowed:?}"
                ))
            }
        }
        Constraint::AllowedObjectFacets { facets: allowed } => {
            // Resource must carry at least one of the listed facets. When the
            // resource itself reports no facets, fail-closed — the grant is
            // facet-bound and an unfaceted target falls outside its scope.
            //
            // The check works on any spec-typed object resource that
            // carries a `facets` field; `ck:flow:` / `ck:space:` /
            // `ck:morph:` projections all surface facets through the
            // same cell-family registry.
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
        Constraint::DelegationControl { .. } => {
            // Check delegation depth
            None // v1: always pass (depth enforced at chain-walk level)
        }
        Constraint::RateLimiting {
            max_operations,
            period,
        } => {
            // The runtime grant shape carries the spec-required quota
            // metadata (`max_operations` + `period`). Service-specific
            // counters are enforced at the operation surface so this generic
            // checker only rejects nonsensical quota declarations.
            if *max_operations == 0 || period.trim().is_empty() {
                Some(
                    "rate_limiting constraint requires max_operations>0 and non-empty period"
                        .to_owned(),
                )
            } else {
                None
            }
        }
        Constraint::Decision { .. } => {
            // Decision constraints are evaluated separately via
            // `decision_from_constraint`; treat as satisfied here so they
            // never fail the satisfaction check.
            None
        }
    }
}

/// G3.S2 — discriminated decision returned by [`check_with_policy_server`].
///
/// `Allowed` means BOTH the local capability check AND (if configured)
/// the remote policy server returned allow. `LocalDeny` short-circuits
/// the remote call when the local check has already rejected.
/// `RemoteDeny` carries the canonical wire response so the caller can
/// surface the reason_code and run obligations.
/// `RemoteObligationFailed` records the case where the remote allowed
/// but a required obligation (mfa / rate_limit / unknown_kind) caused
/// the executor to deny.
#[derive(Debug)]
pub enum MergedAuthzDecision {
    Allowed {
        local: AuthzResult,
        remote: Option<contrix_sdk::PolicyCheckResponse>,
    },
    LocalDeny(AuthzResult),
    RemoteDeny {
        local: AuthzResult,
        remote: contrix_sdk::PolicyCheckResponse,
    },
    RemoteObligationFailed {
        local: AuthzResult,
        remote: contrix_sdk::PolicyCheckResponse,
        error: obligation_executor::ObligationError,
    },
}

impl MergedAuthzDecision {
    pub fn is_allowed(&self) -> bool {
        matches!(self, MergedAuthzDecision::Allowed { .. })
    }
}

/// G3.S2 — integration helper. Runs the local capability check first;
/// if it allows AND the realm has a `cx.realm.policy_server` config,
/// calls the remote policy server. Merges the two decisions per the
/// spec rule "deny if either denies; allow only if both allow", then
/// runs the remote response's obligations through the executor.
///
/// `realm_id` is the canonical Realm identifier the policy server
/// keys decisions on (NOT the SDK `SpaceId` — pass the wire string).
#[allow(clippy::too_many_arguments)]
pub async fn check_with_policy_server(
    engine: &AuthzEngine,
    actor: &str,
    action: &str,
    resource: &str,
    space_id: &str,
    owner: Option<&str>,
    members: &[String],
    resource_facets: &[String],
    realm_id: &str,
    policy_client: Option<&policy_client::PolicyClient>,
    realm_config: Option<crate::reducer::RealmPolicyServerConfig>,
    policy_request: Option<policy_client::PolicyCheckRequestInput>,
    request_ctx: &mut obligation_executor::RequestContext,
) -> MergedAuthzDecision {
    // Step 1 — local capability check (existing behaviour).
    let local = engine.check(
        actor,
        action,
        resource,
        space_id,
        owner,
        members,
        resource_facets,
    );
    if !local.allowed {
        return MergedAuthzDecision::LocalDeny(local);
    }

    // Step 2 — short-circuit when there's no policy server for this
    // realm (no per-realm config AND no org-fallback resolved).
    let (Some(client), Some(config), Some(input)) = (policy_client, realm_config, policy_request)
    else {
        return MergedAuthzDecision::Allowed {
            local,
            remote: None,
        };
    };
    // `realm_id` is informational here — the client resolves config
    // strictly via the closure we pass.
    let _ = realm_id;

    let config_clone = config.clone();
    let remote = match client.check(input, move |_| Some(config_clone)).await {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(
                error = %e,
                actor = %actor,
                action = %action,
                "policy_client check failed unexpectedly; treating as deny"
            );
            // Synthesise a deny so we never silently allow on a hard fault.
            return MergedAuthzDecision::LocalDeny(AuthzResult {
                allowed: false,
                reason: "policy_client_error".to_owned(),
                reason_detail: Some(e.to_string()),
                grants: local.grants.clone(),
            });
        }
    };

    use contrix_sdk::model::AuthzDecision;
    let allow = matches!(remote.decision, AuthzDecision::Allow);
    if !allow {
        return MergedAuthzDecision::RemoteDeny { local, remote };
    }

    // Step 3 — run obligations on the allow path.
    if let Err(err) = obligation_executor::execute_obligations(&remote.obligations, request_ctx) {
        return MergedAuthzDecision::RemoteObligationFailed {
            local,
            remote,
            error: err,
        };
    }

    MergedAuthzDecision::Allowed {
        local,
        remote: Some(remote),
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
            "space:ck:space:1",
            "ck:space:1",
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
            "space:ck:space:1",
            "ck:space:1",
            Some("did:web:alice"),
            &members,
            &[],
        );
        assert!(result.allowed);
        assert_eq!(result.reason, "member");

        let denied = engine.check(
            "did:web:bob",
            "manage_space",
            "space:ck:space:1",
            "ck:space:1",
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
            "ck:space:1".to_owned(),
            "did:web:alice".to_owned(),
            "did:web:bob".to_owned(),
            "*".to_owned(),
            vec!["manage_space".to_owned()],
            vec![],
        );
        let result = engine.check(
            "did:web:bob",
            "manage_space",
            "space:ck:space:1",
            "ck:space:1",
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
            "ck:space:1".to_owned(),
            "did:web:alice".to_owned(),
            "did:web:bob".to_owned(),
            "*".to_owned(),
            vec!["send".to_owned()],
            vec![Constraint::Decision {
                decision: GrantDecisionVerdict::Allow,
            }],
        );
        engine.create_grant(
            "ck:space:1".to_owned(),
            "did:web:alice".to_owned(),
            "did:web:bob".to_owned(),
            "*".to_owned(),
            vec!["send".to_owned()],
            vec![Constraint::Decision {
                decision: GrantDecisionVerdict::Deny,
            }],
        );
        let result = engine.check(
            "did:web:bob",
            "send",
            "space:ck:space:1",
            "ck:space:1",
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
            "ck:space:1".to_owned(),
            "did:web:alice".to_owned(),
            "did:web:bob".to_owned(),
            "*".to_owned(),
            vec!["send".to_owned()],
            vec![Constraint::Decision {
                decision: GrantDecisionVerdict::RequireReview,
            }],
        );
        engine.create_grant(
            "ck:space:1".to_owned(),
            "did:web:alice".to_owned(),
            "did:web:bob".to_owned(),
            "*".to_owned(),
            vec!["send".to_owned()],
            vec![Constraint::Decision {
                decision: GrantDecisionVerdict::Allow,
            }],
        );
        let reviewed = engine.check(
            "did:web:bob",
            "send",
            "space:ck:space:1",
            "ck:space:1",
            Some("did:web:alice"),
            &[],
            &[],
        );
        assert!(!reviewed.allowed, "require_review must outrank allow");
        assert_eq!(reviewed.reason, "require_review");

        engine.create_grant(
            "ck:space:1".to_owned(),
            "did:web:alice".to_owned(),
            "did:web:bob".to_owned(),
            "*".to_owned(),
            vec!["send".to_owned()],
            vec![Constraint::Decision {
                decision: GrantDecisionVerdict::Quarantine,
            }],
        );
        let quarantined = engine.check(
            "did:web:bob",
            "send",
            "space:ck:space:1",
            "ck:space:1",
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
            "ck:space:1".to_owned(),
            "did:web:alice".to_owned(),
            "did:web:bob".to_owned(),
            "*".to_owned(),
            vec!["manage_space".to_owned()],
            vec![],
        );
        engine.revoke_grant_with_cascade(&grant.grant_id);
        let result = engine.check(
            "did:web:bob",
            "manage_space",
            "space:ck:space:1",
            "ck:space:1",
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
            "space:ck:space:1",
            "ck:space:1",
            Some("did:web:alice"),
            &[],
            &[],
        );
        assert!(!result.allowed);
    }
}
