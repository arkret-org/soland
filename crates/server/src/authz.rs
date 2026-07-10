//! Capability-based authorization engine.
//!
//! Evaluates grants to determine whether an actor may perform an action
//! on a resource within a scope. Default rules:
//! - Owner gets ordinary Realm-level actions
//! - Circle-local management actions require explicit Circle-scoped grants
//! - Explicit grants authorize non-owner actors
//!
//! ## G3.S2 — policy server integration
//!
//! [`SolandAuthzEngine::check`] is the LOCAL capability decision. The
//! remote `/policy/check` round-trip lives in [`policy_client`], and
//! the post-decision side-effect set lives in [`obligation_executor`].
//! The integration helper [`check_with_policy_server`] composes the
//! two so request handlers can hand off the merge logic to one call.

// G3.S2 — policy-server outbound + obligation executor.
pub mod obligation_executor;
pub mod policy_client;

use std::collections::BTreeMap;
use std::sync::Arc;

// Delegation primitives — `Grant`, `Constraint` (alias of `GrantConstraint`),
// `DelegationError`, and the chain-integrity / cascade / expiry helpers —
// live in the SDK so inkson and sodmin admin can call them client-side. See
// `arkret_sdk::authz::delegation` (crates/sdk/src/authz/delegation.rs).
pub use arkret_sdk::authz::delegation::{
    AppletDelegationBindingError, DelegationError, Grant, GrantConstraint as Constraint,
    GrantDecisionVerdict, GrantRequestDraft, delegation_chain_intact, grant_effective_expiry,
    is_grant_expired, max_delegation_depth, resource_within, revoke_with_cascade,
    validate_applet_delegation_binding,
};
use parking_lot::Mutex;
use serde::Serialize;
use serde_json::{Map, Value};

use crate::ids;

const SELECTOR_SHORTHAND_MAX_BYTES: usize = 4096;
const SELECTOR_TOKEN_MAX: usize = 256;
const SELECTOR_DISJUNCTION_MAX: usize = 16;
const SELECTOR_CONJUNCTION_MAX: usize = 64;
const SELECTOR_TERM_MAX_BYTES: usize = 1024;
const SELECTOR_JSON_MAX_BYTES: usize = 64 * 1024;
const RESOURCE_SELECTOR_KNOWN_FIELDS: &[&str] = &[
    "kind",
    "realm_id",
    "space_id",
    "circle_id",
    "object_type",
    "object_ref",
    "strand_id",
    "message_id",
    "morph_id",
    "morph_type",
    "relation_kind",
    "relation_id",
    "view_id",
    "event_id",
    "actor_id",
    "schema_ref",
    "policy_id",
    "invite_id",
    "blob_ref",
    "match_scope",
];
const RESOURCE_SELECTOR_KINDS: &[&str] = &[
    "realm",
    "space",
    "circle",
    "strand",
    "message",
    "morph",
    "object",
    "relation",
    "view",
    "event",
    "actor",
    "schema",
    "policy",
    "invite",
    "notification",
    "read_cursor",
    "blob",
    "*",
];
pub(crate) const REASON_GRANT_REVOKED_UPSTREAM: &str = "grant_revoked_upstream";
pub(crate) const REASON_CAPABILITY_ACTION_UNKNOWN: &str = "capability_action_unknown";
pub(crate) const REASON_CAPABILITY_ACTION_REGISTRY_UNAVAILABLE: &str =
    "capability_action_registry_unavailable";
const REASON_CAPABILITY_ACTION_INVALID: &str = "capability_action_invalid";
const REASON_CAPABILITY_ACTION_WILDCARD_FORBIDDEN: &str = "capability_action_wildcard_forbidden";
const REASON_CAPABILITY_GRANT_ACTION_UNKNOWN: &str = "capability_grant_action_unknown";

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
pub struct SolandAuthzEngine {
    grants: Arc<Mutex<BTreeMap<String, Grant>>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum GrantDecision {
    Deny,
    Quarantine,
    Allow,
    RequireReview,
}

impl SolandAuthzEngine {
    pub fn new() -> Self {
        Self {
            grants: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }

    /// Create a new owner-issued (root) grant. Use [`Self::create_delegated_grant`]
    /// when the issuer is a non-owner re-delegating a capability they hold.
    pub fn create_grant(
        &self,
        realm_id: String,
        issuer: String,
        subject: String,
        resource: String,
        actions: Vec<String>,
        constraints: Vec<Constraint>,
    ) -> Grant {
        self.create_grant_with_options(
            realm_id,
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
        realm_id: String,
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
            realm_id,
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
        if grant_scope_valid(&grant).is_ok() {
            self.grants
                .lock()
                .insert(grant.grant_id.clone(), grant.clone());
        }
        grant
    }

    /// Issue a delegated grant. Per capabilities.md §10:
    /// - caller MUST be the subject of `parent_grant_id`
    /// - delegated actions MUST be a subset of the parent's
    /// - delegated expiry MUST NOT exceed the parent's
    /// - resource MUST NOT widen the parent's scope
    ///
    /// Thin wrapper around [`arkret_sdk::authz::delegation::create_delegated_grant`]:
    /// the SDK helper does the pure validation work; this method snapshots the
    /// engine's grant table, runs the check, assigns a server-issued grant id,
    /// and persists. inkson / sodmin call the SDK helper directly for client-side
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
        let delegated_realm_id = {
            // SOL-REL-01 / SOL-SOTA-01 — parking_lot mutex: no poisoning, so
            // the authorization hot path cannot crash on a stale poison flag.
            let grants = self.grants.lock();
            grants
                .get(parent_grant_id)
                .map(|g| g.realm_id.clone())
                .ok_or(DelegationError::ParentNotFound)?
        };
        let snapshot: Vec<Grant> = self.grants.lock().values().cloned().collect();
        let request = GrantRequestDraft {
            // Parent's realm_id is authoritative for delegated children
            // (the wire `realm_id` argument is informational only; the SDK
            // helper does not check it). Use the parent's so persisted
            // child matches.
            realm_id: delegated_realm_id,
            issuer,
            subject,
            resource,
            actions,
            constraints,
            expires_at,
        };
        let mut child = arkret_sdk::authz::delegation::create_delegated_grant(
            parent_grant_id,
            &request,
            &snapshot,
            chrono::Utc::now(),
        )?;
        if validate_capability_actions(&child.actions).is_err() {
            return Err(DelegationError::ActionsNotHeld {
                offending: child.actions.clone(),
            });
        }
        if validate_resource_pattern(&child.resource).is_err() {
            return Err(DelegationError::ResourceOutOfScope);
        }
        // SDK leaves grant_id empty for caller-supplied id allocation.
        child.grant_id = ids::generate_grant_id();
        self.grants
            .lock()
            .insert(child.grant_id.clone(), child.clone());
        Ok(child)
    }

    /// Revoke a grant and cascade to every delegated descendant.
    /// Returns `(true, cascade_ids)` when the named grant existed, where
    /// `cascade_ids` enumerates all descendants whose state flipped to
    /// `revoked` as part of this call (does NOT include `grant_id` itself).
    ///
    /// The cascade *plan* (which ids would be revoked) comes from
    /// [`arkret_sdk::authz::delegation::revoke_with_cascade`]; this method
    /// applies the resulting mutation to the engine's in-memory map.
    pub fn revoke_grant_with_cascade(&self, grant_id: &str) -> (bool, Vec<String>) {
        let mut grants = self.grants.lock();
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

    /// P1 — projection-driven index maintenance.
    ///
    /// The capability grant cell (`ak.component.capability.grant.v1`) is the
    /// source of truth; this engine's in-memory map is a read-side index over
    /// it (`SolandAuthzEngine::check` still reads the map). The reducer
    /// projects grant / revoke / delegate into cells, then the projection
    /// driver calls this to fold the cell-derived effective `Grant` back into
    /// the index. Upsert by `grant_id` (a re-projection of the same grant_id
    /// replaces the prior row); a `revoked` grant stays in the map with
    /// `revoked = true` so the check filters it and the cascade helpers can
    /// still see the tombstone.
    pub fn upsert_projected_grant(&self, grant: Grant) {
        self.grants.lock().insert(grant.grant_id.clone(), grant);
    }

    /// P1 — mark a projected grant revoked in the read index (idempotent).
    /// Mirrors a `ak.capability.revoke` cell observed-remove. No-op if the
    /// grant_id is unknown to the index (the cell tombstone is authoritative;
    /// the index simply has nothing to filter yet).
    pub fn mark_projected_grant_revoked(&self, grant_id: &str) {
        if let Some(grant) = self.grants.lock().get_mut(grant_id) {
            grant.revoked = true;
        }
    }

    pub fn mark_projected_grants_revoked_for_subject(&self, subject: &str) -> usize {
        let mut count = 0usize;
        let mut grants = self.grants.lock();
        for grant in grants.values_mut() {
            if grant.subject == subject && !grant.revoked {
                grant.revoked = true;
                count += 1;
            }
        }
        count
    }

    /// Look up a grant by id. Returns `None` if unknown.
    pub fn get_grant(&self, grant_id: &str) -> Option<Grant> {
        self.grants.lock().get(grant_id).cloned()
    }

    /// Get all grants for a subject in a space. Filters out invalid,
    /// revoked, expired, and cascade-broken grants so callers see only the
    /// *effective* set (capabilities.md §11).
    pub fn grants_for_subject(&self, subject: &str, realm_id: &str) -> Vec<Grant> {
        let snapshot: Vec<Grant> = self.grants.lock().values().cloned().collect();
        let now = chrono::Utc::now();
        snapshot
            .iter()
            .filter(|g| {
                g.subject == subject
                    && g.realm_id == realm_id
                    && grant_scope_valid(g).is_ok()
                    && !g.revoked
                    && !is_grant_expired(g, now)
                    && delegation_chain_intact(&snapshot, &g.grant_id, now)
            })
            .cloned()
            .collect()
    }

    /// Get all effective grants held by `subject` across every realm.
    /// Same filtering as [`Self::grants_for_subject`] minus the realm pin —
    /// read model for the controller-facing agent settings surface
    /// (`GET /_arkret/self/agents/{id}` `agent_view.grants[]`).
    pub fn grants_for_subject_all_realms(&self, subject: &str) -> Vec<Grant> {
        let snapshot: Vec<Grant> = self.grants.lock().values().cloned().collect();
        let now = chrono::Utc::now();
        snapshot
            .iter()
            .filter(|g| {
                g.subject == subject
                    && grant_scope_valid(g).is_ok()
                    && !g.revoked
                    && !is_grant_expired(g, now)
                    && delegation_chain_intact(&snapshot, &g.grant_id, now)
            })
            .cloned()
            .collect()
    }

    /// Get all valid, non-revoked, non-expired, chain-intact grants in a space.
    pub fn grants_in_realm(&self, realm_id: &str) -> Vec<Grant> {
        let snapshot: Vec<Grant> = self.grants.lock().values().cloned().collect();
        let now = chrono::Utc::now();
        snapshot
            .iter()
            .filter(|g| {
                g.realm_id == realm_id
                    && grant_scope_valid(g).is_ok()
                    && !g.revoked
                    && !is_grant_expired(g, now)
                    && delegation_chain_intact(&snapshot, &g.grant_id, now)
            })
            .cloned()
            .collect()
    }

    pub(crate) fn grants_snapshot(&self) -> Vec<Grant> {
        self.grants.lock().values().cloned().collect()
    }

    /// Check if an actor can perform an action on a resource.
    ///
    /// Default rules (when no explicit grants exist):
    /// - Owner of the realm → all registered Realm-level actions allowed
    /// - Everyone else → denied
    #[allow(clippy::too_many_arguments)]
    pub fn check(
        &self,
        actor: &str,
        action: &str,
        resource: &str,
        realm_id: &str,
        owner: Option<&str>,
        members: &[String],
        resource_facets: &[String],
    ) -> AuthzResult {
        if let Err(reason) = validate_runtime_capability_action(action) {
            return AuthzResult {
                allowed: false,
                reason: reason.to_owned(),
                reason_detail: None,
                grants: Vec::new(),
            };
        }

        // Check explicit grants first. Delegated grants drop out if any
        // ancestor in the chain is revoked or expired (capabilities.md §3.3
        // cascade + §10 delegation chain integrity).
        let snapshot: Vec<Grant> = self.grants.lock().values().cloned().collect();
        let now = chrono::Utc::now();
        let matching_grants: Vec<Grant> = snapshot
            .iter()
            .filter(|g| {
                !g.revoked
                    && g.realm_id == realm_id
                    && g.subject == actor
                    && grant_scope_valid(g).is_ok()
                    && g.actions.iter().any(|a| a == action)
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
        if !satisfied_grants.is_empty()
            && let Some(decision) = highest_priority_decision(&satisfied_grants)
        {
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

        if let Some(reason_detail) = first_constraint_reason {
            return AuthzResult {
                allowed: false,
                reason: "constraints_not_satisfied".to_owned(),
                reason_detail: Some(reason_detail),
                grants: Vec::new(),
            };
        }
        let has_revoked_upstream_grant = matching_request_has_revoked_upstream_grant(
            &snapshot, actor, action, resource, realm_id, now,
        );

        // Default rules. Circle-local management deliberately does not use the
        // owner shortcut: Realm ownership/admin handoff must not imply
        // membership, audit, or management over existing Circle scopes.
        if circle_local_management_action_requires_explicit_grant(action) {
            if has_revoked_upstream_grant {
                return AuthzResult {
                    allowed: false,
                    reason: REASON_GRANT_REVOKED_UPSTREAM.to_owned(),
                    reason_detail: None,
                    grants: Vec::new(),
                };
            }
            return AuthzResult {
                allowed: false,
                reason: default_deny_reason(action).to_owned(),
                reason_detail: None,
                grants: Vec::new(),
            };
        }
        if owner.is_some_and(|o| o == actor) {
            return AuthzResult {
                allowed: true,
                reason: "owner".to_owned(),
                reason_detail: None,
                grants: Vec::new(),
            };
        }
        if has_revoked_upstream_grant {
            return AuthzResult {
                allowed: false,
                reason: REASON_GRANT_REVOKED_UPSTREAM.to_owned(),
                reason_detail: None,
                grants: Vec::new(),
            };
        }

        let _ = members;

        AuthzResult {
            allowed: false,
            reason: default_deny_reason(action).to_owned(),
            reason_detail: None,
            grants: Vec::new(),
        }
    }
}

impl Default for SolandAuthzEngine {
    fn default() -> Self {
        Self::new()
    }
}

fn default_deny_reason(action: &str) -> &'static str {
    match action {
        "ak.message.create" => "no_strand_track_message_grant",
        _ => "capability_denied",
    }
}

pub(crate) fn grant_revoked_upstream(
    snapshot: &[Grant],
    grant_id: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> bool {
    let map: BTreeMap<&str, &Grant> = snapshot
        .iter()
        .map(|grant| (grant.grant_id.as_str(), grant))
        .collect();
    let Some(grant) = map.get(grant_id).copied() else {
        return false;
    };
    let Some(mut current) = grant.delegated_from.as_deref() else {
        return false;
    };
    let mut visited = 0usize;
    while let Some(parent) = map.get(current).copied() {
        if visited >= 64 {
            return false;
        }
        visited += 1;
        if parent.revoked || is_grant_expired(parent, now) {
            return true;
        }
        let Some(next) = parent.delegated_from.as_deref() else {
            return false;
        };
        current = next;
    }
    false
}

fn matching_request_has_revoked_upstream_grant(
    snapshot: &[Grant],
    actor: &str,
    action: &str,
    resource: &str,
    realm_id: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> bool {
    snapshot.iter().any(|grant| {
        grant.realm_id == realm_id
            && grant.subject == actor
            && grant_scope_valid(grant).is_ok()
            && grant.actions.iter().any(|candidate| candidate == action)
            && resource_matches(&grant.resource, resource)
            && grant_revoked_upstream(snapshot, &grant.grant_id, now)
    })
}

fn circle_local_management_action_requires_explicit_grant(action: &str) -> bool {
    matches!(
        action,
        "ak.circle.manage"
            | "ak.circle.member.manage"
            | "ak.circle.member.add.others"
            | "ak.circle.audit"
    )
}

/// Check if a grant resource pattern matches the requested resource.
///
/// AKP-0007 / SEL-1 (R3 spec-sync 2026-05-27, arkret-spec b47ff6ec) —
/// the spec resource-selector enum admits `realm`, `space`, `strand`,
/// `morph`, `circle`, `actor`. soland's resource matcher accepts the
/// `ak:circle:<uuid>` typed-id form alongside the existing space /
/// realm forms, plus a `circle` keyword selector that resolves to
/// "any ak:circle:<uuid>" so policy-authoring tools can express
/// circle-wide grants without enumerating each circle.
pub(crate) fn resource_matches(pattern: &str, resource: &str) -> bool {
    if pattern == "*" {
        return false;
    }
    let resources = resource
        .split(',')
        .map(str::trim)
        .filter(|resource| !resource.is_empty())
        .collect::<Vec<_>>();
    if resources.is_empty() {
        return false;
    }
    pattern.split(',').any(|alternative| {
        let alternative = alternative.trim();
        !alternative.is_empty()
            && alternative.split('+').map(str::trim).all(|term| {
                !term.is_empty()
                    && resources
                        .iter()
                        .any(|resource| resource_term_matches(term, resource))
            })
    })
}

fn resource_term_matches(pattern: &str, resource: &str) -> bool {
    if pattern == "*" {
        return false;
    }
    if pattern == resource {
        return true;
    }
    match pattern {
        "realm" => return resource.starts_with("ak:realm:"),
        "space" => return resource.starts_with("ak:space:"),
        "circle" => return resource.starts_with("ak:circle:"),
        "strand" => return resource.starts_with("ak:strand:"),
        "message" => {
            return resource.starts_with("ak:message:") || resource.starts_with("ak:event:");
        }
        "morph" => return resource.starts_with("ak:morph:"),
        "object" => return is_canonical_object_ref(resource),
        "relation" => return resource.starts_with("ak:relation:"),
        "view" => return resource.starts_with("ak:view:"),
        "event" => return resource.starts_with("ak:event:"),
        "actor" => return resource.starts_with("did:") || resource.starts_with("ak:actor:"),
        "schema" => {
            return resource.starts_with("ak:schema:") || resource.starts_with("ak.schema.");
        }
        "policy" => return resource.starts_with("ak:policy:"),
        "invite" => return resource.starts_with("ak:invite:"),
        "notification" => return resource.starts_with("ak:notification:"),
        "read_cursor" => return resource.starts_with("ak:read_cursor:"),
        "blob" => return resource.starts_with("ak:blob:"),
        _ => {}
    }
    if let Some(prefix) = pattern.strip_suffix('*') {
        return resource.starts_with(prefix);
    }
    false
}

fn is_canonical_object_ref(value: &str) -> bool {
    [
        "ak:realm:",
        "ak:space:",
        "ak:circle:",
        "ak:strand:",
        "ak:message:",
        "ak:morph:",
        "ak:relation:",
        "ak:view:",
        "ak:event:",
        "ak:policy:",
        "ak:invite:",
        "ak:blob:",
    ]
    .iter()
    .any(|prefix| value.starts_with(prefix))
}

pub(crate) fn grant_scope_valid(grant: &Grant) -> Result<(), &'static str> {
    validate_capability_actions(&grant.actions)?;
    validate_resource_pattern(&grant.resource)
}

pub(crate) fn validate_capability_actions(actions: &[String]) -> Result<(), &'static str> {
    if actions.is_empty() {
        return Err("capability_grant_actions_empty");
    }
    for action in actions {
        validate_capability_action(action)?;
    }
    Ok(())
}

fn validate_capability_action(action: &str) -> Result<(), &'static str> {
    validate_capability_action_shape(
        action,
        "capability_grant_action_wildcard_forbidden",
        "capability_grant_action_invalid",
    )?;
    validate_registered_capability_action(action, REASON_CAPABILITY_GRANT_ACTION_UNKNOWN)
}

fn validate_runtime_capability_action(action: &str) -> Result<(), &'static str> {
    validate_capability_action_shape(
        action,
        REASON_CAPABILITY_ACTION_WILDCARD_FORBIDDEN,
        REASON_CAPABILITY_ACTION_INVALID,
    )?;
    validate_registered_capability_action(action, REASON_CAPABILITY_ACTION_UNKNOWN)
}

fn validate_capability_action_shape(
    action: &str,
    wildcard_reason: &'static str,
    invalid_reason: &'static str,
) -> Result<(), &'static str> {
    if action.contains('*') {
        return Err(wildcard_reason);
    }
    let mut segments = action.split('.');
    if segments.next() != Some("ak") {
        return Err(invalid_reason);
    }
    let mut saw_segment = false;
    for segment in segments {
        saw_segment = true;
        if segment.is_empty()
            || !segment
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
        {
            return Err(invalid_reason);
        }
    }
    if !saw_segment {
        return Err(invalid_reason);
    }
    Ok(())
}

fn validate_registered_capability_action(
    action: &str,
    unknown_reason: &'static str,
) -> Result<(), &'static str> {
    match arkret_sdk::schema::embedded_capability_action(action) {
        Ok(Some(_)) => Ok(()),
        Ok(None) => Err(unknown_reason),
        Err(_) => Err(REASON_CAPABILITY_ACTION_REGISTRY_UNAVAILABLE),
    }
}

pub(crate) fn validate_resource_pattern(pattern: &str) -> Result<(), &'static str> {
    let pattern = pattern.trim();
    if pattern == "*" {
        return Err("capability_grant_resource_wildcard_forbidden");
    }
    if pattern.len() > SELECTOR_SHORTHAND_MAX_BYTES {
        return Err("selector_too_complex");
    }
    if pattern.is_empty() {
        return Err("capability_grant_resource_invalid");
    }

    let alternatives: Vec<&str> = pattern.split(',').collect();
    if alternatives.len() > SELECTOR_DISJUNCTION_MAX {
        return Err("selector_too_complex");
    }

    let mut token_count = 0usize;
    let mut term_count = 0usize;
    for alternative in alternatives {
        let terms: Vec<&str> = alternative.split('+').collect();
        for term in terms {
            let term = term.trim();
            if term.is_empty() {
                return Err("capability_grant_resource_invalid");
            }
            if term.len() > SELECTOR_TERM_MAX_BYTES {
                return Err("selector_too_complex");
            }
            validate_resource_selector_term(term)?;
            term_count += 1;
        }
    }
    token_count += term_count;
    if term_count > 0 {
        token_count += pattern.matches(',').count() + pattern.matches('+').count();
    }
    if token_count > SELECTOR_TOKEN_MAX || term_count > SELECTOR_CONJUNCTION_MAX {
        return Err("selector_too_complex");
    }

    Ok(())
}

pub(crate) fn validate_resource_selector_object(
    map: &Map<String, Value>,
) -> Result<(), &'static str> {
    let json_bytes = serde_json::to_vec(map).map_err(|_| "capability_grant_resources_invalid")?;
    if json_bytes.len() > SELECTOR_JSON_MAX_BYTES {
        return Err("selector_too_complex");
    }
    let unknown_fields = map
        .keys()
        .filter(|key| !RESOURCE_SELECTOR_KNOWN_FIELDS.contains(&key.as_str()))
        .count();
    if unknown_fields > 0 {
        return Err("capability_grant_resources_invalid");
    }
    let Some(kind) = map.get("kind").and_then(Value::as_str) else {
        return Err("capability_grant_resources_invalid");
    };
    if !RESOURCE_SELECTOR_KINDS.contains(&kind) {
        return Err("capability_grant_resources_invalid");
    }
    let match_scope = map
        .get("match_scope")
        .and_then(Value::as_str)
        .unwrap_or("exact");
    if !matches!(match_scope, "exact" | "children" | "subtree" | "realm_wide") {
        return Err("capability_grant_resources_invalid");
    }
    if match_scope == "realm_wide" && map.get("realm_id").and_then(Value::as_str).is_none() {
        return Err("capability_grant_resources_invalid");
    }
    if matches!(match_scope, "children" | "subtree") && kind != "space" {
        return Err("capability_grant_resources_invalid");
    }
    if matches!(match_scope, "children" | "subtree")
        && map
            .get("space_id")
            .and_then(Value::as_str)
            .is_none_or(|value| value.trim().is_empty())
    {
        return Err("capability_grant_resources_invalid");
    }
    if match_scope == "realm_wide" && !matches!(kind, "space" | "circle") {
        return Err("capability_grant_resources_invalid");
    }
    if matches!(kind, "space" | "circle" | "notification" | "read_cursor")
        && map.get("realm_id").and_then(Value::as_str).is_none()
    {
        return Err("capability_grant_resources_invalid");
    }
    if map.get("actor_id").and_then(Value::as_str) == Some("*") {
        return Err("selector_actor_wildcard_forbidden");
    }
    if map.get("kind").and_then(Value::as_str) == Some("actor")
        && map.get("actor_id").and_then(Value::as_str).is_none()
    {
        return Err("selector_actor_wildcard_forbidden");
    }
    if selector_uses_governance_wildcard(map) {
        return Err("selector_governance_wildcard_forbidden");
    }
    for value in map.values() {
        validate_selector_field_value(value)?;
    }
    Ok(())
}

fn validate_selector_field_value(value: &Value) -> Result<(), &'static str> {
    match value {
        Value::String(value) if value.len() > SELECTOR_TERM_MAX_BYTES => {
            Err("selector_too_complex")
        }
        Value::Array(values) => {
            for value in values {
                validate_selector_field_value(value)?;
            }
            Ok(())
        }
        Value::Object(object) => {
            for value in object.values() {
                validate_selector_field_value(value)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn validate_resource_selector_term(term: &str) -> Result<(), &'static str> {
    if term == "*" {
        return Err("capability_grant_resource_wildcard_forbidden");
    }
    if term == "actor:*" {
        return Err("selector_actor_wildcard_forbidden");
    }
    if selector_term_uses_governance_wildcard(term) {
        return Err("selector_governance_wildcard_forbidden");
    }
    Ok(())
}

fn selector_term_uses_governance_wildcard(term: &str) -> bool {
    if term == "policy:*" || (term.starts_with("policy:") && term.ends_with(":*")) {
        return true;
    }
    if term == "schema:*" || (term.starts_with("schema:") && term.ends_with(":*")) {
        return true;
    }
    let Some(tail) = object_selector_tail(term) else {
        return false;
    };
    matches!(tail.as_str(), "policy" | "schema")
}

fn object_selector_tail(term: &str) -> Option<String> {
    let remainder = term.strip_prefix("object:")?;
    if remainder == "*" {
        return None;
    }
    if let Some(tail) = remainder.strip_prefix("*:") {
        return (!tail.is_empty()).then(|| tail.to_owned());
    }
    let parts = remainder.split(':').collect::<Vec<_>>();
    if parts.len() <= 3 || parts[0] != "ak" || parts[1] != "realm" || parts[2].is_empty() {
        return None;
    }
    let tail = parts[3..].join(":");
    (!tail.is_empty()).then_some(tail)
}

fn selector_uses_governance_wildcard(map: &Map<String, Value>) -> bool {
    match map.get("kind").and_then(Value::as_str) {
        Some("policy") => {
            selector_field_missing_or_wildcard(map, "policy_id")
                || selector_field_missing_or_wildcard(map, "realm_id")
        }
        Some("schema") => {
            selector_field_missing_or_wildcard(map, "schema_ref")
                || selector_field_missing_or_wildcard(map, "realm_id")
        }
        Some("object") => {
            let object_type = map.get("object_type").and_then(Value::as_str);
            let object_ref = map.get("object_ref").and_then(Value::as_str);
            let governance_type = matches!(object_type, Some("policy" | "schema"));
            let governance_ref = object_ref.is_some_and(|value| {
                value.starts_with("ak:policy:") || value.starts_with("ak:schema:")
            });
            (governance_type
                && (selector_field_missing_or_wildcard(map, "object_ref")
                    || selector_field_missing_or_wildcard(map, "realm_id")))
                || (governance_ref && selector_field_missing_or_wildcard(map, "realm_id"))
        }
        _ => false,
    }
}

fn selector_field_missing_or_wildcard(map: &Map<String, Value>, field: &str) -> bool {
    map.get(field)
        .and_then(Value::as_str)
        .is_none_or(|value| value == "*")
}

/// Pick the resulting decision over a set of satisfied grants.
///
/// Per Arkret v1 (spec optimization round, _todos B3/B5): the three non-allow
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
            // AKP-0007 (spec b7d35be) — narrow a Circle-management
            // capability (`ak.circle.manage`, `ak.circle.member.manage`,
            // `ak.circle.member.add.others`, `ak.circle.audit`) to a
            // specific Circle id set. The spec
            // `capability-action-registry.json` declares
            // `required_constraints=["allowed_circle_ids"]` on each
            // gated action; unconstrained Realm-wide grants for these
            // actions MUST be rejected (a separate guard at grant-issue
            // time).
            //
            // Evaluation contract: the resource selector for a Circle
            // capability is of the form `ak:circle:<uuid>` (mirrors the
            // `ak:space:<uuid>` pattern used by `realm.*` / `space.*`
            // grants). If the resource looks like a Circle id, it MUST
            // be a member of the allowed set; otherwise the constraint
            // does not apply and silently passes (caller-policy: any
            // non-Circle resource is out of this constraint's scope).
            if allowed_circle_ids.is_empty() {
                return Some(
                    "allowed_circle_ids constraint requires a non-empty allow list".to_owned(),
                );
            }
            if !resource.starts_with("ak:circle:") {
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
        Constraint::AllowedSessionIds {
            allowed_session_ids,
        } => {
            if allowed_session_ids.is_empty() {
                return Some(
                    "allowed_session_ids constraint requires a non-empty allow list".to_owned(),
                );
            }
            if !resource.starts_with("ak:agent_interop_session:") {
                return None;
            }
            if allowed_session_ids
                .iter()
                .any(|session| session.as_ref() == resource)
            {
                None
            } else {
                let allowed: Vec<&str> = allowed_session_ids.iter().map(AsRef::as_ref).collect();
                Some(format!(
                    "allowed_session_ids constraint not satisfied: {resource:?} not in {allowed:?}"
                ))
            }
        }
        Constraint::AllowedObjectFacets { facets: allowed } => {
            // Resource must carry at least one of the listed facets. When the
            // resource itself reports no facets, fail-closed — the grant is
            // facet-bound and an unfaceted target falls outside its scope.
            //
            // The check works on any spec-typed object resource that
            // carries a `facets` field; `ak:strand:` / `ak:space:` /
            // `ak:morph:` projections all surface facets through the
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
        Constraint::AppletDelegationBinding { .. } => {
            // Applet binding is checked by the Applet event reducer, where the
            // installed package and registration epoch evidence are available.
            None
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
        remote: Option<arkret_sdk::PolicyCheckOutcome>,
    },
    LocalDeny(AuthzResult),
    RemoteDeny {
        local: AuthzResult,
        remote: arkret_sdk::PolicyCheckOutcome,
    },
    RemoteObligationFailed {
        local: AuthzResult,
        remote: arkret_sdk::PolicyCheckOutcome,
        error: obligation_executor::ObligationError,
    },
}

impl MergedAuthzDecision {
    pub fn is_allowed(&self) -> bool {
        matches!(self, MergedAuthzDecision::Allowed { .. })
    }
}

/// G3.S2 — integration helper. Runs the local capability check first;
/// if it allows AND the realm has a `ak.realm.policy_server` config,
/// calls the remote policy server. Merges the two decisions per the
/// spec rule "deny if either denies; allow only if both allow", then
/// runs the remote response's obligations through the executor.
///
/// `realm_id` is the canonical Realm identifier the policy server
/// keys decisions on (NOT the SDK `RealmId` newtype — pass the wire string).
pub(crate) fn revocation_freshness_fail_closed(
    action: &str,
    freshness_state: arkret_sdk::FreshnessState,
) -> bool {
    use arkret_sdk::FreshnessState;
    use arkret_sdk::schema::CapabilityRiskTier;

    match freshness_state {
        FreshnessState::Fresh => false,
        FreshnessState::Stale => !matches!(
            capability_action_risk_tier(action),
            Some(CapabilityRiskTier::Low | CapabilityRiskTier::Medium)
        ),
        FreshnessState::Unknown => !matches!(
            capability_action_risk_tier(action),
            Some(CapabilityRiskTier::Low)
        ),
    }
}

fn capability_action_risk_tier(action: &str) -> Option<arkret_sdk::schema::CapabilityRiskTier> {
    arkret_sdk::schema::embedded_capability_action(action)
        .ok()
        .flatten()
        .map(|descriptor| descriptor.risk_tier)
}

#[allow(clippy::too_many_arguments)]
pub async fn check_with_policy_server(
    engine: &SolandAuthzEngine,
    actor: &str,
    action: &str,
    resource: &str,
    realm_id: &str,
    owner: Option<&str>,
    members: &[String],
    resource_facets: &[String],
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
        realm_id,
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

    use arkret_sdk::models::AuthzDecision;
    let allow = matches!(remote.decision, AuthzDecision::Allow);
    if !allow {
        return MergedAuthzDecision::RemoteDeny { local, remote };
    }
    if revocation_freshness_fail_closed(action, remote.freshness_state) {
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
        let engine = SolandAuthzEngine::new();
        let result = engine.check(
            "did:web:alice",
            "ak.message.create",
            "ak:space:1",
            "ak:space:1",
            Some("did:web:alice"),
            &[],
            &[],
        );
        assert!(result.allowed);
        assert_eq!(result.reason, "owner");
    }

    #[test]
    fn unknown_action_denied_before_owner_default_allow() {
        let engine = SolandAuthzEngine::new();
        let result = engine.check(
            "did:web:alice",
            "ak.future.action",
            "ak:space:1",
            "ak:space:1",
            Some("did:web:alice"),
            &[],
            &[],
        );
        assert!(!result.allowed);
        assert_eq!(result.reason, REASON_CAPABILITY_ACTION_UNKNOWN);
    }

    #[test]
    fn unknown_action_grant_is_fail_closed() {
        let engine = SolandAuthzEngine::new();
        let grant = engine.create_grant(
            "ak:space:1".to_owned(),
            "did:web:alice".to_owned(),
            "did:web:bob".to_owned(),
            "ak:space:1".to_owned(),
            vec!["ak.future.action".to_owned()],
            vec![],
        );
        assert!(engine.get_grant(&grant.grant_id).is_none());
        assert_eq!(
            validate_capability_actions(&grant.actions),
            Err(REASON_CAPABILITY_GRANT_ACTION_UNKNOWN)
        );

        let result = engine.check(
            "did:web:bob",
            "ak.future.action",
            "ak:space:1",
            "ak:space:1",
            None,
            &[],
            &[],
        );
        assert!(!result.allowed);
        assert_eq!(result.reason, REASON_CAPABILITY_ACTION_UNKNOWN);
    }

    #[test]
    fn owner_does_not_get_circle_local_management_by_default() {
        let engine = SolandAuthzEngine::new();
        for action in [
            "ak.circle.manage",
            "ak.circle.member.manage",
            "ak.circle.member.add.others",
            "ak.circle.audit",
        ] {
            let result = engine.check(
                "did:web:alice",
                action,
                "ak:circle:01904100-0000-7000-8000-000000000001",
                "ak:realm:01904100-0000-7000-8000-000000000001",
                Some("did:web:alice"),
                &[],
                &[],
            );
            assert!(!result.allowed, "{action} should require an explicit grant");
            assert_eq!(result.reason, "capability_denied");
        }
    }

    #[test]
    fn membership_does_not_grant_baseline_capability() {
        let engine = SolandAuthzEngine::new();
        let members = vec!["did:web:bob".to_owned()];
        let read = engine.check(
            "did:web:bob",
            "ak.strand.read",
            "ak:space:1",
            "ak:space:1",
            Some("did:web:alice"),
            &members,
            &[],
        );
        assert!(!read.allowed);
        assert_eq!(read.reason, "capability_denied");

        let write = engine.check(
            "did:web:bob",
            "ak.message.create",
            "ak:space:1",
            "ak:space:1",
            Some("did:web:alice"),
            &members,
            &[],
        );
        assert!(!write.allowed);
        assert_eq!(write.reason, "no_strand_track_message_grant");
    }

    #[test]
    fn member_read_requires_explicit_grant() {
        let engine = SolandAuthzEngine::new();
        let members = vec!["did:web:bob".to_owned()];
        engine.create_grant(
            "ak:space:1".to_owned(),
            "did:web:alice".to_owned(),
            "did:web:bob".to_owned(),
            "ak:space:1".to_owned(),
            vec!["ak.strand.read".to_owned()],
            vec![],
        );
        let result = engine.check(
            "did:web:bob",
            "ak.strand.read",
            "ak:space:1",
            "ak:space:1",
            Some("did:web:alice"),
            &members,
            &[],
        );
        assert!(result.allowed);
        assert_eq!(result.reason, "explicit_grant");
    }

    #[test]
    fn explicit_grant_overrides_default() {
        let engine = SolandAuthzEngine::new();
        engine.create_grant(
            "ak:space:1".to_owned(),
            "did:web:alice".to_owned(),
            "did:web:bob".to_owned(),
            "ak:space:1".to_owned(),
            vec!["ak.message.create".to_owned()],
            vec![],
        );
        let result = engine.check(
            "did:web:bob",
            "ak.message.create",
            "ak:space:1",
            "ak:space:1",
            Some("did:web:alice"),
            &[],
            &[],
        );
        assert!(result.allowed);
        assert_eq!(result.reason, "explicit_grant");
    }

    #[test]
    fn explicit_deny_overrides_allow() {
        let engine = SolandAuthzEngine::new();
        engine.create_grant(
            "ak:space:1".to_owned(),
            "did:web:alice".to_owned(),
            "did:web:bob".to_owned(),
            "ak:space:1".to_owned(),
            vec!["ak.message.create".to_owned()],
            vec![Constraint::Decision {
                decision: GrantDecisionVerdict::Allow,
            }],
        );
        engine.create_grant(
            "ak:space:1".to_owned(),
            "did:web:alice".to_owned(),
            "did:web:bob".to_owned(),
            "ak:space:1".to_owned(),
            vec!["ak.message.create".to_owned()],
            vec![Constraint::Decision {
                decision: GrantDecisionVerdict::Deny,
            }],
        );
        let result = engine.check(
            "did:web:bob",
            "ak.message.create",
            "ak:space:1",
            "ak:space:1",
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
        let engine = SolandAuthzEngine::new();
        engine.create_grant(
            "ak:space:1".to_owned(),
            "did:web:alice".to_owned(),
            "did:web:bob".to_owned(),
            "ak:space:1".to_owned(),
            vec!["ak.message.create".to_owned()],
            vec![Constraint::Decision {
                decision: GrantDecisionVerdict::RequireReview,
            }],
        );
        engine.create_grant(
            "ak:space:1".to_owned(),
            "did:web:alice".to_owned(),
            "did:web:bob".to_owned(),
            "ak:space:1".to_owned(),
            vec!["ak.message.create".to_owned()],
            vec![Constraint::Decision {
                decision: GrantDecisionVerdict::Allow,
            }],
        );
        let reviewed = engine.check(
            "did:web:bob",
            "ak.message.create",
            "ak:space:1",
            "ak:space:1",
            Some("did:web:alice"),
            &[],
            &[],
        );
        assert!(!reviewed.allowed, "require_review must outrank allow");
        assert_eq!(reviewed.reason, "require_review");

        engine.create_grant(
            "ak:space:1".to_owned(),
            "did:web:alice".to_owned(),
            "did:web:bob".to_owned(),
            "ak:space:1".to_owned(),
            vec!["ak.message.create".to_owned()],
            vec![Constraint::Decision {
                decision: GrantDecisionVerdict::Quarantine,
            }],
        );
        let quarantined = engine.check(
            "did:web:bob",
            "ak.message.create",
            "ak:space:1",
            "ak:space:1",
            Some("did:web:alice"),
            &[],
            &[],
        );
        assert!(!quarantined.allowed);
        assert_eq!(quarantined.reason, "quarantine");
    }

    #[test]
    fn revoked_grant_denied() {
        let engine = SolandAuthzEngine::new();
        let grant = engine.create_grant(
            "ak:space:1".to_owned(),
            "did:web:alice".to_owned(),
            "did:web:bob".to_owned(),
            "ak:space:1".to_owned(),
            vec!["ak.message.create".to_owned()],
            vec![],
        );
        engine.revoke_grant_with_cascade(&grant.grant_id);
        let result = engine.check(
            "did:web:bob",
            "ak.message.create",
            "ak:space:1",
            "ak:space:1",
            Some("did:web:alice"),
            &[],
            &[],
        );
        assert!(!result.allowed);
    }

    #[test]
    fn delegated_child_denied_with_upstream_revocation_reason() {
        let engine = SolandAuthzEngine::new();
        let parent = engine.create_grant(
            "ak:space:1".to_owned(),
            "did:web:alice".to_owned(),
            "did:web:bob".to_owned(),
            "ak:space:1".to_owned(),
            vec!["ak.message.create".to_owned()],
            vec![],
        );
        let child = engine
            .create_delegated_grant(
                &parent.grant_id,
                "did:web:bob".to_owned(),
                "did:web:carol".to_owned(),
                "ak:space:1".to_owned(),
                vec!["ak.message.create".to_owned()],
                vec![],
                None,
            )
            .expect("child grant should be valid before parent revoke");
        engine.revoke_grant_with_cascade(&parent.grant_id);
        let result = engine.check(
            "did:web:carol",
            "ak.message.create",
            "ak:space:1",
            "ak:space:1",
            Some("did:web:alice"),
            &[],
            &[],
        );
        assert!(!result.allowed);
        assert_eq!(result.reason, REASON_GRANT_REVOKED_UPSTREAM);
        assert!(
            engine
                .get_grant(&child.grant_id)
                .is_some_and(|grant| grant.revoked),
            "cascade marks the child revoked in the index"
        );
    }

    #[test]
    fn stranger_denied() {
        let engine = SolandAuthzEngine::new();
        let result = engine.check(
            "did:web:eve",
            "ak.strand.read",
            "ak:space:1",
            "ak:space:1",
            Some("did:web:alice"),
            &[],
            &[],
        );
        assert!(!result.allowed);
    }

    #[test]
    fn wildcard_action_grant_is_fail_closed() {
        let engine = SolandAuthzEngine::new();
        engine.create_grant(
            "ak:realm:1".to_owned(),
            "did:web:alice".to_owned(),
            "did:web:bob".to_owned(),
            "ak:realm:1".to_owned(),
            vec!["ak.pin.*".to_owned()],
            vec![],
        );
        let result = engine.check(
            "did:web:bob",
            "ak.pin.add",
            "ak:realm:1",
            "ak:realm:1",
            None,
            &[],
            &[],
        );
        assert!(!result.allowed);
        assert_eq!(result.reason, "capability_denied");
    }

    #[test]
    fn bare_wildcard_resource_grant_is_fail_closed() {
        let engine = SolandAuthzEngine::new();
        engine.create_grant(
            "ak:realm:1".to_owned(),
            "did:web:alice".to_owned(),
            "did:web:bob".to_owned(),
            "*".to_owned(),
            vec!["ak.pin.add".to_owned()],
            vec![],
        );
        let result = engine.check(
            "did:web:bob",
            "ak.pin.add",
            "ak:realm:1",
            "ak:realm:1",
            None,
            &[],
            &[],
        );
        assert!(!result.allowed);
        assert_eq!(result.reason, "capability_denied");
    }
}
