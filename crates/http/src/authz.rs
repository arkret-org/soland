//! Capability-based authorization engine.
//!
//! Evaluates grants to determine whether an actor may perform an action
//! on a resource within a scope. Default rules:
//! - Active explicit grants authorize actors
//! - Realm ownership and membership never imply a capability
//!
use std::collections::BTreeMap;
use std::sync::Arc;

// Delegation primitives — `Grant`, `GrantConstraint`,
// and the chain-integrity / expiry helpers — live in the SDK so inkson and
// sodmin admin can call them client-side. See
// `arkret_policy::authz::authority`.
//
// Grant *authoring* (issuance, re-delegation, revoke cascade) is NOT mirrored
// here: the accepted `ak.component.capability.grant.v1` cell projection in
// `soland_domain::reducer::apply_capability` is the only place a grant comes
// into existence, and this engine is strictly the read-side index over it.
pub use arkret_policy::authz::authority::{
    AppletAuthorityBindingError, Grant, GrantConstraint, GrantDecisionVerdict,
    authority_chain_intact, is_grant_expired, validate_applet_authority_binding,
};
use parking_lot::Mutex;
use serde::Serialize;
pub(crate) use soland_domain::capability::resource_matches;
use soland_domain::capability::validate_resource_pattern;
use soland_services::authorization::AuthorizationService;

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

    pub fn mark_projected_grants_revoked_for_subject(
        &self,
        subject: &str,
        subject_principal_server_id: Option<&str>,
    ) -> usize {
        let mut count = 0usize;
        let mut grants = self.grants.lock();
        for grant in grants.values_mut() {
            if grant.subject_id.as_str() == subject
                && grant
                    .subject_principal_server_id
                    .as_ref()
                    .map(arkret_wire::DidCoreId::as_str)
                    == subject_principal_server_id
                && !grant.revoked
            {
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
    pub fn grants_for_subject(
        &self,
        subject: &str,
        subject_principal_server_id: Option<&str>,
        realm_id: &str,
    ) -> Vec<Grant> {
        self.grants_for_subject_at(
            subject,
            subject_principal_server_id,
            realm_id,
            chrono::Utc::now(),
        )
    }

    /// Return grants effective at the caller-selected evaluation instant.
    pub fn grants_for_subject_at(
        &self,
        subject: &str,
        subject_principal_server_id: Option<&str>,
        realm_id: &str,
        evaluated_at: chrono::DateTime<chrono::Utc>,
    ) -> Vec<Grant> {
        let snapshot: Vec<Grant> = self.grants.lock().values().cloned().collect();
        snapshot
            .iter()
            .filter(|g| {
                g.subject_id.as_str() == subject
                    && g.subject_principal_server_id
                        .as_ref()
                        .map(arkret_wire::DidCoreId::as_str)
                        == subject_principal_server_id
                    && g.realm_id == realm_id
                    && grant_scope_valid(g).is_ok()
                    && !g.revoked
                    && g.created_at <= evaluated_at
                    && !is_grant_expired(g, evaluated_at)
                    && authority_chain_intact(&snapshot, &g.grant_id, evaluated_at)
            })
            .cloned()
            .collect()
    }

    /// Get all effective grants held by `subject` across every realm.
    /// Same filtering as [`Self::grants_for_subject`] minus the realm pin —
    /// read model for the controller-facing agent settings surface
    /// (`GET /_arkret/self/agents/{id}` `agent_view.grants[]`).
    pub fn grants_for_subject_all_realms(
        &self,
        subject: &str,
        subject_principal_server_id: Option<&str>,
    ) -> Vec<Grant> {
        let snapshot: Vec<Grant> = self.grants.lock().values().cloned().collect();
        let now = chrono::Utc::now();
        snapshot
            .iter()
            .filter(|g| {
                g.subject_id.as_str() == subject
                    && g.subject_principal_server_id
                        .as_ref()
                        .map(arkret_wire::DidCoreId::as_str)
                        == subject_principal_server_id
                    && grant_scope_valid(g).is_ok()
                    && !g.revoked
                    && !is_grant_expired(g, now)
                    && authority_chain_intact(&snapshot, &g.grant_id, now)
            })
            .cloned()
            .collect()
    }

    pub(crate) fn grants_snapshot(&self) -> Vec<Grant> {
        self.grants.lock().values().cloned().collect()
    }

    /// Check if an actor can perform an action on a resource.
    ///
    /// When no explicit active grant matches, authorization is denied.
    #[allow(clippy::too_many_arguments)]
    pub fn check(
        &self,
        actor: &str,
        action: &str,
        resource: &str,
        realm_id: &str,
        _owner: Option<&str>,
        _members: &[String],
        resource_facets: &[String],
    ) -> AuthzResult {
        self.check_for_authority(
            actor,
            None,
            action,
            resource,
            realm_id,
            _owner,
            _members,
            resource_facets,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn check_for_authority(
        &self,
        actor: &str,
        actor_principal_server_id: Option<&str>,
        action: &str,
        resource: &str,
        realm_id: &str,
        _owner: Option<&str>,
        _members: &[String],
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
                    && g.subject_id.as_str() == actor
                    && g.subject_principal_server_id
                        .as_ref()
                        .map(arkret_wire::DidCoreId::as_str)
                        == actor_principal_server_id
                    && grant_scope_valid(g).is_ok()
                    && g.actions.iter().any(|a| a == action)
                    && resource_matches(&g.resource, resource)
                    && !is_grant_expired(g, now)
                    && authority_chain_intact(&snapshot, &g.grant_id, now)
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
            &snapshot,
            actor,
            actor_principal_server_id,
            action,
            resource,
            realm_id,
            now,
        );

        if has_revoked_upstream_grant {
            return AuthzResult {
                allowed: false,
                reason: arkret_wire::ReasonCode::GRANT_REVOKED_UPSTREAM.to_owned(),
                reason_detail: None,
                grants: Vec::new(),
            };
        }

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

/// Test fixture — an already-resolved `Grant` shaped exactly like the one the
/// capability-cell projection folds into the read index.
///
/// Tests use this instead of a service-side issuance API: soland has no such
/// API, because a grant only exists once an accepted
/// `ak.component.capability.grant.v1` cell projects it.
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn projected_grant_fixture(
    realm_id: String,
    issuer: String,
    subject: String,
    resource: String,
    actions: Vec<String>,
    constraints: Vec<GrantConstraint>,
) -> Grant {
    Grant {
        // `grant` is Event-derived, so the id can only be the create Event's
        // token retyped. The fixture stands in for an accepted
        // `ak.capability.grant`, so it derives one from a synthetic Event
        // digest rather than minting a UUID the SDK would reject.
        grant_id: {
            static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
            let seq = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let digest = arkret_canonical::sha256_bytes(seq.to_be_bytes());
            let event_id = arkret_identifiers::EventId::from_digest(
                arkret_canonical::DigestSuite::Sha256,
                digest,
            );
            arkret_identifiers::GrantId::from_event_id(&event_id).into_string()
        },
        realm_id,
        issuer_principal_server_id: arkret_wire::DidCoreId::new(issuer.clone()).unwrap(),
        issuer_id: arkret_wire::DidCoreId::new(issuer).unwrap(),
        subject_id: arkret_wire::DidCoreId::new(subject).unwrap(),
        subject_principal_server_id: None,
        resource,
        actions,
        constraints,
        revoked: false,
        created_at: chrono::Utc::now(),
        issuer_authority_refs: Vec::new(),
        authority_depth: None,
        authority_root_refs: Vec::new(),
    }
}

/// Install [`projected_grant_fixture`] through the same projection ingress the
/// reducer-driven projection driver uses, and hand the grant back so the test
/// can cite its `grant_id`.
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn install_projected_grant(
    authz: &AuthorizationService,
    realm_id: String,
    issuer: String,
    subject: String,
    resource: String,
    actions: Vec<String>,
    constraints: Vec<GrantConstraint>,
) -> Grant {
    let grant = projected_grant_fixture(realm_id, issuer, subject, resource, actions, constraints);
    authz.upsert_projected_grant(grant.clone());
    grant
}

fn default_deny_reason(action: &str) -> &'static str {
    match action {
        arkret_wire::CapabilityActionId::MESSAGE_CREATE => "no_strand_track_message_grant",
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
    // Every `grant` ref is walked: multiple refs only add constraints, so one
    // revoked ancestor on any path is enough. A grant that names only
    // `realm_root` refs has no upstream to be revoked.
    let mut pending: Vec<&str> = grant
        .issuer_authority_refs
        .iter()
        .filter_map(arkret_policy::authz::authority::IssuerAuthorityRef::grant_id)
        .collect();
    let mut visited: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
    while let Some(current) = pending.pop() {
        if !visited.insert(current) {
            continue;
        }
        if visited.len() > 64 {
            return false;
        }
        let Some(parent) = map.get(current).copied() else {
            return false;
        };
        if parent.revoked || is_grant_expired(parent, now) {
            return true;
        }
        pending.extend(
            parent
                .issuer_authority_refs
                .iter()
                .filter_map(arkret_policy::authz::authority::IssuerAuthorityRef::grant_id),
        );
    }
    false
}

fn matching_request_has_revoked_upstream_grant(
    snapshot: &[Grant],
    actor: &str,
    actor_principal_server_id: Option<&str>,
    action: &str,
    resource: &str,
    realm_id: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> bool {
    snapshot.iter().any(|grant| {
        grant.realm_id == realm_id
            && grant.subject_id.as_str() == actor
            && grant
                .subject_principal_server_id
                .as_ref()
                .map(arkret_wire::DidCoreId::as_str)
                == actor_principal_server_id
            && grant_scope_valid(grant).is_ok()
            && grant.actions.iter().any(|candidate| candidate == action)
            && resource_matches(&grant.resource, resource)
            && grant_revoked_upstream(snapshot, &grant.grant_id, now)
    })
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
    match arkret_schema::embedded_capability_action(action) {
        Ok(Some(_)) => Ok(()),
        Ok(None) => Err(unknown_reason),
        Err(_) => Err(REASON_CAPABILITY_ACTION_REGISTRY_UNAVAILABLE),
    }
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

fn is_decision_constraint(constraint: &GrantConstraint) -> bool {
    decision_from_constraint(constraint).is_some()
}

fn decision_from_constraint(constraint: &GrantConstraint) -> Option<GrantDecision> {
    match constraint {
        GrantConstraint::Decision { decision } => Some(match decision {
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
    constraint: &GrantConstraint,
    _actor: &str,
    resource: &str,
    resource_facets: &[String],
) -> Option<String> {
    match constraint {
        GrantConstraint::Temporal { expires_at, .. } => {
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
        GrantConstraint::AllowedCircleIds { allowed_circle_ids } => {
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
            // capability is a complete event-derived `ak:circle:` id (mirrors the
            // event-derived `ak:space:` pattern used by `realm.*` / `space.*`
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
                // GrantConstraint is Circle-scoped — non-Circle resources are
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
        GrantConstraint::AllowedSessionIds {
            allowed_session_ids,
        } => {
            if allowed_session_ids.is_empty() {
                return Some(
                    "allowed_session_ids constraint requires a non-empty allow list".to_owned(),
                );
            }
            if allowed_session_ids
                .iter()
                .any(|session| session == resource)
            {
                None
            } else {
                let allowed: Vec<&str> = allowed_session_ids.iter().map(AsRef::as_ref).collect();
                Some(format!(
                    "allowed_session_ids constraint not satisfied: {resource:?} not in {allowed:?}"
                ))
            }
        }
        GrantConstraint::AllowedObjectFacets { facets: allowed } => {
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
        GrantConstraint::AuthorityControl { .. } => {
            // Depth is enforced at chain-walk time. The registered
            // applet_authority subkind is checked by the Applet Event
            // reducer, where registration epoch evidence is available.
            None
        }
        GrantConstraint::RateLimiting {
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
        GrantConstraint::FieldAccess { .. } => {
            // These constraints require operation-derived dotted paths and
            // track targets. DataEvent admission evaluates them against the
            // signed payload in `capability_refs`; this resource-only helper
            // has no safe context from which to do so.
            None
        }
        GrantConstraint::ScopeLimitation {
            allowed_strand_ids,
            denied_strand_ids,
            allowed_circle_ids,
            allowed_session_ids,
            ..
        } => {
            if resource.starts_with("ak:strand:")
                && (denied_strand_ids.iter().any(|id| id == resource)
                    || (!allowed_strand_ids.is_empty()
                        && !allowed_strand_ids.iter().any(|id| id == resource)))
            {
                return Some("scope_limitation does not allow the target Strand".to_owned());
            }
            if resource.starts_with("ak:circle:")
                && (allowed_circle_ids.is_empty()
                    || !allowed_circle_ids.iter().any(|id| id.as_ref() == resource))
            {
                return Some("scope_limitation does not allow the target Circle".to_owned());
            }
            if !allowed_session_ids.is_empty()
                && !resource.starts_with("ak:")
                && !allowed_session_ids.iter().any(|id| id == resource)
            {
                return Some("scope_limitation does not allow the target session".to_owned());
            }
            None
        }
        GrantConstraint::Decision { .. } => {
            // Decision constraints are evaluated separately via
            // `decision_from_constraint`; treat as satisfied here so they
            // never fail the satisfaction check.
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fold a projected grant into the read index, mirroring what the
    /// capability-cell projection driver does for an accepted grant Event.
    fn project(
        engine: &SolandAuthzEngine,
        realm_id: &str,
        issuer: &str,
        subject: &str,
        resource: &str,
        actions: &[&str],
        constraints: Vec<GrantConstraint>,
    ) -> Grant {
        let grant = projected_grant_fixture(
            realm_id.to_owned(),
            issuer.to_owned(),
            subject.to_owned(),
            resource.to_owned(),
            actions.iter().map(|action| (*action).to_owned()).collect(),
            constraints,
        );
        engine.upsert_projected_grant(grant.clone());
        grant
    }

    #[test]
    fn owner_without_explicit_grant_is_denied() {
        let engine = SolandAuthzEngine::new();
        let result = engine.check(
            "ak:did_core:web:alice",
            "ak.message.create",
            "ak:space:1",
            "ak:space:1",
            Some("ak:did_core:web:alice"),
            &[],
            &[],
        );
        assert!(!result.allowed);
        assert_eq!(result.reason, "no_strand_track_message_grant");
    }

    #[test]
    fn unknown_action_denied_for_owner_without_registry_entry() {
        let engine = SolandAuthzEngine::new();
        let result = engine.check(
            "ak:did_core:web:alice",
            "ak.future.action",
            "ak:space:1",
            "ak:space:1",
            Some("ak:did_core:web:alice"),
            &[],
            &[],
        );
        assert!(!result.allowed);
        assert_eq!(result.reason, REASON_CAPABILITY_ACTION_UNKNOWN);
    }

    #[test]
    fn unknown_action_grant_is_fail_closed() {
        let engine = SolandAuthzEngine::new();
        // Even if such a grant somehow reached the read index, the check-time
        // scope filter still refuses it — the index is never the authority.
        let grant = project(
            &engine,
            "ak:space:1",
            "ak:did_core:web:alice",
            "ak:did_core:web:bob",
            "ak:space:1",
            &["ak.future.action"],
            vec![],
        );
        assert_eq!(
            validate_capability_actions(&grant.actions),
            Err(REASON_CAPABILITY_GRANT_ACTION_UNKNOWN)
        );

        let result = engine.check(
            "ak:did_core:web:bob",
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
                "ak:did_core:web:alice",
                action,
                "ak:circle:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
                "ak:realm:Abeq9pC3fxOERl1X0ivHa5cJCBy41KfYu5LKvGfPFq5K",
                Some("ak:did_core:web:alice"),
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
        let members = vec!["ak:did_core:web:bob".to_owned()];
        let read = engine.check(
            "ak:did_core:web:bob",
            "ak.strand.read",
            "ak:space:1",
            "ak:space:1",
            Some("ak:did_core:web:alice"),
            &members,
            &[],
        );
        assert!(!read.allowed);
        assert_eq!(read.reason, "capability_denied");

        let write = engine.check(
            "ak:did_core:web:bob",
            "ak.message.create",
            "ak:space:1",
            "ak:space:1",
            Some("ak:did_core:web:alice"),
            &members,
            &[],
        );
        assert!(!write.allowed);
        assert_eq!(write.reason, "no_strand_track_message_grant");
    }

    #[test]
    fn member_read_requires_explicit_grant() {
        let engine = SolandAuthzEngine::new();
        let members = vec!["ak:did_core:web:bob".to_owned()];
        project(
            &engine,
            "ak:space:1",
            "ak:did_core:web:alice",
            "ak:did_core:web:bob",
            "ak:space:1",
            &["ak.strand.read"],
            vec![],
        );
        let result = engine.check(
            "ak:did_core:web:bob",
            "ak.strand.read",
            "ak:space:1",
            "ak:space:1",
            Some("ak:did_core:web:alice"),
            &members,
            &[],
        );
        assert!(result.allowed);
        assert_eq!(result.reason, "explicit_grant");
    }

    #[test]
    fn explicit_grant_overrides_default() {
        let engine = SolandAuthzEngine::new();
        project(
            &engine,
            "ak:space:1",
            "ak:did_core:web:alice",
            "ak:did_core:web:bob",
            "ak:space:1",
            &["ak.message.create"],
            vec![],
        );
        let result = engine.check(
            "ak:did_core:web:bob",
            "ak.message.create",
            "ak:space:1",
            "ak:space:1",
            Some("ak:did_core:web:alice"),
            &[],
            &[],
        );
        assert!(result.allowed);
        assert_eq!(result.reason, "explicit_grant");
    }

    #[test]
    fn explicit_deny_overrides_allow() {
        let engine = SolandAuthzEngine::new();
        project(
            &engine,
            "ak:space:1",
            "ak:did_core:web:alice",
            "ak:did_core:web:bob",
            "ak:space:1",
            &["ak.message.create"],
            vec![GrantConstraint::Decision {
                decision: GrantDecisionVerdict::Allow,
            }],
        );
        project(
            &engine,
            "ak:space:1",
            "ak:did_core:web:alice",
            "ak:did_core:web:bob",
            "ak:space:1",
            &["ak.message.create"],
            vec![GrantConstraint::Decision {
                decision: GrantDecisionVerdict::Deny,
            }],
        );
        let result = engine.check(
            "ak:did_core:web:bob",
            "ak.message.create",
            "ak:space:1",
            "ak:space:1",
            Some("ak:did_core:web:alice"),
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
        project(
            &engine,
            "ak:space:1",
            "ak:did_core:web:alice",
            "ak:did_core:web:bob",
            "ak:space:1",
            &["ak.message.create"],
            vec![GrantConstraint::Decision {
                decision: GrantDecisionVerdict::RequireReview,
            }],
        );
        project(
            &engine,
            "ak:space:1",
            "ak:did_core:web:alice",
            "ak:did_core:web:bob",
            "ak:space:1",
            &["ak.message.create"],
            vec![GrantConstraint::Decision {
                decision: GrantDecisionVerdict::Allow,
            }],
        );
        let reviewed = engine.check(
            "ak:did_core:web:bob",
            "ak.message.create",
            "ak:space:1",
            "ak:space:1",
            Some("ak:did_core:web:alice"),
            &[],
            &[],
        );
        assert!(!reviewed.allowed, "require_review must outrank allow");
        assert_eq!(reviewed.reason, "require_review");

        project(
            &engine,
            "ak:space:1",
            "ak:did_core:web:alice",
            "ak:did_core:web:bob",
            "ak:space:1",
            &["ak.message.create"],
            vec![GrantConstraint::Decision {
                decision: GrantDecisionVerdict::Quarantine,
            }],
        );
        let quarantined = engine.check(
            "ak:did_core:web:bob",
            "ak.message.create",
            "ak:space:1",
            "ak:space:1",
            Some("ak:did_core:web:alice"),
            &[],
            &[],
        );
        assert!(!quarantined.allowed);
        assert_eq!(quarantined.reason, "quarantine");
    }

    #[test]
    fn revoked_grant_denied() {
        let engine = SolandAuthzEngine::new();
        let grant = project(
            &engine,
            "ak:space:1",
            "ak:did_core:web:alice",
            "ak:did_core:web:bob",
            "ak:space:1",
            &["ak.message.create"],
            vec![],
        );
        engine.mark_projected_grant_revoked(&grant.grant_id);
        let result = engine.check(
            "ak:did_core:web:bob",
            "ak.message.create",
            "ak:space:1",
            "ak:space:1",
            Some("ak:did_core:web:alice"),
            &[],
            &[],
        );
        assert!(!result.allowed);
    }

    #[test]
    fn authority_child_denied_with_upstream_revocation_reason() {
        let engine = SolandAuthzEngine::new();
        let parent = project(
            &engine,
            "ak:space:1",
            "ak:did_core:web:alice",
            "ak:did_core:web:bob",
            "ak:space:1",
            &["ak.message.create"],
            vec![],
        );
        let mut child = projected_grant_fixture(
            "ak:space:1".to_owned(),
            "ak:did_core:web:bob".to_owned(),
            "ak:did_core:web:carol".to_owned(),
            "ak:space:1".to_owned(),
            vec!["ak.message.create".to_owned()],
            vec![],
        );
        child.issuer_authority_refs =
            vec![arkret_policy::authz::authority::IssuerAuthorityRef::Grant {
                grant_id: parent.grant_id.clone(),
            }];
        engine.upsert_projected_grant(child.clone());
        engine.mark_projected_grant_revoked(&parent.grant_id);
        let result = engine.check(
            "ak:did_core:web:carol",
            "ak.message.create",
            "ak:space:1",
            "ak:space:1",
            Some("ak:did_core:web:alice"),
            &[],
            &[],
        );
        assert!(!result.allowed);
        assert_eq!(
            result.reason,
            arkret_wire::ReasonCode::GRANT_REVOKED_UPSTREAM
        );
        assert!(
            engine
                .get_grant(&child.grant_id)
                .is_some_and(|grant| !grant.revoked),
            "the child's own tombstone is only set by its own accepted revoke; \
             the deny above comes from chain integrity, not from an index-side cascade"
        );
    }

    #[test]
    fn stranger_denied() {
        let engine = SolandAuthzEngine::new();
        let result = engine.check(
            "ak:did_core:web:eve",
            "ak.strand.read",
            "ak:space:1",
            "ak:space:1",
            Some("ak:did_core:web:alice"),
            &[],
            &[],
        );
        assert!(!result.allowed);
    }

    #[test]
    fn wildcard_action_grant_is_fail_closed() {
        let engine = SolandAuthzEngine::new();
        project(
            &engine,
            "ak:realm:1",
            "ak:did_core:web:alice",
            "ak:did_core:web:bob",
            "ak:realm:1",
            &["ak.pin.*"],
            vec![],
        );
        let result = engine.check(
            "ak:did_core:web:bob",
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
        project(
            &engine,
            "ak:realm:1",
            "ak:did_core:web:alice",
            "ak:did_core:web:bob",
            "*",
            &["ak.pin.add"],
            vec![],
        );
        let result = engine.check(
            "ak:did_core:web:bob",
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
