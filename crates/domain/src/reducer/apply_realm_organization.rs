//! SOL-ORG-02 / SOL-ORG-03 — `ak.realm.organization` relationship-statement
//! reducer + projection.
//!
//! ## Model
//!
//! `ak.realm.organization` carries an **organization-authorized Realm
//! relationship statement or revocation** (spec event-kind-registry +
//! `event-payload.schema.json#/$defs/realm_organization_payload`). It is NOT
//! Realm mutable metadata: the cell family `ak.component.realm.organization.v1`
//! is a `cas_register` keyed by the composite subject
//! `(organization_id, relationship)`, so distinct
//! `(organization_id, relationship)` pairs form independent cells and an
//! `owner` / `governance` / `sponsor` / `directory_certifier` relationship can
//! all coexist for one Realm.
//!
//! ## Two-sided authorization gate (SOL-ORG-03)
//!
//! Accepting a relationship requires BOTH:
//!   1. **Realm side** — the event must be admitted into Realm history by a bootstrap path or by an
//!      actor holding `ak.realm.admin` (enforced at ingest in the routing/authz layer, not here —
//!      the reducer runs after admission). A human OIDC session only proves the executor's
//!      identity; it never by itself creates organization principal control.
//!   2. **Organization side** — the statement's `authorization` must pass the SDK
//!      [`verify_realm_organization_statement`] check: issuer-role / delegation coupling (delegated
//!      roles MUST carry a resolvable `delegation_ref`), proof presence, validity window, and
//!      status/revocation consistency.
//!
//! The reducer is a pure projection with no DID-document runtime, so it injects
//! the fail-closed [`NoDelegationResolver`]: a `governance_service` /
//! `account_authority` statement (which requires a live delegation) is rejected
//! here and only accepted once a runtime resolver is wired at the
//! admission/HTTP layer (see SOL-ORG-06 notes). `organization_did` /
//! `threshold_quorum` statements (no `delegation_ref`) project directly.

use arkret_sdk::Operation;
use arkret_sdk::models::{
    NoDelegationResolver, RealmOrganizationControlScope, RealmOrganizationPayload,
    SignatureMaterial, verify_realm_organization_statement,
};

use super::{ProjectionEffect, ProjectionState, RealmOrganizationStatementState};

impl ProjectionState {
    /// Project a `ak.realm.organization` relationship statement.
    ///
    /// Cell family: `ak.component.realm.organization.v1` (cas-register,
    /// composite subject `(organization_id, relationship)`).
    ///
    /// On an `active` statement that passes the organization-side verifier the
    /// relationship projection is written/updated; a `revoked` statement marks
    /// the relationship inactive while retaining `statement_id` for audit.
    /// Supports `expires_at` / `not_before` / `supersedes_statement_id` /
    /// `revokes_statement_id`.
    pub(crate) fn apply_realm_organization(
        &mut self,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
    ) -> ProjectionEffect {
        // Strong-typed parse. We never hand-roll the wire struct.
        let payload: RealmOrganizationPayload =
            match serde_json::from_value(operation.payload.clone()) {
                Ok(payload) => payload,
                Err(_) => {
                    return ProjectionEffect::Rejected {
                        reason: arkret_sdk::ErrorCode::SCHEMA_VIOLATION.to_owned(),
                    };
                }
            };

        // The statement's `realm_id` MUST equal the enclosing event's
        // `realm_id`. The SDK verifier also checks this, but we resolve the
        // expected RealmId up front so a malformed envelope realm fails closed.
        let expected_realm_id = operation.realm_id.clone();

        // SOL-ORG-03 organization side: run the SDK fail-closed verifier with
        // the offline resolver. Delegated issuer roles
        // (governance_service / account_authority) require a live delegation
        // and are rejected here until a runtime resolver is injected upstream.
        if let Err(error) = verify_realm_organization_statement(
            &payload,
            &expected_realm_id,
            now,
            &NoDelegationResolver,
        ) {
            // A statement that fails ONLY because it is outside its validity
            // window (expired or not-yet-valid) is still projected as an audit
            // row: it is retained for history and simply excluded from the
            // verified set by the read-side `is_effective_active` filter. The
            // SDK verifier checks proof / issuer-role / delegation strictly
            // before the validity window, so a validity-window error code means
            // every structural and authorization check already passed. Any
            // other failure (bad proof, unresolved delegation, status mismatch)
            // fails closed and is not stored.
            let reason = organization_rejection_reason(&error.to_string());
            let window_only = (reason == arkret_sdk::ReasonCode::TTL_EXPIRED
                && payload.is_expired(now))
                || (reason == arkret_sdk::ErrorCode::FAILED_PRECONDITION
                    && payload.is_not_yet_valid(now));
            if !window_only {
                tracing::warn!(
                    statement_id = %payload.statement_id,
                    organization_id = %payload.organization_id.as_str(),
                    error = %error,
                    "rejected ak.realm.organization: organization-side verification failed"
                );
                return ProjectionEffect::Rejected { reason };
            }
        }

        let realm_id = expected_realm_id.to_string();
        let organization_id = payload.organization_id.as_str().to_owned();
        let relationship = relationship_str(&payload).to_owned();
        let status = if payload.is_active_status() {
            "active"
        } else {
            "revoked"
        };

        // Cell write — cas-register keyed by the composite
        // `{organization_id}::{relationship}` subject. This mirrors the SDK
        // `RealmOrganization::subject_for_effect` form exactly so the inline
        // cache and the Move/Seal cell store agree.
        if let Some(cell_id) = Self::realm_organization_cell_id(&organization_id, &relationship) {
            let value = serde_json::json!({
                "statement_id": payload.statement_id,
                "realm_id": realm_id,
                "organization_id": organization_id,
                "relationship": relationship,
                "status": status,
                "control_scopes": control_scopes_str(&payload),
                "issued_at": arkret_sdk::canonical::format_timestamp_canonical(payload.issued_at),
                "updated_at": arkret_sdk::canonical::format_timestamp_canonical(now),
                "operation_id": operation.operation_id.as_str(),
            });
            self.cells
                .insert(cell_id, arkret_sdk::lattice::CellState::Value(value));
        }

        let row = RealmOrganizationStatementState {
            realm_id: realm_id.clone(),
            organization_id: organization_id.clone(),
            relationship: relationship.clone(),
            statement_id: payload.statement_id.clone(),
            status: status.to_owned(),
            control_scopes: control_scopes_str(&payload),
            issued_at: payload.issued_at,
            not_before: payload.not_before,
            expires_at: payload.expires_at,
            supersedes_statement_id: payload.supersedes_statement_id.clone(),
            revokes_statement_id: payload.revokes_statement_id.clone(),
            realm_frontier_digest: payload
                .realm_frontier_digest
                .as_ref()
                .map(|hash| hash.as_str().to_owned()),
            proof_digest: proof_digest(&payload.authorization.proof),
            delegation_ref: payload.authorization.delegation_ref.clone(),
            issuer_role: issuer_role_str(&payload).to_owned(),
            updated_at: now,
        };
        self.realm_organization_statements.insert(
            (
                realm_id.clone(),
                organization_id.clone(),
                relationship.clone(),
            ),
            row,
        );

        ProjectionEffect::RealmOrganizationProjected {
            realm_id,
            organization_id,
            relationship,
            status: status.to_owned(),
        }
    }

    /// SOL-ORG-02 — the canonical `ak.component.realm.organization.v1` cell id
    /// for a `(organization_id, relationship)` pair. The subject form mirrors
    /// the SDK `RealmOrganization::subject_for_effect` (`{org}::{rel}`).
    pub(crate) fn realm_organization_cell_id(
        organization_id: &str,
        relationship: &str,
    ) -> Option<arkret_sdk::CellRef> {
        let subject = arkret_sdk::composite_subject(&[organization_id, relationship]).ok()?;
        arkret_sdk::CellRef::new(format!(
            "ak:cell:ak.component.realm.organization.v1:{subject}"
        ))
        .ok()
    }

    // ── SOL-ORG-05 — verified-relationship + effective-policy reads ──

    /// Every `ak.realm.organization` relationship statement projected for
    /// `realm_id`, regardless of status / validity. Admin / audit surfaces use
    /// this to render revoked / expired history; the verified-relationship and
    /// policy-inheritance reads use the filtered helpers below.
    pub fn realm_organization_statements_for_realm(
        &self,
        realm_id: &str,
    ) -> Vec<&RealmOrganizationStatementState> {
        self.realm_organization_statements
            .iter()
            .filter(|((rid, ..), _)| rid == realm_id)
            .map(|(_, row)| row)
            .collect()
    }

    /// SOL-ORG-05 — the verified (active + in-window) organization
    /// relationships for `realm_id` at `now`. A revoked or expired statement
    /// immediately drops out of this set; an `owning_organizations` declared
    /// hint never enters it.
    pub fn verified_organization_relationships(
        &self,
        realm_id: &str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Vec<&RealmOrganizationStatementState> {
        self.realm_organization_statements_for_realm(realm_id)
            .into_iter()
            .filter(|row| row.is_effective_active(now))
            .collect()
    }

    /// SOL-ORG-05 — `true` iff some active, in-window `ak.realm.organization`
    /// statement endorses `realm_id` with a `control_scope` covering `scope`.
    /// This is the only basis on which organization policy inheritance for the
    /// matching policy facet may apply; `owning_organizations` no longer
    /// satisfies it.
    pub fn realm_has_verified_control_scope(
        &self,
        realm_id: &str,
        scope: RealmOrganizationControlScope,
        now: chrono::DateTime<chrono::Utc>,
    ) -> bool {
        let scope = control_scope_str(scope);
        self.verified_organization_relationships(realm_id, now)
            .iter()
            .any(|row| row.covers_scope(scope))
    }

    /// SOL-ORG-05 — the verified organization DIDs whose active statement for
    /// `realm_id` covers `scope` at `now`. Drives scope-gated policy
    /// inheritance: only these organizations' policies may flow into the
    /// matching effective-policy facet.
    pub fn verified_organizations_with_scope(
        &self,
        realm_id: &str,
        scope: RealmOrganizationControlScope,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Vec<String> {
        let scope = control_scope_str(scope);
        self.verified_organization_relationships(realm_id, now)
            .iter()
            .filter(|row| row.covers_scope(scope))
            .map(|row| row.organization_id.clone())
            .collect()
    }
}

/// Map the SDK verifier's `Error::Protocol` message — which embeds the canonical
/// spec wire error-code constant in parentheses — onto the soland rejection
/// reason. We surface the embedded code when present, falling back to a stable
/// generic when the message shape is unexpected.
fn organization_rejection_reason(message: &str) -> String {
    // The verifier formats every error as `... (<wire_code>)`. Extract the
    // last parenthesised token.
    if let Some(open) = message.rfind('(')
        && let Some(close) = message[open..].find(')')
    {
        let code = message[open + 1..open + close].trim();
        if !code.is_empty() {
            return code.to_owned();
        }
    }
    arkret_sdk::ErrorCode::SCHEMA_VIOLATION.to_owned()
}

/// Audit-only digest of the proof material — never the raw signature bytes.
fn proof_digest(proof: &SignatureMaterial) -> Option<String> {
    let bytes = match proof {
        SignatureMaterial::NonEmptyString(s) => s.as_bytes().to_vec(),
        SignatureMaterial::Variant1(map) => {
            arkret_sdk::canonical::canonical_json_bytes(map).unwrap_or_default()
        }
    };
    if bytes.is_empty() {
        return None;
    }
    Some(arkret_sdk::canonical::sha256_digest(&bytes))
}

fn relationship_str(payload: &RealmOrganizationPayload) -> &'static str {
    use arkret_sdk::models::RealmOrganizationRelationship as R;
    match payload.relationship {
        R::Owner => "owner",
        R::Governance => "governance",
        R::Sponsor => "sponsor",
        R::DirectoryCertifier => "directory_certifier",
    }
}

fn issuer_role_str(payload: &RealmOrganizationPayload) -> &'static str {
    use arkret_sdk::models::RealmOrganizationIssuerRole as Role;
    match payload.authorization.issuer_role {
        Role::OrganizationDid => "organization_did",
        Role::GovernanceService => "governance_service",
        Role::AccountAuthority => "account_authority",
        Role::ThresholdQuorum => "threshold_quorum",
    }
}

pub(crate) fn control_scope_str(scope: RealmOrganizationControlScope) -> &'static str {
    use RealmOrganizationControlScope as S;
    match scope {
        S::OfficialBadge => "official_badge",
        S::RealmAdmin => "realm_admin",
        S::NotaryControl => "notary_control",
        S::PolicyServer => "policy_server",
        S::DeliveryBindingPolicy => "delivery_binding_policy",
        S::DurabilityPolicy => "durability_policy",
        S::ModerationPolicy => "moderation_policy",
        S::RetentionPolicy => "retention_policy",
        S::DirectoryListing => "directory_listing",
        S::PlaintextVisibleService => "plaintext_visible_service",
    }
}

fn control_scopes_str(payload: &RealmOrganizationPayload) -> Vec<String> {
    payload
        .control_scopes
        .iter()
        .map(|scope| control_scope_str(*scope).to_owned())
        .collect()
}

#[cfg(test)]
mod tests {
    use arkret_sdk::models::RealmOrganizationControlScope as Scope;
    use arkret_sdk::{Operation, OperationId, RealmId};
    use serde_json::{Value, json};

    use super::*;

    const REALM: &str = "ak:realm:0196419b-0000-7000-8000-000000000010";
    const REALM_OTHER: &str = "ak:realm:0196419b-0000-7000-8000-000000000099";
    const ORG: &str = "did:webvh:example.test:orgs:01J0000000000000000000000A";
    const ORG2: &str = "did:webvh:example.test:orgs:01J0000000000000000000000B";

    fn now() -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::parse_from_rfc3339("2026-06-25T12:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc)
    }

    fn op(realm_id: &str, payload: Value) -> Operation {
        Operation::create(
            OperationId::new(format!("ak:operation:{}", uuid::Uuid::now_v7())).unwrap(),
            RealmId::new(realm_id).unwrap(),
            arkret_sdk::events::EventKind::REALM_ORGANIZATION,
            payload,
        )
    }

    /// Active `organization_did` statement (no delegation_ref required).
    fn active_payload(realm_id: &str, org: &str, relationship: &str, scopes: &[&str]) -> Value {
        json!({
            "statement_id": format!("org-stmt-{relationship}"),
            "realm_id": realm_id,
            "organization_id": org,
            "relationship": relationship,
            "status": "active",
            "control_scopes": scopes,
            "issued_at": "2026-06-25T00:00:00Z",
            "authorization": {
                "issuer": org,
                "issuer_role": "organization_did",
                "verification_method": format!("{org}#k1"),
                "signed_at": "2026-06-25T00:00:00Z",
                "proof": "c2ln"
            }
        })
    }

    fn apply(state: &mut ProjectionState, payload: Value) -> ProjectionEffect {
        state.apply_realm_organization(&op(REALM, payload), now())
    }

    #[test]
    fn active_organization_did_statement_projects_relationship() {
        let mut state = ProjectionState::new();
        let effect = apply(
            &mut state,
            active_payload(REALM, ORG, "owner", &["official_badge", "realm_admin"]),
        );
        assert!(matches!(
            effect,
            ProjectionEffect::RealmOrganizationProjected { ref status, .. } if status == "active"
        ));
        let verified = state.verified_organization_relationships(REALM, now());
        assert_eq!(verified.len(), 1);
        assert_eq!(verified[0].organization_id, ORG);
        assert_eq!(verified[0].relationship, "owner");
        assert!(state.realm_has_verified_control_scope(REALM, Scope::RealmAdmin, now()));
        // Cell written under the composite subject.
        assert!(
            ProjectionState::realm_organization_cell_id(ORG, "owner")
                .and_then(|cell| state.cell_value(&cell))
                .is_some()
        );
    }

    #[test]
    fn distinct_relationships_coexist_for_same_realm() {
        let mut state = ProjectionState::new();
        apply(
            &mut state,
            active_payload(REALM, ORG, "owner", &["realm_admin"]),
        );
        apply(
            &mut state,
            active_payload(REALM, ORG2, "governance", &["moderation_policy"]),
        );
        apply(
            &mut state,
            active_payload(REALM, ORG, "sponsor", &["official_badge"]),
        );
        let verified = state.verified_organization_relationships(REALM, now());
        assert_eq!(verified.len(), 3);
        // moderation_policy scope only from the governance org.
        let mods = state.verified_organizations_with_scope(REALM, Scope::ModerationPolicy, now());
        assert_eq!(mods, vec![ORG2.to_owned()]);
    }

    #[test]
    fn revoked_statement_marks_inactive_but_retains_audit() {
        let mut state = ProjectionState::new();
        apply(
            &mut state,
            active_payload(REALM, ORG, "owner", &["realm_admin"]),
        );
        assert_eq!(
            state
                .verified_organization_relationships(REALM, now())
                .len(),
            1
        );

        let mut revoke = active_payload(REALM, ORG, "owner", &["realm_admin"]);
        revoke["status"] = json!("revoked");
        revoke["statement_id"] = json!("org-stmt-owner-2");
        revoke["revokes_statement_id"] = json!("org-stmt-owner");
        let effect = apply(&mut state, revoke);
        assert!(matches!(
            effect,
            ProjectionEffect::RealmOrganizationProjected { ref status, .. } if status == "revoked"
        ));
        // Verified relationship + control scope immediately gone.
        assert!(
            state
                .verified_organization_relationships(REALM, now())
                .is_empty()
        );
        assert!(!state.realm_has_verified_control_scope(REALM, Scope::RealmAdmin, now()));
        // Audit row retained with the revoking statement_id.
        let all = state.realm_organization_statements_for_realm(REALM);
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].status, "revoked");
        assert_eq!(all[0].statement_id, "org-stmt-owner-2");
        assert_eq!(
            all[0].revokes_statement_id.as_deref(),
            Some("org-stmt-owner")
        );
    }

    #[test]
    fn sol_org_06_lifecycle_phase_split() {
        // SOL-ORG-06 read contract: the org-relationship projection the
        // `ak.self.realm_organization.query.list` handler reads must expose
        // BOTH the active and the revoked statement, with exactly the active,
        // in-window one classified `verified_active` (the others
        // `revoked_or_expired`). An org with a currently-verified statement is
        // never also surfaced as an unverified declared hint.
        let mut state = ProjectionState::new();
        apply(
            &mut state,
            active_payload(REALM, ORG, "owner", &["realm_admin"]),
        );
        let mut revoke = active_payload(REALM, ORG2, "governance", &["moderation_policy"]);
        revoke["status"] = json!("revoked");
        revoke["statement_id"] = json!("org-stmt-governance-2");
        revoke["revokes_statement_id"] = json!("org-stmt-governance");
        apply(&mut state, revoke);

        let rows = state.realm_organization_statements_for_realm(REALM);
        assert_eq!(rows.len(), 2, "both active and revoked rows are projected");
        let verified: Vec<_> = rows
            .iter()
            .filter(|row| row.is_effective_active(now()))
            .map(|row| row.organization_id.clone())
            .collect();
        // Exactly the active statement maps onto verified_active.
        assert_eq!(verified, vec![ORG.to_owned()]);
        // The revoked statement maps onto revoked_or_expired (not verified).
        assert!(
            rows.iter()
                .any(|row| row.organization_id == ORG2 && !row.is_effective_active(now()))
        );
    }

    #[test]
    fn expired_statement_is_not_verified() {
        let mut state = ProjectionState::new();
        let mut payload = active_payload(REALM, ORG, "owner", &["realm_admin"]);
        payload["expires_at"] = json!("2026-06-25T06:00:00Z");
        apply(&mut state, payload);
        // Row stored, but not verified at `now()` (12:00 > 06:00 expiry).
        assert_eq!(
            state.realm_organization_statements_for_realm(REALM).len(),
            1
        );
        assert!(
            state
                .verified_organization_relationships(REALM, now())
                .is_empty()
        );
    }

    #[test]
    fn not_yet_valid_statement_is_not_verified() {
        let mut state = ProjectionState::new();
        let mut payload = active_payload(REALM, ORG, "owner", &["realm_admin"]);
        payload["not_before"] = json!("2026-06-26T00:00:00Z");
        apply(&mut state, payload);
        assert!(
            state
                .verified_organization_relationships(REALM, now())
                .is_empty()
        );
    }

    #[test]
    fn missing_delegation_for_delegated_role_is_rejected() {
        let mut state = ProjectionState::new();
        let mut payload = active_payload(REALM, ORG, "owner", &["realm_admin"]);
        payload["authorization"]["issuer_role"] = json!("governance_service");
        let effect = apply(&mut state, payload);
        assert!(matches!(effect, ProjectionEffect::Rejected { .. }));
        assert!(
            state
                .realm_organization_statements_for_realm(REALM)
                .is_empty()
        );
    }

    #[test]
    fn delegated_role_with_delegation_ref_fails_closed_in_reducer() {
        // The in-reducer NoDelegationResolver cannot resolve any delegation, so
        // even a well-formed delegated statement is rejected here (it must be
        // accepted at the admission layer where a runtime resolver is wired).
        let mut state = ProjectionState::new();
        let mut payload = active_payload(REALM, ORG, "governance", &["moderation_policy"]);
        payload["authorization"]["issuer_role"] = json!("account_authority");
        payload["authorization"]["delegation_ref"] =
            json!("ak:grant:01904100-0000-7000-8000-000000000001");
        let effect = apply(&mut state, payload);
        assert!(matches!(effect, ProjectionEffect::Rejected { .. }));
    }

    #[test]
    fn bad_proof_is_rejected() {
        let mut state = ProjectionState::new();
        let mut payload = active_payload(REALM, ORG, "owner", &["realm_admin"]);
        payload["authorization"]["proof"] = json!("   ");
        let effect = apply(&mut state, payload);
        assert!(matches!(effect, ProjectionEffect::Rejected { .. }));
    }

    #[test]
    fn realm_id_mismatch_is_rejected() {
        let mut state = ProjectionState::new();
        // Envelope realm REALM, but payload claims REALM_OTHER.
        let payload = active_payload(REALM_OTHER, ORG, "owner", &["realm_admin"]);
        let effect = state.apply_realm_organization(&op(REALM, payload), now());
        assert!(matches!(effect, ProjectionEffect::Rejected { .. }));
    }

    #[test]
    fn malformed_payload_is_schema_violation() {
        let mut state = ProjectionState::new();
        let effect = apply(
            &mut state,
            json!({ "organization_ref": "did:web:org.example" }),
        );
        assert!(matches!(
            effect,
            ProjectionEffect::Rejected { ref reason }
                if reason == arkret_sdk::ErrorCode::SCHEMA_VIOLATION
        ));
    }

    #[test]
    fn proof_digest_is_recorded_not_raw_bytes() {
        let mut state = ProjectionState::new();
        apply(
            &mut state,
            active_payload(REALM, ORG, "owner", &["realm_admin"]),
        );
        let row = state.realm_organization_statements_for_realm(REALM)[0];
        let digest = row.proof_digest.as_deref().expect("proof digest");
        assert_ne!(digest, "c2ln");
        assert!(!digest.is_empty());
    }
}
