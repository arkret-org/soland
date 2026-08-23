use super::*;

/// Allowed `proof_kind` enum per the spec
/// `recovery-policy.schema.json`.
pub(super) const ALLOWED_PROOF_KINDS: &[&str] = &[
    "did_root",
    "recovery_unlock",
    "device_quorum",
    "trusted_recovery_service",
    "threshold_recovery",
];

pub(super) const POLICY_ALLOWED_SIGNED_FIELDS: &[&str] = &[
    "schema",
    "policy_id",
    "principal_id",
    "version",
    "supersedes",
    "trust_domain",
    "allowed_proof_kinds",
    "publication_authorization_rules",
    "threshold",
    "device_quorum",
    "trusted_recovery_services",
    "recovery_keys",
    "recovery_key_agreements",
    "approval_requirement",
    "audit",
    "issued_at",
    "not_before",
    "expires_at",
];

pub(super) const POLICY_REQUIRED_SIGNED_FIELDS: &[&str] = &[
    "schema",
    "policy_id",
    "principal_id",
    "version",
    "supersedes",
    "trust_domain",
    "allowed_proof_kinds",
    "publication_authorization_rules",
    "issued_at",
];

#[derive(salvo::oapi::ToSchema, Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SolandRecoveryPoliciesOutcome {
    pub(super) policies: Vec<RecoveryPolicySummary>,
}
