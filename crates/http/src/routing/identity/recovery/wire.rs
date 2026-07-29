use super::*;

/// Allowed `proof_kind` enum per the spec
/// `recovery-policy.schema.json`.
pub(super) const ALLOWED_PROOF_KINDS: &[&str] = &[
    "principal_signing",
    "recovery_unlock",
    "device_quorum",
    "trusted_recovery_service",
    "threshold_recovery",
];

/// C-P2 (REC-1) — recovery session lifetime. A freshly created session must be
/// proven + completed within this window; afterwards it is treated as
/// `expired`. Matches the device-lifecycle interactive recovery window.
pub(super) const RECOVERY_SESSION_TTL_SECS: i64 = 900;

pub(super) const POLICY_SIGNATURE_TYPE: &str = "ak.identity.recovery_policy.signature.v1";

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
