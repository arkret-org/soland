use super::*;

/// Allowed `proof_kind` enum per the spec
/// `recovery-policy.schema.json` / `recovery-receipt.schema.json`.
pub(super) const ALLOWED_PROOF_KINDS: &[&str] = &[
    "principal_signing",
    "recovery_unlock",
    "device_quorum",
    "trusted_recovery_service",
    "threshold_recovery",
];

/// REC-1 — witness freshness window. A recovery proof carrying a
/// `witness_ref` older than this is rejected with
/// `recovery_witness_revoke_lagging`. The window matches spec
/// `device-lifecycle.md §14.5` (default 24h).
pub(super) const RECOVERY_WITNESS_FRESHNESS_SECS: i64 = 86_400;

/// C-P2 (REC-1) — recovery session lifetime. A freshly created session must be
/// proven + completed within this window; afterwards it is treated as
/// `expired`. Matches the device-lifecycle interactive recovery window.
pub(super) const RECOVERY_SESSION_TTL_SECS: i64 = 900;

pub(super) const POLICY_SIGNATURE_TYPE: &str = "ck.identity.recovery_policy.signature.v1";
pub(super) const RECEIPT_SIGNATURE_TYPE: &str = "ck.identity.recovery_receipt.signature.v1";

pub(super) const POLICY_ALLOWED_SIGNED_FIELDS: &[&str] = &[
    "schema",
    "policy_id",
    "principal_id",
    "version",
    "trust_domain",
    "allowed_proof_kinds",
    "supersedes",
    "issued_at",
    "expires_at",
];

pub(super) const POLICY_REQUIRED_SIGNED_FIELDS: &[&str] = POLICY_ALLOWED_SIGNED_FIELDS;

pub(super) const RECEIPT_ALLOWED_SIGNED_FIELDS: &[&str] = &[
    "schema",
    "receipt_id",
    "principal_id",
    "recovery_session_id",
    "policy_id",
    "policy_version",
    "trust_domain",
    "new_device_id",
    "proof_summary",
    "backup_classes_unlocked",
    "welcome_count",
    "welcome_realm_summary",
    "previous_ssk_generation",
    "new_ssk_generation",
    "outcome",
    "outcome_reason_code",
    "started_at",
    "completed_at",
];

// device-lifecycle.md §15 step 7 / recovery-receipt.schema.json: signed_fields
// MUST cover the full normative receipt binding, including backup_classes_unlocked
// and welcome_count.
pub(super) const RECEIPT_REQUIRED_SIGNED_FIELDS: &[&str] = &[
    "schema",
    "receipt_id",
    "principal_id",
    "recovery_session_id",
    "policy_id",
    "policy_version",
    "trust_domain",
    "new_device_id",
    "proof_summary",
    "backup_classes_unlocked",
    "welcome_count",
    "outcome",
    "started_at",
    "completed_at",
];

#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct SolandRecoveryPoliciesOutcome {
    pub(super) policies: Vec<RecoveryPolicySummary>,
}

#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct SolandRecoveryReceiptsOutcome {
    pub(super) receipts: Vec<SolandRecoveryReceiptItem>,
}

#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct SolandRecoveryReceiptItem {
    receipt_id: ReceiptId,
    principal_id: Did,
    recovery_session_id: RecoverySessionId,
    policy_id: PolicyId,
    policy_version: u64,
    trust_domain: TypedTrustDomainId,
    new_device_id: DeviceId,
    outcome: RecoveryReceiptOutcome,
    completed_at: chrono::DateTime<chrono::Utc>,
    accepted_at: chrono::DateTime<chrono::Utc>,
    #[salvo(schema(value_type = serde_json::Value))]
    receipt: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct SolandRecoveryReceiptPutOutcome {
    ok: bool,
    receipt_id: ReceiptId,
    principal_id: Did,
    recovery_session_id: RecoverySessionId,
    outcome: RecoveryReceiptOutcome,
    accepted_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone, Debug, Deserialize, ToSchema)]
#[serde(transparent)]
pub(super) struct SignedRecoveryReceiptRequestBody(
    #[salvo(schema(value_type = serde_json::Value))] pub(super) Value,
);
