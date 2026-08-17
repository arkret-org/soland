//! Deployment-local policy document contract
//! (`GET`/`POST`/`DELETE /_soland/self/policies`).
//!
//! Both sides of this endpoint used to hand-write their own shape. The
//! producer emitted `owner` and a required canonical `updated_at`; the
//! operator console dropped `owner` entirely and declared `updated_at` an
//! optional string, so a producer rename would have blanked the column at
//! runtime with nothing failing to compile. One definition removes that
//! whole class of drift.
//!
//! `effect` is a closed set on the wire — `access-control.md` and
//! `service-operation-dtos.schema.json#PolicyCheckOutcome.decision` register
//! exactly five decisions — so it is typed here rather than validated after
//! the fact.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// The v1 policy decision set. A bare `deny` is not a valid wire decision —
/// callers MUST choose `soft_deny` or `hard_deny`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum PolicyEffect {
    Allow,
    SoftDeny,
    HardDeny,
    RequireReview,
    Quarantine,
}

impl PolicyEffect {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::SoftDeny => "soft_deny",
            Self::HardDeny => "hard_deny",
            Self::RequireReview => "require_review",
            Self::Quarantine => "quarantine",
        }
    }

    pub fn from_wire(value: &str) -> Option<Self> {
        match value {
            "allow" => Some(Self::Allow),
            "soft_deny" => Some(Self::SoftDeny),
            "hard_deny" => Some(Self::HardDeny),
            "require_review" => Some(Self::RequireReview),
            "quarantine" => Some(Self::Quarantine),
            _ => None,
        }
    }
}

/// The stored decision body. The shape does not vary with `policy_kind` —
/// every document carries these four members — so it is a struct, not a
/// `policy_kind`-keyed `Value`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AdminPolicyPayload {
    pub effect: PolicyEffect,
    #[serde(default)]
    pub actions: Vec<String>,
    /// Operator-authored match target. Genuinely open JSON: the console
    /// stores its own `name` / `description` / `priority` / `rules` under it.
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    #[serde(default)]
    pub resource: Value,
    /// Operator-authored obligations, evaluated by the authz path.
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    #[serde(default)]
    pub obligations: Vec<Value>,
}

/// One stored policy document as served to the operator console.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AdminPolicyDocument {
    pub policy_id: String,
    /// Actor that owns the document. Dropped by the previous console mirror,
    /// which is why the policy list could not say who authored a rule.
    pub owner: String,
    pub scope: String,
    pub subject_ref: String,
    pub policy_kind: String,
    pub payload: AdminPolicyPayload,
    pub active: bool,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub updated_at: DateTime<Utc>,
}

/// Cursor page of policy documents.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AdminPolicyDocumentPage {
    pub policies: Vec<AdminPolicyDocument>,
    pub next_cursor: Option<String>,
}

/// Create-or-replace request body. Shared so the console cannot send a shape
/// the server does not accept.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct UpsertPolicyDocumentRequestBody {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_id: Option<String>,
    pub scope: String,
    pub subject_ref: String,
    pub policy_kind: String,
    pub effect: PolicyEffect,
    #[serde(default)]
    pub actions: Vec<String>,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    #[serde(default)]
    pub resource: Value,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    #[serde(default)]
    pub obligations: Vec<Value>,
    #[serde(default = "default_active")]
    pub active: bool,
}

fn default_active() -> bool {
    true
}
