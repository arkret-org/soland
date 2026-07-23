use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct CreateInviteTokenRequest {
    #[serde(default)]
    pub realm_id: Option<String>,
    #[serde(default)]
    pub invitee: Option<String>,
    #[serde(default)]
    pub invite_delivery_target: Option<Value>,
    #[serde(default)]
    pub introduction_evidence_digest: Option<String>,
    #[serde(default)]
    pub uses_allowed: Option<u64>,
    #[serde(default)]
    pub expires_at: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct AdminInviteTokenItem {
    pub kind: String,
    pub id: String,
    pub invite_id: String,
    pub token: String,
    pub realm_id: String,
    pub inviter: String,
    pub created_by: String,
    pub invitee: Option<String>,
    pub invite_delivery_target: Option<Value>,
    pub introduction_evidence_digest: Option<String>,
    pub token_hash: String,
    pub status: String,
    pub uses_allowed: u64,
    pub uses_completed: u64,
    pub uses_pending: u64,
    #[serde(
        default,
        serialize_with = "arkret_canonical::serialize_optional_canonical_timestamp",
        deserialize_with = "arkret_canonical::deserialize_optional_canonical_timestamp"
    )]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(
        serialize_with = "arkret_canonical::serialize_canonical_timestamp",
        deserialize_with = "arkret_canonical::deserialize_canonical_timestamp"
    )]
    pub created_at: DateTime<Utc>,
}
