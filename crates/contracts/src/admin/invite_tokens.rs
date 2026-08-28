use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct AdminInviteTokenItem {
    pub kind: String,
    pub id: String,
    pub invite_id: String,
    pub token: String,
    pub realm_id: String,
    pub inviter_id: String,
    pub created_by: String,
    pub invitee_id: Option<String>,
    pub invite_delivery_target: Option<Value>,
    pub introduction_evidence_digest: Option<String>,
    pub token_hash: String,
    pub status: String,
    pub uses_allowed: u64,
    pub uses_completed: u64,
    pub uses_pending: u64,
    #[serde(
        default,
        with = "arkret_canonical::serde_helpers::optional_canonical_timestamp"
    )]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub created_at: DateTime<Utc>,
}
