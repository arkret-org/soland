use arkret_identifiers::DidCoreId;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct AdminInviteTokenItem {
    pub kind: String,
    pub id: String,
    pub invite_id: String,
    pub token: String,
    pub realm_id: String,
    pub inviter_id: DidCoreId,
    pub created_by: DidCoreId,
    pub invitee_id: Option<DidCoreId>,
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
