use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct AdminHandleRecord {
    pub id: String,
    pub canonical_uri: String,
    pub aliases: Vec<String>,
    pub issuer_did: Option<String>,
    pub subject_id: Option<String>,
    pub assigned_at: Option<String>,
    pub expires_at: Option<String>,
    pub last_reassignment_at: Option<String>,
    pub status: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct AdminHandleAuditEvent {
    pub id: String,
    pub action: String,
    pub actor_id: Option<String>,
    pub timestamp: Option<String>,
    pub reason: Option<String>,
    pub previous_subject_id: Option<String>,
    pub new_subject_id: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct AdminHandleListOutcome {
    pub data: Vec<AdminHandleRecord>,
    pub total: u64,
    pub next_cursor: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct AdminHandleAuditListOutcome {
    pub data: Vec<AdminHandleAuditEvent>,
    pub total: u64,
    pub next_cursor: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct AdminHandleReassignBody {
    pub new_subject_id: String,
    pub reason: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct AdminHandleRevokeBody {
    #[serde(default)]
    pub reason: Option<String>,
}
