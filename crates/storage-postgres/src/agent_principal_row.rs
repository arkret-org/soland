use chrono::{DateTime, Utc};
use diesel::{AsChangeset, Insertable, Queryable, Selectable};
use serde_json::Value;
use soland_storage::AgentPrincipalRecord;
use uuid::Uuid;

use crate::schema::agent_principals;

#[derive(Clone, Debug, PartialEq, Queryable, Selectable, Insertable, AsChangeset)]
#[diesel(table_name = agent_principals)]
#[diesel(check_for_backend(diesel::pg::Pg))]
#[diesel(treat_none_as_null = true)]
pub(crate) struct AgentPrincipalRow {
    #[diesel(skip_update)]
    pub id: String,
    #[diesel(skip_update)]
    pub controller_id: String,
    #[diesel(skip_update)]
    pub principal_control_realm_id: String,
    #[diesel(skip_update)]
    pub controller_authorization_ref: String,
    pub display_name: Option<String>,
    pub agent_slug: Option<String>,
    pub avatar_blob_ref: Option<String>,
    pub state: String,
    #[diesel(skip_update)]
    pub requested_scope: Option<Value>,
    pub accountability: Option<Value>,
    pub provision_event_refs: Option<Value>,
    pub pairing_request_id: Option<String>,
    pub paired_pairing_request_id: Option<String>,
    pub paired_request_digest: Option<String>,
    pub pairing_code: Option<String>,
    pub pairing_expires_at: Option<DateTime<Utc>>,
    pub approval_request_id: Option<String>,
    pub controller_account_id: Option<Uuid>,
    pub recipient_service_id: Option<String>,
    pub runtime_key_binding_digest: Option<String>,
    pub runtime_public_key_digest: Option<String>,
    pub runtime_attestation_digest: Option<String>,
    pub approval_notification_id: Option<Uuid>,
    pub runtime_key_request: Option<Value>,
    pub approval_requested_at: Option<DateTime<Utc>>,
    pub authorized_event_ref: Option<String>,
    pub authorized_verification_method: Option<String>,
    pub authorized_public_key_digest: Option<String>,
    pub authorized_signing_key_binding: Option<Value>,
    pub state_changed_at: Option<DateTime<Utc>>,
    #[diesel(skip_update)]
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

macro_rules! convert_agent_principal {
    ($source:expr, $target:ident) => {{
        let source = $source;
        $target {
            id: source.id,
            controller_id: source.controller_id,
            principal_control_realm_id: source.principal_control_realm_id,
            controller_authorization_ref: source.controller_authorization_ref,
            display_name: source.display_name,
            agent_slug: source.agent_slug,
            avatar_blob_ref: source.avatar_blob_ref,
            state: source.state,
            requested_scope: source.requested_scope,
            accountability: source.accountability,
            provision_event_refs: source.provision_event_refs,
            pairing_request_id: source.pairing_request_id,
            paired_pairing_request_id: source.paired_pairing_request_id,
            paired_request_digest: source.paired_request_digest,
            pairing_code: source.pairing_code,
            pairing_expires_at: source.pairing_expires_at,
            approval_request_id: source.approval_request_id,
            controller_account_id: source.controller_account_id,
            recipient_service_id: source.recipient_service_id,
            runtime_key_binding_digest: source.runtime_key_binding_digest,
            runtime_public_key_digest: source.runtime_public_key_digest,
            runtime_attestation_digest: source.runtime_attestation_digest,
            approval_notification_id: source.approval_notification_id,
            runtime_key_request: source.runtime_key_request,
            approval_requested_at: source.approval_requested_at,
            authorized_event_ref: source.authorized_event_ref,
            authorized_verification_method: source.authorized_verification_method,
            authorized_public_key_digest: source.authorized_public_key_digest,
            authorized_signing_key_binding: source.authorized_signing_key_binding,
            state_changed_at: source.state_changed_at,
            created_at: source.created_at,
            updated_at: source.updated_at,
        }
    }};
}

impl From<AgentPrincipalRecord> for AgentPrincipalRow {
    fn from(record: AgentPrincipalRecord) -> Self {
        convert_agent_principal!(record, AgentPrincipalRow)
    }
}

impl From<AgentPrincipalRow> for AgentPrincipalRecord {
    fn from(row: AgentPrincipalRow) -> Self {
        convert_agent_principal!(row, AgentPrincipalRecord)
    }
}
