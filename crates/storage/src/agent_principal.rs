use chrono::{DateTime, Utc};
use serde_json::Value;
use uuid::Uuid;

/// Durable projection of a managed Agent principal.
///
/// The controller, PCR, and controller-authorization fields form the immutable
/// identity binding. Adapters preserve those immutable fields during updates.
#[derive(Clone, Debug, PartialEq)]
pub struct AgentPrincipalRecord {
    pub id: String,
    pub controller_id: String,
    pub principal_control_realm_id: String,
    pub controller_authorization_ref: String,
    pub display_name: Option<String>,
    pub agent_slug: Option<String>,
    pub avatar_blob_ref: Option<String>,
    pub state: String,
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
    pub state_changed_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl AgentPrincipalRecord {
    pub fn new(
        id: String,
        controller_id: String,
        principal_control_realm_id: String,
        controller_authorization_ref: String,
        state: String,
        created_at: DateTime<Utc>,
    ) -> Self {
        Self {
            id,
            controller_id,
            principal_control_realm_id,
            controller_authorization_ref,
            display_name: None,
            agent_slug: None,
            avatar_blob_ref: None,
            state,
            requested_scope: None,
            accountability: None,
            provision_event_refs: None,
            pairing_request_id: None,
            paired_pairing_request_id: None,
            paired_request_digest: None,
            pairing_code: None,
            pairing_expires_at: None,
            approval_request_id: None,
            controller_account_id: None,
            recipient_service_id: None,
            runtime_key_binding_digest: None,
            runtime_public_key_digest: None,
            runtime_attestation_digest: None,
            approval_notification_id: None,
            runtime_key_request: None,
            approval_requested_at: None,
            authorized_event_ref: None,
            authorized_verification_method: None,
            authorized_public_key_digest: None,
            state_changed_at: Some(created_at),
            created_at,
            updated_at: created_at,
        }
    }
}
