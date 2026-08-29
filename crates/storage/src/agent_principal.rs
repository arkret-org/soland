use arkret_models_collaboration::agent_operations::{
    AgentLifecycleState, AgentRuntimeApprovalControllerProjection,
};
use arkret_models_identity::agent_signer_evidence::AgentSigningKeyBinding;
use arkret_wire::{DidUrl, OpaqueLocalId, ServiceAccountId};
use chrono::{DateTime, Utc};
use serde_json::Value;
use uuid::Uuid;

#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct PendingAgentPairingCommitIntent {
    pub request_digest: String,
    pub authorize_event_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signing_key_binding: Option<AgentSigningKeyBinding>,
}

/// Durable projection of a managed Agent principal.
///
/// The controller, PCR, and controller-authorization fields form the immutable
/// identity binding. Adapters preserve those immutable fields during updates.
#[derive(Clone, Debug, PartialEq)]
pub struct AgentPrincipalRecord {
    pub id: String,
    pub controller_id: String,
    pub principal_control_realm_id: String,
    pub controller_authorization_ref: DidUrl,
    pub display_name: Option<String>,
    pub agent_slug: Option<String>,
    pub avatar_blob_ref: Option<String>,
    pub state: AgentLifecycleState,
    pub requested_scope: Option<Value>,
    pub accountability: Option<Value>,
    pub provision_event_refs: Option<Value>,
    pub pairing_request_id: Option<OpaqueLocalId>,
    pub paired_pairing_request_id: Option<OpaqueLocalId>,
    pub paired_request_digest: Option<String>,
    pub pending_pairing_commit_intent: Option<PendingAgentPairingCommitIntent>,
    pub pairing_code: Option<String>,
    pub pairing_expires_at: Option<DateTime<Utc>>,
    pub approval_request_id: Option<OpaqueLocalId>,
    pub controller_account_id: Option<ServiceAccountId>,
    pub recipient_id: Option<String>,
    pub runtime_key_binding_digest: Option<String>,
    pub runtime_public_key_digest: Option<String>,
    pub runtime_attestation_digest: Option<String>,
    pub approval_notification_id: Option<Uuid>,
    pub runtime_key_request: Option<AgentRuntimeApprovalControllerProjection>,
    pub approval_requested_at: Option<DateTime<Utc>>,
    pub authorized_event_ref: Option<String>,
    pub authorized_verification_method: Option<String>,
    pub authorized_public_key_digest: Option<String>,
    pub authorized_signing_key_binding: Option<AgentSigningKeyBinding>,
    pub state_changed_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl AgentPrincipalRecord {
    pub fn new(
        id: String,
        controller_id: String,
        principal_control_realm_id: String,
        controller_authorization_ref: DidUrl,
        state: AgentLifecycleState,
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
            pending_pairing_commit_intent: None,
            pairing_code: None,
            pairing_expires_at: None,
            approval_request_id: None,
            controller_account_id: None,
            recipient_id: None,
            runtime_key_binding_digest: None,
            runtime_public_key_digest: None,
            runtime_attestation_digest: None,
            approval_notification_id: None,
            runtime_key_request: None,
            approval_requested_at: None,
            authorized_event_ref: None,
            authorized_verification_method: None,
            authorized_public_key_digest: None,
            authorized_signing_key_binding: None,
            state_changed_at: Some(created_at),
            created_at,
            updated_at: created_at,
        }
    }
}
