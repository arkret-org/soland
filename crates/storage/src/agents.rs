use arkret_wire::{OpaqueLocalId, ServiceAccountId};

use super::{AgentPrincipalRecord, PersistenceResult, Value, async_trait};
/// AKP-0010 — agent participation policy persistence. Controller
/// selections (`ak.agent.participation.v1`) and the governance ceiling
/// projection are stored as JSON records. A selection record contains only
/// its agent/scope identity, CAS version and five independent selection bits;
/// governance policy is evaluated separately at action time.
#[async_trait]
pub trait AgentParticipationStore: Send + Sync {
    /// Atomically replace a controller selection when the stored version
    /// equals `expected_version`. Returns false without writing on mismatch.
    async fn compare_and_swap_selection(
        &self,
        record: Value,
        expected_version: u64,
    ) -> PersistenceResult<bool>;
    /// All selections for one agent.
    async fn list_selections(&self, agent_id: &str) -> PersistenceResult<Vec<Value>>;
    /// Ceiling rows whose scope_key is in `scope_keys`.
    async fn ceilings_for_scope_keys(&self, scope_keys: &[String])
    -> PersistenceResult<Vec<Value>>;
    /// Upsert a governance ceiling row keyed by scope_key.
    async fn put_ceiling(&self, record: Value) -> PersistenceResult<()>;
}
#[doc(hidden)]
pub fn agent_participation_record_key(record: &Value) -> (Option<String>, Option<String>) {
    (
        record
            .get("agent_id")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned),
        record
            .get("scope_key")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned),
    )
}
/// AKP-0008 — native personal agent principal persistence (provision /
/// list / get / lifecycle). The typed persistence model keeps database column
/// names, nullability, UUIDs, and timestamps checked at compile time. The wire
/// boundary projects it into `agent_projection`, dropping internal columns —
/// see `routing::identity::agents::agent_projection_from_record`.
#[derive(Clone, Debug)]
pub struct AgentRuntimeActivation {
    pub agent_id: String,
    pub approval_request_id: OpaqueLocalId,
    pub runtime_key_binding_digest: String,
    pub pairing_request_id: OpaqueLocalId,
    pub paired_request_digest: String,
    pub authorized_event_ref: String,
    pub authorized_verification_method: String,
    pub authorized_public_key_digest: String,
    pub authorized_signing_key_binding:
        arkret_models_identity::agent_signer_evidence::AgentSigningKeyBinding,
    pub authorized_at: chrono::DateTime<chrono::Utc>,
}
#[derive(Clone, Debug)]
pub struct AgentPairingCommitIntent {
    pub agent_id: String,
    pub approval_request_id: OpaqueLocalId,
    pub runtime_key_binding_digest: String,
    pub pairing_request_id: OpaqueLocalId,
    pub request_digest: String,
    pub authorize_event_id: String,
    pub signing_key_binding: arkret_models_identity::agent_signer_evidence::AgentSigningKeyBinding,
}
#[derive(Clone, Debug)]
pub struct AgentRuntimeApprovalWrite {
    pub agent_id: String,
    pub pairing_request_id: OpaqueLocalId,
    pub approval_request_id: OpaqueLocalId,
    pub approval_notification_id: String,
    pub approval_requested_at: chrono::DateTime<chrono::Utc>,
    pub controller_account_id: ServiceAccountId,
    pub recipient_id: String,
    pub runtime_key_binding_digest: String,
    pub runtime_public_key_digest: String,
    pub runtime_attestation_digest: String,
    pub runtime_key_request:
        arkret_models_collaboration::agent_operations::AgentRuntimeApprovalControllerProjection,
}

/// Exact active-runtime snapshot that a durable Agent inbox write is allowed
/// to target.  `updated_at` is part of the guard so a pause, re-key, or
/// endpoint replacement that races delivery cannot receive the message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentRuntimeSnapshotGuard {
    pub agent_id: String,
    pub verification_method: String,
    pub authorized_event_ref: String,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct EnqueueAgentRuntimeMessage {
    pub request_key: String,
    pub request_digest: String,
    pub snapshot: AgentRuntimeSnapshotGuard,
    /// The exact repair/runtime envelope delivered to the Agent.  Storage
    /// compares this value on replay; a request digest alone is insufficient.
    pub content: serde_json::Value,
    pub enqueued_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct AgentRuntimeMessageRecord {
    pub message_id: uuid::Uuid,
    pub request_key: String,
    pub request_digest: String,
    pub agent_id: String,
    pub verification_method: String,
    pub authorized_event_ref: String,
    pub content: serde_json::Value,
    pub enqueued_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum AgentRuntimeEnqueueOutcome {
    Stored(AgentRuntimeMessageRecord),
    Duplicate(AgentRuntimeMessageRecord),
    RequestConflict,
    SnapshotConflict,
}
#[async_trait]
pub trait AgentStore: Send + Sync {
    async fn put(&self, record: AgentPrincipalRecord) -> PersistenceResult<()>;
    async fn get(&self, agent_id: &str) -> PersistenceResult<Option<AgentPrincipalRecord>>;
    async fn get_by_pairing_request_id(
        &self,
        pairing_request_id: &str,
    ) -> PersistenceResult<Option<AgentPrincipalRecord>>;
    async fn list_for_controller(
        &self,
        controller_id: &str,
    ) -> PersistenceResult<Vec<AgentPrincipalRecord>>;
    async fn set_state(
        &self,
        agent_id: &str,
        state: arkret_models_collaboration::agent_operations::AgentLifecycleState,
        changed_at: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<bool>;
    async fn activate_runtime_if_current(
        &self,
        activation: &AgentRuntimeActivation,
    ) -> PersistenceResult<bool>;
    /// Durably bind the one open pairing handle to the exact final request
    /// before Event admission. Exact retries are idempotent; a different
    /// request or Event id cannot replace an existing intent.
    async fn put_pairing_commit_intent_if_compatible(
        &self,
        intent: &AgentPairingCommitIntent,
    ) -> PersistenceResult<Option<AgentPrincipalRecord>>;
    /// Clear the retained approval/notification correlation only after the
    /// terminal account-notification delta is durable. Retaining it across the
    /// activation write makes a crash between those writes reconcilable.
    async fn clear_runtime_approval_notification_if_current(
        &self,
        agent_id: &str,
        approval_request_id: &str,
    ) -> PersistenceResult<bool>;
    async fn put_runtime_approval_if_compatible(
        &self,
        write: &AgentRuntimeApprovalWrite,
    ) -> PersistenceResult<Option<AgentPrincipalRecord>>;
    /// Check exact replay first, then atomically validate the unique current
    /// active runtime snapshot and append one inbox message.
    async fn enqueue_runtime_message_if_current(
        &self,
        command: &EnqueueAgentRuntimeMessage,
    ) -> PersistenceResult<AgentRuntimeEnqueueOutcome>;
}
