use super::{AgentPrincipalRecord, PersistenceResult, Value, async_trait};
/// AKP-0010 — agent participation policy persistence. Controller
/// selections (`ak.agent.participation.v1`) and the governance ceiling
/// projection are stored as JSON records mirroring the
/// `arkret_sdk::AgentParticipation*` wire shape (keys:
/// agent_id, scope, scope_kind, scope_key, realm_id, reply,
/// accept_third_party_mention, act_on_behalf).
#[async_trait]
pub trait AgentParticipationStore: Send + Sync {
    /// Upsert a controller selection keyed by (agent_id, scope_key).
    async fn put_selection(&self, record: Value) -> PersistenceResult<()>;
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
    pub approval_request_id: String,
    pub runtime_key_binding_digest: String,
    pub pairing_request_id: String,
    pub paired_request_digest: String,
    pub authorized_event_ref: String,
    pub authorized_verification_method: String,
    pub authorized_public_key_digest: String,
    pub authorized_at: chrono::DateTime<chrono::Utc>,
}
#[derive(Clone, Debug)]
pub struct AgentRuntimeApprovalWrite {
    pub agent_id: String,
    pub pairing_request_id: String,
    pub approval_request_id: String,
    pub approval_notification_id: String,
    pub approval_requested_at: chrono::DateTime<chrono::Utc>,
    pub controller_account_id: String,
    pub recipient_service_id: String,
    pub runtime_key_binding_digest: String,
    pub runtime_public_key_digest: String,
    pub runtime_attestation_digest: String,
    pub runtime_key_request: Value,
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
        state: &str,
        changed_at: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<bool>;
    async fn activate_runtime_if_current(
        &self,
        activation: &AgentRuntimeActivation,
    ) -> PersistenceResult<bool>;
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
}
