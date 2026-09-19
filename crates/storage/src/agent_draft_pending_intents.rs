use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde_json::Value;

use crate::PersistenceResult;

/// Station-private materialization of one accepted `ak.agent.draft.propose`.
///
/// The JSON fields are already schema-validated protocol values. Keeping them
/// opaque here prevents persistence from inventing a second wire contract.
#[derive(Clone, Debug, PartialEq)]
pub struct AgentDraftPendingIntentRecord {
    pub controller_account_id: arkret_wire::AccountId,
    pub agent_id: arkret_wire::DidCoreId,
    pub draft_id: String,
    pub proposed_action: String,
    pub target: Value,
    pub content_digest: arkret_wire::Hash,
    /// Present only while the intent is live. Terminal rows retain their
    /// create-once identity and outcome metadata but permanently redact the
    /// HPKE ciphertext.
    pub content_handoff: Option<Value>,
    pub canonical_event_digest: arkret_wire::Hash,
    pub accepted_event_id: arkret_wire::EventId,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub state: AgentDraftPendingIntentState,
    pub consumption: Option<AgentDraftPendingIntentConsumption>,
    pub expired_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AgentDraftPendingIntentState {
    Available,
    Consumed,
    Expired,
}

impl AgentDraftPendingIntentState {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Available => "available",
            Self::Consumed => "consumed",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentDraftPendingIntentConsumption {
    pub account_data_set_event_id: arkret_wire::EventId,
    pub account_data_key: String,
    pub accepted_revision: u64,
    pub consumed_at: DateTime<Utc>,
}

/// Mutation carried by the accepted proposal Event's transaction.
#[derive(Clone, Debug)]
pub struct AgentDraftPendingIntentCommit {
    pub record: AgentDraftPendingIntentRecord,
}

/// Station-private source read used by the account-global projection.
///
/// This port is not itself a client-visible carrier. Public delivery is only
/// through the dedicated account-subscribe `agent_draft_pending_intents`
/// baseline/delta channel.
#[async_trait]
pub trait AgentDraftPendingIntentStore: Send + Sync {
    async fn get_by_source_event(
        &self,
        controller_account_id: &arkret_wire::AccountId,
        source_event_id: &arkret_wire::EventId,
        protocol_time: DateTime<Utc>,
    ) -> PersistenceResult<Option<AgentDraftPendingIntentRecord>>;

    async fn list_for_controller(
        &self,
        controller_account_id: &arkret_wire::AccountId,
        protocol_time: DateTime<Utc>,
    ) -> PersistenceResult<Vec<AgentDraftPendingIntentRecord>>;
}
