use arkret_models_collaboration::governance::agent_membership_cascade::AgentCleanupPendingRecord;
use arkret_wire::{EventId, Hash};
use async_trait::async_trait;
use chrono::{DateTime, Utc};

use crate::PersistenceResult;

#[derive(Clone, Debug)]
pub enum AgentMembershipCascadeCommit {
    AtomicSelfLeave {
        controller_transition_event_id: EventId,
        agent_transition_event_ids: Vec<EventId>,
        expected_agent_ids: Vec<arkret_wire::DidCoreId>,
    },
    EmergencyTerminal {
        record: Box<AgentCleanupPendingRecord>,
    },
    EmergencyCleanup {
        cleanup_intent_digest: Hash,
        controller_terminal_event_id: EventId,
        agent_transition_event_ids: Vec<EventId>,
        completed_at: DateTime<Utc>,
    },
}

#[async_trait]
pub trait AgentMembershipCascadeStore: Send + Sync {
    async fn agent_cleanup_intent(
        &self,
        cleanup_intent_digest: &Hash,
    ) -> PersistenceResult<Option<AgentCleanupPendingRecord>>;

    async fn agent_cleanup_intent_for_terminal_event(
        &self,
        controller_terminal_event_id: &EventId,
    ) -> PersistenceResult<Option<AgentCleanupPendingRecord>>;

    async fn incomplete_agent_cleanup_intents(
        &self,
        now: DateTime<Utc>,
        limit: usize,
    ) -> PersistenceResult<Vec<AgentCleanupPendingRecord>>;
}
