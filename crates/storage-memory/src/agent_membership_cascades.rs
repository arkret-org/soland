use arkret_models_collaboration::governance::agent_membership_cascade::AgentCleanupRecord;
use arkret_wire::Hash;

use super::*;

#[derive(Clone, Default)]
pub(crate) struct MemoryAgentMembershipCascadeStore {
    pub(crate) data: Arc<Mutex<BTreeMap<String, AgentCleanupRecord>>>,
}

impl MemoryAgentMembershipCascadeStore {
    pub(crate) fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl soland_storage::AgentMembershipCascadeStore for MemoryAgentMembershipCascadeStore {
    async fn agent_cleanup_intent(
        &self,
        cleanup_intent_digest: &Hash,
    ) -> PersistenceResult<Option<AgentCleanupRecord>> {
        let records = self.data.lock();
        Ok(records.get(cleanup_intent_digest.as_str()).cloned())
    }

    async fn agent_cleanup_intent_for_terminal_event(
        &self,
        controller_terminal_event_id: &arkret_wire::EventId,
    ) -> PersistenceResult<Option<AgentCleanupRecord>> {
        let records = self.data.lock();
        Ok(records
            .values()
            .find(|record| record.controller_terminal_event_id == *controller_terminal_event_id)
            .cloned())
    }

    async fn incomplete_agent_cleanup_intents(
        &self,
        _now: chrono::DateTime<Utc>,
        limit: usize,
    ) -> PersistenceResult<Vec<AgentCleanupRecord>> {
        let records = self.data.lock();
        let mut incomplete = records
            .values()
            .filter(|record| record.completed_at.is_none())
            .cloned()
            .collect::<Vec<_>>();
        incomplete.sort_by(|left, right| {
            (left.cleanup_due_at, left.cleanup_intent_digest.as_str())
                .cmp(&(right.cleanup_due_at, right.cleanup_intent_digest.as_str()))
        });
        incomplete.truncate(limit);
        Ok(incomplete)
    }
}
