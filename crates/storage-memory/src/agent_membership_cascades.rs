use arkret_models_collaboration::governance::agent_membership_cascade::{
    AgentCleanupPendingRecord, AgentCleanupStatus,
};
use arkret_wire::Hash;

use super::*;

#[derive(Clone, Default)]
pub(crate) struct MemoryAgentMembershipCascadeStore {
    pub(crate) data: Arc<Mutex<BTreeMap<String, AgentCleanupPendingRecord>>>,
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
    ) -> PersistenceResult<Option<AgentCleanupPendingRecord>> {
        let mut records = self.data.lock();
        let record = records.get_mut(cleanup_intent_digest.as_str());
        if let Some(record) = record
            && record.status == AgentCleanupStatus::AgentCleanupPending
            && record.cleanup_due_at <= Utc::now()
        {
            record.status = AgentCleanupStatus::AgentCleanupOverdue;
        }
        Ok(records.get(cleanup_intent_digest.as_str()).cloned())
    }

    async fn incomplete_agent_cleanup_intents(
        &self,
        now: chrono::DateTime<Utc>,
        limit: usize,
    ) -> PersistenceResult<Vec<AgentCleanupPendingRecord>> {
        let mut records = self.data.lock();
        for record in records.values_mut() {
            if record.status == AgentCleanupStatus::AgentCleanupPending
                && record.cleanup_due_at <= now
            {
                record.status = AgentCleanupStatus::AgentCleanupOverdue;
            }
        }
        let mut incomplete = records
            .values()
            .filter(|record| record.status != AgentCleanupStatus::AgentCleanupCompleted)
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
