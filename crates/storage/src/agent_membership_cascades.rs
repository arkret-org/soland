use arkret_wire::{EventId, Hash};
use async_trait::async_trait;
use chrono::{DateTime, Utc};

use crate::PersistenceResult;

pub const MAX_AGENT_MEMBERSHIP_CASCADE_TRANSITIONS: usize = 256;

/// Durable, authority-committed cleanup intent for dependent Agent
/// memberships when their controller leaves a Realm.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AgentCleanupRecord {
    pub realm_id: arkret_wire::RealmId,
    pub controller_account_id: arkret_wire::AccountId,
    pub controller_membership_ref: arkret_wire::CommittedEventRef,
    pub initiator_actor_id: arkret_wire::ActorId,
    pub controller_terminal_event_id: EventId,
    pub expected_agent_ids: Vec<arkret_wire::ActorId>,
    pub cleanup_intent_digest: Hash,
    pub accepted_at: DateTime<Utc>,
    pub cleanup_due_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub agent_transition_event_ids: Option<Vec<EventId>>,
}

impl AgentCleanupRecord {
    pub fn expected_cleanup_intent_digest(&self) -> arkret_wire::Result<Hash> {
        Ok(Hash::new(arkret_canonical::canonical_sha256(
            &serde_json::json!({
                "realm_id": self.realm_id,
                "controller_account_id": self.controller_account_id,
                "controller_membership_ref": self.controller_membership_ref,
                "initiator_actor_id": self.initiator_actor_id,
                "controller_terminal_event_id": self.controller_terminal_event_id,
                "expected_agent_ids": self.expected_agent_ids,
            }),
        )?)?)
    }

    pub fn validate(&self) -> arkret_wire::Result<()> {
        if self.cleanup_due_at <= self.accepted_at
            || self.expected_agent_ids.len() > MAX_AGENT_MEMBERSHIP_CASCADE_TRANSITIONS
            || self.cleanup_intent_digest != self.expected_cleanup_intent_digest()?
        {
            return Err(arkret_wire::WireError::Protocol(
                "agent cleanup intent is invalid".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub enum AgentMembershipCascadeCommit {
    AtomicSelfLeave {
        controller_transition_event_id: EventId,
        agent_transition_event_ids: Vec<EventId>,
        expected_agent_ids: Vec<arkret_wire::ActorId>,
    },
    EmergencyTerminal {
        record: Box<AgentCleanupRecord>,
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
    ) -> PersistenceResult<Option<AgentCleanupRecord>>;

    async fn agent_cleanup_intent_for_terminal_event(
        &self,
        controller_terminal_event_id: &EventId,
    ) -> PersistenceResult<Option<AgentCleanupRecord>>;

    async fn incomplete_agent_cleanup_intents(
        &self,
        now: DateTime<Utc>,
        limit: usize,
    ) -> PersistenceResult<Vec<AgentCleanupRecord>>;
}
