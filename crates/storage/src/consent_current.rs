//! Holder-private PCR Consent current, never a process-local authority cache.

use arkret_models_collaboration::consent_operations::{ConsentValue, ConsentView};
use arkret_wire::{AccountId, CurrentRevision, Event, RealmCommit};
use async_trait::async_trait;

use crate::{AuthorityCommitTransaction, PersistenceResult};

#[derive(Clone, Debug)]
pub struct ConsentAdmissionWrite {
    pub transaction: AuthorityCommitTransaction,
}

#[derive(Clone, Debug)]
pub struct ConsentCurrentRecord {
    pub value: ConsentValue,
    pub event: Event,
    pub commit: RealmCommit,
    /// Successful invalidation CAS; absent on reads and exact retries.
    pub quarantine_update: Option<crate::AccountDataRecord>,
}

impl ConsentCurrentRecord {
    /// Evaluate the complete peer and the current grant at the read cut.
    /// Unimplemented constraint semantics never silently widen consent.
    pub fn permits(
        &self,
        peer: &arkret_wire::ActorId,
        scope: arkret_wire::ConsentScope,
        at: chrono::DateTime<chrono::Utc>,
    ) -> bool {
        self.value.status == arkret_models_collaboration::consent_operations::ConsentState::Active
            && self.value.peer
                == (arkret_models_collaboration::events_payloads::consent::ConsentPeer::Actor {
                    actor_id: peer.clone(),
                })
            && (self.value.consent_scope == scope
                || self.value.consent_scope == arkret_wire::ConsentScope::Any)
            && self.value.not_before.is_none_or(|start| start <= at)
            && self.value.expires_at.is_none_or(|end| at < end)
            && self.value.constraints.as_ref().is_none_or(Vec::is_empty)
    }

    pub fn view(&self) -> ConsentView {
        ConsentView {
            consent_id: self.value.consent_id.clone(),
            peer: self.value.peer.clone(),
            consent_scope: self.value.consent_scope,
            state: self.value.status,
            expires_at: self.value.expires_at,
            updated_at: self.commit.committed_at,
            revision: CurrentRevision {
                commit_id: self.commit.commit_id.clone(),
                stream_position: self.commit.stream_position,
            },
        }
    }
}

#[derive(Clone, Debug)]
pub enum ConsentAdmissionOutcome {
    Committed(ConsentCurrentRecord),
    Duplicate(ConsentCurrentRecord),
}

/// Internal private-delivery CAS bound to a current Consent at its write cut.
#[derive(Clone, Debug)]
pub struct ConsentDeliveryWrite {
    pub holder: AccountId,
    pub peer: arkret_wire::ActorId,
    pub consent_grant_ref: arkret_wire::EventId,
    pub consent_id: Option<arkret_identifiers::ConsentId>,
    pub record: crate::AccountDataRecord,
    pub expected_revision: u64,
}

#[async_trait]
pub trait ConsentCurrentStore: Send + Sync {
    async fn admit(
        &self,
        write: ConsentAdmissionWrite,
    ) -> PersistenceResult<ConsentAdmissionOutcome>;
    /// `None` refuses a no-longer-valid proof without any private write.
    async fn admit_invite_delivery(
        &self,
        write: ConsentDeliveryWrite,
    ) -> PersistenceResult<Option<crate::AccountDataCasResult>>;
    async fn list(&self, holder: &AccountId) -> PersistenceResult<Vec<ConsentCurrentRecord>>;
}
