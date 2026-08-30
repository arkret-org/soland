use arkret_models_collaboration::objects::read_receipts::Notification;
use arkret_models_collaboration::sync_frames::account_sync::NotificationDelta;
use arkret_wire::events::EventKind;
use arkret_wire::{ActorId, DidCoreId};

use super::{AccountPk, PersistenceResult, async_trait};

#[derive(Clone, Debug, PartialEq)]
pub struct RecipientNotificationRecord {
    pub notification: Notification,
    pub event_kind: EventKind,
    pub source_actor_id: Option<ActorId>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct AccountNotificationDeltaWrite {
    pub delta: NotificationDelta,
    pub recipient_actor_id: ActorId,
    pub controller_account_pk: AccountPk,
    pub recipient_id: DidCoreId,
    pub source_account_artifact_id: String,
}

#[derive(Clone, Debug, PartialEq)]
pub struct StoredAccountNotificationDelta {
    pub record: AccountNotificationDeltaWrite,
    pub projection_position: i64,
}

/// AKP-0016 §9.4.5 — per-recipient notification projection (mention
/// fanout output). Native agents are gated by their effective
/// accept_third_party_mention bit before a row is written here.
#[async_trait]
pub trait NotificationStore: Send + Sync {
    async fn put(&self, record: RecipientNotificationRecord) -> PersistenceResult<()>;
    async fn put_account_delta(
        &self,
        record: AccountNotificationDeltaWrite,
    ) -> PersistenceResult<()>;
    async fn list_for_recipient(
        &self,
        recipient_id: &str,
    ) -> PersistenceResult<Vec<RecipientNotificationRecord>>;
    async fn list_for_account(
        &self,
        controller_account_pk: &AccountPk,
        recipient_id: &str,
        after_position: Option<i64>,
    ) -> PersistenceResult<Vec<StoredAccountNotificationDelta>>;
}
