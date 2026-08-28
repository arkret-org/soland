use arkret_models_collaboration::objects::read_receipts::NotificationSource;
use soland_storage::{
    AccountNotificationDeltaWrite, NotificationStore, RecipientNotificationRecord,
    StoredAccountNotificationDelta,
};

use super::{Mutex, PersistenceResult, async_trait};

#[derive(Default)]
pub(crate) struct MemoryNotificationStore {
    recipient_notifications: Mutex<Vec<RecipientNotificationRecord>>,
    account_notifications: Mutex<Vec<StoredAccountNotificationDelta>>,
    position: Mutex<i64>,
}

impl MemoryNotificationStore {
    pub(crate) fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl NotificationStore for MemoryNotificationStore {
    async fn put(&self, mut record: RecipientNotificationRecord) -> PersistenceResult<()> {
        let source_event_id = match &record.notification.source {
            NotificationSource::Event(source) => source.source_event_id.as_str(),
            NotificationSource::AccountArtifact(_) => {
                return Err(super::PersistenceError::Internal(
                    "recipient notification must have an Event source".to_owned(),
                ));
            }
        };
        let mut data = self.recipient_notifications.lock();
        if let Some(existing) = data.iter_mut().find(|candidate| {
            let candidate_source_event_id = match &candidate.notification.source {
                NotificationSource::Event(source) => source.source_event_id.as_str(),
                NotificationSource::AccountArtifact(_) => return false,
            };
            candidate.notification.actor_id == record.notification.actor_id
                && candidate_source_event_id == source_event_id
                && candidate.notification.notification_kind == record.notification.notification_kind
        }) {
            record.notification.id = existing.notification.id.clone();
            record.notification.created_at = existing.notification.created_at;
            *existing = record;
            return Ok(());
        }
        data.push(record);
        Ok(())
    }

    async fn put_account_delta(
        &self,
        record: AccountNotificationDeltaWrite,
    ) -> PersistenceResult<()> {
        let mut position = self.position.lock();
        *position += 1;
        let stored = StoredAccountNotificationDelta {
            record,
            projection_position: *position,
        };
        let mut data = self.account_notifications.lock();
        if let Some(existing) = data.iter_mut().find(|candidate| {
            candidate.record.controller_account_id == stored.record.controller_account_id
                && candidate.record.recipient_id == stored.record.recipient_id
                && candidate.record.source_account_artifact_id
                    == stored.record.source_account_artifact_id
        }) {
            *existing = stored;
        } else {
            data.push(stored);
        }
        Ok(())
    }

    async fn list_for_recipient(
        &self,
        recipient_id: &str,
    ) -> PersistenceResult<Vec<RecipientNotificationRecord>> {
        Ok(self
            .recipient_notifications
            .lock()
            .iter()
            .filter(|record| record.notification.actor_id.as_str() == recipient_id)
            .cloned()
            .collect())
    }

    async fn list_for_account(
        &self,
        controller_account_id: &str,
        recipient_id: &str,
        after_position: Option<i64>,
    ) -> PersistenceResult<Vec<StoredAccountNotificationDelta>> {
        let mut rows = self
            .account_notifications
            .lock()
            .iter()
            .filter(|record| {
                record.record.controller_account_id == controller_account_id
                    && record.record.recipient_id.as_str() == recipient_id
                    && after_position.is_none_or(|after| record.projection_position > after)
            })
            .cloned()
            .collect::<Vec<_>>();
        rows.sort_by_key(|record| record.projection_position);
        Ok(rows)
    }
}
