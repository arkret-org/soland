use super::{Mutex, NotificationStore, PersistenceError, PersistenceResult, Value, async_trait};
#[derive(Default)]
pub(crate) struct MemoryNotificationStore {
    data: Mutex<Vec<Value>>,
    position: Mutex<i64>,
}
impl MemoryNotificationStore {
    pub(crate) fn new() -> Self {
        Self::default()
    }
}
#[async_trait]
impl NotificationStore for MemoryNotificationStore {
    async fn put(&self, record: Value) -> PersistenceResult<()> {
        let recipient_id = record.get("recipient_id").and_then(Value::as_str);
        let source_event_id = record.get("source_event_id").and_then(Value::as_str);
        let notification_type = record.get("notification_type").and_then(Value::as_str);
        let mut data = self.data.lock();
        if let (Some(recipient_id), Some(source_event_id), Some(notification_type)) =
            (recipient_id, source_event_id, notification_type)
            && let Some(existing) = data.iter_mut().find(|candidate| {
                candidate.get("recipient_id").and_then(Value::as_str) == Some(recipient_id)
                    && candidate.get("source_event_id").and_then(Value::as_str)
                        == Some(source_event_id)
                    && candidate.get("notification_type").and_then(Value::as_str)
                        == Some(notification_type)
            })
        {
            let notification_id = existing
                .get("notification_id")
                .cloned()
                .or_else(|| record.get("notification_id").cloned());
            let created_at = existing
                .get("created_at")
                .cloned()
                .or_else(|| record.get("created_at").cloned());
            *existing = record;
            if let Some(notification_id) = notification_id {
                existing["notification_id"] = notification_id;
            }
            if let Some(created_at) = created_at {
                existing["created_at"] = created_at;
            }
            return Ok(());
        }
        data.push(record);
        Ok(())
    }

    async fn put_account_delta(&self, mut record: Value) -> PersistenceResult<()> {
        let account_id = record
            .get("controller_account_id")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
            .ok_or_else(|| {
                PersistenceError::Internal(
                    "account notification missing controller_account_id".to_owned(),
                )
            })?;
        let service_id = record
            .get("recipient_service_id")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
            .ok_or_else(|| {
                PersistenceError::Internal(
                    "account notification missing recipient_service_id".to_owned(),
                )
            })?;
        let artifact_id = record
            .get("source_account_artifact_id")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
            .ok_or_else(|| {
                PersistenceError::Internal(
                    "account notification missing source_account_artifact_id".to_owned(),
                )
            })?;
        let mut position = self.position.lock();
        *position += 1;
        record["projection_position"] = serde_json::json!(*position);
        let mut data = self.data.lock();
        if let Some(existing) = data.iter_mut().find(|candidate| {
            candidate
                .get("controller_account_id")
                .and_then(Value::as_str)
                == Some(account_id.as_str())
                && candidate
                    .get("recipient_service_id")
                    .and_then(Value::as_str)
                    == Some(service_id.as_str())
                && candidate
                    .get("source_account_artifact_id")
                    .and_then(Value::as_str)
                    == Some(artifact_id.as_str())
        }) {
            *existing = record;
        } else {
            data.push(record);
        }
        Ok(())
    }

    async fn list_for_recipient(&self, recipient_id: &str) -> PersistenceResult<Vec<Value>> {
        Ok(self
            .data
            .lock()
            .iter()
            .filter(|r| r.get("recipient_id").and_then(Value::as_str) == Some(recipient_id))
            .cloned()
            .collect())
    }

    async fn list_for_account(
        &self,
        controller_account_id: &str,
        recipient_service_id: &str,
        after_position: Option<i64>,
    ) -> PersistenceResult<Vec<Value>> {
        let mut rows = self
            .data
            .lock()
            .iter()
            .filter(|record| {
                record.get("controller_account_id").and_then(Value::as_str)
                    == Some(controller_account_id)
                    && record.get("recipient_service_id").and_then(Value::as_str)
                        == Some(recipient_service_id)
                    && after_position.is_none_or(|after| {
                        record
                            .get("projection_position")
                            .and_then(Value::as_i64)
                            .unwrap_or_default()
                            > after
                    })
            })
            .cloned()
            .collect::<Vec<_>>();
        rows.sort_by_key(|record| {
            record
                .get("projection_position")
                .and_then(Value::as_i64)
                .unwrap_or_default()
        });
        Ok(rows)
    }
}
