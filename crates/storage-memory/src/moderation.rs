use super::{ModerationStore, Mutex, PersistenceError, PersistenceResult, Value, async_trait};
#[derive(Default)]
pub(crate) struct MemoryModerationStore {
    reports: Mutex<Vec<Value>>,
    queue_items: Mutex<Vec<Value>>,
}
impl MemoryModerationStore {
    pub(crate) fn new() -> Self {
        Self::default()
    }
}
#[async_trait]
impl ModerationStore for MemoryModerationStore {
    async fn append_report(&self, report: Value) -> PersistenceResult<()> {
        let report_id = report
            .get("report_id")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                PersistenceError::Internal("moderation report missing report_id".to_owned())
            })?
            .to_owned();
        let mut reports = self.reports.lock();
        if let Some(existing) = reports
            .iter_mut()
            .find(|item| item.get("report_id").and_then(Value::as_str) == Some(report_id.as_str()))
        {
            *existing = report;
        } else {
            reports.push(report);
        }
        Ok(())
    }

    async fn list_reports(&self) -> PersistenceResult<Vec<Value>> {
        Ok(self.reports.lock().clone())
    }

    async fn upsert_queue_item(&self, item: Value) -> PersistenceResult<()> {
        let id = item
            .get("id")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                PersistenceError::Internal("moderation queue item missing id".to_owned())
            })?
            .to_owned();
        let mut queue = self.queue_items.lock();
        if let Some(slot) = queue
            .iter_mut()
            .find(|i| i.get("id").and_then(Value::as_str) == Some(id.as_str()))
        {
            *slot = item;
        } else {
            queue.push(item);
        }
        Ok(())
    }

    async fn list_queue_items(&self) -> PersistenceResult<Vec<Value>> {
        Ok(self.queue_items.lock().clone())
    }

    async fn get_queue_item(&self, id: &str) -> PersistenceResult<Option<Value>> {
        Ok(self
            .queue_items
            .lock()
            .iter()
            .find(|i| i.get("id").and_then(Value::as_str) == Some(id))
            .cloned())
    }

    async fn get_submitted_queue_item_for_report_event(
        &self,
        report_event_id: &str,
    ) -> PersistenceResult<Option<Value>> {
        Ok(self
            .queue_items
            .lock()
            .iter()
            .find(|item| {
                item.pointer("/report/event_id").and_then(Value::as_str) == Some(report_event_id)
                    && item.get("status").and_then(Value::as_str) == Some("submitted")
            })
            .cloned())
    }

}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn submitted_queue_lookup_is_keyed_by_report_event() {
        let store = MemoryModerationStore::new();
        store
            .upsert_queue_item(serde_json::json!({
                "id": "ak:event:queue",
                "status": "submitted",
                "report": { "event_id": "ak:event:report" }
            }))
            .await
            .unwrap();

        assert!(
            store
                .get_submitted_queue_item_for_report_event("ak:event:report")
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            store
                .get_submitted_queue_item_for_report_event("ak:event:other")
                .await
                .unwrap()
                .is_none()
        );
    }
}
