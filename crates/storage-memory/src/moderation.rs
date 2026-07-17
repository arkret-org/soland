use super::{ModerationStore, Mutex, PersistenceError, PersistenceResult, Value, async_trait};
#[derive(Default)]
pub(crate) struct MemoryModerationStore {
    reports: Mutex<Vec<Value>>,
    actions: Mutex<Vec<Value>>,
    decisions: Mutex<Vec<Value>>,
    decision_lifts: Mutex<Vec<Value>>,
    queue_items: Mutex<Vec<Value>>,
    appeals: Mutex<Vec<Value>>,
}
impl MemoryModerationStore {
    pub(crate) fn new() -> Self {
        Self::default()
    }
}
#[async_trait]
impl ModerationStore for MemoryModerationStore {
    async fn append_report(&self, report: Value) -> PersistenceResult<()> {
        self.reports.lock().push(report);
        Ok(())
    }

    async fn append_action(&self, action: Value) -> PersistenceResult<()> {
        self.actions.lock().push(action);
        Ok(())
    }

    async fn list_reports(&self) -> PersistenceResult<Vec<Value>> {
        Ok(self.reports.lock().clone())
    }

    async fn list_actions(&self) -> PersistenceResult<Vec<Value>> {
        Ok(self.actions.lock().clone())
    }

    async fn append_decision(&self, decision: Value) -> PersistenceResult<()> {
        let id = decision
            .get("decision_id")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                PersistenceError::Internal("moderation decision missing decision_id".to_owned())
            })?
            .to_owned();
        let mut decisions = self.decisions.lock();
        if !decisions
            .iter()
            .any(|d| d.get("decision_id").and_then(Value::as_str) == Some(id.as_str()))
        {
            decisions.push(decision);
        }
        Ok(())
    }

    async fn list_decisions(&self) -> PersistenceResult<Vec<Value>> {
        Ok(self.decisions.lock().clone())
    }

    async fn get_decision(&self, decision_id: &str) -> PersistenceResult<Option<Value>> {
        Ok(self
            .decisions
            .lock()
            .iter()
            .find(|d| d.get("decision_id").and_then(Value::as_str) == Some(decision_id))
            .cloned())
    }

    async fn append_decision_lift(&self, lift: Value) -> PersistenceResult<()> {
        self.decision_lifts.lock().push(lift);
        Ok(())
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

    async fn append_appeal(&self, appeal: Value) -> PersistenceResult<()> {
        if appeal.get("appeal_id").and_then(Value::as_str).is_none() {
            return Err(PersistenceError::Internal(
                "moderation appeal missing appeal_id".to_owned(),
            ));
        }
        self.appeals.lock().push(appeal);
        Ok(())
    }

    async fn list_appeals(&self) -> PersistenceResult<Vec<Value>> {
        // Collapse history → one record per appeal_id, keeping the
        // last-appended event (insertion order = chronological).
        let all = self.appeals.lock().clone();
        let mut latest: std::collections::BTreeMap<String, Value> =
            std::collections::BTreeMap::new();
        for record in all {
            if let Some(id) = record.get("appeal_id").and_then(Value::as_str) {
                latest.insert(id.to_owned(), record);
            }
        }
        Ok(latest.into_values().collect())
    }

    async fn appeal_history(&self, appeal_id: &str) -> PersistenceResult<Vec<Value>> {
        Ok(self
            .appeals
            .lock()
            .iter()
            .filter(|a| a.get("appeal_id").and_then(Value::as_str) == Some(appeal_id))
            .cloned()
            .collect())
    }
}
