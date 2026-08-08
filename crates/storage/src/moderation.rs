use super::{PersistenceError, PersistenceResult, Value, async_trait};
/// Moderation reports + assigned actions + decisions + appeals + queue items.
///
/// Reports and actions are append-only. Appeals and queue items support the
/// moderation workbench; canonical decisions remain durable Events projected
/// by `soland_domain::reducer::apply_moderation`.
///
/// The Pg backend stubs appeals/queue items as
/// `Err(PersistenceError::Internal("not yet wired"))` so production
/// instances fail loudly until a migration ships; the in-memory backend
/// implements them fully and is used by dev mode + tests.
#[async_trait]
pub trait ModerationStore: Send + Sync {
    async fn append_report(&self, report: Value) -> PersistenceResult<()>;
    async fn append_action(&self, action: Value) -> PersistenceResult<()>;
    async fn list_reports(&self) -> PersistenceResult<Vec<Value>>;
    async fn list_actions(&self) -> PersistenceResult<Vec<Value>>;

    /// Upsert a `ModerationQueueItem` record. The JSON must carry
    /// `id`, `status`, `visibility`, `created_at`.
    async fn upsert_queue_item(&self, _item: Value) -> PersistenceResult<()> {
        Err(PersistenceError::Internal(
            "moderation queue item upsert not wired in this backend".to_owned(),
        ))
    }
    async fn list_queue_items(&self) -> PersistenceResult<Vec<Value>> {
        Ok(Vec::new())
    }
    async fn get_queue_item(&self, _id: &str) -> PersistenceResult<Option<Value>> {
        Ok(None)
    }

    /// Append a projected appeal event. The projection record MUST carry the
    /// event-derived `appeal_id`, `realm_id`, and the variant-specific fields (see
    /// the SDK `ModerationAppealPayload`). The store
    /// keeps an event log per appeal; the current FSM state is derived
    /// by replaying events.
    async fn append_appeal(&self, _appeal: Value) -> PersistenceResult<()> {
        Err(PersistenceError::Internal(
            "moderation appeal append not wired in this backend".to_owned(),
        ))
    }
    /// List the latest known event for each known appeal (one record
    /// per appeal_id). Used by sodmin to render the queue.
    async fn list_appeals(&self) -> PersistenceResult<Vec<Value>> {
        Ok(Vec::new())
    }
    /// Full event history for one appeal, in append order.
    async fn appeal_history(&self, _appeal_id: &str) -> PersistenceResult<Vec<Value>> {
        Ok(Vec::new())
    }
}
