use super::*;
/// Moderation reports + assigned actions + decisions + appeals + queue items.
///
/// Reports and actions are append-only (back-compat). The newer methods
/// (decisions, appeals, queue items) form the spec-compliant triage
/// strand: a report becomes a queue item, a queue item gets a decision,
/// a decision can be appealed (4-state appeal FSM lives in the reducer
/// `soland_domain::reducer::apply_moderation`).
///
/// The Pg backend stubs decisions/appeals/queue items as
/// `Err(PersistenceError::Internal("not yet wired"))` so production
/// instances fail loudly until a migration ships; the in-memory backend
/// implements them fully and is used by dev mode + tests.
#[async_trait]
pub trait ModerationStore: Send + Sync {
    async fn append_report(&self, report: Value) -> PersistenceResult<()>;
    async fn append_action(&self, action: Value) -> PersistenceResult<()>;
    async fn list_reports(&self) -> PersistenceResult<Vec<Value>>;
    async fn list_actions(&self) -> PersistenceResult<Vec<Value>>;

    /// Append a `ak.moderation.decision` record. The JSON must carry at
    /// least `decision_id`, `target_ref`, `action`, `decided_by`,
    /// `decided_at`. Idempotent on `decision_id`.
    async fn append_decision(&self, _decision: Value) -> PersistenceResult<()> {
        Err(PersistenceError::Internal(
            "moderation decision append not wired in this backend".to_owned(),
        ))
    }
    async fn list_decisions(&self) -> PersistenceResult<Vec<Value>> {
        Ok(Vec::new())
    }
    async fn get_decision(&self, _decision_id: &str) -> PersistenceResult<Option<Value>> {
        Ok(None)
    }
    /// Mark a decision as lifted (used when an appeal verdict=overturn
    /// is paired with `ak.moderation.decision.lift`). Stores the lift
    /// record verbatim; readers MUST join against `list_decisions` to
    /// determine the current active state.
    async fn append_decision_lift(&self, _lift: Value) -> PersistenceResult<()> {
        Err(PersistenceError::Internal(
            "moderation decision lift not wired in this backend".to_owned(),
        ))
    }

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

    /// Append an appeal event. `payload` MUST carry `appeal_id`,
    /// `realm_id`, and the variant-specific fields (see
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
