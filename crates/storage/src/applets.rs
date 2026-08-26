use super::{PersistenceResult, Value, async_trait};
#[async_trait]
pub trait AppletStore: Send + Sync {
    async fn get(&self, applet_id: &str) -> PersistenceResult<Option<Value>>;
    async fn compare_and_swap(
        &self,
        applet_id: &str,
        expected: &Value,
        replacement: Value,
    ) -> PersistenceResult<bool>;
    async fn list(&self) -> PersistenceResult<Vec<Value>>;
    async fn begin_transaction_replay(
        &self,
        record: AppletTransactionReplayRecord,
    ) -> PersistenceResult<AppletTransactionReplayBegin>;
    async fn complete_transaction_replay(
        &self,
        applet_id: &str,
        source_service_id: &str,
        idempotency_key: &str,
        outcome: Value,
    ) -> PersistenceResult<()>;
    async fn issue_authoring_preview(
        &self,
        candidate: AppletAuthoringPreviewRecord,
    ) -> PersistenceResult<AppletAuthoringPreviewRecord>;
    async fn current_authoring_preview(
        &self,
        subject_key: &str,
    ) -> PersistenceResult<Option<AppletAuthoringPreviewRecord>>;
}

#[derive(Clone, Debug)]
pub struct AppletAuthoringPreviewRecord {
    pub subject_key: String,
    pub basis_digest: String,
    pub request_digest: String,
    pub signed_request: Value,
    pub issued_at: chrono::DateTime<chrono::Utc>,
    pub expires_at: chrono::DateTime<chrono::Utc>,
}
#[derive(Clone, Debug)]
pub struct AppletTransactionReplayRecord {
    pub applet_id: arkret_wire::AppletId,
    pub source_service_id: String,
    pub idempotency_key: String,
    pub delivery_authentication_record_digest: String,
    pub request_digest: String,
    pub outcome: Option<Value>,
    pub received_at: chrono::DateTime<chrono::Utc>,
    pub completed_at: Option<chrono::DateTime<chrono::Utc>>,
}
#[derive(Clone, Debug)]
pub enum AppletTransactionReplayBegin {
    Fresh,
    Existing(AppletTransactionReplayRecord),
}
#[doc(hidden)]
pub fn applet_registration_select_sql(suffix: &str) -> String {
    format!("SELECT record FROM applet_registrations {suffix}")
}
#[doc(hidden)]
pub fn applet_transaction_replay_select_sql() -> &'static str {
    "SELECT applet_id, source_service_id, idempotency_key, delivery_authentication_record_digest, request_digest, \
     outcome, received_at, completed_at \
     FROM applet_transactions \
     WHERE applet_id = $1 AND source_service_id = $2 AND idempotency_key = $3"
}
