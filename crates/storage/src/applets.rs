use super::{PersistenceResult, Value, async_trait};
#[async_trait]
pub trait AppletStore: Send + Sync {
    async fn get_identity(
        &self,
        applet_id: &str,
        target_principal_server_id: &str,
    ) -> PersistenceResult<Option<Value>>;
    async fn get(
        &self,
        applet_id: &str,
        effective_scope_key: &str,
    ) -> PersistenceResult<Option<Value>>;
    async fn compare_and_swap(
        &self,
        applet_id: &str,
        effective_scope_key: &str,
        expected: &Value,
        replacement: Value,
    ) -> PersistenceResult<bool>;
    /// Atomically fences one exact installation and, iff it was the final
    /// active scope, stamps the independent managed-identity winner.
    async fn fence_installation(
        &self,
        applet_id: &str,
        effective_scope_key: &str,
        target_principal_server_id: &str,
        expected: &Value,
        replacement: Value,
        fenced_at: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<AppletInstallationFenceOutcome>;
    async fn list(&self) -> PersistenceResult<Vec<Value>>;
    async fn begin_transaction_replay(
        &self,
        record: AppletTransactionReplayRecord,
    ) -> PersistenceResult<AppletTransactionReplayBegin>;
    async fn complete_transaction_replay(
        &self,
        applet_id: &str,
        source_id: &str,
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

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AppletInstallationFenceOutcome {
    pub updated: bool,
    pub globally_fenced: bool,
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
    pub source_id: String,
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
    format!("SELECT record FROM applet_installations {suffix}")
}
#[doc(hidden)]
pub fn applet_transaction_replay_select_sql() -> &'static str {
    "SELECT applet_id, source_id, idempotency_key, delivery_authentication_record_digest, request_digest, \
     outcome, received_at, completed_at \
     FROM applet_transactions \
     WHERE applet_id = $1 AND source_id = $2 AND idempotency_key = $3"
}
