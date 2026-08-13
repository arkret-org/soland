use super::{PersistenceError, PersistenceResult, Value, async_trait};
#[async_trait]
pub trait AppletStore: Send + Sync {
    async fn get(&self, applet_id: &str) -> PersistenceResult<Option<Value>>;
    async fn put(&self, applet_id: &str, record: Value) -> PersistenceResult<()>;
    async fn list(&self) -> PersistenceResult<Vec<Value>>;
    async fn begin_transaction_replay(
        &self,
        record: AppletTransactionReplayRecord,
    ) -> PersistenceResult<AppletTransactionReplayBegin>;
    async fn complete_transaction_replay(
        &self,
        source_service_id: &str,
        idempotency_key: &str,
        outcome: Value,
    ) -> PersistenceResult<()>;
}
#[derive(Clone, Debug)]
pub struct AppletTransactionReplayRecord {
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
    format!(
        "SELECT id, namespace, owner_actor_id, registry_did, bot_actor_id, portal_realm_id, \
         capabilities, manifest, package, namespaces, ghost_actors_allowed, status, \
         registered_at, revoked_at, idempotency_key, install_body_digest, install_id, \
         install_response, install_execution, ghosts FROM applet_registrations {suffix}"
    )
}
#[doc(hidden)]
pub fn applet_transaction_replay_select_sql() -> &'static str {
    "SELECT source_service_id, idempotency_key, delivery_authentication_record_digest, request_digest, \
     outcome, received_at, completed_at \
     FROM applet_transactions \
     WHERE source_service_id = $1 AND idempotency_key = $2"
}
#[doc(hidden)]
pub fn required_record_str(record: &Value, key: &str) -> PersistenceResult<String> {
    record
        .get(key)
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .ok_or_else(|| PersistenceError::Internal(format!("applet record missing {key}")))
}
#[doc(hidden)]
pub fn optional_record_str(record: &Value, key: &str) -> Option<String> {
    record
        .get(key)
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
}
#[doc(hidden)]
pub fn optional_record_value(record: &Value, key: &str) -> Option<Value> {
    record.get(key).filter(|value| !value.is_null()).cloned()
}
#[doc(hidden)]
pub fn required_record_timestamp(
    record: &Value,
    key: &str,
) -> PersistenceResult<chrono::DateTime<chrono::Utc>> {
    let value = record
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| PersistenceError::Internal(format!("applet record missing {key}")))?;
    parse_record_timestamp(value, key)
}
#[doc(hidden)]
pub fn optional_record_timestamp(
    record: &Value,
    key: &str,
) -> PersistenceResult<Option<chrono::DateTime<chrono::Utc>>> {
    record
        .get(key)
        .filter(|value| !value.is_null())
        .and_then(Value::as_str)
        .map(|value| parse_record_timestamp(value, key))
        .transpose()
}
#[doc(hidden)]
pub fn parse_record_timestamp(
    value: &str,
    key: &str,
) -> PersistenceResult<chrono::DateTime<chrono::Utc>> {
    chrono::DateTime::parse_from_rfc3339(value)
        .map(|dt| dt.with_timezone(&chrono::Utc))
        .map_err(|error| {
            PersistenceError::Internal(format!("applet record {key} timestamp invalid: {error}"))
        })
}
