use super::*;

/// CKP-0016 §9.4.5 — per-recipient notification projection (mention
/// fanout output). Native agents are gated by their effective
/// accept_third_party_mention bit before a row is written here.
#[async_trait]
pub trait NotificationStore: Send + Sync {
    async fn put(&self, record: Value) -> PersistenceResult<()>;
    async fn list_for_recipient(&self, recipient_id: &str) -> PersistenceResult<Vec<Value>>;
}

#[derive(Default)]
pub(crate) struct MemoryNotificationStore {
    data: Mutex<Vec<Value>>,
}

impl MemoryNotificationStore {
    pub(crate) fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl NotificationStore for MemoryNotificationStore {
    async fn put(&self, record: Value) -> PersistenceResult<()> {
        self.data.lock().push(record);
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
}

#[derive(QueryableByName)]
struct NotificationRow {
    #[diesel(sql_type = SqlUuid)]
    notification_id: Uuid,
    #[diesel(sql_type = Text)]
    recipient_id: String,
    #[diesel(sql_type = SqlUuid)]
    realm_id: Uuid,
    #[diesel(sql_type = Text)]
    source_event_id: String,
    #[diesel(sql_type = Text)]
    notification_type: String,
    #[diesel(sql_type = Timestamptz)]
    created_at: chrono::DateTime<chrono::Utc>,
}

impl From<NotificationRow> for Value {
    fn from(row: NotificationRow) -> Self {
        serde_json::json!({
            "notification_id": ids::format_typed_uuid("notification", &row.notification_id),
            "recipient_id": row.recipient_id,
            "realm_id": ids::format_typed_uuid("realm", &row.realm_id),
            "source_event_id": row.source_event_id,
            "notification_type": row.notification_type,
            "created_at": row.created_at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        })
    }
}

pub(crate) struct PgNotificationStore {
    pub(crate) pool: PgPool,
}

#[async_trait]
impl NotificationStore for PgNotificationStore {
    async fn put(&self, record: Value) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool).await?;
        let get_str = |key: &str| -> PersistenceResult<String> {
            record
                .get(key)
                .and_then(Value::as_str)
                .map(ToOwned::to_owned)
                .ok_or_else(|| {
                    PersistenceError::Internal(format!("notification record missing {key}"))
                })
        };
        let notification_id = get_str("notification_id")?;
        let recipient_id = get_str("recipient_id")?;
        let realm_id = get_str("realm_id")?;
        let source_event_id = get_str("source_event_id")?;
        let notification_type = get_str("notification_type")?;
        sql_query(
            "INSERT INTO notifications \
             (id, recipient_id, realm_id, source_event_id, notification_type, \
              created_at) \
             VALUES ($1, $2, $3, $4, $5, NOW()) \
             ON CONFLICT (id) DO NOTHING",
        )
        .bind::<SqlUuid, _>(ids::typed_uuid_part_expect_internal(&notification_id))
        .bind::<Text, _>(&recipient_id)
        .bind::<SqlUuid, _>(ids::typed_uuid_part_expect_internal(&realm_id))
        .bind::<Text, _>(&source_event_id)
        .bind::<Text, _>(&notification_type)
        .execute(&mut *conn)
        .await
        .map(|_| ())
        .map_err(PersistenceError::from)
    }

    async fn list_for_recipient(&self, recipient_id: &str) -> PersistenceResult<Vec<Value>> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "SELECT id AS notification_id, recipient_id, realm_id, source_event_id, notification_type, \
             created_at FROM notifications WHERE recipient_id = $1 ORDER BY created_at DESC",
        )
        .bind::<Text, _>(recipient_id)
        .load::<NotificationRow>(&mut *conn)
        .await
        .map(|rows| rows.into_iter().map(Value::from).collect())
        .map_err(PersistenceError::from)
    }
}
