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
    #[diesel(sql_type = Nullable<Text>)]
    source_ref: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    strand_id: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    track_name: Option<String>,
    #[diesel(sql_type = Text)]
    notification_type: String,
    #[diesel(sql_type = Nullable<Text>)]
    event_kind: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    source_actor_id: Option<String>,
    #[diesel(sql_type = Text)]
    priority: String,
    #[diesel(sql_type = Text)]
    state: String,
    #[diesel(sql_type = Nullable<Jsonb>)]
    preview: Option<Value>,
    #[diesel(sql_type = Timestamptz)]
    created_at: chrono::DateTime<chrono::Utc>,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    updated_at: Option<chrono::DateTime<chrono::Utc>>,
}

impl From<NotificationRow> for Value {
    fn from(row: NotificationRow) -> Self {
        serde_json::json!({
            "notification_id": ids::format_typed_uuid("notification", &row.notification_id),
            "recipient_id": row.recipient_id,
            "realm_id": ids::format_typed_uuid("realm", &row.realm_id),
            "source_event_id": row.source_event_id,
            "source_ref": row.source_ref,
            "strand_id": row.strand_id,
            "track_name": row.track_name,
            "notification_type": row.notification_type,
            "event_kind": row.event_kind,
            "source_actor_id": row.source_actor_id,
            "priority": row.priority,
            "state": row.state,
            "preview": row.preview,
            "created_at": row.created_at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            "updated_at": row.updated_at.map(|ts| {
                ts.to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
            }),
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
        let get_opt_str = |key: &str| -> Option<String> {
            record
                .get(key)
                .and_then(Value::as_str)
                .filter(|value| !value.trim().is_empty())
                .map(ToOwned::to_owned)
        };
        let source_ref = get_opt_str("source_ref");
        let strand_id = get_opt_str("strand_id");
        let track_name = get_opt_str("track_name");
        let event_kind = get_opt_str("event_kind");
        let source_actor_id = get_opt_str("source_actor_id");
        let priority = get_opt_str("priority").unwrap_or_else(|| "normal".to_owned());
        let state = get_opt_str("state").unwrap_or_else(|| "unread".to_owned());
        let preview = record
            .get("preview")
            .cloned()
            .filter(|value| !value.is_null());
        sql_query(
            "INSERT INTO notifications \
             (id, recipient_id, realm_id, source_event_id, source_ref, strand_id, track_name, \
              notification_type, event_kind, source_actor_id, priority, state, preview, \
              created_at, updated_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, NOW(), NOW()) \
             ON CONFLICT (recipient_id, source_event_id, notification_type) DO UPDATE SET \
              source_ref = EXCLUDED.source_ref, \
              strand_id = EXCLUDED.strand_id, \
              track_name = EXCLUDED.track_name, \
              event_kind = EXCLUDED.event_kind, \
              source_actor_id = EXCLUDED.source_actor_id, \
              priority = EXCLUDED.priority, \
              state = EXCLUDED.state, \
              preview = EXCLUDED.preview, \
              updated_at = NOW()",
        )
        .bind::<SqlUuid, _>(ids::typed_uuid_part_expect_internal(&notification_id))
        .bind::<Text, _>(&recipient_id)
        .bind::<SqlUuid, _>(ids::typed_uuid_part_expect_internal(&realm_id))
        .bind::<Text, _>(&source_event_id)
        .bind::<Nullable<Text>, _>(source_ref.as_deref())
        .bind::<Nullable<Text>, _>(strand_id.as_deref())
        .bind::<Nullable<Text>, _>(track_name.as_deref())
        .bind::<Text, _>(&notification_type)
        .bind::<Nullable<Text>, _>(event_kind.as_deref())
        .bind::<Nullable<Text>, _>(source_actor_id.as_deref())
        .bind::<Text, _>(&priority)
        .bind::<Text, _>(&state)
        .bind::<Nullable<Jsonb>, _>(preview.as_ref())
        .execute(&mut *conn)
        .await
        .map(|_| ())
        .map_err(PersistenceError::from)
    }

    async fn list_for_recipient(&self, recipient_id: &str) -> PersistenceResult<Vec<Value>> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "SELECT id AS notification_id, recipient_id, realm_id, source_event_id, source_ref, \
             strand_id, track_name, notification_type, event_kind, source_actor_id, priority, \
             state, preview, created_at, updated_at \
             FROM notifications WHERE recipient_id = $1 ORDER BY created_at DESC",
        )
        .bind::<Text, _>(recipient_id)
        .load::<NotificationRow>(&mut *conn)
        .await
        .map(|rows| rows.into_iter().map(Value::from).collect())
        .map_err(PersistenceError::from)
    }
}
