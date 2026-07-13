use super::*;

/// AKP-0016 §9.4.5 — per-recipient notification projection (mention
/// fanout output). Native agents are gated by their effective
/// accept_third_party_mention bit before a row is written here.
#[async_trait]
pub trait NotificationStore: Send + Sync {
    async fn put(&self, record: Value) -> PersistenceResult<()>;
    async fn put_account_delta(&self, record: Value) -> PersistenceResult<()>;
    async fn list_for_recipient(&self, recipient_id: &str) -> PersistenceResult<Vec<Value>>;
    async fn list_for_account(
        &self,
        controller_account_id: &str,
        recipient_service_id: &str,
        after_position: Option<i64>,
    ) -> PersistenceResult<Vec<Value>>;
}

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

#[derive(QueryableByName)]
struct NotificationRow {
    #[diesel(sql_type = SqlUuid)]
    notification_id: Uuid,
    #[diesel(sql_type = Text)]
    recipient_id: String,
    #[diesel(sql_type = Nullable<SqlUuid>)]
    realm_id: Option<Uuid>,
    #[diesel(sql_type = Nullable<Text>)]
    source_event_id: Option<String>,
    #[diesel(sql_type = Nullable<SqlUuid>)]
    controller_account_id: Option<Uuid>,
    #[diesel(sql_type = Nullable<Text>)]
    recipient_service_id: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    source_account_artifact_kind: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    source_account_artifact_id: Option<String>,
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
    #[diesel(sql_type = Nullable<Text>)]
    projection_action: Option<String>,
    #[diesel(sql_type = Nullable<Jsonb>)]
    projection_data: Option<Value>,
    #[diesel(sql_type = BigInt)]
    projection_position: i64,
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
            "realm_id": row.realm_id.map(|id| ids::format_typed_uuid("realm", &id)),
            "source_event_id": row.source_event_id,
            "controller_account_id": row.controller_account_id.map(|id| ids::format_typed_uuid("account", &id)),
            "recipient_service_id": row.recipient_service_id,
            "source_account_artifact_kind": row.source_account_artifact_kind,
            "source_account_artifact_id": row.source_account_artifact_id,
            "source_ref": row.source_ref,
            "strand_id": row.strand_id,
            "track_name": row.track_name,
            "notification_type": row.notification_type,
            "event_kind": row.event_kind,
            "source_actor_id": row.source_actor_id,
            "priority": row.priority,
            "state": row.state,
            "preview": row.preview,
            "projection_action": row.projection_action,
            "projection_data": row.projection_data,
            "projection_position": row.projection_position,
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
              projection_position = nextval('notification_projection_position_seq'), \
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

    async fn put_account_delta(&self, record: Value) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool).await?;
        let required = |key: &str| -> PersistenceResult<String> {
            record
                .get(key)
                .and_then(Value::as_str)
                .map(ToOwned::to_owned)
                .ok_or_else(|| {
                    PersistenceError::Internal(format!("account notification missing {key}"))
                })
        };
        let notification_id = required("notification_id")?;
        let recipient_id = required("recipient_id")?;
        let controller_account_id = required("controller_account_id")?;
        let recipient_service_id = required("recipient_service_id")?;
        let artifact_id = required("source_account_artifact_id")?;
        let action = required("projection_action")?;
        let data = record
            .get("projection_data")
            .cloned()
            .filter(|value| !value.is_null());
        sql_query(
            "INSERT INTO notifications \
             (id, recipient_id, controller_account_id, recipient_service_id, \
              source_account_artifact_kind, source_account_artifact_id, notification_type, \
              priority, state, projection_action, projection_data, created_at, updated_at) \
             VALUES ($1, $2, $3, $4, 'agent_runtime_approval', $5, 'agent', \
              'normal', 'unread', $6, $7, NOW(), NOW()) \
             ON CONFLICT (controller_account_id, recipient_service_id, \
              source_account_artifact_kind, source_account_artifact_id) \
              WHERE controller_account_id IS NOT NULL DO UPDATE SET \
              projection_action = EXCLUDED.projection_action, \
              projection_data = EXCLUDED.projection_data, \
              projection_position = CASE \
                WHEN notifications.projection_action IS DISTINCT FROM EXCLUDED.projection_action \
                  OR notifications.projection_data IS DISTINCT FROM EXCLUDED.projection_data \
                THEN nextval('notification_projection_position_seq') \
                ELSE notifications.projection_position \
              END, \
              updated_at = NOW()",
        )
        .bind::<SqlUuid, _>(ids::typed_uuid_part_expect_internal(&notification_id))
        .bind::<Text, _>(&recipient_id)
        .bind::<SqlUuid, _>(ids::typed_uuid_part_expect_internal(&controller_account_id))
        .bind::<Text, _>(&recipient_service_id)
        .bind::<Text, _>(&artifact_id)
        .bind::<Text, _>(&action)
        .bind::<Nullable<Jsonb>, _>(data.as_ref())
        .execute(&mut *conn)
        .await
        .map(|_| ())
        .map_err(PersistenceError::from)
    }

    async fn list_for_recipient(&self, recipient_id: &str) -> PersistenceResult<Vec<Value>> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "SELECT id AS notification_id, recipient_id, realm_id, source_event_id, \
             controller_account_id, recipient_service_id, source_account_artifact_kind, \
             source_account_artifact_id, source_ref, \
             strand_id, track_name, notification_type, event_kind, source_actor_id, priority, \
             state, preview, projection_action, projection_data, projection_position, \
             created_at, updated_at \
             FROM notifications WHERE recipient_id = $1 ORDER BY created_at DESC",
        )
        .bind::<Text, _>(recipient_id)
        .load::<NotificationRow>(&mut *conn)
        .await
        .map(|rows| rows.into_iter().map(Value::from).collect())
        .map_err(PersistenceError::from)
    }

    async fn list_for_account(
        &self,
        controller_account_id: &str,
        recipient_service_id: &str,
        after_position: Option<i64>,
    ) -> PersistenceResult<Vec<Value>> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "SELECT id AS notification_id, recipient_id, realm_id, source_event_id, \
             controller_account_id, recipient_service_id, source_account_artifact_kind, \
             source_account_artifact_id, source_ref, strand_id, track_name, notification_type, \
             event_kind, source_actor_id, priority, state, preview, projection_action, \
             projection_data, projection_position, created_at, updated_at \
             FROM notifications \
             WHERE controller_account_id = $1 AND recipient_service_id = $2 \
               AND ($3 IS NULL OR projection_position > $3) \
             ORDER BY projection_position",
        )
        .bind::<SqlUuid, _>(ids::typed_uuid_part_expect_internal(controller_account_id))
        .bind::<Text, _>(recipient_service_id)
        .bind::<Nullable<BigInt>, _>(after_position)
        .load::<NotificationRow>(&mut *conn)
        .await
        .map(|rows| rows.into_iter().map(Value::from).collect())
        .map_err(PersistenceError::from)
    }
}
