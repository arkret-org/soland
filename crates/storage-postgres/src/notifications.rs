use arkret_models_collaboration::objects::read_receipts::{
    Notification, NotificationEventSource, NotificationSchema, NotificationSource,
    NotificationSourceRef,
};
use arkret_models_collaboration::sync_frames::account_sync::{NotificationData, NotificationDelta};
use arkret_wire::events::EventKind;
use arkret_wire::{DidCoreId, EventId, NotificationId, RealmId, StrandId};
use soland_storage::{
    AccountNotificationDeltaWrite, RecipientNotificationRecord, StoredAccountNotificationDelta,
};

use super::{
    BigInt, Jsonb, NotificationStore, Nullable, PersistenceError, PersistenceResult, PgPool,
    QueryableByName, RunQueryDsl, SqlUuid, Text, Timestamptz, Uuid, Value, async_trait, ids,
    pg_conn, sql_query,
};
#[derive(QueryableByName)]
struct NotificationRow {
    #[diesel(sql_type = SqlUuid)]
    notification_id: Uuid,
    #[diesel(sql_type = Text)]
    recipient_id: String,
    #[diesel(sql_type = Nullable<Text>)]
    realm_id: Option<String>,
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
    notification_kind: String,
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
impl NotificationRow {
    fn into_recipient_record(self) -> PersistenceResult<RecipientNotificationRecord> {
        let notification_kind = decode_enum("notification_kind", self.notification_kind)?;
        let priority = decode_enum("priority", self.priority)?;
        let state = decode_enum("state", self.state)?;
        let source_event_id = self
            .source_event_id
            .ok_or_else(|| {
                PersistenceError::Internal(
                    "recipient notification is missing source_event_id".to_owned(),
                )
            })
            .and_then(|value| {
                EventId::new(value).map_err(|error| {
                    PersistenceError::Internal(format!(
                        "recipient notification source_event_id is invalid: {error}"
                    ))
                })
            })?;
        let realm_id = self
            .realm_id
            .map(RealmId::new)
            .transpose()
            .map_err(|error| {
                PersistenceError::Internal(format!(
                    "recipient notification realm_id is invalid: {error}"
                ))
            })?;
        let strand_id = self
            .strand_id
            .map(StrandId::new)
            .transpose()
            .map_err(|error| {
                PersistenceError::Internal(format!(
                    "recipient notification strand_id is invalid: {error}"
                ))
            })?;
        let preview = self
            .preview
            .map(serde_json::from_value)
            .transpose()
            .map_err(|error| {
                PersistenceError::Internal(format!(
                    "recipient notification preview is invalid: {error}"
                ))
            })?;
        let notification = Notification {
            id: NotificationId::new(ids::format_typed_uuid(
                "notification",
                &self.notification_id,
            ))
            .map_err(|error| {
                PersistenceError::Internal(format!("recipient notification id is invalid: {error}"))
            })?,
            schema: NotificationSchema::V1,
            actor_id: DidCoreId::new(self.recipient_id).map_err(|error| {
                PersistenceError::Internal(format!(
                    "recipient notification actor_id is invalid: {error}"
                ))
            })?,
            source: NotificationSource::Event(NotificationEventSource {
                source_event_id,
                realm_id,
                source_ref: self
                    .source_ref
                    .map(NotificationSourceRef::new)
                    .transpose()
                    .map_err(|error| {
                        PersistenceError::Internal(format!(
                            "recipient notification source_ref is invalid: {error}"
                        ))
                    })?,
                strand_id,
                track_name: self.track_name,
            }),
            notification_kind,
            priority,
            state,
            preview,
            created_at: self.created_at,
            updated_at: self.updated_at,
        };
        notification.validate().map_err(|error| {
            PersistenceError::Internal(format!(
                "recipient notification projection is invalid: {error}"
            ))
        })?;
        let event_kind = self
            .event_kind
            .as_deref()
            .and_then(EventKind::try_new)
            .ok_or_else(|| {
                PersistenceError::Internal(
                    "recipient notification event_kind is invalid".to_owned(),
                )
            })?;
        let source_actor_id = self
            .source_actor_id
            .map(DidCoreId::new)
            .transpose()
            .map_err(|error| {
                PersistenceError::Internal(format!(
                    "recipient notification source_actor_id is invalid: {error}"
                ))
            })?;
        Ok(RecipientNotificationRecord {
            notification,
            event_kind,
            source_actor_id,
        })
    }

    fn into_account_record(self) -> PersistenceResult<StoredAccountNotificationDelta> {
        if self.source_account_artifact_kind.as_deref() != Some("agent_runtime_approval") {
            return Err(PersistenceError::Internal(
                "account notification artifact kind is invalid".to_owned(),
            ));
        }
        let action = self.projection_action.ok_or_else(|| {
            PersistenceError::Internal(
                "account notification is missing projection_action".to_owned(),
            )
        })?;
        let action = decode_enum("projection_action", action)?;
        let data = self
            .projection_data
            .map(serde_json::from_value::<NotificationData>)
            .transpose()
            .map_err(|error| {
                PersistenceError::Internal(format!(
                    "account notification projection_data is invalid: {error}"
                ))
            })?;
        let delta = NotificationDelta::try_new(
            NotificationId::new(ids::format_typed_uuid(
                "notification",
                &self.notification_id,
            ))
            .map_err(|error| {
                PersistenceError::Internal(format!("account notification id is invalid: {error}"))
            })?,
            decode_enum("notification_kind", self.notification_kind)?,
            action,
            data,
        )
        .map_err(|error| {
            PersistenceError::Internal(format!("account notification delta is invalid: {error}"))
        })?;
        let controller_account_id = self.controller_account_id.ok_or_else(|| {
            PersistenceError::Internal(
                "account notification is missing controller_account_id".to_owned(),
            )
        })?;
        let recipient_service_id = self.recipient_service_id.ok_or_else(|| {
            PersistenceError::Internal(
                "account notification is missing recipient_service_id".to_owned(),
            )
        })?;
        let source_account_artifact_id = self.source_account_artifact_id.ok_or_else(|| {
            PersistenceError::Internal(
                "account notification is missing source_account_artifact_id".to_owned(),
            )
        })?;
        Ok(StoredAccountNotificationDelta {
            record: AccountNotificationDeltaWrite {
                delta,
                recipient_id: DidCoreId::new(self.recipient_id).map_err(|error| {
                    PersistenceError::Internal(format!(
                        "account notification recipient_id is invalid: {error}"
                    ))
                })?,
                controller_account_id: ids::format_typed_uuid("account", &controller_account_id),
                recipient_service_id: DidCoreId::new(recipient_service_id).map_err(|error| {
                    PersistenceError::Internal(format!(
                        "account notification recipient_service_id is invalid: {error}"
                    ))
                })?,
                source_account_artifact_id,
            },
            projection_position: self.projection_position,
        })
    }
}

fn decode_enum<T>(field: &str, value: String) -> PersistenceResult<T>
where
    T: serde::de::DeserializeOwned,
{
    serde_json::from_value(Value::String(value)).map_err(|error| {
        PersistenceError::Internal(format!("notification {field} is invalid: {error}"))
    })
}
pub struct PgNotificationStore {
    pub pool: PgPool,
}
#[async_trait]
impl NotificationStore for PgNotificationStore {
    async fn put(&self, record: RecipientNotificationRecord) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        record.notification.validate().map_err(|error| {
            PersistenceError::Internal(format!("notification record is invalid: {error}"))
        })?;
        let NotificationSource::Event(source) = &record.notification.source else {
            return Err(PersistenceError::Internal(
                "recipient notification must have an Event source".to_owned(),
            ));
        };
        let realm_id = source.realm_id.as_ref().map(RealmId::as_str);
        crate::realm_identity::ensure_optional_realm_pk(&mut conn, realm_id).await?;
        let preview = record
            .notification
            .preview
            .as_ref()
            .map(serde_json::to_value)
            .transpose()
            .map_err(|error| {
                PersistenceError::Internal(format!(
                    "notification preview serialization failed: {error}"
                ))
            })?;
        let notification_kind =
            encode_enum("notification_kind", &record.notification.notification_kind)?;
        let priority = encode_enum("priority", &record.notification.priority)?;
        let state = encode_enum("state", &record.notification.state)?;
        sql_query(
            "INSERT INTO notifications \
             (id, recipient_id, realm_id, source_event_id, source_ref, strand_id, track_name, \
              notification_kind, event_kind, source_actor_id, priority, state, preview, \
              created_at, updated_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15) \
             ON CONFLICT (recipient_id, source_event_id, notification_kind) DO UPDATE SET \
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
        .bind::<SqlUuid, _>(ids::typed_uuid_part_expect_internal(
            record.notification.id.as_str(),
        ))
        .bind::<Text, _>(record.notification.actor_id.as_str())
        .bind::<Nullable<Text>, _>(realm_id)
        .bind::<Text, _>(source.source_event_id.as_str())
        .bind::<Nullable<Text>, _>(
            source
                .source_ref
                .as_ref()
                .map(NotificationSourceRef::as_str),
        )
        .bind::<Nullable<Text>, _>(source.strand_id.as_ref().map(StrandId::as_str))
        .bind::<Nullable<Text>, _>(source.track_name.as_deref())
        .bind::<Text, _>(&notification_kind)
        .bind::<Nullable<Text>, _>(Some(record.event_kind.as_str()))
        .bind::<Nullable<Text>, _>(record.source_actor_id.as_ref().map(DidCoreId::as_str))
        .bind::<Text, _>(&priority)
        .bind::<Text, _>(&state)
        .bind::<Nullable<Jsonb>, _>(preview.as_ref())
        .bind::<Timestamptz, _>(record.notification.created_at)
        .bind::<Nullable<Timestamptz>, _>(record.notification.updated_at)
        .execute(&mut *conn)
        .await
        .map(|_| ())
        .map_err(PersistenceError::database)
    }

    async fn put_account_delta(
        &self,
        record: AccountNotificationDeltaWrite,
    ) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        record.delta.validate_shape().map_err(|error| {
            PersistenceError::Internal(format!("account notification delta is invalid: {error}"))
        })?;
        let action = encode_enum("projection_action", &record.delta.action)?;
        let notification_kind = encode_enum("notification_kind", &record.delta.notification_kind)?;
        let data = record
            .delta
            .data
            .as_ref()
            .map(serde_json::to_value)
            .transpose()
            .map_err(|error| {
                PersistenceError::Internal(format!(
                    "account notification data serialization failed: {error}"
                ))
            })?;
        sql_query(
            "INSERT INTO notifications \
             (id, recipient_id, controller_account_id, recipient_service_id, \
              source_account_artifact_kind, source_account_artifact_id, notification_kind, \
              priority, state, projection_action, projection_data, created_at, updated_at) \
             VALUES ($1, $2, $3, $4, 'agent_runtime_approval', $5, $6, \
              'normal', 'unread', $7, $8, NOW(), NOW()) \
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
        .bind::<SqlUuid, _>(ids::typed_uuid_part_expect_internal(
            record.delta.id.as_str(),
        ))
        .bind::<Text, _>(record.recipient_id.as_str())
        .bind::<SqlUuid, _>(ids::typed_uuid_part_expect_internal(
            &record.controller_account_id,
        ))
        .bind::<Text, _>(record.recipient_service_id.as_str())
        .bind::<Text, _>(&record.source_account_artifact_id)
        .bind::<Text, _>(&notification_kind)
        .bind::<Text, _>(&action)
        .bind::<Nullable<Jsonb>, _>(data.as_ref())
        .execute(&mut *conn)
        .await
        .map(|_| ())
        .map_err(PersistenceError::database)
    }

    async fn list_for_recipient(
        &self,
        recipient_id: &str,
    ) -> PersistenceResult<Vec<RecipientNotificationRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(
            "SELECT id AS notification_id, recipient_id, realm_id, source_event_id, \
             controller_account_id, recipient_service_id, source_account_artifact_kind, \
             source_account_artifact_id, source_ref, \
             strand_id, track_name, notification_kind, event_kind, source_actor_id, priority, \
             state, preview, projection_action, projection_data, projection_position, \
             created_at, updated_at \
             FROM notifications WHERE recipient_id = $1 ORDER BY created_at DESC",
        )
        .bind::<Text, _>(recipient_id)
        .load::<NotificationRow>(&mut *conn)
        .await
        .map_err(PersistenceError::database)?
        .into_iter()
        .map(NotificationRow::into_recipient_record)
        .collect()
    }

    async fn list_for_account(
        &self,
        controller_account_id: &str,
        recipient_service_id: &str,
        after_position: Option<i64>,
    ) -> PersistenceResult<Vec<StoredAccountNotificationDelta>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(
            "SELECT id AS notification_id, recipient_id, realm_id, source_event_id, \
             controller_account_id, recipient_service_id, source_account_artifact_kind, \
             source_account_artifact_id, source_ref, strand_id, track_name, notification_kind, \
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
        .map_err(PersistenceError::database)?
        .into_iter()
        .map(NotificationRow::into_account_record)
        .collect()
    }
}

fn encode_enum<T>(field: &str, value: &T) -> PersistenceResult<String>
where
    T: serde::Serialize,
{
    serde_json::to_value(value)
        .map_err(|error| {
            PersistenceError::Internal(format!(
                "notification {field} serialization failed: {error}"
            ))
        })?
        .as_str()
        .map(ToOwned::to_owned)
        .ok_or_else(|| {
            PersistenceError::Internal(format!(
                "notification {field} did not serialize as a string"
            ))
        })
}
