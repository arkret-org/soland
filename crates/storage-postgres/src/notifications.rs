use arkret_models_collaboration::objects::read_receipts::{
    Notification, NotificationEventSource, NotificationIdentity, NotificationSchema,
    NotificationSource, NotificationSourceRef, OrdinaryProjectionContent,
};
use arkret_models_collaboration::sync_frames::account_subscribe::{
    NotificationData, NotificationDelta, NotificationDeltaAction,
};
use arkret_wire::events::EventKind;
use arkret_wire::{
    ActorId, DidCoreId, EventId, NotificationId, NotificationKind, RealmId, StrandId,
};
use soland_storage::{
    AccountNotificationDeltaWrite, AccountPk, RecipientNotificationRecord,
    StoredAccountNotificationDelta,
};

use super::{
    BigInt, Jsonb, NotificationStore, Nullable, PersistenceError, PersistenceResult, PgPool,
    QueryableByName, RunQueryDsl, Text, Timestamptz, Uuid, Value, async_trait, ids, pg_conn,
    sql_query, sql_types,
};
#[derive(QueryableByName, serde::Deserialize)]
struct NotificationRow {
    #[diesel(sql_type = sql_types::Uuid)]
    notification_id: Uuid,
    #[diesel(sql_type = Nullable<Text>)]
    projection_id: Option<String>,
    #[diesel(sql_type = Text)]
    recipient_actor_id: String,
    #[diesel(sql_type = Nullable<Text>)]
    realm_id: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    source_event_id: Option<String>,
    #[diesel(sql_type = Nullable<BigInt>)]
    controller_account_pk: Option<i64>,
    #[diesel(sql_type = Nullable<Text>)]
    recipient_id: Option<DidCoreId>,
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
    #[diesel(sql_type = Nullable<Text>)]
    notification_kind: Option<String>,
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
        let notification_kind: NotificationKind = self
            .notification_kind
            .ok_or_else(|| {
                PersistenceError::Internal(
                    "recipient notification is missing notification_kind".to_owned(),
                )
            })
            .and_then(|value| decode_enum("notification_kind", value))?;
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
        let actor_id: ActorId =
            serde_json::from_str(&self.recipient_actor_id).map_err(|error| {
                PersistenceError::Internal(format!(
                    "recipient notification actor_id is invalid: {error}"
                ))
            })?;
        let id =
            arkret_models_collaboration::objects::read_receipts::derive_notification_projection_id(
                actor_id.as_account_id().ok_or_else(|| {
                    PersistenceError::Internal(
                        "notification recipient must be an account".to_owned(),
                    )
                })?,
                realm_id.as_ref().ok_or_else(|| {
                    PersistenceError::Internal("notification source Realm is missing".to_owned())
                })?,
                &source_event_id,
                arkret_wire::OrdinaryNotificationKind::try_from(&notification_kind)
                    .map_err(|error| PersistenceError::Internal(error.to_string()))?,
            )
            .map_err(|error| PersistenceError::Internal(error.to_string()))?;
        let notification = Notification {
            id: id.into(),
            schema: NotificationSchema::V1,
            actor_id,
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
            .map(|value| serde_json::from_str::<ActorId>(&value))
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

    fn into_delta(&self) -> PersistenceResult<NotificationDelta> {
        let action = self.projection_action.as_ref().ok_or_else(|| {
            PersistenceError::Internal(
                "account notification is missing projection_action".to_owned(),
            )
        })?;
        let action: NotificationDeltaAction = decode_enum("projection_action", action.clone())?;
        // The `id` form is the only discriminator between the two notification
        // branches, and `expired`/`superseded` appear in both removal
        // vocabularies. Decode the stored payload into the branch the id
        // selects rather than letting an untagged decoder pick, or an ordinary
        // removal reason lands on an Agent approval row.
        let id = if let Some(projection_id) = self.projection_id.as_ref() {
            NotificationIdentity::new(projection_id.clone())
        } else {
            NotificationIdentity::new(ids::format_typed_uuid(
                "notification",
                &self.notification_id,
            ))
        }
        .map_err(|error| {
            PersistenceError::Internal(format!("account notification id is invalid: {error}"))
        })?;
        let data = match (&id, action, self.projection_data.clone()) {
            (_, _, None) | (_, _, Some(Value::Null)) => None,
            (NotificationIdentity::Projection(_), NotificationDeltaAction::Upsert, Some(value)) => {
                Some(NotificationData::OrdinaryProjection(Box::new(
                    decode_notification_data(value)?,
                )))
            }
            (NotificationIdentity::Projection(_), NotificationDeltaAction::Remove, Some(value)) => {
                Some(NotificationData::OrdinaryRemoval(decode_notification_data(
                    value,
                )?))
            }
            (
                NotificationIdentity::AgentApproval(_),
                NotificationDeltaAction::Upsert,
                Some(value),
            ) => Some(NotificationData::AgentRuntimeApproval(
                decode_notification_data(value)?,
            )),
            (
                NotificationIdentity::AgentApproval(_),
                NotificationDeltaAction::Remove,
                Some(value),
            ) => Some(NotificationData::AgentRuntimeApprovalRemoval(
                decode_notification_data(value)?,
            )),
        };
        NotificationDelta::try_new(id, action, data).map_err(|error| {
            PersistenceError::Internal(format!("account notification delta is invalid: {error}"))
        })
    }

    fn into_account_record(self) -> PersistenceResult<StoredAccountNotificationDelta> {
        if self.source_account_artifact_kind.as_deref() != Some("agent_runtime_approval") {
            return Err(PersistenceError::Internal(
                "account notification artifact kind is invalid".to_owned(),
            ));
        }
        let delta = self.into_delta()?;
        let controller_account_pk = self.controller_account_pk.ok_or_else(|| {
            PersistenceError::Internal(
                "account notification is missing controller_account_pk".to_owned(),
            )
        })?;
        let recipient_id = self.recipient_id.ok_or_else(|| {
            PersistenceError::Internal("account notification is missing recipient_id".to_owned())
        })?;
        let source_account_artifact_id = self.source_account_artifact_id.ok_or_else(|| {
            PersistenceError::Internal(
                "account notification is missing source_account_artifact_id".to_owned(),
            )
        })?;
        let recipient_actor_id = serde_json::from_str::<ActorId>(&self.recipient_actor_id)
            .map_err(|error| {
                PersistenceError::Internal(format!(
                    "account notification recipient_actor_id is invalid: {error}"
                ))
            })?;
        Ok(StoredAccountNotificationDelta {
            record: AccountNotificationDeltaWrite {
                delta,
                recipient_actor_id,
                controller_account_pk: AccountPk(controller_account_pk),
                recipient_id,
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
        let ordinary = OrdinaryProjectionContent {
            realm_id: source.realm_id.clone().ok_or_else(|| {
                PersistenceError::Internal("notification source Realm is missing".to_owned())
            })?,
            source_event_id: source.source_event_id.clone(),
            source_ref: source.source_ref.clone(),
            strand_id: source.strand_id.clone(),
            track_name: source.track_name.clone(),
            notification_kind: arkret_wire::OrdinaryNotificationKind::try_from(
                &record.notification.notification_kind,
            )
            .map_err(|error| PersistenceError::Internal(error.to_string()))?,
            priority: record.notification.priority,
            preview: record.notification.preview.clone(),
            created_at: record.notification.created_at,
            updated_at: record.notification.updated_at,
        };
        ordinary
            .validate()
            .map_err(|error| PersistenceError::Internal(error.to_string()))?;
        let projection_id = record.notification.id.as_str().to_owned();
        if !matches!(record.notification.id, NotificationIdentity::Projection(_)) {
            return Err(PersistenceError::Internal(
                "ordinary notification requires a projection identity".to_owned(),
            ));
        }
        let projection_data = serde_json::to_value(&ordinary).map_err(|error| {
            PersistenceError::Internal(format!(
                "ordinary notification projection serialization failed: {error}"
            ))
        })?;
        sql_query(
            "WITH written AS (INSERT INTO notifications \
             (id, projection_id, recipient_actor_id, realm_id, source_event_id, source_ref, strand_id, track_name, \
              notification_kind, event_kind, source_actor_id, priority, state, preview, \
              projection_action, projection_data, ordinary_projection_data, created_at, updated_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, 'upsert', $15, $15, $16, $17) \
             ON CONFLICT (recipient_actor_id, realm_id, source_event_id, notification_kind) \
              WHERE source_event_id IS NOT NULL DO UPDATE SET \
              projection_id = EXCLUDED.projection_id, \
              source_ref = EXCLUDED.source_ref, \
              strand_id = EXCLUDED.strand_id, \
              track_name = EXCLUDED.track_name, \
              event_kind = EXCLUDED.event_kind, \
              source_actor_id = EXCLUDED.source_actor_id, \
              priority = EXCLUDED.priority, \
              state = EXCLUDED.state, \
              preview = EXCLUDED.preview, \
              projection_action = EXCLUDED.projection_action, \
              projection_data = EXCLUDED.projection_data, \
              ordinary_projection_data = EXCLUDED.ordinary_projection_data, \
              projection_position = nextval('notification_projection_position_seq'), \
              updated_at = NOW() \
             RETURNING recipient_actor_id) \
             UPDATE notifications SET \
              projection_action = 'remove', \
              projection_data = jsonb_build_object('reason','expired'), \
              projection_position = nextval('notification_projection_position_seq'), \
              updated_at = NOW() \
             WHERE id IN (SELECT id FROM notifications \
              WHERE recipient_actor_id=(SELECT recipient_actor_id FROM written LIMIT 1) \
                AND projection_id IS NOT NULL AND projection_action='upsert' \
              ORDER BY created_at DESC, projection_id OFFSET 100)",
        )
        // This UUID is only the cache row key. The public identity is derived
        // from the complete source tuple when reading the row.
        .bind::<sql_types::Uuid, _>(Uuid::now_v7())
        .bind::<Text, _>(&projection_id)
        .bind::<Text, _>(record.notification.actor_id.to_string())
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
        .bind::<Nullable<Text>, _>(record.source_actor_id.as_ref().map(ToString::to_string))
        .bind::<Text, _>(&priority)
        .bind::<Text, _>(&state)
        .bind::<Nullable<Jsonb>, _>(preview.as_ref())
        .bind::<Jsonb, _>(&projection_data)
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
        if record.delta.id.as_str().trim().is_empty() {
            return Err(PersistenceError::SchemaViolation(
                "account notification delta id is empty".to_owned(),
            ));
        }
        let action = encode_enum("projection_action", &record.delta.action)?;
        let data = record
            .delta
            .data
            .as_ref()
            .map(serde_json::to_value)
            .transpose()
            .map_err(|error| {
                PersistenceError::Internal(format!(
                    "account notification data is not serializable: {error}"
                ))
            })?;
        sql_query(
            "INSERT INTO notifications \
             (id, recipient_actor_id, controller_account_pk, recipient_id, \
              source_account_artifact_kind, source_account_artifact_id, \
              priority, state, projection_action, projection_data, created_at, updated_at) \
             VALUES ($1, $2, $3, $4, 'agent_runtime_approval', $5, \
              'normal', 'unread', $6, $7, NOW(), NOW()) \
             ON CONFLICT (controller_account_pk, recipient_id, \
              source_account_artifact_kind, source_account_artifact_id) \
              WHERE controller_account_pk IS NOT NULL DO UPDATE SET \
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
        .bind::<sql_types::Uuid, _>(ids::typed_uuid_part_expect_internal(
            record.delta.id.as_str(),
        ))
        .bind::<Text, _>(record.recipient_actor_id.to_string())
        .bind::<BigInt, _>(record.controller_account_pk.get())
        .bind::<Text, _>(record.recipient_id.as_str())
        .bind::<Text, _>(&record.source_account_artifact_id)
        .bind::<Text, _>(&action)
        .bind::<Nullable<Jsonb>, _>(data)
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
            "SELECT id AS notification_id, projection_id, recipient_actor_id, realm_id, source_event_id, \
             controller_account_pk, recipient_id, source_account_artifact_kind, \
             source_account_artifact_id, source_ref, \
             strand_id, track_name, notification_kind, event_kind, source_actor_id, priority, \
             state, preview, projection_action, projection_data, projection_position, \
             created_at, updated_at \
             FROM notifications \
             WHERE recipient_actor_id = $1 AND source_event_id IS NOT NULL \
             ORDER BY created_at DESC",
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
        controller_account_pk: &AccountPk,
        recipient_id: &str,
        after_position: Option<i64>,
    ) -> PersistenceResult<Vec<StoredAccountNotificationDelta>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(
            "SELECT id AS notification_id, projection_id, recipient_actor_id, realm_id, source_event_id, \
             controller_account_pk, recipient_id, source_account_artifact_kind, \
             source_account_artifact_id, source_ref, strand_id, track_name, notification_kind, \
             event_kind, source_actor_id, priority, state, preview, projection_action, \
             projection_data, projection_position, created_at, updated_at \
             FROM notifications \
             WHERE controller_account_pk = $1 AND recipient_id = $2 \
               AND ($3 IS NULL OR projection_position > $3) \
             ORDER BY projection_position",
        )
        .bind::<BigInt, _>(controller_account_pk.get())
        .bind::<Text, _>(recipient_id)
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

pub(crate) fn global_notification_payload(value: Value) -> PersistenceResult<Value> {
    let row: NotificationRow = serde_json::from_value(value)
        .map_err(|error| PersistenceError::Internal(error.to_string()))?;
    serde_json::to_value(row.into_delta()?)
        .map_err(|error| PersistenceError::Internal(error.to_string()))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    fn ordinary_row() -> NotificationRow {
        let account = arkret_wire::AccountId::new(
            arkret_wire::DidCoreId::new("ak:did_core:web:alice.example".to_owned()).unwrap(),
            arkret_wire::DidCoreId::new("ak:did_core:web:station.example".to_owned()).unwrap(),
        );
        let content = OrdinaryProjectionContent {
            realm_id: RealmId::new(
                "ak:realm:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-".to_owned(),
            )
            .unwrap(),
            source_event_id: EventId::new(
                "ak:event:AQM8rE4gp8l4axkSbbb9_dkqwWE8ZPYHwFsC24o2mrIL".to_owned(),
            )
            .unwrap(),
            source_ref: None,
            strand_id: None,
            track_name: None,
            notification_kind: arkret_wire::OrdinaryNotificationKind::Message,
            priority: arkret_wire::NotificationPriority::Normal,
            preview: Some(BTreeMap::from([(
                "body".to_owned(),
                serde_json::json!("hello"),
            )])),
            created_at: "2026-09-10T00:00:00Z".parse().unwrap(),
            updated_at: None,
        };
        let projection_id = content.derive_id(&account).unwrap().to_string();
        NotificationRow {
            notification_id: Uuid::nil(),
            projection_id: Some(projection_id),
            recipient_actor_id: ActorId::account(account).to_string(),
            realm_id: Some(content.realm_id.to_string()),
            source_event_id: Some(content.source_event_id.to_string()),
            controller_account_pk: None,
            recipient_id: None,
            source_account_artifact_kind: None,
            source_account_artifact_id: None,
            source_ref: None,
            strand_id: None,
            track_name: None,
            notification_kind: Some("message".to_owned()),
            event_kind: Some("ak.message.create".to_owned()),
            source_actor_id: None,
            priority: "normal".to_owned(),
            state: "unread".to_owned(),
            preview: None,
            projection_action: Some("upsert".to_owned()),
            projection_data: Some(serde_json::to_value(content).unwrap()),
            projection_position: 1,
            created_at: "2026-09-10T00:00:00Z".parse().unwrap(),
            updated_at: None,
        }
    }

    #[test]
    fn ordinary_projection_row_decodes_by_projection_id_branch() {
        let row = ordinary_row();
        let delta = row.into_delta().unwrap();
        assert!(matches!(
            delta.data,
            Some(NotificationData::OrdinaryProjection(_))
        ));
    }

    #[test]
    fn ordinary_removal_row_requires_the_ordinary_reason_vocabulary() {
        let mut row = ordinary_row();
        row.projection_action = Some("remove".to_owned());
        row.projection_data = Some(serde_json::json!({"reason":"access_revoked"}));
        let delta = row.into_delta().unwrap();
        assert_eq!(
            delta.ordinary_removal_reason(),
            Some(
                arkret_models_collaboration::sync_frames::account_sync::OrdinaryNotificationRemovalReason::AccessRevoked
            )
        );
    }
}

/// Decode one stored notification payload into the branch its `id` form
/// selected. Used only by `into_delta`, which has already chosen the branch.
fn decode_notification_data<T: serde::de::DeserializeOwned>(value: Value) -> PersistenceResult<T> {
    serde_json::from_value(value).map_err(|error| {
        PersistenceError::Internal(format!("account notification data is invalid: {error}"))
    })
}
