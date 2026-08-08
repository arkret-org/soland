use super::{
    AsyncConnection, BTreeMap, BTreeSet, BigInt, Bool, DeviceInventoryRecord, DeviceInventoryStore,
    DeviceMessageBatchCommitOutcome, DeviceMessageBatchInspection, DeviceMessageBatchRecord,
    DeviceMessageIntentRecord, DeviceMessageRecord, DeviceMessageStore, Jsonb, MaxSeqRow, Nullable,
    OptionalExtension, PersistenceError, PersistenceResult, PgPool, PgTransactionError,
    QueryableByName, RunQueryDsl, SqlUuid, Text, Timestamptz, Utc, Uuid, Value, async_trait,
    ensure_device_message_id, fresh_device_message_ack_token, pg_conn, sql_query,
};
pub struct PgDeviceMessageStore {
    pub pool: PgPool,
}
#[derive(QueryableByName)]
struct DeviceMessageRow {
    #[diesel(sql_type = Text)]
    idempotency_key: String,
    #[diesel(sql_type = Text)]
    sender: String,
    #[diesel(sql_type = Text)]
    recipient: String,
    #[diesel(sql_type = Text)]
    device_id: String,
    #[diesel(sql_type = BigInt)]
    position: i64,
    #[diesel(sql_type = Jsonb)]
    content: Value,
    #[diesel(sql_type = Timestamptz)]
    created_at: chrono::DateTime<Utc>,
}
impl From<DeviceMessageRow> for DeviceMessageRecord {
    fn from(row: DeviceMessageRow) -> Self {
        Self {
            idempotency_key: row.idempotency_key,
            sender: row.sender,
            recipient: row.recipient,
            device_id: row.device_id,
            position: row.position,
            content: row.content,
            created_at: row.created_at,
        }
    }
}
#[derive(QueryableByName)]
struct DeviceMessageAckTokenRow {
    #[diesel(sql_type = Text)]
    recipient: String,
    #[diesel(sql_type = Text)]
    device_id: String,
    #[diesel(sql_type = BigInt)]
    queue_position: i64,
    #[diesel(sql_type = Timestamptz)]
    expires_at: chrono::DateTime<Utc>,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    consumed_at: Option<chrono::DateTime<Utc>>,
}
#[derive(QueryableByName)]
struct DeviceMessageTxnRow {
    #[diesel(sql_type = Text)]
    request_digest: String,
    #[diesel(sql_type = Jsonb)]
    outcome: Value,
}
#[derive(QueryableByName)]
struct DeviceMessageIntentRow {
    #[diesel(sql_type = Text)]
    intent_digest: String,
    #[diesel(sql_type = Bool)]
    delivered: bool,
}
#[async_trait]
impl DeviceMessageStore for PgDeviceMessageStore {
    async fn append(&self, mut message: DeviceMessageRecord) -> PersistenceResult<()> {
        ensure_device_message_id(&mut message);
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(
            "INSERT INTO device_messages \
             (id, idempotency_key, sender, recipient, device_id, position, content, created_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8) \
             ON CONFLICT (recipient, device_id, position) DO NOTHING",
        )
        .bind::<SqlUuid, _>(Uuid::new_v4())
        .bind::<Text, _>(&message.idempotency_key)
        .bind::<Text, _>(&message.sender)
        .bind::<Text, _>(&message.recipient)
        .bind::<Text, _>(&message.device_id)
        .bind::<BigInt, _>(message.position)
        .bind::<Jsonb, _>(&message.content)
        .bind::<Timestamptz, _>(message.created_at)
        .execute(&mut *conn)
        .await
        .map(|_| ())
        .map_err(PersistenceError::database)
    }

    async fn inspect_batch(
        &self,
        request_key: &str,
        request_digest: &str,
        items: &[DeviceMessageIntentRecord],
    ) -> PersistenceResult<DeviceMessageBatchInspection> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let existing_request = sql_query(
            "SELECT request_digest, outcome FROM device_message_txns \
             WHERE key = $1 AND expires_at > NOW()",
        )
        .bind::<Text, _>(request_key)
        .get_result::<DeviceMessageTxnRow>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?;
        if let Some(existing) = existing_request {
            return if existing.request_digest == request_digest {
                let outcome = serde_json::from_value(existing.outcome).map_err(|error| {
                    PersistenceError::Internal(format!(
                        "device message request outcome deserialize: {error}"
                    ))
                })?;
                Ok(DeviceMessageBatchInspection::Duplicate(outcome))
            } else {
                Ok(DeviceMessageBatchInspection::RequestConflict)
            };
        }
        let mut batch_digests = BTreeMap::new();
        let mut existing_message_outcomes = BTreeMap::new();
        for item in items {
            if let Some(digest) =
                batch_digests.insert(item.message_key.clone(), item.intent_digest.clone())
                && digest != item.intent_digest
            {
                return Ok(DeviceMessageBatchInspection::MessageConflict {
                    message_key: item.message_key.clone(),
                });
            }
            let existing = sql_query(
                "SELECT intent_digest, delivered FROM device_message_idempotency \
                 WHERE message_key = $1 AND expires_at > NOW()",
            )
            .bind::<Text, _>(&item.message_key)
            .get_result::<DeviceMessageIntentRow>(&mut *conn)
            .await
            .optional()
            .map_err(PersistenceError::database)?;
            if let Some(existing) = existing {
                if existing.intent_digest != item.intent_digest {
                    return Ok(DeviceMessageBatchInspection::MessageConflict {
                        message_key: item.message_key.clone(),
                    });
                }
                existing_message_outcomes.insert(item.message_key.clone(), existing.delivered);
            }
        }
        Ok(DeviceMessageBatchInspection::Fresh {
            existing_message_outcomes,
        })
    }

    async fn commit_batch(
        &self,
        batch: DeviceMessageBatchRecord,
    ) -> PersistenceResult<DeviceMessageBatchCommitOutcome> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            sql_query(
                "LOCK TABLE device_message_txns, device_message_idempotency \
                 IN SHARE ROW EXCLUSIVE MODE",
            )
            .execute(&mut *conn)
            .await
            .map_err(PersistenceError::database)?;
            sql_query("DELETE FROM device_message_txns WHERE expires_at <= NOW()")
                .execute(&mut *conn)
                .await
                .map_err(PersistenceError::database)?;
            sql_query("DELETE FROM device_message_idempotency WHERE expires_at <= NOW()")
                .execute(&mut *conn)
                .await
                .map_err(PersistenceError::database)?;

            let existing_request = sql_query(
                "SELECT request_digest, outcome FROM device_message_txns WHERE key = $1",
            )
            .bind::<Text, _>(&batch.request_key)
            .get_result::<DeviceMessageTxnRow>(&mut *conn)
            .await
            .optional()
            .map_err(PersistenceError::database)?;
            if let Some(existing) = existing_request {
                return if existing.request_digest == batch.request_digest {
                    let outcome = serde_json::from_value(existing.outcome).map_err(|error| {
                        PersistenceError::Internal(format!(
                            "device message request outcome deserialize: {error}"
                        ))
                    })?;
                    Ok(DeviceMessageBatchCommitOutcome::Duplicate(outcome))
                } else {
                    Ok(DeviceMessageBatchCommitOutcome::RequestConflict)
                };
            }

            let mut batch_digests = BTreeMap::new();
            let mut fresh_message_keys = BTreeSet::new();
            for item in &batch.items {
                if let Some(digest) = batch_digests.insert(
                    item.message_key.clone(),
                    item.intent_digest.clone(),
                ) && digest != item.intent_digest
                {
                    return Ok(DeviceMessageBatchCommitOutcome::MessageConflict {
                        message_key: item.message_key.clone(),
                    });
                }
                let existing = sql_query(
                    "SELECT intent_digest, delivered FROM device_message_idempotency \
                     WHERE message_key = $1",
                )
                .bind::<Text, _>(&item.message_key)
                .get_result::<DeviceMessageIntentRow>(&mut *conn)
                .await
                .optional()
                .map_err(PersistenceError::database)?;
                match existing {
                    Some(existing) if existing.intent_digest != item.intent_digest => {
                        return Ok(DeviceMessageBatchCommitOutcome::MessageConflict {
                            message_key: item.message_key.clone(),
                        });
                    }
                    Some(_) => {}
                    None => {
                        fresh_message_keys.insert(item.message_key.clone());
                    }
                }
            }

            let mut outcomes = BTreeMap::new();
            for item in batch.items {
                if !fresh_message_keys.remove(&item.message_key) {
                    let existing = sql_query(
                        "SELECT intent_digest, delivered FROM device_message_idempotency \
                         WHERE message_key = $1",
                    )
                    .bind::<Text, _>(&item.message_key)
                    .get_result::<DeviceMessageIntentRow>(&mut *conn)
                    .await
                    .map_err(PersistenceError::database)?;
                    outcomes.insert(item.message_key, existing.delivered);
                    continue;
                }
                let delivered = item.message.is_some();
                sql_query(
                    "INSERT INTO device_message_idempotency \
                     (message_key, intent_digest, delivered, expires_at, created_at) \
                     VALUES ($1, $2, $3, $4, NOW())",
                )
                .bind::<Text, _>(&item.message_key)
                .bind::<Text, _>(&item.intent_digest)
                .bind::<Bool, _>(delivered)
                .bind::<Timestamptz, _>(item.idempotency_expires_at)
                .execute(&mut *conn)
                .await
                .map_err(PersistenceError::database)?;
                outcomes.insert(item.message_key, delivered);
                let Some(mut message) = item.message else {
                    continue;
                };
                ensure_device_message_id(&mut message);
                sql_query(
                    "INSERT INTO device_messages \
                     (id, idempotency_key, sender, recipient, device_id, position, content, created_at) \
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
                )
                .bind::<SqlUuid, _>(Uuid::new_v4())
                .bind::<Text, _>(&message.idempotency_key)
                .bind::<Text, _>(&message.sender)
                .bind::<Text, _>(&message.recipient)
                .bind::<Text, _>(&message.device_id)
                .bind::<BigInt, _>(message.position)
                .bind::<Jsonb, _>(&message.content)
                .bind::<Timestamptz, _>(message.created_at)
                .execute(&mut *conn)
                .await
                .map_err(PersistenceError::database)?;
            }
            sql_query(
                "INSERT INTO device_message_txns \
                 (key, request_digest, outcome, expires_at, created_at) \
                 VALUES ($1, $2, $3, $4, NOW())",
            )
            .bind::<Text, _>(&batch.request_key)
            .bind::<Text, _>(&batch.request_digest)
            .bind::<Jsonb, _>(
                serde_json::to_value(&outcomes).map_err(|error| {
                    PersistenceError::Internal(format!(
                        "device message request outcome serialize: {error}"
                    ))
                })?,
            )
            .bind::<Timestamptz, _>(batch.idempotency_expires_at)
            .execute(&mut *conn)
            .await
            .map_err(PersistenceError::database)?;
            Ok(DeviceMessageBatchCommitOutcome::Stored(outcomes))
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }

    async fn issue_ack_token(
        &self,
        recipient: &str,
        device_id: &str,
        queue_position: i64,
    ) -> PersistenceResult<Option<String>> {
        if queue_position <= 0 {
            return Ok(None);
        }
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let token = fresh_device_message_ack_token();
        let expires_at = Utc::now() + chrono::Duration::hours(24);
        sql_query(
            "DELETE FROM device_message_ack_tokens \
             WHERE expires_at <= NOW()",
        )
        .execute(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
        sql_query(
            "INSERT INTO device_message_ack_tokens \
             (ack_token, recipient, device_id, queue_position, issued_at, expires_at, consumed_at) \
             VALUES ($1, $2, $3, $4, NOW(), $5, NULL)",
        )
        .bind::<Text, _>(&token)
        .bind::<Text, _>(recipient)
        .bind::<Text, _>(device_id)
        .bind::<BigInt, _>(queue_position)
        .bind::<Timestamptz, _>(expires_at)
        .execute(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
        Ok(Some(token))
    }

    async fn ack_with_token(
        &self,
        recipient: &str,
        device_id: &str,
        ack_token: &str,
    ) -> PersistenceResult<Option<usize>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let token = sql_query(
            "SELECT recipient, device_id, queue_position, expires_at, consumed_at \
             FROM device_message_ack_tokens \
             WHERE ack_token = $1",
        )
        .bind::<Text, _>(ack_token)
        .get_result::<DeviceMessageAckTokenRow>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?;
        let Some(token) = token else {
            return Ok(None);
        };
        if token.recipient != recipient
            || token.device_id != device_id
            || token.expires_at <= Utc::now()
        {
            return Ok(None);
        }
        if token.consumed_at.is_some() {
            return Ok(Some(0));
        }
        let pruned = sql_query(
            "DELETE FROM device_messages \
             WHERE recipient = $1 AND device_id = $2 AND position <= $3",
        )
        .bind::<Text, _>(recipient)
        .bind::<Text, _>(device_id)
        .bind::<BigInt, _>(token.queue_position)
        .execute(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
        sql_query(
            "UPDATE device_message_ack_tokens \
             SET consumed_at = NOW() \
             WHERE ack_token = $1 AND consumed_at IS NULL",
        )
        .bind::<Text, _>(ack_token)
        .execute(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
        Ok(Some(pruned))
    }

    async fn list_after(
        &self,
        recipient: &str,
        device_id: &str,
        queue_position: i64,
    ) -> PersistenceResult<Vec<DeviceMessageRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(
            "SELECT idempotency_key, sender, recipient, device_id, position, content, created_at \
             FROM device_messages \
             WHERE recipient = $1 AND device_id = $2 AND position > $3 \
             ORDER BY position ASC",
        )
        .bind::<Text, _>(recipient)
        .bind::<Text, _>(device_id)
        .bind::<BigInt, _>(queue_position)
        .load::<DeviceMessageRow>(&mut *conn)
        .await
        .map(|rows| rows.into_iter().map(DeviceMessageRecord::from).collect())
        .map_err(PersistenceError::database)
    }

    async fn prune_expired(&self, now: chrono::DateTime<Utc>) -> PersistenceResult<usize> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(
            "WITH expired AS ( \
                 SELECT recipient, device_id, MAX(position) AS lost_through \
                 FROM device_messages \
                 WHERE COALESCE(NULLIF(content->>'expires_at', '')::timestamptz, created_at + interval '1 hour') <= $1 \
                 GROUP BY recipient, device_id \
             ), upserted AS ( \
                 INSERT INTO device_message_lost_watermarks \
                     (recipient, device_id, lost_through, updated_at) \
                 SELECT recipient, device_id, lost_through, $1 FROM expired \
                 ON CONFLICT (recipient, device_id) DO UPDATE \
                 SET lost_through = GREATEST(device_message_lost_watermarks.lost_through, EXCLUDED.lost_through), \
                     updated_at = EXCLUDED.updated_at \
                 RETURNING 1 \
             ) \
            DELETE FROM device_messages \
             WHERE COALESCE(NULLIF(content->>'expires_at', '')::timestamptz, created_at + interval '1 hour') <= $1",
        )
        .bind::<Timestamptz, _>(now)
        .execute(&mut *conn)
        .await
        .map_err(PersistenceError::database)
    }

    async fn prune_over_capacity(
        &self,
        per_device_capacity: usize,
        now: chrono::DateTime<Utc>,
    ) -> PersistenceResult<usize> {
        if per_device_capacity == 0 {
            return Ok(0);
        }
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(
            "WITH ranked AS ( \
                 SELECT recipient, device_id, position, \
                        ROW_NUMBER() OVER ( \
                            PARTITION BY recipient, device_id \
                            ORDER BY position DESC \
                        ) AS keep_rank \
                 FROM device_messages \
             ), evicted AS ( \
                 SELECT recipient, device_id, MAX(position) AS lost_through \
                 FROM ranked \
                 WHERE keep_rank > $1 \
                 GROUP BY recipient, device_id \
             ), upserted AS ( \
                 INSERT INTO device_message_lost_watermarks \
                     (recipient, device_id, lost_through, updated_at) \
                 SELECT recipient, device_id, lost_through, $2 FROM evicted \
                 ON CONFLICT (recipient, device_id) DO UPDATE \
                 SET lost_through = GREATEST(device_message_lost_watermarks.lost_through, EXCLUDED.lost_through), \
                     updated_at = EXCLUDED.updated_at \
                 RETURNING 1 \
             ) \
             DELETE FROM device_messages USING ranked \
             WHERE device_messages.recipient = ranked.recipient \
               AND device_messages.device_id = ranked.device_id \
               AND device_messages.position = ranked.position \
               AND ranked.keep_rank > $1",
        )
        .bind::<BigInt, _>(per_device_capacity as i64)
        .bind::<Timestamptz, _>(now)
        .execute(&mut *conn)
        .await
        .map_err(PersistenceError::database)
    }

    async fn lost_watermark(
        &self,
        recipient: &str,
        device_id: &str,
    ) -> PersistenceResult<Option<i64>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(
            "SELECT lost_through AS max_seq \
             FROM device_message_lost_watermarks \
             WHERE recipient = $1 AND device_id = $2",
        )
        .bind::<Text, _>(recipient)
        .bind::<Text, _>(device_id)
        .get_result::<MaxSeqRow>(&mut *conn)
        .await
        .optional()
        .map(|row| row.and_then(|row| row.max_seq))
        .map_err(PersistenceError::database)
    }

    async fn purge(&self, recipient: &str, device_id: &str) -> PersistenceResult<usize> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(
            "DELETE FROM device_message_ack_tokens \
             WHERE recipient = $1 AND device_id = $2",
        )
        .bind::<Text, _>(recipient)
        .bind::<Text, _>(device_id)
        .execute(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
        sql_query(
            "DELETE FROM device_messages \
             WHERE recipient = $1 AND device_id = $2",
        )
        .bind::<Text, _>(recipient)
        .bind::<Text, _>(device_id)
        .execute(&mut *conn)
        .await
        .map_err(PersistenceError::database)
    }
}
// ── G3.S1: in-memory MLS lifecycle stores ─────────────────────────────

pub struct PgDeviceInventoryStore {
    pub pool: PgPool,
}
#[async_trait]
impl DeviceInventoryStore for PgDeviceInventoryStore {
    async fn get(
        &self,
        actor: &str,
        device_id: &str,
    ) -> PersistenceResult<Option<DeviceInventoryRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(
            "SELECT actor_id AS actor, device_id, payload, verification_state, created_at, updated_at, revoked_at \
             FROM devices WHERE actor_id = $1 AND device_id = $2 AND revoked_at IS NULL",
        )
            .bind::<Text, _>(actor)
            .bind::<Text, _>(device_id)
            .get_result::<DeviceRow>(&mut *conn).await
            .optional()
            .map(|row| row.map(DeviceInventoryRecord::from))
            .map_err(PersistenceError::database)
    }

    async fn put(&self, record: &DeviceInventoryRecord) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(
            "INSERT INTO devices (id, actor_id, device_id, payload, verification_state, created_at, updated_at, revoked_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8) \
             ON CONFLICT (actor_id, device_id) DO UPDATE SET payload = EXCLUDED.payload, \
             verification_state = EXCLUDED.verification_state, updated_at = EXCLUDED.updated_at, revoked_at = EXCLUDED.revoked_at",
        )
        .bind::<diesel::sql_types::Uuid, _>(uuid::Uuid::now_v7())
        .bind::<Text, _>(&record.actor)
        .bind::<Text, _>(&record.device_id)
        .bind::<Jsonb, _>(&record.payload)
        .bind::<Text, _>(&record.verification_state)
        .bind::<Timestamptz, _>(record.created_at)
        .bind::<Timestamptz, _>(record.updated_at)
        .bind::<Nullable<Timestamptz>, _>(record.revoked_at)
        .execute(&mut *conn).await
        .map(|_| ())
        .map_err(PersistenceError::database)
    }

    async fn put_if_absent(&self, record: &DeviceInventoryRecord) -> PersistenceResult<bool> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(
            "INSERT INTO devices (id, actor_id, device_id, payload, verification_state, created_at, updated_at, revoked_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8) \
             ON CONFLICT (actor_id, device_id) DO NOTHING",
        )
        .bind::<diesel::sql_types::Uuid, _>(uuid::Uuid::now_v7())
        .bind::<Text, _>(&record.actor)
        .bind::<Text, _>(&record.device_id)
        .bind::<Jsonb, _>(&record.payload)
        .bind::<Text, _>(&record.verification_state)
        .bind::<Timestamptz, _>(record.created_at)
        .bind::<Timestamptz, _>(record.updated_at)
        .bind::<Nullable<Timestamptz>, _>(record.revoked_at)
        .execute(&mut *conn)
        .await
        .map(|affected| affected > 0)
        .map_err(PersistenceError::database)
    }

    async fn list_for_actor(&self, actor: &str) -> PersistenceResult<Vec<DeviceInventoryRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let rows = sql_query(
            "SELECT actor_id AS actor, device_id, payload, verification_state, created_at, updated_at, revoked_at \
             FROM devices WHERE actor_id = $1 AND revoked_at IS NULL ORDER BY device_id",
        )
        .bind::<Text, _>(actor)
        .load::<DeviceRow>(&mut *conn).await
        .map_err(PersistenceError::database)?;
        Ok(rows.into_iter().map(DeviceInventoryRecord::from).collect())
    }

    async fn list_for_actor_including_revoked(
        &self,
        actor: &str,
    ) -> PersistenceResult<Vec<DeviceInventoryRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let rows = sql_query(
            "SELECT actor_id AS actor, device_id, payload, verification_state, created_at, updated_at, revoked_at \
             FROM devices WHERE actor_id = $1 ORDER BY device_id",
        )
        .bind::<Text, _>(actor)
        .load::<DeviceRow>(&mut *conn).await
        .map_err(PersistenceError::database)?;
        Ok(rows.into_iter().map(DeviceInventoryRecord::from).collect())
    }

    async fn list(&self) -> PersistenceResult<Vec<DeviceInventoryRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let rows = sql_query(
            "SELECT actor_id AS actor, device_id, payload, verification_state, created_at, updated_at, revoked_at \
             FROM devices WHERE revoked_at IS NULL ORDER BY actor_id, device_id",
        )
        .load::<DeviceRow>(&mut *conn).await
        .map_err(PersistenceError::database)?;
        Ok(rows.into_iter().map(DeviceInventoryRecord::from).collect())
    }
}
#[derive(QueryableByName)]
struct DeviceRow {
    #[diesel(sql_type = Text)]
    actor: String,
    #[diesel(sql_type = Text)]
    device_id: String,
    #[diesel(sql_type = Jsonb)]
    payload: Value,
    #[diesel(sql_type = Text)]
    verification_state: String,
    #[diesel(sql_type = Timestamptz)]
    created_at: chrono::DateTime<chrono::Utc>,
    #[diesel(sql_type = Timestamptz)]
    updated_at: chrono::DateTime<chrono::Utc>,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    revoked_at: Option<chrono::DateTime<chrono::Utc>>,
}
impl From<DeviceRow> for DeviceInventoryRecord {
    fn from(row: DeviceRow) -> Self {
        let display_name = row
            .payload
            .get("display_name")
            .and_then(|value| value.as_str())
            .map(ToOwned::to_owned);
        Self {
            actor: row.actor,
            device_id: row.device_id,
            display_name,
            verification_state: row.verification_state,
            payload: row.payload,
            created_at: row.created_at,
            updated_at: row.updated_at,
            revoked_at: row.revoked_at,
        }
    }
}
