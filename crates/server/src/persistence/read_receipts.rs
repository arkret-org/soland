use super::*;

/// Short-TTL relay for `ck.receipt.read` ephemeral payloads.
///
/// Records are retained only until `expires_at` and are delivered through the
/// account sync `ephemeral` segment. `position` is a monotonic per-Realm
/// deliver-once cursor; full syncs ignore the watermark so reconnecting
/// devices can recover still-live receipts.
#[async_trait]
pub trait ReadReceiptRelayStore: Send + Sync {
    async fn append(&self, record: ReadReceiptRelayRecord) -> PersistenceResult<()>;
    async fn list_for_realm(
        &self,
        realm_id: &str,
    ) -> PersistenceResult<Vec<ReadReceiptRelayRecord>>;
    async fn list_for_event(
        &self,
        event_id: &str,
    ) -> PersistenceResult<Vec<ReadReceiptRelayRecord>>;
    async fn prune_expired(&self) -> PersistenceResult<usize>;
    async fn delivered_through(
        &self,
        actor: &str,
        device: &str,
        realm_id: &str,
    ) -> PersistenceResult<u64>;
    async fn advance(
        &self,
        actor: &str,
        device: &str,
        realm_id: &str,
        position: u64,
    ) -> PersistenceResult<()>;
}

/// Per-Realm cap on retained relayed read receipts to bound memory/table growth.
pub(crate) const READ_RECEIPT_RELAY_MAX_PER_REALM: usize = 512;

#[derive(Default)]
pub(crate) struct MemoryReadReceiptRelayStore {
    data: Mutex<BTreeMap<String, Vec<ReadReceiptRelayRecord>>>,
    next_position: Mutex<BTreeMap<String, u64>>,
    watermark: Mutex<BTreeMap<(String, String, String), u64>>,
}

impl MemoryReadReceiptRelayStore {
    pub(crate) fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl ReadReceiptRelayStore for MemoryReadReceiptRelayStore {
    async fn append(&self, mut record: ReadReceiptRelayRecord) -> PersistenceResult<()> {
        let now = Utc::now();
        let realm_id = record.realm_id.clone();
        let position = {
            let mut counters = self.next_position.lock();
            let counter = counters.entry(realm_id.clone()).or_insert(0);
            *counter += 1;
            *counter
        };
        record.position = position;

        let mut data = self.data.lock();
        let bucket = data.entry(realm_id).or_default();
        bucket.retain(|existing| existing.expires_at > now);
        bucket.push(record);
        if bucket.len() > READ_RECEIPT_RELAY_MAX_PER_REALM {
            let overflow = bucket.len() - READ_RECEIPT_RELAY_MAX_PER_REALM;
            bucket.drain(0..overflow);
        }
        Ok(())
    }

    async fn list_for_realm(
        &self,
        realm_id: &str,
    ) -> PersistenceResult<Vec<ReadReceiptRelayRecord>> {
        let now = Utc::now();
        Ok(self
            .data
            .lock()
            .get(realm_id)
            .map(|bucket| {
                bucket
                    .iter()
                    .filter(|record| record.expires_at > now)
                    .cloned()
                    .collect()
            })
            .unwrap_or_default())
    }

    async fn list_for_event(
        &self,
        event_id: &str,
    ) -> PersistenceResult<Vec<ReadReceiptRelayRecord>> {
        let now = Utc::now();
        Ok(self
            .data
            .lock()
            .values()
            .flat_map(|bucket| bucket.iter())
            .filter(|record| record.event_id == event_id && record.expires_at > now)
            .cloned()
            .collect())
    }

    async fn prune_expired(&self) -> PersistenceResult<usize> {
        let now = Utc::now();
        let mut data = self.data.lock();
        let mut removed = 0usize;
        for bucket in data.values_mut() {
            let before = bucket.len();
            bucket.retain(|record| record.expires_at > now);
            removed += before - bucket.len();
        }
        data.retain(|_, bucket| !bucket.is_empty());
        Ok(removed)
    }

    async fn delivered_through(
        &self,
        actor: &str,
        device: &str,
        realm_id: &str,
    ) -> PersistenceResult<u64> {
        let key = (actor.to_owned(), device.to_owned(), realm_id.to_owned());
        Ok(self.watermark.lock().get(&key).copied().unwrap_or(0))
    }

    async fn advance(
        &self,
        actor: &str,
        device: &str,
        realm_id: &str,
        position: u64,
    ) -> PersistenceResult<()> {
        let key = (actor.to_owned(), device.to_owned(), realm_id.to_owned());
        let mut watermark = self.watermark.lock();
        let entry = watermark.entry(key).or_insert(0);
        if position > *entry {
            *entry = position;
        }
        Ok(())
    }
}

/// PostgreSQL-backed `ck.receipt.read` relay.
pub(crate) struct PgReadReceiptRelayStore {
    pub(crate) pool: PgPool,
}

#[derive(QueryableByName)]
struct ReadReceiptRelayPositionRow {
    #[diesel(sql_type = BigInt)]
    next_position: i64,
}

#[derive(QueryableByName)]
struct ReadReceiptRelayRow {
    #[diesel(sql_type = Text)]
    realm_id: String,
    #[diesel(sql_type = BigInt)]
    position: i64,
    #[diesel(sql_type = Text)]
    actor_id: String,
    #[diesel(sql_type = Nullable<Text>)]
    sender_device: Option<String>,
    #[diesel(sql_type = Text)]
    event_id: String,
    #[diesel(sql_type = Jsonb)]
    read_scope: Value,
    #[diesel(sql_type = Nullable<Text>)]
    target_actor: Option<String>,
    #[diesel(sql_type = Text)]
    visibility: String,
    #[diesel(sql_type = Jsonb)]
    receipt: Value,
    #[diesel(sql_type = Timestamptz)]
    created_at: chrono::DateTime<chrono::Utc>,
    #[diesel(sql_type = Timestamptz)]
    expires_at: chrono::DateTime<chrono::Utc>,
}

impl From<ReadReceiptRelayRow> for ReadReceiptRelayRecord {
    fn from(row: ReadReceiptRelayRow) -> Self {
        Self {
            realm_id: row.realm_id,
            actor_id: row.actor_id,
            sender_device: row.sender_device,
            event_id: row.event_id,
            read_scope: row.read_scope,
            target_actor: row.target_actor,
            visibility: row.visibility,
            receipt: row.receipt,
            created_at: row.created_at,
            expires_at: row.expires_at,
            position: row.position.max(0) as u64,
        }
    }
}

#[derive(QueryableByName)]
struct ReadReceiptWatermarkRow {
    #[diesel(sql_type = BigInt)]
    delivered_through: i64,
}

#[async_trait]
impl ReadReceiptRelayStore for PgReadReceiptRelayStore {
    async fn append(&self, mut record: ReadReceiptRelayRecord) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool).await?;
        let position_row = sql_query(
            "INSERT INTO read_receipt_relay_position (realm_id, next_position, updated_at) \
             VALUES ($1, 1, NOW()) \
             ON CONFLICT (realm_id) DO UPDATE SET \
                next_position = read_receipt_relay_position.next_position + 1, \
                updated_at = NOW() \
             RETURNING next_position",
        )
        .bind::<Text, _>(&record.realm_id)
        .get_result::<ReadReceiptRelayPositionRow>(&mut *conn)
        .await
        .map_err(PersistenceError::from)?;
        let position = position_row.next_position;
        record.position = position.max(0) as u64;

        sql_query(
            "INSERT INTO read_receipt_relay \
             (id, realm_id, position, actor_id, sender_device, event_id, read_scope, target_actor, visibility, receipt, created_at, expires_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)",
        )
        .bind::<SqlUuid, _>(Uuid::now_v7())
        .bind::<Text, _>(&record.realm_id)
        .bind::<BigInt, _>(position)
        .bind::<Text, _>(&record.actor_id)
        .bind::<Nullable<Text>, _>(record.sender_device.as_deref())
        .bind::<Text, _>(&record.event_id)
        .bind::<Jsonb, _>(&record.read_scope)
        .bind::<Nullable<Text>, _>(record.target_actor.as_deref())
        .bind::<Text, _>(&record.visibility)
        .bind::<Jsonb, _>(&record.receipt)
        .bind::<Timestamptz, _>(record.created_at)
        .bind::<Timestamptz, _>(record.expires_at)
        .execute(&mut *conn)
        .await
        .map_err(PersistenceError::from)?;

        sql_query(
            "DELETE FROM read_receipt_relay \
             WHERE realm_id = $1 AND position <= $2 - $3",
        )
        .bind::<Text, _>(&record.realm_id)
        .bind::<BigInt, _>(position)
        .bind::<BigInt, _>(READ_RECEIPT_RELAY_MAX_PER_REALM as i64)
        .execute(&mut *conn)
        .await
        .map_err(PersistenceError::from)?;
        Ok(())
    }

    async fn list_for_realm(
        &self,
        realm_id: &str,
    ) -> PersistenceResult<Vec<ReadReceiptRelayRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        let rows = sql_query(
            "SELECT realm_id, position, actor_id, sender_device, event_id, read_scope, target_actor, visibility, receipt, created_at, expires_at \
             FROM read_receipt_relay \
             WHERE realm_id = $1 AND expires_at > NOW() \
             ORDER BY position ASC",
        )
        .bind::<Text, _>(realm_id)
        .load::<ReadReceiptRelayRow>(&mut *conn)
        .await
        .map_err(PersistenceError::from)?;
        Ok(rows.into_iter().map(ReadReceiptRelayRecord::from).collect())
    }

    async fn list_for_event(
        &self,
        event_id: &str,
    ) -> PersistenceResult<Vec<ReadReceiptRelayRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        let rows = sql_query(
            "SELECT realm_id, position, actor_id, sender_device, event_id, read_scope, target_actor, visibility, receipt, created_at, expires_at \
             FROM read_receipt_relay \
             WHERE event_id = $1 AND expires_at > NOW() \
             ORDER BY position ASC",
        )
        .bind::<Text, _>(event_id)
        .load::<ReadReceiptRelayRow>(&mut *conn)
        .await
        .map_err(PersistenceError::from)?;
        Ok(rows.into_iter().map(ReadReceiptRelayRecord::from).collect())
    }

    async fn prune_expired(&self) -> PersistenceResult<usize> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query("DELETE FROM read_receipt_relay WHERE expires_at <= NOW()")
            .execute(&mut *conn)
            .await
            .map_err(PersistenceError::from)
    }

    async fn delivered_through(
        &self,
        actor: &str,
        device: &str,
        realm_id: &str,
    ) -> PersistenceResult<u64> {
        let mut conn = pg_conn(&self.pool).await?;
        let row = sql_query(
            "SELECT delivered_through FROM read_receipt_relay_watermark \
             WHERE actor_id = $1 AND device_id = $2 AND realm_id = $3",
        )
        .bind::<Text, _>(actor)
        .bind::<Text, _>(device)
        .bind::<Text, _>(realm_id)
        .get_result::<ReadReceiptWatermarkRow>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::from)?;
        Ok(row.map(|r| r.delivered_through.max(0) as u64).unwrap_or(0))
    }

    async fn advance(
        &self,
        actor: &str,
        device: &str,
        realm_id: &str,
        position: u64,
    ) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "INSERT INTO read_receipt_relay_watermark \
             (actor_id, device_id, realm_id, delivered_through, updated_at) \
             VALUES ($1, $2, $3, $4, NOW()) \
             ON CONFLICT (actor_id, device_id, realm_id) DO UPDATE SET \
                delivered_through = GREATEST(read_receipt_relay_watermark.delivered_through, EXCLUDED.delivered_through), \
                updated_at = NOW()",
        )
        .bind::<Text, _>(actor)
        .bind::<Text, _>(device)
        .bind::<Text, _>(realm_id)
        .bind::<BigInt, _>(position as i64)
        .execute(&mut *conn)
        .await
        .map(|_| ())
        .map_err(PersistenceError::from)
    }
}
