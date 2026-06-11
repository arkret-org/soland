use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

use super::*;

/// Trait for durable device inventory operations.
#[async_trait]
pub trait DeviceInventoryStore: Send + Sync {
    async fn get(
        &self,
        actor: &str,
        device_id: &str,
    ) -> PersistenceResult<Option<DeviceInventoryRecord>>;
    async fn put(&self, record: &DeviceInventoryRecord) -> PersistenceResult<()>;
    async fn list_for_actor(&self, actor: &str) -> PersistenceResult<Vec<DeviceInventoryRecord>>;
    async fn list(&self) -> PersistenceResult<Vec<DeviceInventoryRecord>>;
}

/// To-device message queue + idempotency-key set.
#[async_trait]
pub trait DeviceMessageStore: Send + Sync {
    async fn append(&self, message: DeviceMessageRecord) -> PersistenceResult<()>;
    /// Insert a fresh `(actor:idempotency_key)` key — returns `false` if it was already there.
    async fn try_register_txn(&self, key: String) -> PersistenceResult<bool>;
    /// Issue a bearer ack token for the delivered high-water queue position.
    async fn issue_ack_token(
        &self,
        recipient: &str,
        device_id: &str,
        queue_position: i64,
    ) -> PersistenceResult<Option<String>>;
    /// Consume a bearer ack token and prune the messages it covers. Returns
    /// `None` when the token is unknown, expired, or not bound to this device.
    async fn ack_with_token(
        &self,
        recipient: &str,
        device_id: &str,
        ack_token: &str,
    ) -> PersistenceResult<Option<usize>>;
    /// List queued messages for a device strictly after `queue_position`.
    async fn list_after(
        &self,
        recipient: &str,
        device_id: &str,
        queue_position: i64,
    ) -> PersistenceResult<Vec<DeviceMessageRecord>>;
    /// Drop everything queued for the recipient+device (used on session revoke).
    async fn purge(&self, recipient: &str, device_id: &str) -> PersistenceResult<usize>;
}

/// Long-term device key bundles (one per `(actor, device_id)`).
#[async_trait]
pub trait DeviceKeyStore: Send + Sync {
    async fn put(&self, actor: String, device_id: String, payload: Value) -> PersistenceResult<()>;
    async fn get(&self, actor: &str, device_id: &str) -> PersistenceResult<Option<Value>>;
}

/// One-time prekey pool. Calls to `claim` pop a single key.
#[async_trait]
pub trait OneTimeKeyStore: Send + Sync {
    async fn put(
        &self,
        actor: String,
        device_id: String,
        keys: Vec<Value>,
    ) -> PersistenceResult<()>;
    async fn claim(&self, actor: &str, device_id: &str) -> PersistenceResult<Option<Value>>;
}

// In-memory device inventory store
pub(crate) struct MemoryDeviceInventoryStore {
    data: Arc<Mutex<BTreeMap<(String, String), DeviceInventoryRecord>>>,
}

impl MemoryDeviceInventoryStore {
    pub(crate) fn new() -> Self {
        Self {
            data: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }
}

#[async_trait]
impl DeviceInventoryStore for MemoryDeviceInventoryStore {
    async fn get(
        &self,
        actor: &str,
        device_id: &str,
    ) -> PersistenceResult<Option<DeviceInventoryRecord>> {
        let data = self.data.lock().expect("lock");
        Ok(data.get(&(actor.to_owned(), device_id.to_owned())).cloned())
    }

    async fn put(&self, record: &DeviceInventoryRecord) -> PersistenceResult<()> {
        let mut data = self.data.lock().expect("lock");
        data.insert(
            (record.actor.clone(), record.device_id.clone()),
            record.clone(),
        );
        Ok(())
    }

    async fn list_for_actor(&self, actor: &str) -> PersistenceResult<Vec<DeviceInventoryRecord>> {
        let data = self.data.lock().expect("lock");
        Ok(data
            .values()
            .filter(|record| record.actor == actor && record.revoked_at.is_none())
            .cloned()
            .collect())
    }

    async fn list(&self) -> PersistenceResult<Vec<DeviceInventoryRecord>> {
        let data = self.data.lock().expect("lock");
        Ok(data
            .values()
            .filter(|record| record.revoked_at.is_none())
            .cloned()
            .collect())
    }
}

#[derive(Default)]
pub(crate) struct MemoryDeviceMessageStore {
    queue: Mutex<VecDeque<DeviceMessageRecord>>,
    txns: Mutex<BTreeSet<String>>,
    ack_tokens: Mutex<BTreeMap<String, DeviceMessageAckTokenRecord>>,
}

impl MemoryDeviceMessageStore {
    pub(crate) fn new() -> Self {
        Self::default()
    }
}

#[derive(Clone)]
struct DeviceMessageAckTokenRecord {
    recipient: String,
    device_id: String,
    queue_position: i64,
    expires_at: chrono::DateTime<Utc>,
    consumed_at: Option<chrono::DateTime<Utc>>,
}

fn fresh_device_message_ack_token() -> String {
    let mut bytes = Vec::with_capacity(32);
    bytes.extend_from_slice(Uuid::new_v4().as_bytes());
    bytes.extend_from_slice(Uuid::new_v4().as_bytes());
    URL_SAFE_NO_PAD.encode(bytes)
}

#[async_trait]
impl DeviceMessageStore for MemoryDeviceMessageStore {
    async fn append(&self, message: DeviceMessageRecord) -> PersistenceResult<()> {
        self.queue
            .lock()
            .expect("device message lock")
            .push_back(message);
        Ok(())
    }

    async fn try_register_txn(&self, key: String) -> PersistenceResult<bool> {
        Ok(self
            .txns
            .lock()
            .expect("device message txn lock")
            .insert(key))
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
        let now = Utc::now();
        let token = fresh_device_message_ack_token();
        let mut tokens = self.ack_tokens.lock().expect("device message ack lock");
        tokens.retain(|_, record| record.expires_at > now);
        tokens.insert(
            token.clone(),
            DeviceMessageAckTokenRecord {
                recipient: recipient.to_owned(),
                device_id: device_id.to_owned(),
                queue_position,
                expires_at: now + chrono::Duration::hours(24),
                consumed_at: None,
            },
        );
        Ok(Some(token))
    }

    async fn ack_with_token(
        &self,
        recipient: &str,
        device_id: &str,
        ack_token: &str,
    ) -> PersistenceResult<Option<usize>> {
        let now = Utc::now();
        let mut tokens = self.ack_tokens.lock().expect("device message ack lock");
        tokens.retain(|_, record| record.expires_at > now);
        let Some(record) = tokens.get_mut(ack_token) else {
            return Ok(None);
        };
        if record.recipient != recipient || record.device_id != device_id {
            return Ok(None);
        }
        if record.consumed_at.is_some() {
            return Ok(Some(0));
        }
        let ack_position = record.queue_position;
        let mut queue = self.queue.lock().expect("device message lock");
        let before = queue.len();
        queue.retain(|message| {
            !(message.recipient == recipient
                && message.device_id == device_id
                && message.position <= ack_position)
        });
        record.consumed_at = Some(now);
        Ok(Some(before - queue.len()))
    }

    async fn list_after(
        &self,
        recipient: &str,
        device_id: &str,
        queue_position: i64,
    ) -> PersistenceResult<Vec<DeviceMessageRecord>> {
        Ok(self
            .queue
            .lock()
            .expect("device message lock")
            .iter()
            .filter(|message| {
                message.recipient == recipient
                    && message.device_id == device_id
                    && message.position > queue_position
            })
            .cloned()
            .collect())
    }

    async fn purge(&self, recipient: &str, device_id: &str) -> PersistenceResult<usize> {
        let mut queue = self.queue.lock().expect("device message lock");
        let before = queue.len();
        queue.retain(|message| !(message.recipient == recipient && message.device_id == device_id));
        self.ack_tokens
            .lock()
            .expect("device message ack lock")
            .retain(|_, token| !(token.recipient == recipient && token.device_id == device_id));
        Ok(before - queue.len())
    }
}

pub(crate) struct PgDeviceMessageStore {
    pub(crate) pool: PgPool,
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

#[async_trait]
impl DeviceMessageStore for PgDeviceMessageStore {
    async fn append(&self, message: DeviceMessageRecord) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool).await?;
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
        .map_err(PersistenceError::from)
    }

    async fn try_register_txn(&self, key: String) -> PersistenceResult<bool> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "INSERT INTO device_message_txns (key, created_at) \
             VALUES ($1, NOW()) \
             ON CONFLICT (key) DO NOTHING",
        )
        .bind::<Text, _>(&key)
        .execute(&mut *conn)
        .await
        .map(|affected| affected > 0)
        .map_err(PersistenceError::from)
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
        let mut conn = pg_conn(&self.pool).await?;
        let token = fresh_device_message_ack_token();
        let expires_at = Utc::now() + chrono::Duration::hours(24);
        sql_query(
            "DELETE FROM device_message_ack_tokens \
             WHERE expires_at <= NOW()",
        )
        .execute(&mut *conn)
        .await
        .map_err(PersistenceError::from)?;
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
        .map_err(PersistenceError::from)?;
        Ok(Some(token))
    }

    async fn ack_with_token(
        &self,
        recipient: &str,
        device_id: &str,
        ack_token: &str,
    ) -> PersistenceResult<Option<usize>> {
        let mut conn = pg_conn(&self.pool).await?;
        let token = sql_query(
            "SELECT recipient, device_id, queue_position, expires_at, consumed_at \
             FROM device_message_ack_tokens \
             WHERE ack_token = $1",
        )
        .bind::<Text, _>(ack_token)
        .get_result::<DeviceMessageAckTokenRow>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::from)?;
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
        .map_err(PersistenceError::from)?;
        sql_query(
            "UPDATE device_message_ack_tokens \
             SET consumed_at = NOW() \
             WHERE ack_token = $1 AND consumed_at IS NULL",
        )
        .bind::<Text, _>(ack_token)
        .execute(&mut *conn)
        .await
        .map_err(PersistenceError::from)?;
        Ok(Some(pruned))
    }

    async fn list_after(
        &self,
        recipient: &str,
        device_id: &str,
        queue_position: i64,
    ) -> PersistenceResult<Vec<DeviceMessageRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
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
        .map_err(PersistenceError::from)
    }

    async fn purge(&self, recipient: &str, device_id: &str) -> PersistenceResult<usize> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "DELETE FROM device_message_ack_tokens \
             WHERE recipient = $1 AND device_id = $2",
        )
        .bind::<Text, _>(recipient)
        .bind::<Text, _>(device_id)
        .execute(&mut *conn)
        .await
        .map_err(PersistenceError::from)?;
        sql_query(
            "DELETE FROM device_messages \
             WHERE recipient = $1 AND device_id = $2",
        )
        .bind::<Text, _>(recipient)
        .bind::<Text, _>(device_id)
        .execute(&mut *conn)
        .await
        .map_err(PersistenceError::from)
    }
}

#[derive(Default)]
pub(crate) struct MemoryDeviceKeyStore {
    data: Mutex<BTreeMap<(String, String), Value>>,
}

impl MemoryDeviceKeyStore {
    pub(crate) fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl DeviceKeyStore for MemoryDeviceKeyStore {
    async fn put(&self, actor: String, device_id: String, payload: Value) -> PersistenceResult<()> {
        self.data
            .lock()
            .expect("device keys lock")
            .insert((actor, device_id), payload);
        Ok(())
    }

    async fn get(&self, actor: &str, device_id: &str) -> PersistenceResult<Option<Value>> {
        Ok(self
            .data
            .lock()
            .expect("device keys lock")
            .get(&(actor.to_owned(), device_id.to_owned()))
            .cloned())
    }
}

#[derive(Default)]
pub(crate) struct MemoryOneTimeKeyStore {
    data: Mutex<BTreeMap<(String, String), Vec<Value>>>,
}

impl MemoryOneTimeKeyStore {
    pub(crate) fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl OneTimeKeyStore for MemoryOneTimeKeyStore {
    async fn put(
        &self,
        actor: String,
        device_id: String,
        keys: Vec<Value>,
    ) -> PersistenceResult<()> {
        self.data
            .lock()
            .expect("one time keys lock")
            .insert((actor, device_id), keys);
        Ok(())
    }

    async fn claim(&self, actor: &str, device_id: &str) -> PersistenceResult<Option<Value>> {
        Ok(self
            .data
            .lock()
            .expect("one time keys lock")
            .get_mut(&(actor.to_owned(), device_id.to_owned()))
            .and_then(|pool| pool.pop()))
    }
}

// ── G3.S1: in-memory MLS lifecycle stores ─────────────────────────────

pub(crate) struct PgDeviceInventoryStore {
    pub(crate) pool: PgPool,
}

#[async_trait]
impl DeviceInventoryStore for PgDeviceInventoryStore {
    async fn get(
        &self,
        actor: &str,
        device_id: &str,
    ) -> PersistenceResult<Option<DeviceInventoryRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "SELECT actor_id AS actor, device_id, payload, verification_state, created_at, updated_at, revoked_at \
             FROM devices WHERE actor_id = $1 AND device_id = $2 AND revoked_at IS NULL",
        )
            .bind::<Text, _>(actor)
            .bind::<Text, _>(device_id)
            .get_result::<DeviceRow>(&mut *conn).await
            .optional()
            .map(|row| row.map(DeviceInventoryRecord::from))
            .map_err(PersistenceError::from)
    }

    async fn put(&self, record: &DeviceInventoryRecord) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool).await?;
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
        .map_err(PersistenceError::from)
    }

    async fn list_for_actor(&self, actor: &str) -> PersistenceResult<Vec<DeviceInventoryRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        let rows = sql_query(
            "SELECT actor_id AS actor, device_id, payload, verification_state, created_at, updated_at, revoked_at \
             FROM devices WHERE actor_id = $1 AND revoked_at IS NULL ORDER BY device_id",
        )
        .bind::<Text, _>(actor)
        .load::<DeviceRow>(&mut *conn).await
        .map_err(PersistenceError::from)?;
        Ok(rows.into_iter().map(DeviceInventoryRecord::from).collect())
    }

    async fn list(&self) -> PersistenceResult<Vec<DeviceInventoryRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        let rows = sql_query(
            "SELECT actor_id AS actor, device_id, payload, verification_state, created_at, updated_at, revoked_at \
             FROM devices WHERE revoked_at IS NULL ORDER BY actor_id, device_id",
        )
        .load::<DeviceRow>(&mut *conn).await
        .map_err(PersistenceError::from)?;
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
