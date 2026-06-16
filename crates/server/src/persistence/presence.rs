use super::*;

/// Presence (online/away/dnd) per actor.
#[async_trait]
pub trait PresenceStore: Send + Sync {
    async fn put(&self, presence: PresenceRecord) -> PersistenceResult<()>;
    async fn get(&self, actor: &str) -> PersistenceResult<Option<PresenceRecord>>;
}

/// Typing indicators per (actor, Realm). Auto-prunes expired entries.
#[async_trait]
pub trait TypingStore: Send + Sync {
    async fn put(&self, typing: TypingRecord) -> PersistenceResult<()>;
    async fn remove(&self, actor: &str, realm_id: &str) -> PersistenceResult<()>;
    async fn list_for_realm(&self, realm_id: &str) -> PersistenceResult<Vec<TypingRecord>>;
    async fn prune_expired(&self) -> PersistenceResult<usize>;
}

/// Realm-broadcast relay for `ck.call.signal` ephemeral envelopes
/// (`webrtc-signaling.md` §5). Stores the verbatim signed envelope per Realm
/// with a TTL; receivers pick it up off the subscribe `ephemeral.call_signals`
/// segment and verify the carried `proof`. Auto-prunes expired entries and
/// caps each Realm to the most recent `CALL_SIGNAL_RELAY_MAX_PER_REALM`.
///
/// Deliver-once: `append` stamps each record with a monotonic per-Realm
/// `position`, and an in-memory per-subscriber-device watermark
/// (`delivered_through` / `advance`) records the highest position already
/// delivered to a `(actor, device, realm)` triple. Incremental re-subscribes
/// inside the TTL window therefore do not re-emit a signal the device already
/// saw, while a full sync still re-delivers all non-expired pending signals so
/// a reconnecting device recovers a pending invite. This mirrors the to_device
/// deliver-once watermark without touching the client-facing sync cursor.
#[async_trait]
pub trait CallSignalRelayStore: Send + Sync {
    async fn append(&self, record: CallSignalRelayRecord) -> PersistenceResult<()>;
    async fn list_for_realm(&self, realm_id: &str)
    -> PersistenceResult<Vec<CallSignalRelayRecord>>;
    async fn prune_expired(&self) -> PersistenceResult<usize>;
    /// Highest per-Realm `position` already delivered to `(actor, device,
    /// realm)`. Returns `0` when nothing has been delivered yet.
    async fn delivered_through(
        &self,
        actor: &str,
        device: &str,
        realm_id: &str,
    ) -> PersistenceResult<u64>;
    /// Advance the `(actor, device, realm)` watermark to `position` (monotonic;
    /// a lower value is ignored).
    async fn advance(
        &self,
        actor: &str,
        device: &str,
        realm_id: &str,
        position: u64,
    ) -> PersistenceResult<()>;
}

/// Per-Realm cap on retained relayed call signals to bound memory growth.
/// Call signals are short-lived (≤5 min ephemeral TTL) so the bound only
/// matters under a burst; the oldest entries are dropped first.
pub(crate) const CALL_SIGNAL_RELAY_MAX_PER_REALM: usize = 256;

#[derive(Default)]
pub(crate) struct MemoryPresenceStore {
    data: Mutex<BTreeMap<String, PresenceRecord>>,
}

impl MemoryPresenceStore {
    pub(crate) fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl PresenceStore for MemoryPresenceStore {
    async fn put(&self, presence: PresenceRecord) -> PersistenceResult<()> {
        let actor = presence.actor.clone();
        self.data
            .lock()
            .expect("presence lock")
            .insert(actor, presence);
        Ok(())
    }

    async fn get(&self, actor: &str) -> PersistenceResult<Option<PresenceRecord>> {
        Ok(self.data.lock().expect("presence lock").get(actor).cloned())
    }
}

#[derive(Default)]
pub(crate) struct MemoryTypingStore {
    data: Mutex<BTreeMap<(String, String), TypingRecord>>,
}

impl MemoryTypingStore {
    pub(crate) fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl TypingStore for MemoryTypingStore {
    async fn put(&self, typing: TypingRecord) -> PersistenceResult<()> {
        let key = (typing.actor.clone(), typing.realm_id.clone());
        self.data.lock().expect("typing lock").insert(key, typing);
        Ok(())
    }

    async fn remove(&self, actor: &str, realm_id: &str) -> PersistenceResult<()> {
        self.data
            .lock()
            .expect("typing lock")
            .remove(&(actor.to_owned(), realm_id.to_owned()));
        Ok(())
    }

    async fn list_for_realm(&self, realm_id: &str) -> PersistenceResult<Vec<TypingRecord>> {
        let now = Utc::now();
        Ok(self
            .data
            .lock()
            .expect("typing lock")
            .values()
            .filter(|record| record.realm_id == realm_id && record.expires_at > now)
            .cloned()
            .collect())
    }

    async fn prune_expired(&self) -> PersistenceResult<usize> {
        let now = Utc::now();
        let mut data = self.data.lock().expect("typing lock");
        let before = data.len();
        data.retain(|_, record| record.expires_at > now);
        Ok(before - data.len())
    }
}

#[derive(Default)]
pub(crate) struct MemoryCallSignalRelayStore {
    data: Mutex<BTreeMap<String, Vec<CallSignalRelayRecord>>>,
    /// Monotonic per-Realm position counter. Never resets (even when the bucket
    /// is fully pruned) so positions stay strictly increasing for the lifetime
    /// of the process and a watermark can never be re-crossed by a recycled id.
    next_position: Mutex<BTreeMap<String, u64>>,
    /// Per-subscriber-device deliver-once watermark keyed by `(actor, device,
    /// realm_id)`: the highest per-Realm `position` already delivered to that
    /// device.
    watermark: Mutex<BTreeMap<(String, String, String), u64>>,
}

impl MemoryCallSignalRelayStore {
    pub(crate) fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl CallSignalRelayStore for MemoryCallSignalRelayStore {
    async fn append(&self, mut record: CallSignalRelayRecord) -> PersistenceResult<()> {
        let now = Utc::now();
        let realm_id = record.realm_id.clone();
        // Assign the monotonic per-Realm position before storing so every
        // delivered record carries a stable deliver-once key.
        let position = {
            let mut counters = self
                .next_position
                .lock()
                .expect("call signal position lock");
            let counter = counters.entry(realm_id.clone()).or_insert(0);
            *counter += 1;
            *counter
        };
        record.position = position;
        let mut data = self.data.lock().expect("call signal relay lock");
        let bucket = data.entry(realm_id).or_default();
        bucket.retain(|existing| existing.expires_at > now);
        bucket.push(record);
        if bucket.len() > CALL_SIGNAL_RELAY_MAX_PER_REALM {
            let overflow = bucket.len() - CALL_SIGNAL_RELAY_MAX_PER_REALM;
            bucket.drain(0..overflow);
        }
        Ok(())
    }

    async fn list_for_realm(
        &self,
        realm_id: &str,
    ) -> PersistenceResult<Vec<CallSignalRelayRecord>> {
        let now = Utc::now();
        Ok(self
            .data
            .lock()
            .expect("call signal relay lock")
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

    async fn prune_expired(&self) -> PersistenceResult<usize> {
        let now = Utc::now();
        let mut data = self.data.lock().expect("call signal relay lock");
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
        Ok(self
            .watermark
            .lock()
            .expect("call signal watermark lock")
            .get(&key)
            .copied()
            .unwrap_or(0))
    }

    async fn advance(
        &self,
        actor: &str,
        device: &str,
        realm_id: &str,
        position: u64,
    ) -> PersistenceResult<()> {
        let key = (actor.to_owned(), device.to_owned(), realm_id.to_owned());
        let mut watermark = self.watermark.lock().expect("call signal watermark lock");
        let entry = watermark.entry(key).or_insert(0);
        if position > *entry {
            *entry = position;
        }
        Ok(())
    }
}

pub(crate) struct PgPresenceStore {
    pub(crate) pool: PgPool,
}

#[derive(QueryableByName)]
struct PresenceRow {
    #[diesel(sql_type = Text)]
    actor: String,
    #[diesel(sql_type = Text)]
    status: String,
    #[diesel(sql_type = Timestamptz)]
    updated_at: chrono::DateTime<chrono::Utc>,
}

impl From<PresenceRow> for PresenceRecord {
    fn from(row: PresenceRow) -> Self {
        Self {
            actor: row.actor,
            status: row.status,
            updated_at: row.updated_at,
        }
    }
}

#[async_trait]
impl PresenceStore for PgPresenceStore {
    async fn put(&self, presence: PresenceRecord) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "INSERT INTO presence (id, status, updated_at) \
             VALUES ($1, $2, $3) \
             ON CONFLICT (id) DO UPDATE SET \
                status = EXCLUDED.status, \
                updated_at = EXCLUDED.updated_at",
        )
        .bind::<Text, _>(&presence.actor)
        .bind::<Text, _>(&presence.status)
        .bind::<Timestamptz, _>(presence.updated_at)
        .execute(&mut *conn)
        .await
        .map(|_| ())
        .map_err(PersistenceError::from)
    }

    async fn get(&self, actor: &str) -> PersistenceResult<Option<PresenceRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query("SELECT id AS actor, status, updated_at FROM presence WHERE id = $1")
            .bind::<Text, _>(actor)
            .get_result::<PresenceRow>(&mut *conn)
            .await
            .optional()
            .map(|row| row.map(PresenceRecord::from))
            .map_err(PersistenceError::from)
    }
}

/// PostgreSQL-backed `ck.call.signal` realm-broadcast relay
/// (`webrtc-signaling.md` §5). Durable so a restart / replica failover keeps
/// pending invites and the per-subscriber-device deliver-once watermark
/// (`call_signal_relay` + `call_signal_relay_position` +
/// `call_signal_relay_watermark`).
pub(crate) struct PgCallSignalRelayStore {
    pub(crate) pool: PgPool,
}

#[derive(QueryableByName)]
struct CallSignalRelayPositionRow {
    #[diesel(sql_type = BigInt)]
    next_position: i64,
}

#[derive(QueryableByName)]
struct CallSignalRelayRow {
    #[diesel(sql_type = Text)]
    realm_id: String,
    #[diesel(sql_type = BigInt)]
    position: i64,
    #[diesel(sql_type = Text)]
    sender_actor: String,
    #[diesel(sql_type = Text)]
    sender_device: String,
    #[diesel(sql_type = Text)]
    call_id: String,
    #[diesel(sql_type = Jsonb)]
    envelope: Value,
    #[diesel(sql_type = Timestamptz)]
    expires_at: chrono::DateTime<chrono::Utc>,
}

impl From<CallSignalRelayRow> for CallSignalRelayRecord {
    fn from(row: CallSignalRelayRow) -> Self {
        Self {
            realm_id: row.realm_id,
            sender_actor: row.sender_actor,
            sender_device: row.sender_device,
            call_id: row.call_id,
            expires_at: row.expires_at,
            envelope: row.envelope,
            position: row.position.max(0) as u64,
        }
    }
}

#[derive(QueryableByName)]
struct CallSignalWatermarkRow {
    #[diesel(sql_type = BigInt)]
    delivered_through: i64,
}

#[async_trait]
impl CallSignalRelayStore for PgCallSignalRelayStore {
    async fn append(&self, mut record: CallSignalRelayRecord) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool).await?;
        // Assign the monotonic per-Realm position from a dedicated counter that
        // never decreases — even after the relay log is pruned — so a recycled
        // position can never re-cross a delivered-through watermark. The
        // `RETURNING` makes the read-increment atomic under concurrent appends.
        let position_row = sql_query(
            "INSERT INTO call_signal_relay_position (realm_id, next_position, updated_at) \
             VALUES ($1, 1, NOW()) \
             ON CONFLICT (realm_id) DO UPDATE SET \
                next_position = call_signal_relay_position.next_position + 1, \
                updated_at = NOW() \
             RETURNING next_position",
        )
        .bind::<Text, _>(&record.realm_id)
        .get_result::<CallSignalRelayPositionRow>(&mut *conn)
        .await
        .map_err(PersistenceError::from)?;
        let position = position_row.next_position;
        record.position = position.max(0) as u64;

        sql_query(
            "INSERT INTO call_signal_relay \
             (id, realm_id, position, sender_actor, sender_device, call_id, envelope, created_at, expires_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, NOW(), $8)",
        )
        .bind::<SqlUuid, _>(uuid::Uuid::now_v7())
        .bind::<Text, _>(&record.realm_id)
        .bind::<BigInt, _>(position)
        .bind::<Text, _>(&record.sender_actor)
        .bind::<Text, _>(&record.sender_device)
        .bind::<Text, _>(&record.call_id)
        .bind::<Jsonb, _>(&record.envelope)
        .bind::<Timestamptz, _>(record.expires_at)
        .execute(&mut *conn)
        .await
        .map_err(PersistenceError::from)?;

        // Bound retained signals per Realm to the most recent
        // `CALL_SIGNAL_RELAY_MAX_PER_REALM` (mirrors the in-memory cap) so a
        // burst cannot grow the table unboundedly; the counter is untouched so
        // positions stay monotonic.
        sql_query(
            "DELETE FROM call_signal_relay \
             WHERE realm_id = $1 AND position <= $2 - $3",
        )
        .bind::<Text, _>(&record.realm_id)
        .bind::<BigInt, _>(position)
        .bind::<BigInt, _>(CALL_SIGNAL_RELAY_MAX_PER_REALM as i64)
        .execute(&mut *conn)
        .await
        .map_err(PersistenceError::from)?;
        Ok(())
    }

    async fn list_for_realm(
        &self,
        realm_id: &str,
    ) -> PersistenceResult<Vec<CallSignalRelayRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        let rows = sql_query(
            "SELECT realm_id, position, sender_actor, sender_device, call_id, envelope, expires_at \
             FROM call_signal_relay \
             WHERE realm_id = $1 AND expires_at > NOW() \
             ORDER BY position ASC",
        )
        .bind::<Text, _>(realm_id)
        .load::<CallSignalRelayRow>(&mut *conn)
        .await
        .map_err(PersistenceError::from)?;
        Ok(rows.into_iter().map(CallSignalRelayRecord::from).collect())
    }

    async fn prune_expired(&self) -> PersistenceResult<usize> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query("DELETE FROM call_signal_relay WHERE expires_at <= NOW()")
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
            "SELECT delivered_through FROM call_signal_relay_watermark \
             WHERE actor_id = $1 AND device_id = $2 AND realm_id = $3",
        )
        .bind::<Text, _>(actor)
        .bind::<Text, _>(device)
        .bind::<Text, _>(realm_id)
        .get_result::<CallSignalWatermarkRow>(&mut *conn)
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
        // Monotonic: `GREATEST` on conflict keeps the highest position so a
        // lower (out-of-order / replayed) advance is ignored.
        sql_query(
            "INSERT INTO call_signal_relay_watermark \
             (actor_id, device_id, realm_id, delivered_through, updated_at) \
             VALUES ($1, $2, $3, $4, NOW()) \
             ON CONFLICT (actor_id, device_id, realm_id) DO UPDATE SET \
                delivered_through = GREATEST(call_signal_relay_watermark.delivered_through, EXCLUDED.delivered_through), \
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
