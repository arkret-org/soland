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
