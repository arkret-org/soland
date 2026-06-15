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
#[async_trait]
pub trait CallSignalRelayStore: Send + Sync {
    async fn append(&self, record: CallSignalRelayRecord) -> PersistenceResult<()>;
    async fn list_for_realm(&self, realm_id: &str)
    -> PersistenceResult<Vec<CallSignalRelayRecord>>;
    async fn prune_expired(&self) -> PersistenceResult<usize>;
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
}

impl MemoryCallSignalRelayStore {
    pub(crate) fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl CallSignalRelayStore for MemoryCallSignalRelayStore {
    async fn append(&self, record: CallSignalRelayRecord) -> PersistenceResult<()> {
        let now = Utc::now();
        let realm_id = record.realm_id.clone();
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
