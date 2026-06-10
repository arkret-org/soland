use super::*;

/// Presence (online/away/dnd) per actor.
#[async_trait]
pub trait PresenceStore: Send + Sync {
    async fn put(&self, presence: PresenceRecord) -> PersistenceResult<()>;
    #[allow(dead_code)]
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
