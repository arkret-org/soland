use super::*;

/// Trait for account storage operations.
#[async_trait]
pub trait AccountStore: Send + Sync {
    async fn get(&self, did: &str) -> PersistenceResult<Option<AccountRecord>>;
    async fn put(&self, record: &AccountRecord) -> PersistenceResult<()>;
    async fn list(&self) -> PersistenceResult<Vec<AccountRecord>>;
    async fn delete(&self, did: &str) -> PersistenceResult<()>;
}

/// Trait for actor-private account data storage.
///
/// `data_type` is the canonical wire key (e.g. `ck.contacts.actor.<did>`,
/// `ck.contacts.realm.<realm_id>`, `ck.read_receipt.preferences`). The
/// payload is opaque to the server — no schema validation runs here; the
/// client owns canonical encoding and (where applicable) encryption.
///
/// Spec: `discovery/client-preferences.md` §2 (storage model), §3.6
/// (actor remarks), §3.7 (Realm remarks).
#[async_trait]
pub trait AccountDataStore: Send + Sync {
    async fn get(
        &self,
        actor: &str,
        data_type: &str,
    ) -> PersistenceResult<Option<AccountDataRecord>>;
    async fn put(&self, record: &AccountDataRecord) -> PersistenceResult<()>;
    async fn delete(&self, actor: &str, data_type: &str) -> PersistenceResult<()>;
    async fn list_for_actor(&self, actor: &str) -> PersistenceResult<Vec<AccountDataRecord>>;
}

// In-memory account store
pub(crate) struct MemoryAccountStore {
    data: Arc<Mutex<BTreeMap<String, AccountRecord>>>,
}

impl MemoryAccountStore {
    pub(crate) fn new() -> Self {
        Self {
            data: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }
}

#[async_trait]
impl AccountStore for MemoryAccountStore {
    async fn get(&self, did: &str) -> PersistenceResult<Option<AccountRecord>> {
        let data = self.data.lock().expect("lock");
        Ok(data.get(did).cloned())
    }

    async fn put(&self, record: &AccountRecord) -> PersistenceResult<()> {
        let mut data = self.data.lock().expect("lock");
        data.insert(record.did.clone(), record.clone());
        Ok(())
    }

    async fn list(&self) -> PersistenceResult<Vec<AccountRecord>> {
        let data = self.data.lock().expect("lock");
        Ok(data.values().cloned().collect())
    }

    async fn delete(&self, did: &str) -> PersistenceResult<()> {
        let mut data = self.data.lock().expect("lock");
        data.remove(did);
        Ok(())
    }
}

// In-memory contact store
/// In-memory `(actor, data_type) -> AccountDataRecord` table. Mirrors the
/// `account_datas` Pg table on the same composite key.
pub(crate) struct MemoryAccountDataStore {
    data: Arc<Mutex<BTreeMap<(String, String), AccountDataRecord>>>,
}

impl MemoryAccountDataStore {
    pub(crate) fn new() -> Self {
        Self {
            data: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }
}

#[async_trait]
impl AccountDataStore for MemoryAccountDataStore {
    async fn get(
        &self,
        actor: &str,
        data_type: &str,
    ) -> PersistenceResult<Option<AccountDataRecord>> {
        let data = self.data.lock().expect("lock");
        Ok(data.get(&(actor.to_owned(), data_type.to_owned())).cloned())
    }

    async fn put(&self, record: &AccountDataRecord) -> PersistenceResult<()> {
        let mut data = self.data.lock().expect("lock");
        data.insert(
            (record.actor.clone(), record.data_type.clone()),
            record.clone(),
        );
        Ok(())
    }

    async fn delete(&self, actor: &str, data_type: &str) -> PersistenceResult<()> {
        let mut data = self.data.lock().expect("lock");
        data.remove(&(actor.to_owned(), data_type.to_owned()));
        Ok(())
    }

    async fn list_for_actor(&self, actor: &str) -> PersistenceResult<Vec<AccountDataRecord>> {
        let data = self.data.lock().expect("lock");
        Ok(data
            .iter()
            .filter(|((row_actor, _), _)| row_actor == actor)
            .map(|(_, record)| record.clone())
            .collect())
    }
}

pub(crate) struct PgAccountStore {
    pub(crate) pool: PgPool,
}

#[async_trait]
impl AccountStore for PgAccountStore {
    async fn get(&self, did: &str) -> PersistenceResult<Option<AccountRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "SELECT id, actor_id AS did, localpart, display_name, created_at FROM accounts WHERE actor_id = $1",
        )
        .bind::<Text, _>(did)
        .get_result::<AccountRow>(&mut *conn)
        .await
        .optional()
        .map(|row| row.map(AccountRecord::from))
        .map_err(PersistenceError::from)
    }

    async fn put(&self, record: &AccountRecord) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "INSERT INTO accounts (id, actor_id, localpart, display_name, payload, created_at, updated_at) \
             VALUES ($1, $2, $3, $4, '{}'::jsonb, $5, $5) \
             ON CONFLICT (actor_id) DO UPDATE SET localpart = EXCLUDED.localpart, \
             display_name = EXCLUDED.display_name, updated_at = NOW()",
        )
        .bind::<SqlUuid, _>(ids::typed_uuid_part_or_panic(&record.id))
        .bind::<Text, _>(&record.did)
        .bind::<Text, _>(&record.localpart)
        .bind::<Nullable<Text>, _>(&record.display_name)
        .bind::<Timestamptz, _>(record.created_at)
        .execute(&mut *conn)
        .await
        .map(|_| ())
        .map_err(PersistenceError::from)
    }

    async fn list(&self) -> PersistenceResult<Vec<AccountRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "SELECT id, actor_id AS did, localpart, display_name, created_at FROM accounts ORDER BY actor_id",
        )
        .load::<AccountRow>(&mut *conn)
        .await
        .map(|rows| rows.into_iter().map(AccountRecord::from).collect())
        .map_err(PersistenceError::from)
    }

    async fn delete(&self, did: &str) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query("DELETE FROM accounts WHERE actor = $1")
            .bind::<Text, _>(did)
            .execute(&mut *conn)
            .await
            .map(|_| ())
            .map_err(PersistenceError::from)
    }
}

pub(crate) struct PgAccountDataStore {
    pub(crate) pool: PgPool,
}

#[async_trait]
impl AccountDataStore for PgAccountDataStore {
    async fn get(
        &self,
        actor: &str,
        data_type: &str,
    ) -> PersistenceResult<Option<AccountDataRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "SELECT actor_id AS actor, data_type, payload, updated_at \
             FROM account_datas WHERE actor_id = $1 AND data_type = $2",
        )
        .bind::<Text, _>(actor)
        .bind::<Text, _>(data_type)
        .get_result::<AccountDataRow>(&mut *conn)
        .await
        .optional()
        .map(|row| row.map(AccountDataRecord::from))
        .map_err(PersistenceError::from)
    }

    async fn put(&self, record: &AccountDataRecord) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "INSERT INTO account_datas (id, actor_id, data_type, payload, updated_at) \
             VALUES ($1, $2, $3, $4, $5) \
             ON CONFLICT (actor_id, data_type) DO UPDATE SET payload = EXCLUDED.payload, \
             updated_at = EXCLUDED.updated_at",
        )
        .bind::<diesel::sql_types::Uuid, _>(uuid::Uuid::now_v7())
        .bind::<Text, _>(&record.actor)
        .bind::<Text, _>(&record.data_type)
        .bind::<Jsonb, _>(&record.payload)
        .bind::<Timestamptz, _>(record.updated_at)
        .execute(&mut *conn)
        .await
        .map(|_| ())
        .map_err(PersistenceError::from)
    }

    async fn delete(&self, actor: &str, data_type: &str) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query("DELETE FROM account_datas WHERE actor_id = $1 AND data_type = $2")
            .bind::<Text, _>(actor)
            .bind::<Text, _>(data_type)
            .execute(&mut *conn)
            .await
            .map(|_| ())
            .map_err(PersistenceError::from)
    }

    async fn list_for_actor(&self, actor: &str) -> PersistenceResult<Vec<AccountDataRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "SELECT actor_id AS actor, data_type, payload, updated_at \
             FROM account_datas WHERE actor_id = $1 ORDER BY data_type",
        )
        .bind::<Text, _>(actor)
        .load::<AccountDataRow>(&mut *conn)
        .await
        .map(|rows| rows.into_iter().map(AccountDataRecord::from).collect())
        .map_err(PersistenceError::from)
    }
}

#[derive(QueryableByName)]
struct AccountRow {
    #[diesel(sql_type = SqlUuid)]
    id: Uuid,
    #[diesel(sql_type = Text)]
    did: String,
    #[diesel(sql_type = Text)]
    localpart: String,
    #[diesel(sql_type = Nullable<Text>)]
    display_name: Option<String>,
    #[diesel(sql_type = Timestamptz)]
    created_at: chrono::DateTime<chrono::Utc>,
}

impl From<AccountRow> for AccountRecord {
    fn from(row: AccountRow) -> Self {
        Self {
            id: ids::format_typed_uuid("account", &row.id),
            did: row.did,
            localpart: row.localpart,
            display_name: row.display_name,
            // Pg backend doesn't carry bio / avatar_url yet — the Memory
            // store does. When the Pg projection lands, extend AccountRow
            // + this hydrate.
            bio: None,
            avatar_url: None,
            created_at: row.created_at,
        }
    }
}

#[derive(QueryableByName)]
struct AccountDataRow {
    #[diesel(sql_type = Text)]
    actor: String,
    #[diesel(sql_type = Text)]
    data_type: String,
    #[diesel(sql_type = Jsonb)]
    payload: Value,
    #[diesel(sql_type = Timestamptz)]
    updated_at: chrono::DateTime<chrono::Utc>,
}

impl From<AccountDataRow> for AccountDataRecord {
    fn from(row: AccountDataRow) -> Self {
        Self {
            actor: row.actor,
            data_type: row.data_type,
            payload: row.payload,
            updated_at: row.updated_at,
        }
    }
}
