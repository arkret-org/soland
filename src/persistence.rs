//! Persistence abstraction layer.
//!
//! Provides a trait-based interface for storage, allowing seamless switching
//! between in-memory and PostgreSQL backends.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use chrono::Utc;
use diesel::{
    OptionalExtension, QueryableByName, RunQueryDsl, sql_query,
    sql_types::{Jsonb, Nullable, Text, Timestamptz},
};
use serde_json::Value;

use crate::db::PgPool;
use crate::state::{
    AccountRecord, BlobRecord, ContactRecord, DeviceInventoryRecord, MessageRecord, SessionRecord,
    SpaceMetaRecord,
};

/// Error type for persistence operations.
#[derive(Debug, thiserror::Error)]
pub enum PersistenceError {
    #[error("not found: {0}")]
    NotFound(String),
    #[error("conflict: {0}")]
    Conflict(String),
    #[error("database error: {0}")]
    Database(#[from] diesel::result::Error),
    #[error("internal error: {0}")]
    Internal(String),
}

/// Result type for persistence operations.
pub type PersistenceResult<T> = Result<T, PersistenceError>;

/// Trait for account storage operations.
pub trait AccountStore: Send + Sync {
    fn get(&self, did: &str) -> PersistenceResult<Option<AccountRecord>>;
    fn put(&self, record: &AccountRecord) -> PersistenceResult<()>;
    fn list(&self) -> PersistenceResult<Vec<AccountRecord>>;
    fn delete(&self, did: &str) -> PersistenceResult<()>;
}

/// Trait for session storage operations.
pub trait SessionStore: Send + Sync {
    fn get(&self, token: &str) -> PersistenceResult<Option<SessionRecord>>;
    fn put(&self, record: &SessionRecord) -> PersistenceResult<()>;
    fn delete(&self, token: &str) -> PersistenceResult<()>;
    fn cleanup_expired(&self) -> PersistenceResult<usize>;
}

/// Trait for contact storage operations.
pub trait ContactStore: Send + Sync {
    fn get(&self, requester: &str, target: &str) -> PersistenceResult<Option<ContactRecord>>;
    fn put(&self, record: &ContactRecord) -> PersistenceResult<()>;
    fn list_for_actor(&self, actor: &str) -> PersistenceResult<Vec<ContactRecord>>;
    fn delete(&self, requester: &str, target: &str) -> PersistenceResult<()>;
}

/// Trait for space metadata storage operations.
pub trait SpaceMetaStore: Send + Sync {
    fn get(&self, space_id: &str) -> PersistenceResult<Option<SpaceMetaRecord>>;
    fn put(&self, space_id: &str, record: &SpaceMetaRecord) -> PersistenceResult<()>;
    fn list(&self) -> PersistenceResult<Vec<(String, SpaceMetaRecord)>>;
    fn delete(&self, space_id: &str) -> PersistenceResult<()>;
}

/// Trait for message storage operations.
pub trait MessageStore: Send + Sync {
    fn get(&self, event_id: &str) -> PersistenceResult<Option<MessageRecord>>;
    fn put(&self, record: &MessageRecord) -> PersistenceResult<()>;
    fn list_for_space(&self, space_id: &str, limit: usize)
    -> PersistenceResult<Vec<MessageRecord>>;
    fn list_for_thread(
        &self,
        thread_id: &str,
        limit: usize,
    ) -> PersistenceResult<Vec<MessageRecord>>;
    fn delete(&self, event_id: &str) -> PersistenceResult<()>;
}

/// Trait for blob storage operations.
pub trait BlobStore: Send + Sync {
    fn get(&self, blob_ref: &str) -> PersistenceResult<Option<BlobRecord>>;
    fn put(&self, blob_ref: &str, record: &BlobRecord) -> PersistenceResult<()>;
    fn delete(&self, blob_ref: &str) -> PersistenceResult<()>;
}

/// Trait for durable device inventory operations.
pub trait DeviceInventoryStore: Send + Sync {
    fn get(&self, actor: &str, device_id: &str)
    -> PersistenceResult<Option<DeviceInventoryRecord>>;
    fn put(&self, record: &DeviceInventoryRecord) -> PersistenceResult<()>;
    fn list_for_actor(&self, actor: &str) -> PersistenceResult<Vec<DeviceInventoryRecord>>;
    fn list(&self) -> PersistenceResult<Vec<DeviceInventoryRecord>>;
}

/// Combined persistence store trait.
pub trait PersistenceStore: Send + Sync {
    fn accounts(&self) -> &dyn AccountStore;
    fn sessions(&self) -> &dyn SessionStore;
    fn contacts(&self) -> &dyn ContactStore;
    fn space_meta(&self) -> &dyn SpaceMetaStore;
    fn messages(&self) -> &dyn MessageStore;
    fn blobs(&self) -> &dyn BlobStore;
    fn devices(&self) -> &dyn DeviceInventoryStore;
}

/// In-memory implementation of persistence store.
pub struct MemoryPersistenceStore {
    accounts: MemoryAccountStore,
    sessions: MemorySessionStore,
    contacts: MemoryContactStore,
    space_meta: MemorySpaceMetaStore,
    messages: MemoryMessageStore,
    blobs: MemoryBlobStore,
    devices: MemoryDeviceInventoryStore,
}

impl MemoryPersistenceStore {
    pub fn new() -> Self {
        Self {
            accounts: MemoryAccountStore::new(),
            sessions: MemorySessionStore::new(),
            contacts: MemoryContactStore::new(),
            space_meta: MemorySpaceMetaStore::new(),
            messages: MemoryMessageStore::new(),
            blobs: MemoryBlobStore::new(),
            devices: MemoryDeviceInventoryStore::new(),
        }
    }
}

impl Default for MemoryPersistenceStore {
    fn default() -> Self {
        Self::new()
    }
}

impl PersistenceStore for MemoryPersistenceStore {
    fn accounts(&self) -> &dyn AccountStore {
        &self.accounts
    }

    fn sessions(&self) -> &dyn SessionStore {
        &self.sessions
    }

    fn contacts(&self) -> &dyn ContactStore {
        &self.contacts
    }

    fn space_meta(&self) -> &dyn SpaceMetaStore {
        &self.space_meta
    }

    fn messages(&self) -> &dyn MessageStore {
        &self.messages
    }

    fn blobs(&self) -> &dyn BlobStore {
        &self.blobs
    }

    fn devices(&self) -> &dyn DeviceInventoryStore {
        &self.devices
    }
}

// In-memory account store
struct MemoryAccountStore {
    data: Arc<Mutex<BTreeMap<String, AccountRecord>>>,
}

impl MemoryAccountStore {
    fn new() -> Self {
        Self {
            data: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }
}

impl AccountStore for MemoryAccountStore {
    fn get(&self, did: &str) -> PersistenceResult<Option<AccountRecord>> {
        let data = self.data.lock().expect("lock");
        Ok(data.get(did).cloned())
    }

    fn put(&self, record: &AccountRecord) -> PersistenceResult<()> {
        let mut data = self.data.lock().expect("lock");
        data.insert(record.did.clone(), record.clone());
        Ok(())
    }

    fn list(&self) -> PersistenceResult<Vec<AccountRecord>> {
        let data = self.data.lock().expect("lock");
        Ok(data.values().cloned().collect())
    }

    fn delete(&self, did: &str) -> PersistenceResult<()> {
        let mut data = self.data.lock().expect("lock");
        data.remove(did);
        Ok(())
    }
}

// In-memory session store
struct MemorySessionStore {
    data: Arc<Mutex<BTreeMap<String, SessionRecord>>>,
}

impl MemorySessionStore {
    fn new() -> Self {
        Self {
            data: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }
}

impl SessionStore for MemorySessionStore {
    fn get(&self, token: &str) -> PersistenceResult<Option<SessionRecord>> {
        let data = self.data.lock().expect("lock");
        Ok(data.get(token).cloned())
    }

    fn put(&self, record: &SessionRecord) -> PersistenceResult<()> {
        let mut data = self.data.lock().expect("lock");
        data.insert(record.token_hash.clone(), record.clone());
        Ok(())
    }

    fn delete(&self, token: &str) -> PersistenceResult<()> {
        let mut data = self.data.lock().expect("lock");
        data.remove(token);
        Ok(())
    }

    fn cleanup_expired(&self) -> PersistenceResult<usize> {
        let mut data = self.data.lock().expect("lock");
        let now = Utc::now();
        let before = data.len();
        data.retain(|_, session| session.expires_at > now);
        Ok(before - data.len())
    }
}

// In-memory contact store
struct MemoryContactStore {
    data: Arc<Mutex<BTreeMap<(String, String), ContactRecord>>>,
}

impl MemoryContactStore {
    fn new() -> Self {
        Self {
            data: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }
}

impl ContactStore for MemoryContactStore {
    fn get(&self, requester: &str, target: &str) -> PersistenceResult<Option<ContactRecord>> {
        let data = self.data.lock().expect("lock");
        Ok(data
            .get(&(requester.to_owned(), target.to_owned()))
            .cloned())
    }

    fn put(&self, record: &ContactRecord) -> PersistenceResult<()> {
        let mut data = self.data.lock().expect("lock");
        data.insert(
            (record.requester.clone(), record.target.clone()),
            record.clone(),
        );
        Ok(())
    }

    fn list_for_actor(&self, actor: &str) -> PersistenceResult<Vec<ContactRecord>> {
        let data = self.data.lock().expect("lock");
        Ok(data
            .values()
            .filter(|c| c.requester == actor || c.target == actor)
            .cloned()
            .collect())
    }

    fn delete(&self, requester: &str, target: &str) -> PersistenceResult<()> {
        let mut data = self.data.lock().expect("lock");
        data.remove(&(requester.to_owned(), target.to_owned()));
        Ok(())
    }
}

// In-memory space meta store
struct MemorySpaceMetaStore {
    data: Arc<Mutex<BTreeMap<String, SpaceMetaRecord>>>,
}

impl MemorySpaceMetaStore {
    fn new() -> Self {
        Self {
            data: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }
}

impl SpaceMetaStore for MemorySpaceMetaStore {
    fn get(&self, space_id: &str) -> PersistenceResult<Option<SpaceMetaRecord>> {
        let data = self.data.lock().expect("lock");
        Ok(data.get(space_id).cloned())
    }

    fn put(&self, space_id: &str, record: &SpaceMetaRecord) -> PersistenceResult<()> {
        let mut data = self.data.lock().expect("lock");
        data.insert(space_id.to_owned(), record.clone());
        Ok(())
    }

    fn list(&self) -> PersistenceResult<Vec<(String, SpaceMetaRecord)>> {
        let data = self.data.lock().expect("lock");
        Ok(data.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
    }

    fn delete(&self, space_id: &str) -> PersistenceResult<()> {
        let mut data = self.data.lock().expect("lock");
        data.remove(space_id);
        Ok(())
    }
}

// In-memory message store
struct MemoryMessageStore {
    data: Arc<Mutex<Vec<MessageRecord>>>,
}

impl MemoryMessageStore {
    fn new() -> Self {
        Self {
            data: Arc::new(Mutex::new(Vec::new())),
        }
    }
}

impl MessageStore for MemoryMessageStore {
    fn get(&self, event_id: &str) -> PersistenceResult<Option<MessageRecord>> {
        let data = self.data.lock().expect("lock");
        Ok(data.iter().find(|m| m.event_id == event_id).cloned())
    }

    fn put(&self, record: &MessageRecord) -> PersistenceResult<()> {
        let mut data = self.data.lock().expect("lock");
        data.push(record.clone());
        Ok(())
    }

    fn list_for_space(
        &self,
        space_id: &str,
        limit: usize,
    ) -> PersistenceResult<Vec<MessageRecord>> {
        let data = self.data.lock().expect("lock");
        let messages: Vec<_> = data
            .iter()
            .filter(|m| m.space_id == space_id)
            .rev()
            .take(limit)
            .cloned()
            .collect();
        Ok(messages)
    }

    fn list_for_thread(
        &self,
        thread_id: &str,
        limit: usize,
    ) -> PersistenceResult<Vec<MessageRecord>> {
        let data = self.data.lock().expect("lock");
        let messages: Vec<_> = data
            .iter()
            .filter(|m| m.thread_id == thread_id)
            .rev()
            .take(limit)
            .cloned()
            .collect();
        Ok(messages)
    }

    fn delete(&self, event_id: &str) -> PersistenceResult<()> {
        let mut data = self.data.lock().expect("lock");
        data.retain(|m| m.event_id != event_id);
        Ok(())
    }
}

// In-memory blob store
struct MemoryBlobStore {
    data: Arc<Mutex<BTreeMap<String, BlobRecord>>>,
}

impl MemoryBlobStore {
    fn new() -> Self {
        Self {
            data: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }
}

impl BlobStore for MemoryBlobStore {
    fn get(&self, blob_ref: &str) -> PersistenceResult<Option<BlobRecord>> {
        let data = self.data.lock().expect("lock");
        Ok(data.get(blob_ref).cloned())
    }

    fn put(&self, blob_ref: &str, record: &BlobRecord) -> PersistenceResult<()> {
        let mut data = self.data.lock().expect("lock");
        data.insert(blob_ref.to_owned(), record.clone());
        Ok(())
    }

    fn delete(&self, blob_ref: &str) -> PersistenceResult<()> {
        let mut data = self.data.lock().expect("lock");
        data.remove(blob_ref);
        Ok(())
    }
}

// In-memory device inventory store
struct MemoryDeviceInventoryStore {
    data: Arc<Mutex<BTreeMap<(String, String), DeviceInventoryRecord>>>,
}

impl MemoryDeviceInventoryStore {
    fn new() -> Self {
        Self {
            data: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }
}

impl DeviceInventoryStore for MemoryDeviceInventoryStore {
    fn get(
        &self,
        actor: &str,
        device_id: &str,
    ) -> PersistenceResult<Option<DeviceInventoryRecord>> {
        let data = self.data.lock().expect("lock");
        Ok(data.get(&(actor.to_owned(), device_id.to_owned())).cloned())
    }

    fn put(&self, record: &DeviceInventoryRecord) -> PersistenceResult<()> {
        let mut data = self.data.lock().expect("lock");
        data.insert(
            (record.actor.clone(), record.device_id.clone()),
            record.clone(),
        );
        Ok(())
    }

    fn list_for_actor(&self, actor: &str) -> PersistenceResult<Vec<DeviceInventoryRecord>> {
        let data = self.data.lock().expect("lock");
        Ok(data
            .values()
            .filter(|record| record.actor == actor && record.revoked_at.is_none())
            .cloned()
            .collect())
    }

    fn list(&self) -> PersistenceResult<Vec<DeviceInventoryRecord>> {
        let data = self.data.lock().expect("lock");
        Ok(data
            .values()
            .filter(|record| record.revoked_at.is_none())
            .cloned()
            .collect())
    }
}

/// PostgreSQL-backed persistence store for the P0 durable account/session/device path.
///
/// TODO(P0 durable-state): move contacts, spaces, messages, blobs, push, presence,
/// policy, audit, federation and sync positions from the memory stores below into
/// Pg-backed stores with shared behavior tests.
pub struct PgPersistenceStore {
    accounts: PgAccountStore,
    sessions: PgSessionStore,
    devices: PgDeviceInventoryStore,
    fallback: MemoryPersistenceStore,
}

impl PgPersistenceStore {
    pub fn new(pool: PgPool) -> Self {
        Self {
            accounts: PgAccountStore { pool: pool.clone() },
            sessions: PgSessionStore { pool: pool.clone() },
            devices: PgDeviceInventoryStore { pool },
            fallback: MemoryPersistenceStore::new(),
        }
    }
}

impl PersistenceStore for PgPersistenceStore {
    fn accounts(&self) -> &dyn AccountStore {
        &self.accounts
    }

    fn sessions(&self) -> &dyn SessionStore {
        &self.sessions
    }

    fn contacts(&self) -> &dyn ContactStore {
        self.fallback.contacts()
    }

    fn space_meta(&self) -> &dyn SpaceMetaStore {
        self.fallback.space_meta()
    }

    fn messages(&self) -> &dyn MessageStore {
        self.fallback.messages()
    }

    fn blobs(&self) -> &dyn BlobStore {
        self.fallback.blobs()
    }

    fn devices(&self) -> &dyn DeviceInventoryStore {
        &self.devices
    }
}

struct PgAccountStore {
    pool: PgPool,
}

impl AccountStore for PgAccountStore {
    fn get(&self, did: &str) -> PersistenceResult<Option<AccountRecord>> {
        let mut conn = pg_conn(&self.pool)?;
        sql_query(
            "SELECT actor AS did, handle, display_name, created_at FROM accounts WHERE actor = $1",
        )
        .bind::<Text, _>(did)
        .get_result::<AccountRow>(&mut conn)
        .optional()
        .map(|row| row.map(AccountRecord::from))
        .map_err(PersistenceError::from)
    }

    fn put(&self, record: &AccountRecord) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool)?;
        sql_query(
            "INSERT INTO accounts (actor, handle, display_name, payload, created_at, updated_at) \
             VALUES ($1, $2, $3, '{}'::jsonb, $4, $4) \
             ON CONFLICT (actor) DO UPDATE SET handle = EXCLUDED.handle, \
             display_name = EXCLUDED.display_name, updated_at = NOW()",
        )
        .bind::<Text, _>(&record.did)
        .bind::<Text, _>(&record.handle)
        .bind::<Nullable<Text>, _>(&record.display_name)
        .bind::<Timestamptz, _>(record.created_at)
        .execute(&mut conn)
        .map(|_| ())
        .map_err(PersistenceError::from)
    }

    fn list(&self) -> PersistenceResult<Vec<AccountRecord>> {
        let mut conn = pg_conn(&self.pool)?;
        sql_query(
            "SELECT actor AS did, handle, display_name, created_at FROM accounts ORDER BY actor",
        )
        .load::<AccountRow>(&mut conn)
        .map(|rows| rows.into_iter().map(AccountRecord::from).collect())
        .map_err(PersistenceError::from)
    }

    fn delete(&self, did: &str) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool)?;
        sql_query("DELETE FROM accounts WHERE actor = $1")
            .bind::<Text, _>(did)
            .execute(&mut conn)
            .map(|_| ())
            .map_err(PersistenceError::from)
    }
}

struct PgSessionStore {
    pool: PgPool,
}

impl SessionStore for PgSessionStore {
    fn get(&self, token: &str) -> PersistenceResult<Option<SessionRecord>> {
        let mut conn = pg_conn(&self.pool)?;
        sql_query(
            "SELECT token_hash, actor, device_id, audience, expires_at, created_at, revoked_at \
             FROM sessions WHERE token_hash = $1",
        )
        .bind::<Text, _>(token)
        .get_result::<SessionRow>(&mut conn)
        .optional()
        .map(|row| row.map(SessionRecord::from))
        .map_err(PersistenceError::from)
    }

    fn put(&self, record: &SessionRecord) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool)?;
        sql_query(
            "INSERT INTO sessions (token_hash, actor, device_id, audience, payload, expires_at, revoked_at, created_at, updated_at) \
             VALUES ($1, $2, $3, $4, '{}'::jsonb, $5, $6, $7, NOW()) \
             ON CONFLICT (token_hash) DO UPDATE SET actor = EXCLUDED.actor, device_id = EXCLUDED.device_id, \
             audience = EXCLUDED.audience, expires_at = EXCLUDED.expires_at, revoked_at = EXCLUDED.revoked_at, updated_at = NOW()",
        )
        .bind::<Text, _>(&record.token_hash)
        .bind::<Text, _>(&record.actor)
        .bind::<Text, _>(&record.device_id)
        .bind::<Text, _>(&record.audience)
        .bind::<Timestamptz, _>(record.expires_at)
        .bind::<Nullable<Timestamptz>, _>(record.revoked_at)
        .bind::<Timestamptz, _>(record.created_at)
        .execute(&mut conn)
        .map(|_| ())
        .map_err(PersistenceError::from)
    }

    fn delete(&self, token: &str) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool)?;
        sql_query("DELETE FROM sessions WHERE token_hash = $1")
            .bind::<Text, _>(token)
            .execute(&mut conn)
            .map(|_| ())
            .map_err(PersistenceError::from)
    }

    fn cleanup_expired(&self) -> PersistenceResult<usize> {
        let mut conn = pg_conn(&self.pool)?;
        sql_query("DELETE FROM sessions WHERE expires_at <= NOW()")
            .execute(&mut conn)
            .map_err(PersistenceError::from)
    }
}

struct PgDeviceInventoryStore {
    pool: PgPool,
}

impl DeviceInventoryStore for PgDeviceInventoryStore {
    fn get(
        &self,
        actor: &str,
        device_id: &str,
    ) -> PersistenceResult<Option<DeviceInventoryRecord>> {
        let mut conn = pg_conn(&self.pool)?;
        sql_query(
            "SELECT actor, device_id, payload, verification_state, created_at, updated_at, revoked_at \
             FROM devices WHERE actor = $1 AND device_id = $2 AND revoked_at IS NULL",
        )
            .bind::<Text, _>(actor)
            .bind::<Text, _>(device_id)
            .get_result::<DeviceRow>(&mut conn)
            .optional()
            .map(|row| row.map(DeviceInventoryRecord::from))
            .map_err(PersistenceError::from)
    }

    fn put(&self, record: &DeviceInventoryRecord) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool)?;
        sql_query(
            "INSERT INTO devices (actor, device_id, payload, verification_state, created_at, updated_at, revoked_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7) \
             ON CONFLICT (actor, device_id) DO UPDATE SET payload = EXCLUDED.payload, \
             verification_state = EXCLUDED.verification_state, updated_at = EXCLUDED.updated_at, revoked_at = EXCLUDED.revoked_at",
        )
        .bind::<Text, _>(&record.actor)
        .bind::<Text, _>(&record.device_id)
        .bind::<Jsonb, _>(&record.payload)
        .bind::<Text, _>(&record.verification_state)
        .bind::<Timestamptz, _>(record.created_at)
        .bind::<Timestamptz, _>(record.updated_at)
        .bind::<Nullable<Timestamptz>, _>(record.revoked_at)
        .execute(&mut conn)
        .map(|_| ())
        .map_err(PersistenceError::from)
    }

    fn list_for_actor(&self, actor: &str) -> PersistenceResult<Vec<DeviceInventoryRecord>> {
        let mut conn = pg_conn(&self.pool)?;
        let rows = sql_query(
            "SELECT actor, device_id, payload, verification_state, created_at, updated_at, revoked_at \
             FROM devices WHERE actor = $1 AND revoked_at IS NULL ORDER BY device_id",
        )
        .bind::<Text, _>(actor)
        .load::<DeviceRow>(&mut conn)
        .map_err(PersistenceError::from)?;
        Ok(rows.into_iter().map(DeviceInventoryRecord::from).collect())
    }

    fn list(&self) -> PersistenceResult<Vec<DeviceInventoryRecord>> {
        let mut conn = pg_conn(&self.pool)?;
        let rows = sql_query(
            "SELECT actor, device_id, payload, verification_state, created_at, updated_at, revoked_at \
             FROM devices WHERE revoked_at IS NULL ORDER BY actor, device_id",
        )
        .load::<DeviceRow>(&mut conn)
        .map_err(PersistenceError::from)?;
        Ok(rows.into_iter().map(DeviceInventoryRecord::from).collect())
    }
}

#[derive(QueryableByName)]
struct AccountRow {
    #[diesel(sql_type = Text)]
    did: String,
    #[diesel(sql_type = Text)]
    handle: String,
    #[diesel(sql_type = Nullable<Text>)]
    display_name: Option<String>,
    #[diesel(sql_type = Timestamptz)]
    created_at: chrono::DateTime<chrono::Utc>,
}

impl From<AccountRow> for AccountRecord {
    fn from(row: AccountRow) -> Self {
        Self {
            did: row.did,
            handle: row.handle,
            display_name: row.display_name,
            created_at: row.created_at,
        }
    }
}

#[derive(QueryableByName)]
struct SessionRow {
    #[diesel(sql_type = Text)]
    token_hash: String,
    #[diesel(sql_type = Text)]
    actor: String,
    #[diesel(sql_type = Text)]
    device_id: String,
    #[diesel(sql_type = Text)]
    audience: String,
    #[diesel(sql_type = Timestamptz)]
    expires_at: chrono::DateTime<chrono::Utc>,
    #[diesel(sql_type = Timestamptz)]
    created_at: chrono::DateTime<chrono::Utc>,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    revoked_at: Option<chrono::DateTime<chrono::Utc>>,
}

impl From<SessionRow> for SessionRecord {
    fn from(row: SessionRow) -> Self {
        Self {
            token_hash: row.token_hash,
            actor: row.actor,
            device_id: row.device_id,
            audience: row.audience,
            expires_at: row.expires_at,
            created_at: row.created_at,
            revoked_at: row.revoked_at,
        }
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

fn pg_conn(
    pool: &PgPool,
) -> PersistenceResult<
    diesel::r2d2::PooledConnection<diesel::r2d2::ConnectionManager<diesel::PgConnection>>,
> {
    pool.get()
        .map_err(|error| PersistenceError::Internal(format!("database pool error: {error}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_account_store_crud() {
        let store = MemoryAccountStore::new();
        let record = AccountRecord {
            did: "did:web:test".to_owned(),
            handle: "@test".to_owned(),
            display_name: Some("Test".to_owned()),
            created_at: Utc::now(),
        };

        // Create
        store.put(&record).unwrap();

        // Read
        let fetched = store.get("did:web:test").unwrap().unwrap();
        assert_eq!(fetched.did, "did:web:test");

        // List
        let all = store.list().unwrap();
        assert_eq!(all.len(), 1);

        // Delete
        store.delete("did:web:test").unwrap();
        assert!(store.get("did:web:test").unwrap().is_none());
    }

    #[test]
    fn memory_session_store_expiry() {
        let store = MemorySessionStore::new();
        let expired = SessionRecord {
            token_hash: "expired".to_owned(),
            actor: "did:web:test".to_owned(),
            device_id: "dev".to_owned(),
            audience: "did:web:soland.local".to_owned(),
            expires_at: Utc::now() - chrono::Duration::hours(1),
            created_at: Utc::now() - chrono::Duration::hours(2),
            revoked_at: None,
        };
        let valid = SessionRecord {
            token_hash: "valid".to_owned(),
            actor: "did:web:test".to_owned(),
            device_id: "dev".to_owned(),
            audience: "did:web:soland.local".to_owned(),
            expires_at: Utc::now() + chrono::Duration::hours(1),
            created_at: Utc::now(),
            revoked_at: None,
        };

        store.put(&expired).unwrap();
        store.put(&valid).unwrap();

        let cleaned = store.cleanup_expired().unwrap();
        assert_eq!(cleaned, 1);
        assert!(store.get("expired").unwrap().is_none());
        assert!(store.get("valid").unwrap().is_some());
    }

    #[test]
    fn memory_contact_store_filtering() {
        let store = MemoryContactStore::new();
        let now = Utc::now();

        store
            .put(&ContactRecord {
                requester: "alice".to_owned(),
                target: "bob".to_owned(),
                status: "accepted".to_owned(),
                created_at: now,
                updated_at: now,
            })
            .unwrap();

        store
            .put(&ContactRecord {
                requester: "charlie".to_owned(),
                target: "alice".to_owned(),
                status: "pending".to_owned(),
                created_at: now,
                updated_at: now,
            })
            .unwrap();

        let alice_contacts = store.list_for_actor("alice").unwrap();
        assert_eq!(alice_contacts.len(), 2);

        let bob_contacts = store.list_for_actor("bob").unwrap();
        assert_eq!(bob_contacts.len(), 1);
    }

    #[test]
    fn memory_device_inventory_store_crud() {
        let store = MemoryDeviceInventoryStore::new();
        let now = Utc::now();
        let record = DeviceInventoryRecord {
            actor: "did:web:test".to_owned(),
            device_id: "DEVICE".to_owned(),
            display_name: Some("Phone".to_owned()),
            verification_state: "unverified".to_owned(),
            payload: serde_json::json!({
            "device_id": "DEVICE",
            "display_name": "Phone",
            "verification": "unverified",
            }),
            created_at: now,
            updated_at: now,
            revoked_at: None,
        };

        store.put(&record).unwrap();

        assert_eq!(
            store
                .get("did:web:test", "DEVICE")
                .unwrap()
                .unwrap()
                .device_id,
            "DEVICE"
        );
        assert_eq!(store.list_for_actor("did:web:test").unwrap().len(), 1);
        assert_eq!(store.list().unwrap().len(), 1);
    }
}
