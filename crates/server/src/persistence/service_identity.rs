use chrono::DateTime;

use super::*;

/// The deployment's own authoritative service identity (identity-did.md §3.7).
///
/// Singleton: at most one row, keyed by the fixed id [`SINGLETON_ID`]. This row
/// is the fail-closed source of truth for `service_did`; a configured
/// `SOLAND_SERVICE_DID` that disagrees with it MUST reject startup (I-2).
#[derive(Debug, Clone)]
pub struct ServiceIdentityRecord {
    pub service_did: String,
    /// `"bootstrapped_local"` — soland self-minted its `did:webvh` and hosts the
    /// log — or `"adopted_config"` — a pre-existing / external `service_did`
    /// recorded from config on first boot.
    pub provenance: String,
    /// The minted DID document for a locally bootstrapped identity; `{}` for an
    /// adopted external identity whose document lives at its own host.
    pub did_document: Value,
    /// Multibase-encoded ed25519 update-key seed for future rotation of a
    /// locally minted DID; `None` for adopted identities (their keys live
    /// elsewhere) and — for now — for freshly minted identities until the
    /// update key is persisted through the platform KeyStore (follow-up).
    pub update_key_seed_multibase: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// Persistence for the singleton [`ServiceIdentityRecord`].
#[async_trait]
pub trait ServiceIdentityStore: Send + Sync {
    async fn get(&self) -> PersistenceResult<Option<ServiceIdentityRecord>>;
    async fn put(&self, record: ServiceIdentityRecord) -> PersistenceResult<()>;
}

/// Fixed primary key for the singleton service-identity row.
const SINGLETON_ID: &str = "self";

#[derive(Default)]
pub(crate) struct MemoryServiceIdentityStore {
    row: Mutex<Option<ServiceIdentityRecord>>,
}

impl MemoryServiceIdentityStore {
    pub(crate) fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl ServiceIdentityStore for MemoryServiceIdentityStore {
    async fn get(&self) -> PersistenceResult<Option<ServiceIdentityRecord>> {
        Ok(self.row.lock().clone())
    }

    async fn put(&self, record: ServiceIdentityRecord) -> PersistenceResult<()> {
        *self.row.lock() = Some(record);
        Ok(())
    }
}

pub(crate) struct PgServiceIdentityStore {
    pub(crate) pool: PgPool,
}

#[derive(QueryableByName)]
struct ServiceIdentityRow {
    #[diesel(sql_type = Text)]
    service_did: String,
    #[diesel(sql_type = Text)]
    provenance: String,
    #[diesel(sql_type = Jsonb)]
    did_document: Value,
    #[diesel(sql_type = Nullable<Text>)]
    update_key_seed_multibase: Option<String>,
    #[diesel(sql_type = Timestamptz)]
    created_at: DateTime<Utc>,
}

impl From<ServiceIdentityRow> for ServiceIdentityRecord {
    fn from(row: ServiceIdentityRow) -> Self {
        Self {
            service_did: row.service_did,
            provenance: row.provenance,
            did_document: row.did_document,
            update_key_seed_multibase: row.update_key_seed_multibase,
            created_at: row.created_at,
        }
    }
}

#[async_trait]
impl ServiceIdentityStore for PgServiceIdentityStore {
    async fn get(&self) -> PersistenceResult<Option<ServiceIdentityRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "SELECT service_did, provenance, did_document, update_key_seed_multibase, created_at \
             FROM service_identity WHERE id = $1",
        )
        .bind::<Text, _>(SINGLETON_ID)
        .get_result::<ServiceIdentityRow>(&mut *conn)
        .await
        .optional()
        .map(|row| row.map(ServiceIdentityRecord::from))
        .map_err(PersistenceError::from)
    }

    async fn put(&self, record: ServiceIdentityRecord) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "INSERT INTO service_identity \
             (id, service_did, provenance, did_document, update_key_seed_multibase, created_at) \
             VALUES ($1, $2, $3, $4, $5, $6) \
             ON CONFLICT (id) DO UPDATE SET \
                service_did = EXCLUDED.service_did, \
                provenance = EXCLUDED.provenance, \
                did_document = EXCLUDED.did_document, \
                update_key_seed_multibase = EXCLUDED.update_key_seed_multibase, \
                created_at = EXCLUDED.created_at",
        )
        .bind::<Text, _>(SINGLETON_ID)
        .bind::<Text, _>(&record.service_did)
        .bind::<Text, _>(&record.provenance)
        .bind::<Jsonb, _>(&record.did_document)
        .bind::<Nullable<Text>, _>(&record.update_key_seed_multibase)
        .bind::<Timestamptz, _>(record.created_at)
        .execute(&mut *conn)
        .await
        .map(|_| ())
        .map_err(PersistenceError::from)
    }
}
