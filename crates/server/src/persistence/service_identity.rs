use arkret_sdk::StoredServiceIdentity;

use super::*;

/// Persistence for the deployment's SDK-defined, verified service identity.
///
/// The singleton row contains only public evidence and opaque `KeyRef`s. Secret
/// signing/control material belongs to the configured SDK `KeyStore` and MUST
/// never be copied into PostgreSQL.
#[async_trait]
pub trait ServiceIdentityStore: Send + Sync {
    async fn get(&self) -> PersistenceResult<Option<StoredServiceIdentity>>;
    async fn put(&self, identity: StoredServiceIdentity) -> PersistenceResult<()>;
}

/// Fixed primary key for the singleton service-identity row.
const SINGLETON_ID: &str = "self";

#[derive(Default)]
pub(crate) struct MemoryServiceIdentityStore {
    row: Mutex<Option<StoredServiceIdentity>>,
}

impl MemoryServiceIdentityStore {
    pub(crate) fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl ServiceIdentityStore for MemoryServiceIdentityStore {
    async fn get(&self) -> PersistenceResult<Option<StoredServiceIdentity>> {
        Ok(self.row.lock().clone())
    }

    async fn put(&self, identity: StoredServiceIdentity) -> PersistenceResult<()> {
        *self.row.lock() = Some(identity);
        Ok(())
    }
}

pub(crate) struct PgServiceIdentityStore {
    pub(crate) pool: PgPool,
}

#[derive(QueryableByName)]
struct ServiceIdentityRow {
    #[diesel(sql_type = Jsonb)]
    identity: Value,
}

impl TryFrom<ServiceIdentityRow> for StoredServiceIdentity {
    type Error = PersistenceError;

    fn try_from(row: ServiceIdentityRow) -> Result<Self, Self::Error> {
        let identity: StoredServiceIdentity = serde_json::from_value(row.identity)
            .map_err(|error| PersistenceError::Internal(error.to_string()))?;
        identity
            .validate()
            .map_err(|error| PersistenceError::Internal(error.to_string()))?;
        Ok(identity)
    }
}

#[async_trait]
impl ServiceIdentityStore for PgServiceIdentityStore {
    async fn get(&self) -> PersistenceResult<Option<StoredServiceIdentity>> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query("SELECT identity FROM service_identity WHERE id = $1")
            .bind::<Text, _>(SINGLETON_ID)
            .get_result::<ServiceIdentityRow>(&mut *conn)
            .await
            .optional()
            .map_err(PersistenceError::from)?
            .map(StoredServiceIdentity::try_from)
            .transpose()
    }

    async fn put(&self, identity: StoredServiceIdentity) -> PersistenceResult<()> {
        identity
            .validate()
            .map_err(|error| PersistenceError::Internal(error.to_string()))?;
        let value = serde_json::to_value(&identity)
            .map_err(|error| PersistenceError::Internal(error.to_string()))?;
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "INSERT INTO service_identity (id, identity) VALUES ($1, $2) \
             ON CONFLICT (id) DO UPDATE SET identity = EXCLUDED.identity",
        )
        .bind::<Text, _>(SINGLETON_ID)
        .bind::<Jsonb, _>(&value)
        .execute(&mut *conn)
        .await
        .map(|_| ())
        .map_err(PersistenceError::from)
    }
}
