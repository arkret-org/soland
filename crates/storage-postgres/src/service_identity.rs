use arkret_sdk::StoredServiceIdentity;

use super::{
    Jsonb, OptionalExtension, PersistenceError, PersistenceResult, PgPool, QueryableByName,
    RunQueryDsl, SINGLETON_ID, ServiceIdentityStore, Text, Value, async_trait, pg_conn, sql_query,
};
pub struct PgServiceIdentityStore {
    pub pool: PgPool,
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
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query("SELECT identity FROM service_identity WHERE id = $1")
            .bind::<Text, _>(SINGLETON_ID)
            .get_result::<ServiceIdentityRow>(&mut *conn)
            .await
            .optional()
            .map_err(PersistenceError::database)?
            .map(StoredServiceIdentity::try_from)
            .transpose()
    }

    async fn put(&self, identity: StoredServiceIdentity) -> PersistenceResult<()> {
        identity
            .validate()
            .map_err(|error| PersistenceError::Internal(error.to_string()))?;
        let value = serde_json::to_value(&identity)
            .map_err(|error| PersistenceError::Internal(error.to_string()))?;
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(
            "INSERT INTO service_identity (id, identity) VALUES ($1, $2) \
             ON CONFLICT (id) DO UPDATE SET identity = EXCLUDED.identity",
        )
        .bind::<Text, _>(SINGLETON_ID)
        .bind::<Jsonb, _>(&value)
        .execute(&mut *conn)
        .await
        .map(|_| ())
        .map_err(PersistenceError::database)
    }
}
