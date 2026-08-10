use arkret_identity::service_identity::StoredServiceIdentity;
use arkret_models_identity::ServiceResolutionRecord;
use arkret_wire::Hash;

use super::{
    Bool, Jsonb, Nullable, OptionalExtension, PersistenceError, PersistenceResult, PgPool,
    QueryableByName, RunQueryDsl, SINGLETON_ID, ServiceIdentityStore, Text, Value, async_trait,
    pg_conn, sql_query,
};
pub struct PgServiceIdentityStore {
    pub pool: PgPool,
}
#[derive(QueryableByName)]
struct ServiceIdentityRow {
    #[diesel(sql_type = Jsonb)]
    identity: Value,
}

#[derive(QueryableByName)]
struct ServiceResolutionRow {
    #[diesel(sql_type = Nullable<Jsonb>)]
    resolution: Option<Value>,
}

#[derive(QueryableByName)]
struct AppliedRow {
    #[diesel(sql_type = Bool)]
    applied: bool,
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

    async fn get_resolution(&self) -> PersistenceResult<Option<ServiceResolutionRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let row = sql_query("SELECT resolution FROM service_identity WHERE id = $1")
            .bind::<Text, _>(SINGLETON_ID)
            .get_result::<ServiceResolutionRow>(&mut *conn)
            .await
            .optional()
            .map_err(PersistenceError::database)?;
        row.and_then(|row| row.resolution)
            .map(serde_json::from_value)
            .transpose()
            .map_err(|error| PersistenceError::Internal(error.to_string()))
    }

    async fn compare_and_set_resolution(
        &self,
        expected_digest: Option<&Hash>,
        record: ServiceResolutionRecord,
    ) -> PersistenceResult<bool> {
        let value = serde_json::to_value(&record)
            .map_err(|error| PersistenceError::Internal(error.to_string()))?;
        let digest = Hash::new(
            arkret_canonical::canonical_sha256(&record)
                .map_err(|error| PersistenceError::Internal(error.to_string()))?,
        )
        .map_err(|error| PersistenceError::Internal(error.to_string()))?;
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(
            "WITH updated AS (\
               UPDATE service_identity SET resolution = $2, resolution_digest = $3 \
               WHERE id = $1 AND (($4 IS NULL AND resolution_digest IS NULL) OR resolution_digest = $4) \
               RETURNING 1\
             ) SELECT EXISTS(SELECT 1 FROM updated) AS applied",
        )
        .bind::<Text, _>(SINGLETON_ID)
        .bind::<Jsonb, _>(&value)
        .bind::<Text, _>(digest.as_str())
        .bind::<Nullable<Text>, _>(expected_digest.map(Hash::as_str))
        .get_result::<AppliedRow>(&mut *conn)
        .await
        .map(|row| row.applied)
        .map_err(PersistenceError::database)
    }
}
