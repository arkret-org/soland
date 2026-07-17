use super::{
    CountRow, DriftResult, JsonPayloadRow, Jsonb, Nullable, OptionalExtension,
    OutboundPushBridgeCacheRecord, PersistenceError, PersistenceResult, PgPool,
    PushBridgeCacheStore, PushDeviceStore, QueryableByName, RunQueryDsl, Text, Timestamptz, Value,
    async_trait, evaluate_drift, pg_conn, sql_query,
};
pub struct PgPushBridgeCacheStore {
    pub pool: PgPool,
}
#[async_trait]
impl PushBridgeCacheStore for PgPushBridgeCacheStore {
    async fn get(
        &self,
        bridge_describe_url: &str,
    ) -> PersistenceResult<Option<OutboundPushBridgeCacheRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(
            "SELECT push_gateway_url, service_base_url, bridge_describe_url, fetch_state, \
             cache_state, contract_digest, fetched_at, remote_contract, \
             trust_level, freshness_at, etag \
             FROM push_bridge_cache WHERE id = $1",
        )
        .bind::<Text, _>(bridge_describe_url)
        .get_result::<PushBridgeCacheRow>(&mut *conn)
        .await
        .optional()
        .map(|row| row.map(OutboundPushBridgeCacheRecord::from))
        .map_err(PersistenceError::database)
    }

    async fn put(
        &self,
        bridge_describe_url: &str,
        record: OutboundPushBridgeCacheRecord,
    ) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(
            "INSERT INTO push_bridge_cache \
             (id, push_gateway_url, service_base_url, bridge_describe_url, fetch_state, \
              cache_state, contract_digest, fetched_at, remote_contract, \
              trust_level, freshness_at, etag, updated_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, NOW()) \
             ON CONFLICT (id) DO UPDATE SET \
                push_gateway_url = EXCLUDED.push_gateway_url, \
                service_base_url = EXCLUDED.service_base_url, \
                bridge_describe_url = EXCLUDED.bridge_describe_url, \
                fetch_state = EXCLUDED.fetch_state, \
                cache_state = EXCLUDED.cache_state, \
                contract_digest = EXCLUDED.contract_digest, \
                fetched_at = EXCLUDED.fetched_at, \
                remote_contract = EXCLUDED.remote_contract, \
                trust_level = EXCLUDED.trust_level, \
                freshness_at = EXCLUDED.freshness_at, \
                etag = EXCLUDED.etag, \
                updated_at = NOW()",
        )
        .bind::<Text, _>(bridge_describe_url)
        .bind::<Text, _>(&record.push_gateway_url)
        .bind::<Text, _>(&record.service_base_url)
        .bind::<Text, _>(&record.bridge_describe_url)
        .bind::<Text, _>(&record.fetch_state)
        .bind::<Text, _>(&record.cache_state)
        .bind::<Text, _>(&record.contract_digest)
        .bind::<Timestamptz, _>(record.fetched_at)
        .bind::<Jsonb, _>(&record.remote_contract)
        .bind::<Text, _>(&record.trust_level)
        .bind::<Timestamptz, _>(record.freshness_at)
        .bind::<Text, _>(&record.etag)
        .execute(&mut *conn)
        .await
        .map(|_| ())
        .map_err(PersistenceError::database)
    }

    async fn delete(&self, bridge_describe_url: &str) -> PersistenceResult<bool> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query("DELETE FROM push_bridge_cache WHERE id = $1")
            .bind::<Text, _>(bridge_describe_url)
            .execute(&mut *conn)
            .await
            .map(|affected| affected > 0)
            .map_err(PersistenceError::database)
    }

    async fn clear(&self) -> PersistenceResult<usize> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query("DELETE FROM push_bridge_cache")
            .execute(&mut *conn)
            .await
            .map_err(PersistenceError::database)
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<OutboundPushBridgeCacheRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(
            "SELECT push_gateway_url, service_base_url, bridge_describe_url, fetch_state, \
             cache_state, contract_digest, fetched_at, remote_contract, \
             trust_level, freshness_at, etag \
             FROM push_bridge_cache ORDER BY id",
        )
        .load::<PushBridgeCacheRow>(&mut *conn)
        .await
        .map(|rows| {
            rows.into_iter()
                .map(OutboundPushBridgeCacheRecord::from)
                .collect()
        })
        .map_err(PersistenceError::database)
    }

    async fn len(&self) -> PersistenceResult<usize> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query("SELECT COUNT(*) AS count FROM push_bridge_cache")
            .get_result::<CountRow>(&mut *conn)
            .await
            .map(|row| row.count as usize)
            .map_err(PersistenceError::database)
    }

    async fn record_contract_snapshot(
        &self,
        gateway_describe_url: &str,
        digest: &str,
        etag: &str,
        trust_level: &str,
    ) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        // Upsert: if a row already exists, only bump digest/etag/trust/freshness;
        // otherwise create a stub row that mirrors the gateway URL into the
        // describe-URL columns until the next live fetch fills in the contract.
        sql_query(
            "INSERT INTO push_bridge_cache \
             (id, push_gateway_url, service_base_url, bridge_describe_url, fetch_state, \
              cache_state, contract_digest, fetched_at, remote_contract, \
              trust_level, freshness_at, etag, updated_at) \
             VALUES ($1, $1, $1, $1, 'snapshot_recorded', 'snapshot_recorded', \
                     $2, NOW(), '{}'::jsonb, $4, NOW(), $3, NOW()) \
             ON CONFLICT (id) DO UPDATE SET \
                contract_digest = EXCLUDED.contract_digest, \
                etag = EXCLUDED.etag, \
                trust_level = EXCLUDED.trust_level, \
                freshness_at = NOW(), \
                updated_at = NOW()",
        )
        .bind::<Text, _>(gateway_describe_url)
        .bind::<Text, _>(digest)
        .bind::<Text, _>(etag)
        .bind::<Text, _>(trust_level)
        .execute(&mut *conn)
        .await
        .map(|_| ())
        .map_err(PersistenceError::database)
    }

    async fn current_contract(
        &self,
        gateway_describe_url: &str,
    ) -> PersistenceResult<Option<OutboundPushBridgeCacheRecord>> {
        // Same projection as `get`; named separately so the call site reads
        // intent (drift verification, not raw cache lookup).
        self.get(gateway_describe_url).await
    }

    async fn verify_contract_freshness(
        &self,
        gateway_describe_url: &str,
        observed_digest: &str,
        max_age: chrono::Duration,
    ) -> PersistenceResult<DriftResult> {
        let snapshot = self
            .current_contract(gateway_describe_url)
            .await
            .map_err(PersistenceError::database)?;
        Ok(evaluate_drift(snapshot.as_ref(), observed_digest, max_age))
    }
}
pub struct PgPushDeviceStore {
    pub pool: PgPool,
}
#[async_trait]
impl PushDeviceStore for PgPushDeviceStore {
    async fn register(&self, device: Value) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let extract = |key: &str| -> Option<String> {
            device
                .get(key)
                .and_then(Value::as_str)
                .map(ToOwned::to_owned)
        };
        let registration_id = extract("registration_id").ok_or_else(|| {
            PersistenceError::Internal(
                "push device registration missing registration_id".to_owned(),
            )
        })?;
        let device_id = extract("device_id").ok_or_else(|| {
            PersistenceError::Internal("push device registration missing device_id".to_owned())
        })?;
        let push_gateway = extract("push_gateway").unwrap_or_default();
        let push_key = extract("push_key").unwrap_or_default();
        let actor = extract("actor");
        let platform = extract("platform");
        let app_id = extract("app_id");
        sql_query(
            "INSERT INTO push_devices \
             (id, actor_id, device_id, push_gateway, push_key, platform, app_id, payload, updated_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW()) \
             ON CONFLICT (id) DO UPDATE SET \
                actor_id = EXCLUDED.actor_id, \
                device_id = EXCLUDED.device_id, \
                push_gateway = EXCLUDED.push_gateway, \
                push_key = EXCLUDED.push_key, \
                platform = EXCLUDED.platform, \
                app_id = EXCLUDED.app_id, \
                payload = EXCLUDED.payload, \
                updated_at = NOW()",
        )
        .bind::<Text, _>(&registration_id)
        .bind::<Nullable<Text>, _>(&actor)
        .bind::<Text, _>(&device_id)
        .bind::<Text, _>(&push_gateway)
        .bind::<Text, _>(&push_key)
        .bind::<Nullable<Text>, _>(&platform)
        .bind::<Nullable<Text>, _>(&app_id)
        .bind::<Jsonb, _>(&device)
        .execute(&mut *conn).await
        .map(|_| ())
        .map_err(PersistenceError::database)
    }

    async fn unregister(
        &self,
        actor: &str,
        device_id: &str,
        push_key: Option<&str>,
        app_id: Option<&str>,
    ) -> PersistenceResult<usize> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(
            "DELETE FROM push_devices \
             WHERE actor_id = $1 \
               AND device_id = $2 \
               AND ($3 IS NULL OR push_key = $3) \
               AND ($4 IS NULL OR app_id = $4)",
        )
        .bind::<Text, _>(actor)
        .bind::<Text, _>(device_id)
        .bind::<Nullable<Text>, _>(push_key)
        .bind::<Nullable<Text>, _>(app_id)
        .execute(&mut *conn)
        .await
        .map_err(PersistenceError::database)
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<Value>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query("SELECT payload FROM push_devices ORDER BY updated_at ASC, id ASC")
            .load::<JsonPayloadRow>(&mut *conn)
            .await
            .map(|rows| rows.into_iter().map(|row| row.payload).collect())
            .map_err(PersistenceError::database)
    }
}
#[derive(QueryableByName)]
struct PushBridgeCacheRow {
    #[diesel(sql_type = Text)]
    push_gateway_url: String,
    #[diesel(sql_type = Text)]
    service_base_url: String,
    #[diesel(sql_type = Text)]
    bridge_describe_url: String,
    #[diesel(sql_type = Text)]
    fetch_state: String,
    #[diesel(sql_type = Text)]
    cache_state: String,
    #[diesel(sql_type = Text)]
    contract_digest: String,
    #[diesel(sql_type = Timestamptz)]
    fetched_at: chrono::DateTime<chrono::Utc>,
    #[diesel(sql_type = Jsonb)]
    remote_contract: Value,
    #[diesel(sql_type = Text)]
    trust_level: String,
    #[diesel(sql_type = Timestamptz)]
    freshness_at: chrono::DateTime<chrono::Utc>,
    #[diesel(sql_type = Text)]
    etag: String,
}
impl From<PushBridgeCacheRow> for OutboundPushBridgeCacheRecord {
    fn from(row: PushBridgeCacheRow) -> Self {
        Self {
            push_gateway_url: row.push_gateway_url,
            service_base_url: row.service_base_url,
            bridge_describe_url: row.bridge_describe_url,
            fetch_state: row.fetch_state,
            cache_state: row.cache_state,
            contract_digest: row.contract_digest,
            fetched_at: row.fetched_at,
            remote_contract: row.remote_contract,
            trust_level: row.trust_level,
            freshness_at: row.freshness_at,
            etag: row.etag,
        }
    }
}
