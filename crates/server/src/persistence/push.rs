use super::*;

/// Push device registrations. Unstructured `Value` while the schema is in
/// flux; the trait gives us a single point to upgrade later.
#[async_trait]
pub trait PushDeviceStore: Send + Sync {
    async fn register(&self, device: Value) -> PersistenceResult<()>;
    async fn unregister(
        &self,
        actor: &str,
        device_id: &str,
        push_key: Option<&str>,
        app_id: Option<&str>,
    ) -> PersistenceResult<usize>;
    async fn snapshot_all(&self) -> PersistenceResult<Vec<Value>>;
}

/// Per-actor push rules.
#[async_trait]
pub trait PushRuleStore: Send + Sync {
    async fn put(&self, rule: PushRuleRecord) -> PersistenceResult<()>;
    async fn delete(&self, actor: &str, rule_id: &str) -> PersistenceResult<()>;
    async fn list_for_actor(&self, actor: &str) -> PersistenceResult<Vec<PushRuleRecord>>;
}

/// Outbound push-bridge contract cache (`bridge_describe_url` → snapshot).
///
/// C33.1 (T0-3a): the cache row doubles as the canonical gateway-contract
/// snapshot. `record_contract_snapshot` lands a digest+etag+trust_level,
/// `current_contract` reads it back, and `verify_contract_freshness` is the
/// fail-closed gate the push outbound publish path calls before fan-out.
#[async_trait]
pub trait PushBridgeCacheStore: Send + Sync {
    async fn get(
        &self,
        bridge_describe_url: &str,
    ) -> PersistenceResult<Option<OutboundPushBridgeCacheRecord>>;
    async fn put(
        &self,
        bridge_describe_url: &str,
        record: OutboundPushBridgeCacheRecord,
    ) -> PersistenceResult<()>;
    async fn delete(&self, bridge_describe_url: &str) -> PersistenceResult<bool>;
    async fn clear(&self) -> PersistenceResult<usize>;
    async fn snapshot_all(&self) -> PersistenceResult<Vec<OutboundPushBridgeCacheRecord>>;
    async fn len(&self) -> PersistenceResult<usize>;
    async fn is_empty(&self) -> PersistenceResult<bool> {
        Ok(self.len().await? == 0)
    }

    /// Persist a fresh contract snapshot for `gateway_describe_url`. Bumps
    /// `freshness_at` to NOW, sets `trust_level`, and stores `digest`+`etag`.
    /// Creates a new row if no prior snapshot exists; otherwise overwrites
    /// the digest/etag/trust/freshness columns in place (rip-and-replace).
    async fn record_contract_snapshot(
        &self,
        gateway_describe_url: &str,
        digest: &str,
        etag: &str,
        trust_level: &str,
    ) -> PersistenceResult<()>;

    /// Read the current persisted contract snapshot for a gateway, if any.
    async fn current_contract(
        &self,
        gateway_describe_url: &str,
    ) -> PersistenceResult<Option<OutboundPushBridgeCacheRecord>>;

    /// Compare a freshly observed contract digest against the persisted
    /// snapshot. Used by `push_notify` (and any other outbound publish
    /// surface) to fail closed before fan-out. The decision is:
    ///
    /// * `Match`           — observed digest matches the persisted digest, trust_level is
    ///   `trusted`, freshness within `max_age`. Caller may proceed.
    /// * `Stale`           — digest matches but `freshness_at` is older than `max_age`. Caller must
    ///   NOT proceed.
    /// * `DigestMismatch`  — persisted snapshot exists but `observed_digest` differs (or persisted
    ///   trust_level is `revoked`).
    /// * `Unknown`         — no snapshot persisted, OR the snapshot is still `pending` / has empty
    ///   digest. Fail-closed.
    async fn verify_contract_freshness(
        &self,
        gateway_describe_url: &str,
        observed_digest: &str,
        max_age: chrono::Duration,
    ) -> PersistenceResult<DriftResult>;
}

/// Outcome of `PushBridgeCacheStore::verify_contract_freshness`. The push
/// outbound publish path treats anything other than `Match` as fail-closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DriftResult {
    /// Observed digest matches a trusted, fresh snapshot.
    Match,
    /// Digest matches but the snapshot is older than `max_age`.
    Stale,
    /// Persisted digest differs from observed (or snapshot revoked).
    DigestMismatch,
    /// No snapshot persisted, or snapshot still pending / empty digest.
    Unknown,
}

impl DriftResult {
    /// Stable string label suitable for audit `outcome` fields and the
    /// `drift_result` field on rejection responses.
    pub fn as_str(self) -> &'static str {
        match self {
            DriftResult::Match => "match",
            DriftResult::Stale => "stale",
            DriftResult::DigestMismatch => "digest_mismatch",
            DriftResult::Unknown => "unknown",
        }
    }
}

#[derive(Default)]
pub(crate) struct MemoryPushDeviceStore {
    data: Mutex<Vec<Value>>,
}

impl MemoryPushDeviceStore {
    pub(crate) fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl PushDeviceStore for MemoryPushDeviceStore {
    async fn register(&self, device: Value) -> PersistenceResult<()> {
        self.data.lock().expect("push devices lock").push(device);
        Ok(())
    }

    async fn unregister(
        &self,
        actor: &str,
        device_id: &str,
        push_key: Option<&str>,
        app_id: Option<&str>,
    ) -> PersistenceResult<usize> {
        let mut data = self.data.lock().expect("push devices lock");
        let before = data.len();
        data.retain(|device| {
            let actor_matches = device.get("actor").and_then(Value::as_str) == Some(actor);
            let device_matches = device.get("device_id").and_then(Value::as_str) == Some(device_id);
            let push_key_matches = push_key.is_none_or(|expected| {
                device.get("push_key").and_then(Value::as_str) == Some(expected)
            });
            let app_id_matches = app_id.is_none_or(|expected| {
                device.get("app_id").and_then(Value::as_str) == Some(expected)
            });
            !(actor_matches && device_matches && push_key_matches && app_id_matches)
        });
        Ok(before.saturating_sub(data.len()))
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<Value>> {
        Ok(self.data.lock().expect("push devices lock").clone())
    }
}

#[derive(Default)]
pub(crate) struct MemoryPushRuleStore {
    data: Mutex<BTreeMap<(String, String), PushRuleRecord>>,
}

impl MemoryPushRuleStore {
    pub(crate) fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl PushRuleStore for MemoryPushRuleStore {
    async fn put(&self, rule: PushRuleRecord) -> PersistenceResult<()> {
        let key = (rule.actor.clone(), rule.rule_id.clone());
        self.data.lock().expect("push rules lock").insert(key, rule);
        Ok(())
    }

    async fn delete(&self, actor: &str, rule_id: &str) -> PersistenceResult<()> {
        self.data
            .lock()
            .expect("push rules lock")
            .remove(&(actor.to_owned(), rule_id.to_owned()));
        Ok(())
    }

    async fn list_for_actor(&self, actor: &str) -> PersistenceResult<Vec<PushRuleRecord>> {
        Ok(self
            .data
            .lock()
            .expect("push rules lock")
            .values()
            .filter(|rule| rule.actor == actor)
            .cloned()
            .collect())
    }
}

#[derive(Default)]
pub(crate) struct MemoryPushBridgeCacheStore {
    pub(crate) data: Mutex<BTreeMap<String, OutboundPushBridgeCacheRecord>>,
}

impl MemoryPushBridgeCacheStore {
    pub(crate) fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl PushBridgeCacheStore for MemoryPushBridgeCacheStore {
    async fn get(
        &self,
        bridge_describe_url: &str,
    ) -> PersistenceResult<Option<OutboundPushBridgeCacheRecord>> {
        Ok(self
            .data
            .lock()
            .expect("push bridge cache lock")
            .get(bridge_describe_url)
            .cloned())
    }

    async fn put(
        &self,
        bridge_describe_url: &str,
        record: OutboundPushBridgeCacheRecord,
    ) -> PersistenceResult<()> {
        self.data
            .lock()
            .expect("push bridge cache lock")
            .insert(bridge_describe_url.to_owned(), record);
        Ok(())
    }

    async fn delete(&self, bridge_describe_url: &str) -> PersistenceResult<bool> {
        Ok(self
            .data
            .lock()
            .expect("push bridge cache lock")
            .remove(bridge_describe_url)
            .is_some())
    }

    async fn clear(&self) -> PersistenceResult<usize> {
        let mut data = self.data.lock().expect("push bridge cache lock");
        let removed = data.len();
        data.clear();
        Ok(removed)
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<OutboundPushBridgeCacheRecord>> {
        Ok(self
            .data
            .lock()
            .expect("push bridge cache lock")
            .values()
            .cloned()
            .collect())
    }

    async fn len(&self) -> PersistenceResult<usize> {
        Ok(self.data.lock().expect("push bridge cache lock").len())
    }

    async fn record_contract_snapshot(
        &self,
        gateway_describe_url: &str,
        digest: &str,
        etag: &str,
        trust_level: &str,
    ) -> PersistenceResult<()> {
        let mut data = self.data.lock().expect("push bridge cache lock");
        let now = Utc::now();
        if let Some(existing) = data.get_mut(gateway_describe_url) {
            existing.contract_digest = digest.to_owned();
            existing.etag = etag.to_owned();
            existing.trust_level = trust_level.to_owned();
            existing.freshness_at = now;
        } else {
            data.insert(
                gateway_describe_url.to_owned(),
                OutboundPushBridgeCacheRecord {
                    push_gateway_url: gateway_describe_url.to_owned(),
                    service_base_url: gateway_describe_url.to_owned(),
                    bridge_describe_url: gateway_describe_url.to_owned(),
                    fetch_state: "snapshot_recorded".to_owned(),
                    cache_state: "snapshot_recorded".to_owned(),
                    contract_digest: digest.to_owned(),
                    fetched_at: now,
                    remote_contract: serde_json::Value::Null,
                    trust_level: trust_level.to_owned(),
                    freshness_at: now,
                    etag: etag.to_owned(),
                },
            );
        }
        Ok(())
    }

    async fn current_contract(
        &self,
        gateway_describe_url: &str,
    ) -> PersistenceResult<Option<OutboundPushBridgeCacheRecord>> {
        Ok(self
            .data
            .lock()
            .expect("push bridge cache lock")
            .get(gateway_describe_url)
            .cloned())
    }

    async fn verify_contract_freshness(
        &self,
        gateway_describe_url: &str,
        observed_digest: &str,
        max_age: chrono::Duration,
    ) -> PersistenceResult<DriftResult> {
        let snapshot = self
            .data
            .lock()
            .expect("push bridge cache lock")
            .get(gateway_describe_url)
            .cloned();
        Ok(evaluate_drift(snapshot.as_ref(), observed_digest, max_age))
    }
}

/// Pure decision function shared by Memory + Pg backends. Keeps the
/// fail-closed semantics in one place so the two impls cannot drift.
fn evaluate_drift(
    snapshot: Option<&OutboundPushBridgeCacheRecord>,
    observed_digest: &str,
    max_age: chrono::Duration,
) -> DriftResult {
    let Some(record) = snapshot else {
        return DriftResult::Unknown;
    };
    if record.contract_digest.is_empty() || record.trust_level == "pending" {
        return DriftResult::Unknown;
    }
    if record.trust_level == "revoked" {
        return DriftResult::DigestMismatch;
    }
    if record.contract_digest != observed_digest {
        return DriftResult::DigestMismatch;
    }
    let age = Utc::now().signed_duration_since(record.freshness_at);
    if age > max_age {
        return DriftResult::Stale;
    }
    DriftResult::Match
}

pub(crate) struct PgPushBridgeCacheStore {
    pub(crate) pool: PgPool,
}

#[async_trait]
impl PushBridgeCacheStore for PgPushBridgeCacheStore {
    async fn get(
        &self,
        bridge_describe_url: &str,
    ) -> PersistenceResult<Option<OutboundPushBridgeCacheRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
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
        .map_err(PersistenceError::from)
    }

    async fn put(
        &self,
        bridge_describe_url: &str,
        record: OutboundPushBridgeCacheRecord,
    ) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool).await?;
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
        .map_err(PersistenceError::from)
    }

    async fn delete(&self, bridge_describe_url: &str) -> PersistenceResult<bool> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query("DELETE FROM push_bridge_cache WHERE id = $1")
            .bind::<Text, _>(bridge_describe_url)
            .execute(&mut *conn)
            .await
            .map(|affected| affected > 0)
            .map_err(PersistenceError::from)
    }

    async fn clear(&self) -> PersistenceResult<usize> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query("DELETE FROM push_bridge_cache")
            .execute(&mut *conn)
            .await
            .map_err(PersistenceError::from)
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<OutboundPushBridgeCacheRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
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
        .map_err(PersistenceError::from)
    }

    async fn len(&self) -> PersistenceResult<usize> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query("SELECT COUNT(*) AS count FROM push_bridge_cache")
            .get_result::<CountRow>(&mut *conn)
            .await
            .map(|row| row.count as usize)
            .map_err(PersistenceError::from)
    }

    async fn record_contract_snapshot(
        &self,
        gateway_describe_url: &str,
        digest: &str,
        etag: &str,
        trust_level: &str,
    ) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool).await?;
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
        .map_err(PersistenceError::from)
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
        let snapshot = self.current_contract(gateway_describe_url).await?;
        Ok(evaluate_drift(snapshot.as_ref(), observed_digest, max_age))
    }
}

pub(crate) struct PgPushDeviceStore {
    pub(crate) pool: PgPool,
}

#[async_trait]
impl PushDeviceStore for PgPushDeviceStore {
    async fn register(&self, device: Value) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool).await?;
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
        .map_err(PersistenceError::from)
    }

    async fn unregister(
        &self,
        actor: &str,
        device_id: &str,
        push_key: Option<&str>,
        app_id: Option<&str>,
    ) -> PersistenceResult<usize> {
        let mut conn = pg_conn(&self.pool).await?;
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
        .map_err(PersistenceError::from)
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<Value>> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query("SELECT payload FROM push_devices ORDER BY updated_at ASC, id ASC")
            .load::<JsonPayloadRow>(&mut *conn)
            .await
            .map(|rows| rows.into_iter().map(|row| row.payload).collect())
            .map_err(PersistenceError::from)
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
