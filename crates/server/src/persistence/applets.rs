use super::*;

#[async_trait]
pub trait AppletStore: Send + Sync {
    async fn get(&self, applet_id: &str) -> PersistenceResult<Option<Value>>;
    async fn put(&self, applet_id: &str, record: Value) -> PersistenceResult<()>;
    async fn list(&self) -> PersistenceResult<Vec<Value>>;
    async fn begin_transaction_replay(
        &self,
        record: AppletTransactionReplayRecord,
    ) -> PersistenceResult<AppletTransactionReplayBegin>;
    async fn complete_transaction_replay(
        &self,
        source_service_did: &str,
        idempotency_key: &str,
        outcome: Value,
    ) -> PersistenceResult<()>;
}

#[derive(Clone, Debug)]
pub struct AppletTransactionReplayRecord {
    pub source_service_did: String,
    pub idempotency_key: String,
    pub source_signature_anchor: String,
    pub request_digest: String,
    pub outcome: Option<Value>,
    pub received_at: chrono::DateTime<chrono::Utc>,
    pub completed_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Clone, Debug)]
pub enum AppletTransactionReplayBegin {
    Fresh,
    Existing(AppletTransactionReplayRecord),
}

pub(crate) struct MemoryAppletStore {
    records: Mutex<BTreeMap<String, Value>>,
    transactions: Mutex<BTreeMap<(String, String), AppletTransactionReplayRecord>>,
}

impl MemoryAppletStore {
    pub(crate) fn new() -> Self {
        Self {
            records: Mutex::new(BTreeMap::new()),
            transactions: Mutex::new(BTreeMap::new()),
        }
    }
}

#[async_trait]
impl AppletStore for MemoryAppletStore {
    async fn get(&self, applet_id: &str) -> PersistenceResult<Option<Value>> {
        Ok(self.records.lock().get(applet_id).cloned())
    }

    async fn put(&self, applet_id: &str, record: Value) -> PersistenceResult<()> {
        self.records.lock().insert(applet_id.to_owned(), record);
        Ok(())
    }

    async fn list(&self) -> PersistenceResult<Vec<Value>> {
        Ok(self.records.lock().values().cloned().collect())
    }

    async fn begin_transaction_replay(
        &self,
        record: AppletTransactionReplayRecord,
    ) -> PersistenceResult<AppletTransactionReplayBegin> {
        let key = (
            record.source_service_did.clone(),
            record.idempotency_key.clone(),
        );
        let mut transactions = self.transactions.lock();
        if let Some(existing) = transactions.get(&key) {
            return Ok(AppletTransactionReplayBegin::Existing(existing.clone()));
        }
        transactions.insert(key, record);
        Ok(AppletTransactionReplayBegin::Fresh)
    }

    async fn complete_transaction_replay(
        &self,
        source_service_did: &str,
        idempotency_key: &str,
        outcome: Value,
    ) -> PersistenceResult<()> {
        let key = (source_service_did.to_owned(), idempotency_key.to_owned());
        let mut transactions = self.transactions.lock();
        let Some(record) = transactions.get_mut(&key) else {
            return Err(PersistenceError::NotFound(format!(
                "applet transaction replay missing for {source_service_did}/{idempotency_key}"
            )));
        };
        record.outcome = Some(outcome);
        record.completed_at = Some(chrono::Utc::now());
        Ok(())
    }
}

#[derive(QueryableByName)]
struct AppletRegistrationRow {
    #[diesel(sql_type = Text)]
    id: String,
    #[diesel(sql_type = Text)]
    namespace: String,
    #[diesel(sql_type = Text)]
    owner_actor_id: String,
    #[diesel(sql_type = Text)]
    registry_did: String,
    #[diesel(sql_type = Text)]
    bot_actor_id: String,
    #[diesel(sql_type = Text)]
    portal_realm_id: String,
    #[diesel(sql_type = Jsonb)]
    capabilities: Value,
    #[diesel(sql_type = Jsonb)]
    manifest: Value,
    #[diesel(sql_type = Nullable<Jsonb>)]
    package: Option<Value>,
    #[diesel(sql_type = Nullable<Jsonb>)]
    namespaces: Option<Value>,
    #[diesel(sql_type = Bool)]
    allow_ghost_actors: bool,
    #[diesel(sql_type = Text)]
    status: String,
    #[diesel(sql_type = Timestamptz)]
    registered_at: chrono::DateTime<chrono::Utc>,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    revoked_at: Option<chrono::DateTime<chrono::Utc>>,
    #[diesel(sql_type = Nullable<Text>)]
    idempotency_key: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    install_body_digest: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    install_id: Option<String>,
    #[diesel(sql_type = Nullable<Jsonb>)]
    install_response: Option<Value>,
    #[diesel(sql_type = Nullable<Jsonb>)]
    install_execution: Option<Value>,
    #[diesel(sql_type = Jsonb)]
    ghosts: Value,
}

#[derive(QueryableByName)]
struct AppletTransactionReplayRow {
    #[diesel(sql_type = Text)]
    source_service_did: String,
    #[diesel(sql_type = Text)]
    idempotency_key: String,
    #[diesel(sql_type = Text)]
    source_signature_anchor: String,
    #[diesel(sql_type = Text)]
    request_digest: String,
    #[diesel(sql_type = Nullable<Jsonb>)]
    outcome: Option<Value>,
    #[diesel(sql_type = Timestamptz)]
    received_at: chrono::DateTime<chrono::Utc>,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    completed_at: Option<chrono::DateTime<chrono::Utc>>,
}

impl From<AppletRegistrationRow> for Value {
    fn from(row: AppletRegistrationRow) -> Self {
        serde_json::json!({
            "applet_id": row.id,
            "namespace": row.namespace,
            "owner_actor_id": row.owner_actor_id,
            "registry_did": row.registry_did,
            "bot_actor_id": row.bot_actor_id,
            "portal_realm_id": row.portal_realm_id,
            "capabilities": row.capabilities,
            "manifest": row.manifest,
            "package": row.package,
            "namespaces": row.namespaces,
            "allow_ghost_actors": row.allow_ghost_actors,
            "status": row.status,
            "registered_at": row.registered_at,
            "revoked_at": row.revoked_at,
            "idempotency_key": row.idempotency_key,
            "install_body_digest": row.install_body_digest,
            "install_id": row.install_id,
            "install_response": row.install_response,
            "install_execution": row.install_execution,
            "ghosts": row.ghosts,
        })
    }
}

impl From<AppletTransactionReplayRow> for AppletTransactionReplayRecord {
    fn from(row: AppletTransactionReplayRow) -> Self {
        Self {
            source_service_did: row.source_service_did,
            idempotency_key: row.idempotency_key,
            source_signature_anchor: row.source_signature_anchor,
            request_digest: row.request_digest,
            outcome: row.outcome,
            received_at: row.received_at,
            completed_at: row.completed_at,
        }
    }
}

pub(crate) struct PgAppletStore {
    pub(crate) pool: PgPool,
}

#[async_trait]
impl AppletStore for PgAppletStore {
    async fn get(&self, applet_id: &str) -> PersistenceResult<Option<Value>> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(applet_registration_select_sql("WHERE id = $1"))
            .bind::<Text, _>(applet_id)
            .get_result::<AppletRegistrationRow>(&mut *conn)
            .await
            .optional()
            .map(|row| row.map(Value::from))
            .map_err(PersistenceError::from)
    }

    async fn put(&self, applet_id: &str, record: Value) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool).await?;
        let namespace = required_record_str(&record, "namespace")?;
        let owner_actor_id = required_record_str(&record, "owner_actor_id")?;
        let registry_did = required_record_str(&record, "registry_did")?;
        let bot_actor_id = required_record_str(&record, "bot_actor_id")?;
        let portal_realm_id = required_record_str(&record, "portal_realm_id")?;
        let capabilities = record
            .get("capabilities")
            .cloned()
            .unwrap_or_else(|| Value::Array(Vec::new()));
        let manifest = record.get("manifest").cloned().ok_or_else(|| {
            PersistenceError::Internal("applet record missing manifest".to_owned())
        })?;
        let package = optional_record_value(&record, "package");
        let namespaces = optional_record_value(&record, "namespaces");
        let allow_ghost_actors = record
            .get("allow_ghost_actors")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let status = required_record_str(&record, "status")?;
        let registered_at = required_record_timestamp(&record, "registered_at")?;
        let revoked_at = optional_record_timestamp(&record, "revoked_at")?;
        let idempotency_key = optional_record_str(&record, "idempotency_key");
        let install_body_digest = optional_record_str(&record, "install_body_digest");
        let install_id = optional_record_str(&record, "install_id");
        let install_response = optional_record_value(&record, "install_response");
        let install_execution = optional_record_value(&record, "install_execution");
        let ghosts = record
            .get("ghosts")
            .cloned()
            .unwrap_or_else(|| Value::Array(Vec::new()));

        sql_query(
            "INSERT INTO applet_registrations \
             (id, namespace, owner_actor_id, registry_did, bot_actor_id, portal_realm_id, \
              capabilities, manifest, package, namespaces, allow_ghost_actors, status, \
              registered_at, revoked_at, idempotency_key, install_body_digest, install_id, \
              install_response, install_execution, ghosts, updated_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, \
                     $16, $17, $18, $19, $20, NOW()) \
             ON CONFLICT (id) DO UPDATE SET \
              namespace = EXCLUDED.namespace, \
              owner_actor_id = EXCLUDED.owner_actor_id, \
              registry_did = EXCLUDED.registry_did, \
              bot_actor_id = EXCLUDED.bot_actor_id, \
              portal_realm_id = EXCLUDED.portal_realm_id, \
              capabilities = EXCLUDED.capabilities, \
              manifest = EXCLUDED.manifest, \
              package = EXCLUDED.package, \
              namespaces = EXCLUDED.namespaces, \
              allow_ghost_actors = EXCLUDED.allow_ghost_actors, \
              status = EXCLUDED.status, \
              registered_at = EXCLUDED.registered_at, \
              revoked_at = EXCLUDED.revoked_at, \
              idempotency_key = EXCLUDED.idempotency_key, \
              install_body_digest = EXCLUDED.install_body_digest, \
              install_id = EXCLUDED.install_id, \
              install_response = EXCLUDED.install_response, \
              install_execution = EXCLUDED.install_execution, \
              ghosts = EXCLUDED.ghosts, \
              updated_at = NOW()",
        )
        .bind::<Text, _>(applet_id)
        .bind::<Text, _>(&namespace)
        .bind::<Text, _>(&owner_actor_id)
        .bind::<Text, _>(&registry_did)
        .bind::<Text, _>(&bot_actor_id)
        .bind::<Text, _>(&portal_realm_id)
        .bind::<Jsonb, _>(&capabilities)
        .bind::<Jsonb, _>(&manifest)
        .bind::<Nullable<Jsonb>, _>(&package)
        .bind::<Nullable<Jsonb>, _>(&namespaces)
        .bind::<Bool, _>(allow_ghost_actors)
        .bind::<Text, _>(&status)
        .bind::<Timestamptz, _>(registered_at)
        .bind::<Nullable<Timestamptz>, _>(revoked_at)
        .bind::<Nullable<Text>, _>(&idempotency_key)
        .bind::<Nullable<Text>, _>(&install_body_digest)
        .bind::<Nullable<Text>, _>(&install_id)
        .bind::<Nullable<Jsonb>, _>(&install_response)
        .bind::<Nullable<Jsonb>, _>(&install_execution)
        .bind::<Jsonb, _>(&ghosts)
        .execute(&mut *conn)
        .await
        .map(|_| ())
        .map_err(PersistenceError::from)
    }

    async fn list(&self) -> PersistenceResult<Vec<Value>> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(applet_registration_select_sql("ORDER BY registered_at, id"))
            .load::<AppletRegistrationRow>(&mut *conn)
            .await
            .map(|rows| rows.into_iter().map(Value::from).collect())
            .map_err(PersistenceError::from)
    }

    async fn begin_transaction_replay(
        &self,
        record: AppletTransactionReplayRecord,
    ) -> PersistenceResult<AppletTransactionReplayBegin> {
        let mut conn = pg_conn(&self.pool).await?;
        let inserted = sql_query(
            "INSERT INTO applet_transactions \
             (source_service_did, idempotency_key, source_signature_anchor, request_digest, \
              outcome, received_at, completed_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7) \
             ON CONFLICT (source_service_did, idempotency_key) DO NOTHING",
        )
        .bind::<Text, _>(&record.source_service_did)
        .bind::<Text, _>(&record.idempotency_key)
        .bind::<Text, _>(&record.source_signature_anchor)
        .bind::<Text, _>(&record.request_digest)
        .bind::<Nullable<Jsonb>, _>(&record.outcome)
        .bind::<Timestamptz, _>(record.received_at)
        .bind::<Nullable<Timestamptz>, _>(record.completed_at)
        .execute(&mut *conn)
        .await
        .map_err(PersistenceError::from)?;
        if inserted == 1 {
            return Ok(AppletTransactionReplayBegin::Fresh);
        }
        sql_query(applet_transaction_replay_select_sql())
            .bind::<Text, _>(&record.source_service_did)
            .bind::<Text, _>(&record.idempotency_key)
            .get_result::<AppletTransactionReplayRow>(&mut *conn)
            .await
            .optional()
            .map_err(PersistenceError::from)?
            .map(AppletTransactionReplayRecord::from)
            .map(AppletTransactionReplayBegin::Existing)
            .ok_or_else(|| {
                PersistenceError::Internal(
                    "applet transaction conflict row disappeared after insert".to_owned(),
                )
            })
    }

    async fn complete_transaction_replay(
        &self,
        source_service_did: &str,
        idempotency_key: &str,
        outcome: Value,
    ) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "UPDATE applet_transactions \
             SET outcome = $3, completed_at = NOW() \
             WHERE source_service_did = $1 AND idempotency_key = $2",
        )
        .bind::<Text, _>(source_service_did)
        .bind::<Text, _>(idempotency_key)
        .bind::<Jsonb, _>(&outcome)
        .execute(&mut *conn)
        .await
        .map_err(PersistenceError::from)
        .and_then(|updated| {
            if updated == 0 {
                Err(PersistenceError::NotFound(format!(
                    "applet transaction replay missing for {source_service_did}/{idempotency_key}"
                )))
            } else {
                Ok(())
            }
        })
    }
}

fn applet_registration_select_sql(suffix: &str) -> String {
    format!(
        "SELECT id, namespace, owner_actor_id, registry_did, bot_actor_id, portal_realm_id, \
         capabilities, manifest, package, namespaces, allow_ghost_actors, status, \
         registered_at, revoked_at, idempotency_key, install_body_digest, install_id, \
         install_response, install_execution, ghosts FROM applet_registrations {suffix}"
    )
}

fn applet_transaction_replay_select_sql() -> &'static str {
    "SELECT source_service_did, idempotency_key, source_signature_anchor, request_digest, \
     outcome, received_at, completed_at \
     FROM applet_transactions \
     WHERE source_service_did = $1 AND idempotency_key = $2"
}

fn required_record_str(record: &Value, key: &str) -> PersistenceResult<String> {
    record
        .get(key)
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .ok_or_else(|| PersistenceError::Internal(format!("applet record missing {key}")))
}

fn optional_record_str(record: &Value, key: &str) -> Option<String> {
    record
        .get(key)
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
}

fn optional_record_value(record: &Value, key: &str) -> Option<Value> {
    record.get(key).filter(|value| !value.is_null()).cloned()
}

fn required_record_timestamp(
    record: &Value,
    key: &str,
) -> PersistenceResult<chrono::DateTime<chrono::Utc>> {
    let value = record
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| PersistenceError::Internal(format!("applet record missing {key}")))?;
    parse_record_timestamp(value, key)
}

fn optional_record_timestamp(
    record: &Value,
    key: &str,
) -> PersistenceResult<Option<chrono::DateTime<chrono::Utc>>> {
    record
        .get(key)
        .filter(|value| !value.is_null())
        .and_then(Value::as_str)
        .map(|value| parse_record_timestamp(value, key))
        .transpose()
}

fn parse_record_timestamp(
    value: &str,
    key: &str,
) -> PersistenceResult<chrono::DateTime<chrono::Utc>> {
    chrono::DateTime::parse_from_rfc3339(value)
        .map(|dt| dt.with_timezone(&chrono::Utc))
        .map_err(|error| {
            PersistenceError::Internal(format!("applet record {key} timestamp invalid: {error}"))
        })
}
