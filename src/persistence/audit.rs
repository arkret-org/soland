use super::*;

/// Append-only audit log. Reads are always actor-scoped; the cursor is the
/// `audit_id` of the last item the caller already saw.
#[async_trait]
pub trait AuditStore: Send + Sync {
    async fn append(&self, entry: Value) -> PersistenceResult<()>;
    async fn list_for_actor(&self, actor: &str) -> PersistenceResult<Vec<Value>>;
    async fn snapshot_all(&self) -> PersistenceResult<Vec<Value>>;
}

#[derive(Default)]
pub(crate) struct MemoryAuditStore {
    data: Mutex<Vec<Value>>,
}

impl MemoryAuditStore {
    pub(crate) fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl AuditStore for MemoryAuditStore {
    async fn append(&self, entry: Value) -> PersistenceResult<()> {
        self.data.lock().expect("audit lock").push(entry);
        Ok(())
    }

    async fn list_for_actor(&self, actor: &str) -> PersistenceResult<Vec<Value>> {
        Ok(self
            .data
            .lock()
            .expect("audit lock")
            .iter()
            .filter(|event| event.get("actor").and_then(Value::as_str) == Some(actor))
            .cloned()
            .collect())
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<Value>> {
        Ok(self.data.lock().expect("audit lock").clone())
    }
}

pub(crate) struct PgAuditStore {
    pub(crate) pool: PgPool,
}

#[derive(QueryableByName)]
struct AuditPayloadRow {
    #[diesel(sql_type = Jsonb)]
    payload: Value,
}

#[async_trait]
impl AuditStore for PgAuditStore {
    async fn append(&self, entry: Value) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool).await?;
        let extract = |key: &str| -> Option<String> {
            entry
                .get(key)
                .and_then(Value::as_str)
                .map(ToOwned::to_owned)
        };
        let audit_id = extract("audit_id")
            .ok_or_else(|| PersistenceError::Internal("audit entry missing audit_id".to_owned()))?;
        let action = extract("action")
            .ok_or_else(|| PersistenceError::Internal("audit entry missing action".to_owned()))?;
        let outcome = extract("outcome")
            .ok_or_else(|| PersistenceError::Internal("audit entry missing outcome".to_owned()))?;
        let actor = extract("actor");
        let request_id = extract("request_id");
        let realm_id = extract("realm_id");
        let operation_id = extract("operation_id");
        let device_id = extract("device_id");
        let audit_id_uuid = ids::typed_uuid_part_or_panic(&audit_id);
        let request_id_uuid: Option<Uuid> =
            request_id.as_deref().map(ids::typed_uuid_part_or_panic);
        let realm_id_uuid: Option<Uuid> = realm_id.as_deref().map(ids::typed_uuid_part_or_panic);
        let operation_id_uuid: Option<Uuid> =
            operation_id.as_deref().map(ids::typed_uuid_part_or_panic);
        sql_query(
            "INSERT INTO audit_logs \
             (id, actor_id, request_id, action, outcome, realm_id, operation_id, device_id, payload, created_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW()) \
             ON CONFLICT (id) DO NOTHING",
        )
        .bind::<SqlUuid, _>(audit_id_uuid)
        .bind::<Nullable<Text>, _>(&actor)
        .bind::<Nullable<SqlUuid>, _>(request_id_uuid)
        .bind::<Text, _>(&action)
        .bind::<Text, _>(&outcome)
        .bind::<Nullable<SqlUuid>, _>(realm_id_uuid)
        .bind::<Nullable<SqlUuid>, _>(operation_id_uuid)
        .bind::<Nullable<Text>, _>(&device_id)
        .bind::<Jsonb, _>(&entry)
        .execute(&mut *conn).await
        .map(|_| ())
        .map_err(PersistenceError::from)
    }

    async fn list_for_actor(&self, actor: &str) -> PersistenceResult<Vec<Value>> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query("SELECT payload FROM audit_logs WHERE actor_id = $1 ORDER BY created_at ASC, id ASC")
            .bind::<Text, _>(actor)
            .load::<AuditPayloadRow>(&mut *conn)
            .await
            .map(|rows| rows.into_iter().map(|row| row.payload).collect())
            .map_err(PersistenceError::from)
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<Value>> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query("SELECT payload FROM audit_logs ORDER BY created_at ASC, id ASC")
            .load::<AuditPayloadRow>(&mut *conn)
            .await
            .map(|rows| rows.into_iter().map(|row| row.payload).collect())
            .map_err(PersistenceError::from)
    }
}
