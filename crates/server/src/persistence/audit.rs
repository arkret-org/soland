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
        self.data.lock().push(entry);
        Ok(())
    }

    async fn list_for_actor(&self, actor: &str) -> PersistenceResult<Vec<Value>> {
        Ok(self
            .data
            .lock()
            .iter()
            .filter(|event| event.get("actor").and_then(Value::as_str) == Some(actor))
            .cloned()
            .collect())
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<Value>> {
        Ok(self.data.lock().clone())
    }
}

pub(crate) struct PgAuditStore {
    pub(crate) pool: PgPool,
}

fn audit_uuid_index(field: &str, value: &str, kind: &str) -> PersistenceResult<Uuid> {
    ids::parse_typed_uuid(value, kind).ok_or_else(|| {
        PersistenceError::Internal(format!(
            "audit entry {field} is not a ck:{kind}: UUID: {value}"
        ))
    })
}

fn optional_audit_uuid_index(
    field: &str,
    value: Option<&str>,
    kind: &str,
) -> PersistenceResult<Option<Uuid>> {
    value
        .map(|value| audit_uuid_index(field, value, kind))
        .transpose()
}

fn operation_uuid_index(value: Option<&str>) -> Option<Uuid> {
    value.and_then(|value| ids::parse_typed_uuid(value, "operation"))
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
        let audit_id_uuid = audit_uuid_index("audit_id", &audit_id, "audit")?;
        let request_id_uuid =
            optional_audit_uuid_index("request_id", request_id.as_deref(), "request")?;
        let realm_id_uuid = optional_audit_uuid_index("realm_id", realm_id.as_deref(), "realm")?;
        let operation_id_uuid = operation_uuid_index(operation_id.as_deref());
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
        sql_query(
            "SELECT payload FROM audit_logs WHERE actor_id = $1 ORDER BY created_at ASC, id ASC",
        )
        .bind::<Text, _>(actor)
        .load::<JsonPayloadRow>(&mut *conn)
        .await
        .map(|rows| rows.into_iter().map(|row| row.payload).collect())
        .map_err(PersistenceError::from)
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<Value>> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query("SELECT payload FROM audit_logs ORDER BY created_at ASC, id ASC")
            .load::<JsonPayloadRow>(&mut *conn)
            .await
            .map(|rows| rows.into_iter().map(|row| row.payload).collect())
            .map_err(PersistenceError::from)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn operation_uuid_index_ignores_protocol_operation_id() {
        assert_eq!(
            operation_uuid_index(Some("ck.gate.account.command.register")),
            None
        );
    }

    #[test]
    fn operation_uuid_index_parses_typed_operation_uuid() {
        let uuid = Uuid::parse_str("01904100-0000-7000-8000-000000000001").unwrap();

        assert_eq!(
            operation_uuid_index(Some("ak:operation:01904100-0000-7000-8000-000000000001")),
            Some(uuid)
        );
    }

    #[test]
    fn audit_uuid_index_rejects_wrong_kind_without_panicking() {
        let error = audit_uuid_index("request_id", "ck.gate.account.command.register", "request")
            .unwrap_err();

        assert!(matches!(error, PersistenceError::Internal(_)));
    }
}
