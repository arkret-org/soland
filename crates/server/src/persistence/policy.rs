use super::*;

/// Per-owner policy documents.
#[async_trait]
pub trait PolicyDocumentStore: Send + Sync {
    async fn get(&self, policy_id: &str) -> PersistenceResult<Option<PolicyDocumentRecord>>;
    async fn put(&self, record: PolicyDocumentRecord) -> PersistenceResult<()>;
    async fn delete(&self, policy_id: &str) -> PersistenceResult<bool>;
    async fn list_for_owner(&self, owner: &str) -> PersistenceResult<Vec<PolicyDocumentRecord>>;
    async fn snapshot_all(&self) -> PersistenceResult<Vec<PolicyDocumentRecord>>;
    /// Return every currently-active policy document. Callers apply their own
    /// match predicate (kept out of the trait so the `#[async_trait]` future
    /// stays `Send` without higher-ranked closure-lifetime gymnastics).
    async fn list_active(&self) -> PersistenceResult<Vec<PolicyDocumentRecord>>;
}

#[derive(Default)]
pub(crate) struct MemoryPolicyDocumentStore {
    data: Mutex<BTreeMap<String, PolicyDocumentRecord>>,
}

impl MemoryPolicyDocumentStore {
    pub(crate) fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl PolicyDocumentStore for MemoryPolicyDocumentStore {
    async fn get(&self, policy_id: &str) -> PersistenceResult<Option<PolicyDocumentRecord>> {
        Ok(self
            .data
            .lock()
            .expect("policy documents lock")
            .get(policy_id)
            .cloned())
    }

    async fn put(&self, record: PolicyDocumentRecord) -> PersistenceResult<()> {
        let id = record.policy_id.clone();
        self.data
            .lock()
            .expect("policy documents lock")
            .insert(id, record);
        Ok(())
    }

    async fn delete(&self, policy_id: &str) -> PersistenceResult<bool> {
        Ok(self
            .data
            .lock()
            .expect("policy documents lock")
            .remove(policy_id)
            .is_some())
    }

    async fn list_for_owner(&self, owner: &str) -> PersistenceResult<Vec<PolicyDocumentRecord>> {
        Ok(self
            .data
            .lock()
            .expect("policy documents lock")
            .values()
            .filter(|record| record.owner == owner)
            .cloned()
            .collect())
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<PolicyDocumentRecord>> {
        Ok(self
            .data
            .lock()
            .expect("policy documents lock")
            .values()
            .cloned()
            .collect())
    }

    async fn list_active(&self) -> PersistenceResult<Vec<PolicyDocumentRecord>> {
        let guard = self.data.lock().expect("policy documents lock");
        Ok(guard
            .values()
            .filter(|record| record.active)
            .cloned()
            .collect())
    }
}

pub(crate) struct PgPolicyDocumentStore {
    pub(crate) pool: PgPool,
}

#[derive(QueryableByName)]
struct PolicyDocumentRow {
    #[diesel(sql_type = SqlUuid)]
    policy_id: Uuid,
    #[diesel(sql_type = Text)]
    owner: String,
    #[diesel(sql_type = Text)]
    scope: String,
    #[diesel(sql_type = Text)]
    subject_ref: String,
    #[diesel(sql_type = Text)]
    policy_type: String,
    #[diesel(sql_type = Jsonb)]
    document: Value,
    #[diesel(sql_type = Bool)]
    active: bool,
    #[diesel(sql_type = Timestamptz)]
    updated_at: chrono::DateTime<chrono::Utc>,
}

impl From<PolicyDocumentRow> for PolicyDocumentRecord {
    fn from(row: PolicyDocumentRow) -> Self {
        Self {
            policy_id: ids::format_typed_uuid("policy", &row.policy_id),
            owner: row.owner,
            scope: row.scope,
            subject_ref: row.subject_ref,
            policy_type: row.policy_type,
            payload: row.document,
            active: row.active,
            updated_at: row.updated_at,
        }
    }
}

#[async_trait]
impl PolicyDocumentStore for PgPolicyDocumentStore {
    async fn get(&self, policy_id: &str) -> PersistenceResult<Option<PolicyDocumentRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "SELECT id AS policy_id, owner_id AS owner, scope, subject_ref, policy_type, document, active, updated_at \
             FROM policy_documents WHERE id = $1",
        )
        .bind::<SqlUuid, _>(ids::typed_uuid_part_or_panic(policy_id))
        .get_result::<PolicyDocumentRow>(&mut *conn).await
        .optional()
        .map(|row| row.map(PolicyDocumentRecord::from))
        .map_err(PersistenceError::from)
    }

    async fn put(&self, record: PolicyDocumentRecord) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool).await?;
        let version: i32 = record
            .payload
            .get("version")
            .and_then(Value::as_i64)
            .map(|v| v.clamp(i32::MIN as i64, i32::MAX as i64) as i32)
            .unwrap_or(0);
        let verification_method: Option<String> = record
            .payload
            .get("verification_method")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned);
        sql_query(
            "INSERT INTO policy_documents \
             (id, owner_id, scope, subject_ref, policy_type, document, version, signed_by_id, active, updated_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) \
             ON CONFLICT (id) DO UPDATE SET \
                owner_id = EXCLUDED.owner_id, \
                scope = EXCLUDED.scope, \
                subject_ref = EXCLUDED.subject_ref, \
                policy_type = EXCLUDED.policy_type, \
                document = EXCLUDED.document, \
                version = EXCLUDED.version, \
                signed_by_id = EXCLUDED.signed_by_id, \
                active = EXCLUDED.active, \
                updated_at = EXCLUDED.updated_at",
        )
        .bind::<SqlUuid, _>(ids::typed_uuid_part_or_panic(&record.policy_id))
        .bind::<Text, _>(&record.owner)
        .bind::<Text, _>(&record.scope)
        .bind::<Text, _>(&record.subject_ref)
        .bind::<Text, _>(&record.policy_type)
        .bind::<Jsonb, _>(&record.payload)
        .bind::<Integer, _>(version)
        .bind::<Nullable<Text>, _>(&verification_method)
        .bind::<Bool, _>(record.active)
        .bind::<Timestamptz, _>(record.updated_at)
        .execute(&mut *conn).await
        .map(|_| ())
        .map_err(PersistenceError::from)
    }

    async fn delete(&self, policy_id: &str) -> PersistenceResult<bool> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query("DELETE FROM policy_documents WHERE id = $1")
            .bind::<SqlUuid, _>(ids::typed_uuid_part_or_panic(policy_id))
            .execute(&mut *conn)
            .await
            .map(|n| n > 0)
            .map_err(PersistenceError::from)
    }

    async fn list_for_owner(&self, owner: &str) -> PersistenceResult<Vec<PolicyDocumentRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "SELECT id AS policy_id, owner_id AS owner, scope, subject_ref, policy_type, document, active, updated_at \
             FROM policy_documents WHERE owner_id = $1 ORDER BY updated_at ASC, id ASC",
        )
        .bind::<Text, _>(owner)
        .load::<PolicyDocumentRow>(&mut *conn).await
        .map(|rows| rows.into_iter().map(PolicyDocumentRecord::from).collect())
        .map_err(PersistenceError::from)
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<PolicyDocumentRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "SELECT id AS policy_id, owner_id AS owner, scope, subject_ref, policy_type, document, active, updated_at \
             FROM policy_documents ORDER BY updated_at ASC, id ASC",
        )
        .load::<PolicyDocumentRow>(&mut *conn).await
        .map(|rows| rows.into_iter().map(PolicyDocumentRecord::from).collect())
        .map_err(PersistenceError::from)
    }

    async fn list_active(&self) -> PersistenceResult<Vec<PolicyDocumentRecord>> {
        // Linear scan in Pg — same semantics as Memory backend but driven by
        // a SELECT. The row count is small (per-Realm policy documents) so a
        // full table walk is acceptable. Callers apply their own match
        // predicate on the returned rows.
        let mut conn = pg_conn(&self.pool).await?;
        let rows: Vec<PolicyDocumentRow> = sql_query(
            "SELECT id AS policy_id, owner_id AS owner, scope, subject_ref, policy_type, document, active, updated_at \
             FROM policy_documents WHERE active = TRUE ORDER BY updated_at ASC, id ASC",
        )
        .load::<PolicyDocumentRow>(&mut *conn).await
        .map_err(PersistenceError::from)?;
        Ok(rows.into_iter().map(PolicyDocumentRecord::from).collect())
    }
}
