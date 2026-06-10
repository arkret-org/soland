use super::*;

/// DID documents + their key-log events. The two are coupled: every accepted
/// `submit_did_operation` writes a document and appends a log entry.
#[async_trait]
pub trait WebvhStore: Send + Sync {
    async fn get_document(&self, did: &str) -> PersistenceResult<Option<WebvhDocumentRecord>>;
    async fn get_embedded_webvh_document_by_local_id(
        &self,
        local_id: &str,
    ) -> PersistenceResult<Option<WebvhDocumentRecord>>;
    async fn put_document(&self, record: WebvhDocumentRecord) -> PersistenceResult<()>;
    async fn append_log_event(&self, event: WebvhLogRecord) -> PersistenceResult<()>;
    async fn list_log_events(&self, did: &str) -> PersistenceResult<Vec<WebvhLogRecord>>;
}

#[derive(Default)]
pub(crate) struct MemoryWebvhStore {
    documents: Mutex<BTreeMap<String, WebvhDocumentRecord>>,
    log: Mutex<BTreeMap<String, Vec<WebvhLogRecord>>>,
}

impl MemoryWebvhStore {
    pub(crate) fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl WebvhStore for MemoryWebvhStore {
    async fn get_document(&self, did: &str) -> PersistenceResult<Option<WebvhDocumentRecord>> {
        Ok(self
            .documents
            .lock()
            .expect("webvh documents lock")
            .get(did)
            .cloned())
    }

    async fn get_embedded_webvh_document_by_local_id(
        &self,
        local_id: &str,
    ) -> PersistenceResult<Option<WebvhDocumentRecord>> {
        Ok(self
            .documents
            .lock()
            .expect("webvh documents lock")
            .values()
            .find(|record| {
                record
                    .method_evidence
                    .get("mode")
                    .and_then(serde_json::Value::as_str)
                    == Some("embedded_webvh_provider")
                    && record
                        .method_evidence
                        .get("local_id")
                        .and_then(serde_json::Value::as_str)
                        == Some(local_id)
            })
            .cloned())
    }

    async fn put_document(&self, mut record: WebvhDocumentRecord) -> PersistenceResult<()> {
        // 写入即 ingest:以"现在"为基线权威标注新鲜度证据,与 Pg backend 一致。
        let (fetched_at, expires_at) = webvh_freshness_on_put();
        record.fetched_at = fetched_at;
        record.expires_at = expires_at;
        let did = record.did.clone();
        self.documents
            .lock()
            .expect("webvh documents lock")
            .insert(did, record);
        Ok(())
    }

    async fn append_log_event(&self, event: WebvhLogRecord) -> PersistenceResult<()> {
        let did = event.did.clone();
        self.log
            .lock()
            .expect("webvh log lock")
            .entry(did)
            .or_default()
            .push(event);
        Ok(())
    }

    async fn list_log_events(&self, did: &str) -> PersistenceResult<Vec<WebvhLogRecord>> {
        Ok(self
            .log
            .lock()
            .expect("webvh log lock")
            .get(did)
            .cloned()
            .unwrap_or_default())
    }
}

pub(crate) struct PgWebvhStore {
    pub(crate) pool: PgPool,
}

#[derive(QueryableByName)]
struct WebvhDocumentRow {
    #[diesel(sql_type = Text)]
    did: String,
    #[diesel(sql_type = Jsonb)]
    did_document: Value,
    #[diesel(sql_type = Nullable<Text>)]
    key_log_head: Option<String>,
    #[diesel(sql_type = BigInt)]
    seq: i64,
    #[diesel(sql_type = Jsonb)]
    method_evidence: Value,
    #[diesel(sql_type = Timestamptz)]
    fetched_at: chrono::DateTime<chrono::Utc>,
    #[diesel(sql_type = Timestamptz)]
    expires_at: chrono::DateTime<chrono::Utc>,
    #[diesel(sql_type = Timestamptz)]
    updated_at: chrono::DateTime<chrono::Utc>,
}

impl From<WebvhDocumentRow> for WebvhDocumentRecord {
    fn from(row: WebvhDocumentRow) -> Self {
        Self {
            did: row.did,
            did_document: row.did_document,
            key_log_head: row.key_log_head,
            seq: row.seq.max(0) as u64,
            method_evidence: row.method_evidence,
            fetched_at: row.fetched_at,
            expires_at: row.expires_at,
            updated_at: row.updated_at,
        }
    }
}

#[derive(QueryableByName)]
struct WebvhLogRow {
    #[diesel(sql_type = Text)]
    event_digest: String,
    #[diesel(sql_type = Text)]
    did: String,
    #[diesel(sql_type = BigInt)]
    seq: i64,
    #[diesel(sql_type = Jsonb)]
    operation: Value,
    #[diesel(sql_type = Timestamptz)]
    created_at: chrono::DateTime<chrono::Utc>,
}

impl From<WebvhLogRow> for WebvhLogRecord {
    fn from(row: WebvhLogRow) -> Self {
        Self {
            event_digest: row.event_digest,
            did: row.did,
            seq: row.seq.max(0) as u64,
            operation: row.operation,
            created_at: row.created_at,
        }
    }
}

#[async_trait]
impl WebvhStore for PgWebvhStore {
    async fn get_document(&self, did: &str) -> PersistenceResult<Option<WebvhDocumentRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "SELECT id AS did, did_document, key_log_head, seq, method_evidence, \
             fetched_at, expires_at, updated_at \
             FROM webvh_documents WHERE id = $1",
        )
        .bind::<Text, _>(did)
        .get_result::<WebvhDocumentRow>(&mut *conn)
        .await
        .optional()
        .map(|row| row.map(WebvhDocumentRecord::from))
        .map_err(PersistenceError::from)
    }

    async fn get_embedded_webvh_document_by_local_id(
        &self,
        local_id: &str,
    ) -> PersistenceResult<Option<WebvhDocumentRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "SELECT id AS did, did_document, key_log_head, seq, method_evidence, \
             fetched_at, expires_at, updated_at \
             FROM webvh_documents \
             WHERE method_evidence->>'mode' = 'embedded_webvh_provider' \
               AND method_evidence->>'local_id' = $1 \
             ORDER BY updated_at DESC \
             LIMIT 1",
        )
        .bind::<Text, _>(local_id)
        .get_result::<WebvhDocumentRow>(&mut *conn)
        .await
        .optional()
        .map(|row| row.map(WebvhDocumentRecord::from))
        .map_err(PersistenceError::from)
    }

    async fn put_document(&self, record: WebvhDocumentRecord) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool).await?;
        // 写入即 ingest:以"现在"为基线权威标注新鲜度证据
        // (`fetched_at = now`、`expires_at = now + 高风险基线 TTL`)。
        let (fetched_at, expires_at) = webvh_freshness_on_put();
        sql_query(
            "INSERT INTO webvh_documents \
             (id, did_document, key_log_head, seq, method_evidence, \
              fetched_at, expires_at, updated_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8) \
             ON CONFLICT (id) DO UPDATE SET \
                did_document = EXCLUDED.did_document, \
                key_log_head = EXCLUDED.key_log_head, \
                seq = EXCLUDED.seq, \
                method_evidence = EXCLUDED.method_evidence, \
                fetched_at = EXCLUDED.fetched_at, \
                expires_at = EXCLUDED.expires_at, \
                updated_at = EXCLUDED.updated_at",
        )
        .bind::<Text, _>(&record.did)
        .bind::<Jsonb, _>(&record.did_document)
        .bind::<Nullable<Text>, _>(&record.key_log_head)
        .bind::<BigInt, _>(record.seq as i64)
        .bind::<Jsonb, _>(&record.method_evidence)
        .bind::<Timestamptz, _>(fetched_at)
        .bind::<Timestamptz, _>(expires_at)
        .bind::<Timestamptz, _>(record.updated_at)
        .execute(&mut *conn)
        .await
        .map(|_| ())
        .map_err(PersistenceError::from)
    }

    async fn append_log_event(&self, event: WebvhLogRecord) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "INSERT INTO webvh_log_events \
             (id, did, seq, operation, created_at) \
             VALUES ($1, $2, $3, $4, $5) \
             ON CONFLICT (id) DO NOTHING",
        )
        .bind::<Text, _>(&event.event_digest)
        .bind::<Text, _>(&event.did)
        .bind::<BigInt, _>(event.seq as i64)
        .bind::<Jsonb, _>(&event.operation)
        .bind::<Timestamptz, _>(event.created_at)
        .execute(&mut *conn)
        .await
        .map(|_| ())
        .map_err(PersistenceError::from)
    }

    async fn list_log_events(&self, did: &str) -> PersistenceResult<Vec<WebvhLogRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "SELECT id AS event_digest, did, seq, operation, created_at \
             FROM webvh_log_events WHERE did = $1 ORDER BY seq ASC, id ASC",
        )
        .bind::<Text, _>(did)
        .load::<WebvhLogRow>(&mut *conn)
        .await
        .map(|rows| rows.into_iter().map(WebvhLogRecord::from).collect())
        .map_err(PersistenceError::from)
    }
}
