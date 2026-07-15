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
    async fn commit_log_operation(
        &self,
        expected_current_head: Option<String>,
        document: WebvhDocumentRecord,
        event: WebvhLogRecord,
    ) -> PersistenceResult<WebvhLogCommitOutcome>;
    async fn get_service_registration(
        &self,
        key: &arkret_sdk::ServiceRegistrationKey,
    ) -> PersistenceResult<Option<arkret_sdk::ServiceRegistrationOutcome>>;
    async fn commit_service_registration(
        &self,
        key: arkret_sdk::ServiceRegistrationKey,
        outcome: arkret_sdk::ServiceRegistrationOutcome,
        document: WebvhDocumentRecord,
        event: WebvhLogRecord,
    ) -> PersistenceResult<ServiceRegistrationCommitOutcome>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WebvhLogCommitOutcome {
    Accepted,
    Duplicate,
    Conflict,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ServiceRegistrationCommitOutcome {
    Created(arkret_sdk::ServiceRegistrationOutcome),
    Existing(arkret_sdk::ServiceRegistrationOutcome),
    Conflict,
}

#[derive(Default)]
pub(crate) struct MemoryWebvhStore {
    documents: Mutex<BTreeMap<String, WebvhDocumentRecord>>,
    log: Mutex<BTreeMap<String, Vec<WebvhLogRecord>>>,
    service_registrations:
        Mutex<BTreeMap<arkret_sdk::ServiceRegistrationKey, arkret_sdk::ServiceRegistrationOutcome>>,
    submission_lock: Mutex<()>,
}

impl MemoryWebvhStore {
    pub(crate) fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl WebvhStore for MemoryWebvhStore {
    async fn get_document(&self, did: &str) -> PersistenceResult<Option<WebvhDocumentRecord>> {
        Ok(self.documents.lock().get(did).cloned())
    }

    async fn get_embedded_webvh_document_by_local_id(
        &self,
        local_id: &str,
    ) -> PersistenceResult<Option<WebvhDocumentRecord>> {
        // A did:webvh document hosted by this provider MUST be resolvable at its
        // canonical `/webvh/{local_id}/did.json` URL regardless of *how* the
        // record was written. Embedded-provider registrations carry the
        // `local_id` in `method_evidence`; documents provisioned through
        // `submit_did_operation` (e.g. coauth account registration) do not, but
        // their DID still ends with `:webvh:{local_id}`. Match on that canonical
        // suffix so both provisioning paths resolve, falling back to the legacy
        // embedded-provider evidence match.
        let suffix = format!(":webvh:{local_id}");
        Ok(self
            .documents
            .lock()
            .values()
            .find(|record| {
                record.did.ends_with(&suffix)
                    || (record
                        .method_evidence
                        .get("mode")
                        .and_then(serde_json::Value::as_str)
                        == Some("embedded_webvh_provider")
                        && record
                            .method_evidence
                            .get("local_id")
                            .and_then(serde_json::Value::as_str)
                            == Some(local_id))
            })
            .cloned())
    }

    async fn put_document(&self, mut record: WebvhDocumentRecord) -> PersistenceResult<()> {
        // Writes are ingestion: stamp freshness evidence with "now", matching
        // the Pg backend.
        let (fetched_at, expires_at) = webvh_freshness_on_put();
        record.fetched_at = fetched_at;
        record.expires_at = expires_at;
        let did = record.did.clone();
        self.documents.lock().insert(did, record);
        Ok(())
    }

    async fn append_log_event(&self, event: WebvhLogRecord) -> PersistenceResult<()> {
        let did = event.did.clone();
        self.log.lock().entry(did).or_default().push(event);
        Ok(())
    }

    async fn list_log_events(&self, did: &str) -> PersistenceResult<Vec<WebvhLogRecord>> {
        Ok(self.log.lock().get(did).cloned().unwrap_or_default())
    }

    async fn commit_log_operation(
        &self,
        expected_current_head: Option<String>,
        mut document: WebvhDocumentRecord,
        event: WebvhLogRecord,
    ) -> PersistenceResult<WebvhLogCommitOutcome> {
        let _submission = self.submission_lock.lock();
        if document.did != event.did
            || document.seq != event.seq
            || document.key_log_head.as_deref() != Some(event.event_digest.as_str())
        {
            return Ok(WebvhLogCommitOutcome::Conflict);
        }
        let mut documents = self.documents.lock();
        let mut logs = self.log.lock();
        let did_log = logs.entry(event.did.clone()).or_default();
        let version_id = event.operation.get("versionId").and_then(Value::as_str);
        if let Some(existing) = did_log.iter().find(|existing| {
            existing.seq == event.seq
                || version_id.is_some_and(|version_id| {
                    existing.operation.get("versionId").and_then(Value::as_str) == Some(version_id)
                })
        }) {
            return Ok(
                if existing.event_digest == event.event_digest
                    && existing.operation == event.operation
                {
                    WebvhLogCommitOutcome::Duplicate
                } else {
                    WebvhLogCommitOutcome::Conflict
                },
            );
        }
        let current = documents.get(&event.did);
        let Some(expected_seq) = current.map_or(Some(1), |record| record.seq.checked_add(1)) else {
            return Ok(WebvhLogCommitOutcome::Conflict);
        };
        let current_head = current.and_then(|record| record.key_log_head.clone());
        let stored_state_matches_log = match (current, did_log.last()) {
            (None, None) => true,
            (Some(document), Some(head)) => {
                document.seq == head.seq
                    && document.key_log_head.as_deref() == Some(head.event_digest.as_str())
            }
            _ => false,
        };
        if !stored_state_matches_log
            || current_head != expected_current_head
            || event.seq != expected_seq
        {
            return Ok(WebvhLogCommitOutcome::Conflict);
        }
        let (fetched_at, expires_at) = webvh_freshness_on_put();
        document.fetched_at = fetched_at;
        document.expires_at = expires_at;
        did_log.push(event);
        documents.insert(document.did.clone(), document);
        Ok(WebvhLogCommitOutcome::Accepted)
    }

    async fn get_service_registration(
        &self,
        key: &arkret_sdk::ServiceRegistrationKey,
    ) -> PersistenceResult<Option<arkret_sdk::ServiceRegistrationOutcome>> {
        Ok(self
            .service_registrations
            .lock()
            .get(key)
            .cloned()
            .map(registration_as_existing))
    }

    async fn commit_service_registration(
        &self,
        key: arkret_sdk::ServiceRegistrationKey,
        outcome: arkret_sdk::ServiceRegistrationOutcome,
        mut document: WebvhDocumentRecord,
        event: WebvhLogRecord,
    ) -> PersistenceResult<ServiceRegistrationCommitOutcome> {
        let _submission = self.submission_lock.lock();
        let mut registrations = self.service_registrations.lock();
        if let Some(existing) = registrations.get(&key) {
            return Ok(if registrations_match(existing, &outcome) {
                ServiceRegistrationCommitOutcome::Existing(registration_as_existing(
                    existing.clone(),
                ))
            } else {
                ServiceRegistrationCommitOutcome::Conflict
            });
        }

        let mut documents = self.documents.lock();
        if documents
            .values()
            .any(|record| document_declares_registration_key(&record.did_document, &key))
        {
            return Ok(ServiceRegistrationCommitOutcome::Conflict);
        }
        let mut logs = self.log.lock();
        if !valid_new_service_registration_records(&outcome, &document, &event)
            || documents.contains_key(&event.did)
            || logs
                .get(&event.did)
                .is_some_and(|events| !events.is_empty())
        {
            return Ok(ServiceRegistrationCommitOutcome::Conflict);
        }

        let (fetched_at, expires_at) = webvh_freshness_on_put();
        document.fetched_at = fetched_at;
        document.expires_at = expires_at;
        logs.insert(event.did.clone(), vec![event]);
        documents.insert(document.did.clone(), document);
        registrations.insert(key, outcome.clone());
        Ok(ServiceRegistrationCommitOutcome::Created(outcome))
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

#[derive(QueryableByName)]
struct WebvhCommitLockRow {
    #[diesel(sql_type = Integer)]
    ok: i32,
}

#[derive(QueryableByName)]
struct ServiceRegistrationRow {
    #[diesel(sql_type = Jsonb)]
    outcome: Value,
}

#[derive(QueryableByName)]
struct ExistingDidRow {
    #[diesel(sql_type = Text)]
    did: String,
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
        // Resolve by the DID's canonical `:webvh:{local_id}` suffix so documents
        // written through *any* provisioning path resolve at the public
        // `/webvh/{local_id}/did.json` URL — embedded-provider registrations as
        // well as `submit_did_operation` documents (coauth account registration),
        // which carry no `local_id` in `method_evidence`. `:webvh:` is 7 chars;
        // an exact `right(...)` suffix comparison avoids LIKE wildcard pitfalls
        // (normalized local_ids may contain `_`). The legacy embedded-provider
        // evidence match is kept as a fallback.
        sql_query(
            "SELECT id AS did, did_document, key_log_head, seq, method_evidence, \
             fetched_at, expires_at, updated_at \
             FROM webvh_documents \
             WHERE right(id, char_length($1) + 7) = ':webvh:' || $1 \
                OR (method_evidence->>'mode' = 'embedded_webvh_provider' \
                    AND method_evidence->>'local_id' = $1) \
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
        // Writes are ingestion: stamp freshness evidence with "now"
        // (`fetched_at = now`, `expires_at = now + high-risk baseline TTL`).
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

    async fn commit_log_operation(
        &self,
        expected_current_head: Option<String>,
        document: WebvhDocumentRecord,
        event: WebvhLogRecord,
    ) -> PersistenceResult<WebvhLogCommitOutcome> {
        if document.did != event.did
            || document.seq != event.seq
            || document.key_log_head.as_deref() != Some(event.event_digest.as_str())
        {
            return Ok(WebvhLogCommitOutcome::Conflict);
        }
        let mut conn = pg_conn(&self.pool).await?;
        conn.transaction::<WebvhLogCommitOutcome, PersistenceError, _>(async move |conn| {
                let lock = sql_query(
                    "SELECT 1 AS ok FROM (SELECT pg_advisory_xact_lock(hashtextextended($1, 0))) AS held",
                )
                .bind::<Text, _>(&event.did)
                .get_result::<WebvhCommitLockRow>(&mut *conn)
                .await?;
                let _ = lock.ok;

                let current = sql_query(
                    "SELECT id AS did, did_document, key_log_head, seq, method_evidence, \
                     fetched_at, expires_at, updated_at \
                     FROM webvh_documents WHERE id = $1 FOR UPDATE",
                )
                .bind::<Text, _>(&event.did)
                .get_result::<WebvhDocumentRow>(&mut *conn)
                .await
                .optional()?;
                let existing_events = sql_query(
                    "SELECT id AS event_digest, did, seq, operation, created_at \
                     FROM webvh_log_events WHERE did = $1 ORDER BY seq ASC, id ASC FOR UPDATE",
                )
                .bind::<Text, _>(&event.did)
                .load::<WebvhLogRow>(&mut *conn)
                .await?;
                let version_id = event
                    .operation
                    .get("versionId")
                    .and_then(Value::as_str);
                if let Some(existing) = existing_events.iter().find(|existing| {
                    existing.seq.max(0) as u64 == event.seq
                        || version_id.is_some_and(|version_id| {
                            existing
                                .operation
                                .get("versionId")
                                .and_then(Value::as_str)
                                == Some(version_id)
                        })
                }) {
                    return Ok(if existing.event_digest == event.event_digest
                        && existing.operation == event.operation
                    {
                        WebvhLogCommitOutcome::Duplicate
                    } else {
                        WebvhLogCommitOutcome::Conflict
                    });
                }
                let Some(expected_seq) = current.as_ref().map_or(Some(1), |record| {
                    (record.seq.max(0) as u64).checked_add(1)
                }) else {
                    return Ok(WebvhLogCommitOutcome::Conflict);
                };
                let stored_state_matches_log = match (current.as_ref(), existing_events.last()) {
                    (None, None) => true,
                    (Some(document), Some(head)) => {
                        document.seq.max(0) as u64 == head.seq.max(0) as u64
                            && document.key_log_head.as_deref()
                                == Some(head.event_digest.as_str())
                    }
                    _ => false,
                };
                let current_head = current.and_then(|record| record.key_log_head);
                if !stored_state_matches_log
                    || current_head != expected_current_head
                    || event.seq != expected_seq
                {
                    return Ok(WebvhLogCommitOutcome::Conflict);
                }

                sql_query(
                    "INSERT INTO webvh_log_events \
                     (id, did, seq, operation, created_at) VALUES ($1, $2, $3, $4, $5)",
                )
                .bind::<Text, _>(&event.event_digest)
                .bind::<Text, _>(&event.did)
                .bind::<BigInt, _>(event.seq as i64)
                .bind::<Jsonb, _>(&event.operation)
                .bind::<Timestamptz, _>(event.created_at)
                .execute(&mut *conn)
                .await?;
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
                .bind::<Text, _>(&document.did)
                .bind::<Jsonb, _>(&document.did_document)
                .bind::<Nullable<Text>, _>(&document.key_log_head)
                .bind::<BigInt, _>(document.seq as i64)
                .bind::<Jsonb, _>(&document.method_evidence)
                .bind::<Timestamptz, _>(fetched_at)
                .bind::<Timestamptz, _>(expires_at)
                .bind::<Timestamptz, _>(document.updated_at)
                .execute(&mut *conn)
                .await?;
                Ok(WebvhLogCommitOutcome::Accepted)
        })
        .await
    }

    async fn get_service_registration(
        &self,
        key: &arkret_sdk::ServiceRegistrationKey,
    ) -> PersistenceResult<Option<arkret_sdk::ServiceRegistrationOutcome>> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "SELECT outcome FROM service_identity_registrations \
             WHERE service_type = $1 AND public_base = $2",
        )
        .bind::<Text, _>(key.service_type().as_str())
        .bind::<Text, _>(key.public_base().as_str())
        .get_result::<ServiceRegistrationRow>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::from)?
        .map(|row| decode_registration_outcome(row.outcome).map(registration_as_existing))
        .transpose()
    }

    async fn commit_service_registration(
        &self,
        key: arkret_sdk::ServiceRegistrationKey,
        outcome: arkret_sdk::ServiceRegistrationOutcome,
        document: WebvhDocumentRecord,
        event: WebvhLogRecord,
    ) -> PersistenceResult<ServiceRegistrationCommitOutcome> {
        if !valid_new_service_registration_records(&outcome, &document, &event) {
            return Ok(ServiceRegistrationCommitOutcome::Conflict);
        }
        let mut conn = pg_conn(&self.pool).await?;
        conn.transaction::<ServiceRegistrationCommitOutcome, PersistenceError, _>(
            async move |conn| {
                let service_type = key.service_type().as_str();
                let public_base = key.public_base().as_str();
                let lock_key = format!("service-registration:{service_type}:{public_base}");
                let lock = sql_query(
                    "SELECT 1 AS ok FROM (SELECT pg_advisory_xact_lock(hashtextextended($1, 0))) AS held",
                )
                .bind::<Text, _>(&lock_key)
                .get_result::<WebvhCommitLockRow>(&mut *conn)
                .await?;
                let _ = lock.ok;

                // A registration key is unique, but the same signed inception
                // may declare more than one ArkretService entry. Serialize on
                // the DID as well so concurrent requests through different
                // registration keys deterministically observe the existing
                // binding instead of surfacing a database unique violation.
                let did_lock_key = format!("service-registration-did:{}", document.did);
                let did_lock = sql_query(
                    "SELECT 1 AS ok FROM (SELECT pg_advisory_xact_lock(hashtextextended($1, 0))) AS held",
                )
                .bind::<Text, _>(&did_lock_key)
                .get_result::<WebvhCommitLockRow>(&mut *conn)
                .await?;
                let _ = did_lock.ok;

                let existing = sql_query(
                    "SELECT outcome FROM service_identity_registrations \
                     WHERE service_type = $1 AND public_base = $2 FOR UPDATE",
                )
                .bind::<Text, _>(service_type)
                .bind::<Text, _>(public_base)
                .get_result::<ServiceRegistrationRow>(&mut *conn)
                .await
                .optional()?;
                if let Some(existing) = existing {
                    let existing = decode_registration_outcome(existing.outcome)?;
                    return Ok(if registrations_match(&existing, &outcome) {
                        ServiceRegistrationCommitOutcome::Existing(registration_as_existing(
                            existing,
                        ))
                    } else {
                        ServiceRegistrationCommitOutcome::Conflict
                    });
                }

                let hosted_binding = sql_query(
                    "SELECT id AS did FROM webvh_documents \
                     WHERE EXISTS ( \
                       SELECT 1 FROM jsonb_array_elements( \
                         CASE WHEN jsonb_typeof(did_document->'service') = 'array' \
                              THEN did_document->'service' ELSE '[]'::jsonb END \
                       ) AS entry \
                       WHERE entry->>'type' = 'ArkretService' \
                         AND entry->>'serviceType' = $1 \
                         AND entry->>'serviceEndpoint' = $2 \
                     ) LIMIT 1 FOR UPDATE",
                )
                .bind::<Text, _>(service_type)
                .bind::<Text, _>(public_base)
                .get_result::<ExistingDidRow>(&mut *conn)
                .await
                .optional()?;
                if let Some(hosted_binding) = hosted_binding {
                    tracing::warn!(
                        existing_did = %hosted_binding.did,
                        service_type,
                        public_base,
                        "refusing service registration because a hosted document already declares the key",
                    );
                    return Ok(ServiceRegistrationCommitOutcome::Conflict);
                }

                let existing_did = sql_query(
                    "SELECT id AS did FROM webvh_documents WHERE id = $1 FOR UPDATE",
                )
                .bind::<Text, _>(&document.did)
                .get_result::<ExistingDidRow>(&mut *conn)
                .await
                .optional()?;
                if existing_did.is_some() {
                    return Ok(ServiceRegistrationCommitOutcome::Conflict);
                }

                sql_query(
                    "INSERT INTO webvh_log_events \
                     (id, did, seq, operation, created_at) VALUES ($1, $2, $3, $4, $5)",
                )
                .bind::<Text, _>(&event.event_digest)
                .bind::<Text, _>(&event.did)
                .bind::<BigInt, _>(event.seq as i64)
                .bind::<Jsonb, _>(&event.operation)
                .bind::<Timestamptz, _>(event.created_at)
                .execute(&mut *conn)
                .await?;

                let (fetched_at, expires_at) = webvh_freshness_on_put();
                sql_query(
                    "INSERT INTO webvh_documents \
                     (id, did_document, key_log_head, seq, method_evidence, \
                      fetched_at, expires_at, updated_at) \
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
                )
                .bind::<Text, _>(&document.did)
                .bind::<Jsonb, _>(&document.did_document)
                .bind::<Nullable<Text>, _>(&document.key_log_head)
                .bind::<BigInt, _>(document.seq as i64)
                .bind::<Jsonb, _>(&document.method_evidence)
                .bind::<Timestamptz, _>(fetched_at)
                .bind::<Timestamptz, _>(expires_at)
                .bind::<Timestamptz, _>(document.updated_at)
                .execute(&mut *conn)
                .await?;

                let outcome_json = serde_json::to_value(&outcome).map_err(|error| {
                    PersistenceError::Internal(format!(
                        "service registration outcome serialization failed: {error}"
                    ))
                })?;
                sql_query(
                    "INSERT INTO service_identity_registrations \
                     (service_type, public_base, service_id, version_id, inception_digest, outcome, created_at, updated_at) \
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $7)",
                )
                .bind::<Text, _>(service_type)
                .bind::<Text, _>(public_base)
                .bind::<Text, _>(outcome.service_id.as_str())
                .bind::<Text, _>(&outcome.version_id)
                .bind::<Text, _>(&outcome.registration_receipt.log_head_digest)
                .bind::<Jsonb, _>(&outcome_json)
                .bind::<Timestamptz, _>(event.created_at)
                .execute(&mut *conn)
                .await?;

                Ok(ServiceRegistrationCommitOutcome::Created(outcome))
            },
        )
        .await
    }
}

fn decode_registration_outcome(
    value: Value,
) -> PersistenceResult<arkret_sdk::ServiceRegistrationOutcome> {
    serde_json::from_value(value).map_err(|error| {
        PersistenceError::Internal(format!(
            "stored service registration outcome is invalid: {error}"
        ))
    })
}

fn registration_as_existing(
    mut outcome: arkret_sdk::ServiceRegistrationOutcome,
) -> arkret_sdk::ServiceRegistrationOutcome {
    outcome.created = false;
    outcome
}

fn registrations_match(
    left: &arkret_sdk::ServiceRegistrationOutcome,
    right: &arkret_sdk::ServiceRegistrationOutcome,
) -> bool {
    left.service_id == right.service_id
        && left.version_id == right.version_id
        && left.registration_receipt.log_head_digest == right.registration_receipt.log_head_digest
        && left.registration_receipt.control_key_digest
            == right.registration_receipt.control_key_digest
}

fn valid_new_service_registration_records(
    outcome: &arkret_sdk::ServiceRegistrationOutcome,
    document: &WebvhDocumentRecord,
    event: &WebvhLogRecord,
) -> bool {
    document.did == outcome.service_id.as_str()
        && event.did == outcome.service_id.as_str()
        && document.seq == 1
        && event.seq == 1
        && document.key_log_head.as_deref() == Some(event.event_digest.as_str())
        && outcome.registration_receipt.log_head_digest == event.event_digest
}

fn document_declares_registration_key(
    document: &Value,
    key: &arkret_sdk::ServiceRegistrationKey,
) -> bool {
    document
        .get("service")
        .and_then(Value::as_array)
        .is_some_and(|services| {
            services.iter().any(|entry| {
                entry.get("type").and_then(Value::as_str) == Some("ArkretService")
                    && entry.get("serviceType").and_then(Value::as_str)
                        == Some(key.service_type().as_str())
                    && entry.get("serviceEndpoint").and_then(Value::as_str)
                        == Some(key.public_base().as_str())
            })
        })
}
