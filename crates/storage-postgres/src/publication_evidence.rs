use super::{
    Jsonb, OptionalExtension, PersistenceError, PersistenceResult, PgPool,
    PublicationEvidenceRecord, PublicationEvidenceStore, QueryableByName, RunQueryDsl, Text, Value,
    async_trait, pg_conn, sql_query,
};

/// PostgreSQL-backed publication evidence keyed by Event canonical digest
/// (`authz/offline-publication.md` §2.1).
pub struct PgPublicationEvidenceStore {
    pub pool: PgPool,
}

#[derive(QueryableByName)]
struct PublicationEvidenceRow {
    #[diesel(sql_type = Text)]
    event_digest: String,
    #[diesel(sql_type = Text)]
    realm_id: String,
    #[diesel(sql_type = Jsonb)]
    authorization_lease: Value,
    #[diesel(sql_type = Jsonb)]
    ingress_receipt: Value,
}

impl TryFrom<PublicationEvidenceRow> for PublicationEvidenceRecord {
    type Error = PersistenceError;

    fn try_from(row: PublicationEvidenceRow) -> PersistenceResult<Self> {
        Ok(Self {
            event_digest: row.event_digest,
            realm_id: row.realm_id,
            authorization_lease: serde_json::from_value(row.authorization_lease).map_err(
                |error| {
                    PersistenceError::SchemaViolation(format!(
                        "stored authorization_lease is invalid: {error}"
                    ))
                },
            )?,
            ingress_receipt: serde_json::from_value(row.ingress_receipt).map_err(|error| {
                PersistenceError::SchemaViolation(format!(
                    "stored ingress_receipt is invalid: {error}"
                ))
            })?,
        })
    }
}

const PUBLICATION_EVIDENCE_COLUMNS: &str =
    "event_digest, realm_id, authorization_lease, ingress_receipt";

#[async_trait]
impl PublicationEvidenceStore for PgPublicationEvidenceStore {
    async fn put_if_absent(
        &self,
        record: PublicationEvidenceRecord,
    ) -> PersistenceResult<PublicationEvidenceRecord> {
        let lease = serde_json::to_value(&record.authorization_lease).map_err(|error| {
            PersistenceError::Internal(format!("failed to encode authorization_lease: {error}"))
        })?;
        let receipt = serde_json::to_value(&record.ingress_receipt).map_err(|error| {
            PersistenceError::Internal(format!("failed to encode ingress_receipt: {error}"))
        })?;
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        // `DO NOTHING` then read back: the first receipt for a digest is the
        // one that stands, so an idempotent retry observes the original
        // `received_at` instead of a re-stamped one.
        sql_query(
            "INSERT INTO publication_evidence \
             (event_digest, realm_id, authorization_lease, ingress_receipt, created_at) \
             VALUES ($1, $2, $3, $4, NOW()) \
             ON CONFLICT (event_digest) DO NOTHING",
        )
        .bind::<Text, _>(&record.event_digest)
        .bind::<Text, _>(&record.realm_id)
        .bind::<Jsonb, _>(&lease)
        .bind::<Jsonb, _>(&receipt)
        .execute(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;

        let row = sql_query(format!(
            "SELECT {PUBLICATION_EVIDENCE_COLUMNS} FROM publication_evidence \
             WHERE event_digest = $1"
        ))
        .bind::<Text, _>(&record.event_digest)
        .get_result::<PublicationEvidenceRow>(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
        PublicationEvidenceRecord::try_from(row)
    }

    async fn get(
        &self,
        event_digest: &str,
    ) -> PersistenceResult<Option<PublicationEvidenceRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let row = sql_query(format!(
            "SELECT {PUBLICATION_EVIDENCE_COLUMNS} FROM publication_evidence \
             WHERE event_digest = $1"
        ))
        .bind::<Text, _>(event_digest)
        .get_result::<PublicationEvidenceRow>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?;
        row.map(PublicationEvidenceRecord::try_from).transpose()
    }

    async fn get_many(
        &self,
        event_digests: &[String],
    ) -> PersistenceResult<Vec<PublicationEvidenceRecord>> {
        if event_digests.is_empty() {
            return Ok(Vec::new());
        }
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let rows = sql_query(format!(
            "SELECT {PUBLICATION_EVIDENCE_COLUMNS} FROM publication_evidence \
             WHERE event_digest = ANY($1)"
        ))
        .bind::<diesel::sql_types::Array<Text>, _>(event_digests.to_vec())
        .load::<PublicationEvidenceRow>(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
        let mut by_digest = std::collections::BTreeMap::new();
        for row in rows {
            let record = PublicationEvidenceRecord::try_from(row)?;
            by_digest.insert(record.event_digest.clone(), record);
        }
        // Preserve the caller's order: it is the Event order of the federation
        // batch being assembled.
        Ok(event_digests
            .iter()
            .filter_map(|digest| by_digest.get(digest).cloned())
            .collect())
    }
}
