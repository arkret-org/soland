use super::{
    Jsonb, OptionalExtension, PersistenceError, PersistenceResult, PgPool,
    ProposalMemberReceiptRecord, ProposalMemberReceiptStore, QueryableByName, RunQueryDsl, Text,
    Timestamptz, Utc, Value, async_trait, pg_conn, sql_query,
};

pub struct PgProposalMemberReceiptStore {
    pub pool: PgPool,
}

#[derive(QueryableByName)]
struct Row {
    #[diesel(sql_type = Text)]
    receipt_key: String,
    #[diesel(sql_type = Text)]
    request_hash: String,
    #[diesel(sql_type = Jsonb)]
    response_body: Value,
    #[diesel(sql_type = Timestamptz)]
    created_at: chrono::DateTime<Utc>,
}

impl From<Row> for ProposalMemberReceiptRecord {
    fn from(row: Row) -> Self {
        Self {
            receipt_key: row.receipt_key,
            request_hash: row.request_hash,
            response_body: row.response_body,
            created_at: row.created_at,
        }
    }
}

#[async_trait]
impl ProposalMemberReceiptStore for PgProposalMemberReceiptStore {
    async fn get(
        &self,
        receipt_key: &str,
    ) -> PersistenceResult<Option<ProposalMemberReceiptRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(
            "SELECT receipt_key, request_hash, response_body, created_at \
             FROM proposal_member_receipts WHERE receipt_key = $1",
        )
        .bind::<Text, _>(receipt_key)
        .get_result::<Row>(&mut *conn)
        .await
        .optional()
        .map(|row| row.map(Into::into))
        .map_err(PersistenceError::database)
    }

    async fn record(&self, record: &ProposalMemberReceiptRecord) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(
            "INSERT INTO proposal_member_receipts \
             (receipt_key, request_hash, response_body, created_at) \
             VALUES ($1, $2, $3, $4) ON CONFLICT (receipt_key) DO NOTHING",
        )
        .bind::<Text, _>(&record.receipt_key)
        .bind::<Text, _>(&record.request_hash)
        .bind::<Jsonb, _>(&record.response_body)
        .bind::<Timestamptz, _>(record.created_at)
        .execute(&mut *conn)
        .await
        .map(|_| ())
        .map_err(PersistenceError::database)
    }
}
