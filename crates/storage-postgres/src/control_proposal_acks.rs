use super::{
    Jsonb, OptionalExtension, PersistenceError, PersistenceResult, PgPool,
    ControlProposalAuthorityAckRecord, ControlProposalAuthorityAckStore, QueryableByName, RunQueryDsl, Text,
    Timestamptz, Utc, Value, async_trait, pg_conn, sql_query,
};

pub struct PgControlProposalAuthorityAckStore {
    pub pool: PgPool,
}

#[derive(QueryableByName)]
struct Row {
    #[diesel(sql_type = Text)]
    ack_key: String,
    #[diesel(sql_type = Text)]
    request_hash: String,
    #[diesel(sql_type = Jsonb)]
    response_body: Value,
    #[diesel(sql_type = Timestamptz)]
    created_at: chrono::DateTime<Utc>,
}

impl From<Row> for ControlProposalAuthorityAckRecord {
    fn from(row: Row) -> Self {
        Self {
            ack_key: row.ack_key,
            request_hash: row.request_hash,
            response_body: row.response_body,
            created_at: row.created_at,
        }
    }
}

#[async_trait]
impl ControlProposalAuthorityAckStore for PgControlProposalAuthorityAckStore {
    async fn get(
        &self,
        ack_key: &str,
    ) -> PersistenceResult<Option<ControlProposalAuthorityAckRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(
            "SELECT ack_key, request_hash, response_body, created_at \
             FROM control_proposal_authority_acks WHERE ack_key = $1",
        )
        .bind::<Text, _>(ack_key)
        .get_result::<Row>(&mut *conn)
        .await
        .optional()
        .map(|row| row.map(Into::into))
        .map_err(PersistenceError::database)
    }

    async fn record(&self, record: &ControlProposalAuthorityAckRecord) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(
            "INSERT INTO control_proposal_authority_acks \
             (ack_key, request_hash, response_body, created_at) \
             VALUES ($1, $2, $3, $4) ON CONFLICT (ack_key) DO NOTHING",
        )
        .bind::<Text, _>(&record.ack_key)
        .bind::<Text, _>(&record.request_hash)
        .bind::<Jsonb, _>(&record.response_body)
        .bind::<Timestamptz, _>(record.created_at)
        .execute(&mut *conn)
        .await
        .map(|_| ())
        .map_err(PersistenceError::database)
    }
}
