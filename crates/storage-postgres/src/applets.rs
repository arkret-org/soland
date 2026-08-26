use super::{
    AppletAuthoringPreviewRecord, AppletStore, AppletTransactionReplayBegin,
    AppletTransactionReplayRecord, AsyncConnection, Jsonb, Nullable, OptionalExtension,
    PersistenceError, PersistenceResult, PgPool, PgTransactionError, QueryableByName, RunQueryDsl,
    Text, Timestamptz, Value, applet_registration_select_sql, applet_transaction_replay_select_sql,
    async_trait, pg_conn, sql_query,
};
#[derive(QueryableByName)]
struct AppletRegistrationRow {
    #[diesel(sql_type = Jsonb)]
    record: Value,
}
#[derive(QueryableByName)]
struct AppletTransactionReplayRow {
    #[diesel(sql_type = Text)]
    applet_id: String,
    #[diesel(sql_type = Text)]
    source_service_id: String,
    #[diesel(sql_type = Text)]
    idempotency_key: String,
    #[diesel(sql_type = Text)]
    delivery_authentication_record_digest: String,
    #[diesel(sql_type = Text)]
    request_digest: String,
    #[diesel(sql_type = Nullable<Jsonb>)]
    outcome: Option<Value>,
    #[diesel(sql_type = Timestamptz)]
    received_at: chrono::DateTime<chrono::Utc>,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    completed_at: Option<chrono::DateTime<chrono::Utc>>,
}
#[derive(QueryableByName)]
struct AppletAuthoringPreviewRow {
    #[diesel(sql_type = Text)]
    subject_key: String,
    #[diesel(sql_type = Text)]
    basis_digest: String,
    #[diesel(sql_type = Text)]
    request_digest: String,
    #[diesel(sql_type = Jsonb)]
    signed_request: Value,
    #[diesel(sql_type = Timestamptz)]
    issued_at: chrono::DateTime<chrono::Utc>,
    #[diesel(sql_type = Timestamptz)]
    expires_at: chrono::DateTime<chrono::Utc>,
}
impl From<AppletRegistrationRow> for Value {
    fn from(row: AppletRegistrationRow) -> Self {
        row.record
    }
}
impl From<AppletTransactionReplayRow> for AppletTransactionReplayRecord {
    fn from(row: AppletTransactionReplayRow) -> Self {
        Self {
            applet_id: arkret_wire::AppletId::new(row.applet_id)
                .expect("stored applet transaction id must be canonical"),
            source_service_id: row.source_service_id,
            idempotency_key: row.idempotency_key,
            delivery_authentication_record_digest: row.delivery_authentication_record_digest,
            request_digest: row.request_digest,
            outcome: row.outcome,
            received_at: row.received_at,
            completed_at: row.completed_at,
        }
    }
}
impl From<AppletAuthoringPreviewRow> for AppletAuthoringPreviewRecord {
    fn from(row: AppletAuthoringPreviewRow) -> Self {
        Self {
            subject_key: row.subject_key,
            basis_digest: row.basis_digest,
            request_digest: row.request_digest,
            signed_request: row.signed_request,
            issued_at: row.issued_at,
            expires_at: row.expires_at,
        }
    }
}
pub struct PgAppletStore {
    pub pool: PgPool,
}
#[async_trait]
impl AppletStore for PgAppletStore {
    async fn get(&self, applet_id: &str) -> PersistenceResult<Option<Value>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(applet_registration_select_sql("WHERE id = $1"))
            .bind::<Text, _>(applet_id)
            .get_result::<AppletRegistrationRow>(&mut *conn)
            .await
            .optional()
            .map(|row| row.map(Value::from))
            .map_err(PersistenceError::database)
    }

    async fn compare_and_swap(
        &self,
        applet_id: &str,
        expected: &Value,
        replacement: Value,
    ) -> PersistenceResult<bool> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(
            "UPDATE applet_registrations SET record = $3, updated_at = NOW() \
             WHERE id = $1 AND record = $2",
        )
        .bind::<Text, _>(applet_id)
        .bind::<Jsonb, _>(expected)
        .bind::<Jsonb, _>(&replacement)
        .execute(&mut *conn)
        .await
        .map(|updated| updated == 1)
        .map_err(PersistenceError::database)
    }

    async fn list(&self) -> PersistenceResult<Vec<Value>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(applet_registration_select_sql(
            "ORDER BY record->>'registered_at', id",
        ))
        .load::<AppletRegistrationRow>(&mut *conn)
        .await
        .map(|rows| rows.into_iter().map(Value::from).collect())
        .map_err(PersistenceError::database)
    }

    async fn begin_transaction_replay(
        &self,
        record: AppletTransactionReplayRecord,
    ) -> PersistenceResult<AppletTransactionReplayBegin> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let inserted = sql_query(
            "INSERT INTO applet_transactions \
             (applet_id, source_service_id, idempotency_key, delivery_authentication_record_digest, request_digest, \
              outcome, received_at, completed_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8) \
             ON CONFLICT (applet_id, source_service_id, idempotency_key) DO NOTHING",
        )
        .bind::<Text, _>(record.applet_id.as_str())
        .bind::<Text, _>(&record.source_service_id)
        .bind::<Text, _>(&record.idempotency_key)
        .bind::<Text, _>(&record.delivery_authentication_record_digest)
        .bind::<Text, _>(&record.request_digest)
        .bind::<Nullable<Jsonb>, _>(&record.outcome)
        .bind::<Timestamptz, _>(record.received_at)
        .bind::<Nullable<Timestamptz>, _>(record.completed_at)
        .execute(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
        if inserted == 1 {
            return Ok(AppletTransactionReplayBegin::Fresh);
        }
        sql_query(applet_transaction_replay_select_sql())
            .bind::<Text, _>(record.applet_id.as_str())
            .bind::<Text, _>(&record.source_service_id)
            .bind::<Text, _>(&record.idempotency_key)
            .get_result::<AppletTransactionReplayRow>(&mut *conn)
            .await
            .optional()
            .map_err(PersistenceError::database)?
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
        applet_id: &str,
        source_service_id: &str,
        idempotency_key: &str,
        outcome: Value,
    ) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(
            "UPDATE applet_transactions \
             SET outcome = $4, completed_at = NOW() \
             WHERE applet_id = $1 AND source_service_id = $2 AND idempotency_key = $3",
        )
        .bind::<Text, _>(applet_id)
        .bind::<Text, _>(source_service_id)
        .bind::<Text, _>(idempotency_key)
        .bind::<Jsonb, _>(&outcome)
        .execute(&mut *conn)
        .await
        .map_err(PersistenceError::database)
        .and_then(|updated| {
            if updated == 0 {
                Err(PersistenceError::NotFound(format!(
                    "applet transaction replay missing for {applet_id}/{source_service_id}/{idempotency_key}"
                )))
            } else {
                Ok(())
            }
        })
    }

    async fn issue_authoring_preview(
        &self,
        candidate: AppletAuthoringPreviewRecord,
    ) -> PersistenceResult<AppletAuthoringPreviewRecord> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            sql_query("SELECT pg_advisory_xact_lock(hashtextextended($1, 1634758768))")
                .bind::<Text, _>(&candidate.subject_key)
                .execute(&mut *conn)
                .await?;
            let current = sql_query(
                "SELECT subject_key, basis_digest, request_digest, signed_request, issued_at, expires_at \
                 FROM applet_authoring_previews WHERE subject_key = $1 AND status = 'current'",
            )
            .bind::<Text, _>(&candidate.subject_key)
            .get_result::<AppletAuthoringPreviewRow>(&mut *conn)
            .await
            .optional()?;
            if let Some(current) = current
                && current.basis_digest == candidate.basis_digest
                && current.expires_at > candidate.issued_at
            {
                return Ok(current.into());
            }
            sql_query(
                "UPDATE applet_authoring_previews SET status = 'superseded', superseded_at = NOW() \
                 WHERE subject_key = $1 AND status = 'current'",
            )
            .bind::<Text, _>(&candidate.subject_key)
            .execute(&mut *conn)
            .await?;
            sql_query(
                "INSERT INTO applet_authoring_previews \
                 (subject_key, basis_digest, request_digest, signed_request, issued_at, expires_at, status) \
                 VALUES ($1, $2, $3, $4, $5, $6, 'current') \
                 ON CONFLICT (subject_key, request_digest) DO UPDATE SET \
                 basis_digest = EXCLUDED.basis_digest, signed_request = EXCLUDED.signed_request, \
                 issued_at = EXCLUDED.issued_at, expires_at = EXCLUDED.expires_at, \
                 status = 'current', superseded_at = NULL, committed_at = NULL",
            )
            .bind::<Text, _>(&candidate.subject_key)
            .bind::<Text, _>(&candidate.basis_digest)
            .bind::<Text, _>(&candidate.request_digest)
            .bind::<Jsonb, _>(&candidate.signed_request)
            .bind::<Timestamptz, _>(candidate.issued_at)
            .bind::<Timestamptz, _>(candidate.expires_at)
            .execute(&mut *conn)
            .await?;
            Ok(candidate)
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }

    async fn current_authoring_preview(
        &self,
        subject_key: &str,
    ) -> PersistenceResult<Option<AppletAuthoringPreviewRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(
            "SELECT subject_key, basis_digest, request_digest, signed_request, issued_at, expires_at \
             FROM applet_authoring_previews WHERE subject_key = $1 AND status = 'current'",
        )
        .bind::<Text, _>(subject_key)
        .get_result::<AppletAuthoringPreviewRow>(&mut *conn)
        .await
        .optional()
        .map(|row| row.map(AppletAuthoringPreviewRecord::from))
        .map_err(PersistenceError::database)
    }
}
