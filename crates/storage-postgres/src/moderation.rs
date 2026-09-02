use super::{
    Binary, JsonPayloadRow, Jsonb, ModerationStore, Nullable, OptionalExtension, PersistenceError,
    PersistenceResult, PgPool, RunQueryDsl, Text, Value, async_trait, ids, pg_conn, sql_query,
};
pub struct PgModerationStore {
    pub pool: PgPool,
}
#[async_trait]
impl ModerationStore for PgModerationStore {
    async fn append_report(&self, report: Value) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let extract = |key: &str| -> Option<String> {
            report
                .get(key)
                .and_then(Value::as_str)
                .map(ToOwned::to_owned)
        };
        let report_id = extract("report_id").ok_or_else(|| {
            PersistenceError::Internal("moderation report missing report_id".to_owned())
        })?;
        let reporter_id = extract("reporter_id");
        let target_actor = extract("target_actor");
        let target_event_id = extract("target_event_id");
        let realm_id = extract("realm_id");
        // `report` is Event-derived and `target_event_id` names an Event, so both
        // carry the 33-byte token rather than a UUID.
        let report_id_token =
            ids::event_token_part_or_schema_violation(&report_id, "report")?.to_vec();
        let target_event_id_token = target_event_id
            .as_deref()
            .map(|event_id| ids::event_token_part_or_schema_violation(event_id, "event"))
            .transpose()?
            .map(|token| token.to_vec());
        crate::realm_identity::ensure_optional_realm_pk(&mut conn, realm_id.as_deref()).await?;
        sql_query(
            "INSERT INTO moderation_reports \
             (id, reporter_id, target_actor_id, target_event_id, realm_id, payload, created_at) \
             VALUES ($1, $2, $3, $4, $5, $6, NOW()) \
             ON CONFLICT (id) DO UPDATE SET \
             reporter_id = EXCLUDED.reporter_id, \
             target_actor_id = EXCLUDED.target_actor_id, \
             target_event_id = EXCLUDED.target_event_id, \
             realm_id = EXCLUDED.realm_id, payload = EXCLUDED.payload",
        )
        .bind::<Binary, _>(report_id_token)
        .bind::<Nullable<Text>, _>(&reporter_id)
        .bind::<Nullable<Text>, _>(&target_actor)
        .bind::<Nullable<Binary>, _>(target_event_id_token)
        .bind::<Nullable<Text>, _>(realm_id.as_deref())
        .bind::<Jsonb, _>(&report)
        .execute(&mut *conn)
        .await
        .map(|_| ())
        .map_err(PersistenceError::database)
    }

    async fn list_reports(&self) -> PersistenceResult<Vec<Value>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query("SELECT payload FROM moderation_reports ORDER BY created_at ASC, pk ASC")
            .load::<JsonPayloadRow>(&mut *conn)
            .await
            .map(|rows| rows.into_iter().map(|row| row.payload).collect())
            .map_err(PersistenceError::database)
    }

    async fn upsert_queue_item(&self, item: Value) -> PersistenceResult<()> {
        let id = item.get("id").and_then(Value::as_str).ok_or_else(|| {
            PersistenceError::Internal("moderation queue item missing id".to_owned())
        })?;
        let realm_id = item
            .pointer("/report/realm_id")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned);
        let report_event_id = item
            .pointer("/report/event_id")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                PersistenceError::Internal(
                    "moderation queue item missing report.event_id".to_owned(),
                )
            })?;
        let id_token =
            ids::event_token_part_or_schema_violation(id, "moderation_queue_item")?.to_vec();
        let report_event_id_token =
            ids::event_token_part_or_schema_violation(report_event_id, "event")?.to_vec();
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        crate::realm_identity::ensure_optional_realm_pk(&mut conn, realm_id.as_deref()).await?;
        sql_query(
            "INSERT INTO moderation_queue_items \
             (id, report_event_id, realm_id, payload, created_at) \
             VALUES ($1, $2, $3, $4, NOW()) \
             ON CONFLICT (id) DO UPDATE SET report_event_id = EXCLUDED.report_event_id, \
             realm_id = EXCLUDED.realm_id, payload = EXCLUDED.payload",
        )
        .bind::<Binary, _>(id_token)
        .bind::<Binary, _>(report_event_id_token)
        .bind::<Nullable<Text>, _>(realm_id.as_deref())
        .bind::<Jsonb, _>(&item)
        .execute(&mut *conn)
        .await
        .map(|_| ())
        .map_err(PersistenceError::database)
    }

    async fn list_queue_items(&self) -> PersistenceResult<Vec<Value>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query("SELECT payload FROM moderation_queue_items ORDER BY created_at ASC, pk ASC")
            .load::<JsonPayloadRow>(&mut *conn)
            .await
            .map(|rows| rows.into_iter().map(|row| row.payload).collect())
            .map_err(PersistenceError::database)
    }

    async fn get_queue_item(&self, id: &str) -> PersistenceResult<Option<Value>> {
        let id_token =
            ids::event_token_part_or_schema_violation(id, "moderation_queue_item")?.to_vec();
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query("SELECT payload FROM moderation_queue_items WHERE id = $1")
            .bind::<Binary, _>(id_token)
            .get_result::<JsonPayloadRow>(&mut *conn)
            .await
            .optional()
            .map(|row| row.map(|row| row.payload))
            .map_err(PersistenceError::database)
    }

    async fn get_submitted_queue_item_for_report_event(
        &self,
        report_event_id: &str,
    ) -> PersistenceResult<Option<Value>> {
        let report_event_id_token =
            ids::event_token_part_or_schema_violation(report_event_id, "event")?.to_vec();
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(
            "SELECT payload FROM moderation_queue_items \
             WHERE report_event_id = $1 AND payload ->> 'status' = 'submitted' \
             ORDER BY created_at ASC, pk ASC LIMIT 1",
        )
        .bind::<Binary, _>(report_event_id_token)
        .get_result::<JsonPayloadRow>(&mut *conn)
        .await
        .optional()
        .map(|row| row.map(|row| row.payload))
        .map_err(PersistenceError::database)
    }

    async fn append_appeal(&self, appeal: Value) -> PersistenceResult<()> {
        let appeal_id = appeal
            .get("appeal_id")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                PersistenceError::Internal("moderation appeal missing appeal_id".to_owned())
            })?;
        let source_event_id = appeal
            .get("source_event_id")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                PersistenceError::Internal("moderation appeal missing source_event_id".to_owned())
            })?;
        let projected_at = appeal
            .get("projected_at")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                PersistenceError::Internal("moderation appeal missing projected_at".to_owned())
            })?;
        let appeal_id_token =
            ids::event_token_part_or_schema_violation(appeal_id, "appeal")?.to_vec();
        let source_event_id_token =
            ids::event_token_part_or_schema_violation(source_event_id, "event")?.to_vec();
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let inserted = sql_query(
            "INSERT INTO moderation_appeal_events \
             (appeal_id, source_event_id, payload, projected_at) \
             VALUES ($1, $2, $3, CAST($4 AS timestamptz)) \
             ON CONFLICT (source_event_id) DO NOTHING",
        )
        .bind::<Binary, _>(appeal_id_token)
        .bind::<Binary, _>(source_event_id_token.clone())
        .bind::<Jsonb, _>(&appeal)
        .bind::<Text, _>(projected_at)
        .execute(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
        if inserted == 0 {
            let existing = sql_query(
                "SELECT payload FROM moderation_appeal_events WHERE source_event_id = $1",
            )
            .bind::<Binary, _>(source_event_id_token)
            .get_result::<JsonPayloadRow>(&mut *conn)
            .await
            .map_err(PersistenceError::database)?;
            if existing.payload != appeal {
                return Err(PersistenceError::Conflict(
                    "moderation appeal source Event replay changed its projection".to_owned(),
                ));
            }
        }
        Ok(())
    }

    async fn list_appeals(&self) -> PersistenceResult<Vec<Value>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(
            "SELECT payload FROM ( \
               SELECT DISTINCT ON (appeal_id) appeal_id, payload, pk \
               FROM moderation_appeal_events ORDER BY appeal_id, pk DESC \
             ) latest ORDER BY appeal_id",
        )
        .load::<JsonPayloadRow>(&mut *conn)
        .await
        .map(|rows| rows.into_iter().map(|row| row.payload).collect())
        .map_err(PersistenceError::database)
    }

    async fn appeal_history(&self, appeal_id: &str) -> PersistenceResult<Vec<Value>> {
        let appeal_id_token =
            ids::event_token_part_or_schema_violation(appeal_id, "appeal")?.to_vec();
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(
            "SELECT payload FROM moderation_appeal_events \
             WHERE appeal_id = $1 ORDER BY pk ASC",
        )
        .bind::<Binary, _>(appeal_id_token)
        .load::<JsonPayloadRow>(&mut *conn)
        .await
        .map(|rows| rows.into_iter().map(|row| row.payload).collect())
        .map_err(PersistenceError::database)
    }
}
