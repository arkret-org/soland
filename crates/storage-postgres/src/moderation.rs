use super::{
    Binary, JsonPayloadRow, Jsonb, ModerationStore, Nullable, PersistenceError, PersistenceResult,
    PgPool, RunQueryDsl, SqlUuid, Text, Value, async_trait, ids, pg_conn, sql_query,
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
        let reporter = extract("reporter");
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
             ON CONFLICT (id) DO NOTHING",
        )
        .bind::<Binary, _>(report_id_token)
        .bind::<Nullable<Text>, _>(&reporter)
        .bind::<Nullable<Text>, _>(&target_actor)
        .bind::<Nullable<Binary>, _>(target_event_id_token)
        .bind::<Nullable<Text>, _>(realm_id.as_deref())
        .bind::<Jsonb, _>(&report)
        .execute(&mut *conn)
        .await
        .map(|_| ())
        .map_err(PersistenceError::database)
    }

    async fn append_action(&self, action: Value) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let extract = |key: &str| -> Option<String> {
            action
                .get(key)
                .and_then(Value::as_str)
                .map(ToOwned::to_owned)
        };
        let action_id = extract("action_id").ok_or_else(|| {
            PersistenceError::Internal("moderation action missing action_id".to_owned())
        })?;
        let moderator = extract("moderator");
        let target_actor = extract("target_actor");
        let action_kind = extract("action_kind");
        let realm_id = extract("realm_id");
        let action_id_uuid = ids::typed_uuid_part_expect_internal(&action_id);
        crate::realm_identity::ensure_optional_realm_pk(&mut conn, realm_id.as_deref()).await?;
        sql_query(
            "INSERT INTO moderation_actions \
             (id, moderator_id, target_actor_id, action_kind, realm_id, payload, created_at) \
             VALUES ($1, $2, $3, $4, $5, $6, NOW()) \
             ON CONFLICT (id) DO NOTHING",
        )
        .bind::<SqlUuid, _>(action_id_uuid)
        .bind::<Nullable<Text>, _>(&moderator)
        .bind::<Nullable<Text>, _>(&target_actor)
        .bind::<Nullable<Text>, _>(&action_kind)
        .bind::<Nullable<Text>, _>(realm_id.as_deref())
        .bind::<Jsonb, _>(&action)
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

    async fn list_actions(&self) -> PersistenceResult<Vec<Value>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query("SELECT payload FROM moderation_actions ORDER BY created_at ASC, id ASC")
            .load::<JsonPayloadRow>(&mut *conn)
            .await
            .map(|rows| rows.into_iter().map(|row| row.payload).collect())
            .map_err(PersistenceError::database)
    }
}
