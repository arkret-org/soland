use arkret_models_collaboration::governance::agent_membership_cascade::AgentCleanupPendingRecord;
use arkret_wire::Hash;

use super::*;

#[derive(QueryableByName)]
struct CleanupIntentRow {
    #[diesel(sql_type = Jsonb)]
    record_json: Value,
}

pub struct PgAgentMembershipCascadeStore {
    pub pool: PgPool,
}

fn decode_record(row: CleanupIntentRow) -> PersistenceResult<AgentCleanupPendingRecord> {
    let record =
        serde_json::from_value::<AgentCleanupPendingRecord>(row.record_json).map_err(|error| {
            PersistenceError::Internal(format!(
                "stored Agent membership cleanup intent is invalid: {error}"
            ))
        })?;
    record.validate().map_err(|error| {
        PersistenceError::Internal(format!(
            "stored Agent membership cleanup intent violates its schema: {error}"
        ))
    })?;
    Ok(record)
}

async fn mark_overdue(
    conn: &mut AsyncPgConnection,
    now: chrono::DateTime<Utc>,
) -> PersistenceResult<()> {
    sql_query(
        "UPDATE agent_membership_cleanup_intents SET \
             status = 'agent_cleanup_overdue', \
             record_json = jsonb_set(record_json, '{status}', to_jsonb('agent_cleanup_overdue'::text), true), \
             updated_at = $1 \
         WHERE status = 'agent_cleanup_pending' AND cleanup_due_at <= $1",
    )
    .bind::<Timestamptz, _>(now)
    .execute(conn)
    .await
    .map_err(PersistenceError::database)?;
    Ok(())
}

#[async_trait]
impl soland_storage::AgentMembershipCascadeStore for PgAgentMembershipCascadeStore {
    async fn agent_cleanup_intent(
        &self,
        cleanup_intent_digest: &Hash,
    ) -> PersistenceResult<Option<AgentCleanupPendingRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        mark_overdue(&mut conn, Utc::now()).await?;
        sql_query(
            "SELECT record_json FROM agent_membership_cleanup_intents \
             WHERE cleanup_intent_digest = $1",
        )
        .bind::<Text, _>(cleanup_intent_digest.as_str())
        .get_result::<CleanupIntentRow>(&mut conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?
        .map(decode_record)
        .transpose()
    }

    async fn agent_cleanup_intent_for_terminal_event(
        &self,
        controller_terminal_event_id: &arkret_wire::EventId,
    ) -> PersistenceResult<Option<AgentCleanupPendingRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        mark_overdue(&mut conn, Utc::now()).await?;
        sql_query(
            "SELECT record_json FROM agent_membership_cleanup_intents \
             WHERE controller_terminal_event_id = $1",
        )
        .bind::<Text, _>(controller_terminal_event_id.as_str())
        .get_result::<CleanupIntentRow>(&mut conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?
        .map(decode_record)
        .transpose()
    }

    async fn incomplete_agent_cleanup_intents(
        &self,
        now: chrono::DateTime<Utc>,
        limit: usize,
    ) -> PersistenceResult<Vec<AgentCleanupPendingRecord>> {
        let limit = i64::try_from(limit).map_err(|_| {
            PersistenceError::SchemaViolation("Agent cleanup query limit is too large".to_owned())
        })?;
        let mut conn = pg_conn(&self.pool).await?;
        mark_overdue(&mut conn, now).await?;
        sql_query(
            "SELECT record_json FROM agent_membership_cleanup_intents \
             WHERE status IN ('agent_cleanup_pending', 'agent_cleanup_overdue') \
             ORDER BY cleanup_due_at ASC, cleanup_intent_digest ASC LIMIT $1",
        )
        .bind::<BigInt, _>(limit)
        .load::<CleanupIntentRow>(&mut conn)
        .await
        .map_err(PersistenceError::database)?
        .into_iter()
        .map(decode_record)
        .collect()
    }
}
