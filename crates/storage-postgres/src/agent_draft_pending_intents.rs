use diesel::sql_types::{Jsonb, Nullable, Text, Timestamptz};
use diesel::{OptionalExtension, sql_query};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use soland_storage::{
    AgentDraftPendingIntentCommit, AgentDraftPendingIntentConsumption,
    AgentDraftPendingIntentRecord, AgentDraftPendingIntentState, AgentDraftPendingIntentStore,
    PersistenceError, PersistenceResult,
};

use crate::{PgPool, pg_conn};

#[derive(Clone)]
pub struct PgAgentDraftPendingIntentStore {
    pub(crate) pool: PgPool,
}

#[derive(diesel::QueryableByName)]
struct PendingIntentRow {
    #[diesel(sql_type = Jsonb)]
    controller_account_id: serde_json::Value,
    #[diesel(sql_type = Text)]
    agent_id: String,
    #[diesel(sql_type = Text)]
    draft_id: String,
    #[diesel(sql_type = Text)]
    proposed_action: String,
    #[diesel(sql_type = Jsonb)]
    target: serde_json::Value,
    #[diesel(sql_type = Text)]
    content_digest: String,
    #[diesel(sql_type = Nullable<Jsonb>)]
    content_handoff: Option<serde_json::Value>,
    #[diesel(sql_type = Text)]
    canonical_event_digest: String,
    #[diesel(sql_type = Text)]
    accepted_event_id: String,
    #[diesel(sql_type = Timestamptz)]
    expires_at: chrono::DateTime<chrono::Utc>,
    #[diesel(sql_type = Timestamptz)]
    created_at: chrono::DateTime<chrono::Utc>,
    #[diesel(sql_type = Text)]
    state: String,
    #[diesel(sql_type = Nullable<Jsonb>)]
    consumption: Option<serde_json::Value>,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    expired_at: Option<chrono::DateTime<chrono::Utc>>,
}

impl TryFrom<PendingIntentRow> for AgentDraftPendingIntentRecord {
    type Error = PersistenceError;

    fn try_from(row: PendingIntentRow) -> Result<Self, Self::Error> {
        let state = match row.state.as_str() {
            "available" => AgentDraftPendingIntentState::Available,
            "consumed" => AgentDraftPendingIntentState::Consumed,
            "expired" => AgentDraftPendingIntentState::Expired,
            value => {
                return Err(PersistenceError::Internal(format!(
                    "invalid agent draft pending intent state {value}"
                )));
            }
        };
        let consumption = row
            .consumption
            .map(serde_json::from_value::<PendingIntentConsumptionWire>)
            .transpose()
            .map_err(|error| PersistenceError::Internal(error.to_string()))?
            .map(AgentDraftPendingIntentConsumption::try_from)
            .transpose()?;
        Ok(Self {
            controller_account_id: serde_json::from_value(row.controller_account_id)
                .map_err(|error| PersistenceError::Internal(error.to_string()))?,
            agent_id: arkret_wire::DidCoreId::new(row.agent_id)
                .map_err(|error| PersistenceError::Internal(error.to_string()))?,
            draft_id: row.draft_id,
            proposed_action: row.proposed_action,
            target: row.target,
            content_digest: arkret_wire::Hash::new(row.content_digest)
                .map_err(|error| PersistenceError::Internal(error.to_string()))?,
            content_handoff: row.content_handoff.ok_or_else(|| {
                PersistenceError::Internal(
                    "agent draft handoff was cleared before a retention policy allowed it"
                        .to_owned(),
                )
            })?,
            canonical_event_digest: arkret_wire::Hash::new(row.canonical_event_digest)
                .map_err(|error| PersistenceError::Internal(error.to_string()))?,
            accepted_event_id: arkret_wire::EventId::new(row.accepted_event_id)
                .map_err(|error| PersistenceError::Internal(error.to_string()))?,
            expires_at: row.expires_at,
            created_at: row.created_at,
            state,
            consumption,
            expired_at: row.expired_at,
        })
    }
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct PendingIntentConsumptionWire {
    account_data_set_event_id: String,
    account_data_key: String,
    accepted_revision: u64,
    consumed_at: chrono::DateTime<chrono::Utc>,
}

impl TryFrom<PendingIntentConsumptionWire> for AgentDraftPendingIntentConsumption {
    type Error = PersistenceError;

    fn try_from(value: PendingIntentConsumptionWire) -> Result<Self, Self::Error> {
        Ok(Self {
            account_data_set_event_id: arkret_wire::EventId::new(value.account_data_set_event_id)
                .map_err(|error| {
                PersistenceError::Internal(error.to_string())
            })?,
            account_data_key: value.account_data_key,
            accepted_revision: value.accepted_revision,
            consumed_at: value.consumed_at,
        })
    }
}

const SELECT_COLUMNS: &str = "controller_account_id, agent_id, draft_id, proposed_action, target, \
    content_digest, content_handoff, canonical_event_digest, accepted_event_id, expires_at, \
    created_at, state, consumption, expired_at";

async fn expire_available(
    conn: &mut AsyncPgConnection,
    controller_key: &str,
    protocol_time: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<()> {
    sql_query(
        "UPDATE agent_draft_pending_intents SET state='expired', expired_at=$2 \
         WHERE controller_account_key=$1 AND state='available' AND expires_at <= $2",
    )
    .bind::<Text, _>(controller_key)
    .bind::<Timestamptz, _>(protocol_time)
    .execute(conn)
    .await
    .map_err(PersistenceError::database)?;
    Ok(())
}

pub(crate) async fn commit_agent_draft_pending_intent_in_connection(
    conn: &mut AsyncPgConnection,
    commit: &AgentDraftPendingIntentCommit,
) -> PersistenceResult<()> {
    let record = &commit.record;
    if record.state != AgentDraftPendingIntentState::Available
        || record.consumption.is_some()
        || record.expired_at.is_some()
        || record.expires_at <= record.created_at
    {
        return Err(PersistenceError::SchemaViolation(
            "new agent draft pending intent must be available and unexpired".to_owned(),
        ));
    }
    let controller_json = serde_json::to_value(&record.controller_account_id)
        .map_err(|error| PersistenceError::Internal(error.to_string()))?;
    let controller_key = record.controller_account_id.to_string();
    let inserted = sql_query(
        "INSERT INTO agent_draft_pending_intents \
         (controller_account_id, controller_account_key, agent_id, draft_id, proposed_action, \
          target, content_digest, content_handoff, canonical_event_digest, accepted_event_id, \
          expires_at, created_at, state) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,'available') \
         ON CONFLICT DO NOTHING",
    )
    .bind::<Jsonb, _>(controller_json)
    .bind::<Text, _>(&controller_key)
    .bind::<Text, _>(record.agent_id.as_str())
    .bind::<Text, _>(&record.draft_id)
    .bind::<Text, _>(&record.proposed_action)
    .bind::<Jsonb, _>(&record.target)
    .bind::<Text, _>(record.content_digest.as_str())
    .bind::<Jsonb, _>(&record.content_handoff)
    .bind::<Text, _>(record.canonical_event_digest.as_str())
    .bind::<Text, _>(record.accepted_event_id.as_str())
    .bind::<Timestamptz, _>(record.expires_at)
    .bind::<Timestamptz, _>(record.created_at)
    .execute(&mut *conn)
    .await
    .map_err(PersistenceError::database)?;
    if inserted == 1 {
        return Ok(());
    }

    let existing = sql_query(format!(
        "SELECT {SELECT_COLUMNS} FROM agent_draft_pending_intents \
         WHERE controller_account_key=$1 AND agent_id=$2 AND draft_id=$3 FOR UPDATE"
    ))
    .bind::<Text, _>(&controller_key)
    .bind::<Text, _>(record.agent_id.as_str())
    .bind::<Text, _>(&record.draft_id)
    .get_result::<PendingIntentRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?;
    if existing.is_some_and(|existing| {
        existing.accepted_event_id == record.accepted_event_id.as_str()
            && existing.canonical_event_digest == record.canonical_event_digest.as_str()
    }) {
        return Ok(());
    }
    Err(PersistenceError::Conflict(
        "duplicate_conflict: agent draft pending-intent key is already occupied".to_owned(),
    ))
}

#[async_trait::async_trait]
impl AgentDraftPendingIntentStore for PgAgentDraftPendingIntentStore {
    async fn get_by_source_event(
        &self,
        controller_account_id: &arkret_wire::AccountId,
        source_event_id: &arkret_wire::EventId,
        protocol_time: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<Option<AgentDraftPendingIntentRecord>> {
        let controller_key = controller_account_id.to_string();
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        expire_available(&mut conn, &controller_key, protocol_time).await?;
        sql_query(format!(
            "SELECT {SELECT_COLUMNS} FROM agent_draft_pending_intents \
             WHERE controller_account_key=$1 AND accepted_event_id=$2"
        ))
        .bind::<Text, _>(&controller_key)
        .bind::<Text, _>(source_event_id.as_str())
        .get_result::<PendingIntentRow>(&mut conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?
        .map(AgentDraftPendingIntentRecord::try_from)
        .transpose()
    }

    async fn list_for_controller(
        &self,
        controller_account_id: &arkret_wire::AccountId,
        protocol_time: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<Vec<AgentDraftPendingIntentRecord>> {
        let controller_key = controller_account_id.to_string();
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        expire_available(&mut conn, &controller_key, protocol_time).await?;
        sql_query(format!(
            "SELECT {SELECT_COLUMNS} FROM agent_draft_pending_intents \
             WHERE controller_account_key=$1 ORDER BY created_at, agent_id, draft_id"
        ))
        .bind::<Text, _>(&controller_key)
        .load::<PendingIntentRow>(&mut conn)
        .await
        .map_err(PersistenceError::database)?
        .into_iter()
        .map(AgentDraftPendingIntentRecord::try_from)
        .collect()
    }
}

#[cfg(test)]
mod tests {
    use diesel::sql_types::BigInt;
    use diesel_async::RunQueryDsl;

    use super::*;

    fn hash(byte: char) -> arkret_wire::Hash {
        arkret_wire::Hash::new(format!("sha256:{}", byte.to_string().repeat(64))).unwrap()
    }

    fn event_id(byte: char) -> arkret_wire::EventId {
        arkret_wire::EventId::from_event_digest(&hash(byte)).unwrap()
    }

    fn account(name: &str) -> arkret_wire::AccountId {
        arkret_wire::AccountId::new(
            arkret_wire::DidCoreId::new(format!("ak:did_core:web:{name}.example")).unwrap(),
            arkret_wire::DidCoreId::new("ak:did_core:web:station.example").unwrap(),
        )
    }

    fn pending(now: chrono::DateTime<chrono::Utc>) -> AgentDraftPendingIntentCommit {
        AgentDraftPendingIntentCommit {
            record: AgentDraftPendingIntentRecord {
                controller_account_id: account("controller"),
                agent_id: arkret_wire::DidCoreId::new("ak:did_core:web:agent.example").unwrap(),
                draft_id: "draft-1".to_owned(),
                proposed_action: "compose".to_owned(),
                target: serde_json::json!({"kind":"account_data","account_data_key":"opaque"}),
                content_digest: hash('1'),
                content_handoff: serde_json::json!({
                    "scheme":"ak.hpke_x25519_aead_chacha20poly1305.v1",
                    "recipients":[{
                        "recipient_device_id":"ak:device:01964137-0000-7000-8000-000000000001",
                        "recipient_hpke_key_digest":hash('2'),
                        "enc":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                        "ciphertext":"AAAAAAAAAAAAAAAAAAAAAA",
                        "ciphertext_digest":hash('3')
                    }]
                }),
                canonical_event_digest: hash('4'),
                accepted_event_id: event_id('4'),
                expires_at: now + chrono::TimeDelta::minutes(5),
                created_at: now,
                state: AgentDraftPendingIntentState::Available,
                consumption: None,
                expired_at: None,
            },
        }
    }

    #[derive(diesel::QueryableByName)]
    struct CountRow {
        #[diesel(sql_type = BigInt)]
        count: i64,
    }

    #[tokio::test]
    async fn create_exact_replay_conflict_expiry_and_domain_isolation() {
        let database = crate::test_database::TestDatabase::lease().await;
        let pool = database.pool();
        let store = PgAgentDraftPendingIntentStore { pool: pool.clone() };
        let now = "2026-09-20T00:00:00Z"
            .parse::<chrono::DateTime<chrono::Utc>>()
            .unwrap();
        let commit = pending(now);
        let mut conn = crate::pg_conn(&pool).await.unwrap();

        commit_agent_draft_pending_intent_in_connection(&mut conn, &commit)
            .await
            .unwrap();
        commit_agent_draft_pending_intent_in_connection(&mut conn, &commit)
            .await
            .expect("byte-identical replay returns the stored outcome");

        let rows = store
            .list_for_controller(&commit.record.controller_account_id, now)
            .await
            .unwrap();
        assert_eq!(rows, vec![commit.record.clone()]);
        assert!(
            store
                .list_for_controller(&account("foreign"), now)
                .await
                .unwrap()
                .is_empty(),
            "a different AccountId cannot read the holder handoff"
        );

        let mut conflicting = commit.clone();
        conflicting.record.canonical_event_digest = hash('5');
        assert!(matches!(
            commit_agent_draft_pending_intent_in_connection(&mut conn, &conflicting).await,
            Err(PersistenceError::Conflict(detail)) if detail.starts_with("duplicate_conflict")
        ));
        conflicting.record.accepted_event_id = event_id('5');
        assert!(matches!(
            commit_agent_draft_pending_intent_in_connection(&mut conn, &conflicting).await,
            Err(PersistenceError::Conflict(detail)) if detail.starts_with("duplicate_conflict")
        ));

        let account_rows = diesel::sql_query("SELECT count(*) AS count FROM account_datas")
            .get_result::<CountRow>(&mut conn)
            .await
            .unwrap()
            .count;
        let projection_rows = diesel::sql_query("SELECT count(*) AS count FROM projection_events")
            .get_result::<CountRow>(&mut conn)
            .await
            .unwrap()
            .count;
        assert_eq!((account_rows, projection_rows), (0, 0));

        let expired = store
            .get_by_source_event(
                &commit.record.controller_account_id,
                &commit.record.accepted_event_id,
                commit.record.expires_at,
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!(expired.state, AgentDraftPendingIntentState::Expired);
        assert_eq!(expired.expired_at, Some(commit.record.expires_at));
        assert!(expired.consumption.is_none());
        assert!(matches!(
            commit_agent_draft_pending_intent_in_connection(&mut conn, &conflicting).await,
            Err(PersistenceError::Conflict(detail)) if detail.starts_with("duplicate_conflict")
        ));
    }

    #[tokio::test]
    async fn transaction_rollback_leaves_no_pending_intent() {
        let database = crate::test_database::TestDatabase::lease().await;
        let pool = database.pool();
        let store = PgAgentDraftPendingIntentStore { pool: pool.clone() };
        let now = "2026-09-20T00:00:00Z"
            .parse::<chrono::DateTime<chrono::Utc>>()
            .unwrap();
        let commit = pending(now);
        let mut conn = crate::pg_conn(&pool).await.unwrap();
        diesel::sql_query("BEGIN").execute(&mut conn).await.unwrap();
        commit_agent_draft_pending_intent_in_connection(&mut conn, &commit)
            .await
            .unwrap();
        diesel::sql_query("ROLLBACK")
            .execute(&mut conn)
            .await
            .unwrap();
        assert!(
            store
                .list_for_controller(&account("controller"), now)
                .await
                .unwrap()
                .is_empty()
        );
    }
}
