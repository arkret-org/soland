use arkret_models_identity::PrincipalResolutionProjection;
use arkret_wire::{CoreId, Event, RealmId};
use diesel::sql_types::{BigInt, Jsonb, Nullable, Text, Timestamptz};
use diesel::{OptionalExtension, QueryableByName, sql_query};
use diesel_async::RunQueryDsl;
use soland_storage::{
    PersistenceError, PersistenceResult, PrincipalResolutionCasResult, PrincipalResolutionRecord,
    PrincipalResolutionStore, validate_principal_resolution_record,
};

use crate::{PgPool, async_trait, pg_conn};

pub struct PgPrincipalResolutionStore {
    pub pool: PgPool,
}

#[derive(QueryableByName)]
struct CurrentRow {
    #[diesel(sql_type = Text)]
    principal_id: String,
    #[diesel(sql_type = Text)]
    principal_control_realm_id: String,
    #[diesel(sql_type = Jsonb)]
    genesis_event: serde_json::Value,
    #[diesel(sql_type = Jsonb)]
    current_event: serde_json::Value,
    #[diesel(sql_type = Jsonb)]
    projection: serde_json::Value,
}

#[derive(QueryableByName)]
struct AppliedRow {
    #[diesel(sql_type = diesel::sql_types::Bool)]
    applied: bool,
}

#[derive(QueryableByName)]
struct EventRow {
    #[diesel(sql_type = Jsonb)]
    event_json: serde_json::Value,
}

impl TryFrom<CurrentRow> for PrincipalResolutionRecord {
    type Error = PersistenceError;

    fn try_from(row: CurrentRow) -> Result<Self, Self::Error> {
        Ok(Self {
            principal_id: CoreId::new(row.principal_id)
                .map_err(|error| PersistenceError::Internal(error.to_string()))?,
            principal_control_realm_id: RealmId::new(row.principal_control_realm_id)
                .map_err(|error| PersistenceError::Internal(error.to_string()))?,
            genesis_event: serde_json::from_value(row.genesis_event)
                .map_err(|error| PersistenceError::Internal(error.to_string()))?,
            current_event: serde_json::from_value(row.current_event)
                .map_err(|error| PersistenceError::Internal(error.to_string()))?,
            projection: serde_json::from_value::<PrincipalResolutionProjection>(row.projection)
                .map_err(|error| PersistenceError::Internal(error.to_string()))?,
        })
    }
}

impl PgPrincipalResolutionStore {
    async fn load_current(
        &self,
        principal_id: &CoreId,
    ) -> PersistenceResult<Option<PrincipalResolutionRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(
            "SELECT p.principal_id, p.principal_control_realm_id, \
                    genesis.event_json AS genesis_event, current.event_json AS current_event, \
                    p.projection \
             FROM principal_resolutions p \
             JOIN principal_resolution_events genesis \
               ON genesis.principal_id = p.principal_id \
              AND genesis.event_id = p.genesis_event_id \
             JOIN principal_resolution_events current \
               ON current.principal_id = p.principal_id \
              AND current.event_id = p.current_event_id \
             WHERE p.principal_id = $1",
        )
        .bind::<Text, _>(principal_id.as_str())
        .get_result::<CurrentRow>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?
        .map(PrincipalResolutionRecord::try_from)
        .transpose()
    }
}

#[async_trait]
impl PrincipalResolutionStore for PgPrincipalResolutionStore {
    async fn current(
        &self,
        principal_id: &CoreId,
    ) -> PersistenceResult<Option<PrincipalResolutionRecord>> {
        self.load_current(principal_id).await
    }

    async fn compare_and_set(
        &self,
        expected_current_event_ref: Option<&str>,
        next: PrincipalResolutionRecord,
    ) -> PersistenceResult<PrincipalResolutionCasResult> {
        validate_principal_resolution_record(&next)?;
        let projection = serde_json::to_value(&next.projection)
            .map_err(|error| PersistenceError::Internal(error.to_string()))?;
        let current_event = serde_json::to_value(&next.current_event)
            .map_err(|error| PersistenceError::Internal(error.to_string()))?;
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let applied = if let Some(expected) = expected_current_event_ref {
            if expected == next.current_event.event_id.as_str() {
                return Err(PersistenceError::SchemaViolation(
                    "principal resolution CAS cannot rewrite the current Event in place".to_owned(),
                ));
            }
            let row = sql_query(
                "WITH inserted_event AS ( \
                   INSERT INTO principal_resolution_events \
                     (principal_id, event_id, previous_event_id, method_history_head, event_json, created_at) \
                   SELECT principal_id, $5, $4, $8, $9, $7 \
                     FROM principal_resolutions \
                    WHERE principal_id = $1 \
                      AND principal_control_realm_id = $2 \
                      AND genesis_event_id = $3 \
                      AND current_event_id = $4 \
                   ON CONFLICT DO NOTHING \
                   RETURNING principal_id \
                 ), updated AS ( \
                   UPDATE principal_resolutions current \
                      SET current_event_id = $5, projection = $6, updated_at = $7 \
                     FROM inserted_event \
                    WHERE current.principal_id = inserted_event.principal_id \
                      AND current.current_event_id = $4 \
                    RETURNING current.principal_id \
                 ) \
                 SELECT EXISTS(SELECT 1 FROM updated) AS applied",
            )
            .bind::<Text, _>(next.principal_id.as_str())
            .bind::<Text, _>(next.principal_control_realm_id.as_str())
            .bind::<Text, _>(next.genesis_event.event_id.as_str())
            .bind::<Text, _>(expected)
            .bind::<Text, _>(next.current_event.event_id.as_str())
            .bind::<Jsonb, _>(&projection)
            .bind::<Timestamptz, _>(next.projection.updated_at)
            .bind::<Text, _>(&next.projection.method_history_head)
            .bind::<Jsonb, _>(&current_event)
            .get_result::<AppliedRow>(&mut *conn)
            .await
            .map_err(PersistenceError::database)?;
            row.applied
        } else {
            if next.current_event.event_id != next.genesis_event.event_id {
                return Err(PersistenceError::SchemaViolation(
                    "principal resolution creation must start at its genesis Event".to_owned(),
                ));
            }
            let genesis_event = serde_json::to_value(&next.genesis_event)
                .map_err(|error| PersistenceError::Internal(error.to_string()))?;
            let row = sql_query(
                "WITH inserted AS ( \
                   INSERT INTO principal_resolutions \
                     (principal_id, principal_control_realm_id, genesis_event_id, current_event_id, projection, updated_at) \
                   VALUES ($1, $2, $3, $3, $4, $5) \
                   ON CONFLICT DO NOTHING \
                   RETURNING principal_id \
                 ), inserted_event AS ( \
                   INSERT INTO principal_resolution_events \
                     (principal_id, event_id, previous_event_id, method_history_head, event_json, created_at) \
                   SELECT principal_id, $3, NULL, $6, $7, $5 FROM inserted \
                 ) \
                 SELECT EXISTS(SELECT 1 FROM inserted) AS applied",
            )
            .bind::<Text, _>(next.principal_id.as_str())
            .bind::<Text, _>(next.principal_control_realm_id.as_str())
            .bind::<Text, _>(next.genesis_event.event_id.as_str())
            .bind::<Jsonb, _>(&projection)
            .bind::<Timestamptz, _>(next.projection.updated_at)
            .bind::<Text, _>(&next.projection.method_history_head)
            .bind::<Jsonb, _>(&genesis_event)
            .get_result::<AppliedRow>(&mut *conn)
            .await
            .map_err(PersistenceError::database)?;
            row.applied
        };

        if applied {
            Ok(PrincipalResolutionCasResult::Applied(next))
        } else {
            Ok(PrincipalResolutionCasResult::Conflict(
                self.load_current(&next.principal_id).await?,
            ))
        }
    }

    async fn history_newest_first(
        &self,
        principal_id: &CoreId,
        after_event_ref: Option<&str>,
        limit: usize,
    ) -> PersistenceResult<Vec<Event>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        if let Some(after) = after_event_ref {
            let exists = sql_query(
                "SELECT EXISTS(SELECT 1 FROM principal_resolution_events \
                  WHERE principal_id = $1 AND event_id = $2) AS applied",
            )
            .bind::<Text, _>(principal_id.as_str())
            .bind::<Text, _>(after)
            .get_result::<AppliedRow>(&mut *conn)
            .await
            .map_err(PersistenceError::database)?
            .applied;
            if !exists {
                return Err(PersistenceError::NotFound(format!(
                    "principal resolution history cursor {after}"
                )));
            }
        }

        let rows = sql_query(
            "WITH RECURSIVE chain AS ( \
               SELECT event.event_json, event.previous_event_id, 0::bigint AS depth \
                 FROM principal_resolution_events event \
                 JOIN principal_resolutions current \
                   ON current.principal_id = event.principal_id \
                WHERE event.principal_id = $1 \
                  AND event.event_id = COALESCE($2, current.current_event_id) \
               UNION ALL \
               SELECT predecessor.event_json, predecessor.previous_event_id, chain.depth + 1 \
                 FROM chain \
                 JOIN principal_resolution_events predecessor \
                   ON predecessor.principal_id = $1 \
                  AND predecessor.event_id = chain.previous_event_id \
             ) \
             SELECT event_json FROM chain \
              WHERE $2 IS NULL OR depth > 0 \
              ORDER BY depth ASC \
              LIMIT $3",
        )
        .bind::<Text, _>(principal_id.as_str())
        .bind::<Nullable<Text>, _>(after_event_ref)
        .bind::<BigInt, _>(i64::try_from(limit).unwrap_or(i64::MAX))
        .load::<EventRow>(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
        rows.into_iter()
            .map(|row| {
                serde_json::from_value(row.event_json)
                    .map_err(|error| PersistenceError::Internal(error.to_string()))
            })
            .collect()
    }
}
