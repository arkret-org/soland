use arkret_models_identity::PrincipalResolutionProjection;
use arkret_wire::{DidCoreId, Event, Hash, PrincipalAuthorityInstance, RealmId};
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
    authority_instance_digest: String,
    #[diesel(sql_type = Text)]
    principal_id: String,
    #[diesel(sql_type = Text)]
    principal_server_id: String,
    #[diesel(sql_type = Text)]
    pcr_realm_id: String,
    #[diesel(sql_type = Text)]
    principal_genesis_receipt_digest: String,
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
        let stored_authority_digest = Hash::new(row.authority_instance_digest)
            .map_err(|error| PersistenceError::Internal(error.to_string()))?;
        let authority_instance = PrincipalAuthorityInstance::new(
            DidCoreId::new(row.principal_id)
                .map_err(|error| PersistenceError::Internal(error.to_string()))?,
            DidCoreId::new(row.principal_server_id)
                .map_err(|error| PersistenceError::Internal(error.to_string()))?,
            RealmId::new(row.pcr_realm_id)
                .map_err(|error| PersistenceError::Internal(error.to_string()))?,
            Hash::new(row.principal_genesis_receipt_digest)
                .map_err(|error| PersistenceError::Internal(error.to_string()))?,
        )
        .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
        if authority_instance.authority_instance_digest != stored_authority_digest {
            return Err(PersistenceError::SchemaViolation(
                "stored principal authority instance digest does not match its four-field preimage"
                    .to_owned(),
            ));
        }
        let record = Self {
            authority_instance,
            genesis_event: serde_json::from_value(row.genesis_event)
                .map_err(|error| PersistenceError::Internal(error.to_string()))?,
            current_event: serde_json::from_value(row.current_event)
                .map_err(|error| PersistenceError::Internal(error.to_string()))?,
            projection: serde_json::from_value::<PrincipalResolutionProjection>(row.projection)
                .map_err(|error| PersistenceError::Internal(error.to_string()))?,
        };
        validate_principal_resolution_record(&record)?;
        Ok(record)
    }
}

impl PgPrincipalResolutionStore {
    async fn load_by_authority_instance_digest(
        &self,
        authority_instance_digest: &Hash,
    ) -> PersistenceResult<Option<PrincipalResolutionRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(
            "SELECT p.authority_instance_digest, p.principal_id, p.principal_server_id, \
                    p.pcr_realm_id, p.principal_genesis_receipt_digest, \
                    genesis.event_json AS genesis_event, current.event_json AS current_event, \
                    p.projection \
             FROM principal_resolutions p \
             JOIN principal_resolution_events genesis \
               ON genesis.authority_instance_digest = p.authority_instance_digest \
              AND genesis.event_id = p.genesis_event_id \
             JOIN principal_resolution_events current \
               ON current.authority_instance_digest = p.authority_instance_digest \
              AND current.event_id = p.current_event_id \
             WHERE p.authority_instance_digest = $1",
        )
        .bind::<Text, _>(authority_instance_digest.as_str())
        .get_result::<CurrentRow>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?
        .map(PrincipalResolutionRecord::try_from)
        .transpose()
    }

    async fn load_for_realm(
        &self,
        pcr_realm_id: &RealmId,
    ) -> PersistenceResult<Option<PrincipalResolutionRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(
            "SELECT p.authority_instance_digest, p.principal_id, p.principal_server_id, \
                    p.pcr_realm_id, p.principal_genesis_receipt_digest, \
                    genesis.event_json AS genesis_event, current.event_json AS current_event, \
                    p.projection \
             FROM principal_resolutions p \
             JOIN principal_resolution_events genesis \
               ON genesis.authority_instance_digest = p.authority_instance_digest \
              AND genesis.event_id = p.genesis_event_id \
             JOIN principal_resolution_events current \
               ON current.authority_instance_digest = p.authority_instance_digest \
              AND current.event_id = p.current_event_id \
             WHERE p.pcr_realm_id = $1",
        )
        .bind::<Text, _>(pcr_realm_id.as_str())
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
    async fn by_authority_instance_digest(
        &self,
        authority_instance_digest: &Hash,
    ) -> PersistenceResult<Option<PrincipalResolutionRecord>> {
        self.load_by_authority_instance_digest(authority_instance_digest)
            .await
    }

    async fn for_realm(
        &self,
        pcr_realm_id: &RealmId,
    ) -> PersistenceResult<Option<PrincipalResolutionRecord>> {
        self.load_for_realm(pcr_realm_id).await
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
                     (authority_instance_digest, event_id, previous_event_id, method_history_head, event_json, created_at) \
                   SELECT authority_instance_digest, $5, $4, $8, $9, $7 \
                     FROM principal_resolutions \
                    WHERE authority_instance_digest = $1 \
                      AND pcr_realm_id = $2 \
                      AND genesis_event_id = $3 \
                      AND current_event_id = $4 \
                   ON CONFLICT DO NOTHING \
                   RETURNING authority_instance_digest \
                 ), updated AS ( \
                   UPDATE principal_resolutions current \
                      SET current_event_id = $5, projection = $6, updated_at = $7 \
                     FROM inserted_event \
                    WHERE current.authority_instance_digest = inserted_event.authority_instance_digest \
                      AND current.current_event_id = $4 \
                    RETURNING current.authority_instance_digest \
                 ) \
                 SELECT EXISTS(SELECT 1 FROM updated) AS applied",
            )
            .bind::<Text, _>(next.authority_instance.authority_instance_digest.as_str())
            .bind::<Text, _>(next.authority_instance.pcr_realm_id.as_str())
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
                     (authority_instance_digest, principal_id, principal_server_id, pcr_realm_id, \
                      principal_genesis_receipt_digest, genesis_event_id, current_event_id, projection, updated_at) \
                   VALUES ($1, $2, $3, $4, $5, $6, $6, $7, $8) \
                   ON CONFLICT DO NOTHING \
                   RETURNING authority_instance_digest \
                 ), inserted_event AS ( \
                   INSERT INTO principal_resolution_events \
                     (authority_instance_digest, event_id, previous_event_id, method_history_head, event_json, created_at) \
                   SELECT authority_instance_digest, $6, NULL, $9, $10, $8 FROM inserted \
                 ) \
                 SELECT EXISTS(SELECT 1 FROM inserted) AS applied",
            )
            .bind::<Text, _>(next.authority_instance.authority_instance_digest.as_str())
            .bind::<Text, _>(next.authority_instance.principal_id.as_str())
            .bind::<Text, _>(next.authority_instance.principal_server_id.as_str())
            .bind::<Text, _>(next.authority_instance.pcr_realm_id.as_str())
            .bind::<Text, _>(next.authority_instance.principal_genesis_receipt_digest.as_str())
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
                self.load_by_authority_instance_digest(
                    &next.authority_instance.authority_instance_digest,
                )
                .await?,
            ))
        }
    }

    async fn history_newest_first(
        &self,
        authority_instance_digest: &Hash,
        after_event_ref: Option<&str>,
        limit: usize,
    ) -> PersistenceResult<Vec<Event>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        if let Some(after) = after_event_ref {
            let exists = sql_query(
                "SELECT EXISTS(SELECT 1 FROM principal_resolution_events \
                  WHERE authority_instance_digest = $1 AND event_id = $2) AS applied",
            )
            .bind::<Text, _>(authority_instance_digest.as_str())
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
                   ON current.authority_instance_digest = event.authority_instance_digest \
                WHERE event.authority_instance_digest = $1 \
                  AND event.event_id = COALESCE($2, current.current_event_id) \
               UNION ALL \
               SELECT predecessor.event_json, predecessor.previous_event_id, chain.depth + 1 \
                 FROM chain \
                 JOIN principal_resolution_events predecessor \
                   ON predecessor.authority_instance_digest = $1 \
                  AND predecessor.event_id = chain.previous_event_id \
             ) \
             SELECT event_json FROM chain \
              WHERE $2 IS NULL OR depth > 0 \
              ORDER BY depth ASC \
              LIMIT $3",
        )
        .bind::<Text, _>(authority_instance_digest.as_str())
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
