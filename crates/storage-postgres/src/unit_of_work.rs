use async_trait::async_trait;
use diesel::sql_query;
use diesel::sql_types::{BigInt, Binary, Integer, Jsonb, Nullable, Text, Timestamptz, Uuid};
use diesel_async::{AsyncConnection, RunQueryDsl};
use soland_storage::{
    CanonicalEventRecord, EventBatchCommitRequest, EventCommitOutcome, EventCommitRequest,
    EventCommitUnitOfWork, PersistenceError, PersistenceResult, ids, validate_actor_scope_commit,
};

use crate::events::CanonicalEventRow;
use crate::{PgPool, PgTransactionError, pg_conn};

#[derive(Clone)]
pub struct PgEventCommitUnitOfWork {
    pool: PgPool,
}

impl PgEventCommitUnitOfWork {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl EventCommitUnitOfWork for PgEventCommitUnitOfWork {
    async fn commit_event(
        &self,
        request: EventCommitRequest,
    ) -> PersistenceResult<EventCommitOutcome> {
        self.commit_event_batch(EventBatchCommitRequest {
            events: vec![request],
            applet_ghosts: None,
        })
        .await
    }

    async fn commit_event_batch(
        &self,
        request: EventBatchCommitRequest,
    ) -> PersistenceResult<EventCommitOutcome> {
        if request.events.is_empty() {
            return Err(PersistenceError::Conflict(
                "schema_violation: empty event batch".to_owned(),
            ));
        }
        let mut conn = pg_conn(&self.pool).await?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            let mut projections_inserted = 0;
            let mut outbox_inserted = 0;
            for request in request.events {
            let event_id = ids::typed_uuid_part_or_schema_violation(&request.event.event_id)?;
            let realm_id = request
                .event
                .realm_id
                .as_deref()
                .map(ids::typed_uuid_part_or_schema_violation)
                .transpose()?;
            let realm_id_value = request.event.realm_id.as_deref().ok_or_else(|| {
                PersistenceError::Conflict("schema_violation: missing realm_id".to_owned())
            })?;
            // PostgreSQL `text` rejects embedded NUL bytes. Length-prefix the
            // Realm component so the lock transcript remains unambiguous
            // without relying on a forbidden separator.
            let scope_lock = format!(
                "realm_actor:{}:{}{}",
                realm_id_value.len(),
                realm_id_value,
                request.event.actor_id
            );
            sql_query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
                .bind::<Text, _>(&scope_lock)
                .execute(conn)
                .await
                .map_err(PersistenceError::database)?;
            let scoped = sql_query(
                "SELECT id, actor_id, actor_seq, realm_id, kind, schema_id, canonical_digest, canonical_bytes, envelope, received_at \
                 FROM canonical_events WHERE realm_id = $1 AND actor_id = $2 ORDER BY actor_seq ASC, id ASC",
            )
            .bind::<Uuid, _>(realm_id.expect("realm_id checked above"))
            .bind::<Text, _>(&request.event.actor_id)
            .load::<CanonicalEventRow>(conn)
            .await
            .map_err(PersistenceError::database)?
            .into_iter()
            .map(CanonicalEventRecord::from)
            .collect::<Vec<_>>();
            validate_actor_scope_commit(scoped.iter(), &request.event)?;
            sql_query(
                "INSERT INTO canonical_events \
                 (id, actor_id, actor_seq, realm_id, kind, schema_id, canonical_digest, canonical_bytes, envelope, received_at) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
            )
            .bind::<Uuid, _>(event_id)
            .bind::<Text, _>(&request.event.actor_id)
            .bind::<BigInt, _>(request.event.actor_seq as i64)
            .bind::<Nullable<Uuid>, _>(realm_id)
            .bind::<Text, _>(&request.event.kind)
            .bind::<Text, _>(&request.event.schema_id)
            .bind::<Text, _>(&request.event.canonical_digest)
            .bind::<Binary, _>(&request.event.canonical_bytes)
            .bind::<Jsonb, _>(&request.event.envelope)
            .bind::<Timestamptz, _>(request.event.received_at)
            .execute(conn)
            .await
            .map_err(PersistenceError::database)?;

            for projection in request.projections {
                let event_id = ids::typed_uuid_part_or_schema_violation(&projection.event_id)?;
                let realm_id = ids::typed_uuid_part_or_schema_violation(&projection.realm_id)?;
                let operation_id = projection
                    .operation_id
                    .as_deref()
                    .map(ids::typed_uuid_part_or_schema_violation)
                    .transpose()?;
                projections_inserted += sql_query(
                    "INSERT INTO projection_events \
                     (event_id, realm_id, event_kind, operation_kind, operation_id, sender_id, payload, created_at, received_at) \
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) \
                     ON CONFLICT (event_id) DO NOTHING",
                )
                .bind::<Uuid, _>(event_id)
                .bind::<Uuid, _>(realm_id)
                .bind::<Text, _>(&projection.event_kind)
                .bind::<Text, _>(&projection.operation_kind)
                .bind::<Nullable<Uuid>, _>(operation_id)
                .bind::<Nullable<Text>, _>(&projection.sender)
                .bind::<Jsonb, _>(&projection.payload)
                .bind::<Timestamptz, _>(projection.created_at)
                .bind::<Timestamptz, _>(projection.received_at)
                .execute(conn)
                .await
                .map_err(PersistenceError::database)?;
            }

            if let Some(record) = request.idempotency {
                let inserted = sql_query(
                    "INSERT INTO idempotency_keys \
                     (principal_id, idempotency_key, service_id, request_hash, response_status, \
                      response_body, created_at, expires_at) \
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8) \
                     ON CONFLICT (principal_id, idempotency_key) DO NOTHING",
                )
                .bind::<Text, _>(&record.principal_id)
                .bind::<Text, _>(&record.idempotency_key)
                .bind::<Text, _>(&record.service_id)
                .bind::<Text, _>(&record.request_hash)
                .bind::<Integer, _>(record.response_status)
                .bind::<Jsonb, _>(&record.response_body)
                .bind::<Timestamptz, _>(record.created_at)
                .bind::<Timestamptz, _>(record.expires_at)
                .execute(conn)
                .await
                .map_err(PersistenceError::database)?;
                if inserted != 1 {
                    return Err(
                        PersistenceError::Conflict("duplicate_conflict".to_owned()).into(),
                    );
                }
            }

            for record in request.outbox {
                outbox_inserted += sql_query(
                    "INSERT INTO federation_outbox \
                     (id, peer_id, peer_url, endpoint, idempotency_key, payload_json, attempts, \
                      next_attempt_at, last_status, last_response_excerpt, created_at, delivered_at) \
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12) \
                     ON CONFLICT (peer_id, idempotency_key) DO NOTHING",
                )
                .bind::<Text, _>(&record.id)
                .bind::<Text, _>(&record.peer_did)
                .bind::<Text, _>(&record.peer_url)
                .bind::<Text, _>(&record.endpoint)
                .bind::<Text, _>(&record.idempotency_key)
                .bind::<Text, _>(&record.payload_json)
                .bind::<Integer, _>(record.attempts)
                .bind::<BigInt, _>(record.next_attempt_at)
                .bind::<Nullable<Integer>, _>(record.last_status)
                .bind::<Nullable<Text>, _>(record.last_response_excerpt.as_deref())
                .bind::<BigInt, _>(record.created_at)
                .bind::<Nullable<BigInt>, _>(record.delivered_at)
                .execute(conn)
                .await
                .map_err(PersistenceError::database)?;
            }
            }

            if let Some(mutation) = request.applet_ghosts {
                let updated = sql_query(
                    "UPDATE applet_registrations \
                     SET ghosts = COALESCE(ghosts, '[]'::jsonb) || jsonb_build_array($2::jsonb), \
                         updated_at = NOW() \
                     WHERE id = $1 AND revoked_at IS NULL \
                     AND status IN ('installed', 'partially_installed') \
                     AND NOT EXISTS ( \
                         SELECT 1 FROM jsonb_array_elements(COALESCE(ghosts, '[]'::jsonb)) existing \
                         WHERE existing->>'external_id' = ($2::jsonb)->>'external_id' \
                            OR existing->>'ghost_actor_id' = ($2::jsonb)->>'ghost_actor_id' \
                     )",
                )
                .bind::<Text, _>(&mutation.applet_id)
                .bind::<Jsonb, _>(&mutation.ghost)
                .execute(conn)
                .await
                .map_err(PersistenceError::database)?;
                if updated != 1 {
                    return Err(PersistenceError::Conflict("applet_revoked".to_owned()).into());
                }
            }

            Ok(EventCommitOutcome {
                event_inserted: true,
                projections_inserted,
                outbox_inserted,
            })
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }
}
