use async_trait::async_trait;
use diesel::sql_types::{
    BigInt, Binary, Integer, Jsonb, Nullable, SmallInt, Text, Timestamptz, Uuid,
};
use diesel::{OptionalExtension, sql_query};
use diesel_async::{AsyncConnection, RunQueryDsl};
use soland_storage::{
    CanonicalEventRecord, EventBatchCommitRequest, EventCommitOutcome, EventCommitRequest,
    EventCommitUnitOfWork, PersistenceError, PersistenceResult, ids, validate_actor_scope_commit,
};

use crate::events::{
    CanonicalEventRow, CanonicalInsertOutcome, insert_canonical_event, realm_actor_lock_key,
};
use crate::{PgPool, PgTransactionError, pg_conn};

#[derive(diesel::QueryableByName)]
struct EventPreflightRow {
    #[diesel(sql_type = Binary)]
    canonical_bytes: Vec<u8>,
    #[diesel(sql_type = Text)]
    state: String,
}

#[derive(Clone)]
pub struct PgEventCommitUnitOfWork {
    pool: PgPool,
}

enum CommitTransactionOutcome {
    Committed(EventCommitOutcome),
    Collision,
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
        let transaction_outcome = conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            // Inspect the whole batch before inserting any of its ordinary
            // rows. A collision in item N may commit quarantine evidence for
            // that identity, but must never commit items 0..N-1 as a prefix.
            let mut ordered = request.events.iter().collect::<Vec<_>>();
            ordered.sort_by(|left, right| left.event.event_id.cmp(&right.event.event_id));
            for item in &ordered {
                let identity = ids::validated_event_identity_parts(
                    &item.event.event_id,
                    &item.event.canonical_digest,
                    &item.event.canonical_bytes,
                )?;
                sql_query("SELECT pg_advisory_xact_lock(hashtextextended(encode($1, 'hex'), 0))")
                    .bind::<Binary, _>(identity.id.to_vec())
                    .execute(&mut *conn)
                    .await
                    .map_err(PersistenceError::database)?;
            }
            let mut incoming = std::collections::BTreeMap::<
                String,
                &CanonicalEventRecord,
            >::new();
            for item in ordered {
                let identity = ids::validated_event_identity_parts(
                    &item.event.event_id,
                    &item.event.canonical_digest,
                    &item.event.canonical_bytes,
                )?;
                let stored = sql_query(
                    "SELECT canonical_bytes, state FROM canonical_events WHERE id = $1",
                )
                .bind::<Binary, _>(identity.id.to_vec())
                .get_result::<EventPreflightRow>(&mut *conn)
                .await
                .optional()
                .map_err(PersistenceError::database)?;
                if let Some(stored) = stored {
                    if stored.canonical_bytes != item.event.canonical_bytes {
                        let outcome = insert_canonical_event(conn, &item.event).await?;
                        debug_assert_eq!(outcome, CanonicalInsertOutcome::Collision);
                        return Ok(CommitTransactionOutcome::Collision);
                    }
                    if stored.state == "quarantined" {
                        return Ok(CommitTransactionOutcome::Collision);
                    }
                    continue;
                }
                if let Some(previous) = incoming.get(&item.event.event_id) {
                    if previous.canonical_bytes != item.event.canonical_bytes {
                        let inserted = insert_canonical_event(conn, previous).await?;
                        debug_assert!(matches!(inserted, CanonicalInsertOutcome::Inserted(_)));
                        let collision = insert_canonical_event(conn, &item.event).await?;
                        debug_assert_eq!(collision, CanonicalInsertOutcome::Collision);
                        return Ok(CommitTransactionOutcome::Collision);
                    }
                } else {
                    incoming.insert(item.event.event_id.clone(), &item.event);
                }
            }
            let mut event_inserted = false;
            let mut projections_inserted = 0;
            let mut outbox_inserted = 0;
            for request in request.events {
            let identity = ids::validated_event_identity_parts(
                &request.event.event_id,
                &request.event.canonical_digest,
                &request.event.canonical_bytes,
            )?;
            sql_query("SELECT pg_advisory_xact_lock(hashtextextended(encode($1, 'hex'), 0))")
                .bind::<Binary, _>(identity.id.to_vec())
                .execute(conn)
                .await
                .map_err(PersistenceError::database)?;
            let identity_matches = sql_query(
                "SELECT id, digest_suite, digest, actor_id, actor_seq, realm_id, kind, schema_id, canonical_bytes, envelope, received_at \
                 FROM canonical_events WHERE id = $1",
            )
            .bind::<Binary, _>(identity.id.to_vec())
            .load::<CanonicalEventRow>(conn)
            .await
            .map_err(PersistenceError::database)?;
            if identity_matches.iter().any(|existing| {
                existing.digest_suite != i16::from(identity.digest_suite)
                    || existing.digest.as_slice() != identity.digest
            }) {
                return Err(PersistenceError::Conflict(
                    "event_id_digest_mismatch".to_owned(),
                )
                .into());
            }
            if !identity_matches.is_empty() {
                let outcome = insert_canonical_event(conn, &request.event).await?;
                if matches!(
                    outcome,
                    CanonicalInsertOutcome::Collision | CanonicalInsertOutcome::Quarantined
                ) {
                    return Ok(CommitTransactionOutcome::Collision);
                }
                continue;
            }
            let realm_id_value = request.event.realm_id.as_deref().ok_or_else(|| {
                PersistenceError::Conflict("schema_violation: missing realm_id".to_owned())
            })?;
            let realm_pk =
                crate::realm_identity::ensure_realm_pk(conn, realm_id_value).await?;
            let scope_lock = realm_actor_lock_key(realm_id_value, &request.event.actor_id);
            sql_query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
                .bind::<Text, _>(&scope_lock)
                .execute(conn)
                .await
                .map_err(PersistenceError::database)?;
            let scoped = sql_query(
                "SELECT id, digest_suite, digest, actor_id, actor_seq, realm_id, kind, schema_id, canonical_bytes, envelope, received_at \
                 FROM canonical_events WHERE state = 'accepted' AND realm_pk = $1 AND actor_id = $2 ORDER BY actor_seq ASC, id ASC",
            )
            .bind::<BigInt, _>(realm_pk)
            .bind::<Text, _>(&request.event.actor_id)
            .load::<CanonicalEventRow>(conn)
            .await
            .map_err(PersistenceError::database)?
            .into_iter()
            .map(CanonicalEventRecord::from)
            .collect::<Vec<_>>();
            validate_actor_scope_commit(scoped.iter(), &request.event)?;
            let event_pk = sql_query(
                "INSERT INTO canonical_events \
                 (id, digest_suite, digest, actor_id, actor_seq, realm_id, realm_pk, kind, schema_id, canonical_bytes, envelope, received_at) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12) RETURNING pk",
            )
            .bind::<Binary, _>(identity.id.to_vec())
            .bind::<SmallInt, _>(i16::from(identity.digest_suite))
            .bind::<Binary, _>(identity.digest.to_vec())
            .bind::<Text, _>(&request.event.actor_id)
            .bind::<BigInt, _>(request.event.actor_seq as i64)
            .bind::<Nullable<Text>, _>(request.event.realm_id.as_deref())
            .bind::<BigInt, _>(realm_pk)
            .bind::<Text, _>(&request.event.kind)
            .bind::<Text, _>(&request.event.schema_id)
            .bind::<Binary, _>(&request.event.canonical_bytes)
            .bind::<Jsonb, _>(&request.event.envelope)
            .bind::<Timestamptz, _>(request.event.received_at)
            .get_result::<EventPkRow>(conn)
            .await
            .map_err(PersistenceError::database)?
            .pk;
            event_inserted = true;

            let typed_event = serde_json::from_value::<arkret_wire::Event>(
                request.event.envelope.clone(),
            )
            .map_err(|error| {
                PersistenceError::Conflict(format!(
                    "schema_violation: accepted Event envelope is not canonical wire: {error}"
                ))
            })?;
            // Control/Data routing is defined by the typed Event plane. A
            // closed genesis anchor is a basis-free Control Move; a DataEvent
            // instead carries `seal_ref` plus `auth_context`.
            let is_control_move = typed_event.kind.is_reducer_input()
                && typed_event.seal_ref.is_none()
                && typed_event.auth_context.is_none();
            if is_control_move {
                let event_digest = typed_event.event_digest().map_err(|error| {
                    PersistenceError::Conflict(format!(
                        "schema_violation: accepted Control Move digest failed: {error}"
                    ))
                })?;
                if event_digest != request.event.canonical_digest {
                    return Err(PersistenceError::Conflict(
                        "schema_violation: canonical digest differs from Control Move digest"
                            .to_owned(),
                    )
                    .into());
                }
                let control_proposal_ack = request
                    .control_proposal_ack
                    .as_ref()
                    .map(|ack| {
                        if ack.proposal_digest.as_str() != event_digest
                            || ack.realm_id != typed_event.realm_id
                        {
                            return Err(PersistenceError::Conflict(
                                "schema_violation: Control Proposal Ack does not bind Control Move"
                                    .to_owned(),
                            ));
                        }
                        serde_json::to_value(ack).map_err(|error| {
                            PersistenceError::Internal(format!(
                                "Control Proposal Ack encoding failed: {error}"
                            ))
                        })
                    })
                    .transpose()?
                    .ok_or_else(|| {
                        PersistenceError::Conflict(
                            "schema_violation: accepted Control Move is missing Control Proposal Ack"
                                .to_owned(),
                        )
                    })?;
                sql_query(
                    "INSERT INTO state_control_events \
                     (event_digest, realm_id, event_json, control_proposal_ack) \
                     VALUES ($1, $2, $3, $4) \
                     ON CONFLICT (event_digest) DO UPDATE SET \
                       control_proposal_ack = COALESCE( \
                         state_control_events.control_proposal_ack, EXCLUDED.control_proposal_ack \
                       ) \
                     WHERE state_control_events.realm_id = EXCLUDED.realm_id \
                       AND state_control_events.event_json = EXCLUDED.event_json \
                       AND (state_control_events.control_proposal_ack IS NULL \
                         OR state_control_events.control_proposal_ack = EXCLUDED.control_proposal_ack)",
                )
                .bind::<Text, _>(&event_digest)
                .bind::<Text, _>(typed_event.realm_id.as_str())
                .bind::<Jsonb, _>(&request.event.envelope)
                .bind::<Jsonb, _>(&control_proposal_ack)
                .execute(conn)
                .await
                .map_err(PersistenceError::database)
                .and_then(|affected| {
                    if affected == 0 {
                        Err(PersistenceError::Conflict(
                            "duplicate_conflict: pending Control Move has different canonical bytes or Control Proposal Ack"
                                .to_owned(),
                        ))
                    } else {
                        Ok(())
                    }
                })?;
            } else if request.control_proposal_ack.is_some() {
                return Err(PersistenceError::Conflict(
                    "schema_violation: non-Control Event cannot carry a Control Proposal Ack"
                        .to_owned(),
                )
                .into());
            }

            for projection in request.projections {
                // The projection no longer carries its own copy of the Event
                // identity -- it is reached through `event_pk`. Admitting a
                // projection that names a different Event than the one this
                // unit committed would silently attach it to the wrong row, so
                // the mismatch is rejected here instead of being dropped.
                if projection.event_id != request.event.event_id {
                    return Err(PersistenceError::Conflict(
                        "schema_violation: projection Event id does not match canonical Event"
                            .to_owned(),
                    )
                    .into());
                }
                let operation_id = projection
                    .operation_id
                    .as_deref()
                    .map(ids::typed_uuid_part_or_schema_violation)
                    .transpose()?;
                let projection_realm_pk =
                    crate::realm_identity::ensure_realm_pk(conn, &projection.realm_id).await?;
                if projection_realm_pk != realm_pk {
                    return Err(PersistenceError::Conflict(
                        "schema_violation: projection Realm does not match canonical Event Realm"
                            .to_owned(),
                    )
                    .into());
                }
                projections_inserted += sql_query(
                    "INSERT INTO projection_events \
                     (event_pk, realm_pk, realm_id, event_kind, operation_kind, operation_id, sender_id, payload, created_at, received_at) \
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) \
                     ON CONFLICT (event_pk) DO NOTHING",
                )
                .bind::<BigInt, _>(event_pk)
                .bind::<BigInt, _>(projection_realm_pk)
                .bind::<Text, _>(&projection.realm_id)
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
                     (id, peer_id, peer_url, endpoint, idempotency_key, payload_json, state, \
                      attempts, semantic_attempts, next_attempt_at, last_http_status, \
                      last_error_code, last_response_excerpt, lease_owner, lease_token, \
                      lease_expires_at, policy_version, supersedes_outbox_id, created_at, \
                      completed_at, event_pk) \
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, \
                      $16, $17, $18, $19, $20, $21) \
                     ON CONFLICT (peer_id, idempotency_key) DO NOTHING",
                )
                .bind::<Text, _>(&record.id)
                .bind::<Text, _>(&record.peer_did)
                .bind::<Text, _>(&record.peer_url)
                .bind::<Text, _>(&record.endpoint)
                .bind::<Text, _>(&record.idempotency_key)
                .bind::<Text, _>(&record.payload_json)
                .bind::<Text, _>(record.state.as_str())
                .bind::<Integer, _>(record.attempts)
                .bind::<Integer, _>(record.semantic_attempts)
                .bind::<BigInt, _>(record.next_attempt_at)
                .bind::<Nullable<Integer>, _>(record.last_http_status)
                .bind::<Nullable<Text>, _>(record.last_error_code.as_deref())
                .bind::<Nullable<Text>, _>(record.last_response_excerpt.as_deref())
                .bind::<Nullable<Text>, _>(record.lease_owner.as_deref())
                .bind::<Nullable<Text>, _>(record.lease_token.as_deref())
                .bind::<Nullable<BigInt>, _>(record.lease_expires_at)
                .bind::<Nullable<Text>, _>(record.policy_version.as_deref())
                .bind::<Nullable<Text>, _>(record.supersedes_outbox_id.as_deref())
                .bind::<BigInt, _>(record.created_at)
                .bind::<Nullable<BigInt>, _>(record.completed_at)
                .bind::<Nullable<BigInt>, _>(Some(event_pk))
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

            Ok(CommitTransactionOutcome::Committed(EventCommitOutcome {
                event_inserted,
                projections_inserted,
                outbox_inserted,
            }))
        })
        .await
        .map_err(PgTransactionError::into_persistence)?;
        match transaction_outcome {
            CommitTransactionOutcome::Committed(outcome) => Ok(outcome),
            CommitTransactionOutcome::Collision => Err(PersistenceError::Conflict(
                "event_hash_collision".to_owned(),
            )),
        }
    }
}

#[derive(diesel::QueryableByName)]
struct EventPkRow {
    #[diesel(sql_type = BigInt)]
    pk: i64,
}
