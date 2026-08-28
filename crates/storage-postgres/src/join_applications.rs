use std::collections::BTreeMap;

use arkret_models_collaboration::governance::join_policy::JoinApplicationAuditAction;
use arkret_wire::{DidCoreId, Hash};

use super::{
    AsyncConnection, JoinApplicationCommand, JoinApplicationCommandOutcome,
    JoinApplicationMutation, JoinApplicationRecord, JoinApplicationStore, Jsonb, OptionalExtension,
    PersistenceError, PersistenceResult, PgPool, PgTransactionError, QueryableByName, RunQueryDsl,
    Text, Timestamptz, async_trait, pg_conn, sql_query,
};

#[derive(QueryableByName)]
struct JoinApplicationRow {
    #[diesel(sql_type = Text)]
    realm_id: String,
    #[diesel(sql_type = Text)]
    application_ref: String,
    #[diesel(sql_type = Jsonb)]
    record: serde_json::Value,
}

impl TryFrom<JoinApplicationRow> for JoinApplicationRecord {
    type Error = PersistenceError;

    fn try_from(row: JoinApplicationRow) -> Result<Self, Self::Error> {
        let record: JoinApplicationRecord =
            serde_json::from_value(row.record).map_err(|error| {
                PersistenceError::Internal(format!("join application row: {error}"))
            })?;
        if record.receipt.realm_id.as_str() != row.realm_id
            || record.application_ref.as_str() != row.application_ref
        {
            return Err(PersistenceError::Internal(
                "join application row key does not match record".to_owned(),
            ));
        }
        Ok(record)
    }
}

#[derive(QueryableByName)]
struct JoinApplicationIdempotencyRow {
    #[diesel(sql_type = Text)]
    principal_id: DidCoreId,
    #[diesel(sql_type = Text)]
    idempotency_key: String,
    #[diesel(sql_type = Text)]
    request_hash: String,
    #[diesel(sql_type = Jsonb)]
    response_body: serde_json::Value,
    #[diesel(sql_type = Text)]
    realm_id: String,
    #[diesel(sql_type = Text)]
    application_ref: String,
    #[diesel(sql_type = Timestamptz)]
    expires_at: chrono::DateTime<chrono::Utc>,
}

pub struct PgJoinApplicationStore {
    pub pool: PgPool,
}

#[async_trait]
impl JoinApplicationStore for PgJoinApplicationStore {
    async fn execute(
        &self,
        command: JoinApplicationCommand,
    ) -> PersistenceResult<JoinApplicationCommandOutcome> {
        let mut conn = pg_conn(&self.pool).await?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            let lock_key = format!(
                "join-application-idempotency:{}:{}",
                command.principal_id, command.idempotency_key
            );
            sql_query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
                .bind::<Text, _>(&lock_key)
                .execute(conn)
                .await
                .map_err(PersistenceError::database)?;
            // The primary key intentionally scopes idempotency to the
            // principal and caller-supplied key. Once the retention window has
            // elapsed, remove that exact stale row while holding the same
            // advisory lock so a legitimate key reuse cannot collide with it.
            sql_query(
                "DELETE FROM join_application_idempotency \
                 WHERE principal_id = $1 AND idempotency_key = $2 AND expires_at <= NOW()",
            )
            .bind::<Text, _>(&command.principal_id)
            .bind::<Text, _>(&command.idempotency_key)
            .execute(conn)
            .await
            .map_err(PersistenceError::database)?;

            let existing = sql_query(
                "SELECT principal_id, idempotency_key, request_hash, response_body, realm_id, \
                 application_ref, expires_at FROM join_application_idempotency \
                 WHERE principal_id = $1 AND idempotency_key = $2 AND expires_at > NOW() \
                 FOR UPDATE",
            )
            .bind::<Text, _>(&command.principal_id)
            .bind::<Text, _>(&command.idempotency_key)
            .get_result::<JoinApplicationIdempotencyRow>(conn)
            .await
            .optional()
            .map_err(PersistenceError::database)?;
            if let Some(existing) = existing {
                debug_assert_eq!(existing.principal_id, command.principal_id);
                debug_assert_eq!(existing.idempotency_key, command.idempotency_key);
                let _ = existing.expires_at;
                if existing.request_hash != command.request_hash {
                    return Ok(JoinApplicationCommandOutcome::IdempotencyConflict);
                }
                let record = load_one(conn, &existing.realm_id, &existing.application_ref, false)
                    .await?
                    .ok_or_else(|| {
                        PersistenceError::Internal(
                            "join application idempotency row points to a missing record"
                                .to_owned(),
                        )
                    })?;
                return Ok(JoinApplicationCommandOutcome::Replay {
                    response_body: existing.response_body,
                    record,
                });
            }

            let realm_id = mutation_realm_id(&command.mutation);
            let receipt_ref =
                soland_storage::join_application_mutation_receipt_ref(&command.mutation);
            sql_query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
                .bind::<Text, _>(&format!("join-applications:{realm_id}"))
                .execute(conn)
                .await
                .map_err(PersistenceError::database)?;
            let rows = sql_query(
                "SELECT realm_id, application_ref, record FROM join_applications \
                 WHERE realm_id = $1 FOR UPDATE",
            )
            .bind::<Text, _>(&realm_id)
            .load::<JoinApplicationRow>(conn)
            .await
            .map_err(PersistenceError::database)?;
            let mut records = BTreeMap::new();
            for row in rows {
                let record = JoinApplicationRecord::try_from(row)?;
                records.insert(
                    (
                        record.receipt.realm_id.as_str().to_owned(),
                        record.application_ref.as_str().to_owned(),
                    ),
                    record,
                );
            }
            let record =
                soland_storage::apply_join_application_mutation(&mut records, command.mutation)?;
            let response_body =
                soland_storage::join_application_response_body(&record, &receipt_ref);
            // Submit-revision may also mark a request-changes predecessor as
            // superseded. Persist the complete locked Realm set so the
            // multi-record mutation stays atomic.
            for updated in records.values() {
                store_record(conn, updated).await?;
            }
            sql_query(
                "INSERT INTO join_application_idempotency \
                 (principal_id, idempotency_key, request_hash, response_body, realm_id, \
                  application_ref, expires_at) VALUES ($1, $2, $3, $4, $5, $6, $7)",
            )
            .bind::<Text, _>(&command.principal_id)
            .bind::<Text, _>(&command.idempotency_key)
            .bind::<Text, _>(&command.request_hash)
            .bind::<Jsonb, _>(&response_body)
            .bind::<Text, _>(record.receipt.realm_id.as_str())
            .bind::<Text, _>(record.application_ref.as_str())
            .bind::<Timestamptz, _>(command.idempotency_expires_at)
            .execute(conn)
            .await
            .map_err(PersistenceError::database)?;
            Ok(JoinApplicationCommandOutcome::Applied {
                response_body,
                record,
            })
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }

    async fn get(
        &self,
        realm_id: &str,
        application_ref: &str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<Option<JoinApplicationRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        let Some(mut record) = load_one(&mut conn, realm_id, application_ref, false).await? else {
            return Ok(None);
        };
        let prior = record.status.clone();
        record.refresh_expiry(now);
        if record.status != prior {
            store_record(&mut conn, &record).await?;
        }
        Ok(Some(record))
    }

    async fn list(
        &self,
        realm_id: &str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<Vec<JoinApplicationRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        let rows = sql_query(
            "SELECT realm_id, application_ref, record FROM join_applications \
             WHERE realm_id = $1 ORDER BY updated_at, application_ref",
        )
        .bind::<Text, _>(realm_id)
        .load::<JoinApplicationRow>(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
        let mut records = Vec::with_capacity(rows.len());
        for row in rows {
            let mut record = JoinApplicationRecord::try_from(row)?;
            let prior = record.status.clone();
            record.refresh_expiry(now);
            if record.status != prior {
                store_record(&mut conn, &record).await?;
            }
            records.push(record);
        }
        Ok(records)
    }

    async fn append_read_audit(
        &self,
        realm_id: &str,
        application_ref: &str,
        actor_id: &str,
        occurred_at: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool).await?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            let mut record = load_one(conn, realm_id, application_ref, true)
                .await?
                .ok_or_else(|| PersistenceError::NotFound("join application".to_owned()))?;
            record.append_audit(
                JoinApplicationAuditAction::Read,
                DidCoreId::new(actor_id.to_owned())
                    .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?,
                occurred_at,
                Hash::new(application_ref.to_owned())
                    .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?,
            );
            store_record(conn, &record).await?;
            Ok(())
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }

    async fn consume_review_authorisations(
        &self,
        realm_id: &str,
        review_receipt_digests: &[String],
        actor_id: &str,
        occurred_at: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<bool> {
        if review_receipt_digests.is_empty() {
            return Ok(false);
        }
        let mut conn = pg_conn(&self.pool).await?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            let rows = sql_query(
                "SELECT realm_id, application_ref, record FROM join_applications \
                 WHERE realm_id = $1 FOR UPDATE",
            )
            .bind::<Text, _>(realm_id)
            .load::<JoinApplicationRow>(conn)
            .await
            .map_err(PersistenceError::database)?;
            let Some(mut record) = rows
                .into_iter()
                .map(JoinApplicationRecord::try_from)
                .collect::<PersistenceResult<Vec<_>>>()?
                .into_iter()
                .find(|record| {
                    record
                        .required_accept_refs
                        .iter()
                        .map(arkret_wire::Hash::as_str)
                        .collect::<std::collections::BTreeSet<_>>()
                        == review_receipt_digests
                            .iter()
                            .map(String::as_str)
                            .collect::<std::collections::BTreeSet<_>>()
                        && record.required_accept_refs.len() == review_receipt_digests.len()
                })
            else {
                return Ok(false);
            };
            record.refresh_expiry(occurred_at);
            if record.invite_consumed
                && record.status
                    == arkret_models_collaboration::governance::join_policy::JoinApplicationStatus::Consumed
            {
                return Ok(true);
            }
            if record.status
                != arkret_models_collaboration::governance::join_policy::JoinApplicationStatus::Accepted
                || record.invite_consumed
            {
                return Ok(false);
            }
            record.invite_consumed = true;
            record.status =
                arkret_models_collaboration::governance::join_policy::JoinApplicationStatus::Consumed;
            let actor_id = DidCoreId::new(actor_id.to_owned())
                .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
            for digest in review_receipt_digests {
                record.append_audit(
                    JoinApplicationAuditAction::InviteConsumed,
                    actor_id.clone(),
                    occurred_at,
                    Hash::new(digest.clone())
                        .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?,
                );
            }
            store_record(conn, &record).await?;
            Ok(true)
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }
}

fn mutation_realm_id(mutation: &JoinApplicationMutation) -> String {
    match mutation {
        JoinApplicationMutation::Submit { record, .. } => {
            record.receipt.realm_id.as_str().to_owned()
        }
        JoinApplicationMutation::Review { realm_id, .. }
        | JoinApplicationMutation::Cancel { realm_id, .. } => realm_id.clone(),
    }
}

async fn load_one(
    conn: &mut diesel_async::AsyncPgConnection,
    realm_id: &str,
    application_ref: &str,
    for_update: bool,
) -> PersistenceResult<Option<JoinApplicationRecord>> {
    let suffix = if for_update { " FOR UPDATE" } else { "" };
    sql_query(format!(
        "SELECT realm_id, application_ref, record FROM join_applications \
         WHERE realm_id = $1 AND application_ref = $2{suffix}"
    ))
    .bind::<Text, _>(realm_id)
    .bind::<Text, _>(application_ref)
    .get_result::<JoinApplicationRow>(conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?
    .map(JoinApplicationRecord::try_from)
    .transpose()
}

async fn store_record(
    conn: &mut diesel_async::AsyncPgConnection,
    record: &JoinApplicationRecord,
) -> PersistenceResult<()> {
    let value = serde_json::to_value(record)
        .map_err(|error| PersistenceError::Internal(format!("join application record: {error}")))?;
    sql_query(
        "INSERT INTO join_applications (realm_id, application_ref, record, updated_at) \
         VALUES ($1, $2, $3, $4) \
         ON CONFLICT (realm_id, application_ref) DO UPDATE SET \
         record = EXCLUDED.record, updated_at = EXCLUDED.updated_at",
    )
    .bind::<Text, _>(record.receipt.realm_id.as_str())
    .bind::<Text, _>(record.application_ref.as_str())
    .bind::<Jsonb, _>(&value)
    .bind::<Timestamptz, _>(record.updated_at)
    .execute(conn)
    .await
    .map(|_| ())
    .map_err(PersistenceError::database)
}
