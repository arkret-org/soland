use arkret_wire::{
    Did, Hash, SecurityTransaction, SecurityTransactionBinding, SecurityTransactionKind,
    SecurityTransactionState, SecurityTransactionStep, TransactionId,
};

use super::{
    AsyncConnection, AsyncPgConnection, Binary, Jsonb, Nullable, OptionalExtension,
    PersistenceError, PersistenceResult, PgPool, PgTransactionError, QueryableByName, RunQueryDsl,
    SecurityTransactionRecord, SecurityTransactionStepAttemptRecord,
    SecurityTransactionStepOutcomeRecord, SecurityTransactionStore, SqlUuid, Text, Timestamptz,
    Uuid, Value, async_trait, ids, pg_conn, sql_query,
};

pub struct PgSecurityTransactionStore {
    pub pool: PgPool,
}

#[derive(QueryableByName)]
struct SecurityTransactionRow {
    #[diesel(sql_type = SqlUuid)]
    id: Uuid,
    #[diesel(sql_type = Text)]
    kind: String,
    #[diesel(sql_type = Text)]
    principal_id: String,
    #[diesel(sql_type = Text)]
    coordinator_service_id: String,
    #[diesel(sql_type = Timestamptz)]
    expires_at: chrono::DateTime<chrono::Utc>,
    #[diesel(sql_type = Timestamptz)]
    created_at: chrono::DateTime<chrono::Utc>,
    #[diesel(sql_type = Text)]
    request_digest: String,
    #[diesel(sql_type = Jsonb)]
    binding: Value,
    #[diesel(sql_type = Jsonb)]
    prepared_plan: Value,
    #[diesel(sql_type = Text)]
    prepared_plan_digest: String,
    #[diesel(sql_type = Text)]
    state: String,
    #[diesel(sql_type = Jsonb)]
    accepted_steps: Value,
    #[diesel(sql_type = Nullable<Text>)]
    next_required_step: Option<String>,
    #[diesel(sql_type = Nullable<Jsonb>)]
    terminal_result: Option<Value>,
    #[diesel(sql_type = Binary)]
    canonical_request: Vec<u8>,
}

#[derive(QueryableByName)]
struct SecurityTransactionStepOutcomeRow {
    #[diesel(sql_type = SqlUuid)]
    transaction_id: Uuid,
    #[diesel(sql_type = Text)]
    step: String,
    #[diesel(sql_type = Binary)]
    canonical_request: Vec<u8>,
    #[diesel(sql_type = Jsonb)]
    response: Value,
    #[diesel(sql_type = Nullable<Jsonb>)]
    participant_outcome: Option<Value>,
}

#[derive(QueryableByName)]
struct SecurityTransactionStepAttemptRow {
    #[diesel(sql_type = SqlUuid)]
    transaction_id: Uuid,
    #[diesel(sql_type = Text)]
    step: String,
    #[diesel(sql_type = Binary)]
    canonical_request: Vec<u8>,
}

impl TryFrom<SecurityTransactionStepAttemptRow> for SecurityTransactionStepAttemptRecord {
    type Error = PersistenceError;

    fn try_from(row: SecurityTransactionStepAttemptRow) -> Result<Self, Self::Error> {
        Ok(Self {
            transaction_id: ids::format_typed_uuid("transaction", &row.transaction_id),
            step: parse_stored("step attempt step", Value::String(row.step))?,
            canonical_request: row.canonical_request,
        })
    }
}

impl TryFrom<SecurityTransactionStepOutcomeRow> for SecurityTransactionStepOutcomeRecord {
    type Error = PersistenceError;

    fn try_from(row: SecurityTransactionStepOutcomeRow) -> Result<Self, Self::Error> {
        Ok(Self {
            transaction_id: ids::format_typed_uuid("transaction", &row.transaction_id),
            step: parse_stored("step outcome step", Value::String(row.step))?,
            canonical_request: row.canonical_request,
            response: row.response,
            participant_outcome: row.participant_outcome,
        })
    }
}

impl TryFrom<SecurityTransactionRow> for SecurityTransactionRecord {
    type Error = PersistenceError;

    fn try_from(row: SecurityTransactionRow) -> Result<Self, Self::Error> {
        let resource = SecurityTransaction {
            transaction_id: TransactionId::new(ids::format_typed_uuid("transaction", &row.id))
                .map_err(|error| PersistenceError::Internal(error.to_string()))?,
            kind: parse_stored("kind", Value::String(row.kind))?,
            principal_id: Did::new(row.principal_id)
                .map_err(|error| PersistenceError::Internal(error.to_string()))?,
            coordinator_service_id: Did::new(row.coordinator_service_id)
                .map_err(|error| PersistenceError::Internal(error.to_string()))?,
            expires_at: row.expires_at,
            created_at: row.created_at,
            request_digest: Hash::new(row.request_digest)
                .map_err(|error| PersistenceError::Internal(error.to_string()))?,
            binding: parse_stored("binding", row.binding)?,
            prepared_plan: parse_stored("prepared_plan", row.prepared_plan)?,
            prepared_plan_digest: Hash::new(row.prepared_plan_digest)
                .map_err(|error| PersistenceError::Internal(error.to_string()))?,
            state: parse_stored("state", Value::String(row.state))?,
            accepted_steps: parse_stored("accepted_steps", row.accepted_steps)?,
            next_required_step: row
                .next_required_step
                .map(|step| parse_stored("next_required_step", Value::String(step)))
                .transpose()?,
            terminal_result: row
                .terminal_result
                .map(|result| parse_stored("terminal_result", result))
                .transpose()?,
        };
        resource
            .validate_structural()
            .map_err(|error| PersistenceError::Internal(error.to_string()))?;
        Ok(Self {
            canonical_request: row.canonical_request,
            resource,
        })
    }
}

fn parse_stored<T: serde::de::DeserializeOwned>(name: &str, value: Value) -> PersistenceResult<T> {
    serde_json::from_value(value).map_err(|error| {
        PersistenceError::Internal(format!(
            "stored security transaction {name} is invalid: {error}"
        ))
    })
}

const COLUMNS: &str = "id, kind, principal_id, coordinator_service_id, expires_at, created_at, \
    request_digest, binding, prepared_plan, prepared_plan_digest, state, accepted_steps, \
    next_required_step, terminal_result, canonical_request";

async fn load_one(
    conn: &mut AsyncPgConnection,
    transaction_id: &str,
    for_update: bool,
) -> PersistenceResult<Option<SecurityTransactionRecord>> {
    let lock = if for_update { " FOR UPDATE" } else { "" };
    let transaction_uuid =
        ids::parse_typed_uuid(transaction_id, "transaction").ok_or_else(|| {
            PersistenceError::SchemaViolation(format!(
                "malformed transaction_id `{transaction_id}`"
            ))
        })?;
    sql_query(format!(
        "SELECT {COLUMNS} FROM security_transactions WHERE id = $1{lock}"
    ))
    .bind::<SqlUuid, _>(transaction_uuid)
    .get_result::<SecurityTransactionRow>(conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?
    .map(SecurityTransactionRecord::try_from)
    .transpose()
}

async fn insert_one(
    conn: &mut AsyncPgConnection,
    record: &SecurityTransactionRecord,
) -> PersistenceResult<()> {
    let resource = &record.resource;
    sql_query(
        "INSERT INTO security_transactions \
         (id, kind, principal_id, coordinator_service_id, expires_at, created_at, request_digest, \
          binding, prepared_plan, prepared_plan_digest, state, accepted_steps, next_required_step, \
          terminal_result, canonical_request) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)",
    )
    .bind::<SqlUuid, _>(ids::typed_uuid_part_expect_internal(
        resource.transaction_id.as_str(),
    ))
    .bind::<Text, _>(match resource.kind {
        SecurityTransactionKind::Recovery => "recovery",
        SecurityTransactionKind::SecurityRotation => "security_rotation",
    })
    .bind::<Text, _>(resource.principal_id.as_str())
    .bind::<Text, _>(resource.coordinator_service_id.as_str())
    .bind::<Timestamptz, _>(resource.expires_at)
    .bind::<Timestamptz, _>(resource.created_at)
    .bind::<Text, _>(resource.request_digest.as_str())
    .bind::<Jsonb, _>(
        serde_json::to_value(&resource.binding)
            .map_err(|error| PersistenceError::Internal(error.to_string()))?,
    )
    .bind::<Jsonb, _>(
        serde_json::to_value(&resource.prepared_plan)
            .map_err(|error| PersistenceError::Internal(error.to_string()))?,
    )
    .bind::<Text, _>(resource.prepared_plan_digest.as_str())
    .bind::<Text, _>(match resource.state {
        SecurityTransactionState::Pending => "pending",
        SecurityTransactionState::Running => "running",
        SecurityTransactionState::AwaitingDeviceAttestation => "awaiting_device_attestation",
        SecurityTransactionState::Completed => "completed",
        SecurityTransactionState::Aborted => "aborted",
        SecurityTransactionState::Expired => "expired",
    })
    .bind::<Jsonb, _>(
        serde_json::to_value(&resource.accepted_steps)
            .map_err(|error| PersistenceError::Internal(error.to_string()))?,
    )
    .bind::<Nullable<Text>, _>(resource.next_required_step.map(enum_text).transpose()?)
    .bind::<Nullable<Jsonb>, _>(
        resource
            .terminal_result
            .as_ref()
            .map(serde_json::to_value)
            .transpose()
            .map_err(|error| PersistenceError::Internal(error.to_string()))?,
    )
    .bind::<Binary, _>(&record.canonical_request)
    .execute(conn)
    .await
    .map(|_| ())
    .map_err(PersistenceError::database)
}

async fn load_step_outcome(
    conn: &mut AsyncPgConnection,
    transaction_id: &str,
    step: SecurityTransactionStep,
) -> PersistenceResult<Option<SecurityTransactionStepOutcomeRecord>> {
    let transaction_uuid =
        ids::parse_typed_uuid(transaction_id, "transaction").ok_or_else(|| {
            PersistenceError::SchemaViolation(format!(
                "malformed transaction_id `{transaction_id}`"
            ))
        })?;
    sql_query(
        "SELECT transaction_id, step, canonical_request, response, participant_outcome \
         FROM security_transaction_step_outcomes WHERE transaction_id = $1 AND step = $2",
    )
    .bind::<SqlUuid, _>(transaction_uuid)
    .bind::<Text, _>(enum_text(step)?)
    .get_result::<SecurityTransactionStepOutcomeRow>(conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?
    .map(SecurityTransactionStepOutcomeRecord::try_from)
    .transpose()
}

async fn load_step_attempt(
    conn: &mut AsyncPgConnection,
    transaction_id: &str,
    step: SecurityTransactionStep,
) -> PersistenceResult<Option<SecurityTransactionStepAttemptRecord>> {
    let transaction_uuid =
        ids::parse_typed_uuid(transaction_id, "transaction").ok_or_else(|| {
            PersistenceError::SchemaViolation(format!(
                "malformed transaction_id `{transaction_id}`"
            ))
        })?;
    sql_query(
        "SELECT transaction_id, step, canonical_request \
         FROM security_transaction_step_attempts WHERE transaction_id = $1 AND step = $2",
    )
    .bind::<SqlUuid, _>(transaction_uuid)
    .bind::<Text, _>(enum_text(step)?)
    .get_result::<SecurityTransactionStepAttemptRow>(conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?
    .map(SecurityTransactionStepAttemptRecord::try_from)
    .transpose()
}

async fn update_mutable_fields(
    conn: &mut AsyncPgConnection,
    record: &SecurityTransactionRecord,
) -> PersistenceResult<()> {
    sql_query(
        "UPDATE security_transactions SET state = $2, accepted_steps = $3, \
         next_required_step = $4, terminal_result = $5 WHERE id = $1",
    )
    .bind::<SqlUuid, _>(ids::typed_uuid_part_expect_internal(
        record.resource.transaction_id.as_str(),
    ))
    .bind::<Text, _>(match record.resource.state {
        SecurityTransactionState::Pending => "pending",
        SecurityTransactionState::Running => "running",
        SecurityTransactionState::AwaitingDeviceAttestation => "awaiting_device_attestation",
        SecurityTransactionState::Completed => "completed",
        SecurityTransactionState::Aborted => "aborted",
        SecurityTransactionState::Expired => "expired",
    })
    .bind::<Jsonb, _>(
        serde_json::to_value(&record.resource.accepted_steps)
            .map_err(|error| PersistenceError::Internal(error.to_string()))?,
    )
    .bind::<Nullable<Text>, _>(
        record
            .resource
            .next_required_step
            .map(enum_text)
            .transpose()?,
    )
    .bind::<Nullable<Jsonb>, _>(
        record
            .resource
            .terminal_result
            .as_ref()
            .map(serde_json::to_value)
            .transpose()
            .map_err(|error| PersistenceError::Internal(error.to_string()))?,
    )
    .execute(conn)
    .await
    .map(|_| ())
    .map_err(PersistenceError::database)
}

fn enum_text<T: serde::Serialize>(value: T) -> PersistenceResult<String> {
    serde_json::to_value(value)
        .map_err(|error| PersistenceError::Internal(error.to_string()))?
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| PersistenceError::Internal("wire enum did not serialize as text".to_owned()))
}

#[derive(QueryableByName)]
struct RecoverySessionBindingRow {
    #[diesel(sql_type = Text)]
    principal_id: String,
    #[diesel(sql_type = Text)]
    state: String,
    #[diesel(sql_type = Timestamptz)]
    expires_at: chrono::DateTime<chrono::Utc>,
    #[diesel(sql_type = Nullable<SqlUuid>)]
    transaction_id: Option<Uuid>,
}

#[async_trait]
impl SecurityTransactionStore for PgSecurityTransactionStore {
    async fn create(
        &self,
        record: SecurityTransactionRecord,
    ) -> PersistenceResult<SecurityTransactionRecord> {
        record
            .resource
            .validate_structural()
            .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
        arkret_canonical::canonical::verify_digest(
            &record.canonical_request,
            record.resource.request_digest.as_str(),
        )
        .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
        let recovery_session_id = match &record.resource.binding {
            SecurityTransactionBinding::Recovery(binding) => {
                Some(binding.recovery_session_id().as_str().to_owned())
            }
            SecurityTransactionBinding::SecurityRotation(_) => None,
        };
        let transaction_id = record.resource.transaction_id.as_str().to_owned();
        let principal_id = record.resource.principal_id.as_str().to_owned();
        let mut conn = pg_conn(&self.pool).await?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            if let Some(existing) = load_one(conn, &transaction_id, true).await? {
                if existing.canonical_request == record.canonical_request {
                    return Ok(existing);
                }
                return Err(PersistenceError::Conflict(format!(
                    "transaction_id `{transaction_id}` already exists with different canonical bytes"
                ))
                .into());
            }
            if let Some(recovery_session_id) = &recovery_session_id {
                let session = sql_query(
                    "SELECT principal_id, state, expires_at, transaction_id FROM recovery_sessions \
                     WHERE id = $1 FOR UPDATE",
                )
                .bind::<SqlUuid, _>(
                    ids::parse_typed_uuid(recovery_session_id, "recovery_session").ok_or_else(
                        || {
                            PersistenceError::SchemaViolation(format!(
                                "malformed recovery_session_id `{recovery_session_id}`"
                            ))
                        },
                    )?,
                )
                .get_result::<RecoverySessionBindingRow>(conn)
                .await
                .optional()
                .map_err(PersistenceError::database)?
                .ok_or_else(|| {
                    PersistenceError::NotFound(format!(
                        "recovery_session_id `{recovery_session_id}` not found"
                    ))
                })?;
                if session.principal_id != principal_id
                    || session.state != "verified"
                    || session.expires_at <= chrono::Utc::now()
                    || session.transaction_id.is_some()
                {
                    return Err(PersistenceError::Conflict(
                        "recovery session is not an unbound current verified session for the transaction principal"
                            .to_owned(),
                    )
                    .into());
                }
            }
            insert_one(conn, &record).await?;
            if let Some(recovery_session_id) = recovery_session_id {
                sql_query(
                    "UPDATE recovery_sessions SET transaction_id = $2, updated_at = NOW() \
                     WHERE id = $1 AND transaction_id IS NULL",
                )
                .bind::<SqlUuid, _>(
                    ids::parse_typed_uuid(&recovery_session_id, "recovery_session").ok_or_else(
                        || {
                            PersistenceError::SchemaViolation(format!(
                                "malformed recovery_session_id `{recovery_session_id}`"
                            ))
                        },
                    )?,
                )
                .bind::<SqlUuid, _>(ids::typed_uuid_part_expect_internal(&transaction_id))
                .execute(conn)
                .await
                .map_err(PersistenceError::database)?;
            }
            Ok(record)
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }

    async fn get(
        &self,
        transaction_id: &str,
    ) -> PersistenceResult<Option<SecurityTransactionRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        load_one(&mut conn, transaction_id, false).await
    }

    async fn update(&self, record: SecurityTransactionRecord) -> PersistenceResult<()> {
        record
            .resource
            .validate_structural()
            .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
        let mut conn = pg_conn(&self.pool).await?;
        let transaction_id = record.resource.transaction_id.as_str().to_owned();
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            let existing = load_one(conn, &transaction_id, true)
                .await?
                .ok_or_else(|| {
                    PersistenceError::NotFound(format!(
                        "transaction_id `{transaction_id}` not found"
                    ))
                })?;
            super::validate_security_transaction_update(&existing, &record)?;
            update_mutable_fields(conn, &record).await?;
            Ok(())
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }

    async fn step_outcome(
        &self,
        transaction_id: &str,
        step: SecurityTransactionStep,
    ) -> PersistenceResult<Option<SecurityTransactionStepOutcomeRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        load_step_outcome(&mut conn, transaction_id, step).await
    }

    async fn begin_step(
        &self,
        attempt: SecurityTransactionStepAttemptRecord,
    ) -> PersistenceResult<SecurityTransactionStepAttemptRecord> {
        let transaction_id = attempt.transaction_id.clone();
        let mut conn = pg_conn(&self.pool).await?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            if load_one(conn, &transaction_id, true).await?.is_none() {
                return Err(PersistenceError::NotFound(format!(
                    "transaction_id `{transaction_id}` not found"
                ))
                .into());
            }
            if let Some(existing) = load_step_attempt(conn, &transaction_id, attempt.step).await? {
                if existing.canonical_request == attempt.canonical_request {
                    return Ok(existing);
                }
                return Err(PersistenceError::Conflict(format!(
                    "security transaction step {:?} already began with different canonical bytes",
                    attempt.step
                ))
                .into());
            }
            sql_query(
                "INSERT INTO security_transaction_step_attempts \
                 (transaction_id, step, canonical_request) VALUES ($1, $2, $3)",
            )
            .bind::<SqlUuid, _>(ids::typed_uuid_part_expect_internal(&transaction_id))
            .bind::<Text, _>(enum_text(attempt.step)?)
            .bind::<Binary, _>(&attempt.canonical_request)
            .execute(conn)
            .await
            .map_err(PersistenceError::database)?;
            Ok(attempt)
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }

    async fn accept_step(
        &self,
        record: SecurityTransactionRecord,
        outcome: SecurityTransactionStepOutcomeRecord,
    ) -> PersistenceResult<SecurityTransactionStepOutcomeRecord> {
        record
            .resource
            .validate_structural()
            .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
        let transaction_id = record.resource.transaction_id.as_str().to_owned();
        if outcome.transaction_id != transaction_id {
            return Err(PersistenceError::SchemaViolation(
                "security transaction step outcome belongs to a different transaction".to_owned(),
            ));
        }
        let mut conn = pg_conn(&self.pool).await?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            let existing = load_one(conn, &transaction_id, true)
                .await?
                .ok_or_else(|| {
                    PersistenceError::NotFound(format!(
                        "transaction_id `{transaction_id}` not found"
                    ))
                })?;
            if let Some(stored) = load_step_outcome(conn, &transaction_id, outcome.step).await? {
                if stored.canonical_request == outcome.canonical_request {
                    return Ok(stored);
                }
                return Err(PersistenceError::Conflict(format!(
                    "security transaction step {:?} already has different canonical request bytes",
                    outcome.step
                ))
                .into());
            }
            let attempt = load_step_attempt(conn, &transaction_id, outcome.step)
                .await?
                .ok_or_else(|| {
                    PersistenceError::Conflict(format!(
                        "security transaction step {:?} was not durably begun",
                        outcome.step
                    ))
                })?;
            if attempt.canonical_request != outcome.canonical_request {
                return Err(PersistenceError::Conflict(format!(
                    "security transaction step {:?} outcome changed the durable request bytes",
                    outcome.step
                ))
                .into());
            }
            super::validate_security_transaction_update(&existing, &record)?;
            if record.resource.accepted_steps.len() != existing.resource.accepted_steps.len() + 1
                || record.resource.accepted_steps.last().map(|step| step.step) != Some(outcome.step)
            {
                return Err(PersistenceError::SchemaViolation(
                    "accepted step outcome must match the single appended transaction step"
                        .to_owned(),
                )
                .into());
            }
            sql_query(
                "INSERT INTO security_transaction_step_outcomes \
                 (transaction_id, step, canonical_request, response, participant_outcome) \
                 VALUES ($1, $2, $3, $4, $5)",
            )
            .bind::<SqlUuid, _>(ids::typed_uuid_part_expect_internal(&transaction_id))
            .bind::<Text, _>(enum_text(outcome.step)?)
            .bind::<Binary, _>(&outcome.canonical_request)
            .bind::<Jsonb, _>(&outcome.response)
            .bind::<Nullable<Jsonb>, _>(&outcome.participant_outcome)
            .execute(conn)
            .await
            .map_err(PersistenceError::database)?;
            update_mutable_fields(conn, &record).await?;
            if record.resource.state == SecurityTransactionState::Completed
                && let SecurityTransactionBinding::Recovery(binding) = &record.resource.binding
            {
                let affected = sql_query(
                    "UPDATE recovery_sessions SET state = 'completed', updated_at = NOW() \
                     WHERE id = $1 AND transaction_id = $2 AND state = 'verified'",
                )
                .bind::<SqlUuid, _>(ids::typed_uuid_part_expect_internal(
                    binding.recovery_session_id().as_str(),
                ))
                .bind::<SqlUuid, _>(ids::typed_uuid_part_expect_internal(&transaction_id))
                .execute(conn)
                .await
                .map_err(PersistenceError::database)?;
                if affected != 1 {
                    return Err(PersistenceError::Conflict(
                        "terminal recovery transaction does not own a verified recovery session"
                            .to_owned(),
                    )
                    .into());
                }
            }
            Ok(outcome)
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }
}
