use diesel::sql_types::SmallInt;
use serde::de::DeserializeOwned;
use soland_storage::{
    AuthorityCommitStore, AuthorityCommitTransaction, AuthorityCommitWriteOutcome,
    CurrentRealmAuthority, QueuedEventRecord, QueuedEventStatus,
};

use super::{
    AsyncConnection, AsyncPgConnection, BigInt, Binary, Jsonb, Nullable, OptionalExtension,
    PersistenceError, PersistenceResult, PgPool, PgTransactionError, QueryableByName, RunQueryDsl,
    Text, Timestamptz, Value, async_trait, ids, pg_conn, sql_query,
};
use crate::capability_grant_current_results::commit_capability_grant_current_result_in_connection;

#[derive(Clone)]
pub struct PgAuthorityCommitStore {
    pub pool: PgPool,
}

#[derive(QueryableByName)]
struct AuthorityRow {
    #[diesel(sql_type = Text)]
    realm_id: String,
    #[diesel(sql_type = BigInt)]
    generation: i64,
    #[diesel(sql_type = Text)]
    service_id: String,
    #[diesel(sql_type = Jsonb)]
    authority_ref: Value,
    #[diesel(sql_type = Nullable<Text>)]
    last_handoff_ref: Option<String>,
}

#[derive(QueryableByName)]
struct EventRow {
    #[diesel(sql_type = Jsonb)]
    envelope: Value,
    #[diesel(sql_type = Text)]
    state: String,
    #[diesel(sql_type = Timestamptz)]
    received_at: chrono::DateTime<chrono::Utc>,
    #[diesel(sql_type = Nullable<Text>)]
    rejection_reason: Option<String>,
    #[diesel(sql_type = Nullable<Jsonb>)]
    commit_json: Option<Value>,
}

#[derive(QueryableByName)]
struct EventPkRow {
    #[diesel(sql_type = BigInt)]
    event_pk: i64,
    #[diesel(sql_type = Text)]
    state: String,
    #[diesel(sql_type = Binary)]
    canonical_bytes: Vec<u8>,
    #[diesel(sql_type = Jsonb)]
    envelope: Value,
}

#[derive(QueryableByName)]
struct CommitRow {
    #[diesel(sql_type = Jsonb)]
    commit_json: Value,
}

#[derive(QueryableByName)]
struct HeadRow {
    #[diesel(sql_type = Jsonb)]
    stream_ref: Value,
    #[diesel(sql_type = BigInt)]
    stream_position: i64,
    #[diesel(sql_type = Text)]
    commit_id: String,
}

#[derive(QueryableByName)]
struct SnapshotRow {
    #[diesel(sql_type = Jsonb)]
    snapshot_json: Value,
}

#[derive(QueryableByName)]
struct HandoffRow {
    #[diesel(sql_type = Jsonb)]
    handoff_json: Value,
}

#[derive(QueryableByName)]
struct CommitStreamRow {
    #[diesel(sql_type = Jsonb)]
    commit_json: Value,
    #[diesel(sql_type = Jsonb)]
    envelope: Value,
}

#[derive(QueryableByName)]
struct EpochRow {
    #[diesel(sql_type = BigInt)]
    epoch: i64,
}

fn invalid(detail: impl std::fmt::Display) -> PersistenceError {
    PersistenceError::SchemaViolation(detail.to_string())
}

fn require_exact_commit_replay(
    existing_commit: &Value,
    candidate_commit: &Value,
) -> PersistenceResult<()> {
    if existing_commit == candidate_commit {
        return Ok(());
    }
    Err(PersistenceError::Conflict(
        "duplicate_conflict: Event already has a different RealmCommit".into(),
    ))
}

fn decode_json<T: DeserializeOwned>(value: Value, what: &str) -> PersistenceResult<T> {
    serde_json::from_value(value)
        .map_err(|error| PersistenceError::Internal(format!("stored {what} is invalid: {error}")))
}

fn decode_text<T: DeserializeOwned>(value: String, what: &str) -> PersistenceResult<T> {
    decode_json(Value::String(value), what)
}

fn to_i64(value: u64, what: &str) -> PersistenceResult<i64> {
    i64::try_from(value).map_err(|_| invalid(format!("{what} exceeds PostgreSQL bigint")))
}

fn to_u64(value: i64, what: &str) -> PersistenceResult<u64> {
    u64::try_from(value)
        .map_err(|_| PersistenceError::Internal(format!("stored {what} is negative")))
}

fn stream_key(stream_ref: &arkret_wire::CommitStreamRef) -> PersistenceResult<String> {
    String::from_utf8(
        arkret_canonical::canonical_json_bytes(stream_ref).map_err(PersistenceError::database)?,
    )
    .map_err(PersistenceError::database)
}

fn authority_from_row(row: AuthorityRow) -> PersistenceResult<CurrentRealmAuthority> {
    Ok(CurrentRealmAuthority {
        realm_id: decode_text(row.realm_id, "authority Realm id")?,
        generation: to_u64(row.generation, "authority generation")?,
        service_id: decode_text(row.service_id, "authority service id")?,
        authority_ref: decode_json(row.authority_ref, "authority reference")?,
        last_handoff_ref: row
            .last_handoff_ref
            .map(|value| decode_text(value, "authority handoff id"))
            .transpose()?,
    })
}

async fn locked_authority(
    conn: &mut AsyncPgConnection,
    realm_id: &arkret_wire::RealmId,
) -> Result<Option<CurrentRealmAuthority>, PgTransactionError> {
    let row = sql_query(
        "SELECT realm_id, generation, service_id, authority_ref, last_handoff_ref \
         FROM realm_authorities WHERE realm_id = $1 FOR UPDATE",
    )
    .bind::<Text, _>(realm_id.as_str())
    .get_result::<AuthorityRow>(conn)
    .await
    .optional()?;
    row.map(authority_from_row).transpose().map_err(Into::into)
}

fn same_authority(left: &CurrentRealmAuthority, right: &CurrentRealmAuthority) -> bool {
    left.realm_id == right.realm_id
        && left.generation == right.generation
        && left.service_id == right.service_id
        && left.authority_ref == right.authority_ref
        && left.last_handoff_ref == right.last_handoff_ref
}

fn signature_service_id(
    signature: &arkret_wire::DetachedObjectSignature,
) -> PersistenceResult<arkret_wire::DidCoreId> {
    let controller = signature
        .verification_method
        .as_str()
        .split_once('#')
        .map(|(controller, _)| controller)
        .ok_or_else(|| invalid("authority signature method has no fragment"))?;
    let did = arkret_wire::Did::new(controller.to_owned()).map_err(invalid)?;
    arkret_identifiers::project_did_to_core_id(&did).map_err(invalid)
}

/// Queue one producer Event on a caller-owned connection.
///
/// A Station that admits and commits in a single transaction calls this
/// immediately before [`commit_transaction_in_connection`], so the queued row
/// and its `RealmCommit` become visible together or not at all.
pub(crate) async fn queue_event_in_connection(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    queued_at: chrono::DateTime<chrono::Utc>,
) -> Result<(), PgTransactionError> {
    event.validate_for_submit_structural().map_err(invalid)?;
    let canonical_bytes =
        arkret_canonical::canonical_json_bytes(&event.digest_payload().map_err(invalid)?)
            .map_err(PersistenceError::database)?;
    let envelope = serde_json::to_value(event).map_err(PersistenceError::database)?;
    let token = ids::parse_event_id(event.event_id.as_str())
        .ok_or_else(|| invalid("Event id is not a canonical Event token"))?;
    let digest_suite = i16::from(token[0] & 0x0f);
    let existing = sql_query(
        "SELECT pk AS event_pk, state, canonical_bytes, envelope \
         FROM canonical_events WHERE id = $1 FOR UPDATE",
    )
    .bind::<Binary, _>(token.to_vec())
    .get_result::<EventPkRow>(&mut *conn)
    .await
    .optional()?;
    if let Some(existing) = existing {
        if existing.canonical_bytes == canonical_bytes && existing.envelope == envelope {
            return Ok(());
        }
        return Err(PersistenceError::Conflict("event_hash_collision".into()).into());
    }
    sql_query(
        "INSERT INTO canonical_events \
         (id, digest_suite, digest, actor_id, realm_id, scope_ref, kind, canonical_bytes, envelope, state, received_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'queued', $10)",
    )
    .bind::<Binary, _>(token.to_vec())
    .bind::<SmallInt, _>(digest_suite)
    .bind::<Binary, _>(token[1..].to_vec())
    .bind::<Text, _>(event.actor_id.to_string())
    .bind::<Text, _>(event.realm_id.as_str())
    .bind::<Jsonb, _>(serde_json::to_value(&event.scope_ref).map_err(PersistenceError::database)?)
    .bind::<Text, _>(event.kind.as_str())
    .bind::<Binary, _>(canonical_bytes)
    .bind::<Jsonb, _>(envelope)
    .bind::<Timestamptz, _>(queued_at)
    .execute(&mut *conn)
    .await?;
    Ok(())
}

/// Installs one authority decision on an existing database transaction.
///
/// Product projections, delivery intents, and the accepted `RealmCommit` must
/// share this connection so a caller can expose either the complete accepted
/// operation or none of it.
pub(crate) async fn commit_transaction_in_connection(
    conn: &mut AsyncPgConnection,
    transaction: &AuthorityCommitTransaction,
) -> Result<AuthorityCommitWriteOutcome, PgTransactionError> {
    transaction.validate().map_err(invalid)?;
    if signature_service_id(&transaction.commit.signature)?
        != transaction.expected_authority.service_id
    {
        return Err(invalid(
            "RealmCommit signature method does not belong to the expected authority",
        )
        .into());
    }
    let canonical_bytes = arkret_canonical::canonical_json_bytes(
        &transaction.event.digest_payload().map_err(invalid)?,
    )
    .map_err(PersistenceError::database)?;
    let event_token = ids::parse_event_id(transaction.event.event_id.as_str())
        .ok_or_else(|| invalid("Event id is not a canonical Event token"))?;
    let stream_key = stream_key(&transaction.commit.stream_ref)?;
    let commit_json =
        serde_json::to_value(&transaction.commit).map_err(PersistenceError::database)?;
    let stream_position = to_i64(transaction.commit.stream_position, "stream position")?;
    let governance_generation = to_i64(
        transaction.commit.governance_generation,
        "governance generation",
    )?;

    let current = locked_authority(conn, &transaction.expected_authority.realm_id)
        .await?
        .ok_or_else(|| PersistenceError::NotFound("Realm authority not initialized".into()))?;
    if !same_authority(&current, &transaction.expected_authority) {
        return Ok(AuthorityCommitWriteOutcome::StaleAuthority(current));
    }

    let event_row = sql_query(
        "SELECT pk AS event_pk, state, canonical_bytes, envelope \
         FROM canonical_events WHERE id = $1 FOR UPDATE",
    )
    .bind::<Binary, _>(event_token.to_vec())
    .get_result::<EventPkRow>(&mut *conn)
    .await
    .optional()?
    .ok_or_else(|| PersistenceError::NotFound("queued Event not found".into()))?;
    if event_row.canonical_bytes != canonical_bytes
        || event_row.envelope
            != serde_json::to_value(&transaction.event).map_err(PersistenceError::database)?
    {
        return Err(PersistenceError::Conflict("event_hash_collision".into()).into());
    }

    let existing = sql_query("SELECT commit_json FROM realm_commits WHERE event_pk = $1")
        .bind::<BigInt, _>(event_row.event_pk)
        .get_result::<CommitRow>(&mut *conn)
        .await
        .optional()?;
    if let Some(existing) = existing {
        require_exact_commit_replay(&existing.commit_json, &commit_json)?;
        return Ok(AuthorityCommitWriteOutcome::Duplicate);
    }
    if event_row.state != "queued" {
        return Err(PersistenceError::Conflict(format!(
            "Event cannot commit from state {}",
            event_row.state
        ))
        .into());
    }

    let previous = sql_query(
        "SELECT commit_json FROM realm_commits \
         WHERE stream_key = $1 ORDER BY stream_position DESC LIMIT 1 FOR UPDATE",
    )
    .bind::<Text, _>(&stream_key)
    .get_result::<CommitRow>(&mut *conn)
    .await
    .optional()?;
    match previous {
        Some(previous) => {
            let previous_commit: arkret_wire::RealmCommit =
                decode_json(previous.commit_json, "previous RealmCommit")?;
            transaction
                .commit
                .validate_successor_of(&previous_commit)
                .map_err(invalid)?;
        }
        None if transaction.commit.stream_position == 0
            && transaction.commit.previous_commit_ref.is_none() => {}
        None => {
            return Err(PersistenceError::Conflict(
                "non-genesis RealmCommit has no stream predecessor".into(),
            )
            .into());
        }
    }

    sql_query(
        "INSERT INTO realm_commits \
         (commit_id, realm_id, stream_key, stream_ref, stream_position, previous_commit_ref, event_pk, governance_generation, commit_json, committed_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
    )
    .bind::<Text, _>(transaction.commit.commit_id.as_str())
    .bind::<Text, _>(transaction.commit.realm_id.as_str())
    .bind::<Text, _>(&stream_key)
    .bind::<Jsonb, _>(serde_json::to_value(&transaction.commit.stream_ref).map_err(PersistenceError::database)?)
    .bind::<BigInt, _>(stream_position)
    .bind::<Nullable<Text>, _>(transaction.commit.previous_commit_ref.as_ref().map(|id| id.as_str()))
    .bind::<BigInt, _>(event_row.event_pk)
    .bind::<BigInt, _>(governance_generation)
    .bind::<Jsonb, _>(&commit_json)
    .bind::<Timestamptz, _>(transaction.commit.committed_at)
    .execute(&mut *conn)
    .await?;
    sql_query(
        "UPDATE canonical_events SET state = 'committed', committed_at = $2, rejection_reason = NULL \
         WHERE pk = $1 AND state = 'queued'",
    )
    .bind::<BigInt, _>(event_row.event_pk)
    .bind::<Timestamptz, _>(transaction.commit.committed_at)
    .execute(&mut *conn)
    .await?;
    if let Some(mls_state) = &transaction.mls_state {
        let previous =
            sql_query("SELECT epoch FROM mls_group_states WHERE group_id = $1 FOR UPDATE")
                .bind::<Text, _>(&mls_state.group_id)
                .get_result::<EpochRow>(&mut *conn)
                .await
                .optional()?;
        let epoch = to_i64(mls_state.epoch, "MLS epoch")?;
        let valid_successor = previous.as_ref().map_or(mls_state.epoch == 1, |row| {
            row.epoch.checked_add(1) == Some(epoch)
        });
        if !valid_successor {
            return Err(PersistenceError::Conflict(
                "MLS staged Commit does not advance the installed epoch exactly".into(),
            )
            .into());
        }
        sql_query(
            "INSERT INTO mls_group_states \
             (group_id, realm_id, effective_scope, epoch, state_bytes, commit_event_pk, updated_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7) \
             ON CONFLICT (group_id) DO UPDATE SET \
               realm_id = EXCLUDED.realm_id, effective_scope = EXCLUDED.effective_scope, \
               epoch = EXCLUDED.epoch, state_bytes = EXCLUDED.state_bytes, \
               commit_event_pk = EXCLUDED.commit_event_pk, updated_at = EXCLUDED.updated_at",
        )
        .bind::<Text, _>(&mls_state.group_id)
        .bind::<Text, _>(transaction.event.realm_id.as_str())
        .bind::<Jsonb, _>(serde_json::to_value(&mls_state.effective_scope).map_err(PersistenceError::database)?)
        .bind::<BigInt, _>(epoch)
        .bind::<Binary, _>(&mls_state.state_bytes)
        .bind::<BigInt, _>(event_row.event_pk)
        .bind::<Timestamptz, _>(transaction.commit.committed_at)
        .execute(&mut *conn)
        .await?;
    }
    for welcome in &transaction.welcomes {
        sql_query(
            "INSERT INTO mls_welcome_deliveries \
             (welcome_id, realm_id, commit_event_pk, recipient_actor_id, delivery_json, state, queued_at) \
             VALUES ($1, $2, $3, $4, $5, 'queued', $6)",
        )
        .bind::<Text, _>(welcome.welcome_id.as_str())
        .bind::<Text, _>(welcome.realm_id.as_str())
        .bind::<BigInt, _>(event_row.event_pk)
        .bind::<Text, _>(welcome.recipient_actor_id.to_string())
        .bind::<Jsonb, _>(serde_json::to_value(welcome).map_err(PersistenceError::database)?)
        .bind::<Timestamptz, _>(transaction.commit.committed_at)
        .execute(&mut *conn)
        .await?;
    }
    Ok(AuthorityCommitWriteOutcome::Committed)
}

fn require_atomic_admission_outcome(
    outcome: AuthorityCommitWriteOutcome,
) -> Result<AuthorityCommitWriteOutcome, PgTransactionError> {
    match outcome {
        AuthorityCommitWriteOutcome::Committed => Ok(AuthorityCommitWriteOutcome::Committed),
        AuthorityCommitWriteOutcome::Duplicate => Ok(AuthorityCommitWriteOutcome::Duplicate),
        AuthorityCommitWriteOutcome::StaleAuthority(_) => Err(PersistenceError::Conflict(
            "stale Realm authority during atomic Event admission".into(),
        )
        .into()),
    }
}

#[async_trait]
impl AuthorityCommitStore for PgAuthorityCommitStore {
    async fn install_genesis_authority(
        &self,
        authority: &CurrentRealmAuthority,
    ) -> PersistenceResult<()> {
        if authority.generation != 0
            || authority.last_handoff_ref.is_some()
            || !matches!(
                authority.authority_ref,
                arkret_wire::RealmCommitAuthorityRef::GenesisOrChangeEvent(_)
            )
        {
            return Err(invalid(
                "genesis authority must use generation 0 without a handoff reference",
            ));
        }
        let mut conn = pg_conn(&self.pool).await?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            sql_query(
                "INSERT INTO realm_authorities \
                 (realm_id, generation, service_id, authority_ref, last_handoff_ref) VALUES ($1, 0, $2, $3, NULL) \
                 ON CONFLICT (realm_id) DO NOTHING",
            )
            .bind::<Text, _>(authority.realm_id.as_str())
            .bind::<Text, _>(authority.service_id.as_str())
            .bind::<Jsonb, _>(serde_json::to_value(&authority.authority_ref).map_err(PersistenceError::database)?)
            .execute(&mut *conn)
            .await?;
            let stored = locked_authority(conn, &authority.realm_id)
                .await?
                .ok_or_else(|| PersistenceError::Internal("genesis authority disappeared".into()))?;
            if !same_authority(&stored, authority) {
                return Err(PersistenceError::Conflict(
                    "realm authority already initialized differently".into(),
                )
                .into());
            }
            Ok(())
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }

    async fn current_authority(
        &self,
        realm_id: &arkret_wire::RealmId,
    ) -> PersistenceResult<Option<CurrentRealmAuthority>> {
        let mut conn = pg_conn(&self.pool).await?;
        let row = sql_query(
            "SELECT realm_id, generation, service_id, authority_ref, last_handoff_ref \
             FROM realm_authorities WHERE realm_id = $1",
        )
        .bind::<Text, _>(realm_id.as_str())
        .get_result::<AuthorityRow>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?;
        row.map(authority_from_row).transpose()
    }

    async fn queue_event(
        &self,
        event: &arkret_wire::Event,
        queued_at: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool).await?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            queue_event_in_connection(conn, event, queued_at).await
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }

    async fn queued_event(
        &self,
        event_id: &arkret_wire::EventId,
    ) -> PersistenceResult<Option<QueuedEventRecord>> {
        let token = ids::parse_event_id(event_id.as_str())
            .ok_or_else(|| invalid("Event id is not a canonical Event token"))?;
        let mut conn = pg_conn(&self.pool).await?;
        let row = sql_query(
            "SELECT e.envelope, e.state, e.received_at, e.rejection_reason, c.commit_json \
             FROM canonical_events e LEFT JOIN realm_commits c ON c.event_pk = e.pk \
             WHERE e.id = $1",
        )
        .bind::<Binary, _>(token.to_vec())
        .get_result::<EventRow>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?;
        row.map(|row| {
            let status = match row.state.as_str() {
                "queued" => QueuedEventStatus::Queued,
                "committed" => QueuedEventStatus::Committed,
                "rejected" => QueuedEventStatus::Rejected,
                other => {
                    return Err(PersistenceError::Internal(format!(
                        "stored Event has unknown queue state {other:?}"
                    )));
                }
            };
            Ok(QueuedEventRecord {
                event: decode_json(row.envelope, "queued Event")?,
                status,
                queued_at: row.received_at,
                committed: row
                    .commit_json
                    .map(|value| decode_json(value, "RealmCommit"))
                    .transpose()?,
                rejection_reason: row.rejection_reason,
            })
        })
        .transpose()
    }

    async fn admit_event_transaction(
        &self,
        transaction: &AuthorityCommitTransaction,
        queued_at: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<AuthorityCommitWriteOutcome> {
        transaction.validate().map_err(invalid)?;
        let mut conn = pg_conn(&self.pool).await?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            queue_event_in_connection(conn, &transaction.event, queued_at).await?;
            let outcome = require_atomic_admission_outcome(
                commit_transaction_in_connection(conn, transaction).await?,
            )?;
            if matches!(outcome, AuthorityCommitWriteOutcome::Committed) {
                commit_capability_grant_current_result_in_connection(
                    conn,
                    &transaction.event,
                    &transaction.commit,
                )
                .await?;
            }
            Ok(outcome)
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }

    async fn commit_transaction(
        &self,
        transaction: &AuthorityCommitTransaction,
    ) -> PersistenceResult<AuthorityCommitWriteOutcome> {
        let mut conn = pg_conn(&self.pool).await?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            let outcome = commit_transaction_in_connection(conn, transaction).await?;
            if matches!(outcome, AuthorityCommitWriteOutcome::Committed) {
                commit_capability_grant_current_result_in_connection(
                    conn,
                    &transaction.event,
                    &transaction.commit,
                )
                .await?;
            }
            Ok(outcome)
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }

    async fn stream_head(
        &self,
        stream_ref: &arkret_wire::CommitStreamRef,
    ) -> PersistenceResult<Option<arkret_wire::CommitStreamHead>> {
        let key = stream_key(stream_ref)?;
        let mut conn = pg_conn(&self.pool).await?;
        let row = sql_query(
            "SELECT stream_ref, stream_position, commit_id FROM realm_commits \
             WHERE stream_key = $1 ORDER BY stream_position DESC LIMIT 1",
        )
        .bind::<Text, _>(key)
        .get_result::<HeadRow>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?;
        row.map(|row| {
            Ok(arkret_wire::CommitStreamHead {
                stream_ref: decode_json(row.stream_ref, "commit stream ref")?,
                stream_position: to_u64(row.stream_position, "stream position")?,
                commit_id: decode_text(row.commit_id, "RealmCommit id")?,
            })
        })
        .transpose()
    }

    async fn committed_event(
        &self,
        event_id: &arkret_wire::EventId,
    ) -> PersistenceResult<Option<soland_storage::CommittedEventRecord>> {
        let token = ids::parse_event_id(event_id.as_str())
            .ok_or_else(|| invalid("committed Event lookup has malformed Event id"))?;
        let mut conn = pg_conn(&self.pool).await?;
        let row = sql_query(
            "SELECT c.commit_json, e.envelope FROM realm_commits c \
             JOIN canonical_events e ON e.pk = c.event_pk \
             WHERE e.id = $1",
        )
        .bind::<Binary, _>(token.to_vec())
        .get_result::<CommitStreamRow>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?;
        row.map(|row| {
            let commit: arkret_wire::RealmCommit = decode_json(row.commit_json, "RealmCommit")?;
            let event: arkret_wire::Event = decode_json(row.envelope, "committed Event")?;
            if commit.event_ref != *event_id || event.event_id != *event_id {
                return Err(PersistenceError::Internal(
                    "durable committed Event pair disagrees with its lookup key".into(),
                ));
            }
            Ok(soland_storage::CommittedEventRecord { commit, event })
        })
        .transpose()
    }

    async fn realm_stream_heads(
        &self,
        realm_id: &arkret_wire::RealmId,
    ) -> PersistenceResult<Vec<arkret_wire::CommitStreamHead>> {
        let mut conn = pg_conn(&self.pool).await?;
        let rows = sql_query(
            "SELECT DISTINCT ON (stream_key) stream_ref, stream_position, commit_id \
             FROM realm_commits WHERE realm_id = $1 \
             ORDER BY stream_key, stream_position DESC",
        )
        .bind::<Text, _>(realm_id.as_str())
        .load::<HeadRow>(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
        let mut heads = rows
            .into_iter()
            .map(|row| {
                Ok(arkret_wire::CommitStreamHead {
                    stream_ref: decode_json(row.stream_ref, "commit stream ref")?,
                    stream_position: to_u64(row.stream_position, "stream position")?,
                    commit_id: decode_text(row.commit_id, "RealmCommit id")?,
                })
            })
            .collect::<PersistenceResult<Vec<_>>>()?;
        heads.sort_by(|left, right| left.stream_ref.cmp(&right.stream_ref));
        Ok(heads)
    }

    async fn scan_stream(
        &self,
        request: &arkret_wire::StreamScanRequest,
    ) -> PersistenceResult<arkret_wire::StreamScanOutcome> {
        request.validate().map_err(invalid)?;
        let key = stream_key(&request.stream_ref)?;
        let after = request
            .after_position
            .map(|position| to_i64(position, "stream cursor"))
            .transpose()?
            .unwrap_or(-1);
        let limit = i64::from(request.limit) + 1;
        let mut conn = pg_conn(&self.pool).await?;
        let rows = sql_query(
            "SELECT c.commit_json, e.envelope FROM realm_commits c \
             JOIN canonical_events e ON e.pk = c.event_pk \
             WHERE c.stream_key = $1 AND c.stream_position > $2 \
             ORDER BY c.stream_position ASC LIMIT $3",
        )
        .bind::<Text, _>(key)
        .bind::<BigInt, _>(after)
        .bind::<BigInt, _>(limit)
        .load::<CommitStreamRow>(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
        let truncated = rows.len() > usize::from(request.limit);
        let committed_events = rows
            .into_iter()
            .take(usize::from(request.limit))
            .map(|row| {
                Ok(arkret_wire::CommittedEventView::Full(
                    arkret_wire::CommittedEventFullView {
                        commit: decode_json(row.commit_json, "RealmCommit")?,
                        event: decode_json(row.envelope, "committed Event")?,
                    },
                ))
            })
            .collect::<PersistenceResult<Vec<_>>>()?;
        let outcome = arkret_wire::StreamScanOutcome {
            committed_events,
            truncated,
        };
        outcome.validate_for_request(request).map_err(invalid)?;
        Ok(outcome)
    }

    async fn install_handoff(
        &self,
        handoff: &arkret_wire::RealmAuthorityHandoff,
        final_stream_heads: &[arkret_wire::CommitStreamHead],
        snapshot: &arkret_wire::RealmStateSnapshot,
    ) -> PersistenceResult<()> {
        handoff.validate_shape().map_err(invalid)?;
        if final_stream_heads.is_empty()
            || !final_stream_heads
                .windows(2)
                .all(|pair| pair[0].stream_ref < pair[1].stream_ref)
            || final_stream_heads
                .iter()
                .any(|head| head.stream_ref.realm_id() != &handoff.realm_id)
        {
            return Err(invalid(
                "handoff stream heads must be non-empty, sorted, unique, and same-Realm",
            ));
        }
        let heads_digest = arkret_identifiers::Hash::new(
            arkret_canonical::canonical_sha256(&final_stream_heads)
                .map_err(PersistenceError::database)?,
        )
        .map_err(invalid)?;
        if heads_digest != handoff.final_stream_heads_digest
            || snapshot.snapshot_id != handoff.snapshot_ref
            || snapshot.realm_id != handoff.realm_id
            || snapshot.governance_generation != handoff.from_generation
            || snapshot.visible_stream_heads != final_stream_heads
            || snapshot.signature.signed_digest != handoff.snapshot_digest
            || snapshot.signature.context != arkret_wire::DetachedSignatureContext::RealmSnapshot
            || signature_service_id(&snapshot.signature)? != handoff.from_service_id
        {
            return Err(invalid("handoff snapshot or stream-head binding mismatch"));
        }
        let snapshot_json = serde_json::to_value(snapshot).map_err(PersistenceError::database)?;
        let handoff_json = serde_json::to_value(handoff).map_err(PersistenceError::database)?;
        let mut conn = pg_conn(&self.pool).await?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            let current = locked_authority(conn, &handoff.realm_id)
                .await?
                .ok_or_else(|| PersistenceError::NotFound("Realm authority not initialized".into()))?;
            if current.generation == handoff.to_generation
                && current.service_id == handoff.to_service_id
                && current.last_handoff_ref.as_ref() == Some(&handoff.handoff_id)
            {
                return Ok(());
            }
            if current.generation != handoff.from_generation
                || current.service_id != handoff.from_service_id
            {
                return Err(PersistenceError::Conflict("stale Realm authority handoff".into()).into());
            }

            let rows = sql_query(
                "SELECT DISTINCT ON (stream_key) stream_ref, stream_position, commit_id \
                 FROM realm_commits WHERE realm_id = $1 \
                 ORDER BY stream_key, stream_position DESC",
            )
            .bind::<Text, _>(handoff.realm_id.as_str())
            .load::<HeadRow>(&mut *conn)
            .await?;
            let mut stored_heads = rows
                .into_iter()
                .map(|row| {
                    Ok(arkret_wire::CommitStreamHead {
                        stream_ref: decode_json(row.stream_ref, "commit stream ref")?,
                        stream_position: to_u64(row.stream_position, "stream position")?,
                        commit_id: decode_text(row.commit_id, "RealmCommit id")?,
                    })
                })
                .collect::<PersistenceResult<Vec<_>>>()?;
            stored_heads.sort_by(|left, right| left.stream_ref.cmp(&right.stream_ref));
            if stored_heads != final_stream_heads {
                return Err(PersistenceError::Conflict(
                    "handoff final stream heads do not match durable stream tails".into(),
                )
                .into());
            }
            let realm_head = final_stream_heads.iter().find(|head| {
                head.stream_ref
                    == arkret_wire::CommitStreamRef::Realm {
                        realm_id: handoff.realm_id.clone(),
                    }
            });
            if realm_head.map(|head| &head.commit_id) != Some(&handoff.change_commit_id) {
                return Err(invalid("handoff change commit is not the final Realm stream head").into());
            }

            sql_query(
                "INSERT INTO realm_state_snapshots \
                 (snapshot_id, realm_id, governance_generation, snapshot_json, created_at) \
                 VALUES ($1, $2, $3, $4, $5)",
            )
            .bind::<Text, _>(snapshot.snapshot_id.as_str())
            .bind::<Text, _>(snapshot.realm_id.as_str())
            .bind::<BigInt, _>(to_i64(snapshot.governance_generation, "snapshot governance generation")?)
            .bind::<Jsonb, _>(&snapshot_json)
            .bind::<Timestamptz, _>(snapshot.created_at)
            .execute(&mut *conn)
            .await?;
            sql_query(
                "INSERT INTO realm_authority_handoffs \
                 (handoff_id, realm_id, from_generation, to_generation, from_service_id, to_service_id, handoff_json) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7)",
            )
            .bind::<Text, _>(handoff.handoff_id.as_str())
            .bind::<Text, _>(handoff.realm_id.as_str())
            .bind::<BigInt, _>(to_i64(handoff.from_generation, "handoff from_generation")?)
            .bind::<BigInt, _>(to_i64(handoff.to_generation, "handoff to_generation")?)
            .bind::<Text, _>(handoff.from_service_id.as_str())
            .bind::<Text, _>(handoff.to_service_id.as_str())
            .bind::<Jsonb, _>(&handoff_json)
            .execute(&mut *conn)
            .await?;
            sql_query(
                "UPDATE realm_authorities SET generation = $2, service_id = $3, \
                 authority_ref = $4, last_handoff_ref = $5, updated_at = now() WHERE realm_id = $1",
            )
            .bind::<Text, _>(handoff.realm_id.as_str())
            .bind::<BigInt, _>(to_i64(handoff.to_generation, "handoff to_generation")?)
            .bind::<Text, _>(handoff.to_service_id.as_str())
            .bind::<Jsonb, _>(serde_json::to_value(arkret_wire::RealmCommitAuthorityRef::Handoff(handoff.handoff_id.clone())).map_err(PersistenceError::database)?)
            .bind::<Text, _>(handoff.handoff_id.as_str())
            .execute(&mut *conn)
            .await?;
            Ok(())
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }

    async fn authority_handoffs(
        &self,
        realm_id: &arkret_wire::RealmId,
    ) -> PersistenceResult<Vec<arkret_wire::RealmAuthorityHandoff>> {
        let mut conn = pg_conn(&self.pool).await?;
        let rows = sql_query(
            "SELECT handoff_json FROM realm_authority_handoffs WHERE realm_id = $1 \
             ORDER BY to_generation ASC",
        )
        .bind::<Text, _>(realm_id.as_str())
        .load::<HandoffRow>(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
        rows.into_iter()
            .map(|row| decode_json(row.handoff_json, "Realm authority handoff"))
            .collect()
    }

    async fn latest_snapshot(
        &self,
        realm_id: &arkret_wire::RealmId,
    ) -> PersistenceResult<Option<arkret_wire::RealmStateSnapshot>> {
        let mut conn = pg_conn(&self.pool).await?;
        let row = sql_query(
            "SELECT snapshot_json FROM realm_state_snapshots WHERE realm_id = $1 \
             ORDER BY governance_generation DESC, created_at DESC LIMIT 1",
        )
        .bind::<Text, _>(realm_id.as_str())
        .get_result::<SnapshotRow>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?;
        row.map(|row| decode_json(row.snapshot_json, "RealmStateSnapshot"))
            .transpose()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stale_authority_is_an_atomic_admission_rollback_error() {
        let realm_id = arkret_wire::RealmId::from_event_id(&arkret_wire::EventId::from_digest(
            arkret_canonical::DigestSuite::Sha256,
            [0x61; 32],
        ));
        let authority = CurrentRealmAuthority {
            realm_id,
            generation: 2,
            service_id: arkret_wire::DidCoreId::new("ak:did_core:web:station.example".to_owned())
                .unwrap(),
            authority_ref: arkret_wire::RealmCommitAuthorityRef::GenesisOrChangeEvent(
                arkret_wire::EventId::from_digest(
                    arkret_canonical::DigestSuite::Sha256,
                    [0x62; 32],
                ),
            ),
            last_handoff_ref: None,
        };
        assert!(
            require_atomic_admission_outcome(AuthorityCommitWriteOutcome::StaleAuthority(
                authority
            ))
            .is_err(),
            "returning Ok(StaleAuthority) would commit the preceding queue insert"
        );
        assert!(matches!(
            require_atomic_admission_outcome(AuthorityCommitWriteOutcome::Committed),
            Ok(AuthorityCommitWriteOutcome::Committed)
        ));
        assert!(matches!(
            require_atomic_admission_outcome(AuthorityCommitWriteOutcome::Duplicate),
            Ok(AuthorityCommitWriteOutcome::Duplicate)
        ));
    }

    #[test]
    fn duplicate_event_accepts_only_the_exact_realm_commit() {
        let existing = serde_json::json!({
            "commit_id":"ak:realm_commit:ARNRmzDi2r78zveOLmoHOb6AephFMwVuGE1fwXmCoeo4",
            "stream_position":7,
            "committed_at":"2026-09-21T00:00:00Z"
        });
        assert!(require_exact_commit_replay(&existing, &existing).is_ok());

        let divergent = serde_json::json!({
            "commit_id":"ak:realm_commit:ARNRmzDi2r78zveOLmoHOb6AephFMwVuGE1fwXmCoeo4",
            "stream_position":7,
            "committed_at":"2026-09-21T00:00:01Z"
        });
        assert!(matches!(
            require_exact_commit_replay(&existing, &divergent),
            Err(PersistenceError::Conflict(reason))
                if reason.starts_with("duplicate_conflict:")
        ));
    }
}
