use diesel::sql_types::{Bool, SmallInt};
use serde::de::DeserializeOwned;
use soland_storage::{
    AcceptedDeviceAuthorizationOutcome, AuthorityCommitStore, AuthorityCommitTransaction,
    AuthorityCommitWriteOutcome, CurrentRealmAuthority, ForwardAttemptRecord, ForwardAttemptStatus,
    OrdinaryRealmBootstrapCommitOutcome, OrdinaryRealmBootstrapCommitUnit, PcrGenesisCommitOutcome,
    PcrGenesisCommitUnit, QueuedEventRecord, QueuedEventStatus, SelfProducerCommitGuard,
};

use super::{
    AsyncConnection, AsyncPgConnection, BigInt, Binary, Jsonb, Nullable, OptionalExtension,
    PersistenceError, PersistenceResult, PgPool, PgTransactionError, QueryableByName, RunQueryDsl,
    Text, Timestamptz, Value, async_trait, ids, pg_conn, sql_query,
};
use crate::agent_current_results::lock_agent_producer_current;
use crate::capability_grant_current_results::{
    commit_capability_grant_current_result_in_connection,
    commit_realm_authority_root_current_result_in_connection,
};

pub(crate) mod replica;

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
    #[diesel(sql_type = Nullable<Text>)]
    forward_status: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    forward_reason_code: Option<String>,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    forward_attempted_at: Option<chrono::DateTime<chrono::Utc>>,
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
struct OrdinaryBootstrapUnitRow {
    #[diesel(sql_type = Text)]
    idempotency_key: String,
    #[diesel(sql_type = Binary)]
    exact_request_body: Vec<u8>,
    #[diesel(sql_type = Jsonb)]
    commits_json: Value,
}

#[derive(QueryableByName)]
struct PcrGenesisUnitRow {
    #[diesel(sql_type = Text)]
    realm_id: String,
    #[diesel(sql_type = Text)]
    idempotency_key: String,
    #[diesel(sql_type = Binary)]
    exact_request_body: Vec<u8>,
    #[diesel(sql_type = Jsonb)]
    result_json: Value,
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
struct SnapshotCurrentRow {
    #[diesel(sql_type = Text)]
    selector_kind: String,
    #[diesel(sql_type = Nullable<Jsonb>)]
    selector_subject: Option<Value>,
    #[diesel(sql_type = Text)]
    current_commit_id: String,
    #[diesel(sql_type = BigInt)]
    current_stream_position: i64,
    #[diesel(sql_type = Jsonb)]
    value: Value,
    #[diesel(sql_type = Nullable<Jsonb>)]
    source_stream_ref: Option<Value>,
}

#[derive(QueryableByName)]
struct MimiRoomBindingCurrentRow {
    #[diesel(sql_type = Text)]
    mimi_room_uri: String,
    #[diesel(sql_type = Text)]
    realm_id: String,
    #[diesel(sql_type = Text)]
    current_commit_id: String,
    #[diesel(sql_type = BigInt)]
    current_stream_position: i64,
    #[diesel(sql_type = Text)]
    current_event_id: String,
    #[diesel(sql_type = Jsonb)]
    value: Value,
}

fn decode_mimi_room_binding_current(
    row: MimiRoomBindingCurrentRow,
) -> PersistenceResult<soland_storage::MimiRoomBindingCurrentRecord> {
    let selector = arkret_wire::CurrentSelector::MimiRoomBinding {
        mimi_room_uri: arkret_wire::MimiRoomUri::new(row.mimi_room_uri)
            .map_err(|error| PersistenceError::Internal(error.to_string()))?,
    };
    let current =
        arkret_models_collaboration::events_payloads::mimi::MimiRoomBindingCurrentResult {
            selector,
            revision: arkret_wire::CurrentRevision {
                commit_id: decode_text(row.current_commit_id, "MIMI current RealmCommit id")?,
                stream_position: to_u64(
                    row.current_stream_position,
                    "MIMI current stream position",
                )?,
            },
            value: decode_json(row.value, "MIMI current binding payload")?,
        };
    current
        .validate()
        .map_err(|error| PersistenceError::Internal(error.to_string()))?;
    Ok(soland_storage::MimiRoomBindingCurrentRecord {
        current,
        source_event_id: decode_text(row.current_event_id, "MIMI current source Event id")?,
        realm_id: decode_text(row.realm_id, "MIMI current Realm id")?,
    })
}

fn invalid_mimi_migration() -> PersistenceError {
    PersistenceError::Conflict(
        soland_storage::ConflictCode::MimiRoomBindingMigrationProofInvalid.to_string(),
    )
}

fn mimi_migration_topology_matches(left: &Value, right: &Value) -> bool {
    [
        "hub_provider_id",
        "follower_provider_ids",
        "local_provider_role",
        "mls_group_id",
    ]
    .iter()
    .all(|field| left.get(*field) == right.get(*field))
}

async fn verify_mimi_migration_in_connection(
    conn: &mut AsyncPgConnection,
    payload: &arkret_models_collaboration::events_payloads::mimi::MimiRoomBindingPayload,
    value: &Value,
    previous: &MimiRoomBindingCurrentRow,
) -> PersistenceResult<()> {
    use arkret_models_collaboration::events_payloads::mimi::MimiRoomBindingMigrationOutcome;

    let proof = payload
        .migration_proof
        .as_ref()
        .ok_or_else(invalid_mimi_migration)?;
    let outcome = payload
        .migration_outcome
        .ok_or_else(invalid_mimi_migration)?;
    if previous.current_event_id != proof.migrating_event_id.as_str()
        || previous.current_commit_id != proof.migrating_commit_id.as_str()
        || previous.realm_id != payload.binding_scope.realm_id.as_str()
    {
        return Err(invalid_mimi_migration());
    }
    let migrating_row = sql_query(
        "SELECT c.commit_json, e.envelope FROM realm_commits c \
         JOIN canonical_events e ON e.pk=c.event_pk WHERE c.commit_id=$1 FOR UPDATE",
    )
    .bind::<Text, _>(proof.migrating_commit_id.as_str())
    .get_result::<CommitStreamRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?
    .ok_or_else(invalid_mimi_migration)?;
    let migrating_commit: arkret_wire::RealmCommit =
        decode_json(migrating_row.commit_json, "MIMI migrating RealmCommit")?;
    let migrating_event: arkret_wire::Event =
        decode_json(migrating_row.envelope, "MIMI migrating Event")?;
    if migrating_commit.commit_id != proof.migrating_commit_id
        || migrating_commit.event_ref != proof.migrating_event_id
        || migrating_event.event_id != proof.migrating_event_id
        || migrating_event.kind != arkret_wire::EventKind::MimiRoomBinding
        || migrating_commit.realm_id != payload.binding_scope.realm_id
        || migrating_event.realm_id != payload.binding_scope.realm_id
        || migrating_commit.stream_position
            != u64::try_from(previous.current_stream_position)
                .map_err(|_| invalid_mimi_migration())?
    {
        return Err(invalid_mimi_migration());
    }
    let migrating_value =
        serde_json::to_value(&migrating_event.payload).map_err(PersistenceError::database)?;
    if migrating_value != previous.value
        || migrating_value.get("status").and_then(Value::as_str) != Some("migrating")
    {
        return Err(invalid_mimi_migration());
    }
    let prior_row = sql_query(
        "SELECT c.commit_json, e.envelope FROM realm_commits c \
         JOIN canonical_events e ON e.pk=c.event_pk \
         WHERE c.realm_id=$1 AND c.stream_ref=$2 AND c.stream_position<$3 \
           AND e.envelope->>'kind'='ak.mimi.room_binding' \
           AND e.envelope->'payload'->>'mimi_room_uri'=$4 \
         ORDER BY c.stream_position DESC LIMIT 1 FOR UPDATE",
    )
    .bind::<Text, _>(payload.binding_scope.realm_id.as_str())
    .bind::<Jsonb, _>(
        serde_json::to_value(&migrating_commit.stream_ref).map_err(PersistenceError::database)?,
    )
    .bind::<BigInt, _>(previous.current_stream_position)
    .bind::<Text, _>(payload.mimi_room_uri.as_str())
    .get_result::<CommitStreamRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?
    .ok_or_else(invalid_mimi_migration)?;
    let prior_commit: arkret_wire::RealmCommit =
        decode_json(prior_row.commit_json, "MIMI previous accepted RealmCommit")?;
    let prior_event: arkret_wire::Event =
        decode_json(prior_row.envelope, "MIMI previous accepted Event")?;
    if prior_commit.commit_id != proof.previous_accepted_commit_id
        || prior_commit.event_ref != proof.previous_accepted_event_id
        || prior_event.event_id != proof.previous_accepted_event_id
        || prior_event.kind != arkret_wire::EventKind::MimiRoomBinding
        || prior_commit.realm_id != payload.binding_scope.realm_id
        || prior_event.realm_id != payload.binding_scope.realm_id
        || prior_commit.stream_ref != migrating_commit.stream_ref
    {
        return Err(invalid_mimi_migration());
    }
    let prior_value =
        serde_json::to_value(&prior_event.payload).map_err(PersistenceError::database)?;
    if prior_value.get("status").and_then(Value::as_str) != Some("accepted") {
        return Err(invalid_mimi_migration());
    }
    for state in [&prior_value, &migrating_value] {
        for field in ["profile", "mimi_room_uri", "binding_scope"] {
            if state.get(field) != value.get(field) {
                return Err(invalid_mimi_migration());
            }
        }
    }
    let expected_topology = match outcome {
        MimiRoomBindingMigrationOutcome::Completed => &migrating_value,
        MimiRoomBindingMigrationOutcome::RolledBack => &prior_value,
    };
    if !mimi_migration_topology_matches(value, expected_topology) {
        return Err(invalid_mimi_migration());
    }
    if payload.mls_group_id.is_some() {
        // The accepted `mls_group` current carries no authenticated MIMI
        // GroupInfo. Until admission can pin that evidence to this
        // transaction, an encrypted-room migration cannot be finalized.
        return Err(invalid_mimi_migration());
    }
    Ok(())
}

async fn commit_mimi_room_binding_current_result_in_connection(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    commit: &arkret_wire::RealmCommit,
) -> PersistenceResult<()> {
    if event.kind != arkret_wire::EventKind::MimiRoomBinding {
        return Ok(());
    }
    let value = serde_json::to_value(&event.payload).map_err(PersistenceError::database)?;
    let payload: arkret_models_collaboration::events_payloads::mimi::MimiRoomBindingPayload =
        decode_json(value.clone(), "MIMI room binding Event payload")?;
    payload.validate_shape().map_err(invalid)?;
    if payload.binding_scope.realm_id != event.realm_id {
        return Err(PersistenceError::SchemaViolation(
            "MIMI room binding Realm does not match its Event".to_owned(),
        ));
    }
    let room_uri = payload.mimi_room_uri.as_str();
    let previous = sql_query(
        "SELECT mimi_room_uri,realm_id,current_commit_id,current_stream_position,current_event_id,value \
         FROM mimi_room_binding_current_results WHERE mimi_room_uri=$1 FOR UPDATE",
    )
    .bind::<Text, _>(room_uri)
    .get_result::<MimiRoomBindingCurrentRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?;
    let previous_status = previous
        .as_ref()
        .and_then(|row| row.value.get("status"))
        .and_then(Value::as_str);
    let next_status = value.get("status").and_then(Value::as_str);
    let allowed = matches!(
        (previous_status, next_status),
        (None, Some("proposed" | "accepted"))
            | (Some("proposed"), Some("accepted" | "revoked"))
            | (Some("accepted"), Some("migrating" | "revoked"))
            | (Some("migrating"), Some("accepted"))
            | (Some("migrating"), Some("revoked"))
    );
    if !allowed {
        return Err(PersistenceError::SchemaViolation(
            "mimi_room_binding_status_transition_invalid".to_owned(),
        ));
    }
    if previous_status == Some("migrating") && next_status == Some("accepted") {
        verify_mimi_migration_in_connection(
            conn,
            &payload,
            &value,
            previous.as_ref().ok_or_else(invalid_mimi_migration)?,
        )
        .await?;
    } else if payload.migration_outcome.is_some() || payload.migration_proof.is_some() {
        return Err(invalid_mimi_migration());
    }
    let stream_position = i64::try_from(commit.stream_position).map_err(|_| {
        PersistenceError::SchemaViolation("MIMI current stream position exceeds i64".to_owned())
    })?;
    sql_query(
        "INSERT INTO mimi_room_binding_current_results \
         (mimi_room_uri,realm_id,current_commit_id,current_stream_position,current_event_id,value,updated_at) \
         VALUES ($1,$2,$3,$4,$5,$6,$7) \
         ON CONFLICT (mimi_room_uri) DO UPDATE SET \
           realm_id=EXCLUDED.realm_id,current_commit_id=EXCLUDED.current_commit_id, \
           current_stream_position=EXCLUDED.current_stream_position, \
           current_event_id=EXCLUDED.current_event_id,value=EXCLUDED.value,updated_at=EXCLUDED.updated_at",
    )
    .bind::<Text, _>(room_uri)
    .bind::<Text, _>(event.realm_id.as_str())
    .bind::<Text, _>(commit.commit_id.as_str())
    .bind::<BigInt, _>(stream_position)
    .bind::<Text, _>(event.event_id.as_str())
    .bind::<Jsonb, _>(value)
    .bind::<Timestamptz, _>(commit.committed_at)
    .execute(&mut *conn)
    .await
    .map_err(PersistenceError::database)?;
    Ok(())
}

/// The head of every commit stream of one Realm, as a loose index scan over
/// `realm_commits_realm_stream_tail_idx`: one index probe per stream, never
/// a walk over the Realm's history or other Realms' streams. The row
/// comparisons keep each probe on the Realm-prefixed index.
pub(crate) const REALM_STREAM_HEADS_SQL: &str = "\
    WITH RECURSIVE stream_keys AS ( \
      (SELECT stream_key FROM realm_commits \
       WHERE (realm_id, stream_key) >= ($1, '') AND realm_id = $1 \
       ORDER BY realm_id, stream_key LIMIT 1) \
      UNION ALL \
      SELECT (SELECT next_row.stream_key FROM realm_commits next_row \
              WHERE (next_row.realm_id, next_row.stream_key) > ($1, stream_keys.stream_key) \
                AND next_row.realm_id = $1 \
              ORDER BY next_row.realm_id, next_row.stream_key LIMIT 1) \
      FROM stream_keys WHERE stream_keys.stream_key IS NOT NULL \
    ) \
    SELECT head.stream_ref, head.stream_position, head.commit_id \
    FROM stream_keys CROSS JOIN LATERAL ( \
      SELECT stream_ref, stream_position, commit_id FROM realm_commits \
      WHERE realm_id = $1 AND stream_key = stream_keys.stream_key \
      ORDER BY stream_position DESC LIMIT 1) head \
    WHERE stream_keys.stream_key IS NOT NULL";

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
struct StreamPageRow {
    #[diesel(sql_type = Jsonb)]
    commit_json: Value,
    #[diesel(sql_type = Nullable<Jsonb>)]
    envelope: Option<Value>,
}

#[derive(QueryableByName)]
struct PresenceRow {
    #[diesel(sql_type = Bool)]
    present: bool,
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

pub(crate) fn stream_key(stream_ref: &arkret_wire::CommitStreamRef) -> PersistenceResult<String> {
    String::from_utf8(
        arkret_canonical::canonical_json_bytes(stream_ref).map_err(PersistenceError::database)?,
    )
    .map_err(PersistenceError::database)
}

/// The oldest retained Commit of one stream.
pub(crate) const STREAM_FLOOR_SQL: &str = "SELECT commit_json FROM realm_commits \
     WHERE stream_key = $1 ORDER BY stream_position ASC LIMIT 1";
/// One keyset page toward newer Commits. A member Station's chain node has
/// no Event and is read as its Commit alone.
pub(crate) const STREAM_PAGE_AFTER_SQL: &str = "SELECT c.commit_json, e.envelope \
     FROM realm_commits c LEFT JOIN canonical_events e ON e.pk = c.event_pk \
     WHERE c.stream_key = $1 AND c.stream_position > $2 \
     ORDER BY c.stream_position ASC LIMIT $3";
/// One keyset page toward older Commits.
pub(crate) const STREAM_PAGE_BEFORE_SQL: &str = "SELECT c.commit_json, e.envelope \
     FROM realm_commits c LEFT JOIN canonical_events e ON e.pk = c.event_pk \
     WHERE c.stream_key = $1 AND c.stream_position < $2 \
     ORDER BY c.stream_position DESC LIMIT $3";
/// The newest page of one stream.
pub(crate) const STREAM_PAGE_NEWEST_SQL: &str = "SELECT c.commit_json, e.envelope \
     FROM realm_commits c LEFT JOIN canonical_events e ON e.pk = c.event_pk \
     WHERE c.stream_key = $1 ORDER BY c.stream_position DESC LIMIT $2";

/// One physical keyset page of a single commit stream on the caller's
/// connection (and therefore its read cut). This is not an authorization
/// decision; public callers go through the Account-scoped scan.
pub(crate) async fn stream_page_in_connection(
    conn: &mut AsyncPgConnection,
    request: &arkret_wire::StreamScanRequest,
) -> PersistenceResult<arkret_wire::StreamScanOutcome> {
    request.validate().map_err(invalid)?;
    let key = stream_key(&request.stream_ref)?;
    let floor = sql_query(STREAM_FLOOR_SQL)
        .bind::<Text, _>(&key)
        .get_result::<CommitRow>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?;
    let readable_floor = floor
        .map(|row| {
            let commit: arkret_wire::RealmCommit =
                decode_json(row.commit_json, "first RealmCommit")?;
            if commit.stream_position != 0 {
                return Err(invalid("stored stream has no genesis RealmCommit"));
            }
            Ok(arkret_wire::ReadableFloor {
                oldest_position: 0,
                floor_commit_id: commit.commit_id,
                floor_reason: arkret_wire::ReadableFloorReason::StreamStart,
            })
        })
        .transpose()?;
    stream_page_above_floor_in_connection(conn, request, readable_floor).await
}

/// One keyset page of a single commit stream bounded below by `floor`: no
/// Commit under `floor.oldest_position` is returned, and a page that stops
/// at the floor is not reported as truncated (`service-http-binding.md`
/// §3.1). The floor itself is the caller's decision; `None` means the stream
/// has no Commit yet.
pub(crate) async fn stream_page_above_floor_in_connection(
    conn: &mut AsyncPgConnection,
    request: &arkret_wire::StreamScanRequest,
    readable_floor: Option<arkret_wire::ReadableFloor>,
) -> PersistenceResult<arkret_wire::StreamScanOutcome> {
    request.validate().map_err(invalid)?;
    let key = stream_key(&request.stream_ref)?;
    let limit = i64::from(request.limit) + 1;
    let lowest = readable_floor
        .as_ref()
        .map(|floor| to_i64(floor.oldest_position, "readable floor"))
        .transpose()?
        .unwrap_or(0);
    let rows = match request.direction {
        arkret_wire::StreamScanDirection::After(after) => {
            let after = after
                .map(|position| to_i64(position, "stream cursor"))
                .transpose()?
                .unwrap_or(-1)
                .max(lowest - 1);
            sql_query(STREAM_PAGE_AFTER_SQL)
                .bind::<Text, _>(&key)
                .bind::<BigInt, _>(after)
                .bind::<BigInt, _>(limit)
                .load::<StreamPageRow>(&mut *conn)
                .await
        }
        arkret_wire::StreamScanDirection::Before(Some(before)) => {
            let before = to_i64(before, "stream cursor")?;
            sql_query(STREAM_PAGE_BEFORE_SQL)
                .bind::<Text, _>(&key)
                .bind::<BigInt, _>(before)
                .bind::<BigInt, _>(limit)
                .load::<StreamPageRow>(&mut *conn)
                .await
        }
        arkret_wire::StreamScanDirection::Before(None) => {
            sql_query(STREAM_PAGE_NEWEST_SQL)
                .bind::<Text, _>(&key)
                .bind::<BigInt, _>(limit)
                .load::<StreamPageRow>(&mut *conn)
                .await
        }
    }
    .map_err(PersistenceError::database)?;
    let committed_events = rows
        .into_iter()
        .map(|row| {
            let commit = decode_json(row.commit_json, "RealmCommit")?;
            Ok(match row.envelope {
                Some(envelope) => {
                    arkret_wire::CommittedEventView::Full(arkret_wire::CommittedEventFullView {
                        commit,
                        event: decode_json(envelope, "committed Event")?,
                    })
                }
                None => arkret_wire::CommittedEventView::Withheld(
                    arkret_wire::CommittedEventWithheldView {
                        commit,
                        event_disclosure: arkret_wire::EventDisclosure {
                            status: arkret_wire::EventDisclosureStatus::Withheld,
                        },
                    },
                ),
            })
        })
        .collect::<PersistenceResult<Vec<_>>>()?
        .into_iter()
        .filter(|item| {
            readable_floor
                .as_ref()
                .is_none_or(|floor| item.commit().stream_position >= floor.oldest_position)
        })
        .collect::<Vec<_>>();
    // Rows are ordered away from the cursor, so dropping those under the
    // floor keeps the page contiguous; one row beyond `limit` inside the
    // interval is what makes the page truncated.
    let truncated = committed_events.len() > usize::from(request.limit);
    let committed_events = committed_events
        .into_iter()
        .take(usize::from(request.limit))
        .collect();
    let outcome = arkret_wire::StreamScanOutcome {
        committed_events,
        readable_floor,
        truncated,
    };
    outcome.validate_for_request(request).map_err(invalid)?;
    Ok(outcome)
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

pub(crate) async fn realm_state_snapshot_material_in_connection(
    conn: &mut AsyncPgConnection,
    realm_id: &arkret_wire::RealmId,
) -> PersistenceResult<Option<soland_storage::RealmStateSnapshotMaterial>> {
    let authority = sql_query(
        "SELECT realm_id, generation, service_id, authority_ref, last_handoff_ref \
         FROM realm_authorities WHERE realm_id = $1",
    )
    .bind::<Text, _>(realm_id.as_str())
    .get_result::<AuthorityRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?
    .map(authority_from_row)
    .transpose()?;
    let Some(authority) = authority else {
        return Ok(None);
    };

    let rows = sql_query(REALM_STREAM_HEADS_SQL)
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

    let rows = sql_query(
        "SELECT result.*, covering.stream_ref AS source_stream_ref FROM ( \
         SELECT result_family AS selector_kind, NULL::jsonb AS selector_subject, \
                current_commit_id, current_stream_position, value \
           FROM realm_bootstrap_current_results WHERE realm_id = $1 \
         UNION ALL \
         SELECT 'realm_authority_root'::text AS selector_kind, NULL::jsonb AS selector_subject, \
                current_commit_id, current_stream_position, \
                jsonb_build_object('controller_actor_id',controller_actor_id, \
                    'controller_epoch',controller_epoch,'authority_generation',authority_generation) AS value \
           FROM realm_authority_root_current_results WHERE realm_id = $1 \
         UNION ALL \
         SELECT 'realm_policy_bundle'::text AS selector_kind, NULL::jsonb AS selector_subject, \
                current_commit_id, current_stream_position, value \
           FROM realm_policy_bundle_current_results WHERE realm_id = $1 \
         UNION ALL \
         SELECT 'member_state'::text AS selector_kind, member_id::jsonb AS selector_subject, \
                current_commit_id, current_stream_position, value \
           FROM member_state_current_results WHERE realm_id = $1 \
         UNION ALL \
         SELECT 'strand'::text AS selector_kind, to_jsonb(strand_id) AS selector_subject, \
                current_commit_id, current_stream_position, value \
           FROM strand_current_results WHERE realm_id = $1 \
         UNION ALL \
         SELECT 'realm_set_default_strand'::text AS selector_kind, NULL::jsonb AS selector_subject, \
                current_commit_id, current_stream_position, value \
           FROM realm_set_default_strand_current_results WHERE realm_id = $1 \
         UNION ALL \
         SELECT 'message_revision'::text AS selector_kind, to_jsonb(message_id) AS selector_subject, \
                current_commit_id, current_stream_position, value \
           FROM message_revision_current_results WHERE realm_id = $1 \
         UNION ALL \
         SELECT 'mls_group'::text AS selector_kind, value->'effective_scope' AS selector_subject, \
                current_commit_id, current_stream_position, value \
           FROM mls_group_current_results WHERE realm_id = $1 \
         UNION ALL \
         SELECT 'moderation_report'::text AS selector_kind, to_jsonb(report_event_id) AS selector_subject, \
                current_commit_id, current_stream_position, value \
           FROM moderation_report_current_results WHERE realm_id = $1 \
         UNION ALL \
         SELECT 'moderation_state'::text AS selector_kind, to_jsonb(target_ref) AS selector_subject, \
                current_commit_id, current_stream_position, value \
           FROM moderation_state_current_results WHERE realm_id = $1 \
         UNION ALL \
         SELECT 'object_redaction'::text AS selector_kind, to_jsonb(target_ref) AS selector_subject, \
                current_commit_id, current_stream_position, value \
           FROM object_redaction_current_results WHERE realm_id = $1 \
         UNION ALL \
         SELECT 'invite_lifecycle'::text AS selector_kind, to_jsonb(invite_id) AS selector_subject, \
                current_commit_id, current_stream_position, value \
           FROM invite_lifecycle_current_results WHERE realm_id = $1 \
         UNION ALL \
         SELECT 'invite_live_target'::text AS selector_kind, invitee_account_id::jsonb AS selector_subject, \
                current_commit_id, current_stream_position, value \
           FROM invite_live_target_current_results WHERE realm_id = $1 \
         UNION ALL \
         SELECT 'invite_directed_invitee'::text AS selector_kind, to_jsonb(invite_id) AS selector_subject, \
                current_commit_id, current_stream_position, value \
           FROM invite_directed_invitee_current_results WHERE realm_id = $1 \
         UNION ALL \
         SELECT 'capability_grant'::text AS selector_kind, to_jsonb(grant_id) AS selector_subject, \
                current_commit_id, current_stream_position, value \
           FROM capability_grant_current_results WHERE realm_id = $1 \
         UNION ALL \
         SELECT 'mimi_room_binding'::text AS selector_kind, to_jsonb(mimi_room_uri) AS selector_subject, \
                current_commit_id, current_stream_position, value \
           FROM mimi_room_binding_current_results WHERE realm_id = $1 \
         UNION ALL \
         SELECT 'agent_status'::text AS selector_kind, to_jsonb(agent_id) AS selector_subject, \
                current_commit_id, current_stream_position, value \
           FROM agent_status_current_results WHERE realm_id = $1 \
         UNION ALL \
         SELECT 'agent_key'::text AS selector_kind, jsonb_build_object('agent_id',agent_id,'agent_key_id',agent_key_id) AS selector_subject, \
                current_commit_id, current_stream_position, value \
           FROM agent_key_current_results WHERE realm_id = $1 \
         ) result LEFT JOIN realm_commits covering \
           ON covering.commit_id=result.current_commit_id \
          AND covering.stream_position=result.current_stream_position \
          AND covering.realm_id=$1",
    )
    .bind::<Text, _>(realm_id.as_str())
    .load::<SnapshotCurrentRow>(&mut *conn)
    .await
    .map_err(PersistenceError::database)?;
    let current_state_entries = rows
        .into_iter()
        .map(|row| {
            let selector = match (row.selector_kind.as_str(), row.selector_subject) {
                ("realm_genesis", None) => arkret_wire::CurrentSelector::RealmGenesis,
                ("realm_authority_root", None) => arkret_wire::CurrentSelector::RealmAuthorityRoot,
                ("realm_profile", None) => arkret_wire::CurrentSelector::RealmProfile,
                ("realm_policy_bundle", None) => arkret_wire::CurrentSelector::RealmPolicyBundle,
                ("realm_join_rule", None) => arkret_wire::CurrentSelector::RealmJoinRule,
                ("realm_history_access", None) => arkret_wire::CurrentSelector::RealmHistoryAccess,
                ("realm_discovery", None) => arkret_wire::CurrentSelector::RealmDiscovery,
                ("realm_alias", None) => arkret_wire::CurrentSelector::RealmAlias,
                ("realm_plaintext_visible_services", None) => {
                    arkret_wire::CurrentSelector::RealmPlaintextVisibleServices
                }
                ("realm_set_default_strand", None) => {
                    arkret_wire::CurrentSelector::RealmSetDefaultStrand
                }
                ("member_state", Some(actor_id)) => arkret_wire::CurrentSelector::MemberState {
                    actor_id: serde_json::from_value(actor_id).map_err(|error| {
                        PersistenceError::Internal(format!(
                            "stored snapshot member actor id is invalid: {error}"
                        ))
                    })?,
                },
                ("strand", Some(strand_id)) => arkret_wire::CurrentSelector::Strand {
                    strand_id: serde_json::from_value(strand_id).map_err(|error| {
                        PersistenceError::Internal(format!(
                            "stored Strand selector identity is invalid: {error}"
                        ))
                    })?,
                },
                ("message_revision", Some(message_id)) => {
                    arkret_wire::CurrentSelector::MessageRevision {
                        message_id: serde_json::from_value(message_id).map_err(|error| {
                            PersistenceError::Internal(format!(
                                "stored Message revision selector identity is invalid: {error}"
                            ))
                        })?,
                    }
                }
                ("mls_group", Some(scope_ref)) => arkret_wire::CurrentSelector::MlsGroup {
                    scope_ref: serde_json::from_value(scope_ref).map_err(|error| {
                        PersistenceError::Internal(format!(
                            "stored mls_group scope is invalid: {error}"
                        ))
                    })?,
                },
                ("moderation_report", Some(event_id)) => {
                    arkret_wire::CurrentSelector::ModerationReport {
                        event_id: serde_json::from_value(event_id).map_err(|error| {
                            PersistenceError::Internal(format!(
                                "stored moderation report selector identity is invalid: {error}"
                            ))
                        })?,
                    }
                }
                ("moderation_state", Some(target_ref)) => {
                    arkret_wire::CurrentSelector::ModerationState {
                        target_ref: serde_json::from_value(target_ref).map_err(|error| {
                            PersistenceError::Internal(format!(
                                "stored moderation_state target is invalid: {error}"
                            ))
                        })?,
                    }
                }
                ("object_redaction", Some(target_ref)) => {
                    arkret_wire::CurrentSelector::ObjectRedaction {
                        target_ref: serde_json::from_value(target_ref).map_err(|error| {
                            PersistenceError::Internal(format!(
                                "stored object_redaction target is invalid: {error}"
                            ))
                        })?,
                    }
                }
                ("invite_lifecycle", Some(invite_id)) => {
                    arkret_wire::CurrentSelector::InviteLifecycle {
                        invite_id: serde_json::from_value(invite_id).map_err(|error| {
                            PersistenceError::Internal(format!(
                                "stored invite_lifecycle selector identity is invalid: {error}"
                            ))
                        })?,
                    }
                }
                ("invite_live_target", Some(invitee_account_id)) => {
                    arkret_wire::CurrentSelector::InviteLiveTarget {
                        invitee_account_id: serde_json::from_value(invitee_account_id).map_err(
                            |error| {
                                PersistenceError::Internal(format!(
                                    "stored invite_live_target selector identity is invalid: {error}"
                                ))
                            },
                        )?,
                    }
                }
                ("invite_directed_invitee", Some(invite_id)) => {
                    arkret_wire::CurrentSelector::InviteDirectedInvitee {
                        invite_id: serde_json::from_value(invite_id).map_err(|error| {
                            PersistenceError::Internal(format!(
                                "stored invite_directed_invitee selector identity is invalid: {error}"
                            ))
                        })?,
                    }
                }
                ("capability_grant", Some(grant_id)) => {
                    arkret_wire::CurrentSelector::CapabilityGrant {
                        grant_id: serde_json::from_value(grant_id).map_err(|error| {
                            PersistenceError::Internal(format!(
                                "stored capability_grant selector identity is invalid: {error}"
                            ))
                        })?,
                    }
                }
                ("mimi_room_binding", Some(room_uri)) => {
                    arkret_wire::CurrentSelector::MimiRoomBinding {
                        mimi_room_uri: arkret_wire::MimiRoomUri::new(
                            room_uri.as_str().ok_or_else(|| {
                                PersistenceError::Internal(
                                    "stored MIMI room URI is not a string".to_owned(),
                                )
                            })?,
                        )
                        .map_err(|error| {
                            PersistenceError::Internal(format!(
                                "stored snapshot MIMI room URI is invalid: {error}"
                            ))
                        })?,
                    }
                }
                ("agent_status", Some(agent_id)) => arkret_wire::CurrentSelector::AgentStatus {
                    agent_id: serde_json::from_value(agent_id).map_err(|error| {
                        PersistenceError::Internal(format!(
                            "stored Agent status identity is invalid: {error}"
                        ))
                    })?,
                },
                ("agent_key", Some(subject)) => {
                    let mut selector = subject
                        .as_object()
                        .ok_or_else(|| {
                            PersistenceError::Internal(
                                "stored Agent key selector is invalid".to_owned(),
                            )
                        })?
                        .clone();
                    selector.insert("kind".to_owned(), Value::String("agent_key".to_owned()));
                    serde_json::from_value(Value::Object(selector)).map_err(|error| {
                        PersistenceError::Internal(format!(
                            "stored Agent key selector is invalid: {error}"
                        ))
                    })?
                }
                _ => {
                    return Err(PersistenceError::Internal(
                        "stored snapshot current selector is invalid".to_owned(),
                    ));
                }
            };
            Ok(arkret_wire::TypedCurrentResult::Value {
                selector,
                source_stream_ref: decode_json(
                    row.source_stream_ref.ok_or_else(|| {
                        PersistenceError::Internal(
                            "snapshot current result has no covering RealmCommit".to_owned(),
                        )
                    })?,
                    "current source stream ref",
                )?,
                revision: arkret_wire::CurrentRevision {
                    commit_id: decode_text(row.current_commit_id, "current RealmCommit id")?,
                    stream_position: to_u64(
                        row.current_stream_position,
                        "current stream position",
                    )?,
                },
                value: row.value,
            })
        })
        .collect::<PersistenceResult<Vec<_>>>()?;
    let mut keyed_entries = current_state_entries
        .into_iter()
        .map(|entry| {
            let key = arkret_canonical::canonical_json_bytes(&entry)
                .map_err(PersistenceError::database)?;
            Ok((key, entry))
        })
        .collect::<PersistenceResult<Vec<_>>>()?;
    keyed_entries.sort_by(|left, right| left.0.cmp(&right.0));
    let current_state_entries: Vec<_> = keyed_entries.into_iter().map(|(_, entry)| entry).collect();
    let history_access = current_state_entries
        .iter()
        .find_map(|entry| match entry {
            arkret_wire::TypedCurrentResult::Value {
                selector: arkret_wire::CurrentSelector::RealmHistoryAccess,
                value,
                ..
            } => Some(value),
            _ => None,
        })
        .map(|value| {
            serde_json::from_value::<arkret_wire::HistoryAccess>(value.clone()).map_err(|error| {
                PersistenceError::Internal(format!(
                    "stored Realm history access is invalid: {error}"
                ))
            })
        })
        .transpose()?
        .unwrap_or(arkret_wire::HistoryAccess::AllHistoryForCurrentMembers);
    let stream_floors = heads
        .iter()
        .map(|head| arkret_wire::StreamHistoryFloor {
            stream_ref: head.stream_ref.clone(),
            oldest_position: 0,
        })
        .collect();
    Ok(Some(soland_storage::RealmStateSnapshotMaterial {
        realm_id: realm_id.clone(),
        governance_generation: authority.generation,
        visible_stream_heads: heads,
        current_state_entries,
        retention_and_history_floor: arkret_wire::RetentionAndHistoryFloor {
            history_access,
            stream_floors,
        },
    }))
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
    let realm_pk = crate::realm_identity::ensure_realm_pk(conn, event.realm_id.as_str()).await?;
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
         (id, digest_suite, digest, actor_id, realm_id, realm_pk, scope_ref, kind, canonical_bytes, envelope, state, received_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, 'queued', $11)",
    )
    .bind::<Binary, _>(token.to_vec())
    .bind::<SmallInt, _>(digest_suite)
    .bind::<Binary, _>(token[1..].to_vec())
    .bind::<Text, _>(event.actor_id.to_string())
    .bind::<Text, _>(event.realm_id.as_str())
    .bind::<BigInt, _>(realm_pk)
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
    commit_transaction_in_connection_with_device_guard(conn, transaction, VerifiedPcrUnit::None)
        .await
}

/// Only the registered PCR genesis, recovery and accepted-device UoWs may
/// call this after they validate the Event/Commit and its authority proof.
pub(crate) async fn commit_verified_pcr_device_transaction_in_connection(
    conn: &mut AsyncPgConnection,
    transaction: &AuthorityCommitTransaction,
) -> Result<AuthorityCommitWriteOutcome, PgTransactionError> {
    commit_transaction_in_connection_with_device_guard(conn, transaction, VerifiedPcrUnit::Device)
        .await
}

/// Only the SecurityRotation proposal unit may call this after rechecking the
/// authorizing device against the typed PCR current cut under authority lock.
pub(crate) async fn commit_verified_pcr_revoke_proposal_in_connection(
    conn: &mut AsyncPgConnection,
    transaction: &AuthorityCommitTransaction,
) -> Result<AuthorityCommitWriteOutcome, PgTransactionError> {
    commit_transaction_in_connection_with_device_guard(
        conn,
        transaction,
        VerifiedPcrUnit::RevokeProposal,
    )
    .await
}

/// Only the KeyBackup pointer unit may call this after rechecking the signing
/// device, generation, source checkpoint and record signature under the PCR
/// authority lock; the same transaction then projects the pointer and marker.
pub(crate) async fn commit_verified_key_backup_pointer_in_connection(
    conn: &mut AsyncPgConnection,
    transaction: &AuthorityCommitTransaction,
) -> Result<AuthorityCommitWriteOutcome, PgTransactionError> {
    commit_transaction_in_connection_with_device_guard(
        conn,
        transaction,
        VerifiedPcrUnit::KeyBackupPointer,
    )
    .await
}

/// Only the recovery policy publication unit may call this after rechecking
/// the signing device, the version ratchet and the policy signature under the
/// PCR authority lock; the same transaction then records the accepted policy.
pub(crate) async fn commit_verified_recovery_policy_in_connection(
    conn: &mut AsyncPgConnection,
    transaction: &AuthorityCommitTransaction,
) -> Result<AuthorityCommitWriteOutcome, PgTransactionError> {
    commit_transaction_in_connection_with_device_guard(
        conn,
        transaction,
        VerifiedPcrUnit::RecoveryPolicy,
    )
    .await
}

/// Only the Agent provision unit may call this after rechecking the signing
/// device, the envelope binding and both declarations under the controller
/// PCR authority lock; the same transaction then writes the four results.
pub(crate) async fn commit_verified_agent_provision_in_connection(
    conn: &mut AsyncPgConnection,
    transaction: &AuthorityCommitTransaction,
) -> Result<AuthorityCommitWriteOutcome, PgTransactionError> {
    commit_transaction_in_connection_with_device_guard(
        conn,
        transaction,
        VerifiedPcrUnit::AgentProvision,
    )
    .await
}

/// Only the Agent control unit may call this after the provision binding,
/// the controller device cut and the kind's gate under the Agent PCR lock.
pub(crate) async fn commit_verified_agent_control_in_connection(
    conn: &mut AsyncPgConnection,
    transaction: &AuthorityCommitTransaction,
) -> Result<AuthorityCommitWriteOutcome, PgTransactionError> {
    commit_transaction_in_connection_with_device_guard(
        conn,
        transaction,
        VerifiedPcrUnit::AgentControl,
    )
    .await
}

/// Only the Agent PCR genesis unit may call this after the provision
/// declaration reverse lookup and the controller device cut.
pub(crate) async fn commit_verified_agent_pcr_genesis_in_connection(
    conn: &mut AsyncPgConnection,
    transaction: &AuthorityCommitTransaction,
) -> Result<AuthorityCommitWriteOutcome, PgTransactionError> {
    commit_transaction_in_connection_with_device_guard(
        conn,
        transaction,
        VerifiedPcrUnit::AgentPcrGenesis,
    )
    .await
}

/// Only the Actor Profile and accountability grant units may call this after
/// rechecking the signing device and the kind's same-cut admission under the
/// PCR authority lock; the same transaction then writes the typed result.
pub(crate) async fn commit_verified_pcr_typed_current_in_connection(
    conn: &mut AsyncPgConnection,
    transaction: &AuthorityCommitTransaction,
) -> Result<AuthorityCommitWriteOutcome, PgTransactionError> {
    commit_transaction_in_connection_with_device_guard(
        conn,
        transaction,
        VerifiedPcrUnit::ProfileOrAccountability,
    )
    .await
}

/// The registered PCR unit whose same-cut checks already ran on this
/// connection. Generic admission is `None` and cannot write these kinds.
#[derive(Clone, Copy, PartialEq, Eq)]
enum VerifiedPcrUnit {
    None,
    Device,
    RevokeProposal,
    KeyBackupPointer,
    RecoveryPolicy,
    ProfileOrAccountability,
    AgentProvision,
    AgentPcrGenesis,
    AgentControl,
}

fn is_agent_pcr_genesis(event: &arkret_wire::Event) -> bool {
    event.kind == arkret_wire::EventKind::RealmCreate
        && event
            .payload
            .get("object")
            .and_then(|object| object.get("purpose"))
            .and_then(serde_json::Value::as_str)
            == Some("agent_control")
}

fn is_recovery_policy_set(event: &arkret_wire::Event) -> bool {
    event.kind == arkret_wire::EventKind::PolicySet
        && event
            .payload
            .get("value")
            .and_then(|value| value.get("schema"))
            .and_then(serde_json::Value::as_str)
            == Some(arkret_wire::SchemaId::RECOVERY_POLICY_V1)
}

async fn commit_transaction_in_connection_with_device_guard(
    conn: &mut AsyncPgConnection,
    transaction: &AuthorityCommitTransaction,
    verified_unit: VerifiedPcrUnit,
) -> Result<AuthorityCommitWriteOutcome, PgTransactionError> {
    let verified_pcr_device_unit = verified_unit == VerifiedPcrUnit::Device;
    let verified_pcr_revoke_unit = verified_unit == VerifiedPcrUnit::RevokeProposal;
    // The pointer's own signature, accepted device authorization, current
    // generation and source checkpoint are rechecked only by the registered
    // pointer unit; generic Event admission must not publish an unchecked
    // pointer.
    if transaction.event.kind == arkret_wire::EventKind::KeyBackupActiveSeries
        && verified_unit != VerifiedPcrUnit::KeyBackupPointer
    {
        return Err(PersistenceError::Conflict(
            "key_backup_active_series_current_device_authority_unavailable".to_owned(),
        )
        .into());
    }
    // A recovery policy is PCR control state; only its publication unit, which
    // records the accepted policy in the same transaction, may commit it.
    if is_recovery_policy_set(&transaction.event)
        && verified_unit != VerifiedPcrUnit::RecoveryPolicy
    {
        return Err(PersistenceError::Conflict(
            "recovery_policy_publication_unit_required".to_owned(),
        )
        .into());
    }
    // Profile and accountability results are PCR typed current written only
    // by their units, which decide the signer and the accountability cut.
    if matches!(
        transaction.event.kind,
        arkret_wire::EventKind::ProfileCreate
            | arkret_wire::EventKind::ProfileUpdate
            | arkret_wire::EventKind::IdentityAccountabilityGrant
    ) && verified_unit != VerifiedPcrUnit::ProfileOrAccountability
    {
        return Err(PersistenceError::Conflict(
            "actor_profile_or_accountability_unit_required".to_owned(),
        )
        .into());
    }
    // An Agent PCR genesis is admitted only by the unit that reverse-looks-up
    // its accepted provision declaration (key-management.md section 3.6.3).
    if is_agent_pcr_genesis(&transaction.event) && verified_unit != VerifiedPcrUnit::AgentPcrGenesis
    {
        return Err(
            PersistenceError::Conflict("agent_pcr_genesis_unit_required".to_owned()).into(),
        );
    }
    // Agent key and lifecycle Events decide the controller delegation and
    // the Agent's current key set and lifecycle at one Agent PCR cut; only
    // their unit may commit them.
    if crate::agent_control::is_agent_control_kind(&transaction.event.kind)
        && verified_unit != VerifiedPcrUnit::AgentControl
    {
        return Err(PersistenceError::Conflict("agent_control_unit_required".to_owned()).into());
    }
    // ak.agent.provision projects four typed results atomically
    // (key-management.md section 3.6.3); only its unit writes that set.
    if transaction.event.kind == arkret_wire::EventKind::AgentProvision
        && verified_unit != VerifiedPcrUnit::AgentProvision
    {
        return Err(
            PersistenceError::Conflict("agent_provision_atomic_unit_required".to_owned()).into(),
        );
    }
    // No registered atomic revoke UoW yet writes the immutable proposal dot
    // and covering command result. Do not accept an Event that read-side
    // device status cannot fold at the same authority cut.
    if transaction.event.kind == arkret_wire::EventKind::DeviceRevoke && !verified_pcr_revoke_unit {
        return Err(PersistenceError::Conflict(
            "pcr_device_revocation_current_authority_unavailable".to_owned(),
        )
        .into());
    }
    if matches!(
        transaction.event.kind,
        arkret_wire::EventKind::DeviceAuthorize | arkret_wire::EventKind::DeviceReanchor
    ) && !verified_pcr_device_unit
    {
        return Err(PersistenceError::Conflict(
            "pcr_device_current_authority_unavailable".to_owned(),
        )
        .into());
    }
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
            // The Station assigns the order (authority-commit-log.md §2/§4):
            // another Commit won this stream after the candidate was built on
            // an older head. Nothing is committed and the exact Event may be
            // retried, so this is `retryable_unavailable`, never a schema fault.
            if previous_commit.stream_ref == transaction.commit.stream_ref
                && previous_commit.stream_position >= transaction.commit.stream_position
            {
                return Err(PersistenceError::Conflict(format!(
                    "{}: stream head advanced to position {} before this RealmCommit",
                    soland_storage::ConflictCode::TemporarilyUnavailable.as_str(),
                    previous_commit.stream_position
                ))
                .into());
            }
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
    Ok(AuthorityCommitWriteOutcome::Committed)
}

#[cfg(any(test, feature = "test-support"))]
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

#[derive(QueryableByName)]
struct ProducerCurrentValueRow {
    #[diesel(sql_type = Jsonb)]
    value: Value,
}

#[derive(QueryableByName)]
struct ProducerAuthorizationRow {
    #[diesel(sql_type = Jsonb)]
    envelope: Value,
    #[diesel(sql_type = Jsonb)]
    commit_json: Value,
}

pub(crate) async fn check_self_producer_guard_in_connection(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    guard: &SelfProducerCommitGuard,
    committed_at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<()> {
    let actor = event.actor_id.as_account_id().ok_or_else(|| {
        PersistenceError::Conflict("self Event producer is not an account".to_owned())
    })?;
    let method = &event
        .producer_proof
        .as_ref()
        .ok_or_else(|| {
            PersistenceError::Conflict("self Event producer proof is missing".to_owned())
        })?
        .verification_method;
    if event.executed_by.is_some() {
        return Err(PersistenceError::Conflict(
            "self Event cannot delegate its producer".to_owned(),
        ));
    }
    match guard {
        SelfProducerCommitGuard::HumanDevice(selector) => {
            if selector.principal_id != actor.principal_id
                || selector.station_id != actor.station_id
                || !method
                    .as_str()
                    .ends_with(&format!("#{}", selector.device_id))
            {
                return Err(PersistenceError::Conflict(
                    "self Event device guard differs from producer".to_owned(),
                ));
            }
            crate::ensure_gate_allowed_in_transaction(conn, selector).await
        }
        SelfProducerCommitGuard::Agent {
            pcr_realm_id,
            agent_id,
            authorization_ref,
            verification_method,
        } => {
            if agent_id != &actor.principal_id || verification_method != method {
                return Err(PersistenceError::Conflict(
                    "self Event Agent guard differs from producer".to_owned(),
                ));
            }
            // encryption-and-audit.md §2.5.2: an Agent runtime whose authorize
            // is revoked, replaced or expired at this cut is refused with the
            // universal `capability_denied`.
            check_agent_endpoint_current_in_connection(
                conn,
                pcr_realm_id,
                agent_id,
                authorization_ref,
                verification_method,
                committed_at,
            )
            .await
            .map_err(|error| match error {
                PersistenceError::Conflict(detail)
                    if soland_storage::ConflictCode::from_detail(&detail).is_none() =>
                {
                    PersistenceError::Conflict(format!(
                        "{}: {detail}",
                        soland_storage::ConflictCode::CapabilityDenied
                    ))
                }
                other => other,
            })
        }
    }
}

/// Recheck, inside the caller's transaction, that `authorization_ref` is the
/// Agent's committed `ak.agent.key_authorize` and still its single active
/// current key for `verification_method` at `committed_at`, with the Agent
/// active.
/// Shared by Agent-produced Events and Agent-sent DeviceMessages.
pub(crate) async fn check_agent_endpoint_current_in_connection(
    conn: &mut AsyncPgConnection,
    pcr_realm_id: &arkret_wire::RealmId,
    agent_id: &arkret_wire::DidCoreId,
    authorization_ref: &arkret_wire::CommittedEventRef,
    verification_method: &arkret_wire::DidUrl,
    committed_at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<()> {
    let method = verification_method;
    if authorization_ref.stream_ref.realm_id() != pcr_realm_id {
        return Err(PersistenceError::Conflict(
            "Agent guard authorization is outside its PCR Realm".to_owned(),
        ));
    }
    let authorization = sql_query(
        "SELECT e.envelope,c.commit_json FROM canonical_events e \
         JOIN realm_commits c ON c.event_pk=e.pk \
         WHERE e.id=$1 AND e.state='committed'",
    )
    .bind::<Binary, _>(
        ids::parse_event_id(authorization_ref.event_id.as_str())
            .ok_or_else(|| invalid("Agent authorization Event id is invalid"))?
            .to_vec(),
    )
    .get_result::<ProducerAuthorizationRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?
    .ok_or_else(|| {
        PersistenceError::Conflict("Agent authorization Event is not committed".to_owned())
    })?;
    let source_event: arkret_wire::Event =
        decode_json(authorization.envelope, "Agent authorization Event")?;
    let source_commit: arkret_wire::RealmCommit =
        decode_json(authorization.commit_json, "Agent authorization Commit")?;
    if source_event.kind != arkret_wire::EventKind::AgentKeyAuthorize
        || source_event.event_id != authorization_ref.event_id
        || source_event.realm_id != *pcr_realm_id
        || source_commit.event_ref != authorization_ref.event_id
        || source_commit.commit_id != authorization_ref.commit_id
        || source_commit.stream_ref != authorization_ref.stream_ref
        || source_commit.stream_position != authorization_ref.stream_position
    {
        return Err(PersistenceError::Conflict(
            "Agent authorization Commit differs from guarded source".to_owned(),
        ));
    }
    lock_agent_producer_current(conn, pcr_realm_id, agent_id).await?;
    let status = sql_query("SELECT value FROM agent_status_current_results WHERE realm_id=$1 AND agent_id=$2 FOR SHARE")
        .bind::<Text, _>(pcr_realm_id.as_str())
        .bind::<Text, _>(agent_id.as_str())
        .get_result::<ProducerCurrentValueRow>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?;
    if status.as_ref().and_then(|row| row.value.as_str()) != Some("active") {
        return Err(PersistenceError::Conflict(
            "Agent producer is no longer active".to_owned(),
        ));
    }
    let rows = sql_query(
        "SELECT value FROM agent_key_current_results WHERE realm_id=$1 AND agent_id=$2 FOR SHARE",
    )
    .bind::<Text, _>(pcr_realm_id.as_str())
    .bind::<Text, _>(agent_id.as_str())
    .load::<ProducerCurrentValueRow>(&mut *conn)
    .await
    .map_err(PersistenceError::database)?;
    let mut active = Vec::new();
    for row in rows {
        let entries = row
            .value
            .get("authorizations")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                PersistenceError::Internal(
                    "stored Agent key current result has no authorizations".to_owned(),
                )
            })?;
        for entry in entries {
            let Some(raw_method) = entry
                .pointer("/value/verification_method")
                .and_then(Value::as_str)
            else {
                continue;
            };
            let payload: arkret_models_collaboration::events_payloads::agent::AgentKeyAuthorizePayload =
                serde_json::from_value(entry.get("value").cloned().unwrap_or(Value::Null))
                .map_err(|error| PersistenceError::Internal(format!("stored Agent key authorization invalid: {error}")))?;
            if payload
                .expires_at
                .is_some_and(|expiry| expiry <= committed_at)
            {
                continue;
            }
            if payload.agent_id != *agent_id
                || entry.get("value")
                    != Some(
                        &serde_json::to_value(&source_event.payload)
                            .map_err(PersistenceError::database)?,
                    )
            {
                return Err(PersistenceError::Conflict(
                    "Agent current authorization differs from its accepted Event".to_owned(),
                ));
            }
            let tag = entry.get("tag_id").and_then(Value::as_str).ok_or_else(|| {
                PersistenceError::Internal("stored Agent authorization has no tag id".to_owned())
            })?;
            active.push((tag.to_owned(), raw_method.to_owned()));
        }
    }
    if active.len() != 1
        || active[0].0 != format!("{}:1", authorization_ref.event_id)
        || active[0].1 != method.as_str()
    {
        return Err(PersistenceError::Conflict(
            "Agent producer authorization changed before commit".to_owned(),
        ));
    }
    Ok(())
}

impl PgAuthorityCommitStore {
    async fn admit_ordinary_realm_bootstrap_unit_inner(
        &self,
        unit: &OrdinaryRealmBootstrapCommitUnit,
        producer_guards: Option<&[SelfProducerCommitGuard]>,
        queued_at: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<OrdinaryRealmBootstrapCommitOutcome> {
        unit.validate().map_err(invalid)?;
        if producer_guards.is_some_and(|guards| guards.len() != unit.transactions.len()) {
            return Err(invalid(
                "ordinary Realm bootstrap needs one producer guard per Event",
            ));
        }
        let first = &unit.transactions[0];
        let authority = &first.expected_authority;
        if authority.generation != 0
            || authority.last_handoff_ref.is_some()
            || authority.authority_ref
                != arkret_wire::RealmCommitAuthorityRef::GenesisOrChangeEvent(
                    first.event.event_id.clone(),
                )
        {
            return Err(invalid(
                "ordinary Realm bootstrap requires its exact genesis authority",
            ));
        }
        let realm_id = authority.realm_id.as_str().to_owned();
        let key = unit.submission.idempotency_key.as_uuid().to_string();
        let commits = unit
            .transactions
            .iter()
            .map(|transaction| transaction.commit.clone())
            .collect::<Vec<_>>();
        let mut conn = pg_conn(&self.pool).await?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            let inserted = sql_query(
                "INSERT INTO ordinary_realm_bootstrap_units \
                 (realm_id,idempotency_key,exact_request_body,commits_json,committed_at) \
                 VALUES ($1,$2,$3,'[]'::jsonb,$4) ON CONFLICT DO NOTHING",
            )
            .bind::<Text, _>(&realm_id)
            .bind::<Text, _>(&key)
            .bind::<Binary, _>(&unit.exact_request_body)
            .bind::<Timestamptz, _>(queued_at)
            .execute(&mut *conn)
            .await?;
            if inserted == 0 {
                let existing = sql_query(
                    "SELECT idempotency_key,exact_request_body,commits_json \
                     FROM ordinary_realm_bootstrap_units WHERE realm_id=$1 FOR UPDATE",
                )
                .bind::<Text, _>(&realm_id)
                .get_result::<OrdinaryBootstrapUnitRow>(&mut *conn)
                .await
                .optional()?;
                let Some(existing) = existing else {
                    return Err(PersistenceError::Conflict("duplicate_conflict".to_owned()).into());
                };
                if existing.idempotency_key != key
                    || existing.exact_request_body != unit.exact_request_body
                {
                    return Err(PersistenceError::Conflict("duplicate_conflict".to_owned()).into());
                }
                let stored = decode_json::<Vec<arkret_wire::RealmCommit>>(
                    existing.commits_json,
                    "ordinary Realm bootstrap committed unit",
                )?;
                if stored.len() != commits.len() || stored.is_empty() {
                    return Err(PersistenceError::Internal(
                        "stored ordinary Realm bootstrap unit is incomplete".to_owned(),
                    )
                    .into());
                }
                return Ok(OrdinaryRealmBootstrapCommitOutcome::Duplicate(stored));
            }
            let authority_inserted = sql_query(
                "INSERT INTO realm_authorities \
                 (realm_id,generation,service_id,authority_ref,last_handoff_ref) \
                 VALUES ($1,0,$2,$3,NULL) ON CONFLICT (realm_id) DO NOTHING",
            )
            .bind::<Text, _>(&realm_id)
            .bind::<Text, _>(authority.service_id.as_str())
            .bind::<Jsonb, _>(
                serde_json::to_value(&authority.authority_ref)
                    .map_err(PersistenceError::database)?,
            )
            .execute(&mut *conn)
            .await?;
            if authority_inserted != 1 {
                return Err(PersistenceError::Conflict("realm_already_exists".to_owned()).into());
            }
            for (index, transaction) in unit.transactions.iter().enumerate() {
                if let Some(guards) = producer_guards {
                    check_self_producer_guard_in_connection(
                        conn,
                        &transaction.event,
                        &guards[index],
                        transaction.commit.committed_at,
                    )
                    .await?;
                }
                queue_event_in_connection(conn, &transaction.event, queued_at).await?;
                match commit_transaction_in_connection(conn, transaction).await? {
                    AuthorityCommitWriteOutcome::Committed => {}
                    AuthorityCommitWriteOutcome::Duplicate => {
                        return Err(
                            PersistenceError::Conflict("duplicate_conflict".to_owned()).into()
                        );
                    }
                    AuthorityCommitWriteOutcome::StaleAuthority(_) => {
                        return Err(
                            PersistenceError::Conflict("stale_realm_authority".to_owned()).into(),
                        );
                    }
                }
                commit_realm_authority_root_current_result_in_connection(
                    conn,
                    &transaction.event,
                    &transaction.commit,
                )
                .await?;
                crate::realm_bootstrap_current_results::commit_ordinary_bootstrap_singleton_current_result_in_connection(
                    conn,
                    &transaction.event,
                    &transaction.commit,
                )
                .await?;
                crate::unit_of_work::commit_parent_membership_current_results(
                    conn,
                    &transaction.event,
                    &transaction.commit,
                )
                .await?;
                commit_capability_grant_current_result_in_connection(
                    conn,
                    &transaction.event,
                    &transaction.commit,
                )
                .await?;
                commit_mimi_room_binding_current_result_in_connection(
                    conn,
                    &transaction.event,
                    &transaction.commit,
                )
                .await?;
            }
            crate::account_summary::publish_realm_account_summary_in_connection(
                conn,
                &authority.realm_id,
            )
            .await?;
            sql_query(
                "UPDATE ordinary_realm_bootstrap_units SET commits_json=$2 WHERE realm_id=$1",
            )
            .bind::<Text, _>(&realm_id)
            .bind::<Jsonb, _>(serde_json::to_value(&commits).map_err(PersistenceError::database)?)
            .execute(&mut *conn)
            .await?;
            Ok(OrdinaryRealmBootstrapCommitOutcome::Committed(commits))
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }
}

/// Whether `member` is a current joined member of `realm_id` in this
/// Station's accepted state (see
/// [`AuthorityCommitStore::accepted_current_member_joined`]).
pub(crate) async fn accepted_current_member_joined_in_connection(
    conn: &mut AsyncPgConnection,
    realm_id: &arkret_wire::RealmId,
    member: &arkret_wire::ActorId,
) -> PersistenceResult<bool> {
    let row = sql_query(
        // A row is backed by the Realm-stream Commit that installed it,
        // held here, or -- on a member Station -- by the verified
        // bootstrap snapshot the held replica is anchored on, whose rows
        // name Commits below the replica's floor (decision 0116).
        "SELECT EXISTS (\
            SELECT 1 FROM member_state_current_results m \
            WHERE m.realm_id = $1 AND m.member_id = $2 AND m.membership = 'join' \
              AND (EXISTS (SELECT 1 FROM realm_commits c \
                           WHERE c.commit_id = m.current_commit_id \
                             AND c.realm_id = m.realm_id \
                             AND c.stream_position = m.current_stream_position \
                             AND c.stream_ref->>'kind' = 'realm' \
                             AND c.stream_ref->>'realm_id' = m.realm_id) \
                   OR EXISTS (SELECT 1 FROM replica_stream_anchors a \
                              WHERE a.realm_id = m.realm_id \
                                AND a.anchor_stream_position >= m.current_stream_position))\
         ) AS present",
    )
    .bind::<Text, _>(realm_id.as_str())
    .bind::<Text, _>(member.to_string())
    .get_result::<PresenceRow>(&mut *conn)
    .await
    .map_err(PersistenceError::database)?;
    Ok(row.present)
}

#[async_trait]
impl AuthorityCommitStore for PgAuthorityCommitStore {
    async fn admit_accepted_device_authorization(
        &self,
        transaction: &AuthorityCommitTransaction,
        queued_at: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<AcceptedDeviceAuthorizationOutcome> {
        transaction.validate().map_err(invalid)?;
        let mut conn = pg_conn(&self.pool).await?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            crate::pcr_accepted_device_unit::admit_accepted_device_unit_in_connection(
                conn,
                transaction,
                queued_at,
            )
            .await
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }

    async fn pcr_genesis_replay(
        &self,
        submission: &arkret_models_collaboration::principal_operations::PcrGenesisAdmissionInput,
        exact_request_body: &[u8],
    ) -> PersistenceResult<
        Option<arkret_models_collaboration::principal_operations::PcrGenesisAdmissionResult>,
    > {
        use arkret_models_collaboration::principal_operations::PcrGenesisAdmissionResult;

        let mut conn = pg_conn(&self.pool).await?;
        let key = submission.idempotency_key.to_string();
        let existing = sql_query(
            "SELECT realm_id,idempotency_key,exact_request_body,result_json \
             FROM pcr_genesis_units WHERE realm_id=$1 OR idempotency_key=$2 \
             ORDER BY (realm_id=$1) DESC LIMIT 1",
        )
        .bind::<Text, _>(submission.pcr_realm_id.as_str())
        .bind::<Text, _>(&key)
        .get_result::<PcrGenesisUnitRow>(&mut conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?;
        let Some(existing) = existing else {
            return Ok(None);
        };
        if existing.realm_id != submission.pcr_realm_id.as_str()
            || existing.idempotency_key != key
            || existing.exact_request_body != exact_request_body
        {
            return Err(PersistenceError::Conflict("duplicate_conflict".to_owned()));
        }
        let stored: PcrGenesisAdmissionResult =
            decode_json(existing.result_json, "PCR genesis result")?;
        stored.validate_against(submission).map_err(invalid)?;
        Ok(Some(stored))
    }

    async fn admit_pcr_genesis_unit(
        &self,
        unit: &PcrGenesisCommitUnit,
        queued_at: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<PcrGenesisCommitOutcome> {
        use arkret_models_collaboration::events_payloads::DeviceAuthorizePayload;
        use arkret_models_collaboration::principal_operations::PcrGenesisAdmissionResult;

        unit.validate().map_err(invalid)?;
        let submission = &unit.submission;
        let authority = &unit.transactions[0].expected_authority;
        let realm_id = submission.pcr_realm_id.as_str();
        let key = submission.idempotency_key.to_string();
        let authorize_payload: DeviceAuthorizePayload = serde_json::from_value(Value::Object(
            unit.transactions[1]
                .event
                .payload
                .clone()
                .into_iter()
                .collect(),
        ))
        .map_err(|error| invalid(format!("founding device payload is invalid: {error}")))?;
        let commits = unit
            .transactions
            .clone()
            .map(|transaction| transaction.commit);
        let result = PcrGenesisAdmissionResult {
            principal_id: submission.principal_id.clone(),
            pcr_realm_id: submission.pcr_realm_id.clone(),
            accepted_device_id: authorize_payload.device_id.clone(),
            resolution: arkret_models_identity::PrincipalResolutionProjection {
                did: submission.did.clone(),
                method_history_head: submission
                    .registration_did_evidence
                    .method_history_head
                    .clone(),
                version_id: submission.did_version_id.clone(),
                resolution_event_ref: unit.transactions[0].event.event_id.to_string(),
                updated_at: commits[0].committed_at,
            },
            commits,
        };
        result.validate_against(submission).map_err(invalid)?;
        let result_json = serde_json::to_value(&result).map_err(PersistenceError::database)?;
        let commits_json =
            serde_json::to_value(&result.commits).map_err(PersistenceError::database)?;
        let resolution_json =
            serde_json::to_value(&result.resolution).map_err(PersistenceError::database)?;
        let create_json = serde_json::to_value(&unit.transactions[0].event)
            .map_err(PersistenceError::database)?;
        let authorization_ref = arkret_wire::CommittedEventRef {
            event_id: unit.transactions[1].event.event_id.clone(),
            commit_id: result.commits[1].commit_id.clone(),
            stream_ref: result.commits[1].stream_ref.clone(),
            stream_position: result.commits[1].stream_position,
        };
        let mut device_json =
            serde_json::to_value(&authorize_payload).map_err(PersistenceError::database)?;
        let device_fields = device_json
            .as_object_mut()
            .ok_or_else(|| invalid("founding device payload must be a JSON object"))?;
        device_fields.insert(
            "device_authorization_ref".to_owned(),
            serde_json::to_value(&authorization_ref).map_err(PersistenceError::database)?,
        );
        device_fields.insert(
            "device_authorize_event_id".to_owned(),
            serde_json::to_value(&unit.transactions[1].event.event_id)
                .map_err(PersistenceError::database)?,
        );
        let mut conn = pg_conn(&self.pool).await?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            let inserted = sql_query(
                "INSERT INTO pcr_genesis_units \
                 (realm_id,principal_id,station_id,idempotency_key,exact_request_body,commits_json,\
                  result_json,committed_at) \
                 VALUES ($1,$2,$3,$4,$5,'[]'::jsonb,'{}'::jsonb,$6) ON CONFLICT DO NOTHING",
            )
            .bind::<Text, _>(realm_id)
            .bind::<Text, _>(submission.principal_id.as_str())
            .bind::<Text, _>(submission.account_authority_id.as_str())
            .bind::<Text, _>(&key)
            .bind::<Binary, _>(&unit.exact_request_body)
            .bind::<Timestamptz, _>(queued_at)
            .execute(&mut *conn)
            .await?;
            if inserted == 0 {
                let existing = sql_query(
                    "SELECT realm_id,idempotency_key,exact_request_body,result_json \
                     FROM pcr_genesis_units WHERE realm_id=$1 OR idempotency_key=$2 \
                     ORDER BY (realm_id=$1) DESC LIMIT 1 FOR UPDATE",
                )
                .bind::<Text, _>(realm_id)
                .bind::<Text, _>(&key)
                .get_result::<PcrGenesisUnitRow>(&mut *conn)
                .await
                .optional()?;
                let Some(existing) = existing else {
                    return Err(PersistenceError::Conflict("duplicate_conflict".to_owned()).into());
                };
                if existing.realm_id != realm_id || existing.idempotency_key != key || existing.exact_request_body != unit.exact_request_body {
                    return Err(PersistenceError::Conflict("duplicate_conflict".to_owned()).into());
                }
                let stored: PcrGenesisAdmissionResult = decode_json(existing.result_json, "PCR genesis result")?;
                stored.validate_against(submission).map_err(invalid)?;
                return Ok(PcrGenesisCommitOutcome::Duplicate(stored));
            }
            let authority_inserted = sql_query(
                "INSERT INTO realm_authorities \
                 (realm_id,generation,service_id,authority_ref,last_handoff_ref) \
                 VALUES ($1,0,$2,$3,NULL) ON CONFLICT (realm_id) DO NOTHING",
            )
            .bind::<Text, _>(realm_id)
            .bind::<Text, _>(authority.service_id.as_str())
            .bind::<Jsonb, _>(serde_json::to_value(&authority.authority_ref).map_err(PersistenceError::database)?)
            .execute(&mut *conn)
            .await?;
            if authority_inserted != 1 {
                return Err(PersistenceError::Conflict("realm_already_exists".to_owned()).into());
            }
            for transaction in &unit.transactions {
                queue_event_in_connection(conn, &transaction.event, queued_at).await?;
                match commit_verified_pcr_device_transaction_in_connection(conn, transaction).await? {
                    AuthorityCommitWriteOutcome::Committed => {}
                    AuthorityCommitWriteOutcome::Duplicate => {
                        return Err(PersistenceError::Conflict("duplicate_conflict".to_owned()).into());
                    }
                    AuthorityCommitWriteOutcome::StaleAuthority(_) => {
                        return Err(PersistenceError::Conflict("stale_realm_authority".to_owned()).into());
                    }
                }
                commit_realm_authority_root_current_result_in_connection(conn, &transaction.event, &transaction.commit).await?;
                commit_capability_grant_current_result_in_connection(conn, &transaction.event, &transaction.commit).await?;
                crate::pcr_device_current_results::project_pcr_device_current_in_connection(
                    conn,
                    &transaction.event,
                    &transaction.commit,
                    Some(&arkret_wire::AccountId::new(
                        submission.principal_id.clone(),
                        submission.account_authority_id.clone(),
                    )),
                )
                .await?;
            }
            let resolution_inserted = sql_query(
                "WITH inserted AS ( \
                   INSERT INTO principal_resolutions \
                     (principal_id,station_id,pcr_realm_id,genesis_event_id,current_event_id,projection,updated_at) \
                   VALUES ($1,$2,$3,$4,$4,$5,$6) ON CONFLICT DO NOTHING \
                   RETURNING principal_id,station_id \
                 ), inserted_event AS ( \
                   INSERT INTO principal_resolution_events \
                     (principal_id,station_id,event_id,previous_event_id,method_history_head,event_json,created_at) \
                   SELECT principal_id,station_id,$4,NULL,$7,$8,$6 FROM inserted \
                 ) SELECT EXISTS(SELECT 1 FROM inserted) AS present",
            )
            .bind::<Text, _>(submission.principal_id.as_str())
            .bind::<Text, _>(submission.account_authority_id.as_str())
            .bind::<Text, _>(realm_id)
            .bind::<Text, _>(unit.transactions[0].event.event_id.as_str())
            .bind::<Jsonb, _>(&resolution_json)
            .bind::<Timestamptz, _>(result.resolution.updated_at)
            .bind::<Text, _>(&result.resolution.method_history_head)
            .bind::<Jsonb, _>(&create_json)
            .get_result::<PresenceRow>(&mut *conn)
            .await?;
            if !resolution_inserted.present {
                return Err(PersistenceError::Conflict("principal_resolution_already_exists".to_owned()).into());
            }
            let device_inserted = sql_query(
                "INSERT INTO devices \
                 (id,station_id,actor_id,device_id,device_key,verification_state,payload,created_at,updated_at) \
                 VALUES ($1,$2,$3,$4,$5,'verified',$6,$7,$7) \
                 ON CONFLICT(actor_id,device_id) DO NOTHING",
            )
            .bind::<diesel::sql_types::Uuid, _>(uuid::Uuid::now_v7())
            .bind::<Text, _>(submission.account_authority_id.as_str())
            .bind::<Text, _>(submission.principal_id.as_str())
            .bind::<Text, _>(result.accepted_device_id.as_str())
            .bind::<Text, _>(authorize_payload.device_public_key_did.as_str())
            .bind::<Jsonb, _>(&device_json)
            .bind::<Timestamptz, _>(result.commits[1].committed_at)
            .execute(&mut *conn)
            .await?;
            if device_inserted != 1 {
                return Err(PersistenceError::Conflict("founding_device_already_exists".to_owned()).into());
            }
            sql_query("UPDATE pcr_genesis_units SET commits_json=$2,result_json=$3 WHERE realm_id=$1")
                .bind::<Text, _>(realm_id)
                .bind::<Jsonb, _>(&commits_json)
                .bind::<Jsonb, _>(&result_json)
                .execute(&mut *conn)
                .await?;
            Ok(PcrGenesisCommitOutcome::Committed(result))
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }

    async fn admit_ordinary_realm_bootstrap_unit(
        &self,
        unit: &OrdinaryRealmBootstrapCommitUnit,
        queued_at: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<OrdinaryRealmBootstrapCommitOutcome> {
        self.admit_ordinary_realm_bootstrap_unit_inner(unit, None, queued_at)
            .await
    }

    async fn admit_self_direct_conversation_founding_unit(
        &self,
        unit: &soland_storage::DirectConversationFoundingCommitUnit,
        producer_guards: &[SelfProducerCommitGuard; 4],
        queued_at: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<soland_storage::DirectConversationFoundingCommitOutcome> {
        crate::direct_conversation_founding::admit_self_direct_conversation_founding_unit(
            &self.pool,
            unit,
            producer_guards,
            queued_at,
        )
        .await
    }

    async fn materialize_peer_direct_conversation_founding_unit(
        &self,
        unit: &soland_storage::DirectConversationFoundingCommitUnit,
        evidence: &arkret_models_collaboration::objects::direct_conversation::DirectConversationFoundingAuthorityEvidence,
        local_station: &arkret_wire::DidCoreId,
        received_at: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<arkret_models_collaboration::authority_commit::AggregateAcceptanceStatus>
    {
        crate::direct_conversation_founding::materialize_peer_direct_conversation_founding_unit(
            &self.pool,
            unit,
            evidence,
            local_station,
            received_at,
        )
        .await
    }

    async fn direct_conversation_admission(
        &self,
        event: &arkret_wire::Event,
    ) -> PersistenceResult<soland_storage::DirectConversationAdmissionCut> {
        let mut conn = pg_conn(&self.pool).await?;
        // One snapshot, not read-only: the table share-locks the rows it
        // reads, exactly as inside the accepting transaction.
        conn.transaction::<_, PgTransactionError, _>(async |conn| {
            sql_query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
                .execute(&mut *conn)
                .await?;
            if crate::direct_conversation_admission::direct_conversation_realm_in_connection(
                conn,
                &event.realm_id,
            )
            .await?
            .is_none()
            {
                return Ok(soland_storage::DirectConversationAdmissionCut::NotDirectConversation);
            }
            Ok(
                match crate::direct_conversation_admission::admission_refusal_in_connection(
                    conn, event,
                )
                .await?
                {
                    Some(code) => soland_storage::DirectConversationAdmissionCut::Refused(code),
                    None => soland_storage::DirectConversationAdmissionCut::Passed,
                },
            )
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }

    async fn direct_conversation_pending_peer_claim_query(
        &self,
        realm_id: &arkret_wire::RealmId,
    ) -> PersistenceResult<Option<soland_storage::DirectConversationPendingPeerClaimQuery>> {
        #[derive(QueryableByName)]
        struct Row {
            #[diesel(sql_type = Text)]
            peer_id: String,
            #[diesel(sql_type = Text)]
            original_request_body: String,
            #[diesel(sql_type = Text)]
            claim_request_id: String,
            #[diesel(sql_type = Text)]
            request_digest: String,
        }
        let mut conn = pg_conn(&self.pool).await?;
        let row = sql_query(
            "SELECT o.peer_id, o.payload_json AS original_request_body, \
                    c.claim_request_id, c.request_digest \
             FROM direct_conversation_group_states g \
             JOIN federation_outbox fan \
               ON fan.endpoint='/_arkret/peer/events' \
              AND fan.payload_json::jsonb #>> '{replications,0,source_commit,event_ref}' \
                  =g.initial_exact_pair_group_state_ref \
             JOIN peer_keypackage_claims c \
               ON c.outcome #>> '{claims,0,claim_id}' \
                  =fan.payload_json::jsonb #>> '{replications,0,welcomes,0,keypackage_claim_ref}' \
             JOIN federation_outbox o \
               ON o.idempotency_key=c.claim_request_id \
              AND o.endpoint='/_arkret/peer/keys/keypackages/claim' \
              AND o.peer_id=fan.peer_id \
              AND o.peer_id=c.outcome->'claim_receipt'->>'destination_id' \
             WHERE g.realm_id=$1 AND c.state IN ('claimed','last_resort_claimed') \
             LIMIT 1",
        )
        .bind::<Text, _>(realm_id.as_str())
        .get_result::<Row>(&mut conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?;
        Ok(row.map(
            |row| soland_storage::DirectConversationPendingPeerClaimQuery {
                peer_id: row.peer_id,
                original_request_body: row.original_request_body,
                claim_request_id: row.claim_request_id,
                request_digest: row.request_digest,
            },
        ))
    }

    async fn admit_self_ordinary_realm_bootstrap_unit(
        &self,
        unit: &OrdinaryRealmBootstrapCommitUnit,
        producer_guards: &[SelfProducerCommitGuard],
        queued_at: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<OrdinaryRealmBootstrapCommitOutcome> {
        self.admit_ordinary_realm_bootstrap_unit_inner(unit, Some(producer_guards), queued_at)
            .await
    }

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

    async fn record_remote_authority(
        &self,
        authority: &CurrentRealmAuthority,
        local_service_id: &arkret_wire::DidCoreId,
    ) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool).await?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            replica::record_remote_authority_in_connection(conn, authority, local_service_id).await
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }

    async fn realm_fanout_still_owed(
        &self,
        event: &arkret_wire::Event,
        local_service_id: &arkret_wire::DidCoreId,
        peer: &arkret_wire::DidCoreId,
        witnesses: &[soland_storage::RealmFanoutAuthorityWitness],
        at: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<bool> {
        let mut conn = pg_conn(&self.pool).await?;
        crate::realm_fanout::fanout_still_owed_in_connection(
            &mut conn,
            event,
            local_service_id,
            peer,
            witnesses,
            at,
        )
        .await
    }

    async fn install_committed_replica(
        &self,
        replica: &soland_storage::CommittedReplica,
    ) -> PersistenceResult<soland_storage::CommittedReplicaOutcome> {
        let mut conn = pg_conn(&self.pool).await?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            replica::install_committed_replica_in_connection(conn, replica).await
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }

    async fn queue_replicated_welcomes(
        &self,
        event: &arkret_wire::Event,
        commit: &arkret_wire::RealmCommit,
        welcomes: &[soland_storage::VerifiedMlsWelcome],
        at: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<soland_storage::CommittedReplicaOutcome> {
        let mut conn = pg_conn(&self.pool).await?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            replica::queue_welcomes_of_held_replica_in_connection(conn, event, commit, welcomes, at)
                .await
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }

    async fn install_committed_chain_node(
        &self,
        node: &soland_storage::CommittedChainNode,
    ) -> PersistenceResult<soland_storage::CommittedReplicaOutcome> {
        let mut conn = pg_conn(&self.pool).await?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            replica::install_committed_chain_node_in_connection(conn, node).await
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }

    async fn replica_stream_anchor(
        &self,
        realm_id: &arkret_wire::RealmId,
    ) -> PersistenceResult<Option<soland_storage::ReplicaStreamAnchor>> {
        let mut conn = pg_conn(&self.pool).await?;
        replica::replica_stream_anchor_in_connection(&mut conn, realm_id)
            .await
            .map_err(PgTransactionError::into_persistence)
    }

    async fn pending_replica_stream_anchors(&self) -> PersistenceResult<Vec<arkret_wire::RealmId>> {
        #[derive(QueryableByName)]
        struct RealmRow {
            #[diesel(sql_type = Text)]
            realm_id: String,
        }
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "SELECT realm_id FROM replica_stream_anchors \
             WHERE anchor_commit_id IS NULL ORDER BY realm_id",
        )
        .load::<RealmRow>(&mut *conn)
        .await
        .map_err(PersistenceError::database)?
        .into_iter()
        .map(|row| decode_text(row.realm_id, "pending replica Realm id"))
        .collect()
    }

    async fn install_replica_anchor(
        &self,
        install: &soland_storage::ReplicaAnchorInstall,
    ) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool).await?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            replica::install_replica_anchor_in_connection(conn, install).await
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }

    async fn held_stream_head_commit(
        &self,
        stream_ref: &arkret_wire::CommitStreamRef,
    ) -> PersistenceResult<Option<arkret_wire::RealmCommit>> {
        let key = stream_key(stream_ref)?;
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "SELECT commit_json FROM realm_commits \
             WHERE stream_key = $1 ORDER BY stream_position DESC LIMIT 1",
        )
        .bind::<Text, _>(key)
        .get_result::<CommitRow>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?
        .map(|row| decode_json(row.commit_json, "held stream head"))
        .transpose()
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

    async fn local_current_member_joined(
        &self,
        realm_id: &arkret_wire::RealmId,
        member: &arkret_wire::ActorId,
        service_id: &arkret_wire::DidCoreId,
    ) -> PersistenceResult<bool> {
        let mut conn = pg_conn(&self.pool).await?;
        let row = sql_query(
            "SELECT EXISTS (\
                SELECT 1 FROM realm_authorities a \
                JOIN member_state_current_results m ON m.realm_id = a.realm_id \
                JOIN realm_commits c ON c.commit_id = m.current_commit_id \
                WHERE a.realm_id = $1 AND a.service_id = $2 \
                  AND m.member_id = $3 AND m.membership = 'join' \
                  AND c.realm_id = m.realm_id \
                  AND c.stream_position = m.current_stream_position \
                  AND c.stream_ref->>'kind' = 'realm' \
                  AND c.stream_ref->>'realm_id' = m.realm_id\
             ) AS present",
        )
        .bind::<Text, _>(realm_id.as_str())
        .bind::<Text, _>(service_id.as_str())
        .bind::<Text, _>(member.to_string())
        .get_result::<PresenceRow>(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
        Ok(row.present)
    }

    async fn accepted_current_member_joined(
        &self,
        realm_id: &arkret_wire::RealmId,
        member: &arkret_wire::ActorId,
    ) -> PersistenceResult<bool> {
        let mut conn = pg_conn(&self.pool).await?;
        accepted_current_member_joined_in_connection(&mut conn, realm_id, member).await
    }

    async fn accepted_effective_agent_member_joined(
        &self,
        realm_id: &arkret_wire::RealmId,
        agent: &arkret_wire::ActorId,
        controller: &arkret_wire::AccountId,
    ) -> PersistenceResult<bool> {
        let mut conn = pg_conn(&self.pool).await?;
        let controller_actor = arkret_wire::ActorId::account(controller.clone());
        let controller_value =
            serde_json::to_value(controller).map_err(PersistenceError::database)?;
        let row = sql_query(
            "SELECT EXISTS (\
               SELECT 1 FROM member_state_current_results agent_member \
               JOIN realm_commits agent_commit \
                 ON agent_commit.commit_id=agent_member.current_commit_id \
                AND agent_commit.realm_id=agent_member.realm_id \
                AND agent_commit.stream_position=agent_member.current_stream_position \
                AND agent_commit.stream_ref->>'kind'='realm' \
               JOIN canonical_events agent_event ON agent_event.pk=agent_commit.event_pk \
               JOIN member_state_current_results controller_member \
                 ON controller_member.realm_id=agent_member.realm_id \
               JOIN realm_commits controller_commit \
                 ON controller_commit.commit_id=controller_member.current_commit_id \
                AND controller_commit.realm_id=controller_member.realm_id \
                AND controller_commit.stream_position=controller_member.current_stream_position \
                AND controller_commit.stream_ref->>'kind'='realm' \
               JOIN canonical_events controller_event ON controller_event.pk=controller_commit.event_pk \
               WHERE agent_member.realm_id=$1 AND agent_member.member_id=$2 \
                 AND agent_member.membership='join' \
                 AND controller_member.member_id=$3 AND controller_member.membership='join' \
                 AND agent_event.envelope->'payload'->'agent_controller_binding'->'controller_account_id'=$4 \
                 AND agent_event.envelope->'payload'->'agent_controller_binding'->>'controller_membership_generation_ref' \
                     =controller_event.envelope->>'event_id' \
                 AND agent_event.kind='ak.member.state' \
             ) AS present",
        )
        .bind::<Text, _>(realm_id.as_str())
        .bind::<Text, _>(agent.to_string())
        .bind::<Text, _>(controller_actor.to_string())
        .bind::<Jsonb, _>(controller_value)
        .get_result::<PresenceRow>(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
        Ok(row.present)
    }

    async fn accepted_realm_reader(
        &self,
        realm_id: &arkret_wire::RealmId,
        actor: &arkret_wire::ActorId,
    ) -> PersistenceResult<bool> {
        let mut conn = pg_conn(&self.pool).await?;
        if accepted_current_member_joined_in_connection(&mut conn, realm_id, actor).await? {
            return Ok(true);
        }
        let Some(account) = actor.as_account_id() else {
            return Ok(false);
        };
        // The owner Account's principal-control Realm, recorded in the same
        // transaction as its PCR genesis.
        Ok(sql_query(
            "SELECT EXISTS (SELECT 1 FROM principal_resolutions \
             WHERE pcr_realm_id = $1 AND principal_id = $2 AND station_id = $3) AS present",
        )
        .bind::<Text, _>(realm_id.as_str())
        .bind::<Text, _>(account.principal_id.as_str())
        .bind::<Text, _>(account.station_id.as_str())
        .get_result::<PresenceRow>(&mut *conn)
        .await
        .map_err(PersistenceError::database)?
        .present)
    }

    async fn accepted_plaintext_visible_services(
        &self,
        realm_id: &arkret_wire::RealmId,
    ) -> PersistenceResult<
        Option<
            arkret_models_collaboration::governance::plaintext_visibility::PlaintextVisibleServicesPayload,
        >,
    >{
        #[derive(QueryableByName)]
        struct ValueRow {
            #[diesel(sql_type = Jsonb)]
            value: Value,
        }
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "SELECT b.value FROM realm_bootstrap_current_results b \
             WHERE b.realm_id = $1 AND b.result_family = 'realm_plaintext_visible_services' \
               AND (EXISTS (SELECT 1 FROM realm_commits c \
                            WHERE c.commit_id = b.current_commit_id \
                              AND c.realm_id = b.realm_id \
                              AND c.stream_position = b.current_stream_position \
                              AND c.stream_ref->>'kind' = 'realm' \
                              AND c.stream_ref->>'realm_id' = b.realm_id) \
                    OR EXISTS (SELECT 1 FROM replica_stream_anchors a \
                               WHERE a.realm_id = b.realm_id \
                                 AND a.anchor_stream_position >= b.current_stream_position))",
        )
        .bind::<Text, _>(realm_id.as_str())
        .get_result::<ValueRow>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?
        .map(|row| decode_json(row.value, "Realm plaintext-visible services"))
        .transpose()
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

    async fn record_forward_attempt(
        &self,
        event_id: &arkret_wire::EventId,
        status: ForwardAttemptStatus,
        reason_code: Option<&str>,
        attempted_at: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<()> {
        if (status == ForwardAttemptStatus::Rejected) != reason_code.is_some() {
            return Err(invalid("forward attempt reason does not match status"));
        }
        let token = ids::parse_event_id(event_id.as_str())
            .ok_or_else(|| invalid("Event id is not a canonical Event token"))?;
        let mut conn = pg_conn(&self.pool).await?;
        let written = sql_query(
            "INSERT INTO authority_forward_attempts (event_pk,status,reason_code,attempted_at) \
             SELECT pk,$2,$3,$4 FROM canonical_events WHERE id=$1 \
             ON CONFLICT (event_pk) DO UPDATE SET status=EXCLUDED.status, \
             reason_code=EXCLUDED.reason_code, attempted_at=EXCLUDED.attempted_at",
        )
        .bind::<Binary, _>(token.to_vec())
        .bind::<Text, _>(status.as_str())
        .bind::<Nullable<Text>, _>(reason_code)
        .bind::<Timestamptz, _>(attempted_at)
        .execute(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
        if written != 1 {
            return Err(PersistenceError::Internal(
                "forward attempt has no queued Event".to_owned(),
            ));
        }
        Ok(())
    }

    async fn queued_event(
        &self,
        event_id: &arkret_wire::EventId,
    ) -> PersistenceResult<Option<QueuedEventRecord>> {
        let token = ids::parse_event_id(event_id.as_str())
            .ok_or_else(|| invalid("Event id is not a canonical Event token"))?;
        let mut conn = pg_conn(&self.pool).await?;
        let row = sql_query(
            "SELECT e.envelope, e.state, e.received_at, e.rejection_reason, c.commit_json, \
                    f.status AS forward_status, f.reason_code AS forward_reason_code, \
                    f.attempted_at AS forward_attempted_at \
             FROM canonical_events e LEFT JOIN realm_commits c ON c.event_pk = e.pk \
             LEFT JOIN authority_forward_attempts f ON f.event_pk=e.pk \
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
                forward_attempt: match (row.forward_status, row.forward_attempted_at) {
                    (None, None) => None,
                    (Some(status), Some(attempted_at)) => Some(ForwardAttemptRecord {
                        status: match status.as_str() {
                            "forwarding" => ForwardAttemptStatus::Forwarding,
                            "rejected" => ForwardAttemptStatus::Rejected,
                            "temporarily_unavailable" => {
                                ForwardAttemptStatus::TemporarilyUnavailable
                            }
                            other => {
                                return Err(PersistenceError::Internal(format!(
                                    "stored forward attempt has unknown status {other:?}"
                                )));
                            }
                        },
                        reason_code: row.forward_reason_code,
                        attempted_at,
                    }),
                    _ => {
                        return Err(PersistenceError::Internal(
                            "stored forward attempt is incomplete".to_owned(),
                        ));
                    }
                },
            })
        })
        .transpose()
    }

    #[cfg(any(test, feature = "test-support"))]
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
                commit_mimi_room_binding_current_result_in_connection(
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

    #[cfg(any(test, feature = "test-support"))]
    async fn admit_self_event_transaction(
        &self,
        transaction: &AuthorityCommitTransaction,
        guard: &SelfProducerCommitGuard,
        queued_at: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<AuthorityCommitWriteOutcome> {
        transaction.validate().map_err(invalid)?;
        let mut conn = pg_conn(&self.pool).await?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            check_self_producer_guard_in_connection(
                conn,
                &transaction.event,
                guard,
                transaction.commit.committed_at,
            )
            .await?;
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
                commit_mimi_room_binding_current_result_in_connection(
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
                commit_mimi_room_binding_current_result_in_connection(
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

    async fn committed_event_by_commit_id(
        &self,
        commit_id: &arkret_wire::RealmCommitId,
    ) -> PersistenceResult<Option<soland_storage::CommittedEventRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        let row = sql_query(
            "SELECT c.commit_json, e.envelope FROM realm_commits c \
             JOIN canonical_events e ON e.pk = c.event_pk \
             WHERE c.commit_id = $1",
        )
        .bind::<Text, _>(commit_id.as_str())
        .get_result::<CommitStreamRow>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?;
        row.map(|row| {
            let commit: arkret_wire::RealmCommit = decode_json(row.commit_json, "RealmCommit")?;
            let event: arkret_wire::Event = decode_json(row.envelope, "committed Event")?;
            if commit.commit_id != *commit_id || commit.event_ref != event.event_id {
                return Err(PersistenceError::Internal(
                    "durable committed Event pair disagrees with its Commit id".into(),
                ));
            }
            Ok(soland_storage::CommittedEventRecord { commit, event })
        })
        .transpose()
    }

    async fn current_mimi_room_binding(
        &self,
        room_uri: &arkret_wire::MimiRoomUri,
    ) -> PersistenceResult<Option<soland_storage::MimiRoomBindingCurrentRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "SELECT mimi_room_uri,realm_id,current_commit_id,current_stream_position,current_event_id,value \
             FROM mimi_room_binding_current_results WHERE mimi_room_uri=$1",
        )
        .bind::<Text, _>(room_uri.as_str())
        .get_result::<MimiRoomBindingCurrentRow>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?
        .map(decode_mimi_room_binding_current)
        .transpose()
    }

    async fn current_agent_result(
        &self,
        realm_id: &arkret_wire::RealmId,
        selector: &arkret_wire::CurrentSelector,
    ) -> PersistenceResult<Option<arkret_wire::TypedCurrentResult>> {
        crate::agent_current_results::read_agent_current_result(&self.pool, realm_id, selector)
            .await
    }

    async fn realm_stream_heads(
        &self,
        realm_id: &arkret_wire::RealmId,
    ) -> PersistenceResult<Vec<arkret_wire::CommitStreamHead>> {
        let mut conn = pg_conn(&self.pool).await?;
        let rows = sql_query(REALM_STREAM_HEADS_SQL)
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

    async fn realm_state_snapshot_material(
        &self,
        realm_id: &arkret_wire::RealmId,
    ) -> PersistenceResult<Option<soland_storage::RealmStateSnapshotMaterial>> {
        let mut conn = pg_conn(&self.pool).await?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            sql_query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
                .execute(&mut *conn)
                .await?;
            realm_state_snapshot_material_in_connection(conn, realm_id)
                .await
                .map_err(Into::into)
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }

    async fn realm_state_snapshot_material_for_account(
        &self,
        realm_id: &arkret_wire::RealmId,
        account: &arkret_wire::AccountId,
    ) -> PersistenceResult<Option<soland_storage::RealmStateSnapshotMaterial>> {
        crate::snapshot_disclosure_gate::account_snapshot_material(&self.pool, realm_id, account)
            .await
    }

    async fn member_station_bootstrap_material(
        &self,
        realm_id: &arkret_wire::RealmId,
        account: &arkret_wire::AccountId,
        membership_commit_id: &arkret_wire::RealmCommitId,
    ) -> PersistenceResult<Option<soland_storage::RealmStateSnapshotMaterial>> {
        crate::snapshot_disclosure_gate::member_station_bootstrap_material(
            &self.pool,
            realm_id,
            account,
            membership_commit_id,
        )
        .await
    }

    async fn issue_realm_state_snapshot_for_account(
        &self,
        realm_id: &arkret_wire::RealmId,
        account: &arkret_wire::AccountId,
        issuer: &arkret_wire::DidCoreId,
        sign: soland_storage::RealmStateSnapshotSigner<'_>,
    ) -> PersistenceResult<Option<arkret_wire::RealmStateSnapshot>> {
        crate::snapshot_disclosure_gate::issue_account_snapshot(
            &self.pool, realm_id, account, issuer, sign,
        )
        .await
    }

    async fn issued_realm_state_snapshot(
        &self,
        realm_id: &arkret_wire::RealmId,
        account: &arkret_wire::AccountId,
        snapshot_id: &arkret_wire::RealmSnapshotId,
        issuer: &arkret_wire::DidCoreId,
    ) -> PersistenceResult<Option<arkret_wire::RealmStateSnapshot>> {
        crate::issued_realm_snapshots::PgIssuedRealmSnapshotArchive::new(self.pool.clone())
            .by_ref(account, realm_id, snapshot_id, issuer)
            .await
    }

    async fn freeze_account_realm_window(
        &self,
        request: &soland_storage::AccountRealmWindowRequest,
        sign: soland_storage::RealmStateSnapshotSigner<'_>,
    ) -> PersistenceResult<Option<soland_storage::AccountRealmWindow>> {
        crate::issued_realm_snapshots::freeze_account_realm_window(&self.pool, request, sign).await
    }

    async fn account_window_basis(
        &self,
        realm_id: &arkret_wire::RealmId,
        account: &arkret_wire::AccountId,
        window_cursor: &str,
        stream_ref: &arkret_wire::CommitStreamRef,
        issuer: &arkret_wire::DidCoreId,
        now_ms: i64,
    ) -> PersistenceResult<
        Option<arkret_models_collaboration::sync_frames::account_sync::StreamWindowStartBasis>,
    > {
        crate::issued_realm_snapshots::account_window_basis(
            &self.pool,
            realm_id,
            account,
            window_cursor,
            stream_ref,
            issuer,
            now_ms,
        )
        .await
    }

    async fn scan_stream(
        &self,
        request: &arkret_wire::StreamScanRequest,
    ) -> PersistenceResult<arkret_wire::StreamScanOutcome> {
        let mut conn = pg_conn(&self.pool).await?;
        stream_page_in_connection(&mut conn, request).await
    }

    async fn scan_stream_for_account(
        &self,
        request: &arkret_wire::StreamScanRequest,
        account: &arkret_wire::AccountId,
        issuer: &arkret_wire::DidCoreId,
    ) -> PersistenceResult<soland_storage::AccountStreamScan> {
        crate::account_stream_scan::scan_stream_for_account(&self.pool, request, account, issuer)
            .await
    }

    async fn committed_event_for_peer(
        &self,
        event_id: &arkret_wire::EventId,
        peer: &arkret_wire::DidCoreId,
        issuer: &arkret_wire::DidCoreId,
    ) -> PersistenceResult<Option<arkret_wire::CommittedEventFullView>> {
        crate::account_stream_scan::committed_event_for_peer(&self.pool, event_id, peer, issuer)
            .await
    }

    async fn committed_event_for_member(
        &self,
        event_id: &arkret_wire::EventId,
        caller: &arkret_wire::ActorId,
        issuer: &arkret_wire::DidCoreId,
    ) -> PersistenceResult<soland_storage::MemberCommittedEventRead> {
        crate::account_stream_scan::committed_event_for_member(&self.pool, event_id, caller, issuer)
            .await
    }

    async fn scan_stream_for_peer(
        &self,
        request: &arkret_wire::StreamScanRequest,
        peer: &arkret_wire::DidCoreId,
        issuer: &arkret_wire::DidCoreId,
    ) -> PersistenceResult<soland_storage::AccountStreamScan> {
        crate::account_stream_scan::scan_stream_for_peer(&self.pool, request, peer, issuer).await
    }

    async fn list_realm_streams_for_account(
        &self,
        realm_id: &arkret_wire::RealmId,
        account: &arkret_wire::AccountId,
        issuer: &arkret_wire::DidCoreId,
    ) -> PersistenceResult<soland_storage::AccountRealmStreamList> {
        crate::self_current_reads::list_realm_streams_for_account(
            &self.pool, realm_id, account, issuer,
        )
        .await
    }

    async fn exact_current_result_for_account(
        &self,
        request: &arkret_models_collaboration::exact_current_results::ExactCurrentResultsReadRequestBody,
        account: &arkret_wire::AccountId,
        issuer: &arkret_wire::DidCoreId,
    ) -> PersistenceResult<
        soland_storage::SelfExactCurrentRead<
            arkret_models_collaboration::exact_current_results::ExactCurrentResultsReadOutcome,
        >,
    > {
        crate::self_current_reads::exact_current_result_for_account(
            &self.pool, request, account, issuer,
        )
        .await
    }

    async fn strand_watch_current_for_account(
        &self,
        request: &arkret_models_collaboration::strand_watch_operations::StrandWatchCurrentRequestBody,
        account: &arkret_wire::AccountId,
        issuer: &arkret_wire::DidCoreId,
    ) -> PersistenceResult<
        soland_storage::SelfExactCurrentRead<
            arkret_models_collaboration::strand_watch_operations::StrandWatchCurrentOutcome,
        >,
    > {
        crate::self_current_reads::strand_watch_current_for_account(
            &self.pool, request, account, issuer,
        )
        .await
    }

    async fn media_service_anchor_for_account(
        &self,
        realm_id: &arkret_wire::RealmId,
        account: &arkret_wire::AccountId,
        issuer: &arkret_wire::DidCoreId,
    ) -> PersistenceResult<soland_storage::MediaServiceAnchorRead> {
        crate::self_current_reads::media_service_anchor_for_account(
            &self.pool, realm_id, account, issuer,
        )
        .await
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
                REALM_STREAM_HEADS_SQL,
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
            "SELECT snapshot_json FROM realm_state_snapshots snapshot WHERE realm_id = $1 \
             AND NOT EXISTS (SELECT 1 FROM realm_state_snapshot_issuances issued \
                             WHERE issued.snapshot_id = snapshot.snapshot_id) \
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

    #[test]
    fn mimi_migration_topology_preserves_optional_field_presence() {
        let absent = serde_json::json!({
            "hub_provider_id": "ak:did_core:web:hub.example",
            "local_provider_role": "hub"
        });
        let present_empty_followers = serde_json::json!({
            "hub_provider_id": "ak:did_core:web:hub.example",
            "local_provider_role": "hub",
            "follower_provider_ids": []
        });
        assert!(!mimi_migration_topology_matches(
            &absent,
            &present_empty_followers
        ));
        assert!(mimi_migration_topology_matches(&absent, &absent));
        assert_eq!(
            invalid_mimi_migration().conflict_code(),
            Some(soland_storage::ConflictCode::MimiRoomBindingMigrationProofInvalid)
        );
    }
}
