use diesel::sql_types::{Bool, SmallInt};
use serde::de::DeserializeOwned;
use soland_storage::{
    AuthorityCommitStore, AuthorityCommitTransaction, AuthorityCommitWriteOutcome,
    CurrentRealmAuthority, OrdinaryRealmBootstrapCommitOutcome, OrdinaryRealmBootstrapCommitUnit,
    PcrGenesisCommitOutcome, PcrGenesisCommitUnit, QueuedEventRecord, QueuedEventStatus,
    SelfProducerCommitGuard,
};

use super::{
    AsyncConnection, AsyncPgConnection, BigInt, Binary, Jsonb, Nullable, OptionalExtension,
    PersistenceError, PersistenceResult, PgPool, PgTransactionError, QueryableByName, RunQueryDsl,
    Text, Timestamptz, Value, async_trait, ids, pg_conn, sql_query,
};
use crate::agent_current_results::{
    lock_agent_producer_current, project_agent_key_in_connection,
    project_agent_status_in_connection,
};
use crate::capability_grant_current_results::commit_capability_grant_current_result_in_connection;
use crate::capability_grant_current_results::commit_realm_authority_root_current_result_in_connection;

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

#[derive(QueryableByName)]
struct MimiMlsCurrentRow {
    #[diesel(sql_type = Text)]
    group_id: String,
    #[diesel(sql_type = Text)]
    realm_id: String,
    #[diesel(sql_type = Jsonb)]
    effective_scope: Value,
    #[diesel(sql_type = Jsonb)]
    commit_json: Value,
    #[diesel(sql_type = Jsonb)]
    envelope: Value,
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
    if let Some(group_id) = payload.mls_group_id.as_ref() {
        let group_row = sql_query(
            "SELECT s.group_id,s.realm_id,s.effective_scope,c.commit_json,e.envelope \
             FROM mls_group_states s JOIN canonical_events e ON e.pk=s.commit_event_pk \
             JOIN realm_commits c ON c.event_pk=e.pk WHERE s.group_id=$1 FOR UPDATE",
        )
        .bind::<Text, _>(group_id.as_str())
        .get_result::<MimiMlsCurrentRow>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?
        .ok_or_else(invalid_mimi_migration)?;
        let scope: arkret_wire::ScopeRef = decode_json(
            group_row.effective_scope,
            "MIMI current MLS effective scope",
        )?;
        let group_commit: arkret_wire::RealmCommit =
            decode_json(group_row.commit_json, "MIMI current MLS RealmCommit")?;
        let group_event: arkret_wire::Event =
            decode_json(group_row.envelope, "MIMI current MLS Event")?;
        let derived = scope
            .canonical_mls_group_id()
            .map_err(|_| invalid_mimi_migration())?;
        if group_row.group_id != group_id.as_str()
            || group_row.realm_id != payload.binding_scope.realm_id.as_str()
            || derived != *group_id
            || group_commit.realm_id != payload.binding_scope.realm_id
            || group_commit.event_ref != group_event.event_id
            || group_event.realm_id != payload.binding_scope.realm_id
        {
            return Err(invalid_mimi_migration());
        }
        // The installed MLS state does not carry an authenticated MIMI
        // GroupInfo. Until admission can pin that evidence to this transaction,
        // an encrypted-room migration cannot be finalized.
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
struct PriorMlsStateRow {
    #[diesel(sql_type = BigInt)]
    epoch: i64,
    #[diesel(sql_type = Text)]
    realm_id: String,
    #[diesel(sql_type = Jsonb)]
    effective_scope: Value,
    #[diesel(sql_type = Jsonb)]
    envelope: Value,
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

    let rows = sql_query(
        "SELECT 'realm_policy'::text AS selector_kind, NULL::jsonb AS selector_subject, \
                current_commit_id, current_stream_position, value \
           FROM realm_policy_bundle_current_results WHERE realm_id = $1 \
         UNION ALL \
         SELECT 'member_state'::text AS selector_kind, member_id::jsonb AS selector_subject, \
                current_commit_id, current_stream_position, value \
           FROM member_state_current_results WHERE realm_id = $1 \
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
           FROM agent_key_current_results WHERE realm_id = $1",
    )
    .bind::<Text, _>(realm_id.as_str())
    .load::<SnapshotCurrentRow>(&mut *conn)
    .await
    .map_err(PersistenceError::database)?;
    let current_state_entries = rows
        .into_iter()
        .map(|row| {
            let selector = match (row.selector_kind.as_str(), row.selector_subject) {
                ("realm_policy", None) => arkret_wire::CurrentSelector::RealmPolicy,
                ("member_state", Some(actor_id)) => arkret_wire::CurrentSelector::MemberState {
                    actor_id: serde_json::from_value(actor_id).map_err(|error| {
                        PersistenceError::Internal(format!(
                            "stored snapshot member actor id is invalid: {error}"
                        ))
                    })?,
                },
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
    let current_state_entries = keyed_entries.into_iter().map(|(_, entry)| entry).collect();
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
            history_access: arkret_wire::HistoryAccess::AllHistoryForCurrentMembers,
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
        let payload: arkret_models_crypto::MlsCommitPayload = serde_json::from_value(
            serde_json::to_value(&transaction.event.payload).map_err(PersistenceError::database)?,
        )
        .map_err(invalid)?;
        let previous = sql_query(
            "SELECT s.epoch,s.realm_id,s.effective_scope,e.envelope \
             FROM mls_group_states s JOIN canonical_events e ON e.pk=s.commit_event_pk \
             WHERE s.group_id=$1 FOR UPDATE OF s",
        )
        .bind::<Text, _>(&mls_state.group_id)
        .get_result::<PriorMlsStateRow>(&mut *conn)
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
        if let Some(prior) = previous {
            let prior_event: arkret_wire::Event =
                decode_json(prior.envelope, "previous installed MLS Commit Event")?;
            let prior_scope: arkret_wire::ScopeRef =
                decode_json(prior.effective_scope, "previous installed MLS scope")?;
            if prior.realm_id != transaction.event.realm_id.as_str()
                || prior_scope != mls_state.effective_scope
                || prior_event.event_id != *payload.base_group_state_ref()
                || prior_event.kind != arkret_wire::EventKind::MlsCommit
            {
                return Err(PersistenceError::Conflict(
                    "MLS Commit base does not match the installed authority state".into(),
                )
                .into());
            }
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
        crate::devices::enqueue_mls_welcome_in_connection(
            conn,
            welcome,
            event_row.event_pk,
            transaction.commit.committed_at,
            transaction.recipient_queue_capacity,
        )
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
            if agent_id != &actor.principal_id
                || verification_method != method
                || authorization_ref.stream_ref.realm_id() != pcr_realm_id
            {
                return Err(PersistenceError::Conflict(
                    "self Event Agent guard differs from producer".to_owned(),
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
            let rows = sql_query("SELECT value FROM agent_key_current_results WHERE realm_id=$1 AND agent_id=$2 FOR SHARE")
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
                            "Agent current authorization differs from its accepted Event"
                                .to_owned(),
                        ));
                    }
                    let tag = entry.get("tag_id").and_then(Value::as_str).ok_or_else(|| {
                        PersistenceError::Internal(
                            "stored Agent authorization has no tag id".to_owned(),
                        )
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
    }
}

#[async_trait]
impl AuthorityCommitStore for PgAuthorityCommitStore {
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
                 (realm_id,idempotency_key,exact_request_body,commits_json,result_json,committed_at) \
                 VALUES ($1,$2,$3,'[]'::jsonb,'{}'::jsonb,$4) ON CONFLICT DO NOTHING",
            )
            .bind::<Text, _>(realm_id)
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
                match commit_transaction_in_connection(conn, transaction).await? {
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
        unit.validate().map_err(invalid)?;
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
            for transaction in &unit.transactions {
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
                project_agent_status_in_connection(conn, &transaction.event, &transaction.commit)
                    .await?;
                project_agent_key_in_connection(conn, &transaction.event, &transaction.commit)
                    .await?;
            }
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
                commit_mimi_room_binding_current_result_in_connection(
                    conn,
                    &transaction.event,
                    &transaction.commit,
                )
                .await?;
                project_agent_status_in_connection(conn, &transaction.event, &transaction.commit)
                    .await?;
                project_agent_key_in_connection(conn, &transaction.event, &transaction.commit)
                    .await?;
            }
            Ok(outcome)
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }

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
                project_agent_status_in_connection(conn, &transaction.event, &transaction.commit)
                    .await?;
                project_agent_key_in_connection(conn, &transaction.event, &transaction.commit)
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
                project_agent_status_in_connection(conn, &transaction.event, &transaction.commit)
                    .await?;
                project_agent_key_in_connection(conn, &transaction.event, &transaction.commit)
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
