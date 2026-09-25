//! Remote current authority records and exact committed replicas held by a
//! non-governance member Station (`federation.md` §3, §4.1.1).
//!
//! A replica never re-admits, re-signs or fans out: it stores the source Event
//! and the source RealmCommit exactly, only as the direct successor of the
//! stream this Station already holds, and only while a member it hosts is
//! joined. The single bootstrap exception is a hosted member's own verified
//! `join` (its `ak.member.state{join}` or its `ak.invite.accept`), which may
//! open the held Realm stream at its position. The derived membership and the
//! hosted Accounts' summaries are written in the replica's transaction.

use soland_storage::{CommittedReplica, CommittedReplicaOutcome, ConflictCode};

use super::{
    AsyncPgConnection, BigInt, CommitRow, CurrentRealmAuthority, Jsonb, Nullable,
    OptionalExtension, PersistenceError, PgTransactionError, QueryableByName, RunQueryDsl, Text,
    Timestamptz, Value, decode_json, invalid, locked_authority, same_authority, sql_query,
    stream_key, to_i64,
};

#[derive(QueryableByName)]
struct ReplicaRow {
    #[diesel(sql_type = Jsonb)]
    commit_json: Value,
    #[diesel(sql_type = Jsonb)]
    envelope: Value,
}

#[derive(QueryableByName)]
struct EventPkOnlyRow {
    #[diesel(sql_type = BigInt)]
    pk: i64,
}

#[derive(QueryableByName)]
struct MemberIdRow {
    #[diesel(sql_type = Text)]
    member_id: String,
}

fn conflict(code: ConflictCode, detail: &str) -> PgTransactionError {
    PersistenceError::Conflict(format!("{code}: {detail}")).into()
}

fn validate_authority_shape(authority: &CurrentRealmAuthority) -> Result<(), PgTransactionError> {
    let consistent = match (&authority.authority_ref, &authority.last_handoff_ref) {
        (arkret_wire::RealmCommitAuthorityRef::GenesisOrChangeEvent(_), None) => {
            authority.generation == 0
        }
        (arkret_wire::RealmCommitAuthorityRef::Handoff(handoff), Some(last)) => {
            authority.generation > 0 && handoff == last
        }
        _ => false,
    };
    if !consistent {
        return Err(invalid("remote authority generation and references disagree").into());
    }
    Ok(())
}

/// Upsert one verified remote authority under the Realm authority row lock.
pub(super) async fn record_remote_authority_in_connection(
    conn: &mut AsyncPgConnection,
    authority: &CurrentRealmAuthority,
    local_service_id: &arkret_wire::DidCoreId,
) -> Result<(), PgTransactionError> {
    validate_authority_shape(authority)?;
    if &authority.service_id == local_service_id {
        return Err(invalid("a remote authority record names this Station").into());
    }
    let authority_ref =
        serde_json::to_value(&authority.authority_ref).map_err(PersistenceError::database)?;
    let generation = to_i64(authority.generation, "remote authority generation")?;
    let last_handoff_ref = authority.last_handoff_ref.as_ref().map(|id| id.as_str());
    sql_query(
        "INSERT INTO realm_authorities \
         (realm_id, generation, service_id, authority_ref, last_handoff_ref) \
         VALUES ($1, $2, $3, $4, $5) ON CONFLICT (realm_id) DO NOTHING",
    )
    .bind::<Text, _>(authority.realm_id.as_str())
    .bind::<BigInt, _>(generation)
    .bind::<Text, _>(authority.service_id.as_str())
    .bind::<Jsonb, _>(&authority_ref)
    .bind::<Nullable<Text>, _>(last_handoff_ref)
    .execute(&mut *conn)
    .await?;
    let current = locked_authority(conn, &authority.realm_id)
        .await?
        .ok_or_else(|| PersistenceError::Internal("remote authority row disappeared".into()))?;
    if &current.service_id == local_service_id {
        return Err(conflict(
            ConflictCode::ForkQuarantine,
            "this Station holds the Realm's current authority",
        ));
    }
    if current.generation > authority.generation {
        return Ok(());
    }
    if current.generation == authority.generation {
        if same_authority(&current, authority) {
            return Ok(());
        }
        return Err(conflict(
            ConflictCode::ForkQuarantine,
            "two different verified authorities share one generation",
        ));
    }
    sql_query(
        "UPDATE realm_authorities SET generation = $2, service_id = $3, authority_ref = $4, \
         last_handoff_ref = $5, updated_at = now() WHERE realm_id = $1",
    )
    .bind::<Text, _>(authority.realm_id.as_str())
    .bind::<BigInt, _>(generation)
    .bind::<Text, _>(authority.service_id.as_str())
    .bind::<Jsonb, _>(&authority_ref)
    .bind::<Nullable<Text>, _>(last_handoff_ref)
    .execute(&mut *conn)
    .await?;
    Ok(())
}

async fn hosts_joined_member(
    conn: &mut AsyncPgConnection,
    realm_id: &arkret_wire::RealmId,
    local_service_id: &arkret_wire::DidCoreId,
) -> Result<bool, PgTransactionError> {
    let rows = sql_query(
        "SELECT member_id FROM member_state_current_results \
         WHERE realm_id=$1 AND membership='join' FOR SHARE",
    )
    .bind::<Text, _>(realm_id.as_str())
    .load::<MemberIdRow>(&mut *conn)
    .await?;
    for row in rows {
        let member: arkret_wire::ActorId =
            serde_json::from_str(&row.member_id).map_err(|error| {
                PersistenceError::Internal(format!("replica member identity is malformed: {error}"))
            })?;
        if member.route_service_id() == local_service_id {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Store one verified replica in the caller's transaction.
pub(super) async fn install_committed_replica_in_connection(
    conn: &mut AsyncPgConnection,
    replica: &CommittedReplica,
) -> Result<CommittedReplicaOutcome, PgTransactionError> {
    let event = &replica.event;
    let commit = &replica.commit;
    if commit.realm_id != replica.authority.realm_id
        || commit.event_ref != event.event_id
        || commit.realm_id != event.realm_id
    {
        return Err(invalid("replica Commit does not bind its Event and Realm").into());
    }
    record_remote_authority_in_connection(conn, &replica.authority, &replica.local_service_id)
        .await?;
    let commit_json = serde_json::to_value(commit).map_err(PersistenceError::database)?;
    let envelope = serde_json::to_value(event).map_err(PersistenceError::database)?;
    if let Some(existing) = sql_query(
        "SELECT c.commit_json, e.envelope FROM realm_commits c \
         JOIN canonical_events e ON e.pk = c.event_pk WHERE c.commit_id = $1",
    )
    .bind::<Text, _>(commit.commit_id.as_str())
    .get_result::<ReplicaRow>(&mut *conn)
    .await
    .optional()?
    {
        if existing.commit_json == commit_json && existing.envelope == envelope {
            return Ok(CommittedReplicaOutcome::Duplicate);
        }
        return Err(conflict(
            ConflictCode::DuplicateConflict,
            "the Commit id is held with different content",
        ));
    }

    let key = stream_key(&commit.stream_ref)?;
    let head = sql_query(
        "SELECT commit_json FROM realm_commits \
         WHERE stream_key = $1 ORDER BY stream_position DESC LIMIT 1 FOR UPDATE",
    )
    .bind::<Text, _>(&key)
    .get_result::<CommitRow>(&mut *conn)
    .await
    .optional()?;
    match head {
        Some(head) => {
            let head: arkret_wire::RealmCommit = decode_json(head.commit_json, "held head")?;
            if commit.stream_position <= head.stream_position {
                return Err(conflict(
                    ConflictCode::ForkQuarantine,
                    "a different Commit is held at or after this stream position",
                ));
            }
            if commit.stream_position > head.stream_position.saturating_add(1) {
                return Err(conflict(
                    ConflictCode::DependencyMissing,
                    "the Commits between the held head and this one are not held",
                ));
            }
            commit
                .validate_successor_of(&head)
                .map_err(|error| conflict(ConflictCode::ForkQuarantine, &error.to_string()))?;
            if !hosts_joined_member(conn, &event.realm_id, &replica.local_service_id).await? {
                return Err(conflict(
                    ConflictCode::CapabilityDenied,
                    "no member this Station hosts may hold the Event",
                ));
            }
        }
        None if replica.opens_stream => {}
        None => {
            return Err(conflict(
                ConflictCode::DependencyMissing,
                "this Station holds no predecessor on the Commit's stream",
            ));
        }
    }

    super::queue_event_in_connection(conn, event, replica.received_at).await?;
    let token = super::ids::parse_event_id(event.event_id.as_str())
        .ok_or_else(|| invalid("Event id is not a canonical Event token"))?;
    let event_pk = sql_query("SELECT pk FROM canonical_events WHERE id = $1 FOR UPDATE")
        .bind::<super::Binary, _>(token.to_vec())
        .get_result::<EventPkOnlyRow>(&mut *conn)
        .await?
        .pk;
    sql_query(
        "INSERT INTO realm_commits \
         (commit_id, realm_id, stream_key, stream_ref, stream_position, previous_commit_ref, \
          event_pk, governance_generation, commit_json, committed_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
    )
    .bind::<Text, _>(commit.commit_id.as_str())
    .bind::<Text, _>(commit.realm_id.as_str())
    .bind::<Text, _>(&key)
    .bind::<Jsonb, _>(serde_json::to_value(&commit.stream_ref).map_err(PersistenceError::database)?)
    .bind::<BigInt, _>(to_i64(commit.stream_position, "stream position")?)
    .bind::<Nullable<Text>, _>(commit.previous_commit_ref.as_ref().map(|id| id.as_str()))
    .bind::<BigInt, _>(event_pk)
    .bind::<BigInt, _>(to_i64(
        commit.governance_generation,
        "governance generation",
    )?)
    .bind::<Jsonb, _>(&commit_json)
    .bind::<Timestamptz, _>(commit.committed_at)
    .execute(&mut *conn)
    .await?;
    sql_query(
        "UPDATE canonical_events SET state = 'committed', committed_at = $2, \
         rejection_reason = NULL WHERE pk = $1 AND state = 'queued'",
    )
    .bind::<BigInt, _>(event_pk)
    .bind::<Timestamptz, _>(commit.committed_at)
    .execute(&mut *conn)
    .await?;
    if matches!(
        event.kind,
        arkret_wire::EventKind::MemberState | arkret_wire::EventKind::InviteAccept
    ) {
        crate::unit_of_work::commit_parent_membership_current_results(conn, event, commit).await?;
    }
    if crate::account_summary::changes_account_summary_inputs(&event.kind) {
        crate::account_summary::publish_realm_account_summary_in_connection(conn, &event.realm_id)
            .await?;
    }
    Ok(CommittedReplicaOutcome::Stored)
}
