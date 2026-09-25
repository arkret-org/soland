//! Remote current authority records and the Realm streams a non-governance
//! member Station holds as replicas (`federation.md` §3, §4.1.1).
//!
//! A replica never re-admits, re-signs or fans out: it stores the source Event
//! and the source RealmCommit exactly, only as the direct successor of the
//! stream this Station already holds. The one way to open a held stream is a
//! hosted member's own verified join (its `ak.member.state{join}` or its
//! `ak.invite.accept`); the stream then stays pending anchor until the
//! governing Station's bootstrap snapshot is installed as its typed current.
//! Commits at or below that snapshot head are held for continuity only; each
//! later replica is re-verified against the hosted-member basis and the
//! Event's visibility at the local typed current, which it then advances in
//! the same transaction together with the hosted Accounts' summaries. A
//! Commit whose Event no hosted member may hold in full is kept as a
//! continuity-only chain node without Event bytes.

use soland_storage::{
    CommittedChainNode, CommittedReplica, CommittedReplicaOutcome, CommittedReplicaRole,
    ConflictCode, ReplicaAnchorInstall, ReplicaStreamAnchor,
};

use super::{
    AsyncPgConnection, BigInt, CommitRow, CurrentRealmAuthority, Jsonb, Nullable,
    OptionalExtension, PersistenceError, PgTransactionError, QueryableByName, RunQueryDsl, Text,
    Timestamptz, Value, decode_json, invalid, locked_authority, same_authority, sql_query,
    stream_key, to_i64,
};

#[derive(QueryableByName)]
struct HeldRow {
    #[diesel(sql_type = Jsonb)]
    commit_json: Value,
    #[diesel(sql_type = Nullable<Jsonb>)]
    envelope: Option<Value>,
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

#[derive(QueryableByName)]
struct AnchorRow {
    #[diesel(sql_type = Text)]
    realm_id: String,
    #[diesel(sql_type = Jsonb)]
    join_commit_json: Value,
    #[diesel(sql_type = Jsonb)]
    member_account_id: Value,
    #[diesel(sql_type = Nullable<Text>)]
    anchor_commit_id: Option<String>,
    #[diesel(sql_type = Nullable<BigInt>)]
    anchor_stream_position: Option<i64>,
}

#[derive(QueryableByName)]
struct ValueRow {
    #[diesel(sql_type = Jsonb)]
    value: Value,
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

/// The Commit held at the head of `key`, locked for this transaction.
async fn locked_head(
    conn: &mut AsyncPgConnection,
    key: &str,
) -> Result<Option<arkret_wire::RealmCommit>, PgTransactionError> {
    sql_query(
        "SELECT commit_json FROM realm_commits \
         WHERE stream_key = $1 ORDER BY stream_position DESC LIMIT 1 FOR UPDATE",
    )
    .bind::<Text, _>(key)
    .get_result::<CommitRow>(&mut *conn)
    .await
    .optional()?
    .map(|row| decode_json(row.commit_json, "held head").map_err(Into::into))
    .transpose()
}

const ANCHOR_SELECT: &str = "SELECT a.realm_id, c.commit_json AS join_commit_json, \
     a.member_account_id, a.anchor_commit_id, a.anchor_stream_position \
     FROM replica_stream_anchors a JOIN realm_commits c ON c.commit_id = a.join_commit_id";

async fn locked_anchor(
    conn: &mut AsyncPgConnection,
    key: &str,
) -> Result<Option<AnchorRow>, PgTransactionError> {
    Ok(sql_query(format!(
        "{ANCHOR_SELECT} WHERE a.stream_key = $1 FOR UPDATE OF a"
    ))
    .bind::<Text, _>(key)
    .get_result::<AnchorRow>(&mut *conn)
    .await
    .optional()?)
}

fn anchor_from_row(row: AnchorRow) -> Result<ReplicaStreamAnchor, PgTransactionError> {
    let join_commit: arkret_wire::RealmCommit =
        decode_json(row.join_commit_json, "replica join Commit")?;
    let anchored_head = match (row.anchor_commit_id, row.anchor_stream_position) {
        (Some(commit_id), Some(position)) => Some(arkret_wire::CommitStreamHead {
            stream_ref: join_commit.stream_ref.clone(),
            stream_position: u64::try_from(position).map_err(|_| {
                PersistenceError::Internal("stored anchor position is negative".to_owned())
            })?,
            commit_id: decode_json(Value::String(commit_id), "replica anchor Commit id")?,
        }),
        (None, None) => None,
        _ => {
            return Err(PersistenceError::Internal("replica anchor row is torn".to_owned()).into());
        }
    };
    Ok(ReplicaStreamAnchor {
        realm_id: decode_json(Value::String(row.realm_id), "replica anchor Realm id")?,
        join_commit,
        member_account_id: decode_json(row.member_account_id, "replica anchor member Account")?,
        anchored_head,
    })
}

/// The anchored head of a held stream, or the refusal of a stream that is
/// not held or not anchored yet.
fn anchored_head(
    anchor: Option<AnchorRow>,
) -> Result<arkret_wire::CommitStreamHead, PgTransactionError> {
    let Some(anchor) = anchor else {
        return Err(conflict(
            ConflictCode::DependencyMissing,
            "this Station holds no anchored replica of the Commit's stream",
        ));
    };
    anchor_from_row(anchor)?.anchored_head.ok_or_else(|| {
        conflict(
            ConflictCode::DependencyMissing,
            "the held stream is pending its bootstrap anchor",
        )
    })
}

/// The held head must be the Commit's direct predecessor.
fn require_direct_successor(
    head: Option<&arkret_wire::RealmCommit>,
    commit: &arkret_wire::RealmCommit,
) -> Result<(), PgTransactionError> {
    let Some(head) = head else {
        return Err(conflict(
            ConflictCode::DependencyMissing,
            "this Station holds no predecessor on the Commit's stream",
        ));
    };
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
        .validate_successor_of(head)
        .map_err(|error| conflict(ConflictCode::ForkQuarantine, &error.to_string()))
}

/// The same held Commit, or the refusal of a Commit id held with other
/// content. A chain node answers an exact replay of its Commit as held.
async fn held_duplicate(
    conn: &mut AsyncPgConnection,
    commit: &arkret_wire::RealmCommit,
    event: Option<&arkret_wire::Event>,
) -> Result<Option<CommittedReplicaOutcome>, PgTransactionError> {
    let Some(existing) = sql_query(
        "SELECT c.commit_json, e.envelope FROM realm_commits c \
         LEFT JOIN canonical_events e ON e.pk = c.event_pk WHERE c.commit_id = $1",
    )
    .bind::<Text, _>(commit.commit_id.as_str())
    .get_result::<HeldRow>(&mut *conn)
    .await
    .optional()?
    else {
        return Ok(None);
    };
    let commit_json = serde_json::to_value(commit).map_err(PersistenceError::database)?;
    let same_event = match (&existing.envelope, event) {
        (Some(envelope), Some(event)) => {
            *envelope == serde_json::to_value(event).map_err(PersistenceError::database)?
        }
        _ => true,
    };
    if existing.commit_json == commit_json && same_event {
        return Ok(Some(CommittedReplicaOutcome::Duplicate));
    }
    Err(conflict(
        ConflictCode::DuplicateConflict,
        "the Commit id is held with different content",
    ))
}

/// Recipient visibility re-verification against the local typed current
/// (`federation.md` §4.1.1): this Station must be allowed to hold the
/// Event's complete canonical bytes.
async fn require_visible(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    local_service_id: &arkret_wire::DidCoreId,
) -> Result<(), PgTransactionError> {
    if crate::realm_fanout::plaintext_message(event) {
        let services = sql_query(
            "SELECT value FROM realm_bootstrap_current_results \
             WHERE realm_id=$1 AND result_family='realm_plaintext_visible_services'",
        )
        .bind::<Text, _>(event.realm_id.as_str())
        .get_result::<ValueRow>(&mut *conn)
        .await
        .optional()?
        .map(|row| crate::realm_fanout::plaintext_message_service_ids(&row.value))
        .unwrap_or_default();
        if !services
            .iter()
            .any(|service| service == local_service_id.as_str())
        {
            return Err(conflict(
                ConflictCode::CapabilityDenied,
                "the Realm does not list this Station as a plaintext message service",
            ));
        }
    }
    if event.kind == arkret_wire::EventKind::SelfModerationReport {
        // Only a moderator may hold a report, and a member Station keeps no
        // capability current to prove a hosted moderator.
        return Err(conflict(
            ConflictCode::CapabilityDenied,
            "no hosted moderator basis is provable on a member Station",
        ));
    }
    Ok(())
}

/// Write the exact Event and its Commit as committed in the caller's
/// transaction.
async fn store_replica_rows(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    commit: &arkret_wire::RealmCommit,
    key: &str,
    received_at: chrono::DateTime<chrono::Utc>,
) -> Result<(), PgTransactionError> {
    super::queue_event_in_connection(conn, event, received_at).await?;
    let token = super::ids::parse_event_id(event.event_id.as_str())
        .ok_or_else(|| invalid("Event id is not a canonical Event token"))?;
    let event_pk = sql_query("SELECT pk FROM canonical_events WHERE id = $1 FOR UPDATE")
        .bind::<super::Binary, _>(token.to_vec())
        .get_result::<EventPkOnlyRow>(&mut *conn)
        .await?
        .pk;
    insert_commit_row(conn, commit, key, Some(event_pk)).await?;
    sql_query(
        "UPDATE canonical_events SET state = 'committed', committed_at = $2, \
         rejection_reason = NULL WHERE pk = $1 AND state = 'queued'",
    )
    .bind::<BigInt, _>(event_pk)
    .bind::<Timestamptz, _>(commit.committed_at)
    .execute(&mut *conn)
    .await?;
    Ok(())
}

async fn insert_commit_row(
    conn: &mut AsyncPgConnection,
    commit: &arkret_wire::RealmCommit,
    key: &str,
    event_pk: Option<i64>,
) -> Result<(), PgTransactionError> {
    sql_query(
        "INSERT INTO realm_commits \
         (commit_id, realm_id, stream_key, stream_ref, stream_position, previous_commit_ref, \
          event_pk, governance_generation, commit_json, committed_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
    )
    .bind::<Text, _>(commit.commit_id.as_str())
    .bind::<Text, _>(commit.realm_id.as_str())
    .bind::<Text, _>(key)
    .bind::<Jsonb, _>(serde_json::to_value(&commit.stream_ref).map_err(PersistenceError::database)?)
    .bind::<BigInt, _>(to_i64(commit.stream_position, "stream position")?)
    .bind::<Nullable<Text>, _>(commit.previous_commit_ref.as_ref().map(|id| id.as_str()))
    .bind::<Nullable<BigInt>, _>(event_pk)
    .bind::<BigInt, _>(to_i64(
        commit.governance_generation,
        "governance generation",
    )?)
    .bind::<Jsonb, _>(serde_json::to_value(commit).map_err(PersistenceError::database)?)
    .bind::<Timestamptz, _>(commit.committed_at)
    .execute(&mut *conn)
    .await?;
    Ok(())
}

fn require_realm_stream(commit: &arkret_wire::RealmCommit) -> Result<(), PgTransactionError> {
    if commit.stream_ref
        != (arkret_wire::CommitStreamRef::Realm {
            realm_id: commit.realm_id.clone(),
        })
    {
        return Err(
            invalid("Circle and Sidecar replicas need their own scope membership basis").into(),
        );
    }
    Ok(())
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
    require_realm_stream(commit)?;
    record_remote_authority_in_connection(conn, &replica.authority, &replica.local_service_id)
        .await?;
    if let Some(outcome) = held_duplicate(conn, commit, Some(event)).await? {
        return Ok(outcome);
    }
    let key = stream_key(&commit.stream_ref)?;
    let head = locked_head(conn, &key).await?;
    let anchor = locked_anchor(conn, &key).await?;
    match &replica.role {
        CommittedReplicaRole::OpeningJoin { member_account_id } => {
            if head.is_some() || anchor.is_some() {
                return Err(conflict(
                    ConflictCode::ForkQuarantine,
                    "this Station already holds the stream a join would open",
                ));
            }
            store_replica_rows(conn, event, commit, &key, replica.received_at).await?;
            sql_query(
                "INSERT INTO replica_stream_anchors \
                 (stream_key, realm_id, join_commit_id, member_account_id) \
                 VALUES ($1, $2, $3, $4)",
            )
            .bind::<Text, _>(&key)
            .bind::<Text, _>(commit.realm_id.as_str())
            .bind::<Text, _>(commit.commit_id.as_str())
            .bind::<Jsonb, _>(
                serde_json::to_value(member_account_id).map_err(PersistenceError::database)?,
            )
            .execute(&mut *conn)
            .await?;
            crate::unit_of_work::commit_parent_membership_current_results(conn, event, commit)
                .await?;
            crate::account_summary::publish_realm_account_summary_in_connection(
                conn,
                &event.realm_id,
            )
            .await?;
        }
        CommittedReplicaRole::HeldStream => {
            let anchored = anchored_head(anchor)?;
            require_direct_successor(head.as_ref(), commit)?;
            if commit.stream_position <= anchored.stream_position {
                // The installed snapshot already carries this Commit's effect.
                store_replica_rows(conn, event, commit, &key, replica.received_at).await?;
                return Ok(CommittedReplicaOutcome::Stored);
            }
            if !hosts_joined_member(conn, &event.realm_id, &replica.local_service_id).await? {
                return Err(conflict(
                    ConflictCode::CapabilityDenied,
                    "no member this Station hosts may hold the Event",
                ));
            }
            require_visible(conn, event, &replica.local_service_id).await?;
            store_replica_rows(conn, event, commit, &key, replica.received_at).await?;
            crate::replica_current::advance_in_connection(conn, event, commit).await?;
            if crate::account_summary::changes_account_summary_inputs(&event.kind) {
                crate::account_summary::publish_realm_account_summary_in_connection(
                    conn,
                    &event.realm_id,
                )
                .await?;
            }
        }
    }
    Ok(CommittedReplicaOutcome::Stored)
}

/// Store one verified withheld Commit as a chain node that directly follows
/// the anchored held head.
pub(super) async fn install_committed_chain_node_in_connection(
    conn: &mut AsyncPgConnection,
    node: &CommittedChainNode,
) -> Result<CommittedReplicaOutcome, PgTransactionError> {
    let commit = &node.commit;
    if commit.realm_id != node.authority.realm_id {
        return Err(invalid("chain node Commit names another Realm").into());
    }
    require_realm_stream(commit)?;
    record_remote_authority_in_connection(conn, &node.authority, &node.local_service_id).await?;
    if let Some(outcome) = held_duplicate(conn, commit, None).await? {
        return Ok(outcome);
    }
    let key = stream_key(&commit.stream_ref)?;
    let head = locked_head(conn, &key).await?;
    anchored_head(locked_anchor(conn, &key).await?)?;
    require_direct_successor(head.as_ref(), commit)?;
    insert_commit_row(conn, commit, &key, None).await?;
    Ok(CommittedReplicaOutcome::Stored)
}

pub(super) async fn replica_stream_anchor_in_connection(
    conn: &mut AsyncPgConnection,
    realm_id: &arkret_wire::RealmId,
) -> Result<Option<ReplicaStreamAnchor>, PgTransactionError> {
    sql_query(format!("{ANCHOR_SELECT} WHERE a.realm_id = $1"))
        .bind::<Text, _>(realm_id.as_str())
        .get_result::<AnchorRow>(&mut *conn)
        .await
        .optional()?
        .map(anchor_from_row)
        .transpose()
}

/// Install a verified bootstrap snapshot as the typed current of a pending
/// replica stream and anchor it at the snapshot head. The held head must
/// still be the join that opened the stream.
pub(super) async fn install_replica_anchor_in_connection(
    conn: &mut AsyncPgConnection,
    install: &ReplicaAnchorInstall,
) -> Result<(), PgTransactionError> {
    let realm_stream = arkret_wire::CommitStreamRef::Realm {
        realm_id: install.realm_id.clone(),
    };
    let key = stream_key(&realm_stream)?;
    let anchor = locked_anchor(conn, &key)
        .await?
        .map(anchor_from_row)
        .transpose()?
        .ok_or_else(|| {
            conflict(
                ConflictCode::DependencyMissing,
                "this Station holds no replica of the Realm stream",
            )
        })?;
    if anchor.anchored_head.is_some() {
        return Err(conflict(
            ConflictCode::DuplicateConflict,
            "the replica stream is already anchored",
        ));
    }
    let join = &anchor.join_commit;
    if join.commit_id != install.join_commit_id {
        return Err(invalid("the anchor names another opening join").into());
    }
    let head = locked_head(conn, &key).await?;
    if head.as_ref().map(|head| &head.commit_id) != Some(&join.commit_id) {
        return Err(PersistenceError::Internal(
            "a pending replica stream holds a Commit after its join".to_owned(),
        )
        .into());
    }
    let snapshot_head = &install.snapshot_head;
    if snapshot_head.stream_ref != realm_stream
        || snapshot_head.stream_position < join.stream_position
        || (snapshot_head.stream_position == join.stream_position
            && snapshot_head.commit_id != join.commit_id)
    {
        return Err(invalid("the bootstrap snapshot head does not cover the join").into());
    }
    let installed_at = chrono::Utc::now();
    crate::replica_current::install_snapshot_in_connection(
        conn,
        &install.realm_id,
        snapshot_head,
        &install.current_state_entries,
        installed_at,
    )
    .await?;
    sql_query(
        "UPDATE replica_stream_anchors SET anchor_commit_id = $2, \
         anchor_stream_position = $3, anchored_at = $4 WHERE stream_key = $1",
    )
    .bind::<Text, _>(&key)
    .bind::<Text, _>(snapshot_head.commit_id.as_str())
    .bind::<BigInt, _>(to_i64(snapshot_head.stream_position, "anchor position")?)
    .bind::<Timestamptz, _>(installed_at)
    .execute(&mut *conn)
    .await?;
    crate::account_summary::publish_realm_account_summary_in_connection(conn, &install.realm_id)
        .await?;
    Ok(())
}
