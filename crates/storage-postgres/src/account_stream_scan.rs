//! Caller-scoped `ak.self.committed_event.read.scan.v1` and
//! `ak.peer.committed_event.read.scan.v1` at one read cut.
//!
//! The caller's readable interval is a protocol decision of the current
//! governing Station: membership join floor, history-access policy, retention
//! and per-Event disclosure all bound it. This Station proves the Realm
//! stream interval of a currently joined member from its join Commit or the
//! genesis Commit ([`caller_realm_floor_in_connection`]). Within it each row
//! is served in full or, when the member committed-event disclosure decision
//! withholds its Event, as the withheld branch on the same Commit. Any other
//! shape fails closed as unproved rather than serving a physical page.
//!
//! A member Station serves its own hosted members from the Realm stream it
//! holds as an anchored replica (`federation.md` §4.1.1): the interval starts
//! at the member's own join under `since_join`, and a history this Station
//! does not hold is unproved. A chain node is served as the withheld branch.
//!
//! A peer Station's replication right on a stream derives from the members
//! routed to it (`federation.md` §4.1.1): from each currently joined member's
//! readable floor to the head, and for a member whose leave or ban ended its
//! joined state, from its readable floor through that terminating Commit.
//! A page stops before the first position outside every interval. Within
//! them each row is served in full only when that Station may hold the
//! Event's complete canonical bytes; a row withheld from that Station keeps
//! only its Commit, so the page stays one verifiable chain.

use arkret_wire::{
    AccountId, ActorId, CommitStreamRef, CommittedEventView, DidCoreId, ReadableFloor,
    ReadableFloorReason, StreamScanOutcome, StreamScanRequest,
};
use soland_storage::AccountStreamScan;

use super::{
    AsyncConnection, AsyncPgConnection, BigInt, Bool, Jsonb, OptionalExtension, PersistenceError,
    PersistenceResult, PgPool, PgTransactionError, QueryableByName, RunQueryDsl, Text, pg_conn,
    sql_query,
};

#[derive(QueryableByName)]
struct TenureRow {
    #[diesel(sql_type = Text)]
    service_id: String,
}

#[derive(QueryableByName)]
struct MemberRow {
    #[diesel(sql_type = Text)]
    member_id: String,
    #[diesel(sql_type = Text)]
    membership: String,
}

pub(crate) async fn scan_stream_for_account(
    pool: &PgPool,
    request: &StreamScanRequest,
    account: &AccountId,
    issuer: &DidCoreId,
) -> PersistenceResult<AccountStreamScan> {
    request
        .validate()
        .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
    let caller = ActorId::account(account.clone()).to_string();
    let mut conn = pg_conn(pool).await?;
    conn.transaction::<_, PgTransactionError, _>(async move |conn| {
        sql_query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
            .execute(&mut *conn)
            .await?;
        let Some(tenure) = sql_query("SELECT service_id FROM realm_authorities WHERE realm_id=$1")
            .bind::<Text, _>(request.realm_id.as_str())
            .get_result::<TenureRow>(&mut *conn)
            .await
            .optional()?
        else {
            return Ok(AccountStreamScan::NotAuthorized);
        };
        let members = sql_query(
            "SELECT member_id, membership FROM member_state_current_results \
             WHERE realm_id=$1 ORDER BY member_id",
        )
        .bind::<Text, _>(request.realm_id.as_str())
        .load::<MemberRow>(&mut *conn)
        .await?;
        if !members
            .iter()
            .any(|row| row.member_id == caller && row.membership == "join")
        {
            return Ok(AccountStreamScan::NotAuthorized);
        }
        if request.stream_ref
            != (CommitStreamRef::Realm {
                realm_id: request.realm_id.clone(),
            })
        {
            return Ok(AccountStreamScan::Unproved(
                "Circle and Sidecar stream visibility is not proved at this cut",
            ));
        }
        let caller_actor = ActorId::account(account.clone());
        let floor = if tenure.service_id == issuer.as_str() {
            caller_realm_floor_in_connection(conn, &request.realm_id, &caller_actor).await?
        } else {
            match replica_realm_floor_in_connection(conn, &request.realm_id, &caller_actor).await? {
                Ok(floor) => Some(floor),
                Err(reason) => return Ok(AccountStreamScan::Unproved(reason)),
            }
        };
        let Some(floor) = floor else {
            return Ok(AccountStreamScan::Unproved(
                "the caller's join or history floor is not proved at this cut",
            ));
        };
        let page = crate::authority_commit::stream_page_above_floor_in_connection(
            conn,
            request,
            Some(floor),
        )
        .await?;
        // Per-Event disclosure applies on top of the interval: a withheld row
        // keeps its Commit so the page stays one verifiable chain.
        let committed_events =
            disclose_page_to_member(conn, page.committed_events.clone(), &caller_actor).await?;
        Ok(AccountStreamScan::Page(StreamScanOutcome {
            committed_events,
            ..page
        }))
    })
    .await
    .map_err(PgTransactionError::into_persistence)
}

#[derive(QueryableByName)]
struct JoinRow {
    #[diesel(sql_type = Text)]
    membership: String,
    #[diesel(sql_type = Text)]
    current_commit_id: String,
    #[diesel(sql_type = BigInt)]
    current_stream_position: i64,
}

#[derive(QueryableByName)]
struct ValueRow {
    #[diesel(sql_type = Jsonb)]
    value: serde_json::Value,
}

#[derive(QueryableByName)]
struct PresentRow {
    #[diesel(sql_type = Bool)]
    present: bool,
}

/// Apply the member committed-event disclosure decision to the full rows of
/// one page, keeping every Commit and the page order.
async fn disclose_page_to_member(
    conn: &mut AsyncPgConnection,
    items: Vec<CommittedEventView>,
    caller: &ActorId,
) -> PersistenceResult<Vec<CommittedEventView>> {
    let full = items
        .iter()
        .filter_map(|item| match item {
            CommittedEventView::Full(view) => Some(view.clone()),
            CommittedEventView::Withheld(_) => None,
        })
        .collect::<Vec<_>>();
    let mut disclosed =
        crate::committed_disclosure::disclose_to_member_in_connection(conn, full, caller)
            .await?
            .into_iter();
    items
        .into_iter()
        .map(|item| match item {
            CommittedEventView::Full(_) => disclosed.next().ok_or_else(|| {
                PersistenceError::Internal("member disclosure dropped a row".to_owned())
            }),
            withheld @ CommittedEventView::Withheld(_) => Ok(withheld),
        })
        .collect()
}

async fn realm_history_access(
    conn: &mut AsyncPgConnection,
    realm_id: &arkret_wire::RealmId,
) -> PersistenceResult<Option<String>> {
    Ok(sql_query(
        "SELECT value FROM realm_bootstrap_current_results \
         WHERE realm_id=$1 AND result_family='realm_history_access'",
    )
    .bind::<Text, _>(realm_id.as_str())
    .get_result::<ValueRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?
    .and_then(|row| row.value.as_str().map(ToOwned::to_owned)))
}

/// The genesis readable floor of the Realm stream this governing Station
/// holds from position 0.
async fn genesis_floor_in_connection(
    conn: &mut AsyncPgConnection,
    realm_id: &arkret_wire::RealmId,
) -> PersistenceResult<Option<ReadableFloor>> {
    Ok(crate::authority_commit::stream_page_in_connection(
        conn,
        &StreamScanRequest {
            realm_id: realm_id.clone(),
            stream_ref: CommitStreamRef::Realm {
                realm_id: realm_id.clone(),
            },
            direction: arkret_wire::StreamScanDirection::After(None),
            limit: 1,
        },
    )
    .await?
    .readable_floor)
}

/// The readable floor a member joined by the Commit `join_commit_id` at
/// `join_position` has on the Realm stream (`history-visibility.md` §3.1,
/// decision 0108 §1045), or `None` when it is not provable here.
///
/// Under `all_history_for_current_members` a joined member reads from the
/// genesis Commit. Under `since_join` the floor is the join Commit itself
/// (`membership_join`), unless that join was accepted in the same atomic
/// bootstrap unit as position 0 -- the founding creator -- whose floor is
/// the genesis Commit (`stream_start`).
async fn join_floor_in_connection(
    conn: &mut AsyncPgConnection,
    realm_id: &arkret_wire::RealmId,
    genesis_floor: &ReadableFloor,
    join_commit_id: &str,
    join_position: i64,
) -> PersistenceResult<Option<ReadableFloor>> {
    match realm_history_access(conn, realm_id).await?.as_deref() {
        Some("all_history_for_current_members") => return Ok(Some(genesis_floor.clone())),
        Some("since_join") => {}
        _ => return Ok(None),
    }
    let founding = sql_query(
        "SELECT EXISTS (SELECT 1 FROM ordinary_realm_bootstrap_units u \
         CROSS JOIN LATERAL jsonb_array_elements(u.commits_json) c \
         WHERE u.realm_id=$1 AND c->>'commit_id'=$2) AS present",
    )
    .bind::<Text, _>(realm_id.as_str())
    .bind::<Text, _>(join_commit_id)
    .get_result::<PresentRow>(&mut *conn)
    .await
    .map_err(PersistenceError::database)?;
    if founding.present {
        return Ok(Some(genesis_floor.clone()));
    }
    held_join_floor(conn, realm_id, join_commit_id, join_position).await
}

/// The `membership_join` floor at a join Commit this Station holds on the
/// Realm stream.
async fn held_join_floor(
    conn: &mut AsyncPgConnection,
    realm_id: &arkret_wire::RealmId,
    join_commit_id: &str,
    join_position: i64,
) -> PersistenceResult<Option<ReadableFloor>> {
    let realm_stream = CommitStreamRef::Realm {
        realm_id: realm_id.clone(),
    };
    let on_stream = sql_query(
        "SELECT EXISTS (SELECT 1 FROM realm_commits \
         WHERE commit_id=$1 AND stream_key=$2 AND stream_position=$3) AS present",
    )
    .bind::<Text, _>(join_commit_id)
    .bind::<Text, _>(crate::authority_commit::stream_key(&realm_stream)?)
    .bind::<BigInt, _>(join_position)
    .get_result::<PresentRow>(&mut *conn)
    .await
    .map_err(PersistenceError::database)?;
    if !on_stream.present {
        return Ok(None);
    }
    Ok(Some(ReadableFloor {
        oldest_position: u64::try_from(join_position).map_err(|_| {
            PersistenceError::Internal("stored join position is negative".to_owned())
        })?,
        floor_commit_id: join_commit_id.parse().map_err(|error| {
            PersistenceError::Internal(format!("stored join Commit id is invalid: {error}"))
        })?,
        floor_reason: ReadableFloorReason::MembershipJoin,
    }))
}

async fn current_join(
    conn: &mut AsyncPgConnection,
    realm_id: &arkret_wire::RealmId,
    member: &ActorId,
) -> PersistenceResult<Option<JoinRow>> {
    Ok(sql_query(
        "SELECT membership, current_commit_id, current_stream_position \
         FROM member_state_current_results WHERE realm_id=$1 AND member_id=$2",
    )
    .bind::<Text, _>(realm_id.as_str())
    .bind::<Text, _>(member.to_string())
    .get_result::<JoinRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?
    .filter(|row| row.membership == "join"))
}

/// The caller's readable floor on the Realm stream at this governing read
/// cut, or `None` when it is not provable here. A member that left and
/// rejoined reads only from its current join.
pub(crate) async fn caller_realm_floor_in_connection(
    conn: &mut AsyncPgConnection,
    realm_id: &arkret_wire::RealmId,
    caller: &ActorId,
) -> PersistenceResult<Option<ReadableFloor>> {
    let Some(genesis_floor) = genesis_floor_in_connection(conn, realm_id).await? else {
        return Ok(None);
    };
    let Some(join) = current_join(conn, realm_id, caller).await? else {
        return Ok(None);
    };
    join_floor_in_connection(
        conn,
        realm_id,
        &genesis_floor,
        &join.current_commit_id,
        join.current_stream_position,
    )
    .await
}

#[derive(QueryableByName)]
struct ReplicaAnchorRow {
    #[diesel(sql_type = diesel::sql_types::Nullable<Text>)]
    anchor_commit_id: Option<String>,
    #[diesel(sql_type = BigInt)]
    join_position: i64,
}

/// The caller's readable floor on a Realm stream this member Station holds
/// as an anchored replica: under `since_join` its own held join Commit, at
/// or after the join that opened the held stream. Earlier history is not
/// held here, so any other interval is unproved.
async fn replica_realm_floor_in_connection(
    conn: &mut AsyncPgConnection,
    realm_id: &arkret_wire::RealmId,
    caller: &ActorId,
) -> PersistenceResult<Result<ReadableFloor, &'static str>> {
    let Some(anchor) = sql_query(
        "SELECT a.anchor_commit_id, c.stream_position AS join_position \
         FROM replica_stream_anchors a JOIN realm_commits c ON c.commit_id=a.join_commit_id \
         WHERE a.realm_id=$1",
    )
    .bind::<Text, _>(realm_id.as_str())
    .get_result::<ReplicaAnchorRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?
    else {
        return Ok(Err(
            "this Station neither governs nor holds the Realm stream",
        ));
    };
    if anchor.anchor_commit_id.is_none() {
        return Ok(Err("the held Realm stream is pending its bootstrap anchor"));
    }
    if realm_history_access(conn, realm_id).await?.as_deref() != Some("since_join") {
        return Ok(Err(
            "the history before this Station's held join is not held here",
        ));
    }
    let Some(join) = current_join(conn, realm_id, caller).await? else {
        return Ok(Err("the caller has no held join"));
    };
    if join.current_stream_position < anchor.join_position {
        return Ok(Err(
            "the caller's join precedes the Realm stream this Station holds",
        ));
    }
    Ok(held_join_floor(
        conn,
        realm_id,
        &join.current_commit_id,
        join.current_stream_position,
    )
    .await?
    .ok_or("the caller's join Commit is not held"))
}

#[derive(QueryableByName)]
struct PriorJoinRow {
    #[diesel(sql_type = Text)]
    commit_id: String,
    #[diesel(sql_type = BigInt)]
    stream_position: i64,
    #[diesel(sql_type = Text)]
    kind: String,
    #[diesel(sql_type = diesel::sql_types::Nullable<Text>)]
    membership: Option<String>,
}

#[derive(QueryableByName)]
struct HostedMemberRow {
    #[diesel(sql_type = Text)]
    member_id: String,
    #[diesel(sql_type = Text)]
    membership: String,
    #[diesel(sql_type = Text)]
    current_commit_id: String,
    #[diesel(sql_type = BigInt)]
    current_stream_position: i64,
}

/// One interval of a peer Station's replication right on the Realm stream:
/// from `floor` through `last` (to the head when `None`).
struct PeerInterval {
    floor: ReadableFloor,
    last: Option<u64>,
}

impl PeerInterval {
    fn covers(&self, position: u64) -> bool {
        position >= self.floor.oldest_position && self.last.is_none_or(|last| position <= last)
    }
}

/// The membership Event that preceded `terminal_position` for `member`, when
/// it was a join (`ak.member.state{join}` or the member's `ak.invite.accept`).
async fn prior_join(
    conn: &mut AsyncPgConnection,
    realm_id: &arkret_wire::RealmId,
    member: &str,
    terminal_position: i64,
) -> PersistenceResult<Option<PriorJoinRow>> {
    let realm_stream = CommitStreamRef::Realm {
        realm_id: realm_id.clone(),
    };
    Ok(sql_query(
        "SELECT c.commit_id, c.stream_position, e.kind, \
                e.envelope->'payload'->>'membership' AS membership \
         FROM realm_commits c JOIN canonical_events e ON e.pk=c.event_pk \
         WHERE c.stream_key=$1 AND c.stream_position < $2 AND e.state='committed' AND ( \
           (e.kind='ak.member.state' AND e.envelope->'payload'->'member_id'=$3::jsonb) \
           OR (e.kind='ak.invite.accept' AND e.envelope->'actor_id'=$3::jsonb)) \
         ORDER BY c.stream_position DESC LIMIT 1",
    )
    .bind::<Text, _>(crate::authority_commit::stream_key(&realm_stream)?)
    .bind::<BigInt, _>(terminal_position)
    .bind::<Text, _>(member)
    .get_result::<PriorJoinRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?
    .filter(|row| {
        row.kind == arkret_wire::EventKind::InviteAccept.as_str()
            || row.membership.as_deref() == Some("join")
    }))
}

/// Every interval of `peer`'s replication right on the Realm stream at this
/// governing cut, with the members routed to it.
async fn peer_intervals(
    conn: &mut AsyncPgConnection,
    realm_id: &arkret_wire::RealmId,
    peer: &DidCoreId,
) -> PersistenceResult<(Vec<PeerInterval>, Vec<ActorId>)> {
    let rows = sql_query(
        "SELECT member_id, membership, current_commit_id, current_stream_position \
         FROM member_state_current_results WHERE realm_id=$1 ORDER BY member_id",
    )
    .bind::<Text, _>(realm_id.as_str())
    .load::<HostedMemberRow>(&mut *conn)
    .await
    .map_err(PersistenceError::database)?;
    let mut hosted = Vec::new();
    for row in rows {
        let member: ActorId = serde_json::from_str(&row.member_id).map_err(|error| {
            PersistenceError::Internal(format!("stored member ActorId is invalid: {error}"))
        })?;
        if member.route_service_id() == peer {
            hosted.push((member, row));
        }
    }
    let mut intervals = Vec::new();
    let mut joined = Vec::new();
    if hosted.is_empty() {
        return Ok((intervals, joined));
    }
    let Some(genesis_floor) = genesis_floor_in_connection(conn, realm_id).await? else {
        return Ok((intervals, joined));
    };
    for (member, row) in hosted {
        match row.membership.as_str() {
            "join" => {
                if let Some(floor) = join_floor_in_connection(
                    conn,
                    realm_id,
                    &genesis_floor,
                    &row.current_commit_id,
                    row.current_stream_position,
                )
                .await?
                {
                    intervals.push(PeerInterval { floor, last: None });
                }
                joined.push(member);
            }
            // A leave or ban that ended the member's joined state keeps the
            // right through that terminating Commit (`federation.md` §4.1.1).
            "leave" | "ban" => {
                let Some(join) =
                    prior_join(conn, realm_id, &row.member_id, row.current_stream_position).await?
                else {
                    continue;
                };
                if let Some(floor) = join_floor_in_connection(
                    conn,
                    realm_id,
                    &genesis_floor,
                    &join.commit_id,
                    join.stream_position,
                )
                .await?
                {
                    intervals.push(PeerInterval {
                        floor,
                        last: Some(u64::try_from(row.current_stream_position).map_err(|_| {
                            PersistenceError::Internal(
                                "stored membership position is negative".to_owned(),
                            )
                        })?),
                    });
                }
            }
            _ => {}
        }
    }
    Ok((intervals, joined))
}

/// Whether `peer` may hold the complete canonical bytes of `event` at this
/// cut: the same content rule the fanout target set applies.
async fn peer_holds_full_event(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    peer: &DidCoreId,
    joined: &[ActorId],
    at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<bool> {
    if crate::realm_fanout::plaintext_message(event) {
        let services = sql_query(
            "SELECT value FROM realm_bootstrap_current_results \
             WHERE realm_id=$1 AND result_family='realm_plaintext_visible_services'",
        )
        .bind::<Text, _>(event.realm_id.as_str())
        .get_result::<ValueRow>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?
        .map(|row| crate::realm_fanout::plaintext_message_service_ids(&row.value))
        .unwrap_or_default();
        if !services.iter().any(|service| service == peer.as_str()) {
            return Ok(false);
        }
    }
    if event.kind == arkret_wire::EventKind::SelfModerationReport {
        for member in joined {
            if crate::capability_grant_current_results::actor_holds_realm_action_in_connection(
                conn,
                &event.realm_id,
                member,
                &[
                    arkret_wire::CapabilityActionId::POLICY_MANAGE,
                    arkret_wire::CapabilityActionId::MODERATION_DECISION,
                ],
                at,
            )
            .await?
            {
                return Ok(true);
            }
        }
        return Ok(false);
    }
    Ok(true)
}

pub(crate) async fn scan_stream_for_peer(
    pool: &PgPool,
    request: &StreamScanRequest,
    peer: &DidCoreId,
    issuer: &DidCoreId,
) -> PersistenceResult<AccountStreamScan> {
    request
        .validate()
        .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
    let mut conn = pg_conn(pool).await?;
    conn.transaction::<_, PgTransactionError, _>(async move |conn| {
        sql_query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
            .execute(&mut *conn)
            .await?;
        let Some(tenure) = sql_query("SELECT service_id FROM realm_authorities WHERE realm_id=$1")
            .bind::<Text, _>(request.realm_id.as_str())
            .get_result::<TenureRow>(&mut *conn)
            .await
            .optional()?
        else {
            return Ok(AccountStreamScan::NotAuthorized);
        };
        if tenure.service_id != issuer.as_str() {
            return Ok(AccountStreamScan::Unproved(
                "this Station does not hold the Realm's governing tenure",
            ));
        }
        let (intervals, joined) = peer_intervals(conn, &request.realm_id, peer).await?;
        let Some(lowest) = intervals
            .iter()
            .min_by_key(|interval| interval.floor.oldest_position)
        else {
            return Ok(AccountStreamScan::NotAuthorized);
        };
        if request.stream_ref
            != (CommitStreamRef::Realm {
                realm_id: request.realm_id.clone(),
            })
        {
            return Ok(AccountStreamScan::Unproved(
                "Circle and Sidecar stream visibility is not proved at this cut",
            ));
        }
        let floor = lowest.floor.clone();
        let last = if intervals.iter().any(|interval| interval.last.is_none()) {
            None
        } else {
            intervals.iter().filter_map(|interval| interval.last).max()
        };
        // A right that ends at a terminating Commit reads nothing after it.
        let mut bounded = request.clone();
        if let (Some(last), arkret_wire::StreamScanDirection::Before(before)) =
            (last, request.direction)
        {
            let cap = last.saturating_add(1);
            bounded.direction =
                arkret_wire::StreamScanDirection::Before(Some(before.map_or(cap, |p| p.min(cap))));
        }
        let mut page = crate::authority_commit::stream_page_above_floor_in_connection(
            conn,
            &bounded,
            Some(floor),
        )
        .await?;
        if let Some(last) = last
            && page
                .committed_events
                .iter()
                .any(|item| item.commit().stream_position >= last)
        {
            page.committed_events
                .retain(|item| item.commit().stream_position <= last);
            page.truncated = false;
        }
        // A position outside every interval is not this peer's to read, not
        // even as a Commit: the page stops before it.
        if let Some(cut) = page.committed_events.iter().position(|item| {
            !intervals
                .iter()
                .any(|interval| interval.covers(item.commit().stream_position))
        }) {
            page.committed_events.truncate(cut);
            page.truncated = false;
        }
        let at = chrono::Utc::now();
        let mut full = Vec::new();
        let mut withheld = std::collections::BTreeSet::new();
        for item in &page.committed_events {
            let CommittedEventView::Full(view) = item else {
                return Err(PgTransactionError::from(PersistenceError::Internal(
                    "a governing stream page holds only full rows".to_owned(),
                )));
            };
            if !peer_holds_full_event(conn, &view.event, peer, &joined, at).await? {
                withheld.insert(view.commit.commit_id.clone());
            }
            full.push(view.clone());
        }
        let committed_events = crate::committed_disclosure::disclose_in_connection(conn, full)
            .await?
            .into_iter()
            .map(|item| match item {
                CommittedEventView::Full(view) if withheld.contains(&view.commit.commit_id) => {
                    CommittedEventView::Withheld(arkret_wire::CommittedEventWithheldView {
                        commit: view.commit,
                        event_disclosure: arkret_wire::EventDisclosure {
                            status: arkret_wire::EventDisclosureStatus::Withheld,
                        },
                    })
                }
                other => other,
            })
            .collect();
        Ok(AccountStreamScan::Page(StreamScanOutcome {
            committed_events,
            ..page
        }))
    })
    .await
    .map_err(PgTransactionError::into_persistence)
}
