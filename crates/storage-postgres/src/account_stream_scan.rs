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
//! A peer Station's replication right on a stream derives from the currently
//! joined members routed to it. That founding shape never has a remote member,
//! so no peer interval is provable here yet: a peer hosting no joined member is
//! refused, and a peer hosting one fails closed as unproved.

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
        if tenure.service_id != issuer.as_str() {
            return Ok(AccountStreamScan::Unproved(
                "this Station does not hold the Realm's governing tenure",
            ));
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
        let Some(floor) =
            caller_realm_floor_in_connection(conn, &request.realm_id, &caller_actor).await?
        else {
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
        let mut rows = Vec::with_capacity(page.committed_events.len());
        for item in page.committed_events {
            let CommittedEventView::Full(view) = item else {
                return Err(PgTransactionError::from(PersistenceError::Internal(
                    "a physical stream page holds only full rows".to_owned(),
                )));
            };
            rows.push(view);
        }
        // Per-Event disclosure applies on top of the interval: a withheld row
        // keeps its Commit so the page stays one verifiable chain.
        let committed_events = crate::committed_disclosure::disclose_to_member_in_connection(
            conn,
            rows,
            &caller_actor,
        )
        .await?;
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

/// The caller's readable floor on the Realm stream at this read cut
/// (`history-visibility.md` §3.1, decision 0108 §1045), or `None` when it is
/// not provable here.
///
/// Under `all_history_for_current_members` a joined member reads from the
/// genesis Commit. Under `since_join` the floor is the caller's current join
/// Commit itself (`membership_join`), unless that join was accepted in the
/// same atomic bootstrap unit as position 0 -- the founding creator -- whose
/// floor is the genesis Commit (`stream_start`). A member that left and
/// rejoined reads only from its current join.
pub(crate) async fn caller_realm_floor_in_connection(
    conn: &mut AsyncPgConnection,
    realm_id: &arkret_wire::RealmId,
    caller: &ActorId,
) -> PersistenceResult<Option<ReadableFloor>> {
    let realm_stream = CommitStreamRef::Realm {
        realm_id: realm_id.clone(),
    };
    let genesis = crate::authority_commit::stream_page_in_connection(
        conn,
        &StreamScanRequest {
            realm_id: realm_id.clone(),
            stream_ref: realm_stream.clone(),
            direction: arkret_wire::StreamScanDirection::After(None),
            limit: 1,
        },
    )
    .await?;
    let Some(genesis_floor) = genesis.readable_floor else {
        return Ok(None);
    };
    let Some(join) = sql_query(
        "SELECT membership, current_commit_id, current_stream_position \
         FROM member_state_current_results WHERE realm_id=$1 AND member_id=$2",
    )
    .bind::<Text, _>(realm_id.as_str())
    .bind::<Text, _>(caller.to_string())
    .get_result::<JoinRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?
    .filter(|row| row.membership == "join") else {
        return Ok(None);
    };
    let history_access = sql_query(
        "SELECT value FROM realm_bootstrap_current_results \
         WHERE realm_id=$1 AND result_family='realm_history_access'",
    )
    .bind::<Text, _>(realm_id.as_str())
    .get_result::<ValueRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?;
    match history_access.as_ref().and_then(|row| row.value.as_str()) {
        Some("all_history_for_current_members") => return Ok(Some(genesis_floor)),
        Some("since_join") => {}
        _ => return Ok(None),
    }
    let founding = sql_query(
        "SELECT EXISTS (SELECT 1 FROM ordinary_realm_bootstrap_units u \
         CROSS JOIN LATERAL jsonb_array_elements(u.commits_json) c \
         WHERE u.realm_id=$1 AND c->>'commit_id'=$2) AS present",
    )
    .bind::<Text, _>(realm_id.as_str())
    .bind::<Text, _>(&join.current_commit_id)
    .get_result::<PresentRow>(&mut *conn)
    .await
    .map_err(PersistenceError::database)?;
    if founding.present {
        return Ok(Some(genesis_floor));
    }
    let on_stream = sql_query(
        "SELECT EXISTS (SELECT 1 FROM realm_commits \
         WHERE commit_id=$1 AND stream_key=$2 AND stream_position=$3) AS present",
    )
    .bind::<Text, _>(&join.current_commit_id)
    .bind::<Text, _>(crate::authority_commit::stream_key(&realm_stream)?)
    .bind::<BigInt, _>(join.current_stream_position)
    .get_result::<PresentRow>(&mut *conn)
    .await
    .map_err(PersistenceError::database)?;
    if !on_stream.present {
        return Ok(None);
    }
    Ok(Some(ReadableFloor {
        oldest_position: u64::try_from(join.current_stream_position).map_err(|_| {
            PersistenceError::Internal("stored join position is negative".to_owned())
        })?,
        floor_commit_id: join.current_commit_id.parse().map_err(|error| {
            PersistenceError::Internal(format!("stored join Commit id is invalid: {error}"))
        })?,
        floor_reason: ReadableFloorReason::MembershipJoin,
    }))
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
        let members = sql_query(
            "SELECT member_id, membership FROM member_state_current_results \
             WHERE realm_id=$1 AND membership='join' ORDER BY member_id",
        )
        .bind::<Text, _>(request.realm_id.as_str())
        .load::<MemberRow>(&mut *conn)
        .await?;
        let mut hosts_member = false;
        for row in &members {
            let member: ActorId = serde_json::from_str(&row.member_id).map_err(|error| {
                PersistenceError::Internal(format!("stored member ActorId is invalid: {error}"))
            })?;
            hosts_member |= member.route_service_id() == peer;
        }
        if !hosts_member {
            return Ok(AccountStreamScan::NotAuthorized);
        }
        if tenure.service_id != issuer.as_str() {
            return Ok(AccountStreamScan::Unproved(
                "this Station does not hold the Realm's governing tenure",
            ));
        }
        Ok(AccountStreamScan::Unproved(
            "the peer's join floor, history access and canonical-byte disclosure are not proved \
             at this cut",
        ))
    })
    .await
    .map_err(PgTransactionError::into_persistence)
}
