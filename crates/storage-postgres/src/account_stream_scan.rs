//! Caller-scoped `ak.self.committed_event.read.scan.v1` and
//! `ak.peer.committed_event.read.scan.v1` at one read cut.
//!
//! The caller's readable interval is a protocol decision of the current
//! governing Station: membership join floor, history-access policy, retention
//! and per-Event disclosure all bound it. This Station proves exactly one
//! interval shape today: the sole founding member of a Realm reading that
//! Realm's stream. Its whole accepted chain was produced by the caller, so the
//! interval starts at the genesis Commit (`stream_start`) and every row is
//! disclosable in full. Any other shape fails closed as unproved rather than
//! serving a physical page.
//!
//! A peer Station's replication right on a stream derives from the currently
//! joined members routed to it. That founding shape never has a remote member,
//! so no peer interval is provable here yet: a peer hosting no joined member is
//! refused, and a peer hosting one fails closed as unproved.

use arkret_wire::{
    AccountId, ActorId, CommitStreamRef, CommittedEventView, DidCoreId, ReadableFloorReason,
    StreamScanRequest,
};
use soland_storage::AccountStreamScan;

use super::{
    AsyncConnection, OptionalExtension, PersistenceError, PersistenceResult, PgPool,
    PgTransactionError, QueryableByName, RunQueryDsl, Text, pg_conn, sql_query,
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
        if members.len() != 1 {
            return Ok(AccountStreamScan::Unproved(
                "a per-member join or history floor is not proved at this cut",
            ));
        }
        let genesis = crate::authority_commit::stream_page_in_connection(
            conn,
            &StreamScanRequest {
                realm_id: request.realm_id.clone(),
                stream_ref: request.stream_ref.clone(),
                direction: arkret_wire::StreamScanDirection::After(None),
                limit: 1,
            },
        )
        .await?;
        let founded_by_caller = match <[_]>::first(&genesis.committed_events) {
            Some(CommittedEventView::Full(view)) => {
                view.commit.stream_position == 0
                    && view.event.kind == arkret_wire::EventKind::RealmCreate
                    && view.event.actor_id.to_string() == caller
            }
            _ => false,
        };
        if !founded_by_caller {
            return Ok(AccountStreamScan::Unproved(
                "the caller is not the Realm's sole founding member",
            ));
        }
        let page = crate::authority_commit::stream_page_in_connection(conn, request).await?;
        let floor_is_genesis = page.readable_floor.as_ref().is_some_and(|floor| {
            floor.oldest_position == 0
                && floor.floor_reason == ReadableFloorReason::StreamStart
                && Some(&floor.floor_commit_id)
                    == <[_]>::first(&genesis.committed_events).map(|item| &item.commit().commit_id)
        });
        if !floor_is_genesis {
            return Ok(AccountStreamScan::Unproved(
                "the founding interval has no retained genesis floor",
            ));
        }
        // Every disclosed row must be the caller's own Event; anything else
        // means the sole-founder proof does not describe this stream.
        if page.committed_events.iter().any(|item| match item {
            CommittedEventView::Full(view) => view.event.actor_id.to_string() != caller,
            _ => true,
        }) {
            return Ok(AccountStreamScan::Unproved(
                "a stream row was produced outside the sole-founder interval",
            ));
        }
        Ok(AccountStreamScan::Page(page))
    })
    .await
    .map_err(PgTransactionError::into_persistence)
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
