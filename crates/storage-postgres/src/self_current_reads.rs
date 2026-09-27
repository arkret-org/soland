//! Authenticated, non-enumerating self reads decided at one governing read
//! cut: `ak.self.realm.read.streams.v1`,
//! `ak.self.current_results.read.exact.v1`,
//! `ak.self.strand.watch.read.current.v1` and the anchor half of
//! `ak.self.media_service_binding.read.resolve.v1`.
//!
//! Every read opens one repeatable-read transaction that fixes the Realm's
//! governing tenure, the caller's membership and the stream heads together.
//! An unknown Realm and a caller that is not a currently joined member share
//! the universal `not_found`. The only disclosure shape this Station proves is
//! a Realm whose sole established stream is the Realm stream: every object of
//! such a Realm lives in the Realm-wide scope that each joined member may
//! read. A Realm with any Circle or Sidecar stream fails closed as unresolved
//! until scope visibility is provable, and no `never_written` answer is ever
//! inferred from a missing row.

use arkret_models_collaboration::exact_current_results::{
    ExactCurrentResultEntry, ExactCurrentResultSelector, ExactCurrentResultsReadOutcome,
    ExactCurrentResultsReadRequestBody, ModerationStateCurrentValue,
    ModerationStateExactCurrentResult, ModerationStateExactCurrentSelector,
    RelationExactCurrentResult,
};
use arkret_models_collaboration::objects::relation::Relation;
use arkret_models_collaboration::strand_watch_operations::{
    StrandWatchCurrentOutcome, StrandWatchCurrentRequestBody, StrandWatchCurrentResult,
    StrandWatchCurrentSelector, StrandWatchSelectorKind,
};
use arkret_wire::{
    AccountId, ActorId, CommitStreamHead, CommitStreamRef, CurrentRevision, DidCoreId, RealmId,
    RealmStreamRow, ScopeRef,
};
use diesel_async::AsyncPgConnection;
use soland_storage::{AccountRealmStreamList, MediaServiceAnchorRead, SelfExactCurrentRead};

use super::{
    AsyncConnection, BigInt, ExistsRow, Jsonb, OptionalExtension, PersistenceError,
    PersistenceResult, PgPool, PgTransactionError, QueryableByName, RunQueryDsl, Text, pg_conn,
    sql_query,
};

#[derive(QueryableByName)]
struct TenureRow {
    #[diesel(sql_type = BigInt)]
    generation: i64,
    #[diesel(sql_type = Text)]
    service_id: String,
}

pub(crate) const RELATION_CURRENT_SQL: &str = "SELECT r.current_commit_id, r.current_stream_position, r.value, c.stream_ref \
             FROM relation_current_results r \
             JOIN realm_commits c ON c.commit_id = r.current_commit_id \
             WHERE r.realm_id=$1 AND r.domain_key=$2 AND c.realm_id=r.realm_id \
               AND c.stream_position=r.current_stream_position";

pub(crate) const MODERATION_CURRENT_SQL: &str = "SELECT s.current_commit_id, s.current_stream_position, s.value, c.stream_ref \
         FROM moderation_state_current_results s \
         JOIN realm_commits c ON c.commit_id = s.current_commit_id \
         WHERE s.realm_id=$1 AND s.target_ref=$2 AND c.realm_id=s.realm_id \
           AND c.stream_position=s.current_stream_position";

pub(crate) const MEMBER_PRESENT_SQL: &str = "SELECT EXISTS(SELECT 1 FROM member_state_current_results \
     WHERE realm_id=$1 AND member_id=$2 AND membership='join') AS present";

pub(crate) const WATCH_CURRENT_SQL: &str = "SELECT w.current_commit_id,w.current_stream_position,w.value,c.stream_ref FROM strand_watch_current_results w JOIN realm_commits c ON c.commit_id=w.current_commit_id WHERE w.realm_id=$1 AND w.strand_id=$2 AND w.watcher_actor_id=$3 AND c.realm_id=w.realm_id AND c.stream_position=w.current_stream_position";

// Probe the adjacent keys on both sides of the Realm stream. Tuple bounds
// keep each probe on the Realm-prefixed index. Scalar ORDER BY/LIMIT prevents
// EXISTS from discarding that order and choosing a history scan instead.
pub(crate) const SCOPED_STREAMS_SQL: &str = "SELECT ( \
    (SELECT stream_key FROM realm_commits \
     WHERE realm_id=$1 AND (realm_id,stream_key)<($1,$2) \
     ORDER BY realm_id DESC,stream_key DESC LIMIT 1) IS NOT NULL OR \
    (SELECT stream_key FROM realm_commits \
     WHERE realm_id=$1 AND (realm_id,stream_key)>($1,$2) \
     ORDER BY realm_id,stream_key LIMIT 1) IS NOT NULL) AS present";

pub(crate) const MEDIA_ANCHOR_SQL: &str = "SELECT EXISTS(SELECT 1 FROM realm_commit_event_kinds \
     WHERE realm_id=$1 AND kind=$2) AS present";

#[derive(QueryableByName)]
struct HeadRow {
    #[diesel(sql_type = Text)]
    commit_id: String,
    #[diesel(sql_type = BigInt)]
    stream_position: i64,
}

/// One typed current row with the stream of its covering RealmCommit.
#[derive(QueryableByName)]
struct CurrentRow {
    #[diesel(sql_type = Text)]
    current_commit_id: String,
    #[diesel(sql_type = BigInt)]
    current_stream_position: i64,
    #[diesel(sql_type = Jsonb)]
    value: serde_json::Value,
    #[diesel(sql_type = Jsonb)]
    stream_ref: serde_json::Value,
}

/// The caller-visible facts every read in this module starts from.
enum MemberCut {
    /// Unknown Realm or not a currently joined member.
    NotVisible,
    /// A joined member of a Realm whose governing tenure is not `issuer`.
    ForeignTenure,
    Member {
        generation: u64,
        /// Head of the Realm stream; `None` before the genesis Commit.
        realm_head: Option<CommitStreamHead>,
        /// Whether any Circle or Sidecar stream has an established chain.
        scoped_streams: bool,
    },
}

fn corrupt(detail: impl Into<String>) -> PersistenceError {
    PersistenceError::Database(detail.into())
}

fn to_u64(value: i64, what: &str) -> PersistenceResult<u64> {
    u64::try_from(value).map_err(|_| corrupt(format!("stored {what} is negative")))
}

async fn begin_read_cut(conn: &mut AsyncPgConnection) -> Result<(), PgTransactionError> {
    sql_query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        .execute(conn)
        .await?;
    Ok(())
}

async fn member_cut(
    conn: &mut AsyncPgConnection,
    realm_id: &RealmId,
    caller: &ActorId,
    issuer: &DidCoreId,
) -> Result<MemberCut, PgTransactionError> {
    let Some(tenure) =
        sql_query("SELECT generation, service_id FROM realm_authorities WHERE realm_id=$1")
            .bind::<Text, _>(realm_id.as_str())
            .get_result::<TenureRow>(&mut *conn)
            .await
            .optional()?
    else {
        return Ok(MemberCut::NotVisible);
    };
    let joined = sql_query(MEMBER_PRESENT_SQL)
        .bind::<Text, _>(realm_id.as_str())
        .bind::<Text, _>(caller.to_string())
        .get_result::<ExistsRow>(&mut *conn)
        .await?
        .present;
    if !joined {
        return Ok(MemberCut::NotVisible);
    }
    if tenure.service_id != issuer.as_str() {
        return Ok(MemberCut::ForeignTenure);
    }
    let realm_stream = CommitStreamRef::Realm {
        realm_id: realm_id.clone(),
    };
    let realm_key = crate::authority_commit::stream_key(&realm_stream)?;
    let realm_head = sql_query(
        "SELECT commit_id, stream_position FROM realm_commits \
         WHERE realm_id=$1 AND stream_key=$2 ORDER BY stream_position DESC LIMIT 1",
    )
    .bind::<Text, _>(realm_id.as_str())
    .bind::<Text, _>(&realm_key)
    .get_result::<HeadRow>(&mut *conn)
    .await
    .optional()?
    .map(|row| {
        Ok::<_, PersistenceError>(CommitStreamHead {
            stream_ref: realm_stream.clone(),
            stream_position: to_u64(row.stream_position, "Realm stream position")?,
            commit_id: row
                .commit_id
                .parse()
                .map_err(|error| corrupt(format!("stored RealmCommit id is invalid: {error}")))?,
        })
    })
    .transpose()?;
    let scoped_streams = sql_query(SCOPED_STREAMS_SQL)
        .bind::<Text, _>(realm_id.as_str())
        .bind::<Text, _>(&realm_key)
        .get_result::<ExistsRow>(&mut *conn)
        .await?
        .present;
    Ok(MemberCut::Member {
        generation: to_u64(tenure.generation, "governance generation")?,
        realm_head,
        scoped_streams,
    })
}

pub(crate) async fn list_realm_streams_for_account(
    pool: &PgPool,
    realm_id: &RealmId,
    account: &AccountId,
    issuer: &DidCoreId,
) -> PersistenceResult<AccountRealmStreamList> {
    let caller = ActorId::account(account.clone());
    let mut conn = pg_conn(pool).await?;
    conn.transaction::<_, PgTransactionError, _>(async move |conn| {
        begin_read_cut(conn).await?;
        let (realm_head, scoped_streams) = match member_cut(conn, realm_id, &caller, issuer).await?
        {
            MemberCut::NotVisible => return Ok(AccountRealmStreamList::NotVisible),
            MemberCut::ForeignTenure => {
                return Ok(AccountRealmStreamList::Unproved(
                    "this Station does not hold the Realm's governing tenure",
                ));
            }
            MemberCut::Member {
                realm_head,
                scoped_streams,
                ..
            } => (realm_head, scoped_streams),
        };
        if scoped_streams {
            return Ok(AccountRealmStreamList::Unproved(
                "Circle and Sidecar stream visibility is not proved at this cut",
            ));
        }
        let Some(head) = realm_head else {
            return Ok(AccountRealmStreamList::Listed(Vec::new()));
        };
        let Some(floor) =
            crate::account_stream_scan::caller_realm_floor_in_connection(conn, realm_id, &caller)
                .await?
        else {
            return Ok(AccountRealmStreamList::Unproved(
                "a per-member join or history floor is not proved at this cut",
            ));
        };
        Ok(AccountRealmStreamList::Listed(vec![RealmStreamRow {
            stream_ref: head.stream_ref,
            head_commit_ref: head.commit_id,
            next_position: head.stream_position.checked_add(1).ok_or_else(|| {
                PersistenceError::Internal("Realm stream position overflows".to_owned())
            })?,
            readable_floor: Some(floor),
        }]))
    })
    .await
    .map_err(PgTransactionError::into_persistence)
}

pub(crate) async fn exact_current_result_for_account(
    pool: &PgPool,
    request: &ExactCurrentResultsReadRequestBody,
    account: &AccountId,
    issuer: &DidCoreId,
) -> PersistenceResult<SelfExactCurrentRead<ExactCurrentResultsReadOutcome>> {
    request
        .validate()
        .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
    let caller = ActorId::account(account.clone());
    let mut conn = pg_conn(pool).await?;
    conn.transaction::<_, PgTransactionError, _>(async move |conn| {
        begin_read_cut(conn).await?;
        let (generation, head) = match member_cut(conn, &request.realm_id, &caller, issuer).await? {
            MemberCut::NotVisible => return Ok(SelfExactCurrentRead::NotFound),
            MemberCut::ForeignTenure => {
                return Ok(SelfExactCurrentRead::Unresolved(
                    "this Station does not hold the Realm's governing tenure",
                ));
            }
            MemberCut::Member {
                scoped_streams: true,
                ..
            } => {
                return Ok(SelfExactCurrentRead::Unresolved(
                    "Circle and Sidecar scope visibility is not proved at this cut",
                ));
            }
            MemberCut::Member {
                realm_head: None, ..
            } => {
                return Ok(SelfExactCurrentRead::Unresolved(
                    "the Realm stream has no established head",
                ));
            }
            MemberCut::Member {
                generation,
                realm_head: Some(head),
                ..
            } => (generation, head),
        };
        let selector = match &request.selector {
            ExactCurrentResultSelector::Relation(selector) => selector,
            ExactCurrentResultSelector::ModerationState(selector) => {
                return moderation_state_read(conn, &request.realm_id, generation, head, selector)
                    .await;
            }
        };
        let domain_key = arkret_canonical::canonical_json_string(&selector.primary_conflict_domain)
            .map_err(|error| {
                PersistenceError::Internal(format!(
                    "Relation primary conflict domain canonicalization failed: {error}"
                ))
            })?;
        let Some(row) = sql_query(RELATION_CURRENT_SQL)
            .bind::<Text, _>(request.realm_id.as_str())
            .bind::<Text, _>(&domain_key)
            .get_result::<CurrentRow>(&mut *conn)
            .await
            .optional()?
        else {
            // Absence of a row cannot prove never_written until the domain's
            // endpoint visibility is decided at this cut.
            return Ok(SelfExactCurrentRead::Unresolved(
                "the Relation domain's endpoint visibility is not proved at this cut",
            ));
        };
        let value = serde_json::from_value::<Relation>(row.value).map_err(|error| {
            corrupt(format!("stored Relation current value is invalid: {error}"))
        })?;
        let source_stream_ref = serde_json::from_value::<CommitStreamRef>(row.stream_ref)
            .map_err(|error| corrupt(format!("stored RealmCommit stream is invalid: {error}")))?;
        let realm_scoped = matches!(
            &value.effective_scope,
            Some(ScopeRef::Realm { realm_id }) if realm_id == &request.realm_id
        );
        if !realm_scoped || source_stream_ref != head.stream_ref {
            return Ok(SelfExactCurrentRead::Unresolved(
                "the Relation's scope visibility is not proved at this cut",
            ));
        }
        let revision = CurrentRevision {
            commit_id: row.current_commit_id.parse().map_err(|error| {
                corrupt(format!("stored Relation Commit id is invalid: {error}"))
            })?,
            stream_position: to_u64(row.current_stream_position, "Relation stream position")?,
        };
        Ok(SelfExactCurrentRead::Answer(
            ExactCurrentResultsReadOutcome::Present {
                realm_id: request.realm_id.clone(),
                governance_generation: generation,
                effective_stream_head: head,
                entry: ExactCurrentResultEntry::Relation(RelationExactCurrentResult {
                    selector: selector.clone(),
                    source_stream_ref,
                    revision,
                    value,
                }),
            },
        ))
    })
    .await
    .map_err(PgTransactionError::into_persistence)
}

/// A `moderation_state` selector on the provable cut: the durable row keyed
/// by the moderated target. A target no decision ever named has nothing a
/// lift could consume, so it is the same `not_found` as an unknown target;
/// `never_written` is structurally Relation-only.
async fn moderation_state_read(
    conn: &mut AsyncPgConnection,
    realm_id: &RealmId,
    generation: u64,
    head: CommitStreamHead,
    selector: &ModerationStateExactCurrentSelector,
) -> Result<SelfExactCurrentRead<ExactCurrentResultsReadOutcome>, PgTransactionError> {
    let Some(row) = sql_query(MODERATION_CURRENT_SQL)
        .bind::<Text, _>(realm_id.as_str())
        .bind::<Text, _>(selector.target_ref.as_str())
        .get_result::<CurrentRow>(&mut *conn)
        .await
        .optional()?
    else {
        return Ok(SelfExactCurrentRead::NotFound);
    };
    let value =
        serde_json::from_value::<ModerationStateCurrentValue>(row.value).map_err(|error| {
            corrupt(format!(
                "stored moderation_state current value is invalid: {error}"
            ))
        })?;
    let source_stream_ref = serde_json::from_value::<CommitStreamRef>(row.stream_ref)
        .map_err(|error| corrupt(format!("stored RealmCommit stream is invalid: {error}")))?;
    if source_stream_ref != head.stream_ref {
        return Ok(SelfExactCurrentRead::Unresolved(
            "the moderated target's scope visibility is not proved at this cut",
        ));
    }
    let revision = CurrentRevision {
        commit_id: row.current_commit_id.parse().map_err(|error| {
            corrupt(format!(
                "stored moderation_state Commit id is invalid: {error}"
            ))
        })?,
        stream_position: to_u64(
            row.current_stream_position,
            "moderation_state stream position",
        )?,
    };
    Ok(SelfExactCurrentRead::Answer(
        ExactCurrentResultsReadOutcome::Present {
            realm_id: realm_id.clone(),
            governance_generation: generation,
            effective_stream_head: head,
            entry: ExactCurrentResultEntry::ModerationState(ModerationStateExactCurrentResult {
                selector: selector.clone(),
                source_stream_ref,
                revision,
                value,
            }),
        },
    ))
}

pub(crate) async fn strand_watch_current_for_account(
    pool: &PgPool,
    request: &StrandWatchCurrentRequestBody,
    account: &AccountId,
    issuer: &DidCoreId,
) -> PersistenceResult<SelfExactCurrentRead<StrandWatchCurrentOutcome>> {
    let caller = ActorId::account(account.clone());
    if request.watcher_actor_id != caller {
        return Ok(SelfExactCurrentRead::NotFound);
    }
    let mut conn = pg_conn(pool).await?;
    conn.transaction::<_, PgTransactionError, _>(async move |conn| {
        begin_read_cut(conn).await?;
        let (generation,head) = match member_cut(conn, &request.realm_id, &caller, issuer).await? {
            MemberCut::NotVisible => return Ok(SelfExactCurrentRead::NotFound),
            MemberCut::ForeignTenure => {
                return Ok(SelfExactCurrentRead::Unresolved(
                    "this Station does not hold the Realm's governing tenure",
                ));
            }
            MemberCut::Member {
                scoped_streams: true,
                ..
            } => {
                return Ok(SelfExactCurrentRead::Unresolved(
                    "Circle and Sidecar scope visibility is not proved at this cut",
                ));
            }
            MemberCut::Member { generation, realm_head: Some(head), .. } => (generation,head),
            MemberCut::Member { .. } => return Ok(SelfExactCurrentRead::Unresolved("watch current stream head is unavailable")),
        };
        let known_strand = sql_query(
            "SELECT EXISTS(SELECT 1 FROM strand_current_results \
             WHERE realm_id=$1 AND strand_id=$2 AND value->>'state'='active' \
               AND (NOT value?'scope_circle_id' OR value->'scope_circle_id'='null'::jsonb)) AS present",
        )
        .bind::<Text, _>(request.realm_id.as_str())
        .bind::<Text, _>(request.strand_id.as_str())
        .get_result::<ExistsRow>(&mut *conn)
        .await?
        .present;
        if !known_strand {
            return Ok(SelfExactCurrentRead::NotFound);
        }
        let confirmed_strand = sql_query("SELECT EXISTS(SELECT 1 FROM strand_current_results s JOIN realm_commits c ON c.commit_id=s.current_commit_id JOIN canonical_events e ON e.pk=c.event_pk WHERE s.realm_id=$1 AND s.strand_id=$2 AND c.realm_id=s.realm_id AND c.stream_position=s.current_stream_position AND c.stream_ref->>'kind'='realm' AND c.stream_ref->>'realm_id'=s.realm_id AND e.state='committed' AND c.stream_position<=$3 AND (c.stream_position<$3 OR c.commit_id=$4)) AS present")
            .bind::<Text,_>(request.realm_id.as_str()).bind::<Text,_>(request.strand_id.as_str()).bind::<BigInt,_>(i64::try_from(head.stream_position).map_err(PersistenceError::database)?).bind::<Text,_>(head.commit_id.as_str())
            .get_result::<ExistsRow>(&mut *conn).await?.present;
        if !confirmed_strand { return Ok(SelfExactCurrentRead::Unresolved("Strand current has no confirmed covering Commit in this stream prefix")); }
        let selector = StrandWatchCurrentSelector { kind: StrandWatchSelectorKind::StrandWatch,
            strand_id: request.strand_id.clone(), watcher_actor_id: caller.clone() };
        let row = sql_query(WATCH_CURRENT_SQL)
            .bind::<Text,_>(request.realm_id.as_str()).bind::<Text,_>(request.strand_id.as_str()).bind::<Text,_>(caller.to_string())
            .get_result::<CurrentRow>(&mut *conn).await.optional()?;
        let outcome = if let Some(row) = row {
            let source_stream_ref: CommitStreamRef = serde_json::from_value(row.stream_ref).map_err(PersistenceError::database)?;
            let revision = CurrentRevision { commit_id: row.current_commit_id.parse().map_err(PersistenceError::database)?,
                stream_position: to_u64(row.current_stream_position,"watch current position")? };
            if source_stream_ref != head.stream_ref || revision.stream_position > head.stream_position
                || (revision.stream_position==head.stream_position && revision.commit_id!=head.commit_id) {
                return Ok(SelfExactCurrentRead::Unresolved("watch current does not belong to the confirmed stream prefix"));
            }
            StrandWatchCurrentOutcome::Current { realm_id: request.realm_id.clone(), governance_generation: generation, stream_head: head,
                result: StrandWatchCurrentResult { selector,source_stream_ref,revision,
                    value: serde_json::from_value(row.value).map_err(PersistenceError::database)? } }
        } else {
            let previously_written = sql_query(crate::strand_watch_current_results::WATCH_HISTORY_SQL)
                .bind::<Text,_>(request.realm_id.as_str()).bind::<Text,_>(request.strand_id.as_str()).bind::<Text,_>(caller.to_string()).bind::<Text,_>("")
                .get_result::<ExistsRow>(&mut *conn).await?.present;
            let orphan_current = sql_query("SELECT EXISTS(SELECT 1 FROM strand_watch_current_results WHERE realm_id=$1 AND strand_id=$2 AND watcher_actor_id=$3) AS present")
                .bind::<Text,_>(request.realm_id.as_str()).bind::<Text,_>(request.strand_id.as_str()).bind::<Text,_>(caller.to_string()).get_result::<ExistsRow>(&mut *conn).await?.present;
            if previously_written || orphan_current || generation!=0 { return Ok(SelfExactCurrentRead::Unresolved("written watch current or tenure import is unavailable")); }
            StrandWatchCurrentOutcome::NeverWritten { realm_id: request.realm_id.clone(),governance_generation:generation,stream_head:head,selector }
        };
        Ok(SelfExactCurrentRead::Answer(outcome))
    })
    .await
    .map_err(PgTransactionError::into_persistence)
}

pub(crate) async fn media_service_anchor_for_account(
    pool: &PgPool,
    realm_id: &RealmId,
    account: &AccountId,
    issuer: &DidCoreId,
) -> PersistenceResult<MediaServiceAnchorRead> {
    let caller = ActorId::account(account.clone());
    let mut conn = pg_conn(pool).await?;
    conn.transaction::<_, PgTransactionError, _>(async move |conn| {
        begin_read_cut(conn).await?;
        if matches!(
            member_cut(conn, realm_id, &caller, issuer).await?,
            MemberCut::NotVisible
        ) {
            return Ok(MediaServiceAnchorRead::NotFound);
        }
        let anchored = sql_query(MEDIA_ANCHOR_SQL)
            .bind::<Text, _>(realm_id.as_str())
            .bind::<Text, _>(arkret_wire::EventKind::RealmMediaService.as_str())
            .get_result::<ExistsRow>(&mut *conn)
            .await?
            .present;
        Ok(if anchored {
            MediaServiceAnchorRead::Anchored
        } else {
            MediaServiceAnchorRead::NotFound
        })
    })
    .await
    .map_err(PgTransactionError::into_persistence)
}
