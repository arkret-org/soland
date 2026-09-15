//! Durable timeline projection order for one Realm's accepted Events.
//!
//! `conformance/encoding.md` 7.3 orders a timeline by
//! `causal_depth, hlc, actor_id, actor_seq, event_id`. Two of those keys cannot
//! be read back off a stored row: `causal_depth` is the longest path over the
//! Event graph, and `hlc` lives inside the signed envelope. So the key is
//! computed once, at the accepted-Event transaction boundary, and indexed.
//!
//! This exists so `sync/client-sync.md` 2.3 can answer "the newest N Events of
//! this Realm in projection order" from a bounded keyset read. The path it
//! replaces read every Event of a Realm and sorted by `received_at`, which
//! 2.3 forbids for the window and 7.3 forbids as an ordering.

/// Newest projection-order position of a Realm, or `None` when it holds no
/// accepted Event. Freezing a window means pinning this value: everything
/// accepted afterwards sorts above it and reaches the client as a live
/// increment instead of silently joining a window already in flight.
pub(crate) async fn window_head(
    conn: &mut AsyncPgConnection,
    realm_id: &str,
) -> PersistenceResult<Option<soland_storage::TimelineOrderPosition>> {
    Ok(timeline_page(conn, realm_id, None, 1)
        .await?
        .into_iter()
        .next()
        .map(position_of))
}

fn position_of(row: TimelineOrderRow) -> soland_storage::TimelineOrderPosition {
    soland_storage::TimelineOrderPosition {
        causal_depth: row.causal_depth,
        hlc: row.hlc,
        actor_id: row.actor_id,
        actor_seq: row.actor_seq,
        event_id: row.event_id,
    }
}

#[derive(QueryableByName)]
struct WindowCandidateRow {
    #[diesel(sql_type = Text)]
    event_id: String,
    #[diesel(sql_type = BigInt)]
    causal_depth: i64,
    #[diesel(sql_type = Nullable<Text>)]
    hlc: Option<String>,
    #[diesel(sql_type = Text)]
    actor_id: String,
    #[diesel(sql_type = BigInt)]
    actor_seq: i64,
    #[diesel(sql_type = Text)]
    kind: String,
    #[diesel(sql_type = Bool)]
    provisional: bool,
    #[diesel(sql_type = diesel::sql_types::Jsonb)]
    envelope: serde_json::Value,
    #[diesel(sql_type = diesel::sql_types::Timestamptz)]
    received_at: chrono::DateTime<chrono::Utc>,
}

/// Bounded scan in ascending projection order.
///
/// Window delivery walks `[floor, head]` with `inclusive` and an `upper`; live
/// delivery walks strictly above the frozen head with neither. Both share one
/// expression tuple with the descending selection scan, so frozen and live
/// delivery can never disagree on an order; only direction and bounds differ.
pub(crate) async fn ascending_scan(
    conn: &mut AsyncPgConnection,
    realm_id: &str,
    from: &soland_storage::TimelineOrderPosition,
    inclusive: bool,
    upper: Option<&soland_storage::TimelineOrderPosition>,
    row_limit: usize,
) -> PersistenceResult<soland_storage::TimelineWindowScan> {
    const TUPLE: &str = "(o.causal_depth, (o.hlc IS NULL), COALESCE(o.hlc, ''), o.actor_id,          o.actor_seq, o.event_id)";
    let comparison = if inclusive { ">=" } else { ">" };
    let (upper_clause, limit_param) = match upper {
        Some(_) => (
            format!(" AND {TUPLE} <= ($8, $9, $10, $11, $12, $13)"),
            "$14",
        ),
        None => (String::new(), "$8"),
    };
    let statement = format!(
        "SELECT o.event_id, o.causal_depth, o.hlc, o.actor_id, o.actor_seq, o.kind, o.provisional,          e.envelope, e.received_at          FROM realm_timeline_order o JOIN canonical_events e ON e.pk = o.event_pk          WHERE o.realm_id = $1 AND e.state = 'accepted'          AND {TUPLE} {comparison} ($2, $3, $4, $5, $6, $7){upper_clause}          ORDER BY o.causal_depth ASC, (o.hlc IS NULL) ASC, COALESCE(o.hlc, '') ASC,          o.actor_id ASC, o.actor_seq ASC, o.event_id ASC LIMIT {limit_param}"
    );
    let rows = match upper {
        None => {
            sql_query(statement)
                .bind::<Text, _>(realm_id)
                .bind::<BigInt, _>(from.causal_depth)
                .bind::<Bool, _>(from.hlc.is_none())
                .bind::<Text, _>(from.hlc.clone().unwrap_or_default())
                .bind::<Text, _>(&from.actor_id)
                .bind::<BigInt, _>(from.actor_seq)
                .bind::<Text, _>(&from.event_id)
                .bind::<BigInt, _>(row_limit as i64)
                .load::<WindowCandidateRow>(conn)
                .await
        }
        Some(upper) => {
            sql_query(statement)
                .bind::<Text, _>(realm_id)
                .bind::<BigInt, _>(from.causal_depth)
                .bind::<Bool, _>(from.hlc.is_none())
                .bind::<Text, _>(from.hlc.clone().unwrap_or_default())
                .bind::<Text, _>(&from.actor_id)
                .bind::<BigInt, _>(from.actor_seq)
                .bind::<Text, _>(&from.event_id)
                .bind::<BigInt, _>(upper.causal_depth)
                .bind::<Bool, _>(upper.hlc.is_none())
                .bind::<Text, _>(upper.hlc.clone().unwrap_or_default())
                .bind::<Text, _>(&upper.actor_id)
                .bind::<BigInt, _>(upper.actor_seq)
                .bind::<Text, _>(&upper.event_id)
                .bind::<BigInt, _>(row_limit as i64)
                .load::<WindowCandidateRow>(conn)
                .await
        }
    }
    .map_err(PersistenceError::database)?;
    let scan_capped = rows.len() == row_limit;
    Ok(soland_storage::TimelineWindowScan {
        exhausted: !scan_capped,
        scan_capped,
        candidates: rows.into_iter().map(candidate_of).collect(),
    })
}

/// Bounded scan of one frozen window, newest first, joined to the accepted
/// envelopes the caller needs in order to decide visibility.
///
/// `head` is the inclusive upper bound of the whole window; `bound` is the
/// exclusive continuation. Quarantined rows are excluded here rather than by
/// the caller: they never belonged to the window, so letting them consume scan
/// budget would let a fork shrink an honest window.
pub(crate) async fn window_scan(
    conn: &mut AsyncPgConnection,
    realm_id: &str,
    head: &soland_storage::TimelineOrderPosition,
    bound: Option<&soland_storage::TimelineOrderPosition>,
    row_limit: usize,
) -> PersistenceResult<soland_storage::TimelineWindowScan> {
    let upper = bound.unwrap_or(head);
    let inclusive = bound.is_none();
    let comparison = if inclusive { "<=" } else { "<" };
    let rows = sql_query(format!(
        "SELECT o.event_id, o.causal_depth, o.hlc, o.actor_id, o.actor_seq, o.kind, o.provisional,          e.envelope, e.received_at          FROM realm_timeline_order o JOIN canonical_events e ON e.pk = o.event_pk          WHERE o.realm_id = $1 AND e.state = 'accepted'          AND (o.causal_depth, (o.hlc IS NULL), COALESCE(o.hlc, ''), o.actor_id, o.actor_seq, o.event_id)              {comparison} ($2, $3, $4, $5, $6, $7)          ORDER BY o.causal_depth DESC, (o.hlc IS NULL) DESC, COALESCE(o.hlc, '') DESC,          o.actor_id DESC, o.actor_seq DESC, o.event_id DESC LIMIT $8"
    ))
    .bind::<Text, _>(realm_id)
    .bind::<BigInt, _>(upper.causal_depth)
    .bind::<Bool, _>(upper.hlc.is_none())
    .bind::<Text, _>(upper.hlc.clone().unwrap_or_default())
    .bind::<Text, _>(&upper.actor_id)
    .bind::<BigInt, _>(upper.actor_seq)
    .bind::<Text, _>(&upper.event_id)
    .bind::<BigInt, _>(row_limit as i64)
    .load::<WindowCandidateRow>(conn)
    .await
    .map_err(PersistenceError::database)?;
    let scan_capped = rows.len() == row_limit;
    Ok(soland_storage::TimelineWindowScan {
        exhausted: !scan_capped,
        scan_capped,
        candidates: rows.into_iter().map(candidate_of).collect(),
    })
}

fn candidate_of(row: WindowCandidateRow) -> soland_storage::TimelineWindowCandidate {
    // `created_at` is the producer-signed instant the visibility rules compare
    // against. `received_at` is only the fallback for an envelope that predates
    // the field, and never participates in ordering.
    let created_at = row
        .envelope
        .get("created_at")
        .and_then(serde_json::Value::as_str)
        .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
        .map(|value| value.with_timezone(&chrono::Utc))
        .unwrap_or(row.received_at);
    let sender = row
        .envelope
        .get("actor_id")
        .and_then(|actor| serde_json::from_value::<arkret_wire::ActorId>(actor.clone()).ok())
        .and_then(|actor| actor.canonical_key().ok());
    soland_storage::TimelineWindowCandidate {
        position: soland_storage::TimelineOrderPosition {
            causal_depth: row.causal_depth,
            hlc: row.hlc,
            actor_id: row.actor_id,
            actor_seq: row.actor_seq,
            event_id: row.event_id,
        },
        kind: row.kind,
        provisional: row.provisional,
        envelope: row.envelope,
        created_at,
        sender,
    }
}

#[cfg(test)]
mod postgres_tests;

use arkret_models_collaboration::sync_frames::client_sync::timeline_predecessors;
use diesel::sql_types::{Array, BigInt, Bool, Nullable, Text};
use diesel::{OptionalExtension, QueryableByName, sql_query};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use soland_storage::{PersistenceError, PersistenceResult};

#[derive(QueryableByName)]
struct PredecessorOrderRow {
    #[diesel(sql_type = Text)]
    event_id: String,
    #[diesel(sql_type = BigInt)]
    causal_depth: i64,
    #[diesel(sql_type = Bool)]
    provisional: bool,
}

#[derive(QueryableByName)]
struct PendingChildRow {
    #[diesel(sql_type = BigInt)]
    child_event_pk: i64,
}

#[derive(QueryableByName)]
struct OrderSubjectRow {
    #[diesel(sql_type = Text)]
    event_id: String,
    #[diesel(sql_type = BigInt)]
    realm_pk: i64,
    #[diesel(sql_type = Text)]
    realm_id: String,
    #[diesel(sql_type = diesel::sql_types::Jsonb)]
    envelope: serde_json::Value,
}

/// One Realm-scoped row of the projection order index.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TimelineOrderRow {
    pub event_id: String,
    pub causal_depth: i64,
    /// `None` is a genuine absent HLC, never a substituted value: 7.3 forbids
    /// filling it with an empty string, a zero HLC, receive time or created_at.
    pub hlc: Option<String>,
    pub actor_id: String,
    pub actor_seq: i64,
    pub kind: String,
    /// Some predecessor edge was unresolved when this row was written, so the
    /// order around it is not final and must not be claimed as such.
    pub provisional: bool,
}

#[derive(QueryableByName)]
struct TimelineOrderQueryRow {
    #[diesel(sql_type = Text)]
    event_id: String,
    #[diesel(sql_type = BigInt)]
    causal_depth: i64,
    #[diesel(sql_type = Nullable<Text>)]
    hlc: Option<String>,
    #[diesel(sql_type = Text)]
    actor_id: String,
    #[diesel(sql_type = BigInt)]
    actor_seq: i64,
    #[diesel(sql_type = Text)]
    kind: String,
    #[diesel(sql_type = Bool)]
    provisional: bool,
}

impl From<TimelineOrderQueryRow> for TimelineOrderRow {
    fn from(row: TimelineOrderQueryRow) -> Self {
        Self {
            event_id: row.event_id,
            causal_depth: row.causal_depth,
            hlc: row.hlc,
            actor_id: row.actor_id,
            actor_seq: row.actor_seq,
            kind: row.kind,
            provisional: row.provisional,
        }
    }
}

const MAX_SAFE_INTEGER: i64 = 9_007_199_254_740_991;

/// Record the accepted Event's projection order key inside the same transaction
/// that accepted it.
///
/// The depth is `1 + max(depth of resolved predecessors)`, or 0 with none, over
/// the canonical 7.3 edge set. A predecessor this Station does not hold, or one
/// that is itself provisional, makes this row provisional too: the receiver
/// cannot have closed over an edge it cannot see.
pub(crate) async fn commit_order_key(
    conn: &mut AsyncPgConnection,
    event_pk: i64,
    realm_pk: i64,
    event: &arkret_wire::Event,
) -> PersistenceResult<()> {
    commit_order_key_within(conn, event_pk, realm_pk, event, CASCADE_BUDGET).await
}

/// The same commit with an explicit cascade ceiling, so the over-budget path is
/// reachable without materializing a backlog of the production size.
async fn commit_order_key_within(
    conn: &mut AsyncPgConnection,
    event_pk: i64,
    realm_pk: i64,
    event: &arkret_wire::Event,
    budget: usize,
) -> PersistenceResult<()> {
    let resolution = resolve_edges(conn, event).await?;
    let causal_depth = resolution.causal_depth;
    let provisional = resolution.provisional;
    sql_query(
        "INSERT INTO realm_timeline_order \
         (event_pk, realm_pk, realm_id, causal_depth, hlc, actor_id, actor_seq, event_id, kind, provisional) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) \
         ON CONFLICT (event_pk) DO NOTHING",
    )
    .bind::<BigInt, _>(event_pk)
    .bind::<BigInt, _>(realm_pk)
    .bind::<Text, _>(event.realm_id.as_str())
    .bind::<BigInt, _>(causal_depth)
    .bind::<Nullable<Text>, _>(event.hlc.as_ref().map(|hlc| hlc.as_str().to_owned()))
    .bind::<Text, _>(
        event
            .actor_id
            .canonical_key()
            .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?,
    )
    .bind::<BigInt, _>(
        i64::try_from(event.actor_seq).map_err(|_| {
            PersistenceError::SchemaViolation("actor_seq exceeds the safe integer bound".to_owned())
        })?,
    )
    .bind::<Text, _>(event.event_id.as_str())
    .bind::<Text, _>(event.kind.as_str())
    .bind::<Bool, _>(provisional)
    .execute(&mut *conn)
    .await
    .map_err(PersistenceError::database)?;
    write_pending_edges(conn, event_pk, realm_pk, &resolution.pending).await?;
    // This Event may be the predecessor others have been waiting on. Draining
    // them here is what turns a late arrival into a corrected order instead of
    // leaving every out-of-order successor stuck at the depth and provisional
    // flag it was first written with.
    let changed = cascade(conn, vec![event.event_id.as_str().to_owned()], budget).await?;
    invalidate_reordered_realms(conn, &changed).await
}

/// One bounded page of a Realm's timeline in 7.3 projection order.
///
/// `before` is the exclusive upper bound as the previous page's oldest key, so
/// paging walks toward older history without rereading. Rows come back newest
/// first; the caller reverses them to deliver in ascending projection order.
pub(crate) async fn timeline_page(
    conn: &mut AsyncPgConnection,
    realm_id: &str,
    before: Option<&TimelineOrderRow>,
    limit: usize,
) -> PersistenceResult<Vec<TimelineOrderRow>> {
    // The ASC projection order is spelled as a NULL-free tuple:
    // `(causal_depth, hlc IS NULL, COALESCE(hlc,''), actor_id, actor_seq,
    // event_id)`. `false < true` in Postgres, so the `hlc IS NULL` column is
    // exactly the absent-last rule, and the remaining comparison never sees a
    // NULL. The index is built on these same expressions, so both the keyset
    // predicate and the ordering are one seek.
    const ORDER_TUPLE: &str =
        "(causal_depth, (hlc IS NULL), COALESCE(hlc, ''), actor_id, actor_seq, event_id)";
    const ORDER_BY: &str = "ORDER BY causal_depth DESC, (hlc IS NULL) DESC, \
         COALESCE(hlc, '') DESC, actor_id DESC, actor_seq DESC, event_id DESC";
    const COLUMNS: &str = "SELECT event_id, causal_depth, hlc, actor_id, actor_seq, kind, provisional \
         FROM realm_timeline_order";
    let rows = match before {
        None => {
            sql_query(format!("{COLUMNS} WHERE realm_id = $1 {ORDER_BY} LIMIT $2"))
                .bind::<Text, _>(realm_id)
                .bind::<BigInt, _>(limit as i64)
                .load::<TimelineOrderQueryRow>(conn)
                .await
        }
        Some(cursor) => {
            sql_query(format!(
                "{COLUMNS} WHERE realm_id = $1 \
                 AND {ORDER_TUPLE} < ($2, $3, $4, $5, $6, $7) {ORDER_BY} LIMIT $8"
            ))
            .bind::<Text, _>(realm_id)
            .bind::<BigInt, _>(cursor.causal_depth)
            .bind::<Bool, _>(cursor.hlc.is_none())
            .bind::<Text, _>(cursor.hlc.clone().unwrap_or_default())
            .bind::<Text, _>(&cursor.actor_id)
            .bind::<BigInt, _>(cursor.actor_seq)
            .bind::<Text, _>(&cursor.event_id)
            .bind::<BigInt, _>(limit as i64)
            .load::<TimelineOrderQueryRow>(conn)
            .await
        }
    }
    .map_err(PersistenceError::database)?;
    Ok(rows.into_iter().map(TimelineOrderRow::from).collect())
}

/// Ceiling on how many order rows one transaction may re-resolve, the same
/// magnitude `rebuild_pending_causal_registers` uses for the other durable
/// projection backlog.
///
/// Whatever does not fit is not dropped. A pending edge whose predecessor has
/// already settled *is* the queued unit of work, so the backlog lives in
/// `realm_timeline_pending_edges` itself rather than in a second list that
/// could drift out of agreement with it; `drain_pending_timeline_edges` sweeps
/// exactly those rows.
const CASCADE_BUDGET: usize = 4096;

/// One Event's 7.3 edge set resolved against what this Station currently holds.
struct EdgeResolution {
    causal_depth: i64,
    provisional: bool,
    /// Edges that are not finally resolved: the predecessor is absent here, or
    /// present but itself provisional, so its own depth can still move. These
    /// are the reverse rows worth keeping; a settled predecessor's depth is
    /// final by induction and can never move a successor again.
    pending: Vec<String>,
}

/// Resolve the whole 7.3 edge set of one Event.
///
/// `timeline_predecessors` is the SDK's single enumeration point for that set
/// (`prev_refs`, `refs` with role `after`, `causal_refs` and the payload reply
/// edge). Computing a narrower set here would make this Station order the same
/// batch of Events differently from every other consumer of the same rule.
async fn resolve_edges(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
) -> PersistenceResult<EdgeResolution> {
    let predecessors = timeline_predecessors(event);
    let predecessor_ids = predecessors
        .event_ids
        .iter()
        .map(|id| id.as_str().to_owned())
        .collect::<Vec<_>>();
    let resolved = if predecessor_ids.is_empty() {
        Vec::new()
    } else {
        sql_query(
            "SELECT event_id, causal_depth, provisional FROM realm_timeline_order \
             WHERE event_id = ANY($1)",
        )
        .bind::<Array<Text>, _>(&predecessor_ids)
        .load::<PredecessorOrderRow>(conn)
        .await
        .map_err(PersistenceError::database)?
    };
    let causal_depth = resolved
        .iter()
        .map(|row| row.causal_depth.saturating_add(1))
        .max()
        .unwrap_or(0)
        .min(MAX_SAFE_INTEGER);
    let settled = resolved
        .iter()
        .filter(|row| !row.provisional)
        .map(|row| row.event_id.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    let pending = predecessor_ids
        .iter()
        .filter(|id| !settled.contains(id.as_str()))
        .cloned()
        .collect::<Vec<_>>();
    Ok(EdgeResolution {
        causal_depth,
        // A digest that cannot even name an Event has no arrival to wait for,
        // so it gets no reverse row; it only keeps the order provisional.
        provisional: !pending.is_empty() || !predecessors.unresolvable_digests.is_empty(),
        pending,
    })
}

/// Replace one Event's reverse edges with its currently unresolved ones.
///
/// Rewriting the whole set rather than adding to it is what retires an edge the
/// moment its predecessor settles, which keeps the table the size of the
/// genuinely unsettled frontier and keeps the backlog sweep from rediscovering
/// work it has already done.
async fn write_pending_edges(
    conn: &mut AsyncPgConnection,
    event_pk: i64,
    realm_pk: i64,
    pending: &[String],
) -> PersistenceResult<()> {
    sql_query("DELETE FROM realm_timeline_pending_edges WHERE child_event_pk = $1")
        .bind::<BigInt, _>(event_pk)
        .execute(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
    if pending.is_empty() {
        return Ok(());
    }
    sql_query(
        "INSERT INTO realm_timeline_pending_edges (child_event_pk, predecessor_event_id, realm_pk) \
         SELECT $1, predecessor, $3 FROM UNNEST($2::text[]) AS predecessor \
         ON CONFLICT (child_event_pk, predecessor_event_id) DO NOTHING",
    )
    .bind::<BigInt, _>(event_pk)
    .bind::<Array<Text>, _>(pending)
    .bind::<BigInt, _>(realm_pk)
    .execute(conn)
    .await
    .map_err(PersistenceError::database)?;
    Ok(())
}

/// Recompute one indexed row's `(causal_depth, provisional)` from its entire
/// edge set and rewrite its reverse edges. Returns `(event_id, realm_id)` when
/// the pair actually moved.
///
/// The recomputation is total, never a patch keyed on the edge that just
/// arrived: the depth is `1 + max(every edge)`, so an edge that is still
/// missing has to keep the row provisional no matter how deep the arriving one
/// turned out to be.
async fn reresolve(
    conn: &mut AsyncPgConnection,
    event_pk: i64,
) -> PersistenceResult<Option<(String, String)>> {
    let Some(subject) = sql_query(
        "SELECT o.event_id, o.realm_pk, o.realm_id, e.envelope \
         FROM realm_timeline_order o JOIN canonical_events e ON e.pk = o.event_pk \
         WHERE o.event_pk = $1",
    )
    .bind::<BigInt, _>(event_pk)
    .get_result::<OrderSubjectRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?
    else {
        return Ok(None);
    };
    let event = serde_json::from_value::<arkret_wire::Event>(subject.envelope)
        .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
    let resolution = resolve_edges(conn, &event).await?;
    let moved = sql_query(
        "UPDATE realm_timeline_order SET causal_depth = $2, provisional = $3 \
         WHERE event_pk = $1 AND (causal_depth, provisional) IS DISTINCT FROM ($2, $3)",
    )
    .bind::<BigInt, _>(event_pk)
    .bind::<BigInt, _>(resolution.causal_depth)
    .bind::<Bool, _>(resolution.provisional)
    .execute(&mut *conn)
    .await
    .map_err(PersistenceError::database)?
        != 0;
    write_pending_edges(conn, event_pk, subject.realm_pk, &resolution.pending).await?;
    Ok(moved.then_some((subject.event_id, subject.realm_id)))
}

/// Walk outward from Events whose order just moved, re-resolving every
/// successor that named one of them as a predecessor.
///
/// The visited set is keyed on the edge, not on the successor: a diamond
/// legitimately reaches the same successor once per predecessor that moved, and
/// every one of those visits has to land or the successor keeps a depth
/// computed from a stale predecessor. A cycle has finitely many edges, so
/// following each at most once ends the cascade structurally rather than by
/// burning the whole budget on it.
async fn cascade(
    conn: &mut AsyncPgConnection,
    roots: Vec<String>,
    budget: usize,
) -> PersistenceResult<std::collections::BTreeSet<String>> {
    let mut frontier = std::collections::VecDeque::from(roots);
    let mut walked = std::collections::BTreeSet::<(i64, String)>::new();
    let mut reordered = std::collections::BTreeSet::new();
    let mut spent = 0usize;
    while let Some(predecessor) = frontier.pop_front() {
        let children = sql_query(
            "SELECT child_event_pk FROM realm_timeline_pending_edges \
             WHERE predecessor_event_id = $1 ORDER BY child_event_pk",
        )
        .bind::<Text, _>(&predecessor)
        .load::<PendingChildRow>(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
        for child in children {
            if !walked.insert((child.child_event_pk, predecessor.clone())) {
                continue;
            }
            if spent >= budget {
                // Leave the edge row alone. Its predecessor is settled now, so
                // this successor is exactly what the durable sweep looks for.
                continue;
            }
            spent += 1;
            if let Some((event_id, realm_id)) = reresolve(conn, child.child_event_pk).await? {
                reordered.insert(realm_id);
                frontier.push_back(event_id);
            }
        }
    }
    Ok(reordered)
}

/// Retire the derived generation of every Realm whose projection order moved.
///
/// A changed `(causal_depth, provisional)` relocates the row in 7.3 order, so a
/// window frozen against the previous order may no longer cover the same
/// `[floor, head]` interval. `client-sync.md` 2.3 answers that with a new
/// generation and never with a silent re-cut of one already in flight, so this
/// hands the case to the invalidation path: an in-flight generation fails its
/// authority check and is rebuilt with its own cut and reservation.
async fn invalidate_reordered_realms(
    conn: &mut AsyncPgConnection,
    reordered: &std::collections::BTreeSet<String>,
) -> PersistenceResult<()> {
    for realm_id in reordered {
        crate::state_resolution::invalidate_realm_projection(conn, realm_id).await?;
    }
    Ok(())
}

/// Drain the durable backlog of re-resolutions owed to one Realm.
///
/// A pending edge whose predecessor has already settled is a successor written
/// before that predecessor arrived and not recomputed since, because an arrival
/// cascade ran out of budget or the process stopped mid-cascade. The condition
/// is derived from the rows themselves, so nothing can be enqueued and then
/// lost, and a crash costs at most the work of recomputing it again.
pub(crate) async fn drain_pending_timeline_edges(
    conn: &mut AsyncPgConnection,
    realm_id: &str,
    budget: usize,
) -> PersistenceResult<usize> {
    let budget = budget.clamp(1, CASCADE_BUDGET);
    let owed = sql_query(
        "SELECT DISTINCT e.child_event_pk FROM realm_timeline_pending_edges e \
         JOIN realm_timeline_order c ON c.event_pk = e.child_event_pk \
         JOIN realm_timeline_order p ON p.event_id = e.predecessor_event_id \
         WHERE c.realm_id = $1 AND NOT p.provisional ORDER BY 1 LIMIT $2",
    )
    .bind::<Text, _>(realm_id)
    .bind::<BigInt, _>(budget as i64)
    .load::<PendingChildRow>(&mut *conn)
    .await
    .map_err(PersistenceError::database)?;
    let mut reordered = std::collections::BTreeSet::new();
    let mut roots = Vec::new();
    for row in &owed {
        if let Some((event_id, realm)) = reresolve(conn, row.child_event_pk).await? {
            reordered.insert(realm);
            roots.push(event_id);
        }
    }
    if !roots.is_empty() {
        reordered.extend(cascade(conn, roots, CASCADE_BUDGET.saturating_sub(owed.len())).await?);
    }
    invalidate_reordered_realms(conn, &reordered).await?;
    Ok(owed.len())
}
