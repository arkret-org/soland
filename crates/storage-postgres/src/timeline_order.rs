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

/// Bounded scan of Events strictly above `after`, oldest first.
///
/// This is the live increment path. Everything accepted after a window was
/// frozen sorts above its head, so it is delivered here instead of joining a
/// window already in flight. It shares the window scan's expression tuple, so
/// live and frozen delivery agree on one order; only direction and strictness
/// differ.
pub(crate) async fn live_scan(
    conn: &mut AsyncPgConnection,
    realm_id: &str,
    after: &soland_storage::TimelineOrderPosition,
    row_limit: usize,
) -> PersistenceResult<soland_storage::TimelineWindowScan> {
    let rows = sql_query(
        "SELECT o.event_id, o.causal_depth, o.hlc, o.actor_id, o.actor_seq, o.kind, o.provisional, \
         e.envelope, e.received_at \
         FROM realm_timeline_order o JOIN canonical_events e ON e.pk = o.event_pk \
         WHERE o.realm_id = $1 AND e.state = 'accepted' \
         AND (o.causal_depth, (o.hlc IS NULL), COALESCE(o.hlc, ''), o.actor_id, o.actor_seq, o.event_id) \
             > ($2, $3, $4, $5, $6, $7) \
         ORDER BY o.causal_depth ASC, (o.hlc IS NULL) ASC, COALESCE(o.hlc, '') ASC, \
         o.actor_id ASC, o.actor_seq ASC, o.event_id ASC LIMIT $8",
    )
    .bind::<Text, _>(realm_id)
    .bind::<BigInt, _>(after.causal_depth)
    .bind::<Bool, _>(after.hlc.is_none())
    .bind::<Text, _>(after.hlc.clone().unwrap_or_default())
    .bind::<Text, _>(&after.actor_id)
    .bind::<BigInt, _>(after.actor_seq)
    .bind::<Text, _>(&after.event_id)
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
use diesel::sql_types::{BigInt, Bool, Nullable, Text};
use diesel::{QueryableByName, sql_query};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use soland_storage::{PersistenceError, PersistenceResult};

#[derive(QueryableByName)]
struct PredecessorOrderRow {
    #[diesel(sql_type = BigInt)]
    causal_depth: i64,
    #[diesel(sql_type = Bool)]
    provisional: bool,
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
            "SELECT causal_depth, provisional FROM realm_timeline_order WHERE event_id = ANY($1)",
        )
        .bind::<diesel::sql_types::Array<Text>, _>(&predecessor_ids)
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
    let provisional = resolved.len() != predecessor_ids.len()
        || !predecessors.unresolvable_digests.is_empty()
        || resolved.iter().any(|row| row.provisional);
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
    .execute(conn)
    .await
    .map_err(PersistenceError::database)?;
    Ok(())
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
