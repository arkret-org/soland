//! The moderation queue View (`moderation-queue-item.schema.json`).
//!
//! content-moderation.md §3.3 makes the queue item a read-side View over the
//! accepted `moderation_report` typed current family and the `moderation_state`
//! records that point at it; the Station keeps no independently writable queue
//! state. Every member is derived here from one REPEATABLE READ snapshot:
//!
//! - visibility of a Realm's reports is limited to its moderators: the current Realm root
//!   controller or the Actor subject of an active, chain-intact Capability Grant for the moderation
//!   decision on the Realm, both judged at this same cut; any other caller sees nothing for that
//!   Realm (no existence oracle);
//! - `status` folds the report family with `moderation_state`: an item is `resolved` once a
//!   committed decision names the report itself, or names the reported target after the report was
//!   accepted; lifts never reopen it;
//! - `visibility` takes the first matching branch of §3.3 item 3 (the supported reports target
//!   Realm-scope content only);
//! - `created_at` is the accepting RealmCommit time;
//! - local workflow members (`priority`, `assigned_to_ids`, `audit_refs`) and the optional
//!   `evidence_policy` are omitted: this Station has none.

use arkret_models_collaboration::events_payloads::moderation::ModerationReportPayload;
use arkret_models_collaboration::governance::moderation_queue::{
    ModerationQueueItem, ModerationQueueStatus, ModerationQueueVisibility,
};
use diesel::sql_types::Nullable;

use super::{
    AsyncConnection, AsyncPgConnection, BigInt, Bool, Jsonb, ModerationStore, PersistenceError,
    PersistenceResult, PgPool, PgTransactionError, QueryableByName, RunQueryDsl, Text, Timestamptz,
    Value, async_trait, pg_conn, sql_query,
};

pub struct PgModerationStore {
    pub pool: PgPool,
}

#[derive(QueryableByName)]
struct RealmRow {
    #[diesel(sql_type = Text)]
    realm_id: String,
}

#[derive(QueryableByName)]
struct PresentRow {
    #[diesel(sql_type = Bool)]
    present: bool,
}

#[derive(QueryableByName)]
struct ReportRow {
    #[diesel(sql_type = Text)]
    report_event_id: String,
    #[diesel(sql_type = Jsonb)]
    value: Value,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    committed_at: Option<chrono::DateTime<chrono::Utc>>,
    #[diesel(sql_type = BigInt)]
    current_stream_position: i64,
}

#[derive(QueryableByName)]
struct CountRow {
    #[diesel(sql_type = BigInt)]
    count: i64,
}

fn corrupt(detail: impl std::fmt::Display) -> PersistenceError {
    PersistenceError::Internal(format!("stored moderation report View source: {detail}"))
}

async fn present(
    conn: &mut AsyncPgConnection,
    query: &'static str,
    realm_id: &str,
) -> PersistenceResult<bool> {
    Ok(sql_query(query)
        .bind::<Text, _>(realm_id)
        .get_result::<PresentRow>(&mut *conn)
        .await
        .map_err(PersistenceError::database)?
        .present)
}

#[derive(QueryableByName)]
struct DecisionRow {
    #[diesel(sql_type = Text)]
    target_ref: String,
    #[diesel(sql_type = BigInt)]
    stream_position: i64,
}

/// Every committed decision assertion of the Realm with the target it was
/// recorded under and its accepting Realm-stream position.
async fn realm_decisions(
    conn: &mut AsyncPgConnection,
    realm_id: &str,
) -> PersistenceResult<Vec<DecisionRow>> {
    sql_query(
        "SELECT s.target_ref, c.stream_position \
         FROM moderation_state_current_results s \
         CROSS JOIN LATERAL jsonb_array_elements(s.value->'assertions') a \
         JOIN realm_commits c ON c.realm_id=s.realm_id \
          AND c.commit_json->>'event_ref'=left(a->>'tag_id', length(a->>'tag_id')-2) \
          AND c.stream_ref->>'kind'='realm' AND c.stream_ref->>'realm_id'=c.realm_id \
         WHERE s.realm_id=$1 AND a->'value' ? 'decision'",
    )
    .bind::<Text, _>(realm_id)
    .load::<DecisionRow>(&mut *conn)
    .await
    .map_err(PersistenceError::database)
}

async fn realm_queue_items(
    conn: &mut AsyncPgConnection,
    realm_id: &str,
) -> PersistenceResult<Vec<ModerationQueueItem>> {
    // content-moderation.md §3.3 item 3, first branch: a scope is plaintext
    // until its unique `ak.mls.genesis` is accepted (realm-and-space.md §5).
    let encrypted = present(
        conn,
        "SELECT EXISTS (SELECT 1 FROM realm_commits c JOIN canonical_events e ON e.pk=c.event_pk \
         WHERE c.realm_id=$1 AND e.state='committed' AND e.kind='ak.mls.genesis' \
           AND c.stream_ref->>'kind'='realm' AND c.stream_ref->>'realm_id'=c.realm_id) AS present",
        realm_id,
    )
    .await?;
    let rows = sql_query(
        "SELECT r.report_event_id, r.value, c.committed_at, r.current_stream_position \
         FROM moderation_report_current_results r \
         LEFT JOIN realm_commits c ON c.commit_id=r.current_commit_id \
          AND c.realm_id=r.realm_id AND c.stream_position=r.current_stream_position \
          AND c.stream_ref->>'kind'='realm' AND c.stream_ref->>'realm_id'=r.realm_id \
          AND c.commit_json->>'event_ref'=r.report_event_id \
         WHERE r.realm_id=$1 ORDER BY r.current_stream_position ASC",
    )
    .bind::<Text, _>(realm_id)
    .load::<ReportRow>(&mut *conn)
    .await
    .map_err(PersistenceError::database)?;
    let decisions = realm_decisions(conn, realm_id).await?;
    rows.into_iter()
        .map(|row| {
            let committed_at = row
                .committed_at
                .ok_or_else(|| corrupt("report row has no covering Realm-stream Commit"))?;
            let event_id = arkret_wire::EventId::new(row.report_event_id).map_err(corrupt)?;
            let report: ModerationReportPayload =
                serde_json::from_value(row.value).map_err(corrupt)?;
            let resolved = decisions.iter().any(|decision| {
                decision.target_ref == event_id.as_str()
                    || (decision.target_ref == report.target_ref.as_str()
                        && decision.stream_position > row.current_stream_position)
            });
            let visibility = if !encrypted {
                ModerationQueueVisibility::PlaintextEvidence
            } else if report.evidence_package.is_some() {
                ModerationQueueVisibility::EncryptedEvidence
            } else if report.franking_proof.is_some() {
                ModerationQueueVisibility::FrankingProofOnly
            } else {
                ModerationQueueVisibility::MetadataOnly
            };
            Ok(ModerationQueueItem {
                id: ModerationQueueItem::id_for_report(&event_id),
                report,
                status: if resolved {
                    ModerationQueueStatus::Resolved
                } else {
                    ModerationQueueStatus::Submitted
                },
                priority: None,
                visibility,
                assigned_to_ids: None,
                evidence_policy: None,
                audit_refs: None,
                created_at: arkret_canonical::normalize_timestamp_canonical(committed_at),
                updated_at: None,
            })
        })
        .collect()
}

async fn queue_view_in_connection(
    conn: &mut AsyncPgConnection,
    actor: &arkret_wire::ActorId,
    realm_filter: Option<&arkret_wire::RealmId>,
    at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<Vec<ModerationQueueItem>> {
    let realms = sql_query(
        "SELECT DISTINCT realm_id FROM moderation_report_current_results \
         WHERE $1::text IS NULL OR realm_id=$1 ORDER BY realm_id",
    )
    .bind::<Nullable<Text>, _>(realm_filter.map(arkret_wire::RealmId::as_str))
    .load::<RealmRow>(&mut *conn)
    .await
    .map_err(PersistenceError::database)?;
    let mut items = Vec::new();
    for RealmRow { realm_id } in realms {
        let realm = arkret_wire::RealmId::new(realm_id.clone()).map_err(corrupt)?;
        if !crate::capability_grant_current_results::actor_holds_realm_action_in_connection(
            conn,
            &realm,
            actor,
            &[
                arkret_wire::CapabilityActionId::POLICY_MANAGE,
                arkret_wire::CapabilityActionId::MODERATION_DECISION,
            ],
            at,
        )
        .await?
        {
            continue;
        }
        items.extend(realm_queue_items(conn, &realm_id).await?);
    }
    Ok(items)
}

#[async_trait]
impl ModerationStore for PgModerationStore {
    async fn queue_view_for_actor(
        &self,
        actor: &arkret_wire::ActorId,
        realm_id: Option<&arkret_wire::RealmId>,
    ) -> PersistenceResult<Vec<ModerationQueueItem>> {
        let at = chrono::Utc::now();
        let mut conn = pg_conn(&self.pool).await?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            sql_query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
                .execute(&mut *conn)
                .await?;
            queue_view_in_connection(conn, actor, realm_id, at)
                .await
                .map_err(Into::into)
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }

    async fn report_count(&self) -> PersistenceResult<u64> {
        let mut conn = pg_conn(&self.pool).await?;
        let count = sql_query("SELECT COUNT(*) AS count FROM moderation_report_current_results")
            .get_result::<CountRow>(&mut *conn)
            .await
            .map_err(PersistenceError::database)?
            .count;
        u64::try_from(count).map_err(corrupt)
    }
}
