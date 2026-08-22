use arkret_models_identity::{ServiceRouteHandoverNotice, ServiceRouteHandoverState};
use arkret_wire::{DidCoreId, Hash};
use chrono::{DateTime, Utc};
use diesel::sql_types::{BigInt, Bool, Integer, Jsonb, Nullable, Text, Timestamptz};
use diesel::{OptionalExtension, QueryableByName, sql_query};
use diesel_async::{AsyncConnection, AsyncPgConnection, RunQueryDsl};
use soland_storage::{
    PersistenceError, PersistenceResult, ServiceRouteHandoverAudienceEntry,
    ServiceRouteHandoverAudienceStatus, ServiceRouteHandoverAudienceTarget,
    ServiceRouteHandoverNoticeCommit, ServiceRouteHandoverNoticeRecord, ServiceRouteHandoverPlan,
    ServiceRouteHandoverPlanState, ServiceRouteHandoverPlanStore, ServiceRouteHandoverPlanWrite,
};

use crate::{PgPool, PgTransactionError, async_trait, pg_conn};

pub struct PgServiceRouteHandoverPlanStore {
    pub pool: PgPool,
}

#[derive(QueryableByName)]
struct PlanRow {
    #[diesel(sql_type = Text)]
    service_id: String,
    #[diesel(sql_type = Text)]
    service_kind: String,
    #[diesel(sql_type = Text)]
    handover_id: String,
    #[diesel(sql_type = BigInt)]
    basis_record_sequence: i64,
    #[diesel(sql_type = Text)]
    basis_record_digest: String,
    #[diesel(sql_type = Text)]
    candidate_base_url: String,
    #[diesel(sql_type = Text)]
    candidate_record_url: String,
    #[diesel(sql_type = Timestamptz)]
    not_before: DateTime<Utc>,
    #[diesel(sql_type = Timestamptz)]
    cutover_at: DateTime<Utc>,
    #[diesel(sql_type = Timestamptz)]
    grace_until: DateTime<Utc>,
    #[diesel(sql_type = Timestamptz)]
    expires_at: DateTime<Utc>,
    #[diesel(sql_type = Text)]
    lifecycle_state: String,
    #[diesel(sql_type = Nullable<Integer>)]
    active_notice_revision: Option<i32>,
    #[diesel(sql_type = Nullable<Text>)]
    active_notice_digest: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    last_error: Option<String>,
    #[diesel(sql_type = Timestamptz)]
    created_at: DateTime<Utc>,
    #[diesel(sql_type = Timestamptz)]
    updated_at: DateTime<Utc>,
}

#[derive(QueryableByName)]
struct NoticeRow {
    #[diesel(sql_type = Text)]
    service_id: String,
    #[diesel(sql_type = Text)]
    service_kind: String,
    #[diesel(sql_type = Text)]
    handover_id: String,
    #[diesel(sql_type = Integer)]
    notice_revision: i32,
    #[diesel(sql_type = Text)]
    notice_digest: String,
    #[diesel(sql_type = Nullable<Text>)]
    previous_notice_digest: Option<String>,
    #[diesel(sql_type = Text)]
    notice_state: String,
    #[diesel(sql_type = Jsonb)]
    notice: serde_json::Value,
    #[diesel(sql_type = Timestamptz)]
    issued_at: DateTime<Utc>,
    #[diesel(sql_type = Timestamptz)]
    expires_at: DateTime<Utc>,
}

#[derive(QueryableByName)]
struct AudienceRow {
    #[diesel(sql_type = Text)]
    service_id: String,
    #[diesel(sql_type = Text)]
    service_kind: String,
    #[diesel(sql_type = Text)]
    handover_id: String,
    #[diesel(sql_type = Text)]
    realm_id: String,
    #[diesel(sql_type = Text)]
    peer_service_id: String,
    #[diesel(sql_type = Text)]
    notice_digest: String,
    #[diesel(sql_type = Jsonb)]
    accepted_frontier: serde_json::Value,
    #[diesel(sql_type = Bool)]
    required: bool,
    #[diesel(sql_type = Text)]
    audience_status: String,
    #[diesel(sql_type = Nullable<Text>)]
    removed_reason: Option<String>,
    #[diesel(sql_type = Timestamptz)]
    created_at: DateTime<Utc>,
    #[diesel(sql_type = Timestamptz)]
    updated_at: DateTime<Utc>,
}

const PLAN_COLUMNS: &str = "service_id, service_kind, handover_id, basis_record_sequence, \
     basis_record_digest, candidate_base_url, candidate_record_url, not_before, cutover_at, \
     grace_until, expires_at, lifecycle_state, active_notice_revision, active_notice_digest, \
     last_error, created_at, updated_at";

const NOTICE_COLUMNS: &str = "service_id, service_kind, handover_id, notice_revision, \
     notice_digest, previous_notice_digest, notice_state, notice, issued_at, expires_at";

const AUDIENCE_COLUMNS: &str = "service_id, service_kind, handover_id, realm_id, \
     peer_service_id, notice_digest, accepted_frontier, required, audience_status, \
     removed_reason, created_at, updated_at";

fn internal(error: impl std::fmt::Display) -> PersistenceError {
    PersistenceError::Internal(error.to_string())
}

fn hash(value: String) -> PersistenceResult<Hash> {
    Hash::new(value).map_err(internal)
}

fn notice_state_str(state: ServiceRouteHandoverState) -> &'static str {
    match state {
        ServiceRouteHandoverState::Scheduled => "scheduled",
        ServiceRouteHandoverState::Cancelled => "cancelled",
    }
}

fn parse_notice_state(value: &str) -> PersistenceResult<ServiceRouteHandoverState> {
    match value {
        "scheduled" => Ok(ServiceRouteHandoverState::Scheduled),
        "cancelled" => Ok(ServiceRouteHandoverState::Cancelled),
        other => Err(PersistenceError::Internal(format!(
            "unknown stored service route handover notice state: {other}"
        ))),
    }
}

/// A `u32` revision is stored as `integer`; anything that does not round-trip
/// is a corrupt row rather than a value this deployment could have written.
fn revision_to_sql(revision: u32) -> PersistenceResult<i32> {
    i32::try_from(revision)
        .map_err(|_| PersistenceError::Internal("notice revision exceeds storage width".to_owned()))
}

fn revision_from_sql(revision: i32) -> PersistenceResult<u32> {
    u32::try_from(revision)
        .map_err(|_| PersistenceError::Internal("stored notice revision is negative".to_owned()))
}

fn sequence_to_sql(sequence: u64) -> PersistenceResult<i64> {
    i64::try_from(sequence)
        .map_err(|_| PersistenceError::Internal("record sequence exceeds storage width".to_owned()))
}

impl PlanRow {
    fn decode(self) -> PersistenceResult<ServiceRouteHandoverPlan> {
        let state =
            ServiceRouteHandoverPlanState::parse(&self.lifecycle_state).ok_or_else(|| {
                PersistenceError::Internal(format!(
                    "unknown stored service route handover plan state: {}",
                    self.lifecycle_state
                ))
            })?;
        Ok(ServiceRouteHandoverPlan {
            service_id: DidCoreId::new(self.service_id).map_err(internal)?,
            service_kind: self.service_kind,
            handover_id: self.handover_id,
            basis_record_sequence: u64::try_from(self.basis_record_sequence).map_err(|_| {
                PersistenceError::Internal("stored basis record sequence is negative".to_owned())
            })?,
            basis_record_digest: hash(self.basis_record_digest)?,
            candidate_base_url: self.candidate_base_url,
            candidate_record_url: self.candidate_record_url,
            not_before: self.not_before,
            cutover_at: self.cutover_at,
            grace_until: self.grace_until,
            expires_at: self.expires_at,
            state,
            active_notice_revision: self
                .active_notice_revision
                .map(revision_from_sql)
                .transpose()?,
            active_notice_digest: self.active_notice_digest.map(hash).transpose()?,
            last_error: self.last_error,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

impl NoticeRow {
    fn decode(self) -> PersistenceResult<ServiceRouteHandoverNoticeRecord> {
        let notice: ServiceRouteHandoverNotice =
            serde_json::from_value(self.notice).map_err(internal)?;
        Ok(ServiceRouteHandoverNoticeRecord {
            service_id: DidCoreId::new(self.service_id).map_err(internal)?,
            service_kind: self.service_kind,
            handover_id: self.handover_id,
            notice_revision: revision_from_sql(self.notice_revision)?,
            notice_digest: hash(self.notice_digest)?,
            previous_notice_digest: self.previous_notice_digest.map(hash).transpose()?,
            state: parse_notice_state(&self.notice_state)?,
            notice,
            issued_at: self.issued_at,
            expires_at: self.expires_at,
        })
    }
}

impl AudienceRow {
    fn decode(self) -> PersistenceResult<ServiceRouteHandoverAudienceEntry> {
        let status =
            ServiceRouteHandoverAudienceStatus::parse(&self.audience_status).ok_or_else(|| {
                PersistenceError::Internal(format!(
                    "unknown stored service route handover audience status: {}",
                    self.audience_status
                ))
            })?;
        let accepted_frontier = serde_json::from_value(self.accepted_frontier).map_err(internal)?;
        Ok(ServiceRouteHandoverAudienceEntry {
            service_id: DidCoreId::new(self.service_id).map_err(internal)?,
            service_kind: self.service_kind,
            handover_id: self.handover_id,
            realm_id: self.realm_id,
            peer_service_id: DidCoreId::new(self.peer_service_id).map_err(internal)?,
            notice_digest: hash(self.notice_digest)?,
            accepted_frontier,
            required: self.required,
            status,
            removed_reason: self.removed_reason,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

async fn lock_plan_slot(
    conn: &mut AsyncPgConnection,
    service_id: &DidCoreId,
    service_kind: &str,
) -> Result<(), PgTransactionError> {
    let key = format!("service-route-plan:{service_id}:{service_kind}");
    sql_query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind::<Text, _>(key)
        .execute(conn)
        .await?;
    Ok(())
}

async fn load_plan(
    conn: &mut AsyncPgConnection,
    service_id: &DidCoreId,
    service_kind: &str,
    handover_id: &str,
) -> Result<Option<ServiceRouteHandoverPlan>, PgTransactionError> {
    let row = sql_query(format!(
        "SELECT {PLAN_COLUMNS} FROM service_route_handover_plans \
         WHERE service_id = $1 AND service_kind = $2 AND handover_id = $3"
    ))
    .bind::<Text, _>(service_id.as_str())
    .bind::<Text, _>(service_kind)
    .bind::<Text, _>(handover_id)
    .get_result::<PlanRow>(conn)
    .await
    .optional()?;
    row.map(PlanRow::decode).transpose().map_err(Into::into)
}

#[async_trait]
impl ServiceRouteHandoverPlanStore for PgServiceRouteHandoverPlanStore {
    async fn plan(
        &self,
        service_id: &DidCoreId,
        service_kind: &str,
        handover_id: &str,
    ) -> PersistenceResult<Option<ServiceRouteHandoverPlan>> {
        let mut conn = pg_conn(&self.pool).await?;
        let row = sql_query(format!(
            "SELECT {PLAN_COLUMNS} FROM service_route_handover_plans \
             WHERE service_id = $1 AND service_kind = $2 AND handover_id = $3"
        ))
        .bind::<Text, _>(service_id.as_str())
        .bind::<Text, _>(service_kind)
        .bind::<Text, _>(handover_id)
        .get_result::<PlanRow>(&mut conn)
        .await
        .optional()
        .map_err(internal)?;
        row.map(PlanRow::decode).transpose()
    }

    async fn active_plan(
        &self,
        service_id: &DidCoreId,
        service_kind: &str,
    ) -> PersistenceResult<Option<ServiceRouteHandoverPlan>> {
        let mut conn = pg_conn(&self.pool).await?;
        let row = sql_query(format!(
            "SELECT {PLAN_COLUMNS} FROM service_route_handover_plans \
             WHERE service_id = $1 AND service_kind = $2 \
               AND lifecycle_state NOT IN ('completed', 'cancelled', 'failed')"
        ))
        .bind::<Text, _>(service_id.as_str())
        .bind::<Text, _>(service_kind)
        .get_result::<PlanRow>(&mut conn)
        .await
        .optional()
        .map_err(internal)?;
        row.map(PlanRow::decode).transpose()
    }

    async fn list_plans(
        &self,
        service_id: &DidCoreId,
        service_kind: &str,
        limit: usize,
    ) -> PersistenceResult<Vec<ServiceRouteHandoverPlan>> {
        let limit = i64::try_from(limit.clamp(1, 256)).map_err(internal)?;
        let mut conn = pg_conn(&self.pool).await?;
        let rows = sql_query(format!(
            "SELECT {PLAN_COLUMNS} FROM service_route_handover_plans \
             WHERE service_id = $1 AND service_kind = $2 \
             ORDER BY created_at DESC, handover_id ASC LIMIT $3"
        ))
        .bind::<Text, _>(service_id.as_str())
        .bind::<Text, _>(service_kind)
        .bind::<BigInt, _>(limit)
        .get_results::<PlanRow>(&mut conn)
        .await
        .map_err(internal)?;
        rows.into_iter().map(PlanRow::decode).collect()
    }

    async fn notices(
        &self,
        service_id: &DidCoreId,
        service_kind: &str,
        handover_id: &str,
        limit: usize,
    ) -> PersistenceResult<Vec<ServiceRouteHandoverNoticeRecord>> {
        let limit = i64::try_from(limit.clamp(1, 256)).map_err(internal)?;
        let mut conn = pg_conn(&self.pool).await?;
        let rows = sql_query(format!(
            "SELECT {NOTICE_COLUMNS} FROM service_route_handover_notices \
             WHERE service_id = $1 AND service_kind = $2 AND handover_id = $3 \
             ORDER BY notice_revision ASC LIMIT $4"
        ))
        .bind::<Text, _>(service_id.as_str())
        .bind::<Text, _>(service_kind)
        .bind::<Text, _>(handover_id)
        .bind::<BigInt, _>(limit)
        .get_results::<NoticeRow>(&mut conn)
        .await
        .map_err(internal)?;
        rows.into_iter().map(NoticeRow::decode).collect()
    }

    async fn audience(
        &self,
        service_id: &DidCoreId,
        service_kind: &str,
        handover_id: &str,
    ) -> PersistenceResult<Vec<ServiceRouteHandoverAudienceEntry>> {
        let mut conn = pg_conn(&self.pool).await?;
        let rows = sql_query(format!(
            "SELECT {AUDIENCE_COLUMNS} FROM service_route_handover_audience \
             WHERE service_id = $1 AND service_kind = $2 AND handover_id = $3 \
             ORDER BY realm_id ASC, peer_service_id ASC"
        ))
        .bind::<Text, _>(service_id.as_str())
        .bind::<Text, _>(service_kind)
        .bind::<Text, _>(handover_id)
        .get_results::<AudienceRow>(&mut conn)
        .await
        .map_err(internal)?;
        rows.into_iter().map(AudienceRow::decode).collect()
    }

    async fn reconcile_audience(
        &self,
        service_id: &DidCoreId,
        service_kind: &str,
        handover_id: &str,
        notice_digest: &Hash,
        targets: Vec<ServiceRouteHandoverAudienceTarget>,
        updated_at: DateTime<Utc>,
    ) -> PersistenceResult<ServiceRouteHandoverPlanWrite> {
        let mut desired = std::collections::BTreeMap::<
            (String, String),
            ServiceRouteHandoverAudienceTarget,
        >::new();
        for mut target in targets {
            if target.realm_id.trim().is_empty() || target.peer_service_id == *service_id {
                return Err(PersistenceError::SchemaViolation(
                    "handover audience target must name a Realm and a remote service".to_owned(),
                ));
            }
            target.accepted_frontier.sort();
            target.accepted_frontier.dedup();
            desired
                .entry((
                    target.realm_id.clone(),
                    target.peer_service_id.as_str().to_owned(),
                ))
                .and_modify(|existing| {
                    existing
                        .accepted_frontier
                        .append(&mut target.accepted_frontier);
                    existing.accepted_frontier.sort();
                    existing.accepted_frontier.dedup();
                })
                .or_insert(target);
        }

        let mut conn = pg_conn(&self.pool).await?;
        let service_id = service_id.clone();
        let service_kind = service_kind.to_owned();
        let handover_id = handover_id.to_owned();
        let notice_digest = notice_digest.clone();
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            lock_plan_slot(conn, &service_id, &service_kind).await?;
            let Some(plan) = load_plan(conn, &service_id, &service_kind, &handover_id).await? else {
                return Ok(ServiceRouteHandoverPlanWrite::Rejected);
            };
            if plan.state.is_terminal()
                || plan.active_notice_digest.as_ref() != Some(&notice_digest)
            {
                return Ok(ServiceRouteHandoverPlanWrite::Rejected);
            }

            sql_query(
                "UPDATE service_route_handover_audience \
                 SET required = false, audience_status = 'removed', \
                     removed_reason = 'accepted_relationship_revoked', updated_at = $4 \
                 WHERE service_id = $1 AND service_kind = $2 AND handover_id = $3 \
                   AND required = true",
            )
            .bind::<Text, _>(service_id.as_str())
            .bind::<Text, _>(service_kind.as_str())
            .bind::<Text, _>(handover_id.as_str())
            .bind::<Timestamptz, _>(updated_at)
            .execute(conn)
            .await?;

            for (_, target) in desired {
                let frontier = serde_json::to_value(target.accepted_frontier).map_err(internal)?;
                sql_query(
                    "INSERT INTO service_route_handover_audience \
                         (service_id, service_kind, handover_id, realm_id, peer_service_id, \
                          notice_digest, accepted_frontier, required, audience_status, \
                          removed_reason, created_at, updated_at) \
                     VALUES ($1, $2, $3, $4, $5, $6, $7, true, 'pending', NULL, $8, $8) \
                     ON CONFLICT (service_id, service_kind, handover_id, realm_id, peer_service_id) \
                     DO UPDATE SET notice_digest = EXCLUDED.notice_digest, \
                         accepted_frontier = EXCLUDED.accepted_frontier, required = true, \
                         audience_status = 'pending', removed_reason = NULL, updated_at = EXCLUDED.updated_at",
                )
                .bind::<Text, _>(service_id.as_str())
                .bind::<Text, _>(service_kind.as_str())
                .bind::<Text, _>(handover_id.as_str())
                .bind::<Text, _>(target.realm_id)
                .bind::<Text, _>(target.peer_service_id.as_str())
                .bind::<Text, _>(notice_digest.as_str())
                .bind::<Jsonb, _>(frontier)
                .bind::<Timestamptz, _>(updated_at)
                .execute(conn)
                .await?;
            }
            Ok(ServiceRouteHandoverPlanWrite::Applied)
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }

    async fn open_plan(
        &self,
        plan: ServiceRouteHandoverPlan,
    ) -> PersistenceResult<ServiceRouteHandoverPlanWrite> {
        let mut conn = pg_conn(&self.pool).await?;
        let basis_sequence = sequence_to_sql(plan.basis_record_sequence)?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            lock_plan_slot(conn, &plan.service_id, &plan.service_kind).await?;

            if let Some(existing) = load_plan(
                conn,
                &plan.service_id,
                &plan.service_kind,
                &plan.handover_id,
            )
            .await?
            {
                return Ok(if existing.matches_definition(&plan) {
                    ServiceRouteHandoverPlanWrite::Replay
                } else {
                    ServiceRouteHandoverPlanWrite::Rejected
                });
            }

            let active = sql_query(format!(
                "SELECT {PLAN_COLUMNS} FROM service_route_handover_plans \
                 WHERE service_id = $1 AND service_kind = $2 \
                   AND lifecycle_state NOT IN ('completed', 'cancelled', 'failed')"
            ))
            .bind::<Text, _>(plan.service_id.as_str())
            .bind::<Text, _>(plan.service_kind.as_str())
            .get_result::<PlanRow>(conn)
            .await
            .optional()?;
            if let Some(active) = active {
                return Ok(ServiceRouteHandoverPlanWrite::PlanAlreadyActive {
                    handover_id: active.handover_id,
                });
            }

            sql_query(format!(
                "INSERT INTO service_route_handover_plans ({PLAN_COLUMNS}) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, NULL, NULL, NULL, \
                 $13, $14)"
            ))
            .bind::<Text, _>(plan.service_id.as_str())
            .bind::<Text, _>(plan.service_kind.as_str())
            .bind::<Text, _>(plan.handover_id.as_str())
            .bind::<BigInt, _>(basis_sequence)
            .bind::<Text, _>(plan.basis_record_digest.as_str())
            .bind::<Text, _>(plan.candidate_base_url.as_str())
            .bind::<Text, _>(plan.candidate_record_url.as_str())
            .bind::<Timestamptz, _>(plan.not_before)
            .bind::<Timestamptz, _>(plan.cutover_at)
            .bind::<Timestamptz, _>(plan.grace_until)
            .bind::<Timestamptz, _>(plan.expires_at)
            .bind::<Text, _>(plan.state.as_str())
            .bind::<Timestamptz, _>(plan.created_at)
            .bind::<Timestamptz, _>(plan.updated_at)
            .execute(conn)
            .await?;
            Ok(ServiceRouteHandoverPlanWrite::Applied)
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }

    async fn commit_notice(
        &self,
        commit: ServiceRouteHandoverNoticeCommit,
    ) -> PersistenceResult<ServiceRouteHandoverPlanWrite> {
        commit.notice.validate()?;
        let digest =
            Hash::new(arkret_canonical::canonical_sha256(&commit.notice.notice).map_err(internal)?)
                .map_err(internal)?;
        if digest != commit.notice.notice_digest {
            return Err(PersistenceError::SchemaViolation(
                "service route handover notice digest does not cover its signed bytes".to_owned(),
            ));
        }
        let revision = revision_to_sql(commit.notice.notice_revision)?;
        let notice_json = serde_json::to_value(&commit.notice.notice).map_err(internal)?;
        let mut conn = pg_conn(&self.pool).await?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            let record = &commit.notice;
            lock_plan_slot(conn, &record.service_id, &record.service_kind).await?;

            let Some(plan) = load_plan(
                conn,
                &record.service_id,
                &record.service_kind,
                &record.handover_id,
            )
            .await?
            else {
                return Ok(ServiceRouteHandoverPlanWrite::Rejected);
            };
            if plan.state.is_terminal() {
                return Ok(ServiceRouteHandoverPlanWrite::Rejected);
            }

            // Identical bytes for a revision already stored are a replay
            // whatever the caller believed the head to be. A client that lost
            // the first response and retries must not be told its own write is
            // a conflict.
            let existing = sql_query(format!(
                "SELECT {NOTICE_COLUMNS} FROM service_route_handover_notices \
                 WHERE service_id = $1 AND service_kind = $2 AND handover_id = $3 \
                   AND notice_revision = $4 FOR UPDATE"
            ))
            .bind::<Text, _>(record.service_id.as_str())
            .bind::<Text, _>(record.service_kind.as_str())
            .bind::<Text, _>(record.handover_id.as_str())
            .bind::<Integer, _>(revision)
            .get_result::<NoticeRow>(conn)
            .await
            .optional()?;
            if let Some(existing) = existing {
                let accepted = hash(existing.notice_digest)?;
                return Ok(if accepted == digest {
                    ServiceRouteHandoverPlanWrite::Replay
                } else {
                    ServiceRouteHandoverPlanWrite::RevisionConflict {
                        accepted_digest: Some(accepted),
                    }
                });
            }

            if plan.basis_record_digest != commit.expected_basis_digest
                || plan.basis_record_sequence != record.notice.notice.from_record_sequence
                || plan.basis_record_digest != record.notice.notice.from_record_digest
            {
                return Ok(ServiceRouteHandoverPlanWrite::BasisChanged {
                    accepted_digest: Some(plan.basis_record_digest),
                });
            }
            if plan.active_notice_digest != commit.expected_active_notice_digest {
                return Ok(ServiceRouteHandoverPlanWrite::RevisionConflict {
                    accepted_digest: plan.active_notice_digest,
                });
            }

            let expected_revision = plan
                .active_notice_revision
                .map_or(0, |revision| revision.saturating_add(1));
            if record.notice_revision != expected_revision
                || record.previous_notice_digest != plan.active_notice_digest
            {
                return Ok(ServiceRouteHandoverPlanWrite::RevisionConflict {
                    accepted_digest: plan.active_notice_digest,
                });
            }

            sql_query(format!(
                "INSERT INTO service_route_handover_notices ({NOTICE_COLUMNS}) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)"
            ))
            .bind::<Text, _>(record.service_id.as_str())
            .bind::<Text, _>(record.service_kind.as_str())
            .bind::<Text, _>(record.handover_id.as_str())
            .bind::<Integer, _>(revision)
            .bind::<Text, _>(digest.as_str())
            .bind::<Nullable<Text>, _>(
                record
                    .previous_notice_digest
                    .as_ref()
                    .map(|value| value.as_str().to_owned()),
            )
            .bind::<Text, _>(notice_state_str(record.state))
            .bind::<Jsonb, _>(notice_json)
            .bind::<Timestamptz, _>(record.issued_at)
            .bind::<Timestamptz, _>(record.expires_at)
            .execute(conn)
            .await?;

            sql_query(
                "UPDATE service_route_handover_plans \
                 SET active_notice_revision = $4, active_notice_digest = $5, \
                     lifecycle_state = $6, updated_at = $7 \
                 WHERE service_id = $1 AND service_kind = $2 AND handover_id = $3",
            )
            .bind::<Text, _>(record.service_id.as_str())
            .bind::<Text, _>(record.service_kind.as_str())
            .bind::<Text, _>(record.handover_id.as_str())
            .bind::<Integer, _>(revision)
            .bind::<Text, _>(digest.as_str())
            .bind::<Text, _>(commit.next_state.as_str())
            .bind::<Timestamptz, _>(commit.updated_at)
            .execute(conn)
            .await?;
            Ok(ServiceRouteHandoverPlanWrite::Applied)
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }

    async fn advance_plan_state(
        &self,
        service_id: &DidCoreId,
        service_kind: &str,
        handover_id: &str,
        expected_state: ServiceRouteHandoverPlanState,
        next_state: ServiceRouteHandoverPlanState,
        last_error: Option<String>,
        updated_at: DateTime<Utc>,
    ) -> PersistenceResult<ServiceRouteHandoverPlanWrite> {
        let mut conn = pg_conn(&self.pool).await?;
        let service_id = service_id.clone();
        let service_kind = service_kind.to_owned();
        let handover_id = handover_id.to_owned();
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            lock_plan_slot(conn, &service_id, &service_kind).await?;
            let Some(plan) = load_plan(conn, &service_id, &service_kind, &handover_id).await?
            else {
                return Ok(ServiceRouteHandoverPlanWrite::Rejected);
            };
            if plan.state == next_state && plan.last_error == last_error {
                return Ok(ServiceRouteHandoverPlanWrite::Replay);
            }
            if plan.state != expected_state || expected_state.is_terminal() {
                return Ok(ServiceRouteHandoverPlanWrite::Rejected);
            }
            sql_query(
                "UPDATE service_route_handover_plans \
                 SET lifecycle_state = $4, last_error = $5, updated_at = $6 \
                 WHERE service_id = $1 AND service_kind = $2 AND handover_id = $3",
            )
            .bind::<Text, _>(service_id.as_str())
            .bind::<Text, _>(service_kind.as_str())
            .bind::<Text, _>(handover_id.as_str())
            .bind::<Text, _>(next_state.as_str())
            .bind::<Nullable<Text>, _>(last_error)
            .bind::<Timestamptz, _>(updated_at)
            .execute(conn)
            .await?;
            Ok(ServiceRouteHandoverPlanWrite::Applied)
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }
}
