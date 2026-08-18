use std::collections::BTreeMap;

use arkret_wire::{DidCoreId, Hash};
use chrono::{DateTime, Utc};
use soland_storage::{
    PersistenceError, PersistenceResult, ServiceRouteHandoverNoticeCommit,
    ServiceRouteHandoverNoticeRecord, ServiceRouteHandoverPlan, ServiceRouteHandoverPlanState,
    ServiceRouteHandoverPlanStore, ServiceRouteHandoverPlanWrite,
};

use super::{Arc, Mutex, async_trait};

type PlanKey = (String, String, String);
type NoticeKey = (String, String, String, u32);

#[derive(Default)]
struct PlanState {
    plans: BTreeMap<PlanKey, ServiceRouteHandoverPlan>,
    notices: BTreeMap<NoticeKey, ServiceRouteHandoverNoticeRecord>,
}

#[derive(Clone, Default)]
pub struct MemoryServiceRouteHandoverPlanStore {
    state: Arc<Mutex<PlanState>>,
}

impl MemoryServiceRouteHandoverPlanStore {
    pub fn new() -> Self {
        Self::default()
    }
}

fn plan_key(service_id: &DidCoreId, service_kind: &str, handover_id: &str) -> PlanKey {
    (
        service_id.as_str().to_owned(),
        service_kind.to_owned(),
        handover_id.to_owned(),
    )
}

fn canonical_notice_digest(record: &ServiceRouteHandoverNoticeRecord) -> PersistenceResult<Hash> {
    Hash::new(
        arkret_canonical::canonical_sha256(&record.notice)
            .map_err(|error| PersistenceError::Internal(error.to_string()))?,
    )
    .map_err(|error| PersistenceError::Internal(error.to_string()))
}

#[async_trait]
impl ServiceRouteHandoverPlanStore for MemoryServiceRouteHandoverPlanStore {
    async fn plan(
        &self,
        service_id: &DidCoreId,
        service_kind: &str,
        handover_id: &str,
    ) -> PersistenceResult<Option<ServiceRouteHandoverPlan>> {
        Ok(self
            .state
            .lock()
            .plans
            .get(&plan_key(service_id, service_kind, handover_id))
            .cloned())
    }

    async fn active_plan(
        &self,
        service_id: &DidCoreId,
        service_kind: &str,
    ) -> PersistenceResult<Option<ServiceRouteHandoverPlan>> {
        Ok(self
            .state
            .lock()
            .plans
            .values()
            .find(|plan| {
                plan.service_id == *service_id
                    && plan.service_kind == service_kind
                    && !plan.state.is_terminal()
            })
            .cloned())
    }

    async fn list_plans(
        &self,
        service_id: &DidCoreId,
        service_kind: &str,
        limit: usize,
    ) -> PersistenceResult<Vec<ServiceRouteHandoverPlan>> {
        let limit = limit.clamp(1, 256);
        let mut plans: Vec<_> = self
            .state
            .lock()
            .plans
            .values()
            .filter(|plan| plan.service_id == *service_id && plan.service_kind == service_kind)
            .cloned()
            .collect();
        plans.sort_by(|left, right| {
            right
                .created_at
                .cmp(&left.created_at)
                .then_with(|| left.handover_id.cmp(&right.handover_id))
        });
        plans.truncate(limit);
        Ok(plans)
    }

    async fn notices(
        &self,
        service_id: &DidCoreId,
        service_kind: &str,
        handover_id: &str,
        limit: usize,
    ) -> PersistenceResult<Vec<ServiceRouteHandoverNoticeRecord>> {
        let limit = limit.clamp(1, 256);
        let mut notices: Vec<_> = self
            .state
            .lock()
            .notices
            .values()
            .filter(|record| {
                record.service_id == *service_id
                    && record.service_kind == service_kind
                    && record.handover_id == handover_id
            })
            .cloned()
            .collect();
        notices.sort_by_key(|record| record.notice_revision);
        notices.truncate(limit);
        Ok(notices)
    }

    async fn open_plan(
        &self,
        plan: ServiceRouteHandoverPlan,
    ) -> PersistenceResult<ServiceRouteHandoverPlanWrite> {
        let key = plan_key(&plan.service_id, &plan.service_kind, &plan.handover_id);
        let mut state = self.state.lock();
        if let Some(existing) = state.plans.get(&key) {
            return Ok(if existing.matches_definition(&plan) {
                ServiceRouteHandoverPlanWrite::Replay
            } else {
                ServiceRouteHandoverPlanWrite::Rejected
            });
        }
        if let Some(active) = state.plans.values().find(|candidate| {
            candidate.service_id == plan.service_id
                && candidate.service_kind == plan.service_kind
                && !candidate.state.is_terminal()
        }) {
            return Ok(ServiceRouteHandoverPlanWrite::PlanAlreadyActive {
                handover_id: active.handover_id.clone(),
            });
        }
        state.plans.insert(key, plan);
        Ok(ServiceRouteHandoverPlanWrite::Applied)
    }

    async fn commit_notice(
        &self,
        commit: ServiceRouteHandoverNoticeCommit,
    ) -> PersistenceResult<ServiceRouteHandoverPlanWrite> {
        commit.notice.validate()?;
        let digest = canonical_notice_digest(&commit.notice)?;
        if digest != commit.notice.notice_digest {
            return Err(PersistenceError::SchemaViolation(
                "service route handover notice digest does not cover its signed bytes".to_owned(),
            ));
        }
        let record = commit.notice;
        let key = plan_key(
            &record.service_id,
            &record.service_kind,
            &record.handover_id,
        );
        let notice_key = (
            key.0.clone(),
            key.1.clone(),
            key.2.clone(),
            record.notice_revision,
        );
        let mut state = self.state.lock();

        let Some(plan) = state.plans.get(&key).cloned() else {
            return Ok(ServiceRouteHandoverPlanWrite::Rejected);
        };
        if plan.state.is_terminal() {
            return Ok(ServiceRouteHandoverPlanWrite::Rejected);
        }
        // Identical bytes for a revision already stored are a replay whatever
        // the caller believed the head to be. A client that lost the first
        // response and retries must not be told its own write is a conflict.
        if let Some(existing) = state.notices.get(&notice_key) {
            return Ok(if existing.notice_digest == digest {
                ServiceRouteHandoverPlanWrite::Replay
            } else {
                ServiceRouteHandoverPlanWrite::RevisionConflict {
                    accepted_digest: Some(existing.notice_digest.clone()),
                }
            });
        }
        if plan.basis_record_digest != commit.expected_basis_digest {
            return Ok(ServiceRouteHandoverPlanWrite::BasisChanged {
                accepted_digest: Some(plan.basis_record_digest),
            });
        }
        if plan.basis_record_sequence != record.notice.notice.from_record_sequence
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

        let mut updated = plan;
        updated.active_notice_revision = Some(record.notice_revision);
        updated.active_notice_digest = Some(digest);
        updated.state = commit.next_state;
        updated.updated_at = commit.updated_at;
        state.notices.insert(notice_key, record);
        state.plans.insert(key, updated);
        Ok(ServiceRouteHandoverPlanWrite::Applied)
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
        let key = plan_key(service_id, service_kind, handover_id);
        let mut state = self.state.lock();
        let Some(plan) = state.plans.get_mut(&key) else {
            return Ok(ServiceRouteHandoverPlanWrite::Rejected);
        };
        if plan.state == next_state && plan.last_error == last_error {
            return Ok(ServiceRouteHandoverPlanWrite::Replay);
        }
        if plan.state != expected_state || expected_state.is_terminal() {
            return Ok(ServiceRouteHandoverPlanWrite::Rejected);
        }
        plan.state = next_state;
        plan.last_error = last_error;
        plan.updated_at = updated_at;
        Ok(ServiceRouteHandoverPlanWrite::Applied)
    }
}
