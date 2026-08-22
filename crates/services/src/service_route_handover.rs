//! Owner-side planning for a same-core service route handover.
//!
//! This is the deployment-local control plane that lets an operator announce,
//! ahead of time, that this service's route is about to move — and then prove,
//! from durable state, whether it is safe to close the old entry.
//!
//! It is deliberately *not* the receiving [`crate::service_route`] resolver.
//! That one decides whether to believe someone else's route; this one issues
//! statements about our own and never grants itself a shortcut past the
//! evidence a peer will demand.
//!
//! Two protocol constraints shape the whole module:
//!
//! - Publishing or revising a notice MUST NOT consume a `ServiceResolutionRecord` sequence
//!   (arkret-spec `sync/service-surface.md` §2.6). So the planner reads the current record as a
//!   *basis* and never calls the code path that mints a successor.
//! - A notice is only meaningful against the exact record its recipients already hold. If the basis
//!   moves underneath a plan, the plan is invalid; it is never silently re-targeted at the new
//!   record.

use std::collections::BTreeMap;
use std::sync::Arc;

use arkret_models_identity::service_identity::CanonicalServiceUrl;
use arkret_models_identity::{
    ServiceResolutionRecord, ServiceRouteHandoverNotice, ServiceRouteHandoverNoticeCore,
    ServiceRouteHandoverState, canonical_service_current_record_path,
    validate_service_current_record_url,
};
use arkret_wire::{DidCoreId, Hash};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use soland_domain::reducer::ProjectionState;
use soland_storage::{
    ConflictCode, ServiceRouteHandoverAudienceEntry, ServiceRouteHandoverAudienceTarget,
    ServiceRouteHandoverNoticeCommit, ServiceRouteHandoverNoticeRecord, ServiceRouteHandoverPlan,
    ServiceRouteHandoverPlanState, ServiceRouteHandoverPlanStore, ServiceRouteHandoverPlanWrite,
};

use crate::{ServiceError, ServiceResult};

/// Signs owner-issued route artifacts.
///
/// The planner never holds a private key. The implementation lives at the
/// composition root, where the runtime signer is already bound to a current
/// service assertion method, and it is the only place that can turn a core
/// into signed bytes.
#[async_trait]
pub trait ServiceRouteNoticeSigner: Send + Sync {
    async fn sign_handover_notice(
        &self,
        core: ServiceRouteHandoverNoticeCore,
    ) -> ServiceResult<ServiceRouteHandoverNotice>;
}

/// Reads this deployment's own current signed resolution record.
///
/// Deliberately read-only: the mint-a-successor path advances the record
/// sequence, which a notice must never do.
#[async_trait]
pub trait CurrentServiceResolutionPort: Send + Sync {
    async fn current_record(&self) -> ServiceResult<Option<ServiceResolutionRecord>>;
}

/// Operator input for a new planned handover.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HandoverPlanRequest {
    pub handover_id: String,
    /// Canonical base URL the service will answer on after the cutover. The
    /// record URL is derived from it mechanically; it is never supplied.
    pub candidate_base_url: String,
    pub not_before: DateTime<Utc>,
    pub cutover_at: DateTime<Utc>,
    pub grace_until: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

/// A plan together with the notice revision that most recently advanced it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlannedHandover {
    pub plan: ServiceRouteHandoverPlan,
    pub notice: ServiceRouteHandoverNotice,
}

/// Build the owner-side inverse index from accepted effective member state.
///
/// No configured peer, contact, DID namespace, or historical event enters
/// this function. A Realm participates only when a current routable member is
/// bound to this deployment; targets are current routable remote bindings in
/// that same Realm. Both sides must retain an accepted frontier, so an
/// incomplete projection fails closed instead of producing an unauditable
/// notification target.
#[must_use]
pub fn derive_realm_handover_audience(
    projection: &ProjectionState,
    local_service_id: &DidCoreId,
    now: DateTime<Utc>,
) -> Vec<ServiceRouteHandoverAudienceTarget> {
    let effective = |member: &soland_domain::reducer::SolandMembershipState| {
        member.state == "join"
            && member.delivery_status.as_deref() == Some("routable")
            && member
                .delivery_binding_expires_at
                .is_none_or(|expires_at| expires_at > now)
    };

    let mut local_frontiers = BTreeMap::<String, Vec<String>>::new();
    for member in projection
        .members
        .values()
        .filter(|member| effective(member))
    {
        if member.recipient_service_id.as_deref() != Some(local_service_id.as_str()) {
            continue;
        }
        let Some(frontier) = member
            .delivery_binding_frontier
            .as_ref()
            .or(member.membership_event_ref.as_ref())
        else {
            continue;
        };
        local_frontiers
            .entry(member.realm_id.clone())
            .or_default()
            .push(frontier.clone());
    }
    for frontiers in local_frontiers.values_mut() {
        frontiers.sort();
        frontiers.dedup();
    }

    let mut targets = BTreeMap::<(String, String), ServiceRouteHandoverAudienceTarget>::new();
    for member in projection
        .members
        .values()
        .filter(|member| effective(member))
    {
        let Some(local_basis) = local_frontiers.get(&member.realm_id) else {
            continue;
        };
        let Some(peer) = member
            .recipient_service_id
            .as_deref()
            .and_then(|value| DidCoreId::new(value.to_owned()).ok())
        else {
            continue;
        };
        if peer == *local_service_id {
            continue;
        }
        if projection
            .federation_delivery_revoked_peers(&member.realm_id)
            .contains(peer.as_str())
        {
            continue;
        }
        let Some(peer_frontier) = member
            .delivery_binding_frontier
            .as_ref()
            .or(member.membership_event_ref.as_ref())
        else {
            continue;
        };
        let key = (member.realm_id.clone(), peer.as_str().to_owned());
        targets
            .entry(key)
            .and_modify(|target| target.accepted_frontier.push(peer_frontier.clone()))
            .or_insert_with(|| {
                let mut accepted_frontier = local_basis.clone();
                accepted_frontier.push(peer_frontier.clone());
                ServiceRouteHandoverAudienceTarget {
                    realm_id: member.realm_id.clone(),
                    peer_service_id: peer,
                    accepted_frontier,
                }
            });
    }
    targets
        .into_values()
        .map(|mut target| {
            target.accepted_frontier.sort();
            target.accepted_frontier.dedup();
            target
        })
        .collect()
}

/// Owner-side handover control plane.
pub struct ServiceRouteHandoverPlanner {
    plans: Arc<dyn ServiceRouteHandoverPlanStore>,
    signer: Arc<dyn ServiceRouteNoticeSigner>,
    resolution: Arc<dyn CurrentServiceResolutionPort>,
    service_id: DidCoreId,
    service_kind: String,
    require_https: bool,
}

fn conflict(code: ConflictCode, detail: impl std::fmt::Display) -> ServiceError {
    ServiceError::Conflict(format!("{}: {detail}", code.as_str()))
}

fn record_digest(record: &ServiceResolutionRecord) -> ServiceResult<Hash> {
    Hash::new(
        arkret_canonical::canonical_sha256(record)
            .map_err(|error| ServiceError::Internal(error.to_string()))?,
    )
    .map_err(|error| ServiceError::Internal(error.to_string()))
}

fn notice_digest(notice: &ServiceRouteHandoverNotice) -> ServiceResult<Hash> {
    Hash::new(
        arkret_canonical::canonical_sha256(notice)
            .map_err(|error| ServiceError::Internal(error.to_string()))?,
    )
    .map_err(|error| ServiceError::Internal(error.to_string()))
}

/// Map a rejected conditional write onto a caller-facing failure.
///
/// Each variant gets a distinct code because the operator action differs:
/// a moved basis needs a rebuilt plan, an occupied slot needs the previous
/// handover finished or cancelled first.
fn plan_write_error(write: ServiceRouteHandoverPlanWrite) -> ServiceError {
    match write {
        ServiceRouteHandoverPlanWrite::Applied | ServiceRouteHandoverPlanWrite::Replay => {
            ServiceError::Internal(
                "a successful service route plan write was treated as a failure".to_owned(),
            )
        }
        ServiceRouteHandoverPlanWrite::PlanAlreadyActive { handover_id } => conflict(
            ConflictCode::DuplicateConflict,
            format!("service route handover {handover_id} is still unfinished"),
        ),
        ServiceRouteHandoverPlanWrite::BasisChanged { .. } => conflict(
            ConflictCode::CasConflict,
            "the current service resolution record moved; rebuild the plan against it",
        ),
        ServiceRouteHandoverPlanWrite::RevisionConflict { .. } => conflict(
            ConflictCode::CasConflict,
            "the handover notice revision was already advanced",
        ),
        ServiceRouteHandoverPlanWrite::Rejected => conflict(
            ConflictCode::FailedPrecondition,
            "the service route handover plan does not accept this transition",
        ),
    }
}

impl ServiceRouteHandoverPlanner {
    pub fn new(
        plans: Arc<dyn ServiceRouteHandoverPlanStore>,
        signer: Arc<dyn ServiceRouteNoticeSigner>,
        resolution: Arc<dyn CurrentServiceResolutionPort>,
        service_id: DidCoreId,
        service_kind: impl Into<String>,
        require_https: bool,
    ) -> Self {
        Self {
            plans,
            signer,
            resolution,
            service_id,
            service_kind: service_kind.into(),
            require_https,
        }
    }

    /// The exact current record this deployment publishes, with its digest.
    ///
    /// Absent means there is nothing to hand over from, which is a
    /// precondition failure rather than an empty success.
    async fn basis(&self) -> ServiceResult<(ServiceResolutionRecord, Hash)> {
        let Some(record) = self.resolution.current_record().await? else {
            return Err(conflict(
                ConflictCode::FailedPrecondition,
                "this deployment has no current signed service resolution record",
            ));
        };
        if record.record.service_id != self.service_id
            || record.record.service_kind != self.service_kind
        {
            return Err(ServiceError::Internal(
                "the durable current record belongs to another service identity".to_owned(),
            ));
        }
        let digest = record_digest(&record)?;
        Ok((record, digest))
    }

    /// Derive the candidate record URL from the candidate base.
    ///
    /// The operator supplies only a base: a hand-written record URL could
    /// point somewhere the base does not, and every recipient re-derives this
    /// value anyway.
    fn candidate_urls(&self, candidate_base_url: &str) -> ServiceResult<(String, String)> {
        let base = CanonicalServiceUrl::canonicalize(candidate_base_url).map_err(|error| {
            ServiceError::SchemaViolation(format!("candidate base URL is invalid: {error}"))
        })?;
        if self.require_https {
            base.require_https()
                .map_err(|error| ServiceError::SchemaViolation(error.to_string()))?;
        }
        let base = base.as_str().to_owned();
        let path = canonical_service_current_record_path(&self.service_id);
        let record_url = format!("{base}{}", path.trim_start_matches('/'));
        if self.require_https {
            validate_service_current_record_url(&record_url, &self.service_id).map_err(
                |error| {
                    ServiceError::SchemaViolation(format!(
                        "derived candidate record URL is not canonical: {error}"
                    ))
                },
            )?;
        }
        Ok((base, record_url))
    }

    /// Sign one notice revision and commit it against the plan head.
    ///
    /// The basis is re-read after signing: signing is not instantaneous, and
    /// a record minted in between would make the signed `from_record_*` stale.
    /// The store then re-checks the same expectation under its own lock, so a
    /// racing writer cannot slip between this check and the write.
    async fn sign_and_commit(
        &self,
        core: ServiceRouteHandoverNoticeCore,
        expected_basis_digest: Hash,
        expected_active_notice_digest: Option<Hash>,
        next_state: ServiceRouteHandoverPlanState,
        now: DateTime<Utc>,
    ) -> ServiceResult<ServiceRouteHandoverNotice> {
        core.validate_shape()
            .map_err(|error| ServiceError::SchemaViolation(error.to_string()))?;
        let handover_id = core.handover_id.clone();
        let notice = self.signer.sign_handover_notice(core).await?;
        let digest = notice_digest(&notice)?;

        let (_, current_basis) = self.basis().await?;
        if current_basis != expected_basis_digest {
            return Err(conflict(
                ConflictCode::CasConflict,
                "the current service resolution record moved while the notice was being signed",
            ));
        }

        let record = ServiceRouteHandoverNoticeRecord {
            service_id: self.service_id.clone(),
            service_kind: self.service_kind.clone(),
            handover_id,
            notice_revision: notice.notice.notice_revision,
            notice_digest: digest,
            previous_notice_digest: notice.notice.previous_notice_digest.clone(),
            state: notice.notice.state,
            notice: notice.clone(),
            issued_at: notice.notice.issued_at,
            expires_at: notice.notice.expires_at,
        };
        let write = self
            .plans
            .commit_notice(ServiceRouteHandoverNoticeCommit {
                notice: record,
                expected_basis_digest,
                expected_active_notice_digest,
                next_state,
                updated_at: now,
            })
            .await?;
        match write {
            ServiceRouteHandoverPlanWrite::Applied | ServiceRouteHandoverPlanWrite::Replay => {
                Ok(notice)
            }
            other => Err(plan_write_error(other)),
        }
    }

    /// Open a plan and publish revision 0 of its scheduled notice.
    pub async fn plan(
        &self,
        request: HandoverPlanRequest,
        now: DateTime<Utc>,
    ) -> ServiceResult<PlannedHandover> {
        if request.handover_id.trim().is_empty() {
            return Err(ServiceError::SchemaViolation(
                "handover id must not be empty".to_owned(),
            ));
        }
        // `validate_shape` enforces the ordering; this adds the one thing it
        // cannot know: a window that already started cannot be preannounced.
        if now > request.not_before {
            return Err(ServiceError::SchemaViolation(
                "handover not_before is already in the past".to_owned(),
            ));
        }

        let (_, basis_digest) = self.basis().await?;
        let (candidate_base_url, candidate_record_url) =
            self.candidate_urls(&request.candidate_base_url)?;
        let (basis_record, basis_digest_recheck) = self.basis().await?;
        if basis_digest != basis_digest_recheck {
            return Err(conflict(
                ConflictCode::CasConflict,
                "the current service resolution record moved while the plan was being prepared",
            ));
        }
        let basis_sequence = basis_record.record.record_sequence;

        let plan = ServiceRouteHandoverPlan {
            service_id: self.service_id.clone(),
            service_kind: self.service_kind.clone(),
            handover_id: request.handover_id.clone(),
            basis_record_sequence: basis_sequence,
            basis_record_digest: basis_digest.clone(),
            candidate_base_url: candidate_base_url.clone(),
            candidate_record_url: candidate_record_url.clone(),
            not_before: request.not_before,
            cutover_at: request.cutover_at,
            grace_until: request.grace_until,
            expires_at: request.expires_at,
            state: ServiceRouteHandoverPlanState::Draft,
            active_notice_revision: None,
            active_notice_digest: None,
            last_error: None,
            created_at: now,
            updated_at: now,
        };
        match self.plans.open_plan(plan).await? {
            ServiceRouteHandoverPlanWrite::Applied | ServiceRouteHandoverPlanWrite::Replay => {}
            other => return Err(plan_write_error(other)),
        }

        // A retried submit of the identical plan returns what was already
        // published. Re-signing would stamp a fresh `issued_at` and therefore
        // produce different bytes for revision 0, which the store would then
        // have to reject — an operator double-click is not a conflict.
        if let Some(existing) = self
            .plans
            .plan(&self.service_id, &self.service_kind, &request.handover_id)
            .await?
            && existing.active_notice_revision.is_some()
        {
            let published = self
                .plans
                .notices(
                    &self.service_id,
                    &self.service_kind,
                    &request.handover_id,
                    1,
                )
                .await?
                .into_iter()
                .next()
                .ok_or_else(|| {
                    ServiceError::Internal(
                        "the plan head names a notice revision the transcript does not hold"
                            .to_owned(),
                    )
                })?;
            return Ok(PlannedHandover {
                plan: existing,
                notice: published.notice,
            });
        }

        let core = ServiceRouteHandoverNoticeCore {
            service_id: self.service_id.clone(),
            service_kind: self.service_kind.clone(),
            handover_id: request.handover_id.clone(),
            notice_revision: 0,
            state: ServiceRouteHandoverState::Scheduled,
            from_record_sequence: basis_sequence,
            from_record_digest: basis_digest.clone(),
            candidate_base_url: Some(candidate_base_url),
            candidate_record_url: Some(candidate_record_url),
            issued_at: now,
            not_before: Some(request.not_before),
            cutover_at: Some(request.cutover_at),
            grace_until: Some(request.grace_until),
            previous_notice_digest: None,
            expires_at: request.expires_at,
        };
        let notice = self
            .sign_and_commit(
                core,
                basis_digest,
                None,
                ServiceRouteHandoverPlanState::Publishing,
                now,
            )
            .await?;
        self.planned(&request.handover_id, notice).await
    }

    /// Publish the next revision, cancelling a plan that has not yet been
    /// superseded by a formal successor record.
    ///
    /// A late cancellation cannot roll a route back: once recipients accepted
    /// the successor, returning to the old URL needs a new record chain, not a
    /// retracted notice. That is enforced downstream at cutover; here the
    /// guard is that a plan past `Cutover` no longer accepts a cancel.
    pub async fn cancel(
        &self,
        handover_id: &str,
        expected_previous_notice_digest: &Hash,
        now: DateTime<Utc>,
    ) -> ServiceResult<PlannedHandover> {
        let Some(plan) = self
            .plans
            .plan(&self.service_id, &self.service_kind, handover_id)
            .await?
        else {
            return Err(ServiceError::NotFound(
                "service route handover plan not found".to_owned(),
            ));
        };
        if plan.state.is_terminal() {
            return Err(conflict(
                ConflictCode::FailedPrecondition,
                "the service route handover plan is already finished",
            ));
        }
        if matches!(
            plan.state,
            ServiceRouteHandoverPlanState::Cutover
                | ServiceRouteHandoverPlanState::Grace
                | ServiceRouteHandoverPlanState::Quarantined
        ) {
            return Err(conflict(
                ConflictCode::FailedPrecondition,
                "the candidate already published a formal successor; cancelling cannot roll the \
                 route back",
            ));
        }
        let (Some(active_revision), Some(active_digest)) = (
            plan.active_notice_revision,
            plan.active_notice_digest.clone(),
        ) else {
            return Err(conflict(
                ConflictCode::FailedPrecondition,
                "the service route handover plan has no published notice to cancel",
            ));
        };
        if active_digest != *expected_previous_notice_digest {
            return Err(conflict(
                ConflictCode::CasConflict,
                "the expected previous notice digest is not the active revision",
            ));
        }

        let core = ServiceRouteHandoverNoticeCore {
            service_id: self.service_id.clone(),
            service_kind: self.service_kind.clone(),
            handover_id: handover_id.to_owned(),
            notice_revision: active_revision.saturating_add(1),
            state: ServiceRouteHandoverState::Cancelled,
            from_record_sequence: plan.basis_record_sequence,
            from_record_digest: plan.basis_record_digest.clone(),
            candidate_base_url: None,
            candidate_record_url: None,
            issued_at: now,
            not_before: None,
            cutover_at: None,
            grace_until: None,
            previous_notice_digest: Some(active_digest.clone()),
            expires_at: plan.expires_at,
        };
        let notice = self
            .sign_and_commit(
                core,
                plan.basis_record_digest,
                Some(active_digest),
                ServiceRouteHandoverPlanState::Cancelled,
                now,
            )
            .await?;
        self.planned(handover_id, notice).await
    }

    async fn planned(
        &self,
        handover_id: &str,
        notice: ServiceRouteHandoverNotice,
    ) -> ServiceResult<PlannedHandover> {
        let plan = self
            .plans
            .plan(&self.service_id, &self.service_kind, handover_id)
            .await?
            .ok_or_else(|| {
                ServiceError::Internal(
                    "the service route handover plan disappeared after a successful write"
                        .to_owned(),
                )
            })?;
        Ok(PlannedHandover { plan, notice })
    }

    pub async fn plan_detail(
        &self,
        handover_id: &str,
        notice_limit: usize,
    ) -> ServiceResult<
        Option<(
            ServiceRouteHandoverPlan,
            Vec<ServiceRouteHandoverNoticeRecord>,
        )>,
    > {
        let Some(plan) = self
            .plans
            .plan(&self.service_id, &self.service_kind, handover_id)
            .await?
        else {
            return Ok(None);
        };
        let notices = self
            .plans
            .notices(
                &self.service_id,
                &self.service_kind,
                handover_id,
                notice_limit,
            )
            .await?;
        Ok(Some((plan, notices)))
    }

    pub async fn list_plans(&self, limit: usize) -> ServiceResult<Vec<ServiceRouteHandoverPlan>> {
        Ok(self
            .plans
            .list_plans(&self.service_id, &self.service_kind, limit)
            .await?)
    }

    pub async fn active_plan(&self) -> ServiceResult<Option<ServiceRouteHandoverPlan>> {
        Ok(self
            .plans
            .active_plan(&self.service_id, &self.service_kind)
            .await?)
    }

    /// Refresh the durable notification set from the current accepted
    /// projection. Callers run this after projection changes and while the old
    /// endpoint remains in grace; restarting cannot forget earlier rows.
    pub async fn reconcile_audience(
        &self,
        projection: &ProjectionState,
        now: DateTime<Utc>,
    ) -> ServiceResult<Vec<ServiceRouteHandoverAudienceEntry>> {
        let Some(plan) = self.active_plan().await? else {
            return Err(conflict(
                ConflictCode::FailedPrecondition,
                "there is no active service route handover plan",
            ));
        };
        if now > plan.grace_until {
            return Err(conflict(
                ConflictCode::FailedPrecondition,
                "the service route handover grace window has ended",
            ));
        }
        let Some(notice_digest) = plan.active_notice_digest.as_ref() else {
            return Err(ServiceError::Internal(
                "the active handover plan has no notice digest".to_owned(),
            ));
        };
        let targets = derive_realm_handover_audience(projection, &self.service_id, now);
        match self
            .plans
            .reconcile_audience(
                &self.service_id,
                &self.service_kind,
                &plan.handover_id,
                notice_digest,
                targets,
                now,
            )
            .await?
        {
            ServiceRouteHandoverPlanWrite::Applied | ServiceRouteHandoverPlanWrite::Replay => {}
            other => return Err(plan_write_error(other)),
        }
        Ok(self
            .plans
            .audience(&self.service_id, &self.service_kind, &plan.handover_id)
            .await?)
    }
}

#[cfg(test)]
mod tests {
    use arkret_models_identity::ServiceResolutionRecordCore;
    use arkret_wire::{Base64UrlString, DidFullId, DidUrl, ProtocolSignature};
    use chrono::{Duration, TimeZone as _};
    use parking_lot::Mutex;
    use soland_storage_memory::MemoryServiceRouteHandoverPlanStore;

    use super::*;

    const FULL: &str = "did:webvh:zCXaWSDv1afiBoxDX5sVBU5an:server.acme.example.com";

    fn hash(byte: char) -> Hash {
        Hash::new(format!("sha256:{}", byte.to_string().repeat(64))).unwrap()
    }

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 19, 0, 0, 0).unwrap()
    }

    fn record(sequence: u64) -> ServiceResolutionRecord {
        let issued_at = now() - Duration::minutes(1);
        let full_id = DidFullId::new(FULL).unwrap();
        ServiceResolutionRecord {
            record: ServiceResolutionRecordCore {
                service_id: DidCoreId::from(
                    arkret_wire::project_full_id_to_core_id(&full_id).unwrap(),
                ),
                service_kind: "principal_server".to_owned(),
                full_id,
                method_history_head: format!("head-{sequence}"),
                version_id: format!("v-{sequence}"),
                resolution_event_ref: format!("did-webvh-entry-{sequence}"),
                record_sequence: sequence,
                previous_record_digest: (sequence > 0).then(|| hash('a')),
                current_record_url: "https://old.example/_arkret/open/services/id/resolution"
                    .to_owned(),
                base_url: "https://old.example/".to_owned(),
                describe_digest: hash('d'),
                issued_at,
                refresh_after: issued_at + Duration::minutes(5),
                expires_at: issued_at + Duration::minutes(10),
            },
            proof: ProtocolSignature {
                verification_method: DidUrl::new(format!("{FULL}#assertion-1")).unwrap(),
                created_at: issued_at,
                jws: Base64UrlString::new("AA".to_owned()).unwrap(),
            },
        }
    }

    fn service_id() -> DidCoreId {
        record(0).record.service_id
    }

    /// Stands in for the composition-root signer. It signs whatever core it is
    /// handed, so a test that reaches it proves the planner accepted the shape.
    struct FakeSigner {
        signed: Mutex<Vec<ServiceRouteHandoverNoticeCore>>,
    }

    #[async_trait]
    impl ServiceRouteNoticeSigner for FakeSigner {
        async fn sign_handover_notice(
            &self,
            core: ServiceRouteHandoverNoticeCore,
        ) -> ServiceResult<ServiceRouteHandoverNotice> {
            self.signed.lock().push(core.clone());
            Ok(ServiceRouteHandoverNotice {
                notice: core,
                proof: ProtocolSignature {
                    verification_method: DidUrl::new(format!("{FULL}#assertion-1")).unwrap(),
                    created_at: now(),
                    jws: Base64UrlString::new("AA".to_owned()).unwrap(),
                },
            })
        }
    }

    struct FakeResolution {
        current: Mutex<Option<ServiceResolutionRecord>>,
    }

    #[async_trait]
    impl CurrentServiceResolutionPort for FakeResolution {
        async fn current_record(&self) -> ServiceResult<Option<ServiceResolutionRecord>> {
            Ok(self.current.lock().clone())
        }
    }

    struct Harness {
        planner: ServiceRouteHandoverPlanner,
        signer: Arc<FakeSigner>,
        resolution: Arc<FakeResolution>,
    }

    fn harness(current: Option<ServiceResolutionRecord>) -> Harness {
        let signer = Arc::new(FakeSigner {
            signed: Mutex::new(Vec::new()),
        });
        let resolution = Arc::new(FakeResolution {
            current: Mutex::new(current),
        });
        let planner = ServiceRouteHandoverPlanner::new(
            Arc::new(MemoryServiceRouteHandoverPlanStore::new()),
            signer.clone(),
            resolution.clone(),
            service_id(),
            "principal_server",
            true,
        );
        Harness {
            planner,
            signer,
            resolution,
        }
    }

    fn request(handover_id: &str) -> HandoverPlanRequest {
        HandoverPlanRequest {
            handover_id: handover_id.to_owned(),
            candidate_base_url: "https://new.example/".to_owned(),
            not_before: now() + Duration::hours(1),
            cutover_at: now() + Duration::hours(2),
            grace_until: now() + Duration::hours(6),
            expires_at: now() + Duration::hours(12),
        }
    }

    fn membership(
        actor: &str,
        realm_id: &str,
        recipient_service_id: &str,
        frontier: &str,
    ) -> soland_domain::reducer::SolandMembershipState {
        soland_domain::reducer::SolandMembershipState {
            member: actor.to_owned(),
            realm_id: realm_id.to_owned(),
            state: "join".to_owned(),
            role: "member".to_owned(),
            delivery_status: Some("routable".to_owned()),
            recipient_service_id: Some(recipient_service_id.to_owned()),
            recipient_service_resolution: None,
            membership_event_ref: Some(frontier.to_owned()),
            delivery_binding_frontier: Some(frontier.to_owned()),
            delivery_binding_expires_at: None,
            invited_at: None,
            joined_at: now(),
            updated_at: now(),
            reason: None,
        }
    }

    #[test]
    fn audience_comes_only_from_current_accepted_realm_bindings() {
        let local = service_id();
        let peer = DidCoreId::new("ak:did_core:web:peer.example").unwrap();
        let mut projection = ProjectionState::default();
        projection.members.insert(
            ("ak:realm:a".to_owned(), "local-a".to_owned()),
            membership("local-a", "ak:realm:a", local.as_str(), "frontier-local-a"),
        );
        projection.members.insert(
            ("ak:realm:a".to_owned(), "remote-a1".to_owned()),
            membership("remote-a1", "ak:realm:a", peer.as_str(), "frontier-peer-a1"),
        );
        projection.members.insert(
            ("ak:realm:a".to_owned(), "remote-a2".to_owned()),
            membership("remote-a2", "ak:realm:a", peer.as_str(), "frontier-peer-a2"),
        );
        projection.members.insert(
            ("ak:realm:b".to_owned(), "local-b".to_owned()),
            membership("local-b", "ak:realm:b", local.as_str(), "frontier-local-b"),
        );
        projection.members.insert(
            ("ak:realm:b".to_owned(), "remote-b".to_owned()),
            membership("remote-b", "ak:realm:b", peer.as_str(), "frontier-peer-b"),
        );

        // Accepted remote membership without local participation is not an
        // audience source. Neither are expired or left bindings.
        projection.members.insert(
            ("ak:realm:c".to_owned(), "remote-c".to_owned()),
            membership("remote-c", "ak:realm:c", peer.as_str(), "frontier-peer-c"),
        );
        let mut expired = membership(
            "expired",
            "ak:realm:a",
            "ak:did_core:web:expired.example",
            "frontier-expired",
        );
        expired.delivery_binding_expires_at = Some(now());
        projection
            .members
            .insert(("ak:realm:a".to_owned(), "expired".to_owned()), expired);
        let mut left = membership(
            "left",
            "ak:realm:a",
            "ak:did_core:web:left.example",
            "frontier-left",
        );
        left.state = "leave".to_owned();
        projection
            .members
            .insert(("ak:realm:a".to_owned(), "left".to_owned()), left);

        let audience = derive_realm_handover_audience(&projection, &local, now());
        assert_eq!(audience.len(), 2, "the peer remains scoped to two Realms");
        assert_eq!(audience[0].realm_id, "ak:realm:a");
        assert_eq!(audience[0].peer_service_id, peer);
        assert_eq!(
            audience[0].accepted_frontier,
            vec![
                "frontier-local-a".to_owned(),
                "frontier-peer-a1".to_owned(),
                "frontier-peer-a2".to_owned(),
            ]
        );
        assert_eq!(audience[1].realm_id, "ak:realm:b");
    }

    #[tokio::test]
    async fn plan_binds_the_exact_current_record_and_derives_the_candidate_url() {
        let harness = harness(Some(record(3)));
        let planned = harness.planner.plan(request("h-1"), now()).await.unwrap();

        let expected_basis =
            Hash::new(arkret_canonical::canonical_sha256(&record(3)).unwrap()).unwrap();
        assert_eq!(planned.plan.basis_record_sequence, 3);
        assert_eq!(planned.plan.basis_record_digest, expected_basis);
        assert_eq!(planned.notice.notice.from_record_sequence, 3);
        assert_eq!(planned.notice.notice.from_record_digest, expected_basis);
        assert_eq!(planned.notice.notice.notice_revision, 0);
        assert!(planned.notice.notice.previous_notice_digest.is_none());
        assert_eq!(
            planned.plan.state,
            ServiceRouteHandoverPlanState::Publishing
        );
        // The record URL is derived, never taken from the operator.
        let expected_url = format!(
            "https://new.example{}",
            canonical_service_current_record_path(&service_id())
        );
        assert_eq!(
            planned.notice.notice.candidate_record_url.as_deref(),
            Some(expected_url.as_str())
        );
    }

    #[tokio::test]
    async fn planning_without_a_current_record_fails_closed() {
        let harness = harness(None);
        let error = harness
            .planner
            .plan(request("h-1"), now())
            .await
            .unwrap_err();
        assert_eq!(
            error.conflict_code(),
            Some(soland_storage::ConflictCode::FailedPrecondition)
        );
        assert!(harness.signer.signed.lock().is_empty());
    }

    #[tokio::test]
    async fn resubmitting_the_identical_plan_returns_the_published_revision() {
        let harness = harness(Some(record(3)));
        let first = harness.planner.plan(request("h-1"), now()).await.unwrap();

        // A retry a minute later must not mint a second revision 0 with a
        // fresh `issued_at`; it returns exactly what peers were already told.
        let again = harness
            .planner
            .plan(request("h-1"), now() + Duration::minutes(1))
            .await
            .unwrap();

        assert_eq!(again.notice, first.notice);
        assert_eq!(
            again.plan.active_notice_digest,
            first.plan.active_notice_digest
        );
        assert_eq!(
            harness.signer.signed.lock().len(),
            1,
            "the retry must not reach the signer"
        );
    }

    #[tokio::test]
    async fn resubmitting_the_same_id_with_a_different_window_is_refused() {
        let harness = harness(Some(record(3)));
        harness.planner.plan(request("h-1"), now()).await.unwrap();
        let mut moved = request("h-1");
        moved.cutover_at = now() + Duration::hours(3);
        let error = harness.planner.plan(moved, now()).await.unwrap_err();
        assert_eq!(
            error.conflict_code(),
            Some(soland_storage::ConflictCode::FailedPrecondition)
        );
        assert_eq!(harness.signer.signed.lock().len(), 1);
    }

    #[tokio::test]
    async fn a_second_plan_cannot_start_under_a_live_one() {
        let harness = harness(Some(record(3)));
        harness.planner.plan(request("h-1"), now()).await.unwrap();
        let error = harness
            .planner
            .plan(request("h-2"), now())
            .await
            .unwrap_err();
        assert_eq!(
            error.conflict_code(),
            Some(soland_storage::ConflictCode::DuplicateConflict)
        );
    }

    #[tokio::test]
    async fn a_basis_that_moves_after_the_plan_rejects_the_next_revision() {
        let harness = harness(Some(record(3)));
        let planned = harness.planner.plan(request("h-1"), now()).await.unwrap();
        let digest = planned.plan.active_notice_digest.clone().unwrap();

        // A successor record was minted after the plan was opened. The notice
        // chain is bound to the old basis, so it must not continue.
        *harness.resolution.current.lock() = Some(record(4));

        let error = harness
            .planner
            .cancel("h-1", &digest, now())
            .await
            .unwrap_err();
        assert_eq!(
            error.conflict_code(),
            Some(soland_storage::ConflictCode::CasConflict)
        );
    }

    #[tokio::test]
    async fn cancel_chains_onto_the_active_revision_and_closes_the_plan() {
        let harness = harness(Some(record(3)));
        let planned = harness.planner.plan(request("h-1"), now()).await.unwrap();
        let active = planned.plan.active_notice_digest.clone().unwrap();

        let cancelled = harness
            .planner
            .cancel("h-1", &active, now() + Duration::minutes(1))
            .await
            .unwrap();

        assert_eq!(cancelled.notice.notice.notice_revision, 1);
        assert_eq!(
            cancelled.notice.notice.previous_notice_digest.as_ref(),
            Some(&active)
        );
        assert_eq!(
            cancelled.notice.notice.state,
            ServiceRouteHandoverState::Cancelled
        );
        assert!(cancelled.notice.notice.candidate_base_url.is_none());
        assert_eq!(
            cancelled.plan.state,
            ServiceRouteHandoverPlanState::Cancelled
        );
        // The slot is released once the plan is terminal.
        assert!(harness.planner.active_plan().await.unwrap().is_none());
    }

    #[tokio::test]
    async fn cancel_requires_the_exact_active_revision_digest() {
        let harness = harness(Some(record(3)));
        harness.planner.plan(request("h-1"), now()).await.unwrap();
        let error = harness
            .planner
            .cancel("h-1", &hash('f'), now())
            .await
            .unwrap_err();
        assert_eq!(
            error.conflict_code(),
            Some(soland_storage::ConflictCode::CasConflict)
        );
    }

    #[tokio::test]
    async fn a_window_that_already_started_is_not_a_preannouncement() {
        let harness = harness(Some(record(3)));
        let mut late = request("h-1");
        late.not_before = now() - Duration::minutes(1);
        let error = harness.planner.plan(late, now()).await.unwrap_err();
        assert!(matches!(error, ServiceError::SchemaViolation(_)));
        assert!(harness.signer.signed.lock().is_empty());
    }

    #[tokio::test]
    async fn a_non_https_candidate_is_refused_outside_development() {
        let harness = harness(Some(record(3)));
        let mut insecure = request("h-1");
        insecure.candidate_base_url = "http://new.example/".to_owned();
        let error = harness.planner.plan(insecure, now()).await.unwrap_err();
        assert!(matches!(error, ServiceError::SchemaViolation(_)));
        assert!(harness.signer.signed.lock().is_empty());
    }
}
