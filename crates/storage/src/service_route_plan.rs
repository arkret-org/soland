//! Owner-side durable state for a planned, same-core service route handover.
//!
//! This is the mirror image of [`super::service_route::ServiceRouteStore`]:
//! that store holds *remote* route material this deployment has verified and
//! must never roll back, while this one holds the material this deployment
//! **issues** about its own route — the plan, the exact signed
//! `ServiceRouteHandoverNotice` bytes, and the lifecycle position that gates a
//! safe cutover.
//!
//! The two are deliberately separate traits. A route fetcher legitimately
//! holds the receiving store, and it must not thereby gain the ability to sign
//! or advance an owner plan.

use arkret_models_identity::{ServiceRouteHandoverNotice, ServiceRouteHandoverState};
use arkret_wire::{DidCoreId, Hash};
use chrono::{DateTime, Utc};

use super::{PersistenceResult, async_trait};

/// Lifecycle position of an owner-side planned handover.
///
/// The transitions are deployment-local; the protocol constrains only the
/// *evidence* required to leave each of them. In particular `Preannounced` is
/// reachable only once every required audience target has returned a durable,
/// independently verified ACK (arkret-spec `sync/federation.md` §6.4), and
/// `Cutover` is reachable only once the candidate has served a continuous
/// formal successor record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServiceRouteHandoverPlanState {
    /// The plan row exists and is bound to a basis record; nothing is signed.
    Draft,
    /// Revision 0 is signed and audience publication is in flight.
    Publishing,
    /// Every required target holds the exact active notice revision.
    Preannounced,
    /// `not_before` has passed and the candidate answered a bounded readiness
    /// probe. This does not authorize business traffic on its own.
    Ready,
    /// The candidate published the formal `sequence + 1` successor record and
    /// it was accepted locally.
    Cutover,
    /// Traffic moved; the old entry is still served until `grace_until`.
    Grace,
    Completed,
    Cancelled,
    Failed,
    /// A route fork or conflicting ACK was observed. Needs an explicit
    /// operator resolution; it is not a terminal state and it keeps the
    /// service's single-active-plan slot occupied.
    Quarantined,
}

impl ServiceRouteHandoverPlanState {
    /// Every state, in declaration order.
    pub const ALL: [Self; 10] = [
        Self::Draft,
        Self::Publishing,
        Self::Preannounced,
        Self::Ready,
        Self::Cutover,
        Self::Grace,
        Self::Completed,
        Self::Cancelled,
        Self::Failed,
        Self::Quarantined,
    ];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Publishing => "publishing",
            Self::Preannounced => "preannounced",
            Self::Ready => "ready",
            Self::Cutover => "cutover",
            Self::Grace => "grace",
            Self::Completed => "completed",
            Self::Cancelled => "cancelled",
            Self::Failed => "failed",
            Self::Quarantined => "quarantined",
        }
    }

    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|state| state.as_str() == value)
    }

    /// A finished plan releases the service's single-active-plan slot.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Cancelled | Self::Failed)
    }
}

/// One owner-side planned handover.
///
/// `basis_record_sequence` / `basis_record_digest` pin the exact current
/// `ServiceResolutionRecord` the plan was built against. They are the notice's
/// `from_record_sequence` / `from_record_digest`, and every signed revision
/// must still match them: a basis that moved underneath the plan invalidates
/// the plan rather than silently re-targeting it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServiceRouteHandoverPlan {
    pub service_id: DidCoreId,
    pub service_kind: String,
    pub handover_id: String,
    pub basis_record_sequence: u64,
    pub basis_record_digest: Hash,
    pub candidate_base_url: String,
    pub candidate_record_url: String,
    pub not_before: DateTime<Utc>,
    pub cutover_at: DateTime<Utc>,
    pub grace_until: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub state: ServiceRouteHandoverPlanState,
    pub active_notice_revision: Option<u32>,
    pub active_notice_digest: Option<Hash>,
    pub last_error: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl ServiceRouteHandoverPlan {
    /// Whether two plan rows describe the same handover.
    ///
    /// Only the operator-declared, immutable half is compared. A stored plan
    /// that already advanced past `Draft` still *is* the same plan, so
    /// re-submitting the identical definition must read as a replay rather
    /// than a rejected transition.
    #[must_use]
    pub fn matches_definition(&self, other: &Self) -> bool {
        self.service_id == other.service_id
            && self.service_kind == other.service_kind
            && self.handover_id == other.handover_id
            && self.basis_record_sequence == other.basis_record_sequence
            && self.basis_record_digest == other.basis_record_digest
            && self.candidate_base_url == other.candidate_base_url
            && self.candidate_record_url == other.candidate_record_url
            && self.not_before == other.not_before
            && self.cutover_at == other.cutover_at
            && self.grace_until == other.grace_until
            && self.expires_at == other.expires_at
    }
}

/// One exact signed notice revision, stored verbatim including its proof.
///
/// The row is append-only: a revision is written once and never rewritten.
/// Re-publishing the identical bytes is a replay; the same revision with a
/// different digest is a conflict with zero overwrite.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServiceRouteHandoverNoticeRecord {
    pub service_id: DidCoreId,
    pub service_kind: String,
    pub handover_id: String,
    pub notice_revision: u32,
    pub notice_digest: Hash,
    pub previous_notice_digest: Option<Hash>,
    pub state: ServiceRouteHandoverState,
    pub notice: ServiceRouteHandoverNotice,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

impl ServiceRouteHandoverNoticeRecord {
    /// Reject a row whose columns disagree with the signed bytes they index.
    ///
    /// The digest itself is supplied by the caller because it must be computed
    /// over the exact canonical bytes that were signed; this check makes sure
    /// the projected columns cannot drift away from them.
    pub fn validate(&self) -> PersistenceResult<()> {
        let core = &self.notice.notice;
        if self.service_id != core.service_id
            || self.service_kind != core.service_kind
            || self.handover_id != core.handover_id
            || self.notice_revision != core.notice_revision
            || self.previous_notice_digest != core.previous_notice_digest
            || self.state != core.state
            || self.issued_at != core.issued_at
            || self.expires_at != core.expires_at
        {
            return Err(super::PersistenceError::SchemaViolation(
                "service route handover notice row disagrees with its signed core".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Atomic commit of one signed notice revision plus the plan head it advances.
///
/// Both the basis and the predecessor revision are expected values, not
/// hints: the store applies the write only if they still hold.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServiceRouteHandoverNoticeCommit {
    pub notice: ServiceRouteHandoverNoticeRecord,
    pub expected_basis_digest: Hash,
    pub expected_active_notice_digest: Option<Hash>,
    pub next_state: ServiceRouteHandoverPlanState,
    pub updated_at: DateTime<Utc>,
}

/// Required-notice state for one accepted Realm relationship.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServiceRouteHandoverAudienceStatus {
    Pending,
    Removed,
}

impl ServiceRouteHandoverAudienceStatus {
    pub const ALL: [Self; 2] = [Self::Pending, Self::Removed];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Removed => "removed",
        }
    }

    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|status| status.as_str() == value)
    }
}

/// Durable inverse-index row derived only from accepted Realm/member state.
///
/// The key deliberately includes `realm_id`: the same remote service may be
/// able to see a notice through two Realms, but one Realm's ACK cannot satisfy
/// the other Realm's authorization path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServiceRouteHandoverAudienceEntry {
    pub service_id: DidCoreId,
    pub service_kind: String,
    pub handover_id: String,
    pub realm_id: String,
    pub peer_service_id: DidCoreId,
    pub notice_digest: Hash,
    pub accepted_frontier: Vec<String>,
    pub required: bool,
    pub status: ServiceRouteHandoverAudienceStatus,
    pub removed_reason: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// One currently accepted Realm/peer relationship before durable reconcile.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServiceRouteHandoverAudienceTarget {
    pub realm_id: String,
    pub peer_service_id: DidCoreId,
    pub accepted_frontier: Vec<String>,
}

/// Outcome of a conditional owner-plan write.
///
/// The conflict variants are kept apart because they demand different
/// operator actions: a moved basis means the plan must be rebuilt against the
/// new current record, while a revision conflict means someone else already
/// advanced this handover.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ServiceRouteHandoverPlanWrite {
    Applied,
    /// The identical artifact was already stored.
    Replay,
    /// Another unfinished plan already occupies this service's slot.
    PlanAlreadyActive {
        handover_id: String,
    },
    /// The durable current record moved after the caller read it.
    BasisChanged {
        accepted_digest: Option<Hash>,
    },
    /// The same revision is already stored with different bytes, or the
    /// predecessor digest does not chain.
    RevisionConflict {
        accepted_digest: Option<Hash>,
    },
    /// The plan does not exist, is terminal, or the transition is not allowed.
    Rejected,
}

/// Durable owner-side handover plan state.
///
/// Every mutating method is conditional. Nothing here signs, and nothing here
/// authorizes a cutover: the store only records what was decided and refuses
/// writes whose preconditions no longer hold.
#[async_trait]
pub trait ServiceRouteHandoverPlanStore: Send + Sync {
    /// One plan by its exact handover id.
    async fn plan(
        &self,
        service_id: &DidCoreId,
        service_kind: &str,
        handover_id: &str,
    ) -> PersistenceResult<Option<ServiceRouteHandoverPlan>>;

    /// The single unfinished plan for this service, if one exists.
    async fn active_plan(
        &self,
        service_id: &DidCoreId,
        service_kind: &str,
    ) -> PersistenceResult<Option<ServiceRouteHandoverPlan>>;

    /// Plans newest first, bounded by `limit`.
    async fn list_plans(
        &self,
        service_id: &DidCoreId,
        service_kind: &str,
        limit: usize,
    ) -> PersistenceResult<Vec<ServiceRouteHandoverPlan>>;

    /// Signed notice revisions for one handover, oldest revision first.
    async fn notices(
        &self,
        service_id: &DidCoreId,
        service_kind: &str,
        handover_id: &str,
        limit: usize,
    ) -> PersistenceResult<Vec<ServiceRouteHandoverNoticeRecord>>;

    /// Current and removed audience rows for one plan, sorted by Realm/peer.
    async fn audience(
        &self,
        service_id: &DidCoreId,
        service_kind: &str,
        handover_id: &str,
    ) -> PersistenceResult<Vec<ServiceRouteHandoverAudienceEntry>>;

    /// Atomically reconcile accepted projection relationships into the
    /// durable audience snapshot for the exact active notice revision.
    async fn reconcile_audience(
        &self,
        service_id: &DidCoreId,
        service_kind: &str,
        handover_id: &str,
        notice_digest: &Hash,
        targets: Vec<ServiceRouteHandoverAudienceTarget>,
        updated_at: DateTime<Utc>,
    ) -> PersistenceResult<ServiceRouteHandoverPlanWrite>;

    /// Open a `Draft` plan. Fails closed when the service already has an
    /// unfinished plan, so a second migration cannot be started underneath a
    /// live one.
    async fn open_plan(
        &self,
        plan: ServiceRouteHandoverPlan,
    ) -> PersistenceResult<ServiceRouteHandoverPlanWrite>;

    /// Store one signed revision and advance the plan head, conditional on the
    /// basis and predecessor revision still holding.
    async fn commit_notice(
        &self,
        commit: ServiceRouteHandoverNoticeCommit,
    ) -> PersistenceResult<ServiceRouteHandoverPlanWrite>;

    /// Record a terminal or diagnostic transition that carries no new notice
    /// (failure, quarantine, completion). `expected_state` guards the write.
    async fn advance_plan_state(
        &self,
        service_id: &DidCoreId,
        service_kind: &str,
        handover_id: &str,
        expected_state: ServiceRouteHandoverPlanState,
        next_state: ServiceRouteHandoverPlanState,
        last_error: Option<String>,
        updated_at: DateTime<Utc>,
    ) -> PersistenceResult<ServiceRouteHandoverPlanWrite>;
}
