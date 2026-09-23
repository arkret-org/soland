//! Durable authority-commit persistence boundary.
//!
//! Producer Events are queued without ordering metadata. Only the current
//! governance Station may atomically append a [`RealmCommit`], mark the Event
//! committed, and enqueue any MLS Welcome deliveries. Each Realm, Circle and
//! Sidecar stream advances independently.

use arkret_wire::{
    CommitStreamHead, CommitStreamRef, Event, MlsWelcomeDelivery, RealmAuthorityHandoff,
    RealmCommit, RealmStateSnapshot,
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};

use crate::PersistenceResult;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QueuedEventStatus {
    Queued,
    Committed,
    Rejected,
}

#[derive(Clone, Debug, PartialEq)]
pub struct QueuedEventRecord {
    pub event: Event,
    pub status: QueuedEventStatus,
    pub queued_at: DateTime<Utc>,
    pub committed: Option<RealmCommit>,
    pub rejection_reason: Option<String>,
}

/// Exact durable pair used to materialize a caller-scoped committed-event
/// read view. This is an internal persistence carrier, not a third protocol
/// object and has no identity or signature of its own.
#[derive(Clone, Debug, PartialEq)]
pub struct CommittedEventRecord {
    pub commit: RealmCommit,
    pub event: Event,
}

/// Durable MIMI room binding winner at one accepted RealmCommit revision.
#[derive(Clone, Debug)]
pub struct MimiRoomBindingCurrentRecord {
    pub current: arkret_models_collaboration::events_payloads::mimi::MimiRoomBindingCurrentResult,
    pub source_event_id: arkret_wire::EventId,
    pub realm_id: arkret_wire::RealmId,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CurrentRealmAuthority {
    pub realm_id: arkret_wire::RealmId,
    pub generation: u64,
    pub service_id: arkret_wire::DidCoreId,
    pub authority_ref: arkret_wire::RealmCommitAuthorityRef,
    pub last_handoff_ref: Option<arkret_wire::RealmAuthorityHandoffId>,
}

/// One durable-cut maximal Realm snapshot projection before identity and
/// Station signature are attached by the serving layer.
#[derive(Clone, Debug, PartialEq)]
pub struct RealmStateSnapshotMaterial {
    pub realm_id: arkret_wire::RealmId,
    pub governance_generation: u64,
    pub visible_stream_heads: Vec<arkret_wire::CommitStreamHead>,
    pub current_state_entries: Vec<arkret_wire::TypedCurrentResult>,
    pub retention_and_history_floor: arkret_wire::RetentionAndHistoryFloor,
}

/// One transaction installed after all Event, authority and MLS checks pass.
#[derive(Clone, Debug, PartialEq)]
pub struct AuthorityCommitTransaction {
    pub expected_authority: CurrentRealmAuthority,
    pub event: Event,
    pub commit: RealmCommit,
    pub mls_state: Option<MlsStateInstallation>,
    pub welcomes: Vec<MlsWelcomeDelivery>,
    /// Service-configured maximum outstanding deliveries for each exact
    /// recipient endpoint. A transaction carrying Welcome must provide a
    /// positive bound; zero is permitted only when no Welcome is present.
    pub recipient_queue_capacity: usize,
}

/// Current producer authorization pinned by the self submit preflight and
/// rechecked inside the same transaction that commits the Event. This is an
/// internal persistence guard, never a caller-supplied protocol claim.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SelfProducerCommitGuard {
    HumanDevice(crate::DeviceRevocationGateSelector),
    Agent {
        pcr_realm_id: arkret_wire::RealmId,
        agent_id: arkret_wire::DidCoreId,
        authorization_ref: arkret_wire::CommittedEventRef,
        verification_method: arkret_wire::DidUrl,
    },
}

/// A complete ordinary Realm bootstrap, including the exact HTTP request
/// bytes used for durable idempotency comparison. Every proposed Commit is
/// prepared and verified by the service before this storage boundary.
#[derive(Clone, Debug, PartialEq)]
pub struct OrdinaryRealmBootstrapCommitUnit {
    pub submission:
        arkret_models_collaboration::authority_commit::OrdinaryRealmBootstrapUnitSubmission,
    pub exact_request_body: Vec<u8>,
    pub transactions: Vec<AuthorityCommitTransaction>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum OrdinaryRealmBootstrapCommitOutcome {
    Committed(Vec<RealmCommit>),
    Duplicate(Vec<RealmCommit>),
}

/// Complete PCR genesis admission prepared by the governance Station after
/// authenticating the Account Authority relay and both producer proofs.
#[derive(Clone, Debug, PartialEq)]
pub struct PcrGenesisCommitUnit {
    pub submission: arkret_models_collaboration::principal_operations::PcrGenesisAdmissionInput,
    pub exact_request_body: Vec<u8>,
    pub transactions: [AuthorityCommitTransaction; 2],
}

#[derive(Clone, Debug, PartialEq)]
pub enum PcrGenesisCommitOutcome {
    Committed(arkret_models_collaboration::principal_operations::PcrGenesisAdmissionResult),
    Duplicate(arkret_models_collaboration::principal_operations::PcrGenesisAdmissionResult),
}

impl PcrGenesisCommitUnit {
    pub fn validate(&self) -> arkret_wire::Result<()> {
        self.submission.validate()?;
        if self.exact_request_body.is_empty()
            || serde_json::from_slice::<
                arkret_models_collaboration::principal_operations::PcrGenesisAdmissionInput,
            >(&self.exact_request_body)
            .ok()
            .as_ref()
                != Some(&self.submission)
        {
            return Err(arkret_wire::WireError::Protocol(
                "PCR genesis exact request bytes differ from the admitted input".to_owned(),
            ));
        }
        let first = &self.transactions[0];
        let second = &self.transactions[1];
        let authority = &first.expected_authority;
        let expected_stream = CommitStreamRef::Realm {
            realm_id: self.submission.pcr_realm_id.clone(),
        };
        if authority.realm_id != self.submission.pcr_realm_id
            || authority.service_id != self.submission.account_authority_id
            || authority.generation != 0
            || authority.last_handoff_ref.is_some()
            || authority.authority_ref
                != arkret_wire::RealmCommitAuthorityRef::GenesisOrChangeEvent(
                    self.submission.genesis_unit.create().event_id.clone(),
                )
            || second.expected_authority != *authority
            || first.event != *self.submission.genesis_unit.create()
            || second.event != *self.submission.genesis_unit.founding_authorize()
            || first.commit.stream_ref != expected_stream
            || second.commit.stream_ref != expected_stream
            || first.commit.stream_position != 0
            || first.commit.previous_commit_ref.is_some()
            || second.commit.stream_position != 1
            || second.commit.previous_commit_ref.as_ref() != Some(&first.commit.commit_id)
            || self.transactions.iter().any(|transaction| {
                transaction.mls_state.is_some() || !transaction.welcomes.is_empty()
            })
        {
            return Err(arkret_wire::WireError::Protocol(
                "PCR genesis transaction does not bind its ordered Event and Commit pair"
                    .to_owned(),
            ));
        }
        first.validate()?;
        second.validate()?;
        Ok(())
    }
}

impl OrdinaryRealmBootstrapCommitUnit {
    pub fn validate(&self) -> arkret_wire::Result<()> {
        self.submission.validate()?;
        if self.exact_request_body.is_empty()
            || self.transactions.len() != self.submission.events.len()
        {
            return Err(arkret_wire::WireError::Protocol(
                "ordinary Realm bootstrap body/transaction cardinality is invalid".to_owned(),
            ));
        }
        match serde_json::from_slice::<
            arkret_models_collaboration::authority_commit::SelfAuthoritySubmitRequest,
        >(&self.exact_request_body)
        {
            Ok(arkret_models_collaboration::authority_commit::SelfAuthoritySubmitRequest::OrdinaryRealmBootstrap(parsed))
                if parsed == self.submission => {}
            _ => return Err(arkret_wire::WireError::Protocol(
                "ordinary Realm bootstrap exact body does not match the submitted unit".to_owned(),
            )),
        }
        let first = &self.transactions[0];
        for (submitted, transaction) in self.submission.events.iter().zip(&self.transactions) {
            transaction.validate()?;
            if submitted.event != transaction.event
                || transaction.expected_authority != first.expected_authority
                || transaction.mls_state.is_some()
                || !transaction.welcomes.is_empty()
            {
                return Err(arkret_wire::WireError::Protocol(
                    "ordinary Realm bootstrap transaction diverges from its submitted Event or authority"
                        .to_owned(),
                ));
            }
        }
        arkret_models_collaboration::authority_commit::OrdinaryRealmBootstrapAcceptanceOutcome {
            unit_kind: self.submission.unit_kind,
            status:
                arkret_models_collaboration::authority_commit::AggregateAcceptanceStatus::Committed,
            commits: self
                .transactions
                .iter()
                .map(|transaction| transaction.commit.clone())
                .collect(),
        }
        .validate()?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MlsStateInstallation {
    pub group_id: String,
    pub effective_scope: arkret_wire::ScopeRef,
    pub epoch: u64,
    pub state_bytes: Vec<u8>,
}

impl AuthorityCommitTransaction {
    pub fn validate(&self) -> arkret_wire::Result<()> {
        if !self.welcomes.is_empty() && self.recipient_queue_capacity == 0 {
            return Err(arkret_wire::WireError::Protocol(
                "MLS Welcome transaction omitted its recipient queue capacity".to_owned(),
            ));
        }
        self.event.validate_for_submit_structural()?;
        self.commit.validate_shape()?;
        let expected_stream =
            CommitStreamRef::from_scope(&self.event.scope_ref, Some(self.event.realm_id.clone()))?;
        if self.expected_authority.realm_id != self.event.realm_id
            || self.commit.realm_id != self.event.realm_id
            || self.commit.event_ref != self.event.event_id
            || self.commit.stream_ref != expected_stream
            || self.commit.governance_generation != self.expected_authority.generation
            || self.commit.authority_ref != self.expected_authority.authority_ref
        {
            return Err(arkret_wire::WireError::Protocol(
                "authority commit transaction bindings disagree".to_owned(),
            ));
        }
        match (&self.mls_state, &self.event.kind) {
            (Some(state), &arkret_wire::EventKind::MlsCommit) => {
                let payload_value = serde_json::to_value(&self.event.payload).map_err(|error| {
                    arkret_wire::WireError::Protocol(format!(
                        "MLS Commit Event payload cannot be encoded: {error}"
                    ))
                })?;
                let payload: arkret_models_crypto::MlsCommitPayload =
                    serde_json::from_value(payload_value).map_err(|error| {
                        arkret_wire::WireError::Protocol(format!(
                            "MLS Commit Event has no valid governance binding: {error}"
                        ))
                    })?;
                validate_mls_installation(&payload, &self.event.scope_ref, state)?;
            }
            (None, kind) if *kind != arkret_wire::EventKind::MlsCommit => {}
            _ => {
                return Err(arkret_wire::WireError::Protocol(
                    "MLS Commit acceptance requires exactly one installed group state".to_owned(),
                ));
            }
        }
        if !self.welcomes.is_empty() && self.event.kind != arkret_wire::EventKind::MlsCommit {
            return Err(arkret_wire::WireError::Protocol(
                "MLS Welcome delivery requires an MLS Commit Event".to_owned(),
            ));
        }
        for welcome in &self.welcomes {
            welcome.validate_shape()?;
            if welcome.realm_id != self.event.realm_id
                || welcome.effective_scope != self.event.scope_ref
                || welcome.commit_event_ref != self.event.event_id
            {
                return Err(arkret_wire::WireError::Protocol(
                    "MLS Welcome does not bind the committed Event and stream".to_owned(),
                ));
            }
        }
        Ok(())
    }
}

fn validate_mls_installation(
    payload: &arkret_models_crypto::MlsCommitPayload,
    event_scope: &arkret_wire::ScopeRef,
    state: &MlsStateInstallation,
) -> arkret_wire::Result<()> {
    let binding = payload.governance_binding();
    let expected_group_id = binding.mls_group_id()?;
    if binding.effective_scope() != event_scope
        || state.effective_scope != *event_scope
        || state.group_id != expected_group_id.as_str()
        || state.epoch != payload.next_epoch()
        || state.state_bytes.is_empty()
        || payload.covers_key_access_revision() != binding.key_access_revision()
    {
        return Err(arkret_wire::WireError::Protocol(
            "installed MLS state differs from the signed Commit governance binding".to_owned(),
        ));
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuthorityCommitWriteOutcome {
    Committed,
    Duplicate,
    StaleAuthority(CurrentRealmAuthority),
}

#[async_trait]
pub trait AuthorityCommitStore: Send + Sync {
    async fn install_genesis_authority(
        &self,
        authority: &CurrentRealmAuthority,
    ) -> PersistenceResult<()>;

    async fn current_authority(
        &self,
        realm_id: &arkret_wire::RealmId,
    ) -> PersistenceResult<Option<CurrentRealmAuthority>>;

    /// Read one accepted current membership only when this service is the
    /// Realm's current governing Station. Missing, remote, or inconsistent
    /// authority/member rows fail closed for optional authoring preparation.
    async fn local_current_member_joined(
        &self,
        realm_id: &arkret_wire::RealmId,
        member: &arkret_wire::ActorId,
        service_id: &arkret_wire::DidCoreId,
    ) -> PersistenceResult<bool>;

    async fn queue_event(&self, event: &Event, queued_at: DateTime<Utc>) -> PersistenceResult<()>;

    async fn queued_event(
        &self,
        event_id: &arkret_wire::EventId,
    ) -> PersistenceResult<Option<QueuedEventRecord>>;

    /// Atomically queues a producer Event and installs its authority Commit.
    ///
    /// Unlike calling [`Self::queue_event`] followed by
    /// [`Self::commit_transaction`], this boundary guarantees that any
    /// authority, predecessor, or persistence failure leaves no queued Event
    /// behind. Product-private Account Authority admission uses this method so
    /// it cannot expose a half-admitted Event after a failed request.
    async fn admit_event_transaction(
        &self,
        transaction: &AuthorityCommitTransaction,
        queued_at: DateTime<Utc>,
    ) -> PersistenceResult<AuthorityCommitWriteOutcome>;

    /// Commit a self Event only while its producer's current authorization is
    /// still the same. Implementations must perform this guard and the
    /// authority/stream CAS within one database transaction.
    async fn admit_self_event_transaction(
        &self,
        transaction: &AuthorityCommitTransaction,
        guard: &SelfProducerCommitGuard,
        queued_at: DateTime<Utc>,
    ) -> PersistenceResult<AuthorityCommitWriteOutcome>;

    /// Install the entire registered ordinary Realm bootstrap in one DB
    /// transaction, including genesis authority, every Event/Commit and all
    /// current projections. Failed units leave no queued or committed Event.
    async fn admit_ordinary_realm_bootstrap_unit(
        &self,
        unit: &OrdinaryRealmBootstrapCommitUnit,
        queued_at: DateTime<Utc>,
    ) -> PersistenceResult<OrdinaryRealmBootstrapCommitOutcome>;

    /// Install the complete PCR genesis, founding device current, and exact
    /// idempotency receipt in one durable transaction.
    async fn admit_pcr_genesis_unit(
        &self,
        unit: &PcrGenesisCommitUnit,
        queued_at: DateTime<Utc>,
    ) -> PersistenceResult<PcrGenesisCommitOutcome>;

    /// Read the first durable PCR genesis receipt before freshness checks on an
    /// exact retry. Reusing either the Realm or idempotency key with different
    /// request bytes is a conflict, never a duplicate acceptance.
    async fn pcr_genesis_replay(
        &self,
        submission: &arkret_models_collaboration::principal_operations::PcrGenesisAdmissionInput,
        exact_request_body: &[u8],
    ) -> PersistenceResult<
        Option<arkret_models_collaboration::principal_operations::PcrGenesisAdmissionResult>,
    >;

    /// Atomically checks current authority, appends the per-stream commit,
    /// changes the Event from queued to committed, and enqueues every Welcome.
    async fn commit_transaction(
        &self,
        transaction: &AuthorityCommitTransaction,
    ) -> PersistenceResult<AuthorityCommitWriteOutcome>;

    async fn stream_head(
        &self,
        stream_ref: &CommitStreamRef,
    ) -> PersistenceResult<Option<CommitStreamHead>>;

    /// Resolve the unique successful RealmCommit for one Event id.
    ///
    /// A missing row returns `None`; storage uniqueness guarantees that this
    /// method never chooses between two successful commits for the same Event.
    async fn committed_event(
        &self,
        event_id: &arkret_wire::EventId,
    ) -> PersistenceResult<Option<CommittedEventRecord>>;

    async fn committed_event_by_commit_id(
        &self,
        commit_id: &arkret_wire::RealmCommitId,
    ) -> PersistenceResult<Option<CommittedEventRecord>>;

    async fn current_mimi_room_binding(
        &self,
        room_uri: &arkret_wire::MimiRoomUri,
    ) -> PersistenceResult<Option<MimiRoomBindingCurrentRecord>>;

    /// Read one accepted Agent typed current row at its durable revision.
    /// Only the closed AgentKey and AgentStatus selectors are admitted.
    async fn current_agent_result(
        &self,
        realm_id: &arkret_wire::RealmId,
        selector: &arkret_wire::CurrentSelector,
    ) -> PersistenceResult<Option<arkret_wire::TypedCurrentResult>>;

    /// Current heads for every independent Realm, Circle, and Sidecar stream
    /// belonging to one Realm, sorted by `stream_ref`.
    async fn realm_stream_heads(
        &self,
        realm_id: &arkret_wire::RealmId,
    ) -> PersistenceResult<Vec<CommitStreamHead>>;

    /// Read the maximal-disclosure snapshot material from one consistent
    /// durable cut. Implementations must sort every repeated field.
    async fn realm_state_snapshot_material(
        &self,
        realm_id: &arkret_wire::RealmId,
    ) -> PersistenceResult<Option<RealmStateSnapshotMaterial>>;

    /// Keyset page over one independent commit stream.
    ///
    /// The only paging key is `realm_commits.stream_position` inside the
    /// single `CommitStreamRef` named by the request: rows start at genesis
    /// position 0 when `after_position` is `None` and otherwise at
    /// `after_position + 1`, run consecutively, and stop after `limit` rows.
    /// No opaque page token, no reverse direction, and no separate
    /// `has_more`: `StreamScanOutcome::truncated` carries that alone.
    async fn scan_stream(
        &self,
        request: &arkret_wire::StreamScanRequest,
    ) -> PersistenceResult<arkret_wire::StreamScanOutcome>;

    async fn install_handoff(
        &self,
        handoff: &RealmAuthorityHandoff,
        final_stream_heads: &[CommitStreamHead],
        snapshot: &RealmStateSnapshot,
    ) -> PersistenceResult<()>;

    /// Returns the consecutive, durable handoff chain used to verify the
    /// current Station from the Realm's genesis authority.
    async fn authority_handoffs(
        &self,
        realm_id: &arkret_wire::RealmId,
    ) -> PersistenceResult<Vec<RealmAuthorityHandoff>>;

    async fn latest_snapshot(
        &self,
        realm_id: &arkret_wire::RealmId,
    ) -> PersistenceResult<Option<RealmStateSnapshot>>;
}

#[cfg(test)]
mod mls_installation_tests {
    use super::{MlsStateInstallation, validate_mls_installation};
    use arkret_models_crypto::{MlsCommitEnvelope, MlsCommitPayload, MlsGovernanceBindingPayload};
    use arkret_wire::{EventId, Hash, RealmId, ScopeRef};

    #[test]
    fn installed_state_must_match_signed_mls_binding() {
        let realm_id =
            RealmId::new("ak:realm:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-").unwrap();
        let base =
            EventId::from_event_digest(&Hash::new(arkret_canonical::sha256_digest([1])).unwrap())
                .unwrap();
        let binding =
            MlsGovernanceBindingPayload::realm(realm_id.clone(), Some(base.clone()), 0, 1, 7)
                .unwrap();
        let commit_bytes = b"canonical-commit";
        let envelope = MlsCommitEnvelope {
            group_id: binding.mls_group_id().unwrap(),
            epoch: 1,
            commit: arkret_wire::base64url::base64url_encode(commit_bytes),
            commit_digest: Hash::new(arkret_canonical::sha256_digest(commit_bytes)).unwrap(),
            ratchet_tree: None,
        };
        let payload = MlsCommitPayload::new(base, 7, &envelope, binding).unwrap();
        let scope = ScopeRef::Realm { realm_id };
        let installed = MlsStateInstallation {
            group_id: envelope.group_id.as_str().to_owned(),
            effective_scope: scope.clone(),
            epoch: 1,
            state_bytes: vec![1],
        };
        assert!(validate_mls_installation(&payload, &scope, &installed).is_ok());

        let mut wrong_group = installed.clone();
        wrong_group.group_id = "other-group".to_owned();
        assert!(validate_mls_installation(&payload, &scope, &wrong_group).is_err());

        let mut wrong_epoch = installed.clone();
        wrong_epoch.epoch = 2;
        assert!(validate_mls_installation(&payload, &scope, &wrong_epoch).is_err());

        let mut missing_state = installed;
        missing_state.state_bytes.clear();
        assert!(validate_mls_installation(&payload, &scope, &missing_state).is_err());
    }
}
