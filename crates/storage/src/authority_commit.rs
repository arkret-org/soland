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

/// Result of a caller-scoped stream scan at one governing read cut. The
/// caller is an authenticated Account (`self`) or peer Station (`peer`).
#[derive(Clone, Debug, PartialEq)]
pub enum AccountStreamScan {
    /// A page inside the caller's proved readable interval.
    Page(arkret_wire::StreamScanOutcome),
    /// The Realm is not governed here, or the caller is not (and hosts no)
    /// currently joined member: it has no readable interval on this stream.
    NotAuthorized,
    /// The caller may be authorized, but this Station cannot prove its exact
    /// readable interval and disclosure at this cut.
    Unproved(&'static str),
}

/// Result of `ak.self.realm.read.streams.v1` for one authenticated Account
/// at one governing read cut.
#[derive(Clone, Debug, PartialEq)]
pub enum AccountRealmStreamList {
    /// Every row the caller may know exists, in JCS(stream_ref) order.
    Listed(Vec<arkret_wire::RealmStreamRow>),
    /// Unknown Realm or a caller that is not a currently joined member: the
    /// universal non-enumerating `not_found`.
    NotVisible,
    /// The caller is a member, but the stream set it may know about or a
    /// row's readable floor cannot be proved at this cut.
    Unproved(&'static str),
}

/// Result of an exact, non-enumerating self current read at one governing
/// read cut (`ak.self.current_results.read.exact.v1`,
/// `ak.self.strand.watch.read.current.v1`).
#[derive(Clone, Debug)]
pub enum SelfExactCurrentRead<T> {
    /// A selector-identical answer bound to the cut's generation and head.
    Answer(T),
    /// Unknown, foreign, invisible or unauthorized selector.
    NotFound,
    /// The current governing basis for the selector cannot be confirmed at
    /// this cut; absence is never inferred from it.
    Unresolved(&'static str),
}

/// Anchor state behind `ak.self.media_service_binding.read.resolve.v1` for one
/// authenticated Account at one governing read cut.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MediaServiceAnchorRead {
    /// Invisible Realm, non-member caller, or no accepted media service
    /// assignment in the Realm.
    NotFound,
    /// A media service assignment was accepted in the visible Realm.
    Anchored,
}

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

/// Signs the exact material proved at an issuance cut. It runs inside that
/// cut, so it must be synchronous and must not read other state.
pub type RealmStateSnapshotSigner<'a> = &'a (
        dyn Fn(&RealmStateSnapshotMaterial) -> PersistenceResult<RealmStateSnapshot> + Send + Sync
    );

/// Freeze of one Account's Realm-stream delivery window
/// (`client-sync.md` 5.2, decision 0101).
///
/// `window_cursor` is the frozen window identity the frame repeats as
/// `window_snapshot_cursor`; `expires_at_ms` is the window's consumable
/// deadline, which also bounds the Account cursor that carries it.
#[derive(Clone, Debug)]
pub struct AccountRealmWindowRequest {
    pub realm_id: arkret_wire::RealmId,
    pub account: arkret_wire::AccountId,
    pub issuer: arkret_wire::DidCoreId,
    pub window_limit: u32,
    pub window_cursor: String,
    pub expires_at_ms: i64,
    pub now_ms: i64,
    /// Canonical bytes the delivered rows may occupy. The window is atomic:
    /// rows that do not fit fail the freeze instead of being truncated.
    pub byte_budget: usize,
    /// The Realm-stream head the Account cursor last delivered. When it is
    /// still an accepted ancestor of the head within `window_limit`, the
    /// window is the live delta after it instead of the last `window_limit`
    /// Commits.
    pub delivered_head: Option<arkret_wire::CommitStreamHead>,
}

/// One frozen, fully delivered stream window and its committed rows.
///
/// A non-preview `window_start_basis` names an exact snapshot already
/// issued to the Account, and the freeze reserved it for the window's
/// consumable period. Without such a reservation a limited window is
/// `preview_only` and carries no basis.
#[derive(Clone, Debug)]
pub struct AccountRealmWindow {
    pub governance_generation: u64,
    pub window: arkret_models_collaboration::sync_frames::account_sync::RealmStreamWindow,
    pub committed_events: Vec<arkret_wire::CommittedEventView>,
    /// Typed current results of the same proved cut, i.e. at the window
    /// head; the Account current carrier of the window's Realm detail.
    pub current_state_entries: Vec<arkret_wire::TypedCurrentResult>,
}

/// An issued snapshot without any live window reservation stays archived at
/// least this long after issuance, the same span as an Account sync
/// snapshot reservation (0441), before retention may reclaim it.
pub const UNRESERVED_ISSUED_SNAPSHOT_RETENTION_MS: i64 = 3_660_000;

/// Longest consumable period a window reservation may claim: the Account
/// stream cursor that carries the window never lives longer.
pub const MAX_ACCOUNT_WINDOW_RESERVATION_MS: i64 = 3_600_000;

/// Issued snapshots of one Account and Realm that no live window reservation
/// names are kept to the newest this many (0441). Issuing a further one
/// reclaims the oldest; a head whose issuance was reclaimed backs no later
/// window basis, so that window is `preview_only`.
pub const MAX_UNRESERVED_ISSUED_SNAPSHOTS_PER_ACCOUNT_REALM: i64 = 8;

/// Live window reservations one Account may hold on one stream (0441). At
/// the cap a newly frozen limited window names no basis and is
/// `preview_only`; a reservation is never evicted before its deadline.
/// Together with the unreserved cap this bounds the signed objects kept for
/// one Account and Realm to 40 within the reservation lifetime.
pub const MAX_LIVE_WINDOW_RESERVATIONS_PER_ACCOUNT_STREAM: i64 = 32;

/// Decision 0081 / 0068: the complete RFC 8785 canonical signed body is one
/// inline object of at most 8 MiB. There is no page, chunk, or truncation.
pub const MAX_INLINE_REALM_STATE_SNAPSHOT_BYTES: usize = 8 * 1024 * 1024;

/// Reject the whole signed object when its canonical body exceeds the limit.
pub fn enforce_inline_realm_state_snapshot_capacity(
    snapshot: &RealmStateSnapshot,
) -> PersistenceResult<()> {
    let bytes = arkret_canonical::canonical_json_bytes(snapshot)
        .map_err(crate::PersistenceError::database)?;
    if bytes.len() > MAX_INLINE_REALM_STATE_SNAPSHOT_BYTES {
        return Err(crate::PersistenceError::Conflict(
            "snapshot_capacity_exceeded: complete signed Realm snapshot exceeds 8 MiB".to_owned(),
        ));
    }
    Ok(())
}

/// The signer may attach only identity, time, and signature; every disclosed
/// member must be exactly the proved material.
pub fn signed_snapshot_matches_material(
    snapshot: &RealmStateSnapshot,
    material: &RealmStateSnapshotMaterial,
) -> bool {
    snapshot.realm_id == material.realm_id
        && snapshot.governance_generation == material.governance_generation
        && snapshot.visible_stream_heads == material.visible_stream_heads
        && snapshot.current_state_entries == material.current_state_entries
        && snapshot.retention_and_history_floor == material.retention_and_history_floor
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

/// The caller-authored four-Event Direct Conversation founding unit with the
/// four consecutive Commits the founder's current Station prepared for it
/// (contact-and-direct-conversation.md sections 5.5 and 6.1). Every
/// coordinate is recomputed from the Event bytes by [`Self::facts`]; nothing
/// the request asserts beside the Events is trusted.
#[derive(Clone, Debug, PartialEq)]
pub struct DirectConversationFoundingCommitUnit {
    pub submission:
        arkret_models_collaboration::authority_commit::DirectConversationFoundingUnitSubmission,
    pub transactions: [AuthorityCommitTransaction; 4],
}

/// Coordinates derived from the exact unit bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirectConversationFoundingFacts {
    pub founder_id: arkret_wire::ActorId,
    pub peer_id: arkret_wire::ActorId,
    pub trust_domain_id: arkret_wire::TrustDomainId,
    /// The genesis `governance_station_id`, which must be the founder's
    /// current Station admitting the unit.
    pub governance_station_id: arkret_wire::DidCoreId,
    pub pair_key: arkret_wire::Hash,
    pub realm_id: arkret_wire::RealmId,
    pub main_strand_id: arkret_wire::StrandId,
    pub founding_unit_digest: arkret_wire::Hash,
    /// The branch-selecting critical ref of the genesis Event.
    pub authority_ref: DirectConversationFoundingAuthorityRef,
}

/// The exact-XOR critical ref role that selects the genesis admission variant
/// (contact-and-direct-conversation.md section 5.4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DirectConversationFoundingAuthorityRef {
    /// `direct_conversation_contact_round`: the pair's current Contact round.
    ContactRound(arkret_wire::Hash),
    /// `direct_conversation_agent_provision`: the accepted provision Event.
    AgentProvision(arkret_wire::EventId),
}

/// The Direct Conversation admission table's verdict at one cut.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DirectConversationAdmissionCut {
    /// The Event's Realm is not a Direct Conversation.
    NotDirectConversation,
    /// No stage of the table refuses the Event.
    Passed,
    /// The first matching stage in registered precedence.
    Refused(crate::ConflictCode),
}

#[derive(Clone, Debug, PartialEq)]
pub enum DirectConversationFoundingCommitOutcome {
    Committed([RealmCommit; 4]),
    Duplicate([RealmCommit; 4]),
}

fn founding_unit_invalid(detail: impl std::fmt::Display) -> arkret_wire::WireError {
    arkret_wire::WireError::Protocol(detail.to_string())
}

impl DirectConversationFoundingCommitUnit {
    /// Recompute every founding coordinate from the four Events and refuse any
    /// unit that is not the closed caller-authored shape of section 6.1 and
    /// the fixed section 6.2 baseline. An error here is always
    /// `direct_conversation_founding_unit_invalid`.
    pub fn facts(&self) -> arkret_wire::Result<DirectConversationFoundingFacts> {
        use arkret_models_collaboration::governance::membership_invite::MembershipPayload;
        use arkret_models_collaboration::objects::direct_conversation::{
            DirectConversationPairKeyParticipant, direct_conversation_pair_key,
        };

        self.submission.validate().map_err(founding_unit_invalid)?;
        let events = self.submission.events.each_ref().map(|item| &item.event);
        let plan =
            arkret_models_collaboration::direct_conversation::DirectConversationFoundingPlan::from_events(
                events,
            )
            .map_err(founding_unit_invalid)?;
        let realm_scope = arkret_wire::ScopeRef::Realm {
            realm_id: plan.realm_id.clone(),
        };
        if events[0].scope_ref != arkret_wire::ScopeRef::RealmGenesis
            || events[1..]
                .iter()
                .any(|event| event.scope_ref != realm_scope)
        {
            return Err(founding_unit_invalid(
                "the genesis opens the Realm and the other three Events target its stream",
            ));
        }
        if self.submission.events.iter().any(|item| {
            item.approval_signatures.is_some()
                || item.event.executed_by.is_some()
                || item.event.authorization_ref.is_some()
                || item.event.applet_id.is_some()
        }) {
            return Err(founding_unit_invalid(
                "the founder authors every founding Event directly",
            ));
        }
        let unit_event_ids = events
            .iter()
            .map(|event| event.event_id.as_str())
            .collect::<std::collections::BTreeSet<_>>();
        if events[1..].iter().any(|event| {
            event.semantic_refs.iter().any(|reference| {
                unit_event_ids.contains(reference.id.as_str())
                    || matches!(
                        reference.role.as_str(),
                        "direct_conversation_contact_round" | "direct_conversation_agent_provision"
                    )
            })
        }) {
            return Err(founding_unit_invalid(
                "only the genesis carries the founding authority ref and no Event names another",
            ));
        }
        let genesis = arkret_event_draft::EventPayloadExt::as_realm_create(events[0])
            .map_err(founding_unit_invalid)?
            .object;
        if genesis.initial_join_rule != arkret_wire::JoinRule::Closed
            || genesis.initial_history_access != arkret_wire::HistoryAccess::SinceJoin
            || matches!(
                genesis.initial_discoverability,
                arkret_wire::Discoverability::Public | arkret_wire::Discoverability::Listed
            )
        {
            return Err(founding_unit_invalid(
                "the genesis must pin the closed, since_join, non-discoverable baseline",
            ));
        }
        let membership = |event: &Event| {
            serde_json::to_value(&event.payload)
                .and_then(serde_json::from_value::<MembershipPayload>)
                .map_err(founding_unit_invalid)
        };
        let founder = membership(events[1])?;
        let peer = membership(events[2])?;
        if [&founder, &peer].into_iter().any(|join| {
            join.strand_id.is_some()
                || !join.gate_proofs.is_empty()
                || join.invite_ref.is_some()
                || join.membership_cause.is_some()
        }) || founder.agent_controller_binding.is_some()
        {
            return Err(founding_unit_invalid(
                "the founding joins are neither invites nor gated entries",
            ));
        }
        let strand = arkret_event_draft::EventPayloadExt::as_strand_create(events[3])
            .map_err(founding_unit_invalid)?
            .object;
        let discussion = strand
            .tracks
            .get(arkret_models_collaboration::objects::profiles::STRAND_TRACK_NAME_DISCUSSION);
        if strand.scope_circle_id.is_some()
            || discussion
                .is_none_or(|track| track.is_primary != Some(true) || track.enabled == Some(false))
        {
            return Err(founding_unit_invalid(
                "the main Strand is Realm-default with a primary discussion track",
            ));
        }
        let trust_domain_id = genesis.trust_domain.clone();
        let pair_key = direct_conversation_pair_key(
            trust_domain_id.clone(),
            DirectConversationPairKeyParticipant::unmapped(founder.member_id.clone()),
            DirectConversationPairKeyParticipant::unmapped(peer.member_id.clone()),
        )
        .map_err(founding_unit_invalid)?;
        let mut roles = events[0].semantic_refs.iter().filter(|reference| {
            matches!(
                reference.role.as_str(),
                "direct_conversation_contact_round" | "direct_conversation_agent_provision"
            )
        });
        let authority_ref = match (roles.next(), roles.next()) {
            (Some(reference), None) if reference.critical => match reference.role.as_str() {
                "direct_conversation_contact_round" => {
                    DirectConversationFoundingAuthorityRef::ContactRound(
                        arkret_wire::Hash::new(reference.id.clone())
                            .map_err(founding_unit_invalid)?,
                    )
                }
                _ => DirectConversationFoundingAuthorityRef::AgentProvision(
                    arkret_wire::EventId::new(reference.id.clone())
                        .map_err(founding_unit_invalid)?,
                ),
            },
            _ => {
                return Err(founding_unit_invalid(
                    "the genesis must carry exactly one critical founding authority ref",
                ));
            }
        };
        if matches!(
            authority_ref,
            DirectConversationFoundingAuthorityRef::ContactRound(_)
        ) && peer.agent_controller_binding.is_some()
        {
            return Err(founding_unit_invalid(
                "a Contact-round founding carries no Agent controller binding",
            ));
        }
        Ok(DirectConversationFoundingFacts {
            founder_id: founder.member_id,
            peer_id: peer.member_id,
            trust_domain_id,
            governance_station_id: genesis.governance_station_id,
            pair_key,
            realm_id: plan.realm_id,
            main_strand_id: plan.main_strand_id,
            founding_unit_digest: plan.founding_unit_digest,
            authority_ref,
        })
    }

    pub fn validate(&self) -> arkret_wire::Result<()> {
        let facts = self.facts()?;
        let first = &self.transactions[0];
        let authority = &first.expected_authority;
        if authority.realm_id != facts.realm_id
            || authority.generation != 0
            || authority.last_handoff_ref.is_some()
            || authority.authority_ref
                != arkret_wire::RealmCommitAuthorityRef::GenesisOrChangeEvent(
                    first.event.event_id.clone(),
                )
        {
            return Err(founding_unit_invalid(
                "the founding unit must install its exact genesis authority",
            ));
        }
        for (submitted, transaction) in self.submission.events.iter().zip(&self.transactions) {
            transaction.validate()?;
            if submitted.event != transaction.event
                || transaction.expected_authority != *authority
                || transaction.mls_state.is_some()
                || !transaction.welcomes.is_empty()
            {
                return Err(founding_unit_invalid(
                    "a founding transaction diverges from its submitted Event or authority",
                ));
            }
        }
        arkret_models_collaboration::authority_commit::DirectConversationFoundingAcceptanceOutcome {
            unit_kind: self.submission.unit_kind,
            status:
                arkret_models_collaboration::authority_commit::AggregateAcceptanceStatus::Committed,
            commits: self.commits(),
        }
        .validate()?;
        if self.transactions[0].commit.stream_position != 0
            || self.transactions[0].commit.previous_commit_ref.is_some()
            || self
                .transactions
                .iter()
                .any(|transaction| transaction.commit.committed_at != first.commit.committed_at)
        {
            return Err(founding_unit_invalid(
                "the four founding Commits must open the Realm stream at one instant",
            ));
        }
        Ok(())
    }

    #[must_use]
    pub fn commits(&self) -> [RealmCommit; 4] {
        self.transactions
            .each_ref()
            .map(|transaction| transaction.commit.clone())
    }
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

/// Outcome of the registered `accepted_device` authorization unit.
#[derive(Clone, Debug, PartialEq)]
pub enum AcceptedDeviceAuthorizationOutcome {
    /// This call committed the Event, its RealmCommit and the device current.
    Committed(arkret_wire::RealmCommit),
    /// The exact Event was already accepted; this is its stored Commit.
    Duplicate(arkret_wire::RealmCommit),
}

/// One committed Event a non-governance member Station stores as an exact
/// source replica (`federation.md` §3, §4.1.1).
///
/// The serving layer has already verified the producer proof, the source
/// RealmCommit under `authority` and the Event/Commit binding. The store
/// re-proves continuity and the hosted-member basis under its own locks.
#[derive(Clone, Debug, PartialEq)]
pub struct CommittedReplica {
    /// This Station's own service id; a replica never names it as governance.
    pub local_service_id: arkret_wire::DidCoreId,
    /// The verified remote current authority the source Commit verified under.
    pub authority: CurrentRealmAuthority,
    pub event: arkret_wire::Event,
    pub commit: arkret_wire::RealmCommit,
    /// The item is a hosted member's own verified `join`, which may open this
    /// Station's held Realm stream at its position (the bootstrap exception).
    pub opens_stream: bool,
    pub received_at: chrono::DateTime<chrono::Utc>,
}

/// Result of storing one committed replica.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CommittedReplicaOutcome {
    Stored,
    Duplicate,
}

#[async_trait]
pub trait AuthorityCommitStore: Send + Sync {
    async fn install_genesis_authority(
        &self,
        authority: &CurrentRealmAuthority,
    ) -> PersistenceResult<()>;

    /// Record a verified remote current authority of a Realm this Station
    /// does not govern, so it can forward to and verify under it. A lower
    /// generation never replaces a higher one, a same-generation different
    /// authority is refused, and a Realm this Station governs is never
    /// rewritten.
    async fn record_remote_authority(
        &self,
        authority: &CurrentRealmAuthority,
        local_service_id: &arkret_wire::DidCoreId,
    ) -> PersistenceResult<()>;

    /// Whether the frozen Realm fanout intent of `event` to `peer` is still
    /// owed at the current accepted cut: one frozen basis must still hold as
    /// a whole (`federation.md` §4.1.1).
    async fn realm_fanout_still_owed(
        &self,
        event: &arkret_wire::Event,
        local_service_id: &arkret_wire::DidCoreId,
        peer: &arkret_wire::DidCoreId,
        witnesses: &[crate::RealmFanoutAuthorityWitness],
        at: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<bool>;

    /// Store one verified committed replica with its held-stream continuity,
    /// hosted-member basis and derived membership in one transaction.
    async fn install_committed_replica(
        &self,
        replica: &CommittedReplica,
    ) -> PersistenceResult<CommittedReplicaOutcome>;

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

    /// Test fixture: atomically queue a producer Event and install its
    /// authority Commit with no domain admission. Production admits every
    /// Event through its registered unit, never through this kind-agnostic
    /// path; the Account Authority private route accepts only the
    /// `accepted_device` unit.
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    async fn admit_event_transaction(
        &self,
        transaction: &AuthorityCommitTransaction,
        queued_at: DateTime<Utc>,
    ) -> PersistenceResult<AuthorityCommitWriteOutcome>;

    /// Test fixture: [`Self::admit_event_transaction`] that also rechecks the
    /// producer's current authorization in the same database transaction.
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
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

    /// Self bootstrap admission rechecks every exact producer binding in the
    /// same transaction as the Realm authority, Events and Commits.
    async fn admit_self_ordinary_realm_bootstrap_unit(
        &self,
        unit: &OrdinaryRealmBootstrapCommitUnit,
        producer_guards: &[SelfProducerCommitGuard],
        queued_at: DateTime<Utc>,
    ) -> PersistenceResult<OrdinaryRealmBootstrapCommitOutcome>;

    /// Admit the caller-authored Direct Conversation founding unit in one
    /// transaction (contact-and-direct-conversation.md sections 5.5 and 6.1):
    /// an exact retry of the same idempotency key and unit returns the stored
    /// Commits first; otherwise the founder's unique slot is claimed, the
    /// founding authority is read from this Station's current state, and the
    /// four Events, their consecutive Commits and current results are written.
    /// Every refusal writes nothing.
    async fn admit_self_direct_conversation_founding_unit(
        &self,
        unit: &DirectConversationFoundingCommitUnit,
        producer_guards: &[SelfProducerCommitGuard; 4],
        queued_at: DateTime<Utc>,
    ) -> PersistenceResult<DirectConversationFoundingCommitOutcome>;

    /// Evaluate the Direct Conversation admission table
    /// (contact-and-direct-conversation.md section 8.4) for `event` at one
    /// read-only cut of its Realm. The accepting transaction evaluates the
    /// same table again at its own cut; this read lets a caller refuse an
    /// Event it has no admission unit for, and skip reducer preflight for a
    /// Direct Conversation Realm, whose table precedes every other authority.
    async fn direct_conversation_admission(
        &self,
        event: &Event,
    ) -> PersistenceResult<DirectConversationAdmissionCut>;

    /// Install the complete PCR genesis, founding device current, and exact
    /// idempotency receipt in one durable transaction.
    async fn admit_pcr_genesis_unit(
        &self,
        unit: &PcrGenesisCommitUnit,
        queued_at: DateTime<Utc>,
    ) -> PersistenceResult<PcrGenesisCommitOutcome>;

    /// Admit one `accepted_device` `ak.device.authorize` relayed by the
    /// Account Authority (device-lifecycle.md §5.4, §5.5.2). At the locked PCR
    /// cut the approving device must be active in the current generation, the
    /// payload must name that generation, the target device must have no
    /// authorization history, and the target possession signature and the
    /// approver's producer proof must verify. The Event, Commit, typed device
    /// authorization and device mirror are written in one transaction; any
    /// refusal writes nothing.
    async fn admit_accepted_device_authorization(
        &self,
        transaction: &AuthorityCommitTransaction,
        queued_at: DateTime<Utc>,
    ) -> PersistenceResult<AcceptedDeviceAuthorizationOutcome>;

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

    /// Return snapshot material only when this exact Account's complete
    /// disclosure can be proved at one durable cut. Unsupported Realm shapes
    /// remain unavailable to the public snapshot endpoint.
    async fn realm_state_snapshot_material_for_account(
        &self,
        realm_id: &arkret_wire::RealmId,
        account: &arkret_wire::AccountId,
    ) -> PersistenceResult<Option<RealmStateSnapshotMaterial>>;

    /// Issue one complete signed Snapshot to `account` from a single durable
    /// cut: the governing tenure of `issuer` is locked and checked, the
    /// complete Account disclosure is proved, `sign` signs exactly that
    /// material, the canonical signed body is held to the 8 MiB inline limit,
    /// and the original object plus its Account issuance are persisted before
    /// the cut commits. Any failure leaves no issued object.
    async fn issue_realm_state_snapshot_for_account(
        &self,
        realm_id: &arkret_wire::RealmId,
        account: &arkret_wire::AccountId,
        issuer: &arkret_wire::DidCoreId,
        sign: RealmStateSnapshotSigner<'_>,
    ) -> PersistenceResult<Option<RealmStateSnapshot>>;

    /// Read the original signed Snapshot previously issued to this exact
    /// Account and recheck, at one read cut, that every disclosed row, head,
    /// and floor is still disclosable to it. `None` means the exact object
    /// was never issued to this Account for this Realm.
    async fn issued_realm_state_snapshot(
        &self,
        realm_id: &arkret_wire::RealmId,
        account: &arkret_wire::AccountId,
        snapshot_id: &arkret_wire::RealmSnapshotId,
        issuer: &arkret_wire::DidCoreId,
    ) -> PersistenceResult<Option<RealmStateSnapshot>>;

    /// Freeze one Account window over the Realm stream at a single durable
    /// cut that share-locks the governing tenure of `issuer` and re-proves the
    /// Account's complete disclosure. A limited window carries a
    /// `window_start_basis` only when an exact snapshot issued to the Account
    /// matches its anchor and can be reserved for the window's consumable
    /// period; otherwise the stream is `preview_only`. The frozen head is
    /// issued to the Account in the same cut, signed by `sign`, so the next
    /// live delta after it names that exact snapshot as its basis. `None`
    /// means the Realm has no governed material.
    async fn freeze_account_realm_window(
        &self,
        request: &AccountRealmWindowRequest,
        sign: RealmStateSnapshotSigner<'_>,
    ) -> PersistenceResult<Option<AccountRealmWindow>>;

    /// Re-read a frozen window's reserved basis. `None` means the guarantee
    /// is lost (never reserved, expired, reclaimed, or no longer disclosable)
    /// and any re-emission of that stream window must be `preview_only`.
    async fn account_window_basis(
        &self,
        realm_id: &arkret_wire::RealmId,
        account: &arkret_wire::AccountId,
        window_cursor: &str,
        stream_ref: &CommitStreamRef,
        issuer: &arkret_wire::DidCoreId,
        now_ms: i64,
    ) -> PersistenceResult<
        Option<arkret_models_collaboration::sync_frames::account_sync::StreamWindowStartBasis>,
    >;

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

    /// `ak.self.committed_event.read.scan.v1` for one authenticated Account.
    ///
    /// Authorization, the readable interval, and the returned page come from
    /// one read cut at which `issuer` holds the Realm's governing tenure.
    /// Only intervals this Station can prove are served; every other shape
    /// fails closed as [`AccountStreamScan::Unproved`], never as a physical
    /// page that could disclose rows outside the caller's permission.
    async fn scan_stream_for_account(
        &self,
        request: &arkret_wire::StreamScanRequest,
        account: &arkret_wire::AccountId,
        issuer: &arkret_wire::DidCoreId,
    ) -> PersistenceResult<AccountStreamScan>;

    /// `ak.peer.committed_event.read.scan.v1` for one authenticated peer
    /// Station (`service-http-binding.md` §3.1.3: the calling Station must
    /// hold the replication right for the exact stream).
    ///
    /// A peer with no currently joined member routed to it has no right on
    /// any stream of the Realm. Every other shape is decided at the same
    /// governing read cut and fails closed as [`AccountStreamScan::Unproved`]
    /// until this Station can prove the peer's exact interval and disclosure.
    async fn scan_stream_for_peer(
        &self,
        request: &arkret_wire::StreamScanRequest,
        peer: &arkret_wire::DidCoreId,
        issuer: &arkret_wire::DidCoreId,
    ) -> PersistenceResult<AccountStreamScan>;

    /// `ak.self.realm.read.streams.v1` for one authenticated Account. The
    /// stream set, each head and each readable floor come from one read cut at
    /// which `issuer` holds the Realm's governing tenure; a set or floor this
    /// Station cannot prove fails closed instead of omitting a stream.
    async fn list_realm_streams_for_account(
        &self,
        realm_id: &arkret_wire::RealmId,
        account: &arkret_wire::AccountId,
        issuer: &arkret_wire::DidCoreId,
    ) -> PersistenceResult<AccountRealmStreamList>;

    /// `ak.self.current_results.read.exact.v1` for one authenticated Account:
    /// membership, governance generation, effective stream head and the
    /// selector's durable current row from one read cut.
    async fn exact_current_result_for_account(
        &self,
        request: &arkret_models_collaboration::exact_current_results::ExactCurrentResultsReadRequestBody,
        account: &arkret_wire::AccountId,
        issuer: &arkret_wire::DidCoreId,
    ) -> PersistenceResult<
        SelfExactCurrentRead<
            arkret_models_collaboration::exact_current_results::ExactCurrentResultsReadOutcome,
        >,
    >;

    /// `ak.self.strand.watch.read.current.v1` for the authenticated Account,
    /// which is also the request's watcher.
    async fn strand_watch_current_for_account(
        &self,
        request: &arkret_models_collaboration::strand_watch_operations::StrandWatchCurrentRequestBody,
        account: &arkret_wire::AccountId,
        issuer: &arkret_wire::DidCoreId,
    ) -> PersistenceResult<
        SelfExactCurrentRead<
            arkret_models_collaboration::strand_watch_operations::StrandWatchCurrentOutcome,
        >,
    >;

    /// Membership visibility and the accepted media service anchor of one
    /// Realm for `ak.self.media_service_binding.read.resolve.v1`.
    async fn media_service_anchor_for_account(
        &self,
        realm_id: &arkret_wire::RealmId,
        account: &arkret_wire::AccountId,
        issuer: &arkret_wire::DidCoreId,
    ) -> PersistenceResult<MediaServiceAnchorRead>;

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

    /// Latest handoff-installed snapshot. Account-issued `/head` objects are
    /// caller-scoped disclosures and never serve as this Realm-wide anchor.
    async fn latest_snapshot(
        &self,
        realm_id: &arkret_wire::RealmId,
    ) -> PersistenceResult<Option<RealmStateSnapshot>>;
}

#[cfg(test)]
mod mls_installation_tests {
    use arkret_models_crypto::{MlsCommitEnvelope, MlsCommitPayload, MlsGovernanceBindingPayload};
    use arkret_wire::{EventId, Hash, RealmId, ScopeRef};

    use super::{MlsStateInstallation, validate_mls_installation};

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
