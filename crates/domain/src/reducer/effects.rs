//! Effect enums returned by the reducer's `apply_*` helpers.
//!
//! Split out of the `reducer` mod file; re-exported there so the
//! `crate::reducer::ProjectionEffect` / `MlsEffect` paths stay unchanged.

use arkret_models_collaboration::agent_operations::AgentLifecycleState;
use serde_json::Value;

use super::{
    CircleLifecycleState, MessageState, ObjectLifecycleState, PushRouteSubject, ReadMarkerState,
    SolandRelationState, SpaceContainerLifecycleState,
};

/// The effect of applying an operation to the projection state.
#[derive(Clone, Debug)]
pub enum ProjectionEffect {
    MessageCreated(MessageState),
    MessageRevised {
        original_id: String,
        revision: MessageState,
    },
    MessageRedacted {
        event_id: String,
    },
    ReactionChanged {
        event_id: String,
        actor: String,
        key: String,
        active: bool,
    },
    RsvpProjected {
        event_ref: String,
        actor_id: String,
        occurrence: Option<String>,
        /// Live `mv_register` heads after the join. More than one means the
        /// responder has concurrent responses that only they can resolve.
        head_count: usize,
    },
    PinProjected {
        pin_scope_key: String,
        target_ref: String,
        active: bool,
    },
    ReadMarkerUpdated(ReadMarkerState),
    RelationCreated(SolandRelationState),
    RelationUpdated(SolandRelationState),
    RelationDeleted {
        relation_id: String,
    },
    ContainerPositionProjected {
        container_ref: String,
        item_ref: String,
    },
    ContainerOrderProjected {
        container_ref: String,
        position_count: usize,
    },
    MembershipChanged {
        realm_id: String,
        member: String,
        action: String,
    },
    InviteStateChanged {
        invite_id: String,
        realm_id: String,
        state: String,
        invitee: Option<String>,
    },
    KeyBackupActiveSeriesProjected {
        actor_id: String,
        backup_kind: String,
        active_series_id: String,
    },
    RealmLifecycle {
        realm_id: String,
        action: String,
    },
    /// COT-06-004 — `ak.realm.set_default_strand` projected. The Realm's
    /// `default_strand_id` now points at `strand_id`.
    RealmDefaultStrandSet {
        realm_id: String,
        strand_id: String,
    },
    /// Space-container lifecycle transition accepted; new state is reflected in
    /// `ProjectionState::space_containers` and (when persisted) `projection_space_containers`.
    SpaceContainerLifecycle {
        container_space_id: String,
        new_state: SpaceContainerLifecycleState,
    },
    /// Strand lifecycle transition accepted. Mirror of `SpaceContainerLifecycle`
    /// for `ProjectionState::strands`.
    StrandLifecycle {
        strand_id: String,
        new_state: ObjectLifecycleState,
    },
    /// Morph lifecycle transition accepted. Same shape as Strand.
    MorphLifecycle {
        morph_id: String,
        new_state: ObjectLifecycleState,
    },
    /// AKP-0007 — Circle lifecycle transition accepted. Reflects
    /// `ak.circle.create` / `update` / `archive` / `restore` / `tombstone`
    /// projection writes; new state is reflected in
    /// `ProjectionState::circles` (and the durable `projection_circles`
    /// mirror once persistence is wired).
    CircleLifecycle {
        circle_id: String,
        new_state: CircleLifecycleState,
    },
    /// AKP-0007 — Circle membership transition. `target_state` is the
    /// `ak.circle.member.state` payload's `state` value (active / removed /
    /// banned / left / invited). The reducer applies the membership write
    /// only after the strict-subset invariant
    /// (`Circle.members ⊆ Realm.members`) has been satisfied.
    CircleMemberStateChanged {
        circle_id: String,
        member: String,
        target_state: String,
    },
    /// Strand watch cell touched. Cell write itself is owned by the
    /// Move/Seal pipeline (cas-register at SDK layer); the projection
    /// only records that a watch change happened for `(strand_id, actor_id)`
    /// so downstream listeners (notification dispatcher, watcher list
    /// projection) can react. `level` is `None` when the effect clears
    /// the cell.
    StrandWatchUpdated {
        strand_id: String,
        actor_id: String,
        level: Option<String>,
        level_public: Option<bool>,
    },
    /// Applet registry projection updated (registration or discovery).
    /// Keyed by the applet's `service_id`.
    AppletProjectionUpdated {
        service_id: String,
    },
    /// R1.2 — `ak.realm.delivery_binding_policy` event was projected
    /// into the canonical `ak.component.realm.delivery_binding_policy.v1`
    /// cas-register cell.
    DeliveryBindingPolicyProjected {
        realm_id: String,
    },
    /// `ak.realm.policy_bundle` projected into the canonical
    /// `ak.component.realm.policy_bundle.v1` cas-register cell.
    RealmPolicyBundleProjected {
        realm_id: String,
    },
    /// A registry-validated Realm bootstrap facet was written to its exact
    /// single-target cas-register cell during the staged genesis transaction.
    RealmBootstrapFacetProjected {
        realm_id: String,
        kind: String,
    },
    RealmDisappearingPolicyProjected {
        realm_id: String,
    },
    RealmSearchPolicyProjected {
        realm_id: String,
    },
    RealmNotaryProjected {
        realm_id: String,
    },
    RealmDigestSuiteTransitionProjected {
        realm_id: String,
        digest_algorithm: String,
    },
    /// `ak.realm.media_service` projected into the canonical
    /// `ak.component.realm.media_service.v1` cas-register cell consumed by
    /// the AKP-0010 media token exchange.
    RealmMediaServiceProjected {
        realm_id: String,
    },
    /// `ak.call.state` projected into the canonical
    /// `ak.component.call.state.v1` cell. Carries the committed
    /// `session_focus` plus the orthogonal recording / transcribe /
    /// moderation projection (`call-state.md` §4.2 / §5).
    CallStateProjected {
        call_id: String,
    },
    /// Audit binding genesis/state projected. The immutable binding document
    /// and its lifecycle live in separate cells keyed by one AuditBindingId.
    AuditBindingProjected {
        binding_id: String,
        state: String,
    },
    /// `call-state.md` §7 — `ak.call.summary` projected into the write-once
    /// `ak.component.call.summary.v1` cas_register cell.
    CallSummaryProjected {
        call_id: String,
    },
    /// R3.1 — `ak.realm.link` event was projected into the
    /// `ak.component.realm.link.v1` FSM cell + the `realm_links`
    /// structured cache.
    RealmLinkProjected {
        realm_id: String,
        target_realm_id: String,
        link_kind: String,
        status: String,
    },
    /// R3.2 — `ak.realm.inheritance_policy` event was projected into the
    /// `ak.component.realm.inheritance_policy.v1` cas-register cell.
    RealmInheritancePolicyProjected {
        realm_id: String,
        source_realm_id: String,
    },
    /// R3.2 — `ak.capability.derived` event was projected into the
    /// `ak.component.capability.derived.v1` cas-register cell.
    CapabilityDerivedProjected {
        capability_id: String,
        realm_id: String,
    },
    /// SOL-ORG-02 — `ak.realm.organization` relationship statement projected
    /// into the `ak.component.realm.organization.v1` cas-register cell keyed by
    /// `(organization_id, relationship)` + the `realm_organization_statements`
    /// structured cache. `status` is `active` (relationship live) or `revoked`
    /// (inactive, retained for audit).
    RealmOrganizationProjected {
        realm_id: String,
        organization_id: String,
        relationship: String,
        status: String,
    },
    /// P1 — `ak.capability.grant` event was projected into the
    /// `ak.component.capability.grant.v1` or_set cell (one cell per
    /// `grant_id`). `revived_terminal=false` always; a re-grant of a
    /// `grant_id` whose add was already observed-removed stays revoked
    /// (capabilities.md §12.1 terminal rule).
    CapabilityGrantProjected {
        grant_id: String,
        realm_id: String,
    },
    /// P1 — `ak.capability.revoke` event was projected as an or_set
    /// observed-remove on the target grant cell (capabilities.md §12 /
    /// §12.1). Terminal: the add dot stays removed under re-add.
    CapabilityRevokeProjected {
        grant_id: String,
        realm_id: String,
    },
    /// `ak.capability.relinquish` removed the target subject's own grant.
    CapabilityRelinquishProjected {
        grant_id: String,
        realm_id: String,
    },
    /// REDU-1 (R3 spec-sync 2026-05-27, arkret-spec b47ff6ec) — agent
    /// lifecycle FSM transition projected. `agent_id` is the DID
    /// from the payload; `new_state` is the post-transition
    /// AgentLifecycleState. Bottom = `Reject`;
    /// Deactivated is terminal.
    AgentLifecycleProjected {
        agent_id: String,
        new_state: AgentLifecycleState,
    },
    /// `ak.agent.key.authorize` projected: the key is recorded in
    /// `agent_authorized_keys`. Realm grants are independent from pairing.
    AgentKeyAuthorizeProjected {
        agent_id: String,
        key_id: String,
    },
    /// AKP-0008 §4.11 — `ak.agent.key.revoke` projected: the key was removed
    /// from `agent_authorized_keys`.
    AgentKeyRevokeProjected {
        agent_id: String,
        key_id: String,
    },
    /// REDU-2 — `actor_private_event` accepted (reducer_input=false).
    /// Wire-accepted and surfaced to audit-log consumers, but does NOT
    /// advance the seal frontier / actor_seq.
    AgentPrivateEventAccepted {
        kind: &'static str,
        event_id: String,
    },
    /// MID-1..6 (R3.1/R3.2, arkret-spec @ b56cab1) —
    /// `ak.member.identity.update` accepted into the ordered-log
    /// `ak.component.member.identity.v1` cell. The actual replacement-edge
    /// filter + per-actor effective-set / `member_display_state_digest`
    /// materialization live on the `MemberIdentityRegistry`
    /// (`AppState::member_identity`) because they span cells; this effect
    /// just signals that an event landed.
    MemberIdentityProjected {
        realm_id: String,
        actor_id: String,
        segment: String,
        event_id: String,
    },
    /// G3.S1 — MLS lifecycle effect. One variant covers all four
    /// reducer paths (publish / claim / welcome_enqueue / commit_epoch)
    /// so the routing layer can dispatch on `MlsEffect` without
    /// growing four near-identical `ProjectionEffect` arms.
    Mls(MlsEffect),
    /// `ak.realm_key.share` accepted by the reducer. Routing projection uses
    /// this effect to enqueue the share onto the recipient device's to-device
    /// queue after the share payload and key scope have passed fail-closed
    /// checks.
    RealmKeyShareProjected {
        realm_id: String,
        recipient_principal_id: String,
        /// Absent for `share_kind=realm_recovery_key` (offline RRK recipient).
        recipient_device_id: Option<String>,
    },
    /// G3.S2 — `ak.realm.policy_server` projected into the
    /// `ak.component.realm.policy_server.v1` cas-register cell + the
    /// `realm_policy_servers` structured cache.
    RealmPolicyServerProjected {
        realm_id: String,
        policy_server_did: String,
    },
    RealmPolicyServerTombstoned {
        realm_id: String,
    },
    /// Two accepted `ak.realm.policy_server` Moves cited the same frozen basis
    /// with different values; the cas-register cell joined to `⊥` and every
    /// dependent read now fails closed until conflict recovery.
    RealmPolicyServerConflicted {
        realm_id: String,
    },
    /// `ak.device.push_route` actor-private state projected into the
    /// per-recipient Principal Server push-route cell cache.
    PushRouteUpdated {
        subject: PushRouteSubject,
        action: String,
    },
    /// An accepted projection event referenced a target that has not reached
    /// this reducer yet. The operation is retained in
    /// `ProjectionState::pending_replay` and replayed once the target is
    /// materialized by backfill, snapshot restore, or a later create event.
    PendingReplayQueued {
        target_ref: String,
        operation_id: String,
        reason: String,
    },
    /// P2 — `ak.moderation.decision` projected as an or_set add into the
    /// `ak.component.moderation_state.v1` cell keyed by `payload.target_ref`
    /// (content-moderation.md §2.6). Carries an issuer/target_ref/decision
    /// snapshot so the appeal separation-of-duties check can reverse-resolve
    /// the original decision issuer from the cell.
    ModerationDecisionProjected {
        decision_id: String,
        realm_id: String,
    },
    /// P2 — `ak.moderation.decision.lift` projected as an or_set
    /// observed-remove / supersede on the moderation_state target cell.
    /// Terminal: a re-add of a lifted decision_id
    /// stays lifted (mirrors capabilities.md §12.1).
    ModerationDecisionLifted {
        decision_id: String,
        realm_id: String,
    },
    /// P2 — `ak.moderation.appeal.{submit,review,decision,close}` projected
    /// onto the `ak.component.moderation.appeal.v1` fsm cell keyed by
    /// `payload.appeal_id`. `new_state` is the post-transition FSM value
    /// (submitted / under_review / decided / closed); content-moderation.md
    /// §5.5.
    ModerationAppealProjected {
        appeal_id: String,
        realm_id: String,
        new_state: String,
    },
    /// State-machine rejected the operation per
    /// `common-fields.md §5.1`. Routing layer maps this to HTTP 412
    /// `failed_precondition` with the canonical reason_code.
    Rejected {
        reason: String,
    },
    Ignored,
}

/// G3.S1 — discriminated effect emitted by the MLS reducer helpers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MlsEffect {
    /// `apply_keypackage_publish` — a fresh KeyPackage row was stored
    /// for `(actor_id, device_id)`.
    KeyPackagePublished {
        keypackage_id: String,
        actor_id: String,
        device_id: String,
    },
    /// `apply_keypackage_claim` — the named KeyPackage was atomically
    /// claimed for `group_id`. CAS guarantees at-most-one of these per
    /// `keypackage_id`.
    KeyPackageClaimed {
        keypackage_id: String,
        group_id: String,
        intended_realm_id: Option<String>,
        last_resort: bool,
        claimed_at: i64,
    },
    /// `apply_welcome_enqueue` — a Welcome envelope was appended to the
    /// per-`(recipient_actor_id, recipient_device_id)` queue.
    WelcomeEnqueued {
        welcome_id: String,
        recipient_actor_id: String,
        recipient_device_id: String,
        group_id: String,
    },
    /// `apply_remove_proposal` — a `ak.mls.proposal{proposal_type="remove"}`
    /// was recorded so a later commit can consume a pending remove obligation.
    RemoveProposalRecorded {
        proposal_ref: String,
        group_id: String,
        effective_scope: Value,
        target_actor_id: String,
        target_device_id: Option<String>,
    },
    /// `apply_group_genesis` — the group was initialized at epoch 0.
    GroupGenesis {
        group_id: String,
        effective_scope: Value,
        epoch: u64,
        creator_actor_id: String,
        creator_device_id: String,
    },
    /// `apply_commit_epoch` — the group's epoch was bumped from
    /// `previous_epoch` to `new_epoch`.
    CommitEpochAdvanced {
        group_id: String,
        effective_scope: Value,
        previous_epoch: u64,
        new_epoch: u64,
        leader_actor_id: String,
    },
    /// `apply_commit_epoch` — a second commit attested the same base epoch with
    /// different commit material, resolving the group's `covered_frontier_cell`
    /// to `⊥` (encryption-and-audit.md §2.5.2). The epoch is left untouched and
    /// marked contested; sends / decrypts on it fail closed as
    /// `decryption_pending` until a resolving commit advances the epoch.
    CommitFrontierContested {
        group_id: String,
        effective_scope: Value,
        epoch: u64,
    },
}

/// Which Space-container lifecycle transition is being attempted. Used by
/// `apply_space_container_lifecycle` to share the state-machine guard across
/// the three event kinds.
#[derive(Clone, Copy, Debug)]
pub(crate) enum SpaceContainerLifecycleTransition {
    Archive,
    Restore,
    Tombstone,
}

/// Strand / Morph lifecycle transition picker. Mirror of
/// `SpaceContainerLifecycleTransition` but for the two-event family (no tombstone).
#[derive(Clone, Copy, Debug)]
pub(crate) enum ObjectLifecycleTransition {
    Archive,
    Restore,
}
