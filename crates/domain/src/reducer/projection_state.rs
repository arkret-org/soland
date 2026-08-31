//! The core [`ProjectionState`] struct and its inline `impl` (cell
//! helpers, push-route apply, dispatch entry points, and Strand / Morph
//! state-machine preflights).
//!
//! Split out of the `reducer` mod file; re-exported there so the
//! `crate::reducer::ProjectionState` path and sibling `super::*` access
//! stay unchanged. Additional `impl ProjectionState` blocks live in the
//! `apply_*` sibling modules.

use std::collections::{BTreeMap, BTreeSet};

use arkret_event_draft::ProjectedEventOperation as Operation;
use arkret_identifiers::{CellRef, RealmId};
use arkret_models_collaboration::agent_operations::AgentLifecycleState;
use arkret_models_collaboration::governance::agent_membership_cascade::AgentControllerMembershipBinding;
use arkret_state::lattice::CellState;
use arkret_state::state::{CellRegistry, CellStore, StoreError};
use arkret_wire::cba::ProjectedCellWrite;
use arkret_wire::{AppletId, ProfileId};
use serde_json::Value;

use super::*;
use crate::hlc::ServerHlc;

/// In-memory projection state produced by the reducer.
#[derive(Clone, Debug, Default)]
pub struct ProjectionState {
    /// Messages keyed by event_id. LWW by created_at.
    pub messages: BTreeMap<String, MessageState>,
    /// Reactions keyed by (event_id, actor, reaction_key). OR-Set.
    pub reactions: BTreeMap<String, BTreeMap<String, BTreeMap<String, ReactionState>>>,
    /// Calendar RSVP projection keyed by the registered composite cell subject
    /// `(event_ref, occurrence, actor_id)`, where `occurrence` keeps the signed
    /// JSON null as `None` rather than a sentinel string.
    ///
    /// This mirrors the `ak.component.calendar.rsvp.v1` `mv_register` cell: it
    /// holds every live head, never a single last-writer value.
    pub rsvps: BTreeMap<(String, Option<String>, String), RsvpProjection>,
    /// Shared pin projection keyed by `(pin_scope_key, target_ref)`.
    /// Saved items remain holder-private account-data and never enter this
    /// shared Realm cache.
    pub pins: BTreeMap<(String, String), PinProjection>,
    /// Read markers keyed by (realm_id, actor, scope_id). Causal-first merge;
    /// HLC/device ordering applies only to causally concurrent positions.
    pub read_cursors: BTreeMap<(String, String, String), ReadMarkerOutcome>,
    /// Relations keyed by relation_id. LWW by HLC.
    pub relations: BTreeMap<String, SolandRelationState>,
    /// Per-(Strand, Actor) notification watch preferences.
    pub strand_watches: BTreeMap<(String, String), StrandWatchProjection>,
    /// Poll projections keyed by poll_id. Poll create is a message content
    /// block; responses are per-actor replacements until the poll is closed.
    pub polls: BTreeMap<String, PollState>,
    /// Structured side-band cache keyed by
    /// `(realm_id, actor_id)`. Holds the FSM state value plus `role` /
    /// `joined_at` / `updated_at` side-band data that doesn't fit in the
    /// `ak.component.member.state.v1` FSM cell itself. Reads should go
    /// through helpers like [`ProjectionState::members_of_realm`] /
    /// [`ProjectionState::members_in_state`] / [`ProjectionState::member`]
    /// rather than touching this directly.
    ///
    /// Banned and knocking members are derived via `members_in_state`
    /// against the FSM state field, not stored as separate collections.
    pub members: BTreeMap<(String, String), SolandMembershipState>,
    /// Exact controller authority and controller join generation carried by a
    /// Agent membership Event. Effective Agent membership is
    /// derived by joining this binding with the current controller member cell.
    pub agent_membership_bindings: BTreeMap<(String, String), AgentControllerMembershipBinding>,
    /// Server-side invite projection keyed by `invite_id`.
    /// `ak.invite.third_party` creates pending third-party invites and
    /// `ak.invite.claim` converts them into DID-targeted claimed invites.
    pub invites: BTreeMap<String, InviteProjection>,
    /// Signed key-backup active-series records keyed by `(actor_id,
    /// backup_kind)`. Recovery MUST use this pointer instead of inferring the
    /// canonical series from list order or latest timestamp.
    pub key_backup_active_series: BTreeMap<(String, String), SolandKeyBackupActiveSeries>,
    /// Realm lifecycle state keyed by realm_id.
    pub realm_states: BTreeMap<String, SolandRealmState>,
    /// Redacted event IDs (tombstones). This stays as a flat
    /// fast-lookup index over the parallel [`Self::redaction_cells`] map.
    pub redactions: BTreeSet<String>,
    /// Parallel `redaction` cells keyed by the target
    /// event_id (subject). Each value is a [`RedactionCellValue`] holding
    /// the accepted redaction fact. The original message entry in [`Self::messages`] is
    /// left intact so the ordered-log historical entry id is preserved;
    /// the projection layer consults this map at read time and replaces
    /// the payload with the tombstone.
    pub redaction_cells: BTreeMap<String, RedactionCellValue>,
    /// Accepted projection operations whose local target is not materialized
    /// yet. Backfill/snapshot/create arrival drains this queue and replays the
    /// operations instead of losing them as accepted no-ops.
    pub pending_replay: BTreeMap<String, Vec<PendingReplayEntry>>,
    /// Per-cell effective state
    /// populated from the Move/Seal pipeline's `apply_seal` write-back.
    ///
    /// Keyed by canonical `CellRef` (e.g.
    /// `ak:cell:ak.component.realm.read_receipt_policy.v1:null`).
    /// Realm-singleton Event effects use the canonical subject `null` on wire;
    /// the enclosing Realm id is carried by the separate
    /// `realm_null_subject_cells` key so singleton values from different
    /// Realms remain isolated.
    /// Each successful `apply_seal` call from peer-event admission or
    /// `crate::notary::NotaryWorker` calls
    /// [`ProjectionState::reload_cells_from_store`] to refresh this map for
    /// the affected Realm. Read handlers query via [`ProjectionState::cell`]
    /// / [`ProjectionState::cell_value`] for cell-keyed state lookups
    /// instead of scanning the durable Event store.
    ///
    /// This map is the canonical source for all cell-driven state in the
    /// Move/Seal pipeline.
    /// Completed migrations:
    ///   - `read_receipt_policies` (CasRegister) — old BTreeMap deleted; read path uses
    ///     `cell_value`.
    ///   - `memberships` / `banned_members` / `knocking_members` (FSM) — replaced by flat
    ///     `members: BTreeMap<(String, String), SolandMembershipState>` cache + per-actor
    ///     `ak.component.member.state.v1` FSM cell.
    ///   - `realm_states` remains an application-side effective view; protocol truth is split
    ///     across genesis/create-log/profile/facet/terminal cells. Helpers: `realm_create_log` /
    ///     `realm_genesis_cell_value` / `realm_profile_cell_value` / `realm_is_destroyed` query
    ///     cells directly. Durable-event-only fields (`messages` / `reactions` / `read_cursors` /
    ///     `relations` / `redactions`) stay structured per spec (those event kinds have no
    ///     `cell_family` declaration).
    pub cells: BTreeMap<CellRef, CellState>,
    /// Realm-scoped resolved values for protocol cell families
    /// whose canonical subject is the literal `null`. The Realm id belongs
    /// to the CellStore namespace, not the wire cell id, so these values
    /// cannot safely share the global `cells` map.
    pub realm_profile_cells: BTreeMap<String, CellState>,
    pub realm_create_cells: BTreeMap<String, CellState>,
    pub realm_notary_cells: BTreeMap<String, CellState>,
    pub realm_policy_bundle_cells: BTreeMap<String, CellState>,
    /// Other canonical null-subject Realm facets keyed by
    /// `(realm_id, canonical_cell_ref)`.
    pub realm_null_subject_cells: BTreeMap<(String, String), CellState>,
    /// Effective `default_join_rule`, keyed by Realm. This mirrors the
    /// bootstrap/create value and later sealed join-rule facet so admission
    /// can select the protocol's C-axis gates without inventing a Realm id
    /// cell subject.
    pub realm_join_rules: BTreeMap<String, String>,
    /// Server-side Space-container projection —
    /// `container_space_id -> SpaceContainerProjection`.
    /// Maintains the canonical state-machine described in
    /// `arkret-spec/v1/zh/models/common-fields.md §5.1` for `ak.space.*`
    /// lifecycle events. Used by `event_log::submit_event` to reject
    /// invalid transitions with HTTP 412 before persisting. Reducer applies
    /// `ak.space.create` / update / parent / archive / restore / tombstone;
    /// mirror table is the `projection_space_containers` durable table.
    pub space_containers: BTreeMap<String, SpaceContainerProjection>,
    /// Server-side Strand projection. Mirrors the canonical state-machine
    /// for ak.strand.create / update / archive / restore. Unlike Space
    /// there is no dedicated `ak.strand.tombstone` event; terminal state
    /// is reached via `ak.redaction`. Mirror table is `projection_strands`
    /// (durable).
    pub strands: BTreeMap<String, StrandProjection>,
    /// AKP-0007 — server-side Circle projection. Mirrors the canonical
    /// state-machine for `ak.circle.*` lifecycle / membership events
    /// (spec b7d35be `zh/models/circle.md`). Keyed by `circle_id`
    /// (`ak:circle:<44-char event token>`); membership and parent-Realm binding live in
    /// the struct so the wire layer can enforce
    /// `Circle.members ⊆ Realm.members` without an extra DB hop.
    pub circles: BTreeMap<String, CircleProjection>,
    /// First-class Sidecars keyed by `sidecar_id`.
    pub sidecars: BTreeMap<String, SidecarProjection>,
    /// Native source-context mappings keyed by `(sidecar_id, kind:id)`.
    pub sidecar_contexts: BTreeMap<(String, String), SidecarContextProjection>,
    /// Accepted control ref that created each Sidecar.
    pub sidecar_create_refs: BTreeMap<String, String>,
    /// Current accepted join ref for each active Circle member.
    pub circle_member_join_refs: BTreeMap<(String, String), String>,
    /// Every accepted MLS Commit ref, used to bind Welcome evidence to an
    /// actually accepted epoch transition.
    pub accepted_mls_commit_refs: BTreeSet<String>,
    /// Side-band membership boundaries for Circle history filtering. Keyed by
    /// `(circle_id, actor_id)` and retained across leave/ban transitions so
    /// read-side helpers can enforce invited/joined floors deterministically.
    pub circle_memberships: BTreeMap<(String, String), CircleMembershipState>,
    /// Server-side Morph projection. Same shape as Strand. Mirror table
    /// is `projection_morphs` (durable).
    pub morphs: BTreeMap<String, MorphProjection>,
    /// Server-side Applet registry projection, keyed by canonical `applet_id`.
    /// `service_id` remains an authority attribute and may identify multiple
    /// Applets. Populated by
    /// `ak.applet.registration` (initial registration / re-registration)
    /// and updated by `ak.applet.discovery` (freshness only). Used by
    /// `GET /_soland/admin/applets` admin snapshot. Runtime-private applet
    /// session progress is not a durable Arkret event and is not mirrored here.
    pub applets: BTreeMap<AppletId, AppletProjection>,
    /// R3 spec-sync (2026-05-27, arkret-spec b47ff6ec) — FSM lifecycle
    /// state for each agent_id. Driven by
    /// `ak.agent.{pause,resume,deactivate}` (REDU-1). Default `Active`
    /// for any agent_id we've seen; `Deactivated` is terminal
    /// (no transition out, no resume after).
    pub agent_lifecycles: BTreeMap<String, AgentLifecycleState>,
    /// Actor-private action approval queue keyed by `request_id`.
    /// `ak.agent.action_request` creates pending entries; approve/reject
    /// resolves them, and pause/deactivate cancels every still-pending request
    /// for the target agent before any future endpoint can be registered.
    pub agent_action_requests: BTreeMap<String, AgentActionRequestProjection>,
    /// Accepted, non-revoked agent key authorizations keyed by `agent_id`.
    /// An entry is the set of authorized `key_id`s the agent currently holds
    /// (cleared on `ak.agent.key.revoke`).
    /// Agent id -> (active key id -> accepted authorize Event id).
    pub agent_authorized_keys: BTreeMap<String, BTreeMap<String, String>>,
    /// Latest accepted FSM head for each independent call cell. This detects
    /// same-basis sibling transitions without coupling orthogonal call axes.
    pub call_fsm_heads: BTreeMap<arkret_identifiers::CellRef, CallFsmHead>,
    /// R3.1 — Realm-link projection. Outer key is the source
    /// `realm_id` (the envelope `realm_id` of a `ak.realm.link` event);
    /// the inner Vec accumulates every directed link the Realm has
    /// declared, including non-`active` status entries (so admin tooling
    /// can render `rejected` / `tombstoned` history). Cell-canonical
    /// values live in `cells` under
    /// `ak.component.realm.link.v1` keyed by `(realm, target, link_kind)`;
    /// this is the structured side-band cache used by the query API.
    pub realm_links: BTreeMap<String, Vec<RealmLinkState>>,
    /// R3.1 — inverse index of [`Self::realm_links`] keyed by the
    /// target `realm_id`. Lets the query API answer
    /// `direction=inbound` in O(1) without a full scan.
    pub realm_links_inbound: BTreeMap<String, Vec<RealmLinkState>>,
    /// R3.2 — `ak.realm.inheritance_policy` projection, keyed by the
    /// child `realm_id` (the envelope `realm_id`). Cas-register
    /// semantics — last write wins.
    pub realm_inheritance_policies: BTreeMap<String, RealmInheritancePolicyState>,
    /// realm-links.md §6.2 — per-`(child_realm, source_realm)` inheritance
    /// declarations, so a child that opts into multiple governance sources
    /// (multi-`governed_by`) retains each source's narrowed allow-list
    /// independently. Cas-register per `(child, source)` pair — a re-declared
    /// `(child, source)` replaces only that pair. This is the substrate the
    /// effective-policy read uses to compute the narrow-only intersection
    /// across all opted-in sources, distinct from the single last-write
    /// `realm_inheritance_policies` map used by the single-source aggregate read.
    pub realm_inheritance_policies_by_source:
        BTreeMap<(String, String), RealmInheritancePolicyState>,
    /// R3.2 — `ak.capability.derived` projection, keyed by
    /// `capability_id`. Cas-register semantics — last write wins per
    /// capability.
    pub capability_derived: BTreeMap<String, CapabilityDerivedState>,
    /// SOL-ORG-02 — `ak.realm.organization` relationship-statement
    /// projection, keyed by `(realm_id, organization_id, relationship)`.
    /// Cas-register semantics per `(organization_id, relationship)` cell
    /// subject — the latest statement (active or revoked) wins. Multiple
    /// owner / governance / sponsor / directory_certifier relationships for
    /// the same Realm coexist as independent rows. Cell-canonical values
    /// live in `cells` under `ak.component.realm.organization.v1` keyed by
    /// the composite `{organization_id}::{relationship}` subject; this is
    /// the structured side-band cache the verified-relationship and
    /// effective-policy reads consult.
    pub realm_organization_statements:
        BTreeMap<(String, arkret_wire::DidCoreId, String), RealmOrganizationStatementState>,
    /// G3.S1 — published MLS KeyPackages keyed by `keypackage_id`. Each
    /// row is per `(actor_id, device_id)`; the `claimed_by` / claim-window
    /// slots flip on a successful CAS claim.
    pub mls_key_packages: BTreeMap<String, MlsKeyPackageProjection>,
    /// G3.S1 — per-device Welcome binding projection. Standard durable
    /// device messages carry delivery; these rows support claim and consume
    /// validation without introducing a product-private transport.
    pub mls_welcomes: BTreeMap<MlsWelcomeQueueKey, Vec<MlsWelcome>>,
    /// G3.S1 — Remove proposals keyed by their canonical `ak.mls.proposal`
    /// event id. Commit validation uses this to ensure pending remove
    /// obligations are consumed by an explicit MLS Remove proposal reference.
    pub mls_remove_proposals: BTreeMap<String, MlsRemoveProposal>,
    /// G3.S1 — per-scope MLS commit-epoch state. Keyed by tagged
    /// effective scope plus `mls_group_id` per the genesis uniqueness
    /// rule. The reducer keeps the monotonic epoch counter in lockstep
    /// with `apply_commit_epoch` CAS rules: each accepted commit bumps
    /// the value by exactly +1 from the previous epoch. The same row
    /// accumulates the governance Seal frontier covered by accepted MLS
    /// commits so E2EE message paths can gate plaintext fallback against
    /// stale epochs.
    pub mls_commit_epochs: BTreeMap<MlsCommitEpochKey, MlsCommitEpoch>,
    /// Reducer-derived MLS remove obligations. A parent Realm
    /// `ak.member.state -> leave/ban` removes the actor from every Circle in
    /// that Realm. For MLS-backed Circle scopes, the same transition queues an
    /// obligation for the MLS path to issue a remove proposal/commit.
    pub pending_mls_removals: Vec<MlsRemoveObligation>,
    /// Device push-route projection keyed by the protocol composite
    /// `(recipient_id, principal_id, device_id, push_route)`.
    /// These are actor-private state cells and MUST stay isolated per
    /// recipient Station.
    pub push_routes: BTreeMap<PushRouteSubject, PushRouteCellValue>,
    /// Optional local Principal/Sync service DID. When set, incoming
    /// `ak.device.push_route` writes whose `recipient_id` does
    /// not match this service are rejected instead of cached.
    pub local_service_id: Option<String>,
    /// Stream-F (Wave 1B) — `ak.audit.erasure_receipt` projection.
    /// Append-only list of receipts the reducer has accepted. Spec
    /// `realm-and-space.md` §2.5.2 + erasure-receipt.schema.json.
    /// Receipts are durable events; the projection cache here is used
    /// by the `erasure_receipts_endpoint` server-describe surface and
    /// by `apply_audit_erasure_receipt_dispatch`.
    pub erasure_receipts: Vec<ErasureReceiptRecord>,
    /// Registry-derived cell writes of the Event currently being reduced.
    ///
    /// The v1 Event wire carries no producer `effects[]`: every cell write is
    /// derived from `kind + payload` by the shared
    /// `arkret_schema::project_registered_cell_writes` contract evaluator and
    /// handed to the reducer here. It is transient per
    /// [`ProjectionState::apply_projected`] call and never part of the durable
    /// projection; a kind whose contract declares writes therefore fails closed
    /// when this is empty.
    projected_cell_writes: Vec<ProjectedCellWrite>,
}

impl ProjectionState {
    pub fn new() -> Self {
        Self::default()
    }

    /// The registry-projected cell writes for the Event under reduction.
    pub(crate) fn projected_cell_writes(&self) -> &[ProjectedCellWrite] {
        &self.projected_cell_writes
    }

    pub fn set_local_service_id(&mut self, service_id: impl Into<String>) {
        self.local_service_id = Some(service_id.into());
    }

    pub fn push_route_cell_value(&self, subject: &PushRouteSubject) -> Option<&PushRouteCellValue> {
        self.push_routes.get(subject)
    }

    pub(crate) fn queue_pending_replay(
        &mut self,
        target_ref: impl Into<String>,
        operation: &Operation,
        reason: impl Into<String>,
    ) -> ProjectionEffect {
        let target_ref = target_ref.into();
        let reason = reason.into();
        let operation_id = operation.operation_id.to_string();
        let queue = self.pending_replay.entry(target_ref.clone()).or_default();
        if !queue.iter().any(|entry| entry.operation_id == operation_id) {
            queue.push(PendingReplayEntry {
                target_ref: target_ref.clone(),
                reason: reason.clone(),
                operation_id: operation_id.clone(),
                operation: operation.clone(),
                cell_writes: self.projected_cell_writes.clone(),
                queued_at: operation.created_at,
            });
        }
        ProjectionEffect::PendingReplayQueued {
            target_ref,
            operation_id,
            reason,
        }
    }

    pub(crate) fn projected_ref_exists(&self, target_ref: &str) -> bool {
        if target_ref.starts_with("ak:grant:") {
            return self.effective_engine_grant(target_ref).is_some();
        }
        if target_ref.starts_with("ak:space:") {
            return self.space_containers.contains_key(target_ref);
        }
        if target_ref.starts_with("ak:strand:") {
            return self.strands.contains_key(target_ref);
        }
        if target_ref.starts_with("ak:morph:") {
            return self.morphs.contains_key(target_ref);
        }
        if target_ref.starts_with("ak:relation:") {
            return self.relations.contains_key(target_ref);
        }
        if arkret_identifiers::EventId::new(target_ref).is_ok()
            || arkret_identifiers::MessageId::new(target_ref).is_ok()
        {
            return self.message_by_target_ref(target_ref).is_some();
        }
        false
    }

    pub fn authz_resource_expr(&self, realm_id: &str, resource: &str) -> String {
        let mut resources = BTreeSet::new();
        for token in resource.split(',').map(str::trim) {
            if token.is_empty() {
                continue;
            }
            resources.insert(token.to_owned());
            self.append_space_hierarchy_authz_aliases(realm_id, token, &mut resources);
        }
        resources.into_iter().collect::<Vec<_>>().join(",")
    }

    fn append_space_hierarchy_authz_aliases(
        &self,
        realm_id: &str,
        resource: &str,
        resources: &mut BTreeSet<String>,
    ) {
        if !resource.starts_with("ak:space:") {
            return;
        }
        let Some(space) = self.space_containers.get(resource) else {
            return;
        };
        if space.realm_id != realm_id {
            return;
        }

        let mut cursor = resource.to_owned();
        let mut visited = BTreeSet::new();
        for depth in 0..64 {
            if !visited.insert(cursor.clone()) {
                break;
            }
            let Some(space) = self.space_containers.get(&cursor) else {
                break;
            };
            if space.realm_id != realm_id || space.parent_ref_locked {
                break;
            }
            let Some(parent_id) = space.parent_ref.as_deref() else {
                break;
            };
            let Some(parent) = self.space_containers.get(parent_id) else {
                break;
            };
            if parent.realm_id != realm_id {
                break;
            }
            if depth == 0 {
                resources.insert(format!("space_child_of:{parent_id}"));
            }
            resources.insert(format!("space_subtree_of:{parent_id}"));
            cursor = parent_id.to_owned();
        }
    }

    pub fn replay_resolved_pending(&mut self, hlc: &ServerHlc) -> usize {
        let mut replayed = 0usize;
        for _ in 0..128 {
            let ready_targets = self
                .pending_replay
                .keys()
                .filter(|target_ref| self.projected_ref_exists(target_ref))
                .cloned()
                .collect::<Vec<_>>();
            if ready_targets.is_empty() {
                break;
            }
            for target_ref in ready_targets {
                let Some(entries) = self.pending_replay.remove(&target_ref) else {
                    continue;
                };
                for entry in entries {
                    let restored =
                        std::mem::replace(&mut self.projected_cell_writes, entry.cell_writes);
                    let _ = self.apply_once(&entry.operation, hlc);
                    self.projected_cell_writes = restored;
                    replayed += 1;
                }
            }
        }
        replayed
    }

    pub(crate) fn apply_device_push_route(&mut self, operation: &Operation) -> ProjectionEffect {
        let payload = match serde_json::from_value::<
            arkret_models_identity::device_push_route::DevicePushRoutePayload,
        >(operation.payload.clone())
        {
            Ok(payload) => payload,
            Err(error) => {
                return ProjectionEffect::Rejected {
                    reason: format!("push_route_payload_invalid:{error}"),
                };
            }
        };
        let scope = payload.scope();
        let recipient_id = scope.account_id.station_id.as_str();
        if let Some(local_service_id) = self.local_service_id.as_deref()
            && local_service_id != recipient_id
        {
            return ProjectionEffect::Rejected {
                reason: "recipient_id_mismatch".to_owned(),
            };
        }
        let account_id = scope
            .account_id
            .canonical_key()
            .expect("validated AccountId has canonical JCS bytes");
        let actor_id =
            serde_json::to_value(arkret_wire::ActorId::account(scope.account_id.clone()))
                .expect("validated AccountId serializes as ActorId");
        let device_id = scope.device_id.as_str();
        let push_route = scope.push_route.as_str();

        let subject = PushRouteSubject {
            account_id: scope.account_id.clone(),
            device_id: device_id.to_owned(),
            push_route: push_route.to_owned(),
        };
        let private_registry = match arkret_lattice_registry::build_actor_private_registry() {
            Ok(registry) => registry,
            Err(error) => {
                return ProjectionEffect::Rejected {
                    reason: format!("push_route_private_registry_unavailable:{error}"),
                };
            }
        };
        let derived_subject = match private_registry.derive_subject(
            arkret_wire::EventKind::DevicePushRoute.as_str(),
            &actor_id,
            &operation.payload,
        ) {
            Ok(subject) => subject,
            Err(error) => {
                return ProjectionEffect::Rejected {
                    reason: format!("push_route_private_subject_invalid:{error}"),
                };
            }
        };
        let expected_subject =
            match arkret_wire::composite_subject(&[&account_id, device_id, push_route]) {
                Ok(subject) => subject,
                Err(error) => {
                    return ProjectionEffect::Rejected {
                        reason: format!("push_route_private_subject_invalid:{error}"),
                    };
                }
            };
        if derived_subject != expected_subject {
            return ProjectionEffect::Rejected {
                reason: "push_route_private_subject_mismatch".to_owned(),
            };
        }

        let expected_revision = payload.expected_revision();
        let incoming_revision = match expected_revision.checked_add(1) {
            Some(revision) => revision,
            None => {
                return ProjectionEffect::Rejected {
                    reason: "push_route_revision_overflow".to_owned(),
                };
            }
        };
        let incoming_value = serde_json::to_value(&payload)
            .expect("validated push-route payload remains serializable");
        let current = self.push_routes.get(&subject).map(|value| {
            arkret_lattice_registry::ActorPrivateCandidate {
                value: serde_json::json!({
                    "account_id": &subject.account_id,
                    "device_id": &subject.device_id,
                    "push_route": &subject.push_route,
                    "push_target_id": &value.push_target_id,
                    "push_gateway_id": &value.push_gateway_id,
                    "encryption_key": &value.encryption_key,
                    "capabilities": &value.capabilities,
                    "revoked": value.revoked,
                }),
                revision: Some(value.revision),
                expected_revision: None,
                causal_order: None,
                hlc: None,
                device_id: None,
            }
        });
        let incoming = arkret_lattice_registry::ActorPrivateCandidate {
            value: incoming_value,
            revision: Some(incoming_revision),
            expected_revision: Some(expected_revision),
            causal_order: None,
            hlc: None,
            device_id: None,
        };
        match private_registry.apply(
            "ak.private.device.push_route.v1",
            current.as_ref(),
            incoming,
        ) {
            Ok(
                arkret_lattice_registry::ActorPrivateMergeOutcome::Accepted(_)
                | arkret_lattice_registry::ActorPrivateMergeOutcome::Unchanged(_),
            ) => {}
            Ok(arkret_lattice_registry::ActorPrivateMergeOutcome::Conflict) => {
                return ProjectionEffect::Rejected {
                    reason: "push_route_cas_conflict".to_owned(),
                };
            }
            Err(error) => {
                return ProjectionEffect::Rejected {
                    reason: format!("push_route_private_merge_failed:{error}"),
                };
            }
        }

        match payload {
            arkret_models_identity::device_push_route::DevicePushRoutePayload::Revoked(_) => {
                self.store_push_route_cell(
                    subject.clone(),
                    PushRouteCellValue {
                        revision: incoming_revision,
                        push_target_id: None,
                        push_gateway_id: None,
                        encryption_key: None,
                        capabilities: Vec::new(),
                        revoked: true,
                    },
                );
                ProjectionEffect::PushRouteUpdated {
                    subject,
                    action: "revoked".to_owned(),
                }
            }
            arkret_models_identity::device_push_route::DevicePushRoutePayload::Active(active) => {
                let action = if self
                    .push_routes
                    .get(&subject)
                    .and_then(|value| value.push_target_id.as_deref())
                    .is_some_and(|previous| previous != active.push_target_id.as_str())
                {
                    "rotated"
                } else {
                    "active"
                };
                self.store_push_route_cell(
                    subject.clone(),
                    PushRouteCellValue {
                        revision: incoming_revision,
                        push_target_id: Some(active.push_target_id.into_string()),
                        push_gateway_id: Some(active.push_gateway_id.into_string()),
                        encryption_key: Some(active.encryption_key),
                        capabilities: active.capabilities,
                        revoked: false,
                    },
                );
                ProjectionEffect::PushRouteUpdated {
                    subject,
                    action: action.to_owned(),
                }
            }
        }
    }

    fn store_push_route_cell(&mut self, subject: PushRouteSubject, value: PushRouteCellValue) {
        // Actor-private routes are deliberately absent from `cells`: that map
        // feeds Realm CBA/Seal/state-root resolution. The recipient Station keeps this revision-CAS
        // value only in its private projection.
        self.push_routes.insert(subject, value);
    }

    /// Look up a cell's resolved state by its canonical [`CellRef`]. Returns
    /// `None` if the cell hasn't been observed (no sealed Move ever wrote
    /// to it). The returned `CellState` is either `Value(_)` (lattice
    /// resolved successfully) or `Bottom(_)` (concurrent conflict requires
    /// recovery).
    pub fn cell(&self, cell_id: &CellRef) -> Option<&CellState> {
        self.cells.get(cell_id)
    }

    /// Look up the JSON value stored in a cell. Returns `None` for absent
    /// cells AND for cells in `Bottom` state — callers that need to
    /// distinguish (e.g. UI showing "this state is in conflict") should
    /// use [`ProjectionState::cell`] directly.
    pub fn cell_value(&self, cell_id: &CellRef) -> Option<&Value> {
        match self.cells.get(cell_id)? {
            CellState::Value(v) => Some(v),
            CellState::Bottom(_) => None,
        }
    }

    /// Look up a cell's resolved state inside one Realm namespace.
    ///
    /// Null-subject singleton cells reuse the same wire [`CellRef`] across
    /// Realms, so they must be resolved through the Realm-partitioned caches
    /// rather than the process-wide `cells` map. Keeping the state-level
    /// lookup here also lets administrative readers expose `Bottom` instead
    /// of accidentally treating it as absent.
    pub fn realm_cell(&self, realm_id: &str, cell_id: &CellRef) -> Option<&CellState> {
        match cell_id.as_str() {
            arkret_wire::REALM_PROFILE_CELL => self.realm_profile_cells.get(realm_id),
            arkret_wire::REALM_CREATE_CELL => self.realm_create_cells.get(realm_id),
            arkret_wire::REALM_NOTARY_CELL => self.realm_notary_cells.get(realm_id),
            "ak:cell:ak.component.realm.policy_bundle.v1:null" => {
                self.realm_policy_bundle_cells.get(realm_id)
            }
            _ => {
                let realm_key = (realm_id.to_owned(), cell_id.as_str().to_owned());
                let realm_state = self.realm_null_subject_cells.get(&realm_key);
                let is_null_subject = arkret_wire::CellId::from_ref(cell_id)
                    .is_ok_and(|parsed| parsed.subject() == "null");
                if is_null_subject {
                    realm_state
                } else {
                    realm_state.or_else(|| self.cells.get(cell_id))
                }
            }
        }
    }

    /// Resolve a cell inside one Realm namespace. Canonical null-subject
    /// singleton cells share the same wire CellRef across Realms, so their
    /// process cache keeps the Realm id as a separate key dimension.
    pub fn realm_cell_value(&self, realm_id: &str, cell_id: &CellRef) -> Option<&Value> {
        match self.realm_cell(realm_id, cell_id)? {
            CellState::Value(value) => Some(value),
            CellState::Bottom(_) => None,
        }
    }

    /// event-and-patch.md §4.4 — a Control Move MAY carry `preconditions[]`;
    /// the reducer MUST evaluate every predicate against the current
    /// materialized head BEFORE applying any effect, and the whole Move MUST
    /// fail closed (`failed_precondition`) without partial application when
    /// any predicate does not hold.
    ///
    /// This evaluates the generic `head_eq` compare-and-swap predicate:
    /// each entry is `{ "cell_id": "<cell_ref>", "predicate": { "op": "head_eq",
    /// "value": { "<field-path>": <expected> } } }`. For a strand-fields cell
    /// (`ak.component.strand.fields.v1:<strand_id>`) the `fields.<key>` paths
    /// resolve against the materialized strand `fields`; for any other cell
    /// family the path resolves against the resolved cell JSON value. A
    /// mismatch — or a referenced cell / strand that is absent or in `Bottom`
    /// — fails the precondition so the Move does not apply.
    ///
    /// Returns `Ok(())` when there are no `preconditions[]`, when every
    /// predicate holds, or when a predicate carries an `op` this engine does
    /// not recognize (forward-compatible: unknown ops are not silently
    /// treated as satisfied for `head_eq`, but other op kinds are deferred to
    /// their dedicated reducer gates and ignored here).
    pub fn check_move_preconditions(&self, operation: &Operation) -> Result<(), &'static str> {
        for precondition in &operation.context.preconditions {
            if precondition.predicate.op != arkret_wire::cba::PredicateOp::HeadEq {
                continue;
            }
            let Some(expected) = precondition.predicate.value.as_ref() else {
                return Err("failed_precondition");
            };
            if !self.head_eq_holds(
                operation.realm_id.as_str(),
                precondition.cell_id.as_str(),
                expected,
            ) {
                return Err("failed_precondition");
            }
        }
        Ok(())
    }

    /// Compare `predicate.value` with the current cell head. Missing cells are
    /// the JSON null head used by genesis CAS writes.
    fn head_eq_holds(&self, realm_id: &str, cell_ref: &str, expected: &Value) -> bool {
        const MEMBER_STATE_FAMILY: &str = arkret_wire::CellFamilyId::MEMBER_STATE_V1;
        const STRAND_FIELDS_FAMILY: &str = arkret_wire::CellFamilyId::STRAND_METADATA_V1;
        // CellStore keys are `(realm_id, cell_ref)`. The structured membership
        // projection retains that Realm dimension, while the registered cell
        // subject is the digest of the complete tagged ActorId key.
        if let Some(actor_subject) = cell_ref
            .strip_prefix("ak:cell:")
            .and_then(|rest| rest.strip_prefix(MEMBER_STATE_FAMILY))
            .and_then(|rest| rest.strip_prefix(':'))
        {
            let member = self
                .members
                .iter()
                .find_map(|((stored_realm, actor_id), member)| {
                    if stored_realm != realm_id {
                        return None;
                    }
                    let actor = serde_json::from_str::<arkret_wire::ActorId>(actor_id).ok()?;
                    let actor_key = actor.canonical_key().ok()?;
                    let subject = arkret_wire::composite_subject(&[actor_key]).ok()?;
                    (subject == actor_subject).then_some(member)
                });
            let Some(member) = member else {
                return expected.is_null();
            };
            let observed = Value::String(member.state.clone());
            return Self::observed_head_eq(&observed, expected);
        }
        if let Some(strand_id) = cell_ref
            .strip_prefix("ak:cell:")
            .and_then(|rest| rest.strip_prefix(STRAND_FIELDS_FAMILY))
            .and_then(|rest| rest.strip_prefix(':'))
        {
            let Some(strand) = self.strands.get(strand_id) else {
                return expected.is_null();
            };
            let observed = Value::Object(
                strand
                    .fields
                    .iter()
                    .map(|(key, value)| (key.clone(), value.clone()))
                    .collect(),
            );
            return Self::observed_head_eq(&observed, expected)
                || expected.as_object().is_some_and(|paths| {
                    !paths.is_empty()
                        && paths.iter().all(|(path, want)| {
                            let key = path.strip_prefix("fields.").unwrap_or(path);
                            strand.fields.get(key) == Some(want)
                        })
                });
        }
        let Ok(cell_id) = CellRef::new(cell_ref.to_owned()) else {
            return false;
        };
        let Some(value) = self.realm_cell_value(realm_id, &cell_id) else {
            return expected.is_null();
        };
        if Self::observed_head_eq(value, expected) {
            return true;
        }
        expected
            .as_object()
            .is_some_and(|paths| !paths.is_empty() && Self::field_path_head_eq_holds(value, paths))
    }

    fn observed_head_eq(observed: &Value, expected: &Value) -> bool {
        observed == expected || observed.get("head") == Some(expected)
    }

    fn field_path_head_eq_holds(
        observed: &Value,
        expected: &serde_json::Map<String, Value>,
    ) -> bool {
        expected.iter().all(|(path, want)| {
            let resolved = path
                .split('.')
                .try_fold(observed, |current, segment| current.get(segment));
            resolved == Some(want)
        })
    }

    pub fn child_order_cell_value(&self, parent_space_id: &str) -> Value {
        let mut children = self
            .space_containers
            .values()
            .filter(|container| container.parent_ref.as_deref() == Some(parent_space_id))
            .filter(|container| container.state == SpaceContainerLifecycleState::Active)
            .collect::<Vec<_>>();
        children.sort_by(|left, right| {
            left.rank
                .cmp(&right.rank)
                .then(left.title.cmp(&right.title))
                .then(left.container_space_id.cmp(&right.container_space_id))
        });
        let order = children
            .iter()
            .map(|container| container.container_space_id.clone())
            .collect::<Vec<_>>();
        let entries = children
            .iter()
            .enumerate()
            .map(|(index, container)| {
                serde_json::json!({
                    "index": index,
                    "space_id": container.container_space_id,
                    "realm_id": container.realm_id,
                    "kind": container.kind,
                    "title": container.title,
                    "rank": container.rank,
                    "state": container.state.as_str(),
                })
            })
            .collect::<Vec<_>>();
        serde_json::json!({
            "schema": CHILD_ORDER_CELL_FAMILY,
            "parent_space_id": parent_space_id,
            "order": order,
            "children": entries,
        })
    }

    pub(crate) fn store_strand_position_relation(
        &mut self,
        strand_id: &str,
        realm_id: &str,
        board_space_id: &str,
        list_space_id: &str,
        rank: Option<&str>,
        now: chrono::DateTime<chrono::Utc>,
    ) {
        let relation_id = format!("ak:relation:kanban.position:{board_space_id}:{strand_id}");
        let scope_circle_id = self
            .strand_scope_circle_id(strand_id)
            .or_else(|| self.space_container_scope_circle_id(list_space_id));
        let relation = self
            .relations
            .entry(relation_id.clone())
            .or_insert_with(|| SolandRelationState {
                relation_id: relation_id.clone(),
                realm_id: realm_id.to_owned(),
                relation_kind: "contains".to_owned(),
                scope_circle_id: scope_circle_id.clone(),
                from_ref: Some(list_space_id.into()),
                to_ref: Some(strand_id.into()),
                fields: BTreeMap::new(),
                state: "active".to_owned(),
                source_event_id: None,
                source_event_digest: None,
                created_at: now,
                history_basis_seals: Vec::new(),
                updated_at: now,
            });
        relation.realm_id = realm_id.to_owned();
        relation.relation_kind = "contains".to_owned();
        relation.scope_circle_id = scope_circle_id;
        relation.from_ref = Some(list_space_id.into());
        relation.to_ref = Some(strand_id.into());
        relation.fields.insert(
            "board_space_id".to_owned(),
            Value::String(board_space_id.to_owned()),
        );
        relation.fields.insert(
            "list_space_id".to_owned(),
            Value::String(list_space_id.to_owned()),
        );
        if let Some(rank) = rank {
            relation
                .fields
                .insert("rank".to_owned(), Value::String(rank.to_owned()));
        }
        relation.state = "active".to_owned();
        relation.updated_at = now;
    }

    /// Reload the cells map for one Realm from the SDK CellStore + apply
    /// each cell's lattice. Called after every successful `apply_seal`
    /// in the peer-event/notary pipeline to keep this projection cache in sync
    /// with sealed cell state.
    ///
    /// This replaces the inline accepted-Event cache with the authoritative
    /// sealed view after `apply_seal`. The durable-Event path may stage the
    /// same cell families before sealing, but correctness after finalization
    /// comes from this reload.
    pub fn reload_cells_from_store(
        &mut self,
        realm_id: &RealmId,
        cell_store: &dyn CellStore,
        cell_registry: &dyn CellRegistry,
    ) -> Result<(), StoreError> {
        let mut resolved_cells = Vec::new();
        for cell in cell_store.list_cells(realm_id)? {
            let ops = cell_store.sealed_ops_for_cell(realm_id, &cell)?;
            let binding = cell_registry
                .resolve(realm_id, &cell)
                .map_err(|e| StoreError::Backend(format!("cell registry resolve: {e}")))?;
            let resolved = arkret_state::join_cell(binding.lattice.as_ref(), &cell, &ops);
            resolved_cells.push((cell, resolved));
        }
        self.install_reloaded_cells(realm_id, resolved_cells);
        Ok(())
    }

    /// Install already-resolved sealed cell values for one Realm.
    ///
    /// Keeping installation separate lets service adapters perform durable
    /// store I/O before they acquire the projection-state mutex.
    pub fn install_reloaded_cells(
        &mut self,
        realm_id: &RealmId,
        resolved_cells: impl IntoIterator<Item = (CellRef, CellState)>,
    ) {
        for (cell, resolved) in resolved_cells {
            match cell.as_str() {
                arkret_wire::REALM_PROFILE_CELL => {
                    self.realm_profile_cells
                        .insert(realm_id.to_string(), resolved);
                }
                arkret_wire::REALM_CREATE_CELL => {
                    self.realm_create_cells
                        .insert(realm_id.to_string(), resolved);
                }
                arkret_wire::REALM_NOTARY_CELL => {
                    self.realm_notary_cells
                        .insert(realm_id.to_string(), resolved);
                }
                "ak:cell:ak.component.realm.policy_bundle.v1:null" => {
                    self.realm_policy_bundle_cells
                        .insert(realm_id.to_string(), resolved);
                }
                _ if cell.as_str().ends_with(":null") => {
                    self.realm_null_subject_cells
                        .insert((realm_id.to_string(), cell.as_str().to_owned()), resolved);
                }
                _ => {
                    self.cells.insert(cell, resolved);
                }
            }
        }
    }

    /// Apply a single operation and return the effect.
    ///
    /// Per-kind dispatch strands through [`APPLY_REGISTRY`] — a static
    /// `HashMap<canonical_kind, ApplyFn>` built by
    /// [`default_apply_registry`]. This replaced a 30-arm `match` that
    /// directly delegated to `ProjectionState::apply_*` helpers; the
    /// dispatch table is now data, the helpers are the same, and adding
    /// a new event_kind only touches the registry builder + one adapter.
    ///
    /// Tolerance for unknown kinds is preserved: a miss in the registry
    /// returns `ProjectionEffect::Ignored` (same as the old wildcard
    /// arm). Durable-event projection's lattice-registry probe
    /// (`apply_via_lattice_registry`) still fails closed for unknown
    /// canonical kinds — the registry miss path here is the
    /// "cell-state-only event reached the inline cache by mistake"
    /// branch.
    ///
    /// All cell-state events (ak.realm.policy / ak.realm.read_receipt_policy /
    /// ak.consent.* / ak.member.state / ak.realm.* facets) are routed via
    /// the Move/Seal pipeline through `LatticeKind` impls in
    /// `lattice_kinds.rs`; the structured ProjectionState fields don't
    /// mirror them. `routing/projection.rs::project_read_receipt_policy`
    /// handles the read-receipt cache fast path explicitly.
    fn apply_once(&mut self, operation: &Operation, hlc: &ServerHlc) -> ProjectionEffect {
        let Some(kind) = crate::kinds::canonical_kind_for_operation(operation) else {
            return ProjectionEffect::Rejected {
                reason: "unknown_event_kind".to_owned(),
            };
        };
        match APPLY_REGISTRY.get(&kind) {
            Some(dispatch) => dispatch(self, operation, hlc),
            None if !kind.is_reducer_input() => ProjectionEffect::Ignored,
            None => ProjectionEffect::Rejected {
                reason: "unregistered_reducer_event_kind".to_owned(),
            },
        }
    }

    /// Apply accepted Events that intentionally sit outside the shared Realm
    /// reducer registry. These projections are local/private read models and
    /// therefore must not make a `reducer_input=false` kind advance the Realm
    /// frontier merely to keep the local cache alive.
    fn apply_non_reducer_event(
        &mut self,
        kind: arkret_wire::EventKind,
        operation: &Operation,
    ) -> ProjectionEffect {
        match kind {
            arkret_wire::EventKind::ReadCursorAdvance => {
                self.apply_read_cursor(operation, operation.created_at)
            }
            arkret_wire::EventKind::DevicePushRoute => self.apply_device_push_route(operation),
            arkret_wire::EventKind::AgentActionRequest => {
                self.apply_agent_action_request(operation)
            }
            arkret_wire::EventKind::AgentActionApprove => {
                self.apply_agent_action_resolution(operation, AgentActionRequestStatus::Approved)
            }
            arkret_wire::EventKind::AgentActionReject => {
                self.apply_agent_action_resolution(operation, AgentActionRequestStatus::Rejected)
            }
            arkret_wire::EventKind::AuditErasureReceipt => {
                self.apply_audit_erasure_receipt(operation, operation.created_at)
            }
            _ => ProjectionEffect::Ignored,
        }
    }

    /// Reduce one Operation whose Event contract declares no cell write.
    ///
    /// Kinds that do declare writes reject with `reducer_projection_failed`
    /// here; the caller must use [`Self::apply_projected`] with the registry
    /// projection of the signed Event.
    pub fn apply(&mut self, operation: &Operation, hlc: &ServerHlc) -> ProjectionEffect {
        let Some(kind) = crate::kinds::canonical_kind_for_operation(operation) else {
            return ProjectionEffect::Rejected {
                reason: "unknown_event_kind".to_owned(),
            };
        };
        if !kind.is_reducer_input() {
            return self.apply_non_reducer_event(kind, operation);
        }
        self.apply_projected(operation, &[], hlc)
    }

    /// Reduce one Operation together with the registry-derived cell writes of
    /// its signed Event (`arkret_schema::project_registered_cell_writes`).
    pub fn apply_projected(
        &mut self,
        operation: &Operation,
        cell_writes: &[ProjectedCellWrite],
        hlc: &ServerHlc,
    ) -> ProjectionEffect {
        let restored = std::mem::replace(&mut self.projected_cell_writes, cell_writes.to_vec());
        let effect = self.apply_once(operation, hlc);
        self.projected_cell_writes = restored;
        self.replay_resolved_pending(hlc);
        effect
    }

    /// Probe the supplied [`LatticeRegistry`] for a `cell_family` that
    /// handles this Operation's canonical kind via `event_kinds()`.
    ///
    /// Behaviour:
    /// - **Hit on a cell-family impl**: routes through the inline `apply_*` helpers (the helpers
    ///   ARE the projection — the registry only validates that the spec maps this event_kind to a
    ///   known cell family, then we trust the inline dispatcher to handle the per-domain effect).
    /// - **No mapping in registry but a known canonical kind**: the kind is durable-Event-only
    ///   (`ak.message.*` / `ak.reaction.*` etc.); fall through to inline `apply()` exactly as
    ///   before. No log noise.
    /// - **Unknown canonical kind**: spec compliance requires us to fail closed — log at `error`
    ///   level and return an observable [`ProjectionEffect::Rejected`].
    pub fn apply_via_lattice_registry(
        &mut self,
        operation: &Operation,
        cell_writes: &[ProjectedCellWrite],
        hlc: &ServerHlc,
        registry: &arkret_lattice_registry::LatticeRegistry,
    ) -> ProjectionEffect {
        let kind = match crate::kinds::canonical_kind_for_operation(operation) {
            Some(k) => k,
            None => {
                tracing::error!(
                    event_kind = %operation.event_kind,
                    operation_id = %operation.operation_id,
                    "lattice registry dispatch: unknown canonical kind for operation; \
                     dropping with bottom (reject)"
                );
                return ProjectionEffect::Rejected {
                    reason: "unknown_event_kind".to_owned(),
                };
            }
        };
        if registry
            .lookups_for_event_kind(kind.as_str())
            .next()
            .is_some()
        {
            // Canonical hit — log at trace + delegate to inline helpers.
            // The inline helpers and the LatticeRegistry-resolved cell
            // family agree by construction (this whole module has one
            // canonical match arm; the registry just declares which
            // event kinds it owns).
            tracing::trace!(
                event_kind = %kind,
                "lattice registry dispatch: routed through LatticeRegistry"
            );
            self.apply_projected(operation, cell_writes, hlc)
        } else {
            // No cell-family implementation is registered for this kind, but
            // the Event registry may still declare cell writes consumed by an
            // inline reducer (for example `ak.call.create`). Preserve the
            // receiver-derived writes here; dropping them through `apply()`
            // turns a valid reducer input into an empty projection.
            self.apply_projected(operation, cell_writes, hlc)
        }
    }

    // ── Strand / Morph projection state machine ──

    /// Read-only state-machine preflight for a `ak.strand.*` lifecycle event.
    /// Mirror of `check_space_container_lifecycle_transition` — used by
    /// `event_log::submit_event` to short-circuit HTTP admission with 412
    /// failed_precondition. Unknown Strand returns `Ok` (causal/backfill
    /// tolerance per common-fields.md §5.1).
    pub fn check_strand_lifecycle_transition(
        &self,
        operation: &Operation,
    ) -> Result<(), &'static str> {
        let kind = match crate::kinds::canonical_kind_for_operation(operation) {
            Some(k) => k,
            None => return Ok(()),
        };
        // `ak.strand.create` is unconditional (no current state to validate).
        // `ak.strand.update` requires Active source.
        // `ak.strand.archive` requires Active source.
        // `ak.strand.restore` requires Archived source.
        let (allowed_source, reason): (&[ObjectLifecycleState], &'static str) = match &kind {
            arkret_wire::EventKind::StrandCreate => return Ok(()),
            arkret_wire::EventKind::StrandUpdate => {
                (&[ObjectLifecycleState::Active], "strand_not_active")
            }
            arkret_wire::EventKind::StrandArchive => {
                (&[ObjectLifecycleState::Active], "strand_not_active")
            }
            arkret_wire::EventKind::StrandRestore => {
                (&[ObjectLifecycleState::Archived], "strand_not_archived")
            }
            _ => return Ok(()),
        };
        let strand_id = match kind {
            arkret_wire::EventKind::StrandUpdate => strand_id_from_payload(&operation.payload),
            arkret_wire::EventKind::StrandArchive | arkret_wire::EventKind::StrandRestore => {
                operation
                    .payload
                    .get("target_ref")
                    .and_then(Value::as_str)
                    .filter(|value| value.starts_with("ak:strand:"))
            }
            _ => None,
        };
        let Some(strand_id) = strand_id else {
            // Missing strand_id is caught upstream by the operation-schema
            // validator; preflight tolerates absence to keep responsibilities
            // separate.
            return Ok(());
        };
        let Some(strand) = self.strands.get(strand_id) else {
            return Ok(());
        };
        if !allowed_source.contains(&strand.state) {
            return Err(reason);
        }
        Ok(())
    }

    /// Read-only preflight for profile-level Strand status FSM stored at
    /// `fields.status`. This guards common workflow statuses while leaving
    /// unknown/custom statuses to Realm profiles.
    pub fn check_strand_status_transition(
        &self,
        operation: &Operation,
    ) -> Result<(), &'static str> {
        if crate::kinds::canonical_kind_for_operation(operation)
            != Some(arkret_wire::EventKind::StrandUpdate)
        {
            return Ok(());
        }
        let Some(strand_id) = strand_id_from_payload(&operation.payload) else {
            return Ok(());
        };
        let Some(strand) = self.strands.get(strand_id) else {
            return Ok(());
        };
        check_strand_status_patch(strand, &operation.payload).map(|_| ())
    }

    /// Return the audit payload for an accepted Strand `fields.status`
    /// transition. Callers invoke this before projection is applied so
    /// `from` is read from the current reducer state.
    pub fn strand_status_transition_audit_payload(
        &self,
        operation: &Operation,
        actor_id: &str,
    ) -> Option<Value> {
        if crate::kinds::canonical_kind_for_operation(operation)
            != Some(arkret_wire::EventKind::StrandUpdate)
        {
            return None;
        }
        let strand_id = strand_id_from_payload(&operation.payload)?;
        let strand = self.strands.get(strand_id)?;
        let next_status = strand_status_patch_target(&operation.payload)
            .ok()
            .flatten()?;
        let current_status = strand.fields.get("status").and_then(Value::as_str)?;
        if current_status == next_status {
            return None;
        }
        Some(serde_json::json!({
            "actor": actor_id,
            "strand_id": strand_id,
            "incident_id": strand_id,
            "realm_id": strand.realm_id,
            "from": current_status,
            "to": next_status,
            "timestamp": arkret_canonical::format_timestamp_canonical(
                operation.created_at
            ),
            "kind": "incident.status.transition",
        }))
    }

    /// Read-only preflight for `ak.redaction` events that
    /// target a Strand / Morph via `object_ref`. Per spec common-fields.md
    /// §5.1, redaction is legal only from `active` or `archived` source;
    /// terminal source MUST `failed_precondition` with
    /// `<kind>_already_terminal`. Unknown object tolerated (causal /
    /// backfill window). Space containers are excluded — spec routes their
    /// removal through `ak.space.tombstone` only.
    pub fn check_redaction_target_transition(
        &self,
        operation: &Operation,
    ) -> Result<(), &'static str> {
        if crate::kinds::canonical_kind_for_operation(operation)
            != Some(arkret_wire::EventKind::Redaction)
        {
            return Ok(());
        }
        let Some(object_ref) = redaction_object_ref(operation) else {
            return Ok(());
        };
        if let Some(strand) = self.strands.get(&object_ref) {
            if strand.state.is_terminal() {
                return Err("strand_already_terminal");
            }
            return Ok(());
        }
        if let Some(morph) = self.morphs.get(&object_ref) {
            if morph.state.is_terminal() {
                return Err("morph_already_terminal");
            }
            return Ok(());
        }
        Ok(())
    }

    /// Read-only state-machine preflight for a `ak.morph.*` lifecycle event.
    /// Same shape as `check_strand_lifecycle_transition`.
    pub fn check_morph_lifecycle_transition(
        &self,
        operation: &Operation,
    ) -> Result<(), &'static str> {
        let kind = match crate::kinds::canonical_kind_for_operation(operation) {
            Some(k) => k,
            None => return Ok(()),
        };
        let (allowed_source, reason): (&[ObjectLifecycleState], &'static str) = match kind {
            arkret_wire::EventKind::MorphCreate => return Ok(()),
            arkret_wire::EventKind::MorphUpdate => {
                (&[ObjectLifecycleState::Active], "morph_not_active")
            }
            arkret_wire::EventKind::MorphArchive => {
                (&[ObjectLifecycleState::Active], "morph_not_active")
            }
            arkret_wire::EventKind::MorphRestore => {
                (&[ObjectLifecycleState::Archived], "morph_not_archived")
            }
            _ => return Ok(()),
        };
        let Some(morph_id) = operation.payload.get("target_ref").and_then(|v| v.as_str()) else {
            return Ok(());
        };
        let Some(morph) = self.morphs.get(morph_id) else {
            return Ok(());
        };
        if !allowed_source.contains(&morph.state) {
            return Err(reason);
        }
        Ok(())
    }

    /// Whether the Realm declared `ak.profile.principal_control_realm.v1`.
    ///
    /// PCR and Agent control Realms permanently pin history access to
    /// `since_join`.
    pub fn realm_is_principal_control(&self, realm_id: &str) -> bool {
        self.realm_schema_refs(realm_id)
            .iter()
            .any(|profile| profile == ProfileId::PRINCIPAL_CONTROL_REALM_V1)
    }

    /// Whether this explicitly selected Realm is a principal-control Realm
    /// owned by `principal_id`.
    ///
    /// This is intentionally scoped to one Realm and principal. The complete
    /// account identity is the `(principal_id, station_id)` pair; on
    /// its Station that pair owns one lifetime-local PCR lineage.
    pub fn realm_is_principal_control_for_actor(&self, realm_id: &str, principal_id: &str) -> bool {
        self.realm_states.get(realm_id).is_some_and(|realm| {
            realm.owner.as_deref() == Some(principal_id)
                && self
                    .realm_schema_refs(realm_id)
                    .iter()
                    .any(|profile| profile == ProfileId::PRINCIPAL_CONTROL_REALM_V1)
        })
    }
}
