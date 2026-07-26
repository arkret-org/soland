//! The core [`ProjectionState`] struct and its inline `impl` (cell
//! helpers, push-route apply, dispatch entry points, and Strand / Morph
//! state-machine preflights).
//!
//! Split out of the `reducer` mod file; re-exported there so the
//! `crate::reducer::ProjectionState` path and sibling `super::*` access
//! stay unchanged. Additional `impl ProjectionState` blocks live in the
//! `apply_*` sibling modules.

use std::collections::{BTreeMap, BTreeSet};

use arkret_event_draft::Operation;
use arkret_identifiers::{CellRef, RealmId};
use arkret_models_collaboration::agent_operations::AgentLifecycleState;
use arkret_state::lattice::CellState;
use arkret_state::state::{CellRegistry, CellStore, StoreError};
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
    /// Calendar RSVP projection keyed by `(event_ref, occurrence, actor_id)`.
    /// The event has no spec-declared cell family; this is a durable-event
    /// side-band cache for agenda/detail views.
    pub rsvps: BTreeMap<(String, String, String), RsvpProjection>,
    /// Shared pin projection keyed by `(pin_scope_key, target_ref)`.
    /// Saved items remain holder-private account-data and never enter this
    /// shared Realm cache.
    pub pins: BTreeMap<(String, String), PinProjection>,
    /// Read markers keyed by (realm_id, actor, scope_id). LWW.
    pub read_cursors: BTreeMap<(String, String, String), ReadMarkerState>,
    /// Disappearing-message read-trigger anchors keyed by message event_id.
    /// The projection stores only the accepted aggregate anchor, never the
    /// reader identities exposed on wire.
    pub message_expiry_anchors: BTreeMap<String, MessageExpiryAnchor>,
    /// Private reducer-side contribution set for read-trigger aggregation.
    /// This is used to make duplicate read delivery idempotent and to decide
    /// when `on_last_read` has reached the active Realm member set.
    pub message_expiry_readers: BTreeMap<String, BTreeSet<String>>,
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
    /// fast-lookup index over the parallel [`Self::redaction_cells`] map
    /// — entries sit here whenever the parallel cell is `Some(_)` and are
    /// removed when the cas-register is set back to null (un-redaction).
    pub redactions: BTreeSet<String>,
    /// Parallel `redaction` cells keyed by the target
    /// event_id (subject). Each value is a [`RedactionCellValue`] holding
    /// `{redacted_at, by, reason}` per the spec, or `None` after an
    /// un-redaction. The original message entry in [`Self::messages`] is
    /// left intact so the ordered-log historical entry id is preserved;
    /// the projection layer consults this map at read time and replaces
    /// the payload with the tombstone.
    pub redaction_cells: BTreeMap<String, Option<RedactionCellValue>>,
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
    ///   - `realm_states` (mixed: ordered-log + cas-register) — kept as structured `realm_states`
    ///     side-band cache (server-side `created_at`/`updated_at`/`deleted` flag) BUT every
    ///     `apply_realm_lifecycle` now also writes one of: `ak.component.realm.create.v1`
    ///     (ordered-log, append) / `ak.component.realm.metadata.v1` (cas-register, latest
    ///     metadata) / `ak.component.realm.destroy.v1` (cas-register, terminal). Helpers:
    ///     `realm_create_log` / `realm_metadata_cell_value` / `realm_is_destroyed` query cells
    ///     directly. Durable-event-only fields (`messages` / `reactions` / `read_cursors` /
    ///     `relations` / `redactions`) stay structured per spec (those event kinds have no
    ///     `cell_family` declaration).
    pub cells: BTreeMap<CellRef, CellState>,
    /// Realm-scoped resolved values for the three protocol cell families
    /// whose canonical subject is the literal `null`. The Realm id belongs
    /// to the CellStore namespace, not the wire cell id, so these values
    /// cannot safely share the global `cells` map.
    pub realm_metadata_cells: BTreeMap<String, CellState>,
    pub realm_create_cells: BTreeMap<String, CellState>,
    pub realm_notary_cells: BTreeMap<String, CellState>,
    pub realm_policy_components_cells: BTreeMap<String, CellState>,
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
    /// (`ak:circle:<uuid>`); membership and parent-Realm binding live in
    /// the struct so the wire layer can enforce
    /// `Circle.members ⊆ Realm.members` without an extra DB hop.
    pub circles: BTreeMap<String, CircleProjection>,
    /// First-class Sidecars keyed by `sidecar_id`.
    pub sidecars: BTreeMap<String, SidecarProjection>,
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
    /// Server-side Applet registry projection, keyed by `service_id`
    /// (the canonical applet identity per spec
    /// `extensions/applet-integration.md`). Populated by
    /// `ak.applet.registration` (initial registration / re-registration)
    /// and updated by `ak.applet.discovery` (manifest refresh). Used by
    /// `GET /_soland/admin/applets` admin snapshot. Runtime-private applet
    /// session progress is not a durable Arkret event and is not mirrored here.
    pub applets: BTreeMap<String, AppletProjection>,
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
        BTreeMap<(String, String, String), RealmOrganizationStatementState>,
    /// G3.S1 — published MLS KeyPackages keyed by `keypackage_id`. Each
    /// row is per `(actor_id, device_id)`; the `claimed_by` / claim-window
    /// slots flip on a successful CAS claim.
    pub mls_key_packages: BTreeMap<String, MlsKeyPackage>,
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
    /// G3.S2 — per-Realm `ak.realm.policy_server` projection. Cas-
    /// register semantics — last write wins. Org-level fallback (when
    /// a Realm has no row of its own) is resolved at query time by
    /// walking the `governed_by` link chain via [`Self::realm_links`].
    /// Cell-family canonical value lives in
    /// `ak.component.realm.policy_server.v1`.
    pub realm_policy_servers: BTreeMap<String, RealmPolicyServerConfig>,
    /// Device push-route projection keyed by the protocol composite
    /// `(recipient_service_id, principal_id, device_id, push_route)`.
    /// These are actor-private state cells and MUST stay isolated per
    /// recipient Principal Server.
    pub push_routes: BTreeMap<PushRouteSubject, PushRouteCellValue>,
    /// Optional local Principal/Sync service DID. When set, incoming
    /// `ak.device.push_route` writes whose `recipient_service_id` does
    /// not match this service are rejected instead of cached.
    pub local_service_id: Option<String>,
    /// Stream-F (Wave 1B) — `ak.audit.erasure_receipt` projection.
    /// Append-only list of receipts the reducer has accepted. Spec
    /// `realm-and-space.md` §2.5.2 + erasure-receipt.schema.json.
    /// Receipts are durable events; the projection cache here is used
    /// by the `erasure_receipts_endpoint` server-describe surface and
    /// by `apply_audit_erasure_receipt_dispatch`.
    pub erasure_receipts: Vec<ErasureReceiptRecord>,
    /// Rebuildable mirror of profile-private join-application records, keyed
    /// by `(realm_id, application_receipt_digest)`. The durable private store,
    /// not shared Event history, owns application/review/cancel receipts and
    /// bodies.
    pub member_applications: BTreeMap<(String, String), MemberApplicationState>,
    /// Per-`(realm_id, applicant_did)` reject cooldown anchor. Spec
    /// `governance/join-policy.md` §3 `cooldown_after_reject` / §12:
    /// after a review reject the reducer MUST refuse a fresh
    /// `member.application` from the same actor until the window elapses.
    /// Distinct from the `cooldown` deny gate (which keys off the last
    /// `leave`); this keys off the last review `reject`.
    pub member_application_reject_at: BTreeMap<(String, String), chrono::DateTime<chrono::Utc>>,
}

impl ProjectionState {
    pub fn new() -> Self {
        Self::default()
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
        if target_ref.starts_with("ak:event:") || target_ref.starts_with("ak:message:") {
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
                    let _ = self.apply_once(&entry.operation, hlc);
                    replayed += 1;
                }
            }
        }
        replayed
    }

    pub(crate) fn apply_device_push_route(&mut self, operation: &Operation) -> ProjectionEffect {
        let Some(payload) = operation.payload.as_object() else {
            return ProjectionEffect::Rejected {
                reason: "push_route_payload_not_object".to_owned(),
            };
        };
        let Some(recipient_service_id) =
            payload.get("recipient_service_id").and_then(Value::as_str)
        else {
            return ProjectionEffect::Rejected {
                reason: "push_route_missing_recipient_service_id".to_owned(),
            };
        };
        if let Some(local_service_id) = self.local_service_id.as_deref()
            && local_service_id != recipient_service_id
        {
            return ProjectionEffect::Rejected {
                reason: "recipient_service_id_mismatch".to_owned(),
            };
        }
        let Some(principal_id) = payload.get("principal_id").and_then(Value::as_str) else {
            return ProjectionEffect::Rejected {
                reason: "push_route_missing_principal_id".to_owned(),
            };
        };
        let Some(device_id) = payload.get("device_id").and_then(Value::as_str) else {
            return ProjectionEffect::Rejected {
                reason: "push_route_missing_device_id".to_owned(),
            };
        };
        let Some(push_route) = payload.get("push_route").and_then(Value::as_str) else {
            return ProjectionEffect::Rejected {
                reason: "push_route_missing_push_route".to_owned(),
            };
        };

        let subject = PushRouteSubject {
            recipient_service_id: recipient_service_id.to_owned(),
            principal_id: principal_id.to_owned(),
            device_id: device_id.to_owned(),
            push_route: push_route.to_owned(),
        };

        let revoked = payload
            .get("revoked")
            .and_then(Value::as_bool)
            .unwrap_or(false);

        if revoked {
            let mut previous = self
                .push_routes
                .get(&subject)
                .cloned()
                .unwrap_or_else(empty_push_route_cell);
            if let Some(target) = previous.push_target_id.take()
                && !previous.revoked_targets.contains(&target)
            {
                previous.revoked_targets.push(target);
            }
            if let Some(target) = payload.get("push_target_id").and_then(Value::as_str)
                && !previous
                    .revoked_targets
                    .iter()
                    .any(|existing| existing == target)
            {
                previous.revoked_targets.push(target.to_owned());
            }
            previous.push_gateway_did = None;
            previous.encryption_key = None;
            previous.capabilities.clear();
            previous.revoked = true;
            self.store_push_route_cell(subject.clone(), previous);
            return ProjectionEffect::PushRouteUpdated {
                subject,
                action: "revoked".to_owned(),
            };
        }

        let Some(push_target_id) = payload.get("push_target_id").and_then(Value::as_str) else {
            return ProjectionEffect::Rejected {
                reason: "push_route_active_missing_push_target_id".to_owned(),
            };
        };
        let Some(push_gateway_did) = payload.get("push_gateway_did").and_then(Value::as_str) else {
            return ProjectionEffect::Rejected {
                reason: "push_route_active_missing_push_gateway_did".to_owned(),
            };
        };
        let capabilities = payload
            .get("capabilities")
            .and_then(Value::as_array)
            .map(|values| {
                values
                    .iter()
                    .filter_map(Value::as_str)
                    .map(ToOwned::to_owned)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let encryption_key = payload
            .get("encryption_key")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned);

        let mut next = self
            .push_routes
            .get(&subject)
            .cloned()
            .unwrap_or_else(empty_push_route_cell);
        let mut action = "active";
        if let Some(previous_target) = next.push_target_id.as_deref()
            && previous_target != push_target_id
        {
            action = "rotated";
            let previous_target = previous_target.to_owned();
            if !next.revoked_targets.contains(&previous_target) {
                next.revoked_targets.push(previous_target);
            }
        }
        next.push_target_id = Some(push_target_id.to_owned());
        next.push_gateway_did = Some(push_gateway_did.to_owned());
        next.encryption_key = encryption_key;
        next.capabilities = capabilities;
        next.revoked = false;
        self.store_push_route_cell(subject.clone(), next);

        ProjectionEffect::PushRouteUpdated {
            subject,
            action: action.to_owned(),
        }
    }

    fn store_push_route_cell(&mut self, subject: PushRouteSubject, value: PushRouteCellValue) {
        if let Some(cell_ref) = push_route_cell_ref(&subject) {
            self.cells.insert(
                cell_ref,
                CellState::Value(serde_json::json!({
                    "recipient_service_id": &subject.recipient_service_id,
                    "principal_id": &subject.principal_id,
                    "device_id": &subject.device_id,
                    "push_route": &subject.push_route,
                    "push_target_id": &value.push_target_id,
                    "push_gateway_did": &value.push_gateway_did,
                    "encryption_key": &value.encryption_key,
                    "capabilities": &value.capabilities,
                    "revoked": value.revoked,
                    "revoked_targets": &value.revoked_targets,
                })),
            );
        }
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

    /// Resolve a cell inside one Realm namespace. Canonical null-subject
    /// singleton cells share the same wire CellRef across Realms, so their
    /// process cache keeps the Realm id as a separate key dimension.
    pub fn realm_cell_value(&self, realm_id: &str, cell_id: &CellRef) -> Option<&Value> {
        let realm_key = (realm_id.to_owned(), cell_id.as_str().to_owned());
        let state = self
            .realm_null_subject_cells
            .get(&realm_key)
            .or_else(|| self.cells.get(cell_id))?;
        match state {
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
    /// each entry is `{ "cell": "<cell_ref>", "predicate": { "op": "head_eq",
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
        let Some(preconditions) = operation
            .payload
            .get("preconditions")
            .and_then(Value::as_array)
        else {
            return Ok(());
        };
        for precondition in preconditions {
            let Some(predicate) = precondition.get("predicate") else {
                continue;
            };
            let op = predicate.get("op").and_then(Value::as_str);
            if op != Some("head_eq") {
                continue;
            }
            let Some(cell_ref) = precondition.get("cell").and_then(Value::as_str) else {
                return Err("failed_precondition");
            };
            let Some(expected) = predicate.get("value") else {
                return Err("failed_precondition");
            };
            if !self.head_eq_holds(operation.realm_id.as_str(), cell_ref, expected) {
                return Err("failed_precondition");
            }
        }
        Ok(())
    }

    /// Compare `predicate.value` with the current cell head. Missing cells are
    /// the JSON null head used by genesis CAS writes.
    fn head_eq_holds(&self, realm_id: &str, cell_ref: &str, expected: &Value) -> bool {
        const MEMBER_STATE_FAMILY: &str = "ak.component.member.state.v1";
        const STRAND_FIELDS_FAMILY: &str = "ak.component.strand.fields.v1";
        // CellStore keys are `(realm_id, cell_ref)`. Membership CellRefs use
        // only the actor DID as their subject, so consulting the flattened
        // `cells` cache here would alias the same actor across every Realm.
        // The structured membership projection retains the missing Realm
        // dimension and is therefore the authoritative CAS head for this
        // family.
        if let Some(actor_id) = cell_ref
            .strip_prefix("ak:cell:")
            .and_then(|rest| rest.strip_prefix(MEMBER_STATE_FAMILY))
            .and_then(|rest| rest.strip_prefix(':'))
        {
            let Some(member) = self.member(realm_id, actor_id) else {
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
        let Some(value) = self.cell_value(&cell_id) else {
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
                from_ref: Some(list_space_id.to_owned()),
                to_ref: Some(strand_id.to_owned()),
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
        relation.from_ref = Some(list_space_id.to_owned());
        relation.to_ref = Some(strand_id.to_owned());
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
        for cell in cell_store.list_cells(realm_id)? {
            let ops = cell_store.sealed_ops_for_cell(realm_id, &cell)?;
            let binding = cell_registry
                .resolve(realm_id, &cell)
                .map_err(|e| StoreError::Backend(format!("cell registry resolve: {e}")))?;
            let resolved = arkret_state::join_cell(binding.lattice.as_ref(), &cell, &ops);
            match cell.as_str() {
                arkret_wire::REALM_METADATA_CELL => {
                    self.realm_metadata_cells
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
                "ak:cell:ak.component.realm.policy_components.v1:null" => {
                    self.realm_policy_components_cells
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
        Ok(())
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
            return ProjectionEffect::Ignored;
        };
        match APPLY_REGISTRY.get(kind) {
            Some(dispatch) => dispatch(self, operation, hlc),
            None => ProjectionEffect::Ignored,
        }
    }

    pub fn apply(&mut self, operation: &Operation, hlc: &ServerHlc) -> ProjectionEffect {
        let effect = self.apply_once(operation, hlc);
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
    ///   level and project as `ProjectionEffect:: Ignored` with `bottom = reject` semantics.
    pub fn apply_via_lattice_registry(
        &mut self,
        operation: &Operation,
        hlc: &ServerHlc,
        registry: &registry::LatticeRegistry,
    ) -> ProjectionEffect {
        let kind = match crate::kinds::canonical_kind_for_operation(operation) {
            Some(k) => k,
            None => {
                tracing::error!(
                    object_kind = %operation.object_kind,
                    operation_id = %operation.operation_id,
                    "lattice registry dispatch: unknown canonical kind for operation; \
                     dropping with bottom (reject)"
                );
                return ProjectionEffect::Ignored;
            }
        };
        if registry.lookup_for_event_kind(kind).is_some() {
            // Canonical hit — log at trace + delegate to inline helpers.
            // The inline helpers and the LatticeRegistry-resolved cell
            // family agree by construction (this whole module has one
            // canonical match arm; the registry just declares which
            // event kinds it owns).
            tracing::trace!(
                event_kind = %kind,
                "lattice registry dispatch: routed through LatticeRegistry"
            );
            self.apply(operation, hlc)
        } else {
            // No cell-family mapping for this kind — durable-Event-only
            // projection (messages / reactions / etc.) goes through the
            // inline cache. This branch is the steady state for the
            // ~10 message-domain kinds.
            self.apply(operation, hlc)
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
        let (allowed_source, reason): (&[ObjectLifecycleState], &'static str) = match kind {
            arkret_wire::events::EventKind::STRAND_CREATE => return Ok(()),
            arkret_wire::events::EventKind::STRAND_UPDATE => {
                (&[ObjectLifecycleState::Active], "strand_not_active")
            }
            arkret_wire::events::EventKind::STRAND_ARCHIVE => {
                (&[ObjectLifecycleState::Active], "strand_not_active")
            }
            arkret_wire::events::EventKind::STRAND_RESTORE => {
                (&[ObjectLifecycleState::Archived], "strand_not_archived")
            }
            _ => return Ok(()),
        };
        let strand_id = match kind {
            arkret_wire::events::EventKind::STRAND_UPDATE => {
                strand_id_from_payload(&operation.payload)
            }
            arkret_wire::events::EventKind::STRAND_ARCHIVE
            | arkret_wire::events::EventKind::STRAND_RESTORE => operation
                .payload
                .get("target_ref")
                .and_then(Value::as_str)
                .filter(|value| value.starts_with("ak:strand:")),
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
            != Some(arkret_wire::events::EventKind::STRAND_UPDATE)
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
            != Some(arkret_wire::events::EventKind::STRAND_UPDATE)
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
            != Some(arkret_wire::events::EventKind::REDACTION)
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
            arkret_wire::events::EventKind::MORPH_CREATE => return Ok(()),
            arkret_wire::events::EventKind::MORPH_UPDATE => {
                (&[ObjectLifecycleState::Active], "morph_not_active")
            }
            arkret_wire::events::EventKind::MORPH_ARCHIVE => {
                (&[ObjectLifecycleState::Active], "morph_not_active")
            }
            arkret_wire::events::EventKind::MORPH_RESTORE => {
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

    /// `morph.md` §4.1 S1/S3 — fail-closed admission gate for
    /// `ak.morph.schema_migrate`. Enforced before durable apply. Capability
    /// (`capability_denied`) is checked separately in the operation policy
    /// layer where the authz engine is available; this method covers the
    /// state-aware preconditions:
    ///
    /// - S1 version binding: the event `requirements.schema[]` MUST bind the migration schema set
    ///   (union of `from`/`to`); otherwise `morph_schema_version_binding_missing`.
    /// - S3 profile gate: `breaking` / `transformation` require the Realm to have declared
    ///   `ak.profile.morph.schema_migration_transformations.v1`; absent →
    ///   `morph_schema_refs_transformation_unsupported`.
    /// - S3 dialect: every `transformation_rules[]` entry's `rule` id MUST be in the profile
    ///   dialect; otherwise `unsupported_transformation_rule` (hard reject, no partial apply).
    /// - additive predicate for the additive class (defence in depth; also enforced statelessly in
    ///   payload validation).
    /// - `from_schema_refs[]` set-equals the Morph's current `schema_refs[]`; otherwise
    ///   `morph_schema_refs_precondition_mismatch`.
    pub fn check_morph_schema_migrate(&self, operation: &Operation) -> Result<(), &'static str> {
        if crate::kinds::canonical_kind_for_operation(operation)
            != Some(arkret_wire::events::EventKind::MORPH_SCHEMA_MIGRATE)
        {
            return Ok(());
        }
        let from_schema_refs =
            crate::reducer::string_array_field_from_payload(&operation.payload, "from_schema_refs");
        let to_schema_refs =
            crate::reducer::string_array_field_from_payload(&operation.payload, "to_schema_refs");
        let compatibility_class = operation
            .payload
            .get("compatibility_class")
            .and_then(Value::as_str)
            .unwrap_or_default();

        // S1 — the event MUST bind the active schema version(s). The migration
        // schema set is the union of from/to; the binding MUST cover every id.
        let bound_schema: std::collections::BTreeSet<&str> = operation
            .payload
            .get("requirements")
            .and_then(|requirements| requirements.get("schema"))
            .and_then(Value::as_array)
            .map(|items| items.iter().filter_map(Value::as_str).collect())
            .unwrap_or_default();
        let union_refs = from_schema_refs
            .iter()
            .chain(to_schema_refs.iter())
            .map(String::as_str);
        if !union_refs
            .clone()
            .all(|schema_ref| bound_schema.contains(schema_ref))
        {
            return Err("morph_schema_version_binding_missing");
        }

        match compatibility_class {
            "additive" => {
                let empty =
                    arkret_models_collaboration::events_payloads::MorphSchemaFieldSet::new();
                arkret_models_collaboration::events_payloads::morph_schema_refs_additive_only(
                    &from_schema_refs,
                    &to_schema_refs,
                    &empty,
                    &empty,
                )
                .map_err(|_| "morph_schema_refs_transformation_unsupported")?;
            }
            "breaking" | "transformation" => {
                if !self.realm_declares_morph_migration_profile(operation.realm_id.as_str()) {
                    return Err("morph_schema_refs_transformation_unsupported");
                }
                if compatibility_class == "transformation" {
                    let rules = operation
                        .payload
                        .get("transformation_rules")
                        .and_then(Value::as_array);
                    let Some(rules) = rules.filter(|rules| !rules.is_empty()) else {
                        return Err("unsupported_transformation_rule");
                    };
                    for rule in rules {
                        let rule_id = rule
                            .as_object()
                            .and_then(|object| object.get("rule"))
                            .and_then(Value::as_str)
                            .unwrap_or_default();
                        if !crate::reducer::SUPPORTED_MORPH_TRANSFORMATION_RULE_IDS
                            .contains(&rule_id)
                        {
                            return Err("unsupported_transformation_rule");
                        }
                    }
                }
            }
            _ => return Err("morph schema_migrate compatibility_class is invalid"),
        }

        // CAS — from_schema_refs[] MUST match the live Morph schema_refs[].
        // An unmaterialized Morph is left to the reducer's pending-replay path.
        if let Some(morph) = self.morphs.get(
            operation
                .payload
                .get("morph_id")
                .and_then(Value::as_str)
                .unwrap_or_default(),
        ) {
            if morph.state != ObjectLifecycleState::Active {
                return Err("morph_not_active");
            }
            if !crate::reducer::string_sets_equal(&morph.schema_refs, &from_schema_refs) {
                return Err("morph_schema_refs_precondition_mismatch");
            }
        }
        Ok(())
    }

    /// `morph.md` §4.1 S3 — whether the Realm has declared the opt-in
    /// `ak.profile.morph.schema_migration_transformations.v1` profile that
    /// permits breaking / transformation schema migrations.
    pub fn realm_declares_morph_migration_profile(&self, realm_id: &str) -> bool {
        self.realm_states.get(realm_id).is_some_and(|realm| {
            realm.active_profiles.iter().any(|profile| {
                profile == crate::reducer::MORPH_SCHEMA_MIGRATION_TRANSFORMATIONS_PROFILE
            })
        })
    }
}
