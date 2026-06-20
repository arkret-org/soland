//! The core [`ProjectionState`] struct and its inline `impl` (cell
//! helpers, push-route apply, dispatch entry points, and Strand / Morph
//! state-machine preflights).
//!
//! Split out of the `reducer` mod file; re-exported there so the
//! `crate::reducer::ProjectionState` path and sibling `super::*` access
//! stay unchanged. Additional `impl ProjectionState` blocks live in the
//! `apply_*` sibling modules.

use std::collections::{BTreeMap, BTreeSet};

use cokret_sdk::lattice::CellState;
use cokret_sdk::state_res::{CellRegistry, CellStore, StoreError};
use cokret_sdk::{AgentLifecycleState, CellRef, Operation, RealmId};
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
    /// Poll projections keyed by poll_id. Poll create is a message content
    /// block; responses are per-actor replacements until the poll is closed.
    pub polls: BTreeMap<String, PollState>,
    /// Structured side-band cache keyed by
    /// `(realm_id, actor_id)`. Holds the FSM state value plus `role` /
    /// `joined_at` / `updated_at` side-band data that doesn't fit in the
    /// `ck.component.member.state.v1` FSM cell itself. Reads should go
    /// through helpers like [`ProjectionState::members_of_realm`] /
    /// [`ProjectionState::members_in_state`] / [`ProjectionState::member`]
    /// rather than touching this directly.
    ///
    /// Banned and knocking members are derived via `members_in_state`
    /// against the FSM state field, not stored as separate collections.
    pub members: BTreeMap<(String, String), SolandMembershipState>,
    /// Server-side invite projection keyed by `invite_id`.
    /// `ck.invite.third_party` creates pending third-party invites and
    /// `ck.invite.claim` converts them into DID-targeted claimed invites.
    pub invites: BTreeMap<String, InviteProjection>,
    /// Signed key-backup active-series records keyed by `(actor_id,
    /// backup_class)`. Recovery MUST use this pointer instead of inferring the
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
    /// `ck:cell:ck.component.realm.read_receipt_policy.v1:<realm_id>`).
    /// Each successful apply_seal (`routing::federation::move_seal::submit_seal` or
    /// `crate::notary::NotaryWorker`) calls
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
    ///     `ck.component.member.state.v1` FSM cell.
    ///   - `realm_states` (mixed: ordered-log + cas-register) — kept as structured `realm_states`
    ///     side-band cache (server-side `created_at`/`updated_at`/`deleted` flag) BUT every
    ///     `apply_realm_lifecycle` now also writes one of: `ck.component.realm.create.v1`
    ///     (ordered-log, append) / `ck.component.realm.organization.v1` (cas-register, latest
    ///     metadata) / `ck.component.realm.destroy.v1` (cas-register, terminal). Helpers:
    ///     `realm_create_log` / `realm_organization_cell_value` / `realm_is_destroyed` query cells
    ///     directly. Durable-event-only fields (`messages` / `reactions` / `read_cursors` /
    ///     `relations` / `redactions`) stay structured per spec (those event kinds have no
    ///     `cell_family` declaration).
    pub cells: BTreeMap<CellRef, CellState>,
    /// Server-side Space-container projection —
    /// `container_space_id -> SpaceContainerProjection`.
    /// Maintains the canonical state-machine described in
    /// `cokret-spec/v1/zh/models/common-fields.md §5.1` for `ck.space.*`
    /// lifecycle events. Used by `event_log::submit_event` to reject
    /// invalid transitions with HTTP 412 before persisting. Reducer applies
    /// `ck.space.create` / update / parent / archive / restore / tombstone;
    /// mirror table is the `projection_space_containers` durable table.
    pub space_containers: BTreeMap<String, SpaceContainerProjection>,
    /// Server-side Strand projection. Mirrors the canonical state-machine
    /// for ck.strand.create / update / archive / restore. Unlike Space
    /// there is no dedicated `ck.strand.tombstone` event; terminal state
    /// is reached via `ck.redaction`. Mirror table is `projection_strands`
    /// (durable).
    pub strands: BTreeMap<String, StrandProjection>,
    /// CKP-0007 — server-side Circle projection. Mirrors the canonical
    /// state-machine for `ck.circle.*` lifecycle / membership events
    /// (spec b7d35be `zh/models/circle.md`). Keyed by `circle_id`
    /// (`ck:circle:<uuid>`); membership and parent-Realm binding live in
    /// the struct so the wire layer can enforce
    /// `Circle.members ⊆ Realm.members` without an extra DB hop.
    pub circles: BTreeMap<String, CircleProjection>,
    /// Side-band membership boundaries for Circle history filtering. Keyed by
    /// `(circle_id, actor_id)` and retained across leave/ban transitions so
    /// read-side helpers can enforce invited/joined floors deterministically.
    pub circle_memberships: BTreeMap<(String, String), CircleMembershipState>,
    /// Server-side Morph projection. Same shape as Strand. Mirror table
    /// is `projection_morphs` (durable).
    pub morphs: BTreeMap<String, MorphProjection>,
    /// Server-side Applet registry projection, keyed by `service_did`
    /// (the canonical applet identity per spec
    /// `extensions/applet-integration.md`). Populated by
    /// `ck.applet.registration` (initial registration / re-registration)
    /// and updated by `ck.applet.discovery` (manifest refresh). Used by
    /// `GET /_soland/admin/applets` admin snapshot. Protocol-session
    /// events (`ck.applet.interop_session.{start,status}`,
    /// `ck.applet.bridge_error`) are NOT mirrored here — sessions are
    /// ephemeral and the applet bridge state machine lives client-side.
    pub applets: BTreeMap<String, AppletProjection>,
    /// Server-side Agent registry projection, keyed by `agent_id`.
    /// Same shape as `applets`. Populated by `ck.agent.endpoint`.
    /// Protocol-session events for agents
    /// (`ck.agent.interop_session.{start,status,result}`) are also not
    /// mirrored — see `applets` rationale.
    pub agents: BTreeMap<String, SolandAgentProjection>,
    /// R3 spec-sync (2026-05-27, cokret-spec b47ff6ec) — FSM lifecycle
    /// state for each agent_principal_id. Driven by
    /// `ck.agent.{pause,resume,deactivate}` (REDU-1). Default `Active`
    /// for any agent_principal_id we've seen; `Deactivated` is terminal
    /// (no transition out, no resume after).
    pub agent_lifecycles: BTreeMap<String, AgentLifecycleState>,
    /// Actor-private action approval queue keyed by `request_id`.
    /// `ck.agent.action_request` creates pending entries; approve/reject
    /// resolves them, and pause/deactivate cancels every still-pending request
    /// for the target agent before any future endpoint can be registered.
    pub agent_action_requests: BTreeMap<String, AgentActionRequestProjection>,
    /// CKP-0008 §4.5 / D3 — accepted, non-revoked agent key authorizations
    /// keyed by `agent_principal_id`. An entry is the set of authorized
    /// `key_id`s the agent currently holds (cleared on
    /// `ck.agent.key.revoke`). The capability evaluator reads this to decide
    /// whether `effective_after_first_authorized_key` grants have activated:
    /// an agent with at least one entry has completed runtime pairing.
    pub agent_authorized_keys: BTreeMap<String, BTreeSet<String>>,
    /// R3 spec-sync — `ck.call.state.session_focus` write-once projection
    /// keyed by `call_id`. Once a focus is committed for a call, the
    /// reducer rejects any subsequent write with
    /// `session_focus_already_committed` (REDU-3).
    pub call_session_focus: BTreeMap<String, String>,
    /// R3.1 — Realm-link projection. Outer key is the source
    /// `realm_id` (the envelope `realm_id` of a `ck.realm.link` event);
    /// the inner Vec accumulates every directed link the Realm has
    /// declared, including non-`active` status entries (so admin tooling
    /// can render `rejected` / `tombstoned` history). Cell-canonical
    /// values live in `cells` under
    /// `ck.component.realm.link.v1` keyed by `(realm, target, link_kind)`;
    /// this is the structured side-band cache used by the query API.
    pub realm_links: BTreeMap<String, Vec<RealmLinkState>>,
    /// R3.1 — inverse index of [`Self::realm_links`] keyed by the
    /// target `realm_id`. Lets the query API answer
    /// `direction=inbound` in O(1) without a full scan.
    pub realm_links_inbound: BTreeMap<String, Vec<RealmLinkState>>,
    /// R3.2 — `ck.realm.inheritance_policy` projection, keyed by the
    /// child `realm_id` (the envelope `realm_id`). Cas-register
    /// semantics — last write wins.
    pub realm_inheritance_policies: BTreeMap<String, RealmInheritancePolicyState>,
    /// R3.2 — `ck.capability.derived` projection, keyed by
    /// `capability_id`. Cas-register semantics — last write wins per
    /// capability.
    pub capability_derived: BTreeMap<String, CapabilityDerivedState>,
    /// G3.S1 — published MLS KeyPackages keyed by `keypackage_id`. Each
    /// row is per `(actor_id, device_id)`; the `claimed_by` /
    /// `consumed_at` slots flip on a successful CAS claim.
    pub mls_key_packages: BTreeMap<String, MlsKeyPackage>,
    /// G3.S1 — per-device Welcome queue. Outer key names the recipient
    /// actor and device; the inner Vec is the FIFO of pending Welcomes.
    /// Entries gain a non-None `delivered_at` when the recipient device
    /// drains them via `GET /_soland/self/keys/keypackages/welcomes/pending`.
    pub mls_welcomes: BTreeMap<MlsWelcomeQueueKey, Vec<MlsWelcome>>,
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
    /// `ck.member.state -> leave/ban` removes the actor from every Circle in
    /// that Realm. For MLS-backed Circle scopes, the same transition queues an
    /// obligation for the MLS path to issue a remove proposal/commit.
    pub pending_mls_removals: Vec<MlsRemoveObligation>,
    /// G3.S2 — per-Realm `ck.realm.policy_server` projection. Cas-
    /// register semantics — last write wins. Org-level fallback (when
    /// a Realm has no row of its own) is resolved at query time by
    /// walking the `governed_by` link chain via [`Self::realm_links`].
    /// Cell-family canonical value lives in
    /// `ck.component.realm.policy_server.v1`.
    pub realm_policy_servers: BTreeMap<String, RealmPolicyServerConfig>,
    /// Device push-route projection keyed by the protocol composite
    /// `(recipient_service_did, principal_id, device_id, push_route)`.
    /// These are actor-private state cells and MUST stay isolated per
    /// recipient Principal Server.
    pub push_routes: BTreeMap<PushRouteSubject, PushRouteCellValue>,
    /// Optional local Principal/Sync service DID. When set, incoming
    /// `ck.device.push_route` writes whose `recipient_service_did` does
    /// not match this service are rejected instead of cached.
    pub local_service_did: Option<String>,
    /// Stream-F (Wave 1B) — `ck.audit.erasure_receipt` projection.
    /// Append-only list of receipts the reducer has accepted. Spec
    /// `realm-and-space.md` §2.5.2 + erasure-receipt.schema.json.
    /// Receipts are durable events; the projection cache here is used
    /// by the `erasure_receipts_endpoint` server-describe surface and
    /// by `apply_audit_erasure_receipt_dispatch`.
    pub erasure_receipts: Vec<ErasureReceiptRecord>,
}

impl ProjectionState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_local_service_did(&mut self, service_did: impl Into<String>) {
        self.local_service_did = Some(service_did.into());
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
        if target_ref.starts_with("ck:space:") {
            return self.space_containers.contains_key(target_ref);
        }
        if target_ref.starts_with("ck:strand:") {
            return self.strands.contains_key(target_ref);
        }
        if target_ref.starts_with("ck:morph:") {
            return self.morphs.contains_key(target_ref);
        }
        if target_ref.starts_with("ck:relation:") {
            return self.relations.contains_key(target_ref);
        }
        if target_ref.starts_with("ck:event:") || target_ref.starts_with("ck:message:") {
            let event_id = message_event_id_from_ref(target_ref);
            return self.messages.contains_key(target_ref) || self.messages.contains_key(&event_id);
        }
        false
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
        let Some(recipient_service_did) =
            payload.get("recipient_service_did").and_then(Value::as_str)
        else {
            return ProjectionEffect::Rejected {
                reason: "push_route_missing_recipient_service_did".to_owned(),
            };
        };
        if let Some(local_service_did) = self.local_service_did.as_deref()
            && local_service_did != recipient_service_did
        {
            return ProjectionEffect::Rejected {
                reason: "recipient_service_did_mismatch".to_owned(),
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
            recipient_service_did: recipient_service_did.to_owned(),
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
                    "recipient_service_did": &subject.recipient_service_did,
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
        let relation_id = format!("ck:relation:kanban.position:{board_space_id}:{strand_id}");
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
    /// in the Move/Seal pipeline
    /// (`routing::federation::move_seal::submit_seal` plus
    /// `crate::notary::NotaryWorker`) to keep this projection cache
    /// in sync with sealed cell state.
    ///
    /// This is the only write path into [`ProjectionState::cells`]; the
    /// durable-Event projection path (`apply()`) does NOT touch cells —
    /// state cells are exclusively a Move/Seal surface per spec.
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
            let resolved = binding.lattice.join(&cell, &ops);
            self.cells.insert(cell, resolved);
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
    /// All cell-state events (ck.realm.policy / ck.realm.read_receipt_policy /
    /// ck.consent.* / ck.member.state / ck.realm.* facets) are routed via
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

    /// Apply a batch of operations.
    pub fn apply_batch(
        &mut self,
        operations: &[Operation],
        hlc: &ServerHlc,
    ) -> Vec<ProjectionEffect> {
        operations.iter().map(|op| self.apply(op, hlc)).collect()
    }

    /// Probe the supplied [`LatticeRegistry`] for a `cell_family` that
    /// handles this Operation's canonical kind via `event_kinds()`.
    ///
    /// Behaviour:
    /// - **Hit on a cell-family impl**: routes through the inline `apply_*` helpers (the helpers
    ///   ARE the projection — the registry only validates that the spec maps this event_kind to a
    ///   known cell family, then we trust the inline dispatcher to handle the per-domain effect).
    /// - **No mapping in registry but a known canonical kind**: the kind is durable-Event-only
    ///   (`ck.message.*` / `ck.reaction.*` etc.); fall through to inline `apply()` exactly as
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
                    object_type = %operation.object_type,
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

    /// Read-only state-machine preflight for a `ck.strand.*` lifecycle event.
    /// Mirror of `check_space_container_lifecycle_transition` — used by
    /// `event_log::submit_event` to short-circuit HTTP admission with 412
    /// failed_precondition. Unknown Strand returns `Ok` (causal/backfill
    /// tolerance per common-fields.md §5.1).
    pub fn check_strand_lifecycle_transition(
        &self,
        operation: &Operation,
    ) -> Result<(), &'static str> {
        use crate::kinds::*;
        let kind = match crate::kinds::canonical_kind_for_operation(operation) {
            Some(k) => k,
            None => return Ok(()),
        };
        // `ck.strand.create` is unconditional (no current state to validate).
        // `ck.strand.update` requires Active source.
        // `ck.strand.archive` requires Active source.
        // `ck.strand.restore` requires Archived source.
        let (allowed_source, reason): (&[ObjectLifecycleState], &'static str) = match kind {
            CK_STRAND_CREATE => return Ok(()),
            CK_STRAND_UPDATE => (&[ObjectLifecycleState::Active], "strand_not_active"),
            CK_STRAND_ARCHIVE => (&[ObjectLifecycleState::Active], "strand_not_active"),
            CK_STRAND_RESTORE => (&[ObjectLifecycleState::Archived], "strand_not_archived"),
            _ => return Ok(()),
        };
        let Some(strand_id) = strand_id_from_payload(&operation.payload) else {
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
            != Some(crate::kinds::CK_STRAND_UPDATE)
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
            != Some(crate::kinds::CK_STRAND_UPDATE)
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
            "timestamp": operation.created_at.to_rfc3339(),
            "kind": "incident.status.transition",
        }))
    }

    /// Read-only preflight for `ck.redaction` events that
    /// target a Strand / Morph via `object_ref`. Per spec common-fields.md
    /// §5.1, redaction is legal only from `active` or `archived` source;
    /// terminal source MUST `failed_precondition` with
    /// `<kind>_already_terminal`. Unknown object tolerated (causal /
    /// backfill window). Space containers are excluded — spec routes their
    /// removal through `ck.space.tombstone` only.
    pub fn check_redaction_target_transition(
        &self,
        operation: &Operation,
    ) -> Result<(), &'static str> {
        if crate::kinds::canonical_kind_for_operation(operation) != Some(crate::kinds::CK_REDACTION)
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

    /// Read-only state-machine preflight for a `ck.morph.*` lifecycle event.
    /// Same shape as `check_strand_lifecycle_transition`.
    pub fn check_morph_lifecycle_transition(
        &self,
        operation: &Operation,
    ) -> Result<(), &'static str> {
        use crate::kinds::*;
        let kind = match crate::kinds::canonical_kind_for_operation(operation) {
            Some(k) => k,
            None => return Ok(()),
        };
        let (allowed_source, reason): (&[ObjectLifecycleState], &'static str) = match kind {
            CK_MORPH_CREATE => return Ok(()),
            CK_MORPH_UPDATE => (&[ObjectLifecycleState::Active], "morph_not_active"),
            CK_MORPH_ARCHIVE => (&[ObjectLifecycleState::Active], "morph_not_active"),
            CK_MORPH_RESTORE => (&[ObjectLifecycleState::Archived], "morph_not_archived"),
            _ => return Ok(()),
        };
        let Some(morph_id) = operation.payload.get("morph_id").and_then(|v| v.as_str()) else {
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
}
