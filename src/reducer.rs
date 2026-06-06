//! Deterministic state reducer for cokret operations.
//!
//! Applies operations to produce projection state using well-known
//! conflict resolution rules:
//! - Scalar fields: Last-Writer-Wins (LWW) by HLC timestamp
//! - Set fields: OR-Set (add-wins with tombstones)
//! - Messages: append-only, revisions form chains
//! - Ordered lists: fractional indexing
//!
//! # Architecture
//!
//! [`ProjectionState::apply`] is a direct match-on-canonical-kind
//! dispatcher to inline projection helpers.
//!
//! The Move/Anchor receive pipeline (`POST /_soland/peer/moves` /
//! `POST /_soland/peer/anchors`) routes through [`registry::LatticeKind`] /
//! [`registry::LatticeRegistry`]. Concrete impls live in
//! [`lattice_kinds`]; [`lattice_kinds::build_sdk_cell_registry`] feeds
//! the SDK's `verify_move` / `apply_anchor` pipeline. This is the
//! protocol-canonical path; [`ProjectionState`]'s structured fields
//! (`messages`, `reactions`, `read_cursors`, etc.) are an in-memory
//! convenience cache populated from the durable Event-Envelope ingestion
//! path that pre-dates the Move/Anchor model. As Anchor projection lands,
//! the structured fields migrate to a single `cells` map.

pub mod lattice_kinds;
pub mod mls;
pub mod realm_links;
// G3.S2: policy server cell reducer
pub mod realm_policy_server;
pub mod registry;

use std::collections::{BTreeMap, BTreeSet};

use cokret_sdk::lattice::CellState;
use cokret_sdk::state_res::{CellRegistry, CellStore, StoreError};
use cokret_sdk::{CellRef, Operation, RealmId};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::hlc::ServerHlc;
use crate::wire::{ReadCursorPositionWire, ReadScopeWire};

pub const CHILD_ORDER_CELL_FAMILY: &str = "ck.component.child_order.v1";
const REALM_ENCRYPTION_PROFILE_CREATE_LOCKED: &str = "realm_encryption_profile_create_locked";
const CIRCLE_ENCRYPTION_PROFILE_CREATE_LOCKED: &str = "circle_encryption_profile_create_locked";
const CIRCLE_ENCRYPTION_BELOW_REALM_FLOOR: &str = "circle_encryption_below_realm_floor";

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
    /// Relations keyed by relation_id. LWW by HLC.
    pub relations: BTreeMap<String, RelationState>,
    /// Poll projections keyed by poll_id. Poll create is a message content
    /// block; responses are per-actor replacements until the poll is closed.
    pub polls: BTreeMap<String, PollState>,
    /// Structured side-band cache keyed by
    /// `(realm_id, actor_did)`. Holds the FSM state value plus `role` /
    /// `joined_at` / `updated_at` side-band data that doesn't fit in the
    /// `ck.component.member.state.v1` FSM cell itself. Reads should go
    /// through helpers like [`ProjectionState::members_of_realm`] /
    /// [`ProjectionState::members_in_state`] / [`ProjectionState::member`]
    /// rather than touching this directly.
    ///
    /// Banned and knocking members are derived via `members_in_state`
    /// against the FSM state field, not stored as separate collections.
    pub members: BTreeMap<(String, String), MembershipState>,
    /// Realm lifecycle state keyed by realm_id.
    pub realm_states: BTreeMap<String, RealmState>,
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
    /// Per-cell effective state
    /// populated from the Move/Anchor pipeline's `apply_anchor` write-back.
    ///
    /// Keyed by canonical `CellRef` (e.g.
    /// `ck:cell:ck.component.realm.read_receipt_policy.v1:<realm_id>`).
    /// Each successful apply_anchor (`routing::federation::move_anchor::submit_anchor` or
    /// `crate::anchorer::AnchorerWorker`) calls
    /// [`ProjectionState::reload_cells_from_store`] to refresh this map for
    /// the affected Realm. Read handlers query via [`ProjectionState::cell`]
    /// / [`ProjectionState::cell_value`] for cell-keyed state lookups
    /// instead of scanning the durable Event store.
    ///
    /// This map is the canonical source for all cell-driven state in the
    /// Move/Anchor pipeline.
    /// Completed migrations:
    ///   - `read_receipt_policies` (CasRegister) — old BTreeMap deleted; read path uses
    ///     `cell_value`.
    ///   - `memberships` / `banned_members` / `knocking_members` (FSM) — replaced by flat
    ///     `members: BTreeMap<(String, String), MembershipState>` cache + per-actor
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
    /// Server-side Flow projection. Mirrors the canonical state-machine
    /// for ck.flow.create / update / archive / restore. Unlike Space
    /// there is no dedicated `ck.flow.tombstone` event; terminal state
    /// is reached via `ck.redaction`. Mirror table is `projection_flows`
    /// (durable).
    pub flows: BTreeMap<String, FlowProjection>,
    /// CKP-0007 — server-side Circle projection. Mirrors the canonical
    /// state-machine for `ck.circle.*` lifecycle / membership events
    /// (spec b7d35be `zh/models/circle.md`). Keyed by `circle_id`
    /// (`ck:circle:<uuid>`); membership and parent-Realm binding live in
    /// the struct so the wire layer can enforce
    /// `Circle.members ⊆ Realm.members` without an extra DB hop.
    pub circles: BTreeMap<String, CircleProjection>,
    /// Server-side Morph projection. Same shape as Flow. Mirror table
    /// is `projection_morphs` (durable).
    pub morphs: BTreeMap<String, MorphProjection>,
    /// Server-side Applet registry projection, keyed by `service_did`
    /// (the canonical applet identity per spec
    /// `extensions/applet-integration.md`). Populated by
    /// `ck.applet.registration` (initial registration / re-registration)
    /// and updated by `ck.applet.discovery` (manifest refresh). Used by
    /// `GET /_soland/admin/applets` admin snapshot. Protocol-session
    /// events (`ck.applet.protocol_session.{start,status}`,
    /// `ck.applet.bridge_error`) are NOT mirrored here — sessions are
    /// ephemeral and the applet bridge state machine lives client-side.
    pub applets: BTreeMap<String, AppletProjection>,
    /// Server-side Agent registry projection, keyed by `agent_id`.
    /// Same shape as `applets`. Populated by `ck.agent.endpoint`.
    /// Protocol-session events for agents
    /// (`ck.agent.protocol_session.{start,status,result}`) are also not
    /// mirrored — see `applets` rationale.
    pub agents: BTreeMap<String, AgentProjection>,
    /// R3 spec-sync (2026-05-27, cokret-spec b47ff6ec) — FSM lifecycle
    /// state for each agent_principal_id. Driven by
    /// `ck.agent.{pause,resume,deactivate}` (REDU-1). Default `Active`
    /// for any agent_principal_id we've seen; `Deactivated` is terminal
    /// (no transition out, no resume after).
    pub agent_lifecycles: BTreeMap<String, AgentLifecycleState>,
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
    /// R3.3 — `ck.realm.audit_policy_downgrade` audit log. Append-only
    /// list of downgrade events per Realm.
    pub realm_audit_downgrades: BTreeMap<String, Vec<RealmAuditDowngradeEntry>>,
    /// G3.S1 — published MLS KeyPackages keyed by `keypackage_id`. Each
    /// row is per `(actor_did, device_id)`; the `claimed_by` /
    /// `consumed_at` slots flip on a successful CAS claim.
    pub mls_key_packages: BTreeMap<String, MlsKeyPackage>,
    /// G3.S1 — per-device Welcome queue. Outer key is
    /// `(recipient_actor_did, recipient_device_id)`; the inner Vec is
    /// the FIFO of pending Welcomes. Entries gain a non-None
    /// `delivered_at` when the recipient device drains them via
    /// `GET /_cokret/self/keys/welcomes/pending`.
    pub mls_welcomes: BTreeMap<(String, String), Vec<MlsWelcome>>,
    /// G3.S1 — per-group MLS commit-epoch state. The reducer keeps the
    /// monotonic epoch counter in lockstep with `apply_commit_epoch`
    /// CAS rules: each accepted commit bumps the value by exactly +1
    /// from the previous epoch. The same row accumulates the governance
    /// Anchor frontier covered by accepted MLS commits so E2EE message
    /// paths can gate plaintext fallback against stale epochs.
    pub mls_commit_epochs: BTreeMap<String, MlsCommitEpoch>,
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

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct PushRouteSubject {
    pub recipient_service_did: String,
    pub principal_id: String,
    pub device_id: String,
    pub push_route: String,
}

/// Stream-F (Wave 2C) — per-peer fanout status for a single
/// `ck.audit.erasure_receipt`. One row per federation peer that has
/// received content from the affected Realm.
///
/// `sent_at` is stamped when the receipt is enqueued into the
/// federation outbox. `acked_at` is stamped when the peer's own
/// follow-up `ck.audit.erasure_receipt` lands back referencing the
/// same `receipt_id`. `outcome` mirrors the peer's reported wire
/// outcome (`completed` / `partially_completed` /
/// `blocked_by_legal_hold` / `scheduled` / `failed`). Spec
/// `realm-and-space.md` §2.5.2.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FanoutPeerStatus {
    pub sent_at: Option<chrono::DateTime<chrono::Utc>>,
    pub acked_at: Option<chrono::DateTime<chrono::Utc>>,
    pub outcome: Option<String>,
}

/// Stream-F (Wave 1B) — `ck.audit.erasure_receipt` projection record.
/// Mirrors a subset of the canonical `ck.schema.erasure_receipt.v1`
/// payload (see
/// `cokret-spec/spec/v1/artifacts/schemas/erasure-receipt.schema.json`).
/// We only keep the fields the local audit / federation fanout layer
/// actually consults — the rest of the payload (`proofs`,
/// `erased_classes`, `retained_stub_digest`, …) round-trips through the
/// raw `payload` blob for replay.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ErasureReceiptRecord {
    pub receipt_id: Option<String>,
    pub issuer: Option<String>,
    pub subject_kind: Option<String>,
    pub subject_ref: Option<String>,
    pub outcome: String,
    pub storage_boundary: Option<String>,
    /// Stream-F (Wave 2C) — affected Realm extracted from
    /// `payload.scope.realm_id`. Used by the federation fanout pass to
    /// pick the set of peers that have received content from the
    /// affected Realm. `None` for purely account-scoped receipts (no
    /// federation fanout needed in that case).
    pub scope_realm_id: Option<String>,
    /// Cross-Principal-Server fanout status — `pending` until the
    /// peer responses have all been collected, `complete` when every
    /// recipient has acknowledged, `incomplete` when the
    /// `erasure_propagation_window_ms` (default 7 days) lapses.
    /// Stream-F (Wave 2C) — the timeout sweep in
    /// `crate::routing::federation::erasure_fanout` flips this to
    /// `incomplete` once `recorded_at + window < now` and any peer
    /// in `peer_status` still has `acked_at.is_none()`.
    pub fanout_status: String,
    /// Stream-F (Wave 2C) — per-peer fanout state. Keyed by the
    /// peer's `service_did` (canonical federation peer identity from
    /// `config.federation_peers`). The reducer seeds one entry per
    /// configured peer when the receipt is accepted; the federation
    /// outbox stamps `sent_at` as soon as the row is enqueued.
    pub peer_status: std::collections::BTreeMap<String, FanoutPeerStatus>,
    pub recorded_at: chrono::DateTime<chrono::Utc>,
    /// Raw payload preserved for replay / audit verifier round-trip.
    pub payload: Value,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PushRouteCellValue {
    pub push_target_id: Option<String>,
    pub push_gateway_did: Option<String>,
    pub encryption_key: Option<String>,
    pub capabilities: Vec<String>,
    pub revoked: bool,
    pub revoked_targets: Vec<String>,
}

/// R3.1 — structured cache row for a single directed Realm link.
/// Mirrors the `ck.component.realm.link.v1` cell value plus envelope-
/// derived timestamps so the query API can render `created_at` /
/// `updated_at` without re-reading the durable Event store.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RealmLinkState {
    pub realm_id: String,
    pub target_realm_id: String,
    /// Canonical link kind string (snake_case, one of the eight values
    /// in `cokret_sdk::RealmLinkKind`).
    pub link_kind: String,
    /// `active` / `rejected` / `tombstoned`.
    pub status: String,
    pub label: Option<String>,
    pub commitment: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

/// G3.S2 — structured cache row for `ck.realm.policy_server`. Mirrors
/// the canonical `ck.component.realm.policy_server.v1` cas-register
/// payload. Per spec `authz/policy-server.md` §2 the wire payload also
/// carries `applies_to[]` / `policy_sources[]` / `abuse_profile_ref` /
/// `public_keys[]`; the runtime fields needed by the outbound
/// `/policy/check` client are the five captured here. The rest is held
/// on the raw cell value for admin tooling that wants to round-trip the
/// full declaration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RealmPolicyServerConfig {
    pub realm_id: String,
    /// DID of the policy decision service. Used to resolve the
    /// signature verification key and match against `bound_to.policy_server_id`.
    pub policy_server_did: String,
    /// HTTPS endpoint that accepts `POST /_cokret/self/policy/check`.
    pub policy_server_url: String,
    /// Decision cache TTL. Spec §2 default `300`. The outbound client
    /// uses this as the per-realm cap on the in-memory decision cache;
    /// a `bypass_cache=true` request still skips it.
    pub cache_ttl_seconds: u64,
    /// Wall-clock timeout for one `/policy/check` round-trip. Spec §6
    /// `fail_mode=closed` deployments MUST fail-closed on timeout (see
    /// `on_timeout` below). Defaults to 2000 ms when absent, matching
    /// coauth's own evaluator deadline.
    pub timeout_ms: u64,
    /// `fail_closed` or `deny`. Both produce a locally-signed
    /// `decision_proxy: true` deny when the upstream times out; the
    /// difference is the canonical `reason_code` we emit.
    pub on_timeout: String,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

/// R3.2 — structured cache row for `ck.realm.inheritance_policy`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RealmInheritancePolicyState {
    pub realm_id: String,
    pub operation_id: String,
    pub source_realm_id: String,
    pub allowed_policies: Vec<String>,
    pub allowed_capability_bundles: Vec<String>,
    pub max_depth: u32,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

/// R3.2 — structured cache row for `ck.capability.derived`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CapabilityDerivedState {
    pub capability_id: String,
    pub realm_id: String,
    pub source_grant_ref: String,
    pub source_realm_inheritance_policy_ref: String,
    pub causal_frontier: String,
    pub effective_actions: Vec<String>,
    pub effective_resources: Vec<Value>,
    pub effective_capability_bundles: Vec<String>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

/// R3.3 — single audit_policy_downgrade entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RealmAuditDowngradeEntry {
    pub realm_id: String,
    pub from_policy: Option<String>,
    pub to_policy: Option<String>,
    pub reason: Option<String>,
    pub approver: Option<String>,
    pub recorded_at: chrono::DateTime<chrono::Utc>,
}

/// G3.S1 — KeyPackage lifetime window. MLS KeyPackages carry a
/// `lifetime = (not_before, not_after)` per RFC 9420 §10. The reducer's
/// CAS claim path enforces `not_before <= now < not_after` (out-of-window
/// publishes are rejected on intake; expired KeyPackages cannot be
/// claimed and a follow-up `claim` returns `keypackage_expired`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyPackageLifetime {
    pub not_before: i64,
    pub not_after: i64,
}

/// G3.S1 — published MLS KeyPackage row.
///
/// One per `(actor_did, device_id, keypackage_id)`. The atomic CAS claim
/// flips `claimed_by` from `None` to `Some(group_id)` and sets
/// `consumed_at`; a second claim against the same `id` is rejected.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MlsKeyPackage {
    /// Canonical `ck:mls_keypackage:<uuid>` identifier.
    pub id: String,
    pub actor_did: String,
    pub device_id: String,
    pub lifetime: KeyPackageLifetime,
    /// Opaque bytes of the MLS KeyPackage (`mls_key_package` per RFC 9420
    /// §11). Server treats this as a black box; only the recipient device
    /// can decrypt the Welcome it backs.
    pub key_package_bytes: Vec<u8>,
    /// `None` while the KeyPackage is still claimable; `Some(group_id)`
    /// after a successful CAS claim. The CAS guarantees at-most-one
    /// claim across concurrent Welcomes.
    pub claimed_by: Option<String>,
    /// Unix seconds at which the CAS claim happened (mirrors
    /// `claimed_by`).
    pub consumed_at: Option<i64>,
    pub created_at: i64,
}

/// G3.S1 — single Welcome envelope queued for a recipient device.
///
/// The reducer's `apply_welcome_enqueue` appends one row per Welcome
/// fanout target; the recipient device drains its queue via
/// `GET /_cokret/self/keys/welcomes/pending`, which marks each delivered row
/// with `delivered_at = now()` so a re-poll won't redeliver.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MlsWelcome {
    /// Canonical `ck:mls_welcome:<uuid>` identifier.
    pub id: String,
    /// MLS group the Welcome admits the recipient into.
    pub group_id: String,
    pub recipient_actor_did: String,
    pub recipient_device_id: String,
    /// Opaque MLSMessage / Welcome bytes per RFC 9420 §12.4.3.
    pub welcome_bytes: Vec<u8>,
    /// References the KeyPackage that was claimed to produce this
    /// Welcome (per `MlsKeyPackage::id`). Audit trail only — the
    /// reducer does not re-validate the claim at delivery time.
    pub key_package_id: String,
    pub enqueued_at: i64,
    /// Unix seconds the recipient first drained this Welcome. `None`
    /// while pending.
    pub delivered_at: Option<i64>,
}

/// G3.S1 — per-group MLS commit-epoch projection.
///
/// Each successful `apply_commit_epoch` bumps `epoch` by exactly +1
/// from `expected_prev_epoch`; out-of-order or stale commits leave the
/// row untouched and the reducer returns `Rejected { reason:
/// "mls_epoch_skew" }`. `covered_frontier` is the or-set style
/// accumulator for governance Anchor ids / tags attested by accepted
/// commits for this group.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MlsCommitEpoch {
    /// MLS group id (`ck:mls_group:<...>`).
    pub group_id: String,
    /// Monotonic epoch counter. Starts at 0 before the first commit;
    /// each commit bumps by +1.
    pub epoch: u64,
    /// DID of the committer (the `leader` per MLS terminology — the
    /// member whose Commit was accepted).
    pub leader_actor_did: String,
    pub covered_frontier: Vec<String>,
    pub committed_at: i64,
}

/// Server-side Space-container state cache. Mirrors the
/// `projection_space_containers` table.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpaceContainerProjection {
    pub container_space_id: String,
    pub realm_id: String,
    pub kind: String,
    pub title: String,
    pub parent_ref: Option<String>,
    pub rank: Option<String>,
    pub state: SpaceContainerLifecycleState,
    pub state_changed_at: Option<chrono::DateTime<chrono::Utc>>,
    pub created_by: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_by: Option<String>,
    pub updated_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Stream-F (Wave 1B) — `realm_destroyed_orphan` flag set by the
    /// `ck.realm.destroy` cascade when this container's home Realm is
    /// destroyed. Spec `realm-and-space.md` §2.5.1 ¶6: orphaned
    /// containers become read-only locked projections; no
    /// `ck.flow.move` / `ck.space.parent` / `ck.space.update` may
    /// revive them. Defaults to `false`.
    pub orphaned: bool,
    /// Stream-F (Wave 2C) — cross-Realm `parent_ref` lazy-link lock.
    /// Set to `true` by `cascade_realm_destroy` when this container's
    /// `parent_ref` points at a Space whose home Realm has been
    /// destroyed. The container itself stays alive in its own home
    /// Realm but the parent edge MUST NOT propagate membership /
    /// capability / history / E2EE / retention from the destroyed
    /// Realm. UI / navigation surfaces SHOULD render this as a locked
    /// lazy link and defer to the local reparent / archive / tombstone
    /// flow inside the policy window. Spec `realm-and-space.md`
    /// §2.5.1 ¶6. Defaults to `false`.
    pub parent_ref_locked: bool,
}

fn space_container_id_from_payload(payload: &Value) -> Option<String> {
    payload
        .get("space_id")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum SpaceContainerLifecycleState {
    #[default]
    Active,
    Archived,
    Tombstoned,
}

impl SpaceContainerLifecycleState {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Archived => "archived",
            Self::Tombstoned => "tombstoned",
        }
    }
}

/// Server-side Flow state cache. Mirrors `projection_flows` table.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FlowProjection {
    pub flow_id: String,
    pub realm_id: String,
    pub title: String,
    pub summary: Option<String>,
    pub fields: BTreeMap<String, Value>,
    pub state: ObjectLifecycleState,
    pub state_changed_at: Option<chrono::DateTime<chrono::Utc>>,
    pub created_by: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_by: Option<String>,
    pub updated_at: Option<chrono::DateTime<chrono::Utc>>,
    /// CKP-0007 — the Circle this Flow is scoped to, if any (`ck:circle:…`).
    /// A message's effective circle-scope is derived from its Flow's
    /// `scope_circle_id` (spec: `scope_circle_id` is a Flow field, not a
    /// message field); messages never carry their own scope.
    pub scope_circle_id: Option<String>,
}

/// CKP-0007 — server-side Circle state cache. Mirrors `projection_circles` +
/// `projection_circle_members` (see migration
/// `20260526010000_add_circles`).
///
/// `members` is the authoritative active-member set; the wire validator and
/// the `ck.circle.member.state` handler use it to enforce the
/// `Circle.members ⊆ Realm.members` invariant
/// (`circle_member_must_be_realm_member`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CircleProjection {
    pub circle_id: String,
    /// Parent Realm id. Create-locked — a Circle never re-binds to another
    /// Realm. Spec `circle.schema.json` §`realm_id`.
    pub realm_id: String,
    pub title: String,
    pub summary: Option<String>,
    pub directory_visibility: String,
    pub join_rule: String,
    pub history_visibility: String,
    /// Optional tightening of metadata-encryption floor; `None` inherits
    /// parent Realm. Reducer enforces "MAY only tighten" against the
    /// projected Realm floor.
    pub metadata_encryption_floor: Option<String>,
    pub encryption_profile: String,
    /// Reducer-derived MLS group binding. Populated when the independent
    /// Circle MLS group is set up; the wire actor MUST NOT submit this.
    pub mls_group_ref: Option<String>,
    pub state: CircleLifecycleState,
    pub state_changed_at: Option<chrono::DateTime<chrono::Utc>>,
    pub created_by: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_by: Option<String>,
    pub updated_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Active Circle members. Maintained by `ck.circle.member.state`
    /// transitions (`active` -> insert, `removed`/`banned`/`left` ->
    /// remove). Always a strict subset of the parent Realm's active
    /// member set.
    pub members: BTreeSet<String>,
}

/// CKP-0007 — Circle lifecycle state. Matches spec `circle.schema.json`
/// `state` enum (active / archived / tombstoned). Distinct from
/// [`ObjectLifecycleState`] (which carries the redacted/deleted forms used
/// by Flow / Morph); Circle has no redaction path because the canonical
/// terminal action is `ck.circle.tombstone`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum CircleLifecycleState {
    #[default]
    Active,
    Archived,
    Tombstoned,
}

impl CircleLifecycleState {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Archived => "archived",
            Self::Tombstoned => "tombstoned",
        }
    }
}

/// Server-side Morph state cache. Mirrors `projection_morphs` table.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MorphProjection {
    pub morph_id: String,
    pub realm_id: String,
    pub morph_type: String,
    pub title: Option<String>,
    pub fields: BTreeMap<String, Value>,
    pub schema_refs: Vec<String>,
    pub facets: Vec<String>,
    pub versions: Vec<DocumentVersionProjection>,
    pub state: ObjectLifecycleState,
    pub state_changed_at: Option<chrono::DateTime<chrono::Utc>>,
    pub created_by: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_by: Option<String>,
    pub updated_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Materialized version row for document-shaped Morphs.
///
/// This is intentionally projection-side state: the canonical source remains
/// the ordered `ck.morph.create` / `ck.morph.update` event stream, while the
/// read API exposes a compact version list for clients that need to hydrate a
/// document view without replaying the whole history.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DocumentVersionProjection {
    pub version_id: String,
    pub event_id: String,
    pub author: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub body_digest: String,
    pub body: Value,
}

/// Server-side Applet registry entry. Populated by
/// `ck.applet.registration` (creates) and `ck.applet.discovery` (refreshes
/// the manifest). Spec `extensions/applet-integration.md` doesn't pin
/// down a state-machine for applet entries themselves (the bridge state
/// machine is per-session and lives client-side), so this is a simple
/// last-write-wins projection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppletProjection {
    /// `service_did` of the applet — canonical identity per spec.
    pub service_did: String,
    pub namespace: String,
    /// Optional snapshot of the most recent `manifest` (from the latest
    /// `ck.applet.discovery` event). `None` if only registration has
    /// landed.
    pub manifest: Option<Value>,
    /// Optional capability list from the latest `ck.applet.registration`.
    pub capabilities: Option<Value>,
    pub registered_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

/// Server-side Agent registry entry. Populated by
/// `ck.agent.endpoint`. Spec `extensions/agent-integration.md` mirrors
/// the applet family shape; same simple last-write-wins semantics.
///
/// `endpoint_url` is the HTTPS URL the agent runtime listens on. It is
/// OPTIONAL on the wire (older clients + DID-only agents that resolve
/// via did:web service entry won't set it), but when present the
/// reference bridge echoes it back in the
/// `ck.agent.protocol_session.result` envelope's `detail.endpoint_url`
/// so timeline consumers see which endpoint answered the invocation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentProjection {
    /// `agent_id` — canonical agent runtime DID per spec.
    pub agent_id: String,
    /// Protocol the agent speaks (free-form string per spec event-kind-registry
    /// payload description; no enum enforcement at this layer).
    pub protocol: String,
    /// HTTPS endpoint URL — optional. Reference bridge currently
    /// uses this only as an observability field; production runtimes
    /// will follow it for outbound dispatch.
    pub endpoint_url: Option<String>,
    pub registered_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

/// R3 spec-sync (2026-05-27, cokret-spec b47ff6ec) — FSM-lattice state
/// for `ck.agent.{pause,resume,deactivate}`. Bottom = `Reject`;
/// `Deactivated` is terminal (no transition out). Reducer enforcement
/// lives in [`ProjectionState::apply_agent_lifecycle`] (REDU-1).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum AgentLifecycleState {
    #[default]
    Active,
    Paused,
    Deactivated,
}

impl AgentLifecycleState {
    pub fn as_wire_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Paused => "paused",
            Self::Deactivated => "deactivated",
        }
    }
}

/// State enum shared by Flow and Morph projections (mirrors SDK
/// `cokret_sdk::ObjectState`). Unlike `SpaceContainerLifecycleState` which has
/// a single `Tombstoned` terminal, Flow / Morph use `Redacted` as their terminal
/// state per spec §5.1.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ObjectLifecycleState {
    #[default]
    Active,
    Archived,
    Redacted,
}

impl ObjectLifecycleState {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Archived => "archived",
            Self::Redacted => "redacted",
        }
    }

    /// Terminal state per spec §5.1: Flow / Morph use `redacted` as their
    /// unrecoverable terminal.
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Redacted)
    }
}

/// Value of the parallel `redaction` cas-register
/// cell on the same subject as the target message cell. Mirrors the spec
/// shape `{redacted_at, by, reason}`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RedactionCellValue {
    pub redacted_at: chrono::DateTime<chrono::Utc>,
    pub by: String,
    pub reason: Option<String>,
}

impl RedactionCellValue {
    /// Render the cas-register payload as JSON for projection / wire emission.
    pub fn to_json(&self) -> Value {
        let mut obj = serde_json::Map::new();
        obj.insert(
            "redacted_at".to_owned(),
            Value::String(self.redacted_at.to_rfc3339()),
        );
        obj.insert("by".to_owned(), Value::String(self.by.clone()));
        if let Some(reason) = &self.reason {
            obj.insert("reason".to_owned(), Value::String(reason.clone()));
        }
        Value::Object(obj)
    }
}

/// Projection-layer view of a single message cell. The reducer
/// keeps the original [`MessageState`] intact; this view is what callers
/// see at read time after the parallel `redaction` cell is consulted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProjectedMessageView {
    pub event_id: String,
    pub realm_id: String,
    pub sender: String,
    pub thread_id: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// `Some(content)` for live messages; `None` when a redaction tombstone
    /// is in effect (the projection layer replaced the payload).
    pub content: Option<Value>,
    /// `Some(value)` while the parallel `redaction` cell is set; `None` for
    /// live messages and for messages whose redaction was reverted (cell
    /// set back to null).
    pub redaction: Option<RedactionCellValue>,
}

#[derive(Clone, Debug)]
pub struct MessageState {
    pub event_id: String,
    pub realm_id: String,
    pub sender: String,
    pub thread_id: String,
    pub content: Value,
    pub expiry: Option<Value>,
    pub encrypted: bool,
    pub operation_id: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// If this is a revision, points to the original event_id.
    pub revision_of: Option<String>,
    /// If redacted, the tombstone timestamp.
    pub redacted_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Clone, Debug)]
pub struct ReactionState {
    pub actor: String,
    pub key: String,
    pub active: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct RsvpProjection {
    pub event_ref: String,
    pub status: String,
    pub occurrence: Option<String>,
    pub comment: Option<Value>,
    pub actor_id: String,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct PinProjection {
    pub pin_scope: Value,
    pub target_ref: String,
    pub rank: Option<String>,
    pub note: Option<Value>,
    pub actor_id: String,
    pub active: bool,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone, Debug)]
pub struct PollOptionState {
    pub id: String,
    pub label: String,
}

#[derive(Clone, Debug)]
pub struct PollState {
    pub poll_id: String,
    pub message_event_id: String,
    pub realm_id: String,
    pub question: String,
    pub options: Vec<PollOptionState>,
    pub votes: BTreeMap<String, BTreeSet<String>>,
    pub max_selections: u32,
    pub closed: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

fn message_event_id_from_ref(value: &str) -> String {
    value
        .strip_prefix("ck:message:")
        .map(|suffix| format!("ck:event:{suffix}"))
        .unwrap_or_else(|| value.to_owned())
}

fn reaction_target_event_id(operation: &Operation) -> Option<String> {
    [
        "target_ref",
        "target_event_id",
        "target",
        "target_message_id",
        "message_id",
        "event_id",
    ]
    .into_iter()
    .find_map(|field| {
        operation
            .payload
            .get(field)
            .and_then(|v| v.as_str())
            .filter(|value| !value.is_empty())
            .map(message_event_id_from_ref)
    })
}

fn operation_actor_id(operation: &Operation) -> String {
    operation
        .payload
        .get("actor_id")
        .or_else(|| operation.payload.get("sender"))
        .or_else(|| operation.payload.get("created_by"))
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| operation.operation_id.to_string())
}

fn occurrence_key(value: Option<&Value>) -> String {
    value
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .unwrap_or("series")
        .to_owned()
}

fn pin_scope_key(pin_scope: &Value) -> Option<String> {
    let kind = pin_scope.get("kind").and_then(Value::as_str)?;
    let id = pin_scope.get("id").and_then(Value::as_str)?;
    Some(format!("{kind}:{id}"))
}

/// Build the stored message content. `scope_circle_id` is the Flow-derived
/// circle scope (spec: messages never carry their own scope — it is resolved
/// from the message's Flow by the caller via
/// [`ProjectionState::flow_scope_circle_id`]). Any client-supplied
/// `scope_circle_id` on the message is dropped and replaced by the authoritative
/// Flow scope.
fn message_content_from_payload(payload: &Value, scope_circle_id: Option<String>) -> Value {
    let mut content = payload
        .get("content")
        .or_else(|| payload.get("encrypted_content"))
        .cloned()
        .unwrap_or_else(|| payload.clone());
    if let Some(object) = content.as_object_mut() {
        for key in [
            "reply_to",
            "in_reply_to",
            "mentions",
            "mention_routing_hint",
            "mention_sidecar_hash",
        ] {
            if !object.contains_key(key)
                && let Some(value) = payload.get(key)
            {
                object.insert(key.to_owned(), value.clone());
            }
        }
        // Never trust a client-supplied scope; stamp the Flow-derived one.
        object.remove("scope_circle_id");
        if let Some(value) = scope_circle_id {
            object.insert("scope_circle_id".to_owned(), Value::String(value));
        }
    }
    content
}

fn content_kind(content: &Value) -> Option<&str> {
    content.get("kind").and_then(Value::as_str)
}

fn poll_id_from_content(content: &Value) -> Option<String> {
    content
        .get("poll_id")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(ToOwned::to_owned)
        .or_else(|| {
            content
                .get("poll")
                .and_then(|poll| poll.get("id"))
                .and_then(Value::as_str)
                .filter(|value| !value.trim().is_empty())
                .map(ToOwned::to_owned)
        })
}

fn text_body(value: &Value) -> Option<&str> {
    value.as_str().or_else(|| {
        value
            .get("body")
            .or_else(|| value.get("label"))
            .and_then(Value::as_str)
    })
}

fn poll_question_from_content(content: &Value) -> Option<String> {
    content
        .get("question")
        .and_then(Value::as_str)
        .or_else(|| content.get("body").and_then(Value::as_str))
        .or_else(|| {
            content
                .get("poll")
                .and_then(|poll| poll.get("question"))
                .and_then(text_body)
        })
        .filter(|value| !value.trim().is_empty())
        .map(|value| value.trim().to_owned())
}

fn poll_options_from_content(content: &Value) -> Vec<PollOptionState> {
    let options = content
        .get("options")
        .and_then(Value::as_array)
        .or_else(|| {
            content
                .get("poll")
                .and_then(|poll| poll.get("answers"))
                .and_then(Value::as_array)
        });
    options
        .map(|items| {
            items
                .iter()
                .enumerate()
                .filter_map(|(idx, item)| {
                    if let Some(label) = item.as_str().filter(|value| !value.trim().is_empty()) {
                        return Some(PollOptionState {
                            id: format!("opt-{idx}"),
                            label: label.trim().to_owned(),
                        });
                    }
                    let id = item
                        .get("id")
                        .and_then(Value::as_str)
                        .map(ToOwned::to_owned)
                        .unwrap_or_else(|| format!("opt-{idx}"));
                    let label = item
                        .get("label")
                        .and_then(Value::as_str)
                        .or_else(|| item.get("text").and_then(text_body))?
                        .trim()
                        .to_owned();
                    if label.is_empty() {
                        None
                    } else {
                        Some(PollOptionState { id, label })
                    }
                })
                .collect()
        })
        .unwrap_or_default()
}

fn poll_choices_from_content(content: &Value) -> Vec<String> {
    content
        .get("choices")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .filter(|value| !value.trim().is_empty())
                .map(ToOwned::to_owned)
                .collect::<Vec<_>>()
        })
        .or_else(|| {
            content
                .get("choice")
                .and_then(Value::as_str)
                .filter(|value| !value.trim().is_empty())
                .map(|choice| vec![choice.to_owned()])
        })
        .unwrap_or_default()
}

#[derive(Clone, Debug)]
pub struct ReadMarkerState {
    pub actor_id: String,
    pub device_id: String,
    pub realm_id: String,
    pub read_scope: ReadScopeWire,
    pub position: ReadCursorPositionWire,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

fn read_scope_key(scope: &ReadScopeWire) -> String {
    let track_selector = scope
        .track
        .as_deref()
        .or_else(|| scope.track_scope.as_ref().map(|_| "all"))
        .unwrap_or("");
    format!(
        "{}\u{1f}{}\u{1f}{}",
        scope.kind.as_str(),
        scope.object_ref.as_deref().unwrap_or(""),
        track_selector
    )
}

#[derive(Clone, Debug)]
pub struct RelationState {
    pub relation_id: String,
    pub realm_id: String,
    pub relation_kind: String,
    pub from_ref: Option<String>,
    pub to_ref: Option<String>,
    pub fields: BTreeMap<String, Value>,
    pub state: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

impl RelationState {
    pub fn is_active(&self) -> bool {
        self.state == "active"
    }
}

#[derive(Clone, Debug)]
pub struct MembershipState {
    pub member: String,
    pub realm_id: String,
    /// Canonical FSM state value (one of `invite` / `join` / `leave` /
    /// `ban` / `knock`). Authoritative source is the
    /// `ck.component.member.state.v1` cell in
    /// [`ProjectionState::cells`]; this field is the structured-cache
    /// mirror updated on every membership transition.
    pub state: String,
    pub role: String,
    /// First effective invite frontier retained after a later join so
    /// `history_visibility=invited` can start at the invite boundary while
    /// `history_visibility=joined` starts at the join boundary.
    pub invited_at: Option<chrono::DateTime<chrono::Utc>>,
    pub joined_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone, Debug)]
pub struct RealmState {
    pub realm_id: String,
    pub owner: Option<String>,
    pub title: Option<String>,
    pub deleted: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    /// Round 4 (B1.2) — Realm trust domain. Captured and locked
    /// immutable on the first `ck.realm.create`; subsequent events that
    /// attempt to set a different trust domain MUST be rejected with
    /// `cross_domain_replay_rejected`. Stored as the canonical
    /// `ck:trust_domain:<scope>` string form.
    pub trust_domain: Option<String>,
    /// Stream-F (Wave 1B) — Realm terminal-state marker. Set by
    /// `apply_realm_lifecycle` when a `ck.realm.tombstone` or
    /// `ck.realm.destroy` event is projected. Possible values:
    ///   - `None` — Realm is live.
    ///   - `Some("tombstoned")` — `ck.realm.tombstone` accepted; the `successor_realm_id` field
    ///     carries the migration target.
    ///   - `Some("destroyed")` — `ck.realm.destroy` accepted; no successor.
    ///
    /// Both terminal states block non-audit writes via
    /// `routing::events::event_log::terminal_realm_check`. Spec
    /// `realm-and-space.md` §2.5 / §2.5.1.
    pub terminal_state: Option<String>,
    /// Stream-F (Wave 1B) — for `ck.realm.tombstone` only: the
    /// `ck:realm:<uuid>` of the successor Realm that takes over child
    /// Space/Flow placement. `None` for live or destroyed Realms.
    pub successor_realm_id: Option<String>,
}

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
        status: String,
    },
    PinProjected {
        pin_scope_key: String,
        target_ref: String,
        active: bool,
    },
    ReadMarkerUpdated(ReadMarkerState),
    RelationCreated(RelationState),
    RelationUpdated(RelationState),
    RelationDeleted {
        relation_id: String,
    },
    MembershipChanged {
        realm_id: String,
        member: String,
        action: String,
    },
    RealmLifecycle {
        realm_id: String,
        action: String,
    },
    /// Space-container lifecycle transition accepted; new state is reflected in
    /// `ProjectionState::space_containers` and (when persisted) `projection_space_containers`.
    SpaceContainerLifecycle {
        container_space_id: String,
        new_state: SpaceContainerLifecycleState,
    },
    /// Flow lifecycle transition accepted. Mirror of `SpaceContainerLifecycle`
    /// for `ProjectionState::flows`.
    FlowLifecycle {
        flow_id: String,
        new_state: ObjectLifecycleState,
    },
    /// Morph lifecycle transition accepted. Same shape as Flow.
    MorphLifecycle {
        morph_id: String,
        new_state: ObjectLifecycleState,
    },
    /// CKP-0007 — Circle lifecycle transition accepted. Reflects
    /// `ck.circle.create` / `update` / `archive` / `restore` / `tombstone`
    /// projection writes; new state is reflected in
    /// `ProjectionState::circles` (and the durable `projection_circles`
    /// mirror once persistence is wired).
    CircleLifecycle {
        circle_id: String,
        new_state: CircleLifecycleState,
    },
    /// CKP-0007 — Circle membership transition. `target_state` is the
    /// `ck.circle.member.state` payload's `state` value (active / removed /
    /// banned / left / invited). The reducer applies the membership write
    /// only after the strict-subset invariant
    /// (`Circle.members ⊆ Realm.members`) has been satisfied.
    CircleMemberStateChanged {
        circle_id: String,
        member: String,
        target_state: String,
    },
    /// Flow watch cell touched. Cell write itself is owned by the
    /// Move/Anchor pipeline (cas-register at SDK layer); the projection
    /// only records that a watch change happened for `(flow_id, actor_did)`
    /// so downstream listeners (notification dispatcher, watcher list
    /// projection) can react. `level` is `None` when the effect clears
    /// the cell.
    FlowWatchUpdated {
        flow_id: String,
        actor_did: String,
        level: Option<String>,
        level_public: Option<bool>,
    },
    /// Applet registry projection updated (registration or discovery).
    /// Keyed by the applet's `service_did`.
    AppletProjectionUpdated {
        service_did: String,
    },
    /// R1.2 — `ck.realm.delivery_binding_policy` event was projected
    /// into the canonical `ck.component.realm.delivery_binding_policy.v1`
    /// cas-register cell.
    DeliveryBindingPolicyProjected {
        realm_id: String,
    },
    RealmDisappearingPolicyProjected {
        realm_id: String,
    },
    RealmSearchPolicyProjected {
        realm_id: String,
    },
    /// R3.1 — `ck.realm.link` event was projected into the
    /// `ck.component.realm.link.v1` or_set cell + the `realm_links`
    /// structured cache.
    RealmLinkProjected {
        realm_id: String,
        target_realm_id: String,
        link_kind: String,
        status: String,
    },
    /// R3.2 — `ck.realm.inheritance_policy` event was projected into the
    /// `ck.component.realm.inheritance_policy.v1` cas-register cell.
    RealmInheritancePolicyProjected {
        realm_id: String,
        source_realm_id: String,
    },
    /// R3.2 — `ck.capability.derived` event was projected into the
    /// `ck.component.capability.derived.v1` cas-register cell.
    CapabilityDerivedProjected {
        capability_id: String,
        realm_id: String,
    },
    /// R3.3 — `ck.realm.audit_policy_downgrade` event was appended to
    /// the `ck.component.realm.audit_policy_downgrade.v1` ordered-log
    /// audit cell + the structured side-band cache.
    RealmAuditPolicyDowngradeProjected {
        realm_id: String,
    },
    /// Agent registry projection updated (endpoint). Keyed by the
    /// agent's `agent_id`.
    AgentProjectionUpdated {
        agent_id: String,
    },
    /// REDU-1 (R3 spec-sync 2026-05-27, cokret-spec b47ff6ec) — agent
    /// lifecycle FSM transition projected. `agent_principal_id` is the DID
    /// from the payload; `new_state` is the post-transition
    /// AgentLifecycleState. Bottom = `Reject`;
    /// Deactivated is terminal.
    AgentLifecycleProjected {
        agent_principal_id: String,
        new_state: AgentLifecycleState,
    },
    /// REDU-2 — `actor_private_event` accepted (reducer_input=false).
    /// Wire-accepted and surfaced to audit-log consumers, but does NOT
    /// advance the anchor frontier / actor_seq.
    AgentPrivateEventAccepted {
        kind: &'static str,
        event_id: String,
    },
    /// MID-1..6 (R3.1/R3.2, cokret-spec @ b56cab1) —
    /// `ck.member.identity.update` accepted into the ordered-log
    /// `ck.component.member.identity.v1` cell. The actual replacement-edge
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
    /// G3.S2 — `ck.realm.policy_server` projected into the
    /// `ck.component.realm.policy_server.v1` cas-register cell + the
    /// `realm_policy_servers` structured cache.
    RealmPolicyServerProjected {
        realm_id: String,
        policy_server_did: String,
    },
    /// `ck.device.push_route` actor-private state projected into the
    /// per-recipient Principal Server push-route cell cache.
    PushRouteUpdated {
        subject: PushRouteSubject,
        action: String,
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
    /// for `(actor_did, device_id)`.
    KeyPackagePublished {
        keypackage_id: String,
        actor_did: String,
        device_id: String,
    },
    /// `apply_keypackage_claim` — the named KeyPackage was atomically
    /// claimed for `group_id`. CAS guarantees at-most-one of these per
    /// `keypackage_id`.
    KeyPackageClaimed {
        keypackage_id: String,
        group_id: String,
        consumed_at: i64,
    },
    /// `apply_welcome_enqueue` — a Welcome envelope was appended to the
    /// per-`(recipient_actor_did, recipient_device_id)` queue.
    WelcomeEnqueued {
        welcome_id: String,
        recipient_actor_did: String,
        recipient_device_id: String,
        group_id: String,
    },
    /// `apply_group_genesis` — the group was initialized at epoch 0.
    GroupGenesis {
        group_id: String,
        epoch: u64,
        creator_actor_did: String,
        covered_frontier: Vec<String>,
    },
    /// `apply_commit_epoch` — the group's epoch was bumped from
    /// `previous_epoch` to `new_epoch` and the attested governance
    /// frontier was merged into the group's covered-frontier accumulator.
    CommitEpochAdvanced {
        group_id: String,
        previous_epoch: u64,
        new_epoch: u64,
        leader_actor_did: String,
        covered_frontier: Vec<String>,
    },
}

/// Which Space-container lifecycle transition is being attempted. Used by
/// `apply_space_container_lifecycle` to share the state-machine guard across
/// the three event kinds.
#[derive(Clone, Copy, Debug)]
enum SpaceContainerLifecycleTransition {
    Archive,
    Restore,
    Tombstone,
}

/// Flow / Morph lifecycle transition picker. Mirror of
/// `SpaceContainerLifecycleTransition` but for the two-event family (no tombstone).
#[derive(Clone, Copy, Debug)]
enum ObjectLifecycleTransition {
    Archive,
    Restore,
}

/// Extract the typed-id object reference from a `ck.redaction` event
/// payload, used by both the reducer (`apply_redaction`) and the preflight
/// (`check_redaction_target_transition`). Returns `None` for redactions
/// that only carry a `target_event_id` (message redaction path), or when no
/// recognised object-ref field is present.
fn redaction_object_ref(operation: &Operation) -> Option<String> {
    operation
        .payload
        .get("object_ref")
        .or_else(|| operation.payload.get("target_object_ref"))
        .or_else(|| operation.payload.get("target_ref"))
        .and_then(|v| v.as_str())
        .map(ToOwned::to_owned)
}

// ────────────────────────── apply() dispatch registry ──────────────────────────
//
// `ProjectionState::apply()` used to be a 30-arm `match` on
// `canonical_kind_for_operation`. Each arm delegated to a `self.apply_*`
// helper, sometimes with extra carrier args (the lifecycle enums, the
// raw kind string for `apply_realm_lifecycle`, the HLC for relations).
//
// This registry keeps the dispatch table out of the match: every
// canonical event_kind maps to a single `ApplyFn` adapter that calls
// the corresponding `apply_*` helper with the per-kind extra args
// baked in. `apply()` becomes a HashMap lookup + indirect call, with
// the "unknown kind → ProjectionEffect::Ignored" tolerance preserved
// in the fallthrough.
//
// The adapter free functions exist solely to turn the per-kind
// `(now, hlc, lifecycle_enum_variant, ...)` arg signatures into the
// uniform `(state, op, hlc) -> ProjectionEffect` shape the registry
// needs. They contain no projection logic — that all stays in the
// `apply_*` methods on `ProjectionState`.

/// Adapter signature for entries in [`default_apply_registry`].
pub type ApplyFn = fn(&mut ProjectionState, &Operation, &ServerHlc) -> ProjectionEffect;

fn apply_message_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_message(op, op.created_at)
}
fn apply_message_revise_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_message_revise(op, op.created_at)
}
fn apply_redaction_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_redaction(op)
}
fn apply_reaction_add_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_reaction_add(op, op.created_at)
}
fn apply_reaction_remove_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_reaction_remove(op)
}
fn apply_rsvp_set_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_rsvp_set(op, op.created_at)
}
fn apply_pin_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_pin(op, op.created_at)
}
fn apply_read_cursor_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_read_cursor(op, op.created_at)
}
fn apply_relation_create_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_relation_create(op, op.created_at)
}
fn apply_relation_update_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_relation_update(op, op.created_at, hlc)
}
fn apply_relation_delete_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_relation_delete(op)
}
fn apply_container_position_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_container_position(op, op.created_at)
}
fn apply_membership_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_membership(op, op.created_at)
}
fn apply_realm_create_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_realm_lifecycle(op, op.created_at, crate::kinds::CK_REALM_CREATE)
}
fn apply_realm_update_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_realm_lifecycle(op, op.created_at, crate::kinds::CK_REALM_UPDATE)
}
fn apply_realm_archive_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_realm_lifecycle(op, op.created_at, crate::kinds::CK_REALM_ARCHIVE)
}
fn apply_realm_tombstone_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_realm_lifecycle(op, op.created_at, crate::kinds::CK_REALM_TOMBSTONE)
}
fn apply_realm_destroy_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_realm_lifecycle(op, op.created_at, crate::kinds::CK_REALM_DESTROY)
}
fn apply_erasure_receipt_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_audit_erasure_receipt(op, op.created_at)
}
fn apply_conflict_repair_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_conflict_repair(op, op.created_at)
}
fn apply_space_container_create_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_space_container_create(op, op.created_at)
}
fn apply_space_container_update_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_space_container_update(op, op.created_at)
}
fn apply_space_container_parent_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_space_container_parent(op, op.created_at)
}
fn apply_space_container_archive_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_space_container_lifecycle(
        op,
        op.created_at,
        SpaceContainerLifecycleTransition::Archive,
    )
}
fn apply_space_container_restore_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_space_container_lifecycle(
        op,
        op.created_at,
        SpaceContainerLifecycleTransition::Restore,
    )
}
fn apply_space_container_tombstone_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_space_container_lifecycle(
        op,
        op.created_at,
        SpaceContainerLifecycleTransition::Tombstone,
    )
}
fn apply_flow_create_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_flow_create(op, op.created_at)
}
fn apply_flow_update_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_flow_update(op, op.created_at)
}
fn apply_flow_archive_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_flow_lifecycle(op, op.created_at, ObjectLifecycleTransition::Archive)
}
fn apply_flow_restore_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_flow_lifecycle(op, op.created_at, ObjectLifecycleTransition::Restore)
}
fn apply_flow_position_touch_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_flow_position_touch(op, op.created_at)
}
fn apply_flow_watch_set_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_flow_watch_set(op, op.created_at)
}
fn apply_flow_track_touch_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_flow_track_touch(op, op.created_at)
}

fn apply_morph_create_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_morph_create(op, op.created_at)
}
fn apply_morph_update_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_morph_update(op, op.created_at)
}
fn apply_morph_archive_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_morph_lifecycle(op, op.created_at, ObjectLifecycleTransition::Archive)
}
fn apply_morph_restore_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_morph_lifecycle(op, op.created_at, ObjectLifecycleTransition::Restore)
}

// CKP-0007 — Circle dispatch wrappers.
fn apply_circle_create_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_circle_create(op, op.created_at)
}
fn apply_circle_update_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_circle_update(op, op.created_at)
}
fn apply_circle_archive_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_circle_lifecycle(op, op.created_at, CircleLifecycleState::Archived)
}
fn apply_circle_restore_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_circle_lifecycle(op, op.created_at, CircleLifecycleState::Active)
}
fn apply_circle_tombstone_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_circle_lifecycle(op, op.created_at, CircleLifecycleState::Tombstoned)
}
fn apply_circle_member_state_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_circle_member_state(op, op.created_at)
}

fn apply_applet_registration_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_applet_registration(op, op.created_at)
}
fn apply_applet_discovery_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_applet_discovery(op, op.created_at)
}
fn apply_agent_endpoint_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_agent_endpoint(op, op.created_at)
}

// REDU-1 (R3 spec-sync 2026-05-27, cokret-spec b47ff6ec) — FSM-lattice
// dispatch for `ck.agent.{pause,resume,deactivate}`. Bottom = `Reject`;
// `Deactivated` is terminal (no transition out, no resume after).
fn apply_agent_pause_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_agent_lifecycle(op, AgentLifecycleState::Paused)
}
fn apply_agent_resume_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_agent_lifecycle(op, AgentLifecycleState::Active)
}
fn apply_agent_deactivate_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_agent_lifecycle(op, AgentLifecycleState::Deactivated)
}

// REDU-2 — actor_private_event dispatchers. `reducer_input=false`: do
// NOT advance the anchor frontier / actor_seq. Wire-accepted only;
// projection consumers (sodmin draft inbox, action approval queue) read
// them through the audit log. TODO(R3.1): persist into per-actor
// private projections and surface to the controller.
fn apply_agent_draft_propose_dispatch(
    _s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    ProjectionEffect::AgentPrivateEventAccepted {
        kind: crate::kinds::CK_AGENT_DRAFT_PROPOSE,
        event_id: op.operation_id.to_string(),
    }
}
fn apply_agent_action_request_dispatch(
    _s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    ProjectionEffect::AgentPrivateEventAccepted {
        kind: crate::kinds::CK_AGENT_ACTION_REQUEST,
        event_id: op.operation_id.to_string(),
    }
}
fn apply_agent_action_approve_dispatch(
    _s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    ProjectionEffect::AgentPrivateEventAccepted {
        kind: crate::kinds::CK_AGENT_ACTION_APPROVE,
        event_id: op.operation_id.to_string(),
    }
}
fn apply_agent_action_reject_dispatch(
    _s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    ProjectionEffect::AgentPrivateEventAccepted {
        kind: crate::kinds::CK_AGENT_ACTION_REJECT,
        event_id: op.operation_id.to_string(),
    }
}
/// MID-1..6 (R3.1/R3.2, cokret-spec @ b56cab1) — reducer-side dispatch for
/// `ck.member.identity.update`. The full ordered-log projection +
/// per-actor effective-set / `member_display_state_digest` materialization
/// happens on `AppState::member_identity` (see
/// `routing::events::projection::project_member_identity_update`);
/// `ProjectionState` itself doesn't hold a MemberIdentity facet, so this
/// dispatcher only emits the lifecycle effect.
fn apply_member_identity_update_dispatch(
    _s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    let realm_id = op
        .payload
        .get("realm_id")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let actor_id = op
        .payload
        .get("actor_id")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let segment = op
        .payload
        .get("segment")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    if realm_id.is_empty() || actor_id.is_empty() || segment.is_empty() {
        return ProjectionEffect::Rejected {
            reason: "member_identity_update_missing_subject".to_owned(),
        };
    }
    if segment != "member_identity" {
        return ProjectionEffect::Rejected {
            reason: cokret_sdk::error::ERROR_CODE_MEMBER_IDENTITY_UNKNOWN_SEGMENT.to_owned(),
        };
    }
    ProjectionEffect::MemberIdentityProjected {
        realm_id,
        actor_id,
        segment,
        event_id: op.operation_id.to_string(),
    }
}

/// Dispatch for `ck.realm.delivery_binding_policy`; cell family is
/// `ck.component.realm.delivery_binding_policy.v1`.
fn apply_delivery_binding_policy_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_delivery_binding_policy(op)
}

fn apply_realm_disappearing_policy_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_realm_disappearing_policy(op)
}

fn apply_realm_search_policy_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_realm_search_policy(op)
}
/// R3.1 — upsert a realm-link row into a per-Realm Vec cache. Matches
/// on the composite key `(realm_id, target_realm_id, link_kind)`; an
/// update replaces in place (keeping the original `created_at`).
fn upsert_realm_link(vec: &mut Vec<RealmLinkState>, row: &RealmLinkState) {
    if let Some(existing) = vec.iter_mut().find(|r| {
        r.realm_id == row.realm_id
            && r.target_realm_id == row.target_realm_id
            && r.link_kind == row.link_kind
    }) {
        let created_at = existing.created_at;
        *existing = row.clone();
        existing.created_at = created_at;
    } else {
        vec.push(row.clone());
    }
}

/// R3.2 — extract a string EventRef id from an `EventRef`-shaped
/// payload field. Accepts both the canonical object shape
/// `{"id": "ck:event:...", "role": "..."}` and a bare string form
/// (older client tolerance).
fn extract_event_ref_id(payload: &Value, field: &str) -> Option<String> {
    let v = payload.get(field)?;
    if let Some(s) = v.as_str() {
        return Some(s.to_owned());
    }
    v.get("id").and_then(Value::as_str).map(ToOwned::to_owned)
}

const CAPABILITY_GRANT_CELL_PREFIX: &str = "ck:cell:ck.component.capability.grant.v1:";

#[derive(Clone, Debug)]
struct CapabilityGrantSnapshot {
    realm_id: Option<String>,
    actions: BTreeSet<String>,
    resources: Vec<Value>,
    constraints: Vec<Value>,
    capability_bundles: BTreeSet<String>,
    expires_at: Option<chrono::DateTime<chrono::Utc>>,
    revoked: bool,
}

#[derive(Clone, Debug)]
struct DerivedCapabilityEvaluation {
    effective_actions: Vec<String>,
    effective_resources: Vec<Value>,
    effective_capability_bundles: Vec<String>,
}

fn is_capability_bearing_realm_link_kind(link_kind: &str) -> bool {
    matches!(link_kind, "governed_by" | "inherits_policy_from")
}

fn active_capability_inheritance_link_kind<'a>(
    state: &'a ProjectionState,
    realm_id: &str,
    source_realm_id: &str,
) -> Result<Option<&'a str>, &'static str> {
    if realm_id == source_realm_id {
        return Ok(None);
    }
    let mut saw_active_non_bearing_link = false;
    if let Some(rows) = state.realm_links.get(realm_id) {
        for row in rows {
            if row.target_realm_id != source_realm_id || row.status != "active" {
                continue;
            }
            if is_capability_bearing_realm_link_kind(&row.link_kind) {
                return Ok(Some(row.link_kind.as_str()));
            }
            saw_active_non_bearing_link = true;
        }
    }
    if saw_active_non_bearing_link {
        Err("realm_inheritance_link_kind_not_capability_bearing")
    } else {
        Err("realm_inheritance_parent_link_missing")
    }
}

fn has_active_realm_link_to_source(
    state: &ProjectionState,
    realm_id: &str,
    source_realm_id: &str,
) -> bool {
    state
        .realm_links
        .get(realm_id)
        .map(|rows| {
            rows.iter()
                .any(|row| row.target_realm_id == source_realm_id && row.status == "active")
        })
        .unwrap_or(false)
}

fn inheritance_policy_cell_ref(realm_id: &str) -> Option<CellRef> {
    CellRef::new(format!(
        "ck:cell:ck.component.realm.inheritance_policy.v1:{realm_id}"
    ))
    .ok()
}

fn inheritance_policy_ref_matches(
    state: &ProjectionState,
    realm_id: &str,
    policy_ref: &str,
) -> bool {
    let cell_ref_string = format!("ck:cell:ck.component.realm.inheritance_policy.v1:{realm_id}");
    if policy_ref == cell_ref_string {
        return true;
    }
    if state
        .realm_inheritance_policy(realm_id)
        .map(|policy| policy.operation_id == policy_ref)
        .unwrap_or(false)
    {
        return true;
    }
    let Some(cell_ref) = inheritance_policy_cell_ref(realm_id) else {
        return false;
    };
    let Some(value) = state.cell_value(&cell_ref) else {
        return false;
    };
    value
        .get("operation_id")
        .and_then(Value::as_str)
        .map(|id| id == policy_ref)
        .unwrap_or(false)
}

fn string_set_field(value: &Value, field: &str) -> BTreeSet<String> {
    value
        .get(field)
        .map(string_set_from_value)
        .unwrap_or_default()
}

fn string_set_from_value(value: &Value) -> BTreeSet<String> {
    match value {
        Value::String(s) => std::iter::once(s.clone()).collect(),
        Value::Array(values) => values
            .iter()
            .filter_map(Value::as_str)
            .map(ToOwned::to_owned)
            .collect(),
        _ => BTreeSet::new(),
    }
}

fn value_array_field(value: &Value, field: &str) -> Vec<Value> {
    value
        .get(field)
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
}

fn inheritance_allowed_policies(payload: &Value) -> Vec<String> {
    let mut out = string_set_field(payload, "allowed_policies");
    if let Some(inherits) = payload.get("inherits") {
        out.extend(string_set_field(inherits, "policy_rules"));
    }
    out.into_iter().collect()
}

fn inheritance_allowed_capability_bundles(payload: &Value) -> Vec<String> {
    let mut out = string_set_field(payload, "allowed_capability_bundles");
    if let Some(inherits) = payload.get("inherits") {
        out.extend(string_set_field(inherits, "capability_bundles"));
    }
    out.into_iter().collect()
}

fn derive_requested_actions(payload: &Value) -> BTreeSet<String> {
    let mut out = string_set_field(payload, "actions");
    out.extend(string_set_field(payload, "capabilities"));
    if let Some(bundle) = payload.get("bundle") {
        out.extend(string_set_field(bundle, "actions"));
        out.extend(string_set_field(bundle, "capabilities"));
    }
    out
}

fn derive_requested_resources(payload: &Value) -> Vec<Value> {
    let mut out = value_array_field(payload, "resources");
    out.extend(value_array_field(payload, "resource_selectors"));
    if let Some(bundle) = payload.get("bundle") {
        out.extend(value_array_field(bundle, "resources"));
        out.extend(value_array_field(bundle, "resource_selectors"));
    }
    out
}

fn derive_requested_capability_bundles(payload: &Value) -> BTreeSet<String> {
    let mut out = string_set_field(payload, "capability_bundles");
    out.extend(string_set_field(payload, "allowed_capability_bundles"));
    if let Some(bundle) = payload.get("bundle") {
        out.extend(string_set_from_value(bundle));
        out.extend(string_set_field(bundle, "id"));
        out.extend(string_set_field(bundle, "bundle_id"));
        out.extend(string_set_field(bundle, "capability_bundles"));
        out.extend(string_set_field(bundle, "bundle_ids"));
    }
    out
}

fn expiry_from_payload(payload: &Value) -> Option<chrono::DateTime<chrono::Utc>> {
    payload
        .get("expires_at")
        .and_then(Value::as_str)
        .or_else(|| {
            payload
                .get("bundle")
                .and_then(|bundle| bundle.get("expires_at"))
                .and_then(Value::as_str)
        })
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .map(|dt| dt.with_timezone(&chrono::Utc))
}

fn parse_rfc3339_utc(value: &Value, field: &str) -> Option<chrono::DateTime<chrono::Utc>> {
    value
        .get(field)
        .and_then(Value::as_str)
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .map(|dt| dt.with_timezone(&chrono::Utc))
}

fn capability_grant_cells(state: &ProjectionState) -> impl Iterator<Item = (&CellRef, &Value)> {
    state.cells.iter().filter_map(|(cell_ref, cell_state)| {
        if !cell_ref.as_str().starts_with(CAPABILITY_GRANT_CELL_PREFIX) {
            return None;
        }
        match cell_state {
            CellState::Value(value) => Some((cell_ref, value)),
            CellState::Bottom(_) => None,
        }
    })
}

fn grant_ids_match(value: &Value, id: &str) -> bool {
    [
        "id",
        "grant_id",
        "capability_id",
        "event_id",
        "operation_id",
    ]
    .into_iter()
    .any(|field| value.get(field).and_then(Value::as_str) == Some(id))
        || value
            .get("grant")
            .map(|grant| grant_ids_match(grant, id))
            .unwrap_or(false)
}

fn grant_snapshot_from_value(value: &Value) -> CapabilityGrantSnapshot {
    let body = value
        .get("grant")
        .filter(|grant| grant.is_object())
        .unwrap_or(value);

    let mut actions = string_set_field(body, "actions");
    actions.extend(string_set_field(value, "actions"));

    let mut resources = value_array_field(body, "resources");
    resources.extend(value_array_field(body, "resource_selectors"));
    resources.extend(value_array_field(value, "resources"));
    resources.extend(value_array_field(value, "resource_selectors"));

    let mut constraints = value_array_field(body, "constraints");
    constraints.extend(value_array_field(value, "constraints"));

    let mut capability_bundles = string_set_field(body, "capability_bundles");
    capability_bundles.extend(string_set_field(body, "bundle_ids"));
    capability_bundles.extend(string_set_field(body, "bundles"));
    capability_bundles.extend(string_set_field(body, "bundle"));
    capability_bundles.extend(string_set_field(value, "capability_bundles"));
    capability_bundles.extend(string_set_field(value, "bundle_ids"));
    capability_bundles.extend(string_set_field(value, "bundles"));
    capability_bundles.extend(string_set_field(value, "bundle"));

    let realm_id = body
        .get("realm_id")
        .and_then(Value::as_str)
        .or_else(|| value.get("realm_id").and_then(Value::as_str))
        .map(ToOwned::to_owned);

    let expires_at =
        parse_rfc3339_utc(body, "expires_at").or_else(|| parse_rfc3339_utc(value, "expires_at"));

    let revoked = body
        .get("revoked")
        .and_then(Value::as_bool)
        .unwrap_or(false)
        || value
            .get("revoked")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        || body.get("revoked_at").is_some()
        || body.get("revoked_by").is_some()
        || value.get("revoked_at").is_some()
        || value.get("revoked_by").is_some();

    CapabilityGrantSnapshot {
        realm_id,
        actions,
        resources,
        constraints,
        capability_bundles,
        expires_at,
        revoked,
    }
}

fn grant_snapshot_from_cell_item(
    requested_ref: &str,
    item: &Value,
) -> Option<CapabilityGrantSnapshot> {
    let tag_matches = item.get("tag").and_then(Value::as_str) == Some(requested_ref);
    if let Some(value) = item.get("value") {
        if tag_matches || grant_ids_match(value, requested_ref) {
            return Some(grant_snapshot_from_value(value));
        }
    }
    if tag_matches || grant_ids_match(item, requested_ref) {
        return Some(grant_snapshot_from_value(item));
    }
    None
}

fn find_capability_grant(
    state: &ProjectionState,
    requested_ref: &str,
) -> Option<CapabilityGrantSnapshot> {
    for (_cell_ref, value) in capability_grant_cells(state) {
        if let Some(items) = value.as_array() {
            for item in items {
                if let Some(grant) = grant_snapshot_from_cell_item(requested_ref, item) {
                    return Some(grant);
                }
            }
        } else if let Some(grant) = grant_snapshot_from_cell_item(requested_ref, value) {
            return Some(grant);
        }
    }
    None
}

fn grants_for_realm(state: &ProjectionState, realm_id: &str) -> Vec<CapabilityGrantSnapshot> {
    let mut grants = Vec::new();
    for (_cell_ref, value) in capability_grant_cells(state) {
        if let Some(items) = value.as_array() {
            for item in items {
                let candidate = item.get("value").unwrap_or(item);
                let grant = grant_snapshot_from_value(candidate);
                if grant.realm_id.as_deref() == Some(realm_id) && !grant.revoked {
                    grants.push(grant);
                }
            }
        } else {
            let grant = grant_snapshot_from_value(value);
            if grant.realm_id.as_deref() == Some(realm_id) && !grant.revoked {
                grants.push(grant);
            }
        }
    }
    grants
}

fn parent_capability_grants_allow(
    state: &ProjectionState,
    source_realm_id: &str,
    allowed_policies: &[String],
    allowed_capability_bundles: &[String],
) -> Result<(), &'static str> {
    let grants = grants_for_realm(state, source_realm_id);
    if grants.is_empty() {
        return Ok(());
    }
    let granted_actions: BTreeSet<String> = grants
        .iter()
        .flat_map(|grant| grant.actions.iter().cloned())
        .collect();
    let granted_bundles: BTreeSet<String> = grants
        .iter()
        .flat_map(|grant| grant.capability_bundles.iter().cloned())
        .collect();
    if allowed_policies
        .iter()
        .any(|policy| !granted_actions.contains(policy))
    {
        return Err("realm_inheritance_parent_policy_not_granted");
    }
    if allowed_capability_bundles
        .iter()
        .any(|bundle| !granted_bundles.contains(bundle))
    {
        return Err("realm_inheritance_parent_bundle_not_granted");
    }
    Ok(())
}

fn validate_derived_capability(
    grant: &CapabilityGrantSnapshot,
    policy: &RealmInheritancePolicyState,
    payload: &Value,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<DerivedCapabilityEvaluation, &'static str> {
    if grant.revoked {
        return Err("capability_derived_source_grant_revoked");
    }
    if grant.expires_at.is_some_and(|expires_at| expires_at <= now) {
        return Err("capability_derived_source_grant_expired");
    }
    if grant
        .realm_id
        .as_deref()
        .is_some_and(|id| id != policy.source_realm_id)
    {
        return Err("capability_derived_source_grant_realm_mismatch");
    }

    let allowed_bundles: BTreeSet<String> =
        policy.allowed_capability_bundles.iter().cloned().collect();
    if !grant.capability_bundles.is_empty()
        && grant
            .capability_bundles
            .iter()
            .any(|bundle| !allowed_bundles.contains(bundle))
    {
        return Err("capability_derived_source_bundle_not_allowed");
    }

    let requested_bundles = derive_requested_capability_bundles(payload);
    if requested_bundles
        .iter()
        .any(|bundle| !allowed_bundles.contains(bundle))
    {
        return Err("capability_derived_bundle_not_allowed");
    }

    let requested_actions = derive_requested_actions(payload);
    if requested_actions
        .iter()
        .any(|action| !grant.actions.contains(action))
    {
        return Err("capability_derived_action_widening");
    }

    let requested_resources = derive_requested_resources(payload);
    if !requested_resources.is_empty()
        && requested_resources
            .iter()
            .any(|resource| !grant.resources.iter().any(|source| source == resource))
    {
        return Err("capability_derived_resource_widening");
    }

    if let Some(derived_expires_at) = expiry_from_payload(payload) {
        if grant
            .expires_at
            .is_some_and(|source_expires_at| derived_expires_at > source_expires_at)
        {
            return Err("capability_derived_expiry_widening");
        }
    }

    let requested_constraints = value_array_field(payload, "constraints");
    if !requested_constraints.is_empty()
        && grant.constraints.iter().any(|source| {
            !requested_constraints
                .iter()
                .any(|derived| derived == source)
        })
    {
        return Err("capability_derived_constraint_widening");
    }

    let effective_actions = if requested_actions.is_empty() {
        grant.actions.iter().cloned().collect()
    } else {
        requested_actions.into_iter().collect()
    };
    let effective_resources = if requested_resources.is_empty() {
        grant.resources.clone()
    } else {
        requested_resources
    };
    let effective_capability_bundles = if requested_bundles.is_empty() {
        grant
            .capability_bundles
            .intersection(&allowed_bundles)
            .cloned()
            .collect()
    } else {
        requested_bundles.into_iter().collect()
    };

    Ok(DerivedCapabilityEvaluation {
        effective_actions,
        effective_resources,
        effective_capability_bundles,
    })
}

/// R3.1 — dispatch for `ck.realm.link`. Projects the typed link payload
/// into the `ck.component.realm.link.v1` or_set cell + structured
/// `realm_links` / `realm_links_inbound` caches.
fn apply_realm_link_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_realm_link(op, op.created_at)
}

/// R3.2 — dispatch for `ck.realm.inheritance_policy`. Projects the
/// cas-register cell + structured cache; validates parent grant bounds
/// when the relevant parent grant cells are available.
fn apply_realm_inheritance_policy_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_realm_inheritance_policy(op, op.created_at)
}

/// R3.2 — dispatch for `ck.capability.derived`. Projects the cas-
/// register cell + structured cache after reducer-side derive evaluation.
fn apply_capability_derived_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_capability_derived(op, op.created_at)
}

/// R3.3 — dispatch for `ck.realm.audit_policy_downgrade`. Appends the
/// downgrade entry to the ordered-log audit cell + the structured
/// side-band cache.
fn apply_realm_audit_policy_downgrade_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_realm_audit_policy_downgrade(op, op.created_at)
}

// ── G3.S1: MLS lifecycle dispatch adapters ────────────────────────────
//
// Each adapter forwards to the free function in `reducer::mls`. The
// inline `ProjectionState` impls stay out of `reducer.rs` so the MLS
// module can grow independently (see top-level `pub mod mls;`).
//
// Canonical event kinds per
// `cokret-spec/spec/v1/artifacts/schemas/event-envelope.schema.json`: a single
// `ck.mls.keypackage` kind covers both publish and claim. The reducer
// dispatches on `payload.action == "publish" | "claim"` (the publish-
// vs-claim split lives at the HTTP operation_id layer:
// `ck.self.keys.keypackages.upload` vs `ck.self.keys.keypackages.claim`).

fn apply_mls_keypackage_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    match op.payload.get("action").and_then(Value::as_str) {
        Some("publish") => mls::apply_keypackage_publish(s, op),
        Some("claim") => mls::apply_keypackage_claim(s, op),
        Some(other) => ProjectionEffect::Rejected {
            reason: format!("mls_keypackage_action_unknown:{other}"),
        },
        None => ProjectionEffect::Rejected {
            reason: "mls_keypackage_action_missing".to_owned(),
        },
    }
}

fn apply_mls_welcome_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    mls::apply_welcome_enqueue(s, op)
}

fn apply_mls_genesis_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    mls::apply_group_genesis(s, op)
}

fn apply_mls_commit_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    mls::apply_commit_epoch(s, op)
}

/// R1.2 — pure validation for a `ck.member.state{join,routable}`
/// `delivery_binding` against a projected
/// `ck.realm.delivery_binding_policy` payload. Returns `Ok(())` when the
/// binding is admissible; `Err(reason_code)` otherwise. Reason codes
/// mirror the spec join-policy.md §5.1 catalogue.
fn enforce_delivery_binding_policy(
    policy: &Value,
    binding: &serde_json::Map<String, Value>,
) -> Result<(), &'static str> {
    let binding_source = binding
        .get("binding_source")
        .and_then(Value::as_str)
        .unwrap_or("");
    let recipient_service_did = binding
        .get("recipient_service_did")
        .and_then(Value::as_str)
        .unwrap_or("");

    // `allow_binding_sources` is an explicit allow-list. Missing or
    // empty means "no source admissible" — fail closed.
    let allow_sources: Vec<&str> = policy
        .get("allow_binding_sources")
        .and_then(Value::as_array)
        .map(|arr| arr.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    if !allow_sources.contains(&binding_source) {
        return Err("binding_source_not_allowed");
    }
    // `did_document_default` requires the toggle even if the source list
    // includes it (spec §5.1.3 — organization/compliance Realms must set
    // `allow_did_document_default=false`).
    if binding_source == "did_document_default"
        && !policy
            .get("allow_did_document_default")
            .and_then(Value::as_bool)
            .unwrap_or(false)
    {
        return Err("binding_source_not_allowed");
    }

    // `allowed_recipient_services`: empty allow-list means unrestricted
    // (per spec, the policy may omit the list to opt out of explicit
    // recipient pinning); non-empty list MUST contain the binding's
    // recipient_service_did.
    let allowed_recipients: Vec<&str> = policy
        .get("allowed_recipient_services")
        .and_then(Value::as_array)
        .map(|arr| arr.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    if !allowed_recipients.is_empty() && !allowed_recipients.contains(&recipient_service_did) {
        return Err("recipient_service_not_allowed");
    }

    // `binding_source=explicit` requires a signed `service_acceptance_ref`.
    if binding_source == "explicit"
        && !binding
            .get("service_acceptance_ref")
            .map(|v| v.is_string())
            .unwrap_or(false)
    {
        return Err("service_acceptance_missing");
    }

    // Frontier check: if the policy declares `policy_frontier`, the
    // binding's carried `delivery_binding_frontier` MUST match or
    // exceed it lexicographically. Missing carried frontier = stale.
    if let Some(policy_frontier) = policy.get("policy_frontier").and_then(Value::as_str) {
        let carried = binding
            .get("delivery_binding_frontier")
            .and_then(Value::as_str);
        match carried {
            None => return Err("delivery_binding_stale"),
            Some(c) if c < policy_frontier => return Err("delivery_binding_stale"),
            _ => {}
        }
    }
    Ok(())
}

/// Build the canonical `event_kind → ApplyFn` registry consumed by
/// [`ProjectionState::apply`]. Public so out-of-crate tests can assert
/// the registry covers every canonical kind they care about.
pub fn default_apply_registry() -> std::collections::HashMap<&'static str, ApplyFn> {
    use crate::kinds::*;
    let mut m: std::collections::HashMap<&'static str, ApplyFn> =
        std::collections::HashMap::with_capacity(40);
    m.insert(CK_MESSAGE_CREATE, apply_message_dispatch as ApplyFn);
    m.insert(CK_MESSAGE_REVISE, apply_message_revise_dispatch);
    m.insert(CK_MESSAGE_REDACT, apply_redaction_dispatch);
    m.insert(CK_REDACTION, apply_redaction_dispatch);
    m.insert(CK_REACTION_ADD, apply_reaction_add_dispatch);
    m.insert(CK_REACTION_REMOVE, apply_reaction_remove_dispatch);
    m.insert(CK_RSVP_SET, apply_rsvp_set_dispatch);
    m.insert(CK_PIN_ADD, apply_pin_dispatch);
    m.insert(CK_PIN_REMOVE, apply_pin_dispatch);
    m.insert(CK_PIN_REORDER, apply_pin_dispatch);
    m.insert(CK_READ_MARKER, apply_read_cursor_dispatch);
    m.insert(CK_RELATION_CREATE, apply_relation_create_dispatch);
    m.insert(CK_RELATION_UPDATE, apply_relation_update_dispatch);
    m.insert(CK_RELATION_DELETE, apply_relation_delete_dispatch);
    m.insert(CK_CONTAINER_MOVE_ITEM, apply_container_position_dispatch);
    m.insert(CK_CONTAINER_REBALANCE, apply_container_position_dispatch);
    m.insert(CK_MEMBER_STATE, apply_membership_dispatch);
    // MID-1..6 (R3.1/R3.2 spec-sync, cokret-spec @ b56cab1) —
    // `ck.member.identity.update`. Cell family
    // `ck.component.member.identity.v1`, lattice `ordered_log`, bottom
    // `expose`. The ordered-log projection (effective-set filter,
    // member_display_state_digest materialization) lives on
    // `AppState::member_identity`
    // (see `routing::events::projection::project_member_identity_update`)
    // because it spans cells; the in-process reducer just records that
    // the event was accepted so subscribers observe the lifecycle effect.
    m.insert(
        CK_MEMBER_IDENTITY_UPDATE,
        apply_member_identity_update_dispatch,
    );
    m.insert(CK_REALM_CREATE, apply_realm_create_dispatch);
    m.insert(CK_REALM_UPDATE, apply_realm_update_dispatch);
    m.insert(CK_REALM_ARCHIVE, apply_realm_archive_dispatch);
    m.insert(CK_REALM_TOMBSTONE, apply_realm_tombstone_dispatch);
    m.insert(CK_REALM_DESTROY, apply_realm_destroy_dispatch);
    m.insert(CK_CONFLICT_REPAIR, apply_conflict_repair_dispatch);
    m.insert(CK_AUDIT_ERASURE_RECEIPT, apply_erasure_receipt_dispatch);
    m.insert(
        CK_SPACE_CONTAINER_CREATE,
        apply_space_container_create_dispatch,
    );
    m.insert(
        CK_SPACE_CONTAINER_UPDATE,
        apply_space_container_update_dispatch,
    );
    m.insert(
        CK_SPACE_CONTAINER_PARENT,
        apply_space_container_parent_dispatch,
    );
    m.insert(
        CK_SPACE_CONTAINER_ARCHIVE,
        apply_space_container_archive_dispatch,
    );
    m.insert(
        CK_SPACE_CONTAINER_RESTORE,
        apply_space_container_restore_dispatch,
    );
    m.insert(
        CK_SPACE_CONTAINER_TOMBSTONE,
        apply_space_container_tombstone_dispatch,
    );
    m.insert(CK_FLOW_CREATE, apply_flow_create_dispatch);
    m.insert(CK_FLOW_UPDATE, apply_flow_update_dispatch);
    m.insert(CK_FLOW_ARCHIVE, apply_flow_archive_dispatch);
    m.insert(CK_FLOW_RESTORE, apply_flow_restore_dispatch);
    m.insert(CK_FLOW_MOVE, apply_flow_position_touch_dispatch);
    m.insert(CK_FLOW_REORDER, apply_flow_position_touch_dispatch);
    m.insert(CK_FLOW_WATCH_SET, apply_flow_watch_set_dispatch);
    // Unified tracks patch. Payload-shape validation (presence of `tracks`
    // patch map) lives in the wire validator. TODO: apply patch ops
    // against soland-side Flow.tracks projection once the server-side
    // projection carries the tracks map.
    m.insert(CK_FLOW_TRACKS_UPDATE, apply_flow_track_touch_dispatch);
    m.insert(CK_MORPH_CREATE, apply_morph_create_dispatch);
    m.insert(CK_MORPH_UPDATE, apply_morph_update_dispatch);
    m.insert(CK_MORPH_ARCHIVE, apply_morph_archive_dispatch);
    m.insert(CK_MORPH_RESTORE, apply_morph_restore_dispatch);
    // CKP-0007 — Circle lifecycle / membership dispatch. The seventh
    // active kind, `ck.circle.anchor_commit`, is reducer-derived (sub-
    // anchor on the Circle's profile cadence) and listed in the SDK's
    // `NON_REDUCER_EVENT_KINDS` set, so no dispatch entry is added for
    // it here.
    m.insert(CK_CIRCLE_CREATE, apply_circle_create_dispatch);
    m.insert(CK_CIRCLE_UPDATE, apply_circle_update_dispatch);
    m.insert(CK_CIRCLE_ARCHIVE, apply_circle_archive_dispatch);
    m.insert(CK_CIRCLE_RESTORE, apply_circle_restore_dispatch);
    m.insert(CK_CIRCLE_TOMBSTONE, apply_circle_tombstone_dispatch);
    m.insert(CK_CIRCLE_MEMBER_STATE, apply_circle_member_state_dispatch);
    m.insert(CK_APPLET_REGISTRATION, apply_applet_registration_dispatch);
    m.insert(CK_APPLET_DISCOVERY, apply_applet_discovery_dispatch);
    m.insert(CK_AGENT_ENDPOINT, apply_agent_endpoint_dispatch);
    // REDU-1 (R3 spec-sync) — agent lifecycle FSM dispatch. bottom=reject,
    // deactivate is terminal.
    m.insert(CK_AGENT_PAUSE, apply_agent_pause_dispatch);
    m.insert(CK_AGENT_RESUME, apply_agent_resume_dispatch);
    m.insert(CK_AGENT_DEACTIVATE, apply_agent_deactivate_dispatch);
    // REDU-2 — actor_private_event kinds (reducer_input=false). These
    // accept but do NOT advance the anchor frontier / actor_seq;
    // downstream consumers read them from the audit log.
    m.insert(CK_AGENT_DRAFT_PROPOSE, apply_agent_draft_propose_dispatch);
    m.insert(CK_AGENT_ACTION_REQUEST, apply_agent_action_request_dispatch);
    m.insert(CK_AGENT_ACTION_APPROVE, apply_agent_action_approve_dispatch);
    m.insert(CK_AGENT_ACTION_REJECT, apply_agent_action_reject_dispatch);
    // delivery_binding_policy is Realm-scoped with cell_family
    // `ck.component.realm.delivery_binding_policy.v1`.
    m.insert(
        CK_REALM_DELIVERY_BINDING_POLICY,
        apply_delivery_binding_policy_dispatch,
    );
    m.insert(
        CK_REALM_DISAPPEARING_POLICY,
        apply_realm_disappearing_policy_dispatch,
    );
    m.insert(CK_REALM_SEARCH_POLICY, apply_realm_search_policy_dispatch);
    m.insert(CK_DEVICE_PUSH_ROUTE, apply_device_push_route_dispatch);
    // R3.1 / R3.2 / R3.3 — Realm-governance event kinds. Each writes a
    // cell + a structured side-band cache; see the per-kind apply
    // helpers for cell-family naming.
    m.insert(CK_REALM_LINK, apply_realm_link_dispatch);
    m.insert(
        CK_REALM_INHERITANCE_POLICY,
        apply_realm_inheritance_policy_dispatch,
    );
    m.insert(CK_CAPABILITY_DERIVED, apply_capability_derived_dispatch);
    m.insert(
        CK_REALM_AUDIT_POLICY_DOWNGRADE,
        apply_realm_audit_policy_downgrade_dispatch,
    );
    // G3.S1: MLS lifecycle. KeyPackage publish/claim (atomic CAS),
    // Welcome to-device persistence, commit monotonic-epoch bump, and
    // governance covered-frontier accumulation.
    // Canonical event kinds — the publish/claim distinction lives at the
    // HTTP operation_id layer and is conveyed inside the kind's payload
    // via `action ∈ {"publish","claim"}`; the event log itself stores
    // only the canonical `ck.mls.keypackage` kind.
    // Deferred (TODO(G3.S1-followup)): decryption_pending. See
    // `reducer/mls.rs`.
    m.insert(CK_MLS_KEYPACKAGE, apply_mls_keypackage_dispatch);
    m.insert(CK_MLS_WELCOME, apply_mls_welcome_dispatch);
    m.insert(CK_MLS_GENESIS, apply_mls_genesis_dispatch);
    m.insert(CK_MLS_COMMIT, apply_mls_commit_dispatch);
    // G3.S9: extensions (applet/bot/tsp)
    m.insert(CK_EXTENSIONS_BOT_REGISTER, apply_bot_register);
    m.insert(CK_EXTENSIONS_BOT_REVOKE, apply_bot_revoke);
    m.insert(
        CK_EXTENSIONS_TSP_TRANSPORT_DECLARE,
        apply_tsp_transport_declare,
    );
    m.insert(CK_EXTENSIONS_TSP_ROUTE_ESTABLISH, apply_tsp_route_establish);
    m.insert(CK_EXTENSIONS_TSP_AUDIT_APPEND, apply_tsp_audit_append);
    // G3.S2: policy server cell
    m.insert(CK_REALM_POLICY_SERVER, apply_realm_policy_server_dispatch);
    m
}

fn conflict_heads_from_payload(payload: &Value) -> Vec<String> {
    payload
        .get("conflict_heads")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|head| head.as_str().map(ToOwned::to_owned))
        .filter(|head| !head.trim().is_empty())
        .collect()
}

fn bottom_head_ids(bottom: &cokret_sdk::Bottom) -> BTreeSet<String> {
    bottom
        .heads
        .iter()
        .filter_map(|head| head.get("move_id").and_then(Value::as_str))
        .map(ToOwned::to_owned)
        .collect()
}

fn augment_repair_winner_value(
    winner: Value,
    heads: &[String],
    operation_id: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> Value {
    let repair_of = Value::Array(heads.iter().cloned().map(Value::String).collect());
    let updated_at = utc_timestamp_z(now);
    match winner {
        Value::Object(mut object) => {
            object.insert("repair_of".to_owned(), repair_of);
            object.insert(
                "operation_id".to_owned(),
                Value::String(operation_id.to_owned()),
            );
            object.insert("updated_at".to_owned(), Value::String(updated_at));
            Value::Object(object)
        }
        other => serde_json::json!({
            "value": other,
            "repair_of": repair_of,
            "operation_id": operation_id,
            "updated_at": updated_at,
        }),
    }
}

fn utc_timestamp_z(now: chrono::DateTime<chrono::Utc>) -> String {
    cokret_sdk::canonical::format_timestamp_canonical(now)
}

fn realm_organization_realm_id_from_cell(cell_id: &str) -> Option<String> {
    cell_id
        .strip_prefix("ck:cell:ck.component.realm.organization.v1:")
        .filter(|realm_id| realm_id.starts_with("ck:realm:"))
        .map(ToOwned::to_owned)
}

// G3.S2: dispatch adapter for `ck.realm.policy_server`. The reducer
// helper lives in the dedicated `reducer::realm_policy_server` module;
// this adapter normalises its `(state, op) -> effect` signature to the
// registry's `(state, op, hlc) -> effect` shape.
fn apply_realm_policy_server_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    crate::reducer::realm_policy_server::apply_realm_policy_server(s, op)
}

fn apply_device_push_route_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_device_push_route(op)
}

// G3.S9 — adapter dispatches for the extensions module. These call
// into the process-local registries in
// `routing::extensions::{bot_actor, tsp}` (which own the structured
// state for the stub) and always return `ProjectionEffect::Ignored`
// because the central `ProjectionState` has no bot/tsp fields yet.
// Full integration is a follow-up — see
// `routing::extensions::mod.rs` TODO(G3.S9-followup).
fn apply_bot_register(
    _s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    let _ = crate::routing::extensions::bot_actor::apply_bot_register(op);
    ProjectionEffect::Ignored
}
fn apply_bot_revoke(
    _s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    let _ = crate::routing::extensions::bot_actor::apply_bot_revoke(op);
    ProjectionEffect::Ignored
}
fn apply_tsp_transport_declare(
    _s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    let _ = crate::routing::extensions::tsp::apply_tsp_transport_declare(op);
    ProjectionEffect::Ignored
}
fn apply_tsp_route_establish(
    _s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    let _ = crate::routing::extensions::tsp::apply_tsp_route_establish(op);
    ProjectionEffect::Ignored
}
fn apply_tsp_audit_append(
    _s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    let _ = crate::routing::extensions::tsp::apply_tsp_audit_append(op);
    ProjectionEffect::Ignored
}

static APPLY_REGISTRY: std::sync::LazyLock<std::collections::HashMap<&'static str, ApplyFn>> =
    std::sync::LazyLock::new(default_apply_registry);

fn empty_push_route_cell() -> PushRouteCellValue {
    PushRouteCellValue {
        push_target_id: None,
        push_gateway_did: None,
        encryption_key: None,
        capabilities: Vec::new(),
        revoked: false,
        revoked_targets: Vec::new(),
    }
}

fn push_route_cell_ref(subject: &PushRouteSubject) -> Option<CellRef> {
    let cell_subject = cokret_sdk::composite_subject(&[
        subject.recipient_service_did.as_str(),
        subject.principal_id.as_str(),
        subject.device_id.as_str(),
        subject.push_route.as_str(),
    ])
    .ok()?;
    CellRef::new(format!(
        "ck:cell:ck.component.device.push_route.v1:{cell_subject}"
    ))
    .ok()
}

fn object_field_string(
    object: &serde_json::Map<String, Value>,
    field_name: &str,
) -> Option<String> {
    // spec 9dabf26: Flow profile fields live under `metadata.fields`, not at
    // the object root. The Flow-position component (board_space_id /
    // list_space_id / rank) is read from there.
    object
        .get("metadata")
        .and_then(Value::as_object)
        .and_then(|metadata| metadata.get("fields"))
        .and_then(Value::as_object)
        .and_then(|fields| fields.get(field_name))
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(ToOwned::to_owned)
}

fn component_field_string(payload: &Value, family: &str, field_name: &str) -> Option<String> {
    payload
        .get("components")
        .and_then(Value::as_array)
        .and_then(|components| {
            components.iter().find(|component| {
                component
                    .get("family")
                    .and_then(Value::as_str)
                    .is_some_and(|value| value == family)
            })
        })
        .and_then(|component| component.get(field_name))
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(ToOwned::to_owned)
}

fn flow_position_from_create_payload(
    payload: &Value,
    object: &serde_json::Map<String, Value>,
) -> Option<(String, String, Option<String>)> {
    let board_space_id = object_field_string(object, "board_space_id").or_else(|| {
        component_field_string(payload, "ck.component.flow.position.v1", "board_space_id")
    })?;
    let list_space_id = object_field_string(object, "list_space_id").or_else(|| {
        component_field_string(payload, "ck.component.flow.position.v1", "list_space_id")
    })?;
    let rank = object_field_string(object, "rank")
        .or_else(|| component_field_string(payload, "ck.component.flow.position.v1", "rank"));
    Some((board_space_id, list_space_id, rank))
}

fn flow_position_from_lifecycle_payload(
    payload: &Value,
) -> Option<(String, String, Option<String>)> {
    let board_space_id = payload
        .get("board_space_id")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())?
        .to_owned();
    let list_space_id = payload
        .get("target_space_id")
        .or_else(|| payload.get("list_space_id"))
        .or_else(|| payload.get("space_id"))
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())?
        .to_owned();
    let rank = payload
        .get("rank")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(ToOwned::to_owned);
    Some((board_space_id, list_space_id, rank))
}

enum PatchAction<'a> {
    Set(&'a Value),
    Unset,
    Ignore,
}

fn patch_action(value: &Value) -> PatchAction<'_> {
    let Some(object) = value.as_object() else {
        return PatchAction::Set(value);
    };
    let Some(op) = object.get("$op").and_then(Value::as_str) else {
        return PatchAction::Set(value);
    };
    match op {
        "set" | "add" => object
            .get("value")
            .map(PatchAction::Set)
            .unwrap_or(PatchAction::Ignore),
        "unset" | "remove" => PatchAction::Unset,
        _ => PatchAction::Ignore,
    }
}

fn patch_string_value(
    patch: &serde_json::Map<String, Value>,
    path: &str,
) -> Option<Option<String>> {
    match patch.get(path).map(patch_action)? {
        PatchAction::Set(value) => value
            .as_str()
            .filter(|value| !value.trim().is_empty())
            .map(|value| Some(value.to_owned())),
        PatchAction::Unset => Some(None),
        PatchAction::Ignore => None,
    }
}

fn flow_status_patch_target(payload: &Value) -> Result<Option<String>, &'static str> {
    let Some(patch) = payload.get("patch").and_then(Value::as_object) else {
        return Ok(None);
    };
    let value = patch
        .get("metadata.fields.status")
        .or_else(|| {
            patch
                .get("metadata.fields")
                .and_then(|fields_patch| match patch_action(fields_patch) {
                    PatchAction::Set(value) => value.get("status"),
                    PatchAction::Unset | PatchAction::Ignore => None,
                })
        })
        .or_else(|| {
            patch
                .get("metadata")
                .and_then(|metadata_patch| match patch_action(metadata_patch) {
                    PatchAction::Set(value) => {
                        value.get("fields").and_then(|fields| fields.get("status"))
                    }
                    PatchAction::Unset | PatchAction::Ignore => None,
                })
        });
    let Some(value) = value else {
        return Ok(None);
    };
    match patch_action(value) {
        PatchAction::Set(value) => value
            .as_str()
            .filter(|value| !value.trim().is_empty())
            .map(|value| Some(value.to_owned()))
            .ok_or("flow_status_invalid"),
        PatchAction::Unset => Err("flow_status_invalid"),
        PatchAction::Ignore => Ok(None),
    }
}

fn patch_metadata_string_value(
    patch: &serde_json::Map<String, Value>,
    key: &str,
) -> Option<Option<String>> {
    let dotted = format!("metadata.{key}");
    if let Some(value) = patch_string_value(patch, &dotted) {
        return Some(value);
    }
    patch
        .get("metadata")
        .and_then(|metadata_patch| match patch_action(metadata_patch) {
            PatchAction::Set(value) => value.get(key).and_then(|value| {
                value
                    .as_str()
                    .filter(|value| !value.trim().is_empty())
                    .map(|value| Some(value.to_owned()))
            }),
            PatchAction::Unset => Some(None),
            PatchAction::Ignore => None,
        })
}

fn flow_metadata_fields_value(value: &Value) -> Option<BTreeMap<String, Value>> {
    value.as_object().map(|fields| {
        fields
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect::<BTreeMap<_, _>>()
    })
}

fn apply_metadata_fields_value(fields: &mut BTreeMap<String, Value>, value: &Value) {
    if let Some(values) = flow_metadata_fields_value(value) {
        for (field_name, field_value) in values {
            fields.insert(field_name, field_value);
        }
    }
}

fn flow_status_transition_allowed(current: &str, next: &str) -> bool {
    if current == next {
        return true;
    }
    match current {
        "todo" => next == "in_progress",
        "in_progress" => matches!(next, "done" | "blocked"),
        "blocked" => matches!(next, "in_progress" | "cancelled"),
        "investigating" => next == "mitigated",
        "mitigated" => next == "resolved",
        _ => true,
    }
}

fn flow_id_from_payload(payload: &Value) -> Option<&str> {
    payload
        .get("flow_id")
        .or_else(|| payload.get("target_ref"))
        .or_else(|| payload.get("object_ref"))
        .and_then(Value::as_str)
        .filter(|value| value.starts_with("ck:flow:"))
}

fn check_flow_status_patch(
    flow: &FlowProjection,
    payload: &Value,
) -> Result<Option<String>, &'static str> {
    let Some(next_status) = flow_status_patch_target(payload)? else {
        return Ok(None);
    };
    let Some(current_status) = flow.fields.get("status").and_then(Value::as_str) else {
        return Ok(Some(next_status));
    };
    if flow_status_transition_allowed(current_status, &next_status) {
        return Ok(Some(next_status));
    }
    Err("flow_status_transition_invalid")
}

fn apply_flow_fields_patch(
    fields: &mut BTreeMap<String, Value>,
    patch: &serde_json::Map<String, Value>,
) {
    for (path, value) in patch {
        if path == "metadata" {
            match patch_action(value) {
                PatchAction::Set(Value::Object(metadata)) => {
                    if let Some(value) = metadata.get("fields") {
                        apply_metadata_fields_value(fields, value);
                    }
                }
                PatchAction::Unset => fields.clear(),
                PatchAction::Set(_) | PatchAction::Ignore => {}
            }
            continue;
        }
        if path == "metadata.fields" {
            match patch_action(value) {
                PatchAction::Set(value) => apply_metadata_fields_value(fields, value),
                PatchAction::Unset => fields.clear(),
                PatchAction::Ignore => {}
            }
            continue;
        }
        let Some(field_name) = path.strip_prefix("metadata.fields.") else {
            continue;
        };
        if field_name.is_empty() {
            continue;
        }
        match patch_action(value) {
            PatchAction::Set(value) => {
                fields.insert(field_name.to_owned(), value.clone());
            }
            PatchAction::Unset => {
                fields.remove(field_name);
            }
            PatchAction::Ignore => {}
        }
    }
}

/// Apply a `ck.flow.update`-style patch to a Morph's `fields` map. Unlike Flow
/// (whose profile fields moved under `metadata.fields` in spec 9dabf26), the
/// Morph object keeps `fields` at the object root (morph.schema.json), so its
/// patch paths are root-level `fields` / `fields.<name>`.
fn apply_morph_fields_patch(
    fields: &mut BTreeMap<String, Value>,
    patch: &serde_json::Map<String, Value>,
) {
    for (path, value) in patch {
        if path == "fields" {
            match patch_action(value) {
                PatchAction::Set(value) => apply_metadata_fields_value(fields, value),
                PatchAction::Unset => fields.clear(),
                PatchAction::Ignore => {}
            }
            continue;
        }
        let Some(field_name) = path.strip_prefix("fields.") else {
            continue;
        };
        if field_name.is_empty() {
            continue;
        }
        match patch_action(value) {
            PatchAction::Set(value) => {
                fields.insert(field_name.to_owned(), value.clone());
            }
            PatchAction::Unset => {
                fields.remove(field_name);
            }
            PatchAction::Ignore => {}
        }
    }
}

fn object_map_to_fields(object: Option<&Value>) -> BTreeMap<String, Value> {
    object
        .and_then(Value::as_object)
        .map(|fields| {
            fields
                .iter()
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect::<BTreeMap<_, _>>()
        })
        .unwrap_or_default()
}

fn string_array_field(object: &serde_json::Map<String, Value>, key: &str) -> Vec<String> {
    let Some(value) = object.get(key) else {
        return Vec::new();
    };
    if let Some(items) = value.as_array() {
        return items
            .iter()
            .filter_map(Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .map(ToOwned::to_owned)
            .collect::<Vec<_>>();
    }
    value
        .as_object()
        .map(|items| {
            items
                .iter()
                .filter_map(|(facet, enabled)| enabled.as_bool().unwrap_or(true).then_some(facet))
                .filter(|value| !value.trim().is_empty())
                .cloned()
                .collect::<Vec<_>>()
        })
        .unwrap_or_default()
}

fn projection_object_realm_id(
    object: &serde_json::Map<String, Value>,
    operation: &Operation,
) -> String {
    object
        .get("realm_id")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| operation.realm_id.to_string())
}

fn morph_document_body(fields: &BTreeMap<String, Value>) -> Option<Value> {
    fields
        .get("document")
        .or_else(|| fields.get("body"))
        .cloned()
        .filter(|value| !value.is_null())
}

fn document_version_from_operation(
    morph_id: &str,
    operation: &Operation,
    body: Value,
) -> DocumentVersionProjection {
    let event_id = operation
        .payload
        .get("event_id")
        .and_then(Value::as_str)
        .unwrap_or(operation.operation_id.as_str())
        .to_owned();
    let body_digest = cokret_sdk::canonical::canonical_sha256(&body)
        .unwrap_or_else(|_| cokret_sdk::canonical::sha256_digest(body.to_string().as_bytes()));
    DocumentVersionProjection {
        version_id: format!("{morph_id}:version:{event_id}"),
        event_id,
        author: operation
            .payload
            .get("sender")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned(),
        created_at: operation.created_at,
        body_digest,
        body,
    }
}

fn operation_encryption_profile(operation: &Operation) -> Option<&str> {
    operation
        .payload
        .get("encryption_profile")
        .and_then(Value::as_str)
        .or_else(|| {
            operation
                .payload
                .get("object")
                .and_then(|object| object.get("encryption_profile"))
                .and_then(Value::as_str)
        })
}

fn operation_touches_encryption_profile(operation: &Operation) -> bool {
    operation.payload.get("encryption_profile").is_some()
        || operation
            .payload
            .get("object")
            .is_some_and(|object| value_has_direct_field(object, "encryption_profile"))
        || operation_patch_touches_field(&operation.payload, "encryption_profile")
}

fn value_has_direct_field(value: &Value, field: &str) -> bool {
    value
        .as_object()
        .is_some_and(|object| object.contains_key(field))
}

fn operation_patch_touches_field(payload: &Value, field: &str) -> bool {
    payload
        .get("patch")
        .and_then(Value::as_object)
        .is_some_and(|patch| {
            patch.iter().any(|(key, value)| {
                patch_key_touches_field(key, field)
                    || (key == "object" && patch_value_has_direct_field(value, field))
            })
        })
}

fn patch_key_touches_field(key: &str, field: &str) -> bool {
    let dotted = format!("{field}.");
    let pointer = format!("/{field}");
    let pointer_child = format!("/{field}/");
    let object_dotted = format!("object.{field}");
    let object_dotted_child = format!("object.{field}.");
    let object_pointer = format!("/object/{field}");
    let object_pointer_child = format!("/object/{field}/");
    key == field
        || key.starts_with(&dotted)
        || key == pointer
        || key.starts_with(&pointer_child)
        || key == object_dotted
        || key.starts_with(&object_dotted_child)
        || key == object_pointer
        || key.starts_with(&object_pointer_child)
}

fn patch_value_has_direct_field(value: &Value, field: &str) -> bool {
    value
        .get("value")
        .unwrap_or(value)
        .as_object()
        .is_some_and(|object| object.contains_key(field))
}

fn encryption_profile_requires_content_encryption(profile: Option<&str>) -> bool {
    profile
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .is_some_and(|profile| !matches!(profile, "none" | "plaintext" | "allow_plaintext"))
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

    fn apply_device_push_route(&mut self, operation: &Operation) -> ProjectionEffect {
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
    /// `None` if the cell hasn't been observed (no anchored Move ever wrote
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

    fn store_flow_position_relation(
        &mut self,
        flow_id: &str,
        realm_id: &str,
        board_space_id: &str,
        list_space_id: &str,
        rank: Option<&str>,
        now: chrono::DateTime<chrono::Utc>,
    ) {
        let relation_id = format!("ck:relation:kanban.position:{board_space_id}:{flow_id}");
        let relation = self
            .relations
            .entry(relation_id.clone())
            .or_insert_with(|| RelationState {
                relation_id: relation_id.clone(),
                realm_id: realm_id.to_owned(),
                relation_kind: "contains".to_owned(),
                from_ref: Some(list_space_id.to_owned()),
                to_ref: Some(flow_id.to_owned()),
                fields: BTreeMap::new(),
                state: "active".to_owned(),
                created_at: now,
                updated_at: now,
            });
        relation.realm_id = realm_id.to_owned();
        relation.relation_kind = "contains".to_owned();
        relation.from_ref = Some(list_space_id.to_owned());
        relation.to_ref = Some(flow_id.to_owned());
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
    /// each cell's lattice. Called after every successful `apply_anchor`
    /// in the Move/Anchor pipeline
    /// (`routing::federation::move_anchor::submit_anchor` plus
    /// `crate::anchorer::AnchorerWorker`) to keep this projection cache
    /// in sync with anchored cell state.
    ///
    /// This is the only write path into [`ProjectionState::cells`]; the
    /// durable-Event projection path (`apply()`) does NOT touch cells —
    /// state cells are exclusively a Move/Anchor surface per spec.
    pub fn reload_cells_from_store(
        &mut self,
        realm_id: &RealmId,
        cell_store: &dyn CellStore,
        cell_registry: &dyn CellRegistry,
    ) -> Result<(), StoreError> {
        for cell in cell_store.list_cells(realm_id)? {
            let ops = cell_store.anchored_ops_for_cell(realm_id, &cell)?;
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
    /// Per-kind dispatch flows through [`APPLY_REGISTRY`] — a static
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
    /// the Move/Anchor pipeline through `LatticeKind` impls in
    /// `lattice_kinds.rs`; the structured ProjectionState fields don't
    /// mirror them. `routing/projection.rs::project_read_receipt_policy`
    /// handles the read-receipt cache fast path explicitly.
    pub fn apply(&mut self, operation: &Operation, hlc: &ServerHlc) -> ProjectionEffect {
        let Some(kind) = crate::kinds::canonical_kind_for_operation(operation) else {
            return ProjectionEffect::Ignored;
        };
        match APPLY_REGISTRY.get(kind) {
            Some(dispatch) => dispatch(self, operation, hlc),
            None => ProjectionEffect::Ignored,
        }
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

    fn apply_message(
        &mut self,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
    ) -> ProjectionEffect {
        let event_id = operation
            .payload
            .get("event_id")
            .and_then(|v| v.as_str())
            .unwrap_or(operation.operation_id.as_str())
            .to_owned();
        let sender = operation
            .payload
            .get("sender")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_owned();
        let thread_id = operation
            .payload
            .get("thread_id")
            .and_then(|v| v.as_str())
            .unwrap_or(operation.realm_id.as_str())
            .to_owned();
        // CKP-0007: derive the message's circle scope from its Flow, never
        // from the message payload (spec: scope_circle_id is a Flow field).
        let flow_scope = operation
            .payload
            .get("flow_id")
            .and_then(Value::as_str)
            .and_then(|flow_id| self.flow_scope_circle_id(flow_id));
        let content = message_content_from_payload(&operation.payload, flow_scope);
        let encrypted = operation
            .payload
            .get("encrypted")
            .and_then(|v| v.as_bool())
            .unwrap_or_else(|| operation.payload.get("encrypted_content").is_some());

        match content_kind(&content) {
            Some("ck.content.poll.response") => {
                return self.apply_poll_response(&content, &sender, now);
            }
            Some("ck.content.poll.close") => {
                return self.apply_poll_close(&content, now);
            }
            _ => {}
        }

        let is_poll_create = content_kind(&content) == Some("ck.content.poll");
        let state = MessageState {
            event_id: event_id.clone(),
            realm_id: operation.realm_id.to_string(),
            sender,
            thread_id,
            content,
            expiry: operation.payload.get("expiry").cloned(),
            encrypted,
            operation_id: operation.operation_id.to_string(),
            created_at: now,
            revision_of: None,
            redacted_at: None,
        };
        let effect = ProjectionEffect::MessageCreated(state.clone());
        if is_poll_create {
            self.apply_poll_create(&state);
        }
        self.messages.insert(event_id, state);
        effect
    }

    fn apply_poll_create(&mut self, message: &MessageState) {
        let poll_id = poll_id_from_content(&message.content)
            .unwrap_or_else(|| message.event_id.replacen("ck:event:", "ck:message:", 1));
        let Some(question) = poll_question_from_content(&message.content) else {
            return;
        };
        let options = poll_options_from_content(&message.content);
        if options.len() < 2 {
            return;
        }
        self.polls.insert(
            poll_id.clone(),
            PollState {
                poll_id,
                message_event_id: message.event_id.clone(),
                realm_id: message.realm_id.clone(),
                question,
                options,
                votes: BTreeMap::new(),
                max_selections: message
                    .content
                    .get("max_selections")
                    .and_then(Value::as_u64)
                    .or_else(|| {
                        message
                            .content
                            .get("poll")
                            .and_then(|poll| poll.get("max_selections"))
                            .and_then(Value::as_u64)
                    })
                    .unwrap_or(1)
                    .max(1) as u32,
                closed: message
                    .content
                    .get("closed")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
                created_at: message.created_at,
                updated_at: message.created_at,
            },
        );
    }

    fn apply_poll_response(
        &mut self,
        content: &Value,
        actor: &str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> ProjectionEffect {
        let Some(poll_id) = poll_id_from_content(content) else {
            return ProjectionEffect::Ignored;
        };
        let choices = poll_choices_from_content(content);
        if choices.is_empty() {
            return ProjectionEffect::Ignored;
        }
        let Some(poll) = self.polls.get_mut(&poll_id) else {
            return ProjectionEffect::Ignored;
        };
        if poll.closed {
            return ProjectionEffect::Rejected {
                reason: "poll_closed".to_owned(),
            };
        }
        let valid: BTreeSet<String> = poll
            .options
            .iter()
            .map(|option| option.id.clone())
            .collect();
        let selected: BTreeSet<String> = choices
            .into_iter()
            .filter(|choice| valid.contains(choice))
            .take(poll.max_selections.max(1) as usize)
            .collect();
        if selected.is_empty() {
            return ProjectionEffect::Ignored;
        }
        poll.votes.insert(actor.to_owned(), selected);
        poll.updated_at = now;
        ProjectionEffect::Ignored
    }

    fn apply_poll_close(
        &mut self,
        content: &Value,
        now: chrono::DateTime<chrono::Utc>,
    ) -> ProjectionEffect {
        let Some(poll_id) = poll_id_from_content(content) else {
            return ProjectionEffect::Ignored;
        };
        if let Some(poll) = self.polls.get_mut(&poll_id) {
            poll.closed = true;
            poll.updated_at = now;
        }
        ProjectionEffect::Ignored
    }

    fn apply_message_revise(
        &mut self,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
    ) -> ProjectionEffect {
        let original_id = operation
            .payload
            .get("target_event_id")
            .or_else(|| operation.payload.get("target_ref"))
            .or_else(|| operation.payload.get("revision_of"))
            .or_else(|| operation.payload.get("event_id"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_owned();
        let new_event_id = operation
            .payload
            .get("new_event_id")
            .or_else(|| operation.payload.get("revised_event_id"))
            .and_then(|v| v.as_str())
            .unwrap_or(operation.operation_id.as_str())
            .to_owned();

        if let Some(original) = self.messages.get(&original_id) {
            let mut revised = original.clone();
            revised.event_id = new_event_id.clone();
            revised.revision_of = Some(original_id.clone());
            revised.created_at = now;
            revised.operation_id = operation.operation_id.to_string();
            // Spec form: `payload.patch` (ck.schema.patch.v1) carrying
            // shallow set/unset entries on the message's content body.
            // The reducer accepts both shapes — legacy `payload.content`
            // (full replace) and the new `payload.patch` (delta) — so
            // existing clients keep working while new clients can emit
            // patches. When both are present, `content` wins (legacy
            // path).
            if let Some(content) = operation.payload.get("content") {
                revised.content = content.clone();
            } else if let Some(patch) = operation.payload.get("patch").and_then(Value::as_object) {
                if let Some(obj) = revised.content.as_object_mut() {
                    for (path, value) in patch {
                        match value {
                            Value::Object(op) if op.contains_key("$op") => {
                                match op.get("$op").and_then(Value::as_str) {
                                    Some("set") => {
                                        if let Some(v) = op.get("value") {
                                            obj.insert(path.clone(), v.clone());
                                        }
                                    }
                                    Some("unset") => {
                                        obj.remove(path);
                                    }
                                    // add/remove on arrays — best-effort
                                    // shallow handling; reducer-side full
                                    // grammar lives in
                                    // `cokret_core::model::patch::Patch`.
                                    Some("add") => {
                                        if let Some(v) = op.get("value") {
                                            if let Some(arr) = obj
                                                .entry(path.clone())
                                                .or_insert_with(|| Value::Array(Vec::new()))
                                                .as_array_mut()
                                            {
                                                arr.push(v.clone());
                                            }
                                        }
                                    }
                                    Some("remove") => {
                                        if let (Some(arr), Some(victim)) = (
                                            obj.get_mut(path).and_then(Value::as_array_mut),
                                            op.get("value"),
                                        ) {
                                            arr.retain(|v| v != victim);
                                        }
                                    }
                                    _ => {}
                                }
                            }
                            // Direct-value sugar = set.
                            other => {
                                obj.insert(path.clone(), other.clone());
                            }
                        }
                    }
                }
            }
            let effect = ProjectionEffect::MessageRevised {
                original_id: original_id.clone(),
                revision: revised.clone(),
            };
            self.messages.insert(new_event_id, revised);
            effect
        } else {
            // Original not found; treat as a new message
            self.apply_message(operation, now)
        }
    }

    /// Writes a parallel `redaction` cas-register
    /// cell on the same subject as the target message cell, value
    /// `{redacted_at, by, reason}`. The ordered-log historical entry id
    /// (the original [`MessageState`]) is preserved unchanged; the
    /// projection layer at read time consults the redaction cell and
    /// replaces the payload with a tombstone.
    ///
    /// Un-redaction: an `apply_redaction` call whose payload sets
    /// `redaction_value: null` (or the equivalent `unredact: true` flag)
    /// resets the cas-register and removes the tombstone.
    ///
    /// When the payload also carries `object_ref` / `target_object_ref`
    /// naming a `ck:flow:` or `ck:morph:` typed-id, the redaction
    /// additionally flips the corresponding projection's state to
    /// `ObjectLifecycleState::Redacted` per spec common-fields.md §5.1.
    /// Space containers are intentionally excluded — they have no Redacted
    /// terminal, and removal routes through `ck.space.tombstone` only.
    fn apply_redaction(&mut self, operation: &Operation) -> ProjectionEffect {
        let target = operation
            .payload
            .get("target_event_id")
            .or_else(|| operation.payload.get("target"))
            .or_else(|| operation.payload.get("redacts"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_owned();
        if target.is_empty() {
            return ProjectionEffect::Ignored;
        }

        // Cas-register set-null path: clears the parallel cell and removes
        // the tombstone. The original MessageState stays intact. Object-ref
        // redactions don't have an un-redact path (terminal state by spec).
        let unredact = operation
            .payload
            .get("redaction_value")
            .map(|v| v.is_null())
            .or_else(|| operation.payload.get("unredact").and_then(|v| v.as_bool()))
            .unwrap_or(false);
        if unredact {
            self.redaction_cells.insert(target.clone(), None);
            self.redactions.remove(&target);
            if let Some(msg) = self.messages.get_mut(&target) {
                msg.redacted_at = None;
            }
            return ProjectionEffect::MessageRedacted { event_id: target };
        }

        // Standard redact path: write the parallel cell + flag the
        // historical entry without removing it.
        let by = operation
            .payload
            .get("by")
            .or_else(|| operation.payload.get("redacted_by"))
            .or_else(|| operation.payload.get("sender"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_owned();
        let reason = redaction_human_reason(&operation.payload);
        let cell = RedactionCellValue {
            redacted_at: operation.created_at,
            by,
            reason: reason.clone(),
        };
        self.redaction_cells
            .insert(target.clone(), Some(cell.clone()));
        self.redactions.insert(target.clone());
        if let Some(msg) = self.messages.get_mut(&target) {
            msg.redacted_at = Some(operation.created_at);
        }

        // Flow / Morph object-level redaction. If payload
        // carries an `object_ref` (or fallback `target_object_ref`)
        // naming a typed-id, push the projection to the Redacted terminal
        // state. State-machine guard against terminal source is policed
        // by `check_redaction_target_transition` preflight — by the time
        // the reducer runs here, the source state is known-permissible.
        let updated_by = operation
            .payload
            .get("by")
            .or_else(|| operation.payload.get("redacted_by"))
            .or_else(|| operation.payload.get("sender"))
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned);
        if let Some(object_ref) = redaction_object_ref(operation) {
            if let Some(flow) = self.flows.get_mut(&object_ref) {
                flow.state = ObjectLifecycleState::Redacted;
                flow.state_changed_at = Some(operation.created_at);
                flow.updated_by.clone_from(&updated_by);
                flow.updated_at = Some(operation.created_at);
                return ProjectionEffect::FlowLifecycle {
                    flow_id: object_ref,
                    new_state: ObjectLifecycleState::Redacted,
                };
            }
            if let Some(morph) = self.morphs.get_mut(&object_ref) {
                morph.state = ObjectLifecycleState::Redacted;
                morph.state_changed_at = Some(operation.created_at);
                morph.updated_by.clone_from(&updated_by);
                morph.updated_at = Some(operation.created_at);
                return ProjectionEffect::MorphLifecycle {
                    morph_id: object_ref,
                    new_state: ObjectLifecycleState::Redacted,
                };
            }
        }

        ProjectionEffect::MessageRedacted { event_id: target }
    }

    fn apply_reaction_add(
        &mut self,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
    ) -> ProjectionEffect {
        let event_id = reaction_target_event_id(operation).unwrap_or_default();
        let actor = operation
            .payload
            .get("actor")
            .or_else(|| operation.payload.get("sender"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_owned();
        let key = operation
            .payload
            .get("key")
            .or_else(|| operation.payload.get("reaction"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_owned();

        if event_id.is_empty() || actor.is_empty() || key.is_empty() {
            return ProjectionEffect::Ignored;
        }

        let reaction = ReactionState {
            actor: actor.clone(),
            key: key.clone(),
            active: true,
            created_at: now,
        };
        self.reactions
            .entry(event_id.clone())
            .or_default()
            .entry(actor.clone())
            .or_default()
            .insert(key.clone(), reaction);

        ProjectionEffect::ReactionChanged {
            event_id,
            actor,
            key,
            active: true,
        }
    }

    fn apply_reaction_remove(&mut self, operation: &Operation) -> ProjectionEffect {
        let event_id = reaction_target_event_id(operation).unwrap_or_default();
        let actor = operation
            .payload
            .get("actor")
            .or_else(|| operation.payload.get("sender"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_owned();
        let key = operation
            .payload
            .get("key")
            .or_else(|| operation.payload.get("reaction"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_owned();

        if event_id.is_empty() || actor.is_empty() || key.is_empty() {
            return ProjectionEffect::Ignored;
        }

        if let Some(event_reactions) = self.reactions.get_mut(&event_id)
            && let Some(actor_reactions) = event_reactions.get_mut(&actor)
        {
            actor_reactions.remove(&key);
        }

        ProjectionEffect::ReactionChanged {
            event_id,
            actor,
            key,
            active: false,
        }
    }

    fn apply_rsvp_set(
        &mut self,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
    ) -> ProjectionEffect {
        let Some(event_ref) = operation.payload.get("event_ref").and_then(Value::as_str) else {
            return ProjectionEffect::Rejected {
                reason: "rsvp_event_ref_missing".to_owned(),
            };
        };
        let Some(status) = operation.payload.get("status").and_then(Value::as_str) else {
            return ProjectionEffect::Rejected {
                reason: "rsvp_status_missing".to_owned(),
            };
        };
        let occurrence = operation
            .payload
            .get("occurrence")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned);
        let actor_id = operation_actor_id(operation);
        let key = (
            event_ref.to_owned(),
            occurrence_key(operation.payload.get("occurrence")),
            actor_id.clone(),
        );
        self.rsvps.insert(
            key,
            RsvpProjection {
                event_ref: event_ref.to_owned(),
                status: status.to_owned(),
                occurrence: occurrence.clone(),
                comment: operation.payload.get("comment").cloned(),
                actor_id: actor_id.clone(),
                updated_at: now,
            },
        );
        ProjectionEffect::RsvpProjected {
            event_ref: event_ref.to_owned(),
            actor_id,
            occurrence,
            status: status.to_owned(),
        }
    }

    fn apply_pin(
        &mut self,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
    ) -> ProjectionEffect {
        let Some(pin_scope) = operation.payload.get("pin_scope") else {
            return ProjectionEffect::Rejected {
                reason: "pin_scope_missing".to_owned(),
            };
        };
        let Some(pin_scope_key) = pin_scope_key(pin_scope) else {
            return ProjectionEffect::Rejected {
                reason: "pin_scope_invalid".to_owned(),
            };
        };
        let Some(target_ref) = operation.payload.get("target_ref").and_then(Value::as_str) else {
            return ProjectionEffect::Rejected {
                reason: "pin_target_ref_missing".to_owned(),
            };
        };
        let map_key = (pin_scope_key.clone(), target_ref.to_owned());
        let operation_kind = crate::kinds::canonical_kind_for_operation(operation);
        if operation_kind == Some(crate::kinds::CK_PIN_REMOVE) {
            if let Some(pin) = self.pins.get_mut(&map_key) {
                pin.active = false;
                pin.updated_at = now;
            }
            return ProjectionEffect::PinProjected {
                pin_scope_key,
                target_ref: target_ref.to_owned(),
                active: false,
            };
        }
        let Some(rank) = operation.payload.get("rank").and_then(Value::as_str) else {
            return ProjectionEffect::Rejected {
                reason: "pin_rank_missing".to_owned(),
            };
        };
        let previous = self.pins.get(&map_key);
        let note = if operation_kind == Some(crate::kinds::CK_PIN_REORDER) {
            previous.and_then(|pin| pin.note.clone())
        } else {
            operation.payload.get("note").cloned()
        };
        self.pins.insert(
            map_key,
            PinProjection {
                pin_scope: pin_scope.clone(),
                target_ref: target_ref.to_owned(),
                rank: Some(rank.to_owned()),
                note,
                actor_id: operation_actor_id(operation),
                active: true,
                updated_at: now,
            },
        );
        ProjectionEffect::PinProjected {
            pin_scope_key,
            target_ref: target_ref.to_owned(),
            active: true,
        }
    }

    fn apply_read_cursor(
        &mut self,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
    ) -> ProjectionEffect {
        let actor_id = operation
            .payload
            .get("actor_id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_owned();
        let device_id = operation
            .payload
            .get("device_id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_owned();
        let realm_id = operation
            .payload
            .get("realm_id")
            .and_then(|v| v.as_str())
            .unwrap_or(operation.realm_id.as_str())
            .to_owned();
        let Some(read_scope) = operation
            .payload
            .get("read_scope")
            .cloned()
            .and_then(|value| serde_json::from_value::<ReadScopeWire>(value).ok())
        else {
            return ProjectionEffect::Ignored;
        };
        if matches!(
            read_scope.kind.as_str(),
            "flow_discussion" | "flow_synthesis"
        ) {
            return ProjectionEffect::Ignored;
        }
        let Some(position) = operation
            .payload
            .get("position")
            .cloned()
            .and_then(|value| serde_json::from_value::<ReadCursorPositionWire>(value).ok())
        else {
            return ProjectionEffect::Ignored;
        };

        if actor_id.is_empty() {
            return ProjectionEffect::Ignored;
        }

        let marker = ReadMarkerState {
            actor_id: actor_id.clone(),
            device_id,
            realm_id: realm_id.clone(),
            read_scope: read_scope.clone(),
            position,
            updated_at: now,
        };
        let key = (realm_id, actor_id, read_scope_key(&read_scope));
        // LWW: only update if newer
        let dominated = self
            .read_cursors
            .get(&key)
            .is_some_and(|existing| existing.updated_at >= marker.updated_at);
        if !dominated {
            self.read_cursors.insert(key, marker.clone());
        }
        ProjectionEffect::ReadMarkerUpdated(marker)
    }

    fn apply_relation_create(
        &mut self,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
    ) -> ProjectionEffect {
        let relation_id = operation
            .payload
            .get("relation_id")
            .or_else(|| operation.payload.get("id"))
            .and_then(|v| v.as_str())
            .unwrap_or(operation.operation_id.as_str())
            .to_owned();
        let relation_kind = operation
            .payload
            .get("relation_kind")
            .or_else(|| operation.payload.get("kind"))
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_owned();
        let from_ref = operation
            .payload
            .get("from")
            .or_else(|| operation.payload.get("from_ref"))
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned);
        let to_ref = operation
            .payload
            .get("to")
            .or_else(|| operation.payload.get("to_ref"))
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned);
        let fields = operation
            .payload
            .get("fields")
            .and_then(|v| v.as_object())
            .map(|m| m.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
            .unwrap_or_default();

        let state = RelationState {
            relation_id: relation_id.clone(),
            realm_id: operation.realm_id.to_string(),
            relation_kind,
            from_ref,
            to_ref,
            fields,
            state: "active".to_owned(),
            created_at: now,
            updated_at: now,
        };
        let effect = ProjectionEffect::RelationCreated(state.clone());
        self.relations.insert(relation_id, state);
        effect
    }

    fn apply_relation_update(
        &mut self,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
        _hlc: &ServerHlc,
    ) -> ProjectionEffect {
        let relation_id = operation
            .payload
            .get("relation_id")
            .or_else(|| operation.payload.get("id"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_owned();
        if relation_id.is_empty() {
            return ProjectionEffect::Ignored;
        }
        // Patch-merge on the existing relation. If the relation does not yet
        // exist locally (out-of-order replication), drop the update — a
        // subsequent gap-fill will replay create + update in order.
        let Some(relation) = self.relations.get_mut(&relation_id) else {
            return ProjectionEffect::Ignored;
        };
        if let Some(kind) = operation
            .payload
            .get("relation_kind")
            .or_else(|| operation.payload.get("kind"))
            .and_then(|v| v.as_str())
        {
            relation.relation_kind = kind.to_owned();
        }
        if let Some(value) = operation
            .payload
            .get("from")
            .or_else(|| operation.payload.get("from_ref"))
        {
            relation.from_ref = value.as_str().map(ToOwned::to_owned);
        }
        if let Some(value) = operation
            .payload
            .get("to")
            .or_else(|| operation.payload.get("to_ref"))
        {
            relation.to_ref = value.as_str().map(ToOwned::to_owned);
        }
        if let Some(fields) = operation.payload.get("fields").and_then(|v| v.as_object()) {
            for (k, v) in fields.iter() {
                if v.is_null() {
                    relation.fields.remove(k);
                } else {
                    relation.fields.insert(k.clone(), v.clone());
                }
            }
        }
        relation.updated_at = now;
        ProjectionEffect::RelationUpdated(relation.clone())
    }

    fn apply_relation_delete(&mut self, operation: &Operation) -> ProjectionEffect {
        let relation_id = operation
            .payload
            .get("relation_id")
            .or_else(|| operation.payload.get("id"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_owned();

        if let Some(relation) = self.relations.get_mut(&relation_id) {
            relation.state = "tombstoned".to_owned();
            relation.updated_at = operation.created_at;
        }
        ProjectionEffect::RelationDeleted { relation_id }
    }

    fn apply_container_position(
        &mut self,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
    ) -> ProjectionEffect {
        let relation_id = operation
            .payload
            .get("relation_id")
            .or_else(|| {
                operation
                    .payload
                    .get("expected_position")
                    .and_then(|value| value.get("relation_id"))
            })
            .and_then(|v| v.as_str())
            .unwrap_or(operation.operation_id.as_str())
            .to_owned();
        let relation_kind = operation
            .payload
            .get("relation_kind")
            .and_then(|v| v.as_str())
            .unwrap_or("contains")
            .to_owned();
        let object_ref = operation
            .payload
            .get("object_ref")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned);
        let container_id = operation
            .payload
            .get("to_container_id")
            .or_else(|| operation.payload.get("container_id"))
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned);
        let mut fields = BTreeMap::new();
        if let Some(rank) = operation.payload.get("rank") {
            fields.insert("rank".to_owned(), rank.clone());
        }

        let state = self
            .relations
            .entry(relation_id.clone())
            .or_insert_with(|| RelationState {
                relation_id: relation_id.clone(),
                realm_id: operation.realm_id.to_string(),
                relation_kind: relation_kind.clone(),
                from_ref: container_id.clone(),
                to_ref: object_ref.clone(),
                fields: BTreeMap::new(),
                state: "active".to_owned(),
                created_at: now,
                updated_at: now,
            });
        state.relation_kind = relation_kind;
        state.from_ref = container_id;
        state.to_ref = object_ref;
        state.fields.extend(fields);
        state.state = "active".to_owned();
        state.updated_at = now;
        ProjectionEffect::RelationCreated(state.clone())
    }

    /// R1.2 — project a `ck.realm.delivery_binding_policy` event into the
    /// `ck.component.realm.delivery_binding_policy.v1` cas-register cell.
    /// The payload is taken whole as the cell value so downstream readers
    /// (`realm_delivery_binding_policy_cell_value` + the `apply_membership`
    /// validation path) can inspect each policy field directly.
    fn apply_delivery_binding_policy(&mut self, operation: &Operation) -> ProjectionEffect {
        let realm_id = operation.realm_id.to_string();
        let value = operation.payload.clone();
        if let Ok(cell_id) = cokret_sdk::CellRef::new(format!(
            "ck:cell:ck.component.realm.delivery_binding_policy.v1:{realm_id}"
        )) {
            self.cells.insert(cell_id, CellState::Value(value));
        }
        ProjectionEffect::DeliveryBindingPolicyProjected { realm_id }
    }

    /// R3.1 — project a `ck.realm.link` event.
    ///
    /// Writes to the canonical `ck.component.realm.link.v1` cell (or_set
    /// lattice, cell_subject = `(realm_id, target_realm_id, link_kind)`)
    /// AND mirrors into the structured `realm_links` /
    /// `realm_links_inbound` caches consumed by the
    /// `/_soland/self/realms/{id}/links` query API.
    ///
    /// Schema-level validation:
    /// - `link_kind` MUST be one of the eight canonical values declared on
    ///   `cokret_sdk::RealmLinkKind`.
    /// - `target_realm_id` is required and MUST be a Realm-shaped id.
    /// - `status` defaults to `active`; valid values are `active|rejected|tombstoned`.
    /// - Self-referential links (target == source) are rejected with `realm_link_self_reference`.
    fn apply_realm_disappearing_policy(&mut self, operation: &Operation) -> ProjectionEffect {
        let realm_id = operation.realm_id.to_string();
        if let Ok(cell_id) = cokret_sdk::CellRef::new(format!(
            "ck:cell:ck.component.realm.disappearing_policy.v1:{realm_id}"
        )) {
            self.cells
                .insert(cell_id, CellState::Value(operation.payload.clone()));
        }
        ProjectionEffect::RealmDisappearingPolicyProjected { realm_id }
    }

    fn apply_realm_search_policy(&mut self, operation: &Operation) -> ProjectionEffect {
        let realm_id = operation.realm_id.to_string();
        if let Ok(cell_id) = cokret_sdk::CellRef::new(format!(
            "ck:cell:ck.component.realm.search_policy.v1:{realm_id}"
        )) {
            self.cells
                .insert(cell_id, CellState::Value(operation.payload.clone()));
        }
        ProjectionEffect::RealmSearchPolicyProjected { realm_id }
    }

    fn apply_realm_link(
        &mut self,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
    ) -> ProjectionEffect {
        let realm_id = operation.realm_id.to_string();
        let Some(target_realm_id) = operation
            .payload
            .get("target_realm_id")
            .and_then(Value::as_str)
        else {
            return ProjectionEffect::Rejected {
                reason: "realm_link_target_missing".to_owned(),
            };
        };
        let Some(link_kind) = operation.payload.get("link_kind").and_then(Value::as_str) else {
            return ProjectionEffect::Rejected {
                reason: "realm_link_kind_missing".to_owned(),
            };
        };
        if cokret_sdk::RealmLinkKind::parse(link_kind).is_none() {
            return ProjectionEffect::Rejected {
                reason: "realm_link_kind_invalid".to_owned(),
            };
        }
        if target_realm_id == realm_id {
            return ProjectionEffect::Rejected {
                reason: "realm_link_self_reference".to_owned(),
            };
        }
        let status = operation
            .payload
            .get("status")
            .and_then(Value::as_str)
            .unwrap_or("active");
        if !matches!(status, "active" | "rejected" | "tombstoned") {
            return ProjectionEffect::Rejected {
                reason: "realm_link_status_invalid".to_owned(),
            };
        }
        // G3.S5 — cycle detection. Only `active` links on the directed
        // governance kinds participate (see
        // `reducer::realm_links::CYCLE_CHECKED_LINK_KINDS`). DFS from
        // the proposed `target_realm_id` back to `realm_id`: if a path
        // already exists, the new edge would close it into a cycle and
        // we reject with `realm_link_cycle`. Rejected / tombstoned
        // status flips are admitted unconditionally — they sever the
        // edge rather than introduce one.
        if status == "active"
            && realm_links::is_cycle_checked_kind(link_kind)
            && realm_links::path_exists(self, target_realm_id, &realm_id)
        {
            return ProjectionEffect::Rejected {
                reason: "realm_link_cycle".to_owned(),
            };
        }
        let label = operation
            .payload
            .get("label")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned);
        let commitment = operation
            .payload
            .get("commitment")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned);

        // Cell write — or_set keyed by composite subject. Encode subject
        // as `(realm, target, link_kind)` joined by `|` (cells store
        // strings; reducer-side decoders re-split).
        if let Ok(cell_id) = cokret_sdk::CellRef::new(format!(
            "ck:cell:ck.component.realm.link.v1:{realm_id}|{target_realm_id}|{link_kind}"
        )) {
            let value = serde_json::json!({
                "realm_id": realm_id,
                "target_realm_id": target_realm_id,
                "link_kind": link_kind,
                "status": status,
                "label": label,
                "commitment": commitment,
                "updated_at": now.to_rfc3339(),
            });
            self.cells.insert(cell_id, CellState::Value(value));
        }

        // Structured side-band cache mirror. Outbound: keyed by source
        // realm. Inbound: keyed by target realm.
        let row = RealmLinkState {
            realm_id: realm_id.clone(),
            target_realm_id: target_realm_id.to_owned(),
            link_kind: link_kind.to_owned(),
            status: status.to_owned(),
            label,
            commitment,
            created_at: now,
            updated_at: now,
        };
        upsert_realm_link(self.realm_links.entry(realm_id.clone()).or_default(), &row);
        upsert_realm_link(
            self.realm_links_inbound
                .entry(target_realm_id.to_owned())
                .or_default(),
            &row,
        );

        ProjectionEffect::RealmLinkProjected {
            realm_id,
            target_realm_id: target_realm_id.to_owned(),
            link_kind: link_kind.to_owned(),
            status: status.to_owned(),
        }
    }

    /// R3.2 — project a `ck.realm.inheritance_policy` event.
    ///
    /// Cell family: `ck.component.realm.inheritance_policy.v1` (cas-register).
    /// Rejects payloads with `max_depth > 1` (current wire cap), rejects
    /// inheritance through an already-active non-capability-bearing Realm
    /// link, and verifies requested policies / bundles against projected
    /// parent grants when those grants are present in the reducer state.
    fn apply_realm_inheritance_policy(
        &mut self,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
    ) -> ProjectionEffect {
        let realm_id = operation.realm_id.to_string();
        let Some(source_realm_id) = operation
            .payload
            .get("source_realm_id")
            .and_then(Value::as_str)
        else {
            return ProjectionEffect::Rejected {
                reason: "realm_inheritance_source_missing".to_owned(),
            };
        };
        if cokret_sdk::RealmId::new(source_realm_id).is_err() {
            return ProjectionEffect::Rejected {
                reason: "realm_inheritance_source_invalid".to_owned(),
            };
        }
        if operation
            .payload
            .get("mode")
            .and_then(Value::as_str)
            .is_some_and(|mode| mode != "narrow_only")
        {
            return ProjectionEffect::Rejected {
                reason: "realm_inheritance_mode_invalid".to_owned(),
            };
        }
        let max_depth = operation
            .payload
            .get("max_depth")
            .and_then(Value::as_u64)
            .unwrap_or(1) as u32;
        if max_depth == 0 {
            return ProjectionEffect::Rejected {
                reason: "realm_inheritance_max_depth_zero".to_owned(),
            };
        }
        if max_depth > cokret_sdk::RealmInheritancePolicy::MAX_DEPTH_CAP {
            return ProjectionEffect::Rejected {
                reason: "realm_inheritance_max_depth_exceeded".to_owned(),
            };
        }
        let allowed_policies = inheritance_allowed_policies(&operation.payload);
        let allowed_capability_bundles = inheritance_allowed_capability_bundles(&operation.payload);

        if has_active_realm_link_to_source(self, &realm_id, source_realm_id) {
            if let Err(reason) =
                active_capability_inheritance_link_kind(self, &realm_id, source_realm_id)
            {
                return ProjectionEffect::Rejected {
                    reason: reason.to_owned(),
                };
            }
        }
        if let Err(reason) = parent_capability_grants_allow(
            self,
            source_realm_id,
            &allowed_policies,
            &allowed_capability_bundles,
        ) {
            return ProjectionEffect::Rejected {
                reason: reason.to_owned(),
            };
        }

        if let Ok(cell_id) = cokret_sdk::CellRef::new(format!(
            "ck:cell:ck.component.realm.inheritance_policy.v1:{realm_id}"
        )) {
            let value = serde_json::json!({
                "operation_id": operation.operation_id.as_str(),
                "source_realm_id": source_realm_id,
                "allowed_policies": allowed_policies,
                "allowed_capability_bundles": allowed_capability_bundles,
                "max_depth": max_depth,
                "updated_at": now.to_rfc3339(),
            });
            self.cells.insert(cell_id, CellState::Value(value));
        }

        self.realm_inheritance_policies.insert(
            realm_id.clone(),
            RealmInheritancePolicyState {
                realm_id: realm_id.clone(),
                operation_id: operation.operation_id.to_string(),
                source_realm_id: source_realm_id.to_owned(),
                allowed_policies,
                allowed_capability_bundles,
                max_depth,
                updated_at: now,
            },
        );

        ProjectionEffect::RealmInheritancePolicyProjected {
            realm_id,
            source_realm_id: source_realm_id.to_owned(),
        }
    }

    /// R3.2 — project a `ck.capability.derived` event.
    ///
    /// Cell family: `ck.component.capability.derived.v1` (cas-register,
    /// keyed by `capability_id`). Schema-level required fields:
    /// `capability_id`, `source_grant_ref`, `source_realm_inheritance_policy_ref`,
    /// `causal_frontier`. The reducer verifies the current inheritance
    /// policy, the capability-bearing Realm link, the parent grant, and
    /// the narrow-only derived actions / resources / bundles before writing
    /// the projected effective capability set.
    fn apply_capability_derived(
        &mut self,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
    ) -> ProjectionEffect {
        let realm_id = operation.realm_id.to_string();
        let Some(capability_id) = operation
            .payload
            .get("capability_id")
            .and_then(Value::as_str)
        else {
            return ProjectionEffect::Rejected {
                reason: "capability_derived_id_missing".to_owned(),
            };
        };
        let source_grant_ref = match extract_event_ref_id(&operation.payload, "source_grant_ref") {
            Some(s) => s,
            None => {
                return ProjectionEffect::Rejected {
                    reason: "capability_derived_source_grant_ref_missing".to_owned(),
                };
            }
        };
        let source_realm_inheritance_policy_ref =
            match extract_event_ref_id(&operation.payload, "source_realm_inheritance_policy_ref") {
                Some(s) => s,
                None => {
                    return ProjectionEffect::Rejected {
                        reason: "capability_derived_inheritance_ref_missing".to_owned(),
                    };
                }
            };
        let Some(causal_frontier) = operation
            .payload
            .get("causal_frontier")
            .and_then(Value::as_str)
        else {
            return ProjectionEffect::Rejected {
                reason: "capability_derived_causal_frontier_missing".to_owned(),
            };
        };

        let Some(inheritance_policy) = self.realm_inheritance_policy(&realm_id).cloned() else {
            return ProjectionEffect::Rejected {
                reason: "capability_derived_inheritance_policy_missing".to_owned(),
            };
        };
        if !inheritance_policy_ref_matches(self, &realm_id, &source_realm_inheritance_policy_ref) {
            return ProjectionEffect::Rejected {
                reason: "capability_derived_inheritance_ref_stale".to_owned(),
            };
        }
        let source_link_kind = match active_capability_inheritance_link_kind(
            self,
            &realm_id,
            &inheritance_policy.source_realm_id,
        ) {
            Ok(kind) => kind.map(ToOwned::to_owned),
            Err("realm_inheritance_parent_link_missing") => {
                return ProjectionEffect::Rejected {
                    reason: "capability_derived_parent_link_missing".to_owned(),
                };
            }
            Err("realm_inheritance_link_kind_not_capability_bearing") => {
                return ProjectionEffect::Rejected {
                    reason: "capability_derived_link_kind_not_capability_bearing".to_owned(),
                };
            }
            Err(reason) => {
                return ProjectionEffect::Rejected {
                    reason: reason.to_owned(),
                };
            }
        };
        let Some(source_grant) = find_capability_grant(self, &source_grant_ref) else {
            return ProjectionEffect::Rejected {
                reason: "capability_derived_source_grant_missing".to_owned(),
            };
        };
        let evaluation = match validate_derived_capability(
            &source_grant,
            &inheritance_policy,
            &operation.payload,
            now,
        ) {
            Ok(evaluation) => evaluation,
            Err(reason) => {
                return ProjectionEffect::Rejected {
                    reason: reason.to_owned(),
                };
            }
        };

        if let Ok(cell_id) = cokret_sdk::CellRef::new(format!(
            "ck:cell:ck.component.capability.derived.v1:{capability_id}"
        )) {
            let mut value = serde_json::Map::new();
            value.insert(
                "capability_id".to_owned(),
                Value::String(capability_id.to_owned()),
            );
            value.insert("realm_id".to_owned(), Value::String(realm_id.clone()));
            value.insert(
                "source_grant_ref".to_owned(),
                Value::String(source_grant_ref.clone()),
            );
            value.insert(
                "source_realm_inheritance_policy_ref".to_owned(),
                Value::String(source_realm_inheritance_policy_ref.clone()),
            );
            value.insert(
                "causal_frontier".to_owned(),
                Value::String(causal_frontier.to_owned()),
            );
            value.insert(
                "source_realm_id".to_owned(),
                Value::String(inheritance_policy.source_realm_id.clone()),
            );
            if let Some(kind) = source_link_kind.as_deref() {
                value.insert(
                    "source_link_kind".to_owned(),
                    Value::String(kind.to_owned()),
                );
            }
            value.insert(
                "effective_actions".to_owned(),
                Value::Array(
                    evaluation
                        .effective_actions
                        .iter()
                        .cloned()
                        .map(Value::String)
                        .collect(),
                ),
            );
            value.insert(
                "effective_resources".to_owned(),
                Value::Array(evaluation.effective_resources.clone()),
            );
            value.insert(
                "effective_capability_bundles".to_owned(),
                Value::Array(
                    evaluation
                        .effective_capability_bundles
                        .iter()
                        .cloned()
                        .map(Value::String)
                        .collect(),
                ),
            );
            value.insert("updated_at".to_owned(), Value::String(now.to_rfc3339()));
            if let Some(bundle) = operation.payload.get("bundle") {
                value.insert("bundle".to_owned(), bundle.clone());
            }
            self.cells
                .insert(cell_id, CellState::Value(Value::Object(value)));
        }

        self.capability_derived.insert(
            capability_id.to_owned(),
            CapabilityDerivedState {
                capability_id: capability_id.to_owned(),
                realm_id: realm_id.clone(),
                source_grant_ref,
                source_realm_inheritance_policy_ref,
                causal_frontier: causal_frontier.to_owned(),
                effective_actions: evaluation.effective_actions,
                effective_resources: evaluation.effective_resources,
                effective_capability_bundles: evaluation.effective_capability_bundles,
                updated_at: now,
            },
        );

        ProjectionEffect::CapabilityDerivedProjected {
            capability_id: capability_id.to_owned(),
            realm_id,
        }
    }

    /// R3.3 — project a `ck.realm.audit_policy_downgrade` event into the
    /// `ck.component.realm.audit_policy_downgrade.v1` ordered-log cell
    /// + the `realm_audit_downgrades` audit cache.
    ///
    /// Full audit closure (notify `ck.realm.notification.audit` holder,
    /// trigger UI banner) is pending — see
    /// `kinds.rs::CK_REALM_AUDIT_POLICY_DOWNGRADE` for the broader
    /// attestation-chain pipeline that drives this downgrade.
    fn apply_realm_audit_policy_downgrade(
        &mut self,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
    ) -> ProjectionEffect {
        let realm_id = operation.realm_id.to_string();
        let from_policy = operation
            .payload
            .get("from_policy")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned);
        let to_policy = operation
            .payload
            .get("to_policy")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned);
        let reason = operation
            .payload
            .get("reason")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned);
        let approver = operation
            .payload
            .get("approver")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned);

        let entry = serde_json::json!({
            "from_policy": from_policy,
            "to_policy": to_policy,
            "reason": reason,
            "approver": approver,
            "recorded_at": now.to_rfc3339(),
            "operation_id": operation.operation_id.as_str(),
        });
        if let Ok(cell_id) = cokret_sdk::CellRef::new(format!(
            "ck:cell:ck.component.realm.audit_policy_downgrade.v1:{realm_id}"
        )) {
            let new_log = match self.cells.get(&cell_id) {
                Some(CellState::Value(Value::Array(existing))) => {
                    let mut log = existing.clone();
                    log.push(entry);
                    CellState::Value(Value::Array(log))
                }
                _ => CellState::Value(Value::Array(vec![entry])),
            };
            self.cells.insert(cell_id, new_log);
        }

        self.realm_audit_downgrades
            .entry(realm_id.clone())
            .or_default()
            .push(RealmAuditDowngradeEntry {
                realm_id: realm_id.clone(),
                from_policy,
                to_policy,
                reason,
                approver,
                recorded_at: now,
            });

        ProjectionEffect::RealmAuditPolicyDowngradeProjected { realm_id }
    }

    fn apply_membership(
        &mut self,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
    ) -> ProjectionEffect {
        let Some(new_state) = operation.payload.get("membership").and_then(Value::as_str) else {
            return ProjectionEffect::Ignored;
        };
        if !matches!(new_state, "invite" | "join" | "leave" | "ban" | "knock") {
            return ProjectionEffect::Ignored;
        }
        let member = operation
            .payload
            .get("actor_id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_owned();
        let realm_id = operation.realm_id.to_string();

        if member.is_empty() {
            return ProjectionEffect::Ignored;
        }

        // Spec 0a5ab85 (`membership_payload` conditional required) — when
        // `membership=join`, the payload MUST carry `actor_id` (above) +
        // `delivery_status`; when `delivery_status=routable`, it MUST carry
        // `delivery_binding`. Validate here and reject malformed joins.
        if new_state == "join" {
            let delivery_status = operation
                .payload
                .get("delivery_status")
                .and_then(Value::as_str);
            match delivery_status {
                None => {
                    tracing::warn!(
                        realm_id = %realm_id,
                        member = %member,
                        "rejected join without delivery_status (spec 0a5ab85)"
                    );
                    return ProjectionEffect::Ignored;
                }
                Some("routable") => {
                    let Some(binding) = operation
                        .payload
                        .get("delivery_binding")
                        .and_then(Value::as_object)
                    else {
                        tracing::warn!(
                            realm_id = %realm_id,
                            member = %member,
                            "rejected routable join without delivery_binding (spec 0a5ab85)"
                        );
                        return ProjectionEffect::Ignored;
                    };
                    // R1.2 — `ck.realm.delivery_binding_policy` enforcement.
                    // Without a projected policy cell, fail-closed for
                    // routable joins per spec join-policy.md §5.1.3 —
                    // there is no DID Document fallback path.
                    let policy_value = self
                        .realm_delivery_binding_policy_cell_value(&realm_id)
                        .cloned();
                    let Some(policy) = policy_value else {
                        return ProjectionEffect::Rejected {
                            reason: "delivery_binding_policy_unset".to_owned(),
                        };
                    };
                    if let Err(reason) = enforce_delivery_binding_policy(&policy, binding) {
                        return ProjectionEffect::Rejected {
                            reason: reason.to_owned(),
                        };
                    }
                }
                Some("unroutable") => {
                    // Member is recorded but Realm-scoped delivery is
                    // suppressed until a rebind upgrades to routable.
                }
                Some(other) => {
                    tracing::warn!(
                        realm_id = %realm_id,
                        member = %member,
                        delivery_status = %other,
                        "rejected join with unknown delivery_status"
                    );
                    return ProjectionEffect::Ignored;
                }
            }
        }

        // Side-band data: `role` lives outside the FSM cell and is captured
        // here for the structured cache. `joined_at` is set on the first
        // `join` transition; subsequent transitions preserve the original.
        let role = operation
            .payload
            .get("role")
            .and_then(|v| v.as_str())
            .unwrap_or("member")
            .to_owned();
        let key = (realm_id.clone(), member.clone());
        let previous = self.members.get(&key);
        let invited_at = match new_state {
            "invite" => previous.and_then(|m| m.invited_at).or(Some(now)),
            "join" => previous.and_then(|m| {
                m.invited_at
                    .or_else(|| (m.state == "invite").then_some(m.updated_at))
            }),
            _ => previous.and_then(|m| m.invited_at),
        };
        let joined_at = match (new_state, previous) {
            ("join", Some(previous)) if previous.state == "join" => previous.joined_at,
            ("join", _) => now,
            (_, Some(previous)) => previous.joined_at,
            _ => now,
        };

        // Update the structured cache with side-band + FSM state mirror.
        self.members.insert(
            key.clone(),
            MembershipState {
                member: member.clone(),
                realm_id: realm_id.clone(),
                state: new_state.to_owned(),
                role,
                invited_at,
                joined_at,
                updated_at: now,
            },
        );

        // Synthesize the FSM cell state. Cell ref shape per spec
        // `ck:cell:ck.component.member.state.v1:<actor_did>` — note the
        // cell_subject is `actor_id` (per-actor), not (realm_id, actor)
        // composite. The Realm scoping is implicit in the CellStore key.
        if let Ok(cell_id) =
            cokret_sdk::CellRef::new(format!("ck:cell:ck.component.member.state.v1:{member}"))
        {
            self.cells.insert(
                cell_id,
                CellState::Value(Value::String(new_state.to_owned())),
            );
        }

        ProjectionEffect::MembershipChanged {
            realm_id,
            member,
            action: new_state.to_owned(),
        }
    }

    fn realm_organization_cell_id(realm_id: &str) -> Option<CellRef> {
        CellRef::new(format!(
            "ck:cell:ck.component.realm.organization.v1:{realm_id}"
        ))
        .ok()
    }

    fn realm_update_conflict_basis(operation: &Operation) -> Option<String> {
        operation
            .payload
            .get("anchor_ref")
            .or_else(|| operation.payload.get("conflict_basis"))
            .or_else(|| operation.payload.get("state_witness"))
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .map(ToOwned::to_owned)
    }

    #[allow(clippy::too_many_arguments)]
    fn realm_update_candidate_value(
        &self,
        cell_id: &CellRef,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
        owner: Option<&String>,
        title: Option<&String>,
        security_class: Option<&String>,
        federation_policy: Option<&String>,
    ) -> Value {
        let mut value = match self.cells.get(cell_id) {
            Some(CellState::Value(Value::Object(existing))) => existing.clone(),
            _ => serde_json::Map::new(),
        };
        if let Some(o) = owner {
            value.insert("owner".to_owned(), Value::String(o.clone()));
        }
        if let Some(t) = title {
            value.insert("title".to_owned(), Value::String(t.clone()));
        }
        if let Some(sc) = security_class {
            value.insert("security_class".to_owned(), Value::String(sc.clone()));
        }
        if let Some(fp) = federation_policy {
            value.insert("federation_policy".to_owned(), Value::String(fp.clone()));
        }
        value.insert("updated_at".to_owned(), Value::String(utc_timestamp_z(now)));
        value.insert(
            "operation_id".to_owned(),
            Value::String(operation.operation_id.as_str().to_owned()),
        );
        Value::Object(value)
    }

    #[allow(clippy::too_many_arguments)]
    fn maybe_project_realm_update_bottom(
        &mut self,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
        realm_id: &str,
        owner: Option<&String>,
        title: Option<&String>,
        security_class: Option<&String>,
        federation_policy: Option<&String>,
    ) -> Option<ProjectionEffect> {
        let cell_id = Self::realm_organization_cell_id(realm_id)?;
        match self.cells.get(&cell_id) {
            Some(CellState::Bottom(_)) => {
                return Some(ProjectionEffect::Rejected {
                    reason: "cell_bottom_state".to_owned(),
                });
            }
            Some(CellState::Value(existing)) => {
                let basis = Self::realm_update_conflict_basis(operation)?;
                let current_operation = existing
                    .get("operation_id")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                if current_operation.is_empty()
                    || current_operation == basis
                    || current_operation == operation.operation_id.as_str()
                {
                    return None;
                }
                let incoming = self.realm_update_candidate_value(
                    &cell_id,
                    operation,
                    now,
                    owner,
                    title,
                    security_class,
                    federation_policy,
                );
                let bottom = cokret_sdk::Bottom {
                    kind: cokret_sdk::BottomKind::Conflict,
                    cells: vec![cell_id.clone()],
                    move_ids: Vec::new(),
                    anchor_view: None,
                    heads: vec![
                        serde_json::json!({
                            "move_id": current_operation,
                            "value": existing,
                        }),
                        serde_json::json!({
                            "move_id": operation.operation_id.as_str(),
                            "value": incoming,
                        }),
                    ],
                    details: Some(serde_json::json!({
                        "reason": "concurrent_realm_update",
                        "basis": basis,
                    })),
                    escalated_at: None,
                };
                self.cells.insert(cell_id, CellState::Bottom(bottom));
                return Some(ProjectionEffect::RealmLifecycle {
                    realm_id: realm_id.to_owned(),
                    action: "bottom_expose".to_owned(),
                });
            }
            None => {}
        }
        None
    }

    pub fn check_bottom_cell_transition(&self, operation: &Operation) -> Result<(), &'static str> {
        match crate::kinds::canonical_kind_for_operation(operation) {
            Some(crate::kinds::CK_REALM_UPDATE) => {
                let realm_id = operation.realm_id.to_string();
                if let Some(cell_id) = Self::realm_organization_cell_id(&realm_id)
                    && matches!(self.cells.get(&cell_id), Some(CellState::Bottom(_)))
                {
                    return Err("cell_bottom_state");
                }
                Ok(())
            }
            Some(crate::kinds::CK_CONFLICT_REPAIR) => {
                self.validate_conflict_repair_operation(operation)
            }
            _ => Ok(()),
        }
    }

    fn validate_conflict_repair_operation(
        &self,
        operation: &Operation,
    ) -> Result<(), &'static str> {
        let cell_id = operation
            .payload
            .get("cell_id")
            .and_then(Value::as_str)
            .ok_or("conflict_repair_missing_cell")?;
        let cell = CellRef::new(cell_id.to_owned()).map_err(|_| "conflict_repair_invalid_cell")?;
        let Some(CellState::Bottom(bottom)) = self.cells.get(&cell) else {
            return Err("cell_not_bottom");
        };
        let declared = conflict_heads_from_payload(&operation.payload);
        if declared.len() < 2 {
            return Err("repair_head_in_missing");
        }
        let actual = bottom_head_ids(bottom);
        if actual.len() < 2 || declared.iter().any(|head| !actual.contains(head)) {
            return Err("repair_head_in_drift");
        }
        if let Some(witness) = operation
            .payload
            .get("state_witness")
            .and_then(Value::as_str)
            && !witness.starts_with("ck:anchor:sha256:")
        {
            return Err("repair_state_witness_invalid");
        }
        Ok(())
    }

    fn apply_conflict_repair(
        &mut self,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
    ) -> ProjectionEffect {
        if let Err(reason) = self.validate_conflict_repair_operation(operation) {
            return ProjectionEffect::Rejected {
                reason: reason.to_owned(),
            };
        }
        let cell_id = operation
            .payload
            .get("cell_id")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        let Ok(cell) = CellRef::new(cell_id.clone()) else {
            return ProjectionEffect::Rejected {
                reason: "conflict_repair_invalid_cell".to_owned(),
            };
        };
        let heads = conflict_heads_from_payload(&operation.payload);
        let winner = operation
            .payload
            .get("winner_value")
            .cloned()
            .unwrap_or(Value::Null);
        let value =
            augment_repair_winner_value(winner, &heads, operation.operation_id.as_str(), now);
        self.cells.insert(cell, CellState::Value(value.clone()));
        if let Some(realm_id) = realm_organization_realm_id_from_cell(&cell_id) {
            if let Some(title) = value.get("title").and_then(Value::as_str) {
                let entry = self
                    .realm_states
                    .entry(realm_id.clone())
                    .or_insert_with(|| RealmState {
                        realm_id: realm_id.clone(),
                        owner: None,
                        title: Some(title.to_owned()),
                        deleted: false,
                        created_at: now,
                        updated_at: now,
                        trust_domain: None,
                        terminal_state: None,
                        successor_realm_id: None,
                    });
                entry.title = Some(title.to_owned());
                entry.updated_at = now;
            }
            return ProjectionEffect::RealmLifecycle {
                realm_id,
                action: "conflict_repair".to_owned(),
            };
        }
        ProjectionEffect::Ignored
    }

    /// Apply a `ck.realm.*` lifecycle event. Stream-F (Wave 1B) rewrite
    /// of the former Realm lifecycle reducer: the function is now
    /// restricted to the canonical Realm lifecycle kinds
    /// (`ck.realm.create`, `ck.realm.update`, `ck.realm.archive`,
    /// `ck.realm.tombstone`, `ck.realm.destroy`). Space-container lifecycle
    /// (`ck.space.create` / `update` / `parent` / `archive` / `restore`
    /// / `tombstone`) is handled by `apply_space_container_*`
    /// in this same impl block — they were already separate methods
    /// before this rename, so no extraction was needed.
    ///
    /// Spec anchors:
    ///   - `realm-and-space.md` §2.5 (terminal state distinction: tombstone vs destroy)
    ///   - `realm-and-space.md` §2.5.1 (destroy cascade rules)
    ///   - `realm-and-space.md` §2.5.2 (erasure receipt fanout — reducer leg only; the actual
    ///     federation push lives outside)
    fn apply_realm_lifecycle(
        &mut self,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
        kind: &'static str,
    ) -> ProjectionEffect {
        // Defensive: only canonical Realm-lifecycle kinds may
        // reach this function. The dispatch table enforces this; the
        // assertion keeps internal callers honest.
        debug_assert!(
            matches!(
                kind,
                crate::kinds::CK_REALM_CREATE
                    | crate::kinds::CK_REALM_UPDATE
                    | crate::kinds::CK_REALM_ARCHIVE
                    | crate::kinds::CK_REALM_TOMBSTONE
                    | crate::kinds::CK_REALM_DESTROY
            ),
            "apply_realm_lifecycle dispatched with non-realm kind: {kind}",
        );

        // Keep the structured cache and the canonical cells map in sync.
        //
        // Per spec event-kind-registry, each ck.realm.* lifecycle event
        // writes a distinct cell family with its own lattice:
        //   ck.realm.create     → ck.component.realm.create.v1  (ordered-log, singleton)
        //   ck.realm.update     → ck.component.realm.organization.v1 (cas-register, singleton)
        //   ck.realm.archive    → ck.component.realm.archive.v1 (cas-register, singleton)
        //   ck.realm.tombstone  → ck.component.realm.destroy.v1 (cas-register, singleton)
        //   ck.realm.destroy    → ck.component.realm.destroy.v1 (cas-register, singleton)
        //
        // Stream-F (Wave 1B): tombstone and destroy write the SAME cell
        // family — both are terminal — but with different value shapes
        // distinguished by the `terminal_kind` field and the presence
        // (or absence) of `successor_realm_id`. Bottom = reject; a
        // second terminal-state write rejects with
        // `realm_already_terminal`.
        let payload_object = operation.payload.get("object").and_then(Value::as_object);
        let realm_id = operation.realm_id.to_string();
        let owner = operation
            .payload
            .get("owner")
            .or_else(|| payload_object.and_then(|object| object.get("created_by")))
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned);
        // Realm create carries metadata in `payload.object`; update carries
        // mutable presentation fields in the patch register.
        let title = operation
            .payload
            .get("title")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned)
            .or_else(|| {
                payload_object
                    .and_then(|object| object.get("title"))
                    .and_then(Value::as_str)
                    .map(ToOwned::to_owned)
            })
            .or_else(|| {
                operation
                    .payload
                    .get("patch")
                    .and_then(|v| v.get("title"))
                    .and_then(|patch_title| match patch_title {
                        // `patch.title: "..."` (direct-value sugar)
                        Value::String(s) => Some(s.clone()),
                        // `patch.title: { "$op": "set", "value": "..." }`
                        Value::Object(op)
                            if op.get("$op").and_then(Value::as_str) == Some("set") =>
                        {
                            op.get("value")
                                .and_then(Value::as_str)
                                .map(ToOwned::to_owned)
                        }
                        _ => None,
                    })
            });
        // R3.4 — Realm security_class + federation_policy projection.
        // Spec: a Realm with `security_class=high_assurance` MUST have
        // `federation_policy ∈ {closed, restricted, quarantine}`. Any
        // update that violates this MUST be rejected with
        // `high_assurance_federation_policy_invalid`. We resolve the
        // effective security_class by taking the new payload's value if
        // present, otherwise the projected value from a prior event.
        let payload_security_class = operation
            .payload
            .get("security_class")
            .or_else(|| payload_object.and_then(|object| object.get("security_class")))
            .and_then(Value::as_str)
            .map(ToOwned::to_owned);
        let payload_federation_policy = operation
            .payload
            .get("federation_policy")
            .or_else(|| payload_object.and_then(|object| object.get("federation_policy")))
            .and_then(Value::as_str)
            .map(ToOwned::to_owned);
        // Round 4 (B1.2) — capture (and validate against any existing
        // locked value) the Realm trust_domain.
        let payload_trust_domain = operation
            .payload
            .get("trust_domain")
            .or_else(|| payload_object.and_then(|object| object.get("trust_domain")))
            .and_then(Value::as_str)
            .map(ToOwned::to_owned);
        let payload_encryption_profile =
            operation_encryption_profile(operation).map(ToOwned::to_owned);
        if kind == crate::kinds::CK_REALM_UPDATE && operation_touches_encryption_profile(operation)
        {
            return ProjectionEffect::Rejected {
                reason: REALM_ENCRYPTION_PROFILE_CREATE_LOCKED.to_owned(),
            };
        }
        if let Some(ref new_td) = payload_trust_domain {
            // Shape MUST be `ck:trust_domain:<scope>` — delegate to SDK
            // typed id validator.
            if cokret_sdk::TypedTrustDomainId::new(new_td.clone()).is_err() {
                return ProjectionEffect::Rejected {
                    reason: cokret_sdk::ERROR_CODE_SCHEMA_VIOLATION.to_owned(),
                };
            }
            // Compare against any prior locked value. Any mismatch is a
            // cross-domain replay attempt: a peer is trying to relabel a
            // Realm into a different trust domain.
            if let Some(existing) = self.realm_states.get(&realm_id)
                && let Some(locked_td) = existing.trust_domain.as_deref()
                && locked_td != new_td.as_str()
            {
                return ProjectionEffect::Rejected {
                    reason: cokret_sdk::ERROR_CODE_CROSS_DOMAIN_REPLAY_REJECTED.to_owned(),
                };
            }
        }
        let projected_security_class = self.realm_security_class(&realm_id);
        let effective_security_class = payload_security_class.clone().or(projected_security_class);
        // Constraint: high_assurance forbids federation_policy=open. The
        // projected federation_policy is computed by taking the payload
        // value if present, otherwise the prior cell value.
        let effective_federation_policy = payload_federation_policy.clone().or_else(|| {
            cokret_sdk::CellRef::new(format!(
                "ck:cell:ck.component.realm.organization.v1:{realm_id}"
            ))
            .ok()
            .and_then(|c| self.cell_value(&c).cloned())
            .and_then(|v| {
                v.get("federation_policy")
                    .and_then(Value::as_str)
                    .map(ToOwned::to_owned)
            })
        });
        if matches!(effective_security_class.as_deref(), Some("high_assurance"))
            && matches!(effective_federation_policy.as_deref(), Some("open"))
        {
            return ProjectionEffect::Rejected {
                reason: "high_assurance_federation_policy_invalid".to_owned(),
            };
        }

        // Stream-F (Wave 1B): terminal-state preflight. A Realm already
        // in `tombstoned` or `destroyed` state MUST NOT accept another
        // terminal-state write (cell family is cas-register with
        // bottom=reject; the structured cache mirrors that).
        if let Some(existing) = self.realm_states.get(&realm_id)
            && existing.terminal_state.is_some()
            && matches!(
                kind,
                crate::kinds::CK_REALM_TOMBSTONE | crate::kinds::CK_REALM_DESTROY
            )
        {
            return ProjectionEffect::Rejected {
                reason: "realm_already_terminal".to_owned(),
            };
        }

        // Stream-F (Wave 1B): ck.realm.tombstone preconditions. The
        // event MUST carry a syntactically valid `successor_realm_id`
        // pointing at a `ck:realm:<UUIDv7>` distinct from the
        // terminating Realm. Absent → `missing_successor`; malformed →
        // `schema_violation`; self-reference → `successor_self_reference`.
        let payload_successor_realm_id = operation
            .payload
            .get("successor_realm_id")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned);
        if kind == crate::kinds::CK_REALM_TOMBSTONE {
            match payload_successor_realm_id.as_deref() {
                None => {
                    return ProjectionEffect::Rejected {
                        reason: "missing_successor".to_owned(),
                    };
                }
                Some(id) => {
                    if cokret_sdk::RealmId::new(id).is_err() {
                        return ProjectionEffect::Rejected {
                            reason: cokret_sdk::ERROR_CODE_SCHEMA_VIOLATION.to_owned(),
                        };
                    }
                    if id == realm_id {
                        return ProjectionEffect::Rejected {
                            reason: "successor_self_reference".to_owned(),
                        };
                    }
                }
            }
        }
        // ck.realm.destroy MUST NOT carry successor_realm_id (spec §2.5).
        if kind == crate::kinds::CK_REALM_DESTROY && payload_successor_realm_id.is_some() {
            return ProjectionEffect::Rejected {
                reason: cokret_sdk::ERROR_CODE_SCHEMA_VIOLATION.to_owned(),
            };
        }

        if kind == crate::kinds::CK_REALM_UPDATE
            && let Some(effect) = self.maybe_project_realm_update_bottom(
                operation,
                now,
                &realm_id,
                owner.as_ref(),
                title.as_ref(),
                payload_security_class.as_ref(),
                payload_federation_policy.as_ref(),
            )
        {
            return effect;
        }

        // Structured cache mirror.
        let realm = self
            .realm_states
            .entry(realm_id.clone())
            .or_insert_with(|| RealmState {
                realm_id: realm_id.clone(),
                owner: owner.clone(),
                title: title.clone(),
                deleted: false,
                created_at: now,
                updated_at: now,
                trust_domain: payload_trust_domain.clone(),
                terminal_state: None,
                successor_realm_id: None,
            });
        // Lock trust_domain on first observation (ck.realm.create). The
        // mismatch case is already rejected above; here we only set the
        // value when it has not yet been captured.
        if realm.trust_domain.is_none()
            && let Some(td) = payload_trust_domain.clone()
        {
            realm.trust_domain = Some(td);
        }
        // Stream-F (Wave 1B): both terminal-state events flip the
        // summary `deleted` flag. The richer `terminal_state` /
        // `successor_realm_id` fields are the source of truth.
        if kind == crate::kinds::CK_REALM_DESTROY || kind == crate::kinds::CK_REALM_TOMBSTONE {
            realm.deleted = true;
        }
        if kind == crate::kinds::CK_REALM_TOMBSTONE {
            realm.terminal_state = Some("tombstoned".to_owned());
            realm.successor_realm_id = payload_successor_realm_id.clone();
        } else if kind == crate::kinds::CK_REALM_DESTROY {
            realm.terminal_state = Some("destroyed".to_owned());
            realm.successor_realm_id = None;
        }
        if owner.is_some() {
            realm.owner.clone_from(&owner);
        }
        if title.is_some() {
            realm.title.clone_from(&title);
        }
        realm.updated_at = now;

        // Cells map: synth a CellState::Value per the spec cell family
        // for this canonical kind.
        match kind {
            k if k == crate::kinds::CK_REALM_CREATE => {
                // ordered-log: append entries. We model the log here as
                // an array of envelopes; each create event appends. For
                // most Realms there's exactly one create entry, but the
                // spec lattice allows multiple (e.g. spec changes,
                // re-genesis under recovery).
                if let Ok(cell_id) = cokret_sdk::CellRef::new(format!(
                    "ck:cell:ck.component.realm.create.v1:{realm_id}"
                )) {
                    let entry = serde_json::json!({
                        "owner": owner,
                        "title": title,
                        "security_class": payload_security_class,
                        "federation_policy": payload_federation_policy,
                        "encryption_profile": payload_encryption_profile,
                        "created_at": now.to_rfc3339(),
                        "operation_id": operation.operation_id.as_str(),
                    });
                    let new_log = match self.cells.get(&cell_id) {
                        Some(CellState::Value(Value::Array(existing))) => {
                            let mut log = existing.clone();
                            log.push(entry);
                            CellState::Value(Value::Array(log))
                        }
                        _ => CellState::Value(Value::Array(vec![entry])),
                    };
                    self.cells.insert(cell_id, new_log);
                }
            }
            k if k == crate::kinds::CK_REALM_UPDATE => {
                // cas-register: latest value wins. Composite of
                // owner / title / arbitrary other organization fields
                // pulled from payload (fields the spec evolves can land
                // here without changing soland code).
                if let Ok(cell_id) = cokret_sdk::CellRef::new(format!(
                    "ck:cell:ck.component.realm.organization.v1:{realm_id}"
                )) {
                    // Start from the existing cell value so partial
                    // updates retain previously-set fields.
                    let mut value = match self.cells.get(&cell_id) {
                        Some(CellState::Value(Value::Object(existing))) => existing.clone(),
                        _ => serde_json::Map::new(),
                    };
                    if let Some(o) = owner.as_ref() {
                        value.insert("owner".to_owned(), Value::String(o.clone()));
                    }
                    if let Some(t) = title.as_ref() {
                        value.insert("title".to_owned(), Value::String(t.clone()));
                    }
                    if let Some(sc) = payload_security_class.as_ref() {
                        value.insert("security_class".to_owned(), Value::String(sc.clone()));
                    }
                    if let Some(fp) = payload_federation_policy.as_ref() {
                        value.insert("federation_policy".to_owned(), Value::String(fp.clone()));
                    }
                    value.insert("updated_at".to_owned(), Value::String(utc_timestamp_z(now)));
                    value.insert(
                        "operation_id".to_owned(),
                        Value::String(operation.operation_id.as_str().to_owned()),
                    );
                    self.cells
                        .insert(cell_id, CellState::Value(Value::Object(value)));
                }
            }
            k if k == crate::kinds::CK_REALM_ARCHIVE => {
                if let Ok(cell_id) = cokret_sdk::CellRef::new(format!(
                    "ck:cell:ck.component.realm.archive.v1:{realm_id}"
                )) {
                    let mut value = serde_json::Map::new();
                    value.insert(
                        "archived".to_owned(),
                        operation
                            .payload
                            .get("archived")
                            .cloned()
                            .unwrap_or(Value::Bool(true)),
                    );
                    if let Some(reason) = operation.payload.get("reason").cloned() {
                        value.insert("reason".to_owned(), reason);
                    }
                    value.insert("updated_at".to_owned(), Value::String(utc_timestamp_z(now)));
                    value.insert(
                        "operation_id".to_owned(),
                        Value::String(operation.operation_id.as_str().to_owned()),
                    );
                    self.cells
                        .insert(cell_id, CellState::Value(Value::Object(value)));
                }
            }
            k if k == crate::kinds::CK_REALM_TOMBSTONE => {
                // Stream-F (Wave 1B): tombstone writes the same cell
                // family as destroy but with `terminal_kind=tombstoned`
                // + `successor_realm_id` so peers hydrating from cells
                // alone can distinguish the two terminal flavours.
                // Bottom = reject (the structured-cache preflight above
                // mirrors that).
                if let Ok(cell_id) = cokret_sdk::CellRef::new(format!(
                    "ck:cell:ck.component.realm.destroy.v1:{realm_id}"
                )) {
                    let value = serde_json::json!({
                        "terminal_kind": "tombstoned",
                        "destroyed": true,
                        "successor_realm_id": payload_successor_realm_id,
                        "at": now.to_rfc3339(),
                        "operation_id": operation.operation_id.as_str(),
                    });
                    self.cells.insert(cell_id, CellState::Value(value));
                }
                // Tombstone keeps child Space/Flow placement live:
                // succession transfers the navigation surface to the
                // successor Realm. Spec §2.5 row "tombstone" — no
                // realm_destroyed_orphan cascade fires here.
            }
            k if k == crate::kinds::CK_REALM_DESTROY => {
                // cas-register: terminal {destroyed: true, at: ts}.
                if let Ok(cell_id) = cokret_sdk::CellRef::new(format!(
                    "ck:cell:ck.component.realm.destroy.v1:{realm_id}"
                )) {
                    let value = serde_json::json!({
                        "terminal_kind": "destroyed",
                        "destroyed": true,
                        "at": now.to_rfc3339(),
                        "operation_id": operation.operation_id.as_str(),
                    });
                    self.cells.insert(cell_id, CellState::Value(value));
                }
                // Stream-F (Wave 1B): destroy cascade per spec
                // §2.5.1 ¶6 + ¶7.
                self.cascade_realm_destroy(&realm_id);
            }
            _ => {}
        }

        ProjectionEffect::RealmLifecycle {
            realm_id,
            action: kind.strip_prefix("ck.realm.").unwrap_or(kind).to_owned(),
        }
    }

    /// Stream-F (Wave 1B + Wave 2C) — `ck.realm.destroy` child-cascade.
    /// Spec `realm-and-space.md` §2.5.1:
    ///   ¶6 child Space-container placement (same Realm) → mark
    ///      `realm_destroyed_orphan` (locked read-only projection).
    ///   ¶6 cross-Realm `parent_ref` edge pointing at a Space inside
    ///      the destroyed Realm → mark the *referencing* container's
    ///      `parent_ref_locked = true` (Stream-F Wave 2C). The
    ///      referencing Space stays alive in its OWN Realm; only the
    ///      parent edge is downgraded so membership / capability /
    ///      history / E2EE / retention stops propagating across the
    ///      destroy frontier.
    /// CKP-0007: `Flow.discussion_realm_ref` is a removed wire field.
    /// Intra-Realm discussion boundaries now live on a Circle
    /// (`scope_circle_id`) and never cross the Realm frontier, so no
    /// cross-Realm discussion cascade is required here.
    ///
    /// The terminal-state admission check (event_log.rs) prevents
    /// further writes against the destroyed Realm itself, which is the
    /// load-bearing safety property; this cascade applies the
    /// projection-side downgrade so UI / navigation surfaces honour
    /// the destroy frontier without a fresh query against the
    /// terminated Realm.
    fn cascade_realm_destroy(&mut self, destroyed_realm_id: &str) {
        // ¶6 same-Realm child Space-container cascade.
        let mut orphaned_count = 0_usize;
        for container in self.space_containers.values_mut() {
            if container.realm_id == destroyed_realm_id && !container.orphaned {
                container.orphaned = true;
                orphaned_count += 1;
            }
        }

        // ¶6 cross-Realm parent_ref lazy-link downgrade (Stream-F
        // Wave 2C). Spec realm-and-space.md §2.5.1 ¶6.
        //
        // For every Space across ALL Realms, check whether its
        // `parent_ref` resolves to a Space whose home Realm is the
        // destroyed one. The destroyed Realm's own children are
        // already covered by the `orphaned` pass above; this loop
        // catches the *cross-Realm* edges that target a Space
        // hosted inside the destroyed Realm. Containers stay alive
        // in their own Realms — only the navigation edge is locked.
        //
        // We first snapshot the parent_id lookup so we can mutate
        // the same map without re-borrowing it.
        let parent_home_realms: std::collections::BTreeMap<String, String> = self
            .space_containers
            .iter()
            .map(|(id, c)| (id.clone(), c.realm_id.clone()))
            .collect();
        let mut parent_lock_count = 0_usize;
        for container in self.space_containers.values_mut() {
            if container.parent_ref_locked {
                continue; // already locked by an earlier destroy frontier
            }
            // Only consider cross-Realm parent edges (same-Realm
            // children of the destroyed Realm are already marked
            // orphaned above; their parent_ref_locked status is
            // implied by the orphaned flag).
            if container.realm_id == destroyed_realm_id {
                continue;
            }
            let Some(parent_id) = container.parent_ref.as_ref() else {
                continue;
            };
            // Resolve the parent's home Realm. If the parent isn't
            // in the projection (federated / not yet replicated),
            // we can't downgrade — leave it for the federation
            // backfill path to catch on next replay.
            let Some(parent_home) = parent_home_realms.get(parent_id) else {
                continue;
            };
            if parent_home == destroyed_realm_id {
                container.parent_ref_locked = true;
                parent_lock_count += 1;
            }
        }

        // CKP-0007: no cross-Realm discussion edges to sever — Circles
        // are intra-Realm and `ck.realm.destroy` already tombstones their
        // parent Realm; further Circle writes fall under the terminal
        // admission check in `event_log::validate_event_envelope`.

        tracing::info!(
            destroyed_realm_id = %destroyed_realm_id,
            orphaned_space_containers = orphaned_count,
            cross_realm_parent_refs_locked = parent_lock_count,
            "stream-F realm.destroy cascade applied"
        );
    }

    /// Stream-F (Wave 1B + Wave 2C) — apply a
    /// `ck.audit.erasure_receipt` event. Stores the receipt in
    /// [`ProjectionState::erasure_receipts`] with validated `outcome` +
    /// `scope.storage_boundary` + `fanout_status` fields. The receipt
    /// is durable; this projection cache backs the
    /// `erasure_receipts_endpoint` server-describe surface.
    ///
    /// Stream-F (Wave 2C) — additionally extracts `scope.realm_id` so
    /// the federation fanout pass can pick the affected Realm's peer
    /// set, and seeds `peer_status` from the caller-supplied list (if
    /// any). The actual peer push + per-peer status writes happen
    /// outside the reducer in
    /// `routing::federation::erasure_fanout::fanout_erasure_receipt`,
    /// which is called from the projection write path with the
    /// `AppState` handle.
    fn apply_audit_erasure_receipt(
        &mut self,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
    ) -> ProjectionEffect {
        let payload = &operation.payload;
        // Accept either the inner payload shape (canonical) or a
        // flat object whose top-level fields are receipt fields.
        // Spec `realm-and-space.md` §2.5.2 + erasure-receipt.schema.json.
        let outcome = payload
            .get("outcome")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned);
        let outcome = match outcome {
            Some(s) => s,
            None => {
                return ProjectionEffect::Rejected {
                    reason: cokret_sdk::ERROR_CODE_SCHEMA_VIOLATION.to_owned(),
                };
            }
        };
        // The canonical schema enumerates 3 outcomes; the spec brief
        // adds `scheduled` / `failed` for the receiving-peer feedback
        // path. We accept all five and let the wire validator enforce
        // the strict canonical set when the schema version requires.
        let valid_outcomes = [
            "completed",
            "partially_completed",
            "blocked_by_legal_hold",
            "scheduled",
            "failed",
        ];
        if !valid_outcomes.contains(&outcome.as_str()) {
            return ProjectionEffect::Rejected {
                reason: cokret_sdk::ERROR_CODE_SCHEMA_VIOLATION.to_owned(),
            };
        }
        // `scope` MUST be present per schema; we only require it to
        // be an object — the wire validator enforces the inner shape.
        let Some(scope) = payload.get("scope").and_then(Value::as_object) else {
            return ProjectionEffect::Rejected {
                reason: cokret_sdk::ERROR_CODE_SCHEMA_VIOLATION.to_owned(),
            };
        };
        let storage_boundary = scope
            .get("storage_boundary")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned);
        // Stream-F (Wave 2C) — extract the optional scope.realm_id.
        // Drives the federation peer-set selection downstream. Per
        // erasure-receipt.schema.json the field is optional; receipts
        // for account-private erasures (no Realm scope) skip the
        // federation fanout entirely.
        let scope_realm_id = scope
            .get("realm_id")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned);

        let receipt_id = payload
            .get("receipt_id")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned);
        let issuer = payload
            .get("issuer")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned);
        let (subject_kind, subject_ref) = payload
            .get("subject")
            .and_then(Value::as_object)
            .map(|s| {
                (
                    s.get("kind").and_then(Value::as_str).map(ToOwned::to_owned),
                    s.get("ref").and_then(Value::as_str).map(ToOwned::to_owned),
                )
            })
            .unwrap_or((None, None));
        let fanout_status = payload
            .get("fanout_status")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
            .unwrap_or_else(|| "pending".to_owned());

        self.erasure_receipts.push(ErasureReceiptRecord {
            receipt_id: receipt_id.clone(),
            issuer,
            subject_kind,
            subject_ref,
            outcome: outcome.clone(),
            storage_boundary,
            scope_realm_id,
            fanout_status,
            // Stream-F (Wave 2C) — `peer_status` is seeded by the
            // federation fanout helper (which has the AppState
            // handle and therefore access to `config.federation_peers`).
            // The reducer itself runs without AppState, so we leave
            // the map empty here and let the outer projection write
            // path populate it via `seed_peer_status`.
            peer_status: std::collections::BTreeMap::new(),
            recorded_at: now,
            payload: payload.clone(),
        });

        tracing::info!(
            receipt_id = ?receipt_id,
            outcome = %outcome,
            operation_id = %operation.operation_id.as_str(),
            "stream-F erasure_receipt recorded"
        );

        // No dedicated ProjectionEffect variant yet — surface as
        // RealmLifecycle with a synthetic action so existing
        // dispatchers (e.g. the broadcast layer) treat the event as
        // a Realm-level audit signal. TODO(stream-F-followup): add
        // a dedicated `ProjectionEffect::ErasureReceiptRecorded` once
        // the federation layer wants a typed handle.
        ProjectionEffect::RealmLifecycle {
            realm_id: operation.realm_id.to_string(),
            action: "audit.erasure_receipt".to_owned(),
        }
    }

    /// Read-only state-machine preflight for a `ck.space.*` container lifecycle
    /// operation. Returns `Err(reason_code)` if the projection's current
    /// Space-container state forbids the transition per `common-fields.md §5.1`,
    /// else `Ok(())`. Used by `event_log::submit_event` to short-circuit
    /// HTTP admission with a 412 failed_precondition instead of letting
    /// the reducer accept-then-reject after persistence. Unknown Space container
    /// (no prior ck.space.create projected) returns Ok — causal /
    /// backfill ordering is allowed; the reducer also tolerates it.
    pub fn check_space_container_lifecycle_transition(
        &self,
        operation: &Operation,
    ) -> Result<(), &'static str> {
        use crate::kinds::*;
        let kind = match crate::kinds::canonical_kind_for_operation(operation) {
            Some(k) => k,
            None => return Ok(()),
        };

        // `ck.space.create` is unconditional (only constraint is that no
        // existing Space container with the same id — but LWW overwrite is fine
        // per the reducer's existing `insert`).
        // `ck.space.update` / `ck.space.parent` require Active source.
        // `ck.space.archive` requires Active.
        // `ck.space.restore` requires Archived.
        // `ck.space.tombstone` requires {Active, Archived}.
        let (allowed_source, reason): (&[SpaceContainerLifecycleState], &'static str) = match kind {
            CK_SPACE_CONTAINER_CREATE => return Ok(()),
            CK_SPACE_CONTAINER_UPDATE | CK_SPACE_CONTAINER_PARENT => {
                (&[SpaceContainerLifecycleState::Active], "space_not_active")
            }
            CK_SPACE_CONTAINER_ARCHIVE => {
                (&[SpaceContainerLifecycleState::Active], "space_not_active")
            }
            CK_SPACE_CONTAINER_RESTORE => (
                &[SpaceContainerLifecycleState::Archived],
                "space_not_archived",
            ),
            CK_SPACE_CONTAINER_TOMBSTONE => (
                &[
                    SpaceContainerLifecycleState::Active,
                    SpaceContainerLifecycleState::Archived,
                ],
                "space_already_terminal",
            ),
            _ => return Ok(()),
        };

        let Some(container_space_id) = space_container_id_from_payload(&operation.payload) else {
            // Missing space_id is a schema-validation problem caught
            // upstream; preflight is not the right place to surface it.
            return Ok(());
        };
        let Some(space_container) = self.space_containers.get(&container_space_id) else {
            // Unknown — causal / backfill window. Don't block.
            return Ok(());
        };
        if !allowed_source.contains(&space_container.state) {
            return Err(reason);
        }
        Ok(())
    }

    /// Apply `ck.space.create` — populate the Space-container projection from
    /// the wire `object` field. Idempotent: re-create with the same id
    /// overwrites the existing entry per LWW.
    fn apply_space_container_create(
        &mut self,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
    ) -> ProjectionEffect {
        let Some(object) = operation.payload.get("object").and_then(|v| v.as_object()) else {
            return ProjectionEffect::Rejected {
                reason: "space_create_missing_object".to_owned(),
            };
        };
        let Some(container_space_id) = object
            .get("id")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned)
        else {
            return ProjectionEffect::Rejected {
                reason: "space_create_missing_id".to_owned(),
            };
        };
        // CKP-0007 — validate optional `scope_circle_id` /
        // `default_scope_circle_id` against the Realm + Circle state.
        // Either field MUST reference an active Circle in this Realm.
        for field in ["scope_circle_id", "default_scope_circle_id"] {
            if let Some(scope_circle_id) = object.get(field).and_then(Value::as_str)
                && let Err(reason) =
                    self.validate_scope_circle_id(scope_circle_id, operation.realm_id.as_ref())
            {
                return ProjectionEffect::Rejected {
                    reason: reason.to_owned(),
                };
            }
        }
        let kind = object
            .get("kind")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_owned();
        let title = object
            .get("title")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_owned();
        // CKP-0007 rename batch 2026-05-25: wire field is `parent_space_id`.
        // The reducer keeps a transitional fallback to `parent_ref` so
        // soland's own internal reducer tests (which build payloads
        // directly without going through the wire validator) keep
        // passing; real wire traffic never carries `parent_ref` because
        // the envelope validator rejects it as a forbidden wire field.
        let parent_ref = object
            .get("parent_space_id")
            .or_else(|| object.get("parent_ref"))
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned);
        let rank = object
            .get("rank")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned);
        let realm_id = projection_object_realm_id(object, operation);
        let created_by = object
            .get("created_by")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned)
            .or_else(|| {
                operation
                    .payload
                    .get("sender")
                    .and_then(|v| v.as_str())
                    .map(ToOwned::to_owned)
            })
            .unwrap_or_default();

        let projection = SpaceContainerProjection {
            container_space_id: container_space_id.clone(),
            realm_id,
            kind,
            title,
            parent_ref,
            rank,
            state: SpaceContainerLifecycleState::Active,
            state_changed_at: None,
            created_by,
            created_at: now,
            updated_by: None,
            updated_at: None,
            orphaned: false,
            parent_ref_locked: false,
        };
        self.space_containers
            .insert(container_space_id.clone(), projection);

        ProjectionEffect::SpaceContainerLifecycle {
            container_space_id,
            new_state: SpaceContainerLifecycleState::Active,
        }
    }

    /// Apply `ck.space.update` — patch title / rank / fields on an
    /// existing Space container. Per common-fields.md §5.1 ("update on non-active
    /// object MUST fail"): rejects with the spec `space_not_active` reason
    /// code if the target is not in Active state. Unknown Space container is
    /// tolerated.
    fn apply_space_container_update(
        &mut self,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
    ) -> ProjectionEffect {
        let Some(container_space_id) = space_container_id_from_payload(&operation.payload) else {
            return ProjectionEffect::Rejected {
                reason: "space_update_missing_space_id".to_owned(),
            };
        };
        let Some(space_container) = self.space_containers.get_mut(&container_space_id) else {
            return ProjectionEffect::Ignored;
        };
        if space_container.state != SpaceContainerLifecycleState::Active {
            return ProjectionEffect::Rejected {
                reason: "space_not_active".to_owned(),
            };
        }
        let patch = operation.payload.get("patch").and_then(|v| v.as_object());
        if let Some(patch) = patch {
            if let Some(title) = patch.get("title").and_then(|v| v.as_str()) {
                space_container.title = title.to_owned();
            }
            if let Some(rank) = patch.get("rank").and_then(|v| v.as_str()) {
                space_container.rank = Some(rank.to_owned());
            }
        }
        space_container.updated_by = operation
            .payload
            .get("sender")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned);
        space_container.updated_at = Some(now);
        ProjectionEffect::SpaceContainerLifecycle {
            container_space_id,
            new_state: space_container.state,
        }
    }

    /// Apply `ck.space.parent` — update parent_ref. State-machine guard
    /// (`parent on non-active MUST fail`) follows the same rule as
    /// `apply_space_container_update`.
    fn apply_space_container_parent(
        &mut self,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
    ) -> ProjectionEffect {
        let Some(container_space_id) = space_container_id_from_payload(&operation.payload) else {
            return ProjectionEffect::Rejected {
                reason: "space_parent_missing_space_id".to_owned(),
            };
        };
        let parent_ref = if operation.payload.get("parent_space_id").is_some() {
            operation
                .payload
                .get("parent_space_id")
                .and_then(|v| v.as_str())
                .map(ToOwned::to_owned)
        } else {
            operation
                .payload
                .get("parent_ref")
                .and_then(|v| v.as_str())
                .map(ToOwned::to_owned)
        };
        let Some(space_container) = self.space_containers.get_mut(&container_space_id) else {
            return ProjectionEffect::Ignored;
        };
        if space_container.state != SpaceContainerLifecycleState::Active {
            return ProjectionEffect::Rejected {
                reason: "space_not_active".to_owned(),
            };
        }
        space_container.parent_ref = parent_ref;
        space_container.updated_by = operation
            .payload
            .get("sender")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned);
        space_container.updated_at = Some(now);
        ProjectionEffect::SpaceContainerLifecycle {
            container_space_id,
            new_state: space_container.state,
        }
    }

    /// Apply a `ck.space.archive` / `ck.space.restore` / `ck.space.tombstone`
    /// event with the canonical state-machine guard from
    /// `common-fields.md §5.1`. Unknown Space container (no prior
    /// ck.space.create in the projection) is tolerated — returns `Ignored` so causal /
    /// backfill ordering doesn't get flagged as invalid. Invalid source
    /// state returns `Rejected { reason }` with the spec reason_code;
    /// `event_log::submit_event` maps that to HTTP 412.
    fn apply_space_container_lifecycle(
        &mut self,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
        transition: SpaceContainerLifecycleTransition,
    ) -> ProjectionEffect {
        let Some(container_space_id) = space_container_id_from_payload(&operation.payload) else {
            return ProjectionEffect::Rejected {
                reason: "missing_space_id".to_owned(),
            };
        };

        let (allowed_source, target_state, reason_on_invalid) = match transition {
            SpaceContainerLifecycleTransition::Archive => (
                &[SpaceContainerLifecycleState::Active][..],
                SpaceContainerLifecycleState::Archived,
                "space_not_active",
            ),
            SpaceContainerLifecycleTransition::Restore => (
                &[SpaceContainerLifecycleState::Archived][..],
                SpaceContainerLifecycleState::Active,
                "space_not_archived",
            ),
            SpaceContainerLifecycleTransition::Tombstone => (
                &[
                    SpaceContainerLifecycleState::Active,
                    SpaceContainerLifecycleState::Archived,
                ][..],
                SpaceContainerLifecycleState::Tombstoned,
                "space_already_terminal",
            ),
        };

        let updated_by = operation
            .payload
            .get("sender")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned);
        {
            let Some(space_container) = self.space_containers.get_mut(&container_space_id) else {
                // Unknown Space container — likely the ck.space.create has not yet
                // been projected (causal / backfill window). Tolerate
                // silently per the spec convention (common-fields.md §5.1
                // unknown-object tolerance).
                return ProjectionEffect::Ignored;
            };

            if !allowed_source.contains(&space_container.state) {
                return ProjectionEffect::Rejected {
                    reason: reason_on_invalid.to_owned(),
                };
            }

            space_container.state = target_state;
            space_container.state_changed_at = Some(now);
            space_container.updated_by = updated_by.clone();
            space_container.updated_at = Some(now);
        }

        self.cascade_space_container_lifecycle(
            &container_space_id,
            target_state,
            now,
            updated_by.as_deref(),
        );

        ProjectionEffect::SpaceContainerLifecycle {
            container_space_id,
            new_state: target_state,
        }
    }

    fn cascade_space_container_lifecycle(
        &mut self,
        container_space_id: &str,
        target_state: SpaceContainerLifecycleState,
        now: chrono::DateTime<chrono::Utc>,
        updated_by: Option<&str>,
    ) {
        if !matches!(
            target_state,
            SpaceContainerLifecycleState::Active | SpaceContainerLifecycleState::Archived
        ) {
            return;
        }

        let child_container_ids = self
            .space_containers
            .values()
            .filter(|container| container.parent_ref.as_deref() == Some(container_space_id))
            .map(|container| container.container_space_id.clone())
            .collect::<Vec<_>>();
        let mut affected_container_ids = BTreeSet::from([container_space_id.to_owned()]);
        for child_id in &child_container_ids {
            affected_container_ids.insert(child_id.clone());
        }

        for child_id in child_container_ids {
            if let Some(child) = self.space_containers.get_mut(&child_id) {
                match target_state {
                    SpaceContainerLifecycleState::Archived
                        if child.state == SpaceContainerLifecycleState::Active =>
                    {
                        child.state = SpaceContainerLifecycleState::Archived;
                        child.state_changed_at = Some(now);
                        child.updated_by = updated_by.map(ToOwned::to_owned);
                        child.updated_at = Some(now);
                    }
                    SpaceContainerLifecycleState::Active
                        if child.state == SpaceContainerLifecycleState::Archived =>
                    {
                        child.state = SpaceContainerLifecycleState::Active;
                        child.state_changed_at = Some(now);
                        child.updated_by = updated_by.map(ToOwned::to_owned);
                        child.updated_at = Some(now);
                    }
                    _ => {}
                }
            }
        }

        let flow_relation_ids = self
            .relations
            .iter()
            .filter(|(_, relation)| relation.is_active())
            .filter(|(_, relation)| relation.relation_kind == "contains")
            .filter(|(_, relation)| {
                relation
                    .from_ref
                    .as_deref()
                    .is_some_and(|from_ref| affected_container_ids.contains(from_ref))
                    || relation
                        .fields
                        .get("board_space_id")
                        .and_then(Value::as_str)
                        == Some(container_space_id)
            })
            .filter_map(|(relation_id, relation)| {
                relation
                    .to_ref
                    .as_deref()
                    .filter(|flow_id| flow_id.starts_with("ck:flow:"))
                    .map(|flow_id| (relation_id.clone(), flow_id.to_owned()))
            })
            .collect::<Vec<_>>();

        for (relation_id, flow_id) in flow_relation_ids {
            let Some(flow) = self.flows.get_mut(&flow_id) else {
                continue;
            };
            let Some(relation) = self.relations.get_mut(&relation_id) else {
                continue;
            };
            match target_state {
                SpaceContainerLifecycleState::Archived
                    if flow.state == ObjectLifecycleState::Active =>
                {
                    flow.state = ObjectLifecycleState::Archived;
                    flow.state_changed_at = Some(now);
                    flow.updated_by = updated_by.map(ToOwned::to_owned);
                    flow.updated_at = Some(now);
                    relation.fields.insert(
                        "cascade_archived_by".to_owned(),
                        Value::String(container_space_id.to_owned()),
                    );
                    relation.updated_at = now;
                }
                SpaceContainerLifecycleState::Active
                    if flow.state == ObjectLifecycleState::Archived
                        && relation
                            .fields
                            .get("cascade_archived_by")
                            .and_then(Value::as_str)
                            == Some(container_space_id) =>
                {
                    flow.state = ObjectLifecycleState::Active;
                    flow.state_changed_at = Some(now);
                    flow.updated_by = updated_by.map(ToOwned::to_owned);
                    flow.updated_at = Some(now);
                    relation.fields.remove("cascade_archived_by");
                    relation.updated_at = now;
                }
                _ => {}
            }
        }
    }

    // ── Flow / Morph projection state machine ──

    /// Read-only state-machine preflight for a `ck.flow.*` lifecycle event.
    /// Mirror of `check_space_container_lifecycle_transition` — used by
    /// `event_log::submit_event` to short-circuit HTTP admission with 412
    /// failed_precondition. Unknown Flow returns `Ok` (causal/backfill
    /// tolerance per common-fields.md §5.1).
    pub fn check_flow_lifecycle_transition(
        &self,
        operation: &Operation,
    ) -> Result<(), &'static str> {
        use crate::kinds::*;
        let kind = match crate::kinds::canonical_kind_for_operation(operation) {
            Some(k) => k,
            None => return Ok(()),
        };
        // `ck.flow.create` is unconditional (no current state to validate).
        // `ck.flow.update` requires Active source.
        // `ck.flow.archive` requires Active source.
        // `ck.flow.restore` requires Archived source.
        let (allowed_source, reason): (&[ObjectLifecycleState], &'static str) = match kind {
            CK_FLOW_CREATE => return Ok(()),
            CK_FLOW_UPDATE => (&[ObjectLifecycleState::Active], "flow_not_active"),
            CK_FLOW_ARCHIVE => (&[ObjectLifecycleState::Active], "flow_not_active"),
            CK_FLOW_RESTORE => (&[ObjectLifecycleState::Archived], "flow_not_archived"),
            _ => return Ok(()),
        };
        let Some(flow_id) = flow_id_from_payload(&operation.payload) else {
            // Missing flow_id is caught upstream by the operation-schema
            // validator; preflight tolerates absence to keep responsibilities
            // separate.
            return Ok(());
        };
        let Some(flow) = self.flows.get(flow_id) else {
            return Ok(());
        };
        if !allowed_source.contains(&flow.state) {
            return Err(reason);
        }
        Ok(())
    }

    /// Read-only preflight for profile-level Flow status FSM stored at
    /// `fields.status`. This guards common workflow statuses while leaving
    /// unknown/custom statuses to Realm profiles.
    pub fn check_flow_status_transition(&self, operation: &Operation) -> Result<(), &'static str> {
        if crate::kinds::canonical_kind_for_operation(operation)
            != Some(crate::kinds::CK_FLOW_UPDATE)
        {
            return Ok(());
        }
        let Some(flow_id) = flow_id_from_payload(&operation.payload) else {
            return Ok(());
        };
        let Some(flow) = self.flows.get(flow_id) else {
            return Ok(());
        };
        check_flow_status_patch(flow, &operation.payload).map(|_| ())
    }

    /// Return the audit payload for an accepted Flow `fields.status`
    /// transition. Callers invoke this before projection is applied so
    /// `from` is read from the current reducer state.
    pub fn flow_status_transition_audit_payload(
        &self,
        operation: &Operation,
        actor_id: &str,
    ) -> Option<Value> {
        if crate::kinds::canonical_kind_for_operation(operation)
            != Some(crate::kinds::CK_FLOW_UPDATE)
        {
            return None;
        }
        let flow_id = flow_id_from_payload(&operation.payload)?;
        let flow = self.flows.get(flow_id)?;
        let next_status = flow_status_patch_target(&operation.payload)
            .ok()
            .flatten()?;
        let current_status = flow.fields.get("status").and_then(Value::as_str)?;
        if current_status == next_status {
            return None;
        }
        Some(serde_json::json!({
            "actor": actor_id,
            "flow_id": flow_id,
            "incident_id": flow_id,
            "realm_id": flow.realm_id,
            "from": current_status,
            "to": next_status,
            "timestamp": operation.created_at.to_rfc3339(),
            "kind": "incident.status.transition",
        }))
    }

    /// Read-only preflight for `ck.redaction` events that
    /// target a Flow / Morph via `object_ref`. Per spec common-fields.md
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
        if let Some(flow) = self.flows.get(&object_ref) {
            if flow.state.is_terminal() {
                return Err("flow_already_terminal");
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
    /// Same shape as `check_flow_lifecycle_transition`.
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

    /// Apply `ck.flow.create` — populate the `flows` projection from
    /// the wire `object` field. Spec: common-fields.md §5 + flow schema.
    /// Idempotent: re-create with same id overwrites the existing entry
    /// (LWW), but the preflight will accept it since `ck.flow.create` has
    /// no source-state guard.
    fn apply_flow_create(
        &mut self,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
    ) -> ProjectionEffect {
        let Some(object) = operation.payload.get("object").and_then(|v| v.as_object()) else {
            return ProjectionEffect::Rejected {
                reason: "flow_create_missing_object".to_owned(),
            };
        };
        let Some(flow_id) = object
            .get("id")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned)
        else {
            return ProjectionEffect::Rejected {
                reason: "flow_create_missing_id".to_owned(),
            };
        };
        let metadata = object.get("metadata").and_then(Value::as_object);
        let title = metadata
            .and_then(|metadata| metadata.get("title"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_owned();
        let summary = metadata
            .and_then(|metadata| metadata.get("summary"))
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned);
        let fields = metadata
            .and_then(|metadata| metadata.get("fields"))
            .and_then(Value::as_object)
            .map(|fields| {
                fields
                    .iter()
                    .map(|(key, value)| (key.clone(), value.clone()))
                    .collect::<BTreeMap<_, _>>()
            })
            .unwrap_or_default();
        // CKP-0007: `discussion_realm_ref` is a forbidden wire field,
        // rejected at the envelope validator. Intra-Realm discussion
        // boundaries are expressed via `scope_circle_id` (Circle); when
        // present, validate the Circle is in this Realm and active.
        if let Some(scope_circle_id) = object.get("scope_circle_id").and_then(Value::as_str)
            && let Err(reason) =
                self.validate_scope_circle_id(scope_circle_id, operation.realm_id.as_ref())
        {
            return ProjectionEffect::Rejected {
                reason: reason.to_owned(),
            };
        }
        let realm_id = projection_object_realm_id(object, operation);
        let created_by = object
            .get("created_by")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned)
            .or_else(|| {
                operation
                    .payload
                    .get("sender")
                    .and_then(|v| v.as_str())
                    .map(ToOwned::to_owned)
            })
            .unwrap_or_default();

        let projection = FlowProjection {
            flow_id: flow_id.clone(),
            realm_id,
            title,
            summary,
            fields,
            state: ObjectLifecycleState::Active,
            state_changed_at: None,
            created_by,
            created_at: now,
            updated_by: None,
            updated_at: None,
            scope_circle_id: object
                .get("scope_circle_id")
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
                .map(ToOwned::to_owned),
        };
        self.flows.insert(flow_id.clone(), projection);
        if let Some((board_space_id, list_space_id, rank)) =
            flow_position_from_create_payload(&operation.payload, object)
        {
            self.store_flow_position_relation(
                &flow_id,
                operation.realm_id.as_ref(),
                &board_space_id,
                &list_space_id,
                rank.as_deref(),
                now,
            );
        }

        ProjectionEffect::FlowLifecycle {
            flow_id,
            new_state: ObjectLifecycleState::Active,
        }
    }

    /// Apply `ck.flow.update` — patch title / summary on an existing Flow.
    /// Spec common-fields.md §5.1: update on non-active object MUST fail
    /// with `flow_not_active`. Unknown Flow tolerated.
    fn apply_flow_update(
        &mut self,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
    ) -> ProjectionEffect {
        let Some(flow_id) = flow_id_from_payload(&operation.payload).map(ToOwned::to_owned) else {
            return ProjectionEffect::Rejected {
                reason: "flow_update_missing_flow_id".to_owned(),
            };
        };
        // CKP-0007: `discussion_realm_ref` is a forbidden wire field,
        // rejected at the envelope validator before reaching the reducer.
        // Flow scope is set at create time; `scope_circle_id` rebinds fail
        // below with `scope_rebind_forbidden`.
        let Some(flow) = self.flows.get_mut(&flow_id) else {
            return ProjectionEffect::Ignored;
        };
        if flow.state != ObjectLifecycleState::Active {
            return ProjectionEffect::Rejected {
                reason: "flow_not_active".to_owned(),
            };
        }
        if let Err(reason) = check_flow_status_patch(flow, &operation.payload) {
            return ProjectionEffect::Rejected {
                reason: reason.to_owned(),
            };
        }
        let patch = operation.payload.get("patch").and_then(|v| v.as_object());
        if let Some(patch) = patch {
            if patch.contains_key("scope_circle_id") {
                return ProjectionEffect::Rejected {
                    reason: "scope_rebind_forbidden".to_owned(),
                };
            }
            if let Some(title) = patch_metadata_string_value(patch, "title") {
                flow.title = title.unwrap_or_default();
            }
            if let Some(summary) = patch_metadata_string_value(patch, "summary") {
                flow.summary = summary;
            }
            apply_flow_fields_patch(&mut flow.fields, patch);
        }
        flow.updated_by = operation
            .payload
            .get("sender")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned);
        flow.updated_at = Some(now);
        ProjectionEffect::FlowLifecycle {
            flow_id,
            new_state: flow.state,
        }
    }

    /// Apply `ck.flow.archive` / `ck.flow.restore`. Spec
    /// `common-fields.md §5.1` + `event-payload.schema.json`
    /// `object_lifecycle_payload`. Unknown Flow tolerated. The target id is
    /// carried by `target_ref` per spec; `object_ref` and the legacy
    /// `flow_id` field are accepted as fallbacks.
    fn apply_flow_lifecycle(
        &mut self,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
        transition: ObjectLifecycleTransition,
    ) -> ProjectionEffect {
        let Some(flow_id) = operation
            .payload
            .get("target_ref")
            .or_else(|| operation.payload.get("object_ref"))
            .or_else(|| operation.payload.get("flow_id"))
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned)
        else {
            return ProjectionEffect::Rejected {
                reason: "missing_flow_id".to_owned(),
            };
        };
        let Some(flow) = self.flows.get_mut(&flow_id) else {
            return ProjectionEffect::Ignored;
        };
        let (allowed_source, target_state, reason_on_invalid) = match transition {
            ObjectLifecycleTransition::Archive => (
                &[ObjectLifecycleState::Active][..],
                ObjectLifecycleState::Archived,
                "flow_not_active",
            ),
            ObjectLifecycleTransition::Restore => (
                &[ObjectLifecycleState::Archived][..],
                ObjectLifecycleState::Active,
                "flow_not_archived",
            ),
        };
        if !allowed_source.contains(&flow.state) {
            return ProjectionEffect::Rejected {
                reason: reason_on_invalid.to_owned(),
            };
        }
        flow.state = target_state;
        flow.state_changed_at = Some(now);
        flow.updated_by = operation
            .payload
            .get("sender")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned);
        flow.updated_at = Some(now);
        ProjectionEffect::FlowLifecycle {
            flow_id,
            new_state: target_state,
        }
    }

    /// Read-only preflight for `ck.flow.tracks.update`. Spec
    /// common-fields.md §5.1 update-on-non-active rule: track mutations
    /// are a kind of update; parent Flow MUST be Active or the admission
    /// MUST `failed_precondition` with `flow_not_active` before
    /// persistence. Unknown Flow tolerated (causal / backfill — matches
    /// the lifecycle preflight family). soland's projection doesn't
    /// carry track-level state (FlowProjection has no `tracks` field by
    /// design — SDK is the source of truth client-side); only the parent
    /// Flow's lifecycle state matters here.
    pub fn check_flow_tracks_transition(&self, operation: &Operation) -> Result<(), &'static str> {
        let kind = match crate::kinds::canonical_kind_for_operation(operation) {
            Some(k) => k,
            None => return Ok(()),
        };
        if !crate::kinds::is_flow_tracks_kind(kind) {
            return Ok(());
        }
        let Some(flow_id) = operation.payload.get("flow_id").and_then(|v| v.as_str()) else {
            // Missing flow_id is caught by operation-schema validator
            // upstream; preflight tolerates absence (responsibilities split).
            return Ok(());
        };
        let Some(flow) = self.flows.get(flow_id) else {
            return Ok(());
        };
        if flow.state != ObjectLifecycleState::Active {
            return Err("flow_not_active");
        }
        Ok(())
    }

    /// Apply `ck.flow.move` / `ck.flow.reorder`. These events
    /// don't affect Flow lifecycle state — they write to the
    /// `ck.component.flow.position.v1` cell family on the Move/Anchor
    /// pipeline. The Event-Envelope reducer just bumps `updated_at` /
    /// `updated_by` on the Flow projection so read-after-write sees the
    /// touch. Unknown Flow is tolerated (causal / backfill).
    fn apply_flow_position_touch(
        &mut self,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
    ) -> ProjectionEffect {
        let Some(flow_id) = operation
            .payload
            .get("flow_id")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned)
        else {
            return ProjectionEffect::Rejected {
                reason: "missing_flow_id".to_owned(),
            };
        };
        let Some(flow) = self.flows.get_mut(&flow_id) else {
            return ProjectionEffect::Ignored;
        };
        flow.updated_by = operation
            .payload
            .get("sender")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned);
        flow.updated_at = Some(now);
        let projected_state = flow.state;
        if let Some((board_space_id, list_space_id, rank)) =
            flow_position_from_lifecycle_payload(&operation.payload)
        {
            self.store_flow_position_relation(
                &flow_id,
                operation.realm_id.as_ref(),
                &board_space_id,
                &list_space_id,
                rank.as_deref(),
                now,
            );
        }
        ProjectionEffect::FlowLifecycle {
            flow_id,
            new_state: projected_state,
        }
    }

    /// Apply `ck.flow.tracks.update` server-side. State guard runs in
    /// `check_flow_tracks_transition` preflight; by the time this reducer
    /// fires, the parent Flow is known to be Active (or unknown, in which
    /// case the touch is a no-op). The actual track membership lives in
    /// SDK reducer's Flow.tracks; soland's projection just bumps
    /// `updated_at` so read-after-write sees the change. Unknown Flow
    /// tolerated.
    fn apply_flow_track_touch(
        &mut self,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
    ) -> ProjectionEffect {
        let Some(flow_id) = operation
            .payload
            .get("flow_id")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned)
        else {
            return ProjectionEffect::Rejected {
                reason: "missing_flow_id".to_owned(),
            };
        };
        let Some(flow) = self.flows.get_mut(&flow_id) else {
            return ProjectionEffect::Ignored;
        };
        // Defence-in-depth: even though check_flow_tracks_transition
        // gated this at the admission layer, re-check here so direct
        // reducer callers (tests / replay paths that bypass HTTP) still
        // see the spec invariant enforced.
        if flow.state != ObjectLifecycleState::Active {
            return ProjectionEffect::Rejected {
                reason: "flow_not_active".to_owned(),
            };
        }
        flow.updated_by = operation
            .payload
            .get("sender")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned);
        flow.updated_at = Some(now);
        ProjectionEffect::FlowLifecycle {
            flow_id,
            new_state: flow.state,
        }
    }

    /// Apply `ck.flow.watch.set`. Writes the watch cell on the
    /// Move/Anchor pipeline (cas-register `ck.component.flow.watch.v1`);
    /// the soland projection records the materialised value into
    /// `projection_flow_watches` via `ProjectionEffect::FlowWatchUpdated`.
    /// The Flow's `updated_at` is NOT bumped — watch is a per-(flow, actor)
    /// subscription, not a Flow mutation. Unknown Flow tolerated (causal
    /// / backfill).
    ///
    /// Reducer invariant: `payload.watcher_actor_id == operation.sender` unless
    /// the writer is gated by `ck.flow.watch.set.others` (capability
    /// check happens at the routing layer; this projection only records).
    fn apply_flow_watch_set(
        &mut self,
        operation: &Operation,
        _now: chrono::DateTime<chrono::Utc>,
    ) -> ProjectionEffect {
        let Some(flow_id) = operation
            .payload
            .get("flow_id")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned)
        else {
            return ProjectionEffect::Rejected {
                reason: "missing_flow_id".to_owned(),
            };
        };
        let Some(actor_did) = operation
            .payload
            .get("watcher_actor_id")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned)
        else {
            return ProjectionEffect::Rejected {
                reason: "missing_watcher_actor_id".to_owned(),
            };
        };
        // `level` is required at schema layer; here we just project the
        // raw value (string or null). Reducer-level enum validation is
        // not duplicated — the SDK lattice impl + JSON Schema cover it.
        let level = operation.payload.get("level").and_then(|v| {
            if v.is_null() {
                None
            } else {
                v.as_str().map(ToOwned::to_owned)
            }
        });
        let level_public = operation
            .payload
            .get("level_public")
            .and_then(|v| v.as_bool());
        ProjectionEffect::FlowWatchUpdated {
            flow_id,
            actor_did,
            level,
            level_public,
        }
    }

    /// Apply `ck.morph.create`. Mirror of `apply_flow_create`.
    fn apply_morph_create(
        &mut self,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
    ) -> ProjectionEffect {
        let Some(object) = operation.payload.get("object").and_then(|v| v.as_object()) else {
            return ProjectionEffect::Rejected {
                reason: "morph_create_missing_object".to_owned(),
            };
        };
        let Some(morph_id) = object
            .get("id")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned)
        else {
            return ProjectionEffect::Rejected {
                reason: "morph_create_missing_id".to_owned(),
            };
        };
        // CKP-0007 — when the Morph carries a `scope_circle_id`, the
        // Circle MUST belong to this Realm and be active. Mirrors the
        // Flow.scope_circle_id validation.
        if let Some(scope_circle_id) = object.get("scope_circle_id").and_then(Value::as_str)
            && let Err(reason) =
                self.validate_scope_circle_id(scope_circle_id, operation.realm_id.as_ref())
        {
            return ProjectionEffect::Rejected {
                reason: reason.to_owned(),
            };
        }
        let morph_type = object
            .get("morph_type")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_owned();
        let title = object
            .get("metadata")
            .and_then(Value::as_object)
            .and_then(|metadata| metadata.get("title"))
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned);
        let fields = object_map_to_fields(object.get("fields"));
        let schema_refs = string_array_field(object, "schema_refs");
        let facets = string_array_field(object, "facets");
        let realm_id = projection_object_realm_id(object, operation);
        let created_by = object
            .get("created_by")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned)
            .or_else(|| {
                operation
                    .payload
                    .get("sender")
                    .and_then(|v| v.as_str())
                    .map(ToOwned::to_owned)
            })
            .unwrap_or_default();
        let versions = morph_document_body(&fields)
            .map(|body| vec![document_version_from_operation(&morph_id, operation, body)])
            .unwrap_or_default();

        let projection = MorphProjection {
            morph_id: morph_id.clone(),
            realm_id,
            morph_type,
            title,
            fields,
            schema_refs,
            facets,
            versions,
            state: ObjectLifecycleState::Active,
            state_changed_at: None,
            created_by,
            created_at: now,
            updated_by: None,
            updated_at: None,
        };
        self.morphs.insert(morph_id.clone(), projection);

        ProjectionEffect::MorphLifecycle {
            morph_id,
            new_state: ObjectLifecycleState::Active,
        }
    }

    /// Apply `ck.morph.update`. Mirror of `apply_flow_update`.
    fn apply_morph_update(
        &mut self,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
    ) -> ProjectionEffect {
        let Some(morph_id) = operation
            .payload
            .get("morph_id")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned)
        else {
            return ProjectionEffect::Rejected {
                reason: "morph_update_missing_morph_id".to_owned(),
            };
        };
        let Some(morph) = self.morphs.get_mut(&morph_id) else {
            return ProjectionEffect::Ignored;
        };
        if morph.state != ObjectLifecycleState::Active {
            return ProjectionEffect::Rejected {
                reason: "morph_not_active".to_owned(),
            };
        }
        let patch = operation.payload.get("patch").and_then(|v| v.as_object());
        if let Some(patch) = patch {
            if let Some(title) = patch_metadata_string_value(patch, "title") {
                morph.title = title;
            }
            if let Some(morph_type) = patch_string_value(patch, "morph_type").flatten() {
                morph.morph_type = morph_type;
            }
            apply_morph_fields_patch(&mut morph.fields, patch);
        }
        morph.updated_by = operation
            .payload
            .get("sender")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned);
        morph.updated_at = Some(now);
        if let Some(body) = morph_document_body(&morph.fields) {
            let next = document_version_from_operation(&morph_id, operation, body);
            let already_recorded = morph
                .versions
                .last()
                .is_some_and(|current| current.body_digest == next.body_digest);
            if !already_recorded {
                morph.versions.push(next);
            }
        }
        ProjectionEffect::MorphLifecycle {
            morph_id,
            new_state: morph.state,
        }
    }

    /// Apply `ck.morph.archive` / `ck.morph.restore`. Mirror of
    /// `apply_flow_lifecycle`.
    fn apply_morph_lifecycle(
        &mut self,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
        transition: ObjectLifecycleTransition,
    ) -> ProjectionEffect {
        let Some(morph_id) = operation
            .payload
            .get("morph_id")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned)
        else {
            return ProjectionEffect::Rejected {
                reason: "missing_morph_id".to_owned(),
            };
        };
        let Some(morph) = self.morphs.get_mut(&morph_id) else {
            return ProjectionEffect::Ignored;
        };
        let (allowed_source, target_state, reason_on_invalid) = match transition {
            ObjectLifecycleTransition::Archive => (
                &[ObjectLifecycleState::Active][..],
                ObjectLifecycleState::Archived,
                "morph_not_active",
            ),
            ObjectLifecycleTransition::Restore => (
                &[ObjectLifecycleState::Archived][..],
                ObjectLifecycleState::Active,
                "morph_not_archived",
            ),
        };
        if !allowed_source.contains(&morph.state) {
            return ProjectionEffect::Rejected {
                reason: reason_on_invalid.to_owned(),
            };
        }
        morph.state = target_state;
        morph.state_changed_at = Some(now);
        morph.updated_by = operation
            .payload
            .get("sender")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned);
        morph.updated_at = Some(now);
        ProjectionEffect::MorphLifecycle {
            morph_id,
            new_state: target_state,
        }
    }

    // ── CKP-0007 Circle reducer ─────────────────────────────────────────
    //
    // Spec source: `cokret-spec/spec/v1/zh/models/circle.md` +
    // `spec/v1/artifacts/schemas/circle.schema.json`. The six on-wire
    // reducer-input kinds are dispatched here (the seventh,
    // `ck.circle.anchor_commit`, is reducer-derived and emitted by the
    // anchorer cadence, not accepted as a submitted event).

    fn apply_circle_create(
        &mut self,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
    ) -> ProjectionEffect {
        let payload = &operation.payload;
        let Some(object) = payload.get("object").and_then(Value::as_object) else {
            return ProjectionEffect::Rejected {
                reason: "circle_create_missing_object".to_owned(),
            };
        };
        let Some(circle_id) = object.get("id").and_then(Value::as_str) else {
            return ProjectionEffect::Rejected {
                reason: "circle_create_missing_id".to_owned(),
            };
        };
        if !circle_id.starts_with("ck:circle:") {
            return ProjectionEffect::Rejected {
                reason: "circle_create_invalid_id_prefix".to_owned(),
            };
        }
        // Spec invariant: Circle.realm_id MUST match the surrounding
        // operation's realm scope; the wire validator already binds
        // `operation.realm_id` to the envelope `realm_id`, so a mismatch
        // surfaces as the registered CKP-0007 schema_violation reason
        // (`circle_realm_mismatch`).
        let realm_id = operation.realm_id.to_string();
        if let Some(payload_realm) = object.get("realm_id").and_then(Value::as_str)
            && payload_realm != realm_id
        {
            return ProjectionEffect::Rejected {
                reason: "circle_realm_mismatch".to_owned(),
            };
        }
        // Parent Realm MUST exist and not be in a terminal state — both
        // checks rely on the same projection cache the Flow create path
        // uses.
        if self.realm_is_destroyed(&realm_id) {
            return ProjectionEffect::Rejected {
                reason: "circle_realm_terminal".to_owned(),
            };
        }
        if !self.realm_states.contains_key(&realm_id) && self.realm_create_log(&realm_id).is_none()
        {
            return ProjectionEffect::Rejected {
                reason: "circle_realm_unknown".to_owned(),
            };
        }
        let title = object
            .get("title")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned();
        let summary = object
            .get("summary")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned);
        let directory_visibility = object
            .get("directory_visibility")
            .and_then(Value::as_str)
            .unwrap_or("members")
            .to_owned();
        let join_rule = object
            .get("join_rule")
            .and_then(Value::as_str)
            .unwrap_or("invite")
            .to_owned();
        let history_visibility = object
            .get("history_visibility")
            .and_then(Value::as_str)
            .unwrap_or("joined")
            .to_owned();
        let metadata_encryption_floor = object
            .get("metadata_encryption_floor")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned);
        let encryption_profile = object
            .get("encryption_profile")
            .and_then(Value::as_str)
            .unwrap_or("mls_rfc9420")
            .to_owned();
        if !encryption_profile_requires_content_encryption(Some(encryption_profile.as_str()))
            && self.realm_requires_content_encryption(&realm_id)
        {
            return ProjectionEffect::Rejected {
                reason: CIRCLE_ENCRYPTION_BELOW_REALM_FLOOR.to_owned(),
            };
        }
        let created_by = object
            .get("created_by")
            .and_then(Value::as_str)
            .or_else(|| payload.get("sender").and_then(Value::as_str))
            .unwrap_or("")
            .to_owned();
        let projection = CircleProjection {
            circle_id: circle_id.to_owned(),
            realm_id: realm_id.clone(),
            title,
            summary,
            directory_visibility,
            join_rule,
            history_visibility,
            metadata_encryption_floor,
            encryption_profile,
            mls_group_ref: None,
            state: CircleLifecycleState::Active,
            state_changed_at: None,
            created_by,
            created_at: now,
            updated_by: None,
            updated_at: None,
            members: BTreeSet::new(),
        };
        self.circles.insert(circle_id.to_owned(), projection);
        ProjectionEffect::CircleLifecycle {
            circle_id: circle_id.to_owned(),
            new_state: CircleLifecycleState::Active,
        }
    }

    fn apply_circle_update(
        &mut self,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
    ) -> ProjectionEffect {
        let payload = &operation.payload;
        let Some(circle_id) = payload
            .get("circle_id")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
        else {
            return ProjectionEffect::Rejected {
                reason: "circle_update_missing_circle_id".to_owned(),
            };
        };
        let Some(circle) = self.circles.get_mut(&circle_id) else {
            return ProjectionEffect::Ignored;
        };
        if circle.state != CircleLifecycleState::Active {
            return ProjectionEffect::Rejected {
                reason: "circle_not_active".to_owned(),
            };
        }
        if operation_touches_encryption_profile(operation) {
            return ProjectionEffect::Rejected {
                reason: CIRCLE_ENCRYPTION_PROFILE_CREATE_LOCKED.to_owned(),
            };
        }
        if let Some(patch) = payload.get("patch").and_then(Value::as_object) {
            if let Some(title) = patch.get("title").and_then(Value::as_str) {
                circle.title = title.to_owned();
            }
            if let Some(summary) = patch.get("summary") {
                circle.summary = summary.as_str().map(ToOwned::to_owned);
            }
            if let Some(visibility) = patch.get("directory_visibility").and_then(Value::as_str) {
                circle.directory_visibility = visibility.to_owned();
            }
            if let Some(join_rule) = patch.get("join_rule").and_then(Value::as_str) {
                circle.join_rule = join_rule.to_owned();
            }
            if let Some(history) = patch.get("history_visibility").and_then(Value::as_str) {
                circle.history_visibility = history.to_owned();
            }
            if let Some(floor) = patch.get("metadata_encryption_floor") {
                circle.metadata_encryption_floor = floor.as_str().map(ToOwned::to_owned);
            }
        }
        circle.updated_by = payload
            .get("sender")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned);
        circle.updated_at = Some(now);
        ProjectionEffect::CircleLifecycle {
            circle_id,
            new_state: CircleLifecycleState::Active,
        }
    }

    fn apply_circle_lifecycle(
        &mut self,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
        target: CircleLifecycleState,
    ) -> ProjectionEffect {
        let payload = &operation.payload;
        let Some(circle_id) = payload
            .get("circle_id")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
        else {
            return ProjectionEffect::Rejected {
                reason: "circle_lifecycle_missing_circle_id".to_owned(),
            };
        };
        let Some(circle) = self.circles.get_mut(&circle_id) else {
            return ProjectionEffect::Ignored;
        };
        // CKP-0007 transition matrix:
        //   active -> archived   (ck.circle.archive)
        //   archived -> active   (ck.circle.restore)
        //   active | archived -> tombstoned   (ck.circle.tombstone)
        let allowed = match target {
            CircleLifecycleState::Archived => circle.state == CircleLifecycleState::Active,
            CircleLifecycleState::Active => circle.state == CircleLifecycleState::Archived,
            CircleLifecycleState::Tombstoned => matches!(
                circle.state,
                CircleLifecycleState::Active | CircleLifecycleState::Archived
            ),
        };
        if !allowed {
            let reason = match target {
                CircleLifecycleState::Archived => "circle_not_active",
                CircleLifecycleState::Active => "circle_not_archived",
                CircleLifecycleState::Tombstoned => "circle_already_terminal",
            };
            return ProjectionEffect::Rejected {
                reason: reason.to_owned(),
            };
        }
        circle.state = target;
        circle.state_changed_at = Some(now);
        circle.updated_by = payload
            .get("sender")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned);
        circle.updated_at = Some(now);
        if target == CircleLifecycleState::Tombstoned {
            // Membership is invalidated when the Circle is tombstoned.
            circle.members.clear();
        }
        ProjectionEffect::CircleLifecycle {
            circle_id,
            new_state: target,
        }
    }

    fn apply_circle_member_state(
        &mut self,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
    ) -> ProjectionEffect {
        let payload = &operation.payload;
        let Some(circle_id) = payload
            .get("circle_id")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
        else {
            return ProjectionEffect::Rejected {
                reason: "circle_member_state_missing_circle_id".to_owned(),
            };
        };
        let Some(actor) = payload
            .get("actor")
            .and_then(Value::as_str)
            .or_else(|| payload.get("actor_id").and_then(Value::as_str))
            .map(ToOwned::to_owned)
        else {
            return ProjectionEffect::Rejected {
                reason: "circle_member_state_missing_actor".to_owned(),
            };
        };
        let target_state = payload
            .get("state")
            .and_then(Value::as_str)
            .or_else(|| payload.get("membership").and_then(Value::as_str))
            .unwrap_or("active")
            .to_owned();
        // Snapshot the parent Realm id BEFORE taking a mutable borrow on
        // the Circle entry so we can run the strict-subset check against
        // the parent Realm's membership set.
        let realm_id = match self.circles.get(&circle_id) {
            Some(c) => c.realm_id.clone(),
            None => return ProjectionEffect::Ignored,
        };
        if target_state == "active" {
            // CKP-0007 strict subset invariant: Circle.members ⊆
            // Realm.members. Reducer reason
            // `circle_member_must_be_realm_member`.
            let parent_joined = self
                .member(&realm_id, &actor)
                .map(|m| m.state == "join")
                .unwrap_or(false);
            if !parent_joined {
                return ProjectionEffect::Rejected {
                    reason: "circle_member_must_be_realm_member".to_owned(),
                };
            }
        }
        let Some(circle) = self.circles.get_mut(&circle_id) else {
            return ProjectionEffect::Ignored;
        };
        if circle.state == CircleLifecycleState::Tombstoned {
            return ProjectionEffect::Rejected {
                reason: "circle_already_terminal".to_owned(),
            };
        }
        if circle.state == CircleLifecycleState::Archived {
            return ProjectionEffect::Rejected {
                reason: "circle_not_active".to_owned(),
            };
        }
        match target_state.as_str() {
            "active" => {
                circle.members.insert(actor.clone());
            }
            "removed" | "banned" | "left" => {
                circle.members.remove(&actor);
            }
            "invited" => {
                // Invited members are not yet active; no projection-side
                // membership change. Wire effect is still emitted so the
                // notification dispatcher can react.
            }
            _ => {
                return ProjectionEffect::Rejected {
                    reason: "circle_member_state_unknown".to_owned(),
                };
            }
        }
        circle.updated_by = payload
            .get("sender")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned);
        circle.updated_at = Some(now);
        ProjectionEffect::CircleMemberStateChanged {
            circle_id,
            member: actor,
            target_state,
        }
    }

    /// CKP-0007 — validate that `scope_circle_id` references an active
    /// Circle whose `realm_id` matches the writer's surrounding Realm
    /// scope. Returns the canonical CKP-0007 reason code on failure:
    ///
    /// - `circle_realm_mismatch`     — Circle belongs to a different Realm
    /// - `circle_not_active`         — Circle is archived
    /// - `circle_already_terminal`   — Circle is tombstoned
    /// - `circle_unknown`            — `circle_id` is not projected
    ///
    /// Called from Flow / Morph / Space create + update paths whenever
    /// the wire object carries a non-null `scope_circle_id`.
    pub(crate) fn validate_scope_circle_id(
        &self,
        scope_circle_id: &str,
        operation_realm_id: &str,
    ) -> Result<(), &'static str> {
        let Some(circle) = self.circles.get(scope_circle_id) else {
            return Err("circle_unknown");
        };
        match circle.state {
            CircleLifecycleState::Tombstoned => return Err("circle_already_terminal"),
            CircleLifecycleState::Archived => return Err("circle_not_active"),
            CircleLifecycleState::Active => {}
        }
        if circle.realm_id != operation_realm_id {
            return Err("circle_realm_mismatch");
        }
        Ok(())
    }

    /// CKP-0007 read helper — return the Circle projection for `circle_id`,
    /// or `None` when the Circle is unknown or already tombstoned. Used by
    /// `/_soland/self/circles/*` route handlers and by `scope_circle_id`
    /// validators that need to confirm the Circle is alive before allowing
    /// Flow / Space / Morph writes against it.
    pub fn circle(&self, circle_id: &str) -> Option<&CircleProjection> {
        let circle = self.circles.get(circle_id)?;
        (circle.state != CircleLifecycleState::Tombstoned).then_some(circle)
    }

    /// CKP-0007 — list all live Circles bound to `realm_id`. Excludes
    /// tombstoned entries; archived Circles are included so the admin UI
    /// can offer a restore path. Stable iteration order
    /// (BTreeMap key ordering).
    pub fn circles_for_realm(&self, realm_id: &str) -> Vec<&CircleProjection> {
        self.circles
            .values()
            .filter(|c| c.realm_id == realm_id && c.state != CircleLifecycleState::Tombstoned)
            .collect()
    }

    pub fn circle_scope_visible_to_actor(&self, circle_id: &str, actor: &str) -> bool {
        self.circles.get(circle_id).is_some_and(|circle| {
            circle.state != CircleLifecycleState::Tombstoned && circle.members.contains(actor)
        })
    }

    /// CKP-0007 — resolve the Circle (`ck:circle:…`) a Flow is scoped to, if
    /// any. A message's effective circle-scope is derived from its Flow via
    /// this lookup — never from the message payload (spec: `scope_circle_id`
    /// is a Flow field). Returns `None` for unknown Flows or Realm-default
    /// scope.
    pub fn flow_scope_circle_id(&self, flow_id: &str) -> Option<String> {
        self.flows
            .get(flow_id)
            .and_then(|flow| flow.scope_circle_id.clone())
            .filter(|scope| scope.starts_with("ck:circle:"))
    }

    /// Apply `ck.applet.registration`. Upserts the
    /// AppletProjection keyed by `service_did`. Re-registration with
    /// the same DID is allowed (replace capabilities + bump
    /// updated_at), matching the spec convention that registration is
    /// idempotent for the same identity.
    fn apply_applet_registration(
        &mut self,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
    ) -> ProjectionEffect {
        let Some(service_did) = operation
            .payload
            .get("service_did")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned)
        else {
            return ProjectionEffect::Rejected {
                reason: "applet_registration_missing_service_did".to_owned(),
            };
        };
        let namespace = operation
            .payload
            .get("namespace")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_owned();
        let capabilities = operation.payload.get("capabilities").cloned();
        let existing_manifest = self
            .applets
            .get(&service_did)
            .and_then(|p| p.manifest.clone());
        let registered_at = self
            .applets
            .get(&service_did)
            .map(|p| p.registered_at)
            .unwrap_or(now);
        let projection = AppletProjection {
            service_did: service_did.clone(),
            namespace,
            manifest: existing_manifest,
            capabilities,
            registered_at,
            updated_at: now,
        };
        self.applets.insert(service_did.clone(), projection);
        ProjectionEffect::AppletProjectionUpdated { service_did }
    }

    /// Apply `ck.applet.discovery`. Updates the manifest
    /// on an existing AppletProjection. If the applet hasn't registered
    /// yet (causal / backfill window), creates a stub entry with the
    /// manifest and empty namespace; subsequent registration will fill
    /// in the namespace + capabilities.
    fn apply_applet_discovery(
        &mut self,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
    ) -> ProjectionEffect {
        let Some(service_did) = operation
            .payload
            .get("service_did")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned)
        else {
            return ProjectionEffect::Rejected {
                reason: "applet_discovery_missing_service_did".to_owned(),
            };
        };
        let manifest = operation.payload.get("manifest").cloned();
        let entry = self
            .applets
            .entry(service_did.clone())
            .or_insert_with(|| AppletProjection {
                service_did: service_did.clone(),
                namespace: String::new(),
                manifest: None,
                capabilities: None,
                registered_at: now,
                updated_at: now,
            });
        entry.manifest = manifest;
        entry.updated_at = now;
        ProjectionEffect::AppletProjectionUpdated { service_did }
    }

    /// Apply `ck.agent.endpoint`. Upserts the AgentProjection keyed by
    /// `agent_id`. If the payload carries an endpoint URL field it
    /// is captured into the projection so the bridge can echo it back
    /// on `protocol_session.result`.
    fn apply_agent_endpoint(
        &mut self,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
    ) -> ProjectionEffect {
        let Some(agent_id) = operation
            .payload
            .get("agent_id")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned)
        else {
            return ProjectionEffect::Rejected {
                reason: "agent_endpoint_missing_agent_id".to_owned(),
            };
        };
        let first_endpoint = operation
            .payload
            .get("endpoints")
            .and_then(|v| v.as_array())
            .and_then(|items| items.first());
        let protocol = operation
            .payload
            .get("protocol")
            .and_then(|v| v.as_str())
            .or_else(|| {
                first_endpoint
                    .and_then(|v| v.get("protocol"))
                    .and_then(|v| v.as_str())
            })
            .unwrap_or("")
            .to_owned();
        let endpoint_url = operation
            .payload
            .get("endpoint_url")
            .and_then(|v| v.as_str())
            .or_else(|| {
                first_endpoint
                    .and_then(|v| v.get("endpoint_url"))
                    .and_then(|v| v.as_str())
            })
            .or_else(|| {
                first_endpoint
                    .and_then(|v| v.get("url"))
                    .and_then(|v| v.as_str())
            })
            .map(ToOwned::to_owned);
        let registered_at = self
            .agents
            .get(&agent_id)
            .map(|p| p.registered_at)
            .unwrap_or(now);
        let projection = AgentProjection {
            agent_id: agent_id.clone(),
            protocol,
            endpoint_url,
            registered_at,
            updated_at: now,
        };
        self.agents.insert(agent_id.clone(), projection);
        ProjectionEffect::AgentProjectionUpdated { agent_id }
    }

    /// REDU-1 (R3 spec-sync 2026-05-27, cokret-spec b47ff6ec) — apply
    /// an `ck.agent.{pause,resume,deactivate}` FSM transition. The
    /// lattice is `fsm` with `bottom=reject`; allowed transitions are:
    ///   - Active → Paused                 via `ck.self.agent.pause`
    ///   - Paused → Active                 via `ck.self.agent.resume`
    ///   - {Active,Paused} → Deactivated   via `ck.self.agent.deactivate`
    ///
    /// `Deactivated` is terminal — any further transition (including a
    /// resume) is rejected.
    pub fn apply_agent_lifecycle(
        &mut self,
        operation: &Operation,
        target: AgentLifecycleState,
    ) -> ProjectionEffect {
        let Some(agent_principal_id) = operation
            .payload
            .get("agent_principal_id")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned)
        else {
            return ProjectionEffect::Rejected {
                reason: "agent_lifecycle_missing_agent_principal_id".to_owned(),
            };
        };
        let current = self
            .agent_lifecycles
            .get(&agent_principal_id)
            .copied()
            .unwrap_or_default();
        // FSM guard. Terminal `Deactivated` rejects any transition.
        let allowed = match (current, target) {
            (AgentLifecycleState::Active, AgentLifecycleState::Paused)
            | (AgentLifecycleState::Paused, AgentLifecycleState::Active)
            | (AgentLifecycleState::Active, AgentLifecycleState::Deactivated)
            | (AgentLifecycleState::Paused, AgentLifecycleState::Deactivated) => true,
            // Idempotent identity transitions are accepted as no-op
            // (the FSM lattice deduplicates redundant pause/resume).
            (a, b) if a == b => true,
            // Bottom=reject; specifically deactivate is terminal so
            // any resume/pause after deactivate is rejected with the
            // spec-canonical `agent_deactivated` reason code.
            _ => false,
        };
        if !allowed {
            let reason = if current == AgentLifecycleState::Deactivated {
                "agent_deactivated"
            } else {
                "invalid_agent_lifecycle_transition"
            };
            return ProjectionEffect::Rejected {
                reason: reason.to_owned(),
            };
        }
        self.agent_lifecycles
            .insert(agent_principal_id.clone(), target);
        ProjectionEffect::AgentLifecycleProjected {
            agent_principal_id,
            new_state: target,
        }
    }

    // ── Query helpers ──

    /// Get all non-redacted messages for a Realm, sorted by creation time.
    pub fn messages_for_realm(&self, realm_id: &str) -> Vec<&MessageState> {
        let mut msgs: Vec<_> = self
            .messages
            .values()
            .filter(|m| {
                m.realm_id == realm_id
                    && self
                        .redaction_cells
                        .get(&m.event_id)
                        .and_then(|cell| cell.as_ref())
                        .is_none()
            })
            .collect();
        msgs.sort_by_key(|a| a.created_at);
        msgs
    }

    /// Get messages for a thread, sorted by creation time.
    pub fn messages_for_thread(&self, thread_id: &str) -> Vec<&MessageState> {
        let mut msgs: Vec<_> = self
            .messages
            .values()
            .filter(|m| {
                m.thread_id == thread_id
                    && self
                        .redaction_cells
                        .get(&m.event_id)
                        .and_then(|cell| cell.as_ref())
                        .is_none()
            })
            .collect();
        msgs.sort_by_key(|a| a.created_at);
        msgs
    }

    /// Resolve a Message's `(created_at, sender, thread_id)` by target ref,
    /// accepting either the `ck:event:` storage id or the `ck:message:`
    /// object-ref form. Used by the constraint-schema.md §14.2 edit/redact
    /// window evaluator, which needs the original Message `created_at` to
    /// measure the elapsed window. Returns `None` for unknown targets.
    pub fn message_origin(
        &self,
        target_ref: &str,
    ) -> Option<(chrono::DateTime<chrono::Utc>, String, String)> {
        let event_id = message_event_id_from_ref(target_ref);
        let msg = self
            .messages
            .get(&event_id)
            .or_else(|| self.messages.get(target_ref))?;
        Some((msg.created_at, msg.sender.clone(), msg.thread_id.clone()))
    }

    /// Resolve the `realm_id` (effective scope) of a Message by target ref,
    /// accepting the `ck:message:` object-ref or `ck:event:` storage id.
    /// Used by the flow-and-message.md §9.8.2 reaction scope check. Returns
    /// `None` for unknown targets (the reducer's dependency handling then
    /// keeps the reaction pending).
    pub fn message_realm(&self, target_ref: &str) -> Option<String> {
        let event_id = message_event_id_from_ref(target_ref);
        self.messages
            .get(&event_id)
            .or_else(|| self.messages.get(target_ref))
            .map(|msg| msg.realm_id.clone())
    }

    /// Projection-layer view of a single message that
    /// consults the parallel `redaction` cell. Returns:
    ///   - `Some(view)` with `content = Some(_)` for live messages (no redaction cell set, or set
    ///     back to null);
    ///   - `Some(view)` with `content = None` + `redaction = Some(_)` when the parallel cell is in
    ///     effect — caller renders the tombstone;
    ///   - `None` if no underlying [`MessageState`] is known.
    ///
    /// The ordered-log historical entry id is preserved unchanged so
    /// federation / sync replay still emits the same `event_id`.
    pub fn projected_message(
        &self,
        event_id: &str,
        viewer_is_author: bool,
    ) -> Option<ProjectedMessageView> {
        let msg = self.messages.get(event_id)?;
        let redaction = self
            .redaction_cells
            .get(event_id)
            .and_then(|cell| cell.as_ref())
            .cloned();
        let content = match (&redaction, viewer_is_author) {
            // No redaction in effect — full payload visible.
            (None, _) => Some(msg.content.clone()),
            // Author keeps the audit-view of the original payload.
            (Some(_), true) => Some(msg.content.clone()),
            // Other members see the tombstone.
            (Some(_), false) => None,
        };
        Some(ProjectedMessageView {
            event_id: msg.event_id.clone(),
            realm_id: msg.realm_id.clone(),
            sender: msg.sender.clone(),
            thread_id: msg.thread_id.clone(),
            created_at: msg.created_at,
            content,
            redaction,
        })
    }

    /// Get active reactions for an event.
    pub fn reactions_for_event(&self, event_id: &str) -> Vec<&ReactionState> {
        self.reactions
            .get(event_id)
            .map(|by_actor| {
                by_actor
                    .values()
                    .flat_map(|by_key| by_key.values().filter(|r| r.active))
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn poll(&self, poll_id: &str) -> Option<&PollState> {
        self.polls.get(poll_id)
    }

    /// Get relations for a Realm, optionally filtered by kind.
    pub fn relations_for_realm(&self, realm_id: &str, kind: Option<&str>) -> Vec<&RelationState> {
        self.relations
            .values()
            .filter(|r| {
                r.realm_id == realm_id && r.is_active() && kind.is_none_or(|k| r.relation_kind == k)
            })
            .collect()
    }

    /// CKP-0007 — list the Flows that point AT `flow_id` via a
    /// `confidential_discussion_of` Relation. Useful for the discovery
    /// surface that resolves the "narrow discussion" companion of a
    /// "wide synthesis" Flow. Returns the `from_ref` side of each live
    /// matching relation.
    pub fn confidential_discussions_of(&self, flow_id: &str) -> Vec<&RelationState> {
        self.relations
            .values()
            .filter(|r| {
                r.is_active()
                    && r.relation_kind == crate::kinds::RELATION_KIND_CONFIDENTIAL_DISCUSSION_OF
                    && r.to_ref.as_deref() == Some(flow_id)
            })
            .collect()
    }

    /// Get members of a Realm currently in `state="join"`.
    /// For state-specific queries use [`members_in_state`].
    pub fn members_of_realm(&self, realm_id: &str) -> Vec<&MembershipState> {
        self.members_in_state(realm_id, "join")
    }

    /// All `MembershipState` entries for a Realm whose FSM state matches
    /// `state` (`invite` / `join` / `leave` / `ban` / `knock`).
    pub fn members_in_state(&self, realm_id: &str, state: &str) -> Vec<&MembershipState> {
        self.members
            .iter()
            .filter(|((sid, _), m)| sid == realm_id && m.state == state)
            .map(|(_, m)| m)
            .collect()
    }

    /// Look up a single `(realm_id, actor_did)` member entry.
    pub fn member(&self, realm_id: &str, actor_did: &str) -> Option<&MembershipState> {
        self.members
            .get(&(realm_id.to_owned(), actor_did.to_owned()))
    }

    /// Read the FSM state of a member directly from the cells map.
    /// Returns `None` if the cell hasn't been written or is in `Bottom`
    /// state. The cell_subject is the actor_did per spec
    /// `ck.component.member.state.v1` cell_family declaration.
    pub fn member_fsm_state(&self, actor_did: &str) -> Option<String> {
        let cell_id =
            cokret_sdk::CellRef::new(format!("ck:cell:ck.component.member.state.v1:{actor_did}"))
                .ok()?;
        self.cell_value(&cell_id)
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
    }

    // ── Cell-keyed query helpers ──

    /// Read the effective `ck.realm.read_receipt_policy` value out of the
    /// cells map. Returns `None` when:
    ///   - the cell has never been written, OR
    ///   - the cell is in `Bottom` state (concurrent conflict needs recovery)
    pub fn read_receipt_policy_cell_value(&self, realm_id: &str) -> Option<&Value> {
        let cell_id = cokret_sdk::CellRef::new(format!(
            "ck:cell:ck.component.realm.read_receipt_policy.v1:{realm_id}"
        ))
        .ok()?;
        self.cell_value(&cell_id)
    }

    // ── Realm lifecycle cell helpers ──

    /// Read the effective `ck.component.realm.organization.v1` cas-register
    /// value (mutable Realm metadata: owner, title, updated_at). Returns
    /// `None` if no `ck.realm.update` event has landed for this realm, or
    /// if the cell is in `Bottom` (concurrent admin updates require recovery).
    pub fn realm_organization_cell_value(&self, realm_id: &str) -> Option<&Value> {
        let cell_id = cokret_sdk::CellRef::new(format!(
            "ck:cell:ck.component.realm.organization.v1:{realm_id}"
        ))
        .ok()?;
        self.cell_value(&cell_id)
    }

    /// Read the `ck.component.realm.create.v1` ordered-log entries for the
    /// realm's genesis history. Returns `None` for realms with no create
    /// events (e.g. before first projection) or `Bottom` state.
    pub fn realm_create_log(&self, realm_id: &str) -> Option<&[Value]> {
        let cell_id =
            cokret_sdk::CellRef::new(format!("ck:cell:ck.component.realm.create.v1:{realm_id}"))
                .ok()?;
        match self.cells.get(&cell_id)? {
            CellState::Value(Value::Array(entries)) => Some(entries.as_slice()),
            _ => None,
        }
    }

    /// True when the `ck.component.realm.destroy.v1` cell has a Value
    /// (any non-Bottom value indicates a terminal-state commit landed).
    /// Equivalent to checking `realm_states[realm_id].deleted` but reads
    /// from the protocol-canonical cells map source.
    ///
    /// Stream-F (Wave 1B) note: this returns true for BOTH
    /// `ck.realm.tombstone` and `ck.realm.destroy` because they share
    /// the same cell family (`ck.component.realm.destroy.v1`). Callers
    /// that need to distinguish the two should consult
    /// [`Self::realm_is_in_terminal_state`] / [`RealmState::terminal_state`].
    pub fn realm_is_destroyed(&self, realm_id: &str) -> bool {
        let Ok(cell_id) =
            cokret_sdk::CellRef::new(format!("ck:cell:ck.component.realm.destroy.v1:{realm_id}"))
        else {
            return false;
        };
        matches!(self.cells.get(&cell_id), Some(CellState::Value(_)))
    }

    /// Stream-F (Wave 1B) — true if the Realm is in ANY terminal state
    /// (tombstoned OR destroyed). The wire-layer
    /// `terminal_realm_check` consults this to reject non-audit
    /// writes against terminal Realms. Spec
    /// `realm-and-space.md` §2.5 / §2.5.1.
    pub fn realm_is_in_terminal_state(&self, realm_id: &str) -> bool {
        if let Some(s) = self.realm_states.get(realm_id)
            && s.terminal_state.is_some()
        {
            return true;
        }
        // Fall back to the cell-presence check so peers that hydrate
        // from cells without rebuilding `realm_states` still see the
        // terminal state.
        self.realm_is_destroyed(realm_id)
    }

    /// Read the projected `ck.component.realm.delivery_binding_policy.v1`
    /// cas-register value, if any. R1.2 introduced a structured cache
    /// for this cell so the wire-validation path in
    /// `apply_membership` can fail-closed on routable joins when policy
    /// is unset. Once the projection mirror table
    /// for delivery_binding_policy lands, switch this from the generic
    /// cells map to the structured cache.
    pub fn realm_delivery_binding_policy_cell_value(&self, realm_id: &str) -> Option<&Value> {
        let cell_id = cokret_sdk::CellRef::new(format!(
            "ck:cell:ck.component.realm.delivery_binding_policy.v1:{realm_id}"
        ))
        .ok()?;
        self.cell_value(&cell_id)
    }

    pub fn realm_disappearing_policy_cell_value(&self, realm_id: &str) -> Option<&Value> {
        let cell_id = cokret_sdk::CellRef::new(format!(
            "ck:cell:ck.component.realm.disappearing_policy.v1:{realm_id}"
        ))
        .ok()?;
        self.cell_value(&cell_id)
    }

    pub fn realm_search_policy_cell_value(&self, realm_id: &str) -> Option<&Value> {
        let cell_id = cokret_sdk::CellRef::new(format!(
            "ck:cell:ck.component.realm.search_policy.v1:{realm_id}"
        ))
        .ok()?;
        self.cell_value(&cell_id)
    }

    /// Read the `policy_frontier` declared on the most recent
    /// `ck.realm.delivery_binding_policy` event for this realm. Wire
    /// this up to a structured cache so the
    /// reducer can emit `delivery_binding_stale` rejections.
    pub fn realm_delivery_binding_policy_frontier(&self, realm_id: &str) -> Option<&str> {
        self.realm_delivery_binding_policy_cell_value(realm_id)?
            .get("policy_frontier")
            .and_then(Value::as_str)
    }

    /// R3.1 — query realm links by direction and optional link_kind
    /// allow-list. Returns a Vec sorted by `(target_realm_id, link_kind)`
    /// so the response is stable across calls.
    ///
    /// `direction` controls which side(s) of the edge to return:
    /// `outbound` → edges where `realm_id == realm_id`, `inbound` →
    /// edges where `target_realm_id == realm_id`, `both` → both
    /// (outbound first, inbound second).
    pub fn realm_links_query(
        &self,
        realm_id: &str,
        direction: cokret_sdk::RealmLinkDirection,
        link_kind_allow: Option<&[String]>,
    ) -> Vec<RealmLinkState> {
        use cokret_sdk::RealmLinkDirection;
        let filter = |row: &&RealmLinkState| {
            link_kind_allow
                .map(|allow| allow.iter().any(|k| k == &row.link_kind))
                .unwrap_or(true)
        };
        let mut out: Vec<RealmLinkState> = Vec::new();
        if matches!(
            direction,
            RealmLinkDirection::Outbound | RealmLinkDirection::Both
        ) {
            if let Some(rows) = self.realm_links.get(realm_id) {
                out.extend(rows.iter().filter(filter).cloned());
            }
        }
        if matches!(
            direction,
            RealmLinkDirection::Inbound | RealmLinkDirection::Both
        ) {
            if let Some(rows) = self.realm_links_inbound.get(realm_id) {
                out.extend(rows.iter().filter(filter).cloned());
            }
        }
        out.sort_by(|a, b| {
            a.target_realm_id
                .cmp(&b.target_realm_id)
                .then(a.link_kind.cmp(&b.link_kind))
                .then(a.realm_id.cmp(&b.realm_id))
        });
        out
    }

    /// R3.2 — read the most-recent `ck.realm.inheritance_policy`
    /// projection for a child Realm, if any.
    pub fn realm_inheritance_policy(&self, realm_id: &str) -> Option<&RealmInheritancePolicyState> {
        self.realm_inheritance_policies.get(realm_id)
    }

    /// R3.2 — read the most-recent `ck.capability.derived` projection
    /// for a capability id, if any.
    pub fn capability_derived_state(&self, capability_id: &str) -> Option<&CapabilityDerivedState> {
        self.capability_derived.get(capability_id)
    }

    /// G3.S2 — read the most-recent `ck.realm.policy_server` projection
    /// for a Realm, walking up the `governed_by` link chain when the
    /// realm itself has no row of its own (org-level fallback). Returns
    /// `None` if neither the realm nor any ancestor declared a policy
    /// server. The walk caps at depth 8 to avoid runaway cycles —
    /// `realm_links.rs` does cycle detection on writes, but the cap is
    /// a defence-in-depth for projections that may have hydrated from
    /// pre-cycle-detection persistence.
    pub fn realm_policy_server_config(&self, realm_id: &str) -> Option<&RealmPolicyServerConfig> {
        if let Some(cfg) = self.realm_policy_servers.get(realm_id) {
            return Some(cfg);
        }
        // Org-level fallback: walk `governed_by` outbound links.
        let mut cursor = realm_id.to_owned();
        for _ in 0..8 {
            let next = self.realm_links.get(&cursor).and_then(|rows| {
                rows.iter()
                    .find(|r| r.link_kind == "governed_by" && r.status == "active")
                    .map(|r| r.target_realm_id.clone())
            })?;
            if next == cursor {
                return None;
            }
            if let Some(cfg) = self.realm_policy_servers.get(&next) {
                return Some(cfg);
            }
            cursor = next;
        }
        None
    }

    /// R3.3 — read the ordered audit log of
    /// `ck.realm.audit_policy_downgrade` entries for a Realm.
    pub fn realm_audit_downgrades(&self, realm_id: &str) -> &[RealmAuditDowngradeEntry] {
        self.realm_audit_downgrades
            .get(realm_id)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    /// Read the create-locked Realm encryption profile from the genesis
    /// create-log. `ck.realm.update` must never mutate this value.
    pub fn realm_encryption_profile(&self, realm_id: &str) -> Option<String> {
        self.realm_create_log(realm_id)
            .and_then(|entries| entries.last())
            .and_then(|entry| entry.get("encryption_profile"))
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
    }

    pub fn realm_requires_content_encryption(&self, realm_id: &str) -> bool {
        encryption_profile_requires_content_encryption(
            self.realm_encryption_profile(realm_id).as_deref(),
        )
    }

    /// R3.4 — read the projected Realm `security_class` (from the
    /// `ck.component.realm.organization.v1` cas-register cell). Returns
    /// `None` when no Realm-update has landed yet — caller may infer
    /// `standard` per spec default.
    pub fn realm_security_class(&self, realm_id: &str) -> Option<String> {
        // First check the organization cell (cas-register, last write
        // wins; carries the most recent update).
        if let Ok(org_cell) = cokret_sdk::CellRef::new(format!(
            "ck:cell:ck.component.realm.organization.v1:{realm_id}"
        )) {
            if let Some(v) = self
                .cell_value(&org_cell)
                .and_then(|c| c.get("security_class"))
                .and_then(Value::as_str)
            {
                return Some(v.to_owned());
            }
        }
        // Fallback: check the create-log cell's last entry.
        if let Ok(create_cell) =
            cokret_sdk::CellRef::new(format!("ck:cell:ck.component.realm.create.v1:{realm_id}"))
        {
            if let Some(arr) = self.cell_value(&create_cell).and_then(Value::as_array) {
                if let Some(last) = arr.last() {
                    if let Some(s) = last.get("security_class").and_then(Value::as_str) {
                        return Some(s.to_owned());
                    }
                }
            }
        }
        None
    }

    /// R3.4 — read the effective Realm federation policy. The mutable
    /// organization cas-register wins; when no update has landed, fall
    /// back to the latest `ck.realm.create` log entry that carried an
    /// initial `federation_policy`.
    pub fn realm_federation_policy(&self, realm_id: &str) -> Option<String> {
        if let Ok(org_cell) = cokret_sdk::CellRef::new(format!(
            "ck:cell:ck.component.realm.organization.v1:{realm_id}"
        )) {
            if let Some(v) = self
                .cell_value(&org_cell)
                .and_then(|c| c.get("federation_policy"))
                .and_then(Value::as_str)
            {
                return Some(v.to_owned());
            }
        }
        self.realm_create_log(realm_id).and_then(|entries| {
            entries.iter().rev().find_map(|entry| {
                entry
                    .get("federation_policy")
                    .and_then(Value::as_str)
                    .map(ToOwned::to_owned)
            })
        })
    }
}

/// Spec T07 — federation fanout window for erasure receipts emitted by
/// `ck.realm.destroy`. Spec: 30 days.
pub const REALM_DESTROY_FANOUT_WINDOW_DAYS: i64 = 30;

/// Extract the operator-supplied human reason from a redaction payload,
/// preferring an explicit `human_reason` over the machine `reason` /
/// `reason_text` fields. Returns `None` when no non-empty reason is
/// present.
pub(crate) fn redaction_human_reason(payload: &Value) -> Option<String> {
    ["human_reason", "reason", "reason_text"]
        .iter()
        .find_map(|field| {
            payload
                .get(*field)
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToOwned::to_owned)
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redaction_human_reason_prefers_explicit_field() {
        let payload = serde_json::json!({
            "target_event_id": "ck:event:01904100-0000-7000-8000-000000000abc",
            "reason": "machine policy",
            "human_reason": "moderator request"
        });

        assert_eq!(
            redaction_human_reason(&payload).as_deref(),
            Some("moderator request")
        );
    }
    use crate::hlc::ServerHlc;

    fn make_operation(object_type: &str, realm_id: &str, payload: Value) -> Operation {
        Operation::create(
            cokret_sdk::OperationId::new(format!("ck:operation:{}", uuid::Uuid::now_v7())).unwrap(),
            cokret_sdk::RealmId::new(realm_id).unwrap(),
            object_type,
            payload,
        )
    }

    #[test]
    fn message_create_and_query() {
        let mut state = ProjectionState::new();
        let hlc = ServerHlc::new("test");
        let op = make_operation(
            crate::kinds::CK_MESSAGE_CREATE,
            "ck:realm:01904100-0000-7000-8000-cfc039892036",
            serde_json::json!({
                "event_id": "ck:event:01904100-0000-7000-8000-caaa6a15bce1",
                "sender": "did:web:alice",
                "thread_id": "ck:flow:1",
                "content": {"kind": "ck.content.text", "body": "hello"}
            }),
        );
        let effect = state.apply(&op, &hlc);
        assert!(matches!(effect, ProjectionEffect::MessageCreated(_)));

        let msgs = state.messages_for_realm("ck:realm:01904100-0000-7000-8000-cfc039892036");
        assert_eq!(msgs.len(), 1);
        assert_eq!(
            msgs[0].event_id,
            "ck:event:01904100-0000-7000-8000-caaa6a15bce1"
        );
    }

    #[test]
    fn redaction_hides_message() {
        let mut state = ProjectionState::new();
        let hlc = ServerHlc::new("test");

        state.apply(
            &make_operation(
                crate::kinds::CK_MESSAGE_CREATE,
                "ck:realm:01904100-0000-7000-8000-cfc039892036",
                serde_json::json!({
                    "event_id": "ck:event:01904100-0000-7000-8000-caaa6a15bce1",
                    "sender": "did:web:alice",
                    "thread_id": "ck:flow:1",
                    "content": {"kind": "ck.content.text", "body": "hello"}
                }),
            ),
            &hlc,
        );
        state.apply(
            &make_operation(
                crate::kinds::CK_MESSAGE_REDACT,
                "ck:realm:01904100-0000-7000-8000-cfc039892036",
                serde_json::json!({
                    "target_event_id": "ck:event:01904100-0000-7000-8000-caaa6a15bce1",
                    "by": "did:web:alice",
                    "reason": "wrong room"
                }),
            ),
            &hlc,
        );

        assert!(
            state
                .messages_for_realm("ck:realm:01904100-0000-7000-8000-cfc039892036")
                .is_empty()
        );
        assert!(
            state
                .redactions
                .contains("ck:event:01904100-0000-7000-8000-caaa6a15bce1")
        );
        // The original MessageState is preserved (only the
        // parallel cell + flat redactions index move).
        assert!(
            state
                .messages
                .contains_key("ck:event:01904100-0000-7000-8000-caaa6a15bce1")
        );
        let cell = state
            .redaction_cells
            .get("ck:event:01904100-0000-7000-8000-caaa6a15bce1")
            .cloned()
            .unwrap()
            .unwrap();
        assert_eq!(cell.by, "did:web:alice");
        assert_eq!(cell.reason.as_deref(), Some("wrong room"));
    }

    // ── Redaction reducer tests ───────────────────────────────────────

    fn redact_make_message(state: &mut ProjectionState, hlc: &ServerHlc, event_id: &str) {
        state.apply(
            &make_operation(
                crate::kinds::CK_MESSAGE_CREATE,
                "ck:realm:01904100-0000-7000-8000-cfc039892036",
                serde_json::json!({
                    "event_id": event_id,
                    "sender": "did:web:alice",
                    "thread_id": "ck:flow:1",
                    "content": {"kind": "ck.content.text", "body": "hello"}
                }),
            ),
            hlc,
        );
    }

    #[test]
    fn mal14_tombstone_visible_to_author() {
        let mut state = ProjectionState::new();
        let hlc = ServerHlc::new("test");
        let event_id = "ck:event:01904100-0000-7000-8000-aaaaaaaaaaa1";
        redact_make_message(&mut state, &hlc, event_id);
        state.apply(
            &make_operation(
                crate::kinds::CK_MESSAGE_REDACT,
                "ck:realm:01904100-0000-7000-8000-cfc039892036",
                serde_json::json!({
                    "target_event_id": event_id,
                    "by": "did:web:alice",
                    "reason": "policy:auto",
                    "human_reason": "rethink",
                }),
            ),
            &hlc,
        );
        let view = state.projected_message(event_id, true).unwrap();
        // Author still sees the original payload (audit-view).
        assert!(view.content.is_some(), "author should see original content");
        // Tombstone metadata is also present.
        let r = view.redaction.unwrap();
        assert_eq!(r.by, "did:web:alice");
        assert_eq!(r.reason.as_deref(), Some("rethink"));
    }

    #[test]
    fn mal14_tombstone_hidden_from_members() {
        let mut state = ProjectionState::new();
        let hlc = ServerHlc::new("test");
        let event_id = "ck:event:01904100-0000-7000-8000-aaaaaaaaaaa2";
        redact_make_message(&mut state, &hlc, event_id);
        state.apply(
            &make_operation(
                crate::kinds::CK_MESSAGE_REDACT,
                "ck:realm:01904100-0000-7000-8000-cfc039892036",
                serde_json::json!({
                    "target_event_id": event_id,
                    "by": "did:web:alice",
                }),
            ),
            &hlc,
        );
        let view = state.projected_message(event_id, false).unwrap();
        assert!(view.content.is_none(), "non-author should see tombstone");
        assert!(view.redaction.is_some());
    }

    #[test]
    fn mal14_unredaction_clears_cell_and_index() {
        let mut state = ProjectionState::new();
        let hlc = ServerHlc::new("test");
        let event_id = "ck:event:01904100-0000-7000-8000-aaaaaaaaaaa3";
        redact_make_message(&mut state, &hlc, event_id);
        // Redact.
        state.apply(
            &make_operation(
                crate::kinds::CK_MESSAGE_REDACT,
                "ck:realm:01904100-0000-7000-8000-cfc039892036",
                serde_json::json!({
                    "target_event_id": event_id,
                    "by": "did:web:alice",
                }),
            ),
            &hlc,
        );
        assert!(state.redactions.contains(event_id));
        // Un-redact via cas-register set null.
        state.apply(
            &make_operation(
                crate::kinds::CK_MESSAGE_REDACT,
                "ck:realm:01904100-0000-7000-8000-cfc039892036",
                serde_json::json!({
                    "target_event_id": event_id,
                    "redaction_value": serde_json::Value::Null,
                }),
            ),
            &hlc,
        );
        assert!(
            !state.redactions.contains(event_id),
            "un-redaction must clear the flat tombstone index"
        );
        let cell = state.redaction_cells.get(event_id).unwrap();
        assert!(cell.is_none(), "parallel cell must be set to null");
        // Un-redacted message renders content for everyone again.
        let view_member = state.projected_message(event_id, false).unwrap();
        assert!(view_member.content.is_some());
        assert!(view_member.redaction.is_none());
    }

    #[test]
    fn mal14_late_arriving_redaction_still_takes_effect() {
        let mut state = ProjectionState::new();
        let hlc = ServerHlc::new("test");
        let event_id = "ck:event:01904100-0000-7000-8000-aaaaaaaaaaa4";
        // Pre-create the projected message and let the projection
        // rendering query it once before the redaction lands.
        redact_make_message(&mut state, &hlc, event_id);
        let pre = state.projected_message(event_id, false).unwrap();
        assert!(pre.content.is_some());
        assert!(pre.redaction.is_none());
        // Now a delayed redaction arrives.
        state.apply(
            &make_operation(
                crate::kinds::CK_MESSAGE_REDACT,
                "ck:realm:01904100-0000-7000-8000-cfc039892036",
                serde_json::json!({
                    "target_event_id": event_id,
                    "by": "did:web:alice",
                    "reason": "late",
                }),
            ),
            &hlc,
        );
        let post = state.projected_message(event_id, false).unwrap();
        assert!(
            post.content.is_none(),
            "late-arriving redaction must hide payload from non-authors"
        );
        let r = post.redaction.unwrap();
        assert_eq!(r.reason.as_deref(), Some("late"));
        // The flat-redactions index now has the entry.
        assert!(state.redactions.contains(event_id));
        // Author still sees the audit-view.
        let post_author = state.projected_message(event_id, true).unwrap();
        assert!(post_author.content.is_some());
    }

    #[test]
    fn reaction_or_set_convergence() {
        let mut state = ProjectionState::new();
        let hlc = ServerHlc::new("test");

        state.apply(
            &make_operation(
                crate::kinds::CK_REACTION_ADD,
                "ck:realm:01904100-0000-7000-8000-cfc039892036",
                serde_json::json!({
                    "event_id": "ck:event:01904100-0000-7000-8000-caaa6a15bce1",
                    "actor": "did:web:alice",
                    "key": "👍"
                }),
            ),
            &hlc,
        );
        assert_eq!(
            state
                .reactions_for_event("ck:event:01904100-0000-7000-8000-caaa6a15bce1")
                .len(),
            1
        );

        state.apply(
            &make_operation(
                crate::kinds::CK_REACTION_REMOVE,
                "ck:realm:01904100-0000-7000-8000-cfc039892036",
                serde_json::json!({
                    "event_id": "ck:event:01904100-0000-7000-8000-caaa6a15bce1",
                    "actor": "did:web:alice",
                    "key": "👍"
                }),
            ),
            &hlc,
        );
        assert_eq!(
            state
                .reactions_for_event("ck:event:01904100-0000-7000-8000-caaa6a15bce1")
                .len(),
            0
        );
    }

    #[test]
    fn membership_join_leave() {
        let mut state = ProjectionState::new();
        let hlc = ServerHlc::new("test");

        // `membership=join` MUST carry `delivery_status` per
        // cokret-spec/spec/v1/zh/governance/join-policy.md §5.1.1.
        // We use `unroutable` so the projection write path does not
        // additionally require a projected `ck.realm.delivery_binding_policy`
        // cell (`routable` joins are exercised by the delivery-binding
        // suite).
        state.apply(
            &make_operation(
                crate::kinds::CK_MEMBER_STATE,
                "ck:realm:01904100-0000-7000-8000-cfc039892036",
                serde_json::json!({
                    "actor_id": "did:web:bob",
                    "membership": "join",
                    "role": "member",
                    "delivery_status": "unroutable"
                }),
            ),
            &hlc,
        );
        assert_eq!(
            state
                .members_of_realm("ck:realm:01904100-0000-7000-8000-cfc039892036")
                .len(),
            1
        );

        state.apply(
            &make_operation(
                crate::kinds::CK_MEMBER_STATE,
                "ck:realm:01904100-0000-7000-8000-cfc039892036",
                serde_json::json!({
                    "actor_id": "did:web:bob",
                    "membership": "leave"
                }),
            ),
            &hlc,
        );
        assert_eq!(
            state
                .members_of_realm("ck:realm:01904100-0000-7000-8000-cfc039892036")
                .len(),
            0
        );
    }

    #[test]
    fn message_revise_creates_chain() {
        let mut state = ProjectionState::new();
        let hlc = ServerHlc::new("test");

        state.apply(
            &make_operation(
                crate::kinds::CK_MESSAGE_CREATE,
                "ck:realm:01904100-0000-7000-8000-cfc039892036",
                serde_json::json!({
                    "event_id": "ck:event:01904100-0000-7000-8000-caaa6a15bce1",
                    "sender": "did:web:alice",
                    "thread_id": "ck:flow:1",
                    "content": {"kind": "ck.content.text", "body": "original"}
                }),
            ),
            &hlc,
        );

        state.apply(
            &make_operation(
                crate::kinds::CK_MESSAGE_REVISE,
                "ck:realm:01904100-0000-7000-8000-cfc039892036",
                serde_json::json!({
                    "target_ref": "ck:event:01904100-0000-7000-8000-caaa6a15bce1",
                    "new_event_id": "ck:event:01904100-0000-7000-8000-c4daaba541fc",
                    "content": {"kind": "ck.content.text", "body": "revised"}
                }),
            ),
            &hlc,
        );

        let msgs = state.messages_for_realm("ck:realm:01904100-0000-7000-8000-cfc039892036");
        assert_eq!(msgs.len(), 2); // original + revision
        let revision = msgs
            .iter()
            .find(|m| m.event_id == "ck:event:01904100-0000-7000-8000-c4daaba541fc")
            .unwrap();
        assert_eq!(
            revision.revision_of.as_deref(),
            Some("ck:event:01904100-0000-7000-8000-caaa6a15bce1")
        );
    }

    // ── Cells map tests ──

    #[test]
    fn cell_value_returns_none_for_unwritten_cell() {
        let state = ProjectionState::new();
        let cell_id = cokret_sdk::CellRef::new(
            "ck:cell:ck.component.realm.read_receipt_policy.v1:ck:realm:01904100-0000-7000-8000-cfc039892036".to_owned(),
        )
        .unwrap();
        assert!(state.cell(&cell_id).is_none());
        assert!(state.cell_value(&cell_id).is_none());
    }

    #[test]
    fn cell_value_returns_none_for_bottom_state() {
        use cokret_sdk::lattice::CellState;
        let mut state = ProjectionState::new();
        let cell_id = cokret_sdk::CellRef::new(
            "ck:cell:ck.component.realm.policy.v1:ck:realm:01904100-0000-7000-8000-cfc039892036"
                .to_owned(),
        )
        .unwrap();
        // Manually insert a Bottom state — represents concurrent conflict.
        let bottom = cokret_sdk::Bottom {
            kind: cokret_sdk::BottomKind::Conflict,
            cells: vec![cell_id.clone()],
            move_ids: vec![],
            anchor_view: None,
            heads: vec![],
            details: Some(serde_json::json!({"reason": "concurrent set"})),
            escalated_at: None,
        };
        state
            .cells
            .insert(cell_id.clone(), CellState::Bottom(bottom));

        // cell() returns Some(Bottom)
        assert!(matches!(state.cell(&cell_id), Some(CellState::Bottom(_))));
        // cell_value() filters out Bottom.
        assert!(state.cell_value(&cell_id).is_none());
    }

    // ── Membership cache + FSM cell tests ──

    #[test]
    fn membership_join_writes_both_structured_cache_and_fsm_cell() {
        let mut state = ProjectionState::new();
        let hlc = ServerHlc::new("test");

        // `membership=join` MUST carry `delivery_status` per
        // cokret-spec/spec/v1/zh/governance/join-policy.md §5.1.1.
        // `unroutable` keeps the projection focused on the FSM cell +
        // structured cache write paths without requiring a projected
        // realm delivery-binding policy.
        state.apply(
            &make_operation(
                crate::kinds::CK_MEMBER_STATE,
                "ck:realm:01904100-0000-7000-8000-cfc039892036",
                serde_json::json!({
                    "actor_id": "did:web:alice",
                    "membership": "join",
                    "role": "admin",
                    "delivery_status": "unroutable"
                }),
            ),
            &hlc,
        );

        // Structured cache populated with state="join" + role="admin".
        let m = state
            .member(
                "ck:realm:01904100-0000-7000-8000-cfc039892036",
                "did:web:alice",
            )
            .expect("member entry should exist after join");
        assert_eq!(m.state, "join");
        assert_eq!(m.role, "admin");

        // FSM cell populated.
        assert_eq!(
            state.member_fsm_state("did:web:alice").as_deref(),
            Some("join")
        );

        // members_of_realm only returns entries in `state="join"`.
        assert_eq!(
            state
                .members_of_realm("ck:realm:01904100-0000-7000-8000-cfc039892036")
                .len(),
            1
        );
    }

    #[test]
    fn ban_then_invite_round_trips_through_fsm_states() {
        let mut state = ProjectionState::new();
        let hlc = ServerHlc::new("test");

        // join -> ban -> invite — full FSM lifecycle.
        for membership in ["join", "ban"] {
            state.apply(
                &make_operation(
                    crate::kinds::CK_MEMBER_STATE,
                    "ck:realm:01904100-0000-7000-8000-cfc039892036",
                    serde_json::json!({
                        "actor_id": "did:web:bob",
                        "membership": membership,
                        "role": "member"
                    }),
                ),
                &hlc,
            );
        }

        // After ban, Bob is in `members_in_state("ban")` and NOT in
        // `members_of_realm()` (which filters by `state="join"`).
        assert_eq!(
            state
                .members_in_state("ck:realm:01904100-0000-7000-8000-cfc039892036", "ban")
                .len(),
            1
        );
        assert_eq!(
            state
                .members_of_realm("ck:realm:01904100-0000-7000-8000-cfc039892036")
                .len(),
            0
        );
        assert_eq!(
            state.member_fsm_state("did:web:bob").as_deref(),
            Some("ban")
        );

        // invite returns the actor to the invite state.
        state.apply(
            &make_operation(
                crate::kinds::CK_MEMBER_STATE,
                "ck:realm:01904100-0000-7000-8000-cfc039892036",
                serde_json::json!({"actor_id": "did:web:bob", "membership": "invite"}),
            ),
            &hlc,
        );
        assert_eq!(
            state.member_fsm_state("did:web:bob").as_deref(),
            Some("invite")
        );
        assert_eq!(
            state
                .members_in_state("ck:realm:01904100-0000-7000-8000-cfc039892036", "ban")
                .len(),
            0
        );
        assert_eq!(
            state
                .members_in_state("ck:realm:01904100-0000-7000-8000-cfc039892036", "invite")
                .len(),
            1
        );
    }

    // ── Realm lifecycle cache + cell tests ──

    #[test]
    fn realm_create_writes_both_structured_cache_and_ordered_log_cell() {
        let mut state = ProjectionState::new();
        let hlc = ServerHlc::new("test");
        state.apply(
            &make_operation(
                crate::kinds::CK_REALM_CREATE,
                "ck:realm:01904100-0000-7000-8000-cfc039892036",
                serde_json::json!({
                    "action": "create",
                    "owner": "did:web:alice",
                    "title": "Test Realm",
                }),
            ),
            &hlc,
        );

        // Structured cache populated.
        let realm = state
            .realm_states
            .get("ck:realm:01904100-0000-7000-8000-cfc039892036")
            .expect("realm_states entry should exist after create");
        assert_eq!(realm.owner.as_deref(), Some("did:web:alice"));
        assert_eq!(realm.title.as_deref(), Some("Test Realm"));
        assert!(!realm.deleted);

        // Ordered-log cell has one entry.
        let log = state
            .realm_create_log("ck:realm:01904100-0000-7000-8000-cfc039892036")
            .expect("create cell should be a Value(Array)");
        assert_eq!(log.len(), 1);
        assert_eq!(
            log[0].get("owner").and_then(Value::as_str),
            Some("did:web:alice")
        );
    }

    #[test]
    fn realm_update_writes_organization_cell_with_cas_register_semantics() {
        let mut state = ProjectionState::new();
        let hlc = ServerHlc::new("test");
        state.apply(
            &make_operation(
                crate::kinds::CK_REALM_UPDATE,
                "ck:realm:01904100-0000-7000-8000-cfc039892036",
                serde_json::json!({
                    "action": "update",
                    "owner": "did:web:alice",
                    "title": "Renamed Realm",
                }),
            ),
            &hlc,
        );

        let value = state
            .realm_organization_cell_value("ck:realm:01904100-0000-7000-8000-cfc039892036")
            .expect("organization cell should resolve to Value");
        assert_eq!(
            value.get("title").and_then(Value::as_str),
            Some("Renamed Realm")
        );
        assert_eq!(
            value.get("owner").and_then(Value::as_str),
            Some("did:web:alice")
        );
        // updated_at is a server-side timestamp present on every update.
        assert!(value.get("updated_at").is_some());
    }

    #[test]
    fn concurrent_realm_updates_with_same_basis_expose_bottom_and_repair_clears() {
        let mut state = ProjectionState::new();
        let hlc = ServerHlc::new("test");
        let realm = "ck:realm:01904100-0000-7000-8000-cfc039892036";
        let basis =
            "ck:anchor:sha256:0000000000000000000000000000000000000000000000000000000000000000";
        let first = make_operation(
            crate::kinds::CK_REALM_UPDATE,
            realm,
            serde_json::json!({
                "patch": {"title": {"$op": "set", "value": "renamed by alice"}},
                "anchor_ref": basis,
            }),
        );
        let first_id = first.operation_id.as_str().to_owned();
        state.apply(&first, &hlc);

        let second = make_operation(
            crate::kinds::CK_REALM_UPDATE,
            realm,
            serde_json::json!({
                "patch": {"title": {"$op": "set", "value": "renamed by bob"}},
                "anchor_ref": basis,
            }),
        );
        let second_id = second.operation_id.as_str().to_owned();
        state.apply(&second, &hlc);

        let cell = ProjectionState::realm_organization_cell_id(realm).unwrap();
        let bottom = match state.cell(&cell) {
            Some(CellState::Bottom(bottom)) => bottom,
            other => panic!("expected bottom cell, got {other:?}"),
        };
        assert_eq!(bottom.heads.len(), 2);
        assert_eq!(
            bottom.heads[0].get("move_id").and_then(Value::as_str),
            Some(first_id.as_str())
        );
        assert_eq!(
            bottom.heads[1].get("move_id").and_then(Value::as_str),
            Some(second_id.as_str())
        );
        assert_eq!(
            state.check_bottom_cell_transition(&make_operation(
                crate::kinds::CK_REALM_UPDATE,
                realm,
                serde_json::json!({
                    "patch": {"title": {"$op": "set", "value": "blocked while bottom"}},
                }),
            )),
            Err("cell_bottom_state")
        );

        let repair = make_operation(
            crate::kinds::CK_CONFLICT_REPAIR,
            realm,
            serde_json::json!({
                "cell_id": cell.as_str(),
                "conflict_heads": [first_id, second_id],
                "recovery_capability_ref": "cap.recovery-01",
                "winner_value": {"title": "renamed by alice"},
                "state_witness": basis,
            }),
        );
        state.apply(&repair, &hlc);
        let repaired = state
            .realm_organization_cell_value(realm)
            .expect("repair should restore cell value");
        assert_eq!(
            repaired.get("title").and_then(Value::as_str),
            Some("renamed by alice")
        );
        assert!(
            repaired
                .get("repair_of")
                .and_then(Value::as_array)
                .is_some()
        );
    }

    #[test]
    fn realm_destroy_writes_destroy_cell_and_marks_cache_deleted() {
        let mut state = ProjectionState::new();
        let hlc = ServerHlc::new("test");
        // First create...
        state.apply(
            &make_operation(
                crate::kinds::CK_REALM_CREATE,
                "ck:realm:01904100-0000-7000-8000-cfc039892036",
                serde_json::json!({"action": "create", "owner": "did:web:alice"}),
            ),
            &hlc,
        );
        assert!(!state.realm_is_destroyed("ck:realm:01904100-0000-7000-8000-cfc039892036"));

        // ...then destroy.
        state.apply(
            &make_operation(
                crate::kinds::CK_REALM_DESTROY,
                "ck:realm:01904100-0000-7000-8000-cfc039892036",
                serde_json::json!({"action": "destroy"}),
            ),
            &hlc,
        );

        // Cell-keyed query returns true.
        assert!(state.realm_is_destroyed("ck:realm:01904100-0000-7000-8000-cfc039892036"));
        // Structured cache mirror agrees.
        let realm = state
            .realm_states
            .get("ck:realm:01904100-0000-7000-8000-cfc039892036")
            .unwrap();
        assert!(realm.deleted);
    }

    /// Stream-F (Wave 2C) — spec `realm-and-space.md` §2.5.1 ¶6.
    /// `ck.realm.destroy` on Realm A must mark cross-Realm child
    /// Spaces in Realm B (whose `parent_ref` points at a Space hosted
    /// inside Realm A) with `parent_ref_locked = true`. The child
    /// Space in Realm B stays alive (it's only the parent edge that
    /// gets downgraded to a locked / lazy link).
    #[test]
    fn cascade_realm_destroy_locks_cross_realm_parent_ref() {
        let mut state = ProjectionState::new();
        let hlc = ServerHlc::new("test");
        let realm_a = "ck:realm:01904100-0000-7000-8000-aaaaaaaaaaaa";
        let realm_b = "ck:realm:01904100-0000-7000-8000-bbbbbbbbbbbb";
        let parent_in_a = "ck:space:01904100-0000-7000-8000-000000000001";
        let child_in_b = "ck:space:01904100-0000-7000-8000-000000000002";
        // Container hosted inside Realm A (the to-be-destroyed Realm).
        state.apply(
            &make_operation(
                crate::kinds::CK_SPACE_CONTAINER_CREATE,
                realm_a,
                serde_json::json!({
                    "object": {
                        "id": parent_in_a,
                        "realm_id": realm_a,
                        "kind": "folder",
                        "title": "Parent in Realm A",
                    }
                }),
            ),
            &hlc,
        );
        // Container hosted inside Realm B whose parent_ref points at
        // the Realm-A container.
        state.apply(
            &make_operation(
                crate::kinds::CK_SPACE_CONTAINER_CREATE,
                realm_b,
                serde_json::json!({
                    "object": {
                        "id": child_in_b,
                        "realm_id": realm_b,
                        "kind": "folder",
                        "title": "Child in Realm B",
                        "parent_ref": parent_in_a,
                    }
                }),
            ),
            &hlc,
        );

        // Pre-condition: neither container is locked.
        let child_pre = state.space_containers.get(child_in_b).unwrap();
        assert!(!child_pre.parent_ref_locked);
        assert!(!child_pre.orphaned);

        // Destroy Realm A.
        state.apply(
            &make_operation(
                crate::kinds::CK_REALM_DESTROY,
                realm_a,
                serde_json::json!({"action": "destroy"}),
            ),
            &hlc,
        );

        // Post-condition: child in Realm B has parent_ref_locked=true
        // but is NOT marked orphaned (it lives in Realm B, which is
        // still active).
        let child_post = state.space_containers.get(child_in_b).unwrap();
        assert!(
            child_post.parent_ref_locked,
            "cross-Realm parent_ref must be locked after parent's home Realm is destroyed"
        );
        assert!(
            !child_post.orphaned,
            "child Space in Realm B is NOT orphaned — only its parent edge is downgraded"
        );
        // The same-Realm container in Realm A IS orphaned by the
        // existing ¶6 same-realm cascade.
        let parent_post = state.space_containers.get(parent_in_a).unwrap();
        assert!(
            parent_post.orphaned,
            "container hosted in destroyed Realm A must be orphaned"
        );
    }

    /// Stream-F (Wave 2C) — `ck.audit.erasure_receipt` reducer pass
    /// extracts `scope.realm_id`, seeds an empty `peer_status` map,
    /// and stamps `fanout_status = "pending"`. The federation outbox
    /// enqueue + per-peer seeding is exercised by
    /// `crate::routing::federation::erasure_fanout::tests`.
    #[test]
    fn audit_erasure_receipt_records_scope_realm_id_and_pending_fanout() {
        let mut state = ProjectionState::new();
        let hlc = ServerHlc::new("test");
        state.apply(
            &make_operation(
                crate::kinds::CK_AUDIT_ERASURE_RECEIPT,
                "ck:realm:01904100-0000-7000-8000-cfc039892036",
                serde_json::json!({
                    "receipt_id": "ck:receipt:01",
                    "schema": "ck.schema.erasure_receipt.v1",
                    "issuer": "did:web:soland.local",
                    "subject": {"kind": "realm", "ref": "ck:realm:01904100-0000-7000-8000-cfc039892036"},
                    "scope": {
                        "storage_boundary": "projection_store",
                        "realm_id": "ck:realm:01904100-0000-7000-8000-cfc039892036",
                    },
                    "outcome": "completed",
                }),
            ),
            &hlc,
        );
        assert_eq!(state.erasure_receipts.len(), 1);
        let record = &state.erasure_receipts[0];
        assert_eq!(record.receipt_id.as_deref(), Some("ck:receipt:01"));
        assert_eq!(record.outcome, "completed");
        assert_eq!(
            record.scope_realm_id.as_deref(),
            Some("ck:realm:01904100-0000-7000-8000-cfc039892036"),
            "scope.realm_id MUST be extracted for the federation fanout pass"
        );
        assert_eq!(record.fanout_status, "pending");
        // peer_status is seeded by the federation fanout helper
        // (outside the reducer) so the in-reducer projection starts
        // empty.
        assert!(record.peer_status.is_empty());
    }

    #[test]
    fn realm_create_log_appends_on_repeated_create_events() {
        let mut state = ProjectionState::new();
        let hlc = ServerHlc::new("test");
        for owner in ["did:web:alice", "did:web:bob"] {
            state.apply(
                &make_operation(
                    crate::kinds::CK_REALM_CREATE,
                    "ck:realm:01904100-0000-7000-8000-cfc039892036",
                    serde_json::json!({"action": "create", "owner": owner}),
                ),
                &hlc,
            );
        }
        let log = state
            .realm_create_log("ck:realm:01904100-0000-7000-8000-cfc039892036")
            .unwrap();
        assert_eq!(log.len(), 2, "ordered-log should accumulate entries");
    }

    #[test]
    fn realm_organization_cell_returns_none_for_uncreated_realm() {
        let realm_id = "ck:realm:01904100-0000-7000-8000-0f863ed7d6d2";
        let state = ProjectionState::new();
        assert!(state.realm_organization_cell_value(realm_id).is_none());
        assert!(state.realm_create_log(realm_id).is_none());
        assert!(!state.realm_is_destroyed(realm_id));
    }

    #[test]
    fn knock_state_visible_in_members_in_state_query() {
        let mut state = ProjectionState::new();
        let hlc = ServerHlc::new("test");
        state.apply(
            &make_operation(
                crate::kinds::CK_MEMBER_STATE,
                "ck:realm:01904100-0000-7000-8000-cfc039892036",
                serde_json::json!({"actor_id": "did:web:carol", "membership": "knock"}),
            ),
            &hlc,
        );
        let knockers =
            state.members_in_state("ck:realm:01904100-0000-7000-8000-cfc039892036", "knock");
        assert_eq!(knockers.len(), 1);
        assert_eq!(knockers[0].member, "did:web:carol");
        assert_eq!(
            state.member_fsm_state("did:web:carol").as_deref(),
            Some("knock")
        );
    }

    #[test]
    fn read_receipt_policy_cell_value_helper_extracts_canonical_value() {
        use cokret_sdk::lattice::CellState;
        let mut state = ProjectionState::new();
        let cell_id = cokret_sdk::CellRef::new(
            "ck:cell:ck.component.realm.read_receipt_policy.v1:ck:realm:01904100-0000-7000-8000-cfc039892036".to_owned(),
        )
        .unwrap();
        state.cells.insert(
            cell_id,
            CellState::Value(serde_json::json!({
                "disclosure": "required",
                "visibility": "members",
                "scope_overrides_allowed": false,
            })),
        );
        let value = state
            .read_receipt_policy_cell_value("ck:realm:01904100-0000-7000-8000-cfc039892036")
            .expect("policy cell should resolve");
        assert_eq!(
            value.get("disclosure").and_then(Value::as_str),
            Some("required")
        );
        assert_eq!(
            value.get("visibility").and_then(Value::as_str),
            Some("members")
        );
        assert_eq!(
            value
                .get("scope_overrides_allowed")
                .and_then(Value::as_bool),
            Some(false)
        );
    }

    /// End-to-end Space-container lifecycle through the dispatcher: create →
    /// archive (active → archived) → restore (archived → active) →
    /// tombstone (active → tombstoned). Verifies the projection's
    /// `space_containers` map tracks state transitions correctly and the
    /// effects carry the new state.
    #[test]
    fn space_container_lifecycle_round_trip() {
        let mut state = ProjectionState::new();
        let hlc = ServerHlc::new("test");
        let realm_id = "ck:realm:01904100-0000-7000-8000-cfc039892036";
        let container_space_id = "ck:space:01904100-0000-7000-8000-1fb50799ad42";

        // create
        let create_effect = state.apply(
            &make_operation(
                crate::kinds::CK_SPACE_CONTAINER_CREATE,
                realm_id,
                serde_json::json!({
                    "object": {
                        "id": container_space_id,
                        "realm_id": realm_id,
                        "kind": "board",
                        "title": "Roadmap",
                        "created_by": "did:web:alice.example",
                    }
                }),
            ),
            &hlc,
        );
        assert!(matches!(
            create_effect,
            ProjectionEffect::SpaceContainerLifecycle {
                new_state: SpaceContainerLifecycleState::Active,
                ..
            }
        ));
        assert_eq!(
            state.space_containers[container_space_id].state,
            SpaceContainerLifecycleState::Active
        );

        // archive
        let archive_effect = state.apply(
            &make_operation(
                crate::kinds::CK_SPACE_CONTAINER_ARCHIVE,
                realm_id,
                serde_json::json!({ "space_id": container_space_id, "sender": "did:web:alice.example" }),
            ),
            &hlc,
        );
        assert!(matches!(
            archive_effect,
            ProjectionEffect::SpaceContainerLifecycle {
                new_state: SpaceContainerLifecycleState::Archived,
                ..
            }
        ));
        assert_eq!(
            state.space_containers[container_space_id].state,
            SpaceContainerLifecycleState::Archived
        );

        // restore
        let restore_effect = state.apply(
            &make_operation(
                crate::kinds::CK_SPACE_CONTAINER_RESTORE,
                realm_id,
                serde_json::json!({ "space_id": container_space_id, "sender": "did:web:alice.example" }),
            ),
            &hlc,
        );
        assert!(matches!(
            restore_effect,
            ProjectionEffect::SpaceContainerLifecycle {
                new_state: SpaceContainerLifecycleState::Active,
                ..
            }
        ));
        assert_eq!(
            state.space_containers[container_space_id].state,
            SpaceContainerLifecycleState::Active
        );

        // tombstone
        let tombstone_effect = state.apply(
            &make_operation(
                crate::kinds::CK_SPACE_CONTAINER_TOMBSTONE,
                realm_id,
                serde_json::json!({ "space_id": container_space_id, "sender": "did:web:alice.example" }),
            ),
            &hlc,
        );
        assert!(matches!(
            tombstone_effect,
            ProjectionEffect::SpaceContainerLifecycle {
                new_state: SpaceContainerLifecycleState::Tombstoned,
                ..
            }
        ));
        assert_eq!(
            state.space_containers[container_space_id].state,
            SpaceContainerLifecycleState::Tombstoned
        );
    }

    /// Preflight `check_space_container_lifecycle_transition` rejects each illegal
    /// transition with the spec-canonical reason_code per
    /// `cokret-spec/v1/zh/models/common-fields.md §5.1`.
    #[test]
    fn space_container_lifecycle_preflight_rejects_illegal_transitions() {
        let mut state = ProjectionState::new();
        let hlc = ServerHlc::new("test");
        let realm_id = "ck:realm:01904100-0000-7000-8000-cfc039892036";
        let container_space_id = "ck:space:01904100-0000-7000-8000-1fb50799ad43";

        // Create the Space container (Active).
        state.apply(
            &make_operation(
                crate::kinds::CK_SPACE_CONTAINER_CREATE,
                realm_id,
                serde_json::json!({
                    "object": {
                        "id": container_space_id,
                        "realm_id": realm_id,
                        "kind": "list",
                        "title": "Todo",
                        "created_by": "did:web:alice.example",
                    }
                }),
            ),
            &hlc,
        );

        // restore on Active → space_not_archived
        let restore_op = make_operation(
            crate::kinds::CK_SPACE_CONTAINER_RESTORE,
            realm_id,
            serde_json::json!({ "space_id": container_space_id }),
        );
        assert_eq!(
            state.check_space_container_lifecycle_transition(&restore_op),
            Err("space_not_archived")
        );

        // Archive then try archive again → space_not_active
        state.apply(
            &make_operation(
                crate::kinds::CK_SPACE_CONTAINER_ARCHIVE,
                realm_id,
                serde_json::json!({ "space_id": container_space_id }),
            ),
            &hlc,
        );
        let archive_op = make_operation(
            crate::kinds::CK_SPACE_CONTAINER_ARCHIVE,
            realm_id,
            serde_json::json!({ "space_id": container_space_id }),
        );
        assert_eq!(
            state.check_space_container_lifecycle_transition(&archive_op),
            Err("space_not_active")
        );

        // Tombstone (legal from Archived).
        state.apply(
            &make_operation(
                crate::kinds::CK_SPACE_CONTAINER_TOMBSTONE,
                realm_id,
                serde_json::json!({ "space_id": container_space_id }),
            ),
            &hlc,
        );
        // Now restore on Tombstoned → still space_not_archived.
        let restore_again = make_operation(
            crate::kinds::CK_SPACE_CONTAINER_RESTORE,
            realm_id,
            serde_json::json!({ "space_id": container_space_id }),
        );
        assert_eq!(
            state.check_space_container_lifecycle_transition(&restore_again),
            Err("space_not_archived")
        );
        // Tombstone on Tombstoned → space_already_terminal.
        let tombstone_again = make_operation(
            crate::kinds::CK_SPACE_CONTAINER_TOMBSTONE,
            realm_id,
            serde_json::json!({ "space_id": container_space_id }),
        );
        assert_eq!(
            state.check_space_container_lifecycle_transition(&tombstone_again),
            Err("space_already_terminal")
        );
        // Update on Tombstoned → space_not_active.
        let update_op = make_operation(
            crate::kinds::CK_SPACE_CONTAINER_UPDATE,
            realm_id,
            serde_json::json!({
                "space_id": container_space_id,
                "patch": { "title": "Renamed while tombstoned" }
            }),
        );
        assert_eq!(
            state.check_space_container_lifecycle_transition(&update_op),
            Err("space_not_active")
        );
    }

    /// Preflight is permissive when the Space container is unknown — causal /
    /// backfill window. Spec: unknown-object tolerance rule in
    /// common-fields §5.1.
    #[test]
    fn space_container_lifecycle_preflight_tolerates_unknown_space_container() {
        let state = ProjectionState::new();
        let archive_unknown = make_operation(
            crate::kinds::CK_SPACE_CONTAINER_ARCHIVE,
            "ck:realm:01904100-0000-7000-8000-cfc039892036",
            serde_json::json!({ "space_id": "ck:space:01904100-0000-7000-8000-cfc039892039" }),
        );
        assert_eq!(
            state.check_space_container_lifecycle_transition(&archive_unknown),
            Ok(())
        );
    }

    #[test]
    fn space_update_and_parent_accept_canonical_payload_fields() {
        let mut state = ProjectionState::new();
        let hlc = ServerHlc::new("test");
        let realm_id = "ck:realm:01904100-0000-7000-8000-cfc039892036";
        let container_space_id = "ck:space:01904100-0000-7000-8000-cfc039892037";
        let parent_space_id = "ck:space:01904100-0000-7000-8000-cfc039892038";

        state.apply(
            &make_operation(
                crate::kinds::CK_SPACE_CONTAINER_CREATE,
                realm_id,
                serde_json::json!({
                    "object": {
                        "id": container_space_id,
                        "realm_id": realm_id,
                        "kind": "list",
                        "title": "Original",
                        "created_by": "did:web:alice.example"
                    }
                }),
            ),
            &hlc,
        );

        let update = make_operation(
            crate::kinds::CK_SPACE_CONTAINER_UPDATE,
            realm_id,
            serde_json::json!({
                "space_id": container_space_id,
                "patch": {
                    "title": "Renamed",
                    "rank": "mV"
                }
            }),
        );
        assert!(matches!(
            state.apply(&update, &hlc),
            ProjectionEffect::SpaceContainerLifecycle { .. }
        ));
        let projection = state.space_containers.get(container_space_id).unwrap();
        assert_eq!(projection.title, "Renamed");
        assert_eq!(projection.rank.as_deref(), Some("mV"));

        let parent = make_operation(
            crate::kinds::CK_SPACE_CONTAINER_PARENT,
            realm_id,
            serde_json::json!({
                "space_id": container_space_id,
                "parent_space_id": parent_space_id,
                "expected_parent_space_id": null
            }),
        );
        assert!(matches!(
            state.apply(&parent, &hlc),
            ProjectionEffect::SpaceContainerLifecycle { .. }
        ));
        assert_eq!(
            state
                .space_containers
                .get(container_space_id)
                .and_then(|projection| projection.parent_ref.as_deref()),
            Some(parent_space_id)
        );

        let detach = make_operation(
            crate::kinds::CK_SPACE_CONTAINER_PARENT,
            realm_id,
            serde_json::json!({
                "space_id": container_space_id,
                "parent_space_id": null,
                "expected_parent_space_id": parent_space_id
            }),
        );
        assert!(matches!(
            state.apply(&detach, &hlc),
            ProjectionEffect::SpaceContainerLifecycle { .. }
        ));
        assert_eq!(
            state
                .space_containers
                .get(container_space_id)
                .and_then(|projection| projection.parent_ref.as_deref()),
            None
        );
    }

    #[test]
    fn space_container_child_order_tracks_rank_updates() {
        let mut state = ProjectionState::new();
        let hlc = ServerHlc::new("test");
        let realm_id = "ck:realm:01904100-0000-7000-8000-cfc039892036";
        let board_id = "ck:space:01904100-0000-7000-8000-0000000000b0";
        let first_id = "ck:space:01904100-0000-7000-8000-0000000000a1";
        let second_id = "ck:space:01904100-0000-7000-8000-0000000000a2";
        let third_id = "ck:space:01904100-0000-7000-8000-0000000000a3";

        state.apply(
            &make_operation(
                crate::kinds::CK_SPACE_CONTAINER_CREATE,
                realm_id,
                serde_json::json!({
                    "object": {
                        "id": board_id,
                        "realm_id": realm_id,
                        "kind": "board",
                        "title": "Sprint",
                        "created_by": "did:web:alice.example"
                    }
                }),
            ),
            &hlc,
        );
        for (space_id, title, rank) in [
            (first_id, "First", "r001"),
            (second_id, "Second", "r002"),
            (third_id, "Third", "r003"),
        ] {
            state.apply(
                &make_operation(
                    crate::kinds::CK_SPACE_CONTAINER_CREATE,
                    realm_id,
                    serde_json::json!({
                        "object": {
                            "id": space_id,
                            "realm_id": realm_id,
                            "kind": "list",
                            "title": title,
                            "parent_ref": board_id,
                            "rank": rank,
                            "created_by": "did:web:alice.example"
                        }
                    }),
                ),
                &hlc,
            );
        }

        state.apply(
            &make_operation(
                crate::kinds::CK_SPACE_CONTAINER_UPDATE,
                realm_id,
                serde_json::json!({
                    "space_id": third_id,
                    "patch": { "rank": "r000" }
                }),
            ),
            &hlc,
        );

        let value = state.child_order_cell_value(board_id);
        let titles = value["children"]
            .as_array()
            .expect("children array")
            .iter()
            .map(|entry| entry["title"].as_str().expect("title"))
            .collect::<Vec<_>>();
        assert_eq!(titles, ["Third", "First", "Second"]);
        assert_eq!(
            value["order"].as_array().expect("order array")[0].as_str(),
            Some(third_id)
        );
    }

    #[test]
    fn list_archive_cascades_card_and_restore_preserves_rank() {
        let mut state = ProjectionState::new();
        let hlc = ServerHlc::new("test");
        let realm_id = "ck:realm:01904100-0000-7000-8000-cfc039892036";
        let board_id = "ck:space:01904100-0000-7000-8000-0000000000b0";
        let list_id = "ck:space:01904100-0000-7000-8000-0000000000a1";
        let flow_id = "ck:flow:01904100-0000-7000-8000-0000000000f1";

        state.apply(
            &make_operation(
                crate::kinds::CK_SPACE_CONTAINER_CREATE,
                realm_id,
                serde_json::json!({
                    "object": {
                        "id": board_id,
                        "realm_id": realm_id,
                        "kind": "board",
                        "title": "Sprint",
                        "created_by": "did:web:alice.example"
                    }
                }),
            ),
            &hlc,
        );
        state.apply(
            &make_operation(
                crate::kinds::CK_SPACE_CONTAINER_CREATE,
                realm_id,
                serde_json::json!({
                    "object": {
                        "id": list_id,
                        "realm_id": realm_id,
                        "kind": "list",
                        "title": "Todo",
                        "parent_ref": board_id,
                        "rank": "r001",
                        "created_by": "did:web:alice.example"
                    }
                }),
            ),
            &hlc,
        );
        state.apply(
            &make_operation(
                crate::kinds::CK_FLOW_CREATE,
                realm_id,
                serde_json::json!({
                    "object": {
                        "id": flow_id,
                        "realm_id": realm_id,
                        "metadata": {
                            "title": "Review PR",
                            "fields": {
                                "board_space_id": board_id,
                                "list_space_id": list_id,
                                "rank": "r007"
                            }
                        },
                        "created_by": "did:web:alice.example"
                    }
                }),
            ),
            &hlc,
        );

        state.apply(
            &make_operation(
                crate::kinds::CK_SPACE_CONTAINER_ARCHIVE,
                realm_id,
                serde_json::json!({ "space_id": list_id, "sender": "did:web:alice.example" }),
            ),
            &hlc,
        );
        assert_eq!(state.flows[flow_id].state, ObjectLifecycleState::Archived);
        let relation = state
            .relations
            .values()
            .find(|relation| relation.to_ref.as_deref() == Some(flow_id))
            .expect("flow position relation");
        assert_eq!(
            relation.fields.get("rank").and_then(Value::as_str),
            Some("r007")
        );
        assert_eq!(
            relation
                .fields
                .get("cascade_archived_by")
                .and_then(Value::as_str),
            Some(list_id)
        );

        state.apply(
            &make_operation(
                crate::kinds::CK_SPACE_CONTAINER_RESTORE,
                realm_id,
                serde_json::json!({ "space_id": list_id, "sender": "did:web:alice.example" }),
            ),
            &hlc,
        );
        assert_eq!(state.flows[flow_id].state, ObjectLifecycleState::Active);
        let relation = state
            .relations
            .values()
            .find(|relation| relation.to_ref.as_deref() == Some(flow_id))
            .expect("flow position relation");
        assert_eq!(
            relation.fields.get("rank").and_then(Value::as_str),
            Some("r007")
        );
        assert!(!relation.fields.contains_key("cascade_archived_by"));
    }

    #[test]
    fn board_archive_cascades_child_lists_and_cards() {
        let mut state = ProjectionState::new();
        let hlc = ServerHlc::new("test");
        let realm_id = "ck:realm:01904100-0000-7000-8000-cfc039892036";
        let board_id = "ck:space:01904100-0000-7000-8000-0000000000b0";
        let list_id = "ck:space:01904100-0000-7000-8000-0000000000a1";
        let flow_id = "ck:flow:01904100-0000-7000-8000-0000000000f1";

        state.apply(
            &make_operation(
                crate::kinds::CK_SPACE_CONTAINER_CREATE,
                realm_id,
                serde_json::json!({
                    "object": {
                        "id": board_id,
                        "realm_id": realm_id,
                        "kind": "board",
                        "title": "Sprint",
                        "created_by": "did:web:alice.example"
                    }
                }),
            ),
            &hlc,
        );
        state.apply(
            &make_operation(
                crate::kinds::CK_SPACE_CONTAINER_CREATE,
                realm_id,
                serde_json::json!({
                    "object": {
                        "id": list_id,
                        "realm_id": realm_id,
                        "kind": "list",
                        "title": "Todo",
                        "parent_ref": board_id,
                        "rank": "r001",
                        "created_by": "did:web:alice.example"
                    }
                }),
            ),
            &hlc,
        );
        state.apply(
            &make_operation(
                crate::kinds::CK_FLOW_CREATE,
                realm_id,
                serde_json::json!({
                    "object": {
                        "id": flow_id,
                        "realm_id": realm_id,
                        "metadata": {
                            "title": "Review PR",
                            "fields": {
                                "board_space_id": board_id,
                                "list_space_id": list_id,
                                "rank": "r007"
                            }
                        },
                        "created_by": "did:web:alice.example"
                    }
                }),
            ),
            &hlc,
        );

        state.apply(
            &make_operation(
                crate::kinds::CK_SPACE_CONTAINER_ARCHIVE,
                realm_id,
                serde_json::json!({ "space_id": board_id, "sender": "did:web:alice.example" }),
            ),
            &hlc,
        );
        assert_eq!(
            state.space_containers[board_id].state,
            SpaceContainerLifecycleState::Archived
        );
        assert_eq!(
            state.space_containers[list_id].state,
            SpaceContainerLifecycleState::Archived
        );
        assert_eq!(state.flows[flow_id].state, ObjectLifecycleState::Archived);

        state.apply(
            &make_operation(
                crate::kinds::CK_SPACE_CONTAINER_RESTORE,
                realm_id,
                serde_json::json!({ "space_id": board_id, "sender": "did:web:alice.example" }),
            ),
            &hlc,
        );
        assert_eq!(
            state.space_containers[list_id].state,
            SpaceContainerLifecycleState::Active
        );
        assert_eq!(state.flows[flow_id].state, ObjectLifecycleState::Active);
        let relation = state
            .relations
            .values()
            .find(|relation| relation.to_ref.as_deref() == Some(flow_id))
            .expect("flow position relation");
        assert_eq!(
            relation.fields.get("rank").and_then(Value::as_str),
            Some("r007")
        );
    }

    // ── Flow lifecycle state-machine tests ──

    /// End-to-end Flow lifecycle through the dispatcher: create → archive →
    /// restore (no tombstone for Flow per spec). Verifies projection state
    /// transitions correctly and effects carry the new state.
    #[test]
    fn flow_lifecycle_round_trip() {
        let mut state = ProjectionState::new();
        let hlc = ServerHlc::new("test");
        let realm_id = "ck:realm:01904100-0000-7000-8000-cfc039892036";
        let flow_id = "ck:flow:01904100-0000-7000-8000-1fb50799ad50";

        let create_effect = state.apply(
            &make_operation(
                crate::kinds::CK_FLOW_CREATE,
                realm_id,
                serde_json::json!({
                    "object": {
                        "id": flow_id,
                        "realm_id": realm_id,
                        "title": "Payment refactor",
                        "created_by": "did:web:alice.example",
                    }
                }),
            ),
            &hlc,
        );
        assert!(matches!(
            create_effect,
            ProjectionEffect::FlowLifecycle {
                new_state: ObjectLifecycleState::Active,
                ..
            }
        ));
        assert_eq!(state.flows[flow_id].state, ObjectLifecycleState::Active);

        let archive_effect = state.apply(
            &make_operation(
                crate::kinds::CK_FLOW_ARCHIVE,
                realm_id,
                serde_json::json!({ "flow_id": flow_id, "sender": "did:web:alice.example" }),
            ),
            &hlc,
        );
        assert!(matches!(
            archive_effect,
            ProjectionEffect::FlowLifecycle {
                new_state: ObjectLifecycleState::Archived,
                ..
            }
        ));
        assert_eq!(state.flows[flow_id].state, ObjectLifecycleState::Archived);

        let restore_effect = state.apply(
            &make_operation(
                crate::kinds::CK_FLOW_RESTORE,
                realm_id,
                serde_json::json!({ "flow_id": flow_id, "sender": "did:web:alice.example" }),
            ),
            &hlc,
        );
        assert!(matches!(
            restore_effect,
            ProjectionEffect::FlowLifecycle {
                new_state: ObjectLifecycleState::Active,
                ..
            }
        ));
        assert_eq!(state.flows[flow_id].state, ObjectLifecycleState::Active);
    }

    /// Preflight `check_flow_lifecycle_transition` rejects illegal
    /// transitions with the spec-canonical reason codes per
    /// `common-fields.md §5.1`.
    #[test]
    fn flow_lifecycle_preflight_rejects_illegal_transitions() {
        let mut state = ProjectionState::new();
        let hlc = ServerHlc::new("test");
        let realm_id = "ck:realm:01904100-0000-7000-8000-cfc039892036";
        let flow_id = "ck:flow:01904100-0000-7000-8000-1fb50799ad51";

        state.apply(
            &make_operation(
                crate::kinds::CK_FLOW_CREATE,
                realm_id,
                serde_json::json!({
                    "object": {
                        "id": flow_id,
                        "realm_id": realm_id,
                        "title": "Refactor",
                        "created_by": "did:web:alice.example",
                    }
                }),
            ),
            &hlc,
        );

        // restore on Active → flow_not_archived
        let restore_op = make_operation(
            crate::kinds::CK_FLOW_RESTORE,
            realm_id,
            serde_json::json!({ "flow_id": flow_id }),
        );
        assert_eq!(
            state.check_flow_lifecycle_transition(&restore_op),
            Err("flow_not_archived")
        );

        // Archive then re-archive → flow_not_active
        state.apply(
            &make_operation(
                crate::kinds::CK_FLOW_ARCHIVE,
                realm_id,
                serde_json::json!({ "flow_id": flow_id }),
            ),
            &hlc,
        );
        let archive_again = make_operation(
            crate::kinds::CK_FLOW_ARCHIVE,
            realm_id,
            serde_json::json!({ "flow_id": flow_id }),
        );
        assert_eq!(
            state.check_flow_lifecycle_transition(&archive_again),
            Err("flow_not_active")
        );

        // Update on Archived → flow_not_active
        let update_op = make_operation(
            crate::kinds::CK_FLOW_UPDATE,
            realm_id,
            serde_json::json!({
                "flow_id": flow_id,
                "patch": { "title": "Edit while archived" }
            }),
        );
        assert_eq!(
            state.check_flow_lifecycle_transition(&update_op),
            Err("flow_not_active")
        );
    }

    #[test]
    fn flow_lifecycle_preflight_tolerates_unknown_flow() {
        let state = ProjectionState::new();
        let archive_unknown = make_operation(
            crate::kinds::CK_FLOW_ARCHIVE,
            "ck:realm:01904100-0000-7000-8000-cfc039892036",
            serde_json::json!({ "flow_id": "ck:flow:nope-not-here" }),
        );
        assert_eq!(
            state.check_flow_lifecycle_transition(&archive_unknown),
            Ok(())
        );
    }

    // ── Morph lifecycle state-machine tests ──

    #[test]
    fn morph_lifecycle_round_trip() {
        let mut state = ProjectionState::new();
        let hlc = ServerHlc::new("test");
        let realm_id = "ck:realm:01904100-0000-7000-8000-cfc039892036";
        let morph_id = "ck:morph:01904100-0000-7000-8000-1fb50799ad60";

        let create_effect = state.apply(
            &make_operation(
                crate::kinds::CK_MORPH_CREATE,
                realm_id,
                serde_json::json!({
                    "object": {
                        "id": morph_id,
                        "realm_id": realm_id,
                        "morph_type": "task",
                        "metadata": { "title": "Backfill" },
                        "created_by": "did:web:alice.example",
                    }
                }),
            ),
            &hlc,
        );
        assert!(matches!(
            create_effect,
            ProjectionEffect::MorphLifecycle {
                new_state: ObjectLifecycleState::Active,
                ..
            }
        ));
        assert_eq!(state.morphs[morph_id].state, ObjectLifecycleState::Active);

        state.apply(
            &make_operation(
                crate::kinds::CK_MORPH_ARCHIVE,
                realm_id,
                serde_json::json!({ "morph_id": morph_id }),
            ),
            &hlc,
        );
        assert_eq!(state.morphs[morph_id].state, ObjectLifecycleState::Archived);

        state.apply(
            &make_operation(
                crate::kinds::CK_MORPH_RESTORE,
                realm_id,
                serde_json::json!({ "morph_id": morph_id }),
            ),
            &hlc,
        );
        assert_eq!(state.morphs[morph_id].state, ObjectLifecycleState::Active);
    }

    #[test]
    fn morph_lifecycle_preflight_rejects_illegal_transitions() {
        let mut state = ProjectionState::new();
        let hlc = ServerHlc::new("test");
        let realm_id = "ck:realm:01904100-0000-7000-8000-cfc039892036";
        let morph_id = "ck:morph:01904100-0000-7000-8000-1fb50799ad61";

        state.apply(
            &make_operation(
                crate::kinds::CK_MORPH_CREATE,
                realm_id,
                serde_json::json!({
                    "object": {
                        "id": morph_id,
                        "realm_id": realm_id,
                        "morph_type": "task",
                        "metadata": { "title": "Backfill" },
                        "created_by": "did:web:alice.example",
                    }
                }),
            ),
            &hlc,
        );

        // restore on Active → morph_not_archived
        let restore_op = make_operation(
            crate::kinds::CK_MORPH_RESTORE,
            realm_id,
            serde_json::json!({ "morph_id": morph_id }),
        );
        assert_eq!(
            state.check_morph_lifecycle_transition(&restore_op),
            Err("morph_not_archived")
        );

        state.apply(
            &make_operation(
                crate::kinds::CK_MORPH_ARCHIVE,
                realm_id,
                serde_json::json!({ "morph_id": morph_id }),
            ),
            &hlc,
        );
        let archive_again = make_operation(
            crate::kinds::CK_MORPH_ARCHIVE,
            realm_id,
            serde_json::json!({ "morph_id": morph_id }),
        );
        assert_eq!(
            state.check_morph_lifecycle_transition(&archive_again),
            Err("morph_not_active")
        );

        // Update on Archived → morph_not_active
        let update_op = make_operation(
            crate::kinds::CK_MORPH_UPDATE,
            realm_id,
            serde_json::json!({
                "morph_id": morph_id,
                "patch": { "metadata.title": "Edit blocked" }
            }),
        );
        assert_eq!(
            state.check_morph_lifecycle_transition(&update_op),
            Err("morph_not_active")
        );
    }

    #[test]
    fn morph_lifecycle_preflight_tolerates_unknown_morph() {
        let state = ProjectionState::new();
        let archive_unknown = make_operation(
            crate::kinds::CK_MORPH_ARCHIVE,
            "ck:realm:01904100-0000-7000-8000-cfc039892036",
            serde_json::json!({ "morph_id": "ck:morph:nope-not-here" }),
        );
        assert_eq!(
            state.check_morph_lifecycle_transition(&archive_unknown),
            Ok(())
        );
    }

    // ── Flow position events (move / reorder) ──

    /// `ck.flow.move` / `ck.flow.reorder` touch the Flow projection's
    /// `updated_at` / `updated_by` but do NOT change state. Cell-write
    /// happens on the Move/Anchor pipeline (out of scope here).
    #[test]
    fn flow_position_events_touch_projection_without_changing_state() {
        let mut state = ProjectionState::new();
        let hlc = ServerHlc::new("test");
        let realm_id = "ck:realm:01904100-0000-7000-8000-cfc039892036";
        let flow_id = "ck:flow:01904100-0000-7000-8000-2fb50799ad50";
        let board_space_id = "ck:space:01904100-0000-7000-8000-c10dc0000001";

        state.apply(
            &make_operation(
                crate::kinds::CK_FLOW_CREATE,
                realm_id,
                serde_json::json!({
                    "object": {
                        "id": flow_id,
                        "realm_id": realm_id,
                        "title": "Launch",
                        "created_by": "did:web:alice.example",
                    }
                }),
            ),
            &hlc,
        );
        let created_state = state.flows[flow_id].state;
        let created_updated_at = state.flows[flow_id].updated_at;
        assert_eq!(created_state, ObjectLifecycleState::Active);
        assert!(
            created_updated_at.is_none(),
            "create does not set updated_at"
        );

        // ck.flow.move — state unchanged, updated_at advances.
        let move_effect = state.apply(
            &make_operation(
                crate::kinds::CK_FLOW_MOVE,
                realm_id,
                serde_json::json!({
                    "flow_id": flow_id,
                    "board_space_id": board_space_id,
                    "target_space_id": "ck:space:01904100-0000-7000-8000-c10dc0000002",
                    "rank": "a1",
                    "sender": "did:web:alice.example",
                }),
            ),
            &hlc,
        );
        assert!(matches!(
            move_effect,
            ProjectionEffect::FlowLifecycle {
                new_state: ObjectLifecycleState::Active,
                ..
            }
        ));
        assert_eq!(state.flows[flow_id].state, ObjectLifecycleState::Active);
        assert!(
            state.flows[flow_id].updated_at.is_some(),
            "move bumps updated_at"
        );
        assert_eq!(
            state.flows[flow_id].updated_by.as_deref(),
            Some("did:web:alice.example")
        );

        // ck.flow.reorder — same family, same effect.
        let reorder_effect = state.apply(
            &make_operation(
                crate::kinds::CK_FLOW_REORDER,
                realm_id,
                serde_json::json!({
                    "flow_id": flow_id,
                    "board_space_id": board_space_id,
                    "space_id": "ck:space:01904100-0000-7000-8000-c10dc0000002",
                    "rank": "a2",
                    "sender": "did:web:alice.example",
                }),
            ),
            &hlc,
        );
        assert!(matches!(
            reorder_effect,
            ProjectionEffect::FlowLifecycle {
                new_state: ObjectLifecycleState::Active,
                ..
            }
        ));
        assert_eq!(state.flows[flow_id].state, ObjectLifecycleState::Active);
    }

    /// Unknown Flow tolerated by the position-touch helper, same convention
    /// as the lifecycle helpers (causal / backfill ordering).
    #[test]
    fn flow_position_events_tolerate_unknown_flow() {
        let mut state = ProjectionState::new();
        let hlc = ServerHlc::new("test");
        let effect = state.apply(
            &make_operation(
                crate::kinds::CK_FLOW_MOVE,
                "ck:realm:01904100-0000-7000-8000-cfc039892036",
                serde_json::json!({
                    "flow_id": "ck:flow:nope-not-here",
                    "board_space_id": "ck:space:01904100-0000-7000-8000-c10dc0000001",
                    "target_space_id": "ck:space:01904100-0000-7000-8000-c10dc0000002",
                    "rank": "a1",
                }),
            ),
            &hlc,
        );
        assert!(matches!(effect, ProjectionEffect::Ignored));
    }

    // ── ck.redaction -> Flow / Morph terminal-state push ──

    /// `ck.redaction` carrying `object_ref: ck:flow:...` flips the
    /// FlowProjection state to Redacted (terminal) per spec
    /// common-fields.md §5.1.
    #[test]
    fn redaction_with_flow_object_ref_flips_to_redacted() {
        let mut state = ProjectionState::new();
        let hlc = ServerHlc::new("test");
        let realm_id = "ck:realm:01904100-0000-7000-8000-cfc039892036";
        let flow_id = "ck:flow:01904100-0000-7000-8000-3fb50799ad50";

        state.apply(
            &make_operation(
                crate::kinds::CK_FLOW_CREATE,
                realm_id,
                serde_json::json!({
                    "object": {
                        "id": flow_id,
                        "realm_id": realm_id,
                        "title": "Sensitive flow",
                        "created_by": "did:web:alice.example",
                    }
                }),
            ),
            &hlc,
        );
        assert_eq!(state.flows[flow_id].state, ObjectLifecycleState::Active);

        let effect = state.apply(
            &make_operation(
                crate::kinds::CK_REDACTION,
                realm_id,
                serde_json::json!({
                    "target_event_id": "ck:event:01904100-0000-7000-8000-1d10dc000001",
                    "object_ref": flow_id,
                    "by": "did:web:alice.example",
                    "reason": "policy violation",
                }),
            ),
            &hlc,
        );
        assert!(matches!(
            effect,
            ProjectionEffect::FlowLifecycle {
                new_state: ObjectLifecycleState::Redacted,
                ..
            }
        ));
        assert_eq!(state.flows[flow_id].state, ObjectLifecycleState::Redacted);
        assert!(state.flows[flow_id].state.is_terminal());
    }

    /// Same for Morph via `object_ref: ck:morph:...`.
    #[test]
    fn redaction_with_morph_object_ref_flips_to_redacted() {
        let mut state = ProjectionState::new();
        let hlc = ServerHlc::new("test");
        let realm_id = "ck:realm:01904100-0000-7000-8000-cfc039892036";
        let morph_id = "ck:morph:01904100-0000-7000-8000-3fb50799ad60";

        state.apply(
            &make_operation(
                crate::kinds::CK_MORPH_CREATE,
                realm_id,
                serde_json::json!({
                    "object": {
                        "id": morph_id,
                        "realm_id": realm_id,
                        "morph_type": "task",
                        "metadata": { "title": "Sensitive task" },
                        "created_by": "did:web:alice.example",
                    }
                }),
            ),
            &hlc,
        );
        let effect = state.apply(
            &make_operation(
                crate::kinds::CK_REDACTION,
                realm_id,
                serde_json::json!({
                    "target_event_id": "ck:event:01904100-0000-7000-8000-1d10dc000002",
                    "object_ref": morph_id,
                    "sender": "did:web:alice.example",
                }),
            ),
            &hlc,
        );
        assert!(matches!(
            effect,
            ProjectionEffect::MorphLifecycle {
                new_state: ObjectLifecycleState::Redacted,
                ..
            }
        ));
        assert_eq!(state.morphs[morph_id].state, ObjectLifecycleState::Redacted);
    }

    /// Preflight rejects `ck.redaction` against an already-terminal
    /// Flow with `flow_already_terminal`. Mirror for Morph also covered.
    #[test]
    fn redaction_preflight_rejects_against_already_terminal() {
        let mut state = ProjectionState::new();
        let hlc = ServerHlc::new("test");
        let realm_id = "ck:realm:01904100-0000-7000-8000-cfc039892036";
        let flow_id = "ck:flow:01904100-0000-7000-8000-3fb50799ad51";
        let morph_id = "ck:morph:01904100-0000-7000-8000-3fb50799ad61";

        // Materialise + redact a Flow once (legal first redaction).
        state.apply(
            &make_operation(
                crate::kinds::CK_FLOW_CREATE,
                realm_id,
                serde_json::json!({
                    "object": {
                        "id": flow_id,
                        "realm_id": realm_id,
                        "title": "Flow",
                        "created_by": "did:web:alice.example",
                    }
                }),
            ),
            &hlc,
        );
        state.apply(
            &make_operation(
                crate::kinds::CK_REDACTION,
                realm_id,
                serde_json::json!({
                    "target_event_id": "ck:event:01904100-0000-7000-8000-1d10dc000003",
                    "object_ref": flow_id,
                }),
            ),
            &hlc,
        );
        assert_eq!(state.flows[flow_id].state, ObjectLifecycleState::Redacted);

        // Second redaction against the now-Redacted Flow → preflight rejects.
        let second_redact = make_operation(
            crate::kinds::CK_REDACTION,
            realm_id,
            serde_json::json!({
                "target_event_id": "ck:event:01904100-0000-7000-8000-1d10dc000004",
                "object_ref": flow_id,
            }),
        );
        assert_eq!(
            state.check_redaction_target_transition(&second_redact),
            Err("flow_already_terminal")
        );

        // Same path for Morph.
        state.apply(
            &make_operation(
                crate::kinds::CK_MORPH_CREATE,
                realm_id,
                serde_json::json!({
                    "object": {
                        "id": morph_id,
                        "realm_id": realm_id,
                        "morph_type": "task",
                        "metadata": { "title": "Task" },
                        "created_by": "did:web:alice.example",
                    }
                }),
            ),
            &hlc,
        );
        state.apply(
            &make_operation(
                crate::kinds::CK_REDACTION,
                realm_id,
                serde_json::json!({
                    "target_event_id": "ck:event:01904100-0000-7000-8000-1d10dc000005",
                    "object_ref": morph_id,
                }),
            ),
            &hlc,
        );
        let second_morph_redact = make_operation(
            crate::kinds::CK_REDACTION,
            realm_id,
            serde_json::json!({
                "target_event_id": "ck:event:01904100-0000-7000-8000-1d10dc000006",
                "object_ref": morph_id,
            }),
        );
        assert_eq!(
            state.check_redaction_target_transition(&second_morph_redact),
            Err("morph_already_terminal")
        );
    }

    // ── Flow tracks update ──

    /// `ck.flow.tracks.update` touches Flow.updated_at but never flips
    /// lifecycle state. Parent Flow must be Active or the touch is
    /// rejected with `flow_not_active` (defence-in-depth in the reducer,
    /// mirroring the admission preflight).
    #[test]
    fn flow_tracks_update_touches_active_flow_only() {
        let mut state = ProjectionState::new();
        let hlc = ServerHlc::new("test");
        let realm_id = "ck:realm:01904100-0000-7000-8000-cfc039892036";
        let flow_id = "ck:flow:01904100-0000-7000-8000-4fb50799ad50";

        state.apply(
            &make_operation(
                crate::kinds::CK_FLOW_CREATE,
                realm_id,
                serde_json::json!({
                    "object": {
                        "id": flow_id,
                        "realm_id": realm_id,
                        "title": "Launch",
                        "created_by": "did:web:alice.example",
                    }
                }),
            ),
            &hlc,
        );

        let effect = state.apply(
            &make_operation(
                crate::kinds::CK_FLOW_TRACKS_UPDATE,
                realm_id,
                serde_json::json!({
                    "flow_id": flow_id,
                    "patch": {
                        "tracks": {
                            "synthesis": {"profile": "synthesis"}
                        }
                    },
                    "sender": "did:web:alice.example",
                }),
            ),
            &hlc,
        );
        assert!(matches!(
            effect,
            ProjectionEffect::FlowLifecycle {
                new_state: ObjectLifecycleState::Active,
                ..
            }
        ));
        assert_eq!(state.flows[flow_id].state, ObjectLifecycleState::Active);
        assert!(state.flows[flow_id].updated_at.is_some());
    }

    /// Preflight returns `flow_not_active` when parent Flow is archived
    /// (or any non-Active state). Reducer-level enforcement is also
    /// present as defence-in-depth — both verified here.
    #[test]
    fn flow_tracks_preflight_rejects_when_flow_archived() {
        let mut state = ProjectionState::new();
        let hlc = ServerHlc::new("test");
        let realm_id = "ck:realm:01904100-0000-7000-8000-cfc039892036";
        let flow_id = "ck:flow:01904100-0000-7000-8000-4fb50799ad51";

        state.apply(
            &make_operation(
                crate::kinds::CK_FLOW_CREATE,
                realm_id,
                serde_json::json!({
                    "object": {
                        "id": flow_id,
                        "realm_id": realm_id,
                        "title": "Refactor",
                        "created_by": "did:web:alice.example",
                    }
                }),
            ),
            &hlc,
        );
        state.apply(
            &make_operation(
                crate::kinds::CK_FLOW_ARCHIVE,
                realm_id,
                serde_json::json!({ "flow_id": flow_id }),
            ),
            &hlc,
        );
        assert_eq!(state.flows[flow_id].state, ObjectLifecycleState::Archived);

        let tracks_op = make_operation(
            crate::kinds::CK_FLOW_TRACKS_UPDATE,
            realm_id,
            serde_json::json!({
                "flow_id": flow_id,
                "patch": {"tracks": {"synthesis": {"profile": "synthesis"}}}
            }),
        );
        assert_eq!(
            state.check_flow_tracks_transition(&tracks_op),
            Err("flow_not_active")
        );

        // Reducer-level defence: also rejects directly.
        let effect = state.apply(&tracks_op, &hlc);
        assert!(matches!(
            effect,
            ProjectionEffect::Rejected { ref reason } if reason == "flow_not_active"
        ));
    }

    /// Unknown Flow tolerated at the preflight (causal / backfill).
    #[test]
    fn flow_tracks_preflight_tolerates_unknown_flow() {
        let state = ProjectionState::new();
        let tracks_op = make_operation(
            crate::kinds::CK_FLOW_TRACKS_UPDATE,
            "ck:realm:01904100-0000-7000-8000-cfc039892036",
            serde_json::json!({
                "flow_id": "ck:flow:nope-not-here",
                "patch": {"tracks": {"synthesis": {"profile": "synthesis"}}}
            }),
        );
        assert_eq!(state.check_flow_tracks_transition(&tracks_op), Ok(()));
    }

    /// Preflight tolerates redactions against unknown objects (causal /
    /// backfill window) and against missing `object_ref` (message
    /// redaction path).
    #[test]
    fn redaction_preflight_tolerates_unknown_object_or_message_path() {
        let state = ProjectionState::new();
        let realm_id = "ck:realm:01904100-0000-7000-8000-cfc039892036";
        // Unknown object_ref.
        let unknown = make_operation(
            crate::kinds::CK_REDACTION,
            realm_id,
            serde_json::json!({
                "target_event_id": "ck:event:01904100-0000-7000-8000-1d10dc000007",
                "object_ref": "ck:flow:nope-not-here",
            }),
        );
        assert_eq!(state.check_redaction_target_transition(&unknown), Ok(()));
        // Missing object_ref (message redaction path).
        let message_redact = make_operation(
            crate::kinds::CK_REDACTION,
            realm_id,
            serde_json::json!({
                "target_event_id": "ck:event:01904100-0000-7000-8000-1d10dc000008",
            }),
        );
        assert_eq!(
            state.check_redaction_target_transition(&message_redact),
            Ok(())
        );
    }
}
