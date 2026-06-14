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
//! The Move/Seal receive pipeline (`POST /_soland/peer/moves` /
//! `POST /_soland/peer/seals`) routes through [`registry::LatticeKind`] /
//! [`registry::LatticeRegistry`]. Concrete impls live in
//! [`lattice_kinds`]; [`lattice_kinds::build_sdk_cell_registry`] feeds
//! the SDK's `verify_move` / `apply_seal` pipeline. This is the
//! protocol-canonical path; [`ProjectionState`]'s structured fields
//! (`messages`, `reactions`, `read_cursors`, etc.) are an in-memory
//! convenience cache populated from the durable Event-Envelope ingestion
//! path that pre-dates the Move/Seal model. As Seal projection lands,
//! the structured fields migrate to a single `cells` map.

// SOL-07-005: flow/morph/circle/applet/agent `apply_*` reducers (additional
// `impl ProjectionState` blocks) split out of this file.
mod apply_capability;
mod apply_messages;
mod apply_moderation;
mod apply_objects;
mod apply_realm_lifecycle;
mod apply_realm_policy;
mod apply_relations;
mod apply_space_container;
pub mod lattice_kinds;
pub mod mls;
pub mod realm_links;
// G3.S2: policy server cell reducer
pub mod realm_policy_server;
pub mod registry;

use std::collections::{BTreeMap, BTreeSet};

use cokret_sdk::lattice::CellState;
use cokret_sdk::state_res::{CellRegistry, CellStore, StoreError};
use cokret_sdk::{AgentLifecycleState, CellRef, Operation, RealmId};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::hlc::ServerHlc;
use crate::wire::{ReadCursorPositionWire, ReadScopeWire};

pub const CHILD_ORDER_CELL_FAMILY: &str = "ck.component.child_order.v1";
const REALM_ENCRYPTION_PROFILE_CREATE_LOCKED: &str = "realm_encryption_profile_create_locked";
const CIRCLE_ENCRYPTION_PROFILE_CREATE_LOCKED: &str = "circle_encryption_profile_create_locked";
const CIRCLE_ENCRYPTION_BELOW_REALM_FLOOR: &str = "circle_encryption_below_realm_floor";
/// CKP-0007 §8 — pulling *another* actor into a Circle (none/left → active by
/// an actor other than the target) requires the requester to hold
/// `ck.circle.member.manage` (narrowed by `allowed_circle_ids`) on this Circle.
/// The HTTP surface runs the authoritative `SolandAuthzEngine::check` and stamps a
/// verdict into the operation payload; the reducer fails closed when that
/// verdict is absent or false, so an unauthorised one-way add is rejected even
/// if it bypasses the HTTP gate.
const CIRCLE_MEMBER_MANAGE_CAPABILITY_REQUIRED: &str = "circle_member_manage_capability_required";
/// CKP-0007 §8 — a self-service join (none/left → active *by the target actor*)
/// is only permitted on an `open` Circle. Self-joining a non-`open` Circle must
/// go through an invite/manage path.
const CIRCLE_JOIN_NOT_OPEN: &str = "circle_join_not_open";
/// One-way ratchet: effective `content_encryption_floor` MUST be monotonically
/// non-decreasing. Lowering `e2ee_required` back to `allow_plaintext` is rejected.
const CONTENT_ENCRYPTION_FLOOR_DOWNGRADE: &str = "content_encryption_floor_downgrade";
/// One-way ratchet: effective metadata encryption floor MUST be monotonically
/// non-decreasing (`allow_plaintext < e2ee_required`).
const METADATA_ENCRYPTION_FLOOR_DOWNGRADE: &str = "metadata_encryption_floor_downgrade";

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
/// One per `(actor_id, device_id, keypackage_id)`. The atomic CAS claim
/// flips `claimed_by` from `None` to `Some(group_id)` and sets
/// `consumed_at`; a second claim against the same `id` is rejected.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MlsKeyPackage {
    /// Canonical `ck:mls_keypackage:<uuid>` identifier.
    pub id: String,
    pub actor_id: String,
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
/// `GET /_soland/self/keys/keypackages/welcomes/pending`, which marks each delivered row
/// with `delivered_at = now()` so a re-poll won't redeliver.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MlsWelcome {
    /// Canonical `ck:mls_welcome:<uuid>` identifier.
    pub id: String,
    /// MLS group the Welcome admits the recipient into.
    pub group_id: String,
    pub recipient_actor_id: String,
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

/// Projection key for the pending Welcome queue owned by one device.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct MlsWelcomeQueueKey {
    pub recipient_actor_id: String,
    pub recipient_device_id: String,
}

impl MlsWelcomeQueueKey {
    pub fn new(
        recipient_actor_id: impl Into<String>,
        recipient_device_id: impl Into<String>,
    ) -> Self {
        Self {
            recipient_actor_id: recipient_actor_id.into(),
            recipient_device_id: recipient_device_id.into(),
        }
    }
}

/// Projection key for one MLS epoch row inside one tagged scope.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct MlsCommitEpochKey {
    pub effective_scope_key: String,
    pub mls_group_id: String,
}

impl MlsCommitEpochKey {
    pub fn new(effective_scope_key: impl Into<String>, mls_group_id: impl Into<String>) -> Self {
        Self {
            effective_scope_key: effective_scope_key.into(),
            mls_group_id: mls_group_id.into(),
        }
    }
}

/// G3.S1 — per-group MLS commit-epoch projection.
///
/// Each successful `apply_commit_epoch` bumps `epoch` by exactly +1
/// from `expected_prev_epoch`; out-of-order or stale commits leave the
/// row untouched and the reducer returns `Rejected { reason:
/// "mls_epoch_skew" }`. `covered_seals` is the or-set style
/// accumulator for governance Seal ids / tags attested by accepted
/// commits for this group.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MlsCommitEpoch {
    /// MLS group id (`ck:mls_group:<...>`).
    pub group_id: String,
    /// Tagged Cokret application scope that this MLS group is bound to.
    pub effective_scope: Value,
    /// Monotonic epoch counter. Starts at 0 before the first commit;
    /// each commit bumps by +1.
    pub epoch: u64,
    /// DID of the committer (the `leader` per MLS terminology — the
    /// member whose Commit was accepted).
    pub leader_actor_id: String,
    pub covered_seals: Vec<String>,
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
    /// Optional Circle-local content-encryption floor; `None` inherits the
    /// parent Realm `content_encryption_floor`. effective = max(parent Realm,
    /// Circle). Reducer enforces "MAY only tighten" + one-way ratchet, and
    /// rejects `e2ee_required` on an `encryption_profile=none` Circle.
    pub content_encryption_floor: Option<String>,
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
/// `ck.agent.interop_session.result` envelope's `detail.endpoint_url`
/// so timeline consumers see which endpoint answered the invocation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SolandAgentProjection {
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
pub struct SolandRelationState {
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

impl SolandRelationState {
    pub fn is_active(&self) -> bool {
        self.state == "active"
    }
}

#[derive(Clone, Debug)]
pub struct SolandMembershipState {
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
pub struct SolandRealmState {
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
    /// COT-06-004 — the Realm's default Flow pointer (`ck:flow:<UUIDv7>`).
    /// Set by `ck.realm.set_default_flow` (`apply_realm_set_default_flow`);
    /// the Flow it names MUST already be projected in this Realm. A Flow's
    /// derived `is_default` flag is computed at query time as
    /// `flow_id == realm.default_flow_id` — there is no separate stored
    /// per-Flow column.
    pub default_flow_id: Option<String>,
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
    RelationCreated(SolandRelationState),
    RelationUpdated(SolandRelationState),
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
    /// COT-06-004 — `ck.realm.set_default_flow` projected. The Realm's
    /// `default_flow_id` now points at `flow_id`.
    RealmDefaultFlowSet {
        realm_id: String,
        flow_id: String,
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
    /// Move/Seal pipeline (cas-register at SDK layer); the projection
    /// only records that a watch change happened for `(flow_id, actor_id)`
    /// so downstream listeners (notification dispatcher, watcher list
    /// projection) can react. `level` is `None` when the effect clears
    /// the cell.
    FlowWatchUpdated {
        flow_id: String,
        actor_id: String,
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
    /// `ck.realm.policy_components` projected into the canonical
    /// `ck.component.realm.policy_components.v1` cas-register cell.
    RealmPolicyComponentsProjected {
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
    /// P1 — `ck.capability.grant` event was projected into the
    /// `ck.component.capability.grant.v1` or_set cell (one cell per
    /// `grant_id`). `revived_terminal=false` always; a re-grant of a
    /// `grant_id` whose add was already observed-removed stays revoked
    /// (capabilities.md §12.1 terminal rule).
    CapabilityGrantProjected {
        grant_id: String,
        realm_id: String,
    },
    /// P1 — `ck.capability.revoke` event was projected as an or_set
    /// observed-remove on the target grant cell (capabilities.md §12 /
    /// §12.1). Terminal: the add dot stays removed under re-add.
    CapabilityRevokeProjected {
        grant_id: String,
        realm_id: String,
    },
    /// P1 — `ck.capability.delegate` event was projected into the
    /// `ck.component.capability.delegate.v1` or_set cell plus the parent
    /// grant chain reference (capabilities.md §10 / §12.1).
    CapabilityDelegateProjected {
        grant_id: String,
        realm_id: String,
        parent_grant_id: Option<String>,
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
    /// advance the seal frontier / actor_seq.
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
    /// P2 — `ck.moderation.decision` projected as an or_set add into the
    /// `ck.component.moderation_state.v1` cell keyed by `payload.decision_id`
    /// (content-moderation.md §2.6). Carries an issuer/target_ref/verdict
    /// snapshot so the appeal separation-of-duties check can reverse-resolve
    /// the original decision issuer from the cell.
    ModerationDecisionProjected {
        decision_id: String,
        realm_id: String,
    },
    /// P2 — `ck.moderation.decision.lift` projected as an or_set
    /// observed-remove / supersede on the moderation_state cell keyed by
    /// `payload.decision_ref`. Terminal: a re-add of a lifted decision_id
    /// stays lifted (mirrors capabilities.md §12.1).
    ModerationDecisionLifted {
        decision_id: String,
        realm_id: String,
    },
    /// P2 — `ck.moderation.appeal.{submit,review,decision,close}` projected
    /// onto the `ck.component.moderation.appeal.v1` fsm cell keyed by
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
        consumed_at: i64,
    },
    /// `apply_welcome_enqueue` — a Welcome envelope was appended to the
    /// per-`(recipient_actor_id, recipient_device_id)` queue.
    WelcomeEnqueued {
        welcome_id: String,
        recipient_actor_id: String,
        recipient_device_id: String,
        group_id: String,
    },
    /// `apply_group_genesis` — the group was initialized at epoch 0.
    GroupGenesis {
        group_id: String,
        effective_scope: Value,
        epoch: u64,
        creator_actor_id: String,
        covered_seals: Vec<String>,
    },
    /// `apply_commit_epoch` — the group's epoch was bumped from
    /// `previous_epoch` to `new_epoch` and the attested governance
    /// Seal set was merged into the group's covered_seals accumulator.
    CommitEpochAdvanced {
        group_id: String,
        effective_scope: Value,
        previous_epoch: u64,
        new_epoch: u64,
        leader_actor_id: String,
        covered_seals: Vec<String>,
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

/// Flow / Morph lifecycle transition picker. Mirror of
/// `SpaceContainerLifecycleTransition` but for the two-event family (no tombstone).
#[derive(Clone, Copy, Debug)]
pub(crate) enum ObjectLifecycleTransition {
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
fn apply_realm_set_default_flow_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_realm_set_default_flow(op, op.created_at)
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
// NOT advance the seal frontier / actor_seq. Wire-accepted only;
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

/// Dispatch for `ck.realm.policy_components`; cell family is
/// `ck.component.realm.policy_components.v1`.
fn apply_realm_policy_components_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_realm_policy_components(op)
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

/// CKP-0007 §8 — does the operation payload carry an authoritative
/// `ck.circle.member.manage` verdict for `circle_id`?
///
/// The Circle HTTP surface (`/_soland/self/circles/{id}/members`) runs the
/// real `SolandAuthzEngine::check(sender, "ck.circle.member.manage",
/// "ck:circle:<id>", …)` — which evaluates the grant's `allowed_circle_ids`
/// selector — and stamps the result into the operation payload before handing
/// it to the reducer. The reducer treats this as a fail-closed assertion:
/// absent / false / mismatched-circle ⇒ not authorised.
///
/// Accepted shapes (any one suffices):
///   - `manage_capability_verified: true`
///   - `actor_capability: { action: "ck.circle.member.manage", circle_id: "ck:circle:…", allowed:
///     true }`
fn payload_asserts_circle_manage(payload: &Value, circle_id: &str) -> bool {
    if payload
        .get("manage_capability_verified")
        .and_then(Value::as_bool)
        == Some(true)
    {
        return true;
    }
    let Some(cap) = payload.get("actor_capability").filter(|v| v.is_object()) else {
        return false;
    };
    let action_ok = cap
        .get("action")
        .and_then(Value::as_str)
        .is_some_and(|a| a == "ck.circle.member.manage");
    let allowed_ok = cap.get("allowed").and_then(Value::as_bool) == Some(true);
    // The stamped verdict MUST be scoped to *this* Circle (mirrors the
    // `allowed_circle_ids` selector the engine evaluated). A verdict that omits
    // `circle_id` is accepted (the engine already bound it), but a mismatched
    // id is rejected.
    let circle_ok = cap
        .get("circle_id")
        .and_then(Value::as_str)
        .is_none_or(|c| c == circle_id);
    action_ok && allowed_ok && circle_ok
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

/// P1 — dispatch for `ck.capability.grant`. Projects the grant snapshot as
/// an or_set add into the `ck.component.capability.grant.v1` cell keyed by
/// `payload.grant_id`.
fn apply_capability_grant_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_capability_grant(op, op.created_at)
}

/// P1 — dispatch for `ck.capability.revoke`. Projects an observed-remove on
/// the target grant cell (capabilities.md §12 / §12.1).
fn apply_capability_revoke_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_capability_revoke(op, op.created_at)
}

/// P1 — dispatch for `ck.capability.delegate`. Projects into the delegate
/// cell + parent grant chain.
fn apply_capability_delegate_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_capability_delegate(op, op.created_at)
}

/// P2 — dispatch for `ck.moderation.decision`. Projects the decision snapshot
/// as an or_set add into the `ck.component.moderation_state.v1` cell keyed by
/// `payload.decision_id`.
fn apply_moderation_decision_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_moderation_decision(op, op.created_at)
}

/// P2 — dispatch for `ck.moderation.decision.lift`. Projects an observed-
/// remove / supersede on the moderation_state cell keyed by
/// `payload.decision_ref`.
fn apply_moderation_decision_lift_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    s.apply_moderation_decision_lift(op, op.created_at)
}

/// P2 — dispatch for `ck.moderation.appeal.{submit,review,decision,close}`.
/// Resolves the target FSM state from the canonical kind and projects the
/// transition (with §5.5.2 reducer constraints) onto the appeal cell.
fn apply_moderation_appeal_dispatch(
    s: &mut ProjectionState,
    op: &Operation,
    _hlc: &ServerHlc,
) -> ProjectionEffect {
    let Some(kind) = crate::kinds::canonical_kind_for_operation(op) else {
        return ProjectionEffect::Ignored;
    };
    let Some(target_state) = apply_moderation::appeal_target_state(kind) else {
        return ProjectionEffect::Rejected {
            reason: "moderation_appeal_kind_unknown".to_owned(),
        };
    };
    s.apply_moderation_appeal(op, target_state)
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
// `ck.self.keys.keypackages.upload.create` vs `ck.self.keys.keypackages.command.claim`).

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

fn state_payload_value(payload: &Value) -> &Value {
    payload.get("value").unwrap_or(payload)
}

/// Validate the Join Policy subset that the reducer must enforce before
/// accepting the policy-components cell. The full Join Policy model has
/// several gate families; this validator focuses on reducer-hard invariants:
/// unique gate IDs and non-empty `principal_admission` selectors.
pub fn validate_join_policy_payload(join_policy: &Value) -> Result<(), &'static str> {
    let Some(object) = join_policy.as_object() else {
        return Err("join_policy must be an object");
    };
    let Some(gates) = object.get("gates").and_then(Value::as_array) else {
        return Err("join_policy requires gates");
    };
    if gates.is_empty() {
        return Err("join_policy requires at least one gate");
    }
    let mut seen_gate_ids = BTreeSet::new();
    for gate in gates {
        let Some(gate) = gate.as_object() else {
            return Err("join_policy gates must be objects");
        };
        let Some(gate_id) = gate.get("gate_id").and_then(Value::as_str) else {
            return Err("join_policy gate requires gate_id");
        };
        if gate_id.is_empty() || !seen_gate_ids.insert(gate_id.to_owned()) {
            return Err("join_policy_duplicate_gate_id");
        }
        if gate.get("kind").and_then(Value::as_str) == Some("principal_admission") {
            validate_principal_admission_gate(gate)?;
        }
    }
    Ok(())
}

fn validate_principal_admission_gate(
    gate: &serde_json::Map<String, Value>,
) -> Result<(), &'static str> {
    let has_allowed_methods = validate_did_method_list(gate, "allowed_did_methods")?;
    let has_allowed_dids = validate_did_list(gate, "allowed_principal_dids")?;
    let has_denied_dids = validate_did_list(gate, "denied_principal_dids")?;
    if !(has_allowed_methods || has_allowed_dids || has_denied_dids) {
        return Err("principal_admission_requires_selector");
    }
    Ok(())
}

fn validate_did_method_list(
    object: &serde_json::Map<String, Value>,
    field: &str,
) -> Result<bool, &'static str> {
    let Some(value) = object.get(field) else {
        return Ok(false);
    };
    let Some(values) = value.as_array() else {
        return Err("principal_admission_methods_invalid");
    };
    for value in values {
        let Some(method) = value.as_str() else {
            return Err("principal_admission_methods_invalid");
        };
        if normalize_policy_did_method(method).is_none() {
            return Err("principal_admission_methods_invalid");
        }
    }
    Ok(!values.is_empty())
}

fn validate_did_list(
    object: &serde_json::Map<String, Value>,
    field: &str,
) -> Result<bool, &'static str> {
    let Some(value) = object.get(field) else {
        return Ok(false);
    };
    let Some(values) = value.as_array() else {
        return Err("principal_admission_dids_invalid");
    };
    for value in values {
        let Some(did) = value.as_str() else {
            return Err("principal_admission_dids_invalid");
        };
        if cokret_sdk::Did::new(did.to_owned()).is_err() {
            return Err("principal_admission_dids_invalid");
        }
    }
    Ok(!values.is_empty())
}

fn normalize_policy_did_method(value: &str) -> Option<&str> {
    let method = value.strip_prefix("did:")?;
    (!method.is_empty()
        && method
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit()))
    .then_some(method)
}

fn principal_admission_gate_allows(gate: &serde_json::Map<String, Value>, member: &str) -> bool {
    if !principal_admission_gate_has_selector(gate) {
        return false;
    }
    let Ok(member_did) = cokret_sdk::Did::new(member.to_owned()) else {
        return false;
    };
    if did_list_contains(gate, "denied_principal_dids", member) {
        return false;
    }
    if did_list_non_empty(gate, "allowed_principal_dids")
        && !did_list_contains(gate, "allowed_principal_dids", member)
    {
        return false;
    }
    let method = member_did.method();
    if let Some(methods) = gate.get("allowed_did_methods").and_then(Value::as_array)
        && !methods.is_empty()
        && !methods.iter().any(|value| {
            value
                .as_str()
                .and_then(normalize_policy_did_method)
                .is_some_and(|allowed| allowed == method)
        })
    {
        return false;
    }
    true
}

fn principal_admission_gate_has_selector(gate: &serde_json::Map<String, Value>) -> bool {
    did_list_non_empty(gate, "allowed_principal_dids")
        || did_list_non_empty(gate, "denied_principal_dids")
        || gate
            .get("allowed_did_methods")
            .and_then(Value::as_array)
            .is_some_and(|values| !values.is_empty())
}

fn did_list_non_empty(gate: &serde_json::Map<String, Value>, field: &str) -> bool {
    gate.get(field)
        .and_then(Value::as_array)
        .is_some_and(|values| !values.is_empty())
}

fn did_list_contains(gate: &serde_json::Map<String, Value>, field: &str, did: &str) -> bool {
    gate.get(field)
        .and_then(Value::as_array)
        .is_some_and(|values| values.iter().any(|value| value.as_str() == Some(did)))
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
    // COT-06-004 — Realm default-Flow pointer.
    m.insert(
        CK_REALM_SET_DEFAULT_FLOW,
        apply_realm_set_default_flow_dispatch,
    );
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
    // active kind, `ck.circle.seal_commit`, is reducer-derived (sub-
    // seal on the Circle's profile cadence) and listed in the SDK's
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
    // accept but do NOT advance the seal frontier / actor_seq;
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
        CK_REALM_POLICY_COMPONENTS,
        apply_realm_policy_components_dispatch,
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
    // P1 — capability control-plane projection (grant / revoke / delegate).
    // grant + revoke share the `ck.component.capability.grant.v1` or_set
    // cell; delegate writes `ck.component.capability.delegate.v1` + parent
    // chain. Acceptance fail-closed lives in `apply_capability.rs`.
    m.insert(CK_CAPABILITY_GRANT, apply_capability_grant_dispatch);
    m.insert(CK_CAPABILITY_REVOKE, apply_capability_revoke_dispatch);
    m.insert(CK_CAPABILITY_DELEGATE, apply_capability_delegate_dispatch);
    // P2 — moderation control-plane projection (decision / lift / appeal.*).
    // decision + lift share the `ck.component.moderation_state.v1` or_set
    // cell; the four appeal kinds drive the `ck.component.moderation.appeal.v1`
    // fsm cell. §5.5.2 reducer constraints + acceptance fail-closed live in
    // `apply_moderation.rs`.
    m.insert(CK_MODERATION_DECISION, apply_moderation_decision_dispatch);
    m.insert(
        CK_MODERATION_DECISION_LIFT,
        apply_moderation_decision_lift_dispatch,
    );
    m.insert(
        CK_MODERATION_APPEAL_SUBMIT,
        apply_moderation_appeal_dispatch,
    );
    m.insert(
        CK_MODERATION_APPEAL_REVIEW,
        apply_moderation_appeal_dispatch,
    );
    m.insert(
        CK_MODERATION_APPEAL_DECISION,
        apply_moderation_appeal_dispatch,
    );
    m.insert(CK_MODERATION_APPEAL_CLOSE, apply_moderation_appeal_dispatch);
    // G3.S1: MLS lifecycle. KeyPackage publish/claim (atomic CAS),
    // Welcome to-device persistence, commit monotonic-epoch bump, and
    // governance covered_seals accumulation.
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

/// Extract an encryption-floor field from a `ck.realm.policy_components`
/// value, accepting both the top-level and `/components/`-nested wire forms
/// (mirrors `realm_join_policy_cell_value`).
fn policy_floor_field<'a>(value: &'a Value, field: &str) -> Option<&'a str> {
    value
        .get(field)
        .or_else(|| value.pointer(&format!("/components/{field}")))
        .and_then(Value::as_str)
}

/// Ordinal rank for `content_encryption_floor` (`allow_plaintext < e2ee_required`).
/// `None` / unknown values rank as `allow_plaintext` (0); spec default is
/// `allow_plaintext` (realm-and-space.md §2.3, circle.md §7).
fn content_floor_rank(floor: Option<&str>) -> u8 {
    match floor.map(str::trim) {
        Some("e2ee_required") => 1,
        _ => 0,
    }
}

/// Ordinal rank for the metadata encryption floor
/// (`allow_plaintext < e2ee_required`), symmetric with the content floor.
/// `None` / unknown ranks as `allow_plaintext` (0).
fn metadata_floor_rank(floor: Option<&str>) -> u8 {
    match floor.map(str::trim) {
        Some("e2ee_required") => 1,
        _ => 0,
    }
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
            .or_insert_with(|| SolandRelationState {
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
    /// the Move/Seal pipeline through `LatticeKind` impls in
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
mod tests;
