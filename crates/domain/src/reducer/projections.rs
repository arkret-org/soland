//! Projection record types produced by the reducer.
//!
//! These are the structured side-band caches and value types that
//! [`super::ProjectionState`] holds. They are split out of the `reducer`
//! mod file for navigability; the mod file re-exports them so the
//! `crate::reducer::Xxx` paths stay unchanged.

use std::collections::{BTreeMap, BTreeSet};

use arkret_event_draft::Operation;
use arkret_models_collaboration::objects::profiles::StrandTrackConfig;
use arkret_models_collaboration::objects::read_receipts::ReadCursorPosition as ReadCursorPositionWire;
use arkret_models_collaboration::objects::space::ChildScopePolicy;
use arkret_wire::ReadCursorScope as ReadScopeWire;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct PushRouteSubject {
    pub recipient_service_id: String,
    pub principal_id: String,
    pub device_id: String,
    pub push_route: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CallFsmHead {
    pub basis: String,
    pub operation_id: String,
    pub value: String,
}

#[derive(Clone, Debug)]
pub struct PendingReplayEntry {
    pub target_ref: String,
    pub reason: String,
    pub operation_id: String,
    pub operation: Operation,
    pub queued_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StrandWatchProjection {
    pub strand_id: String,
    pub actor_id: String,
    pub level: Option<String>,
    pub level_public: bool,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

/// Stream-F (Wave 1B) — `ak.audit.erasure_receipt` projection record.
/// Mirrors a subset of the canonical `ak.schema.erasure_receipt.v1`
/// payload (see
/// `arkret-spec/spec/v1/artifacts/schemas/erasure-receipt.schema.json`).
/// We only keep the fields the local audit layer actually consults — the
/// rest of the payload (`proofs`,
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
    /// Affected Realm extracted from `payload.scope.realm_id`. `None` for
    /// purely account-scoped receipts.
    pub scope_realm_id: Option<String>,
    /// Propagation status carried by the canonical receipt payload.
    pub fanout_status: String,
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InviteProjection {
    pub invite_id: String,
    pub realm_id: String,
    pub inviter: String,
    pub invitee: Option<String>,
    pub third_party_id: Option<Value>,
    pub join_rule_snapshot: Value,
    pub state: String,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    pub claim_nonces: BTreeMap<String, String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SolandKeyBackupActiveSeries {
    pub actor_id: String,
    pub backup_kind: String,
    pub active_series_id: String,
    pub series_pointer_version: u64,
    pub previous_series_ids: Vec<String>,
    pub record_digest: String,
    pub frontier_ref:
        arkret_models_collaboration::events_payloads::KeyBackupActiveSeriesFrontierRef,
    pub issued_at: chrono::DateTime<chrono::Utc>,
    pub auth_data: arkret_models_collaboration::events_payloads::KeyBackupActiveSeriesAuthData,
    pub extra: BTreeMap<String, Value>,
    pub event_id: String,
}

/// R3.1 — structured cache row for a single directed Realm link.
/// Mirrors the `ak.component.realm.link.v1` cell value plus envelope-
/// derived timestamps so the query API can render `created_at` /
/// `updated_at` without re-reading the durable Event store.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RealmLinkState {
    pub realm_id: String,
    pub target_realm_id: String,
    /// Canonical link kind string (snake_case, one of the eight values
    /// in `arkret_models_collaboration::governance::realm_governance::RealmLinkKind`).
    pub link_kind: String,
    /// `active` / `rejected` / `tombstoned`.
    pub status: String,
    pub label: Option<String>,
    pub commitment: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

/// G3.S2 — structured cache row for `ak.realm.policy_server`. Mirrors
/// the canonical `ak.component.realm.policy_server.v1` cas-register
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
    /// HTTPS endpoint that accepts `POST /_arkret/self/policy/check`.
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

/// R3.2 — structured cache row for `ak.realm.inheritance_policy`.
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

/// SOL-ORG-02 — structured cache row for one `ak.realm.organization`
/// relationship statement projection. Mirrors the canonical
/// `ak.component.realm.organization.v1` cas-register cell keyed by the
/// composite subject `(organization_id, relationship)`. The reducer keeps
/// the latest statement per `(realm_id, organization_id, relationship)`; an
/// `active` statement marks the relationship live, a `revoked` statement
/// marks it inactive while retaining `statement_id` for audit.
///
/// Field order mirrors the spec `realm_organization_payload` so the
/// persistence row and query DTO stay aligned.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RealmOrganizationStatementState {
    pub realm_id: String,
    pub organization_id: String,
    /// snake_case relationship: `owner` / `governance` / `sponsor` /
    /// `directory_certifier`.
    pub relationship: String,
    pub statement_id: String,
    /// `active` (relationship live) or `revoked` (inactive, retained for
    /// audit).
    pub status: String,
    /// Endorsement scopes covered by the organization's consent
    /// (snake_case `control_scopes[]` items).
    pub control_scopes: Vec<String>,
    pub issued_at: chrono::DateTime<chrono::Utc>,
    pub not_before: Option<chrono::DateTime<chrono::Utc>>,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    pub supersedes_statement_id: Option<String>,
    pub revokes_statement_id: Option<String>,
    /// Digest of the Realm control frontier the organization evaluated.
    pub realm_frontier_digest: Option<String>,
    /// Audit summary of the proof material (never the raw signature bytes).
    pub proof_digest: Option<String>,
    /// `authorization.delegation_ref` when present (delegated issuer roles).
    pub delegation_ref: Option<String>,
    /// `authorization.issuer_role` (snake_case).
    pub issuer_role: String,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

impl RealmOrganizationStatementState {
    /// `true` when this is an `active` statement currently inside its
    /// validity window (`not_before <= now < expires_at`).
    pub fn is_effective_active(&self, now: chrono::DateTime<chrono::Utc>) -> bool {
        if self.status != "active" {
            return false;
        }
        if let Some(nbf) = self.not_before
            && now < nbf
        {
            return false;
        }
        if let Some(exp) = self.expires_at
            && now >= exp
        {
            return false;
        }
        true
    }

    /// `true` when this active statement's `control_scopes` cover `scope`.
    pub fn covers_scope(&self, scope: &str) -> bool {
        self.control_scopes.iter().any(|s| s == scope)
    }
}

/// R3.2 — structured cache row for `ak.capability.derived`.
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
/// One per `(actor_id, device_id, keypackage_id)`. Ordinary packages use
/// an atomic CAS claim that flips `claimed_by` from `None` to `Some(group_id)`
/// and sets its claim window; last-resort packages keep the row published and
/// bind reuse to a single Realm.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MlsKeyPackage {
    /// Canonical `ak:mls_keypackage:<uuid>` identifier.
    pub id: String,
    pub keypackage_ref: String,
    pub keypackage_digest: String,
    pub actor_id: String,
    pub device_id: String,
    pub lifetime: KeyPackageLifetime,
    /// Opaque bytes of the MLS KeyPackage (`mls_key_package` per RFC 9420
    /// §11). Server treats this as a black box; only the recipient device
    /// can decrypt the Welcome it backs.
    pub key_package_bytes: Vec<u8>,
    pub capabilities: Vec<String>,
    pub capabilities_digest: String,
    pub device_signature: serde_json::Value,
    pub last_resort: bool,
    pub last_resort_realm_id: Option<String>,
    /// `None` while the KeyPackage is still claimable; `Some(group_id)`
    /// after a successful CAS claim. The CAS guarantees at-most-one
    /// claim across concurrent Welcomes.
    pub claimed_by: Option<String>,
    /// Claimed device trust binding captured when the KeyPackage was
    /// published. Exactly one of `ssk_generation`,
    /// `device_authorize_event_id`, or `agent_key_authorize_event_id` is
    /// present.
    pub ssk_generation: Option<u64>,
    pub device_authorize_event_id: Option<String>,
    pub agent_key_authorize_event_id: Option<String>,
    /// Unix seconds at which the CAS claim happened (mirrors `claimed_by`).
    pub claimed_at: Option<i64>,
    /// Unix milliseconds for the single-use claim authorization deadline.
    pub claim_expires_at_unix_ms: Option<i64>,
    /// Unix seconds at which the target device consumed the claim.
    pub consumed_at: Option<i64>,
    pub created_at: i64,
}

/// G3.S1 — single Welcome envelope queued for a recipient device.
///
/// The reducer's `apply_welcome_enqueue` appends one row per Welcome fanout
/// target. Delivery uses the standard durable device-message stream; this
/// projection retains the Welcome binding for claim and consume validation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MlsWelcome {
    /// Canonical `ak:mls_welcome:<uuid>` identifier.
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
    /// Epoch established by the Add Commit referenced by this Welcome.
    pub epoch: u64,
    /// Accepted Add Commit Event ref. Sidecar Welcome admission requires it.
    pub commit_ref: Option<String>,
    /// Full governance binding retained for exact Sidecar evidence.
    pub governance_binding: Value,
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

/// Reducer-side index for `ak.mls.proposal{proposal_type="remove"}`.
///
/// The opaque MLS proposal bytes stay client-owned; the reducer only keeps the
/// canonical event ref and the target tuple needed to verify that a later
/// `ak.mls.commit` consuming a pending remove obligation really references a
/// Remove proposal for the revoked / removed leaf.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MlsRemoveProposal {
    pub proposal_ref: String,
    pub group_id: String,
    pub effective_scope: Value,
    pub base_epoch: u64,
    pub target_actor_id: String,
    pub target_device_id: Option<String>,
    pub created_at: i64,
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
    /// MLS group id (`ak:mls_group:<...>`).
    pub group_id: String,
    /// Tagged Arkret application scope that this MLS group is bound to.
    pub effective_scope: Value,
    /// Monotonic epoch counter. Starts at 0 before the first commit;
    /// each commit bumps by +1.
    pub epoch: u64,
    /// DID of the committer (the `leader` per MLS terminology — the
    /// member whose Commit was accepted).
    pub leader_actor_id: String,
    /// Device that authored the accepted epoch-0 genesis.
    pub creator_device_id: String,
    /// Accepted genesis Event/control ref.
    pub genesis_event_ref: String,
    pub covered_seals: Vec<String>,
    pub committed_at: i64,
    /// Full governance binding accepted for the current epoch.
    pub governance_binding: Value,
    /// `governance_binding.policy_root` the genesis bound this MLS group to.
    /// Every later commit's binding MUST carry the same `policy_root`; a
    /// mismatch is rejected with `governance_binding_mismatch`
    /// (encryption-and-audit.md §2.5.1).
    pub policy_root: String,
    /// `commit_digest` of the commit that advanced the group into the current
    /// epoch. A *different* commit that attests the same base epoch
    /// (`accepted_from_epoch`) drives the group's `covered_frontier_cell` to
    /// `⊥` (encryption-and-audit.md §2.5.2). `None` at genesis (no commit yet).
    pub accepted_commit_digest: Option<String>,
    /// Accepted Commit Event/control ref for the current epoch.
    pub accepted_commit_ref: Option<String>,
    /// Base epoch the `accepted_commit_digest` commit attested. Lets the reducer
    /// tell a *concurrent* commit at that same base (⊥ contention) apart from a
    /// plain stale / out-of-order replay (`mls_epoch_skew`). `None` at genesis.
    pub accepted_from_epoch: Option<u64>,
    /// `true` once concurrent commits resolved the frontier to `⊥`. While
    /// contested, sends / decrypts on this epoch fail closed as
    /// `decryption_pending` until a resolving commit advances the epoch.
    pub frontier_contested: bool,
}

/// Reducer-derived MLS remove obligation created when an MLS-backed
/// Realm-default or Circle scope loses an active member. The MLS worker path
/// is responsible for turning this obligation into a remove proposal/commit;
/// `circle_id=None` identifies the Realm-default scope.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MlsRemoveObligation {
    pub realm_id: String,
    pub circle_id: Option<String>,
    pub mls_group_ref: Option<String>,
    pub actor_id: String,
    pub device_id: Option<String>,
    pub membership_frontier: Vec<String>,
    pub trigger_membership: String,
    pub triggered_at: chrono::DateTime<chrono::Utc>,
}

/// Server-side Space-container state cache. Mirrors the
/// `projection_space_containers` table.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpaceContainerProjection {
    pub container_space_id: String,
    pub realm_id: String,
    pub kind: String,
    pub title: String,
    pub fields: BTreeMap<String, Value>,
    pub scope_circle_id: Option<String>,
    pub child_scope_policy: Option<ChildScopePolicy>,
    pub parent_ref: Option<String>,
    pub rank: Option<String>,
    pub state: SpaceContainerLifecycleState,
    pub state_changed_at: Option<chrono::DateTime<chrono::Utc>>,
    pub created_by: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub history_basis_seals: Vec<String>,
    pub updated_by: Option<String>,
    pub updated_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Stream-F (Wave 1B) — `realm_destroyed_orphan` flag set by the
    /// `ak.realm.destroy` cascade when this container's home Realm is
    /// destroyed. Spec `realm-and-space.md` §2.5.1 ¶6: orphaned
    /// containers become read-only locked projections; no
    /// `ak.strand.move` / `ak.space.parent` / `ak.space.update` may
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
    /// strand inside the policy window. Spec `realm-and-space.md`
    /// §2.5.1 ¶6. Defaults to `false`.
    pub parent_ref_locked: bool,
}

pub(crate) fn space_container_id_from_payload(payload: &Value) -> Option<String> {
    payload
        .get("space_id")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
}

pub(crate) fn operation_history_basis_seals(operation: &Operation) -> Vec<String> {
    let mut seals = Vec::new();
    if let Some(seal_ref) = operation
        .payload
        .get("seal_ref")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
    {
        seals.push(seal_ref.to_owned());
    }
    if let Some(seal_basis) = operation.payload.get("seal_basis") {
        if let Some(seal_ref) = seal_basis.as_str().filter(|value| !value.trim().is_empty()) {
            seals.push(seal_ref.to_owned());
        }
        if let Some(leaves) = seal_basis.get("leaves").and_then(Value::as_array) {
            for leaf in leaves {
                if let Some(seal_ref) = leaf.as_str().filter(|value| !value.trim().is_empty()) {
                    seals.push(seal_ref.to_owned());
                }
            }
        }
    }
    seals.sort();
    seals.dedup();
    seals
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

/// Server-side Strand state cache. Mirrors `projection_strands` table.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StrandProjection {
    pub strand_id: String,
    pub realm_id: String,
    /// Active Strand track definitions. Track entries are display/timeline
    /// configuration only; access still derives from `scope_circle_id`.
    pub tracks: BTreeMap<String, StrandTrackConfig>,
    pub title: String,
    pub summary: Option<String>,
    pub fields: BTreeMap<String, Value>,
    pub state: ObjectLifecycleState,
    pub state_changed_at: Option<chrono::DateTime<chrono::Utc>>,
    pub created_by: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub history_basis_seals: Vec<String>,
    pub updated_by: Option<String>,
    pub updated_at: Option<chrono::DateTime<chrono::Utc>>,
    /// AKP-0007 — the Circle this Strand is scoped to, if any (`ak:circle:…`).
    /// A message's effective circle-scope is derived from its Strand's
    /// `scope_circle_id` (spec: `scope_circle_id` is a Strand field, not a
    /// message field); messages never carry their own scope.
    pub scope_circle_id: Option<String>,
}

pub(crate) fn default_strand_tracks() -> BTreeMap<String, StrandTrackConfig> {
    BTreeMap::from([(
        arkret_models_collaboration::objects::profiles::STRAND_TRACK_NAME_SYNTHESIS.to_owned(),
        StrandTrackConfig::synthesis(),
    )])
}

/// AKP-0007 — server-side Circle state cache. Mirrors `projection_circles` +
/// `projection_circle_members` (see migration
/// `20260526010000_add_circles`).
///
/// `members` is the authoritative active-member set; the wire validator and
/// the `ak.circle.member.state` handler use it to enforce the
/// `Circle.members ⊆ Realm.members` invariant
/// (`circle_member_must_be_realm_member`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CircleProjection {
    pub circle_id: String,
    /// Parent Realm id. Create-locked — a Circle never re-binds to another
    /// Realm. Spec `circle.schema.json` §`realm_id`.
    pub realm_id: String,
    /// Optional create-locked Circle semantic profile discriminator.
    pub profile_ref: Option<String>,
    pub title: String,
    pub summary: Option<String>,
    pub display: Value,
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
    /// Active Circle members. Maintained by `ak.circle.member.state`
    /// transitions (`active` -> insert, `removed`/`banned`/`left` ->
    /// remove). Always a strict subset of the parent Realm's active
    /// member set.
    pub members: BTreeSet<String>,
}

/// First-class Agent Sidecar aggregate. The referenced Circle is an internal
/// delivery/MLS binding and is never the Sidecar identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SidecarProjection {
    pub sidecar_id: String,
    pub realm_id: String,
    pub controller_id: String,
    pub backing_circle_id: String,
    pub encryption_profile:
        arkret_models_collaboration::agent_operations::AgentSidecarEncryptionProfile,
    pub state: arkret_models_collaboration::agent_operations::AgentSidecarState,
    pub state_changed_at: Option<chrono::DateTime<chrono::Utc>>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CircleMembershipState {
    pub circle_id: String,
    pub member: String,
    pub state: String,
    pub invited_at: Option<chrono::DateTime<chrono::Utc>>,
    pub joined_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

/// AKP-0007 — Circle lifecycle state. Matches spec `circle.schema.json`
/// `state` enum (active / archived / tombstoned). Distinct from
/// [`ObjectLifecycleState`] (which carries the redacted/deleted forms used
/// by Strand / Morph); Circle has no redaction path because the canonical
/// terminal action is `ak.circle.tombstone`.
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
    /// AKP-0007 - the Circle this Morph is scoped to, if any (`ak:circle:...`).
    /// Morph updates and lifecycle writes must satisfy the same Circle
    /// membership conjunct as creates.
    pub scope_circle_id: Option<String>,
    pub morph_kind: String,
    pub title: Option<String>,
    pub fields: BTreeMap<String, Value>,
    pub schema_refs: Vec<String>,
    pub facets: Vec<String>,
    pub versions: Vec<DocumentVersionProjection>,
    pub state: ObjectLifecycleState,
    pub state_changed_at: Option<chrono::DateTime<chrono::Utc>>,
    pub created_by: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub history_basis_seals: Vec<String>,
    pub updated_by: Option<String>,
    pub updated_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Materialized version row for document-shaped Morphs.
///
/// This is intentionally projection-side state: the canonical source remains
/// the ordered `ak.morph.create` / `ak.morph.update` event stream, while the
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
/// `ak.applet.registration` (creates) and `ak.applet.discovery` (refreshes
/// the manifest). Spec `extensions/applet-integration.md` doesn't pin
/// down a state-machine for applet entries themselves (the bridge state
/// machine is per-session and lives client-side), so this is a simple
/// last-write-wins projection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppletProjection {
    /// `service_id` of the applet — canonical identity per spec.
    pub service_id: String,
    pub namespace: String,
    /// Optional snapshot of the most recent `manifest` (from the latest
    /// `ak.applet.discovery` event). `None` if only registration has
    /// landed.
    pub manifest: Option<Value>,
    /// Optional capability list from the latest `ak.applet.registration`.
    pub capabilities: Option<Value>,
    pub registered_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AgentActionRequestStatus {
    Pending,
    Approved,
    Rejected,
    Cancelled,
}

/// Server-side pending approval queue entry for `ak.agent.action_request`.
///
/// Actor-private action events do not advance reducer input clocks, but the
/// controller still needs a fail-closed projection so lifecycle revocation can
/// cancel outstanding approvals before an agent resumes or re-registers a
/// runtime endpoint.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentActionRequestProjection {
    pub request_id: String,
    pub agent_id: String,
    pub status: AgentActionRequestStatus,
    pub requested_at: chrono::DateTime<chrono::Utc>,
    pub resolved_at: Option<chrono::DateTime<chrono::Utc>>,
    pub resolution_event_id: Option<String>,
    pub cancel_reason: Option<String>,
    pub approval: Option<AgentActionApprovalProjection>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentActionApprovalProjection {
    pub approval_id: String,
    pub proposed_action: String,
    pub target: serde_json::Value,
    pub approved_payload_digest: String,
    pub approval_nonce: String,
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

/// State enum shared by Strand and Morph projections (mirrors SDK
/// `arkret_wire::ObjectState`). Unlike `SpaceContainerLifecycleState` which has
/// a single `Tombstoned` terminal, Strand / Morph use `Redacted` as their terminal
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

    /// Terminal state per spec §5.1: Strand / Morph use `redacted` as their
    /// unrecoverable terminal.
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Redacted)
    }
}

/// Value of the parallel `redaction` cas-register
/// cell on the same subject as the target message cell. Mirrors the spec
/// shape `{redacted_at, by, reason}` and carries the triggering
/// `ak.message.redact` event id so the read path can surface
/// `redaction_ref` on the message tombstone (strand-and-message.md §9).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RedactionCellValue {
    pub redacted_at: chrono::DateTime<chrono::Utc>,
    pub by: String,
    pub reason: Option<String>,
    pub redaction_event_id: Option<String>,
}

impl RedactionCellValue {
    /// Render the cas-register payload as JSON for projection / wire emission.
    pub fn to_json(&self) -> Value {
        let mut obj = serde_json::Map::new();
        obj.insert(
            "redacted_at".to_owned(),
            Value::String(arkret_canonical::format_timestamp_canonical(
                self.redacted_at,
            )),
        );
        obj.insert("by".to_owned(), Value::String(self.by.clone()));
        if let Some(reason) = &self.reason {
            obj.insert("reason".to_owned(), Value::String(reason.clone()));
        }
        if let Some(redaction_event_id) = &self.redaction_event_id {
            obj.insert(
                "redaction_ref".to_owned(),
                Value::String(redaction_event_id.clone()),
            );
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
    pub message_id: String,
    pub realm_id: String,
    pub sender: String,
    pub thread_id: String,
    pub content: Value,
    pub expiry: Option<Value>,
    pub encrypted: bool,
    pub operation_id: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub history_basis_seals: Vec<String>,
    /// If this is a revision, points to the original event_id.
    pub revision_of: Option<String>,
    /// If redacted, the tombstone timestamp.
    pub redacted_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MessageExpiryProjectionState {
    Live,
    Expired,
    UnsupportedTrigger,
    InvalidMetadata,
}

impl MessageExpiryProjectionState {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Live => "active",
            Self::Expired => "expired",
            Self::UnsupportedTrigger => "unsupported_trigger",
            Self::InvalidMetadata => "invalid_metadata",
        }
    }

    pub fn is_stub(&self) -> bool {
        !matches!(self, Self::Live)
    }

    pub fn reason_code(&self) -> Option<&'static str> {
        match self {
            Self::Live => None,
            Self::Expired => Some("ttl_expired"),
            Self::UnsupportedTrigger => Some("read_trigger_unsupported"),
            Self::InvalidMetadata => Some("invalid_expiry_metadata"),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MessageExpiryProjection {
    pub state: MessageExpiryProjectionState,
    pub trigger: String,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    pub anchor_hlc: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MessageExpiryAnchor {
    pub trigger: String,
    pub anchor_hlc: String,
    pub anchored_at: chrono::DateTime<chrono::Utc>,
}

impl MessageExpiryProjection {
    pub fn is_stub(&self) -> bool {
        self.state.is_stub()
    }

    pub fn state_str(&self) -> &'static str {
        self.state.as_str()
    }

    pub fn reason_code(&self) -> Option<&'static str> {
        self.state.reason_code()
    }
}

pub fn message_expiry_projection_from_value(
    expiry: Option<&Value>,
    created_at: chrono::DateTime<chrono::Utc>,
    now: chrono::DateTime<chrono::Utc>,
) -> Option<MessageExpiryProjection> {
    message_expiry_projection_from_value_with_anchor(expiry, created_at, now, None)
}

pub fn message_expiry_projection_from_value_with_anchor(
    expiry: Option<&Value>,
    created_at: chrono::DateTime<chrono::Utc>,
    now: chrono::DateTime<chrono::Utc>,
    anchor: Option<&MessageExpiryAnchor>,
) -> Option<MessageExpiryProjection> {
    let expiry = expiry?;
    let Some(object) = expiry.as_object() else {
        return Some(MessageExpiryProjection {
            state: MessageExpiryProjectionState::InvalidMetadata,
            trigger: "unknown".to_owned(),
            expires_at: None,
            anchor_hlc: None,
        });
    };
    let trigger = object
        .get("trigger")
        .and_then(Value::as_str)
        .unwrap_or("unknown")
        .to_owned();

    if matches!(trigger.as_str(), "on_first_read" | "on_last_read") {
        let ttl_ms = object.get("ttl_ms").and_then(Value::as_u64);
        let grace_ms = object.get("grace_ms").and_then(Value::as_u64).unwrap_or(0);
        let Some(anchor) = anchor.filter(|anchor| anchor.trigger == trigger) else {
            return Some(MessageExpiryProjection {
                state: MessageExpiryProjectionState::Live,
                trigger,
                expires_at: None,
                anchor_hlc: None,
            });
        };
        let expires_at = ttl_ms
            .and_then(|ttl_ms| ttl_ms.checked_add(grace_ms))
            .and_then(|total_ms| i64::try_from(total_ms).ok())
            .and_then(|total_ms| {
                anchor
                    .anchored_at
                    .checked_add_signed(chrono::Duration::milliseconds(total_ms))
            });
        let Some(expires_at) = expires_at else {
            return Some(MessageExpiryProjection {
                state: MessageExpiryProjectionState::InvalidMetadata,
                trigger,
                expires_at: None,
                anchor_hlc: Some(anchor.anchor_hlc.clone()),
            });
        };
        return Some(MessageExpiryProjection {
            state: if expires_at <= now {
                MessageExpiryProjectionState::Expired
            } else {
                MessageExpiryProjectionState::Live
            },
            trigger,
            expires_at: Some(expires_at),
            anchor_hlc: Some(anchor.anchor_hlc.clone()),
        });
    }

    if trigger != "on_send" {
        return Some(MessageExpiryProjection {
            state: MessageExpiryProjectionState::InvalidMetadata,
            trigger,
            expires_at: None,
            anchor_hlc: None,
        });
    }
    let ttl_ms = object.get("ttl_ms").and_then(Value::as_u64);
    let grace_ms = object.get("grace_ms").and_then(Value::as_u64).unwrap_or(0);
    let expires_at = ttl_ms
        .and_then(|ttl_ms| ttl_ms.checked_add(grace_ms))
        .and_then(|total_ms| i64::try_from(total_ms).ok())
        .and_then(|total_ms| {
            created_at.checked_add_signed(chrono::Duration::milliseconds(total_ms))
        });
    let Some(expires_at) = expires_at else {
        return Some(MessageExpiryProjection {
            state: MessageExpiryProjectionState::InvalidMetadata,
            trigger,
            expires_at: None,
            anchor_hlc: None,
        });
    };
    Some(MessageExpiryProjection {
        state: if expires_at <= now {
            MessageExpiryProjectionState::Expired
        } else {
            MessageExpiryProjectionState::Live
        },
        trigger,
        expires_at: Some(expires_at),
        anchor_hlc: None,
    })
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
    pub updated_hlc: String,
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

#[derive(Clone, Debug)]
pub struct ReadMarkerState {
    pub actor_id: String,
    pub device_id: String,
    pub realm_id: String,
    pub read_scope: ReadScopeWire,
    pub position: ReadCursorPositionWire,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone, Debug)]
pub struct SolandRelationState {
    pub relation_id: String,
    pub realm_id: String,
    pub relation_kind: String,
    pub scope_circle_id: Option<String>,
    pub from_ref: Option<String>,
    pub to_ref: Option<String>,
    pub fields: BTreeMap<String, Value>,
    pub state: String,
    pub source_event_id: Option<String>,
    pub source_event_digest: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub history_basis_seals: Vec<String>,
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
    /// `ak.component.member.state.v1` cell in
    /// [`super::ProjectionState::cells`]; this field is the structured-cache
    /// mirror updated on every membership transition.
    pub state: String,
    pub role: String,
    /// Effective member delivery status from the accepted
    /// `ak.member.state{membership=join}` payload. Only `routable` joins
    /// participate in Realm-scoped service fanout.
    pub delivery_status: Option<String>,
    /// Principal Server service DID materialized from the member
    /// `delivery_binding`. This is the single routing source for federated
    /// Realm event delivery; senders must not re-resolve DID Documents.
    pub recipient_service_id: Option<String>,
    /// Event frontier that established the current member state.
    pub membership_event_ref: Option<String>,
    /// Event frontier used for the current delivery binding. Falls back to
    /// the membership event when the binding does not carry a narrower
    /// frontier.
    pub delivery_binding_frontier: Option<String>,
    /// First effective invite frontier retained after a later join so
    /// `history_visibility=invited` can start at the invite boundary while
    /// `history_visibility=joined` starts at the join boundary.
    pub invited_at: Option<chrono::DateTime<chrono::Utc>>,
    pub joined_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    /// Machine-readable reason for the current state when the transition was
    /// not member-initiated (for example `controller_membership_ended` on the
    /// forced native-agent cascade, actor.md §3.3). `None` for ordinary
    /// member-driven transitions.
    pub reason: Option<String>,
}

#[derive(Clone, Debug)]
pub struct SolandRealmState {
    pub realm_id: String,
    pub owner: Option<String>,
    pub title: Option<String>,
    pub deleted: bool,
    pub archived: bool,
    pub frozen: bool,
    pub freeze_expires_at: Option<chrono::DateTime<chrono::Utc>>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    /// Round 4 (B1.2) — Realm trust domain. Captured and locked
    /// immutable on the first `ak.realm.create`; subsequent events that
    /// attempt to set a different trust domain MUST be rejected with
    /// `cross_domain_replay_rejected`. Stored as the canonical
    /// `ak:trust_domain:<scope>` string form.
    pub trust_domain: Option<String>,
    /// Stream-F (Wave 1B) — Realm terminal-state marker. Set by
    /// `apply_realm_lifecycle` when a `ak.realm.tombstone` or
    /// `ak.realm.destroy` event is projected. Possible values:
    ///   - `None` — Realm is live.
    ///   - `Some("tombstoned")` — `ak.realm.tombstone` accepted; the `successor_realm_id` field
    ///     carries the migration target.
    ///   - `Some("destroyed")` — `ak.realm.destroy` accepted; no successor.
    ///
    /// Both terminal states block non-audit writes via
    /// `routing::events::event_log::terminal_realm_check`. Spec
    /// `realm-and-space.md` §2.5 / §2.5.1.
    pub terminal_state: Option<String>,
    /// Stream-F (Wave 1B) — for `ak.realm.tombstone` only: the
    /// `ak:realm:<uuid>` of the successor Realm that takes over child
    /// Space/Strand placement. `None` for live or destroyed Realms.
    pub successor_realm_id: Option<String>,
    /// COT-06-004 — the Realm's default Strand pointer (`ak:strand:<UUIDv7>`).
    /// Set by `ak.realm.set_default_strand` (`apply_realm_set_default_strand`);
    /// the Strand it names MUST already be projected in this Realm. A Strand's
    /// derived `is_default` flag is computed at query time as
    /// `strand_id == realm.default_strand_id` — there is no separate stored
    /// per-Strand column.
    pub default_strand_id: Option<String>,
    /// `morph.md` §4.1 S3 — opt-in conformance profile ids the Realm has
    /// declared (`active_profiles[]` / `profiles[]` on `ak.realm.create` or
    /// `ak.realm.update`). Projected as a monotonically-growing set: a profile
    /// once observed stays declared (soland is not the committer and never
    /// silently relaxes a declared profile). Read by the morph schema-migration
    /// gate to decide whether breaking / transformation migrations are allowed.
    pub active_profiles: Vec<String>,
}
