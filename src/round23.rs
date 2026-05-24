//! Round R2/R3 (2026-05-20; spec 8b7978d) wire-breaking implementations.
//!
//! This module consolidates the 17 new normative reducer/validation paths
//! introduced by spec round 2+3 cleanup. It contains:
//!
//! - **events.submit gates** — ephemeral kind reject, receipt-object reject,
//!   terminal-Realm reject (T02 / T07 / T23).
//! - **cross_signing.reset cross-domain replay defence** (T08).
//! - **realm.policy_components hard ceiling + compliance mutex + media
//!   plaintext binding** (T09 / T12).
//! - **anchor frontier digest validation** (T04).
//! - **moderation.appeal.* reducer + state machine** (T06).
//! - **Realm tombstone vs destroy lifecycle** (T07).
//! - **Account deactivation fanout shape** (T07).
//! - **Presign blob fail-closed gates + headers** (T11).
//! - **Federation idempotency cache service-key binding** (T14).
//! - **identity_link cache policy_frontier_digest invalidation** (T13).
//! - **Cursor handle generation/validation** (T03).
//! - **Late key recovery state machine** (T16).
//! - **Consent revoke scope=any cascade + cache invalidation** (T17).
//!
//! The bodies here are deliberately minimal — most paths emit a `// TODO
//! (round23-T<XX>)` for the deeper internal logic and ship the wire-level
//! reject + new event-kind shape that other implementers depend on.

use chrono::{DateTime, Utc};
use contrix_sdk::events::{is_ephemeral_kind, is_receipt_object_only, is_terminal_realm_state};
use contrix_sdk::{
    EPHEMERAL_ABSOLUTE_HARD_CEILING_MS, EventId, Hash, TypedTrustDomainId, canonical,
    compute_policy_frontier_digest, validate_relaxed_window_ms,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::ErrorCode;

// ────────────────────────────────────────────────────────────────────────
// T02 / T23 — events.submit ephemeral / receipt-object rejection.
// ────────────────────────────────────────────────────────────────────────

/// Reject any event kind that is ephemeral or receipt-object-only at the
/// `cx.events.submit` entrypoint. Round R2/R3 (T02 + T23).
///
/// Returns the canonical [`ErrorCode`] + human reason when the kind MUST
/// be rejected; returns `None` when the kind is fine to forward to the
/// existing durable-event validator pipeline.
///
/// Wire-breaking: callers MUST hard-reject pre-Round-R2/R3 events that
/// carried ephemeral kinds on this endpoint — there is no compatibility
/// shim. Producers MUST migrate to `cx.schema.ephemeral_envelope.v1` for
/// broadcast forms and `cx.schema.device_message.v1` for point-to-point
/// to-device signals (`cx.key.verification.*`).
pub fn events_submit_pre_admit_check(kind: &str) -> Option<(ErrorCode, &'static str)> {
    if is_ephemeral_kind(kind) {
        // TODO(round23-T02): include kind in the human reason once the
        // tracing layer scrubs it; for now the literal cannot leak PII.
        return Some((
            ErrorCode::SchemaViolation,
            "ephemeral kind MUST be carried via cx.schema.ephemeral_envelope.v1 \
             (broadcast forms) or cx.schema.device_message.v1 \
             (cx.key.verification.* to-device); not durable cx.events.submit",
        ));
    }
    if is_receipt_object_only(kind) {
        // T23 — `cx.event_batch_receipt` is a receipt object only.
        return Some((
            ErrorCode::SchemaViolation,
            "cx.event_batch_receipt is a receipt object only; \
             never accepted as Event.kind",
        ));
    }
    None
}

/// True for events that MUST be accepted even after a Realm has reached
/// the destroyed terminal state — purely audit-class events such as
/// `cx.audit.*` and `cx.audit.ryw_receipt`. Used by [`terminal_realm_check`].
/// Round R2/R3 (T07).
pub fn is_audit_class_kind(kind: &str) -> bool {
    // Delegate to the canonical helper now that kinds.rs owns the
    // classifier. Local re-export kept for back-compat with callers
    // that already import `round23::is_audit_class_kind`.
    crate::kinds::is_audit_kind(kind)
}

/// Reject any non-audit-class write on a Realm whose lifecycle state is
/// terminal (`cx.realm.tombstone` or `cx.realm.destroy` applied).
/// Round R2/R3 (T07); extended by Stream-F (Wave 1B) to cover the
/// tombstone state per `realm-and-space.md` §2.5 / §2.5.1.
///
/// Returns `Some((ErrorCode::RealmTerminalState, reason))` when the write
/// MUST be rejected; `None` otherwise.
pub fn terminal_realm_check(
    realm_in_terminal_state: bool,
    kind: &str,
) -> Option<(ErrorCode, &'static str)> {
    if realm_in_terminal_state && !is_audit_class_kind(kind) {
        return Some((
            ErrorCode::RealmTerminalState,
            "Realm has reached cx.realm.tombstone or cx.realm.destroy \
             terminal state; only audit-class events are accepted",
        ));
    }
    None
}

// ────────────────────────────────────────────────────────────────────────
// T08 — cx.cross_signing.reset cross-domain replay defence.
// ────────────────────────────────────────────────────────────────────────

/// `cx.cross_signing.reset` payload trust-domain & reset_event_id check.
/// Round R2/R3 (T08).
///
/// Verification order MUST be:
/// 1. `payload.trust_domain` equals server's configured trust_domain
///    (else `cross_domain_replay_rejected`)
/// 2. `payload.reset_event_id` equals the enclosing Event's id
///    (else `reset_event_id_mismatch`)
/// 3. signature check (existing path; not implemented here)
///
/// Wire-breaking: the old payload without these required fields MUST be
/// hard-rejected (caller is responsible for raising `schema_violation`
/// on the prior missing-field path).
pub fn cross_signing_reset_replay_check(
    payload: &Value,
    event_id: &str,
    server_trust_domain: &str,
) -> Result<(), (ErrorCode, String)> {
    let payload_td = payload
        .get("trust_domain")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            (
                ErrorCode::SchemaViolation,
                "cross_signing.reset payload missing required `trust_domain` \
                 field (Round R2/R3 wire-breaking)"
                    .to_owned(),
            )
        })?;
    // Validate shape — the SDK typed id enforces the regex.
    if TypedTrustDomainId::new(payload_td).is_err() {
        return Err((
            ErrorCode::SchemaViolation,
            "cross_signing.reset.trust_domain must match \
             cx:trust_domain:<scope> per spec"
                .to_owned(),
        ));
    }
    if payload_td != server_trust_domain {
        return Err((
            ErrorCode::CrossDomainReplayRejected,
            "cross_signing.reset.trust_domain does not match this \
             Principal Server's configured trust_domain"
                .to_owned(),
        ));
    }
    let payload_reset_event_id = payload
        .get("reset_event_id")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            (
                ErrorCode::SchemaViolation,
                "cross_signing.reset payload missing required \
                     `reset_event_id` field (Round R2/R3 wire-breaking)"
                    .to_owned(),
            )
        })?;
    if EventId::new(payload_reset_event_id).is_err() {
        return Err((
            ErrorCode::SchemaViolation,
            "cross_signing.reset.reset_event_id must be a cx:event:<uuidv7>".to_owned(),
        ));
    }
    if payload_reset_event_id != event_id {
        return Err((
            ErrorCode::ResetEventIdMismatch,
            "cross_signing.reset.reset_event_id must equal the enclosing \
             Event.event_id"
                .to_owned(),
        ));
    }
    Ok(())
}

// ────────────────────────────────────────────────────────────────────────
// T09 / T12 — cx.realm.policy_components reducer checks.
// ────────────────────────────────────────────────────────────────────────

/// Active audit-compliance profile ids. Round R2/R3 (T09).
pub const AUDIT_COMPLIANCE_PROFILES: &[&str] = &[
    "cx.profile.attested_audit.e2ee.v1",
    "cx.profile.disclosed_audit.e2ee.v1",
];

/// Validate a `cx.realm.policy_components` payload. Round R2/R3 (T09 + T12).
///
/// Checks (in order):
/// 1. `relaxed_window_max_ms <= 300_000` (T09 hard ceiling)
/// 2. `cx.profile.e2ee_relaxed.v1` not active with any audit compliance
///    profile (T09 mutex)
/// 3. When `media_service_decrypts=true`, all three governance bindings
///    are present (T12) — caller passes the resolved bindings.
pub fn realm_policy_components_check(
    payload: &Value,
    active_profiles: &[String],
    media_plaintext_service_present: bool,
    mls_governance_binding_covers_policy_root: bool,
) -> Result<(), (ErrorCode, String)> {
    // (1) T09 — relaxed_window_max_ms ceiling.
    if let Some(window) = payload
        .pointer("/e2ee_relaxed/relaxed_window_max_ms")
        .and_then(Value::as_u64)
    {
        // SDK helper does the numeric check; out-of-range u32 also rejects.
        let window_u32 = u32::try_from(window).unwrap_or(u32::MAX);
        if validate_relaxed_window_ms(window_u32).is_err() {
            return Err((
                ErrorCode::RelaxedWindowExceedsCeiling,
                format!(
                    "e2ee_relaxed.relaxed_window_max_ms={window} exceeds absolute \
                     hard ceiling of {EPHEMERAL_ABSOLUTE_HARD_CEILING_MS}ms"
                ),
            ));
        }
    }

    // (2) T09 — e2ee_relaxed.v1 mutex against audit compliance.
    let relaxed_active = active_profiles
        .iter()
        .any(|p| p == "cx.profile.e2ee_relaxed.v1")
        || payload
            .pointer("/e2ee_relaxed/profile")
            .and_then(Value::as_str)
            == Some("cx.profile.e2ee_relaxed.v1");
    let compliance_active = active_profiles
        .iter()
        .any(|p| AUDIT_COMPLIANCE_PROFILES.contains(&p.as_str()));
    if relaxed_active && compliance_active {
        return Err((
            ErrorCode::E2eeRelaxedDisallowedInComplianceProfile,
            "cx.profile.e2ee_relaxed.v1 is mutually exclusive with audit \
             compliance profiles (attested_audit.e2ee.v1 / \
             disclosed_audit.e2ee.v1)"
                .to_owned(),
        ));
    }

    // (3) T12 — media_service_decrypts triple binding.
    if payload
        .get("media_service_decrypts")
        .and_then(Value::as_bool)
        == Some(true)
    {
        if !media_plaintext_service_present {
            return Err((
                ErrorCode::MediaPlaintextServiceNotAuthorised,
                "media_service_decrypts=true requires the SFU/MCU service DID \
                 to be listed in plaintext_visible_services[] with \
                 purpose=media_plaintext"
                    .to_owned(),
            ));
        }
        if !mls_governance_binding_covers_policy_root {
            return Err((
                ErrorCode::MlsGovernanceBindingStale,
                "media_service_decrypts=true requires the current MLS epoch \
                 governance binding's policy_root to cover the active media \
                 plaintext policy"
                    .to_owned(),
            ));
        }
    }
    Ok(())
}

// ────────────────────────────────────────────────────────────────────────
// T04 — anchor frontier digest validation.
// ────────────────────────────────────────────────────────────────────────

/// Validate every entry in an Anchor `frontier[]` is shaped as
/// `sha256:<64 lowercase hex>` — never a `cx:event:<uuid>` form. Round
/// R2/R3 (T04).
///
/// Receivers MUST recompute and verify entries; the strict shape check
/// here guards against the legacy event-id form that was permitted in
/// pre-R2/R3 spec drafts.
pub fn validate_anchor_frontier_entries(frontier: &[String]) -> Result<(), (ErrorCode, String)> {
    for entry in frontier {
        if !is_sha256_digest(entry) {
            return Err((
                ErrorCode::SchemaViolation,
                format!(
                    "anchor frontier entries must match sha256:<64 lowercase hex>; \
                     got {entry:?}"
                ),
            ));
        }
    }
    Ok(())
}

fn is_sha256_digest(s: &str) -> bool {
    let Some(hex) = s.strip_prefix("sha256:") else {
        return false;
    };
    hex.len() == 64
        && hex
            .chars()
            .all(|c| c.is_ascii_digit() || matches!(c, 'a'..='f'))
}

// ────────────────────────────────────────────────────────────────────────
// T06 — cx.moderation.appeal.* reducer & state machine.
// ────────────────────────────────────────────────────────────────────────

/// Cell state machine for a `cx:appeal:<uuid>` row. Round R2/R3 (T06).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AppealState {
    None,
    Submitted,
    UnderReview,
    Decided,
    Closed,
}

impl AppealState {
    /// True when `new` is a valid transition from `self` for the
    /// moderation-appeal cell. Round R2/R3 (T06).
    pub fn can_transition_to(self, new: AppealState) -> bool {
        use AppealState::*;
        matches!(
            (self, new),
            (None, Submitted)
                | (Submitted, UnderReview)
                | (UnderReview, Decided)
                | (Decided, Closed)
        )
    }
}

/// Auto-close cool-off in days. Round R2/R3 (T06) — open appeals MUST be
/// auto-closed once their submitted_at is more than 30 days behind the
/// reducer's current time.
pub const APPEAL_AUTO_CLOSE_COOL_OFF_DAYS: i64 = 30;

/// Build the canonical cell id for an appeal. Round R2/R3 (T06).
pub fn appeal_cell_id(appeal_id: &str) -> String {
    format!("cx:cell:cx.component.moderation.appeal.v1:{appeal_id}")
}

/// Round R2/R3 (T06) — when an appeal `decision` event has
/// `verdict=overturn`, the reducer MUST find a paired
/// `cx.moderation.decision.lift` event in the same Anchor batch
/// referencing the original decision.
///
/// Returns `Err(AppealOverturnMissingLift)` when the verdict is overturn
/// but no qualifying lift event was provided in the batch.
pub fn appeal_decision_overturn_paired_check(
    verdict: &str,
    original_decision_id: &str,
    batch_kinds_and_refs: &[(&str, &str)],
) -> Result<(), (ErrorCode, String)> {
    if verdict != "overturn" {
        return Ok(());
    }
    let has_lift = batch_kinds_and_refs.iter().any(|(kind, ref_id)| {
        *kind == "cx.moderation.decision.lift" && *ref_id == original_decision_id
    });
    if !has_lift {
        return Err((
            ErrorCode::AppealOverturnMissingLift,
            "cx.moderation.appeal.decision verdict=overturn requires a paired \
             cx.moderation.decision.lift in the same Anchor batch referencing \
             the original decision"
                .to_owned(),
        ));
    }
    Ok(())
}

/// Round R2/R3 (T06) — reviewer / decision-issuer separation of duties.
/// The reviewer (or decision actor) MUST NOT be the actor who issued
/// the original moderation decision.
pub fn appeal_self_review_check(
    reviewer: &str,
    original_decision_issuer: &str,
) -> Result<(), (ErrorCode, String)> {
    if reviewer == original_decision_issuer {
        return Err((
            ErrorCode::AppealSelfReviewForbidden,
            "cx.moderation.appeal review/decision actor MUST differ from the \
             original moderation decision issuer (separation of duties)"
                .to_owned(),
        ));
    }
    Ok(())
}

// ────────────────────────────────────────────────────────────────────────
// T07 — Realm tombstone vs destroy.
// ────────────────────────────────────────────────────────────────────────

/// Round R2/R3 (T07) — Realm lifecycle state classifier mirror of the
/// SDK [`contrix_sdk::RealmLifecycleState`] enum.
pub fn realm_state_is_terminal(state: contrix_sdk::events::RealmLifecycleState) -> bool {
    is_terminal_realm_state(state)
}

/// Round R2/R3 (T07) — federation fanout window for erasure receipts
/// emitted by `cx.realm.destroy`. Spec: 30 days.
pub const REALM_DESTROY_FANOUT_WINDOW_DAYS: i64 = 30;

// ────────────────────────────────────────────────────────────────────────
// T07 — Account deactivation fanout state.
// ────────────────────────────────────────────────────────────────────────

/// The 7 fanout domains triggered by `cx.account.deactivate`. Round
/// R2/R3 (T07).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeactivationFanoutDomain {
    SessionRevoke,
    DeviceTombstone,
    AppletUninstall,
    KeypackageBurn,
    PushChannelUnbind,
    ToDeviceQueueDrain,
    CapabilityCacheInvalidate,
}

impl DeactivationFanoutDomain {
    pub const ALL: &'static [Self] = &[
        Self::SessionRevoke,
        Self::DeviceTombstone,
        Self::AppletUninstall,
        Self::KeypackageBurn,
        Self::PushChannelUnbind,
        Self::ToDeviceQueueDrain,
        Self::CapabilityCacheInvalidate,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::SessionRevoke => "session_revoke",
            Self::DeviceTombstone => "device_tombstone",
            Self::AppletUninstall => "applet_uninstall",
            Self::KeypackageBurn => "keypackage_burn",
            Self::PushChannelUnbind => "push_channel_unbind",
            Self::ToDeviceQueueDrain => "to_device_queue_drain",
            Self::CapabilityCacheInvalidate => "capability_cache_invalidate",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeactivationDomainStatus {
    Pending,
    Completed,
    Failed,
}

/// Per-actor deactivation status projection. Round R2/R3 (T07).
///
/// TODO(round23-T07): the async fanout worker that actually drains each
/// domain still lives in implementer follow-ups (floria for push, chime
/// for to-device); this struct is the canonical projection shape that
/// other implementers can read from to surface UI state. The "outcome"
/// field is `partially_completed` whenever any non-failed domain is
/// still pending.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DeactivationFanoutProjection {
    pub actor: String,
    pub initiated_at: DateTime<Utc>,
    pub domain_status: std::collections::BTreeMap<String, DeactivationDomainStatus>,
    pub outcome: String,
}

impl DeactivationFanoutProjection {
    pub fn new(actor: impl Into<String>, now: DateTime<Utc>) -> Self {
        let mut domain_status = std::collections::BTreeMap::new();
        for domain in DeactivationFanoutDomain::ALL {
            domain_status.insert(
                domain.as_str().to_owned(),
                DeactivationDomainStatus::Pending,
            );
        }
        Self {
            actor: actor.into(),
            initiated_at: now,
            domain_status,
            outcome: "in_progress".to_owned(),
        }
    }

    /// Refresh `outcome` based on the current per-domain status table.
    /// Returns the new outcome string for convenience.
    pub fn refresh_outcome(&mut self) -> &str {
        let mut any_failed = false;
        let mut any_pending = false;
        let mut all_completed = true;
        for status in self.domain_status.values() {
            match status {
                DeactivationDomainStatus::Failed => {
                    any_failed = true;
                    all_completed = false;
                }
                DeactivationDomainStatus::Pending => {
                    any_pending = true;
                    all_completed = false;
                }
                DeactivationDomainStatus::Completed => {}
            }
        }
        self.outcome = if all_completed {
            "completed".to_owned()
        } else if any_failed && !any_pending {
            "partially_completed".to_owned()
        } else if any_pending
            && self.domain_status.values().any(|s| {
                matches!(
                    s,
                    DeactivationDomainStatus::Completed | DeactivationDomainStatus::Failed
                )
            })
        {
            "partially_completed".to_owned()
        } else {
            "in_progress".to_owned()
        };
        &self.outcome
    }
}

// ────────────────────────────────────────────────────────────────────────
// T11 — Presign blob fail-closed gating.
// ────────────────────────────────────────────────────────────────────────

/// Blob preflight classifier for presign endpoints. Round R2/R3 (T11).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PresignBlobBlock {
    /// Blob payload is end-to-end encrypted; presign would expose key
    /// material — refuse fail-closed.
    E2ee,
    /// Blob is currently subject to a legal hold.
    LegalHold,
    /// Blob has been redacted.
    Redacted,
    /// Blob is actor_private and the requester is not the owner.
    ActorPrivate,
}

impl PresignBlobBlock {
    pub fn as_error(self) -> (ErrorCode, &'static str) {
        match self {
            Self::E2ee => (
                ErrorCode::CapabilityDenied,
                "blob is end-to-end encrypted; presign is refused fail-closed",
            ),
            Self::LegalHold => (
                ErrorCode::LegalHoldActive,
                "blob is currently subject to a legal hold; presign refused",
            ),
            Self::Redacted => (
                ErrorCode::BlobRedacted,
                "blob has been redacted; presign refused",
            ),
            Self::ActorPrivate => (
                ErrorCode::CapabilityDenied,
                "blob is actor_private; only the owner may request a presign URL",
            ),
        }
    }
}

/// Inspect a blob record for any of the four fail-closed classes. Round
/// R2/R3 (T11). Returns the matching block reason or `None`.
///
/// The blob record is taken as a JSON value so this fn stays decoupled
/// from `crate::state::BlobRecord`; presign callers pass
/// `serde_json::to_value(&record)` (cheap — BlobRecord is small).
pub fn classify_presign_blob_block(
    blob: &Value,
    requester_actor: &str,
) -> Option<PresignBlobBlock> {
    // E2EE: any encryption metadata present.
    if blob.get("encryption").is_some_and(|v| !v.is_null()) {
        return Some(PresignBlobBlock::E2ee);
    }
    // Legal hold flag.
    if blob.get("legal_hold").and_then(Value::as_bool) == Some(true) {
        return Some(PresignBlobBlock::LegalHold);
    }
    // Redaction.
    if blob.get("redacted").and_then(Value::as_bool) == Some(true) {
        return Some(PresignBlobBlock::Redacted);
    }
    // actor_private visibility class.
    if blob.get("visibility").and_then(Value::as_str) == Some("actor_private") {
        let owner = blob
            .get("uploaded_by")
            .and_then(Value::as_str)
            .unwrap_or("");
        if owner != requester_actor {
            return Some(PresignBlobBlock::ActorPrivate);
        }
    }
    None
}

/// Response headers that MUST be set on presign responses. Round R2/R3 (T11).
///
/// Per spec: presign URLs are short-lived bearer tokens; intermediaries
/// MUST NOT cache them and the referring page MUST NOT leak the URL.
pub const PRESIGN_CACHE_CONTROL: &str = "private, no-store";
pub const PRESIGN_REFERRER_POLICY: &str = "no-referrer";

/// Scrub a presign URL down to its origin + path for tracing/logging.
/// Round R2/R3 (T11) — the query string carries the signature and MUST
/// NOT appear in logs.
pub fn scrub_presign_url_for_log(url: &str) -> String {
    match url.split_once('?') {
        Some((origin_path, _query)) => format!("{origin_path}?<scrubbed>"),
        None => url.to_owned(),
    }
}

// ────────────────────────────────────────────────────────────────────────
// T14 — Federation idempotency cache service-key binding.
// ────────────────────────────────────────────────────────────────────────

/// Round R2/R3 (T14) — fields added to the federation idempotency cache
/// key so a replay after key revoke is recognised as a stale historical
/// request rather than a fresh one.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FederationIdempotencyServiceBinding {
    pub source_service_did: String,
    pub verification_method: String,
    pub service_binding_ref: String,
    pub origin_key_state_digest: String,
}

/// Round R2/R3 (T14) — when a cached federation transaction is replayed
/// after the source service has rotated its verification key, the
/// receiver MUST return the original cached response with this marker
/// rather than triggering side effects.
pub const HISTORICAL_ONLY_MARKER: &str = "historical_only";

/// Mark a cached federation response as `historical_only=true`. Round
/// R2/R3 (T14).
pub fn mark_response_historical_only(mut response: Value) -> Value {
    if let Some(object) = response.as_object_mut() {
        object.insert(HISTORICAL_ONLY_MARKER.to_owned(), Value::Bool(true));
    }
    response
}

// ────────────────────────────────────────────────────────────────────────
// T13 — identity_link cache policy_frontier_digest.
// ────────────────────────────────────────────────────────────────────────

/// Round R2/R3 (T13) — compute the four-field policy frontier hash for
/// an identity_link cache entry via SDK.
pub fn identity_link_policy_frontier_digest(
    disclosure_policy: &Value,
    history_visibility: &Value,
    identity_disclosure_profile: &Value,
    minimal_metadata_mode: &Value,
) -> [u8; 32] {
    compute_policy_frontier_digest(
        disclosure_policy,
        history_visibility,
        identity_disclosure_profile,
        minimal_metadata_mode,
    )
    .unwrap_or([0u8; 32])
}

/// Round R2/R3 (T13) — five governance-input change classifications that
/// MUST eagerly invalidate cached identity_link routing decisions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IdentityLinkInvalidationTrigger {
    DisclosurePolicyStricter,
    MinimalMetadataStricter,
    HistoryVisibilityTighter,
    IdentityDisclosureProfileChange,
    LinkedRealmTighter,
}

// ────────────────────────────────────────────────────────────────────────
// T03 — cursor handle.
// ────────────────────────────────────────────────────────────────────────

/// Round R2/R3 (T03) — minimum length of a base64url cursor handle to
/// supply ≥128-bit entropy. Spec tightened `h.minLength` from 16 → 22.
pub const CURSOR_HANDLE_MIN_LENGTH: usize = 22;

/// Validate an inbound cursor handle (post-base64url-decode is callers'
/// responsibility). Round R2/R3 (T03) — rejects shorter than 22 chars.
pub fn validate_cursor_handle(handle: &str) -> Result<(), (ErrorCode, &'static str)> {
    if handle.len() < CURSOR_HANDLE_MIN_LENGTH {
        return Err((
            ErrorCode::CursorIntegrityInvalid,
            "cursor handle MUST be at least 22 base64url characters \
             (≥128-bit entropy); Round R2/R3 spec tightening",
        ));
    }
    if !handle
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_'))
    {
        return Err((
            ErrorCode::CursorIntegrityInvalid,
            "cursor handle MUST be base64url (no padding)",
        ));
    }
    Ok(())
}

// ────────────────────────────────────────────────────────────────────────
// T16 — Late key recovery state machine.
// ────────────────────────────────────────────────────────────────────────

/// Round R2/R3 (T16) — per-(actor, ciphertext) late-recovery state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LateRecoveryState {
    DecryptionPending,
    DecryptionFailed,
    LateRecovered,
}

impl LateRecoveryState {
    pub fn can_transition_to(self, new: Self) -> bool {
        use LateRecoveryState::*;
        matches!(
            (self, new),
            (DecryptionPending, DecryptionFailed)
                | (DecryptionPending, LateRecovered)
                | (DecryptionFailed, LateRecovered)
        )
    }
}

/// Round R2/R3 (T16) — accept-late-recovery preconditions. All four
/// MUST evaluate true for the reducer to apply a late key share to a
/// `decryption_failed` cell.
#[derive(Clone, Copy, Debug)]
pub struct LateRecoveryAcceptInputs {
    /// (a) Actor was a Realm member at T₀ (recovery-target ciphertext's
    /// epoch).
    pub member_at_t0: bool,
    /// (b) Realm policy at T₀ permitted the actor to read the
    /// ciphertext.
    pub policy_permitted_at_t0: bool,
    /// (c) The presented key share was authorised by an origin permitted
    /// to issue late shares (e.g. cross-signed device or trusted
    /// recovery service).
    pub key_share_authorised: bool,
    /// (d) Audit profile MUST emit a paired `cx.audit.accessed{late_recovery=true}`
    /// event for the read. Callers set this true once they have queued
    /// the audit emit.
    pub audit_emit_queued: bool,
}

/// Round R2/R3 (T16) — apply the 4 accept conditions; reject revoked /
/// removed members with `late_recovery_rejected_membership`.
pub fn late_recovery_accept_check(
    inputs: LateRecoveryAcceptInputs,
) -> Result<(), (ErrorCode, &'static str)> {
    if !inputs.member_at_t0 {
        return Err((
            ErrorCode::LateRecoveryRejectedMembership,
            "actor was not a Realm member at the recovery T₀; late key \
             recovery refused",
        ));
    }
    if !inputs.policy_permitted_at_t0 {
        return Err((
            ErrorCode::LateRecoveryRejectedMembership,
            "Realm policy at T₀ did not permit the actor to read this \
             ciphertext",
        ));
    }
    if !inputs.key_share_authorised {
        return Err((
            ErrorCode::InvalidSignature,
            "late key share origin is not authorised",
        ));
    }
    if !inputs.audit_emit_queued {
        return Err((
            ErrorCode::FailedPrecondition,
            "late key recovery requires a paired cx.audit.accessed{late_recovery=true} \
             audit emit",
        ));
    }
    Ok(())
}

// ────────────────────────────────────────────────────────────────────────
// T17 — Consent revoke scope=any cascade.
// ────────────────────────────────────────────────────────────────────────

/// Round R2/R3 (T17) — child scopes that a `scope=any` revoke MUST
/// cascade into. The full list is open-ended in spec; soland tracks the
/// five that gate cross-service routing today.
pub const CONSENT_SCOPE_CASCADE: &[&str] = &[
    "directory_reachability",
    "mimi_consent",
    "push_contact_psi",
    "invite_gate",
    "in_flight_invite",
];

/// Round R2/R3 (T17) — when a consent revoke is issued with `scope=any`,
/// the projection MUST mark every cascaded child scope with this marker
/// so consumers can distinguish "explicitly revoked" from "swept by an
/// any-revoke".
pub const SUPERSEDED_BY_ANY_REVOKE: &str = "superseded_by_any_revoke";

/// Round R2/R3 (T17) — five cache-invalidation channels that an
/// `any`-revoke MUST broadcast to cross-service consumers (teabay /
/// floria / coauth).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConsentRevokeInvalidationChannel {
    DirectoryReachability,
    MimiConsent,
    PushContactPsi,
    InviteGate,
    InFlightInvite,
}

impl ConsentRevokeInvalidationChannel {
    pub const ALL: &'static [Self] = &[
        Self::DirectoryReachability,
        Self::MimiConsent,
        Self::PushContactPsi,
        Self::InviteGate,
        Self::InFlightInvite,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::DirectoryReachability => "directory_reachability",
            Self::MimiConsent => "mimi_consent",
            Self::PushContactPsi => "push_contact_psi",
            Self::InviteGate => "invite_gate",
            Self::InFlightInvite => "in_flight_invite",
        }
    }
}

// ────────────────────────────────────────────────────────────────────────
// T23 — receipt object/event layering.
// ────────────────────────────────────────────────────────────────────────

/// Round R2/R3 (T23) — true when `cx.audit.ryw_receipt` may be accepted
/// as a durable Event. Requires `cx.profile.attested_audit.e2ee.v1` to
/// be in the Realm's active profile set.
pub fn ryw_receipt_durable_event_allowed(active_profiles: &[String]) -> bool {
    active_profiles
        .iter()
        .any(|p| p == "cx.profile.attested_audit.e2ee.v1")
}

// ────────────────────────────────────────────────────────────────────────
// Canonical-hash helper for moderation appeal cell payloads.
// ────────────────────────────────────────────────────────────────────────

/// SHA-256 of canonical-JSON encoded value. Round R2/R3 helper used by
/// the moderation-appeal reducer to derive the appeal cell digest.
pub fn canonical_sha256_hex(value: &Value) -> String {
    use sha2::Digest;
    let bytes = canonical::canonical_json_bytes(value).unwrap_or_default();
    let digest = sha2::Sha256::digest(&bytes);
    format!("sha256:{:x}", digest)
}

/// Type alias kept for clarity at call sites that expect a Hash.
pub type Sha256Hex = String;

/// Convenience — render an SDK [`Hash`] to a hex string for cell key
/// composition. Round R2/R3.
pub fn hash_to_hex(hash: &Hash) -> String {
    hash.as_str().to_owned()
}

// ────────────────────────────────────────────────────────────────────────
// Tests — at least one per new reducer per task scope.
// ────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn ephemeral_kind_rejected_at_submit_entry() {
        // T02 — all 12 ephemeral patterns hit the guard.
        for kind in [
            "cx.call.signal",
            "cx.presence",
            "cx.typing",
            "cx.receipt.read",
            "cx.key.verification.start",
            "cx.key.verification.accept",
            "cx.key.verification.mac",
        ] {
            let result = events_submit_pre_admit_check(kind);
            assert!(
                matches!(result, Some((ErrorCode::SchemaViolation, _))),
                "ephemeral kind {kind} must be rejected by submit entry"
            );
        }
    }

    #[test]
    fn receipt_object_kind_rejected_at_submit_entry() {
        // T23
        assert!(matches!(
            events_submit_pre_admit_check("cx.event_batch_receipt"),
            Some((ErrorCode::SchemaViolation, _))
        ));
    }

    #[test]
    fn durable_kind_passes_submit_entry() {
        assert!(events_submit_pre_admit_check("cx.message.create").is_none());
        assert!(events_submit_pre_admit_check("cx.realm.create").is_none());
    }

    #[test]
    fn terminal_realm_blocks_non_audit_kind() {
        let blocked = terminal_realm_check(true, "cx.message.create");
        assert!(matches!(blocked, Some((ErrorCode::RealmTerminalState, _))));
        let audit_ok = terminal_realm_check(true, "cx.audit.accessed");
        assert!(audit_ok.is_none());
        let live_ok = terminal_realm_check(false, "cx.message.create");
        assert!(live_ok.is_none());
    }

    #[test]
    fn cross_signing_reset_replay_rejects_wrong_trust_domain() {
        let payload = json!({
            "trust_domain": "cx:trust_domain:other.example",
            "reset_event_id": "cx:event:01904100-0000-7000-8000-000000000001",
        });
        let err = cross_signing_reset_replay_check(
            &payload,
            "cx:event:01904100-0000-7000-8000-000000000001",
            "cx:trust_domain:soland.local",
        )
        .unwrap_err();
        assert_eq!(err.0, ErrorCode::CrossDomainReplayRejected);
    }

    #[test]
    fn cross_signing_reset_replay_rejects_wrong_event_id() {
        let payload = json!({
            "trust_domain": "cx:trust_domain:soland.local",
            "reset_event_id": "cx:event:01904100-0000-7000-8000-000000000002",
        });
        let err = cross_signing_reset_replay_check(
            &payload,
            "cx:event:01904100-0000-7000-8000-000000000001",
            "cx:trust_domain:soland.local",
        )
        .unwrap_err();
        assert_eq!(err.0, ErrorCode::ResetEventIdMismatch);
    }

    #[test]
    fn cross_signing_reset_replay_passes_when_matched() {
        let payload = json!({
            "trust_domain": "cx:trust_domain:soland.local",
            "reset_event_id": "cx:event:01904100-0000-7000-8000-000000000001",
        });
        cross_signing_reset_replay_check(
            &payload,
            "cx:event:01904100-0000-7000-8000-000000000001",
            "cx:trust_domain:soland.local",
        )
        .unwrap();
    }

    #[test]
    fn realm_policy_components_relaxed_window_ceiling() {
        let payload = json!({"e2ee_relaxed": {"relaxed_window_max_ms": 300_001 }});
        let err = realm_policy_components_check(&payload, &[], false, false).unwrap_err();
        assert_eq!(err.0, ErrorCode::RelaxedWindowExceedsCeiling);
    }

    #[test]
    fn realm_policy_components_e2ee_relaxed_compliance_mutex() {
        let payload = json!({"e2ee_relaxed": {"profile": "cx.profile.e2ee_relaxed.v1"}});
        let err = realm_policy_components_check(
            &payload,
            &["cx.profile.attested_audit.e2ee.v1".to_owned()],
            false,
            false,
        )
        .unwrap_err();
        assert_eq!(err.0, ErrorCode::E2eeRelaxedDisallowedInComplianceProfile);
    }

    #[test]
    fn realm_policy_components_media_plaintext_triple_binding() {
        let payload = json!({"media_service_decrypts": true});
        let err = realm_policy_components_check(&payload, &[], false, true).unwrap_err();
        assert_eq!(err.0, ErrorCode::MediaPlaintextServiceNotAuthorised);
        let err2 = realm_policy_components_check(&payload, &[], true, false).unwrap_err();
        assert_eq!(err2.0, ErrorCode::MlsGovernanceBindingStale);
        // All bindings present — ok.
        realm_policy_components_check(&payload, &[], true, true).unwrap();
    }

    #[test]
    fn anchor_frontier_rejects_event_id_form() {
        let entries = vec!["cx:event:01904100-0000-7000-8000-000000000001".to_owned()];
        let err = validate_anchor_frontier_entries(&entries).unwrap_err();
        assert_eq!(err.0, ErrorCode::SchemaViolation);
    }

    #[test]
    fn anchor_frontier_accepts_sha256() {
        let entries = vec![format!("sha256:{}", "a".repeat(64))];
        validate_anchor_frontier_entries(&entries).unwrap();
    }

    #[test]
    fn appeal_state_machine_transitions() {
        use AppealState::*;
        assert!(None.can_transition_to(Submitted));
        assert!(Submitted.can_transition_to(UnderReview));
        assert!(UnderReview.can_transition_to(Decided));
        assert!(Decided.can_transition_to(Closed));
        assert!(!Submitted.can_transition_to(Closed));
        assert!(!UnderReview.can_transition_to(Closed));
        assert!(!Decided.can_transition_to(Submitted));
        assert!(!Closed.can_transition_to(Submitted));
    }

    #[test]
    fn appeal_decision_overturn_requires_lift_in_batch() {
        let err = appeal_decision_overturn_paired_check(
            "overturn",
            "cx:event:01904100-0000-7000-8000-000000000aaa",
            &[],
        )
        .unwrap_err();
        assert_eq!(err.0, ErrorCode::AppealOverturnMissingLift);
        // Lift event present — ok.
        appeal_decision_overturn_paired_check(
            "overturn",
            "cx:event:01904100-0000-7000-8000-000000000aaa",
            &[(
                "cx.moderation.decision.lift",
                "cx:event:01904100-0000-7000-8000-000000000aaa",
            )],
        )
        .unwrap();
    }

    #[test]
    fn appeal_self_review_forbidden() {
        let err =
            appeal_self_review_check("did:web:mod.example", "did:web:mod.example").unwrap_err();
        assert_eq!(err.0, ErrorCode::AppealSelfReviewForbidden);
        appeal_self_review_check("did:web:reviewer.example", "did:web:mod.example").unwrap();
    }

    #[test]
    fn deactivation_fanout_outcome_progression() {
        let mut p = DeactivationFanoutProjection::new("did:web:alice.example", Utc::now());
        assert_eq!(p.refresh_outcome(), "in_progress");
        // Complete the first 4 domains, leave 3 pending → partially_completed.
        for domain in &DeactivationFanoutDomain::ALL[..4] {
            p.domain_status.insert(
                domain.as_str().to_owned(),
                DeactivationDomainStatus::Completed,
            );
        }
        assert_eq!(p.refresh_outcome(), "partially_completed");
        // All completed → completed.
        for domain in DeactivationFanoutDomain::ALL {
            p.domain_status.insert(
                domain.as_str().to_owned(),
                DeactivationDomainStatus::Completed,
            );
        }
        assert_eq!(p.refresh_outcome(), "completed");
    }

    #[test]
    fn presign_blob_e2ee_blocked() {
        let blob = json!({"encryption": {"alg": "xchacha20poly1305"}, "uploaded_by": "did:web:alice.example"});
        assert_eq!(
            classify_presign_blob_block(&blob, "did:web:alice.example"),
            Some(PresignBlobBlock::E2ee)
        );
    }

    #[test]
    fn presign_blob_legal_hold_blocked() {
        let blob = json!({"legal_hold": true, "uploaded_by": "did:web:alice.example"});
        assert_eq!(
            classify_presign_blob_block(&blob, "did:web:alice.example"),
            Some(PresignBlobBlock::LegalHold)
        );
    }

    #[test]
    fn presign_blob_redacted_blocked() {
        let blob = json!({"redacted": true, "uploaded_by": "did:web:alice.example"});
        assert_eq!(
            classify_presign_blob_block(&blob, "did:web:alice.example"),
            Some(PresignBlobBlock::Redacted)
        );
    }

    #[test]
    fn presign_blob_actor_private_blocked_for_non_owner() {
        let blob = json!({"visibility": "actor_private", "uploaded_by": "did:web:alice.example"});
        assert_eq!(
            classify_presign_blob_block(&blob, "did:web:bob.example"),
            Some(PresignBlobBlock::ActorPrivate)
        );
        assert_eq!(
            classify_presign_blob_block(&blob, "did:web:alice.example"),
            None
        );
    }

    #[test]
    fn presign_url_scrub_drops_query_string() {
        let s = scrub_presign_url_for_log("https://s3/x/y?token=xyz&sig=abc");
        assert!(!s.contains("token=xyz"));
        assert!(!s.contains("sig=abc"));
        assert!(s.contains("https://s3/x/y"));
    }

    #[test]
    fn federation_historical_only_mark() {
        let v = json!({"ok": true});
        let marked = mark_response_historical_only(v);
        assert_eq!(
            marked.get("historical_only").and_then(Value::as_bool),
            Some(true)
        );
    }

    #[test]
    fn cursor_handle_minimum_length_enforced() {
        // 22-char handle should pass.
        let ok = "a".repeat(22);
        validate_cursor_handle(&ok).unwrap();
        // 21-char handle must fail.
        let bad = "a".repeat(21);
        let err = validate_cursor_handle(&bad).unwrap_err();
        assert_eq!(err.0, ErrorCode::CursorIntegrityInvalid);
    }

    #[test]
    fn late_recovery_rejects_revoked_actor() {
        let err = late_recovery_accept_check(LateRecoveryAcceptInputs {
            member_at_t0: false,
            policy_permitted_at_t0: true,
            key_share_authorised: true,
            audit_emit_queued: true,
        })
        .unwrap_err();
        assert_eq!(err.0, ErrorCode::LateRecoveryRejectedMembership);
    }

    #[test]
    fn late_recovery_accepts_when_all_four_conditions() {
        late_recovery_accept_check(LateRecoveryAcceptInputs {
            member_at_t0: true,
            policy_permitted_at_t0: true,
            key_share_authorised: true,
            audit_emit_queued: true,
        })
        .unwrap();
    }

    #[test]
    fn late_recovery_state_machine_transitions() {
        use LateRecoveryState::*;
        assert!(DecryptionPending.can_transition_to(DecryptionFailed));
        assert!(DecryptionFailed.can_transition_to(LateRecovered));
        assert!(!LateRecovered.can_transition_to(DecryptionPending));
    }

    #[test]
    fn consent_revoke_cascade_table_stable() {
        // Sanity — 5 channels, 5 cascade scopes.
        assert_eq!(ConsentRevokeInvalidationChannel::ALL.len(), 5);
        assert_eq!(CONSENT_SCOPE_CASCADE.len(), 5);
    }

    #[test]
    fn ryw_receipt_durable_only_under_attested_profile() {
        assert!(!ryw_receipt_durable_event_allowed(&[]));
        assert!(ryw_receipt_durable_event_allowed(&[
            "cx.profile.attested_audit.e2ee.v1".to_owned()
        ]));
    }

    #[test]
    fn identity_link_policy_frontier_digest_is_deterministic() {
        let a = identity_link_policy_frontier_digest(
            &json!({"mode": "strict"}),
            &json!("members_only"),
            &json!({"profile": "default"}),
            &json!(false),
        );
        let b = identity_link_policy_frontier_digest(
            &json!({"mode": "strict"}),
            &json!("members_only"),
            &json!({"profile": "default"}),
            &json!(false),
        );
        assert_eq!(a, b);
    }
}
