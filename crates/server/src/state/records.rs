use std::collections::{BTreeMap, BTreeSet};

use cokret_sdk::{BlobVisibility, FreshnessState, PlaintextDataClassKind};
use serde_json::Value;

#[derive(Clone, Debug)]
pub struct AgentSessionRecord {
    pub scope_details: Value,
    pub freshness_state: FreshnessState,
}

#[derive(Clone, Debug)]
pub struct SessionRecord {
    pub token_hash: String,
    pub actor: String,
    pub device_id: String,
    pub audience: String,
    /// Session signing key (JWK) bound by `ck.session.grant`, used to verify
    /// RFC 9421 PoP presentations on `/_cokret/self/*` (api-conventions.md
    /// §3.2). `None` for bearer-only / dev-login / OAuth-bridged sessions.
    pub session_public_key: Option<String>,
    pub agent_session: Option<AgentSessionRecord>,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub revoked_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Clone, Debug)]
pub struct DeviceInventoryRecord {
    pub actor: String,
    pub device_id: String,
    pub display_name: Option<String>,
    pub verification_state: String,
    pub payload: Value,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    pub revoked_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Clone, Debug)]
pub struct AccountRecord {
    /// Surrogate row primary key (`ck:account:<uuid7>`), minted by
    /// [`crate::ids::generate_account_id`] at account creation. Stable
    /// internal handle decoupled from the `principal_id` DID (which may rotate).
    pub id: String,
    /// The account's protocol identity DID (DB column `principal_id`).
    pub did: String,
    /// Bare handle localpart (`alice` — never `@alice` or `alice:domain`).
    /// The domain half of the canonical `<localpart>:<domain>` handle is
    /// implicit (always this server's own service domain), so renaming the
    /// server's domain never rewrites account rows. Wire/display surfaces
    /// use [`AccountRecord::handle`] for the `@`-prefixed form.
    pub localpart: String,
    pub display_name: Option<String>,
    /// Free-form short description for directory rendering. Updated via
    /// `POST /_cokret/self/account/profile` (operationId
    /// `ck.self.account.command.update_profile`); rendered by `demo_actors` in directory
    /// search results.
    pub bio: Option<String>,
    /// HTTPS URL pointing at the actor's avatar image. Server holds the
    /// link verbatim — no transcoding or caching.
    pub avatar_url: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

impl AccountRecord {
    /// `@<localpart>` form used by the product API, audit log and
    /// directory projections.
    pub fn handle(&self) -> String {
        format!("@{}", self.localpart)
    }
}

#[derive(Clone, Debug)]
pub struct AccountLifecycleRecord {
    pub state: String,
    pub reason: Option<String>,
    pub changed_by: Option<String>,
    pub changed_at: chrono::DateTime<chrono::Utc>,
}

/// REC-1 (R3 spec-sync 2026-05-27, cokret-spec b47ff6ec) — accepted
/// recovery policy snapshot persisted by `RecoveryPolicyStore`.
///
/// Spec: `cokret-spec/spec/v1/artifacts/schemas/recovery-policy.schema.json`.
#[derive(Clone, Debug)]
pub struct RecoveryPolicyRecord {
    pub policy_id: String,
    pub principal_id: String,
    pub version: u32,
    pub trust_domain: String,
    pub allowed_proof_kinds: Vec<String>,
    pub supersedes: Option<String>,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    pub issued_at: chrono::DateTime<chrono::Utc>,
    pub raw_payload: Value,
    pub accepted_at: chrono::DateTime<chrono::Utc>,
    /// Verification-method DID URL of the issuer. The full proof
    /// verification (signature + signed_fields enforcement) is flagged
    /// `TODO(R4): wire principal signing-key resolver + signature
    /// validation through DidResolver chain`.
    pub verification_method: String,
}

/// REC-1 — accepted recovery receipt snapshot.
///
/// Spec: `cokret-spec/spec/v1/artifacts/schemas/recovery-receipt.schema.json`.
#[derive(Clone, Debug)]
pub struct RecoveryReceiptRecord {
    pub receipt_id: String,
    pub principal_id: String,
    pub recovery_session_id: String,
    pub policy_id: String,
    pub policy_version: u32,
    pub trust_domain: String,
    pub new_device_id: String,
    pub proof_digest: String,
    pub outcome: String,
    pub started_at: chrono::DateTime<chrono::Utc>,
    pub completed_at: chrono::DateTime<chrono::Utc>,
    pub raw_payload: Value,
    pub verification_method: String,
    pub accepted_at: chrono::DateTime<chrono::Utc>,
}

/// C-P2 (REC-1) — recovery session lifecycle record.
///
/// A session binds a requesting device to the principal's active recovery
/// policy snapshot + a server challenge, and transitions
/// `pending -> verified -> completed` (or `rejected` / `expired`). Proof
/// verification (C-P3) is what advances `pending -> verified`; completion
/// (C-P4) emits a `ck.device.authorize` + receipt.
#[derive(Clone, Debug)]
pub struct RecoverySessionRecord {
    pub recovery_session_id: String,
    pub principal_id: String,
    pub requesting_device_id: String,
    pub trust_domain: String,
    pub policy_id: String,
    pub policy_version: u32,
    /// Accepted cross-signing generation snapshotted at session creation. The
    /// recovery proof transcript binds it, and completion (C-P4) MUST reject if
    /// the current accepted generation no longer equals this value
    /// (`device_recovery_ssk_generation_mismatch`). Spec: device-lifecycle.md §15.
    pub ssk_generation: u32,
    /// Snapshot of the active policy at session-creation time (so a later policy
    /// rotation cannot retroactively change what this session was bound to).
    pub policy_payload: Value,
    /// Server-issued anti-replay challenge the proof transcript MUST bind.
    pub challenge: String,
    /// `pending` | `verified` | `completed` | `rejected` | `expired`.
    pub state: String,
    /// The submitted proof payload (recorded on `/proofs`; verified in C-P3).
    pub proof_payload: Option<Value>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

/// Per-actor failed-login bookkeeping. Spec: A.3 — five failures within
/// the active window flip the actor into a 15-minute lockout. The record
/// is cleared on any successful login.
#[derive(Clone, Debug)]
pub struct FailedLoginRecord {
    /// Number of failed attempts observed in the current window.
    pub attempts: u32,
    /// When the most recent failure was recorded. Drives the rolling
    /// window check: failures older than `ACCOUNT_LOCKOUT_WINDOW` reset
    /// the counter rather than locking the actor.
    pub last_failure_at: chrono::DateTime<chrono::Utc>,
    /// `Some(until)` if the actor is currently locked out — auth
    /// handlers return 403 `policy_denied` (lockout) until `Utc::now() >= until`.
    pub locked_until: Option<chrono::DateTime<chrono::Utc>>,
}

/// Threshold of consecutive failed auth attempts before the actor is
/// locked out. Spec: A.3.
pub const ACCOUNT_LOCKOUT_THRESHOLD: u32 = 5;
/// Lockout window — once the actor crosses [`ACCOUNT_LOCKOUT_THRESHOLD`]
/// they stay locked for this long. Spec: A.3.
pub const ACCOUNT_LOCKOUT_DURATION: chrono::Duration = chrono::Duration::minutes(15);
/// Rolling window over which failed attempts accumulate. Failures older
/// than this reset the counter rather than escalating to a lockout.
pub const ACCOUNT_LOCKOUT_WINDOW: chrono::Duration = chrono::Duration::minutes(15);

// --- SEC-09: PSI / contact-discovery timing side-channel defenses ---
// (consent-model.md §6.2: per-(requester, holder) rate limit + coarse hit
// bucket + holder-auditable probe record.)

/// Coarse time-bucket granularity (seconds) applied to PSI / contact-discovery
/// hit visibility. The `as_of` timestamp a requester observes for a match is
/// floored to this bucket so the precise moment a holder's reachability bit
/// flipped (grant/revoke) is not directly readable — mirrors presence
/// `last_active_at` bucketing. SEC-09.
pub const PSI_HIT_BUCKET_SECS: i64 = 900; // 15 minutes

/// Rolling window over which a single `(requester, holder)` pair's PSI probes
/// accumulate before the pair is rate-limited. SEC-09.
pub const PSI_PROBE_WINDOW: chrono::Duration = chrono::Duration::minutes(10);

/// Max PSI probes a single `(requester, holder)` pair MAY make within
/// [`PSI_PROBE_WINDOW`] before further probes are rate-limited. SEC-09.
pub const PSI_PROBE_MAX_PER_WINDOW: u32 = 20;

/// Spec `identity/key-management.md` §7.8 — default per-principal ceiling on
/// full-ciphertext key-backup downloads
/// (`GET /_cokret/self/keys/backups/{backup_id}`) within a rolling
/// [`KEY_BACKUP_DOWNLOAD_WINDOW`]. Encrypted backup ciphertext is offline
/// KDF-cracking ammunition; the quota covers a legitimate restore over a long
/// backup series while blocking bulk dumps. Deployments may adjust via
/// `SOLAND_KEY_BACKUP_DAILY_DOWNLOAD_LIMIT`, clamped to the spec-allowed
/// `[16, 256]` range ([`KEY_BACKUP_DAILY_DOWNLOAD_LIMIT_MIN`] /
/// [`KEY_BACKUP_DAILY_DOWNLOAD_LIMIT_MAX`]).
pub const KEY_BACKUP_DAILY_DOWNLOAD_LIMIT_DEFAULT: u32 = 64;

/// Spec §7.8 — lower bound of the deployment-adjustable download quota.
pub const KEY_BACKUP_DAILY_DOWNLOAD_LIMIT_MIN: u32 = 16;

/// Spec §7.8 — upper bound of the deployment-adjustable download quota.
pub const KEY_BACKUP_DAILY_DOWNLOAD_LIMIT_MAX: u32 = 256;

/// Rolling window over which a principal's key-backup ciphertext downloads
/// accumulate before further reads are rejected. Spec §7.8 phrases the limit
/// as "per principal per 24h".
pub const KEY_BACKUP_DOWNLOAD_WINDOW: chrono::Duration = chrono::Duration::hours(24);

pub(crate) fn key_backup_daily_download_limit() -> u32 {
    let configured = std::env::var("SOLAND_KEY_BACKUP_DAILY_DOWNLOAD_LIMIT")
        .ok()
        .and_then(|value| value.trim().parse::<u32>().ok());
    clamp_key_backup_daily_download_limit(configured)
}

pub(crate) fn clamp_key_backup_daily_download_limit(configured: Option<u32>) -> u32 {
    configured
        .map(|value| {
            value.clamp(
                KEY_BACKUP_DAILY_DOWNLOAD_LIMIT_MIN,
                KEY_BACKUP_DAILY_DOWNLOAD_LIMIT_MAX,
            )
        })
        .unwrap_or(KEY_BACKUP_DAILY_DOWNLOAD_LIMIT_DEFAULT)
}

/// A revoked cursor authority recorded by `ck.self.account.command.revoke_cursor`.
///
/// `scope` mirrors the wire enum: `this_cursor` matches the exact cursor by
/// `cursor_digest`; `same_device` / `same_session` match any cursor that
/// resolves to the same authenticated `(principal_id, device_id)` binding —
/// soland's stateful cursor binds principal + device (not a finer session
/// handle), so `same_session` is enforced at the same `(principal, device)`
/// granularity as `same_device`. Entries are dropped once `expires_at` passes
/// (the revoked cursor's maximum possible TTL).
#[derive(Clone, Debug)]
pub struct CursorRevocation {
    /// sha256 hex of the exact revoked `ck:cursor:` token (used by `this_cursor`).
    pub cursor_digest: String,
    /// Authenticated principal that requested the revocation.
    pub principal_id: String,
    /// Bound device for `same_device` / `same_session` scope (the caller's
    /// session device); `None` for `this_cursor`.
    pub device_id: Option<String>,
    /// `this_cursor` | `same_device` | `same_session`.
    pub scope: String,
    /// Client-supplied revocation reason (audited).
    pub reason_code: String,
    pub revoked_at: chrono::DateTime<chrono::Utc>,
    /// GC horizon — the entry may be pruned after this instant.
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

/// Per-`(requester, holder)` PSI probe counter (SEC-09). Drives the rolling
/// rate-limit window that blunts high-frequency hit-bit timing probes.
#[derive(Clone, Debug)]
pub struct PsiProbeRecord {
    /// Probes observed in the current window.
    pub count: u32,
    /// Start of the current rolling window.
    pub window_started_at: chrono::DateTime<chrono::Utc>,
    /// Timestamp of the most recent probe.
    pub last_probe_at: chrono::DateTime<chrono::Utc>,
}

/// Result of recording a PSI probe against the `(requester, holder)` limiter.
#[derive(Clone, Debug)]
pub struct PsiProbeOutcome {
    /// `true` once this pair exceeds [`PSI_PROBE_MAX_PER_WINDOW`] in the
    /// current window; callers MUST then withhold a fresh match result and
    /// surface `retry_after_ms`.
    pub rate_limited: bool,
    /// Probe count in the current window (post-increment).
    pub count: u32,
    /// Suggested client backoff when `rate_limited` is set.
    pub retry_after_ms: i64,
}

/// Per-principal key-backup ciphertext download counter
/// (spec `identity/key-management.md` §7.8). Drives the rolling 24h
/// anti-bulk-dump quota on `GET /_cokret/self/keys/backups/{backup_id}`.
#[derive(Clone, Debug)]
pub struct KeyBackupDownloadRecord {
    /// Full-envelope downloads observed in the current window.
    pub count: u32,
    /// Start of the current rolling window.
    pub window_started_at: chrono::DateTime<chrono::Utc>,
    /// Timestamp of the most recent download attempt.
    pub last_download_at: chrono::DateTime<chrono::Utc>,
}

/// Result of recording a key-backup ciphertext download against the
/// per-principal §7.8 quota.
#[derive(Clone, Debug)]
pub struct KeyBackupDownloadOutcome {
    /// `true` once the principal exceeds the effective daily limit in the
    /// current window; callers MUST then withhold the ciphertext, return
    /// `429`, and write the §7.8 `key_backup_read` audit entry.
    pub rate_limited: bool,
    /// Download count in the current window (post-increment).
    pub count: u32,
    /// Suggested client backoff when `rate_limited` is set.
    pub retry_after_ms: i64,
}

/// Upper bound for the canonical JSON bytes of a moderation evidence package.
/// This is intentionally separate from the HTTP request-size guard because the
/// report body can carry other metadata; the evidence blob itself must have a
/// protocol-level ceiling.
pub const MODERATION_REPORT_EVIDENCE_MAX_TOTAL_BLOB_BYTES: usize = 64 * 1024;
/// Rolling window for moderation report entrypoint quota buckets.
pub const MODERATION_REPORT_RATE_WINDOW_SECS: i64 = 10 * 60;
/// Per-reporter reports admitted in one moderation window.
pub const MODERATION_REPORT_MAX_PER_REPORTER_WINDOW: u32 = 20;
/// Per-source-service reports admitted in one moderation window.
pub const MODERATION_REPORT_MAX_PER_SOURCE_SERVICE_WINDOW: u32 = 80;
/// Per-reporter-per-Realm reports admitted in one moderation window.
pub const MODERATION_REPORT_MAX_PER_REPORTER_REALM_WINDOW: u32 = 10;
/// Per-source-IP reports admitted in one moderation window.
pub const MODERATION_REPORT_MAX_PER_SOURCE_IP_WINDOW: u32 = 80;
/// Duplicate reports for the same target by the same reporter in one window.
pub const MODERATION_REPORT_MAX_PER_REPORTER_TARGET_WINDOW: u32 = 1;
/// Bounded franking replay nonce retention horizon.
pub const MODERATION_FRANKING_REPLAY_WINDOW_SECS: i64 = 24 * 60 * 60;
/// Bounded franking replay nonce ledger size.
pub const MODERATION_FRANKING_REPLAY_MAX_ENTRIES: usize = 4096;

/// Rolling counter for moderation report anti-abuse buckets.
#[derive(Clone, Debug)]
pub struct ModerationReportRateRecord {
    pub count: u32,
    pub window_started_at: chrono::DateTime<chrono::Utc>,
    pub last_report_at: chrono::DateTime<chrono::Utc>,
}

/// Result of recording one moderation report attempt across all quota buckets.
#[derive(Clone, Debug)]
pub struct ModerationReportRateOutcome {
    pub rate_limited: bool,
    pub bucket: Option<String>,
    pub count: u32,
    pub limit: u32,
    pub retry_after_ms: i64,
}

/// Bounded anti-replay ledger row for `franking_proof.replay_nonce`.
#[derive(Clone, Debug)]
pub struct ModerationFrankingReplayRecord {
    pub first_seen_at: chrono::DateTime<chrono::Utc>,
    pub last_seen_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone, Debug)]
pub struct WebvhDocumentRecord {
    pub did: String,
    pub did_document: Value,
    pub key_log_head: Option<String>,
    pub seq: u64,
    pub method_evidence: Value,
    /// Time this record was ingested by this node. High-risk verification
    /// paths compare `age = now - fetched_at` with the caller-provided
    /// `max_age` via `verify_did_document_freshness`. Writes are ingestion:
    /// `put_document` stamps this field with "now", so persisted records
    /// always carry freshness evidence.
    pub fetched_at: chrono::DateTime<chrono::Utc>,
    /// High-risk baseline expiry hint, usually `fetched_at + high-risk
    /// baseline TTL` (15 minutes). This is only a storage and cleanup-index
    /// hint per §3.4; actual freshness uses `age vs max_age`. Degraded
    /// read-only paths may use a larger `max_age` (24h) and mark records that
    /// have passed `expires_at`.
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone, Debug)]
pub struct WebvhLogRecord {
    pub event_digest: String,
    pub did: String,
    pub seq: u64,
    pub operation: Value,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone, Debug)]
pub struct ContactRecord {
    pub requester: String,
    pub target: String,
    pub scope: String,
    pub status: String,
    pub request_event_ref: Option<String>,
    pub response_event_ref: Option<String>,
    pub tombstone_event_ref: Option<String>,
    /// Optional free-text greeting carried on `ck.contact.requested`
    /// (spec 0015 §3.4). NFC-normalized, 1..2000 chars. `None` when the
    /// request carried no message or the row originated from a consent
    /// grant rather than an explicit request.
    pub message: Option<String>,
    /// Service DID of the Principal Server hosting the contact's *peer* end,
    /// when learned from a cross-Principal-Server contact delivery
    /// (`ck.peer.contacts.command.submit`, `source-service-did` header). `None` for
    /// same-Principal-Server contacts. In-memory projection only — surfaced on
    /// `contact_list_row.peer_service_did` so the holder can address
    /// responses/invites back to the peer's home server.
    pub peer_service_did: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ConsentCellKey {
    pub holder: String,
    pub peer: String,
    pub scope: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConsentGrantDot {
    pub dot: String,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    pub granted_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConsentCellRecord {
    pub holder: String,
    pub peer: String,
    pub scope: String,
    pub cell_id: String,
    pub requested_at: Option<chrono::DateTime<chrono::Utc>>,
    pub grant_dots: BTreeMap<String, ConsentGrantDot>,
    pub revoked_dots: BTreeSet<String>,
    pub revoked_at: Option<chrono::DateTime<chrono::Utc>>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone, Debug)]
pub struct DirectConversationBindingRecord {
    pub participants_unordered: Vec<String>,
    pub realm_id: String,
    pub main_strand_id: String,
    pub binding_event_ref: String,
    pub state: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

/// Actor-private account data row (`ck.account_data.set` storage).
///
/// One row per `(actor, data_type)`. `data_type` is the canonical wire key
/// (e.g. `ck.read_receipt.preferences`, `ck.contacts.actor.did:web:alice.example`,
/// `ck.contacts.realm.ck:realm:0196419b-0000-7000-8000-000000000000`). Soland
/// treats the `payload` as an opaque encrypted blob — no schema validation
/// happens server-side; clients are responsible for canonical encoding.
///
/// Spec: `discovery/client-preferences.md` §2 (storage model) and §3.7
/// (Realm remarks, `ck.contacts.realm.<realm_id>`).
#[derive(Clone, Debug)]
pub struct AccountDataRecord {
    pub actor: String,
    pub data_type: String,
    pub payload: Value,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone, Debug)]
pub struct RealmInviteRecord {
    pub invite_id: String,
    pub realm_id: String,
    pub inviter: String,
    pub invitee: Option<String>,
    pub invite_delivery_target: Option<Value>,
    pub introduction_evidence_digest: Option<String>,
    pub third_party_id: Option<Value>,
    pub join_rule_snapshot: Option<Value>,
    pub invite_token: String,
    pub status: String,
    pub claim_nonces: BTreeMap<String, String>,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Clone, Debug)]
pub struct RealmMetaRecord {
    pub owner: String,
    pub deleted: bool,
    pub discoverability: String,
    /// One of `world_readable` / `shared` / `invited` / `joined` /
    /// `restricted`. `restricted` is fail-closed unless
    /// `history_sharing_policy` has an explicit matching rule.
    pub history_visibility: String,
    /// Effective `ck.realm.history_sharing_policy.value` plus its canonical
    /// digest. The policy gates E2EE history key shares and restricted history
    /// reads; history visibility alone never grants old epoch keys.
    pub history_sharing_policy: Option<Value>,
    pub history_sharing_policy_digest: Option<String>,
    /// Effective `ck.realm.preview_policy.value` plus its canonical digest.
    /// Directory/object preview must fail closed when this is missing.
    pub preview_policy: Option<Value>,
    pub preview_policy_digest: Option<String>,
    /// Effective `ck.realm.asset_privacy_policy.value` plus its canonical
    /// digest. Blob presign/download re-checks this at response time.
    pub asset_privacy_policy: Option<Value>,
    pub asset_privacy_policy_digest: Option<String>,
    /// Optional encryption profile (`mls_rfc9420` / `plaintext`). Cross-checked
    /// against `history_visibility` at create time — `mls_rfc9420` is
    /// incompatible with `world_readable` (realm-and-space.md §3.1.3).
    pub encryption_profile: Option<String>,
    pub plaintext_visible_services: BTreeSet<String>,
    pub plaintext_visible_service_classes: BTreeMap<String, BTreeSet<PlaintextDataClassKind>>,
    /// SEC-08 — the Realm declared `ck.profile.mls.minimal_metadata_realm.v1`
    /// (`crypto-media/encryption-and-audit.md` §2.9). Projected from the
    /// `profiles[]` / `active_profiles[]` declaration on a `ck.realm.create` /
    /// `ck.realm.policy_components` operation. Once observed it latches true:
    /// soland is not the committer and never relaxes a minimal-metadata Realm
    /// back to a wider profile on its own. Drives the server-side
    /// defence-in-depth reject of non-`hidden` `aad_visibility_event_id` on
    /// encrypted `ck.message.create` / reaction envelopes.
    pub minimal_metadata_realm: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

impl RealmMetaRecord {
    pub fn allows_plaintext_data_class(
        &self,
        service_did: &str,
        data_class: PlaintextDataClassKind,
    ) -> bool {
        self.plaintext_visible_service_classes
            .get(service_did)
            .is_some_and(|classes| classes.contains(&data_class))
    }

    pub fn allows_any_plaintext_data_class(&self, service_did: &str) -> bool {
        self.plaintext_visible_service_classes
            .get(service_did)
            .is_some_and(|classes| !classes.is_empty())
    }
}

#[derive(Clone, Debug)]
pub struct MessageRecord {
    pub event_id: String,
    pub message_id: String,
    pub realm_id: String,
    pub sender: String,
    pub thread_id: String,
    pub content: Value,
    pub encrypted: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone, Debug)]
pub struct CanonicalEventRecord {
    pub event_id: String,
    pub actor_id: String,
    pub actor_seq: u64,
    pub realm_id: Option<String>,
    pub kind: String,
    pub schema_id: String,
    pub canonical_digest: String,
    pub canonical_bytes: Vec<u8>,
    pub envelope: Value,
    pub received_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone, Debug)]
pub struct ProjectionEventRecord {
    pub event_id: String,
    pub realm_id: String,
    /// Canonical Cokret event kind (e.g. `ck.message.create`).
    pub event_kind: String,
    pub operation_type: String,
    pub operation_id: Option<String>,
    pub sender: Option<String>,
    pub payload: Value,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone, Debug)]
pub struct DeviceMessageRecord {
    pub idempotency_key: String,
    pub sender: String,
    pub recipient: String,
    pub device_id: String,
    pub position: i64,
    pub content: Value,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone, Debug)]
pub struct BlobRecord {
    pub sha256: String,
    pub size_bytes: i64,
    pub storage_backend: String,
    pub storage_key: String,
    pub media_type: String,
    pub filename: Option<String>,
    pub realm_id: Option<String>,
    pub encryption: Option<Value>,
    pub legal_hold: bool,
    pub redacted: bool,
    pub visibility: BlobVisibility,
    pub uploaded_by: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone, Debug)]
pub struct FederationTransactionRecord {
    pub origin: String,
    pub txn_id: String,
    pub destination: String,
    pub realm_id: Option<String>,
    pub content_digest: String,
    pub origin_verification_method: Option<String>,
    pub service_binding_ref: Option<String>,
    pub origin_key_state_digest: Option<String>,
    pub local_peer_policy_digest: Option<String>,
    pub status: String,
    pub response: Value,
    pub received_at: chrono::DateTime<chrono::Utc>,
    pub processed_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// G3.S0 — one outbound federation HTTP POST queued for the
/// `FederationDispatcher` background worker. See
/// `routing/federation/outbox.rs` for the worker loop and
/// the `federation_outbox` table in `migrations/00000000000000_initial/up.sql`
/// for the durable schema.
///
/// Timestamps are stored as unix-seconds (`i64`) to match the SQLite-style
/// schema defined in the spec subset; the Pg-backed store maps them to
/// `BIGINT`. The reason we don't use `TIMESTAMPTZ` here is so the SDK +
/// in-memory backend share the exact same numeric encoding the wire
/// receipts (`Idempotency-Key`, dispatcher logs) compare against.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FederationOutboxRecord {
    /// ULID/UUID — primary key.
    pub id: String,
    /// Peer service DID from the `base_url|service_did` federation peer entry.
    pub peer_did: String,
    /// Fully-qualified peer base URL (no trailing slash) the dispatcher
    /// concatenates with `endpoint` to form the POST target.
    pub peer_url: String,
    /// Endpoint path on the peer, e.g. `/_cokret/peer/events`.
    pub endpoint: String,
    /// `Idempotency-Key` header value the dispatcher sends. Derived
    /// deterministically from `(origin, resource_kind, resource_id)` so
    /// retries collapse onto the same row server-side per
    /// `federation.md` §8.5.
    pub idempotency_key: String,
    /// Canonical request body the dispatcher POSTs verbatim.
    pub payload_json: String,
    /// Number of completed delivery attempts (excluding the next one).
    pub attempts: i32,
    /// Unix seconds — earliest time the worker may pick this row.
    pub next_attempt_at: i64,
    /// Last observed HTTP status code, or `-1` after the worker gave up
    /// (attempts cap reached on retryable error). `None` until the first
    /// attempt completes.
    pub last_status: Option<i32>,
    /// First ~1 KiB of the most recent response body, for postmortem.
    pub last_response_excerpt: Option<String>,
    /// Unix seconds — when the row was enqueued.
    pub created_at: i64,
    /// Unix seconds — when delivery terminated (2xx success, permanent
    /// 4xx failure, or the gave-up sentinel). `None` while the row is
    /// still pending.
    pub delivered_at: Option<i64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FederationOutboxDeadLetterRecord {
    pub id: String,
    pub outbox_id: String,
    pub peer_did: String,
    pub endpoint: String,
    pub idempotency_key: String,
    pub terminal_status: i32,
    pub attempts: i32,
    pub response_excerpt: Option<String>,
    pub failed_at: i64,
    pub reason: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FederationFrontierExchangeRecord {
    pub realm_id: String,
    pub peer_service_did: String,
    pub status: String,
    pub consecutive_failures: i32,
    pub last_success_at: Option<i64>,
    pub last_failure_at: Option<i64>,
    pub last_frontier_root: Option<String>,
    pub last_error: Option<String>,
    pub updated_at: i64,
}

#[derive(Clone, Debug)]
pub struct PresenceRecord {
    pub actor: String,
    pub status: String,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone, Debug)]
pub struct TypingRecord {
    pub actor: String,
    pub realm_id: String,
    pub scope_id: Option<String>,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

/// Relayed `ck.call.signal` envelope for realm-broadcast ephemeral delivery
/// (`webrtc-signaling.md` §5). The full signed envelope is stored verbatim so
/// the receiver can verify `proof` over the canonical bytes.
#[derive(Clone, Debug, Default)]
pub struct CallSignalRelayRecord {
    pub realm_id: String,
    pub sender_actor: String,
    pub sender_device: String,
    pub call_id: String,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub envelope: serde_json::Value,
    /// Monotonic per-Realm position assigned by `CallSignalRelayStore::append`.
    /// Drives per-subscriber-device deliver-once: a subscriber's watermark
    /// records the highest `position` already delivered to that device, so an
    /// incremental re-subscribe inside the TTL window does not re-emit the same
    /// envelope. Producers leave this `0`; `append` overwrites it.
    pub position: u64,
}

/// Relayed `ck.receipt.read` payload for short-TTL read receipt delivery.
/// The normalized `receipt` value is the wire object emitted to subscribers;
/// relay metadata drives visibility and deliver-once behavior.
#[derive(Clone, Debug, Default)]
pub struct ReadReceiptRelayRecord {
    pub realm_id: String,
    pub actor_id: String,
    pub sender_device: Option<String>,
    pub event_id: String,
    pub read_scope: serde_json::Value,
    pub target_actor: Option<String>,
    pub visibility: String,
    pub receipt: serde_json::Value,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    /// Monotonic per-Realm position assigned by `ReadReceiptRelayStore::append`.
    pub position: u64,
}

#[derive(Clone, Debug)]
pub struct PushRuleRecord {
    pub actor: String,
    pub rule_id: String,
    pub enabled: bool,
    pub actions: Vec<String>,
    pub conditions: Value,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone, Debug)]
pub struct OutboundPushBridgeCacheRecord {
    pub push_gateway_url: String,
    pub service_base_url: String,
    pub bridge_describe_url: String,
    pub fetch_state: String,
    pub cache_state: String,
    pub contract_digest: String,
    pub fetched_at: chrono::DateTime<chrono::Utc>,
    pub remote_contract: Value,
    /// Explicit trust state for the cached snapshot. This introduces
    /// `pending` / `trusted` / `revoked` so `verify_contract_freshness` can
    /// fail-closed when a snapshot has not yet been promoted to trusted.
    pub trust_level: String,
    /// Last time we affirmatively re-checked the upstream contract; bumped
    /// independently from `fetched_at` so freshness/age policy can reject
    /// snapshots that haven't been re-verified within `max_age`.
    pub freshness_at: chrono::DateTime<chrono::Utc>,
    /// Opaque server-issued ETag from the upstream describe response.
    /// Compared alongside `contract_digest` so a same-digest-but-rotated
    /// etag still trips drift fail-closed.
    pub etag: String,
}

/// One row of the persistent multisig coordinator buffer.
///
/// Holds an in-flight pending Seal that is awaiting threshold partial
/// signatures. The `partials` map is keyed by signer DID → submitted partial
/// payload (`{signature_b64, kid, submitted_at}`). When the number of
/// partials reaches `threshold_k`, the leader aggregates them via SDK
/// `ThresholdAggregator` and publishes the final threshold-signed Seal,
/// then deletes the row.
#[derive(Clone, Debug)]
pub struct MultisigPendingRecord {
    pub seal_id: String,
    pub realm_id: String,
    pub threshold_k: u32,
    pub threshold_n: u32,
    pub members: Vec<String>,
    /// Canonical bytes (base64) the partial signatures sign over. Empty when
    /// the buffer was created without an explicit canonical body (smoke
    /// tests). Real partial-signature aggregation requires this to be
    /// non-empty.
    pub canonical_b64: String,
    /// `signer_did` -> JSON `{signature_b64, kid, submitted_at}`.
    pub partials: BTreeMap<String, Value>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    /// Node id of the watchdog instance currently leasing this row, or
    /// `None` when unclaimed. The lease is valid until
    /// [`MultisigPendingRecord::claimed_until`].
    pub claimed_by_node_id: Option<String>,
    /// Lease expiry timestamp. A row is "claimable" when this is `None` or
    /// in the past.
    pub claimed_until: Option<chrono::DateTime<chrono::Utc>>,
    /// Partition-tolerant fencing token. Every successful
    /// `try_claim` bumps this counter; a stale leader (whose lease was
    /// silently superseded after a network partition healed) carries the
    /// pre-bump value so its post-aggregate `delete_with_fence` /
    /// `renew_claim` is rejected at the row level. Monotonic across the
    /// row's lifetime.
    pub claim_seq: i64,
}

#[derive(Clone, Debug)]
pub struct PolicyDocumentRecord {
    pub policy_id: String,
    pub owner: String,
    pub scope: String,
    pub subject_ref: String,
    pub policy_type: String,
    pub payload: Value,
    pub active: bool,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone, Debug)]
pub struct OrganizationRecord {
    pub organization_id: String,
    pub organization_did: String,
    pub handle: Option<String>,
    pub display_name: String,
    pub verified: bool,
    pub members: BTreeSet<String>,
    pub member_count: usize,
    pub created_by: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone, Debug)]
pub struct OrganizationPolicyRecord {
    pub organization_id: String,
    pub policy_id: String,
    pub payload: Value,
    pub version: u64,
    pub updated_by: String,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone, Debug)]
pub struct RealmModerationPolicyRecord {
    pub realm_id: String,
    pub payload: Value,
    pub updated_by: String,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone, Debug, Default)]
pub struct SovereignDeploymentState {
    pub profile_override: Option<String>,
    pub upstream_main: Option<String>,
    pub trust_roots: Vec<String>,
    pub allow_external_via_enclave: bool,
    pub trusted_enclaves: BTreeMap<String, SovereignEnclaveRecord>,
    pub enclave_realms: BTreeMap<String, SovereignRealmRecord>,
    pub external_invites: BTreeMap<String, SovereignExternalInviteRecord>,
    pub external_accounts: BTreeMap<String, SovereignExternalAccountRecord>,
    pub audit_log: Vec<SovereignAuditRecord>,
    pub upstream_available: bool,
    pub store_forward_queue: Vec<SovereignStoreForwardRecord>,
    pub received_store_forward: Vec<SovereignStoreForwardRecord>,
}

#[derive(Clone, Debug)]
pub struct SovereignEnclaveRecord {
    pub server_id: String,
    pub base_url: String,
    pub trust_chain: Vec<String>,
    pub registered_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone, Debug)]
pub struct SovereignRealmRecord {
    pub realm_id: String,
    pub deployment_profile: String,
    pub hosted_on: String,
    pub external_invite_policy: String,
    pub created_by: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub enclave_frontier: i64,
    pub main_frontier: i64,
}

#[derive(Clone, Debug)]
pub struct SovereignExternalInviteRecord {
    pub invite_token: String,
    pub target_realm: String,
    pub target_host: String,
    pub invitee: String,
    pub inviter: String,
    pub accepted: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone, Debug)]
pub struct SovereignExternalAccountRecord {
    pub did: String,
    pub realm_id: String,
    pub bound_node: String,
    pub trust_chain_profile: String,
    pub active: bool,
    pub joined_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone, Debug)]
pub struct SovereignAuditRecord {
    pub subject: String,
    pub action: String,
    pub realm_id: Option<String>,
    pub status: String,
    pub detail: Value,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone, Debug)]
pub struct SovereignStoreForwardRecord {
    pub id: String,
    pub realm_id: String,
    pub actor: String,
    pub content: Value,
    pub state: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub forwarded_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Clone, Debug)]
pub struct RetentionPolicyRecord {
    pub realm_id: String,
    pub ttl_seconds: i64,
    pub updated_by: String,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone, Debug)]
pub struct RetentionTombstoneRecord {
    pub event_id: String,
    pub realm_id: String,
    pub reason: String,
    pub policy_ttl_seconds: i64,
    pub expired_at: chrono::DateTime<chrono::Utc>,
    pub tombstoned_at: chrono::DateTime<chrono::Utc>,
    pub sealed: bool,
}
