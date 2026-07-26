use std::collections::{BTreeMap, BTreeSet};

use arkret_identifiers::{BlobRef, Hash};
use arkret_models_collaboration::objects::blob::BlobVisibility;
use arkret_models_crypto::{DeviceGenerationStatus, RecoveryIdentityModel};
use arkret_wire::{FreshnessState, NonEmptyString, PlaintextDataClassKind, SealBasis};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AgentSessionRecord {
    pub granted_scope: Vec<String>,
    pub scope_details: Value,
    pub freshness_state: FreshnessState,
}

#[derive(Clone, Debug)]
pub struct SessionRecord {
    pub token_hash: String,
    pub actor: String,
    pub device_id: String,
    pub audience: String,
    /// Session signing key (JWK) bound by `ak.session.grant`, used to verify
    /// RFC 9421 PoP presentations on `/_arkret/self/*` (api-conventions.md
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
    /// Surrogate row primary key (`ak:account:<uuid7>`), minted by
    /// The composition root mints this identifier at account creation. Stable
    /// internal handle decoupled from the `principal_id` DID (which may rotate).
    pub id: String,
    /// The account's protocol identity DID (DB column `principal_id`).
    pub did: String,
    /// Primary bare handle localpart (`alice` — never `@alice` or
    /// `alice:domain`). This is derived from `account_localparts`, not stored
    /// on the account row. Wire/display surfaces use [`AccountRecord::handle`]
    /// for the `@`-prefixed form.
    pub localpart: String,
    pub display_name: Option<String>,
    /// Free-form short description for directory rendering. Updated via
    /// `POST /_arkret/self/account/profile` (operationId
    /// `ak.self.account.command.update_profile`); rendered by `demo_actors` in directory
    /// search results.
    pub bio: Option<String>,
    /// Canonical content-addressed avatar Blob reference.
    pub avatar_blob_ref: Option<BlobRef>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

impl AccountRecord {
    /// `@<localpart>` form used by the product API, audit log and
    /// directory projections.
    pub fn handle(&self) -> String {
        if self.localpart.is_empty() {
            String::new()
        } else {
            format!("@{}", self.localpart)
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountLocalpartRecord {
    pub id: String,
    pub account_did: String,
    pub localpart: String,
    pub is_primary: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone, Debug)]
pub struct AccountLifecycleRecord {
    pub state: String,
    pub reason: Option<String>,
    pub changed_by: Option<String>,
    pub changed_at: chrono::DateTime<chrono::Utc>,
}

/// REC-1 (R3 spec-sync 2026-05-27, arkret-spec b47ff6ec) — accepted
/// recovery policy snapshot persisted by `RecoveryPolicyStore`.
///
/// Spec: `arkret-spec/spec/v1/artifacts/schemas/recovery-policy.schema.json`.
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
/// Spec: `arkret-spec/spec/v1/artifacts/schemas/recovery-receipt.schema.json`.
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
/// (C-P4) emits a `ak.device.authorize` + receipt.
#[derive(Clone, Debug)]
pub struct RecoverySessionRecord {
    pub recovery_session_id: String,
    pub principal_id: String,
    pub requesting_device_id: String,
    pub trust_domain: String,
    pub policy_id: String,
    pub policy_version: u32,
    pub identity_model: RecoveryIdentityModel,
    pub ssk_generation: Option<u64>,
    pub current_device_generation_ref: Option<NonEmptyString>,
    pub device_generation_status: Option<DeviceGenerationStatus>,
    pub registry_head: Option<Hash>,
    pub accepted_seal_frontier: Option<SealBasis>,
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

/// A revoked cursor authority recorded by `ak.self.account.command.revoke_cursor`.
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
    /// sha256 hex of the exact revoked `ak:cursor:` token (used by `this_cursor`).
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

/// Actor-private account data row (`ak.account_data.set` storage).
///
/// One row per `(actor, data_type)`. `data_type` is the canonical wire key
/// (e.g. `ak.read_receipt.preferences`, `ak.contacts.actor.did:web:alice.example`,
/// `ak.contacts.realm.ak:realm:0196419b-0000-7000-8000-000000000000`). Soland
/// treats the `payload` as an opaque encrypted blob — no schema validation
/// happens server-side; clients are responsible for canonical encoding.
///
/// Spec: `discovery/client-preferences.md` §2 (storage model) and §3.7
/// (Realm remarks, `ak.contacts.realm.<realm_id>`).
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
    /// Effective `ak.realm.history_sharing_policy.value` plus its canonical
    /// digest. The policy gates E2EE history key shares and restricted history
    /// reads; history visibility alone never grants old epoch keys.
    pub history_sharing_policy: Option<Value>,
    pub history_sharing_policy_digest: Option<String>,
    /// Effective `ak.realm.preview_policy.value` plus its canonical digest.
    /// Directory/object preview must fail closed when this is missing.
    pub preview_policy: Option<Value>,
    pub preview_policy_digest: Option<String>,
    /// Effective `ak.realm.asset_privacy_policy.value` plus its canonical
    /// digest. Blob presign/download re-checks this at response time.
    pub asset_privacy_policy: Option<Value>,
    pub asset_privacy_policy_digest: Option<String>,
    /// Optional encryption profile (`mls_rfc9420` / `plaintext`). Cross-checked
    /// against `history_visibility` at create time — `mls_rfc9420` is
    /// incompatible with `world_readable` (realm-and-space.md §3.1.3).
    pub encryption_profile: Option<String>,
    pub plaintext_visible_services: BTreeSet<String>,
    pub plaintext_visible_service_classes: BTreeMap<String, BTreeSet<PlaintextDataClassKind>>,
    /// SEC-08 — the Realm declared `ak.profile.mls.minimal_metadata_realm.v1`
    /// (`crypto-media/encryption-and-audit.md` §2.9). Projected from the
    /// `profiles[]` / `active_profiles[]` declaration on a `ak.realm.create` /
    /// `ak.realm.policy_components` operation. Once observed it latches true:
    /// soland is not the committer and never relaxes a minimal-metadata Realm
    /// back to a wider profile on its own. Drives the server-side
    /// defence-in-depth reject of non-`hidden` `aad_visibility_event_id` on
    /// encrypted `ak.message.create` / reaction envelopes.
    pub minimal_metadata_realm: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

impl RealmMetaRecord {
    pub fn allows_plaintext_data_class(
        &self,
        service_id: &str,
        data_class: PlaintextDataClassKind,
    ) -> bool {
        self.plaintext_visible_service_classes
            .get(service_id)
            .is_some_and(|classes| classes.contains(&data_class))
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
    /// Canonical Arkret event kind (e.g. `ak.message.create`).
    pub event_kind: String,
    pub operation_type: String,
    pub operation_id: Option<String>,
    pub sender: Option<String>,
    pub payload: Value,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub received_at: chrono::DateTime<chrono::Utc>,
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
pub struct DeviceMessageIntentRecord {
    pub message_key: String,
    pub intent_digest: String,
}

#[derive(Clone, Debug)]
pub struct DeviceMessageBatchItemRecord {
    pub message_key: String,
    pub intent_digest: String,
    pub idempotency_expires_at: chrono::DateTime<chrono::Utc>,
    pub message: Option<DeviceMessageRecord>,
}

#[derive(Clone, Debug)]
pub struct DeviceMessageBatchRecord {
    pub request_key: String,
    pub request_digest: String,
    pub idempotency_expires_at: chrono::DateTime<chrono::Utc>,
    pub items: Vec<DeviceMessageBatchItemRecord>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum DeviceMessageBatchInspection {
    Fresh {
        existing_message_outcomes: BTreeMap<String, bool>,
    },
    Duplicate(BTreeMap<String, bool>),
    RequestConflict,
    MessageConflict {
        message_key: String,
    },
}

#[derive(Clone, Debug, PartialEq)]
pub enum DeviceMessageBatchCommitOutcome {
    Stored(BTreeMap<String, bool>),
    Duplicate(BTreeMap<String, bool>),
    RequestConflict,
    MessageConflict { message_key: String },
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
    /// Peer service DID discovered from the configured federation endpoint.
    pub peer_did: String,
    /// Fully-qualified peer base URL (no trailing slash) the dispatcher
    /// concatenates with `endpoint` to form the POST target.
    pub peer_url: String,
    /// Endpoint path on the peer, e.g. `/_arkret/peer/events`.
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
    pub peer_service_id: String,
    pub status: String,
    pub consecutive_failures: i32,
    pub last_success_at: Option<i64>,
    pub last_failure_at: Option<i64>,
    pub last_frontier_root: Option<String>,
    pub last_error: Option<String>,
    pub updated_at: i64,
}

/// Per-device presence broadcast admitted from `ak.presence`
/// (profiles-presence.md §3.3). One actor may have several device rows;
/// the projection aggregates them (`dnd > online > idle`, all expired →
/// `offline`) before anything reaches an observer.
#[derive(Clone, Debug)]
pub struct PresenceRecord {
    pub actor: String,
    /// Broadcasting device (proof-bound `device_id` of the envelope).
    pub device_id: String,
    /// Closed v1 wire state (`online` / `idle` / `dnd` / `offline`),
    /// validated at admission via `PresenceStatus::parse_wire`.
    pub status: String,
    /// Transient status-message override, validated at admission
    /// (≤256 code points, NFC, no control chars).
    pub status_message: Option<String>,
    /// Sender-supplied `last_active_at` wire value (bucket interval),
    /// validated fail-closed at admission and passed through verbatim.
    pub last_active_at: Option<String>,
    /// Envelope TTL; expired rows only contribute the stale-offline
    /// fallback to aggregation.
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    /// Original proof-bearing broadcast envelope delivered to subscribers.
    pub envelope: arkret_models_collaboration::events_payloads::ephemeral::EphemeralEnvelope,
}

#[derive(Clone, Debug)]
pub struct TypingRecord {
    pub actor: String,
    pub realm_id: String,
    pub scope_id: Option<String>,
    /// Strictly monotonic per-Realm revision assigned by `TypingStore::put`.
    /// Producer code leaves this at `0`; storage replaces it before the row
    /// becomes visible. TTL timestamps are lifecycle data, not ordering data.
    pub position: i64,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    /// Original proof-bearing broadcast envelope delivered to subscribers.
    pub envelope: arkret_models_collaboration::events_payloads::ephemeral::EphemeralEnvelope,
}

/// Relayed `ak.call.signal` envelope for realm-broadcast ephemeral delivery
/// (`webrtc-signaling.md` §5). The full signed envelope is stored verbatim so
/// the receiver can verify `proof` over the canonical bytes.
#[derive(Clone, Debug)]
pub struct CallSignalRelayRecord {
    pub realm_id: String,
    pub sender_actor: String,
    pub sender_device: String,
    pub call_id: String,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub envelope: arkret_models_collaboration::events_payloads::ephemeral::EphemeralEnvelope,
    /// Monotonic per-Realm position assigned by `CallSignalRelayStore::append`.
    /// Drives per-subscriber-device deliver-once: a subscriber's watermark
    /// records the highest `position` already delivered to that device, so an
    /// incremental re-subscribe inside the TTL window does not re-emit the same
    /// envelope. Producers leave this `0`; `append` overwrites it.
    pub position: u64,
}

/// Relayed `ak.receipt.read` payload for short-TTL read receipt delivery.
/// The normalized `receipt` value is the wire object emitted to subscribers;
/// relay metadata drives visibility and deliver-once behavior.
#[derive(Clone, Debug)]
pub struct ReadReceiptRelayRecord {
    pub realm_id: String,
    pub actor_id: String,
    pub sender_device: Option<String>,
    pub event_id: String,
    pub read_scope: serde_json::Value,
    pub target_actor: Option<String>,
    pub visibility: String,
    pub receipt: serde_json::Value,
    pub envelope: arkret_models_collaboration::events_payloads::ephemeral::EphemeralEnvelope,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    /// Monotonic per-Realm position assigned by `ReadReceiptRelayStore::append`.
    pub position: u64,
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
    pub source_refs: Vec<String>,
    pub policy_revision: String,
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

/// SOL-ORG-04 — durable row for one verified `ak.realm.organization`
/// relationship statement. Primary key `(realm_id, organization_id,
/// relationship)`. Field order mirrors the spec `realm_organization_payload`.
/// `control_scopes` is a JSON string array; the proof / delegation references
/// are stored as audit digests, never raw signature bytes.
#[derive(Clone, Debug)]
pub struct RealmOrganizationStatementRecord {
    pub realm_id: String,
    pub organization_id: String,
    /// snake_case relationship: `owner` / `governance` / `sponsor` /
    /// `directory_certifier`.
    pub relationship: String,
    pub statement_id: String,
    /// `active` or `revoked`.
    pub status: String,
    pub control_scopes: Vec<String>,
    pub issued_at: chrono::DateTime<chrono::Utc>,
    pub not_before: Option<chrono::DateTime<chrono::Utc>>,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    pub supersedes_statement_id: Option<String>,
    pub revokes_statement_id: Option<String>,
    pub realm_frontier_digest: Option<String>,
    pub proof_digest: Option<String>,
    pub delegation_ref: Option<String>,
    pub issuer_role: String,
    pub updated_at: chrono::DateTime<chrono::Utc>,
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
