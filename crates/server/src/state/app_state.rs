use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};

use arc_swap::ArcSwap;
use arkret_sdk::state::{CellRegistry, CellStore, MoveStore, SealStore};
use arkret_sdk::{
    AccountRegistrationPolicy, AccountStatus, AppletPackage, CanonicalServiceUrl, Did,
    LocalServiceIdentity, RealmId, ServiceIdentityKeyRef, ServiceIdentityState,
    ServiceRegistrationKey, ServiceType,
};
use ed25519_dalek::{SigningKey, VerifyingKey};
use serde_json::Value;
use sha2::{Digest, Sha256};
use soland_application::delivery::DeliveryApplicationService;
use soland_application::events::{
    EventApplicationService, EventQueryApplicationService, MlsCommitQueryApplicationService,
    MlsKeyPackageApplicationService, RealmInviteApplicationService, RealmQueryApplicationService,
};
use soland_application::federation::FederationApplicationService;
use soland_application::governance::GovernanceApplicationService;
use soland_application::identity::{
    AccountDataApplicationService, AgentPairingApplicationService,
    AgentParticipationApplicationService, ConsentApplicationService, ContactApplicationService,
    DidApplicationService, IdentityApplicationService, KeyBackupApplicationService,
    KeyMaterialApplicationService, RecoveryPolicyApplicationService,
    RecoveryReceiptApplicationService, RecoverySessionApplicationService,
    SessionApplicationService,
};
use soland_application::jobs::JobsApplicationService;
use soland_application::sync::SyncApplicationService;
use soland_domain::hlc::ServerHlc;
use soland_domain::identity::{ConsentCellKey, ConsentCellRecord, DirectConversationBindingRecord};
use soland_domain::reducer::ProjectionState;
use soland_storage::{
    ACCOUNT_LOCKOUT_DURATION, ACCOUNT_LOCKOUT_THRESHOLD, ACCOUNT_LOCKOUT_WINDOW,
    AccountLifecycleRecord, AccountRecord, CanonicalEventRecord, CursorRevocation,
    FailedLoginRecord, FederationOutboxRecord, KEY_BACKUP_DOWNLOAD_TRACKER_MAX_ENTRIES,
    KEY_BACKUP_DOWNLOAD_WINDOW, KeyBackupDownloadOutcome, KeyBackupDownloadRecord,
    MODERATION_FRANKING_REPLAY_MAX_ENTRIES, MODERATION_FRANKING_REPLAY_WINDOW_SECS,
    MODERATION_REPORT_MAX_PER_REPORTER_REALM_WINDOW,
    MODERATION_REPORT_MAX_PER_REPORTER_TARGET_WINDOW, MODERATION_REPORT_MAX_PER_REPORTER_WINDOW,
    MODERATION_REPORT_MAX_PER_SOURCE_IP_WINDOW, MODERATION_REPORT_MAX_PER_SOURCE_SERVICE_WINDOW,
    MODERATION_REPORT_RATE_TRACKER_MAX_ENTRIES, MODERATION_REPORT_RATE_WINDOW_SECS,
    ModerationFrankingReplayRecord, ModerationReportRateOutcome, ModerationReportRateRecord,
    OrganizationPolicyRecord, OrganizationRecord, PSI_HIT_BUCKET_SECS, PSI_PROBE_MAX_PER_WINDOW,
    PSI_PROBE_TRACKER_MAX_ENTRIES, PSI_PROBE_WINDOW, PersistenceResult, PersistenceStore,
    PsiProbeOutcome, PsiProbeRecord, RealmMetaRecord, RealmModerationPolicyRecord,
    RetentionPolicyRecord, RetentionTombstoneRecord, SovereignDeploymentState,
};
use soland_storage_memory::SolandMemoryPersistenceStore;
use soland_storage_postgres::Db;

use super::did_resolver_chain;
use super::member_identity::MemberIdentityRegistry;
use super::notification::{EventBroadcast, Mutex, SubscribeReconnectGate};
use super::realm_directory::{RealmDirectoryEntry, RealmDirectoryIndex};
use crate::authz::SolandAuthzEngine;
use crate::config::{AppConfig, NotarySigningKeyOrigin};
use crate::object_storage::{ObjectStorage, build_object_storage};
use crate::persistence_registry::PgPersistenceStore;
use crate::verified_profiles::VerifiedProfileDescriptor;

mod hydration;

use hydration::*;

/// Single-process service state. Every long-lived data surface lives behind
/// `persistence` (a `dyn PersistenceStore`); the few remaining fields are
/// either non-record state (config, db pool, hlc, authz engine) or runtime
/// facets that don't fit the trait shape (in-memory `RealmDirectoryIndex`,
/// DID resolver service, `ProjectionState`).
#[derive(Clone)]
pub struct AppState {
    pub(crate) config: AppConfig,
    /// Runtime-authoritative service DID. It is resolved from durable identity
    /// state before construction and is never loaded from configuration.
    pub(crate) service_id: String,
    /// Full service-identity lifecycle state used by readiness, doctor, and
    /// identity-mutation gates.
    pub(crate) service_identity: Arc<ArcSwap<ServiceIdentityState>>,
    /// Mutable operational overlay (admin allowlist, rate-limit ceilings,
    /// federation peers, feature toggles). Seeded from `config` at boot,
    /// overlaid by the `server_settings` DB row in [`AppState::hydrate`], and
    /// hot-swapped by the admin settings endpoint. Read a consistent snapshot
    /// via [`AppState::settings`]. See [`crate::runtime_settings`].
    pub(crate) settings: Arc<ArcSwap<crate::runtime_settings::RuntimeSettings>>,
    pub(crate) db: Db,
    persistence: Arc<dyn PersistenceStore>,
    event_application: EventApplicationService,
    event_query_application: EventQueryApplicationService,
    mls_commit_query_application: MlsCommitQueryApplicationService,
    mls_key_package_application: MlsKeyPackageApplicationService,
    realm_query_application: RealmQueryApplicationService,
    realm_invite_application: RealmInviteApplicationService,
    delivery_application: DeliveryApplicationService,
    identity_application: IdentityApplicationService,
    account_data_application: AccountDataApplicationService,
    key_material_application: KeyMaterialApplicationService,
    consent_application: ConsentApplicationService,
    contact_application: ContactApplicationService,
    agent_pairing_application: AgentPairingApplicationService,
    agent_participation_application: AgentParticipationApplicationService,
    key_backup_application: KeyBackupApplicationService,
    session_application: SessionApplicationService,
    recovery_policy_application: RecoveryPolicyApplicationService,
    recovery_receipt_application: RecoveryReceiptApplicationService,
    recovery_session_application: RecoverySessionApplicationService,
    did_application: DidApplicationService,
    federation_application: FederationApplicationService,
    governance_application: GovernanceApplicationService,
    sync_application: SyncApplicationService,
    jobs_application: JobsApplicationService,
    pub(crate) object_storage: Arc<dyn ObjectStorage>,
    pub(crate) hlc: ServerHlc,
    pub(crate) projection: Arc<Mutex<ProjectionState>>,
    pub(crate) authz: SolandAuthzEngine,
    pub(crate) realms: Arc<Mutex<RealmDirectoryIndex>>,
    /// Cross-signing state machine (PSK→SSK/USK publishes + device trust
    /// chains), per spec crypto-media/device-lifecycle.md §5. Fed by the
    /// projector when `ak.cross_signing.publish` lands, and read when verifying
    /// a `ak.device.authorize` `cross_signing_binding`. In-memory like the other
    /// reducer projections; durable rehydration rides on the durable event
    /// store (control-realm Phase 3).
    pub(crate) cross_signing: Arc<Mutex<arkret_sdk::DeviceManager>>,
    /// Process-local replay fence for consumed cross-signing reset
    /// `(principal_id, previous_generation)` tuples.
    pub(crate) cross_signing_reset_replays:
        Arc<Mutex<BTreeMap<(String, u64), chrono::DateTime<chrono::Utc>>>>,
    /// Handle release ledger keyed by bare localpart. The map is hydrated
    /// from `persistence.handle_releases()` and write-through updates keep
    /// post-release grace state durable across restarts.
    pub(crate) handle_releases: Arc<Mutex<BTreeMap<String, chrono::DateTime<chrono::Utc>>>>,
    /// Account lifecycle state projection keyed by actor DID. Missing rows
    /// mean `active`; non-active rows gate auth/session issuance and directory
    /// visibility. Hydrated from `persistence.account_lifecycle()` at boot.
    pub(crate) account_lifecycle: Arc<Mutex<BTreeMap<String, AccountLifecycleRecord>>>,
    /// In-memory failed-auth counter, keyed by actor DID. Once an actor
    /// crosses `ACCOUNT_LOCKOUT_THRESHOLD` (5) within the active window it is
    /// locked out for `ACCOUNT_LOCKOUT_DURATION` (15 min); a successful login
    /// clears the row.
    ///
    /// **Never populated today, so the lockout never triggers.** Its only
    /// writer (`record_failed_login`) has no caller: it was written for
    /// `/_arkret/gate/account/session-grants`, which soland no longer mounts
    /// (api-conventions.md §3.3 moved credential issuance to the Account
    /// Authority). soland now delegates credential checks to coauth's
    /// introspection endpoint and never sees a failure to count, and the one
    /// remaining reader — dev-login — authenticates nothing. See
    /// `docs/account-lifecycle.md` and `review_code.md`; do not treat this
    /// counter as live protection.
    pub(crate) failed_login_attempts: Arc<Mutex<BTreeMap<String, FailedLoginRecord>>>,
    /// Deployment-local account registration policy. It uses the canonical
    /// account-operation DTO so the HTTP handler, audit payload, tests, and a
    /// future admin policy cell all speak the same wire vocabulary.
    pub(crate) account_registration_policy: Arc<Mutex<AccountRegistrationPolicy>>,
    /// Process-local registration attempt counters keyed by principal DID.
    /// This is the account-registration-specific quota; the generic HTTP rate
    /// limiter still protects the route by source address.
    pub(crate) account_registration_rate_tracker:
        Arc<Mutex<BTreeMap<String, (chrono::DateTime<chrono::Utc>, u32)>>>,
    /// SEC-09 — per-`(requester_did, holder_did)` PSI / contact-discovery
    /// probe counters; backs the timing-side-channel rate limit in
    /// `directory::private_contact_discovery`.
    pub(crate) psi_probe_tracker: Arc<Mutex<BTreeMap<(String, String), PsiProbeRecord>>>,
    /// Spec `identity/key-management.md` §7.8 — per-principal rolling-24h
    /// counter of full-ciphertext key-backup downloads; backs the
    /// anti-bulk-dump quota in `identity::key_backup::unlock_key_backup`.
    /// In-memory like the other limiters; a restart resets the window.
    pub(crate) key_backup_download_tracker: Arc<Mutex<BTreeMap<String, KeyBackupDownloadRecord>>>,
    /// Per-scope moderation report quotas keyed by bucket labels. The
    /// canonical report endpoint is an abuse-amplifiable write path, so it
    /// carries a local rolling limiter in addition to the generic HTTP class
    /// limiter.
    pub(crate) moderation_report_rate_tracker:
        Arc<Mutex<BTreeMap<String, ModerationReportRateRecord>>>,
    /// Bounded franking proof replay nonce ledger. Entries are process-local
    /// and intentionally finite; stale or excess nonces are evicted before new
    /// inserts.
    pub(crate) moderation_franking_replay_nonces:
        Arc<Mutex<BTreeMap<String, ModerationFrankingReplayRecord>>>,
    /// Process-local single-use approval nonce ledger for native-agent
    /// act-on-behalf publishes. Durable controller approval state lives in the
    /// projection; this table prevents replay within the approval TTL.
    pub(crate) agent_approval_nonces: Arc<Mutex<BTreeMap<String, chrono::DateTime<chrono::Utc>>>>,
    /// Per-actor notifications read marker. `mark_all_read(actor)` writes
    /// `Utc::now()`; the notifications read-side filter uses it to flag
    /// rows as read. Same in-memory shape as the other two.
    pub(crate) notification_read_cursors:
        Arc<Mutex<BTreeMap<String, chrono::DateTime<chrono::Utc>>>>,
    /// Domain-separated HMAC key for the deterministic stateful sync-cursor
    /// handle (`routing/events/sync.rs::derive_cursor_handle`). The handle
    /// binding rows themselves live in the durable
    /// `persistence.sync_cursors()` table, so a restart no longer invalidates
    /// every client's resume cursor.
    pub(crate) sync_cursor_hmac_key: [u8; 32],
    /// Domain-separated root key for service-scoped push target pseudonyms.
    /// Per-epoch keys are derived from this root inside the push routing
    /// module; only public epoch labels are exposed on describe.
    pub(crate) push_target_hmac_key: [u8; 32],
    /// Revoked cursor authorities (`ak.self.account.command.revoke_cursor`). High-assurance
    /// optional endpoint: a revoked cursor returns `cursor_revoked` and MUST NOT
    /// advance to-device ack, account-subscribe resume position, wait-for barrier
    /// state, or dropped-recovery state. Entries are pruned once the revoked
    /// cursor's maximum TTL has elapsed (`CursorRevocation::expires_at`).
    /// This vector is a read cache over the durable
    /// `persistence.sync_cursors()` revocation ledger
    /// (`sync_cursor_revocations` table): the revoke endpoint writes the
    /// ledger first (fail-closed) and [`AppState::hydrate`] reloads active
    /// rows at boot, so a restart cannot resurrect a revoked cursor.
    pub(crate) sync_cursor_revocations: Arc<Mutex<Vec<CursorRevocation>>>,
    /// Monotonic position allocator for to-device queues. Cursor ack uses
    /// numeric `position <= ack_position` pruning, so positions must advance
    /// even when multiple fanout writes land in the same wall-clock microsecond.
    pub(crate) to_device_position_counter: Arc<AtomicI64>,
    /// Holder-private consent cell projection keyed by
    /// `(holder_did, peer_did, scope)`. This is the minimal G3.S4
    /// reducer cache that backs `/_soland/self/consent/cells/*` and the contact
    /// gate; durable Move/Seal cell hydration can replace the backing map
    /// without changing the routing contract.
    pub(crate) consent_cells: Arc<Mutex<BTreeMap<ConsentCellKey, ConsentCellRecord>>>,
    /// Per-subject private `invite_receive_policy` overrides keyed by the
    /// subject (holder) DID. Spec `sync/invite-addressing.md` §5 — the policy
    /// is subject/private state and MUST NOT enter the durable Realm event
    /// log; the in-memory map is the bounded fallback until durable holder
    /// state hydration lands. Subjects without an entry fall back to the
    /// recommended default policy. `ak.self.contact.command.tombstone(block_peer)`
    /// writes the peer DID into the holder entry's `blocked_subjects`.
    pub(crate) invite_receive_policies:
        Arc<Mutex<BTreeMap<String, arkret_sdk::InviteReceivePolicy>>>,
    /// Direct conversation binding projection keyed by sorted participant DID
    /// pair. This is the bounded server-side fallback for
    /// `ak.self.direct_conversation.command.resolve` until signed
    /// `ak.direct_conversation.bound` event projection is fully wired.
    pub(crate) direct_conversation_bindings:
        Arc<Mutex<BTreeMap<String, DirectConversationBindingRecord>>>,
    /// Runtime state for sovereign-main / enclave deployment handshakes,
    /// trust-root decisions, boundary audit, and store-and-forward queues.
    /// The P2-056 implementation keeps this in memory so the dual-soland
    /// conformance harness can exercise the protocol shape locally; a durable
    /// store can replace the backing map without changing the HTTP contract.
    pub(crate) sovereign_deployment: Arc<Mutex<SovereignDeploymentState>>,
    /// Per-Realm retention policy projection. Hydrated from durable
    /// `retention_policies` rows and write-through on accepted Realm events
    /// or admin updates.
    pub(crate) retention_policies: Arc<Mutex<BTreeMap<String, RetentionPolicyRecord>>>,
    /// Retention tombstones keyed by event_id. Tombstoned events keep their
    /// stable event_id and remain in the canonical/projection stores; render
    /// paths redact the content to `[expired]`.
    pub(crate) retention_tombstones: Arc<Mutex<BTreeMap<String, RetentionTombstoneRecord>>>,
    /// Local organization directory rows keyed by organization DID/id.
    /// Hydrated from durable organization projection rows.
    pub(crate) organizations: Arc<Mutex<BTreeMap<String, OrganizationRecord>>>,
    /// Current organization moderation policy per organization.
    pub(crate) organization_policies: Arc<Mutex<BTreeMap<String, OrganizationPolicyRecord>>>,
    /// SOL-ORG-05 — Realm -> `owning_organizations` DECLARED HINTS, sourced
    /// from `ak.realm.create.owning_organizations` or the local organization
    /// link endpoint. These are NOT verified relationships and MUST NOT drive
    /// governance / durability / delivery / directory policy inheritance — only
    /// a verified `ak.realm.organization` statement does (see the reducer
    /// `realm_organization_statements` projection). Retained as a discovery /
    /// display hint surface only.
    pub(crate) realm_organizations: Arc<Mutex<BTreeMap<String, BTreeSet<String>>>>,
    /// Organization -> member Realm ids. This is the read-side fanout index:
    /// policy updates do not rewrite per-Realm rows.
    pub(crate) organization_realms: Arc<Mutex<BTreeMap<String, BTreeSet<String>>>>,
    /// Accepted Realm-level moderation-policy overrides keyed by Realm id.
    pub(crate) realm_moderation_policies: Arc<Mutex<BTreeMap<String, RealmModerationPolicyRecord>>>,
    pub(crate) did_resolver: Arc<did_resolver_chain::SolandDidResolver>,
    /// Runtime-only verification keys learned from endpoint-discovered
    /// federation peer DID documents. Configuration contains endpoints, not
    /// copied service DIDs or public-key pins; discovery validates the
    /// document's Principal Server endpoint binding before publishing a key.
    pub(crate) federation_peer_verifying_keys: Arc<ArcSwap<BTreeMap<String, VerifyingKey>>>,
    /// Move/Seal/Lattice runtime stores. Pg-backed in database mode,
    /// SDK memory-backed in explicitly in-memory test mode.
    pub(crate) move_store: Arc<dyn MoveStore>,
    pub(crate) seal_store: Arc<dyn SealStore>,
    pub(crate) cell_store: Arc<dyn CellStore>,
    pub(crate) cell_registry: Arc<dyn CellRegistry>,
    pub(crate) event_seal_committer: Arc<dyn soland_storage_postgres::EventSealCommitStore>,
    /// Live event notification bus for `ak.self.events.stream.subscribe`.
    /// Memory mode uses the local broadcast channel; PostgreSQL mode also
    /// publishes over LISTEN/NOTIFY so subscribers connected to another
    /// replica receive the same live frames.
    pub(crate) event_broadcast: EventBroadcast,
    /// Server-enforced reconnect windows advertised by subscribe control
    /// frames. This prevents a faulty or overloaded client from immediately
    /// re-opening the same subscribe scope after `dropped` /
    /// `resync_required`.
    pub(crate) subscribe_reconnect_gate: Arc<Mutex<SubscribeReconnectGate>>,
    /// Persistent Ed25519 signing key for NotaryWorker + admin endpoints.
    /// Production construction receives the exact seed resolved and
    /// key-bound by service-identity bootstrap; AppState never re-resolves or
    /// independently mints this signer.
    ///
    /// Shared across all signing paths so the NotaryWorker, the
    /// `service_admin_signer` admin shortcut, and the threshold partial-
    /// signature coordinator all bind to the **same** key/DID identity.
    /// Readers acquire the current key via `ArcSwap::load_full()`. The
    /// historical signing-key-only rotation path is fail-closed because it
    /// cannot atomically update WebVH, the DID document, durable identity,
    /// KeyStore, and recovery bundle.
    pub(crate) notary_signing_key: Arc<ArcSwap<SigningKey>>,
    /// The origin tag rotates with the key. Stored alongside it
    /// behind a [`Mutex`] (one-shot writes from the rotation path are not
    /// in the hot read path; the per-pass diagnostic helper just snapshots).
    pub(crate) notary_signing_key_origin: Arc<Mutex<NotarySigningKeyOrigin>>,
    /// Per-admin signing keys: SDK
    /// [`arkret_sdk::AdminKeyStore`] keyed by the `application_id`
    /// `soland.<service_id>`. Each admin DID in
    /// `config.admin_principal_dids` gets its own ed25519 signing seed
    /// (provisioned at boot in `development_mode`; lazily loaded from the
    /// configured durable KeyStore otherwise). The signer for an admin DID is
    /// built via `admin_signer_for(state, admin_did)` — this replaces the
    /// service-wide `service_admin_signer` shortcut for endpoints that
    /// want operator attribution in the audit chain.
    pub(crate) admin_keystore: Arc<arkret_sdk::AdminKeyStore>,
    /// G4.T3 — verified-profile descriptors loaded from the artifact path in
    /// `SOLAND_VERIFIED_PROFILES_ARTIFACT` at startup. Filtered to entries
    /// whose `service_role == "principal_server"` and additionally
    /// cross-checked against the local `claimed_profiles[]` set inside
    /// `describe.rs::apply_claim_level_partition`. Empty when the env var
    /// is unset / file missing / file malformed — that's the dev-mode
    /// invariant in service-surface.md §3.0.
    pub(crate) verified_profiles: Arc<Vec<VerifiedProfileDescriptor>>,
    /// MID-1..6 (R3.1 spec-sync 2026-05-27, arkret-spec @ 7157ee8) — in-
    /// memory registry of `ak.member.identity.update` events. Reducer
    /// dispatch (`apply_member_identity_update`) and the sync roster
    /// projection (`SYNC-MEM-1..3`) both go through this. See
    /// [`MemberIdentityRegistry`] above for storage and effective-set
    /// semantics; durable persistence lands when the MID schema migration
    /// ships. Plaintext Ed25519 MemberIdentity proofs are verified on
    /// event ingest; encrypted/non-Ed25519 proof forms are refused
    /// fail-closed. Reducer-shape validation (digest binding, segment
    /// whitelist) IS real per MID-2.
    pub(crate) member_identity: Arc<Mutex<MemberIdentityRegistry>>,
}

fn development_fixture_service_identity(config: &AppConfig) -> ServiceIdentityState {
    let registration_key = ServiceRegistrationKey::new(
        ServiceType::PrincipalServer,
        CanonicalServiceUrl::canonicalize(&config.public_base_url)
            .expect("test/development public base must be canonicalizable"),
    )
    .expect("principal-server registration key");
    let signing_key_ref =
        ServiceIdentityKeyRef::new("fixture:soland:service-signing-key").expect("fixture key ref");
    ServiceIdentityState::Ready {
        identity: LocalServiceIdentity {
            service_id: Did::new(
                "did:webvh:z2dmjYwAPJzv5CZsnAzt8auVZRn1GfuxhpK2t3Q3K3rj4B1x:soland.local:webvh:service",
            )
            .expect("fixture service DID"),
            registration_key,
            provider: None,
            signing_key_refs: vec![signing_key_ref.clone()],
            active_signing_key_ref: signing_key_ref,
            control_key_ref: ServiceIdentityKeyRef::new("fixture:soland:webvh-control-key")
                .expect("fixture control key ref"),
            version_id: "fixture-v1".to_owned(),
            last_verified_at: chrono::Utc::now(),
        },
    }
}

fn evict_oldest_entries<K, V, O>(
    map: &mut BTreeMap<K, V>,
    max_entries: usize,
    mut sort_key: impl FnMut(&V) -> O,
) where
    K: Ord + Clone,
    O: Ord,
{
    if max_entries == 0 {
        map.clear();
        return;
    }
    while map.len() >= max_entries {
        let Some(oldest_key) = map
            .iter()
            .min_by_key(|(_, record)| sort_key(record))
            .map(|(key, _)| key.clone())
        else {
            break;
        };
        map.remove(&oldest_key);
    }
}

impl AppState {
    pub fn config(&self) -> &AppConfig {
        &self.config
    }

    pub fn service_id(&self) -> &String {
        &self.service_id
    }

    pub fn storage_mode(&self) -> &'static str {
        self.db.mode()
    }

    pub fn runtime_settings_handle(
        &self,
    ) -> &Arc<ArcSwap<crate::runtime_settings::RuntimeSettings>> {
        &self.settings
    }

    pub fn federation_peer_verifying_keys_handle(
        &self,
    ) -> &Arc<ArcSwap<BTreeMap<String, VerifyingKey>>> {
        &self.federation_peer_verifying_keys
    }

    /// Snapshot the current service-identity lifecycle state.
    pub fn service_identity_state(&self) -> Arc<ServiceIdentityState> {
        self.service_identity.load_full()
    }

    pub fn replace_service_identity_state(&self, state: ServiceIdentityState) {
        self.service_identity.store(Arc::new(state));
    }

    /// Snapshot the persistent Ed25519 signing key shared by
    /// the NotaryWorker and all admin signing paths. Returns a fresh
    /// `Arc<SigningKey>` (lock-free `ArcSwap::load_full`) so callers can
    /// hold the snapshot for the duration of a signing pass even if the
    /// rotate-signing-key endpoint races with them.
    pub fn notary_signing_key(&self) -> Arc<SigningKey> {
        self.notary_signing_key.load_full()
    }

    /// Public Ed25519 verifying key for the current notary signing key.
    ///
    /// Used by the `ak.call.state` participant_binding verifier: in the
    /// arkret-native self-signed deployment the binding `sig` is minted with
    /// the notary signing key (`routing::interop::webrtc`), so the receiver
    /// verifies against this key after anchoring `issuer_kid` to the current
    /// media_service epoch.
    pub fn notary_verifying_key(&self) -> ed25519_dalek::VerifyingKey {
        self.notary_signing_key.load().verifying_key()
    }

    /// Snapshot a verification key learned from a federation peer's
    /// endpoint-bound DID document.
    pub fn federation_peer_verifying_key(&self, service_id: &str) -> Option<VerifyingKey> {
        self.federation_peer_verifying_keys
            .load()
            .get(service_id)
            .copied()
    }

    /// Origin tag for diagnostics (`Configured` / `Ephemeral` / `Rotated`).
    pub fn notary_signing_key_origin(&self) -> NotarySigningKeyOrigin {
        *self.notary_signing_key_origin.lock()
    }

    pub fn new(config: AppConfig, db: Db) -> Self {
        let persistence: Arc<dyn PersistenceStore> = db
            .pool
            .as_ref()
            .map(|pool| {
                Arc::new(PgPersistenceStore::new(pool.clone())) as Arc<dyn PersistenceStore>
            })
            .unwrap_or_else(|| {
                // The sync integration harness builds a fresh in-memory state
                // per request and does not run the async boot hydration step.
                // Seed the explicitly-enabled demo account in the concrete
                // memory store so directory, moderation, and admin projections
                // observe the same fixture as a normally hydrated dev server.
                let store = if config.seed_demo_data {
                    SolandMemoryPersistenceStore::new_with_demo_data()
                } else {
                    SolandMemoryPersistenceStore::new()
                };
                Arc::new(store)
            });
        Self::new_with_persistence(config, db, persistence)
    }

    pub fn new_with_persistence(
        config: AppConfig,
        db: Db,
        persistence: Arc<dyn PersistenceStore>,
    ) -> Self {
        let identity = development_fixture_service_identity(&config);
        let signing_seed = config.notary_signing_key_seed.unwrap_or_else(|| {
            let mut hasher = Sha256::new();
            hasher.update(b"soland:test-fixture-notary:");
            hasher.update(
                identity
                    .identity()
                    .expect("fixture has a serving identity")
                    .service_id
                    .as_str()
                    .as_bytes(),
            );
            hasher.finalize().into()
        });
        Self::new_with_service_identity(config, db, persistence, identity, signing_seed)
    }

    pub fn new_with_service_identity(
        config: AppConfig,
        db: Db,
        persistence: Arc<dyn PersistenceStore>,
        service_identity: ServiceIdentityState,
        resolved_signing_seed: [u8; 32],
    ) -> Self {
        let mut realms = RealmDirectoryIndex::new();
        let now = chrono::Utc::now();

        let service_id = service_identity
            .identity()
            .expect("AppState requires a serving service identity")
            .service_id
            .to_string();
        let service_identity = Arc::new(ArcSwap::from_pointee(service_identity));

        let object_storage = build_object_storage(&config.object_storage)
            .expect("object storage backend initializes");

        // Seed the deterministic demo Realm into the in-memory directory index
        // when explicitly opted in (tests via `test_config()`, dev harnesses via
        // `SOLAND_SEED_DEMO_DATA=true`). In production this stays off so soland
        // deployments don't all advertise the same hard-coded "Arkret Demo
        // Space" id across federation peers.
        //
        // The DB-touching half of the demo seed (writing the demo account +
        // Realm metadata through the now-async persistence store) and the
        // durable hydration steps run in [`AppState::hydrate`], an explicit
        // async boot step driven from `main`, so the synchronous constructor
        // never touches the database.
        if config.seed_demo_data {
            let demo_realm_id = "ak:realm:0196419b-0000-7000-8000-000000000000";
            let mut demo = RealmDirectoryEntry::new(
                RealmId::new(demo_realm_id.to_owned()).expect("valid demo Realm id"),
                "Arkret Demo Realm",
            );
            demo.description = Some("Shared demo Realm served by soland".to_owned());
            demo.public = true;
            demo.members
                .insert(Did::new("did:web:alice.example").expect("valid did"));
            demo.tags.insert("demo".to_owned());
            demo.category = Some("collaboration".to_owned());
            realms.upsert(demo);
        }

        // Build the production DID resolver chain before the struct literal
        // so we can still
        // borrow `&config` for the helper before `config` itself is
        // moved into `Self.config`.
        let did_resolver = Arc::new(did_resolver_chain::build_soland_did_resolver(
            &config,
            Some(persistence.clone()),
        ));

        // Bootstrap has already validated that this exact seed is the key
        // published by the resolved service DID document. Re-reading a
        // differently-derived key here would split the runtime signer from
        // its authoritative service identity.
        let signing_seed = resolved_signing_seed;
        let notary_signing_key_origin =
            if config.notary_signing_key_seed.is_some() || config.key_store.is_durable() {
                NotarySigningKeyOrigin::Configured
            } else {
                // Only fixture constructors can reach this branch. Production
                // bootstrap requires durable key custody or an explicit secret.
                NotarySigningKeyOrigin::Ephemeral
            };

        let notary_signing_key =
            Arc::new(ArcSwap::from_pointee(SigningKey::from_bytes(&signing_seed)));
        let notary_signing_key_origin = Arc::new(Mutex::new(notary_signing_key_origin));

        // Domain-separated key for the deterministic sync-cursor handle HMAC
        // (routing/events/sync.rs `derive_cursor_handle`). Derived from the
        // notary seed so it inherits the seed's stability story: stable in
        // development_mode / with a configured seed, per-boot otherwise. A
        // changed key only changes which handle an unchanged frontier maps
        // to — persisted rows still resolve by handle, so old cursors stay
        // valid across restarts either way.
        let sync_cursor_hmac_key: [u8; 32] = {
            let mut hasher = Sha256::new();
            hasher.update(b"soland:sync-cursor-handle:v1:");
            hasher.update(signing_seed);
            hasher.finalize().into()
        };
        let push_target_hmac_key: [u8; 32] = {
            let mut hasher = Sha256::new();
            hasher.update(b"soland:push-target-id:v1:");
            hasher.update(signing_seed);
            hasher.finalize().into()
        };

        // Per-admin signing keys: build a single
        // [`AdminKeyStore`] for this principal. The application_id
        // mirrors the NotaryWorker pattern (`soland.<service_id>`) so
        // operators only manage one secret-storage namespace.
        //
        // In `development_mode` we proactively mint an ephemeral seed
        // for every DID listed in `admin_principal_dids` so smoke-tests
        // can call admin endpoints under the operator DID without any
        // out-of-band provisioning step. Production deployments must
        // pre-populate the configured durable KeyStore explicitly — admin DIDs
        // without a provisioned key fall back to
        // `service_admin_signer` at signing time with a sticky-warn.
        let admin_app_id = format!("soland.{service_id}");
        let admin_keystore_inner: Box<dyn arkret_sdk::KeyStore> = config
            .key_store
            .open(&admin_app_id)
            .expect("configured KeyStore must open every namespace")
            .unwrap_or_else(|| Box::new(arkret_sdk::keystore::InMemoryKeyStore::new()));
        let admin_keystore =
            arkret_sdk::AdminKeyStore::new(admin_app_id.clone(), admin_keystore_inner);
        if config.development_mode {
            for did_str in &config.admin_principal_dids {
                let Ok(did) = Did::new(did_str.clone()) else {
                    tracing::warn!(%did_str, "skipping admin keystore provision: invalid DID shape");
                    continue;
                };
                let has_key = admin_keystore.has_admin_key(&did).unwrap_or(false);
                if !has_key {
                    let mut seed = [0u8; 32];
                    getrandom_seed(&mut seed);
                    if let Err(error) = admin_keystore.store_admin_key(&did, &seed) {
                        tracing::warn!(%error, %did_str,
                            "failed to provision ephemeral admin signing key");
                    } else {
                        tracing::info!(%did_str,
                            "provisioned ephemeral admin signing key (development_mode)");
                    }
                }
            }
        }
        let admin_keystore = Arc::new(admin_keystore);

        let cell_registry =
            Arc::new(soland_domain::reducer::lattice_kinds::build_sdk_cell_registry());
        let state_resolution_stores =
            soland_storage_postgres::build_state_resolution_stores(db.pool.clone(), cell_registry);

        // Space-container/Strand/Morph projections are hydrated from durable
        // persistence in [`AppState::hydrate`] (an explicit async boot step)
        // rather than here, because the persistence store is now async. The
        // write-through path in `routing::events::projection.rs::
        // write_through_projection` keeps these tables in sync as reducer
        // apply mutates the in-memory state.
        let hydrated = ProjectionState::new();
        let event_broadcast_database_url = config
            .database_url
            .clone()
            .or_else(|| std::env::var("DATABASE_URL").ok());
        let event_broadcast_pool = db.pool.clone();

        // Seed the mutable overlay from boot config; `hydrate` overlays the
        // persisted `server_settings` row on top if one exists.
        let initial_settings = Arc::new(ArcSwap::from_pointee(
            crate::runtime_settings::RuntimeSettings::from_config(&config),
        ));

        let event_application =
            EventApplicationService::new(Arc::new(PersistenceEventCommitter(persistence.clone())));
        let event_query_application = EventQueryApplicationService::new(Arc::new(
            PersistenceEventReader(persistence.clone()),
        ));
        let mls_commit_query_application = MlsCommitQueryApplicationService::new(Arc::new(
            PersistenceMlsCommitReader(persistence.clone()),
        ));
        let mls_key_package_application = MlsKeyPackageApplicationService::new(Arc::new(
            PersistenceMlsKeyPackageMaintenance(persistence.clone()),
        ));
        let realm_query_application = RealmQueryApplicationService::new(Arc::new(
            PersistenceRealmMetadata(persistence.clone()),
        ));
        let realm_invite_application = RealmInviteApplicationService::new(Arc::new(
            PersistenceRealmInvites(persistence.clone()),
        ));
        let delivery_application = DeliveryApplicationService::new(
            Arc::new(PersistenceNotificationWriter(persistence.clone())),
            Arc::new(PersistenceDeviceDelivery(persistence.clone())),
            Arc::new(PersistenceDeviceMessages(persistence.clone())),
        );
        let identity_application = IdentityApplicationService::new(
            Arc::new(PersistenceAccountLookup(persistence.clone())),
            Arc::new(PersistenceDeviceDirectory(persistence.clone())),
            Arc::new(PersistenceAgentDirectory(persistence.clone())),
        );
        let account_data_application = AccountDataApplicationService::new(Arc::new(
            PersistenceAccountData(persistence.clone()),
        ));
        let key_material_application = KeyMaterialApplicationService::new(
            Arc::new(PersistenceDeviceKeys(persistence.clone())),
            Arc::new(PersistenceOneTimeKeys(persistence.clone())),
        );
        let consent_application =
            ConsentApplicationService::new(Arc::new(PersistenceConsentCells(persistence.clone())));
        let contact_application = ContactApplicationService::new(
            Arc::new(PersistenceContacts(persistence.clone())),
            Arc::new(PersistenceInviteReceivePolicies(persistence.clone())),
            Arc::new(PersistenceDirectConversationBindings(persistence.clone())),
        );
        let agent_pairing_application = AgentPairingApplicationService::new(Arc::new(
            PersistenceAgentPairing(persistence.clone()),
        ));
        let agent_participation_application = AgentParticipationApplicationService::new(Arc::new(
            PersistenceAgentParticipation(persistence.clone()),
        ));
        let key_backup_application =
            KeyBackupApplicationService::new(Arc::new(PersistenceKeyBackups(persistence.clone())));
        let session_application =
            SessionApplicationService::new(Arc::new(PersistenceSessions(persistence.clone())));
        let recovery_policy_application = RecoveryPolicyApplicationService::new(Arc::new(
            PersistenceRecoveryPolicies(persistence.clone()),
        ));
        let recovery_receipt_application = RecoveryReceiptApplicationService::new(Arc::new(
            PersistenceRecoveryReceipts(persistence.clone()),
        ));
        let recovery_session_application = RecoverySessionApplicationService::new(Arc::new(
            PersistenceRecoverySessions(persistence.clone()),
        ));
        let did_application =
            DidApplicationService::new(Arc::new(PersistenceDidDocuments(persistence.clone())));
        let federation_application = FederationApplicationService::new(Arc::new(
            PersistenceFederationOutbox(persistence.clone()),
        ));
        let governance_application =
            GovernanceApplicationService::new(Arc::new(PersistenceAuditLog(persistence.clone())));
        let sync_application =
            SyncApplicationService::new(Arc::new(PersistenceCursorStore(persistence.clone())));
        let jobs_application =
            JobsApplicationService::new(Arc::new(PersistenceMaintenance(persistence.clone())));

        Self {
            config,
            service_id: service_id.clone(),
            service_identity,
            settings: initial_settings,
            hlc: ServerHlc::new(&service_id),
            projection: Arc::new(Mutex::new(hydrated)),
            authz: SolandAuthzEngine::new(),
            db,
            persistence,
            event_application,
            event_query_application,
            mls_commit_query_application,
            mls_key_package_application,
            realm_query_application,
            realm_invite_application,
            delivery_application,
            identity_application,
            account_data_application,
            key_material_application,
            consent_application,
            contact_application,
            agent_pairing_application,
            agent_participation_application,
            key_backup_application,
            session_application,
            recovery_policy_application,
            recovery_receipt_application,
            recovery_session_application,
            did_application,
            federation_application,
            governance_application,
            sync_application,
            jobs_application,
            object_storage,
            realms: Arc::new(Mutex::new(realms)),
            cross_signing: Arc::new(Mutex::new(arkret_sdk::DeviceManager::new())),
            cross_signing_reset_replays: Arc::new(Mutex::new(BTreeMap::new())),
            handle_releases: Arc::new(Mutex::new(BTreeMap::new())),
            account_lifecycle: Arc::new(Mutex::new(BTreeMap::new())),
            failed_login_attempts: Arc::new(Mutex::new(BTreeMap::new())),
            account_registration_policy: Arc::new(Mutex::new(AccountRegistrationPolicy::default())),
            account_registration_rate_tracker: Arc::new(Mutex::new(BTreeMap::new())),
            psi_probe_tracker: Arc::new(Mutex::new(BTreeMap::new())),
            key_backup_download_tracker: Arc::new(Mutex::new(BTreeMap::new())),
            moderation_report_rate_tracker: Arc::new(Mutex::new(BTreeMap::new())),
            moderation_franking_replay_nonces: Arc::new(Mutex::new(BTreeMap::new())),
            agent_approval_nonces: Arc::new(Mutex::new(BTreeMap::new())),
            notification_read_cursors: Arc::new(Mutex::new(BTreeMap::new())),
            sync_cursor_hmac_key,
            push_target_hmac_key,
            sync_cursor_revocations: Arc::new(Mutex::new(Vec::new())),
            to_device_position_counter: Arc::new(AtomicI64::new(now.timestamp_micros())),
            consent_cells: Arc::new(Mutex::new(BTreeMap::new())),
            invite_receive_policies: Arc::new(Mutex::new(BTreeMap::new())),
            direct_conversation_bindings: Arc::new(Mutex::new(BTreeMap::new())),
            sovereign_deployment: Arc::new(Mutex::new(SovereignDeploymentState {
                upstream_available: true,
                ..Default::default()
            })),
            retention_policies: Arc::new(Mutex::new(BTreeMap::new())),
            retention_tombstones: Arc::new(Mutex::new(BTreeMap::new())),
            organizations: Arc::new(Mutex::new(BTreeMap::new())),
            organization_policies: Arc::new(Mutex::new(BTreeMap::new())),
            realm_organizations: Arc::new(Mutex::new(BTreeMap::new())),
            organization_realms: Arc::new(Mutex::new(BTreeMap::new())),
            realm_moderation_policies: Arc::new(Mutex::new(BTreeMap::new())),
            did_resolver,
            federation_peer_verifying_keys: Arc::new(ArcSwap::from_pointee(BTreeMap::new())),
            move_store: state_resolution_stores.move_store,
            seal_store: state_resolution_stores.seal_store,
            cell_store: state_resolution_stores.cell_store,
            cell_registry: state_resolution_stores.cell_registry,
            event_seal_committer: state_resolution_stores.event_seal_committer,
            event_broadcast: EventBroadcast::new(
                event_broadcast_pool,
                event_broadcast_database_url,
                1024,
            ),
            subscribe_reconnect_gate: Arc::new(Mutex::new(SubscribeReconnectGate::default())),
            notary_signing_key,
            notary_signing_key_origin,
            admin_keystore,
            // G4.T3 — load verified-profile descriptors at startup. The env
            // var IS the feature flag; absence keeps the dev-mode
            // verified_profiles=[] invariant. See
            // crate::verified_profiles::load_from_env for the file
            // schema and logging policy.
            verified_profiles: crate::verified_profiles::load_from_env(),
            member_identity: Arc::new(Mutex::new(MemberIdentityRegistry::new())),
        }
    }

    /// Load a consistent snapshot of the mutable operational settings. Cheap
    /// (an atomic pointer load + refcount bump); call per request rather than
    /// caching, so a hot-swap by the admin endpoint is observed immediately.
    #[inline]
    pub fn settings(&self) -> Arc<crate::runtime_settings::RuntimeSettings> {
        self.settings.load_full()
    }

    pub(crate) fn event_application(&self) -> &EventApplicationService {
        &self.event_application
    }

    pub(crate) fn event_query_application(&self) -> &EventQueryApplicationService {
        &self.event_query_application
    }

    pub(crate) fn mls_commit_query_application(&self) -> &MlsCommitQueryApplicationService {
        &self.mls_commit_query_application
    }

    pub(crate) fn mls_key_package_application(&self) -> &MlsKeyPackageApplicationService {
        &self.mls_key_package_application
    }

    pub(crate) fn realm_query_application(&self) -> &RealmQueryApplicationService {
        &self.realm_query_application
    }

    pub(crate) fn realm_invite_application(&self) -> &RealmInviteApplicationService {
        &self.realm_invite_application
    }

    pub(crate) fn account_data_store(&self) -> &dyn soland_storage::AccountDataStore {
        self.persistence.account_data()
    }

    pub(crate) fn accounts_store(&self) -> &dyn soland_storage::AccountStore {
        self.persistence.accounts()
    }

    pub(crate) fn account_localparts_store(&self) -> &dyn soland_storage::AccountLocalpartStore {
        self.persistence.account_localparts()
    }

    pub(crate) fn audit_store(&self) -> &dyn soland_storage::AuditStore {
        self.persistence.audit()
    }

    pub(crate) fn retention_tombstones_store(
        &self,
    ) -> &dyn soland_storage::RetentionTombstoneStore {
        self.persistence.retention_tombstones()
    }

    pub(crate) fn multisig_pending_store(&self) -> &dyn soland_storage::MultisigPendingStore {
        self.persistence.multisig_pending()
    }

    pub(crate) fn agent_participation_store(&self) -> &dyn soland_storage::AgentParticipationStore {
        self.persistence.agent_participation()
    }

    pub(crate) fn agents_store(&self) -> &dyn soland_storage::AgentStore {
        self.persistence.agents()
    }

    pub(crate) fn applets_store(&self) -> &dyn soland_storage::AppletStore {
        self.persistence.applets()
    }

    pub(crate) fn blobs_store(&self) -> &dyn soland_storage::BlobStore {
        self.persistence.blobs()
    }

    pub(crate) fn call_signal_relay_store(&self) -> &dyn soland_storage::CallSignalRelayStore {
        self.persistence.call_signal_relay()
    }

    pub(crate) fn devices_store(&self) -> &dyn soland_storage::DeviceInventoryStore {
        self.persistence.devices()
    }

    pub(crate) fn events_store(&self) -> &dyn soland_storage::EventStore {
        self.persistence.events()
    }

    pub(crate) fn federation_frontier_exchange_store(
        &self,
    ) -> &dyn soland_storage::FederationFrontierExchangeStore {
        self.persistence.federation_frontier_exchange()
    }

    pub(crate) fn federation_operations_store(
        &self,
    ) -> &dyn soland_storage::FederationOperationsStore {
        self.persistence.federation_operations()
    }

    pub(crate) fn federation_outbox_store(&self) -> &dyn soland_storage::FederationOutboxStore {
        self.persistence.federation_outbox()
    }

    pub(crate) fn federation_transactions_store(
        &self,
    ) -> &dyn soland_storage::FederationTransactionStore {
        self.persistence.federation_transactions()
    }

    pub(crate) fn idempotency_keys_store(&self) -> &dyn soland_storage::IdempotencyStore {
        self.persistence.idempotency_keys()
    }

    pub(crate) fn messages_store(&self) -> &dyn soland_storage::MessageStore {
        self.persistence.messages()
    }

    pub(crate) fn mls_commits_store(&self) -> &dyn soland_storage::MlsCommitStore {
        self.persistence.mls_commits()
    }

    pub(crate) fn mls_key_packages_store(&self) -> &dyn soland_storage::MlsKeyPackageStore {
        self.persistence.mls_key_packages()
    }

    pub(crate) fn mls_welcomes_store(&self) -> &dyn soland_storage::MlsWelcomeStore {
        self.persistence.mls_welcomes()
    }

    pub(crate) fn moderation_store(&self) -> &dyn soland_storage::ModerationStore {
        self.persistence.moderation()
    }

    pub(crate) fn morph_projections_store(&self) -> &dyn soland_storage::MorphProjectionStore {
        self.persistence.morph_projections()
    }

    pub(crate) fn policy_documents_store(&self) -> &dyn soland_storage::PolicyDocumentStore {
        self.persistence.policy_documents()
    }

    pub(crate) fn organizations_store(&self) -> &dyn soland_storage::OrganizationStore {
        self.persistence.organizations()
    }

    pub(crate) fn organization_policies_store(
        &self,
    ) -> &dyn soland_storage::OrganizationPolicyStore {
        self.persistence.organization_policies()
    }

    pub(crate) fn realm_organizations_store(&self) -> &dyn soland_storage::RealmOrganizationStore {
        self.persistence.realm_organizations()
    }

    pub(crate) fn realm_moderation_policies_store(
        &self,
    ) -> &dyn soland_storage::RealmModerationPolicyStore {
        self.persistence.realm_moderation_policies()
    }

    pub(crate) fn presence_store(&self) -> &dyn soland_storage::PresenceStore {
        self.persistence.presence()
    }

    pub(crate) fn push_devices_store(&self) -> &dyn soland_storage::PushDeviceStore {
        self.persistence.push_devices()
    }

    pub(crate) fn push_bridge_cache_store(&self) -> &dyn soland_storage::PushBridgeCacheStore {
        self.persistence.push_bridge_cache()
    }

    pub(crate) fn projection_events_store(&self) -> &dyn soland_storage::ProjectionEventStore {
        self.persistence.projection_events()
    }

    pub(crate) fn read_receipt_relay_store(&self) -> &dyn soland_storage::ReadReceiptRelayStore {
        self.persistence.read_receipt_relay()
    }

    pub(crate) fn realm_meta_store(&self) -> &dyn soland_storage::RealmMetaStore {
        self.persistence.realm_meta()
    }

    pub(crate) fn realm_organization_statements_store(
        &self,
    ) -> &dyn soland_storage::RealmOrganizationStatementStore {
        self.persistence.realm_organization_statements()
    }

    pub(crate) fn recovery_sessions_store(&self) -> &dyn soland_storage::RecoverySessionStore {
        self.persistence.recovery_sessions()
    }

    pub(crate) fn retention_policies_store(&self) -> &dyn soland_storage::RetentionPolicyStore {
        self.persistence.retention_policies()
    }

    pub(crate) fn space_container_projections_store(
        &self,
    ) -> &dyn soland_storage::SpaceContainerProjectionStore {
        self.persistence.space_container_projections()
    }

    pub(crate) fn strand_projections_store(&self) -> &dyn soland_storage::StrandProjectionStore {
        self.persistence.strand_projections()
    }

    pub(crate) fn typing_store(&self) -> &dyn soland_storage::TypingStore {
        self.persistence.typing()
    }

    #[allow(dead_code)]
    pub(crate) fn webvh_store(&self) -> &dyn soland_storage::WebvhStore {
        self.persistence.webvh()
    }

    #[allow(dead_code)]
    pub(crate) fn sync_cursors_store(&self) -> &dyn soland_storage::SyncCursorStore {
        self.persistence.sync_cursors()
    }

    #[allow(dead_code)]
    pub(crate) fn notifications_store(&self) -> &dyn soland_storage::NotificationStore {
        self.persistence.notifications()
    }

    pub(crate) fn delivery_application(&self) -> &DeliveryApplicationService {
        &self.delivery_application
    }

    pub(crate) fn identity_application(&self) -> &IdentityApplicationService {
        &self.identity_application
    }

    pub(crate) fn account_data_application(&self) -> &AccountDataApplicationService {
        &self.account_data_application
    }

    pub(crate) fn key_material_application(&self) -> &KeyMaterialApplicationService {
        &self.key_material_application
    }

    pub(crate) fn consent_application(&self) -> &ConsentApplicationService {
        &self.consent_application
    }

    pub(crate) fn contact_application(&self) -> &ContactApplicationService {
        &self.contact_application
    }

    pub(crate) fn did_application(&self) -> &DidApplicationService {
        &self.did_application
    }

    pub(crate) fn agent_pairing_application(&self) -> &AgentPairingApplicationService {
        &self.agent_pairing_application
    }

    pub(crate) fn agent_participation_application(&self) -> &AgentParticipationApplicationService {
        &self.agent_participation_application
    }

    pub(crate) fn key_backup_application(&self) -> &KeyBackupApplicationService {
        &self.key_backup_application
    }

    pub(crate) fn session_application(&self) -> &SessionApplicationService {
        &self.session_application
    }

    pub(crate) fn recovery_policy_application(&self) -> &RecoveryPolicyApplicationService {
        &self.recovery_policy_application
    }

    pub(crate) fn recovery_receipt_application(&self) -> &RecoveryReceiptApplicationService {
        &self.recovery_receipt_application
    }

    pub(crate) fn recovery_session_application(&self) -> &RecoverySessionApplicationService {
        &self.recovery_session_application
    }

    pub(crate) fn federation_application(&self) -> &FederationApplicationService {
        &self.federation_application
    }

    pub(crate) fn governance_application(&self) -> &GovernanceApplicationService {
        &self.governance_application
    }

    pub(crate) fn sync_application(&self) -> &SyncApplicationService {
        &self.sync_application
    }

    pub(crate) fn jobs_application(&self) -> &JobsApplicationService {
        &self.jobs_application
    }

    /// Runtime-authoritative admin-allowlist check. Reads the live overlay,
    /// so an admin added via the settings endpoint takes effect without a
    /// restart.
    #[inline]
    pub fn is_admin_principal(&self, actor: &str) -> bool {
        self.settings().is_admin_principal(actor)
    }

    /// Effective admin-API auth posture from the live overlay + boot
    /// `development_mode`. Mirrors [`crate::config::AppConfig::admin_auth_mode`]
    /// but reflects runtime allowlist changes.
    pub fn admin_auth_mode(&self) -> &'static str {
        if self.config.development_mode {
            "development"
        } else if !self.settings().admin_principal_dids.is_empty() {
            "did_allowlist"
        } else {
            "closed"
        }
    }

    /// Touch the (now async) persistence store to finish boot:
    ///   * seed the demo account + Realm metadata when `seed_demo_data` is on,
    ///   * hydrate the Realm directory from persisted `ak.realm.create` events,
    ///   * hydrate Space-container/Strand/Morph projections from durable rows.
    ///
    /// Extracted out of the synchronous `new` constructor so the DB work runs
    /// in an async context (driven from `main`); see the diesel-async
    /// conversion. Safe to call in memory mode — every store read returns an
    /// empty snapshot, so this is a no-op there.
    pub async fn hydrate(&self) -> PersistenceResult<()> {
        let now = chrono::Utc::now();
        // Overlay the persisted per-key operational settings on top of the
        // boot-config seed. Only overridden keys have rows; everything else
        // keeps its env default. Per-key decode failures are logged and
        // skipped so a corrupt row can never brick startup.
        if let Some(pool) = self.db.pool.as_ref() {
            match crate::runtime_settings::load_overrides(pool).await {
                Ok(rows) if !rows.is_empty() => {
                    let mut merged =
                        crate::runtime_settings::RuntimeSettings::from_config(&self.config);
                    let count = rows.len();
                    merged.apply_override_rows(rows);
                    self.settings.store(Arc::new(merged));
                    tracing::info!(count, "applied server_settings overrides");
                }
                Ok(_) => {}
                Err(error) => {
                    tracing::warn!(%error, "failed to load server_settings; using boot config");
                }
            }
        }
        if self.config.seed_demo_data {
            let demo_realm_id = "ak:realm:0196419b-0000-7000-8000-000000000000";
            let demo_account = AccountRecord {
                id: "ak:account:0196419b-0000-7000-8000-000000000001".to_owned(),
                did: "did:web:alice.example".to_owned(),
                localpart: "alice".to_owned(),
                display_name: Some("Alice Example".to_owned()),
                bio: None,
                avatar_blob_ref: None,
                created_at: now,
            };
            if let Err(error) = self.persistence.accounts().put(&demo_account).await {
                tracing::warn!(%error, "failed to seed demo account into persistence store");
            }
            if let Err(error) = self
                .persistence
                .account_localparts()
                .add(&demo_account.did, &demo_account.localpart, true)
                .await
            {
                tracing::warn!(%error, "failed to seed demo account localpart into persistence store");
            }

            let demo_realm_meta = RealmMetaRecord {
                owner: "did:web:alice.example".to_owned(),
                deleted: false,
                discoverability: "public".to_owned(),
                history_visibility: "shared".to_owned(),
                history_sharing_policy: None,
                history_sharing_policy_digest: None,
                preview_policy: None,
                preview_policy_digest: None,
                asset_privacy_policy: None,
                asset_privacy_policy_digest: None,
                encryption_profile: None,
                plaintext_visible_services: BTreeSet::new(),
                plaintext_visible_service_classes: BTreeMap::new(),
                minimal_metadata_realm: false,
                created_at: now,
                updated_at: now,
            };
            if let Err(error) = self
                .persistence
                .realm_meta()
                .put(demo_realm_id, &demo_realm_meta)
                .await
            {
                tracing::warn!(%error, "failed to seed demo Realm metadata into persistence store");
            }
        }

        // Build the hydrated views off-lock (the async DB reads must not hold
        // a std::sync Mutex guard across `.await`), then merge under a short
        // synchronous critical section.
        let mut realm_updates = RealmDirectoryIndex::new();
        hydrate_realms_from_canonical_events(
            self.persistence.as_ref(),
            &mut realm_updates,
            &self.service_id,
        )
        .await;
        {
            let mut realms = self.realms.lock();
            for (_, entry) in realm_updates.entries_iter() {
                realms.upsert(entry.clone());
            }
        }

        // A-model active-series signatures are bound to the current accepted
        // SSK generation. Rebuild the DeviceManager before restoring those
        // pointers; otherwise a restart makes every correctly hydrated
        // pointer appear stale because the generation cache is empty.
        let cross_signing =
            hydrate_cross_signing_from_persistence(self.persistence.as_ref()).await?;
        *self.cross_signing.lock() = cross_signing;

        let mut proj_updates = ProjectionState::new();
        hydrate_projections_from_persistence(
            self.persistence.as_ref(),
            &mut proj_updates,
            &self.authz,
        )
        .await?;
        {
            let mut proj = self.projection.lock();
            proj.realm_states.extend(proj_updates.realm_states);
            proj.space_containers.extend(proj_updates.space_containers);
            proj.strands.extend(proj_updates.strands);
            proj.morphs.extend(proj_updates.morphs);
            proj.mls_key_packages.extend(proj_updates.mls_key_packages);
            proj.mls_commit_epochs
                .extend(proj_updates.mls_commit_epochs);
            proj.key_backup_active_series
                .extend(proj_updates.key_backup_active_series);
            proj.replay_resolved_pending(&self.hlc);
        }

        let hydrated_realm_ids: Vec<RealmId> = {
            let realms = self.realms.lock();
            realms
                .search(Default::default())
                .into_iter()
                .filter_map(|entry| RealmId::new(entry.realm_id.to_string()).ok())
                .collect()
        };
        {
            let mut proj = self.projection.lock();
            for realm_id in hydrated_realm_ids {
                if let Err(error) = proj.reload_cells_from_store(
                    &realm_id,
                    self.cell_store.as_ref(),
                    self.cell_registry.as_ref(),
                ) {
                    tracing::warn!(%error, realm_id = %realm_id, "failed to hydrate cells from state store");
                }
            }
        }

        // Hydrate per-subject invite_receive_policy overrides from durable
        // storage into the in-memory working map (built off-lock first; the
        // async snapshot read MUST NOT hold the std Mutex across `.await`).
        let policies = self
            .persistence
            .invite_receive_policies()
            .snapshot_all()
            .await?;
        {
            let mut map = self.invite_receive_policies.lock();
            for (subject_id, policy) in policies {
                map.entry(subject_id).or_insert(policy);
            }
        }

        // Hydrate the holder-private consent-cell projection from durable
        // storage. Built off-lock first; the async snapshot read MUST NOT hold
        // the std Mutex across `.await`.
        let cells = self.persistence.consent_cells().snapshot_all().await?;
        {
            let mut map = self.consent_cells.lock();
            for (key, record) in cells {
                map.entry(key).or_insert(record);
            }
        }

        // Hydrate the direct-conversation binding projection (sorted
        // participant pair → binding) from durable storage.
        let bindings = self
            .persistence
            .direct_conversation_bindings()
            .snapshot_all()
            .await?;
        {
            let mut map = self.direct_conversation_bindings.lock();
            for (participants_key, record) in bindings {
                map.entry(participants_key).or_insert(record);
            }
        }

        let lifecycle_records = self.persistence.account_lifecycle().snapshot_all().await?;
        {
            let mut map = self.account_lifecycle.lock();
            for (did, record) in lifecycle_records {
                if record.state == "active" {
                    map.remove(&did);
                } else {
                    map.insert(did, record);
                }
            }
        }

        let handle_releases = self.persistence.handle_releases().snapshot_all().await?;
        {
            let mut map = self.handle_releases.lock();
            for (localpart, released_at) in handle_releases {
                map.insert(localpart, released_at);
            }
        }

        let retention_policies = self.persistence.retention_policies().snapshot_all().await?;
        {
            let mut map = self.retention_policies.lock();
            for record in retention_policies {
                map.insert(record.realm_id.clone(), record);
            }
        }

        let retention_tombstones = self
            .persistence
            .retention_tombstones()
            .snapshot_all()
            .await?;
        {
            let mut map = self.retention_tombstones.lock();
            for record in retention_tombstones {
                map.insert(record.event_id.clone(), record);
            }
        }

        let organizations = self.persistence.organizations().list().await?;
        {
            let mut map = self.organizations.lock();
            for record in organizations {
                map.insert(record.organization_id.clone(), record);
            }
        }

        let organization_policies = self
            .persistence
            .organization_policies()
            .snapshot_all()
            .await?;
        {
            let mut map = self.organization_policies.lock();
            for record in organization_policies {
                map.insert(record.organization_id.clone(), record);
            }
        }

        let realm_organizations = self
            .persistence
            .realm_organizations()
            .snapshot_all()
            .await?;
        {
            let mut realm_map = self.realm_organizations.lock();
            let mut org_map = self.organization_realms.lock();
            for (realm_id, organization_ids) in realm_organizations {
                for organization_id in &organization_ids {
                    org_map
                        .entry(organization_id.clone())
                        .or_default()
                        .insert(realm_id.clone());
                }
                realm_map.insert(realm_id, organization_ids);
            }
        }

        // SOL-ORG-04 — rehydrate verified `ak.realm.organization` relationship
        // statements into the reducer projection so verified relationships /
        // scope-gated policy inheritance survive a restart.
        let realm_organization_statements = self
            .persistence
            .realm_organization_statements()
            .snapshot_all()
            .await?;
        {
            let mut proj = self.projection.lock();
            for record in realm_organization_statements {
                let row = soland_domain::reducer::RealmOrganizationStatementState {
                    realm_id: record.realm_id.clone(),
                    organization_id: record.organization_id.clone(),
                    relationship: record.relationship.clone(),
                    statement_id: record.statement_id,
                    status: record.status,
                    control_scopes: record.control_scopes,
                    issued_at: record.issued_at,
                    not_before: record.not_before,
                    expires_at: record.expires_at,
                    supersedes_statement_id: record.supersedes_statement_id,
                    revokes_statement_id: record.revokes_statement_id,
                    realm_frontier_digest: record.realm_frontier_digest,
                    proof_digest: record.proof_digest,
                    delegation_ref: record.delegation_ref,
                    issuer_role: record.issuer_role,
                    updated_at: record.updated_at,
                };
                proj.realm_organization_statements.insert(
                    (record.realm_id, record.organization_id, record.relationship),
                    row,
                );
            }
        }

        let realm_moderation_policies = self
            .persistence
            .realm_moderation_policies()
            .snapshot_all()
            .await?;
        {
            let mut map = self.realm_moderation_policies.lock();
            for record in realm_moderation_policies {
                map.insert(record.realm_id.clone(), record);
            }
        }

        // Hydrate the cursor-revocation cache from the durable
        // `sync_cursor_revocations` ledger so a revoked cursor stays revoked
        // across restarts (spec `client-sync.md` cursor-revoke semantics —
        // a revoked cursor MUST keep returning `cursor_revoked` and MUST NOT
        // advance to-device ack / resume / wait-for / dropped-recovery
        // state). Built off-lock first; merge under a short critical section.
        match self.sync_application().active_cursor_revocations(now).await {
            Ok(revocations) => {
                let mut cache = self.sync_cursor_revocations.lock();
                cache.extend(
                    revocations
                        .into_iter()
                        .map(persistence_cursor_revocation_owned),
                );
            }
            Err(error) => {
                tracing::warn!(%error, "failed to hydrate cursor revocations from persistence store");
            }
        }
        Ok(())
    }

    /// MID-1..6 — borrow a clone of the in-memory MemberIdentity
    /// registry, suitable for read-only projection paths (sync roster,
    /// describe payload). Callers that need to mutate state must lock
    /// `self.member_identity` directly.
    pub fn member_identity_registry(&self) -> MemberIdentityRegistry {
        self.member_identity.lock().clone()
    }

    pub fn next_to_device_position(&self) -> i64 {
        let wall = chrono::Utc::now().timestamp_micros();
        loop {
            let current = self.to_device_position_counter.load(Ordering::Relaxed);
            let next = wall.max(current.saturating_add(1));
            match self.to_device_position_counter.compare_exchange(
                current,
                next,
                Ordering::SeqCst,
                Ordering::Relaxed,
            ) {
                Ok(_) => return next,
                Err(_) => continue,
            }
        }
    }

    pub fn account_lifecycle_record(&self, did: &str) -> AccountLifecycleRecord {
        self.account_lifecycle
            .lock()
            .get(did)
            .cloned()
            .unwrap_or_else(|| AccountLifecycleRecord {
                state: "active".to_owned(),
                reason: None,
                changed_by: None,
                changed_at: chrono::Utc::now(),
            })
    }

    pub fn account_lifecycle_status(&self, did: &str) -> AccountStatus {
        let record = self.account_lifecycle_record(did);
        account_lifecycle_status_from_wire(&record.state)
    }

    pub fn account_lifecycle_state(&self, did: &str) -> String {
        self.account_lifecycle_status(did).as_str().to_owned()
    }

    pub fn set_account_lifecycle_record(&self, did: &str, record: AccountLifecycleRecord) {
        let mut lifecycle = self.account_lifecycle.lock();
        if record.state == "active" {
            lifecycle.remove(did);
        } else {
            lifecycle.insert(did.to_owned(), record);
        }
    }

    /// Return `Some(locked_until)` if the actor is currently locked out by
    /// the failed-login counter. Stale lockouts (`locked_until <= now`)
    /// auto-clear, so the caller can safely treat a `None` return as
    /// "proceed".
    pub fn account_lockout_active_until(&self, did: &str) -> Option<chrono::DateTime<chrono::Utc>> {
        let mut map = self.failed_login_attempts.lock();
        let now = chrono::Utc::now();
        let record = map.get(did).cloned()?;
        match record.locked_until {
            Some(until) if until > now => Some(until),
            Some(_) => {
                // Lockout window expired — clear the record so the actor
                // gets a clean slate on the next attempt.
                map.remove(did);
                None
            }
            None => None,
        }
    }

    /// Record a failed auth attempt against the given actor. Returns the
    /// updated record so the caller can include lockout context in the
    /// audit trail.
    pub fn record_failed_login(&self, did: &str) -> FailedLoginRecord {
        let mut map = self.failed_login_attempts.lock();
        let now = chrono::Utc::now();
        let entry = map.entry(did.to_owned()).or_insert(FailedLoginRecord {
            attempts: 0,
            last_failure_at: now,
            locked_until: None,
        });
        // Reset the rolling counter if the previous failure aged out.
        if now - entry.last_failure_at > ACCOUNT_LOCKOUT_WINDOW {
            entry.attempts = 0;
            entry.locked_until = None;
        }
        entry.attempts = entry.attempts.saturating_add(1);
        entry.last_failure_at = now;
        if entry.attempts >= ACCOUNT_LOCKOUT_THRESHOLD {
            entry.locked_until = Some(now + ACCOUNT_LOCKOUT_DURATION);
        }
        entry.clone()
    }

    /// Clear a successful login's failure history so the rolling counter
    /// doesn't trip on a future stray failure.
    pub fn clear_failed_login(&self, did: &str) {
        self.failed_login_attempts.lock().remove(did);
    }

    /// SEC-09 — record a PSI / contact-discovery probe for the
    /// `(requester, holder)` pair and report whether it is rate-limited.
    /// A rolling [`PSI_PROBE_WINDOW`] caps probes at
    /// [`PSI_PROBE_MAX_PER_WINDOW`]; once exceeded the caller MUST withhold a
    /// fresh match result and surface `retry_after_ms`, so a requester cannot
    /// poll the holder's hit bit at high frequency to read grant/revoke timing.
    ///
    /// **Not wired.** The only caller is `routing::operation_conformance_tests`,
    /// so no PSI surface actually withholds results and the SEC-09 cap is not
    /// enforced against a real requester. Tracked in `review_code.md`.
    pub fn record_psi_probe(&self, requester: &str, holder: &str) -> PsiProbeOutcome {
        let mut map = self.psi_probe_tracker.lock();
        let now = chrono::Utc::now();
        let expires_before = now - PSI_PROBE_WINDOW;
        map.retain(|_, record| record.last_probe_at >= expires_before);
        let key = (requester.to_owned(), holder.to_owned());
        if !map.contains_key(&key) {
            evict_oldest_entries(&mut map, PSI_PROBE_TRACKER_MAX_ENTRIES, |record| {
                record.last_probe_at.timestamp_millis()
            });
        }
        let entry = map.entry(key).or_insert(PsiProbeRecord {
            count: 0,
            window_started_at: now,
            last_probe_at: now,
        });
        // Roll the window if the current one has elapsed.
        if now - entry.window_started_at > PSI_PROBE_WINDOW {
            entry.count = 0;
            entry.window_started_at = now;
        }
        entry.count = entry.count.saturating_add(1);
        entry.last_probe_at = now;
        let rate_limited = entry.count > PSI_PROBE_MAX_PER_WINDOW;
        let retry_after_ms = if rate_limited {
            (entry.window_started_at + PSI_PROBE_WINDOW - now)
                .num_milliseconds()
                .max(0)
        } else {
            0
        };
        PsiProbeOutcome {
            rate_limited,
            count: entry.count,
            retry_after_ms,
        }
    }

    /// Spec `identity/key-management.md` §7.8 — record a full-ciphertext
    /// key-backup download for `principal_id` and report whether the rolling
    /// 24h quota ([`KEY_BACKUP_DOWNLOAD_WINDOW`]) is exhausted. Once
    /// `count > limit` the caller MUST withhold the ciphertext (HTTP 429)
    /// and write the `access_kind="key_backup_read"` audit entry — encrypted
    /// backups are offline-KDF-cracking ammunition, so bulk dumps must be
    /// throttled even for the legitimate owner session.
    pub fn record_key_backup_download(
        &self,
        principal_id: &str,
        limit: u32,
    ) -> KeyBackupDownloadOutcome {
        let mut map = self.key_backup_download_tracker.lock();
        let now = chrono::Utc::now();
        let expires_before = now - KEY_BACKUP_DOWNLOAD_WINDOW;
        map.retain(|_, record| record.last_download_at >= expires_before);
        let key = principal_id.to_owned();
        if !map.contains_key(&key) {
            evict_oldest_entries(
                &mut map,
                KEY_BACKUP_DOWNLOAD_TRACKER_MAX_ENTRIES,
                |record| record.last_download_at.timestamp_millis(),
            );
        }
        let entry = map.entry(key).or_insert(KeyBackupDownloadRecord {
            count: 0,
            window_started_at: now,
            last_download_at: now,
        });
        // Roll the window if the current one has elapsed.
        if now - entry.window_started_at > KEY_BACKUP_DOWNLOAD_WINDOW {
            entry.count = 0;
            entry.window_started_at = now;
        }
        entry.count = entry.count.saturating_add(1);
        entry.last_download_at = now;
        let rate_limited = entry.count > limit;
        let retry_after_ms = if rate_limited {
            (entry.window_started_at + KEY_BACKUP_DOWNLOAD_WINDOW - now)
                .num_milliseconds()
                .max(0)
        } else {
            0
        };
        KeyBackupDownloadOutcome {
            rate_limited,
            count: entry.count,
            retry_after_ms,
        }
    }

    /// SEC-09 — floor a timestamp to [`PSI_HIT_BUCKET_SECS`] so PSI hit
    /// visibility only changes at coarse bucket boundaries, hiding the precise
    /// moment a holder's reachability bit flipped.
    /// Record one moderation report attempt across the entrypoint's layered
    /// anti-abuse buckets. The generic HTTP rate limiter remains the broad
    /// transport guard; this protocol-level limiter adds reporter, source
    /// service, Realm, source IP, and duplicate-target pressure.
    pub fn record_moderation_report_attempt(
        &self,
        reporter: &str,
        source_service: Option<&str>,
        realm_id: &str,
        source_ip_hash: &str,
        target_ref: &str,
    ) -> ModerationReportRateOutcome {
        let mut buckets = vec![
            (
                format!("reporter:{reporter}"),
                MODERATION_REPORT_MAX_PER_REPORTER_WINDOW,
            ),
            (
                format!("reporter_realm:{reporter}:{realm_id}"),
                MODERATION_REPORT_MAX_PER_REPORTER_REALM_WINDOW,
            ),
            (
                format!("source_ip:{source_ip_hash}:moderation_report"),
                MODERATION_REPORT_MAX_PER_SOURCE_IP_WINDOW,
            ),
            (
                format!("reporter_target:{reporter}:{target_ref}"),
                MODERATION_REPORT_MAX_PER_REPORTER_TARGET_WINDOW,
            ),
        ];
        if let Some(source_service) = source_service.filter(|value| !value.trim().is_empty()) {
            buckets.push((
                format!("source_service:{source_service}"),
                MODERATION_REPORT_MAX_PER_SOURCE_SERVICE_WINDOW,
            ));
            buckets.push((
                format!("reporter_source_service:{reporter}:{source_service}"),
                MODERATION_REPORT_MAX_PER_REPORTER_REALM_WINDOW,
            ));
        }

        let mut map = self.moderation_report_rate_tracker.lock();
        let now = chrono::Utc::now();
        let window = chrono::Duration::seconds(MODERATION_REPORT_RATE_WINDOW_SECS);
        let expires_before = now - window;
        map.retain(|_, record| record.last_report_at >= expires_before);
        let mut exceeded = None;
        for (bucket, limit) in buckets {
            if !map.contains_key(&bucket) {
                evict_oldest_entries(
                    &mut map,
                    MODERATION_REPORT_RATE_TRACKER_MAX_ENTRIES,
                    |record| record.last_report_at.timestamp_millis(),
                );
            }
            let entry = map
                .entry(bucket.clone())
                .or_insert(ModerationReportRateRecord {
                    count: 0,
                    window_started_at: now,
                    last_report_at: now,
                });
            if now - entry.window_started_at > window {
                entry.count = 0;
                entry.window_started_at = now;
            }
            entry.count = entry.count.saturating_add(1);
            entry.last_report_at = now;
            if exceeded.is_none() && entry.count > limit {
                let retry_after_ms = (entry.window_started_at + window - now)
                    .num_milliseconds()
                    .max(0);
                exceeded = Some(ModerationReportRateOutcome {
                    rate_limited: true,
                    bucket: Some(bucket),
                    count: entry.count,
                    limit,
                    retry_after_ms,
                });
            }
        }

        exceeded.unwrap_or(ModerationReportRateOutcome {
            rate_limited: false,
            bucket: None,
            count: 0,
            limit: 0,
            retry_after_ms: 0,
        })
    }

    /// Remember a franking replay nonce within a finite retention window.
    /// Returns `true` for a fresh nonce and `false` for an in-window replay.
    pub fn remember_moderation_franking_nonce(
        &self,
        realm_id: &str,
        received_by: &str,
        replay_nonce: &str,
    ) -> bool {
        let mut map = self.moderation_franking_replay_nonces.lock();
        let now = chrono::Utc::now();
        let expires_before =
            now - chrono::Duration::seconds(MODERATION_FRANKING_REPLAY_WINDOW_SECS);
        map.retain(|_, record| record.last_seen_at >= expires_before);
        while map.len() >= MODERATION_FRANKING_REPLAY_MAX_ENTRIES {
            let Some(oldest_key) = map
                .iter()
                .min_by_key(|(_, record)| record.first_seen_at)
                .map(|(key, _)| key.clone())
            else {
                break;
            };
            map.remove(&oldest_key);
        }

        let key = format!("{realm_id}:{received_by}:{replay_nonce}");
        if let Some(record) = map.get_mut(&key) {
            record.last_seen_at = now;
            return false;
        }
        map.insert(
            key,
            ModerationFrankingReplayRecord {
                first_seen_at: now,
                last_seen_at: now,
            },
        );
        true
    }

    /// Consume a native-agent act-on-behalf approval nonce until the approval
    /// expires. Returns false when the nonce was already consumed or expired.
    pub fn remember_agent_approval_nonce(
        &self,
        agent_id: &str,
        authorization_ref: &str,
        request_id: &str,
        approval_nonce: &str,
        expires_at: chrono::DateTime<chrono::Utc>,
    ) -> bool {
        let now = chrono::Utc::now();
        if expires_at <= now {
            return false;
        }
        let mut map = self.agent_approval_nonces.lock();
        map.retain(|_, expiry| *expiry > now);
        let key = format!("{agent_id}:{authorization_ref}:{request_id}:{approval_nonce}");
        if map.contains_key(&key) {
            return false;
        }
        const AGENT_APPROVAL_NONCE_MAX_ENTRIES: usize = 4096;
        if map.len() >= AGENT_APPROVAL_NONCE_MAX_ENTRIES {
            return false;
        }
        map.insert(key, expires_at);
        true
    }

    pub fn psi_bucket_timestamp(
        ts: chrono::DateTime<chrono::Utc>,
    ) -> chrono::DateTime<chrono::Utc> {
        let secs = ts.timestamp();
        let bucketed = secs - secs.rem_euclid(PSI_HIT_BUCKET_SECS);
        chrono::DateTime::<chrono::Utc>::from_timestamp(bucketed, 0).unwrap_or(ts)
    }
}

impl AppState {
    pub(crate) fn invite_locator_store(&self) -> &dyn soland_storage::InviteLocatorStore {
        self.persistence.invite_locators()
    }

    #[doc(hidden)]
    pub fn test_set_service_id(&mut self, service_id: String) {
        self.service_id = service_id;
    }

    #[doc(hidden)]
    pub fn test_persistence(&self) -> &Arc<dyn PersistenceStore> {
        &self.persistence
    }

    #[doc(hidden)]
    pub fn test_projection(&self) -> &Arc<Mutex<ProjectionState>> {
        &self.projection
    }

    #[doc(hidden)]
    pub fn test_seal_store(&self) -> &Arc<dyn arkret_sdk::SealStore> {
        &self.seal_store
    }

    #[doc(hidden)]
    pub fn test_realms(&self) -> &Arc<Mutex<RealmDirectoryIndex>> {
        &self.realms
    }

    #[doc(hidden)]
    pub fn test_hlc(&self) -> &ServerHlc {
        &self.hlc
    }

    #[doc(hidden)]
    pub fn test_authz(&self) -> &SolandAuthzEngine {
        &self.authz
    }

    #[doc(hidden)]
    pub fn test_object_storage(&self) -> &Arc<dyn ObjectStorage> {
        &self.object_storage
    }

    #[doc(hidden)]
    pub fn test_event_broadcast(&self) -> &EventBroadcast {
        &self.event_broadcast
    }

    #[doc(hidden)]
    pub fn test_did_resolver(&self) -> &Arc<did_resolver_chain::SolandDidResolver> {
        &self.did_resolver
    }

    #[doc(hidden)]
    pub fn test_cross_signing(&self) -> &Arc<Mutex<arkret_sdk::DeviceManager>> {
        &self.cross_signing
    }

    #[doc(hidden)]
    pub fn test_account_registration_policy(&self) -> &Arc<Mutex<AccountRegistrationPolicy>> {
        &self.account_registration_policy
    }

    #[doc(hidden)]
    pub fn test_consent_cells(&self) -> &Arc<Mutex<BTreeMap<ConsentCellKey, ConsentCellRecord>>> {
        &self.consent_cells
    }

    #[doc(hidden)]
    pub fn test_direct_conversation_bindings(
        &self,
    ) -> &Arc<Mutex<BTreeMap<String, DirectConversationBindingRecord>>> {
        &self.direct_conversation_bindings
    }
}

#[derive(Clone)]
struct PersistenceEventCommitter(Arc<dyn PersistenceStore>);

struct PersistenceEventReader(Arc<dyn PersistenceStore>);

struct PersistenceMlsCommitReader(Arc<dyn PersistenceStore>);

struct PersistenceMlsKeyPackageMaintenance(Arc<dyn PersistenceStore>);

struct PersistenceRealmMetadata(Arc<dyn PersistenceStore>);
struct PersistenceRealmInvites(Arc<dyn PersistenceStore>);
struct PersistenceNotificationWriter(Arc<dyn PersistenceStore>);

struct PersistenceDeviceDelivery(Arc<dyn PersistenceStore>);

struct PersistenceDeviceMessages(Arc<dyn PersistenceStore>);

struct PersistenceAccountLookup(Arc<dyn PersistenceStore>);

struct PersistenceAccountData(Arc<dyn PersistenceStore>);

struct PersistenceDeviceKeys(Arc<dyn PersistenceStore>);

struct PersistenceOneTimeKeys(Arc<dyn PersistenceStore>);

struct PersistenceConsentCells(Arc<dyn PersistenceStore>);

struct PersistenceContacts(Arc<dyn PersistenceStore>);

struct PersistenceInviteReceivePolicies(Arc<dyn PersistenceStore>);

struct PersistenceDirectConversationBindings(Arc<dyn PersistenceStore>);

struct PersistenceDeviceDirectory(Arc<dyn PersistenceStore>);

struct PersistenceAgentDirectory(Arc<dyn PersistenceStore>);

struct PersistenceAgentPairing(Arc<dyn PersistenceStore>);

struct PersistenceAgentParticipation(Arc<dyn PersistenceStore>);

struct PersistenceKeyBackups(Arc<dyn PersistenceStore>);

struct PersistenceSessions(Arc<dyn PersistenceStore>);

struct PersistenceRecoveryPolicies(Arc<dyn PersistenceStore>);

struct PersistenceRecoveryReceipts(Arc<dyn PersistenceStore>);

struct PersistenceRecoverySessions(Arc<dyn PersistenceStore>);

struct PersistenceDidDocuments(Arc<dyn PersistenceStore>);

struct PersistenceFederationOutbox(Arc<dyn PersistenceStore>);

struct PersistenceAuditLog(Arc<dyn PersistenceStore>);

struct PersistenceCursorStore(Arc<dyn PersistenceStore>);

struct PersistenceMaintenance(Arc<dyn PersistenceStore>);

fn federation_delivery_record(
    record: soland_application::federation::FederationDeliveryRecord,
) -> FederationOutboxRecord {
    FederationOutboxRecord {
        id: record.id,
        peer_did: record.peer_did,
        peer_url: record.peer_url,
        endpoint: record.endpoint,
        idempotency_key: record.idempotency_key,
        payload_json: record.payload_json,
        attempts: 0,
        next_attempt_at: record.created_at,
        last_status: None,
        last_response_excerpt: None,
        created_at: record.created_at,
        delivered_at: None,
    }
}

fn application_delivery_record(
    record: &FederationOutboxRecord,
) -> soland_application::federation::FederationDeliveryRecord {
    soland_application::federation::FederationDeliveryRecord {
        id: record.id.clone(),
        peer_did: record.peer_did.clone(),
        peer_url: record.peer_url.clone(),
        endpoint: record.endpoint.clone(),
        idempotency_key: record.idempotency_key.clone(),
        payload_json: record.payload_json.clone(),
        created_at: record.created_at,
    }
}

fn application_pending_delivery(
    record: FederationOutboxRecord,
) -> soland_application::federation::PendingFederationDelivery {
    soland_application::federation::PendingFederationDelivery {
        delivery: application_delivery_record(&record),
        attempts: record.attempts,
        next_attempt_at: record.next_attempt_at,
        last_status: record.last_status,
        last_response_excerpt: record.last_response_excerpt,
        delivered_at: record.delivered_at,
    }
}

fn persistence_pending_delivery(
    record: &soland_application::federation::PendingFederationDelivery,
) -> FederationOutboxRecord {
    FederationOutboxRecord {
        id: record.delivery.id.clone(),
        peer_did: record.delivery.peer_did.clone(),
        peer_url: record.delivery.peer_url.clone(),
        endpoint: record.delivery.endpoint.clone(),
        idempotency_key: record.delivery.idempotency_key.clone(),
        payload_json: record.delivery.payload_json.clone(),
        attempts: record.attempts,
        next_attempt_at: record.next_attempt_at,
        last_status: record.last_status,
        last_response_excerpt: record.last_response_excerpt.clone(),
        created_at: record.delivery.created_at,
        delivered_at: record.delivered_at,
    }
}

#[async_trait::async_trait]
impl soland_application::federation::FederationOutboxPort for PersistenceFederationOutbox {
    async fn enqueue(
        &self,
        delivery: &soland_application::federation::FederationDeliveryRecord,
    ) -> soland_application::ApplicationResult<bool> {
        Ok(self
            .0
            .federation_outbox()
            .enqueue(&federation_delivery_record(delivery.clone()))
            .await?)
    }

    async fn find(
        &self,
        peer_did: &str,
        idempotency_key: &str,
    ) -> soland_application::ApplicationResult<
        Option<soland_application::federation::FederationDeliveryRecord>,
    > {
        Ok(self
            .0
            .federation_outbox()
            .snapshot_all()
            .await?
            .into_iter()
            .find(|row| row.peer_did == peer_did && row.idempotency_key == idempotency_key)
            .map(|row| application_delivery_record(&row)))
    }

    async fn pending_due(
        &self,
        now: i64,
        limit: usize,
    ) -> soland_application::ApplicationResult<
        Vec<soland_application::federation::PendingFederationDelivery>,
    > {
        Ok(self
            .0
            .federation_outbox()
            .pending_due(now, limit)
            .await?
            .into_iter()
            .map(application_pending_delivery)
            .collect())
    }

    async fn update(
        &self,
        delivery: &soland_application::federation::PendingFederationDelivery,
    ) -> soland_application::ApplicationResult<()> {
        self.0
            .federation_outbox()
            .update(&persistence_pending_delivery(delivery))
            .await?;
        Ok(())
    }

    async fn insert_dead_letter(
        &self,
        record: &soland_application::federation::FederationDeadLetter,
    ) -> soland_application::ApplicationResult<()> {
        self.0
            .federation_outbox()
            .insert_dead_letter(&soland_storage::FederationOutboxDeadLetterRecord {
                id: record.id.clone(),
                outbox_id: record.outbox_id.clone(),
                peer_did: record.peer_did.clone(),
                endpoint: record.endpoint.clone(),
                idempotency_key: record.idempotency_key.clone(),
                terminal_status: record.terminal_status,
                attempts: record.attempts,
                response_excerpt: record.response_excerpt.clone(),
                failed_at: record.failed_at,
                reason: record.reason.clone(),
            })
            .await?;
        Ok(())
    }
}

#[async_trait::async_trait]
impl soland_application::governance::AuditLogPort for PersistenceAuditLog {
    async fn append(&self, entry: Value) -> soland_application::ApplicationResult<()> {
        self.0.audit().append(entry).await?;
        Ok(())
    }

    async fn entries_for_actor(
        &self,
        actor_id: &str,
    ) -> soland_application::ApplicationResult<Vec<Value>> {
        Ok(self.0.audit().list_for_actor(actor_id).await?)
    }
}

#[async_trait::async_trait]
impl soland_application::jobs::MaintenancePort for PersistenceMaintenance {
    async fn prune_expired_idempotency(
        &self,
        now: chrono::DateTime<chrono::Utc>,
    ) -> soland_application::ApplicationResult<usize> {
        Ok(self.0.idempotency_keys().prune_expired(now).await?)
    }
}

fn application_cursor_state(
    record: soland_storage::SyncCursorRecord,
) -> soland_application::sync::CursorState {
    soland_application::sync::CursorState {
        handle: record.handle,
        principal_id: record.principal_id,
        device_id: record.device_id,
        service_id: record.service_id,
        filter_digest: record.filter_digest,
        purpose: record.purpose,
        positions: record.positions,
        target: record.target,
        issued_at_ms: record.issued_at_ms,
        expires_at_ms: record.expires_at_ms,
    }
}

fn persistence_cursor_state(
    record: &soland_application::sync::CursorState,
) -> soland_storage::SyncCursorRecord {
    soland_storage::SyncCursorRecord {
        handle: record.handle.clone(),
        principal_id: record.principal_id.clone(),
        device_id: record.device_id.clone(),
        service_id: record.service_id.clone(),
        filter_digest: record.filter_digest.clone(),
        purpose: record.purpose.clone(),
        positions: record.positions.clone(),
        target: record.target.clone(),
        issued_at_ms: record.issued_at_ms,
        expires_at_ms: record.expires_at_ms,
    }
}

fn application_cursor_revocation(
    record: CursorRevocation,
) -> soland_application::sync::CursorRevocationState {
    soland_application::sync::CursorRevocationState {
        cursor_digest: record.cursor_digest,
        principal_id: record.principal_id,
        device_id: record.device_id,
        scope: record.scope,
        reason_code: record.reason_code,
        revoked_at: record.revoked_at,
        expires_at: record.expires_at,
    }
}

fn persistence_cursor_revocation(
    record: &soland_application::sync::CursorRevocationState,
) -> CursorRevocation {
    CursorRevocation {
        cursor_digest: record.cursor_digest.clone(),
        principal_id: record.principal_id.clone(),
        device_id: record.device_id.clone(),
        scope: record.scope.clone(),
        reason_code: record.reason_code.clone(),
        revoked_at: record.revoked_at,
        expires_at: record.expires_at,
    }
}

fn persistence_cursor_revocation_owned(
    record: soland_application::sync::CursorRevocationState,
) -> CursorRevocation {
    persistence_cursor_revocation(&record)
}

#[async_trait::async_trait]
impl soland_application::sync::CursorStorePort for PersistenceCursorStore {
    async fn get(
        &self,
        handle: &str,
    ) -> soland_application::ApplicationResult<Option<soland_application::sync::CursorState>> {
        Ok(self
            .0
            .sync_cursors()
            .get(handle)
            .await?
            .map(application_cursor_state))
    }

    async fn upsert(
        &self,
        record: &soland_application::sync::CursorState,
    ) -> soland_application::ApplicationResult<()> {
        self.0
            .sync_cursors()
            .upsert(&persistence_cursor_state(record))
            .await?;
        Ok(())
    }

    async fn delete(&self, handle: &str) -> soland_application::ApplicationResult<bool> {
        Ok(self.0.sync_cursors().delete(handle).await?)
    }

    async fn prune_stream_superseded(
        &self,
        principal_id: &str,
        device_id: &str,
        filter_digest: &str,
        presented_issued_at_ms: i64,
    ) -> soland_application::ApplicationResult<usize> {
        Ok(self
            .0
            .sync_cursors()
            .prune_stream_superseded(
                principal_id,
                device_id,
                filter_digest,
                presented_issued_at_ms,
            )
            .await?)
    }

    async fn prune_expired(&self, now_ms: i64) -> soland_application::ApplicationResult<usize> {
        Ok(self.0.sync_cursors().prune_expired(now_ms).await?)
    }

    async fn record_revocation(
        &self,
        record: &soland_application::sync::CursorRevocationState,
    ) -> soland_application::ApplicationResult<()> {
        self.0
            .sync_cursors()
            .record_revocation(&persistence_cursor_revocation(record))
            .await?;
        Ok(())
    }

    async fn active_revocations(
        &self,
        now: chrono::DateTime<chrono::Utc>,
    ) -> soland_application::ApplicationResult<Vec<soland_application::sync::CursorRevocationState>>
    {
        Ok(self
            .0
            .sync_cursors()
            .active_revocations(now)
            .await?
            .into_iter()
            .map(application_cursor_revocation)
            .collect())
    }
}

#[async_trait::async_trait]
impl soland_application::identity::AccountLookupPort for PersistenceAccountLookup {
    async fn find_account_by_actor(
        &self,
        actor_id: &str,
    ) -> soland_application::ApplicationResult<Option<soland_application::identity::AccountIdentity>>
    {
        Ok(self.0.accounts().get(actor_id).await?.map(|account| {
            soland_application::identity::AccountIdentity {
                account_id: account.id,
            }
        }))
    }

    async fn register_account(
        &self,
        command: soland_application::identity::RegisterAccountCommand,
    ) -> soland_application::ApplicationResult<()> {
        let account = soland_storage::AccountRecord {
            id: command.account_id,
            did: command.actor_id.clone(),
            localpart: command.localpart.clone(),
            display_name: command.display_name,
            bio: None,
            avatar_blob_ref: None,
            created_at: command.created_at,
        };
        self.0.accounts().put(&account).await?;
        self.0
            .account_localparts()
            .add(&command.actor_id, &command.localpart, true)
            .await?;
        Ok(())
    }

    async fn account(
        &self,
        actor_id: &str,
    ) -> soland_application::ApplicationResult<
        Option<soland_application::identity::AccountProfileState>,
    > {
        Ok(self
            .0
            .accounts()
            .get(actor_id)
            .await?
            .map(application_account_profile))
    }

    async fn save_account(
        &self,
        account: soland_application::identity::AccountProfileState,
    ) -> soland_application::ApplicationResult<()> {
        self.0
            .accounts()
            .put(&persistence_account_profile(account))
            .await?;
        Ok(())
    }

    async fn delete_account(&self, actor_id: &str) -> soland_application::ApplicationResult<()> {
        self.0.accounts().delete(actor_id).await?;
        Ok(())
    }

    async fn account_localparts(
        &self,
        actor_id: &str,
    ) -> soland_application::ApplicationResult<
        Vec<soland_application::identity::AccountLocalpartState>,
    > {
        Ok(self
            .0
            .account_localparts()
            .list_for_account(actor_id)
            .await?
            .into_iter()
            .map(application_account_localpart)
            .collect())
    }

    async fn localpart_owner(
        &self,
        localpart: &str,
    ) -> soland_application::ApplicationResult<
        Option<soland_application::identity::AccountLocalpartState>,
    > {
        Ok(self
            .0
            .account_localparts()
            .owner_of(localpart)
            .await?
            .map(application_account_localpart))
    }

    async fn add_localpart(
        &self,
        actor_id: &str,
        localpart: &str,
        primary: bool,
    ) -> soland_application::ApplicationResult<soland_application::identity::AccountLocalpartState>
    {
        Ok(application_account_localpart(
            self.0
                .account_localparts()
                .add(actor_id, localpart, primary)
                .await?,
        ))
    }

    async fn set_primary_localpart(
        &self,
        actor_id: &str,
        localpart: &str,
    ) -> soland_application::ApplicationResult<soland_application::identity::AccountLocalpartState>
    {
        Ok(application_account_localpart(
            self.0
                .account_localparts()
                .set_primary(actor_id, localpart)
                .await?,
        ))
    }

    async fn remove_localpart(
        &self,
        actor_id: &str,
        localpart: &str,
    ) -> soland_application::ApplicationResult<()> {
        self.0
            .account_localparts()
            .remove(actor_id, localpart)
            .await?;
        Ok(())
    }

    async fn clear_localparts(&self, actor_id: &str) -> soland_application::ApplicationResult<()> {
        self.0
            .account_localparts()
            .clear_for_account(actor_id)
            .await?;
        Ok(())
    }

    async fn record_handle_release(
        &self,
        localpart: &str,
        released_at: chrono::DateTime<chrono::Utc>,
    ) -> soland_application::ApplicationResult<()> {
        self.0.handle_releases().put(localpart, released_at).await?;
        Ok(())
    }

    async fn save_account_lifecycle(
        &self,
        actor_id: &str,
        lifecycle: soland_application::identity::AccountLifecycleState,
    ) -> soland_application::ApplicationResult<()> {
        self.0
            .account_lifecycle()
            .put(
                actor_id,
                &soland_storage::AccountLifecycleRecord {
                    state: lifecycle.state,
                    reason: lifecycle.reason,
                    changed_by: lifecycle.changed_by,
                    changed_at: lifecycle.changed_at,
                },
            )
            .await?;
        Ok(())
    }

    async fn delete_account_lifecycle(
        &self,
        actor_id: &str,
    ) -> soland_application::ApplicationResult<()> {
        self.0.account_lifecycle().delete(actor_id).await?;
        Ok(())
    }
}

fn application_account_profile(
    account: soland_storage::AccountRecord,
) -> soland_application::identity::AccountProfileState {
    soland_application::identity::AccountProfileState {
        id: account.id,
        did: account.did,
        localpart: account.localpart,
        display_name: account.display_name,
        bio: account.bio,
        avatar_blob_ref: account.avatar_blob_ref,
        created_at: account.created_at,
    }
}

fn persistence_account_profile(
    account: soland_application::identity::AccountProfileState,
) -> soland_storage::AccountRecord {
    soland_storage::AccountRecord {
        id: account.id,
        did: account.did,
        localpart: account.localpart,
        display_name: account.display_name,
        bio: account.bio,
        avatar_blob_ref: account.avatar_blob_ref,
        created_at: account.created_at,
    }
}

fn application_account_localpart(
    record: soland_storage::AccountLocalpartRecord,
) -> soland_application::identity::AccountLocalpartState {
    soland_application::identity::AccountLocalpartState {
        id: record.id,
        account_did: record.account_did,
        localpart: record.localpart,
        is_primary: record.is_primary,
        created_at: record.created_at,
        updated_at: record.updated_at,
    }
}

#[async_trait::async_trait]
impl soland_application::identity::AccountDataPort for PersistenceAccountData {
    async fn entry(
        &self,
        actor_id: &str,
        data_type: &str,
    ) -> soland_application::ApplicationResult<Option<soland_application::identity::AccountDataState>>
    {
        Ok(self
            .0
            .account_data()
            .get(actor_id, data_type)
            .await?
            .map(application_account_data))
    }

    async fn entries_for_actor(
        &self,
        actor_id: &str,
    ) -> soland_application::ApplicationResult<Vec<soland_application::identity::AccountDataState>>
    {
        Ok(self
            .0
            .account_data()
            .list_for_actor(actor_id)
            .await?
            .into_iter()
            .map(application_account_data)
            .collect())
    }

    async fn save_entry(
        &self,
        entry: soland_application::identity::AccountDataState,
    ) -> soland_application::ApplicationResult<()> {
        self.0
            .account_data()
            .put(&soland_storage::AccountDataRecord {
                actor: entry.actor_id,
                data_type: entry.data_type,
                payload: entry.payload,
                updated_at: entry.updated_at,
            })
            .await?;
        Ok(())
    }

    async fn delete_entry(
        &self,
        actor_id: &str,
        data_type: &str,
    ) -> soland_application::ApplicationResult<()> {
        self.0.account_data().delete(actor_id, data_type).await?;
        Ok(())
    }
}

fn application_account_data(
    record: soland_storage::AccountDataRecord,
) -> soland_application::identity::AccountDataState {
    soland_application::identity::AccountDataState {
        actor_id: record.actor,
        data_type: record.data_type,
        payload: record.payload,
        updated_at: record.updated_at,
    }
}

#[async_trait::async_trait]
impl soland_application::identity::ConsentCellPort for PersistenceConsentCells {
    async fn save_cell(
        &self,
        cell: soland_domain::identity::ConsentCellRecord,
    ) -> soland_application::ApplicationResult<()> {
        self.0.consent_cells().put(&cell).await?;
        Ok(())
    }

    async fn cells(
        &self,
    ) -> soland_application::ApplicationResult<
        Vec<(
            soland_domain::identity::ConsentCellKey,
            soland_domain::identity::ConsentCellRecord,
        )>,
    > {
        Ok(self.0.consent_cells().snapshot_all().await?)
    }
}

#[async_trait::async_trait]
impl soland_application::identity::ContactPort for PersistenceContacts {
    async fn contact_any(
        &self,
        requester: &str,
        target: &str,
    ) -> soland_application::ApplicationResult<Option<soland_domain::identity::ContactRecord>> {
        Ok(self.0.contacts().get(requester, target).await?)
    }

    async fn contact(
        &self,
        requester: &str,
        target: &str,
        scope: &str,
    ) -> soland_application::ApplicationResult<Option<soland_domain::identity::ContactRecord>> {
        Ok(self
            .0
            .contacts()
            .get_scoped(requester, target, scope)
            .await?)
    }

    async fn contacts_for_actor(
        &self,
        actor_id: &str,
    ) -> soland_application::ApplicationResult<Vec<soland_domain::identity::ContactRecord>> {
        Ok(self.0.contacts().list_for_actor(actor_id).await?)
    }

    async fn save_contact(
        &self,
        contact: soland_domain::identity::ContactRecord,
    ) -> soland_application::ApplicationResult<()> {
        self.0.contacts().put(&contact).await?;
        Ok(())
    }
}

#[async_trait::async_trait]
impl soland_application::identity::InviteReceivePolicyPort for PersistenceInviteReceivePolicies {
    async fn save_policy(
        &self,
        policy: arkret_sdk::InviteReceivePolicy,
    ) -> soland_application::ApplicationResult<()> {
        self.0.invite_receive_policies().put(&policy).await?;
        Ok(())
    }
}

#[async_trait::async_trait]
impl soland_application::identity::DirectConversationBindingPort
    for PersistenceDirectConversationBindings
{
    async fn save_binding(
        &self,
        pair_key: &str,
        binding: soland_domain::identity::DirectConversationBindingRecord,
    ) -> soland_application::ApplicationResult<()> {
        self.0
            .direct_conversation_bindings()
            .put(pair_key, &binding)
            .await?;
        Ok(())
    }

    async fn delete_binding(&self, pair_key: &str) -> soland_application::ApplicationResult<()> {
        self.0
            .direct_conversation_bindings()
            .delete(pair_key)
            .await?;
        Ok(())
    }
}

#[async_trait::async_trait]
impl soland_application::identity::DeviceKeyPort for PersistenceDeviceKeys {
    async fn save_bundle(
        &self,
        actor_id: String,
        device_id: String,
        payload: Value,
    ) -> soland_application::ApplicationResult<()> {
        self.0
            .device_keys()
            .put(actor_id, device_id, payload)
            .await?;
        Ok(())
    }

    async fn bundle(
        &self,
        actor_id: &str,
        device_id: &str,
    ) -> soland_application::ApplicationResult<Option<Value>> {
        Ok(self.0.device_keys().get(actor_id, device_id).await?)
    }
}

#[async_trait::async_trait]
impl soland_application::identity::OneTimeKeyPort for PersistenceOneTimeKeys {
    async fn save_keys(
        &self,
        actor_id: String,
        device_id: String,
        keys: Vec<Value>,
    ) -> soland_application::ApplicationResult<()> {
        self.0
            .one_time_keys()
            .put(actor_id, device_id, keys)
            .await?;
        Ok(())
    }

    async fn claim_key(
        &self,
        actor_id: &str,
        device_id: &str,
    ) -> soland_application::ApplicationResult<Option<Value>> {
        Ok(self.0.one_time_keys().claim(actor_id, device_id).await?)
    }
}

#[async_trait::async_trait]
impl soland_application::identity::DeviceDirectoryPort for PersistenceDeviceDirectory {
    async fn list_active_device_actors(
        &self,
    ) -> soland_application::ApplicationResult<Vec<String>> {
        Ok(self
            .0
            .devices()
            .list()
            .await?
            .into_iter()
            .filter(|device| device.revoked_at.is_none())
            .map(|device| device.actor)
            .collect())
    }

    async fn find_device(
        &self,
        actor_id: &str,
        device_id: &str,
    ) -> soland_application::ApplicationResult<Option<soland_application::identity::DeviceIdentity>>
    {
        Ok(self
            .0
            .devices()
            .get(actor_id, device_id)
            .await?
            .map(|device| soland_application::identity::DeviceIdentity {
                actor_id: device.actor,
                device_id: device.device_id,
                display_name: device.display_name,
                verification_state: device.verification_state,
                payload: device.payload,
                created_at: device.created_at,
                updated_at: device.updated_at,
                revoked_at: device.revoked_at,
            }))
    }

    async fn save_device(
        &self,
        command: soland_application::identity::SaveDeviceCommand,
    ) -> soland_application::ApplicationResult<()> {
        self.0
            .devices()
            .put(&soland_storage::DeviceInventoryRecord {
                actor: command.actor_id,
                device_id: command.device_id,
                display_name: command.display_name,
                verification_state: command.device.verification_state,
                payload: command.device.payload,
                created_at: command.device.created_at,
                updated_at: command.device.updated_at,
                revoked_at: command.device.revoked_at,
            })
            .await?;
        Ok(())
    }

    async fn save_device_if_absent(
        &self,
        device: soland_application::identity::DeviceIdentity,
    ) -> soland_application::ApplicationResult<bool> {
        Ok(self
            .0
            .devices()
            .put_if_absent(&soland_storage::DeviceInventoryRecord {
                actor: device.actor_id,
                device_id: device.device_id,
                display_name: device.display_name,
                verification_state: device.verification_state,
                payload: device.payload,
                created_at: device.created_at,
                updated_at: device.updated_at,
                revoked_at: device.revoked_at,
            })
            .await?)
    }

    async fn devices_for_actor(
        &self,
        actor_id: &str,
    ) -> soland_application::ApplicationResult<Vec<soland_application::identity::DeviceIdentity>>
    {
        Ok(self
            .0
            .devices()
            .list_for_actor_including_revoked(actor_id)
            .await?
            .into_iter()
            .map(|device| soland_application::identity::DeviceIdentity {
                actor_id: device.actor,
                device_id: device.device_id,
                display_name: device.display_name,
                verification_state: device.verification_state,
                payload: device.payload,
                created_at: device.created_at,
                updated_at: device.updated_at,
                revoked_at: device.revoked_at,
            })
            .collect())
    }
}

#[async_trait::async_trait]
impl soland_application::identity::AgentDirectoryPort for PersistenceAgentDirectory {
    async fn find_agent_controller(
        &self,
        agent_id: &str,
    ) -> soland_application::ApplicationResult<Option<soland_application::identity::AgentController>>
    {
        Ok(self.0.agents().get(agent_id).await?.map(|agent| {
            soland_application::identity::AgentController {
                controller_id: agent.controller_id,
            }
        }))
    }
}

#[async_trait::async_trait]
impl soland_application::identity::AgentPairingPort for PersistenceAgentPairing {
    async fn pairing_record(
        &self,
        pairing_request_id: &str,
    ) -> soland_application::ApplicationResult<
        Option<soland_application::identity::AgentPairingState>,
    > {
        Ok(self
            .0
            .agents()
            .get_by_pairing_request_id(pairing_request_id)
            .await?
            .map(application_agent_pairing))
    }

    async fn agent(
        &self,
        agent_id: &str,
    ) -> soland_application::ApplicationResult<
        Option<soland_application::identity::AgentPairingState>,
    > {
        Ok(self
            .0
            .agents()
            .get(agent_id)
            .await?
            .map(application_agent_pairing))
    }

    async fn agents_for_controller(
        &self,
        controller_id: &str,
    ) -> soland_application::ApplicationResult<Vec<soland_application::identity::AgentPairingState>>
    {
        Ok(self
            .0
            .agents()
            .list_for_controller(controller_id)
            .await?
            .into_iter()
            .map(application_agent_pairing)
            .collect())
    }

    async fn save_agent(
        &self,
        agent: soland_application::identity::AgentPairingState,
    ) -> soland_application::ApplicationResult<()> {
        self.0
            .agents()
            .put(persistence_agent_pairing(agent))
            .await?;
        Ok(())
    }

    async fn store_runtime_approval(
        &self,
        command: &soland_application::identity::StoreAgentRuntimeApprovalCommand,
    ) -> soland_application::ApplicationResult<
        Option<soland_application::identity::AgentPairingState>,
    > {
        let write = soland_storage::AgentRuntimeApprovalWrite {
            agent_id: command.agent_id.clone(),
            pairing_request_id: command.pairing_request_id.clone(),
            approval_request_id: command.approval_request_id.clone(),
            approval_notification_id: command.approval_notification_id.clone(),
            approval_requested_at: command.approval_requested_at,
            controller_account_id: command.controller_account_id.clone(),
            recipient_service_id: command.recipient_service_id.clone(),
            runtime_key_binding_digest: command.runtime_key_binding_digest.clone(),
            runtime_public_key_digest: command.runtime_public_key_digest.clone(),
            runtime_attestation_digest: command.runtime_attestation_digest.clone(),
            runtime_key_request: command.runtime_key_request.clone(),
        };
        Ok(self
            .0
            .agents()
            .put_runtime_approval_if_compatible(&write)
            .await?
            .map(application_agent_pairing))
    }

    async fn activate_runtime_if_current(
        &self,
        command: &soland_application::identity::ActivateAgentRuntimeCommand,
    ) -> soland_application::ApplicationResult<bool> {
        let activation = soland_storage::AgentRuntimeActivation {
            agent_id: command.agent_id.clone(),
            approval_request_id: command.approval_request_id.clone(),
            runtime_key_binding_digest: command.runtime_key_binding_digest.clone(),
            pairing_request_id: command.pairing_request_id.clone(),
            paired_request_digest: command.paired_request_digest.clone(),
            authorized_event_ref: command.authorized_event_ref.clone(),
            authorized_verification_method: command.authorized_verification_method.clone(),
            authorized_public_key_digest: command.authorized_public_key_digest.clone(),
            authorized_at: command.authorized_at,
        };
        Ok(self
            .0
            .agents()
            .activate_runtime_if_current(&activation)
            .await?)
    }

    async fn clear_approval_notification_if_current(
        &self,
        agent_id: &str,
        approval_request_id: &str,
    ) -> soland_application::ApplicationResult<bool> {
        Ok(self
            .0
            .agents()
            .clear_runtime_approval_notification_if_current(agent_id, approval_request_id)
            .await?)
    }
}

fn application_agent_pairing(
    record: soland_storage::AgentPrincipalRecord,
) -> soland_application::identity::AgentPairingState {
    soland_application::identity::AgentPairingState {
        id: record.id,
        controller_id: record.controller_id,
        principal_control_realm_id: record.principal_control_realm_id,
        controller_authorization_ref: record.controller_authorization_ref,
        display_name: record.display_name,
        agent_slug: record.agent_slug,
        avatar_blob_ref: record.avatar_blob_ref,
        state: record.state,
        requested_scope: record.requested_scope,
        accountability: record.accountability,
        provision_event_refs: record.provision_event_refs,
        pairing_request_id: record.pairing_request_id,
        paired_pairing_request_id: record.paired_pairing_request_id,
        paired_request_digest: record.paired_request_digest,
        pairing_code: record.pairing_code,
        pairing_expires_at: record.pairing_expires_at,
        approval_request_id: record.approval_request_id,
        controller_account_id: record.controller_account_id,
        recipient_service_id: record.recipient_service_id,
        runtime_key_binding_digest: record.runtime_key_binding_digest,
        runtime_public_key_digest: record.runtime_public_key_digest,
        runtime_attestation_digest: record.runtime_attestation_digest,
        approval_notification_id: record.approval_notification_id,
        runtime_key_request: record.runtime_key_request,
        approval_requested_at: record.approval_requested_at,
        authorized_event_ref: record.authorized_event_ref,
        authorized_verification_method: record.authorized_verification_method,
        authorized_public_key_digest: record.authorized_public_key_digest,
        state_changed_at: record.state_changed_at,
        created_at: record.created_at,
        updated_at: record.updated_at,
    }
}

fn persistence_agent_pairing(
    record: soland_application::identity::AgentPairingState,
) -> soland_storage::AgentPrincipalRecord {
    soland_storage::AgentPrincipalRecord {
        id: record.id,
        controller_id: record.controller_id,
        principal_control_realm_id: record.principal_control_realm_id,
        controller_authorization_ref: record.controller_authorization_ref,
        display_name: record.display_name,
        agent_slug: record.agent_slug,
        avatar_blob_ref: record.avatar_blob_ref,
        state: record.state,
        requested_scope: record.requested_scope,
        accountability: record.accountability,
        provision_event_refs: record.provision_event_refs,
        pairing_request_id: record.pairing_request_id,
        paired_pairing_request_id: record.paired_pairing_request_id,
        paired_request_digest: record.paired_request_digest,
        pairing_code: record.pairing_code,
        pairing_expires_at: record.pairing_expires_at,
        approval_request_id: record.approval_request_id,
        controller_account_id: record.controller_account_id,
        recipient_service_id: record.recipient_service_id,
        runtime_key_binding_digest: record.runtime_key_binding_digest,
        runtime_public_key_digest: record.runtime_public_key_digest,
        runtime_attestation_digest: record.runtime_attestation_digest,
        approval_notification_id: record.approval_notification_id,
        runtime_key_request: record.runtime_key_request,
        approval_requested_at: record.approval_requested_at,
        authorized_event_ref: record.authorized_event_ref,
        authorized_verification_method: record.authorized_verification_method,
        authorized_public_key_digest: record.authorized_public_key_digest,
        state_changed_at: record.state_changed_at,
        created_at: record.created_at,
        updated_at: record.updated_at,
    }
}

#[async_trait::async_trait]
impl soland_application::identity::AgentParticipationPort for PersistenceAgentParticipation {
    async fn store_selection(
        &self,
        selection: serde_json::Value,
    ) -> soland_application::ApplicationResult<()> {
        self.0
            .agent_participation()
            .put_selection(selection)
            .await?;
        Ok(())
    }

    async fn selections(
        &self,
        agent_id: &str,
    ) -> soland_application::ApplicationResult<Vec<serde_json::Value>> {
        Ok(self
            .0
            .agent_participation()
            .list_selections(agent_id)
            .await?)
    }
}

#[async_trait::async_trait]
impl soland_application::identity::KeyBackupPort for PersistenceKeyBackups {
    async fn backup(
        &self,
        backup_id: &str,
    ) -> soland_application::ApplicationResult<Option<serde_json::Value>> {
        Ok(self.0.key_backups().get(backup_id).await?)
    }

    async fn backups_for_actor(
        &self,
        actor_id: &str,
    ) -> soland_application::ApplicationResult<Vec<serde_json::Value>> {
        Ok(self.0.key_backups().list_for_actor(actor_id).await?)
    }

    async fn store_backup(
        &self,
        backup_id: String,
        payload: serde_json::Value,
    ) -> soland_application::ApplicationResult<()> {
        self.0.key_backups().put(backup_id, payload).await?;
        Ok(())
    }

    async fn delete_backup(&self, backup_id: &str) -> soland_application::ApplicationResult<bool> {
        Ok(self.0.key_backups().delete(backup_id).await?)
    }
}

#[async_trait::async_trait]
impl soland_application::identity::SessionIdentityPort for PersistenceSessions {
    async fn session(
        &self,
        token_hash: &str,
    ) -> soland_application::ApplicationResult<
        Option<soland_application::identity::SessionIdentityState>,
    > {
        Ok(self
            .0
            .sessions()
            .get(token_hash)
            .await?
            .map(application_session_identity))
    }

    async fn sessions(
        &self,
    ) -> soland_application::ApplicationResult<
        Vec<soland_application::identity::SessionIdentityState>,
    > {
        Ok(self
            .0
            .sessions()
            .snapshot_all()
            .await?
            .into_iter()
            .map(application_session_identity)
            .collect())
    }

    async fn save_session(
        &self,
        session: soland_application::identity::SessionIdentityState,
    ) -> soland_application::ApplicationResult<()> {
        self.0
            .sessions()
            .put(&persistence_session_identity(session))
            .await?;
        Ok(())
    }

    async fn revoke_session(
        &self,
        token_hash: &str,
        revoked_at: chrono::DateTime<chrono::Utc>,
    ) -> soland_application::ApplicationResult<
        Option<soland_application::identity::SessionIdentityState>,
    > {
        let Some(mut session) = self.0.sessions().get(token_hash).await? else {
            return Ok(None);
        };
        if session.revoked_at.is_some() {
            return Ok(None);
        }
        session.revoked_at = Some(revoked_at);
        self.0.sessions().put(&session).await?;
        Ok(Some(application_session_identity(session)))
    }

    async fn revoke_actor_sessions(
        &self,
        actor_id: &str,
        revoked_at: chrono::DateTime<chrono::Utc>,
    ) -> soland_application::ApplicationResult<usize> {
        self.revoke_matching_sessions(actor_id, None, revoked_at)
            .await
    }

    async fn revoke_actor_device_sessions(
        &self,
        actor_id: &str,
        device_id: &str,
        revoked_at: chrono::DateTime<chrono::Utc>,
    ) -> soland_application::ApplicationResult<usize> {
        self.revoke_matching_sessions(actor_id, Some(device_id), revoked_at)
            .await
    }
}

impl PersistenceSessions {
    async fn revoke_matching_sessions(
        &self,
        actor_id: &str,
        device_id: Option<&str>,
        revoked_at: chrono::DateTime<chrono::Utc>,
    ) -> soland_application::ApplicationResult<usize> {
        let sessions = self.0.sessions().snapshot_all().await?;
        let mut count = 0;
        for mut session in sessions.into_iter().filter(|session| {
            session.actor == actor_id
                && session.revoked_at.is_none()
                && device_id.is_none_or(|device_id| session.device_id == device_id)
        }) {
            session.revoked_at = Some(revoked_at);
            self.0.sessions().put(&session).await?;
            count += 1;
        }
        Ok(count)
    }
}

fn application_session_identity(
    session: soland_storage::SessionRecord,
) -> soland_application::identity::SessionIdentityState {
    soland_application::identity::SessionIdentityState {
        token_hash: session.token_hash,
        actor_id: session.actor,
        device_id: session.device_id,
        audience: session.audience,
        session_public_key: session.session_public_key,
        agent_session: session.agent_session.map(|agent| {
            soland_application::identity::AgentSessionState {
                granted_scope: agent.granted_scope,
                scope_details: agent.scope_details,
                freshness_state: agent.freshness_state,
            }
        }),
        expires_at: session.expires_at,
        created_at: session.created_at,
        revoked_at: session.revoked_at,
    }
}

fn persistence_session_identity(
    session: soland_application::identity::SessionIdentityState,
) -> soland_storage::SessionRecord {
    soland_storage::SessionRecord {
        token_hash: session.token_hash,
        actor: session.actor_id,
        device_id: session.device_id,
        audience: session.audience,
        session_public_key: session.session_public_key,
        agent_session: session
            .agent_session
            .map(|agent| soland_storage::AgentSessionRecord {
                granted_scope: agent.granted_scope,
                scope_details: agent.scope_details,
                freshness_state: agent.freshness_state,
            }),
        expires_at: session.expires_at,
        created_at: session.created_at,
        revoked_at: session.revoked_at,
    }
}

fn application_recovery_policy(
    record: soland_storage::RecoveryPolicyRecord,
) -> soland_application::identity::RecoveryPolicyState {
    soland_application::identity::RecoveryPolicyState {
        policy_id: record.policy_id,
        principal_id: record.principal_id,
        version: record.version,
        trust_domain: record.trust_domain,
        allowed_proof_kinds: record.allowed_proof_kinds,
        supersedes: record.supersedes,
        expires_at: record.expires_at,
        issued_at: record.issued_at,
        raw_payload: record.raw_payload,
        accepted_at: record.accepted_at,
        verification_method: record.verification_method,
    }
}

fn persistence_recovery_policy(
    policy: soland_application::identity::RecoveryPolicyState,
) -> soland_storage::RecoveryPolicyRecord {
    soland_storage::RecoveryPolicyRecord {
        policy_id: policy.policy_id,
        principal_id: policy.principal_id,
        version: policy.version,
        trust_domain: policy.trust_domain,
        allowed_proof_kinds: policy.allowed_proof_kinds,
        supersedes: policy.supersedes,
        expires_at: policy.expires_at,
        issued_at: policy.issued_at,
        raw_payload: policy.raw_payload,
        accepted_at: policy.accepted_at,
        verification_method: policy.verification_method,
    }
}

#[async_trait::async_trait]
impl soland_application::identity::RecoveryPolicyPort for PersistenceRecoveryPolicies {
    async fn active_policy(
        &self,
        principal_id: &str,
    ) -> soland_application::ApplicationResult<
        Option<soland_application::identity::RecoveryPolicyState>,
    > {
        Ok(self
            .0
            .recovery_policies()
            .get_active_for_principal(principal_id)
            .await?
            .map(application_recovery_policy))
    }

    async fn policy_history(
        &self,
        principal_id: &str,
    ) -> soland_application::ApplicationResult<Vec<soland_application::identity::RecoveryPolicyState>>
    {
        Ok(self
            .0
            .recovery_policies()
            .list_for_principal(principal_id)
            .await?
            .into_iter()
            .map(application_recovery_policy)
            .collect())
    }

    async fn insert_policy(
        &self,
        policy: soland_application::identity::RecoveryPolicyState,
    ) -> soland_application::ApplicationResult<()> {
        self.0
            .recovery_policies()
            .insert(persistence_recovery_policy(policy))
            .await?;
        Ok(())
    }
}

fn application_recovery_receipt(
    record: soland_storage::RecoveryReceiptRecord,
) -> soland_application::identity::RecoveryReceiptState {
    soland_application::identity::RecoveryReceiptState {
        receipt_id: record.receipt_id,
        principal_id: record.principal_id,
        recovery_session_id: record.recovery_session_id,
        policy_id: record.policy_id,
        policy_version: record.policy_version,
        trust_domain: record.trust_domain,
        new_device_id: record.new_device_id,
        proof_digest: record.proof_digest,
        outcome: record.outcome,
        started_at: record.started_at,
        completed_at: record.completed_at,
        raw_payload: record.raw_payload,
        verification_method: record.verification_method,
        accepted_at: record.accepted_at,
    }
}

fn persistence_recovery_receipt(
    receipt: soland_application::identity::RecoveryReceiptState,
) -> soland_storage::RecoveryReceiptRecord {
    soland_storage::RecoveryReceiptRecord {
        receipt_id: receipt.receipt_id,
        principal_id: receipt.principal_id,
        recovery_session_id: receipt.recovery_session_id,
        policy_id: receipt.policy_id,
        policy_version: receipt.policy_version,
        trust_domain: receipt.trust_domain,
        new_device_id: receipt.new_device_id,
        proof_digest: receipt.proof_digest,
        outcome: receipt.outcome,
        started_at: receipt.started_at,
        completed_at: receipt.completed_at,
        raw_payload: receipt.raw_payload,
        verification_method: receipt.verification_method,
        accepted_at: receipt.accepted_at,
    }
}

#[async_trait::async_trait]
impl soland_application::identity::RecoveryReceiptPort for PersistenceRecoveryReceipts {
    async fn receipt_history(
        &self,
        principal_id: &str,
    ) -> soland_application::ApplicationResult<
        Vec<soland_application::identity::RecoveryReceiptState>,
    > {
        Ok(self
            .0
            .recovery_receipts()
            .list_for_principal(principal_id)
            .await?
            .into_iter()
            .map(application_recovery_receipt)
            .collect())
    }

    async fn insert_receipt(
        &self,
        receipt: soland_application::identity::RecoveryReceiptState,
    ) -> soland_application::ApplicationResult<()> {
        self.0
            .recovery_receipts()
            .insert(persistence_recovery_receipt(receipt))
            .await?;
        Ok(())
    }
}

fn application_recovery_session(
    record: soland_storage::RecoverySessionRecord,
) -> soland_application::identity::RecoverySessionState {
    soland_application::identity::RecoverySessionState {
        recovery_session_id: record.recovery_session_id,
        principal_id: record.principal_id,
        requesting_device_id: record.requesting_device_id,
        trust_domain: record.trust_domain,
        policy_id: record.policy_id,
        policy_version: record.policy_version,
        identity_model: record.identity_model,
        ssk_generation: record.ssk_generation,
        current_device_generation_ref: record.current_device_generation_ref,
        device_generation_status: record.device_generation_status,
        registry_head: record.registry_head,
        accepted_seal_frontier: record.accepted_seal_frontier,
        policy_payload: record.policy_payload,
        challenge: record.challenge,
        state: record.state,
        proof_payload: record.proof_payload,
        created_at: record.created_at,
        updated_at: record.updated_at,
        expires_at: record.expires_at,
    }
}

fn persistence_recovery_session(
    session: soland_application::identity::RecoverySessionState,
) -> soland_storage::RecoverySessionRecord {
    soland_storage::RecoverySessionRecord {
        recovery_session_id: session.recovery_session_id,
        principal_id: session.principal_id,
        requesting_device_id: session.requesting_device_id,
        trust_domain: session.trust_domain,
        policy_id: session.policy_id,
        policy_version: session.policy_version,
        identity_model: session.identity_model,
        ssk_generation: session.ssk_generation,
        current_device_generation_ref: session.current_device_generation_ref,
        device_generation_status: session.device_generation_status,
        registry_head: session.registry_head,
        accepted_seal_frontier: session.accepted_seal_frontier,
        policy_payload: session.policy_payload,
        challenge: session.challenge,
        state: session.state,
        proof_payload: session.proof_payload,
        created_at: session.created_at,
        updated_at: session.updated_at,
        expires_at: session.expires_at,
    }
}

#[async_trait::async_trait]
impl soland_application::identity::RecoverySessionPort for PersistenceRecoverySessions {
    async fn session(
        &self,
        recovery_session_id: &str,
    ) -> soland_application::ApplicationResult<
        Option<soland_application::identity::RecoverySessionState>,
    > {
        Ok(self
            .0
            .recovery_sessions()
            .get(recovery_session_id)
            .await?
            .map(application_recovery_session))
    }

    async fn insert_session(
        &self,
        session: soland_application::identity::RecoverySessionState,
    ) -> soland_application::ApplicationResult<()> {
        self.0
            .recovery_sessions()
            .insert(persistence_recovery_session(session))
            .await?;
        Ok(())
    }

    async fn update_session(
        &self,
        session: soland_application::identity::RecoverySessionState,
    ) -> soland_application::ApplicationResult<()> {
        self.0
            .recovery_sessions()
            .update(persistence_recovery_session(session))
            .await?;
        Ok(())
    }
}

fn application_did_document(
    record: soland_storage::WebvhDocumentRecord,
) -> soland_application::identity::DidDocumentState {
    soland_application::identity::DidDocumentState {
        did: record.did,
        did_document: record.did_document,
        key_log_head: record.key_log_head,
        seq: record.seq,
        method_evidence: record.method_evidence,
        fetched_at: record.fetched_at,
        expires_at: record.expires_at,
        updated_at: record.updated_at,
    }
}

fn persistence_did_document(
    record: soland_application::identity::DidDocumentState,
) -> soland_storage::WebvhDocumentRecord {
    soland_storage::WebvhDocumentRecord {
        did: record.did,
        did_document: record.did_document,
        key_log_head: record.key_log_head,
        seq: record.seq,
        method_evidence: record.method_evidence,
        fetched_at: record.fetched_at,
        expires_at: record.expires_at,
        updated_at: record.updated_at,
    }
}

fn application_did_log_event(
    record: soland_storage::WebvhLogRecord,
) -> soland_application::identity::DidLogEvent {
    soland_application::identity::DidLogEvent {
        event_digest: record.event_digest,
        did: record.did,
        seq: record.seq,
        operation: record.operation,
        created_at: record.created_at,
    }
}

fn persistence_did_log_event(
    record: soland_application::identity::DidLogEvent,
) -> soland_storage::WebvhLogRecord {
    soland_storage::WebvhLogRecord {
        event_digest: record.event_digest,
        did: record.did,
        seq: record.seq,
        operation: record.operation,
        created_at: record.created_at,
    }
}

#[async_trait::async_trait]
impl soland_application::identity::DidDocumentPort for PersistenceDidDocuments {
    async fn document(
        &self,
        did: &str,
    ) -> soland_application::ApplicationResult<Option<soland_application::identity::DidDocumentState>>
    {
        Ok(self
            .0
            .webvh()
            .get_document(did)
            .await?
            .map(application_did_document))
    }

    async fn embedded_document(
        &self,
        local_id: &str,
    ) -> soland_application::ApplicationResult<Option<soland_application::identity::DidDocumentState>>
    {
        Ok(self
            .0
            .webvh()
            .get_embedded_webvh_document_by_local_id(local_id)
            .await?
            .map(application_did_document))
    }

    async fn log_events(
        &self,
        did: &str,
    ) -> soland_application::ApplicationResult<Vec<soland_application::identity::DidLogEvent>> {
        Ok(self
            .0
            .webvh()
            .list_log_events(did)
            .await?
            .into_iter()
            .map(application_did_log_event)
            .collect())
    }

    async fn store_document(
        &self,
        document: soland_application::identity::DidDocumentState,
    ) -> soland_application::ApplicationResult<()> {
        self.0
            .webvh()
            .put_document(persistence_did_document(document))
            .await?;
        Ok(())
    }

    async fn append_log_event(
        &self,
        event: soland_application::identity::DidLogEvent,
    ) -> soland_application::ApplicationResult<()> {
        self.0
            .webvh()
            .append_log_event(persistence_did_log_event(event))
            .await?;
        Ok(())
    }

    async fn service_registration(
        &self,
        key: &arkret_sdk::ServiceRegistrationKey,
    ) -> soland_application::ApplicationResult<Option<arkret_sdk::ServiceRegistrationOutcome>> {
        Ok(self.0.webvh().get_service_registration(key).await?)
    }

    async fn commit_service_registration(
        &self,
        key: arkret_sdk::ServiceRegistrationKey,
        outcome: arkret_sdk::ServiceRegistrationOutcome,
        document: soland_application::identity::DidDocumentState,
        event: soland_application::identity::DidLogEvent,
    ) -> soland_application::ApplicationResult<
        soland_application::identity::ServiceRegistrationCommitResult,
    > {
        Ok(
            match self
                .0
                .webvh()
                .commit_service_registration(
                    key,
                    outcome,
                    persistence_did_document(document),
                    persistence_did_log_event(event),
                )
                .await?
            {
                soland_storage::ServiceRegistrationCommitOutcome::Created(outcome) => {
                    soland_application::identity::ServiceRegistrationCommitResult::Created(outcome)
                }
                soland_storage::ServiceRegistrationCommitOutcome::Existing(outcome) => {
                    soland_application::identity::ServiceRegistrationCommitResult::Existing(outcome)
                }
                soland_storage::ServiceRegistrationCommitOutcome::Conflict => {
                    soland_application::identity::ServiceRegistrationCommitResult::Conflict
                }
            },
        )
    }

    async fn commit_log_operation(
        &self,
        expected_current_head: Option<String>,
        document: soland_application::identity::DidDocumentState,
        event: soland_application::identity::DidLogEvent,
    ) -> soland_application::ApplicationResult<soland_application::identity::DidLogCommitResult>
    {
        Ok(
            match self
                .0
                .webvh()
                .commit_log_operation(
                    expected_current_head,
                    persistence_did_document(document),
                    persistence_did_log_event(event),
                )
                .await?
            {
                soland_storage::WebvhLogCommitOutcome::Accepted => {
                    soland_application::identity::DidLogCommitResult::Accepted
                }
                soland_storage::WebvhLogCommitOutcome::Duplicate => {
                    soland_application::identity::DidLogCommitResult::Duplicate
                }
                soland_storage::WebvhLogCommitOutcome::Conflict => {
                    soland_application::identity::DidLogCommitResult::Conflict
                }
            },
        )
    }
}

#[async_trait::async_trait]
impl soland_application::delivery::NotificationWritePort for PersistenceNotificationWriter {
    async fn store_notification(&self, record: Value) -> soland_application::ApplicationResult<()> {
        self.0.notifications().put(record).await?;
        Ok(())
    }

    async fn store_account_delta(
        &self,
        record: Value,
    ) -> soland_application::ApplicationResult<()> {
        self.0.notifications().put_account_delta(record).await?;
        Ok(())
    }

    async fn list_for_account(
        &self,
        controller_account_id: &str,
        recipient_service_id: &str,
        after_position: Option<i64>,
    ) -> soland_application::ApplicationResult<Vec<Value>> {
        Ok(self
            .0
            .notifications()
            .list_for_account(controller_account_id, recipient_service_id, after_position)
            .await?)
    }

    async fn list_for_recipient(
        &self,
        recipient_id: &str,
    ) -> soland_application::ApplicationResult<Vec<Value>> {
        Ok(self
            .0
            .notifications()
            .list_for_recipient(recipient_id)
            .await?)
    }
}

#[async_trait::async_trait]
impl soland_application::delivery::DeviceDeliveryPort for PersistenceDeviceDelivery {
    async fn purge_device_delivery(
        &self,
        actor_id: &str,
        device_id: &str,
    ) -> soland_application::ApplicationResult<
        soland_application::delivery::DeviceDeliveryPurgeResult,
    > {
        let to_device_messages_dropped = match self
            .0
            .device_messages()
            .purge(actor_id, device_id)
            .await
        {
            Ok(count) => count,
            Err(error) => {
                tracing::error!(%error, actor_id, device_id, "failed to purge to-device messages");
                0
            }
        };
        let push_registrations_removed = match self
            .0
            .push_devices()
            .unregister(actor_id, device_id, None, None)
            .await
        {
            Ok(count) => count,
            Err(error) => {
                tracing::error!(%error, actor_id, device_id, "failed to unregister push devices");
                0
            }
        };
        Ok(soland_application::delivery::DeviceDeliveryPurgeResult {
            to_device_messages_dropped,
            push_registrations_removed,
        })
    }

    async fn purge_stale_cross_signing_messages(
        &self,
        actor_id: &str,
        new_generation: u64,
    ) -> soland_application::ApplicationResult<usize> {
        Ok(self
            .0
            .device_messages()
            .purge_cross_signing_reset_stale_messages(actor_id, new_generation)
            .await?)
    }
}

fn application_device_message(
    record: soland_storage::DeviceMessageRecord,
) -> soland_application::delivery::DeviceMessageState {
    soland_application::delivery::DeviceMessageState {
        idempotency_key: record.idempotency_key,
        sender: record.sender,
        recipient: record.recipient,
        device_id: record.device_id,
        position: record.position,
        content: record.content,
        created_at: record.created_at,
    }
}

fn persistence_device_message(
    message: soland_application::delivery::DeviceMessageState,
) -> soland_storage::DeviceMessageRecord {
    soland_storage::DeviceMessageRecord {
        idempotency_key: message.idempotency_key,
        sender: message.sender,
        recipient: message.recipient,
        device_id: message.device_id,
        position: message.position,
        content: message.content,
        created_at: message.created_at,
    }
}

#[async_trait::async_trait]
impl soland_application::delivery::DeviceMessagePort for PersistenceDeviceMessages {
    async fn append(
        &self,
        message: soland_application::delivery::DeviceMessageState,
    ) -> soland_application::ApplicationResult<()> {
        self.0
            .device_messages()
            .append(persistence_device_message(message))
            .await?;
        Ok(())
    }

    async fn commit_batch(
        &self,
        batch: soland_storage::DeviceMessageBatchRecord,
    ) -> soland_application::ApplicationResult<soland_storage::DeviceMessageBatchCommitOutcome>
    {
        Ok(self.0.device_messages().commit_batch(batch).await?)
    }

    async fn inspect_batch(
        &self,
        request_key: &str,
        request_digest: &str,
        items: &[soland_storage::DeviceMessageIntentRecord],
    ) -> soland_application::ApplicationResult<soland_storage::DeviceMessageBatchInspection> {
        Ok(self
            .0
            .device_messages()
            .inspect_batch(request_key, request_digest, items)
            .await?)
    }

    async fn issue_ack_token(
        &self,
        recipient: &str,
        device_id: &str,
        queue_position: i64,
    ) -> soland_application::ApplicationResult<Option<String>> {
        Ok(self
            .0
            .device_messages()
            .issue_ack_token(recipient, device_id, queue_position)
            .await?)
    }

    async fn acknowledge(
        &self,
        recipient: &str,
        device_id: &str,
        ack_token: &str,
    ) -> soland_application::ApplicationResult<Option<usize>> {
        Ok(self
            .0
            .device_messages()
            .ack_with_token(recipient, device_id, ack_token)
            .await?)
    }

    async fn messages_after(
        &self,
        recipient: &str,
        device_id: &str,
        queue_position: i64,
    ) -> soland_application::ApplicationResult<Vec<soland_application::delivery::DeviceMessageState>>
    {
        Ok(self
            .0
            .device_messages()
            .list_after(recipient, device_id, queue_position)
            .await?
            .into_iter()
            .map(application_device_message)
            .collect())
    }

    async fn prune(
        &self,
        per_device_capacity: usize,
        now: chrono::DateTime<chrono::Utc>,
    ) -> soland_application::ApplicationResult<()> {
        self.0.device_messages().prune_expired(now).await?;
        self.0
            .device_messages()
            .prune_over_capacity(per_device_capacity, now)
            .await?;
        Ok(())
    }

    async fn lost_watermark(
        &self,
        recipient: &str,
        device_id: &str,
    ) -> soland_application::ApplicationResult<Option<i64>> {
        Ok(self
            .0
            .device_messages()
            .lost_watermark(recipient, device_id)
            .await?)
    }
}

fn application_accepted_event(
    record: soland_storage::CanonicalEventRecord,
) -> soland_application::events::AcceptedEvent {
    soland_application::events::AcceptedEvent {
        event_id: record.event_id,
        actor_id: record.actor_id,
        actor_seq: record.actor_seq,
        realm_id: record.realm_id,
        kind: record.kind,
        schema_id: record.schema_id,
        canonical_digest: record.canonical_digest,
        canonical_bytes: record.canonical_bytes,
        envelope: record.envelope,
        received_at: record.received_at,
    }
}

#[async_trait::async_trait]
impl soland_application::events::EventReadPort for PersistenceEventReader {
    async fn accepted_event(
        &self,
        event_id: &str,
    ) -> soland_application::ApplicationResult<Option<soland_application::events::AcceptedEvent>>
    {
        Ok(self
            .0
            .events()
            .get(event_id)
            .await?
            .map(application_accepted_event))
    }

    async fn accepted_events(
        &self,
    ) -> soland_application::ApplicationResult<Vec<soland_application::events::AcceptedEvent>> {
        Ok(self
            .0
            .events()
            .snapshot_all()
            .await?
            .into_iter()
            .map(application_accepted_event)
            .collect())
    }

    async fn projected_events(
        &self,
    ) -> soland_application::ApplicationResult<Vec<soland_application::events::ProjectedEvent>>
    {
        Ok(self
            .0
            .projection_events()
            .snapshot_all()
            .await?
            .into_iter()
            .map(|event| soland_application::events::ProjectedEvent {
                event_id: event.event_id,
                realm_id: event.realm_id,
                event_kind: event.event_kind,
                operation_type: event.operation_type,
                operation_id: event.operation_id,
                sender: event.sender,
                payload: event.payload,
                created_at: event.created_at,
                received_at: event.received_at,
            })
            .collect())
    }

    async fn accepted_events_for_actor(
        &self,
        actor_id: &str,
    ) -> soland_application::ApplicationResult<Vec<soland_application::events::AcceptedEvent>> {
        Ok(self
            .0
            .events()
            .list_for_actor(actor_id)
            .await?
            .into_iter()
            .map(application_accepted_event)
            .collect())
    }

    async fn max_actor_sequence(
        &self,
        actor_id: &str,
    ) -> soland_application::ApplicationResult<Option<u64>> {
        Ok(self.0.events().max_actor_seq(actor_id).await?)
    }

    async fn batch_receipts_for_event(
        &self,
        event_id: &str,
    ) -> soland_application::ApplicationResult<Vec<soland_application::events::AcceptedBatchReceipt>>
    {
        self.0
            .events()
            .batch_receipts_for_event(event_id)
            .await?
            .into_iter()
            .map(|receipt| {
                serde_json::to_value(receipt)
                    .map(|value| soland_application::events::AcceptedBatchReceipt { value })
                    .map_err(|error| {
                        soland_storage::PersistenceError::Internal(format!(
                            "event batch receipt serialization failed: {error}"
                        ))
                        .into()
                    })
            })
            .collect()
    }
}

#[async_trait::async_trait]
impl soland_application::events::MlsCommitReadPort for PersistenceMlsCommitReader {
    async fn commits(
        &self,
    ) -> soland_application::ApplicationResult<Vec<soland_application::events::MlsCommitState>>
    {
        Ok(self
            .0
            .mls_commits()
            .snapshot_all()
            .await?
            .into_iter()
            .map(|commit| soland_application::events::MlsCommitState {
                group_id: commit.group_id,
                effective_scope: commit.effective_scope,
                epoch: commit.epoch,
                frontier_contested: commit.frontier_contested,
            })
            .collect())
    }
}

#[async_trait::async_trait]
impl soland_application::events::MlsKeyPackageMaintenancePort
    for PersistenceMlsKeyPackageMaintenance
{
    async fn retire_actor_keypackages(
        &self,
        actor_id: &str,
        retired_at: i64,
    ) -> soland_application::ApplicationResult<usize> {
        let rows = self.0.mls_key_packages().snapshot_all().await?;
        let mut retired = 0;
        for row in rows.into_iter().filter(|row| {
            row.actor_id == actor_id
                && row.claimed_by_mls_group_id.is_none()
                && row.consumed_at.is_none()
        }) {
            if self
                .0
                .mls_key_packages()
                .try_claim(&row.id, "revoked", None, None, None, retired_at)
                .await?
                .is_some()
            {
                retired += 1;
            }
        }
        Ok(retired)
    }
}

#[async_trait::async_trait]
impl soland_application::events::RealmMetadataPort for PersistenceRealmMetadata {
    async fn realm_metadata(
        &self,
        realm_id: &str,
    ) -> soland_application::ApplicationResult<Option<soland_application::events::RealmMetadata>>
    {
        Ok(self.0.realm_meta().get(realm_id).await?.map(|metadata| {
            soland_application::events::RealmMetadata {
                realm_id: realm_id.to_owned(),
                owner_id: metadata.owner,
                discoverability: metadata.discoverability,
                history_visibility: metadata.history_visibility,
                deleted: metadata.deleted,
                created_at: metadata.created_at,
                updated_at: metadata.updated_at,
            }
        }))
    }

    async fn realm_metadata_list(
        &self,
    ) -> soland_application::ApplicationResult<Vec<soland_application::events::RealmMetadata>> {
        Ok(self
            .0
            .realm_meta()
            .list()
            .await?
            .into_iter()
            .map(
                |(realm_id, metadata)| soland_application::events::RealmMetadata {
                    realm_id,
                    owner_id: metadata.owner,
                    discoverability: metadata.discoverability,
                    history_visibility: metadata.history_visibility,
                    deleted: metadata.deleted,
                    created_at: metadata.created_at,
                    updated_at: metadata.updated_at,
                },
            )
            .collect())
    }
}

#[async_trait::async_trait]
impl soland_application::events::RealmInvitePort for PersistenceRealmInvites {
    async fn get(
        &self,
        invite_id: &str,
    ) -> soland_application::ApplicationResult<Option<soland_storage::RealmInviteRecord>> {
        Ok(self.0.realm_invites().get(invite_id).await?)
    }

    async fn put(
        &self,
        record: soland_storage::RealmInviteRecord,
    ) -> soland_application::ApplicationResult<()> {
        Ok(self.0.realm_invites().put(record).await?)
    }

    async fn snapshot_all(
        &self,
    ) -> soland_application::ApplicationResult<Vec<soland_storage::RealmInviteRecord>> {
        Ok(self.0.realm_invites().snapshot_all().await?)
    }
}

#[async_trait::async_trait]
impl soland_storage::EventCommitUnitOfWork for PersistenceEventCommitter {
    async fn commit_event(
        &self,
        request: soland_storage::EventCommitRequest,
    ) -> soland_storage::PersistenceResult<soland_storage::EventCommitOutcome> {
        self.0.commit_event(request).await
    }
}

fn account_lifecycle_status_from_wire(value: &str) -> AccountStatus {
    match value {
        "erased" => AccountStatus::ErasurePending,
        _ => AccountStatus::from_wire(value).unwrap_or_else(|| {
            tracing::warn!(state = value, "unknown account lifecycle state");
            AccountStatus::Suspended
        }),
    }
}

/// Fill `out` with cryptographically secure random bytes via `rand::rng`.
/// Used by service-identity bootstrap and development admin-key provisioning.
pub(crate) fn getrandom_seed(out: &mut [u8; 32]) {
    use rand::RngExt;
    rand::rng().fill(out);
}

#[cfg(test)]
mod membership_hydration_tests {
    use arkret_sdk::{Did, RealmId};
    use soland_storage::{
        EventProjectionStoreRegistry, IdentityStoreRegistry, MlsAgentStoreRegistry,
    };

    use super::*;

    #[test]
    fn app_state_uses_the_bootstrap_resolved_signing_seed() {
        let config = AppConfig::test_default();
        let identity = development_fixture_service_identity(&config);
        let persistence: Arc<dyn PersistenceStore> = Arc::new(SolandMemoryPersistenceStore::new());
        let resolved_seed = [0xa5; 32];

        let state = AppState::new_with_service_identity(
            config,
            Db { pool: None },
            persistence,
            identity,
            resolved_seed,
        );

        assert_eq!(state.notary_signing_key().to_bytes(), resolved_seed);
    }

    fn member_state_event(realm_id: &str, member: &str, membership: &str) -> CanonicalEventRecord {
        CanonicalEventRecord {
            event_id: format!("ak:event:{member}-{membership}"),
            actor_id: member.to_owned(),
            actor_seq: 1,
            realm_id: Some(realm_id.to_owned()),
            kind: "ak.member.state".to_owned(),
            schema_id: String::new(),
            canonical_digest: String::new(),
            canonical_bytes: Vec::new(),
            envelope: serde_json::json!({
                "realm_id": realm_id,
                "payload": { "membership": membership, "actor_id": member },
            }),
            received_at: chrono::DateTime::<chrono::Utc>::from_timestamp(0, 0).unwrap(),
        }
    }

    fn directory_with_creator(realm_id: &RealmId, creator: &Did) -> RealmDirectoryIndex {
        let mut realms = RealmDirectoryIndex::new();
        let mut entry = RealmDirectoryEntry::new(realm_id.clone(), "Hydration Test Realm");
        entry.members.insert(creator.clone());
        realms.upsert(entry);
        realms
    }

    // Regression: a joined invitee's `ak.member.state{join}` MUST be replayed
    // into the realm directory on boot. Without it the admin's synced roster
    // shows only the creator, admin-side MLS admission never fires, and the
    // invitee is stuck "waiting for a Welcome" after every restart.
    #[test]
    fn joined_member_survives_directory_hydration() {
        let realm_id = RealmId::new("ak:realm:019f0dd3-081c-7f03-b388-e0399e7759fc".to_owned())
            .expect("realm id");
        let creator = Did::new("did:web:alice.example".to_owned()).expect("creator did");
        let invitee = Did::new("did:web:bob.example".to_owned()).expect("invitee did");

        let mut realms = directory_with_creator(&realm_id, &creator);
        // Before replay: only the creator is present (the realm.create seed).
        assert_eq!(realms.get(&realm_id).unwrap().members.len(), 1);

        hydrate_realm_member_state_event(
            &mut realms,
            &member_state_event(realm_id.as_str(), invitee.as_str(), "join"),
        );

        let members = &realms.get(&realm_id).unwrap().members;
        assert!(
            members.contains(&invitee),
            "joined invitee must survive directory hydration"
        );
        assert!(members.contains(&creator));
        assert_eq!(members.len(), 2);
    }

    #[test]
    fn left_member_is_dropped_on_directory_hydration() {
        let realm_id = RealmId::new("ak:realm:019f0dd3-081c-7f03-b388-e0399e7759fc".to_owned())
            .expect("realm id");
        let creator = Did::new("did:web:alice.example".to_owned()).expect("creator did");
        let invitee = Did::new("did:web:bob.example".to_owned()).expect("invitee did");

        let mut realms = directory_with_creator(&realm_id, &creator);
        hydrate_realm_member_state_event(
            &mut realms,
            &member_state_event(realm_id.as_str(), invitee.as_str(), "join"),
        );
        hydrate_realm_member_state_event(
            &mut realms,
            &member_state_event(realm_id.as_str(), invitee.as_str(), "leave"),
        );

        let members = &realms.get(&realm_id).unwrap().members;
        assert!(!members.contains(&invitee), "left member must be removed");
        assert!(members.contains(&creator));
    }

    // `invite`/`knock` are not directory member-set transitions (they live in
    // the structured membership projection), so they must not add a directory
    // member during hydration.
    #[test]
    fn invite_state_does_not_add_directory_member() {
        let realm_id = RealmId::new("ak:realm:019f0dd3-081c-7f03-b388-e0399e7759fc".to_owned())
            .expect("realm id");
        let creator = Did::new("did:web:alice.example".to_owned()).expect("creator did");
        let invitee = Did::new("did:web:bob.example".to_owned()).expect("invitee did");

        let mut realms = directory_with_creator(&realm_id, &creator);
        hydrate_realm_member_state_event(
            &mut realms,
            &member_state_event(realm_id.as_str(), invitee.as_str(), "invite"),
        );

        let members = &realms.get(&realm_id).unwrap().members;
        assert!(!members.contains(&invitee));
        assert_eq!(members.len(), 1);
    }

    // Regression: the MLS KeyPackage + commit-epoch projections — which the
    // claim selector and the commit-epoch CAS read ONLY from memory — MUST be
    // rebuilt from their durable tables on boot, or a restart strands every
    // pending admission (admin can't claim the invitee's KeyPackage; add-member
    // commit is rejected for "no genesis").
    #[tokio::test]
    async fn mls_projections_rehydrate_from_durable_stores() {
        use soland_storage::MlsKeyPackageRow;

        let realm_id = "ak:realm:019f0dd3-081c-7f03-b388-e0399e7759fc";
        let group_id = "ak:mls_group:019f0dd3-aaaa";
        let store = SolandMemoryPersistenceStore::new();

        store
            .mls_key_packages()
            .put(&MlsKeyPackageRow {
                id: "ak:mls_keypackage:01".to_owned(),
                keypackage_ref: "sha256:ref".to_owned(),
                keypackage_digest: "sha256:digest".to_owned(),
                actor_id: "did:web:bob.example".to_owned(),
                device_id: "ak:device:bob-1".to_owned(),
                key_package_bytes: vec![1, 2, 3],
                capabilities: vec!["ak.content.v1".to_owned()],
                capabilities_digest: "sha256:caps".to_owned(),
                device_signature: serde_json::json!({}),
                last_resort: true,
                last_resort_realm_id: Some(realm_id.to_owned()),
                lifetime_not_before: 0,
                lifetime_not_after: i64::MAX,
                claimed_by_mls_group_id: None,
                ssk_generation: None,
                device_authorize_event_id: Some("ak:event:auth".to_owned()),
                consumed_at: None,
                created_at: 1,
            })
            .await
            .expect("put keypackage");

        let effective_scope = serde_json::json!({ "kind": "realm", "realm_id": realm_id });
        let governance_binding = serde_json::json!({ "policy_root": "sha256:locked-root" });
        store
            .mls_commits()
            .initialize_genesis(
                &effective_scope,
                group_id,
                "did:web:alice.example",
                &[],
                &governance_binding,
                1,
            )
            .await
            .expect("init genesis");

        let mut proj = ProjectionState::new();
        let authz = SolandAuthzEngine::new();
        hydrate_projections_from_persistence(&store, &mut proj, &authz)
            .await
            .expect("hydrate projections");

        // KeyPackage projection is rebuilt → the claim selector can find it.
        let kp = proj
            .mls_key_packages
            .get("ak:mls_keypackage:01")
            .expect("keypackage rehydrated");
        assert_eq!(kp.actor_id, "did:web:bob.example");
        assert!(kp.last_resort);
        assert!(kp.claimed_by.is_none());

        // Commit-epoch projection is rebuilt with the genesis-locked policy_root
        // → the add-member commit's governance binding check passes.
        let key = soland_domain::reducer::MlsCommitEpochKey::new(
            soland_domain::reducer::mls::effective_scope_key(&effective_scope).unwrap(),
            group_id.to_owned(),
        );
        let epoch = proj
            .mls_commit_epochs
            .get(&key)
            .expect("commit epoch rehydrated");
        assert_eq!(epoch.epoch, 0);
        assert_eq!(epoch.policy_root, "sha256:locked-root");
    }

    #[test]
    fn child_scope_policy_hydration_uses_the_sdk_wire_type_and_fails_closed() {
        let circle_id = "ak:circle:0196419b-0000-7000-8000-000000000003";
        assert_eq!(
            hydration::parse_child_scope_policy(None, None).unwrap(),
            None
        );
        assert_eq!(
            hydration::parse_child_scope_policy(Some("require_scope_circle_id"), Some(circle_id))
                .unwrap(),
            Some(arkret_sdk::ChildScopePolicy::RequireScopeCircleId {
                scope_circle_id: arkret_sdk::CircleId::new(circle_id.to_owned()).unwrap(),
            })
        );
        assert!(hydration::parse_child_scope_policy(Some("allow_any"), Some(circle_id)).is_err());
        assert!(
            hydration::parse_child_scope_policy(Some("require_scope_circle_id"), None).is_err()
        );
        assert!(hydration::parse_child_scope_policy(Some("legacy_policy"), None).is_err());
        assert!(hydration::parse_child_scope_policy(None, Some(circle_id)).is_err());
    }

    #[tokio::test]
    async fn key_backup_active_series_rehydrates_from_projection_events() {
        use soland_storage::{ProjectionEventAppendOutcome, ProjectionEventRecord};

        let store = SolandMemoryPersistenceStore::new();
        let actor = "did:web:alice.example";
        let realm_id = "ak:realm:019f0dd3-081c-7f03-b388-e0399e7759fc";
        let series_id = "ak:backup_series:019f0dd3-081c-7f03-b388-e0399e775901";
        let now = chrono::Utc::now();
        let appended = store
            .projection_events()
            .append(ProjectionEventRecord {
                event_id: "ak:event:019f0dd3-081c-7f03-b388-e0399e775902".to_owned(),
                realm_id: realm_id.to_owned(),
                event_kind: arkret_sdk::events::EventKind::KEY_BACKUP_ACTIVE_SERIES.to_owned(),
                operation_type: "event".to_owned(),
                operation_id: Some(
                    "ak:operation:019f0dd3-081c-7f03-b388-e0399e775903".to_owned(),
                ),
                sender: Some(actor.to_owned()),
                payload: serde_json::json!({
                    "schema": "ak.schema.key_backup_active_series.v1",
                    "actor_id": actor,
                    "backup_class": "mls_history",
                    "active_series_id": series_id,
                    "series_pointer_version": 1,
                    "previous_series_ids": [],
                    "frontier_ref": {
                        "frontier_digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                        "seal_ref": "ak:seal:sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                        "ssk_generation": 1
                    },
                    "issued_at": "2026-07-18T00:00:00Z",
                    "auth_data": {
                        "verification_method": "did:web:alice.example#device-key",
                        "signature_algorithm": "Ed25519",
                        "signature": "AA",
                        "signed_fields": [
                            "schema",
                            "actor_id",
                            "backup_class",
                            "active_series_id",
                            "series_pointer_version",
                            "previous_series_ids",
                            "frontier_ref",
                            "issued_at"
                        ],
                        "ssk_generation": 1
                    }
                }),
                created_at: now,
                received_at: now,
            })
            .await
            .expect("append active-series projection event");
        assert_eq!(appended, ProjectionEventAppendOutcome::Inserted);

        let mut proj = ProjectionState::new();
        hydrate_projections_from_persistence(&store, &mut proj, &SolandAuthzEngine::new())
            .await
            .expect("hydrate active-series projection");

        let pointer = proj
            .key_backup_active_series(actor, "mls_history")
            .expect("active-series pointer rehydrated");
        assert_eq!(pointer.active_series_id, series_id);
        assert_eq!(pointer.series_pointer_version, 1);

        store
            .projection_events()
            .append(ProjectionEventRecord {
                event_id: "ak:event:019f0dd3-081c-7f03-b388-e0399e775904".to_owned(),
                realm_id: realm_id.to_owned(),
                event_kind: arkret_sdk::events::EventKind::KEY_BACKUP_ACTIVE_SERIES.to_owned(),
                operation_type: "event".to_owned(),
                operation_id: Some(
                    "ak:operation:019f0dd3-081c-7f03-b388-e0399e775905".to_owned(),
                ),
                sender: Some(actor.to_owned()),
                payload: serde_json::json!({
                    "schema": "ak.schema.key_backup_active_series.v1",
                    "actor_id": actor,
                    "backup_class": "mls_history",
                    "active_series_id": series_id,
                    "series_pointer_version": 3,
                    "previous_series_ids": [],
                    "frontier_ref": {
                        "frontier_digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                        "ssk_generation": 1
                    },
                    "issued_at": "2026-07-18T00:01:00Z",
                    "auth_data": {
                        "verification_method": "did:web:alice.example#device-key",
                        "signature_algorithm": "Ed25519",
                        "signature": "AA",
                        "signed_fields": [
                            "schema", "actor_id", "backup_class", "active_series_id",
                            "series_pointer_version", "previous_series_ids", "frontier_ref",
                            "issued_at"
                        ],
                        "ssk_generation": 1
                    }
                }),
                created_at: now,
                received_at: now,
            })
            .await
            .expect("append invalid gap projection event");
        let mut poisoned = ProjectionState::new();
        assert!(
            hydrate_projections_from_persistence(&store, &mut poisoned, &SolandAuthzEngine::new(),)
                .await
                .is_err(),
            "hydration must fail closed on a durable active-series gap"
        );
    }

    #[tokio::test]
    async fn agent_key_authorization_rehydrates_from_projection_events() {
        use soland_storage::{ProjectionEventAppendOutcome, ProjectionEventRecord};

        let store = SolandMemoryPersistenceStore::new();
        let agent_id =
            "did:webvh:z6mkfixture:example.test:webvh:agent:019f0dd3-081c-7f03-b388-e0399e775901";
        let realm_id = "ak:realm:019f0dd3-081c-7f03-b388-e0399e775902";
        let event_id = "ak:event:019f0dd3-081c-7f03-b388-e0399e775903";
        let key_id = format!("{agent_id}#runtime-1");
        let replacement_event_id = "ak:event:019f0dd3-081c-7f03-b388-e0399e775907";
        let replacement_key_id = format!("{agent_id}#runtime-2");
        let now = chrono::Utc::now();
        let appended = store
            .projection_events()
            .append(ProjectionEventRecord {
                event_id: event_id.to_owned(),
                realm_id: realm_id.to_owned(),
                event_kind: arkret_sdk::events::EventKind::AGENT_KEY_AUTHORIZE.to_owned(),
                operation_type: "event".to_owned(),
                operation_id: Some("ak:operation:019f0dd3-081c-7f03-b388-e0399e775904".to_owned()),
                sender: Some(agent_id.to_owned()),
                payload: serde_json::json!({
                    "agent_id": agent_id,
                    "key_id": key_id,
                    "accepted_event_id": event_id
                }),
                created_at: now,
                received_at: now,
            })
            .await
            .expect("append agent-key authorization projection event");
        assert_eq!(appended, ProjectionEventAppendOutcome::Inserted);
        store
            .projection_events()
            .append(ProjectionEventRecord {
                event_id: "ak:event:019f0dd3-081c-7f03-b388-e0399e775905".to_owned(),
                realm_id: realm_id.to_owned(),
                event_kind: arkret_sdk::events::EventKind::AGENT_KEY_REVOKE.to_owned(),
                operation_type: "event".to_owned(),
                operation_id: Some("ak:operation:019f0dd3-081c-7f03-b388-e0399e775906".to_owned()),
                sender: Some(agent_id.to_owned()),
                payload: serde_json::json!({
                    "agent_id": agent_id,
                    "key_id": key_id
                }),
                created_at: now,
                received_at: now,
            })
            .await
            .expect("append agent-key revocation projection event");
        store
            .projection_events()
            .append(ProjectionEventRecord {
                event_id: replacement_event_id.to_owned(),
                realm_id: realm_id.to_owned(),
                event_kind: arkret_sdk::events::EventKind::AGENT_KEY_AUTHORIZE.to_owned(),
                operation_type: "event".to_owned(),
                operation_id: Some("ak:operation:019f0dd3-081c-7f03-b388-e0399e775908".to_owned()),
                sender: Some(agent_id.to_owned()),
                payload: serde_json::json!({
                    "agent_id": agent_id,
                    "key_id": replacement_key_id,
                    "accepted_event_id": replacement_event_id
                }),
                created_at: now,
                received_at: now,
            })
            .await
            .expect("append replacement agent-key authorization projection event");

        let mut proj = ProjectionState::new();
        assert!(!proj.agent_has_authorized_key(agent_id));
        hydrate_projections_from_persistence(&store, &mut proj, &SolandAuthzEngine::new())
            .await
            .expect("hydrate agent-key authorization");

        assert!(proj.agent_has_authorized_key(agent_id));
        assert_eq!(
            proj.active_agent_key_authorizations(agent_id),
            vec![(replacement_key_id, replacement_event_id.to_owned())]
        );
    }

    #[tokio::test]
    async fn realm_owner_rehydrates_for_capability_upper_bound_checks() {
        use soland_storage_memory::SolandMemoryPersistenceStore;

        let realm_id = "ak:realm:019f0dd3-081c-7f03-b388-e0399e7759fc";
        let owner = "did:webvh:z6mkfixture:example.test:users:alice";
        let now = chrono::Utc::now();
        let store = SolandMemoryPersistenceStore::new();
        store
            .realm_meta()
            .put(
                realm_id,
                &RealmMetaRecord {
                    owner: owner.to_owned(),
                    deleted: false,
                    discoverability: "invite_only".to_owned(),
                    history_visibility: "shared".to_owned(),
                    history_sharing_policy: None,
                    history_sharing_policy_digest: None,
                    preview_policy: None,
                    preview_policy_digest: None,
                    asset_privacy_policy: None,
                    asset_privacy_policy_digest: None,
                    encryption_profile: None,
                    plaintext_visible_services: BTreeSet::new(),
                    plaintext_visible_service_classes: BTreeMap::new(),
                    minimal_metadata_realm: false,
                    created_at: now,
                    updated_at: now,
                },
            )
            .await
            .expect("put realm metadata");

        let mut proj = ProjectionState::new();
        hydrate_projections_from_persistence(&store, &mut proj, &SolandAuthzEngine::new())
            .await
            .expect("hydrate projections");

        let hydrated = proj.realm_states.get(realm_id).expect("realm rehydrated");
        assert_eq!(hydrated.owner.as_deref(), Some(owner));
        assert!(proj.issuer_has_projected_capability(
            owner,
            realm_id,
            "ak.message.create",
            realm_id,
        ));
    }
}
