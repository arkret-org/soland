use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use arc_swap::ArcSwap;
use cokret_sdk::identity::CompositeDidResolver;
use cokret_sdk::state_res::{CellRegistry, CellStore, MoveStore, SealStore};
use cokret_sdk::{AccountRegistrationPolicy, AccountStatus, AppletPackage, Did, RealmId};
use ed25519_dalek::SigningKey;
use serde_json::Value;
use sha2::{Digest, Sha256};

use super::did_resolver_chain;
use super::member_identity::MemberIdentityRegistry;
use super::notification::{EventBroadcast, Mutex, SubscribeReconnectGate};
use super::realm_directory::{RealmDirectoryEntry, RealmDirectoryIndex};
use super::records::{
    ACCOUNT_LOCKOUT_DURATION, ACCOUNT_LOCKOUT_THRESHOLD, ACCOUNT_LOCKOUT_WINDOW,
    AccountLifecycleRecord, AccountRecord, CanonicalEventRecord, ConsentCellKey, ConsentCellRecord,
    CursorRevocation, DirectConversationBindingRecord, FailedLoginRecord,
    KEY_BACKUP_DOWNLOAD_WINDOW, KeyBackupDownloadOutcome, KeyBackupDownloadRecord,
    MODERATION_FRANKING_REPLAY_MAX_ENTRIES, MODERATION_FRANKING_REPLAY_WINDOW_SECS,
    MODERATION_REPORT_MAX_PER_REPORTER_REALM_WINDOW,
    MODERATION_REPORT_MAX_PER_REPORTER_TARGET_WINDOW, MODERATION_REPORT_MAX_PER_REPORTER_WINDOW,
    MODERATION_REPORT_MAX_PER_SOURCE_IP_WINDOW, MODERATION_REPORT_MAX_PER_SOURCE_SERVICE_WINDOW,
    MODERATION_REPORT_RATE_WINDOW_SECS, ModerationFrankingReplayRecord,
    ModerationReportRateOutcome, ModerationReportRateRecord, OrganizationPolicyRecord,
    OrganizationRecord, PSI_HIT_BUCKET_SECS, PSI_PROBE_MAX_PER_WINDOW, PSI_PROBE_WINDOW,
    PsiProbeOutcome, PsiProbeRecord, RealmMetaRecord, RealmModerationPolicyRecord,
    RetentionPolicyRecord, RetentionTombstoneRecord, SovereignDeploymentState,
};
use crate::authz::SolandAuthzEngine;
use crate::config::{AppConfig, NotarySigningKeyOrigin};
use crate::db::Db;
use crate::hlc::ServerHlc;
use crate::object_storage::{ObjectStorage, build_object_storage};
use crate::persistence::{
    PersistenceResult, PersistenceStore, PgPersistenceStore, SolandMemoryPersistenceStore,
};
use crate::reducer::ProjectionState;
use crate::verified_profiles::VerifiedProfileDescriptor;

/// Single-process service state. Every long-lived data surface lives behind
/// `persistence` (a `dyn PersistenceStore`); the few remaining fields are
/// either non-record state (config, db pool, hlc, authz engine) or runtime
/// facets that don't fit the trait shape (in-memory `RealmDirectoryIndex`,
/// `CompositeDidResolver`, `ProjectionState`).
#[derive(Clone)]
pub struct AppState {
    pub config: AppConfig,
    pub db: Db,
    pub persistence: Arc<dyn PersistenceStore>,
    pub object_storage: Arc<dyn ObjectStorage>,
    pub hlc: ServerHlc,
    pub projection: Arc<Mutex<ProjectionState>>,
    pub authz: SolandAuthzEngine,
    pub realms: Arc<Mutex<RealmDirectoryIndex>>,
    /// Cross-signing state machine (PSK→SSK/USK publishes + device trust
    /// chains), per spec crypto-media/device-lifecycle.md §5. Fed by the
    /// projector when `ck.cross_signing.publish` lands, and read when verifying
    /// a `ck.device.authorize` `cross_signing_binding`. In-memory like the other
    /// reducer projections; durable rehydration rides on the durable event
    /// store (control-realm Phase 3).
    pub cross_signing: Arc<Mutex<cokret_sdk::DeviceManager>>,
    /// Process-local replay fence for consumed cross-signing reset
    /// `(principal_id, previous_generation)` tuples.
    pub cross_signing_reset_replays:
        Arc<Mutex<BTreeMap<(String, u64), chrono::DateTime<chrono::Utc>>>>,
    /// Handle release ledger keyed by bare localpart. The map is hydrated
    /// from `persistence.handle_releases()` and write-through updates keep
    /// post-release grace state durable across restarts.
    pub handle_releases: Arc<Mutex<BTreeMap<String, chrono::DateTime<chrono::Utc>>>>,
    /// Account lifecycle state projection keyed by actor DID. Missing rows
    /// mean `active`; non-active rows gate auth/session issuance and directory
    /// visibility. Hydrated from `persistence.account_lifecycle()` at boot.
    pub account_lifecycle: Arc<Mutex<BTreeMap<String, AccountLifecycleRecord>>>,
    /// In-memory failed-auth counter, keyed by actor DID.
    /// Spec: A.3 — auth handlers (`/_soland/gate/auth/dev-login`,
    /// `/_cokret/gate/account/session-grants`) bump the counter on failure; once it
    /// crosses `ACCOUNT_LOCKOUT_THRESHOLD` (5) within the active window
    /// the actor is locked out for `ACCOUNT_LOCKOUT_DURATION` (15 min).
    /// A successful login clears the row. Durable storage lands with
    /// the account-state projection.
    pub failed_login_attempts: Arc<Mutex<BTreeMap<String, FailedLoginRecord>>>,
    /// Deployment-local account registration policy. It uses the canonical
    /// account-operation DTO so the HTTP handler, audit payload, tests, and a
    /// future admin policy cell all speak the same wire vocabulary.
    pub account_registration_policy: Arc<Mutex<AccountRegistrationPolicy>>,
    /// Process-local registration attempt counters keyed by principal DID.
    /// This is the account-registration-specific quota; the generic HTTP rate
    /// limiter still protects the route by source address.
    pub account_registration_rate_tracker:
        Arc<Mutex<BTreeMap<String, (chrono::DateTime<chrono::Utc>, u32)>>>,
    /// SEC-09 — per-`(requester_did, holder_did)` PSI / contact-discovery
    /// probe counters; backs the timing-side-channel rate limit in
    /// `directory::private_contact_discovery`.
    pub psi_probe_tracker: Arc<Mutex<BTreeMap<(String, String), PsiProbeRecord>>>,
    /// Spec `identity/key-management.md` §7.8 — per-principal rolling-24h
    /// counter of full-ciphertext key-backup downloads; backs the
    /// anti-bulk-dump quota in `identity::key_backup::unlock_key_backup`.
    /// In-memory like the other limiters; a restart resets the window.
    pub key_backup_download_tracker: Arc<Mutex<BTreeMap<String, KeyBackupDownloadRecord>>>,
    /// Per-scope moderation report quotas keyed by bucket labels. The
    /// canonical report endpoint is an abuse-amplifiable write path, so it
    /// carries a local rolling limiter in addition to the generic HTTP class
    /// limiter.
    pub moderation_report_rate_tracker: Arc<Mutex<BTreeMap<String, ModerationReportRateRecord>>>,
    /// Bounded franking proof replay nonce ledger. Entries are process-local
    /// and intentionally finite; stale or excess nonces are evicted before new
    /// inserts.
    pub moderation_franking_replay_nonces:
        Arc<Mutex<BTreeMap<String, ModerationFrankingReplayRecord>>>,
    /// Process-local single-use approval nonce ledger for native-agent
    /// act-on-behalf publishes. Durable controller approval state lives in the
    /// projection; this table prevents replay within the approval TTL.
    pub agent_approval_nonces: Arc<Mutex<BTreeMap<String, chrono::DateTime<chrono::Utc>>>>,
    /// Per-actor notifications read marker. `mark_all_read(actor)` writes
    /// `Utc::now()`; the notifications read-side filter uses it to flag
    /// rows as read. Same in-memory shape as the other two.
    pub notification_read_cursors: Arc<Mutex<BTreeMap<String, chrono::DateTime<chrono::Utc>>>>,
    /// Domain-separated HMAC key for the deterministic stateful sync-cursor
    /// handle (`routing/events/sync.rs::derive_cursor_handle`). The handle
    /// binding rows themselves live in the durable
    /// `persistence.sync_cursors()` table, so a restart no longer invalidates
    /// every client's resume cursor.
    pub sync_cursor_hmac_key: [u8; 32],
    /// Domain-separated root key for service-scoped push target pseudonyms.
    /// Per-epoch keys are derived from this root inside the push routing
    /// module; only public epoch labels are exposed on describe.
    pub push_target_hmac_key: [u8; 32],
    /// Revoked cursor authorities (`ck.self.account.command.revoke_cursor`). High-assurance
    /// optional endpoint: a revoked cursor returns `cursor_revoked` and MUST NOT
    /// advance to-device ack, account-subscribe resume position, wait-for barrier
    /// state, or dropped-recovery state. Entries are pruned once the revoked
    /// cursor's maximum TTL has elapsed (`CursorRevocation::expires_at`).
    /// This vector is a read cache over the durable
    /// `persistence.sync_cursors()` revocation ledger
    /// (`sync_cursor_revocations` table): the revoke endpoint writes the
    /// ledger first (fail-closed) and [`AppState::hydrate`] reloads active
    /// rows at boot, so a restart cannot resurrect a revoked cursor.
    pub sync_cursor_revocations: Arc<Mutex<Vec<CursorRevocation>>>,
    /// Monotonic position allocator for to-device queues. Cursor ack uses
    /// numeric `position <= ack_position` pruning, so positions must advance
    /// even when multiple fanout writes land in the same wall-clock microsecond.
    pub to_device_position_counter: Arc<AtomicI64>,
    /// Holder-private consent cell projection keyed by
    /// `(holder_did, peer_did, scope)`. This is the minimal G3.S4
    /// reducer cache that backs `/_soland/self/consent/cells/*` and the contact
    /// gate; durable Move/Seal cell hydration can replace the backing map
    /// without changing the routing contract.
    pub consent_cells: Arc<Mutex<BTreeMap<ConsentCellKey, ConsentCellRecord>>>,
    /// Per-subject private `invite_receive_policy` overrides keyed by the
    /// subject (holder) DID. Spec `sync/invite-addressing.md` §5 — the policy
    /// is subject/private state and MUST NOT enter the durable Realm event
    /// log; the in-memory map is the bounded fallback until durable holder
    /// state hydration lands. Subjects without an entry fall back to the
    /// recommended default policy. `ck.self.contact.command.tombstone(block_peer)`
    /// writes the peer DID into the holder entry's `blocked_subjects`.
    pub invite_receive_policies: Arc<Mutex<BTreeMap<String, cokret_sdk::InviteReceivePolicy>>>,
    /// Direct conversation binding projection keyed by sorted participant DID
    /// pair. This is the bounded server-side fallback for
    /// `ck.self.direct_conversation.command.resolve` until signed
    /// `ck.direct_conversation.bound` event projection is fully wired.
    pub direct_conversation_bindings: Arc<Mutex<BTreeMap<String, DirectConversationBindingRecord>>>,
    /// Runtime state for sovereign-main / enclave deployment handshakes,
    /// trust-root decisions, boundary audit, and store-and-forward queues.
    /// The P2-056 implementation keeps this in memory so the dual-soland
    /// conformance harness can exercise the protocol shape locally; a durable
    /// store can replace the backing map without changing the HTTP contract.
    pub sovereign_deployment: Arc<Mutex<SovereignDeploymentState>>,
    /// Per-Realm retention policy projection. Hydrated from durable
    /// `retention_policies` rows and write-through on accepted Realm events
    /// or admin updates.
    pub retention_policies: Arc<Mutex<BTreeMap<String, RetentionPolicyRecord>>>,
    /// Retention tombstones keyed by event_id. Tombstoned events keep their
    /// stable event_id and remain in the canonical/projection stores; render
    /// paths redact the content to `[expired]`.
    pub retention_tombstones: Arc<Mutex<BTreeMap<String, RetentionTombstoneRecord>>>,
    /// Local organization directory rows keyed by organization DID/id.
    /// Hydrated from durable organization projection rows.
    pub organizations: Arc<Mutex<BTreeMap<String, OrganizationRecord>>>,
    /// Current organization moderation policy per organization.
    pub organization_policies: Arc<Mutex<BTreeMap<String, OrganizationPolicyRecord>>>,
    /// Realm -> organizations declared by `ck.realm.create.owning_organizations`
    /// or the local organization link endpoint.
    pub realm_organizations: Arc<Mutex<BTreeMap<String, BTreeSet<String>>>>,
    /// Organization -> member Realm ids. This is the read-side fanout index:
    /// policy updates do not rewrite per-Realm rows.
    pub organization_realms: Arc<Mutex<BTreeMap<String, BTreeSet<String>>>>,
    /// Accepted Realm-level moderation-policy overrides keyed by Realm id.
    pub realm_moderation_policies: Arc<Mutex<BTreeMap<String, RealmModerationPolicyRecord>>>,
    pub did_resolver: Arc<CompositeDidResolver>,
    /// Move/Seal/Lattice runtime stores. Pg-backed in database mode,
    /// SDK memory-backed in explicitly in-memory test mode.
    pub move_store: Arc<dyn MoveStore>,
    pub seal_store: Arc<dyn SealStore>,
    pub cell_store: Arc<dyn CellStore>,
    pub cell_registry: Arc<dyn CellRegistry>,
    /// Live event notification bus for `ck.self.events.stream.subscribe`.
    /// Memory mode uses the local broadcast channel; PostgreSQL mode also
    /// publishes over LISTEN/NOTIFY so subscribers connected to another
    /// replica receive the same live frames.
    pub event_broadcast: EventBroadcast,
    /// Server-enforced reconnect windows advertised by subscribe control
    /// frames. This prevents a faulty or overloaded client from immediately
    /// re-opening the same subscribe scope after `dropped` /
    /// `resync_required`.
    pub subscribe_reconnect_gate: Arc<Mutex<SubscribeReconnectGate>>,
    /// Persistent Ed25519 signing key for NotaryWorker +
    /// admin endpoints (`admin_reconfigure_notary`, `admin_repair_bottom`).
    /// Loaded from `AppConfig::notary_signing_key_seed` at boot when set;
    /// otherwise minted from `sha256(service_did || nanos_since_epoch)` and
    /// flagged as `NotarySigningKeyOrigin::Ephemeral` so a sticky-warn
    /// fires on first use.
    ///
    /// Shared across all signing paths so the NotaryWorker, the
    /// `service_admin_signer` admin shortcut, and the threshold partial-
    /// signature coordinator all bind to the **same** key/DID identity.
    /// Swapped lock-free via [`ArcSwap`] so
    /// the `POST /_soland/admin/realms/{realm_id}/notary/rotate-signing-key`
    /// endpoint can publish a fresh ed25519 seed without tearing concurrent
    /// signing passes. Readers acquire the current key via `load_full()`
    /// (returns `Arc<SigningKey>`); writers `store(...)` a new `Arc`.
    pub notary_signing_key: Arc<ArcSwap<SigningKey>>,
    /// The origin tag rotates with the key. Stored alongside it
    /// behind a [`Mutex`] (one-shot writes from the rotation path are not
    /// in the hot read path; the per-pass diagnostic helper just snapshots).
    pub notary_signing_key_origin: Arc<Mutex<NotarySigningKeyOrigin>>,
    /// Per-admin signing keys: SDK
    /// [`cokret_sdk::AdminKeyStore`] keyed by the `application_id`
    /// `soland.<service_did>`. Each admin DID in
    /// `config.admin_principal_dids` gets its own ed25519 signing seed
    /// (provisioned at boot in `development_mode`; lazily loaded from the
    /// platform keystore otherwise). The signer for an admin DID is
    /// built via `admin_signer_for(state, admin_did)` — this replaces the
    /// service-wide `service_admin_signer` shortcut for endpoints that
    /// want operator attribution in the audit chain.
    pub admin_keystore: Arc<cokret_sdk::AdminKeyStore>,
    /// G4.T3 — verified-profile descriptors loaded from the artifact path in
    /// `SOLAND_VERIFIED_PROFILES_ARTIFACT` at startup. Filtered to entries
    /// whose `service_role == "principal_server"` and additionally
    /// cross-checked against the local `claimed_profiles[]` set inside
    /// `describe.rs::apply_claim_level_partition`. Empty when the env var
    /// is unset / file missing / file malformed — that's the dev-mode
    /// invariant in service-surface.md §3.0.
    pub verified_profiles: Arc<Vec<VerifiedProfileDescriptor>>,
    /// MID-1..6 (R3.1 spec-sync 2026-05-27, cokret-spec @ 7157ee8) — in-
    /// memory registry of `ck.member.identity.update` events. Reducer
    /// dispatch (`apply_member_identity_update`) and the sync roster
    /// projection (`SYNC-MEM-1..3`) both go through this. See
    /// [`MemberIdentityRegistry`] above for storage and effective-set
    /// semantics; durable persistence lands when the MID schema migration
    /// ships. Plaintext Ed25519 MemberIdentity proofs are verified on
    /// event ingest; encrypted/non-Ed25519 proof forms are refused
    /// fail-closed. Reducer-shape validation (digest binding, segment
    /// whitelist) IS real per MID-2.
    pub member_identity: Arc<Mutex<MemberIdentityRegistry>>,
}

impl AppState {
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
    /// Used by the `ck.call.state` participant_binding verifier: in the
    /// cokret-native self-signed deployment the binding `sig` is minted with
    /// the notary signing key (`routing::interop::webrtc`), so the receiver
    /// verifies against this key after anchoring `issuer_kid` to the current
    /// media_service epoch.
    pub fn notary_verifying_key(&self) -> ed25519_dalek::VerifyingKey {
        self.notary_signing_key.load().verifying_key()
    }

    /// Origin tag for diagnostics (`Configured` / `Ephemeral` / `Rotated`).
    pub fn notary_signing_key_origin(&self) -> NotarySigningKeyOrigin {
        *self
            .notary_signing_key_origin
            .lock()
            .expect("notary signing key origin lock")
    }

    /// Hot-rotate the NotaryWorker signing key. Writers swap
    /// the `ArcSwap` and update the origin tag in lockstep. Returns the
    /// newly-published `Arc<SigningKey>` for callers (the rotate-signing-key
    /// endpoint uses it to compute the resulting did:key kid).
    pub fn rotate_notary_signing_key(
        &self,
        seed: &[u8; 32],
        origin: NotarySigningKeyOrigin,
    ) -> Arc<SigningKey> {
        let new_key = Arc::new(SigningKey::from_bytes(seed));
        self.notary_signing_key.store(new_key.clone());
        if let Ok(mut guard) = self.notary_signing_key_origin.lock() {
            *guard = origin;
        }
        new_key
    }

    pub fn new(config: AppConfig, db: Db) -> Self {
        let persistence: Arc<dyn PersistenceStore> = db
            .pool
            .as_ref()
            .map(|pool| {
                Arc::new(PgPersistenceStore::new(pool.clone())) as Arc<dyn PersistenceStore>
            })
            .unwrap_or_else(|| Arc::new(SolandMemoryPersistenceStore::new()));
        Self::new_with_persistence(config, db, persistence)
    }

    pub fn new_with_persistence(
        config: AppConfig,
        db: Db,
        persistence: Arc<dyn PersistenceStore>,
    ) -> Self {
        let mut realms = RealmDirectoryIndex::new();
        let now = chrono::Utc::now();

        let service_did = config.service_did.clone();

        let object_storage = build_object_storage(&config.object_storage)
            .expect("object storage backend initializes");

        // Seed the deterministic demo Realm into the in-memory directory index
        // when explicitly opted in (tests via `test_config()`, dev harnesses via
        // `SOLAND_SEED_DEMO_DATA=true`). In production this stays off so soland
        // deployments don't all advertise the same hard-coded "Cokret Demo
        // Space" id across federation peers.
        //
        // The DB-touching half of the demo seed (writing the demo account +
        // Realm metadata through the now-async persistence store) and the
        // durable hydration steps run in [`AppState::hydrate`], an explicit
        // async boot step driven from `main`, so the synchronous constructor
        // never touches the database.
        if config.seed_demo_data {
            let demo_realm_id = "ck:realm:0196419b-0000-7000-8000-000000000000";
            let mut demo = RealmDirectoryEntry::new(
                RealmId::new(demo_realm_id.to_owned()).expect("valid demo Realm id"),
                "Cokret Demo Realm",
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
        let did_resolver = Arc::new(did_resolver_chain::build_did_resolver_chain_with_identity(
            &config,
            Some(persistence.clone()),
        ));

        // Derive the NotaryWorker's Ed25519 signing key.
        // Resolution order:
        //   1. KeyStore (when `use_keystore=true` and the platform store has a previously-persisted
        //      seed under our id) → Configured.
        //   2. `config.notary_signing_key_seed` (env-loaded) → Configured. When `use_keystore=true`
        //      we *also* persist this seed back to the KeyStore on first boot so subsequent
        //      restarts skip the env path.
        //   3. SHA-256(service_did || boot_nanos) → Ephemeral.
        let (signing_seed, notary_signing_key_origin) =
            (|| -> ([u8; 32], NotarySigningKeyOrigin) {
                if config.use_keystore {
                    let app_id = format!("soland.{service_did}");
                    let key_id = format!("cokret:signer:soland-notary:{service_did}");
                    let store = cokret_sdk::platform_default_keystore(&app_id);
                    if let Ok(bytes) = store.load(&key_id) {
                        if bytes.len() == 32 {
                            let mut seed = [0u8; 32];
                            seed.copy_from_slice(&bytes);
                            tracing::info!(%key_id, "loaded notary signing seed from platform KeyStore");
                            return (seed, NotarySigningKeyOrigin::Configured);
                        }
                        tracing::warn!(%key_id, len = bytes.len(),
                        "platform KeyStore returned non-32-byte payload; falling back");
                    }
                    if let Some(seed) = config.notary_signing_key_seed {
                        if let Err(error) = store.store(&key_id, &seed) {
                            tracing::warn!(%error, %key_id,
                            "failed to seed platform KeyStore from env-supplied seed");
                        } else {
                            tracing::info!(%key_id,
                            "persisted env-supplied notary seed into platform KeyStore");
                        }
                        return (seed, NotarySigningKeyOrigin::Configured);
                    }
                    // Mint + persist a one-shot seed.
                    let mut seed = [0u8; 32];
                    getrandom_seed(&mut seed);
                    if let Err(error) = store.store(&key_id, &seed) {
                        tracing::warn!(%error, %key_id,
                        "failed to persist freshly-minted notary seed to KeyStore");
                    } else {
                        tracing::info!(%key_id,
                        "minted + persisted fresh notary seed via platform KeyStore");
                    }
                    return (seed, NotarySigningKeyOrigin::Configured);
                }
                if let Some(seed) = config.notary_signing_key_seed {
                    return (seed, NotarySigningKeyOrigin::Configured);
                }
                // Ephemeral fallback. In production we mix in `boot_nanos`
                // so a soland that boots without a configured seed never
                // signs with the same key twice — this is a security
                // posture choice (no implicit long-lived key on disk).
                //
                // In `development_mode=true` we drop `boot_nanos` and
                // derive the seed deterministically from `service_did`
                // alone. The trade-off: every dev restart kept invalidating
                // every previously-issued sync cursor with
                // `cursor_integrity_invalid` because the freshly-minted
                // key couldn't reproduce yesterday's signature. Stable in
                // dev = `cargo run` doesn't break a connected yougen.
                let mut hasher = Sha256::new();
                hasher.update(b"soland:notary-ephemeral:");
                hasher.update(service_did.as_bytes());
                if !config.development_mode {
                    let boot_nanos = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .map(|d| d.as_nanos() as u64)
                        .unwrap_or(0);
                    hasher.update(boot_nanos.to_le_bytes());
                }
                let seed: [u8; 32] = hasher.finalize().into();
                (seed, NotarySigningKeyOrigin::Ephemeral)
            })();

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
        // mirrors the NotaryWorker pattern (`soland.<service_did>`) so
        // operators only manage one secret-storage namespace.
        //
        // In `development_mode` we proactively mint an ephemeral seed
        // for every DID listed in `admin_principal_dids` so smoke-tests
        // can call admin endpoints under the operator DID without any
        // out-of-band provisioning step. Production deployments must
        // pre-populate the platform keystore explicitly — admin DIDs
        // without a provisioned key fall back to
        // `service_admin_signer` at signing time with a sticky-warn.
        let admin_app_id = format!("soland.{}", config.service_did);
        let admin_keystore_inner: Box<dyn cokret_sdk::KeyStore> = if config.use_keystore {
            cokret_sdk::platform_default_keystore(&admin_app_id)
        } else {
            Box::new(cokret_sdk::keystore::InMemoryKeyStore::new())
        };
        let admin_keystore =
            cokret_sdk::AdminKeyStore::new(admin_app_id.clone(), admin_keystore_inner);
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

        let state_resolution_stores =
            super::state_resolution::build_state_resolution_stores(db.pool.clone());

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

        Self {
            config,
            hlc: ServerHlc::new(&service_did),
            projection: Arc::new(Mutex::new(hydrated)),
            authz: SolandAuthzEngine::new(),
            db,
            persistence,
            object_storage,
            realms: Arc::new(Mutex::new(realms)),
            cross_signing: Arc::new(Mutex::new(cokret_sdk::DeviceManager::new())),
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
            move_store: state_resolution_stores.move_store,
            seal_store: state_resolution_stores.seal_store,
            cell_store: state_resolution_stores.cell_store,
            cell_registry: state_resolution_stores.cell_registry,
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

    /// Touch the (now async) persistence store to finish boot:
    ///   * seed the demo account + Realm metadata when `seed_demo_data` is on,
    ///   * hydrate the Realm directory from persisted `ck.realm.create` events,
    ///   * hydrate Space-container/Strand/Morph projections from durable rows.
    ///
    /// Extracted out of the synchronous `new` constructor so the DB work runs
    /// in an async context (driven from `main`); see the diesel-async
    /// conversion. Safe to call in memory mode — every store read returns an
    /// empty snapshot, so this is a no-op there.
    pub async fn hydrate(&self) -> PersistenceResult<()> {
        let now = chrono::Utc::now();
        if self.config.seed_demo_data {
            let demo_realm_id = "ck:realm:0196419b-0000-7000-8000-000000000000";
            let demo_account = AccountRecord {
                id: "ck:account:0196419b-0000-7000-8000-000000000001".to_owned(),
                did: "did:web:alice.example".to_owned(),
                localpart: "alice".to_owned(),
                display_name: Some("Alice Example".to_owned()),
                bio: None,
                avatar_url: None,
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
            &self.config.service_did,
        )
        .await;
        {
            let mut realms = self.realms.lock().expect("realms lock");
            for (_, entry) in realm_updates.entries_iter() {
                realms.upsert(entry.clone());
            }
        }

        let mut proj_updates = ProjectionState::new();
        hydrate_projections_from_persistence(
            self.persistence.as_ref(),
            &mut proj_updates,
            &self.authz,
        )
        .await;
        {
            let mut proj = self.projection.lock().expect("projection lock");
            proj.space_containers.extend(proj_updates.space_containers);
            proj.strands.extend(proj_updates.strands);
            proj.morphs.extend(proj_updates.morphs);
            proj.replay_resolved_pending(&self.hlc);
        }

        let hydrated_realm_ids: Vec<RealmId> = {
            let realms = self.realms.lock().expect("realms lock");
            realms
                .search(Default::default())
                .into_iter()
                .filter_map(|entry| RealmId::new(entry.realm_id.to_string()).ok())
                .collect()
        };
        {
            let mut proj = self.projection.lock().expect("projection lock");
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
            let mut map = self
                .invite_receive_policies
                .lock()
                .expect("invite_receive_policies lock");
            for (subject_id, policy) in policies {
                map.entry(subject_id).or_insert(policy);
            }
        }

        // Hydrate the holder-private consent-cell projection from durable
        // storage. Built off-lock first; the async snapshot read MUST NOT hold
        // the std Mutex across `.await`.
        let cells = self.persistence.consent_cells().snapshot_all().await?;
        {
            let mut map = self.consent_cells.lock().expect("consent_cells lock");
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
            let mut map = self
                .direct_conversation_bindings
                .lock()
                .expect("direct_conversation_bindings lock");
            for (participants_key, record) in bindings {
                map.entry(participants_key).or_insert(record);
            }
        }

        let lifecycle_records = self.persistence.account_lifecycle().snapshot_all().await?;
        {
            let mut map = self
                .account_lifecycle
                .lock()
                .expect("account_lifecycle lock");
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
            let mut map = self.handle_releases.lock().expect("handle_releases lock");
            for (localpart, released_at) in handle_releases {
                map.insert(localpart, released_at);
            }
        }

        let retention_policies = self.persistence.retention_policies().snapshot_all().await?;
        {
            let mut map = self
                .retention_policies
                .lock()
                .expect("retention_policies lock");
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
            let mut map = self
                .retention_tombstones
                .lock()
                .expect("retention_tombstones lock");
            for record in retention_tombstones {
                map.insert(record.event_id.clone(), record);
            }
        }

        let organizations = self.persistence.organizations().list().await?;
        {
            let mut map = self.organizations.lock().expect("organizations lock");
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
            let mut map = self
                .organization_policies
                .lock()
                .expect("organization_policies lock");
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
            let mut realm_map = self
                .realm_organizations
                .lock()
                .expect("realm_organizations lock");
            let mut org_map = self
                .organization_realms
                .lock()
                .expect("organization_realms lock");
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

        let realm_moderation_policies = self
            .persistence
            .realm_moderation_policies()
            .snapshot_all()
            .await?;
        {
            let mut map = self
                .realm_moderation_policies
                .lock()
                .expect("realm_moderation_policies lock");
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
        match self
            .persistence
            .sync_cursors()
            .active_revocations(now)
            .await
        {
            Ok(revocations) => {
                let mut cache = self
                    .sync_cursor_revocations
                    .lock()
                    .expect("sync cursor revocations lock");
                cache.extend(revocations);
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
        self.member_identity
            .lock()
            .expect("member_identity lock")
            .clone()
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
            .expect("account_lifecycle lock")
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
        let mut lifecycle = self
            .account_lifecycle
            .lock()
            .expect("account_lifecycle lock");
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
        let mut map = self
            .failed_login_attempts
            .lock()
            .expect("failed_login_attempts lock");
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
        let mut map = self
            .failed_login_attempts
            .lock()
            .expect("failed_login_attempts lock");
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
        self.failed_login_attempts
            .lock()
            .expect("failed_login_attempts lock")
            .remove(did);
    }

    /// SEC-09 — record a PSI / contact-discovery probe for the
    /// `(requester, holder)` pair and report whether it is rate-limited.
    /// A rolling [`PSI_PROBE_WINDOW`] caps probes at
    /// [`PSI_PROBE_MAX_PER_WINDOW`]; once exceeded the caller MUST withhold a
    /// fresh match result and surface `retry_after_ms`, so a requester cannot
    /// poll the holder's hit bit at high frequency to read grant/revoke timing.
    pub fn record_psi_probe(&self, requester: &str, holder: &str) -> PsiProbeOutcome {
        let mut map = self
            .psi_probe_tracker
            .lock()
            .expect("psi_probe_tracker lock");
        let now = chrono::Utc::now();
        let entry = map
            .entry((requester.to_owned(), holder.to_owned()))
            .or_insert(PsiProbeRecord {
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
        let mut map = self
            .key_backup_download_tracker
            .lock()
            .expect("key_backup_download_tracker lock");
        let now = chrono::Utc::now();
        let entry = map
            .entry(principal_id.to_owned())
            .or_insert(KeyBackupDownloadRecord {
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

        let mut map = self
            .moderation_report_rate_tracker
            .lock()
            .expect("moderation_report_rate_tracker lock");
        let now = chrono::Utc::now();
        let window = chrono::Duration::seconds(MODERATION_REPORT_RATE_WINDOW_SECS);
        let mut exceeded = None;
        for (bucket, limit) in buckets {
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
        let mut map = self
            .moderation_franking_replay_nonces
            .lock()
            .expect("moderation_franking_replay_nonces lock");
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
        agent_principal_id: &str,
        authorization_ref: &str,
        request_id: &str,
        approval_nonce: &str,
        expires_at: chrono::DateTime<chrono::Utc>,
    ) -> bool {
        let now = chrono::Utc::now();
        if expires_at <= now {
            return false;
        }
        let mut map = self
            .agent_approval_nonces
            .lock()
            .expect("agent_approval_nonces lock");
        map.retain(|_, expiry| *expiry > now);
        let key = format!("{agent_principal_id}:{authorization_ref}:{request_id}:{approval_nonce}");
        if map.contains_key(&key) {
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

fn account_lifecycle_status_from_wire(value: &str) -> AccountStatus {
    match value {
        "erased" => AccountStatus::ErasurePending,
        _ => AccountStatus::from_wire(value).unwrap_or_else(|| {
            tracing::warn!(state = value, "unknown account lifecycle state");
            AccountStatus::Suspended
        }),
    }
}

/// Fill `out` with cryptographically secure random bytes via
/// `rand::rng`. Used by both the boot path (one-shot KeyStore mint) and
/// the rotate-signing-key endpoint.
pub(crate) fn getrandom_seed(out: &mut [u8; 32]) {
    use rand::RngExt;
    rand::rng().fill(out);
}

/// Read Space-container / Strand / Morph projection rows from durable
/// persistence into the supplied `ProjectionState`. Called at
/// `AppState::new` so restart picks up the lifecycle state the
/// write-through path stamped down on the way in. Unknown state
/// strings or invalid rows are silently skipped (logged at warn) —
/// the in-memory state stays authoritative.
async fn hydrate_projections_from_persistence(
    persistence: &dyn crate::persistence::PersistenceStore,
    proj: &mut ProjectionState,
    authz: &SolandAuthzEngine,
) {
    use crate::reducer::{
        AppletProjection, ChildScopePolicy, MorphProjection, ObjectLifecycleState,
        SpaceContainerLifecycleState, SpaceContainerProjection, StrandProjection,
    };

    fn parse_space_container_state(value: &str) -> Option<SpaceContainerLifecycleState> {
        match value {
            "active" => Some(SpaceContainerLifecycleState::Active),
            "archived" => Some(SpaceContainerLifecycleState::Archived),
            "tombstoned" => Some(SpaceContainerLifecycleState::Tombstoned),
            _ => None,
        }
    }
    fn parse_object_state(value: &str) -> Option<ObjectLifecycleState> {
        match value {
            "active" => Some(ObjectLifecycleState::Active),
            "archived" => Some(ObjectLifecycleState::Archived),
            "redacted" => Some(ObjectLifecycleState::Redacted),
            _ => None,
        }
    }

    if let Ok(rows) = persistence
        .space_container_projections()
        .snapshot_all()
        .await
    {
        for record in rows {
            let Some(state) = parse_space_container_state(&record.state) else {
                tracing::warn!(
                    container_space_id = %record.container_space_id,
                    state = %record.state,
                    "skipping space-container projection row with unknown state during hydrate"
                );
                continue;
            };
            proj.space_containers.insert(
                record.container_space_id.clone(),
                SpaceContainerProjection {
                    container_space_id: record.container_space_id,
                    realm_id: record.realm_id,
                    kind: record.kind,
                    title: record.title,
                    scope_circle_id: record.scope_circle_id,
                    default_scope_circle_id: record.default_scope_circle_id,
                    child_scope_policy: ChildScopePolicy::from_parts(
                        record.child_scope_policy,
                        record.child_scope_policy_scope_circle_id,
                        record.child_scope_policy_metadata_encryption_floor,
                    ),
                    parent_ref: record.parent_ref,
                    rank: record.rank,
                    state,
                    state_changed_at: record.state_changed_at,
                    created_by: record.created_by,
                    created_at: record.created_at,
                    history_basis_seals: record.history_basis_seals,
                    updated_by: record.updated_by,
                    updated_at: record.updated_at,
                    // Stream-F (Wave 1B): orphaned flag is reducer-only
                    // bookkeeping; not persisted to the durable mirror
                    // table yet. Replayed durable events will rebuild
                    // it via apply_realm_lifecycle cascade.
                    orphaned: false,
                    // Stream-F (Wave 2C): same story — cross-Realm
                    // parent_ref_locked is also a reducer-only flag
                    // rebuilt by the destroy cascade on replay.
                    parent_ref_locked: false,
                },
            );
        }
    }
    if let Ok(rows) = persistence.strand_projections().snapshot_all().await {
        for record in rows {
            let Some(state) = parse_object_state(&record.state) else {
                tracing::warn!(
                    strand_id = %record.strand_id,
                    state = %record.state,
                    "skipping strand projection row with unknown state during hydrate"
                );
                continue;
            };
            proj.strands.insert(
                record.strand_id.clone(),
                StrandProjection {
                    strand_id: record.strand_id,
                    realm_id: record.realm_id,
                    tracks: record.tracks,
                    title: record.title,
                    summary: record.summary,
                    fields: Default::default(),
                    state,
                    state_changed_at: record.state_changed_at,
                    created_by: record.created_by,
                    created_at: record.created_at,
                    history_basis_seals: record.history_basis_seals,
                    updated_by: record.updated_by,
                    updated_at: record.updated_at,
                    scope_circle_id: record.scope_circle_id,
                },
            );
        }
    }
    if let Ok(rows) = persistence.morph_projections().snapshot_all().await {
        for record in rows {
            let Some(state) = parse_object_state(&record.state) else {
                tracing::warn!(
                    morph_id = %record.morph_id,
                    state = %record.state,
                    "skipping morph projection row with unknown state during hydrate"
                );
                continue;
            };
            proj.morphs.insert(
                record.morph_id.clone(),
                MorphProjection {
                    morph_id: record.morph_id,
                    realm_id: record.realm_id,
                    scope_circle_id: record.scope_circle_id,
                    morph_type: record.morph_type,
                    title: record.title,
                    fields: record
                        .fields
                        .as_object()
                        .map(|fields| {
                            fields
                                .iter()
                                .map(|(key, value)| (key.clone(), value.clone()))
                                .collect()
                        })
                        .unwrap_or_default(),
                    schema_refs: record
                        .schema_refs
                        .as_array()
                        .map(|items| {
                            items
                                .iter()
                                .filter_map(serde_json::Value::as_str)
                                .map(ToOwned::to_owned)
                                .collect()
                        })
                        .unwrap_or_default(),
                    facets: record
                        .facets
                        .as_array()
                        .map(|items| {
                            items
                                .iter()
                                .filter_map(serde_json::Value::as_str)
                                .map(ToOwned::to_owned)
                                .collect()
                        })
                        .unwrap_or_default(),
                    versions: serde_json::from_value(record.versions).unwrap_or_default(),
                    state,
                    state_changed_at: record.state_changed_at,
                    created_by: record.created_by,
                    created_at: record.created_at,
                    history_basis_seals: record.history_basis_seals,
                    updated_by: record.updated_by,
                    updated_at: record.updated_at,
                },
            );
        }
    }
    if let Ok(rows) = persistence.applets().list().await {
        for row in rows {
            let applet_id = row
                .get("applet_id")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned);
            let namespace = row
                .get("namespace")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned();
            let Some(package_value) = row.get("package").filter(|value| !value.is_null()).cloned()
            else {
                continue;
            };
            let Ok(package) = serde_json::from_value::<AppletPackage>(package_value) else {
                if let Some(applet_id) = &applet_id {
                    tracing::warn!(%applet_id, "skipping applet projection row with invalid package during hydrate");
                }
                continue;
            };
            let registered_at = row
                .get("registered_at")
                .cloned()
                .and_then(|value| {
                    serde_json::from_value::<chrono::DateTime<chrono::Utc>>(value).ok()
                })
                .unwrap_or_else(chrono::Utc::now);
            let projection = AppletProjection {
                service_did: package.service_did.to_string(),
                namespace,
                manifest: Some(package.manifest_snapshot()),
                capabilities: row.get("capabilities").cloned(),
                registered_at,
                updated_at: registered_at,
            };
            proj.applets
                .insert(projection.service_did.clone(), projection.clone());
            if let Some(applet_id) = applet_id {
                proj.applets.insert(applet_id, projection);
            }
            hydrate_applet_install_grants(authz, &row, &package, registered_at);
        }
    }
}

fn hydrate_applet_install_grants(
    authz: &SolandAuthzEngine,
    row: &Value,
    package: &AppletPackage,
    registered_at: chrono::DateTime<chrono::Utc>,
) {
    let status = row
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if !matches!(status, "installed" | "partially_installed")
        || row.get("revoked_at").is_some_and(|value| !value.is_null())
    {
        return;
    }
    let Some(owner_actor_id) = row.get("owner_actor_id").and_then(Value::as_str) else {
        return;
    };
    let Some(portal_realm_id) = row.get("portal_realm_id").and_then(Value::as_str) else {
        return;
    };
    let Some(grant_ids) = row
        .get("install_response")
        .and_then(|value| value.get("capability_grant_refs"))
        .and_then(Value::as_array)
    else {
        return;
    };
    let Some(actions) = row.get("capabilities").and_then(Value::as_array) else {
        return;
    };
    for (grant_id, action) in grant_ids.iter().zip(actions.iter()) {
        let (Some(grant_id), Some(action)) = (grant_id.as_str(), action.as_str()) else {
            continue;
        };
        authz.upsert_projected_grant(crate::authz::Grant {
            grant_id: grant_id.to_owned(),
            realm_id: portal_realm_id.to_owned(),
            issuer: owner_actor_id.to_owned(),
            subject: package.service_did.to_string(),
            resource: portal_realm_id.to_owned(),
            actions: vec![action.to_owned()],
            constraints: vec![crate::authz::Constraint::AppletDelegationBinding {
                applet_id: package.applet_id.clone(),
                executed_by: package.service_did.to_string(),
                registration_epoch: package.registration_epoch.to_string(),
            }],
            revoked: false,
            created_at: registered_at,
            delegated_from: None,
            expires_at: None,
        });
    }
}

async fn hydrate_realms_from_canonical_events(
    persistence: &dyn crate::persistence::PersistenceStore,
    realms: &mut RealmDirectoryIndex,
    service_did: &str,
) {
    let Ok(events) = persistence.events().snapshot_all().await else {
        return;
    };
    for record in events {
        if record.kind == "ck.realm.create" {
            hydrate_realm_create_event(persistence, realms, &record, service_did).await;
        } else if matches!(
            record.kind.as_str(),
            "ck.realm.history_visibility"
                | "ck.realm.history_sharing_policy"
                | "ck.realm.preview_policy"
                | "ck.realm.asset_privacy_policy"
        ) {
            hydrate_realm_policy_event(persistence, &record).await;
        }
    }
}

async fn hydrate_realm_create_event(
    persistence: &dyn crate::persistence::PersistenceStore,
    realms: &mut RealmDirectoryIndex,
    record: &CanonicalEventRecord,
    service_did: &str,
) {
    let payload_object = record
        .envelope
        .get("payload")
        .and_then(|payload| payload.get("object"));
    let Some(realm_id) = record
        .envelope
        .get("realm_id")
        .and_then(Value::as_str)
        .or_else(|| {
            payload_object
                .and_then(|object| object.get("id"))
                .and_then(Value::as_str)
        })
        .or(record.realm_id.as_deref())
        .map(normalize_persisted_realm_id)
    else {
        return;
    };
    let Ok(realm_id) = RealmId::new(realm_id.clone()) else {
        tracing::warn!(realm_id = %realm_id, "skipping persisted realm.create with invalid realm_id");
        return;
    };
    let Ok(actor) = Did::new(record.actor_id.clone()) else {
        tracing::warn!(actor = %record.actor_id, "skipping persisted realm.create with invalid actor");
        return;
    };
    let title = payload_object
        .and_then(|object| object.get("title"))
        .and_then(Value::as_str)
        .unwrap_or(realm_id.as_str());
    let summary = payload_object
        .and_then(|object| object.get("summary"))
        .and_then(Value::as_str)
        .map(ToOwned::to_owned);
    let discoverability = payload_object
        .and_then(|object| object.get("default_discoverability"))
        .and_then(Value::as_str)
        .unwrap_or("invite_only")
        .to_owned();
    let history_visibility = payload_object
        .and_then(|object| object.get("history_visibility"))
        .and_then(Value::as_str)
        .unwrap_or("shared")
        .to_owned();
    let encryption_profile = payload_object
        .and_then(|object| object.get("encryption_profile"))
        .and_then(Value::as_str)
        .map(ToOwned::to_owned);
    let history_sharing_policy = payload_object
        .and_then(|object| object.get("history_sharing_policy"))
        .cloned();
    let history_sharing_policy_digest = history_sharing_policy
        .as_ref()
        .and_then(canonical_value_digest);
    let preview_policy = payload_object
        .and_then(|object| object.get("preview_policy"))
        .cloned();
    let preview_policy_digest = preview_policy.as_ref().and_then(canonical_value_digest);
    let asset_privacy_policy = payload_object
        .and_then(|object| object.get("asset_privacy_policy"))
        .cloned();
    let asset_privacy_policy_digest = asset_privacy_policy
        .as_ref()
        .and_then(canonical_value_digest);
    let plaintext_visible_services = record
        .envelope
        .get("payload")
        .and_then(|payload| payload.get("plaintext_visible_services"))
        .or_else(|| payload_object.and_then(|object| object.get("plaintext_visible_services")))
        .and_then(Value::as_array)
        .map(|services| {
            services
                .iter()
                .filter_map(|service| service.as_str().map(ToOwned::to_owned))
                .collect::<BTreeSet<_>>()
        })
        .unwrap_or_default();
    let mut plaintext_visible_service_classes = record
        .envelope
        .get("payload")
        .map(crate::routing::events::projection::plaintext_service_classes_from_value)
        .unwrap_or_default();
    if let Some(object) = payload_object {
        for (service, classes) in
            crate::routing::events::projection::plaintext_service_classes_from_value(object)
        {
            plaintext_visible_service_classes
                .entry(service)
                .or_default()
                .extend(classes);
        }
    }
    let minimal_metadata_realm =
        payload_object.is_some_and(crate::kinds::payload_declares_minimal_metadata_realm);

    let mut entry = RealmDirectoryEntry::new(realm_id.clone(), title);
    entry.description = summary.clone();
    entry.public = discoverability == "public";
    entry.members.insert(actor);
    entry.as_of = record.received_at;
    entry.source_refs = vec![record.event_id.clone()];
    entry.policy_revision = preview_policy_digest
        .clone()
        .unwrap_or_else(|| record.canonical_digest.clone());
    // Realm alias (object-addressing.md §3.3) — rebuild from the persisted
    // create event so the alias survives restart, mirroring the live projection
    // in routing/events/projection/realm.rs. First-writer-wins on conflict.
    if let Some(canonical) = payload_object
        .and_then(|object| object.get("alias"))
        .and_then(Value::as_str)
        .and_then(|raw| crate::realm_alias::canonical_realm_alias(service_did, raw))
    {
        let taken = realms.entries_iter().any(|(rid, existing)| {
            rid != &realm_id && existing.alias.as_deref() == Some(canonical.as_str())
        });
        if !taken {
            entry.alias = Some(canonical);
        }
    }
    realms.upsert(entry);

    let meta = RealmMetaRecord {
        owner: record.actor_id.clone(),
        deleted: false,
        discoverability,
        history_visibility,
        history_sharing_policy,
        history_sharing_policy_digest,
        preview_policy,
        preview_policy_digest,
        asset_privacy_policy,
        asset_privacy_policy_digest,
        encryption_profile,
        plaintext_visible_services,
        plaintext_visible_service_classes,
        minimal_metadata_realm,
        created_at: record.received_at,
        updated_at: record.received_at,
    };
    if let Err(error) = persistence.realm_meta().put(realm_id.as_str(), &meta).await {
        tracing::warn!(%error, realm_id = %realm_id, "failed to hydrate persisted realm meta");
    }
}

async fn hydrate_realm_policy_event(
    persistence: &dyn crate::persistence::PersistenceStore,
    record: &CanonicalEventRecord,
) {
    let Some(realm_id) = event_record_realm_id(record) else {
        return;
    };
    let Ok(Some(mut meta)) = persistence.realm_meta().get(&realm_id).await else {
        return;
    };
    let Some(payload) = record.envelope.get("payload") else {
        return;
    };
    match record.kind.as_str() {
        "ck.realm.history_visibility" => {
            if let Some(value) = payload.get("value").and_then(Value::as_str) {
                meta.history_visibility = value.to_owned();
            }
        }
        "ck.realm.history_sharing_policy" => {
            if let Some(value) = payload.get("value") {
                meta.history_sharing_policy = Some(value.clone());
                meta.history_sharing_policy_digest = canonical_value_digest(value);
            }
        }
        "ck.realm.preview_policy" => {
            if let Some(value) = payload.get("value") {
                meta.preview_policy = Some(value.clone());
                meta.preview_policy_digest = canonical_value_digest(value);
            }
        }
        "ck.realm.asset_privacy_policy" => {
            if let Some(value) = payload.get("value") {
                meta.asset_privacy_policy = Some(value.clone());
                meta.asset_privacy_policy_digest = canonical_value_digest(value);
            }
        }
        _ => {}
    }
    meta.updated_at = record.received_at;
    if let Err(error) = persistence.realm_meta().put(&realm_id, &meta).await {
        tracing::warn!(%error, realm_id = %realm_id, "failed to hydrate Realm policy event");
    }
}

fn event_record_realm_id(record: &CanonicalEventRecord) -> Option<String> {
    record
        .envelope
        .get("realm_id")
        .and_then(Value::as_str)
        .or(record.realm_id.as_deref())
        .map(normalize_persisted_realm_id)
}

fn canonical_value_digest(value: &Value) -> Option<String> {
    let bytes = cokret_sdk::canonical::canonical_json_bytes(value).ok()?;
    Some(cokret_sdk::canonical::sha256_digest(bytes))
}

fn normalize_persisted_realm_id(id: &str) -> String {
    id.to_owned()
}
