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
use soland_data::Db;

use super::did_resolver_chain;
use super::member_identity::MemberIdentityRegistry;
use super::notification::{EventBroadcast, Mutex, SubscribeReconnectGate};
use super::realm_directory::{RealmDirectoryEntry, RealmDirectoryIndex};
use super::records::{
    ACCOUNT_LOCKOUT_DURATION, ACCOUNT_LOCKOUT_THRESHOLD, ACCOUNT_LOCKOUT_WINDOW,
    AccountLifecycleRecord, AccountRecord, CanonicalEventRecord, ConsentCellKey, ConsentCellRecord,
    CursorRevocation, DirectConversationBindingRecord, FailedLoginRecord,
    KEY_BACKUP_DOWNLOAD_TRACKER_MAX_ENTRIES, KEY_BACKUP_DOWNLOAD_WINDOW, KeyBackupDownloadOutcome,
    KeyBackupDownloadRecord, MODERATION_FRANKING_REPLAY_MAX_ENTRIES,
    MODERATION_FRANKING_REPLAY_WINDOW_SECS, MODERATION_REPORT_MAX_PER_REPORTER_REALM_WINDOW,
    MODERATION_REPORT_MAX_PER_REPORTER_TARGET_WINDOW, MODERATION_REPORT_MAX_PER_REPORTER_WINDOW,
    MODERATION_REPORT_MAX_PER_SOURCE_IP_WINDOW, MODERATION_REPORT_MAX_PER_SOURCE_SERVICE_WINDOW,
    MODERATION_REPORT_RATE_TRACKER_MAX_ENTRIES, MODERATION_REPORT_RATE_WINDOW_SECS,
    ModerationFrankingReplayRecord, ModerationReportRateOutcome, ModerationReportRateRecord,
    OrganizationPolicyRecord, OrganizationRecord, PSI_HIT_BUCKET_SECS, PSI_PROBE_MAX_PER_WINDOW,
    PSI_PROBE_TRACKER_MAX_ENTRIES, PSI_PROBE_WINDOW, PsiProbeOutcome, PsiProbeRecord,
    RealmMetaRecord, RealmModerationPolicyRecord, RetentionPolicyRecord, RetentionTombstoneRecord,
    SovereignDeploymentState,
};
use crate::authz::SolandAuthzEngine;
use crate::config::{AppConfig, NotarySigningKeyOrigin};
use crate::hlc::ServerHlc;
use crate::object_storage::{ObjectStorage, build_object_storage};
use crate::persistence::{
    PersistenceResult, PersistenceStore, PgPersistenceStore, SolandMemoryPersistenceStore,
};
use crate::reducer::ProjectionState;
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
    pub config: AppConfig,
    /// Runtime-authoritative service DID. It is resolved from durable identity
    /// state before construction and is never loaded from configuration.
    pub service_id: String,
    /// Full service-identity lifecycle state used by readiness, doctor, and
    /// identity-mutation gates.
    pub service_identity: Arc<ArcSwap<ServiceIdentityState>>,
    /// Mutable operational overlay (admin allowlist, rate-limit ceilings,
    /// federation peers, feature toggles). Seeded from `config` at boot,
    /// overlaid by the `server_settings` DB row in [`AppState::hydrate`], and
    /// hot-swapped by the admin settings endpoint. Read a consistent snapshot
    /// via [`AppState::settings`]. See [`crate::runtime_settings`].
    pub settings: Arc<ArcSwap<crate::runtime_settings::RuntimeSettings>>,
    pub db: Db,
    pub persistence: Arc<dyn PersistenceStore>,
    pub object_storage: Arc<dyn ObjectStorage>,
    pub hlc: ServerHlc,
    pub projection: Arc<Mutex<ProjectionState>>,
    pub authz: SolandAuthzEngine,
    pub realms: Arc<Mutex<RealmDirectoryIndex>>,
    /// Cross-signing state machine (PSK→SSK/USK publishes + device trust
    /// chains), per spec crypto-media/device-lifecycle.md §5. Fed by the
    /// projector when `ak.cross_signing.publish` lands, and read when verifying
    /// a `ak.device.authorize` `cross_signing_binding`. In-memory like the other
    /// reducer projections; durable rehydration rides on the durable event
    /// store (control-realm Phase 3).
    pub cross_signing: Arc<Mutex<arkret_sdk::DeviceManager>>,
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
    /// recommended default policy. `ak.self.contact.command.tombstone(block_peer)`
    /// writes the peer DID into the holder entry's `blocked_subjects`.
    pub invite_receive_policies: Arc<Mutex<BTreeMap<String, arkret_sdk::InviteReceivePolicy>>>,
    /// Direct conversation binding projection keyed by sorted participant DID
    /// pair. This is the bounded server-side fallback for
    /// `ak.self.direct_conversation.command.resolve` until signed
    /// `ak.direct_conversation.bound` event projection is fully wired.
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
    /// SOL-ORG-05 — Realm -> `owning_organizations` DECLARED HINTS, sourced
    /// from `ak.realm.create.owning_organizations` or the local organization
    /// link endpoint. These are NOT verified relationships and MUST NOT drive
    /// governance / durability / delivery / directory policy inheritance — only
    /// a verified `ak.realm.organization` statement does (see the reducer
    /// `realm_organization_statements` projection). Retained as a discovery /
    /// display hint surface only.
    pub realm_organizations: Arc<Mutex<BTreeMap<String, BTreeSet<String>>>>,
    /// Organization -> member Realm ids. This is the read-side fanout index:
    /// policy updates do not rewrite per-Realm rows.
    pub organization_realms: Arc<Mutex<BTreeMap<String, BTreeSet<String>>>>,
    /// Accepted Realm-level moderation-policy overrides keyed by Realm id.
    pub realm_moderation_policies: Arc<Mutex<BTreeMap<String, RealmModerationPolicyRecord>>>,
    pub did_resolver: Arc<did_resolver_chain::SolandDidResolver>,
    /// Runtime-only verification keys learned from endpoint-discovered
    /// federation peer DID documents. Configuration contains endpoints, not
    /// copied service DIDs or public-key pins; discovery validates the
    /// document's Principal Server endpoint binding before publishing a key.
    pub federation_peer_verifying_keys: Arc<ArcSwap<BTreeMap<String, VerifyingKey>>>,
    /// Move/Seal/Lattice runtime stores. Pg-backed in database mode,
    /// SDK memory-backed in explicitly in-memory test mode.
    pub move_store: Arc<dyn MoveStore>,
    pub seal_store: Arc<dyn SealStore>,
    pub cell_store: Arc<dyn CellStore>,
    pub cell_registry: Arc<dyn CellRegistry>,
    pub(crate) event_seal_committer: Arc<dyn super::state_resolution::EventSealCommitStore>,
    /// Live event notification bus for `ak.self.events.stream.subscribe`.
    /// Memory mode uses the local broadcast channel; PostgreSQL mode also
    /// publishes over LISTEN/NOTIFY so subscribers connected to another
    /// replica receive the same live frames.
    pub event_broadcast: EventBroadcast,
    /// Server-enforced reconnect windows advertised by subscribe control
    /// frames. This prevents a faulty or overloaded client from immediately
    /// re-opening the same subscribe scope after `dropped` /
    /// `resync_required`.
    pub subscribe_reconnect_gate: Arc<Mutex<SubscribeReconnectGate>>,
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
    pub notary_signing_key: Arc<ArcSwap<SigningKey>>,
    /// The origin tag rotates with the key. Stored alongside it
    /// behind a [`Mutex`] (one-shot writes from the rotation path are not
    /// in the hot read path; the per-pass diagnostic helper just snapshots).
    pub notary_signing_key_origin: Arc<Mutex<NotarySigningKeyOrigin>>,
    /// Per-admin signing keys: SDK
    /// [`arkret_sdk::AdminKeyStore`] keyed by the `application_id`
    /// `soland.<service_id>`. Each admin DID in
    /// `config.admin_principal_dids` gets its own ed25519 signing seed
    /// (provisioned at boot in `development_mode`; lazily loaded from the
    /// configured durable KeyStore otherwise). The signer for an admin DID is
    /// built via `admin_signer_for(state, admin_did)` — this replaces the
    /// service-wide `service_admin_signer` shortcut for endpoints that
    /// want operator attribution in the audit chain.
    pub admin_keystore: Arc<arkret_sdk::AdminKeyStore>,
    /// G4.T3 — verified-profile descriptors loaded from the artifact path in
    /// `SOLAND_VERIFIED_PROFILES_ARTIFACT` at startup. Filtered to entries
    /// whose `service_role == "principal_server"` and additionally
    /// cross-checked against the local `claimed_profiles[]` set inside
    /// `describe.rs::apply_claim_level_partition`. Empty when the env var
    /// is unset / file missing / file malformed — that's the dev-mode
    /// invariant in service-surface.md §3.0.
    pub verified_profiles: Arc<Vec<VerifiedProfileDescriptor>>,
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
    pub member_identity: Arc<Mutex<MemberIdentityRegistry>>,
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
    /// Snapshot the current service-identity lifecycle state.
    pub fn service_identity_state(&self) -> Arc<ServiceIdentityState> {
        self.service_identity.load_full()
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

        // Seed the mutable overlay from boot config; `hydrate` overlays the
        // persisted `server_settings` row on top if one exists.
        let initial_settings = Arc::new(ArcSwap::from_pointee(
            crate::runtime_settings::RuntimeSettings::from_config(&config),
        ));

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

        let mut proj_updates = ProjectionState::new();
        hydrate_projections_from_persistence(
            self.persistence.as_ref(),
            &mut proj_updates,
            &self.authz,
        )
        .await;
        {
            let mut proj = self.projection.lock();
            proj.realm_states.extend(proj_updates.realm_states);
            proj.space_containers.extend(proj_updates.space_containers);
            proj.strands.extend(proj_updates.strands);
            proj.morphs.extend(proj_updates.morphs);
            proj.mls_key_packages.extend(proj_updates.mls_key_packages);
            proj.mls_commit_epochs
                .extend(proj_updates.mls_commit_epochs);
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
                let row = crate::reducer::RealmOrganizationStatementState {
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
        match self
            .persistence
            .sync_cursors()
            .active_revocations(now)
            .await
        {
            Ok(revocations) => {
                let mut cache = self.sync_cursor_revocations.lock();
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

/// Fill `out` with cryptographically secure random bytes via `rand::rng`.
/// Used by service-identity bootstrap and development admin-key provisioning.
pub(crate) fn getrandom_seed(out: &mut [u8; 32]) {
    use rand::RngExt;
    rand::rng().fill(out);
}

#[cfg(test)]
mod membership_hydration_tests {
    use arkret_sdk::{Did, RealmId};

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
        use crate::persistence::{
            MlsKeyPackageRow, PersistenceStore, SolandMemoryPersistenceStore,
        };

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
        hydrate_projections_from_persistence(&store, &mut proj, &authz).await;

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
        let key = crate::reducer::MlsCommitEpochKey::new(
            crate::reducer::mls::effective_scope_key(&effective_scope).unwrap(),
            group_id.to_owned(),
        );
        let epoch = proj
            .mls_commit_epochs
            .get(&key)
            .expect("commit epoch rehydrated");
        assert_eq!(epoch.epoch, 0);
        assert_eq!(epoch.policy_root, "sha256:locked-root");
    }

    #[tokio::test]
    async fn realm_owner_rehydrates_for_capability_upper_bound_checks() {
        use crate::persistence::{PersistenceStore, SolandMemoryPersistenceStore};

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
        hydrate_projections_from_persistence(&store, &mut proj, &SolandAuthzEngine::new()).await;

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
