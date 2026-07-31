#[cfg(test)]
use std::collections::BTreeSet;
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};

use arc_swap::ArcSwap;
use arkret_identifiers::{Did, RealmId};
use arkret_identity::service_identity::ServiceIdentityState;
#[cfg(test)]
use arkret_identity::service_identity::{LocalServiceIdentity, ServiceIdentityKeyRef};
use arkret_models_collaboration::objects::account_status::AccountStatus;
use arkret_models_identity::account::AccountRegistrationPolicy;
#[cfg(test)]
use arkret_models_identity::service_identity::{CanonicalServiceUrl, ServiceRegistrationKey};
#[cfg(test)]
use arkret_wire::ServiceKind;
use ed25519_dalek::{SigningKey, VerifyingKey};
use serde_json::Value;
use sha2::{Digest, Sha256};
use soland_services::authorization::{
    AuthorizationCheck, AuthorizationDecision, AuthorizationPort, AuthorizationService,
};
use soland_services::delivery::{DeliveryService, ObjectStoragePort};
use soland_services::events::{
    EventQueryService, EventService, MlsCommitQueryService, MlsKeyPackageService,
    RealmDirectoryEntry, RealmDirectoryIndex, RealmDirectoryService, RealmInviteService,
    RealmQueryService,
};
use soland_services::federation::{FederationService, SovereignDeploymentState};
use soland_services::governance::{AdminSigningKeyPort, GovernanceService, RuntimeSettingsPort};
use soland_services::hydration::HydrationProjectionAdapter;
use soland_services::identity::{
    AccountDataService, AgentPairingService, AgentParticipationService, ConsentService,
    ContactService, DevicePairingService, DidService, IdentityService, KeyBackupService,
    KeyMaterialService, RecoveryPolicyService, RecoverySessionService, SecurityTransactionService,
    SessionService,
};
use soland_services::jobs::{JobsService, RuntimeHealthPort};
use soland_services::join_applications::JoinApplicationService;
use soland_services::organization_registration::OrganizationRegistrationService;
use soland_services::persistence::PersistenceHandle;
use soland_services::persistence_events::PersistenceEventServices;
use soland_services::persistence_identity::PersistenceIdentityServices;
use soland_services::persistence_operations::PersistenceOperationalServices;
#[cfg(test)]
use soland_services::projection::ProjectionSnapshot as ProjectionState;
use soland_services::projection::{ProjectionService, ServiceClock};
use soland_services::runtime_guards::{
    KeyBackupDownloadOutcome, ModerationReportRateOutcome, RuntimeGuardService,
};
use soland_services::sync::SyncService;

use super::did_resolver_chain;
use super::member_identity::MemberIdentityRegistry;
use super::notification::{EventBroadcast, EventNotification, Mutex};
use crate::authz::SolandAuthzEngine;
use crate::config::{AppConfig, NotarySigningKeyOrigin};
use crate::verified_profiles::VerifiedProfileDescriptor;

/// Upper bound on accepted DID bindings held in process. Eviction is
/// deterministic (oldest `verified_at` first) in the SDK store, and evicting a
/// binding only costs one re-acceptance — never a downgrade of trust.
const DID_BINDING_STORE_CAPACITY: usize = 4_096;

/// Single-process service state. Every long-lived data surface lives behind
/// `persistence` (a `dyn PersistenceStore`); the few remaining fields are
/// either non-record state (config, db pool, hlc, authz engine) or runtime
/// facets that don't fit the trait shape (in-memory `RealmDirectoryIndex`,
/// DID resolver service, `ProjectionState`).
#[derive(Clone)]
pub struct AppState {
    config: AppConfig,
    /// Runtime-authoritative service DID. It is resolved from durable identity
    /// state before construction and is never loaded from configuration.
    service_id: String,
    /// Full service-identity lifecycle state used by readiness, doctor, and
    /// identity-mutation gates.
    service_identity: Arc<ArcSwap<ServiceIdentityState>>,
    /// Mutable operational overlay (admin allowlist, rate-limit ceilings,
    /// federation peers, feature toggles). Seeded from `config` at boot,
    /// overlaid by the `server_settings` DB row in [`AppState::hydrate`], and
    /// hot-swapped by the admin settings endpoint. Read a consistent snapshot
    /// via [`AppState::settings`]. See [`crate::runtime_settings`].
    settings: Arc<ArcSwap<crate::runtime_settings::RuntimeSettings>>,
    storage_mode: &'static str,
    persistence: PersistenceHandle,
    events: EventService,
    event_queries: EventQueryService,
    mls_commits: MlsCommitQueryService,
    mls_key_packages: MlsKeyPackageService,
    realms: RealmQueryService,
    realm_invites: RealmInviteService,
    deliveries: DeliveryService,
    identities: IdentityService,
    account_data: AccountDataService,
    key_material: KeyMaterialService,
    consents: ConsentService,
    contacts: ContactService,
    agent_pairings: AgentPairingService,
    device_pairings: DevicePairingService,
    agent_participations: AgentParticipationService,
    key_backups: KeyBackupService,
    sessions: SessionService,
    recovery_policies: RecoveryPolicyService,
    recovery_sessions: RecoverySessionService,
    security_transactions: SecurityTransactionService,
    dids: DidService,
    /// Accepted DID authority bindings (`did-usage-and-verification.md` §5).
    ///
    /// This is the SDK's shared value object + store — soland deliberately does
    /// not define a parallel model. Ordinary Event ingress consults it before
    /// touching the authority path, so a second Event signed by the same
    /// accepted key resolves nothing.
    did_bindings: Arc<dyn arkret_identity::VerifiedDidBindingStore>,
    organization_registrations: OrganizationRegistrationService,
    federation: FederationService,
    governance: GovernanceService,
    sync: SyncService,
    jobs: JobsService,
    join_applications: JoinApplicationService,
    projections: ProjectionService,
    authorization: AuthorizationService,
    realm_directory: RealmDirectoryService,
    /// Deployment-local account registration policy. It uses the canonical
    /// account-operation DTO so the HTTP handler, audit payload, tests, and a
    /// future admin policy cell all speak the same wire vocabulary.
    account_registration_policy: Arc<Mutex<AccountRegistrationPolicy>>,
    runtime_guards: RuntimeGuardService,
    /// Domain-separated HMAC key for the deterministic stateful sync-cursor
    /// handle (`routing/events/sync.rs::derive_cursor_handle`). The handle
    /// binding rows themselves live in the durable
    /// `persistence.sync_cursors()` table, so a restart no longer invalidates
    /// every client's resume cursor.
    /// Domain-separated root key for service-scoped push target pseudonyms.
    /// Per-epoch keys are derived from this root inside the push routing
    /// module; only public epoch labels are exposed on describe.
    /// Revoked cursor authorities (`ak.self.account.command.revoke_cursor`). High-assurance
    /// optional endpoint: a revoked cursor returns `cursor_revoked` and MUST NOT
    /// advance to-device ack, account-subscribe resume position, wait-for barrier
    /// state, or dropped-recovery state. Entries are pruned once the revoked
    /// cursor's maximum TTL has elapsed (`CursorRevocation::expires_at`).
    /// Monotonic position allocator for to-device queues. Cursor ack uses
    /// numeric `position <= ack_position` pruning, so positions must advance
    /// even when multiple fanout writes land in the same wall-clock microsecond.
    to_device_position_counter: Arc<AtomicI64>,
    /// Runtime state for sovereign-main / enclave deployment handshakes,
    /// trust-root decisions, boundary audit, and store-and-forward queues.
    /// The P2-056 implementation keeps this in memory so the dual-soland
    /// conformance harness can exercise the protocol shape locally; a durable
    /// store can replace the backing map without changing the HTTP contract.
    /// Runtime-only verification keys learned from endpoint-discovered
    /// federation peer DID documents. Entries are keyed either by service DID
    /// (the HTTP Message Signature key) or by an exact verification-method
    /// DID URL (artifact-specific assertion keys). Configuration contains
    /// endpoints, not copied service DIDs or public-key pins; discovery
    /// validates the document's Principal Server endpoint binding before
    /// publishing a key.
    federation_peer_verifying_keys: Arc<ArcSwap<BTreeMap<String, VerifyingKey>>>,
    /// Live event notification bus for `ak.self.events.stream.subscribe`.
    /// Memory mode uses the local broadcast channel; PostgreSQL mode also
    /// publishes over LISTEN/NOTIFY so subscribers connected to another
    /// replica receive the same live frames.
    event_broadcast: EventBroadcast,
    /// Lossy process-local acceleration signal. Durable pending rows remain
    /// the reconciliation source of truth after missed wakeups or restarts.
    control_seal_wakeup: Arc<tokio::sync::Notify>,
    /// Server-enforced reconnect windows advertised by subscribe control
    /// frames. This prevents a faulty or overloaded client from immediately
    /// re-opening the same subscribe scope after `dropped` /
    /// `resync_required`.
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
    notary_signing_key: Arc<ArcSwap<SigningKey>>,
    /// The origin tag rotates with the key. Stored alongside it
    /// behind a [`Mutex`] (one-shot writes from the rotation path are not
    /// in the hot read path; the per-pass diagnostic helper just snapshots).
    notary_signing_key_origin: Arc<Mutex<NotarySigningKeyOrigin>>,
    /// Per-admin signing keys: SDK
    /// [`arkret_auth::AdminKeyStore`] keyed by the `application_id`
    /// `soland.<service_id>`. Each admin DID in
    /// `config.admin_principal_dids` gets its own ed25519 signing seed
    /// (provisioned at boot in `development_mode`; lazily loaded from the
    /// configured durable KeyStore otherwise). The signer for an admin DID is
    /// built via `admin_signer_for(state, admin_did)` — this replaces the
    /// service-wide `service_admin_signer` shortcut for endpoints that
    /// want operator attribution in the audit chain.
    /// G4.T3 — verified-profile descriptors loaded from the artifact path in
    /// `SOLAND_VERIFIED_PROFILES_ARTIFACT` at startup. Filtered to entries
    /// whose `service_role == "principal_server"` and additionally
    /// cross-checked against the local `claimed_profiles[]` set inside
    /// `describe.rs::apply_claim_level_partition`. Empty when the env var
    /// is unset / file missing / file malformed — that's the dev-mode
    /// invariant in service-surface.md §3.0.
    verified_profiles: Arc<Vec<VerifiedProfileDescriptor>>,
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
    member_identity: Arc<Mutex<MemberIdentityRegistry>>,
}

pub struct AppStateRuntime {
    pub persistence: PersistenceHandle,
    pub projections: ProjectionService,
    pub realm_directory: RealmDirectoryService,
    pub projected_operation_persistence:
        Arc<dyn soland_services::events::ProjectedOperationPersistencePort>,
    pub object_storage: Arc<dyn ObjectStoragePort>,
    pub settings_persistence: Arc<dyn RuntimeSettingsPort>,
    pub runtime_health: Arc<dyn RuntimeHealthPort>,
    pub event_broadcast: EventBroadcast,
    pub storage_mode: &'static str,
}

pub fn build_realm_directory(config: &AppConfig) -> RealmDirectoryService {
    let mut realms = RealmDirectoryIndex::new();
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
    RealmDirectoryService::new(realms)
}

#[cfg(test)]
fn development_fixture_service_identity(config: &AppConfig) -> ServiceIdentityState {
    let registration_key = ServiceRegistrationKey::new(
        ServiceKind::PrincipalServer,
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

#[cfg(test)]
mod test_construction {
    use std::collections::{BTreeMap, BTreeSet};
    use std::ops::Range;
    use std::path::Path;

    use async_trait::async_trait;
    use bytes::Bytes;
    use futures_util::stream::{self, BoxStream, StreamExt};
    use parking_lot::Mutex;
    use soland_services::events::ProjectedOperationPersistencePort;
    use soland_services::governance::RuntimeSettingsPort;
    use soland_services::jobs::RuntimeHealthPort;
    use soland_services::projection::EventSealCommitPort;
    use soland_storage::PersistenceStore;
    use soland_storage_memory::SolandMemoryPersistenceStore;
    use soland_storage_postgres::{Db, EventSealCommitStore, PgPersistenceStore};

    use super::*;

    impl AppState {
        pub fn new(config: AppConfig, db: Db) -> Self {
            let fallback: Arc<dyn PersistenceStore> = if config.seed_demo_data {
                Arc::new(SolandMemoryPersistenceStore::new_with_demo_data())
            } else {
                Arc::new(SolandMemoryPersistenceStore::new())
            };
            let persistence = db.pool.as_ref().map_or_else(
                || fallback.clone(),
                |pool| Arc::new(PgPersistenceStore::new(pool.clone(), fallback.clone())),
            );
            Self::new_with_persistence(config, db, persistence)
        }

        pub fn new_with_persistence(
            config: AppConfig,
            db: Db,
            persistence: Arc<dyn PersistenceStore>,
        ) -> Self {
            let identity = development_fixture_service_identity(&config);
            let signing_seed = fixture_signing_seed(&config, &identity);
            Self::new_with_service_identity(config, db, persistence, identity, signing_seed)
        }

        pub fn new_with_service_identity(
            config: AppConfig,
            db: Db,
            persistence: Arc<dyn PersistenceStore>,
            service_identity: ServiceIdentityState,
            resolved_signing_seed: [u8; 32],
        ) -> Self {
            let cell_registry = ProjectionService::sdk_cell_registry();
            let stores = soland_storage_postgres::build_state_resolution_stores(
                db.pool.clone(),
                cell_registry,
            );
            let event_seal_committer =
                Arc::new(TestEventSealCommitter(stores.event_seal_committer));
            let storage_mode = db.mode();
            let service_id = service_identity
                .identity()
                .expect("fixture has a serving identity")
                .service_id
                .to_string();
            let projections = ProjectionService::new(
                stores.control_event_store,
                stores.seal_store,
                stores.cell_store,
                stores.cell_registry,
                event_seal_committer,
                &service_id,
            );
            let realm_directory = build_realm_directory(&config);
            Self::from_runtime(
                config,
                AppStateRuntime {
                    persistence: PersistenceHandle::from_shared(persistence),
                    projections,
                    realm_directory,
                    projected_operation_persistence: Arc::new(NoProjectedOperationPersistence),
                    object_storage: Arc::new(MemoryObjectStorage::default()),
                    settings_persistence: Arc::new(NoRuntimeSettings),
                    runtime_health: Arc::new(TestRuntimeHealth(db)),
                    event_broadcast: EventBroadcast::new(1024),
                    storage_mode,
                },
                service_identity,
                resolved_signing_seed,
            )
        }
    }

    fn fixture_signing_seed(config: &AppConfig, identity: &ServiceIdentityState) -> [u8; 32] {
        config.notary_signing_key_seed.unwrap_or_else(|| {
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
        })
    }

    struct TestEventSealCommitter(Arc<dyn EventSealCommitStore>);

    impl EventSealCommitPort for TestEventSealCommitter {
        fn commit_if_frontier(
            &self,
            seal: &arkret_wire::Seal,
            expected_store_frontier: &[arkret_identifiers::SealId],
            new_ops: &[(
                arkret_identifiers::CellRef,
                arkret_state::lattice::ordered_log::IssuedOp,
            )],
            covered: &BTreeSet<arkret_identifiers::Hash>,
        ) -> arkret_state::state::StoreResult<bool> {
            self.0
                .commit_if_frontier(seal, expected_store_frontier, new_ops, covered)
        }
    }

    #[derive(Default)]
    struct MemoryObjectStorage {
        objects: Mutex<BTreeMap<String, Vec<u8>>>,
    }

    #[async_trait]
    impl ObjectStoragePort for MemoryObjectStorage {
        fn backend_name(&self) -> String {
            "memory".to_owned()
        }

        fn object_key_for_sha256(&self, sha256: &str) -> String {
            format!("sha256/{sha256}")
        }

        async fn put(&self, key: &str, bytes: Vec<u8>) -> Result<(), String> {
            self.objects.lock().insert(key.to_owned(), bytes);
            Ok(())
        }

        async fn put_file(&self, key: &str, file_path: &Path) -> Result<(), String> {
            self.put(
                key,
                std::fs::read(file_path).map_err(|error| error.to_string())?,
            )
            .await
        }

        async fn get(&self, key: &str) -> Result<Vec<u8>, String> {
            self.objects
                .lock()
                .get(key)
                .cloned()
                .ok_or_else(|| format!("object not found: {key}"))
        }

        async fn get_range_stream(
            &self,
            key: &str,
            range: Range<u64>,
        ) -> Result<BoxStream<'static, Result<Bytes, String>>, String> {
            let bytes = self.get(key).await?;
            let start = usize::try_from(range.start).map_err(|error| error.to_string())?;
            let end = usize::try_from(range.end).map_err(|error| error.to_string())?;
            let slice = bytes
                .get(start..end.min(bytes.len()))
                .ok_or_else(|| "object range is out of bounds".to_owned())?
                .to_vec();
            Ok(stream::once(async move { Ok(Bytes::from(slice)) }).boxed())
        }

        async fn delete(&self, key: &str) -> Result<(), String> {
            self.objects.lock().remove(key);
            Ok(())
        }
    }

    struct NoProjectedOperationPersistence;

    #[async_trait]
    impl ProjectedOperationPersistencePort for NoProjectedOperationPersistence {
        async fn persist_projected_operation(
            &self,
            _origin: &str,
            _operation: &arkret_event_draft::Operation,
            _event_type: &str,
            _is_message_create: bool,
            _is_membership_or_realm_lifecycle: bool,
        ) -> Result<(), String> {
            Ok(())
        }
    }

    struct NoRuntimeSettings;

    #[async_trait]
    impl RuntimeSettingsPort for NoRuntimeSettings {
        async fn load_overrides(&self) -> soland_services::ServiceResult<Vec<(String, Value)>> {
            Ok(Vec::new())
        }

        async fn store_override(
            &self,
            _key: &str,
            _value: &Value,
            _updated_by: &str,
        ) -> soland_services::ServiceResult<()> {
            Ok(())
        }
    }

    struct TestRuntimeHealth(Db);

    #[async_trait]
    impl RuntimeHealthPort for TestRuntimeHealth {
        async fn database_ready(&self) -> bool {
            soland_storage_postgres::database_ready(self.0.pool.as_ref()).await
        }

        fn storage_mode(&self) -> &'static str {
            self.0.mode()
        }

        fn migrations_applied(&self) -> bool {
            self.0.migrations_applied()
        }

        fn database_configured(&self) -> bool {
            self.0.pool.is_some()
        }

        fn database_pool_in_use(&self) -> u32 {
            self.0.pool_in_use()
        }
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
        self.storage_mode
    }

    pub fn install_federation_peer_verifying_key(
        &self,
        previous_service_id: Option<&str>,
        service_id: &str,
        verifying_key: VerifyingKey,
    ) {
        self.federation_peer_verifying_keys.rcu(|current| {
            let mut next = (**current).clone();
            if let Some(previous_service_id) = previous_service_id
                && previous_service_id != service_id
            {
                next.remove(previous_service_id);
            }
            next.insert(service_id.to_owned(), verifying_key);
            Arc::new(next)
        });
    }

    pub fn install_federation_peer_verification_method_key(
        &self,
        previous_verification_method: Option<&str>,
        verification_method: &str,
        verifying_key: VerifyingKey,
    ) {
        self.federation_peer_verifying_keys.rcu(|current| {
            let mut next = (**current).clone();
            if let Some(previous_verification_method) = previous_verification_method
                && previous_verification_method != verification_method
            {
                next.remove(previous_verification_method);
            }
            next.insert(verification_method.to_owned(), verifying_key);
            Arc::new(next)
        });
    }

    pub fn apply_resolved_federation_peers(&self, resolved: &HashMap<String, String>) {
        self.settings.rcu(|current| {
            let mut next = (**current).clone();
            for entry in &mut next.federation_peers {
                if let Some(discovered) = resolved.get(entry) {
                    *entry = discovered.clone();
                }
            }
            Arc::new(next)
        });
    }

    #[cfg(feature = "test-support")]
    #[doc(hidden)]
    pub fn test_registry_key(&self) -> usize {
        Arc::as_ptr(&self.settings) as usize
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
    /// hold the snapshot for the duration of a signing pass.
    pub fn notary_signing_key(&self) -> Arc<SigningKey> {
        self.notary_signing_key.load_full()
    }

    /// Public Ed25519 verifying key for the current notary signing key.
    ///
    /// Used by the `ak.call.state` participant_binding verifier: in the
    /// arkret_native self-signed deployment the binding `sig` is minted with
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

    /// Snapshot a peer assertion key bound to an exact verification-method
    /// DID URL in the endpoint-discovered service DID document.
    pub fn federation_peer_verification_method_key(
        &self,
        verification_method: &str,
    ) -> Option<VerifyingKey> {
        self.federation_peer_verifying_keys
            .load()
            .get(verification_method)
            .copied()
    }

    /// Origin tag for diagnostics (`Configured` / `Ephemeral` / `Rotated`).
    pub fn notary_signing_key_origin(&self) -> NotarySigningKeyOrigin {
        *self.notary_signing_key_origin.lock()
    }

    pub fn from_runtime(
        config: AppConfig,
        runtime: AppStateRuntime,
        service_identity: ServiceIdentityState,
        resolved_signing_seed: [u8; 32],
    ) -> Self {
        let AppStateRuntime {
            persistence,
            projections,
            realm_directory,
            projected_operation_persistence,
            object_storage,
            settings_persistence,
            runtime_health,
            event_broadcast,
            storage_mode,
        } = runtime;
        let now = chrono::Utc::now();

        let service_id = service_identity
            .identity()
            .expect("AppState requires a serving service identity")
            .service_id
            .to_string();
        let service_identity = Arc::new(ArcSwap::from_pointee(service_identity));

        // Build the production DID resolver chain before the struct literal
        // so we can still
        // borrow `&config` for the helper before `config` itself is
        // moved into `Self.config`.
        let did_resolver = Arc::new(did_resolver_chain::build_soland_did_resolver(&config));
        // §5 — one process-wide accepted-binding store. Building it here (not
        // per request) is what makes "second Event under the same accepted key
        // costs zero resolver calls" structural rather than incidental.
        let did_bindings: Arc<dyn arkret_identity::VerifiedDidBindingStore> = Arc::new(
            arkret_identity::InMemoryVerifiedDidBindingStore::new(DID_BINDING_STORE_CAPACITY),
        );

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
        let admin_keystore_inner: Box<dyn arkret_keystore::KeyStore> = config
            .key_store
            .open(&admin_app_id)
            .expect("configured KeyStore must open every namespace")
            .unwrap_or_else(|| Box::new(arkret_keystore::InMemoryKeyStore::new()));
        let admin_keystore =
            arkret_auth::AdminKeyStore::new(admin_app_id.clone(), admin_keystore_inner);
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

        // Seed the mutable overlay from boot config; `hydrate` overlays the
        // persisted `server_settings` row on top if one exists.
        let initial_settings = Arc::new(ArcSwap::from_pointee(
            crate::runtime_settings::RuntimeSettings::from_config(&config),
        ));

        let authorization = AuthorizationService::new(Arc::new(SolandAuthzEngine::new()));
        let PersistenceEventServices {
            events,
            queries: event_queries,
            mls_commits,
            mls_key_packages,
            realm_queries: realms,
            realm_invites,
        } = persistence.event_services(projected_operation_persistence);
        let deliveries = persistence.delivery_service(object_storage, push_target_hmac_key);
        let PersistenceIdentityServices {
            identity: identities,
            account_data,
            key_material,
            consent: consents,
            contact: contacts,
            agent_pairing: agent_pairings,
            device_pairing: device_pairings,
            agent_participation: agent_participations,
            key_backup: key_backups,
            session: sessions,
            recovery_policy: recovery_policies,
            recovery_session: recovery_sessions,
            security_transaction: security_transactions,
            did: dids,
            organization_registration: organization_registrations,
        } = persistence.identity_services(did_resolver.clone());
        let PersistenceOperationalServices {
            federation,
            governance,
            sync,
            jobs,
        } = persistence.operational_services(
            Arc::new(RuntimeAdminSigningKeys(admin_keystore)),
            settings_persistence,
            runtime_health,
            sync_cursor_hmac_key,
        );
        let join_applications = persistence.join_application_service();
        federation.install_sovereign_state(SovereignDeploymentState {
            upstream_available: true,
            ..Default::default()
        });

        Self {
            config,
            service_id: service_id.clone(),
            service_identity,
            settings: initial_settings,
            authorization,
            storage_mode,
            persistence,
            events,
            event_queries,
            mls_commits,
            mls_key_packages,
            realms,
            realm_invites,
            deliveries,
            identities,
            account_data,
            key_material,
            consents,
            contacts,
            agent_pairings,
            device_pairings,
            agent_participations,
            key_backups,
            sessions,
            recovery_policies,
            recovery_sessions,
            security_transactions,
            dids,
            did_bindings,
            organization_registrations,
            federation,
            governance,
            sync,
            jobs,
            join_applications,
            projections,
            realm_directory,
            account_registration_policy: Arc::new(Mutex::new(AccountRegistrationPolicy::default())),
            runtime_guards: RuntimeGuardService::default(),
            to_device_position_counter: Arc::new(AtomicI64::new(now.timestamp_micros())),
            federation_peer_verifying_keys: Arc::new(ArcSwap::from_pointee(BTreeMap::new())),
            event_broadcast,
            control_seal_wakeup: Arc::new(tokio::sync::Notify::new()),
            notary_signing_key,
            notary_signing_key_origin,
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

    pub fn replace_settings(&self, settings: crate::runtime_settings::RuntimeSettings) {
        self.settings.store(Arc::new(settings));
    }

    pub fn verified_profiles(&self) -> &[VerifiedProfileDescriptor] {
        self.verified_profiles.as_ref()
    }

    pub(crate) fn events(&self) -> &EventService {
        &self.events
    }

    pub(crate) fn event_queries(&self) -> &EventQueryService {
        &self.event_queries
    }

    pub(crate) fn mls_commits(&self) -> &MlsCommitQueryService {
        &self.mls_commits
    }

    pub(crate) fn mls_key_packages(&self) -> &MlsKeyPackageService {
        &self.mls_key_packages
    }

    pub(crate) fn realms(&self) -> &RealmQueryService {
        &self.realms
    }

    pub(crate) fn realm_invites(&self) -> &RealmInviteService {
        &self.realm_invites
    }

    pub(crate) fn deliveries(&self) -> &DeliveryService {
        &self.deliveries
    }

    pub(crate) fn identities(&self) -> &IdentityService {
        &self.identities
    }

    pub(crate) fn account_data(&self) -> &AccountDataService {
        &self.account_data
    }

    pub(crate) fn key_material(&self) -> &KeyMaterialService {
        &self.key_material
    }

    pub(crate) fn consents(&self) -> &ConsentService {
        &self.consents
    }

    pub(crate) fn contacts(&self) -> &ContactService {
        &self.contacts
    }

    pub(crate) fn dids(&self) -> &DidService {
        &self.dids
    }

    /// Accepted DID authority bindings (`did-usage-and-verification.md` §5).
    pub fn did_bindings(&self) -> &dyn arkret_identity::VerifiedDidBindingStore {
        self.did_bindings.as_ref()
    }

    /// Inject a spy / pre-seeded binding store. Tests use this to assert the
    /// DID-P1-A03 call-count contract without reaching the network.
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn test_set_did_binding_store(
        &mut self,
        store: Arc<dyn arkret_identity::VerifiedDidBindingStore>,
    ) {
        self.did_bindings = store;
    }

    /// The §5.3 `policy_digest` every binding this deployment accepts is scoped
    /// to.
    ///
    /// The computation is the SDK's canonical resolver policy snapshot
    /// (`ak.did.resolver_policy.v1`) and nothing else, so soland, teabay,
    /// bridges, coauth and inkson derive byte-identical digests from the same
    /// policy value instead of each encoding one.
    ///
    /// The snapshot's three required members — the accepted DID methods, the
    /// resolver fail mode and the trust roots — are what decide whether a
    /// resolution is admissible, and changing any of them changes the digest,
    /// which changes every [`arkret_identity::VerifiedDidBindingKey`], which
    /// makes every acceptance taken under the old policy structurally
    /// unreachable.
    ///
    /// # Why `development_mode` is no longer an input
    ///
    /// It used to be a digest extension. §5.3 closed the snapshot: a deployment
    /// with extra admissibility dimensions MUST register its own
    /// `policy_profile` with a closed `profile_policy` schema, and v1 registers
    /// only the base profile. Registering one would be right if the dimension
    /// could discriminate anything here — it cannot. `development_mode` comes
    /// from the startup `AppConfig` snapshot, and the acceptance store is the
    /// process-local `InMemoryVerifiedDidBindingStore` built alongside it in
    /// `AppState::new`, so no process can ever read an acceptance made under a
    /// different value of the flag. Keeping it would state a scoping property
    /// the store already provides structurally.
    ///
    /// Giving this store a durable backend would change that, and would then
    /// require a registered profile rather than a re-added extension.
    ///
    /// `trust_domain` is likewise not an input:
    /// [`arkret_identity::VerifiedDidBindingKey`] already carries it as its own
    /// key dimension, so folding it in here scopes nothing extra.
    pub fn did_binding_policy_digest(
        &self,
    ) -> Result<arkret_identifiers::Hash, arkret_identity::DigestError> {
        crate::state::did_resolver_chain::did_resolver_policy(self.config()).policy_digest()
    }

    /// Drop every accepted binding for `did` in this trust domain
    /// (`did-usage-and-verification.md` §5: rotation / deactivation /
    /// controller or service delegation change MUST invalidate).
    ///
    /// Called from the single place soland learns a DID document moved —
    /// [`Self::cache_resolved_did_document`] — so an ordinary Event can never
    /// keep verifying against a superseded key.
    pub fn invalidate_did_bindings(&self, did: &arkret_identifiers::Did) -> usize {
        self.did_bindings
            .invalidate(&arkret_identity::BindingInvalidation::for_did(did.clone()))
    }

    /// Ingest a freshly resolved / verified DID document into the resolver
    /// snapshot **and** invalidate any binding that pinned the previous one.
    pub(crate) fn cache_resolved_did_document(
        &self,
        record: soland_services::identity::DidDocumentState,
    ) -> Result<arkret_identity::DidDocument, String> {
        let document = self.dids.cache_resolved_document_state(record)?;
        // Only a document that actually moved invalidates: re-caching the same
        // bytes (which the freshness gate does on every high-risk check) must
        // not churn accepted bindings.
        if let Ok(digest) = arkret_identity::document_canonical_digest(&document) {
            let superseded = self.did_bindings.snapshot().into_iter().any(|accepted| {
                accepted.binding().did() == &document.id
                    && accepted.binding().document_digest() != &digest
            });
            if superseded {
                self.invalidate_did_bindings(&document.id);
            }
        }
        Ok(document)
    }

    /// This deployment's trust domain as the typed identifier the SDK binding
    /// key expects.
    pub fn did_binding_trust_domain(
        &self,
    ) -> Result<arkret_identifiers::TypedTrustDomainId, String> {
        arkret_identifiers::TypedTrustDomainId::new(self.config().trust_domain.clone())
            .map_err(|error| format!("configured trust_domain is invalid: {error}"))
    }

    pub(crate) fn organization_registrations(&self) -> &OrganizationRegistrationService {
        &self.organization_registrations
    }

    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn test_set_organization_registration_service(
        &mut self,
        service: OrganizationRegistrationService,
    ) {
        self.organization_registrations = service;
    }

    pub(crate) fn agent_pairings(&self) -> &AgentPairingService {
        &self.agent_pairings
    }

    pub(crate) fn device_pairings(&self) -> &DevicePairingService {
        &self.device_pairings
    }

    pub(crate) fn agent_participations(&self) -> &AgentParticipationService {
        &self.agent_participations
    }

    pub(crate) fn key_backups(&self) -> &KeyBackupService {
        &self.key_backups
    }

    pub(crate) fn sessions(&self) -> &SessionService {
        &self.sessions
    }

    pub(crate) fn recovery_policies(&self) -> &RecoveryPolicyService {
        &self.recovery_policies
    }

    pub(crate) fn recovery_sessions(&self) -> &RecoverySessionService {
        &self.recovery_sessions
    }

    pub(crate) fn security_transactions(&self) -> &SecurityTransactionService {
        &self.security_transactions
    }

    pub(crate) fn federation(&self) -> &FederationService {
        &self.federation
    }

    pub(crate) fn governance(&self) -> &GovernanceService {
        &self.governance
    }

    pub(crate) fn sync(&self) -> &SyncService {
        &self.sync
    }

    pub(crate) fn jobs(&self) -> &JobsService {
        &self.jobs
    }

    pub(crate) fn join_applications(&self) -> &JoinApplicationService {
        &self.join_applications
    }

    pub(crate) fn projections(&self) -> &ProjectionService {
        &self.projections
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
    pub async fn hydrate(&self) -> soland_services::ServiceResult<()> {
        let now = chrono::Utc::now();
        // Overlay the persisted per-key operational settings on top of the
        // boot-config seed. Only overridden keys have rows; everything else
        // keeps its env default. Per-key decode failures are logged and
        // skipped so a corrupt row can never brick startup.
        match self.governance.runtime_setting_overrides().await {
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
        if self.config.seed_demo_data
            && let Err(error) = self.persistence.seed_demo_identity().await
        {
            tracing::warn!(%error, "failed to seed demo identity into persistence store");
        }

        // Build the hydrated views off-lock (the async DB reads must not hold
        // a std::sync Mutex guard across `.await`), then merge under a short
        // synchronous critical section.
        let realm_updates = self.persistence.hydrate_realm_directory().await;
        for (_, entry) in realm_updates.entries_iter() {
            self.realm_directory.upsert(entry.clone());
        }

        // A-model active-series signatures are bound to the current accepted
        // SSK generation. Rebuild the cross-signing registry before restoring those
        // pointers; otherwise a restart makes every correctly hydrated
        // pointer appear stale because the generation cache is empty.
        let cross_signing = self.persistence.hydrate_cross_signing().await?;
        self.identities
            .install_cross_signing_registry(cross_signing);

        let hydrated_realm_ids: Vec<RealmId> = {
            let realms = self.realm_directory.snapshot();
            realms
                .search(Default::default())
                .into_iter()
                .filter_map(|entry| RealmId::new(entry.realm_id.to_string()).ok())
                .collect()
        };
        // Install profile-private join records before replaying Realm Events.
        // Historical invite.create reducers can then consume their cited
        // review receipts without ever placing the private body in Event
        // history.
        for realm_id in &hydrated_realm_ids {
            for record in self
                .join_applications
                .list(realm_id.as_str(), chrono::Utc::now())
                .await?
            {
                self.projections.install_join_application_record(&record);
            }
        }
        self.persistence
            .hydrate_projection(
                &self.projections,
                &RuntimeHydrationProjectionAdapter,
                hydrated_realm_ids.clone(),
            )
            .await?;
        // Reconcile the durable consumed flag after a crash between Event
        // acceptance and the private-store mirror. The operation is
        // idempotent for records already marked consumed.
        for record in self.event_queries.canonical_events().await? {
            if record.kind != arkret_wire::events::EventKind::INVITE_CREATE {
                continue;
            }
            let Some(operation) =
                crate::routing::events::event_log::projection_operation_from_canonical_record(
                    &record,
                )
            else {
                continue;
            };
            crate::routing::events::projection::mirror_join_authorisation_consumption(
                self,
                &record.actor_id,
                &operation,
            )
            .await;
        }

        // Hydrate per-subject invite_receive_policy overrides into the
        // application-owned working projection.
        self.contacts.hydrate_runtime().await?;

        // Hydrate the holder-private consent-cell working projection owned by
        // the application service.
        self.consents.hydrate_runtime().await?;

        let mut direct_binding_records = self
            .event_queries()
            .canonical_events()
            .await?
            .into_iter()
            .filter(|record| {
                record.kind == arkret_wire::events::EventKind::DIRECT_CONVERSATION_BOUND
            })
            .collect::<Vec<_>>();
        // Fold active candidates before explicit retirements so a retirement
        // can resolve its supersedes_binding_ref regardless of storage order.
        direct_binding_records.sort_by_key(|record| {
            let retired = record
                .envelope
                .get("payload")
                .and_then(|payload| payload.get("binding_state"))
                .and_then(serde_json::Value::as_str)
                == Some("retired");
            (retired, record.received_at, record.event_id.clone())
        });
        for record in direct_binding_records {
            let Some(operation) =
                crate::routing::events::event_log::projection_operation_from_canonical_record(
                    &record,
                )
            else {
                tracing::warn!(event_id = %record.event_id, "ignored unprojectable direct binding during hydration");
                continue;
            };
            if let Err(reason) =
                crate::routing::identity::validate_direct_binding_operation(self, &operation).await
            {
                tracing::warn!(event_id = %record.event_id, reason, "ignored invalid direct binding during hydration");
                continue;
            }
            crate::routing::identity::project_canonical_direct_binding(self, &operation).await;
        }

        self.identities.hydrate_account_lifecycles().await?;

        self.governance.hydrate_projections().await?;
        // Hydrate the cursor-revocation cache from the durable
        // `sync_cursor_revocations` ledger so a revoked cursor stays revoked
        // across restarts (spec `client-sync.md` cursor-revoke semantics —
        // a revoked cursor MUST keep returning `cursor_revoked` and MUST NOT
        // advance to-device ack / resume / wait-for / dropped-recovery
        // state). Built off-lock first; merge under a short critical section.
        match self.sync().active_cursor_revocations(now).await {
            Ok(revocations) => self.sync().replace_cursor_revocations(revocations),
            Err(error) => {
                tracing::warn!(%error, "failed to hydrate cursor revocations from persistence store");
            }
        }
        Ok(())
    }

    pub(crate) fn member_identity_snapshot(
        &self,
        realm_id: &str,
        actor_id: &str,
    ) -> Option<super::MemberIdentitySnapshot> {
        self.member_identity
            .lock()
            .snapshot_for_actor(realm_id, actor_id)
    }

    pub(crate) fn handle_claims_snapshot(
        &self,
    ) -> BTreeMap<String, Vec<super::HandleClaimEvidenceRecord>> {
        self.member_identity.lock().snapshot_handle_claims()
    }

    pub(crate) fn member_identity_state_digest(
        &self,
        realm_id: &str,
        actor_id: &str,
    ) -> Option<String> {
        self.member_identity
            .lock()
            .current_state_digest_for_actor(realm_id, actor_id)
    }

    pub(crate) fn record_member_identity_update(
        &self,
        record: super::MemberIdentityEventRecord,
        identity_payload: &Value,
    ) {
        let mut registry = self.member_identity.lock();
        registry.insert(record);
        registry.upsert_handle_claims_from_identity_payload(identity_payload);
    }

    pub(crate) fn cache_handle_claim(&self, envelope: Value) -> Option<String> {
        self.member_identity
            .lock()
            .upsert_handle_claim_envelope(envelope)
    }

    pub(crate) fn cached_handle_claims_for_subject(
        &self,
        subject_id: &str,
    ) -> Vec<super::HandleClaimEvidenceRecord> {
        self.member_identity
            .lock()
            .handle_claims_for_subject(subject_id)
    }

    pub(crate) fn invalidate_cached_handle_claims_for_subject(&self, subject_id: &str) -> usize {
        self.member_identity
            .lock()
            .invalidate_handle_claims_for_subject(subject_id)
    }

    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn test_insert_member_identity(&self, record: super::MemberIdentityEventRecord) {
        self.member_identity.lock().insert(record);
    }

    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn test_cache_handle_claim(&self, envelope: Value) -> Option<String> {
        self.cache_handle_claim(envelope)
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

    pub fn account_registration_policy(&self) -> AccountRegistrationPolicy {
        self.account_registration_policy.lock().clone()
    }

    pub fn account_lifecycle_status(&self, did: &str) -> AccountStatus {
        self.identities.account_lifecycle_status(did)
    }

    pub fn account_lifecycle_state(&self, did: &str) -> String {
        self.identities.account_lifecycle_state(did)
    }

    /// Record a new peer KeyPackage claim attempt. Duplicate deliveries are
    /// checked against the durable idempotency ledger before this method is
    /// called and therefore do not consume quota.
    pub fn peer_keypackage_claim_rate_limited(
        &self,
        source_service_id: &str,
        target_principal_id: &str,
    ) -> bool {
        self.runtime_guards
            .peer_keypackage_claim_rate_limited(source_service_id, target_principal_id)
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
        self.runtime_guards
            .record_key_backup_download(principal_id, limit)
    }

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
        self.runtime_guards.record_moderation_report_attempt(
            reporter,
            source_service,
            realm_id,
            source_ip_hash,
            target_ref,
        )
    }

    /// Remember a franking replay nonce within a finite retention window.
    /// Returns `true` for a fresh nonce and `false` for an in-window replay.
    pub fn remember_moderation_franking_nonce(
        &self,
        realm_id: &str,
        received_by: &str,
        replay_nonce: &str,
    ) -> bool {
        self.runtime_guards
            .remember_moderation_franking_nonce(realm_id, received_by, replay_nonce)
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
        self.runtime_guards.remember_agent_approval_nonce(
            agent_id,
            authorization_ref,
            request_id,
            approval_nonce,
            expires_at,
        )
    }
}

impl AppState {
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn test_set_service_id(&mut self, service_id: String) {
        self.service_id = service_id;
    }

    #[cfg(test)]
    pub(crate) fn test_persistence(
        &self,
    ) -> Arc<soland_services::persistence::TestPersistenceStore> {
        self.persistence.shared_for_tests()
    }

    #[cfg(test)]
    pub(crate) fn test_projection(&self) -> &Arc<Mutex<ProjectionState>> {
        self.projections.test_state()
    }

    pub(crate) fn realm_directory(&self) -> &RealmDirectoryService {
        &self.realm_directory
    }

    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn test_hlc(&self) -> &ServiceClock {
        self.hlc()
    }

    pub(crate) fn hlc(&self) -> &ServiceClock {
        self.projections.clock()
    }

    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn test_authz(&self) -> &AuthorizationService {
        &self.authorization
    }

    /// Fixture-only: publish a grant into the authz index the way accepting a
    /// capability Event does. A test that seals a governance basis directly
    /// never runs the accept path, so without this the authz surface denies
    /// actions the sealed basis grants.
    #[doc(hidden)]
    pub fn upsert_projected_grant_for_test(&self, grant: arkret_policy::authz::delegation::Grant) {
        self.authorization().upsert_projected_grant(grant);
    }

    pub(crate) fn authorization(&self) -> &AuthorizationService {
        &self.authorization
    }

    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn test_object_key_for_sha256(&self, sha256: &str) -> String {
        self.deliveries.object_key_for_sha256(sha256)
    }

    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub async fn test_put_object(&self, key: &str, bytes: Vec<u8>) -> Result<(), String> {
        self.deliveries.put_object(key, bytes).await
    }

    pub(crate) fn subscribe_event_notifications(
        &self,
    ) -> tokio::sync::broadcast::Receiver<EventNotification> {
        self.event_broadcast.subscribe()
    }

    pub(crate) fn publish_event_notification(
        &self,
        notification: EventNotification,
    ) -> Result<usize, tokio::sync::broadcast::error::SendError<EventNotification>> {
        self.event_broadcast.send(notification)
    }

    pub(crate) fn wake_control_seal_coordinator(&self) {
        self.control_seal_wakeup.notify_one();
    }

    pub(crate) async fn control_seal_wakeup_notified(&self) {
        self.control_seal_wakeup.notified().await;
    }

    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn test_subscribe_event_notifications(
        &self,
    ) -> tokio::sync::broadcast::Receiver<EventNotification> {
        self.subscribe_event_notifications()
    }

    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn test_publish_event_notification(
        &self,
        notification: EventNotification,
    ) -> Result<usize, tokio::sync::broadcast::error::SendError<EventNotification>> {
        self.publish_event_notification(notification)
    }

    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn test_cache_resolved_webvh_record(
        &self,
        record: soland_services::identity::DidDocumentState,
    ) -> Result<arkret_identity::DidDocument, String> {
        self.dids.cache_resolved_document_state(record)
    }

    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn test_account_registration_policy(&self) -> &Arc<Mutex<AccountRegistrationPolicy>> {
        &self.account_registration_policy
    }

    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn test_install_consent_cell(&self, cell: soland_services::identity::ConsentCellRecord) {
        self.consents.install_runtime_cell(cell);
    }

    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn test_direct_conversation_binding_count(&self) -> usize {
        self.contacts.runtime_direct_binding_count()
    }

    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn test_record_cross_signing_publish(
        &self,
        publish: arkret_models_identity::CrossSigningPublish,
    ) -> arkret_identity::Result<()> {
        self.identities.record_cross_signing_publish(publish)
    }

    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn test_record_cross_signing_reset(
        &self,
        reset: &arkret_models_identity::CrossSigningResetPayload,
    ) -> arkret_identity::Result<()> {
        self.identities.record_cross_signing_reset(reset)
    }

    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn test_has_current_cross_signing(&self, principal: &arkret_identifiers::Did) -> bool {
        self.identities.current_cross_signing(principal).is_some()
    }

    /// Refresh one test fixture grant from the durable sealed-cell projection
    /// into the runtime authorization index.
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn test_refresh_grant_from_sealed_cells(
        &self,
        realm_id: &arkret_identifiers::RealmId,
        grant_id: &str,
    ) {
        self.projections
            .reload_cells_from_store(realm_id)
            .expect("test fixture sealed cells reload");
        let grant = self
            .projections
            .effective_engine_grant(grant_id)
            .expect("test fixture sealed grant is effective");
        self.authorization.upsert_projected_grant(grant);
    }
}

struct RuntimeAdminSigningKeys(Arc<arkret_auth::AdminKeyStore>);

struct RuntimeHydrationProjectionAdapter;

impl HydrationProjectionAdapter for RuntimeHydrationProjectionAdapter {
    fn operation_from_canonical_record(
        &self,
        record: &soland_services::events::CanonicalEventRecord,
    ) -> Option<arkret_event_draft::Operation> {
        crate::routing::events::event_log::projection_operation_from_canonical_record(record)
    }
}

impl AuthorizationPort for SolandAuthzEngine {
    fn check(&self, request: AuthorizationCheck<'_>) -> AuthorizationDecision {
        let AuthorizationCheck {
            actor,
            action,
            resource,
            realm_id,
            owner,
            members,
            resource_facets,
        } = request;
        let decision = self.check(
            actor,
            action,
            resource,
            realm_id,
            owner,
            members,
            resource_facets,
        );
        AuthorizationDecision {
            allowed: decision.allowed,
            reason: decision.reason,
            reason_detail: decision.reason_detail,
            grants: decision.grants,
        }
    }

    fn upsert_projected_grant(&self, grant: arkret_policy::authz::delegation::Grant) {
        self.upsert_projected_grant(grant);
    }

    fn mark_projected_grant_revoked(&self, grant_id: &str) {
        self.mark_projected_grant_revoked(grant_id);
    }

    fn mark_projected_grants_revoked_for_subject(&self, subject: &str) -> usize {
        self.mark_projected_grants_revoked_for_subject(subject)
    }

    fn get_grant(&self, grant_id: &str) -> Option<arkret_policy::authz::delegation::Grant> {
        self.get_grant(grant_id)
    }

    fn grants_for_subject(
        &self,
        subject: &str,
        realm_id: &str,
    ) -> Vec<arkret_policy::authz::delegation::Grant> {
        self.grants_for_subject(subject, realm_id)
    }

    fn grants_for_subject_all_realms(
        &self,
        subject: &str,
    ) -> Vec<arkret_policy::authz::delegation::Grant> {
        self.grants_for_subject_all_realms(subject)
    }

    fn grants_snapshot(&self) -> Vec<arkret_policy::authz::delegation::Grant> {
        self.grants_snapshot()
    }
}

impl AdminSigningKeyPort for RuntimeAdminSigningKeys {
    fn load_admin_key(&self, admin_did: &Did) -> Result<Vec<u8>, String> {
        self.0
            .load_admin_key(admin_did)
            .map(|bytes| bytes.to_vec())
            .map_err(|error| error.to_string())
    }
}

/// Fill `out` with cryptographically secure random bytes via `rand::rng`.
/// Used by service-identity bootstrap and development admin-key provisioning.
pub fn getrandom_seed(out: &mut [u8; 32]) {
    use rand::RngExt;
    rand::rng().fill(out);
}

#[cfg(test)]
mod membership_hydration_tests {
    use arkret_identifiers::{Did, RealmId};
    use soland_services::hydration::{
        hydrate_projections_from_persistence, hydrate_realm_member_state_event,
    };
    use soland_storage::{
        CanonicalEventRecord, EventProjectionStoreRegistry, IdentityStoreRegistry,
        MlsAgentStoreRegistry, PersistenceStore, RealmMetaRecord,
    };
    use soland_storage_memory::SolandMemoryPersistenceStore;
    use soland_storage_postgres::Db;

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

    #[tokio::test]
    async fn active_direct_binding_rows_are_not_boot_authority() {
        let state = AppState::new(AppConfig::test_default(), Db { pool: None });
        let now = chrono::Utc::now();
        state
            .test_persistence()
            .direct_conversation_bindings()
            .put(
                "sha256:stale-private-row",
                &soland_domain::identity::DirectConversationBindingRecord {
                    participants_unordered: vec![
                        "did:web:alice.example".to_owned(),
                        "did:web:bob.example".to_owned(),
                    ],
                    realm_id: "ak:realm:01904100-0000-7000-8000-000000000001".to_owned(),
                    main_strand_id: "ak:strand:01904100-0000-7000-8000-000000000002".to_owned(),
                    binding_event_ref: "ak:event:01904100-0000-7000-8000-000000000003".to_owned(),
                    state: "active".to_owned(),
                    authoring_context: None,
                    created_at: now,
                    updated_at: now,
                },
            )
            .await
            .expect("seed stale materialized binding row");

        state.hydrate().await.expect("hydrate application state");

        assert!(
            state
                .contacts()
                .direct_binding("sha256:stale-private-row")
                .is_none(),
            "active bindings must be rebuilt from accepted signed Events, not private rows"
        );
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

    // Regression for sidecar creation after restart: the Realm directory was
    // already replaying member Events, but the reducer cache was not. That
    // made an agent visible as a Realm member in Inkson while
    // `ak.circle.member.state` rejected the same agent as a non-member.
    #[tokio::test]
    async fn joined_member_survives_reducer_projection_hydration() {
        let realm_id = "ak:realm:019f0dd3-081c-7f03-b388-e0399e7759fc";
        let member = "did:web:bob.example";
        let store = SolandMemoryPersistenceStore::new();
        store
            .events()
            .put(CanonicalEventRecord {
                event_id: "ak:event:019f0dd3-081c-7f03-b388-e0399e775901".to_owned(),
                actor_id: "did:web:alice.example".to_owned(),
                actor_seq: 2,
                realm_id: Some(realm_id.to_owned()),
                kind: arkret_wire::events::EventKind::MEMBER_STATE.to_owned(),
                schema_id: "ak.schema.event.v1".to_owned(),
                canonical_digest: "sha256:membership".to_owned(),
                canonical_bytes: Vec::new(),
                envelope: serde_json::json!({
                    "event_id": "ak:event:019f0dd3-081c-7f03-b388-e0399e775901",
                    "actor_id": "did:web:alice.example",
                    "actor_seq": 2,
                    "realm_id": realm_id,
                    "kind": arkret_wire::events::EventKind::MEMBER_STATE,
                    "created_at": "2026-07-20T00:00:00.000Z",
                    "payload": {
                        "actor_id": member,
                        "membership": "join",
                        "delivery_status": "unroutable",
                    },
                }),
                received_at: chrono::DateTime::parse_from_rfc3339("2026-07-20T00:00:01.000Z")
                    .unwrap()
                    .with_timezone(&chrono::Utc),
            })
            .await
            .expect("persist member Event");

        let mut projection = ProjectionState::new();
        projection.realm_states.insert(
            realm_id.to_owned(),
            soland_domain::reducer::SolandRealmState {
                realm_id: realm_id.to_owned(),
                owner: Some("did:web:alice.example".to_owned()),
                title: Some("Hydration Test Realm".to_owned()),
                deleted: false,
                archived: false,
                frozen: false,
                freeze_expires_at: None,
                created_at: chrono::Utc::now(),
                updated_at: chrono::Utc::now(),
                trust_domain: None,
                terminal_state: None,
                successor_realm_id: None,
                default_strand_id: None,
                active_profiles: Vec::new(),
            },
        );
        soland_services::hydration::hydrate_canonical_realm_memberships(
            &store,
            &mut projection,
            &RuntimeHydrationProjectionAdapter,
        )
        .await
        .expect("hydrate reducer memberships");

        let hydrated = projection
            .member(realm_id, member)
            .expect("joined member restored to reducer projection");
        assert_eq!(hydrated.state, "join");
        assert_eq!(hydrated.delivery_status.as_deref(), Some("unroutable"));
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
                agent_key_authorize_event_id: None,
                claimed_at: None,
                claim_expires_at_unix_ms: None,
                consumed_at: None,
                created_at: 1,
            })
            .await
            .expect("put keypackage");
        store
            .mls_key_packages()
            .put(&MlsKeyPackageRow {
                id: "ak:mls_keypackage:retired".to_owned(),
                keypackage_ref: "sha256:retired-ref".to_owned(),
                keypackage_digest: "sha256:retired-digest".to_owned(),
                actor_id: "did:web:bob.example".to_owned(),
                device_id: "ak:device:bob-1".to_owned(),
                key_package_bytes: vec![4, 5, 6],
                capabilities: vec!["ak.content.v1".to_owned()],
                capabilities_digest: "sha256:retired-caps".to_owned(),
                device_signature: serde_json::json!({}),
                last_resort: false,
                last_resort_realm_id: None,
                lifetime_not_before: 0,
                lifetime_not_after: i64::MAX,
                claimed_by_mls_group_id: Some("retired".to_owned()),
                ssk_generation: None,
                device_authorize_event_id: Some("ak:event:auth".to_owned()),
                agent_key_authorize_event_id: None,
                claimed_at: None,
                claim_expires_at_unix_ms: None,
                consumed_at: None,
                created_at: 2,
            })
            .await
            .expect("put retired keypackage");

        let effective_scope = serde_json::json!({ "kind": "realm", "realm_id": realm_id });
        let governance_binding = serde_json::json!({ "policy_root": "sha256:locked-root" });
        store
            .mls_commits()
            .initialize_genesis(soland_storage::MlsCommitGenesis {
                effective_scope: &effective_scope,
                group_id,
                leader_actor_id: "did:web:alice.example",
                creator_device_id: "ak:device:alice-1",
                genesis_event_ref: "ak:event:genesis",
                covered_seals: &[],
                governance_binding: &governance_binding,
                committed_at: 1,
            })
            .await
            .expect("init genesis");

        let mut proj = ProjectionState::new();
        hydrate_projections_from_persistence(&store, &mut proj, &RuntimeHydrationProjectionAdapter)
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
        let retired = proj
            .mls_key_packages
            .get("ak:mls_keypackage:retired")
            .expect("retired keypackage rehydrated");
        assert_eq!(retired.claimed_by.as_deref(), Some("retired"));
        assert!(retired.claimed_at.is_none());
        assert!(retired.claim_expires_at_unix_ms.is_none());
        assert!(retired.consumed_at.is_none());

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
        assert_eq!(epoch.creator_device_id, "ak:device:alice-1");
        assert_eq!(epoch.genesis_event_ref, "ak:event:genesis");
        assert_eq!(epoch.governance_binding, governance_binding);
    }

    #[test]
    fn child_scope_policy_hydration_uses_the_sdk_wire_type_and_fails_closed() {
        let circle_id = "ak:circle:0196419b-0000-7000-8000-000000000003";
        assert_eq!(
            soland_services::hydration::parse_child_scope_policy(None, None).unwrap(),
            None
        );
        assert_eq!(
            soland_services::hydration::parse_child_scope_policy(
                Some("require_scope_circle_id"),
                Some(circle_id),
            )
            .unwrap(),
            Some(arkret_models_collaboration::objects::space::ChildScopePolicy::RequireScopeCircleId {
                scope_circle_id: arkret_identifiers::CircleId::new(circle_id.to_owned()).unwrap(),
            })
        );
        assert!(
            soland_services::hydration::parse_child_scope_policy(
                Some("allow_any"),
                Some(circle_id)
            )
            .is_err()
        );
        assert!(
            soland_services::hydration::parse_child_scope_policy(
                Some("require_scope_circle_id"),
                None
            )
            .is_err()
        );
        assert!(
            soland_services::hydration::parse_child_scope_policy(Some("legacy_policy"), None)
                .is_err()
        );
        assert!(
            soland_services::hydration::parse_child_scope_policy(None, Some(circle_id)).is_err()
        );
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
                event_kind: arkret_wire::events::EventKind::KEY_BACKUP_ACTIVE_SERIES.to_owned(),
                operation_kind: "event".to_owned(),
                operation_id: Some(
                    "ak:operation:019f0dd3-081c-7f03-b388-e0399e775903".to_owned(),
                ),
                sender: Some(actor.to_owned()),
                payload: serde_json::json!({
                    "schema": "ak.schema.key_backup_active_series.v1",
                    "actor_id": actor,
                    "backup_kind": "mls_history",
                    "active_series_id": series_id,
                    "series_pointer_version": 1,
                    "previous_series_ids": [],
                    "frontier_ref": {
                        "frontier_digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                        "seal_ref": "ak:seal:sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                        "ssk_generation": 1
                    },
                    "issued_at": "2026-07-18T00:00:00.000Z",
                    "auth_data": {
                        "verification_method": "did:web:alice.example#device-key",
                        "signature_algorithm": "Ed25519",
                        "signature": "AA",
                        "signed_fields": [
                            "schema",
                            "actor_id",
                            "backup_kind",
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
        hydrate_projections_from_persistence(&store, &mut proj, &RuntimeHydrationProjectionAdapter)
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
                event_kind: arkret_wire::events::EventKind::KEY_BACKUP_ACTIVE_SERIES.to_owned(),
                operation_kind: "event".to_owned(),
                operation_id: Some(
                    "ak:operation:019f0dd3-081c-7f03-b388-e0399e775905".to_owned(),
                ),
                sender: Some(actor.to_owned()),
                payload: serde_json::json!({
                    "schema": "ak.schema.key_backup_active_series.v1",
                    "actor_id": actor,
                    "backup_kind": "mls_history",
                    "active_series_id": series_id,
                    "series_pointer_version": 3,
                    "previous_series_ids": [],
                    "frontier_ref": {
                        "frontier_digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                        "ssk_generation": 1
                    },
                    "issued_at": "2026-07-18T00:01:00.000Z",
                    "auth_data": {
                        "verification_method": "did:web:alice.example#device-key",
                        "signature_algorithm": "Ed25519",
                        "signature": "AA",
                        "signed_fields": [
                            "schema", "actor_id", "backup_kind", "active_series_id",
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
            hydrate_projections_from_persistence(
                &store,
                &mut poisoned,
                &RuntimeHydrationProjectionAdapter,
            )
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
                event_kind: arkret_wire::events::EventKind::AGENT_KEY_AUTHORIZE.to_owned(),
                operation_kind: "event".to_owned(),
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
                event_kind: arkret_wire::events::EventKind::AGENT_KEY_REVOKE.to_owned(),
                operation_kind: "event".to_owned(),
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
                event_kind: arkret_wire::events::EventKind::AGENT_KEY_AUTHORIZE.to_owned(),
                operation_kind: "event".to_owned(),
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
        hydrate_projections_from_persistence(&store, &mut proj, &RuntimeHydrationProjectionAdapter)
            .await
            .expect("hydrate agent-key authorization");

        assert!(proj.agent_has_authorized_key(agent_id));
        assert_eq!(
            proj.active_agent_key_authorizations(agent_id),
            vec![(replacement_key_id, replacement_event_id.to_owned())]
        );
    }

    #[tokio::test]
    async fn realm_owner_metadata_rehydrates_without_implying_capability() {
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
        hydrate_projections_from_persistence(&store, &mut proj, &RuntimeHydrationProjectionAdapter)
            .await
            .expect("hydrate projections");

        let hydrated = proj.realm_states.get(realm_id).expect("realm rehydrated");
        assert_eq!(hydrated.owner.as_deref(), Some(owner));
        assert!(!proj.issuer_has_projected_capability(
            owner,
            realm_id,
            "ak.message.create",
            realm_id,
            chrono::Utc::now(),
        ));
    }
}
