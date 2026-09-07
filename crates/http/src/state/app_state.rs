#[cfg(test)]
use std::collections::BTreeSet;
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};

use arc_swap::ArcSwap;
use arkret_identifiers::{Did, DidCoreId, Hash, RealmId};
use arkret_identity::service_identity::DidCoreIdentityState;
#[cfg(test)]
use arkret_identity::service_identity::{DidCoreIdentityKeyRef, LocalDidCoreIdentity};
use arkret_models_collaboration::objects::account_status::AccountStatus;
use arkret_models_identity::ResolutionCommitment;
use arkret_models_identity::account::AccountRegistrationPolicy;
#[cfg(test)]
use arkret_models_identity::service_identity::{CanonicalServiceUrl, ServiceRegistrationKey};
#[cfg(test)]
use arkret_wire::ServiceKind;
use ed25519_dalek::{SigningKey, VerifyingKey};
use serde_json::Value;
use sha2::{Digest, Sha256};
#[cfg(test)]
use soland_domain::reducer::ProjectionState;
use soland_services::authorization::{
    AuthorizationCheck, AuthorizationDecision, AuthorizationPort, AuthorizationService,
};
use soland_services::delivery::{DeliveryService, ObjectStoragePort};
use soland_services::events::{
    EventQueryService, EventService, MlsCommitQueryService, MlsKeyPackageService,
    RealmDirectoryEntry, RealmDirectoryIndex, RealmDirectoryService, RealmInviteService,
    RealmQueryService,
};
use soland_services::federation::FederationService;
use soland_services::governance::{GovernanceService, RuntimeSettingsPort};
use soland_services::hydration::HydrationProjectionAdapter;
use soland_services::identity::{
    AccountDataService, AgentPairingService, AgentParticipationService, ConsentService,
    ContactService, DevicePairingService, DidService, IdentityService, KeyBackupService,
    KeyMaterialService, RecoveryPolicyService, RecoverySessionService, SecurityTransactionService,
    SessionService,
};
use soland_services::jobs::{JobsService, RuntimeHealthPort};
use soland_services::organization_registration::OrganizationRegistrationService;
use soland_services::persistence::PersistenceHandle;
use soland_services::persistence_events::PersistenceEventServices;
use soland_services::persistence_identity::PersistenceIdentityServices;
use soland_services::persistence_operations::PersistenceOperationalServices;
use soland_services::projection::{ProjectionService, ServiceClock};
use soland_services::runtime_guards::{
    KeyBackupDownloadOutcome, ModerationReportRateOutcome, RuntimeGuardService,
};
use soland_services::service_route::ServiceRouteResolver;
use soland_services::sync::SyncService;

use super::member_identity::MemberIdentityRegistry;
use super::notification::{EventBroadcast, EventNotification, Mutex};
use super::{VerifiedBindingRouteFetcher, did_resolver_chain};
use crate::authz::SolandAuthzEngine;
use crate::config::{AppConfig, NotarySigningKeyOrigin};
use crate::verified_profiles::VerifiedProfileArtifactEntry;

/// Upper bound on accepted DID bindings held in process. Eviction is
/// deterministic (oldest `verified_at` first) in the SDK store, and evicting a
/// binding only costs one re-acceptance — never a downgrade of trust.
const DID_BINDING_STORE_CAPACITY: usize = 4_096;

/// Reconnect delay a drained peer must honour before dialling again. It gives
/// the replacement instance time to become the one that answers.
const CONNECTION_DRAIN_RECONNECT_AFTER_MS: u32 = 5_000;

/// A published service drain: reconnect no sooner than `reconnect_after_ms`,
/// and expect this instance to stop serving at `deadline`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConnectionDrain {
    pub reconnect_after_ms: u32,
    pub deadline: chrono::DateTime<chrono::Utc>,
}

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
    service_identity: Arc<ArcSwap<DidCoreIdentityState>>,
    /// Exact current service method-history coordinates. Public describe,
    /// open resolution, and Account-Authority gate assembly all read this
    /// same snapshot instead of projecting a stable DidCoreId back into a DID.
    service_resolution_commitment: Arc<ArcSwap<ResolutionCommitment>>,
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
    /// Unique process-wide injection point for outbound service routing.
    /// Sending code must use this shared resolver (and fail closed while it is
    /// absent) so cache, durable floor, and quarantine decisions cannot split
    /// across ad-hoc resolver instances.
    service_route_resolver: Arc<Mutex<Option<Arc<ServiceRouteResolver>>>>,
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
    /// Revoked cursor authorities (`ak.self.account.command.revoke_cursor.v1`). High-assurance
    /// optional endpoint: a revoked cursor returns `cursor_revoked` and MUST NOT
    /// advance to-device ack, account-subscribe resume position, wait-for barrier
    /// state, or dropped-recovery state. Entries are pruned once the revoked
    /// cursor's maximum TTL has elapsed (`CursorRevocation::expires_at`).
    /// Monotonic position allocator for to-device queues. Cursor ack uses
    /// numeric `position <= ack_position` pruning, so positions must advance
    /// even when multiple fanout writes land in the same wall-clock microsecond.
    to_device_position_counter: Arc<AtomicI64>,
    /// Runtime-only verification keys learned from endpoint-discovered
    /// federation peer DID documents. Entries are keyed either by service DID
    /// (the HTTP Message Signature key) or by an exact verification-method
    /// DID URL (artifact-specific assertion keys). Configuration contains
    /// endpoints, not copied service DIDs or public-key pins; discovery
    /// validates the document's Station endpoint binding before
    /// publishing a key.
    federation_peer_verifying_keys: Arc<ArcSwap<BTreeMap<String, VerifyingKey>>>,
    /// Live event notification bus for `ak.self.events.stream.subscribe.v1`.
    /// Memory mode uses the local broadcast channel; PostgreSQL mode also
    /// publishes over LISTEN/NOTIFY so subscribers connected to another
    /// replica receive the same live frames.
    event_broadcast: EventBroadcast,
    /// Latched service-drain notice for long-lived transports. `None` until a
    /// shutdown signal arrives; a `watch` (not a broadcast) because a
    /// connection that opens mid-drain must observe the notice immediately
    /// rather than wait for an edge that already passed.
    connection_drain: Arc<tokio::sync::watch::Sender<Option<ConnectionDrain>>>,
    /// Lossy process-local acceleration signal. Durable pending rows remain
    /// the reconciliation source of truth after missed wakeups or restarts.
    control_seal_wakeup: Arc<tokio::sync::Notify>,
    /// Inbound admission slots for Applet edge transactions. Saturation is a
    /// protocol outcome, not a timeout: applet-integration.md 7.3 requires the
    /// shed delivery to come back as per-event `queue_full` with
    /// `retry_after_ms`, and to leave the idempotency identity unconsumed so
    /// the sender may re-deliver the same bytes.
    applet_transaction_slots: Arc<tokio::sync::Semaphore>,
    /// Server-enforced reconnect windows advertised by subscribe control
    /// frames. This prevents a faulty or overloaded client from immediately
    /// re-opening the same subscribe scope after `dropped` /
    /// `resync_required`.
    /// Persistent Ed25519 signing key for the NotaryWorker and service-owned signing paths.
    /// Production construction receives the exact seed resolved and
    /// key-bound by service-identity bootstrap; AppState never re-resolves or
    /// independently mints this signer.
    ///
    /// Shared across service-owned signing paths so they bind to the same
    /// key/DID identity.
    /// Readers acquire the current key via `ArcSwap::load_full()`. The
    /// historical signing-key-only rotation path is fail-closed because it
    /// cannot atomically update WebVH, the DID document, durable identity,
    /// KeyStore, and recovery bundle.
    notary_signing_key: Arc<ArcSwap<SigningKey>>,
    /// The origin tag rotates with the key. Stored alongside it
    /// behind a [`Mutex`] (one-shot writes from the rotation path are not
    /// in the hot read path; the per-pass diagnostic helper just snapshots).
    notary_signing_key_origin: Arc<Mutex<NotarySigningKeyOrigin>>,
    /// G4.T3 — verified-profile descriptors loaded from the artifact path in
    /// `SOLAND_VERIFIED_PROFILES_ARTIFACT` at startup. Filtered to entries
    /// whose `service_role == "station"` and additionally
    /// cross-checked against the local `claimed_profiles[]` set inside
    /// `describe.rs::apply_claim_level_partition`. Empty when the env var
    /// is unset / file missing / file malformed — that's the dev-mode
    /// invariant in service-surface.md §3.0.
    verified_profiles: Arc<Vec<VerifiedProfileArtifactEntry>>,
    /// MID-1..6 (R3.1 spec-sync 2026-05-27, arkret-spec @ 7157ee8) — in-
    /// memory registry of `ak.member.identity.update` events. Reducer
    /// dispatch (`apply_member_identity_update`) and the sync roster
    /// projection (`SYNC-MEM-1..3`) both go through this. See
    /// [`MemberIdentityRegistry`] above for storage and effective-set
    /// semantics; writers persist through the durable
    /// [`soland_storage::MemberIdentityStore`] first and startup hydration
    /// rebuilds this registry from it. Plaintext Ed25519 MemberIdentity
    /// proofs are verified on
    /// event ingest; encrypted/non-Ed25519 proof forms are refused
    /// fail-closed. Reducer-shape validation (digest binding, segment
    /// whitelist) IS real per MID-2.
    member_identity: Arc<Mutex<MemberIdentityRegistry>>,
    /// In-memory projection of the spec's `deactivation_partial` flag
    /// (`account-lifecycle.md` §3 / §7.1): DIDs whose push-gateway
    /// deactivation fanout has failed and is still being retried. Durable
    /// truth is the account-lifecycle registry plus the fanout completion
    /// markers in the jobs idempotency ledger; the inline fanout attempt and
    /// the [`crate::deactivation_push_fanout`] worker keep this set
    /// converged (including after a restart, on the worker's first pass).
    /// Orthogonal to `deactivation_federation_incomplete` — never merged.
    deactivation_push_partial: Arc<Mutex<std::collections::BTreeSet<String>>>,
}

pub struct AppStateRuntime {
    pub persistence: PersistenceHandle,
    pub projections: ProjectionService,
    pub realm_directory: RealmDirectoryService,
    pub object_storage: Arc<dyn ObjectStoragePort>,
    pub settings_persistence: Arc<dyn RuntimeSettingsPort>,
    pub runtime_health: Arc<dyn RuntimeHealthPort>,
    pub event_broadcast: EventBroadcast,
    pub storage_mode: &'static str,
}

/// Founding principal of the development demo Realm.
pub const DEVELOPMENT_DEMO_SUBJECT_DID: &str = "did:web:alice.example";
const DEVELOPMENT_DEMO_TRUST_DOMAIN: &str = "ak:trust_domain:soland.test";
const DEVELOPMENT_DEMO_GENESIS_HLC: &str = "0196419b0000-0000-51c0a1ed";
const DEVELOPMENT_DEMO_GENESIS_CREATED_AT: &str = "2026-01-01T00:00:00Z";

/// Canonical `ak.realm.create` payload for a deterministic Realm genesis.
#[must_use]
pub fn realm_genesis_payload(
    _subject: &str,
    notary_signer: &arkret_wire::NotarySignerDescriptor,
    trust_domain: &str,
) -> Value {
    let notary = arkret_wire::NotaryValue::single_signer(notary_signer.clone());
    notary
        .validate()
        .expect("Realm genesis notary descriptor must be canonical");
    serde_json::json!({
        "object": {
            "schema": "ak.schema.realm_genesis.v1",
            "purpose": "collaboration",
            "genesis_salt": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "reducer_profile": arkret_wire::CORE_REDUCER_PROFILE,
            "trust_domain": trust_domain,
            "schema_refs": ["ak.schema.realm.v1"],
            "encryption_profile": "none",
            "security_class": "standard",
            "digest_algorithm": "sha256",
            "notary": notary
        }
    })
}

fn demo_notary_signer_descriptor(
    service_did: &Did,
    service_id: &DidCoreId,
    signing_seed: [u8; 32],
) -> arkret_wire::NotarySignerDescriptor {
    let verifying_key = ed25519_dalek::SigningKey::from_bytes(&signing_seed).verifying_key();
    soland_services::identity::ed25519_notary_signer_descriptor(
        service_id.clone(),
        arkret_wire::DidUrl::new(format!("{service_did}#notary-key"))
            .expect("development notary verification method"),
        verifying_key.as_bytes(),
    )
    .expect("development notary signer descriptor")
}

/// The development demo Realm's canonical genesis Event.
///
/// Every input except the deployment identity is a development constant, so the
/// Event — and therefore the Realm id it derives — is fully determined by this
/// deployment's own service identity, its notary key and the current
/// `arkret-spec` artifacts. There is no parameterless variant: a demo Realm id
/// derived from a copied service DID is a Realm no running deployment can
/// re-derive.
#[must_use]
pub fn development_demo_genesis_event(
    service_did: &Did,
    service_id: &DidCoreId,
    signing_seed: [u8; 32],
) -> arkret_wire::AuthoredEvent {
    let created_at = chrono::DateTime::parse_from_rfc3339(DEVELOPMENT_DEMO_GENESIS_CREATED_AT)
        .expect("development demo genesis timestamp")
        .with_timezone(&chrono::Utc);
    let notary_signer = demo_notary_signer_descriptor(service_did, service_id, signing_seed);
    let payload: arkret_models_collaboration::events_payloads::RealmCreatePayload =
        serde_json::from_value(realm_genesis_payload(
            DEVELOPMENT_DEMO_SUBJECT_DID,
            &notary_signer,
            DEVELOPMENT_DEMO_TRUST_DOMAIN,
        ))
        .expect("development demo genesis payload");
    arkret_event_draft::TypedEventDraft::<arkret_wire::event_spec::RealmCreate>::new(
        arkret_wire::ScopeRef::RealmGenesis,
        arkret_wire::ActorId::account(arkret_wire::AccountId::new(
            arkret_wire::project_did_to_core_id(
                &Did::new(DEVELOPMENT_DEMO_SUBJECT_DID.to_owned())
                    .expect("development demo subject DID"),
            )
            .expect("development demo subject projection"),
            service_id.clone(),
        )),
        payload,
    )
    .expect("development demo genesis draft")
    .author_with_digest_suite(
        0,
        arkret_identifiers::Hlc::new(DEVELOPMENT_DEMO_GENESIS_HLC)
            .expect("development demo genesis HLC"),
        created_at,
        arkret_canonical::DigestSuite::Sha256,
    )
    .expect("development demo genesis Event")
}

/// Realm identity of the development demo Realm served by this deployment.
///
/// This is content-derived (`retype(genesis_event.event_id)`), so it moves
/// whenever anything inside the genesis Event's canonical bytes moves — the
/// deployment's own service identity and notary key included, because the
/// genesis payload freezes the notary signer descriptor. It is therefore
/// **derived**, never copied: a hard-coded literal went stale four times, most
/// recently as a service DID copied from one deployment into another.
#[must_use]
pub fn development_demo_realm_id(
    service_did: &Did,
    service_id: &DidCoreId,
    signing_seed: [u8; 32],
) -> RealmId {
    RealmId::from_event_id(
        development_demo_genesis_event(service_did, service_id, signing_seed).event_id(),
    )
}

pub fn build_realm_directory(
    config: &AppConfig,
    service_did: &Did,
    service_id: &DidCoreId,
    resolved_signing_seed: [u8; 32],
) -> RealmDirectoryService {
    let mut realms = RealmDirectoryIndex::new();
    if config.seed_demo_data {
        let mut demo = RealmDirectoryEntry::new(
            development_demo_realm_id(service_did, service_id, resolved_signing_seed),
            "Arkret Demo Realm",
            // Seeded locally, not projected from an Event.
            soland_services::events::DirectoryProvenance::LocalOnly,
        );
        demo.description = Some("Shared demo Realm served by soland".to_owned());
        demo.public = true;
        demo.members
            .insert(DidCoreId::new("ak:did_core:web:alice.example").expect("valid principal id"));
        demo.tags.insert("demo".to_owned());
        demo.category = Some("collaboration".to_owned());
        realms.upsert(demo);
    }
    RealmDirectoryService::new(realms)
}

#[cfg(test)]
fn development_fixture_service_identity(config: &AppConfig) -> DidCoreIdentityState {
    let registration_key = ServiceRegistrationKey::new(
        ServiceKind::Station,
        CanonicalServiceUrl::canonicalize(&config.public_base_url)
            .expect("test/development public base must be canonicalizable"),
    )
    .expect("station registration key");
    let signing_key_ref =
        DidCoreIdentityKeyRef::new("fixture:soland:service-signing-key").expect("fixture key ref");
    DidCoreIdentityState::Ready {
        identity: LocalDidCoreIdentity {
            did: Did::new(
                "did:webvh:z2dmjYwAPJzv5CZsnAzt8auVZRn1GfuxhpK2t3Q3K3rj4B1x:soland.local:webvh:service",
            )
            .expect("fixture service DID"),
            service_id: arkret_wire::project_did_to_core_id(
                    &Did::new(
                        "did:webvh:z2dmjYwAPJzv5CZsnAzt8auVZRn1GfuxhpK2t3Q3K3rj4B1x:soland.local:webvh:service",
                    )
                    .expect("fixture service DID"),
                )
                .expect("fixture service projection"),
            registration_key,
            provider: None,
            signing_key_refs: vec![signing_key_ref.clone()],
            active_signing_key_ref: signing_key_ref,
            control_key_ref: DidCoreIdentityKeyRef::new("fixture:soland:webvh-control-key")
                .expect("fixture control key ref"),
            version_id: "fixture-v1".to_owned(),
            last_verified_at: chrono::Utc::now(),
        },
    }
}

#[cfg(test)]
fn development_fixture_resolution_commitment(
    identity: &DidCoreIdentityState,
) -> ResolutionCommitment {
    ResolutionCommitment {
        did: arkret_wire::Did::new(
            identity
                .identity()
                .expect("fixture has a serving identity")
                .did
                .to_string(),
        )
        .expect("fixture service DID"),
        method_history_head: format!("sha256:{}", "0".repeat(64)),
        version_id: "fixture-v1".to_owned(),
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
    use soland_services::governance::RuntimeSettingsPort;
    use soland_services::jobs::RuntimeHealthPort;
    use soland_services::projection::EventSealCommitPort;
    use soland_storage::PersistenceStore;
    use soland_storage_postgres::test_database::{TestDatabase, block_on_lease_runtime};
    use soland_storage_postgres::{Db, EventSealCommitStore, PgPersistenceStore};

    use super::*;

    impl AppState {
        /// Build a fixture `AppState`.
        ///
        /// A caller that already has a pool keeps it. A caller that does not
        /// leases a real database: Soland stores through one adapter, so a
        /// fixture reaching for a second implementation would prove nothing
        /// about what production runs. The lease is owned by the persistence
        /// store, so the slot is returned when the last holder drops.
        pub fn new(config: AppConfig, db: Db) -> Self {
            let (db, persistence): (Db, Arc<dyn PersistenceStore>) = match db.pool.clone() {
                Some(pool) => (db, Arc::new(PgPersistenceStore::new(pool))),
                None => {
                    // The lease supplies the persistence store only. The
                    // state-resolution plane keeps the SDK's in-process stores
                    // it already used here: its traits are synchronous, and
                    // driving the durable ones from a current-thread test
                    // runtime deadlocks the connection that serves them.
                    let leased = Arc::new(TestDatabase::lease_blocking());
                    (
                        Db { pool: None },
                        Arc::new(PgPersistenceStore::leased(leased)),
                    )
                }
            };
            if config.seed_demo_data {
                seed_demo_data(&persistence);
            }
            Self::new_with_persistence(config, db, persistence)
        }

        pub fn new_with_persistence(
            config: AppConfig,
            db: Db,
            persistence: Arc<dyn PersistenceStore>,
        ) -> Self {
            let identity = development_fixture_service_identity(&config);
            let signing_seed = fixture_signing_seed(&config, &identity);
            let commitment = development_fixture_resolution_commitment(&identity);
            Self::new_with_service_identity(
                config,
                db,
                persistence,
                identity,
                commitment,
                signing_seed,
            )
        }

        pub fn new_with_service_identity(
            config: AppConfig,
            db: Db,
            persistence: Arc<dyn PersistenceStore>,
            service_identity: DidCoreIdentityState,
            service_resolution_commitment: ResolutionCommitment,
            resolved_signing_seed: [u8; 32],
        ) -> Self {
            let cell_registry = ProjectionService::sdk_cell_registry();
            let stores = soland_storage_postgres::build_state_resolution_stores(
                db.pool.clone(),
                cell_registry,
            );
            // Mirror production bootstrap: the memory device-revocation
            // adapter derives seal-settled state from this Control Event
            // store; durable adapters ignore the bind.
            persistence
                .device_revocations()
                .bind_control_event_store(stores.control_event_store.clone());
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
            let identity = service_identity
                .identity()
                .expect("fixture has a serving identity");
            let realm_directory = build_realm_directory(
                &config,
                &identity.did,
                &identity.service_id,
                resolved_signing_seed,
            );
            Self::from_runtime(
                config,
                AppStateRuntime {
                    persistence: PersistenceHandle::from_shared(persistence),
                    projections,
                    realm_directory,
                    object_storage: Arc::new(MemoryObjectStorage::default()),
                    settings_persistence: Arc::new(NoRuntimeSettings),
                    runtime_health: Arc::new(TestRuntimeHealth(db)),
                    event_broadcast: EventBroadcast::new(1024),
                    storage_mode,
                },
                service_identity,
                service_resolution_commitment,
                resolved_signing_seed,
            )
        }
    }

    /// The two rows the development demo projection reads.
    ///
    /// The demo Realm id itself is derived from config and identity, not read
    /// back from storage, so only these rows need seeding.
    const DEMO_REALM_ID: &str = "ak:realm:AZAySZA7XRDeJ9cO4MqaDWrJD-rqPk6Cudk7CCzsDQz1";

    fn seed_demo_data(persistence: &Arc<dyn PersistenceStore>) {
        use soland_storage::{AccountRecord, RealmMetaRecord};

        let store = persistence.clone();
        block_on_lease_runtime(async move {
            let now = chrono::Utc::now();
            store
                .accounts()
                .put(&AccountRecord {
                    // The store assigns the primary key.
                    pk: soland_storage::AccountPk(0),
                    principal_id: arkret_wire::DidCoreId::new(
                        "ak:did_core:web:alice.example".to_owned(),
                    )
                    .expect("demo principal id is canonical"),
                    station_id: arkret_wire::DidCoreId::new(
                        "ak:did_core:web:server.example".to_owned(),
                    )
                    .expect("demo Station id is canonical"),
                    localpart: "alice".to_owned(),
                    display_name: Some("Alice Example".to_owned()),
                    bio: None,
                    avatar_blob_ref: None,
                    created_at: now,
                })
                .await
                .expect("seed the demo account");
            store
                .realm_meta()
                .put(
                    DEMO_REALM_ID,
                    &RealmMetaRecord {
                        owner: "ak:did_core:web:alice.example".to_owned(),
                        deleted: false,
                        discoverability: "public".to_owned(),
                        history_access: "all_history_for_current_members".to_owned(),
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
                .expect("seed the demo Realm metadata");
        });
    }

    fn fixture_signing_seed(config: &AppConfig, identity: &DidCoreIdentityState) -> [u8; 32] {
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

    #[async_trait::async_trait]
    impl EventSealCommitPort for TestEventSealCommitter {
        async fn commit_if_frontier(
            &self,
            seal: &arkret_wire::Seal,
            digest_suite: arkret_canonical::DigestSuite,
            expected_store_frontier: &[arkret_identifiers::SealId],
            new_ops: &[(
                arkret_identifiers::CellRef,
                arkret_state::lattice::ordered_log::IssuedOp,
            )],
            covered: &BTreeSet<arkret_identifiers::Hash>,
            data_event_leaf_manifest: Option<&BTreeSet<arkret_identifiers::Hash>>,
            governance_dependencies: &[soland_storage::GovernanceDependencyWrite],
        ) -> arkret_state::state::StoreResult<bool> {
            self.0
                .commit_if_frontier(
                    seal,
                    digest_suite,
                    expected_store_frontier,
                    new_ops,
                    covered,
                    data_event_leaf_manifest,
                    governance_dependencies,
                )
                .await
        }

        async fn data_event_leaf_manifest(
            &self,
            seal_id: &arkret_identifiers::SealId,
        ) -> arkret_state::state::StoreResult<Option<BTreeSet<arkret_identifiers::Hash>>> {
            self.0.data_event_leaf_manifest(seal_id).await
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

    pub fn service_core_id(&self) -> DidCoreId {
        DidCoreId::new(self.service_id.clone())
            .expect("runtime service_id was validated during AppState construction")
    }

    /// Return the currently resolved, version-pinned service DID.
    ///
    /// `service_id` is the projected Arkret core identifier and must never be
    /// used as the base of a DID URL. Signing surfaces use this DID so a
    /// core-id/DID mismatch is rejected at this single typed boundary.
    pub fn service_did(&self) -> Did {
        self.service_resolution_commitment().did.clone()
    }

    pub fn service_verification_method(
        &self,
        fragment: &str,
    ) -> Result<arkret_wire::DidUrl, String> {
        arkret_wire::DidUrl::new(format!("{}#{fragment}", self.service_did()))
            .map_err(|error| format!("service verification method is invalid: {error}"))
    }

    /// The development demo Realm this deployment seeds when `seed_demo_data`
    /// is on.
    ///
    /// Derived from exactly the three inputs [`build_realm_directory`] used, so
    /// the directory entry, the canonical genesis Event and every fixture that
    /// re-seeds that Event agree by construction rather than by a copied
    /// literal.
    #[must_use]
    pub fn development_demo_realm_id(&self) -> RealmId {
        let identity_state = self.service_identity_state();
        let identity = identity_state
            .identity()
            .expect("AppState requires a serving service identity");
        development_demo_realm_id(
            &identity.did,
            &identity.service_id,
            self.notary_signing_key().to_bytes(),
        )
    }

    pub fn service_notary_signer_descriptor(
        &self,
    ) -> Result<arkret_wire::NotarySignerDescriptor, String> {
        soland_services::identity::ed25519_notary_signer_descriptor(
            DidCoreId::new(self.service_id().clone()).map_err(|error| error.to_string())?,
            self.service_verification_method("notary-key")?,
            self.notary_verifying_key().as_bytes(),
        )
    }

    pub fn storage_mode(&self) -> &'static str {
        self.storage_mode
    }

    pub async fn current_service_receipt_binding(
        &self,
    ) -> Result<(Hash, arkret_wire::DidUrl), String> {
        let stored = self
            .persistence
            .stored_service_identity()
            .await
            .map_err(|error| error.to_string())?
            .ok_or_else(|| "durable service identity is unavailable".to_owned())?;
        if stored.identity.service_id.as_str() != self.service_id {
            return Err("durable service identity does not match the serving service".to_owned());
        }
        let expected_multibase = arkret_canonical::ed25519_pubkey_to_did_key_multibase(
            self.notary_verifying_key().as_bytes(),
        );
        let assertion_method = stored
            .did_document
            .verification_method
            .iter()
            .find(|method| {
                method.public_key_multibase == expected_multibase
                    && stored.did_document.assertion_method.contains(&method.id)
            })
            .ok_or_else(|| "runtime signer is not a current service assertion method".to_owned())?;
        let normalized_document: arkret_models_identity::DidDocument = serde_json::from_value(
            serde_json::to_value(&stored.did_document).map_err(|error| error.to_string())?,
        )
        .map_err(|error| error.to_string())?;
        let document_digest = arkret_identity::document_canonical_digest(&normalized_document)
            .map_err(|error| error.to_string())?;
        let assertion_method = arkret_wire::DidUrl::new(assertion_method.id.clone())
            .map_err(|error| error.to_string())?;
        Ok((document_digest, assertion_method))
    }

    pub async fn stored_service_identity(
        &self,
    ) -> Result<arkret_identity::service_identity::StoredDidCoreIdentity, String> {
        self.persistence
            .stored_service_identity()
            .await
            .map_err(|error| error.to_string())?
            .ok_or_else(|| "durable service identity is unavailable".to_owned())
    }

    pub async fn current_signed_service_resolution(
        &self,
    ) -> Result<Option<arkret_models_identity::ServiceResolutionRecord>, String> {
        self.persistence
            .current_service_resolution()
            .await
            .map_err(|error| error.to_string())
    }

    pub async fn compare_and_set_signed_service_resolution(
        &self,
        expected_digest: Option<&Hash>,
        record: arkret_models_identity::ServiceResolutionRecord,
    ) -> Result<bool, String> {
        self.persistence
            .compare_and_set_service_resolution(expected_digest, record)
            .await
            .map_err(|error| error.to_string())
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

    /// Atomically replace the endpoint-discovered signing keys for one peer.
    ///
    /// Exact verification-method entries from an older WebVH version must be
    /// removed when the peer rotates its DID. Leaving them cached would
    /// allow a transcript naming the retired key id to bypass the refreshed
    /// endpoint document.
    pub fn install_discovered_federation_peer_keys(
        &self,
        previous_service_id: Option<&str>,
        service_id: &str,
        federation_verification_method: &str,
        federation_verifying_key: VerifyingKey,
        receipt_verification_method: &str,
        receipt_verifying_key: VerifyingKey,
    ) {
        self.federation_peer_verifying_keys.rcu(|current| {
            let mut next = (**current).clone();
            next.retain(|candidate, _| {
                !verification_key_belongs_to_service(candidate, service_id)
                    && !previous_service_id.is_some_and(|previous| {
                        verification_key_belongs_to_service(candidate, previous)
                    })
            });
            next.insert(service_id.to_owned(), federation_verifying_key);
            next.insert(
                federation_verification_method.to_owned(),
                federation_verifying_key,
            );
            next.insert(
                receipt_verification_method.to_owned(),
                receipt_verifying_key,
            );
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
    pub fn service_identity_state(&self) -> Arc<DidCoreIdentityState> {
        self.service_identity.load_full()
    }

    pub fn replace_service_identity_state(&self, state: DidCoreIdentityState) {
        self.service_identity.store(Arc::new(state));
    }

    pub fn service_resolution_commitment(&self) -> Arc<ResolutionCommitment> {
        self.service_resolution_commitment.load_full()
    }

    pub fn replace_service_resolution_commitment(&self, commitment: ResolutionCommitment) {
        self.service_resolution_commitment
            .store(Arc::new(commitment));
    }

    /// Snapshot the persistent Ed25519 signing key shared by
    /// the NotaryWorker and service-owned signing paths. Returns a fresh
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
        service_identity: DidCoreIdentityState,
        service_resolution_commitment: ResolutionCommitment,
        resolved_signing_seed: [u8; 32],
    ) -> Self {
        let AppStateRuntime {
            persistence,
            projections,
            realm_directory,
            object_storage,
            settings_persistence,
            runtime_health,
            event_broadcast,
            storage_mode,
        } = runtime;
        persistence.bind_history_authority_view_cas(Arc::new(projections.clone()));
        let now = chrono::Utc::now();
        let applet_transaction_inflight_capacity = config.applet_transaction_inflight_capacity;

        let service_id = service_identity
            .identity()
            .expect("AppState requires a serving service identity")
            .service_id
            .to_string();
        let service_identity = Arc::new(ArcSwap::from_pointee(service_identity));
        let service_resolution_commitment =
            Arc::new(ArcSwap::from_pointee(service_resolution_commitment));

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
        } = persistence.event_services();
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
            settings_persistence,
            runtime_health,
            sync_cursor_hmac_key,
        );
        let service_route_store: Arc<dyn soland_storage::ServiceRouteStore> =
            Arc::new(persistence.clone());
        let service_route_resolver = Arc::new(ServiceRouteResolver::new(
            service_route_store.clone(),
            Arc::new(VerifiedBindingRouteFetcher::new(
                dids.clone(),
                service_route_store,
                config.development_mode,
            )),
        ));

        // Read before `config` is moved into the struct below.
        let verified_profiles = crate::verified_profiles::load_from_configured_path(
            config.verified_profiles_artifact.as_deref(),
        );

        Self {
            config,
            service_id: service_id.clone(),
            service_identity,
            service_resolution_commitment,
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
            service_route_resolver: Arc::new(Mutex::new(Some(service_route_resolver))),
            did_bindings,
            organization_registrations,
            federation,
            governance,
            sync,
            jobs,
            projections,
            realm_directory,
            account_registration_policy: Arc::new(Mutex::new(AccountRegistrationPolicy::default())),
            runtime_guards: RuntimeGuardService::default(),
            to_device_position_counter: Arc::new(AtomicI64::new(now.timestamp_micros())),
            federation_peer_verifying_keys: Arc::new(ArcSwap::from_pointee(BTreeMap::new())),
            event_broadcast,
            connection_drain: Arc::new(tokio::sync::watch::Sender::new(None)),
            control_seal_wakeup: Arc::new(tokio::sync::Notify::new()),
            applet_transaction_slots: Arc::new(tokio::sync::Semaphore::new(
                applet_transaction_inflight_capacity,
            )),
            notary_signing_key,
            notary_signing_key_origin,
            // G4.T3 — load verified-profile descriptors at startup. An unset
            // artifact path IS the feature flag; absence keeps the dev-mode
            // verified_profiles=[] invariant. See
            // crate::verified_profiles::load_from_configured_path for the file
            // schema and logging policy.
            verified_profiles,
            member_identity: Arc::new(Mutex::new(MemberIdentityRegistry::new())),
            deactivation_push_partial: Arc::new(Mutex::new(std::collections::BTreeSet::new())),
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

    pub fn verified_profiles(&self) -> &[VerifiedProfileArtifactEntry] {
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

    /// Retain a peer document that has already passed the standard
    /// ServiceDescribe, registration-key, and assertion-method checks.
    pub fn cache_verified_federation_peer_document(
        &self,
        document: soland_services::identity::DidDocumentState,
    ) -> Result<(), String> {
        self.dids
            .cache_resolved_document_state(document)
            .map(|_| ())
    }

    /// Obtain the shared resolver for a production send. Absence is a hard
    /// configuration error; callers must never fall back to a raw URL/cache.
    pub fn service_route_resolver(&self) -> Result<Arc<ServiceRouteResolver>, &'static str> {
        self.service_route_resolver
            .lock()
            .clone()
            .ok_or("service route resolver is not installed")
    }

    /// Replace the production route fetcher at test composition time while
    /// retaining the same durable floor, cache, and quarantine store.
    ///
    /// This hook exists only for integration fixtures that model an
    /// independently verified route source. It must be called before the
    /// state performs any route resolution; production callers cannot enable
    /// it and sending code still resolves exclusively through the shared
    /// [`ServiceRouteResolver`].
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn test_install_service_route_fetcher(
        &self,
        fetcher: Arc<dyn soland_services::service_route::ServiceRouteFetcher>,
    ) {
        let resolver = Arc::new(ServiceRouteResolver::new(
            Arc::new(self.persistence.clone()),
            fetcher,
        ));
        *self.service_route_resolver.lock() = Some(resolver);
    }

    /// Accepted DID authority bindings (`did-usage-and-verification.md` §5).
    pub fn did_bindings(&self) -> &dyn arkret_identity::VerifiedDidBindingStore {
        self.did_bindings.as_ref()
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
    pub fn did_binding_trust_domain(&self) -> Result<arkret_identifiers::TrustDomainId, String> {
        Ok(self.config().trust_domain.clone())
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

    pub(crate) fn projections(&self) -> &ProjectionService {
        &self.projections
    }

    #[cfg(feature = "test-support")]
    #[doc(hidden)]
    pub fn test_projections(&self) -> &ProjectionService {
        &self.projections
    }

    pub(crate) fn persistence(&self) -> &PersistenceHandle {
        &self.persistence
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
        } else if !self.settings().admin_principal_ids.is_empty() {
            "principal_id_allowlist"
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

        let hydrated_realm_ids: Vec<RealmId> = {
            let realms = self.realm_directory.snapshot();
            realms
                .search(Default::default())
                .into_iter()
                .filter_map(|entry| RealmId::new(entry.realm_id.to_string()).ok())
                .collect()
        };
        self.persistence
            .hydrate_projection(
                &self.projections,
                &RuntimeHydrationProjectionAdapter,
                hydrated_realm_ids.clone(),
            )
            .await?;
        let mut reconciled_realms = self.realm_directory.snapshot();
        soland_services::hydration::reconcile_hydrated_agent_memberships(
            &mut reconciled_realms,
            &self.projections.snapshot(),
        );
        for (_, entry) in reconciled_realms.entries_iter() {
            self.realm_directory.upsert(entry.clone());
        }
        // Hydrate per-subject invite_receive_policy overrides into the
        // application-owned working projection.
        self.contacts.hydrate_runtime().await?;

        // Hydrate the holder-private consent-cell working projection owned by
        // the application service.
        self.consents.hydrate_runtime().await?;

        // MID-1..6 — rebuild the in-memory member-identity registry from the
        // durable store so a restart does not reset the R3.2 effective-set
        // digests (`expected_state_digest` guard) or the roster projection.
        {
            let store = self.persistence.member_identity_store();
            match (
                store.snapshot_events().await,
                store.snapshot_handle_claims().await,
            ) {
                (Ok(events), Ok(claims)) => {
                    let mut registry = super::member_identity::MemberIdentityRegistry::new();
                    let event_count = events.len();
                    let claim_count = claims.len();
                    for event in events {
                        registry.insert(event);
                    }
                    for claim in claims {
                        registry.restore_handle_claim(claim);
                    }
                    *self.member_identity.lock() = registry;
                    if event_count > 0 || claim_count > 0 {
                        tracing::info!(
                            event_count,
                            claim_count,
                            "hydrated member identity registry from persistence store"
                        );
                    }
                }
                (events, claims) => {
                    if let Err(error) = events {
                        tracing::warn!(%error, "failed to hydrate member identity events");
                    }
                    if let Err(error) = claims {
                        tracing::warn!(%error, "failed to hydrate member identity handle claims");
                    }
                }
            }
        }

        // `ak.component.direct_conversation.binding.v1` is an or_set, so fold
        // order carries no meaning: every accepted endorsement is a compatible
        // add and nothing supersedes anything (`contact-and-direct-conversation.md`
        // §8.3). The payload is `deny_unknown_fields` and carries no
        // `binding_state` / `supersedes_binding_ref`, so there is nothing to
        // order on either.
        let direct_binding_records = self
            .event_queries()
            .canonical_events()
            .await?
            .into_iter()
            .filter(|record| {
                record.kind == arkret_wire::EventKind::DirectConversationBound.as_str()
            })
            .collect::<Vec<_>>();
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
    ) -> BTreeMap<arkret_wire::DidCoreId, Vec<super::HandleClaimEvidenceRecord>> {
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

    /// MID-2..6 — persist the accepted `ak.member.identity.update` event (and
    /// the handle-claim envelopes its payload carries) through the durable
    /// store, then update the in-memory registry projection. The durable
    /// write runs first so a crash mid-projection loses at worst the
    /// in-memory view that hydration rebuilds on startup.
    pub(crate) async fn record_member_identity_update(
        &self,
        record: super::MemberIdentityEventRecord,
        identity_payload: &Value,
    ) {
        let store = self.persistence.member_identity_store();
        if let Err(error) = store.put_event(&record).await {
            tracing::error!(
                %error,
                event_id = %record.event_id,
                "failed to persist member identity event"
            );
        }
        let claim_records: Vec<super::HandleClaimEvidenceRecord> =
            super::member_identity::handle_claim_envelopes_in_identity_payload(identity_payload)
                .into_iter()
                .filter_map(super::member_identity::handle_claim_record_from_envelope)
                .collect();
        for claim in &claim_records {
            if let Err(error) = store.put_handle_claim(claim).await {
                tracing::error!(
                    %error,
                    digest = %claim.digest,
                    "failed to persist handle claim evidence"
                );
            }
        }
        let mut registry = self.member_identity.lock();
        registry.insert(record);
        for claim in claim_records {
            registry.restore_handle_claim(claim);
        }
    }

    pub(crate) async fn cache_handle_claim(&self, envelope: Value) -> Option<String> {
        let record = super::member_identity::handle_claim_record_from_envelope(&envelope)?;
        let digest = record.digest.clone();
        if let Err(error) = self
            .persistence
            .member_identity_store()
            .put_handle_claim(&record)
            .await
        {
            tracing::error!(%error, %digest, "failed to persist handle claim evidence");
        }
        self.member_identity.lock().restore_handle_claim(record);
        Some(digest)
    }

    pub(crate) fn cached_handle_claims_for_subject(
        &self,
        subject_id: &str,
    ) -> Vec<super::HandleClaimEvidenceRecord> {
        let Ok(subject_id) = arkret_wire::DidCoreId::new(subject_id.to_owned()) else {
            return Vec::new();
        };
        self.member_identity
            .lock()
            .handle_claims_for_subject(&subject_id)
    }

    pub(crate) async fn invalidate_cached_handle_claims_for_subject(
        &self,
        subject_id: &str,
    ) -> usize {
        let Ok(subject_id) = arkret_wire::DidCoreId::new(subject_id.to_owned()) else {
            return 0;
        };
        if let Err(error) = self
            .persistence
            .member_identity_store()
            .delete_handle_claims_for_subject(&subject_id)
            .await
        {
            tracing::error!(%error, subject_id = %subject_id, "failed to persist handle claim invalidation");
        }
        self.member_identity
            .lock()
            .invalidate_handle_claims_for_subject(&subject_id)
    }

    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn test_insert_member_identity(&self, record: super::MemberIdentityEventRecord) {
        self.member_identity.lock().insert(record);
    }

    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn test_cache_handle_claim(&self, envelope: Value) -> Option<String> {
        let record = super::member_identity::handle_claim_record_from_envelope(&envelope)?;
        let digest = record.digest.clone();
        self.member_identity.lock().restore_handle_claim(record);
        Some(digest)
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

    /// Whether the push-gateway leg of `did`'s deactivation fanout is still
    /// incomplete (`deactivation_partial`, `account-lifecycle.md` §3/§7.1).
    /// Always `false` when no push gateway is configured — in that posture
    /// the local push-route purge is the complete Push-route action.
    pub fn deactivation_push_partial(&self, did: &str) -> bool {
        self.deactivation_push_partial.lock().contains(did)
    }

    /// Raise or clear the `deactivation_partial` projection for `did`.
    /// Only the deactivation fanout path and its reconciliation worker
    /// call this.
    pub fn set_deactivation_push_partial(&self, did: &str, partial: bool) {
        let mut set = self.deactivation_push_partial.lock();
        if partial {
            set.insert(did.to_owned());
        } else {
            set.remove(did);
        }
    }

    /// Record a new peer KeyPackage claim attempt. Duplicate deliveries are
    /// checked against the durable idempotency ledger before this method is
    /// called and therefore do not consume quota.
    pub fn peer_keypackage_claim_rate_limited(
        &self,
        source_id: &str,
        target_identity_key: &str,
    ) -> bool {
        self.runtime_guards
            .peer_keypackage_claim_rate_limited(source_id, target_identity_key)
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
    /// transport guard; this protocol-level limiter adds reporter_id, source
    /// service, Realm, source IP, and duplicate-target pressure.
    pub fn record_moderation_report_attempt(
        &self,
        reporter_id: &str,
        source_service: Option<&str>,
        realm_id: &str,
        source_ip_hash: &str,
        target_ref: &str,
    ) -> ModerationReportRateOutcome {
        self.runtime_guards.record_moderation_report_attempt(
            reporter_id,
            source_service,
            realm_id,
            source_ip_hash,
            target_ref,
        )
    }
}

fn verification_key_belongs_to_service(candidate: &str, service_id: &str) -> bool {
    if candidate == service_id {
        return true;
    }
    let Ok(controller) = arkret_identity::verification_method_did(candidate) else {
        return false;
    };
    arkret_wire::project_did_to_core_id(&controller)
        .is_ok_and(|controller| controller.as_str() == service_id)
}

impl AppState {
    #[cfg(test)]
    pub(crate) fn test_persistence(&self) -> Arc<dyn soland_storage::PersistenceStore> {
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

    /// Stored push-device registrations, for tests that need the
    /// service-derived `push_target_id` from the server's side.
    ///
    /// `push_register_device_outcome` returns the pseudonym to the registering
    /// client (`zh/discovery/push-notifications.md` §3.1); a test that needs
    /// the value as the notify path sees it reads the stored registration
    /// here.
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub async fn test_push_devices(&self) -> Vec<serde_json::Value> {
        self.deliveries()
            .push_devices()
            .await
            .expect("push device registrations are readable")
    }

    /// One content-addressed object as this Station stored it.
    ///
    /// A snapshot manifest commits to its chunks only through their content
    /// address, so a test that wants to assert on chunk contents has to read the
    /// bytes back rather than trust the manifest.
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub async fn test_object_by_sha256(&self, sha256: &str) -> Vec<u8> {
        let key = self.deliveries().object_key_for_sha256(sha256);
        self.deliveries()
            .get_object(&key)
            .await
            .expect("the object this Station persisted is readable")
    }

    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub async fn test_effective_state_at(
        &self,
        leaves: &[arkret_identifiers::SealId],
        realm_id: &arkret_identifiers::RealmId,
    ) -> Result<
        std::collections::BTreeMap<arkret_identifiers::CellRef, arkret_state::lattice::CellState>,
        arkret_state::state::SealReject,
    > {
        self.projections.effective_state_at(leaves, realm_id).await
    }

    /// The `cas_register` head identities of the same view
    /// [`Self::test_effective_state_at`] resolves. A fixture that recomputes a
    /// `state_root` needs both halves (spec section 6.2.1).
    pub async fn test_effective_cas_heads_at(
        &self,
        leaves: &[arkret_identifiers::SealId],
        realm_id: &arkret_identifiers::RealmId,
    ) -> Result<arkret_state::CasHeadsByCell, arkret_state::state::SealReject> {
        self.projections
            .effective_cas_heads_at(leaves, realm_id)
            .await
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
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn upsert_projected_grant_for_test(&self, grant: arkret_policy::authz::authority::Grant) {
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

    /// Announce a bounded service drain. Long-lived transports tell their peers
    /// to checkpoint and reconnect elsewhere, then stop by `deadline`.
    ///
    /// Idempotent: a second signal keeps the first deadline, so a repeated
    /// SIGTERM cannot extend the window a client was already given.
    pub fn begin_connection_drain(&self, grace: std::time::Duration) {
        self.connection_drain.send_if_modified(|current| {
            if current.is_some() {
                return false;
            }
            *current = Some(ConnectionDrain {
                reconnect_after_ms: CONNECTION_DRAIN_RECONNECT_AFTER_MS,
                deadline: chrono::Utc::now()
                    + chrono::Duration::from_std(grace).unwrap_or(chrono::Duration::zero()),
            });
            true
        });
    }

    pub(crate) fn subscribe_connection_drain(
        &self,
    ) -> tokio::sync::watch::Receiver<Option<ConnectionDrain>> {
        self.connection_drain.subscribe()
    }

    pub(crate) fn current_connection_drain(&self) -> Option<ConnectionDrain> {
        *self.connection_drain.borrow()
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

    /// Claim one inbound Applet-transaction admission slot, or `None` when the
    /// Station is already at capacity. The permit is released when the returned
    /// guard drops, so a delivery holds a slot for exactly as long as it is
    /// being processed.
    pub(crate) fn try_claim_applet_transaction_slot(
        &self,
    ) -> Option<tokio::sync::OwnedSemaphorePermit> {
        Arc::clone(&self.applet_transaction_slots)
            .try_acquire_owned()
            .ok()
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
        self.consents.install_committed_cell(cell);
    }

    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn test_direct_conversation_binding_count(&self) -> usize {
        self.contacts.runtime_direct_binding_count()
    }

    /// Refresh one test fixture grant from the durable sealed-cell projection
    /// into the runtime authorization index.
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub async fn test_refresh_grant_from_sealed_cells(
        &self,
        realm_id: &arkret_identifiers::RealmId,
        grant_id: &str,
    ) {
        self.projections
            .reload_cells_from_store(realm_id)
            .await
            .expect("test fixture sealed cells reload");
        let grant = self
            .projections
            .effective_engine_grant(grant_id)
            .expect("test fixture sealed grant is effective");
        self.authorization.upsert_projected_grant(grant);
    }
}

struct RuntimeHydrationProjectionAdapter;

impl HydrationProjectionAdapter for RuntimeHydrationProjectionAdapter {
    fn operation_from_canonical_record(
        &self,
        record: &soland_services::events::AcceptedEvent,
    ) -> Option<arkret_event_draft::ProjectedEventOperation> {
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
        let decision = self.check_for_authority(
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

    fn upsert_projected_grant(&self, grant: arkret_policy::authz::authority::Grant) {
        self.upsert_projected_grant(grant);
    }

    fn mark_projected_grant_revoked(&self, grant_id: &str) {
        self.mark_projected_grant_revoked(grant_id);
    }

    fn mark_projected_grants_revoked_for_subject(&self, subject: &arkret_wire::ActorId) -> usize {
        self.mark_projected_grants_revoked_for_subject(subject)
    }

    fn get_grant(&self, grant_id: &str) -> Option<arkret_policy::authz::authority::Grant> {
        self.get_grant(grant_id)
    }

    fn grants_for_subject(
        &self,
        subject: &arkret_wire::ActorId,
        realm_id: &str,
    ) -> Vec<arkret_policy::authz::authority::Grant> {
        self.grants_for_subject(subject, realm_id)
    }

    fn grants_for_subject_at(
        &self,
        subject: &arkret_wire::ActorId,
        realm_id: &str,
        evaluated_at: chrono::DateTime<chrono::Utc>,
    ) -> Vec<arkret_policy::authz::authority::Grant> {
        self.grants_for_subject_at(subject, realm_id, evaluated_at)
    }

    fn grants_for_subject_all_realms(
        &self,
        subject: &arkret_wire::ActorId,
    ) -> Vec<arkret_policy::authz::authority::Grant> {
        self.grants_for_subject_all_realms(subject)
    }

    fn grants_snapshot(&self) -> Vec<arkret_policy::authz::authority::Grant> {
        self.grants_snapshot()
    }
}

/// Fill `out` with cryptographically secure random bytes via `rand::rng`.
/// Used by service-identity bootstrap.
pub fn getrandom_seed(out: &mut [u8; 32]) {
    use rand::RngExt;
    rand::rng().fill(out);
}

#[cfg(test)]
mod membership_hydration_tests {
    use arkret_identifiers::RealmId;
    use soland_services::hydration::{
        hydrate_projections_from_persistence, hydrate_realm_member_state_event,
        hydrate_realms_from_canonical_events,
    };
    use soland_storage::{
        CanonicalEventRecord, EventProjectionStoreRegistry, IdentityStoreRegistry,
        MlsAgentStoreRegistry, PersistenceStore, RealmMetaRecord,
    };
    use soland_storage_postgres::test_database::TestDatabase;
    use soland_storage_postgres::{Db, PgPersistenceStore};

    use super::*;

    #[test]
    fn app_state_uses_the_bootstrap_resolved_signing_seed() {
        let config = AppConfig::test_default();
        let identity = development_fixture_service_identity(&config);
        let commitment = development_fixture_resolution_commitment(&identity);
        let persistence: Arc<dyn PersistenceStore> = Arc::new(PgPersistenceStore::leased(
            Arc::new(TestDatabase::lease_blocking()),
        ));
        let resolved_seed = [0xa5; 32];

        let state = AppState::new_with_service_identity(
            config,
            Db { pool: None },
            persistence,
            identity,
            commitment,
            resolved_seed,
        );

        assert_eq!(state.notary_signing_key().to_bytes(), resolved_seed);
    }

    fn canonical_projection_source_event(
        realm_id: &str,
        actor_id: &str,
        actor_seq: u64,
        kind: impl AsRef<str>,
        payload: serde_json::Value,
        received_at: chrono::DateTime<chrono::Utc>,
    ) -> CanonicalEventRecord {
        let kind = kind.as_ref();
        let actor_id = arkret_wire::DidCoreId::new(actor_id.to_owned())
            .unwrap_or_else(|_| crate::test_actor_id_str(actor_id));
        let event = crate::test_event::raw_event_at(
            kind,
            arkret_wire::ScopeRef::Realm {
                realm_id: RealmId::new(realm_id).unwrap(),
            },
            actor_id.clone(),
            actor_seq,
            arkret_identifiers::Hlc::new(format!("019041000000-{actor_seq:04x}-aabbccdd")).unwrap(),
            payload,
            received_at,
        )
        .unwrap();
        let canonical_bytes = arkret_canonical::canonical_json_bytes(
            &event.digest_payload().expect("membership digest payload"),
        )
        .expect("membership canonical bytes");
        let canonical_digest = arkret_canonical::sha256_digest(&canonical_bytes);
        let event_id = event.event_id.to_string();
        let canonical_actor = event.actor_id.to_string();
        let envelope = serde_json::to_value(event).unwrap();
        CanonicalEventRecord {
            event_id,
            actor_id: canonical_actor,
            actor_seq,
            realm_id: Some(realm_id.to_owned()),
            kind: kind.to_owned(),
            schema_id: "ak.schema.event.v1".to_owned(),
            digest_suite: arkret_canonical::DigestSuite::Sha256,
            canonical_digest,
            canonical_bytes,
            envelope,
            received_at,
        }
    }

    fn member_state_event(realm_id: &str, member: &str, membership: &str) -> CanonicalEventRecord {
        let received_at = chrono::DateTime::parse_from_rfc3339("2026-07-20T00:00:01.000Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        canonical_projection_source_event(
            realm_id,
            member,
            1,
            arkret_wire::EventKind::MemberState,
            serde_json::json!({
                "membership": membership,
                "member_id": arkret_wire::ActorId::account(arkret_wire::AccountId::new(
                    DidCoreId::new(member).unwrap(), crate::test_event::station_id(),
                ))
            }),
            received_at,
        )
    }

    fn directory_with_creator(realm_id: &RealmId, creator: &DidCoreId) -> RealmDirectoryIndex {
        let mut realms = RealmDirectoryIndex::new();
        let mut entry = RealmDirectoryEntry::new(
            realm_id.clone(),
            "Hydration Test Realm",
            soland_services::events::DirectoryProvenance::LocalOnly,
        );
        entry.members.insert(creator.clone());
        realms.upsert(entry);
        realms
    }

    // Regression: a joined invitee_id's `ak.member.state{join}` MUST be replayed
    // into the realm directory on boot. Without it the admin's synced roster
    // shows only the creator, admin-side MLS admission never fires, and the
    // invitee_id is stuck "waiting for a Welcome" after every restart.
    #[test]
    fn joined_member_survives_directory_hydration() {
        let realm_id =
            RealmId::new("ak:realm:AcKqpIvVOZVtWunlTXZCQtNUZl5ICaoTGA-SU-z-901C".to_owned())
                .expect("realm id");
        let creator = DidCoreId::new("ak:did_core:web:alice.example".to_owned()).unwrap();
        let invitee_id = DidCoreId::new("ak:did_core:web:bob.example".to_owned()).unwrap();

        let mut realms = directory_with_creator(&realm_id, &creator);
        // Before replay: only the creator is present (the realm.create seed).
        assert_eq!(realms.get(&realm_id).unwrap().members.len(), 1);

        hydrate_realm_member_state_event(
            &mut realms,
            &member_state_event(realm_id.as_str(), invitee_id.as_str(), "join"),
        );

        let members = &realms.get(&realm_id).unwrap().members;
        assert!(
            members.contains(&invitee_id),
            "joined invitee_id must survive directory hydration"
        );
        assert!(members.contains(&creator));
        assert_eq!(members.len(), 2);
    }

    #[test]
    fn left_member_is_dropped_on_directory_hydration() {
        let realm_id =
            RealmId::new("ak:realm:AcKqpIvVOZVtWunlTXZCQtNUZl5ICaoTGA-SU-z-901C".to_owned())
                .expect("realm id");
        let creator = DidCoreId::new("ak:did_core:web:alice.example".to_owned()).unwrap();
        let invitee_id = DidCoreId::new("ak:did_core:web:bob.example".to_owned()).unwrap();

        let mut realms = directory_with_creator(&realm_id, &creator);
        hydrate_realm_member_state_event(
            &mut realms,
            &member_state_event(realm_id.as_str(), invitee_id.as_str(), "join"),
        );
        hydrate_realm_member_state_event(
            &mut realms,
            &member_state_event(realm_id.as_str(), invitee_id.as_str(), "leave"),
        );

        let members = &realms.get(&realm_id).unwrap().members;
        assert!(
            !members.contains(&invitee_id),
            "left member must be removed"
        );
        assert!(members.contains(&creator));
    }

    // `invite`/`knock` are not directory member-set transitions (they live in
    // the structured membership projection), so they must not add a directory
    // member during hydration.
    #[test]
    fn invite_state_does_not_add_directory_member() {
        let realm_id =
            RealmId::new("ak:realm:AcKqpIvVOZVtWunlTXZCQtNUZl5ICaoTGA-SU-z-901C".to_owned())
                .expect("realm id");
        let creator = DidCoreId::new("ak:did_core:web:alice.example".to_owned()).unwrap();
        let invitee_id = DidCoreId::new("ak:did_core:web:bob.example".to_owned()).unwrap();

        let mut realms = directory_with_creator(&realm_id, &creator);
        hydrate_realm_member_state_event(
            &mut realms,
            &member_state_event(realm_id.as_str(), invitee_id.as_str(), "invite"),
        );

        let members = &realms.get(&realm_id).unwrap().members;
        assert!(!members.contains(&invitee_id));
        assert_eq!(members.len(), 1);
    }

    #[tokio::test]
    async fn accepted_invite_membership_survives_restart_and_later_leave() {
        let realm_id = "ak:realm:AcKqpIvVOZVtWunlTXZCQtNUZl5ICaoTGA-SU-z-901C";
        let creator = DidCoreId::new("ak:did_core:web:alice.example").unwrap();
        let principal = DidCoreId::new("ak:did_core:web:bob.example").unwrap();
        let account =
            arkret_wire::AccountId::new(principal.clone(), crate::test_event::station_id());
        let actor = arkret_wire::ActorId::account(account.clone());
        let created_at = chrono::DateTime::parse_from_rfc3339("2026-07-20T00:00:00.000Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let create = canonical_projection_source_event(
            realm_id,
            creator.as_str(),
            1,
            arkret_wire::EventKind::InviteCreate,
            serde_json::json!({
                "invitee_account_id": account,
                "introduction_evidence_digest": format!("sha256:{}", "11".repeat(32)),
                "expires_at": "2026-07-21T00:00:00.000Z",
            }),
            created_at,
        );
        let invite_id = arkret_wire::InviteId::from_event_id(
            &arkret_wire::EventId::new(create.event_id.clone()).unwrap(),
        );
        let accept = canonical_projection_source_event(
            realm_id,
            principal.as_str(),
            1,
            arkret_wire::EventKind::InviteAccept,
            serde_json::json!({"invite_id": invite_id, "invitee_account_id": account}),
            created_at + chrono::Duration::seconds(1),
        );
        let database = TestDatabase::lease().await;
        let store = PgPersistenceStore::new(database.pool());
        store.events().put(create).await.unwrap();
        store.events().put(accept.clone()).await.unwrap();
        let mut projection = ProjectionState::new();
        let mut directory = directory_with_creator(&RealmId::new(realm_id).unwrap(), &creator);
        // Replay after the invite has expired: acceptance is durable truth,
        // not a new admission to evaluate against today's policy or time.
        for _ in 0..2 {
            soland_services::hydration::hydrate_canonical_realm_memberships(
                &store,
                &mut projection,
                &RuntimeHydrationProjectionAdapter,
            )
            .await
            .unwrap();
            hydrate_realms_from_canonical_events(&store, &mut directory).await;
            let membership = projection.member(realm_id, &actor.to_string()).unwrap();
            assert_eq!(membership.state, "join");
            assert_eq!(
                membership.membership_event_ref.as_deref(),
                Some(accept.event_id.as_str())
            );
            assert_eq!(membership.invited_at, Some(created_at));
            assert_eq!(
                membership.joined_at,
                created_at + chrono::Duration::seconds(1)
            );
            assert!(
                directory
                    .get(&RealmId::new(realm_id).unwrap())
                    .unwrap()
                    .members
                    .contains(&principal)
            );
            let foreign = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
                principal.clone(),
                DidCoreId::new("ak:did_core:web:other.example").unwrap(),
            ));
            assert!(projection.member(realm_id, &foreign.to_string()).is_none());
        }
        let leave = canonical_projection_source_event(
            realm_id,
            principal.as_str(),
            2,
            arkret_wire::EventKind::MemberState,
            serde_json::json!({"member_id": actor, "membership": "leave"}),
            created_at + chrono::Duration::seconds(2),
        );
        store.events().put(leave).await.unwrap();
        let mut restarted = ProjectionState::new();
        soland_services::hydration::hydrate_canonical_realm_memberships(
            &store,
            &mut restarted,
            &RuntimeHydrationProjectionAdapter,
        )
        .await
        .unwrap();
        hydrate_realms_from_canonical_events(&store, &mut directory).await;
        assert_eq!(
            restarted
                .member(realm_id, &actor.to_string())
                .unwrap()
                .state,
            "leave"
        );
        assert!(
            !directory
                .get(&RealmId::new(realm_id).unwrap())
                .unwrap()
                .members
                .contains(&principal)
        );
    }

    // Regression for sidecar creation after restart: the Realm directory was
    // already replaying member Events, but the reducer cache was not. That
    // made an agent visible as a Realm member in Inkson while
    // `ak.circle.member.state` rejected the same agent as a non-member.
    #[tokio::test]
    async fn joined_member_survives_reducer_projection_hydration() {
        let realm_id = "ak:realm:AcKqpIvVOZVtWunlTXZCQtNUZl5ICaoTGA-SU-z-901C";
        let member = "ak:did_core:web:bob.example";
        let database = TestDatabase::lease().await;
        let store = PgPersistenceStore::new(database.pool());
        store
            .events()
            .put(member_state_event(realm_id, member, "join"))
            .await
            .expect("persist member Event");

        let mut projection = ProjectionState::new();
        projection.realm_states.insert(
            realm_id.to_owned(),
            soland_domain::reducer::SolandRealmState {
                realm_id: realm_id.to_owned(),
                owner: Some("ak:did_core:web:alice.example".to_owned()),
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
            .member(
                realm_id,
                &arkret_wire::ActorId::account(arkret_wire::AccountId::new(
                    DidCoreId::new(member).unwrap(),
                    crate::test_event::station_id(),
                ))
                .to_string(),
            )
            .expect("joined member restored to reducer projection");
        assert_eq!(hydrated.state, "join");
    }

    // Regression: the MLS KeyPackage + commit-epoch projections — which the
    // claim selector and the commit-epoch CAS read ONLY from memory — MUST be
    // rebuilt from their durable tables on boot, or a restart strands every
    // pending admission (admin can't claim the invitee_id's KeyPackage; add-member
    // commit is rejected for "no genesis").
    #[tokio::test]
    async fn mls_projections_rehydrate_from_durable_stores() {
        use soland_storage::MlsKeyPackageRow;

        let realm_id = "ak:realm:AcKqpIvVOZVtWunlTXZCQtNUZl5ICaoTGA-SU-z-901C";
        let group_id = "mls-group-019f0dd3-aaaa";
        let database = TestDatabase::lease().await;
        let store = PgPersistenceStore::new(database.pool());
        // `mls_key_packages.owner_account_pk` references `accounts`, so the
        // owner has to exist before its KeyPackages can.
        let owner_account_pk = store
            .accounts()
            .put(&soland_storage::AccountRecord {
                pk: soland_storage::AccountPk(0),
                principal_id: arkret_wire::DidCoreId::new("ak:did_core:web:bob.example".to_owned())
                    .expect("fixture principal id is canonical"),
                station_id: arkret_wire::DidCoreId::new(
                    "ak:did_core:web:server.example".to_owned(),
                )
                .expect("fixture Station id is canonical"),
                localpart: "bob".to_owned(),
                display_name: None,
                bio: None,
                avatar_blob_ref: None,
                created_at: chrono::Utc::now(),
            })
            .await
            .expect("seed the KeyPackage owner account");

        store
            .mls_key_packages()
            .put(&MlsKeyPackageRow {
                id: "keypackage-01".to_owned(),
                keypackage_ref: "sha256:ref".to_owned(),
                keypackage_digest: "sha256:digest".to_owned(),
                owner_account_pk,
                actor_id: "ak:did_core:web:bob.example".to_owned(),
                device_id: Some("ak:device:bob-1".to_owned()),
                endpoint_verification_method: None,
                intended_realm_id: None,
                key_package_bytes: vec![1, 2, 3],
                capabilities: vec!["ak.content.v1".to_owned()],
                capabilities_digest: "sha256:caps".to_owned(),
                last_resort: true,
                last_resort_realm_id: Some(realm_id.to_owned()),
                lifetime_not_before: 0,
                lifetime_not_after: i64::MAX,
                claimed_by_mls_group_id: None,
                device_authorize_event_id: Some(
                    "ak:event:AUAf2-oZl31wupPqnQLO-zloaqgMoX5xk2tpVSbi8zjD".to_owned(),
                ),
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
                id: "keypackage-retired".to_owned(),
                keypackage_ref: "sha256:retired-ref".to_owned(),
                keypackage_digest: "sha256:retired-digest".to_owned(),
                owner_account_pk,
                actor_id: "ak:did_core:web:bob.example".to_owned(),
                device_id: Some("ak:device:bob-1".to_owned()),
                endpoint_verification_method: None,
                intended_realm_id: None,
                key_package_bytes: vec![4, 5, 6],
                capabilities: vec!["ak.content.v1".to_owned()],
                capabilities_digest: "sha256:retired-caps".to_owned(),
                last_resort: false,
                last_resort_realm_id: None,
                lifetime_not_before: 0,
                lifetime_not_after: i64::MAX,
                claimed_by_mls_group_id: Some("retired".to_owned()),
                device_authorize_event_id: Some(
                    "ak:event:AUAf2-oZl31wupPqnQLO-zloaqgMoX5xk2tpVSbi8zjD".to_owned(),
                ),
                agent_key_authorize_event_id: None,
                claimed_at: None,
                claim_expires_at_unix_ms: None,
                consumed_at: None,
                created_at: 2,
            })
            .await
            .expect("put retired keypackage");

        let effective_scope = serde_json::json!({ "kind": "realm", "realm_id": realm_id });
        let governance_binding = serde_json::json!({
            "security_frontier_digest": format!("sha256:{}", "1".repeat(64))
        });
        store
            .mls_commits()
            .initialize_genesis(soland_storage::MlsCommitGenesis {
                effective_scope: &effective_scope,
                group_id,
                leader_actor_id: "ak:did_core:web:alice.example",
                creator_device_id: "ak:device:alice-1",
                genesis_event_ref: "ak:event:AZ6wcRvTARthqkHiE-HOofDuOIbhnuXN6XUmeCaLoGhn",
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
            .get("keypackage-01")
            .expect("keypackage rehydrated");
        assert_eq!(kp.actor_id, "ak:did_core:web:bob.example");
        assert!(kp.last_resort);
        assert!(kp.claimed_by.is_none());
        let retired = proj
            .mls_key_packages
            .get("keypackage-retired")
            .expect("retired keypackage rehydrated");
        assert_eq!(retired.claimed_by.as_deref(), Some("retired"));
        assert!(retired.claimed_at.is_none());
        assert!(retired.claim_expires_at_unix_ms.is_none());
        assert!(retired.consumed_at.is_none());

        // Commit-epoch projection is rebuilt with the durable governance binding.
        let key = soland_domain::reducer::MlsCommitEpochKey::new(
            soland_domain::reducer::mls::effective_scope_key(&effective_scope).unwrap(),
            group_id.to_owned(),
        );
        let epoch = proj
            .mls_commit_epochs
            .get(&key)
            .expect("commit epoch rehydrated");
        assert_eq!(epoch.epoch, 0);
        assert_eq!(epoch.creator_device_id, "ak:device:alice-1");
        assert_eq!(
            epoch.genesis_event_ref,
            "ak:event:AZ6wcRvTARthqkHiE-HOofDuOIbhnuXN6XUmeCaLoGhn"
        );
        assert_eq!(epoch.governance_binding, governance_binding);
    }

    #[test]
    fn child_scope_policy_hydration_uses_the_sdk_wire_type_and_fails_closed() {
        let circle_id = "ak:circle:AV624IkuHj3HmxAYE6uyYmBa4Est3gGGdnOsjn71z5L2";
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
            soland_services::hydration::parse_child_scope_policy(Some("unknown_policy"), None)
                .is_err()
        );
        assert!(
            soland_services::hydration::parse_child_scope_policy(None, Some(circle_id)).is_err()
        );
    }

    #[tokio::test]
    async fn key_backup_active_series_rehydrates_from_projection_events() {
        use soland_storage::{ProjectionEventAppendOutcome, ProjectionEventRecord};

        let database = TestDatabase::lease().await;
        let store = PgPersistenceStore::new(database.pool());
        let actor = "ak:did_core:web:alice.example";
        let realm_id = "ak:realm:AcKqpIvVOZVtWunlTXZCQtNUZl5ICaoTGA-SU-z-901C";
        let series_id = "ak:backup_series:019f0dd3-081c-7f03-b388-e0399e775901";
        let now = chrono::Utc::now();
        let first_payload = serde_json::json!({
            "schema": "ak.schema.key_backup_active_series.v1",
            "actor_id": arkret_wire::ActorId::account(arkret_wire::AccountId::new(
                DidCoreId::new(actor).unwrap(), crate::test_event::station_id(),
            )),
            "backup_kind": "mls_history",
            "active_series_id": series_id,
            "series_pointer_version": 1,
            "previous_series_ids": [],
            "frontier_ref": {
                "frontier_digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "seal_ref": "ak:seal:sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "device_generation_ref": 1
            },
            "issued_at": "2026-07-18T00:00:00.000Z",
            "auth_data": {
                "verification_method": "did:web:alice.example#device-key",
                "signature_algorithm": "Ed25519",
                "signature": "AA",
                "device_authorize_event_id": "ak:event:ATyaOl1JkDDCC-6ZytsgoAKvlQJ6s6NJuDC_bmWKARBa"
            }
        });
        let first_source = canonical_projection_source_event(
            realm_id,
            actor,
            1,
            arkret_wire::EventKind::KeyBackupActiveSeries,
            first_payload.clone(),
            now,
        );
        let first_event_id = first_source.event_id.clone();
        store
            .events()
            .put(first_source)
            .await
            .expect("persist active-series canonical Event");
        let appended = store
            .projection_events()
            .append(ProjectionEventRecord {
                event_id: first_event_id,
                realm_id: realm_id.to_owned(),
                event_kind: arkret_wire::EventKind::KeyBackupActiveSeries
                    .as_str()
                    .to_owned(),
                operation_kind: "event".to_owned(),
                operation_id: Some("ak:operation:019f0dd3-081c-7f03-b388-e0399e775903".to_owned()),
                sender: Some(actor.to_owned()),
                payload: first_payload,
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
            .key_backup_active_series(
                &arkret_wire::ActorId::account(arkret_wire::AccountId::new(
                    DidCoreId::new(actor).unwrap(),
                    crate::test_event::station_id(),
                ))
                .to_string(),
                "mls_history",
            )
            .expect("active-series pointer rehydrated");
        assert_eq!(pointer.active_series_id, series_id);
        assert_eq!(pointer.series_pointer_version, 1);

        let gap_payload = serde_json::json!({
            "schema": "ak.schema.key_backup_active_series.v1",
            "actor_id": arkret_wire::ActorId::account(arkret_wire::AccountId::new(
                DidCoreId::new(actor).unwrap(), crate::test_event::station_id(),
            )),
            "backup_kind": "mls_history",
            "active_series_id": series_id,
            "series_pointer_version": 3,
            "previous_series_ids": [],
            "frontier_ref": {
                "frontier_digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "device_generation_ref": 1
            },
            "issued_at": "2026-07-18T00:01:00.000Z",
            "auth_data": {
                "verification_method": "did:web:alice.example#device-key",
                "signature_algorithm": "Ed25519",
                "signature": "AA",
                "device_authorize_event_id": "ak:event:ATyaOl1JkDDCC-6ZytsgoAKvlQJ6s6NJuDC_bmWKARBa"
            }
        });
        let gap_source = canonical_projection_source_event(
            realm_id,
            actor,
            2,
            arkret_wire::EventKind::KeyBackupActiveSeries,
            gap_payload.clone(),
            now,
        );
        let gap_event_id = gap_source.event_id.clone();
        store
            .events()
            .put(gap_source)
            .await
            .expect("persist gap active-series canonical Event");
        store
            .projection_events()
            .append(ProjectionEventRecord {
                event_id: gap_event_id,
                realm_id: realm_id.to_owned(),
                event_kind: arkret_wire::EventKind::KeyBackupActiveSeries
                    .as_str()
                    .to_owned(),
                operation_kind: "event".to_owned(),
                operation_id: Some("ak:operation:019f0dd3-081c-7f03-b388-e0399e775905".to_owned()),
                sender: Some(actor.to_owned()),
                payload: gap_payload,
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

        let database = TestDatabase::lease().await;
        let store = PgPersistenceStore::new(database.pool());
        let agent_id =
            "did:webvh:z6mkfixture:example.test:webvh:agent:019f0dd3-081c-7f03-b388-e0399e775901";
        let realm_id = "ak:realm:ATOqK9nfa8bBku-Ep99rtz0j0cavouf7r7EzOLgzm-LP";
        let key_id = format!("{agent_id}#runtime-1");
        let replacement_key_id = format!("{agent_id}#runtime-2");
        let now = chrono::Utc::now();
        let authorize_source = canonical_projection_source_event(
            realm_id,
            agent_id,
            1,
            arkret_wire::EventKind::AgentKeyAuthorize,
            serde_json::json!({
                "agent_id": agent_id,
                "key_id": key_id
            }),
            now,
        );
        let event_id = authorize_source.event_id.clone();
        store
            .events()
            .put(authorize_source)
            .await
            .expect("persist agent-key authorization canonical Event");
        let appended = store
            .projection_events()
            .append(ProjectionEventRecord {
                event_id: event_id.clone(),
                realm_id: realm_id.to_owned(),
                event_kind: arkret_wire::EventKind::AgentKeyAuthorize
                    .as_str()
                    .to_owned(),
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
        let revoke_source = canonical_projection_source_event(
            realm_id,
            agent_id,
            2,
            arkret_wire::EventKind::AgentKeyRevoke,
            serde_json::json!({
                "agent_id": agent_id,
                "key_id": key_id
            }),
            now,
        );
        let revoke_event_id = revoke_source.event_id.clone();
        store
            .events()
            .put(revoke_source)
            .await
            .expect("persist agent-key revocation canonical Event");
        store
            .projection_events()
            .append(ProjectionEventRecord {
                event_id: revoke_event_id,
                realm_id: realm_id.to_owned(),
                event_kind: arkret_wire::EventKind::AgentKeyRevoke.as_str().to_owned(),
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
        let replacement_source = canonical_projection_source_event(
            realm_id,
            agent_id,
            3,
            arkret_wire::EventKind::AgentKeyAuthorize,
            serde_json::json!({
                "agent_id": agent_id,
                "key_id": replacement_key_id
            }),
            now,
        );
        let replacement_event_id = replacement_source.event_id.clone();
        store
            .events()
            .put(replacement_source)
            .await
            .expect("persist replacement agent-key authorization canonical Event");
        store
            .projection_events()
            .append(ProjectionEventRecord {
                event_id: replacement_event_id.clone(),
                realm_id: realm_id.to_owned(),
                event_kind: arkret_wire::EventKind::AgentKeyAuthorize
                    .as_str()
                    .to_owned(),
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
        let realm_id = "ak:realm:AcKqpIvVOZVtWunlTXZCQtNUZl5ICaoTGA-SU-z-901C";
        let owner = "did:webvh:z6mkfixture:example.test:users:alice";
        let now = chrono::Utc::now();
        let database = TestDatabase::lease().await;
        let store = PgPersistenceStore::new(database.pool());
        store
            .realm_meta()
            .put(
                realm_id,
                &RealmMetaRecord {
                    owner: owner.to_owned(),
                    deleted: false,
                    discoverability: "invite_only".to_owned(),
                    history_access: "all_history_for_current_members".to_owned(),
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
            &crate::test_account_actor(&arkret_wire::Did::new(owner).unwrap()),
            realm_id,
            "ak.message.create",
            realm_id,
            chrono::Utc::now(),
        ));
    }

    #[tokio::test]
    async fn plaintext_visible_services_rehydrate_from_bootstrap_policy_event() {
        let realm_id = "ak:realm:AcKqpIvVOZVtWunlTXZCQtNUZl5ICaoTGA-SU-z-901C";
        let actor_id = "ak:did_core:web:alice.example";
        let service_id = "ak:did_core:webvh:z2dmjYwAPJzv5CZsnAzt8auVZRn1GfuxhpK2t3Q3K3rj4B1x";
        let created_at = chrono::DateTime::parse_from_rfc3339("2026-07-20T00:00:01.000Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let database = TestDatabase::lease().await;
        let store = PgPersistenceStore::new(database.pool());
        store
            .events()
            .put(canonical_projection_source_event(
                realm_id,
                actor_id,
                0,
                arkret_wire::EventKind::RealmCreate,
                serde_json::json!({
                    "object": {
                        "purpose": "collaboration",
                        "default_discoverability": "invite_only",
                        "history_access": "since_join",
                        "encryption_profile": "none"
                    }
                }),
                created_at,
            ))
            .await
            .unwrap();
        store
            .events()
            .put(canonical_projection_source_event(
                realm_id,
                actor_id,
                1,
                arkret_wire::EventKind::RealmPlaintextVisibleServices,
                serde_json::json!({
                    "services": [{
                        "service_id": service_id,
                        "service_kind": "station",
                        "purposes": ["message_index"],
                        "data_classes": ["message_content"],
                        "visibility": "private_plaintext"
                    }]
                }),
                created_at + chrono::Duration::milliseconds(1),
            ))
            .await
            .unwrap();

        let mut realms = RealmDirectoryIndex::new();
        hydrate_realms_from_canonical_events(&store, &mut realms).await;

        let meta = store.realm_meta().get(realm_id).await.unwrap().unwrap();
        assert!(meta.plaintext_visible_services.contains(service_id));
        assert!(
            meta.plaintext_visible_service_classes[service_id]
                .contains(&arkret_wire::PlaintextDataClassKind::MessageContent)
        );
    }
}
