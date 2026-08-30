#![forbid(unsafe_code)]

pub mod cba_basis;
pub mod sealed_grant;
pub mod signed_event;

use std::collections::{BTreeMap, BTreeSet};
use std::ops::Range;
use std::path::Path;
use std::sync::{Arc, OnceLock};

use arkret_identifiers::{CellRef, Did, Hash, RealmId, SealId};
use arkret_identity::service_identity::{
    DidCoreIdentityKeyRef, DidCoreIdentityState, LocalDidCoreIdentity, StoredDidCoreIdentity,
};
use arkret_models_identity::service_identity::{
    CanonicalServiceUrl, ServiceDidDocument, ServiceDidEndpoint, ServiceDidVerificationMethod,
    ServiceRegistrationKey, ServiceRegistrationReceipt,
};
use arkret_state::lattice::CellState;
use arkret_state::lattice::ordered_log::IssuedOp;
use arkret_state::state::{
    CellRegistry, CellStore, ControlEventStore, MemoryCellStore, MemoryControlEventStore,
    MemorySealStore, SealStore, StoreError, StoreResult, compute_state_root,
};
use arkret_wire::{DidCoreId, Seal, ServiceKind, project_did_to_core_id};
use async_trait::async_trait;
use bytes::Bytes;
use futures_util::stream::{self, BoxStream, StreamExt};
use parking_lot::Mutex;
use rand_core::SeedableRng;
use serde_json::Value;
use sha2::{Digest, Sha256};
use soland_domain::reducer::ProjectionState;
use soland_http::config::AppConfig;
use soland_http::state::{AppState, AppStateRuntime, EventBroadcast};
use soland_services::delivery::ObjectStoragePort;
use soland_services::events::RealmDirectoryIndex;
use soland_services::governance::RuntimeSettingsPort;
use soland_services::jobs::RuntimeHealthPort;
use soland_services::persistence::PersistenceHandle;
use soland_services::projection::{EventSealCommitPort, ProjectionService};
use soland_storage::PersistenceStore;
use soland_storage_memory::SolandMemoryPersistenceStore;

pub fn app_config() -> AppConfig {
    AppConfig {
        public_base_url: "https://server.test".to_owned(),
        ..AppConfig::test_default()
    }
}

pub fn app_state(config: AppConfig) -> AppState {
    let identity = fixture_service_identity(&config);
    let signing_seed = fixture_signing_seed(&config, &identity);
    let persistence = if config.seed_demo_data {
        SolandMemoryPersistenceStore::new_with_demo_data()
    } else {
        SolandMemoryPersistenceStore::new()
    };
    persistence.seed_service_identity(fixture_stored_service_identity(
        &config,
        &identity,
        signing_seed,
    ));
    persistence.seed_webvh_log_event(fixture_service_webvh_log(&config, signing_seed));
    app_state_with_identity(config, Arc::new(persistence), identity, signing_seed)
}

pub fn app_state_with_service_did(config: AppConfig, did: Did) -> AppState {
    let identity = fixture_service_identity_for_did(&config, did);
    let signing_seed = fixture_signing_seed(&config, &identity);
    let persistence = if config.seed_demo_data {
        SolandMemoryPersistenceStore::new_with_demo_data()
    } else {
        SolandMemoryPersistenceStore::new()
    };
    persistence.seed_service_identity(fixture_stored_service_identity(
        &config,
        &identity,
        signing_seed,
    ));
    app_state_with_identity(config, Arc::new(persistence), identity, signing_seed)
}

pub async fn app_state_with_persistence(
    config: AppConfig,
    persistence: Arc<dyn PersistenceStore>,
) -> AppState {
    let identity = fixture_service_identity(&config);
    let signing_seed = fixture_signing_seed(&config, &identity);
    let stored = persistence
        .service_identity()
        .get()
        .await
        .expect("fixture service identity lookup");
    if stored.is_none() {
        persistence
            .service_identity()
            .put(fixture_stored_service_identity(
                &config,
                &identity,
                signing_seed,
            ))
            .await
            .expect("fixture service identity seed");
    }
    if persistence
        .webvh()
        .list_log_events(
            identity
                .identity()
                .expect("fixture has a serving identity")
                .did
                .as_str(),
        )
        .await
        .expect("fixture service WebVH history lookup")
        .is_empty()
    {
        persistence
            .webvh()
            .append_log_event(fixture_service_webvh_log(&config, signing_seed))
            .await
            .expect("fixture service WebVH history seed");
    }
    app_state_with_identity(config, persistence, identity, signing_seed)
}

/// Mint a syntactically valid v1 Event-derived token for an out-of-band fixture.
///
/// The returned token is always the full 33-byte `SHA-256 suite || digest`
/// wire form. It is deliberately not an object derivation because the fixture
/// has no producer Event; fixtures that model a real create flow must build the
/// Event first and call the typed `from_event_id` constructor instead.
pub fn fixture_content_bound_id(prefix: &str) -> String {
    use sha2::Digest as _;
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let seq = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let mut hasher = sha2::Sha256::new();
    hasher.update(b"soland:fixture-content-bound-id:v1:");
    hasher.update(prefix.as_bytes());
    hasher.update(seq.to_be_bytes());
    hasher.update(std::process::id().to_be_bytes());
    let digest: [u8; 32] = hasher.finalize().into();
    let event_id =
        arkret_identifiers::EventId::from_digest(arkret_canonical::DigestSuite::Sha256, digest);
    arkret_identifiers::encode_event_token(prefix, event_id.token_bytes())
}

pub fn fixture_signing_seed(config: &AppConfig, identity: &DidCoreIdentityState) -> [u8; 32] {
    let _ = identity.identity().expect("fixture has a serving identity");
    fixture_service_signing_seed(config)
}

fn fixture_service_signing_seed(config: &AppConfig) -> [u8; 32] {
    config.notary_signing_key_seed.unwrap_or_else(|| {
        let mut hasher = Sha256::new();
        hasher.update(b"soland:test-fixture-notary:");
        hasher.update(config.public_base_url.as_bytes());
        hasher.finalize().into()
    })
}

fn fixture_prepared_service_inception(
    config: &AppConfig,
    signing_seed: [u8; 32],
) -> arkret_signatures::webvh::PreparedInception {
    let principal_endpoint = CanonicalServiceUrl::canonicalize(&config.public_base_url)
        .expect("test public base must be canonicalizable");
    let mut rng_seed = Sha256::new();
    rng_seed.update(b"soland:test-fixture-webvh-update:");
    rng_seed.update(config.public_base_url.as_bytes());
    let mut rng = rand_chacha::ChaCha20Rng::from_seed(rng_seed.finalize().into());
    let version_time = chrono::DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
        .expect("fixture WebVH timestamp")
        .with_timezone(&chrono::Utc);
    arkret_signatures::webvh::prepare_service_inception_with_did_key_seed(
        &mut rng,
        &arkret_signatures::webvh::ServiceInceptionInput {
            principal_endpoint: &principal_endpoint.as_url(),
            local_id: "service",
            also_known_as: &[],
            version_time,
            did_key_fragment: Some("notary-key"),
        },
        &signing_seed,
    )
    .expect("fixture service WebVH inception")
}

fn fixture_service_webvh_log(
    config: &AppConfig,
    signing_seed: [u8; 32],
) -> soland_storage::WebvhLogRecord {
    let prepared = fixture_prepared_service_inception(config, signing_seed);
    let event_digest = arkret_canonical::canonical_sha256(&prepared.log_entry)
        .expect("fixture service WebVH history digest");
    soland_storage::WebvhLogRecord {
        event_digest,
        did: prepared.did.clone(),
        seq: 1,
        operation: prepared.log_entry.clone(),
        created_at: chrono::DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
            .expect("fixture WebVH timestamp")
            .with_timezone(&chrono::Utc),
    }
}

pub fn app_state_with_identity(
    config: AppConfig,
    persistence: Arc<dyn PersistenceStore>,
    service_identity: DidCoreIdentityState,
    resolved_signing_seed: [u8; 32],
) -> AppState {
    let cell_registry = ProjectionService::sdk_cell_registry();
    let control_event_store: Arc<dyn ControlEventStore> =
        Arc::new(MemoryControlEventStore::default());
    // Mirror production bootstrap: the memory device-revocation adapter
    // derives seal-settled state from this Control Event store.
    persistence
        .device_revocations()
        .bind_control_event_store(control_event_store.clone());
    let seal_store = Arc::new(MemorySealStore::default());
    let cell_store = Arc::new(MemoryCellStore::default());
    let event_seal_committer = Arc::new(MemoryEventSealCommitter {
        lock: Mutex::new(()),
        data_event_leaf_manifests: Mutex::new(BTreeMap::new()),
        seal_store: seal_store.clone(),
        cell_store: cell_store.clone(),
        cell_registry: cell_registry.clone(),
    });
    let serving_identity = service_identity
        .identity()
        .expect("fixture has a serving identity");
    let service_id = serving_identity.service_id.to_string();
    let service_resolution_commitment = {
        let identity = service_identity
            .identity()
            .expect("fixture has a serving identity");
        let prepared = fixture_prepared_service_inception(&config, resolved_signing_seed);
        let method_history_head = if prepared.did == identity.did.as_str() {
            arkret_canonical::canonical_sha256(&prepared.log_entry)
                .expect("fixture service WebVH history digest")
        } else {
            format!("sha256:{}", "0".repeat(64))
        };
        arkret_models_identity::ResolutionCommitment {
            did: identity.did.clone(),
            method_history_head,
            version_id: identity.version_id.clone(),
        }
    };
    let projections = ProjectionService::new(
        control_event_store,
        seal_store.clone(),
        cell_store.clone(),
        cell_registry,
        event_seal_committer,
        &service_id,
    );
    let projection = Box::leak(Box::new(projections.test_state().clone()));
    let realm_directory = soland_http::state::build_realm_directory(
        &config,
        &serving_identity.did,
        &serving_identity.service_id,
        resolved_signing_seed,
    );
    let realms = Box::leak(Box::new(realm_directory.test_index().clone()));
    let state = AppState::from_runtime(
        config,
        AppStateRuntime {
            persistence: PersistenceHandle::from_shared(persistence.clone()),
            projections,
            realm_directory,
            object_storage: Arc::new(MemoryObjectStorage::default()),
            settings_persistence: Arc::new(NoRuntimeSettings),
            runtime_health: Arc::new(MemoryRuntimeHealth),
            event_broadcast: EventBroadcast::new(1024),
            storage_mode: "memory",
        },
        service_identity,
        service_resolution_commitment,
        resolved_signing_seed,
    );
    state_test_registry().lock().insert(
        app_state_key(&state),
        StateTestResources {
            persistence,
            projection: Some(projection),
            realms: Some(realms),
            seal_store: Some(seal_store),
            cell_store: Some(cell_store),
        },
    );
    state
}

pub trait AppStateTestExt {
    fn test_persistence(&self) -> Arc<dyn PersistenceStore>;
    fn test_projection(&self) -> &'static Arc<Mutex<ProjectionState>>;
    fn test_realms(&self) -> &'static Arc<Mutex<RealmDirectoryIndex>>;
    fn test_put_seal(
        &self,
        seal: &Seal,
        digest_suite: arkret_canonical::DigestSuite,
    ) -> StoreResult<()>;
    fn test_seal(&self, seal_id: &SealId) -> StoreResult<Option<Seal>>;
    fn test_seal_leaves(&self, realm_id: &RealmId) -> StoreResult<Vec<SealId>>;

    /// Append sealed cell effects the way `apply_seal` commits them.
    ///
    /// `arkret_state::effective_state_at` resolves a Seal's governance view
    /// from the cell log filtered by that Seal's covered Control-Move digests,
    /// so a fixture that only puts a Seal object leaves the view empty. A
    /// fixture that needs the Seal to actually *carry* state — for example a
    /// capability grant — has to write the ops the sealed Control Moves
    /// projected, which is what this does.
    fn test_append_sealed_effects(
        &self,
        realm_id: &RealmId,
        seal_id: &SealId,
        ops: &[(CellRef, IssuedOp)],
    ) -> StoreResult<()>;
}

pub fn register_persistence(state: &AppState, persistence: Arc<dyn PersistenceStore>) {
    state_test_registry().lock().insert(
        app_state_key(state),
        StateTestResources {
            persistence,
            projection: None,
            realms: None,
            seal_store: None,
            cell_store: None,
        },
    );
}

impl AppStateTestExt for AppState {
    fn test_persistence(&self) -> Arc<dyn PersistenceStore> {
        state_test_registry()
            .lock()
            .get(&app_state_key(self))
            .map(|resources| resources.persistence.clone())
            .expect("AppState was not constructed by soland-test-support")
    }

    fn test_projection(&self) -> &'static Arc<Mutex<ProjectionState>> {
        state_test_registry()
            .lock()
            .get(&app_state_key(self))
            .and_then(|resources| resources.projection)
            .expect("test projection is unavailable for this AppState")
    }

    fn test_realms(&self) -> &'static Arc<Mutex<RealmDirectoryIndex>> {
        state_test_registry()
            .lock()
            .get(&app_state_key(self))
            .and_then(|resources| resources.realms)
            .expect("test Realm directory is unavailable for this AppState")
    }

    fn test_put_seal(
        &self,
        seal: &Seal,
        digest_suite: arkret_canonical::DigestSuite,
    ) -> StoreResult<()> {
        state_test_registry()
            .lock()
            .get(&app_state_key(self))
            .and_then(|resources| resources.seal_store.clone())
            .expect("test Seal store is unavailable for this AppState")
            .put(seal, digest_suite)
    }

    fn test_seal(&self, seal_id: &SealId) -> StoreResult<Option<Seal>> {
        state_test_registry()
            .lock()
            .get(&app_state_key(self))
            .and_then(|resources| resources.seal_store.clone())
            .expect("test Seal store is unavailable for this AppState")
            .get(seal_id)
    }

    fn test_seal_leaves(&self, realm_id: &RealmId) -> StoreResult<Vec<SealId>> {
        state_test_registry()
            .lock()
            .get(&app_state_key(self))
            .and_then(|resources| resources.seal_store.clone())
            .expect("test Seal store is unavailable for this AppState")
            .list_leaves(realm_id)
    }

    fn test_append_sealed_effects(
        &self,
        realm_id: &RealmId,
        seal_id: &SealId,
        ops: &[(CellRef, IssuedOp)],
    ) -> StoreResult<()> {
        state_test_registry()
            .lock()
            .get(&app_state_key(self))
            .and_then(|resources| resources.cell_store.clone())
            .expect("test cell store is unavailable for this AppState")
            .append_sealed_effects(realm_id, seal_id, ops)
    }
}

fn app_state_key(state: &AppState) -> usize {
    state.test_registry_key()
}

struct StateTestResources {
    persistence: Arc<dyn PersistenceStore>,
    projection: Option<&'static Arc<Mutex<ProjectionState>>>,
    realms: Option<&'static Arc<Mutex<RealmDirectoryIndex>>>,
    seal_store: Option<Arc<dyn SealStore>>,
    cell_store: Option<Arc<dyn CellStore>>,
}

fn state_test_registry() -> &'static Mutex<BTreeMap<usize, StateTestResources>> {
    static REGISTRY: OnceLock<Mutex<BTreeMap<usize, StateTestResources>>> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(BTreeMap::new()))
}

#[must_use]
pub fn fixture_station_id() -> DidCoreId {
    fixture_service_identity(&app_config())
        .identity()
        .expect("fixture has a serving identity")
        .service_id
        .clone()
}

pub fn fixture_service_identity(config: &AppConfig) -> DidCoreIdentityState {
    let signing_seed = fixture_service_signing_seed(config);
    let prepared = fixture_prepared_service_inception(config, signing_seed);
    fixture_service_identity_for_did_and_version(
        config,
        Did::new(prepared.did.clone()).expect("prepared fixture service DID"),
        prepared.version_id.clone(),
    )
}

fn fixture_service_identity_for_did(config: &AppConfig, did: Did) -> DidCoreIdentityState {
    fixture_service_identity_for_did_and_version(config, did, "fixture-v1".to_owned())
}

fn fixture_service_identity_for_did_and_version(
    config: &AppConfig,
    did: Did,
    version_id: String,
) -> DidCoreIdentityState {
    let registration_key = ServiceRegistrationKey::new(
        ServiceKind::Station,
        CanonicalServiceUrl::canonicalize(&config.public_base_url)
            .expect("test public base must be canonicalizable"),
    )
    .expect("station registration key");
    let signing_key_ref =
        DidCoreIdentityKeyRef::new("fixture:soland:service-signing-key").expect("fixture key ref");
    let service_id =
        project_did_to_core_id(&did).expect("fixture service DID projects to a core id");
    DidCoreIdentityState::Ready {
        identity: LocalDidCoreIdentity {
            service_id,
            did,
            registration_key,
            provider: None,
            signing_key_refs: vec![signing_key_ref.clone()],
            active_signing_key_ref: signing_key_ref,
            control_key_ref: DidCoreIdentityKeyRef::new("fixture:soland:webvh-control-key")
                .expect("fixture control key ref"),
            version_id,
            last_verified_at: chrono::Utc::now(),
        },
    }
}

fn fixture_stored_service_identity(
    config: &AppConfig,
    state: &DidCoreIdentityState,
    signing_seed: [u8; 32],
) -> StoredDidCoreIdentity {
    let identity = state
        .identity()
        .expect("fixture has a serving identity")
        .clone();
    let verification_method = format!("{}#notary-key", identity.did);
    let prepared = fixture_prepared_service_inception(config, signing_seed);
    let prepared_matches_identity = prepared.did == identity.did.as_str();
    let did_document = if prepared_matches_identity {
        serde_json::from_value(
            prepared
                .log_entry
                .get("state")
                .cloned()
                .expect("fixture WebVH inception state"),
        )
        .expect("fixture WebVH DID document")
    } else {
        ServiceDidDocument {
            context: vec!["https://www.w3.org/ns/did/v1".to_owned()],
            id: identity.did.clone(),
            also_known_as: Vec::new(),
            verification_method: vec![ServiceDidVerificationMethod {
                id: verification_method.clone(),
                method_type: "Multikey".to_owned(),
                controller: identity.did.clone(),
                public_key_multibase: arkret_canonical::ed25519_pubkey_to_did_key_multibase(
                    ed25519_dalek::SigningKey::from_bytes(&signing_seed)
                        .verifying_key()
                        .as_bytes(),
                ),
            }],
            authentication: vec![verification_method.clone()],
            assertion_method: vec![verification_method],
            service: vec![ServiceDidEndpoint {
                id: format!("{}#service", identity.did),
                endpoint_type: "ArkretService".to_owned(),
                service_kind: ServiceKind::Station,
                service_endpoint: identity.registration_key.public_base_url().clone(),
            }],
        }
    };
    let log_head_digest = if prepared_matches_identity {
        arkret_canonical::canonical_sha256(&prepared.log_entry)
            .expect("fixture service WebVH history digest")
    } else {
        format!("sha256:{}", "0".repeat(64))
    };
    let issued_at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
    let provider_did = Did::new("did:webvh:z6mkfixture:provider.example:webvh:service".to_owned())
        .expect("fixture provider DID");
    let mut receipt = ServiceRegistrationReceipt {
        registration_receipt_id: arkret_wire::ServiceRegistrationReceiptId::new(format!(
            "ak:service_registration_receipt:{}",
            "a".repeat(64)
        ))
        .expect("fixture receipt id"),
        registration_key: identity.registration_key.clone(),
        service_id: identity.service_id.clone(),
        did: identity.did.clone(),
        version_id: identity.version_id.clone(),
        log_head_digest,
        control_key_digest: format!("sha256:{}", "1".repeat(64)),
        issued_at,
        provider_id: project_did_to_core_id(&provider_did).expect("fixture provider projection"),
        proof: arkret_wire::PayloadProof {
            kind: arkret_wire::proof_kind::DETACHED_JWS.to_owned(),
            verification_method: arkret_wire::DidUrl::new(format!("{provider_did}#service-key"))
                .expect("fixture provider method"),
            payload_digest: Hash::new(format!("sha256:{}", "0".repeat(64)))
                .expect("fixture receipt digest"),
            created_at: issued_at,
            domain: None,
            audience: None,
            proof_purpose: None,
            jws: format!(
                "eyJhbGciOiJFZDI1NTE5In0..{}",
                arkret_canonical::base64url::base64url_encode([0_u8; 64])
            ),
        },
    };
    receipt.registration_receipt_id = receipt
        .expected_registration_receipt_id()
        .expect("fixture receipt id binding");
    receipt.proof.payload_digest = receipt
        .expected_payload_digest()
        .expect("fixture receipt payload digest");
    let stored = StoredDidCoreIdentity {
        identity,
        did_document,
        registration_receipt: receipt,
        stored_at: issued_at,
    };
    stored
        .validate()
        .expect("valid stored fixture service identity");
    stored
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
        let bytes = std::fs::read(file_path).map_err(|error| error.to_string())?;
        self.put(key, bytes).await
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

struct MemoryRuntimeHealth;

#[async_trait]
impl RuntimeHealthPort for MemoryRuntimeHealth {
    async fn database_ready(&self) -> bool {
        true
    }

    fn storage_mode(&self) -> &'static str {
        "memory"
    }

    fn migrations_applied(&self) -> bool {
        true
    }

    fn database_configured(&self) -> bool {
        false
    }

    fn database_pool_in_use(&self) -> u32 {
        0
    }
}

struct MemoryEventSealCommitter {
    lock: Mutex<()>,
    data_event_leaf_manifests: Mutex<BTreeMap<SealId, BTreeSet<Hash>>>,
    seal_store: Arc<MemorySealStore>,
    cell_store: Arc<MemoryCellStore>,
    cell_registry: Arc<dyn CellRegistry>,
}

impl EventSealCommitPort for MemoryEventSealCommitter {
    fn commit_if_frontier(
        &self,
        seal: &Seal,
        digest_suite: arkret_canonical::DigestSuite,
        expected_store_frontier: &[SealId],
        new_ops: &[(CellRef, IssuedOp)],
        covered: &BTreeSet<Hash>,
        data_event_leaf_manifest: &BTreeSet<Hash>,
        _governance_dependencies: &[soland_storage::GovernanceDependencyWrite],
    ) -> StoreResult<bool> {
        let _guard = self.lock.lock();
        let computed_root = (!data_event_leaf_manifest.is_empty())
            .then(|| arkret_state::event_digest_set_root(data_event_leaf_manifest, digest_suite))
            .transpose()
            .map_err(|error| StoreError::Backend(error.to_string()))?;
        if computed_root != seal.data_event_set_root {
            return Err(StoreError::Conflict(
                "Event Seal data_event_set_root does not match its frozen leaf manifest".to_owned(),
            ));
        }
        if let Some(existing) = self.seal_store.get(&seal.id)? {
            let existing_bytes = arkret_canonical::canonical_json_bytes(&existing)
                .map_err(|error| StoreError::Backend(error.to_string()))?;
            let retry_bytes = arkret_canonical::canonical_json_bytes(seal)
                .map_err(|error| StoreError::Backend(error.to_string()))?;
            if existing_bytes != retry_bytes
                || self.data_event_leaf_manifests.lock().get(&seal.id)
                    != Some(data_event_leaf_manifest)
            {
                return Err(StoreError::Conflict(
                    "duplicate_conflict: exact Seal replay changed its frozen DataEvent leaf manifest"
                        .to_owned(),
                ));
            }
            return Ok(true);
        }
        let actual = self
            .seal_store
            .list_leaves(&seal.realm_id)?
            .into_iter()
            .collect::<BTreeSet<_>>();
        let expected = expected_store_frontier
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        if actual != expected {
            return Ok(false);
        }
        let post_state = effective_state_with_new_ops(
            self.cell_store.as_ref(),
            self.cell_registry.as_ref(),
            &seal.realm_id,
            covered,
            new_ops,
        )?;
        let state_root = compute_state_root(&post_state, digest_suite)
            .map_err(|error| StoreError::Backend(format!("state_root recompute: {error}")))?;
        if state_root != seal.state_root {
            return Err(StoreError::Conflict(format!(
                "Event Seal state_root mismatch: declared {}, recomputed {}",
                seal.state_root, state_root
            )));
        }
        self.cell_store
            .append_sealed_effects(&seal.realm_id, &seal.id, new_ops)?;
        match self
            .seal_store
            .put_if_frontier(seal, expected_store_frontier, digest_suite)
        {
            Ok(true) => {
                self.data_event_leaf_manifests
                    .lock()
                    .insert(seal.id.clone(), data_event_leaf_manifest.clone());
                Ok(true)
            }
            Ok(false) => {
                self.cell_store.rollback_seal(&seal.realm_id, &seal.id)?;
                Ok(false)
            }
            Err(error) => {
                let _ = self.cell_store.rollback_seal(&seal.realm_id, &seal.id);
                Err(error)
            }
        }
    }

    fn data_event_leaf_manifest(&self, seal_id: &SealId) -> StoreResult<Option<BTreeSet<Hash>>> {
        let _guard = self.lock.lock();
        Ok(self.data_event_leaf_manifests.lock().get(seal_id).cloned())
    }
}

fn effective_state_with_new_ops(
    cells: &dyn CellStore,
    registry: &dyn CellRegistry,
    realm_id: &arkret_identifiers::RealmId,
    covered: &BTreeSet<Hash>,
    new_ops: &[(CellRef, IssuedOp)],
) -> StoreResult<BTreeMap<CellRef, CellState>> {
    let mut cell_refs = cells
        .list_cells(realm_id)?
        .into_iter()
        .collect::<BTreeSet<_>>();
    cell_refs.extend(new_ops.iter().map(|(cell, _)| cell.clone()));
    let mut joined = BTreeMap::new();
    for cell in cell_refs {
        let mut batches = cells
            .sealed_op_batches_for_cell(realm_id, &cell)?
            .into_iter()
            .filter_map(|(_, ops)| {
                let ops = ops
                    .into_iter()
                    .filter(|issued| covered.contains(&issued.op.move_id))
                    .collect::<Vec<_>>();
                (!ops.is_empty()).then_some(ops)
            })
            .collect::<Vec<_>>();
        let new_batch = new_ops
            .iter()
            .filter(|(candidate, issued)| {
                candidate == &cell && covered.contains(&issued.op.move_id)
            })
            .map(|(_, operation)| operation.clone())
            .collect::<Vec<_>>();
        if !new_batch.is_empty() {
            batches.push(new_batch);
        }
        if batches.is_empty() {
            continue;
        }
        // Match production CellStore semantics: persisted operations and
        // `new_ops` are both causal. The Control Move id is a content hash,
        // not an ordering
        // key for FSM transitions.
        let binding = registry.resolve(realm_id, &cell)?;
        joined.insert(
            cell.clone(),
            arkret_state::join_cell_seal_batches(binding.lattice.as_ref(), &cell, &batches),
        );
    }
    Ok(joined)
}

pub use soland_http::project_accepted_operations;

/// Stable event-derived PCR address for fixtures that do not exercise the
/// full signed genesis builder. Production code must resolve accepted PCRs.
pub fn fixture_principal_control_realm(principal_did: &str) -> String {
    cba_basis::fixture_principal_control_realm_create(principal_did)
        .realm_id
        .to_string()
}

/// Project one accepted principal device together with the exact local account
/// authority/PCR coordinate required by strict principal-device proof gates.
pub async fn project_authorized_principal_device(
    state: &AppState,
    principal_did: &str,
    device_id: &str,
    signing_key: &ed25519_dalek::SigningKey,
) -> String {
    let principal_did = Did::new(principal_did.to_owned()).unwrap();
    let principal_id = arkret_wire::project_did_to_core_id(&principal_did).unwrap();
    let pcr_create = cba_basis::fixture_principal_control_realm_create_for_server(
        principal_did.as_str(),
        arkret_identifiers::DidCoreId::new(state.service_id().clone())
            .expect("fixture service core DID"),
    );
    let pcr_realm_id = pcr_create.realm_id.clone();
    cba_basis::seed_realm_genesis_event(state, pcr_realm_id.as_str(), principal_did.as_str()).await;
    let genesis_record = state
        .test_persistence()
        .events()
        .realm_events_newest_first(pcr_realm_id.as_str())
        .await
        .unwrap()
        .into_iter()
        .find(|record| record.kind == arkret_wire::EventKind::RealmCreate.as_str())
        .expect("PCR genesis Event");
    let genesis: arkret_wire::Event = serde_json::from_value(genesis_record.envelope).unwrap();
    let station_id = genesis.actor_id.route_service_id().clone();
    let now = chrono::Utc::now();
    let device_public_key = arkret_canonical::ed25519_pubkey_to_did_key_multibase(
        signing_key.verifying_key().as_bytes(),
    );
    let mut authorize = arkret_wire::test_support::raw_event_at(
        arkret_wire::EventKind::DeviceAuthorize.as_str(),
        arkret_wire::ScopeRef::Realm {
            realm_id: pcr_realm_id.clone(),
        },
        principal_id.clone(),
        station_id.clone(),
        1,
        arkret_identifiers::Hlc::new("019041000000-0000-00000001".to_owned()).unwrap(),
        serde_json::json!({
            "principal_id": principal_id,
            "device_id": device_id,
            "device_public_key_did": device_public_key,
            "hpke_key": "z6LSTestAuthorizedDeviceHpkeKey",
            "algorithms": ["ak.hpke_x25519_aead_chacha20poly1305.v1", "ak.mls.v1"],
            "authorized_by": principal_id,
            "not_before": "2026-05-25T00:00:00.000Z",
            "authorization_binding_kind": "registration_anchor",
            "device_signature": "c2ln"
        }),
        now,
    )
    .unwrap();
    authorize.prev_refs = vec![genesis.event_id.clone()];
    authorize
        .refresh_content_bound_identity_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
        .unwrap();
    let authorize = signed_event::sign_fixture_event(
        authorize,
        principal_did.as_str(),
        device_id,
        signing_key.to_bytes(),
    );
    let operation = arkret_event_draft::ProjectedEventOperation::from_accepted_event(
        arkret_identifiers::OperationId::new(arkret_identifiers::new_prefixed_uuid7(
            "ak:operation:",
        ))
        .unwrap(),
        arkret_wire::OperationKind::Create,
        None,
        &authorize,
        arkret_canonical::DigestSuite::Sha256,
    )
    .unwrap();
    let authorize_event_id = authorize.event_id.to_string();
    state
        .test_persistence()
        .events()
        .put(signed_event::canonical_event_record(
            &authorize,
            Some(pcr_realm_id.as_str()),
            now,
        ))
        .await
        .unwrap();
    let authority_key = arkret_wire::AccountId::new(principal_id.clone(), station_id);
    if state
        .test_persistence()
        .principal_resolutions()
        .by_account_id(&authority_key)
        .await
        .unwrap()
        .is_none()
    {
        let applied = state
            .test_persistence()
            .principal_resolutions()
            .compare_and_set(
                None,
                soland_storage::PrincipalResolutionRecord {
                    account_id: authority_key,
                    pcr_realm_id: pcr_realm_id.clone(),
                    genesis_event: genesis.clone(),
                    current_event: genesis.clone(),
                    projection: arkret_models_identity::PrincipalResolutionProjection {
                        did: principal_did,
                        method_history_head: format!("sha256:{}", "1".repeat(64)),
                        version_id: "1-QmTestAuthority".to_owned(),
                        resolution_event_ref: genesis.event_id.to_string(),
                        updated_at: genesis.created_at,
                    },
                },
            )
            .await
            .unwrap();
        assert!(matches!(
            applied,
            soland_storage::PrincipalResolutionCasResult::Applied(_)
        ));
    }
    soland_http::project_accepted_operations(state, principal_id.as_str(), &[operation]).await;
    let mut projected_device = state
        .test_persistence()
        .devices()
        .get(principal_id.as_str(), device_id)
        .await
        .unwrap()
        .expect("projected authorized device");
    projected_device
        .payload
        .as_object_mut()
        .expect("projected authorized device payload")
        .insert("authorized_generation_ref".to_owned(), serde_json::json!(1));
    state
        .test_persistence()
        .devices()
        .put(&projected_device)
        .await
        .unwrap();
    authorize_event_id
}

/// Read the service-derived `push_target_id` for one registered device.
///
/// `push_register_device_outcome` returns the pseudonym to the registering
/// client itself (`zh/discovery/push-notifications.md` §3.1: the registration
/// response is the only contractual path that hands it out); this helper reads
/// the stored registration instead, which is what a notify caller inside the
/// service does. A test that reuses `registration_id` as a push target is
/// asserting a conflation the two values never had.
pub async fn registered_push_target_id(
    state: &AppState,
    principal_id: &str,
    device_id: &str,
) -> String {
    state
        .test_push_devices()
        .await
        .into_iter()
        .find(|record| {
            record.get("principal_id").and_then(|v| v.as_str()) == Some(principal_id)
                && record.get("device_id").and_then(|v| v.as_str()) == Some(device_id)
        })
        .and_then(|record| {
            record
                .get("push_target_id")
                .and_then(|v| v.as_str())
                .map(ToOwned::to_owned)
        })
        .expect("registered push device carries a push_target_id")
}
