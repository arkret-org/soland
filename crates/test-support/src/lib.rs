#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::ops::Range;
use std::path::Path;
use std::sync::{Arc, OnceLock};

use arkret_identifiers::{CellRef, Did, MoveId, SealId};
use arkret_identity::service_identity::{
    LocalServiceIdentity, ServiceIdentityKeyRef, ServiceIdentityState,
};
use arkret_models_identity::service_identity::{CanonicalServiceUrl, ServiceRegistrationKey};
use arkret_state::lattice::{CellState, SealedOp};
use arkret_state::state::{
    CellRegistry, CellStore, MemoryCellStore, MemoryMoveStore, MemorySealStore, MoveStore,
    SealStore, StoreError, StoreResult, compute_state_root,
};
use arkret_wire::{Seal, ServiceType};
use async_trait::async_trait;
use bytes::Bytes;
use futures_util::stream::{self, BoxStream, StreamExt};
use parking_lot::Mutex;
use serde_json::Value;
use sha2::{Digest, Sha256};
use soland_application::delivery::ObjectStoragePort;
use soland_application::events::{ProjectedOperationPersistencePort, RealmDirectoryIndex};
use soland_application::governance::RuntimeSettingsPort;
use soland_application::jobs::RuntimeHealthPort;
use soland_application::persistence::PersistenceHandle;
use soland_application::projection::{
    EventSealCommitPort, ProjectionApplicationService, ProjectionSnapshot,
};
use soland_http::config::AppConfig;
use soland_http::state::{AppState, AppStateRuntime, EventBroadcast};
use soland_storage::PersistenceStore;
use soland_storage_memory::SolandMemoryPersistenceStore;

pub fn app_config() -> AppConfig {
    AppConfig::test_default()
}

pub fn app_state(config: AppConfig) -> AppState {
    let persistence: Arc<dyn PersistenceStore> = if config.seed_demo_data {
        Arc::new(SolandMemoryPersistenceStore::new_with_demo_data())
    } else {
        Arc::new(SolandMemoryPersistenceStore::new())
    };
    app_state_with_persistence(config, persistence)
}

pub fn app_state_with_persistence(
    config: AppConfig,
    persistence: Arc<dyn PersistenceStore>,
) -> AppState {
    let identity = fixture_service_identity(&config);
    let signing_seed = fixture_signing_seed(&config, &identity);
    app_state_with_identity(config, persistence, identity, signing_seed)
}

pub fn fixture_signing_seed(config: &AppConfig, identity: &ServiceIdentityState) -> [u8; 32] {
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

pub fn app_state_with_identity(
    config: AppConfig,
    persistence: Arc<dyn PersistenceStore>,
    service_identity: ServiceIdentityState,
    resolved_signing_seed: [u8; 32],
) -> AppState {
    let cell_registry = ProjectionApplicationService::sdk_cell_registry();
    let move_store: Arc<dyn MoveStore> = Arc::new(MemoryMoveStore::default());
    let seal_store = Arc::new(MemorySealStore::default());
    let cell_store = Arc::new(MemoryCellStore::default());
    let event_seal_committer = Arc::new(MemoryEventSealCommitter {
        lock: Mutex::new(()),
        seal_store: seal_store.clone(),
        cell_store: cell_store.clone(),
        cell_registry: cell_registry.clone(),
    });
    let service_id = service_identity
        .identity()
        .expect("fixture has a serving identity")
        .service_id
        .to_string();
    let projection_application = ProjectionApplicationService::new(
        move_store,
        seal_store.clone(),
        cell_store,
        cell_registry,
        event_seal_committer,
        &service_id,
    );
    let projection = Box::leak(Box::new(projection_application.test_state().clone()));
    let realm_directory_application =
        soland_http::state::build_realm_directory_application(&config);
    let realms = Box::leak(Box::new(realm_directory_application.test_index().clone()));
    let state = AppState::from_runtime(
        config,
        AppStateRuntime {
            persistence: PersistenceHandle::from_shared(persistence.clone()),
            projection_application,
            realm_directory_application,
            projected_operation_persistence: Arc::new(NoProjectedOperationPersistence),
            object_storage: Arc::new(MemoryObjectStorage::default()),
            settings_persistence: Arc::new(NoRuntimeSettings),
            runtime_health: Arc::new(MemoryRuntimeHealth),
            event_broadcast: EventBroadcast::new(1024),
            storage_mode: "memory",
        },
        service_identity,
        resolved_signing_seed,
    );
    state_test_registry().lock().insert(
        app_state_key(&state),
        StateTestResources {
            persistence,
            projection: Some(projection),
            realms: Some(realms),
            seal_store: Some(seal_store),
        },
    );
    state
}

pub trait AppStateTestExt {
    fn test_persistence(&self) -> Arc<dyn PersistenceStore>;
    fn test_projection(&self) -> &'static Arc<Mutex<ProjectionSnapshot>>;
    fn test_realms(&self) -> &'static Arc<Mutex<RealmDirectoryIndex>>;
    fn test_put_seal(&self, seal: &Seal) -> StoreResult<()>;
}

pub fn register_persistence(state: &AppState, persistence: Arc<dyn PersistenceStore>) {
    state_test_registry().lock().insert(
        app_state_key(state),
        StateTestResources {
            persistence,
            projection: None,
            realms: None,
            seal_store: None,
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

    fn test_projection(&self) -> &'static Arc<Mutex<ProjectionSnapshot>> {
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

    fn test_put_seal(&self, seal: &Seal) -> StoreResult<()> {
        state_test_registry()
            .lock()
            .get(&app_state_key(self))
            .and_then(|resources| resources.seal_store.clone())
            .expect("test Seal store is unavailable for this AppState")
            .put(seal)
    }
}

fn app_state_key(state: &AppState) -> usize {
    state.test_registry_key()
}

struct StateTestResources {
    persistence: Arc<dyn PersistenceStore>,
    projection: Option<&'static Arc<Mutex<ProjectionSnapshot>>>,
    realms: Option<&'static Arc<Mutex<RealmDirectoryIndex>>>,
    seal_store: Option<Arc<dyn SealStore>>,
}

fn state_test_registry() -> &'static Mutex<BTreeMap<usize, StateTestResources>> {
    static REGISTRY: OnceLock<Mutex<BTreeMap<usize, StateTestResources>>> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(BTreeMap::new()))
}

pub fn fixture_service_identity(config: &AppConfig) -> ServiceIdentityState {
    let registration_key = ServiceRegistrationKey::new(
        ServiceType::PrincipalServer,
        CanonicalServiceUrl::canonicalize(&config.public_base_url)
            .expect("test public base must be canonicalizable"),
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
    async fn load_overrides(&self) -> soland_application::ApplicationResult<Vec<(String, Value)>> {
        Ok(Vec::new())
    }

    async fn store_override(
        &self,
        _key: &str,
        _value: &Value,
        _updated_by: &str,
    ) -> soland_application::ApplicationResult<()> {
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
    seal_store: Arc<MemorySealStore>,
    cell_store: Arc<MemoryCellStore>,
    cell_registry: Arc<dyn CellRegistry>,
}

impl EventSealCommitPort for MemoryEventSealCommitter {
    fn commit_if_frontier(
        &self,
        seal: &Seal,
        expected_store_frontier: &[SealId],
        new_ops: &[(CellRef, SealedOp)],
        covered: &BTreeSet<MoveId>,
    ) -> StoreResult<bool> {
        let _guard = self.lock.lock();
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
        let state_root = compute_state_root(&post_state)
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
            .put_if_frontier(seal, expected_store_frontier)
        {
            Ok(true) => Ok(true),
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
}

fn effective_state_with_new_ops(
    cells: &dyn CellStore,
    registry: &dyn CellRegistry,
    realm_id: &arkret_identifiers::RealmId,
    covered: &BTreeSet<MoveId>,
    new_ops: &[(CellRef, SealedOp)],
) -> StoreResult<BTreeMap<CellRef, CellState>> {
    let mut cell_refs = cells
        .list_cells(realm_id)?
        .into_iter()
        .collect::<BTreeSet<_>>();
    cell_refs.extend(new_ops.iter().map(|(cell, _)| cell.clone()));
    let mut joined = BTreeMap::new();
    for cell in cell_refs {
        let mut ops = cells
            .sealed_ops_for_cell(realm_id, &cell)?
            .into_iter()
            .filter(|operation| covered.contains(&operation.move_id))
            .collect::<Vec<_>>();
        ops.extend(
            new_ops
                .iter()
                .filter(|(candidate, operation)| {
                    candidate == &cell && covered.contains(&operation.move_id)
                })
                .map(|(_, operation)| operation.clone()),
        );
        if ops.is_empty() {
            continue;
        }
        ops.sort_by(|left, right| right.move_id.as_str().cmp(left.move_id.as_str()));
        let binding = registry.resolve(realm_id, &cell)?;
        joined.insert(cell.clone(), binding.lattice.join(&cell, &ops));
    }
    Ok(joined)
}

pub use soland_application::identity::principal_control_realm_for_did;
pub use soland_http::project_accepted_operations;
