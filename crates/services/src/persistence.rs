use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use arkret_identifiers::RealmId;
use soland_storage::{PersistenceResult, PersistenceStore};

use crate::delivery::{DeliveryService, ObjectStoragePort};
use crate::events::RealmDirectoryIndex;
use crate::governance::{AdminSigningKeyPort, RuntimeSettingsPort};
use crate::hydration::{
    HydrationProjectionAdapter, hydrate_cross_signing_from_persistence,
    hydrate_realms_from_canonical_events,
};
use crate::identity::{
    CrossSigningRegistry, DidDocumentState, DidLogEvent, DidResolverPort,
    ServiceRegistrationCommitResult,
};
use crate::jobs::RuntimeHealthPort;
use crate::join_applications::JoinApplicationService;
use crate::persistence_delivery::build_persistence_delivery_service;
use crate::persistence_events::{PersistenceEventServices, build_persistence_event_services};
use crate::persistence_identity::{
    PersistenceIdentityServices, build_persistence_identity_services,
};
use crate::persistence_operations::{
    PersistenceOperationalServices, build_persistence_operational_services,
};
use crate::projection::ProjectionService;

#[doc(hidden)]
pub type TestPersistenceStore = dyn PersistenceStore;

/// Opaque application-owned handle used by the composition root to install a
/// concrete persistence adapter without exposing the storage registry to HTTP
/// or runtime state.
#[derive(Clone)]
pub struct PersistenceHandle {
    persistence: Arc<dyn PersistenceStore>,
}

impl PersistenceHandle {
    pub async fn stored_service_identity(
        &self,
    ) -> crate::ServiceResult<Option<arkret_identity::service_identity::StoredServiceIdentity>>
    {
        Ok(self.persistence.service_identity().get().await?)
    }

    pub async fn store_service_identity(
        &self,
        identity: arkret_identity::service_identity::StoredServiceIdentity,
    ) -> crate::ServiceResult<()> {
        self.persistence.service_identity().put(identity).await?;
        Ok(())
    }

    pub async fn service_registration(
        &self,
        key: &arkret_models_identity::service_identity::ServiceRegistrationKey,
    ) -> crate::ServiceResult<
        Option<arkret_models_identity::service_identity::ServiceRegistrationOutcome>,
    > {
        Ok(self
            .persistence
            .webvh()
            .get_service_registration(key)
            .await?)
    }

    pub async fn webvh_history(&self, did: &str) -> crate::ServiceResult<Vec<DidLogEvent>> {
        Ok(self
            .persistence
            .webvh()
            .list_log_events(did)
            .await?
            .into_iter()
            .map(|record| DidLogEvent {
                event_digest: record.event_digest,
                did: record.did,
                seq: record.seq,
                operation: record.operation,
                created_at: record.created_at,
            })
            .collect())
    }

    pub async fn commit_service_registration(
        &self,
        key: arkret_models_identity::service_identity::ServiceRegistrationKey,
        outcome: arkret_models_identity::service_identity::ServiceRegistrationOutcome,
        document: DidDocumentState,
        event: DidLogEvent,
    ) -> crate::ServiceResult<ServiceRegistrationCommitResult> {
        let document = soland_storage::WebvhDocumentRecord {
            did: document.did,
            did_document: document.did_document,
            key_log_head: document.key_log_head,
            seq: document.seq,
            method_evidence: document.method_evidence,
            fetched_at: document.fetched_at,
            expires_at: document.expires_at,
            updated_at: document.updated_at,
        };
        let event = soland_storage::WebvhLogRecord {
            event_digest: event.event_digest,
            did: event.did,
            seq: event.seq,
            operation: event.operation,
            created_at: event.created_at,
        };
        Ok(
            match self
                .persistence
                .webvh()
                .commit_service_registration(key, outcome, document, event)
                .await?
            {
                soland_storage::ServiceRegistrationCommitOutcome::Created(outcome) => {
                    ServiceRegistrationCommitResult::Created(outcome)
                }
                soland_storage::ServiceRegistrationCommitOutcome::Existing(outcome) => {
                    ServiceRegistrationCommitResult::Existing(outcome)
                }
                soland_storage::ServiceRegistrationCommitOutcome::Conflict => {
                    ServiceRegistrationCommitResult::Conflict
                }
            },
        )
    }

    pub async fn seed_demo_identity(&self) -> crate::ServiceResult<()> {
        let now = chrono::Utc::now();
        let account = soland_storage::AccountRecord {
            id: "ak:account:0196419b-0000-7000-8000-000000000001".to_owned(),
            did: "did:web:alice.example".to_owned(),
            localpart: "alice".to_owned(),
            display_name: Some("Alice Example".to_owned()),
            bio: None,
            avatar_blob_ref: None,
            created_at: now,
        };
        self.persistence.accounts().put(&account).await?;
        self.persistence
            .account_localparts()
            .add(&account.did, &account.localpart, true)
            .await?;
        self.persistence
            .realm_meta()
            .put(
                "ak:realm:0196419b-0000-8000-8000-000000000000",
                &soland_storage::RealmMetaRecord {
                    owner: account.did,
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
                    aad_visibility_ceiling: Default::default(),
                    created_at: now,
                    updated_at: now,
                },
            )
            .await?;
        Ok(())
    }

    pub fn new<P>(persistence: Arc<P>) -> Self
    where
        P: PersistenceStore + 'static,
    {
        Self { persistence }
    }

    #[doc(hidden)]
    pub fn from_shared(persistence: Arc<dyn PersistenceStore>) -> Self {
        Self { persistence }
    }

    pub fn event_services(
        &self,
        projected_operations: Arc<dyn crate::events::ProjectedOperationPersistencePort>,
    ) -> PersistenceEventServices {
        build_persistence_event_services(self.persistence.clone(), projected_operations)
    }

    pub fn delivery_service(
        &self,
        object_storage: Arc<dyn ObjectStoragePort>,
        push_target_hmac_key: [u8; 32],
    ) -> DeliveryService {
        build_persistence_delivery_service(
            self.persistence.clone(),
            object_storage,
            push_target_hmac_key,
        )
    }

    pub fn identity_services(
        &self,
        did_resolver: Arc<dyn DidResolverPort>,
    ) -> PersistenceIdentityServices {
        build_persistence_identity_services(self.persistence.clone(), did_resolver)
    }

    pub fn operational_services(
        &self,
        admin_signing_keys: Arc<dyn AdminSigningKeyPort>,
        runtime_settings: Arc<dyn RuntimeSettingsPort>,
        runtime_health: Arc<dyn RuntimeHealthPort>,
        sync_cursor_hmac_key: [u8; 32],
    ) -> PersistenceOperationalServices {
        build_persistence_operational_services(
            self.persistence.clone(),
            admin_signing_keys,
            runtime_settings,
            runtime_health,
            sync_cursor_hmac_key,
        )
    }

    pub fn join_application_service(&self) -> JoinApplicationService {
        JoinApplicationService::new(self.persistence.clone())
    }

    pub async fn hydrate_realm_directory(&self) -> RealmDirectoryIndex {
        let mut realms = RealmDirectoryIndex::new();
        hydrate_realms_from_canonical_events(self.persistence.as_ref(), &mut realms).await;
        realms
    }

    pub async fn hydrate_cross_signing(&self) -> PersistenceResult<CrossSigningRegistry> {
        hydrate_cross_signing_from_persistence(self.persistence.as_ref()).await
    }

    pub async fn hydrate_projection(
        &self,
        projection: &ProjectionService,
        projection_adapter: &dyn HydrationProjectionAdapter,
        realm_ids: impl IntoIterator<Item = RealmId>,
    ) -> PersistenceResult<()> {
        projection
            .hydrate_from_persistence(self.persistence.as_ref(), projection_adapter, realm_ids)
            .await
    }

    #[doc(hidden)]
    pub fn shared_for_tests(&self) -> Arc<TestPersistenceStore> {
        self.persistence.clone()
    }
}
