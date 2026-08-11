use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use arkret_identifiers::RealmId;
use soland_storage::{PersistenceResult, PersistenceStore};

use crate::delivery::{DeliveryService, ObjectStoragePort};
use crate::events::RealmDirectoryIndex;
use crate::governance::RuntimeSettingsPort;
use crate::hydration::{HydrationProjectionAdapter, hydrate_realms_from_canonical_events};
use crate::identity::{
    DidDocumentState, DidLogEvent, DidResolverPort, ServiceRegistrationCommitResult,
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
    pub async fn idempotency_record(
        &self,
        principal_id: &str,
        idempotency_key: &str,
    ) -> crate::ServiceResult<Option<soland_storage::IdempotencyRecord>> {
        Ok(self
            .persistence
            .idempotency_keys()
            .get(principal_id, idempotency_key)
            .await?)
    }

    pub async fn record_idempotency(
        &self,
        record: &soland_storage::IdempotencyRecord,
    ) -> crate::ServiceResult<()> {
        self.persistence.idempotency_keys().record(record).await?;
        Ok(())
    }

    pub async fn stored_service_route_keys(
        &self,
        after: Option<&soland_storage::ServiceRouteStoredKey>,
        limit: usize,
    ) -> crate::ServiceResult<Vec<soland_storage::ServiceRouteStoredKey>> {
        Ok(self
            .persistence
            .service_routes()
            .list_stored_route_keys(after, limit)
            .await?)
    }

    pub async fn stored_service_route_notice_states(
        &self,
        service_id: &arkret_wire::DidCoreId,
        service_kind: &str,
        limit: usize,
    ) -> crate::ServiceResult<Vec<arkret_models_identity::ServiceRouteNoticeState>> {
        Ok(self
            .persistence
            .service_routes()
            .notice_states(service_id, service_kind, limit)
            .await?)
    }

    pub async fn stored_service_route_mirrors(
        &self,
        service_id: &arkret_wire::DidCoreId,
        service_kind: &str,
        limit: usize,
    ) -> crate::ServiceResult<Vec<soland_storage::ServiceResolutionMirrorEntry>> {
        Ok(self
            .persistence
            .service_routes()
            .handover_mirror_entries(service_id, service_kind, limit)
            .await?)
    }

    pub async fn stored_service_route_quarantine(
        &self,
        service_id: &arkret_wire::DidCoreId,
        service_kind: &str,
        limit: usize,
    ) -> crate::ServiceResult<Vec<soland_storage::ServiceResolutionForkEvidence>> {
        Ok(self
            .persistence
            .service_routes()
            .quarantine_evidence(service_id, service_kind, limit)
            .await?)
    }

    pub async fn service_route_cache(
        &self,
        service_id: &arkret_wire::DidCoreId,
        service_kind: &str,
    ) -> crate::ServiceResult<Option<arkret_models_identity::ServiceRouteCacheEntry>> {
        Ok(self
            .persistence
            .service_routes()
            .route_cache(service_id, service_kind)
            .await?)
    }

    pub async fn service_route_floor(
        &self,
        service_id: &arkret_wire::DidCoreId,
        service_kind: &str,
    ) -> crate::ServiceResult<Option<arkret_models_identity::ServiceResolutionLastSeenFloor>> {
        Ok(self
            .persistence
            .service_routes()
            .last_seen_floor(service_id, service_kind)
            .await?)
    }

    pub async fn advance_service_route_floor(
        &self,
        floor: arkret_models_identity::ServiceResolutionLastSeenFloor,
    ) -> crate::ServiceResult<soland_storage::MonotonicRouteWrite> {
        Ok(self
            .persistence
            .service_routes()
            .advance_last_seen_floor(floor)
            .await?)
    }

    pub async fn service_route_notice_state(
        &self,
        service_id: &arkret_wire::DidCoreId,
        service_kind: &str,
        handover_id: &str,
    ) -> crate::ServiceResult<Option<arkret_models_identity::ServiceRouteNoticeState>> {
        Ok(self
            .persistence
            .service_routes()
            .notice_state(service_id, service_kind, handover_id)
            .await?)
    }

    pub async fn advance_service_route_notice(
        &self,
        notice: arkret_models_identity::ServiceRouteNoticeState,
    ) -> crate::ServiceResult<soland_storage::MonotonicRouteWrite> {
        Ok(self
            .persistence
            .service_routes()
            .advance_notice_state(notice)
            .await?)
    }

    pub async fn commit_service_route_mirror(
        &self,
        entry: soland_storage::ServiceResolutionMirrorEntry,
    ) -> crate::ServiceResult<soland_storage::ServiceResolutionMirrorCommit> {
        Ok(self
            .persistence
            .service_routes()
            .commit_mirror(entry)
            .await?)
    }

    pub async fn service_route_successors(
        &self,
        source_service_id: &arkret_wire::DidCoreId,
        realm_id: &arkret_wire::RealmId,
        target_service_id: &arkret_wire::DidCoreId,
        service_kind: &str,
        after_sequence: u64,
        limit: usize,
    ) -> crate::ServiceResult<Vec<arkret_models_identity::ServiceResolutionRecord>> {
        Ok(self
            .persistence
            .service_routes()
            .successor_records(
                source_service_id,
                realm_id,
                target_service_id,
                service_kind,
                after_sequence,
                limit,
            )
            .await?)
    }

    pub async fn latest_service_route_notice(
        &self,
        source_service_id: &arkret_wire::DidCoreId,
        realm_id: &arkret_wire::RealmId,
        target_service_id: &arkret_wire::DidCoreId,
        service_kind: &str,
    ) -> crate::ServiceResult<Option<arkret_models_identity::ServiceRouteHandoverNotice>> {
        Ok(self
            .persistence
            .service_routes()
            .latest_notice(source_service_id, realm_id, target_service_id, service_kind)
            .await?)
    }

    pub async fn quarantine_service_route_fork(
        &self,
        evidence: soland_storage::ServiceResolutionForkEvidence,
    ) -> crate::ServiceResult<()> {
        self.persistence
            .service_routes()
            .quarantine_fork(evidence)
            .await?;
        Ok(())
    }

    pub async fn service_route_is_quarantined(
        &self,
        service_id: &arkret_wire::DidCoreId,
        service_kind: &str,
    ) -> crate::ServiceResult<bool> {
        Ok(self
            .persistence
            .service_routes()
            .is_quarantined(service_id, service_kind)
            .await?)
    }

    pub async fn stored_service_identity(
        &self,
    ) -> crate::ServiceResult<Option<arkret_identity::service_identity::StoredDidCoreIdentity>>
    {
        Ok(self.persistence.service_identity().get().await?)
    }

    pub async fn store_service_identity(
        &self,
        identity: arkret_identity::service_identity::StoredDidCoreIdentity,
    ) -> crate::ServiceResult<()> {
        self.persistence.service_identity().put(identity).await?;
        Ok(())
    }

    pub async fn current_service_resolution(
        &self,
    ) -> crate::ServiceResult<Option<arkret_models_identity::ServiceResolutionRecord>> {
        Ok(self.persistence.service_identity().get_resolution().await?)
    }

    pub async fn compare_and_set_service_resolution(
        &self,
        expected_digest: Option<&arkret_wire::Hash>,
        record: arkret_models_identity::ServiceResolutionRecord,
    ) -> crate::ServiceResult<bool> {
        Ok(self
            .persistence
            .service_identity()
            .compare_and_set_resolution(expected_digest, record)
            .await?)
    }

    pub async fn principal_resolution_by_authority_instance(
        &self,
        authority_instance_digest: &arkret_wire::Hash,
    ) -> crate::ServiceResult<Option<soland_storage::PrincipalResolutionRecord>> {
        Ok(self
            .persistence
            .principal_resolutions()
            .by_authority_instance_digest(authority_instance_digest)
            .await?)
    }

    pub async fn principal_resolution_for_realm(
        &self,
        pcr_realm_id: &arkret_wire::RealmId,
    ) -> crate::ServiceResult<Option<soland_storage::PrincipalResolutionRecord>> {
        Ok(self
            .persistence
            .principal_resolutions()
            .for_realm(pcr_realm_id)
            .await?)
    }

    pub async fn compare_and_set_principal_resolution(
        &self,
        expected_current_event_ref: Option<&str>,
        next: soland_storage::PrincipalResolutionRecord,
    ) -> crate::ServiceResult<soland_storage::PrincipalResolutionCasResult> {
        Ok(self
            .persistence
            .principal_resolutions()
            .compare_and_set(expected_current_event_ref, next)
            .await?)
    }

    pub async fn principal_resolution_history(
        &self,
        authority_instance_digest: &arkret_wire::Hash,
        after_event_ref: Option<&str>,
        limit: usize,
    ) -> crate::ServiceResult<Vec<arkret_wire::Event>> {
        Ok(self
            .persistence
            .principal_resolutions()
            .history_newest_first(authority_instance_digest, after_event_ref, limit)
            .await?)
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
            did: "ak:did_core:web:alice.example".to_owned(),
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
                "ak:realm:AehgGDMLc7-ZyfS74e4jHU84lk8I1GrpNU5GJWkxMGV4",
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
        runtime_settings: Arc<dyn RuntimeSettingsPort>,
        runtime_health: Arc<dyn RuntimeHealthPort>,
        sync_cursor_hmac_key: [u8; 32],
    ) -> PersistenceOperationalServices {
        build_persistence_operational_services(
            self.persistence.clone(),
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

/// Let the composition root install the route resolver over the exact same
/// persistence registry as the rest of the application. No route-safety
/// state is copied into an HTTP-local adapter.
#[async_trait::async_trait]
impl soland_storage::ServiceRouteStore for PersistenceHandle {
    async fn list_stored_route_keys(
        &self,
        after: Option<&soland_storage::ServiceRouteStoredKey>,
        limit: usize,
    ) -> PersistenceResult<Vec<soland_storage::ServiceRouteStoredKey>> {
        self.persistence
            .service_routes()
            .list_stored_route_keys(after, limit)
            .await
    }

    async fn notice_states(
        &self,
        service_id: &arkret_wire::DidCoreId,
        service_kind: &str,
        limit: usize,
    ) -> PersistenceResult<Vec<arkret_models_identity::ServiceRouteNoticeState>> {
        self.persistence
            .service_routes()
            .notice_states(service_id, service_kind, limit)
            .await
    }

    async fn handover_mirror_entries(
        &self,
        service_id: &arkret_wire::DidCoreId,
        service_kind: &str,
        limit: usize,
    ) -> PersistenceResult<Vec<soland_storage::ServiceResolutionMirrorEntry>> {
        self.persistence
            .service_routes()
            .handover_mirror_entries(service_id, service_kind, limit)
            .await
    }

    async fn quarantine_evidence(
        &self,
        service_id: &arkret_wire::DidCoreId,
        service_kind: &str,
        limit: usize,
    ) -> PersistenceResult<Vec<soland_storage::ServiceResolutionForkEvidence>> {
        self.persistence
            .service_routes()
            .quarantine_evidence(service_id, service_kind, limit)
            .await
    }

    async fn last_seen_floor(
        &self,
        service_id: &arkret_wire::DidCoreId,
        service_kind: &str,
    ) -> PersistenceResult<Option<arkret_models_identity::ServiceResolutionLastSeenFloor>> {
        self.persistence
            .service_routes()
            .last_seen_floor(service_id, service_kind)
            .await
    }

    async fn advance_last_seen_floor(
        &self,
        floor: arkret_models_identity::ServiceResolutionLastSeenFloor,
    ) -> PersistenceResult<soland_storage::MonotonicRouteWrite> {
        self.persistence
            .service_routes()
            .advance_last_seen_floor(floor)
            .await
    }

    async fn notice_state(
        &self,
        service_id: &arkret_wire::DidCoreId,
        service_kind: &str,
        handover_id: &str,
    ) -> PersistenceResult<Option<arkret_models_identity::ServiceRouteNoticeState>> {
        self.persistence
            .service_routes()
            .notice_state(service_id, service_kind, handover_id)
            .await
    }

    async fn advance_notice_state(
        &self,
        state: arkret_models_identity::ServiceRouteNoticeState,
    ) -> PersistenceResult<soland_storage::MonotonicRouteWrite> {
        self.persistence
            .service_routes()
            .advance_notice_state(state)
            .await
    }

    async fn commit_mirror(
        &self,
        entry: soland_storage::ServiceResolutionMirrorEntry,
    ) -> PersistenceResult<soland_storage::ServiceResolutionMirrorCommit> {
        self.persistence.service_routes().commit_mirror(entry).await
    }

    async fn successor_records(
        &self,
        source_service_id: &arkret_wire::DidCoreId,
        realm_id: &arkret_wire::RealmId,
        target_service_id: &arkret_wire::DidCoreId,
        service_kind: &str,
        after_sequence: u64,
        limit: usize,
    ) -> PersistenceResult<Vec<arkret_models_identity::ServiceResolutionRecord>> {
        self.persistence
            .service_routes()
            .successor_records(
                source_service_id,
                realm_id,
                target_service_id,
                service_kind,
                after_sequence,
                limit,
            )
            .await
    }

    async fn latest_notice(
        &self,
        source_service_id: &arkret_wire::DidCoreId,
        realm_id: &arkret_wire::RealmId,
        target_service_id: &arkret_wire::DidCoreId,
        service_kind: &str,
    ) -> PersistenceResult<Option<arkret_models_identity::ServiceRouteHandoverNotice>> {
        self.persistence
            .service_routes()
            .latest_notice(source_service_id, realm_id, target_service_id, service_kind)
            .await
    }

    async fn quarantine_fork(
        &self,
        evidence: soland_storage::ServiceResolutionForkEvidence,
    ) -> PersistenceResult<()> {
        self.persistence
            .service_routes()
            .quarantine_fork(evidence)
            .await
    }

    async fn is_quarantined(
        &self,
        service_id: &arkret_wire::DidCoreId,
        service_kind: &str,
    ) -> PersistenceResult<bool> {
        self.persistence
            .service_routes()
            .is_quarantined(service_id, service_kind)
            .await
    }

    async fn route_cache(
        &self,
        service_id: &arkret_wire::DidCoreId,
        service_kind: &str,
    ) -> PersistenceResult<Option<arkret_models_identity::ServiceRouteCacheEntry>> {
        self.persistence
            .service_routes()
            .route_cache(service_id, service_kind)
            .await
    }

    async fn put_route_cache(
        &self,
        entry: arkret_models_identity::ServiceRouteCacheEntry,
    ) -> PersistenceResult<()> {
        self.persistence
            .service_routes()
            .put_route_cache(entry)
            .await
    }

    async fn evict_route_cache(
        &self,
        service_id: &arkret_wire::DidCoreId,
        service_kind: &str,
    ) -> PersistenceResult<()> {
        self.persistence
            .service_routes()
            .evict_route_cache(service_id, service_kind)
            .await
    }
}
