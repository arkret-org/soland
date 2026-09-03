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
use crate::persistence_delivery::build_persistence_delivery_service;
use crate::persistence_events::{PersistenceEventServices, build_persistence_event_services};
use crate::persistence_identity::{
    PersistenceIdentityServices, build_persistence_identity_services,
};
use crate::persistence_operations::{
    PersistenceOperationalServices, build_persistence_operational_services,
};
use crate::projection::ProjectionService;

/// Opaque application-owned handle used by the composition root to install a
/// concrete persistence adapter without exposing the storage registry to HTTP
/// or runtime state.
#[derive(Clone)]
pub struct PersistenceHandle {
    persistence: Arc<dyn PersistenceStore>,
}

impl PersistenceHandle {
    pub fn bind_history_authority_view_cas(
        &self,
        authority_view_cas: Arc<dyn soland_storage::HistoryAuthorityViewCas>,
    ) {
        self.persistence
            .history_response_streams()
            .bind_authority_view_cas(authority_view_cas);
    }

    pub async fn append_account_status_record(
        &self,
        record: &arkret_models_collaboration::account_lifecycle::AccountStatusRecord,
        receipt: &arkret_models_collaboration::account_lifecycle::AccountStatusReceipt,
    ) -> crate::ServiceResult<soland_storage::AccountStatusReplicaAppend> {
        Ok(self
            .persistence
            .account_status_replicas()
            .append(record, receipt)
            .await?)
    }

    pub async fn resolve_account_status_records(
        &self,
        account_authority_id: &str,
        account_id: &arkret_wire::AccountId,
        from_status_seq: u64,
        limit: u16,
    ) -> crate::ServiceResult<
        Vec<arkret_models_collaboration::account_lifecycle::AccountStatusRecord>,
    > {
        Ok(self
            .persistence
            .account_status_replicas()
            .resolve(account_authority_id, account_id, from_status_seq, limit)
            .await?)
    }

    pub async fn current_account_status_record(
        &self,
        account_authority_id: &str,
        account_id: &arkret_wire::AccountId,
    ) -> crate::ServiceResult<
        Option<arkret_models_collaboration::account_lifecycle::AccountStatusRecord>,
    > {
        Ok(self
            .persistence
            .account_status_replicas()
            .current(account_authority_id, account_id)
            .await?)
    }

    pub async fn erasure_pending_account_status_records(
        &self,
        limit: u16,
    ) -> crate::ServiceResult<
        Vec<arkret_models_collaboration::account_lifecycle::AccountStatusRecord>,
    > {
        Ok(self
            .persistence
            .account_status_replicas()
            .erasure_pending(limit)
            .await?)
    }

    pub async fn account_status_receipt(
        &self,
        account_authority_id: &str,
        account_id: &arkret_wire::AccountId,
        status_seq: u64,
    ) -> crate::ServiceResult<
        Option<arkret_models_collaboration::account_lifecycle::AccountStatusReceipt>,
    > {
        Ok(self
            .persistence
            .account_status_replicas()
            .receipt(account_authority_id, account_id, status_seq)
            .await?)
    }

    pub async fn contact_verified_mirror(
        &self,
        target_holder_id: &str,
        request_event_id: &str,
    ) -> crate::ServiceResult<Option<soland_storage::ContactVerifiedMirrorRecord>> {
        Ok(self
            .persistence
            .contact_verified_mirrors()
            .get(target_holder_id, request_event_id)
            .await?)
    }

    pub async fn contact_verified_mirror_by_digest(
        &self,
        target_holder_id: &str,
        request_digest: &str,
    ) -> crate::ServiceResult<Option<soland_storage::ContactVerifiedMirrorRecord>> {
        Ok(self
            .persistence
            .contact_verified_mirrors()
            .get_by_digest(target_holder_id, request_digest)
            .await?)
    }

    pub async fn put_contact_verified_mirror(
        &self,
        record: &soland_storage::ContactVerifiedMirrorRecord,
    ) -> crate::ServiceResult<()> {
        Ok(self
            .persistence
            .contact_verified_mirrors()
            .put_verified(record)
            .await?)
    }

    pub async fn agent_cleanup_intent(
        &self,
        cleanup_intent_digest: &arkret_wire::Hash,
    ) -> crate::ServiceResult<
        Option<
            arkret_models_collaboration::governance::agent_membership_cascade::AgentCleanupRecord,
        >,
    > {
        Ok(self
            .persistence
            .agent_membership_cascades()
            .agent_cleanup_intent(cleanup_intent_digest)
            .await?)
    }

    pub async fn agent_cleanup_intent_for_terminal_event(
        &self,
        controller_terminal_event_id: &arkret_wire::EventId,
    ) -> crate::ServiceResult<
        Option<
            arkret_models_collaboration::governance::agent_membership_cascade::AgentCleanupRecord,
        >,
    > {
        Ok(self
            .persistence
            .agent_membership_cascades()
            .agent_cleanup_intent_for_terminal_event(controller_terminal_event_id)
            .await?)
    }

    pub async fn incomplete_agent_cleanup_intents(
        &self,
        now: chrono::DateTime<chrono::Utc>,
        limit: usize,
    ) -> crate::ServiceResult<
        Vec<arkret_models_collaboration::governance::agent_membership_cascade::AgentCleanupRecord>,
    > {
        Ok(self
            .persistence
            .agent_membership_cascades()
            .incomplete_agent_cleanup_intents(now, limit)
            .await?)
    }

    pub async fn device_revocation_gate_status(
        &self,
        selector: &soland_storage::DeviceRevocationGateSelector,
    ) -> crate::ServiceResult<soland_storage::DeviceRevocationGateStatus> {
        Ok(self
            .persistence
            .device_revocations()
            .gate_status(selector)
            .await?)
    }

    pub async fn device_revocation_targets(
        &self,
        selector: &soland_storage::DeviceRevocationGateSelector,
    ) -> crate::ServiceResult<Vec<soland_storage::DeviceRevocationTargetRecord>> {
        Ok(self
            .persistence
            .device_revocations()
            .list_targets(selector)
            .await?)
    }

    pub async fn linearize_device_revocation_gate(
        &self,
        request: soland_storage::DeviceRevocationGateLinearizationRequest,
    ) -> crate::ServiceResult<soland_storage::DeviceRevocationGateLinearization> {
        Ok(self
            .persistence
            .device_revocations()
            .linearize_gate(request)
            .await?)
    }

    pub async fn pending_device_revocation_cleanup_intents(
        &self,
        limit: usize,
    ) -> crate::ServiceResult<Vec<soland_storage::DeviceRevocationCleanupIntent>> {
        Ok(self
            .persistence
            .device_revocations()
            .pending_cleanup_intents(limit)
            .await?)
    }

    pub async fn complete_device_revocation_material_cleanup(
        &self,
        proposal_digest: &str,
        completed_at: chrono::DateTime<chrono::Utc>,
    ) -> crate::ServiceResult<bool> {
        Ok(self
            .persistence
            .device_revocations()
            .complete_material_cleanup(proposal_digest, completed_at)
            .await?)
    }

    pub async fn complete_device_revocation_mls_obligation_by_event_id(
        &self,
        proposal_event_id: &str,
        completed_at: chrono::DateTime<chrono::Utc>,
    ) -> crate::ServiceResult<bool> {
        Ok(self
            .persistence
            .device_revocations()
            .complete_mls_obligation_by_event_id(proposal_event_id, completed_at)
            .await?)
    }

    pub async fn idempotency_record(
        &self,
        principal_id: &arkret_identifiers::DidCoreId,
        idempotency_key: &str,
    ) -> crate::ServiceResult<Option<soland_storage::IdempotencyRecord>> {
        Ok(self
            .persistence
            .idempotency_keys()
            .get(
                &arkret_wire::ActorId::service(principal_id.clone()),
                crate::jobs::INTERNAL_IDEMPOTENCY_OPERATION,
                idempotency_key,
            )
            .await?)
    }

    pub async fn scoped_idempotency_record(
        &self,
        authenticated_actor: &arkret_wire::ActorId,
        operation_id: &str,
        idempotency_key: &str,
    ) -> crate::ServiceResult<Option<soland_storage::IdempotencyRecord>> {
        Ok(self
            .persistence
            .idempotency_keys()
            .get(authenticated_actor, operation_id, idempotency_key)
            .await?)
    }

    pub async fn record_idempotency(
        &self,
        record: &soland_storage::IdempotencyRecord,
    ) -> crate::ServiceResult<()> {
        self.persistence.idempotency_keys().record(record).await?;
        Ok(())
    }

    pub async fn complete_idempotency_reservation(
        &self,
        expected: &soland_storage::IdempotencyRecord,
        completed: &soland_storage::IdempotencyRecord,
    ) -> crate::ServiceResult<bool> {
        Ok(self
            .persistence
            .idempotency_keys()
            .complete_reservation(expected, completed)
            .await?)
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
        source_id: &arkret_wire::DidCoreId,
        realm_id: &arkret_wire::RealmId,
        target_id: &arkret_wire::DidCoreId,
        service_kind: &str,
        after_sequence: u64,
        limit: usize,
    ) -> crate::ServiceResult<Vec<arkret_models_identity::ServiceResolutionRecord>> {
        Ok(self
            .persistence
            .service_routes()
            .successor_records(
                source_id,
                realm_id,
                target_id,
                service_kind,
                after_sequence,
                limit,
            )
            .await?)
    }

    pub async fn latest_service_route_notice(
        &self,
        source_id: &arkret_wire::DidCoreId,
        realm_id: &arkret_wire::RealmId,
        target_id: &arkret_wire::DidCoreId,
        service_kind: &str,
    ) -> crate::ServiceResult<Option<arkret_models_identity::ServiceRouteHandoverNotice>> {
        Ok(self
            .persistence
            .service_routes()
            .latest_notice(source_id, realm_id, target_id, service_kind)
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

    pub async fn principal_resolution_by_account_id(
        &self,
        account_id: &arkret_wire::AccountId,
    ) -> crate::ServiceResult<Option<soland_storage::PrincipalResolutionRecord>> {
        Ok(self
            .persistence
            .principal_resolutions()
            .by_account_id(account_id)
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
        account_id: &arkret_wire::AccountId,
        after_event_ref: Option<&str>,
        limit: usize,
    ) -> crate::ServiceResult<Vec<arkret_wire::Event>> {
        Ok(self
            .persistence
            .principal_resolutions()
            .history_newest_first(account_id, after_event_ref, limit)
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

    /// Append one successor entry to a DID this deployment hosts, comparing the
    /// current head so a concurrent writer cannot be overwritten.
    ///
    /// `commit_service_registration` is inception-only. Everything after it -
    /// authorizing a delegated assertion key, retiring one, moving an endpoint -
    /// arrives here.
    pub async fn commit_webvh_log_operation(
        &self,
        expected_current_head: Option<String>,
        document: DidDocumentState,
        event: DidLogEvent,
    ) -> crate::ServiceResult<soland_storage::WebvhLogCommitOutcome> {
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
        Ok(self
            .persistence
            .webvh()
            .commit_log_operation(expected_current_head, document, event)
            .await?)
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
            pk: soland_storage::AccountPk(0),
            principal_id: arkret_wire::DidCoreId::new("ak:did_core:web:alice.example".to_owned())
                .expect("demo principal id is canonical"),
            station_id: arkret_wire::DidCoreId::new("ak:did_core:web:server.example".to_owned())
                .expect("demo Station id is canonical"),
            localpart: "alice".to_owned(),
            display_name: Some("Alice Example".to_owned()),
            bio: None,
            avatar_blob_ref: None,
            created_at: now,
        };
        self.persistence.accounts().put(&account).await?;
        self.persistence
            .realm_meta()
            .put(
                "ak:realm:AezgkQb6OtCT0VrUyihcuY6ih8wmyafofZG6EmHBpM7e",
                &soland_storage::RealmMetaRecord {
                    owner: arkret_wire::ActorId::account(arkret_wire::AccountId::new(
                        account.principal_id,
                        account.station_id,
                    ))
                    .to_string(),
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

    /// Durable member-identity registry store (accepted
    /// `ak.member.identity.update` events plus the local handle-claim evidence
    /// cache). `AppState` writes accepted projections through to this store
    /// and rebuilds its in-memory registry from it during startup hydration.
    pub fn member_identity_store(&self) -> &dyn soland_storage::MemberIdentityStore {
        self.persistence.member_identity()
    }

    pub fn governance_dependency_store(&self) -> &dyn soland_storage::GovernanceDependencyStore {
        self.persistence.governance_dependencies()
    }

    /// Server-internal seen-source ledger behind the invite quarantine
    /// new-source quota (`identity/consent-model.md` section 6.1.1.4). It is
    /// reachable only from the admission chokepoint and from account erasure;
    /// no operation projects it onto the wire.
    pub fn invite_new_source_ledger_store(
        &self,
    ) -> &dyn soland_storage::InviteNewSourceLedgerStore {
        self.persistence.invite_new_source_ledger()
    }

    pub fn event_services(&self) -> PersistenceEventServices {
        build_persistence_event_services(self.persistence.clone())
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

    pub fn governance_history_service(
        &self,
    ) -> crate::governance_history::GovernanceHistoryService {
        crate::governance_history::GovernanceHistoryService::new(self.persistence.clone())
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

    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn shared_for_tests(&self) -> Arc<dyn PersistenceStore> {
        self.persistence.clone()
    }
}

#[async_trait::async_trait]
impl soland_storage::DeviceRevocationStore for PersistenceHandle {
    fn bind_control_event_store(
        &self,
        control_events: Arc<dyn arkret_state::state::ControlEventStore>,
    ) {
        self.persistence
            .device_revocations()
            .bind_control_event_store(control_events);
    }

    async fn gate_status(
        &self,
        selector: &soland_storage::DeviceRevocationGateSelector,
    ) -> PersistenceResult<soland_storage::DeviceRevocationGateStatus> {
        self.persistence
            .device_revocations()
            .gate_status(selector)
            .await
    }

    async fn list_targets(
        &self,
        selector: &soland_storage::DeviceRevocationGateSelector,
    ) -> PersistenceResult<Vec<soland_storage::DeviceRevocationTargetRecord>> {
        self.persistence
            .device_revocations()
            .list_targets(selector)
            .await
    }

    async fn linearize_gate(
        &self,
        request: soland_storage::DeviceRevocationGateLinearizationRequest,
    ) -> PersistenceResult<soland_storage::DeviceRevocationGateLinearization> {
        self.persistence
            .device_revocations()
            .linearize_gate(request)
            .await
    }

    async fn mark_rejected(
        &self,
        proposal_digest: &str,
        terminal_decision: &arkret_wire::ControlProposalDecision,
    ) -> PersistenceResult<bool> {
        self.persistence
            .device_revocations()
            .mark_rejected(proposal_digest, terminal_decision)
            .await
    }

    async fn commit_decision(
        &self,
        proposal_digest: &str,
        decision: &arkret_wire::ControlProposalDecision,
        policy: arkret_wire::ControlProposalDecisionPolicy,
    ) -> PersistenceResult<soland_storage::ControlProposalDecisionCommitOutcome> {
        self.persistence
            .device_revocations()
            .commit_decision(proposal_digest, decision, policy)
            .await
    }

    async fn mark_sealed(
        &self,
        proposal_digest: &str,
        covering_seal_id: &str,
        sealed_at: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<bool> {
        self.persistence
            .device_revocations()
            .mark_sealed(proposal_digest, covering_seal_id, sealed_at)
            .await
    }

    async fn pending_cleanup_intents(
        &self,
        limit: usize,
    ) -> PersistenceResult<Vec<soland_storage::DeviceRevocationCleanupIntent>> {
        self.persistence
            .device_revocations()
            .pending_cleanup_intents(limit)
            .await
    }

    async fn complete_material_cleanup(
        &self,
        proposal_digest: &str,
        completed_at: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<bool> {
        self.persistence
            .device_revocations()
            .complete_material_cleanup(proposal_digest, completed_at)
            .await
    }

    async fn complete_mls_obligation(
        &self,
        proposal_digest: &str,
        completed_at: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<bool> {
        self.persistence
            .device_revocations()
            .complete_mls_obligation(proposal_digest, completed_at)
            .await
    }

    async fn complete_mls_obligation_by_event_id(
        &self,
        proposal_event_id: &str,
        completed_at: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<bool> {
        self.persistence
            .device_revocations()
            .complete_mls_obligation_by_event_id(proposal_event_id, completed_at)
            .await
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

    async fn publish_route_cache(
        &self,
        floor: arkret_models_identity::ServiceResolutionLastSeenFloor,
        entry: arkret_models_identity::ServiceRouteCacheEntry,
    ) -> PersistenceResult<soland_storage::MonotonicRouteWrite> {
        self.persistence
            .service_routes()
            .publish_route_cache(floor, entry)
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
        source_id: &arkret_wire::DidCoreId,
        realm_id: &arkret_wire::RealmId,
        target_id: &arkret_wire::DidCoreId,
        service_kind: &str,
        after_sequence: u64,
        limit: usize,
    ) -> PersistenceResult<Vec<arkret_models_identity::ServiceResolutionRecord>> {
        self.persistence
            .service_routes()
            .successor_records(
                source_id,
                realm_id,
                target_id,
                service_kind,
                after_sequence,
                limit,
            )
            .await
    }

    async fn latest_notice(
        &self,
        source_id: &arkret_wire::DidCoreId,
        realm_id: &arkret_wire::RealmId,
        target_id: &arkret_wire::DidCoreId,
        service_kind: &str,
    ) -> PersistenceResult<Option<arkret_models_identity::ServiceRouteHandoverNotice>> {
        self.persistence
            .service_routes()
            .latest_notice(source_id, realm_id, target_id, service_kind)
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
