//! In-memory implementation of [`PersistenceStore`].

use soland_storage::ProposalMemberReceiptStore;

use super::{
    AccountDataStore, AccountLifecycleStore, AccountLocalpartStore, AccountRecord, AccountStore,
    AgentParticipationStore, AgentStore, AppletStore, Arc, AuditStore, BTreeMap, BlobStore,
    ConsentCellStore, ContactStore, DeviceInventoryStore, DeviceKeyStore, DeviceMessageStore,
    DevicePairingAuthorizationCommit, DevicePairingCommitUnitOfWork, DevicePairingStore,
    DirectConversationBindingStore, EventStore, FederationFrontierExchangeStore,
    FederationOperationsStore, FederationOutboxStore, HandleReleaseStore, IdempotencyStore,
    InviteLocatorStore, InviteReceivePolicyStore, KeyBackupStore, MemoryAccountDataStore,
    MemoryAccountLifecycleStore, MemoryAccountLocalpartStore, MemoryAccountStore,
    MemoryAgentParticipationStore, MemoryAgentStore, MemoryAppletStore, MemoryAuditStore,
    MemoryBlobStore, MemoryConsentCellStore, MemoryContactStore, MemoryDeviceInventoryStore,
    MemoryDeviceKeyStore, MemoryDeviceMessageStore, MemoryDevicePairingStore,
    MemoryDirectConversationBindingStore, MemoryEventStore, MemoryFederationFrontierExchangeStore,
    MemoryFederationOperationsStore, MemoryFederationOutboxStore, MemoryHandleReleaseStore,
    MemoryIdempotencyStore, MemoryInviteLocatorStore, MemoryInviteReceivePolicyStore,
    MemoryJoinApplicationStore, MemoryKeyBackupStore, MemoryMessageStore, MemoryMlsCommitStore,
    MemoryMlsKeyPackageStore, MemoryMlsWelcomeStore, MemoryModerationStore,
    MemoryMorphProjectionStore, MemoryMultisigPendingStore, MemoryNotificationStore,
    MemoryOneTimeKeyStore, MemoryOrganizationPolicyStore, MemoryOrganizationRegistrationStore,
    MemoryOrganizationStore, MemoryPolicyDocumentStore, MemoryProjectionEventStore,
    MemoryPublicationEvidenceStore, MemoryPushBridgeCacheStore, MemoryPushDeviceStore,
    MemoryRealmInviteStore, MemoryRealmMetaStore, MemoryRealmModerationPolicyStore,
    MemoryRealmOrganizationStatementStore, MemoryRealmOrganizationStore, MemoryRecoveryPolicyStore,
    MemoryRecoverySessionStore, MemoryRetentionPolicyStore, MemoryRetentionTombstoneStore,
    MemorySecurityTransactionStore, MemoryServiceIdentityStore, MemorySessionStore,
    MemorySidecarStore, MemorySignalRelayStore, MemorySpaceContainerProjectionStore,
    MemoryStrandProjectionStore, MemorySyncCursorStore, MemoryWebsocketAuthStore, MemoryWebvhStore,
    MessageStore, MlsCommitStore, MlsKeyPackageStore, MlsWelcomeStore, ModerationStore,
    MorphProjectionStore, MultisigPendingStore, Mutex, NotificationStore, OneTimeKeyStore,
    OrganizationPolicyStore, OrganizationRegistrationStore, OrganizationStore, PersistenceStore,
    PolicyDocumentStore, ProjectionEventStore, PublicationEvidenceStore, PushBridgeCacheStore,
    PushDeviceStore, RealmInviteStore, RealmMetaRecord, RealmMetaStore, RealmModerationPolicyStore,
    RealmOrganizationStatementStore, RealmOrganizationStore, RecoveryPolicyStore,
    RecoverySessionStore, RetentionPolicyStore, RetentionTombstoneStore, SecurityTransactionStore,
    ServiceIdentityStore, SessionStore, SidecarStore, SignalRelayStore,
    SpaceContainerProjectionStore, StrandProjectionStore, SyncCursorStore, WebsocketAuthStore,
    WebvhStore,
};
#[cfg(feature = "fault-injection")]
use crate::FaultInjector;
use crate::MemoryProposalMemberReceiptStore;

/// In-memory implementation of persistence store.
pub struct SolandMemoryPersistenceStore {
    #[cfg(feature = "fault-injection")]
    pub(crate) fault_injector: Arc<FaultInjector>,
    accounts: MemoryAccountStore,
    account_localparts: MemoryAccountLocalpartStore,
    account_lifecycle: MemoryAccountLifecycleStore,
    sessions: MemorySessionStore,
    account_data: MemoryAccountDataStore,
    contacts: MemoryContactStore,
    invite_receive_policies: MemoryInviteReceivePolicyStore,
    invite_locators: MemoryInviteLocatorStore,
    consent_cells: MemoryConsentCellStore,
    direct_conversation_bindings: MemoryDirectConversationBindingStore,
    realm_meta: MemoryRealmMetaStore,
    messages: MemoryMessageStore,
    blobs: MemoryBlobStore,
    devices: MemoryDeviceInventoryStore,
    device_pairings: MemoryDevicePairingStore,
    pub(crate) federation_outbox: MemoryFederationOutboxStore,
    federation_frontier_exchange: MemoryFederationFrontierExchangeStore,
    handle_releases: MemoryHandleReleaseStore,
    retention_policies: MemoryRetentionPolicyStore,
    retention_tombstones: MemoryRetentionTombstoneStore,
    organizations: MemoryOrganizationStore,
    organization_registrations: MemoryOrganizationRegistrationStore,
    organization_policies: MemoryOrganizationPolicyStore,
    realm_organizations: MemoryRealmOrganizationStore,
    realm_organization_statements: MemoryRealmOrganizationStatementStore,
    realm_moderation_policies: MemoryRealmModerationPolicyStore,
    join_applications: MemoryJoinApplicationStore,
    audit: MemoryAuditStore,
    moderation: MemoryModerationStore,
    federation_operations: MemoryFederationOperationsStore,
    push_devices: MemoryPushDeviceStore,
    signal_relay: MemorySignalRelayStore,
    push_bridge_cache: MemoryPushBridgeCacheStore,
    policy_documents: MemoryPolicyDocumentStore,
    recovery_policies: MemoryRecoveryPolicyStore,
    recovery_sessions: MemoryRecoverySessionStore,
    security_transactions: MemorySecurityTransactionStore,
    webvh: MemoryWebvhStore,
    service_identity: MemoryServiceIdentityStore,
    realm_invites: MemoryRealmInviteStore,
    pub(crate) events: MemoryEventStore,
    pub(crate) projection_events: MemoryProjectionEventStore,
    pub(crate) applets: MemoryAppletStore,
    device_messages: MemoryDeviceMessageStore,
    device_keys: MemoryDeviceKeyStore,
    one_time_keys: MemoryOneTimeKeyStore,
    key_backups: MemoryKeyBackupStore,
    multisig_pending: MemoryMultisigPendingStore,
    space_container_projections: MemorySpaceContainerProjectionStore,
    strand_projections: MemoryStrandProjectionStore,
    morph_projections: MemoryMorphProjectionStore,
    publication_evidence: MemoryPublicationEvidenceStore,
    // G3.S1: MLS lifecycle stores.
    mls_key_packages: MemoryMlsKeyPackageStore,
    mls_welcomes: MemoryMlsWelcomeStore,
    mls_commits: MemoryMlsCommitStore,
    agent_participation: MemoryAgentParticipationStore,
    agents: MemoryAgentStore,
    sidecars: MemorySidecarStore,
    notifications: MemoryNotificationStore,
    sync_cursors: MemorySyncCursorStore,
    pub(crate) idempotency_keys: MemoryIdempotencyStore,
    proposal_member_receipts: MemoryProposalMemberReceiptStore,
    websocket_auth: MemoryWebsocketAuthStore,
}

impl SolandMemoryPersistenceStore {
    pub fn new() -> Self {
        #[cfg(feature = "fault-injection")]
        let fault_injector = Arc::new(FaultInjector::default());
        let account_localparts = MemoryAccountLocalpartStore::new();
        let accounts = MemoryAccountStore::new(account_localparts.shared_data());
        let devices = MemoryDeviceInventoryStore::new();
        let publication_evidence_data = Arc::new(Mutex::new(BTreeMap::new()));
        let federation_outbox = MemoryFederationOutboxStore::new();
        let events = MemoryEventStore::with_devices(
            devices.shared_data(),
            publication_evidence_data.clone(),
            federation_outbox.data.clone(),
        );
        let recovery_sessions = MemoryRecoverySessionStore::new();
        let security_transactions =
            MemorySecurityTransactionStore::new(recovery_sessions.shared_data());
        Self {
            #[cfg(feature = "fault-injection")]
            fault_injector: fault_injector.clone(),
            accounts,
            account_localparts,
            account_lifecycle: MemoryAccountLifecycleStore::new(),
            sessions: MemorySessionStore::new(),
            account_data: MemoryAccountDataStore::new(),
            contacts: MemoryContactStore::new(),
            invite_receive_policies: MemoryInviteReceivePolicyStore::new(),
            invite_locators: MemoryInviteLocatorStore::new(),
            consent_cells: MemoryConsentCellStore::new(),
            direct_conversation_bindings: MemoryDirectConversationBindingStore::new(),
            realm_meta: MemoryRealmMetaStore::new(),
            messages: MemoryMessageStore::new(),
            blobs: MemoryBlobStore::new(),
            devices,
            device_pairings: MemoryDevicePairingStore::new(),
            federation_outbox,
            federation_frontier_exchange: MemoryFederationFrontierExchangeStore::new(),
            handle_releases: MemoryHandleReleaseStore::new(),
            retention_policies: MemoryRetentionPolicyStore::new(),
            retention_tombstones: MemoryRetentionTombstoneStore::new(),
            organizations: MemoryOrganizationStore::new(),
            organization_registrations: MemoryOrganizationRegistrationStore::new(),
            organization_policies: MemoryOrganizationPolicyStore::new(),
            realm_organizations: MemoryRealmOrganizationStore::new(),
            realm_organization_statements: MemoryRealmOrganizationStatementStore::new(),
            realm_moderation_policies: MemoryRealmModerationPolicyStore::new(),
            join_applications: MemoryJoinApplicationStore::new(),
            audit: MemoryAuditStore::new(),
            moderation: MemoryModerationStore::new(),
            federation_operations: MemoryFederationOperationsStore::new(),
            push_devices: MemoryPushDeviceStore::new(),
            signal_relay: MemorySignalRelayStore::new(),
            push_bridge_cache: MemoryPushBridgeCacheStore::new(),
            policy_documents: MemoryPolicyDocumentStore::new(),
            recovery_policies: MemoryRecoveryPolicyStore::new(),
            recovery_sessions,
            security_transactions,
            webvh: {
                #[cfg(feature = "fault-injection")]
                {
                    MemoryWebvhStore::with_fault_injector(fault_injector.clone())
                }
                #[cfg(not(feature = "fault-injection"))]
                {
                    MemoryWebvhStore::new()
                }
            },
            service_identity: MemoryServiceIdentityStore::new(),
            realm_invites: MemoryRealmInviteStore::new(),
            events,
            projection_events: MemoryProjectionEventStore::new(),
            applets: MemoryAppletStore::new(),
            device_messages: MemoryDeviceMessageStore::new(),
            device_keys: MemoryDeviceKeyStore::new(),
            one_time_keys: MemoryOneTimeKeyStore::new(),
            key_backups: MemoryKeyBackupStore::new(),
            multisig_pending: MemoryMultisigPendingStore::new(),
            space_container_projections: MemorySpaceContainerProjectionStore::new(),
            strand_projections: MemoryStrandProjectionStore::new(),
            morph_projections: MemoryMorphProjectionStore::new(),
            publication_evidence: MemoryPublicationEvidenceStore::with_data(
                publication_evidence_data,
            ),
            // G3.S1: MLS lifecycle stores.
            mls_key_packages: MemoryMlsKeyPackageStore::new(),
            mls_welcomes: MemoryMlsWelcomeStore::new(),
            mls_commits: MemoryMlsCommitStore::new(),
            agent_participation: MemoryAgentParticipationStore::new(),
            agents: {
                #[cfg(feature = "fault-injection")]
                {
                    MemoryAgentStore::with_fault_injector(fault_injector.clone())
                }
                #[cfg(not(feature = "fault-injection"))]
                {
                    MemoryAgentStore::new()
                }
            },
            sidecars: MemorySidecarStore::new(),
            notifications: MemoryNotificationStore::new(),
            sync_cursors: MemorySyncCursorStore::new(),
            idempotency_keys: {
                #[cfg(feature = "fault-injection")]
                {
                    MemoryIdempotencyStore::with_fault_injector(fault_injector.clone())
                }
                #[cfg(not(feature = "fault-injection"))]
                {
                    MemoryIdempotencyStore::new()
                }
            },
            proposal_member_receipts: MemoryProposalMemberReceiptStore::new(),
            websocket_auth: MemoryWebsocketAuthStore::new(),
        }
    }

    pub fn new_with_demo_data() -> Self {
        let store = Self::new();
        let now = chrono::Utc::now();
        store.accounts.seed(AccountRecord {
            id: "ak:account:0196419b-0000-7000-8000-000000000001".to_owned(),
            did: "did:web:alice.example".to_owned(),
            localpart: "alice".to_owned(),
            display_name: Some("Alice Example".to_owned()),
            bio: None,
            avatar_blob_ref: None,
            created_at: now,
        });
        store.realm_meta.seed(
            "ak:realm:0196419b-0000-8000-8000-000000000000",
            RealmMetaRecord {
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
                plaintext_visible_services: std::collections::BTreeSet::new(),
                plaintext_visible_service_classes: std::collections::BTreeMap::new(),
                minimal_metadata_realm: false,
                aad_visibility_ceiling: Default::default(),
                created_at: now,
                updated_at: now,
            },
        );
        store
    }

    #[cfg(feature = "fault-injection")]
    pub fn fault_injector(&self) -> Arc<FaultInjector> {
        self.fault_injector.clone()
    }
}

impl Default for SolandMemoryPersistenceStore {
    fn default() -> Self {
        Self::new()
    }
}

impl soland_storage::IdentityStoreRegistry for SolandMemoryPersistenceStore {
    fn accounts(&self) -> &dyn AccountStore {
        &self.accounts
    }

    fn account_localparts(&self) -> &dyn AccountLocalpartStore {
        &self.account_localparts
    }

    fn account_lifecycle(&self) -> &dyn AccountLifecycleStore {
        &self.account_lifecycle
    }

    fn sessions(&self) -> &dyn SessionStore {
        &self.sessions
    }

    fn account_data(&self) -> &dyn AccountDataStore {
        &self.account_data
    }

    fn contacts(&self) -> &dyn ContactStore {
        &self.contacts
    }

    fn invite_receive_policies(&self) -> &dyn InviteReceivePolicyStore {
        &self.invite_receive_policies
    }

    fn invite_locators(&self) -> &dyn InviteLocatorStore {
        &self.invite_locators
    }

    fn consent_cells(&self) -> &dyn ConsentCellStore {
        &self.consent_cells
    }

    fn direct_conversation_bindings(&self) -> &dyn DirectConversationBindingStore {
        &self.direct_conversation_bindings
    }

    fn realm_meta(&self) -> &dyn RealmMetaStore {
        &self.realm_meta
    }

    fn messages(&self) -> &dyn MessageStore {
        &self.messages
    }

    fn blobs(&self) -> &dyn BlobStore {
        &self.blobs
    }

    fn devices(&self) -> &dyn DeviceInventoryStore {
        &self.devices
    }

    fn device_pairings(&self) -> &dyn DevicePairingStore {
        &self.device_pairings
    }
}

#[async_trait::async_trait]
impl DevicePairingCommitUnitOfWork for SolandMemoryPersistenceStore {
    async fn commit_device_pairing_authorization(
        &self,
        commit: DevicePairingAuthorizationCommit,
    ) -> soland_storage::PersistenceResult<bool> {
        let mut pairings = self.device_pairings.data.lock();
        let Some(pairing) = pairings.get_mut(&commit.device_pairing_request_id) else {
            return Ok(false);
        };
        if pairing.state != "pending_authorization"
            || pairing.expires_at <= commit.changed_at
            || pairing.pairing_code != commit.pairing_code
            || pairing.new_device_pubkey != commit.new_device_pubkey
            || commit.device.actor != commit.authorized_by_actor_id
        {
            return Ok(false);
        }

        let devices = self.devices.shared_data();
        let mut devices = devices.lock();
        devices.insert(
            (commit.device.actor.clone(), commit.device.device_id.clone()),
            commit.device.clone(),
        );
        pairing.state = "authorized".to_owned();
        pairing.device_id = Some(commit.device.device_id);
        pairing.authorized_by_actor_id = Some(commit.authorized_by_actor_id);
        pairing.authorized_event_ref = Some(commit.authorized_event_ref);
        Ok(true)
    }
}

impl soland_storage::FederationGovernanceStoreRegistry for SolandMemoryPersistenceStore {
    fn federation_outbox(&self) -> &dyn FederationOutboxStore {
        &self.federation_outbox
    }

    fn federation_frontier_exchange(&self) -> &dyn FederationFrontierExchangeStore {
        &self.federation_frontier_exchange
    }

    fn handle_releases(&self) -> &dyn HandleReleaseStore {
        &self.handle_releases
    }

    fn retention_policies(&self) -> &dyn RetentionPolicyStore {
        &self.retention_policies
    }

    fn retention_tombstones(&self) -> &dyn RetentionTombstoneStore {
        &self.retention_tombstones
    }

    fn organizations(&self) -> &dyn OrganizationStore {
        &self.organizations
    }

    fn organization_registrations(&self) -> &dyn OrganizationRegistrationStore {
        &self.organization_registrations
    }

    fn organization_policies(&self) -> &dyn OrganizationPolicyStore {
        &self.organization_policies
    }

    fn realm_organizations(&self) -> &dyn RealmOrganizationStore {
        &self.realm_organizations
    }

    fn realm_organization_statements(&self) -> &dyn RealmOrganizationStatementStore {
        &self.realm_organization_statements
    }

    fn realm_moderation_policies(&self) -> &dyn RealmModerationPolicyStore {
        &self.realm_moderation_policies
    }

    fn audit(&self) -> &dyn AuditStore {
        &self.audit
    }

    fn join_applications(&self) -> &dyn soland_storage::JoinApplicationStore {
        &self.join_applications
    }
}

impl soland_storage::DeliveryPolicyStoreRegistry for SolandMemoryPersistenceStore {
    fn moderation(&self) -> &dyn ModerationStore {
        &self.moderation
    }

    fn federation_operations(&self) -> &dyn FederationOperationsStore {
        &self.federation_operations
    }

    fn push_devices(&self) -> &dyn PushDeviceStore {
        &self.push_devices
    }

    fn signal_relay(&self) -> &dyn SignalRelayStore {
        &self.signal_relay
    }

    fn push_bridge_cache(&self) -> &dyn PushBridgeCacheStore {
        &self.push_bridge_cache
    }

    fn policy_documents(&self) -> &dyn PolicyDocumentStore {
        &self.policy_documents
    }

    fn recovery_policies(&self) -> &dyn RecoveryPolicyStore {
        &self.recovery_policies
    }

    fn recovery_sessions(&self) -> &dyn RecoverySessionStore {
        &self.recovery_sessions
    }

    fn security_transactions(&self) -> &dyn SecurityTransactionStore {
        &self.security_transactions
    }

    fn webvh(&self) -> &dyn WebvhStore {
        &self.webvh
    }

    fn service_identity(&self) -> &dyn ServiceIdentityStore {
        &self.service_identity
    }

    fn realm_invites(&self) -> &dyn RealmInviteStore {
        &self.realm_invites
    }
}

impl soland_storage::EventProjectionStoreRegistry for SolandMemoryPersistenceStore {
    fn events(&self) -> &dyn EventStore {
        &self.events
    }

    fn projection_events(&self) -> &dyn ProjectionEventStore {
        &self.projection_events
    }

    fn applets(&self) -> &dyn AppletStore {
        &self.applets
    }

    fn device_messages(&self) -> &dyn DeviceMessageStore {
        &self.device_messages
    }

    fn device_keys(&self) -> &dyn DeviceKeyStore {
        &self.device_keys
    }

    fn one_time_keys(&self) -> &dyn OneTimeKeyStore {
        &self.one_time_keys
    }

    fn key_backups(&self) -> &dyn KeyBackupStore {
        &self.key_backups
    }

    fn multisig_pending(&self) -> &dyn MultisigPendingStore {
        &self.multisig_pending
    }

    fn space_container_projections(&self) -> &dyn SpaceContainerProjectionStore {
        &self.space_container_projections
    }

    fn strand_projections(&self) -> &dyn StrandProjectionStore {
        &self.strand_projections
    }

    fn morph_projections(&self) -> &dyn MorphProjectionStore {
        &self.morph_projections
    }

    fn publication_evidence(&self) -> &dyn PublicationEvidenceStore {
        &self.publication_evidence
    }
}

impl soland_storage::MlsAgentStoreRegistry for SolandMemoryPersistenceStore {
    // G3.S1: MLS lifecycle stores.
    fn mls_key_packages(&self) -> &dyn MlsKeyPackageStore {
        &self.mls_key_packages
    }

    fn mls_welcomes(&self) -> &dyn MlsWelcomeStore {
        &self.mls_welcomes
    }

    fn mls_commits(&self) -> &dyn MlsCommitStore {
        &self.mls_commits
    }

    fn agent_participation(&self) -> &dyn AgentParticipationStore {
        &self.agent_participation
    }

    fn agents(&self) -> &dyn AgentStore {
        &self.agents
    }

    fn sidecars(&self) -> &dyn SidecarStore {
        &self.sidecars
    }

    fn notifications(&self) -> &dyn NotificationStore {
        &self.notifications
    }
}

impl soland_storage::SyncStoreRegistry for SolandMemoryPersistenceStore {
    fn sync_cursors(&self) -> &dyn SyncCursorStore {
        &self.sync_cursors
    }

    fn idempotency_keys(&self) -> &dyn IdempotencyStore {
        &self.idempotency_keys
    }

    fn proposal_member_receipts(&self) -> &dyn ProposalMemberReceiptStore {
        &self.proposal_member_receipts
    }

    fn websocket_auth(&self) -> &dyn WebsocketAuthStore {
        &self.websocket_auth
    }
}

impl PersistenceStore for SolandMemoryPersistenceStore {}

#[cfg(test)]
mod device_pairing_commit_tests {
    use soland_storage::{DeviceInventoryRecord, DevicePairingRecord};

    use super::*;

    #[tokio::test]
    async fn staged_pairing_commit_is_atomic_and_strictly_bound() {
        let store = SolandMemoryPersistenceStore::new();
        let now = chrono::Utc::now();
        let request_id = "device_pairing_request:01964137-0000-7000-8000-0000000000c1".to_owned();
        let public_key = serde_json::json!({
            "algorithm": "Ed25519",
            "key": "z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH",
            "kid": "ak:device:01964137-0000-7000-8000-0000000000b2",
            "kty": "OKP"
        });
        store
            .device_pairings
            .put(DevicePairingRecord::new(
                request_id.clone(),
                "7H2K9M4Q".to_owned(),
                public_key.clone(),
                "AAAAAAAAAAAAAAAAAAAAAA".to_owned(),
                "https://account.example".to_owned(),
                "BBBBBBBBBBBBBBBBBBBBBB".to_owned(),
                None,
                None,
                "pending_authorization".to_owned(),
                now,
                now + chrono::Duration::minutes(10),
            ))
            .await
            .unwrap();

        let device = DeviceInventoryRecord {
            actor: "did:web:example.com:alice".to_owned(),
            device_id: "ak:device:01964137-0000-7000-8000-0000000000b2".to_owned(),
            display_name: None,
            verification_state: "verified".to_owned(),
            payload: serde_json::json!({"authorized": true}),
            created_at: now,
            updated_at: now,
            revoked_at: None,
        };
        let commit = |pairing_code: &str| DevicePairingAuthorizationCommit {
            device_pairing_request_id: request_id.clone(),
            pairing_code: pairing_code.to_owned(),
            new_device_pubkey: public_key.clone(),
            device: device.clone(),
            authorized_by_actor_id: device.actor.clone(),
            authorized_event_ref: "ak:event:01964137-0000-8000-8000-00000000d001".to_owned(),
            changed_at: now,
        };

        assert!(
            !store
                .commit_device_pairing_authorization(commit("8J3L5N7P"))
                .await
                .unwrap()
        );
        assert!(
            store
                .devices
                .get(&device.actor, &device.device_id)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            store
                .commit_device_pairing_authorization(commit("7H2K9M4Q"))
                .await
                .unwrap()
        );
        assert!(
            store
                .devices
                .get(&device.actor, &device.device_id)
                .await
                .unwrap()
                .is_some()
        );
        let pairing = store
            .device_pairings
            .get_by_request_id(&request_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(pairing.state, "authorized");
        assert_eq!(
            pairing.device_id.as_deref(),
            Some(device.device_id.as_str())
        );
    }
}
