//! In-memory implementation of [`PersistenceStore`].

use super::*;

/// In-memory implementation of persistence store.
pub struct SolandMemoryPersistenceStore {
    accounts: MemoryAccountStore,
    account_localparts: MemoryAccountLocalpartStore,
    account_lifecycle: MemoryAccountLifecycleStore,
    sessions: MemorySessionStore,
    account_data: MemoryAccountDataStore,
    contacts: MemoryContactStore,
    invite_receive_policies: MemoryInviteReceivePolicyStore,
    consent_cells: MemoryConsentCellStore,
    direct_conversation_bindings: MemoryDirectConversationBindingStore,
    realm_meta: MemoryRealmMetaStore,
    messages: MemoryMessageStore,
    blobs: MemoryBlobStore,
    devices: MemoryDeviceInventoryStore,
    federation_transactions: MemoryFederationTransactionStore,
    federation_outbox: MemoryFederationOutboxStore,
    federation_frontier_exchange: MemoryFederationFrontierExchangeStore,
    handle_releases: MemoryHandleReleaseStore,
    retention_policies: MemoryRetentionPolicyStore,
    retention_tombstones: MemoryRetentionTombstoneStore,
    organizations: MemoryOrganizationStore,
    organization_policies: MemoryOrganizationPolicyStore,
    realm_organizations: MemoryRealmOrganizationStore,
    realm_moderation_policies: MemoryRealmModerationPolicyStore,
    audit: MemoryAuditStore,
    moderation: MemoryModerationStore,
    federation_operations: MemoryFederationOperationsStore,
    push_devices: MemoryPushDeviceStore,
    push_rules: MemoryPushRuleStore,
    presence: MemoryPresenceStore,
    typing: MemoryTypingStore,
    call_signal_relay: MemoryCallSignalRelayStore,
    read_receipt_relay: MemoryReadReceiptRelayStore,
    push_bridge_cache: MemoryPushBridgeCacheStore,
    policy_documents: MemoryPolicyDocumentStore,
    recovery_policies: MemoryRecoveryPolicyStore,
    recovery_receipts: MemoryRecoveryReceiptStore,
    recovery_sessions: MemoryRecoverySessionStore,
    webvh: MemoryWebvhStore,
    realm_invites: MemoryRealmInviteStore,
    events: MemoryEventStore,
    projection_events: MemoryProjectionEventStore,
    applets: MemoryAppletStore,
    device_messages: MemoryDeviceMessageStore,
    device_keys: MemoryDeviceKeyStore,
    one_time_keys: MemoryOneTimeKeyStore,
    key_backups: MemoryKeyBackupStore,
    multisig_pending: MemoryMultisigPendingStore,
    space_container_projections: MemorySpaceContainerProjectionStore,
    strand_projections: MemoryStrandProjectionStore,
    morph_projections: MemoryMorphProjectionStore,
    // G3.S1: MLS lifecycle stores.
    mls_key_packages: MemoryMlsKeyPackageStore,
    mls_welcomes: MemoryMlsWelcomeStore,
    mls_commits: MemoryMlsCommitStore,
    agent_participation: MemoryAgentParticipationStore,
    agents: MemoryAgentStore,
    notifications: MemoryNotificationStore,
    sync_cursors: MemorySyncCursorStore,
}

impl SolandMemoryPersistenceStore {
    pub fn new() -> Self {
        let account_localparts = MemoryAccountLocalpartStore::new();
        let accounts = MemoryAccountStore::new(account_localparts.shared_data());
        Self {
            accounts,
            account_localparts,
            account_lifecycle: MemoryAccountLifecycleStore::new(),
            sessions: MemorySessionStore::new(),
            account_data: MemoryAccountDataStore::new(),
            contacts: MemoryContactStore::new(),
            invite_receive_policies: MemoryInviteReceivePolicyStore::new(),
            consent_cells: MemoryConsentCellStore::new(),
            direct_conversation_bindings: MemoryDirectConversationBindingStore::new(),
            realm_meta: MemoryRealmMetaStore::new(),
            messages: MemoryMessageStore::new(),
            blobs: MemoryBlobStore::new(),
            devices: MemoryDeviceInventoryStore::new(),
            federation_transactions: MemoryFederationTransactionStore::new(),
            federation_outbox: MemoryFederationOutboxStore::new(),
            federation_frontier_exchange: MemoryFederationFrontierExchangeStore::new(),
            handle_releases: MemoryHandleReleaseStore::new(),
            retention_policies: MemoryRetentionPolicyStore::new(),
            retention_tombstones: MemoryRetentionTombstoneStore::new(),
            organizations: MemoryOrganizationStore::new(),
            organization_policies: MemoryOrganizationPolicyStore::new(),
            realm_organizations: MemoryRealmOrganizationStore::new(),
            realm_moderation_policies: MemoryRealmModerationPolicyStore::new(),
            audit: MemoryAuditStore::new(),
            moderation: MemoryModerationStore::new(),
            federation_operations: MemoryFederationOperationsStore::new(),
            push_devices: MemoryPushDeviceStore::new(),
            push_rules: MemoryPushRuleStore::new(),
            presence: MemoryPresenceStore::new(),
            typing: MemoryTypingStore::new(),
            call_signal_relay: MemoryCallSignalRelayStore::new(),
            read_receipt_relay: MemoryReadReceiptRelayStore::new(),
            push_bridge_cache: MemoryPushBridgeCacheStore::new(),
            policy_documents: MemoryPolicyDocumentStore::new(),
            recovery_policies: MemoryRecoveryPolicyStore::new(),
            recovery_receipts: MemoryRecoveryReceiptStore::new(),
            recovery_sessions: MemoryRecoverySessionStore::new(),
            webvh: MemoryWebvhStore::new(),
            realm_invites: MemoryRealmInviteStore::new(),
            events: MemoryEventStore::new(),
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
            // G3.S1: MLS lifecycle stores.
            mls_key_packages: MemoryMlsKeyPackageStore::new(),
            mls_welcomes: MemoryMlsWelcomeStore::new(),
            mls_commits: MemoryMlsCommitStore::new(),
            agent_participation: MemoryAgentParticipationStore::new(),
            agents: MemoryAgentStore::new(),
            notifications: MemoryNotificationStore::new(),
            sync_cursors: MemorySyncCursorStore::new(),
        }
    }
}

impl Default for SolandMemoryPersistenceStore {
    fn default() -> Self {
        Self::new()
    }
}

impl PersistenceStore for SolandMemoryPersistenceStore {
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

    fn federation_transactions(&self) -> &dyn FederationTransactionStore {
        &self.federation_transactions
    }

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

    fn organization_policies(&self) -> &dyn OrganizationPolicyStore {
        &self.organization_policies
    }

    fn realm_organizations(&self) -> &dyn RealmOrganizationStore {
        &self.realm_organizations
    }

    fn realm_moderation_policies(&self) -> &dyn RealmModerationPolicyStore {
        &self.realm_moderation_policies
    }

    fn audit(&self) -> &dyn AuditStore {
        &self.audit
    }

    fn moderation(&self) -> &dyn ModerationStore {
        &self.moderation
    }

    fn federation_operations(&self) -> &dyn FederationOperationsStore {
        &self.federation_operations
    }

    fn push_devices(&self) -> &dyn PushDeviceStore {
        &self.push_devices
    }

    fn push_rules(&self) -> &dyn PushRuleStore {
        &self.push_rules
    }

    fn presence(&self) -> &dyn PresenceStore {
        &self.presence
    }

    fn typing(&self) -> &dyn TypingStore {
        &self.typing
    }

    fn call_signal_relay(&self) -> &dyn CallSignalRelayStore {
        &self.call_signal_relay
    }

    fn read_receipt_relay(&self) -> &dyn ReadReceiptRelayStore {
        &self.read_receipt_relay
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

    fn recovery_receipts(&self) -> &dyn RecoveryReceiptStore {
        &self.recovery_receipts
    }

    fn recovery_sessions(&self) -> &dyn RecoverySessionStore {
        &self.recovery_sessions
    }

    fn webvh(&self) -> &dyn WebvhStore {
        &self.webvh
    }

    fn realm_invites(&self) -> &dyn RealmInviteStore {
        &self.realm_invites
    }

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

    fn notifications(&self) -> &dyn NotificationStore {
        &self.notifications
    }

    fn sync_cursors(&self) -> &dyn SyncCursorStore {
        &self.sync_cursors
    }
}
