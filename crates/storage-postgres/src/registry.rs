//! PostgreSQL-backed implementation of [`PersistenceStore`].

use std::sync::Arc;

use soland_storage::*;

use crate::*;

/// PostgreSQL-backed persistence store for durable projections with shipped Pg
/// tables. Stores without a Pg implementation still delegate to the embedded
/// memory fallback, but contact, consent-cell, invite-receive-policy, and
/// direct-conversation binding accessors are wired to Pg stores.
pub struct PgPersistenceStore {
    event_commits: PgEventCommitUnitOfWork,
    accounts: PgAccountStore,
    account_localparts: PgAccountLocalpartStore,
    account_lifecycle: PgAccountLifecycleStore,
    sessions: PgSessionStore,
    account_data: PgAccountDataStore,
    contacts: PgContactStore,
    invite_receive_policies: PgInviteReceivePolicyStore,
    invite_locators: PgInviteLocatorStore,
    join_applications: PgJoinApplicationStore,
    consent_cells: PgConsentCellStore,
    direct_conversation_bindings: PgDirectConversationBindingStore,
    blobs: PgBlobStore,
    devices: PgDeviceInventoryStore,
    device_pairings: PgDevicePairingStore,
    federation_transactions: PgFederationTransactionStore,
    federation_outbox: PgFederationOutboxStore,
    federation_frontier_exchange: PgFederationFrontierExchangeStore,
    handle_releases: PgHandleReleaseStore,
    retention_policies: PgRetentionPolicyStore,
    retention_tombstones: PgRetentionTombstoneStore,
    organizations: PgOrganizationStore,
    organization_policies: PgOrganizationPolicyStore,
    realm_organizations: PgRealmOrganizationStore,
    realm_organization_statements: PgRealmOrganizationStatementStore,
    realm_moderation_policies: PgRealmModerationPolicyStore,
    push_bridge_cache: PgPushBridgeCacheStore,
    multisig_pending: PgMultisigPendingStore,
    audit: PgAuditStore,
    push_devices: PgPushDeviceStore,
    events: PgEventStore,
    federation_operations: PgFederationOperationsStore,
    moderation: PgModerationStore,
    presence: PgPresenceStore,
    call_signal_relay: PgCallSignalRelayStore,
    read_receipt_relay: PgReadReceiptRelayStore,
    webvh: PgWebvhStore,
    service_identity: PgServiceIdentityStore,
    realm_invites: PgRealmInviteStore,
    key_backups: PgKeyBackupStore,
    policy_documents: PgPolicyDocumentStore,
    recovery_policies: PgRecoveryPolicyStore,
    recovery_receipts: PgRecoveryReceiptStore,
    recovery_sessions: PgRecoverySessionStore,
    space_container_projections: PgSpaceContainerProjectionStore,
    strand_projections: PgStrandProjectionStore,
    morph_projections: PgMorphProjectionStore,
    projection_events: PgProjectionEventStore,
    applets: PgAppletStore,
    device_messages: PgDeviceMessageStore,
    mls_key_packages: PgMlsKeyPackageStore,
    mls_welcomes: PgMlsWelcomeStore,
    mls_commits: PgMlsCommitStore,
    agent_participation: PgAgentParticipationStore,
    agents: PgAgentStore,
    sidecars: PgSidecarStore,
    notifications: PgNotificationStore,
    sync_cursors: PgSyncCursorStore,
    idempotency_keys: PgIdempotencyStore,
    fallback: Arc<dyn PersistenceStore>,
}

impl PgPersistenceStore {
    pub fn new(pool: PgPool, fallback: Arc<dyn PersistenceStore>) -> Self {
        Self {
            event_commits: PgEventCommitUnitOfWork::new(pool.clone()),
            accounts: PgAccountStore { pool: pool.clone() },
            account_localparts: PgAccountLocalpartStore { pool: pool.clone() },
            account_lifecycle: PgAccountLifecycleStore { pool: pool.clone() },
            sessions: PgSessionStore { pool: pool.clone() },
            account_data: PgAccountDataStore { pool: pool.clone() },
            contacts: PgContactStore { pool: pool.clone() },
            invite_receive_policies: PgInviteReceivePolicyStore { pool: pool.clone() },
            invite_locators: PgInviteLocatorStore { pool: pool.clone() },
            join_applications: PgJoinApplicationStore { pool: pool.clone() },
            consent_cells: PgConsentCellStore { pool: pool.clone() },
            direct_conversation_bindings: PgDirectConversationBindingStore { pool: pool.clone() },
            blobs: PgBlobStore { pool: pool.clone() },
            devices: PgDeviceInventoryStore { pool: pool.clone() },
            device_pairings: PgDevicePairingStore { pool: pool.clone() },
            federation_transactions: PgFederationTransactionStore { pool: pool.clone() },
            federation_outbox: PgFederationOutboxStore { pool: pool.clone() },
            federation_frontier_exchange: PgFederationFrontierExchangeStore { pool: pool.clone() },
            handle_releases: PgHandleReleaseStore { pool: pool.clone() },
            retention_policies: PgRetentionPolicyStore { pool: pool.clone() },
            retention_tombstones: PgRetentionTombstoneStore { pool: pool.clone() },
            organizations: PgOrganizationStore { pool: pool.clone() },
            organization_policies: PgOrganizationPolicyStore { pool: pool.clone() },
            realm_organizations: PgRealmOrganizationStore { pool: pool.clone() },
            realm_organization_statements: PgRealmOrganizationStatementStore { pool: pool.clone() },
            realm_moderation_policies: PgRealmModerationPolicyStore { pool: pool.clone() },
            push_bridge_cache: PgPushBridgeCacheStore { pool: pool.clone() },
            multisig_pending: PgMultisigPendingStore { pool: pool.clone() },
            audit: PgAuditStore { pool: pool.clone() },
            push_devices: PgPushDeviceStore { pool: pool.clone() },
            events: PgEventStore { pool: pool.clone() },
            federation_operations: PgFederationOperationsStore { pool: pool.clone() },
            moderation: PgModerationStore { pool: pool.clone() },
            presence: PgPresenceStore { pool: pool.clone() },
            call_signal_relay: PgCallSignalRelayStore { pool: pool.clone() },
            read_receipt_relay: PgReadReceiptRelayStore { pool: pool.clone() },
            webvh: PgWebvhStore { pool: pool.clone() },
            service_identity: PgServiceIdentityStore { pool: pool.clone() },
            realm_invites: PgRealmInviteStore { pool: pool.clone() },
            key_backups: PgKeyBackupStore { pool: pool.clone() },
            policy_documents: PgPolicyDocumentStore { pool: pool.clone() },
            recovery_policies: PgRecoveryPolicyStore { pool: pool.clone() },
            recovery_receipts: PgRecoveryReceiptStore { pool: pool.clone() },
            recovery_sessions: PgRecoverySessionStore { pool: pool.clone() },
            space_container_projections: PgSpaceContainerProjectionStore { pool: pool.clone() },
            strand_projections: PgStrandProjectionStore { pool: pool.clone() },
            morph_projections: PgMorphProjectionStore { pool: pool.clone() },
            projection_events: PgProjectionEventStore { pool: pool.clone() },
            applets: PgAppletStore { pool: pool.clone() },
            device_messages: PgDeviceMessageStore { pool: pool.clone() },
            mls_key_packages: PgMlsKeyPackageStore { pool: pool.clone() },
            mls_welcomes: PgMlsWelcomeStore { pool: pool.clone() },
            mls_commits: PgMlsCommitStore { pool: pool.clone() },
            agent_participation: PgAgentParticipationStore { pool: pool.clone() },
            agents: PgAgentStore { pool: pool.clone() },
            sidecars: PgSidecarStore { pool: pool.clone() },
            sync_cursors: PgSyncCursorStore { pool: pool.clone() },
            idempotency_keys: PgIdempotencyStore { pool: pool.clone() },
            notifications: PgNotificationStore { pool },
            fallback,
        }
    }
}

#[async_trait::async_trait]
impl EventCommitUnitOfWork for PgPersistenceStore {
    async fn commit_event(
        &self,
        request: EventCommitRequest,
    ) -> PersistenceResult<EventCommitOutcome> {
        self.event_commits.commit_event(request).await
    }

    async fn commit_event_batch(
        &self,
        request: soland_storage::EventBatchCommitRequest,
    ) -> PersistenceResult<EventCommitOutcome> {
        self.event_commits.commit_event_batch(request).await
    }
}

impl IdentityStoreRegistry for PgPersistenceStore {
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
        self.fallback.realm_meta()
    }

    fn messages(&self) -> &dyn MessageStore {
        self.fallback.messages()
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

#[async_trait]
impl DevicePairingCommitUnitOfWork for PgPersistenceStore {
    async fn commit_device_pairing_authorization(
        &self,
        commit: DevicePairingAuthorizationCommit,
    ) -> PersistenceResult<bool> {
        let mut conn = pg_conn(&self.device_pairings.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(
            "WITH claimed AS (\
                UPDATE device_pairings SET \
                    state = 'authorized', \
                    device_id = $5, \
                    authorized_by_actor_id = $6, \
                    authorized_event_ref = $7 \
                WHERE device_pairing_request_id = $1 \
                    AND pairing_code = $2 \
                    AND new_device_pubkey = $3 \
                    AND challenge_signature = $4 \
                    AND state = 'pending_authorization' \
                    AND expires_at > $8 \
                RETURNING 1\
            ) \
            INSERT INTO devices \
                (id, actor_id, device_id, payload, verification_state, created_at, updated_at, revoked_at) \
            SELECT $9, $6, $5, $10, $11, $12, $13, $14 FROM claimed \
            ON CONFLICT (actor_id, device_id) DO UPDATE SET \
                payload = EXCLUDED.payload, \
                verification_state = EXCLUDED.verification_state, \
                updated_at = EXCLUDED.updated_at, \
                revoked_at = EXCLUDED.revoked_at",
        )
        .bind::<Text, _>(&commit.device_pairing_request_id)
        .bind::<Text, _>(&commit.pairing_code)
        .bind::<Jsonb, _>(&commit.new_device_pubkey)
        .bind::<Text, _>(&commit.challenge_signature)
        .bind::<Text, _>(&commit.device.device_id)
        .bind::<Text, _>(&commit.authorized_by_actor_id)
        .bind::<Text, _>(&commit.authorized_event_ref)
        .bind::<Timestamptz, _>(commit.changed_at)
        .bind::<SqlUuid, _>(uuid::Uuid::now_v7())
        .bind::<Jsonb, _>(&commit.device.payload)
        .bind::<Text, _>(&commit.device.verification_state)
        .bind::<Timestamptz, _>(commit.device.created_at)
        .bind::<Timestamptz, _>(commit.device.updated_at)
        .bind::<Nullable<Timestamptz>, _>(commit.device.revoked_at)
        .execute(&mut *conn)
        .await
        .map(|rows| rows > 0)
        .map_err(PersistenceError::database)
    }
}

impl FederationGovernanceStoreRegistry for PgPersistenceStore {
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

    fn realm_organization_statements(&self) -> &dyn RealmOrganizationStatementStore {
        &self.realm_organization_statements
    }

    fn realm_moderation_policies(&self) -> &dyn RealmModerationPolicyStore {
        &self.realm_moderation_policies
    }

    fn audit(&self) -> &dyn AuditStore {
        &self.audit
    }

    fn join_applications(&self) -> &dyn JoinApplicationStore {
        &self.join_applications
    }
}

impl DeliveryPolicyStoreRegistry for PgPersistenceStore {
    fn moderation(&self) -> &dyn ModerationStore {
        &self.moderation
    }

    fn federation_operations(&self) -> &dyn FederationOperationsStore {
        &self.federation_operations
    }

    fn push_devices(&self) -> &dyn PushDeviceStore {
        &self.push_devices
    }

    fn presence(&self) -> &dyn PresenceStore {
        &self.presence
    }

    fn typing(&self) -> &dyn TypingStore {
        self.fallback.typing()
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

    fn service_identity(&self) -> &dyn ServiceIdentityStore {
        &self.service_identity
    }

    fn realm_invites(&self) -> &dyn RealmInviteStore {
        &self.realm_invites
    }
}

impl EventProjectionStoreRegistry for PgPersistenceStore {
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
        self.fallback.device_keys()
    }

    fn one_time_keys(&self) -> &dyn OneTimeKeyStore {
        self.fallback.one_time_keys()
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
}

impl MlsAgentStoreRegistry for PgPersistenceStore {
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

impl SyncStoreRegistry for PgPersistenceStore {
    fn sync_cursors(&self) -> &dyn SyncCursorStore {
        &self.sync_cursors
    }

    fn idempotency_keys(&self) -> &dyn IdempotencyStore {
        &self.idempotency_keys
    }
}

impl PersistenceStore for PgPersistenceStore {}
