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
    agent_membership_cascades: PgAgentMembershipCascadeStore,
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
    mimi_consent_correlations: PgMimiConsentCorrelationStore,
    blobs: PgBlobStore,
    devices: PgDeviceInventoryStore,
    device_pairings: PgDevicePairingStore,
    device_revocations: PgDeviceRevocationStore,
    federation_outbox: PgFederationOutboxStore,
    federation_frontier_exchange: PgFederationFrontierExchangeStore,
    handle_releases: PgHandleReleaseStore,
    retention_policies: PgRetentionPolicyStore,
    retention_tombstones: PgRetentionTombstoneStore,
    organizations: PgOrganizationStore,
    organization_registrations: PgOrganizationRegistrationStore,
    organization_policies: PgOrganizationPolicyStore,
    realm_organizations: PgRealmOrganizationStore,
    realm_organization_statements: PgRealmOrganizationStatementStore,
    push_bridge_cache: PgPushBridgeCacheStore,
    multisig_pending: PgMultisigPendingStore,
    audit: PgAuditStore,
    push_devices: PgPushDeviceStore,
    events: PgEventStore,
    federation_operations: PgFederationOperationsStore,
    moderation: PgModerationStore,
    signal_relay: PgSignalRelayStore,
    webvh: PgWebvhStore,
    service_identity: PgServiceIdentityStore,
    principal_resolutions: PgPrincipalResolutionStore,
    service_routes: PgServiceRouteStore,
    realm_invites: PgRealmInviteStore,
    circle_projections: PgCircleProjectionStore,
    strand_watch_projections: PgStrandWatchProjectionStore,
    key_backups: PgKeyBackupStore,
    policy_documents: PgPolicyDocumentStore,
    recovery_policies: PgRecoveryPolicyStore,
    recovery_sessions: PgRecoverySessionStore,
    security_transactions: PgSecurityTransactionStore,
    space_container_projections: PgSpaceContainerProjectionStore,
    strand_projections: PgStrandProjectionStore,
    morph_projections: PgMorphProjectionStore,
    publication_evidence: PgPublicationEvidenceStore,
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
    websocket_auth: PgWebsocketAuthStore,
    control_proposal_authority_acks: PgControlProposalAuthorityAckStore,
    fallback: Arc<dyn PersistenceStore>,
}

impl PgPersistenceStore {
    pub fn new(pool: PgPool, fallback: Arc<dyn PersistenceStore>) -> Self {
        Self {
            event_commits: PgEventCommitUnitOfWork::new(pool.clone()),
            agent_membership_cascades: PgAgentMembershipCascadeStore { pool: pool.clone() },
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
            mimi_consent_correlations: PgMimiConsentCorrelationStore { pool: pool.clone() },
            blobs: PgBlobStore { pool: pool.clone() },
            devices: PgDeviceInventoryStore { pool: pool.clone() },
            device_pairings: PgDevicePairingStore { pool: pool.clone() },
            device_revocations: PgDeviceRevocationStore { pool: pool.clone() },
            federation_outbox: PgFederationOutboxStore { pool: pool.clone() },
            federation_frontier_exchange: PgFederationFrontierExchangeStore { pool: pool.clone() },
            handle_releases: PgHandleReleaseStore { pool: pool.clone() },
            retention_policies: PgRetentionPolicyStore { pool: pool.clone() },
            retention_tombstones: PgRetentionTombstoneStore { pool: pool.clone() },
            organizations: PgOrganizationStore { pool: pool.clone() },
            organization_registrations: PgOrganizationRegistrationStore::new(pool.clone()),
            organization_policies: PgOrganizationPolicyStore { pool: pool.clone() },
            realm_organizations: PgRealmOrganizationStore { pool: pool.clone() },
            realm_organization_statements: PgRealmOrganizationStatementStore { pool: pool.clone() },
            push_bridge_cache: PgPushBridgeCacheStore { pool: pool.clone() },
            multisig_pending: PgMultisigPendingStore { pool: pool.clone() },
            audit: PgAuditStore { pool: pool.clone() },
            push_devices: PgPushDeviceStore { pool: pool.clone() },
            events: PgEventStore { pool: pool.clone() },
            federation_operations: PgFederationOperationsStore { pool: pool.clone() },
            moderation: PgModerationStore { pool: pool.clone() },
            signal_relay: PgSignalRelayStore { pool: pool.clone() },
            webvh: PgWebvhStore { pool: pool.clone() },
            service_identity: PgServiceIdentityStore { pool: pool.clone() },
            principal_resolutions: PgPrincipalResolutionStore { pool: pool.clone() },
            service_routes: PgServiceRouteStore { pool: pool.clone() },
            realm_invites: PgRealmInviteStore { pool: pool.clone() },
            circle_projections: PgCircleProjectionStore { pool: pool.clone() },
            strand_watch_projections: PgStrandWatchProjectionStore { pool: pool.clone() },
            key_backups: PgKeyBackupStore { pool: pool.clone() },
            policy_documents: PgPolicyDocumentStore { pool: pool.clone() },
            recovery_policies: PgRecoveryPolicyStore { pool: pool.clone() },
            recovery_sessions: PgRecoverySessionStore { pool: pool.clone() },
            security_transactions: PgSecurityTransactionStore { pool: pool.clone() },
            space_container_projections: PgSpaceContainerProjectionStore { pool: pool.clone() },
            strand_projections: PgStrandProjectionStore { pool: pool.clone() },
            morph_projections: PgMorphProjectionStore { pool: pool.clone() },
            publication_evidence: PgPublicationEvidenceStore { pool: pool.clone() },
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
            websocket_auth: PgWebsocketAuthStore { pool: pool.clone() },
            control_proposal_authority_acks: PgControlProposalAuthorityAckStore {
                pool: pool.clone(),
            },
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

    fn mimi_consent_correlations(&self) -> &dyn MimiConsentCorrelationStore {
        &self.mimi_consent_correlations
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

    fn device_revocations(&self) -> &dyn DeviceRevocationStore {
        &self.device_revocations
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
        let new_device_pubkey =
            serde_json::to_value(&commit.new_device_pubkey).map_err(|error| {
                PersistenceError::Internal(format!(
                    "cannot encode device pairing authorization public key: {error}"
                ))
            })?;
        sql_query(
            "UPDATE device_pairings SET \
                    state = 'authorized', \
                    device_id = $4, \
                    authorized_by_actor_id = $5, \
                    authorized_event_ref = $6 \
                WHERE device_pairing_request_id = $1 \
                    AND pairing_code = $2 \
                    AND new_device_pubkey = $3 \
                    AND state = 'pending_authorization' \
                    AND expires_at > $7",
        )
        .bind::<Text, _>(&commit.device_pairing_request_id)
        .bind::<Text, _>(&commit.pairing_code)
        .bind::<Jsonb, _>(&new_device_pubkey)
        .bind::<Text, _>(&commit.device_id)
        .bind::<Text, _>(&commit.authorized_by_actor_id)
        .bind::<Text, _>(&commit.authorized_event_ref)
        .bind::<Timestamptz, _>(commit.changed_at)
        .execute(&mut *conn)
        .await
        .map(|rows| rows > 0)
        .map_err(PersistenceError::database)
    }
}

impl FederationGovernanceStoreRegistry for PgPersistenceStore {
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

    fn circle_projections(&self) -> &dyn CircleProjectionStore {
        &self.circle_projections
    }

    fn strand_watch_projections(&self) -> &dyn StrandWatchProjectionStore {
        &self.strand_watch_projections
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

    fn agent_membership_cascades(&self) -> &dyn AgentMembershipCascadeStore {
        &self.agent_membership_cascades
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

    fn websocket_auth(&self) -> &dyn WebsocketAuthStore {
        &self.websocket_auth
    }

    fn control_proposal_authority_acks(&self) -> &dyn ControlProposalAuthorityAckStore {
        &self.control_proposal_authority_acks
    }
}

impl ResolutionStoreRegistry for PgPersistenceStore {
    fn principal_resolutions(&self) -> &dyn PrincipalResolutionStore {
        &self.principal_resolutions
    }

    fn service_routes(&self) -> &dyn ServiceRouteStore {
        &self.service_routes
    }
}

impl PersistenceStore for PgPersistenceStore {}
