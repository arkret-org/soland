use std::sync::Arc;

use serde_json::Value;
use soland_storage::*;

use crate::events::*;

#[derive(Clone)]
struct PersistenceEventCommitter(Arc<dyn PersistenceStore>);
struct PersistenceEventReader(Arc<dyn PersistenceStore>);
struct PersistenceProjectionWriter {
    persistence: Arc<dyn PersistenceStore>,
    projected_operations: Arc<dyn ProjectedOperationPersistencePort>,
}
struct PersistenceMlsCommitReader(Arc<dyn PersistenceStore>);
struct PersistenceMlsKeyPackageMaintenance(Arc<dyn PersistenceStore>);
struct PersistenceRealmMetadata(Arc<dyn PersistenceStore>);
struct PersistenceRealmInvites(Arc<dyn PersistenceStore>);
fn application_accepted_event(
    record: soland_storage::CanonicalEventRecord,
) -> crate::events::AcceptedEvent {
    crate::events::AcceptedEvent {
        event_id: record.event_id,
        actor_id: record.actor_id,
        actor_seq: record.actor_seq,
        realm_id: record.realm_id,
        kind: record.kind,
        schema_id: record.schema_id,
        canonical_digest: record.canonical_digest,
        canonical_bytes: record.canonical_bytes,
        envelope: record.envelope,
        received_at: record.received_at,
    }
}

fn persistence_canonical_event(
    record: crate::events::CanonicalEventRecord,
) -> soland_storage::CanonicalEventRecord {
    soland_storage::CanonicalEventRecord {
        event_id: record.event_id,
        actor_id: record.actor_id,
        actor_seq: record.actor_seq,
        realm_id: record.realm_id,
        kind: record.kind,
        schema_id: record.schema_id,
        canonical_digest: record.canonical_digest,
        canonical_bytes: record.canonical_bytes,
        envelope: record.envelope,
        received_at: record.received_at,
    }
}

fn application_projected_event(
    event: soland_storage::ProjectionEventRecord,
) -> crate::events::ProjectedEvent {
    crate::events::ProjectedEvent {
        event_id: event.event_id,
        realm_id: event.realm_id,
        event_kind: event.event_kind,
        operation_kind: event.operation_kind,
        operation_id: event.operation_id,
        sender: event.sender,
        payload: event.payload,
        created_at: event.created_at,
        received_at: event.received_at,
    }
}

fn persistence_projected_event(
    event: crate::events::ProjectedEvent,
) -> soland_storage::ProjectionEventRecord {
    soland_storage::ProjectionEventRecord {
        event_id: event.event_id,
        realm_id: event.realm_id,
        event_kind: event.event_kind,
        operation_kind: event.operation_kind,
        operation_id: event.operation_id,
        sender: event.sender,
        payload: event.payload,
        created_at: event.created_at,
        received_at: event.received_at,
    }
}

fn persistence_event_commit_request(
    command: crate::events::CommitAcceptedEventCommand,
) -> soland_storage::EventCommitRequest {
    soland_storage::EventCommitRequest {
        event: persistence_canonical_event(command.event),
        projections: command
            .projections
            .into_iter()
            .map(persistence_projected_event)
            .collect(),
        idempotency: command
            .idempotency
            .map(|record| soland_storage::IdempotencyRecord {
                principal_id: record.principal_id,
                idempotency_key: record.key,
                service_id: record.service_id,
                request_hash: record.request_hash,
                response_status: record.status,
                response_body: record.body,
                created_at: record.created_at,
                expires_at: record.expires_at,
            }),
        outbox: command
            .deliveries
            .into_iter()
            .map(|delivery| soland_storage::FederationOutboxRecord {
                id: delivery.id,
                peer_did: delivery.peer_did,
                peer_url: delivery.peer_url,
                endpoint: delivery.endpoint,
                idempotency_key: delivery.idempotency_key,
                payload_json: delivery.payload_json,
                attempts: 0,
                next_attempt_at: delivery.created_at,
                last_status: None,
                last_response_excerpt: None,
                created_at: delivery.created_at,
                delivered_at: None,
            })
            .collect(),
    }
}

#[async_trait::async_trait]
impl crate::events::EventReadPort for PersistenceEventReader {
    async fn store_canonical_event(
        &self,
        record: crate::events::CanonicalEventRecord,
    ) -> crate::ServiceResult<()> {
        self.0
            .events()
            .put(persistence_canonical_event(record))
            .await?;
        Ok(())
    }
    async fn store_realm_bootstrap_batch(
        &self,
        records: Vec<crate::events::CanonicalEventRecord>,
    ) -> crate::ServiceResult<()> {
        self.0
            .events()
            .put_realm_bootstrap_batch_atomic(
                records
                    .into_iter()
                    .map(persistence_canonical_event)
                    .collect(),
            )
            .await?;
        Ok(())
    }
    async fn store_identity_anchor_batch(
        &self,
        records: Vec<crate::events::CanonicalEventRecord>,
        receipt: Option<arkret_wire::EventBatchReceipt>,
        device: Option<crate::events::IdentityAnchorDeviceState>,
        frontier_cas: Option<crate::events::IdentityAnchorFrontierState>,
        reanchor_slot: Option<crate::events::IdentityAnchorReanchorState>,
    ) -> crate::ServiceResult<crate::events::IdentityAnchorCommitResult> {
        let outcome = self
            .0
            .events()
            .put_identity_anchor_batch_atomic(
                records
                    .into_iter()
                    .map(persistence_canonical_event)
                    .collect(),
                receipt,
                device.map(|state| soland_storage::DeviceInventoryRecord {
                    actor: state.actor,
                    device_id: state.device_id,
                    display_name: state.display_name,
                    verification_state: state.verification_state,
                    payload: state.payload,
                    created_at: state.created_at,
                    updated_at: state.updated_at,
                    revoked_at: state.revoked_at,
                }),
                frontier_cas.map(|state| soland_storage::IdentityAnchorFrontierCas {
                    realm_id: state.realm_id,
                    raw_leaves: state.raw_leaves,
                }),
                reanchor_slot.map(|state| soland_storage::IdentityAnchorReanchorSlot {
                    actor_id: state.actor_id,
                    version_number: state.version_number,
                    did_version_id: state.did_version_id,
                    reanchor_digest: state.reanchor_digest,
                    authorize_digest: state.authorize_digest,
                }),
            )
            .await?;
        Ok(crate::events::IdentityAnchorCommitResult {
            reanchor_conflict: outcome.reanchor_conflict,
        })
    }
    async fn canonical_event(
        &self,
        event_id: &str,
    ) -> crate::ServiceResult<Option<crate::events::CanonicalEventRecord>> {
        Ok(self
            .0
            .events()
            .get(event_id)
            .await?
            .map(application_accepted_event))
    }
    async fn has_canonical_event(&self, event_id: &str) -> crate::ServiceResult<bool> {
        Ok(self.0.events().contains(event_id).await?)
    }
    async fn canonical_events(
        &self,
    ) -> crate::ServiceResult<Vec<crate::events::CanonicalEventRecord>> {
        Ok(self
            .0
            .events()
            .snapshot_all()
            .await?
            .into_iter()
            .map(application_accepted_event)
            .collect())
    }
    async fn canonical_events_for_actor(
        &self,
        actor_id: &str,
    ) -> crate::ServiceResult<Vec<crate::events::CanonicalEventRecord>> {
        Ok(self
            .0
            .events()
            .list_for_actor(actor_id)
            .await?
            .into_iter()
            .map(application_accepted_event)
            .collect())
    }
    async fn canonical_events_for_realm_actor(
        &self,
        realm_id: &str,
        actor_id: &str,
    ) -> crate::ServiceResult<Vec<crate::events::CanonicalEventRecord>> {
        Ok(self
            .0
            .events()
            .list_for_realm_actor(realm_id, actor_id)
            .await?
            .into_iter()
            .map(application_accepted_event)
            .collect())
    }
    async fn canonical_batch_receipts_for_event(
        &self,
        event_id: &str,
    ) -> crate::ServiceResult<Vec<arkret_wire::EventBatchReceipt>> {
        Ok(self.0.events().batch_receipts_for_event(event_id).await?)
    }
    async fn realm_event_stats(
        &self,
        realm_id: &str,
    ) -> crate::ServiceResult<soland_storage::RealmEventStats> {
        Ok(self.0.events().realm_event_stats(realm_id).await?)
    }
    async fn peer_authz_state_records(
        &self,
    ) -> crate::ServiceResult<Vec<crate::events::CanonicalEventRecord>> {
        Ok(self
            .0
            .events()
            .peer_authz_state_records()
            .await?
            .into_iter()
            .map(application_accepted_event)
            .collect())
    }
    async fn peer_events_query_page(
        &self,
        query: &crate::events::PeerEventsPageQuery,
    ) -> crate::ServiceResult<Vec<crate::events::CanonicalEventRecord>> {
        let query = soland_storage::PeerEventsPageQuery {
            realms: query.realms.clone(),
            actors: query.actors.clone(),
            kind_filter: query.kind_filter.clone(),
            cursor_event_id: query.cursor_event_id.clone(),
            backward: query.backward,
            limit: query.limit,
        };
        Ok(self
            .0
            .events()
            .peer_events_query_page(&query)
            .await?
            .into_iter()
            .map(application_accepted_event)
            .collect())
    }
    async fn realm_events_newest_first(
        &self,
        realm_id: &str,
    ) -> crate::ServiceResult<Vec<crate::events::CanonicalEventRecord>> {
        Ok(self
            .0
            .events()
            .realm_events_newest_first(realm_id)
            .await?
            .into_iter()
            .map(application_accepted_event)
            .collect())
    }

    async fn accepted_event(
        &self,
        event_id: &str,
    ) -> crate::ServiceResult<Option<crate::events::AcceptedEvent>> {
        Ok(self
            .0
            .events()
            .get(event_id)
            .await?
            .map(application_accepted_event))
    }

    async fn accepted_events(&self) -> crate::ServiceResult<Vec<crate::events::AcceptedEvent>> {
        Ok(self
            .0
            .events()
            .snapshot_all()
            .await?
            .into_iter()
            .map(application_accepted_event)
            .collect())
    }

    async fn projected_events(&self) -> crate::ServiceResult<Vec<crate::events::ProjectedEvent>> {
        Ok(self
            .0
            .projection_events()
            .snapshot_all()
            .await?
            .into_iter()
            .map(application_projected_event)
            .collect())
    }

    async fn projected_events_capped(
        &self,
        limit: usize,
    ) -> crate::ServiceResult<Vec<crate::events::ProjectedEvent>> {
        Ok(self
            .0
            .projection_events()
            .snapshot_capped(limit)
            .await?
            .into_iter()
            .map(application_projected_event)
            .collect())
    }

    async fn append_projected_event(
        &self,
        event: crate::events::ProjectedEvent,
    ) -> crate::ServiceResult<crate::events::ProjectedEventAppendResult> {
        Ok(
            match self
                .0
                .projection_events()
                .append(persistence_projected_event(event))
                .await?
            {
                soland_storage::ProjectionEventAppendOutcome::Inserted => {
                    crate::events::ProjectedEventAppendResult::Inserted
                }
                soland_storage::ProjectionEventAppendOutcome::AlreadyExists => {
                    crate::events::ProjectedEventAppendResult::AlreadyExists
                }
            },
        )
    }

    async fn accepted_events_for_actor(
        &self,
        actor_id: &str,
    ) -> crate::ServiceResult<Vec<crate::events::AcceptedEvent>> {
        Ok(self
            .0
            .events()
            .list_for_actor(actor_id)
            .await?
            .into_iter()
            .map(application_accepted_event)
            .collect())
    }

    async fn max_actor_sequence(&self, actor_id: &str) -> crate::ServiceResult<Option<u64>> {
        Ok(self.0.events().max_actor_seq(actor_id).await?)
    }

    async fn batch_receipts_for_event(
        &self,
        event_id: &str,
    ) -> crate::ServiceResult<Vec<crate::events::AcceptedBatchReceipt>> {
        self.0
            .events()
            .batch_receipts_for_event(event_id)
            .await?
            .into_iter()
            .map(|receipt| {
                serde_json::to_value(receipt)
                    .map(|value| crate::events::AcceptedBatchReceipt { value })
                    .map_err(|error| {
                        soland_storage::PersistenceError::Internal(format!(
                            "event batch receipt serialization failed: {error}"
                        ))
                        .into()
                    })
            })
            .collect()
    }
}

fn application_message(record: soland_storage::MessageRecord) -> crate::events::MessageState {
    crate::events::MessageState {
        event_id: record.event_id,
        message_id: record.message_id,
        realm_id: record.realm_id,
        sender: record.sender,
        thread_id: record.thread_id,
        content: record.content,
        encrypted: record.encrypted,
        created_at: record.created_at,
    }
}

fn persistence_message(message: crate::events::MessageState) -> soland_storage::MessageRecord {
    soland_storage::MessageRecord {
        event_id: message.event_id,
        message_id: message.message_id,
        realm_id: message.realm_id,
        sender: message.sender,
        thread_id: message.thread_id,
        content: message.content,
        encrypted: message.encrypted,
        created_at: message.created_at,
    }
}

#[async_trait::async_trait]
impl crate::events::MessagePort for PersistenceEventReader {
    async fn message(
        &self,
        event_id: &str,
    ) -> crate::ServiceResult<Option<crate::events::MessageState>> {
        Ok(self
            .0
            .messages()
            .get(event_id)
            .await?
            .map(application_message))
    }

    async fn store_message(
        &self,
        message: crate::events::MessageState,
    ) -> crate::ServiceResult<()> {
        self.0.messages().put(&persistence_message(message)).await?;
        Ok(())
    }

    async fn messages_for_realm(
        &self,
        realm_id: &str,
        limit: usize,
    ) -> crate::ServiceResult<Vec<crate::events::MessageState>> {
        Ok(self
            .0
            .messages()
            .list_for_realm(realm_id, limit)
            .await?
            .into_iter()
            .map(application_message)
            .collect())
    }
}

fn application_applet_replay(
    record: soland_storage::AppletTransactionReplayRecord,
) -> crate::events::AppletTransactionReplayState {
    crate::events::AppletTransactionReplayState {
        source_service_id: record.source_service_id,
        idempotency_key: record.idempotency_key,
        source_signature_anchor: record.source_signature_anchor,
        request_digest: record.request_digest,
        outcome: record.outcome,
        received_at: record.received_at,
        completed_at: record.completed_at,
    }
}
fn persistence_applet_replay(
    record: crate::events::AppletTransactionReplayState,
) -> soland_storage::AppletTransactionReplayRecord {
    soland_storage::AppletTransactionReplayRecord {
        source_service_id: record.source_service_id,
        idempotency_key: record.idempotency_key,
        source_signature_anchor: record.source_signature_anchor,
        request_digest: record.request_digest,
        outcome: record.outcome,
        received_at: record.received_at,
        completed_at: record.completed_at,
    }
}

#[async_trait::async_trait]
impl crate::events::AppletPort for PersistenceEventReader {
    async fn applet(&self, applet_id: &str) -> crate::ServiceResult<Option<Value>> {
        Ok(self.0.applets().get(applet_id).await?)
    }
    async fn applets(&self) -> crate::ServiceResult<Vec<Value>> {
        Ok(self.0.applets().list().await?)
    }
    async fn store_applet(&self, applet_id: &str, applet: Value) -> crate::ServiceResult<()> {
        self.0.applets().put(applet_id, applet).await?;
        Ok(())
    }
    async fn begin_applet_transaction(
        &self,
        replay: crate::events::AppletTransactionReplayState,
    ) -> crate::ServiceResult<crate::events::AppletTransactionReplayResult> {
        Ok(
            match self
                .0
                .applets()
                .begin_transaction_replay(persistence_applet_replay(replay))
                .await?
            {
                soland_storage::AppletTransactionReplayBegin::Fresh => {
                    crate::events::AppletTransactionReplayResult::Fresh
                }
                soland_storage::AppletTransactionReplayBegin::Existing(existing) => {
                    crate::events::AppletTransactionReplayResult::Existing(
                        application_applet_replay(existing),
                    )
                }
            },
        )
    }
    async fn complete_applet_transaction(
        &self,
        source_service_id: &str,
        idempotency_key: &str,
        outcome: Value,
    ) -> crate::ServiceResult<()> {
        self.0
            .applets()
            .complete_transaction_replay(source_service_id, idempotency_key, outcome)
            .await?;
        Ok(())
    }
}

#[async_trait::async_trait]
impl crate::events::ProjectionWritePort for PersistenceProjectionWriter {
    async fn persist_projected_operation(
        &self,
        origin: &str,
        operation: &arkret_event_draft::Operation,
    ) -> crate::ServiceResult<()> {
        let event_type = soland_domain::kinds::canonical_kind_string(operation);
        let is_message_create = soland_domain::kinds::operation_is_message_create(operation);
        let is_membership_or_realm_lifecycle =
            soland_domain::kinds::operation_is_membership(operation)
                || soland_domain::kinds::operation_is_realm_lifecycle(operation);
        self.projected_operations
            .persist_projected_operation(
                origin,
                operation,
                &event_type,
                is_message_create,
                is_membership_or_realm_lifecycle,
            )
            .await
            .map_err(soland_storage::PersistenceError::Internal)
            .map_err(Into::into)
    }

    async fn store_space_container_projection(
        &self,
        record: &crate::events::SpaceContainerProjectionRecord,
    ) -> crate::ServiceResult<()> {
        let record = soland_storage::SpaceContainerProjectionRecord {
            container_space_id: record.container_space_id.clone(),
            realm_id: record.realm_id.clone(),
            kind: record.kind.clone(),
            title: record.title.clone(),
            fields: record.fields.clone(),
            scope_circle_id: record.scope_circle_id.clone(),
            child_scope_policy: record.child_scope_policy.clone(),
            child_scope_policy_scope_circle_id: record.child_scope_policy_scope_circle_id.clone(),
            parent_ref: record.parent_ref.clone(),
            rank: record.rank.clone(),
            state: record.state.clone(),
            state_changed_at: record.state_changed_at,
            created_by: record.created_by.clone(),
            created_at: record.created_at,
            history_basis_seals: record.history_basis_seals.clone(),
            updated_by: record.updated_by.clone(),
            updated_at: record.updated_at,
        };
        self.persistence
            .space_container_projections()
            .put(&record)
            .await?;
        Ok(())
    }

    async fn store_strand_projection(
        &self,
        record: &crate::events::StrandProjectionRecord,
    ) -> crate::ServiceResult<()> {
        let record = soland_storage::StrandProjectionRecord {
            strand_id: record.strand_id.clone(),
            realm_id: record.realm_id.clone(),
            tracks: record.tracks.clone(),
            title: record.title.clone(),
            summary: record.summary.clone(),
            state: record.state.clone(),
            state_changed_at: record.state_changed_at,
            created_by: record.created_by.clone(),
            created_at: record.created_at,
            history_basis_seals: record.history_basis_seals.clone(),
            updated_by: record.updated_by.clone(),
            updated_at: record.updated_at,
            scope_circle_id: record.scope_circle_id.clone(),
        };
        self.persistence.strand_projections().put(&record).await?;
        Ok(())
    }

    async fn store_morph_projection(
        &self,
        record: &crate::events::MorphProjectionRecord,
    ) -> crate::ServiceResult<()> {
        let record = soland_storage::MorphProjectionRecord {
            morph_id: record.morph_id.clone(),
            realm_id: record.realm_id.clone(),
            scope_circle_id: record.scope_circle_id.clone(),
            morph_kind: record.morph_kind.clone(),
            title: record.title.clone(),
            fields: record.fields.clone(),
            schema_refs: record.schema_refs.clone(),
            facets: record.facets.clone(),
            versions: record.versions.clone(),
            state: record.state.clone(),
            state_changed_at: record.state_changed_at,
            created_by: record.created_by.clone(),
            created_at: record.created_at,
            history_basis_seals: record.history_basis_seals.clone(),
            updated_by: record.updated_by.clone(),
            updated_at: record.updated_at,
        };
        self.persistence.morph_projections().put(&record).await?;
        Ok(())
    }

    async fn store_realm_organization_statement(
        &self,
        record: &crate::events::RealmOrganizationStatementRecord,
    ) -> crate::ServiceResult<()> {
        let record = soland_storage::RealmOrganizationStatementRecord {
            realm_id: record.realm_id.clone(),
            organization_id: record.organization_id.clone(),
            relationship: record.relationship.clone(),
            statement_id: record.statement_id.clone(),
            status: record.status.clone(),
            control_scopes: record.control_scopes.clone(),
            issued_at: record.issued_at,
            not_before: record.not_before,
            expires_at: record.expires_at,
            supersedes_statement_id: record.supersedes_statement_id.clone(),
            revokes_statement_id: record.revokes_statement_id.clone(),
            realm_frontier_digest: record.realm_frontier_digest.clone(),
            proof_digest: record.proof_digest.clone(),
            delegation_ref: record.delegation_ref.clone(),
            issuer_role: record.issuer_role.clone(),
            updated_at: record.updated_at,
        };
        self.persistence
            .realm_organization_statements()
            .put(&record)
            .await?;
        Ok(())
    }
}

#[async_trait::async_trait]
impl crate::events::MlsCommitReadPort for PersistenceMlsCommitReader {
    async fn commits(&self) -> crate::ServiceResult<Vec<crate::events::MlsCommitState>> {
        Ok(self
            .0
            .mls_commits()
            .snapshot_all()
            .await?
            .into_iter()
            .map(|commit| crate::events::MlsCommitState {
                group_id: commit.group_id,
                effective_scope: commit.effective_scope,
                epoch: commit.epoch,
                creator_device_id: commit.creator_device_id,
                genesis_event_ref: commit.genesis_event_ref,
                governance_binding: commit.governance_binding,
                accepted_commit_ref: commit.accepted_commit_ref,
                frontier_contested: commit.frontier_contested,
            })
            .collect())
    }

    async fn commit(
        &self,
        effective_scope: &serde_json::Value,
        group_id: &str,
    ) -> crate::ServiceResult<Option<crate::events::MlsCommitState>> {
        Ok(self
            .0
            .mls_commits()
            .get(effective_scope, group_id)
            .await?
            .map(application_mls_commit))
    }

    async fn initialize_group(
        &self,
        command: crate::events::InitializeMlsGroupCommand,
    ) -> crate::ServiceResult<Option<crate::events::MlsCommitState>> {
        Ok(self
            .0
            .mls_commits()
            .initialize_genesis(soland_storage::MlsCommitGenesis {
                effective_scope: &command.effective_scope,
                group_id: &command.group_id,
                leader_actor_id: &command.leader_actor_id,
                creator_device_id: &command.creator_device_id,
                genesis_event_ref: &command.genesis_event_ref,
                covered_seals: &command.covered_seals,
                governance_binding: &command.governance_binding,
                committed_at: command.committed_at,
            })
            .await?
            .map(application_mls_commit))
    }

    async fn advance_epoch(
        &self,
        command: crate::events::AdvanceMlsEpochCommand,
    ) -> crate::ServiceResult<Option<crate::events::MlsCommitState>> {
        Ok(self
            .0
            .mls_commits()
            .try_bump(
                command.expected_previous_epoch,
                soland_storage::MlsCommitEpochAdvance {
                    effective_scope: &command.effective_scope,
                    group_id: &command.group_id,
                    leader_actor_id: &command.leader_actor_id,
                    covered_seals: &command.covered_seals,
                    governance_binding: &command.governance_binding,
                    accepted_commit_ref: &command.accepted_commit_ref,
                    committed_at: command.committed_at,
                },
            )
            .await?
            .map(application_mls_commit))
    }

    async fn mark_frontier_contested(
        &self,
        effective_scope: &serde_json::Value,
        group_id: &str,
        epoch: u64,
    ) -> crate::ServiceResult<Option<crate::events::MlsCommitState>> {
        Ok(self
            .0
            .mls_commits()
            .mark_frontier_contested(effective_scope, group_id, epoch)
            .await?
            .map(application_mls_commit))
    }
}

fn application_mls_commit(
    commit: soland_storage::MlsCommitEpochRecord,
) -> crate::events::MlsCommitState {
    crate::events::MlsCommitState {
        group_id: commit.group_id,
        effective_scope: commit.effective_scope,
        epoch: commit.epoch,
        creator_device_id: commit.creator_device_id,
        genesis_event_ref: commit.genesis_event_ref,
        governance_binding: commit.governance_binding,
        accepted_commit_ref: commit.accepted_commit_ref,
        frontier_contested: commit.frontier_contested,
    }
}

fn application_mls_key_package(
    row: soland_storage::MlsKeyPackageRow,
) -> crate::events::MlsKeyPackageState {
    crate::events::MlsKeyPackageState {
        id: row.id,
        keypackage_ref: row.keypackage_ref,
        keypackage_digest: row.keypackage_digest,
        actor_id: row.actor_id,
        device_id: row.device_id,
        key_package_bytes: row.key_package_bytes,
        capabilities: row.capabilities,
        capabilities_digest: row.capabilities_digest,
        device_signature: row.device_signature,
        last_resort: row.last_resort,
        last_resort_realm_id: row.last_resort_realm_id,
        lifetime_not_before: row.lifetime_not_before,
        lifetime_not_after: row.lifetime_not_after,
        claimed_by_mls_group_id: row.claimed_by_mls_group_id,
        ssk_generation: row.ssk_generation,
        device_authorize_event_id: row.device_authorize_event_id,
        agent_key_authorize_event_id: row.agent_key_authorize_event_id,
        claimed_at: row.claimed_at,
        claim_expires_at_unix_ms: row.claim_expires_at_unix_ms,
        consumed_at: row.consumed_at,
        created_at: row.created_at,
    }
}

fn persistence_mls_key_package(
    row: &crate::events::MlsKeyPackageState,
) -> soland_storage::MlsKeyPackageRow {
    soland_storage::MlsKeyPackageRow {
        id: row.id.clone(),
        keypackage_ref: row.keypackage_ref.clone(),
        keypackage_digest: row.keypackage_digest.clone(),
        actor_id: row.actor_id.clone(),
        device_id: row.device_id.clone(),
        key_package_bytes: row.key_package_bytes.clone(),
        capabilities: row.capabilities.clone(),
        capabilities_digest: row.capabilities_digest.clone(),
        device_signature: row.device_signature.clone(),
        last_resort: row.last_resort,
        last_resort_realm_id: row.last_resort_realm_id.clone(),
        lifetime_not_before: row.lifetime_not_before,
        lifetime_not_after: row.lifetime_not_after,
        claimed_by_mls_group_id: row.claimed_by_mls_group_id.clone(),
        ssk_generation: row.ssk_generation,
        device_authorize_event_id: row.device_authorize_event_id.clone(),
        agent_key_authorize_event_id: row.agent_key_authorize_event_id.clone(),
        claimed_at: row.claimed_at,
        claim_expires_at_unix_ms: row.claim_expires_at_unix_ms,
        consumed_at: row.consumed_at,
        created_at: row.created_at,
    }
}

fn application_peer_claim(
    row: soland_storage::PeerKeyPackageClaimLedgerRecord,
) -> crate::events::PeerKeyPackageClaimLedgerState {
    crate::events::PeerKeyPackageClaimLedgerState {
        source_service_id: row.source_service_id,
        claim_request_id: row.claim_request_id,
        request_digest: row.request_digest,
        state: row.state,
        outcome: row.outcome,
        keypackage_id: row.keypackage_id,
        claim_expires_at_unix_ms: row.claim_expires_at_unix_ms,
        expires_at: row.expires_at,
        updated_at: row.updated_at,
    }
}

fn persistence_peer_claim(
    row: &crate::events::PeerKeyPackageClaimLedgerState,
) -> soland_storage::PeerKeyPackageClaimLedgerRecord {
    soland_storage::PeerKeyPackageClaimLedgerRecord {
        source_service_id: row.source_service_id.clone(),
        claim_request_id: row.claim_request_id.clone(),
        request_digest: row.request_digest.clone(),
        state: row.state.clone(),
        outcome: row.outcome.clone(),
        keypackage_id: row.keypackage_id.clone(),
        claim_expires_at_unix_ms: row.claim_expires_at_unix_ms,
        expires_at: row.expires_at,
        updated_at: row.updated_at,
    }
}

#[async_trait::async_trait]
impl crate::events::MlsKeyPackageMaintenancePort for PersistenceMlsKeyPackageMaintenance {
    async fn store_key_package(
        &self,
        record: &crate::events::MlsKeyPackageState,
    ) -> crate::ServiceResult<bool> {
        Ok(self
            .0
            .mls_key_packages()
            .put(&persistence_mls_key_package(record))
            .await?)
    }
    async fn key_package(
        &self,
        id: &str,
    ) -> crate::ServiceResult<Option<crate::events::MlsKeyPackageState>> {
        Ok(self
            .0
            .mls_key_packages()
            .get(id)
            .await?
            .map(application_mls_key_package))
    }
    async fn key_package_by_ref(
        &self,
        keypackage_ref: &str,
    ) -> crate::ServiceResult<Option<crate::events::MlsKeyPackageState>> {
        Ok(self
            .0
            .mls_key_packages()
            .get_by_ref(keypackage_ref)
            .await?
            .map(application_mls_key_package))
    }
    async fn claim_key_package(
        &self,
        command: crate::events::ClaimMlsKeyPackageCommand<'_>,
    ) -> crate::ServiceResult<Option<crate::events::MlsKeyPackageState>> {
        Ok(self
            .0
            .mls_key_packages()
            .try_claim(soland_storage::MlsKeyPackageClaim {
                id: command.id,
                mls_group_id: command.mls_group_id,
                intended_realm_id: command.intended_realm_id,
                ssk_generation: command.ssk_generation,
                device_authorize_event_id: command.device_authorize_event_id,
                agent_key_authorize_event_id: command.agent_key_authorize_event_id,
                claimed_at: command.claimed_at,
                claim_expires_at_unix_ms: command.claim_expires_at_unix_ms,
            })
            .await?
            .map(application_mls_key_package))
    }
    async fn consume_key_package_claim(
        &self,
        id: &str,
        mls_group_id: &str,
        consumed_at: i64,
    ) -> crate::ServiceResult<Option<crate::events::MlsKeyPackageState>> {
        Ok(self
            .0
            .mls_key_packages()
            .consume_claim(id, mls_group_id, consumed_at)
            .await?
            .map(application_mls_key_package))
    }
    async fn peer_claim(
        &self,
        source_service_id: &str,
        claim_request_id: &str,
    ) -> crate::ServiceResult<Option<crate::events::PeerKeyPackageClaimLedgerState>> {
        Ok(self
            .0
            .mls_key_packages()
            .get_peer_claim(source_service_id, claim_request_id)
            .await?
            .map(application_peer_claim))
    }
    async fn claim_peer_key_package(
        &self,
        attempt: crate::events::PeerKeyPackageClaimCommand<'_>,
    ) -> crate::ServiceResult<crate::events::PeerKeyPackageClaimResult> {
        let ledger = persistence_peer_claim(attempt.ledger);
        Ok(
            match self
                .0
                .mls_key_packages()
                .try_claim_peer(soland_storage::PeerKeyPackageClaimAttempt {
                    keypackage_id: attempt.keypackage_id,
                    mls_group_id: attempt.mls_group_id,
                    ssk_generation: attempt.ssk_generation,
                    device_authorize_event_id: attempt.device_authorize_event_id,
                    agent_key_authorize_event_id: attempt.agent_key_authorize_event_id,
                    claimed_at: attempt.claimed_at,
                    claim_expires_at_unix_ms: attempt.claim_expires_at_unix_ms,
                    ledger: &ledger,
                })
                .await?
            {
                soland_storage::PeerKeyPackageClaimAttemptResult::Claimed(row) => {
                    crate::events::PeerKeyPackageClaimResult::Claimed(Box::new(
                        application_mls_key_package(*row),
                    ))
                }
                soland_storage::PeerKeyPackageClaimAttemptResult::Existing(row) => {
                    crate::events::PeerKeyPackageClaimResult::Existing(application_peer_claim(row))
                }
                soland_storage::PeerKeyPackageClaimAttemptResult::KeyPackageUnavailable => {
                    crate::events::PeerKeyPackageClaimResult::KeyPackageUnavailable
                }
            },
        )
    }
    async fn store_peer_claim_terminal(
        &self,
        record: &crate::events::PeerKeyPackageClaimLedgerState,
    ) -> crate::ServiceResult<crate::events::PeerKeyPackageClaimLedgerWriteResult> {
        Ok(
            match self
                .0
                .mls_key_packages()
                .record_peer_claim_terminal(&persistence_peer_claim(record))
                .await?
            {
                soland_storage::PeerKeyPackageClaimLedgerWriteResult::Inserted => {
                    crate::events::PeerKeyPackageClaimLedgerWriteResult::Inserted
                }
                soland_storage::PeerKeyPackageClaimLedgerWriteResult::Existing(row) => {
                    crate::events::PeerKeyPackageClaimLedgerWriteResult::Existing(
                        application_peer_claim(row),
                    )
                }
            },
        )
    }
    async fn revoke_expired_peer_claims(
        &self,
        now_unix_ms: i64,
    ) -> crate::ServiceResult<Vec<String>> {
        Ok(self
            .0
            .mls_key_packages()
            .revoke_expired_peer_claims(now_unix_ms)
            .await?)
    }
    async fn key_packages(&self) -> crate::ServiceResult<Vec<crate::events::MlsKeyPackageState>> {
        Ok(self
            .0
            .mls_key_packages()
            .snapshot_all()
            .await?
            .into_iter()
            .map(application_mls_key_package)
            .collect())
    }
    async fn key_packages_claimed_by_group(
        &self,
        mls_group_id: &str,
    ) -> crate::ServiceResult<Vec<crate::events::MlsKeyPackageState>> {
        Ok(self
            .0
            .mls_key_packages()
            .list_claimed_by_group(mls_group_id)
            .await?
            .into_iter()
            .map(application_mls_key_package)
            .collect())
    }

    async fn retire_actor_keypackages(
        &self,
        actor_id: &str,
        retired_at: i64,
    ) -> crate::ServiceResult<usize> {
        let rows = self.0.mls_key_packages().snapshot_all().await?;
        let mut retired = 0;
        for row in rows.into_iter().filter(|row| {
            row.actor_id == actor_id
                && row.claimed_by_mls_group_id.is_none()
                && row.consumed_at.is_none()
        }) {
            if self
                .0
                .mls_key_packages()
                .try_claim(soland_storage::MlsKeyPackageClaim {
                    id: &row.id,
                    mls_group_id: "revoked",
                    intended_realm_id: None,
                    ssk_generation: None,
                    device_authorize_event_id: None,
                    agent_key_authorize_event_id: None,
                    claimed_at: retired_at,
                    claim_expires_at_unix_ms: None,
                })
                .await?
                .is_some()
            {
                retired += 1;
            }
        }
        Ok(retired)
    }

    async fn enqueue_welcome(
        &self,
        welcome: crate::events::MlsWelcomeState,
    ) -> crate::ServiceResult<()> {
        self.0
            .mls_welcomes()
            .enqueue(&persistence_mls_welcome(welcome))
            .await?;
        Ok(())
    }
}

fn persistence_mls_welcome(
    welcome: crate::events::MlsWelcomeState,
) -> soland_storage::MlsWelcomeRecord {
    soland_storage::MlsWelcomeRecord {
        id: welcome.id,
        group_id: welcome.group_id,
        recipient_actor_id: welcome.recipient_actor_id,
        recipient_device_id: welcome.recipient_device_id,
        welcome_bytes: welcome.welcome_bytes,
        key_package_id: welcome.key_package_id,
        epoch: welcome.epoch,
        commit_ref: welcome.commit_ref,
        governance_binding: welcome.governance_binding,
        enqueued_at: welcome.enqueued_at,
        delivered_at: welcome.delivered_at,
    }
}

#[async_trait::async_trait]
impl crate::events::RealmMetadataPort for PersistenceRealmMetadata {
    async fn realm_metadata(
        &self,
        realm_id: &str,
    ) -> crate::ServiceResult<Option<crate::events::RealmMetadata>> {
        Ok(self
            .0
            .realm_meta()
            .get(realm_id)
            .await?
            .map(application_realm_metadata))
    }

    async fn realm_metadata_list(
        &self,
    ) -> crate::ServiceResult<Vec<(String, crate::events::RealmMetadata)>> {
        Ok(self
            .0
            .realm_meta()
            .list()
            .await?
            .into_iter()
            .map(|(realm_id, metadata)| (realm_id, application_realm_metadata(metadata)))
            .collect())
    }

    async fn store_realm_metadata(
        &self,
        realm_id: &str,
        metadata: crate::events::RealmMetadata,
    ) -> crate::ServiceResult<()> {
        self.0
            .realm_meta()
            .put(realm_id, &persistence_realm_metadata(metadata))
            .await?;
        Ok(())
    }

    async fn delete_realm_metadata(&self, realm_id: &str) -> crate::ServiceResult<()> {
        self.0.realm_meta().delete(realm_id).await?;
        Ok(())
    }
}

fn application_realm_metadata(
    metadata: soland_storage::RealmMetaRecord,
) -> crate::events::RealmMetadata {
    crate::events::RealmMetadata {
        owner: metadata.owner,
        deleted: metadata.deleted,
        discoverability: metadata.discoverability,
        history_visibility: metadata.history_visibility,
        history_sharing_policy: metadata.history_sharing_policy,
        history_sharing_policy_digest: metadata.history_sharing_policy_digest,
        preview_policy: metadata.preview_policy,
        preview_policy_digest: metadata.preview_policy_digest,
        asset_privacy_policy: metadata.asset_privacy_policy,
        asset_privacy_policy_digest: metadata.asset_privacy_policy_digest,
        encryption_profile: metadata.encryption_profile,
        plaintext_visible_services: metadata.plaintext_visible_services,
        plaintext_visible_service_classes: metadata.plaintext_visible_service_classes,
        minimal_metadata_realm: metadata.minimal_metadata_realm,
        created_at: metadata.created_at,
        updated_at: metadata.updated_at,
    }
}
fn persistence_realm_metadata(
    metadata: crate::events::RealmMetadata,
) -> soland_storage::RealmMetaRecord {
    soland_storage::RealmMetaRecord {
        owner: metadata.owner,
        deleted: metadata.deleted,
        discoverability: metadata.discoverability,
        history_visibility: metadata.history_visibility,
        history_sharing_policy: metadata.history_sharing_policy,
        history_sharing_policy_digest: metadata.history_sharing_policy_digest,
        preview_policy: metadata.preview_policy,
        preview_policy_digest: metadata.preview_policy_digest,
        asset_privacy_policy: metadata.asset_privacy_policy,
        asset_privacy_policy_digest: metadata.asset_privacy_policy_digest,
        encryption_profile: metadata.encryption_profile,
        plaintext_visible_services: metadata.plaintext_visible_services,
        plaintext_visible_service_classes: metadata.plaintext_visible_service_classes,
        minimal_metadata_realm: metadata.minimal_metadata_realm,
        created_at: metadata.created_at,
        updated_at: metadata.updated_at,
    }
}

fn application_realm_invite(
    record: soland_storage::RealmInviteRecord,
) -> crate::events::RealmInviteState {
    crate::events::RealmInviteState {
        invite_id: record.invite_id,
        realm_id: record.realm_id,
        inviter: record.inviter,
        invitee: record.invitee,
        invite_delivery_target: record.invite_delivery_target,
        introduction_evidence_digest: record.introduction_evidence_digest,
        third_party_id: record.third_party_id,
        join_rule_snapshot: record.join_rule_snapshot,
        invite_token: record.invite_token,
        status: record.status,
        claim_nonces: record.claim_nonces,
        expires_at: record.expires_at,
        created_at: record.created_at,
        updated_at: record.updated_at,
    }
}

fn persistence_realm_invite(
    record: crate::events::RealmInviteState,
) -> soland_storage::RealmInviteRecord {
    soland_storage::RealmInviteRecord {
        invite_id: record.invite_id,
        realm_id: record.realm_id,
        inviter: record.inviter,
        invitee: record.invitee,
        invite_delivery_target: record.invite_delivery_target,
        introduction_evidence_digest: record.introduction_evidence_digest,
        third_party_id: record.third_party_id,
        join_rule_snapshot: record.join_rule_snapshot,
        invite_token: record.invite_token,
        status: record.status,
        claim_nonces: record.claim_nonces,
        expires_at: record.expires_at,
        created_at: record.created_at,
        updated_at: record.updated_at,
    }
}

fn application_invite_locator(
    record: soland_storage::InviteLocatorRecord,
) -> crate::events::InviteLocatorState {
    crate::events::InviteLocatorState {
        locator_id: record.locator_id,
        token_digest: record.token_digest,
        subject_id: record.subject_id,
        recipient_service_id: record.recipient_service_id,
        issued_at: record.issued_at,
        expires_at: record.expires_at,
        one_time_use: record.one_time_use,
        display_hint: record.display_hint,
        revoked_at: record.revoked_at,
        consumed_at: record.consumed_at,
    }
}

fn persistence_invite_locator(
    record: &crate::events::InviteLocatorState,
) -> soland_storage::InviteLocatorRecord {
    soland_storage::InviteLocatorRecord {
        locator_id: record.locator_id.clone(),
        token_digest: record.token_digest.clone(),
        subject_id: record.subject_id.clone(),
        recipient_service_id: record.recipient_service_id.clone(),
        issued_at: record.issued_at,
        expires_at: record.expires_at,
        one_time_use: record.one_time_use,
        display_hint: record.display_hint.clone(),
        revoked_at: record.revoked_at,
        consumed_at: record.consumed_at,
    }
}

#[async_trait::async_trait]
impl crate::events::RealmInvitePort for PersistenceRealmInvites {
    async fn get(
        &self,
        invite_id: &str,
    ) -> crate::ServiceResult<Option<crate::events::RealmInviteState>> {
        Ok(self
            .0
            .realm_invites()
            .get(invite_id)
            .await?
            .map(application_realm_invite))
    }

    async fn put(&self, record: crate::events::RealmInviteState) -> crate::ServiceResult<()> {
        Ok(self
            .0
            .realm_invites()
            .put(persistence_realm_invite(record))
            .await?)
    }

    async fn snapshot_all(&self) -> crate::ServiceResult<Vec<crate::events::RealmInviteState>> {
        Ok(self
            .0
            .realm_invites()
            .snapshot_all()
            .await?
            .into_iter()
            .map(application_realm_invite)
            .collect())
    }
}

#[async_trait::async_trait]
impl crate::events::InviteLocatorPort for PersistenceRealmInvites {
    async fn insert(
        &self,
        record: &crate::events::InviteLocatorState,
        active_limit: usize,
        now: chrono::DateTime<chrono::Utc>,
    ) -> crate::ServiceResult<crate::events::InviteLocatorInsertResult> {
        Ok(
            match self
                .0
                .invite_locators()
                .insert(&persistence_invite_locator(record), active_limit, now)
                .await?
            {
                soland_storage::InviteLocatorInsertOutcome::Inserted => {
                    crate::events::InviteLocatorInsertResult::Inserted
                }
                soland_storage::InviteLocatorInsertOutcome::ActiveLimitReached => {
                    crate::events::InviteLocatorInsertResult::ActiveLimitReached
                }
            },
        )
    }

    async fn resolve_and_consume(
        &self,
        token_digest: &str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> crate::ServiceResult<Option<crate::events::InviteLocatorState>> {
        Ok(self
            .0
            .invite_locators()
            .resolve_and_consume(token_digest, now)
            .await?
            .map(application_invite_locator))
    }

    async fn rotate(
        &self,
        subject_id: &str,
        old_locator_id: &str,
        mutation: &crate::events::InviteLocatorRotateCommand,
        now: chrono::DateTime<chrono::Utc>,
    ) -> crate::ServiceResult<Option<crate::events::InviteLocatorState>> {
        let mutation = soland_storage::InviteLocatorRotateMutation {
            locator_id: mutation.locator_id.clone(),
            token_digest: mutation.token_digest.clone(),
            issued_at: mutation.issued_at,
            ttl_seconds: mutation.ttl_seconds,
            one_time_use: mutation.one_time_use,
            display_hint: mutation.display_hint.clone(),
        };
        Ok(self
            .0
            .invite_locators()
            .rotate(subject_id, old_locator_id, &mutation, now)
            .await?
            .map(application_invite_locator))
    }

    async fn revoke(
        &self,
        subject_id: &str,
        locator_id: &str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> crate::ServiceResult<Option<crate::events::InviteLocatorState>> {
        Ok(self
            .0
            .invite_locators()
            .revoke(subject_id, locator_id, now)
            .await?
            .map(application_invite_locator))
    }
}

#[async_trait::async_trait]
impl crate::events::EventCommitPort for PersistenceEventCommitter {
    async fn commit_accepted_event(
        &self,
        command: crate::events::CommitAcceptedEventCommand,
    ) -> crate::ServiceResult<crate::events::CommitAcceptedEventResult> {
        let outcome = self
            .0
            .commit_event(persistence_event_commit_request(command))
            .await?;
        Ok(crate::events::CommitAcceptedEventResult {
            projections_inserted: outcome.projections_inserted,
            deliveries_inserted: outcome.outbox_inserted,
        })
    }

    async fn commit_accepted_event_batch(
        &self,
        command: crate::events::CommitAcceptedEventBatchCommand,
    ) -> crate::ServiceResult<crate::events::CommitAcceptedEventResult> {
        let outcome = self
            .0
            .commit_event_batch(soland_storage::EventBatchCommitRequest {
                events: command
                    .events
                    .into_iter()
                    .map(persistence_event_commit_request)
                    .collect(),
                applet_ghosts: command.applet_ghosts.map(|mutation| {
                    soland_storage::AppletGhostCommit {
                        applet_id: mutation.applet_id,
                        ghost: mutation.ghost,
                    }
                }),
            })
            .await?;
        Ok(crate::events::CommitAcceptedEventResult {
            projections_inserted: outcome.projections_inserted,
            deliveries_inserted: outcome.outbox_inserted,
        })
    }
}

#[derive(Clone)]
pub struct PersistenceEventServices {
    pub events: EventService,
    pub queries: EventQueryService,
    pub mls_commits: MlsCommitQueryService,
    pub mls_key_packages: MlsKeyPackageService,
    pub realm_queries: RealmQueryService,
    pub realm_invites: RealmInviteService,
}

pub fn build_persistence_event_services(
    persistence: Arc<dyn PersistenceStore>,
    projected_operations: Arc<dyn ProjectedOperationPersistencePort>,
) -> PersistenceEventServices {
    let reader = || Arc::new(PersistenceEventReader(persistence.clone()));
    PersistenceEventServices {
        events: EventService::new(Arc::new(PersistenceEventCommitter(persistence.clone()))),
        queries: EventQueryService::new(
            reader(),
            reader(),
            reader(),
            Arc::new(PersistenceProjectionWriter {
                persistence: persistence.clone(),
                projected_operations,
            }),
        ),
        mls_commits: MlsCommitQueryService::new(Arc::new(PersistenceMlsCommitReader(
            persistence.clone(),
        ))),
        mls_key_packages: MlsKeyPackageService::new(Arc::new(PersistenceMlsKeyPackageMaintenance(
            persistence.clone(),
        ))),
        realm_queries: RealmQueryService::new(Arc::new(PersistenceRealmMetadata(
            persistence.clone(),
        ))),
        realm_invites: RealmInviteService::new(
            Arc::new(PersistenceRealmInvites(persistence.clone())),
            Arc::new(PersistenceRealmInvites(persistence)),
        ),
    }
}
