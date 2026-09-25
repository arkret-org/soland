use std::sync::Arc;

use serde_json::Value;
use soland_storage::*;

use crate::events::*;

#[derive(Clone)]
struct PersistenceEventCommitter(Arc<dyn PersistenceStore>);
struct PersistenceEventReader(Arc<dyn PersistenceStore>);
struct PersistenceProjectionWriter {
    persistence: Arc<dyn PersistenceStore>,
}
struct PersistenceMlsCommitReader(Arc<dyn PersistenceStore>);
struct PersistenceMlsKeyPackageMaintenance(Arc<dyn PersistenceStore>);
struct PersistenceRealmMetadata(Arc<dyn PersistenceStore>);
struct PersistenceRealmInvites(Arc<dyn PersistenceStore>);

fn application_projected_event(
    event: soland_storage::ProjectionEventRecord,
) -> crate::events::ProjectedEvent {
    crate::events::ProjectedEvent {
        event_id: event.event_id,
        realm_id: event.realm_id,
        event_kind: arkret_wire::EventKind::from_wire(&event.event_kind),
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
        event_kind: event.event_kind.as_str().to_owned(),
        operation_kind: event.operation_kind,
        operation_id: event.operation_id,
        sender: event.sender,
        payload: event.payload,
        created_at: event.created_at,
        received_at: event.received_at,
    }
}

fn persistence_outbox_row(
    delivery: crate::federation::FederationDeliveryRecord,
) -> soland_storage::FederationOutboxRecord {
    let coalescing_key = delivery.coalescing_key.clone();
    let coalescing_position = delivery.coalescing_position;
    let mut persisted = match delivery.realm_fanout {
        Some(binding) => soland_storage::FederationOutboxRecord::realm_fanout(
            soland_storage::RealmFanoutOutboxInput {
                id: delivery.id,
                peer_id: delivery.peer_id,
                peer_url: delivery.peer_url,
                endpoint: delivery.endpoint,
                idempotency_key: delivery.idempotency_key,
                payload_json: delivery.payload_json,
                binding,
                created_at: delivery.created_at,
            },
        ),
        None => soland_storage::FederationOutboxRecord::pending(
            delivery.id,
            delivery.peer_id,
            delivery
                .peer_url
                .expect("generic federation delivery requires a route"),
            delivery.endpoint,
            delivery.idempotency_key,
            delivery.payload_json,
            delivery.created_at,
        ),
    };
    persisted.coalescing_key = coalescing_key;
    persisted.coalescing_position = coalescing_position;
    persisted
}

fn persistence_event_commit_request(
    command: crate::events::CommitAcceptedEventCommand,
) -> soland_storage::EventCommitRequest {
    soland_storage::EventCommitRequest {
        authority_commit: command.authority_commit,
        self_producer_guard: command.self_producer_guard,
        forwarded_producer_evidence: command.forwarded_producer_evidence,
        event: command.event,
        parent_membership_admission: command.parent_membership_admission,
        contact_projection: command.contact_projection,
        consent_projection: command.consent_projection.map(|commit| {
            soland_storage::ConsentProjectionCommit {
                grant: commit.grant,
                holder_quarantine: commit.holder_quarantine.map(|cas| {
                    soland_storage::AccountDataCasCommit {
                        record: soland_storage::AccountDataRecord {
                            actor: cas.record.actor_id,
                            account_data_key: cas.record.account_data_key,
                            revision: cas.record.revision,
                            payload: cas.record.payload,
                            tombstone: cas.record.tombstone,
                            updated_at: cas.record.updated_at,
                        },
                        expected_revision: cas.expected_revision,
                        conflict_code: cas.conflict_code,
                    }
                }),
            }
        }),
        device_revocation_transition: command.device_revocation_transition,
        device_revocation_gate: command.device_revocation_gate,
        projections: command
            .projections
            .into_iter()
            .map(persistence_projected_event)
            .collect(),
        idempotency: command
            .idempotency
            .map(|record| soland_storage::IdempotencyRecord {
                authenticated_actor: record.authenticated_actor,
                operation_id: record.operation_id,
                idempotency_key: record.key,
                request_hash: record.request_hash,
                response_status: record.status,
                response_body: record.body,
                created_at: record.created_at,
                expires_at: record.expires_at,
            }),
        outbox: command
            .deliveries
            .into_iter()
            .map(persistence_outbox_row)
            .collect(),
        realm_fanout_source: command.realm_fanout_source,
    }
}

#[async_trait::async_trait]
impl crate::events::EventReadPort for PersistenceEventReader {
    async fn direct_conversation_founding_slot(
        &self,
        founder_id: &str,
        trust_domain_id: &str,
        pair_key: &str,
    ) -> crate::ServiceResult<Option<soland_storage::DirectConversationFoundingSlotRecord>> {
        Ok(self
            .0
            .events()
            .direct_conversation_founding_slot(founder_id, trust_domain_id, pair_key)
            .await?)
    }
    async fn canonical_event(
        &self,
        event_id: &str,
    ) -> crate::ServiceResult<Option<crate::events::AcceptedEvent>> {
        Ok(self.0.events().get(event_id).await?)
    }
    async fn has_canonical_event(&self, event_id: &str) -> crate::ServiceResult<bool> {
        Ok(self.0.events().contains(event_id).await?)
    }
    async fn canonical_events(&self) -> crate::ServiceResult<Vec<crate::events::AcceptedEvent>> {
        Ok(self.0.events().snapshot_all().await?)
    }
    async fn canonical_events_for_actor(
        &self,
        actor_id: &str,
    ) -> crate::ServiceResult<Vec<crate::events::AcceptedEvent>> {
        Ok(self.0.events().list_for_actor(actor_id).await?)
    }
    async fn franking_proofs_for_target(
        &self,
        realm_id: &str,
        received_by: &arkret_identifiers::DidCoreId,
        target_event_id: &str,
    ) -> crate::ServiceResult<Vec<crate::events::AcceptedEvent>> {
        Ok(self
            .0
            .events()
            .franking_proofs_for_target(realm_id, received_by, target_event_id)
            .await?)
    }
    async fn identity_anchor_account_slot(
        &self,
        account_id: &arkret_wire::AccountId,
    ) -> crate::ServiceResult<Option<soland_storage::IdentityAnchorAccountSlot>> {
        Ok(self
            .0
            .events()
            .identity_anchor_account_slot(account_id)
            .await?)
    }
    async fn realm_event_stats(
        &self,
        realm_id: &str,
    ) -> crate::ServiceResult<soland_storage::RealmEventStats> {
        Ok(self.0.events().realm_event_stats(realm_id).await?)
    }
    async fn realm_events_newest_first(
        &self,
        realm_id: &str,
    ) -> crate::ServiceResult<Vec<crate::events::AcceptedEvent>> {
        Ok(self.0.events().realm_events_newest_first(realm_id).await?)
    }

    async fn accepted_event(
        &self,
        event_id: &str,
    ) -> crate::ServiceResult<Option<crate::events::AcceptedEvent>> {
        Ok(self.0.events().get(event_id).await?)
    }

    async fn accepted_events(&self) -> crate::ServiceResult<Vec<crate::events::AcceptedEvent>> {
        Ok(self.0.events().snapshot_all().await?)
    }

    async fn projected_event(
        &self,
        event_id: &str,
    ) -> crate::ServiceResult<Option<crate::events::ProjectedEvent>> {
        Ok(self
            .0
            .projection_events()
            .get(event_id)
            .await?
            .map(application_projected_event))
    }

    async fn projected_event_by_operation_id(
        &self,
        operation_id: &str,
    ) -> crate::ServiceResult<Option<crate::events::ProjectedEvent>> {
        Ok(self
            .0
            .projection_events()
            .get_by_operation_id(operation_id)
            .await?
            .map(application_projected_event))
    }

    async fn projected_events_for_realm(
        &self,
        realm_id: &str,
    ) -> crate::ServiceResult<Vec<crate::events::ProjectedEvent>> {
        Ok(self
            .0
            .projection_events()
            .snapshot_realm(realm_id)
            .await?
            .into_iter()
            .map(application_projected_event)
            .collect())
    }

    async fn projected_events_for_actor(
        &self,
        actor_id: &str,
    ) -> crate::ServiceResult<Vec<crate::events::ProjectedEvent>> {
        Ok(self
            .0
            .projection_events()
            .snapshot_actor(actor_id)
            .await?
            .into_iter()
            .map(application_projected_event)
            .collect())
    }

    async fn projected_events_for_kind(
        &self,
        event_kind: arkret_wire::EventKind,
    ) -> crate::ServiceResult<Vec<crate::events::ProjectedEvent>> {
        Ok(self
            .0
            .projection_events()
            .snapshot_kind(event_kind.as_str())
            .await?
            .into_iter()
            .map(application_projected_event)
            .collect())
    }

    async fn append_projected_event(
        &self,
        event: crate::events::ProjectedEvent,
    ) -> crate::ServiceResult<crate::events::ProjectedEventAppendResult> {
        Ok(self
            .0
            .projection_events()
            .append(persistence_projected_event(event))
            .await?)
    }

    async fn accepted_events_for_actor(
        &self,
        actor_id: &str,
    ) -> crate::ServiceResult<Vec<crate::events::AcceptedEvent>> {
        Ok(self.0.events().list_for_actor(actor_id).await?)
    }
}

#[async_trait::async_trait]
impl crate::events::MessagePort for PersistenceEventReader {
    async fn message(
        &self,
        event_id: &str,
    ) -> crate::ServiceResult<Option<crate::events::MessageState>> {
        Ok(self.0.messages().get(event_id).await?)
    }

    async fn store_message(
        &self,
        message: crate::events::MessageState,
    ) -> crate::ServiceResult<()> {
        self.0.messages().put(&message).await?;
        Ok(())
    }

    async fn messages_for_realm(
        &self,
        realm_id: &str,
        limit: usize,
    ) -> crate::ServiceResult<Vec<crate::events::MessageState>> {
        Ok(self.0.messages().list_for_realm(realm_id, limit).await?)
    }
}

#[async_trait::async_trait]
impl crate::events::AppletPort for PersistenceEventReader {
    async fn applet_identity(
        &self,
        applet_id: &str,
        target_station_id: &str,
    ) -> crate::ServiceResult<Option<Value>> {
        Ok(self
            .0
            .applets()
            .get_identity(applet_id, target_station_id)
            .await?)
    }

    async fn applet(
        &self,
        applet_id: &str,
        effective_scope_key: &str,
    ) -> crate::ServiceResult<Option<Value>> {
        Ok(self.0.applets().get(applet_id, effective_scope_key).await?)
    }
    async fn applets(&self) -> crate::ServiceResult<Vec<Value>> {
        Ok(self.0.applets().list().await?)
    }
    async fn compare_and_swap_applet(
        &self,
        applet_id: &str,
        effective_scope_key: &str,
        expected: &Value,
        replacement: Value,
    ) -> crate::ServiceResult<bool> {
        Ok(self
            .0
            .applets()
            .compare_and_swap(applet_id, effective_scope_key, expected, replacement)
            .await?)
    }
    async fn fence_applet_installation(
        &self,
        applet_id: &str,
        effective_scope_key: &str,
        target_station_id: &str,
        expected: &Value,
        replacement: Value,
        fenced_at: chrono::DateTime<chrono::Utc>,
    ) -> crate::ServiceResult<soland_storage::AppletInstallationFenceOutcome> {
        Ok(self
            .0
            .applets()
            .fence_installation(
                applet_id,
                effective_scope_key,
                target_station_id,
                expected,
                replacement,
                fenced_at,
            )
            .await?)
    }
    async fn begin_applet_transaction(
        &self,
        replay: crate::events::AppletTransactionReplayState,
    ) -> crate::ServiceResult<crate::events::AppletTransactionReplayResult> {
        Ok(self.0.applets().begin_transaction_replay(replay).await?)
    }
    async fn complete_applet_transaction(
        &self,
        applet_id: &str,
        source_id: &str,
        idempotency_key: &str,
        outcome: Value,
    ) -> crate::ServiceResult<()> {
        self.0
            .applets()
            .complete_transaction_replay(applet_id, source_id, idempotency_key, outcome)
            .await?;
        Ok(())
    }

    async fn issue_applet_authoring_preview(
        &self,
        candidate: crate::events::AppletAuthoringPreviewState,
    ) -> crate::ServiceResult<crate::events::AppletAuthoringPreviewState> {
        Ok(self.0.applets().issue_authoring_preview(candidate).await?)
    }

    async fn current_applet_authoring_preview(
        &self,
        subject_key: &str,
    ) -> crate::ServiceResult<Option<crate::events::AppletAuthoringPreviewState>> {
        Ok(self
            .0
            .applets()
            .current_authoring_preview(subject_key)
            .await?)
    }
}

#[async_trait::async_trait]
impl crate::events::ProjectionWritePort for PersistenceProjectionWriter {
    async fn store_space_container_projection(
        &self,
        record: &crate::events::SpaceContainerProjectionRecord,
    ) -> crate::ServiceResult<()> {
        self.persistence
            .space_container_projections()
            .put(record)
            .await?;
        Ok(())
    }

    async fn store_strand_projection(
        &self,
        record: &crate::events::StrandProjectionRecord,
    ) -> crate::ServiceResult<()> {
        self.persistence.strand_projections().put(record).await?;
        Ok(())
    }

    async fn store_circle_projection(
        &self,
        record: &crate::events::CircleProjectionRecord,
        members: &[crate::events::CircleMemberProjectionRecord],
    ) -> crate::ServiceResult<()> {
        let circles = self.persistence.circle_projections();
        circles.put(record).await?;
        circles.put_members(&record.circle_id, members).await?;
        Ok(())
    }

    async fn store_strand_watch_projection(
        &self,
        record: &crate::events::StrandWatchProjectionRecord,
    ) -> crate::ServiceResult<()> {
        self.persistence
            .strand_watch_projections()
            .put(record)
            .await?;
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
            fields: encode_mls_contract(&record.fields, "Morph fields")?,
            schema_refs: encode_mls_contract(&record.schema_refs, "Morph schema_refs")?,
            facets: encode_mls_contract(&record.facets, "Morph facets")?,
            versions: encode_mls_contract(&record.versions, "Morph versions")?,
            content: record
                .content
                .as_ref()
                .map(|content| encode_mls_contract(content, "Morph content"))
                .transpose()?,
            encrypted_content: record.encrypted_content.clone(),
            state: record.state.clone(),
            state_changed_at: record.state_changed_at,
            stage: record.stage.clone(),
            stage_changed_at: record.stage_changed_at,
            created_by: record.created_by.clone(),
            created_at: record.created_at,
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
        self.persistence
            .realm_organization_statements()
            .put(record)
            .await?;
        Ok(())
    }
}

#[async_trait::async_trait]
impl crate::events::MlsCommitReadPort for PersistenceMlsCommitReader {
    async fn commits(&self) -> crate::ServiceResult<Vec<crate::events::MlsCommitState>> {
        self.0
            .mls_commits()
            .snapshot_all()
            .await?
            .into_iter()
            .map(application_mls_commit)
            .collect()
    }

    async fn commit(
        &self,
        effective_scope: &arkret_wire::ScopeRef,
        group_id: &str,
    ) -> crate::ServiceResult<Option<crate::events::MlsCommitState>> {
        let effective_scope = encode_mls_contract(effective_scope, "effective_scope")?;
        Ok(self
            .0
            .mls_commits()
            .get(&effective_scope, group_id)
            .await?
            .map(application_mls_commit)
            .transpose()?)
    }

    async fn initialize_group(
        &self,
        command: crate::events::InitializeMlsGroupCommand,
    ) -> crate::ServiceResult<Option<crate::events::MlsCommitState>> {
        let effective_scope = encode_mls_contract(&command.effective_scope, "effective_scope")?;
        let governance_binding =
            encode_mls_contract(&command.governance_binding, "governance_binding")?;
        Ok(self
            .0
            .mls_commits()
            .initialize_genesis(soland_storage::MlsCommitGenesis {
                effective_scope: &effective_scope,
                group_id: &command.group_id,
                leader_actor_id: &command.leader_actor_id,
                creator_device_id: &command.creator_device_id,
                genesis_event_ref: &command.genesis_event_ref,
                governance_binding: &governance_binding,
                committed_at: command.committed_at,
            })
            .await?
            .map(application_mls_commit)
            .transpose()?)
    }

    async fn advance_epoch(
        &self,
        command: crate::events::AdvanceMlsEpochCommand,
    ) -> crate::ServiceResult<Option<crate::events::MlsCommitState>> {
        let effective_scope = encode_mls_contract(&command.effective_scope, "effective_scope")?;
        let governance_binding =
            encode_mls_contract(&command.governance_binding, "governance_binding")?;
        Ok(self
            .0
            .mls_commits()
            .try_bump(
                command.expected_previous_epoch,
                soland_storage::MlsCommitEpochAdvance {
                    effective_scope: &effective_scope,
                    group_id: &command.group_id,
                    leader_actor_id: &command.leader_actor_id,
                    governance_binding: &governance_binding,
                    accepted_commit_ref: &command.accepted_commit_ref,
                    committed_at: command.committed_at,
                },
            )
            .await?
            .map(application_mls_commit)
            .transpose()?)
    }
}

fn application_mls_commit(
    commit: soland_storage::MlsCommitEpochRecord,
) -> crate::ServiceResult<crate::events::MlsCommitState> {
    Ok(crate::events::MlsCommitState {
        group_id: commit.group_id,
        effective_scope: decode_mls_contract(commit.effective_scope, "effective_scope")?,
        epoch: commit.epoch,
        creator_device_id: commit.creator_device_id,
        genesis_event_ref: commit.genesis_event_ref,
        governance_binding: decode_mls_contract(commit.governance_binding, "governance_binding")?,
        accepted_commit_ref: commit.accepted_commit_ref,
    })
}

fn encode_mls_contract<T: serde::Serialize>(
    value: &T,
    field: &str,
) -> crate::ServiceResult<serde_json::Value> {
    serde_json::to_value(value).map_err(|error| {
        crate::ServiceError::Internal(format!("MLS {field} encode failed: {error}"))
    })
}

fn decode_mls_contract<T: serde::de::DeserializeOwned>(
    value: serde_json::Value,
    field: &str,
) -> crate::ServiceResult<T> {
    serde_json::from_value(value).map_err(|error| {
        crate::ServiceError::Internal(format!("stored MLS {field} is invalid: {error}"))
    })
}

#[async_trait::async_trait]
impl crate::events::MlsKeyPackageMaintenancePort for PersistenceMlsKeyPackageMaintenance {
    async fn store_key_package(
        &self,
        record: &crate::events::MlsKeyPackageState,
    ) -> crate::ServiceResult<bool> {
        Ok(self.0.mls_key_packages().put(record).await?)
    }
    async fn key_package(
        &self,
        id: &str,
    ) -> crate::ServiceResult<Option<crate::events::MlsKeyPackageState>> {
        Ok(self.0.mls_key_packages().get(id).await?)
    }
    async fn key_package_by_ref(
        &self,
        keypackage_ref: &str,
    ) -> crate::ServiceResult<Option<crate::events::MlsKeyPackageState>> {
        Ok(self.0.mls_key_packages().get_by_ref(keypackage_ref).await?)
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
                target: match command.target {
                    crate::events::ClaimMlsKeyPackageTarget::Group(group_id) => {
                        soland_storage::MlsKeyPackageClaimTarget::Group(group_id)
                    }
                    crate::events::ClaimMlsKeyPackageTarget::Retire => {
                        soland_storage::MlsKeyPackageClaimTarget::Retire
                    }
                    crate::events::ClaimMlsKeyPackageTarget::Revoke => {
                        soland_storage::MlsKeyPackageClaimTarget::Revoke
                    }
                },
                intended_realm_id: command.intended_realm_id,
                device_authorize_event_id: command.device_authorize_event_id,
                agent_key_authorize_event_id: command.agent_key_authorize_event_id,
                device_revocation_gate: command.device_revocation_gate.cloned(),
                claimed_at: command.claimed_at,
                claim_expires_at_unix_ms: command.claim_expires_at_unix_ms,
            })
            .await?)
    }
    async fn consume_key_package_claim(
        &self,
        id: &str,
        mls_group_id: &str,
        now_unix_ms: i64,
        peer_consume_receipt: Option<&Value>,
    ) -> crate::ServiceResult<Option<crate::events::MlsKeyPackageState>> {
        Ok(self
            .0
            .mls_key_packages()
            .consume_claim(id, mls_group_id, now_unix_ms, peer_consume_receipt)
            .await?)
    }
    async fn peer_claim(
        &self,
        source_id: &str,
        claim_request_id: &str,
    ) -> crate::ServiceResult<Option<crate::events::PeerKeyPackageClaimLedgerState>> {
        Ok(self
            .0
            .mls_key_packages()
            .get_peer_claim(source_id, claim_request_id)
            .await?)
    }
    async fn peer_claim_by_keypackage_id(
        &self,
        keypackage_id: &str,
    ) -> crate::ServiceResult<Option<crate::events::PeerKeyPackageClaimLedgerState>> {
        Ok(self
            .0
            .mls_key_packages()
            .get_peer_claim_by_keypackage_id(keypackage_id)
            .await?)
    }
    async fn claim_peer_key_package(
        &self,
        attempt: crate::events::PeerKeyPackageClaimCommand<'_>,
    ) -> crate::ServiceResult<crate::events::PeerKeyPackageClaimResult> {
        Ok(self
            .0
            .mls_key_packages()
            .try_claim_peer(soland_storage::PeerKeyPackageClaimAttempt {
                keypackage_id: attempt.keypackage_id,
                mls_group_id: attempt.mls_group_id,
                device_authorize_event_id: attempt.device_authorize_event_id,
                agent_key_authorize_event_id: attempt.agent_key_authorize_event_id,
                device_revocation_gate: attempt.device_revocation_gate.cloned(),
                claimed_at_unix_ms: attempt.claimed_at_unix_ms,
                claim_expires_at_unix_ms: attempt.claim_expires_at_unix_ms,
                ledger: attempt.ledger,
            })
            .await?)
    }
    async fn store_peer_claim_terminal(
        &self,
        record: &crate::events::PeerKeyPackageClaimLedgerState,
    ) -> crate::ServiceResult<crate::events::PeerKeyPackageClaimLedgerWriteResult> {
        Ok(self
            .0
            .mls_key_packages()
            .record_peer_claim_terminal(record)
            .await?)
    }
    async fn attach_peer_claim_terminal_receipt(
        &self,
        source_id: &str,
        claim_request_id: &str,
        request_digest: &str,
        terminal_receipt: &Value,
        updated_at: i64,
    ) -> crate::ServiceResult<Option<crate::events::PeerKeyPackageClaimLedgerState>> {
        Ok(self
            .0
            .mls_key_packages()
            .attach_peer_claim_terminal_receipt(
                source_id,
                claim_request_id,
                request_digest,
                terminal_receipt,
                updated_at,
            )
            .await?)
    }
    async fn attach_peer_claim_consume_receipt(
        &self,
        source_id: &str,
        claim_request_id: &str,
        request_digest: &str,
        consume_receipt: &Value,
        now_unix_ms: i64,
    ) -> crate::ServiceResult<Option<crate::events::PeerKeyPackageClaimLedgerState>> {
        Ok(self
            .0
            .mls_key_packages()
            .attach_peer_claim_consume_receipt(
                source_id,
                claim_request_id,
                request_digest,
                consume_receipt,
                now_unix_ms,
            )
            .await?)
    }
    async fn transition_peer_claim_consumed(
        &self,
        source_id: &str,
        claim_request_id: &str,
        request_digest: &str,
        expected_outcome: &Value,
        consume_receipt: &Value,
        consumed_at_unix_ms: i64,
    ) -> crate::ServiceResult<Option<crate::events::PeerKeyPackageClaimLedgerState>> {
        Ok(self
            .0
            .mls_key_packages()
            .transition_peer_claim_consumed(
                source_id,
                claim_request_id,
                request_digest,
                expected_outcome,
                consume_receipt,
                consumed_at_unix_ms,
            )
            .await?)
    }
    async fn transition_peer_claim_terminal(
        &self,
        transition: PeerClaimTerminalTransitionCommand<'_>,
    ) -> crate::ServiceResult<Option<crate::events::PeerKeyPackageClaimLedgerState>> {
        Ok(self
            .0
            .mls_key_packages()
            .transition_peer_claim_terminal(soland_storage::PeerClaimTerminalTransition {
                source_id: transition.source_id,
                claim_request_id: transition.claim_request_id,
                request_digest: transition.request_digest,
                expected_outcome: transition.expected_outcome,
                terminal_state: transition.terminal_state,
                terminal_receipt: transition.terminal_receipt,
                now_unix_ms: transition.now_unix_ms,
            })
            .await?)
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
        Ok(self.0.mls_key_packages().snapshot_all().await?)
    }
    async fn key_packages_claimed_by_group(
        &self,
        mls_group_id: &str,
    ) -> crate::ServiceResult<Vec<crate::events::MlsKeyPackageState>> {
        Ok(self
            .0
            .mls_key_packages()
            .list_claimed_by_group(mls_group_id)
            .await?)
    }

    async fn retire_owner_account_keypackages(
        &self,
        owner_account_pk: soland_storage::AccountPk,
        retired_at: i64,
    ) -> crate::ServiceResult<usize> {
        let rows = self.0.mls_key_packages().snapshot_all().await?;
        let mut retired = 0;
        for row in rows.into_iter().filter(|row| {
            row.owner_account_pk == owner_account_pk
                && row.claimed_by_mls_group_id.is_none()
                && row.consumed_at.is_none()
        }) {
            if self
                .0
                .mls_key_packages()
                .try_claim(soland_storage::MlsKeyPackageClaim {
                    id: &row.id,
                    target: soland_storage::MlsKeyPackageClaimTarget::Retire,
                    intended_realm_id: None,
                    device_authorize_event_id: None,
                    agent_key_authorize_event_id: None,
                    device_revocation_gate: None,
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
}

#[async_trait::async_trait]
impl crate::events::RealmMetadataPort for PersistenceRealmMetadata {
    async fn realm_metadata(
        &self,
        realm_id: &str,
    ) -> crate::ServiceResult<Option<crate::events::RealmMetadata>> {
        Ok(self.0.realm_meta().get(realm_id).await?)
    }

    async fn realm_metadata_list(
        &self,
    ) -> crate::ServiceResult<Vec<(String, crate::events::RealmMetadata)>> {
        Ok(self.0.realm_meta().list().await?)
    }

    async fn store_realm_metadata(
        &self,
        realm_id: &str,
        metadata: crate::events::RealmMetadata,
    ) -> crate::ServiceResult<()> {
        self.0.realm_meta().put(realm_id, &metadata).await?;
        Ok(())
    }

    async fn delete_realm_metadata(&self, realm_id: &str) -> crate::ServiceResult<()> {
        self.0.realm_meta().delete(realm_id).await?;
        Ok(())
    }
}

#[async_trait::async_trait]
impl crate::events::RealmInvitePort for PersistenceRealmInvites {
    async fn get(
        &self,
        invite_id: &str,
    ) -> crate::ServiceResult<Option<crate::events::RealmInviteState>> {
        Ok(self.0.realm_invites().get(invite_id).await?)
    }

    async fn put(&self, record: crate::events::RealmInviteState) -> crate::ServiceResult<()> {
        Ok(self.0.realm_invites().put(record).await?)
    }

    async fn snapshot_all(&self) -> crate::ServiceResult<Vec<crate::events::RealmInviteState>> {
        Ok(self.0.realm_invites().snapshot_all().await?)
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
        Ok(self
            .0
            .invite_locators()
            .insert(record, active_limit, now)
            .await?)
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
            .await?)
    }

    async fn rotate(
        &self,
        subject_id: &str,
        old_locator_id: &str,
        mutation: &crate::events::InviteLocatorRotateCommand,
        now: chrono::DateTime<chrono::Utc>,
    ) -> crate::ServiceResult<Option<crate::events::InviteLocatorState>> {
        Ok(self
            .0
            .invite_locators()
            .rotate(subject_id, old_locator_id, mutation, now)
            .await?)
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
            .await?)
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
                franking_replay_nonce: command.franking_replay_nonce,
                applet_record: command.applet_record,
                applet_authoring_preview: command.applet_authoring_preview,
                agent_membership_cascade: command.agent_membership_cascade,
            })
            .await?;
        Ok(crate::events::CommitAcceptedEventResult {
            projections_inserted: outcome.projections_inserted,
            deliveries_inserted: outcome.outbox_inserted,
        })
    }
}

#[derive(Clone)]
pub struct PersistencePublicationEvidence(Arc<dyn PersistenceStore>);

#[async_trait::async_trait]
impl crate::events::PublicationEvidencePort for PersistencePublicationEvidence {
    async fn store_publication_evidence(
        &self,
        record: soland_storage::PublicationEvidenceRecord,
    ) -> crate::ServiceResult<soland_storage::PublicationEvidenceRecord> {
        Ok(self.0.publication_evidence().put_if_absent(record).await?)
    }

    async fn publication_evidence(
        &self,
        event_id: &arkret_wire::EventId,
    ) -> crate::ServiceResult<Option<soland_storage::PublicationEvidenceRecord>> {
        Ok(self.0.publication_evidence().get(event_id).await?)
    }

    async fn publication_evidence_for_events(
        &self,
        event_ids: &[arkret_wire::EventId],
    ) -> crate::ServiceResult<Vec<soland_storage::PublicationEvidenceRecord>> {
        Ok(self.0.publication_evidence().get_many(event_ids).await?)
    }
}

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
            }),
            Arc::new(PersistencePublicationEvidence(persistence.clone())),
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
