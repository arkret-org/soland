use std::sync::Arc;

use serde_json::Value;
use soland_storage::*;

use crate::identity::*;

struct PersistenceAccountLookup(Arc<dyn PersistenceStore>);
struct PersistenceAccountData(Arc<dyn PersistenceStore>);
struct PersistenceDeviceKeys(Arc<dyn PersistenceStore>);
struct PersistenceOneTimeKeys(Arc<dyn PersistenceStore>);
struct PersistenceConsentCells(Arc<dyn PersistenceStore>);
struct PersistenceMimiConsentCorrelations(Arc<dyn PersistenceStore>);
struct PersistenceContacts(Arc<dyn PersistenceStore>);
struct PersistenceInviteReceivePolicies(Arc<dyn PersistenceStore>);
struct PersistenceDeviceDirectory(Arc<dyn PersistenceStore>);
struct PersistenceAgentDirectory(Arc<dyn PersistenceStore>);
struct PersistenceAgentPairing(Arc<dyn PersistenceStore>);
struct PersistenceDevicePairing(Arc<dyn PersistenceStore>);
struct PersistenceSidecars(Arc<dyn PersistenceStore>);
struct PersistenceAgentParticipation(Arc<dyn PersistenceStore>);
struct PersistenceKeyBackups(Arc<dyn PersistenceStore>);
struct PersistenceSessions(Arc<dyn PersistenceStore>);
struct PersistenceRecoveryPolicies(Arc<dyn PersistenceStore>);
struct PersistenceRecoverySessions(Arc<dyn PersistenceStore>);
struct PersistenceSecurityTransactions(Arc<dyn PersistenceStore>);
struct PersistenceDidDocuments(Arc<dyn PersistenceStore>);
#[async_trait::async_trait]
impl crate::identity::AccountLookupPort for PersistenceAccountLookup {
    async fn find_account_by_actor(
        &self,
        account_id: &arkret_wire::AccountId,
    ) -> crate::ServiceResult<Option<crate::identity::AccountIdentity>> {
        Ok(self.0.accounts().get(account_id).await?.map(|account| {
            crate::identity::AccountIdentity {
                account_pk: account.pk,
                account_id: arkret_wire::AccountId::new(account.principal_id, account.station_id),
            }
        }))
    }

    async fn account_by_id(
        &self,
        account_pk: AccountPk,
    ) -> crate::ServiceResult<Option<crate::identity::AccountProfileState>> {
        Ok(self
            .0
            .accounts()
            .get_by_pk(account_pk)
            .await?
            .map(application_account_profile))
    }

    async fn register_account(
        &self,
        command: crate::identity::RegisterAccountCommand,
    ) -> crate::ServiceResult<crate::identity::AccountIdentity> {
        let account = soland_storage::AccountRecord {
            pk: AccountPk(0),
            principal_id: command.account_id.principal_id.clone(),
            station_id: command.account_id.station_id.clone(),
            localpart: command.localpart.clone(),
            display_name: command.display_name,
            bio: None,
            avatar_blob_ref: None,
            created_at: command.created_at,
        };
        let account_pk = self.0.accounts().put(&account).await?;
        Ok(crate::identity::AccountIdentity {
            account_pk,
            account_id: command.account_id,
        })
    }

    async fn account(
        &self,
        account_id: &arkret_wire::AccountId,
    ) -> crate::ServiceResult<Option<crate::identity::AccountProfileState>> {
        Ok(self
            .0
            .accounts()
            .get(account_id)
            .await?
            .map(application_account_profile))
    }

    async fn accounts(&self) -> crate::ServiceResult<Vec<crate::identity::AccountProfileState>> {
        Ok(self
            .0
            .accounts()
            .list()
            .await?
            .into_iter()
            .map(application_account_profile)
            .collect())
    }

    async fn save_account(
        &self,
        account: crate::identity::AccountProfileState,
    ) -> crate::ServiceResult<()> {
        self.0
            .accounts()
            .put(&persistence_account_profile(account))
            .await?;
        Ok(())
    }

    async fn delete_account(
        &self,
        account_id: &arkret_wire::AccountId,
    ) -> crate::ServiceResult<()> {
        self.0.accounts().delete(account_id).await?;
        Ok(())
    }

    async fn account_localparts(
        &self,
        account_pk: AccountPk,
    ) -> crate::ServiceResult<Vec<crate::identity::AccountLocalpartState>> {
        Ok(self
            .0
            .account_localparts()
            .list_for_account(account_pk)
            .await?
            .into_iter()
            .map(application_account_localpart)
            .collect())
    }

    async fn localpart_owner(
        &self,
        localpart: &str,
    ) -> crate::ServiceResult<Option<crate::identity::AccountLocalpartState>> {
        Ok(self
            .0
            .account_localparts()
            .owner_of(localpart)
            .await?
            .map(application_account_localpart))
    }

    async fn add_localpart(
        &self,
        account_pk: AccountPk,
        localpart: &str,
        primary: bool,
    ) -> crate::ServiceResult<crate::identity::AccountLocalpartState> {
        Ok(application_account_localpart(
            self.0
                .account_localparts()
                .add(account_pk, localpart, primary)
                .await?,
        ))
    }

    async fn set_primary_localpart(
        &self,
        account_pk: AccountPk,
        localpart: &str,
    ) -> crate::ServiceResult<crate::identity::AccountLocalpartState> {
        Ok(application_account_localpart(
            self.0
                .account_localparts()
                .set_primary(account_pk, localpart)
                .await?,
        ))
    }

    async fn remove_localpart(
        &self,
        account_pk: AccountPk,
        localpart: &str,
    ) -> crate::ServiceResult<()> {
        self.0
            .account_localparts()
            .remove(account_pk, localpart)
            .await?;
        Ok(())
    }

    async fn clear_localparts(&self, account_pk: AccountPk) -> crate::ServiceResult<()> {
        self.0
            .account_localparts()
            .clear_for_account(account_pk)
            .await?;
        Ok(())
    }

    async fn record_handle_release(
        &self,
        localpart: &str,
        released_at: chrono::DateTime<chrono::Utc>,
    ) -> crate::ServiceResult<()> {
        self.0.handle_releases().put(localpart, released_at).await?;
        Ok(())
    }

    async fn save_account_lifecycle(
        &self,
        account_pk: AccountPk,
        _actor_id: &str,
        lifecycle: crate::identity::AccountLifecycleState,
    ) -> crate::ServiceResult<()> {
        self.0
            .account_lifecycle()
            .put(
                account_pk,
                &soland_storage::AccountLifecycleRecord {
                    state: lifecycle.state,
                    reason: lifecycle.reason,
                    changed_by: lifecycle.changed_by,
                    changed_at: lifecycle.changed_at,
                },
            )
            .await?;
        Ok(())
    }

    async fn delete_account_lifecycle(
        &self,
        account_pk: AccountPk,
        _actor_id: &str,
    ) -> crate::ServiceResult<()> {
        self.0.account_lifecycle().delete(account_pk).await?;
        Ok(())
    }

    async fn account_lifecycles(
        &self,
    ) -> crate::ServiceResult<
        Vec<(
            arkret_wire::AccountId,
            crate::identity::AccountLifecycleState,
        )>,
    > {
        Ok(self
            .0
            .account_lifecycle()
            .snapshot_all()
            .await?
            .into_iter()
            .map(|(actor_id, lifecycle)| {
                (
                    actor_id,
                    crate::identity::AccountLifecycleState {
                        state: lifecycle.state,
                        reason: lifecycle.reason,
                        changed_by: lifecycle.changed_by,
                        changed_at: lifecycle.changed_at,
                    },
                )
            })
            .collect())
    }
}

fn application_account_profile(
    account: soland_storage::AccountRecord,
) -> crate::identity::AccountProfileState {
    crate::identity::AccountProfileState {
        pk: account.pk,
        account_id: arkret_wire::AccountId::new(
            account.principal_id.clone(),
            account.station_id.clone(),
        ),
        principal_id: account.principal_id,
        localpart: account.localpart,
        display_name: account.display_name,
        bio: account.bio,
        avatar_blob_ref: account.avatar_blob_ref,
        created_at: account.created_at,
    }
}

fn persistence_account_profile(
    account: crate::identity::AccountProfileState,
) -> soland_storage::AccountRecord {
    soland_storage::AccountRecord {
        pk: account.pk,
        principal_id: account.principal_id,
        station_id: account.account_id.station_id,
        localpart: account.localpart,
        display_name: account.display_name,
        bio: account.bio,
        avatar_blob_ref: account.avatar_blob_ref,
        created_at: account.created_at,
    }
}

fn application_account_localpart(
    record: soland_storage::AccountLocalpartRecord,
) -> crate::identity::AccountLocalpartState {
    crate::identity::AccountLocalpartState {
        id: record.id,
        account_pk: record.account_pk,
        localpart: record.localpart,
        is_primary: record.is_primary,
        created_at: record.created_at,
        updated_at: record.updated_at,
    }
}

#[async_trait::async_trait]
impl crate::identity::AccountDataPort for PersistenceAccountData {
    async fn entry(
        &self,
        actor_id: &str,
        account_data_key: &str,
    ) -> crate::ServiceResult<Option<crate::identity::AccountDataState>> {
        Ok(self
            .0
            .account_data()
            .get(actor_id, account_data_key)
            .await?
            .map(application_account_data))
    }

    async fn entries_for_actor(
        &self,
        actor_id: &str,
    ) -> crate::ServiceResult<Vec<crate::identity::AccountDataState>> {
        Ok(self
            .0
            .account_data()
            .list_for_actor(actor_id)
            .await?
            .into_iter()
            .map(application_account_data)
            .collect())
    }

    async fn compare_and_set(
        &self,
        entry: crate::identity::AccountDataState,
        expected_revision: u64,
    ) -> crate::ServiceResult<crate::identity::AccountDataCasOutcome> {
        let outcome = self
            .0
            .account_data()
            .compare_and_set(
                &soland_storage::AccountDataRecord {
                    actor: entry.actor_id,
                    account_data_key: entry.account_data_key,
                    revision: entry.revision,
                    payload: entry.payload,
                    tombstone: entry.tombstone,
                    updated_at: entry.updated_at,
                },
                expected_revision,
            )
            .await?;
        Ok(match outcome {
            soland_storage::AccountDataCasResult::Applied(record) => {
                crate::identity::AccountDataCasOutcome::Applied(application_account_data(record))
            }
            soland_storage::AccountDataCasResult::Conflict(record) => {
                crate::identity::AccountDataCasOutcome::Conflict(
                    record.map(application_account_data),
                )
            }
        })
    }
}

fn application_account_data(
    record: soland_storage::AccountDataRecord,
) -> crate::identity::AccountDataState {
    crate::identity::AccountDataState {
        actor_id: record.actor,
        account_data_key: record.account_data_key,
        revision: record.revision,
        payload: record.payload,
        tombstone: record.tombstone,
        updated_at: record.updated_at,
    }
}

#[async_trait::async_trait]
impl crate::identity::ConsentCellPort for PersistenceConsentCells {
    async fn cells(
        &self,
    ) -> crate::ServiceResult<
        Vec<(
            crate::identity::ConsentCellKey,
            crate::identity::ConsentCellRecord,
        )>,
    > {
        Ok(self
            .0
            .consent_cells()
            .snapshot_all()
            .await?
            .into_iter()
            .map(|(key, cell)| (application_consent_key(key), application_consent_cell(cell)))
            .collect())
    }
}

#[async_trait::async_trait]
impl crate::identity::MimiConsentCorrelationPort for PersistenceMimiConsentCorrelations {
    async fn save_correlation(
        &self,
        correlation: crate::identity::MimiConsentCorrelation,
    ) -> crate::ServiceResult<()> {
        self.0
            .mimi_consent_correlations()
            .put(&storage_mimi_consent_correlation(correlation))
            .await?;
        Ok(())
    }

    async fn correlation(
        &self,
        consent_id: &str,
    ) -> crate::ServiceResult<Option<crate::identity::MimiConsentCorrelation>> {
        Ok(self
            .0
            .mimi_consent_correlations()
            .get(consent_id)
            .await?
            .map(application_mimi_consent_correlation))
    }
}

fn storage_mimi_consent_correlation(
    correlation: crate::identity::MimiConsentCorrelation,
) -> soland_storage::MimiConsentCorrelationRecord {
    soland_storage::MimiConsentCorrelationRecord {
        consent_id: correlation.consent_id,
        requester_id: correlation.requester_id,
        target_kind: correlation.target_kind,
        target_id: correlation.target_id,
        purpose: correlation.purpose,
        strand_id: correlation.strand_id,
        source_id: correlation.source_id,
        created_at: correlation.created_at,
        expires_at: correlation.expires_at,
    }
}

fn application_mimi_consent_correlation(
    correlation: soland_storage::MimiConsentCorrelationRecord,
) -> crate::identity::MimiConsentCorrelation {
    crate::identity::MimiConsentCorrelation {
        consent_id: correlation.consent_id,
        requester_id: correlation.requester_id,
        target_kind: correlation.target_kind,
        target_id: correlation.target_id,
        purpose: correlation.purpose,
        strand_id: correlation.strand_id,
        source_id: correlation.source_id,
        created_at: correlation.created_at,
        expires_at: correlation.expires_at,
    }
}

#[async_trait::async_trait]
impl crate::identity::ContactPort for PersistenceContacts {
    async fn contact_any(
        &self,
        requester_id: &arkret_wire::ActorId,
        target_id: &arkret_wire::ActorId,
    ) -> crate::ServiceResult<Option<crate::identity::ContactRecord>> {
        Ok(self
            .0
            .contacts()
            .get(requester_id, target_id)
            .await?
            .map(application_contact))
    }

    async fn contacts_for_actor(
        &self,
        actor_id: &arkret_wire::ActorId,
    ) -> crate::ServiceResult<Vec<crate::identity::ContactRecord>> {
        Ok(self
            .0
            .contacts()
            .list_for_actor(actor_id)
            .await?
            .into_iter()
            .map(application_contact)
            .collect())
    }

    async fn save_contact(
        &self,
        contact: crate::identity::ContactRecord,
    ) -> crate::ServiceResult<()> {
        self.0.contacts().put(&storage_contact(contact)).await?;
        Ok(())
    }

    async fn save_contact_if_updated_at(
        &self,
        expected_updated_at: chrono::DateTime<chrono::Utc>,
        contact: crate::identity::ContactRecord,
    ) -> crate::ServiceResult<bool> {
        Ok(self
            .0
            .contacts()
            .put_if_updated_at(expected_updated_at, &storage_contact(contact))
            .await?)
    }
}

#[async_trait::async_trait]
impl crate::identity::InviteReceivePolicyPort for PersistenceInviteReceivePolicies {
    async fn save_policy(
        &self,
        account_id: &arkret_wire::AccountId,
        policy: arkret_models_collaboration::governance::invite_addressing::InviteReceivePolicy,
    ) -> crate::ServiceResult<()> {
        self.0
            .invite_receive_policies()
            .put(account_id, &policy)
            .await?;
        Ok(())
    }

    async fn policies(
        &self,
    ) -> crate::ServiceResult<
        Vec<(
            arkret_wire::AccountId,
            arkret_models_collaboration::governance::invite_addressing::InviteReceivePolicy,
        )>,
    > {
        Ok(self.0.invite_receive_policies().snapshot_all().await?)
    }
}

fn application_consent_key(key: soland_storage::ConsentCellKey) -> crate::identity::ConsentCellKey {
    crate::identity::ConsentCellKey {
        holder_principal_id: key.holder_principal_id,
        cell_id: key.cell_id,
    }
}

fn application_consent_cell(
    cell: soland_storage::ConsentCellRecord,
) -> crate::identity::ConsentCellRecord {
    crate::identity::ConsentCellRecord {
        cell_id: cell.cell_id,
        holder_principal_id: cell.holder_principal_id,
        peer_principal_id: cell.peer_principal_id,
        consent_scope: cell.consent_scope,
        grant_dots: cell
            .grant_dots
            .into_iter()
            .map(|(key, dot)| {
                (
                    key,
                    crate::identity::ConsentGrantDot {
                        dot: dot.dot,
                        not_before: dot.not_before,
                        expires_at: dot.expires_at,
                        granted_at: dot.granted_at,
                    },
                )
            })
            .collect(),
        revoked_dots: cell.revoked_dots,
        updated_at: cell.updated_at,
    }
}

pub(crate) fn storage_consent_cell(
    cell: crate::identity::ConsentCellRecord,
) -> soland_storage::ConsentCellRecord {
    soland_storage::ConsentCellRecord {
        cell_id: cell.cell_id,
        holder_principal_id: cell.holder_principal_id,
        peer_principal_id: cell.peer_principal_id,
        consent_scope: cell.consent_scope,
        grant_dots: cell
            .grant_dots
            .into_iter()
            .map(|(key, dot)| {
                (
                    key,
                    soland_storage::ConsentGrantDot {
                        dot: dot.dot,
                        not_before: dot.not_before,
                        expires_at: dot.expires_at,
                        granted_at: dot.granted_at,
                    },
                )
            })
            .collect(),
        revoked_dots: cell.revoked_dots,
        updated_at: cell.updated_at,
    }
}

fn application_contact(record: soland_storage::ContactRecord) -> crate::identity::ContactRecord {
    crate::identity::ContactRecord {
        requester_id: record.requester_id,
        target_id: record.target_id,
        contact_round_id: record.contact_round_id,
        version: record.version,
        granted_to_target_scopes: record.granted_to_target_scopes,
        granted_to_requester_scopes: record.granted_to_requester_scopes,
        status: record.status,
        request_event_ref: record.request_event_ref,
        request_receipts: record.request_receipts,
        request_mirror_receipts: record.request_mirror_receipts,
        contact_round_evidence: record.contact_round_evidence,
        contact_round_evidence_history: record.contact_round_evidence_history,
        control_outcomes: record.control_outcomes,
        response_event_ref: record.response_event_ref,
        tombstone_event_ref: record.tombstone_event_ref,
        message: record.message,
        peer_host_id: record.peer_host_id,
        peer_service_resolution: record.peer_service_resolution,
        created_at: record.created_at,
        updated_at: record.updated_at,
    }
}

fn storage_contact(record: crate::identity::ContactRecord) -> soland_storage::ContactRecord {
    soland_storage::ContactRecord {
        requester_id: record.requester_id,
        target_id: record.target_id,
        contact_round_id: record.contact_round_id,
        version: record.version,
        granted_to_target_scopes: record.granted_to_target_scopes,
        granted_to_requester_scopes: record.granted_to_requester_scopes,
        status: record.status,
        request_event_ref: record.request_event_ref,
        request_receipts: record.request_receipts,
        request_mirror_receipts: record.request_mirror_receipts,
        contact_round_evidence: record.contact_round_evidence,
        contact_round_evidence_history: record.contact_round_evidence_history,
        control_outcomes: record.control_outcomes,
        response_event_ref: record.response_event_ref,
        tombstone_event_ref: record.tombstone_event_ref,
        message: record.message,
        peer_host_id: record.peer_host_id,
        peer_service_resolution: record.peer_service_resolution,
        created_at: record.created_at,
        updated_at: record.updated_at,
    }
}

#[async_trait::async_trait]
impl crate::identity::DeviceKeyPort for PersistenceDeviceKeys {
    async fn save_bundle(
        &self,
        actor_id: String,
        device_id: String,
        payload: Value,
    ) -> crate::ServiceResult<()> {
        self.0
            .device_keys()
            .put(actor_id, device_id, payload)
            .await?;
        Ok(())
    }

    async fn bundle(&self, actor_id: &str, device_id: &str) -> crate::ServiceResult<Option<Value>> {
        Ok(self.0.device_keys().get(actor_id, device_id).await?)
    }
}

#[async_trait::async_trait]
impl crate::identity::OneTimeKeyPort for PersistenceOneTimeKeys {
    async fn save_keys(
        &self,
        actor_id: String,
        device_id: String,
        keys: Vec<Value>,
    ) -> crate::ServiceResult<()> {
        self.0
            .one_time_keys()
            .put(actor_id, device_id, keys)
            .await?;
        Ok(())
    }

    async fn claim_key(
        &self,
        actor_id: &str,
        device_id: &str,
    ) -> crate::ServiceResult<Option<Value>> {
        Ok(self.0.one_time_keys().claim(actor_id, device_id).await?)
    }
}

#[async_trait::async_trait]
impl crate::identity::DeviceDirectoryPort for PersistenceDeviceDirectory {
    async fn list_active_device_actors(&self) -> crate::ServiceResult<Vec<String>> {
        Ok(self
            .0
            .devices()
            .list()
            .await?
            .into_iter()
            .filter(|device| device.revoked_at.is_none())
            .map(|device| device.actor)
            .collect())
    }

    async fn devices(&self) -> crate::ServiceResult<Vec<crate::identity::DeviceIdentity>> {
        Ok(self
            .0
            .devices()
            .list()
            .await?
            .into_iter()
            .map(application_device_identity)
            .collect())
    }

    async fn find_device(
        &self,
        actor_id: &str,
        device_id: &str,
    ) -> crate::ServiceResult<Option<crate::identity::DeviceIdentity>> {
        Ok(self
            .0
            .devices()
            .get(actor_id, device_id)
            .await?
            .map(application_device_identity))
    }

    async fn save_device(
        &self,
        command: crate::identity::SaveDeviceCommand,
    ) -> crate::ServiceResult<()> {
        self.0
            .devices()
            .put(&soland_storage::DeviceInventoryRecord {
                actor: command.actor_id,
                device_id: command.device_id,
                display_name: command.display_name,
                verification_state: command.device.verification_state,
                payload: command.device.payload,
                created_at: command.device.created_at,
                updated_at: command.device.updated_at,
                revoked_at: command.device.revoked_at,
            })
            .await?;
        Ok(())
    }

    async fn save_device_if_absent(
        &self,
        device: crate::identity::DeviceIdentity,
    ) -> crate::ServiceResult<bool> {
        Ok(self
            .0
            .devices()
            .put_if_absent(&persistence_device_identity(device))
            .await?)
    }

    async fn devices_for_actor(
        &self,
        actor_id: &str,
    ) -> crate::ServiceResult<Vec<crate::identity::DeviceIdentity>> {
        Ok(self
            .0
            .devices()
            .list_for_actor_including_revoked(actor_id)
            .await?
            .into_iter()
            .map(application_device_identity)
            .collect())
    }
}

fn application_device_identity(
    device: soland_storage::DeviceInventoryRecord,
) -> crate::identity::DeviceIdentity {
    crate::identity::DeviceIdentity {
        actor_id: device.actor,
        device_id: device.device_id,
        display_name: device.display_name,
        verification_state: device.verification_state,
        payload: device.payload,
        created_at: device.created_at,
        updated_at: device.updated_at,
        revoked_at: device.revoked_at,
    }
}

fn persistence_device_identity(
    device: crate::identity::DeviceIdentity,
) -> soland_storage::DeviceInventoryRecord {
    soland_storage::DeviceInventoryRecord {
        actor: device.actor_id,
        device_id: device.device_id,
        display_name: device.display_name,
        verification_state: device.verification_state,
        payload: device.payload,
        created_at: device.created_at,
        updated_at: device.updated_at,
        revoked_at: device.revoked_at,
    }
}

#[async_trait::async_trait]
impl crate::identity::AgentDirectoryPort for PersistenceAgentDirectory {
    async fn find_agent_controller(
        &self,
        agent_id: &str,
    ) -> crate::ServiceResult<Option<crate::identity::AgentController>> {
        Ok(self
            .0
            .agents()
            .get(agent_id)
            .await?
            .map(|agent| crate::identity::AgentController {
                controller_id: agent.controller_id,
            }))
    }
}

#[async_trait::async_trait]
impl crate::identity::AgentPairingPort for PersistenceAgentPairing {
    async fn pairing_record(
        &self,
        pairing_request_id: &str,
    ) -> crate::ServiceResult<Option<crate::identity::AgentPairingState>> {
        Ok(self
            .0
            .agents()
            .get_by_pairing_request_id(pairing_request_id)
            .await?
            .map(application_agent_pairing))
    }

    async fn agent(
        &self,
        agent_id: &str,
    ) -> crate::ServiceResult<Option<crate::identity::AgentPairingState>> {
        Ok(self
            .0
            .agents()
            .get(agent_id)
            .await?
            .map(application_agent_pairing))
    }

    async fn agents_for_controller(
        &self,
        controller_id: &str,
    ) -> crate::ServiceResult<Vec<crate::identity::AgentPairingState>> {
        Ok(self
            .0
            .agents()
            .list_for_controller(controller_id)
            .await?
            .into_iter()
            .map(application_agent_pairing)
            .collect())
    }

    async fn save_agent(
        &self,
        agent: crate::identity::AgentPairingState,
    ) -> crate::ServiceResult<()> {
        self.0
            .agents()
            .put(persistence_agent_pairing(agent))
            .await?;
        Ok(())
    }

    async fn store_runtime_approval(
        &self,
        command: &crate::identity::StoreAgentRuntimeApprovalCommand,
    ) -> crate::ServiceResult<Option<crate::identity::AgentPairingState>> {
        let write = soland_storage::AgentRuntimeApprovalWrite {
            agent_id: command.agent_id.clone(),
            pairing_request_id: command.pairing_request_id.clone(),
            approval_request_id: command.approval_request_id.clone(),
            approval_notification_id: command.approval_notification_id.clone(),
            approval_requested_at: command.approval_requested_at,
            controller_account_pk: command.controller_account_pk,
            recipient_id: command.recipient_id.clone(),
            runtime_key_binding_digest: command.runtime_key_binding_digest.clone(),
            runtime_public_key_digest: command.runtime_public_key_digest.clone(),
            runtime_attestation_digest: command.runtime_attestation_digest.clone(),
            runtime_key_request: command.runtime_key_request.clone(),
        };
        Ok(self
            .0
            .agents()
            .put_runtime_approval_if_compatible(&write)
            .await?
            .map(application_agent_pairing))
    }

    async fn activate_runtime_if_current(
        &self,
        command: &crate::identity::ActivateAgentRuntimeCommand,
    ) -> crate::ServiceResult<bool> {
        let activation = soland_storage::AgentRuntimeActivation {
            agent_id: command.agent_id.clone(),
            approval_request_id: command.approval_request_id.clone(),
            runtime_key_binding_digest: command.runtime_key_binding_digest.clone(),
            pairing_request_id: command.pairing_request_id.clone(),
            paired_request_digest: command.paired_request_digest.clone(),
            authorized_event_ref: command.authorized_event_ref.clone(),
            authorized_verification_method: command.authorized_verification_method.clone(),
            authorized_public_key_digest: command.authorized_public_key_digest.clone(),
            authorized_signing_key_binding: command.authorized_signing_key_binding.clone(),
            authorized_at: command.authorized_at,
        };
        Ok(self
            .0
            .agents()
            .activate_runtime_if_current(&activation)
            .await?)
    }

    async fn record_pairing_commit_intent(
        &self,
        command: &crate::identity::RecordAgentPairingCommitIntentCommand,
    ) -> crate::ServiceResult<Option<crate::identity::AgentPairingState>> {
        let intent = soland_storage::AgentPairingCommitIntent {
            agent_id: command.agent_id.clone(),
            approval_request_id: command.approval_request_id.clone(),
            runtime_key_binding_digest: command.runtime_key_binding_digest.clone(),
            pairing_request_id: command.pairing_request_id.clone(),
            request_digest: command.request_digest.clone(),
            authorize_event_id: command.authorize_event_id.clone(),
            signing_key_binding: command.signing_key_binding.clone(),
        };
        Ok(self
            .0
            .agents()
            .put_pairing_commit_intent_if_compatible(&intent)
            .await?
            .map(application_agent_pairing))
    }

    async fn clear_approval_notification_if_current(
        &self,
        agent_id: &str,
        approval_request_id: &str,
    ) -> crate::ServiceResult<bool> {
        Ok(self
            .0
            .agents()
            .clear_runtime_approval_notification_if_current(agent_id, approval_request_id)
            .await?)
    }

    async fn enqueue_runtime_message_if_current(
        &self,
        command: &EnqueueAgentRuntimeMessage,
    ) -> crate::ServiceResult<AgentRuntimeEnqueueOutcome> {
        Ok(self
            .0
            .agents()
            .enqueue_runtime_message_if_current(command)
            .await?)
    }
}

#[async_trait::async_trait]
impl crate::identity::DevicePairingPort for PersistenceDevicePairing {
    async fn stage(&self, record: crate::identity::DevicePairingState) -> crate::ServiceResult<()> {
        self.0
            .device_pairings()
            .put(persistence_device_pairing(record))
            .await?;
        Ok(())
    }

    async fn get(
        &self,
        device_pairing_request_id: &str,
    ) -> crate::ServiceResult<Option<crate::identity::DevicePairingState>> {
        Ok(self
            .0
            .device_pairings()
            .get_by_request_id(device_pairing_request_id)
            .await?
            .map(application_device_pairing))
    }

    async fn prune_expired_before(
        &self,
        cutoff: chrono::DateTime<chrono::Utc>,
    ) -> crate::ServiceResult<u64> {
        Ok(self
            .0
            .device_pairings()
            .delete_expired_before(cutoff)
            .await?)
    }
}

fn application_device_pairing(
    record: soland_storage::DevicePairingRecord,
) -> crate::identity::DevicePairingState {
    crate::identity::DevicePairingState {
        device_pairing_request_id: record.device_pairing_request_id,
        pairing_code: record.pairing_code,
        new_device_pubkey: record.new_device_pubkey,
        client_nonce: record.client_nonce,
        gate_audience: record.gate_audience,
        server_nonce: record.server_nonce,
        display_name: record.display_name,
        device_metadata: record.device_metadata,
        state: record.state,
        device_id: record.device_id,
        authorized_by_actor_id: record.authorized_by_actor_id,
        authorized_event_ref: record.authorized_event_ref,
        created_at: record.created_at,
        expires_at: record.expires_at,
    }
}

fn persistence_device_pairing(
    record: crate::identity::DevicePairingState,
) -> soland_storage::DevicePairingRecord {
    soland_storage::DevicePairingRecord {
        device_pairing_request_id: record.device_pairing_request_id,
        pairing_code: record.pairing_code,
        new_device_pubkey: record.new_device_pubkey,
        client_nonce: record.client_nonce,
        gate_audience: record.gate_audience,
        server_nonce: record.server_nonce,
        display_name: record.display_name,
        device_metadata: record.device_metadata,
        state: record.state,
        device_id: record.device_id,
        authorized_by_actor_id: record.authorized_by_actor_id,
        authorized_event_ref: record.authorized_event_ref,
        created_at: record.created_at,
        expires_at: record.expires_at,
    }
}

fn application_agent_pairing(
    record: soland_storage::AgentPrincipalRecord,
) -> crate::identity::AgentPairingState {
    crate::identity::AgentPairingState {
        id: record.id,
        controller_id: record.controller_id,
        principal_control_realm_id: record.principal_control_realm_id,
        controller_authorization_ref: record.controller_authorization_ref,
        display_name: record.display_name,
        agent_slug: record.agent_slug,
        avatar_blob_ref: record.avatar_blob_ref,
        state: record.state,
        requested_scope: record.requested_scope,
        accountability: record.accountability,
        provision_event_refs: record.provision_event_refs,
        pairing_request_id: record.pairing_request_id,
        paired_pairing_request_id: record.paired_pairing_request_id,
        paired_request_digest: record.paired_request_digest,
        pending_pairing_commit_intent: record.pending_pairing_commit_intent.map(|intent| {
            crate::identity::AgentPairingCommitIntentState {
                request_digest: intent.request_digest,
                authorize_event_id: intent.authorize_event_id,
                signing_key_binding: intent.signing_key_binding,
            }
        }),
        pairing_code: record.pairing_code,
        pairing_expires_at: record.pairing_expires_at,
        approval_request_id: record.approval_request_id,
        controller_account_pk: record.controller_account_pk,
        recipient_id: record.recipient_id,
        runtime_key_binding_digest: record.runtime_key_binding_digest,
        runtime_public_key_digest: record.runtime_public_key_digest,
        runtime_attestation_digest: record.runtime_attestation_digest,
        approval_notification_id: record.approval_notification_id,
        runtime_key_request: record.runtime_key_request,
        approval_requested_at: record.approval_requested_at,
        authorized_event_ref: record.authorized_event_ref,
        authorized_verification_method: record.authorized_verification_method,
        authorized_public_key_digest: record.authorized_public_key_digest,
        authorized_signing_key_binding: record.authorized_signing_key_binding,
        state_changed_at: record.state_changed_at,
        created_at: record.created_at,
        updated_at: record.updated_at,
    }
}

fn persistence_agent_pairing(
    record: crate::identity::AgentPairingState,
) -> soland_storage::AgentPrincipalRecord {
    soland_storage::AgentPrincipalRecord {
        id: record.id,
        controller_id: record.controller_id,
        principal_control_realm_id: record.principal_control_realm_id,
        controller_authorization_ref: record.controller_authorization_ref,
        display_name: record.display_name,
        agent_slug: record.agent_slug,
        avatar_blob_ref: record.avatar_blob_ref,
        state: record.state,
        requested_scope: record.requested_scope,
        accountability: record.accountability,
        provision_event_refs: record.provision_event_refs,
        pairing_request_id: record.pairing_request_id,
        paired_pairing_request_id: record.paired_pairing_request_id,
        paired_request_digest: record.paired_request_digest,
        pending_pairing_commit_intent: record.pending_pairing_commit_intent.map(|intent| {
            soland_storage::PendingAgentPairingCommitIntent {
                request_digest: intent.request_digest,
                authorize_event_id: intent.authorize_event_id,
                signing_key_binding: intent.signing_key_binding,
            }
        }),
        pairing_code: record.pairing_code,
        pairing_expires_at: record.pairing_expires_at,
        approval_request_id: record.approval_request_id,
        controller_account_pk: record.controller_account_pk,
        recipient_id: record.recipient_id,
        runtime_key_binding_digest: record.runtime_key_binding_digest,
        runtime_public_key_digest: record.runtime_public_key_digest,
        runtime_attestation_digest: record.runtime_attestation_digest,
        approval_notification_id: record.approval_notification_id,
        runtime_key_request: record.runtime_key_request,
        approval_requested_at: record.approval_requested_at,
        authorized_event_ref: record.authorized_event_ref,
        authorized_verification_method: record.authorized_verification_method,
        authorized_public_key_digest: record.authorized_public_key_digest,
        authorized_signing_key_binding: record.authorized_signing_key_binding,
        state_changed_at: record.state_changed_at,
        created_at: record.created_at,
        updated_at: record.updated_at,
    }
}

fn application_sidecar(
    record: soland_storage::AgentSidecarRecord,
) -> crate::identity::AgentSidecarState {
    crate::identity::AgentSidecarState {
        sidecar_id: record.sidecar_id,
        realm_id: record.realm_id,
        controller_id: record.controller_id,
        state: record.state,
        state_changed_at: record.state_changed_at,
        created_at: record.created_at,
        updated_at: record.updated_at,
    }
}
fn persistence_sidecar(
    record: crate::identity::AgentSidecarState,
) -> soland_storage::AgentSidecarRecord {
    soland_storage::AgentSidecarRecord {
        sidecar_id: record.sidecar_id,
        realm_id: record.realm_id,
        controller_id: record.controller_id,
        state: record.state,
        state_changed_at: record.state_changed_at,
        created_at: record.created_at,
        updated_at: record.updated_at,
    }
}
fn application_sidecar_context(
    record: soland_storage::AgentSidecarContextRecord,
) -> crate::identity::AgentSidecarContextState {
    crate::identity::AgentSidecarContextState {
        sidecar_id: record.sidecar_id,
        normalized_context_ref_digest: record.normalized_context_ref_digest,
        normalized_context_ref: record.normalized_context_ref,
        version: record.version,
        predecessor_event_ref: record.predecessor_event_ref,
        attach_event_ref: record.attach_event_ref,
        created_at: record.created_at,
    }
}
fn persistence_sidecar_context(
    record: crate::identity::AgentSidecarContextState,
) -> soland_storage::AgentSidecarContextRecord {
    soland_storage::AgentSidecarContextRecord {
        sidecar_id: record.sidecar_id,
        normalized_context_ref_digest: record.normalized_context_ref_digest,
        normalized_context_ref: record.normalized_context_ref,
        version: record.version,
        predecessor_event_ref: record.predecessor_event_ref,
        attach_event_ref: record.attach_event_ref,
        created_at: record.created_at,
    }
}

#[async_trait::async_trait]
impl crate::identity::SidecarPort for PersistenceSidecars {
    async fn ensure_sidecar(
        &self,
        sidecar: crate::identity::AgentSidecarState,
    ) -> crate::ServiceResult<crate::identity::AgentSidecarState> {
        Ok(application_sidecar(
            self.0
                .sidecars()
                .insert_or_get(persistence_sidecar(sidecar))
                .await?,
        ))
    }
    async fn sidecar(
        &self,
        sidecar_id: &str,
    ) -> crate::ServiceResult<Option<crate::identity::AgentSidecarState>> {
        Ok(self
            .0
            .sidecars()
            .get(sidecar_id)
            .await?
            .map(application_sidecar))
    }
    async fn sidecar_for_realm_controller(
        &self,
        realm_id: &str,
        controller_id: &str,
    ) -> crate::ServiceResult<Option<crate::identity::AgentSidecarState>> {
        Ok(self
            .0
            .sidecars()
            .get_for_realm_controller(realm_id, controller_id)
            .await?
            .map(application_sidecar))
    }
    async fn sidecars_for_controller(
        &self,
        controller_id: &str,
        realm_id: Option<&str>,
    ) -> crate::ServiceResult<Vec<crate::identity::AgentSidecarState>> {
        Ok(self
            .0
            .sidecars()
            .list_for_controller(controller_id, realm_id)
            .await?
            .into_iter()
            .map(application_sidecar)
            .collect())
    }
    async fn ensure_context(
        &self,
        context: crate::identity::AgentSidecarContextState,
    ) -> crate::ServiceResult<crate::identity::AgentSidecarContextState> {
        Ok(application_sidecar_context(
            self.0
                .sidecars()
                .insert_or_get_context(persistence_sidecar_context(context))
                .await?,
        ))
    }
    async fn context(
        &self,
        sidecar_id: &str,
        digest: &str,
    ) -> crate::ServiceResult<Option<crate::identity::AgentSidecarContextState>> {
        Ok(self
            .0
            .sidecars()
            .get_context(sidecar_id, digest)
            .await?
            .map(application_sidecar_context))
    }
}

#[async_trait::async_trait]
impl crate::identity::AgentParticipationPort for PersistenceAgentParticipation {
    async fn compare_and_swap_selection(
        &self,
        selection: serde_json::Value,
        expected_version: u64,
    ) -> crate::ServiceResult<bool> {
        Ok(self
            .0
            .agent_participation()
            .compare_and_swap_selection(selection, expected_version)
            .await?)
    }

    async fn selections(&self, agent_id: &str) -> crate::ServiceResult<Vec<serde_json::Value>> {
        Ok(self
            .0
            .agent_participation()
            .list_selections(agent_id)
            .await?)
    }

    async fn ceilings(
        &self,
        scope_keys: &[String],
    ) -> crate::ServiceResult<Vec<serde_json::Value>> {
        Ok(self
            .0
            .agent_participation()
            .ceilings_for_scope_keys(scope_keys)
            .await?)
    }

    async fn store_ceiling(&self, ceiling: serde_json::Value) -> crate::ServiceResult<()> {
        self.0.agent_participation().put_ceiling(ceiling).await?;
        Ok(())
    }
}

#[async_trait::async_trait]
impl crate::identity::KeyBackupPort for PersistenceKeyBackups {
    async fn backup(&self, backup_id: &str) -> crate::ServiceResult<Option<serde_json::Value>> {
        Ok(self.0.key_backups().get(backup_id).await?)
    }

    async fn backups_for_actor(
        &self,
        actor_id: &str,
    ) -> crate::ServiceResult<Vec<serde_json::Value>> {
        Ok(self.0.key_backups().list_for_actor(actor_id).await?)
    }

    async fn store_backup(
        &self,
        backup_id: String,
        payload: serde_json::Value,
    ) -> crate::ServiceResult<()> {
        self.0.key_backups().put(backup_id, payload).await?;
        Ok(())
    }

    async fn delete_backup(&self, backup_id: &str) -> crate::ServiceResult<bool> {
        Ok(self.0.key_backups().delete(backup_id).await?)
    }

    async fn issue_delete_challenge(
        &self,
        record: soland_storage::KeyBackupDeleteChallengeRecord,
        now: chrono::DateTime<chrono::Utc>,
    ) -> crate::ServiceResult<soland_storage::KeyBackupDeleteChallengeRecord> {
        Ok(self
            .0
            .key_backups()
            .issue_delete_challenge(record, now)
            .await?)
    }

    async fn delete_challenge(
        &self,
        challenge_id: &str,
    ) -> crate::ServiceResult<Option<soland_storage::KeyBackupDeleteChallengeRecord>> {
        Ok(self.0.key_backups().delete_challenge(challenge_id).await?)
    }

    async fn consume_delete_challenge(
        &self,
        challenge_id: &str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> crate::ServiceResult<bool> {
        Ok(self
            .0
            .key_backups()
            .consume_delete_challenge(challenge_id, now)
            .await?)
    }

    async fn prune_expired_delete_challenges(
        &self,
        now: chrono::DateTime<chrono::Utc>,
    ) -> crate::ServiceResult<usize> {
        Ok(self
            .0
            .key_backups()
            .prune_expired_delete_challenges(now)
            .await?)
    }
}

#[async_trait::async_trait]
impl crate::identity::SessionIdentityPort for PersistenceSessions {
    async fn session(
        &self,
        token_hash: &str,
    ) -> crate::ServiceResult<Option<crate::identity::SessionIdentityState>> {
        Ok(self
            .0
            .sessions()
            .get(token_hash)
            .await?
            .map(application_session_identity))
    }

    async fn sessions(&self) -> crate::ServiceResult<Vec<crate::identity::SessionIdentityState>> {
        Ok(self
            .0
            .sessions()
            .snapshot_all()
            .await?
            .into_iter()
            .map(application_session_identity)
            .collect())
    }

    async fn save_session(
        &self,
        session: crate::identity::SessionIdentityState,
    ) -> crate::ServiceResult<()> {
        self.0
            .sessions()
            .put(&persistence_session_identity(session))
            .await?;
        Ok(())
    }

    async fn revoke_session(
        &self,
        token_hash: &str,
        revoked_at: chrono::DateTime<chrono::Utc>,
    ) -> crate::ServiceResult<Option<crate::identity::SessionIdentityState>> {
        let Some(mut session) = self.0.sessions().get(token_hash).await? else {
            return Ok(None);
        };
        if session.revoked_at.is_some() {
            return Ok(None);
        }
        session.revoked_at = Some(revoked_at);
        self.0.sessions().put(&session).await?;
        Ok(Some(application_session_identity(session)))
    }

    async fn revoke_actor_sessions(
        &self,
        actor_id: &str,
        revoked_at: chrono::DateTime<chrono::Utc>,
    ) -> crate::ServiceResult<usize> {
        self.revoke_matching_sessions(actor_id, None, revoked_at)
            .await
    }

    async fn revoke_actor_device_sessions(
        &self,
        actor_id: &str,
        device_id: &str,
        revoked_at: chrono::DateTime<chrono::Utc>,
    ) -> crate::ServiceResult<usize> {
        self.revoke_matching_sessions(actor_id, Some(device_id), revoked_at)
            .await
    }
}

impl PersistenceSessions {
    async fn revoke_matching_sessions(
        &self,
        actor_id: &str,
        device_id: Option<&str>,
        revoked_at: chrono::DateTime<chrono::Utc>,
    ) -> crate::ServiceResult<usize> {
        let sessions = self.0.sessions().snapshot_all().await?;
        let mut count = 0;
        for mut session in sessions.into_iter().filter(|session| {
            session.actor == actor_id
                && session.revoked_at.is_none()
                && device_id.is_none_or(|device_id| session.device_id == device_id)
        }) {
            session.revoked_at = Some(revoked_at);
            self.0.sessions().put(&session).await?;
            count += 1;
        }
        Ok(count)
    }
}

fn application_session_identity(
    session: soland_storage::SessionRecord,
) -> crate::identity::SessionIdentityState {
    crate::identity::SessionIdentityState {
        token_hash: session.token_hash,
        account_pk: Some(session.account_pk),
        actor: session.actor,
        device_id: session.device_id,
        audience: session.audience,
        session_public_key: session.session_public_key,
        agent_session: session
            .agent_session
            .map(|agent| crate::identity::AgentSessionState {
                granted_scope: agent.granted_scope,
                scope_details: agent.scope_details,
                freshness_state: agent.freshness_state,
            }),
        session_grant: None,
        expires_at: session.expires_at,
        created_at: session.created_at,
        revoked_at: session.revoked_at,
    }
}

fn persistence_session_identity(
    session: crate::identity::SessionIdentityState,
) -> soland_storage::SessionRecord {
    debug_assert!(
        session.session_grant.is_none(),
        "request-scoped session grants must never be persisted"
    );
    soland_storage::SessionRecord {
        token_hash: session.token_hash,
        account_pk: session
            .account_pk
            .expect("only account-bound sessions may be persisted"),
        actor: session.actor,
        device_id: session.device_id,
        audience: session.audience,
        session_public_key: session.session_public_key,
        agent_session: session
            .agent_session
            .map(|agent| soland_storage::AgentSessionRecord {
                granted_scope: agent.granted_scope,
                scope_details: agent.scope_details,
                freshness_state: agent.freshness_state,
            }),
        expires_at: session.expires_at,
        created_at: session.created_at,
        revoked_at: session.revoked_at,
    }
}

fn application_recovery_policy(
    record: soland_storage::RecoveryPolicyRecord,
) -> crate::identity::RecoveryPolicyState {
    crate::identity::RecoveryPolicyState {
        policy_id: record.policy_id,
        principal_id: record.principal_id,
        version: record.version,
        acceptance_basis: record.acceptance_basis,
        trust_domain: record.trust_domain,
        allowed_proof_kinds: record.allowed_proof_kinds,
        supersedes: record.supersedes,
        expires_at: record.expires_at,
        issued_at: record.issued_at,
        raw_payload: record.raw_payload,
        accepted_at: record.accepted_at,
        verification_method: record.verification_method,
    }
}

fn persistence_recovery_policy(
    policy: crate::identity::RecoveryPolicyState,
) -> soland_storage::RecoveryPolicyRecord {
    soland_storage::RecoveryPolicyRecord {
        policy_id: policy.policy_id,
        principal_id: policy.principal_id,
        version: policy.version,
        acceptance_basis: policy.acceptance_basis,
        trust_domain: policy.trust_domain,
        allowed_proof_kinds: policy.allowed_proof_kinds,
        supersedes: policy.supersedes,
        expires_at: policy.expires_at,
        issued_at: policy.issued_at,
        raw_payload: policy.raw_payload,
        accepted_at: policy.accepted_at,
        verification_method: policy.verification_method,
    }
}

#[async_trait::async_trait]
impl crate::identity::RecoveryPolicyPort for PersistenceRecoveryPolicies {
    async fn active_policy(
        &self,
        principal_id: &str,
    ) -> crate::ServiceResult<Option<crate::identity::RecoveryPolicyState>> {
        Ok(self
            .0
            .recovery_policies()
            .get_active_for_principal(principal_id)
            .await?
            .map(application_recovery_policy))
    }

    async fn policy_history(
        &self,
        principal_id: &str,
    ) -> crate::ServiceResult<Vec<crate::identity::RecoveryPolicyState>> {
        Ok(self
            .0
            .recovery_policies()
            .list_for_principal(principal_id)
            .await?
            .into_iter()
            .map(application_recovery_policy)
            .collect())
    }

    async fn insert_policy(
        &self,
        policy: crate::identity::RecoveryPolicyState,
    ) -> crate::ServiceResult<()> {
        self.0
            .recovery_policies()
            .insert(persistence_recovery_policy(policy))
            .await?;
        Ok(())
    }
}

fn application_recovery_session(
    record: soland_storage::RecoverySessionRecord,
) -> crate::identity::RecoverySessionState {
    crate::identity::RecoverySessionState {
        request_id: record.request_id,
        create_intent_digest: record.create_intent_digest,
        recovery_session_id: record.recovery_session_id,
        session_grant_id: record.session_grant_id,
        session_grant_cnf_jkt: record.session_grant_cnf_jkt,
        principal_id: record.principal_id,
        station_id: record.station_id,
        requesting_device_id: record.requesting_device_id,
        trust_domain: record.trust_domain,
        policy_id: record.policy_id,
        policy_version: record.policy_version,
        identity_model: record.identity_model,
        current_device_generation_ref: record.current_device_generation_ref,
        device_generation_status: record.device_generation_status,
        registry_head: record.registry_head,
        accepted_seal_frontier: record.accepted_seal_frontier,
        policy_payload: record.policy_payload,
        publication_authority_context: record.publication_authority_context,
        publication_authority_context_digest: record.publication_authority_context_digest,
        challenge: record.challenge,
        state: record.state,
        proof_payload: record.proof_payload,
        transaction_id: record.transaction_id,
        created_at: record.created_at,
        updated_at: record.updated_at,
        expires_at: record.expires_at,
    }
}

fn persistence_recovery_session(
    session: crate::identity::RecoverySessionState,
) -> soland_storage::RecoverySessionRecord {
    soland_storage::RecoverySessionRecord {
        request_id: session.request_id,
        create_intent_digest: session.create_intent_digest,
        recovery_session_id: session.recovery_session_id,
        session_grant_id: session.session_grant_id,
        session_grant_cnf_jkt: session.session_grant_cnf_jkt,
        principal_id: session.principal_id,
        station_id: session.station_id,
        requesting_device_id: session.requesting_device_id,
        trust_domain: session.trust_domain,
        policy_id: session.policy_id,
        policy_version: session.policy_version,
        identity_model: session.identity_model,
        current_device_generation_ref: session.current_device_generation_ref,
        device_generation_status: session.device_generation_status,
        registry_head: session.registry_head,
        accepted_seal_frontier: session.accepted_seal_frontier,
        policy_payload: session.policy_payload,
        publication_authority_context: session.publication_authority_context,
        publication_authority_context_digest: session.publication_authority_context_digest,
        challenge: session.challenge,
        state: session.state,
        proof_payload: session.proof_payload,
        transaction_id: session.transaction_id,
        created_at: session.created_at,
        updated_at: session.updated_at,
        expires_at: session.expires_at,
    }
}

#[async_trait::async_trait]
impl crate::identity::RecoverySessionPort for PersistenceRecoverySessions {
    async fn session(
        &self,
        recovery_session_id: &str,
    ) -> crate::ServiceResult<Option<crate::identity::RecoverySessionState>> {
        Ok(self
            .0
            .recovery_sessions()
            .get(recovery_session_id)
            .await?
            .map(application_recovery_session))
    }

    async fn session_for_grant(
        &self,
        session_grant_id: &str,
    ) -> crate::ServiceResult<Option<crate::identity::RecoverySessionState>> {
        Ok(self
            .0
            .recovery_sessions()
            .get_by_grant_id(session_grant_id)
            .await?
            .map(application_recovery_session))
    }

    async fn session_for_request(
        &self,
        session_grant_id: &str,
        request_id: &str,
    ) -> crate::ServiceResult<Option<crate::identity::RecoverySessionState>> {
        Ok(self
            .0
            .recovery_sessions()
            .get_by_grant_request(session_grant_id, request_id)
            .await?
            .map(application_recovery_session))
    }

    async fn insert_session(
        &self,
        session: crate::identity::RecoverySessionState,
    ) -> crate::ServiceResult<()> {
        self.0
            .recovery_sessions()
            .insert(persistence_recovery_session(session))
            .await?;
        Ok(())
    }

    async fn update_session(
        &self,
        session: crate::identity::RecoverySessionState,
    ) -> crate::ServiceResult<()> {
        self.0
            .recovery_sessions()
            .update(persistence_recovery_session(session))
            .await?;
        Ok(())
    }
}

fn application_security_transaction(
    record: soland_storage::SecurityTransactionRecord,
) -> crate::identity::SecurityTransactionRecord {
    crate::identity::SecurityTransactionRecord {
        canonical_request: record.canonical_request,
        resource: record.resource,
    }
}

fn persistence_security_transaction(
    transaction: crate::identity::SecurityTransactionRecord,
) -> soland_storage::SecurityTransactionRecord {
    soland_storage::SecurityTransactionRecord {
        canonical_request: transaction.canonical_request,
        resource: transaction.resource,
    }
}

fn application_security_transaction_step_outcome(
    record: soland_storage::SecurityTransactionStepOutcomeRecord,
) -> crate::identity::SecurityTransactionStepOutcomeState {
    crate::identity::SecurityTransactionStepOutcomeState {
        transaction_id: record.transaction_id,
        step: record.step,
        canonical_request: record.canonical_request,
        response: record.response,
        participant_outcome: record.participant_outcome,
    }
}

fn application_security_transaction_step_attempt(
    record: soland_storage::SecurityTransactionStepAttemptRecord,
) -> crate::identity::SecurityTransactionStepAttemptState {
    crate::identity::SecurityTransactionStepAttemptState {
        transaction_id: record.transaction_id,
        step: record.step,
        canonical_request: record.canonical_request,
    }
}

fn persistence_security_transaction_step_attempt(
    attempt: crate::identity::SecurityTransactionStepAttemptState,
) -> soland_storage::SecurityTransactionStepAttemptRecord {
    soland_storage::SecurityTransactionStepAttemptRecord {
        transaction_id: attempt.transaction_id,
        step: attempt.step,
        canonical_request: attempt.canonical_request,
    }
}

fn persistence_security_transaction_step_outcome(
    outcome: crate::identity::SecurityTransactionStepOutcomeState,
) -> soland_storage::SecurityTransactionStepOutcomeRecord {
    soland_storage::SecurityTransactionStepOutcomeRecord {
        transaction_id: outcome.transaction_id,
        step: outcome.step,
        canonical_request: outcome.canonical_request,
        response: outcome.response,
        participant_outcome: outcome.participant_outcome,
    }
}

fn application_backup_series_erase_progress(
    record: soland_storage::BackupSeriesEraseProgressRecord,
) -> crate::identity::BackupSeriesEraseProgressState {
    crate::identity::BackupSeriesEraseProgressState {
        transaction_id: record.transaction_id,
        canonical_request: record.canonical_request,
        outcome: record.outcome,
    }
}

fn persistence_backup_series_erase_progress(
    progress: crate::identity::BackupSeriesEraseProgressState,
) -> soland_storage::BackupSeriesEraseProgressRecord {
    soland_storage::BackupSeriesEraseProgressRecord {
        transaction_id: progress.transaction_id,
        canonical_request: progress.canonical_request,
        outcome: progress.outcome,
    }
}

#[async_trait::async_trait]
impl crate::identity::SecurityTransactionPort for PersistenceSecurityTransactions {
    async fn create(
        &self,
        transaction: crate::identity::SecurityTransactionRecord,
    ) -> crate::ServiceResult<crate::identity::SecurityTransactionRecord> {
        Ok(application_security_transaction(
            self.0
                .security_transactions()
                .create(persistence_security_transaction(transaction))
                .await?,
        ))
    }

    async fn transaction(
        &self,
        transaction_id: &str,
    ) -> crate::ServiceResult<Option<crate::identity::SecurityTransactionRecord>> {
        Ok(self
            .0
            .security_transactions()
            .get(transaction_id)
            .await?
            .map(application_security_transaction))
    }

    async fn save(
        &self,
        transaction: crate::identity::SecurityTransactionRecord,
    ) -> crate::ServiceResult<()> {
        self.0
            .security_transactions()
            .update(persistence_security_transaction(transaction))
            .await?;
        Ok(())
    }

    async fn step_outcome(
        &self,
        transaction_id: &str,
        step: arkret_wire::SecurityTransactionStep,
    ) -> crate::ServiceResult<Option<crate::identity::SecurityTransactionStepOutcomeState>> {
        Ok(self
            .0
            .security_transactions()
            .step_outcome(transaction_id, step)
            .await?
            .map(application_security_transaction_step_outcome))
    }

    async fn step_attempt(
        &self,
        transaction_id: &str,
        step: arkret_wire::SecurityTransactionStep,
    ) -> crate::ServiceResult<Option<crate::identity::SecurityTransactionStepAttemptState>> {
        Ok(self
            .0
            .security_transactions()
            .step_attempt(transaction_id, step)
            .await?
            .map(application_security_transaction_step_attempt))
    }

    async fn begin_step(
        &self,
        attempt: crate::identity::SecurityTransactionStepAttemptState,
    ) -> crate::ServiceResult<crate::identity::SecurityTransactionStepAttemptState> {
        Ok(application_security_transaction_step_attempt(
            self.0
                .security_transactions()
                .begin_step(persistence_security_transaction_step_attempt(attempt))
                .await?,
        ))
    }

    async fn accept_step(
        &self,
        transaction: crate::identity::SecurityTransactionRecord,
        outcome: crate::identity::SecurityTransactionStepOutcomeState,
    ) -> crate::ServiceResult<crate::identity::SecurityTransactionStepOutcomeState> {
        Ok(application_security_transaction_step_outcome(
            self.0
                .security_transactions()
                .accept_step(
                    persistence_security_transaction(transaction),
                    persistence_security_transaction_step_outcome(outcome),
                )
                .await?,
        ))
    }

    async fn backup_erase_progress(
        &self,
        transaction_id: &str,
    ) -> crate::ServiceResult<Option<crate::identity::BackupSeriesEraseProgressState>> {
        Ok(self
            .0
            .security_transactions()
            .backup_erase_progress(transaction_id)
            .await?
            .map(application_backup_series_erase_progress))
    }

    async fn begin_backup_erase(
        &self,
        progress: crate::identity::BackupSeriesEraseProgressState,
    ) -> crate::ServiceResult<crate::identity::BackupSeriesEraseProgressState> {
        Ok(application_backup_series_erase_progress(
            self.0
                .security_transactions()
                .begin_backup_erase(persistence_backup_series_erase_progress(progress))
                .await?,
        ))
    }

    async fn update_backup_erase(
        &self,
        progress: crate::identity::BackupSeriesEraseProgressState,
    ) -> crate::ServiceResult<crate::identity::BackupSeriesEraseProgressState> {
        Ok(application_backup_series_erase_progress(
            self.0
                .security_transactions()
                .update_backup_erase(persistence_backup_series_erase_progress(progress))
                .await?,
        ))
    }
}

fn application_did_document(
    record: soland_storage::WebvhDocumentRecord,
) -> crate::identity::DidDocumentState {
    crate::identity::DidDocumentState {
        did: record.did,
        did_document: record.did_document,
        key_log_head: record.key_log_head,
        seq: record.seq,
        method_evidence: record.method_evidence,
        fetched_at: record.fetched_at,
        expires_at: record.expires_at,
        updated_at: record.updated_at,
    }
}

fn persistence_did_document(
    record: crate::identity::DidDocumentState,
) -> soland_storage::WebvhDocumentRecord {
    soland_storage::WebvhDocumentRecord {
        did: record.did,
        did_document: record.did_document,
        key_log_head: record.key_log_head,
        seq: record.seq,
        method_evidence: record.method_evidence,
        fetched_at: record.fetched_at,
        expires_at: record.expires_at,
        updated_at: record.updated_at,
    }
}

fn application_did_log_event(
    record: soland_storage::WebvhLogRecord,
) -> crate::identity::DidLogEvent {
    crate::identity::DidLogEvent {
        event_digest: record.event_digest,
        did: record.did,
        seq: record.seq,
        operation: record.operation,
        created_at: record.created_at,
    }
}

fn persistence_did_log_event(
    record: crate::identity::DidLogEvent,
) -> soland_storage::WebvhLogRecord {
    soland_storage::WebvhLogRecord {
        event_digest: record.event_digest,
        did: record.did,
        seq: record.seq,
        operation: record.operation,
        created_at: record.created_at,
    }
}

#[async_trait::async_trait]
impl crate::identity::DidDocumentPort for PersistenceDidDocuments {
    async fn document(
        &self,
        did: &str,
    ) -> crate::ServiceResult<Option<crate::identity::DidDocumentState>> {
        Ok(self
            .0
            .webvh()
            .get_document(did)
            .await?
            .map(application_did_document))
    }

    async fn embedded_document(
        &self,
        local_id: &str,
    ) -> crate::ServiceResult<Option<crate::identity::DidDocumentState>> {
        Ok(self
            .0
            .webvh()
            .get_embedded_webvh_document_by_local_id(local_id)
            .await?
            .map(application_did_document))
    }

    async fn log_events(
        &self,
        did: &str,
    ) -> crate::ServiceResult<Vec<crate::identity::DidLogEvent>> {
        Ok(self
            .0
            .webvh()
            .list_log_events(did)
            .await?
            .into_iter()
            .map(application_did_log_event)
            .collect())
    }

    async fn store_document(
        &self,
        document: crate::identity::DidDocumentState,
    ) -> crate::ServiceResult<()> {
        self.0
            .webvh()
            .put_document(persistence_did_document(document))
            .await?;
        Ok(())
    }

    async fn append_log_event(
        &self,
        event: crate::identity::DidLogEvent,
    ) -> crate::ServiceResult<()> {
        self.0
            .webvh()
            .append_log_event(persistence_did_log_event(event))
            .await?;
        Ok(())
    }

    async fn service_registration(
        &self,
        key: &arkret_models_identity::service_identity::ServiceRegistrationKey,
    ) -> crate::ServiceResult<
        Option<arkret_models_identity::service_identity::ServiceRegistrationOutcome>,
    > {
        Ok(self.0.webvh().get_service_registration(key).await?)
    }

    async fn commit_service_registration(
        &self,
        key: arkret_models_identity::service_identity::ServiceRegistrationKey,
        outcome: arkret_models_identity::service_identity::ServiceRegistrationOutcome,
        document: crate::identity::DidDocumentState,
        event: crate::identity::DidLogEvent,
    ) -> crate::ServiceResult<crate::identity::ServiceRegistrationCommitResult> {
        Ok(
            match self
                .0
                .webvh()
                .commit_service_registration(
                    key,
                    outcome,
                    persistence_did_document(document),
                    persistence_did_log_event(event),
                )
                .await?
            {
                soland_storage::ServiceRegistrationCommitOutcome::Created(outcome) => {
                    crate::identity::ServiceRegistrationCommitResult::Created(outcome)
                }
                soland_storage::ServiceRegistrationCommitOutcome::Existing(outcome) => {
                    crate::identity::ServiceRegistrationCommitResult::Existing(outcome)
                }
                soland_storage::ServiceRegistrationCommitOutcome::Conflict => {
                    crate::identity::ServiceRegistrationCommitResult::Conflict
                }
            },
        )
    }

    async fn commit_log_operation(
        &self,
        expected_current_head: Option<String>,
        document: crate::identity::DidDocumentState,
        event: crate::identity::DidLogEvent,
    ) -> crate::ServiceResult<crate::identity::DidLogCommitResult> {
        Ok(
            match self
                .0
                .webvh()
                .commit_log_operation(
                    expected_current_head,
                    persistence_did_document(document),
                    persistence_did_log_event(event),
                )
                .await?
            {
                soland_storage::WebvhLogCommitOutcome::Accepted => {
                    crate::identity::DidLogCommitResult::Accepted
                }
                soland_storage::WebvhLogCommitOutcome::Duplicate => {
                    crate::identity::DidLogCommitResult::Duplicate
                }
                soland_storage::WebvhLogCommitOutcome::Conflict => {
                    crate::identity::DidLogCommitResult::Conflict
                }
            },
        )
    }
}

#[derive(Clone)]
pub struct PersistenceIdentityServices {
    pub identity: IdentityService,
    pub account_data: AccountDataService,
    pub key_material: KeyMaterialService,
    pub consent: ConsentService,
    pub contact: ContactService,
    pub agent_pairing: AgentPairingService,
    pub device_pairing: DevicePairingService,
    pub agent_participation: AgentParticipationService,
    pub key_backup: KeyBackupService,
    pub session: SessionService,
    pub recovery_policy: RecoveryPolicyService,
    pub recovery_session: RecoverySessionService,
    pub security_transaction: SecurityTransactionService,
    pub did: DidService,
    pub organization_registration:
        crate::organization_registration::OrganizationRegistrationService,
}

pub fn build_persistence_identity_services(
    persistence: Arc<dyn PersistenceStore>,
    did_resolver: Arc<dyn DidResolverPort>,
) -> PersistenceIdentityServices {
    let did = DidService::new(
        Arc::new(PersistenceDidDocuments(persistence.clone())),
        did_resolver,
    );
    PersistenceIdentityServices {
        identity: IdentityService::new(
            Arc::new(PersistenceAccountLookup(persistence.clone())),
            Arc::new(PersistenceDeviceDirectory(persistence.clone())),
            Arc::new(PersistenceAgentDirectory(persistence.clone())),
        ),
        account_data: AccountDataService::new(Arc::new(PersistenceAccountData(
            persistence.clone(),
        ))),
        key_material: KeyMaterialService::new(
            Arc::new(PersistenceDeviceKeys(persistence.clone())),
            Arc::new(PersistenceOneTimeKeys(persistence.clone())),
        ),
        consent: ConsentService::new(
            Arc::new(PersistenceConsentCells(persistence.clone())),
            Arc::new(PersistenceMimiConsentCorrelations(persistence.clone())),
        ),
        contact: ContactService::new(
            Arc::new(PersistenceContacts(persistence.clone())),
            Arc::new(PersistenceInviteReceivePolicies(persistence.clone())),
        ),
        agent_pairing: AgentPairingService::new(
            Arc::new(PersistenceAgentPairing(persistence.clone())),
            Arc::new(PersistenceSidecars(persistence.clone())),
        ),
        device_pairing: DevicePairingService::new(Arc::new(PersistenceDevicePairing(
            persistence.clone(),
        ))),
        agent_participation: AgentParticipationService::new(Arc::new(
            PersistenceAgentParticipation(persistence.clone()),
        )),
        key_backup: KeyBackupService::new(Arc::new(PersistenceKeyBackups(persistence.clone()))),
        session: SessionService::new(Arc::new(PersistenceSessions(persistence.clone()))),
        recovery_policy: RecoveryPolicyService::new(Arc::new(PersistenceRecoveryPolicies(
            persistence.clone(),
        ))),
        recovery_session: RecoverySessionService::new(Arc::new(PersistenceRecoverySessions(
            persistence.clone(),
        ))),
        security_transaction: SecurityTransactionService::new(Arc::new(
            PersistenceSecurityTransactions(persistence.clone()),
        )),
        organization_registration:
            crate::organization_registration::OrganizationRegistrationService::new(
                persistence,
                did.clone(),
            ),
        did,
    }
}
