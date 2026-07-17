use std::sync::Arc;

use arkret_sdk::{
    BlobRef, DeviceGenerationStatus, Hash, NonEmptyString, RecoveryIdentityModel, SealBasis,
    ServiceRegistrationKey, ServiceRegistrationOutcome,
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde_json::Value;
use soland_domain::identity::{
    ConsentCellKey, ConsentCellRecord, ContactRecord, DirectConversationBindingRecord,
};

use crate::ApplicationResult;

#[derive(Clone, Debug)]
pub struct FindAccountByActorQuery {
    pub actor_id: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccountIdentity {
    pub account_id: String,
}

#[derive(Clone, Debug)]
pub struct AccountProfileState {
    pub id: String,
    pub did: String,
    pub localpart: String,
    pub display_name: Option<String>,
    pub bio: Option<String>,
    pub avatar_blob_ref: Option<BlobRef>,
    pub created_at: DateTime<Utc>,
}

impl AccountProfileState {
    pub fn handle(&self) -> String {
        if self.localpart.is_empty() {
            String::new()
        } else {
            format!("@{}", self.localpart)
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccountLocalpartState {
    pub id: String,
    pub account_did: String,
    pub localpart: String,
    pub is_primary: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug)]
pub struct AccountLifecycleState {
    pub state: String,
    pub reason: Option<String>,
    pub changed_by: Option<String>,
    pub changed_at: DateTime<Utc>,
}

#[derive(Clone, Debug)]
pub struct RegisterAccountCommand {
    pub account_id: String,
    pub actor_id: String,
    pub localpart: String,
    pub display_name: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Clone, Debug)]
pub struct AccountDataState {
    pub actor_id: String,
    pub data_type: String,
    pub payload: Value,
    pub updated_at: DateTime<Utc>,
}

#[async_trait]
pub trait AccountDataPort: Send + Sync {
    async fn entry(
        &self,
        actor_id: &str,
        data_type: &str,
    ) -> ApplicationResult<Option<AccountDataState>>;
    async fn entries_for_actor(&self, actor_id: &str) -> ApplicationResult<Vec<AccountDataState>>;
    async fn save_entry(&self, entry: AccountDataState) -> ApplicationResult<()>;
    async fn delete_entry(&self, actor_id: &str, data_type: &str) -> ApplicationResult<()>;
}

#[derive(Clone)]
pub struct AccountDataApplicationService {
    account_data: Arc<dyn AccountDataPort>,
}

#[async_trait]
pub trait ConsentCellPort: Send + Sync {
    async fn save_cell(&self, cell: ConsentCellRecord) -> ApplicationResult<()>;
    async fn cells(&self) -> ApplicationResult<Vec<(ConsentCellKey, ConsentCellRecord)>>;
}

#[derive(Clone)]
pub struct ConsentApplicationService {
    consent_cells: Arc<dyn ConsentCellPort>,
}

#[async_trait]
pub trait ContactPort: Send + Sync {
    async fn contact_any(
        &self,
        requester: &str,
        target: &str,
    ) -> ApplicationResult<Option<ContactRecord>>;
    async fn contact(
        &self,
        requester: &str,
        target: &str,
        scope: &str,
    ) -> ApplicationResult<Option<ContactRecord>>;
    async fn contacts_for_actor(&self, actor_id: &str) -> ApplicationResult<Vec<ContactRecord>>;
    async fn save_contact(&self, contact: ContactRecord) -> ApplicationResult<()>;
}

#[async_trait]
pub trait InviteReceivePolicyPort: Send + Sync {
    async fn save_policy(&self, policy: arkret_sdk::InviteReceivePolicy) -> ApplicationResult<()>;
}

#[async_trait]
pub trait DirectConversationBindingPort: Send + Sync {
    async fn save_binding(
        &self,
        pair_key: &str,
        binding: DirectConversationBindingRecord,
    ) -> ApplicationResult<()>;
    async fn delete_binding(&self, pair_key: &str) -> ApplicationResult<()>;
}

#[derive(Clone)]
pub struct ContactApplicationService {
    contacts: Arc<dyn ContactPort>,
    invite_policies: Arc<dyn InviteReceivePolicyPort>,
    direct_bindings: Arc<dyn DirectConversationBindingPort>,
}

impl ContactApplicationService {
    pub fn new(
        contacts: Arc<dyn ContactPort>,
        invite_policies: Arc<dyn InviteReceivePolicyPort>,
        direct_bindings: Arc<dyn DirectConversationBindingPort>,
    ) -> Self {
        Self {
            contacts,
            invite_policies,
            direct_bindings,
        }
    }

    pub async fn contact(
        &self,
        requester: &str,
        target: &str,
        scope: &str,
    ) -> ApplicationResult<Option<ContactRecord>> {
        self.contacts.contact(requester, target, scope).await
    }

    pub async fn contact_any(
        &self,
        requester: &str,
        target: &str,
    ) -> ApplicationResult<Option<ContactRecord>> {
        self.contacts.contact_any(requester, target).await
    }

    pub async fn contacts_for_actor(
        &self,
        actor_id: &str,
    ) -> ApplicationResult<Vec<ContactRecord>> {
        self.contacts.contacts_for_actor(actor_id).await
    }

    pub async fn save_contact(&self, contact: ContactRecord) -> ApplicationResult<()> {
        self.contacts.save_contact(contact).await
    }

    pub async fn save_invite_policy(
        &self,
        policy: arkret_sdk::InviteReceivePolicy,
    ) -> ApplicationResult<()> {
        self.invite_policies.save_policy(policy).await
    }

    pub async fn save_direct_binding(
        &self,
        pair_key: &str,
        binding: DirectConversationBindingRecord,
    ) -> ApplicationResult<()> {
        self.direct_bindings.save_binding(pair_key, binding).await
    }

    pub async fn delete_direct_binding(&self, pair_key: &str) -> ApplicationResult<()> {
        self.direct_bindings.delete_binding(pair_key).await
    }
}

impl ConsentApplicationService {
    pub fn new(consent_cells: Arc<dyn ConsentCellPort>) -> Self {
        Self { consent_cells }
    }

    pub async fn save_cell(&self, cell: ConsentCellRecord) -> ApplicationResult<()> {
        self.consent_cells.save_cell(cell).await
    }

    pub async fn cells(&self) -> ApplicationResult<Vec<(ConsentCellKey, ConsentCellRecord)>> {
        self.consent_cells.cells().await
    }
}

impl AccountDataApplicationService {
    pub fn new(account_data: Arc<dyn AccountDataPort>) -> Self {
        Self { account_data }
    }

    pub async fn entry(
        &self,
        actor_id: &str,
        data_type: &str,
    ) -> ApplicationResult<Option<AccountDataState>> {
        self.account_data.entry(actor_id, data_type).await
    }

    pub async fn entries_for_actor(
        &self,
        actor_id: &str,
    ) -> ApplicationResult<Vec<AccountDataState>> {
        self.account_data.entries_for_actor(actor_id).await
    }

    pub async fn save_entry(&self, entry: AccountDataState) -> ApplicationResult<()> {
        self.account_data.save_entry(entry).await
    }

    pub async fn delete_entry(&self, actor_id: &str, data_type: &str) -> ApplicationResult<()> {
        self.account_data.delete_entry(actor_id, data_type).await
    }
}

#[derive(Clone, Debug, Default)]
pub struct ListActiveDeviceActorsQuery;

#[derive(Clone, Debug)]
pub struct FindDeviceQuery {
    pub actor_id: String,
    pub device_id: String,
}

#[derive(Clone, Debug)]
pub struct DeviceIdentity {
    pub actor_id: String,
    pub device_id: String,
    pub display_name: Option<String>,
    pub verification_state: String,
    pub payload: Value,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
}

#[async_trait]
pub trait DeviceKeyPort: Send + Sync {
    async fn save_bundle(
        &self,
        actor_id: String,
        device_id: String,
        payload: Value,
    ) -> ApplicationResult<()>;
    async fn bundle(&self, actor_id: &str, device_id: &str) -> ApplicationResult<Option<Value>>;
}

#[async_trait]
pub trait OneTimeKeyPort: Send + Sync {
    async fn save_keys(
        &self,
        actor_id: String,
        device_id: String,
        keys: Vec<Value>,
    ) -> ApplicationResult<()>;
    async fn claim_key(&self, actor_id: &str, device_id: &str) -> ApplicationResult<Option<Value>>;
}

#[derive(Clone)]
pub struct KeyMaterialApplicationService {
    device_keys: Arc<dyn DeviceKeyPort>,
    one_time_keys: Arc<dyn OneTimeKeyPort>,
}

impl KeyMaterialApplicationService {
    pub fn new(
        device_keys: Arc<dyn DeviceKeyPort>,
        one_time_keys: Arc<dyn OneTimeKeyPort>,
    ) -> Self {
        Self {
            device_keys,
            one_time_keys,
        }
    }

    pub async fn save_bundle(
        &self,
        actor_id: String,
        device_id: String,
        payload: Value,
    ) -> ApplicationResult<()> {
        self.device_keys
            .save_bundle(actor_id, device_id, payload)
            .await
    }

    pub async fn bundle(
        &self,
        actor_id: &str,
        device_id: &str,
    ) -> ApplicationResult<Option<Value>> {
        self.device_keys.bundle(actor_id, device_id).await
    }

    pub async fn save_one_time_keys(
        &self,
        actor_id: String,
        device_id: String,
        keys: Vec<Value>,
    ) -> ApplicationResult<()> {
        self.one_time_keys
            .save_keys(actor_id, device_id, keys)
            .await
    }

    pub async fn claim_one_time_key(
        &self,
        actor_id: &str,
        device_id: &str,
    ) -> ApplicationResult<Option<Value>> {
        self.one_time_keys.claim_key(actor_id, device_id).await
    }
}

#[derive(Clone, Debug)]
pub struct SaveDeviceCommand {
    pub actor_id: String,
    pub device_id: String,
    pub display_name: Option<String>,
    pub device: DeviceIdentity,
}

#[derive(Clone, Debug)]
pub struct FindAgentControllerQuery {
    pub agent_id: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentController {
    pub controller_id: String,
}

#[async_trait]
pub trait AccountLookupPort: Send + Sync {
    async fn find_account_by_actor(
        &self,
        actor_id: &str,
    ) -> ApplicationResult<Option<AccountIdentity>>;
    async fn register_account(&self, command: RegisterAccountCommand) -> ApplicationResult<()>;
    async fn account(&self, actor_id: &str) -> ApplicationResult<Option<AccountProfileState>>;
    async fn save_account(&self, account: AccountProfileState) -> ApplicationResult<()>;
    async fn delete_account(&self, actor_id: &str) -> ApplicationResult<()>;
    async fn account_localparts(
        &self,
        actor_id: &str,
    ) -> ApplicationResult<Vec<AccountLocalpartState>>;
    async fn localpart_owner(
        &self,
        localpart: &str,
    ) -> ApplicationResult<Option<AccountLocalpartState>>;
    async fn add_localpart(
        &self,
        actor_id: &str,
        localpart: &str,
        primary: bool,
    ) -> ApplicationResult<AccountLocalpartState>;
    async fn set_primary_localpart(
        &self,
        actor_id: &str,
        localpart: &str,
    ) -> ApplicationResult<AccountLocalpartState>;
    async fn remove_localpart(&self, actor_id: &str, localpart: &str) -> ApplicationResult<()>;
    async fn clear_localparts(&self, actor_id: &str) -> ApplicationResult<()>;
    async fn record_handle_release(
        &self,
        localpart: &str,
        released_at: DateTime<Utc>,
    ) -> ApplicationResult<()>;
    async fn save_account_lifecycle(
        &self,
        actor_id: &str,
        lifecycle: AccountLifecycleState,
    ) -> ApplicationResult<()>;
    async fn delete_account_lifecycle(&self, actor_id: &str) -> ApplicationResult<()>;
}

#[async_trait]
pub trait DeviceDirectoryPort: Send + Sync {
    async fn list_active_device_actors(&self) -> ApplicationResult<Vec<String>>;
    async fn find_device(
        &self,
        actor_id: &str,
        device_id: &str,
    ) -> ApplicationResult<Option<DeviceIdentity>>;
    async fn save_device(&self, command: SaveDeviceCommand) -> ApplicationResult<()>;
    async fn save_device_if_absent(&self, device: DeviceIdentity) -> ApplicationResult<bool>;
    async fn devices_for_actor(&self, actor_id: &str) -> ApplicationResult<Vec<DeviceIdentity>>;
}

#[async_trait]
pub trait AgentDirectoryPort: Send + Sync {
    async fn find_agent_controller(
        &self,
        agent_id: &str,
    ) -> ApplicationResult<Option<AgentController>>;
}

#[derive(Clone)]
pub struct IdentityApplicationService {
    accounts: Arc<dyn AccountLookupPort>,
    devices: Arc<dyn DeviceDirectoryPort>,
    agents: Arc<dyn AgentDirectoryPort>,
}

#[derive(Clone, Debug)]
pub struct ActivateAgentRuntimeCommand {
    pub agent_id: String,
    pub approval_request_id: String,
    pub runtime_key_binding_digest: String,
    pub pairing_request_id: String,
    pub paired_request_digest: String,
    pub authorized_event_ref: String,
    pub authorized_verification_method: String,
    pub authorized_public_key_digest: String,
    pub authorized_at: DateTime<Utc>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct AgentPairingState {
    pub id: String,
    pub controller_id: String,
    pub principal_control_realm_id: String,
    pub controller_authorization_ref: String,
    pub display_name: Option<String>,
    pub agent_slug: Option<String>,
    pub avatar_blob_ref: Option<String>,
    pub state: String,
    pub requested_scope: Option<Value>,
    pub accountability: Option<Value>,
    pub provision_event_refs: Option<Value>,
    pub pairing_request_id: Option<String>,
    pub paired_pairing_request_id: Option<String>,
    pub paired_request_digest: Option<String>,
    pub pairing_code: Option<String>,
    pub pairing_expires_at: Option<DateTime<Utc>>,
    pub approval_request_id: Option<String>,
    pub controller_account_id: Option<uuid::Uuid>,
    pub recipient_service_id: Option<String>,
    pub runtime_key_binding_digest: Option<String>,
    pub runtime_public_key_digest: Option<String>,
    pub runtime_attestation_digest: Option<String>,
    pub approval_notification_id: Option<uuid::Uuid>,
    pub runtime_key_request: Option<Value>,
    pub approval_requested_at: Option<DateTime<Utc>>,
    pub authorized_event_ref: Option<String>,
    pub authorized_verification_method: Option<String>,
    pub authorized_public_key_digest: Option<String>,
    pub state_changed_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl AgentPairingState {
    pub fn new(
        id: String,
        controller_id: String,
        principal_control_realm_id: String,
        controller_authorization_ref: String,
        state: String,
        created_at: DateTime<Utc>,
    ) -> Self {
        Self {
            id,
            controller_id,
            principal_control_realm_id,
            controller_authorization_ref,
            display_name: None,
            agent_slug: None,
            avatar_blob_ref: None,
            state,
            requested_scope: None,
            accountability: None,
            provision_event_refs: None,
            pairing_request_id: None,
            paired_pairing_request_id: None,
            paired_request_digest: None,
            pairing_code: None,
            pairing_expires_at: None,
            approval_request_id: None,
            controller_account_id: None,
            recipient_service_id: None,
            runtime_key_binding_digest: None,
            runtime_public_key_digest: None,
            runtime_attestation_digest: None,
            approval_notification_id: None,
            runtime_key_request: None,
            approval_requested_at: None,
            authorized_event_ref: None,
            authorized_verification_method: None,
            authorized_public_key_digest: None,
            state_changed_at: Some(created_at),
            created_at,
            updated_at: created_at,
        }
    }
}

#[derive(Clone, Debug)]
pub struct StoreAgentRuntimeApprovalCommand {
    pub agent_id: String,
    pub pairing_request_id: String,
    pub approval_request_id: String,
    pub approval_notification_id: String,
    pub approval_requested_at: DateTime<Utc>,
    pub controller_account_id: String,
    pub recipient_service_id: String,
    pub runtime_key_binding_digest: String,
    pub runtime_public_key_digest: String,
    pub runtime_attestation_digest: String,
    pub runtime_key_request: Value,
}

#[async_trait]
pub trait AgentPairingPort: Send + Sync {
    async fn pairing_record(
        &self,
        pairing_request_id: &str,
    ) -> ApplicationResult<Option<AgentPairingState>>;
    async fn agent(&self, agent_id: &str) -> ApplicationResult<Option<AgentPairingState>>;
    async fn agents_for_controller(
        &self,
        controller_id: &str,
    ) -> ApplicationResult<Vec<AgentPairingState>>;
    async fn save_agent(&self, agent: AgentPairingState) -> ApplicationResult<()>;
    async fn store_runtime_approval(
        &self,
        command: &StoreAgentRuntimeApprovalCommand,
    ) -> ApplicationResult<Option<AgentPairingState>>;
    async fn activate_runtime_if_current(
        &self,
        command: &ActivateAgentRuntimeCommand,
    ) -> ApplicationResult<bool>;
    async fn clear_approval_notification_if_current(
        &self,
        agent_id: &str,
        approval_request_id: &str,
    ) -> ApplicationResult<bool>;
}

#[derive(Clone)]
pub struct AgentPairingApplicationService {
    pairing: Arc<dyn AgentPairingPort>,
}

#[derive(Clone, Debug)]
pub struct RecoveryPolicyState {
    pub policy_id: String,
    pub principal_id: String,
    pub version: u32,
    pub trust_domain: String,
    pub allowed_proof_kinds: Vec<String>,
    pub supersedes: Option<String>,
    pub expires_at: Option<DateTime<Utc>>,
    pub issued_at: DateTime<Utc>,
    pub raw_payload: Value,
    pub accepted_at: DateTime<Utc>,
    pub verification_method: String,
}

#[derive(Clone, Debug)]
pub struct PublishRecoveryPolicyCommand {
    pub policy: RecoveryPolicyState,
}

#[derive(Clone, Debug)]
pub enum PublishRecoveryPolicyResult {
    Accepted(RecoveryPolicyState),
    GenesisVersionInvalid {
        actual: u32,
    },
    VersionNotMonotonic {
        actual: u32,
        current: u32,
    },
    SupersedesInvalid {
        actual: Option<String>,
        current_policy_id: String,
    },
}

#[async_trait]
pub trait RecoveryPolicyPort: Send + Sync {
    async fn active_policy(
        &self,
        principal_id: &str,
    ) -> ApplicationResult<Option<RecoveryPolicyState>>;
    async fn policy_history(
        &self,
        principal_id: &str,
    ) -> ApplicationResult<Vec<RecoveryPolicyState>>;
    async fn insert_policy(&self, policy: RecoveryPolicyState) -> ApplicationResult<()>;
}

#[derive(Clone)]
pub struct RecoveryPolicyApplicationService {
    policies: Arc<dyn RecoveryPolicyPort>,
}

impl RecoveryPolicyApplicationService {
    pub fn new(policies: Arc<dyn RecoveryPolicyPort>) -> Self {
        Self { policies }
    }

    pub async fn active_policy(
        &self,
        principal_id: &str,
    ) -> ApplicationResult<Option<RecoveryPolicyState>> {
        self.policies.active_policy(principal_id).await
    }

    pub async fn policy_history(
        &self,
        principal_id: &str,
    ) -> ApplicationResult<Vec<RecoveryPolicyState>> {
        self.policies.policy_history(principal_id).await
    }

    pub async fn publish_policy(
        &self,
        command: PublishRecoveryPolicyCommand,
    ) -> ApplicationResult<PublishRecoveryPolicyResult> {
        let policy = command.policy;
        let existing = self.policies.active_policy(&policy.principal_id).await?;
        if let Some(existing) = existing {
            if policy.version <= existing.version {
                return Ok(PublishRecoveryPolicyResult::VersionNotMonotonic {
                    actual: policy.version,
                    current: existing.version,
                });
            }
            if policy.supersedes.as_deref() != Some(existing.policy_id.as_str()) {
                return Ok(PublishRecoveryPolicyResult::SupersedesInvalid {
                    actual: policy.supersedes,
                    current_policy_id: existing.policy_id,
                });
            }
        } else if policy.version != 1 {
            return Ok(PublishRecoveryPolicyResult::GenesisVersionInvalid {
                actual: policy.version,
            });
        }
        self.policies.insert_policy(policy.clone()).await?;
        Ok(PublishRecoveryPolicyResult::Accepted(policy))
    }
}

#[derive(Clone, Debug)]
pub struct RecoveryReceiptState {
    pub receipt_id: String,
    pub principal_id: String,
    pub recovery_session_id: String,
    pub policy_id: String,
    pub policy_version: u32,
    pub trust_domain: String,
    pub new_device_id: String,
    pub proof_digest: String,
    pub outcome: String,
    pub started_at: DateTime<Utc>,
    pub completed_at: DateTime<Utc>,
    pub raw_payload: Value,
    pub verification_method: String,
    pub accepted_at: DateTime<Utc>,
}

#[async_trait]
pub trait RecoveryReceiptPort: Send + Sync {
    async fn receipt_history(
        &self,
        principal_id: &str,
    ) -> ApplicationResult<Vec<RecoveryReceiptState>>;
    async fn insert_receipt(&self, receipt: RecoveryReceiptState) -> ApplicationResult<()>;
}

#[derive(Clone)]
pub struct RecoveryReceiptApplicationService {
    receipts: Arc<dyn RecoveryReceiptPort>,
}

impl RecoveryReceiptApplicationService {
    pub fn new(receipts: Arc<dyn RecoveryReceiptPort>) -> Self {
        Self { receipts }
    }

    pub async fn receipt_history(
        &self,
        principal_id: &str,
    ) -> ApplicationResult<Vec<RecoveryReceiptState>> {
        self.receipts.receipt_history(principal_id).await
    }

    pub async fn record_receipt(&self, receipt: RecoveryReceiptState) -> ApplicationResult<()> {
        self.receipts.insert_receipt(receipt).await
    }
}

#[derive(Clone, Debug)]
pub struct RecoverySessionState {
    pub recovery_session_id: String,
    pub principal_id: String,
    pub requesting_device_id: String,
    pub trust_domain: String,
    pub policy_id: String,
    pub policy_version: u32,
    pub identity_model: RecoveryIdentityModel,
    pub ssk_generation: Option<u64>,
    pub current_device_generation_ref: Option<NonEmptyString>,
    pub device_generation_status: Option<DeviceGenerationStatus>,
    pub registry_head: Option<Hash>,
    pub accepted_seal_frontier: Option<SealBasis>,
    pub policy_payload: Value,
    pub challenge: String,
    pub state: String,
    pub proof_payload: Option<Value>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[async_trait]
pub trait RecoverySessionPort: Send + Sync {
    async fn session(
        &self,
        recovery_session_id: &str,
    ) -> ApplicationResult<Option<RecoverySessionState>>;
    async fn insert_session(&self, session: RecoverySessionState) -> ApplicationResult<()>;
    async fn update_session(&self, session: RecoverySessionState) -> ApplicationResult<()>;
}

#[derive(Clone)]
pub struct RecoverySessionApplicationService {
    sessions: Arc<dyn RecoverySessionPort>,
}

impl RecoverySessionApplicationService {
    pub fn new(sessions: Arc<dyn RecoverySessionPort>) -> Self {
        Self { sessions }
    }

    pub async fn session(
        &self,
        recovery_session_id: &str,
    ) -> ApplicationResult<Option<RecoverySessionState>> {
        self.sessions.session(recovery_session_id).await
    }

    pub async fn create_session(&self, session: RecoverySessionState) -> ApplicationResult<()> {
        self.sessions.insert_session(session).await
    }

    pub async fn save_session(&self, session: RecoverySessionState) -> ApplicationResult<()> {
        self.sessions.update_session(session).await
    }
}

#[async_trait]
pub trait AgentParticipationPort: Send + Sync {
    async fn store_selection(&self, selection: Value) -> ApplicationResult<()>;
    async fn selections(&self, agent_id: &str) -> ApplicationResult<Vec<Value>>;
}

#[derive(Clone)]
pub struct AgentParticipationApplicationService {
    participation: Arc<dyn AgentParticipationPort>,
}

impl AgentParticipationApplicationService {
    pub fn new(participation: Arc<dyn AgentParticipationPort>) -> Self {
        Self { participation }
    }

    pub async fn store_selection(&self, selection: Value) -> ApplicationResult<()> {
        self.participation.store_selection(selection).await
    }

    pub async fn selections(&self, agent_id: &str) -> ApplicationResult<Vec<Value>> {
        self.participation.selections(agent_id).await
    }
}

#[async_trait]
pub trait KeyBackupPort: Send + Sync {
    async fn backup(&self, backup_id: &str) -> ApplicationResult<Option<Value>>;
    async fn backups_for_actor(&self, actor_id: &str) -> ApplicationResult<Vec<Value>>;
    async fn store_backup(&self, backup_id: String, payload: Value) -> ApplicationResult<()>;
    async fn delete_backup(&self, backup_id: &str) -> ApplicationResult<bool>;
}

#[derive(Clone)]
pub struct KeyBackupApplicationService {
    backups: Arc<dyn KeyBackupPort>,
}

#[derive(Clone, Debug)]
pub struct AgentSessionState {
    pub granted_scope: Vec<String>,
    pub scope_details: Value,
    pub freshness_state: arkret_sdk::FreshnessState,
}

#[derive(Clone, Debug)]
pub struct SessionIdentityState {
    pub token_hash: String,
    pub actor_id: String,
    pub device_id: String,
    pub audience: String,
    pub session_public_key: Option<String>,
    pub agent_session: Option<AgentSessionState>,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
}

#[async_trait]
pub trait SessionIdentityPort: Send + Sync {
    async fn session(&self, token_hash: &str) -> ApplicationResult<Option<SessionIdentityState>>;
    async fn sessions(&self) -> ApplicationResult<Vec<SessionIdentityState>>;
    async fn save_session(&self, session: SessionIdentityState) -> ApplicationResult<()>;
    async fn revoke_session(
        &self,
        token_hash: &str,
        revoked_at: DateTime<Utc>,
    ) -> ApplicationResult<Option<SessionIdentityState>>;
    async fn revoke_actor_sessions(
        &self,
        actor_id: &str,
        revoked_at: DateTime<Utc>,
    ) -> ApplicationResult<usize>;
    async fn revoke_actor_device_sessions(
        &self,
        actor_id: &str,
        device_id: &str,
        revoked_at: DateTime<Utc>,
    ) -> ApplicationResult<usize>;
}

#[derive(Clone)]
pub struct SessionApplicationService {
    sessions: Arc<dyn SessionIdentityPort>,
}

impl SessionApplicationService {
    pub fn new(sessions: Arc<dyn SessionIdentityPort>) -> Self {
        Self { sessions }
    }

    pub async fn session(
        &self,
        token_hash: &str,
    ) -> ApplicationResult<Option<SessionIdentityState>> {
        self.sessions.session(token_hash).await
    }

    pub async fn create_session(&self, session: SessionIdentityState) -> ApplicationResult<()> {
        self.sessions.save_session(session).await
    }

    pub async fn revoke_session(
        &self,
        token_hash: &str,
        revoked_at: DateTime<Utc>,
    ) -> ApplicationResult<Option<SessionIdentityState>> {
        self.sessions.revoke_session(token_hash, revoked_at).await
    }

    pub async fn revoke_actor_sessions(
        &self,
        actor_id: &str,
        revoked_at: DateTime<Utc>,
    ) -> ApplicationResult<usize> {
        self.sessions
            .revoke_actor_sessions(actor_id, revoked_at)
            .await
    }

    pub async fn revoke_actor_device_sessions(
        &self,
        actor_id: &str,
        device_id: &str,
        revoked_at: DateTime<Utc>,
    ) -> ApplicationResult<usize> {
        self.sessions
            .revoke_actor_device_sessions(actor_id, device_id, revoked_at)
            .await
    }

    pub async fn active_delegated_sessions_for_actor(
        &self,
        actor_id: &str,
    ) -> ApplicationResult<usize> {
        Ok(self
            .sessions
            .sessions()
            .await?
            .into_iter()
            .filter(|session| {
                session.actor_id == actor_id
                    && session.revoked_at.is_none()
                    && session.agent_session.is_some()
            })
            .count())
    }

    pub async fn revoke_delegated_sessions(
        &self,
        applet_id: &str,
        service_id: Option<&str>,
        grant_refs: &[String],
        revoked_at: DateTime<Utc>,
    ) -> ApplicationResult<Vec<String>> {
        let sessions = self.sessions.sessions().await?;
        let mut revoked_refs = Vec::new();
        for mut session in sessions.into_iter().filter(|session| {
            session.revoked_at.is_none()
                && session.agent_session.as_ref().is_some_and(|agent| {
                    delegated_session_matches(agent, applet_id, service_id, grant_refs)
                })
        }) {
            session.revoked_at = Some(revoked_at);
            revoked_refs.push(delegated_session_revocation_ref(&session));
            self.sessions.save_session(session).await?;
        }
        revoked_refs.sort();
        revoked_refs.dedup();
        Ok(revoked_refs)
    }
}

fn delegated_session_matches(
    agent: &AgentSessionState,
    applet_id: &str,
    service_id: Option<&str>,
    grant_refs: &[String],
) -> bool {
    json_contains_string(&agent.scope_details, applet_id)
        || service_id.is_some_and(|did| json_contains_string(&agent.scope_details, did))
        || grant_refs
            .iter()
            .any(|grant_ref| json_contains_string(&agent.scope_details, grant_ref))
}

fn delegated_session_revocation_ref(session: &SessionIdentityState) -> String {
    session
        .agent_session
        .as_ref()
        .and_then(|agent| {
            find_first_string_key(
                &agent.scope_details,
                &[
                    "session_grant_revocation_ref",
                    "revocation_ref",
                    "session_grant_id",
                    "grant_id",
                    "authorization_ref",
                ],
            )
        })
        .unwrap_or_else(|| session.token_hash.clone())
}

fn find_first_string_key(value: &Value, keys: &[&str]) -> Option<String> {
    match value {
        Value::Object(object) => {
            for key in keys {
                if let Some(value) = object.get(*key).and_then(Value::as_str)
                    && !value.trim().is_empty()
                {
                    return Some(value.to_owned());
                }
            }
            object
                .values()
                .find_map(|value| find_first_string_key(value, keys))
        }
        Value::Array(values) => values
            .iter()
            .find_map(|value| find_first_string_key(value, keys)),
        _ => None,
    }
}

fn json_contains_string(value: &Value, needle: &str) -> bool {
    match value {
        Value::String(value) => value == needle,
        Value::Array(values) => values
            .iter()
            .any(|value| json_contains_string(value, needle)),
        Value::Object(object) => object
            .values()
            .any(|value| json_contains_string(value, needle)),
        _ => false,
    }
}

impl KeyBackupApplicationService {
    pub fn new(backups: Arc<dyn KeyBackupPort>) -> Self {
        Self { backups }
    }

    pub async fn backup(&self, backup_id: &str) -> ApplicationResult<Option<Value>> {
        self.backups.backup(backup_id).await
    }

    pub async fn backups_for_actor(&self, actor_id: &str) -> ApplicationResult<Vec<Value>> {
        self.backups.backups_for_actor(actor_id).await
    }

    pub async fn store_backup(&self, backup_id: String, payload: Value) -> ApplicationResult<()> {
        self.backups.store_backup(backup_id, payload).await
    }

    pub async fn delete_backup(&self, backup_id: &str) -> ApplicationResult<bool> {
        self.backups.delete_backup(backup_id).await
    }
}

impl AgentPairingApplicationService {
    pub fn new(pairing: Arc<dyn AgentPairingPort>) -> Self {
        Self { pairing }
    }

    pub async fn pairing_record(
        &self,
        pairing_request_id: &str,
    ) -> ApplicationResult<Option<AgentPairingState>> {
        self.pairing.pairing_record(pairing_request_id).await
    }

    pub async fn agent(&self, agent_id: &str) -> ApplicationResult<Option<AgentPairingState>> {
        self.pairing.agent(agent_id).await
    }

    pub async fn agents_for_controller(
        &self,
        controller_id: &str,
    ) -> ApplicationResult<Vec<AgentPairingState>> {
        self.pairing.agents_for_controller(controller_id).await
    }

    pub async fn save_agent(&self, agent: AgentPairingState) -> ApplicationResult<()> {
        self.pairing.save_agent(agent).await
    }

    pub async fn store_runtime_approval(
        &self,
        command: &StoreAgentRuntimeApprovalCommand,
    ) -> ApplicationResult<Option<AgentPairingState>> {
        self.pairing.store_runtime_approval(command).await
    }

    pub async fn activate_runtime(
        &self,
        command: &ActivateAgentRuntimeCommand,
    ) -> ApplicationResult<bool> {
        self.pairing.activate_runtime_if_current(command).await
    }

    pub async fn clear_approval_notification(
        &self,
        agent_id: &str,
        approval_request_id: &str,
    ) -> ApplicationResult<bool> {
        self.pairing
            .clear_approval_notification_if_current(agent_id, approval_request_id)
            .await
    }
}

impl IdentityApplicationService {
    pub fn new(
        accounts: Arc<dyn AccountLookupPort>,
        devices: Arc<dyn DeviceDirectoryPort>,
        agents: Arc<dyn AgentDirectoryPort>,
    ) -> Self {
        Self {
            accounts,
            devices,
            agents,
        }
    }

    pub async fn find_account_by_actor(
        &self,
        query: FindAccountByActorQuery,
    ) -> ApplicationResult<Option<AccountIdentity>> {
        self.accounts.find_account_by_actor(&query.actor_id).await
    }

    pub async fn register_account(&self, command: RegisterAccountCommand) -> ApplicationResult<()> {
        self.accounts.register_account(command).await
    }

    pub async fn account(&self, actor_id: &str) -> ApplicationResult<Option<AccountProfileState>> {
        self.accounts.account(actor_id).await
    }

    pub async fn save_account(&self, account: AccountProfileState) -> ApplicationResult<()> {
        self.accounts.save_account(account).await
    }

    pub async fn delete_account(&self, actor_id: &str) -> ApplicationResult<()> {
        self.accounts.delete_account(actor_id).await
    }

    pub async fn account_localparts(
        &self,
        actor_id: &str,
    ) -> ApplicationResult<Vec<AccountLocalpartState>> {
        self.accounts.account_localparts(actor_id).await
    }

    pub async fn localpart_owner(
        &self,
        localpart: &str,
    ) -> ApplicationResult<Option<AccountLocalpartState>> {
        self.accounts.localpart_owner(localpart).await
    }

    pub async fn add_localpart(
        &self,
        actor_id: &str,
        localpart: &str,
        primary: bool,
    ) -> ApplicationResult<AccountLocalpartState> {
        self.accounts
            .add_localpart(actor_id, localpart, primary)
            .await
    }

    pub async fn set_primary_localpart(
        &self,
        actor_id: &str,
        localpart: &str,
    ) -> ApplicationResult<AccountLocalpartState> {
        self.accounts
            .set_primary_localpart(actor_id, localpart)
            .await
    }

    pub async fn remove_localpart(&self, actor_id: &str, localpart: &str) -> ApplicationResult<()> {
        self.accounts.remove_localpart(actor_id, localpart).await
    }

    pub async fn clear_localparts(&self, actor_id: &str) -> ApplicationResult<()> {
        self.accounts.clear_localparts(actor_id).await
    }

    pub async fn record_handle_release(
        &self,
        localpart: &str,
        released_at: DateTime<Utc>,
    ) -> ApplicationResult<()> {
        self.accounts
            .record_handle_release(localpart, released_at)
            .await
    }

    pub async fn save_account_lifecycle(
        &self,
        actor_id: &str,
        lifecycle: AccountLifecycleState,
    ) -> ApplicationResult<()> {
        self.accounts
            .save_account_lifecycle(actor_id, lifecycle)
            .await
    }

    pub async fn delete_account_lifecycle(&self, actor_id: &str) -> ApplicationResult<()> {
        self.accounts.delete_account_lifecycle(actor_id).await
    }

    pub async fn list_active_device_actors(
        &self,
        _query: ListActiveDeviceActorsQuery,
    ) -> ApplicationResult<Vec<String>> {
        self.devices.list_active_device_actors().await
    }

    pub async fn find_device(
        &self,
        query: FindDeviceQuery,
    ) -> ApplicationResult<Option<DeviceIdentity>> {
        self.devices
            .find_device(&query.actor_id, &query.device_id)
            .await
    }

    pub async fn save_device(&self, command: SaveDeviceCommand) -> ApplicationResult<()> {
        self.devices.save_device(command).await
    }

    pub async fn save_device_if_absent(&self, device: DeviceIdentity) -> ApplicationResult<bool> {
        self.devices.save_device_if_absent(device).await
    }

    pub async fn devices_for_actor(
        &self,
        actor_id: &str,
    ) -> ApplicationResult<Vec<DeviceIdentity>> {
        self.devices.devices_for_actor(actor_id).await
    }

    pub async fn find_agent_controller(
        &self,
        query: FindAgentControllerQuery,
    ) -> ApplicationResult<Option<AgentController>> {
        self.agents.find_agent_controller(&query.agent_id).await
    }
}

#[derive(Clone, Debug)]
pub struct DidDocumentState {
    pub did: String,
    pub did_document: Value,
    pub key_log_head: Option<String>,
    pub seq: u64,
    pub method_evidence: Value,
    pub fetched_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug)]
pub struct DidLogEvent {
    pub event_digest: String,
    pub did: String,
    pub seq: u64,
    pub operation: Value,
    pub created_at: DateTime<Utc>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DidLogCommitResult {
    Accepted,
    Duplicate,
    Conflict,
}

#[derive(Clone, Debug)]
pub enum ServiceRegistrationCommitResult {
    Created(ServiceRegistrationOutcome),
    Existing(ServiceRegistrationOutcome),
    Conflict,
}

#[async_trait]
pub trait DidDocumentPort: Send + Sync {
    async fn document(&self, did: &str) -> ApplicationResult<Option<DidDocumentState>>;
    async fn embedded_document(
        &self,
        local_id: &str,
    ) -> ApplicationResult<Option<DidDocumentState>>;
    async fn log_events(&self, did: &str) -> ApplicationResult<Vec<DidLogEvent>>;
    async fn store_document(&self, document: DidDocumentState) -> ApplicationResult<()>;
    async fn append_log_event(&self, event: DidLogEvent) -> ApplicationResult<()>;
    async fn service_registration(
        &self,
        key: &ServiceRegistrationKey,
    ) -> ApplicationResult<Option<ServiceRegistrationOutcome>>;
    async fn commit_service_registration(
        &self,
        key: ServiceRegistrationKey,
        outcome: ServiceRegistrationOutcome,
        document: DidDocumentState,
        event: DidLogEvent,
    ) -> ApplicationResult<ServiceRegistrationCommitResult>;
    async fn commit_log_operation(
        &self,
        expected_current_head: Option<String>,
        document: DidDocumentState,
        event: DidLogEvent,
    ) -> ApplicationResult<DidLogCommitResult>;
}

#[derive(Clone)]
pub struct DidApplicationService {
    documents: Arc<dyn DidDocumentPort>,
}

impl DidApplicationService {
    pub fn new(documents: Arc<dyn DidDocumentPort>) -> Self {
        Self { documents }
    }

    pub async fn document(&self, did: &str) -> ApplicationResult<Option<DidDocumentState>> {
        self.documents.document(did).await
    }

    pub async fn embedded_document(
        &self,
        local_id: &str,
    ) -> ApplicationResult<Option<DidDocumentState>> {
        self.documents.embedded_document(local_id).await
    }

    pub async fn log_events(&self, did: &str) -> ApplicationResult<Vec<DidLogEvent>> {
        self.documents.log_events(did).await
    }

    pub async fn store_document(&self, document: DidDocumentState) -> ApplicationResult<()> {
        self.documents.store_document(document).await
    }

    pub async fn append_log_event(&self, event: DidLogEvent) -> ApplicationResult<()> {
        self.documents.append_log_event(event).await
    }

    pub async fn service_registration(
        &self,
        key: &ServiceRegistrationKey,
    ) -> ApplicationResult<Option<ServiceRegistrationOutcome>> {
        self.documents.service_registration(key).await
    }

    pub async fn commit_service_registration(
        &self,
        key: ServiceRegistrationKey,
        outcome: ServiceRegistrationOutcome,
        document: DidDocumentState,
        event: DidLogEvent,
    ) -> ApplicationResult<ServiceRegistrationCommitResult> {
        self.documents
            .commit_service_registration(key, outcome, document, event)
            .await
    }

    pub async fn commit_log_operation(
        &self,
        expected_current_head: Option<String>,
        document: DidDocumentState,
        event: DidLogEvent,
    ) -> ApplicationResult<DidLogCommitResult> {
        self.documents
            .commit_log_operation(expected_current_head, document, event)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct StaticAccount;

    struct NoDevices;

    struct NoAgents;

    struct StaticDidDocuments;

    struct AcceptPairing;

    struct CurrentRecoveryPolicy;

    #[async_trait]
    impl AccountLookupPort for StaticAccount {
        async fn find_account_by_actor(
            &self,
            actor_id: &str,
        ) -> ApplicationResult<Option<AccountIdentity>> {
            Ok(
                (actor_id == "did:web:alice.example").then(|| AccountIdentity {
                    account_id: "ak:account:alice".to_owned(),
                }),
            )
        }

        async fn register_account(
            &self,
            _command: RegisterAccountCommand,
        ) -> ApplicationResult<()> {
            Ok(())
        }

        async fn account(&self, _actor_id: &str) -> ApplicationResult<Option<AccountProfileState>> {
            Ok(None)
        }

        async fn save_account(&self, _account: AccountProfileState) -> ApplicationResult<()> {
            Ok(())
        }

        async fn delete_account(&self, _actor_id: &str) -> ApplicationResult<()> {
            Ok(())
        }

        async fn account_localparts(
            &self,
            _actor_id: &str,
        ) -> ApplicationResult<Vec<AccountLocalpartState>> {
            Ok(Vec::new())
        }

        async fn localpart_owner(
            &self,
            _localpart: &str,
        ) -> ApplicationResult<Option<AccountLocalpartState>> {
            Ok(None)
        }

        async fn add_localpart(
            &self,
            _actor_id: &str,
            _localpart: &str,
            _primary: bool,
        ) -> ApplicationResult<AccountLocalpartState> {
            unreachable!()
        }

        async fn set_primary_localpart(
            &self,
            _actor_id: &str,
            _localpart: &str,
        ) -> ApplicationResult<AccountLocalpartState> {
            unreachable!()
        }

        async fn remove_localpart(
            &self,
            _actor_id: &str,
            _localpart: &str,
        ) -> ApplicationResult<()> {
            Ok(())
        }

        async fn clear_localparts(&self, _actor_id: &str) -> ApplicationResult<()> {
            Ok(())
        }

        async fn record_handle_release(
            &self,
            _localpart: &str,
            _released_at: DateTime<Utc>,
        ) -> ApplicationResult<()> {
            Ok(())
        }

        async fn save_account_lifecycle(
            &self,
            _actor_id: &str,
            _lifecycle: AccountLifecycleState,
        ) -> ApplicationResult<()> {
            Ok(())
        }

        async fn delete_account_lifecycle(&self, _actor_id: &str) -> ApplicationResult<()> {
            Ok(())
        }
    }

    #[async_trait]
    impl DeviceDirectoryPort for NoDevices {
        async fn list_active_device_actors(&self) -> ApplicationResult<Vec<String>> {
            Ok(Vec::new())
        }

        async fn find_device(
            &self,
            _actor_id: &str,
            _device_id: &str,
        ) -> ApplicationResult<Option<DeviceIdentity>> {
            Ok(None)
        }

        async fn save_device(&self, _command: SaveDeviceCommand) -> ApplicationResult<()> {
            Ok(())
        }

        async fn save_device_if_absent(&self, _device: DeviceIdentity) -> ApplicationResult<bool> {
            Ok(true)
        }

        async fn devices_for_actor(
            &self,
            _actor_id: &str,
        ) -> ApplicationResult<Vec<DeviceIdentity>> {
            Ok(Vec::new())
        }
    }

    #[async_trait]
    impl AgentDirectoryPort for NoAgents {
        async fn find_agent_controller(
            &self,
            _agent_id: &str,
        ) -> ApplicationResult<Option<AgentController>> {
            Ok(None)
        }
    }

    #[async_trait]
    impl DidDocumentPort for StaticDidDocuments {
        async fn document(&self, did: &str) -> ApplicationResult<Option<DidDocumentState>> {
            let now = Utc::now();
            Ok((did == "did:web:alice.example").then(|| DidDocumentState {
                did: did.to_owned(),
                did_document: serde_json::json!({"id": did}),
                key_log_head: None,
                seq: 1,
                method_evidence: Value::Null,
                fetched_at: now,
                expires_at: now,
                updated_at: now,
            }))
        }

        async fn embedded_document(
            &self,
            _local_id: &str,
        ) -> ApplicationResult<Option<DidDocumentState>> {
            Ok(None)
        }

        async fn log_events(&self, _did: &str) -> ApplicationResult<Vec<DidLogEvent>> {
            Ok(Vec::new())
        }

        async fn store_document(&self, _document: DidDocumentState) -> ApplicationResult<()> {
            Ok(())
        }

        async fn append_log_event(&self, _event: DidLogEvent) -> ApplicationResult<()> {
            Ok(())
        }

        async fn service_registration(
            &self,
            _key: &ServiceRegistrationKey,
        ) -> ApplicationResult<Option<ServiceRegistrationOutcome>> {
            Ok(None)
        }

        async fn commit_service_registration(
            &self,
            _key: ServiceRegistrationKey,
            _outcome: ServiceRegistrationOutcome,
            _document: DidDocumentState,
            _event: DidLogEvent,
        ) -> ApplicationResult<ServiceRegistrationCommitResult> {
            Ok(ServiceRegistrationCommitResult::Conflict)
        }

        async fn commit_log_operation(
            &self,
            _expected_current_head: Option<String>,
            _document: DidDocumentState,
            _event: DidLogEvent,
        ) -> ApplicationResult<DidLogCommitResult> {
            Ok(DidLogCommitResult::Conflict)
        }
    }

    #[async_trait]
    impl AgentPairingPort for AcceptPairing {
        async fn pairing_record(
            &self,
            _pairing_request_id: &str,
        ) -> ApplicationResult<Option<AgentPairingState>> {
            Ok(None)
        }

        async fn agent(&self, _agent_id: &str) -> ApplicationResult<Option<AgentPairingState>> {
            Ok(None)
        }

        async fn agents_for_controller(
            &self,
            _controller_id: &str,
        ) -> ApplicationResult<Vec<AgentPairingState>> {
            Ok(Vec::new())
        }

        async fn save_agent(&self, _agent: AgentPairingState) -> ApplicationResult<()> {
            Ok(())
        }

        async fn store_runtime_approval(
            &self,
            _command: &StoreAgentRuntimeApprovalCommand,
        ) -> ApplicationResult<Option<AgentPairingState>> {
            Ok(None)
        }

        async fn activate_runtime_if_current(
            &self,
            command: &ActivateAgentRuntimeCommand,
        ) -> ApplicationResult<bool> {
            Ok(command.pairing_request_id == "pairing-1")
        }

        async fn clear_approval_notification_if_current(
            &self,
            _agent_id: &str,
            _approval_request_id: &str,
        ) -> ApplicationResult<bool> {
            Ok(true)
        }
    }

    #[async_trait]
    impl RecoveryPolicyPort for CurrentRecoveryPolicy {
        async fn active_policy(
            &self,
            principal_id: &str,
        ) -> ApplicationResult<Option<RecoveryPolicyState>> {
            Ok(Some(RecoveryPolicyState {
                policy_id: "ak:policy:current".to_owned(),
                principal_id: principal_id.to_owned(),
                version: 2,
                trust_domain: "ak:trust_domain:personal".to_owned(),
                allowed_proof_kinds: vec!["principal_signing".to_owned()],
                supersedes: Some("ak:policy:genesis".to_owned()),
                expires_at: None,
                issued_at: Utc::now(),
                raw_payload: Value::Null,
                accepted_at: Utc::now(),
                verification_method: "did:web:alice.example#key-1".to_owned(),
            }))
        }

        async fn policy_history(
            &self,
            _principal_id: &str,
        ) -> ApplicationResult<Vec<RecoveryPolicyState>> {
            Ok(Vec::new())
        }

        async fn insert_policy(&self, _policy: RecoveryPolicyState) -> ApplicationResult<()> {
            panic!("a non-monotonic policy must not reach persistence")
        }
    }

    #[tokio::test]
    async fn account_lookup_returns_application_owned_result() {
        let service = IdentityApplicationService::new(
            Arc::new(StaticAccount),
            Arc::new(NoDevices),
            Arc::new(NoAgents),
        );
        let account = service
            .find_account_by_actor(FindAccountByActorQuery {
                actor_id: "did:web:alice.example".to_owned(),
            })
            .await
            .expect("lookup account")
            .expect("account exists");
        assert_eq!(account.account_id, "ak:account:alice");
    }

    #[tokio::test]
    async fn did_lookup_is_independent_from_http_and_app_state() {
        let service = DidApplicationService::new(Arc::new(StaticDidDocuments));
        let document = service
            .document("did:web:alice.example")
            .await
            .expect("lookup DID")
            .expect("DID exists");
        assert_eq!(
            document.did_document,
            serde_json::json!({"id": document.did})
        );
    }

    #[tokio::test]
    async fn pairing_activation_is_one_atomic_port_call() {
        let service = AgentPairingApplicationService::new(Arc::new(AcceptPairing));
        let command = ActivateAgentRuntimeCommand {
            agent_id: "did:web:agent.example".to_owned(),
            approval_request_id: "approval-1".to_owned(),
            runtime_key_binding_digest: "sha256:binding".to_owned(),
            pairing_request_id: "pairing-1".to_owned(),
            paired_request_digest: "sha256:request".to_owned(),
            authorized_event_ref: "ak:event:1".to_owned(),
            authorized_verification_method: "did:web:agent.example#key-1".to_owned(),
            authorized_public_key_digest: "sha256:key".to_owned(),
            authorized_at: Utc::now(),
        };
        assert!(
            service
                .activate_runtime(&command)
                .await
                .expect("activate runtime")
        );
    }

    #[tokio::test]
    async fn recovery_policy_monotonicity_is_enforced_in_application() {
        let service = RecoveryPolicyApplicationService::new(Arc::new(CurrentRecoveryPolicy));
        let result = service
            .publish_policy(PublishRecoveryPolicyCommand {
                policy: RecoveryPolicyState {
                    policy_id: "ak:policy:stale".to_owned(),
                    principal_id: "did:web:alice.example".to_owned(),
                    version: 2,
                    trust_domain: "ak:trust_domain:personal".to_owned(),
                    allowed_proof_kinds: vec!["principal_signing".to_owned()],
                    supersedes: Some("ak:policy:current".to_owned()),
                    expires_at: None,
                    issued_at: Utc::now(),
                    raw_payload: Value::Null,
                    accepted_at: Utc::now(),
                    verification_method: "did:web:alice.example#key-1".to_owned(),
                },
            })
            .await
            .expect("evaluate policy");
        assert!(matches!(
            result,
            PublishRecoveryPolicyResult::VersionNotMonotonic {
                actual: 2,
                current: 2
            }
        ));
    }
}
