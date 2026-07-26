use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use parking_lot::Mutex;
use serde_json::Value;

use crate::ServiceResult;

#[derive(Clone, Debug)]
pub struct MultisigPendingRecord {
    pub seal_id: String,
    pub realm_id: String,
    pub threshold_k: u32,
    pub threshold_n: u32,
    pub members: Vec<String>,
    pub canonical_b64: String,
    pub partials: BTreeMap<String, Value>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub claimed_by_node_id: Option<String>,
    pub claimed_until: Option<DateTime<Utc>>,
    pub claim_seq: i64,
}

#[derive(Clone, Debug)]
pub struct PolicyDocumentRecord {
    pub policy_id: String,
    pub owner: String,
    pub scope: String,
    pub subject_ref: String,
    pub policy_kind: String,
    pub payload: Value,
    pub active: bool,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug)]
pub struct OrganizationRecord {
    pub organization_id: String,
    pub organization_did: String,
    pub handle: Option<String>,
    pub display_name: String,
    pub source_refs: Vec<String>,
    pub policy_revision: String,
    pub verified: bool,
    pub members: BTreeSet<String>,
    pub member_count: usize,
    pub created_by: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug)]
pub struct OrganizationPolicyRecord {
    pub organization_id: String,
    pub policy_id: String,
    pub payload: Value,
    pub version: u64,
    pub updated_by: String,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug)]
pub struct RealmModerationPolicyRecord {
    pub realm_id: String,
    pub payload: Value,
    pub updated_by: String,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug)]
pub struct RetentionPolicyRecord {
    pub realm_id: String,
    pub ttl_seconds: i64,
    pub updated_by: String,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug)]
pub struct RetentionTombstoneRecord {
    pub event_id: String,
    pub realm_id: String,
    pub reason: String,
    pub policy_ttl_seconds: i64,
    pub expired_at: DateTime<Utc>,
    pub tombstoned_at: DateTime<Utc>,
    pub sealed: bool,
}

pub trait AdminSigningKeyPort: Send + Sync {
    fn load_admin_key(&self, admin_did: &arkret_identifiers::Did) -> Result<Vec<u8>, String>;
}

#[async_trait]
pub trait RuntimeSettingsPort: Send + Sync {
    async fn load_overrides(&self) -> ServiceResult<Vec<(String, Value)>>;
    async fn store_override(&self, key: &str, value: &Value, updated_by: &str)
    -> ServiceResult<()>;
}

#[derive(Clone, Debug)]
pub struct AppendAuditEntryCommand {
    pub entry: Value,
}

#[async_trait]
pub trait AuditLogPort: Send + Sync {
    async fn append(&self, entry: Value) -> ServiceResult<()>;
    async fn entries(&self) -> ServiceResult<Vec<Value>>;
    async fn entries_for_actor(&self, actor_id: &str) -> ServiceResult<Vec<Value>>;
}

#[async_trait]
pub trait ModerationPort: Send + Sync {
    async fn append_report(&self, report: Value) -> ServiceResult<()>;
    async fn append_action(&self, action: Value) -> ServiceResult<()>;
    async fn reports(&self) -> ServiceResult<Vec<Value>>;
    async fn upsert_queue_item(&self, item: Value) -> ServiceResult<()>;
    async fn queue_items(&self) -> ServiceResult<Vec<Value>>;
    async fn queue_item(&self, id: &str) -> ServiceResult<Option<Value>>;
    async fn append_appeal(&self, appeal: Value) -> ServiceResult<()>;
    async fn appeals(&self) -> ServiceResult<Vec<Value>>;
    async fn appeal_history(&self, appeal_id: &str) -> ServiceResult<Vec<Value>>;
}

#[async_trait]
pub trait GovernanceRecordsPort: Send + Sync {
    async fn organization(
        &self,
        organization_id: &str,
    ) -> ServiceResult<Option<OrganizationRecord>>;
    async fn store_organization(&self, record: &OrganizationRecord) -> ServiceResult<()>;
    async fn organizations(&self) -> ServiceResult<Vec<OrganizationRecord>>;
    async fn organization_policy(
        &self,
        organization_id: &str,
    ) -> ServiceResult<Option<OrganizationPolicyRecord>>;
    async fn store_organization_policy(
        &self,
        record: &OrganizationPolicyRecord,
    ) -> ServiceResult<()>;
    async fn organization_policies(&self) -> ServiceResult<Vec<OrganizationPolicyRecord>>;
    async fn link_realm_organization(
        &self,
        realm_id: &str,
        organization_id: &str,
    ) -> ServiceResult<()>;
    async fn realm_organization_links(&self) -> ServiceResult<Vec<(String, BTreeSet<String>)>>;
    async fn store_realm_moderation_policy(
        &self,
        record: &RealmModerationPolicyRecord,
    ) -> ServiceResult<()>;
    async fn realm_moderation_policies(&self) -> ServiceResult<Vec<RealmModerationPolicyRecord>>;
    async fn policy_document(&self, policy_id: &str)
    -> ServiceResult<Option<PolicyDocumentRecord>>;
    async fn store_policy_document(&self, record: PolicyDocumentRecord) -> ServiceResult<()>;
    async fn delete_policy_document(&self, policy_id: &str) -> ServiceResult<bool>;
    async fn policy_documents_for_owner(
        &self,
        owner: &str,
    ) -> ServiceResult<Vec<PolicyDocumentRecord>>;
    async fn policy_documents(&self) -> ServiceResult<Vec<PolicyDocumentRecord>>;
    async fn active_policy_documents(&self) -> ServiceResult<Vec<PolicyDocumentRecord>>;
    async fn retention_policy(
        &self,
        realm_id: &str,
    ) -> ServiceResult<Option<RetentionPolicyRecord>>;
    async fn store_retention_policy(&self, record: &RetentionPolicyRecord) -> ServiceResult<()>;
    async fn retention_tombstone(
        &self,
        event_id: &str,
    ) -> ServiceResult<Option<RetentionTombstoneRecord>>;
    async fn retention_tombstones(&self) -> ServiceResult<Vec<RetentionTombstoneRecord>>;
    async fn store_retention_tombstone(
        &self,
        record: &RetentionTombstoneRecord,
    ) -> ServiceResult<()>;
    async fn multisig_pending(&self, seal_id: &str)
    -> ServiceResult<Option<MultisigPendingRecord>>;
    async fn store_multisig_pending(&self, record: MultisigPendingRecord) -> ServiceResult<()>;
    async fn multisig_pending_for_realm(
        &self,
        realm_id: &str,
    ) -> ServiceResult<Vec<MultisigPendingRecord>>;
    async fn multisig_pending_all(&self) -> ServiceResult<Vec<MultisigPendingRecord>>;
    async fn claim_multisig_pending(
        &self,
        seal_id: &str,
        node_id: &str,
        now: chrono::DateTime<chrono::Utc>,
        claimed_until: chrono::DateTime<chrono::Utc>,
    ) -> ServiceResult<(bool, i64)>;
    async fn release_multisig_claim(&self, seal_id: &str, node_id: &str) -> ServiceResult<()>;
    async fn delete_multisig_with_fence(
        &self,
        seal_id: &str,
        node_id: &str,
        claim_seq: i64,
    ) -> ServiceResult<bool>;
    async fn renew_multisig_claim(
        &self,
        seal_id: &str,
        node_id: &str,
        claim_seq: i64,
        new_claimed_until: chrono::DateTime<chrono::Utc>,
    ) -> ServiceResult<bool>;
}

#[derive(Clone)]
pub struct GovernanceService {
    audit_log: Arc<dyn AuditLogPort>,
    moderation: Arc<dyn ModerationPort>,
    records: Arc<dyn GovernanceRecordsPort>,
    organizations: Arc<Mutex<BTreeMap<String, OrganizationRecord>>>,
    organization_policies: Arc<Mutex<BTreeMap<String, OrganizationPolicyRecord>>>,
    realm_organizations: Arc<Mutex<BTreeMap<String, BTreeSet<String>>>>,
    organization_realms: Arc<Mutex<BTreeMap<String, BTreeSet<String>>>>,
    realm_moderation_policies: Arc<Mutex<BTreeMap<String, RealmModerationPolicyRecord>>>,
    retention_tombstones: Arc<Mutex<BTreeMap<String, RetentionTombstoneRecord>>>,
    admin_signing_keys: Arc<dyn AdminSigningKeyPort>,
    runtime_settings: Arc<dyn RuntimeSettingsPort>,
}

impl GovernanceService {
    pub async fn hydrate_projections(&self) -> ServiceResult<()> {
        let retention_tombstones = self.records.retention_tombstones().await?;
        let organizations = self.records.organizations().await?;
        let organization_policies = self.records.organization_policies().await?;
        let realm_organizations = self.records.realm_organization_links().await?;
        let realm_moderation_policies = self.records.realm_moderation_policies().await?;

        self.replace_retention_tombstones(retention_tombstones);
        self.replace_organization_projection(
            organizations,
            organization_policies,
            realm_organizations,
            realm_moderation_policies,
        );
        Ok(())
    }

    pub async fn organization(
        &self,
        organization_id: &str,
    ) -> ServiceResult<Option<OrganizationRecord>> {
        self.records.organization(organization_id).await
    }

    pub async fn store_organization(&self, record: &OrganizationRecord) -> ServiceResult<()> {
        self.records.store_organization(record).await?;
        self.organizations
            .lock()
            .insert(record.organization_id.clone(), record.clone());
        Ok(())
    }

    pub async fn organizations(&self) -> ServiceResult<Vec<OrganizationRecord>> {
        self.records.organizations().await
    }

    pub async fn organization_policy(
        &self,
        organization_id: &str,
    ) -> ServiceResult<Option<OrganizationPolicyRecord>> {
        self.records.organization_policy(organization_id).await
    }

    pub async fn store_organization_policy(
        &self,
        record: &OrganizationPolicyRecord,
    ) -> ServiceResult<()> {
        self.records.store_organization_policy(record).await?;
        self.organization_policies
            .lock()
            .insert(record.organization_id.clone(), record.clone());
        Ok(())
    }

    pub async fn organization_policies(&self) -> ServiceResult<Vec<OrganizationPolicyRecord>> {
        self.records.organization_policies().await
    }

    pub async fn link_realm_organization(
        &self,
        realm_id: &str,
        organization_id: &str,
    ) -> ServiceResult<()> {
        self.records
            .link_realm_organization(realm_id, organization_id)
            .await?;
        self.realm_organizations
            .lock()
            .entry(realm_id.to_owned())
            .or_default()
            .insert(organization_id.to_owned());
        self.organization_realms
            .lock()
            .entry(organization_id.to_owned())
            .or_default()
            .insert(realm_id.to_owned());
        Ok(())
    }

    pub async fn realm_organization_links(&self) -> ServiceResult<Vec<(String, BTreeSet<String>)>> {
        self.records.realm_organization_links().await
    }

    pub async fn store_realm_moderation_policy(
        &self,
        record: &RealmModerationPolicyRecord,
    ) -> ServiceResult<()> {
        self.records.store_realm_moderation_policy(record).await?;
        self.realm_moderation_policies
            .lock()
            .insert(record.realm_id.clone(), record.clone());
        Ok(())
    }

    pub async fn realm_moderation_policies(
        &self,
    ) -> ServiceResult<Vec<RealmModerationPolicyRecord>> {
        self.records.realm_moderation_policies().await
    }

    pub fn new(
        audit_log: Arc<dyn AuditLogPort>,
        moderation: Arc<dyn ModerationPort>,
        records: Arc<dyn GovernanceRecordsPort>,
        admin_signing_keys: Arc<dyn AdminSigningKeyPort>,
        runtime_settings: Arc<dyn RuntimeSettingsPort>,
    ) -> Self {
        Self {
            audit_log,
            moderation,
            records,
            organizations: Arc::new(Mutex::new(BTreeMap::new())),
            organization_policies: Arc::new(Mutex::new(BTreeMap::new())),
            realm_organizations: Arc::new(Mutex::new(BTreeMap::new())),
            organization_realms: Arc::new(Mutex::new(BTreeMap::new())),
            realm_moderation_policies: Arc::new(Mutex::new(BTreeMap::new())),
            retention_tombstones: Arc::new(Mutex::new(BTreeMap::new())),
            admin_signing_keys,
            runtime_settings,
        }
    }

    pub fn admin_signing_key(
        &self,
        admin_did: &arkret_identifiers::Did,
    ) -> Result<Vec<u8>, String> {
        self.admin_signing_keys.load_admin_key(admin_did)
    }

    pub async fn runtime_setting_overrides(&self) -> ServiceResult<Vec<(String, Value)>> {
        self.runtime_settings.load_overrides().await
    }

    pub async fn store_runtime_setting(
        &self,
        key: &str,
        value: &Value,
        updated_by: &str,
    ) -> ServiceResult<()> {
        self.runtime_settings
            .store_override(key, value, updated_by)
            .await
    }

    pub fn replace_organization_projection(
        &self,
        organizations: impl IntoIterator<Item = OrganizationRecord>,
        policies: impl IntoIterator<Item = OrganizationPolicyRecord>,
        links: impl IntoIterator<Item = (String, BTreeSet<String>)>,
        realm_policies: impl IntoIterator<Item = RealmModerationPolicyRecord>,
    ) {
        *self.organizations.lock() = organizations
            .into_iter()
            .map(|record| (record.organization_id.clone(), record))
            .collect();
        *self.organization_policies.lock() = policies
            .into_iter()
            .map(|record| (record.organization_id.clone(), record))
            .collect();
        let realm_organizations: BTreeMap<_, _> = links.into_iter().collect();
        let mut organization_realms = BTreeMap::<String, BTreeSet<String>>::new();
        for (realm_id, organization_ids) in &realm_organizations {
            for organization_id in organization_ids {
                organization_realms
                    .entry(organization_id.clone())
                    .or_default()
                    .insert(realm_id.clone());
            }
        }
        *self.realm_organizations.lock() = realm_organizations;
        *self.organization_realms.lock() = organization_realms;
        *self.realm_moderation_policies.lock() = realm_policies
            .into_iter()
            .map(|record| (record.realm_id.clone(), record))
            .collect();
    }

    pub fn cached_organization(&self, organization_id: &str) -> Option<OrganizationRecord> {
        self.organizations.lock().get(organization_id).cloned()
    }

    pub fn cached_organizations(&self) -> Vec<OrganizationRecord> {
        self.organizations.lock().values().cloned().collect()
    }

    pub fn cached_organization_policy(
        &self,
        organization_id: &str,
    ) -> Option<OrganizationPolicyRecord> {
        self.organization_policies
            .lock()
            .get(organization_id)
            .cloned()
    }

    pub fn cached_organization_policies(
        &self,
        organization_ids: &[String],
    ) -> Vec<(String, OrganizationPolicyRecord)> {
        let policies = self.organization_policies.lock();
        organization_ids
            .iter()
            .filter_map(|id| policies.get(id).cloned().map(|policy| (id.clone(), policy)))
            .collect()
    }

    pub fn cached_organization_realms(&self, organization_id: &str) -> Vec<String> {
        self.organization_realms
            .lock()
            .get(organization_id)
            .map(|realms| realms.iter().cloned().collect())
            .unwrap_or_default()
    }

    pub fn cached_realm_organizations(&self, realm_id: &str) -> Vec<String> {
        self.realm_organizations
            .lock()
            .get(realm_id)
            .map(|organizations| organizations.iter().cloned().collect())
            .unwrap_or_default()
    }

    pub fn cached_realm_moderation_policy(
        &self,
        realm_id: &str,
    ) -> Option<RealmModerationPolicyRecord> {
        self.realm_moderation_policies.lock().get(realm_id).cloned()
    }

    pub fn replace_retention_tombstones(
        &self,
        tombstones: impl IntoIterator<Item = RetentionTombstoneRecord>,
    ) {
        *self.retention_tombstones.lock() = tombstones
            .into_iter()
            .map(|record| (record.event_id.clone(), record))
            .collect();
    }

    pub fn cached_retention_tombstone(&self, event_id: &str) -> Option<RetentionTombstoneRecord> {
        self.retention_tombstones.lock().get(event_id).cloned()
    }

    pub async fn append_audit_entry(&self, command: AppendAuditEntryCommand) -> ServiceResult<()> {
        self.audit_log.append(command.entry).await
    }

    pub async fn audit_entries_for_actor(&self, actor_id: &str) -> ServiceResult<Vec<Value>> {
        self.audit_log.entries_for_actor(actor_id).await
    }

    pub async fn audit_entries(&self) -> ServiceResult<Vec<Value>> {
        self.audit_log.entries().await
    }

    pub async fn append_moderation_report(&self, report: Value) -> ServiceResult<()> {
        self.moderation.append_report(report).await
    }
    pub async fn append_moderation_action(&self, action: Value) -> ServiceResult<()> {
        self.moderation.append_action(action).await
    }
    pub async fn moderation_reports(&self) -> ServiceResult<Vec<Value>> {
        self.moderation.reports().await
    }
    pub async fn upsert_moderation_queue_item(&self, item: Value) -> ServiceResult<()> {
        self.moderation.upsert_queue_item(item).await
    }
    pub async fn moderation_queue_items(&self) -> ServiceResult<Vec<Value>> {
        self.moderation.queue_items().await
    }
    pub async fn moderation_queue_item(&self, id: &str) -> ServiceResult<Option<Value>> {
        self.moderation.queue_item(id).await
    }
    pub async fn append_moderation_appeal(&self, appeal: Value) -> ServiceResult<()> {
        self.moderation.append_appeal(appeal).await
    }
    pub async fn moderation_appeals(&self) -> ServiceResult<Vec<Value>> {
        self.moderation.appeals().await
    }
    pub async fn moderation_appeal_history(&self, appeal_id: &str) -> ServiceResult<Vec<Value>> {
        self.moderation.appeal_history(appeal_id).await
    }

    pub async fn retention_policy(
        &self,
        realm_id: &str,
    ) -> ServiceResult<Option<RetentionPolicyRecord>> {
        self.records.retention_policy(realm_id).await
    }

    pub async fn policy_document(
        &self,
        policy_id: &str,
    ) -> ServiceResult<Option<PolicyDocumentRecord>> {
        self.records.policy_document(policy_id).await
    }

    pub async fn store_policy_document(&self, record: PolicyDocumentRecord) -> ServiceResult<()> {
        self.records.store_policy_document(record).await
    }

    pub async fn delete_policy_document(&self, policy_id: &str) -> ServiceResult<bool> {
        self.records.delete_policy_document(policy_id).await
    }

    pub async fn policy_documents_for_owner(
        &self,
        owner: &str,
    ) -> ServiceResult<Vec<PolicyDocumentRecord>> {
        self.records.policy_documents_for_owner(owner).await
    }

    pub async fn policy_documents(&self) -> ServiceResult<Vec<PolicyDocumentRecord>> {
        self.records.policy_documents().await
    }

    pub async fn active_policy_documents(&self) -> ServiceResult<Vec<PolicyDocumentRecord>> {
        self.records.active_policy_documents().await
    }

    pub async fn store_retention_policy(
        &self,
        record: &RetentionPolicyRecord,
    ) -> ServiceResult<()> {
        self.records.store_retention_policy(record).await
    }

    pub async fn retention_tombstone(
        &self,
        event_id: &str,
    ) -> ServiceResult<Option<RetentionTombstoneRecord>> {
        self.records.retention_tombstone(event_id).await
    }

    pub async fn store_retention_tombstone(
        &self,
        record: &RetentionTombstoneRecord,
    ) -> ServiceResult<()> {
        self.records.store_retention_tombstone(record).await?;
        self.retention_tombstones
            .lock()
            .insert(record.event_id.clone(), record.clone());
        Ok(())
    }

    pub async fn multisig_pending(
        &self,
        seal_id: &str,
    ) -> ServiceResult<Option<MultisigPendingRecord>> {
        self.records.multisig_pending(seal_id).await
    }

    pub async fn store_multisig_pending(&self, record: MultisigPendingRecord) -> ServiceResult<()> {
        self.records.store_multisig_pending(record).await
    }

    pub async fn multisig_pending_for_realm(
        &self,
        realm_id: &str,
    ) -> ServiceResult<Vec<MultisigPendingRecord>> {
        self.records.multisig_pending_for_realm(realm_id).await
    }

    pub async fn multisig_pending_all(&self) -> ServiceResult<Vec<MultisigPendingRecord>> {
        self.records.multisig_pending_all().await
    }

    pub async fn claim_multisig_pending(
        &self,
        seal_id: &str,
        node_id: &str,
        now: chrono::DateTime<chrono::Utc>,
        claimed_until: chrono::DateTime<chrono::Utc>,
    ) -> ServiceResult<(bool, i64)> {
        self.records
            .claim_multisig_pending(seal_id, node_id, now, claimed_until)
            .await
    }

    pub async fn release_multisig_claim(&self, seal_id: &str, node_id: &str) -> ServiceResult<()> {
        self.records.release_multisig_claim(seal_id, node_id).await
    }

    pub async fn delete_multisig_with_fence(
        &self,
        seal_id: &str,
        node_id: &str,
        claim_seq: i64,
    ) -> ServiceResult<bool> {
        self.records
            .delete_multisig_with_fence(seal_id, node_id, claim_seq)
            .await
    }

    pub async fn renew_multisig_claim(
        &self,
        seal_id: &str,
        node_id: &str,
        claim_seq: i64,
        new_claimed_until: chrono::DateTime<chrono::Utc>,
    ) -> ServiceResult<bool> {
        self.records
            .renew_multisig_claim(seal_id, node_id, claim_seq, new_claimed_until)
            .await
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    #[derive(Default)]
    struct RecordingAuditLog(Mutex<Vec<Value>>);
    struct NoModeration;

    struct NoAdminSigningKeys;

    struct NoRuntimeSettings;

    impl AdminSigningKeyPort for NoAdminSigningKeys {
        fn load_admin_key(&self, _admin_did: &arkret_identifiers::Did) -> Result<Vec<u8>, String> {
            Err("not configured".to_owned())
        }
    }

    #[async_trait]
    impl RuntimeSettingsPort for NoRuntimeSettings {
        async fn load_overrides(&self) -> ServiceResult<Vec<(String, Value)>> {
            Ok(Vec::new())
        }

        async fn store_override(
            &self,
            _key: &str,
            _value: &Value,
            _updated_by: &str,
        ) -> ServiceResult<()> {
            Ok(())
        }
    }
    struct NoGovernanceRecords;

    #[async_trait]
    impl GovernanceRecordsPort for NoGovernanceRecords {
        async fn organization(
            &self,
            _organization_id: &str,
        ) -> ServiceResult<Option<OrganizationRecord>> {
            Ok(None)
        }
        async fn store_organization(&self, _record: &OrganizationRecord) -> ServiceResult<()> {
            Ok(())
        }
        async fn organizations(&self) -> ServiceResult<Vec<OrganizationRecord>> {
            Ok(Vec::new())
        }
        async fn organization_policy(
            &self,
            _organization_id: &str,
        ) -> ServiceResult<Option<OrganizationPolicyRecord>> {
            Ok(None)
        }
        async fn store_organization_policy(
            &self,
            _record: &OrganizationPolicyRecord,
        ) -> ServiceResult<()> {
            Ok(())
        }
        async fn organization_policies(&self) -> ServiceResult<Vec<OrganizationPolicyRecord>> {
            Ok(Vec::new())
        }
        async fn link_realm_organization(
            &self,
            _realm_id: &str,
            _organization_id: &str,
        ) -> ServiceResult<()> {
            Ok(())
        }
        async fn realm_organization_links(&self) -> ServiceResult<Vec<(String, BTreeSet<String>)>> {
            Ok(Vec::new())
        }
        async fn store_realm_moderation_policy(
            &self,
            _record: &RealmModerationPolicyRecord,
        ) -> ServiceResult<()> {
            Ok(())
        }
        async fn realm_moderation_policies(
            &self,
        ) -> ServiceResult<Vec<RealmModerationPolicyRecord>> {
            Ok(Vec::new())
        }
        async fn policy_document(
            &self,
            _policy_id: &str,
        ) -> ServiceResult<Option<PolicyDocumentRecord>> {
            Ok(None)
        }
        async fn store_policy_document(&self, _record: PolicyDocumentRecord) -> ServiceResult<()> {
            Ok(())
        }
        async fn delete_policy_document(&self, _policy_id: &str) -> ServiceResult<bool> {
            Ok(false)
        }
        async fn policy_documents_for_owner(
            &self,
            _owner: &str,
        ) -> ServiceResult<Vec<PolicyDocumentRecord>> {
            Ok(Vec::new())
        }
        async fn policy_documents(&self) -> ServiceResult<Vec<PolicyDocumentRecord>> {
            Ok(Vec::new())
        }
        async fn active_policy_documents(&self) -> ServiceResult<Vec<PolicyDocumentRecord>> {
            Ok(Vec::new())
        }
        async fn retention_policy(
            &self,
            _realm_id: &str,
        ) -> ServiceResult<Option<RetentionPolicyRecord>> {
            Ok(None)
        }
        async fn store_retention_policy(
            &self,
            _record: &RetentionPolicyRecord,
        ) -> ServiceResult<()> {
            Ok(())
        }
        async fn retention_tombstone(
            &self,
            _event_id: &str,
        ) -> ServiceResult<Option<RetentionTombstoneRecord>> {
            Ok(None)
        }
        async fn retention_tombstones(&self) -> ServiceResult<Vec<RetentionTombstoneRecord>> {
            Ok(Vec::new())
        }
        async fn store_retention_tombstone(
            &self,
            _record: &RetentionTombstoneRecord,
        ) -> ServiceResult<()> {
            Ok(())
        }
        async fn multisig_pending(
            &self,
            _seal_id: &str,
        ) -> ServiceResult<Option<MultisigPendingRecord>> {
            Ok(None)
        }
        async fn store_multisig_pending(
            &self,
            _record: MultisigPendingRecord,
        ) -> ServiceResult<()> {
            Ok(())
        }
        async fn multisig_pending_for_realm(
            &self,
            _realm_id: &str,
        ) -> ServiceResult<Vec<MultisigPendingRecord>> {
            Ok(Vec::new())
        }
        async fn multisig_pending_all(&self) -> ServiceResult<Vec<MultisigPendingRecord>> {
            Ok(Vec::new())
        }
        async fn claim_multisig_pending(
            &self,
            _seal_id: &str,
            _node_id: &str,
            _now: chrono::DateTime<chrono::Utc>,
            _claimed_until: chrono::DateTime<chrono::Utc>,
        ) -> ServiceResult<(bool, i64)> {
            Ok((false, 0))
        }
        async fn release_multisig_claim(
            &self,
            _seal_id: &str,
            _node_id: &str,
        ) -> ServiceResult<()> {
            Ok(())
        }
        async fn delete_multisig_with_fence(
            &self,
            _seal_id: &str,
            _node_id: &str,
            _claim_seq: i64,
        ) -> ServiceResult<bool> {
            Ok(false)
        }
        async fn renew_multisig_claim(
            &self,
            _seal_id: &str,
            _node_id: &str,
            _claim_seq: i64,
            _new_claimed_until: chrono::DateTime<chrono::Utc>,
        ) -> ServiceResult<bool> {
            Ok(false)
        }
    }

    #[async_trait]
    impl ModerationPort for NoModeration {
        async fn append_report(&self, _report: Value) -> ServiceResult<()> {
            Ok(())
        }
        async fn append_action(&self, _action: Value) -> ServiceResult<()> {
            Ok(())
        }
        async fn reports(&self) -> ServiceResult<Vec<Value>> {
            Ok(Vec::new())
        }
        async fn upsert_queue_item(&self, _item: Value) -> ServiceResult<()> {
            Ok(())
        }
        async fn queue_items(&self) -> ServiceResult<Vec<Value>> {
            Ok(Vec::new())
        }
        async fn queue_item(&self, _id: &str) -> ServiceResult<Option<Value>> {
            Ok(None)
        }
        async fn append_appeal(&self, _appeal: Value) -> ServiceResult<()> {
            Ok(())
        }
        async fn appeals(&self) -> ServiceResult<Vec<Value>> {
            Ok(Vec::new())
        }
        async fn appeal_history(&self, _appeal_id: &str) -> ServiceResult<Vec<Value>> {
            Ok(Vec::new())
        }
    }

    #[async_trait]
    impl AuditLogPort for RecordingAuditLog {
        async fn append(&self, entry: Value) -> ServiceResult<()> {
            self.0.lock().expect("audit lock").push(entry);
            Ok(())
        }

        async fn entries(&self) -> ServiceResult<Vec<Value>> {
            Ok(self.0.lock().expect("audit lock").clone())
        }

        async fn entries_for_actor(&self, _actor_id: &str) -> ServiceResult<Vec<Value>> {
            Ok(self.0.lock().expect("audit lock").clone())
        }
    }

    #[tokio::test]
    async fn audit_append_uses_only_the_audit_port() {
        let port = Arc::new(RecordingAuditLog::default());
        let service = GovernanceService::new(
            port.clone(),
            Arc::new(NoModeration),
            Arc::new(NoGovernanceRecords),
            Arc::new(NoAdminSigningKeys),
            Arc::new(NoRuntimeSettings),
        );
        service
            .append_audit_entry(AppendAuditEntryCommand {
                entry: serde_json::json!({"audit_id": "ak:audit:test"}),
            })
            .await
            .expect("append audit entry");
        assert_eq!(port.0.lock().expect("audit lock").len(), 1);
        assert_eq!(
            service
                .audit_entries()
                .await
                .expect("list audit entries")
                .len(),
            1
        );
    }
}
