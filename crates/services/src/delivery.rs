use std::collections::BTreeMap;
use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use chrono::{DateTime, Utc};
use futures_util::stream::BoxStream;
use serde_json::Value;

use crate::ServiceResult;

#[async_trait]
pub trait ObjectStoragePort: Send + Sync {
    fn backend_name(&self) -> String;
    fn object_key_for_sha256(&self, sha256: &str) -> String;
    async fn put(&self, key: &str, bytes: Vec<u8>) -> Result<(), String>;
    async fn put_file(&self, key: &str, file_path: &std::path::Path) -> Result<(), String>;
    async fn get(&self, key: &str) -> Result<Vec<u8>, String>;
    async fn get_range_stream(
        &self,
        key: &str,
        range: std::ops::Range<u64>,
    ) -> Result<BoxStream<'static, Result<Bytes, String>>, String>;
    async fn delete(&self, key: &str) -> Result<(), String>;
}

#[derive(Clone, Debug)]
pub struct StoreNotificationCommand {
    pub record: Value,
}

#[derive(Clone, Debug)]
pub struct StoreAccountNotificationDeltaCommand {
    pub record: Value,
}

#[derive(Clone, Debug)]
pub struct ListAccountNotificationDeltasQuery {
    pub controller_account_id: String,
    pub recipient_service_id: String,
    pub after_position: Option<i64>,
}

#[derive(Clone, Debug)]
pub struct ListRecipientNotificationsQuery {
    pub recipient_id: String,
}

#[async_trait]
pub trait NotificationWritePort: Send + Sync {
    async fn store_notification(&self, record: Value) -> ServiceResult<()>;
    async fn store_account_delta(&self, record: Value) -> ServiceResult<()>;
    async fn list_for_account(
        &self,
        controller_account_id: &str,
        recipient_service_id: &str,
        after_position: Option<i64>,
    ) -> ServiceResult<Vec<Value>>;
    async fn list_for_recipient(&self, recipient_id: &str) -> ServiceResult<Vec<Value>>;
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DeviceDeliveryPurgeResult {
    pub to_device_messages_dropped: usize,
    pub push_registrations_removed: usize,
}

#[async_trait]
pub trait DeviceDeliveryPort: Send + Sync {
    async fn purge_device_delivery(
        &self,
        actor_id: &str,
        device_id: &str,
    ) -> ServiceResult<DeviceDeliveryPurgeResult>;
    async fn purge_stale_cross_signing_messages(
        &self,
        actor_id: &str,
        new_generation: u64,
    ) -> ServiceResult<usize>;
    async fn register_push_device(&self, registration: Value) -> ServiceResult<()>;
    async fn unregister_push_device(
        &self,
        actor_id: &str,
        device_id: &str,
        push_key: Option<&str>,
        app_id: Option<&str>,
    ) -> ServiceResult<usize>;
    async fn push_devices(&self) -> ServiceResult<Vec<Value>>;
}

#[derive(Clone, Debug)]
pub struct DeviceMessageState {
    pub idempotency_key: String,
    pub sender: String,
    pub recipient: String,
    pub device_id: String,
    pub position: i64,
    pub content: Value,
    pub created_at: DateTime<Utc>,
}

#[derive(Clone, Debug)]
pub struct DeviceMessageIntentRecord {
    pub message_key: String,
    pub intent_digest: String,
}

#[derive(Clone, Debug)]
pub struct DeviceMessageBatchItemRecord {
    pub message_key: String,
    pub intent_digest: String,
    pub idempotency_expires_at: DateTime<Utc>,
    pub message: Option<DeviceMessageState>,
}

#[derive(Clone, Debug)]
pub struct DeviceMessageBatchRecord {
    pub request_key: String,
    pub request_digest: String,
    pub idempotency_expires_at: DateTime<Utc>,
    pub items: Vec<DeviceMessageBatchItemRecord>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum DeviceMessageBatchInspection {
    Fresh {
        existing_message_outcomes: BTreeMap<String, bool>,
    },
    Duplicate(BTreeMap<String, bool>),
    RequestConflict,
    MessageConflict {
        message_key: String,
    },
}

#[derive(Clone, Debug, PartialEq)]
pub enum DeviceMessageBatchCommitOutcome {
    Stored(BTreeMap<String, bool>),
    Duplicate(BTreeMap<String, bool>),
    RequestConflict,
    MessageConflict { message_key: String },
}

#[derive(Clone, Debug)]
pub struct PresenceState {
    pub actor: String,
    pub device_id: String,
    pub status: String,
    pub status_message: Option<String>,
    pub last_active_at: Option<String>,
    pub expires_at: Option<DateTime<Utc>>,
    pub updated_at: DateTime<Utc>,
    pub envelope: arkret_models_collaboration::events_payloads::ephemeral::EphemeralEnvelope,
}

#[derive(Clone, Debug)]
pub struct TypingState {
    pub actor: String,
    pub realm_id: String,
    pub scope_id: Option<String>,
    pub position: i64,
    pub expires_at: DateTime<Utc>,
    pub envelope: arkret_models_collaboration::events_payloads::ephemeral::EphemeralEnvelope,
}

#[derive(Clone, Debug)]
pub struct CallSignalState {
    pub realm_id: String,
    pub sender_actor: String,
    pub sender_device: String,
    pub call_id: String,
    pub expires_at: DateTime<Utc>,
    pub envelope: arkret_models_collaboration::events_payloads::ephemeral::EphemeralEnvelope,
    pub position: u64,
}

#[derive(Clone, Debug)]
pub struct ReadReceiptState {
    pub realm_id: String,
    pub actor_id: String,
    pub sender_device: Option<String>,
    pub event_id: String,
    pub read_scope: Value,
    pub target_actor: Option<String>,
    pub visibility: String,
    pub receipt: Value,
    pub envelope: arkret_models_collaboration::events_payloads::ephemeral::EphemeralEnvelope,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub position: u64,
}

#[derive(Clone, Debug)]
pub struct BlobState {
    pub sha256: String,
    pub size_bytes: i64,
    pub storage_backend: String,
    pub storage_key: String,
    pub media_type: String,
    pub filename: Option<String>,
    pub realm_id: Option<String>,
    pub encryption: Option<Value>,
    pub legal_hold: bool,
    pub redacted: bool,
    pub visibility: arkret_models_collaboration::objects::blob::BlobVisibility,
    pub uploaded_by: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Clone, Debug)]
pub struct OutboundPushBridgeCacheState {
    pub push_gateway_url: String,
    pub service_base_url: String,
    pub bridge_describe_url: String,
    pub fetch_state: String,
    pub cache_state: String,
    pub contract_digest: String,
    pub fetched_at: DateTime<Utc>,
    pub remote_contract: Value,
    pub trust_level: String,
    pub freshness_at: DateTime<Utc>,
    pub etag: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PushContractDrift {
    Match,
    Stale,
    DigestMismatch,
    Unknown,
}

impl PushContractDrift {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Match => "match",
            Self::Stale => "stale",
            Self::DigestMismatch => "digest_mismatch",
            Self::Unknown => "unknown",
        }
    }
}

#[async_trait]
pub trait BlobPort: Send + Sync {
    async fn blob(&self, blob_ref: &str) -> ServiceResult<Option<BlobState>>;
    async fn store_blob(&self, blob_ref: &str, blob: BlobState) -> ServiceResult<()>;
    async fn blobs(&self) -> ServiceResult<Vec<BlobState>>;
}

#[async_trait]
pub trait PushBridgeCachePort: Send + Sync {
    async fn entry(
        &self,
        bridge_describe_url: &str,
    ) -> ServiceResult<Option<OutboundPushBridgeCacheState>>;
    async fn store_entry(
        &self,
        bridge_describe_url: &str,
        record: OutboundPushBridgeCacheState,
    ) -> ServiceResult<()>;
    async fn delete_entry(&self, bridge_describe_url: &str) -> ServiceResult<bool>;
    async fn clear(&self) -> ServiceResult<usize>;
    async fn entries(&self) -> ServiceResult<Vec<OutboundPushBridgeCacheState>>;
    async fn entry_count(&self) -> ServiceResult<usize>;
    async fn current_contract(
        &self,
        bridge_describe_url: &str,
    ) -> ServiceResult<Option<OutboundPushBridgeCacheState>>;
    async fn verify_contract_freshness(
        &self,
        bridge_describe_url: &str,
        observed_digest: &str,
        max_age: chrono::Duration,
    ) -> ServiceResult<PushContractDrift>;
}

#[async_trait]
pub trait EphemeralDeliveryPort: Send + Sync {
    async fn store_presence(&self, presence: PresenceState) -> ServiceResult<()>;
    async fn presence_for_actor(&self, actor_id: &str) -> ServiceResult<Vec<PresenceState>>;
    async fn delete_presence(&self, actor_id: &str) -> ServiceResult<()>;
    async fn store_typing(&self, typing: TypingState) -> ServiceResult<()>;
    async fn remove_typing(&self, actor_id: &str, realm_id: &str) -> ServiceResult<()>;
    async fn typing_for_realm(&self, realm_id: &str) -> ServiceResult<Vec<TypingState>>;
    async fn prune_expired_typing(&self) -> ServiceResult<usize>;
    async fn store_call_signal(&self, signal: CallSignalState) -> ServiceResult<()>;
    async fn call_signals_for_realm(
        &self,
        realm_id: &str,
    ) -> ServiceResult<Vec<CallSignalState>>;
    async fn call_signal_watermark(
        &self,
        actor_id: &str,
        device_id: &str,
        realm_id: &str,
    ) -> ServiceResult<u64>;
    async fn advance_call_signal_watermark(
        &self,
        actor_id: &str,
        device_id: &str,
        realm_id: &str,
        position: u64,
    ) -> ServiceResult<()>;
    async fn store_read_receipt(&self, receipt: ReadReceiptState) -> ServiceResult<()>;
    async fn read_receipts_for_realm(
        &self,
        realm_id: &str,
    ) -> ServiceResult<Vec<ReadReceiptState>>;
    async fn read_receipts_for_event(
        &self,
        event_id: &str,
    ) -> ServiceResult<Vec<ReadReceiptState>>;
    async fn read_receipt_watermark(
        &self,
        actor_id: &str,
        device_id: &str,
        realm_id: &str,
    ) -> ServiceResult<u64>;
    async fn advance_read_receipt_watermark(
        &self,
        actor_id: &str,
        device_id: &str,
        realm_id: &str,
        position: u64,
    ) -> ServiceResult<()>;
}

#[async_trait]
pub trait DeviceMessagePort: Send + Sync {
    async fn append(&self, message: DeviceMessageState) -> ServiceResult<()>;
    async fn inspect_batch(
        &self,
        request_key: &str,
        request_digest: &str,
        items: &[DeviceMessageIntentRecord],
    ) -> ServiceResult<DeviceMessageBatchInspection>;
    async fn commit_batch(
        &self,
        batch: DeviceMessageBatchRecord,
    ) -> ServiceResult<DeviceMessageBatchCommitOutcome>;
    async fn issue_ack_token(
        &self,
        recipient: &str,
        device_id: &str,
        queue_position: i64,
    ) -> ServiceResult<Option<String>>;
    async fn acknowledge(
        &self,
        recipient: &str,
        device_id: &str,
        ack_token: &str,
    ) -> ServiceResult<Option<usize>>;
    async fn messages_after(
        &self,
        recipient: &str,
        device_id: &str,
        queue_position: i64,
    ) -> ServiceResult<Vec<DeviceMessageState>>;
    async fn prune(&self, per_device_capacity: usize, now: DateTime<Utc>) -> ServiceResult<()>;
    async fn lost_watermark(
        &self,
        recipient: &str,
        device_id: &str,
    ) -> ServiceResult<Option<i64>>;
}

#[derive(Clone)]
pub struct DeliveryService {
    notifications: Arc<dyn NotificationWritePort>,
    device_delivery: Arc<dyn DeviceDeliveryPort>,
    device_messages: Arc<dyn DeviceMessagePort>,
    ephemeral: Arc<dyn EphemeralDeliveryPort>,
    blobs: Arc<dyn BlobPort>,
    push_bridge_cache: Arc<dyn PushBridgeCachePort>,
    object_storage: Arc<dyn ObjectStoragePort>,
    push_target_hmac_key: [u8; 32],
}

pub struct DeliveryServiceRuntime {
    pub notifications: Arc<dyn NotificationWritePort>,
    pub device_delivery: Arc<dyn DeviceDeliveryPort>,
    pub device_messages: Arc<dyn DeviceMessagePort>,
    pub ephemeral: Arc<dyn EphemeralDeliveryPort>,
    pub blobs: Arc<dyn BlobPort>,
    pub push_bridge_cache: Arc<dyn PushBridgeCachePort>,
    pub object_storage: Arc<dyn ObjectStoragePort>,
    pub push_target_hmac_key: [u8; 32],
}

impl DeliveryService {
    pub fn new(runtime: DeliveryServiceRuntime) -> Self {
        let DeliveryServiceRuntime {
            notifications,
            device_delivery,
            device_messages,
            ephemeral,
            blobs,
            push_bridge_cache,
            object_storage,
            push_target_hmac_key,
        } = runtime;
        Self {
            notifications,
            device_delivery,
            device_messages,
            ephemeral,
            blobs,
            push_bridge_cache,
            object_storage,
            push_target_hmac_key,
        }
    }

    pub fn object_storage_backend_name(&self) -> String {
        self.object_storage.backend_name()
    }

    pub fn object_key_for_sha256(&self, sha256: &str) -> String {
        self.object_storage.object_key_for_sha256(sha256)
    }

    pub async fn put_object(&self, key: &str, bytes: Vec<u8>) -> Result<(), String> {
        self.object_storage.put(key, bytes).await
    }

    pub async fn put_object_file(
        &self,
        key: &str,
        file_path: &std::path::Path,
    ) -> Result<(), String> {
        self.object_storage.put_file(key, file_path).await
    }

    pub async fn get_object(&self, key: &str) -> Result<Vec<u8>, String> {
        self.object_storage.get(key).await
    }

    pub async fn get_object_range_stream(
        &self,
        key: &str,
        range: std::ops::Range<u64>,
    ) -> Result<BoxStream<'static, Result<Bytes, String>>, String> {
        self.object_storage.get_range_stream(key, range).await
    }

    pub async fn delete_object(&self, key: &str) -> Result<(), String> {
        self.object_storage.delete(key).await
    }

    pub fn push_target_hmac_key(&self) -> &[u8; 32] {
        &self.push_target_hmac_key
    }

    pub async fn store_notification(
        &self,
        command: StoreNotificationCommand,
    ) -> ServiceResult<()> {
        self.notifications.store_notification(command.record).await
    }

    pub async fn store_account_delta(
        &self,
        command: StoreAccountNotificationDeltaCommand,
    ) -> ServiceResult<()> {
        self.notifications.store_account_delta(command.record).await
    }

    pub async fn list_account_deltas(
        &self,
        query: ListAccountNotificationDeltasQuery,
    ) -> ServiceResult<Vec<Value>> {
        self.notifications
            .list_for_account(
                &query.controller_account_id,
                &query.recipient_service_id,
                query.after_position,
            )
            .await
    }

    pub async fn list_recipient_notifications(
        &self,
        query: ListRecipientNotificationsQuery,
    ) -> ServiceResult<Vec<Value>> {
        self.notifications
            .list_for_recipient(&query.recipient_id)
            .await
    }

    pub async fn purge_device_delivery(
        &self,
        actor_id: &str,
        device_id: &str,
    ) -> ServiceResult<DeviceDeliveryPurgeResult> {
        self.device_delivery
            .purge_device_delivery(actor_id, device_id)
            .await
    }

    pub async fn purge_stale_cross_signing_messages(
        &self,
        actor_id: &str,
        new_generation: u64,
    ) -> ServiceResult<usize> {
        self.device_delivery
            .purge_stale_cross_signing_messages(actor_id, new_generation)
            .await
    }

    pub async fn register_push_device(&self, registration: Value) -> ServiceResult<()> {
        self.device_delivery
            .register_push_device(registration)
            .await
    }
    pub async fn unregister_push_device(
        &self,
        actor_id: &str,
        device_id: &str,
        push_key: Option<&str>,
        app_id: Option<&str>,
    ) -> ServiceResult<usize> {
        self.device_delivery
            .unregister_push_device(actor_id, device_id, push_key, app_id)
            .await
    }
    pub async fn push_devices(&self) -> ServiceResult<Vec<Value>> {
        self.device_delivery.push_devices().await
    }

    pub async fn append_device_message(
        &self,
        message: DeviceMessageState,
    ) -> ServiceResult<()> {
        self.device_messages.append(message).await
    }

    pub async fn commit_device_message_batch(
        &self,
        batch: DeviceMessageBatchRecord,
    ) -> ServiceResult<DeviceMessageBatchCommitOutcome> {
        self.device_messages.commit_batch(batch).await
    }

    pub async fn inspect_device_message_batch(
        &self,
        request_key: &str,
        request_digest: &str,
        items: &[DeviceMessageIntentRecord],
    ) -> ServiceResult<DeviceMessageBatchInspection> {
        self.device_messages
            .inspect_batch(request_key, request_digest, items)
            .await
    }

    pub async fn issue_device_message_ack_token(
        &self,
        recipient: &str,
        device_id: &str,
        queue_position: i64,
    ) -> ServiceResult<Option<String>> {
        self.device_messages
            .issue_ack_token(recipient, device_id, queue_position)
            .await
    }

    pub async fn acknowledge_device_messages(
        &self,
        recipient: &str,
        device_id: &str,
        ack_token: &str,
    ) -> ServiceResult<Option<usize>> {
        self.device_messages
            .acknowledge(recipient, device_id, ack_token)
            .await
    }

    pub async fn device_messages_after(
        &self,
        recipient: &str,
        device_id: &str,
        queue_position: i64,
    ) -> ServiceResult<Vec<DeviceMessageState>> {
        self.device_messages
            .messages_after(recipient, device_id, queue_position)
            .await
    }

    pub async fn prune_device_messages(
        &self,
        per_device_capacity: usize,
        now: DateTime<Utc>,
    ) -> ServiceResult<()> {
        self.device_messages.prune(per_device_capacity, now).await
    }

    pub async fn device_message_lost_watermark(
        &self,
        recipient: &str,
        device_id: &str,
    ) -> ServiceResult<Option<i64>> {
        self.device_messages
            .lost_watermark(recipient, device_id)
            .await
    }

    pub async fn store_presence(&self, presence: PresenceState) -> ServiceResult<()> {
        self.ephemeral.store_presence(presence).await
    }

    pub async fn presence_for_actor(
        &self,
        actor_id: &str,
    ) -> ServiceResult<Vec<PresenceState>> {
        self.ephemeral.presence_for_actor(actor_id).await
    }

    pub async fn delete_presence(&self, actor_id: &str) -> ServiceResult<()> {
        self.ephemeral.delete_presence(actor_id).await
    }

    pub async fn store_typing(&self, typing: TypingState) -> ServiceResult<()> {
        self.ephemeral.store_typing(typing).await
    }

    pub async fn remove_typing(&self, actor_id: &str, realm_id: &str) -> ServiceResult<()> {
        self.ephemeral.remove_typing(actor_id, realm_id).await
    }

    pub async fn typing_for_realm(&self, realm_id: &str) -> ServiceResult<Vec<TypingState>> {
        self.ephemeral.typing_for_realm(realm_id).await
    }

    pub async fn prune_expired_typing(&self) -> ServiceResult<usize> {
        self.ephemeral.prune_expired_typing().await
    }

    pub async fn store_call_signal(&self, signal: CallSignalState) -> ServiceResult<()> {
        self.ephemeral.store_call_signal(signal).await
    }
    pub async fn call_signals_for_realm(
        &self,
        realm_id: &str,
    ) -> ServiceResult<Vec<CallSignalState>> {
        self.ephemeral.call_signals_for_realm(realm_id).await
    }
    pub async fn call_signal_watermark(
        &self,
        actor_id: &str,
        device_id: &str,
        realm_id: &str,
    ) -> ServiceResult<u64> {
        self.ephemeral
            .call_signal_watermark(actor_id, device_id, realm_id)
            .await
    }
    pub async fn advance_call_signal_watermark(
        &self,
        actor_id: &str,
        device_id: &str,
        realm_id: &str,
        position: u64,
    ) -> ServiceResult<()> {
        self.ephemeral
            .advance_call_signal_watermark(actor_id, device_id, realm_id, position)
            .await
    }
    pub async fn store_read_receipt(&self, receipt: ReadReceiptState) -> ServiceResult<()> {
        self.ephemeral.store_read_receipt(receipt).await
    }
    pub async fn read_receipts_for_realm(
        &self,
        realm_id: &str,
    ) -> ServiceResult<Vec<ReadReceiptState>> {
        self.ephemeral.read_receipts_for_realm(realm_id).await
    }
    pub async fn read_receipts_for_event(
        &self,
        event_id: &str,
    ) -> ServiceResult<Vec<ReadReceiptState>> {
        self.ephemeral.read_receipts_for_event(event_id).await
    }
    pub async fn read_receipt_watermark(
        &self,
        actor_id: &str,
        device_id: &str,
        realm_id: &str,
    ) -> ServiceResult<u64> {
        self.ephemeral
            .read_receipt_watermark(actor_id, device_id, realm_id)
            .await
    }
    pub async fn advance_read_receipt_watermark(
        &self,
        actor_id: &str,
        device_id: &str,
        realm_id: &str,
        position: u64,
    ) -> ServiceResult<()> {
        self.ephemeral
            .advance_read_receipt_watermark(actor_id, device_id, realm_id, position)
            .await
    }

    pub async fn blob(&self, blob_ref: &str) -> ServiceResult<Option<BlobState>> {
        self.blobs.blob(blob_ref).await
    }
    pub async fn store_blob(&self, blob_ref: &str, blob: BlobState) -> ServiceResult<()> {
        self.blobs.store_blob(blob_ref, blob).await
    }
    pub async fn blobs(&self) -> ServiceResult<Vec<BlobState>> {
        self.blobs.blobs().await
    }

    pub async fn push_bridge_cache_entry(
        &self,
        bridge_describe_url: &str,
    ) -> ServiceResult<Option<OutboundPushBridgeCacheState>> {
        self.push_bridge_cache.entry(bridge_describe_url).await
    }
    pub async fn store_push_bridge_cache_entry(
        &self,
        bridge_describe_url: &str,
        record: OutboundPushBridgeCacheState,
    ) -> ServiceResult<()> {
        self.push_bridge_cache
            .store_entry(bridge_describe_url, record)
            .await
    }
    pub async fn delete_push_bridge_cache_entry(
        &self,
        bridge_describe_url: &str,
    ) -> ServiceResult<bool> {
        self.push_bridge_cache
            .delete_entry(bridge_describe_url)
            .await
    }
    pub async fn clear_push_bridge_cache(&self) -> ServiceResult<usize> {
        self.push_bridge_cache.clear().await
    }
    pub async fn push_bridge_cache_entries(
        &self,
    ) -> ServiceResult<Vec<OutboundPushBridgeCacheState>> {
        self.push_bridge_cache.entries().await
    }
    pub async fn push_bridge_cache_len(&self) -> ServiceResult<usize> {
        self.push_bridge_cache.entry_count().await
    }
    pub async fn current_push_bridge_contract(
        &self,
        bridge_describe_url: &str,
    ) -> ServiceResult<Option<OutboundPushBridgeCacheState>> {
        self.push_bridge_cache
            .current_contract(bridge_describe_url)
            .await
    }
    pub async fn verify_push_bridge_contract_freshness(
        &self,
        bridge_describe_url: &str,
        observed_digest: &str,
        max_age: chrono::Duration,
    ) -> ServiceResult<PushContractDrift> {
        self.push_bridge_cache
            .verify_contract_freshness(bridge_describe_url, observed_digest, max_age)
            .await
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    #[derive(Default)]
    struct RecordingNotifications(Mutex<Vec<Value>>);

    struct NoDeviceDelivery;

    struct NoDeviceMessages;
    struct NoEphemeralDelivery;
    struct NoBlobs;
    struct NoPushBridgeCache;
    struct NoObjectStorage;

    #[async_trait]
    impl ObjectStoragePort for NoObjectStorage {
        fn backend_name(&self) -> String {
            "memory".to_owned()
        }

        fn object_key_for_sha256(&self, sha256: &str) -> String {
            format!("sha256/{sha256}")
        }

        async fn put(&self, _key: &str, _bytes: Vec<u8>) -> Result<(), String> {
            Ok(())
        }

        async fn put_file(&self, _key: &str, _file_path: &std::path::Path) -> Result<(), String> {
            Ok(())
        }

        async fn get(&self, _key: &str) -> Result<Vec<u8>, String> {
            Ok(Vec::new())
        }

        async fn get_range_stream(
            &self,
            _key: &str,
            _range: std::ops::Range<u64>,
        ) -> Result<BoxStream<'static, Result<Bytes, String>>, String> {
            Ok(Box::pin(futures_util::stream::empty()))
        }

        async fn delete(&self, _key: &str) -> Result<(), String> {
            Ok(())
        }
    }

    #[async_trait]
    impl PushBridgeCachePort for NoPushBridgeCache {
        async fn entry(
            &self,
            _bridge_describe_url: &str,
        ) -> ServiceResult<Option<OutboundPushBridgeCacheState>> {
            Ok(None)
        }
        async fn store_entry(
            &self,
            _bridge_describe_url: &str,
            _record: OutboundPushBridgeCacheState,
        ) -> ServiceResult<()> {
            Ok(())
        }
        async fn delete_entry(&self, _bridge_describe_url: &str) -> ServiceResult<bool> {
            Ok(false)
        }
        async fn clear(&self) -> ServiceResult<usize> {
            Ok(0)
        }
        async fn entries(&self) -> ServiceResult<Vec<OutboundPushBridgeCacheState>> {
            Ok(Vec::new())
        }
        async fn entry_count(&self) -> ServiceResult<usize> {
            Ok(0)
        }
        async fn current_contract(
            &self,
            _bridge_describe_url: &str,
        ) -> ServiceResult<Option<OutboundPushBridgeCacheState>> {
            Ok(None)
        }
        async fn verify_contract_freshness(
            &self,
            _bridge_describe_url: &str,
            _observed_digest: &str,
            _max_age: chrono::Duration,
        ) -> ServiceResult<PushContractDrift> {
            Ok(PushContractDrift::Unknown)
        }
    }

    #[async_trait]
    impl BlobPort for NoBlobs {
        async fn blob(&self, _blob_ref: &str) -> ServiceResult<Option<BlobState>> {
            Ok(None)
        }
        async fn store_blob(&self, _blob_ref: &str, _blob: BlobState) -> ServiceResult<()> {
            Ok(())
        }
        async fn blobs(&self) -> ServiceResult<Vec<BlobState>> {
            Ok(Vec::new())
        }
    }

    #[async_trait]
    impl EphemeralDeliveryPort for NoEphemeralDelivery {
        async fn store_presence(&self, _presence: PresenceState) -> ServiceResult<()> {
            Ok(())
        }
        async fn presence_for_actor(
            &self,
            _actor_id: &str,
        ) -> ServiceResult<Vec<PresenceState>> {
            Ok(Vec::new())
        }
        async fn delete_presence(&self, _actor_id: &str) -> ServiceResult<()> {
            Ok(())
        }
        async fn store_typing(&self, _typing: TypingState) -> ServiceResult<()> {
            Ok(())
        }
        async fn remove_typing(&self, _actor_id: &str, _realm_id: &str) -> ServiceResult<()> {
            Ok(())
        }
        async fn typing_for_realm(&self, _realm_id: &str) -> ServiceResult<Vec<TypingState>> {
            Ok(Vec::new())
        }
        async fn prune_expired_typing(&self) -> ServiceResult<usize> {
            Ok(0)
        }
        async fn store_call_signal(&self, _signal: CallSignalState) -> ServiceResult<()> {
            Ok(())
        }
        async fn call_signals_for_realm(
            &self,
            _realm_id: &str,
        ) -> ServiceResult<Vec<CallSignalState>> {
            Ok(Vec::new())
        }
        async fn call_signal_watermark(
            &self,
            _actor_id: &str,
            _device_id: &str,
            _realm_id: &str,
        ) -> ServiceResult<u64> {
            Ok(0)
        }
        async fn advance_call_signal_watermark(
            &self,
            _actor_id: &str,
            _device_id: &str,
            _realm_id: &str,
            _position: u64,
        ) -> ServiceResult<()> {
            Ok(())
        }
        async fn store_read_receipt(&self, _receipt: ReadReceiptState) -> ServiceResult<()> {
            Ok(())
        }
        async fn read_receipts_for_realm(
            &self,
            _realm_id: &str,
        ) -> ServiceResult<Vec<ReadReceiptState>> {
            Ok(Vec::new())
        }
        async fn read_receipts_for_event(
            &self,
            _event_id: &str,
        ) -> ServiceResult<Vec<ReadReceiptState>> {
            Ok(Vec::new())
        }
        async fn read_receipt_watermark(
            &self,
            _actor_id: &str,
            _device_id: &str,
            _realm_id: &str,
        ) -> ServiceResult<u64> {
            Ok(0)
        }
        async fn advance_read_receipt_watermark(
            &self,
            _actor_id: &str,
            _device_id: &str,
            _realm_id: &str,
            _position: u64,
        ) -> ServiceResult<()> {
            Ok(())
        }
    }

    #[async_trait]
    impl DeviceMessagePort for NoDeviceMessages {
        async fn append(&self, _message: DeviceMessageState) -> ServiceResult<()> {
            Ok(())
        }
        async fn inspect_batch(
            &self,
            _request_key: &str,
            _request_digest: &str,
            _items: &[DeviceMessageIntentRecord],
        ) -> ServiceResult<DeviceMessageBatchInspection> {
            Ok(DeviceMessageBatchInspection::Fresh {
                existing_message_outcomes: Default::default(),
            })
        }
        async fn commit_batch(
            &self,
            _batch: DeviceMessageBatchRecord,
        ) -> ServiceResult<DeviceMessageBatchCommitOutcome> {
            Ok(DeviceMessageBatchCommitOutcome::Stored(Default::default()))
        }
        async fn issue_ack_token(
            &self,
            _recipient: &str,
            _device_id: &str,
            _queue_position: i64,
        ) -> ServiceResult<Option<String>> {
            Ok(None)
        }
        async fn acknowledge(
            &self,
            _recipient: &str,
            _device_id: &str,
            _ack_token: &str,
        ) -> ServiceResult<Option<usize>> {
            Ok(None)
        }
        async fn messages_after(
            &self,
            _recipient: &str,
            _device_id: &str,
            _queue_position: i64,
        ) -> ServiceResult<Vec<DeviceMessageState>> {
            Ok(Vec::new())
        }
        async fn prune(
            &self,
            _per_device_capacity: usize,
            _now: DateTime<Utc>,
        ) -> ServiceResult<()> {
            Ok(())
        }
        async fn lost_watermark(
            &self,
            _recipient: &str,
            _device_id: &str,
        ) -> ServiceResult<Option<i64>> {
            Ok(None)
        }
    }

    #[async_trait]
    impl DeviceDeliveryPort for NoDeviceDelivery {
        async fn purge_device_delivery(
            &self,
            _actor_id: &str,
            _device_id: &str,
        ) -> ServiceResult<DeviceDeliveryPurgeResult> {
            Ok(DeviceDeliveryPurgeResult::default())
        }

        async fn purge_stale_cross_signing_messages(
            &self,
            _actor_id: &str,
            _new_generation: u64,
        ) -> ServiceResult<usize> {
            Ok(0)
        }
        async fn register_push_device(&self, _registration: Value) -> ServiceResult<()> {
            Ok(())
        }
        async fn unregister_push_device(
            &self,
            _actor_id: &str,
            _device_id: &str,
            _push_key: Option<&str>,
            _app_id: Option<&str>,
        ) -> ServiceResult<usize> {
            Ok(0)
        }
        async fn push_devices(&self) -> ServiceResult<Vec<Value>> {
            Ok(Vec::new())
        }
    }

    #[async_trait]
    impl NotificationWritePort for RecordingNotifications {
        async fn store_notification(&self, record: Value) -> ServiceResult<()> {
            self.0.lock().expect("notification lock").push(record);
            Ok(())
        }

        async fn store_account_delta(&self, record: Value) -> ServiceResult<()> {
            self.0.lock().expect("notification lock").push(record);
            Ok(())
        }

        async fn list_for_account(
            &self,
            _controller_account_id: &str,
            _recipient_service_id: &str,
            _after_position: Option<i64>,
        ) -> ServiceResult<Vec<Value>> {
            Ok(self.0.lock().expect("notification lock").clone())
        }

        async fn list_for_recipient(&self, _recipient_id: &str) -> ServiceResult<Vec<Value>> {
            Ok(self.0.lock().expect("notification lock").clone())
        }
    }

    #[tokio::test]
    async fn notification_write_uses_only_the_narrow_port() {
        let port = Arc::new(RecordingNotifications::default());
        let service = DeliveryService::new(DeliveryServiceRuntime {
            notifications: port.clone(),
            device_delivery: Arc::new(NoDeviceDelivery),
            device_messages: Arc::new(NoDeviceMessages),
            ephemeral: Arc::new(NoEphemeralDelivery),
            blobs: Arc::new(NoBlobs),
            push_bridge_cache: Arc::new(NoPushBridgeCache),
            object_storage: Arc::new(NoObjectStorage),
            push_target_hmac_key: [0; 32],
        });
        service
            .store_notification(StoreNotificationCommand {
                record: serde_json::json!({"notification_id": "notification:test"}),
            })
            .await
            .expect("store notification");
        assert_eq!(port.0.lock().expect("notification lock").len(), 1);
    }
}

