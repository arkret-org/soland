use std::sync::Arc;

use serde_json::Value;
use soland_storage::*;

use crate::delivery::*;

struct PersistenceNotificationWriter(Arc<dyn PersistenceStore>);
struct PersistenceDeviceDelivery(Arc<dyn PersistenceStore>);
struct PersistenceDeviceMessages(Arc<dyn PersistenceStore>);
struct PersistenceSignalRelay(Arc<dyn PersistenceStore>);
struct PersistenceBlobs(Arc<dyn PersistenceStore>);
struct PersistencePushBridgeCache(Arc<dyn PersistenceStore>);

fn application_push_bridge_cache(
    record: soland_storage::OutboundPushBridgeCacheRecord,
) -> crate::delivery::OutboundPushBridgeCacheState {
    crate::delivery::OutboundPushBridgeCacheState {
        push_gateway_url: record.push_gateway_url,
        service_base_url: record.service_base_url,
        bridge_describe_url: record.bridge_describe_url,
        fetch_state: record.fetch_state,
        cache_state: record.cache_state,
        contract_digest: record.contract_digest,
        fetched_at: record.fetched_at,
        remote_contract: record.remote_contract,
        trust_level: record.trust_level,
        freshness_at: record.freshness_at,
        etag: record.etag,
    }
}

fn persistence_push_bridge_cache(
    record: crate::delivery::OutboundPushBridgeCacheState,
) -> soland_storage::OutboundPushBridgeCacheRecord {
    soland_storage::OutboundPushBridgeCacheRecord {
        push_gateway_url: record.push_gateway_url,
        service_base_url: record.service_base_url,
        bridge_describe_url: record.bridge_describe_url,
        fetch_state: record.fetch_state,
        cache_state: record.cache_state,
        contract_digest: record.contract_digest,
        fetched_at: record.fetched_at,
        remote_contract: record.remote_contract,
        trust_level: record.trust_level,
        freshness_at: record.freshness_at,
        etag: record.etag,
    }
}

fn application_push_contract_drift(
    result: soland_storage::DriftResult,
) -> crate::delivery::PushContractDrift {
    match result {
        soland_storage::DriftResult::Match => crate::delivery::PushContractDrift::Match,
        soland_storage::DriftResult::Stale => crate::delivery::PushContractDrift::Stale,
        soland_storage::DriftResult::DigestMismatch => {
            crate::delivery::PushContractDrift::DigestMismatch
        }
        soland_storage::DriftResult::Unknown => crate::delivery::PushContractDrift::Unknown,
    }
}
#[async_trait::async_trait]
impl crate::delivery::NotificationWritePort for PersistenceNotificationWriter {
    async fn store_notification(
        &self,
        record: RecipientNotificationRecord,
    ) -> crate::ServiceResult<()> {
        self.0.notifications().put(record).await?;
        Ok(())
    }

    async fn store_account_delta(
        &self,
        record: AccountNotificationDeltaWrite,
    ) -> crate::ServiceResult<()> {
        self.0.notifications().put_account_delta(record).await?;
        Ok(())
    }

    async fn list_for_account(
        &self,
        controller_account_id: &str,
        recipient_service_id: &str,
        after_position: Option<i64>,
    ) -> crate::ServiceResult<Vec<StoredAccountNotificationDelta>> {
        Ok(self
            .0
            .notifications()
            .list_for_account(controller_account_id, recipient_service_id, after_position)
            .await?)
    }

    async fn list_for_recipient(
        &self,
        recipient_id: &str,
    ) -> crate::ServiceResult<Vec<RecipientNotificationRecord>> {
        Ok(self
            .0
            .notifications()
            .list_for_recipient(recipient_id)
            .await?)
    }
}

#[async_trait::async_trait]
impl crate::delivery::DeviceDeliveryPort for PersistenceDeviceDelivery {
    async fn purge_device_delivery(
        &self,
        actor_id: &str,
        device_id: &str,
    ) -> crate::ServiceResult<crate::delivery::DeviceDeliveryPurgeResult> {
        let to_device_messages_dropped = match self
            .0
            .device_messages()
            .purge(actor_id, device_id)
            .await
        {
            Ok(count) => count,
            Err(error) => {
                tracing::error!(%error, actor_id, device_id, "failed to purge to-device messages");
                0
            }
        };
        let push_registrations_removed = match self
            .0
            .push_devices()
            .unregister(actor_id, device_id, None, None)
            .await
        {
            Ok(count) => count,
            Err(error) => {
                tracing::error!(%error, actor_id, device_id, "failed to unregister push devices");
                0
            }
        };
        Ok(crate::delivery::DeviceDeliveryPurgeResult {
            to_device_messages_dropped,
            push_registrations_removed,
        })
    }

    async fn purge_stale_cross_signing_messages(
        &self,
        actor_id: &str,
        new_generation: u64,
    ) -> crate::ServiceResult<usize> {
        Ok(self
            .0
            .device_messages()
            .purge_cross_signing_reset_stale_messages(actor_id, new_generation)
            .await?)
    }

    async fn register_push_device(&self, registration: Value) -> crate::ServiceResult<()> {
        self.0.push_devices().register(registration).await?;
        Ok(())
    }

    async fn unregister_push_device(
        &self,
        actor_id: &str,
        device_id: &str,
        push_key: Option<&str>,
        app_id: Option<&str>,
    ) -> crate::ServiceResult<usize> {
        Ok(self
            .0
            .push_devices()
            .unregister(actor_id, device_id, push_key, app_id)
            .await?)
    }

    async fn push_devices(&self) -> crate::ServiceResult<Vec<Value>> {
        Ok(self.0.push_devices().snapshot_all().await?)
    }
}

#[async_trait::async_trait]
impl crate::delivery::SignalRelayPort for PersistenceSignalRelay {
    async fn append_signal(
        &self,
        record: crate::delivery::SignalRelayState,
    ) -> crate::ServiceResult<()> {
        self.0.signal_relay().append(record).await?;
        Ok(())
    }

    async fn signals_for_realm(
        &self,
        realm_id: &str,
    ) -> crate::ServiceResult<Vec<crate::delivery::SignalRelayState>> {
        Ok(self.0.signal_relay().list_for_realm(realm_id).await?)
    }

    async fn signal_digest_seen(
        &self,
        realm_id: &str,
        envelope_digest: &str,
    ) -> crate::ServiceResult<bool> {
        Ok(self
            .0
            .signal_relay()
            .contains_digest(realm_id, envelope_digest)
            .await?)
    }

    async fn prune_expired_signals(&self) -> crate::ServiceResult<usize> {
        Ok(self.0.signal_relay().prune_expired().await?)
    }

    async fn signal_watermark(
        &self,
        actor_id: &str,
        device_id: &str,
        realm_id: &str,
    ) -> crate::ServiceResult<u64> {
        Ok(self
            .0
            .signal_relay()
            .delivered_through(actor_id, device_id, realm_id)
            .await?)
    }

    async fn advance_signal_watermark(
        &self,
        actor_id: &str,
        device_id: &str,
        realm_id: &str,
        position: u64,
    ) -> crate::ServiceResult<()> {
        self.0
            .signal_relay()
            .advance(actor_id, device_id, realm_id, position)
            .await?;
        Ok(())
    }
}

fn application_blob(record: soland_storage::BlobRecord) -> crate::delivery::BlobState {
    crate::delivery::BlobState {
        sha256: record.sha256,
        size_bytes: record.size_bytes,
        storage_backend: record.storage_backend,
        storage_key: record.storage_key,
        media_type: record.media_type,
        filename: record.filename,
        realm_id: record.realm_id,
        encryption: record.encryption,
        legal_hold: record.legal_hold,
        redacted: record.redacted,
        visibility: record.visibility,
        uploaded_by: record.uploaded_by,
        created_at: record.created_at,
    }
}
fn persistence_blob(record: crate::delivery::BlobState) -> soland_storage::BlobRecord {
    soland_storage::BlobRecord {
        sha256: record.sha256,
        size_bytes: record.size_bytes,
        storage_backend: record.storage_backend,
        storage_key: record.storage_key,
        media_type: record.media_type,
        filename: record.filename,
        realm_id: record.realm_id,
        encryption: record.encryption,
        legal_hold: record.legal_hold,
        redacted: record.redacted,
        visibility: record.visibility,
        uploaded_by: record.uploaded_by,
        created_at: record.created_at,
    }
}

#[async_trait::async_trait]
impl crate::delivery::BlobPort for PersistenceBlobs {
    async fn blob(
        &self,
        blob_ref: &str,
    ) -> crate::ServiceResult<Option<crate::delivery::BlobState>> {
        Ok(self.0.blobs().get(blob_ref).await?.map(application_blob))
    }
    async fn store_blob(
        &self,
        blob_ref: &str,
        blob: crate::delivery::BlobState,
    ) -> crate::ServiceResult<()> {
        self.0
            .blobs()
            .put(blob_ref, &persistence_blob(blob))
            .await?;
        Ok(())
    }
    async fn blobs(&self) -> crate::ServiceResult<Vec<crate::delivery::BlobState>> {
        Ok(self
            .0
            .blobs()
            .snapshot_all()
            .await?
            .into_iter()
            .map(application_blob)
            .collect())
    }
}

#[async_trait::async_trait]
impl crate::delivery::PushBridgeCachePort for PersistencePushBridgeCache {
    async fn entry(
        &self,
        bridge_describe_url: &str,
    ) -> crate::ServiceResult<Option<crate::delivery::OutboundPushBridgeCacheState>> {
        Ok(self
            .0
            .push_bridge_cache()
            .get(bridge_describe_url)
            .await?
            .map(application_push_bridge_cache))
    }

    async fn store_entry(
        &self,
        bridge_describe_url: &str,
        record: crate::delivery::OutboundPushBridgeCacheState,
    ) -> crate::ServiceResult<()> {
        self.0
            .push_bridge_cache()
            .put(bridge_describe_url, persistence_push_bridge_cache(record))
            .await?;
        Ok(())
    }

    async fn delete_entry(&self, bridge_describe_url: &str) -> crate::ServiceResult<bool> {
        Ok(self
            .0
            .push_bridge_cache()
            .delete(bridge_describe_url)
            .await?)
    }

    async fn clear(&self) -> crate::ServiceResult<usize> {
        Ok(self.0.push_bridge_cache().clear().await?)
    }

    async fn entries(
        &self,
    ) -> crate::ServiceResult<Vec<crate::delivery::OutboundPushBridgeCacheState>> {
        Ok(self
            .0
            .push_bridge_cache()
            .snapshot_all()
            .await?
            .into_iter()
            .map(application_push_bridge_cache)
            .collect())
    }

    async fn entry_count(&self) -> crate::ServiceResult<usize> {
        Ok(self.0.push_bridge_cache().len().await?)
    }

    async fn current_contract(
        &self,
        bridge_describe_url: &str,
    ) -> crate::ServiceResult<Option<crate::delivery::OutboundPushBridgeCacheState>> {
        Ok(self
            .0
            .push_bridge_cache()
            .current_contract(bridge_describe_url)
            .await?
            .map(application_push_bridge_cache))
    }
    async fn verify_contract_freshness(
        &self,
        bridge_describe_url: &str,
        observed_digest: &str,
        max_age: chrono::Duration,
    ) -> crate::ServiceResult<crate::delivery::PushContractDrift> {
        Ok(application_push_contract_drift(
            self.0
                .push_bridge_cache()
                .verify_contract_freshness(bridge_describe_url, observed_digest, max_age)
                .await?,
        ))
    }
}

fn application_device_message(
    record: soland_storage::DeviceMessageRecord,
) -> crate::delivery::DeviceMessageState {
    crate::delivery::DeviceMessageState {
        idempotency_key: record.idempotency_key,
        sender: record.sender,
        recipient: record.recipient,
        device_id: record.device_id,
        position: record.position,
        content: record.content,
        created_at: record.created_at,
    }
}

fn persistence_device_message(
    message: crate::delivery::DeviceMessageState,
) -> soland_storage::DeviceMessageRecord {
    soland_storage::DeviceMessageRecord {
        idempotency_key: message.idempotency_key,
        sender: message.sender,
        recipient: message.recipient,
        device_id: message.device_id,
        position: message.position,
        content: message.content,
        created_at: message.created_at,
    }
}

fn persistence_device_message_batch(
    batch: crate::delivery::DeviceMessageBatchRecord,
) -> soland_storage::DeviceMessageBatchRecord {
    soland_storage::DeviceMessageBatchRecord {
        request_key: batch.request_key,
        request_digest: batch.request_digest,
        idempotency_expires_at: batch.idempotency_expires_at,
        items: batch
            .items
            .into_iter()
            .map(|item| soland_storage::DeviceMessageBatchItemRecord {
                message_key: item.message_key,
                intent_digest: item.intent_digest,
                idempotency_expires_at: item.idempotency_expires_at,
                message: item.message.map(persistence_device_message),
            })
            .collect(),
    }
}

fn application_device_message_inspection(
    inspection: soland_storage::DeviceMessageBatchInspection,
) -> crate::delivery::DeviceMessageBatchInspection {
    match inspection {
        soland_storage::DeviceMessageBatchInspection::Fresh {
            existing_message_outcomes,
        } => crate::delivery::DeviceMessageBatchInspection::Fresh {
            existing_message_outcomes,
        },
        soland_storage::DeviceMessageBatchInspection::Duplicate(outcomes) => {
            crate::delivery::DeviceMessageBatchInspection::Duplicate(outcomes)
        }
        soland_storage::DeviceMessageBatchInspection::RequestConflict => {
            crate::delivery::DeviceMessageBatchInspection::RequestConflict
        }
        soland_storage::DeviceMessageBatchInspection::MessageConflict { message_key } => {
            crate::delivery::DeviceMessageBatchInspection::MessageConflict { message_key }
        }
    }
}

fn application_device_message_commit_outcome(
    outcome: soland_storage::DeviceMessageBatchCommitOutcome,
) -> crate::delivery::DeviceMessageBatchCommitOutcome {
    match outcome {
        soland_storage::DeviceMessageBatchCommitOutcome::Stored(outcomes) => {
            crate::delivery::DeviceMessageBatchCommitOutcome::Stored(outcomes)
        }
        soland_storage::DeviceMessageBatchCommitOutcome::Duplicate(outcomes) => {
            crate::delivery::DeviceMessageBatchCommitOutcome::Duplicate(outcomes)
        }
        soland_storage::DeviceMessageBatchCommitOutcome::RequestConflict => {
            crate::delivery::DeviceMessageBatchCommitOutcome::RequestConflict
        }
        soland_storage::DeviceMessageBatchCommitOutcome::MessageConflict { message_key } => {
            crate::delivery::DeviceMessageBatchCommitOutcome::MessageConflict { message_key }
        }
    }
}

#[async_trait::async_trait]
impl crate::delivery::DeviceMessagePort for PersistenceDeviceMessages {
    async fn append(
        &self,
        message: crate::delivery::DeviceMessageState,
    ) -> crate::ServiceResult<()> {
        self.0
            .device_messages()
            .append(persistence_device_message(message))
            .await?;
        Ok(())
    }

    async fn commit_batch(
        &self,
        batch: crate::delivery::DeviceMessageBatchRecord,
    ) -> crate::ServiceResult<crate::delivery::DeviceMessageBatchCommitOutcome> {
        Ok(application_device_message_commit_outcome(
            self.0
                .device_messages()
                .commit_batch(persistence_device_message_batch(batch))
                .await?,
        ))
    }

    async fn inspect_batch(
        &self,
        request_key: &str,
        request_digest: &str,
        items: &[crate::delivery::DeviceMessageIntentRecord],
    ) -> crate::ServiceResult<crate::delivery::DeviceMessageBatchInspection> {
        let items = items
            .iter()
            .map(|item| soland_storage::DeviceMessageIntentRecord {
                message_key: item.message_key.clone(),
                intent_digest: item.intent_digest.clone(),
            })
            .collect::<Vec<_>>();
        Ok(application_device_message_inspection(
            self.0
                .device_messages()
                .inspect_batch(request_key, request_digest, &items)
                .await?,
        ))
    }

    async fn issue_ack_token(
        &self,
        recipient: &str,
        device_id: &str,
        queue_position: i64,
    ) -> crate::ServiceResult<Option<String>> {
        Ok(self
            .0
            .device_messages()
            .issue_ack_token(recipient, device_id, queue_position)
            .await?)
    }

    async fn acknowledge(
        &self,
        recipient: &str,
        device_id: &str,
        ack_token: &str,
    ) -> crate::ServiceResult<Option<usize>> {
        Ok(self
            .0
            .device_messages()
            .ack_with_token(recipient, device_id, ack_token)
            .await?)
    }

    async fn messages_after(
        &self,
        recipient: &str,
        device_id: &str,
        queue_position: i64,
    ) -> crate::ServiceResult<Vec<crate::delivery::DeviceMessageState>> {
        Ok(self
            .0
            .device_messages()
            .list_after(recipient, device_id, queue_position)
            .await?
            .into_iter()
            .map(application_device_message)
            .collect())
    }

    async fn prune(
        &self,
        per_device_capacity: usize,
        now: chrono::DateTime<chrono::Utc>,
    ) -> crate::ServiceResult<()> {
        self.0.device_messages().prune_expired(now).await?;
        self.0
            .device_messages()
            .prune_over_capacity(per_device_capacity, now)
            .await?;
        Ok(())
    }

    async fn lost_watermark(
        &self,
        recipient: &str,
        device_id: &str,
    ) -> crate::ServiceResult<Option<i64>> {
        Ok(self
            .0
            .device_messages()
            .lost_watermark(recipient, device_id)
            .await?)
    }
}

pub fn build_persistence_delivery_service(
    persistence: Arc<dyn PersistenceStore>,
    object_storage: Arc<dyn ObjectStoragePort>,
    push_target_hmac_key: [u8; 32],
) -> DeliveryService {
    DeliveryService::new(crate::delivery::DeliveryServiceRuntime {
        notifications: Arc::new(PersistenceNotificationWriter(persistence.clone())),
        device_delivery: Arc::new(PersistenceDeviceDelivery(persistence.clone())),
        device_messages: Arc::new(PersistenceDeviceMessages(persistence.clone())),
        signals: Arc::new(PersistenceSignalRelay(persistence.clone())),
        blobs: Arc::new(PersistenceBlobs(persistence.clone())),
        push_bridge_cache: Arc::new(PersistencePushBridgeCache(persistence)),
        object_storage,
        push_target_hmac_key,
    })
}
