use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde_json::Value;

use crate::ApplicationResult;

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
    async fn store_notification(&self, record: Value) -> ApplicationResult<()>;
    async fn store_account_delta(&self, record: Value) -> ApplicationResult<()>;
    async fn list_for_account(
        &self,
        controller_account_id: &str,
        recipient_service_id: &str,
        after_position: Option<i64>,
    ) -> ApplicationResult<Vec<Value>>;
    async fn list_for_recipient(&self, recipient_id: &str) -> ApplicationResult<Vec<Value>>;
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
    ) -> ApplicationResult<DeviceDeliveryPurgeResult>;
    async fn purge_stale_cross_signing_messages(
        &self,
        actor_id: &str,
        new_generation: u64,
    ) -> ApplicationResult<usize>;
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

#[async_trait]
pub trait DeviceMessagePort: Send + Sync {
    async fn append(&self, message: DeviceMessageState) -> ApplicationResult<()>;
    async fn register_transaction(&self, key: String) -> ApplicationResult<bool>;
    async fn issue_ack_token(
        &self,
        recipient: &str,
        device_id: &str,
        queue_position: i64,
    ) -> ApplicationResult<Option<String>>;
    async fn acknowledge(
        &self,
        recipient: &str,
        device_id: &str,
        ack_token: &str,
    ) -> ApplicationResult<Option<usize>>;
    async fn messages_after(
        &self,
        recipient: &str,
        device_id: &str,
        queue_position: i64,
    ) -> ApplicationResult<Vec<DeviceMessageState>>;
    async fn prune(&self, per_device_capacity: usize, now: DateTime<Utc>) -> ApplicationResult<()>;
    async fn lost_watermark(
        &self,
        recipient: &str,
        device_id: &str,
    ) -> ApplicationResult<Option<i64>>;
}

#[derive(Clone)]
pub struct DeliveryApplicationService {
    notifications: Arc<dyn NotificationWritePort>,
    device_delivery: Arc<dyn DeviceDeliveryPort>,
    device_messages: Arc<dyn DeviceMessagePort>,
}

impl DeliveryApplicationService {
    pub fn new(
        notifications: Arc<dyn NotificationWritePort>,
        device_delivery: Arc<dyn DeviceDeliveryPort>,
        device_messages: Arc<dyn DeviceMessagePort>,
    ) -> Self {
        Self {
            notifications,
            device_delivery,
            device_messages,
        }
    }

    pub async fn store_notification(
        &self,
        command: StoreNotificationCommand,
    ) -> ApplicationResult<()> {
        self.notifications.store_notification(command.record).await
    }

    pub async fn store_account_delta(
        &self,
        command: StoreAccountNotificationDeltaCommand,
    ) -> ApplicationResult<()> {
        self.notifications.store_account_delta(command.record).await
    }

    pub async fn list_account_deltas(
        &self,
        query: ListAccountNotificationDeltasQuery,
    ) -> ApplicationResult<Vec<Value>> {
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
    ) -> ApplicationResult<Vec<Value>> {
        self.notifications
            .list_for_recipient(&query.recipient_id)
            .await
    }

    pub async fn purge_device_delivery(
        &self,
        actor_id: &str,
        device_id: &str,
    ) -> ApplicationResult<DeviceDeliveryPurgeResult> {
        self.device_delivery
            .purge_device_delivery(actor_id, device_id)
            .await
    }

    pub async fn purge_stale_cross_signing_messages(
        &self,
        actor_id: &str,
        new_generation: u64,
    ) -> ApplicationResult<usize> {
        self.device_delivery
            .purge_stale_cross_signing_messages(actor_id, new_generation)
            .await
    }

    pub async fn append_device_message(
        &self,
        message: DeviceMessageState,
    ) -> ApplicationResult<()> {
        self.device_messages.append(message).await
    }

    pub async fn register_device_message_transaction(
        &self,
        key: String,
    ) -> ApplicationResult<bool> {
        self.device_messages.register_transaction(key).await
    }

    pub async fn issue_device_message_ack_token(
        &self,
        recipient: &str,
        device_id: &str,
        queue_position: i64,
    ) -> ApplicationResult<Option<String>> {
        self.device_messages
            .issue_ack_token(recipient, device_id, queue_position)
            .await
    }

    pub async fn acknowledge_device_messages(
        &self,
        recipient: &str,
        device_id: &str,
        ack_token: &str,
    ) -> ApplicationResult<Option<usize>> {
        self.device_messages
            .acknowledge(recipient, device_id, ack_token)
            .await
    }

    pub async fn device_messages_after(
        &self,
        recipient: &str,
        device_id: &str,
        queue_position: i64,
    ) -> ApplicationResult<Vec<DeviceMessageState>> {
        self.device_messages
            .messages_after(recipient, device_id, queue_position)
            .await
    }

    pub async fn prune_device_messages(
        &self,
        per_device_capacity: usize,
        now: DateTime<Utc>,
    ) -> ApplicationResult<()> {
        self.device_messages.prune(per_device_capacity, now).await
    }

    pub async fn device_message_lost_watermark(
        &self,
        recipient: &str,
        device_id: &str,
    ) -> ApplicationResult<Option<i64>> {
        self.device_messages
            .lost_watermark(recipient, device_id)
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

    #[async_trait]
    impl DeviceMessagePort for NoDeviceMessages {
        async fn append(&self, _message: DeviceMessageState) -> ApplicationResult<()> {
            Ok(())
        }
        async fn register_transaction(&self, _key: String) -> ApplicationResult<bool> {
            Ok(true)
        }
        async fn issue_ack_token(
            &self,
            _recipient: &str,
            _device_id: &str,
            _queue_position: i64,
        ) -> ApplicationResult<Option<String>> {
            Ok(None)
        }
        async fn acknowledge(
            &self,
            _recipient: &str,
            _device_id: &str,
            _ack_token: &str,
        ) -> ApplicationResult<Option<usize>> {
            Ok(None)
        }
        async fn messages_after(
            &self,
            _recipient: &str,
            _device_id: &str,
            _queue_position: i64,
        ) -> ApplicationResult<Vec<DeviceMessageState>> {
            Ok(Vec::new())
        }
        async fn prune(
            &self,
            _per_device_capacity: usize,
            _now: DateTime<Utc>,
        ) -> ApplicationResult<()> {
            Ok(())
        }
        async fn lost_watermark(
            &self,
            _recipient: &str,
            _device_id: &str,
        ) -> ApplicationResult<Option<i64>> {
            Ok(None)
        }
    }

    #[async_trait]
    impl DeviceDeliveryPort for NoDeviceDelivery {
        async fn purge_device_delivery(
            &self,
            _actor_id: &str,
            _device_id: &str,
        ) -> ApplicationResult<DeviceDeliveryPurgeResult> {
            Ok(DeviceDeliveryPurgeResult::default())
        }

        async fn purge_stale_cross_signing_messages(
            &self,
            _actor_id: &str,
            _new_generation: u64,
        ) -> ApplicationResult<usize> {
            Ok(0)
        }
    }

    #[async_trait]
    impl NotificationWritePort for RecordingNotifications {
        async fn store_notification(&self, record: Value) -> ApplicationResult<()> {
            self.0.lock().expect("notification lock").push(record);
            Ok(())
        }

        async fn store_account_delta(&self, record: Value) -> ApplicationResult<()> {
            self.0.lock().expect("notification lock").push(record);
            Ok(())
        }

        async fn list_for_account(
            &self,
            _controller_account_id: &str,
            _recipient_service_id: &str,
            _after_position: Option<i64>,
        ) -> ApplicationResult<Vec<Value>> {
            Ok(self.0.lock().expect("notification lock").clone())
        }

        async fn list_for_recipient(&self, _recipient_id: &str) -> ApplicationResult<Vec<Value>> {
            Ok(self.0.lock().expect("notification lock").clone())
        }
    }

    #[tokio::test]
    async fn notification_write_uses_only_the_narrow_port() {
        let port = Arc::new(RecordingNotifications::default());
        let service = DeliveryApplicationService::new(
            port.clone(),
            Arc::new(NoDeviceDelivery),
            Arc::new(NoDeviceMessages),
        );
        service
            .store_notification(StoreNotificationCommand {
                record: serde_json::json!({"notification_id": "notification:test"}),
            })
            .await
            .expect("store notification");
        assert_eq!(port.0.lock().expect("notification lock").len(), 1);
    }
}
