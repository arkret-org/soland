use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

use arkret_canonical::DigestSuite;
use arkret_models_collaboration::governance_dependencies::{
    GovernanceDependency, GovernanceDependencySelector,
};
use arkret_models_identity::DidOperationSubmitRequestBody;
use arkret_wire::{Event, Seal};

use super::{
    DeviceInventoryRecord, DeviceMessageBatchCommitOutcome, DeviceMessageBatchInspection,
    DeviceMessageBatchRecord, DeviceMessageIntentRecord, DeviceMessageRecord,
    DeviceRevocationGateSelector, PersistenceError, PersistenceResult, Utc, Uuid, Value,
    async_trait,
};

/// Receiver-verified PCR history and the immutable generic-Control signer
/// roots derived from it.
///
/// Construction deliberately replays every exact Event/Seal prefix through
/// the SDK. Persistence never accepts a caller-authored root, a current-head
/// alias, or a Station-attested `account_device` shortcut at the Seal CAS
/// boundary.
#[derive(Clone, Debug)]
pub struct ConfirmedDeviceControlProjection {
    history: arkret::DeviceAuthorizationHistory,
    roots: Vec<GovernanceDependency>,
}

impl ConfirmedDeviceControlProjection {
    /// Build the complete immutable root set for every successfully confirmed
    /// authorization visible in `history`. Each root freezes the
    /// authorization's first confirmation Seal even when `history` has since
    /// advanced to a later head or revocation.
    pub fn from_verified_history(
        history: arkret::DeviceAuthorizationHistory,
        principal_inception: &DidOperationSubmitRequestBody,
        seals: &[Seal],
        events: &[Event],
        suite: DigestSuite,
    ) -> PersistenceResult<Self> {
        let mut roots = Vec::with_capacity(history.authorizations().len());
        for authorization in history.authorizations() {
            let evidence = history
                .account_device_control_evidence(
                    authorization.authorization_event_id(),
                    principal_inception,
                    seals,
                    events,
                    suite,
                )
                .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
            let evidence_ref = evidence
                .evidence_ref()
                .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
            let item = GovernanceDependency::AuthenticatedSignerResolutionEvidence {
                selector: GovernanceDependencySelector::AuthenticatedSignerResolutionEvidence {
                    content_digest: evidence_ref
                        .content_digest()
                        .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?,
                },
                authenticated_signer_resolution_evidence: Box::new(evidence),
            };
            let canonical = crate::governance_signer_evidence_canonical(&item)?;
            roots.push((canonical.selector_value, item));
        }
        roots.sort_by(|left, right| left.0.as_bytes().cmp(right.0.as_bytes()));
        let roots = roots.into_iter().map(|(_, item)| item).collect();
        Ok(Self { history, roots })
    }

    pub fn history(&self) -> &arkret::DeviceAuthorizationHistory {
        &self.history
    }

    pub fn roots(&self) -> &[GovernanceDependency] {
        &self.roots
    }
}
/// Local presentation/activity fields. Protocol authorization is deliberately
/// absent: only authenticated history may install it.
#[derive(Clone, Debug)]
pub struct DeviceInventoryMetadata {
    pub actor: String,
    pub device_id: String,
    pub display_name: Option<String>,
    pub last_seen_at: Option<chrono::DateTime<Utc>>,
    pub last_key_upload_at: Option<chrono::DateTime<Utc>>,
    pub updated_at: chrono::DateTime<Utc>,
}

/// Trait for durable device inventory operations.
#[async_trait]
pub trait DeviceInventoryStore: Send + Sync {
    /// Legacy fixture helper for storage tests that predate portable Control
    /// roots. Production code must install a [`ConfirmedDeviceControlProjection`]
    /// through the atomic Seal commit boundary instead.
    #[doc(hidden)]
    async fn seed_test_confirmed_history_without_control_roots(
        &self,
        history: &arkret::DeviceAuthorizationHistory,
    ) -> PersistenceResult<()>;
    async fn get(
        &self,
        actor: &str,
        device_id: &str,
    ) -> PersistenceResult<Option<DeviceInventoryRecord>>;
    async fn put_metadata(&self, record: &DeviceInventoryMetadata) -> PersistenceResult<()>;
    async fn revoke_actor(
        &self,
        actor: &str,
        revoked_at: chrono::DateTime<Utc>,
    ) -> PersistenceResult<usize>;
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    async fn seed_test_record(&self, record: &DeviceInventoryRecord) -> PersistenceResult<()>;
    /// Insert a placeholder only when the actor/device row does not exist.
    ///
    /// Account registration is idempotent and may be replayed after an
    /// `ak.device.authorize` projection has already verified the device.  A
    /// placeholder write must never overwrite that authoritative projection.
    async fn put_if_absent(&self, record: &DeviceInventoryRecord) -> PersistenceResult<bool>;
    async fn list_for_actor(&self, actor: &str) -> PersistenceResult<Vec<DeviceInventoryRecord>>;
    async fn list_for_actor_including_revoked(
        &self,
        actor: &str,
    ) -> PersistenceResult<Vec<DeviceInventoryRecord>>;
    async fn list(&self) -> PersistenceResult<Vec<DeviceInventoryRecord>>;
}
/// To-device message queue + idempotency-key set.
#[async_trait]
pub trait DeviceMessageStore: Send + Sync {
    async fn append(
        &self,
        device_revocation_gate: Option<&DeviceRevocationGateSelector>,
        message: DeviceMessageRecord,
    ) -> PersistenceResult<()>;
    /// Read current request/message idempotency state before dynamic device-policy checks. The
    /// subsequent commit rechecks the same records atomically to close inspection races.
    async fn inspect_batch(
        &self,
        request_key: &str,
        request_digest: &str,
        items: &[DeviceMessageIntentRecord],
    ) -> PersistenceResult<DeviceMessageBatchInspection>;
    /// Atomically bind request- and message-level idempotency records and enqueue only fresh
    /// logical messages.
    async fn commit_batch(
        &self,
        batch: DeviceMessageBatchRecord,
    ) -> PersistenceResult<DeviceMessageBatchCommitOutcome>;
    /// Issue a bearer ack token for the delivered high-water queue position.
    async fn issue_ack_token(
        &self,
        recipient: &str,
        device_id: &str,
        queue_position: i64,
    ) -> PersistenceResult<Option<String>>;
    /// Consume a bearer ack token and prune the messages it covers. Returns
    /// `None` when the token is unknown, expired, or not bound to this device.
    async fn ack_with_token(
        &self,
        recipient: &str,
        device_id: &str,
        ack_token: &str,
    ) -> PersistenceResult<Option<usize>>;
    /// List queued messages for a device strictly after `queue_position`.
    async fn list_after(
        &self,
        recipient: &str,
        device_id: &str,
        queue_position: i64,
        limit: usize,
    ) -> PersistenceResult<Vec<DeviceMessageRecord>>;
    /// Prune expired unacked messages and record the highest lost queue position per device.
    async fn prune_expired(&self, now: chrono::DateTime<Utc>) -> PersistenceResult<usize>;
    /// Prune older unacked messages beyond a per-device capacity, recording lost positions.
    async fn prune_over_capacity(
        &self,
        per_device_capacity: usize,
        now: chrono::DateTime<Utc>,
    ) -> PersistenceResult<usize>;
    /// Highest queue position known lost for this device due to TTL/capacity eviction.
    async fn lost_watermark(
        &self,
        recipient: &str,
        device_id: &str,
    ) -> PersistenceResult<Option<i64>>;
    /// Drop everything queued for the recipient+device (used on session revoke).
    async fn purge(&self, recipient: &str, device_id: &str) -> PersistenceResult<usize>;
}
/// Long-term device key bundles (one per `(actor, device_id)`).
#[async_trait]
pub trait DeviceKeyStore: Send + Sync {
    async fn put(
        &self,
        authorization: &DeviceRevocationGateSelector,
        payload: Value,
    ) -> PersistenceResult<()>;
    async fn get(&self, actor: &str, device_id: &str) -> PersistenceResult<Option<Value>>;
}
/// One-time prekey pool. Calls to `claim` pop a single key.
#[async_trait]
pub trait OneTimeKeyStore: Send + Sync {
    async fn put(
        &self,
        authorization: &DeviceRevocationGateSelector,
        keys: Vec<Value>,
    ) -> PersistenceResult<()>;
    async fn claim(&self, actor: &str, device_id: &str) -> PersistenceResult<Option<Value>>;
}
#[derive(Clone)]
#[doc(hidden)]
pub struct DeviceMessageAckTokenRecord {
    pub recipient: String,
    pub device_id: String,
    pub queue_position: i64,
    pub expires_at: chrono::DateTime<Utc>,
    pub consumed_at: Option<chrono::DateTime<Utc>>,
}
#[doc(hidden)]
pub fn fresh_device_message_ack_token() -> String {
    let mut bytes = Vec::with_capacity(32);
    bytes.extend_from_slice(Uuid::new_v4().as_bytes());
    bytes.extend_from_slice(Uuid::new_v4().as_bytes());
    URL_SAFE_NO_PAD.encode(bytes)
}
#[doc(hidden)]
pub fn ensure_device_message_id(message: &mut DeviceMessageRecord) {
    if let Some(content) = message.content.as_object_mut()
        && !content.contains_key("device_message_id")
    {
        content.insert(
            "device_message_id".to_owned(),
            Value::String(crate::ids::generate("device_message")),
        );
    }
}
