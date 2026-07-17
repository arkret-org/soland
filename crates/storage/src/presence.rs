use super::{CallSignalRelayRecord, PersistenceResult, PresenceRecord, TypingRecord, async_trait};
/// Presence (online/idle/dnd/offline) per (actor, device). Upserts are
/// keyed by the broadcasting device so one actor's devices coexist and
/// the read side can aggregate them per profiles-presence.md §3.3.
#[async_trait]
pub trait PresenceStore: Send + Sync {
    async fn put(&self, presence: PresenceRecord) -> PersistenceResult<()>;
    async fn list_for_actor(&self, actor: &str) -> PersistenceResult<Vec<PresenceRecord>>;
    /// Remove every device row of `actor` (used when the visibility
    /// policy flips to `nobody`).
    async fn delete(&self, actor: &str) -> PersistenceResult<()>;
}
/// Typing indicators per (actor, Realm). Auto-prunes expired entries.
#[async_trait]
pub trait TypingStore: Send + Sync {
    async fn put(&self, typing: TypingRecord) -> PersistenceResult<()>;
    async fn remove(&self, actor: &str, realm_id: &str) -> PersistenceResult<()>;
    async fn list_for_realm(&self, realm_id: &str) -> PersistenceResult<Vec<TypingRecord>>;
    async fn prune_expired(&self) -> PersistenceResult<usize>;
}
/// Realm-broadcast relay for `ak.call.signal` ephemeral envelopes
/// (`webrtc-signaling.md` §5). Stores the verbatim signed envelope per Realm
/// with a TTL; receivers pick it up from the subscribe `ephemeral.events`
/// segment and verify the carried `proof`. Auto-prunes expired entries and
/// caps each Realm to the most recent `CALL_SIGNAL_RELAY_MAX_PER_REALM`.
///
/// Deliver-once: `append` stamps each record with a monotonic per-Realm
/// `position`, and an in-memory per-subscriber-device watermark
/// (`delivered_through` / `advance`) records the highest position already
/// delivered to a `(actor, device, realm)` triple. Incremental re-subscribes
/// inside the TTL window therefore do not re-emit a signal the device already
/// saw, while a full sync still re-delivers all non-expired pending signals so
/// a reconnecting device recovers a pending invite. This mirrors the to_device
/// deliver-once watermark without touching the client-facing sync cursor.
#[async_trait]
pub trait CallSignalRelayStore: Send + Sync {
    async fn append(&self, record: CallSignalRelayRecord) -> PersistenceResult<()>;
    async fn list_for_realm(&self, realm_id: &str)
    -> PersistenceResult<Vec<CallSignalRelayRecord>>;
    async fn prune_expired(&self) -> PersistenceResult<usize>;
    /// Highest per-Realm `position` already delivered to `(actor, device,
    /// realm)`. Returns `0` when nothing has been delivered yet.
    async fn delivered_through(
        &self,
        actor: &str,
        device: &str,
        realm_id: &str,
    ) -> PersistenceResult<u64>;
    /// Advance the `(actor, device, realm)` watermark to `position` (monotonic;
    /// a lower value is ignored).
    async fn advance(
        &self,
        actor: &str,
        device: &str,
        realm_id: &str,
        position: u64,
    ) -> PersistenceResult<()>;
}
/// Per-Realm cap on retained relayed call signals to bound memory growth.
/// Call signals are short-lived (≤5 min ephemeral TTL) so the bound only
/// matters under a burst; the oldest entries are dropped first.
pub const CALL_SIGNAL_RELAY_MAX_PER_REALM: usize = 256;
