use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Duration as ChronoDuration, Utc};
use diesel::sql_query;
use diesel::sql_types::Text;
use diesel_async::RunQueryDsl;
use futures_util::future::poll_fn;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::broadcast;
use tokio_postgres::{AsyncMessage, NoTls};

use soland_data::PgPool;

pub(crate) const MAX_SUBSCRIBE_RECONNECT_WINDOW_MS: u64 = 86_400_000;
const EVENT_NOTIFICATION_CHANNEL: &str = "soland_event_notifications";

/// Poison-free mutex for every [`crate::state::AppState`] shared surface.
///
/// `std::sync::Mutex` poisons itself when the holding thread panics: every
/// later `lock()` returns `Err` forever, which turned a single in-critical-
/// section panic into either a process-wide 500 storm or a silent fail-open
/// until restart. `parking_lot::Mutex` has no poisoning: `lock()` returns
/// the guard directly, so admission checks always run (fail-closed) and no
/// caller needs a failure branch.
pub use parking_lot::Mutex;

/// broadcast payload for the
/// [`crate::state::AppState::event_broadcast`] channel. Subscribers filter by
/// `realm_id` first, then dispatch on `kind` to produce the right
/// NDJSON frame.
///
/// added control-frame variants alongside the original `Event`
/// (mid-stream control frames per spec):
///   - `EpochRotation` — emitted when `ck.component.mls.epoch.v1` cell changes (E2EE epoch shift;
///     clients MUST re-fetch keys)
///   - `Frontier` — seal frontier advanced (Snapshot of cursor / state_root after `apply_seal`);
///     clients use this as a resync waypoint
///   - `ResyncRequired` — server detected per-subscriber drift; client MUST drop local cache and
///     re-subscribe with `from=null`
///   - `Unauthorized` — subscriber's session token revoked / expired mid-stream; client MUST close
///   - `Ephemeral` — short-TTL account-sync relay wakeup; events.subscribe ignores it
///     + re-auth
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EventNotification {
    pub realm_id: String,
    pub kind: EventNotificationKind,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum EventNotificationKind {
    /// Ordinary projection event (one `ck.message.create` etc.).
    Event {
        /// Stable cursor for the event — typically the canonical
        /// `event_id`. Clients use as resume position.
        cursor: String,
        /// Projection-event JSON (same shape as `projection_event_json`).
        event_payload: Value,
    },
    /// MLS epoch shift detected on `ck.component.mls.epoch.v1` cell.
    EpochRotation {
        /// Old epoch value (the previous CellState::Value if known).
        previous_epoch: Option<Value>,
        /// New epoch value (current CellState::Value after the
        /// triggering apply_seal).
        new_epoch: Value,
    },
    /// Seal frontier advanced. Emitted post-`apply_seal` so clients
    /// can update their resume cursor without waiting for the next event.
    Frontier {
        /// `apply_seal`'s `post_state_root` (canonical Merkle).
        state_root: String,
        /// The Seal's id, useful for clients tracking Seal DAG.
        seal_id: String,
    },
    /// Per-subscriber drift / corrupted-cursor signal. Clients SHOULD
    /// drop local cache + restart subscription with no `from`.
    ResyncRequired {
        reason: String,
        reconnect_after_ms: Option<u64>,
    },
    /// Session token invalidated mid-stream — client MUST close.
    Unauthorized { reason: String },
    /// Short-TTL account sync wakeup for relayed ephemeral state.
    Ephemeral { kind: String },
}

#[derive(Clone)]
pub struct EventBroadcast {
    local: broadcast::Sender<EventNotification>,
    relay: Option<Arc<PgEventNotificationRelay>>,
}

#[derive(Clone)]
struct PgEventNotificationRelay {
    pool: PgPool,
    database_url: String,
    origin: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct PgEventNotificationEnvelope {
    origin: String,
    notification: EventNotification,
}

impl EventBroadcast {
    pub fn new(pool: Option<PgPool>, database_url: Option<String>, capacity: usize) -> Self {
        let local = broadcast::channel::<EventNotification>(capacity).0;
        let relay = pool
            .zip(database_url.filter(|value| !value.trim().is_empty()))
            .map(|(pool, database_url)| {
                Arc::new(PgEventNotificationRelay {
                    pool,
                    database_url,
                    origin: uuid::Uuid::now_v7().to_string(),
                })
            });
        if let Some(relay) = relay.clone()
            && let Ok(handle) = tokio::runtime::Handle::try_current()
        {
            let local_for_listener = local.clone();
            handle.spawn(async move {
                relay.listen_forever(local_for_listener).await;
            });
        }
        Self { local, relay }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<EventNotification> {
        self.local.subscribe()
    }

    pub fn send(
        &self,
        notification: EventNotification,
    ) -> Result<usize, broadcast::error::SendError<EventNotification>> {
        let local_result = self.local.send(notification.clone());
        if let Some(relay) = self.relay.clone()
            && let Ok(handle) = tokio::runtime::Handle::try_current()
        {
            handle.spawn(async move {
                if let Err(error) = relay.publish(notification).await {
                    tracing::warn!(%error, "failed to publish event notification over PostgreSQL");
                }
            });
        }
        local_result
    }
}

impl PgEventNotificationRelay {
    async fn publish(&self, notification: EventNotification) -> anyhow::Result<()> {
        let envelope = PgEventNotificationEnvelope {
            origin: self.origin.clone(),
            notification,
        };
        let payload = serde_json::to_string(&envelope)?;
        let mut conn = crate::persistence::pg_conn(&self.pool).await?;
        sql_query("SELECT pg_notify('soland_event_notifications', $1)")
            .bind::<Text, _>(&payload)
            .execute(&mut *conn)
            .await?;
        Ok(())
    }

    async fn listen_forever(self: Arc<Self>, local: broadcast::Sender<EventNotification>) {
        loop {
            if let Err(error) = self.listen_once(local.clone()).await {
                tracing::warn!(%error, "PostgreSQL event notification listener stopped");
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }

    async fn listen_once(&self, local: broadcast::Sender<EventNotification>) -> anyhow::Result<()> {
        let (client, mut connection) = tokio_postgres::connect(&self.database_url, NoTls).await?;
        client
            .batch_execute(&format!("LISTEN {EVENT_NOTIFICATION_CHANNEL}"))
            .await?;
        loop {
            match poll_fn(|cx| connection.poll_message(cx)).await {
                Some(Ok(AsyncMessage::Notification(notification))) => {
                    if notification.channel() != EVENT_NOTIFICATION_CHANNEL {
                        continue;
                    }
                    let envelope =
                        serde_json::from_str::<PgEventNotificationEnvelope>(notification.payload());
                    let Ok(envelope) = envelope else {
                        tracing::warn!("ignored malformed PostgreSQL event notification payload");
                        continue;
                    };
                    if envelope.origin == self.origin {
                        continue;
                    }
                    let _ = local.send(envelope.notification);
                }
                Some(Ok(AsyncMessage::Notice(notice))) => {
                    tracing::debug!(message = %notice.message(), "PostgreSQL listener notice");
                }
                Some(Ok(_)) => {}
                Some(Err(error)) => return Err(error.into()),
                None => return Ok(()),
            }
        }
    }
}

impl EventNotification {
    pub fn event(realm_id: String, cursor: String, event_payload: Value) -> Self {
        Self {
            realm_id,
            kind: EventNotificationKind::Event {
                cursor,
                event_payload,
            },
        }
    }

    pub fn epoch_rotation(
        realm_id: String,
        previous_epoch: Option<Value>,
        new_epoch: Value,
    ) -> Self {
        Self {
            realm_id,
            kind: EventNotificationKind::EpochRotation {
                previous_epoch,
                new_epoch,
            },
        }
    }

    pub fn frontier(realm_id: String, seal_id: String, state_root: String) -> Self {
        Self {
            realm_id,
            kind: EventNotificationKind::Frontier {
                state_root,
                seal_id,
            },
        }
    }

    pub fn ephemeral(realm_id: String, kind: impl Into<String>) -> Self {
        Self {
            realm_id,
            kind: EventNotificationKind::Ephemeral { kind: kind.into() },
        }
    }
}

/// In-process reconnect gate for `ck.self.events.stream.subscribe` and
/// `ck.self.account.stream.subscribe`. Keys are operation + caller identity + selector
/// scope, and values are the earliest accepted reconnect time.
#[derive(Clone, Debug, Default)]
pub struct SubscribeReconnectGate {
    deadlines: BTreeMap<String, DateTime<Utc>>,
}

impl SubscribeReconnectGate {
    pub fn retry_after_ms(&mut self, key: &str, now: DateTime<Utc>) -> Option<u64> {
        self.prune_expired(now);
        let deadline = self.deadlines.get(key)?;
        if *deadline <= now {
            self.deadlines.remove(key);
            return None;
        }
        Some((*deadline - now).num_milliseconds().max(1) as u64)
    }

    pub fn arm(&mut self, key: impl Into<String>, now: DateTime<Utc>, delay_ms: u64) {
        if delay_ms == 0 {
            return;
        }
        let clamped_ms = delay_ms.min(MAX_SUBSCRIBE_RECONNECT_WINDOW_MS) as i64;
        self.deadlines
            .insert(key.into(), now + ChronoDuration::milliseconds(clamped_ms));
        self.prune_expired(now);
    }

    fn prune_expired(&mut self, now: DateTime<Utc>) {
        self.deadlines.retain(|_, deadline| *deadline > now);
    }
}

#[cfg(test)]
mod subscribe_reconnect_gate_tests {
    use super::*;

    #[test]
    fn reports_remaining_window_and_expires() {
        let mut gate = SubscribeReconnectGate::default();
        let now = Utc::now();
        gate.arm("ck.self.events.stream.subscribe|alice|realm-a", now, 10_000);

        let retry_after = gate
            .retry_after_ms(
                "ck.self.events.stream.subscribe|alice|realm-a",
                now + ChronoDuration::milliseconds(2_500),
            )
            .expect("cooldown active");
        assert!((7_400..=7_500).contains(&retry_after));

        assert!(
            gate.retry_after_ms(
                "ck.self.events.stream.subscribe|alice|realm-a",
                now + ChronoDuration::milliseconds(10_000),
            )
            .is_none()
        );
    }
}
