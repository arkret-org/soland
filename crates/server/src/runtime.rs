use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use futures_util::future::poll_fn;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use soland_http::config::AppConfig;
use soland_http::state::{
    AppState, AppStateRuntime, EventBroadcast, EventNotification, EventNotificationRelay,
};
use soland_services::events::ProjectedOperationPersistencePort;
use soland_services::governance::RuntimeSettingsPort;
use soland_services::jobs::RuntimeHealthPort;
use soland_services::persistence::PersistenceHandle;
use soland_services::projection::EventSealCommitPort;
use soland_storage_postgres::{Db, PgPool};
use tokio::sync::mpsc;
use tokio_postgres::{AsyncMessage, NoTls};

use crate::object_storage::build_object_storage;

const EVENT_NOTIFICATION_CHANNEL: &str = "soland_event_notifications";

pub fn build_app_state(
    config: AppConfig,
    db: Db,
    persistence: PersistenceHandle,
    service_identity: arkret_identity::service_identity::DidCoreIdentityState,
    service_resolution_commitment: arkret_models_identity::ResolutionCommitment,
    resolved_signing_seed: [u8; 32],
) -> anyhow::Result<AppState> {
    let cell_registry = soland_services::projection::ProjectionService::try_sdk_cell_registry()
        .map_err(|error| {
            anyhow::anyhow!("canonical shared FSM registry failed startup validation: {error}")
        })?;
    let stores =
        soland_storage_postgres::build_state_resolution_stores(db.pool.clone(), cell_registry);
    let service_id = service_identity
        .identity()
        .ok_or_else(|| anyhow::anyhow!("runtime requires a serving service identity"))?
        .service_id
        .to_string();
    let projections = soland_services::projection::ProjectionService::new(
        stores.control_event_store,
        stores.seal_store,
        stores.cell_store,
        stores.cell_registry,
        Arc::new(RuntimeEventSealCommitter(stores.event_seal_committer)),
        &service_id,
    );
    let realm_directory = soland_http::state::build_realm_directory(&config);
    let object_storage = build_object_storage(&config.object_storage)?;
    // `AppConfig::from_env_and_args` already resolved `DATABASE_URL`, and it
    // dropped a blank value to `None`. Re-reading the environment here only
    // reintroduced the blank case as `Some("")`.
    let event_broadcast = event_broadcast(db.pool.clone(), config.database_url.clone(), 1024);
    let storage_mode = db.mode();
    let pool = db.pool.clone();

    Ok(AppState::from_runtime(
        config,
        AppStateRuntime {
            persistence,
            projections,
            realm_directory,
            projected_operation_persistence: Arc::new(RuntimeProjectedOperationPersistence(
                pool.clone(),
            )),
            object_storage,
            settings_persistence: Arc::new(RuntimeSettingsPersistence { pool: pool.clone() }),
            runtime_health: Arc::new(RuntimeDatabaseHealth(db)),
            event_broadcast,
            storage_mode,
        },
        service_identity,
        service_resolution_commitment,
        resolved_signing_seed,
    ))
}

struct RuntimeSettingsPersistence {
    pool: Option<PgPool>,
}

struct RuntimeDatabaseHealth(Db);
struct RuntimeEventSealCommitter(Arc<dyn soland_storage_postgres::EventSealCommitStore>);
struct RuntimeProjectedOperationPersistence(Option<PgPool>);

impl EventSealCommitPort for RuntimeEventSealCommitter {
    fn commit_if_frontier(
        &self,
        seal: &arkret_wire::Seal,
        expected_store_frontier: &[arkret_wire::SealId],
        new_ops: &[(
            arkret_identifiers::CellRef,
            arkret_state::lattice::ordered_log::IssuedOp,
        )],
        covered: &BTreeSet<arkret_wire::Hash>,
    ) -> arkret_state::state::StoreResult<bool> {
        self.0
            .commit_if_frontier(seal, expected_store_frontier, new_ops, covered)
    }
}

#[async_trait::async_trait]
impl RuntimeSettingsPort for RuntimeSettingsPersistence {
    async fn load_overrides(&self) -> soland_services::ServiceResult<Vec<(String, Value)>> {
        let Some(pool) = self.pool.as_ref() else {
            return Ok(Vec::new());
        };
        soland_storage_postgres::load_settings_overrides(pool)
            .await
            .map_err(Into::into)
    }

    async fn store_override(
        &self,
        key: &str,
        value: &Value,
        updated_by: &str,
    ) -> soland_services::ServiceResult<()> {
        let Some(pool) = self.pool.as_ref() else {
            return Ok(());
        };
        soland_storage_postgres::store_settings_override(pool, key, value, updated_by)
            .await
            .map_err(Into::into)
    }
}

#[async_trait::async_trait]
impl RuntimeHealthPort for RuntimeDatabaseHealth {
    async fn database_ready(&self) -> bool {
        soland_storage_postgres::database_ready(self.0.pool.as_ref()).await
    }

    fn storage_mode(&self) -> &'static str {
        self.0.mode()
    }

    fn migrations_applied(&self) -> bool {
        self.0.migrations_applied()
    }

    fn database_configured(&self) -> bool {
        self.0.pool.is_some()
    }

    fn database_pool_in_use(&self) -> u32 {
        self.0.pool_in_use()
    }
}

#[async_trait::async_trait]
impl ProjectedOperationPersistencePort for RuntimeProjectedOperationPersistence {
    async fn persist_projected_operation(
        &self,
        origin: &str,
        operation: &arkret_event_draft::ProjectedEventOperation,
        event_type: &str,
        is_membership_or_realm_lifecycle: bool,
    ) -> Result<(), String> {
        let Some(pool) = self.0.as_ref() else {
            return Ok(());
        };
        soland_storage_postgres::persist_projected_operation_to_pg(
            pool,
            origin,
            operation,
            event_type,
            is_membership_or_realm_lifecycle,
        )
        .await
        .map_err(|error| error.to_string())
    }
}

fn event_broadcast(
    pool: Option<PgPool>,
    database_url: Option<String>,
    capacity: usize,
) -> EventBroadcast {
    let Some((pool, database_url)) =
        pool.zip(database_url.filter(|value| !value.trim().is_empty()))
    else {
        return EventBroadcast::new(capacity);
    };
    EventBroadcast::new_with_relay(capacity, move |local| {
        PgEventNotificationRelay::start(pool, database_url, local, capacity)
    })
}

struct PgEventNotificationRelay {
    relay_tx: mpsc::Sender<EventNotification>,
}

#[derive(Clone)]
struct PgEventNotificationWorker {
    pool: PgPool,
    database_url: String,
    origin: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct PgEventNotificationEnvelope {
    origin: String,
    notification: EventNotification,
}

impl PgEventNotificationRelay {
    fn start(
        pool: PgPool,
        database_url: String,
        local: EventBroadcast,
        capacity: usize,
    ) -> Arc<dyn EventNotificationRelay> {
        let worker = Arc::new(PgEventNotificationWorker {
            pool,
            database_url,
            origin: uuid::Uuid::now_v7().to_string(),
        });
        let (relay_tx, mut relay_rx) = mpsc::channel(capacity.max(1));
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            let listener = worker.clone();
            handle.spawn(async move {
                listener.listen_forever(local).await;
            });
            handle.spawn(async move {
                while let Some(notification) = relay_rx.recv().await {
                    if let Err(error) = worker.publish(notification).await {
                        tracing::warn!(%error, "failed to publish event notification over PostgreSQL");
                    }
                }
            });
        }
        Arc::new(Self { relay_tx })
    }
}

impl EventNotificationRelay for PgEventNotificationRelay {
    fn publish(&self, notification: EventNotification) {
        match self.relay_tx.try_send(notification) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(_)) => {
                tracing::warn!("PostgreSQL event notification queue is full");
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                tracing::warn!("PostgreSQL event notification publisher stopped");
            }
        }
    }
}

impl PgEventNotificationWorker {
    async fn publish(&self, notification: EventNotification) -> anyhow::Result<()> {
        let payload = serde_json::to_string(&PgEventNotificationEnvelope {
            origin: self.origin.clone(),
            notification,
        })?;
        soland_storage_postgres::publish_event_notification(&self.pool, &payload).await
    }

    async fn listen_forever(self: Arc<Self>, local: EventBroadcast) {
        loop {
            if let Err(error) = self.listen_once(&local).await {
                tracing::warn!(%error, "PostgreSQL event notification listener stopped");
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }

    async fn listen_once(&self, local: &EventBroadcast) -> anyhow::Result<()> {
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
                    let Ok(envelope) =
                        serde_json::from_str::<PgEventNotificationEnvelope>(notification.payload())
                    else {
                        tracing::warn!("ignored malformed PostgreSQL event notification payload");
                        continue;
                    };
                    if envelope.origin != self.origin {
                        let _ = local.send_local(envelope.notification);
                    }
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
