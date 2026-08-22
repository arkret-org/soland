//! Durable owner-side route handover audience reconciliation.
//!
//! Projection and plan notifications only reduce latency. Every pass reads the
//! durable active plan and a fresh accepted projection snapshot, and the
//! periodic tick repairs missed notifications and process restarts.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use soland_services::service_route_handover::ServiceRouteAudienceReconcilePass;

use crate::state::{AppState, service_route_handover_planner};

const RECONCILE_INTERVAL: Duration = Duration::from_secs(30);

#[async_trait]
trait ReconcileRunner: Send + Sync {
    async fn reconcile(
        &self,
        now: DateTime<Utc>,
    ) -> Result<ServiceRouteAudienceReconcilePass, String>;
}

struct AppStateReconcileRunner {
    state: AppState,
}

#[async_trait]
impl ReconcileRunner for AppStateReconcileRunner {
    async fn reconcile(
        &self,
        now: DateTime<Utc>,
    ) -> Result<ServiceRouteAudienceReconcilePass, String> {
        let planner =
            service_route_handover_planner(&self.state).map_err(|error| error.to_string())?;
        let projection = self.state.projections().snapshot();
        planner
            .reconcile_active_audience(&projection, now)
            .await
            .map_err(|error| error.to_string())
    }
}

/// Periodic durable reconciler with lossy projection and plan wakeups.
pub struct Worker {
    runner: Arc<dyn ReconcileRunner>,
    wakeup: Arc<tokio::sync::Notify>,
    interval: Duration,
}

impl Worker {
    pub fn new(state: AppState) -> Self {
        Self {
            runner: Arc::new(AppStateReconcileRunner {
                state: state.clone(),
            }),
            wakeup: state.service_route_handover_wakeup(),
            interval: RECONCILE_INTERVAL,
        }
    }

    async fn run_once(&self) {
        match self.runner.reconcile(Utc::now()).await {
            Ok(ServiceRouteAudienceReconcilePass::Reconciled {
                handover_id,
                required,
                removed,
            }) => {
                tracing::debug!(
                    %handover_id,
                    required,
                    removed,
                    worker = "service_route_handover_audience",
                    "reconciled durable service route handover audience"
                );
            }
            Ok(
                ServiceRouteAudienceReconcilePass::NoActivePlan
                | ServiceRouteAudienceReconcilePass::InactiveLifecycle { .. }
                | ServiceRouteAudienceReconcilePass::GraceEnded { .. },
            ) => {}
            Err(error) => {
                tracing::warn!(
                    %error,
                    worker = "service_route_handover_audience",
                    "service route handover audience reconciliation failed"
                );
            }
        }
    }

    /// Spawn the process-lifetime reconciliation loop.
    pub fn spawn(self) -> Arc<tokio::task::JoinHandle<()>> {
        Arc::new(tokio::spawn(async move {
            let mut ticker = tokio::time::interval(self.interval);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tokio::select! {
                    _ = ticker.tick() => {}
                    _ = self.wakeup.notified() => {}
                }
                self.run_once().await;
            }
        }))
    }
}

/// Start the owner-side audience reconciler.
#[must_use]
pub fn spawn(state: AppState) -> Arc<tokio::task::JoinHandle<()>> {
    Worker::new(state).spawn()
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    struct CountingRunner {
        calls: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl ReconcileRunner for CountingRunner {
        async fn reconcile(
            &self,
            _now: DateTime<Utc>,
        ) -> Result<ServiceRouteAudienceReconcilePass, String> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(ServiceRouteAudienceReconcilePass::NoActivePlan)
        }
    }

    fn worker(interval: Duration) -> (Worker, Arc<AtomicUsize>, Arc<tokio::sync::Notify>) {
        let calls = Arc::new(AtomicUsize::new(0));
        let wakeup = Arc::new(tokio::sync::Notify::new());
        (
            Worker {
                runner: Arc::new(CountingRunner {
                    calls: calls.clone(),
                }),
                wakeup: wakeup.clone(),
                interval,
            },
            calls,
            wakeup,
        )
    }

    async fn wait_for_calls(calls: &AtomicUsize, expected: usize) {
        tokio::time::timeout(Duration::from_secs(1), async {
            while calls.load(Ordering::SeqCst) < expected {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("worker did not reconcile before the test deadline");
    }

    #[tokio::test]
    async fn plan_or_projection_changes_wake_the_worker() {
        let (worker, calls, wakeup) = worker(Duration::from_secs(3600));
        let handle = worker.spawn();
        wait_for_calls(&calls, 1).await;

        wakeup.notify_one();
        wait_for_calls(&calls, 2).await;
        handle.abort();
    }

    #[tokio::test]
    async fn periodic_tick_repairs_missed_wakeups() {
        let (worker, calls, ..) = worker(Duration::from_millis(10));
        let handle = worker.spawn();
        wait_for_calls(&calls, 2).await;
        handle.abort();
    }
}
