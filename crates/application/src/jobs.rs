use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};

use crate::ApplicationResult;

#[async_trait]
pub trait MaintenancePort: Send + Sync {
    async fn prune_expired_idempotency(&self, now: DateTime<Utc>) -> ApplicationResult<usize>;
}

#[derive(Clone)]
pub struct JobsApplicationService {
    maintenance: Arc<dyn MaintenancePort>,
}

impl JobsApplicationService {
    pub fn new(maintenance: Arc<dyn MaintenancePort>) -> Self {
        Self { maintenance }
    }

    pub async fn prune_expired_idempotency(&self, now: DateTime<Utc>) -> ApplicationResult<usize> {
        self.maintenance.prune_expired_idempotency(now).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct StaticMaintenance;

    #[async_trait]
    impl MaintenancePort for StaticMaintenance {
        async fn prune_expired_idempotency(&self, _now: DateTime<Utc>) -> ApplicationResult<usize> {
            Ok(3)
        }
    }

    #[tokio::test]
    async fn maintenance_step_is_independent_from_the_scheduler() {
        let service = JobsApplicationService::new(Arc::new(StaticMaintenance));
        assert_eq!(
            service
                .prune_expired_idempotency(Utc::now())
                .await
                .expect("prune idempotency"),
            3
        );
    }
}
