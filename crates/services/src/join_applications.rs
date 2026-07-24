use std::sync::Arc;

use soland_storage::PersistenceStore;
pub use soland_storage::{
    JoinApplicationCommand, JoinApplicationCommandOutcome, JoinApplicationMutation,
    JoinApplicationRecord,
};

use crate::ServiceResult;

#[derive(Clone)]
pub struct JoinApplicationService {
    persistence: Arc<dyn PersistenceStore>,
}

impl JoinApplicationService {
    pub(crate) fn new(persistence: Arc<dyn PersistenceStore>) -> Self {
        Self { persistence }
    }

    pub async fn execute(
        &self,
        command: JoinApplicationCommand,
    ) -> ServiceResult<JoinApplicationCommandOutcome> {
        Ok(self
            .persistence
            .join_applications()
            .execute(command)
            .await?)
    }

    pub async fn get(
        &self,
        realm_id: &str,
        application_ref: &str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> ServiceResult<Option<JoinApplicationRecord>> {
        Ok(self
            .persistence
            .join_applications()
            .get(realm_id, application_ref, now)
            .await?)
    }

    pub async fn list(
        &self,
        realm_id: &str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> ServiceResult<Vec<JoinApplicationRecord>> {
        Ok(self
            .persistence
            .join_applications()
            .list(realm_id, now)
            .await?)
    }

    pub async fn append_read_audit(
        &self,
        realm_id: &str,
        application_ref: &str,
        actor_id: &str,
        occurred_at: chrono::DateTime<chrono::Utc>,
    ) -> ServiceResult<()> {
        Ok(self
            .persistence
            .join_applications()
            .append_read_audit(realm_id, application_ref, actor_id, occurred_at)
            .await?)
    }

    pub async fn consume_review_authorisations(
        &self,
        realm_id: &str,
        review_receipt_digests: &[String],
        actor_id: &str,
        occurred_at: chrono::DateTime<chrono::Utc>,
    ) -> ServiceResult<bool> {
        Ok(self
            .persistence
            .join_applications()
            .consume_review_authorisations(realm_id, review_receipt_digests, actor_id, occurred_at)
            .await?)
    }
}
