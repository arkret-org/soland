use std::sync::Arc;

use async_trait::async_trait;
use serde_json::Value;

use crate::ApplicationResult;

#[derive(Clone, Debug)]
pub struct AppendAuditEntryCommand {
    pub entry: Value,
}

#[async_trait]
pub trait AuditLogPort: Send + Sync {
    async fn append(&self, entry: Value) -> ApplicationResult<()>;
    async fn entries(&self) -> ApplicationResult<Vec<Value>>;
    async fn entries_for_actor(&self, actor_id: &str) -> ApplicationResult<Vec<Value>>;
}

#[derive(Clone)]
pub struct GovernanceApplicationService {
    audit_log: Arc<dyn AuditLogPort>,
}

impl GovernanceApplicationService {
    pub fn new(audit_log: Arc<dyn AuditLogPort>) -> Self {
        Self { audit_log }
    }

    pub async fn append_audit_entry(
        &self,
        command: AppendAuditEntryCommand,
    ) -> ApplicationResult<()> {
        self.audit_log.append(command.entry).await
    }

    pub async fn audit_entries_for_actor(&self, actor_id: &str) -> ApplicationResult<Vec<Value>> {
        self.audit_log.entries_for_actor(actor_id).await
    }

    pub async fn audit_entries(&self) -> ApplicationResult<Vec<Value>> {
        self.audit_log.entries().await
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    #[derive(Default)]
    struct RecordingAuditLog(Mutex<Vec<Value>>);

    #[async_trait]
    impl AuditLogPort for RecordingAuditLog {
        async fn append(&self, entry: Value) -> ApplicationResult<()> {
            self.0.lock().expect("audit lock").push(entry);
            Ok(())
        }

        async fn entries(&self) -> ApplicationResult<Vec<Value>> {
            Ok(self.0.lock().expect("audit lock").clone())
        }

        async fn entries_for_actor(&self, _actor_id: &str) -> ApplicationResult<Vec<Value>> {
            Ok(self.0.lock().expect("audit lock").clone())
        }
    }

    #[tokio::test]
    async fn audit_append_uses_only_the_audit_port() {
        let port = Arc::new(RecordingAuditLog::default());
        let service = GovernanceApplicationService::new(port.clone());
        service
            .append_audit_entry(AppendAuditEntryCommand {
                entry: serde_json::json!({"audit_id": "ak:audit:test"}),
            })
            .await
            .expect("append audit entry");
        assert_eq!(port.0.lock().expect("audit lock").len(), 1);
        assert_eq!(
            service
                .audit_entries()
                .await
                .expect("list audit entries")
                .len(),
            1
        );
    }
}
