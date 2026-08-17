use arkret_models_collaboration::account_lifecycle::{AccountStatusReceipt, AccountStatusRecord};

use crate::{PersistenceResult, async_trait};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccountStatusReplicaConflictKind {
    Fork,
    BindingRollback,
    TransitionInvalid,
    ErasurePendingTerminal,
}

#[derive(Clone, Debug, PartialEq)]
pub enum AccountStatusReplicaAppend {
    Accepted(AccountStatusReceipt),
    Duplicate(AccountStatusReceipt),
    DependencyMissing {
        current_record: Option<AccountStatusRecord>,
        required_status_seq: u64,
    },
    Stale {
        current_record: AccountStatusRecord,
    },
    Conflict {
        current_record: Option<AccountStatusRecord>,
        kind: AccountStatusReplicaConflictKind,
    },
}

#[async_trait]
pub trait AccountStatusReplicaStore: Send + Sync {
    async fn append(
        &self,
        record: &AccountStatusRecord,
        receipt: &AccountStatusReceipt,
    ) -> PersistenceResult<AccountStatusReplicaAppend>;

    async fn current(
        &self,
        account_authority_id: &str,
        account_id: &str,
    ) -> PersistenceResult<Option<AccountStatusRecord>>;

    async fn resolve(
        &self,
        account_authority_id: &str,
        account_id: &str,
        from_status_seq: u64,
        limit: u16,
    ) -> PersistenceResult<Vec<AccountStatusRecord>>;

    async fn erasure_pending(&self, limit: u16) -> PersistenceResult<Vec<AccountStatusRecord>>;

    async fn receipt(
        &self,
        account_authority_id: &str,
        account_id: &str,
        status_seq: u64,
    ) -> PersistenceResult<Option<AccountStatusReceipt>>;
}
