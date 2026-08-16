use crate::{PersistenceResult, async_trait};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountStatusAuthorityBindingFloor {
    pub account_authority_id: String,
    pub account_id: String,
    pub binding_version: u64,
    pub issuer_service_id: String,
    pub principal_control_realm_id: String,
    pub principal_id: String,
}

impl AccountStatusAuthorityBindingFloor {
    pub fn same_binding_tuple(&self, other: &Self) -> bool {
        self.account_authority_id == other.account_authority_id
            && self.account_id == other.account_id
            && self.issuer_service_id == other.issuer_service_id
            && self.principal_control_realm_id == other.principal_control_realm_id
            && self.principal_id == other.principal_id
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AccountStatusAuthorityBindingAdvance {
    Advanced,
    Replay,
    Rollback,
    Fork,
}

#[async_trait]
pub trait AccountStatusAuthorityBindingStore: Send + Sync {
    async fn advance(
        &self,
        candidate: AccountStatusAuthorityBindingFloor,
    ) -> PersistenceResult<AccountStatusAuthorityBindingAdvance>;
}
