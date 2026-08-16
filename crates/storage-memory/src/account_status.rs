use soland_storage::{
    AccountStatusAuthorityBindingAdvance, AccountStatusAuthorityBindingFloor,
    AccountStatusAuthorityBindingStore, PersistenceResult,
};

use crate::{BTreeMap, Mutex, async_trait};

#[derive(Default)]
pub struct MemoryAccountStatusAuthorityBindingStore {
    floors: Mutex<BTreeMap<(String, String), AccountStatusAuthorityBindingFloor>>,
}

impl MemoryAccountStatusAuthorityBindingStore {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl AccountStatusAuthorityBindingStore for MemoryAccountStatusAuthorityBindingStore {
    async fn advance(
        &self,
        candidate: AccountStatusAuthorityBindingFloor,
    ) -> PersistenceResult<AccountStatusAuthorityBindingAdvance> {
        let key = (
            candidate.account_authority_id.clone(),
            candidate.account_id.clone(),
        );
        let mut floors = self.floors.lock();
        let Some(current) = floors.get(&key) else {
            floors.insert(key, candidate);
            return Ok(AccountStatusAuthorityBindingAdvance::Advanced);
        };
        if candidate.binding_version < current.binding_version {
            return Ok(AccountStatusAuthorityBindingAdvance::Rollback);
        }
        if candidate.binding_version == current.binding_version {
            return Ok(if candidate.same_binding_tuple(current) {
                AccountStatusAuthorityBindingAdvance::Replay
            } else {
                AccountStatusAuthorityBindingAdvance::Fork
            });
        }
        floors.insert(key, candidate);
        Ok(AccountStatusAuthorityBindingAdvance::Advanced)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn floor(version: u64, issuer: &str) -> AccountStatusAuthorityBindingFloor {
        AccountStatusAuthorityBindingFloor {
            account_authority_id: "ak:did_core:web:authority.example".to_owned(),
            account_id: "account-1".to_owned(),
            binding_version: version,
            issuer_service_id: issuer.to_owned(),
            principal_control_realm_id: "ak:realm:ARQRpvtCGBgQfVQzTK4_Hgbg0D0HSnc3gPCvXOQUICir"
                .to_owned(),
            principal_id: "ak:did_core:web:alice.example".to_owned(),
        }
    }

    #[tokio::test]
    async fn binding_floor_accepts_reissue_and_advance_but_rejects_rollback_and_fork() {
        let store = MemoryAccountStatusAuthorityBindingStore::new();
        assert_eq!(
            store
                .advance(floor(1, "ak:did_core:web:issuer.example"))
                .await
                .unwrap(),
            AccountStatusAuthorityBindingAdvance::Advanced
        );
        assert_eq!(
            store
                .advance(floor(1, "ak:did_core:web:issuer.example"))
                .await
                .unwrap(),
            AccountStatusAuthorityBindingAdvance::Replay
        );
        assert_eq!(
            store
                .advance(floor(1, "ak:did_core:web:fork.example"))
                .await
                .unwrap(),
            AccountStatusAuthorityBindingAdvance::Fork
        );
        assert_eq!(
            store
                .advance(floor(2, "ak:did_core:web:issuer.example"))
                .await
                .unwrap(),
            AccountStatusAuthorityBindingAdvance::Advanced
        );
        assert_eq!(
            store
                .advance(floor(1, "ak:did_core:web:issuer.example"))
                .await
                .unwrap(),
            AccountStatusAuthorityBindingAdvance::Rollback
        );
    }
}
