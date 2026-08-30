use arkret_wire::AccountId;

use super::{
    AccountDataCasResult, AccountDataRecord, AccountLifecycleRecord, AccountLocalpartRecord,
    AccountPk, AccountRecord, PersistenceResult, async_trait,
};
/// Trait for account storage operations.
#[async_trait]
pub trait AccountStore: Send + Sync {
    async fn get(&self, account_id: &AccountId) -> PersistenceResult<Option<AccountRecord>>;
    async fn get_by_pk(&self, account_pk: AccountPk) -> PersistenceResult<Option<AccountRecord>>;
    async fn put(&self, record: &AccountRecord) -> PersistenceResult<AccountPk>;
    async fn list(&self) -> PersistenceResult<Vec<AccountRecord>>;
    async fn delete(&self, account_id: &AccountId) -> PersistenceResult<()>;
}
#[async_trait]
pub trait AccountLocalpartStore: Send + Sync {
    async fn list_for_account(
        &self,
        account_pk: AccountPk,
    ) -> PersistenceResult<Vec<AccountLocalpartRecord>>;
    async fn primary_for_account(
        &self,
        account_pk: AccountPk,
    ) -> PersistenceResult<Option<AccountLocalpartRecord>>;
    async fn owner_of(&self, localpart: &str) -> PersistenceResult<Option<AccountLocalpartRecord>>;
    async fn add(
        &self,
        account_pk: AccountPk,
        localpart: &str,
        primary: bool,
    ) -> PersistenceResult<AccountLocalpartRecord>;
    async fn set_primary(
        &self,
        account_pk: AccountPk,
        localpart: &str,
    ) -> PersistenceResult<AccountLocalpartRecord>;
    async fn remove(&self, account_pk: AccountPk, localpart: &str) -> PersistenceResult<()>;
    async fn clear_for_account(&self, account_pk: AccountPk) -> PersistenceResult<()>;
}
#[async_trait]
pub trait AccountLifecycleStore: Send + Sync {
    async fn put(
        &self,
        account_pk: AccountPk,
        record: &AccountLifecycleRecord,
    ) -> PersistenceResult<()>;
    async fn delete(&self, account_pk: AccountPk) -> PersistenceResult<()>;
    async fn snapshot_all(&self) -> PersistenceResult<Vec<(AccountId, AccountLifecycleRecord)>>;
}
/// Trait for actor-private account data storage.
///
/// `account_data_key` is the canonical wire key (e.g. `ak.contacts.actor.<did>`,
/// `ak.contacts.realm.<realm_id>`, `ak.read_receipt.preferences`). The
/// payload is opaque to the server — no schema validation runs here; the
/// client owns canonical encoding and (where applicable) encryption.
///
/// Spec: `discovery/client-preferences.md` §2 (storage model), §3.6
/// (actor remarks), §3.7 (Realm remarks).
#[async_trait]
pub trait AccountDataStore: Send + Sync {
    async fn get(
        &self,
        actor: &str,
        account_data_key: &str,
    ) -> PersistenceResult<Option<AccountDataRecord>>;
    /// Atomically replace the whole value when the stored revision equals
    /// `expected_revision`. An absent key has revision 0.
    async fn compare_and_set(
        &self,
        record: &AccountDataRecord,
        expected_revision: u64,
    ) -> PersistenceResult<AccountDataCasResult>;
    async fn list_for_actor(&self, actor: &str) -> PersistenceResult<Vec<AccountDataRecord>>;
}
#[doc(hidden)]
pub fn account_with_primary_localpart_select(where_clause: &str) -> String {
    format!(
        "SELECT a.pk, a.principal_id, a.principal_server_id, COALESCE(lp.localpart, '') AS localpart, \
         a.display_name, a.payload, a.created_at \
         FROM accounts a \
         LEFT JOIN LATERAL ( \
             SELECT localpart FROM account_localparts \
             WHERE account_pk = a.pk \
             ORDER BY is_primary DESC, created_at ASC, localpart ASC \
             LIMIT 1 \
         ) lp ON true \
         {where_clause}"
    )
}
