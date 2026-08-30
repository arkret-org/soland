use arkret_wire::AccountId;

use super::{
    AccountDataCasResult, AccountDataRecord, AccountDataStore, AccountLifecycleRecord,
    AccountLifecycleStore, AccountLocalpartRecord, AccountLocalpartStore, AccountPk, AccountRecord,
    AccountStore, Arc, BTreeMap, Mutex, PersistenceError, PersistenceResult, Utc, async_trait, ids,
};
// In-memory account store
pub(crate) type AccountLocalpartMemory = Arc<Mutex<BTreeMap<String, AccountLocalpartRecord>>>;
pub(crate) struct MemoryAccountStore {
    data: Arc<Mutex<BTreeMap<String, AccountRecord>>>,
    localparts: AccountLocalpartMemory,
}
impl MemoryAccountStore {
    pub(crate) fn new(localparts: AccountLocalpartMemory) -> Self {
        Self {
            data: Arc::new(Mutex::new(BTreeMap::new())),
            localparts,
        }
    }

    /// Insert a constructor-time fixture without requiring an async runtime.
    ///
    /// This is intentionally limited to the in-memory store used by the
    /// development/test harness. Database-backed startup continues to seed
    /// through `AppState::hydrate`, where writes can be awaited normally.
    pub(crate) fn seed(&self, record: AccountRecord) {
        self.data.lock().insert(
            AccountId::new(record.principal_id.clone(), record.station_id.clone()).to_string(),
            record.clone(),
        );

        if record.localpart.trim().is_empty() {
            return;
        }
        self.localparts.lock().insert(
            record.localpart.clone(),
            AccountLocalpartRecord {
                id: ids::generate("account_localpart"),
                account_pk: record.pk,
                localpart: record.localpart,
                is_primary: true,
                created_at: record.created_at,
                updated_at: record.created_at,
            },
        );
    }

    pub(crate) fn shared_data(&self) -> Arc<Mutex<BTreeMap<String, AccountRecord>>> {
        self.data.clone()
    }

    fn primary_localpart_from(
        localparts: &BTreeMap<String, AccountLocalpartRecord>,
        account_pk: AccountPk,
    ) -> String {
        let mut rows: Vec<&AccountLocalpartRecord> = localparts
            .values()
            .filter(|record| record.account_pk == account_pk)
            .collect();
        rows.sort_by(|left, right| {
            right
                .is_primary
                .cmp(&left.is_primary)
                .then(left.created_at.cmp(&right.created_at))
                .then(left.localpart.cmp(&right.localpart))
        });
        rows.as_slice()
            .first()
            .map(|record| record.localpart.clone())
            .unwrap_or_default()
    }

    fn with_current_localpart(&self, mut record: AccountRecord) -> AccountRecord {
        let localparts = self.localparts.lock();
        record.localpart = Self::primary_localpart_from(&localparts, record.pk);
        record
    }
}
#[async_trait]
impl AccountStore for MemoryAccountStore {
    async fn get(&self, account_id: &AccountId) -> PersistenceResult<Option<AccountRecord>> {
        let data = self.data.lock();
        let record = data.get(&account_id.to_string()).cloned();
        drop(data);
        Ok(record.map(|record| self.with_current_localpart(record)))
    }

    async fn get_by_pk(&self, account_pk: AccountPk) -> PersistenceResult<Option<AccountRecord>> {
        let data = self.data.lock();
        let record = data
            .values()
            .find(|record| record.pk == account_pk)
            .cloned();
        drop(data);
        Ok(record.map(|record| self.with_current_localpart(record)))
    }

    async fn put(&self, record: &AccountRecord) -> PersistenceResult<AccountPk> {
        let mut data = self.data.lock();
        let account_pk = if record.pk.get() == 0 {
            AccountPk(
                data.values()
                    .map(|record| record.pk.get())
                    .max()
                    .unwrap_or(0)
                    + 1,
            )
        } else {
            record.pk
        };
        let mut stored = record.clone();
        stored.pk = account_pk;
        data.insert(
            AccountId::new(record.principal_id.clone(), record.station_id.clone()).to_string(),
            stored,
        );
        drop(data);

        let now = Utc::now();
        let mut localparts = self.localparts.lock();
        if record.localpart.trim().is_empty() {
            localparts.retain(|_, localpart| localpart.account_pk != account_pk);
            return Ok(account_pk);
        }
        if localparts
            .get(&record.localpart)
            .is_some_and(|localpart| localpart.account_pk != account_pk)
        {
            return Err(PersistenceError::Conflict(format!(
                "localpart `{}` is already assigned",
                record.localpart
            )));
        }
        for localpart in localparts.values_mut() {
            if localpart.account_pk == account_pk && localpart.localpart != record.localpart {
                localpart.is_primary = false;
                localpart.updated_at = now;
            }
        }
        let existing = localparts.get(&record.localpart).cloned();
        localparts.insert(
            record.localpart.clone(),
            AccountLocalpartRecord {
                id: existing
                    .as_ref()
                    .map(|localpart| localpart.id.clone())
                    .unwrap_or_else(|| ids::generate("account_localpart")),
                account_pk,
                localpart: record.localpart.clone(),
                is_primary: true,
                created_at: existing
                    .as_ref()
                    .map(|localpart| localpart.created_at)
                    .unwrap_or(record.created_at),
                updated_at: now,
            },
        );
        Ok(account_pk)
    }

    async fn list(&self) -> PersistenceResult<Vec<AccountRecord>> {
        let data = self.data.lock();
        let records: Vec<AccountRecord> = data.values().cloned().collect();
        drop(data);
        Ok(records
            .into_iter()
            .map(|record| self.with_current_localpart(record))
            .collect())
    }

    async fn delete(&self, account_id: &AccountId) -> PersistenceResult<()> {
        let mut data = self.data.lock();
        let removed = data.remove(&account_id.to_string());
        drop(data);
        if let Some(removed) = removed {
            self.localparts
                .lock()
                .retain(|_, localpart| localpart.account_pk != removed.pk);
        }
        Ok(())
    }
}
pub(crate) struct MemoryAccountLocalpartStore {
    data: AccountLocalpartMemory,
}
impl MemoryAccountLocalpartStore {
    pub(crate) fn new() -> Self {
        Self {
            data: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }

    pub(crate) fn shared_data(&self) -> AccountLocalpartMemory {
        self.data.clone()
    }
}
#[async_trait]
impl AccountLocalpartStore for MemoryAccountLocalpartStore {
    async fn list_for_account(
        &self,
        account_pk: AccountPk,
    ) -> PersistenceResult<Vec<AccountLocalpartRecord>> {
        let data = self.data.lock();
        let mut rows: Vec<AccountLocalpartRecord> = data
            .values()
            .filter(|record| record.account_pk == account_pk)
            .cloned()
            .collect();
        rows.sort_by(|left, right| {
            right
                .is_primary
                .cmp(&left.is_primary)
                .then(left.localpart.cmp(&right.localpart))
        });
        Ok(rows)
    }

    async fn primary_for_account(
        &self,
        account_pk: AccountPk,
    ) -> PersistenceResult<Option<AccountLocalpartRecord>> {
        Ok(self
            .list_for_account(account_pk)
            .await?
            .into_iter()
            .find(|record| record.is_primary))
    }

    async fn owner_of(&self, localpart: &str) -> PersistenceResult<Option<AccountLocalpartRecord>> {
        let data = self.data.lock();
        Ok(data.get(localpart).cloned())
    }

    async fn add(
        &self,
        account_pk: AccountPk,
        localpart: &str,
        primary: bool,
    ) -> PersistenceResult<AccountLocalpartRecord> {
        let now = Utc::now();
        let mut data = self.data.lock();
        if data
            .get(localpart)
            .is_some_and(|record| record.account_pk != account_pk)
        {
            return Err(PersistenceError::Conflict(format!(
                "localpart `{localpart}` is already assigned"
            )));
        }
        if primary {
            for record in data.values_mut() {
                if record.account_pk == account_pk {
                    record.is_primary = false;
                    record.updated_at = now;
                }
            }
        }
        let existing = data.get(localpart).cloned();
        let record = AccountLocalpartRecord {
            id: existing
                .as_ref()
                .map(|record| record.id.clone())
                .unwrap_or_else(|| ids::generate("account_localpart")),
            account_pk,
            localpart: localpart.to_owned(),
            is_primary: primary || existing.as_ref().is_some_and(|record| record.is_primary),
            created_at: existing
                .as_ref()
                .map(|record| record.created_at)
                .unwrap_or(now),
            updated_at: now,
        };
        data.insert(localpart.to_owned(), record.clone());
        Ok(record)
    }

    async fn set_primary(
        &self,
        account_pk: AccountPk,
        localpart: &str,
    ) -> PersistenceResult<AccountLocalpartRecord> {
        let now = Utc::now();
        let mut data = self.data.lock();
        let owner = data
            .get(localpart)
            .ok_or_else(|| PersistenceError::NotFound("localpart not found".to_owned()))?
            .account_pk;
        if owner != account_pk {
            return Err(PersistenceError::Conflict(format!(
                "localpart `{localpart}` is assigned to another account"
            )));
        }
        for record in data.values_mut() {
            if record.account_pk == account_pk {
                record.is_primary = record.localpart == localpart;
                record.updated_at = now;
            }
        }
        data.get(localpart)
            .cloned()
            .ok_or_else(|| PersistenceError::NotFound("localpart not found".to_owned()))
    }

    async fn remove(&self, account_pk: AccountPk, localpart: &str) -> PersistenceResult<()> {
        let mut data = self.data.lock();
        match data.get(localpart) {
            Some(record) if record.account_pk == account_pk => {
                data.remove(localpart);
                Ok(())
            }
            Some(_) => Err(PersistenceError::Conflict(format!(
                "localpart `{localpart}` is assigned to another account"
            ))),
            None => Ok(()),
        }
    }

    async fn clear_for_account(&self, account_pk: AccountPk) -> PersistenceResult<()> {
        let mut data = self.data.lock();
        data.retain(|_, record| record.account_pk != account_pk);
        Ok(())
    }
}
pub(crate) struct MemoryAccountLifecycleStore {
    data: Arc<Mutex<BTreeMap<AccountPk, AccountLifecycleRecord>>>,
    accounts: Arc<Mutex<BTreeMap<String, AccountRecord>>>,
}
impl MemoryAccountLifecycleStore {
    pub(crate) fn new(accounts: Arc<Mutex<BTreeMap<String, AccountRecord>>>) -> Self {
        Self {
            data: Arc::new(Mutex::new(BTreeMap::new())),
            accounts,
        }
    }
}
#[async_trait]
impl AccountLifecycleStore for MemoryAccountLifecycleStore {
    async fn put(
        &self,
        account_pk: AccountPk,
        record: &AccountLifecycleRecord,
    ) -> PersistenceResult<()> {
        self.data.lock().insert(account_pk, record.clone());
        Ok(())
    }

    async fn delete(&self, account_pk: AccountPk) -> PersistenceResult<()> {
        self.data.lock().remove(&account_pk);
        Ok(())
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<(AccountId, AccountLifecycleRecord)>> {
        let accounts = self.accounts.lock();
        self.data
            .lock()
            .iter()
            .map(|(account_pk, record)| {
                let account = accounts
                    .values()
                    .find(|account| account.pk == *account_pk)
                    .ok_or_else(|| {
                        PersistenceError::NotFound(format!(
                            "account lifecycle owner pk {}",
                            account_pk.get()
                        ))
                    })?;
                Ok((
                    AccountId::new(account.principal_id.clone(), account.station_id.clone()),
                    record.clone(),
                ))
            })
            .collect()
    }
}
// In-memory contact store
/// In-memory `(actor, account_data_key) -> AccountDataRecord` table. Mirrors the
/// `account_datas` Pg table on the same composite key.
pub(crate) struct MemoryAccountDataStore {
    pub(crate) data: Arc<Mutex<BTreeMap<(String, String), AccountDataRecord>>>,
}
impl MemoryAccountDataStore {
    pub(crate) fn new() -> Self {
        Self {
            data: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }
}
#[async_trait]
impl AccountDataStore for MemoryAccountDataStore {
    async fn get(
        &self,
        actor: &str,
        account_data_key: &str,
    ) -> PersistenceResult<Option<AccountDataRecord>> {
        let data = self.data.lock();
        Ok(data
            .get(&(actor.to_owned(), account_data_key.to_owned()))
            .cloned())
    }

    async fn compare_and_set(
        &self,
        record: &AccountDataRecord,
        expected_revision: u64,
    ) -> PersistenceResult<AccountDataCasResult> {
        let mut data = self.data.lock();
        let key = (record.actor.clone(), record.account_data_key.clone());
        let current = data.get(&key);
        let current_revision = current.map_or(0, |value| value.revision);
        if current_revision != expected_revision {
            return Ok(AccountDataCasResult::Conflict(current.cloned()));
        }
        let Some(next_revision) = expected_revision.checked_add(1) else {
            return Err(PersistenceError::Conflict(
                "account_data revision exhausted".to_owned(),
            ));
        };
        if record.revision != next_revision {
            return Err(PersistenceError::Internal(
                "account_data record revision must equal expected_revision + 1".to_owned(),
            ));
        }
        data.insert(key, record.clone());
        Ok(AccountDataCasResult::Applied(record.clone()))
    }

    async fn list_for_actor(&self, actor: &str) -> PersistenceResult<Vec<AccountDataRecord>> {
        let data = self.data.lock();
        Ok(data
            .iter()
            .filter(|((row_actor, _), record)| row_actor == actor && !record.tombstone)
            .map(|(_, record)| record.clone())
            .collect())
    }
}
