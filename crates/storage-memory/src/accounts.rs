use super::{
    AccountDataRecord, AccountDataStore, AccountLifecycleRecord, AccountLifecycleStore,
    AccountLocalpartRecord, AccountLocalpartStore, AccountRecord, AccountStore, Arc, BTreeMap,
    Mutex, PersistenceError, PersistenceResult, Utc, async_trait, ids,
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
        self.data.lock().insert(record.did.clone(), record.clone());

        if record.localpart.trim().is_empty() {
            return;
        }
        self.localparts.lock().insert(
            record.localpart.clone(),
            AccountLocalpartRecord {
                id: ids::generate("account_localpart"),
                account_did: record.did,
                localpart: record.localpart,
                is_primary: true,
                created_at: record.created_at,
                updated_at: record.created_at,
            },
        );
    }

    fn primary_localpart_from(
        localparts: &BTreeMap<String, AccountLocalpartRecord>,
        did: &str,
    ) -> String {
        let mut rows: Vec<&AccountLocalpartRecord> = localparts
            .values()
            .filter(|record| record.account_did == did)
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
        record.localpart = Self::primary_localpart_from(&localparts, &record.did);
        record
    }
}
#[async_trait]
impl AccountStore for MemoryAccountStore {
    async fn get(&self, did: &str) -> PersistenceResult<Option<AccountRecord>> {
        let data = self.data.lock();
        let record = data.get(did).cloned();
        drop(data);
        Ok(record.map(|record| self.with_current_localpart(record)))
    }

    async fn put(&self, record: &AccountRecord) -> PersistenceResult<()> {
        let mut data = self.data.lock();
        data.insert(record.did.clone(), record.clone());
        drop(data);

        let now = Utc::now();
        let mut localparts = self.localparts.lock();
        if record.localpart.trim().is_empty() {
            localparts.retain(|_, localpart| localpart.account_did != record.did);
            return Ok(());
        }
        if localparts
            .get(&record.localpart)
            .is_some_and(|localpart| localpart.account_did != record.did)
        {
            return Err(PersistenceError::Conflict(format!(
                "localpart `{}` is already assigned",
                record.localpart
            )));
        }
        for localpart in localparts.values_mut() {
            if localpart.account_did == record.did && localpart.localpart != record.localpart {
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
                account_did: record.did.clone(),
                localpart: record.localpart.clone(),
                is_primary: true,
                created_at: existing
                    .as_ref()
                    .map(|localpart| localpart.created_at)
                    .unwrap_or(record.created_at),
                updated_at: now,
            },
        );
        Ok(())
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

    async fn delete(&self, did: &str) -> PersistenceResult<()> {
        let mut data = self.data.lock();
        data.remove(did);
        drop(data);
        self.localparts
            .lock()
            .retain(|_, localpart| localpart.account_did != did);
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
        account_did: &str,
    ) -> PersistenceResult<Vec<AccountLocalpartRecord>> {
        let data = self.data.lock();
        let mut rows: Vec<AccountLocalpartRecord> = data
            .values()
            .filter(|record| record.account_did == account_did)
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
        account_did: &str,
    ) -> PersistenceResult<Option<AccountLocalpartRecord>> {
        Ok(self
            .list_for_account(account_did)
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
        account_did: &str,
        localpart: &str,
        primary: bool,
    ) -> PersistenceResult<AccountLocalpartRecord> {
        let now = Utc::now();
        let mut data = self.data.lock();
        if data
            .get(localpart)
            .is_some_and(|record| record.account_did != account_did)
        {
            return Err(PersistenceError::Conflict(format!(
                "localpart `{localpart}` is already assigned"
            )));
        }
        if primary {
            for record in data.values_mut() {
                if record.account_did == account_did {
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
            account_did: account_did.to_owned(),
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
        account_did: &str,
        localpart: &str,
    ) -> PersistenceResult<AccountLocalpartRecord> {
        let now = Utc::now();
        let mut data = self.data.lock();
        let owner = data
            .get(localpart)
            .ok_or_else(|| PersistenceError::NotFound("localpart not found".to_owned()))?
            .account_did
            .clone();
        if owner != account_did {
            return Err(PersistenceError::Conflict(format!(
                "localpart `{localpart}` is assigned to another account"
            )));
        }
        for record in data.values_mut() {
            if record.account_did == account_did {
                record.is_primary = record.localpart == localpart;
                record.updated_at = now;
            }
        }
        data.get(localpart)
            .cloned()
            .ok_or_else(|| PersistenceError::NotFound("localpart not found".to_owned()))
    }

    async fn remove(&self, account_did: &str, localpart: &str) -> PersistenceResult<()> {
        let mut data = self.data.lock();
        match data.get(localpart) {
            Some(record) if record.account_did == account_did => {
                data.remove(localpart);
                Ok(())
            }
            Some(_) => Err(PersistenceError::Conflict(format!(
                "localpart `{localpart}` is assigned to another account"
            ))),
            None => Ok(()),
        }
    }

    async fn clear_for_account(&self, account_did: &str) -> PersistenceResult<()> {
        let mut data = self.data.lock();
        data.retain(|_, record| record.account_did != account_did);
        Ok(())
    }
}
pub(crate) struct MemoryAccountLifecycleStore {
    data: Arc<Mutex<BTreeMap<String, AccountLifecycleRecord>>>,
}
impl MemoryAccountLifecycleStore {
    pub(crate) fn new() -> Self {
        Self {
            data: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }
}
#[async_trait]
impl AccountLifecycleStore for MemoryAccountLifecycleStore {
    async fn put(&self, did: &str, record: &AccountLifecycleRecord) -> PersistenceResult<()> {
        self.data.lock().insert(did.to_owned(), record.clone());
        Ok(())
    }

    async fn delete(&self, did: &str) -> PersistenceResult<()> {
        self.data.lock().remove(did);
        Ok(())
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<(String, AccountLifecycleRecord)>> {
        Ok(self
            .data
            .lock()
            .iter()
            .map(|(did, record)| (did.clone(), record.clone()))
            .collect())
    }
}
// In-memory contact store
/// In-memory `(actor, account_data_key) -> AccountDataRecord` table. Mirrors the
/// `account_datas` Pg table on the same composite key.
pub(crate) struct MemoryAccountDataStore {
    data: Arc<Mutex<BTreeMap<(String, String), AccountDataRecord>>>,
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

    async fn put(&self, record: &AccountDataRecord) -> PersistenceResult<()> {
        let mut data = self.data.lock();
        data.insert(
            (record.actor.clone(), record.account_data_key.clone()),
            record.clone(),
        );
        Ok(())
    }

    async fn delete(&self, actor: &str, account_data_key: &str) -> PersistenceResult<()> {
        let mut data = self.data.lock();
        data.remove(&(actor.to_owned(), account_data_key.to_owned()));
        Ok(())
    }

    async fn list_for_actor(&self, actor: &str) -> PersistenceResult<Vec<AccountDataRecord>> {
        let data = self.data.lock();
        Ok(data
            .iter()
            .filter(|((row_actor, _), _)| row_actor == actor)
            .map(|(_, record)| record.clone())
            .collect())
    }
}
