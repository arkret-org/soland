use super::*;

/// Trait for account storage operations.
#[async_trait]
pub trait AccountStore: Send + Sync {
    async fn get(&self, did: &str) -> PersistenceResult<Option<AccountRecord>>;
    async fn put(&self, record: &AccountRecord) -> PersistenceResult<()>;
    async fn list(&self) -> PersistenceResult<Vec<AccountRecord>>;
    async fn delete(&self, did: &str) -> PersistenceResult<()>;
}

#[async_trait]
pub trait AccountLocalpartStore: Send + Sync {
    async fn list_for_account(
        &self,
        account_did: &str,
    ) -> PersistenceResult<Vec<AccountLocalpartRecord>>;
    async fn primary_for_account(
        &self,
        account_did: &str,
    ) -> PersistenceResult<Option<AccountLocalpartRecord>>;
    async fn owner_of(&self, localpart: &str) -> PersistenceResult<Option<AccountLocalpartRecord>>;
    async fn add(
        &self,
        account_did: &str,
        localpart: &str,
        primary: bool,
    ) -> PersistenceResult<AccountLocalpartRecord>;
    async fn set_primary(
        &self,
        account_did: &str,
        localpart: &str,
    ) -> PersistenceResult<AccountLocalpartRecord>;
    async fn remove(&self, account_did: &str, localpart: &str) -> PersistenceResult<()>;
    async fn clear_for_account(&self, account_did: &str) -> PersistenceResult<()>;
}

#[async_trait]
pub trait AccountLifecycleStore: Send + Sync {
    async fn put(&self, did: &str, record: &AccountLifecycleRecord) -> PersistenceResult<()>;
    async fn delete(&self, did: &str) -> PersistenceResult<()>;
    async fn snapshot_all(&self) -> PersistenceResult<Vec<(String, AccountLifecycleRecord)>>;
}

/// Trait for actor-private account data storage.
///
/// `data_type` is the canonical wire key (e.g. `ck.contacts.actor.<did>`,
/// `ck.contacts.realm.<realm_id>`, `ck.read_receipt.preferences`). The
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
        data_type: &str,
    ) -> PersistenceResult<Option<AccountDataRecord>>;
    async fn put(&self, record: &AccountDataRecord) -> PersistenceResult<()>;
    async fn delete(&self, actor: &str, data_type: &str) -> PersistenceResult<()>;
    async fn list_for_actor(&self, actor: &str) -> PersistenceResult<Vec<AccountDataRecord>>;
}

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
        let localparts = self.localparts.lock().expect("account localpart lock");
        record.localpart = Self::primary_localpart_from(&localparts, &record.did);
        record
    }
}

#[async_trait]
impl AccountStore for MemoryAccountStore {
    async fn get(&self, did: &str) -> PersistenceResult<Option<AccountRecord>> {
        let data = self.data.lock().expect("lock");
        let record = data.get(did).cloned();
        drop(data);
        Ok(record.map(|record| self.with_current_localpart(record)))
    }

    async fn put(&self, record: &AccountRecord) -> PersistenceResult<()> {
        let mut data = self.data.lock().expect("lock");
        data.insert(record.did.clone(), record.clone());
        drop(data);

        let now = Utc::now();
        let mut localparts = self.localparts.lock().expect("account localpart lock");
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
        let data = self.data.lock().expect("lock");
        let records: Vec<AccountRecord> = data.values().cloned().collect();
        drop(data);
        Ok(records
            .into_iter()
            .map(|record| self.with_current_localpart(record))
            .collect())
    }

    async fn delete(&self, did: &str) -> PersistenceResult<()> {
        let mut data = self.data.lock().expect("lock");
        data.remove(did);
        drop(data);
        self.localparts
            .lock()
            .expect("account localpart lock")
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
        let data = self.data.lock().expect("account localpart lock");
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
        let data = self.data.lock().expect("account localpart lock");
        Ok(data.get(localpart).cloned())
    }

    async fn add(
        &self,
        account_did: &str,
        localpart: &str,
        primary: bool,
    ) -> PersistenceResult<AccountLocalpartRecord> {
        let now = Utc::now();
        let mut data = self.data.lock().expect("account localpart lock");
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
        let mut data = self.data.lock().expect("account localpart lock");
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
        let mut data = self.data.lock().expect("account localpart lock");
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
        let mut data = self.data.lock().expect("account localpart lock");
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
        self.data
            .lock()
            .expect("account lifecycle lock")
            .insert(did.to_owned(), record.clone());
        Ok(())
    }

    async fn delete(&self, did: &str) -> PersistenceResult<()> {
        self.data
            .lock()
            .expect("account lifecycle lock")
            .remove(did);
        Ok(())
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<(String, AccountLifecycleRecord)>> {
        Ok(self
            .data
            .lock()
            .expect("account lifecycle lock")
            .iter()
            .map(|(did, record)| (did.clone(), record.clone()))
            .collect())
    }
}

// In-memory contact store
/// In-memory `(actor, data_type) -> AccountDataRecord` table. Mirrors the
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
        data_type: &str,
    ) -> PersistenceResult<Option<AccountDataRecord>> {
        let data = self.data.lock().expect("lock");
        Ok(data.get(&(actor.to_owned(), data_type.to_owned())).cloned())
    }

    async fn put(&self, record: &AccountDataRecord) -> PersistenceResult<()> {
        let mut data = self.data.lock().expect("lock");
        data.insert(
            (record.actor.clone(), record.data_type.clone()),
            record.clone(),
        );
        Ok(())
    }

    async fn delete(&self, actor: &str, data_type: &str) -> PersistenceResult<()> {
        let mut data = self.data.lock().expect("lock");
        data.remove(&(actor.to_owned(), data_type.to_owned()));
        Ok(())
    }

    async fn list_for_actor(&self, actor: &str) -> PersistenceResult<Vec<AccountDataRecord>> {
        let data = self.data.lock().expect("lock");
        Ok(data
            .iter()
            .filter(|((row_actor, _), _)| row_actor == actor)
            .map(|(_, record)| record.clone())
            .collect())
    }
}

pub(crate) struct PgAccountStore {
    pub(crate) pool: PgPool,
}

fn account_with_primary_localpart_select(where_clause: &str) -> String {
    format!(
        "SELECT a.id, a.principal_id AS did, COALESCE(lp.localpart, '') AS localpart, \
         a.display_name, a.created_at \
         FROM accounts a \
         LEFT JOIN LATERAL ( \
             SELECT localpart FROM account_localparts \
             WHERE account_id = a.id \
             ORDER BY is_primary DESC, created_at ASC, localpart ASC \
             LIMIT 1 \
         ) lp ON true \
         {where_clause}"
    )
}

#[async_trait]
impl AccountStore for PgAccountStore {
    async fn get(&self, did: &str) -> PersistenceResult<Option<AccountRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(account_with_primary_localpart_select(
            "WHERE a.principal_id = $1",
        ))
        .bind::<Text, _>(did)
        .get_result::<AccountRow>(&mut *conn)
        .await
        .optional()
        .map(|row| row.map(AccountRecord::from))
        .map_err(PersistenceError::from)
    }

    async fn put(&self, record: &AccountRecord) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool).await?;
        let row = sql_query(
            "INSERT INTO accounts (id, principal_id, display_name, payload, created_at, updated_at) \
             VALUES ($1, $2, $3, '{}'::jsonb, $4, $4) \
             ON CONFLICT (principal_id) DO UPDATE SET \
             display_name = EXCLUDED.display_name, updated_at = NOW() \
             RETURNING id",
        )
        .bind::<SqlUuid, _>(ids::typed_uuid_part_expect_internal(&record.id))
        .bind::<Text, _>(&record.did)
        .bind::<Nullable<Text>, _>(&record.display_name)
        .bind::<Timestamptz, _>(record.created_at)
        .get_result::<AccountIdRow>(&mut *conn)
        .await
        .map_err(PersistenceError::from)?;

        if record.localpart.trim().is_empty() {
            sql_query("DELETE FROM account_localparts WHERE account_id = $1")
                .bind::<SqlUuid, _>(row.id)
                .execute(&mut *conn)
                .await
                .map_err(PersistenceError::from)?;
        } else {
            sql_query(
                "UPDATE account_localparts SET is_primary = false, updated_at = NOW() \
                 WHERE account_id = $1 AND localpart <> $2",
            )
            .bind::<SqlUuid, _>(row.id)
            .bind::<Text, _>(&record.localpart)
            .execute(&mut *conn)
            .await
            .map_err(PersistenceError::from)?;
            let assigned = sql_query(
                "INSERT INTO account_localparts \
                 (id, account_id, localpart, is_primary, created_at, updated_at) \
                 VALUES ($1, $2, $3, true, $4, $4) \
                 ON CONFLICT (localpart) DO UPDATE SET \
                 account_id = EXCLUDED.account_id, is_primary = true, updated_at = NOW() \
                 WHERE account_localparts.account_id = EXCLUDED.account_id \
                 RETURNING localpart",
            )
            .bind::<SqlUuid, _>(Uuid::now_v7())
            .bind::<SqlUuid, _>(row.id)
            .bind::<Text, _>(&record.localpart)
            .bind::<Timestamptz, _>(record.created_at)
            .get_result::<LocalpartOnlyRow>(&mut *conn)
            .await
            .optional()
            .map_err(PersistenceError::from)?;
            if assigned.is_none() {
                return Err(PersistenceError::Conflict(format!(
                    "localpart `{}` is already assigned",
                    record.localpart
                )));
            }
        }
        Ok(())
    }

    async fn list(&self) -> PersistenceResult<Vec<AccountRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(account_with_primary_localpart_select(
            "ORDER BY a.principal_id",
        ))
        .load::<AccountRow>(&mut *conn)
        .await
        .map(|rows| rows.into_iter().map(AccountRecord::from).collect())
        .map_err(PersistenceError::from)
    }

    async fn delete(&self, did: &str) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query("DELETE FROM accounts WHERE principal_id = $1")
            .bind::<Text, _>(did)
            .execute(&mut *conn)
            .await
            .map(|_| ())
            .map_err(PersistenceError::from)
    }
}

pub(crate) struct PgAccountLocalpartStore {
    pub(crate) pool: PgPool,
}

#[async_trait]
impl AccountLocalpartStore for PgAccountLocalpartStore {
    async fn list_for_account(
        &self,
        account_did: &str,
    ) -> PersistenceResult<Vec<AccountLocalpartRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "SELECT lp.id, a.principal_id AS account_did, lp.localpart, lp.is_primary, \
             lp.created_at, lp.updated_at \
             FROM account_localparts lp \
             JOIN accounts a ON a.id = lp.account_id \
             WHERE a.principal_id = $1 \
             ORDER BY lp.is_primary DESC, lp.localpart ASC",
        )
        .bind::<Text, _>(account_did)
        .load::<AccountLocalpartRow>(&mut *conn)
        .await
        .map(|rows| rows.into_iter().map(AccountLocalpartRecord::from).collect())
        .map_err(PersistenceError::from)
    }

    async fn primary_for_account(
        &self,
        account_did: &str,
    ) -> PersistenceResult<Option<AccountLocalpartRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "SELECT lp.id, a.principal_id AS account_did, lp.localpart, lp.is_primary, \
             lp.created_at, lp.updated_at \
             FROM account_localparts lp \
             JOIN accounts a ON a.id = lp.account_id \
             WHERE a.principal_id = $1 \
             ORDER BY lp.is_primary DESC, lp.created_at ASC, lp.localpart ASC \
             LIMIT 1",
        )
        .bind::<Text, _>(account_did)
        .get_result::<AccountLocalpartRow>(&mut *conn)
        .await
        .optional()
        .map(|row| row.map(AccountLocalpartRecord::from))
        .map_err(PersistenceError::from)
    }

    async fn owner_of(&self, localpart: &str) -> PersistenceResult<Option<AccountLocalpartRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "SELECT lp.id, a.principal_id AS account_did, lp.localpart, lp.is_primary, \
             lp.created_at, lp.updated_at \
             FROM account_localparts lp \
             JOIN accounts a ON a.id = lp.account_id \
             WHERE lp.localpart = $1",
        )
        .bind::<Text, _>(localpart)
        .get_result::<AccountLocalpartRow>(&mut *conn)
        .await
        .optional()
        .map(|row| row.map(AccountLocalpartRecord::from))
        .map_err(PersistenceError::from)
    }

    async fn add(
        &self,
        account_did: &str,
        localpart: &str,
        primary: bool,
    ) -> PersistenceResult<AccountLocalpartRecord> {
        let mut conn = pg_conn(&self.pool).await?;
        let account = sql_query("SELECT id FROM accounts WHERE principal_id = $1")
            .bind::<Text, _>(account_did)
            .get_result::<AccountIdRow>(&mut *conn)
            .await
            .optional()
            .map_err(PersistenceError::from)?
            .ok_or_else(|| PersistenceError::NotFound("account not found".to_owned()))?;
        let existing_owner =
            sql_query("SELECT account_id AS id FROM account_localparts WHERE localpart = $1")
                .bind::<Text, _>(localpart)
                .get_result::<AccountIdRow>(&mut *conn)
                .await
                .optional()
                .map_err(PersistenceError::from)?;
        if existing_owner.is_some_and(|owner| owner.id != account.id) {
            return Err(PersistenceError::Conflict(format!(
                "localpart `{localpart}` is already assigned"
            )));
        }
        if primary {
            sql_query(
                "UPDATE account_localparts SET is_primary = false, updated_at = NOW() \
                 WHERE account_id = $1",
            )
            .bind::<SqlUuid, _>(account.id)
            .execute(&mut *conn)
            .await
            .map_err(PersistenceError::from)?;
        }
        let assigned = sql_query(
            "INSERT INTO account_localparts \
             (id, account_id, localpart, is_primary, created_at, updated_at) \
             VALUES ($1, $2, $3, $4, NOW(), NOW()) \
             ON CONFLICT (localpart) DO UPDATE SET \
             account_id = EXCLUDED.account_id, \
             is_primary = CASE WHEN EXCLUDED.is_primary THEN true ELSE account_localparts.is_primary END, \
             updated_at = NOW() \
             WHERE account_localparts.account_id = EXCLUDED.account_id \
             RETURNING id, $5::text AS account_did, localpart, is_primary, created_at, updated_at",
        )
        .bind::<SqlUuid, _>(Uuid::now_v7())
        .bind::<SqlUuid, _>(account.id)
        .bind::<Text, _>(localpart)
        .bind::<Bool, _>(primary)
        .bind::<Text, _>(account_did)
        .get_result::<AccountLocalpartRow>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::from)?;
        assigned.map(AccountLocalpartRecord::from).ok_or_else(|| {
            PersistenceError::Conflict(format!("localpart `{localpart}` is already assigned"))
        })
    }

    async fn set_primary(
        &self,
        account_did: &str,
        localpart: &str,
    ) -> PersistenceResult<AccountLocalpartRecord> {
        let mut conn = pg_conn(&self.pool).await?;
        let account = sql_query("SELECT id FROM accounts WHERE principal_id = $1")
            .bind::<Text, _>(account_did)
            .get_result::<AccountIdRow>(&mut *conn)
            .await
            .optional()
            .map_err(PersistenceError::from)?
            .ok_or_else(|| PersistenceError::NotFound("account not found".to_owned()))?;
        let owner =
            sql_query("SELECT account_id AS id FROM account_localparts WHERE localpart = $1")
                .bind::<Text, _>(localpart)
                .get_result::<AccountIdRow>(&mut *conn)
                .await
                .optional()
                .map_err(PersistenceError::from)?
                .ok_or_else(|| PersistenceError::NotFound("localpart not found".to_owned()))?;
        if owner.id != account.id {
            return Err(PersistenceError::Conflict(format!(
                "localpart `{localpart}` is assigned to another account"
            )));
        }
        sql_query(
            "UPDATE account_localparts SET is_primary = (localpart = $2), updated_at = NOW() \
             WHERE account_id = $1",
        )
        .bind::<SqlUuid, _>(account.id)
        .bind::<Text, _>(localpart)
        .execute(&mut *conn)
        .await
        .map_err(PersistenceError::from)?;
        self.owner_of(localpart)
            .await?
            .ok_or_else(|| PersistenceError::NotFound("localpart not found".to_owned()))
    }

    async fn remove(&self, account_did: &str, localpart: &str) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "DELETE FROM account_localparts lp \
             USING accounts a \
             WHERE lp.account_id = a.id AND a.principal_id = $1 AND lp.localpart = $2",
        )
        .bind::<Text, _>(account_did)
        .bind::<Text, _>(localpart)
        .execute(&mut *conn)
        .await
        .map(|_| ())
        .map_err(PersistenceError::from)
    }

    async fn clear_for_account(&self, account_did: &str) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "DELETE FROM account_localparts lp \
             USING accounts a \
             WHERE lp.account_id = a.id AND a.principal_id = $1",
        )
        .bind::<Text, _>(account_did)
        .execute(&mut *conn)
        .await
        .map(|_| ())
        .map_err(PersistenceError::from)
    }
}

pub(crate) struct PgAccountLifecycleStore {
    pub(crate) pool: PgPool,
}

#[async_trait]
impl AccountLifecycleStore for PgAccountLifecycleStore {
    async fn put(&self, did: &str, record: &AccountLifecycleRecord) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "INSERT INTO account_lifecycle \
             (principal_id, state, reason, changed_by, changed_at) \
             VALUES ($1, $2, $3, $4, $5) \
             ON CONFLICT (principal_id) DO UPDATE SET \
               state = EXCLUDED.state, \
               reason = EXCLUDED.reason, \
               changed_by = EXCLUDED.changed_by, \
               changed_at = EXCLUDED.changed_at",
        )
        .bind::<Text, _>(did)
        .bind::<Text, _>(&record.state)
        .bind::<Nullable<Text>, _>(&record.reason)
        .bind::<Nullable<Text>, _>(&record.changed_by)
        .bind::<Timestamptz, _>(record.changed_at)
        .execute(&mut *conn)
        .await
        .map(|_| ())
        .map_err(PersistenceError::from)
    }

    async fn delete(&self, did: &str) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query("DELETE FROM account_lifecycle WHERE principal_id = $1")
            .bind::<Text, _>(did)
            .execute(&mut *conn)
            .await
            .map(|_| ())
            .map_err(PersistenceError::from)
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<(String, AccountLifecycleRecord)>> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "SELECT principal_id, state, reason, changed_by, changed_at \
             FROM account_lifecycle ORDER BY principal_id",
        )
        .load::<AccountLifecycleRow>(&mut *conn)
        .await
        .map(|rows| {
            rows.into_iter()
                .map(|row| {
                    (
                        row.principal_id,
                        AccountLifecycleRecord {
                            state: row.state,
                            reason: row.reason,
                            changed_by: row.changed_by,
                            changed_at: row.changed_at,
                        },
                    )
                })
                .collect()
        })
        .map_err(PersistenceError::from)
    }
}

pub(crate) struct PgAccountDataStore {
    pub(crate) pool: PgPool,
}

#[async_trait]
impl AccountDataStore for PgAccountDataStore {
    async fn get(
        &self,
        actor: &str,
        data_type: &str,
    ) -> PersistenceResult<Option<AccountDataRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "SELECT actor_id AS actor, data_type, payload, updated_at \
             FROM account_datas WHERE actor_id = $1 AND data_type = $2",
        )
        .bind::<Text, _>(actor)
        .bind::<Text, _>(data_type)
        .get_result::<AccountDataRow>(&mut *conn)
        .await
        .optional()
        .map(|row| row.map(AccountDataRecord::from))
        .map_err(PersistenceError::from)
    }

    async fn put(&self, record: &AccountDataRecord) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "INSERT INTO account_datas (id, actor_id, data_type, payload, updated_at) \
             VALUES ($1, $2, $3, $4, $5) \
             ON CONFLICT (actor_id, data_type) DO UPDATE SET payload = EXCLUDED.payload, \
             updated_at = EXCLUDED.updated_at",
        )
        .bind::<diesel::sql_types::Uuid, _>(uuid::Uuid::now_v7())
        .bind::<Text, _>(&record.actor)
        .bind::<Text, _>(&record.data_type)
        .bind::<Jsonb, _>(&record.payload)
        .bind::<Timestamptz, _>(record.updated_at)
        .execute(&mut *conn)
        .await
        .map(|_| ())
        .map_err(PersistenceError::from)
    }

    async fn delete(&self, actor: &str, data_type: &str) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query("DELETE FROM account_datas WHERE actor_id = $1 AND data_type = $2")
            .bind::<Text, _>(actor)
            .bind::<Text, _>(data_type)
            .execute(&mut *conn)
            .await
            .map(|_| ())
            .map_err(PersistenceError::from)
    }

    async fn list_for_actor(&self, actor: &str) -> PersistenceResult<Vec<AccountDataRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "SELECT actor_id AS actor, data_type, payload, updated_at \
             FROM account_datas WHERE actor_id = $1 ORDER BY data_type",
        )
        .bind::<Text, _>(actor)
        .load::<AccountDataRow>(&mut *conn)
        .await
        .map(|rows| rows.into_iter().map(AccountDataRecord::from).collect())
        .map_err(PersistenceError::from)
    }
}

#[derive(QueryableByName)]
struct AccountRow {
    #[diesel(sql_type = SqlUuid)]
    id: Uuid,
    #[diesel(sql_type = Text)]
    did: String,
    #[diesel(sql_type = Text)]
    localpart: String,
    #[diesel(sql_type = Nullable<Text>)]
    display_name: Option<String>,
    #[diesel(sql_type = Timestamptz)]
    created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(QueryableByName)]
struct AccountIdRow {
    #[diesel(sql_type = SqlUuid)]
    id: Uuid,
}

#[derive(QueryableByName)]
struct AccountLocalpartRow {
    #[diesel(sql_type = SqlUuid)]
    id: Uuid,
    #[diesel(sql_type = Text)]
    account_did: String,
    #[diesel(sql_type = Text)]
    localpart: String,
    #[diesel(sql_type = Bool)]
    is_primary: bool,
    #[diesel(sql_type = Timestamptz)]
    created_at: chrono::DateTime<chrono::Utc>,
    #[diesel(sql_type = Timestamptz)]
    updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(QueryableByName)]
struct LocalpartOnlyRow {
    #[diesel(sql_type = Text)]
    #[allow(dead_code)]
    localpart: String,
}

#[derive(QueryableByName)]
struct AccountLifecycleRow {
    #[diesel(sql_type = Text)]
    principal_id: String,
    #[diesel(sql_type = Text)]
    state: String,
    #[diesel(sql_type = Nullable<Text>)]
    reason: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    changed_by: Option<String>,
    #[diesel(sql_type = Timestamptz)]
    changed_at: chrono::DateTime<chrono::Utc>,
}

impl From<AccountLocalpartRow> for AccountLocalpartRecord {
    fn from(row: AccountLocalpartRow) -> Self {
        Self {
            id: ids::format_typed_uuid("account_localpart", &row.id),
            account_did: row.account_did,
            localpart: row.localpart,
            is_primary: row.is_primary,
            created_at: row.created_at,
            updated_at: row.updated_at,
        }
    }
}

impl From<AccountRow> for AccountRecord {
    fn from(row: AccountRow) -> Self {
        Self {
            id: ids::format_typed_uuid("account", &row.id),
            did: row.did,
            localpart: row.localpart,
            display_name: row.display_name,
            // Pg backend doesn't carry bio / avatar_url yet — the Memory
            // store does. When the Pg projection lands, extend AccountRow
            // + this hydrate.
            bio: None,
            avatar_url: None,
            created_at: row.created_at,
        }
    }
}

#[derive(QueryableByName)]
struct AccountDataRow {
    #[diesel(sql_type = Text)]
    actor: String,
    #[diesel(sql_type = Text)]
    data_type: String,
    #[diesel(sql_type = Jsonb)]
    payload: Value,
    #[diesel(sql_type = Timestamptz)]
    updated_at: chrono::DateTime<chrono::Utc>,
}

impl From<AccountDataRow> for AccountDataRecord {
    fn from(row: AccountDataRow) -> Self {
        Self {
            actor: row.actor,
            data_type: row.data_type,
            payload: row.payload,
            updated_at: row.updated_at,
        }
    }
}
