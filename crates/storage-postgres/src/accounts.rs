use soland_storage::AccountPk;

use super::{
    AccountDataCasResult, AccountDataRecord, AccountDataStore, AccountLifecycleRecord,
    AccountLifecycleStore, AccountLocalpartRecord, AccountLocalpartStore, AccountRecord,
    AccountStore, BigInt, BlobRef, Bool, Jsonb, Nullable, OptionalExtension, PersistenceError,
    PersistenceResult, PgPool, QueryableByName, RunQueryDsl, Text, Timestamptz, Uuid, Value,
    account_with_primary_localpart_select, async_trait, ids, pg_conn, sql_query, sql_types,
};
pub struct PgAccountStore {
    pub pool: PgPool,
}
#[async_trait]
impl AccountStore for PgAccountStore {
    async fn get(
        &self,
        account_id: &arkret_wire::AccountId,
    ) -> PersistenceResult<Option<AccountRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let row = sql_query(account_with_primary_localpart_select(
            "WHERE a.principal_server_id = $1 AND a.principal_id = $2",
        ))
        .bind::<Text, _>(account_id.principal_server_id.as_str())
        .bind::<Text, _>(account_id.principal_id.as_str())
        .get_result::<AccountRow>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?;
        row.map(AccountRecord::try_from).transpose()
    }

    async fn get_by_pk(&self, account_pk: AccountPk) -> PersistenceResult<Option<AccountRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let row = sql_query(account_with_primary_localpart_select("WHERE a.pk = $1"))
            .bind::<BigInt, _>(account_pk.get())
            .get_result::<AccountRow>(&mut *conn)
            .await
            .optional()
            .map_err(PersistenceError::database)?;
        row.map(AccountRecord::try_from).transpose()
    }

    async fn put(&self, record: &AccountRecord) -> PersistenceResult<AccountPk> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let payload = serde_json::json!({
            "bio": record.bio,
            "avatar_blob_ref": record.avatar_blob_ref,
        });
        let row = sql_query(
            "INSERT INTO accounts (principal_id, principal_server_id, display_name, payload, created_at, updated_at) \
             VALUES ($1, $2, $3, $4, $5, $5) \
             ON CONFLICT (principal_server_id, principal_id) DO UPDATE SET \
             display_name = EXCLUDED.display_name, payload = EXCLUDED.payload, updated_at = NOW() \
             RETURNING pk",
        )
        .bind::<Text, _>(record.principal_id.as_str())
        .bind::<Text, _>(record.principal_server_id.as_str())
        .bind::<Nullable<Text>, _>(&record.display_name)
        .bind::<Jsonb, _>(&payload)
        .bind::<Timestamptz, _>(record.created_at)
        .get_result::<AccountIdRow>(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;

        if record.localpart.trim().is_empty() {
            sql_query("DELETE FROM account_localparts WHERE account_pk = $1")
                .bind::<BigInt, _>(row.pk)
                .execute(&mut *conn)
                .await
                .map_err(PersistenceError::database)?;
        } else {
            sql_query(
                "UPDATE account_localparts SET is_primary = false, updated_at = NOW() \
                 WHERE account_pk = $1 AND localpart <> $2",
            )
            .bind::<BigInt, _>(row.pk)
            .bind::<Text, _>(&record.localpart)
            .execute(&mut *conn)
            .await
            .map_err(PersistenceError::database)?;
            let assigned = sql_query(
                "INSERT INTO account_localparts \
                 (id, account_pk, localpart, is_primary, created_at, updated_at) \
                 VALUES ($1, $2, $3, true, $4, $4) \
                 ON CONFLICT (localpart) DO UPDATE SET \
                 account_pk = EXCLUDED.account_pk, is_primary = true, updated_at = NOW() \
                 WHERE account_localparts.account_pk = EXCLUDED.account_pk \
                 RETURNING localpart",
            )
            .bind::<sql_types::Uuid, _>(Uuid::now_v7())
            .bind::<BigInt, _>(row.pk)
            .bind::<Text, _>(&record.localpart)
            .bind::<Timestamptz, _>(record.created_at)
            .get_result::<LocalpartOnlyRow>(&mut *conn)
            .await
            .optional()
            .map_err(PersistenceError::database)?;
            let assigned_localpart = assigned.map(|row| row.localpart);
            if assigned_localpart.is_none() {
                return Err(PersistenceError::Conflict(format!(
                    "localpart `{}` is already assigned",
                    record.localpart
                )));
            }
        }
        Ok(AccountPk(row.pk))
    }

    async fn list(&self) -> PersistenceResult<Vec<AccountRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let rows = sql_query(account_with_primary_localpart_select(
            "ORDER BY a.principal_server_id, a.principal_id",
        ))
        .load::<AccountRow>(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
        rows.into_iter().map(AccountRecord::try_from).collect()
    }

    async fn delete(&self, account_id: &arkret_wire::AccountId) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query("DELETE FROM accounts WHERE principal_server_id = $1 AND principal_id = $2")
            .bind::<Text, _>(account_id.principal_server_id.as_str())
            .bind::<Text, _>(account_id.principal_id.as_str())
            .execute(&mut *conn)
            .await
            .map(|_| ())
            .map_err(PersistenceError::database)
    }
}
pub struct PgAccountLocalpartStore {
    pub pool: PgPool,
}
#[async_trait]
impl AccountLocalpartStore for PgAccountLocalpartStore {
    async fn list_for_account(
        &self,
        account_pk: AccountPk,
    ) -> PersistenceResult<Vec<AccountLocalpartRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let rows = sql_query(
            "SELECT lp.id, lp.account_pk, lp.localpart, lp.is_primary, lp.created_at, lp.updated_at \
             FROM account_localparts lp WHERE lp.account_pk = $1 \
             ORDER BY lp.is_primary DESC, lp.localpart ASC",
        )
        .bind::<BigInt, _>(account_pk.get())
        .load::<AccountLocalpartRow>(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
        rows.into_iter()
            .map(AccountLocalpartRecord::try_from)
            .collect()
    }

    async fn primary_for_account(
        &self,
        account_pk: AccountPk,
    ) -> PersistenceResult<Option<AccountLocalpartRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let row = sql_query(
            "SELECT lp.id, lp.account_pk, lp.localpart, lp.is_primary, lp.created_at, lp.updated_at \
             FROM account_localparts lp WHERE lp.account_pk = $1 \
             ORDER BY lp.is_primary DESC, lp.created_at ASC, lp.localpart ASC \
             LIMIT 1",
        )
        .bind::<BigInt, _>(account_pk.get())
        .get_result::<AccountLocalpartRow>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?;
        row.map(AccountLocalpartRecord::try_from).transpose()
    }

    async fn owner_of(&self, localpart: &str) -> PersistenceResult<Option<AccountLocalpartRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let row = sql_query(
            "SELECT lp.id, lp.account_pk, lp.localpart, lp.is_primary, lp.created_at, lp.updated_at \
             FROM account_localparts lp WHERE lp.localpart = $1",
        )
        .bind::<Text, _>(localpart)
        .get_result::<AccountLocalpartRow>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?;
        row.map(AccountLocalpartRecord::try_from).transpose()
    }

    async fn add(
        &self,
        account_pk: AccountPk,
        localpart: &str,
        primary: bool,
    ) -> PersistenceResult<AccountLocalpartRecord> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let existing_owner =
            sql_query("SELECT account_pk AS pk FROM account_localparts WHERE localpart = $1")
                .bind::<Text, _>(localpart)
                .get_result::<AccountIdRow>(&mut *conn)
                .await
                .optional()
                .map_err(PersistenceError::database)?;
        if existing_owner.is_some_and(|owner| owner.pk != account_pk.get()) {
            return Err(PersistenceError::Conflict(format!(
                "localpart `{localpart}` is already assigned"
            )));
        }
        if primary {
            sql_query(
                "UPDATE account_localparts SET is_primary = false, updated_at = NOW() \
                 WHERE account_pk = $1",
            )
            .bind::<BigInt, _>(account_pk.get())
            .execute(&mut *conn)
            .await
            .map_err(PersistenceError::database)?;
        }
        let assigned = sql_query(
            "INSERT INTO account_localparts \
             (id, account_pk, localpart, is_primary, created_at, updated_at) \
             VALUES ($1, $2, $3, $4, NOW(), NOW()) \
             ON CONFLICT (localpart) DO UPDATE SET \
             account_pk = EXCLUDED.account_pk, \
             is_primary = CASE WHEN EXCLUDED.is_primary THEN true ELSE account_localparts.is_primary END, \
             updated_at = NOW() \
             WHERE account_localparts.account_pk = EXCLUDED.account_pk \
             RETURNING id, account_pk, localpart, is_primary, created_at, updated_at",
        )
        .bind::<sql_types::Uuid, _>(Uuid::now_v7())
        .bind::<BigInt, _>(account_pk.get())
        .bind::<Text, _>(localpart)
        .bind::<Bool, _>(primary)
        .get_result::<AccountLocalpartRow>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?;
        let assigned = assigned.ok_or_else(|| {
            PersistenceError::Conflict(format!("localpart `{localpart}` is already assigned"))
        })?;
        AccountLocalpartRecord::try_from(assigned)
    }

    async fn set_primary(
        &self,
        account_pk: AccountPk,
        localpart: &str,
    ) -> PersistenceResult<AccountLocalpartRecord> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let owner =
            sql_query("SELECT account_pk AS pk FROM account_localparts WHERE localpart = $1")
                .bind::<Text, _>(localpart)
                .get_result::<AccountIdRow>(&mut *conn)
                .await
                .optional()
                .map_err(PersistenceError::database)?
                .ok_or_else(|| PersistenceError::NotFound("localpart not found".to_owned()))?;
        if owner.pk != account_pk.get() {
            return Err(PersistenceError::Conflict(format!(
                "localpart `{localpart}` is assigned to another account"
            )));
        }
        sql_query(
            "UPDATE account_localparts SET is_primary = (localpart = $2), updated_at = NOW() \
             WHERE account_pk = $1",
        )
        .bind::<BigInt, _>(account_pk.get())
        .bind::<Text, _>(localpart)
        .execute(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
        self.owner_of(localpart)
            .await
            .map_err(PersistenceError::database)?
            .ok_or_else(|| PersistenceError::NotFound("localpart not found".to_owned()))
    }

    async fn remove(&self, account_pk: AccountPk, localpart: &str) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query("DELETE FROM account_localparts WHERE account_pk = $1 AND localpart = $2")
            .bind::<BigInt, _>(account_pk.get())
            .bind::<Text, _>(localpart)
            .execute(&mut *conn)
            .await
            .map(|_| ())
            .map_err(PersistenceError::database)
    }

    async fn clear_for_account(&self, account_pk: AccountPk) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query("DELETE FROM account_localparts WHERE account_pk = $1")
            .bind::<BigInt, _>(account_pk.get())
            .execute(&mut *conn)
            .await
            .map(|_| ())
            .map_err(PersistenceError::database)
    }
}
pub struct PgAccountLifecycleStore {
    pub pool: PgPool,
}
#[async_trait]
impl AccountLifecycleStore for PgAccountLifecycleStore {
    async fn put(
        &self,
        account_pk: AccountPk,
        record: &AccountLifecycleRecord,
    ) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(
            "INSERT INTO account_lifecycle \
             (account_pk, state, reason, changed_by, changed_at) \
             VALUES ($1, $2, $3, $4, $5) \
             ON CONFLICT (account_pk) DO UPDATE SET \
               state = EXCLUDED.state, \
               reason = EXCLUDED.reason, \
               changed_by = EXCLUDED.changed_by, \
               changed_at = EXCLUDED.changed_at",
        )
        .bind::<BigInt, _>(account_pk.get())
        .bind::<Text, _>(&record.state)
        .bind::<Nullable<Text>, _>(&record.reason)
        .bind::<Nullable<Jsonb>, _>(
            record
                .changed_by
                .as_ref()
                .map(serde_json::to_value)
                .transpose()
                .map_err(|error| PersistenceError::database(format!("changed_by JSON: {error}")))?,
        )
        .bind::<Timestamptz, _>(record.changed_at)
        .execute(&mut *conn)
        .await
        .map(|_| ())
        .map_err(PersistenceError::database)
    }

    async fn delete(&self, account_pk: AccountPk) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query("DELETE FROM account_lifecycle WHERE account_pk = $1")
            .bind::<BigInt, _>(account_pk.get())
            .execute(&mut *conn)
            .await
            .map(|_| ())
            .map_err(PersistenceError::database)
    }

    async fn snapshot_all(
        &self,
    ) -> PersistenceResult<Vec<(arkret_wire::AccountId, AccountLifecycleRecord)>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let rows = sql_query(
            "SELECT a.principal_id, a.principal_server_id, l.state, l.reason, \
                    l.changed_by, l.changed_at \
             FROM account_lifecycle l \
             JOIN accounts a ON a.pk = l.account_pk \
             ORDER BY a.principal_server_id, a.principal_id",
        )
        .load::<AccountLifecycleRow>(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
        rows.into_iter()
            .map(|row| {
                let changed_by = row
                    .changed_by
                    .map(serde_json::from_value::<arkret_wire::ActorId>)
                    .transpose()
                    .map_err(|error| {
                        PersistenceError::database(format!("stored changed_by JSON: {error}"))
                    })?;
                Ok((
                    arkret_wire::AccountId::new(row.principal_id, row.principal_server_id),
                    AccountLifecycleRecord {
                        state: row.state,
                        reason: row.reason,
                        changed_by,
                        changed_at: row.changed_at,
                    },
                ))
            })
            .collect()
    }
}
pub struct PgAccountDataStore {
    pub pool: PgPool,
}
#[async_trait]
impl AccountDataStore for PgAccountDataStore {
    async fn get(
        &self,
        actor: &str,
        account_data_key: &str,
    ) -> PersistenceResult<Option<AccountDataRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(
            "SELECT actor_id AS actor, account_data_key, revision, payload, tombstone, updated_at \
             FROM account_datas WHERE actor_id = $1 AND account_data_key = $2",
        )
        .bind::<Text, _>(actor)
        .bind::<Text, _>(account_data_key)
        .get_result::<AccountDataRow>(&mut *conn)
        .await
        .optional()
        .map(|row| row.map(AccountDataRecord::from))
        .map_err(PersistenceError::database)
    }

    async fn compare_and_set(
        &self,
        record: &AccountDataRecord,
        expected_revision: u64,
    ) -> PersistenceResult<AccountDataCasResult> {
        let expected_revision = i64::try_from(expected_revision).map_err(|_| {
            PersistenceError::Conflict("account_data revision exceeds i64 storage range".to_owned())
        })?;
        let revision = i64::try_from(record.revision).map_err(|_| {
            PersistenceError::Conflict("account_data revision exceeds i64 storage range".to_owned())
        })?;
        if revision
            != expected_revision.checked_add(1).ok_or_else(|| {
                PersistenceError::Conflict("account_data revision exhausted".to_owned())
            })?
        {
            return Err(PersistenceError::Internal(
                "account_data record revision must equal expected_revision + 1".to_owned(),
            ));
        }
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let applied = sql_query(
            "WITH updated AS ( \
                 UPDATE account_datas SET revision = $4, payload = $5, tombstone = $6, updated_at = $7 \
                 WHERE actor_id = $2 AND account_data_key = $3 AND revision = $8 \
                 RETURNING actor_id AS actor, account_data_key, revision, payload, tombstone, updated_at \
             ), inserted AS ( \
                 INSERT INTO account_datas \
                    (id, actor_id, account_data_key, revision, payload, tombstone, updated_at) \
                 SELECT $1, $2, $3, $4, $5, $6, $7 \
                 WHERE $8 = 0 AND NOT EXISTS ( \
                     SELECT 1 FROM account_datas WHERE actor_id = $2 AND account_data_key = $3 \
                 ) \
                 ON CONFLICT (actor_id, account_data_key) DO NOTHING \
                 RETURNING actor_id AS actor, account_data_key, revision, payload, tombstone, updated_at \
             ) \
             SELECT * FROM updated UNION ALL SELECT * FROM inserted",
        )
        .bind::<diesel::sql_types::Uuid, _>(uuid::Uuid::now_v7())
        .bind::<Text, _>(&record.actor)
        .bind::<Text, _>(&record.account_data_key)
        .bind::<BigInt, _>(revision)
        .bind::<Jsonb, _>(&record.payload)
        .bind::<Bool, _>(record.tombstone)
        .bind::<Timestamptz, _>(record.updated_at)
        .bind::<BigInt, _>(expected_revision)
        .get_result::<AccountDataRow>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?;
        if let Some(applied) = applied {
            return Ok(AccountDataCasResult::Applied(applied.into()));
        }
        let current = self.get(&record.actor, &record.account_data_key).await?;
        Ok(AccountDataCasResult::Conflict(current))
    }

    async fn list_for_actor(&self, actor: &str) -> PersistenceResult<Vec<AccountDataRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(
            "SELECT actor_id AS actor, account_data_key, revision, payload, tombstone, updated_at \
             FROM account_datas WHERE actor_id = $1 AND tombstone = FALSE \
             ORDER BY account_data_key",
        )
        .bind::<Text, _>(actor)
        .load::<AccountDataRow>(&mut *conn)
        .await
        .map(|rows| rows.into_iter().map(AccountDataRecord::from).collect())
        .map_err(PersistenceError::database)
    }
}
#[derive(QueryableByName)]
struct AccountRow {
    #[diesel(sql_type = BigInt)]
    pk: i64,
    #[diesel(sql_type = Text)]
    principal_id: arkret_wire::DidCoreId,
    #[diesel(sql_type = Text)]
    principal_server_id: arkret_wire::DidCoreId,
    #[diesel(sql_type = Text)]
    localpart: String,
    #[diesel(sql_type = Nullable<Text>)]
    display_name: Option<String>,
    #[diesel(sql_type = Jsonb)]
    payload: Value,
    #[diesel(sql_type = Timestamptz)]
    created_at: chrono::DateTime<chrono::Utc>,
}
#[derive(QueryableByName)]
struct AccountIdRow {
    #[diesel(sql_type = BigInt)]
    pk: i64,
}
#[derive(QueryableByName)]
struct AccountLocalpartRow {
    #[diesel(sql_type = sql_types::Uuid)]
    id: Uuid,
    #[diesel(sql_type = BigInt)]
    account_pk: i64,
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
    localpart: String,
}
#[derive(QueryableByName)]
struct AccountLifecycleRow {
    #[diesel(sql_type = Text)]
    principal_id: arkret_wire::DidCoreId,
    #[diesel(sql_type = Text)]
    principal_server_id: arkret_wire::DidCoreId,
    #[diesel(sql_type = Text)]
    state: String,
    #[diesel(sql_type = Nullable<Text>)]
    reason: Option<String>,
    #[diesel(sql_type = Nullable<Jsonb>)]
    changed_by: Option<Value>,
    #[diesel(sql_type = Timestamptz)]
    changed_at: chrono::DateTime<chrono::Utc>,
}
impl TryFrom<AccountLocalpartRow> for AccountLocalpartRecord {
    type Error = PersistenceError;

    fn try_from(row: AccountLocalpartRow) -> Result<Self, Self::Error> {
        Ok(Self {
            id: ids::format_typed_uuid("account_localpart", &row.id),
            account_pk: AccountPk(row.account_pk),
            localpart: row.localpart,
            is_primary: row.is_primary,
            created_at: row.created_at,
            updated_at: row.updated_at,
        })
    }
}
impl TryFrom<AccountRow> for AccountRecord {
    type Error = PersistenceError;

    fn try_from(row: AccountRow) -> Result<Self, Self::Error> {
        Ok(Self {
            pk: AccountPk(row.pk),
            principal_id: row.principal_id,
            principal_server_id: row.principal_server_id,
            localpart: row.localpart,
            display_name: row.display_name,
            bio: row
                .payload
                .get("bio")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned),
            avatar_blob_ref: row
                .payload
                .get("avatar_blob_ref")
                .and_then(Value::as_str)
                .and_then(|value| BlobRef::new(value.to_owned()).ok()),
            created_at: row.created_at,
        })
    }
}
#[derive(QueryableByName)]
struct AccountDataRow {
    #[diesel(sql_type = Text)]
    actor: String,
    #[diesel(sql_type = Text)]
    account_data_key: String,
    #[diesel(sql_type = BigInt)]
    revision: i64,
    #[diesel(sql_type = Jsonb)]
    payload: Value,
    #[diesel(sql_type = Bool)]
    tombstone: bool,
    #[diesel(sql_type = Timestamptz)]
    updated_at: chrono::DateTime<chrono::Utc>,
}
impl From<AccountDataRow> for AccountDataRecord {
    fn from(row: AccountDataRow) -> Self {
        Self {
            actor: row.actor,
            account_data_key: row.account_data_key,
            revision: u64::try_from(row.revision)
                .expect("account_data revision constraint guarantees non-negative values"),
            payload: row.payload,
            tombstone: row.tombstone,
            updated_at: row.updated_at,
        }
    }
}
