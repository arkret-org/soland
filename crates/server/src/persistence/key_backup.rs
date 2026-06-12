use super::*;

/// Encrypted key-backup envelopes (one row per `backup_id`).
#[async_trait]
pub trait KeyBackupStore: Send + Sync {
    async fn put(&self, backup_id: String, payload: Value) -> PersistenceResult<()>;
    async fn get(&self, backup_id: &str) -> PersistenceResult<Option<Value>>;
    async fn delete(&self, backup_id: &str) -> PersistenceResult<bool>;
    async fn snapshot_all(&self) -> PersistenceResult<Vec<Value>>;
}

#[derive(Default)]
pub(crate) struct MemoryKeyBackupStore {
    backups: Mutex<BTreeMap<String, Value>>,
}

impl MemoryKeyBackupStore {
    pub(crate) fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl KeyBackupStore for MemoryKeyBackupStore {
    async fn put(&self, backup_id: String, payload: Value) -> PersistenceResult<()> {
        self.backups
            .lock()
            .expect("key backup lock")
            .insert(backup_id, payload);
        Ok(())
    }

    async fn get(&self, backup_id: &str) -> PersistenceResult<Option<Value>> {
        Ok(self
            .backups
            .lock()
            .expect("key backup lock")
            .get(backup_id)
            .cloned())
    }

    async fn delete(&self, backup_id: &str) -> PersistenceResult<bool> {
        Ok(self
            .backups
            .lock()
            .expect("key backup lock")
            .remove(backup_id)
            .is_some())
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<Value>> {
        Ok(self
            .backups
            .lock()
            .expect("key backup lock")
            .values()
            .cloned()
            .collect())
    }
}

pub(crate) struct PgKeyBackupStore {
    pub(crate) pool: PgPool,
}

#[async_trait]
impl KeyBackupStore for PgKeyBackupStore {
    async fn put(&self, backup_id: String, payload: Value) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool).await?;
        let extract_str = |key: &str| -> Option<String> {
            payload
                .get(key)
                .and_then(Value::as_str)
                .map(ToOwned::to_owned)
        };
        let account_id = extract_str("account_id")
            .or_else(|| extract_str("actor_id"))
            .or_else(|| extract_str("actor"));
        let device_id = extract_str("device_id");
        let scheme = extract_str("scheme").or_else(|| extract_str("algorithm"));
        let version: i32 = payload
            .get("version")
            .and_then(Value::as_i64)
            .map(|v| v.clamp(i32::MIN as i64, i32::MAX as i64) as i32)
            .unwrap_or(0);
        // base64-decoded key material lives in `key_material_encrypted` if the
        // caller already provided raw bytes via a `bytes_b64` field. Otherwise
        // the encrypted material stays in the JSONB envelope.
        let key_material: Option<Vec<u8>> = payload
            .get("key_material_encrypted_b64")
            .and_then(Value::as_str)
            .and_then(|s| {
                use base64::Engine as _;
                use base64::engine::general_purpose::STANDARD;
                STANDARD.decode(s).ok()
            });
        sql_query(
            "INSERT INTO key_backups \
             (id, account_id, device_id, scheme, version, key_material_encrypted, payload, created_at, last_accessed_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, NOW(), NULL) \
             ON CONFLICT (id) DO UPDATE SET \
                account_id = EXCLUDED.account_id, \
                device_id = EXCLUDED.device_id, \
                scheme = EXCLUDED.scheme, \
                version = EXCLUDED.version, \
                key_material_encrypted = EXCLUDED.key_material_encrypted, \
                payload = EXCLUDED.payload",
        )
        .bind::<SqlUuid, _>(ids::typed_uuid_part_or_panic(&backup_id))
        .bind::<Nullable<Text>, _>(&account_id)
        .bind::<Nullable<Text>, _>(&device_id)
        .bind::<Nullable<Text>, _>(&scheme)
        .bind::<Integer, _>(version)
        .bind::<Nullable<Binary>, _>(key_material.as_deref())
        .bind::<Jsonb, _>(&payload)
        .execute(&mut *conn).await
        .map(|_| ())
        .map_err(PersistenceError::from)
    }

    async fn get(&self, backup_id: &str) -> PersistenceResult<Option<Value>> {
        let mut conn = pg_conn(&self.pool).await?;
        // last_accessed_at side-effect on read is informational; failure here
        // must not crash the get path.
        let _ = sql_query("UPDATE key_backups SET last_accessed_at = NOW() WHERE id = $1")
            .bind::<SqlUuid, _>(ids::typed_uuid_part_or_panic(backup_id))
            .execute(&mut *conn)
            .await;
        sql_query("SELECT payload FROM key_backups WHERE id = $1")
            .bind::<SqlUuid, _>(ids::typed_uuid_part_or_panic(backup_id))
            .get_result::<JsonPayloadRow>(&mut *conn)
            .await
            .optional()
            .map(|row| row.map(|r| r.payload))
            .map_err(PersistenceError::from)
    }

    async fn delete(&self, backup_id: &str) -> PersistenceResult<bool> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query("DELETE FROM key_backups WHERE id = $1")
            .bind::<SqlUuid, _>(ids::typed_uuid_part_or_panic(backup_id))
            .execute(&mut *conn)
            .await
            .map(|n| n > 0)
            .map_err(PersistenceError::from)
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<Value>> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query("SELECT payload FROM key_backups ORDER BY created_at ASC, id ASC")
            .load::<JsonPayloadRow>(&mut *conn)
            .await
            .map(|rows| rows.into_iter().map(|r| r.payload).collect())
            .map_err(PersistenceError::from)
    }
}
