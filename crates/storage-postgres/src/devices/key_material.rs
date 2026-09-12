//! Device key material retains the authorization instance authenticated at upload.
use super::*;

pub struct PgDeviceKeyStore {
    pub pool: PgPool,
}
pub struct PgOneTimeKeyStore {
    pub pool: PgPool,
}

async fn current_binding(
    conn: &mut diesel_async::AsyncPgConnection,
    actor: &str,
    device: &str,
) -> PersistenceResult<Option<Value>> {
    let Some(binding) =
        crate::device_revocations::local_device_binding_in_transaction(conn, actor, device).await?
    else {
        return Ok(None);
    };
    if crate::device_revocations::gate_status_in_transaction(conn, &binding).await?
        != DeviceRevocationGateStatus::Active
    {
        return Ok(None);
    }
    serde_json::to_value(binding)
        .map(Some)
        .map_err(PersistenceError::database)
}

#[async_trait]
impl DeviceKeyStore for PgDeviceKeyStore {
    async fn put(
        &self,
        authorization: &DeviceRevocationGateSelector,
        payload: Value,
    ) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        conn.transaction::<_,PgTransactionError,_>(async move |conn| {
            crate::ensure_gate_allowed_in_transaction(conn,authorization).await?;
            let binding = serde_json::to_value(authorization).map_err(PersistenceError::database)?;
            sql_query("INSERT INTO device_keys(actor_id,device_id,device_authorization,payload,updated_at) VALUES($1,$2,$3,$4,NOW()) ON CONFLICT(actor_id,device_id) DO UPDATE SET device_authorization=EXCLUDED.device_authorization,payload=EXCLUDED.payload,updated_at=NOW()")
                .bind::<Text,_>(authorization.principal_id.as_str()).bind::<Text,_>(&authorization.device_id)
                .bind::<Jsonb,_>(binding).bind::<Jsonb,_>(payload).execute(conn).await?;
            Ok(())
        }).await.map_err(PgTransactionError::into_persistence)
    }

    async fn get(&self, actor: &str, device_id: &str) -> PersistenceResult<Option<Value>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        conn.transaction::<_,PgTransactionError,_>(async move |conn| {
            let Some(binding) = current_binding(conn,actor,device_id).await? else { return Ok(None); };
            Ok(sql_query("SELECT payload FROM device_keys WHERE actor_id=$1 AND device_id=$2 AND device_authorization=$3")
                .bind::<Text,_>(actor).bind::<Text,_>(device_id).bind::<Jsonb,_>(binding)
                .get_result::<JsonPayloadRow>(conn).await.optional()?.map(|r|r.payload))
        }).await.map_err(PgTransactionError::into_persistence)
    }
}

#[async_trait]
impl OneTimeKeyStore for PgOneTimeKeyStore {
    async fn put(
        &self,
        authorization: &DeviceRevocationGateSelector,
        keys: Vec<Value>,
    ) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        conn.transaction::<_,PgTransactionError,_>(async move |conn| {
            crate::ensure_gate_allowed_in_transaction(conn,authorization).await?;
            let binding = serde_json::to_value(authorization).map_err(PersistenceError::database)?;
            sql_query("DELETE FROM one_time_keys WHERE actor_id=$1 AND device_id=$2")
                .bind::<Text,_>(authorization.principal_id.as_str()).bind::<Text,_>(&authorization.device_id).execute(conn).await?;
            for (position,key) in keys.iter().enumerate() {
                let position = i32::try_from(position).map_err(|_|PersistenceError::SchemaViolation("one-time key pool exceeds capacity".into()))?;
                sql_query("INSERT INTO one_time_keys(actor_id,device_id,device_authorization,position,key) VALUES($1,$2,$3,$4,$5)")
                    .bind::<Text,_>(authorization.principal_id.as_str()).bind::<Text,_>(&authorization.device_id)
                    .bind::<Jsonb,_>(&binding).bind::<Integer,_>(position).bind::<Jsonb,_>(key).execute(conn).await?;
            }
            Ok(())
        }).await.map_err(PgTransactionError::into_persistence)
    }

    async fn claim(&self, actor: &str, device_id: &str) -> PersistenceResult<Option<Value>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        conn.transaction::<_,PgTransactionError,_>(async move |conn| {
            let Some(binding) = current_binding(conn,actor,device_id).await? else { return Ok(None); };
            Ok(sql_query("DELETE FROM one_time_keys WHERE (actor_id,device_id,position)=(SELECT actor_id,device_id,position FROM one_time_keys WHERE actor_id=$1 AND device_id=$2 AND device_authorization=$3 ORDER BY position DESC LIMIT 1 FOR UPDATE) RETURNING key AS payload")
                .bind::<Text,_>(actor).bind::<Text,_>(device_id).bind::<Jsonb,_>(binding)
                .get_result::<JsonPayloadRow>(conn).await.optional()?.map(|row|row.payload))
        }).await.map_err(PgTransactionError::into_persistence)
    }
}
