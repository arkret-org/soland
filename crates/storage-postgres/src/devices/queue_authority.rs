//! Queue reads, acknowledgements and writes retain the recipient's original
//! authorization. No artifact can be relabelled by a later same-device login.
use super::*;

pub(super) fn validate_recipient(message: &DeviceMessageRecord) -> PersistenceResult<()> {
    let source = &message.recipient_device_authorization;
    if source.principal_id.as_str() != message.recipient || source.device_id != message.device_id {
        return Err(PersistenceError::SchemaViolation(
            "queue recipient differs from its original authorization".into(),
        ));
    }
    Ok(())
}

async fn current_binding(
    conn: &mut diesel_async::AsyncPgConnection,
    recipient: &str,
    device_id: &str,
) -> PersistenceResult<Option<Value>> {
    let Some(binding) =
        crate::device_revocations::local_device_binding_in_transaction(conn, recipient, device_id)
            .await?
    else {
        return Ok(None);
    };
    if crate::gate_status_in_transaction(conn, &binding).await?
        != DeviceRevocationGateStatus::Active
    {
        return Ok(None);
    }
    serde_json::to_value(binding)
        .map(Some)
        .map_err(PersistenceError::database)
}

pub(super) async fn issue_ack_token(
    pool: &PgPool,
    recipient: &str,
    device_id: &str,
    queue_position: i64,
) -> PersistenceResult<Option<String>> {
    if queue_position <= 0 {
        return Ok(None);
    }
    let mut conn = pg_conn(pool).await.map_err(PersistenceError::database)?;
    conn.transaction::<_, PgTransactionError, _>(async move |conn| {
        let Some(binding) = current_binding(conn, recipient, device_id).await? else { return Ok(None); };
        // A cursor from an older instance cannot mint an acknowledgement for
        // the replacement instance. Bind to an actually delivered queue row.
        let exists = sql_query("SELECT EXISTS(SELECT 1 FROM device_messages WHERE recipient=$1 AND device_id=$2 AND position=$3 AND recipient_device_authorization=$4) AS present")
            .bind::<Text,_>(recipient).bind::<Text,_>(device_id).bind::<BigInt,_>(queue_position).bind::<Jsonb,_>(&binding)
            .get_result::<crate::ExistsRow>(conn).await?;
        if !exists.present { return Ok(None); }
        let token = fresh_device_message_ack_token();
        sql_query("INSERT INTO device_message_ack_tokens(ack_token,recipient,device_id,recipient_device_authorization,queue_position,issued_at,expires_at,consumed_at) VALUES($1,$2,$3,$4,$5,NOW(),$6,NULL)")
            .bind::<Text,_>(&token).bind::<Text,_>(recipient).bind::<Text,_>(device_id).bind::<Jsonb,_>(&binding)
            .bind::<BigInt,_>(queue_position).bind::<Timestamptz,_>(Utc::now()+chrono::Duration::hours(24)).execute(conn).await?;
        Ok(Some(token))
    }).await.map_err(PgTransactionError::into_persistence)
}

pub(super) async fn ack_with_token(
    pool: &PgPool,
    recipient: &str,
    device_id: &str,
    ack_token: &str,
) -> PersistenceResult<Option<usize>> {
    let mut conn = pg_conn(pool).await.map_err(PersistenceError::database)?;
    conn.transaction::<_, PgTransactionError, _>(async move |conn| {
        let Some(binding) = current_binding(conn, recipient, device_id).await? else { return Ok(None); };
        let token = sql_query("SELECT recipient,device_id,recipient_device_authorization,queue_position,expires_at,consumed_at FROM device_message_ack_tokens WHERE ack_token=$1 FOR UPDATE")
            .bind::<Text,_>(ack_token).get_result::<DeviceMessageAckTokenRow>(conn).await.optional()?;
        let Some(token) = token else { return Ok(None); };
        if token.recipient != recipient || token.device_id != device_id || token.recipient_device_authorization != binding || token.expires_at <= Utc::now() { return Ok(None); }
        if token.consumed_at.is_some() { return Ok(Some(0)); }
        let count = sql_query("DELETE FROM device_messages WHERE recipient=$1 AND device_id=$2 AND position<=$3 AND recipient_device_authorization=$4")
            .bind::<Text,_>(recipient).bind::<Text,_>(device_id).bind::<BigInt,_>(token.queue_position).bind::<Jsonb,_>(binding).execute(conn).await?;
        sql_query("UPDATE device_message_ack_tokens SET consumed_at=NOW() WHERE ack_token=$1 AND consumed_at IS NULL").bind::<Text,_>(ack_token).execute(conn).await?;
        Ok(Some(count))
    }).await.map_err(PgTransactionError::into_persistence)
}

pub(super) async fn list_after(
    pool: &PgPool,
    recipient: &str,
    device_id: &str,
    position: i64,
    limit: usize,
) -> PersistenceResult<Vec<DeviceMessageRecord>> {
    let mut conn = pg_conn(pool).await.map_err(PersistenceError::database)?;
    conn.transaction::<_, PgTransactionError, _>(async move |conn| {
        let Some(binding) = current_binding(conn, recipient, device_id).await? else { return Ok(vec![]); };
        let rows = sql_query("SELECT idempotency_key,sender,recipient,device_id,recipient_device_authorization,position,content,created_at FROM device_messages WHERE recipient=$1 AND device_id=$2 AND position>$3 AND recipient_device_authorization=$4 ORDER BY position ASC LIMIT $5")
            .bind::<Text,_>(recipient).bind::<Text,_>(device_id).bind::<BigInt,_>(position).bind::<Jsonb,_>(binding).bind::<BigInt,_>(limit.min(1001) as i64)
            .load::<DeviceMessageRow>(conn).await?;
        rows.into_iter().map(DeviceMessageRecord::try_from).collect::<PersistenceResult<Vec<_>>>().map_err(Into::into)
    }).await.map_err(PgTransactionError::into_persistence)
}
