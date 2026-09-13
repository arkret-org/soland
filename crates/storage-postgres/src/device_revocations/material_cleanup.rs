//! Atomic destruction of one confirmed, immutable device authorization's
//! private artifacts. Completion is durable only with all effects below.
use super::*;

async fn intent(
    conn: &mut AsyncPgConnection,
    proposal_digest: &str,
    lock: bool,
) -> PersistenceResult<Option<CleanupRow>> {
    let query = "SELECT proposal_digest,proposal_event_id,covering_seal_id,principal_id,station_id,device_id, \
                 target_device_authorize_event_id,target_device_generation_ref,created_at, \
                 material_cleanup_completed_at,mls_obligation_completed_at \
                 FROM device_revocation_cleanup_intents WHERE proposal_digest=$1";
    let query = if lock {
        format!("{query} FOR UPDATE")
    } else {
        query.to_owned()
    };
    sql_query(query)
        .bind::<Text, _>(proposal_digest)
        .get_result::<CleanupRow>(conn)
        .await
        .optional()
        .map_err(PersistenceError::database)
}

pub(super) async fn cleanup(
    pool: &PgPool,
    proposal_digest: &str,
    completed_at: chrono::DateTime<Utc>,
) -> PersistenceResult<bool> {
    let mut conn = pg_conn(pool).await.map_err(PersistenceError::database)?;
    conn.transaction::<_,PgTransactionError,_>(async move |conn| {
        let Some(source) = intent(conn,proposal_digest,false).await? else { return Ok(false); };
        // Artifact writers use this same immutable account/device lock before
        // touching their rows. The cleanup intent is never caller-supplied.
        ensure_head_locked(conn,source.principal_id.as_str(),source.station_id.as_str(),&source.device_id).await?;
        let source = intent(conn,proposal_digest,true).await?.ok_or_else(|| PersistenceError::Conflict("confirmed cleanup intent disappeared".into()))?;
        if source.material_cleanup_completed_at.is_some() { return Ok(false); }
        let selector = DeviceRevocationGateSelector {
            principal_id: source.principal_id.clone(), station_id: source.station_id.clone(),
            device_id: source.device_id.clone(), target_device_authorize_event_id: source.target_device_authorize_event_id.clone(),
            target_device_generation_ref: u64::try_from(source.target_device_generation_ref).map_err(|_|PersistenceError::SchemaViolation("negative device generation".into()))?,
        };
        let binding = serde_json::to_value(&selector).map_err(PersistenceError::database)?;
        sql_query("UPDATE sessions SET revoked_at=COALESCE(revoked_at,$2),updated_at=$2 WHERE payload->'device_authorization'=$1")
            .bind::<Jsonb,_>(&binding).bind::<Timestamptz,_>(completed_at).execute(conn).await?;
        // Preserve consumed packages and their immutable leaf-source evidence.
        // Both ordinary and last-resort unconsumed packages become unusable.
        let authorize_token = soland_storage::ids::event_token_part_or_schema_violation(&source.target_device_authorize_event_id,"event")?;
        sql_query("UPDATE mls_key_packages k SET claimed_by_mls_group_id='revoked',claimed_at=NULL,claim_expires_at_unix_ms=NULL \
                   FROM accounts a WHERE k.owner_account_pk=a.pk AND a.principal_id=$1 AND a.station_id=$2 AND k.actor_id=$1 AND k.device_id=$3 \
                   AND k.device_authorize_event_id=$4 AND k.consumed_at IS NULL AND k.claimed_by_mls_group_id IS DISTINCT FROM 'retired'")
            .bind::<Text,_>(source.principal_id.as_str()).bind::<Text,_>(source.station_id.as_str()).bind::<Text,_>(&source.device_id)
            .bind::<Binary,_>(authorize_token.to_vec()).execute(conn).await?;
        // These are private source columns, never fields inside public payloads.
        sql_query("DELETE FROM device_keys WHERE device_authorization=$1").bind::<Jsonb,_>(&binding).execute(conn).await?;
        sql_query("DELETE FROM one_time_keys WHERE device_authorization=$1").bind::<Jsonb,_>(&binding).execute(conn).await?;
        sql_query("DELETE FROM device_message_ack_tokens WHERE recipient_device_authorization=$1").bind::<Jsonb,_>(&binding).execute(conn).await?;
        sql_query("DELETE FROM device_messages WHERE recipient_device_authorization=$1").bind::<Jsonb,_>(&binding).execute(conn).await?;
        sql_query("DELETE FROM push_devices WHERE device_authorization=$1").bind::<Jsonb,_>(&binding).execute(conn).await?;
        let affected = sql_query("UPDATE device_revocation_cleanup_intents SET material_cleanup_completed_at=$2 WHERE proposal_digest=$1 AND material_cleanup_completed_at IS NULL")
            .bind::<Text,_>(proposal_digest).bind::<Timestamptz,_>(completed_at).execute(conn).await?;
        Ok(affected == 1)
    }).await.map_err(PgTransactionError::into_persistence)
}
