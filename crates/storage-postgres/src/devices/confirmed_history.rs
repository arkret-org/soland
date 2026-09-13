use super::*;

#[derive(QueryableByName)]
struct ConfirmedHead {
    #[diesel(sql_type = Text)]
    id: String,
}

pub(super) async fn install(
    pool: &PgPool,
    history: &arkret::DeviceAuthorizationHistory,
) -> PersistenceResult<()> {
    let mut conn = pg_conn(pool).await.map_err(PersistenceError::database)?;
    conn.transaction::<_, PgTransactionError, _>(async move |conn| {
        sql_query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
            .bind::<Text, _>(history.realm_id().as_str()).execute(&mut *conn).await
            .map_err(PersistenceError::database)?;
        let station = sql_query("SELECT station_id AS id FROM device_inventory_station WHERE singleton")
            .get_result::<ConfirmedHead>(&mut *conn).await.map_err(PersistenceError::database)?;
        if station.id != history.account_id().station_id.as_str() {
            return Err(PersistenceError::Conflict("device history belongs to another Station".into()).into());
        }
        let heads = sql_query(
            "SELECT parent.id FROM state_seals parent WHERE parent.realm_id=$1 \
             AND NOT EXISTS (SELECT 1 FROM state_seal_quarantine_realms q WHERE q.realm_id=$1) \
             AND NOT EXISTS (SELECT 1 FROM state_seals child WHERE child.realm_id=$1 AND child.predecessor_ref=parent.id)"
        ).bind::<Text, _>(history.realm_id().as_str()).load::<ConfirmedHead>(&mut *conn).await
            .map_err(PersistenceError::database)?;
        if heads.len() != 1 || heads[0].id != history.confirmed_head().as_str() {
            return Err(PersistenceError::Conflict("confirmed device history head advanced or is quarantined".into()).into());
        }
        let installed = sql_query("SELECT confirmed_head AS id FROM device_history_projections WHERE principal_id=$1 AND station_id=$2 AND realm_id=$3")
            .bind::<Text,_>(history.account_id().principal_id.as_str())
            .bind::<Text,_>(history.account_id().station_id.as_str())
            .bind::<Text,_>(history.realm_id().as_str()).get_result::<ConfirmedHead>(&mut *conn).await.optional().map_err(PersistenceError::database)?;
        if installed.is_some_and(|installed| installed.id == history.confirmed_head().as_str()) { return Ok(()); }
        // This transaction may be resumed with the same complete history.
        // Old instances become unusable before any replacement becomes active;
        // never update old authorization coordinates to today's generation.
        sql_query("UPDATE devices SET verification_state='unverified' WHERE actor_id=$1 AND payload ? 'device_authorize_event_id'")
            .bind::<Text, _>(history.account_id().principal_id.as_str()).execute(&mut *conn).await
            .map_err(PersistenceError::database)?;
        for authorization in history.authorizations().iter().filter(|a| history.is_currently_active(a)) {
            let evidence = history
                .control_signer_evidence(authorization.authorization_event_id())
                .map_err(|error| PersistenceError::Internal(error.to_string()))?;
            let content_digest = evidence
                .canonical_sha256_digest()
                .map_err(|error| PersistenceError::Internal(error.to_string()))?;
            let evidence_ref = evidence
                .evidence_ref()
                .map_err(|error| PersistenceError::Internal(error.to_string()))?;
            crate::governance_history::put_unscoped_signer_evidence_exact_in_transaction(
                conn,
                arkret_models_collaboration::governance_dependencies::GovernanceDependency::AuthenticatedSignerResolutionEvidence {
                    selector: arkret_models_collaboration::governance_dependencies::GovernanceDependencySelector::AuthenticatedSignerResolutionEvidence { content_digest },
                    authenticated_signer_resolution_evidence: Box::new(evidence),
                },
            )
            .await?;
            let mut payload = serde_json::to_value(authorization.payload()).map_err(|e| PersistenceError::Internal(e.to_string()))?;
            let object = payload.as_object_mut().ok_or_else(|| PersistenceError::Internal("device payload is not an object".into()))?;
            object.insert("device_authorize_projected".into(), Value::Bool(true));
            object.insert("device_authorize_event_id".into(), Value::String(authorization.authorization_event_id().to_string()));
            object.insert("authorized_generation_ref".into(), serde_json::json!(authorization.authorized_generation_ref()));
            object.insert("generation_event_id".into(), Value::String(authorization.generation_event_id().to_string()));
            object.insert("confirmed_seal_id".into(), Value::String(history.confirmed_head().to_string()));
            object.insert(
                "signer_resolution_evidence_ref".into(),
                Value::String(evidence_ref.as_ref().to_owned()),
            );
            sql_query(
                "INSERT INTO devices(id,actor_id,device_id,payload,verification_state,created_at,updated_at,revoked_at) \
                 VALUES($1,$2,$3,$4,'verified',$5,$6,NULL) \
                 ON CONFLICT(actor_id,device_id) DO UPDATE SET \
                 payload=EXCLUDED.payload || jsonb_strip_nulls(jsonb_build_object('display_name',devices.payload->'display_name','last_seen_at',devices.payload->'last_seen_at','last_key_upload_at',devices.payload->'last_key_upload_at')), \
                 verification_state='verified',updated_at=EXCLUDED.updated_at,revoked_at=CASE WHEN devices.payload->>'device_authorize_event_id'=EXCLUDED.payload->>'device_authorize_event_id' THEN devices.revoked_at ELSE NULL END"
            ).bind::<sql_types::Uuid,_>(Uuid::now_v7())
                .bind::<Text,_>(history.account_id().principal_id.as_str())
                .bind::<Text,_>(authorization.device_id().as_str())
                .bind::<Jsonb,_>(payload)
                .bind::<Timestamptz,_>(authorization.event().created_at)
                .bind::<Timestamptz,_>(authorization.sealed_at())
                .execute(&mut *conn).await.map_err(PersistenceError::database)?;
        }
        sql_query("INSERT INTO device_history_projections(principal_id,station_id,realm_id,confirmed_head) VALUES($1,$2,$3,$4) ON CONFLICT(principal_id,station_id) DO UPDATE SET realm_id=EXCLUDED.realm_id,confirmed_head=EXCLUDED.confirmed_head")
            .bind::<Text,_>(history.account_id().principal_id.as_str()).bind::<Text,_>(history.account_id().station_id.as_str())
            .bind::<Text,_>(history.realm_id().as_str()).bind::<Text,_>(history.confirmed_head().as_str())
            .execute(&mut *conn).await.map_err(PersistenceError::database)?;
        Ok(())
    }).await.map_err(PgTransactionError::into_persistence)
}
