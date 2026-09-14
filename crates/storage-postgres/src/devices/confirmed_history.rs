use super::*;

#[derive(QueryableByName)]
struct ConfirmedHead {
    #[diesel(sql_type = Text)]
    id: String,
}

#[derive(QueryableByName)]
struct StoredDeviceProjection {
    #[diesel(sql_type = Text)]
    device_id: String,
    #[diesel(sql_type = Text)]
    verification_state: String,
    #[diesel(sql_type = Jsonb)]
    payload: Value,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AtomicProjectionMode {
    Insert,
    ExactRetry,
}

fn control_root_refs(
    projection: &soland_storage::ConfirmedDeviceControlProjection,
) -> PersistenceResult<std::collections::BTreeMap<String, String>> {
    let history = projection.history();
    let mut roots = std::collections::BTreeMap::new();
    for root in projection.roots() {
        let arkret_models_collaboration::governance_dependencies::GovernanceDependency::AuthenticatedSignerResolutionEvidence {
            authenticated_signer_resolution_evidence,
            ..
        } = root
        else {
            return Err(PersistenceError::SchemaViolation(
                "confirmed device Control projection contains a non-signer dependency".into(),
            ));
        };
        let arkret_models_identity::AuthenticatedSignerResolutionEvidence::AccountDeviceControl {
            account_id,
            authorization_event_ref,
            confirmation_seal_ref,
            ..
        } = authenticated_signer_resolution_evidence.as_ref()
        else {
            return Err(PersistenceError::SchemaViolation(
                "confirmed device Control projection contains another signer evidence kind".into(),
            ));
        };
        let Some(authorization) = history.authorization(authorization_event_ref) else {
            return Err(PersistenceError::SchemaViolation(
                "confirmed device Control root has no matching authorization".into(),
            ));
        };
        if account_id != history.account_id()
            || confirmation_seal_ref != authorization.confirmed_seal()
        {
            return Err(PersistenceError::SchemaViolation(
                "confirmed device Control root differs from verified history".into(),
            ));
        }
        let evidence_ref = authenticated_signer_resolution_evidence
            .evidence_ref()
            .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
        if roots
            .insert(
                authorization_event_ref.to_string(),
                evidence_ref.as_ref().to_owned(),
            )
            .is_some()
        {
            return Err(PersistenceError::SchemaViolation(
                "confirmed device Control projection repeats an authorization root".into(),
            ));
        }
    }
    if roots.len() != history.authorizations().len() {
        return Err(PersistenceError::SchemaViolation(
            "confirmed device Control projection omits an authorization root".into(),
        ));
    }
    Ok(roots)
}

async fn require_local_station(
    conn: &mut AsyncPgConnection,
    history: &arkret::DeviceAuthorizationHistory,
) -> PersistenceResult<()> {
    let station =
        sql_query("SELECT station_id AS id FROM device_inventory_station WHERE singleton")
            .get_result::<ConfirmedHead>(&mut *conn)
            .await
            .map_err(PersistenceError::database)?;
    if station.id != history.account_id().station_id.as_str() {
        return Err(PersistenceError::Conflict(
            "device history belongs to another Station".into(),
        ));
    }
    Ok(())
}

async fn install_rows(
    conn: &mut AsyncPgConnection,
    history: &arkret::DeviceAuthorizationHistory,
    control_root_refs: Option<&std::collections::BTreeMap<String, String>>,
) -> PersistenceResult<()> {
    sql_query("UPDATE devices SET verification_state='unverified' WHERE actor_id=$1 AND payload ? 'device_authorize_event_id'")
        .bind::<Text, _>(history.account_id().principal_id.as_str()).execute(&mut *conn).await
        .map_err(PersistenceError::database)?;
    for authorization in history
        .authorizations()
        .iter()
        .filter(|a| history.is_currently_active(a))
    {
        let mut payload = serde_json::to_value(authorization.payload())
            .map_err(|e| PersistenceError::Internal(e.to_string()))?;
        let object = payload
            .as_object_mut()
            .ok_or_else(|| PersistenceError::Internal("device payload is not an object".into()))?;
        object.insert("device_authorize_projected".into(), Value::Bool(true));
        object.insert(
            "device_authorize_event_id".into(),
            Value::String(authorization.authorization_event_id().to_string()),
        );
        object.insert(
            "authorized_generation_ref".into(),
            serde_json::json!(authorization.authorized_generation_ref()),
        );
        object.insert(
            "generation_event_id".into(),
            Value::String(authorization.generation_event_id().to_string()),
        );
        object.insert(
            "confirmed_seal_id".into(),
            Value::String(authorization.confirmed_seal().to_string()),
        );
        if let Some(root_ref) = control_root_refs
            .and_then(|roots| roots.get(authorization.authorization_event_id().as_str()))
        {
            object.insert(
                "signer_resolution_evidence_ref".into(),
                Value::String(root_ref.clone()),
            );
        }
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
}

async fn verify_exact_rows(
    conn: &mut AsyncPgConnection,
    history: &arkret::DeviceAuthorizationHistory,
    roots: &std::collections::BTreeMap<String, String>,
) -> PersistenceResult<bool> {
    let marker = sql_query("SELECT confirmed_head AS id FROM device_history_projections WHERE principal_id=$1 AND station_id=$2 AND realm_id=$3")
        .bind::<Text,_>(history.account_id().principal_id.as_str())
        .bind::<Text,_>(history.account_id().station_id.as_str())
        .bind::<Text,_>(history.realm_id().as_str()).get_result::<ConfirmedHead>(&mut *conn).await.optional().map_err(PersistenceError::database)?;
    if marker.as_ref().map(|row| row.id.as_str()) != Some(history.confirmed_head().as_str()) {
        return Ok(false);
    }
    let rows = sql_query("SELECT device_id,verification_state,payload FROM devices WHERE actor_id=$1 AND payload ? 'device_authorize_event_id'")
        .bind::<Text,_>(history.account_id().principal_id.as_str())
        .load::<StoredDeviceProjection>(&mut *conn).await.map_err(PersistenceError::database)?;
    let active = history
        .authorizations()
        .iter()
        .filter(|authorization| history.is_currently_active(authorization))
        .map(|authorization| (authorization.device_id().as_str(), authorization))
        .collect::<std::collections::BTreeMap<_, _>>();
    for (device_id, authorization) in &active {
        let Some(row) = rows.iter().find(|row| row.device_id == *device_id) else {
            return Ok(false);
        };
        let root_ref = roots.get(authorization.authorization_event_id().as_str());
        if row.verification_state != "verified"
            || row
                .payload
                .get("device_authorize_event_id")
                .and_then(Value::as_str)
                != Some(authorization.authorization_event_id().as_str())
            || row
                .payload
                .get("authorized_generation_ref")
                .and_then(Value::as_u64)
                != Some(authorization.authorized_generation_ref())
            || row
                .payload
                .get("generation_event_id")
                .and_then(Value::as_str)
                != Some(authorization.generation_event_id().as_str())
            || row.payload.get("confirmed_seal_id").and_then(Value::as_str)
                != Some(authorization.confirmed_seal().as_str())
            || row
                .payload
                .get("signer_resolution_evidence_ref")
                .and_then(Value::as_str)
                != root_ref.map(String::as_str)
        {
            return Ok(false);
        }
    }
    Ok(rows.iter().all(|row| {
        active.contains_key(row.device_id.as_str()) || row.verification_state == "unverified"
    }))
}

pub(crate) async fn install_control_projection_in_transaction(
    conn: &mut AsyncPgConnection,
    projection: &soland_storage::ConfirmedDeviceControlProjection,
    mode: AtomicProjectionMode,
) -> PersistenceResult<()> {
    let history = projection.history();
    require_local_station(conn, history).await?;
    let roots = control_root_refs(projection)?;
    match mode {
        AtomicProjectionMode::Insert => {
            for root in projection.roots() {
                crate::put_unscoped_signer_evidence_exact_in_transaction(conn, root).await?;
            }
            install_rows(conn, history, Some(&roots)).await
        }
        AtomicProjectionMode::ExactRetry => {
            for root in projection.roots() {
                if !crate::unscoped_signer_evidence_matches_in_transaction(conn, root).await? {
                    return Err(PersistenceError::Conflict(
                        "duplicate_conflict: exact Seal replay is missing or differs from its account_device_control root".into(),
                    ));
                }
            }
            if !verify_exact_rows(conn, history, &roots).await? {
                return Err(PersistenceError::Conflict(
                    "duplicate_conflict: exact Seal replay is missing or differs from its device Control mapping".into(),
                ));
            }
            Ok(())
        }
    }
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
        require_local_station(conn, history).await?;
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
        install_rows(conn, history, None).await.map_err(Into::into)
    }).await.map_err(PgTransactionError::into_persistence)
}
