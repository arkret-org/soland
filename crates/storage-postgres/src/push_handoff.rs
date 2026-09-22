use arkret_models_integration::{
    PushRegistrationHandoffRequestBody, PushRegistrationId, PushRegistrationInstallationReceipt,
    PushRegistrationRecord,
};
use arkret_wire::{AccountId, DeviceId, DidCoreId, Hash};

use super::{
    AsyncConnection, AsyncPgConnection, BigInt, Binary, Jsonb, Nullable, OptionalExtension,
    PersistenceError, PersistenceResult, PgPool, PgTransactionError,
    PushRegistrationHandoffIntentRecord, PushRegistrationHandoffIntentStatus,
    PushRegistrationHandoffIntentWrite, PushRegistrationHandoffReceiptWrite,
    PushRegistrationHandoffRetryCursor, PushRegistrationHandoffRouteLocator,
    PushRegistrationHandoffStore, QueryableByName, RunQueryDsl, Text, Timestamptz, Value,
    apply_push_registration_desired_intent, apply_verified_push_registration_receipt, async_trait,
    pg_conn, sql_query,
};
use crate::push::{
    PushDeviceRouteWriteMode, push_device_lock_key, write_push_device_route_in_transaction,
};

pub struct PgPushRegistrationHandoffStore {
    pub pool: PgPool,
}

#[derive(QueryableByName)]
struct CurrentPushRouteRow {
    #[diesel(sql_type = Jsonb)]
    payload: Value,
    #[diesel(sql_type = Jsonb)]
    device_authorization: Value,
}

#[derive(QueryableByName)]
struct HandoffIntentRow {
    #[diesel(sql_type = Text)]
    source_station_id: DidCoreId,
    #[diesel(sql_type = Jsonb)]
    local_account_id: Value,
    #[diesel(sql_type = Text)]
    local_device_id: String,
    #[diesel(sql_type = Text)]
    local_push_route_id: String,
    #[diesel(sql_type = Jsonb)]
    device_authorization: Value,
    #[diesel(sql_type = Text)]
    registration_id: String,
    #[diesel(sql_type = Text)]
    destination_gateway_id: DidCoreId,
    #[diesel(sql_type = Text)]
    desired_state: String,
    #[diesel(sql_type = Text)]
    request_digest: String,
    #[diesel(sql_type = Text)]
    client_input_digest: String,
    #[diesel(sql_type = Binary)]
    canonical_request: Vec<u8>,
    #[diesel(sql_type = Text)]
    status: String,
    #[diesel(sql_type = Nullable<Jsonb>)]
    receipt: Option<Value>,
    #[diesel(sql_type = Timestamptz)]
    created_at: chrono::DateTime<chrono::Utc>,
    #[diesel(sql_type = Timestamptz)]
    updated_at: chrono::DateTime<chrono::Utc>,
}

impl TryFrom<HandoffIntentRow> for PushRegistrationHandoffIntentRecord {
    type Error = PersistenceError;

    fn try_from(row: HandoffIntentRow) -> Result<Self, Self::Error> {
        let local_route = PushRegistrationHandoffRouteLocator {
            account_id: serde_json::from_value(row.local_account_id).map_err(|error| {
                PersistenceError::Internal(format!(
                    "stored push registration handoff local account is invalid: {error}"
                ))
            })?,
            device_id: arkret_wire::DeviceId::new(row.local_device_id)
                .map_err(|error| PersistenceError::Internal(error.to_string()))?,
            push_route_id: row.local_push_route_id,
            destination_gateway_id: row.destination_gateway_id.clone(),
        };
        let record = Self {
            source_station_id: row.source_station_id,
            local_route,
            device_authorization: serde_json::from_value(row.device_authorization).map_err(
                |error| {
                    PersistenceError::Internal(format!(
                        "stored push handoff device authorization is invalid: {error}"
                    ))
                },
            )?,
            client_input_digest: Hash::new(row.client_input_digest)
                .map_err(|error| PersistenceError::Internal(error.to_string()))?,
            destination_gateway_id: row.destination_gateway_id,
            registration_id: PushRegistrationId::new(row.registration_id)
                .map_err(|error| PersistenceError::Internal(error.to_string()))?,
            desired_state: serde_json::from_value(Value::String(row.desired_state)).map_err(
                |error| {
                    PersistenceError::Internal(format!(
                        "stored push registration handoff desired state is invalid: {error}"
                    ))
                },
            )?,
            request_digest: Hash::new(row.request_digest)
                .map_err(|error| PersistenceError::Internal(error.to_string()))?,
            canonical_request: row.canonical_request,
            status: match row.status.as_str() {
                "awaiting_receipt" => PushRegistrationHandoffIntentStatus::AwaitingReceipt,
                "receipt_verified" => PushRegistrationHandoffIntentStatus::ReceiptVerified,
                _ => {
                    return Err(PersistenceError::Internal(format!(
                        "stored push registration handoff status is invalid: {}",
                        row.status
                    )));
                }
            },
            receipt: row
                .receipt
                .map(serde_json::from_value)
                .transpose()
                .map_err(|error| {
                    PersistenceError::Internal(format!(
                        "stored push registration handoff receipt is invalid: {error}"
                    ))
                })?,
            created_at: row.created_at,
            updated_at: row.updated_at,
        };
        record.validate()?;
        Ok(record)
    }
}

const HANDOFF_COLUMNS: &str = "source_station_id, local_account_id, local_device_id, \
    local_push_route_id, device_authorization, registration_id, destination_gateway_id, \
    desired_state, request_digest, client_input_digest, canonical_request, status, receipt, \
    created_at, updated_at";

async fn load_intent(
    conn: &mut AsyncPgConnection,
    source_station_id: &DidCoreId,
    registration_id: &PushRegistrationId,
    for_update: bool,
) -> PersistenceResult<Option<PushRegistrationHandoffIntentRecord>> {
    let suffix = if for_update { " FOR UPDATE" } else { "" };
    let query = format!(
        "SELECT {HANDOFF_COLUMNS} FROM push_registration_handoff_intents \
         WHERE source_station_id = $1 AND registration_id = $2{suffix}"
    );
    sql_query(query)
        .bind::<Text, _>(source_station_id)
        .bind::<Text, _>(registration_id.as_str())
        .get_result::<HandoffIntentRow>(conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?
        .map(TryInto::try_into)
        .transpose()
}

async fn load_local_route_intent(
    conn: &mut AsyncPgConnection,
    source_station_id: &DidCoreId,
    local_route: &PushRegistrationHandoffRouteLocator,
    for_update: bool,
) -> PersistenceResult<Option<PushRegistrationHandoffIntentRecord>> {
    let suffix = if for_update { " FOR UPDATE" } else { "" };
    let account_id =
        serde_json::to_value(&local_route.account_id).map_err(PersistenceError::database)?;
    let query = format!(
        "SELECT {HANDOFF_COLUMNS} FROM push_registration_handoff_intents \
         WHERE source_station_id = $1 AND local_account_id = $2 \
           AND local_device_id = $3 AND local_push_route_id = $4 \
           AND destination_gateway_id = $5 \
         ORDER BY (status = 'awaiting_receipt') DESC, updated_at DESC, registration_id DESC \
         LIMIT 1{suffix}"
    );
    sql_query(query)
        .bind::<Text, _>(source_station_id)
        .bind::<Jsonb, _>(&account_id)
        .bind::<Text, _>(local_route.device_id.as_str())
        .bind::<Text, _>(&local_route.push_route_id)
        .bind::<Text, _>(&local_route.destination_gateway_id)
        .get_result::<HandoffIntentRow>(conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?
        .map(TryInto::try_into)
        .transpose()
}

fn local_route_lock_key(
    source_station_id: &DidCoreId,
    local_route: &PushRegistrationHandoffRouteLocator,
) -> PersistenceResult<String> {
    let canonical = arkret_canonical::canonical::canonical_json_bytes(&serde_json::json!({
        "source_station_id": source_station_id,
        "local_route": local_route,
    }))
    .map_err(PersistenceError::database)?;
    Ok(format!(
        "push-registration-handoff:{}",
        arkret_canonical::sha256_hex(canonical)
    ))
}

async fn store_receipt_transition(
    conn: &mut AsyncPgConnection,
    source_station_id: &DidCoreId,
    registration_id: &PushRegistrationId,
    expected_request_digest: &Hash,
    outcome: &PushRegistrationHandoffReceiptWrite,
) -> PersistenceResult<()> {
    let PushRegistrationHandoffReceiptWrite::Stored(committed) = outcome else {
        return Ok(());
    };
    let receipt_json = serde_json::to_value(
        committed
            .receipt
            .as_ref()
            .expect("stored receipt transition carries a receipt"),
    )
    .map_err(PersistenceError::database)?;
    let updated = sql_query(
        "UPDATE push_registration_handoff_intents \
         SET status = $4, receipt = $5, updated_at = $6 \
         WHERE source_station_id = $1 AND registration_id = $2 \
           AND request_digest = $3 AND status = 'awaiting_receipt' AND receipt IS NULL",
    )
    .bind::<Text, _>(source_station_id)
    .bind::<Text, _>(registration_id.as_str())
    .bind::<Text, _>(expected_request_digest.as_str())
    .bind::<Text, _>(committed.status.as_str())
    .bind::<Jsonb, _>(&receipt_json)
    .bind::<Timestamptz, _>(committed.updated_at)
    .execute(conn)
    .await
    .map_err(PersistenceError::database)?;
    if updated != 1 {
        return Err(PersistenceError::Conflict(
            "cas_conflict: push registration handoff receipt state changed".to_owned(),
        ));
    }
    Ok(())
}

fn active_request_matches_filters(
    request: &PushRegistrationHandoffRequestBody,
    push_key: Option<&str>,
    app_id: Option<&str>,
) -> bool {
    let PushRegistrationHandoffRequestBody::Active {
        push_key: request_push_key,
        app_id: request_app_id,
        ..
    } = request
    else {
        return false;
    };
    push_key.is_none_or(|expected| expected == request_push_key.as_str())
        && app_id.is_none_or(|expected| Some(expected) == request_app_id.as_deref())
}

fn public_unregistration_input_digest(
    account_id: &AccountId,
    device_id: &DeviceId,
    push_key: Option<&str>,
    app_id: Option<&str>,
) -> PersistenceResult<Hash> {
    let input = serde_json::json!({
        "account_id": account_id,
        "device_id": device_id,
        "push_key": push_key,
        "app_id": app_id,
    });
    Hash::new(arkret_canonical::canonical_sha256(&input).map_err(PersistenceError::database)?)
        .map_err(|error| PersistenceError::Internal(error.to_string()))
}

async fn advance_active_intent_to_revoked(
    conn: &mut AsyncPgConnection,
    stored: &PushRegistrationHandoffIntentRecord,
    client_input_digest: &Hash,
    now: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<PushRegistrationHandoffIntentRecord> {
    let active = stored.request()?;
    let PushRegistrationHandoffRequestBody::Active {
        push_target_id,
        device_id,
        ..
    } = active
    else {
        return Err(PersistenceError::Conflict(
            "cas_conflict: public push handoff is not active".to_owned(),
        ));
    };
    let revoke_request = PushRegistrationHandoffRequestBody::Revoked {
        registration_id: stored.registration_id.clone(),
        push_target_id,
        device_id,
    };
    let candidate = PushRegistrationHandoffIntentRecord::prepare(
        stored.source_station_id.clone(),
        stored.local_route.clone(),
        stored.device_authorization.clone(),
        client_input_digest.clone(),
        &revoke_request,
        now,
    )?;
    let outcome = apply_push_registration_desired_intent(stored, &candidate)?;
    let PushRegistrationHandoffIntentWrite::AdvancedToRevoked(revoked) = outcome else {
        return Err(PersistenceError::Conflict(
            "cas_conflict: public push handoff did not advance to revoked".to_owned(),
        ));
    };
    let updated = sql_query(
        "UPDATE push_registration_handoff_intents \
         SET desired_state = $5, request_digest = $6, client_input_digest = $7, \
             canonical_request = $8, status = $9, receipt = NULL, updated_at = $10 \
         WHERE source_station_id = $1 AND registration_id = $2 \
           AND destination_gateway_id = $3 AND request_digest = $4 \
           AND desired_state = 'active'",
    )
    .bind::<Text, _>(&stored.source_station_id)
    .bind::<Text, _>(stored.registration_id.as_str())
    .bind::<Text, _>(&stored.destination_gateway_id)
    .bind::<Text, _>(stored.request_digest.as_str())
    .bind::<Text, _>(revoked.desired_state.as_str())
    .bind::<Text, _>(revoked.request_digest.as_str())
    .bind::<Text, _>(revoked.client_input_digest.as_str())
    .bind::<Binary, _>(&revoked.canonical_request)
    .bind::<Text, _>(revoked.status.as_str())
    .bind::<Timestamptz, _>(revoked.updated_at)
    .execute(conn)
    .await
    .map_err(PersistenceError::database)?;
    if updated != 1 {
        return Err(PersistenceError::Conflict(
            "cas_conflict: public push handoff changed during unregistration".to_owned(),
        ));
    }
    Ok(revoked)
}

#[async_trait]
impl PushRegistrationHandoffStore for PgPushRegistrationHandoffStore {
    async fn ensure_desired_intent(
        &self,
        source_station_id: &DidCoreId,
        local_route: &PushRegistrationHandoffRouteLocator,
        device_authorization: &soland_storage::DeviceRevocationGateSelector,
        client_input_digest: &Hash,
        request: &PushRegistrationHandoffRequestBody,
        now: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<PushRegistrationHandoffIntentWrite> {
        let candidate = PushRegistrationHandoffIntentRecord::prepare(
            source_station_id.clone(),
            local_route.clone(),
            device_authorization.clone(),
            client_input_digest.clone(),
            request,
            now,
        )?;
        let account_lock_key = push_device_lock_key(
            &candidate.local_route.account_id,
            candidate.local_route.device_id.as_str(),
        );
        let route_lock_key = local_route_lock_key(source_station_id, local_route)?;
        let mut conn = pg_conn(&self.pool).await?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            sql_query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
                .bind::<Text, _>(&account_lock_key)
                .execute(conn)
                .await?;
            sql_query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
                .bind::<Text, _>(&route_lock_key)
                .execute(conn)
                .await?;

            if let Some(stored) = load_intent(
                conn,
                &candidate.source_station_id,
                &candidate.registration_id,
                true,
            )
            .await?
            {
                let outcome = apply_push_registration_desired_intent(&stored, &candidate)?;
                let PushRegistrationHandoffIntentWrite::AdvancedToRevoked(revoked) = &outcome
                else {
                    return Ok(outcome);
                };
                let updated = sql_query(
                    "UPDATE push_registration_handoff_intents \
                     SET desired_state = $5, request_digest = $6, client_input_digest = $7, \
                         canonical_request = $8, status = $9, receipt = NULL, updated_at = $10 \
                     WHERE source_station_id = $1 AND registration_id = $2 \
                       AND destination_gateway_id = $3 AND request_digest = $4 \
                       AND desired_state = 'active'",
                )
                .bind::<Text, _>(&stored.source_station_id)
                .bind::<Text, _>(stored.registration_id.as_str())
                .bind::<Text, _>(&stored.destination_gateway_id)
                .bind::<Text, _>(stored.request_digest.as_str())
                .bind::<Text, _>(revoked.desired_state.as_str())
                .bind::<Text, _>(revoked.request_digest.as_str())
                .bind::<Text, _>(revoked.client_input_digest.as_str())
                .bind::<Binary, _>(&revoked.canonical_request)
                .bind::<Text, _>(revoked.status.as_str())
                .bind::<Timestamptz, _>(revoked.updated_at)
                .execute(conn)
                .await?;
                if updated != 1 {
                    return Err(PersistenceError::Conflict(
                        "cas_conflict: push registration handoff desired state changed".to_owned(),
                    )
                    .into());
                }
                return Ok(outcome);
            }

            if let Some(stored) = load_local_route_intent(
                conn,
                &candidate.source_station_id,
                &candidate.local_route,
                true,
            )
            .await?
                && stored.status == PushRegistrationHandoffIntentStatus::AwaitingReceipt
            {
                if stored.client_input_digest == candidate.client_input_digest
                    && stored.desired_state == candidate.desired_state
                {
                    return Ok(PushRegistrationHandoffIntentWrite::ExactReplay(stored));
                }
                return Err(PersistenceError::Conflict(
                    "cas_conflict: push handoff local route already has another awaiting client intent"
                        .to_owned(),
                )
                .into());
            }

            let inserted = sql_query(
                "INSERT INTO push_registration_handoff_intents \
                 (source_station_id, local_account_id, local_device_id, local_push_route_id, \
                  device_authorization, registration_id, destination_gateway_id, desired_state, \
                  request_digest, client_input_digest, canonical_request, status, receipt, \
                  created_at, updated_at) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, NULL, $13, $13) \
                 ON CONFLICT (source_station_id, registration_id) DO NOTHING",
            )
            .bind::<Text, _>(&candidate.source_station_id)
            .bind::<Jsonb, _>(
                serde_json::to_value(&candidate.local_route.account_id)
                    .map_err(PersistenceError::database)?,
            )
            .bind::<Text, _>(candidate.local_route.device_id.as_str())
            .bind::<Text, _>(&candidate.local_route.push_route_id)
            .bind::<Jsonb, _>(
                serde_json::to_value(&candidate.device_authorization)
                    .map_err(PersistenceError::database)?,
            )
            .bind::<Text, _>(candidate.registration_id.as_str())
            .bind::<Text, _>(&candidate.destination_gateway_id)
            .bind::<Text, _>(candidate.desired_state.as_str())
            .bind::<Text, _>(candidate.request_digest.as_str())
            .bind::<Text, _>(candidate.client_input_digest.as_str())
            .bind::<Binary, _>(&candidate.canonical_request)
            .bind::<Text, _>(candidate.status.as_str())
            .bind::<Timestamptz, _>(candidate.created_at)
            .execute(conn)
            .await?;
            if inserted == 1 {
                return Ok(PushRegistrationHandoffIntentWrite::Created(candidate));
            }
            let stored = load_intent(
                conn,
                &candidate.source_station_id,
                &candidate.registration_id,
                true,
            )
            .await?
            .ok_or_else(|| {
                PersistenceError::Internal(
                    "push registration handoff conflict row disappeared".to_owned(),
                )
            })?;
            apply_push_registration_desired_intent(&stored, &candidate).map_err(Into::into)
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }

    async fn get_intent(
        &self,
        source_station_id: &DidCoreId,
        registration_id: &PushRegistrationId,
    ) -> PersistenceResult<Option<PushRegistrationHandoffIntentRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        load_intent(&mut conn, source_station_id, registration_id, false).await
    }

    async fn lookup_local_route_intent(
        &self,
        source_station_id: &DidCoreId,
        local_route: &PushRegistrationHandoffRouteLocator,
    ) -> PersistenceResult<Option<PushRegistrationHandoffIntentRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        load_local_route_intent(&mut conn, source_station_id, local_route, false).await
    }

    async fn commit_verified_receipt(
        &self,
        source_station_id: &DidCoreId,
        registration_id: &PushRegistrationId,
        expected_request_digest: &Hash,
        receipt: &PushRegistrationInstallationReceipt,
        now: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<PushRegistrationHandoffReceiptWrite> {
        let source_station_id = source_station_id.clone();
        let registration_id = registration_id.clone();
        let expected_request_digest = expected_request_digest.clone();
        let receipt = receipt.clone();
        let mut conn = pg_conn(&self.pool).await?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            let record = load_intent(conn, &source_station_id, &registration_id, true)
                .await?
                .ok_or_else(|| {
                    PersistenceError::NotFound(
                        "push registration handoff desired intent".to_owned(),
                    )
                })?;
            let outcome = apply_verified_push_registration_receipt(
                &record,
                &expected_request_digest,
                &receipt,
                now,
            )?;
            store_receipt_transition(
                conn,
                &source_station_id,
                &registration_id,
                &expected_request_digest,
                &outcome,
            )
            .await?;
            Ok(outcome)
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }

    async fn begin_public_push_unregistration(
        &self,
        account_id: &AccountId,
        device_id: &DeviceId,
        push_key: Option<&str>,
        app_id: Option<&str>,
        now: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<Vec<PushRegistrationHandoffIntentRecord>> {
        account_id
            .validate()
            .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
        let revoke_input_digest =
            public_unregistration_input_digest(account_id, device_id, push_key, app_id)?;
        let account_id = account_id.clone();
        let device_id = device_id.clone();
        let push_key = push_key.map(str::to_owned);
        let app_id = app_id.map(str::to_owned);
        let account_json = serde_json::to_value(&account_id).map_err(PersistenceError::database)?;
        let account_lock_key = push_device_lock_key(&account_id, device_id.as_str());
        let mut conn = pg_conn(&self.pool).await?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            // The active-receipt UOW takes the same account/device lock before
            // handoff route and intent locks, so replacement and revoke cannot
            // deadlock or make a deleted route deliverable again.
            sql_query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
                .bind::<Text, _>(&account_lock_key)
                .execute(&mut *conn)
                .await?;
            let routes = sql_query(
                "SELECT payload, device_authorization FROM push_devices \
                 WHERE payload->'account_id' = $1 AND device_id = $2 \
                   AND ($3 IS NULL OR push_key = $3) \
                   AND ($4 IS NULL OR app_id = $4) \
                 ORDER BY payload->>'push_route_id', id",
            )
            .bind::<Jsonb, _>(&account_json)
            .bind::<Text, _>(device_id.as_str())
            .bind::<Nullable<Text>, _>(push_key.as_deref())
            .bind::<Nullable<Text>, _>(app_id.as_deref())
            .load::<CurrentPushRouteRow>(&mut *conn)
            .await?;
            let awaiting_query = format!(
                "SELECT {HANDOFF_COLUMNS} FROM push_registration_handoff_intents \
                 WHERE source_station_id = $1 AND local_account_id = $2 \
                   AND local_device_id = $3 AND desired_state = 'active' \
                   AND status = 'awaiting_receipt' \
                 ORDER BY local_push_route_id, destination_gateway_id, registration_id"
            );
            let awaiting = sql_query(awaiting_query)
                .bind::<Text, _>(&account_id.station_id)
                .bind::<Jsonb, _>(&account_json)
                .bind::<Text, _>(device_id.as_str())
                .load::<HandoffIntentRow>(&mut *conn)
                .await?;
            let replay_query = format!(
                "SELECT {HANDOFF_COLUMNS} FROM push_registration_handoff_intents \
                 WHERE source_station_id = $1 AND local_account_id = $2 \
                   AND local_device_id = $3 AND desired_state = 'revoked' \
                   AND status = 'awaiting_receipt' AND client_input_digest = $4 \
                 ORDER BY local_push_route_id, destination_gateway_id, registration_id"
            );
            let mut revoked = sql_query(replay_query)
                .bind::<Text, _>(&account_id.station_id)
                .bind::<Jsonb, _>(&account_json)
                .bind::<Text, _>(device_id.as_str())
                .bind::<Text, _>(revoke_input_digest.as_str())
                .load::<HandoffIntentRow>(&mut *conn)
                .await?
                .into_iter()
                .map(TryInto::try_into)
                .collect::<PersistenceResult<Vec<_>>>()?;
            for snapshot in awaiting {
                let snapshot: PushRegistrationHandoffIntentRecord = snapshot.try_into()?;
                let request = snapshot.request()?;
                if !active_request_matches_filters(
                    &request,
                    push_key.as_deref(),
                    app_id.as_deref(),
                ) {
                    continue;
                }
                let route_lock_key =
                    local_route_lock_key(&account_id.station_id, &snapshot.local_route)?;
                sql_query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
                    .bind::<Text, _>(&route_lock_key)
                    .execute(&mut *conn)
                    .await?;
                let stored = load_intent(
                    conn,
                    &account_id.station_id,
                    &snapshot.registration_id,
                    true,
                )
                .await?
                .ok_or_else(|| {
                    PersistenceError::Conflict(
                        "cas_conflict: pending public push handoff disappeared during unregistration"
                            .to_owned(),
                    )
                })?;
                if stored.local_route != snapshot.local_route
                    || stored.local_route.account_id != account_id
                    || stored.local_route.device_id != device_id
                    || stored.desired_state
                        != arkret_models_integration::PushRegistrationHandoffState::Active
                {
                    return Err(PersistenceError::Conflict(
                        "cas_conflict: pending public push handoff changed during unregistration"
                            .to_owned(),
                    )
                    .into());
                }
                revoked.push(
                    advance_active_intent_to_revoked(
                        conn,
                        &stored,
                        &revoke_input_digest,
                        now,
                    )
                    .await?,
                );
            }
            for route_row in routes {
                let registration: PushRegistrationRecord =
                    serde_json::from_value(route_row.payload.clone()).map_err(|error| {
                        PersistenceError::Internal(format!(
                            "stored push route is invalid during public unregistration: {error}"
                        ))
                    })?;
                let Ok(registration_id) =
                    PushRegistrationId::new(registration.registration_id.as_str().to_owned())
                else {
                    // Private or legacy local routes have no public Gateway
                    // installation identity and stay under the existing local
                    // unregister path.
                    continue;
                };
                let Some(snapshot) =
                    load_intent(conn, &account_id.station_id, &registration_id, false).await?
                else {
                    continue;
                };
                let route_lock_key =
                    local_route_lock_key(&account_id.station_id, &snapshot.local_route)?;
                sql_query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
                    .bind::<Text, _>(&route_lock_key)
                    .execute(&mut *conn)
                    .await?;
                let stored = load_intent(conn, &account_id.station_id, &registration_id, true)
                    .await?
                    .ok_or_else(|| {
                        PersistenceError::Conflict(
                            "cas_conflict: public push handoff disappeared during unregistration"
                                .to_owned(),
                        )
                    })?;
                let route_authorization: soland_storage::DeviceRevocationGateSelector =
                    serde_json::from_value(route_row.device_authorization.clone()).map_err(
                        |error| {
                            PersistenceError::Internal(format!(
                                "stored push route authorization is invalid: {error}"
                            ))
                        },
                    )?;
                if stored.status != PushRegistrationHandoffIntentStatus::ReceiptVerified
                    || stored.desired_state
                        != arkret_models_integration::PushRegistrationHandoffState::Active
                    || stored.device_authorization != route_authorization
                    || stored.local_route.account_id != account_id
                    || stored.local_route.device_id != device_id
                    || stored.local_route.push_route_id != registration.push_route_id
                    || stored.registration_id != registration_id
                {
                    return Err(PersistenceError::Conflict(
                        "cas_conflict: current public push route differs from its handoff intent"
                            .to_owned(),
                    )
                    .into());
                }
                let active = stored.request()?;
                let PushRegistrationHandoffRequestBody::Active {
                    push_target_id,
                    device_id: request_device_id,
                    push_key: request_push_key,
                    platform,
                    app_id: request_app_id,
                    visible_notification_opt_in,
                    expires_at,
                    ..
                } = active
                else {
                    return Err(PersistenceError::Conflict(
                        "cas_conflict: current public push route has no active handoff".to_owned(),
                    )
                    .into());
                };
                if registration.push_target_id != push_target_id
                    || registration.device_id != request_device_id
                    || registration.push_key != request_push_key
                    || registration.platform != platform
                    || registration.app_id != request_app_id
                    || registration.visible_notification_opt_in != visible_notification_opt_in
                    || registration.expires_at != expires_at
                {
                    return Err(PersistenceError::Conflict(
                        "cas_conflict: current public push route payload differs from its handoff"
                            .to_owned(),
                    )
                    .into());
                }
                let revoked_record = advance_active_intent_to_revoked(
                    conn,
                    &stored,
                    &revoke_input_digest,
                    now,
                )
                .await?;
                let removed = sql_query(
                    "DELETE FROM push_devices WHERE payload->'account_id' = $1 \
                       AND device_id = $2 AND payload->>'push_route_id' = $3 \
                       AND id = $4 AND device_authorization = $5",
                )
                .bind::<Jsonb, _>(&account_json)
                .bind::<Text, _>(device_id.as_str())
                .bind::<Text, _>(&registration.push_route_id)
                .bind::<Text, _>(registration.registration_id.as_str())
                .bind::<Jsonb, _>(&route_row.device_authorization)
                .execute(&mut *conn)
                .await?;
                if removed != 1 {
                    return Err(PersistenceError::Conflict(
                        "cas_conflict: public push route changed during unregistration".to_owned(),
                    )
                    .into());
                }
                revoked.push(revoked_record);
            }
            Ok(revoked)
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }

    async fn list_awaiting_revoked_intents(
        &self,
        source_station_id: &DidCoreId,
        after: Option<&PushRegistrationHandoffRetryCursor>,
        limit: usize,
    ) -> PersistenceResult<Vec<PushRegistrationHandoffIntentRecord>> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let limit = i64::try_from(limit.min(1_000)).map_err(PersistenceError::database)?;
        let mut conn = pg_conn(&self.pool).await?;
        let rows = if let Some(after) = after {
            let query = format!(
                "SELECT {HANDOFF_COLUMNS} FROM push_registration_handoff_intents \
                 WHERE source_station_id = $1 AND desired_state = 'revoked' \
                   AND status = 'awaiting_receipt' \
                   AND (updated_at > $2 OR (updated_at = $2 AND registration_id > $3)) \
                 ORDER BY updated_at, registration_id LIMIT $4"
            );
            sql_query(query)
                .bind::<Text, _>(source_station_id)
                .bind::<Timestamptz, _>(after.updated_at)
                .bind::<Text, _>(after.registration_id.as_str())
                .bind::<BigInt, _>(limit)
                .load::<HandoffIntentRow>(&mut conn)
                .await
                .map_err(PersistenceError::database)?
        } else {
            let query = format!(
                "SELECT {HANDOFF_COLUMNS} FROM push_registration_handoff_intents \
                 WHERE source_station_id = $1 AND desired_state = 'revoked' \
                   AND status = 'awaiting_receipt' \
                 ORDER BY updated_at, registration_id LIMIT $2"
            );
            sql_query(query)
                .bind::<Text, _>(source_station_id)
                .bind::<BigInt, _>(limit)
                .load::<HandoffIntentRow>(&mut conn)
                .await
                .map_err(PersistenceError::database)?
        };
        rows.into_iter().map(TryInto::try_into).collect()
    }

    async fn commit_verified_active_receipt_and_push_route(
        &self,
        source_station_id: &DidCoreId,
        local_route: &PushRegistrationHandoffRouteLocator,
        registration_id: &PushRegistrationId,
        expected_request_digest: &Hash,
        receipt: &PushRegistrationInstallationReceipt,
        authorization: &soland_storage::DeviceRevocationGateSelector,
        registration: &PushRegistrationRecord,
        now: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<PushRegistrationHandoffReceiptWrite> {
        let source_station_id = source_station_id.clone();
        let local_route = local_route.clone();
        let registration_id = registration_id.clone();
        let expected_request_digest = expected_request_digest.clone();
        let receipt = receipt.clone();
        let authorization = authorization.clone();
        let registration = registration.clone();
        let account_lock_key =
            push_device_lock_key(&registration.account_id, registration.device_id.as_str());
        let route_lock_key = local_route_lock_key(&source_station_id, &local_route)?;
        let mut conn = pg_conn(&self.pool).await?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            // Lock order: live device gate, account/device, handoff route,
            // handoff intent, then the local push-device route.
            crate::ensure_gate_allowed_in_transaction(conn, &authorization).await?;
            sql_query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
                .bind::<Text, _>(&account_lock_key)
                .execute(conn)
                .await?;
            sql_query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
                .bind::<Text, _>(&route_lock_key)
                .execute(conn)
                .await?;
            let record = load_intent(conn, &source_station_id, &registration_id, true)
                .await?
                .ok_or_else(|| {
                    PersistenceError::NotFound(
                        "push registration handoff desired intent".to_owned(),
                    )
                })?;
            if record.local_route != local_route {
                return Err(PersistenceError::Conflict(
                    "cas_conflict: push handoff intent belongs to another local route".to_owned(),
                )
                .into());
            }
            record.validate_active_local_registration(&authorization, &registration)?;
            let outcome = apply_verified_push_registration_receipt(
                &record,
                &expected_request_digest,
                &receipt,
                now,
            )?;
            let mode = match &outcome {
                PushRegistrationHandoffReceiptWrite::Stored(_) => {
                    PushDeviceRouteWriteMode::AllowReplace
                }
                PushRegistrationHandoffReceiptWrite::ExactReplay(_) => {
                    PushDeviceRouteWriteMode::RequireExact
                }
            };
            write_push_device_route_in_transaction(conn, &authorization, registration, now, mode)
                .await?;
            store_receipt_transition(
                conn,
                &source_station_id,
                &registration_id,
                &expected_request_digest,
                &outcome,
            )
            .await?;
            Ok(outcome)
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use arkret_models_integration::PushRegistrationHandoffState;
    use arkret_wire::{AccountId, Audience, DeviceId, DidUrl, PayloadProof};
    use serde_json::json;
    use soland_storage::{DeviceInventoryStore, DeviceRevocationStore, PushDeviceStore};
    use tokio::sync::Barrier;

    use super::*;
    use crate::{PgDeviceInventoryStore, PgDeviceRevocationStore, PgPushDeviceStore};

    #[path = "../../../../test-support/src/device_authorization_history.rs"]
    mod device_history_fixture;

    fn active_request() -> PushRegistrationHandoffRequestBody {
        active_request_with_id("registration_0123456789abcdef", None)
    }

    fn active_request_with_id(
        registration_id: &str,
        supersedes_registration_id: Option<&PushRegistrationId>,
    ) -> PushRegistrationHandoffRequestBody {
        serde_json::from_value(json!({
            "registration_id": registration_id,
            "push_target_id": "ak:pseudonym:push:kosc9iQ4gVct1OB-b6X364WIFIsJFVbVzn7BMBs1sm8",
            "device_id": "ak:device:01904100-0000-7000-8000-000000000001",
            "state": "active",
            "push_key": "provider-secret",
            "platform": "apns",
            "app_id": "com.example.app",
            "visible_notification_opt_in": false,
            "supersedes_registration_id": supersedes_registration_id
        }))
        .unwrap()
    }

    fn local_route(
        source: &DidCoreId,
        destination: &DidCoreId,
    ) -> PushRegistrationHandoffRouteLocator {
        local_route_for_account(
            AccountId::new(
                DidCoreId::new("ak:did_core:web:account.example").unwrap(),
                source.clone(),
            ),
            DeviceId::new("ak:device:01904100-0000-7000-8000-000000000001").unwrap(),
            destination,
        )
    }

    fn local_route_for_account(
        account_id: AccountId,
        device_id: DeviceId,
        destination: &DidCoreId,
    ) -> PushRegistrationHandoffRouteLocator {
        PushRegistrationHandoffRouteLocator {
            account_id,
            device_id,
            push_route_id: "com.example.app".to_owned(),
            destination_gateway_id: destination.clone(),
        }
    }

    fn client_input_digest(byte: char) -> Hash {
        Hash::new(format!("sha256:{}", byte.to_string().repeat(64))).unwrap()
    }

    fn device_authorization(
        route: &PushRegistrationHandoffRouteLocator,
    ) -> soland_storage::DeviceRevocationGateSelector {
        let event_id =
            arkret_wire::EventId::new("ak:event:AcIMom-0qqAXx_hmDJfxxaUJb_oJ64S3ARW1-WKFDCoD")
                .unwrap();
        soland_storage::DeviceRevocationGateSelector {
            principal_id: route.account_id.principal_id.clone(),
            station_id: route.account_id.station_id.clone(),
            device_id: route.device_id.as_str().to_owned(),
            authorization_ref: arkret_wire::CommittedEventRef {
                commit_id: arkret_wire::RealmCommitId::from_digest(arkret_canonical::sha256_bytes(
                    event_id.as_str().as_bytes(),
                )),
                stream_ref: arkret_wire::CommitStreamRef::Realm {
                    realm_id: arkret_wire::RealmId::new(
                        "ak:realm:ARQRpvtCGBgQfVQzTK4_Hgbg0D0HSnc3gPCvXOQUICir",
                    )
                    .unwrap(),
                },
                stream_position: 1,
                event_id,
            },
        }
    }

    fn active_request_for_device(
        registration_id: &str,
        device_id: &DeviceId,
        push_target_id: &str,
        push_key: &str,
    ) -> PushRegistrationHandoffRequestBody {
        active_request_for_route(
            registration_id,
            device_id,
            push_target_id,
            push_key,
            "com.example.app",
        )
    }

    fn active_request_for_route(
        registration_id: &str,
        device_id: &DeviceId,
        push_target_id: &str,
        push_key: &str,
        app_id: &str,
    ) -> PushRegistrationHandoffRequestBody {
        active_request_for_route_superseding(
            registration_id,
            device_id,
            push_target_id,
            push_key,
            app_id,
            None,
        )
    }

    fn active_request_for_route_superseding(
        registration_id: &str,
        device_id: &DeviceId,
        push_target_id: &str,
        push_key: &str,
        app_id: &str,
        supersedes_registration_id: Option<&PushRegistrationId>,
    ) -> PushRegistrationHandoffRequestBody {
        serde_json::from_value(json!({
            "registration_id": registration_id,
            "push_target_id": push_target_id,
            "device_id": device_id,
            "state": "active",
            "push_key": push_key,
            "platform": "apns",
            "app_id": app_id,
            "visible_notification_opt_in": false,
            "supersedes_registration_id": supersedes_registration_id
        }))
        .unwrap()
    }

    fn local_registration(
        account_id: &AccountId,
        request: &PushRegistrationHandoffRequestBody,
    ) -> PushRegistrationRecord {
        let PushRegistrationHandoffRequestBody::Active {
            registration_id,
            push_target_id,
            device_id,
            push_key,
            platform,
            app_id,
            visible_notification_opt_in,
            expires_at,
            ..
        } = request
        else {
            panic!("test registration request must be active")
        };
        PushRegistrationRecord {
            registration_id: arkret_wire::OpaqueLocalId::new(registration_id.as_str()).unwrap(),
            account_id: account_id.clone(),
            device_id: device_id.clone(),
            push_gateway: "https://push.example/".to_owned(),
            push_key: push_key.clone(),
            platform: platform.clone(),
            app_id: app_id.clone(),
            visible_notification_opt_in: *visible_notification_opt_in,
            push_route_id: "com.example.app".to_owned(),
            push_target_id: push_target_id.clone(),
            salt_epoch_id: "ak.push.salt_epoch.42".to_owned(),
            expires_at: *expires_at,
            retained_push_targets: Vec::new(),
        }
    }

    #[derive(QueryableByName)]
    struct StoredPushRoute {
        #[diesel(sql_type = Jsonb)]
        payload: Value,
        #[diesel(sql_type = Timestamptz)]
        updated_at: chrono::DateTime<chrono::Utc>,
    }

    async fn stored_push_route(
        pool: &PgPool,
        route: &PushRegistrationHandoffRouteLocator,
    ) -> Option<StoredPushRoute> {
        let account = serde_json::to_value(&route.account_id).unwrap();
        let mut conn = pool.get().await.unwrap();
        sql_query(
            "SELECT payload, updated_at FROM push_devices \
             WHERE payload->'account_id'=$1 AND device_id=$2 \
               AND payload->>'push_route_id'=$3",
        )
        .bind::<Jsonb, _>(&account)
        .bind::<Text, _>(route.device_id.as_str())
        .bind::<Text, _>(&route.push_route_id)
        .get_result::<StoredPushRoute>(&mut *conn)
        .await
        .optional()
        .unwrap()
    }

    async fn install_public_route(
        store: &PgPushRegistrationHandoffStore,
        station_id: &DidCoreId,
        route: &PushRegistrationHandoffRouteLocator,
        authorization: &soland_storage::DeviceRevocationGateSelector,
        request: &PushRegistrationHandoffRequestBody,
        client_digest: &Hash,
        at: chrono::DateTime<chrono::Utc>,
    ) {
        store
            .ensure_desired_intent(station_id, route, authorization, client_digest, request, at)
            .await
            .unwrap();
        let receipt = receipt_for(
            request,
            station_id,
            &route.destination_gateway_id,
            at + chrono::Duration::milliseconds(1),
        );
        let mut registration = local_registration(&route.account_id, request);
        registration.push_route_id = route.push_route_id.clone();
        store
            .commit_verified_active_receipt_and_push_route(
                station_id,
                route,
                request.registration_id(),
                &request.request_digest().unwrap(),
                &receipt,
                authorization,
                &registration,
                at + chrono::Duration::milliseconds(2),
            )
            .await
            .unwrap();
    }

    fn receipt_for(
        request: &PushRegistrationHandoffRequestBody,
        source: &DidCoreId,
        destination: &DidCoreId,
        stored_at: chrono::DateTime<chrono::Utc>,
    ) -> PushRegistrationInstallationReceipt {
        let mut receipt = PushRegistrationInstallationReceipt {
            registration_id: request.registration_id().clone(),
            push_target_id: request.push_target_id().clone(),
            device_id: request.device_id().clone(),
            state: request.state(),
            request_digest: request.request_digest().unwrap(),
            source_station_id: source.clone(),
            destination_gateway_id: destination.clone(),
            stored_at,
            proof: PayloadProof {
                kind: arkret_wire::proof_kind::DETACHED_JWS.to_owned(),
                verification_method: DidUrl::new(format!(
                    "did:{}#push-receipt-key",
                    destination
                        .as_str()
                        .strip_prefix("ak:did_core:")
                        .expect("test destination is a projected DID")
                ))
                .unwrap(),
                payload_digest: Hash::new(format!("sha256:{}", "0".repeat(64))).unwrap(),
                created_at: stored_at,
                domain: None,
                audience: Some(Audience::Single(source.as_str().to_owned())),
                proof_purpose: None,
                jws: "fixture..signature".to_owned(),
            },
        };
        receipt.proof.payload_digest = receipt.expected_payload_digest().unwrap();
        receipt
    }

    #[tokio::test]
    async fn concurrent_revoke_wins_over_active_receipt_and_late_receipt_fails_cas() {
        let database = crate::test_database::TestDatabase::lease().await;
        let pool = database.pool();
        let store = PgPushRegistrationHandoffStore { pool: pool.clone() };
        let source = DidCoreId::new("ak:did_core:web:source.example").unwrap();
        let destination = DidCoreId::new("ak:did_core:web:gateway.example").unwrap();
        let route = local_route(&source, &destination);
        let active_client_digest = client_input_digest('1');
        let active = active_request();
        let active_digest = active.request_digest().unwrap();
        let started_at = chrono::Utc::now();
        assert!(matches!(
            store
                .ensure_desired_intent(
                    &source,
                    &route,
                    &device_authorization(&route),
                    &active_client_digest,
                    &active,
                    started_at,
                )
                .await
                .unwrap(),
            PushRegistrationHandoffIntentWrite::Created(_)
        ));
        let revoked: PushRegistrationHandoffRequestBody = serde_json::from_value(json!({
            "registration_id": active.registration_id(),
            "push_target_id": active.push_target_id(),
            "device_id": active.device_id(),
            "state": "revoked"
        }))
        .unwrap();
        let receipt = receipt_for(
            &active,
            &source,
            &destination,
            started_at + chrono::Duration::seconds(1),
        );
        let barrier = Arc::new(Barrier::new(3));

        let revoke_task = {
            let barrier = barrier.clone();
            let store = PgPushRegistrationHandoffStore { pool: pool.clone() };
            let source = source.clone();
            let route = route.clone();
            let revoked = revoked.clone();
            tokio::spawn(async move {
                barrier.wait().await;
                store
                    .ensure_desired_intent(
                        &source,
                        &route,
                        &device_authorization(&route),
                        &client_input_digest('2'),
                        &revoked,
                        started_at + chrono::Duration::seconds(2),
                    )
                    .await
            })
        };
        let receipt_task = {
            let barrier = barrier.clone();
            let store = PgPushRegistrationHandoffStore { pool: pool.clone() };
            let source = source.clone();
            let registration_id = active.registration_id().clone();
            let active_digest = active_digest.clone();
            let receipt = receipt.clone();
            tokio::spawn(async move {
                barrier.wait().await;
                store
                    .commit_verified_receipt(
                        &source,
                        &registration_id,
                        &active_digest,
                        &receipt,
                        started_at + chrono::Duration::seconds(2),
                    )
                    .await
            })
        };
        barrier.wait().await;
        assert!(matches!(
            revoke_task.await.unwrap().unwrap(),
            PushRegistrationHandoffIntentWrite::AdvancedToRevoked(_)
        ));
        let concurrent_receipt = receipt_task.await.unwrap();
        assert!(
            concurrent_receipt.is_ok()
                || matches!(concurrent_receipt, Err(PersistenceError::Conflict(_)))
        );

        let stored = store
            .get_intent(&source, active.registration_id())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored.desired_state, PushRegistrationHandoffState::Revoked);
        assert_eq!(
            stored.status,
            PushRegistrationHandoffIntentStatus::AwaitingReceipt
        );
        assert!(stored.receipt.is_none());
        assert!(matches!(
            store
                .commit_verified_receipt(
                    &source,
                    active.registration_id(),
                    &active_digest,
                    &receipt,
                    started_at + chrono::Duration::seconds(3),
                )
                .await,
            Err(PersistenceError::Conflict(_))
        ));
        assert!(matches!(
            store
                .ensure_desired_intent(
                    &source,
                    &route,
                    &device_authorization(&route),
                    &client_input_digest('2'),
                    &revoked,
                    started_at + chrono::Duration::seconds(4),
                )
                .await
                .unwrap(),
            PushRegistrationHandoffIntentWrite::ExactReplay(_)
        ));
        assert!(matches!(
            store
                .ensure_desired_intent(
                    &source,
                    &route,
                    &device_authorization(&route),
                    &active_client_digest,
                    &active,
                    started_at + chrono::Duration::seconds(5),
                )
                .await,
            Err(PersistenceError::Conflict(_))
        ));
    }

    #[tokio::test]
    async fn concurrent_local_route_retry_reuses_pending_body_and_preserves_predecessor() {
        let database = crate::test_database::TestDatabase::lease().await;
        let pool = database.pool();
        let store = PgPushRegistrationHandoffStore { pool: pool.clone() };
        let source = DidCoreId::new("ak:did_core:web:source.example").unwrap();
        let destination = DidCoreId::new("ak:did_core:web:gateway.example").unwrap();
        let route = local_route(&source, &destination);
        let same_client_input = client_input_digest('3');
        let first = active_request_with_id("registration_aaaaaaaaaaaaaaaa", None);
        let retry = active_request_with_id("registration_bbbbbbbbbbbbbbbb", None);
        let started_at = chrono::Utc::now();
        let barrier = Arc::new(Barrier::new(3));

        let first_task = {
            let barrier = barrier.clone();
            let store = PgPushRegistrationHandoffStore { pool: pool.clone() };
            let source = source.clone();
            let route = route.clone();
            let digest = same_client_input.clone();
            let request = first.clone();
            tokio::spawn(async move {
                barrier.wait().await;
                store
                    .ensure_desired_intent(
                        &source,
                        &route,
                        &device_authorization(&route),
                        &digest,
                        &request,
                        started_at,
                    )
                    .await
            })
        };
        let retry_task = {
            let barrier = barrier.clone();
            let store = PgPushRegistrationHandoffStore { pool: pool.clone() };
            let source = source.clone();
            let route = route.clone();
            let digest = same_client_input.clone();
            let request = retry;
            tokio::spawn(async move {
                barrier.wait().await;
                store
                    .ensure_desired_intent(
                        &source,
                        &route,
                        &device_authorization(&route),
                        &digest,
                        &request,
                        started_at,
                    )
                    .await
            })
        };
        barrier.wait().await;
        let outcomes = [
            first_task.await.unwrap().unwrap(),
            retry_task.await.unwrap().unwrap(),
        ];
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| matches!(outcome, PushRegistrationHandoffIntentWrite::Created(_)))
                .count(),
            1
        );
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| matches!(
                    outcome,
                    PushRegistrationHandoffIntentWrite::ExactReplay(_)
                ))
                .count(),
            1
        );
        let records = outcomes.map(|outcome| match outcome {
            PushRegistrationHandoffIntentWrite::Created(record)
            | PushRegistrationHandoffIntentWrite::ExactReplay(record) => record,
            PushRegistrationHandoffIntentWrite::AdvancedToRevoked(_) => {
                panic!("active retry advanced to revoked")
            }
        });
        assert_eq!(records[0].registration_id, records[1].registration_id);
        assert_eq!(records[0].canonical_request, records[1].canonical_request);
        assert_eq!(records[0].client_input_digest, same_client_input);

        let pending = store
            .lookup_local_route_intent(&source, &route)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(pending.registration_id, records[0].registration_id);
        assert_eq!(
            pending.status,
            PushRegistrationHandoffIntentStatus::AwaitingReceipt
        );

        let successor_input = client_input_digest('4');
        let successor = active_request_with_id(
            "registration_cccccccccccccccc",
            Some(&pending.registration_id),
        );
        assert!(matches!(
            store
                .ensure_desired_intent(
                    &source,
                    &route,
                    &device_authorization(&route),
                    &successor_input,
                    &successor,
                    started_at + chrono::Duration::seconds(1),
                )
                .await,
            Err(PersistenceError::Conflict(_))
        ));

        let pending_request = pending.request().unwrap();
        let receipt = receipt_for(
            &pending_request,
            &source,
            &destination,
            started_at + chrono::Duration::seconds(2),
        );
        store
            .commit_verified_receipt(
                &source,
                &pending.registration_id,
                &pending.request_digest,
                &receipt,
                started_at + chrono::Duration::seconds(2),
            )
            .await
            .unwrap();
        let predecessor = store
            .lookup_local_route_intent(&source, &route)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(predecessor.registration_id, pending.registration_id);
        assert_eq!(
            predecessor.status,
            PushRegistrationHandoffIntentStatus::ReceiptVerified
        );

        assert!(matches!(
            store
                .ensure_desired_intent(
                    &source,
                    &route,
                    &device_authorization(&route),
                    &successor_input,
                    &successor,
                    started_at + chrono::Duration::seconds(3),
                )
                .await
                .unwrap(),
            PushRegistrationHandoffIntentWrite::Created(_)
        ));
        let current = store
            .lookup_local_route_intent(&source, &route)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&current.registration_id, successor.registration_id());
        assert_eq!(
            current.status,
            PushRegistrationHandoffIntentStatus::AwaitingReceipt
        );
        let retained = store
            .get_intent(&source, &predecessor.registration_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            retained.status,
            PushRegistrationHandoffIntentStatus::ReceiptVerified
        );
    }

    #[tokio::test]
    async fn verified_receipt_and_local_route_replace_are_one_uow() {
        let database = crate::test_database::TestDatabase::lease().await;
        let pool = database.pool();
        let station_id = DidCoreId::new("ak:did_core:web:station.example").unwrap();
        let source = device_history_fixture::DeviceHistoryFixture::new(station_id.clone());
        {
            let mut conn = pool.get().await.unwrap();
            sql_query("INSERT INTO device_inventory_station(singleton,station_id) VALUES(TRUE,$1)")
                .bind::<Text, _>(station_id.as_str())
                .execute(&mut *conn)
                .await
                .unwrap();
        }
        let inventory = PgDeviceInventoryStore { pool: pool.clone() };
        for device in source.device_inventory_records() {
            inventory.seed_test_record(&device).await.unwrap();
        }
        let authorization = source
            .gate_selectors()
            .into_iter()
            .find(|selector| selector.device_id == source.founding_device_id.as_str())
            .unwrap();
        let destination = DidCoreId::new("ak:did_core:web:gateway.example").unwrap();
        let route = local_route_for_account(
            source.account.clone(),
            source.founding_device_id.clone(),
            &destination,
        );
        let request = active_request_for_device(
            "registration_dddddddddddddddd",
            &source.founding_device_id,
            "ak:pseudonym:push:lg8aqJ2eJjms1GQpkzloxGn8F802f8RfmfmfsC85eRo",
            "provider-token",
        );
        let registration = local_registration(&source.account, &request);
        let push_store = PgPushDeviceStore { pool: pool.clone() };
        let mut predecessor = registration.clone();
        predecessor.registration_id =
            arkret_wire::OpaqueLocalId::new("push_registration:predecessor").unwrap();
        predecessor.push_target_id =
            "ak:pseudonym:push:kosc9iQ4gVct1OB-b6X364WIFIsJFVbVzn7BMBs1sm8"
                .parse()
                .unwrap();
        predecessor.salt_epoch_id = "ak.push.salt_epoch.41".to_owned();
        push_store
            .register(&authorization, serde_json::to_value(&predecessor).unwrap())
            .await
            .unwrap();
        let before = stored_push_route(&pool, &route).await.unwrap();

        let store = PgPushRegistrationHandoffStore { pool: pool.clone() };
        let client_digest = client_input_digest('5');
        let started_at = chrono::DateTime::parse_from_rfc3339("2026-09-22T12:00:00.123Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        store
            .ensure_desired_intent(
                &station_id,
                &route,
                &authorization,
                &client_digest,
                &request,
                started_at,
            )
            .await
            .unwrap();
        let receipt = receipt_for(
            &request,
            &station_id,
            &destination,
            started_at + chrono::Duration::seconds(1),
        );

        let stale_digest = client_input_digest('f');
        assert!(matches!(
            store
                .commit_verified_active_receipt_and_push_route(
                    &station_id,
                    &route,
                    request.registration_id(),
                    &stale_digest,
                    &receipt,
                    &authorization,
                    &registration,
                    started_at + chrono::Duration::seconds(2),
                )
                .await,
            Err(PersistenceError::Conflict(_))
        ));
        let after_stale = stored_push_route(&pool, &route).await.unwrap();
        assert_eq!(after_stale.payload, before.payload);
        assert_eq!(after_stale.updated_at, before.updated_at);

        let mut wrong_receipt = receipt.clone();
        wrong_receipt.destination_gateway_id =
            DidCoreId::new("ak:did_core:web:wrong-gateway.example").unwrap();
        assert!(
            store
                .commit_verified_active_receipt_and_push_route(
                    &station_id,
                    &route,
                    request.registration_id(),
                    &request.request_digest().unwrap(),
                    &wrong_receipt,
                    &authorization,
                    &registration,
                    started_at + chrono::Duration::seconds(2),
                )
                .await
                .is_err()
        );
        let after_wrong_receipt = stored_push_route(&pool, &route).await.unwrap();
        assert_eq!(after_wrong_receipt.payload, before.payload);
        assert_eq!(after_wrong_receipt.updated_at, before.updated_at);
        let mut wrong_local_route = registration.clone();
        wrong_local_route.push_route_id = "other.app".to_owned();
        assert!(matches!(
            store
                .commit_verified_active_receipt_and_push_route(
                    &station_id,
                    &route,
                    request.registration_id(),
                    &request.request_digest().unwrap(),
                    &receipt,
                    &authorization,
                    &wrong_local_route,
                    started_at + chrono::Duration::seconds(2),
                )
                .await,
            Err(PersistenceError::Conflict(_))
        ));
        let after_wrong_route = stored_push_route(&pool, &route).await.unwrap();
        assert_eq!(after_wrong_route.payload, before.payload);
        assert_eq!(after_wrong_route.updated_at, before.updated_at);
        assert_eq!(
            store
                .get_intent(&station_id, request.registration_id())
                .await
                .unwrap()
                .unwrap()
                .status,
            PushRegistrationHandoffIntentStatus::AwaitingReceipt
        );

        let stored = store
            .commit_verified_active_receipt_and_push_route(
                &station_id,
                &route,
                request.registration_id(),
                &request.request_digest().unwrap(),
                &receipt,
                &authorization,
                &registration,
                started_at + chrono::Duration::seconds(3),
            )
            .await
            .unwrap();
        assert!(matches!(
            stored,
            PushRegistrationHandoffReceiptWrite::Stored(_)
        ));
        let installed = stored_push_route(&pool, &route).await.unwrap();
        let installed_registration: PushRegistrationRecord =
            serde_json::from_value(installed.payload.clone()).unwrap();
        assert_eq!(
            installed_registration.registration_id.as_str(),
            request.registration_id().as_str()
        );
        assert_eq!(installed_registration.retained_push_targets.len(), 1);
        assert_eq!(
            installed_registration.retained_push_targets[0].push_target_id,
            predecessor.push_target_id
        );
        assert_eq!(
            store
                .get_intent(&station_id, request.registration_id())
                .await
                .unwrap()
                .unwrap()
                .status,
            PushRegistrationHandoffIntentStatus::ReceiptVerified
        );

        let replay = store
            .commit_verified_active_receipt_and_push_route(
                &station_id,
                &route,
                request.registration_id(),
                &request.request_digest().unwrap(),
                &receipt,
                &authorization,
                &registration,
                started_at + chrono::Duration::seconds(4),
            )
            .await
            .unwrap();
        assert!(matches!(
            replay,
            PushRegistrationHandoffReceiptWrite::ExactReplay(_)
        ));
        let after_replay = stored_push_route(&pool, &route).await.unwrap();
        assert_eq!(after_replay.payload, installed.payload);
        assert_eq!(after_replay.updated_at, installed.updated_at);

        let successor = active_request_for_device(
            "registration_eeeeeeeeeeeeeeee",
            &source.founding_device_id,
            "ak:pseudonym:push:7EMHE3J_lA1FENBqXW-mmf4Ku3gfVeCu5N73ThBrOEg",
            "replacement-token",
        );
        let successor_registration = local_registration(&source.account, &successor);
        store
            .ensure_desired_intent(
                &station_id,
                &route,
                &authorization,
                &client_input_digest('6'),
                &successor,
                started_at + chrono::Duration::seconds(5),
            )
            .await
            .unwrap();
        PgDeviceRevocationStore { pool: pool.clone() }
            .commit_revocation(&soland_storage::DeviceRevocationTransition {
                selector: authorization.clone(),
                revoke_ref: authorization.authorization_ref.clone(),
                committed_at: started_at + chrono::Duration::seconds(6),
            })
            .await
            .unwrap();
        let successor_receipt = receipt_for(
            &successor,
            &station_id,
            &destination,
            started_at + chrono::Duration::seconds(7),
        );
        assert!(matches!(
            store
                .commit_verified_active_receipt_and_push_route(
                    &station_id,
                    &route,
                    successor.registration_id(),
                    &successor.request_digest().unwrap(),
                    &successor_receipt,
                    &authorization,
                    &successor_registration,
                    started_at + chrono::Duration::seconds(8),
                )
                .await,
            Err(PersistenceError::Conflict(_))
        ));
        let after_revoked_gate = stored_push_route(&pool, &route).await.unwrap();
        assert_eq!(after_revoked_gate.payload, installed.payload);
        assert_eq!(after_revoked_gate.updated_at, installed.updated_at);
        assert_eq!(
            store
                .get_intent(&station_id, successor.registration_id())
                .await
                .unwrap()
                .unwrap()
                .status,
            PushRegistrationHandoffIntentStatus::AwaitingReceipt
        );
    }

    #[tokio::test]
    async fn public_unregistration_filters_routes_and_retains_exact_revoke_outbox() {
        let database = crate::test_database::TestDatabase::lease().await;
        let pool = database.pool();
        let station_id = DidCoreId::new("ak:did_core:web:station.example").unwrap();
        let source = device_history_fixture::DeviceHistoryFixture::new(station_id.clone());
        {
            let mut conn = pool.get().await.unwrap();
            sql_query("INSERT INTO device_inventory_station(singleton,station_id) VALUES(TRUE,$1)")
                .bind::<Text, _>(station_id.as_str())
                .execute(&mut *conn)
                .await
                .unwrap();
        }
        let inventory = PgDeviceInventoryStore { pool: pool.clone() };
        for device in source.device_inventory_records() {
            inventory.seed_test_record(&device).await.unwrap();
        }
        let authorization = source
            .gate_selectors()
            .into_iter()
            .find(|selector| selector.device_id == source.founding_device_id.as_str())
            .unwrap();
        let destination = DidCoreId::new("ak:did_core:web:gateway.example").unwrap();
        let route_a = local_route_for_account(
            source.account.clone(),
            source.founding_device_id.clone(),
            &destination,
        );
        let mut route_b = route_a.clone();
        route_b.push_route_id = "com.example.voip".to_owned();
        let request_a = active_request_for_route(
            "registration_1111111111111111",
            &source.founding_device_id,
            "ak:pseudonym:push:kosc9iQ4gVct1OB-b6X364WIFIsJFVbVzn7BMBs1sm8",
            "provider-token-a",
            "com.example.app",
        );
        let request_b = active_request_for_route(
            "registration_2222222222222222",
            &source.founding_device_id,
            "ak:pseudonym:push:7EMHE3J_lA1FENBqXW-mmf4Ku3gfVeCu5N73ThBrOEg",
            "provider-token-b",
            "com.example.voip",
        );
        let store = PgPushRegistrationHandoffStore { pool: pool.clone() };
        let started_at = chrono::DateTime::parse_from_rfc3339("2026-09-23T00:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        install_public_route(
            &store,
            &station_id,
            &route_a,
            &authorization,
            &request_a,
            &client_input_digest('a'),
            started_at,
        )
        .await;
        install_public_route(
            &store,
            &station_id,
            &route_b,
            &authorization,
            &request_b,
            &client_input_digest('b'),
            started_at + chrono::Duration::seconds(1),
        )
        .await;

        let successor = active_request_for_route_superseding(
            "registration_aaaaaaaaaaaaaaaa",
            &source.founding_device_id,
            "ak:pseudonym:push:kosc9iQ4gVct1OB-b6X364WIFIsJFVbVzn7BMBs1sm8",
            "provider-token-a",
            "com.example.app",
            Some(request_a.registration_id()),
        );
        store
            .ensure_desired_intent(
                &station_id,
                &route_a,
                &authorization,
                &client_input_digest('d'),
                &successor,
                started_at + chrono::Duration::seconds(2),
            )
            .await
            .unwrap();
        let other_destination = DidCoreId::new("ak:did_core:web:gateway-two.example").unwrap();
        let mut other_gateway_route = route_a.clone();
        other_gateway_route.destination_gateway_id = other_destination;
        let other_gateway_pending = active_request_for_route(
            "registration_bbbbbbbbbbbbbbbb",
            &source.founding_device_id,
            "ak:pseudonym:push:kosc9iQ4gVct1OB-b6X364WIFIsJFVbVzn7BMBs1sm8",
            "provider-token-a",
            "com.example.app",
        );
        store
            .ensure_desired_intent(
                &station_id,
                &other_gateway_route,
                &authorization,
                &client_input_digest('e'),
                &other_gateway_pending,
                started_at + chrono::Duration::seconds(3),
            )
            .await
            .unwrap();

        let revoked = store
            .begin_public_push_unregistration(
                &source.account,
                &source.founding_device_id,
                Some("provider-token-a"),
                Some("com.example.app"),
                started_at + chrono::Duration::seconds(4),
            )
            .await
            .unwrap();
        assert_eq!(revoked.len(), 3);
        assert!(revoked.iter().all(|record| {
            record.desired_state == PushRegistrationHandoffState::Revoked
                && record.device_authorization == authorization
        }));
        assert!(stored_push_route(&pool, &route_a).await.is_none());
        assert!(stored_push_route(&pool, &route_b).await.is_some());

        let due = store
            .list_awaiting_revoked_intents(&station_id, None, 10)
            .await
            .unwrap();
        let first_page = store
            .list_awaiting_revoked_intents(&station_id, None, 1)
            .await
            .unwrap();
        assert_eq!(first_page.len(), 1);
        let cursor = PushRegistrationHandoffRetryCursor::after(&first_page[0]);
        let next_page = store
            .list_awaiting_revoked_intents(&station_id, Some(&cursor), 10)
            .await
            .unwrap();
        assert_eq!(next_page.len(), due.len() - 1);
        assert!(next_page.iter().all(|record| {
            record.updated_at > cursor.updated_at
                || (record.updated_at == cursor.updated_at
                    && record.registration_id > cursor.registration_id)
        }));
        let mut due_ids = due
            .iter()
            .map(|record| record.registration_id.as_str())
            .collect::<Vec<_>>();
        due_ids.sort_unstable();
        assert_eq!(
            due_ids,
            vec![
                request_a.registration_id().as_str(),
                successor.registration_id().as_str(),
                other_gateway_pending.registration_id().as_str(),
            ]
        );
        let retry = store
            .begin_public_push_unregistration(
                &source.account,
                &source.founding_device_id,
                Some("provider-token-a"),
                Some("com.example.app"),
                started_at + chrono::Duration::seconds(5),
            )
            .await
            .unwrap();
        assert_eq!(retry.len(), revoked.len());
        assert!(retry.iter().all(|replayed| {
            revoked.iter().any(|first| {
                first.registration_id == replayed.registration_id
                    && first.canonical_request == replayed.canonical_request
            })
        }));
        let active_receipt = receipt_for(
            &request_a,
            &station_id,
            &destination,
            started_at + chrono::Duration::seconds(6),
        );
        assert!(matches!(
            store
                .commit_verified_receipt(
                    &station_id,
                    request_a.registration_id(),
                    &request_a.request_digest().unwrap(),
                    &active_receipt,
                    started_at + chrono::Duration::seconds(7),
                )
                .await,
            Err(PersistenceError::Conflict(_))
        ));
        let successor_receipt = receipt_for(
            &successor,
            &station_id,
            &destination,
            started_at + chrono::Duration::seconds(6),
        );
        let successor_registration = local_registration(&source.account, &successor);
        assert!(matches!(
            store
                .commit_verified_active_receipt_and_push_route(
                    &station_id,
                    &route_a,
                    successor.registration_id(),
                    &successor.request_digest().unwrap(),
                    &successor_receipt,
                    &authorization,
                    &successor_registration,
                    started_at + chrono::Duration::seconds(7),
                )
                .await,
            Err(PersistenceError::Conflict(_))
        ));
        let other_gateway_receipt = receipt_for(
            &other_gateway_pending,
            &station_id,
            &other_gateway_route.destination_gateway_id,
            started_at + chrono::Duration::seconds(6),
        );
        let other_gateway_registration =
            local_registration(&source.account, &other_gateway_pending);
        assert!(matches!(
            store
                .commit_verified_active_receipt_and_push_route(
                    &station_id,
                    &other_gateway_route,
                    other_gateway_pending.registration_id(),
                    &other_gateway_pending.request_digest().unwrap(),
                    &other_gateway_receipt,
                    &authorization,
                    &other_gateway_registration,
                    started_at + chrono::Duration::seconds(7),
                )
                .await,
            Err(PersistenceError::Conflict(_))
        ));
        assert!(stored_push_route(&pool, &route_a).await.is_none());
        assert!(
            stored_push_route(&pool, &other_gateway_route)
                .await
                .is_none()
        );

        let predecessor_revoke = retry
            .iter()
            .find(|record| record.registration_id == *request_a.registration_id())
            .unwrap();
        let predecessor_revoke_request = predecessor_revoke.request().unwrap();
        let predecessor_revoke_receipt = receipt_for(
            &predecessor_revoke_request,
            &station_id,
            &predecessor_revoke.destination_gateway_id,
            started_at + chrono::Duration::seconds(8),
        );
        store
            .commit_verified_receipt(
                &station_id,
                &predecessor_revoke.registration_id,
                &predecessor_revoke.request_digest,
                &predecessor_revoke_receipt,
                started_at + chrono::Duration::seconds(8),
            )
            .await
            .unwrap();
        let remaining = store
            .begin_public_push_unregistration(
                &source.account,
                &source.founding_device_id,
                Some("provider-token-a"),
                Some("com.example.app"),
                started_at + chrono::Duration::seconds(9),
            )
            .await
            .unwrap();
        assert_eq!(
            remaining.len(),
            2,
            "confirmed revokes leave only retryable peers"
        );
        for record in remaining {
            let request = record.request().unwrap();
            let receipt = receipt_for(
                &request,
                &station_id,
                &record.destination_gateway_id,
                started_at + chrono::Duration::seconds(10),
            );
            store
                .commit_verified_receipt(
                    &station_id,
                    &record.registration_id,
                    &record.request_digest,
                    &receipt,
                    started_at + chrono::Duration::seconds(10),
                )
                .await
                .unwrap();
        }
        assert!(
            store
                .begin_public_push_unregistration(
                    &source.account,
                    &source.founding_device_id,
                    Some("provider-token-a"),
                    Some("com.example.app"),
                    started_at + chrono::Duration::seconds(11),
                )
                .await
                .unwrap()
                .is_empty(),
            "a fully confirmed exact retry has zero remaining public work"
        );

        let mut wrong_generation = authorization.clone();
        wrong_generation.authorization_ref.stream_position += 1;
        {
            let mut conn = pool.get().await.unwrap();
            sql_query("UPDATE push_devices SET device_authorization=$2 WHERE id=$1")
                .bind::<Text, _>(request_b.registration_id().as_str())
                .bind::<Jsonb, _>(serde_json::to_value(&wrong_generation).unwrap())
                .execute(&mut *conn)
                .await
                .unwrap();
        }
        assert!(matches!(
            store
                .begin_public_push_unregistration(
                    &source.account,
                    &source.founding_device_id,
                    Some("provider-token-b"),
                    Some("com.example.voip"),
                    started_at + chrono::Duration::seconds(12),
                )
                .await,
            Err(PersistenceError::Conflict(_))
        ));
        assert!(stored_push_route(&pool, &route_b).await.is_some());
        assert_eq!(
            store
                .get_intent(&station_id, request_b.registration_id())
                .await
                .unwrap()
                .unwrap()
                .desired_state,
            PushRegistrationHandoffState::Active
        );
    }

    #[tokio::test]
    async fn concurrent_public_unregistration_advances_once_and_replays_exact_revoke() {
        let database = crate::test_database::TestDatabase::lease().await;
        let pool = database.pool();
        let station_id = DidCoreId::new("ak:did_core:web:station.example").unwrap();
        let source = device_history_fixture::DeviceHistoryFixture::new(station_id.clone());
        {
            let mut conn = pool.get().await.unwrap();
            sql_query("INSERT INTO device_inventory_station(singleton,station_id) VALUES(TRUE,$1)")
                .bind::<Text, _>(station_id.as_str())
                .execute(&mut *conn)
                .await
                .unwrap();
        }
        let inventory = PgDeviceInventoryStore { pool: pool.clone() };
        for device in source.device_inventory_records() {
            inventory.seed_test_record(&device).await.unwrap();
        }
        let authorization = source
            .gate_selectors()
            .into_iter()
            .find(|selector| selector.device_id == source.founding_device_id.as_str())
            .unwrap();
        let destination = DidCoreId::new("ak:did_core:web:gateway.example").unwrap();
        let route = local_route_for_account(
            source.account.clone(),
            source.founding_device_id.clone(),
            &destination,
        );
        let request = active_request_for_device(
            "registration_3333333333333333",
            &source.founding_device_id,
            "ak:pseudonym:push:kosc9iQ4gVct1OB-b6X364WIFIsJFVbVzn7BMBs1sm8",
            "provider-token",
        );
        let started_at = chrono::DateTime::parse_from_rfc3339("2026-09-23T00:10:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let store = PgPushRegistrationHandoffStore { pool: pool.clone() };
        install_public_route(
            &store,
            &station_id,
            &route,
            &authorization,
            &request,
            &client_input_digest('c'),
            started_at,
        )
        .await;
        let barrier = Arc::new(Barrier::new(3));
        let mut tasks = Vec::new();
        for _ in 0..2 {
            let barrier = barrier.clone();
            let store = PgPushRegistrationHandoffStore { pool: pool.clone() };
            let account = source.account.clone();
            let device_id = source.founding_device_id.clone();
            tasks.push(tokio::spawn(async move {
                barrier.wait().await;
                store
                    .begin_public_push_unregistration(
                        &account,
                        &device_id,
                        None,
                        None,
                        started_at + chrono::Duration::seconds(1),
                    )
                    .await
            }));
        }
        barrier.wait().await;
        let first = tasks.remove(0).await.unwrap().unwrap();
        let second = tasks.remove(0).await.unwrap().unwrap();
        assert_eq!(first.len(), 1);
        assert_eq!(second.len(), 1);
        assert_eq!(first[0].registration_id, second[0].registration_id);
        assert_eq!(first[0].canonical_request, second[0].canonical_request);
        assert!(stored_push_route(&pool, &route).await.is_none());
        let due = store
            .list_awaiting_revoked_intents(&station_id, None, 10)
            .await
            .unwrap();
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].registration_id, *request.registration_id());
        assert_eq!(
            due[0].request().unwrap().state(),
            PushRegistrationHandoffState::Revoked
        );
    }

    #[tokio::test]
    async fn concurrent_pending_create_linearizes_before_or_after_unregistration() {
        let database = crate::test_database::TestDatabase::lease().await;
        let pool = database.pool();
        let station_id = DidCoreId::new("ak:did_core:web:station.example").unwrap();
        let destination = DidCoreId::new("ak:did_core:web:gateway.example").unwrap();
        let route = local_route(&station_id, &destination);
        let authorization = device_authorization(&route);
        let existing = active_request_with_id("registration_cccccccccccccccc", None);
        let store = PgPushRegistrationHandoffStore { pool: pool.clone() };
        let started_at = chrono::DateTime::parse_from_rfc3339("2026-09-23T00:15:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        store
            .ensure_desired_intent(
                &station_id,
                &route,
                &authorization,
                &client_input_digest('f'),
                &existing,
                started_at,
            )
            .await
            .unwrap();

        let second_destination = DidCoreId::new("ak:did_core:web:gateway-two.example").unwrap();
        let mut raced_route = route.clone();
        raced_route.destination_gateway_id = second_destination;
        let raced = active_request_with_id("registration_dddddddddddddddd", None);
        let barrier = Arc::new(Barrier::new(3));
        let unregister_task = {
            let barrier = barrier.clone();
            let store = PgPushRegistrationHandoffStore { pool: pool.clone() };
            let account_id = route.account_id.clone();
            let device_id = route.device_id.clone();
            tokio::spawn(async move {
                barrier.wait().await;
                store
                    .begin_public_push_unregistration(
                        &account_id,
                        &device_id,
                        None,
                        None,
                        started_at + chrono::Duration::seconds(1),
                    )
                    .await
            })
        };
        let create_task = {
            let barrier = barrier.clone();
            let store = PgPushRegistrationHandoffStore { pool: pool.clone() };
            let station_id = station_id.clone();
            let authorization = authorization.clone();
            let raced_route = raced_route.clone();
            let raced = raced.clone();
            tokio::spawn(async move {
                barrier.wait().await;
                store
                    .ensure_desired_intent(
                        &station_id,
                        &raced_route,
                        &authorization,
                        &client_input_digest('9'),
                        &raced,
                        started_at + chrono::Duration::seconds(1),
                    )
                    .await
            })
        };
        barrier.wait().await;
        let revoked = unregister_task.await.unwrap().unwrap();
        assert!(matches!(
            create_task.await.unwrap().unwrap(),
            PushRegistrationHandoffIntentWrite::Created(_)
        ));

        let existing_after = store
            .get_intent(&station_id, existing.registration_id())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            existing_after.desired_state,
            PushRegistrationHandoffState::Revoked,
            "an intent durable before the account/device lock is always terminated"
        );
        let raced_after = store
            .get_intent(&station_id, raced.registration_id())
            .await
            .unwrap()
            .unwrap();
        let raced_was_revoked = revoked
            .iter()
            .any(|record| record.registration_id == *raced.registration_id());
        assert_eq!(
            raced_after.desired_state == PushRegistrationHandoffState::Revoked,
            raced_was_revoked,
            "the raced create is either included before the linearization point or remains a later explicit registration"
        );
    }

    #[tokio::test]
    async fn verified_replay_requires_the_exact_live_gate_and_local_route() {
        let database = crate::test_database::TestDatabase::lease().await;
        let pool = database.pool();
        let station_id = DidCoreId::new("ak:did_core:web:station.example").unwrap();
        let source = device_history_fixture::DeviceHistoryFixture::new(station_id.clone());
        {
            let mut conn = pool.get().await.unwrap();
            sql_query("INSERT INTO device_inventory_station(singleton,station_id) VALUES(TRUE,$1)")
                .bind::<Text, _>(station_id.as_str())
                .execute(&mut *conn)
                .await
                .unwrap();
        }
        let inventory = PgDeviceInventoryStore { pool: pool.clone() };
        for device in source.device_inventory_records() {
            inventory.seed_test_record(&device).await.unwrap();
        }
        let authorization = source
            .gate_selectors()
            .into_iter()
            .find(|selector| selector.device_id == source.founding_device_id.as_str())
            .unwrap();
        let destination = DidCoreId::new("ak:did_core:web:gateway.example").unwrap();
        let route = local_route_for_account(
            source.account.clone(),
            source.founding_device_id.clone(),
            &destination,
        );
        let request = active_request_for_device(
            "registration_4444444444444444",
            &source.founding_device_id,
            "ak:pseudonym:push:kosc9iQ4gVct1OB-b6X364WIFIsJFVbVzn7BMBs1sm8",
            "provider-token",
        );
        let started_at = chrono::DateTime::parse_from_rfc3339("2026-09-23T00:20:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let store = PgPushRegistrationHandoffStore { pool: pool.clone() };
        install_public_route(
            &store,
            &station_id,
            &route,
            &authorization,
            &request,
            &client_input_digest('d'),
            started_at,
        )
        .await;
        let receipt = receipt_for(
            &request,
            &station_id,
            &destination,
            started_at + chrono::Duration::milliseconds(1),
        );
        let registration = local_registration(&source.account, &request);
        {
            let mut conn = pool.get().await.unwrap();
            sql_query("DELETE FROM push_devices WHERE id=$1")
                .bind::<Text, _>(request.registration_id().as_str())
                .execute(&mut *conn)
                .await
                .unwrap();
        }
        assert!(matches!(
            store
                .commit_verified_active_receipt_and_push_route(
                    &station_id,
                    &route,
                    request.registration_id(),
                    &request.request_digest().unwrap(),
                    &receipt,
                    &authorization,
                    &registration,
                    started_at + chrono::Duration::seconds(1),
                )
                .await,
            Err(PersistenceError::Conflict(_))
        ));

        PgPushDeviceStore { pool: pool.clone() }
            .register(&authorization, serde_json::to_value(&registration).unwrap())
            .await
            .unwrap();
        assert!(matches!(
            store
                .commit_verified_active_receipt_and_push_route(
                    &station_id,
                    &route,
                    request.registration_id(),
                    &request.request_digest().unwrap(),
                    &receipt,
                    &authorization,
                    &registration,
                    started_at + chrono::Duration::seconds(2),
                )
                .await
                .unwrap(),
            PushRegistrationHandoffReceiptWrite::ExactReplay(_)
        ));
        PgDeviceRevocationStore { pool: pool.clone() }
            .commit_revocation(&soland_storage::DeviceRevocationTransition {
                selector: authorization.clone(),
                revoke_ref: authorization.authorization_ref.clone(),
                committed_at: started_at + chrono::Duration::seconds(3),
            })
            .await
            .unwrap();
        assert!(matches!(
            store
                .commit_verified_active_receipt_and_push_route(
                    &station_id,
                    &route,
                    request.registration_id(),
                    &request.request_digest().unwrap(),
                    &receipt,
                    &authorization,
                    &registration,
                    started_at + chrono::Duration::seconds(4),
                )
                .await,
            Err(PersistenceError::Conflict(_))
        ));
    }
}
