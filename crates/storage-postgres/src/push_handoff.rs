use arkret_models_integration::{
    PushRegistrationHandoffRequestBody, PushRegistrationId, PushRegistrationInstallationReceipt,
};
use arkret_wire::{DidCoreId, Hash};

use super::{
    AsyncConnection, AsyncPgConnection, Binary, Jsonb, Nullable, OptionalExtension,
    PersistenceError, PersistenceResult, PgPool, PgTransactionError,
    PushRegistrationHandoffIntentRecord, PushRegistrationHandoffIntentStatus,
    PushRegistrationHandoffIntentWrite, PushRegistrationHandoffReceiptWrite,
    PushRegistrationHandoffRouteLocator, PushRegistrationHandoffStore, QueryableByName,
    RunQueryDsl, Text, Timestamptz, Value, apply_push_registration_desired_intent,
    apply_verified_push_registration_receipt, async_trait, pg_conn, sql_query,
};

pub struct PgPushRegistrationHandoffStore {
    pub pool: PgPool,
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
    local_push_route_id, registration_id, destination_gateway_id, desired_state, request_digest, \
    client_input_digest, canonical_request, status, receipt, created_at, updated_at";

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

#[async_trait]
impl PushRegistrationHandoffStore for PgPushRegistrationHandoffStore {
    async fn ensure_desired_intent(
        &self,
        source_station_id: &DidCoreId,
        local_route: &PushRegistrationHandoffRouteLocator,
        client_input_digest: &Hash,
        request: &PushRegistrationHandoffRequestBody,
        now: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<PushRegistrationHandoffIntentWrite> {
        let candidate = PushRegistrationHandoffIntentRecord::prepare(
            source_station_id.clone(),
            local_route.clone(),
            client_input_digest.clone(),
            request,
            now,
        )?;
        let route_lock_key = local_route_lock_key(source_station_id, local_route)?;
        let mut conn = pg_conn(&self.pool).await?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
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
                  registration_id, destination_gateway_id, desired_state, request_digest, \
                  client_input_digest, canonical_request, status, receipt, created_at, updated_at) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, NULL, $12, $12) \
                 ON CONFLICT (source_station_id, registration_id) DO NOTHING",
            )
            .bind::<Text, _>(&candidate.source_station_id)
            .bind::<Jsonb, _>(
                serde_json::to_value(&candidate.local_route.account_id)
                    .map_err(PersistenceError::database)?,
            )
            .bind::<Text, _>(candidate.local_route.device_id.as_str())
            .bind::<Text, _>(&candidate.local_route.push_route_id)
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
            let PushRegistrationHandoffReceiptWrite::Stored(committed) = &outcome else {
                return Ok(outcome);
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
            .bind::<Text, _>(&source_station_id)
            .bind::<Text, _>(registration_id.as_str())
            .bind::<Text, _>(expected_request_digest.as_str())
            .bind::<Text, _>(committed.status.as_str())
            .bind::<Jsonb, _>(&receipt_json)
            .bind::<Timestamptz, _>(committed.updated_at)
            .execute(conn)
            .await?;
            if updated != 1 {
                return Err(PersistenceError::Conflict(
                    "cas_conflict: push registration handoff receipt state changed".to_owned(),
                )
                .into());
            }
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
    use tokio::sync::Barrier;

    use super::*;

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
        PushRegistrationHandoffRouteLocator {
            account_id: AccountId::new(
                DidCoreId::new("ak:did_core:web:account.example").unwrap(),
                source.clone(),
            ),
            device_id: DeviceId::new("ak:device:01904100-0000-7000-8000-000000000001").unwrap(),
            push_route_id: "com.example.app".to_owned(),
            destination_gateway_id: destination.clone(),
        }
    }

    fn client_input_digest(byte: char) -> Hash {
        Hash::new(format!("sha256:{}", byte.to_string().repeat(64))).unwrap()
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
                verification_method: DidUrl::new("did:web:gateway.example#push-receipt-key")
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
                .ensure_desired_intent(&source, &route, &active_client_digest, &active, started_at,)
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
                    .ensure_desired_intent(&source, &route, &digest, &request, started_at)
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
                    .ensure_desired_intent(&source, &route, &digest, &request, started_at)
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
}
