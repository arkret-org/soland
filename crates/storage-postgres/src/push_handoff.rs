use arkret_models_integration::{
    PushRegistrationHandoffRequestBody, PushRegistrationId, PushRegistrationInstallationReceipt,
};
use arkret_wire::{DidCoreId, Hash};

use super::{
    AsyncConnection, AsyncPgConnection, Binary, Jsonb, Nullable, OptionalExtension,
    PersistenceError, PersistenceResult, PgPool, PgTransactionError,
    PushRegistrationHandoffIntentRecord, PushRegistrationHandoffIntentStatus,
    PushRegistrationHandoffIntentWrite, PushRegistrationHandoffReceiptWrite,
    PushRegistrationHandoffStore, QueryableByName, RunQueryDsl, Text, Timestamptz, Value,
    apply_push_registration_desired_intent, apply_verified_push_registration_receipt, async_trait,
    pg_conn, sql_query,
};

pub struct PgPushRegistrationHandoffStore {
    pub pool: PgPool,
}

#[derive(QueryableByName)]
struct HandoffIntentRow {
    #[diesel(sql_type = Text)]
    source_station_id: DidCoreId,
    #[diesel(sql_type = Text)]
    registration_id: String,
    #[diesel(sql_type = Text)]
    destination_gateway_id: DidCoreId,
    #[diesel(sql_type = Text)]
    desired_state: String,
    #[diesel(sql_type = Text)]
    request_digest: String,
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
        let record = Self {
            source_station_id: row.source_station_id,
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

const HANDOFF_COLUMNS: &str = "source_station_id, registration_id, destination_gateway_id, \
    desired_state, request_digest, canonical_request, status, receipt, created_at, updated_at";

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

#[async_trait]
impl PushRegistrationHandoffStore for PgPushRegistrationHandoffStore {
    async fn ensure_desired_intent(
        &self,
        source_station_id: &DidCoreId,
        destination_gateway_id: &DidCoreId,
        request: &PushRegistrationHandoffRequestBody,
        now: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<PushRegistrationHandoffIntentWrite> {
        let candidate = PushRegistrationHandoffIntentRecord::prepare(
            source_station_id.clone(),
            destination_gateway_id.clone(),
            request,
            now,
        )?;
        let mut conn = pg_conn(&self.pool).await?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            let inserted = sql_query(
                "INSERT INTO push_registration_handoff_intents \
                 (source_station_id, registration_id, destination_gateway_id, desired_state, \
                  request_digest, canonical_request, status, receipt, created_at, updated_at) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, NULL, $8, $8) \
                 ON CONFLICT (source_station_id, registration_id) DO NOTHING",
            )
            .bind::<Text, _>(&candidate.source_station_id)
            .bind::<Text, _>(candidate.registration_id.as_str())
            .bind::<Text, _>(&candidate.destination_gateway_id)
            .bind::<Text, _>(candidate.desired_state.as_str())
            .bind::<Text, _>(candidate.request_digest.as_str())
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
            let outcome = apply_push_registration_desired_intent(&stored, &candidate)?;
            let PushRegistrationHandoffIntentWrite::AdvancedToRevoked(revoked) = &outcome else {
                return Ok(outcome);
            };
            let updated = sql_query(
                "UPDATE push_registration_handoff_intents \
                 SET desired_state = $5, request_digest = $6, canonical_request = $7, \
                     status = $8, receipt = NULL, updated_at = $9 \
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
            Ok(outcome)
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
    use arkret_wire::{Audience, DidUrl, PayloadProof};
    use serde_json::json;
    use tokio::sync::Barrier;

    use super::*;

    fn active_request() -> PushRegistrationHandoffRequestBody {
        serde_json::from_value(json!({
            "registration_id": "registration_0123456789abcdef",
            "push_target_id": "ak:pseudonym:push:kosc9iQ4gVct1OB-b6X364WIFIsJFVbVzn7BMBs1sm8",
            "device_id": "ak:device:01904100-0000-7000-8000-000000000001",
            "state": "active",
            "push_key": "provider-secret",
            "platform": "apns",
            "app_id": "com.example.app",
            "visible_notification_opt_in": false
        }))
        .unwrap()
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
        let active = active_request();
        let active_digest = active.request_digest().unwrap();
        let started_at = chrono::Utc::now();
        assert!(matches!(
            store
                .ensure_desired_intent(&source, &destination, &active, started_at)
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
            let destination = destination.clone();
            let revoked = revoked.clone();
            tokio::spawn(async move {
                barrier.wait().await;
                store
                    .ensure_desired_intent(
                        &source,
                        &destination,
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
                    &destination,
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
                    &destination,
                    &active,
                    started_at + chrono::Duration::seconds(5),
                )
                .await,
            Err(PersistenceError::Conflict(_))
        ));
    }
}
