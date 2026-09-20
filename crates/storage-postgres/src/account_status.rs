use arkret_models_collaboration::account_status::{AccountStatusReceipt, AccountStatusRecord};
use soland_storage::{
    AccountStatusAffectedServiceObservation, classify_account_status_replica_append,
};

use super::{
    AccountStatusReplicaAppend, AccountStatusReplicaStore, AsyncConnection, BigInt, Jsonb,
    OptionalExtension, PersistenceError, PersistenceResult, PgPool, PgTransactionError,
    QueryableByName, RunQueryDsl, Text, Timestamptz, async_trait, pg_conn, sql_query,
};

/// The durable replica head for one `(account_authority_id, account_id)` pair:
/// the accepted record and the receipt that acknowledged it.
type ReplicaHead = (AccountStatusRecord, AccountStatusReceipt);

pub struct PgAccountStatusReplicaStore {
    pub pool: PgPool,
}

#[derive(QueryableByName)]
struct RecordRow {
    #[diesel(sql_type = Jsonb)]
    record: serde_json::Value,
    #[diesel(sql_type = Jsonb)]
    receipt: serde_json::Value,
}

#[derive(QueryableByName)]
struct AffectedServiceRow {
    #[diesel(sql_type = Text)]
    service_id: String,
}

#[derive(QueryableByName)]
struct AffectedSourceRow {
    #[diesel(sql_type = Text)]
    source: String,
}

#[derive(QueryableByName)]
struct AffectedCandidateRow {
    #[diesel(sql_type = Text)]
    source: String,
    #[diesel(sql_type = Text)]
    candidate: String,
}

fn affected_source(
    value: &str,
) -> PersistenceResult<soland_storage::AccountStatusAffectedServiceSource> {
    use soland_storage::AccountStatusAffectedServiceSource as Source;
    match value {
        "session" => Ok(Source::Session),
        "device" => Ok(Source::Device),
        "key_package" => Ok(Source::KeyPackage),
        "to_device" => Ok(Source::ToDevice),
        "push_route" => Ok(Source::PushRoute),
        "principal_locator" => Ok(Source::PrincipalLocator),
        "realm_membership" => Ok(Source::RealmMembership),
        other => Err(PersistenceError::Internal(format!(
            "stored affected-service source is invalid: {other}"
        ))),
    }
}

fn push_unique_observation(
    observations: &mut Vec<AccountStatusAffectedServiceObservation>,
    service_id: arkret_wire::DidCoreId,
    source: soland_storage::AccountStatusAffectedServiceSource,
    observed_at: chrono::DateTime<chrono::Utc>,
) {
    if observations
        .iter()
        .any(|observation| observation.service_id == service_id && observation.source == source)
    {
        return;
    }
    observations.push(AccountStatusAffectedServiceObservation {
        service_id,
        source,
        observed_at,
    });
}

fn decode_record(row: &RecordRow) -> PersistenceResult<AccountStatusRecord> {
    serde_json::from_value(row.record.clone()).map_err(|error| {
        PersistenceError::Internal(format!("stored account-status record is invalid: {error}"))
    })
}

fn decode_receipt(row: &RecordRow) -> PersistenceResult<AccountStatusReceipt> {
    serde_json::from_value(row.receipt.clone()).map_err(|error| {
        PersistenceError::Internal(format!("stored account-status receipt is invalid: {error}"))
    })
}

fn encode_account_id(account: &arkret_wire::AccountId) -> PersistenceResult<serde_json::Value> {
    serde_json::to_value(account).map_err(|error| {
        PersistenceError::Internal(format!("account identity cannot be encoded: {error}"))
    })
}

#[async_trait]
impl AccountStatusReplicaStore for PgAccountStatusReplicaStore {
    async fn append(
        &self,
        record: &AccountStatusRecord,
        receipt: &AccountStatusReceipt,
    ) -> PersistenceResult<AccountStatusReplicaAppend> {
        receipt.validate_for_record(record).map_err(|error| {
            PersistenceError::SchemaViolation(format!(
                "account-status record/receipt pair is invalid: {error}"
            ))
        })?;
        let mut conn = pg_conn(&self.pool).await?;
        let record = record.clone();
        let receipt = receipt.clone();
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            let authority = record.account_authority_id.to_string();
            let account = encode_account_id(&record.account_id)?;
            let lock_key = format!("account-status:{authority}:{}", record.account_id);
            sql_query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
                .bind::<Text, _>(&lock_key)
                .execute(&mut *conn)
                .await
                .map_err(PersistenceError::database)?;

            let head = sql_query(
                "SELECT record, receipt FROM account_status_replica_records \
                 WHERE account_authority_id = $1 AND account_id = $2 \
                 ORDER BY status_seq DESC LIMIT 1",
            )
            .bind::<Text, _>(&authority)
            .bind::<Jsonb, _>(&account)
            .get_result::<RecordRow>(&mut *conn)
            .await
            .optional()
            .map_err(PersistenceError::database)?
            .map(|row| -> PersistenceResult<ReplicaHead> {
                Ok((decode_record(&row)?, decode_receipt(&row)?))
            })
            .transpose()?;

            if let Some(outcome) = classify_account_status_replica_append(&record, head.as_ref()) {
                return Ok(outcome);
            }

            sql_query(
                "INSERT INTO account_status_replica_records \
                 (account_authority_id, account_id, status_seq, record_id, record, receipt) \
                 VALUES ($1, $2, $3, $4, $5, $6)",
            )
            .bind::<Text, _>(&authority)
            .bind::<Jsonb, _>(&account)
            .bind::<BigInt, _>(i64::try_from(record.status_seq).map_err(|_| {
                PersistenceError::SchemaViolation(
                    "account-status sequence exceeds PostgreSQL bigint".to_owned(),
                )
            })?)
            .bind::<Text, _>(record.account_status_record_id.as_str())
            .bind::<Jsonb, _>(serde_json::to_value(&record).map_err(|error| {
                PersistenceError::Internal(format!(
                    "account-status record cannot be encoded: {error}"
                ))
            })?)
            .bind::<Jsonb, _>(serde_json::to_value(&receipt).map_err(|error| {
                PersistenceError::Internal(format!(
                    "account-status receipt cannot be encoded: {error}"
                ))
            })?)
            .execute(&mut *conn)
            .await
            .map_err(PersistenceError::database)?;
            Ok(AccountStatusReplicaAppend::Accepted(receipt))
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }

    async fn current(
        &self,
        account_authority_id: &str,
        account_id: &arkret_wire::AccountId,
    ) -> PersistenceResult<Option<AccountStatusRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "SELECT record, receipt FROM account_status_replica_records \
             WHERE account_authority_id = $1 AND account_id = $2 \
             ORDER BY status_seq DESC LIMIT 1",
        )
        .bind::<Text, _>(account_authority_id)
        .bind::<Jsonb, _>(encode_account_id(account_id)?)
        .get_result::<RecordRow>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?
        .map(|row| decode_record(&row))
        .transpose()
    }

    async fn resolve(
        &self,
        account_authority_id: &str,
        account_id: &arkret_wire::AccountId,
        from_status_seq: u64,
        limit: u16,
    ) -> PersistenceResult<Vec<AccountStatusRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        let rows = sql_query(
            "SELECT record, receipt FROM account_status_replica_records \
             WHERE account_authority_id = $1 AND account_id = $2 AND status_seq >= $3 \
             ORDER BY status_seq ASC LIMIT $4",
        )
        .bind::<Text, _>(account_authority_id)
        .bind::<Jsonb, _>(encode_account_id(account_id)?)
        .bind::<BigInt, _>(i64::try_from(from_status_seq).map_err(|_| {
            PersistenceError::SchemaViolation(
                "account-status sequence exceeds PostgreSQL bigint".to_owned(),
            )
        })?)
        .bind::<BigInt, _>(i64::from(limit))
        .load::<RecordRow>(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
        rows.into_iter().map(|row| decode_record(&row)).collect()
    }

    async fn erasure_pending(&self, limit: u16) -> PersistenceResult<Vec<AccountStatusRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        let rows = sql_query(
            "SELECT record, receipt FROM account_status_replica_records \
             WHERE record #>> '{status}' = 'erasure_pending' \
             ORDER BY accepted_at, account_authority_id, account_id, status_seq LIMIT $1",
        )
        .bind::<BigInt, _>(i64::from(limit))
        .load::<RecordRow>(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
        rows.into_iter().map(|row| decode_record(&row)).collect()
    }

    async fn receipt(
        &self,
        account_authority_id: &str,
        account_id: &arkret_wire::AccountId,
        status_seq: u64,
    ) -> PersistenceResult<Option<AccountStatusReceipt>> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "SELECT record, receipt FROM account_status_replica_records \
             WHERE account_authority_id = $1 AND account_id = $2 AND status_seq = $3",
        )
        .bind::<Text, _>(account_authority_id)
        .bind::<Jsonb, _>(encode_account_id(account_id)?)
        .bind::<BigInt, _>(i64::try_from(status_seq).map_err(|_| {
            PersistenceError::SchemaViolation(
                "account-status sequence exceeds PostgreSQL bigint".to_owned(),
            )
        })?)
        .get_result::<RecordRow>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?
        .map(|row| decode_receipt(&row))
        .transpose()
    }

    async fn merge_affected_services(
        &self,
        account_id: &arkret_wire::AccountId,
        observations: &[AccountStatusAffectedServiceObservation],
        max_services: usize,
    ) -> PersistenceResult<Vec<arkret_wire::DidCoreId>> {
        if max_services == 0 {
            return Err(PersistenceError::SchemaViolation(
                "account-status affected-service limit must be positive".to_owned(),
            ));
        }
        let mut conn = pg_conn(&self.pool).await?;
        let account = encode_account_id(account_id)?;
        let observations = observations.to_vec();
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            let lock_key = format!("account-status-affected:{account_id}");
            sql_query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
                .bind::<Text, _>(&lock_key)
                .execute(&mut *conn)
                .await
                .map_err(PersistenceError::database)?;

            let mut services = sql_query(
                "SELECT DISTINCT service_id FROM account_status_affected_services \
                 WHERE account_id = $1 ORDER BY service_id",
            )
            .bind::<Jsonb, _>(&account)
            .load::<AffectedServiceRow>(&mut *conn)
            .await
            .map_err(PersistenceError::database)?
            .into_iter()
            .map(|row| row.service_id)
            .collect::<std::collections::BTreeSet<_>>();
            services.extend(
                observations
                    .iter()
                    .map(|observation| observation.service_id.as_str().to_owned()),
            );
            if services.len() > max_services {
                return Err(PersistenceError::SchemaViolation(format!(
                    "account-status affected-service set exceeds {max_services}"
                ))
                .into());
            }
            for observation in &observations {
                sql_query(
                    "INSERT INTO account_status_affected_services \
                     (account_id, service_id, source, first_observed_at, last_observed_at) \
                     VALUES ($1, $2, $3, $4, $4) \
                     ON CONFLICT (account_id, service_id, source) DO UPDATE SET \
                     last_observed_at = GREATEST(account_status_affected_services.last_observed_at, EXCLUDED.last_observed_at)",
                )
                .bind::<Jsonb, _>(&account)
                .bind::<Text, _>(observation.service_id.as_str())
                .bind::<Text, _>(observation.source.as_str())
                .bind::<Timestamptz, _>(observation.observed_at)
                .execute(&mut *conn)
                .await
                .map_err(PersistenceError::database)?;
            }
            Ok(services
                .into_iter()
                .map(|service_id| {
                    arkret_wire::DidCoreId::new(service_id).map_err(|error| {
                        PersistenceError::Internal(format!(
                            "stored affected service id is invalid: {error}"
                        ))
                    })
                })
                .collect::<PersistenceResult<Vec<_>>>()?)
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }

    async fn discover_affected_services(
        &self,
        account_id: &arkret_wire::AccountId,
        holder_service_id: &arkret_wire::DidCoreId,
        observed_at: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<Vec<AccountStatusAffectedServiceObservation>> {
        let mut conn = pg_conn(&self.pool).await?;
        let account_actor = arkret_wire::ActorId::account(account_id.clone()).to_string();
        let account = encode_account_id(account_id)?;
        let local_sources = sql_query(
            "SELECT 'session'::text AS source WHERE EXISTS (SELECT 1 FROM sessions WHERE actor_id = $1) \
             UNION ALL SELECT 'device'::text WHERE EXISTS (SELECT 1 FROM devices WHERE actor_id = $1) \
             UNION ALL SELECT 'key_package'::text WHERE EXISTS (SELECT 1 FROM mls_key_packages WHERE actor_id = $1) \
             UNION ALL SELECT 'to_device'::text WHERE EXISTS (SELECT 1 FROM device_messages WHERE sender = $1 OR recipient = $1) \
             UNION ALL SELECT 'push_route'::text WHERE EXISTS (SELECT 1 FROM push_devices WHERE payload->'account_id' = $2) \
             UNION ALL SELECT 'principal_locator'::text WHERE EXISTS (SELECT 1 FROM invite_locators WHERE subject_id = $1 OR recipient_id = $1)",
        )
        .bind::<Text, _>(&account_actor)
        .bind::<Jsonb, _>(&account)
        .load::<AffectedSourceRow>(&mut conn)
        .await
        .map_err(PersistenceError::database)?;

        let mut observations = Vec::new();
        for row in local_sources {
            push_unique_observation(
                &mut observations,
                holder_service_id.clone(),
                affected_source(&row.source)?,
                observed_at,
            );
        }

        // Session audiences are explicit service identities. They are not
        // inferred from a URL or deployment config.
        let session_candidates = sql_query(
            "SELECT DISTINCT 'session'::text AS source, audience AS candidate \
             FROM sessions WHERE actor_id = $1",
        )
        .bind::<Text, _>(&account_actor)
        .load::<AffectedCandidateRow>(&mut conn)
        .await
        .map_err(PersistenceError::database)?;
        for row in session_candidates {
            if let Ok(service_id) = arkret_wire::DidCoreId::new(row.candidate) {
                push_unique_observation(
                    &mut observations,
                    service_id,
                    affected_source(&row.source)?,
                    observed_at,
                );
            }
        }

        // To-device and locator rows can name a peer only through the typed
        // counterpart ActorId. Malformed or principal-only strings do not
        // broaden the affected set.
        let actor_candidates = sql_query(
            "SELECT DISTINCT 'to_device'::text AS source, \
                 CASE WHEN sender = $1 THEN recipient ELSE sender END AS candidate \
             FROM device_messages WHERE sender = $1 OR recipient = $1 \
             UNION ALL \
             SELECT DISTINCT 'principal_locator'::text AS source, \
                 CASE WHEN subject_id = $1 THEN recipient_id ELSE subject_id END AS candidate \
             FROM invite_locators WHERE subject_id = $1 OR recipient_id = $1",
        )
        .bind::<Text, _>(&account_actor)
        .load::<AffectedCandidateRow>(&mut conn)
        .await
        .map_err(PersistenceError::database)?;
        for row in actor_candidates {
            let Ok(actor) = serde_json::from_str::<arkret_wire::ActorId>(&row.candidate) else {
                continue;
            };
            push_unique_observation(
                &mut observations,
                actor.route_service_id().clone(),
                affected_source(&row.source)?,
                observed_at,
            );
        }
        Ok(observations)
    }

    async fn affected_services(
        &self,
        account_id: &arkret_wire::AccountId,
        limit: usize,
    ) -> PersistenceResult<Vec<arkret_wire::DidCoreId>> {
        let mut conn = pg_conn(&self.pool).await?;
        let rows = sql_query(
            "SELECT DISTINCT service_id FROM account_status_affected_services \
             WHERE account_id = $1 ORDER BY service_id LIMIT $2",
        )
        .bind::<Jsonb, _>(encode_account_id(account_id)?)
        .bind::<BigInt, _>(i64::try_from(limit).map_err(|_| {
            PersistenceError::SchemaViolation(
                "account-status affected-service read limit exceeds PostgreSQL bigint".to_owned(),
            )
        })?)
        .load::<AffectedServiceRow>(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
        rows.into_iter()
            .map(|row| {
                arkret_wire::DidCoreId::new(row.service_id).map_err(|error| {
                    PersistenceError::Internal(format!(
                        "stored affected service id is invalid: {error}"
                    ))
                })
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use soland_storage::{
        AccountStatusAffectedServiceSource,
        contract_tests::assert_account_status_replica_decision_table_contract,
    };

    use super::*;

    #[derive(QueryableByName)]
    struct TestAccountPk {
        #[diesel(sql_type = BigInt)]
        pk: i64,
    }

    /// The shared contract pool. `SOLAND_TEST_DATABASE_URL` or `DATABASE_URL`
    /// must name a reachable database; these contracts fail rather than skip.
    async fn test_pool() -> PgPool {
        crate::test_database::contract_pool().await
    }

    /// Each run claims a fresh account so the shared database cannot leak a
    /// durable head between runs.
    fn unique_namespace() -> String {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock is after the unix epoch")
            .as_nanos();
        format!("postgres-account-status-{nanos}")
    }

    #[tokio::test]
    async fn postgres_adapter_satisfies_account_status_decision_table() {
        let pool = test_pool().await;
        let store = PgAccountStatusReplicaStore { pool };
        assert_account_status_replica_decision_table_contract(&store, &unique_namespace()).await;
    }

    #[tokio::test]
    async fn postgres_affected_service_index_is_durable_bounded_and_source_deduplicated() {
        let pool = test_pool().await;
        let namespace = unique_namespace();
        let account_id = arkret_wire::AccountId::new(
            arkret_wire::DidCoreId::new(format!("ak:did_core:web:{namespace}.example")).unwrap(),
            arkret_wire::DidCoreId::new("ak:did_core:web:origin.example").unwrap(),
        );
        let service_a = arkret_wire::DidCoreId::new("ak:did_core:web:target-a.example").unwrap();
        let service_b = arkret_wire::DidCoreId::new("ak:did_core:web:target-b.example").unwrap();
        let service_c = arkret_wire::DidCoreId::new("ak:did_core:web:target-c.example").unwrap();
        let observed_at = chrono::Utc::now();
        let store = PgAccountStatusReplicaStore { pool: pool.clone() };

        let services = store
            .merge_affected_services(
                &account_id,
                &[
                    AccountStatusAffectedServiceObservation {
                        service_id: service_a.clone(),
                        source: AccountStatusAffectedServiceSource::RealmMembership,
                        observed_at,
                    },
                    AccountStatusAffectedServiceObservation {
                        service_id: service_a.clone(),
                        source: AccountStatusAffectedServiceSource::Session,
                        observed_at,
                    },
                    AccountStatusAffectedServiceObservation {
                        service_id: service_b.clone(),
                        source: AccountStatusAffectedServiceSource::Device,
                        observed_at,
                    },
                ],
                2,
            )
            .await
            .expect("two distinct services fit the configured ceiling");
        assert_eq!(services, vec![service_a.clone(), service_b.clone()]);

        let error = store
            .merge_affected_services(
                &account_id,
                &[AccountStatusAffectedServiceObservation {
                    service_id: service_c,
                    source: AccountStatusAffectedServiceSource::PushRoute,
                    observed_at,
                }],
                2,
            )
            .await
            .expect_err("a third distinct service must fail closed");
        assert!(matches!(error, PersistenceError::SchemaViolation(_)));

        // A new adapter instance models process restart: durable targets remain,
        // while the rejected over-limit observation left no partial row behind.
        let restarted = PgAccountStatusReplicaStore { pool };
        assert_eq!(
            restarted
                .affected_services(&account_id, 3)
                .await
                .expect("durable index is readable after restart"),
            vec![service_a, service_b]
        );
    }

    #[tokio::test]
    async fn postgres_discovers_the_closed_local_state_source_families_for_exact_account() {
        let pool = test_pool().await;
        let namespace = unique_namespace();
        let account_id = arkret_wire::AccountId::new(
            arkret_wire::DidCoreId::new(format!("ak:did_core:web:{namespace}.example")).unwrap(),
            arkret_wire::DidCoreId::new(format!("ak:did_core:web:origin-{namespace}.example"))
                .unwrap(),
        );
        let account_actor = arkret_wire::ActorId::account(account_id.clone()).to_string();
        let holder =
            arkret_wire::DidCoreId::new(format!("ak:did_core:web:holder-{namespace}.example"))
                .unwrap();
        let peer = arkret_wire::DidCoreId::new(format!("ak:did_core:web:peer-{namespace}.example"))
            .unwrap();
        let peer_actor = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
            arkret_wire::DidCoreId::new(format!(
                "ak:did_core:web:peer-principal-{namespace}.example"
            ))
            .unwrap(),
            peer.clone(),
        ))
        .to_string();
        let now = chrono::Utc::now();
        let mut conn = pg_conn(&pool).await.expect("contract database connection");
        let account_pk = sql_query(
            "INSERT INTO accounts (principal_id, station_id, payload) VALUES ($1, $2, '{}'::jsonb) RETURNING pk",
        )
        .bind::<Text, _>(account_id.principal_id.as_str())
        .bind::<Text, _>(account_id.station_id.as_str())
        .get_result::<TestAccountPk>(&mut conn)
        .await
        .expect("insert exact account")
        .pk;
        sql_query(
            "INSERT INTO sessions (id, account_pk, actor_id, device_id, audience, expires_at) \
             VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind::<Text, _>(format!("session-{namespace}"))
        .bind::<BigInt, _>(account_pk)
        .bind::<Text, _>(&account_actor)
        .bind::<Text, _>(format!("device-{namespace}"))
        .bind::<Text, _>(peer.as_str())
        .bind::<Timestamptz, _>(now + chrono::Duration::hours(1))
        .execute(&mut conn)
        .await
        .expect("insert session source");
        sql_query(
            "INSERT INTO device_inventory_station (singleton, station_id) VALUES (TRUE, $1) \
             ON CONFLICT (singleton) DO NOTHING",
        )
        .bind::<Text, _>(holder.as_str())
        .execute(&mut conn)
        .await
        .expect("ensure device inventory owner");
        sql_query(
            "INSERT INTO devices (id, actor_id, device_id, payload) VALUES ($1, $2, $3, '{}'::jsonb)",
        )
        .bind::<diesel::sql_types::Uuid, _>(uuid::Uuid::new_v4())
        .bind::<Text, _>(&account_actor)
        .bind::<Text, _>(format!("inventory-device-{namespace}"))
        .execute(&mut conn)
        .await
        .expect("insert device source");
        sql_query(
            "INSERT INTO mls_key_packages \
             (id, keypackage_ref, keypackage_digest, owner_account_pk, actor_id, device_id, \
              key_package_bytes, capabilities, capabilities_digest, last_resort, \
              lifetime_not_before, lifetime_not_after, device_authorize_event_id, created_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, '[]'::jsonb, $8, FALSE, 1, 2, $9, 1)",
        )
        .bind::<Text, _>(format!("key-package-{namespace}"))
        .bind::<Text, _>(format!("key-package-ref-{namespace}"))
        .bind::<Text, _>(format!("sha256:{:0<64}", namespace))
        .bind::<BigInt, _>(account_pk)
        .bind::<Text, _>(&account_actor)
        .bind::<Text, _>(format!("inventory-device-{namespace}"))
        .bind::<diesel::sql_types::Binary, _>(vec![1_u8])
        .bind::<Text, _>(format!("sha256:{:1<64}", namespace))
        .bind::<diesel::sql_types::Binary, _>(vec![0_u8; 33])
        .execute(&mut conn)
        .await
        .expect("insert KeyPackage source");
        sql_query(
            "INSERT INTO device_messages \
             (id, idempotency_key, sender, recipient, device_id, recipient_device_authorization, position, content) \
             VALUES ($1, $2, $3, $4, $5, '{}'::jsonb, 1, '{}'::jsonb)",
        )
        .bind::<diesel::sql_types::Uuid, _>(uuid::Uuid::new_v4())
        .bind::<Text, _>(format!("message-{namespace}"))
        .bind::<Text, _>(&account_actor)
        .bind::<Text, _>(&peer_actor)
        .bind::<Text, _>(format!("peer-device-{namespace}"))
        .execute(&mut conn)
        .await
        .expect("insert to-device source");
        sql_query(
            "INSERT INTO push_devices \
             (id, actor_id, device_id, device_authorization, push_gateway, push_key, payload) \
             VALUES ($1, $2, $3, '{}'::jsonb, $4, $5, $6)",
        )
        .bind::<Text, _>(format!("push-{namespace}"))
        .bind::<Text, _>(&account_actor)
        .bind::<Text, _>(format!("inventory-device-{namespace}"))
        .bind::<Text, _>("https://push.invalid/")
        .bind::<Text, _>(format!("push-key-{namespace}"))
        .bind::<Jsonb, _>(serde_json::json!({
            "account_id": account_id,
            "push_route_id": format!("route-{namespace}"),
            "push_target_id": format!("target-{namespace}")
        }))
        .execute(&mut conn)
        .await
        .expect("insert push-route source");
        sql_query(
            "INSERT INTO invite_locators \
             (locator_id, token_digest, subject_id, recipient_id, issued_at, expires_at, record_payload) \
             VALUES ($1, $2, $3, $4, $5, $6, '{}'::jsonb)",
        )
        .bind::<Text, _>(format!("locator-{namespace}"))
        .bind::<Text, _>(format!("token-{namespace}"))
        .bind::<Text, _>(&account_actor)
        .bind::<Text, _>(&peer_actor)
        .bind::<Timestamptz, _>(now)
        .bind::<Timestamptz, _>(now + chrono::Duration::hours(1))
        .execute(&mut conn)
        .await
        .expect("insert principal-locator source");

        let store = PgAccountStatusReplicaStore { pool };
        let observations = store
            .discover_affected_services(&account_id, &holder, now)
            .await
            .expect("discover closed source families");
        for source in [
            AccountStatusAffectedServiceSource::Session,
            AccountStatusAffectedServiceSource::Device,
            AccountStatusAffectedServiceSource::KeyPackage,
            AccountStatusAffectedServiceSource::ToDevice,
            AccountStatusAffectedServiceSource::PushRoute,
            AccountStatusAffectedServiceSource::PrincipalLocator,
        ] {
            assert!(observations.iter().any(|observation| {
                observation.source == source && observation.service_id == holder
            }));
        }
        for source in [
            AccountStatusAffectedServiceSource::Session,
            AccountStatusAffectedServiceSource::ToDevice,
            AccountStatusAffectedServiceSource::PrincipalLocator,
        ] {
            assert!(observations.iter().any(|observation| {
                observation.source == source && observation.service_id == peer
            }));
        }
    }
}
