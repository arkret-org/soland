use super::{
    JsonPayloadRow, Jsonb, Nullable, OptionalExtension, PersistenceError, PersistenceResult,
    PgPool, PushDeviceStore, RunQueryDsl, Text, Value, async_trait, pg_conn, sql_query,
};
use crate::PgTransactionError;
pub struct PgPushDeviceStore {
    pub pool: PgPool,
}
#[async_trait]
impl PushDeviceStore for PgPushDeviceStore {
    async fn register(&self, device: Value) -> PersistenceResult<()> {
        use diesel_async::AsyncConnection;
        let mut registration: arkret_models_integration::PushRegistrationRecord =
            serde_json::from_value(device).map_err(|error| {
                PersistenceError::Internal(format!(
                    "invalid authenticated push registration: {error}"
                ))
            })?;
        registration
            .account_id
            .validate()
            .map_err(|error| PersistenceError::Internal(error.to_string()))?;
        if registration.push_gateway.is_empty() || registration.push_route_id.is_empty() {
            return Err(PersistenceError::Internal(
                "push registration requires gateway and route".to_owned(),
            ));
        }
        let account =
            serde_json::to_value(&registration.account_id).map_err(PersistenceError::database)?;
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            // Serialize replacement and unregistration for this exact account/device.
            let lock_key = format!("push:{}:{}", registration.account_id.principal_id, registration.device_id);
            sql_query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
                .bind::<Text,_>(&lock_key).execute(&mut *conn).await.map_err(PersistenceError::database)?;
            let previous = sql_query("SELECT payload FROM push_devices WHERE payload->'account_id' = $1 AND device_id = $2 AND payload->>'push_route_id' = $3 FOR UPDATE")
                .bind::<Jsonb,_>(&account).bind::<Text,_>(registration.device_id.as_str()).bind::<Text,_>(&registration.push_route_id)
                .get_result::<JsonPayloadRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?;
            let at = chrono::Utc::now();
            registration.retained_push_targets.clear();
            if let Some(previous) = previous {
                let old: arkret_models_integration::PushRegistrationRecord = serde_json::from_value(previous.payload).map_err(PersistenceError::database)?;
                // Aliases survive salt rotation only; route/provider replacement never
                // grants an old target access to a newly registered delivery token.
                if old.push_key == registration.push_key && old.push_gateway == registration.push_gateway {
                    registration.retained_push_targets = old.retained_push_targets.into_iter().filter(|entry| at < entry.retained_until).collect();
                    if old.push_target_id != registration.push_target_id {
                        registration.retained_push_targets.push(arkret_models_integration::RetainedPushTarget {
                            push_target_id: old.push_target_id,
                            retained_until: at + chrono::Duration::hours(24),
                        });
                    }
                }
            }
            let payload = serde_json::to_value(&registration).map_err(PersistenceError::database)?;
            sql_query("INSERT INTO push_devices (id, actor_id, device_id, push_gateway, push_key, platform, app_id, payload, updated_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,NOW()) ON CONFLICT ((payload->'account_id'), device_id, (payload->>'push_route_id')) DO UPDATE SET id=EXCLUDED.id, actor_id=EXCLUDED.actor_id, push_gateway=EXCLUDED.push_gateway, push_key=EXCLUDED.push_key, platform=EXCLUDED.platform, app_id=EXCLUDED.app_id, payload=EXCLUDED.payload, updated_at=NOW()")
                .bind::<Text,_>(registration.registration_id.as_str())
                .bind::<Text,_>(registration.account_id.principal_id.as_str())
                .bind::<Text,_>(registration.device_id.as_str())
                .bind::<Text,_>(&registration.push_gateway)
                .bind::<Text,_>(registration.push_key.as_str())
                .bind::<Nullable<Text>,_>(&registration.platform)
                .bind::<Nullable<Text>,_>(&registration.app_id)
                .bind::<Jsonb,_>(&payload).execute(&mut *conn).await.map_err(PersistenceError::database)?;
            Ok(())
        }).await.map_err(PgTransactionError::into_persistence)
    }

    async fn unregister(
        &self,
        account: &arkret_wire::AccountId,
        device_id: &str,
        push_key: Option<&str>,
        app_id: Option<&str>,
    ) -> PersistenceResult<usize> {
        use diesel_async::AsyncConnection;
        let account_value = serde_json::to_value(account).map_err(PersistenceError::database)?;
        let lock_key = format!("push:{}:{device_id}", account.principal_id);
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            sql_query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))").bind::<Text,_>(&lock_key).execute(&mut *conn).await.map_err(PersistenceError::database)?;
            sql_query("DELETE FROM push_devices WHERE payload->'account_id' = $1 AND device_id = $2 AND ($3 IS NULL OR push_key = $3) AND ($4 IS NULL OR app_id = $4)")
                .bind::<Jsonb,_>(&account_value).bind::<Text,_>(device_id).bind::<Nullable<Text>,_>(push_key).bind::<Nullable<Text>,_>(app_id)
                .execute(&mut *conn).await.map_err(PgTransactionError::from)
        }).await.map_err(PgTransactionError::into_persistence)
    }

    async fn purge_principal_device(
        &self,
        actor: &str,
        device_id: &str,
    ) -> PersistenceResult<usize> {
        use diesel_async::AsyncConnection;
        let lock_key = format!("push:{actor}:{device_id}");
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            sql_query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
                .bind::<Text, _>(&lock_key)
                .execute(&mut *conn)
                .await
                .map_err(PersistenceError::database)?;
            sql_query("DELETE FROM push_devices WHERE actor_id = $1 AND device_id = $2")
                .bind::<Text, _>(actor)
                .bind::<Text, _>(device_id)
                .execute(&mut *conn)
                .await
                .map_err(PgTransactionError::from)
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<Value>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query("SELECT payload FROM push_devices ORDER BY updated_at ASC, id ASC")
            .load::<JsonPayloadRow>(&mut *conn)
            .await
            .map(|rows| rows.into_iter().map(|row| row.payload).collect())
            .map_err(PersistenceError::database)
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn postgres_push_registration_atomic_rotation_and_exact_account_removal() {
        let database = crate::test_database::TestDatabase::lease().await;
        let store = PgPushDeviceStore {
            pool: database.pool(),
        };
        let mut record: arkret_models_integration::PushRegistrationRecord = serde_json::from_value(serde_json::json!({
            "registration_id":"push_registration:first", "account_id":{"principal_id":"ak:did_core:web:alice.example", "station_id":"ak:did_core:web:station.example"},
            "device_id":"ak:device:0196419b-0000-7000-8000-000000000001",
            "push_gateway":"https://push.example/", "push_key":"token", "platform":null,
            "app_id":"app", "visible_notification_opt_in":false, "push_route_id":"app",
            "push_target_id":"ak:pseudonym:push:kosc9iQ4gVct1OB-b6X364WIFIsJFVbVzn7BMBs1sm8",
            "salt_epoch_id":"first", "expires_at":null, "retained_push_targets":[]
        })).unwrap();
        store
            .register(serde_json::to_value(&record).unwrap())
            .await
            .unwrap();
        let first_target = record.push_target_id.clone();
        record.registration_id = "push_registration:second".parse().unwrap();
        record.push_target_id = "ak:pseudonym:push:lg8aqJ2eJjms1GQpkzloxGn8F802f8RfmfmfsC85eRo"
            .parse()
            .unwrap();
        record.salt_epoch_id = "second".to_owned();
        record.visible_notification_opt_in = true;
        store
            .register(serde_json::to_value(&record).unwrap())
            .await
            .unwrap();
        let rows = store.snapshot_all().await.unwrap();
        assert_eq!(rows.len(), 1);
        let rotated: arkret_models_integration::PushRegistrationRecord =
            serde_json::from_value(rows[0].clone()).unwrap();
        assert!(rotated.accepts_target(&first_target, chrono::Utc::now()));
        assert!(rotated.visible_notification_opt_in);
        assert!(!rotated.accepts_target(
            &first_target,
            chrono::Utc::now() + chrono::Duration::hours(25)
        ));
        record.push_key = arkret_models_integration::PushKey::new("new-token").unwrap();
        record.visible_notification_opt_in = false;
        store
            .register(serde_json::to_value(&record).unwrap())
            .await
            .unwrap();
        let rows = store.snapshot_all().await.unwrap();
        let replaced: arkret_models_integration::PushRegistrationRecord =
            serde_json::from_value(rows[0].clone()).unwrap();
        assert!(replaced.retained_push_targets.is_empty());
        assert!(!replaced.visible_notification_opt_in);
        let mut wrong_account = record.account_id.clone();
        wrong_account.station_id = "ak:did_core:web:other.example".parse().unwrap();
        assert_eq!(
            store
                .unregister(&wrong_account, record.device_id.as_str(), None, None)
                .await
                .unwrap(),
            0
        );
        assert_eq!(
            store
                .unregister(
                    &record.account_id,
                    record.device_id.as_str(),
                    Some("token"),
                    None
                )
                .await
                .unwrap(),
            0
        );
        assert_eq!(
            store
                .unregister(&record.account_id, record.device_id.as_str(), None, None)
                .await
                .unwrap(),
            1
        );
        assert!(store.snapshot_all().await.unwrap().is_empty());
    }
}
