//! Accepted KeyBackup pointer projection and same-snapshot PCR head read.

use arkret_models_collaboration::events_payloads::{
    KeyBackupActiveSeries, validate_key_backup_active_series_record,
    validate_key_backup_active_series_transition,
};
use arkret_models_crypto::{
    BackupActiveSeriesPointer, BackupActiveSeriesState, BackupKind,
    derive_key_backup_active_series_current_key,
};
use arkret_wire::{AccountId, ActorId, CommitStreamRef, Event, RealmCommit};
use diesel::sql_types::{BigInt, Jsonb, Nullable, Text, Timestamptz};
use diesel::{OptionalExtension, QueryableByName, sql_query};
use diesel_async::RunQueryDsl;
use serde_json::Value;

use crate::{AsyncPgConnection, PersistenceError, PersistenceResult, PgPool, pg_conn};

#[derive(QueryableByName)]
struct CurrentRow {
    #[diesel(sql_type = Jsonb)]
    value: Value,
}

#[derive(QueryableByName)]
struct ConfirmedPointerRow {
    #[diesel(sql_type = Text)]
    pcr_realm_id: String,
    #[diesel(sql_type = Text)]
    head_commit_id: String,
    #[diesel(sql_type = BigInt)]
    head_position: i64,
    #[diesel(sql_type = Nullable<Text>)]
    pointer_commit_id: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    pointer_event_id: Option<String>,
    #[diesel(sql_type = Nullable<BigInt>)]
    pointer_position: Option<i64>,
    #[diesel(sql_type = Nullable<Jsonb>)]
    pointer_value: Option<Value>,
    #[diesel(sql_type = Nullable<Jsonb>)]
    pointer_commit_json: Option<Value>,
}

fn invalid(message: impl Into<String>) -> PersistenceError {
    PersistenceError::SchemaViolation(message.into())
}

/// Project the exact signed payload in the same transaction as its accepting
/// RealmCommit. The caller must have already verified producer authority and
/// the device-generation source anchor; this function enforces the durable
/// pointer CAS against concurrent accepts.
pub(crate) async fn commit_key_backup_pointer_in_connection(
    conn: &mut AsyncPgConnection,
    event: &Event,
    commit: &RealmCommit,
) -> PersistenceResult<()> {
    if event.kind != arkret_wire::EventKind::KeyBackupActiveSeries {
        return Ok(());
    }
    let record: KeyBackupActiveSeries = serde_json::from_value(
        serde_json::to_value(&event.payload).map_err(PersistenceError::database)?,
    )
    .map_err(|error| invalid(format!("KeyBackup pointer payload is invalid: {error}")))?;
    if record.actor_id != event.actor_id
        || commit.event_ref != event.event_id
        || commit.realm_id != event.realm_id
        || commit.stream_ref
            != (CommitStreamRef::Realm {
                realm_id: event.realm_id.clone(),
            })
    {
        return Err(invalid("KeyBackup pointer Event and RealmCommit differ"));
    }
    let account = record
        .actor_id
        .as_account_id()
        .ok_or_else(|| invalid("KeyBackup pointer actor is not an account"))?;
    let current_key =
        derive_key_backup_active_series_current_key(&record.actor_id, record.backup_kind)
            .map_err(|error| invalid(error.to_string()))?;
    let pcr = sql_query(
        "SELECT pcr_realm_id FROM principal_resolutions \
         WHERE principal_id=$1 AND station_id=$2 FOR SHARE",
    )
    .bind::<Text, _>(account.principal_id.as_str())
    .bind::<Text, _>(account.station_id.as_str())
    .get_result::<PcrRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?
    .ok_or_else(|| invalid("KeyBackup pointer PCR is unavailable"))?;
    if pcr.pcr_realm_id != event.realm_id.as_str() {
        return Err(invalid("KeyBackup pointer targets a different PCR"));
    }
    let prior = sql_query(
        "SELECT value FROM key_backup_active_series_current_results \
         WHERE realm_id=$1 AND current_key=$2 FOR UPDATE",
    )
    .bind::<Text, _>(event.realm_id.as_str())
    .bind::<Text, _>(&current_key)
    .get_result::<CurrentRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?;
    let prior = prior
        .map(|row| {
            serde_json::from_value::<KeyBackupActiveSeries>(row.value)
                .map_err(|error| invalid(format!("stored KeyBackup pointer is invalid: {error}")))
        })
        .transpose()?;
    let prior_head = prior
        .as_ref()
        .map(arkret_models_collaboration::events_payloads::key_backup_active_series_head)
        .transpose()
        .map_err(|error| invalid(error.to_string()))?;
    validate_key_backup_active_series_transition(prior_head.as_ref(), &record)
        .map_err(|error| invalid(error.to_string()))?;
    if prior
        .as_ref()
        .is_some_and(|prior| record.series_pointer_version <= prior.series_pointer_version)
    {
        return Err(PersistenceError::Conflict(
            "key_backup_active_series_pointer_version_not_advanced".to_owned(),
        ));
    }
    let position = i64::try_from(commit.stream_position)
        .map_err(|_| invalid("KeyBackup pointer stream position overflow"))?;
    let value = serde_json::to_value(&record).map_err(PersistenceError::database)?;
    sql_query(
        "INSERT INTO key_backup_active_series_current_results \
         (realm_id,current_key,actor_id,backup_kind,current_event_id,current_commit_id, \
          current_stream_position,value,updated_at) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) \
         ON CONFLICT (realm_id,current_key) DO UPDATE SET \
           current_event_id=EXCLUDED.current_event_id, \
           current_commit_id=EXCLUDED.current_commit_id, \
           current_stream_position=EXCLUDED.current_stream_position, \
           value=EXCLUDED.value,updated_at=EXCLUDED.updated_at",
    )
    .bind::<Text, _>(event.realm_id.as_str())
    .bind::<Text, _>(&current_key)
    .bind::<Jsonb, _>(serde_json::to_value(&record.actor_id).map_err(PersistenceError::database)?)
    .bind::<Text, _>(record.backup_kind.as_str())
    .bind::<Text, _>(event.event_id.as_str())
    .bind::<Text, _>(commit.commit_id.as_str())
    .bind::<BigInt, _>(position)
    .bind::<Jsonb, _>(value)
    .bind::<Timestamptz, _>(commit.committed_at)
    .execute(&mut *conn)
    .await
    .map_err(PersistenceError::database)?;
    Ok(())
}

#[derive(QueryableByName)]
struct PcrRow {
    #[diesel(sql_type = Text)]
    pcr_realm_id: String,
}

/// Returns `None` when the PCR or confirmed Realm head is unavailable. A
/// confirmed head with no pointer row yields the explicit `Absent` branch.
/// One SQL statement gives all inputs the same PostgreSQL MVCC snapshot.
pub(crate) async fn confirmed_key_backup_pointer(
    pool: &PgPool,
    account_id: &AccountId,
) -> PersistenceResult<Option<BackupActiveSeriesState>> {
    let actor = ActorId::account(account_id.clone());
    let current_key =
        derive_key_backup_active_series_current_key(&actor, BackupKind::SecretStorage)
            .map_err(|error| invalid(error.to_string()))?;
    let mut conn = pg_conn(pool).await?;
    let row = sql_query(
        "SELECT p.pcr_realm_id, h.commit_id AS head_commit_id, \
                h.stream_position AS head_position, \
                b.current_commit_id AS pointer_commit_id, \
                b.current_event_id AS pointer_event_id, \
                b.current_stream_position AS pointer_position, \
                b.value AS pointer_value, c.commit_json AS pointer_commit_json \
         FROM principal_resolutions p \
         JOIN realm_authorities a ON a.realm_id=p.pcr_realm_id \
                                  AND a.service_id=p.station_id \
         JOIN LATERAL (SELECT commit_id,stream_position FROM realm_commits \
                       WHERE realm_id=p.pcr_realm_id \
                         AND stream_ref=jsonb_build_object('kind','realm','realm_id',p.pcr_realm_id) \
                       ORDER BY stream_position DESC LIMIT 1) h ON TRUE \
         LEFT JOIN key_backup_active_series_current_results b \
           ON b.realm_id=p.pcr_realm_id AND b.current_key=$3 \
         LEFT JOIN realm_commits c ON c.commit_id=b.current_commit_id \
         WHERE p.principal_id=$1 AND p.station_id=$2",
    )
    .bind::<Text, _>(account_id.principal_id.as_str())
    .bind::<Text, _>(account_id.station_id.as_str())
    .bind::<Text, _>(&current_key)
    .get_result::<ConfirmedPointerRow>(&mut conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?;
    let Some(row) = row else { return Ok(None) };
    let control_realm_id =
        arkret_wire::RealmId::new(row.pcr_realm_id).map_err(|error| invalid(error.to_string()))?;
    let authority_commit_id = arkret_wire::RealmCommitId::new(row.head_commit_id)
        .map_err(|error| invalid(error.to_string()))?;
    let pointer = match (
        row.pointer_commit_id,
        row.pointer_event_id,
        row.pointer_position,
        row.pointer_value,
        row.pointer_commit_json,
    ) {
        (None, None, None, None, None) => BackupActiveSeriesPointer::Absent {},
        (Some(commit_id), Some(event_id), Some(position), Some(value), Some(commit_json)) => {
            let record: KeyBackupActiveSeries = serde_json::from_value(value).map_err(|error| {
                invalid(format!("stored KeyBackup pointer is invalid: {error}"))
            })?;
            let commit: RealmCommit = serde_json::from_value(commit_json)
                .map_err(|error| invalid(format!("stored pointer Commit is invalid: {error}")))?;
            if record.actor_id != actor
                || record.backup_kind != BackupKind::SecretStorage
                || commit.commit_id.as_str() != commit_id
                || commit.event_ref.as_str() != event_id
                || commit.realm_id != control_realm_id
                || commit.stream_ref
                    != (CommitStreamRef::Realm {
                        realm_id: control_realm_id.clone(),
                    })
                || commit.stream_position
                    != u64::try_from(position)
                        .map_err(|_| invalid("stored pointer position is negative"))?
                || commit.stream_position
                    > u64::try_from(row.head_position)
                        .map_err(|_| invalid("stored head position is negative"))?
            {
                return Err(invalid(
                    "KeyBackup pointer is not bound to the confirmed PCR cut",
                ));
            }
            validate_key_backup_active_series_record(&record)
                .map_err(|error| invalid(error.to_string()))?;
            if record.series_pointer_version == 0 {
                return Err(invalid("stored KeyBackup pointer version is zero"));
            }
            BackupActiveSeriesPointer::Active {
                active_series_id: record.active_series_id,
                series_pointer_version: record.series_pointer_version,
            }
        }
        _ => return Err(invalid("KeyBackup pointer provenance is incomplete")),
    };
    Ok(Some(BackupActiveSeriesState {
        account_id: account_id.clone(),
        control_realm_id,
        authority_commit_id,
        secret_storage: pointer,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AsyncConnection, Binary, PgTransactionError};

    #[derive(QueryableByName)]
    struct CountRow {
        #[diesel(sql_type = BigInt)]
        count: i64,
    }

    fn account() -> AccountId {
        AccountId::new(
            arkret_wire::DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
            arkret_wire::DidCoreId::new("ak:did_core:web:station.example").unwrap(),
        )
    }

    fn commit(
        event_id: arkret_wire::EventId,
        realm_id: arkret_wire::RealmId,
        position: u64,
        previous: Option<arkret_wire::RealmCommitId>,
    ) -> RealmCommit {
        let now = chrono::DateTime::parse_from_rfc3339("2026-09-24T00:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        RealmCommit {
            commit_id: arkret_wire::RealmCommitId::from_digest([position as u8 + 10; 32]),
            realm_id: realm_id.clone(),
            stream_ref: CommitStreamRef::Realm { realm_id },
            stream_position: position,
            previous_commit_ref: previous,
            event_ref: event_id.clone(),
            governance_generation: 0,
            authority_ref: arkret_wire::RealmCommitAuthorityRef::GenesisOrChangeEvent(event_id),
            committed_at: now,
            signature: arkret_wire::DetachedObjectSignature {
                context: arkret_wire::DetachedSignatureContext::RealmCommit,
                signature_algorithm: arkret_wire::DetachedSignatureAlgorithm::Ed25519,
                verification_method: arkret_wire::DidUrl::new("did:web:station.example#authority")
                    .unwrap(),
                signed_digest: arkret_wire::Hash::new(format!("sha256:{}", "aa".repeat(32)))
                    .unwrap(),
                created_at: now,
                sig: arkret_wire::Base64UrlString::new("c2lnbmF0dXJl").unwrap(),
            },
        }
    }

    async fn insert_commit(conn: &mut AsyncPgConnection, commit: &RealmCommit, event: &Event) {
        let token = crate::ids::event_token_part_expect_internal(event.event_id.as_str(), "event");
        sql_query(
            "INSERT INTO canonical_events \
             (id,digest_suite,digest,actor_id,realm_id,scope_ref,kind,canonical_bytes,envelope,state,received_at,committed_at) \
             VALUES($1,1,$2,$3,$4,$5,$6,'\\x00'::bytea,$7,'committed',$8,$8)",
        )
        .bind::<Binary, _>(token.to_vec())
        .bind::<Binary, _>(token[1..].to_vec())
        .bind::<Text, _>(event.actor_id.to_string())
        .bind::<Text, _>(event.realm_id.as_str())
        .bind::<Jsonb, _>(serde_json::to_value(&event.scope_ref).unwrap())
        .bind::<Text, _>(event.kind.as_str())
        .bind::<Jsonb, _>(serde_json::to_value(event).unwrap())
        .bind::<Timestamptz, _>(commit.committed_at)
        .execute(&mut *conn)
        .await
        .unwrap();
        sql_query(
            "INSERT INTO realm_commits \
             (commit_id,realm_id,stream_key,stream_ref,stream_position,previous_commit_ref,event_pk,governance_generation,commit_json,committed_at) \
             SELECT $1,$2,$3,$4,$5,$6,pk,0,$7,$8 FROM canonical_events WHERE id=$9",
        )
        .bind::<Text, _>(commit.commit_id.as_str())
        .bind::<Text, _>(commit.realm_id.as_str())
        .bind::<Text, _>(arkret_canonical::canonical_json_string(&commit.stream_ref).unwrap())
        .bind::<Jsonb, _>(serde_json::to_value(&commit.stream_ref).unwrap())
        .bind::<BigInt, _>(commit.stream_position as i64)
        .bind::<Nullable<Text>, _>(commit.previous_commit_ref.as_ref().map(|id| id.as_str()))
        .bind::<Jsonb, _>(serde_json::to_value(commit).unwrap())
        .bind::<Timestamptz, _>(commit.committed_at)
        .bind::<Binary, _>(token.to_vec())
        .execute(&mut *conn)
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn pointer_is_visible_only_with_accepted_commit_and_survives_rollback() {
        let database = crate::test_database::TestDatabase::lease().await;
        let pool = database.pool();
        let account = account();
        let realm_id = arkret_wire::RealmId::from_event_id(&arkret_wire::EventId::from_digest(
            arkret_canonical::DigestSuite::Sha256,
            [1; 32],
        ));
        let genesis = arkret_wire::test_support::raw_event(
            arkret_wire::EventKind::RealmCreate.as_str(),
            arkret_wire::ScopeRef::Realm {
                realm_id: realm_id.clone(),
            },
            account.principal_id.clone(),
            account.station_id.clone(),
            serde_json::json!({"genesis":true}),
        )
        .unwrap();
        let genesis_commit = commit(genesis.event_id.clone(), realm_id.clone(), 0, None);
        let mut conn = pg_conn(&pool).await.unwrap();
        sql_query(
            "INSERT INTO realm_authorities(realm_id,generation,service_id,authority_ref) VALUES($1,0,$2,$3)",
        )
        .bind::<Text, _>(realm_id.as_str())
        .bind::<Text, _>(account.station_id.as_str())
        .bind::<Jsonb, _>(serde_json::to_value(&genesis_commit.authority_ref).unwrap())
        .execute(&mut conn)
        .await
        .unwrap();
        sql_query(
            "INSERT INTO principal_resolutions \
             (principal_id,station_id,pcr_realm_id,genesis_event_id,current_event_id,projection,updated_at) \
             VALUES($1,$2,$3,$4,$4,'{}'::jsonb,now())",
        )
        .bind::<Text, _>(account.principal_id.as_str())
        .bind::<Text, _>(account.station_id.as_str())
        .bind::<Text, _>(realm_id.as_str())
        .bind::<Text, _>(genesis.event_id.as_str())
        .execute(&mut conn)
        .await
        .unwrap();
        insert_commit(&mut conn, &genesis_commit, &genesis).await;
        let absent = confirmed_key_backup_pointer(&pool, &account)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(absent.authority_commit_id, genesis_commit.commit_id);
        assert_eq!(absent.secret_storage, BackupActiveSeriesPointer::Absent {});

        let payload = serde_json::json!({
            "schema":"ak.schema.key_backup_active_series.v1",
            "actor_id":ActorId::account(account.clone()),
            "backup_kind":"secret_storage",
            "active_series_id":"ak:backup_series:01964137-1000-7000-8000-000000000000",
            "series_pointer_version":1,
            "previous_series_ids":[],
            "source_commit_ref":{"realm_commit_id":genesis_commit.commit_id,"device_generation_ref":1},
            "issued_at":"2026-09-24T00:00:00.000Z",
            "auth_data":{
                "verification_method":"did:web:alice.example#ak_device_01964137",
                "signature_algorithm":"Ed25519",
                "signature":"c2lnbmF0dXJl",
                "device_authorize_event_id":genesis.event_id
            }
        });
        let event = arkret_wire::test_support::raw_event(
            arkret_wire::EventKind::KeyBackupActiveSeries.as_str(),
            arkret_wire::ScopeRef::Realm {
                realm_id: realm_id.clone(),
            },
            account.principal_id.clone(),
            account.station_id.clone(),
            payload,
        )
        .unwrap();
        let successor = commit(
            event.event_id.clone(),
            realm_id,
            1,
            Some(genesis_commit.commit_id.clone()),
        );
        let generic = crate::authority_commit::commit_transaction_in_connection(
            &mut conn,
            &soland_storage::AuthorityCommitTransaction {
                expected_authority: soland_storage::CurrentRealmAuthority {
                    realm_id: successor.realm_id.clone(),
                    generation: 0,
                    service_id: account.station_id.clone(),
                    authority_ref: successor.authority_ref.clone(),
                    last_handoff_ref: None,
                },
                event: event.clone(),
                commit: successor.clone(),
                mls_state: None,
                welcomes: Vec::new(),
                recipient_queue_capacity: 0,
            },
        )
        .await;
        let generic_error = generic
            .err()
            .expect("unchecked pointer must be rejected")
            .into_persistence();
        assert!(
            matches!(&generic_error, PersistenceError::Conflict(reason)
                if reason == "key_backup_active_series_current_device_authority_unavailable"),
            "unexpected generic admission failure: {generic_error}"
        );
        let event_token =
            crate::ids::event_token_part_expect_internal(event.event_id.as_str(), "event");
        let row = sql_query(
            "SELECT (SELECT count(*) FROM canonical_events WHERE id=$1) + \
                    (SELECT count(*) FROM realm_commits WHERE commit_id=$2) + \
                    (SELECT count(*) FROM key_backup_active_series_current_results WHERE realm_id=$3) AS count",
        )
        .bind::<Binary, _>(event_token.to_vec())
        .bind::<Text, _>(successor.commit_id.as_str())
        .bind::<Text, _>(successor.realm_id.as_str())
        .get_result::<CountRow>(&mut conn)
        .await
        .unwrap();
        assert_eq!(
            row.count, 0,
            "unchecked pointer admission made durable writes"
        );
        let rollback = conn
            .transaction::<(), PgTransactionError, _>(async |conn| {
                insert_commit(conn, &successor, &event).await;
                commit_key_backup_pointer_in_connection(conn, &event, &successor).await?;
                Err(PersistenceError::Conflict("abort fixture transaction".to_owned()).into())
            })
            .await;
        assert!(rollback.is_err());
        assert_eq!(
            confirmed_key_backup_pointer(&pool, &account)
                .await
                .unwrap()
                .unwrap()
                .secret_storage,
            BackupActiveSeriesPointer::Absent {}
        );
        conn.transaction::<(), PgTransactionError, _>(async |conn| {
            insert_commit(conn, &successor, &event).await;
            commit_key_backup_pointer_in_connection(conn, &event, &successor).await?;
            Ok(())
        })
        .await
        .map_err(PgTransactionError::into_persistence)
        .unwrap();
        let active = confirmed_key_backup_pointer(&pool, &account)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(active.authority_commit_id, successor.commit_id);
        assert!(matches!(
            active.secret_storage,
            BackupActiveSeriesPointer::Active {
                series_pointer_version: 1,
                ..
            }
        ));
    }
}
