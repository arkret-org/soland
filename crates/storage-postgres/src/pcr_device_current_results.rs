//! PCR device authorization and generation typed current materialization.

use arkret_models_collaboration::events_payloads::{
    DeviceAuthorizationBindingKind, DeviceAuthorizePayload, DeviceReanchorPayload,
};
use arkret_wire::{AccountId, CommitStreamRef, Event, EventKind, RealmCommit};
use diesel::sql_types::{BigInt, Jsonb, Text, Timestamptz};
use diesel::{OptionalExtension, QueryableByName, sql_query};
use diesel_async::RunQueryDsl;
use serde_json::{Value, json};

use crate::{AsyncPgConnection, PersistenceError, PersistenceResult};

#[derive(QueryableByName)]
struct GenerationRow {
    #[diesel(sql_type = Jsonb)]
    value: Value,
}

#[derive(QueryableByName)]
struct PcrRow {
    #[diesel(sql_type = Text)]
    pcr_realm_id: String,
}

fn invalid(message: impl Into<String>) -> PersistenceError {
    PersistenceError::SchemaViolation(message.into())
}

async fn require_pcr(
    conn: &mut AsyncPgConnection,
    event: &Event,
    account: &AccountId,
    genesis_account: Option<&AccountId>,
) -> PersistenceResult<()> {
    if genesis_account.is_some() {
        if genesis_account != Some(account) {
            return Err(invalid(
                "PCR genesis device actor differs from registration account",
            ));
        }
        return Ok(());
    }
    let row = sql_query(
        "SELECT pcr_realm_id FROM principal_resolutions \
         WHERE principal_id=$1 AND station_id=$2 FOR SHARE",
    )
    .bind::<Text, _>(account.principal_id.as_str())
    .bind::<Text, _>(account.station_id.as_str())
    .get_result::<PcrRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?
    .ok_or_else(|| invalid("PCR device authority has no accepted principal resolution"))?;
    if row.pcr_realm_id != event.realm_id.as_str() {
        return Err(invalid("device authority Event is outside its PCR"));
    }
    Ok(())
}

async fn generation(
    conn: &mut AsyncPgConnection,
    realm_id: &arkret_wire::RealmId,
) -> PersistenceResult<Option<u64>> {
    let row = sql_query(
        "SELECT value FROM pcr_device_generation_current_results WHERE realm_id=$1 FOR UPDATE",
    )
    .bind::<Text, _>(realm_id.as_str())
    .get_result::<GenerationRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?;
    row.map(|row| {
        let object = row
            .value
            .as_object()
            .ok_or_else(|| invalid("stored PCR device generation is not an object"))?;
        if object.len() != 1 {
            return Err(invalid("stored PCR device generation is not closed"));
        }
        row.value["current_device_generation_ref"]
            .as_u64()
            .filter(|generation| *generation > 0)
            .ok_or_else(|| invalid("stored PCR device generation is invalid"))
    })
    .transpose()
}

async fn write_generation(
    conn: &mut AsyncPgConnection,
    commit: &RealmCommit,
    expected: Option<u64>,
    next: u64,
) -> PersistenceResult<()> {
    if (expected.is_none() && next != 1)
        || expected.is_some_and(|prior| prior.checked_add(1) != Some(next))
    {
        return Err(PersistenceError::Conflict(
            "pcr_device_generation_cas_mismatch".to_owned(),
        ));
    }
    let position = i64::try_from(commit.stream_position)
        .map_err(|_| invalid("PCR device generation position overflow"))?;
    let value = json!({"current_device_generation_ref":next});
    let affected = match expected {
        None => sql_query(
            "INSERT INTO pcr_device_generation_current_results \
                 (realm_id,current_commit_id,current_stream_position,value,updated_at) \
                 VALUES($1,$2,$3,$4,$5) ON CONFLICT(realm_id) DO NOTHING",
        )
        .bind::<Text, _>(commit.realm_id.as_str())
        .bind::<Text, _>(commit.commit_id.as_str())
        .bind::<BigInt, _>(position)
        .bind::<Jsonb, _>(&value)
        .bind::<Timestamptz, _>(commit.committed_at)
        .execute(&mut *conn)
        .await
        .map_err(PersistenceError::database)?,
        Some(prior) => sql_query(
            "UPDATE pcr_device_generation_current_results SET \
                   current_commit_id=$2,current_stream_position=$3,value=$4,updated_at=$5 \
                 WHERE realm_id=$1 AND (value->>'current_device_generation_ref')::bigint=$6",
        )
        .bind::<Text, _>(commit.realm_id.as_str())
        .bind::<Text, _>(commit.commit_id.as_str())
        .bind::<BigInt, _>(position)
        .bind::<Jsonb, _>(&value)
        .bind::<Timestamptz, _>(commit.committed_at)
        .bind::<BigInt, _>(
            i64::try_from(prior).map_err(|_| invalid("PCR generation exceeds bigint"))?,
        )
        .execute(&mut *conn)
        .await
        .map_err(PersistenceError::database)?,
    };
    if affected != 1 {
        return Err(PersistenceError::Conflict(
            "pcr_device_generation_cas_mismatch".to_owned(),
        ));
    }
    Ok(())
}

/// Materialize a device Event only after its producer proof and PCR admission
/// have been verified by a registered atomic UoW. Generic Event admission
/// must not call this function without a typed authorization guard.
pub(crate) async fn project_pcr_device_current_in_connection(
    conn: &mut AsyncPgConnection,
    event: &Event,
    commit: &RealmCommit,
    genesis_account: Option<&AccountId>,
) -> PersistenceResult<()> {
    if !matches!(
        event.kind,
        EventKind::DeviceAuthorize | EventKind::DeviceReanchor
    ) {
        return Ok(());
    }
    if commit.event_ref != event.event_id
        || commit.realm_id != event.realm_id
        || commit.stream_ref
            != (CommitStreamRef::Realm {
                realm_id: event.realm_id.clone(),
            })
    {
        return Err(invalid("PCR device current Event and Commit differ"));
    }
    let account = event
        .actor_id
        .as_account_id()
        .ok_or_else(|| invalid("PCR device current actor is not an account"))?;
    require_pcr(conn, event, account, genesis_account).await?;
    let payload = serde_json::to_value(&event.payload).map_err(PersistenceError::database)?;
    match event.kind {
        EventKind::DeviceAuthorize => {
            let typed: DeviceAuthorizePayload =
                serde_json::from_value(payload.clone()).map_err(|error| {
                    invalid(format!("device authorize payload is invalid: {error}"))
                })?;
            let current = generation(conn, &event.realm_id).await?;
            if typed.authorization_binding_kind
                == DeviceAuthorizationBindingKind::RegistrationAnchor
            {
                if genesis_account.is_none() || commit.stream_position != 1 {
                    return Err(invalid(
                        "registration device authorization is not PCR genesis",
                    ));
                }
                write_generation(conn, commit, None, 1).await?;
            } else if current != Some(typed.authorized_generation_ref) {
                return Err(PersistenceError::Conflict(
                    "device_authorization_generation_stale".to_owned(),
                ));
            }
            let mut value = payload
                .as_object()
                .ok_or_else(|| invalid("device authorize payload is not an object"))?
                .clone();
            value.remove("device_id");
            value.insert(
                "device_authorize_event_id".to_owned(),
                serde_json::to_value(&event.event_id).map_err(PersistenceError::database)?,
            );
            let position = i64::try_from(commit.stream_position)
                .map_err(|_| invalid("device authorization position overflow"))?;
            sql_query(
                "INSERT INTO pcr_device_authorization_current_results \
                 (realm_id,device_id,current_commit_id,current_stream_position,value,updated_at) \
                 VALUES($1,$2,$3,$4,$5,$6) \
                 ON CONFLICT(realm_id,device_id) DO UPDATE SET \
                   current_commit_id=EXCLUDED.current_commit_id, \
                   current_stream_position=EXCLUDED.current_stream_position, \
                   value=EXCLUDED.value,updated_at=EXCLUDED.updated_at",
            )
            .bind::<Text, _>(event.realm_id.as_str())
            .bind::<Text, _>(typed.device_id.as_str())
            .bind::<Text, _>(commit.commit_id.as_str())
            .bind::<BigInt, _>(position)
            .bind::<Jsonb, _>(Value::Object(value))
            .bind::<Timestamptz, _>(commit.committed_at)
            .execute(&mut *conn)
            .await
            .map_err(PersistenceError::database)?;
        }
        EventKind::DeviceReanchor => {
            if genesis_account.is_some() {
                return Err(invalid("device reanchor cannot occur during PCR genesis"));
            }
            let typed: DeviceReanchorPayload = serde_json::from_value(payload)
                .map_err(|error| invalid(format!("device reanchor payload is invalid: {error}")))?;
            if typed.account_id != *account {
                return Err(invalid("device reanchor account differs from actor"));
            }
            write_generation(
                conn,
                commit,
                Some(typed.previous_device_generation),
                typed.new_device_generation,
            )
            .await?;
        }
        _ => unreachable!(),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use diesel::sql_types::Nullable;

    use super::*;
    use crate::{AsyncConnection, Binary, PgTransactionError, pg_conn};

    fn commit(event: &Event) -> RealmCommit {
        let now = chrono::DateTime::parse_from_rfc3339("2026-09-24T00:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        RealmCommit {
            commit_id: arkret_wire::RealmCommitId::from_digest([77; 32]),
            realm_id: event.realm_id.clone(),
            stream_ref: CommitStreamRef::Realm {
                realm_id: event.realm_id.clone(),
            },
            stream_position: 0,
            previous_commit_ref: None,
            event_ref: event.event_id.clone(),
            governance_generation: 0,
            authority_ref: arkret_wire::RealmCommitAuthorityRef::GenesisOrChangeEvent(
                event.event_id.clone(),
            ),
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

    #[tokio::test]
    async fn generation_cas_rejects_stale_and_rolls_back() {
        let database = crate::test_database::TestDatabase::lease().await;
        let pool = database.pool();
        let realm_id = arkret_wire::RealmId::from_event_id(&arkret_wire::EventId::from_digest(
            arkret_canonical::DigestSuite::Sha256,
            [31; 32],
        ));
        let event = arkret_wire::test_support::raw_event(
            EventKind::RealmCreate.as_str(),
            arkret_wire::ScopeRef::Realm {
                realm_id: realm_id.clone(),
            },
            arkret_wire::DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
            arkret_wire::DidCoreId::new("ak:did_core:web:station.example").unwrap(),
            json!({"genesis":true}),
        )
        .unwrap();
        let commit = commit(&event);
        let mut conn = pg_conn(&pool).await.unwrap();
        sql_query("INSERT INTO realm_authorities(realm_id,generation,service_id,authority_ref) VALUES($1,0,$2,$3)")
            .bind::<Text,_>(realm_id.as_str())
            .bind::<Text,_>("ak:did_core:web:station.example")
            .bind::<Jsonb,_>(serde_json::to_value(&commit.authority_ref).unwrap())
            .execute(&mut conn).await.unwrap();
        let token = crate::ids::event_token_part_expect_internal(event.event_id.as_str(), "event");
        sql_query("INSERT INTO canonical_events (id,digest_suite,digest,actor_id,realm_id,scope_ref,kind,canonical_bytes,envelope,state,received_at,committed_at) VALUES($1,1,$2,$3,$4,$5,$6,'\\x00'::bytea,$7,'committed',$8,$8)")
            .bind::<Binary,_>(token.to_vec())
            .bind::<Binary,_>(token[1..].to_vec())
            .bind::<Text,_>(event.actor_id.to_string())
            .bind::<Text,_>(realm_id.as_str())
            .bind::<Jsonb,_>(serde_json::to_value(&event.scope_ref).unwrap())
            .bind::<Text,_>(event.kind.as_str())
            .bind::<Jsonb,_>(serde_json::to_value(&event).unwrap())
            .bind::<Timestamptz,_>(commit.committed_at)
            .execute(&mut conn).await.unwrap();
        sql_query("INSERT INTO realm_commits (commit_id,realm_id,stream_key,stream_ref,stream_position,previous_commit_ref,event_pk,governance_generation,commit_json,committed_at) SELECT $1,$2,$3,$4,$5,$6,pk,0,$7,$8 FROM canonical_events WHERE id=$9")
            .bind::<Text,_>(commit.commit_id.as_str())
            .bind::<Text,_>(realm_id.as_str())
            .bind::<Text,_>(arkret_canonical::canonical_json_string(&commit.stream_ref).unwrap())
            .bind::<Jsonb,_>(serde_json::to_value(&commit.stream_ref).unwrap())
            .bind::<BigInt,_>(commit.stream_position as i64)
            .bind::<Nullable<Text>,_>(None::<&str>)
            .bind::<Jsonb,_>(serde_json::to_value(&commit).unwrap())
            .bind::<Timestamptz,_>(commit.committed_at)
            .bind::<Binary,_>(token.to_vec())
            .execute(&mut conn).await.unwrap();

        write_generation(&mut conn, &commit, None, 1).await.unwrap();
        assert!(matches!(
            write_generation(&mut conn, &commit, None, 1).await,
            Err(PersistenceError::Conflict(_))
        ));
        assert!(matches!(
            write_generation(&mut conn, &commit, Some(2), 3).await,
            Err(PersistenceError::Conflict(_))
        ));
        assert_eq!(generation(&mut conn, &realm_id).await.unwrap(), Some(1));
        let rollback = conn
            .transaction::<(), PgTransactionError, _>(async |conn| {
                write_generation(conn, &commit, Some(1), 2).await?;
                Err(PersistenceError::Conflict("abort generation transaction".to_owned()).into())
            })
            .await;
        assert!(rollback.is_err());
        assert_eq!(generation(&mut conn, &realm_id).await.unwrap(), Some(1));
        write_generation(&mut conn, &commit, Some(1), 2)
            .await
            .unwrap();
        assert_eq!(generation(&mut conn, &realm_id).await.unwrap(), Some(2));
        assert!(matches!(
            write_generation(&mut conn, &commit, Some(1), 2).await,
            Err(PersistenceError::Conflict(_))
        ));
    }
}
