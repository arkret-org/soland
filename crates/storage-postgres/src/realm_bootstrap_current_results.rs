//! Durable singleton current results established by an ordinary Realm bootstrap.

use diesel::sql_types::{BigInt, Jsonb, Text, Timestamptz};
use diesel_async::{AsyncPgConnection, RunQueryDsl};

use crate::{PersistenceError, PersistenceResult};

fn missing(field: &str) -> PersistenceError {
    PersistenceError::SchemaViolation(format!(
        "ordinary Realm bootstrap result is missing {field}"
    ))
}

/// Materialize the singleton families declared by the registered ordinary
/// bootstrap Event kinds. The authority root, policy bundle and creator
/// member state have dedicated durable tables and are written by their own
/// materializers in the same transaction.
pub(crate) async fn commit_ordinary_bootstrap_singleton_current_result_in_connection(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    commit: &arkret_wire::RealmCommit,
) -> PersistenceResult<()> {
    let payload = serde_json::to_value(&event.payload).map_err(PersistenceError::database)?;
    let (family, value) = match event.kind {
        arkret_wire::EventKind::RealmCreate => (
            "realm_genesis",
            payload
                .get("object")
                .filter(|value| value.is_object())
                .cloned()
                .ok_or_else(|| missing("payload.object"))?,
        ),
        arkret_wire::EventKind::RealmProfile => ("realm_profile", payload),
        arkret_wire::EventKind::RealmJoinRule => (
            "realm_join_rule",
            payload
                .get("value")
                .filter(|value| value.is_string())
                .cloned()
                .ok_or_else(|| missing("payload.value"))?,
        ),
        arkret_wire::EventKind::RealmHistoryAccess => {
            if payload.get("from") != Some(&serde_json::Value::Null) {
                return Err(PersistenceError::Conflict(
                    "ordinary Realm bootstrap history must transition from null".to_owned(),
                ));
            }
            (
                "realm_history_access",
                payload
                    .get("to")
                    .filter(|value| value.is_string())
                    .cloned()
                    .ok_or_else(|| missing("payload.to"))?,
            )
        }
        arkret_wire::EventKind::RealmDiscovery => (
            "realm_discovery",
            payload
                .get("value")
                .filter(|value| value.is_string())
                .cloned()
                .ok_or_else(|| missing("payload.value"))?,
        ),
        arkret_wire::EventKind::RealmAlias => ("realm_alias", payload),
        arkret_wire::EventKind::RealmPlaintextVisibleServices => {
            ("realm_plaintext_visible_services", payload)
        }
        _ => return Ok(()),
    };
    let position = i64::try_from(commit.stream_position).map_err(|_| {
        PersistenceError::SchemaViolation(
            "ordinary Realm bootstrap stream position exceeds PostgreSQL BIGINT".to_owned(),
        )
    })?;
    let inserted = diesel::sql_query(
        "INSERT INTO realm_bootstrap_current_results \
         (realm_id,result_family,current_commit_id,current_stream_position,value,updated_at) \
         VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING",
    )
    .bind::<Text, _>(event.realm_id.as_str())
    .bind::<Text, _>(family)
    .bind::<Text, _>(commit.commit_id.as_str())
    .bind::<BigInt, _>(position)
    .bind::<Jsonb, _>(&value)
    .bind::<Timestamptz, _>(commit.committed_at)
    .execute(conn)
    .await
    .map_err(PersistenceError::database)?;
    if inserted != 1 {
        return Err(PersistenceError::Conflict(format!(
            "ordinary Realm bootstrap current result {family} already exists"
        )));
    }
    Ok(())
}
