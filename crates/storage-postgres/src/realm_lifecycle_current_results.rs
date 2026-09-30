//! Registered Realm lifecycle results at the accepting Commit.

use diesel::sql_types::{BigInt, Bool, Jsonb, Text, Timestamptz};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use soland_storage::{PersistenceError, PersistenceResult};

#[derive(diesel::QueryableByName)]
struct ReplicaLifecycle {
    #[diesel(sql_type = Bool)]
    terminal: bool,
    #[diesel(sql_type = Bool)]
    archived: bool,
    #[diesel(sql_type = Bool)]
    frozen: bool,
}

/// A fresh successor may project only while its anchored scope is live.
/// Historical rows at or below the installed anchor do not call this gate.
pub(crate) async fn require_replica_live_in_connection(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
) -> PersistenceResult<()> {
    let gates = diesel::sql_query(
        "SELECT EXISTS(SELECT 1 FROM realm_bootstrap_current_results \
         WHERE realm_id=$1 AND result_family='realm_tombstone') AS terminal, \
         EXISTS(SELECT 1 FROM realm_bootstrap_current_results \
         WHERE realm_id=$1 AND result_family='realm_archive' AND value->>'archived'='true') AS archived, \
         EXISTS(SELECT 1 FROM realm_bootstrap_current_results \
         WHERE realm_id=$1 AND result_family='realm_freeze' AND value->>'frozen'='true') AS frozen",
    )
    .bind::<Text, _>(event.realm_id.as_str())
    .get_result::<ReplicaLifecycle>(conn)
    .await
    .map_err(PersistenceError::database)?;
    if event.kind == arkret_wire::EventKind::RealmDestroy
        || (gates.terminal && !arkret_wire::events::kinds::is_audit_kind(&event.kind))
    {
        return Err(PersistenceError::Conflict(
            "failed_precondition: replica cannot create live effects in a terminal Realm"
                .to_owned(),
        ));
    }
    let payload = serde_json::Value::Object(event.payload.clone().into_iter().collect());
    if (gates.archived || gates.frozen)
        && !arkret_wire::events::kinds::realm_write_gate_exempt(&event.kind, &payload)
    {
        return Err(PersistenceError::Conflict(
            "realm_frozen: replica cannot create live effects in an archived or frozen Realm"
                .to_owned(),
        ));
    }
    Ok(())
}

pub(crate) async fn commit_in_connection(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    commit: &arkret_wire::RealmCommit,
) -> PersistenceResult<()> {
    use arkret_wire::EventKind;
    let (family, value) = match event.kind {
        EventKind::RealmTombstone => (
            "realm_tombstone",
            serde_json::to_value(&event.payload).map_err(PersistenceError::database)?,
        ),
        EventKind::RealmArchive => ("realm_archive", serde_json::json!({"archived": true})),
        EventKind::RealmRestore => ("realm_archive", serde_json::json!({"archived": false})),
        EventKind::RealmFreeze => ("realm_freeze", serde_json::json!({"frozen": true})),
        EventKind::RealmUnfreeze => ("realm_freeze", serde_json::json!({"frozen": false})),
        _ => return Ok(()),
    };
    let position = i64::try_from(commit.stream_position)
        .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
    let changed = diesel::sql_query(
        "INSERT INTO realm_bootstrap_current_results \
         (realm_id,result_family,current_commit_id,current_stream_position,value,updated_at) \
         VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(realm_id,result_family) DO UPDATE SET \
         current_commit_id=EXCLUDED.current_commit_id, \
         current_stream_position=EXCLUDED.current_stream_position, \
         value=EXCLUDED.value,updated_at=EXCLUDED.updated_at \
         WHERE realm_bootstrap_current_results.current_stream_position < EXCLUDED.current_stream_position \
           AND EXCLUDED.result_family <> 'realm_tombstone'",
    )
    .bind::<Text, _>(event.realm_id.as_str())
    .bind::<Text, _>(family)
    .bind::<Text, _>(commit.commit_id.as_str())
    .bind::<BigInt, _>(position)
    .bind::<Jsonb, _>(&value)
    .bind::<Timestamptz, _>(commit.committed_at)
    .execute(conn).await.map_err(PersistenceError::database)?;
    if changed != 1 {
        return Err(PersistenceError::Conflict(
            "failed_precondition: lifecycle current cannot advance".to_owned(),
        ));
    }
    Ok(())
}
