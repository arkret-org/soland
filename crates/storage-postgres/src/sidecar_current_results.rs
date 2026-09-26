//! Same-cut Sidecar genesis reservation and durable current. The public
//! ensure route remains closed until create and attach can commit as one unit.

use arkret_wire::{CommitStreamRef, Event, EventKind, RealmCommit, ScopeRef, SidecarId};
use diesel::sql_types::{BigInt, Jsonb, Text, Timestamptz};
use diesel::{OptionalExtension as _, sql_query};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use serde_json::{Value, json};
use soland_storage::{ConflictCode, PersistenceError, PersistenceResult};

#[derive(diesel::QueryableByName)]
struct ExistingCreate {
    #[diesel(sql_type = Text)]
    create_event_id: String,
}

fn invalid(detail: &str) -> PersistenceError {
    PersistenceError::SchemaViolation(detail.to_owned())
}

fn denied(detail: &str) -> PersistenceError {
    PersistenceError::Conflict(format!("{}: {detail}", ConflictCode::CapabilityDenied))
}

pub(crate) async fn admit_in_connection(
    conn: &mut AsyncPgConnection,
    event: &Event,
    commit: &RealmCommit,
) -> PersistenceResult<()> {
    if event.kind != EventKind::SidecarCreate {
        return Ok(());
    }
    if event.scope_ref
        != (ScopeRef::Realm {
            realm_id: event.realm_id.clone(),
        })
        || commit.stream_ref
            != (CommitStreamRef::Realm {
                realm_id: event.realm_id.clone(),
            })
        || !event.payload.is_empty()
        || event.executed_by.is_some()
        || event.applet_id.is_some()
    {
        return Err(invalid(
            "Sidecar genesis needs its empty Realm-stream account Event",
        ));
    }
    let Some(controller) = event.actor_id.as_account_id() else {
        return Err(denied("sidecar_create_denied"));
    };
    crate::realm_authorization_cut::lock_realm_authorization_cut(conn, &event.realm_id).await?;
    if crate::member_state_admission::locked_membership(conn, &event.realm_id, &event.actor_id)
        .await?
        != "join"
    {
        return Err(denied("sidecar_create_denied"));
    }
    let existing = sql_query(
        "SELECT create_event_id FROM sidecar_current_results \
         WHERE realm_id=$1 AND controller_account_id=$2 FOR SHARE",
    )
    .bind::<Text, _>(event.realm_id.as_str())
    .bind::<Jsonb, _>(serde_json::to_value(controller).map_err(PersistenceError::database)?)
    .get_result::<ExistingCreate>(conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?;
    if existing.is_some_and(|row| row.create_event_id != event.event_id.as_str()) {
        return Err(PersistenceError::Conflict(format!(
            "{}: Sidecar singleton already reserved",
            ConflictCode::FailedPrecondition
        )));
    }
    Ok(())
}

pub(crate) async fn commit_in_connection(
    conn: &mut AsyncPgConnection,
    event: &Event,
    commit: &RealmCommit,
) -> PersistenceResult<()> {
    if event.kind != EventKind::SidecarCreate {
        return Ok(());
    }
    let controller = event
        .actor_id
        .as_account_id()
        .ok_or_else(|| denied("sidecar_create_denied"))?;
    let id = SidecarId::from_event_id(&event.event_id);
    let position = i64::try_from(commit.stream_position)
        .map_err(|_| invalid("Sidecar stream position exceeds storage"))?;
    let value: Value = json!({
        "id": id,
        "schema": "ak.schema.agent_sidecar.v1",
        "realm_id": event.realm_id,
        "controller_account_id": controller,
        "state": "active",
        "created_at": arkret_canonical::format_timestamp_canonical(event.created_at),
        "updated_at": arkret_canonical::format_timestamp_canonical(event.created_at),
    });
    sql_query(
        "INSERT INTO sidecar_current_results \
         (realm_id,sidecar_id,controller_account_id,create_event_id,current_commit_id,current_stream_position,source_stream_ref,value,updated_at) \
         VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)",
    )
    .bind::<Text, _>(event.realm_id.as_str())
    .bind::<Text, _>(id.as_str())
    .bind::<Jsonb, _>(serde_json::to_value(controller).map_err(PersistenceError::database)?)
    .bind::<Text, _>(event.event_id.as_str())
    .bind::<Text, _>(commit.commit_id.as_str())
    .bind::<BigInt, _>(position)
    .bind::<Jsonb, _>(serde_json::to_value(&commit.stream_ref).map_err(PersistenceError::database)?)
    .bind::<Jsonb, _>(value)
    .bind::<Timestamptz, _>(commit.committed_at)
    .execute(conn)
    .await
    .map_err(PersistenceError::database)?;
    Ok(())
}
