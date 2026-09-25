//! Registered event-derived Strand current result at the RealmCommit cut.

use diesel::sql_types::{BigInt, Jsonb, Text, Timestamptz};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use soland_storage::{PersistenceError, PersistenceResult};

/// The registered `strand` current value an accepted `ak.strand.create`
/// derives: the authored initial object with its Event-derived id and the
/// `active` state. Every Station that projects the Event derives it here.
pub(crate) fn strand_create_current_value(
    event: &arkret_wire::Event,
) -> PersistenceResult<(arkret_wire::StrandId, serde_json::Value)> {
    arkret_schema::validate_event_for_submit(event)
        .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
    let payload: arkret_models_collaboration::events_payloads::StrandCreatePayload =
        serde_json::from_value(
            serde_json::to_value(&event.payload).map_err(PersistenceError::database)?,
        )
        .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
    let object = payload.object;
    let authored = serde_json::to_value(&object).map_err(PersistenceError::database)?;
    if authored.get("state").is_some_and(|state| state != "active") {
        return Err(PersistenceError::SchemaViolation(
            "Strand create must begin active".to_owned(),
        ));
    }
    if object.id.is_some()
        || object.realm_id != event.realm_id
        || object.created_by != event.actor_id
        || object.created_at != event.created_at
        || object.stage.is_some()
        || object.stage_changed_at.is_some()
        || object.updated_by.is_some()
        || object.updated_at.is_some()
        || object.state_changed_at.is_some()
    {
        return Err(PersistenceError::SchemaViolation(
            "Strand create contains a forged or non-initial derived member".to_owned(),
        ));
    }
    let strand_id = arkret_wire::StrandId::from_event_id(&event.event_id);
    let mut value = authored;
    let value_object = value.as_object_mut().ok_or_else(|| {
        PersistenceError::SchemaViolation("Strand create object is not a JSON object".to_owned())
    })?;
    value_object.insert(
        "id".to_owned(),
        serde_json::to_value(&strand_id).map_err(PersistenceError::database)?,
    );
    value_object.insert("state".to_owned(), serde_json::json!("active"));
    Ok((strand_id, value))
}

pub(crate) async fn commit_strand_create_current_result_in_connection(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    commit: &arkret_wire::RealmCommit,
) -> PersistenceResult<()> {
    if event.kind != arkret_wire::EventKind::StrandCreate {
        return Ok(());
    }
    let (strand_id, value) = strand_create_current_value(event)?;
    let stream_position = i64::try_from(commit.stream_position).map_err(|_| {
        PersistenceError::SchemaViolation("Strand stream position exceeds BIGINT".to_owned())
    })?;
    let inserted = diesel::sql_query(
        "INSERT INTO strand_current_results \
         (realm_id,strand_id,current_commit_id,current_stream_position,value,updated_at) \
         VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING",
    )
    .bind::<Text, _>(event.realm_id.as_str())
    .bind::<Text, _>(strand_id.as_str())
    .bind::<Text, _>(commit.commit_id.as_str())
    .bind::<BigInt, _>(stream_position)
    .bind::<Jsonb, _>(&value)
    .bind::<Timestamptz, _>(commit.committed_at)
    .execute(conn)
    .await
    .map_err(PersistenceError::database)?;
    if inserted != 1 {
        return Err(PersistenceError::Conflict(
            "Strand current result already exists".to_owned(),
        ));
    }
    Ok(())
}
