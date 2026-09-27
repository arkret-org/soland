//! Registered typed-pair Strand position current storage. The value and
//! selector types come from the SDK, including the whole JSON-null value.

use arkret_models_collaboration::objects::strand::StrandPositionCurrent;
use arkret_wire::{CurrentRevision, RealmId, SpaceId, StrandId};
use diesel::sql_types::{BigInt, Jsonb, Text, Timestamptz};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use soland_storage::{PersistenceError, PersistenceResult};

/// Install the value of a verified snapshot or project an accepted Commit.
/// Admission checks belong to the authority writer, never this replica sink.
pub(crate) async fn install_in_connection(
    conn: &mut AsyncPgConnection,
    realm_id: &RealmId,
    board_space_id: &SpaceId,
    strand_id: &StrandId,
    revision: &CurrentRevision,
    current: &Option<StrandPositionCurrent>,
    at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<()> {
    let position = i64::try_from(revision.stream_position).map_err(|_| {
        PersistenceError::SchemaViolation("position revision exceeds BIGINT".to_owned())
    })?;
    let value = serde_json::to_value(current).map_err(PersistenceError::database)?;
    let changed = diesel::sql_query(
        "INSERT INTO strand_position_current_results \
         (realm_id,board_space_id,strand_id,current_commit_id,current_stream_position,value,updated_at) \
         VALUES($1,$2,$3,$4,$5,$6,$7) \
         ON CONFLICT(board_space_id,strand_id) DO UPDATE SET \
         current_commit_id=EXCLUDED.current_commit_id,current_stream_position=EXCLUDED.current_stream_position, \
         value=EXCLUDED.value,updated_at=EXCLUDED.updated_at \
         WHERE strand_position_current_results.realm_id=EXCLUDED.realm_id \
           AND strand_position_current_results.current_stream_position<=EXCLUDED.current_stream_position",
    )
    .bind::<Text,_>(realm_id.as_str())
    .bind::<Text,_>(board_space_id.as_str())
    .bind::<Text,_>(strand_id.as_str())
    .bind::<Text,_>(revision.commit_id.as_str())
    .bind::<BigInt,_>(position)
    .bind::<Jsonb,_>(value)
    .bind::<Timestamptz,_>(at)
    .execute(conn).await.map_err(PersistenceError::database)?;
    if changed != 1 {
        return Err(PersistenceError::Conflict(
            "failed_precondition: position identity belongs to another Realm or a later revision"
                .to_owned(),
        ));
    }
    Ok(())
}
