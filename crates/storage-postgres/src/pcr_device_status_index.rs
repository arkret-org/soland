//! PCR conflict-index cut advancement. The fork evidence writer is deliberately
//! absent until the signed two-branch proof verifier is wired; an unverified
//! caller must not create a conflict record or assert an empty current set.

use arkret_wire::{CommitStreamRef, RealmCommit};
use diesel::sql_query;
use diesel::sql_types::{BigInt, Text, Timestamptz};
use diesel_async::RunQueryDsl;

use crate::{AsyncPgConnection, PersistenceError, PersistenceResult};

/// Called inside the same verified PCR authority transaction that installs
/// the accepted Commit and all of its typed current writes. A rollback removes
/// the marker with the Event/Commit. `conflict_revision` is unchanged by a
/// normal PCR Commit and equals the durable verified-fork record count.
pub(crate) async fn advance_pcr_conflict_index_cut_in_connection(
    conn: &mut AsyncPgConnection,
    commit: &RealmCommit,
) -> PersistenceResult<()> {
    if commit.stream_ref
        != (CommitStreamRef::Realm {
            realm_id: commit.realm_id.clone(),
        })
    {
        return Err(PersistenceError::SchemaViolation(
            "PCR conflict cut requires the Realm stream".to_owned(),
        ));
    }
    let position = i64::try_from(commit.stream_position).map_err(|_| {
        PersistenceError::SchemaViolation("PCR conflict cut position overflow".to_owned())
    })?;
    let affected = match &commit.previous_commit_ref {
        None if position == 0 => sql_query(
            "INSERT INTO pcr_device_conflict_index_cuts \
                 (realm_id,pcr_head_commit_id,conflict_revision,updated_at) \
                 SELECT $1,$2,0,$4 WHERE EXISTS( \
                   SELECT 1 FROM realm_commits c WHERE c.commit_id=$2 \
                     AND c.realm_id=$1 AND c.stream_position=$3) \
                 AND NOT EXISTS(SELECT 1 FROM pcr_verified_fork_records f WHERE f.realm_id=$1) \
                 ON CONFLICT(realm_id) DO NOTHING",
        )
        .bind::<Text, _>(commit.realm_id.as_str())
        .bind::<Text, _>(commit.commit_id.as_str())
        .bind::<BigInt, _>(position)
        .bind::<Timestamptz, _>(commit.committed_at)
        .execute(&mut *conn)
        .await
        .map_err(PersistenceError::database)?,
        Some(previous) if position > 0 => sql_query(
            "UPDATE pcr_device_conflict_index_cuts m \
                 SET pcr_head_commit_id=$2,updated_at=$5 \
                 WHERE m.realm_id=$1 AND m.pcr_head_commit_id=$4 \
                   AND m.conflict_revision=( \
                     SELECT count(*) FROM pcr_verified_fork_records f WHERE f.realm_id=$1) \
                   AND EXISTS(SELECT 1 FROM realm_commits c WHERE c.commit_id=$2 \
                     AND c.realm_id=$1 AND c.stream_position=$3)",
        )
        .bind::<Text, _>(commit.realm_id.as_str())
        .bind::<Text, _>(commit.commit_id.as_str())
        .bind::<BigInt, _>(position)
        .bind::<Text, _>(previous.as_str())
        .bind::<Timestamptz, _>(commit.committed_at)
        .execute(&mut *conn)
        .await
        .map_err(PersistenceError::database)?,
        _ => {
            return Err(PersistenceError::SchemaViolation(
                "PCR conflict cut predecessor/position is invalid".to_owned(),
            ));
        }
    };
    if affected != 1 {
        return Err(PersistenceError::Conflict(
            "pcr_conflict_index_cut_cas_mismatch".to_owned(),
        ));
    }
    Ok(())
}
