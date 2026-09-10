//! Versioned current-result publication shared by accepted DataEvents and
//! sealed governance. Callers own the accepted transaction and revision cut.

pub(crate) mod read;

use arkret_models_collaboration::sync_frames::current_results::{
    CurrentResultEntry, CurrentTarget,
};
use diesel::sql_types::{BigInt, Jsonb, Text};
use diesel::{QueryableByName, sql_query};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use soland_storage::{PersistenceError, PersistenceResult};

#[derive(QueryableByName)]
struct RevisionRow {
    #[diesel(sql_type=BigInt)]
    revision: i64,
}

pub(crate) async fn next_revision(conn: &mut AsyncPgConnection) -> PersistenceResult<u64> {
    let row = sql_query("UPDATE account_summary_clock SET revision=revision+1 WHERE singleton AND revision<9007199254740991 RETURNING revision")
        .get_result::<RevisionRow>(&mut *conn).await.map_err(PersistenceError::database)?;
    Ok(row.revision as u64)
}

/// Entries are validated SDK results, not source operations. One caller's
/// accepted transaction uses one common revision for every changed selector.
/// An unchanged selector retains its prior revision and creates no new version.
pub(crate) async fn publish_entries(
    conn: &mut AsyncPgConnection,
    entries: &[CurrentResultEntry],
) -> PersistenceResult<()> {
    let Some(first) = entries.first() else {
        return Ok(());
    };
    let revision =
        sql_query("SELECT revision FROM account_summary_clock WHERE singleton FOR UPDATE")
            .get_result::<RevisionRow>(&mut *conn)
            .await
            .map_err(PersistenceError::database)?
            .revision;
    if entries
        .iter()
        .any(|entry| entry.revision() != first.revision())
        || revision as u64 != first.revision()
    {
        return Err(PersistenceError::Conflict(
            "current publication must use this transaction's common revision".into(),
        ));
    }
    let mut ordered = entries
        .iter()
        .map(|entry| {
            entry
                .selector()
                .canonical_key()
                .map(|key| (key, entry))
                .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))
        })
        .collect::<PersistenceResult<Vec<_>>>()?;
    ordered.sort_by(|left, right| left.0.as_bytes().cmp(right.0.as_bytes()));
    for (key, entry) in ordered {
        let realm = match &entry.selector().scope_ref {
            arkret_wire::ScopeRef::Realm { realm_id }
            | arkret_wire::ScopeRef::Circle { realm_id, .. } => realm_id,
            _ => {
                return Err(PersistenceError::SchemaViolation(
                    "current result requires effective scope".into(),
                ));
            }
        };
        let (kind, target_key) = match entry.target() {
            CurrentTarget::Realm => ("realm", String::new()),
            CurrentTarget::Strand { strand_id } => ("strand", strand_id.to_string()),
            CurrentTarget::Event { event_id } => ("event", event_id.to_string()),
            CurrentTarget::Member { actor_id } => (
                "member",
                actor_id
                    .canonical_key()
                    .map_err(|e| PersistenceError::SchemaViolation(e.to_string()))?,
            ),
        };
        let payload = serde_json::to_value(entry).map_err(PersistenceError::database)?;
        let changed = sql_query("WITH previous AS MATERIALIZED (SELECT * FROM current_result_heads WHERE realm_id=$1 AND selector_key=$2 FOR UPDATE), closed AS (UPDATE current_result_versions v SET valid_until=$3 FROM previous p WHERE v.realm_id=p.realm_id AND v.selector_key=p.selector_key AND v.revision=p.revision AND p.payload->'result' IS DISTINCT FROM $4->'result' AND p.revision<$3 AND p.payload->'target'=$4->'target'), inserted AS (INSERT INTO current_result_heads(realm_id,selector_key,revision,target_kind,target_key,payload) SELECT $1,$2,$3,$5,$6,$4 WHERE NOT EXISTS(SELECT 1 FROM previous) OR EXISTS(SELECT 1 FROM previous p WHERE p.revision<$3 AND p.payload->'target'=$4->'target' AND p.payload->'result' IS DISTINCT FROM $4->'result') ON CONFLICT(realm_id,selector_key) DO UPDATE SET revision=EXCLUDED.revision,payload=EXCLUDED.payload RETURNING *) INSERT INTO current_result_versions(realm_id,selector_key,revision,target_kind,target_key,payload) SELECT realm_id,selector_key,revision,target_kind,target_key,payload FROM inserted")
            .bind::<Text,_>(realm.as_str()).bind::<Text,_>(&key).bind::<BigInt,_>(entry.revision() as i64)
            .bind::<Jsonb,_>(&payload).bind::<Text,_>(kind).bind::<Text,_>(&target_key)
            .execute(&mut *conn).await.map_err(PersistenceError::database)?;
        if changed == 0 {
            #[derive(QueryableByName)]
            struct Existing {
                #[diesel(sql_type=Jsonb)]
                payload: serde_json::Value,
            }
            let existing = sql_query(
                "SELECT payload FROM current_result_heads WHERE realm_id=$1 AND selector_key=$2",
            )
            .bind::<Text, _>(realm.as_str())
            .bind::<Text, _>(&key)
            .get_result::<Existing>(&mut *conn)
            .await
            .map_err(PersistenceError::database)?;
            if existing.payload["target"] != payload["target"]
                || existing.payload["result"] != payload["result"]
            {
                return Err(PersistenceError::Conflict(
                    "current selector target changed or revision regressed".into(),
                ));
            }
        }
    }
    Ok(())
}
