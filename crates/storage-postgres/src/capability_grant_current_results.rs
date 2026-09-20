use std::str::FromStr;

use arkret_wire::{CurrentRevision, GrantId, RealmCommitId, RealmId};

use super::{
    BigInt, CapabilityGrantCurrentResultRecord, CapabilityGrantCurrentResultStore,
    CapabilityGrantCurrentStatus, Jsonb, OptionalExtension, PersistenceError, PersistenceResult,
    PgPool, QueryableByName, RunQueryDsl, Text, async_trait, pg_conn, sql_query,
};

pub struct PgCapabilityGrantCurrentResultStore {
    pub pool: PgPool,
}

#[derive(QueryableByName)]
struct CapabilityGrantCurrentResultReadRow {
    #[diesel(sql_type = Text)]
    realm_id: String,
    #[diesel(sql_type = Text)]
    grant_id: String,
    #[diesel(sql_type = Text)]
    status: String,
    #[diesel(sql_type = Text)]
    current_commit_id: String,
    #[diesel(sql_type = BigInt)]
    current_stream_position: i64,
    #[diesel(sql_type = Jsonb)]
    value: serde_json::Value,
}

fn corrupt(detail: impl Into<String>) -> PersistenceError {
    PersistenceError::Database(detail.into())
}

fn decode_row(
    row: CapabilityGrantCurrentResultReadRow,
) -> PersistenceResult<CapabilityGrantCurrentResultRecord> {
    let realm_id = RealmId::from_str(&row.realm_id).map_err(|error| {
        corrupt(format!(
            "stored Capability Grant Realm id is invalid: {error}"
        ))
    })?;
    let grant_id = GrantId::from_str(&row.grant_id)
        .map_err(|error| corrupt(format!("stored Capability Grant id is invalid: {error}")))?;
    let status = CapabilityGrantCurrentStatus::from_str(&row.status)?;
    let stream_position = u64::try_from(row.current_stream_position)
        .map_err(|_| corrupt("stored Capability Grant stream position is negative"))?;
    let commit_id = RealmCommitId::from_str(&row.current_commit_id).map_err(|error| {
        corrupt(format!(
            "stored Capability Grant Commit id is invalid: {error}"
        ))
    })?;
    CapabilityGrantCurrentResultRecord::try_new(
        realm_id,
        grant_id,
        status,
        row.value,
        CurrentRevision {
            commit_id,
            stream_position,
        },
    )
}

#[async_trait]
impl CapabilityGrantCurrentResultStore for PgCapabilityGrantCurrentResultStore {
    async fn get(
        &self,
        realm_id: &RealmId,
        grant_id: &GrantId,
    ) -> PersistenceResult<Option<CapabilityGrantCurrentResultRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "SELECT realm_id,grant_id,status,current_commit_id,current_stream_position,value \
             FROM capability_grant_current_results WHERE realm_id=$1 AND grant_id=$2",
        )
        .bind::<Text, _>(realm_id.as_str())
        .bind::<Text, _>(grant_id.as_str())
        .get_result::<CapabilityGrantCurrentResultReadRow>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?
        .map(decode_row)
        .transpose()
    }

    async fn snapshot_for_realm(
        &self,
        realm_id: &RealmId,
    ) -> PersistenceResult<Vec<CapabilityGrantCurrentResultRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "SELECT realm_id,grant_id,status,current_commit_id,current_stream_position,value \
             FROM capability_grant_current_results WHERE realm_id=$1 ORDER BY grant_id ASC",
        )
        .bind::<Text, _>(realm_id.as_str())
        .load::<CapabilityGrantCurrentResultReadRow>(&mut *conn)
        .await
        .map_err(PersistenceError::database)?
        .into_iter()
        .map(decode_row)
        .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const REALM_ID: &str = "ak:realm:AUGIFvQctz4TjQTmvvO4Wdy-xdc5XP2ZnJ5Qpbh4s8Ru";
    const GRANT_ID: &str = "ak:grant:AcFfzgdHkT6eFkto1gjLaKniVuMXx9sD0GKQwk8BXykz";
    const COMMIT_ID: &str = "ak:realm_commit:ARNRmzDi2r78zveOLmoHOb6AephFMwVuGE1fwXmCoeo4";

    fn row(status: &str) -> CapabilityGrantCurrentResultReadRow {
        CapabilityGrantCurrentResultReadRow {
            realm_id: REALM_ID.to_owned(),
            grant_id: GRANT_ID.to_owned(),
            status: status.to_owned(),
            current_commit_id: COMMIT_ID.to_owned(),
            current_stream_position: 7,
            value: serde_json::json!({
                "id": GRANT_ID,
                "schema": "ak.schema.capability.v1",
                "realm_id": REALM_ID,
                "status": status
            }),
        }
    }

    #[test]
    fn reader_returns_value_and_exact_commit_revision_from_one_row() {
        let record = decode_row(row("active")).unwrap();
        assert_eq!(record.status, CapabilityGrantCurrentStatus::Active);
        assert_eq!(record.value["id"], GRANT_ID);
        assert_eq!(record.revision.commit_id.as_str(), COMMIT_ID);
        assert_eq!(record.revision.stream_position, 7);
    }

    #[test]
    fn reader_rejects_lifecycle_or_identity_drift() {
        let mut lifecycle = row("active");
        lifecycle.value["status"] = serde_json::json!("revoked");
        assert!(matches!(
            decode_row(lifecycle),
            Err(PersistenceError::Database(_))
        ));

        let mut identity = row("active");
        identity.value["realm_id"] =
            serde_json::json!("ak:realm:ASm71QhtF54BxHBvRFcIhmLfPFYTrXhTcLnVAEMmqZ5t");
        assert!(matches!(
            decode_row(identity),
            Err(PersistenceError::Database(_))
        ));
    }

    #[test]
    fn reader_rejects_non_commit_revision_material() {
        let mut invalid_commit = row("active");
        invalid_commit.current_commit_id =
            "ak:event:ARNRmzDi2r78zveOLmoHOb6AephFMwVuGE1fwXmCoeo4".to_owned();
        assert!(matches!(
            decode_row(invalid_commit),
            Err(PersistenceError::Database(_))
        ));

        let mut negative_position = row("active");
        negative_position.current_stream_position = -1;
        assert!(matches!(
            decode_row(negative_position),
            Err(PersistenceError::Database(_))
        ));
    }
}
