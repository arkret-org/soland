use arkret_models_collaboration::objects::relation::{
    Relation, RelationPrimaryConflictDomain, RelationPrimaryConflictDomainKind,
};
use arkret_wire::{CurrentRevision, RealmCommitId, RelationState};

use super::{
    BigInt, Jsonb, PersistenceError, PersistenceResult, PgPool, QueryableByName,
    RelationCurrentResultRecord, RelationCurrentResultStore, RunQueryDsl, Text, async_trait,
    pg_conn, sql_query,
};

pub struct PgRelationCurrentResultStore {
    pub pool: PgPool,
}

#[derive(QueryableByName)]
struct RelationCurrentResultReadRow {
    #[diesel(sql_type = Text)]
    realm_id: String,
    #[diesel(sql_type = Text)]
    domain_key: String,
    #[diesel(sql_type = Jsonb)]
    domain: serde_json::Value,
    #[diesel(sql_type = Text)]
    relation_id: String,
    #[diesel(sql_type = Text)]
    state: String,
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

fn domain_matches_relation(domain: &RelationPrimaryConflictDomain, relation: &Relation) -> bool {
    domain.relation_kind == relation.relation_kind
        && domain.from_ref == relation.from_ref
        && match domain.domain_kind {
            RelationPrimaryConflictDomainKind::Tuple => {
                domain.to_ref.as_ref() == Some(&relation.to_ref)
            }
            RelationPrimaryConflictDomainKind::From => domain.to_ref.is_none(),
        }
}

fn decode_row(row: RelationCurrentResultReadRow) -> PersistenceResult<RelationCurrentResultRecord> {
    let realm_id = row
        .realm_id
        .parse::<arkret_wire::RealmId>()
        .map_err(|error| corrupt(format!("stored Relation Realm id is invalid: {error}")))?;
    let domain = serde_json::from_value::<RelationPrimaryConflictDomain>(row.domain)
        .map_err(|error| corrupt(format!("stored Relation domain is invalid: {error}")))?;
    let canonical_domain = arkret_canonical::canonical_json_string(&domain).map_err(|error| {
        corrupt(format!(
            "stored Relation domain cannot canonicalize: {error}"
        ))
    })?;
    if canonical_domain != row.domain_key {
        return Err(corrupt(
            "stored Relation domain key does not match its domain",
        ));
    }
    let relation = serde_json::from_value::<Relation>(row.value)
        .map_err(|error| corrupt(format!("stored Relation current value is invalid: {error}")))?;
    if relation.schema != Relation::SCHEMA
        || relation.validate_endpoints().is_err()
        || relation.realm_id != realm_id
        || relation.id.as_ref().map(|id| id.as_str()) != Some(row.relation_id.as_str())
        || !domain_matches_relation(&domain, &relation)
    {
        return Err(corrupt(
            "stored Relation current value does not match its row identity",
        ));
    }
    let state_matches = matches!(
        (row.state.as_str(), relation.state.as_ref()),
        ("active", Some(RelationState::Active)) | ("tombstoned", Some(RelationState::Tombstoned))
    );
    if !state_matches {
        return Err(corrupt(
            "stored Relation lifecycle does not match its current row",
        ));
    }
    let stream_position = u64::try_from(row.current_stream_position)
        .map_err(|_| corrupt("stored Relation stream position is negative"))?;
    let commit_id = row
        .current_commit_id
        .parse::<RealmCommitId>()
        .map_err(|error| corrupt(format!("stored Relation Commit id is invalid: {error}")))?;
    Ok(RelationCurrentResultRecord {
        realm_id,
        domain_key: row.domain_key,
        primary_conflict_domain: domain,
        relation,
        revision: CurrentRevision {
            commit_id,
            stream_position,
        },
    })
}

#[async_trait]
impl RelationCurrentResultStore for PgRelationCurrentResultStore {
    async fn snapshot_all(&self) -> PersistenceResult<Vec<RelationCurrentResultRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        let rows = sql_query(
            "SELECT realm_id,domain_key,domain,relation_id,state,current_commit_id,\
             current_stream_position,value FROM relation_current_results \
             ORDER BY realm_id ASC,domain_key ASC",
        )
        .load::<RelationCurrentResultReadRow>(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
        rows.into_iter().map(decode_row).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reader_rejects_a_value_whose_lifecycle_disagrees_with_the_row() {
        let row = RelationCurrentResultReadRow {
            realm_id: "ak:realm:AUGIFvQctz4TjQTmvvO4Wdy-xdc5XP2ZnJ5Qpbh4s8Ru".to_owned(),
            domain_key: arkret_canonical::canonical_json_string(&serde_json::json!({
                "domain_kind":"tuple",
                "relation_kind":"references",
                "from_ref":"ak:strand:AUifoAUG8AEOHYXp999WnI7WlLt19ByDoqYUsFwbw4A4",
                "to_ref":"ak:strand:AQdknt9AByYY2gb16KB093xeB4J8b02mTEd4Mt8z2rO-"
            }))
            .unwrap(),
            domain: serde_json::json!({
                "domain_kind":"tuple",
                "relation_kind":"references",
                "from_ref":"ak:strand:AUifoAUG8AEOHYXp999WnI7WlLt19ByDoqYUsFwbw4A4",
                "to_ref":"ak:strand:AQdknt9AByYY2gb16KB093xeB4J8b02mTEd4Mt8z2rO-"
            }),
            relation_id: "ak:relation:AcFfzgdHkT6eFkto1gjLaKniVuMXx9sD0GKQwk8BXykz".to_owned(),
            state: "active".to_owned(),
            current_commit_id: "ak:realm_commit:ARNRmzDi2r78zveOLmoHOb6AephFMwVuGE1fwXmCoeo4"
                .to_owned(),
            current_stream_position: 4,
            value: serde_json::json!({
                "schema":"ak.schema.relation.v1",
                "id":"ak:relation:AcFfzgdHkT6eFkto1gjLaKniVuMXx9sD0GKQwk8BXykz",
                "realm_id":"ak:realm:AUGIFvQctz4TjQTmvvO4Wdy-xdc5XP2ZnJ5Qpbh4s8Ru",
                "effective_scope":{"kind":"realm","realm_id":"ak:realm:AUGIFvQctz4TjQTmvvO4Wdy-xdc5XP2ZnJ5Qpbh4s8Ru"},
                "relation_kind":"references",
                "from_ref":"ak:strand:AUifoAUG8AEOHYXp999WnI7WlLt19ByDoqYUsFwbw4A4",
                "to_ref":"ak:strand:AQdknt9AByYY2gb16KB093xeB4J8b02mTEd4Mt8z2rO-",
                "state":"tombstoned",
                "created_by":{
                    "kind":"account",
                    "account_id":{
                        "principal_id":"ak:did_core:web:relation-author.example",
                        "station_id":"ak:did_core:web:relation-station.example"
                    }
                },
                "created_at":"2026-09-21T00:00:00.000Z"
            }),
        };
        assert!(matches!(
            decode_row(row),
            Err(PersistenceError::Database(_))
        ));
    }
}
