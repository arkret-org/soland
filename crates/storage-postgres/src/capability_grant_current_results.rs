use std::str::FromStr;

use arkret_models_collaboration::governance::grant_constraint::{
    CapabilityGrant, CapabilityGrantStatus,
};
use arkret_wire::{
    CommitStreamRef, CommittedEventRef, CurrentRevision, EventId, GrantId, RealmCommitId, RealmId,
};

use super::{
    AsyncPgConnection, BigInt, Bool, CapabilityGrantCurrentResultRecord,
    CapabilityGrantCurrentResultStore, CapabilityGrantCurrentStatus, Jsonb, OptionalExtension,
    PersistenceError, PersistenceResult, PgPool, QueryableByName, RunQueryDsl, Text, Timestamptz,
    async_trait, pg_conn, sql_query,
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
    current_event_id: String,
    #[diesel(sql_type = Text)]
    current_commit_id: String,
    #[diesel(sql_type = Jsonb)]
    current_stream_ref: serde_json::Value,
    #[diesel(sql_type = BigInt)]
    current_stream_position: i64,
    #[diesel(sql_type = Jsonb)]
    value: serde_json::Value,
}

fn corrupt(detail: impl Into<String>) -> PersistenceError {
    PersistenceError::Database(detail.into())
}

fn schema_violation(detail: impl Into<String>) -> PersistenceError {
    PersistenceError::SchemaViolation(detail.into())
}

fn conflict(detail: impl Into<String>) -> PersistenceError {
    PersistenceError::Conflict(detail.into())
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
    let event_id = EventId::from_str(&row.current_event_id).map_err(|error| {
        corrupt(format!(
            "stored Capability Grant source Event id is invalid: {error}"
        ))
    })?;
    let stream_ref =
        serde_json::from_value::<CommitStreamRef>(row.current_stream_ref).map_err(|error| {
            corrupt(format!(
                "stored Capability Grant stream ref is invalid: {error}"
            ))
        })?;
    CapabilityGrantCurrentResultRecord::try_new(
        realm_id,
        grant_id,
        status,
        row.value,
        CurrentRevision {
            commit_id: commit_id.clone(),
            stream_position,
        },
        CommittedEventRef {
            event_id,
            commit_id,
            stream_ref,
            stream_position,
        },
    )
}

enum CapabilityGrantCurrentMutation {
    Create {
        grant_id: GrantId,
        value: serde_json::Value,
    },
    Close {
        grant_id: GrantId,
        expected_revision: CurrentRevision,
        status: CapabilityGrantCurrentStatus,
    },
}

fn mutation_for_event(
    event: &arkret_wire::Event,
) -> PersistenceResult<Option<CapabilityGrantCurrentMutation>> {
    let invalid = |what: &str, error: serde_json::Error| {
        schema_violation(format!(
            "{what} payload violates its typed SDK contract: {error}"
        ))
    };
    let payload_value = || serde_json::Value::Object(event.payload.clone().into_iter().collect());
    match event.kind {
        arkret_wire::EventKind::CapabilityGrant => {
            let payload = serde_json::from_value::<
                arkret_models_collaboration::events_payloads::CapabilityGrantPayload,
            >(payload_value())
            .map_err(|error| invalid("Capability Grant", error))?;
            if payload.grant.schema != arkret_wire::SchemaId::CAPABILITY_V1
                || payload.grant.issuer_id != event.actor_id
                || payload
                    .grant
                    .realm_id
                    .as_ref()
                    .is_some_and(|realm_id| realm_id != &event.realm_id)
            {
                return Err(schema_violation(
                    "Capability Grant authoring body does not match its Event envelope",
                ));
            }
            let grant_id = GrantId::from_event_id(&event.event_id);
            let grant = CapabilityGrant {
                id: grant_id.clone(),
                schema: payload.grant.schema,
                realm_id: Some(event.realm_id.clone()),
                issuer_id: payload.grant.issuer_id,
                subject: payload.grant.subject,
                actions: payload.grant.actions,
                resources: payload.grant.resources,
                constraints: payload.grant.constraints,
                issuer_authority_refs: payload.grant.issuer_authority_refs,
                issued_at: payload.grant.issued_at,
                status: CapabilityGrantStatus::Active,
                updated_by: None,
                updated_at: None,
                revoked_by: None,
                revoked_at: None,
            };
            let value = serde_json::to_value(grant).map_err(PersistenceError::database)?;
            Ok(Some(CapabilityGrantCurrentMutation::Create {
                grant_id,
                value,
            }))
        }
        arkret_wire::EventKind::CapabilityDerived => {
            let payload = serde_json::from_value::<
                arkret_models_collaboration::governance::realm_governance::CapabilityDerived,
            >(payload_value())
            .map_err(|error| invalid("Capability Derived", error))?;
            if payload.grant.id != payload.grant_id
                || payload.grant.realm_id.as_ref() != Some(&event.realm_id)
                || payload.grant.status != CapabilityGrantStatus::Active
                || payload.grant.updated_by.is_some()
                || payload.grant.updated_at.is_some()
                || payload.grant.revoked_by.is_some()
                || payload.grant.revoked_at.is_some()
            {
                return Err(schema_violation(
                    "Capability Derived must carry one active target-Realm grant",
                ));
            }
            let value = serde_json::to_value(&payload.grant).map_err(PersistenceError::database)?;
            Ok(Some(CapabilityGrantCurrentMutation::Create {
                grant_id: payload.grant_id,
                value,
            }))
        }
        arkret_wire::EventKind::CapabilityRevoke => {
            let payload = serde_json::from_value::<
                arkret_models_collaboration::events_payloads::CapabilityRevokePayload,
            >(payload_value())
            .map_err(|error| invalid("Capability Revoke", error))?;
            Ok(Some(CapabilityGrantCurrentMutation::Close {
                grant_id: payload.grant_id,
                expected_revision: payload.expected_revision,
                status: CapabilityGrantCurrentStatus::Revoked,
            }))
        }
        arkret_wire::EventKind::CapabilityRelinquish => {
            let payload = serde_json::from_value::<
                arkret_models_collaboration::events_payloads::CapabilityRelinquishPayload,
            >(payload_value())
            .map_err(|error| invalid("Capability Relinquish", error))?;
            Ok(Some(CapabilityGrantCurrentMutation::Close {
                grant_id: payload.grant_id,
                expected_revision: payload.expected_revision,
                status: CapabilityGrantCurrentStatus::Relinquished,
            }))
        }
        _ => Ok(None),
    }
}

fn revision_matches(
    current: &CapabilityGrantCurrentResultRecord,
    expected: &CurrentRevision,
) -> bool {
    current.revision == *expected
}

/// Materialize one of the four registered `capability_grant` writers inside
/// the same PostgreSQL transaction as its Event and RealmCommit.
pub(crate) async fn commit_capability_grant_current_result_in_connection(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    commit: &arkret_wire::RealmCommit,
) -> PersistenceResult<()> {
    let Some(mutation) = mutation_for_event(event)? else {
        return Ok(());
    };
    let grant_id = match &mutation {
        CapabilityGrantCurrentMutation::Create { grant_id, .. }
        | CapabilityGrantCurrentMutation::Close { grant_id, .. } => grant_id.clone(),
    };
    let lock_key = format!("capability-grant\u{0}{}\u{0}{}", event.realm_id, grant_id);
    #[derive(QueryableByName)]
    struct AdvisoryLockRow {
        #[diesel(sql_type = Bool)]
        acquired: bool,
    }
    let lock =
        sql_query("SELECT pg_advisory_xact_lock(hashtextextended($1,0)) IS NULL AS acquired")
            .bind::<Text, _>(&lock_key)
            .get_result::<AdvisoryLockRow>(&mut *conn)
            .await
            .map_err(PersistenceError::database)?;
    if !lock.acquired {
        return Err(PersistenceError::Internal(
            "Capability Grant transaction lock was not acquired".to_owned(),
        ));
    }

    let current = sql_query(
        "SELECT realm_id,grant_id,status,current_event_id,current_commit_id,current_stream_ref,\
         current_stream_position,value FROM capability_grant_current_results \
         WHERE realm_id=$1 AND grant_id=$2 FOR UPDATE",
    )
    .bind::<Text, _>(event.realm_id.as_str())
    .bind::<Text, _>(grant_id.as_str())
    .get_result::<CapabilityGrantCurrentResultReadRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?
    .map(decode_row)
    .transpose()?;

    let (status, value) = match (mutation, current.as_ref()) {
        (CapabilityGrantCurrentMutation::Create { value, .. }, None) => {
            (CapabilityGrantCurrentStatus::Active, value)
        }
        (CapabilityGrantCurrentMutation::Create { .. }, Some(_)) => {
            return Err(conflict(
                "failed_precondition: Capability Grant current result already exists",
            ));
        }
        (
            CapabilityGrantCurrentMutation::Close {
                grant_id,
                expected_revision,
                status,
            },
            Some(current),
        ) => {
            if current.status != CapabilityGrantCurrentStatus::Active
                || !revision_matches(current, &expected_revision)
            {
                return Err(conflict(
                    "cas_conflict: Capability Grant current revision does not match",
                ));
            }
            let typed = serde_json::from_value::<CapabilityGrant>(current.value.clone()).map_err(
                |error| {
                    corrupt(format!(
                        "stored Capability Grant current value is invalid: {error}"
                    ))
                },
            )?;
            if typed.id != grant_id
                || typed.realm_id.as_ref() != Some(&event.realm_id)
                || typed.status != CapabilityGrantStatus::Active
            {
                return Err(corrupt(
                    "stored Capability Grant current value disagrees with its authoritative row",
                ));
            }
            let mut value = current.value.clone();
            let object = value
                .as_object_mut()
                .ok_or_else(|| corrupt("stored Capability Grant current value is not an object"))?;
            object.insert(
                "status".to_owned(),
                serde_json::Value::String(status.as_str().to_owned()),
            );
            match status {
                CapabilityGrantCurrentStatus::Revoked => {
                    object.insert(
                        "revoked_by".to_owned(),
                        serde_json::to_value(&event.actor_id)
                            .map_err(PersistenceError::database)?,
                    );
                    object.insert(
                        "revoked_at".to_owned(),
                        serde_json::to_value(event.created_at)
                            .map_err(PersistenceError::database)?,
                    );
                }
                CapabilityGrantCurrentStatus::Relinquished => {
                    object.insert(
                        "updated_by".to_owned(),
                        serde_json::to_value(&event.actor_id)
                            .map_err(PersistenceError::database)?,
                    );
                    object.insert(
                        "updated_at".to_owned(),
                        serde_json::to_value(event.created_at)
                            .map_err(PersistenceError::database)?,
                    );
                }
                CapabilityGrantCurrentStatus::Active => unreachable!("close cannot remain active"),
            }
            (status, value)
        }
        (CapabilityGrantCurrentMutation::Close { .. }, None) => {
            return Err(conflict(
                "failed_precondition: Capability Grant current result does not exist",
            ));
        }
    };

    let stream_position = i64::try_from(commit.stream_position).map_err(|_| {
        PersistenceError::Internal(
            "Capability Grant stream position exceeds PostgreSQL BIGINT".to_owned(),
        )
    })?;
    let stream_ref =
        serde_json::to_value(&commit.stream_ref).map_err(PersistenceError::database)?;
    sql_query(
        "INSERT INTO capability_grant_current_results \
         (realm_id,grant_id,status,current_event_id,current_commit_id,current_stream_ref,\
          current_stream_position,value,updated_at) \
         VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) \
         ON CONFLICT(realm_id,grant_id) DO UPDATE SET \
           status=EXCLUDED.status,current_event_id=EXCLUDED.current_event_id, \
           current_commit_id=EXCLUDED.current_commit_id, \
           current_stream_ref=EXCLUDED.current_stream_ref, \
           current_stream_position=EXCLUDED.current_stream_position, \
           value=EXCLUDED.value,updated_at=EXCLUDED.updated_at",
    )
    .bind::<Text, _>(event.realm_id.as_str())
    .bind::<Text, _>(grant_id.as_str())
    .bind::<Text, _>(status.as_str())
    .bind::<Text, _>(event.event_id.as_str())
    .bind::<Text, _>(commit.commit_id.as_str())
    .bind::<Jsonb, _>(&stream_ref)
    .bind::<BigInt, _>(stream_position)
    .bind::<Jsonb, _>(&value)
    .bind::<Timestamptz, _>(commit.committed_at)
    .execute(&mut *conn)
    .await
    .map_err(PersistenceError::database)?;
    Ok(())
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
            "SELECT realm_id,grant_id,status,current_event_id,current_commit_id,current_stream_ref,current_stream_position,value \
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
            "SELECT realm_id,grant_id,status,current_event_id,current_commit_id,current_stream_ref,current_stream_position,value \
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
            current_event_id: EventId::from_digest(
                arkret_canonical::DigestSuite::Sha256,
                [0x44; 32],
            )
            .to_string(),
            current_commit_id: COMMIT_ID.to_owned(),
            current_stream_ref: serde_json::json!({"kind":"realm","realm_id":REALM_ID}),
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
