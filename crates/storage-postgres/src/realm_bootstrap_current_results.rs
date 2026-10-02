//! Durable singleton current results established by an ordinary Realm bootstrap.

use arkret_event_draft::EventPayloadExt;
use arkret_models_collaboration::events_payloads::realm::RealmPurpose;
use diesel::sql_types::{BigInt, Jsonb, Text, Timestamptz};
use diesel_async::{AsyncPgConnection, RunQueryDsl};

use crate::{PersistenceError, PersistenceResult};

#[cfg(test)]
#[path = "../tests/support/ordinary_realm.rs"]
#[allow(dead_code)]
mod ordinary_realm;

fn typed_payload<T>(
    event: &arkret_wire::Event,
    decode: fn(&arkret_wire::Event) -> arkret_wire::Result<T>,
) -> PersistenceResult<T> {
    decode(event).map_err(|error| {
        PersistenceError::SchemaViolation(format!(
            "ordinary Realm bootstrap payload is invalid: {error}"
        ))
    })
}

fn result_value<T: serde::Serialize>(value: &T) -> PersistenceResult<serde_json::Value> {
    serde_json::to_value(value).map_err(PersistenceError::database)
}

/// Materialize the singleton families declared by the registered ordinary
/// bootstrap Event kinds. The authority root, policy bundle and creator
/// member state have dedicated durable tables and are written by their own
/// materializers in the same transaction.
///
/// `realm-and-space.md` §2.5 create projection rows 5 and 7: a Direct
/// Conversation or control-Realm genesis also runs `realm_history_access`
/// `null -> since_join` in the same write, since those profiles have no
/// history-access bootstrap facet.
pub(crate) async fn commit_ordinary_bootstrap_singleton_current_result_in_connection(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    commit: &arkret_wire::RealmCommit,
) -> PersistenceResult<()> {
    let rows = match event.kind {
        arkret_wire::EventKind::RealmCreate => {
            let genesis = typed_payload(event, EventPayloadExt::as_realm_create)?.object;
            let mut rows = vec![("realm_genesis", result_value(&genesis)?)];
            if matches!(
                genesis.purpose,
                RealmPurpose::DirectConversation
                    | RealmPurpose::PrincipalControl
                    | RealmPurpose::AgentControl
            ) {
                rows.push((
                    "realm_history_access",
                    result_value(&arkret_wire::HistoryAccess::SinceJoin)?,
                ));
            }
            rows
        }
        arkret_wire::EventKind::RealmProfile => vec![(
            "realm_profile",
            result_value(&typed_payload(event, EventPayloadExt::as_realm_profile)?)?,
        )],
        arkret_wire::EventKind::RealmJoinRule => vec![(
            "realm_join_rule",
            result_value(&typed_payload(event, EventPayloadExt::as_realm_join_rule)?.value)?,
        )],
        arkret_wire::EventKind::RealmHistoryAccess => {
            let payload = typed_payload(event, EventPayloadExt::as_realm_history_access)?;
            if payload.from.is_some() {
                return Err(PersistenceError::Conflict(
                    "ordinary Realm bootstrap history must transition from null".to_owned(),
                ));
            }
            vec![("realm_history_access", result_value(&payload.to)?)]
        }
        arkret_wire::EventKind::RealmDiscovery => vec![(
            "realm_discovery",
            result_value(&typed_payload(event, EventPayloadExt::as_realm_discovery)?.value)?,
        )],
        arkret_wire::EventKind::RealmAlias => vec![(
            "realm_alias",
            result_value(&typed_payload(event, EventPayloadExt::as_realm_alias)?)?,
        )],
        arkret_wire::EventKind::RealmPlaintextVisibleServices => vec![(
            "realm_plaintext_visible_services",
            result_value(&typed_payload(
                event,
                EventPayloadExt::as_realm_plaintext_visible_services,
            )?)?,
        )],
        _ => return Ok(()),
    };
    for (family, value) in rows {
        insert_singleton(conn, event, commit, family, &value).await?;
    }
    Ok(())
}

/// Advance the complete profile value with its covering RealmCommit. Omitted
/// optional fields disappear; no previous value is merged into the new value.
pub(crate) async fn commit_realm_profile_authority_current_result_in_connection(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    commit: &arkret_wire::RealmCommit,
) -> PersistenceResult<()> {
    if event.kind != arkret_wire::EventKind::RealmProfile {
        return Ok(());
    }
    crate::realm_authorization_cut::authorize_capability_gated_event_in_connection(
        conn,
        event,
        commit.committed_at,
    )
    .await?;
    commit_realm_profile_current_result_in_connection(conn, event, commit).await
}

/// Apply an already verified profile Commit to the typed current value.
pub(crate) async fn commit_realm_profile_current_result_in_connection(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    commit: &arkret_wire::RealmCommit,
) -> PersistenceResult<()> {
    if event.kind != arkret_wire::EventKind::RealmProfile {
        return Ok(());
    }
    let profile = typed_payload(event, EventPayloadExt::as_realm_profile)?;
    let value = profile.to_value().map_err(|error| {
        PersistenceError::SchemaViolation(format!("invalid Realm profile: {error}"))
    })?;
    advance_singleton(conn, event, commit, "realm_profile", &value).await
}

/// Read-receipt disclosure is a separate Realm current family; it does not
/// alter the policy bundle or the MLS key-access revision.
pub(crate) async fn commit_read_receipt_policy_authority_current_result_in_connection(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    commit: &arkret_wire::RealmCommit,
) -> PersistenceResult<()> {
    if event.kind != arkret_wire::EventKind::RealmReadReceiptPolicy {
        return Ok(());
    }
    crate::realm_authorization_cut::authorize_capability_gated_event_in_connection(
        conn,
        event,
        commit.committed_at,
    )
    .await?;
    commit_read_receipt_policy_current_result_in_connection(conn, event, commit).await
}

pub(crate) async fn commit_read_receipt_policy_current_result_in_connection(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    commit: &arkret_wire::RealmCommit,
) -> PersistenceResult<()> {
    if event.kind != arkret_wire::EventKind::RealmReadReceiptPolicy {
        return Ok(());
    }
    arkret_schema::validate_event_for_submit(event)
        .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
    if event.kind != arkret_wire::EventKind::RealmReadReceiptPolicy
        || event.scope_ref
            != (arkret_wire::ScopeRef::Realm {
                realm_id: event.realm_id.clone(),
            })
        || commit.stream_ref
            != (arkret_wire::CommitStreamRef::Realm {
                realm_id: event.realm_id.clone(),
            })
        || commit.realm_id != event.realm_id
        || commit.event_ref != event.event_id
    {
        return Err(PersistenceError::Conflict(
            "read-receipt policy requires its exact Realm Event and covering Commit".to_owned(),
        ));
    }
    let policy = typed_payload(event, EventPayloadExt::as_realm_read_receipt_policy)?;
    policy
        .validate()
        .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
    advance_singleton(
        conn,
        event,
        commit,
        "realm_read_receipt_policy",
        &result_value(&policy)?,
    )
    .await
}

async fn advance_singleton(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    commit: &arkret_wire::RealmCommit,
    family: &str,
    value: &serde_json::Value,
) -> PersistenceResult<()> {
    let position = i64::try_from(commit.stream_position).map_err(|_| {
        PersistenceError::SchemaViolation("Realm singleton position exceeds BIGINT".to_owned())
    })?;
    let changed = diesel::sql_query(
        "INSERT INTO realm_bootstrap_current_results \
         (realm_id,result_family,current_commit_id,current_stream_position,value,updated_at) \
         VALUES($1,$2,$3,$4,$5,$6) \
         ON CONFLICT(realm_id,result_family) DO UPDATE SET \
         current_commit_id=EXCLUDED.current_commit_id, \
         current_stream_position=EXCLUDED.current_stream_position, \
         value=EXCLUDED.value,updated_at=EXCLUDED.updated_at \
         WHERE realm_bootstrap_current_results.current_stream_position < EXCLUDED.current_stream_position",
    )
    .bind::<Text, _>(event.realm_id.as_str())
    .bind::<Text, _>(family)
    .bind::<Text, _>(commit.commit_id.as_str())
    .bind::<BigInt, _>(position)
    .bind::<Jsonb, _>(value)
    .bind::<Timestamptz, _>(commit.committed_at)
    .execute(conn)
    .await
    .map_err(PersistenceError::database)?;
    if changed != 1 {
        return Err(PersistenceError::Conflict(format!(
            "Realm singleton {family} cannot advance from this Commit"
        )));
    }
    Ok(())
}

async fn insert_singleton(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    commit: &arkret_wire::RealmCommit,
    family: &str,
    value: &serde_json::Value,
) -> PersistenceResult<()> {
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
    .bind::<Jsonb, _>(value)
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

#[cfg(test)]
mod tests {
    use soland_storage::{EventCommitUnitOfWork, EventStore};

    use super::*;

    #[derive(diesel::QueryableByName)]
    struct Row {
        #[diesel(sql_type = Text)]
        current_commit_id: String,
        #[diesel(sql_type = Jsonb)]
        value: serde_json::Value,
    }

    #[tokio::test]
    async fn read_receipt_policy_commits_exact_current_and_rejects_unauthorized_writes() {
        let database = crate::test_database::TestDatabase::lease().await;
        let pool = database.pool();
        let discussion =
            ordinary_realm::open_human_discussion(&pool, &uuid::Uuid::now_v7().to_string()).await;
        let mut previous = discussion.head.authority_commit;
        let uow = crate::PgEventCommitUnitOfWork::new(pool.clone());
        let founder = discussion.unit.transactions[0]
            .event
            .actor_id
            .signing_principal_id();
        for payload in [
            serde_json::json!({"disclosure":"disabled","visibility":"private"}),
            serde_json::json!({"disclosure":"required"}),
        ] {
            let request = ordinary_realm::next_request(
                &previous,
                arkret_wire::EventKind::RealmReadReceiptPolicy,
                founder,
                payload.clone(),
                chrono::Utc::now(),
            );
            uow.commit_event(request.clone()).await.unwrap();
            let mut conn = pool.get().await.unwrap();
            let current = diesel::sql_query("SELECT current_commit_id,value FROM realm_bootstrap_current_results WHERE realm_id=$1 AND result_family='realm_read_receipt_policy'")
                .bind::<Text, _>(request.authority_commit.event.realm_id.as_str()).get_result::<Row>(&mut *conn).await.unwrap();
            assert_eq!(
                current.current_commit_id,
                request.authority_commit.commit.commit_id.as_str()
            );
            assert_eq!(
                current.value, payload,
                "a successor replaces the entire policy value"
            );
            previous = request.authority_commit;
        }
        let outsider = arkret_wire::DidCoreId::new("ak:did_core:web:outsider.example").unwrap();
        let denied = ordinary_realm::next_request(
            &previous,
            arkret_wire::EventKind::RealmReadReceiptPolicy,
            &outsider,
            serde_json::json!({"disclosure":"disabled"}),
            chrono::Utc::now(),
        );
        assert!(uow.commit_event(denied.clone()).await.is_err());
        let mut conn = pool.get().await.unwrap();
        let current = diesel::sql_query("SELECT current_commit_id,value FROM realm_bootstrap_current_results WHERE realm_id=$1 AND result_family='realm_read_receipt_policy'")
            .bind::<Text, _>(previous.event.realm_id.as_str()).get_result::<Row>(&mut *conn).await.unwrap();
        assert_eq!(
            current.current_commit_id,
            previous.commit.commit_id.as_str()
        );
        assert_eq!(current.value, serde_json::json!({"disclosure":"required"}));
        let stored = crate::PgEventStore { pool }
            .get(&denied.authority_commit.event.event_id.to_string())
            .await
            .unwrap();
        assert!(
            stored.is_none(),
            "an unauthorized policy must leave no canonical Event"
        );
    }
}
