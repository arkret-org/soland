//! Durable singleton current results established by an ordinary Realm bootstrap.

use arkret_event_draft::EventPayloadExt;
use arkret_models_collaboration::events_payloads::realm::RealmPurpose;
use diesel::sql_types::{BigInt, Jsonb, Text, Timestamptz};
use diesel_async::{AsyncPgConnection, RunQueryDsl};

use crate::{PersistenceError, PersistenceResult};

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
    let position = i64::try_from(commit.stream_position).map_err(|_| {
        PersistenceError::SchemaViolation("Realm profile position exceeds BIGINT".to_owned())
    })?;
    let changed = diesel::sql_query(
        "INSERT INTO realm_bootstrap_current_results \
         (realm_id,result_family,current_commit_id,current_stream_position,value,updated_at) \
         VALUES($1,'realm_profile',$2,$3,$4,$5) \
         ON CONFLICT(realm_id,result_family) DO UPDATE SET \
         current_commit_id=EXCLUDED.current_commit_id, \
         current_stream_position=EXCLUDED.current_stream_position, \
         value=EXCLUDED.value,updated_at=EXCLUDED.updated_at \
         WHERE realm_bootstrap_current_results.current_stream_position < EXCLUDED.current_stream_position",
    )
    .bind::<Text, _>(event.realm_id.as_str())
    .bind::<Text, _>(commit.commit_id.as_str())
    .bind::<BigInt, _>(position)
    .bind::<Jsonb, _>(&value)
    .bind::<Timestamptz, _>(commit.committed_at)
    .execute(conn)
    .await
    .map_err(PersistenceError::database)?;
    if changed != 1 {
        return Err(PersistenceError::Conflict(
            "Realm profile current result cannot advance from this Commit".to_owned(),
        ));
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
