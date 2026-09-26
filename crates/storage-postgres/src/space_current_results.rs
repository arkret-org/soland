//! The three registered `ak.space.create` results at one RealmCommit cut.
//!
//! `space` is metadata only. The structural parent and child scope policy have
//! their own current families; an absent signed member becomes an explicit
//! genesis `null` in those families. This writer runs inside the Event/Commit
//! transaction, while the caller holds the Realm authority row lock.

use diesel::OptionalExtension as _;
use diesel::sql_types::{BigInt, Jsonb, Text, Timestamptz};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use serde_json::{Value, json};
use soland_storage::{PersistenceError, PersistenceResult};

#[derive(diesel::QueryableByName)]
struct ParentCurrentRow {
    #[diesel(sql_type = Text)]
    realm_id: String,
    #[diesel(sql_type = Text)]
    space_commit_id: String,
    #[diesel(sql_type = BigInt)]
    space_position: i64,
    #[diesel(sql_type = Jsonb)]
    space: Value,
    #[diesel(sql_type = Text)]
    parent_commit_id: String,
    #[diesel(sql_type = BigInt)]
    parent_position: i64,
    #[diesel(sql_type = Jsonb)]
    parent: Value,
    #[diesel(sql_type = Text)]
    policy_commit_id: String,
    #[diesel(sql_type = BigInt)]
    policy_position: i64,
    #[diesel(sql_type = Jsonb)]
    policy: Value,
}

#[derive(diesel::QueryableByName)]
struct PresentRow {
    #[diesel(sql_type = diesel::sql_types::Bool)]
    present: bool,
}

pub(crate) struct SpaceCreateValues {
    pub(crate) space_id: arkret_wire::SpaceId,
    pub(crate) space: Value,
    pub(crate) parent: Value,
    pub(crate) child_scope_policy: Value,
}

fn reject(detail: impl Into<String>) -> PersistenceError {
    PersistenceError::Conflict(format!("failed_precondition: {}", detail.into()))
}

/// Derive the three registry results from the signed Event, without trusting
/// a payload-provided object id, parent in metadata, or synthesized policy.
pub(crate) fn space_create_current_values(
    event: &arkret_wire::Event,
) -> PersistenceResult<SpaceCreateValues> {
    if event.kind != arkret_wire::EventKind::SpaceCreate {
        return Err(PersistenceError::SchemaViolation(
            "expected ak.space.create".to_owned(),
        ));
    }
    arkret_schema::validate_event_for_submit(event)
        .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
    let payload: arkret_models_collaboration::events_payloads::space::SpaceCreatePayload =
        serde_json::from_value(
            serde_json::to_value(&event.payload).map_err(PersistenceError::database)?,
        )
        .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
    let object = payload.object;
    object
        .validate()
        .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
    if object.id.is_some()
        || object.realm_id != event.realm_id
        || object.created_by != event.actor_id
        || object.created_at != event.created_at
        || object
            .state
            .as_ref()
            .is_some_and(|state| state != &arkret_wire::SpaceState::Active)
        || object.state_changed_at.is_some()
        || object.updated_by.is_some()
        || object.updated_at.is_some()
        || object.schema != arkret_models_collaboration::objects::space::Space::SCHEMA
    {
        return Err(PersistenceError::SchemaViolation(
            "Space create contains a forged or non-initial derived member".to_owned(),
        ));
    }
    let space_id = arkret_wire::SpaceId::from_event_id(&event.event_id);
    if object.parent_space_id.as_ref() == Some(&space_id) {
        return Err(reject("space_parent_cycle"));
    }
    if matches!(
        object.child_scope_policy.as_ref(),
        Some(
            arkret_models_collaboration::objects::space::ChildScopePolicy::RequireScopeCircleId { .. }
        )
    ) {
        return Err(reject(
            "Circle-targeting child policy needs a confirmed Circle authority cut",
        ));
    }
    let parent = json!({"parent_space_id": object.parent_space_id.as_ref()});
    let child_scope_policy =
        serde_json::to_value(&object.child_scope_policy).map_err(PersistenceError::database)?;
    let mut space = serde_json::to_value(&object).map_err(PersistenceError::database)?;
    let members = space.as_object_mut().ok_or_else(|| {
        PersistenceError::SchemaViolation("Space create object is not an object".to_owned())
    })?;
    members.remove("parent_space_id");
    members.remove("child_scope_policy");
    members.insert("id".to_owned(), json!(space_id));
    members.insert("state".to_owned(), json!("active"));
    Ok(SpaceCreateValues {
        space_id,
        space,
        parent,
        child_scope_policy,
    })
}

/// Prove the parent from complete same-Realm current rows. The standalone
/// Realm-scope slice refuses Circle-scoped metadata until a Circle authority
/// cut supplies its scope/readability proof. It also refuses a missing or
/// mismatched sibling family rather than treating it as a root or allow-any.
async fn require_parent_in_connection(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    position: i64,
    values: &SpaceCreateValues,
) -> PersistenceResult<()> {
    if values.space.get("scope_circle_id").is_some() {
        return Err(reject("Circle-scoped Space needs a Circle authority cut"));
    }
    let Some(parent_id) = values.parent["parent_space_id"].as_str() else {
        return Ok(());
    };
    let parent = diesel::sql_query(
        "SELECT s.realm_id,s.current_commit_id AS space_commit_id,\
                s.current_stream_position AS space_position,s.value AS space,\
                p.current_commit_id AS parent_commit_id,\
                p.current_stream_position AS parent_position,p.value AS parent,\
                c.current_commit_id AS policy_commit_id,\
                c.current_stream_position AS policy_position,c.value AS policy \
         FROM space_current_results s \
         JOIN space_parent_current_results p ON p.space_id=s.space_id AND p.realm_id=s.realm_id \
         JOIN space_child_scope_policy_current_results c ON c.space_id=s.space_id AND c.realm_id=s.realm_id \
         JOIN realm_commits rc ON rc.commit_id=s.current_commit_id \
           AND rc.realm_id=s.realm_id \
           AND rc.stream_position=s.current_stream_position \
           AND rc.stream_ref->>'kind'='realm' \
           AND rc.stream_ref->>'realm_id'=s.realm_id \
         WHERE s.space_id=$1 AND s.realm_id=$2 AND s.current_stream_position<$3 \
         FOR SHARE OF s,p,c",
    )
    .bind::<Text, _>(parent_id)
    .bind::<Text, _>(event.realm_id.as_str())
    .bind::<BigInt, _>(position)
    .get_result::<ParentCurrentRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?
    .ok_or_else(|| reject("space_parent_unreadable"))?;
    debug_assert_eq!(parent.realm_id, event.realm_id.as_str());
    // Until lifecycle, reparent and policy successors have their own same-cut
    // writers, all three results must still be the common genesis cut.
    if parent.space_commit_id != parent.parent_commit_id
        || parent.space_commit_id != parent.policy_commit_id
        || parent.space_position != parent.parent_position
        || parent.space_position != parent.policy_position
    {
        return Err(reject("space_parent_unreadable"));
    }
    // A separately accepted Space successor cannot be ignored as though
    // genesis were the complete parent basis. This is fail-closed until the
    // corresponding lifecycle, reparent and policy writers exist.
    let successor = diesel::sql_query(
        "SELECT EXISTS ( \
           SELECT 1 FROM canonical_events e JOIN realm_commits rc ON rc.event_pk=e.pk \
           WHERE e.realm_id=$1 AND e.state='committed' \
             AND rc.stream_position>$2 AND rc.stream_position<$3 \
             AND e.kind LIKE 'ak.space.%' AND e.kind<>'ak.space.create' \
         ) AS present",
    )
    .bind::<Text, _>(event.realm_id.as_str())
    .bind::<BigInt, _>(parent.space_position)
    .bind::<BigInt, _>(position)
    .get_result::<PresentRow>(&mut *conn)
    .await
    .map_err(PersistenceError::database)?;
    if successor.present {
        return Err(reject("space_parent_unreadable"));
    }
    if parent.space.get("state") != Some(&json!("active")) {
        return Err(reject("space_not_active"));
    }
    if parent.space.get("scope_circle_id").is_some() {
        return Err(reject("space_parent_unreadable"));
    }
    if parent
        .parent
        .as_object()
        .is_none_or(|value| value.len() != 1 || !value.contains_key("parent_space_id"))
    {
        return Err(reject("space_parent_unreadable"));
    }
    match &parent.policy {
        Value::Null => {}
        Value::Object(policy) if policy.get("kind") == Some(&json!("allow_any")) => {}
        Value::Object(policy) if policy.get("kind") == Some(&json!("require_same_scope")) => {}
        _ => return Err(reject(arkret_wire::ErrorCode::POLICY_VIOLATION)),
    }
    Ok(())
}

pub(crate) async fn commit_space_create_current_results_in_connection(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    commit: &arkret_wire::RealmCommit,
) -> PersistenceResult<()> {
    if event.kind != arkret_wire::EventKind::SpaceCreate {
        return Ok(());
    }
    if commit.stream_ref
        != (arkret_wire::CommitStreamRef::Realm {
            realm_id: event.realm_id.clone(),
        })
    {
        return Err(reject("Space create requires the Realm commit stream"));
    }
    // The route bypasses the old in-process reducer preflight. Its capability
    // verdict and quota reservation must therefore be fixed by the same
    // locked PG cut as these result writes.
    crate::realm_authorization_cut::authorize_capability_gated_event_in_connection(
        conn,
        event,
        commit.committed_at,
    )
    .await?;
    let values = space_create_current_values(event)?;
    let position = i64::try_from(commit.stream_position)
        .map_err(|_| reject("invalid Space stream position"))?;
    require_parent_in_connection(conn, event, position, &values).await?;
    let rows = [
        ("space_current_results", &values.space),
        ("space_parent_current_results", &values.parent),
        (
            "space_child_scope_policy_current_results",
            &values.child_scope_policy,
        ),
    ];
    for (table, value) in rows {
        let query = format!(
            "INSERT INTO {table} \
             (realm_id,space_id,current_commit_id,current_stream_position,value,updated_at) \
             VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING"
        );
        let inserted = diesel::sql_query(query)
            .bind::<Text, _>(event.realm_id.as_str())
            .bind::<Text, _>(values.space_id.as_str())
            .bind::<Text, _>(commit.commit_id.as_str())
            .bind::<BigInt, _>(position)
            .bind::<Jsonb, _>(value)
            .bind::<Timestamptz, _>(commit.committed_at)
            .execute(&mut *conn)
            .await
            .map_err(PersistenceError::database)?;
        if inserted != 1 {
            return Err(reject("Space current result already exists"));
        }
    }
    Ok(())
}
