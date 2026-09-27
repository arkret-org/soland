//! Circle convenience reads from accepted current cells in one snapshot.

use arkret_models_collaboration::governance::circle::{
    Circle, CircleDirectoryVisibility, CircleMembership, CircleView,
};
use arkret_wire::{ActorId, CircleId, RealmId};
use diesel::sql_types::{Jsonb, Text};
use diesel_async::{AsyncConnection as _, AsyncPgConnection, RunQueryDsl};
use soland_storage::{PersistenceError, PersistenceResult};

use crate::{PgPool, PgTransactionError, pg_conn};

#[derive(diesel::QueryableByName)]
struct CircleRow {
    #[diesel(sql_type=Jsonb)]
    value: serde_json::Value,
    #[diesel(sql_type=Jsonb)]
    envelope: serde_json::Value,
    #[diesel(sql_type=Jsonb)]
    commit_json: serde_json::Value,
    #[diesel(sql_type=Text)]
    circle_id: String,
}

#[derive(diesel::QueryableByName)]
struct MemberRow {
    #[diesel(sql_type=Text)]
    member_id: String,
    #[diesel(sql_type=Jsonb)]
    value: serde_json::Value,
    #[diesel(sql_type=Jsonb)]
    envelope: serde_json::Value,
    #[diesel(sql_type=Jsonb)]
    commit_json: serde_json::Value,
}

#[derive(diesel::QueryableByName)]
struct AcceptedGroupRow {
    #[diesel(sql_type=Jsonb)]
    value: serde_json::Value,
    #[diesel(sql_type=Jsonb)]
    envelope: serde_json::Value,
    #[diesel(sql_type=Jsonb)]
    commit_json: serde_json::Value,
}

fn corrupt(detail: impl std::fmt::Display) -> PersistenceError {
    PersistenceError::Internal(format!("invalid accepted Circle current: {detail}"))
}

fn covering_event(
    envelope: serde_json::Value,
    commit: serde_json::Value,
) -> PersistenceResult<arkret_wire::Event> {
    let event: arkret_wire::Event = serde_json::from_value(envelope).map_err(corrupt)?;
    let commit: arkret_wire::RealmCommit = serde_json::from_value(commit).map_err(corrupt)?;
    if commit.event_ref != event.event_id || commit.realm_id != event.realm_id {
        return Err(corrupt("Commit does not cover its canonical Event"));
    }
    Ok(event)
}

async fn views(
    conn: &mut AsyncPgConnection,
    realm: Option<&RealmId>,
    circle_id: Option<&CircleId>,
    actor: &ActorId,
) -> PersistenceResult<Vec<CircleView>> {
    use diesel::sql_types::Nullable;
    let circles = diesel::sql_query(
        "SELECT r.value,e.envelope,c.commit_json,r.circle_id FROM circle_current_results r \
         LEFT JOIN realm_commits c ON c.commit_id=r.current_commit_id AND c.realm_id=r.realm_id \
             AND c.stream_position=r.current_stream_position AND c.stream_ref=r.source_stream_ref \
         LEFT JOIN canonical_events e ON e.pk=c.event_pk AND e.state='committed' \
         WHERE ($1::text IS NULL OR r.realm_id=$1) AND ($2::text IS NULL OR r.circle_id=$2) ORDER BY r.circle_id",
    ).bind::<Nullable<Text>,_>(realm.map(RealmId::as_str)).bind::<Nullable<Text>,_>(circle_id.map(CircleId::as_str))
        .load::<CircleRow>(&mut *conn).await.map_err(PersistenceError::database)?;
    let mut result = Vec::new();
    let at = chrono::Utc::now();
    for row in circles {
        let circle: Circle = serde_json::from_value(row.value).map_err(corrupt)?;
        let id: CircleId = row.circle_id.parse().map_err(corrupt)?;
        let create = covering_event(row.envelope, row.commit_json)?;
        let mut payload: arkret_models_collaboration::events_payloads::circle::CircleCreatePayload =
            serde_json::from_value(serde_json::json!(&create.payload)).map_err(corrupt)?;
        payload.object.id = Some(id.clone());
        let object = serde_json::to_value(payload.object).map_err(corrupt)?;
        if create.kind != arkret_wire::EventKind::CircleCreate
            || CircleId::from_event_id(&create.event_id) != id
            || circle.id.as_ref() != Some(&id)
            || circle.realm_id != create.realm_id
            || create.scope_ref
                != (arkret_wire::ScopeRef::Realm {
                    realm_id: circle.realm_id.clone(),
                })
            || serde_json::to_value(&circle).map_err(corrupt)? != object
        {
            return Err(corrupt(
                "profile does not match its covering accepted create",
            ));
        }
        if circle.profile_ref.is_some()
            || circle.title == "Agent Sidecar Scope"
            || circle.display.short_name.starts_with("SC-")
        {
            continue;
        }
        if !crate::authority_commit::accepted_current_member_joined_in_connection(
            conn,
            &circle.realm_id,
            actor,
        )
        .await?
        {
            continue;
        }
        let mut joined = crate::account_stream_scan::caller_circle_floor_in_connection(
            conn,
            &circle.realm_id,
            &id,
            actor,
        )
        .await?
        .is_some();
        let mut member_ids = Vec::new();
        let mut viewer_membership = None;
        let members = diesel::sql_query(
            "SELECT m.member_id,m.value,e.envelope,c.commit_json FROM circle_member_state_current_results m \
             LEFT JOIN realm_commits c ON c.commit_id=m.current_commit_id AND c.realm_id=m.realm_id \
                AND c.stream_position=m.current_stream_position AND c.stream_ref=m.source_stream_ref \
             LEFT JOIN canonical_events e ON e.pk=c.event_pk AND e.state='committed' \
             WHERE m.realm_id=$1 AND m.circle_id=$2 ORDER BY m.member_id",
        ).bind::<Text,_>(circle.realm_id.as_str()).bind::<Text,_>(id.as_str())
            .load::<MemberRow>(&mut *conn).await.map_err(PersistenceError::database)?;
        if joined {
            joined = members
                .iter()
                .find(|member| member.member_id == actor.to_string())
                .map(|member| {
                    serde_json::from_value::<arkret_wire::CircleMemberStateCurrent>(
                        member.value.clone(),
                    )
                    .map_err(corrupt)
                })
                .transpose()?
                .is_some_and(|current| {
                    current.membership == arkret_wire::MembershipState::Join
                        && current.effective_at <= at
                });
        }
        if !joined && circle.directory_visibility != CircleDirectoryVisibility::RealmMembers {
            continue;
        }
        for member in members {
            let who: ActorId = serde_json::from_str(&member.member_id).map_err(corrupt)?;
            let current: arkret_wire::CircleMemberStateCurrent =
                serde_json::from_value(member.value).map_err(corrupt)?;
            let event = covering_event(member.envelope, member.commit_json)?;
            if event.kind != arkret_wire::EventKind::CircleMemberState
                || event.scope_ref
                    != (arkret_wire::ScopeRef::Circle {
                        realm_id: circle.realm_id.clone(),
                        circle_id: id.clone(),
                    })
                || serde_json::from_value::<ActorId>(
                    event
                        .payload
                        .get("member_id")
                        .cloned()
                        .ok_or_else(|| corrupt("member absent"))?,
                )
                .map_err(corrupt)?
                    != who
                || event.payload.get("membership")
                    != Some(&serde_json::to_value(current.membership).map_err(corrupt)?)
            {
                return Err(corrupt(
                    "membership does not match its covering accepted Event",
                ));
            }
            let membership: CircleMembership =
                serde_json::from_value(serde_json::json!(current.membership)).map_err(corrupt)?;
            if who == *actor {
                viewer_membership = Some(membership);
            }
            if joined
                && membership == CircleMembership::Join
                && current.effective_at <= at
                && crate::account_stream_scan::caller_circle_floor_in_connection(
                    conn,
                    &circle.realm_id,
                    &id,
                    &who,
                )
                .await?
                .is_some()
            {
                member_ids.push(who);
            }
        }
        let scope = arkret_wire::ScopeRef::Circle {
            realm_id: circle.realm_id.clone(),
            circle_id: id.clone(),
        };
        let key =
            String::from_utf8(arkret_canonical::canonical_json_bytes(&scope).map_err(corrupt)?)
                .map_err(corrupt)?;
        let groups = diesel::sql_query(
            "SELECT g.value,e.envelope,c.commit_json FROM mls_group_current_results g \
             LEFT JOIN realm_commits c ON c.commit_id=g.current_commit_id AND c.realm_id=g.realm_id \
               AND c.stream_position=g.current_stream_position \
             LEFT JOIN canonical_events e ON e.pk=c.event_pk AND e.state='committed' \
             WHERE g.scope_key=$1",
        ).bind::<Text,_>(&key).load::<AcceptedGroupRow>(&mut *conn).await.map_err(PersistenceError::database)?;
        let mls_group_id = if let Some(group) = groups.into_iter().next() {
            let current: arkret_wire::MlsGroupCurrent =
                serde_json::from_value(group.value).map_err(corrupt)?;
            let event = covering_event(group.envelope, group.commit_json)?;
            if current.effective_scope != scope
                || event.scope_ref != scope
                || !matches!(
                    event.kind,
                    arkret_wire::EventKind::MlsGenesis | arkret_wire::EventKind::MlsCommit
                )
            {
                return Err(corrupt(
                    "MLS current has no matching covering accepted transition",
                ));
            }
            Some(scope.canonical_mls_group_id().map_err(corrupt)?.to_string())
        } else {
            None
        };
        result.push(CircleView {
            circle_id: id,
            realm_id: circle.realm_id,
            profile_ref: circle.profile_ref,
            title: circle.title,
            summary: circle.summary,
            display: circle.display,
            directory_visibility: circle.directory_visibility,
            join_rule: circle.join_rule,
            history_access: circle.history_access,
            mls_group_id,
            state: circle.state,
            viewer_membership,
            member_ids,
            created_by: circle.created_by,
            created_at: circle.created_at,
            updated_by: circle.updated_by,
            updated_at: circle.updated_at,
        });
    }
    Ok(result)
}

pub(crate) async fn circle_views_for_actor(
    pool: &PgPool,
    realm: &RealmId,
    actor: &ActorId,
) -> PersistenceResult<Vec<CircleView>> {
    let mut conn = pg_conn(pool).await.map_err(PersistenceError::database)?;
    conn.transaction::<_, PgTransactionError, _>(async move |conn| {
        diesel::sql_query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
            .execute(conn)
            .await
            .map_err(PersistenceError::database)?;
        views(conn, Some(realm), None, actor)
            .await
            .map_err(PgTransactionError::from)
    })
    .await
    .map_err(PgTransactionError::into_persistence)
}

pub(crate) async fn circle_view_for_actor(
    pool: &PgPool,
    circle: &CircleId,
    actor: &ActorId,
) -> PersistenceResult<Option<CircleView>> {
    let mut conn = pg_conn(pool).await.map_err(PersistenceError::database)?;
    conn.transaction::<_, PgTransactionError, _>(async move |conn| {
        diesel::sql_query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
            .execute(conn)
            .await
            .map_err(PersistenceError::database)?;
        Ok(views(conn, None, Some(circle), actor).await?.pop())
    })
    .await
    .map_err(PgTransactionError::into_persistence)
}
