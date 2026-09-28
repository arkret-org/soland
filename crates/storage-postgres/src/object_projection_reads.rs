//! Caller-visible Space and Strand lists derived from durable current rows.
//! No mutable in-process projection is an admission or read-state source.

use std::collections::{BTreeMap, BTreeSet};

use arkret_models_collaboration::objects::query_projection::{
    ProjectionAssignedToRelation, ProjectionSpaceList, ProjectionSpaceRow, ProjectionStrandList,
    ProjectionStrandRow,
};
use arkret_models_collaboration::objects::relation::Relation;
use arkret_models_collaboration::objects::space::Space;
use arkret_models_collaboration::objects::strand::{Strand, StrandPositionCurrent};
use arkret_wire::{
    ActorId, CircleId, CommitStreamRef, ObjectState, RealmId, ScopeRef, SpaceId, SpaceState,
    StrandId,
};
use diesel::sql_types::{Jsonb, Text};
use diesel_async::{AsyncConnection, RunQueryDsl};
use serde_json::Value;
use soland_storage::{
    ObjectCurrentSnapshot, ObjectCurrentSnapshotStore, PersistenceError, PersistenceResult,
};

use crate::{PgPool, PgTransactionError};

#[derive(diesel::QueryableByName)]
struct ValueRow {
    #[diesel(sql_type = Jsonb)]
    value: Value,
}

#[derive(diesel::QueryableByName)]
struct CircleRow {
    #[diesel(sql_type = Text)]
    circle_id: String,
}

#[derive(diesel::QueryableByName)]
struct PositionRow {
    #[diesel(sql_type = Text)]
    board_space_id: String,
    #[diesel(sql_type = Text)]
    strand_id: String,
    #[diesel(sql_type = Jsonb)]
    value: Value,
}

#[derive(diesel::QueryableByName)]
struct CurrentObjectRow {
    #[diesel(sql_type = Text)]
    id: String,
    #[diesel(sql_type = Text)]
    realm_id: String,
    #[diesel(sql_type = Jsonb)]
    value: Value,
    #[diesel(sql_type = diesel::sql_types::Bool)]
    proved: bool,
}

#[derive(diesel::QueryableByName)]
struct StrandSnapshotRow {
    #[diesel(sql_type = Text)]
    id: String,
    #[diesel(sql_type = Text)]
    realm_id: String,
    #[diesel(sql_type = Jsonb)]
    value: Value,
    #[diesel(sql_type = diesel::sql_types::Nullable<Jsonb>)]
    source_stream_ref: Option<Value>,
}

pub struct PgObjectCurrentSnapshotStore {
    pub pool: PgPool,
}

#[async_trait::async_trait]
impl ObjectCurrentSnapshotStore for PgObjectCurrentSnapshotStore {
    async fn snapshot(&self) -> PersistenceResult<ObjectCurrentSnapshot> {
        let mut conn = self.pool.get().await.map_err(PersistenceError::database)?;
        let (space_rows, strand_rows) = conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            diesel::sql_query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
                .execute(&mut *conn).await?;
            let orphan_sibling: crate::ExistsRow = diesel::sql_query(
                "SELECT EXISTS(SELECT 1 FROM space_parent_current_results p \
                 LEFT JOIN space_current_results s ON s.realm_id=p.realm_id AND s.space_id=p.space_id \
                 WHERE s.space_id IS NULL UNION ALL SELECT 1 FROM space_child_scope_policy_current_results c \
                 LEFT JOIN space_current_results s ON s.realm_id=c.realm_id AND s.space_id=c.space_id \
                 WHERE s.space_id IS NULL) AS present",
            ).get_result(&mut *conn).await?;
            if orphan_sibling.present {
                return Err(corrupt("Space current has orphan sibling family").into());
            }
            let spaces = diesel::sql_query(
                "SELECT s.space_id AS id,s.realm_id, \
                 s.value || jsonb_build_object('parent_space_id',p.value->'parent_space_id', \
                 'child_scope_policy',c.value) AS value, \
                 (sc.commit_id IS NOT NULL AND pc.commit_id IS NOT NULL AND cc.commit_id IS NOT NULL \
                   AND NOT (s.value ? 'parent_space_id') AND NOT (s.value ? 'child_scope_policy') \
                   AND jsonb_typeof(p.value)='object' AND p.value ? 'parent_space_id' \
                   AND p.value - 'parent_space_id'='{}'::jsonb) AS proved \
                 FROM space_current_results s \
                 LEFT JOIN space_parent_current_results p ON p.realm_id=s.realm_id AND p.space_id=s.space_id \
                 LEFT JOIN space_child_scope_policy_current_results c ON c.realm_id=s.realm_id AND c.space_id=s.space_id \
                 LEFT JOIN realm_commits sc ON sc.commit_id=s.current_commit_id AND sc.realm_id=s.realm_id \
                   AND sc.stream_position=s.current_stream_position \
                   AND sc.stream_ref=jsonb_build_object('kind','realm','realm_id',s.realm_id) \
                 LEFT JOIN realm_commits pc ON pc.commit_id=p.current_commit_id AND pc.realm_id=p.realm_id \
                   AND pc.stream_position=p.current_stream_position \
                   AND pc.stream_ref=jsonb_build_object('kind','realm','realm_id',p.realm_id) \
                 LEFT JOIN realm_commits cc ON cc.commit_id=c.current_commit_id AND cc.realm_id=c.realm_id \
                   AND cc.stream_position=c.current_stream_position \
                   AND cc.stream_ref=jsonb_build_object('kind','realm','realm_id',c.realm_id) \
                 ORDER BY s.realm_id,s.space_id",
            ).load::<CurrentObjectRow>(&mut *conn).await?;
            let strands = diesel::sql_query(
                "SELECT s.strand_id AS id,s.realm_id,s.value, \
                 rc.stream_ref AS source_stream_ref FROM strand_current_results s \
                 LEFT JOIN realm_commits rc ON rc.commit_id=s.current_commit_id AND rc.realm_id=s.realm_id \
                   AND rc.stream_position=s.current_stream_position \
                 ORDER BY s.realm_id,s.strand_id",
            ).load::<StrandSnapshotRow>(&mut *conn).await?;
            Ok((spaces,strands))
        }).await.map_err(PgTransactionError::into_persistence)?;
        let spaces = space_rows
            .into_iter()
            .map(|row| {
                if !row.proved {
                    return Err(corrupt("Space current sibling has no covering RealmCommit"));
                }
                let space: Space =
                    serde_json::from_value(row.value).map_err(PersistenceError::database)?;
                if space.id.as_ref().is_none_or(|id| id.as_str() != row.id)
                    || space.realm_id.as_str() != row.realm_id
                {
                    return Err(corrupt("Space current identity mismatch"));
                }
                Ok(space)
            })
            .collect::<PersistenceResult<Vec<_>>>()?;
        let strands = strand_rows
            .into_iter()
            .map(|row| {
                let strand: Strand =
                    serde_json::from_value(row.value).map_err(PersistenceError::database)?;
                if strand.id.as_ref().is_none_or(|id| id.as_str() != row.id)
                    || strand.realm_id.as_str() != row.realm_id
                {
                    return Err(corrupt("Strand current identity mismatch"));
                }
                let expected_stream_ref = match &strand.scope_circle_id {
                    Some(circle_id) => CommitStreamRef::Circle {
                        realm_id: strand.realm_id.clone(),
                        circle_id: circle_id.clone(),
                    },
                    None => CommitStreamRef::Realm {
                        realm_id: strand.realm_id.clone(),
                    },
                };
                let source_stream_ref = row
                    .source_stream_ref
                    .ok_or_else(|| corrupt("Strand current has no covering RealmCommit"))?;
                let source_stream_ref: CommitStreamRef = serde_json::from_value(source_stream_ref)
                    .map_err(|_| corrupt("Strand current has invalid source stream"))?;
                if source_stream_ref != expected_stream_ref {
                    return Err(corrupt("Strand current source stream mismatches its scope"));
                }
                Ok(strand)
            })
            .collect::<PersistenceResult<Vec<_>>>()?;
        Ok(ObjectCurrentSnapshot { spaces, strands })
    }
}

fn corrupt(detail: impl Into<String>) -> PersistenceError {
    PersistenceError::Internal(format!("invalid projection current: {}", detail.into()))
}

fn visible(circle: Option<&CircleId>, circles: &BTreeSet<CircleId>) -> bool {
    circle.is_none_or(|id| circles.contains(id))
}

pub(crate) async fn lists_for_actor(
    pool: &PgPool,
    realm_id: &RealmId,
    actor: &ActorId,
    include_terminal: bool,
) -> PersistenceResult<Option<(ProjectionSpaceList, ProjectionStrandList)>> {
    let mut conn = pool.get().await.map_err(PersistenceError::database)?;
    conn.transaction::<_, PgTransactionError, _>(async move |conn| {
        diesel::sql_query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
            .execute(&mut *conn).await?;
        let joined: Option<ValueRow> = diesel::sql_query(
            "SELECT value FROM member_state_current_results \
             WHERE realm_id=$1 AND member_id=$2 AND membership='join'",
        ).bind::<Text,_>(realm_id.as_str()).bind::<Text,_>(actor.to_string())
            .get_result(&mut *conn).await.optional()?;
        if joined.is_none() { return Ok(None); }
        if joined.as_ref().is_some_and(|row| row.value != serde_json::json!({"membership":"join"})) {
            return Err(corrupt("member current value disagrees with joined state").into());
        }
        let circle_rows = diesel::sql_query(
            "SELECT m.circle_id FROM circle_member_state_current_results m \
             JOIN circle_current_results c ON c.circle_id=m.circle_id AND c.realm_id=m.realm_id \
             JOIN realm_commits rc ON rc.commit_id=m.current_commit_id \
               AND rc.realm_id=m.realm_id AND rc.stream_position=m.current_stream_position \
               AND rc.stream_ref=m.source_stream_ref \
             WHERE m.realm_id=$1 AND m.member_id=$2 AND m.membership='join' \
               AND c.value->>'state'='active' \
               AND m.source_stream_ref->>'circle_id'=m.circle_id",
        ).bind::<Text,_>(realm_id.as_str()).bind::<Text,_>(actor.to_string())
            .load::<CircleRow>(&mut *conn).await?;
        let circles = circle_rows.into_iter().map(|row| row.circle_id.parse::<CircleId>()
            .map_err(|error| corrupt(error.to_string()))).collect::<PersistenceResult<BTreeSet<_>>>()?;
        let incomplete_space = diesel::sql_query(
            "SELECT EXISTS(SELECT 1 FROM space_current_results s \
             LEFT JOIN space_parent_current_results p ON p.realm_id=s.realm_id AND p.space_id=s.space_id \
             LEFT JOIN space_child_scope_policy_current_results c ON c.realm_id=s.realm_id AND c.space_id=s.space_id \
             WHERE s.realm_id=$1 AND (p.space_id IS NULL OR c.space_id IS NULL \
               OR s.value ? 'parent_space_id' OR s.value ? 'child_scope_policy' \
               OR jsonb_typeof(p.value)<>'object' OR NOT p.value ? 'parent_space_id' \
               OR p.value - 'parent_space_id' <> '{}'::jsonb)) \
             OR EXISTS(SELECT 1 FROM space_parent_current_results p \
               LEFT JOIN space_current_results s ON s.realm_id=p.realm_id AND s.space_id=p.space_id \
               WHERE p.realm_id=$1 AND s.space_id IS NULL) \
             OR EXISTS(SELECT 1 FROM space_child_scope_policy_current_results c \
               LEFT JOIN space_current_results s ON s.realm_id=c.realm_id AND s.space_id=c.space_id \
               WHERE c.realm_id=$1 AND s.space_id IS NULL) AS present",
        ).bind::<Text,_>(realm_id.as_str()).get_result::<crate::ExistsRow>(&mut *conn).await?;
        if incomplete_space.present {
            return Err(corrupt("Space registered sibling families are incomplete or conflicting").into());
        }
        let space_rows = diesel::sql_query(
            "SELECT s.value || jsonb_build_object('parent_space_id',p.value->'parent_space_id', \
             'child_scope_policy',c.value) AS value FROM space_current_results s \
             JOIN space_parent_current_results p ON p.realm_id=s.realm_id AND p.space_id=s.space_id \
             JOIN space_child_scope_policy_current_results c ON c.realm_id=s.realm_id AND c.space_id=s.space_id \
             WHERE s.realm_id=$1 ORDER BY s.space_id",
        ).bind::<Text,_>(realm_id.as_str()).load::<ValueRow>(&mut *conn).await?;
        let mut spaces = Vec::new();
        let mut space_objects = BTreeMap::new();
        for row in space_rows {
            let space: Space = serde_json::from_value(row.value).map_err(PersistenceError::database)?;
            if space.realm_id != *realm_id { return Err(corrupt("Space Realm mismatch").into()); }
            let space_id = space.id.clone().ok_or_else(|| corrupt("Space id absent"))?;
            space_objects.insert(space_id, space.clone());
            if !visible(space.scope_circle_id.as_ref(), &circles) { continue; }
            let state = space.state.ok_or_else(|| corrupt("Space state absent"))?;
            if !include_terminal && state == SpaceState::Tombstoned { continue; }
            spaces.push(ProjectionSpaceRow {
                space_id: space.id.ok_or_else(|| corrupt("Space id absent"))?,
                realm_id: space.realm_id, kind: space.kind, title: space.title,
                parent_space_id: space.parent_space_id, rank: space.rank, state,
                state_changed_at: space.state_changed_at,
                created_by: Some(space.created_by), created_at: Some(space.created_at), updated_at: space.updated_at,
            });
        }
        let default: Option<ValueRow> = diesel::sql_query(
            "SELECT value FROM realm_set_default_strand_current_results WHERE realm_id=$1",
        ).bind::<Text,_>(realm_id.as_str()).get_result(&mut *conn).await.optional()?;
        let default = default.map(|row| serde_json::from_value::<Option<StrandId>>(
            row.value.get("default_strand_id").cloned().ok_or_else(|| corrupt("default Strand pointer absent"))?
        ).map_err(PersistenceError::database)).transpose()?.flatten();
        let mut assignments: BTreeMap<StrandId, Vec<ProjectionAssignedToRelation>> = BTreeMap::new();
        let relations = diesel::sql_query(
            "SELECT value FROM relation_current_results WHERE realm_id=$1 AND state='active' \
             AND value->>'relation_kind'='assigned_to' ORDER BY relation_id",
        ).bind::<Text,_>(realm_id.as_str()).load::<ValueRow>(&mut *conn).await?;
        for row in relations {
            let relation: Relation = serde_json::from_value(row.value).map_err(PersistenceError::database)?;
            if relation.realm_id != *realm_id || !visible(relation.scope_circle_id.as_ref(), &circles) { continue; }
            if relation.effective_scope.as_ref().is_some_and(|scope| match scope {
                ScopeRef::Realm { realm_id: id } => id != realm_id,
                ScopeRef::Circle { realm_id: id, circle_id } => id != realm_id || !circles.contains(circle_id),
                _ => true,
            }) { continue; }
            let source = relation.from_ref.as_object_ref().ok_or_else(|| corrupt("assignment source is not an object"))?;
            let strand = source.parse::<StrandId>().map_err(|error| corrupt(error.to_string()))?;
            assignments.entry(strand).or_default().push(ProjectionAssignedToRelation {
                relation_id: relation.id.ok_or_else(|| corrupt("assignment id absent"))?,
                actor_id: relation.to_ref.as_actor_id().ok_or_else(|| corrupt("assignment target is not an Actor"))?.clone(),
            });
        }
        let unproved_position = diesel::sql_query(
            "SELECT EXISTS(SELECT 1 FROM strand_position_current_results p \
             LEFT JOIN realm_commits c ON c.commit_id=p.current_commit_id \
               AND c.realm_id=p.realm_id AND c.stream_position=p.current_stream_position \
               AND c.stream_ref=jsonb_build_object('kind','realm','realm_id',p.realm_id) \
             WHERE p.realm_id=$1 AND c.commit_id IS NULL) AS present",
        ).bind::<Text,_>(realm_id.as_str()).get_result::<crate::ExistsRow>(&mut *conn).await?;
        if unproved_position.present {
            return Err(corrupt("position current has no covering RealmCommit").into());
        }
        let position_rows = diesel::sql_query(
            "SELECT board_space_id,strand_id,value FROM strand_position_current_results \
             WHERE realm_id=$1 ORDER BY strand_id,board_space_id",
        ).bind::<Text,_>(realm_id.as_str()).load::<PositionRow>(&mut *conn).await?;
        let mut positions: BTreeMap<StrandId, Vec<(SpaceId, StrandPositionCurrent)>> = BTreeMap::new();
        for row in position_rows {
            let board = row.board_space_id.parse::<SpaceId>().map_err(|error| corrupt(error.to_string()))?;
            let strand = row.strand_id.parse::<StrandId>().map_err(|error| corrupt(error.to_string()))?;
            let value = serde_json::from_value::<Option<StrandPositionCurrent>>(row.value).map_err(PersistenceError::database)?;
            if let Some(value) = value { positions.entry(strand).or_default().push((board, value)); }
        }
        let strand_rows = diesel::sql_query(
            "SELECT value FROM strand_current_results WHERE realm_id=$1 ORDER BY strand_id",
        ).bind::<Text,_>(realm_id.as_str()).load::<ValueRow>(&mut *conn).await?;
        let mut strands = Vec::new();
        for row in strand_rows {
            let strand: Strand = serde_json::from_value(row.value).map_err(PersistenceError::database)?;
            if strand.realm_id != *realm_id { return Err(corrupt("Strand Realm mismatch").into()); }
            if !visible(strand.scope_circle_id.as_ref(), &circles) { continue; }
            let state = strand.state.ok_or_else(|| corrupt("Strand state absent"))?;
            if !include_terminal && state == ObjectState::Redacted { continue; }
            let id = strand.id.ok_or_else(|| corrupt("Strand id absent"))?;
            let mut placement = None;
            for (board_id, position) in positions.remove(&id).unwrap_or_default() {
                let board = space_objects.get(&board_id).ok_or_else(|| corrupt("position Board metadata absent"))?;
                let list = space_objects.get(&position.list_space_id).ok_or_else(|| corrupt("position List metadata absent"))?;
                if !visible(board.scope_circle_id.as_ref(), &circles) || !visible(list.scope_circle_id.as_ref(), &circles) { continue; }
                if board.kind != "board" || list.kind != "list"
                    || board.state == Some(SpaceState::Tombstoned) || list.state == Some(SpaceState::Tombstoned)
                    || list.parent_space_id.as_ref() != Some(&board_id)
                    || strand.scope_circle_id != board.scope_circle_id || strand.scope_circle_id != list.scope_circle_id {
                    return Err(corrupt("position cannot form an available structural placement").into());
                }
                if placement.is_some() {
                    return Err(corrupt("Strand has multiple visible Board placements; this row cannot select one").into());
                }
                placement = Some((board_id, position));
            }
            let assigned = assignments.remove(&id).unwrap_or_default();
            let mut actors = assigned.iter().map(|row| row.actor_id.clone()).collect::<Vec<_>>();
            actors.sort_by_key(ToString::to_string); actors.dedup();
            strands.push(ProjectionStrandRow {
                is_default: default.as_ref() == Some(&id), strand_id: id,
                realm_id: strand.realm_id, state, state_changed_at: strand.state_changed_at,
                stage: strand.stage, stage_changed_at: strand.stage_changed_at,
                title: strand.metadata.as_ref().and_then(|metadata| metadata.title.clone()),
                summary: strand.metadata.as_ref().and_then(|metadata| metadata.summary.clone()),
                board_space_id: placement.as_ref().map(|(board, _)| board.clone()),
                list_space_id: placement.as_ref().map(|(_, position)| position.list_space_id.clone()),
                rank: placement.map(|(_, position)| position.rank),
                assigned_actor_ids: actors, assigned_to_relations: assigned,
                created_by: Some(strand.created_by), created_at: Some(strand.created_at),
                updated_by: strand.updated_by, updated_at: strand.updated_at,
            });
        }
        Ok(Some((
            ProjectionSpaceList { realm_id: realm_id.clone(), total: spaces.len() as u64, spaces, next_cursor: None, has_more: false },
            ProjectionStrandList { realm_id: realm_id.clone(), total: strands.len() as u64, strands, next_cursor: None, has_more: false },
        )))
    }).await.map_err(PgTransactionError::into_persistence)
}

use diesel::OptionalExtension as _;
