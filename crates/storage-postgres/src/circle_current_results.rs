//! Same-cut authority admission and durable current for the first ordinary
//! Circle create and self-membership edges. Unsupported Circle branches remain
//! closed; no projection table is an authorization source.

use arkret_models_collaboration::events_payloads::circle::CircleCreatePayload;
use arkret_models_collaboration::governance::circle::CircleState;
use arkret_wire::{
    ActorId, CircleId, CommitStreamRef, Event, EventKind, RealmCommit, SchemaId, ScopeRef,
};
use diesel::sql_types::{BigInt, Jsonb, Text, Timestamptz};
use diesel::{OptionalExtension as _, sql_query};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use serde_json::{Value, json};
use soland_storage::{ConflictCode, PersistenceError, PersistenceResult};

#[derive(diesel::QueryableByName)]
struct CircleRow {
    #[diesel(sql_type = Jsonb)]
    value: Value,
}

#[derive(diesel::QueryableByName)]
struct MemberRow {
    #[diesel(sql_type = Text)]
    membership: String,
}

fn conflict(code: ConflictCode, detail: &str) -> PersistenceError {
    PersistenceError::Conflict(format!("{code}: {detail}"))
}

fn schema(detail: &str) -> PersistenceError {
    PersistenceError::SchemaViolation(detail.to_owned())
}

fn circle_id(event: &Event) -> CircleId {
    CircleId::from_event_id(&event.event_id)
}

fn folded_short_name(name: &str) -> PersistenceResult<String> {
    let bytes = name.as_bytes();
    if !(1..=24).contains(&bytes.len())
        || !bytes[0].is_ascii_uppercase()
        || !bytes[1..]
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b' ' | b'_' | b'-'))
    {
        return Err(schema(
            "Circle short_name is outside its closed ASCII profile",
        ));
    }
    Ok(name.to_ascii_lowercase())
}

pub(crate) async fn admit_in_connection(
    conn: &mut AsyncPgConnection,
    event: &Event,
    commit: &RealmCommit,
    _authority_station: &arkret_wire::DidCoreId,
) -> PersistenceResult<()> {
    match &event.kind {
        EventKind::CircleCreate => {
            if event.scope_ref
                != (ScopeRef::Realm {
                    realm_id: event.realm_id.clone(),
                })
                || commit.stream_ref
                    != (CommitStreamRef::Realm {
                        realm_id: event.realm_id.clone(),
                    })
            {
                return Err(schema("Circle create must be on the Realm stream"));
            }
            let payload: CircleCreatePayload = serde_json::from_value(json!(&event.payload))
                .map_err(|_| schema("Circle create payload is invalid"))?;
            let object = payload.object;
            if object.schema != SchemaId::CIRCLE_V1
                || object.id.is_some()
                || object.mls_group_id.is_some()
                || object.realm_id != event.realm_id
                || object.created_by != event.actor_id
                || object.created_at != event.created_at
                || object.state != CircleState::Active
                || object.state_changed_at.is_some()
                || object.updated_by.is_some()
                || object.updated_at.is_some()
            {
                return Err(schema("Circle create object differs from its signed Event"));
            }
            if object.profile_ref.is_some() || object.agent_participation.is_some() {
                return Err(conflict(
                    ConflictCode::UnsupportedFeature,
                    "Circle profile and Agent participation need their own admission cuts",
                ));
            }
            let short_name = folded_short_name(&object.display.short_name)?;
            crate::realm_authorization_cut::authorize_capability_gated_event_in_connection(
                conn,
                event,
                commit.committed_at,
            )
            .await?;
            let used_name = sql_query(
                "SELECT value FROM circle_current_results WHERE realm_id=$1 AND short_name_folded=$2 FOR SHARE",
            )
            .bind::<Text, _>(event.realm_id.as_str())
            .bind::<Text, _>(short_name)
            .get_result::<CircleRow>(&mut *conn)
            .await
            .optional()
            .map_err(PersistenceError::database)?;
            if used_name.is_some() {
                return Err(conflict(
                    ConflictCode::FailedPrecondition,
                    "circle_short_name_taken",
                ));
            }
            Ok(())
        }
        EventKind::CircleMemberState => {
            let ScopeRef::Circle {
                realm_id,
                circle_id,
            } = &event.scope_ref
            else {
                return Err(schema("Circle membership needs a Circle stream"));
            };
            if realm_id != &event.realm_id
                || commit.stream_ref
                    != (CommitStreamRef::Circle {
                        realm_id: realm_id.clone(),
                        circle_id: circle_id.clone(),
                    })
                || event.payload.get("circle_id").and_then(Value::as_str)
                    != Some(circle_id.as_str())
            {
                return Err(schema("Circle membership scope and payload differ"));
            }
            let member: ActorId = serde_json::from_value(
                event
                    .payload
                    .get("member_id")
                    .cloned()
                    .ok_or_else(|| schema("member_id missing"))?,
            )
            .map_err(|_| schema("member_id invalid"))?;
            if member != event.actor_id {
                return Err(conflict(
                    ConflictCode::UnsupportedFeature,
                    "cross-actor Circle membership needs its audit and manager cut",
                ));
            }
            let next = event
                .payload
                .get("membership")
                .and_then(Value::as_str)
                .ok_or_else(|| schema("membership missing"))?;
            crate::realm_authorization_cut::lock_realm_authorization_cut(conn, &event.realm_id)
                .await?;
            if crate::member_state_admission::locked_membership(conn, &event.realm_id, &member)
                .await?
                != "join"
            {
                return Err(conflict(
                    ConflictCode::FailedPrecondition,
                    "circle_member_must_be_realm_member",
                ));
            }
            crate::realm_authorization_cut::authorize_capability_gated_event_in_connection(
                conn,
                event,
                commit.committed_at,
            )
            .await?;
            let circle = sql_query(
                "SELECT value FROM circle_current_results WHERE realm_id=$1 AND circle_id=$2 FOR SHARE",
            )
            .bind::<Text, _>(event.realm_id.as_str())
            .bind::<Text, _>(circle_id.as_str())
            .get_result::<CircleRow>(&mut *conn)
            .await
            .optional()
            .map_err(PersistenceError::database)?
            .ok_or_else(|| PersistenceError::NotFound("Circle is not available".to_owned()))?;
            if circle.value.get("state").and_then(Value::as_str) != Some("active") {
                return Err(conflict(
                    ConflictCode::FailedPrecondition,
                    "circle_not_active",
                ));
            }
            if next == "join"
                && circle.value.get("join_rule").and_then(Value::as_str) != Some("public")
            {
                return Err(conflict(
                    ConflictCode::UnsupportedFeature,
                    "Circle self-entry requires a public Circle",
                ));
            }
            let current = sql_query(
                "SELECT membership FROM circle_member_state_current_results \
                 WHERE circle_id=$1 AND member_id=$2 FOR UPDATE",
            )
            .bind::<Text, _>(circle_id.as_str())
            .bind::<Text, _>(member.to_string())
            .get_result::<MemberRow>(&mut *conn)
            .await
            .optional()
            .map_err(PersistenceError::database)?;
            let previous = current.as_ref().map(|row| row.membership.as_str());
            if let Some(expected) = event.payload.get("expected_membership") {
                let matches = match expected {
                    Value::Null => previous.is_none(),
                    Value::String(value) => previous == Some(value.as_str()),
                    _ => false,
                };
                if !matches {
                    return Err(conflict(
                        ConflictCode::FailedPrecondition,
                        "Circle membership CAS differs",
                    ));
                }
            }
            if !matches!(
                (previous, next),
                (None | Some("leave"), "join") | (Some("join"), "leave")
            ) {
                return Err(conflict(
                    ConflictCode::FailedPrecondition,
                    "Circle self-membership edge is invalid",
                ));
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

pub(crate) async fn commit_in_connection(
    conn: &mut AsyncPgConnection,
    event: &Event,
    commit: &RealmCommit,
) -> PersistenceResult<()> {
    let position = i64::try_from(commit.stream_position)
        .map_err(|_| schema("Circle stream position exceeds storage"))?;
    match &event.kind {
        EventKind::CircleCreate => {
            let mut payload: CircleCreatePayload = serde_json::from_value(json!(&event.payload))
                .map_err(|_| schema("Circle create payload is invalid"))?;
            let id = circle_id(event);
            let short_name = folded_short_name(&payload.object.display.short_name)?;
            payload.object.id = Some(id.clone());
            let value = serde_json::to_value(payload.object).map_err(PersistenceError::database)?;
            sql_query(
                "INSERT INTO circle_current_results \
                 (realm_id,circle_id,create_event_id,current_commit_id,current_stream_position,source_stream_ref,short_name_folded,value,updated_at) \
                 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)",
            )
            .bind::<Text, _>(event.realm_id.as_str())
            .bind::<Text, _>(id.as_str())
            .bind::<Text, _>(event.event_id.as_str())
            .bind::<Text, _>(commit.commit_id.as_str())
            .bind::<BigInt, _>(position)
            .bind::<Jsonb, _>(serde_json::to_value(&commit.stream_ref).map_err(PersistenceError::database)?)
            .bind::<Text, _>(short_name)
            .bind::<Jsonb, _>(value)
            .bind::<Timestamptz, _>(commit.committed_at)
            .execute(&mut *conn)
            .await
            .map_err(PersistenceError::database)?;
        }
        EventKind::CircleMemberState => {
            let ScopeRef::Circle { circle_id, .. } = &event.scope_ref else {
                return Err(schema("Circle membership scope invalid"));
            };
            let member: ActorId = serde_json::from_value(
                event
                    .payload
                    .get("member_id")
                    .cloned()
                    .ok_or_else(|| schema("member_id missing"))?,
            )
            .map_err(|_| schema("member_id invalid"))?;
            let membership = event
                .payload
                .get("membership")
                .and_then(Value::as_str)
                .ok_or_else(|| schema("membership missing"))?;
            let effective_at = event
                .payload
                .get("effective_at")
                .cloned()
                .unwrap_or_else(|| {
                    json!(arkret_canonical::format_timestamp_canonical(
                        event.created_at
                    ))
                });
            let value = json!({"membership": membership, "effective_at": effective_at});
            let changed = sql_query(
                "INSERT INTO circle_member_state_current_results \
                 (realm_id,circle_id,member_id,membership,current_commit_id,current_stream_position,source_stream_ref,value,updated_at) \
                 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) \
                 ON CONFLICT(circle_id,member_id) DO UPDATE SET \
                 membership=EXCLUDED.membership,current_commit_id=EXCLUDED.current_commit_id, \
                 current_stream_position=EXCLUDED.current_stream_position,source_stream_ref=EXCLUDED.source_stream_ref, \
                 value=EXCLUDED.value,updated_at=EXCLUDED.updated_at \
                 WHERE circle_member_state_current_results.realm_id=EXCLUDED.realm_id \
                   AND circle_member_state_current_results.source_stream_ref=EXCLUDED.source_stream_ref \
                   AND (circle_member_state_current_results.current_stream_position<EXCLUDED.current_stream_position \
                     OR (circle_member_state_current_results.current_stream_position=EXCLUDED.current_stream_position \
                       AND circle_member_state_current_results.current_commit_id=EXCLUDED.current_commit_id \
                       AND circle_member_state_current_results.membership=EXCLUDED.membership \
                       AND circle_member_state_current_results.value=EXCLUDED.value))",
            )
            .bind::<Text, _>(event.realm_id.as_str())
            .bind::<Text, _>(circle_id.as_str())
            .bind::<Text, _>(member.to_string())
            .bind::<Text, _>(membership)
            .bind::<Text, _>(commit.commit_id.as_str())
            .bind::<BigInt, _>(position)
            .bind::<Jsonb, _>(serde_json::to_value(&commit.stream_ref).map_err(PersistenceError::database)?)
            .bind::<Jsonb, _>(value)
            .bind::<Timestamptz, _>(commit.committed_at)
            .execute(&mut *conn)
            .await
            .map_err(PersistenceError::database)?;
            if changed != 1 {
                return Err(conflict(
                    ConflictCode::FailedPrecondition,
                    "Circle membership current revision or value differs",
                ));
            }
        }
        _ => {}
    }
    Ok(())
}
