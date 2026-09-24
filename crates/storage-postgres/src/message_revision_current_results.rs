//! A bounded Message create current writer at the accepting RealmCommit cut.
//!
//! The supported carrier is a root-controller-authored, Realm-scope plain
//! text Message in an active local discussion Strand. Other Message forms
//! require their own source-scope and effect admission and remain closed.

use diesel::OptionalExtension as _;
use diesel::sql_types::{BigInt, Bool, Jsonb, Text, Timestamptz};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use serde_json::Value;
use soland_storage::{PersistenceError, PersistenceResult};

#[derive(diesel::QueryableByName)]
struct RootRow {
    #[diesel(sql_type = Jsonb)]
    controller_actor_id: Value,
    #[diesel(sql_type = Text)]
    authority_event_ref: String,
}

#[derive(diesel::QueryableByName)]
struct StrandRow {
    #[diesel(sql_type = Jsonb)]
    value: Value,
    #[diesel(sql_type = BigInt)]
    current_stream_position: i64,
    #[diesel(sql_type = Text)]
    created_event_id: String,
}

#[derive(diesel::QueryableByName)]
struct CurrentValueRow {
    #[diesel(sql_type = Jsonb)]
    value: Value,
}

#[derive(diesel::QueryableByName)]
struct PresentRow {
    #[diesel(sql_type = Bool)]
    present: bool,
}

fn conflict(detail: &'static str) -> PersistenceError {
    PersistenceError::Conflict(detail.to_owned())
}

fn supported_plain_text(payload: &Value) -> bool {
    let Some(object) = payload.as_object() else {
        return false;
    };
    if object.len() != 3
        || !object.contains_key("strand_id")
        || object.get("track_name") != Some(&Value::String("discussion".to_owned()))
    {
        return false;
    }
    let Some(content) = object.get("content").and_then(Value::as_object) else {
        return false;
    };
    content.len() == 3
        && content.get("kind") == Some(&Value::String("ak.content.text".to_owned()))
        && content.get("format") == Some(&Value::String("plain".to_owned()))
        && content.get("body").is_some_and(Value::is_string)
}

pub(crate) async fn commit_message_create_current_result_in_connection(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    commit: &arkret_wire::RealmCommit,
) -> PersistenceResult<()> {
    if event.kind != arkret_wire::EventKind::MessageCreate {
        return Ok(());
    }
    arkret_schema::validate_event_for_submit(event)
        .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
    if !matches!(&event.scope_ref, arkret_wire::ScopeRef::Realm { realm_id } if realm_id == &event.realm_id)
        || commit.stream_ref
            != (arkret_wire::CommitStreamRef::Realm {
                realm_id: event.realm_id.clone(),
            })
    {
        return Err(conflict("Message create requires the Realm source stream"));
    }
    let ordinary = diesel::sql_query(
        "SELECT EXISTS (SELECT 1 FROM realm_commits c JOIN canonical_events e ON e.pk=c.event_pk \
         WHERE c.realm_id=$1 AND c.stream_position=0 AND e.kind='ak.realm.create' \
           AND e.state='committed' AND e.envelope->'payload'->'object'->>'purpose'='collaboration') AS present",
    )
    .bind::<Text, _>(event.realm_id.as_str())
    .get_result::<PresentRow>(&mut *conn)
    .await
    .map_err(PersistenceError::database)?;
    if !ordinary.present {
        return Err(conflict(
            "Message current writer supports ordinary collaboration Realms only",
        ));
    }
    let payload = serde_json::to_value(&event.payload).map_err(PersistenceError::database)?;
    if !supported_plain_text(&payload) {
        return Err(conflict("Message carrier needs a dedicated authority cut"));
    }
    let typed: arkret_models_collaboration::events_payloads::message::MessageCreatePayload =
        serde_json::from_value(payload.clone())
            .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
    let root = diesel::sql_query(
        "SELECT r.controller_actor_id,r.authority_event_ref FROM realm_authority_root_current_results r \
         JOIN realm_commits c ON c.commit_id=r.current_commit_id \
         WHERE r.realm_id=$1 AND c.realm_id=r.realm_id \
           AND c.stream_position=r.current_stream_position \
           AND c.stream_ref->>'kind'='realm' AND c.stream_ref->>'realm_id'=r.realm_id \
         FOR SHARE OF r",
    )
    .bind::<Text, _>(event.realm_id.as_str())
    .get_result::<RootRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?
    .ok_or_else(|| conflict("Message root authority is unavailable"))?;
    let controller: arkret_wire::ActorId = serde_json::from_value(root.controller_actor_id)
        .map_err(|error| {
            PersistenceError::Internal(format!("stored Realm controller is invalid: {error}"))
        })?;
    if controller != event.actor_id {
        return Err(conflict("Message actor has no same-cut root capability"));
    }
    if event
        .authorization_ref
        .as_ref()
        .is_some_and(|reference| reference.as_str() != root.authority_event_ref.as_str())
    {
        return Err(conflict(
            "Message authorization ref differs from current Realm root",
        ));
    }
    let member = diesel::sql_query(
        "SELECT EXISTS (SELECT 1 FROM member_state_current_results m \
         JOIN realm_commits c ON c.commit_id=m.current_commit_id \
         WHERE m.realm_id=$1 AND m.member_id=$2 AND m.membership='join' \
           AND c.realm_id=m.realm_id AND c.stream_position=m.current_stream_position \
           AND c.stream_ref->>'kind'='realm' AND c.stream_ref->>'realm_id'=m.realm_id) AS present",
    )
    .bind::<Text, _>(event.realm_id.as_str())
    .bind::<Text, _>(event.actor_id.to_string())
    .get_result::<PresentRow>(&mut *conn)
    .await
    .map_err(PersistenceError::database)?;
    if !member.present {
        return Err(conflict("Message actor is not a confirmed Realm member"));
    }
    let realm_closed = diesel::sql_query(
        "SELECT EXISTS (SELECT 1 FROM canonical_events e JOIN realm_commits c ON c.event_pk=e.pk \
         WHERE e.realm_id=$1 AND e.state='committed' AND c.stream_position<$2 \
           AND e.kind IN ('ak.realm.archive','ak.realm.tombstone','ak.realm.destroy')) AS present",
    )
    .bind::<Text, _>(event.realm_id.as_str())
    .bind::<BigInt, _>(
        i64::try_from(commit.stream_position)
            .map_err(|_| conflict("invalid Message stream position"))?,
    )
    .get_result::<PresentRow>(&mut *conn)
    .await
    .map_err(PersistenceError::database)?;
    if realm_closed.present {
        return Err(conflict("Message Realm has a closed lifecycle"));
    }
    let strand = diesel::sql_query(
        "SELECT s.value,s.current_stream_position,e.envelope->>'event_id' AS created_event_id \
         FROM strand_current_results s \
         JOIN realm_commits c ON c.commit_id=s.current_commit_id \
         JOIN canonical_events e ON e.pk=c.event_pk \
         WHERE s.realm_id=$1 AND s.strand_id=$2 \
           AND c.realm_id=s.realm_id AND c.stream_position=s.current_stream_position \
           AND c.stream_ref->>'kind'='realm' AND c.stream_ref->>'realm_id'=s.realm_id \
           AND e.kind='ak.strand.create' AND e.state='committed' \
         FOR SHARE OF s",
    )
    .bind::<Text, _>(event.realm_id.as_str())
    .bind::<Text, _>(typed.strand_id.as_str())
    .get_result::<StrandRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?
    .ok_or_else(|| conflict("Message target Strand is unavailable"))?;
    let created_event_id = arkret_wire::EventId::new(strand.created_event_id).map_err(|error| {
        PersistenceError::Internal(format!(
            "stored Strand creating Event id is invalid: {error}"
        ))
    })?;
    if arkret_wire::StrandId::from_event_id(&created_event_id) != typed.strand_id {
        return Err(conflict(
            "Message target Strand identity has no creating Event",
        ));
    }
    if strand.value.get("state") != Some(&Value::String("active".to_owned()))
        || strand
            .value
            .get("scope_circle_id")
            .is_some_and(|value| !value.is_null())
    {
        return Err(conflict(
            "Message target Strand is not active in the Realm scope",
        ));
    }
    let discussion = strand
        .value
        .pointer("/tracks/discussion")
        .and_then(Value::as_object)
        .ok_or_else(|| conflict("Message discussion track is unavailable"))?;
    if discussion.get("enabled") == Some(&Value::Bool(false)) {
        return Err(conflict("Message discussion track is disabled"));
    }
    // No same-cut lifecycle writer exists yet for later Strand updates. Any
    // later lifecycle in this Realm makes the create row insufficient proof.
    let changed = diesel::sql_query(
        "SELECT EXISTS (SELECT 1 FROM canonical_events e JOIN realm_commits c ON c.event_pk=e.pk \
         WHERE e.realm_id=$1 AND e.state='committed' AND c.stream_position>$2 \
           AND ((e.kind LIKE 'ak.strand.%' AND e.kind<>'ak.strand.create') OR e.kind='ak.redaction')) AS present",
    )
    .bind::<Text, _>(event.realm_id.as_str())
    .bind::<BigInt, _>(strand.current_stream_position)
    .get_result::<PresentRow>(&mut *conn)
    .await
    .map_err(PersistenceError::database)?;
    if changed.present {
        return Err(conflict("Message Strand has an unprojected successor"));
    }
    let plaintext = diesel::sql_query(
        "SELECT b.value FROM realm_bootstrap_current_results b \
         JOIN realm_commits c ON c.commit_id=b.current_commit_id \
         WHERE b.realm_id=$1 AND b.result_family='realm_plaintext_visible_services' \
           AND c.realm_id=b.realm_id AND c.stream_position=b.current_stream_position \
           AND c.stream_ref->>'kind'='realm' AND c.stream_ref->>'realm_id'=b.realm_id",
    )
    .bind::<Text, _>(event.realm_id.as_str())
    .get_result::<CurrentValueRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?
    .ok_or_else(|| conflict("Message plaintext service policy is unavailable"))?;
    let service_id = diesel::sql_query(
        "SELECT service_id AS value FROM realm_authorities WHERE realm_id=$1 FOR SHARE",
    )
    .bind::<Text, _>(event.realm_id.as_str())
    .get_result::<ServiceIdRow>(&mut *conn)
    .await
    .map_err(PersistenceError::database)?;
    let allowed = plaintext
        .value
        .get("services")
        .and_then(Value::as_array)
        .is_some_and(|services| {
            services.iter().any(|service| {
                service.get("service_id").and_then(Value::as_str) == Some(service_id.value.as_str())
                    && service.get("visibility").and_then(Value::as_str)
                        == Some("private_plaintext")
                    && service
                        .get("data_classes")
                        .and_then(Value::as_array)
                        .is_some_and(|classes| {
                            classes.iter().any(|class| class == "message_content")
                        })
                    && service.get("expires_at").is_none_or(|expires| {
                        expires
                            .as_str()
                            .and_then(|time| chrono::DateTime::parse_from_rfc3339(time).ok())
                            .is_some_and(|time| {
                                time.with_timezone(&chrono::Utc) > commit.committed_at
                            })
                    })
            })
        });
    if !allowed {
        return Err(conflict(
            "Message plaintext service is not authorized at this cut",
        ));
    }
    let message_id = arkret_wire::MessageId::from_event_id(&event.event_id);
    let inserted = diesel::sql_query(
        "INSERT INTO message_revision_current_results \
         (realm_id,message_id,current_commit_id,current_stream_position,value,updated_at) \
         VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING",
    )
    .bind::<Text, _>(event.realm_id.as_str())
    .bind::<Text, _>(message_id.as_str())
    .bind::<Text, _>(commit.commit_id.as_str())
    .bind::<BigInt, _>(
        i64::try_from(commit.stream_position)
            .map_err(|_| conflict("invalid Message stream position"))?,
    )
    .bind::<Jsonb, _>(&payload)
    .bind::<Timestamptz, _>(commit.committed_at)
    .execute(conn)
    .await
    .map_err(PersistenceError::database)?;
    if inserted != 1 {
        return Err(conflict("Message revision current result already exists"));
    }
    Ok(())
}

#[derive(diesel::QueryableByName)]
struct ServiceIdRow {
    #[diesel(sql_type = Text)]
    value: String,
}
