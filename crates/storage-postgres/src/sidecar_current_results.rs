//! Same-cut Sidecar genesis reservation and durable current. The public
//! ensure route remains closed until create and attach can commit as one unit.

use arkret_models_collaboration::events_payloads::sidecar::SidecarContextAttachPayload;
use arkret_models_collaboration::sidecar_operations::SidecarContextRef;
use arkret_wire::{CommitStreamRef, Event, EventKind, RealmCommit, ScopeRef, SidecarId};
use diesel::sql_types::{BigInt, Jsonb, Text, Timestamptz};
use diesel::{OptionalExtension as _, sql_query};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use serde_json::{Value, json};
use soland_storage::{ConflictCode, PersistenceError, PersistenceResult};

#[derive(diesel::QueryableByName)]
struct ExistingCreate {
    #[diesel(sql_type = Text)]
    create_event_id: String,
}

#[derive(diesel::QueryableByName)]
struct SidecarOwner {
    #[diesel(sql_type = Jsonb)]
    controller_account_id: Value,
    #[diesel(sql_type = Text)]
    create_event_id: String,
    #[diesel(sql_type = Jsonb)]
    value: Value,
}

#[derive(diesel::QueryableByName)]
struct ContextHead {
    #[diesel(sql_type = BigInt)]
    version: i64,
    #[diesel(sql_type = Text)]
    attach_event_id: String,
}

#[derive(diesel::QueryableByName)]
struct SourceValue {
    #[diesel(sql_type = Jsonb)]
    value: Value,
}

fn invalid(detail: &str) -> PersistenceError {
    PersistenceError::SchemaViolation(detail.to_owned())
}

fn denied(detail: &str) -> PersistenceError {
    PersistenceError::Conflict(format!("{}: {detail}", ConflictCode::CapabilityDenied))
}

fn conflict(code: ConflictCode, detail: &str) -> PersistenceError {
    PersistenceError::Conflict(format!("{code}: {detail}"))
}

fn context_digest(context: &SidecarContextRef) -> PersistenceResult<String> {
    arkret_canonical::canonical_sha256(context).map_err(PersistenceError::database)
}

async fn source_value(
    conn: &mut AsyncPgConnection,
    event: &Event,
    context: &SidecarContextRef,
) -> PersistenceResult<Option<Value>> {
    let value = match context {
        SidecarContextRef::Strand { strand_id } => sql_query(
            "SELECT value FROM strand_current_results WHERE realm_id=$1 AND strand_id=$2 FOR SHARE",
        )
        .bind::<Text, _>(event.realm_id.as_str())
        .bind::<Text, _>(strand_id.as_str())
        .get_result::<SourceValue>(conn)
        .await
        .optional(),
        SidecarContextRef::Relation { relation_id } => sql_query(
            "SELECT value FROM relation_current_results \
             WHERE realm_id=$1 AND relation_id=$2 AND state='active' LIMIT 1 FOR SHARE",
        )
        .bind::<Text, _>(event.realm_id.as_str())
        .bind::<Text, _>(relation_id.as_str())
        .get_result::<SourceValue>(conn)
        .await
        .optional(),
    }
    .map_err(PersistenceError::database)?;
    Ok(value.map(|row| row.value))
}

async fn admit_context_attach(
    conn: &mut AsyncPgConnection,
    event: &Event,
    commit: &RealmCommit,
) -> PersistenceResult<()> {
    let payload: SidecarContextAttachPayload = serde_json::from_value(json!(&event.payload))
        .map_err(|_| invalid("Sidecar context payload is invalid"))?;
    payload
        .validate()
        .map_err(|_| invalid("Sidecar context version/predecessor is invalid"))?;
    if event.scope_ref
        != (ScopeRef::Sidecar {
            realm_id: event.realm_id.clone(),
            sidecar_id: payload.sidecar_id.clone(),
        })
        || commit.stream_ref
            != (CommitStreamRef::Sidecar {
                realm_id: event.realm_id.clone(),
                sidecar_id: payload.sidecar_id.clone(),
            })
        || event.executed_by.is_some()
        || event.applet_id.is_some()
    {
        return Err(invalid(
            "Sidecar context needs its native stream and direct actor",
        ));
    }
    let Some(account) = event.actor_id.as_account_id() else {
        return Err(denied(
            "Sidecar context actor is not its controller Account",
        ));
    };
    crate::realm_authorization_cut::lock_realm_authorization_cut(conn, &event.realm_id).await?;
    if crate::member_state_admission::locked_membership(conn, &event.realm_id, &event.actor_id)
        .await?
        != "join"
    {
        return Err(denied("Sidecar controller is not a current Realm member"));
    }
    let owner = sql_query(
        "SELECT controller_account_id,create_event_id,value FROM sidecar_current_results \
         WHERE realm_id=$1 AND sidecar_id=$2 FOR SHARE",
    )
    .bind::<Text, _>(event.realm_id.as_str())
    .bind::<Text, _>(payload.sidecar_id.as_str())
    .get_result::<SidecarOwner>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?
    .ok_or_else(|| denied("Sidecar controller or scope is unavailable"))?;
    if owner.controller_account_id
        != serde_json::to_value(account).map_err(PersistenceError::database)?
        || owner.value["state"] != "active"
    {
        return Err(denied("Sidecar controller or scope is unavailable"));
    }
    let after: Vec<_> = event
        .semantic_refs
        .iter()
        .filter(|reference| reference.role == "after")
        .collect();
    if after.len() != 1 || !after[0].critical || after[0].id != owner.create_event_id {
        return Err(invalid("Sidecar context must cite its exact genesis Event"));
    }
    let source = source_value(conn, event, &payload.source_context_ref)
        .await?
        .ok_or_else(|| {
            conflict(
                ConflictCode::FailedPrecondition,
                "source context is unavailable",
            )
        })?;
    // A Circle-scoped source needs the Circle ACL cut, which this unit does
    // not yet possess. Realm-default sources are visible to joined members.
    if source
        .get("scope_circle_id")
        .is_some_and(|scope| !scope.is_null())
    {
        return Err(conflict(
            ConflictCode::UnsupportedFeature,
            "Circle-scoped Sidecar source needs its scope authorization cut",
        ));
    }
    let digest = context_digest(&payload.source_context_ref)?;
    let head = sql_query(
        "SELECT version,attach_event_id FROM sidecar_context_current_results \
         WHERE sidecar_id=$1 AND context_ref_digest=$2 FOR UPDATE",
    )
    .bind::<Text, _>(payload.sidecar_id.as_str())
    .bind::<Text, _>(&digest)
    .get_result::<ContextHead>(conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?;
    match head {
        None if payload.version == 1 && payload.predecessor_event_ref.is_none() => Ok(()),
        Some(head)
            if i64::try_from(payload.version).ok() == head.version.checked_add(1)
                && payload.predecessor_event_ref.as_ref().map(|id| id.as_str())
                    == Some(head.attach_event_id.as_str()) =>
        {
            Ok(())
        }
        _ => Err(conflict(
            ConflictCode::CasConflict,
            "Sidecar context predecessor or version is stale",
        )),
    }
}

pub(crate) async fn admit_in_connection(
    conn: &mut AsyncPgConnection,
    event: &Event,
    commit: &RealmCommit,
) -> PersistenceResult<()> {
    if event.kind == EventKind::SidecarContextAttach {
        return admit_context_attach(conn, event, commit).await;
    }
    if event.kind != EventKind::SidecarCreate {
        return Ok(());
    }
    if event.scope_ref
        != (ScopeRef::Realm {
            realm_id: event.realm_id.clone(),
        })
        || commit.stream_ref
            != (CommitStreamRef::Realm {
                realm_id: event.realm_id.clone(),
            })
        || !event.payload.is_empty()
        || event.executed_by.is_some()
        || event.applet_id.is_some()
    {
        return Err(invalid(
            "Sidecar genesis needs its empty Realm-stream account Event",
        ));
    }
    let Some(controller) = event.actor_id.as_account_id() else {
        return Err(denied("sidecar_create_denied"));
    };
    crate::realm_authorization_cut::lock_realm_authorization_cut(conn, &event.realm_id).await?;
    if crate::member_state_admission::locked_membership(conn, &event.realm_id, &event.actor_id)
        .await?
        != "join"
    {
        return Err(denied("sidecar_create_denied"));
    }
    let existing = sql_query(
        "SELECT create_event_id FROM sidecar_current_results \
         WHERE realm_id=$1 AND controller_account_id=$2 FOR SHARE",
    )
    .bind::<Text, _>(event.realm_id.as_str())
    .bind::<Jsonb, _>(serde_json::to_value(controller).map_err(PersistenceError::database)?)
    .get_result::<ExistingCreate>(conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?;
    if existing.is_some_and(|row| row.create_event_id != event.event_id.as_str()) {
        return Err(PersistenceError::Conflict(format!(
            "{}: Sidecar singleton already reserved",
            ConflictCode::FailedPrecondition
        )));
    }
    Ok(())
}

pub(crate) async fn commit_in_connection(
    conn: &mut AsyncPgConnection,
    event: &Event,
    commit: &RealmCommit,
) -> PersistenceResult<()> {
    if event.kind == EventKind::SidecarContextAttach {
        let payload: SidecarContextAttachPayload = serde_json::from_value(json!(&event.payload))
            .map_err(|_| invalid("Sidecar context payload is invalid"))?;
        let position = i64::try_from(commit.stream_position)
            .map_err(|_| invalid("Sidecar stream position exceeds storage"))?;
        let version = i64::try_from(payload.version)
            .map_err(|_| invalid("Sidecar context version exceeds storage"))?;
        let digest = context_digest(&payload.source_context_ref)?;
        let context = serde_json::to_value(&payload.source_context_ref)
            .map_err(PersistenceError::database)?;
        let value = serde_json::to_value(&payload).map_err(PersistenceError::database)?;
        let written = sql_query(
            "INSERT INTO sidecar_context_current_results \
             (realm_id,sidecar_id,context_ref_digest,context_ref,version,predecessor_event_ref,attach_event_id,current_commit_id,current_stream_position,source_stream_ref,value,updated_at) \
             VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) \
             ON CONFLICT(sidecar_id,context_ref_digest) DO UPDATE SET \
             version=EXCLUDED.version,predecessor_event_ref=EXCLUDED.predecessor_event_ref, \
             attach_event_id=EXCLUDED.attach_event_id,current_commit_id=EXCLUDED.current_commit_id, \
             current_stream_position=EXCLUDED.current_stream_position,source_stream_ref=EXCLUDED.source_stream_ref, \
             value=EXCLUDED.value,updated_at=EXCLUDED.updated_at \
             WHERE sidecar_context_current_results.version + 1 = EXCLUDED.version \
             AND sidecar_context_current_results.attach_event_id = EXCLUDED.predecessor_event_ref",
        )
        .bind::<Text, _>(event.realm_id.as_str())
        .bind::<Text, _>(payload.sidecar_id.as_str())
        .bind::<Text, _>(digest)
        .bind::<Jsonb, _>(context)
        .bind::<BigInt, _>(version)
        .bind::<diesel::sql_types::Nullable<Text>, _>(payload.predecessor_event_ref.as_ref().map(|id| id.as_str()))
        .bind::<Text, _>(event.event_id.as_str())
        .bind::<Text, _>(commit.commit_id.as_str())
        .bind::<BigInt, _>(position)
        .bind::<Jsonb, _>(serde_json::to_value(&commit.stream_ref).map_err(PersistenceError::database)?)
        .bind::<Jsonb, _>(value)
        .bind::<Timestamptz, _>(commit.committed_at)
        .execute(conn)
        .await
        .map_err(PersistenceError::database)?;
        if written != 1 {
            return Err(conflict(
                ConflictCode::CasConflict,
                "Sidecar context predecessor or version is stale",
            ));
        }
        return Ok(());
    }
    if event.kind != EventKind::SidecarCreate {
        return Ok(());
    }
    let controller = event
        .actor_id
        .as_account_id()
        .ok_or_else(|| denied("sidecar_create_denied"))?;
    let id = SidecarId::from_event_id(&event.event_id);
    let position = i64::try_from(commit.stream_position)
        .map_err(|_| invalid("Sidecar stream position exceeds storage"))?;
    let value: Value = json!({
        "id": id,
        "schema": "ak.schema.agent_sidecar.v1",
        "realm_id": event.realm_id,
        "controller_account_id": controller,
        "state": "active",
        "created_at": arkret_canonical::format_timestamp_canonical(event.created_at),
        "updated_at": arkret_canonical::format_timestamp_canonical(event.created_at),
    });
    sql_query(
        "INSERT INTO sidecar_current_results \
         (realm_id,sidecar_id,controller_account_id,create_event_id,current_commit_id,current_stream_position,source_stream_ref,value,updated_at) \
         VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)",
    )
    .bind::<Text, _>(event.realm_id.as_str())
    .bind::<Text, _>(id.as_str())
    .bind::<Jsonb, _>(serde_json::to_value(controller).map_err(PersistenceError::database)?)
    .bind::<Text, _>(event.event_id.as_str())
    .bind::<Text, _>(commit.commit_id.as_str())
    .bind::<BigInt, _>(position)
    .bind::<Jsonb, _>(serde_json::to_value(&commit.stream_ref).map_err(PersistenceError::database)?)
    .bind::<Jsonb, _>(value)
    .bind::<Timestamptz, _>(commit.committed_at)
    .execute(conn)
    .await
    .map_err(PersistenceError::database)?;
    Ok(())
}
