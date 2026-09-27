//! Registered event-derived Strand current result at the RealmCommit cut.

use diesel::OptionalExtension as _;
use diesel::sql_types::{BigInt, Jsonb, Text, Timestamptz};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use serde_json::Value;
use soland_storage::{PersistenceError, PersistenceResult};

#[derive(diesel::QueryableByName)]
struct StrandCurrentRow {
    #[diesel(sql_type = Text)]
    realm_id: String,
    #[diesel(sql_type = Text)]
    current_commit_id: String,
    #[diesel(sql_type = BigInt)]
    current_stream_position: i64,
    #[diesel(sql_type = Jsonb)]
    value: Value,
}

fn reject(detail: impl Into<String>) -> PersistenceError {
    PersistenceError::Conflict(format!("failed_precondition: {}", detail.into()))
}

/// The registered `strand` current value an accepted `ak.strand.create`
/// derives: the authored initial object with its Event-derived id and the
/// `active` state. Every Station that projects the Event derives it here.
pub(crate) fn strand_create_current_value(
    event: &arkret_wire::Event,
) -> PersistenceResult<(arkret_wire::StrandId, serde_json::Value)> {
    arkret_schema::validate_event_for_submit(event)
        .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
    let payload: arkret_models_collaboration::events_payloads::StrandCreatePayload =
        serde_json::from_value(
            serde_json::to_value(&event.payload).map_err(PersistenceError::database)?,
        )
        .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
    let object = payload.object;
    let authored = serde_json::to_value(&object).map_err(PersistenceError::database)?;
    if authored.get("state").is_some_and(|state| state != "active") {
        return Err(PersistenceError::SchemaViolation(
            "Strand create must begin active".to_owned(),
        ));
    }
    if object.id.is_some()
        || object.realm_id != event.realm_id
        || object.created_by != event.actor_id
        || object.created_at != event.created_at
        || object.stage.is_some()
        || object.stage_changed_at.is_some()
        || object.updated_by.is_some()
        || object.updated_at.is_some()
        || object.state_changed_at.is_some()
    {
        return Err(PersistenceError::SchemaViolation(
            "Strand create contains a forged or non-initial derived member".to_owned(),
        ));
    }
    let strand_id = arkret_wire::StrandId::from_event_id(&event.event_id);
    let mut value = authored;
    let value_object = value.as_object_mut().ok_or_else(|| {
        PersistenceError::SchemaViolation("Strand create object is not a JSON object".to_owned())
    })?;
    value_object.insert(
        "id".to_owned(),
        serde_json::to_value(&strand_id).map_err(PersistenceError::database)?,
    );
    value_object.insert("state".to_owned(), serde_json::json!("active"));
    Ok((strand_id, value))
}

pub(crate) async fn commit_strand_create_current_result_in_connection(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    commit: &arkret_wire::RealmCommit,
) -> PersistenceResult<()> {
    if event.kind != arkret_wire::EventKind::StrandCreate {
        return Ok(());
    }
    let (strand_id, value) = strand_create_current_value(event)?;
    let stream_position = i64::try_from(commit.stream_position).map_err(|_| {
        PersistenceError::SchemaViolation("Strand stream position exceeds BIGINT".to_owned())
    })?;
    let inserted = diesel::sql_query(
        "INSERT INTO strand_current_results \
         (realm_id,strand_id,current_commit_id,current_stream_position,value,updated_at) \
         VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING",
    )
    .bind::<Text, _>(event.realm_id.as_str())
    .bind::<Text, _>(strand_id.as_str())
    .bind::<Text, _>(commit.commit_id.as_str())
    .bind::<BigInt, _>(stream_position)
    .bind::<Jsonb, _>(&value)
    .bind::<Timestamptz, _>(commit.committed_at)
    .execute(conn)
    .await
    .map_err(PersistenceError::database)?;
    if inserted != 1 {
        return Err(PersistenceError::Conflict(
            "Strand current result already exists".to_owned(),
        ));
    }
    Ok(())
}

/// Admit a Strand patch with the authorization facts and target value frozen
/// in the accepting transaction. Replica folds call the value writer below
/// after verification and never re-adjudicate the authority's permissions.
pub(crate) async fn commit_strand_update_authority_current_result_in_connection(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    commit: &arkret_wire::RealmCommit,
) -> PersistenceResult<()> {
    if event.kind != arkret_wire::EventKind::StrandUpdate {
        return Ok(());
    }
    crate::realm_authorization_cut::authorize_capability_gated_event_in_connection(
        conn,
        event,
        commit.committed_at,
    )
    .await?;
    commit_strand_update_current_result_in_connection(conn, event, commit).await
}

/// Advance the registered Strand value at the same authority cut as its Event.
/// The Realm authority row lock held by the UOW serializes all writers; the
/// target row lock also freezes the exact value used by the optional digest.
pub(crate) async fn commit_strand_update_current_result_in_connection(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    commit: &arkret_wire::RealmCommit,
) -> PersistenceResult<()> {
    if event.kind != arkret_wire::EventKind::StrandUpdate {
        return Ok(());
    }
    arkret_schema::validate_event_for_submit(event)
        .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
    if commit.stream_ref
        != (arkret_wire::CommitStreamRef::Realm {
            realm_id: event.realm_id.clone(),
        })
    {
        return Err(reject("Strand update requires the Realm commit stream"));
    }
    let payload: arkret_models_collaboration::events_payloads::strand::StrandPatchPayload =
        serde_json::from_value(
            serde_json::to_value(&event.payload).map_err(PersistenceError::database)?,
        )
        .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
    payload
        .patch
        .validate()
        .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
    for (path, _) in payload.patch.iter() {
        // event-kind-registry.json: ak.strand.update owns these six roots.
        // scope_circle_id is listed by the generic projection vocabulary but
        // strand-and-message.md §5 explicitly forbids rebinding it.
        let root = path.split('.').next().unwrap_or(path);
        if !matches!(
            root,
            "schema_refs"
                | "agent_participation"
                | "metadata"
                | "encrypted_metadata"
                | "content"
                | "encrypted_content"
        ) || arkret_wire::patch::reducer_managed_patch_reason("strand", path).is_some()
            || arkret_wire::forbidden_wire::forbidden_wire_path_hard_reject(
                "strand_update_payload",
                path,
            )
        {
            return Err(PersistenceError::SchemaViolation(format!(
                "Strand update patch path is forbidden: {path}"
            )));
        }
    }
    let row = diesel::sql_query(
        "SELECT realm_id,current_commit_id,current_stream_position,value \
         FROM strand_current_results WHERE strand_id=$1 FOR UPDATE",
    )
    .bind::<Text, _>(payload.target_ref.as_str())
    .get_result::<StrandCurrentRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?
    .ok_or_else(|| reject("Strand update target is absent"))?;
    if row.realm_id != event.realm_id.as_str() {
        return Err(reject("Strand update target belongs to another Realm"));
    }
    let position = i64::try_from(commit.stream_position)
        .map_err(|_| reject("Strand stream position exceeds BIGINT"))?;
    if row.current_stream_position >= position || row.current_commit_id == commit.commit_id.as_str()
    {
        return Err(reject("Strand current revision does not precede Event"));
    }
    let current: arkret_models_collaboration::objects::strand::Strand =
        serde_json::from_value(row.value.clone()).map_err(|error| {
            PersistenceError::Internal(format!("stored Strand current value is invalid: {error}"))
        })?;
    if current.id.as_ref() != Some(&payload.target_ref)
        || current.realm_id != event.realm_id
        || current.state != Some(arkret_wire::ObjectState::Active)
    {
        return Err(reject(
            "Strand update target is not an active Strand in this Realm",
        ));
    }
    let expected_scope = match current.scope_circle_id.as_ref() {
        Some(circle_id) => arkret_wire::ScopeRef::Circle {
            realm_id: event.realm_id.clone(),
            circle_id: circle_id.clone(),
        },
        None => arkret_wire::ScopeRef::Realm {
            realm_id: event.realm_id.clone(),
        },
    };
    if event.scope_ref != expected_scope {
        return Err(reject(
            "Strand update Event scope differs from target scope",
        ));
    }
    if let Some(expected) = payload.expected_state_digest.as_ref() {
        let actual = arkret_wire::Hash::new(arkret_canonical::sha256_digest(
            arkret_canonical::canonical_json_bytes(&row.value)
                .map_err(|error| PersistenceError::Internal(error.to_string()))?,
        ))
        .map_err(|error| PersistenceError::Internal(error.to_string()))?;
        if expected != &actual {
            return Err(reject(
                "Strand expected_state_digest does not match current value",
            ));
        }
    }
    let mut post = payload
        .patch
        .apply_for_typed_target(&row.value, payload.target_ref.as_str())
        .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
    let object = post.as_object_mut().ok_or_else(|| {
        PersistenceError::SchemaViolation("Strand patch did not produce an object".to_owned())
    })?;
    object.insert(
        "updated_by".to_owned(),
        serde_json::to_value(&event.actor_id).map_err(PersistenceError::database)?,
    );
    object.insert(
        "updated_at".to_owned(),
        Value::String(arkret_canonical::format_timestamp_canonical(
            event.created_at,
        )),
    );
    if arkret_wire::forbidden_wire::forbidden_wire_violation(
        "materialized_object",
        "strand.schema.json",
        &post,
    )
    .is_some()
    {
        return Err(PersistenceError::SchemaViolation(
            "Strand post-patch value contains a forbidden field".to_owned(),
        ));
    }
    let next: arkret_models_collaboration::objects::strand::Strand =
        serde_json::from_value(post.clone()).map_err(|error| {
            PersistenceError::SchemaViolation(format!(
                "Strand post-patch value is invalid: {error}"
            ))
        })?;
    if next.id != current.id
        || next.realm_id != current.realm_id
        || next.scope_circle_id != current.scope_circle_id
        || next.tracks != current.tracks
        || next.state != current.state
        || next.state_changed_at != current.state_changed_at
        || next.stage != current.stage
        || next.stage_changed_at != current.stage_changed_at
        || next.created_by != current.created_by
        || next.created_at != current.created_at
        || next.updated_by.as_ref() != Some(&event.actor_id)
        || next.updated_at != Some(event.created_at)
    {
        return Err(PersistenceError::SchemaViolation(
            "Strand patch changed a retained or derived member".to_owned(),
        ));
    }
    next.validate_content_surfaces()
        .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
    validate_calendar_profile(&next)?;
    let updated = diesel::sql_query(
        "UPDATE strand_current_results SET current_commit_id=$3,current_stream_position=$4,\
         value=$5,updated_at=$6 WHERE realm_id=$1 AND strand_id=$2 AND current_commit_id=$7",
    )
    .bind::<Text, _>(event.realm_id.as_str())
    .bind::<Text, _>(payload.target_ref.as_str())
    .bind::<Text, _>(commit.commit_id.as_str())
    .bind::<BigInt, _>(position)
    .bind::<Jsonb, _>(&post)
    .bind::<Timestamptz, _>(commit.committed_at)
    .bind::<Text, _>(&row.current_commit_id)
    .execute(conn)
    .await
    .map_err(PersistenceError::database)?;
    if updated != 1 {
        return Err(reject("Strand current changed before update"));
    }
    Ok(())
}

fn validate_calendar_profile(
    strand: &arkret_models_collaboration::objects::strand::Strand,
) -> PersistenceResult<()> {
    if let Some(refs) = strand.schema_refs.as_ref() {
        // v1 registers exactly one Strand profile. A second spelling cannot
        // activate an unregistered namespace or the Strand container schema.
        if refs.len() != 1 || refs[0] != "ak.schema.calendar_event.v1" {
            return Err(PersistenceError::SchemaViolation(
                "Strand schema_refs contains an unregistered or duplicate profile".to_owned(),
            ));
        }
    }
    if strand.metadata.is_some() && strand.encrypted_metadata.is_some() {
        return Err(PersistenceError::SchemaViolation(
            "Strand metadata and encrypted_metadata are mutually exclusive".to_owned(),
        ));
    }
    let fields = strand.metadata.as_ref().map(|metadata| &metadata.fields);
    let calendar = fields.is_some_and(|fields| fields.contains_key("calendar"));
    let schema_ref = strand.schema_refs.as_ref().is_some_and(|refs| {
        refs.iter()
            .any(|reference| reference == "ak.schema.calendar_event.v1")
    });
    if calendar != schema_ref {
        return Err(PersistenceError::SchemaViolation(
            "calendar_activation_mismatch".to_owned(),
        ));
    }
    if let Some(fields) = fields {
        arkret_models_collaboration::objects::productivity::validate_calendar_event_metadata_fields(fields)
            .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
    }
    Ok(())
}
