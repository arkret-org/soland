//! Registered event-derived Strand current result at the RealmCommit cut.

use diesel::OptionalExtension as _;
use diesel::sql_types::{BigInt, Bool, Jsonb, Text, Timestamptz};
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

#[derive(diesel::QueryableByName)]
struct PresentRow {
    #[diesel(sql_type = Bool)]
    present: bool,
}

fn reject(detail: impl Into<String>) -> PersistenceError {
    PersistenceError::Conflict(format!("failed_precondition: {}", detail.into()))
}

fn reject_lifecycle(code: soland_storage::ConflictCode, detail: &str) -> PersistenceError {
    PersistenceError::Conflict(format!("{}: {detail}", code.as_str()))
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
    commit_strand_create_current_result_with_authority_in_connection(conn, event, commit, true)
        .await
}

/// Only the validated four-Event Direct Conversation founding transaction may
/// write its main Strand without an earlier capability basis. The fourth
/// Event shares one atomic acceptance cut with the two founding joins.
pub(crate) async fn commit_direct_conversation_founding_strand_in_connection(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    commit: &arkret_wire::RealmCommit,
) -> PersistenceResult<()> {
    if event.kind != arkret_wire::EventKind::StrandCreate {
        return Err(reject(
            "Direct Conversation founding has no main Strand Event",
        ));
    }
    commit_strand_create_current_result_with_authority_in_connection(conn, event, commit, false)
        .await
}

async fn commit_strand_create_current_result_with_authority_in_connection(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    commit: &arkret_wire::RealmCommit,
    require_existing_authority: bool,
) -> PersistenceResult<()> {
    if event.kind != arkret_wire::EventKind::StrandCreate {
        return Ok(());
    }
    let (strand_id, value) = strand_create_current_value(event)?;
    let expected_stream = match (
        &event.scope_ref,
        value.get("scope_circle_id").and_then(Value::as_str),
    ) {
        (arkret_wire::ScopeRef::Realm { realm_id }, None) if realm_id == &event.realm_id => {
            arkret_wire::CommitStreamRef::Realm {
                realm_id: realm_id.clone(),
            }
        }
        (
            arkret_wire::ScopeRef::Circle {
                realm_id,
                circle_id,
            },
            Some(authored_circle),
        ) if realm_id == &event.realm_id && circle_id.as_str() == authored_circle => {
            arkret_wire::CommitStreamRef::Circle {
                realm_id: realm_id.clone(),
                circle_id: circle_id.clone(),
            }
        }
        _ => {
            return Err(reject(
                "Strand create signed scope differs from object scope",
            ));
        }
    };
    if commit.event_ref != event.event_id || commit.stream_ref != expected_stream {
        return Err(reject("Strand create has no exact source stream"));
    }
    if require_existing_authority {
        crate::realm_authorization_cut::authorize_capability_gated_event_in_connection(
            conn,
            event,
            commit.committed_at,
        )
        .await?;
    }
    if matches!(event.scope_ref, arkret_wire::ScopeRef::Circle { .. }) {
        crate::circle_current_results::require_active_author_in_connection(conn, event, commit)
            .await?;
        // A newly activated Circle requires an encrypted object carrier with
        // its own epoch proof. This bounded Strand-create writer admits only
        // the pre-Genesis plaintext Circle branch, and cannot leak authored
        // metadata into an MLS-backed scope.
        let scope_key = String::from_utf8(
            arkret_canonical::canonical_json_bytes(&event.scope_ref)
                .map_err(PersistenceError::database)?,
        )
        .map_err(PersistenceError::database)?;
        let activated = diesel::sql_query(
            "SELECT EXISTS (SELECT 1 FROM mls_group_current_results WHERE scope_key=$1) AS present",
        )
        .bind::<Text, _>(scope_key)
        .get_result::<PresentRow>(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
        if activated.present {
            return Err(reject(
                "Circle Strand create needs an admitted MLS object carrier",
            ));
        }
        if value
            .get("encrypted_content")
            .is_some_and(|value| !value.is_null())
            || value
                .get("encrypted_metadata")
                .is_some_and(|value| !value.is_null())
        {
            return Err(reject(
                "pre-Genesis Circle Strand cannot carry MLS ciphertext",
            ));
        }
    }
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

/// Commit the lifecycle and progress axes from their registered payloads.
/// Authority admission and verified replica folding share this value writer.
pub(crate) async fn commit_strand_transition_in_connection(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    commit: &arkret_wire::RealmCommit,
    authorize: bool,
) -> PersistenceResult<()> {
    use arkret_wire::EventKind;
    if !matches!(
        event.kind,
        EventKind::StrandArchive | EventKind::StrandRestore | EventKind::StrandStageSet
    ) {
        return Ok(());
    }
    arkret_schema::validate_event_for_submit(event)
        .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
    let realm_scope = arkret_wire::ScopeRef::Realm {
        realm_id: event.realm_id.clone(),
    };
    let realm_stream = arkret_wire::CommitStreamRef::Realm {
        realm_id: event.realm_id.clone(),
    };
    if event.scope_ref != realm_scope || commit.stream_ref != realm_stream {
        return Err(reject(
            "Strand transition requires a Realm-scope authority cut",
        ));
    }
    let payload = serde_json::to_value(&event.payload).map_err(PersistenceError::database)?;
    let (target, stage) = if event.kind == EventKind::StrandStageSet {
        let body: arkret_models_collaboration::events_payloads::strand::StrandStageSetPayload =
            serde_json::from_value(payload).map_err(PersistenceError::database)?;
        (body.strand_id.clone(), Some(body))
    } else {
        let body: arkret_models_collaboration::governance::realm_lifecycle::ObjectLifecyclePayload =
            serde_json::from_value(payload).map_err(PersistenceError::database)?;
        let target = arkret_wire::StrandId::new(body.target_ref.as_str())
            .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
        (target, None)
    };
    if authorize {
        crate::realm_authorization_cut::authorize_capability_gated_event_in_connection(
            conn,
            event,
            commit.committed_at,
        )
        .await?;
    }
    let current_sql = if authorize {
        "SELECT s.realm_id,s.current_commit_id,s.current_stream_position,s.value \
         FROM strand_current_results s JOIN realm_commits c ON c.commit_id=s.current_commit_id \
         WHERE s.realm_id=$1 AND s.strand_id=$2 AND c.realm_id=s.realm_id \
           AND c.stream_position=s.current_stream_position AND c.stream_ref->>'kind'='realm' \
           AND c.stream_ref->>'realm_id'=s.realm_id FOR UPDATE OF s"
    } else {
        // A verified snapshot can install current below its readable floor,
        // without replicating that row's historical Event/Commit. The replica
        // verifier, snapshot signature and immediately following stream head
        // prove this baseline; no local historical cover is required here.
        "SELECT realm_id,current_commit_id,current_stream_position,value \
         FROM strand_current_results WHERE realm_id=$1 AND strand_id=$2 FOR UPDATE"
    };
    let row = diesel::sql_query(current_sql)
        .bind::<Text, _>(event.realm_id.as_str())
        .bind::<Text, _>(target.as_str())
        .get_result::<StrandCurrentRow>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?
        .ok_or_else(|| reject("Strand transition target has no confirmed current value"))?;
    let position = i64::try_from(commit.stream_position).map_err(PersistenceError::database)?;
    if row.current_stream_position >= position || row.current_commit_id == commit.commit_id.as_str()
    {
        return Err(reject(
            "Strand current revision does not precede transition",
        ));
    }
    let current: arkret_models_collaboration::objects::strand::Strand =
        serde_json::from_value(row.value.clone()).map_err(PersistenceError::database)?;
    if current.id.as_ref() != Some(&target)
        || current.realm_id != event.realm_id
        || current.scope_circle_id.is_some()
    {
        return Err(reject("Strand transition target identity or scope differs"));
    }
    if current.state == Some(arkret_wire::ObjectState::Redacted) {
        return Err(reject_lifecycle(
            soland_storage::ConflictCode::StrandAlreadyTerminal,
            "Strand transition target is redacted",
        ));
    }
    let mut post = row.value.clone();
    let time = Value::String(arkret_canonical::format_timestamp_canonical(
        event.created_at,
    ));
    let lifecycle_time = Value::String(arkret_canonical::format_timestamp_canonical(
        event.created_at.max(commit.committed_at),
    ));
    if let Some(body) = stage {
        if current.state != Some(arkret_wire::ObjectState::Active) {
            return Err(reject_lifecycle(
                soland_storage::ConflictCode::StrandNotActive,
                "Strand stage target is not active",
            ));
        }
        if row.value.get("stage").and_then(Value::as_str) != body.expected_stage.as_deref() {
            return Err(reject("Strand expected_stage differs from current stage"));
        }
        if row.value.get("stage").and_then(Value::as_str) != Some(body.stage.as_str()) {
            post["stage"] = Value::String(body.stage);
            post["stage_changed_at"] = time.clone();
            post["updated_by"] =
                serde_json::to_value(&event.actor_id).map_err(PersistenceError::database)?;
            post["updated_at"] = lifecycle_time.clone();
        }
    } else {
        let (expected, next, reason) = if event.kind == EventKind::StrandArchive {
            (
                arkret_wire::ObjectState::Active,
                "archived",
                soland_storage::ConflictCode::StrandNotActive,
            )
        } else {
            (
                arkret_wire::ObjectState::Archived,
                "active",
                soland_storage::ConflictCode::StrandNotArchived,
            )
        };
        if current.state != Some(expected) {
            return Err(reject_lifecycle(
                reason,
                "Strand lifecycle source state differs",
            ));
        }
        post["state"] = Value::String(next.to_owned());
        post["state_changed_at"] = lifecycle_time.clone();
        post["updated_by"] =
            serde_json::to_value(&event.actor_id).map_err(PersistenceError::database)?;
        post["updated_at"] = lifecycle_time;
    }
    let _: arkret_models_collaboration::objects::strand::Strand =
        serde_json::from_value(post.clone()).map_err(PersistenceError::database)?;
    let changed = diesel::sql_query("UPDATE strand_current_results SET current_commit_id=$3,current_stream_position=$4,value=$5,updated_at=$6 WHERE realm_id=$1 AND strand_id=$2 AND current_commit_id=$7")
        .bind::<Text,_>(event.realm_id.as_str()).bind::<Text,_>(target.as_str())
        .bind::<Text,_>(commit.commit_id.as_str()).bind::<BigInt,_>(position).bind::<Jsonb,_>(&post)
        .bind::<Timestamptz,_>(commit.committed_at).bind::<Text,_>(&row.current_commit_id)
        .execute(conn).await.map_err(PersistenceError::database)?;
    if changed != 1 {
        return Err(reject("Strand current changed before transition"));
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
        // The narrative paths are distinct from track configuration.
        // scope_circle_id is listed by the generic projection vocabulary but
        // strand-and-message.md §5 explicitly forbids rebinding it.
        let root = path.split('.').next().unwrap_or(path);
        if !matches!(
            root,
            "schema_refs"
                | "agent_participation"
                | "metadata"
                | "encrypted_metadata"
                | "topic"
                | "content"
                | "encrypted_content"
        ) && !matches!(
            path.as_str(),
            "tracks.synthesis.content" | "tracks.synthesis.encrypted_content"
        ) || arkret_wire::patch::reducer_managed_patch_reason("strand", path).is_some()
            || arkret_wire::forbidden_wire::forbidden_wire_path_hard_reject(
                "strand_patch_payload",
                path,
            )
        {
            return Err(PersistenceError::SchemaViolation(format!(
                "Strand update patch path is forbidden: {path}"
            )));
        }
    }
    let (row, current, position) = lock_active_patch_target(conn, event, commit, &payload).await?;
    if payload.patch.iter().any(|(path, _)| path == "topic") {
        if payload.expected_state_digest.is_none()
            || crate::direct_conversation_admission::direct_conversation_realm_in_connection(
                conn,
                &event.realm_id,
            )
            .await?
            .is_none()
            || current.scope_circle_id.is_some()
            || !arkret_models_collaboration::objects::profiles::resolve_primary_track(
                &current.tracks,
                None,
            )
            .ok()
            .flatten()
            .is_some_and(|(name, _)| name == "discussion")
        {
            return Err(reject(
                "Topic classification requires a Direct Conversation Chat and exact digest CAS",
            ));
        }
        for (_, op) in payload
            .patch
            .iter()
            .filter(|(path, _)| path.as_str() == "topic")
        {
            match op {
                arkret_wire::patch::PatchOp::Explicit {
                    op: arkret_wire::patch::PatchOpKind::Set,
                    value: Some(value),
                } => {
                    let topic: arkret_models_collaboration::objects::strand::StrandTopic =
                        serde_json::from_value(value.clone())
                            .map_err(PersistenceError::database)?;
                    let present = diesel::sql_query("SELECT EXISTS (SELECT 1 FROM space_current_results s JOIN space_parent_current_results p ON p.space_id=s.space_id AND p.realm_id=s.realm_id WHERE s.realm_id=$1 AND s.space_id=$2 AND s.value->>'kind'='topic' AND s.value->>'state'='active' AND NOT (s.value ? 'scope_circle_id') AND p.value->'parent_space_id'='null'::jsonb) AS present")
                        .bind::<Text,_>(event.realm_id.as_str()).bind::<Text,_>(topic.space_id.as_str())
                        .get_result::<PresentRow>(&mut *conn).await.map_err(PersistenceError::database)?;
                    if !present.present {
                        return Err(reject(
                            "Topic classification target is not an active same-Realm root Topic",
                        ));
                    }
                }
                arkret_wire::patch::PatchOp::Explicit {
                    op: arkret_wire::patch::PatchOpKind::Unset,
                    value: None,
                } if current.topic.is_some() => {}
                _ => {
                    return Err(reject(
                        "Topic classification requires a whole explicit set or existing-value unset",
                    ));
                }
            }
        }
    }
    let writes_synthesis = payload.patch.iter().any(|(path, _)| {
        matches!(
            path.as_str(),
            "tracks.synthesis.content" | "tracks.synthesis.encrypted_content"
        )
    });
    if writes_synthesis
        && !current
            .tracks
            .get("synthesis")
            .is_some_and(|track| track.enabled.unwrap_or(true))
    {
        return Err(PersistenceError::Conflict(
            "track_disabled: Synthesis content requires an existing active track".to_owned(),
        ));
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
    let mut retained_tracks = next.tracks.clone();
    if let Some(track) = retained_tracks.get_mut("synthesis") {
        if let Some(previous) = current.tracks.get("synthesis") {
            track.content = previous.content.clone();
            track.encrypted_content = previous.encrypted_content.clone();
        }
    }
    if writes_synthesis
        && [&current, &next].into_iter().any(|strand| {
            !strand
                .tracks
                .get("synthesis")
                .is_some_and(|track| track.enabled.unwrap_or(true))
        })
    {
        return Err(PersistenceError::Conflict(
            "track_disabled: Synthesis content requires an existing active track".to_owned(),
        ));
    }
    if next.id != current.id
        || next.realm_id != current.realm_id
        || next.scope_circle_id != current.scope_circle_id
        || retained_tracks != current.tracks
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
    store_patched_strand(conn, event, commit, &payload, &row, position, &post).await
}

/// Lock the Strand a patch targets at the accepting cut and require it to be
/// the Active, same-Realm, same-scope object the signed payload names, with
/// the optional `expected_state_digest` over its exact current value.
async fn lock_active_patch_target(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    commit: &arkret_wire::RealmCommit,
    payload: &arkret_models_collaboration::events_payloads::strand::StrandPatchPayload,
) -> PersistenceResult<(
    StrandCurrentRow,
    arkret_models_collaboration::objects::strand::Strand,
    i64,
)> {
    let row = diesel::sql_query(
        "SELECT realm_id,current_commit_id,current_stream_position,value \
         FROM strand_current_results WHERE strand_id=$1 FOR UPDATE",
    )
    .bind::<Text, _>(payload.target_ref.as_str())
    .get_result::<StrandCurrentRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?
    .ok_or_else(|| reject("Strand patch target is absent"))?;
    if row.realm_id != event.realm_id.as_str() {
        return Err(reject("Strand patch target belongs to another Realm"));
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
    if current.id.as_ref() != Some(&payload.target_ref) || current.realm_id != event.realm_id {
        return Err(reject("Strand patch target identity or Realm differs"));
    }
    match current.state {
        Some(arkret_wire::ObjectState::Active) => {}
        Some(arkret_wire::ObjectState::Redacted) => {
            return Err(reject_lifecycle(
                soland_storage::ConflictCode::StrandAlreadyTerminal,
                "Strand patch target is redacted",
            ));
        }
        _ => {
            return Err(reject_lifecycle(
                soland_storage::ConflictCode::StrandNotActive,
                "Strand patch target is not active",
            ));
        }
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
        return Err(reject("Strand patch Event scope differs from target scope"));
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
    Ok((row, current, position))
}

/// Replace the target's current value with the validated post-patch value.
async fn store_patched_strand(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    commit: &arkret_wire::RealmCommit,
    payload: &arkret_models_collaboration::events_payloads::strand::StrandPatchPayload,
    row: &StrandCurrentRow,
    position: i64,
    post: &Value,
) -> PersistenceResult<()> {
    let updated = diesel::sql_query(
        "UPDATE strand_current_results SET current_commit_id=$3,current_stream_position=$4,\
         value=$5,updated_at=$6 WHERE realm_id=$1 AND strand_id=$2 AND current_commit_id=$7",
    )
    .bind::<Text, _>(event.realm_id.as_str())
    .bind::<Text, _>(payload.target_ref.as_str())
    .bind::<Text, _>(commit.commit_id.as_str())
    .bind::<BigInt, _>(position)
    .bind::<Jsonb, _>(post)
    .bind::<Timestamptz, _>(commit.committed_at)
    .bind::<Text, _>(&row.current_commit_id)
    .execute(conn)
    .await
    .map_err(PersistenceError::database)?;
    if updated != 1 {
        return Err(reject("Strand current changed before patch"));
    }
    Ok(())
}

/// Admit an `ak.strand.tracks.update` with the authorization facts and target
/// value frozen in the accepting transaction.
pub(crate) async fn commit_strand_tracks_update_authority_current_result_in_connection(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    commit: &arkret_wire::RealmCommit,
) -> PersistenceResult<()> {
    if event.kind != arkret_wire::EventKind::StrandTracksUpdate {
        return Ok(());
    }
    crate::realm_authorization_cut::authorize_capability_gated_event_in_connection(
        conn,
        event,
        commit.committed_at,
    )
    .await?;
    commit_strand_tracks_update_current_result_in_connection(conn, event, commit).await
}

/// Advance the registered Strand value for `ak.strand.tracks.update`.
///
/// event-kind-registry.json projects the patch with `allowed_paths:
/// ["tracks"]` and retains every other member; strand-and-message.md section
/// 4.8 requires registered track names and an uninterrupted primary track, and
/// section 4.7 keeps track content on the content-carrying Events.
pub(crate) async fn commit_strand_tracks_update_current_result_in_connection(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    commit: &arkret_wire::RealmCommit,
) -> PersistenceResult<()> {
    if event.kind != arkret_wire::EventKind::StrandTracksUpdate {
        return Ok(());
    }
    arkret_schema::validate_event_for_submit(event)
        .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
    if commit.stream_ref
        != (arkret_wire::CommitStreamRef::Realm {
            realm_id: event.realm_id.clone(),
        })
    {
        return Err(reject(
            "Strand tracks update requires the Realm commit stream",
        ));
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
        if path.split('.').next() != Some("tracks")
            || arkret_wire::patch::reducer_managed_patch_reason("strand", path).is_some()
            || arkret_wire::forbidden_wire::forbidden_wire_path_hard_reject(
                "strand_patch_payload",
                path,
            )
        {
            return Err(PersistenceError::SchemaViolation(format!(
                "Strand tracks update patch path is forbidden: {path}"
            )));
        }
    }
    let (row, current, position) = lock_active_patch_target(conn, event, commit, &payload).await?;
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
    let retained = |value: &Value| {
        let mut members = value.as_object().cloned().unwrap_or_default();
        for derived in ["tracks", "updated_by", "updated_at"] {
            members.remove(derived);
        }
        members
    };
    if retained(&post) != retained(&row.value) {
        return Err(PersistenceError::SchemaViolation(
            "Strand tracks update changed a retained member".to_owned(),
        ));
    }
    let next: arkret_models_collaboration::objects::strand::Strand =
        serde_json::from_value(post.clone()).map_err(|error| {
            PersistenceError::SchemaViolation(format!(
                "Strand post-patch value is invalid: {error}"
            ))
        })?;
    next.validate_content_surfaces()
        .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
    let track_content =
        |track: Option<&arkret_models_collaboration::objects::profiles::StrandTrack>| {
            track.map_or((Value::Null, Value::Null), |track| {
                (
                    serde_json::to_value(&track.content).unwrap_or(Value::Null),
                    serde_json::to_value(&track.encrypted_content).unwrap_or(Value::Null),
                )
            })
        };
    if current
        .tracks
        .keys()
        .chain(next.tracks.keys())
        .any(|name| track_content(current.tracks.get(name)) != track_content(next.tracks.get(name)))
    {
        return Err(PersistenceError::SchemaViolation(
            "Strand tracks update cannot change track content".to_owned(),
        ));
    }
    arkret_models_collaboration::objects::profiles::validate_primary_track_transition(
        &current.tracks,
        &next.tracks,
        None,
    )
    .map_err(|error| {
        let detail = error.to_string();
        if detail.contains("track_disabled") {
            PersistenceError::Conflict(format!("track_disabled: {detail}"))
        } else {
            reject(format!("Strand primary track is required: {detail}"))
        }
    })?;
    store_patched_strand(conn, event, commit, &payload, &row, position, &post).await
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
