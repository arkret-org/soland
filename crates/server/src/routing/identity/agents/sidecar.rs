use arkret_core::models::{
    AgentSidecar, AgentSidecarAccessReadiness, AgentSidecarContextRef,
    AgentSidecarEncryptionProfile, AgentSidecarEnsureOutcome, AgentSidecarEnsureRequestBody,
    AgentSidecarList, AgentSidecarSchema, AgentSidecarState, AgentSidecarView,
    PendingSidecarAccessReconciliationItem, PendingSidecarAccessReconciliationStage,
};
use arkret_core::{NonEmptyString, SidecarId};
use salvo::oapi::extract::QueryParam;
use soland_storage::{AgentSidecarContextRecord, AgentSidecarRecord};

use super::*;

pub(super) const ADDRESSED_AGENT_NOT_ELIGIBLE: &str = "addressed_agent_not_eligible";
pub(super) const CONTROLLER_IN_ADDRESSED_AGENTS: &str = "controller_in_addressed_agents";

const SIDECAR_ENSURE_LOCK_SHARDS: usize = 256;
const SIDECAR_LIST_PAGE_SIZE: usize = 100;

async fn lock_sidecar_ensure(realm_id: &str, controller: &str) -> tokio::sync::OwnedMutexGuard<()> {
    use std::hash::{Hash as _, Hasher as _};
    use std::sync::{Arc, OnceLock};

    static LOCKS: OnceLock<Vec<Arc<tokio::sync::Mutex<()>>>> = OnceLock::new();
    let locks = LOCKS.get_or_init(|| {
        (0..SIDECAR_ENSURE_LOCK_SHARDS)
            .map(|_| Arc::new(tokio::sync::Mutex::new(())))
            .collect()
    });
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    realm_id.hash(&mut hasher);
    controller.hash(&mut hasher);
    let shard = (hasher.finish() as usize) % SIDECAR_ENSURE_LOCK_SHARDS;
    locks[shard].clone().lock_owned().await
}

pub(super) fn sidecar_create_denied(message: impl Into<String>) -> AppError {
    AppError::capability_denied(message)
        .with_wire_code(arkret_core::ReasonCode::SIDECAR_CREATE_DENIED)
}

pub(super) fn sidecar_failed_precondition(
    reason: &'static str,
    message: impl Into<String>,
) -> AppError {
    AppError::new(ErrorCode::FailedPrecondition, message.into())
        .with_status(StatusCode::PRECONDITION_FAILED)
        .with_wire_code(reason)
}

fn sidecar_reducer_reject_to_app_error(reason: &'static str) -> AppError {
    AppError::new(
        ErrorCode::FailedPrecondition,
        format!("agent sidecar reducer rejected: {reason}"),
    )
    .with_status(StatusCode::PRECONDITION_FAILED)
    .with_wire_code(reason)
}

async fn authorize_sidecar_ensure(
    state: &AppState,
    controller: &str,
    realm_id: &str,
) -> Result<(), AppError> {
    let owner = state
        .realm_query_application()
        .realm_metadata(realm_id)
        .await
        .ok()
        .flatten()
        .map(|meta| meta.owner_id);
    let members = realm_members_for_authz(state, realm_id);
    let verdict = state.authz.check(
        controller,
        arkret_core::CapabilityActionId::SELF_AGENT_SIDECAR_COMMAND_ENSURE,
        realm_id,
        realm_id,
        owner.as_deref(),
        &members,
        &[],
    );
    if verdict.allowed {
        return Ok(());
    }
    if matches!(
        verdict.reason.as_str(),
        "explicit_deny" | "quarantine" | "require_review" | "constraints_not_satisfied"
    ) {
        return Err(sidecar_create_denied(
            "ak.self.agent.sidecar.command.ensure denied by policy",
        ));
    }
    if realm_member_joined(state, realm_id, controller) {
        return Ok(());
    }
    Err(sidecar_create_denied(
        "ak.self.agent.sidecar.command.ensure requires a Realm member controller",
    ))
}

fn realm_members_for_authz(state: &AppState, realm_id: &str) -> Vec<String> {
    let realms = state.realms.lock();
    RealmId::new(realm_id.to_owned())
        .ok()
        .and_then(|id| realms.get(&id).cloned())
        .map(|realm| realm.members.iter().map(ToString::to_string).collect())
        .unwrap_or_default()
}

pub(super) fn realm_member_joined(state: &AppState, realm_id: &str, actor: &str) -> bool {
    let in_realm_directory = {
        let realms = state.realms.lock();
        RealmId::new(realm_id.to_owned())
            .ok()
            .and_then(|id| realms.get(&id).cloned())
    }
    .and_then(|realm| {
        Did::new(actor.to_owned())
            .ok()
            .map(|did| realm.members.contains(&did))
    })
    .unwrap_or(false);
    in_realm_directory
        || state
            .projection
            .lock()
            .member(realm_id, actor)
            .is_some_and(|membership| membership.state == "join")
}

fn normalize_sidecar_context_ref(context_ref: &AgentSidecarContextRef) -> Result<Value, AppError> {
    serde_json::to_value(context_ref)
        .map_err(|err| AppError::internal(format!("context_ref serialization failed: {err}")))
}

fn context_realm_id(context_ref: &AgentSidecarContextRef) -> &RealmId {
    context_ref.realm_id()
}

fn sidecar_context_target_ref(context_ref: &AgentSidecarContextRef) -> &str {
    match context_ref {
        AgentSidecarContextRef::Strand(context) => context.strand_id.as_str(),
        AgentSidecarContextRef::Relation(context) => context.relation_id.as_str(),
    }
}

fn validate_sidecar_context_projection(
    state: &AppState,
    context_ref: &AgentSidecarContextRef,
) -> Result<(), AppError> {
    let projection = state.projection.lock();
    let realm_id = context_ref.realm_id().as_str();
    match context_ref {
        AgentSidecarContextRef::Strand(context) => {
            let strand = projection
                .strands
                .get(context.strand_id.as_str())
                .ok_or_else(|| AppError::not_found("context_ref.strand_id not found"))?;
            if strand.realm_id != realm_id {
                return Err(sidecar_failed_precondition(
                    "context_ref_realm_mismatch",
                    "context_ref.strand_id belongs to another Realm",
                ));
            }
        }
        AgentSidecarContextRef::Relation(context) => {
            let relation = projection
                .relations
                .get(context.relation_id.as_str())
                .ok_or_else(|| AppError::not_found("context_ref.relation_id not found"))?;
            if relation.realm_id != realm_id {
                return Err(sidecar_failed_precondition(
                    "context_ref_realm_mismatch",
                    "context_ref.relation_id belongs to another Realm",
                ));
            }
            if relation.state != "active" {
                return Err(sidecar_failed_precondition(
                    "relation_not_active",
                    "context_ref.relation_id is not active",
                ));
            }
        }
    }
    Ok(())
}

pub(super) fn normalize_addressed_agents(
    controller: &str,
    body: &AgentSidecarEnsureRequestBody,
) -> Result<Vec<String>, AppError> {
    if body
        .addressed_agent_ids
        .iter()
        .any(|agent| agent.as_str() == controller)
    {
        return Err(sidecar_failed_precondition(
            CONTROLLER_IN_ADDRESSED_AGENTS,
            "addressed_agent_ids must not contain the controller",
        ));
    }
    body.validate()
        .map_err(|error| AppError::invalid_param(error.to_string()))?;
    let mut out = Vec::with_capacity(body.addressed_agent_ids.len());
    for agent in &body.addressed_agent_ids {
        out.push(agent.to_string());
    }
    Ok(out)
}

pub(crate) async fn eligible_sidecar_agents(
    state: &AppState,
    realm_id: &str,
    controller: &str,
    addressed_agents: &[String],
) -> Result<Vec<String>, AppError> {
    let records = state
        .agent_pairing_application()
        .agents_for_controller(controller)
        .await
        .map_err(|err| AppError::internal(format!("agent list failed: {err}")))?;
    let eligible = records
        .iter()
        .filter(|record| agent_record_is_sidecar_eligible(state, realm_id, controller, record))
        .map(|record| record.id.clone())
        .collect::<BTreeSet<_>>();
    if addressed_agents
        .iter()
        .any(|addressed| !eligible.contains(addressed))
    {
        return Err(sidecar_failed_precondition(
            ADDRESSED_AGENT_NOT_ELIGIBLE,
            "addressed agent is not eligible for this Sidecar Realm",
        ));
    }
    Ok(eligible.into_iter().collect())
}

fn agent_record_is_sidecar_eligible(
    state: &AppState,
    realm_id: &str,
    controller: &str,
    record: &AgentPrincipalRecord,
) -> bool {
    let agent_id = record.id.as_str();
    record.controller_id == controller
        && record.state == "active"
        && realm_member_joined(state, realm_id, agent_id)
        && {
            let projection = state.projection.lock();
            !matches!(
                projection.agent_lifecycles.get(agent_id),
                Some(AgentLifecycleState::Paused | AgentLifecycleState::Deactivated)
            ) && projection.agent_has_authorized_key(agent_id)
        }
}

fn new_sidecar_operation(
    realm_id: &RealmId,
    kind: &'static str,
    payload: Value,
) -> Result<Operation, AppError> {
    let operation_id = OperationId::new(ids::generate_operation_id())
        .map_err(|err| AppError::internal(format!("generated operation id invalid: {err}")))?;
    Ok(Operation::create(
        operation_id,
        realm_id.clone(),
        kind,
        payload,
    ))
}

fn backing_circle_is_compliant(
    circle: &soland_domain::reducer::CircleProjection,
    sidecar_id: &SidecarId,
    controller: &str,
) -> bool {
    let expected_short_name =
        arkret_core::agent_sidecar_backing_circle_short_name(sidecar_id.as_str());
    circle.profile_ref.is_none()
        && circle.title == "Agent Sidecar Scope"
        && circle.summary.is_none()
        && circle.created_by == controller
        && circle.directory_visibility == "members"
        && circle.join_rule == "invite"
        && circle.history_visibility == "restricted"
        && circle.encryption_profile == "mls_rfc9420"
        && circle.content_encryption_floor.as_deref() == Some("e2ee_required")
        && circle.metadata_encryption_floor.as_deref() == Some("e2ee_required")
        && circle
            .display
            .pointer("/short_name")
            .and_then(Value::as_str)
            == Some(expected_short_name.as_str())
        && circle
            .display
            .pointer("/symbol/glyph")
            .and_then(Value::as_str)
            == Some("lock")
}

async fn ensure_backing_circle(
    state: &AppState,
    controller: &str,
    realm_id: &RealmId,
    sidecar_id: &SidecarId,
    circle_id: &CircleId,
) -> Result<(), AppError> {
    if let Some(circle) = state.projection.lock().circles.get(circle_id.as_str()) {
        return if circle.realm_id == realm_id.as_str()
            && backing_circle_is_compliant(circle, sidecar_id, controller)
        {
            Ok(())
        } else {
            Err(sidecar_create_denied("Sidecar backing scope conflict"))
        };
    }
    let short_name = arkret_core::agent_sidecar_backing_circle_short_name(sidecar_id.as_str());
    let object = json!({
        "id": circle_id,
        "schema": "ak.schema.circle.v1",
        "realm_id": realm_id,
        "title": "Agent Sidecar Scope",
        "display": {
            "short_name": short_name,
            "color_token": "slate",
            "symbol": { "glyph": "lock" }
        },
        "directory_visibility": "members",
        "join_rule": "invite",
        "history_visibility": "restricted",
        "content_encryption_floor": "e2ee_required",
        "metadata_encryption_floor": "e2ee_required",
        "encryption_profile": "mls_rfc9420",
        "state": "active",
        "created_by": controller,
        "created_at": arkret_core::canonical::format_timestamp_canonical(chrono::Utc::now())
    });
    let operation = new_sidecar_operation(
        realm_id,
        arkret_core::events::EventKind::CIRCLE_CREATE,
        json!({"object": object}),
    )?;
    crate::routing::events::projection::accept_trusted_sidecar_circle_operation(
        state, controller, sidecar_id, &operation,
    )
    .await
    .map_err(sidecar_reducer_reject_to_app_error)?;
    if state
        .projection
        .lock()
        .circles
        .get(circle_id.as_str())
        .is_some_and(|circle| backing_circle_is_compliant(circle, sidecar_id, controller))
    {
        Ok(())
    } else {
        Err(AppError::internal(
            "Sidecar backing Circle accepted but not projected",
        ))
    }
}

async fn ensure_sidecar_aggregate(
    state: &AppState,
    controller: &str,
    realm_id: &RealmId,
) -> Result<AgentSidecarRecord, AppError> {
    if let Some(record) = state
        .sidecars_store()
        .get_for_realm_controller(realm_id.as_str(), controller)
        .await
        .map_err(|error| AppError::internal(format!("Sidecar lookup failed: {error}")))?
    {
        let sidecar_id = SidecarId::new(record.sidecar_id.clone())
            .map_err(|error| AppError::internal(format!("stored Sidecar id: {error}")))?;
        let circle_id = CircleId::new(record.backing_circle_id.clone())
            .map_err(|error| AppError::internal(format!("stored backing Circle id: {error}")))?;
        ensure_backing_circle(state, controller, realm_id, &sidecar_id, &circle_id).await?;
        return Ok(record);
    }

    let sidecar_id = SidecarId::new(ids::generate("sidecar"))
        .map_err(|error| AppError::internal(format!("generated Sidecar id: {error}")))?;
    let backing_circle_id = CircleId::new(ids::generate_circle_id())
        .map_err(|error| AppError::internal(format!("generated Circle id: {error}")))?;
    let created_at = chrono::Utc::now();
    ensure_backing_circle(state, controller, realm_id, &sidecar_id, &backing_circle_id).await?;
    let sidecar = AgentSidecar {
        id: sidecar_id.clone(),
        schema: AgentSidecarSchema::V1,
        realm_id: realm_id.clone(),
        controller_id: Did::new(controller.to_owned())
            .map_err(|error| AppError::internal(format!("controller id: {error}")))?,
        backing_circle_id: backing_circle_id.clone(),
        encryption_profile: AgentSidecarEncryptionProfile::MlsRfc9420,
        state: AgentSidecarState::Active,
        state_changed_at: None,
        created_at,
        updated_at: None,
    };
    let operation = new_sidecar_operation(
        realm_id,
        arkret_core::events::EventKind::SIDECAR_CREATE,
        json!({"object": sidecar}),
    )?;
    crate::routing::events::projection::accept_trusted_sidecar_create_operation(
        state,
        controller,
        &backing_circle_id,
        &operation,
    )
    .await
    .map_err(sidecar_reducer_reject_to_app_error)?;
    let record = AgentSidecarRecord {
        sidecar_id: sidecar_id.to_string(),
        realm_id: realm_id.to_string(),
        controller_id: controller.to_owned(),
        backing_circle_id: backing_circle_id.to_string(),
        state: "active".to_owned(),
        state_changed_at: None,
        created_at,
        updated_at: None,
    };
    state
        .sidecars_store()
        .insert_or_get(record)
        .await
        .map_err(|error| AppError::internal(format!("Sidecar persistence failed: {error}")))
}

fn circle_has_member(state: &AppState, circle_id: &str, actor: &str) -> bool {
    state
        .projection
        .lock()
        .circles
        .get(circle_id)
        .is_some_and(|circle| circle.members.contains(actor))
}

async fn ensure_sidecar_member(
    state: &AppState,
    controller: &str,
    realm_id: &RealmId,
    circle_id: &CircleId,
    actor: &str,
) -> Result<(), AppError> {
    if circle_has_member(state, circle_id.as_str(), actor) {
        return Ok(());
    }
    let operation = new_sidecar_operation(
        realm_id,
        arkret_core::events::EventKind::CIRCLE_MEMBER_STATE,
        json!({"circle_id": circle_id, "actor_id": actor, "membership": "join"}),
    )?;
    crate::routing::events::projection::accept_trusted_sidecar_member_operation(
        state, controller, &operation,
    )
    .await
    .map_err(sidecar_reducer_reject_to_app_error)?;
    if circle_has_member(state, circle_id.as_str(), actor) {
        Ok(())
    } else {
        Err(AppError::internal(
            "Sidecar backing membership accepted but not projected",
        ))
    }
}

async fn ensure_sidecar_mls_genesis(
    state: &AppState,
    controller: &str,
    controller_device_id: &str,
    realm_id: &RealmId,
    circle_id: &CircleId,
) -> Result<(), AppError> {
    if state
        .projection
        .lock()
        .circles
        .get(circle_id.as_str())
        .is_some_and(|circle| circle.mls_group_ref.is_some())
    {
        return Ok(());
    }
    let mut member_event_refs = state
        .projection_events_store()
        .snapshot_all()
        .await
        .map_err(|error| {
            AppError::internal(format!("Sidecar MLS frontier lookup failed: {error}"))
        })?
        .into_iter()
        .filter(|event| event.event_kind == arkret_core::events::EventKind::CIRCLE_MEMBER_STATE)
        .filter(|event| {
            event.payload.get("circle_id").and_then(Value::as_str) == Some(circle_id.as_str())
                && event.payload.get("membership").and_then(Value::as_str) == Some("join")
        })
        .map(|event| event.event_id)
        .collect::<Vec<_>>();
    member_event_refs.sort();
    member_event_refs.dedup();
    if member_event_refs.is_empty() {
        return Err(AppError::internal(
            "Sidecar MLS genesis requires a persisted membership frontier",
        ));
    }
    let group_id = ids::generate("mls_group");
    let effective_scope = json!({
        "kind": "circle",
        "realm_id": realm_id,
        "circle_id": circle_id,
    });
    let governance_binding = json!({
        "binding_version": 1,
        "encoding_profile": "cbor-deterministic-rfc8949-v1",
        "realm_id": realm_id,
        "circle_id": circle_id,
        "effective_scope": effective_scope,
        "mls_group_id": group_id,
        "previous_epoch": 0,
        "next_epoch": 0,
        "membership_frontier": member_event_refs,
        "policy_root": arkret_core::canonical::sha256_digest(format!("sidecar-policy:{realm_id}:{group_id}")),
        "binding_profile": soland_domain::kinds::MLS_GOVERNANCE_BINDING_FULL_PROFILE,
        "reducer_profile": soland_domain::kinds::MLS_REDUCER_PROFILE_V1,
    });
    let operation = new_sidecar_operation(
        realm_id,
        arkret_core::events::EventKind::MLS_GENESIS,
        json!({
            "mls_group_id": group_id,
            "effective_scope": effective_scope,
            "epoch": 0,
            "creator_principal_id": controller,
            "creator_device_id": controller_device_id,
            "cipher_suite": "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
            "group_info_digest": arkret_core::canonical::sha256_digest(format!("sidecar-group-info:{realm_id}:{group_id}")),
            "ratchet_tree_digest": arkret_core::canonical::sha256_digest(format!("sidecar-ratchet-tree:{realm_id}:{group_id}")),
            "covered_seals": member_event_refs,
            "governance_binding": governance_binding,
            "created_at": arkret_core::canonical::format_timestamp_canonical(chrono::Utc::now()),
        }),
    )?;
    let effect =
        soland_domain::reducer::mls::apply_group_genesis(&mut state.projection.lock(), &operation);
    match &effect {
        soland_domain::reducer::ProjectionEffect::Mls(
            soland_domain::reducer::MlsEffect::GroupGenesis { .. },
        ) => {
            crate::routing::events::projection::mirror_mls_effect_to_persistence(
                state,
                controller,
                controller_device_id,
                &operation,
                &effect,
            )
            .await;
            Ok(())
        }
        soland_domain::reducer::ProjectionEffect::Rejected { reason } => Err(AppError::internal(
            format!("Sidecar MLS genesis rejected: {reason}"),
        )),
        other => Err(AppError::internal(format!(
            "unexpected Sidecar MLS genesis effect: {other:?}"
        ))),
    }
}

fn private_tracks_for_context(state: &AppState, context_ref: &AgentSidecarContextRef) -> Value {
    let AgentSidecarContextRef::Strand(context) = context_ref else {
        return json!({"synthesis": {}, "discussion": {"profile": "discussion", "is_primary": true}});
    };
    state
        .projection
        .lock()
        .strands
        .get(context.strand_id.as_str())
        .and_then(|strand| serde_json::to_value(&strand.tracks).ok())
        .unwrap_or_else(|| json!({"synthesis": {}}))
}

fn private_context_strand_object(
    strand_id: &StrandId,
    realm_id: &RealmId,
    circle_id: &CircleId,
    controller: &str,
    tracks: Value,
    created_at: &str,
) -> Value {
    json!({
        "id": strand_id,
        "schema": "ak.schema.strand.v1",
        "realm_id": realm_id,
        "tracks": tracks,
        "scope_circle_id": circle_id,
        "created_by": controller,
        "created_at": created_at
    })
}

async fn create_private_context(
    state: &AppState,
    controller: &str,
    sidecar: &AgentSidecarRecord,
    context_ref: &AgentSidecarContextRef,
    normalized_context_ref: &Value,
    normalized_context_ref_digest: &str,
) -> Result<AgentSidecarContextRecord, AppError> {
    let realm_id = RealmId::new(sidecar.realm_id.clone())
        .map_err(|error| AppError::internal(format!("stored Realm id: {error}")))?;
    let circle_id = CircleId::new(sidecar.backing_circle_id.clone())
        .map_err(|error| AppError::internal(format!("stored Circle id: {error}")))?;
    let strand_id = StrandId::new(ids::generate("strand"))
        .map_err(|error| AppError::internal(format!("generated Strand id: {error}")))?;
    let tracks = private_tracks_for_context(state, context_ref);
    let created_at = arkret_core::canonical::format_timestamp_canonical(chrono::Utc::now());
    let object = private_context_strand_object(
        &strand_id,
        &realm_id,
        &circle_id,
        controller,
        tracks,
        &created_at,
    );
    let strand_operation = new_sidecar_operation(
        &realm_id,
        arkret_core::events::EventKind::STRAND_CREATE,
        json!({"object": object}),
    )?;
    accept_local_operations(state, controller, std::slice::from_ref(&strand_operation))
        .await
        .map_err(sidecar_reducer_reject_to_app_error)?;

    let relation_id = RelationId::new(ids::generate_relation_id())
        .map_err(|error| AppError::internal(format!("generated Relation id: {error}")))?;
    let relation_operation = new_sidecar_operation(
        &realm_id,
        arkret_core::events::EventKind::RELATION_CREATE,
        json!({"relation": {
            "id": relation_id,
            "kind": "agent_sidecar_of",
            "from_ref": strand_id,
            "to_ref": sidecar_context_target_ref(context_ref),
            "scope_circle_id": circle_id,
            "created_by": controller
        }}),
    )?;
    accept_local_operations(state, controller, std::slice::from_ref(&relation_operation))
        .await
        .map_err(sidecar_reducer_reject_to_app_error)?;

    let record = AgentSidecarContextRecord {
        sidecar_id: sidecar.sidecar_id.clone(),
        normalized_context_ref_digest: normalized_context_ref_digest.to_owned(),
        normalized_context_ref: normalized_context_ref.clone(),
        private_strand_id: strand_id.to_string(),
        private_relation_id: relation_id.to_string(),
        created_at: chrono::Utc::now(),
    };
    state
        .sidecars_store()
        .insert_or_get_context(record)
        .await
        .map_err(|error| AppError::internal(format!("Sidecar context persistence failed: {error}")))
}

async fn ensure_private_context(
    state: &AppState,
    controller: &str,
    sidecar: &AgentSidecarRecord,
    context_ref: &AgentSidecarContextRef,
    normalized_context_ref: &Value,
    normalized_context_ref_digest: &str,
) -> Result<AgentSidecarContextRecord, AppError> {
    if let Some(record) = state
        .sidecars_store()
        .get_context(&sidecar.sidecar_id, normalized_context_ref_digest)
        .await
        .map_err(|error| AppError::internal(format!("Sidecar context lookup failed: {error}")))?
    {
        return Ok(record);
    }
    create_private_context(
        state,
        controller,
        sidecar,
        context_ref,
        normalized_context_ref,
        normalized_context_ref_digest,
    )
    .await
}

fn sidecar_from_record(record: &AgentSidecarRecord) -> Result<AgentSidecar, AppError> {
    let state = match record.state.as_str() {
        "active" => AgentSidecarState::Active,
        "suspended" => AgentSidecarState::Suspended,
        "tombstoned" => AgentSidecarState::Tombstoned,
        _ => return Err(AppError::internal("stored Sidecar state is invalid")),
    };
    Ok(AgentSidecar {
        id: SidecarId::new(record.sidecar_id.clone())
            .map_err(|error| AppError::internal(format!("stored Sidecar id: {error}")))?,
        schema: AgentSidecarSchema::V1,
        realm_id: RealmId::new(record.realm_id.clone())
            .map_err(|error| AppError::internal(format!("stored Realm id: {error}")))?,
        controller_id: Did::new(record.controller_id.clone())
            .map_err(|error| AppError::internal(format!("stored controller id: {error}")))?,
        backing_circle_id: CircleId::new(record.backing_circle_id.clone())
            .map_err(|error| AppError::internal(format!("stored Circle id: {error}")))?,
        encryption_profile: AgentSidecarEncryptionProfile::MlsRfc9420,
        state,
        state_changed_at: record.state_changed_at,
        created_at: record.created_at,
        updated_at: record.updated_at,
    })
}

async fn sidecar_view(
    state: &AppState,
    record: &AgentSidecarRecord,
) -> Result<AgentSidecarView, AppError> {
    let desired =
        eligible_sidecar_agents(state, &record.realm_id, &record.controller_id, &[]).await?;
    let (circle_members, mls_ready) = state
        .projection
        .lock()
        .circles
        .get(&record.backing_circle_id)
        .map(|circle| (circle.members.clone(), circle.mls_group_ref.is_some()))
        .unwrap_or_default();
    let mut pending = Vec::new();
    let effective = Vec::<Did>::new();
    for agent_id in &desired {
        let stage = if !circle_members.contains(agent_id) {
            Some((
                PendingSidecarAccessReconciliationStage::BackingScopeMembership,
                "backing_scope_membership_pending",
            ))
        } else if !mls_ready {
            Some((
                PendingSidecarAccessReconciliationStage::MlsWelcome,
                "mls_group_or_welcome_pending",
            ))
        } else {
            Some((
                PendingSidecarAccessReconciliationStage::MlsWelcome,
                "mls_welcome_or_epoch_commit_pending",
            ))
        };
        if let Some((stage, reason)) = stage {
            pending.push(PendingSidecarAccessReconciliationItem {
                agent_id: Did::new(agent_id.clone())
                    .map_err(|error| AppError::internal(format!("stored Agent id: {error}")))?,
                stage,
                reason: NonEmptyString::new(reason).map_err(|error| {
                    AppError::internal(format!("reconciliation reason: {error}"))
                })?,
            });
        }
    }
    let access_readiness = if pending
        .iter()
        .any(|item| item.stage == PendingSidecarAccessReconciliationStage::BackingScopeMembership)
    {
        AgentSidecarAccessReadiness::AccessReconciliationPending
    } else if !mls_ready || !pending.is_empty() {
        AgentSidecarAccessReadiness::KeyMaterialPending
    } else {
        AgentSidecarAccessReadiness::Ready
    };
    let view = AgentSidecarView {
        sidecar: sidecar_from_record(record)?,
        desired_agent_ids: desired
            .into_iter()
            .map(Did::new)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| AppError::internal(format!("stored Agent id: {error}")))?,
        effective_agent_ids: effective,
        access_readiness,
        pending_access_reconciliations: pending,
    };
    view.validate()
        .map_err(|error| AppError::internal(format!("Sidecar view invariant: {error}")))?;
    Ok(view)
}

async fn ensure_sidecar_impl(
    aa: AuthArgs,
    body: AgentSidecarEnsureRequestBody,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AgentSidecarEnsureOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    if body.controller_id.as_str() != session.actor {
        return Err(sidecar_create_denied(
            "Sidecar controller_id must match the authenticated session",
        ));
    }
    let controller = body.controller_id.as_str();
    let realm_id = context_realm_id(&body.context_ref).clone();
    authorize_sidecar_ensure(state, controller, realm_id.as_str()).await?;
    validate_sidecar_context_projection(state, &body.context_ref)?;
    let addressed_agents = normalize_addressed_agents(controller, &body)?;
    let normalized_context_ref = normalize_sidecar_context_ref(&body.context_ref)?;
    let normalized_context_ref_digest =
        arkret_core::canonical::canonical_sha256(&normalized_context_ref)
            .map_err(|error| AppError::internal(format!("context_ref digest failed: {error}")))?;
    let eligible_agents =
        eligible_sidecar_agents(state, realm_id.as_str(), controller, &addressed_agents).await?;

    let _guard = lock_sidecar_ensure(realm_id.as_str(), controller).await;
    let sidecar = ensure_sidecar_aggregate(state, controller, &realm_id).await?;
    let circle_id = CircleId::new(sidecar.backing_circle_id.clone())
        .map_err(|error| AppError::internal(format!("stored Circle id: {error}")))?;
    ensure_sidecar_member(state, controller, &realm_id, &circle_id, controller).await?;
    for agent_id in &eligible_agents {
        ensure_sidecar_member(state, controller, &realm_id, &circle_id, agent_id).await?;
    }
    ensure_sidecar_mls_genesis(state, controller, &session.device_id, &realm_id, &circle_id)
        .await?;
    let context = ensure_private_context(
        state,
        controller,
        &sidecar,
        &body.context_ref,
        &normalized_context_ref,
        &normalized_context_ref_digest,
    )
    .await?;
    let view = sidecar_view(state, &sidecar).await?;
    append_audit_log(
        state,
        Some(&session.actor),
        "ak.self.agent.sidecar.command.ensure",
        json!({
            "controller_id": body.controller_id,
            "realm_id": realm_id,
            "addressed_agent_count": addressed_agents.len(),
            "context_ref_digest": normalized_context_ref_digest
        }),
        "accepted",
    )
    .await;
    json_ok(AgentSidecarEnsureOutcome {
        ok: true,
        sidecar_id: view.sidecar.id,
        private_strand_id: StrandId::new(context.private_strand_id)
            .map_err(|error| AppError::internal(format!("stored Strand id: {error}")))?,
        private_relation_id: RelationId::new(context.private_relation_id)
            .map_err(|error| AppError::internal(format!("stored Relation id: {error}")))?,
        access_readiness: view.access_readiness,
        pending_access_reconciliations: view.pending_access_reconciliations,
    })
}

#[endpoint(
    operation_id = "ak.self.agent.sidecar.command.ensure",
    tags("agents"),
    summary = "Idempotently ensure a controller-owned Agent Sidecar",
    status_codes(200, 201, 400, 401, 403, 412, 500)
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.agent.sidecar.command.ensure"))]
pub(super) async fn ensure_sidecar(
    aa: AuthArgs,
    body: JsonBody<AgentSidecarEnsureRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AgentSidecarEnsureOutcome> {
    ensure_sidecar_impl(aa, body.into_inner(), depot, req).await
}

#[endpoint(
    operation_id = "ak.self.agent.sidecar.resource.get",
    tags("agents"),
    summary = "Read one controller-owned Agent Sidecar",
    status_codes(200, 401, 404, 500)
)]
pub(super) async fn get_sidecar(
    aa: AuthArgs,
    sidecar_id: PathParam<SidecarId>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AgentSidecarView> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let record = state
        .sidecars_store()
        .get(sidecar_id.as_str())
        .await
        .map_err(|error| AppError::internal(format!("Sidecar lookup failed: {error}")))?
        .filter(|record| record.controller_id == session.actor)
        .ok_or_else(|| AppError::not_found("Sidecar not found"))?;
    json_ok(sidecar_view(state, &record).await?)
}

#[endpoint(
    operation_id = "ak.self.agent.sidecar.query.list",
    tags("agents"),
    summary = "List controller-owned Agent Sidecars",
    status_codes(200, 400, 401, 500)
)]
pub(super) async fn list_sidecars(
    aa: AuthArgs,
    realm_id: QueryParam<RealmId, false>,
    cursor: QueryParam<String, false>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AgentSidecarList> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let mut records = state
        .sidecars_store()
        .list_for_controller(&session.actor, realm_id.as_ref().map(RealmId::as_str))
        .await
        .map_err(|error| AppError::internal(format!("Sidecar list failed: {error}")))?;
    records.sort_by(|left, right| left.sidecar_id.cmp(&right.sidecar_id));
    if let Some(cursor) = cursor.as_ref() {
        records.retain(|record| record.sidecar_id.as_str() > cursor.as_str());
    }
    let has_more = records.len() > SIDECAR_LIST_PAGE_SIZE;
    records.truncate(SIDECAR_LIST_PAGE_SIZE);
    let next_cursor = has_more
        .then(|| records.last().map(|record| record.sidecar_id.clone()))
        .flatten()
        .map(NonEmptyString::new)
        .transpose()
        .map_err(|error| AppError::internal(format!("Sidecar cursor: {error}")))?;
    let mut items = Vec::with_capacity(records.len());
    for record in records {
        items.push(sidecar_view(state, &record).await?);
    }
    json_ok(AgentSidecarList { items, next_cursor })
}

#[cfg(test)]
mod tests {
    use chrono::{TimeZone as _, Timelike as _};

    use super::*;

    #[test]
    fn freshly_created_sidecar_passes_the_canonical_operation_timestamp_gate() {
        let created_at = chrono::Utc
            .with_ymd_and_hms(2026, 7, 20, 12, 34, 56)
            .unwrap()
            .with_nanosecond(987_654_321)
            .unwrap();
        let realm_id =
            RealmId::new("ak:realm:01964137-0000-7000-8000-000000000030".to_owned()).unwrap();
        let sidecar = AgentSidecar {
            id: SidecarId::new("ak:sidecar:01964137-0000-7000-8000-000000000031".to_owned())
                .unwrap(),
            schema: AgentSidecarSchema::V1,
            realm_id: realm_id.clone(),
            controller_id: Did::new("did:web:example.com:users:alice".to_owned()).unwrap(),
            backing_circle_id: CircleId::new(
                "ak:circle:01964137-0000-7000-8000-000000000032".to_owned(),
            )
            .unwrap(),
            encryption_profile: AgentSidecarEncryptionProfile::MlsRfc9420,
            state: AgentSidecarState::Active,
            state_changed_at: Some(created_at),
            created_at,
            updated_at: Some(created_at),
        };

        let operation = new_sidecar_operation(
            &realm_id,
            arkret_core::events::EventKind::SIDECAR_CREATE,
            json!({"object": sidecar}),
        )
        .unwrap();

        crate::routing::events::operations::validate_canonical_json_value(&operation.payload)
            .unwrap();
        let object = operation.payload.get("object").unwrap();
        assert_eq!(
            object.get("created_at").unwrap(),
            "2026-07-20T12:34:56.987Z"
        );
        assert_eq!(
            object.get("state_changed_at").unwrap(),
            "2026-07-20T12:34:56.987Z"
        );
        assert_eq!(
            object.get("updated_at").unwrap(),
            "2026-07-20T12:34:56.987Z"
        );
    }

    #[test]
    fn private_context_strand_preserves_all_tracks_without_plaintext_metadata() {
        let strand_id =
            StrandId::new("ak:strand:01964137-0000-7000-8000-000000000031".to_owned()).unwrap();
        let realm_id =
            RealmId::new("ak:realm:01964137-0000-7000-8000-000000000030".to_owned()).unwrap();
        let circle_id =
            CircleId::new("ak:circle:01964137-0000-7000-8000-000000000032".to_owned()).unwrap();
        let tracks = json!({
            "description": {"profile": "document"},
            "synthesis": {"profile": "document"},
            "discussion": {"profile": "discussion", "is_primary": true}
        });

        let object = private_context_strand_object(
            &strand_id,
            &realm_id,
            &circle_id,
            "did:web:example.com:users:alice",
            tracks.clone(),
            "2026-07-20T00:00:00.000Z",
        );

        assert_eq!(object.get("tracks"), Some(&tracks));
        assert!(object.get("metadata").is_none());
        assert!(object.get("title").is_none());
        assert!(object.get("summary").is_none());
    }
}
