use arkret_identifiers::SidecarId;
use arkret_models_collaboration::agent_operations::{
    AgentSidecar, AgentSidecarAccessReadiness, AgentSidecarContextRef,
    AgentSidecarEncryptionProfile, AgentSidecarEnsureOutcome, AgentSidecarEnsureRequestBody,
    AgentSidecarList, AgentSidecarMlsContext, AgentSidecarSchema, AgentSidecarState,
    AgentSidecarView, PendingSidecarAccessReconciliationItem,
    PendingSidecarAccessReconciliationStage, agent_sidecar_desired_access_digest,
};
use arkret_models_crypto::{MlsGovernanceBindingPayload, SidecarMlsBinding};
use arkret_wire::{MlsGroupId, NonEmptyString};
use salvo::oapi::extract::QueryParam;
use soland_services::identity::{
    AgentSidecarContextState as AgentSidecarContextRecord, AgentSidecarState as AgentSidecarRecord,
};

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
        .with_wire_code(arkret_wire::ReasonCode::SIDECAR_CREATE_DENIED)
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
        .realms()
        .realm_metadata(realm_id)
        .await
        .ok()
        .flatten()
        .map(|meta| meta.owner);
    let members = realm_members_for_authz(state, realm_id);
    let verdict = state
        .authorization()
        .check(soland_services::authorization::AuthorizationCheck {
            actor: controller,
            action: arkret_wire::CapabilityActionId::SELF_AGENT_SIDECAR_COMMAND_ENSURE,
            resource: realm_id,
            realm_id,
            owner: owner.as_deref(),
            members: &members,
            resource_facets: &[],
        });
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
    let realms = state.realm_directory().snapshot();
    RealmId::new(realm_id.to_owned())
        .ok()
        .and_then(|id| realms.get(&id).cloned())
        .map(|realm| realm.members.iter().map(ToString::to_string).collect())
        .unwrap_or_default()
}

pub(super) fn realm_member_joined(state: &AppState, realm_id: &str, actor: &str) -> bool {
    let in_realm_directory = {
        let realms = state.realm_directory().snapshot();
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
            .projections()
            .snapshot()
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
    let projection = state.projections().snapshot();
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
        .agent_pairings()
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
            let projection = state.projections().snapshot();
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
    circle: &soland_services::projection::CircleReadModel,
    sidecar_id: &SidecarId,
    controller: &str,
) -> bool {
    let expected_short_name =
        arkret_wire::constants::agent_sidecar_backing_circle_short_name(sidecar_id.as_str());
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
    if let Some(circle) = state
        .projections()
        .snapshot()
        .circles
        .get(circle_id.as_str())
    {
        return if circle.realm_id == realm_id.as_str()
            && backing_circle_is_compliant(circle, sidecar_id, controller)
        {
            Ok(())
        } else {
            Err(sidecar_create_denied("Sidecar backing scope conflict"))
        };
    }
    let short_name =
        arkret_wire::constants::agent_sidecar_backing_circle_short_name(sidecar_id.as_str());
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
        "created_at": arkret_canonical::format_timestamp_canonical(chrono::Utc::now())
    });
    let operation = new_sidecar_operation(
        realm_id,
        arkret_wire::events::EventKind::CIRCLE_CREATE,
        json!({"object": object}),
    )?;
    crate::routing::events::projection::accept_trusted_sidecar_circle_operation(
        state, controller, sidecar_id, &operation,
    )
    .await
    .map_err(sidecar_reducer_reject_to_app_error)?;
    if state
        .projections()
        .snapshot()
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
        .agent_pairings()
        .sidecar_for_realm_controller(realm_id.as_str(), controller)
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
        arkret_wire::events::EventKind::SIDECAR_CREATE,
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
        .agent_pairings()
        .ensure_sidecar(record)
        .await
        .map_err(|error| AppError::internal(format!("Sidecar persistence failed: {error}")))
}

fn circle_has_member(state: &AppState, circle_id: &str, actor: &str) -> bool {
    state
        .projections()
        .snapshot()
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
        arkret_wire::events::EventKind::CIRCLE_MEMBER_STATE,
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

pub(crate) async fn remove_agent_from_controller_sidecars(
    state: &AppState,
    controller: &str,
    agent_id: &str,
) -> Result<(), AppError> {
    let sidecars = state
        .agent_pairings()
        .sidecars_for_controller(controller, None)
        .await
        .map_err(|error| AppError::internal(format!("Sidecar list failed: {error}")))?;
    for sidecar in sidecars {
        let _sidecar_guard = lock_sidecar_ensure(&sidecar.realm_id, controller).await;
        if !circle_has_member(state, &sidecar.backing_circle_id, agent_id) {
            continue;
        }
        let realm_id = RealmId::new(sidecar.realm_id.clone())
            .map_err(|error| AppError::internal(format!("stored Realm id: {error}")))?;
        let circle_id = CircleId::new(sidecar.backing_circle_id.clone())
            .map_err(|error| AppError::internal(format!("stored Circle id: {error}")))?;
        let operation = new_sidecar_operation(
            &realm_id,
            arkret_wire::events::EventKind::CIRCLE_MEMBER_STATE,
            json!({"circle_id": circle_id, "actor_id": agent_id, "membership": "leave"}),
        )?;
        crate::routing::events::projection::accept_trusted_sidecar_member_operation(
            state, controller, &operation,
        )
        .await
        .map_err(sidecar_reducer_reject_to_app_error)?;
        if circle_has_member(state, &sidecar.backing_circle_id, agent_id) {
            return Err(AppError::internal(
                "Sidecar backing membership leave accepted but not projected",
            ));
        }
    }
    Ok(())
}

fn private_tracks_for_context(state: &AppState, context_ref: &AgentSidecarContextRef) -> Value {
    let AgentSidecarContextRef::Strand(context) = context_ref else {
        return json!({"synthesis": {}, "discussion": {"profile": "discussion", "is_primary": true}});
    };
    state
        .projections()
        .snapshot()
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
    let created_at = arkret_canonical::format_timestamp_canonical(chrono::Utc::now());
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
        arkret_wire::events::EventKind::STRAND_CREATE,
        json!({"object": object}),
    )?;
    accept_local_operations(state, controller, std::slice::from_ref(&strand_operation))
        .await
        .map_err(sidecar_reducer_reject_to_app_error)?;

    let relation_id = RelationId::new(ids::generate_relation_id())
        .map_err(|error| AppError::internal(format!("generated Relation id: {error}")))?;
    let relation_operation = new_sidecar_operation(
        &realm_id,
        arkret_wire::events::EventKind::RELATION_CREATE,
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
        .agent_pairings()
        .ensure_sidecar_context(record)
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
        .agent_pairings()
        .sidecar_context(&sidecar.sidecar_id, normalized_context_ref_digest)
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

fn sidecar_access_readiness(
    pending: &[PendingSidecarAccessReconciliationItem],
    has_group: bool,
    controller_device_ready: bool,
    frontier_contested: bool,
) -> AgentSidecarAccessReadiness {
    if pending.iter().any(|item| {
        item.provisioning_phase == PendingSidecarAccessReconciliationStage::BackingScopeMembership
    }) {
        AgentSidecarAccessReadiness::AccessReconciliationPending
    } else if frontier_contested
        || pending.iter().any(|item| {
            matches!(
                item.provisioning_phase,
                PendingSidecarAccessReconciliationStage::MlsRemove
                    | PendingSidecarAccessReconciliationStage::EpochRotation
            )
        })
    {
        AgentSidecarAccessReadiness::EpochUpdateRequired
    } else if !has_group || !controller_device_ready || !pending.is_empty() {
        AgentSidecarAccessReadiness::KeyMaterialPending
    } else {
        AgentSidecarAccessReadiness::Ready
    }
}

fn typed_desired_agents(desired: &[String]) -> Result<Vec<Did>, AppError> {
    desired
        .iter()
        .cloned()
        .map(Did::new)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| AppError::internal(format!("stored Agent id: {error}")))
}

fn sidecar_control_frontier(
    projection: &soland_services::projection::ProjectionSnapshot,
    record: &AgentSidecarRecord,
    desired: &[String],
) -> Result<Vec<NonEmptyString>, AppError> {
    let mut refs = vec![
        projection
            .sidecar_create_refs
            .get(&record.sidecar_id)
            .cloned()
            .ok_or_else(|| AppError::internal("Sidecar create control ref is unavailable"))?,
    ];
    for principal_id in std::iter::once(&record.controller_id).chain(desired.iter()) {
        if let Some(join_ref) = projection
            .circle_member_join_refs
            .get(&(record.backing_circle_id.clone(), principal_id.clone()))
        {
            refs.push(join_ref.clone());
        }
    }
    refs.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
    refs.dedup();
    refs.into_iter()
        .map(NonEmptyString::new)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| AppError::internal(format!("Sidecar control ref: {error}")))
}

pub(crate) async fn expected_sidecar_mls_binding(
    state: &AppState,
    record: &AgentSidecarRecord,
) -> Result<SidecarMlsBinding, AppError> {
    let desired =
        eligible_sidecar_agents(state, &record.realm_id, &record.controller_id, &[]).await?;
    let desired_typed = typed_desired_agents(&desired)?;
    let sidecar_id = SidecarId::new(record.sidecar_id.clone())
        .map_err(|error| AppError::internal(format!("stored Sidecar id: {error}")))?;
    let realm_id = RealmId::new(record.realm_id.clone())
        .map_err(|error| AppError::internal(format!("stored Realm id: {error}")))?;
    let controller_id = Did::new(record.controller_id.clone())
        .map_err(|error| AppError::internal(format!("stored controller id: {error}")))?;
    let projection = state.projections().snapshot();
    let control_frontier = sidecar_control_frontier(&projection, record, &desired)?;
    let desired_access_digest = agent_sidecar_desired_access_digest(
        sidecar_id.clone(),
        realm_id,
        controller_id,
        &desired_typed,
    )
    .map_err(|error| AppError::internal(format!("Sidecar desired access digest: {error}")))?;
    Ok(SidecarMlsBinding {
        sidecar_id,
        desired_access_digest,
        control_frontier,
    })
}

/// Admission gate for `ak.agent.sidecar.exchange.control`
/// (zh/models/sidecar.md §7.2.3). The Event is legal only inside a Sidecar
/// backing-Circle-scoped private Strand and only from that Sidecar's
/// controller; the service never decrypts the control plaintext. Every
/// failure returns one uniform reason so unauthorized callers cannot probe
/// Sidecar existence.
pub(crate) fn validate_sidecar_exchange_control_event(
    state: &AppState,
    actor_id: &str,
    operation: &Operation,
) -> Result<(), &'static str> {
    if operation.object_kind.as_str()
        != arkret_wire::events::EventKind::AGENT_SIDECAR_EXCHANGE_CONTROL
    {
        return Ok(());
    }
    const REASON: &str = "sidecar_exchange_control_forbidden";
    let strand_id = operation
        .payload
        .get("strand_id")
        .and_then(Value::as_str)
        .ok_or(REASON)?;
    if !operation
        .payload
        .get("encrypted_payload")
        .is_some_and(Value::is_object)
    {
        return Err(REASON);
    }
    let projection = state.projections().snapshot();
    let strand = projection.strands.get(strand_id).ok_or(REASON)?;
    // §7.2.3: the control Event must be submitted into the private Strand's
    // own Realm. A mismatched operation.realm_id would let a caller route the
    // control Event through another Realm's admission/capability context while
    // still naming the Sidecar Strand.
    if strand.realm_id != operation.realm_id.as_str() {
        return Err(REASON);
    }
    let circle_id = strand.scope_circle_id.as_deref().ok_or(REASON)?;
    let sidecar = projection
        .sidecars
        .values()
        .find(|sidecar| sidecar.backing_circle_id == circle_id)
        .ok_or(REASON)?;
    if actor_id != sidecar.controller_id {
        return Err(REASON);
    }
    Ok(())
}

pub(crate) async fn validate_sidecar_mls_event_binding(
    state: &AppState,
    actor_id: &str,
    device_id: &str,
    operation: &Operation,
) -> Result<(), &'static str> {
    if !matches!(
        operation.object_kind.as_str(),
        arkret_wire::events::EventKind::MLS_GENESIS
            | arkret_wire::events::EventKind::MLS_PROPOSAL
            | arkret_wire::events::EventKind::MLS_COMMIT
            | arkret_wire::events::EventKind::MLS_WELCOME
    ) {
        return Ok(());
    }
    let binding_value = operation
        .payload
        .get("governance_binding")
        .or_else(|| operation.payload.get("mls_governance_binding"))
        .ok_or("mls_governance_binding_missing")?;
    let binding = serde_json::from_value::<MlsGovernanceBindingPayload>(binding_value.clone())
        .map_err(|_| "mls_governance_binding_invalid")?;
    let circle_id = binding.circle_id().map(ToString::to_string);
    let sidecar_for_scope = circle_id.as_deref().and_then(|circle_id| {
        state
            .projections()
            .snapshot()
            .sidecars
            .values()
            .find(|sidecar| sidecar.backing_circle_id == circle_id)
            .cloned()
    });
    let Some(sidecar_projection) = sidecar_for_scope else {
        return if binding.sidecar_binding().is_some() {
            Err("mls_sidecar_binding_forbidden")
        } else {
            Ok(())
        };
    };
    let supplied = binding
        .sidecar_binding()
        .ok_or("mls_sidecar_binding_missing")?;
    if supplied.sidecar_id.as_str() != sidecar_projection.sidecar_id {
        return Err("mls_sidecar_binding_mismatch");
    }
    let record = state
        .agent_pairings()
        .sidecar(&sidecar_projection.sidecar_id)
        .await
        .map_err(|_| "mls_sidecar_binding_state_unavailable")?
        .ok_or("mls_sidecar_binding_mismatch")?;
    let _sidecar_guard = lock_sidecar_ensure(&record.realm_id, &record.controller_id).await;
    let expected = expected_sidecar_mls_binding(state, &record)
        .await
        .map_err(|_| "mls_sidecar_binding_state_unavailable")?;
    if supplied != &expected {
        return Err("mls_sidecar_binding_stale");
    }
    let desired = eligible_sidecar_agents(
        state,
        &sidecar_projection.realm_id,
        &sidecar_projection.controller_id,
        &[],
    )
    .await
    .map_err(|_| "mls_sidecar_binding_state_unavailable")?;
    let expected_members = std::iter::once(sidecar_projection.controller_id.clone())
        .chain(desired)
        .collect::<std::collections::BTreeSet<_>>();
    let materialized_members = state
        .projections()
        .snapshot()
        .circles
        .get(&sidecar_projection.backing_circle_id)
        .map(|circle| circle.members.clone())
        .unwrap_or_default();
    if materialized_members != expected_members {
        return Err("mls_sidecar_membership_reconciliation_pending");
    }
    let payload_group_id = operation
        .payload
        .get("mls_group_id")
        .or_else(|| operation.payload.get("group_id"))
        .and_then(Value::as_str)
        .ok_or("mls_group_id_missing")?;
    if binding.mls_group_id() != payload_group_id {
        return Err("mls_sidecar_binding_mismatch");
    }
    let current_group = state
        .projections()
        .snapshot()
        .circles
        .get(&sidecar_projection.backing_circle_id)
        .and_then(|circle| circle.mls_group_ref.clone());
    match operation.object_kind.as_str() {
        arkret_wire::events::EventKind::MLS_GENESIS => {
            if current_group.is_some()
                || operation
                    .payload
                    .get("creator_principal_id")
                    .and_then(Value::as_str)
                    != Some(sidecar_projection.controller_id.as_str())
                || operation
                    .payload
                    .get("creator_device_id")
                    .and_then(Value::as_str)
                    != Some(device_id)
                || actor_id != sidecar_projection.controller_id
            {
                return Err("mls_sidecar_genesis_authority_mismatch");
            }
        }
        arkret_wire::events::EventKind::MLS_WELCOME => {
            if current_group.as_deref() != Some(payload_group_id) {
                return Err("mls_sidecar_group_mismatch");
            }
            let projection = state.projections().snapshot();
            let commit_ref = operation
                .payload
                .get("commit_ref")
                .and_then(Value::as_str)
                .ok_or("mls_sidecar_welcome_commit_ref_missing")?;
            if !projection.accepted_mls_commit_refs.contains(commit_ref) {
                return Err("mls_sidecar_welcome_commit_ref_unaccepted");
            }
            let epoch = operation
                .payload
                .get("epoch")
                .and_then(Value::as_u64)
                .ok_or("mls_welcome_epoch_missing")?;
            if !projection
                .mls_commit_epochs
                .values()
                .any(|row| row.group_id == payload_group_id && row.epoch == epoch)
            {
                return Err("mls_sidecar_welcome_epoch_mismatch");
            }
        }
        _ if current_group.as_deref() != Some(payload_group_id) => {
            return Err("mls_sidecar_group_mismatch");
        }
        _ => {}
    }
    Ok(())
}

fn welcome_matches_sidecar_binding(
    welcome: &soland_services::projection::MlsWelcomeView,
    sidecar_id: &SidecarId,
    current_join_ref: &str,
) -> bool {
    serde_json::from_value::<MlsGovernanceBindingPayload>(welcome.governance_binding.clone())
        .ok()
        .and_then(|binding| binding.sidecar_binding().cloned())
        .is_some_and(|binding| {
            &binding.sidecar_id == sidecar_id
                && binding
                    .control_frontier
                    .iter()
                    .any(|control_ref| control_ref.as_str() == current_join_ref)
        })
}

fn device_has_effective_sidecar_evidence(
    projection: &soland_services::projection::ProjectionSnapshot,
    principal_id: &str,
    device_id: Option<&str>,
    group_id: &str,
    current_epoch: u64,
    sidecar_id: &SidecarId,
    current_join_ref: &str,
) -> bool {
    projection.mls_key_packages.values().any(|key_package| {
        key_package.actor_id == principal_id
            && device_id.is_none_or(|expected| key_package.device_id == expected)
            && key_package.claimed_by.as_deref() == Some(group_id)
            && key_package.consumed_at.is_some()
            && projection.mls_welcomes.values().flatten().any(|welcome| {
                welcome.group_id == group_id
                    && welcome.recipient_actor_id == principal_id
                    && welcome.recipient_device_id == key_package.device_id
                    && welcome.key_package_id == key_package.id
                    && welcome.delivered_at.is_some()
                    && welcome.epoch <= current_epoch
                    && welcome.commit_ref.as_ref().is_some_and(|commit_ref| {
                        projection.accepted_mls_commit_refs.contains(commit_ref)
                    })
                    && welcome_matches_sidecar_binding(welcome, sidecar_id, current_join_ref)
            })
    })
}

fn principal_has_pending_sidecar_welcome(
    projection: &soland_services::projection::ProjectionSnapshot,
    principal_id: &str,
    group_id: &str,
    sidecar_id: &SidecarId,
    current_join_ref: &str,
) -> bool {
    projection.mls_welcomes.values().flatten().any(|welcome| {
        welcome.group_id == group_id
            && welcome.recipient_actor_id == principal_id
            && projection
                .mls_key_packages
                .get(&welcome.key_package_id)
                .is_some_and(|key_package| {
                    key_package.claimed_by.as_deref() == Some(group_id)
                        && key_package.consumed_at.is_none()
                })
            && welcome
                .commit_ref
                .as_ref()
                .is_some_and(|commit_ref| projection.accepted_mls_commit_refs.contains(commit_ref))
            && welcome_matches_sidecar_binding(welcome, sidecar_id, current_join_ref)
    })
}

fn epoch_matches_sidecar_binding(
    row: &soland_services::projection::MlsCommitEpochView,
    expected: &SidecarMlsBinding,
) -> bool {
    serde_json::from_value::<MlsGovernanceBindingPayload>(row.governance_binding.clone())
        .ok()
        .and_then(|binding| binding.sidecar_binding().cloned())
        .as_ref()
        == Some(expected)
}

async fn sidecar_view(
    state: &AppState,
    record: &AgentSidecarRecord,
    controller_device_id: &str,
) -> Result<AgentSidecarView, AppError> {
    let desired =
        eligible_sidecar_agents(state, &record.realm_id, &record.controller_id, &[]).await?;
    let desired_typed = typed_desired_agents(&desired)?;
    let expected_binding = expected_sidecar_mls_binding(state, record).await?;
    let projection = state.projections().snapshot();
    let (circle_members, group_id) = projection
        .circles
        .get(&record.backing_circle_id)
        .map(|circle| (circle.members.clone(), circle.mls_group_ref.clone()))
        .unwrap_or_default();
    let expected_scope = json!({
        "kind": "circle",
        "realm_id": record.realm_id,
        "circle_id": record.backing_circle_id,
    });
    let epoch_row = group_id.as_deref().and_then(|group_id| {
        projection
            .mls_commit_epochs
            .values()
            .find(|row| row.group_id == group_id && row.effective_scope == expected_scope)
    });
    let epoch_binding_current =
        epoch_row.is_some_and(|row| epoch_matches_sidecar_binding(row, &expected_binding));
    let controller_join_ref = projection.circle_member_join_refs.get(&(
        record.backing_circle_id.clone(),
        record.controller_id.clone(),
    ));
    let controller_device_ready = epoch_binding_current
        && epoch_row.is_some_and(|row| {
            row.creator_device_id == controller_device_id
                || controller_join_ref.is_some_and(|join_ref| {
                    device_has_effective_sidecar_evidence(
                        &projection,
                        &record.controller_id,
                        Some(controller_device_id),
                        &row.group_id,
                        row.epoch,
                        &expected_binding.sidecar_id,
                        join_ref,
                    )
                })
        });
    let mut pending = Vec::new();
    let mut effective = Vec::<Did>::new();
    for agent_id in &desired {
        let provisioning_phase = if !circle_members.contains(agent_id) {
            Some((
                PendingSidecarAccessReconciliationStage::BackingScopeMembership,
                "backing_scope_membership_pending",
            ))
        } else if epoch_row.is_none() {
            Some((
                PendingSidecarAccessReconciliationStage::MlsWelcome,
                "mls_group_or_welcome_pending",
            ))
        } else if !epoch_binding_current {
            Some((
                PendingSidecarAccessReconciliationStage::MlsWelcome,
                "mls_epoch_binding_update_pending",
            ))
        } else if !projection
            .circle_member_join_refs
            .get(&(record.backing_circle_id.clone(), agent_id.clone()))
            .is_some_and(|join_ref| {
                device_has_effective_sidecar_evidence(
                    &projection,
                    agent_id,
                    None,
                    &epoch_row.expect("presence checked").group_id,
                    epoch_row.expect("presence checked").epoch,
                    &expected_binding.sidecar_id,
                    join_ref,
                )
            })
        {
            let join_ref = projection
                .circle_member_join_refs
                .get(&(record.backing_circle_id.clone(), agent_id.clone()))
                .expect("membership presence checked");
            if principal_has_pending_sidecar_welcome(
                &projection,
                agent_id,
                &epoch_row.expect("presence checked").group_id,
                &expected_binding.sidecar_id,
                join_ref,
            ) {
                Some((
                    PendingSidecarAccessReconciliationStage::DeviceKeyMaterial,
                    "mls_welcome_delivery_or_consume_pending",
                ))
            } else {
                Some((
                    PendingSidecarAccessReconciliationStage::MlsWelcome,
                    "mls_welcome_or_epoch_commit_pending",
                ))
            }
        } else {
            effective.push(
                Did::new(agent_id.clone())
                    .map_err(|error| AppError::internal(format!("stored Agent id: {error}")))?,
            );
            None
        };
        if let Some((provisioning_phase, reason)) = provisioning_phase {
            pending.push(PendingSidecarAccessReconciliationItem {
                agent_id: Did::new(agent_id.clone())
                    .map_err(|error| AppError::internal(format!("stored Agent id: {error}")))?,
                provisioning_phase,
                reason: NonEmptyString::new(reason).map_err(|error| {
                    AppError::internal(format!("reconciliation reason: {error}"))
                })?,
                membership_frontier: None,
            });
        }
    }
    for obligation in projection.pending_mls_removals.iter().filter(|obligation| {
        obligation.realm_id == record.realm_id
            && obligation.circle_id.as_deref() == Some(record.backing_circle_id.as_str())
            && !desired.contains(&obligation.actor_id)
    }) {
        let mut membership_frontier = obligation
            .membership_frontier
            .iter()
            .map(|event_id| {
                EventId::new(event_id.clone()).map_err(|error| {
                    AppError::internal(format!("stored MLS removal frontier ref: {error}"))
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        membership_frontier.sort_by(|left, right| left.as_str().cmp(right.as_str()));
        membership_frontier.dedup();
        if membership_frontier.is_empty() {
            return Err(AppError::internal(
                "stored Sidecar MLS removal obligation has an empty membership frontier",
            ));
        }
        pending.push(PendingSidecarAccessReconciliationItem {
            agent_id: Did::new(obligation.actor_id.clone()).map_err(|error| {
                AppError::internal(format!("stored Sidecar removal Agent id: {error}"))
            })?,
            provisioning_phase: PendingSidecarAccessReconciliationStage::MlsRemove,
            reason: NonEmptyString::new("mls_remove_obligation_pending")
                .expect("static reconciliation reason is non-empty"),
            membership_frontier: Some(membership_frontier),
        });
    }
    let access_readiness = sidecar_access_readiness(
        &pending,
        epoch_row.is_some(),
        controller_device_ready,
        epoch_row.is_some_and(|row| row.frontier_contested)
            || (epoch_row.is_some() && !epoch_binding_current),
    );
    let mls_context = AgentSidecarMlsContext {
        desired_access_digest: expected_binding.desired_access_digest.clone(),
        control_frontier: expected_binding.control_frontier.clone(),
        mls_group_id: epoch_row
            .map(|row| MlsGroupId::new(row.group_id.clone()))
            .transpose()
            .map_err(|error| AppError::internal(format!("stored MLS group id: {error}")))?,
        epoch: epoch_row.map(|row| row.epoch),
        genesis_event_ref: epoch_row
            .map(|row| EventId::new(row.genesis_event_ref.clone()))
            .transpose()
            .map_err(|error| AppError::internal(format!("stored genesis Event ref: {error}")))?,
        current_controller_device_ready: controller_device_ready,
    };
    let view = AgentSidecarView {
        sidecar: sidecar_from_record(record)?,
        desired_agent_ids: desired_typed,
        effective_agent_ids: effective,
        mls_context,
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
    let normalized_context_ref_digest = arkret_canonical::canonical_sha256(&normalized_context_ref)
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
    let context = ensure_private_context(
        state,
        controller,
        &sidecar,
        &body.context_ref,
        &normalized_context_ref,
        &normalized_context_ref_digest,
    )
    .await?;
    let view = sidecar_view(state, &sidecar, &session.device_id).await?;
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

#[salvo::oapi::endpoint(
    operation_id = "ak.self.agent.sidecar.command.ensure",
    tags("identity")
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

#[salvo::oapi::endpoint(tags("identity"))]
pub(super) async fn get_sidecar(
    aa: AuthArgs,
    sidecar_id: PathParam<SidecarId>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AgentSidecarView> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let record = state
        .agent_pairings()
        .sidecar(sidecar_id.as_str())
        .await
        .map_err(|error| AppError::internal(format!("Sidecar lookup failed: {error}")))?
        .filter(|record| record.controller_id == session.actor)
        .ok_or_else(|| AppError::not_found("Sidecar not found"))?;
    json_ok(sidecar_view(state, &record, &session.device_id).await?)
}

#[salvo::oapi::endpoint(tags("identity"))]
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
        .agent_pairings()
        .sidecars_for_controller(&session.actor, realm_id.as_ref().map(RealmId::as_str))
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
        items.push(sidecar_view(state, &record, &session.device_id).await?);
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
            arkret_wire::events::EventKind::SIDECAR_CREATE,
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

    #[test]
    fn empty_agent_reconciliation_does_not_prove_controller_device_readiness() {
        assert_eq!(
            sidecar_access_readiness(&[], false, false, false),
            AgentSidecarAccessReadiness::KeyMaterialPending
        );
    }

    #[test]
    fn backing_membership_pending_takes_precedence_over_key_material() {
        let pending = PendingSidecarAccessReconciliationItem {
            agent_id: Did::new("did:web:example.com:agents:assistant".to_owned()).unwrap(),
            provisioning_phase: PendingSidecarAccessReconciliationStage::BackingScopeMembership,
            reason: NonEmptyString::new("backing_scope_membership_pending").unwrap(),
            membership_frontier: None,
        };

        assert_eq!(
            sidecar_access_readiness(&[pending], true, true, false),
            AgentSidecarAccessReadiness::AccessReconciliationPending
        );
    }

    #[test]
    fn stale_epoch_requires_update_before_ready() {
        assert_eq!(
            sidecar_access_readiness(&[], true, true, true),
            AgentSidecarAccessReadiness::EpochUpdateRequired
        );
    }

    #[test]
    fn pending_sidecar_removal_requires_epoch_update() {
        let pending = PendingSidecarAccessReconciliationItem {
            agent_id: Did::new("did:web:example.com:agents:assistant".to_owned()).unwrap(),
            provisioning_phase: PendingSidecarAccessReconciliationStage::MlsRemove,
            reason: NonEmptyString::new("mls_remove_obligation_pending").unwrap(),
            membership_frontier: Some(vec![
                EventId::new("ak:event:01964137-0000-7000-8000-000000000001").unwrap(),
            ]),
        };

        assert_eq!(
            sidecar_access_readiness(&[pending], true, true, false),
            AgentSidecarAccessReadiness::EpochUpdateRequired
        );
    }

    #[test]
    fn historical_welcome_tracks_the_current_join_ref_not_the_full_frontier() {
        let sidecar_id = SidecarId::new("ak:sidecar:01964137-0000-7000-8000-000000000031").unwrap();
        let governance_binding = json!({
            "binding_version": 1,
            "encoding_profile": "cbor-deterministic-rfc8949-v1",
            "realm_id": "ak:realm:01964137-0000-7000-8000-000000000030",
            "circle_id": "ak:circle:01964137-0000-7000-8000-000000000032",
            "effective_scope": {
                "kind": "circle",
                "realm_id": "ak:realm:01964137-0000-7000-8000-000000000030",
                "circle_id": "ak:circle:01964137-0000-7000-8000-000000000032"
            },
            "mls_group_id": "YXJrcmV0LW1scy10ZXN0LWdyb3Vw",
            "previous_epoch": 0,
            "next_epoch": 1,
            "membership_frontier": ["ak:event:01964137-0000-7000-8000-000000000040"],
            "policy_root": format!("sha256:{}", "1".repeat(64)),
            "capability_root": format!("sha256:{}", "2".repeat(64)),
            "discussion_metadata_digest": format!("sha256:{}", "3".repeat(64)),
            "binding_profile": "ak.profile.mls_governance_binding.full.v1",
            "reducer_profile": "ak.reducer.v1",
            "sidecar_binding": {
                "sidecar_id": sidecar_id,
                "desired_access_digest": format!("sha256:{}", "4".repeat(64)),
                "control_frontier": [
                    "ak:event:01964137-0000-7000-8000-000000000041",
                    "ak:event:01964137-0000-7000-8000-000000000042"
                ]
            }
        });
        let welcome = soland_domain::reducer::MlsWelcome {
            id: "ak:mls_welcome:01964137-0000-7000-8000-000000000043".to_owned(),
            group_id: "YXJrcmV0LW1scy10ZXN0LWdyb3Vw".to_owned(),
            recipient_actor_id: "did:web:example.com:agents:assistant".to_owned(),
            recipient_device_id: "ak:device:01964137-0000-7000-8000-000000000044".to_owned(),
            welcome_bytes: vec![1],
            key_package_id: "ak:mls_keypackage:01964137-0000-7000-8000-000000000045".to_owned(),
            epoch: 1,
            commit_ref: Some("ak:event:01964137-0000-7000-8000-000000000046".to_owned()),
            governance_binding,
            enqueued_at: 1,
            delivered_at: Some(2),
        };
        serde_json::from_value::<MlsGovernanceBindingPayload>(welcome.governance_binding.clone())
            .unwrap();

        assert!(welcome_matches_sidecar_binding(
            &welcome,
            &sidecar_id,
            "ak:event:01964137-0000-7000-8000-000000000042"
        ));
        assert!(!welcome_matches_sidecar_binding(
            &welcome,
            &sidecar_id,
            "ak:event:01964137-0000-7000-8000-000000000047"
        ));

        let mut projection = soland_domain::reducer::ProjectionState::new();
        projection
            .accepted_mls_commit_refs
            .insert("ak:event:01964137-0000-7000-8000-000000000046".to_owned());
        projection.mls_welcomes.insert(
            soland_domain::reducer::MlsWelcomeQueueKey::new(
                welcome.recipient_actor_id.clone(),
                welcome.recipient_device_id.clone(),
            ),
            vec![welcome.clone()],
        );
        projection.mls_key_packages.insert(
            welcome.key_package_id.clone(),
            soland_domain::reducer::MlsKeyPackage {
                id: welcome.key_package_id.clone(),
                keypackage_ref: "sha256:keypackage".to_owned(),
                keypackage_digest: format!("sha256:{}", "5".repeat(64)),
                actor_id: welcome.recipient_actor_id.clone(),
                device_id: welcome.recipient_device_id.clone(),
                lifetime: soland_domain::reducer::KeyPackageLifetime {
                    not_before: 0,
                    not_after: i64::MAX,
                },
                key_package_bytes: vec![1],
                capabilities: Vec::new(),
                capabilities_digest: format!("sha256:{}", "6".repeat(64)),
                device_signature: json!({}),
                last_resort: false,
                last_resort_realm_id: None,
                claimed_by: Some(welcome.group_id.clone()),
                ssk_generation: None,
                device_authorize_event_id: Some(
                    "ak:event:01964137-0000-7000-8000-000000000048".to_owned(),
                ),
                agent_key_authorize_event_id: None,
                claimed_at: Some(1),
                claim_expires_at_unix_ms: Some(i64::MAX),
                consumed_at: None,
                created_at: 1,
            },
        );
        assert!(principal_has_pending_sidecar_welcome(
            &projection,
            &welcome.recipient_actor_id,
            &welcome.group_id,
            &sidecar_id,
            "ak:event:01964137-0000-7000-8000-000000000042",
        ));
        projection
            .mls_key_packages
            .get_mut(&welcome.key_package_id)
            .unwrap()
            .consumed_at = Some(2);
        assert!(!principal_has_pending_sidecar_welcome(
            &projection,
            &welcome.recipient_actor_id,
            &welcome.group_id,
            &sidecar_id,
            "ak:event:01964137-0000-7000-8000-000000000042",
        ));
    }
}
