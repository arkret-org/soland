use arkret_event_draft::{EventPayloadExt as _, TypedEventDraft};
use arkret_identifiers::SidecarId;
use arkret_models_collaboration::agent_operations::{
    AgentLifecycleState, AgentSidecar, AgentSidecarAccessReadiness, AgentSidecarContextRef,
    AgentSidecarEncryptionProfile, AgentSidecarExchangeControlPayload, AgentSidecarList,
    AgentSidecarMlsContext, AgentSidecarSchema, AgentSidecarState, AgentSidecarView,
    PendingSidecarAccessReconciliation, PendingSidecarAccessReconciliationStage,
    agent_sidecar_participant_authority_digest,
};
use arkret_models_collaboration::events_payloads::sidecar::SidecarCreatePayload;
use arkret_models_collaboration::prepared_event_draft::PreparedEventDraft;
use arkret_models_collaboration::sidecar_operations::{
    SidecarContextAttachPayload, SidecarContextRef, SidecarEnsureOutcome, SidecarEnsureRequestBody,
    SidecarPreparedOutcome,
};
use arkret_models_crypto::{MlsGovernanceBindingPayload, SidecarMlsBinding};
use arkret_wire::{MlsGroupId, NonEmptyString};
use salvo::oapi::extract::QueryParam;
use soland_services::identity::{
    AgentSidecarContextState as AgentSidecarContextRecord, AgentSidecarState as AgentSidecarRecord,
};

use super::*;
use crate::routing::events::event_log::VerifiedActorPredecessors;

const SIDECAR_ENSURE_LOCK_SHARDS: usize = 256;
const SIDECAR_LIST_PAGE_SIZE: usize = 100;

async fn lock_sidecar_ensure(
    realm_id: &str,
    controller_account_id: &arkret_wire::AccountId,
) -> tokio::sync::OwnedMutexGuard<()> {
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
    controller_account_id
        .principal_id
        .as_str()
        .hash(&mut hasher);
    controller_account_id.station_id.as_str().hash(&mut hasher);
    let shard = (hasher.finish() as usize) % SIDECAR_ENSURE_LOCK_SHARDS;
    locks[shard].clone().lock_owned().await
}

pub(super) fn sidecar_create_denied(message: impl Into<String>) -> AppError {
    AppError::capability_denied(message)
        .with_reason_code(arkret_wire::ReasonCode::SIDECAR_CREATE_DENIED)
}

pub(super) fn sidecar_failed_precondition(
    reason: &'static str,
    message: impl Into<String>,
) -> AppError {
    crate::app_error!(FailedPrecondition, message.into()).with_rejection_code(reason)
}

async fn authorize_sidecar_ensure(
    state: &AppState,
    session: &SessionRecord,
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
    let controller_actor =
        crate::routing::identity::session_actor::session_actor_from_credential(state, session)?;
    if controller_actor.as_account_id().is_none() {
        return Err(sidecar_create_denied(
            "Sidecar controller must be an Account",
        ));
    }
    let verdict = state
        .authorization()
        .check(soland_services::authorization::AuthorizationCheck {
            actor: &controller_actor,
            action: arkret_wire::CapabilityActionId::SELF_AGENT_SIDECAR_COMMAND_ENSURE_V1,
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
            "ak.self.agent.sidecar.command.ensure.v1 denied by policy",
        ));
    }
    if realm_member_joined(state, realm_id, &controller_actor.to_string()) {
        return Ok(());
    }
    Err(sidecar_create_denied(
        "ak.self.agent.sidecar.command.ensure.v1 requires a Realm member controller",
    ))
}

fn realm_members_for_authz(state: &AppState, realm_id: &str) -> Vec<String> {
    state
        .projections()
        .snapshot()
        .members_of_realm(realm_id)
        .into_iter()
        .map(|member| member.member.clone())
        .filter(|actor| realm_member_joined(state, realm_id, actor))
        .collect()
}

pub(super) fn realm_member_joined(state: &AppState, realm_id: &str, actor: &str) -> bool {
    if serde_json::from_str::<arkret_wire::ActorId>(actor).is_err() {
        return false;
    }
    let projection = state.projections().snapshot();
    projection
        .member(realm_id, actor)
        .is_some_and(|membership| membership.state == "join")
        && (projection
            .agent_membership_binding(realm_id, actor)
            .is_none()
            || projection.effective_agent_membership_base(realm_id, actor))
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

pub(crate) async fn derive_sidecar_desired_agent_ids(
    state: &AppState,
    realm_id: &str,
    controller: &arkret_wire::AccountId,
) -> Result<Vec<String>, AppError> {
    let records = state
        .agent_pairings()
        .agents_for_controller(controller.principal_id.as_str())
        .await
        .map_err(|err| AppError::internal(format!("agent list failed: {err}")))?;
    let mut desired = BTreeSet::new();
    for record in &records {
        if agent_record_is_desired_sidecar_member(state, realm_id, controller, record).await? {
            desired.insert(record.id.clone());
        }
    }
    Ok(desired.into_iter().collect())
}

async fn agent_record_is_desired_sidecar_member(
    state: &AppState,
    realm_id: &str,
    controller: &arkret_wire::AccountId,
    record: &AgentPrincipalRecord,
) -> Result<bool, AppError> {
    let agent_id = record.id.as_str();
    if record.controller_principal_id != controller.principal_id.as_str()
        || record.state != AgentLifecycleState::Active
    {
        return Ok(false);
    }
    let account =
        crate::routing::identity::agent_pcr::agent_controller_account(state, record).await?;
    if &account != controller {
        return Ok(false);
    }
    let agent_actor = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
        arkret_wire::DidCoreId::new(agent_id)
            .map_err(|error| AppError::internal(format!("invalid Agent principal: {error}")))?,
        account.station_id,
    ));
    let has_authorization = !accepted_agent_key_authorizations(state, record)
        .await?
        .is_empty();
    Ok(
        realm_member_joined(state, realm_id, &agent_actor.to_string()) && {
            let projection = state.projections().snapshot();
            !matches!(
                projection.agent_lifecycles.get(&agent_actor.to_string()),
                Some(AgentLifecycleState::Paused | AgentLifecycleState::Deactivated)
            ) && has_authorization
        },
    )
}

fn sidecar_from_record(record: &AgentSidecarRecord) -> Result<AgentSidecar, AppError> {
    Ok(AgentSidecar {
        id: SidecarId::new(record.sidecar_id.clone())
            .map_err(|error| AppError::internal(format!("stored Sidecar id: {error}")))?,
        schema: AgentSidecarSchema::V1,
        realm_id: RealmId::new(record.realm_id.clone())
            .map_err(|error| AppError::internal(format!("stored Realm id: {error}")))?,
        controller_account_id: record.controller_account_id.clone(),
        encryption_profile: AgentSidecarEncryptionProfile::MlsRfc9420,
        state: record.state,
        state_changed_at: record.state_changed_at,
        created_at: record.created_at,
        updated_at: record.updated_at,
    })
}

fn sidecar_access_readiness(
    pending: &[PendingSidecarAccessReconciliation],
    has_group: bool,
    controller_device_ready: bool,
    epoch_binding_stale: bool,
) -> AgentSidecarAccessReadiness {
    if epoch_binding_stale
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

fn typed_agent_ids(agent_ids: &[String]) -> Result<Vec<arkret_wire::DidCoreId>, AppError> {
    agent_ids
        .iter()
        .cloned()
        .map(arkret_wire::DidCoreId::new)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| AppError::internal(format!("stored Agent id: {error}")))
}

fn sidecar_control_frontier(
    projection: &soland_domain::reducer::ProjectionState,
    record: &AgentSidecarRecord,
) -> Result<Vec<NonEmptyString>, AppError> {
    let create_ref = projection
        .sidecar_create_refs
        .get(&record.sidecar_id)
        .cloned()
        .ok_or_else(|| AppError::internal("Sidecar create control ref is unavailable"))?;
    Ok(vec![NonEmptyString::new(create_ref).map_err(|error| {
        AppError::internal(format!("Sidecar control ref: {error}"))
    })?])
}

fn sidecar_mls_binding_for_desired(
    record: &AgentSidecarRecord,
    desired_agent_ids: &[arkret_wire::DidCoreId],
    projection: &soland_domain::reducer::ProjectionState,
) -> Result<SidecarMlsBinding, AppError> {
    let sidecar_id = SidecarId::new(record.sidecar_id.clone())
        .map_err(|error| AppError::internal(format!("stored Sidecar id: {error}")))?;
    let realm_id = RealmId::new(record.realm_id.clone())
        .map_err(|error| AppError::internal(format!("stored Realm id: {error}")))?;
    let controller_account_id = record.controller_account_id.clone();
    let control_frontier = sidecar_control_frontier(projection, record)?;
    let participant_authority_digest = agent_sidecar_participant_authority_digest(
        sidecar_id.clone(),
        realm_id,
        controller_account_id,
        desired_agent_ids,
    )
    .map_err(|error| {
        AppError::internal(format!("Sidecar participant authority digest: {error}"))
    })?;
    Ok(SidecarMlsBinding {
        sidecar_id,
        participant_authority_digest,
        control_frontier,
    })
}

fn sidecar_controller_account(
    state: &AppState,
    record: &AgentSidecarRecord,
) -> Result<arkret_wire::AccountId, AppError> {
    let projection = state.projections().snapshot();
    let sidecar = projection
        .sidecars
        .get(&record.sidecar_id)
        .filter(|sidecar| sidecar.realm_id == record.realm_id)
        .ok_or_else(|| AppError::not_found("Sidecar not found"))?;
    if sidecar.controller_account_id != record.controller_account_id {
        return Err(AppError::internal(
            "Sidecar controller Account binding is invalid",
        ));
    }
    Ok(record.controller_account_id.clone())
}

pub(crate) async fn expected_sidecar_mls_binding(
    state: &AppState,
    record: &AgentSidecarRecord,
) -> Result<SidecarMlsBinding, AppError> {
    let controller = sidecar_controller_account(state, record)?;
    let desired = derive_sidecar_desired_agent_ids(state, &record.realm_id, &controller).await?;
    let desired_typed = typed_agent_ids(&desired)?;
    let projection = state.projections().snapshot();
    sidecar_mls_binding_for_desired(record, &desired_typed, &projection)
}

/// Admission gate for `ak.agent.sidecar.exchange.control`. The Event is legal
/// only for an attached native Sidecar source context and only from that
/// Sidecar's controller; the service never decrypts the control plaintext. Every
/// failure returns one uniform reason so unauthorized callers cannot probe
/// Sidecar existence.
pub(crate) fn validate_sidecar_exchange_control_event(
    state: &AppState,
    operation: &Operation,
) -> Result<(), &'static str> {
    if operation.event_kind.as_str() != arkret_wire::EventKind::AgentSidecarExchangeControl.as_str()
    {
        return Ok(());
    }
    const REASON: &str = "sidecar_exchange_control_forbidden";
    let mut wire_payload = operation.payload.clone();
    if let Some(object) = wire_payload.as_object_mut() {
        for field in ["event_id", "sender", "hlc"] {
            object.remove(field);
        }
    }
    let payload = serde_json::from_value::<AgentSidecarExchangeControlPayload>(wire_payload)
        .map_err(|_| REASON)?;
    let projection = state.projections().snapshot();
    let sidecar = projection
        .sidecars
        .get(payload.sidecar_id.as_str())
        .ok_or(REASON)?;
    let normalized_context_ref =
        serde_json::to_value(&payload.source_context_ref).map_err(|_| REASON)?;
    if operation.context.sender.as_account_id() != Some(&sidecar.controller_account_id)
        || sidecar.realm_id != operation.realm_id.as_str()
        || !projection.sidecar_contexts.values().any(|context| {
            context.sidecar_id == payload.sidecar_id.as_str()
                && context.normalized_context_ref == normalized_context_ref
        })
    {
        return Err(REASON);
    }
    Ok(())
}

pub(crate) async fn validate_sidecar_mls_event_binding(
    state: &AppState,
    controller_device_id: &str,
    operation: &Operation,
) -> Result<(), &'static str> {
    if !matches!(
        &operation.event_kind,
        arkret_wire::EventKind::MlsGenesis
            | arkret_wire::EventKind::MlsProposal
            | arkret_wire::EventKind::MlsCommit
    ) {
        return Ok(());
    }
    // Public MLS events name the binding `governance_binding`.
    let binding_value = crate::routing::mls::payload_fields::governance_binding(&operation.payload)
        .ok_or("mls_governance_binding_missing")?;
    let binding = serde_json::from_value::<MlsGovernanceBindingPayload>(binding_value.clone())
        .map_err(|_| "mls_governance_binding_invalid")?;
    let sidecar_for_scope = binding.sidecar_id().and_then(|sidecar_id| {
        state
            .projections()
            .snapshot()
            .sidecars
            .get(sidecar_id.as_str())
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
    let _sidecar_guard = lock_sidecar_ensure(&record.realm_id, &record.controller_account_id).await;
    let expected = expected_sidecar_mls_binding(state, &record)
        .await
        .map_err(|_| "mls_sidecar_binding_state_unavailable")?;
    if supplied != &expected {
        return Err("mls_sidecar_binding_stale");
    }
    let payload_group_id = crate::routing::mls::payload_fields::mls_group_id(&operation.payload)
        .ok_or("mls_group_id_missing")?;
    if binding.mls_group_id() != payload_group_id {
        return Err("mls_sidecar_binding_mismatch");
    }
    let expected_scope = json!({
        "kind": "sidecar",
        "realm_id": sidecar_projection.realm_id,
        "sidecar_id": sidecar_projection.sidecar_id,
    });
    let current_group = state
        .projections()
        .snapshot()
        .mls_commit_epochs
        .values()
        .filter(|row| row.effective_scope == expected_scope)
        .max_by_key(|row| row.epoch)
        .map(|row| row.group_id.clone());
    match operation.event_kind.clone() {
        arkret_wire::EventKind::MlsGenesis => {
            if current_group.is_some()
                || operation.context.sender.as_account_id()
                    != Some(&sidecar_projection.controller_account_id)
                || !device_coordinates_match(
                    operation
                        .context
                        .producer_device_id
                        .as_ref()
                        .map(|device_id| device_id.as_str()),
                    controller_device_id,
                )
            {
                return Err("mls_sidecar_genesis_authority_mismatch");
            }
        }
        _ if current_group.as_deref() != Some(payload_group_id.as_str()) => {
            return Err("mls_sidecar_group_mismatch");
        }
        _ => {}
    }
    Ok(())
}

fn device_coordinates_match(projected: Option<&str>, authenticated: &str) -> bool {
    !authenticated.is_empty()
        && projected.is_some_and(|projected| !projected.is_empty() && projected == authenticated)
}

/// The second `current_controller_device_ready` disjunct of
/// `agent-operations.schema.json#/$defs/agent_sidecar_mls_context`.
///
/// A controller device that did not create the accepted Sidecar genesis is
/// ready once it has completed matching Welcome and KeyPackage consume
/// evidence for this exact group: a Welcome addressed to that device admitting
/// it into `group_id`, whose claimed KeyPackage belongs to the same device and
/// carries a consume record for the same group. Evidence from another Sidecar's
/// group never satisfies this (`models/sidecar.md` section 5).
fn controller_device_completed_group_join(
    _projection: &soland_domain::reducer::ProjectionState,
    _controller_account_id: &arkret_wire::AccountId,
    _controller_device_id: &str,
    _group_id: &str,
) -> bool {
    // Formal delivery current/read/ACK is wired by 0366. The legacy Realm
    // Event projection must never make another controller device ready.
    false
}

fn epoch_matches_sidecar_binding(
    row: &soland_domain::reducer::MlsCommitEpoch,
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
    session: &SessionRecord,
) -> Result<AgentSidecarView, AppError> {
    let controller_actor =
        crate::routing::identity::session_actor::session_actor_from_credential(state, session)?;
    let controller_account = sidecar_controller_account(state, record)?;
    if controller_actor.as_account_id() != Some(&controller_account) {
        return Err(AppError::not_found("Sidecar not found"));
    }
    let controller_device_id = session.device_id.as_str();
    let desired =
        derive_sidecar_desired_agent_ids(state, &record.realm_id, &controller_account).await?;
    let desired_typed = typed_agent_ids(&desired)?;
    let projection = state.projections().snapshot();
    let expected_binding = sidecar_mls_binding_for_desired(record, &desired_typed, &projection)?;
    let expected_scope = json!({
        "kind": "sidecar",
        "realm_id": record.realm_id,
        "sidecar_id": record.sidecar_id,
    });
    let epoch_row = projection
        .mls_commit_epochs
        .values()
        .filter(|row| row.effective_scope == expected_scope)
        .max_by_key(|row| row.epoch);
    let epoch_binding_current =
        epoch_row.is_some_and(|row| epoch_matches_sidecar_binding(row, &expected_binding));
    let genesis_actor = if let Some(row) = epoch_row {
        state
            .event_queries()
            .canonical_event(&row.genesis_event_ref)
            .await
            .map_err(|error| AppError::internal(format!("Sidecar genesis lookup: {error}")))?
            .and_then(|event| serde_json::from_str::<arkret_wire::ActorId>(&event.actor_id).ok())
    } else {
        None
    };
    let controller_device_ready = epoch_binding_current
        && !controller_device_id.is_empty()
        && epoch_row.is_some_and(|row| {
            (genesis_actor.as_ref() == Some(&controller_actor)
                && device_coordinates_match(Some(&row.creator_device_id), controller_device_id))
                || controller_device_completed_group_join(
                    &projection,
                    &controller_account,
                    controller_device_id,
                    &row.group_id,
                )
        });
    let effective = if epoch_binding_current {
        desired_typed.clone()
    } else {
        Vec::new()
    };
    let pending = if epoch_binding_current {
        Vec::new()
    } else {
        desired
            .iter()
            .cloned()
            .map(|agent_id| {
                Ok(PendingSidecarAccessReconciliation {
                    agent_id: arkret_wire::DidCoreId::new(agent_id)
                        .map_err(|error| AppError::internal(format!("stored Agent id: {error}")))?,
                    provisioning_phase: if epoch_row.is_some() {
                        PendingSidecarAccessReconciliationStage::EpochRotation
                    } else {
                        PendingSidecarAccessReconciliationStage::MlsWelcome
                    },
                    membership_frontier: None,
                })
            })
            .collect::<Result<Vec<_>, AppError>>()?
    };
    let access_readiness = sidecar_access_readiness(
        &pending,
        epoch_row.is_some(),
        controller_device_ready,
        epoch_row.is_some() && !epoch_binding_current,
    );
    let mls_context = AgentSidecarMlsContext {
        participant_authority_digest: expected_binding.participant_authority_digest.clone(),
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

fn sidecar_context_for_realm(
    realm_id: &RealmId,
    context_ref: &SidecarContextRef,
) -> AgentSidecarContextRef {
    match context_ref {
        SidecarContextRef::Strand { strand_id } => {
            AgentSidecarContextRef::strand(realm_id.clone(), strand_id.clone())
        }
        SidecarContextRef::Relation { relation_id } => {
            AgentSidecarContextRef::relation(realm_id.clone(), relation_id.clone())
        }
    }
}

fn sidecar_event_draft(
    event: &arkret_wire::Event,
    digest_suite: arkret_canonical::DigestSuite,
) -> Result<PreparedEventDraft, AppError> {
    let unsigned_bytes = arkret_canonical::canonical_json_bytes(
        &event
            .digest_payload()
            .map_err(|error| AppError::internal(format!("Sidecar draft payload: {error}")))?,
    )
    .map_err(|error| AppError::internal(format!("Sidecar draft canonicalize: {error}")))?;
    let event_digest = Hash::new(
        event
            .event_digest_with_digest_suite(digest_suite)
            .map_err(|error| AppError::internal(format!("Sidecar draft digest: {error}")))?,
    )
    .map_err(|error| AppError::internal(format!("Sidecar draft digest invalid: {error}")))?;
    Ok(PreparedEventDraft {
        unsigned_event_bytes: arkret_wire::Base64UrlString::new(
            URL_SAFE_NO_PAD.encode(unsigned_bytes),
        )
        .map_err(|error| AppError::internal(format!("Sidecar draft bytes invalid: {error}")))?,
        event_digest,
    })
}

fn author_typed_sidecar_event<K: arkret_event_draft::EventSpec>(
    scope_ref: arkret_wire::ScopeRef,
    actor_id: arkret_wire::ActorId,
    actor_seq: u64,
    hlc: arkret_identifiers::Hlc,
    prev_refs: Vec<EventId>,
    semantic_refs: Vec<arkret_wire::SemanticRef>,
    created_at: chrono::DateTime<chrono::Utc>,
    payload: K::Payload,
    digest_suite: arkret_canonical::DigestSuite,
) -> Result<arkret_wire::AuthoredEvent, AppError> {
    TypedEventDraft::<K>::new(scope_ref, actor_id, payload)
        .map(|draft| {
            draft
                .with_prev_refs(prev_refs)
                .with_semantic_refs(semantic_refs)
        })
        .and_then(|draft| draft.author_with_digest_suite(actor_seq, hlc, created_at, digest_suite))
        .map_err(|error| AppError::internal(format!("Sidecar typed Event draft: {error}")))
}

fn sidecar_reservation_key(handle: &arkret_wire::ReservationHandle) -> String {
    format!("sidecar-reservation:{}", handle.as_str())
}

async fn store_sidecar_prepare(
    state: &AppState,
    principal_id: &str,
    idempotency_key: &str,
    request_hash: &str,
    reservation_handle: &arkret_wire::ReservationHandle,
    expires_at: chrono::DateTime<chrono::Utc>,
    outcome: &SidecarEnsureOutcome,
) -> Result<(), AppError> {
    let principal_id = arkret_wire::DidCoreId::new(principal_id.to_owned())
        .map_err(|error| AppError::internal(format!("Sidecar principal id invalid: {error}")))?;
    let response_body = serde_json::to_value(outcome)
        .map_err(|error| AppError::internal(format!("Sidecar outcome encode: {error}")))?;
    let created_at = chrono::Utc::now();
    for key in [
        idempotency_key.to_owned(),
        sidecar_reservation_key(reservation_handle),
    ] {
        state
            .jobs()
            .store_idempotency_record(soland_services::jobs::IdempotencyState {
                authenticated_actor: arkret_wire::ActorId::account(arkret_wire::AccountId::new(
                    principal_id.clone(),
                    state.service_core_id(),
                )),
                operation_id: "ak.self.agent.sidecar.command.ensure".to_owned(),
                idempotency_key: key,
                request_hash: request_hash.to_owned(),
                response_status: StatusCode::OK.as_u16().into(),
                response_body: response_body.clone(),
                created_at,
                expires_at,
            })
            .await
            .map_err(|error| AppError::internal(format!("Sidecar reservation store: {error}")))?;
    }
    Ok(())
}

async fn store_sidecar_final_outcome(
    state: &AppState,
    principal_id: &str,
    idempotency_key: &str,
    request_hash: &str,
    outcome: &SidecarEnsureOutcome,
) -> Result<(), AppError> {
    let created_at = chrono::Utc::now();
    let principal_id = arkret_wire::DidCoreId::new(principal_id.to_owned())
        .map_err(|error| AppError::internal(format!("Sidecar principal id invalid: {error}")))?;
    state
        .jobs()
        .store_idempotency_record(soland_services::jobs::IdempotencyState {
            authenticated_actor: arkret_wire::ActorId::account(arkret_wire::AccountId::new(
                principal_id,
                state.service_core_id(),
            )),
            operation_id: "ak.self.agent.sidecar.command.ensure".to_owned(),
            idempotency_key: idempotency_key.to_owned(),
            request_hash: request_hash.to_owned(),
            response_status: StatusCode::OK.as_u16().into(),
            response_body: serde_json::to_value(outcome)
                .map_err(|error| AppError::internal(format!("Sidecar outcome encode: {error}")))?,
            created_at,
            expires_at: created_at + chrono::Duration::hours(24),
        })
        .await
        .map_err(|error| AppError::internal(format!("Sidecar outcome store: {error}")))
}

async fn prepare_sidecar(
    state: &AppState,
    session: &SessionRecord,
    body: arkret_models_collaboration::sidecar_operations::SidecarEnsurePrepareRequestBody,
) -> JsonResult<SidecarEnsureOutcome> {
    let principal_id = arkret_wire::DidCoreId::new(session.actor.clone())
        .map_err(|error| AppError::internal(format!("session actor invalid: {error}")))?;
    let authenticated_controller_account_id =
        arkret_wire::AccountId::new(principal_id.clone(), state.service_core_id().clone());
    if body.controller_account_id != authenticated_controller_account_id {
        return Err(sidecar_create_denied(
            "Sidecar controller_account_id must match the authenticated session",
        ));
    }
    authorize_sidecar_ensure(state, session, body.source_realm_id.as_str()).await?;
    let context_ref = sidecar_context_for_realm(&body.source_realm_id, &body.context_ref);
    validate_sidecar_context_projection(state, &context_ref)?;
    let normalized_context_ref = serde_json::to_value(&body.context_ref).map_err(|error| {
        AppError::internal(format!("context_ref serialization failed: {error}"))
    })?;
    let normalized_context_ref_digest = arkret_canonical::canonical_sha256(&normalized_context_ref)
        .map_err(|error| AppError::internal(format!("context_ref digest failed: {error}")))?;
    let request_hash = arkret_canonical::canonical_sha256(&body)
        .map_err(|error| AppError::internal(format!("Sidecar prepare digest: {error}")))?;
    if let Some(cached) = state
        .jobs()
        .scoped_idempotency_record(
            &arkret_wire::ActorId::account(arkret_wire::AccountId::new(
                principal_id.clone(),
                state.service_core_id(),
            )),
            "ak.self.agent.sidecar.command.ensure",
            body.idempotency_key.as_str(),
        )
        .await
        .map_err(|error| AppError::internal(format!("Sidecar idempotency lookup: {error}")))?
    {
        if cached.request_hash != request_hash {
            return Err(AppError::conflict(
                "idempotency key was used for another Sidecar prepare",
            ));
        }
        let outcome = serde_json::from_value::<SidecarEnsureOutcome>(cached.response_body)
            .map_err(|error| AppError::internal(format!("stored Sidecar outcome: {error}")))?;
        return json_ok(outcome);
    }

    let _guard =
        lock_sidecar_ensure(body.source_realm_id.as_str(), &body.controller_account_id).await;
    let existing_sidecar = state
        .agent_pairings()
        .sidecar_for_realm_controller(body.source_realm_id.as_str(), &body.controller_account_id)
        .await
        .map_err(|error| AppError::internal(format!("Sidecar lookup failed: {error}")))?;
    if let Some(sidecar) = &existing_sidecar
        && let Some(_context) = state
            .agent_pairings()
            .sidecar_context(&sidecar.sidecar_id, &normalized_context_ref_digest)
            .await
            .map_err(|error| {
                AppError::internal(format!("Sidecar context lookup failed: {error}"))
            })?
    {
        return json_ok(SidecarEnsureOutcome::Accepted {
            operation_id: body.operation_id,
            accepted_phase:
                arkret_models_collaboration::sidecar_operations::SidecarAcceptedPhase::Attach,
            ok: arkret_models_collaboration::sidecar_operations::SidecarAcceptedOk,
            sidecar_id: SidecarId::new(sidecar.sidecar_id.clone())
                .map_err(|error| AppError::internal(format!("stored Sidecar id: {error}")))?,
            source_context_ref: body.context_ref,
            access_readiness: AgentSidecarAccessReadiness::KeyMaterialPending,
            pending_access_reconciliations: Vec::new(),
        });
    }

    let controller_actor =
        crate::routing::identity::session_actor::session_actor_from_credential(state, session)?;
    let digest_suite = state
        .projections()
        .realm_digest_suite(body.source_realm_id.as_str());
    let frontier = crate::routing::events::event_log::load_realm_actor_frontier(
        state,
        body.source_realm_id.clone(),
        controller_actor.clone(),
        VerifiedActorPredecessors::none(),
    )
    .await?;
    let created_at = chrono::Utc::now();
    let create_event = if existing_sidecar.is_none() {
        Some(author_typed_sidecar_event::<
            arkret_wire::event_spec::SidecarCreate,
        >(
            arkret_wire::ScopeRef::Realm {
                realm_id: body.source_realm_id.clone(),
            },
            controller_actor.clone(),
            frontier.next_actor_seq,
            arkret_identifiers::Hlc::new(state.hlc().now())
                .map_err(|error| AppError::internal(format!("Sidecar create HLC: {error}")))?,
            frontier.frontier_event_ids.clone(),
            Vec::new(),
            created_at,
            SidecarCreatePayload::default(),
            digest_suite,
        )?)
    } else {
        None
    };
    let sidecar_id = match (&existing_sidecar, &create_event) {
        (Some(record), _) => SidecarId::new(record.sidecar_id.clone())
            .map_err(|error| AppError::internal(format!("stored Sidecar id: {error}")))?,
        (None, Some(event)) => SidecarId::from_event_id(&event.event_id),
        (None, None) => unreachable!("new Sidecar always has a create Event"),
    };
    let attach_seq = frontier
        .next_actor_seq
        .checked_add(u64::from(create_event.is_some()))
        .ok_or_else(|| AppError::conflict("Sidecar actor sequence is exhausted"))?;
    let attach_event = author_typed_sidecar_event::<arkret_wire::event_spec::SidecarContextAttach>(
        arkret_wire::ScopeRef::Sidecar {
            realm_id: body.source_realm_id.clone(),
            sidecar_id: sidecar_id.clone(),
        },
        controller_actor,
        attach_seq,
        arkret_identifiers::Hlc::new(state.hlc().now())
            .map_err(|error| AppError::internal(format!("Sidecar attach HLC: {error}")))?,
        create_event.as_ref().map_or_else(
            || frontier.frontier_event_ids.clone(),
            |event| vec![event.event_id.clone()],
        ),
        create_event
            .as_ref()
            .map(|event| {
                vec![arkret_wire::SemanticRef::new(
                    event.event_id.to_string(),
                    "after",
                )]
            })
            .unwrap_or_default(),
        created_at,
        SidecarContextAttachPayload {
            sidecar_id: sidecar_id.clone(),
            source_context_ref: body.context_ref.clone(),
            version: 1,
            predecessor_event_ref: None,
        },
        digest_suite,
    )?;
    let context_attach_event_draft = sidecar_event_draft(&attach_event, digest_suite)?;
    let reservation_handle = arkret_wire::ReservationHandle::new(ids::generate("reservation"))
        .map_err(AppError::internal)?;
    let expires_at = created_at + chrono::Duration::minutes(10);
    let prepared = if let Some(create_event) = create_event {
        SidecarPreparedOutcome::New {
            operation_id: body.operation_id.clone(),
            reservation_handle: reservation_handle.clone(),
            expires_at,
            create_event_draft: sidecar_event_draft(&create_event, digest_suite)?,
            context_attach_event_draft,
        }
    } else {
        SidecarPreparedOutcome::Existing {
            operation_id: body.operation_id.clone(),
            reservation_handle: reservation_handle.clone(),
            expires_at,
            sidecar_id,
            context_attach_event_draft,
        }
    };
    let outcome = SidecarEnsureOutcome::Prepared { prepared };
    store_sidecar_prepare(
        state,
        session.actor.as_str(),
        body.idempotency_key.as_str(),
        &request_hash,
        &reservation_handle,
        expires_at,
        &outcome,
    )
    .await?;
    json_ok(outcome)
}

fn validate_signed_sidecar_draft(
    signed_event: &arkret_wire::Event,
    draft: &PreparedEventDraft,
) -> Result<(), AppError> {
    let actual_unsigned = arkret_canonical::canonical_json_bytes(
        &signed_event
            .digest_payload()
            .map_err(|error| AppError::param_invalid(format!("signed Sidecar Event: {error}")))?,
    )
    .map_err(|error| AppError::param_invalid(format!("signed Sidecar Event: {error}")))?;
    let expected_unsigned = URL_SAFE_NO_PAD
        .decode(draft.unsigned_event_bytes.as_str())
        .map_err(|_| AppError::internal("stored Sidecar draft bytes are invalid"))?;
    let digest_suite = draft
        .event_digest
        .digest_suite()
        .map_err(|error| AppError::internal(format!("stored Sidecar digest suite: {error}")))?;
    let digest = Hash::new(
        signed_event
            .event_digest_with_digest_suite(digest_suite)
            .map_err(|error| AppError::param_invalid(format!("signed Sidecar Event: {error}")))?,
    )
    .map_err(|error| AppError::param_invalid(format!("signed Sidecar Event digest: {error}")))?;
    if actual_unsigned != expected_unsigned
        || digest != draft.event_digest
        || signed_event.producer_proof.is_none()
        || signed_event
            .producer_proof
            .as_ref()
            .is_some_and(|proof| proof.event_digest != draft.event_digest)
    {
        return Err(AppError::param_invalid(
            "signed Sidecar Event does not exactly match its reservation draft",
        ));
    }
    Ok(())
}

async fn validate_sidecar_commit_reservation(
    state: &AppState,
    session: &SessionRecord,
    operation_id: &arkret_wire::ProtocolOperationId,
    reservation_handle: &arkret_wire::ReservationHandle,
    create_event: Option<&arkret_wire::Event>,
    context_attach_event: &arkret_wire::Event,
) -> Result<SidecarPreparedOutcome, AppError> {
    let principal_id = arkret_wire::DidCoreId::new(session.actor.clone())
        .map_err(|error| AppError::internal(format!("session actor invalid: {error}")))?;
    let record = state
        .jobs()
        .scoped_idempotency_record(
            &arkret_wire::ActorId::account(arkret_wire::AccountId::new(
                principal_id.clone(),
                state.service_core_id(),
            )),
            "ak.self.agent.sidecar.command.ensure",
            &sidecar_reservation_key(reservation_handle),
        )
        .await
        .map_err(|error| AppError::internal(format!("Sidecar reservation lookup: {error}")))?
        .ok_or_else(|| AppError::conflict("Sidecar reservation is missing or expired"))?;
    if record.expires_at <= chrono::Utc::now() {
        return Err(AppError::conflict("Sidecar reservation has expired"));
    }
    let outcome = serde_json::from_value::<SidecarEnsureOutcome>(record.response_body)
        .map_err(|error| AppError::internal(format!("stored Sidecar reservation: {error}")))?;
    let SidecarEnsureOutcome::Prepared { prepared } = outcome else {
        return Err(AppError::conflict(
            "Sidecar reservation is already finalized",
        ));
    };
    match &prepared {
        SidecarPreparedOutcome::New {
            operation_id: reserved_operation_id,
            reservation_handle: reserved_handle,
            create_event_draft,
            context_attach_event_draft,
            ..
        } => {
            if reserved_operation_id != operation_id || reserved_handle != reservation_handle {
                return Err(AppError::param_invalid(
                    "Sidecar reservation binding mismatch",
                ));
            }
            let create_event = create_event.ok_or_else(|| {
                AppError::param_invalid("new Sidecar commit requires create_event")
            })?;
            validate_signed_sidecar_draft(create_event, create_event_draft)?;
            validate_signed_sidecar_draft(context_attach_event, context_attach_event_draft)?;
        }
        SidecarPreparedOutcome::Existing {
            operation_id: reserved_operation_id,
            reservation_handle: reserved_handle,
            context_attach_event_draft,
            ..
        } => {
            if reserved_operation_id != operation_id || reserved_handle != reservation_handle {
                return Err(AppError::param_invalid(
                    "Sidecar reservation binding mismatch",
                ));
            }
            if create_event.is_some() {
                return Err(AppError::param_invalid(
                    "existing Sidecar attach must not carry create_event",
                ));
            }
            validate_signed_sidecar_draft(context_attach_event, context_attach_event_draft)?;
        }
    }
    Ok(prepared)
}

fn sidecar_prepared_sidecar_id(prepared: &SidecarPreparedOutcome) -> Result<SidecarId, AppError> {
    match prepared {
        SidecarPreparedOutcome::New {
            create_event_draft, ..
        } => create_event_draft
            .event_id()
            .map(|event_id| SidecarId::from_event_id(&event_id))
            .map_err(|error| AppError::internal(format!("stored Sidecar draft: {error}"))),
        SidecarPreparedOutcome::Existing { sidecar_id, .. } => Ok(sidecar_id.clone()),
    }
}

async fn finalize_sidecar_projection_records(
    state: &AppState,
    session: &SessionRecord,
    prepared: &SidecarPreparedOutcome,
    context_attach_event: &arkret_wire::Event,
) -> Result<(), AppError> {
    let sidecar_id = sidecar_prepared_sidecar_id(prepared)?;
    let created_at = context_attach_event.created_at;
    state
        .agent_pairings()
        .ensure_sidecar(AgentSidecarRecord {
            sidecar_id: sidecar_id.to_string(),
            realm_id: context_attach_event.realm_id.to_string(),
            controller_account_id: arkret_wire::AccountId::new(
                arkret_wire::DidCoreId::new(session.actor.clone()).map_err(|error| {
                    AppError::internal(format!("session actor invalid: {error}"))
                })?,
                state.service_core_id().clone(),
            ),
            state: AgentSidecarState::Active,
            state_changed_at: None,
            created_at,
            updated_at: None,
        })
        .await
        .map_err(|error| AppError::internal(format!("Sidecar projection persistence: {error}")))?;
    let payload = serde_json::from_value::<SidecarContextAttachPayload>(
        serde_json::to_value(&context_attach_event.payload)
            .map_err(|error| AppError::internal(format!("accepted Sidecar payload: {error}")))?,
    )
    .map_err(|error| AppError::internal(format!("accepted Sidecar context payload: {error}")))?;
    let normalized_context_ref = serde_json::to_value(&payload.source_context_ref)
        .map_err(|error| AppError::internal(format!("accepted Sidecar context ref: {error}")))?;
    let normalized_context_ref_digest = arkret_canonical::canonical_sha256(&normalized_context_ref)
        .map_err(|error| AppError::internal(format!("accepted Sidecar context digest: {error}")))?;
    state
        .agent_pairings()
        .ensure_sidecar_context(AgentSidecarContextRecord {
            sidecar_id: sidecar_id.to_string(),
            normalized_context_ref_digest,
            normalized_context_ref,
            version: i64::try_from(payload.version)
                .map_err(|_| AppError::internal("Sidecar context version exceeds i64"))?,
            predecessor_event_ref: payload.predecessor_event_ref.map(|id| id.to_string()),
            attach_event_ref: context_attach_event.event_id.to_string(),
            created_at,
        })
        .await
        .map(|_| ())
        .map_err(|error| AppError::internal(format!("Sidecar context persistence: {error}")))
}

async fn ensure_sidecar_impl(
    aa: AuthArgs,
    body: SidecarEnsureRequestBody,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<SidecarEnsureOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let principal_id = arkret_wire::DidCoreId::new(session.actor.clone())
        .map_err(|error| AppError::internal(format!("session actor invalid: {error}")))?;
    match body {
        SidecarEnsureRequestBody::Prepare(body) => prepare_sidecar(state, &session, body).await,
        SidecarEnsureRequestBody::Commit(body) => {
            let request_hash = arkret_canonical::canonical_sha256(&body)
                .map_err(|error| AppError::internal(format!("Sidecar commit digest: {error}")))?;
            if let Some(cached) = state
                .jobs()
                .scoped_idempotency_record(
                    &arkret_wire::ActorId::account(arkret_wire::AccountId::new(
                        principal_id.clone(),
                        state.service_core_id(),
                    )),
                    "ak.self.agent.sidecar.command.ensure",
                    body.idempotency_key.as_str(),
                )
                .await
                .map_err(|error| AppError::internal(format!("Sidecar commit replay: {error}")))?
            {
                if cached.request_hash != request_hash {
                    return Err(AppError::conflict(
                        "idempotency key was used for another Sidecar commit",
                    ));
                }
                return json_ok(
                    serde_json::from_value(cached.response_body).map_err(|error| {
                        AppError::internal(format!("stored Sidecar commit outcome: {error}"))
                    })?,
                );
            }
            let prepared = validate_sidecar_commit_reservation(
                state,
                &session,
                &body.operation_id,
                &body.reservation_handle,
                Some(&body.create_event),
                &body.context_attach_event,
            )
            .await?;
            authorize_sidecar_ensure(state, &session, body.create_event.realm_id.as_str()).await?;
            crate::routing::events::event_log::submit_sidecar_ensure_batch(
                state,
                &session,
                Some(body.create_event),
                body.context_attach_event.clone(),
            )
            .await
            .map_err(|error| {
                crate::app_error!(FailedPrecondition, error.message())
                    .with_rejection_code(error.code())
            })?;
            finalize_sidecar_projection_records(
                state,
                &session,
                &prepared,
                &body.context_attach_event,
            )
            .await?;
            let sidecar_id = sidecar_prepared_sidecar_id(&prepared)?;
            let source_context_ref = body
                .context_attach_event
                .typed_payload::<arkret_wire::event_spec::SidecarContextAttach>()
                .map_err(|error| AppError::internal(format!("accepted Sidecar context: {error}")))?
                .source_context_ref;
            let outcome = SidecarEnsureOutcome::Accepted {
                operation_id: body.operation_id,
                accepted_phase:
                    arkret_models_collaboration::sidecar_operations::SidecarAcceptedPhase::Commit,
                ok: arkret_models_collaboration::sidecar_operations::SidecarAcceptedOk,
                sidecar_id: sidecar_id.clone(),
                source_context_ref,
                access_readiness: AgentSidecarAccessReadiness::KeyMaterialPending,
                pending_access_reconciliations: Vec::new(),
            };
            store_sidecar_final_outcome(
                state,
                session.actor.as_str(),
                body.idempotency_key.as_str(),
                &request_hash,
                &outcome,
            )
            .await?;
            json_ok(outcome)
        }
        SidecarEnsureRequestBody::Attach(body) => {
            let request_hash = arkret_canonical::canonical_sha256(&body)
                .map_err(|error| AppError::internal(format!("Sidecar attach digest: {error}")))?;
            if let Some(cached) = state
                .jobs()
                .scoped_idempotency_record(
                    &arkret_wire::ActorId::account(arkret_wire::AccountId::new(
                        principal_id.clone(),
                        state.service_core_id(),
                    )),
                    "ak.self.agent.sidecar.command.ensure",
                    body.idempotency_key.as_str(),
                )
                .await
                .map_err(|error| AppError::internal(format!("Sidecar attach replay: {error}")))?
            {
                if cached.request_hash != request_hash {
                    return Err(AppError::conflict(
                        "idempotency key was used for another Sidecar attach",
                    ));
                }
                return json_ok(
                    serde_json::from_value(cached.response_body).map_err(|error| {
                        AppError::internal(format!("stored Sidecar attach outcome: {error}"))
                    })?,
                );
            }
            let prepared = validate_sidecar_commit_reservation(
                state,
                &session,
                &body.operation_id,
                &body.reservation_handle,
                None,
                &body.context_attach_event,
            )
            .await?;
            authorize_sidecar_ensure(state, &session, body.context_attach_event.realm_id.as_str())
                .await?;
            crate::routing::events::event_log::submit_sidecar_ensure_batch(
                state,
                &session,
                None,
                body.context_attach_event.clone(),
            )
            .await
            .map_err(|error| {
                crate::app_error!(FailedPrecondition, error.message())
                    .with_rejection_code(error.code())
            })?;
            finalize_sidecar_projection_records(
                state,
                &session,
                &prepared,
                &body.context_attach_event,
            )
            .await?;
            let sidecar_id = sidecar_prepared_sidecar_id(&prepared)?;
            let source_context_ref = body
                .context_attach_event
                .typed_payload::<arkret_wire::event_spec::SidecarContextAttach>()
                .map_err(|error| AppError::internal(format!("accepted Sidecar context: {error}")))?
                .source_context_ref;
            let outcome = SidecarEnsureOutcome::Accepted {
                operation_id: body.operation_id,
                accepted_phase:
                    arkret_models_collaboration::sidecar_operations::SidecarAcceptedPhase::Attach,
                ok: arkret_models_collaboration::sidecar_operations::SidecarAcceptedOk,
                sidecar_id: sidecar_id.clone(),
                source_context_ref,
                access_readiness: AgentSidecarAccessReadiness::KeyMaterialPending,
                pending_access_reconciliations: Vec::new(),
            };
            store_sidecar_final_outcome(
                state,
                session.actor.as_str(),
                body.idempotency_key.as_str(),
                &request_hash,
                &outcome,
            )
            .await?;
            json_ok(outcome)
        }
    }
}

#[salvo::oapi::endpoint(
    operation_id = "ak.self.agent.sidecar.command.ensure",
    tags("identity")
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.agent.sidecar.command.ensure.v1"))]
pub(super) async fn ensure_sidecar(
    aa: AuthArgs,
    body: JsonBody<SidecarEnsureRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<SidecarEnsureOutcome> {
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
    let controller_account_id = arkret_wire::AccountId::new(
        arkret_wire::DidCoreId::new(session.actor.clone())
            .map_err(|error| AppError::internal(format!("session actor invalid: {error}")))?,
        state.service_core_id().clone(),
    );
    let record = state
        .agent_pairings()
        .sidecar(sidecar_id.as_str())
        .await
        .map_err(|error| AppError::internal(format!("Sidecar lookup failed: {error}")))?
        .filter(|record| record.controller_account_id == controller_account_id)
        .ok_or_else(|| AppError::not_found("Sidecar not found"))?;
    json_ok(sidecar_view(state, &record, &session).await?)
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
    let controller_account_id = arkret_wire::AccountId::new(
        arkret_wire::DidCoreId::new(session.actor.clone())
            .map_err(|error| AppError::internal(format!("session actor invalid: {error}")))?,
        state.service_core_id().clone(),
    );
    let mut records = state
        .agent_pairings()
        .sidecars_for_controller(
            &controller_account_id,
            realm_id.as_ref().map(RealmId::as_str),
        )
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
        items.push(sidecar_view(state, &record, &session).await?);
    }
    json_ok(AgentSidecarList {
        sidecars: items,
        next_cursor,
    })
}

#[cfg(test)]
mod tests {
    use chrono::{TimeZone as _, Timelike as _};

    use super::*;

    #[test]
    fn prepared_create_event_is_content_bound_and_derives_sidecar_id() {
        let created_at = chrono::Utc
            .with_ymd_and_hms(2026, 7, 20, 12, 34, 56)
            .unwrap()
            .with_nanosecond(987_654_321)
            .unwrap();
        let realm_id =
            RealmId::new("ak:realm:AQcksDTzb8Sxrn1BUVVlHtH4vBOy99RKUB4EwOq_413b".to_owned())
                .unwrap();
        let event = author_typed_sidecar_event::<arkret_wire::event_spec::SidecarCreate>(
            arkret_wire::ScopeRef::Realm { realm_id },
            arkret_wire::ActorId::account(arkret_wire::AccountId::new(
                crate::test_actor_id_str("did:web:example.com:users:alice"),
                crate::test_event::station_id(),
            )),
            1,
            arkret_identifiers::Hlc::new("01970e589d21-0000-a13f9c2e").unwrap(),
            Vec::new(),
            Vec::new(),
            created_at,
            SidecarCreatePayload::default(),
            arkret_canonical::DigestSuite::Sha256,
        )
        .unwrap();
        event
            .verify_event_id_matches_content_with_digest_suite(
                arkret_canonical::DigestSuite::Sha256,
            )
            .unwrap();
        let sidecar_id = SidecarId::from_event_id(&event.event_id);
        assert_eq!(
            sidecar_id.as_str().strip_prefix("ak:sidecar:"),
            event.event_id.as_str().strip_prefix("ak:event:")
        );
        assert_eq!(
            event.payload.get("encryption_profile"),
            Some(&json!("mls_rfc9420"))
        );
        assert!(!event.payload.contains_key("object"));
    }

    #[test]
    fn context_attach_contains_only_the_native_source_mapping() {
        let payload = serde_json::to_value(SidecarContextAttachPayload {
            sidecar_id: SidecarId::new("ak:sidecar:AcweNVvZUYNuOdCMey9HT7PQHKPbHPJwOFTgn_cx7yjo")
                .unwrap(),
            source_context_ref: SidecarContextRef::Strand {
                strand_id: arkret_identifiers::StrandId::new(
                    "ak:strand:ATxk9k3t-DqTNiiB9n8GoSjjar3vZJvO3Dtpd1SzdHZF",
                )
                .unwrap(),
            },
            version: 1,
            predecessor_event_ref: None,
        });
        let payload = payload.unwrap();
        assert_eq!(
            payload.pointer("/source_context_ref/kind"),
            Some(&json!("strand"))
        );
        assert!(payload.get("private_strand").is_none());
        assert!(payload.get("relation").is_none());
    }

    #[test]
    fn empty_agent_reconciliation_does_not_prove_controller_device_readiness() {
        assert_eq!(
            sidecar_access_readiness(&[], false, false, false),
            AgentSidecarAccessReadiness::KeyMaterialPending
        );
    }

    #[test]
    fn sidecar_membership_uses_exact_projected_actor_not_directory_principal() {
        let state = AppState::new(
            crate::config::AppConfig::test_default(),
            soland_storage_postgres::Db { pool: None },
        );
        let realm_id = "ak:realm:AQcksDTzb8Sxrn1BUVVlHtH4vBOy99RKUB4EwOq_413b";
        let principal = DidCoreId::new("ak:did_core:web:alice.example").unwrap();
        let local_actor = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
            principal.clone(),
            state.service_core_id(),
        ));
        let foreign_actor = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
            principal.clone(),
            DidCoreId::new("ak:did_core:web:other-station.example").unwrap(),
        ));
        let mut directory = soland_services::events::RealmDirectoryEntry::new(
            RealmId::new(realm_id).unwrap(),
            "discovery only",
            soland_services::events::DirectoryProvenance::LocalOnly,
        );
        directory.members.insert(principal.clone());
        state.realm_directory().upsert(directory);
        assert!(!realm_member_joined(
            &state,
            realm_id,
            &local_actor.to_string()
        ));
        let now = chrono::Utc::now();
        state.test_projection().lock().members.insert(
            (realm_id.to_owned(), local_actor.to_string()),
            soland_domain::reducer::SolandMembershipState {
                member: local_actor.to_string(),
                realm_id: realm_id.to_owned(),
                state: "join".to_owned(),
                role: "member".to_owned(),
                membership_event_ref: None,
                invited_at: None,
                joined_at: now,
                updated_at: now,
                reason: None,
            },
        );
        assert!(realm_member_joined(
            &state,
            realm_id,
            &local_actor.to_string()
        ));
        assert!(!realm_member_joined(
            &state,
            realm_id,
            &foreign_actor.to_string()
        ));
        assert!(!realm_member_joined(&state, realm_id, principal.as_str()));
        assert_eq!(
            realm_members_for_authz(&state, realm_id),
            vec![local_actor.to_string()]
        );
    }

    #[test]
    fn absent_device_coordinates_never_match() {
        assert!(!device_coordinates_match(None, ""));
        assert!(!device_coordinates_match(Some(""), ""));
        assert!(!device_coordinates_match(
            None,
            "ak:device:01904100-0000-7000-8000-a11ce0000001"
        ));
        assert!(device_coordinates_match(
            Some("ak:device:01904100-0000-7000-8000-a11ce0000001"),
            "ak:device:01904100-0000-7000-8000-a11ce0000001"
        ));
    }

    #[test]
    fn welcome_pending_takes_precedence_over_key_material() {
        let pending = PendingSidecarAccessReconciliation {
            agent_id: DidCoreId::new("ak:did_core:web:example.com:agents:assistant".to_owned())
                .unwrap(),
            provisioning_phase: PendingSidecarAccessReconciliationStage::MlsWelcome,
            membership_frontier: None,
        };

        assert_eq!(
            sidecar_access_readiness(&[pending], true, true, false),
            AgentSidecarAccessReadiness::KeyMaterialPending
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
        let pending = PendingSidecarAccessReconciliation {
            agent_id: DidCoreId::new("ak:did_core:web:example.com:agents:assistant".to_owned())
                .unwrap(),
            provisioning_phase: PendingSidecarAccessReconciliationStage::MlsRemove,
            membership_frontier: Some(vec![
                EventId::new("ak:event:AS8XThowW7JnZc80U10gJh-_lqkA-iSQ-LAvBXj6_9O5").unwrap(),
            ]),
        };

        assert_eq!(
            sidecar_access_readiness(&[pending], true, true, false),
            AgentSidecarAccessReadiness::EpochUpdateRequired
        );
    }

    #[test]
    fn native_sidecar_governance_binding_uses_sidecar_scope() {
        let value = json!({
            "binding_version": 1,
            "encoding_profile": "cbor-deterministic-rfc8949-v1",
            "realm_id": "ak:realm:AQcksDTzb8Sxrn1BUVVlHtH4vBOy99RKUB4EwOq_413b",
            "sidecar_id": "ak:sidecar:AcweNVvZUYNuOdCMey9HT7PQHKPbHPJwOFTgn_cx7yjo",
            "effective_scope": {
                "kind": "sidecar",
                "realm_id": "ak:realm:AQcksDTzb8Sxrn1BUVVlHtH4vBOy99RKUB4EwOq_413b",
                "sidecar_id": "ak:sidecar:AcweNVvZUYNuOdCMey9HT7PQHKPbHPJwOFTgn_cx7yjo"
            },
            "mls_group_id": "YXJrcmV0LW1scy10ZXN0LWdyb3Vw",
            "previous_epoch": 0,
            "next_epoch": 1,
            "security_frontier_digest": format!("sha256:{}", "1".repeat(64)),
            "content_scheme": "mls_rfc9420",
            "binding_profile": "ak.profile.mls_governance_binding.full.v1",
            "reducer_profile": "ak.reducer.core.v1",
            "sidecar_binding": {
                "sidecar_id": "ak:sidecar:AcweNVvZUYNuOdCMey9HT7PQHKPbHPJwOFTgn_cx7yjo",
                "participant_authority_digest": format!("sha256:{}", "4".repeat(64)),
                "control_frontier": ["ak:event:AbLN8Zik9Z7ZJiPG_sNwMk4iV0JGKAnWmyOB0FKWVGCV"]
            }
        });
        let binding = serde_json::from_value::<MlsGovernanceBindingPayload>(value).unwrap();
        assert_eq!(
            binding.sidecar_id().map(|id| id.as_str()),
            Some("ak:sidecar:AcweNVvZUYNuOdCMey9HT7PQHKPbHPJwOFTgn_cx7yjo")
        );
        assert!(matches!(
            binding.effective_scope(),
            arkret_wire::ScopeRef::Sidecar { .. }
        ));
    }
}
