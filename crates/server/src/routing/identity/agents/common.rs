use super::*;

/// Narrow internal execution context used only after the caller has authenticated
/// the deployment S2S credential and the handler has re-validated the claimed
/// controller against the authoritative Agent record.
pub(super) fn controller_service_session(controller_id: &str, state: &AppState) -> SessionRecord {
    SessionRecord {
        token_hash: format!("agent-pair-commit:{controller_id}"),
        actor: controller_id.to_owned(),
        device_id: "agent-pair-commit".to_owned(),
        audience: state.config.service_id.clone(),
        session_public_key: None,
        agent_session: None,
        expires_at: now() + chrono::Duration::minutes(5),
        created_at: now(),
        revoked_at: None,
    }
}

/// Submit a controller-signed delegated Event through the normal Event
/// admission pipeline with the Agent as the envelope actor. The pairing
/// handler validates the controller/delegation/PCR bindings before creating
/// this context; signature validation still runs in the shared pipeline.
pub(super) fn delegated_agent_session(
    controller_session: &SessionRecord,
    agent_id: &str,
) -> SessionRecord {
    let mut session = controller_session.clone();
    session.token_hash = format!(
        "agent-delegated-event:{}:{agent_id}",
        controller_session.token_hash
    );
    session.actor = agent_id.to_owned();
    session
}

pub(super) fn validate_agent_id(value: &str) -> Result<(), AppError> {
    if validate_did(value).is_err() {
        return Err(AppError::invalid_param("agent_id must be a DID scalar"));
    }
    Ok(())
}

pub(super) fn ensure_agent_record_controller(
    record: &AgentPrincipalRecord,
    agent_id: &str,
    session: &SessionRecord,
) -> Result<(), AppError> {
    if record.id != agent_id {
        return Err(AppError::capability_denied(
            "agent principal record does not match the requested principal",
        ));
    }
    if record.controller_id.trim().is_empty() {
        return Err(AppError::capability_denied(
            "agent principal has no controller binding",
        ));
    }
    if record.controller_id != session.actor {
        return Err(AppError::capability_denied(
            "agent principal is not controlled by the authenticated session",
        ));
    }
    Ok(())
}

pub(super) async fn require_agent_controller(
    state: &AppState,
    session: &SessionRecord,
    agent_id: &str,
) -> Result<AgentPrincipalRecord, AppError> {
    validate_agent_id(agent_id)?;
    let record = state
        .persistence
        .agents()
        .get(agent_id)
        .await
        .map_err(|err| AppError::internal(format!("agent controller lookup failed: {err}")))?
        .ok_or_else(|| AppError::capability_denied("agent principal has no controller binding"))?;
    ensure_agent_record_controller(&record, agent_id, session)?;
    Ok(record)
}

pub(super) fn ensure_sidecar_controller_request(
    body: &AgentSidecarThreadEnsureRequestBody,
    session: &SessionRecord,
) -> Result<(), AppError> {
    if body.controller_id.as_str() != session.actor.as_str() {
        return Err(sidecar_create_denied(
            "sidecar controller_id must match the authenticated session",
        ));
    }
    Ok(())
}

pub(super) fn verification_method_principal(verification_method: &str) -> &str {
    verification_method
        .split('#')
        .next()
        .unwrap_or("")
        .split('?')
        .next()
        .unwrap_or("")
}

/// Mint a `did:webvh` principal DID for a server-provisioned agent.
///
/// did:webvh-only red line: agent principals MUST NOT use `did:web` (no
/// key-log history). The DID host is the deployment's real service host
/// (derived from the configured `service_id`), never a `.agents.example`
/// placeholder. The SCID is a self-certifying multihash derived from a
/// per-agent genesis skeleton so the identifier is bound to its inception
/// material rather than being an opaque random string.
pub(super) fn generate_agent_principal_did(service_id: &str) -> String {
    let host = crate::config::did_host_from_service_id(service_id)
        .unwrap_or_else(|| "soland.local".to_owned());
    let agent_uuid = uuid::Uuid::now_v7();
    // Genesis skeleton: the SCID is the multihash of this canonical structure
    // with the SCID field left as the placeholder, matching the did:webvh SCID
    // derivation used elsewhere in soland.
    let skeleton = serde_json::json!({
        "scid": "{SCID}",
        "host": host,
        "path": format!("webvh:agent:{agent_uuid}"),
    });
    let scid =
        crate::routing::identity::webvh_validation::derive_webvh_scid_from_skeleton(&skeleton)
            .unwrap_or_else(|_| agent_uuid.simple().to_string());
    format!("did:webvh:{scid}:{host}:webvh:agent:{agent_uuid}")
}

/// Project a persisted agent_principal JSON record into the spec
/// `agent_projection` shape (`agent-operations.schema.json#/$defs/agent_projection`):
/// `{agent_id, display_name?, slug, avatar_blob_ref?, status, created_at?, updated_at?}`.
/// Soland-internal columns (`controller_id`, `pairing_*`) are NOT
/// part of the protocol projection and are dropped at the wire boundary; the
/// persistence `state` column carries the `agent_status` enum value verbatim.
pub(super) fn agent_projection_from_record(record: &AgentPrincipalRecord) -> AgentProjection {
    let status = match record.state.as_str() {
        "pending_runtime_key" => AgentStatus::PendingRuntimeKey,
        "pairing_expired" => AgentStatus::PairingExpired,
        "paused" => AgentStatus::Paused,
        "deactivated" => AgentStatus::Deactivated,
        _ => AgentStatus::Active,
    };
    AgentProjection {
        agent_id: Did::new(record.id.clone())
            .unwrap_or_else(|_| Did::new("did:webvh:invalid:invalid").expect("static did")),
        display_name: record.display_name.clone().filter(|value| !value.is_empty()),
        slug: record.agent_slug.clone().unwrap_or_default(),
        avatar_blob_ref: record
            .avatar_blob_ref
            .as_ref()
            .filter(|value| !value.is_empty())
            .and_then(|value| BlobRef::new(value.clone()).ok()),
        status,
        created_at: Some(record.created_at),
        updated_at: Some(record.updated_at),
    }
}

/// Build the spec `agent_view` (`agent-operations.schema.json#/$defs/agent_view`)
/// from a persisted record: `{agent: <agent_projection>, status, grants[], key_state}`.
/// The `agent`/`status` pair is required. `grants` defaults empty here — the
/// `get_agent` read path overlays it from the authz projection
/// (`grants_for_subject_all_realms`) so the controller UI sees live grants.
pub(super) async fn agent_view_from_record(
    state: &AppState,
    record: &AgentPrincipalRecord,
) -> Result<AgentView, AppError> {
    let agent = agent_projection_from_record(record);
    let active_authorizations = active_agent_key_authorizations(state, &record.id)?;
    let pcr_recovery =
        crate::routing::identity::managed_agent_pcr::project_agent_pcr_recovery(state, record)
            .await?;
    let key_state = agent_key_state_from_record(record, pcr_recovery, active_authorizations)?;
    Ok(AgentView {
        status: agent.status,
        agent,
        grants: Vec::new(),
        key_state: Some(key_state),
    })
}

pub(super) fn agent_key_state_from_record(
    record: &AgentPrincipalRecord,
    pcr_recovery: arkret_sdk::AgentPcrRecoveryState,
    active_authorizations: Vec<arkret_sdk::AgentKeyAuthorizationState>,
) -> Result<KeyState, AppError> {
    let requested_scope = record
        .requested_scope
        .clone()
        .map(serde_json::from_value)
        .transpose()
        .map_err(|error| AppError::internal(format!("persisted Agent scope is invalid: {error}")))?;
    let authorized_event_ref = record
        .authorized_event_ref
        .as_ref()
        .map(|value| EventId::new(value.clone()))
        .transpose()
        .map_err(|error| {
            AppError::internal(format!("persisted Agent authorization Event is invalid: {error}"))
        })?;
    Ok(KeyState {
        agent_id: Did::new(record.id.clone())
            .map_err(|error| AppError::internal(format!("persisted Agent DID is invalid: {error}")))?,
        controller_id: Did::new(record.controller_id.clone()).map_err(|error| {
            AppError::internal(format!("persisted Agent controller DID is invalid: {error}"))
        })?,
        principal_control_realm_id: RealmId::new(record.principal_control_realm_id.clone())
            .map_err(|error| AppError::internal(format!("persisted Agent PCR is invalid: {error}")))?,
        controller_authorization_ref: record.controller_authorization_ref.clone(),
        status: agent_projection_from_record(record).status,
        pcr_recovery,
        requested_scope,
        pairing_request_id: record.pairing_request_id.clone(),
        pairing_code: record.pairing_code.clone(),
        pairing_expires_at: record.pairing_expires_at,
        approval_request_id: record
            .runtime_key_request
            .as_ref()
            .filter(|value| value.is_object())
            .and(record.approval_request_id.clone()),
        pending_runtime_key_request: record
            .runtime_key_request
            .clone()
            .filter(|value| value.is_object()),
        approval_requested_at: record
            .runtime_key_request
            .as_ref()
            .filter(|value| value.is_object())
            .and(record.approval_requested_at),
        authorized_event_ref,
        active_authorizations,
    })
}

fn active_agent_key_authorizations(
    state: &AppState,
    agent_id: &str,
) -> Result<Vec<arkret_sdk::AgentKeyAuthorizationState>, AppError> {
    state
        .projection
        .lock()
        .active_agent_key_authorizations(agent_id)
        .into_iter()
        .map(|(key_id, authorized_event_ref)| {
            Ok(arkret_sdk::AgentKeyAuthorizationState {
                verification_method: key_id.clone(),
                key_id,
                authorized_event_ref: EventId::new(authorized_event_ref).map_err(|error| {
                    AppError::internal(format!("projected Agent authorization Event is invalid: {error}"))
                })?,
                expires_at: None,
            })
        })
        .collect()
}

// ─────────────────────────────────────────────────────────────────────
// AKP-0010 — agent participation policy (set / get).
//
// Stands up the cross-project HTTP contract at the same fidelity as the
// sibling agent handlers (audit-log row + typed response), but performs
// the REAL ceiling check via the shared `arkret_sdk` validators so the
// "inner scope MUST NOT exceed the outer ceiling" invariant is enforced
// at the edge. Persistence into `agent_participation`, ceiling
// resolution from the realm/circle/strand policy projection,
// capability-grant materialization (`ak.capability.grant` / `revoke`),
// and the dispatcher mention gate are P2-impl — matching the rest of
// this surface.
// ─────────────────────────────────────────────────────────────────────
