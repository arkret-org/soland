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
    record: &Value,
    agent_id: &str,
    session: &SessionRecord,
) -> Result<(), AppError> {
    if record.get("agent_id").and_then(Value::as_str) != Some(agent_id) {
        return Err(AppError::capability_denied(
            "agent principal record does not match the requested principal",
        ));
    }
    let Some(controller_id) = record
        .get("controller_id")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
    else {
        return Err(AppError::capability_denied(
            "agent principal has no controller binding",
        ));
    };
    if controller_id != session.actor.as_str() {
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
) -> Result<Value, AppError> {
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
pub(super) fn agent_projection_from_record(record: &Value) -> AgentProjection {
    let str_field = |key: &str| record.get(key).and_then(Value::as_str);
    let parse_ts = |key: &str| {
        str_field(key)
            .filter(|value| !value.is_empty())
            .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
            .map(|ts| ts.with_timezone(&chrono::Utc))
    };
    let status = match str_field("state").unwrap_or("active") {
        "pending_runtime_key" => AgentStatus::PendingRuntimeKey,
        "pairing_expired" => AgentStatus::PairingExpired,
        "paused" => AgentStatus::Paused,
        "deactivated" => AgentStatus::Deactivated,
        _ => AgentStatus::Active,
    };
    AgentProjection {
        agent_id: Did::new(str_field("agent_id").unwrap_or_default())
            .unwrap_or_else(|_| Did::new("did:webvh:invalid:invalid").expect("static did")),
        display_name: str_field("display_name")
            .filter(|value| !value.is_empty())
            .map(str::to_owned),
        slug: str_field("agent_slug")
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
            .unwrap_or_default(),
        avatar_blob_ref: str_field("avatar_blob_ref")
            .filter(|value| !value.is_empty())
            .and_then(|value| BlobRef::new(value.to_owned()).ok()),
        status,
        created_at: parse_ts("created_at"),
        updated_at: parse_ts("updated_at"),
    }
}

/// Build the spec `agent_view` (`agent-operations.schema.json#/$defs/agent_view`)
/// from a persisted record: `{agent: <agent_projection>, status, grants[], key_state}`.
/// The `agent`/`status` pair is required. `grants` defaults empty here — the
/// `get_agent` read path overlays it from the authz projection
/// (`grants_for_subject_all_realms`) so the controller UI sees live grants.
pub(super) fn agent_view_from_record(state: &AppState, record: &Value) -> AgentView {
    let status = record
        .get("state")
        .and_then(Value::as_str)
        .unwrap_or("active")
        .to_owned();
    let agent_id = record
        .get("agent_id")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let active_authorizations = active_agent_key_authorizations(state, agent_id);
    let key_state = agent_key_state_from_record(record, active_authorizations);
    AgentView {
        agent: serde_json::to_value(agent_projection_from_record(record)).unwrap_or(Value::Null),
        status,
        grants: Vec::new(),
        key_state,
    }
}

pub(super) fn agent_key_state_from_record(
    record: &Value,
    active_authorizations: Vec<Value>,
) -> Value {
    let status = record
        .get("state")
        .and_then(Value::as_str)
        .unwrap_or("active");
    let mut key_state = serde_json::Map::new();
    key_state.insert("status".to_owned(), json!(status));
    let agent_id = record
        .get("agent_id")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let controller_id = record
        .get("controller_id")
        .and_then(Value::as_str)
        .unwrap_or_default();
    key_state.insert("agent_id".to_owned(), json!(agent_id));
    key_state.insert("controller_id".to_owned(), json!(controller_id));
    if let Some(realm_id) = record.get("self_realm_id").and_then(Value::as_str) {
        key_state.insert("principal_control_realm_id".to_owned(), json!(realm_id));
    }
    key_state.insert(
        "controller_authorization_ref".to_owned(),
        json!(format!("{agent_id}#managed-controller")),
    );
    if let Some(value) = record
        .get("requested_scope")
        .filter(|value| !value.is_null())
    {
        key_state.insert("requested_scope".to_owned(), value.clone());
    }
    if let Some(value) = record
        .get("pairing_request_id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
    {
        key_state.insert("pairing_request_id".to_owned(), json!(value));
    }
    if let Some(value) = record
        .get("pairing_code")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
    {
        key_state.insert("pairing_code".to_owned(), json!(value));
    }
    if let Some(value) = record
        .get("pairing_expires_at")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
    {
        key_state.insert("pairing_expires_at".to_owned(), json!(value));
    }
    let pending_runtime_key_request = record
        .get("runtime_key_request")
        .filter(|value| value.is_object());
    if let Some(value) = pending_runtime_key_request {
        key_state.insert("pending_runtime_key_request".to_owned(), value.clone());
        if let Some(value) = record
            .get("approval_request_id")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
        {
            key_state.insert("approval_request_id".to_owned(), json!(value));
        }
        if let Some(value) = record
            .get("approval_requested_at")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
        {
            key_state.insert("approval_requested_at".to_owned(), json!(value));
        }
    }
    if let Some(value) = record
        .get("authorized_event_ref")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
    {
        key_state.insert("authorized_event_ref".to_owned(), json!(value));
    }
    key_state.insert(
        "active_authorizations".to_owned(),
        Value::Array(active_authorizations),
    );
    Value::Object(key_state)
}

fn active_agent_key_authorizations(state: &AppState, agent_id: &str) -> Vec<Value> {
    state
        .projection
        .lock()
        .active_agent_key_authorizations(agent_id)
        .into_iter()
        .map(|(key_id, authorized_event_ref)| {
            json!({
                "verification_method": key_id,
                "key_id": key_id,
                "authorized_event_ref": authorized_event_ref,
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
