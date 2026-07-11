use super::*;

pub(super) fn controller_dev_session(controller_id: &str, state: &AppState) -> SessionRecord {
    SessionRecord {
        token_hash: format!("agent-dev-fanout:{controller_id}"),
        actor: controller_id.to_owned(),
        device_id: "agent-dev-fanout".to_owned(),
        audience: state.config.service_id.clone(),
        session_public_key: None,
        agent_session: None,
        expires_at: now() + chrono::Duration::minutes(5),
        created_at: now(),
        revoked_at: None,
    }
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
/// `{agent_id, display_name?, slug?, status, created_at?, updated_at?}`.
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
pub(super) fn agent_view_from_record(record: &Value) -> AgentView {
    let status = record
        .get("state")
        .and_then(Value::as_str)
        .unwrap_or("active")
        .to_owned();
    let key_state = agent_key_state_from_record(record);
    AgentView {
        agent: serde_json::to_value(agent_projection_from_record(record)).unwrap_or(Value::Null),
        status,
        grants: Vec::new(),
        key_state,
    }
}

pub(super) fn agent_key_state_from_record(record: &Value) -> Value {
    let status = record
        .get("state")
        .and_then(Value::as_str)
        .unwrap_or("active");
    let mut state = serde_json::Map::new();
    state.insert("status".to_owned(), json!(status));
    if let Some(value) = record
        .get("requested_scope")
        .filter(|value| !value.is_null())
    {
        state.insert("requested_scope".to_owned(), value.clone());
    }
    if let Some(value) = record
        .get("pairing_request_id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
    {
        state.insert("pairing_request_id".to_owned(), json!(value));
    }
    if let Some(value) = record
        .get("pairing_code")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
    {
        state.insert("pairing_code".to_owned(), json!(value));
    }
    if let Some(value) = record
        .get("pairing_expires_at")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
    {
        state.insert("pairing_expires_at".to_owned(), json!(value));
    }
    if let Some(value) = record
        .get("approval_request_id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
    {
        state.insert("approval_request_id".to_owned(), json!(value));
    }
    if let Some(value) = record
        .get("runtime_key_request")
        .filter(|value| !value.is_null())
    {
        state.insert("pending_runtime_key_request".to_owned(), value.clone());
    }
    if let Some(value) = record
        .get("approval_requested_at")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
    {
        state.insert("approval_requested_at".to_owned(), json!(value));
    }
    if let Some(value) = record
        .get("authorized_event_ref")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
    {
        state.insert("authorized_event_ref".to_owned(), json!(value));
    }
    Value::Object(state)
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
