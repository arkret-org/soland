use super::*;

const ACTION_EVENT_READ: &str = "ak.event.read";
const ACTION_MESSAGE_CREATE: &str = "ak.message.create";
const ACTION_REACTION_ADD: &str = "ak.reaction.add";

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

fn requested_scope_actions(record: &AgentPrincipalRecord) -> BTreeSet<&str> {
    record
        .requested_scope
        .as_ref()
        .and_then(|scope| scope.get("actions"))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect()
}

fn is_content_scope_kind(kind: Option<&str>) -> bool {
    matches!(kind, Some("realm" | "strand" | "space" | "object"))
}

fn scope_resource_ref(resource: &Value) -> Option<&Value> {
    resource
        .get("resource_ref")
        .or_else(|| resource.get("strand_id"))
        .or_else(|| resource.get("space_id"))
        .or_else(|| resource.get("object_ref"))
}

fn scope_resource_selector_covers(ceiling: &Value, resource: &Value) -> bool {
    let ceiling_kind = ceiling.get("kind").and_then(Value::as_str);
    let resource_kind = resource.get("kind").and_then(Value::as_str);
    let kind_covers = ceiling_kind == resource_kind
        || (ceiling_kind == Some("realm") && is_content_scope_kind(resource_kind));
    if !kind_covers {
        return false;
    }
    if ceiling
        .get("realm_id")
        .is_some_and(|value| resource.get("realm_id") != Some(value))
    {
        return false;
    }
    match ceiling_kind {
        Some("operation") => ceiling
            .get("operation")
            .is_none_or(|value| resource.get("operation") == Some(value)),
        Some("service") => ceiling
            .get("service_id")
            .is_none_or(|value| resource.get("service_id") == Some(value)),
        _ => scope_resource_ref(ceiling)
            .is_none_or(|value| scope_resource_ref(resource) == Some(value)),
    }
}

fn scope_resources_within_requested_scope(requested_scope: &Value, resources: &[Value]) -> bool {
    let ceilings = requested_scope
        .get("resources")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default();
    let has_content_ceiling = ceilings
        .iter()
        .any(|ceiling| is_content_scope_kind(ceiling.get("kind").and_then(Value::as_str)));
    resources.iter().all(|resource| {
        let resource_kind = resource.get("kind").and_then(Value::as_str);
        (is_content_scope_kind(resource_kind) && !has_content_ceiling)
            || ceilings
                .iter()
                .any(|ceiling| scope_resource_selector_covers(ceiling, resource))
    })
}

fn constraints_preserve_requested_scope(requested_scope: &Value, constraints: &[Value]) -> bool {
    let mandatory = requested_scope
        .get("constraints")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default();
    mandatory
        .iter()
        .all(|constraint| constraints.contains(constraint))
}

/// A per-key scope may narrow, but never widen, the immutable provision scope.
pub(crate) fn agent_key_scope_within_requested_scope(
    record: &AgentPrincipalRecord,
    scope: &Value,
) -> bool {
    let Some(requested_scope) = record.requested_scope.as_ref() else {
        return false;
    };
    let Some(actions) = scope.get("actions").and_then(Value::as_array) else {
        return false;
    };
    let Some(resources) = scope.get("resources").and_then(Value::as_array) else {
        return false;
    };
    let constraints = scope
        .get("constraints")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default();
    let requested_actions = requested_scope_actions(record);
    actions.iter().all(|action| {
        action
            .as_str()
            .is_some_and(|action| requested_actions.contains(action))
    }) && scope_resources_within_requested_scope(requested_scope, resources)
        && constraints_preserve_requested_scope(requested_scope, constraints)
}

/// Managed Agent grants are always bounded by the immutable scope selected
/// at provisioning. Realm membership and policy can only narrow this set.
pub(crate) fn agent_actions_within_requested_scope(
    record: &AgentPrincipalRecord,
    actions: &[String],
) -> bool {
    let ceiling = requested_scope_actions(record);
    actions
        .iter()
        .all(|action| ceiling.contains(action.as_str()))
}

/// Enforce the action ceiling and, when provisioning declared explicit
/// content selectors, the optional resource ceiling. With no content
/// selectors, Realm grants remain responsible for choosing concrete scope.
pub(crate) fn agent_grant_within_requested_scope(
    record: &AgentPrincipalRecord,
    actions: &[String],
    resources: &[Value],
    constraints: &[Value],
) -> bool {
    if !agent_actions_within_requested_scope(record, actions) {
        return false;
    }
    record.requested_scope.as_ref().is_some_and(|scope| {
        scope_resources_within_requested_scope(scope, resources)
            && constraints_preserve_requested_scope(scope, constraints)
    })
}

/// Project the provision-time action ceiling onto the participation bits.
/// Third-party mention delivery requires read authority; replying requires
/// both actions in the materialized reply grant. Acting on behalf additionally
/// requires the explicit controller-approval constraint that distinguishes it
/// from ordinary `ak.message.create` authority.
pub(super) fn agent_requested_participation_ceiling(
    record: &AgentPrincipalRecord,
) -> AgentParticipation {
    let actions = requested_scope_actions(record);
    let message_create = actions.contains(ACTION_MESSAGE_CREATE);
    let approval_required = record
        .requested_scope
        .as_ref()
        .and_then(|scope| scope.get("constraints"))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .any(|constraint| {
            let approval = constraint
                .get("controller_approval_required")
                .and_then(Value::as_bool)
                .unwrap_or(false)
                || constraint
                    .get("approval_required")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
            let applies_to_message_create = constraint
                .get("applies_to_actions")
                .and_then(Value::as_array)
                .is_none_or(|values| {
                    values
                        .iter()
                        .any(|value| value.as_str() == Some(ACTION_MESSAGE_CREATE))
                });
            approval && applies_to_message_create
        });
    AgentParticipation {
        reply: message_create && actions.contains(ACTION_REACTION_ADD),
        accept_third_party_mention: actions.contains(ACTION_EVENT_READ),
        act_on_behalf: message_create && approval_required,
    }
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

#[cfg(test)]
mod requested_scope_tests {
    use super::*;

    fn record_with_scope(scope: Value) -> AgentPrincipalRecord {
        let mut record = AgentPrincipalRecord::new(
            "did:webvh:agent.example:agents:test".to_owned(),
            "did:webvh:controller.example:users:test".to_owned(),
            "ak:realm:019f6000-0000-7000-8000-000000000001".to_owned(),
            "did:webvh:agent.example:agents:test#controller".to_owned(),
            "active".to_owned(),
            chrono::Utc::now(),
        );
        record.requested_scope = Some(scope);
        record
    }

    #[test]
    fn realm_grant_actions_cannot_exceed_provision_ceiling() {
        let record = record_with_scope(json!({
            "actions": [ACTION_MESSAGE_CREATE, ACTION_REACTION_ADD]
        }));

        assert!(agent_actions_within_requested_scope(
            &record,
            &[ACTION_MESSAGE_CREATE.to_owned()]
        ));
        assert!(!agent_actions_within_requested_scope(
            &record,
            &[ACTION_EVENT_READ.to_owned()]
        ));
    }

    #[test]
    fn explicit_content_resources_narrow_later_realm_grants() {
        let record = record_with_scope(json!({
            "actions": [ACTION_EVENT_READ],
            "resources": [{
                "kind": "realm",
                "realm_id": "ak:realm:019f6000-0000-7000-8000-000000000001"
            }]
        }));
        assert!(agent_grant_within_requested_scope(
            &record,
            &[ACTION_EVENT_READ.to_owned()],
            &[json!({
                "kind": "strand",
                "realm_id": "ak:realm:019f6000-0000-7000-8000-000000000001",
                "strand_id": "ak:strand:019f6000-0000-7000-8000-000000000002"
            })],
            &[]
        ));
        assert!(!agent_grant_within_requested_scope(
            &record,
            &[ACTION_EVENT_READ.to_owned()],
            &[json!({
                "kind": "realm",
                "realm_id": "ak:realm:019f6000-0000-7000-8000-000000000099"
            })],
            &[]
        ));

        let realm_wide_strand_ceiling = record_with_scope(json!({
            "actions": [ACTION_EVENT_READ],
            "resources": [{
                "kind": "strand",
                "realm_id": "ak:realm:019f6000-0000-7000-8000-000000000001"
            }]
        }));
        assert!(agent_grant_within_requested_scope(
            &realm_wide_strand_ceiling,
            &[ACTION_EVENT_READ.to_owned()],
            &[json!({
                "kind": "strand",
                "realm_id": "ak:realm:019f6000-0000-7000-8000-000000000001",
                "strand_id": "ak:strand:019f6000-0000-7000-8000-000000000002"
            })],
            &[]
        ));

        let global_strand_ceiling = record_with_scope(json!({
            "actions": [ACTION_EVENT_READ],
            "resources": [{ "kind": "strand" }]
        }));
        assert!(agent_grant_within_requested_scope(
            &global_strand_ceiling,
            &[ACTION_EVENT_READ.to_owned()],
            &[json!({
                "kind": "strand",
                "realm_id": "ak:realm:019f6000-0000-7000-8000-000000000099",
                "strand_id": "ak:strand:019f6000-0000-7000-8000-000000000002"
            })],
            &[]
        ));
    }

    #[test]
    fn realm_grant_must_preserve_provision_constraints() {
        let mandatory = json!({"controller_approval_required": true});
        let record = record_with_scope(json!({
            "actions": [ACTION_EVENT_READ],
            "resources": [{
                "kind": "operation",
                "operation": "ak.self.events.stream.subscribe"
            }],
            "constraints": [mandatory.clone()]
        }));
        let resources = [json!({
            "kind": "strand",
            "realm_id": "ak:realm:019f6000-0000-7000-8000-000000000001",
            "strand_id": "ak:strand:019f6000-0000-7000-8000-000000000002"
        })];

        assert!(agent_grant_within_requested_scope(
            &record,
            &[ACTION_EVENT_READ.to_owned()],
            &resources,
            &[mandatory]
        ));
        assert!(!agent_grant_within_requested_scope(
            &record,
            &[ACTION_EVENT_READ.to_owned()],
            &resources,
            &[]
        ));
    }

    #[test]
    fn participation_is_intersected_with_provision_ceiling() {
        let record = record_with_scope(json!({
            "actions": [ACTION_EVENT_READ, ACTION_MESSAGE_CREATE, ACTION_REACTION_ADD],
            "constraints": [{
                "applies_to_actions": [ACTION_MESSAGE_CREATE],
                "controller_approval_required": true
            }]
        }));

        assert_eq!(
            agent_requested_participation_ceiling(&record),
            AgentParticipation {
                reply: true,
                accept_third_party_mention: true,
                act_on_behalf: true,
            }
        );

        let record = record_with_scope(json!({
            "actions": [ACTION_MESSAGE_CREATE]
        }));
        assert_eq!(
            agent_requested_participation_ceiling(&record),
            AgentParticipation {
                reply: false,
                accept_third_party_mention: false,
                act_on_behalf: false,
            }
        );
    }
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
        display_name: record
            .display_name
            .clone()
            .filter(|value| !value.is_empty()),
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
        .ok_or_else(|| AppError::internal("persisted Agent requested_scope is missing"))?;
    let requested_scope = serde_json::from_value(requested_scope).map_err(|error| {
        AppError::internal(format!("persisted Agent scope is invalid: {error}"))
    })?;
    let authorized_event_ref = record
        .authorized_event_ref
        .as_ref()
        .map(|value| EventId::new(value.clone()))
        .transpose()
        .map_err(|error| {
            AppError::internal(format!(
                "persisted Agent authorization Event is invalid: {error}"
            ))
        })?;
    Ok(KeyState {
        agent_id: Did::new(record.id.clone()).map_err(|error| {
            AppError::internal(format!("persisted Agent DID is invalid: {error}"))
        })?,
        controller_id: Did::new(record.controller_id.clone()).map_err(|error| {
            AppError::internal(format!(
                "persisted Agent controller DID is invalid: {error}"
            ))
        })?,
        principal_control_realm_id: RealmId::new(record.principal_control_realm_id.clone())
            .map_err(|error| {
                AppError::internal(format!("persisted Agent PCR is invalid: {error}"))
            })?,
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
                    AppError::internal(format!(
                        "projected Agent authorization Event is invalid: {error}"
                    ))
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
