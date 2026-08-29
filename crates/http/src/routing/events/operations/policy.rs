use super::*;

mod accountability;
mod agent_participation;
mod governance;
mod message_rules;
mod realm_circle;

use accountability::*;
pub(crate) use agent_participation::{
    agent_participation_ceiling_record, validate_agent_participation_ceiling,
    validate_agent_reply_participation,
};
use governance::*;
#[cfg(test)]
pub(crate) async fn validate_member_state_policy_for_test(
    state: &AppState,
    operation: &Operation,
) -> Result<(), &'static str> {
    governance::validate_member_state_policy(state, operation, false).await
}
pub(crate) use message_rules::validate_content_encryption_floor;
#[cfg(test)]
pub(super) use message_rules::validate_principal_control_realm_binding;
use message_rules::*;
#[cfg(test)]
pub(crate) use message_rules::{message_window_permits, realm_ids_match};
use realm_circle::*;

pub(crate) fn validate_trusted_sidecar_create_operation(
    operation: &Operation,
    controller: &str,
) -> Result<(), &'static str> {
    if kinds::canonical_kind_for_operation(operation) != Some(arkret_wire::EventKind::SidecarCreate)
    {
        return Err("sidecar_create_denied");
    }
    let payload = operation
        .payload
        .as_object()
        .ok_or("sidecar_create_denied")?;
    if operation.context.sender.as_str() != controller
        || payload.get("encryption_profile").and_then(Value::as_str) != Some("mls_rfc9420")
        || payload.keys().any(|field| {
            !matches!(
                field.as_str(),
                "encryption_profile" | "event_id" | "sender" | "hlc"
            )
        })
        || !payload
            .get("event_id")
            .and_then(Value::as_str)
            .is_some_and(|event_id| arkret_identifiers::EventId::new(event_id.to_owned()).is_ok())
    {
        return Err("sidecar_create_denied");
    }
    Ok(())
}

pub fn operation_policy_reason_code(message: &str) -> (salvo::http::StatusCode, &'static str) {
    if message == "agent_pcr_recovery_not_ready" {
        (
            salvo::http::StatusCode::PRECONDITION_FAILED,
            "agent_pcr_recovery_not_ready",
        )
    } else if message == arkret_wire::ReasonCode::REQUIRES_ORGANIZATION_APPROVAL {
        (salvo::http::StatusCode::CONFLICT, "failed_precondition")
    } else if message.starts_with("message_edit_window")
        || message.starts_with("message_redact_window")
        || message.starts_with("direct_conversation_")
        || message == arkret_wire::ReasonCode::REACTION_SCOPE_MISMATCH
        || message == arkret_wire::ReasonCode::HISTORY_ACCESS_REQUIRES_HISTORY_CAPABLE_SCHEME
    {
        (
            salvo::http::StatusCode::PRECONDITION_FAILED,
            "failed_precondition",
        )
    } else if message == "applet_registration_unauthorized" {
        // applet-integration.md §4 — surface the spec reason verbatim (matches
        // the dedicated install aggregate's `with_wire_code`), not the generic
        // `capability_denied`.
        (
            salvo::http::StatusCode::FORBIDDEN,
            "applet_registration_unauthorized",
        )
    } else if message == arkret_wire::ReasonCode::TRANSCRIPTION_DENIED {
        (
            salvo::http::StatusCode::FORBIDDEN,
            arkret_wire::ReasonCode::TRANSCRIPTION_DENIED,
        )
    } else if message == arkret_wire::ReasonCode::ACCOUNTABILITY_GRANT_MISSING {
        (
            salvo::http::StatusCode::PRECONDITION_FAILED,
            arkret_wire::ReasonCode::ACCOUNTABILITY_GRANT_MISSING,
        )
    } else if message == soland_services::operation_semantics::REASON_KEYPACKAGE_NOT_FOUND {
        (
            salvo::http::StatusCode::PRECONDITION_FAILED,
            soland_services::operation_semantics::REASON_KEYPACKAGE_NOT_FOUND,
        )
    } else if message == arkret_wire::ErrorCode::READ_RECEIPT_COMPLIANCE_FLOOR_VIOLATED {
        (
            salvo::http::StatusCode::UNPROCESSABLE_ENTITY,
            arkret_wire::ErrorCode::READ_RECEIPT_COMPLIANCE_FLOOR_VIOLATED,
        )
    } else if message == "sidecar_create_denied" {
        (salvo::http::StatusCode::FORBIDDEN, "sidecar_create_denied")
    } else if message == "circle_manage_capability_required" {
        (
            salvo::http::StatusCode::FORBIDDEN,
            "circle_manage_capability_required",
        )
    } else if message == "circle_member_manage_capability_required" {
        (
            salvo::http::StatusCode::FORBIDDEN,
            "circle_member_manage_capability_required",
        )
    } else if message == "circle_member_must_be_realm_member" {
        (
            salvo::http::StatusCode::UNPROCESSABLE_ENTITY,
            "circle_member_must_be_realm_member",
        )
    } else if message == "realm_terminal_state" {
        (salvo::http::StatusCode::FORBIDDEN, "realm_terminal_state")
    } else if message == arkret_wire::ErrorCode::REALM_FROZEN {
        (
            salvo::http::StatusCode::FORBIDDEN,
            arkret_wire::ErrorCode::REALM_FROZEN,
        )
    } else if matches!(
        message,
        "history_not_visible"
            | "not_member"
            | "policy_denied"
            | "device_revoked"
            | "audit_required"
    ) {
        (
            salvo::http::StatusCode::FORBIDDEN,
            match message {
                "history_not_visible" => "history_not_visible",
                "not_member" => "not_member",
                "policy_denied" => "policy_denied",
                "device_revoked" => "device_revoked",
                "audit_required" => "audit_required",
                _ => "capability_denied",
            },
        )
    } else if message == "not_found" {
        (salvo::http::StatusCode::NOT_FOUND, "not_found")
    } else {
        (salvo::http::StatusCode::FORBIDDEN, "capability_denied")
    }
}

pub async fn validate_operation_policy(
    state: &AppState,
    operations: &[Operation],
) -> Result<(), &'static str> {
    validate_operation_policy_common(state, operations, false, false).await
}

pub async fn validate_operation_policy_with_plaintext_service_binding(
    state: &AppState,
    operations: &[Operation],
    has_plaintext_service_binding: bool,
) -> Result<(), &'static str> {
    validate_operation_policy_common(state, operations, has_plaintext_service_binding, false).await
}

/// Validate one Operation of a submit batch against policy.
///
/// Per-Event admission commits each batch member before admitting the next,
/// so re-running the per-operation gates on not-yet-committed siblings would
/// judge them against a state their own in-batch predecessors have not
/// landed. Only the batch-aware validators (history_access × content_scheme,
/// read-receipt combinations,
/// accountability profile) receive the full sibling slice; every other gate
/// sees exactly the Operation being admitted.
pub(crate) async fn validate_single_operation_policy_in_batch(
    state: &AppState,
    operation: &Operation,
    batch: &[Operation],
    has_plaintext_service_binding: bool,
) -> Result<(), &'static str> {
    validate_one_operation_policy(
        state,
        operation,
        batch,
        has_plaintext_service_binding,
        false,
    )
    .await
}

/// The agent-membership-cascade half of [`validate_single_operation_policy_in_batch`].
pub(crate) async fn validate_single_operation_policy_for_agent_membership_cascade(
    state: &AppState,
    operation: &Operation,
    batch: &[Operation],
    has_plaintext_service_binding: bool,
) -> Result<(), &'static str> {
    validate_one_operation_policy(state, operation, batch, has_plaintext_service_binding, true)
        .await
}

async fn validate_operation_policy_common(
    state: &AppState,
    operations: &[Operation],
    has_plaintext_service_binding: bool,
    agent_membership_cascade: bool,
) -> Result<(), &'static str> {
    for operation in operations {
        validate_one_operation_policy(
            state,
            operation,
            operations,
            has_plaintext_service_binding,
            agent_membership_cascade,
        )
        .await?;
    }
    Ok(())
}

async fn validate_one_operation_policy(
    state: &AppState,
    operation: &Operation,
    operations: &[Operation],
    has_plaintext_service_binding: bool,
    agent_membership_cascade: bool,
) -> Result<(), &'static str> {
    {
        validate_realm_lifecycle_write_gate(state, operation)?;
        let cleanup_transition = agent_membership_cascade_cleanup_transition(operation);
        if cleanup_transition && !agent_membership_cascade {
            return Err("agent_membership_cascade_required");
        }
        if !(agent_membership_cascade && cleanup_transition) {
            validate_agent_operation_membership(state, operation).await?;
        }
        if kinds::canonical_kind_for_operation(operation)
            == Some(arkret_wire::EventKind::SidecarCreate)
        {
            // Only the authenticated ensure aggregate may construct this
            // reducer-derived event; the generic submit path is closed.
            return Err("sidecar_create_denied");
        }
        validate_managed_agent_grant_ceiling(state, operation).await?;
        if kinds::operation_is_message_create(operation)
            && !message_operation_is_encrypted(operation)
            && !has_plaintext_service_binding
            && known_realm_denies_plaintext_service(state, operation.realm_id.as_str()).await
        {
            return Err(
                "private plaintext message operations require this service in plaintext_visible_services",
            );
        }
        validate_principal_control_realm_binding(state, operation)?;
        message_rules::validate_managed_agent_control_realm_binding(state, operation).await?;
        validate_accountability_profile_policy(state, operations, operation).await?;
        crate::routing::identity::managed_agent_pcr::validate_active_series_operation_authority(
            state, operation,
        )
        .await?;
        // Verify the canonical device possession proof on every
        // ak.device.authorize at ingest.
        if kinds::canonical_kind(operation) == arkret_wire::EventKind::DeviceAuthorize {
            let payload = serde_json::from_value::<
                arkret_models_collaboration::events_payloads::device_identity::DeviceAuthorizePayload,
            >(operation.payload.clone())
            .map_err(|_| "ak.device.authorize payload violates SDK artifact schema")?;
            crate::routing::identity::device_signing::validate_device_authorize_binding(
                state, &payload,
            )?;
        }
        validate_direct_conversation_realm_policy(state, operation)?;
        crate::routing::identity::account::validate_direct_binding_operation(state, operation)
            .await?;
        validate_circle_create_policy(state, operation).await?;
        validate_circle_management_policy(state, operation).await?;
        validate_member_state_policy(state, operation, agent_membership_cascade).await?;
        validate_circle_scope_membership(state, operation)?;
        validate_pin_scope_safety(state, operation)?;
        validate_applet_registration_authz(state, operation).await?;
        validate_call_recording_start_policy(state, operation).await?;
        validate_moderation_event_policy(state, operation).await?;
        validate_set_default_strand_policy(state, operation).await?;
        validate_realm_organization_policy(state, operation).await?;
        validate_history_access_content_scheme_policy(state, operations, operation).await?;
        validate_read_receipt_policy_combination_write(state, operations, operation).await?;
        validate_realm_moderation_policy(state, operation).await?;
        validate_audience_mention_operation_policy(state, operation).await?;
        validate_message_edit_redact_window_policy(state, operation).await?;
        validate_reaction_scope_policy(state, operation)?;
    }
    Ok(())
}

fn agent_membership_cascade_cleanup_transition(operation: &Operation) -> bool {
    kinds::canonical_kind_for_operation(operation) == Some(arkret_wire::EventKind::MemberState)
        && operation.payload.get("membership").and_then(Value::as_str) == Some("leave")
        && operation
            .payload
            .get("membership_cause")
            .and_then(Value::as_str)
            == Some("controller_membership_ended")
        && operation
            .payload
            .pointer("/agent_controller_binding/controller_terminal_event_ref")
            .and_then(Value::as_str)
            .is_some()
}

async fn validate_agent_operation_membership(
    state: &AppState,
    operation: &Operation,
) -> Result<(), &'static str> {
    let actor_id = operation.context.sender.as_str();
    let record = state
        .agent_pairings()
        .agent(actor_id)
        .await
        .map_err(|_| "agent_membership_lookup_failed")?;
    let Some(record) = record else {
        return Ok(());
    };
    // The managed Agent's own PCR genesis is a lifecycle bootstrap, not a
    // Realm-participation write. Its controller delegation, provision Event,
    // accountability grant and PCR binding have already been checked by the
    // closed envelope gate. Requiring an effective Realm membership here
    // would create a cycle: the Agent PCR must exist before its first
    // controller-generation membership binding can be projected.
    if operation.realm_id.as_str() == record.principal_control_realm_id
        && kinds::canonical_kind_for_operation(operation)
            == Some(arkret_wire::EventKind::RealmCreate)
    {
        return Ok(());
    }
    let result = if operation.realm_id.as_str() == record.principal_control_realm_id {
        crate::routing::identity::managed_agent_pcr::validate_agent_controller_binding(
            state,
            &record,
            operation.created_at,
        )
        .await
    } else {
        crate::routing::identity::managed_agent_pcr::validate_effective_agent_realm_membership(
            state,
            &record,
            operation.realm_id.as_str(),
            operation.created_at,
        )
        .await
    };
    result.map_err(|_| "agent_membership_inactive")
}

#[cfg(test)]
#[expect(
    clippy::items_after_test_module,
    reason = "focused policy tests stay adjacent to the public policy entry point"
)]
mod tests {
    use soland_storage_postgres::Db;

    use super::*;

    fn circle_create_with_payload(payload: Value) -> Operation {
        arkret_event_draft::test_support::raw_projected_operation(
            arkret_identifiers::OperationId::new(
                "ak:operation:01964137-0000-7000-8000-000000000040",
            )
            .unwrap(),
            arkret_identifiers::RealmId::new(
                "ak:realm:AQcksDTzb8Sxrn1BUVVlHtH4vBOy99RKUB4EwOq_413b",
            )
            .unwrap(),
            arkret_wire::EventKind::CircleCreate.as_str(),
            payload,
        )
    }

    #[test]
    fn policy_sender_uses_typed_envelope_sender_for_full_object_create_payload() {
        let op = circle_create_with_payload(serde_json::json!({
            "object": { "created_by": "did:web:example.com:users:alice" },
        }));
        assert_eq!(
            policy_operation_sender(&op),
            Some("ak:did_core:web:fixture.example")
        );
    }

    #[tokio::test]
    async fn ordinary_circle_create_cannot_claim_reserved_sidecar_shape() {
        let actor = "did:web:example.com:users:alice";
        let operation = circle_create_with_payload(serde_json::json!({
            "object": {
                "id": "ak:circle:AbLN8Zik9Z7ZJiPG_sNwMk4iV0JGKAnWmyOB0FKWVGCV",
                "schema": "ak.schema.circle.v1",
                "realm_id": "ak:realm:AQcksDTzb8Sxrn1BUVVlHtH4vBOy99RKUB4EwOq_413b",
                "title": "Agent Sidecar Scope",
                "display": {
                    "short_name": "SC-ABCDEFGHIJKLMNOP",
                    "color_token": "slate",
                    "symbol": { "glyph": "lock" }
                },
                "directory_visibility": "members",
                "join_rule": "invite",
                "history_access": "since_join",
                "content_encryption_floor": "e2ee_required",
                "metadata_encryption_floor": "e2ee_required",
                "encryption_profile": "mls_rfc9420",
                "state": "active",
                "created_by": actor,
                "created_at": "2026-07-20T00:00:00.000Z"
            }
        }));
        let state = AppState::new(crate::config::AppConfig::test_default(), Db { pool: None });
        assert_eq!(
            validate_circle_create_policy(&state, &operation).await,
            Err("sidecar_create_denied")
        );
    }
}

async fn validate_managed_agent_grant_ceiling(
    state: &AppState,
    operation: &Operation,
) -> Result<(), &'static str> {
    if kinds::canonical_kind_for_operation(operation)
        != Some(arkret_wire::EventKind::CapabilityGrant)
    {
        return Ok(());
    }
    let grant = operation.payload.get("grant").unwrap_or(&operation.payload);
    let Some(subject) = grant.get("subject").and_then(Value::as_str) else {
        return Ok(());
    };
    let record = state
        .agent_pairings()
        .agent(subject)
        .await
        .map_err(|_| "agent_grant_ceiling_lookup_failed")?;
    let Some(record) = record else {
        return Ok(());
    };
    crate::routing::identity::managed_agent_pcr::validate_effective_agent_realm_membership(
        state,
        &record,
        operation.realm_id.as_str(),
        chrono::Utc::now(),
    )
    .await
    .map_err(|_| "agent_requested_scope_commitment_invalid")?;
    let Some(actions) = grant.get("actions").and_then(Value::as_array) else {
        return Err("agent_grant_exceeds_requested_scope");
    };
    let actions = actions
        .iter()
        .map(|action| action.as_str().map(ToOwned::to_owned))
        .collect::<Option<Vec<_>>>()
        .ok_or("agent_grant_exceeds_requested_scope")?;
    let Some(resources) = grant.get("resources").and_then(Value::as_array) else {
        return Err("agent_grant_exceeds_requested_scope");
    };
    let resources = serde_json::from_value::<
        Vec<arkret_wire::resource_selector::WireResourceSelector>,
    >(Value::Array(resources.clone()))
    .map_err(|_| "agent_grant_exceeds_requested_scope")?;
    let constraints = grant
        .get("constraints")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let constraints = serde_json::from_value::<
        Vec<arkret_models_collaboration::governance::grant_constraint::GrantConstraint>,
    >(Value::Array(constraints))
    .map_err(|_| "agent_grant_exceeds_requested_scope")?;
    if crate::routing::identity::agents::agent_grant_within_requested_scope(
        &record,
        &actions,
        &resources,
        &constraints,
    ) {
        Ok(())
    } else {
        Err("agent_grant_exceeds_requested_scope")
    }
}
