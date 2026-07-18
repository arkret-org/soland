use super::*;

mod accountability;
mod agent_participation;
mod governance;
mod message_rules;
mod realm_circle;

#[cfg(test)]
pub(super) use accountability::minimal_metadata_aad_visibility;
use accountability::*;
pub(crate) use agent_participation::{
    agent_participation_ceiling_record, validate_agent_participation_ceiling,
    validate_agent_reply_participation,
};
use governance::*;
pub(crate) use message_rules::validate_content_encryption_floor;
#[cfg(test)]
pub(super) use message_rules::validate_principal_control_realm_binding;
use message_rules::*;
#[cfg(test)]
pub(crate) use message_rules::{message_window_permits, realm_ids_match};
use realm_circle::*;

pub(crate) async fn validate_trusted_sidecar_member_operation(
    state: &AppState,
    operation: &Operation,
    controller: &str,
) -> Result<(), &'static str> {
    let Some(circle_id) = operation_circle_id(operation) else {
        return Err("sidecar_create_denied");
    };
    if sidecar_member_state_shape_is_constrained(state, operation, controller, circle_id).await {
        Ok(())
    } else {
        Err("sidecar_create_denied")
    }
}

pub fn operation_policy_reason_code(message: &str) -> (salvo::http::StatusCode, &'static str) {
    if message == "agent_pcr_recovery_not_ready" {
        (
            salvo::http::StatusCode::PRECONDITION_FAILED,
            "agent_pcr_recovery_not_ready",
        )
    } else if message == arkret_sdk::ReasonCode::REQUIRES_ORGANIZATION_APPROVAL {
        (salvo::http::StatusCode::CONFLICT, "failed_precondition")
    } else if message.starts_with("message_edit_window")
        || message.starts_with("message_redact_window")
        || message.starts_with("disappearing_")
        || message.starts_with("direct_conversation_")
        || message.starts_with("cross_signing_reset_")
        || message == "cross_signing_model_mismatch"
        || message == arkret_sdk::error::ReasonCode::REACTION_SCOPE_MISMATCH
    {
        (
            salvo::http::StatusCode::PRECONDITION_FAILED,
            "failed_precondition",
        )
    } else if message
        == arkret_sdk::error::ReasonCode::HISTORY_VISIBILITY_REQUIRES_HISTORY_CAPABLE_SCHEME
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
    } else if message == arkret_sdk::ReasonCode::TRANSCRIPTION_DENIED {
        (
            salvo::http::StatusCode::FORBIDDEN,
            arkret_sdk::ReasonCode::TRANSCRIPTION_DENIED,
        )
    } else if message == arkret_sdk::ReasonCode::ACCOUNTABILITY_GRANT_MISSING {
        (
            salvo::http::StatusCode::PRECONDITION_FAILED,
            arkret_sdk::ReasonCode::ACCOUNTABILITY_GRANT_MISSING,
        )
    } else if message == arkret_sdk::ErrorCode::READ_RECEIPT_COMPLIANCE_FLOOR_VIOLATED {
        (
            salvo::http::StatusCode::UNPROCESSABLE_ENTITY,
            arkret_sdk::ErrorCode::READ_RECEIPT_COMPLIANCE_FLOOR_VIOLATED,
        )
    } else if matches!(
        message,
        "read_receipt_visibility_combination_invalid"
            | "read_receipt_forced_public_world_readable_forbidden"
    ) {
        (
            salvo::http::StatusCode::FORBIDDEN,
            match message {
                "read_receipt_visibility_combination_invalid" => {
                    "read_receipt_visibility_combination_invalid"
                }
                "read_receipt_forced_public_world_readable_forbidden" => {
                    "read_receipt_forced_public_world_readable_forbidden"
                }
                _ => "capability_denied",
            },
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
    } else if message == "realm_terminal_state" {
        (salvo::http::StatusCode::FORBIDDEN, "realm_terminal_state")
    } else if message == arkret_sdk::ErrorCode::REALM_FROZEN {
        (
            salvo::http::StatusCode::FORBIDDEN,
            arkret_sdk::ErrorCode::REALM_FROZEN,
        )
    } else if matches!(
        message,
        "history_sharing_policy_missing"
            | "history_not_visible"
            | "not_member"
            | "policy_denied"
            | "device_revoked"
            | "audit_required"
    ) {
        (
            salvo::http::StatusCode::FORBIDDEN,
            match message {
                "history_sharing_policy_missing" => "history_sharing_policy_missing",
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
    validate_operation_policy_with_plaintext_service_binding(state, operations, false).await
}

pub async fn validate_operation_policy_with_plaintext_service_binding(
    state: &AppState,
    operations: &[Operation],
    has_plaintext_service_binding: bool,
) -> Result<(), &'static str> {
    for operation in operations {
        validate_realm_lifecycle_write_gate(state, operation)?;
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
        if kinds::canonical_kind_for_operation(operation)
            == Some(arkret_sdk::events::EventKind::MORPH_SCHEMA_MIGRATE)
        {
            validate_morph_schema_migrate_capability(operation)?;
            validate_morph_schema_migrate_authz(state, operation).await?;
        }
        validate_principal_control_realm_binding(operation)?;
        message_rules::validate_managed_agent_control_realm_binding(state, operation).await?;
        validate_accountability_profile_policy(state, operations, operation).await?;
        if kinds::canonical_kind_string(operation) == "ak.cross_signing.publish" {
            crate::routing::identity::cross_signing::validate_cross_signing_publish(
                state,
                &operation.payload,
            )
            .await?;
        }
        if kinds::canonical_kind_string(operation) == "ak.cross_signing.reset" {
            crate::routing::identity::cross_signing::validate_cross_signing_reset(
                state,
                &operation.payload,
            )
            .await?;
        }
        // 3a — verify the cross_signing_binding on ANY ak.device.authorize at
        // ingest (recovery /complete, or a future client-submitted control event).
        if kinds::canonical_kind_string(operation) == "ak.device.authorize" {
            crate::routing::identity::cross_signing::validate_device_authorize_binding(
                state,
                &operation.payload,
            )?;
        }
        validate_direct_conversation_realm_policy(state, operation)?;
        validate_circle_create_policy(state, operation).await?;
        validate_circle_management_policy(state, operation).await?;
        validate_member_state_policy(state, operation).await?;
        validate_circle_scope_membership(state, operation)?;
        validate_pin_scope_safety(state, operation)?;
        validate_applet_registration_authz(state, operation).await?;
        validate_call_recording_start_policy(state, operation).await?;
        validate_moderation_event_policy(state, operation).await?;
        validate_set_default_strand_policy(state, operation).await?;
        validate_realm_organization_policy(state, operation).await?;
        validate_history_visibility_policy(state, operation).await?;
        validate_history_visibility_content_scheme_policy(state, operations, operation).await?;
        validate_read_receipt_policy_combination_write(state, operations, operation).await?;
        validate_realm_key_share_policy(state, operation).await?;
        validate_realm_moderation_policy(state, operation).await?;
        validate_poll_operation_policy(state, operation)?;
        validate_audience_mention_operation_policy(state, operation).await?;
        validate_message_edit_redact_window_policy(state, operation).await?;
        validate_reaction_scope_policy(state, operation)?;
        validate_minimal_metadata_aad_policy(state, operation).await?;
        validate_disappearing_message_policy(state, operation)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn circle_create_with_payload(payload: Value) -> Operation {
        Operation::create(
            arkret_sdk::OperationId::new("ak:operation:01964137-0000-7000-8000-000000000040")
                .unwrap(),
            arkret_sdk::RealmId::new("ak:realm:01964137-0000-7000-8000-000000000030").unwrap(),
            arkret_sdk::events::EventKind::CIRCLE_CREATE,
            payload,
        )
    }

    #[test]
    fn policy_sender_uses_object_created_by_for_full_object_create_payload() {
        let actor = "did:web:example.com:users:alice";
        let op = circle_create_with_payload(serde_json::json!({
            "object": {
                "created_by": actor,
            },
        }));

        assert_eq!(policy_operation_sender(&op), Some(actor));
    }

    #[test]
    fn sidecar_circle_create_shape_requires_derived_short_name() {
        let actor = "did:web:example.com:users:alice";
        let realm_id = "ak:realm:01964137-0000-7000-8000-000000000030";
        let key = arkret_sdk::agent_sidecar_circle_key(realm_id, actor);
        let short_name = arkret_sdk::agent_sidecar_short_name(&key);
        let valid_payload = serde_json::json!({
            "profile": arkret_sdk::PROFILE_AGENT_SIDECAR_THREAD,
            "sidecar_ensure_capability_verified": true,
            "controller_id": actor,
            "controller_agent_circle_key": key,
            "object": {
                "id": "ak:circle:01964137-0000-7000-8000-000000000041",
                "realm_id": realm_id,
                "title": short_name,
                "display": { "short_name": short_name },
                "directory_visibility": "members",
                "join_rule": "invite",
                "history_visibility": "joined",
                "profile_ref": arkret_sdk::PROFILE_AGENT_SIDECAR_THREAD,
                "created_by": actor,
            },
        });
        let op = circle_create_with_payload(valid_payload.clone());
        assert!(payload_asserts_agent_sidecar_ensure(&valid_payload));
        assert!(sidecar_circle_create_shape_is_constrained(
            &valid_payload,
            &op,
            actor
        ));

        let mut invalid_payload = valid_payload;
        invalid_payload["object"]["title"] = Value::String("general".to_owned());
        let invalid_op = circle_create_with_payload(invalid_payload.clone());
        assert!(!sidecar_circle_create_shape_is_constrained(
            &invalid_payload,
            &invalid_op,
            actor
        ));
    }
}

async fn validate_managed_agent_grant_ceiling(
    state: &AppState,
    operation: &Operation,
) -> Result<(), &'static str> {
    if kinds::canonical_kind_for_operation(operation)
        != Some(arkret_sdk::events::EventKind::CAPABILITY_GRANT)
    {
        return Ok(());
    }
    let grant = operation.payload.get("grant").unwrap_or(&operation.payload);
    let Some(subject) = grant.get("subject").and_then(Value::as_str) else {
        return Ok(());
    };
    let record = state
        .agent_pairing_application()
        .agent(subject)
        .await
        .map_err(|_| "agent_grant_ceiling_lookup_failed")?;
    let Some(record) = record else {
        return Ok(());
    };
    crate::routing::identity::managed_agent_pcr::validate_agent_controller_binding(
        state,
        &record,
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
    let resources = serde_json::from_value::<Vec<arkret_sdk::WireResourceSelector>>(Value::Array(
        resources.clone(),
    ))
    .map_err(|_| "agent_grant_exceeds_requested_scope")?;
    let constraints = grant
        .get("constraints")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let constraints =
        serde_json::from_value::<Vec<arkret_sdk::GrantConstraint>>(Value::Array(constraints))
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
