use super::*;

mod accountability;
mod agent_interop;
mod agent_participation;
mod governance;
mod message_rules;
mod realm_circle;

#[cfg(test)]
pub(super) use accountability::minimal_metadata_aad_visibility;
use accountability::*;
use agent_interop::*;
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

pub fn operation_policy_reason_code(message: &str) -> (salvo::http::StatusCode, &'static str) {
    if message.starts_with("message_edit_window")
        || message.starts_with("message_redact_window")
        || message.starts_with("disappearing_")
        || message.starts_with("direct_conversation_")
        || message.starts_with("cross_signing_reset_")
        || message == cokret_sdk::error::REASON_REACTION_SCOPE_MISMATCH
    {
        (
            salvo::http::StatusCode::PRECONDITION_FAILED,
            "failed_precondition",
        )
    } else if message
        == cokret_sdk::error::REASON_HISTORY_VISIBILITY_REQUIRES_HISTORY_CAPABLE_SCHEME
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
    } else if message == crate::error::reasons::TRANSCRIPTION_DENIED {
        (
            salvo::http::StatusCode::FORBIDDEN,
            crate::error::reasons::TRANSCRIPTION_DENIED,
        )
    } else if message == crate::error::reasons::ACCOUNTABILITY_GRANT_MISSING {
        (
            salvo::http::StatusCode::PRECONDITION_FAILED,
            crate::error::reasons::ACCOUNTABILITY_GRANT_MISSING,
        )
    } else if message == "interop_session_writer_unauthorized" {
        (
            salvo::http::StatusCode::FORBIDDEN,
            "interop_session_writer_unauthorized",
        )
    } else if message == cokret_sdk::ERROR_CODE_READ_RECEIPT_COMPLIANCE_FLOOR_VIOLATED {
        (
            salvo::http::StatusCode::UNPROCESSABLE_ENTITY,
            cokret_sdk::ERROR_CODE_READ_RECEIPT_COMPLIANCE_FLOOR_VIOLATED,
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
    } else if message == cokret_sdk::ERROR_CODE_REALM_FROZEN {
        (
            salvo::http::StatusCode::FORBIDDEN,
            cokret_sdk::ERROR_CODE_REALM_FROZEN,
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
    for operation in operations {
        validate_realm_lifecycle_write_gate(state, operation)?;
        if kinds::operation_is_message_create(operation)
            && !message_operation_is_encrypted(operation)
            && known_realm_denies_plaintext_service(state, operation.realm_id.as_str()).await
        {
            return Err(
                "private plaintext message operations require this service in plaintext_visible_services",
            );
        }
        if kinds::canonical_kind_for_operation(operation)
            == Some(cokret_sdk::events::kinds::MORPH_SCHEMA_MIGRATE)
        {
            validate_morph_schema_migrate_capability(operation)?;
            validate_morph_schema_migrate_authz(state, operation).await?;
        }
        validate_principal_control_realm_binding(operation)?;
        validate_accountability_profile_policy(state, operations, operation).await?;
        validate_agent_interop_session_writer_policy(state, operations, operation).await?;
        if kinds::canonical_kind_string(operation) == "ck.cross_signing.publish" {
            crate::routing::identity::cross_signing::validate_cross_signing_publish(
                state,
                &operation.payload,
            )
            .await?;
        }
        if kinds::canonical_kind_string(operation) == "ck.cross_signing.reset" {
            crate::routing::identity::cross_signing::validate_cross_signing_reset(
                state,
                &operation.payload,
            )
            .await?;
        }
        // 3a — verify the cross_signing_binding on ANY ck.device.authorize at
        // ingest (recovery /complete, or a future client-submitted control event).
        if kinds::canonical_kind_string(operation) == "ck.device.authorize" {
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
            cokret_sdk::OperationId::new("ck:operation:01964137-0000-7000-8000-000000000040")
                .unwrap(),
            cokret_sdk::RealmId::new("ck:realm:01964137-0000-7000-8000-000000000030").unwrap(),
            cokret_sdk::events::kinds::CIRCLE_CREATE,
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
        let realm_id = "ck:realm:01964137-0000-7000-8000-000000000030";
        let key = cokret_sdk::agent_sidecar_circle_key(realm_id, actor);
        let short_name = cokret_sdk::agent_sidecar_short_name(&key);
        let valid_payload = serde_json::json!({
            "profile": cokret_sdk::PROFILE_AGENT_SIDECAR_THREAD,
            "sidecar_ensure_capability_verified": true,
            "object": {
                "id": "ck:circle:01964137-0000-7000-8000-000000000041",
                "realm_id": realm_id,
                "title": short_name,
                "display": { "short_name": short_name },
                "directory_visibility": "members",
                "join_rule": "invite",
                "history_visibility": "joined",
                "sidecar_profile": cokret_sdk::PROFILE_AGENT_SIDECAR_THREAD,
                "created_by": actor,
                "controller_principal_id": actor,
                "controller_agent_circle_key": key,
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
