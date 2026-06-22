use super::*;

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
        if kinds::canonical_kind_for_operation(operation) == Some(kinds::CK_MORPH_SCHEMA_MIGRATE) {
            validate_morph_schema_migrate_capability(operation)?;
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
        validate_history_visibility_policy(state, operation).await?;
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

fn realm_frozen_operation_exempt(kind: &str) -> bool {
    kinds::is_audit_kind(kind)
        || matches!(
            kind,
            kinds::CK_REALM_ARCHIVE
                | kinds::CK_REALM_FREEZE
                | kinds::CK_REALM_TOMBSTONE
                | kinds::CK_REALM_DESTROY
        )
}

fn validate_realm_lifecycle_write_gate(
    state: &AppState,
    operation: &Operation,
) -> Result<(), &'static str> {
    let kind = kinds::canonical_kind_string(operation);
    let realm_id = operation.realm_id.as_str();
    let projection = state
        .projection
        .lock()
        .map_err(|_| "projection_unavailable")?;
    if projection.realm_is_in_terminal_state(realm_id) && !kinds::is_audit_kind(&kind) {
        return Err("realm_terminal_state");
    }
    if projection.realm_is_frozen_at(realm_id, chrono::Utc::now())
        && !realm_frozen_operation_exempt(&kind)
    {
        return Err(cokret_sdk::ERROR_CODE_REALM_FROZEN);
    }
    Ok(())
}

async fn validate_circle_create_policy(
    state: &AppState,
    operation: &Operation,
) -> Result<(), &'static str> {
    if kinds::canonical_kind_for_operation(operation) != Some(kinds::CK_CIRCLE_CREATE) {
        return Ok(());
    }
    if payload_asserts_agent_sidecar_ensure(&operation.payload) {
        let Some(actor) = operation_actor(operation) else {
            return Err("sidecar_create_denied");
        };
        if !sidecar_circle_create_shape_is_constrained(&operation.payload, operation, actor) {
            return Err("sidecar_create_denied");
        }
        let realm_id = operation.realm_id.as_str();
        let (owner, members) = realm_owner_and_members(state, realm_id).await;
        let verdict = state.authz.check(
            actor,
            cokret_sdk::CAP_ACTION_AGENT_SIDECAR_THREAD_ENSURE,
            realm_id,
            realm_id,
            owner.as_deref(),
            &members,
            &[],
        );
        if verdict.allowed
            || members.iter().any(|member| member == actor)
            || policy_realm_member_joined(state, realm_id, actor)
        {
            return Ok(());
        }
        return Err("sidecar_create_denied");
    }
    let Some(actor) = operation_actor(operation) else {
        return Ok(());
    };
    let realm_id = operation.realm_id.as_str();
    let (owner, members) = realm_owner_and_members(state, realm_id).await;
    if state
        .authz
        .check(
            actor,
            cokret_sdk::CAP_ACTION_CIRCLE_CREATE,
            realm_id,
            realm_id,
            owner.as_deref(),
            &members,
            &[],
        )
        .allowed
    {
        return Ok(());
    }
    Err("missing_capability")
}

async fn validate_circle_management_policy(
    state: &AppState,
    operation: &Operation,
) -> Result<(), &'static str> {
    let Some(kind) = kinds::canonical_kind_for_operation(operation) else {
        return Ok(());
    };
    let (action, reason) = match kind {
        kinds::CK_CIRCLE_UPDATE
        | kinds::CK_CIRCLE_ARCHIVE
        | kinds::CK_CIRCLE_RESTORE
        | kinds::CK_CIRCLE_TOMBSTONE => ("ck.circle.manage", "circle_manage_capability_required"),
        kinds::CK_CIRCLE_MEMBER_STATE if circle_member_manage_required(operation) => (
            "ck.circle.member.manage",
            "circle_member_manage_capability_required",
        ),
        _ => return Ok(()),
    };
    let Some(actor) = operation_actor(operation) else {
        return Ok(());
    };
    let Some(circle_id) = operation_circle_id(operation) else {
        return Ok(());
    };
    let realm_id = operation.realm_id.as_str();
    let (owner, members) = realm_owner_and_members(state, realm_id).await;
    if state
        .authz
        .check(
            actor,
            action,
            circle_id,
            realm_id,
            owner.as_deref(),
            &members,
            &[],
        )
        .allowed
    {
        return Ok(());
    }
    Err(reason)
}

fn operation_circle_id(operation: &Operation) -> Option<&str> {
    operation
        .payload
        .get("circle_id")
        .and_then(Value::as_str)
        .or_else(|| {
            operation
                .payload
                .get("object")
                .and_then(|object| object.get("id"))
                .and_then(Value::as_str)
        })
}

fn circle_member_manage_required(operation: &Operation) -> bool {
    let Some(actor) = operation_actor(operation) else {
        return false;
    };
    let Some(target) = operation
        .payload
        .get("actor")
        .or_else(|| operation.payload.get("actor_id"))
        .and_then(Value::as_str)
    else {
        return false;
    };
    let membership = operation
        .payload
        .get("state")
        .or_else(|| operation.payload.get("membership"))
        .and_then(Value::as_str)
        .unwrap_or("join");
    target != actor || matches!(membership, "invite" | "invited" | "ban" | "banned")
}

fn policy_realm_member_joined(state: &AppState, realm_id: &str, actor: &str) -> bool {
    state
        .projection
        .lock()
        .ok()
        .and_then(|projection| {
            projection
                .member(realm_id, actor)
                .map(|membership| membership.state == "join")
        })
        .unwrap_or(false)
}

fn payload_asserts_agent_sidecar_ensure(payload: &Value) -> bool {
    let profile_matches = payload.get("profile").and_then(Value::as_str).or_else(|| {
        payload
            .get("object")
            .and_then(|object| object.get("sidecar_profile"))
            .and_then(Value::as_str)
    }) == Some(cokret_sdk::PROFILE_AGENT_SIDECAR_THREAD);
    if !profile_matches {
        return false;
    }
    if payload
        .get("sidecar_ensure_capability_verified")
        .and_then(Value::as_bool)
        == Some(true)
    {
        return true;
    }
    payload
        .get("actor_capability")
        .and_then(Value::as_object)
        .is_some_and(|cap| {
            cap.get("action").and_then(Value::as_str)
                == Some(cokret_sdk::CAP_ACTION_AGENT_SIDECAR_THREAD_ENSURE)
                && cap.get("allowed").and_then(Value::as_bool) == Some(true)
        })
}

fn sidecar_circle_create_shape_is_constrained(
    payload: &Value,
    operation: &Operation,
    actor: &str,
) -> bool {
    let Some(object) = payload.get("object").and_then(Value::as_object) else {
        return false;
    };
    let realm_id = operation.realm_id.as_str();
    let controller = object
        .get("controller_principal_id")
        .and_then(Value::as_str)
        .unwrap_or(actor);
    if controller != actor {
        return false;
    }
    if object.get("realm_id").and_then(Value::as_str) != Some(realm_id) {
        return false;
    }
    if object.get("created_by").and_then(Value::as_str) != Some(actor) {
        return false;
    }
    if object.get("sidecar_profile").and_then(Value::as_str)
        != Some(cokret_sdk::PROFILE_AGENT_SIDECAR_THREAD)
    {
        return false;
    }
    if object.get("directory_visibility").and_then(Value::as_str) != Some("members") {
        return false;
    }
    if object.get("join_rule").and_then(Value::as_str) != Some("invite") {
        return false;
    }
    if object.get("history_visibility").and_then(Value::as_str) != Some("joined") {
        return false;
    }
    let expected_key = cokret_sdk::agent_sidecar_circle_key(realm_id, actor);
    if object
        .get("controller_agent_circle_key")
        .and_then(Value::as_str)
        != Some(expected_key.as_str())
    {
        return false;
    }
    let expected_short_name = cokret_sdk::agent_sidecar_short_name(&expected_key);
    object.get("title").and_then(Value::as_str) == Some(expected_short_name.as_str())
        && object
            .get("display")
            .and_then(|display| display.get("short_name"))
            .and_then(Value::as_str)
            == Some(expected_short_name.as_str())
}

async fn validate_agent_interop_session_writer_policy(
    state: &AppState,
    operations: &[Operation],
    operation: &Operation,
) -> Result<(), &'static str> {
    let Some(kind) = kinds::canonical_kind_for_operation(operation) else {
        return Ok(());
    };
    if !matches!(
        kind,
        kinds::CK_AGENT_INTEROP_SESSION_STATUS | kinds::CK_AGENT_INTEROP_SESSION_RESULT
    ) {
        return Ok(());
    }
    let Some(session_id) = agent_interop_session_id_from_payload(&operation.payload) else {
        return Err("interop_session_writer_unauthorized");
    };
    let Some(actor) = operation_actor(operation) else {
        return Err("interop_session_writer_unauthorized");
    };
    if agent_interop_session_start_actor(state, operations, operation.realm_id.as_str(), session_id)
        .await
        .as_deref()
        == Some(actor)
    {
        return Ok(());
    }
    if agent_interop_session_delegate_allows(state, operation, actor, session_id) {
        return Ok(());
    }
    Err("interop_session_writer_unauthorized")
}

fn agent_interop_session_id_from_payload(payload: &Value) -> Option<&str> {
    payload
        .get("session_id")
        .and_then(Value::as_str)
        .filter(|value| value.starts_with("ck:agent_interop_session:"))
}

async fn agent_interop_session_start_actor(
    state: &AppState,
    operations: &[Operation],
    realm_id: &str,
    session_id: &str,
) -> Option<String> {
    if let Some(actor) = operations.iter().find_map(|candidate| {
        (kinds::canonical_kind_for_operation(candidate)
            == Some(kinds::CK_AGENT_INTEROP_SESSION_START)
            && candidate.realm_id.as_str() == realm_id
            && agent_interop_session_id_from_payload(&candidate.payload) == Some(session_id))
        .then(|| operation_actor(candidate).map(ToOwned::to_owned))
        .flatten()
    }) {
        return Some(actor);
    }
    state
        .persistence
        .events()
        .snapshot_all()
        .await
        .ok()?
        .iter()
        .find_map(|record| {
            if record.kind != kinds::CK_AGENT_INTEROP_SESSION_START {
                return None;
            }
            if record.realm_id.as_deref() != Some(realm_id) {
                return None;
            }
            let payload = record.envelope.get("payload").unwrap_or(&record.envelope);
            if agent_interop_session_id_from_payload(payload) != Some(session_id) {
                return None;
            }
            Some(record.actor_id.clone())
        })
}

fn agent_interop_session_delegate_allows(
    state: &AppState,
    operation: &Operation,
    actor: &str,
    session_id: &str,
) -> bool {
    let actions = agent_interop_session_delegate_actions(operation);
    if actions.is_empty() {
        return false;
    }
    state
        .authz
        .grants_for_subject(actor, operation.realm_id.as_str())
        .iter()
        .any(|grant| {
            let action_allowed = grant.actions.iter().any(|action| {
                actions
                    .iter()
                    .any(|candidate| action.as_str() == *candidate)
            });
            let resource_allowed =
                crate::authz::resource_matches(&grant.resource, operation.realm_id.as_str())
                    || crate::authz::resource_matches(&grant.resource, session_id);
            let has_blocking_decision = grant.constraints.iter().any(|constraint| {
                matches!(
                    constraint,
                    crate::authz::Constraint::Decision {
                        decision: crate::authz::GrantDecisionVerdict::Deny
                            | crate::authz::GrantDecisionVerdict::Quarantine
                            | crate::authz::GrantDecisionVerdict::RequireReview
                    }
                )
            });
            let session_allowed = grant.constraints.iter().any(|constraint| {
                matches!(
                    constraint,
                    crate::authz::Constraint::AllowedSessionIds { allowed_session_ids }
                        if allowed_session_ids.iter().any(|allowed| allowed.as_ref() == session_id)
                )
            });
            action_allowed && resource_allowed && !has_blocking_decision && session_allowed
        })
}

fn agent_interop_session_delegate_actions(operation: &Operation) -> &'static [&'static str] {
    let cancelled = operation.payload.get("status").and_then(Value::as_str) == Some("cancelled");
    match kinds::canonical_kind_for_operation(operation) {
        Some(kinds::CK_AGENT_INTEROP_SESSION_STATUS) if cancelled => {
            &["ck.agent.interop_session.cancel"]
        }
        Some(kinds::CK_AGENT_INTEROP_SESSION_STATUS) => &["ck.agent.interop_session.stream_status"],
        Some(kinds::CK_AGENT_INTEROP_SESSION_RESULT) if cancelled => {
            &["ck.agent.interop_session.cancel"]
        }
        Some(kinds::CK_AGENT_INTEROP_SESSION_RESULT) => {
            &["ck.agent.interop_session.attach_artifact"]
        }
        _ => &[],
    }
}

fn validate_pin_scope_safety(state: &AppState, operation: &Operation) -> Result<(), &'static str> {
    if !kinds::canonical_kind_for_operation(operation).is_some_and(kinds::is_pin_kind) {
        return Ok(());
    }
    let Ok(projection) = state.projection.lock() else {
        return Err("pin_scope_safety_unavailable");
    };
    projection.check_pin_scope_safety(operation)
}

async fn validate_accountability_profile_policy(
    state: &AppState,
    operations: &[Operation],
    operation: &Operation,
) -> Result<(), &'static str> {
    if !matches!(
        kinds::canonical_kind_string(operation).as_str(),
        "ck.profile.create" | "ck.profile.update"
    ) {
        return Ok(());
    }
    let accountable_principal_ids = profile_accountable_principal_ids(operation);
    if accountable_principal_ids.is_empty() {
        return Ok(());
    }
    let Some(principal_id) = profile_principal_id(operation) else {
        return Err(crate::error::reasons::ACCOUNTABILITY_GRANT_MISSING);
    };
    let now = chrono::Utc::now();
    let accepted_events = state
        .persistence
        .events()
        .snapshot_all()
        .await
        .unwrap_or_default();
    for issuer in accountable_principal_ids {
        let in_batch = operations.iter().any(|candidate| {
            accountability_grant_operation_active_for(
                candidate,
                operation.realm_id.as_str(),
                &issuer,
                &principal_id,
                now,
            )
        });
        let accepted = accepted_events.iter().any(|record| {
            if record.kind != "ck.identity.accountability_grant" {
                return false;
            }
            if record.realm_id.as_deref() != Some(operation.realm_id.as_str()) {
                return false;
            }
            if !accountability_grant_envelope_signed_by(record, &issuer) {
                return false;
            }
            let payload = record.envelope.get("payload").unwrap_or(&record.envelope);
            accountability_grant_value_active_for(payload, &issuer, &principal_id, now)
        });
        if !in_batch && !accepted {
            return Err(crate::error::reasons::ACCOUNTABILITY_GRANT_MISSING);
        }
    }
    Ok(())
}

fn profile_body_value(operation: &Operation) -> &Value {
    operation
        .payload
        .get("profile")
        .or_else(|| operation.payload.get("object"))
        .or_else(|| operation.payload.get("value"))
        .unwrap_or(&operation.payload)
}

fn profile_principal_id(operation: &Operation) -> Option<String> {
    let body = profile_body_value(operation);
    body.get("principal_id")
        .or_else(|| body.get("actor_id"))
        .or_else(|| operation.payload.get("principal_id"))
        .or_else(|| operation.payload.get("actor_id"))
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(ToOwned::to_owned)
}

fn profile_accountable_principal_ids(operation: &Operation) -> Vec<String> {
    let body = profile_body_value(operation);
    body.get("accountable_principal_ids")
        .or_else(|| operation.payload.get("accountable_principal_ids"))
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToOwned::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

fn accountability_grant_operation_active_for(
    operation: &Operation,
    realm_id: &str,
    issuer: &str,
    subject: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> bool {
    kinds::canonical_kind_string(operation) == "ck.identity.accountability_grant"
        && operation.realm_id.as_str() == realm_id
        && accountability_grant_operation_signed_by(operation, issuer)
        && accountability_grant_value_active_for(&operation.payload, issuer, subject, now)
}

fn accountability_grant_operation_signed_by(operation: &Operation, issuer: &str) -> bool {
    operation
        .payload
        .get("executed_by")
        .or_else(|| operation.payload.get("sender"))
        .and_then(Value::as_str)
        == Some(issuer)
}

fn accountability_grant_envelope_signed_by(
    record: &crate::state::CanonicalEventRecord,
    issuer: &str,
) -> bool {
    record
        .envelope
        .get("executed_by")
        .and_then(Value::as_str)
        .unwrap_or(record.actor_id.as_str())
        == issuer
}

fn accountability_grant_body(value: &Value) -> &Value {
    value
        .get("grant")
        .filter(|grant| grant.is_object())
        .or_else(|| value.get("value").filter(|grant| grant.is_object()))
        .or_else(|| value.get("object").filter(|grant| grant.is_object()))
        .unwrap_or(value)
}

fn accountability_grant_value_active_for(
    value: &Value,
    issuer: &str,
    subject: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> bool {
    let body = accountability_grant_body(value);
    if body.get("issuer").and_then(Value::as_str) != Some(issuer) {
        return false;
    }
    if body
        .get("subject")
        .or_else(|| body.get("subject_id"))
        .or_else(|| body.get("principal_id"))
        .and_then(Value::as_str)
        != Some(subject)
    {
        return false;
    }
    if body
        .get("grant_status")
        .or_else(|| body.get("status"))
        .and_then(Value::as_str)
        .is_some_and(|status| !matches!(status, "active" | "granted"))
    {
        return false;
    }
    let Some(not_before) = accountability_grant_time(body, "not_before")
        .or_else(|| accountability_grant_time(body, "issued_at"))
    else {
        return false;
    };
    let Some(expires_at) = accountability_grant_time(body, "expires_at") else {
        return false;
    };
    not_before <= now && now <= expires_at
}

fn accountability_grant_time(value: &Value, field: &str) -> Option<chrono::DateTime<chrono::Utc>> {
    value
        .get(field)
        .and_then(Value::as_str)
        .and_then(|raw| chrono::DateTime::parse_from_rfc3339(raw).ok())
        .map(|parsed| parsed.with_timezone(&chrono::Utc))
}

/// SEC-08 — server-side defence-in-depth for `ck.profile.mls.minimal_metadata_realm.v1`
/// Realms (`crypto-media/encryption-and-audit.md` §2.9).
///
/// For a Realm that has declared the minimal-metadata profile, an encrypted
/// `ck.message.create` / reaction envelope MUST set
/// `aad_visibility_event_id="hidden"`; any other value (or an absent
/// discriminator on an encrypted envelope) is rejected so message-id exposure
/// cannot widen reaction-frequency correlation from per-`target_ref` to
/// per-message. The fail-closed decision is delegated to the SDK helper
/// [`cokret_sdk::mls::enforce_minimal_metadata_aad`] so the wire enum mapping
/// stays single-sourced.
///
/// Scope notes (honest boundary): soland holds no MLS group key and is not the
/// committer, so the §2.9 `epoch lifetime MUST ≤ 1h` obligation stays a client /
/// committer duty (SDK `minimal_metadata_epoch_overdue`). This gate only
/// enforces the aad-visibility half, and only when soland can observe the
/// profile declaration in projected Realm meta and the discriminator on the
/// encrypted envelope; plaintext operations are unaffected.
async fn validate_minimal_metadata_aad_policy(
    state: &AppState,
    operation: &Operation,
) -> Result<(), &'static str> {
    let kind = kinds::canonical_kind_for_operation(operation);
    let is_message_or_reaction = matches!(
        kind,
        Some(kinds::CK_MESSAGE_CREATE | kinds::CK_REACTION_ADD | kinds::CK_REACTION_REMOVE)
    );
    if !is_message_or_reaction {
        return Ok(());
    }
    // Only encrypted envelopes carry an aad-visibility discriminator; plaintext
    // operations are governed by other policy gates.
    let Some(envelope) = operation.payload.get("encrypted_content") else {
        return Ok(());
    };
    // Fail closed only for Realms we can positively confirm declared the
    // minimal-metadata profile; absent meta (target realm unknown) leaves the
    // obligation to the committer / client.
    let is_minimal = state
        .persistence
        .realm_meta()
        .get(operation.realm_id.as_str())
        .await
        .ok()
        .flatten()
        .is_some_and(|record| record.minimal_metadata_realm);
    if !is_minimal {
        return Ok(());
    }
    let Some(visibility) = minimal_metadata_aad_visibility(envelope) else {
        // Minimal-metadata Realm + encrypted envelope with no / unrecognised
        // discriminator → cannot prove it is `hidden`, so fail closed.
        return Err(
            "minimal_metadata_realm encrypted envelope requires aad_visibility_event_id=hidden",
        );
    };
    cokret_sdk::mls::enforce_minimal_metadata_aad(&visibility, true)
        .map_err(|_| "minimal_metadata_realm requires aad_visibility_event_id=hidden")
}

/// SEC-08 — map the wire `aad_visibility_event_id` discriminator on an encrypted
/// envelope to the SDK [`cokret_sdk::mls::AadVisibility`] enum. Returns `None`
/// when the field is missing or carries an unknown value, which the caller
/// treats as fail-closed for a minimal-metadata Realm.
fn validate_disappearing_message_policy(
    state: &AppState,
    operation: &Operation,
) -> Result<(), &'static str> {
    if !kinds::operation_is_message_create(operation) || operation.payload.get("expiry").is_none() {
        return Ok(());
    }
    validate_message_expiry_payload(operation)?;
    let expiry = operation
        .payload
        .get("expiry")
        .and_then(Value::as_object)
        .ok_or("disappearing_expiry_invalid")?;
    let ttl_ms = expiry
        .get("ttl_ms")
        .and_then(Value::as_u64)
        .ok_or("disappearing_expiry_ttl_missing")?;
    let trigger = expiry
        .get("trigger")
        .and_then(Value::as_str)
        .ok_or("disappearing_expiry_trigger_missing")?;
    let policy = state
        .projection
        .lock()
        .ok()
        .and_then(|projection| {
            projection
                .realm_disappearing_policy_cell_value(operation.realm_id.as_str())
                .cloned()
        })
        .ok_or("disappearing_policy_unset")?;
    if !policy
        .get("enabled")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        return Err("disappearing_policy_disabled");
    }
    let max_ttl_ms = policy
        .get("max_ttl_ms")
        .and_then(Value::as_u64)
        .ok_or("disappearing_policy_max_ttl_missing")?;
    if ttl_ms > max_ttl_ms {
        return Err("disappearing_ttl_exceeds_policy");
    }
    let trigger_allowed = policy
        .get("allowed_triggers")
        .and_then(Value::as_array)
        .is_some_and(|triggers| triggers.iter().any(|value| value.as_str() == Some(trigger)));
    if !trigger_allowed {
        return Err("disappearing_trigger_not_allowed");
    }
    if !message_operation_is_encrypted(operation)
        && !policy
            .get("allow_plaintext_realms")
            .and_then(Value::as_bool)
            .unwrap_or(false)
    {
        return Err("disappearing_plaintext_realm_not_allowed");
    }
    Ok(())
}

pub(super) fn minimal_metadata_aad_visibility(
    envelope: &Value,
) -> Option<cokret_sdk::mls::AadVisibility> {
    use cokret_sdk::mls::AadVisibility;
    // The discriminator lives at the envelope root; tolerate a nested
    // `envelope` wrapper as shown in the spec wire example.
    let raw = envelope
        .pointer("/aad_visibility_event_id")
        .or_else(|| envelope.pointer("/envelope/aad_visibility_event_id"))
        .and_then(Value::as_str)?;
    match raw {
        "hidden" => Some(AadVisibility::Hidden),
        "routing_digest" => Some(AadVisibility::RoutingDigest),
        "opaque_id" => Some(AadVisibility::OpaqueId),
        _ => None,
    }
}

/// strand-and-message.md §9.8.2 — a reaction MUST target an object inside its
/// own effective scope. soland's effective scope is the Realm, so a
/// `ck.reaction.*` whose `target_ref` resolves to a Message in a different
/// Realm is rejected with `reaction_scope_mismatch` (a `failed_precondition`
/// sub-reason). The target-kind gate (`reaction_target_unsupported`) already
/// ran in `validate_operation_semantics`; an unknown / not-yet-observed
/// target is left to the reducer's dependency handling.
fn validate_reaction_scope_policy(
    state: &AppState,
    operation: &Operation,
) -> Result<(), &'static str> {
    let Some(kind) = kinds::canonical_kind_for_operation(operation) else {
        return Ok(());
    };
    if !matches!(kind, kinds::CK_REACTION_ADD | kinds::CK_REACTION_REMOVE) {
        return Ok(());
    }
    let target = REACTION_TARGET_FIELDS.iter().find_map(|field| {
        operation
            .payload
            .get(*field)
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
    });
    let Some(target) = target else {
        return Ok(());
    };
    let Some(target_realm) = state
        .projection
        .lock()
        .ok()
        .and_then(|projection| projection.message_realm(target))
    else {
        // Target not yet observed — reducer keeps the reaction pending.
        return Ok(());
    };
    if realm_ids_match(operation.realm_id.as_str(), &target_realm) {
        Ok(())
    } else {
        Err(cokret_sdk::error::REASON_REACTION_SCOPE_MISMATCH)
    }
}

/// circle.md §8 — resolve the Circle a write operation lands content into, if
/// any. Returns the `ck:circle:…` id when the operation introduces, mutates, or
/// tombstones a Circle-scoped object, else `None` (Realm-default scope).
/// Object-carrying creates declare scope inline (`payload.object` /
/// `payload.relation` / top-level `scope_circle_id`); updates and lifecycle
/// writes derive scope from the projected target. `ck.message.create` derives
/// scope from the projected Strand — a Message never self-declares its scope.
fn operation_target_scope_circle_id(
    projection: &crate::reducer::ProjectionState,
    operation: &Operation,
) -> Option<String> {
    let top_level_scope = || -> Option<String> {
        operation
            .payload
            .get("scope_circle_id")
            .and_then(Value::as_str)
            .filter(|value| value.starts_with("ck:circle:"))
            .map(ToOwned::to_owned)
    };
    let inline_scope = |field: &str| -> Option<String> {
        operation
            .payload
            .get(field)
            .and_then(Value::as_object)
            .and_then(|object| object.get("scope_circle_id"))
            .and_then(Value::as_str)
            .filter(|value| value.starts_with("ck:circle:"))
            .map(ToOwned::to_owned)
    };
    let relation_scope = |field: &str| -> Option<String> {
        operation
            .payload
            .get(field)
            .and_then(Value::as_str)
            .and_then(|relation_id| projection.relation_scope_circle_id(relation_id))
    };
    let strand_scope = |field: &str| -> Option<String> {
        operation
            .payload
            .get(field)
            .and_then(Value::as_str)
            .and_then(|strand_id| projection.strand_scope_circle_id(strand_id))
    };
    let morph_scope = |field: &str| -> Option<String> {
        operation
            .payload
            .get(field)
            .and_then(Value::as_str)
            .and_then(|morph_id| projection.morph_scope_circle_id(morph_id))
    };
    match kinds::canonical_kind_for_operation(operation)? {
        kinds::CK_STRAND_CREATE | kinds::CK_MORPH_CREATE | kinds::CK_SPACE_CONTAINER_CREATE => {
            inline_scope("object")
        }
        kinds::CK_RELATION_CREATE => inline_scope("relation")
            .or_else(|| inline_scope("object"))
            .or_else(top_level_scope),
        kinds::CK_RELATION_UPDATE | kinds::CK_RELATION_DELETE => {
            relation_scope("relation_id").or_else(|| relation_scope("id"))
        }
        kinds::CK_MESSAGE_CREATE | kinds::CK_STRAND_UPDATE => strand_scope("strand_id"),
        kinds::CK_MORPH_UPDATE | kinds::CK_MORPH_ARCHIVE | kinds::CK_MORPH_RESTORE => {
            morph_scope("target_ref")
        }
        kinds::CK_STRAND_ARCHIVE
        | kinds::CK_STRAND_RESTORE
        | kinds::CK_STRAND_MOVE
        | kinds::CK_STRAND_REORDER => {
            strand_scope("target_ref").or_else(|| strand_scope("strand_id"))
        }
        kinds::CK_REACTION_ADD | kinds::CK_REACTION_REMOVE => {
            // A reaction's scope is the target Message's Strand scope — reacting
            // into a Circle is a write into that scope and requires Circle
            // membership just like authoring there. Unknown target (not yet
            // observed) → None: the reducer keeps the reaction pending and a
            // non-member cannot name a Circle message id it never received.
            let target = REACTION_TARGET_FIELDS.iter().find_map(|field| {
                operation
                    .payload
                    .get(*field)
                    .and_then(Value::as_str)
                    .filter(|value| !value.trim().is_empty())
            })?;
            let (_, _, thread_id) = projection.message_origin(target)?;
            projection.strand_scope_circle_id(&thread_id)
        }
        _ => None,
    }
}

/// circle.md §8 — the membership half of the two-layer authorization AND for
/// Circle-scoped writes:
///
/// ```text
/// authorized ⇔ capability_grant(actor, action)
///              ∧ (effective_scope.kind == "realm" ∨ actor ∈ Circle.members)
/// ```
///
/// Holding a Realm-wide capability does **not** authorize writing into a Circle:
/// the author MUST also be a member of that Circle. Without this gate any holder
/// of a Realm-wide grant — notably an Applet bot / Ghost Actor
/// (`extensions/applet-integration.md` §3.4.1, which requires a deployment to be
/// able to keep Realm-level automation out of Circles) — could inject Strands /
/// Morphs / Messages into a Circle it never joined. The Sync-side scope filter
/// (`circle_scope_visible_to_actor` in delivery) only hides reads from
/// non-members; it does not stop the write, so membership MUST be enforced at
/// admission too.
///
/// Coverage: object-carrying creates (Strand / Morph / Space / Relation),
/// relation update/tombstone, `ck.message.create`, Strand update / lifecycle,
/// Morph update / lifecycle, and `ck.reaction.add` / `ck.reaction.remove`
/// (scope derived from the target Message's Strand).
///
/// Membership is evaluated against the current Circle projection (soland's
/// convergence frontier), matching the delivery-side check. Peer / service-
/// originated federation operations without a typed actor stay accepted
/// (convergence / backfill), mirroring the ban / moderation gates; direct client
/// and Applet submits always carry an actor and are gated.
fn validate_circle_scope_membership(
    state: &AppState,
    operation: &Operation,
) -> Result<(), &'static str> {
    let Ok(projection) = state.projection.lock() else {
        // A poisoned projection lock is a server fault, not an authorization
        // grant — fail closed rather than silently admitting the write.
        return Err("circle_scope_membership_unavailable");
    };
    let Some(scope_circle_id) = operation_target_scope_circle_id(&projection, operation) else {
        return Ok(());
    };
    let Some(actor) = operation_actor(operation) else {
        return Ok(());
    };
    if projection.circle_scope_visible_to_actor(&scope_circle_id, actor) {
        Ok(())
    } else {
        Err("circle_scope_membership_required")
    }
}

/// applet-integration.md §4 / §4b — installing an Applet into a Realm is gated
/// by the machine-readable `ck.realm.admin` capability: the actor submitting a
/// `ck.applet.registration` MUST own the target Realm or hold an active
/// `ck.realm.admin` grant covering it, else reject `applet_registration_unauthorized`.
///
/// The dedicated install aggregate (`POST /_cokret/self/applets/install`) checks
/// this in its own handler and persists the registration projection directly —
/// it does NOT flow through this admission path. This gate closes the *bypass*:
/// a raw `ck.applet.registration` submitted via `/_cokret/self/events` otherwise
/// reaches `apply_applet_registration` with no authorization of its own.
/// Registration staying `service_attested` (carrier authenticity) is orthogonal
/// to "who may install" (§4) — both must hold. Mirrors the ban gate
/// (`validate_member_state_policy`); peer / service-originated federation ops
/// without a typed actor stay accepted for convergence.
async fn validate_applet_registration_authz(
    state: &AppState,
    operation: &Operation,
) -> Result<(), &'static str> {
    if kinds::canonical_kind_for_operation(operation) != Some(kinds::CK_APPLET_REGISTRATION) {
        return Ok(());
    }
    let Some(actor) = operation_actor(operation) else {
        return Ok(());
    };
    let realm_id = operation.realm_id.as_str();
    if realm_owner_matches(state, realm_id, actor).await {
        return Ok(());
    }
    let (owner, members) = realm_owner_and_members(state, realm_id).await;
    if state
        .authz
        .check(
            actor,
            "ck.realm.admin",
            realm_id,
            realm_id,
            owner.as_deref(),
            &members,
            &[],
        )
        .allowed
    {
        return Ok(());
    }
    Err("applet_registration_unauthorized")
}

/// Control-stream events carry their owning principal in `payload.principal_id`.
const PRINCIPAL_CONTROL_EVENT_KINDS: &[&str] = &[
    "ck.device.authorize",
    "ck.device.list_update",
    "ck.device.revoke",
    "ck.cross_signing.publish",
    "ck.cross_signing.reset",
];

/// Phase 2 — principal control realm isolation (key-management.md §4.1). A
/// control-stream event MUST land on its principal's deterministic control realm
/// (`principal_control_realm_for_did(payload.principal_id)`); it cannot be
/// written into a collaboration realm or another principal's control realm.
pub(super) fn validate_principal_control_realm_binding(
    operation: &Operation,
) -> Result<(), &'static str> {
    let kind = kinds::canonical_kind_string(operation);
    if !PRINCIPAL_CONTROL_EVENT_KINDS.contains(&kind.as_str()) {
        return Ok(());
    }
    let principal = operation
        .payload
        .get("principal_id")
        .and_then(Value::as_str)
        .ok_or("principal_control_event_missing_principal_id")?;
    let expected = crate::routing::identity::recovery::principal_control_realm_for_did(principal);
    if realm_ids_match(operation.realm_id.as_str(), &expected) {
        Ok(())
    } else {
        Err("principal_control_realm_mismatch")
    }
}

pub(crate) fn realm_ids_match(a: &str, b: &str) -> bool {
    a == b
}

/// constraint-schema.md §14.2 — enforce the message edit / redact temporal
/// windows declared on the actor's grants.
///
/// The pure SDK constraint engine cannot run on this path (it needs the
/// target Message `created_at` plus the actor's effective grant set), so
/// soland evaluates the window at admission time. The rules:
///
/// - The window only bites when a grant authorizing the relevant `.own` action carries a `temporal`
///   window field. With no such grant the action is unbounded (default member / owner behaviour is
///   unchanged).
/// - Holding the broader `ck.message.revise` / `ck.message.redact` capability (or `*`), or being
///   the Realm owner, lifts the window entirely (admin override).
/// - `message_redact_window` is authoritative for redact; otherwise redact shares the edit window
///   unless `allow_redact_after_window` is set.
async fn validate_message_edit_redact_window_policy(
    state: &AppState,
    operation: &Operation,
) -> Result<(), &'static str> {
    let Some(kind) = kinds::canonical_kind_for_operation(operation) else {
        return Ok(());
    };
    let is_redact = matches!(kind, kinds::CK_MESSAGE_REDACT | kinds::CK_REDACTION);
    let is_revise = matches!(kind, kinds::CK_MESSAGE_REVISE);
    if !is_redact && !is_revise {
        return Ok(());
    }
    let Some(actor) = operation_actor(operation) else {
        return Ok(());
    };
    let realm_id = operation.realm_id.as_str();

    // Realm owner is exempt from the .own window (admin override).
    if realm_owner_matches(state, realm_id, actor).await {
        return Ok(());
    }

    // Resolve the target Message's creation time.
    let target_ref = if is_redact {
        operation
            .payload
            .get("target_event_id")
            .or_else(|| operation.payload.get("target"))
            .or_else(|| operation.payload.get("redacts"))
    } else {
        operation
            .payload
            .get("target_event_id")
            .or_else(|| operation.payload.get("target_ref"))
            .or_else(|| operation.payload.get("revision_of"))
            .or_else(|| operation.payload.get("event_id"))
    }
    .and_then(Value::as_str)
    .filter(|value| !value.is_empty());
    let Some(target_ref) = target_ref else {
        return Ok(());
    };
    let Some(created_at) = state
        .projection
        .lock()
        .ok()
        .and_then(|projection| projection.message_origin(target_ref).map(|origin| origin.0))
    else {
        // Unknown target — leave it to the reducer's dependency handling.
        return Ok(());
    };

    let (own_action, broad_action) = if is_redact {
        ("ck.message.redact.own", "ck.message.redact")
    } else {
        ("ck.message.revise.own", "ck.message.revise")
    };

    let grants = state.authz.grants_for_subject(actor, realm_id);

    // Admin override: a broader (non-`.own`) capability is not time-boxed.
    let holds_broad = grants.iter().any(|grant| {
        grant
            .actions
            .iter()
            .any(|action| action == broad_action)
    });
    if holds_broad {
        return Ok(());
    }

    let age = operation.created_at - created_at;
    let mut saw_window = false;
    let mut permitted = false;
    for grant in &grants {
        let authorizes = grant
            .actions
            .iter()
            .any(|action| action == own_action || action == broad_action);
        if !authorizes {
            continue;
        }
        for constraint in &grant.constraints {
            if let crate::authz::Constraint::Temporal {
                message_edit_window,
                message_redact_window,
                allow_redact_after_window,
                ..
            } = constraint
            {
                if message_edit_window.is_none() && message_redact_window.is_none() {
                    continue; // plain expiry-only temporal constraint
                }
                saw_window = true;
                if message_window_permits(
                    is_redact,
                    age,
                    message_edit_window.as_ref(),
                    message_redact_window.as_ref(),
                    *allow_redact_after_window,
                ) {
                    permitted = true;
                }
            }
        }
    }

    // No window declared anywhere → unbounded. Otherwise allow when at least
    // one authorizing grant's window still permits the action.
    if !saw_window || permitted {
        Ok(())
    } else if is_redact {
        Err("message_redact_window elapsed")
    } else {
        Err("message_edit_window elapsed")
    }
}

/// Decide whether a single grant's window permits the action, per §14.2.
pub(crate) fn message_window_permits(
    is_redact: bool,
    age: chrono::Duration,
    message_edit_window: Option<&cokret_sdk::authz::ConstraintDuration>,
    message_redact_window: Option<&cokret_sdk::authz::ConstraintDuration>,
    allow_redact_after_window: bool,
) -> bool {
    if is_redact {
        // Redact window is authoritative when declared.
        if let Some(window) = message_redact_window {
            return duration_covers_age(window, age);
        }
        // Otherwise redact is coupled to the edit window unless the grant
        // opts out (then recall is unbounded).
        if allow_redact_after_window {
            return true;
        }
        if let Some(window) = message_edit_window {
            return duration_covers_age(window, age);
        }
        return true;
    }
    match message_edit_window {
        Some(window) => duration_covers_age(window, age),
        None => true,
    }
}

/// `true` when `age` is within the constraint window (mirror of the SDK
/// `max_age_contains` helper). Unknown units fail closed.
fn duration_covers_age(
    window: &cokret_sdk::authz::ConstraintDuration,
    age: chrono::Duration,
) -> bool {
    let allowed = match window.unit.as_str() {
        "s" => chrono::Duration::seconds(window.value as i64),
        "m" => chrono::Duration::minutes(window.value as i64),
        "h" => chrono::Duration::hours(window.value as i64),
        "d" => chrono::Duration::days(window.value as i64),
        _ => return false,
    };
    age <= allowed
}

pub async fn validate_content_encryption_floor(
    state: &AppState,
    operations: &[Operation],
) -> Result<(), &'static str> {
    for operation in operations {
        match kinds::canonical_kind_for_operation(operation) {
            Some(kinds::CK_REALM_UPDATE) if operation_touches_encryption_profile(operation) => {
                return Err(REALM_ENCRYPTION_PROFILE_CREATE_LOCKED);
            }
            Some(kinds::CK_CIRCLE_UPDATE) if operation_touches_encryption_profile(operation) => {
                return Err(CIRCLE_ENCRYPTION_PROFILE_CREATE_LOCKED);
            }
            Some(kinds::CK_CIRCLE_CREATE) => {
                if let Some(profile) = operation_circle_encryption_profile(operation)
                    && !encryption_profile_requires_content_encryption(Some(profile))
                    && realm_requires_content_encryption(state, operation.realm_id.as_str()).await
                {
                    return Err(CIRCLE_ENCRYPTION_BELOW_REALM_FLOOR);
                }
            }
            _ => {}
        }
        if strand_operation_carries_plaintext_private_content(operation)
            && realm_content_floor_requires_e2ee(state, operation.realm_id.as_str())
        {
            return Err(CONTENT_ENCRYPTION_FLOOR_VIOLATION);
        }
    }
    Ok(())
}

// ── CKP-0016 — agent participation ceiling (admission validate + projection write) ──

fn ap_uuid_part(typed_id: &str) -> &str {
    typed_id.rsplit(':').next().unwrap_or(typed_id)
}

fn ap_bool(value: &Value, key: &str) -> bool {
    value.get(key).and_then(Value::as_bool).unwrap_or(false)
}

/// Extract the agent_participation ceiling a realm-policy / circle / strand
/// operation carries, plus the parent scope_key chain to validate
/// tighten-only against. Returns `(scope_kind, scope_key, child_ceiling,
/// parent_scope_keys)` or None when the operation carries no ceiling.
fn agent_participation_ceiling_change(
    operation: &Operation,
) -> Option<(
    &'static str,
    String,
    cokret_sdk::models::AgentParticipation,
    Vec<String>,
)> {
    use cokret_sdk::models::AgentParticipation;
    let payload = &operation.payload;
    let realm_uuid = ap_uuid_part(operation.realm_id.as_str()).to_owned();
    let find = |native: bool| -> Option<Value> {
        let base = payload
            .get("agent_participation")
            .or_else(|| {
                payload
                    .get("patch")
                    .and_then(|p| p.get("agent_participation"))
            })
            .or_else(|| {
                payload
                    .get("state")
                    .and_then(|p| p.get("agent_participation"))
            })
            .or_else(|| {
                payload
                    .get("object")
                    .and_then(|p| p.get("agent_participation"))
            })?;
        if native {
            base.get("native_agent").cloned()
        } else {
            Some(base.clone())
        }
    };
    let to_part = |value: &Value| AgentParticipation {
        reply: ap_bool(value, "reply"),
        accept_third_party_mention: ap_bool(value, "accept_third_party_mention"),
        act_on_behalf: ap_bool(value, "act_on_behalf"),
    };
    let id_of = |key: &str| -> Option<String> {
        payload
            .get(key)
            .and_then(Value::as_str)
            .or_else(|| {
                payload
                    .get("patch")
                    .and_then(|p| p.get(key))
                    .and_then(Value::as_str)
            })
            .or_else(|| {
                payload
                    .get("object")
                    .and_then(|p| p.get("id"))
                    .and_then(Value::as_str)
            })
            .map(ToOwned::to_owned)
    };
    match kinds::canonical_kind_for_operation(operation) {
        Some(kinds::CK_REALM_POLICY_COMPONENTS) => {
            let value = find(true)?;
            Some((
                "realm",
                format!("realm:{realm_uuid}"),
                to_part(&value),
                Vec::new(),
            ))
        }
        Some(kinds::CK_CIRCLE_CREATE) | Some(kinds::CK_CIRCLE_UPDATE) => {
            let value = find(false)?;
            let circle_uuid = ap_uuid_part(&id_of("circle_id")?).to_owned();
            Some((
                "circle",
                format!("circle:{realm_uuid}:{circle_uuid}"),
                to_part(&value),
                vec![format!("realm:{realm_uuid}")],
            ))
        }
        Some(kinds::CK_STRAND_CREATE) | Some(kinds::CK_STRAND_UPDATE) => {
            let value = find(false)?;
            let strand_uuid = ap_uuid_part(&id_of("strand_id")?).to_owned();
            Some((
                "strand",
                format!("strand:{realm_uuid}:{strand_uuid}"),
                to_part(&value),
                vec![format!("realm:{realm_uuid}")],
            ))
        }
        _ => None,
    }
}

/// Admission gate (CKP-0016 §3 invariant 1): an inner-scope
/// `agent_participation` ceiling MUST NOT widen its parent ceiling. The
/// parent ceiling is the deployment default (`ALL` in dev) intersected
/// with any persisted parent-scope ceiling rows.
fn agent_participation_parent_scope_keys(
    state: &AppState,
    operation: &Operation,
    scope_kind: &str,
    fallback_parent_keys: Vec<String>,
) -> Vec<String> {
    if scope_kind != "strand" {
        return fallback_parent_keys;
    }
    let realm_uuid = ap_uuid_part(operation.realm_id.as_str()).to_owned();
    let mut parent_keys = vec![format!("realm:{realm_uuid}")];
    let scope_circle_id = operation
        .payload
        .pointer("/object/scope_circle_id")
        .or_else(|| operation.payload.get("scope_circle_id"))
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .or_else(|| {
            let strand_id = operation
                .payload
                .get("strand_id")
                .and_then(Value::as_str)
                .or_else(|| {
                    operation
                        .payload
                        .get("object")
                        .and_then(|object| object.get("id"))
                        .and_then(Value::as_str)
                })?;
            state
                .projection
                .lock()
                .ok()
                .and_then(|projection| projection.strand_scope_circle_id(strand_id))
        });
    if let Some(circle_id) = scope_circle_id {
        parent_keys.push(crate::routing::agent_participation::circle_scope_key(
            operation.realm_id.as_str(),
            &circle_id,
        ));
    }
    parent_keys
}

/// Admission gate (CKP-0016): an inner-scope `agent_participation` ceiling
/// must not widen its parent ceiling.
pub async fn validate_agent_participation_ceiling(
    state: &AppState,
    operations: &[Operation],
) -> Result<(), &'static str> {
    use cokret_sdk::models::{AgentParticipation, validate_agent_participation_tightens};
    for operation in operations {
        let Some((scope_kind, _scope_key, child, parent_keys)) =
            agent_participation_ceiling_change(operation)
        else {
            continue;
        };
        let parent_keys =
            agent_participation_parent_scope_keys(state, operation, scope_kind, parent_keys);
        let mut parent = AgentParticipation::ALL;
        if !parent_keys.is_empty() {
            let rows = state
                .persistence
                .agent_participation()
                .ceilings_for_scope_keys(&parent_keys)
                .await
                .unwrap_or_default();
            for row in &rows {
                parent = parent.intersect(AgentParticipation {
                    reply: ap_bool(row, "reply"),
                    accept_third_party_mention: ap_bool(row, "accept_third_party_mention"),
                    act_on_behalf: ap_bool(row, "act_on_behalf"),
                });
            }
        }
        if validate_agent_participation_tightens(parent, child).is_err() {
            return Err("agent_participation_ceiling_widen");
        }
    }
    Ok(())
}

/// The `agent_participation_ceiling` row to UPSERT after an event with a
/// ceiling change is accepted (projection write), or None.
pub(crate) fn agent_participation_ceiling_record(operation: &Operation) -> Option<Value> {
    let (scope_kind, scope_key, child, _parents) = agent_participation_ceiling_change(operation)?;
    Some(serde_json::json!({
        "scope_kind": scope_kind,
        "scope_key": scope_key,
        "realm_id": operation.realm_id.as_str(),
        "reply": child.reply,
        "accept_third_party_mention": child.accept_third_party_mention,
        "act_on_behalf": child.act_on_behalf,
    }))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AgentParticipationMode {
    Reply,
    ActOnBehalf,
}

impl AgentParticipationMode {
    fn rejection_reason(self) -> &'static str {
        match self {
            Self::Reply => "agent_reply_not_permitted",
            Self::ActOnBehalf => "agent_act_on_behalf_not_permitted",
        }
    }
}

fn ap_effective_for_mode(
    mode: AgentParticipationMode,
    effective: cokret_sdk::models::AgentParticipation,
) -> bool {
    match mode {
        AgentParticipationMode::Reply => effective.reply,
        AgentParticipationMode::ActOnBehalf => effective.act_on_behalf,
    }
}

async fn native_agent_exists(state: &AppState, principal_id: &str) -> Result<bool, &'static str> {
    state
        .persistence
        .agents()
        .get(principal_id)
        .await
        .map(|record| record.is_some())
        .map_err(|_| "agent_principal_lookup_unavailable")
}

fn agent_participation_action(operation: &Operation) -> Option<&str> {
    kinds::canonical_kind_for_operation(operation)
}

fn validate_agent_act_on_behalf_authorization_ref(
    state: &AppState,
    operation: &Operation,
    agent_principal_id: &str,
) -> Result<String, &'static str> {
    let authorization_ref = operation
        .payload
        .get("authorization_ref")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or("agent_act_on_behalf_authorization_ref_missing")?;
    if !authorization_ref.starts_with("ck:grant:") {
        return Err("agent_act_on_behalf_authorization_ref_invalid");
    }
    let Some(action) = agent_participation_action(operation) else {
        return Err("agent_act_on_behalf_authorization_action_unsupported");
    };
    let resource = operation
        .object_id
        .as_deref()
        .unwrap_or_else(|| operation.realm_id.as_str());
    let grants = state
        .authz
        .grants_for_subject(agent_principal_id, operation.realm_id.as_str());
    let Some(grant) = grants
        .iter()
        .find(|grant| grant.grant_id == authorization_ref)
    else {
        return Err("agent_act_on_behalf_authorization_ref_inactive");
    };
    let action_allowed = grant
        .actions
        .iter()
        .any(|candidate| candidate == action);
    if !action_allowed || !crate::authz::resource_matches(&grant.resource, resource) {
        return Err("agent_act_on_behalf_authorization_ref_scope");
    }
    Ok(authorization_ref.to_owned())
}

fn agent_action_target_matches(target: &Value, operation: &Operation) -> bool {
    if target
        .get("operation_id")
        .and_then(Value::as_str)
        .is_some_and(|operation_id| operation_id == operation.operation_id.as_str())
    {
        return true;
    }
    match target.get("kind").and_then(Value::as_str) {
        Some("realm") => target
            .get("realm_id")
            .and_then(Value::as_str)
            .is_some_and(|realm_id| realm_id == operation.realm_id.as_str()),
        Some("strand") => {
            let Some(target_ref) = target.get("ref").and_then(Value::as_str) else {
                return false;
            };
            operation
                .payload
                .get("strand_id")
                .or_else(|| operation.payload.get("thread_id"))
                .and_then(Value::as_str)
                .is_some_and(|strand_id| strand_id == target_ref)
        }
        Some("message") | Some("object") => {
            let Some(target_ref) = target.get("ref").and_then(Value::as_str) else {
                return false;
            };
            operation.object_id.as_deref() == Some(target_ref)
                || operation
                    .payload
                    .get("message_id")
                    .and_then(Value::as_str)
                    .is_some_and(|message_id| message_id == target_ref)
        }
        _ => false,
    }
}

fn validate_agent_act_on_behalf_approval(
    state: &AppState,
    operation: &Operation,
    agent_principal_id: &str,
    authorization_ref: &str,
) -> Result<(), &'static str> {
    let request_id = operation
        .payload
        .get("approval_request_id")
        .or_else(|| operation.payload.get("request_id"))
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or("agent_act_on_behalf_approval_request_id_missing")?;
    let approval_nonce = operation
        .payload
        .get("approval_nonce")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or("agent_act_on_behalf_approval_nonce_missing")?;
    let action = agent_participation_action(operation)
        .ok_or("agent_act_on_behalf_approval_action_unsupported")?;
    let Ok(projection) = state.projection.lock() else {
        return Err("agent_act_on_behalf_approval_unavailable");
    };
    let request = projection
        .agent_action_requests
        .get(request_id)
        .ok_or("agent_act_on_behalf_approval_request_missing")?;
    if request.status != crate::reducer::AgentActionRequestStatus::Approved {
        return Err("agent_act_on_behalf_approval_request_not_approved");
    }
    if request.agent_principal_id != agent_principal_id {
        return Err("agent_act_on_behalf_approval_agent_mismatch");
    }
    let approval = request
        .approval
        .as_ref()
        .ok_or("agent_act_on_behalf_approval_missing")?;
    if approval.approval_nonce != approval_nonce {
        return Err("agent_act_on_behalf_approval_nonce_mismatch");
    }
    if approval.expires_at <= chrono::Utc::now() {
        return Err("agent_act_on_behalf_approval_expired");
    }
    if approval.proposed_action != action {
        return Err("agent_act_on_behalf_approval_action_mismatch");
    }
    if !agent_action_target_matches(&approval.target, operation) {
        return Err("agent_act_on_behalf_approval_target_mismatch");
    }
    let payload_digest = cokret_sdk::canonical::canonical_sha256(&operation.payload)
        .map_err(|_| "agent_act_on_behalf_approval_payload_digest_invalid")?;
    if approval.approved_payload_digest != payload_digest {
        return Err("agent_act_on_behalf_approval_payload_digest_mismatch");
    }
    let expires_at = approval.expires_at;
    drop(projection);
    if !state.remember_agent_approval_nonce(
        agent_principal_id,
        authorization_ref,
        request_id,
        approval_nonce,
        expires_at,
    ) {
        return Err(cokret_sdk::error::REASON_APPROVAL_NONCE_REUSED);
    }
    Ok(())
}

fn operation_agent_context(operation: &Operation) -> Option<&Value> {
    operation
        .payload
        .get("agent_context")
        .or_else(|| {
            operation
                .payload
                .get("provenance")
                .and_then(|provenance| provenance.get("agent_context"))
        })
        .filter(|value| !value.is_null())
}

fn agent_context_string<'a>(
    context: &'a Value,
    field: &str,
    missing_reason: &'static str,
) -> Result<&'a str, &'static str> {
    let object = context.as_object().ok_or("agent_context_invalid")?;
    object
        .get(field)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or(missing_reason)
}

fn agent_context_agent_id(operation: &Operation) -> Option<&str> {
    operation_agent_context(operation).and_then(|context| {
        context
            .as_object()
            .and_then(|object| object.get("agent_id"))
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
    })
}

fn operation_agent_provenance(operation: &Operation) -> Option<&Value> {
    operation
        .payload
        .get("provenance")
        .or_else(|| operation.payload.get("agent_provenance"))
        .filter(|value| value.is_object())
}

fn operation_provenance_agent_id(operation: &Operation) -> Option<&str> {
    operation_agent_provenance(operation).and_then(|provenance| {
        provenance
            .get("agent_id")
            .or_else(|| provenance.get("executed_by"))
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
    })
}

fn operation_executed_by(operation: &Operation) -> Option<&str> {
    operation
        .payload
        .get("executed_by")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .or_else(|| {
            operation_agent_provenance(operation).and_then(|provenance| {
                provenance
                    .get("executed_by")
                    .and_then(Value::as_str)
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
            })
        })
}

fn operation_provenance_marks_agent(operation: &Operation) -> bool {
    let Some(provenance) = operation_agent_provenance(operation) else {
        return false;
    };
    provenance
        .get("actor_kind")
        .and_then(Value::as_str)
        .is_some_and(|value| value == "agent")
        || provenance
            .get("kind")
            .and_then(Value::as_str)
            .is_some_and(|value| value == "agent")
        || operation_provenance_agent_id(operation).is_some()
}

async fn operation_agent_write_context(
    state: &AppState,
    operation: &Operation,
) -> Result<Option<(String, AgentParticipationMode)>, &'static str> {
    if let Some(executed_by) = operation_executed_by(operation) {
        if agent_context_agent_id(operation) == Some(executed_by)
            || operation_provenance_marks_agent(operation)
            || native_agent_exists(state, executed_by).await?
        {
            return Ok(Some((
                executed_by.to_owned(),
                AgentParticipationMode::ActOnBehalf,
            )));
        }
    }
    if let Some(agent_id) = agent_context_agent_id(operation) {
        let mode = if operation_executed_by(operation).is_some() {
            AgentParticipationMode::ActOnBehalf
        } else {
            AgentParticipationMode::Reply
        };
        return Ok(Some((agent_id.to_owned(), mode)));
    }
    if operation_provenance_marks_agent(operation)
        && let Some(agent_id) =
            operation_provenance_agent_id(operation).or_else(|| operation_actor(operation))
    {
        let mode = if operation_executed_by(operation).is_some() {
            AgentParticipationMode::ActOnBehalf
        } else {
            AgentParticipationMode::Reply
        };
        return Ok(Some((agent_id.to_owned(), mode)));
    }
    if let Some(sender) = operation_actor(operation)
        && native_agent_exists(state, sender).await?
    {
        return Ok(Some((sender.to_owned(), AgentParticipationMode::Reply)));
    }
    Ok(None)
}

fn validate_agent_context_authorization_ref(
    state: &AppState,
    operation: &Operation,
    agent_principal_id: &str,
    authorization_ref: &str,
) -> Result<(), &'static str> {
    if !authorization_ref.starts_with("ck:grant:") {
        return Err("agent_context_authorization_ref_invalid");
    }
    let Some(action) = agent_participation_action(operation) else {
        return Err("agent_context_authorization_action_unsupported");
    };
    let resource = operation
        .object_id
        .as_deref()
        .unwrap_or_else(|| operation.realm_id.as_str());
    let grants = state
        .authz
        .grants_for_subject(agent_principal_id, operation.realm_id.as_str());
    let Some(grant) = grants
        .iter()
        .find(|grant| grant.grant_id == authorization_ref)
    else {
        return Err("agent_context_authorization_ref_inactive");
    };
    let action_allowed = grant
        .actions
        .iter()
        .any(|candidate| candidate == action);
    if !action_allowed || !crate::authz::resource_matches(&grant.resource, resource) {
        return Err("agent_context_authorization_ref_scope");
    }
    Ok(())
}

fn validate_agent_context(
    state: &AppState,
    operation: &Operation,
    agent_principal_id: &str,
    envelope_authorization_ref: Option<&str>,
) -> Result<(), &'static str> {
    let context = operation_agent_context(operation).ok_or("agent_context_missing")?;
    let agent_id = agent_context_string(context, "agent_id", "agent_context_agent_id_missing")?;
    if agent_id != agent_principal_id {
        return Err("agent_context_agent_mismatch");
    }
    agent_context_string(
        context,
        "operator_or_controller",
        "agent_context_operator_or_controller_missing",
    )?;
    agent_context_string(
        context,
        "execution_purpose",
        "agent_context_execution_purpose_missing",
    )?;
    let context_authorization_ref = agent_context_string(
        context,
        "authorization_ref",
        "agent_context_authorization_ref_missing",
    )?;
    validate_agent_context_authorization_ref(
        state,
        operation,
        agent_principal_id,
        context_authorization_ref,
    )?;
    if let Some(envelope_authorization_ref) = envelope_authorization_ref
        && context_authorization_ref != envelope_authorization_ref
    {
        return Err("agent_context_authorization_ref_mismatch");
    }
    Ok(())
}

/// CKP-0016 §5.2 / CKP-0008 §4.10 + architecture §7 enforcement
/// (soland-native): every agent-originated Event carries auditable
/// `agent_context`. Reply-as-agent uses the `reply` bit; act-on-behalf uses
/// envelope-derived `executed_by`, requires a referenced active grant, and
/// uses the `act_on_behalf` bit. Non-agent actors fall through to standard
/// authz.
pub async fn validate_agent_reply_participation(
    state: &AppState,
    operations: &[Operation],
) -> Result<(), &'static str> {
    for operation in operations {
        let Some((agent_principal_id, mode)) =
            operation_agent_write_context(state, operation).await?
        else {
            continue;
        };
        let authorization_ref = if mode == AgentParticipationMode::ActOnBehalf {
            Some(validate_agent_act_on_behalf_authorization_ref(
                state,
                operation,
                &agent_principal_id,
            )?)
        } else {
            None
        };
        validate_agent_context(
            state,
            operation,
            &agent_principal_id,
            authorization_ref.as_deref(),
        )?;
        let strand_id = operation
            .payload
            .get("strand_id")
            .and_then(Value::as_str)
            .or_else(|| operation.payload.get("thread_id").and_then(Value::as_str));
        let Some(scope_keys) = crate::routing::agent_participation::scope_keys_for_message(
            state,
            operation.realm_id.as_str(),
            strand_id,
        ) else {
            return Err(mode.rejection_reason());
        };
        let Some(resolved) =
            crate::routing::agent_participation::resolve_agent_participation_for_scope_keys(
                state,
                &agent_principal_id,
                &scope_keys,
            )
            .await
        else {
            return Err(mode.rejection_reason());
        };
        if !ap_effective_for_mode(mode, resolved.effective) {
            return Err(mode.rejection_reason());
        }
        if let Some(authorization_ref) = authorization_ref {
            validate_agent_act_on_behalf_approval(
                state,
                operation,
                &agent_principal_id,
                &authorization_ref,
            )?;
        }
    }
    Ok(())
}

fn validate_direct_conversation_realm_policy(
    state: &AppState,
    operation: &Operation,
) -> Result<(), &'static str> {
    if active_direct_conversation_binding_for_realm(state, operation.realm_id.as_str()).is_none() {
        return Ok(());
    }
    if kinds::operation_is_invite(operation) {
        return Err("direct_conversation_invite_forbidden");
    }
    if operation_is_space_container(operation) {
        return Err("direct_conversation_space_forbidden");
    }
    Ok(())
}

fn operation_is_space_container(operation: &Operation) -> bool {
    matches!(
        kinds::canonical_kind_for_operation(operation),
        Some(
            kinds::CK_SPACE_CONTAINER_CREATE
                | kinds::CK_SPACE_CONTAINER_UPDATE
                | kinds::CK_SPACE_CONTAINER_PARENT
                | kinds::CK_SPACE_CONTAINER_ARCHIVE
                | kinds::CK_SPACE_CONTAINER_RESTORE
                | kinds::CK_SPACE_CONTAINER_TOMBSTONE
        )
    )
}

async fn validate_member_state_policy(
    state: &AppState,
    operation: &Operation,
) -> Result<(), &'static str> {
    if kinds::canonical_kind_for_operation(operation) != Some(kinds::CK_MEMBER_STATE) {
        return Ok(());
    }
    if let Some(reason) = direct_conversation_member_state_guard(state, operation) {
        return Err(reason);
    }
    if operation.payload.get("membership").and_then(Value::as_str) == Some("join") {
        if let Some(member) = membership_target(operation) {
            if crate::routing::organizations::organization_policy_blocks_join(
                state,
                operation.realm_id.as_str(),
                member,
            )
            .await
            {
                return Err("organization_policy_denied");
            }
        }
        return Ok(());
    }
    if operation.payload.get("membership").and_then(Value::as_str) != Some("ban") {
        return Ok(());
    }
    let Some(actor) = operation.payload.get("sender").and_then(Value::as_str) else {
        // Peer/service-originated federation operations predate a typed actor
        // envelope. They stay accepted so existing convergence/backfill
        // paths keep working; direct client submits always carry `sender`.
        return Ok(());
    };
    if realm_owner_matches(state, operation.realm_id.as_str(), actor).await {
        return Ok(());
    }
    // P1 — a non-owner MAY ban iff they hold `ck.realm.admin` on this Realm
    // (capabilities.md §16 — `ck.realm.admin` governs `ck.member.state`
    // writes). The owner implicitly holds admin and already returned above;
    // this reads the projected capability grant index via
    // SolandAuthzEngine::check. fail-closed: anything other than an explicit
    // allow keeps the `missing_capability` rejection.
    let realm_id = operation.realm_id.as_str();
    let (owner, members) = realm_owner_and_members(state, realm_id).await;
    if state
        .authz
        .check(
            actor,
            "ck.realm.admin",
            realm_id,
            realm_id,
            owner.as_deref(),
            &members,
            &[],
        )
        .allowed
    {
        return Ok(());
    }
    Err("missing_capability")
}

/// COT-06-004 — capability gate for `ck.realm.set_default_strand`. Mirrors the
/// ban / moderation gates: the actor MUST own the Realm or hold
/// `ck.realm.set_default_strand` (or the broader `ck.realm.admin`) on it.
/// fail-closed `missing_capability` otherwise. Peer/service-originated
/// federation operations (no `sender`) stay accepted for convergence/backfill.
async fn validate_set_default_strand_policy(
    state: &AppState,
    operation: &Operation,
) -> Result<(), &'static str> {
    if kinds::canonical_kind_for_operation(operation) != Some(kinds::CK_REALM_SET_DEFAULT_STRAND) {
        return Ok(());
    }
    let Some(actor) = operation
        .payload
        .get("sender")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
    else {
        return Ok(());
    };
    let realm_id = operation.realm_id.as_str();
    if realm_owner_matches(state, realm_id, actor).await {
        return Ok(());
    }
    let (owner, members) = realm_owner_and_members(state, realm_id).await;
    // A grant of either the precise action or the broad realm-admin action
    // authorizes the write. `ck.realm.admin` aggregates Realm governance, so
    // an admin holder need not also hold the narrow set_default_strand action.
    for action in ["ck.realm.set_default_strand", "ck.realm.admin"] {
        if state
            .authz
            .check(
                actor,
                action,
                realm_id,
                realm_id,
                owner.as_deref(),
                &members,
                &[],
            )
            .allowed
        {
            return Ok(());
        }
    }
    Err("missing_capability")
}

/// P2 — capability gate for the moderation control-plane events ingested at
/// `/_cokret/self/events` (content-moderation.md §2.6 / §5.5; capability-
/// action-registry.json). Mirrors [`validate_member_state_policy`]'s ban
/// gate: the actor MUST hold the matching moderation capability action on the
/// Realm, or own the Realm. fail-closed `missing_capability` otherwise.
///
/// Action mapping (capability-action-registry.json):
/// - `ck.moderation.decision`            → action `ck.moderation.decision`
/// - `ck.moderation.decision.lift`       → action `ck.moderation.decision.lift`
/// - `ck.moderation.appeal.submit`       → action `ck.moderation.appeal.submit`
/// - `ck.moderation.appeal.{review,decision,close}` → action `ck.moderation.appeal.review`
///   (aggregate_admin: one review capability covers review / decision / close — §5.5.1 table note).
///
/// `ck.moderation.appeal.close` additionally admits the appellant-withdrawal
/// path: an appellant closing their own appeal (closer == cell appellant)
/// needs no review capability (§5.5.2).
async fn validate_moderation_event_policy(
    state: &AppState,
    operation: &Operation,
) -> Result<(), &'static str> {
    let Some(kind) = kinds::canonical_kind_for_operation(operation) else {
        return Ok(());
    };
    let action = match kind {
        kinds::CK_MODERATION_DECISION => "ck.moderation.decision",
        kinds::CK_MODERATION_DECISION_LIFT => "ck.moderation.decision.lift",
        kinds::CK_MODERATION_APPEAL_SUBMIT => "ck.moderation.appeal.submit",
        kinds::CK_MODERATION_APPEAL_REVIEW
        | kinds::CK_MODERATION_APPEAL_DECISION
        | kinds::CK_MODERATION_APPEAL_CLOSE => "ck.moderation.appeal.review",
        _ => return Ok(()),
    };

    // Peer/service-originated federation operations predate a typed actor
    // envelope; they stay accepted so convergence/backfill keep working
    // (mirrors the ban gate). Direct client submits always carry an actor.
    let Some(actor) = moderation_actor(operation, kind)? else {
        return Ok(());
    };

    // §5.5.2 appellant-withdrawal: an appellant MAY close their own appeal
    // without the review capability (closer == cell appellant).
    if kind == kinds::CK_MODERATION_APPEAL_CLOSE
        && moderation_close_is_appellant_withdrawal(state, operation, actor)
    {
        return Ok(());
    }

    let realm_id = operation.realm_id.as_str();
    if realm_owner_matches(state, realm_id, actor).await {
        return Ok(());
    }
    let (owner, members) = realm_owner_and_members(state, realm_id).await;
    if state
        .authz
        .check(
            actor,
            action,
            realm_id,
            realm_id,
            owner.as_deref(),
            &members,
            &[],
        )
        .allowed
    {
        return Ok(());
    }
    Err("missing_capability")
}

async fn validate_call_recording_start_policy(
    state: &AppState,
    operation: &Operation,
) -> Result<(), &'static str> {
    if kinds::canonical_kind_string(operation) != cokret_sdk::events::kinds::CALL_RECORDING_START {
        return Ok(());
    }
    let action = call_recording_start_required_action(operation);
    let Some(actor) = operation_actor(operation) else {
        return Ok(());
    };
    let realm_id = operation.realm_id.as_str();
    let (owner, members) = realm_owner_and_members(state, realm_id).await;
    if state
        .authz
        .check(
            actor,
            action,
            realm_id,
            realm_id,
            owner.as_deref(),
            &members,
            &[],
        )
        .allowed
    {
        return Ok(());
    }
    if action == cokret_sdk::CAP_ACTION_CALL_TRANSCRIBE {
        Err(crate::error::reasons::TRANSCRIPTION_DENIED)
    } else {
        Err("missing_capability")
    }
}

fn call_recording_start_required_action(operation: &Operation) -> &'static str {
    match operation
        .payload
        .get("capture_kind")
        .and_then(Value::as_str)
        .unwrap_or("recording")
    {
        "transcript" => cokret_sdk::CAP_ACTION_CALL_TRANSCRIBE,
        _ => cokret_sdk::CAP_ACTION_CALL_RECORD,
    }
}

/// Extract the authoring actor for a moderation event from the spec field for
/// that kind. The projection adapter injects envelope.actor_id into
/// payload.sender; when both sender and the kind-specific actor are present
/// they must match so a privileged sender cannot spoof the decision issuer.
fn moderation_actor<'a>(
    operation: &'a Operation,
    kind: &str,
) -> Result<Option<&'a str>, &'static str> {
    let actor = match kind {
        kinds::CK_MODERATION_DECISION => operation
            .payload
            .get("issuer")
            .or_else(|| operation.payload.get("decided_by"))
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .ok_or("moderation_decision_issuer_missing")?,
        kinds::CK_MODERATION_DECISION_LIFT => {
            return Ok(operation
                .payload
                .get("sender")
                .or_else(|| operation.payload.get("actor_id"))
                .and_then(Value::as_str)
                .filter(|value| !value.trim().is_empty()));
        }
        kinds::CK_MODERATION_APPEAL_SUBMIT => operation
            .payload
            .get("appellant")
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .ok_or("moderation_appeal_actor_missing")?,
        kinds::CK_MODERATION_APPEAL_REVIEW | kinds::CK_MODERATION_APPEAL_DECISION => operation
            .payload
            .get("reviewer")
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .ok_or("moderation_appeal_actor_missing")?,
        kinds::CK_MODERATION_APPEAL_CLOSE => operation
            .payload
            .get("closer")
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .ok_or("moderation_appeal_actor_missing")?,
        _ => return Ok(None),
    };
    if operation
        .payload
        .get("sender")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .is_some_and(|sender| sender != actor)
    {
        return Err("moderation_actor_mismatch");
    }
    Ok(Some(actor))
}

/// True when an `appeal.close` is an appellant self-withdrawal: the closer
/// equals the appellant anchored on the projected appeal cell at submit time.
fn moderation_close_is_appellant_withdrawal(
    state: &AppState,
    operation: &Operation,
    actor: &str,
) -> bool {
    let Some(appeal_id) = operation.payload.get("appeal_id").and_then(Value::as_str) else {
        return false;
    };
    let appellant = state
        .projection
        .lock()
        .ok()
        .and_then(|proj| proj.moderation_appeal_appellant(appeal_id));
    matches!(appellant, Some(appellant) if appellant == actor)
}

fn direct_conversation_member_state_guard(
    state: &AppState,
    operation: &Operation,
) -> Option<&'static str> {
    let membership = operation
        .payload
        .get("membership")
        .and_then(Value::as_str)?;
    let binding = active_direct_conversation_binding_for_realm(state, operation.realm_id.as_str())?;
    if binding.participants_unordered.len() != 2 {
        return Some("direct_conversation_member_count_invalid");
    }
    if !matches!(membership, "invite" | "join") {
        return None;
    }
    let target = membership_target(operation)?;
    if binding
        .participants_unordered
        .iter()
        .any(|participant| participant == target)
    {
        None
    } else {
        Some("direct_conversation_third_party_member_forbidden")
    }
}

fn active_direct_conversation_binding_for_realm(
    state: &AppState,
    realm_id: &str,
) -> Option<crate::state::DirectConversationBindingRecord> {
    state
        .direct_conversation_bindings
        .lock()
        .expect("direct_conversation_bindings lock")
        .values()
        .find(|binding| binding.state == "active" && binding.realm_id == realm_id)
        .cloned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn circle_create_with_payload(payload: Value) -> Operation {
        Operation::create(
            cokret_sdk::OperationId::new("ck:operation:01964137-0000-7000-8000-000000000040")
                .unwrap(),
            cokret_sdk::RealmId::new("ck:realm:01964137-0000-7000-8000-000000000030").unwrap(),
            kinds::CK_CIRCLE_CREATE,
            payload,
        )
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
