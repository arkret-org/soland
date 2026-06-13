use super::*;

pub fn operation_policy_reason_code(message: &str) -> (salvo::http::StatusCode, &'static str) {
    if message.starts_with("message_edit_window")
        || message.starts_with("message_redact_window")
        || message.starts_with("disappearing_")
        || message.starts_with("direct_conversation_")
        || message == cokret_sdk::error::REASON_REACTION_SCOPE_MISMATCH
    {
        (
            salvo::http::StatusCode::PRECONDITION_FAILED,
            "failed_precondition",
        )
    } else {
        (salvo::http::StatusCode::FORBIDDEN, "capability_denied")
    }
}

pub async fn validate_operation_policy(
    state: &AppState,
    operations: &[Operation],
) -> Result<(), &'static str> {
    for operation in operations {
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
        validate_member_state_policy(state, operation).await?;
        validate_history_visibility_policy(state, operation).await?;
        validate_realm_key_share_policy(state, operation).await?;
        validate_realm_moderation_policy(state, operation)?;
        validate_poll_operation_policy(state, operation)?;
        validate_audience_mention_operation_policy(state, operation).await?;
        validate_message_edit_redact_window_policy(state, operation).await?;
        validate_reaction_scope_policy(state, operation)?;
        validate_minimal_metadata_aad_policy(state, operation).await?;
        validate_disappearing_message_policy(state, operation)?;
    }
    Ok(())
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

fn minimal_metadata_aad_visibility(envelope: &Value) -> Option<cokret_sdk::mls::AadVisibility> {
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

/// flow-and-message.md §9.8.2 — a reaction MUST target an object inside its
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
fn validate_principal_control_realm_binding(operation: &Operation) -> Result<(), &'static str> {
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
            .any(|action| action == broad_action || action == "*")
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
        if flow_operation_carries_plaintext_private_content(operation)
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

/// Extract the agent_participation ceiling a realm-policy / circle / flow
/// operation carries, plus the parent scope_key chain to validate
/// tighten-only against. Returns `(scope_kind, scope_key, child_ceiling,
/// parent_scope_keys)` or None when the operation carries no ceiling.
fn agent_participation_ceiling_change(
    operation: &Operation,
) -> Option<(
    &'static str,
    String,
    cokret_sdk::model::AgentParticipation,
    Vec<String>,
)> {
    use cokret_sdk::model::AgentParticipation;
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
        Some(kinds::CK_FLOW_CREATE) | Some(kinds::CK_FLOW_UPDATE) => {
            let value = find(false)?;
            let flow_uuid = ap_uuid_part(&id_of("flow_id")?).to_owned();
            Some((
                "flow",
                format!("flow:{realm_uuid}:{flow_uuid}"),
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
pub async fn validate_agent_participation_ceiling(
    state: &AppState,
    operations: &[Operation],
) -> Result<(), &'static str> {
    use cokret_sdk::model::{AgentParticipation, validate_agent_participation_tightens};
    for operation in operations {
        let Some((_scope_kind, _scope_key, child, parent_keys)) =
            agent_participation_ceiling_change(operation)
        else {
            continue;
        };
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

fn ap_effective_reply(selection: &Value, ceiling: cokret_sdk::model::AgentParticipation) -> bool {
    ap_bool(selection, "reply") && ceiling.reply
}

/// CKP-0016 §5.2 enforcement (soland-native): a native personal agent may
/// only author `ck.message.create` / `ck.reaction.add` in a scope where
/// its effective participation `reply` bit is true (selection ∩ ceiling).
/// Non-agent actors are unaffected — they fall through to standard authz.
/// The agent's most-specific selection (flow over realm) governs; an agent
/// with no reply-enabled selection covering the scope is rejected
/// (least-privilege, CKP-0008 §4.9).
pub async fn validate_agent_reply_participation(
    state: &AppState,
    operations: &[Operation],
) -> Result<(), &'static str> {
    use cokret_sdk::model::AgentParticipation;
    for operation in operations {
        match kinds::canonical_kind_for_operation(operation) {
            Some(kinds::CK_MESSAGE_CREATE) | Some(kinds::CK_REACTION_ADD) => {}
            _ => continue,
        }
        let Some(actor) = operation.payload.get("sender").and_then(Value::as_str) else {
            continue;
        };
        // Only native personal agents are gated.
        let is_agent = state
            .persistence
            .agents()
            .get(actor)
            .await
            .ok()
            .flatten()
            .is_some();
        if !is_agent {
            continue;
        }
        let realm_uuid = ap_uuid_part(operation.realm_id.as_str()).to_owned();
        let realm_key = format!("realm:{realm_uuid}");
        let flow_key = operation
            .payload
            .get("flow_id")
            .and_then(Value::as_str)
            .or_else(|| operation.payload.get("thread_id").and_then(Value::as_str))
            .map(|f| format!("flow:{realm_uuid}:{}", ap_uuid_part(f)));
        let selections = state
            .persistence
            .agent_participation()
            .list_selections(actor)
            .await
            .unwrap_or_default();
        let find = |key: &str| {
            selections
                .iter()
                .find(|r| r.get("scope_key").and_then(Value::as_str) == Some(key))
                .cloned()
        };
        let selection = flow_key
            .as_deref()
            .and_then(find)
            .or_else(|| find(&realm_key));
        let Some(selection) = selection else {
            return Err("agent_reply_not_permitted");
        };
        let selection_scope_key = selection
            .get("scope_key")
            .and_then(Value::as_str)
            .unwrap_or(realm_key.as_str())
            .to_owned();
        let ceiling_rows = state
            .persistence
            .agent_participation()
            .ceilings_for_scope_keys(&[realm_key.clone(), selection_scope_key])
            .await
            .unwrap_or_default();
        let mut ceiling = AgentParticipation::ALL;
        for row in &ceiling_rows {
            ceiling = ceiling.intersect(AgentParticipation {
                reply: ap_bool(row, "reply"),
                accept_third_party_mention: ap_bool(row, "accept_third_party_mention"),
                act_on_behalf: ap_bool(row, "act_on_behalf"),
            });
        }
        if !ap_effective_reply(&selection, ceiling) {
            return Err("agent_reply_not_permitted");
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
        if let Some(member) = membership_target(operation)
            && crate::routing::organizations::organization_policy_blocks_join(
                state,
                operation.realm_id.as_str(),
                member,
            )
        {
            return Err("organization_policy_denied");
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
    Err("missing_capability")
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
